//! The PBX core: routes calls between registered devices (docs/02 §4).
//!
//! A [`Switch`] is a pure message processor: SIP messages in (already parsed),
//! SIP messages out plus call-log lines. No sockets, no clock of its own —
//! the daemon and the simulation drive it the same way.
//!
//! Each call is a B2BUA: one dialog leg toward the caller, one toward the
//! callee, glued by the call state machine ([`crate::call`]).
//!
//! **Lifetime rule** (learned from real phones, docs/09): a call stays around
//! until its *transactions* are done, not just its state machine. Retransmitted
//! INVITEs, BYEs and 2xx responses must keep getting answers — otherwise a
//! single lost datagram creates phantom calls and stuck phones. The switch
//! garbage-collects calls whose transactions have all finished (typically
//! ~32 s after the call ends).

use std::collections::{BTreeSet, HashMap};

use sip_stack::{
    ack_for_2xx, make_response, tag_of, uri_of, with_tag, Action, ClientTransaction, Dialog,
    ServerTransaction, Timer,
};
use sip_syntax::{canonical_header, parse_sdp, Header, Message, Method, Request, Response};

use crate::call::{transit, CallEvent, CallState, Command};
use crate::registration::{header, number_from_uri, Device, Registrar};

/// The methods we implement (docs/07); anything else gets `405` + `Allow`.
pub const ALLOW: &str = "INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS";

/// Everything the switch needs to know from the config file.
#[derive(Debug, Clone)]
pub struct SwitchConfig {
    /// Realm used in digest challenges.
    pub realm: String,
    /// Our SIP address ("sip:192.0.2.10").
    pub pbx_uri: String,
    /// Our host:port, for Via headers ("192.0.2.10:5060").
    pub pbx_host: String,
    /// Our Contact ("<sip:192.0.2.10:5060>").
    pub pbx_contact: String,
    /// Our IP, advertised in SDP for media relaying.
    pub rtp_host: String,
    /// First media relay port.
    pub rtp_port_base: u16,
    /// How many media ports are available (two per concurrent call).
    pub rtp_ports: u16,
    /// The devices that may register and be called.
    pub devices: Vec<Device>,
}

/// What the switch wants the environment to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send this SIP message.
    Send(Message),
    /// Send these RTP bytes to `to` ("ip:port") — the transparent pipe.
    SendRtp {
        /// The relay port to send from (the one advertised to that leg).
        from_port: u16,
        /// Destination address.
        to: String,
        /// The exact packet bytes to forward.
        data: Vec<u8>,
    },
    /// Append this line to the call log (one per finished call).
    CallLog(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leg {
    Caller,
    Callee,
}

/// Which transaction a timer belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxSlot {
    Caller,
    Callee,
    Server(usize),
    Client(usize),
}

/// One leg's media relay endpoint.
#[derive(Debug)]
struct LegMedia {
    /// The UDP port we receive this leg's RTP on.
    our_port: u16,
    /// Where the leg said its media lives (from its SDP).
    peer_addr: String,
    /// Where its packets actually come from (symmetric RTP), when known.
    learned: Option<String>,
}

impl LegMedia {
    fn send_to(&self) -> Option<String> {
        self.learned
            .clone()
            .filter(|address| !address.is_empty())
            .or_else(|| (!self.peer_addr.is_empty()).then(|| self.peer_addr.clone()))
    }
}

#[derive(Debug)]
struct CallMedia {
    caller: LegMedia,
    callee: LegMedia,
}

#[derive(Debug)]
struct CallCtx {
    state: CallState,
    logged: bool,
    caller_number: String,
    callee_number: String,
    caller_call_id: String,
    callee_call_id: String,
    caller_invite: Request,
    caller_tx: ServerTransaction,
    caller_dialog: Dialog,
    callee_tx: Option<ClientTransaction>,
    callee_invite: Option<Request>,
    callee_dialog: Option<Dialog>,
    /// Our ACK for the callee's 2xx; re-sent if they retransmit it.
    callee_ack: Option<Request>,
    /// Server transactions for in-dialog requests we received (BYE, re-INVITE).
    server_txs: Vec<ServerTransaction>,
    /// Client transactions for requests we sent besides the INVITE (BYE, CANCEL).
    client_txs: Vec<ClientTransaction>,
    media: Option<CallMedia>,
    started_ms: u64,
    outcome: String,
}

/// The switch.
#[derive(Debug)]
pub struct Switch {
    config: SwitchConfig,
    registrar: Registrar,
    calls: HashMap<u64, CallCtx>,
    /// Both legs' Call-IDs → call.
    by_call_id: HashMap<String, u64>,
    next_tag: u64,
    next_call: u64,
    free_rtp_ports: BTreeSet<u16>,
}

impl Switch {
    /// Creates a switch for the given devices and addresses.
    pub fn new(config: SwitchConfig) -> Self {
        let registrar = Registrar::new(&config.realm, config.devices.clone());
        let free_rtp_ports =
            (config.rtp_port_base..config.rtp_port_base.saturating_add(config.rtp_ports)).collect();
        Switch {
            config,
            registrar,
            calls: HashMap::new(),
            by_call_id: HashMap::new(),
            next_tag: 0,
            next_call: 0,
            free_rtp_ports,
        }
    }

    /// Currently registered numbers.
    pub fn registered(&self, now_ms: u64) -> Vec<String> {
        self.registrar.registered(now_ms)
    }

    /// How many calls are in flight (finished-but-retained calls not counted).
    pub fn active_calls(&self) -> usize {
        self.calls
            .values()
            .filter(|call| call.state != CallState::Terminated)
            .count()
    }

    /// How many calls are retained for late retransmissions (tests/debug).
    pub fn retained_calls(&self) -> usize {
        self.calls.len()
    }

    /// State of a call, by either of its Call-IDs.
    pub fn call_state(&self, call_id: &str) -> Option<CallState> {
        self.calls
            .get(self.by_call_id.get(call_id)?)
            .map(|call| call.state)
    }

    /// Outstanding transaction timers as `(name, due_ms)`. The environment
    /// arms them and fires them back through [`Switch::on_timer`].
    pub fn timers(&self) -> Vec<(String, u64)> {
        let mut timers = Vec::new();
        for (id, call) in &self.calls {
            let mut collect = |slot: TxSlot, due_timer: Option<(u64, Timer)>| {
                if let Some((due, timer)) = due_timer {
                    timers.push((timer_name(*id, slot, timer), due));
                }
            };
            collect(TxSlot::Caller, call.caller_tx.next_timer());
            collect(
                TxSlot::Callee,
                call.callee_tx.as_ref().and_then(|tx| tx.next_timer()),
            );
            for (index, tx) in call.server_txs.iter().enumerate() {
                collect(TxSlot::Server(index), tx.next_timer());
            }
            for (index, tx) in call.client_txs.iter().enumerate() {
                collect(TxSlot::Client(index), tx.next_timer());
            }
        }
        timers.sort();
        timers
    }

    /// A timer armed from [`Switch::timers`] fired.
    pub fn on_timer(&mut self, name: &str, now_ms: u64) -> Vec<Output> {
        let Some((id, slot, timer)) = parse_timer_name(name) else {
            return vec![];
        };
        let Some(call) = self.calls.get_mut(&id) else {
            return vec![];
        };
        let actions = match slot {
            TxSlot::Caller => call.caller_tx.on_timer(timer, now_ms),
            TxSlot::Callee => call
                .callee_tx
                .as_mut()
                .map(|tx| tx.on_timer(timer, now_ms))
                .unwrap_or_default(),
            TxSlot::Server(index) => call
                .server_txs
                .get_mut(index)
                .map(|tx| tx.on_timer(timer, now_ms))
                .unwrap_or_default(),
            TxSlot::Client(index) => call
                .client_txs
                .get_mut(index)
                .map(|tx| tx.on_timer(timer, now_ms))
                .unwrap_or_default(),
        };
        let mut outputs = self.apply_actions(&id, actions, now_ms);
        outputs.extend(self.settle(&id, now_ms));
        self.gc();
        outputs
    }

    /// Feeds one incoming SIP message; returns what to send and log.
    pub fn handle(&mut self, message: Message, now_ms: u64) -> Vec<Output> {
        let mut outputs = match message {
            Message::Request(request) => self.handle_request(request, now_ms),
            Message::Response(response) => self.handle_response(response, now_ms),
        };
        outputs.extend(self.collect_settled(now_ms));
        outputs
    }

    /// Runs the final transition on every call that reached `Terminating`.
    fn collect_settled(&mut self, now_ms: u64) -> Vec<Output> {
        let ids: Vec<u64> = self.calls.keys().copied().collect();
        let mut outputs = Vec::new();
        for id in ids {
            outputs.extend(self.settle(&id, now_ms));
        }
        self.gc();
        outputs
    }

    fn handle_request(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        match request.method {
            Method::Register => {
                let response = self.registrar.handle_register(&request, now_ms);
                vec![Output::Send(Message::Response(response))]
            }
            Method::Options => {
                let mut response = make_response(&request, 200, "OK");
                response.headers.push(Header {
                    name: "Allow".to_string(),
                    value: ALLOW.to_string(),
                });
                vec![Output::Send(Message::Response(response))]
            }
            // An INVITE inside an existing dialog is a re-INVITE (session
            // refresh, renegotiation) — never a new call.
            Method::Invite if self.find_leg(&request).is_some() => {
                self.handle_reinvite(request, now_ms)
            }
            Method::Invite => self.handle_invite(request, now_ms),
            Method::Ack => self.handle_ack(request, now_ms),
            Method::Bye => self.handle_bye(request, now_ms),
            Method::Cancel => self.handle_cancel(request, now_ms),
            Method::Other(_) => {
                let mut response = make_response(&request, 405, "Method Not Allowed");
                response.headers.push(Header {
                    name: "Allow".to_string(),
                    value: ALLOW.to_string(),
                });
                vec![Output::Send(Message::Response(response))]
            }
        }
    }

    // ----- call setup ------------------------------------------------------

    fn handle_invite(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        let mut outputs = Vec::new();
        let caller_call_id = header(&request.headers, "call-id")
            .unwrap_or("")
            .to_string();

        // Retransmission of an INVITE whose call we still hold: repeat our
        // last response instead of starting a second call.
        if let Some(&id) = self.by_call_id.get(&caller_call_id) {
            if let Some(call) = self.calls.get_mut(&id) {
                let actions = call.caller_tx.on_request(&request);
                push_sends(&mut outputs, actions);
            }
            return outputs;
        }

        let caller_number = header(&request.headers, "from")
            .map(uri_of)
            .and_then(number_from_uri)
            .unwrap_or_default();
        let callee_number = number_from_uri(&request.uri).unwrap_or_default();

        let (mut caller_tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        push_sends(&mut outputs, actions);

        // Only registered devices may place calls (docs/02 §6, docs/07).
        if !self.registrar.is_registered(&caller_number, now_ms) {
            let response = tagged(make_response(&request, 403, "Forbidden"), &self.fresh_tag());
            let actions = caller_tx.on_response_from_user(response, now_ms);
            push_sends(&mut outputs, actions);
            outputs.push(Output::CallLog(call_log_line(
                &caller_number,
                &callee_number,
                now_ms,
                now_ms,
                "unauthorized",
            )));
            return outputs;
        }

        // Where does the call go?
        let Some(callee_contact) = self
            .registrar
            .lookup(&callee_number, now_ms)
            .map(str::to_string)
        else {
            let response = tagged(make_response(&request, 404, "Not Found"), &self.fresh_tag());
            let actions = caller_tx.on_response_from_user(response, now_ms);
            push_sends(&mut outputs, actions);
            // Failed calls are logged too: "why didn't my call go through".
            outputs.push(Output::CallLog(call_log_line(
                &caller_number,
                &callee_number,
                now_ms,
                now_ms,
                "not-found",
            )));
            return outputs;
        };

        // Media: if the caller offered audio, we relay it (docs/02 §8).
        let media = match media_target(&request.body) {
            Some(peer_addr) => match self.allocate_media_ports() {
                Some((caller_port, callee_port)) => Some(CallMedia {
                    caller: LegMedia {
                        our_port: caller_port,
                        peer_addr,
                        learned: None,
                    },
                    callee: LegMedia {
                        our_port: callee_port,
                        peer_addr: String::new(),
                        learned: None,
                    },
                }),
                None => {
                    let response = tagged(
                        make_response(&request, 503, "Service Unavailable"),
                        &self.fresh_tag(),
                    );
                    let actions = caller_tx.on_response_from_user(response, now_ms);
                    push_sends(&mut outputs, actions);
                    outputs.push(Output::CallLog(call_log_line(
                        &caller_number,
                        &callee_number,
                        now_ms,
                        now_ms,
                        "no-media",
                    )));
                    return outputs;
                }
            },
            None => None,
        };
        let callee_body = match &media {
            Some(media) => media::audio_sdp(&self.config.rtp_host, media.callee.our_port),
            None => Vec::new(),
        };

        let caller_uri = header(&request.headers, "from")
            .map(uri_of)
            .unwrap_or("")
            .to_string();
        let caller_tag = header(&request.headers, "from")
            .and_then(tag_of)
            .unwrap_or("")
            .to_string();
        let caller_contact = header(&request.headers, "contact")
            .map(uri_of)
            .unwrap_or("")
            .to_string();

        // B2BUA: a brand-new leg toward the callee.
        let our_caller_tag = self.fresh_tag();
        let callee_invite =
            self.build_callee_invite(&request, &caller_uri, &callee_contact, callee_body);
        let callee_call_id = header(&callee_invite.headers, "call-id")
            .unwrap_or("")
            .to_string();
        let callee_from_tag = header(&callee_invite.headers, "from")
            .and_then(tag_of)
            .unwrap_or("")
            .to_string();

        let (callee_tx, actions) = ClientTransaction::new(callee_invite.clone(), now_ms);
        push_sends(&mut outputs, actions);

        let caller_dialog = Dialog::new(
            &caller_call_id,
            &request.uri, // our side is the address of record being called
            &our_caller_tag,
            &caller_uri,
            &caller_tag,
            &caller_contact,
        );
        let mut callee_dialog = Dialog::new(
            &callee_call_id,
            &caller_uri,
            &callee_from_tag,
            &request.uri,
            "",
            &callee_contact,
        );
        // The INVITE took CSeq 1; the next request we send down this leg
        // (BYE) must be 2 (RFC 3261 §12.2.1.1).
        callee_dialog.local_cseq = 1;

        self.next_call += 1;
        let id = self.next_call;
        self.by_call_id.insert(caller_call_id.clone(), id);
        self.by_call_id.insert(callee_call_id.clone(), id);
        self.calls.insert(
            id,
            CallCtx {
                state: CallState::Offering,
                logged: false,
                caller_number,
                callee_number,
                caller_call_id,
                callee_call_id,
                caller_invite: request,
                caller_tx,
                caller_dialog,
                callee_tx: Some(callee_tx),
                callee_invite: Some(callee_invite),
                callee_dialog: Some(callee_dialog),
                callee_ack: None,
                server_txs: Vec::new(),
                client_txs: Vec::new(),
                media,
                started_ms: now_ms,
                outcome: "no-answer".to_string(),
            },
        );
        outputs
    }

    /// A re-INVITE inside a dialog: answer it, keeping the session as it is
    /// (docs/07). Real peers send these for session refresh.
    fn handle_reinvite(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        let Some((id, leg)) = self.find_leg(&request) else {
            return vec![];
        };
        let mut outputs = Vec::new();
        let (mut tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        push_sends(&mut outputs, actions);

        let (our_tag, our_port) = {
            let Some(call) = self.calls.get(&id) else {
                return outputs;
            };
            let dialog = match leg {
                Leg::Caller => &call.caller_dialog,
                Leg::Callee => call.callee_dialog.as_ref().expect("matched"),
            };
            let port = call.media.as_ref().map(|media| match leg {
                Leg::Caller => media.caller.our_port,
                Leg::Callee => media.callee.our_port,
            });
            (dialog.local_tag.clone(), port)
        };

        let mut response = tagged(make_response(&request, 200, "OK"), &our_tag);
        if !request.body.is_empty() {
            if let Some(port) = our_port {
                let offered = sdp_payload_types(&request.body);
                response.headers.push(Header {
                    name: "Content-Type".to_string(),
                    value: "application/sdp".to_string(),
                });
                response.body = media::audio_sdp_answer(&self.config.rtp_host, port, &offered);
            }
        }
        let actions = tx.on_response_from_user(response, now_ms);
        push_sends(&mut outputs, actions);
        if let Some(call) = self.calls.get_mut(&id) {
            call.server_txs.push(tx);
        }
        outputs
    }

    // ----- in-dialog traffic ----------------------------------------------

    fn handle_response(&mut self, response: Response, now_ms: u64) -> Vec<Output> {
        let Some(id) = self
            .calls
            .iter()
            .find(|(_, call)| {
                call.callee_tx
                    .as_ref()
                    .map(|tx| tx.matches_response(&response))
                    .unwrap_or(false)
            })
            .map(|(id, _)| *id)
        else {
            // A retransmitted 2xx after our INVITE transaction finished:
            // re-send our ACK (RFC 3261 §13.2.2.4).
            return self.re_ack(&response);
        };
        let Some(call) = self.calls.get_mut(&id) else {
            return vec![];
        };
        let finished = call
            .callee_tx
            .as_ref()
            .map(|tx| tx.is_finished())
            .unwrap_or(true);
        if finished {
            // Only a retransmitted 2xx still needs an answer from us.
            return self.re_ack(&response);
        }
        let Some(transaction) = call.callee_tx.as_mut() else {
            return vec![];
        };
        let actions = transaction.on_response(response, now_ms);
        self.apply_actions(&id, actions, now_ms)
    }

    /// Re-ACKs a retransmitted 2xx for a call we still hold.
    fn re_ack(&mut self, response: &Response) -> Vec<Output> {
        if response.status < 200 || response.status >= 300 {
            return vec![];
        }
        let call_id = header(&response.headers, "call-id").unwrap_or("");
        let Some(&id) = self.by_call_id.get(call_id) else {
            return vec![];
        };
        let Some(call) = self.calls.get_mut(&id) else {
            return vec![];
        };
        match &call.callee_ack {
            Some(ack) => vec![Output::Send(Message::Request(ack.clone()))],
            None => vec![],
        }
    }

    fn handle_ack(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        // A non-2xx ACK shares its INVITE's branch; find that transaction and
        // let it finish (Timer I). A 2xx ACK is its own transaction and needs
        // no state here.
        let Some(&id) = self
            .by_call_id
            .get(header(&request.headers, "call-id").unwrap_or(""))
        else {
            return vec![];
        };
        let Some(call) = self.calls.get_mut(&id) else {
            return vec![];
        };
        let mut actions = call.caller_tx.on_ack(now_ms);
        for tx in &mut call.server_txs {
            if tx.branch().is_some() && tx.branch() == sip_stack::branch(&request.headers) {
                actions.extend(tx.on_ack(now_ms));
            }
        }
        self.apply_actions(&id, actions, now_ms)
    }

    fn handle_bye(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        let mut outputs = Vec::new();
        let Some((id, leg)) = self.find_leg(&request) else {
            let response = make_response(&request, 481, "Call/Transaction Does Not Exist");
            return vec![Output::Send(Message::Response(response))];
        };

        // Answer the BYE on its own transaction (retransmission-safe).
        let (mut tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        push_sends(&mut outputs, actions);
        let actions = tx.on_response_from_user(make_response(&request, 200, "OK"), now_ms);
        push_sends(&mut outputs, actions);
        if let Some(call) = self.calls.get_mut(&id) {
            call.server_txs.push(tx);
            if call.state == CallState::Answered {
                call.outcome = "completed".to_string();
            }
        }

        let event = match leg {
            Leg::Caller => CallEvent::CallerHungUp,
            Leg::Callee => CallEvent::CalleeHungUp,
        };
        let actions = self.event_on(&id, event, now_ms);
        outputs.extend(self.apply_actions(&id, actions, now_ms));
        outputs.extend(self.settle(&id, now_ms));
        self.gc();
        outputs
    }

    fn handle_cancel(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        let mut outputs = Vec::new();
        let call_id = header(&request.headers, "call-id").unwrap_or("");
        let Some(&id) = self.by_call_id.get(call_id) else {
            let response = make_response(&request, 481, "Call/Transaction Does Not Exist");
            return vec![Output::Send(Message::Response(response))];
        };

        // Answer the CANCEL itself.
        let (mut tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        push_sends(&mut outputs, actions);
        let actions = tx.on_response_from_user(make_response(&request, 200, "OK"), now_ms);
        push_sends(&mut outputs, actions);
        let Some(call) = self.calls.get_mut(&id) else {
            return outputs;
        };
        call.server_txs.push(tx);

        if !matches!(call.state, CallState::Offering | CallState::Ringing) {
            return outputs; // too late to cancel; the call stands
        }
        call.outcome = "cancelled".to_string();
        let actions = self.event_on(&id, CallEvent::CallerCancelled, now_ms);
        outputs.extend(self.apply_actions(&id, actions, now_ms));
        outputs.extend(self.settle(&id, now_ms));
        self.gc();
        outputs
    }

    // ----- media ----------------------------------------------------------

    /// RTP arrived on one of our relay ports: forward it down the other leg.
    ///
    /// The transparent pipe (docs/02 §8): the packet's bytes go out unchanged.
    /// Garbage in, nothing out.
    pub fn on_rtp(&mut self, local_port: u16, from: &str, data: &[u8]) -> Vec<Output> {
        let Ok(packet) = rtp::Packet::parse(data) else {
            return vec![];
        };
        let Some((id, leg)) = self.find_media_port(local_port) else {
            return vec![];
        };
        let Some(call) = self.calls.get_mut(&id) else {
            return vec![];
        };
        let Some(media) = call.media.as_mut() else {
            return vec![];
        };
        let (source, target) = match leg {
            Leg::Caller => (&mut media.caller, &media.callee),
            Leg::Callee => (&mut media.callee, &media.caller),
        };
        // Symmetric RTP: whoever speaks is where their media goes back to.
        source.learned = Some(from.to_string());
        let Some(to) = target.send_to() else {
            return vec![]; // the other side has not spoken yet
        };
        vec![Output::SendRtp {
            from_port: target.our_port,
            to,
            data: packet.to_bytes().to_vec(),
        }]
    }

    fn find_media_port(&self, local_port: u16) -> Option<(u64, Leg)> {
        self.calls.iter().find_map(|(id, call)| {
            let media = call.media.as_ref()?;
            if media.caller.our_port == local_port {
                Some((*id, Leg::Caller))
            } else if media.callee.our_port == local_port {
                Some((*id, Leg::Callee))
            } else {
                None
            }
        })
    }

    fn allocate_media_ports(&mut self) -> Option<(u16, u16)> {
        let caller = *self.free_rtp_ports.iter().next()?;
        self.free_rtp_ports.remove(&caller);
        let callee = *self.free_rtp_ports.iter().next()?;
        self.free_rtp_ports.remove(&callee);
        Some((caller, callee))
    }

    // ----- the call state machine ------------------------------------------

    /// Turns transaction actions into outputs and feeds resulting call events
    /// back into the state machine.
    fn apply_actions(&mut self, id: &u64, actions: Vec<Action>, now_ms: u64) -> Vec<Output> {
        let mut outputs = Vec::new();
        for action in actions {
            match action {
                Action::Send(message) => outputs.push(Output::Send(message)),
                Action::DeliverResponse(response) => {
                    // Learn their dialog bits while we are at it.
                    if let Some(call) = self.calls.get_mut(id) {
                        if let Some(tag) = tag_of(header(&response.headers, "to").unwrap_or("")) {
                            if let Some(dialog) = call.callee_dialog.as_mut() {
                                dialog.remote_tag = tag.to_string();
                            }
                        }
                        if response.status >= 200 {
                            if let Some(contact) = header(&response.headers, "contact") {
                                if let Some(dialog) = call.callee_dialog.as_mut() {
                                    dialog.remote_target = uri_of(contact).to_string();
                                }
                            }
                            // Where their media lives (from their SDP).
                            if let Some(peer_addr) = media_target(&response.body) {
                                if let Some(media) = call.media.as_mut() {
                                    media.callee.peer_addr = peer_addr;
                                }
                            }
                        }
                    }
                    if response.status == 100 {
                        continue; // hop-by-hop; never shown to the caller
                    }
                    let event = if response.status < 200 {
                        CallEvent::CalleeProgress(response.status)
                    } else if response.status < 300 {
                        // ACK for the 2xx (new transaction, §13.2.2.4).
                        let ack = self.calls.get(id).and_then(|call| {
                            let invite = call.callee_invite.as_ref()?;
                            Some(ack_for_2xx(
                                invite,
                                &response,
                                &self.via("ack"),
                                &self.config.pbx_contact.clone(),
                            ))
                        });
                        if let Some(ack) = ack {
                            if let Some(call) = self.calls.get_mut(id) {
                                call.callee_ack = Some(ack.clone());
                            }
                            outputs.push(Output::Send(Message::Request(ack)));
                        }
                        CallEvent::CalleeAnswered
                    } else {
                        if let Some(call) = self.calls.get_mut(id) {
                            call.outcome = format!("rejected:{}", response.status);
                        }
                        CallEvent::CalleeRejected(response.status)
                    };
                    let actions = self.event_on(id, event, now_ms);
                    outputs.extend(self.apply_actions(id, actions, now_ms));
                }
                Action::DeliverRequest(_) => {}
                Action::Timeout => {
                    if let Some(call) = self.calls.get_mut(id) {
                        call.outcome = "no-answer".to_string();
                    }
                    let actions = self.event_on(id, CallEvent::CalleeTimeout, now_ms);
                    outputs.extend(self.apply_actions(id, actions, now_ms));
                }
                Action::Done => {}
            }
        }
        outputs
    }

    /// Runs one call event through the state machine, expanding the commands
    /// it returns into transaction actions.
    fn event_on(&mut self, id: &u64, event: CallEvent, now_ms: u64) -> Vec<Action> {
        let Some(call) = self.calls.get_mut(id) else {
            return vec![];
        };
        let prior = call.state;
        let (state, commands) = transit(call.state, event);
        call.state = state;
        // How the call ends depends on how far it got.
        if state == CallState::Terminating {
            match event {
                CallEvent::CallerHungUp | CallEvent::CalleeHungUp => {
                    call.outcome = if prior == CallState::Answered {
                        "completed".to_string()
                    } else {
                        "cancelled".to_string()
                    };
                }
                CallEvent::CallerCancelled => call.outcome = "cancelled".to_string(),
                _ => {}
            }
        }
        let mut actions = Vec::new();
        for command in commands {
            actions.extend(self.command_actions(id, command, now_ms));
        }
        actions
    }

    /// Turns one semantic command into the SIP actions that carry it out.
    fn command_actions(&mut self, id: &u64, command: Command, now_ms: u64) -> Vec<Action> {
        let contact = self.config.pbx_contact.clone();
        let rtp_host = self.config.rtp_host.clone();
        let via = self.via("bye");
        let Some(call) = self.calls.get_mut(id) else {
            return vec![];
        };
        match command {
            Command::ProgressCaller(code) => {
                let response = tagged(
                    make_response(&call.caller_invite, code, reason_phrase(code)),
                    &call.caller_dialog.local_tag.clone(),
                );
                call.caller_tx.on_response_from_user(response, now_ms)
            }
            Command::AnswerCaller => {
                let mut response = tagged(
                    make_response(&call.caller_invite, 200, "OK"),
                    &call.caller_dialog.local_tag.clone(),
                );
                response.headers.push(Header {
                    name: "Contact".to_string(),
                    value: contact,
                });
                if let Some(media) = &call.media {
                    let offered = sdp_payload_types(&call.caller_invite.body);
                    response.headers.push(Header {
                        name: "Content-Type".to_string(),
                        value: "application/sdp".to_string(),
                    });
                    response.body =
                        media::audio_sdp_answer(&rtp_host, media.caller.our_port, &offered);
                }
                call.caller_tx.on_response_from_user(response, now_ms)
            }
            Command::FailCaller(status) => {
                let response = tagged(
                    make_response(&call.caller_invite, status, reason_phrase(status)),
                    &call.caller_dialog.local_tag.clone(),
                );
                call.caller_tx.on_response_from_user(response, now_ms)
            }
            Command::CancelCaller => {
                // 200 for the CANCEL already went out; reject the INVITE and
                // cancel the leg toward the callee (with a real transaction,
                // so a lost CANCEL is retried).
                let mut actions = Vec::new();
                let response = tagged(
                    make_response(&call.caller_invite, 487, "Request Terminated"),
                    &call.caller_dialog.local_tag.clone(),
                );
                actions.extend(call.caller_tx.on_response_from_user(response, now_ms));
                if let Some(invite) = &call.callee_invite {
                    let (tx, tx_actions) = ClientTransaction::new(cancel_for(invite), now_ms);
                    if let Some(call) = self.calls.get_mut(id) {
                        call.client_txs.push(tx);
                    }
                    actions.extend(tx_actions);
                }
                actions
            }
            Command::ByeCallee | Command::ByeCaller => {
                let request = match command {
                    Command::ByeCallee => call
                        .callee_dialog
                        .as_mut()
                        .map(|dialog| dialog.request(Method::Bye, &via, &contact)),
                    _ => Some(call.caller_dialog.request(Method::Bye, &via, &contact)),
                };
                match request {
                    Some(request) => {
                        let (tx, actions) = ClientTransaction::new(request, now_ms);
                        if let Some(call) = self.calls.get_mut(id) {
                            call.client_txs.push(tx);
                        }
                        actions
                    }
                    None => vec![],
                }
            }
            Command::CompleteCaller | Command::CompleteCallee => vec![], // answered as requests arrive
            Command::Finish => vec![],                                   // handled by settle()
        }
    }

    /// When a call reaches `Terminating`, runs the final transition: the call
    /// log line is written once and media ports return to the pool. The call
    /// record itself stays until its transactions finish.
    fn settle(&mut self, id: &u64, now_ms: u64) -> Vec<Output> {
        let Some(call) = self.calls.get_mut(id) else {
            return vec![];
        };
        if call.state != CallState::Terminating {
            return vec![];
        }
        call.state = CallState::Terminated;
        let mut outputs = Vec::new();
        if !call.logged {
            call.logged = true;
            outputs.push(Output::CallLog(call_log_line(
                &call.caller_number,
                &call.callee_number,
                call.started_ms,
                now_ms,
                &call.outcome,
            )));
        }
        if let Some(media) = call.media.take() {
            self.free_rtp_ports.insert(media.caller.our_port);
            self.free_rtp_ports.insert(media.callee.our_port);
        }
        outputs
    }

    /// Drops calls whose transactions have all finished (they exist only to
    /// answer late retransmissions).
    fn gc(&mut self) {
        let finished: Vec<u64> = self
            .calls
            .iter()
            .filter(|(_, call)| {
                call.state == CallState::Terminated
                    && call.caller_tx.is_finished()
                    && call.callee_tx.as_ref().is_none_or(|tx| tx.is_finished())
                    && call.server_txs.iter().all(|tx| tx.is_finished())
                    && call.client_txs.iter().all(|tx| tx.is_finished())
            })
            .map(|(id, _)| *id)
            .collect();
        for id in finished {
            if let Some(call) = self.calls.remove(&id) {
                self.by_call_id.remove(&call.caller_call_id);
                self.by_call_id.remove(&call.callee_call_id);
            }
        }
    }

    /// Which leg of which call an in-dialog request belongs to.
    fn find_leg(&self, request: &Request) -> Option<(u64, Leg)> {
        let call_id = header(&request.headers, "call-id").unwrap_or("");
        let from_tag = header(&request.headers, "from")
            .and_then(tag_of)
            .unwrap_or("");
        let to_tag = header(&request.headers, "to")
            .and_then(tag_of)
            .unwrap_or("");
        let id = *self.by_call_id.get(call_id)?;
        let call = self.calls.get(&id)?;
        if call.caller_dialog.matches(call_id, from_tag, to_tag) {
            return Some((id, Leg::Caller));
        }
        match &call.callee_dialog {
            Some(dialog) if dialog.matches(call_id, from_tag, to_tag) => Some((id, Leg::Callee)),
            _ => None,
        }
    }

    fn build_callee_invite(
        &mut self,
        caller_invite: &Request,
        caller_uri: &str,
        callee_contact: &str,
        body: Vec<u8>,
    ) -> Request {
        let callee_aor = caller_invite.uri.clone();
        let from_tag = self.fresh_tag();
        Request {
            method: Method::Invite,
            uri: callee_contact.to_string(),
            headers: vec![
                Header {
                    name: "Via".to_string(),
                    value: self.via("invite"),
                },
                Header {
                    name: "Max-Forwards".to_string(),
                    value: "70".to_string(),
                },
                Header {
                    name: "From".to_string(),
                    value: format!("<{caller_uri}>;tag={from_tag}"),
                },
                Header {
                    name: "To".to_string(),
                    value: format!("<{callee_aor}>"),
                },
                Header {
                    name: "Call-ID".to_string(),
                    value: self.fresh_call_id(),
                },
                Header {
                    name: "CSeq".to_string(),
                    value: "1 INVITE".to_string(),
                },
                Header {
                    name: "Contact".to_string(),
                    value: self.config.pbx_contact.clone(),
                },
                Header {
                    name: "Content-Type".to_string(),
                    value: "application/sdp".to_string(),
                },
            ],
            body,
        }
    }

    fn fresh_tag(&mut self) -> String {
        self.next_tag += 1;
        format!("pbx{:06}", self.next_tag)
    }

    fn fresh_call_id(&mut self) -> String {
        format!(
            "pbx-call-{:06}@{}",
            self.next_call + 1,
            self.config.pbx_host
        )
    }

    fn via(&self, what: &str) -> String {
        format!(
            "SIP/2.0/UDP {};branch=z9hG4bK-{}-{:06}-{:x}",
            self.config.pbx_host,
            what,
            self.next_call + 1,
            self.next_tag
        )
    }
}

// ----- free functions -------------------------------------------------------

fn timer_name(id: u64, slot: TxSlot, timer: Timer) -> String {
    let slot = match slot {
        TxSlot::Caller => "caller".to_string(),
        TxSlot::Callee => "callee".to_string(),
        TxSlot::Server(index) => format!("s{index}"),
        TxSlot::Client(index) => format!("c{index}"),
    };
    format!("t:{id}:{slot}:{timer:?}")
}

fn parse_timer_name(name: &str) -> Option<(u64, TxSlot, Timer)> {
    let mut parts = name.split(':');
    if parts.next()? != "t" {
        return None;
    }
    let id = parts.next()?.parse().ok()?;
    let slot = match parts.next()? {
        "caller" => TxSlot::Caller,
        "callee" => TxSlot::Callee,
        other => match (other.as_bytes().first(), other[1..].parse().ok()) {
            (Some(b's'), Some(index)) => TxSlot::Server(index),
            (Some(b'c'), Some(index)) => TxSlot::Client(index),
            _ => return None,
        },
    };
    let timer = match parts.next()? {
        "A" => Timer::A,
        "B" => Timer::B,
        "D" => Timer::D,
        "E" => Timer::E,
        "F" => Timer::F,
        "G" => Timer::G,
        "H" => Timer::H,
        "I" => Timer::I,
        "J" => Timer::J,
        "K" => Timer::K,
        "L" => Timer::L,
        _ => return None,
    };
    Some((id, slot, timer))
}

/// Payload type numbers an SDP body offers, for codec intersection.
fn sdp_payload_types(body: &[u8]) -> Vec<u8> {
    parse_sdp(body)
        .ok()
        .map(|sdp| {
            sdp.media
                .iter()
                .filter(|media| media.media == "audio")
                .flat_map(|media| media.payload_types.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// The media address ("ip:port") an SDP body offers for audio, if any.
fn media_target(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let sdp = parse_sdp(body).ok()?;
    let audio = sdp.media.iter().find(|media| media.media == "audio")?;
    let connection = audio.connection.as_ref()?;
    if connection.is_empty() || audio.port == 0 {
        return None;
    }
    Some(format!("{connection}:{}", audio.port))
}

fn call_log_line(
    caller: &str,
    callee: &str,
    started_ms: u64,
    ended_ms: u64,
    result: &str,
) -> String {
    format!(
        "{{\"caller\":\"{}\",\"callee\":\"{}\",\"started_ms\":{started_ms},\"ended_ms\":{ended_ms},\"result\":\"{}\"}}",
        json_escape(caller),
        json_escape(callee),
        json_escape(result),
    )
}

/// Escapes a string for one JSON value (call-log injection protection).
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn push_sends(outputs: &mut Vec<Output>, actions: Vec<Action>) {
    for action in actions {
        if let Action::Send(message) = action {
            outputs.push(Output::Send(message));
        }
    }
}

fn tagged(mut response: Response, tag: &str) -> Response {
    for header in &mut response.headers {
        if canonical_header(&header.name) == "to" {
            header.value = with_tag(&header.value, tag);
        }
    }
    response
}

/// The CANCEL for an INVITE we sent: same Via branch, same CSeq number,
/// method CANCEL (RFC 3261 §9.1).
fn cancel_for(invite: &Request) -> Request {
    let mut headers: Vec<Header> = invite
        .headers
        .iter()
        .filter(|header| {
            matches!(
                canonical_header(&header.name).as_str(),
                "via" | "max-forwards" | "from" | "to" | "call-id"
            )
        })
        .cloned()
        .collect();
    let number = header(&invite.headers, "cseq")
        .and_then(|cseq| cseq.split_whitespace().next())
        .unwrap_or("1");
    headers.push(Header {
        name: "CSeq".to_string(),
        value: format!("{number} CANCEL"),
    });
    Request {
        method: Method::Cancel,
        uri: invite.uri.clone(),
        headers,
        body: Vec::new(),
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Trying",
        180 => "Ringing",
        183 => "Session Progress",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        481 => "Call/Transaction Does Not Exist",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        500 => "Server Internal Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}
