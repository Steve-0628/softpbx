//! The PBX core: routes calls between registered devices (docs/02 §2, docs/03).
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

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use sip_stack::{
    ack_for_2xx, cseq_parts, make_response, tag_of, uri_of, with_tag, Action, ClientTransaction,
    Dialog, ServerState, ServerTransaction, Timer,
};
use sip_syntax::{
    canonical_header, parse_sdp, Direction, Header, Message, Method, Request, Response,
};

use crate::call::{transit, CallEvent, CallState, Command};
use crate::interfaces::{interface_for, Interface};
use crate::registration::{header, number_from_uri, Device, Registrar};
use crate::routing::{route, Destination, Rule};

/// How long a call may go without media before we call it dead (docs/04).
pub const MEDIA_TIMEOUT_MS: u64 = 120_000;

/// The methods we implement (docs/07); anything else gets `405` + `Allow`.
pub const ALLOW: &str = "INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS";

/// A trunk to another PBX (docs/06 §1): a peer we send calls to and accept
/// calls from. Identified by its address — no registration involved.
#[derive(Debug, Clone)]
pub struct TrunkConfig {
    /// Label used in routing rules and logs ("mikopbx").
    pub name: String,
    /// Where its SIP messages come from, and where we send ours.
    pub peer: SocketAddr,
    /// Digest credentials, for peers that challenge our INVITEs (RFC 2617).
    pub username: Option<String>,
    pub secret: Option<String>,
}

/// Everything the switch needs to know from the config file.
#[derive(Debug, Clone)]
pub struct SwitchConfig {
    /// Realm used in digest challenges.
    pub realm: String,
    /// Our local addresses, one per network we serve (docs/02 §4). Each peer
    /// is served from the interface whose network holds its address: that
    /// interface's addresses are the ones it sees in Via, Contact and SDP.
    pub interfaces: Vec<Interface>,
    /// First media relay port.
    pub rtp_port_base: u16,
    /// How many media ports are available (two per concurrent call).
    pub rtp_ports: u16,
    /// Call routing rules, in order (docs/03 §4). Empty = "the dialed number
    /// rings the device that has it".
    pub routing: Vec<Rule>,
    /// Trunks to other PBXs (docs/06 §1).
    pub trunks: Vec<TrunkConfig>,
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
    /// Whether this side's media is relayed to the other leg: its SDP says
    /// it sends (`sendrecv`/`sendonly`). A side on hold may still send —
    /// its hold music must reach the far side.
    sends: bool,
    /// Whether media from the other leg is relayed to it: its SDP says it
    /// receives, and its stream is not declined.
    receives: bool,
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
    /// Payload types the callee's answer committed the bridge to. Both legs
    /// must run the same codec: the relay does not transcode (docs/02 §8).
    callee_payloads: Vec<u8>,
}

impl CallMedia {
    /// Whether some side is not fully sending and receiving — a hold in
    /// effect (RFC 3264 §6).
    fn held(&self) -> bool {
        let full = |leg: &LegMedia| leg.sends && leg.receives;
        !(full(&self.caller) && full(&self.callee))
    }

    /// The payload types an answer toward the caller may contain: never wider
    /// than what the callee's answer committed to (RFC 3264 §6 still applies —
    /// and a codec the callee refused would be relayed as garbage).
    fn answerable_payloads(&self, offered: Vec<u8>) -> Vec<u8> {
        if self.callee_payloads.is_empty() {
            offered
        } else {
            offered
                .into_iter()
                .filter(|pt| self.callee_payloads.contains(pt))
                .collect()
        }
    }
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
    /// Which trunk the callee leg is on, if any.
    callee_trunk: Option<String>,
    /// The caller's address: which local interface serves that side.
    caller_peer: Option<IpAddr>,
    /// The callee's address: which local interface serves that side.
    callee_peer: Option<IpAddr>,
    /// Whether we already retried the INVITE with credentials.
    auth_retried: bool,
    /// Our ACK for the callee's 2xx; re-sent if they retransmit it.
    callee_ack: Option<Request>,
    /// When media last flowed (for the inactivity sweep).
    last_media_ms: u64,
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
    calls: BTreeMap<u64, CallCtx>,
    /// Both legs' Call-IDs → call.
    by_call_id: BTreeMap<String, u64>,
    next_tag: u64,
    next_call: u64,
    next_branch: u64,
    free_rtp_ports: BTreeSet<u16>,
}

impl Switch {
    /// Creates a switch for the given devices and addresses.
    pub fn new(config: SwitchConfig) -> Self {
        assert!(
            !config.interfaces.is_empty(),
            "a switch needs at least one local interface"
        );
        let registrar = Registrar::new(&config.realm, config.devices.clone());
        let free_rtp_ports =
            (config.rtp_port_base..config.rtp_port_base.saturating_add(config.rtp_ports)).collect();
        Switch {
            config,
            registrar,
            calls: BTreeMap::new(),
            by_call_id: BTreeMap::new(),
            next_tag: 0,
            next_call: 0,
            next_branch: 0,
            free_rtp_ports,
        }
    }

    /// Drops expired registrations (call occasionally; cheap).
    pub fn expire(&mut self, now_ms: u64) {
        self.registrar.expire(now_ms);
    }

    /// Tears down calls whose media went silent: endpoints that die without a
    /// BYE must not hold their relay ports forever (docs/04 "no leaks").
    /// Mirrors the peer-side `rtp_timeout` behavior we saw on MikoPBX.
    /// Held calls are exempt: silence is the point of a hold, so the
    /// inactivity clock restarts when media resumes.
    #[must_use = "the outputs are the BYEs and call log of the teardown; dispatch them"]
    pub fn sweep(&mut self, now_ms: u64) -> Vec<Output> {
        let stale: Vec<u64> = self
            .calls
            .iter()
            .filter(|(_, call)| {
                call.state == CallState::Answered
                    && call.media.as_ref().is_some_and(|media| !media.held())
                    && now_ms.saturating_sub(call.last_media_ms) >= MEDIA_TIMEOUT_MS
            })
            .map(|(id, _)| *id)
            .collect();
        let mut outputs = Vec::new();
        for id in stale {
            if let Some(call) = self.calls.get_mut(&id) {
                call.outcome = "media-timeout".to_string();
            }
            let actions = self.event_on(&id, CallEvent::MediaTimeout, now_ms);
            outputs.extend(self.apply_actions(&id, actions, now_ms));
            outputs.extend(self.settle(&id, now_ms));
        }
        self.gc();
        outputs
    }

    /// How many media ports are still free (leak checks in tests).
    pub fn free_media_ports(&self) -> usize {
        self.free_rtp_ports.len()
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
    #[must_use = "the outputs are SIP messages; dispatch them"]
    pub fn on_timer(&mut self, name: &str, now_ms: u64) -> Vec<Output> {
        let Some((id, slot, timer)) = parse_timer_name(name) else {
            return vec![];
        };
        let Some(call) = self.calls.get_mut(&id) else {
            return vec![];
        };
        // Ignore stale timer names: the transaction may have moved on (an auth
        // retry swaps it out from under a pending tick).
        let fresh = match slot {
            TxSlot::Caller => call.caller_tx.next_timer().map(|(_, t)| t) == Some(timer),
            TxSlot::Callee => {
                call.callee_tx
                    .as_ref()
                    .and_then(|tx| tx.next_timer())
                    .map(|(_, t)| t)
                    == Some(timer)
            }
            TxSlot::Server(index) => {
                call.server_txs
                    .get(index)
                    .and_then(|tx| tx.next_timer())
                    .map(|(_, t)| t)
                    == Some(timer)
            }
            TxSlot::Client(index) => {
                call.client_txs
                    .get(index)
                    .and_then(|tx| tx.next_timer())
                    .map(|(_, t)| t)
                    == Some(timer)
            }
        };
        if !fresh {
            return vec![];
        }
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

    /// Feeds one incoming SIP message; returns what to send and log. `from` is
    /// where the message arrived from (a trunk peer, a phone) — it decides
    /// admission, and which local address serves that side of a new call.
    #[must_use = "the outputs are SIP messages and call log; dispatch them"]
    pub fn handle(
        &mut self,
        message: Message,
        now_ms: u64,
        from: Option<SocketAddr>,
    ) -> Vec<Output> {
        let mut outputs = match message {
            Message::Request(request) => self.handle_request(request, now_ms, from),
            Message::Response(response) => self.handle_response(response, now_ms),
        };
        outputs.extend(self.collect_settled(now_ms));
        outputs
    }

    /// Whether this address belongs to one of our trunk peers (by IP: the
    /// port is where we *send*, not who they are — NAT rewrites source ports).
    pub fn is_trunk_peer(&self, address: SocketAddr) -> bool {
        self.config
            .trunks
            .iter()
            .any(|trunk| trunk.peer.ip() == address.ip())
    }

    /// The local interface that serves a peer's address (docs/02 §4): the
    /// most specific configured network containing it — the first interface
    /// when the address is unknown or in no network at all.
    fn local(&self, peer: Option<IpAddr>) -> &Interface {
        peer.and_then(|address| interface_for(&self.config.interfaces, address))
            .unwrap_or(&self.config.interfaces[0])
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

    fn handle_request(
        &mut self,
        request: Request,
        now_ms: u64,
        from: Option<SocketAddr>,
    ) -> Vec<Output> {
        // RFC 3261 §8.2.2.3: never half-implement an extension — anything the
        // request *requires* that we do not implement gets 420 + Unsupported.
        // The same section says Require MUST be *ignored* in ACK and CANCEL;
        // we extend that to BYE on purpose — teardown must never be blocked by
        // an extension we do not implement (docs/07 §2).
        let check_require = !matches!(request.method, Method::Ack | Method::Cancel | Method::Bye);
        let unsupported = if check_require {
            unsupported_require(&request)
        } else {
            Vec::new()
        };
        if !unsupported.is_empty() {
            return self.refuse(
                &request,
                420,
                "Bad Extension",
                Some(("Unsupported", &unsupported.join(", "))),
                now_ms,
            );
        }
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
            // An INVITE that *looks* in-dialog (To has a tag) but whose dialog
            // is gone gets 481 — it must never re-ring a number.
            Method::Invite if header(&request.headers, "to").and_then(tag_of).is_some() => self
                .refuse(
                    &request,
                    481,
                    "Call/Transaction Does Not Exist",
                    None,
                    now_ms,
                ),
            Method::Invite => self.handle_invite(request, now_ms, from),
            Method::Ack => self.handle_ack(request, now_ms),
            Method::Bye => self.handle_bye(request, now_ms),
            Method::Cancel => self.handle_cancel(request, now_ms),
            Method::Other(_) => self.refuse(
                &request,
                405,
                "Method Not Allowed",
                Some(("Allow", ALLOW)),
                now_ms,
            ),
        }
    }

    /// Refuses a request with a status through a real server transaction:
    /// retransmission-safe, and properly tagged (RFC 3261 §8.2.6.2).
    fn refuse(
        &mut self,
        request: &Request,
        status: u16,
        reason: &str,
        extra: Option<(&str, &str)>,
        now_ms: u64,
    ) -> Vec<Output> {
        let mut outputs = Vec::new();
        let (mut tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        push_sends(&mut outputs, actions);
        let mut response = tagged(make_response(request, status, reason), &self.fresh_tag());
        if let Some((name, value)) = extra {
            response.headers.push(Header {
                name: name.to_string(),
                value: value.to_string(),
            });
        }
        let actions = tx.on_response_from_user(response, now_ms);
        push_sends(&mut outputs, actions);
        outputs
    }

    // ----- call setup ------------------------------------------------------

    fn handle_invite(
        &mut self,
        request: Request,
        now_ms: u64,
        from: Option<SocketAddr>,
    ) -> Vec<Output> {
        let mut outputs = Vec::new();
        let caller_call_id = header(&request.headers, "call-id")
            .unwrap_or("")
            .to_string();

        // Same Call-ID as something we know?
        if let Some(&id) = self.by_call_id.get(&caller_call_id) {
            let Some(call) = self.calls.get_mut(&id) else {
                return outputs;
            };
            let same_transaction = call.caller_tx.branch().is_some()
                && call.caller_tx.branch() == sip_stack::branch(&request.headers);
            if same_transaction {
                // Retransmission: repeat our last response, never re-ring.
                let actions = call.caller_tx.on_request(&request);
                push_sends(&mut outputs, actions);
                return outputs;
            }
            if call.state != CallState::Terminated {
                // A live call and a different transaction: refuse politely —
                // never silence.
                return self.refuse(&request, 491, "Request Pending", None, now_ms);
            }
            // A stale retained call whose Call-ID is being reused: drop it and
            // treat this as a brand-new call.
            self.by_call_id.remove(&caller_call_id);
            self.calls.remove(&id);
        }

        let caller_number = header(&request.headers, "from")
            .map(uri_of)
            .and_then(number_from_uri)
            .unwrap_or_default();
        let dialed = number_from_uri(&request.uri).unwrap_or_default();
        let (mut caller_tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        push_sends(&mut outputs, actions);

        // RFC 3261 §8.1.1.8: an INVITE must carry a Contact — it is where we
        // send BYE later. Without one the call would be unhangupable.
        if header(&request.headers, "contact")
            .map(uri_of)
            .unwrap_or("")
            .is_empty()
        {
            let response = tagged(
                make_response(&request, 400, "Bad Request"),
                &self.fresh_tag(),
            );
            let actions = caller_tx.on_response_from_user(response, now_ms);
            push_sends(&mut outputs, actions);
            return outputs;
        }

        // Only registered devices may place calls (docs/02 §6, docs/07) —
        // except calls from a trunk peer, which is identified by its address
        // and does not register.
        let from_trunk = from
            .map(|address| self.is_trunk_peer(address))
            .unwrap_or(false);
        // A trunk caller may be anyone — but not *us*: an INVITE from a trunk
        // whose From claims one of our numbers in our own domain is
        // impersonation (docs/02 §6). The far side's own labels (its trunk
        // login in its own domain) are fine.
        if from_trunk {
            // "Our own domain" is any address we serve peers from.
            let claims_our_address = host_ip(header(&request.headers, "from").unwrap_or(""))
                .is_some_and(|address| {
                    self.config
                        .interfaces
                        .iter()
                        .any(|interface| interface.sip.ip() == address)
                });
            if claims_our_address
                && self
                    .config
                    .devices
                    .iter()
                    .any(|device| device.number == caller_number)
            {
                let response = tagged(make_response(&request, 403, "Forbidden"), &self.fresh_tag());
                let actions = caller_tx.on_response_from_user(response, now_ms);
                push_sends(&mut outputs, actions);
                outputs.push(Output::CallLog(call_log_line(
                    &caller_number,
                    &dialed,
                    now_ms,
                    now_ms,
                    "impersonation",
                )));
                return outputs;
            }
        }
        if !from_trunk && !self.registrar.is_registered(&caller_number, now_ms) {
            let response = tagged(make_response(&request, 403, "Forbidden"), &self.fresh_tag());
            let actions = caller_tx.on_response_from_user(response, now_ms);
            push_sends(&mut outputs, actions);
            outputs.push(Output::CallLog(call_log_line(
                &caller_number,
                &dialed,
                now_ms,
                now_ms,
                "unauthorized",
            )));
            return outputs;
        }

        // Call routing (docs/03 §4): where does this number go — a device
        // here, or a number down a trunk to another PBX?
        let mut callee_trunk: Option<String> = None;
        let (callee_number, callee_contact, callee_domain) =
            match route(&self.config.routing, &dialed) {
                Destination::Reject => {
                    let response =
                        tagged(make_response(&request, 403, "Forbidden"), &self.fresh_tag());
                    let actions = caller_tx.on_response_from_user(response, now_ms);
                    push_sends(&mut outputs, actions);
                    outputs.push(Output::CallLog(call_log_line(
                        &caller_number,
                        &dialed,
                        now_ms,
                        now_ms,
                        "restricted",
                    )));
                    return outputs;
                }
                Destination::Ring(number) => {
                    // Where does the call go?
                    let Some(contact) = self.registrar.lookup(&number, now_ms).map(str::to_string)
                    else {
                        let response =
                            tagged(make_response(&request, 404, "Not Found"), &self.fresh_tag());
                        let actions = caller_tx.on_response_from_user(response, now_ms);
                        push_sends(&mut outputs, actions);
                        // Failed calls are logged too: "why didn't my call go
                        // through".
                        outputs.push(Output::CallLog(call_log_line(
                            &caller_number,
                            &number,
                            now_ms,
                            now_ms,
                            "not-found",
                        )));
                        return outputs;
                    };
                    // The callee is served from the interface that holds its
                    // address; that interface is its domain.
                    let domain = self.local(host_ip(&contact)).sip.ip().to_string();
                    (number, contact, domain)
                }
                Destination::Trunk(name, number) => {
                    // Down the trunk: the peer routes the number itself, and
                    // the number lives in the peer's domain (docs/06 §1).
                    //
                    // Loop guard: a call that arrived *from* a trunk never
                    // goes back to the same one (overlapping number ranges
                    // between two PBXs would otherwise ping-pong forever).
                    if from
                        .map(|address| {
                            self.config
                                .trunks
                                .iter()
                                .any(|trunk| trunk.name == name && trunk.peer.ip() == address.ip())
                        })
                        .unwrap_or(false)
                    {
                        let response =
                            tagged(make_response(&request, 403, "Forbidden"), &self.fresh_tag());
                        let actions = caller_tx.on_response_from_user(response, now_ms);
                        push_sends(&mut outputs, actions);
                        outputs.push(Output::CallLog(call_log_line(
                            &caller_number,
                            &number,
                            now_ms,
                            now_ms,
                            "routing-loop",
                        )));
                        return outputs;
                    }
                    let Some(trunk) = self.config.trunks.iter().find(|trunk| trunk.name == name)
                    else {
                        let response = tagged(
                            make_response(&request, 503, "Service Unavailable"),
                            &self.fresh_tag(),
                        );
                        let actions = caller_tx.on_response_from_user(response, now_ms);
                        push_sends(&mut outputs, actions);
                        outputs.push(Output::CallLog(call_log_line(
                            &caller_number,
                            &number,
                            now_ms,
                            now_ms,
                            "unknown-trunk",
                        )));
                        return outputs;
                    };
                    callee_trunk = Some(trunk.name.clone());
                    (
                        number.clone(),
                        format!("sip:{number}@{}", trunk.peer),
                        trunk.peer.ip().to_string(),
                    )
                }
            };

        // RFC 3264 §6: never answer with a codec they did not offer. If the
        // offer shares none of ours, the call cannot carry audio — refuse it
        // instead of ringing into a dead line.
        let offered = sdp_payload_types(&request.body);
        if media_target(&request.body).is_some()
            && !offered.is_empty()
            && !offered
                .iter()
                .any(|pt| media::Codec::of_payload_type(*pt).is_some())
        {
            let response = tagged(
                make_response(&request, 488, "Not Acceptable Here"),
                &self.fresh_tag(),
            );
            let actions = caller_tx.on_response_from_user(response, now_ms);
            push_sends(&mut outputs, actions);
            outputs.push(Output::CallLog(call_log_line(
                &caller_number,
                &callee_number,
                now_ms,
                now_ms,
                "no-codec",
            )));
            return outputs;
        }

        // Media: if the caller offered audio, we relay it (docs/02 §8). The
        // offer's direction attributes say what the caller sends and
        // receives (RFC 3264 §6).
        let media = match media_target(&request.body) {
            Some(peer_addr) => match self.allocate_media_ports() {
                Some((caller_port, callee_port)) => {
                    let (sends, receives) = media_stance(&request.body).unwrap_or((true, true));
                    Some(CallMedia {
                        caller: LegMedia {
                            our_port: caller_port,
                            peer_addr,
                            learned: None,
                            sends,
                            receives,
                        },
                        callee: LegMedia {
                            our_port: callee_port,
                            peer_addr: String::new(),
                            learned: None,
                            sends: true,
                            receives: true,
                        },
                        callee_payloads: Vec::new(),
                    })
                }
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
        // Both legs must end up on one codec (the relay does not transcode),
        // so the offer toward the callee is what the caller offered, narrowed
        // to what we support — never our full set. The media address in it is
        // the one the callee's network reaches us on.
        let callee_peer = host_ip(&callee_contact);
        let callee_body = match &media {
            Some(media) => media::audio_sdp_offer(
                &self.local(callee_peer).rtp.to_string(),
                media.callee.our_port,
                &offered,
            ),
            None => Vec::new(),
        };

        let caller_uri = header(&request.headers, "from")
            .map(uri_of)
            .unwrap_or("")
            .to_string();
        let caller_display = header(&request.headers, "from")
            .map(sip_stack::display_name)
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

        // Each side is served from the interface that holds its address
        // (docs/02 §4): the source of their messages wins, their Contact
        // stands in when we were not told.
        let caller_peer = from
            .map(|address| address.ip())
            .or_else(|| host_ip(&caller_contact));

        // The callee's address of record is the *routed* number, not whatever
        // was dialed (docs/03 §4).
        let callee_aor = format!("sip:{callee_number}@{callee_domain}");

        // B2BUA: a brand-new leg toward the callee.
        let our_caller_tag = self.fresh_tag();
        let callee_invite = self.build_callee_invite(
            &callee_aor,
            &caller_uri,
            &caller_display,
            &callee_contact,
            callee_body,
            self.local(callee_peer).sip,
        );
        let callee_call_id = header(&callee_invite.headers, "call-id")
            .unwrap_or("")
            .to_string();
        let callee_from_tag = header(&callee_invite.headers, "from")
            .and_then(tag_of)
            .unwrap_or("")
            .to_string();

        let (callee_tx, actions) = ClientTransaction::new(callee_invite.clone(), now_ms);
        push_sends(&mut outputs, actions);

        let caller_to_uri = header(&request.headers, "to").map(uri_of).unwrap_or("");
        let mut caller_dialog = Dialog::new(
            &caller_call_id,
            caller_to_uri, // §12.2.1.1: our side is the request's To URI
            &our_caller_tag,
            &caller_uri,
            &caller_tag,
            &caller_contact,
        );
        // The INVITE opened the dialog, so its CSeq is the remote sequence
        // number everything from the caller must beat (RFC 3261 §12.2.2).
        caller_dialog.remote_cseq = cseq_number_of(&request);
        let mut callee_dialog = Dialog::new(
            &callee_call_id,
            &caller_uri,
            &callee_from_tag,
            &callee_aor,
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
                callee_trunk,
                caller_peer,
                callee_peer,
                auth_retried: false,
                callee_ack: None,
                last_media_ms: now_ms,
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
        // A retransmission gets our last response again (§17.2) — never a
        // second answer and never a fresh look at its CSeq.
        if let Some(call) = self.calls.get_mut(&id) {
            if let Some(tx) = call
                .server_txs
                .iter_mut()
                .find(|tx| tx.matches_request(&request))
            {
                let mut outputs = Vec::new();
                push_sends(&mut outputs, tx.on_request(&request));
                return outputs;
            }
        }
        // Only a live call can be refreshed; a re-INVITE after teardown gets
        // 481 (no dead-session resurrections).
        if self
            .calls
            .get(&id)
            .is_none_or(|call| call.state != CallState::Answered)
        {
            let response = make_response(&request, 481, "Call/Transaction Does Not Exist");
            return vec![Output::Send(Message::Response(response))];
        }
        // RFC 3261 §12.2.2: a request whose CSeq is not higher than the last
        // one from that side is out of order and gets 500 — it must not drag
        // media or signaling targets back to where an older request left them.
        if !self.accept_remote_cseq(&id, leg, &request) {
            return self.refuse(&request, 500, "Server Internal Error", None, now_ms);
        }
        let mut outputs = Vec::new();
        let (mut tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        push_sends(&mut outputs, actions);

        let (our_tag, our_port, peer) = {
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
            let peer = match leg {
                Leg::Caller => call.caller_peer,
                Leg::Callee => call.callee_peer,
            };
            (dialog.local_tag.clone(), port, peer)
        };

        // A re-INVITE may also move their signaling target (Contact).
        if let Some(contact) = header(&request.headers, "contact") {
            let target = uri_of(contact).to_string();
            if !target.is_empty() {
                if let Some(call) = self.calls.get_mut(&id) {
                    match leg {
                        Leg::Caller => call.caller_dialog.remote_target = target,
                        Leg::Callee => {
                            if let Some(dialog) = call.callee_dialog.as_mut() {
                                dialog.remote_target = target;
                            }
                        }
                    }
                }
            }
        }

        // A re-INVITE that moves media moves our relay target with it, and
        // its direction attributes (RFC 3264 §6) say what this side sends
        // and receives. A hold stops only the direction *toward* the held
        // side — the holder's own media (its hold music) still reaches the
        // far side — and a resumed side starts the pair flowing again.
        if !request.body.is_empty() {
            let moved = media_target(&request.body);
            let stance = media_stance(&request.body);
            if moved.is_some() || stance.is_some() {
                if let Some(call) = self.calls.get_mut(&id) {
                    let mut resumed = false;
                    if let Some(media) = call.media.as_mut() {
                        let was_held = media.held();
                        let leg = match leg {
                            Leg::Caller => &mut media.caller,
                            Leg::Callee => &mut media.callee,
                        };
                        if let Some(address) = moved {
                            leg.peer_addr = address;
                            leg.learned = None;
                        }
                        if let Some((sends, receives)) = stance {
                            leg.sends = sends;
                            leg.receives = receives;
                        }
                        resumed = was_held && !media.held();
                    }
                    if resumed {
                        // Media flows again: restart the inactivity clock, or
                        // a call held longer than the timeout dies on resume.
                        call.last_media_ms = now_ms;
                    }
                }
            }
        }

        let mut response = tagged(make_response(&request, 200, "OK"), &our_tag);
        if !request.body.is_empty() {
            let rtp_host = self.local(peer).rtp.to_string();
            if stream_withdrawn(&request.body) {
                // A withdrawn stream is mirrored as withdrawn (RFC 3264 §6).
                response.headers.push(Header {
                    name: "Content-Type".to_string(),
                    value: "application/sdp".to_string(),
                });
                response.body = media::declined_sdp(&rtp_host);
            } else if let Some(port) = our_port {
                let offered = sdp_payload_types(&request.body);
                // The same rule as the answer at setup: never widen past what
                // the other leg is running.
                let answer = match self.calls.get(&id).and_then(|call| call.media.as_ref()) {
                    Some(media) => media.answerable_payloads(offered),
                    None => offered,
                };
                // Our direction is the reciprocal of theirs (RFC 3264 §6):
                // toward a held side we send nothing but keep receiving its
                // music.
                let direction = reciprocal_direction(media_stance(&request.body));
                response.headers.push(Header {
                    name: "Content-Type".to_string(),
                    value: "application/sdp".to_string(),
                });
                response.body = media::audio_sdp_answer(&rtp_host, port, &answer, direction);
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
        // Responses to our own BYE/CANCEL transactions complete those
        // transactions — they drive no call events.
        let client_hit = self.calls.iter().find_map(|(id, call)| {
            call.client_txs
                .iter()
                .position(|tx| tx.matches_response(&response))
                .map(|index| (*id, index))
        });
        if let Some((id, index)) = client_hit {
            let Some(call) = self.calls.get_mut(&id) else {
                return vec![];
            };
            let actions = call.client_txs[index].on_response(response, now_ms);
            let mut outputs = Vec::new();
            push_sends(&mut outputs, actions);
            return outputs;
        }

        // The callee INVITE transaction (or its late retransmissions).
        let Some(id) = self.calls.iter().find_map(|(id, call)| {
            call.callee_tx
                .as_ref()
                .filter(|tx| tx.matches_response(&response))
                .map(|_| *id)
        }) else {
            return self.re_ack(&response);
        };
        let Some(call) = self.calls.get_mut(&id) else {
            return vec![];
        };
        let finished = call.callee_tx.as_ref().is_none_or(|tx| tx.is_finished());
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

    /// Re-ACKs a retransmitted 2xx of *our INVITE* for a call we still hold.
    /// (Never for anything else — a BYE's 200 is not an INVITE's 2xx.)
    fn re_ack(&mut self, response: &Response) -> Vec<Output> {
        if !(200..300).contains(&response.status) {
            return vec![];
        }
        let ours_invite = cseq_parts(header(&response.headers, "cseq").unwrap_or(""))
            .map(|(_, method)| method.eq_ignore_ascii_case("INVITE"))
            .unwrap_or(false);
        if !ours_invite {
            return vec![];
        }
        let call_id = header(&response.headers, "call-id").unwrap_or("");
        let Some(&id) = self.by_call_id.get(call_id) else {
            return vec![];
        };
        let Some(call) = self.calls.get_mut(&id) else {
            return vec![];
        };
        let Some(invite) = &call.callee_invite else {
            return vec![];
        };
        if sip_stack::branch(&invite.headers) != sip_stack::branch(&response.headers) {
            return vec![];
        }
        match &call.callee_ack {
            Some(ack) => vec![Output::Send(Message::Request(ack.clone()))],
            None => vec![],
        }
    }

    fn handle_ack(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        // A non-2xx ACK shares its INVITE's branch; find that transaction and
        // let it finish (Timer I). A 2xx ACK is its own transaction and needs
        // no state here. Only the matching transaction reacts — a stray ACK
        // must not silence a legitimate 487 retransmission.
        let Some(&id) = self
            .by_call_id
            .get(header(&request.headers, "call-id").unwrap_or(""))
        else {
            return vec![];
        };
        let Some(call) = self.calls.get_mut(&id) else {
            return vec![];
        };
        // The matching transaction stops retransmitting: a non-2xx ACK shares
        // its INVITE's branch, a 2xx ACK is its own transaction (§13.2.2.4)
        // and matches by Call-ID + CSeq instead.
        let mut actions = Vec::new();
        if call.caller_tx.matches_ack(&request) {
            actions.extend(call.caller_tx.on_ack(now_ms));
        }
        for tx in &mut call.server_txs {
            if tx.matches_ack(&request) {
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

        // A retransmitted BYE gets our last response again (§17.2) — the call
        // is torn down once, not once per copy on the wire.
        if let Some(call) = self.calls.get_mut(&id) {
            if let Some(tx) = call
                .server_txs
                .iter_mut()
                .find(|tx| tx.matches_request(&request))
            {
                push_sends(&mut outputs, tx.on_request(&request));
                return outputs;
            }
        }
        // RFC 3261 §12.2.2: out-of-order requests are stale and get 500.
        if !self.accept_remote_cseq(&id, leg, &request) {
            return self.refuse(&request, 500, "Server Internal Error", None, now_ms);
        }

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
        let cancel_branch = sip_stack::branch(&request.headers);
        let refuse = |outputs: &mut Vec<Output>| {
            // RFC 3261 §9.2: a CANCEL must match a transaction that still
            // exists. After the INVITE is answered, it does not.
            let response = make_response(&request, 481, "Call/Transaction Does Not Exist");
            outputs.push(Output::Send(Message::Response(response)));
        };

        let Some(&id) = self.by_call_id.get(call_id) else {
            refuse(&mut outputs);
            return outputs;
        };
        let Some(call) = self.calls.get_mut(&id) else {
            refuse(&mut outputs);
            return outputs;
        };

        let cancels_call_setup = matches!(call.state, CallState::Offering | CallState::Ringing)
            && cancel_branch.is_some()
            && call.caller_tx.branch() == cancel_branch;
        let cancels_reinvite = cancel_branch.is_some()
            && call
                .server_txs
                .iter()
                .any(|tx| tx.branch() == cancel_branch && tx.state() == ServerState::Proceeding);
        if !(cancels_call_setup || cancels_reinvite) {
            refuse(&mut outputs);
            return outputs;
        }

        // Answer the CANCEL itself.
        let (mut tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        push_sends(&mut outputs, actions);
        let actions = tx.on_response_from_user(make_response(&request, 200, "OK"), now_ms);
        push_sends(&mut outputs, actions);
        if let Some(call) = self.calls.get_mut(&id) {
            call.server_txs.push(tx);
        }

        if !cancels_call_setup {
            return outputs; // a cancelled re-INVITE leaves the call alone
        }
        if let Some(call) = self.calls.get_mut(&id) {
            call.outcome = "cancelled".to_string();
        }
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
    #[must_use = "the outputs are the relayed packets; dispatch them"]
    pub fn on_rtp(&mut self, local_port: u16, from: &str, data: &[u8], now_ms: u64) -> Vec<Output> {
        let Ok(packet) = rtp::Packet::parse(data) else {
            return vec![];
        };
        let Some((id, leg)) = self.find_media_port(local_port) else {
            return vec![];
        };
        let Some(call) = self.calls.get_mut(&id) else {
            return vec![];
        };
        call.last_media_ms = now_ms;
        let Some(media) = call.media.as_mut() else {
            return vec![];
        };
        let (source, target) = match leg {
            Leg::Caller => (&mut media.caller, &media.callee),
            Leg::Callee => (&mut media.callee, &media.caller),
        };
        // Symmetric RTP: whoever speaks is where their media goes back to.
        source.learned = Some(from.to_string());
        // Only what a side sends, and only toward a side that receives
        // (RFC 3264 §6). A hold stops one direction, not the pipe: the
        // holder's own media — its hold music — still reaches the far side.
        if !(source.sends && target.receives) {
            return vec![];
        }
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
                        }
                        // Where their media lives (from their SDP) — including
                        // 183 early media (docs/06: inband announcements). A
                        // live stream is also their codec choice, and that pins
                        // what we may answer toward the caller. Their
                        // direction attributes say what they send and receive.
                        if let Some(media) = call.media.as_mut() {
                            if let Some((sends, receives)) = media_stance(&response.body) {
                                media.callee.sends = sends;
                                media.callee.receives = receives;
                            }
                            if let Some(peer_addr) = media_target(&response.body) {
                                media.callee.peer_addr = peer_addr;
                                let payload_types = sdp_payload_types(&response.body);
                                if !payload_types.is_empty() {
                                    media.callee_payloads = payload_types;
                                }
                            }
                        }
                    }
                    if response.status == 100 {
                        continue; // hop-by-hop; never shown to the caller
                    }
                    // A peer that challenges our INVITE gets a credentialed
                    // retry (RFC 2617) — trunk authentication, not a failure.
                    if matches!(response.status, 401 | 407) {
                        if let Some(outputs2) = self.trunk_auth_retry(id, &response, now_ms) {
                            outputs.extend(outputs2);
                            continue;
                        }
                    }
                    let event = if response.status < 200 {
                        CallEvent::CalleeProgress(response.status)
                    } else if response.status < 300 {
                        // ACK for the 2xx (new transaction, §13.2.2.4).
                        let callee_host = self
                            .calls
                            .get(id)
                            .map(|call| self.local(call.callee_peer).sip);
                        let ack = callee_host.and_then(|host| {
                            let ack_via = self.via("ack", host);
                            let contact = contact_for(host);
                            self.calls.get(id).and_then(|call| {
                                let invite = call.callee_invite.as_ref()?;
                                Some(ack_for_2xx(invite, &response, &ack_via, &contact))
                            })
                        });
                        if let Some(ack) = ack {
                            if let Some(call) = self.calls.get_mut(id) {
                                call.callee_ack = Some(ack.clone());
                            }
                            outputs.push(Output::Send(Message::Request(ack)));
                        }
                        // A CANCEL may have crossed this 200: the callee just
                        // answered a call the caller already gave up on.
                        // RFC 3261 §15.1.1 — hang that callee up.
                        let crossed = self.calls.get(id).is_some_and(|call| {
                            matches!(call.state, CallState::Terminating | CallState::Terminated)
                        });
                        // The relay does not transcode (docs/02 §8): if the
                        // callee's answer leaves nothing we could answer the
                        // caller with, the two legs can never understand each
                        // other. Hang the callee up and fail the call rather
                        // than bridge a call that cannot carry audio.
                        let incompatible = self.calls.get(id).is_some_and(|call| {
                            let Some(media) = call.media.as_ref() else {
                                return false;
                            };
                            let offered = sdp_payload_types(&call.caller_invite.body);
                            let answer = media.answerable_payloads(offered);
                            !answer
                                .iter()
                                .any(|pt| media::Codec::of_payload_type(*pt).is_some())
                        });
                        if crossed || incompatible {
                            let bye = callee_host.and_then(|host| {
                                let bye_via = self.via("bye", host);
                                let contact = contact_for(host);
                                self.calls.get_mut(id).and_then(|call| {
                                    call.callee_dialog.as_mut().map(|dialog| {
                                        dialog.request(Method::Bye, &bye_via, &contact)
                                    })
                                })
                            });
                            if let Some(bye) = bye {
                                let (tx, actions) = ClientTransaction::new(bye, now_ms);
                                if let Some(call) = self.calls.get_mut(id) {
                                    call.client_txs.push(tx);
                                }
                                push_sends(&mut outputs, actions);
                            }
                        }
                        if incompatible && !crossed {
                            if let Some(call) = self.calls.get_mut(id) {
                                call.outcome = "no-codec".to_string();
                            }
                            CallEvent::CalleeRejected(488)
                        } else {
                            CallEvent::CalleeAnswered
                        }
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

    /// Retries the callee-leg INVITE with digest credentials when a trunk
    /// peer challenges it. Returns `None` when this is not that situation.
    fn trunk_auth_retry(
        &mut self,
        id: &u64,
        response: &Response,
        now_ms: u64,
    ) -> Option<Vec<Output>> {
        let challenge = if response.status == 407 {
            header(&response.headers, "proxy-authenticate")
                .or_else(|| header(&response.headers, "www-authenticate"))?
        } else {
            header(&response.headers, "www-authenticate")?
        };
        let call = self.calls.get(id)?;
        if call.auth_retried || !matches!(call.state, CallState::Offering | CallState::Ringing) {
            return None;
        }
        let trunk_name = call.callee_trunk.clone()?;
        let invite = call.callee_invite.clone()?;
        let callee_peer = call.callee_peer;
        let (username, secret) = {
            let trunk = self.config.trunks.iter().find(|t| t.name == trunk_name)?;
            (trunk.username.clone()?, trunk.secret.clone()?)
        };
        let challenge = sip_stack::digest::parse_challenge(challenge)?;
        // qop negotiation: we answer qop=auth, or nothing at all.
        if let Some(qop) = &challenge.qop {
            if !qop.split(',').any(|q| q.trim() == "auth") {
                return None;
            }
        }
        let auth_header = if response.status == 407 {
            "Proxy-Authorization"
        } else {
            "Authorization"
        };
        let mut retry = invite;
        // A retry is a new transaction: fresh Via branch, next CSeq.
        let callee_host = self.local(callee_peer).sip;
        let cseq = header(&retry.headers, "cseq")
            .and_then(|cseq| cseq.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(1)
            + 1;
        for entry in &mut retry.headers {
            match canonical_header(&entry.name).as_str() {
                "via" => entry.value = self.via("invite", callee_host),
                "cseq" => entry.value = format!("{cseq} INVITE"),
                _ => {}
            }
        }
        let value = sip_stack::digest::authorization_value(
            &challenge, &username, &secret, "INVITE", &retry.uri,
        );
        retry.headers.push(Header {
            name: auth_header.to_string(),
            value,
        });
        let (transaction, actions) = ClientTransaction::new(retry.clone(), now_ms);
        if let Some(call) = self.calls.get_mut(id) {
            call.auth_retried = true;
            call.callee_invite = Some(retry);
            call.callee_tx = Some(transaction);
            // The retry took a CSeq number: the dialog must not reuse it
            // (RFC 3261 §12.2.1.1) or our later BYE would collide.
            if let Some(dialog) = call.callee_dialog.as_mut() {
                dialog.local_cseq = cseq;
            }
        }
        let mut outputs = Vec::new();
        push_sends(&mut outputs, actions);
        Some(outputs)
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
        // The side this command talks to is served from its own local address
        // (docs/02 §4): the caller sees the caller-side one, the callee the
        // callee-side one.
        let Some(call) = self.calls.get(id) else {
            return vec![];
        };
        let local = self.local(match command {
            Command::ByeCallee => call.callee_peer,
            _ => call.caller_peer,
        });
        let (host, rtp_host) = (local.sip, local.rtp.to_string());
        let contact = contact_for(host);
        let via = self.via("bye", host);
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
                // No session timers (docs/07 §3): we never claim the
                // extension, so the answer carries no Session-Expires and the
                // peer runs the session as it sees fit.
                if let Some(media) = &call.media {
                    let offered = sdp_payload_types(&call.caller_invite.body);
                    // Never answer with a codec the callee did not accept: the
                    // relay does not transcode, so a wider answer would let the
                    // two legs run different codecs and the audio arrive as
                    // garbage.
                    let answer = media.answerable_payloads(offered);
                    // Our direction is the reciprocal of their offer's
                    // (RFC 3264 §6).
                    let direction = reciprocal_direction(media_stance(&call.caller_invite.body));
                    response.headers.push(Header {
                        name: "Content-Type".to_string(),
                        value: "application/sdp".to_string(),
                    });
                    response.body = media::audio_sdp_answer(
                        &rtp_host,
                        media.caller.our_port,
                        &answer,
                        direction,
                    );
                }
                call.caller_tx.on_response_from_user(response, now_ms)
            }
            Command::FailCaller(status) => {
                // Never relay a challenge-less 401/407 toward the caller:
                // the challenge died with the callee leg. Say what it meant.
                let status = if matches!(status, 401 | 407) {
                    503
                } else {
                    status
                };
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

    /// Applies an in-dialog request's CSeq to the dialog it came in on
    /// (RFC 3261 §12.2.2): requests from one side must strictly increase,
    /// or they are stale and must leave dialog state alone.
    fn accept_remote_cseq(&mut self, id: &u64, leg: Leg, request: &Request) -> bool {
        let Some(cseq) = cseq_number_of(request) else {
            return false;
        };
        let Some(call) = self.calls.get_mut(id) else {
            return false;
        };
        let dialog = match leg {
            Leg::Caller => &mut call.caller_dialog,
            Leg::Callee => match call.callee_dialog.as_mut() {
                Some(dialog) => dialog,
                None => return false,
            },
        };
        dialog.accept_remote_cseq(cseq)
    }

    fn build_callee_invite(
        &mut self,
        callee_aor: &str,
        caller_uri: &str,
        caller_display: &str,
        callee_contact: &str,
        body: Vec<u8>,
        local: SocketAddr,
    ) -> Request {
        let from_tag = self.fresh_tag();
        // Caller identity is carried over, display name included.
        let from = if caller_display.is_empty() {
            format!("<{caller_uri}>;tag={from_tag}")
        } else {
            format!("{caller_display} <{caller_uri}>;tag={from_tag}")
        };
        Request {
            method: Method::Invite,
            uri: callee_contact.to_string(),
            headers: vec![
                Header {
                    name: "Via".to_string(),
                    value: self.via("invite", local),
                },
                Header {
                    name: "Max-Forwards".to_string(),
                    value: "70".to_string(),
                },
                Header {
                    name: "From".to_string(),
                    value: from,
                },
                Header {
                    name: "To".to_string(),
                    value: format!("<{callee_aor}>"),
                },
                Header {
                    name: "Call-ID".to_string(),
                    value: self.fresh_call_id(local),
                },
                Header {
                    name: "CSeq".to_string(),
                    value: "1 INVITE".to_string(),
                },
                Header {
                    name: "Contact".to_string(),
                    value: contact_for(local),
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

    fn fresh_call_id(&mut self, local: SocketAddr) -> String {
        format!("pbx-call-{:06}@{}", self.next_call + 1, local)
    }

    fn via(&mut self, what: &str, local: SocketAddr) -> String {
        self.next_branch += 1;
        format!(
            "SIP/2.0/UDP {};branch=z9hG4bK-{}-{:08}",
            local, what, self.next_branch
        )
    }
}

// ----- free functions -------------------------------------------------------

/// Our Contact on a local interface ("<sip:192.0.2.10:5060>").
fn contact_for(local: SocketAddr) -> String {
    format!("<sip:{local}>")
}

/// The IP address a SIP URI or header value points at
/// (`"Alice" <sip:1001@192.0.2.1:5060;transport=udp>` → `192.0.2.1`).
/// Hostnames resolve to nothing: peers are IP literals (docs/07).
fn host_ip(value: &str) -> Option<IpAddr> {
    let address = uri_of(value);
    let address = address
        .strip_prefix("sips:")
        .or_else(|| address.strip_prefix("sip:"))
        .unwrap_or(address);
    let hostport = address.rsplit('@').next().unwrap_or(address).trim();
    if let Ok(socket) = hostport.parse::<SocketAddr>() {
        return Some(socket.ip());
    }
    hostport.parse::<IpAddr>().ok()
}

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

/// Option tags a request requires that we do not implement (RFC 3261 §8.2.2.3).
/// We implement none, so every tag in `Require` is unsupported — and that is
/// the honest answer (docs/07 §2). Duplicates are listed once.
fn unsupported_require(request: &Request) -> Vec<String> {
    let mut tags: Vec<String> = request
        .headers
        .iter()
        .filter(|header| canonical_header(&header.name) == "require")
        .flat_map(|header| header.value.split(','))
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect();
    tags.sort();
    tags.dedup();
    tags
}

/// What an SDP body says about the audio its sender will carry (RFC 3264
/// §6): whether media *from* it is sent onward, and whether media is
/// delivered *to* it. `None` when the body names no audio stream.
///
/// A declined stream (`c=0.0.0.0` / `m=audio 0`) receives nothing — but
/// phones on hold keep streaming their music from behind one, so what they
/// send is still relayed (the transparent pipe, docs/02 §8).
fn media_stance(body: &[u8]) -> Option<(bool, bool)> {
    let sdp = parse_sdp(body).ok()?;
    let audio = sdp.media.iter().find(|media| media.media == "audio")?;
    let direction = audio.direction.unwrap_or(Direction::SendRecv);
    let declined = audio.port == 0 || audio.connection.as_deref() == Some("0.0.0.0");
    Some((direction.sends(), direction.receives() && !declined))
}

/// Whether an SDP body withdraws its audio stream (`m=audio 0`): the stream
/// is gone (RFC 3264 §6) and our answer mirrors that.
fn stream_withdrawn(body: &[u8]) -> bool {
    parse_sdp(body).is_ok_and(|sdp| {
        sdp.media
            .iter()
            .any(|media| media.media == "audio" && media.port == 0)
    })
}

/// The direction our answer takes toward a peer with this stance (RFC 3264
/// §6): we send what it receives and receive what it sends. `None` is plain
/// `sendrecv` — no direction attribute on the wire.
fn reciprocal_direction(stance: Option<(bool, bool)>) -> Option<Direction> {
    match stance? {
        (true, true) => None,
        (true, false) => Some(Direction::RecvOnly),
        (false, true) => Some(Direction::SendOnly),
        (false, false) => Some(Direction::Inactive),
    }
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

/// The CSeq sequence number of a request, if it has one.
fn cseq_number_of(request: &Request) -> Option<u64> {
    cseq_parts(header(&request.headers, "cseq").unwrap_or(""))
        .and_then(|(number, _)| number.parse().ok())
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
    if connection == "0.0.0.0" {
        return None; // hold: media is off (RFC 3264 §6)
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
        401 => "Unauthorized",
        403 => "Forbidden",
        407 => "Proxy Authentication Required",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        420 => "Bad Extension",
        481 => "Call/Transaction Does Not Exist",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        500 => "Server Internal Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}
