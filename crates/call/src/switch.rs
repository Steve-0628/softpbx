//! The PBX core: routes calls between registered devices (docs/02 §4).
//!
//! A [`Switch`] is a pure message processor: SIP messages in (already parsed),
//! SIP messages out plus call-log lines. No sockets, no clock of its own —
//! the daemon and the simulation drive it the same way.
//!
//! Each call is a B2BUA: one dialog leg toward the caller, one toward the
//! callee, glued by the call state machine ([`crate::call`]).

use std::collections::HashMap;

use sip_stack::{
    ack_for_non_2xx, make_response, tag_of, uri_of, with_tag, Action, ClientTransaction, Dialog,
    ServerTransaction, Timer,
};
use sip_syntax::{canonical_header, Header, Message, Method, Request, Response};

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
    /// The devices that may register and be called.
    pub devices: Vec<Device>,
}

/// What the switch wants the environment to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send this SIP message.
    Send(Message),
    /// Append this line to the call log (one per finished call).
    CallLog(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leg {
    Caller,
    Callee,
}

#[derive(Debug)]
struct CallCtx {
    state: CallState,
    caller_number: String,
    callee_number: String,
    caller_invite: Request,
    caller_tx: ServerTransaction,
    caller_dialog: Dialog,
    callee_tx: Option<ClientTransaction>,
    callee_invite: Option<Request>,
    callee_dialog: Option<Dialog>,
    started_ms: u64,
    outcome: String,
}

impl CallCtx {
    /// Which leg an in-dialog request belongs to.
    fn leg_of(&self, request: &Request) -> Option<Leg> {
        let call_id = header(&request.headers, "call-id").unwrap_or("");
        let from_tag = header(&request.headers, "from")
            .and_then(tag_of)
            .unwrap_or("");
        let to_tag = header(&request.headers, "to")
            .and_then(tag_of)
            .unwrap_or("");
        if self.caller_dialog.matches(call_id, from_tag, to_tag) {
            return Some(Leg::Caller);
        }
        match &self.callee_dialog {
            Some(dialog) if dialog.matches(call_id, from_tag, to_tag) => Some(Leg::Callee),
            _ => None,
        }
    }
}

/// The switch.
#[derive(Debug)]
pub struct Switch {
    config: SwitchConfig,
    registrar: Registrar,
    calls: HashMap<String, CallCtx>,
    next_tag: u64,
    next_id: u64,
}

impl Switch {
    /// Creates a switch for the given devices and addresses.
    pub fn new(config: SwitchConfig) -> Self {
        let registrar = Registrar::new(&config.realm, config.devices.clone());
        Switch {
            config,
            registrar,
            calls: HashMap::new(),
            next_tag: 0,
            next_id: 0,
        }
    }

    /// Currently registered numbers.
    pub fn registered(&self, now_ms: u64) -> Vec<String> {
        self.registrar.registered(now_ms)
    }

    /// How many calls are in flight.
    pub fn active_calls(&self) -> usize {
        self.calls.len()
    }

    /// State of a call, by its caller-leg Call-ID.
    pub fn call_state(&self, call_id: &str) -> Option<CallState> {
        self.calls.get(call_id).map(|call| call.state)
    }

    /// Outstanding transaction timers as `(name, due_ms)`. The environment
    /// arms them and fires them back through [`Switch::on_timer`].
    pub fn timers(&self) -> Vec<(String, u64)> {
        let mut timers = Vec::new();
        for (call_id, call) in &self.calls {
            if let Some((due, timer)) = call.caller_tx.next_timer() {
                timers.push((timer_name(call_id, Leg::Caller, timer), due));
            }
            if let Some((due, timer)) = call
                .callee_tx
                .as_ref()
                .and_then(|transaction| transaction.next_timer())
            {
                timers.push((timer_name(call_id, Leg::Callee, timer), due));
            }
        }
        timers.sort();
        timers
    }

    /// A timer armed from [`Switch::timers`] fired.
    pub fn on_timer(&mut self, name: &str, now_ms: u64) -> Vec<Output> {
        let Some((call_id, leg, timer)) = parse_timer_name(name) else {
            return vec![];
        };
        let Some(call) = self.calls.get_mut(&call_id) else {
            return vec![];
        };
        let actions = match leg {
            Leg::Caller => call.caller_tx.on_timer(timer, now_ms),
            Leg::Callee => match call.callee_tx.as_mut() {
                Some(transaction) => transaction.on_timer(timer, now_ms),
                None => vec![],
            },
        };
        self.apply_actions(&call_id, actions, now_ms)
    }

    /// Feeds one incoming SIP message; returns what to send and log.
    pub fn handle(&mut self, message: Message, now_ms: u64) -> Vec<Output> {
        match message {
            Message::Request(request) => self.handle_request(request, now_ms),
            Message::Response(response) => self.handle_response(response, now_ms),
        }
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

    fn handle_invite(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        let mut outputs = Vec::new();
        let call_id = header(&request.headers, "call-id")
            .unwrap_or("")
            .to_string();
        if let Some(call) = self.calls.get_mut(&call_id) {
            // Retransmission: the server transaction repeats our last response.
            let actions = call.caller_tx.on_request(&request);
            let mut outputs = Vec::new();
            push_sends(&mut outputs, actions);
            return outputs;
        }

        let (mut caller_tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        push_sends(&mut outputs, actions);

        // The caller is who the INVITE is From; the callee is what was dialed.
        let caller_number = header(&request.headers, "from")
            .map(uri_of)
            .and_then(number_from_uri)
            .unwrap_or_default();
        let callee_number = number_from_uri(&request.uri).unwrap_or_default();
        let caller_uri = header(&request.headers, "from")
            .map(uri_of)
            .unwrap_or("")
            .to_string();
        let caller_tag = header(&request.headers, "from")
            .and_then(tag_of)
            .unwrap_or("")
            .to_string();
        let caller_contact = header(&request.headers, "contact")
            .map(|contact| uri_of(contact).to_string())
            .unwrap_or_default();

        // Where does the call go?
        let Some(callee_contact) = self.registrar.lookup(&callee_number, now_ms) else {
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
        let callee_contact = callee_contact.to_string();

        // B2BUA: a brand-new leg toward the callee.
        let our_caller_tag = self.fresh_tag();
        let callee_invite =
            self.build_callee_invite(&request, &caller_uri, &callee_contact, now_ms);
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
            &call_id,
            &request.uri, // our side is the address of record being called
            &our_caller_tag,
            &caller_uri,
            &caller_tag,
            &caller_contact,
        );
        let callee_dialog = Dialog::new(
            &callee_call_id,
            &caller_uri,
            &callee_from_tag,
            &request.uri,
            "",
            &callee_contact,
        );

        self.calls.insert(
            call_id,
            CallCtx {
                state: CallState::Offering,
                caller_number,
                callee_number,
                caller_invite: request,
                caller_tx,
                caller_dialog,
                callee_tx: Some(callee_tx),
                callee_invite: Some(callee_invite),
                callee_dialog: Some(callee_dialog),
                started_ms: now_ms,
                outcome: "no-answer".to_string(),
            },
        );
        outputs
    }

    fn handle_response(&mut self, response: Response, now_ms: u64) -> Vec<Output> {
        let Some(call_id) = self
            .calls
            .iter()
            .find(|(_, call)| {
                call.callee_tx
                    .as_ref()
                    .map(|transaction| transaction.matches_response(&response))
                    .unwrap_or(false)
            })
            .map(|(call_id, _)| call_id.clone())
        else {
            return vec![]; // late response for a call we forgot: ignore
        };
        let Some(call) = self.calls.get_mut(&call_id) else {
            return vec![];
        };
        let Some(transaction) = call.callee_tx.as_mut() else {
            return vec![];
        };
        let actions = transaction.on_response(response, now_ms);
        self.apply_actions(&call_id, actions, now_ms)
    }

    fn handle_ack(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        let Some(call_id) = self.find_call(&request) else {
            return vec![];
        };
        let Some(call) = self.calls.get_mut(&call_id) else {
            return vec![];
        };
        // ACK for a non-2xx final belongs to the INVITE server transaction.
        let actions = call.caller_tx.on_ack(now_ms);
        self.apply_actions(&call_id, actions, now_ms)
    }

    fn handle_cancel(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        let mut outputs = Vec::new();
        let Some(call_id) = self.find_call(&request) else {
            let response = make_response(&request, 481, "Call/Transaction Does Not Exist");
            return vec![Output::Send(Message::Response(response))];
        };
        // Answer the CANCEL itself.
        let (mut cancel_tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        push_sends(&mut outputs, actions);
        let actions = cancel_tx.on_response_from_user(make_response(&request, 200, "OK"), now_ms);
        push_sends(&mut outputs, actions);

        let Some(call) = self.calls.get_mut(&call_id) else {
            return outputs;
        };
        if !matches!(call.state, CallState::Offering | CallState::Ringing) {
            return outputs;
        }
        call.outcome = "cancelled".to_string();
        let actions = self.event_on(&call_id, CallEvent::CallerCancelled, now_ms);
        outputs.extend(self.apply_actions(&call_id, actions, now_ms));
        outputs
    }

    fn handle_bye(&mut self, request: Request, now_ms: u64) -> Vec<Output> {
        let Some(call_id) = self.find_call(&request) else {
            let response = make_response(&request, 481, "Call/Transaction Does Not Exist");
            return vec![Output::Send(Message::Response(response))];
        };
        let Some(leg) = self
            .calls
            .get(&call_id)
            .and_then(|call| call.leg_of(&request))
        else {
            let response = make_response(&request, 481, "Call/Transaction Does Not Exist");
            return vec![Output::Send(Message::Response(response))];
        };

        // Answer the BYE on its own transaction.
        let (mut bye_tx, actions) = ServerTransaction::new(request.clone(), now_ms);
        let mut outputs = Vec::new();
        push_sends(&mut outputs, actions);
        let actions = bye_tx.on_response_from_user(make_response(&request, 200, "OK"), now_ms);
        push_sends(&mut outputs, actions);

        if let Some(call) = self.calls.get_mut(&call_id) {
            call.outcome = "completed".to_string();
        }
        let event = match leg {
            Leg::Caller => CallEvent::CallerHungUp,
            Leg::Callee => CallEvent::CalleeHungUp,
        };
        let actions = self.event_on(&call_id, event, now_ms);
        outputs.extend(self.apply_actions(&call_id, actions, now_ms));
        outputs
    }

    /// Turns transaction actions into outputs and feeds resulting call events
    /// back into the state machine.
    fn apply_actions(&mut self, call_id: &str, actions: Vec<Action>, now_ms: u64) -> Vec<Output> {
        let mut outputs = Vec::new();
        for action in actions {
            match action {
                Action::Send(message) => outputs.push(Output::Send(message)),
                Action::DeliverResponse(response) => {
                    let event = if response.status < 200 {
                        CallEvent::CalleeRinging
                    } else if response.status < 300 {
                        // The dialog layer ACKs the 2xx of our INVITE.
                        if let Some(call) = self.calls.get(call_id) {
                            if let (Some(invite), Some(transaction)) =
                                (&call.callee_invite, &call.callee_tx)
                            {
                                if transaction.is_invite() {
                                    let ack = ack_for_non_2xx(invite, &response);
                                    outputs.push(Output::Send(Message::Request(ack)));
                                }
                            }
                        }
                        CallEvent::CalleeAnswered
                    } else {
                        if let Some(call) = self.calls.get_mut(call_id) {
                            call.outcome = format!("rejected:{}", response.status);
                        }
                        CallEvent::CalleeRejected(response.status)
                    };
                    let actions = self.event_on(call_id, event, now_ms);
                    outputs.extend(self.apply_actions(call_id, actions, now_ms));
                }
                Action::DeliverRequest(_) => {}
                Action::Timeout => {
                    if let Some(call) = self.calls.get_mut(call_id) {
                        call.outcome = "no-answer".to_string();
                    }
                    let actions = self.event_on(call_id, CallEvent::CalleeTimeout, now_ms);
                    outputs.extend(self.apply_actions(call_id, actions, now_ms));
                }
                Action::Done => {}
            }
        }
        outputs.extend(self.finish(call_id, now_ms));
        outputs
    }

    /// Runs one call event through the state machine, expanding the commands
    /// it returns into transaction actions.
    fn event_on(&mut self, call_id: &str, event: CallEvent, now_ms: u64) -> Vec<Action> {
        let Some(call) = self.calls.get_mut(call_id) else {
            return vec![];
        };
        let (state, commands) = transit(call.state, event);
        call.state = state;
        if matches!(event, CallEvent::CallerHungUp | CallEvent::CalleeHungUp) {
            call.outcome = "completed".to_string();
        }
        let mut actions = Vec::new();
        for command in commands {
            actions.extend(self.command_actions(call_id, command, now_ms));
        }
        actions
    }

    /// Turns one semantic command into the SIP actions that carry it out.
    fn command_actions(&mut self, call_id: &str, command: Command, now_ms: u64) -> Vec<Action> {
        let via = self.via("bye");
        let contact = self.config.pbx_contact.clone();
        let Some(call) = self.calls.get_mut(call_id) else {
            return vec![];
        };
        match command {
            Command::RingCaller => {
                let response = tagged(
                    make_response(&call.caller_invite, 180, "Ringing"),
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
                call.caller_tx.on_response_from_user(response, now_ms)
            }
            Command::FailCaller(status) => {
                let reason = reason_phrase(status);
                let response = tagged(
                    make_response(&call.caller_invite, status, reason),
                    &call.caller_dialog.local_tag.clone(),
                );
                call.caller_tx.on_response_from_user(response, now_ms)
            }
            Command::CancelCaller => {
                // 200 for the CANCEL already went out; reject the INVITE and
                // cancel the leg toward the callee.
                let mut actions = Vec::new();
                let response = tagged(
                    make_response(&call.caller_invite, 487, "Request Terminated"),
                    &call.caller_dialog.local_tag.clone(),
                );
                actions.extend(call.caller_tx.on_response_from_user(response, now_ms));
                if let Some(invite) = &call.callee_invite {
                    actions.push(Action::Send(Message::Request(cancel_for(invite))));
                }
                actions
            }
            Command::ByeCallee => {
                let Some(dialog) = call.callee_dialog.as_mut() else {
                    return vec![];
                };
                let bye = dialog.request(Method::Bye, &via, &contact);
                vec![Action::Send(Message::Request(bye))]
            }
            Command::ByeCaller => {
                let bye = call.caller_dialog.request(Method::Bye, &via, &contact);
                vec![Action::Send(Message::Request(bye))]
            }
            Command::CompleteCaller | Command::CompleteCallee => vec![], // answered as requests arrive
            Command::Finish => vec![],                                   // handled by finish()
        }
    }

    /// When a call reaches `Terminating`, runs the final transition and emits
    /// its call-log line.
    fn finish(&mut self, call_id: &str, now_ms: u64) -> Vec<Output> {
        let Some(call) = self.calls.get(call_id) else {
            return vec![];
        };
        if call.state != CallState::Terminating {
            return vec![];
        }
        let call = self.calls.remove(call_id).expect("checked above");
        let (state, commands) = transit(call.state, CallEvent::Teardown);
        debug_assert_eq!(state, CallState::Terminated);
        debug_assert!(commands.contains(&Command::Finish));
        vec![Output::CallLog(call_log_line(
            &call.caller_number,
            &call.callee_number,
            call.started_ms,
            now_ms,
            &call.outcome,
        ))]
    }

    fn find_call(&self, request: &Request) -> Option<String> {
        let call_id = header(&request.headers, "call-id").unwrap_or("");
        self.calls
            .get(call_id)
            .map(|_| call_id.to_string())
            .or_else(|| {
                self.calls
                    .iter()
                    .find(|(_, call)| call.leg_of(request).is_some())
                    .map(|(call_id, _)| call_id.clone())
            })
    }

    fn build_callee_invite(
        &mut self,
        caller_invite: &Request,
        caller_uri: &str,
        callee_contact: &str,
        _now_ms: u64,
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
            ],
            body: Vec::new(),
        }
    }

    fn fresh_tag(&mut self) -> String {
        self.next_tag += 1;
        format!("pbx{:06}", self.next_tag)
    }

    fn fresh_call_id(&mut self) -> String {
        self.next_id += 1;
        format!("pbx-call-{:06}@{}", self.next_id, self.config.pbx_host)
    }

    fn via(&self, what: &str) -> String {
        format!(
            "SIP/2.0/UDP {};branch=z9hG4bK-{}-{:06}",
            self.config.pbx_host, what, self.next_id
        )
    }
}

fn call_log_line(
    caller: &str,
    callee: &str,
    started_ms: u64,
    ended_ms: u64,
    result: &str,
) -> String {
    format!(
        "{{\"caller\":\"{caller}\",\"callee\":\"{callee}\",\"started_ms\":{started_ms},\"ended_ms\":{ended_ms},\"result\":\"{result}\"}}"
    )
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

fn timer_name(call_id: &str, leg: Leg, timer: Timer) -> String {
    let leg = match leg {
        Leg::Caller => "caller",
        Leg::Callee => "callee",
    };
    format!("call:{call_id}:{leg}:{timer:?}")
}

fn parse_timer_name(name: &str) -> Option<(String, Leg, Timer)> {
    let mut parts = name.split(':');
    if parts.next()? != "call" {
        return None;
    }
    let call_id = parts.next()?.to_string();
    let leg = match parts.next()? {
        "caller" => Leg::Caller,
        "callee" => Leg::Callee,
        _ => return None,
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
        _ => return None,
    };
    Some((call_id, leg, timer))
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        500 => "Server Internal Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}
