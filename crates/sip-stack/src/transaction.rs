//! SIP transactions (RFC 3261 §17, plus RFC 6026 for 2xx handling).
//!
//! Transport-agnostic and side-effect free: inputs take `now_ms` explicitly,
//! outputs are [`Action`]s for the caller to execute. That is what lets the
//! deterministic simulation (docs/04) drive retransmission timers exactly.
//!
//! Covered here: INVITE and non-INVITE client/server transactions over an
//! unreliable transport (UDP) — retransmission, timeouts, `100 Trying`, the
//! RFC 6026 "Accepted" state for sent 2xx responses, and the 2xx ACK shape
//! (§13.2.2.4). The switch above owns dialogs and decides when to send what.

use sip_syntax::{canonical_header, Header, Message, Method, Request, Response};

/// RFC 3261 timer T1: initial retransmission interval, ms.
pub const T1_MS: u64 = 500;
/// RFC 3261 timer T2: maximum retransmission interval, ms.
pub const T2_MS: u64 = 4_000;
/// RFC 3261 timer T4: maximum network lifetime, ms.
pub const T4_MS: u64 = 5_000;
/// The 64·T1 "give up" horizon shared by timers B, F, H and J.
pub const GIVE_UP_MS: u64 = 64 * T1_MS;
/// Timer D (UDP): how long to keep a client transaction alive after ACKing a
/// non-2xx final response.
pub const TIMER_D_MS: u64 = 32_000;

/// RFC 3261 §17 timers (plus RFC 6026 Timer L).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timer {
    /// INVITE client: retransmit request (T1 doubling).
    A,
    /// INVITE client: give up (64·T1).
    B,
    /// INVITE client: wait after ACKing a non-2xx (UDP).
    D,
    /// Non-INVITE client: retransmit request (T1 doubling to T2).
    E,
    /// Non-INVITE client: give up (64·T1).
    F,
    /// INVITE server: retransmit final response (T1 doubling to T2).
    G,
    /// INVITE server: give up waiting for ACK (64·T1).
    H,
    /// INVITE server: wait after ACK (T4).
    I,
    /// Non-INVITE server: wait after final response (64·T1).
    J,
    /// Non-INVITE client: absorb response retransmissions after Completed (T4).
    K,
    /// INVITE server (RFC 6026): wait after sending a 2xx (64·T1).
    L,
}

/// What the caller must do on behalf of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send this message (initial send, retransmission, or an ACK we built).
    Send(Message),
    /// Hand this response to the transaction user (the call layer).
    DeliverResponse(Response),
    /// Hand this request to the transaction user (the call layer).
    DeliverRequest(Request),
    /// The transaction timed out waiting for a response (client side).
    Timeout,
    /// The transaction is finished; discard it.
    Done,
}

/// Client transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// INVITE sent, no response yet.
    Calling,
    /// Non-INVITE request sent, no response yet.
    Trying,
    /// A provisional response arrived; waiting for a final one.
    Proceeding,
    /// Final response handled (INVITE non-2xx: waiting out Timer D).
    Completed,
    /// Done.
    Terminated,
}

/// Server transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Request received, no response sent yet (non-INVITE).
    Trying,
    /// 1xx (or auto `100 Trying`) sent; waiting for the user's final response.
    Proceeding,
    /// Final response sent; retransmitting it (INVITE) or waiting out Timer J.
    Completed,
    /// 2xx sent for an INVITE (RFC 6026): retransmit it on request
    /// retransmissions until Timer L expires.
    Accepted,
    /// ACK received (INVITE, non-2xx); waiting out Timer I.
    Confirmed,
    /// Done.
    Terminated,
}

/// A client transaction: sends one request, matches its responses.
#[derive(Debug, Clone)]
pub struct ClientTransaction {
    request: Request,
    invite: bool,
    state: ClientState,
    started_ms: u64,
    retransmit_next_ms: u64,
    retransmit_interval_ms: u64,
    /// When "Completed" ends: Timer D (INVITE) or Timer K (non-INVITE).
    completed_timer: Option<(u64, Timer)>,
    last_ack: Option<Request>,
}

impl ClientTransaction {
    /// Creates a transaction for `request`. The returned actions include the
    /// initial send.
    pub fn new(request: Request, now_ms: u64) -> (Self, Vec<Action>) {
        let invite = request.method == Method::Invite;
        let transaction = ClientTransaction {
            request: request.clone(),
            invite,
            state: if invite {
                ClientState::Calling
            } else {
                ClientState::Trying
            },
            started_ms: now_ms,
            retransmit_next_ms: now_ms + T1_MS,
            retransmit_interval_ms: T1_MS,
            completed_timer: None,
            last_ack: None,
        };
        (transaction, vec![Action::Send(Message::Request(request))])
    }

    /// Current state.
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// Whether this transaction is completely done (safe to drop).
    pub fn is_finished(&self) -> bool {
        self.state == ClientState::Terminated
    }

    /// Whether this transaction carries an INVITE.
    pub fn is_invite(&self) -> bool {
        self.invite
    }

    /// The earliest timer the caller should arm, as `(due_ms, timer)`.
    ///
    /// Arming is "replace any previously armed timer of another name": the
    /// caller only ever needs this call's current answer.
    pub fn next_timer(&self) -> Option<(u64, Timer)> {
        let give_up = self.started_ms + GIVE_UP_MS;
        match self.state {
            ClientState::Calling => Some(earliest(
                (self.retransmit_next_ms, Timer::A),
                (give_up, Timer::B),
            )),
            // Timer E keeps retransmitting in "Proceeding", at T2
            // (RFC 3261 §17.1.2.2).
            ClientState::Trying => Some(earliest(
                (self.retransmit_next_ms, Timer::E),
                (give_up, Timer::F),
            )),
            ClientState::Proceeding if !self.invite => Some(earliest(
                (self.retransmit_next_ms, Timer::E),
                (give_up, Timer::F),
            )),
            ClientState::Proceeding => Some((give_up, Timer::B)),
            ClientState::Completed => self.completed_timer,
            ClientState::Terminated => None,
        }
    }

    /// A response arrived. Non-matching responses are ignored.
    pub fn on_response(&mut self, response: Response, now_ms: u64) -> Vec<Action> {
        if !self.matches_response(&response) {
            return vec![];
        }
        // A retransmitted final response gets a retransmitted ACK (§17.1.1.3).
        if self.invite && self.state == ClientState::Completed && response.status >= 200 {
            return match &self.last_ack {
                Some(ack) => vec![Action::Send(Message::Request(ack.clone()))],
                None => vec![],
            };
        }
        match self.state {
            ClientState::Calling | ClientState::Trying | ClientState::Proceeding => {
                if response.status < 200 {
                    self.state = ClientState::Proceeding;
                    vec![Action::DeliverResponse(response)]
                } else {
                    self.finish(response, now_ms)
                }
            }
            _ => vec![],
        }
    }

    /// A due timer fired.
    pub fn on_timer(&mut self, timer: Timer, now_ms: u64) -> Vec<Action> {
        match (self.state, timer) {
            (ClientState::Calling, Timer::A) => {
                self.retransmit_interval_ms = self.retransmit_interval_ms.saturating_mul(2);
                self.retransmit_next_ms = now_ms + self.retransmit_interval_ms;
                vec![Action::Send(Message::Request(self.request.clone()))]
            }
            (ClientState::Trying, Timer::E) => {
                self.retransmit_interval_ms = (self.retransmit_interval_ms * 2).min(T2_MS);
                self.retransmit_next_ms = now_ms + self.retransmit_interval_ms;
                vec![Action::Send(Message::Request(self.request.clone()))]
            }
            // In "Proceeding" the request is still retransmitted, now at T2
            // (RFC 3261 §17.1.2.2).
            (ClientState::Proceeding, Timer::E) if !self.invite => {
                self.retransmit_interval_ms = T2_MS;
                self.retransmit_next_ms = now_ms + T2_MS;
                vec![Action::Send(Message::Request(self.request.clone()))]
            }
            (ClientState::Calling, Timer::B) | (ClientState::Proceeding, Timer::B)
                if self.invite =>
            {
                self.state = ClientState::Terminated;
                vec![Action::Timeout, Action::Done]
            }
            (ClientState::Trying, Timer::F) | (ClientState::Proceeding, Timer::F)
                if !self.invite =>
            {
                self.state = ClientState::Terminated;
                vec![Action::Timeout, Action::Done]
            }
            (ClientState::Completed, Timer::D | Timer::K) => {
                self.state = ClientState::Terminated;
                vec![Action::Done]
            }
            _ => vec![],
        }
    }

    /// Whether this response belongs to this transaction (Via branch + CSeq
    /// method; falls back to Call-ID + CSeq number when a branch is missing).
    pub fn matches_response(&self, response: &Response) -> bool {
        // The CSeq method tells INVITE and CANCEL apart — they share a branch.
        let method_ok = match cseq_parts(header(&response.headers, "cseq").unwrap_or("")) {
            Some((_, method)) => method.eq_ignore_ascii_case(self.request.method.as_str()),
            None => true,
        };
        if !method_ok {
            return false;
        }
        let mine = branch(&self.request.headers);
        let theirs = branch(&response.headers);
        match (mine, theirs) {
            (Some(a), Some(b)) => a == b,
            _ => {
                header(&self.request.headers, "call-id") == header(&response.headers, "call-id")
                    && cseq_number(&self.request.headers) == cseq_number(&response.headers)
                    && header(&self.request.headers, "call-id").is_some()
            }
        }
    }

    fn finish(&mut self, response: Response, now_ms: u64) -> Vec<Action> {
        if !self.invite {
            // Completed absorbs response retransmissions until Timer K (T4).
            self.state = ClientState::Completed;
            self.completed_timer = Some((now_ms + T4_MS, Timer::K));
            return vec![Action::DeliverResponse(response)];
        }
        if response.status < 300 {
            // 2xx: the dialog layer takes over (it sends the ACK).
            self.state = ClientState::Terminated;
            return vec![Action::DeliverResponse(response), Action::Done];
        }
        let ack = ack_for_non_2xx(&self.request, &response);
        self.last_ack = Some(ack.clone());
        self.state = ClientState::Completed;
        self.completed_timer = Some((now_ms + TIMER_D_MS, Timer::D));
        vec![
            Action::Send(Message::Request(ack)),
            Action::DeliverResponse(response),
        ]
    }
}

/// A server transaction: receives one request, sends its responses.
#[derive(Debug, Clone)]
pub struct ServerTransaction {
    request: Request,
    invite: bool,
    state: ServerState,
    last_response: Option<Response>,
    retransmit_next_ms: u64,
    retransmit_interval_ms: u64,
    give_up_ms: u64,
    confirmed_ms: Option<u64>,
}

impl ServerTransaction {
    /// Creates a transaction for a received request. An INVITE gets an
    /// automatic `100 Trying` (docs/07) to stop the caller retransmitting
    /// while the call layer thinks.
    ///
    /// Contract: the call layer must eventually send a final response (or the
    /// caller CANCELs); the transaction has no timeout of its own (RFC 3261).
    pub fn new(request: Request, now_ms: u64) -> (Self, Vec<Action>) {
        let invite = request.method == Method::Invite;
        if invite {
            let trying = make_response(&request, 100, "Trying");
            let transaction = ServerTransaction {
                request: request.clone(),
                invite: true,
                state: ServerState::Proceeding,
                last_response: Some(trying.clone()),
                retransmit_next_ms: now_ms + T1_MS,
                retransmit_interval_ms: T1_MS,
                give_up_ms: now_ms + GIVE_UP_MS,
                confirmed_ms: None,
            };
            (
                transaction,
                vec![
                    Action::Send(Message::Response(trying)),
                    Action::DeliverRequest(request),
                ],
            )
        } else {
            let transaction = ServerTransaction {
                request: request.clone(),
                invite: false,
                state: ServerState::Trying,
                last_response: None,
                retransmit_next_ms: now_ms + T1_MS,
                retransmit_interval_ms: T1_MS,
                give_up_ms: now_ms + GIVE_UP_MS,
                confirmed_ms: None,
            };
            (transaction, vec![Action::DeliverRequest(request)])
        }
    }

    /// Current state.
    pub fn state(&self) -> ServerState {
        self.state
    }

    /// Whether this transaction carries an INVITE.
    pub fn is_invite(&self) -> bool {
        self.invite
    }

    /// The earliest timer the caller should arm, as `(due_ms, timer)`.
    pub fn next_timer(&self) -> Option<(u64, Timer)> {
        match self.state {
            ServerState::Completed if self.invite => Some(earliest(
                (self.retransmit_next_ms, Timer::G),
                (self.give_up_ms, Timer::H),
            )),
            ServerState::Completed => Some((self.give_up_ms, Timer::J)),
            // RFC 6026: a sent 2xx is retransmitted on request
            // retransmissions until Timer L expires.
            ServerState::Accepted => Some((self.give_up_ms, Timer::L)),
            ServerState::Confirmed => self.confirmed_ms.map(|due| (due, Timer::I)),
            _ => None,
        }
    }

    /// Whether this transaction is completely done (safe to drop).
    pub fn is_finished(&self) -> bool {
        self.state == ServerState::Terminated
    }

    /// The call layer decided on a response; send it and update state.
    ///
    /// Ignored once the transaction is over (`Terminated`) or the call is
    /// confirmed (`Confirmed`): a finished transaction stays finished.
    pub fn on_response_from_user(&mut self, response: Response, now_ms: u64) -> Vec<Action> {
        if !matches!(self.state, ServerState::Trying | ServerState::Proceeding) {
            return vec![];
        }
        match (self.invite, response.status) {
            (true, status) if status < 200 => {
                self.state = ServerState::Proceeding;
                self.last_response = Some(response.clone());
                vec![Action::Send(Message::Response(response))]
            }
            (true, status) if status < 300 => {
                // RFC 6026: the server transaction stays in "Accepted" and
                // retransmits the 2xx on request retransmissions until
                // Timer L; the dialog layer owns the ACK.
                self.state = ServerState::Accepted;
                self.last_response = Some(response.clone());
                self.give_up_ms = now_ms + GIVE_UP_MS;
                vec![Action::Send(Message::Response(response))]
            }
            (true, _) => {
                self.state = ServerState::Completed;
                self.last_response = Some(response.clone());
                self.retransmit_interval_ms = T1_MS;
                self.retransmit_next_ms = now_ms + T1_MS;
                self.give_up_ms = now_ms + GIVE_UP_MS;
                vec![Action::Send(Message::Response(response))]
            }
            (false, status) if status < 200 => {
                self.state = ServerState::Proceeding;
                self.last_response = Some(response.clone());
                vec![Action::Send(Message::Response(response))]
            }
            (false, _) => {
                self.state = ServerState::Completed;
                self.last_response = Some(response.clone());
                self.give_up_ms = now_ms + GIVE_UP_MS;
                vec![Action::Send(Message::Response(response))]
            }
        }
    }

    /// A request retransmission arrived; retransmit our last response if we
    /// have one (§17.2).
    pub fn on_request(&mut self, request: &Request) -> Vec<Action> {
        if request.method != self.request.method || !self.matches_request(request) {
            return vec![];
        }
        let retransmit = matches!(
            (self.invite, self.state),
            (
                true,
                ServerState::Proceeding | ServerState::Completed | ServerState::Accepted
            ) | (false, ServerState::Proceeding | ServerState::Completed)
        );
        match (&retransmit, &self.last_response) {
            (true, Some(response)) => vec![Action::Send(Message::Response(response.clone()))],
            _ => vec![],
        }
    }

    /// The ACK for our non-2xx final response arrived.
    pub fn on_ack(&mut self, now_ms: u64) -> Vec<Action> {
        if self.invite && self.state == ServerState::Completed {
            self.state = ServerState::Confirmed;
            self.confirmed_ms = Some(now_ms + T4_MS);
        }
        vec![]
    }

    /// A due timer fired.
    pub fn on_timer(&mut self, timer: Timer, now_ms: u64) -> Vec<Action> {
        match (self.state, timer) {
            (ServerState::Completed, Timer::G) if self.invite => {
                self.retransmit_interval_ms = (self.retransmit_interval_ms * 2).min(T2_MS);
                self.retransmit_next_ms = now_ms + self.retransmit_interval_ms;
                match &self.last_response {
                    Some(response) => vec![Action::Send(Message::Response(response.clone()))],
                    None => vec![],
                }
            }
            (ServerState::Completed, Timer::H) if self.invite => {
                // No ACK ever came.
                self.state = ServerState::Terminated;
                vec![Action::Done]
            }
            (ServerState::Accepted, Timer::L) => {
                self.state = ServerState::Terminated;
                vec![Action::Done]
            }
            (ServerState::Confirmed, Timer::I) => {
                self.state = ServerState::Terminated;
                vec![Action::Done]
            }
            (ServerState::Completed, Timer::J) if !self.invite => {
                self.state = ServerState::Terminated;
                vec![Action::Done]
            }
            _ => vec![],
        }
    }

    /// The branch this transaction is identified by.
    pub fn branch(&self) -> Option<&str> {
        branch(&self.request.headers)
    }

    /// Whether this request is a retransmission of ours (Via branch + method).
    pub fn matches_request(&self, request: &Request) -> bool {
        match (branch(&self.request.headers), branch(&request.headers)) {
            (Some(a), Some(b)) => a == b,
            _ => {
                header(&self.request.headers, "call-id") == header(&request.headers, "call-id")
                    && cseq_number(&self.request.headers) == cseq_number(&request.headers)
                    && header(&self.request.headers, "call-id").is_some()
            }
        }
    }
}

/// Builds a response copying the headers a response must echo (§8.2.6):
/// all `Via`, `From`, `To`, `Call-ID`, `CSeq`.
pub fn make_response(request: &Request, status: u16, reason: &str) -> Response {
    let mut headers = Vec::new();
    for name in ["via", "from", "to", "call-id", "cseq"] {
        for header in &request.headers {
            if canonical_header(&header.name) == name {
                headers.push(header.clone());
            }
        }
    }
    Response {
        status,
        reason: reason.to_string(),
        headers,
        body: Vec::new(),
    }
}

/// Builds the ACK a client transaction sends for a non-2xx final response
/// (§17.1.1.3): same Via/From/Call-ID as the INVITE, the response's `To`, and
/// a CSeq with method ACK. No body.
pub fn ack_for_non_2xx(invite: &Request, response: &Response) -> Request {
    let mut headers = Vec::new();
    for header in &invite.headers {
        if matches!(
            canonical_header(&header.name).as_str(),
            "via" | "from" | "call-id"
        ) {
            headers.push(header.clone());
        }
    }
    let to = header(&response.headers, "to")
        .or_else(|| header(&invite.headers, "to"))
        .unwrap_or("")
        .to_string();
    headers.push(Header {
        name: "To".to_string(),
        value: to,
    });
    let number = cseq_parts(header(&invite.headers, "cseq").unwrap_or(""))
        .map(|(number, _)| number.to_string())
        .unwrap_or_default();
    headers.push(Header {
        name: "CSeq".to_string(),
        value: format!("{number} ACK"),
    });
    Request {
        method: Method::Ack,
        uri: invite.uri.clone(),
        headers,
        body: Vec::new(),
    }
}

/// Builds the ACK for a 2xx response to our INVITE (RFC 3261 §13.2.2.4).
/// This ACK starts a new transaction, so it gets a **fresh Via branch** (the
/// caller supplies the Via), and it goes to the remote target (the response's
/// Contact) — not back to the INVITE's request-URI. CSeq keeps the INVITE's
/// number with method ACK.
pub fn ack_for_2xx(invite: &Request, response: &Response, via: &str, contact: &str) -> Request {
    let mut headers = vec![
        Header {
            name: "Via".to_string(),
            value: via.to_string(),
        },
        Header {
            name: "Max-Forwards".to_string(),
            value: "70".to_string(),
        },
    ];
    for header in &invite.headers {
        if matches!(canonical_header(&header.name).as_str(), "from" | "call-id") {
            headers.push(header.clone());
        }
    }
    let to = header(&response.headers, "to")
        .or_else(|| header(&invite.headers, "to"))
        .unwrap_or("")
        .to_string();
    headers.push(Header {
        name: "To".to_string(),
        value: to,
    });
    let number = cseq_parts(header(&invite.headers, "cseq").unwrap_or(""))
        .map(|(number, _)| number.to_string())
        .unwrap_or_default();
    headers.push(Header {
        name: "CSeq".to_string(),
        value: format!("{number} ACK"),
    });
    headers.push(Header {
        name: "Contact".to_string(),
        value: contact.to_string(),
    });
    let remote_target = header(&response.headers, "contact")
        .map(crate::dialog::uri_of)
        .filter(|uri| !uri.is_empty())
        .unwrap_or(&invite.uri)
        .to_string();
    Request {
        method: Method::Ack,
        uri: remote_target,
        headers,
        body: Vec::new(),
    }
}

/// The `branch=` parameter of the topmost `Via`, if any.
pub fn branch(headers: &[Header]) -> Option<&str> {
    let via = header(headers, "via")?;
    for parameter in via.split(';').skip(1) {
        let mut parts = parameter.trim().splitn(2, '=');
        let name = parts.next().unwrap_or("");
        if name.eq_ignore_ascii_case("branch") {
            return parts.next().map(|value| value.trim());
        }
    }
    None
}

/// Splits a CSeq value into `(sequence number, method)`.
pub fn cseq_parts(value: &str) -> Option<(&str, &str)> {
    let mut parts = value.split_whitespace();
    let number = parts.next()?;
    let method = parts.next()?;
    Some((number, method))
}

fn cseq_number(headers: &[Header]) -> Option<&str> {
    cseq_parts(header(headers, "cseq")?).map(|(number, _)| number)
}

fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    let want = canonical_header(name);
    headers
        .iter()
        .find(|header| canonical_header(&header.name) == want)
        .map(|header| header.value.as_str())
}

fn earliest(a: (u64, Timer), b: (u64, Timer)) -> (u64, Timer) {
    if a.0 <= b.0 {
        a
    } else {
        b
    }
}
