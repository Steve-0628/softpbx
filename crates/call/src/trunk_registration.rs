//! Outbound REGISTER transaction user (RFC 3261 sections 10 and 17).
//! Driven by the same explicit clock and UDP transactions as calls.
use std::collections::HashMap;
use std::net::SocketAddr;

use sip_stack::{cseq_parts, digest, make_response, uri_of, Action, ClientTransaction};
use sip_syntax::{canonical_header, Header, Method, Request, Response};

use crate::registration::{header, number_from_request, Binding, NonceStore};
use crate::switch::{Output, TrunkAuth};

/// How a trunk locates its peer. Static trunks remain the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrunkRegistration {
    #[default]
    None,
    /// Accept authenticated registrations using the inbound credentials.
    Incoming,
    /// Register using the outbound credentials, refreshing before expiry.
    Outgoing { expires_s: u64 },
}

#[derive(Debug)]
pub(crate) struct OutboundRegistration {
    pub(crate) name: String,
    peer: SocketAddr,
    local: SocketAddr,
    auth: TrunkAuth,
    call_id: String,
    cseq: u64,
    expires_s: u64,
    next_ms: u64,
    registered_until_ms: u64,
    retries: u8,
    tx: Option<ClientTransaction>,
}

fn field(name: &str, value: impl ToString) -> Header {
    Header {
        name: name.into(),
        value: value.to_string(),
    }
}

impl OutboundRegistration {
    pub(crate) fn new(
        name: String,
        peer: SocketAddr,
        local: SocketAddr,
        auth: TrunkAuth,
        expires_s: u64,
        call_id: String,
    ) -> Self {
        Self {
            name,
            peer,
            local,
            auth,
            call_id,
            cseq: 0,
            expires_s,
            next_ms: 0,
            registered_until_ms: 0,
            retries: 0,
            tx: None,
        }
    }

    pub(crate) fn registered(&self, now_ms: u64) -> bool {
        now_ms < self.registered_until_ms
    }

    pub(crate) fn timer(&self) -> (String, u64) {
        let due = self
            .tx
            .as_ref()
            .and_then(|tx| tx.next_timer())
            .map(|(due, _)| due)
            .unwrap_or(self.next_ms);
        (format!("register:{}:{}", self.name, self.cseq), due)
    }

    pub(crate) fn on_timer(&mut self, now_ms: u64) -> Vec<Output> {
        if let Some(tx) = &mut self.tx {
            if let Some((due, timer)) = tx.next_timer() {
                if due <= now_ms {
                    let actions = tx.on_timer(timer, now_ms);
                    if actions.contains(&Action::Timeout) {
                        self.fail(now_ms, 30);
                    }
                    return sends(actions);
                }
            }
            return vec![];
        }
        if self.next_ms > now_ms {
            return vec![];
        }
        self.retries = 0;
        self.send(None, now_ms)
    }

    fn contact(&self) -> String {
        format!("sip:{}@{}", self.auth.username, self.local)
    }

    fn send(&mut self, authorization: Option<Header>, now_ms: u64) -> Vec<Output> {
        self.cseq += 1;
        let aor = format!("sip:{}@{}", self.auth.username, self.peer);
        let mut request = Request {
            method: Method::Register,
            uri: format!("sip:{}", self.peer),
            headers: vec![
                field(
                    "Via",
                    format!(
                        "SIP/2.0/UDP {};branch=z9hG4bK-{}-{};rport",
                        self.local, self.call_id, self.cseq
                    ),
                ),
                field("Max-Forwards", 70),
                field("From", format!("<{aor}>;tag={}", self.call_id)),
                field("To", format!("<{aor}>")),
                field("Call-ID", &self.call_id),
                field("CSeq", format!("{} REGISTER", self.cseq)),
                field("Contact", format!("<{}>", self.contact())),
                field("Expires", self.expires_s),
            ],
            body: vec![],
        };
        if let Some(auth) = authorization {
            request.headers.push(auth);
        }
        let (tx, actions) = ClientTransaction::new(request, now_ms);
        self.tx = Some(tx);
        sends(actions)
    }

    pub(crate) fn matches(&self, response: &Response) -> bool {
        self.tx
            .as_ref()
            .is_some_and(|tx| tx.matches_response(response))
            && header(&response.headers, "call-id") == Some(self.call_id.as_str())
            && header(&response.headers, "cseq")
                .and_then(cseq_parts)
                .is_some_and(|(number, method)| {
                    number.parse::<u64>().ok() == Some(self.cseq) && method == "REGISTER"
                })
    }

    pub(crate) fn response(&mut self, response: Response, now_ms: u64) -> Vec<Output> {
        let actions = self.tx.as_mut().unwrap().on_response(response, now_ms);
        let mut outputs = vec![];
        for action in actions {
            let Action::DeliverResponse(response) = action else {
                continue;
            };
            if response.status < 200 {
                continue;
            }
            // There is no ACK for REGISTER. A completed transaction is replaced
            // only by a new CSeq/branch; duplicate old finals cannot change state.
            self.tx = None;
            match response.status {
                401 | 407 if self.retries < 2 => {
                    let (challenge_name, auth_name) = if response.status == 407 {
                        ("proxy-authenticate", "Proxy-Authorization")
                    } else {
                        ("www-authenticate", "Authorization")
                    };
                    let challenge = response
                        .headers
                        .iter()
                        .filter(|h| h.name.eq_ignore_ascii_case(challenge_name))
                        .find_map(|h| digest::parse_challenge(&h.value));
                    if let Some(challenge) = challenge.filter(|c| {
                        c.qop
                            .as_ref()
                            .is_none_or(|q| q.split(',').any(|q| q.trim() == "auth"))
                    }) {
                        self.retries += 1;
                        let value = digest::authorization_value_with_cnonce(
                            &challenge,
                            &self.auth.username,
                            &self.auth.secret,
                            "REGISTER",
                            &format!("sip:{}", self.peer),
                            &format!("{}-{}", self.call_id, self.cseq + 1),
                        );
                        outputs.extend(self.send(Some(field(auth_name, value)), now_ms));
                    } else {
                        self.fail(now_ms, 30);
                    }
                }
                423 if self.retries < 2 => {
                    if let Some(min) = header(&response.headers, "min-expires")
                        .and_then(|s| s.parse::<u64>().ok())
                        .filter(|s| *s > self.expires_s && *s <= 86_400)
                    {
                        self.expires_s = min;
                        self.retries += 1;
                        outputs.extend(self.send(None, now_ms));
                    } else {
                        self.fail(now_ms, 30);
                    }
                }
                200..=299 => {
                    let contact = self.contact();
                    // Match our binding, not another registrant sharing the AOR.
                    let binding = response
                        .headers
                        .iter()
                        .filter(|h| canonical_header(&h.name) == "contact")
                        .flat_map(|h| h.value.split(','))
                        .find(|value| uri_of(value.trim()) == contact);
                    let Some(binding) = binding else {
                        // A 200 for another contact is not our registration.
                        self.fail(now_ms, 30);
                        continue;
                    };
                    let granted = contact_expires(binding)
                        .or_else(|| {
                            header(&response.headers, "expires").and_then(|s| s.parse().ok())
                        })
                        .unwrap_or(self.expires_s)
                        .min(86_400);
                    if granted == 0 {
                        self.registered_until_ms = 0;
                        self.fail(now_ms, 30);
                    } else {
                        self.registered_until_ms = now_ms.saturating_add(granted * 1_000);
                        self.next_ms = now_ms.saturating_add((granted * 800).max(1));
                    }
                }
                _ => {
                    let delay = header(&response.headers, "retry-after")
                        .and_then(|v| v.split(';').next()?.trim().parse().ok())
                        .unwrap_or(30);
                    self.fail(now_ms, delay);
                }
            }
        }
        outputs
    }

    fn fail(&mut self, now_ms: u64, delay_s: u64) {
        self.tx = None;
        self.next_ms = now_ms.saturating_add(delay_s.max(1).saturating_mul(1_000));
    }
}

pub(crate) fn contact_expires(value: &str) -> Option<u64> {
    let parameters = value.rsplit_once('>').map(|(_, p)| p).unwrap_or(value);
    parameters.split(';').skip(1).find_map(|p| {
        let (name, value) = p.trim().split_once('=')?;
        name.eq_ignore_ascii_case("expires")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

fn sends(actions: Vec<Action>) -> Vec<Output> {
    actions
        .into_iter()
        .filter_map(|a| match a {
            Action::Send(m) => Some(Output::Send(m)),
            _ => None,
        })
        .collect()
}

/// One live contact and the last successful transaction per trunk account.
/// Keeping this separate leaves the existing phone registrar unchanged.
#[derive(Debug)]
struct IncomingAccount {
    secret: String,
    binding: Option<Binding>,
    last: Option<(Request, Response)>,
}

#[derive(Debug)]
pub(crate) struct IncomingRegistrations {
    realm: String,
    accounts: HashMap<String, IncomingAccount>,
    nonces: NonceStore,
}

impl IncomingRegistrations {
    pub(crate) fn new(realm: &str, credentials: Vec<TrunkAuth>) -> Self {
        Self {
            realm: realm.into(),
            accounts: credentials
                .into_iter()
                .map(|a| {
                    (
                        a.username,
                        IncomingAccount {
                            secret: a.secret,
                            binding: None,
                            last: None,
                        },
                    )
                })
                .collect(),
            nonces: NonceStore::new(realm),
        }
    }

    pub(crate) fn lookup(&self, username: &str, now_ms: u64) -> Option<&str> {
        self.accounts
            .get(username)?
            .binding
            .as_ref()
            .filter(|b| b.expires_at_ms > now_ms)
            .map(|b| b.contact.as_str())
    }

    pub(crate) fn is_registered(&self, username: &str, now_ms: u64) -> bool {
        self.lookup(username, now_ms).is_some()
    }

    pub(crate) fn expire(&mut self, now_ms: u64) {
        for account in self.accounts.values_mut() {
            if account
                .binding
                .as_ref()
                .is_some_and(|b| b.expires_at_ms <= now_ms)
            {
                account.binding = None;
                account.last = None;
            }
        }
    }

    pub(crate) fn handle_register(&mut self, request: &Request, now_ms: u64) -> Response {
        let Some(account) = number_from_request(request).and_then(|n| self.accounts.get_mut(&n))
        else {
            return make_response(request, 403, "Forbidden");
        };
        let authorized = header(&request.headers, "authorization")
            .and_then(digest::parse_authorization)
            .filter(|c| {
                Some(&c.username) == number_from_request(request).as_ref()
                    && c.realm == self.realm
                    && c.uri == request.uri
            })
            .is_some_and(|c| self.nonces.authorize(&c, &account.secret, request, now_ms));
        if !authorized {
            let mut response = make_response(request, 401, "Unauthorized");
            response.headers.push(field(
                "WWW-Authenticate",
                self.nonces.challenge(now_ms).header_value(),
            ));
            return response;
        }
        if let Some((previous, response)) = &account.last {
            if previous == request {
                return response.clone();
            }
            // Retransmissions are answered above; older transactions cannot
            // replace or remove a newer binding with the same Call-ID.
            if header(&previous.headers, "call-id") == header(&request.headers, "call-id") {
                let seq = |r: &Request| {
                    header(&r.headers, "cseq")
                        .and_then(cseq_parts)
                        .and_then(|(n, _)| n.parse::<u64>().ok())
                };
                if seq(request)
                    .zip(seq(previous))
                    .is_some_and(|(new, old)| new <= old)
                {
                    return make_response(request, 500, "CSeq Out of Order");
                }
            }
        }
        let contact = header(&request.headers, "contact");
        let mut response = make_response(request, 200, "OK");
        if let Some(contact) = contact {
            let expires = contact_expires(contact)
                .or_else(|| header(&request.headers, "expires").and_then(|v| v.parse().ok()))
                .unwrap_or(3600)
                .min(86400);
            let uri = uri_of(contact);
            let wildcard = contact.trim() == "*";
            if (wildcard && expires != 0)
                || (!wildcard
                    && (!uri.starts_with("sip:")
                        || uri.contains(char::is_whitespace)
                        || contact.contains(',')))
                || request
                    .headers
                    .iter()
                    .filter(|h| canonical_header(&h.name) == "contact")
                    .count()
                    != 1
            {
                return make_response(request, 400, "Bad Request");
            }
            if expires > 0 && expires < 60 {
                let mut response = make_response(request, 423, "Interval Too Brief");
                response.headers.push(field("Min-Expires", 60));
                return response;
            }
            if expires == 0 {
                if wildcard || account.binding.as_ref().is_some_and(|b| b.contact == uri) {
                    account.binding = None;
                }
            } else {
                account.binding = Some(Binding {
                    contact: uri.into(),
                    expires_at_ms: now_ms.saturating_add(expires * 1000),
                });
            }
        }
        // No Contact is an authenticated query; report the remaining lease
        // without changing it. Contact expiry also reports the granted lifetime.
        if let Some(binding) = account
            .binding
            .as_ref()
            .filter(|b| b.expires_at_ms > now_ms)
        {
            response.headers.push(field(
                "Contact",
                format!(
                    "<{}>;expires={}",
                    binding.contact,
                    (binding.expires_at_ms - now_ms).div_ceil(1000)
                ),
            ));
        }
        account.last = Some((request.clone(), response.clone()));
        response
    }
}
