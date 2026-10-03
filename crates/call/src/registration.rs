//! Registration: which device is where (docs/03 §1).
//!
//! A device (today: a phone) announces "my number is 1001 and I am here" with
//! a REGISTER carrying digest credentials. We keep the binding in memory with
//! an expiry; when the daemon restarts, phones simply register again.

use std::collections::HashMap;

use sip_stack::digest::{self, Challenge};
use sip_stack::make_response;
use sip_syntax::{Header, Request, Response};

/// Registration lifetime a device gets when it does not ask for one.
pub const DEFAULT_EXPIRES_S: u64 = 3_600;
/// Shortest lifetime we grant.
pub const MIN_EXPIRES_S: u64 = 60;
/// Longest lifetime we grant.
pub const MAX_EXPIRES_S: u64 = 86_400;

/// A device that may register: a number, a display name, a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Its number ("1001").
    pub number: String,
    /// Display name ("Alice").
    pub name: String,
    /// Password the device uses to register.
    pub secret: String,
}

/// Where a registered device is, and until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// Contact address ("sip:alice@192.0.2.1:5060").
    pub contact: String,
    /// Absolute expiry time in ms (simulated or real time, caller's clock).
    pub expires_at_ms: u64,
}

/// The registrar: known devices and their current bindings. In memory only.
#[derive(Debug)]
pub struct Registrar {
    realm: String,
    devices: HashMap<String, Device>,
    bindings: HashMap<String, Binding>,
    nonce_counter: u64,
}

impl Registrar {
    /// Creates a registrar for the given devices.
    pub fn new(realm: &str, devices: Vec<Device>) -> Self {
        Registrar {
            realm: realm.to_string(),
            devices: devices
                .into_iter()
                .map(|device| (device.number.clone(), device))
                .collect(),
            bindings: HashMap::new(),
            nonce_counter: 0,
        }
    }

    /// Handles a REGISTER and returns the response to send.
    ///
    /// Rules (docs/03 §1): unknown number → `403`; missing or wrong
    /// credentials → `401` with a fresh challenge; `Expires: 0` (or `Contact: *`)
    /// removes the binding; otherwise the binding is stored and echoed back.
    pub fn handle_register(&mut self, request: &Request, now_ms: u64) -> Response {
        let Some(number) = number_from_request(request) else {
            return make_response(request, 400, "Bad Request");
        };
        let Some(device) = self.devices.get(&number).cloned() else {
            return make_response(request, 403, "Forbidden");
        };

        if !self.is_authorized(request, &device) {
            let challenge = Challenge {
                realm: self.realm.clone(),
                nonce: self.next_nonce(now_ms),
            };
            let mut response = make_response(request, 401, "Unauthorized");
            response.headers.push(Header {
                name: "WWW-Authenticate".to_string(),
                value: challenge.header_value(),
            });
            return response;
        }

        let expires_s = requested_expires_s(request).unwrap_or(DEFAULT_EXPIRES_S);
        if expires_s == 0 || contact_is_wildcard(request) {
            self.bindings.remove(&number);
            let mut response = make_response(request, 200, "OK");
            response.headers.push(Header {
                name: "Expires".to_string(),
                value: "0".to_string(),
            });
            return response;
        }

        let expires_s = expires_s.clamp(MIN_EXPIRES_S, MAX_EXPIRES_S);
        let Some(contact) = contact_of(request) else {
            return make_response(request, 400, "Bad Request");
        };
        self.bindings.insert(
            number,
            Binding {
                contact,
                expires_at_ms: now_ms + expires_s * 1_000,
            },
        );

        let mut response = make_response(request, 200, "OK");
        if let Some(contact) = header(&request.headers, "contact") {
            response.headers.push(Header {
                name: "Contact".to_string(),
                value: contact.to_string(),
            });
        }
        response.headers.push(Header {
            name: "Expires".to_string(),
            value: expires_s.to_string(),
        });
        response
    }

    /// Where a registered, unexpired device is.
    pub fn lookup(&self, number: &str, now_ms: u64) -> Option<&str> {
        let binding = self.bindings.get(number)?;
        if binding.expires_at_ms <= now_ms {
            return None;
        }
        Some(&binding.contact)
    }

    /// The binding of a device, even if the caller wants to see the expiry.
    pub fn binding(&self, number: &str) -> Option<&Binding> {
        self.bindings.get(number)
    }

    /// Numbers of all currently registered (unexpired) devices, sorted.
    pub fn registered(&self, now_ms: u64) -> Vec<String> {
        let mut numbers: Vec<String> = self
            .bindings
            .iter()
            .filter(|(_, binding)| binding.expires_at_ms > now_ms)
            .map(|(number, _)| number.clone())
            .collect();
        numbers.sort();
        numbers
    }

    /// Drops expired bindings.
    pub fn expire(&mut self, now_ms: u64) {
        self.bindings
            .retain(|_, binding| binding.expires_at_ms > now_ms);
    }

    /// The realm used in challenges.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    fn is_authorized(&self, request: &Request, device: &Device) -> bool {
        let Some(value) = header(&request.headers, "authorization") else {
            return false;
        };
        let Some(credentials) = digest::parse_authorization(value) else {
            return false;
        };
        credentials.username == device.number
            && digest::verify(&credentials, &device.secret, request.method.as_str())
    }

    fn next_nonce(&mut self, now_ms: u64) -> String {
        self.nonce_counter += 1;
        format!("{now_ms:x}-{:x}", self.nonce_counter)
    }
}

/// The number a REGISTER is about: the user part of `To` (the address of
/// record, RFC 3261 §10), falling back to the Request-URI.
/// `<sip:1001@192.0.2.10>` → `1001`.
pub fn number_from_request(request: &Request) -> Option<String> {
    let to = header(&request.headers, "to").unwrap_or("");
    number_from_uri(to).or_else(|| number_from_uri(&request.uri))
}

/// The user part of a SIP URI: `<sip:1001@192.0.2.10>` → `1001`. A URI
/// without `@` has no user part at all.
pub fn number_from_uri(uri: &str) -> Option<String> {
    let uri = uri.trim().trim_start_matches('<').trim_end_matches('>');
    let rest = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))
        .unwrap_or(uri);
    // No '@' means no user part at all ("sip:192.0.2.10" is a host).
    let user = rest.split('@').next().unwrap_or("").trim();
    if user.is_empty() || !rest.contains('@') {
        None
    } else {
        Some(user.to_string())
    }
}

fn contact_of(request: &Request) -> Option<String> {
    let contact = header(&request.headers, "contact")?.trim();
    let address = match contact.split_once('>') {
        Some((open, _)) => open.trim_start_matches('<').trim(),
        None => contact.split(';').next().unwrap_or("").trim(),
    };
    if address.is_empty() || address == "*" {
        None
    } else {
        Some(address.to_string())
    }
}

fn contact_is_wildcard(request: &Request) -> bool {
    header(&request.headers, "contact")
        .map(|contact| contact.trim() == "*")
        .unwrap_or(false)
}

/// Requested lifetime: `Expires` header, else the Contact `;expires=` parameter.
fn requested_expires_s(request: &Request) -> Option<u64> {
    if let Some(expires) = header(&request.headers, "expires") {
        return expires.trim().parse().ok();
    }
    let contact = header(&request.headers, "contact")?;
    for parameter in contact.split(';').skip(1) {
        let mut parts = parameter.trim().splitn(2, '=');
        if parts
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("expires")
        {
            return parts.next().and_then(|value| value.trim().parse().ok());
        }
    }
    None
}

pub(crate) fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    let want = sip_syntax::canonical_header(name);
    headers
        .iter()
        .find(|header| sip_syntax::canonical_header(&header.name) == want)
        .map(|header| header.value.as_str())
}
