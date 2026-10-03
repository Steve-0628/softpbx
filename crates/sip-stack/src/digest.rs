//! Digest authentication (RFC 2617, MD5) — the only authentication in v1.
//!
//! Tolerant parsing of `Authorization` headers, strict verification of the
//! response hash. Nonce freshness is enforced by the caller (the registrar
//! only accepts nonces it issued, within a short window).

use md5::{Digest, Md5};

fn md5hex(input: &str) -> String {
    format!("{:x}", Md5::digest(input.as_bytes()))
}

/// The challenge sent in `WWW-Authenticate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Realm (shown to the phone; we use it in the password hash).
    pub realm: String,
    /// Opaque-to-the-client nonce.
    pub nonce: String,
}

impl Challenge {
    /// The `WWW-Authenticate` header value for this challenge.
    pub fn header_value(&self) -> String {
        format!(
            "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5",
            self.realm, self.nonce
        )
    }
}

/// Parsed `Authorization: Digest ...` credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Who claims to be authenticating (the device number).
    pub username: String,
    /// Realm the client echoed back.
    pub realm: String,
    /// Nonce the client echoed back.
    pub nonce: String,
    /// Request-URI the client used (echoed into the hash).
    pub uri: String,
    /// The response hash.
    pub response: String,
    /// `qop` value, when the client uses quality-of-protection.
    pub qop: Option<String>,
    /// Nonce count, with `qop`.
    pub nc: Option<String>,
    /// Client nonce, with `qop`.
    pub cnonce: Option<String>,
}

/// Parses an `Authorization: Digest ...` value.
///
/// Tolerant: unknown keys ignored, quotes optional, whitespace flexible.
/// Returns `None` when it is not a usable Digest credential.
pub fn parse_authorization(value: &str) -> Option<Credentials> {
    let mut words = value.trim().splitn(2, char::is_whitespace);
    if !words.next()?.eq_ignore_ascii_case("digest") {
        return None;
    }
    let mut rest = words.next().unwrap_or("").trim();

    let mut fields: Vec<(String, String)> = Vec::new();
    while !rest.is_empty() {
        let (key, after) = rest.split_once('=')?;
        let key = key.trim().to_ascii_lowercase();
        let after = after.trim_start();
        let (field_value, remaining) = if let Some(unquoted) = after.strip_prefix('"') {
            let end = unquoted.find('"')?;
            (unquoted[..end].to_string(), &unquoted[end + 1..])
        } else {
            match after.split_once(',') {
                Some((field_value, remaining)) => (field_value.trim().to_string(), remaining),
                None => (after.trim().to_string(), ""),
            }
        };
        fields.push((key, field_value));
        rest = remaining.trim_start().trim_start_matches(',').trim();
    }

    let get = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, field_value)| field_value.clone())
    };
    // We implement qop=auth only; auth-int (body hashing) is not supported and
    // must not be silently accepted.
    match get("qop").as_deref() {
        None | Some("auth") => {}
        Some(_) => return None,
    }
    Some(Credentials {
        username: get("username")?,
        realm: get("realm")?,
        nonce: get("nonce")?,
        uri: get("uri")?,
        response: get("response")?,
        qop: get("qop"),
        nc: get("nc"),
        cnonce: get("cnonce"),
    })
}

/// Computes the expected `response` hash (RFC 2617 §3.2.2) for these
/// credentials and this request `method`.
pub fn expected_response(credentials: &Credentials, password: &str, method: &str) -> String {
    let ha1 = md5hex(&format!(
        "{}:{}:{}",
        credentials.username, credentials.realm, password
    ));
    let ha2 = md5hex(&format!("{method}:{}", credentials.uri));
    match credentials.qop.as_deref() {
        Some(qop) => md5hex(&format!(
            "{ha1}:{}:{}:{}:{qop}:{ha2}",
            credentials.nonce,
            credentials.nc.as_deref().unwrap_or(""),
            credentials.cnonce.as_deref().unwrap_or(""),
        )),
        None => md5hex(&format!("{ha1}:{}:{ha2}", credentials.nonce)),
    }
}

/// Verifies credentials against the password for this request `method`.
pub fn verify(credentials: &Credentials, password: &str, method: &str) -> bool {
    let expected = expected_response(credentials, password, method);
    expected.eq_ignore_ascii_case(&credentials.response)
}
