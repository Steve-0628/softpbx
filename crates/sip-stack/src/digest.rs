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

/// A `WWW-Authenticate: Digest ...` challenge from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestChallenge {
    /// The peer's realm.
    pub realm: String,
    /// The peer's nonce.
    pub nonce: String,
    /// Opaque token to echo back, when offered.
    pub opaque: Option<String>,
    /// Quality of protection offered ("auth" is what we answer).
    pub qop: Option<String>,
}

/// Parses a `WWW-Authenticate: Digest ...` challenge.
pub fn parse_challenge(value: &str) -> Option<DigestChallenge> {
    let mut words = value.trim().splitn(2, char::is_whitespace);
    if !words.next()?.eq_ignore_ascii_case("digest") {
        return None;
    }
    let fields = digest_fields(words.next().unwrap_or(""))?;
    let get = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, field_value)| field_value.clone())
    };
    Some(DigestChallenge {
        realm: get("realm")?,
        nonce: get("nonce")?,
        opaque: get("opaque"),
        qop: get("qop"),
    })
}

/// Builds the `Authorization` header value answering a challenge (RFC 2617).
/// `cnonce` is deterministic so tests reproduce byte for byte.
pub fn authorization_value(
    challenge: &DigestChallenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> String {
    let qop_auth = challenge
        .qop
        .as_deref()
        .map(|qop| qop.split(',').any(|q| q.trim() == "auth"))
        .unwrap_or(false);
    let credentials = Credentials {
        username: username.to_string(),
        realm: challenge.realm.clone(),
        nonce: challenge.nonce.clone(),
        uri: uri.to_string(),
        response: String::new(),
        qop: qop_auth.then(|| "auth".to_string()),
        nc: qop_auth.then(|| "00000001".to_string()),
        cnonce: qop_auth.then(|| "softpbx".to_string()),
    };
    let response = expected_response(&credentials, password, method);
    let mut value = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5",
        username, challenge.realm, challenge.nonce, uri, response
    );
    if qop_auth {
        value.push_str(", qop=auth, nc=00000001, cnonce=\"softpbx\"");
    }
    if let Some(opaque) = &challenge.opaque {
        value.push_str(&format!(", opaque=\"{opaque}\""));
    }
    value
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
    let fields = digest_fields(words.next().unwrap_or(""))?;
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

/// Scans `key=value, key="quoted"` fields.
fn digest_fields(input: &str) -> Option<Vec<(String, String)>> {
    let mut rest = input.trim();
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
    Some(fields)
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
