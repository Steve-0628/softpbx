//! SIP message and SDP parsing.
//!
//! Pure functions: no I/O, no dependencies. Input is bytes, output is typed data.
//! Malformed input produces a [`ParseError`] — never a panic, never unbounded
//! memory growth (docs/07).
//!
//! The boundary of what we parse is defined in `docs/07-sip-subset.md`. This
//! crate is deliberately lenient about *what* it accepts (real phones are
//! messy) and strict about *how much* (resource limits).

mod parse;
mod sdp;
mod serialize;

pub use parse::{parse_message, parse_message_with_limits};
pub use sdp::{parse_sdp, MediaDescription, Sdp};
pub use serialize::serialize_message;

/// SIP version. Only SIP/2.0 exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// SIP/2.0.
    V2,
}

/// SIP method.
///
/// The six methods we implement are named variants. Anything else is kept
/// verbatim in [`Method::Other`]: we still parse it (so we can answer 405 with
/// an `Allow` header, docs/07), but we do not act on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// Call setup.
    Invite,
    /// Confirms an INVITE.
    Ack,
    /// Ends a call.
    Bye,
    /// Cancels a call that is still ringing.
    Cancel,
    /// Registers a device's address.
    Register,
    /// Capability probe / keepalive.
    Options,
    /// Any other method, kept exactly as received.
    Other(String),
}

impl Method {
    /// Parses a wire-form method name (case-sensitive, as the RFC requires).
    pub fn parse(name: &str) -> Self {
        match name {
            "INVITE" => Method::Invite,
            "ACK" => Method::Ack,
            "BYE" => Method::Bye,
            "CANCEL" => Method::Cancel,
            "REGISTER" => Method::Register,
            "OPTIONS" => Method::Options,
            other => Method::Other(other.to_string()),
        }
    }

    /// The wire form ("INVITE" etc.).
    pub fn as_str(&self) -> &str {
        match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Register => "REGISTER",
            Method::Options => "OPTIONS",
            Method::Other(name) => name,
        }
    }
}

/// A header field (name and value). Order of appearance is preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Field name, with the spelling the sender used ("Call-ID", "call-id", "i").
    pub name: String,
    /// Field value, surrounding whitespace trimmed.
    pub value: String,
}

/// A SIP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Request-URI, kept as a string (we copy and compare; we do not audit it).
    pub uri: String,
    /// Header fields in order of appearance.
    pub headers: Vec<Header>,
    /// Body (e.g. SDP).
    pub body: Vec<u8>,
}

/// A SIP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Status code (100..=699).
    pub status: u16,
    /// Reason phrase.
    pub reason: String,
    /// Header fields in order of appearance.
    pub headers: Vec<Header>,
    /// Body (e.g. SDP).
    pub body: Vec<u8>,
}

/// A SIP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A request.
    Request(Request),
    /// A response.
    Response(Response),
}

impl Message {
    /// Header fields in order of appearance.
    pub fn headers(&self) -> &[Header] {
        match self {
            Message::Request(r) => &r.headers,
            Message::Response(r) => &r.headers,
        }
    }

    /// Body bytes.
    pub fn body(&self) -> &[u8] {
        match self {
            Message::Request(r) => &r.body,
            Message::Response(r) => &r.body,
        }
    }

    /// First header field matching `name`, compared case-insensitively with
    /// compact forms resolved ("i" finds "Call-ID", and vice versa).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers_all(name).first().copied()
    }

    /// Every header field matching `name`, in order of appearance.
    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        let want = canonical_header(name);
        self.headers()
            .iter()
            .filter(|h| canonical_header(&h.name) == want)
            .map(|h| h.value.as_str())
            .collect()
    }
}

/// Whether this datagram is a transport keepalive rather than a message:
/// just CRLFs (RFC 5626 double-CRLF ping). Real phones send these constantly;
/// there is nothing to parse and nothing to answer beyond a bare CRLF.
pub fn is_keepalive(input: &[u8]) -> bool {
    !input.is_empty() && input.iter().all(|&b| b == b'\r' || b == b'\n')
}

/// Canonical (lowercase, long form) name of a header field.
///
/// Single-letter compact forms (RFC 3261 §7.3.3) are expanded first:
/// `v` → "via", `i` → "call-id", `m` → "contact", `l` → "content-length", etc.
/// Compact letters are matched case-insensitively (real devices send `I:`).
/// Used for comparisons only; the original spelling is kept in [`Header::name`].
pub fn canonical_header(name: &str) -> String {
    let expanded = match name.to_ascii_lowercase().as_str() {
        "v" => "Via",
        "l" => "Content-Length",
        "f" => "From",
        "i" => "Call-ID",
        "m" => "Contact",
        "c" => "Content-Type",
        "k" => "Supported",
        "e" => "Content-Encoding",
        "s" => "Subject",
        "t" => "To",
        "x" => "Session-Expires",
        _ => name,
    };
    expanded.to_ascii_lowercase()
}

/// Why parsing failed.
///
/// Fuzzing contract: arbitrary input must produce one of these — never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Input ends mid-message; the caller should supply the rest (TCP streams).
    /// Over UDP a complete datagram that yields this is simply rejected.
    Incomplete,
    /// The start line is malformed.
    BadStartLine,
    /// A header field is malformed (missing colon, bad name, control bytes).
    BadHeader,
    /// `Content-Length` is unusable: not a number, or two conflicting values.
    BadBodyLength,
    /// A resource limit was exceeded (see [`Limits`]).
    LimitExceeded,
}

/// Resource limits for parsing. Defaults are generous for SIP, tight enough to
/// be safe against garbage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum total message size in bytes (docs/07: UDP cap).
    pub max_message: usize,
    /// Maximum start line length.
    pub max_start_line: usize,
    /// Maximum length of one header line.
    pub max_header_line: usize,
    /// Maximum number of header fields.
    pub max_headers: usize,
    /// Maximum body size.
    pub max_body: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_message: 65_535,
            max_start_line: 1_024,
            max_header_line: 8_192,
            max_headers: 128,
            max_body: 16_384,
        }
    }
}
