//! SDP parsing (RFC 4566) — the subset we need: media lines.
//!
//! Everything except `m=` lines is ignored. That is deliberate: we only need to
//! know "what media, where, transported how, which payload types" to answer an
//! offer (docs/07).

use crate::parse::split_line;
use crate::ParseError;

/// A parsed SDP session: just its media descriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sdp {
    /// One entry per `m=` line.
    pub media: Vec<MediaDescription>,
}

/// One `m=` media description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaDescription {
    /// Media type ("audio", "image", "application", ...).
    pub media: String,
    /// Port (the `N` in `N/` is dropped).
    pub port: u16,
    /// Transport ("RTP/AVP", "udptl", ...).
    pub transport: String,
    /// Payload type numbers from the format list. Non-numeric format tokens
    /// (e.g. `t38` in `m=image`) are ignored — we only need the numbers.
    pub payload_types: Vec<u8>,
    /// Connection address (`c=`): media-level if present, else session-level.
    pub connection: Option<String>,
}

const MAX_SDP_LINE: usize = 8_192;
const MAX_MEDIA: usize = 64;

/// Parses an SDP body. Lines that are not `m=` (or `c=`) lines are ignored; a
/// malformed `m=` line is an error.
pub fn parse_sdp(input: &[u8]) -> Result<Sdp, ParseError> {
    let mut media = Vec::new();
    let mut session_connection: Option<String> = None;
    let mut current: Option<MediaDescription> = None;
    let mut rest = input;
    while !rest.is_empty() {
        // A final line without a trailing newline is still a line.
        let (line, next) = match split_line(rest) {
            Some((line, next)) => (line, next),
            None => (rest, &[][..]),
        };
        rest = next;
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_SDP_LINE {
            return Err(ParseError::LimitExceeded);
        }
        if let Some(fields) = line.strip_prefix(b"m=") {
            if let Some(description) = current.take() {
                media.push(description);
            }
            if media.len() >= MAX_MEDIA {
                return Err(ParseError::LimitExceeded);
            }
            let mut description = parse_media_line(fields)?;
            description.connection = session_connection.clone();
            current = Some(description);
        } else if let Some(fields) = line.strip_prefix(b"c=") {
            let address = parse_connection_line(fields);
            match &mut current {
                Some(description) => description.connection = Some(address),
                None => session_connection = Some(address),
            }
        }
    }
    if let Some(description) = current.take() {
        media.push(description);
    }
    Ok(Sdp { media })
}

/// `c=IN IP4 192.0.2.1` → "192.0.2.1" (the last field).
fn parse_connection_line(fields: &[u8]) -> String {
    let line = String::from_utf8_lossy(fields);
    line.split_whitespace()
        .last()
        .unwrap_or("")
        .trim()
        .to_string()
}

fn parse_media_line(fields: &[u8]) -> Result<MediaDescription, ParseError> {
    let mut parts = fields.split(|&b| b == b' ').filter(|part| !part.is_empty());
    let media = parts.next().ok_or(ParseError::BadHeader)?;
    let port = parts.next().ok_or(ParseError::BadHeader)?;
    let transport = parts.next().ok_or(ParseError::BadHeader)?;
    if media.is_empty() || transport.is_empty() {
        return Err(ParseError::BadHeader);
    }

    // Port may be written as "5004/2" (port/number-of-ports); take the port.
    let port_bytes = port
        .split(|&b| b == b'/')
        .next()
        .ok_or(ParseError::BadHeader)?;
    let port: u16 = std::str::from_utf8(port_bytes)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(ParseError::BadHeader)?;

    let mut payload_types = Vec::new();
    for part in parts {
        // Non-numeric format tokens exist in the wild (T.38 uses "t38");
        // only payload numbers matter to us.
        if let Ok(pt) = std::str::from_utf8(part)
            .map_err(|_| ParseError::BadHeader)?
            .parse::<u8>()
        {
            payload_types.push(pt);
        }
    }

    Ok(MediaDescription {
        media: std::str::from_utf8(media)
            .map_err(|_| ParseError::BadHeader)?
            .to_string(),
        port,
        transport: std::str::from_utf8(transport)
            .map_err(|_| ParseError::BadHeader)?
            .to_string(),
        payload_types,
        connection: None,
    })
}
