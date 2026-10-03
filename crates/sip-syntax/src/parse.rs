//! Message parsing: start line, header fields, body. See `docs/07-sip-subset.md`.

use std::str;

use crate::{canonical_header, Header, Limits, Message, Method, ParseError, Request, Response};

/// Parses one complete SIP message with the default [`Limits`].
///
/// If the input ends mid-message (a TCP stream fragment), returns
/// [`ParseError::Incomplete`]; the caller accumulates the rest. Over UDP the
/// datagram is the message, so `Incomplete` simply means "reject".
pub fn parse_message(input: &[u8]) -> Result<Message, ParseError> {
    parse_message_with_limits(input, &Limits::default())
}

/// Parses one complete SIP message with explicit limits.
pub fn parse_message_with_limits(input: &[u8], limits: &Limits) -> Result<Message, ParseError> {
    if input.is_empty() {
        return Err(ParseError::Incomplete);
    }
    if input.len() > limits.max_message {
        return Err(ParseError::LimitExceeded);
    }

    let (start_line, mut rest) = split_line(input).ok_or(ParseError::Incomplete)?;
    if start_line.is_empty() {
        return Err(ParseError::BadStartLine);
    }
    if start_line.len() > limits.max_start_line {
        return Err(ParseError::LimitExceeded);
    }
    let start = StartLine::parse(start_line)?;

    // Header fields, until the empty line that ends them.
    let mut headers: Vec<Header> = Vec::new();
    loop {
        let (line, next) = split_line(rest).ok_or(ParseError::Incomplete)?;
        rest = next;
        if line.is_empty() {
            break;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            // Folded continuation of the previous field (RFC 3261 §7).
            let previous = headers.last_mut().ok_or(ParseError::BadHeader)?;
            previous.value.push(' ');
            previous
                .value
                .push_str(str::from_utf8(trim_ws(line)).map_err(|_| ParseError::BadHeader)?);
            continue;
        }
        if line.len() > limits.max_header_line {
            return Err(ParseError::LimitExceeded);
        }
        if headers.len() >= limits.max_headers {
            return Err(ParseError::LimitExceeded);
        }
        headers.push(parse_header_line(line)?);
    }

    // Body: Content-Length decides the size; without it, the rest is the body.
    let body_len = match content_length(&headers)? {
        Some(n) => n,
        None => rest.len(),
    };
    if body_len > limits.max_body {
        return Err(ParseError::LimitExceeded);
    }
    if rest.len() < body_len {
        return Err(ParseError::Incomplete);
    }
    let body = rest[..body_len].to_vec();

    Ok(match start {
        StartLine::Request(method, uri) => Message::Request(Request {
            method: Method::parse(str::from_utf8(method).map_err(|_| ParseError::BadStartLine)?),
            uri: str::from_utf8(uri)
                .map_err(|_| ParseError::BadStartLine)?
                .to_string(),
            headers,
            body,
        }),
        StartLine::Response(status, reason) => Message::Response(Response {
            status,
            reason: reason.to_string(),
            headers,
            body,
        }),
    })
}

enum StartLine<'a> {
    Request(&'a [u8], &'a [u8]),
    Response(u16, &'a str),
}

impl<'a> StartLine<'a> {
    fn parse(line: &'a [u8]) -> Result<Self, ParseError> {
        if line.starts_with(b"SIP/") {
            // Response: SIP/2.0 SP status SP reason (reason may be empty).
            let mut fields = line.splitn(3, |&b| b == b' ');
            let version = fields.next().ok_or(ParseError::BadStartLine)?;
            let status = fields.next().ok_or(ParseError::BadStartLine)?;
            let reason = fields.next().unwrap_or(b"");
            if version != b"SIP/2.0" {
                return Err(ParseError::BadStartLine);
            }
            if status.len() != 3 || !status.iter().all(u8::is_ascii_digit) {
                return Err(ParseError::BadStartLine);
            }
            let status: u16 = str::from_utf8(status)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or(ParseError::BadStartLine)?;
            if !(100..=699).contains(&status) {
                return Err(ParseError::BadStartLine);
            }
            let reason = str::from_utf8(reason).map_err(|_| ParseError::BadStartLine)?;
            Ok(StartLine::Response(status, reason))
        } else {
            // Request: METHOD SP Request-URI SP SIP/2.0.
            let mut fields = line.split(|&b| b == b' ');
            let method = fields.next().ok_or(ParseError::BadStartLine)?;
            let uri = fields.next().ok_or(ParseError::BadStartLine)?;
            let version = fields.next().ok_or(ParseError::BadStartLine)?;
            if fields.next().is_some() {
                return Err(ParseError::BadStartLine);
            }
            if method.is_empty() || !method.iter().copied().all(is_token_char) {
                return Err(ParseError::BadStartLine);
            }
            if uri.is_empty() || uri.contains(&b' ') {
                return Err(ParseError::BadStartLine);
            }
            if version != b"SIP/2.0" {
                return Err(ParseError::BadStartLine);
            }
            Ok(StartLine::Request(method, uri))
        }
    }
}

fn parse_header_line(line: &[u8]) -> Result<Header, ParseError> {
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(ParseError::BadHeader)?;
    let name = &line[..colon];
    if name.is_empty() || !name.iter().copied().all(is_token_char) {
        return Err(ParseError::BadHeader);
    }
    let value = trim_ws(&line[colon + 1..]);
    if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(ParseError::BadHeader);
    }
    Ok(Header {
        name: str::from_utf8(name)
            .map_err(|_| ParseError::BadHeader)?
            .to_string(),
        value: str::from_utf8(value)
            .map_err(|_| ParseError::BadHeader)?
            .to_string(),
    })
}

/// The body length from `Content-Length` (compact form `l` included).
///
/// Two conflicting values are rejected (message smuggling protection). A value
/// that is not a plain number is [`ParseError::BadBodyLength`].
fn content_length(headers: &[Header]) -> Result<Option<usize>, ParseError> {
    let mut found: Option<usize> = None;
    for header in headers {
        if canonical_header(&header.name) == "content-length" {
            let n: usize = header
                .value
                .trim()
                .parse()
                .map_err(|_| ParseError::BadBodyLength)?;
            if let Some(previous) = found {
                if previous != n {
                    return Err(ParseError::BadBodyLength);
                }
            }
            found = Some(n);
        }
    }
    Ok(found)
}

/// Splits one line at `\n`, tolerating `\r\n` and bare `\n` endings.
/// Returns `None` when no line ending is present yet.
pub(crate) fn split_line(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let newline = input.iter().position(|&b| b == b'\n')?;
    let mut end = newline;
    if end > 0 && input[end - 1] == b'\r' {
        end -= 1;
    }
    Some((&input[..end], &input[newline + 1..]))
}

fn trim_ws(mut bytes: &[u8]) -> &[u8] {
    while let Some(&first) = bytes.first() {
        if first == b' ' || first == b'\t' {
            bytes = &bytes[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = bytes.last() {
        if last == b' ' || last == b'\t' {
            bytes = &bytes[..bytes.len() - 1];
        } else {
            break;
        }
    }
    bytes
}

/// RFC 3261 token character (slightly permissive — real devices are messy).
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'!'
                | b'%'
                | b'*'
                | b'_'
                | b'`'
                | b'\''
                | b'~'
                | b'+'
                | b'#'
                | b'$'
                | b'&'
        )
}
