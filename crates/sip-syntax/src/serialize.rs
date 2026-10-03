//! Message serialization. Deterministic: the same message always produces the
//! same bytes, with `Content-Length` recomputed from the body.

use crate::{canonical_header, Message};

/// Serializes a message to wire form (CRLF line endings).
///
/// `Content-Length` is always written last, before the body, and reflects the
/// actual body length; any `Content-Length` in the message is dropped and
/// replaced. Header order is otherwise preserved. The caller is trusted to
/// supply values without line breaks (parsing never produces any).
pub fn serialize_message(message: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    match message {
        Message::Request(request) => {
            out.extend_from_slice(request.method.as_str().as_bytes());
            out.push(b' ');
            out.extend_from_slice(request.uri.as_bytes());
            out.extend_from_slice(b" SIP/2.0\r\n");
        }
        Message::Response(response) => {
            out.extend_from_slice(b"SIP/2.0 ");
            out.extend_from_slice(response.status.to_string().as_bytes());
            out.push(b' ');
            out.extend_from_slice(response.reason.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    for header in message.headers() {
        if canonical_header(&header.name) == "content-length" {
            continue; // recomputed below
        }
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    let body = message.body();
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}
