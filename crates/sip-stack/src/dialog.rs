//! Dialogs (RFC 3261 §12): a call leg's signaling relationship.
//!
//! A dialog knows the identities (tags, Call-ID), where to send in-dialog
//! requests (the remote target from Contact) and the CSeq numbering. Building
//! requests needs the transport's `Via`, so the caller supplies it.

use sip_syntax::{Header, Method, Request};

/// A dialog leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialog {
    /// Call-ID shared by both ends.
    pub call_id: String,
    /// Our tag.
    pub local_tag: String,
    /// Their tag (empty until the early dialog gets one).
    pub remote_tag: String,
    /// Our URI (the From/To side that is ours).
    pub local_uri: String,
    /// Their URI.
    pub remote_uri: String,
    /// Where in-dialog requests go (their Contact).
    pub remote_target: String,
    /// CSeq number for the next request we send.
    pub local_cseq: u64,
}

impl Dialog {
    /// Creates a dialog. The first request we send will use CSeq 1.
    pub fn new(
        call_id: &str,
        local_uri: &str,
        local_tag: &str,
        remote_uri: &str,
        remote_tag: &str,
        remote_target: &str,
    ) -> Self {
        Dialog {
            call_id: call_id.to_string(),
            local_tag: local_tag.to_string(),
            remote_tag: remote_tag.to_string(),
            local_uri: local_uri.to_string(),
            remote_uri: remote_uri.to_string(),
            remote_target: remote_target.to_string(),
            local_cseq: 0,
        }
    }

    /// Builds an in-dialog request (BYE, ...), numbering its CSeq.
    /// `via` is the transport's Via header value, `contact` our address.
    pub fn request(&mut self, method: Method, via: &str, contact: &str) -> Request {
        self.local_cseq += 1;
        let cseq = format!("{} {}", self.local_cseq, method.as_str());
        Request {
            method,
            uri: self.remote_target.clone(),
            headers: vec![
                Header {
                    name: "Via".to_string(),
                    value: via.to_string(),
                },
                Header {
                    name: "Max-Forwards".to_string(),
                    value: "70".to_string(),
                },
                Header {
                    name: "From".to_string(),
                    value: format!("<{}>;tag={}", self.local_uri, self.local_tag),
                },
                Header {
                    name: "To".to_string(),
                    value: format!("<{}>;tag={}", self.remote_uri, self.remote_tag),
                },
                Header {
                    name: "Call-ID".to_string(),
                    value: self.call_id.clone(),
                },
                Header {
                    name: "CSeq".to_string(),
                    value: cseq,
                },
                Header {
                    name: "Contact".to_string(),
                    value: contact.to_string(),
                },
            ],
            body: Vec::new(),
        }
    }

    /// Whether an in-dialog message belongs to this dialog: same Call-ID,
    /// their tag on From, our tag on To.
    pub fn matches(&self, call_id: &str, from_tag: &str, to_tag: &str) -> bool {
        self.call_id == call_id
            && self.remote_tag == from_tag
            && (self.local_tag == to_tag || to_tag.is_empty())
    }
}

/// The URI inside a header value: strips `<`/`>` and any `;params`.
pub fn uri_of(value: &str) -> &str {
    let value = value.trim();
    let value = value
        .strip_prefix('<')
        .map(|rest| rest.split('>').next().unwrap_or(rest))
        .unwrap_or(value);
    value.split(';').next().unwrap_or(value).trim()
}

/// The `tag=` parameter of a `From`/`To` header value, if any.
pub fn tag_of(value: &str) -> Option<&str> {
    for parameter in value.split(';').skip(1) {
        let mut parts = parameter.trim().splitn(2, '=');
        if parts
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("tag")
        {
            return parts.next().map(|tag| tag.trim());
        }
    }
    None
}

/// Appends `;tag=` to a `To` header value that has none (we answer with our
/// side of the dialog).
pub fn with_tag(value: &str, tag: &str) -> String {
    if tag_of(value).is_some() {
        value.to_string()
    } else {
        format!("{value};tag={tag}")
    }
}
