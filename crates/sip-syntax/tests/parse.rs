//! Parsing and serialization tests: well-formed input, messy input, and
//! resource limits. The contract under test (docs/07): malformed input produces
//! a `ParseError` — never a panic.

use sip_syntax::{
    canonical_header, parse_message, parse_message_with_limits, parse_sdp, serialize_message,
    Limits, Message, Method, ParseError,
};

fn invite_body() -> Vec<u8> {
    b"v=0\r\n\
      o=alice 2890844526 2890844526 IN IP4 192.0.2.1\r\n\
      s=-\r\n\
      c=IN IP4 192.0.2.1\r\n\
      t=0 0\r\n\
      m=audio 5004 RTP/AVP 0 8 101\r\n\
      a=rtpmap:0 PCMU/8000\r\n\
      a=rtpmap:101 telephone-event/8000\r\n"
        .to_vec()
}

fn invite() -> Vec<u8> {
    let mut msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
        v: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n\
        Max-Forwards: 70\r\n\
        f: <sip:alice@example.com>;tag=88sja8x\r\n\
        t: <sip:bob@example.com>\r\n\
        i: 843817637684230@192.0.2.1\r\n\
        CSeq: 1 INVITE\r\n\
        m: <sip:alice@192.0.2.1:5060>\r\n\
        c: application/sdp\r\n"
        .to_vec();
    let body = invite_body();
    msg.extend_from_slice(format!("l: {}\r\n\r\n", body.len()).as_bytes());
    msg.extend_from_slice(&body);
    msg
}

#[test]
fn request_with_sdp_body_parses() {
    let message = parse_message(&invite()).expect("well-formed INVITE");
    let Message::Request(request) = &message else {
        panic!("expected a request");
    };
    assert_eq!(request.method, Method::Invite);
    assert_eq!(request.uri, "sip:bob@example.com");
    assert_eq!(request.headers.len(), 9);
    assert_eq!(request.body, invite_body());
}

#[test]
fn response_parses() {
    let raw = b"SIP/2.0 200 OK\r\n\
        Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n\
        CSeq: 1 REGISTER\r\n\
        Content-Length: 0\r\n\r\n";
    let message = parse_message(raw).expect("well-formed response");
    let Message::Response(response) = &message else {
        panic!("expected a response");
    };
    assert_eq!(response.status, 200);
    assert_eq!(response.reason, "OK");
    assert!(response.body.is_empty());
}

#[test]
fn empty_reason_phrase_is_allowed() {
    let message = parse_message(b"SIP/2.0 200\r\nContent-Length: 0\r\n\r\n").unwrap();
    let Message::Response(response) = &message else {
        panic!("expected a response");
    };
    assert_eq!(response.reason, "");
}

#[test]
fn compact_header_names_are_resolved() {
    let message = parse_message(&invite()).unwrap();
    assert_eq!(message.header("call-id"), Some("843817637684230@192.0.2.1"));
    assert_eq!(message.header("Call-ID"), Some("843817637684230@192.0.2.1"));
    assert_eq!(message.header("i"), Some("843817637684230@192.0.2.1"));
    assert_eq!(
        message.header("contact"),
        Some("<sip:alice@192.0.2.1:5060>")
    );
    assert_eq!(canonical_header("v"), "via");
    assert_eq!(canonical_header("Via"), "via");
}

#[test]
fn header_order_and_duplicates_are_preserved() {
    let raw = b"OPTIONS sip:x SIP/2.0\r\n\
        Via: SIP/2.0/UDP one\r\n\
        Via: SIP/2.0/UDP two\r\n\
        Content-Length: 0\r\n\r\n";
    let message = parse_message(raw).unwrap();
    let names: Vec<&str> = message.headers().iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, ["Via", "Via", "Content-Length"]);
    assert_eq!(
        message.headers_all("via"),
        ["SIP/2.0/UDP one", "SIP/2.0/UDP two"]
    );
}

#[test]
fn folded_header_line_is_joined() {
    let raw = b"OPTIONS sip:x SIP/2.0\r\n\
        Subject: first part\r\n\
        \tsecond part\r\n\
        Content-Length: 0\r\n\r\n";
    let message = parse_message(raw).unwrap();
    assert_eq!(message.header("subject"), Some("first part second part"));
}

#[test]
fn bare_lf_line_endings_are_tolerated() {
    let raw = b"OPTIONS sip:x SIP/2.0\nVia: SIP/2.0/UDP one\nContent-Length: 0\n\n";
    let message = parse_message(raw).expect("real devices send bare LF");
    assert_eq!(message.header("via"), Some("SIP/2.0/UDP one"));
}

#[test]
fn missing_colon_is_bad_header() {
    let raw = b"OPTIONS sip:x SIP/2.0\r\nBroken header\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(parse_message(raw), Err(ParseError::BadHeader));
}

#[test]
fn bad_header_names_are_rejected() {
    for raw in [
        &b"OPTIONS sip:x SIP/2.0\r\n: empty name\r\n\r\n"[..],
        &b"OPTIONS sip:x SIP/2.0\r\nBad Name: space\r\n\r\n"[..],
        &b"OPTIONS sip:x SIP/2.0\r\nX: a\x07b\r\n\r\n"[..],
        &b"OPTIONS sip:x SIP/2.0\r\nX: a\rb\r\n\r\n"[..],
    ] {
        assert_eq!(parse_message(raw), Err(ParseError::BadHeader), "{raw:?}");
    }
}

#[test]
fn folded_line_without_previous_header_is_bad_header() {
    let raw = b"OPTIONS sip:x SIP/2.0\r\n orphan\r\n\r\n";
    assert_eq!(parse_message(raw), Err(ParseError::BadHeader));
}

#[test]
fn bad_start_lines_are_rejected() {
    for raw in [
        &b"\r\nContent-Length: 0\r\n\r\n"[..],      // empty start line
        &b"HELLO\r\n\r\n"[..],                      // one field
        &b"INVITE sip:x SIP/1.0\r\n\r\n"[..],       // wrong version
        &b"INVITE sip:x SIP/2.0 extra\r\n\r\n"[..], // trailing field
        &b"INVITE  SIP/2.0\r\n\r\n"[..],            // empty URI (two spaces)
        &b"IN VITE sip:x SIP/2.0\r\n\r\n"[..],      // space in method
        &b"SIP/1.0 200 OK\r\n\r\n"[..],             // wrong version
        &b"SIP/2.0 20 x\r\n\r\n"[..],               // two-digit status
        &b"SIP/2.0 20x OK\r\n\r\n"[..],             // non-numeric status
        &b"SIP/2.0 99 OK\r\n\r\n"[..],              // out of range
        &b"SIP/2.0 700 OK\r\n\r\n"[..],             // out of range
    ] {
        assert_eq!(parse_message(raw), Err(ParseError::BadStartLine), "{raw:?}");
    }
}

#[test]
fn truncated_input_is_incomplete() {
    let whole = invite();
    for cut in [0, 10, 60, whole.len() - 1] {
        let message = parse_message(&whole[..cut]);
        if cut == 0 {
            assert_eq!(message, Err(ParseError::Incomplete));
        } else {
            assert_eq!(message, Err(ParseError::Incomplete), "cut at {cut}");
        }
    }
    // Complete message parses.
    assert!(parse_message(&whole).is_ok());
}

#[test]
fn body_shorter_than_content_length_is_incomplete() {
    let raw = b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 10\r\n\r\nshort";
    assert_eq!(parse_message(raw), Err(ParseError::Incomplete));
}

#[test]
fn trailing_bytes_after_body_are_ignored() {
    let raw = b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\ngarbage";
    let message = parse_message(raw).unwrap();
    assert!(message.body().is_empty());
}

#[test]
fn bad_content_length_is_bad_body_length() {
    for raw in [
        &b"OPTIONS sip:x SIP/2.0\r\nContent-Length: x\r\n\r\n"[..],
        &b"OPTIONS sip:x SIP/2.0\r\nl: -1\r\n\r\n"[..],
        &b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"[..],
    ] {
        assert_eq!(
            parse_message(raw),
            Err(ParseError::BadBodyLength),
            "{raw:?}"
        );
    }
}

#[test]
fn identical_duplicate_content_length_is_accepted() {
    let raw = b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 0\r\nl: 0\r\n\r\n";
    assert!(parse_message(raw).is_ok());
}

#[test]
fn limits_are_enforced() {
    // Too many header fields.
    let mut raw = b"OPTIONS sip:x SIP/2.0\r\n".to_vec();
    for n in 0..200 {
        raw.extend_from_slice(format!("X-{n}: v\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    assert_eq!(parse_message(&raw), Err(ParseError::LimitExceeded));

    // Header line too long.
    let mut raw = b"OPTIONS sip:x SIP/2.0\r\nX: ".to_vec();
    raw.extend(std::iter::repeat_n(b'a', 9_000));
    raw.extend_from_slice(b"\r\n\r\n");
    assert_eq!(parse_message(&raw), Err(ParseError::LimitExceeded));

    // Message too long overall.
    let mut raw = b"OPTIONS sip:x SIP/2.0\r\n".to_vec();
    raw.extend(std::iter::repeat_n(b'a', 70_000));
    assert_eq!(parse_message(&raw), Err(ParseError::LimitExceeded));

    // Body larger than the limit (Content-Length says so).
    let raw = b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 20000\r\n\r\n";
    assert_eq!(parse_message(raw), Err(ParseError::LimitExceeded));

    // Tight limits can be set explicitly.
    let limits = Limits {
        max_headers: 2,
        ..Limits::default()
    };
    let raw = b"OPTIONS sip:x SIP/2.0\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n";
    assert_eq!(
        parse_message_with_limits(raw, &limits),
        Err(ParseError::LimitExceeded)
    );
}

#[test]
fn empty_input_is_incomplete() {
    assert_eq!(parse_message(b""), Err(ParseError::Incomplete));
}

#[test]
fn unknown_methods_are_kept_verbatim() {
    let raw = b"PING sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n";
    let Message::Request(request) = parse_message(raw).unwrap() else {
        panic!("expected a request");
    };
    assert_eq!(request.method, Method::Other("PING".to_string()));
    assert_eq!(request.method.as_str(), "PING");
}

#[test]
fn serialization_round_trips() {
    let message = parse_message(&invite()).unwrap();
    let bytes = serialize_message(&message);
    let reparsed = parse_message(&bytes).expect("our own output must parse");
    // Serialization normalizes Content-Length, so compare the stable forms.
    assert_eq!(serialize_message(&reparsed), bytes);
    assert_eq!(reparsed.body(), message.body());
    assert_eq!(reparsed.header("call-id"), message.header("call-id"));
    assert_eq!(reparsed.header("from"), message.header("from"));
}

#[test]
fn serialization_recomputes_content_length() {
    let message = parse_message(&invite()).unwrap();
    let bytes = serialize_message(&message);
    let expected = format!("Content-Length: {}\r\n", invite_body().len());
    assert!(String::from_utf8_lossy(&bytes).contains(&expected));
    // Exactly one Content-Length field.
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text.matches("Content-Length:").count(), 1);
}

#[test]
fn sdp_media_lines_parse() {
    let sdp = parse_sdp(
        b"v=0\r\n\
          o=alice 1 1 IN IP4 192.0.2.1\r\n\
          s=-\r\n\
          m=audio 5004 RTP/AVP 0 8 101\r\n\
          a=rtpmap:0 PCMU/8000\r\n\
          m=image 6004 udptl t38\r\n",
    )
    .unwrap();
    assert_eq!(sdp.media.len(), 2);
    assert_eq!(sdp.media[0].media, "audio");
    assert_eq!(sdp.media[0].port, 5004);
    assert_eq!(sdp.media[0].transport, "RTP/AVP");
    assert_eq!(sdp.media[0].payload_types, [0, 8, 101]);
    assert_eq!(sdp.media[1].media, "image");
    assert_eq!(sdp.media[1].transport, "udptl");
    assert!(sdp.media[1].payload_types.is_empty()); // "t38" is not a number
}

#[test]
fn sdp_port_with_port_count_parses() {
    let sdp = parse_sdp(b"m=audio 5004/2 RTP/AVP 0").unwrap();
    assert_eq!(sdp.media[0].port, 5004);
}

#[test]
fn sdp_without_trailing_newline_parses() {
    let sdp = parse_sdp(b"m=audio 5004 RTP/AVP 0").unwrap();
    assert_eq!(sdp.media.len(), 1);
}

#[test]
fn sdp_ignores_non_media_lines() {
    let sdp = parse_sdp(b"v=0\r\nweird line without equals\r\ns=-\r\n").unwrap();
    assert!(sdp.media.is_empty());
}

#[test]
fn sdp_skips_non_numeric_format_tokens() {
    // Real-world case: T.38 writes "t38" in the format list.
    let sdp = parse_sdp(b"m=image 6004 udptl t38\r\n").unwrap();
    assert!(sdp.media[0].payload_types.is_empty());
    let sdp = parse_sdp(b"m=audio 5004 RTP/AVP 0 x 8\r\n").unwrap();
    assert_eq!(sdp.media[0].payload_types, [0, 8]);
}

#[test]
fn malformed_sdp_media_lines_are_rejected() {
    for raw in [
        &b"m=audio\r\n"[..],
        &b"m=audio 5004\r\n"[..],
        &b"m=audio notaport RTP/AVP\r\n"[..],
        &b"m=audio 70000 RTP/AVP\r\n"[..],
    ] {
        assert_eq!(parse_sdp(raw), Err(ParseError::BadHeader), "{raw:?}");
    }
}
