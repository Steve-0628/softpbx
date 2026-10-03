//! Digest authentication: parsing and verification against known vectors.

use sip_stack::digest::{expected_response, parse_authorization, verify, Challenge, Credentials};

fn base(username: &str, realm: &str, nonce: &str, uri: &str) -> Credentials {
    Credentials {
        username: username.to_string(),
        realm: realm.to_string(),
        nonce: nonce.to_string(),
        uri: uri.to_string(),
        response: String::new(),
        qop: None,
        nc: None,
        cnonce: None,
    }
}

#[test]
fn rfc2617_example_vector() {
    // RFC 2617 §3.5, cross-checked with an independent MD5 implementation.
    let request = Credentials {
        qop: Some("auth".to_string()),
        nc: Some("00000001".to_string()),
        cnonce: Some("0a4f113b".to_string()),
        ..base(
            "Mufasa",
            "testrealm@host.com",
            "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            "/dir/index.html",
        )
    };
    let expected = expected_response(&request, "Circle Of Life", "GET");
    assert_eq!(expected, "6629fae49393a05397450978507c4ef1");
}

#[test]
fn sip_register_vectors() {
    // Cross-checked with an independent MD5 implementation.
    let no_qop = base("1001", "softpbx", "abc123", "sip:192.0.2.10");
    assert_eq!(
        expected_response(&no_qop, "change-me", "REGISTER"),
        "872f2ad2a566f783021a46229ad82d37"
    );

    let with_qop = Credentials {
        qop: Some("auth".to_string()),
        nc: Some("00000001".to_string()),
        cnonce: Some("xyz".to_string()),
        ..base("1001", "softpbx", "abc123", "sip:192.0.2.10")
    };
    assert_eq!(
        expected_response(&with_qop, "change-me", "REGISTER"),
        "18b0f8197278d1fdf2b4c52df0004d9d"
    );
}

#[test]
fn parses_quoted_and_unquoted_fields() {
    let parsed = parse_authorization(
        "Digest username=\"1001\", realm=\"softpbx\", nonce=\"abc123\", \
         uri=\"sip:192.0.2.10\", response=\"deadbeef\", algorithm=MD5",
    )
    .expect("must parse");
    assert_eq!(parsed.username, "1001");
    assert_eq!(parsed.uri, "sip:192.0.2.10");
    assert_eq!(parsed.response, "deadbeef");
    assert_eq!(parsed.qop, None);

    // Unquoted values, qop fields, odd spacing, lowercase scheme.
    let parsed = parse_authorization(
        "digest username=1001, realm=softpbx, nonce=abc123, uri=sip:192.0.2.10, \
         response=deadbeef, qop=auth, nc=00000001, cnonce=xyz",
    )
    .expect("must parse");
    assert_eq!(parsed.qop.as_deref(), Some("auth"));
    assert_eq!(parsed.nc.as_deref(), Some("00000001"));
    assert_eq!(parsed.cnonce.as_deref(), Some("xyz"));
}

#[test]
fn rejects_non_digest_or_incomplete_credentials() {
    assert_eq!(parse_authorization("Basic dXNlcjpwYXNz"), None);
    assert_eq!(parse_authorization("Digest"), None);
    assert_eq!(parse_authorization("Digest username=1001"), None); // missing fields
    assert_eq!(parse_authorization("Digest username=\"1001"), None); // unterminated quote
    assert_eq!(parse_authorization(""), None);
}

#[test]
fn verifies_correct_password_and_rejects_wrong_ones() {
    let request = base("1001", "softpbx", "abc123", "sip:192.0.2.10");
    let response = expected_response(&request, "change-me", "REGISTER");
    let request = Credentials {
        response,
        ..base("1001", "softpbx", "abc123", "sip:192.0.2.10")
    };
    assert!(verify(&request, "change-me", "REGISTER"));

    // Wrong password, wrong method, tampered response: all rejected.
    assert!(!verify(&request, "wrong", "REGISTER"));
    assert!(!verify(&request, "change-me", "INVITE"));
    let mut tampered = request.clone();
    tampered.response.replace_range(0..1, "0");
    assert!(!verify(&tampered, "change-me", "REGISTER"));
}

#[test]
fn challenge_header_value() {
    let challenge = Challenge {
        realm: "softpbx".to_string(),
        nonce: "abc123".to_string(),
    };
    assert_eq!(
        challenge.header_value(),
        "Digest realm=\"softpbx\", nonce=\"abc123\", algorithm=MD5"
    );
}
