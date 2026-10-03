//! Registrar behavior: registration, challenge/response, expiry.

use call::{Device, Registrar, DEFAULT_EXPIRES_S, MAX_EXPIRES_S, MIN_EXPIRES_S};
use sip_stack::digest::{expected_response, Credentials};
use sip_syntax::{Header, Method, Request, Response};

const REALM: &str = "softpbx";
const PBX: &str = "sip:192.0.2.10";

fn registrar() -> Registrar {
    Registrar::new(
        REALM,
        vec![
            Device {
                number: "1001".to_string(),
                name: "Alice".to_string(),
                secret: "change-me".to_string(),
            },
            Device {
                number: "1002".to_string(),
                name: "Bob".to_string(),
                secret: "bob-secret".to_string(),
            },
        ],
    )
}

fn register(
    number: &str,
    contact: &str,
    expires: Option<&str>,
    authorization: Option<String>,
) -> Request {
    let mut headers = vec![
        Header {
            name: "Via".to_string(),
            value: format!("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{number}"),
        },
        Header {
            name: "From".to_string(),
            value: format!("<sip:{number}@192.0.2.10>;tag=1"),
        },
        Header {
            name: "To".to_string(),
            value: format!("<sip:{number}@192.0.2.10>"),
        },
        Header {
            name: "Call-ID".to_string(),
            value: format!("call-{number}"),
        },
        Header {
            name: "CSeq".to_string(),
            value: "1 REGISTER".to_string(),
        },
        Header {
            name: "Contact".to_string(),
            value: contact.to_string(),
        },
    ];
    if let Some(expires) = expires {
        headers.push(Header {
            name: "Expires".to_string(),
            value: expires.to_string(),
        });
    }
    if let Some(authorization) = authorization {
        headers.push(Header {
            name: "Authorization".to_string(),
            value: authorization,
        });
    }
    Request {
        method: Method::Register,
        uri: PBX.to_string(),
        headers,
        body: Vec::new(),
    }
}

/// Builds credentials the way a phone would: answer the challenge.
fn authorize(number: &str, secret: &str, nonce: &str, method: &str) -> String {
    let request = Credentials {
        username: number.to_string(),
        realm: REALM.to_string(),
        nonce: nonce.to_string(),
        uri: PBX.to_string(),
        response: String::new(),
        qop: None,
        nc: None,
        cnonce: None,
    };
    let response = expected_response(&request, secret, method);
    format!(
        "Digest username=\"{number}\", realm=\"{REALM}\", nonce=\"{nonce}\", \
         uri=\"{PBX}\", response=\"{response}\""
    )
}

fn nonce_of(response: &Response) -> String {
    let challenge = response
        .headers
        .iter()
        .find(|header| header.name == "WWW-Authenticate")
        .expect("challenge present")
        .value
        .clone();
    let start = challenge.find("nonce=\"").expect("nonce in challenge") + "nonce=\"".len();
    let end = challenge[start..].find('"').expect("closing quote") + start;
    challenge[start..end].to_string()
}

/// A phone registers the honest way: get challenged, answer, done.
fn register_ok(registrar: &mut Registrar, number: &str, secret: &str, contact: &str) -> Response {
    let challenge = registrar.handle_register(&register(number, contact, None, None), 0);
    assert_eq!(challenge.status, 401, "first attempt is challenged");
    let nonce = nonce_of(&challenge);
    registrar.handle_register(
        &register(
            number,
            contact,
            None,
            Some(authorize(number, secret, &nonce, "REGISTER")),
        ),
        0,
    )
}

#[test]
fn correct_password_registers() {
    let mut registrar = registrar();
    let response = register_ok(
        &mut registrar,
        "1001",
        "change-me",
        "<sip:alice@192.0.2.1:5060>",
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        registrar.lookup("1001", 0),
        Some("sip:alice@192.0.2.1:5060")
    );
    assert_eq!(registrar.registered(0), vec!["1001".to_string()]);

    // Contact and granted lifetime are echoed back.
    let contact = response
        .headers
        .iter()
        .find(|h| h.name == "Contact")
        .unwrap();
    assert_eq!(contact.value, "<sip:alice@192.0.2.1:5060>");
    let expires = response
        .headers
        .iter()
        .find(|h| h.name == "Expires")
        .unwrap();
    assert_eq!(expires.value, DEFAULT_EXPIRES_S.to_string());
}

#[test]
fn wrong_password_is_rejected() {
    let mut registrar = registrar();
    let challenge = registrar.handle_register(
        &register("1001", "<sip:alice@192.0.2.1:5060>", None, None),
        0,
    );
    let nonce = nonce_of(&challenge);
    let response = registrar.handle_register(
        &register(
            "1001",
            "<sip:alice@192.0.2.1:5060>",
            None,
            Some(authorize("1001", "wrong-password", &nonce, "REGISTER")),
        ),
        0,
    );
    assert_eq!(response.status, 401);
    assert!(registrar.lookup("1001", 0).is_none());
}

#[test]
fn missing_authorization_is_challenged() {
    let mut registrar = registrar();
    let response = registrar.handle_register(
        &register("1001", "<sip:alice@192.0.2.1:5060>", None, None),
        0,
    );
    assert_eq!(response.status, 401);
    assert!(response
        .headers
        .iter()
        .any(|header| header.name == "WWW-Authenticate"));
}

#[test]
fn unknown_number_is_forbidden() {
    let mut registrar = registrar();
    let response = registrar.handle_register(&register("9999", "<sip:x@192.0.2.1>", None, None), 0);
    assert_eq!(response.status, 403);
}

#[test]
fn expires_zero_unregisters() {
    let mut registrar = registrar();
    let _ = register_ok(
        &mut registrar,
        "1001",
        "change-me",
        "<sip:alice@192.0.2.1:5060>",
    );
    assert!(registrar.lookup("1001", 0).is_some());

    let challenge = registrar.handle_register(
        &register("1001", "<sip:alice@192.0.2.1:5060>", Some("0"), None),
        10,
    );
    let nonce = nonce_of(&challenge);
    let response = registrar.handle_register(
        &register(
            "1001",
            "<sip:alice@192.0.2.1:5060>",
            Some("0"),
            Some(authorize("1001", "change-me", &nonce, "REGISTER")),
        ),
        10,
    );
    assert_eq!(response.status, 200);
    assert!(registrar.lookup("1001", 10).is_none());
}

#[test]
fn wildcard_contact_unregisters() {
    let mut registrar = registrar();
    let _ = register_ok(
        &mut registrar,
        "1002",
        "bob-secret",
        "<sip:bob@192.0.2.2:5060>",
    );
    let challenge = registrar.handle_register(&register("1002", "*", Some("0"), None), 0);
    let nonce = nonce_of(&challenge);
    let response = registrar.handle_register(
        &register(
            "1002",
            "*",
            Some("0"),
            Some(authorize("1002", "bob-secret", &nonce, "REGISTER")),
        ),
        0,
    );
    assert_eq!(response.status, 200);
    assert!(registrar.lookup("1002", 0).is_none());
}

#[test]
fn bindings_expire() {
    let mut registrar = registrar();
    let challenge = registrar.handle_register(
        &register("1001", "<sip:alice@192.0.2.1:5060>", Some("120"), None),
        1_000,
    );
    let nonce = nonce_of(&challenge);
    let response = registrar.handle_register(
        &register(
            "1001",
            "<sip:alice@192.0.2.1:5060>",
            Some("120"),
            Some(authorize("1001", "change-me", &nonce, "REGISTER")),
        ),
        1_000,
    );
    assert_eq!(response.status, 200);
    let expires = response
        .headers
        .iter()
        .find(|h| h.name == "Expires")
        .unwrap();
    assert_eq!(expires.value, "120");

    assert!(registrar.lookup("1001", 1_000 + 119_000).is_some());
    assert!(registrar.lookup("1001", 1_000 + 121_000).is_none());

    registrar.expire(1_000 + 121_000);
    assert!(registrar.binding("1001").is_none());
}

#[test]
fn granted_expires_is_clamped() {
    let mut registrar = registrar();
    for (asked, granted) in [("5", MIN_EXPIRES_S), ("999999", MAX_EXPIRES_S)] {
        let challenge = registrar.handle_register(
            &register("1001", "<sip:alice@192.0.2.1:5060>", Some(asked), None),
            0,
        );
        let nonce = nonce_of(&challenge);
        let response = registrar.handle_register(
            &register(
                "1001",
                "<sip:alice@192.0.2.1:5060>",
                Some(asked),
                Some(authorize("1001", "change-me", &nonce, "REGISTER")),
            ),
            0,
        );
        let expires = response
            .headers
            .iter()
            .find(|h| h.name == "Expires")
            .unwrap();
        assert_eq!(expires.value, granted.to_string(), "asked {asked}");
    }
}

#[test]
fn contact_expires_parameter_is_honored() {
    let mut registrar = registrar();
    let contact = "<sip:alice@192.0.2.1:5060>;expires=300";
    let challenge = registrar.handle_register(&register("1001", contact, None, None), 0);
    let nonce = nonce_of(&challenge);
    let response = registrar.handle_register(
        &register(
            "1001",
            contact,
            None,
            Some(authorize("1001", "change-me", &nonce, "REGISTER")),
        ),
        0,
    );
    let expires = response
        .headers
        .iter()
        .find(|h| h.name == "Expires")
        .unwrap();
    assert_eq!(expires.value, "300");
}

#[test]
fn number_is_taken_from_to_header() {
    let request = register("1001", "<sip:alice@192.0.2.1:5060>", None, None);
    assert_eq!(
        call::number_from_request(&request),
        Some("1001".to_string())
    );

    // Messy but real: the To header has no user part, the Request-URI does.
    let mut request = register("1001", "<sip:alice@192.0.2.1:5060>", None, None);
    request.uri = "sip:1001@192.0.2.10;transport=udp".to_string();
    request.headers[2].value = "<sip:192.0.2.10>".to_string(); // To without user
    assert_eq!(
        call::number_from_request(&request),
        Some("1001".to_string())
    );

    // No user part anywhere: no number.
    let mut request = register("1001", "<sip:alice@192.0.2.1:5060>", None, None);
    request.uri = "sip:192.0.2.10".to_string();
    request.headers[2].value = "<sip:192.0.2.10>".to_string();
    assert_eq!(call::number_from_request(&request), None);
}
