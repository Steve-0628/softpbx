//! M0 acceptance tests (docs/04 §3), as they become possible:
//!
//! 1. registration ✅ (this file)
//! 2. basic call, 4. teardown — with the call FSM (phase 4)
//! 3. audio, 5. concurrency — with RTP (phase 5)
//! 6. robustness — parser tests + fuzzing (phase 1)
//! 7. determinism — `same_seed_produces_identical_trace` (phase 2)
//!
//! Every test runs on the deterministic world: virtual clock, seeded RNG,
//! real SIP messages as bytes.

use call::{Device, Registrar};
use engine_sim::World;
use sip_stack::digest::{expected_response, Credentials};
use sip_syntax::{parse_message, serialize_message, Message, Response};

const REALM: &str = "softpbx";
const PBX_URI: &str = "sip:192.0.2.10";

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

fn register_bytes(number: &str, contact: &str, authorization: Option<&str>) -> Vec<u8> {
    let mut text = format!(
        "REGISTER {PBX_URI} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{number}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:{number}@192.0.2.10>;tag=1\r\n\
         To: <sip:{number}@192.0.2.10>\r\n\
         Call-ID: call-{number}\r\n\
         CSeq: 1 REGISTER\r\n\
         Contact: {contact}\r\n"
    );
    if let Some(authorization) = authorization {
        text.push_str(&format!("Authorization: {authorization}\r\n"));
    }
    text.push_str("Content-Length: 0\r\n\r\n");
    text.into_bytes()
}

fn authorize(number: &str, secret: &str, nonce: &str, method: &str) -> String {
    let request = Credentials {
        username: number.to_string(),
        realm: REALM.to_string(),
        nonce: nonce.to_string(),
        uri: PBX_URI.to_string(),
        response: String::new(),
        qop: None,
        nc: None,
        cnonce: None,
    };
    let response = expected_response(&request, secret, method);
    format!(
        "Digest username=\"{number}\", realm=\"{REALM}\", nonce=\"{nonce}\", \
         uri=\"{PBX_URI}\", response=\"{response}\""
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
    let start = challenge.find("nonce=\"").expect("nonce") + 7;
    let end = challenge[start..].find('"').expect("closing quote") + start;
    challenge[start..end].to_string()
}

/// Feeds one message through the real pipeline: bytes → parse → registrar →
/// bytes. Logs both ends in the world's trace.
fn exchange(world: &mut World, registrar: &mut Registrar, raw: &[u8]) -> Response {
    let message = parse_message(raw).expect("our own messages parse");
    let Message::Request(request) = message else {
        panic!("expected a request");
    };
    world.log(format!(
        "phone -> pbx: {} {}",
        request.method.as_str(),
        request.uri
    ));
    let response = registrar.handle_register(&request, world.now_ms());
    let bytes = serialize_message(&Message::Response(response.clone()));
    let Message::Response(parsing_back) = parse_message(&bytes).expect("our responses parse")
    else {
        panic!("expected a response");
    };
    world.log(format!("pbx -> phone: {}", parsing_back.status));
    let reserialized = serialize_message(&Message::Response(parsing_back.clone()));
    assert_eq!(
        reserialized, bytes,
        "our responses round-trip through the parser"
    );
    parsing_back
}

/// AC-01 (docs/04 §3): two devices register; a wrong password is rejected.
#[test]
fn ac01_registration() {
    let mut world = World::with_seed(0x5EED);
    let mut registrar = registrar();

    // Alice gets challenged, then answers correctly.
    let challenge = exchange(
        &mut world,
        &mut registrar,
        &register_bytes("1001", "<sip:alice@192.0.2.1:5060>", None),
    );
    assert_eq!(challenge.status, 401);
    let nonce = nonce_of(&challenge);
    let ok = exchange(
        &mut world,
        &mut registrar,
        &register_bytes(
            "1001",
            "<sip:alice@192.0.2.1:5060>",
            Some(&authorize("1001", "change-me", &nonce, "REGISTER")),
        ),
    );
    assert_eq!(ok.status, 200);

    // Bob registers the same way.
    let challenge = exchange(
        &mut world,
        &mut registrar,
        &register_bytes("1002", "<sip:bob@192.0.2.2:5060>", None),
    );
    let nonce = nonce_of(&challenge);
    let ok = exchange(
        &mut world,
        &mut registrar,
        &register_bytes(
            "1002",
            "<sip:bob@192.0.2.2:5060>",
            Some(&authorize("1002", "bob-secret", &nonce, "REGISTER")),
        ),
    );
    assert_eq!(ok.status, 200);

    // A wrong password is rejected, and leaves no binding behind.
    let challenge = exchange(
        &mut world,
        &mut registrar,
        &register_bytes("1001", "<sip:mallory@192.0.2.66:5060>", None),
    );
    let nonce = nonce_of(&challenge);
    let rejected = exchange(
        &mut world,
        &mut registrar,
        &register_bytes(
            "1001",
            "<sip:mallory@192.0.2.66:5060>",
            Some(&authorize("1001", "wrong-password", &nonce, "REGISTER")),
        ),
    );
    assert_eq!(rejected.status, 401);

    // Both devices are registered to their own addresses.
    assert_eq!(registrar.registered(world.now_ms()), vec!["1001", "1002"]);
    assert_eq!(
        registrar.lookup("1001", world.now_ms()),
        Some("sip:alice@192.0.2.1:5060")
    );
    assert_eq!(
        registrar.lookup("1002", world.now_ms()),
        Some("sip:bob@192.0.2.2:5060")
    );

    world.log("AC-01 ok");
    assert!(world.trace().iter().any(|line| line.contains("AC-01 ok")));
}

/// AC-01 also covers an unknown number being refused outright.
#[test]
fn ac01_unknown_number_is_refused() {
    let mut world = World::with_seed(0x5EED);
    let mut registrar = registrar();
    let response = exchange(
        &mut world,
        &mut registrar,
        &register_bytes("9999", "<sip:x@192.0.2.9>", None),
    );
    assert_eq!(response.status, 403);
    assert!(registrar.registered(world.now_ms()).is_empty());
}

/// The registrar is pure time-in logic, so the whole exchange is reproducible:
/// same seed, same trace, byte for byte.
#[test]
fn ac01_registration_is_deterministic() {
    fn run() -> Vec<String> {
        let mut world = World::with_seed(0x5EED);
        let mut registrar = registrar();
        let challenge = exchange(
            &mut world,
            &mut registrar,
            &register_bytes("1001", "<sip:alice@192.0.2.1:5060>", None),
        );
        let nonce = nonce_of(&challenge);
        let _ = exchange(
            &mut world,
            &mut registrar,
            &register_bytes(
                "1001",
                "<sip:alice@192.0.2.1:5060>",
                Some(&authorize("1001", "change-me", &nonce, "REGISTER")),
            ),
        );
        world.trace().to_vec()
    }
    assert_eq!(run(), run());
}
