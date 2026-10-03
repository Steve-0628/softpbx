//! M0 acceptance tests (docs/04 §3), as they become possible:
//!
//! 1. registration ✅ (AC-01)
//! 2. basic call ✅ / 4. teardown ✅ (AC-02, AC-04 — signaling; audio follows
//!    in phase 5)
//! 3. audio, 5. concurrency — with RTP (phase 5)
//! 6. robustness — parser tests + fuzzing (phase 1)
//! 7. determinism — plus `same_seed_produces_identical_trace` (phase 2)
//!
//! Everything runs on the deterministic world and speaks real SIP: messages
//! cross the boundary as bytes.

use call::{CallState, Device, Output, Switch, SwitchConfig};
use engine_sim::{Event, World};
use sip_stack::digest::{expected_response, Credentials};
use sip_stack::{make_response, tag_of, with_tag};
use sip_syntax::{parse_message, serialize_message, Message, Method, Request, Response};

const REALM: &str = "softpbx";
const PBX_URI: &str = "sip:192.0.2.10";
const PBX_HOST: &str = "192.0.2.10:5060";
const PBX_CONTACT: &str = "<sip:192.0.2.10:5060>";

fn switch() -> Switch {
    Switch::new(SwitchConfig {
        realm: REALM.to_string(),
        pbx_uri: PBX_URI.to_string(),
        pbx_host: PBX_HOST.to_string(),
        pbx_contact: PBX_CONTACT.to_string(),
        devices: vec![
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
    })
}

/// Bytes in → parse → switch → outputs, with both ends traced.
fn feed(world: &mut World, switch: &mut Switch, raw: &[u8]) -> Vec<Output> {
    let message = parse_message(raw).expect("our own messages parse");
    match &message {
        Message::Request(request) => world.log(format!(
            "phone -> pbx: {} {}",
            request.method.as_str(),
            request.uri
        )),
        Message::Response(response) => {
            world.log(format!("phone -> pbx: {}", response.status));
        }
    }
    let outputs = switch.handle(message, world.now_ms());
    for output in &outputs {
        match output {
            Output::Send(Message::Request(request)) => world.log(format!(
                "pbx -> phone: {} {}",
                request.method.as_str(),
                request.uri
            )),
            Output::Send(Message::Response(response)) => {
                world.log(format!("pbx -> phone: {}", response.status))
            }
            Output::CallLog(line) => world.log(format!("call log: {line}")),
        }
    }
    outputs
}

fn response_of(outputs: &[Output], status: u16) -> Response {
    outputs
        .iter()
        .find_map(|output| match output {
            Output::Send(Message::Response(response)) if response.status == status => {
                Some(response.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {status} response in {outputs:?}"))
}

fn request_of(outputs: &[Output], method: Method) -> Request {
    outputs
        .iter()
        .find_map(|output| match output {
            Output::Send(Message::Request(request)) if request.method == method => {
                Some(request.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {method:?} request in {outputs:?}"))
}

fn call_logs(outputs: &[Output]) -> Vec<String> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::CallLog(line) => Some(line.clone()),
            _ => None,
        })
        .collect()
}

fn header_value<'a>(headers: &'a [sip_syntax::Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

// ----- messages the fake phones send ---------------------------------------

fn register_bytes(number: &str, contact: &str, authorization: Option<&str>) -> Vec<u8> {
    let mut text = format!(
        "REGISTER {PBX_URI} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-reg-{number}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:{number}@192.0.2.10>;tag=1\r\n\
         To: <sip:{number}@192.0.2.10>\r\n\
         Call-ID: reg-{number}\r\n\
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
    let credentials = Credentials {
        username: number.to_string(),
        realm: REALM.to_string(),
        nonce: nonce.to_string(),
        uri: PBX_URI.to_string(),
        response: String::new(),
        qop: None,
        nc: None,
        cnonce: None,
    };
    let response = expected_response(&credentials, secret, method);
    format!(
        "Digest username=\"{number}\", realm=\"{REALM}\", nonce=\"{nonce}\", \
         uri=\"{PBX_URI}\", response=\"{response}\""
    )
}

fn nonce_of(response: &Response) -> String {
    let challenge = header_value(&response.headers, "WWW-Authenticate").expect("challenge");
    let start = challenge.find("nonce=\"").expect("nonce") + 7;
    let end = challenge[start..].find('"').expect("closing quote") + start;
    challenge[start..end].to_string()
}

fn invite_bytes(from: &str, to: &str, call_id: &str) -> Vec<u8> {
    format!(
        "INVITE sip:{to}@192.0.2.10 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:{from}@192.0.2.10>;tag=from1\r\n\
         To: <sip:{to}@192.0.2.10>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:{from}@192.0.2.1:5060>\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

fn bye_bytes(from: &str, to_uri: &str, to_tag: &str, call_id: &str, cseq: u32) -> Vec<u8> {
    format!(
        "BYE {to_uri} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-bye-{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:{from}@192.0.2.10>;tag=from1\r\n\
         To: <{to_uri}>;tag={to_tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} BYE\r\n\
         Contact: <sip:{from}@192.0.2.1:5060>\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

/// A phone's response to a request the PBX sent it.
fn response_bytes(request: &Request, status: u16, reason: &str, to_tag: &str) -> Vec<u8> {
    let mut response = make_response(request, status, reason);
    for header in &mut response.headers {
        if header.name == "To" {
            header.value = with_tag(&header.value, to_tag);
        }
    }
    serialize_message(&Message::Response(response))
}

/// Registers a device the honest way: challenge, then answer.
fn register_device(
    world: &mut World,
    switch: &mut Switch,
    number: &str,
    secret: &str,
    contact: &str,
) {
    let outputs = feed(world, switch, &register_bytes(number, contact, None));
    let challenge = response_of(&outputs, 401);
    let nonce = nonce_of(&challenge);
    let outputs = feed(
        world,
        switch,
        &register_bytes(
            number,
            contact,
            Some(&authorize(number, secret, &nonce, "REGISTER")),
        ),
    );
    assert_eq!(response_of(&outputs, 200).status, 200, "{number} registers");
}

/// Runs a full call setup: Alice calls Bob, Bob rings, Bob answers, ACK.
/// Returns the caller's call-id and the To-tag we gave the caller.
fn establish_call(world: &mut World, switch: &mut Switch) -> (String, String) {
    let outputs = feed(world, switch, &invite_bytes("1001", "1002", "ac02-call"));
    let callee_invite = request_of(&outputs, Method::Invite);
    assert!(
        response_of(&outputs, 100).status >= 100,
        "caller gets a response"
    );

    let outputs = feed(
        world,
        switch,
        &response_bytes(&callee_invite, 180, "Ringing", "bob1"),
    );
    assert_eq!(
        response_of(&outputs, 180).status,
        180,
        "the caller hears ringing"
    );

    let outputs = feed(
        world,
        switch,
        &response_bytes(&callee_invite, 200, "OK", "bob1"),
    );
    assert_eq!(
        request_of(&outputs, Method::Ack).method,
        Method::Ack,
        "we ACK the callee's 200"
    );
    let answered = response_of(&outputs, 200);
    let to_tag = tag_of(header_value(&answered.headers, "to").unwrap())
        .expect("our To tag")
        .to_string();

    let outputs = feed(world, switch, &ack_for("ac02-call", &to_tag));
    assert!(outputs.is_empty(), "the ACK needs no answer");
    ("ac02-call".to_string(), to_tag)
}

// ----- AC-01: registration --------------------------------------------------

#[test]
fn ac01_registration() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();

    register_device(
        &mut world,
        &mut switch,
        "1001",
        "change-me",
        "<sip:alice@192.0.2.1:5060>",
    );
    register_device(
        &mut world,
        &mut switch,
        "1002",
        "bob-secret",
        "<sip:bob@192.0.2.2:5060>",
    );

    // A wrong password is rejected and binds nothing.
    let outputs = feed(
        &mut world,
        &mut switch,
        &register_bytes("1001", "<sip:mallory@192.0.2.66:5060>", None),
    );
    let nonce = nonce_of(&response_of(&outputs, 401));
    let outputs = feed(
        &mut world,
        &mut switch,
        &register_bytes(
            "1001",
            "<sip:mallory@192.0.2.66:5060>",
            Some(&authorize("1001", "wrong-password", &nonce, "REGISTER")),
        ),
    );
    assert_eq!(response_of(&outputs, 401).status, 401);

    // An unknown number is refused outright.
    let outputs = feed(
        &mut world,
        &mut switch,
        &register_bytes("9999", "<sip:x@192.0.2.9>", None),
    );
    assert_eq!(response_of(&outputs, 403).status, 403);

    assert_eq!(switch.registered(world.now_ms()), vec!["1001", "1002"]);
}

// ----- AC-02: basic call ----------------------------------------------------

#[test]
fn ac02_call_setup_and_answer() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(
        &mut world,
        &mut switch,
        "1001",
        "change-me",
        "<sip:alice@192.0.2.1:5060>",
    );
    register_device(
        &mut world,
        &mut switch,
        "1002",
        "bob-secret",
        "<sip:bob@192.0.2.2:5060>",
    );

    // Alice dials 1002: the PBX rings Bob (a brand-new leg, B2BUA).
    let outputs = feed(
        &mut world,
        &mut switch,
        &invite_bytes("1001", "1002", "ac02-call"),
    );
    let callee_invite = request_of(&outputs, Method::Invite);
    assert_eq!(callee_invite.uri, "sip:bob@192.0.2.2:5060");
    assert!(
        header_value(&callee_invite.headers, "from")
            .unwrap()
            .contains("sip:1001@"),
        "caller identity is carried over: {:?}",
        callee_invite.headers
    );
    assert_ne!(
        header_value(&callee_invite.headers, "call-id"),
        Some("ac02-call"),
        "the callee leg has its own Call-ID (B2BUA)"
    );

    // Bob rings; Alice hears it.
    let outputs = feed(
        &mut world,
        &mut switch,
        &response_bytes(&callee_invite, 180, "Ringing", "bob1"),
    );
    assert_eq!(response_of(&outputs, 180).status, 180);

    // Bob answers: we ACK him and tell Alice the call is up.
    let outputs = feed(
        &mut world,
        &mut switch,
        &response_bytes(&callee_invite, 200, "OK", "bob1"),
    );
    assert_eq!(request_of(&outputs, Method::Ack).method, Method::Ack);
    let answered = response_of(&outputs, 200);
    let to_tag = tag_of(header_value(&answered.headers, "to").unwrap()).expect("our To tag");

    // Alice's ACK completes the handshake.
    let outputs = feed(&mut world, &mut switch, &ack_for("ac02-call", to_tag));
    assert!(outputs.is_empty());

    assert_eq!(switch.call_state("ac02-call"), Some(CallState::Answered));
    assert_eq!(switch.active_calls(), 1);
}

#[test]
fn ac02_no_answer_gives_up() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(
        &mut world,
        &mut switch,
        "1002",
        "bob-secret",
        "<sip:bob@192.0.2.2:5060>",
    );

    let _ = feed(
        &mut world,
        &mut switch,
        &invite_bytes("1001", "1002", "ac02b-call"),
    );

    // Bob never answers. The transaction timers run out on the virtual clock.
    let mut caller_responses = Vec::new();
    let mut logs = Vec::new();
    loop {
        let timers = switch.timers();
        if timers.is_empty() {
            break;
        }
        for (name, due) in timers {
            world.arm(name, due);
        }
        while let Some(event) = world.next_event() {
            if let Event::Timer { name } = event {
                let outputs = switch.on_timer(&name, world.now_ms());
                for output in &outputs {
                    if let Output::Send(Message::Response(response)) = output {
                        if response.status != 100 {
                            caller_responses.push(response.status);
                        }
                    }
                }
                logs.extend(call_logs(&outputs));
            }
        }
    }

    assert_eq!(
        caller_responses,
        vec![408],
        "the caller is told it timed out"
    );
    assert_eq!(logs.len(), 1);
    assert!(logs[0].contains("\"result\":\"no-answer\""), "{}", logs[0]);
    assert_eq!(switch.active_calls(), 0);
}

// ----- AC-04: teardown ------------------------------------------------------

#[test]
fn ac04_call_teardown_and_log() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(
        &mut world,
        &mut switch,
        "1001",
        "change-me",
        "<sip:alice@192.0.2.1:5060>",
    );
    register_device(
        &mut world,
        &mut switch,
        "1002",
        "bob-secret",
        "<sip:bob@192.0.2.2:5060>",
    );
    let (call_id, to_tag) = establish_call(&mut world, &mut switch);

    // Alice hangs up: her BYE is answered and Bob gets a BYE.
    let outputs = feed(
        &mut world,
        &mut switch,
        &bye_bytes("1001", "sip:192.0.2.10:5060", &to_tag, &call_id, 2),
    );
    assert_eq!(
        response_of(&outputs, 200).status,
        200,
        "her BYE is answered"
    );
    assert_eq!(
        request_of(&outputs, Method::Bye).method,
        Method::Bye,
        "Bob gets a BYE too"
    );

    // One call-log line came with the teardown; the call is gone.
    let logs = call_logs(&outputs);
    assert_eq!(logs.len(), 1, "exactly one log line per call: {logs:?}");
    assert!(logs[0].contains("\"caller\":\"1001\""), "{}", logs[0]);
    assert!(logs[0].contains("\"callee\":\"1002\""), "{}", logs[0]);
    assert!(logs[0].contains("\"result\":\"completed\""), "{}", logs[0]);
    assert_eq!(switch.active_calls(), 0, "no call, no leaked resources");
}

/// Determinism (docs/04 §3 test 7): the same seed replays the same call
/// byte for byte.
#[test]
fn call_scenario_is_deterministic() {
    fn run() -> Vec<String> {
        let mut world = World::with_seed(0x5EED);
        let mut switch = switch();
        register_device(
            &mut world,
            &mut switch,
            "1001",
            "change-me",
            "<sip:alice@192.0.2.1:5060>",
        );
        register_device(
            &mut world,
            &mut switch,
            "1002",
            "bob-secret",
            "<sip:bob@192.0.2.2:5060>",
        );
        let (call_id, to_tag) = establish_call(&mut world, &mut switch);
        let _ = feed(
            &mut world,
            &mut switch,
            &bye_bytes("1001", "sip:192.0.2.10:5060", &to_tag, &call_id, 2),
        );
        world.trace().to_vec()
    }
    assert_eq!(run(), run());
}

// ----- helpers used by the flows above --------------------------------------

/// The caller's ACK for our 200, by call-id and our To-tag.
fn ack_for(call_id: &str, to_tag: &str) -> Vec<u8> {
    format!(
        "ACK sip:192.0.2.10:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:1001@192.0.2.10>;tag=from1\r\n\
         To: <sip:1002@192.0.2.10>;tag={to_tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 ACK\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}
