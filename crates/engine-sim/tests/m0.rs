//! M0 acceptance tests (docs/04 §3):
//!
//! 1. registration ✅ (AC-01)
//! 2. basic call ✅ (AC-02)
//! 3. audio quality ✅ (AC-03)
//! 4. teardown ✅ (AC-04)
//! 5. concurrent calls ✅ (AC-05)
//! 6. robustness — parser tests + fuzzing (phase 1)
//! 7. determinism — plus `same_seed_produces_identical_trace` (phase 2)
//!
//! Everything runs on the deterministic world and speaks real SIP: messages
//! cross the boundary as bytes.

use call::{CallState, Device, Output, Switch, SwitchConfig};
use engine_sim::{Event, World};
use rtp::Packet;
use sip_stack::digest::{expected_response, Credentials};
use sip_stack::{make_response, tag_of, with_tag};
use sip_syntax::{
    parse_message, parse_sdp, serialize_message, Header, Message, Method, Request, Response,
};

const REALM: &str = "softpbx";
const PBX_URI: &str = "sip:192.0.2.10";
const PBX_HOST: &str = "192.0.2.10:5060";
const PBX_CONTACT: &str = "<sip:192.0.2.10:5060>";

fn switch_with(devices: Vec<Device>) -> Switch {
    Switch::new(SwitchConfig {
        realm: REALM.to_string(),
        pbx_uri: PBX_URI.to_string(),
        pbx_host: PBX_HOST.to_string(),
        pbx_contact: PBX_CONTACT.to_string(),
        rtp_host: "192.0.2.10".to_string(),
        rtp_port_base: 10_000,
        devices,
    })
}

fn switch() -> Switch {
    switch_with(vec![
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
    ])
}

// ----- test plumbing --------------------------------------------------------

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
            Output::SendRtp { to, .. } => world.log(format!("pbx -> media: {to}")),
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

fn rtp_forwards(outputs: &[Output]) -> Vec<(String, Vec<u8>)> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::SendRtp { to, data, .. } => Some((to.clone(), data.clone())),
            _ => None,
        })
        .collect()
}

fn header_value<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

/// ("ip", port) of the audio stream an SDP body offers.
fn sdp_audio_media(body: &[u8]) -> Option<(String, u16)> {
    let sdp = parse_sdp(body).ok()?;
    let audio = sdp.media.iter().find(|media| media.media == "audio")?;
    Some((audio.connection.clone()?, audio.port))
}

// ----- messages the fake phones send ---------------------------------------

fn sdp_body(media: &str) -> Vec<u8> {
    let (ip, port) = media.split_once(':').expect("ip:port");
    format!(
        "v=0\r\n\
         o=phone 1 1 IN IP4 {ip}\r\n\
         s=-\r\n\
         c=IN IP4 {ip}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0 8 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=ptime:10\r\n"
    )
    .into_bytes()
}

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

fn invite_bytes(from: &str, to: &str, call_id: &str, media: &str) -> Vec<u8> {
    let body = sdp_body(media);
    let mut text = format!(
        "INVITE sip:{to}@192.0.2.10 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:{from}@192.0.2.10>;tag=from1\r\n\
         To: <sip:{to}@192.0.2.10>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:{from}@192.0.2.1:5060>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    text.push_str(&String::from_utf8(body).unwrap());
    text.into_bytes()
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

/// A phone's response to a request the PBX sent it (optionally with SDP).
fn response_bytes(
    request: &Request,
    status: u16,
    reason: &str,
    to_tag: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut response = make_response(request, status, reason);
    for header in &mut response.headers {
        if header.name == "To" {
            header.value = with_tag(&header.value, to_tag);
        }
    }
    if !body.is_empty() {
        response.headers.push(Header {
            name: "Content-Type".to_string(),
            value: "application/sdp".to_string(),
        });
        response.body = body.to_vec();
    }
    serialize_message(&Message::Response(response))
}

/// The caller's ACK for our 200.
fn ack_bytes(call_id: &str, from: &str, to: &str, to_tag: &str) -> Vec<u8> {
    format!(
        "ACK sip:192.0.2.10:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:{from}@192.0.2.10>;tag=from1\r\n\
         To: <sip:{to}@192.0.2.10>;tag={to_tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 ACK\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
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

/// What a completed call setup gives us to work with.
struct CallSetup {
    call_id: String,
    to_tag: String,
    /// Our relay port for the caller's leg.
    caller_relay_port: u16,
    /// Our relay port for the callee's leg.
    callee_relay_port: u16,
    caller_media: String,
    callee_media: String,
}

/// Full call setup: INVITE → ring → answer → ACK, with media on both legs.
fn establish_call(
    world: &mut World,
    switch: &mut Switch,
    call_id: &str,
    from: &str,
    to: &str,
    caller_media: &str,
    callee_media: &str,
) -> CallSetup {
    let outputs = feed(
        world,
        switch,
        &invite_bytes(from, to, call_id, caller_media),
    );
    let callee_invite = request_of(&outputs, Method::Invite);
    let (_, callee_relay_port) = sdp_audio_media(&callee_invite.body).expect("our SDP offer");

    let outputs = feed(
        world,
        switch,
        &response_bytes(&callee_invite, 180, "Ringing", "bob1", b""),
    );
    assert_eq!(
        response_of(&outputs, 180).status,
        180,
        "the caller hears ringing"
    );

    let outputs = feed(
        world,
        switch,
        &response_bytes(&callee_invite, 200, "OK", "bob1", &sdp_body(callee_media)),
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
    let (_, caller_relay_port) = sdp_audio_media(&answered.body).expect("our SDP answer");

    let outputs = feed(world, switch, &ack_bytes(call_id, from, to, &to_tag));
    assert!(outputs.is_empty(), "the ACK needs no answer");
    assert_eq!(switch.call_state(call_id), Some(CallState::Answered));

    CallSetup {
        call_id: call_id.to_string(),
        to_tag,
        caller_relay_port,
        callee_relay_port,
        caller_media: caller_media.to_string(),
        callee_media: callee_media.to_string(),
    }
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
        &invite_bytes("1001", "1002", "ac02-call", "192.0.2.1:10000"),
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
        &response_bytes(&callee_invite, 180, "Ringing", "bob1", b""),
    );
    assert_eq!(response_of(&outputs, 180).status, 180);

    // Bob answers: we ACK him and tell Alice the call is up.
    let outputs = feed(
        &mut world,
        &mut switch,
        &response_bytes(
            &callee_invite,
            200,
            "OK",
            "bob1",
            &sdp_body("192.0.2.2:20000"),
        ),
    );
    assert_eq!(request_of(&outputs, Method::Ack).method, Method::Ack);
    let answered = response_of(&outputs, 200);
    let to_tag = tag_of(header_value(&answered.headers, "to").unwrap()).expect("our To tag");

    // Alice's ACK completes the handshake.
    let outputs = feed(
        &mut world,
        &mut switch,
        &ack_bytes("ac02-call", "1001", "1002", to_tag),
    );
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
        &invite_bytes("1001", "1002", "ac02b-call", "192.0.2.1:10000"),
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

// ----- AC-03: audio quality -------------------------------------------------

#[test]
fn ac03_audio_flows_without_loss() {
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
    let call = establish_call(
        &mut world,
        &mut switch,
        "ac03-call",
        "1001",
        "1002",
        "192.0.2.1:10000",
        "192.0.2.2:20000",
    );

    // 60 seconds of G.711 at 10 ms per packet, both directions.
    let packets: u32 = 6_000;
    let payload = [0xffu8; 80]; // 10 ms of G.711 at 8 kHz
    let mut to_bob = 0u64;
    let mut to_alice = 0u64;
    let mut last_seq_bob = None;
    let mut last_seq_alice = None;
    for i in 0..packets {
        world.advance(10);
        let sequence = i as u16;

        // Alice → relay → Bob.
        let packet = Packet::build(false, 0, sequence, i * 160, 0xa11ce, &payload);
        let outputs = switch.on_rtp(
            call.caller_relay_port,
            &call.caller_media,
            packet.to_bytes(),
        );
        for (to, data) in rtp_forwards(&outputs) {
            assert_eq!(to, call.callee_media, "Alice's audio goes to Bob");
            assert_eq!(data, packet.to_bytes(), "the pipe is transparent");
            assert_eq!(data[2..4], sequence.to_be_bytes(), "order preserved");
            to_bob += 1;
        }

        // Bob → relay → Alice.
        let packet = Packet::build(false, 8, sequence, i * 160, 0xb0b, &payload);
        let outputs = switch.on_rtp(
            call.callee_relay_port,
            &call.callee_media,
            packet.to_bytes(),
        );
        for (to, data) in rtp_forwards(&outputs) {
            assert_eq!(to, call.caller_media, "Bob's audio goes to Alice");
            assert_eq!(data[2..4], sequence.to_be_bytes(), "order preserved");
            to_alice += 1;
        }
        last_seq_bob = Some(sequence);
        last_seq_alice = Some(sequence);
    }

    assert_eq!(to_bob, u64::from(packets), "no packet lost Alice → Bob");
    assert_eq!(to_alice, u64::from(packets), "no packet lost Bob → Alice");
    assert_eq!(last_seq_bob, Some(packets as u16 - 1));
    assert_eq!(last_seq_alice, Some(packets as u16 - 1));

    // Garbage is dropped, not forwarded (docs/07).
    let outputs = switch.on_rtp(call.caller_relay_port, &call.caller_media, b"not rtp");
    assert!(rtp_forwards(&outputs).is_empty());
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
    let call = establish_call(
        &mut world,
        &mut switch,
        "ac04-call",
        "1001",
        "1002",
        "192.0.2.1:10000",
        "192.0.2.2:20000",
    );

    // Alice hangs up: her BYE is answered and Bob gets a BYE.
    let outputs = feed(
        &mut world,
        &mut switch,
        &bye_bytes(
            "1001",
            "sip:192.0.2.10:5060",
            &call.to_tag,
            &call.call_id,
            2,
        ),
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

    // Late media for the dead call is dropped, not forwarded.
    let late = Packet::build(false, 0, 1, 160, 7, &[0xff; 80]);
    let outputs = switch.on_rtp(call.caller_relay_port, &call.caller_media, late.to_bytes());
    assert!(rtp_forwards(&outputs).is_empty(), "no leaked media path");
}

// ----- AC-05: concurrent calls ----------------------------------------------

#[test]
fn ac05_ten_concurrent_calls() {
    let mut world = World::with_seed(0x5EED);
    let devices: Vec<Device> = (1001..1021)
        .map(|number| Device {
            number: number.to_string(),
            name: format!("Phone {number}"),
            secret: format!("secret-{number}"),
        })
        .collect();
    let mut switch = switch_with(devices);

    // 20 devices register.
    for number in 1001..1021u32 {
        let contact = format!("<sip:{number}@192.0.2.{}:5060>", number - 900);
        register_device(
            &mut world,
            &mut switch,
            &number.to_string(),
            &format!("secret-{number}"),
            &contact,
        );
    }
    assert_eq!(switch.registered(world.now_ms()).len(), 20);

    // 10 calls, all up at the same time.
    let mut calls = Vec::new();
    for pair in 0..10 {
        let caller = (1001 + pair * 2).to_string();
        let callee = (1002 + pair * 2).to_string();
        let call = establish_call(
            &mut world,
            &mut switch,
            &format!("ac05-call-{pair}"),
            &caller,
            &callee,
            &format!("192.0.2.{}:10000", 100 + pair),
            &format!("192.0.2.{}:20000", 150 + pair),
        );
        calls.push(call);
    }
    assert_eq!(switch.active_calls(), 10, "all calls are up together");

    // 100 packets each way on every call.
    let mut forwarded = 0u64;
    for i in 0..100u16 {
        world.advance(10);
        for call in &calls {
            let packet = Packet::build(false, 0, i, u32::from(i) * 160, 1, &[0xff; 80]);
            let outputs = switch.on_rtp(
                call.caller_relay_port,
                &call.caller_media,
                packet.to_bytes(),
            );
            for (to, _) in rtp_forwards(&outputs) {
                assert_eq!(to, call.callee_media);
                forwarded += 1;
            }
            let packet = Packet::build(false, 8, i, u32::from(i) * 160, 2, &[0xff; 80]);
            let outputs = switch.on_rtp(
                call.callee_relay_port,
                &call.callee_media,
                packet.to_bytes(),
            );
            for (to, _) in rtp_forwards(&outputs) {
                assert_eq!(to, call.caller_media);
                forwarded += 1;
            }
        }
    }
    assert_eq!(forwarded, 2_000, "10 calls × 2 directions × 100 packets");
}

// ----- determinism (docs/04 §3 test 7) --------------------------------------

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
        let call = establish_call(
            &mut world,
            &mut switch,
            "det-call",
            "1001",
            "1002",
            "192.0.2.1:10000",
            "192.0.2.2:20000",
        );
        for i in 0..50u16 {
            world.advance(10);
            let packet = Packet::build(false, 0, i, u32::from(i) * 160, 9, &[0xff; 80]);
            let _ = switch.on_rtp(
                call.caller_relay_port,
                &call.caller_media,
                packet.to_bytes(),
            );
        }
        let _ = feed(
            &mut world,
            &mut switch,
            &bye_bytes(
                "1001",
                "sip:192.0.2.10:5060",
                &call.to_tag,
                &call.call_id,
                2,
            ),
        );
        world.trace().to_vec()
    }
    assert_eq!(run(), run());
}
