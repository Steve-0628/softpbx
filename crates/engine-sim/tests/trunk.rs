//! Phase 9 (docs/08): trunk core — site-to-site calls through a trunk, in the
//! simulation, against a peer that speaks like MikoPBX (docs/09 §6).
//!
//! The peer is played by the tests: it "sends" from the trunk's address and
//! speaks the captured wire forms (its own domain in To/From, trunk login in
//! From when configured, no session timers, answers OPTIONS).

use std::net::SocketAddr;

use call::{Action, Device, Output, Rule, Switch, SwitchConfig, TrunkConfig};
use engine_sim::{Event, World};
use sip_stack::digest::{expected_response, Credentials};
use sip_stack::{make_response, tag_of};
use sip_syntax::{parse_message, serialize_message, Header, Message, Method, Request, Response};

const REALM: &str = "softpbx";
const PBX_URI: &str = "sip:192.0.2.10";
const PBX_HOST: &str = "192.0.2.10:5060";
const PEER: &str = "192.168.77.108:5060"; // the captured MikoPBX address

fn peer_addr() -> SocketAddr {
    PEER.parse().expect("peer address")
}

fn switch() -> Switch {
    Switch::new(SwitchConfig {
        realm: REALM.to_string(),
        pbx_uri: PBX_URI.to_string(),
        pbx_host: PBX_HOST.to_string(),
        pbx_contact: "<sip:192.0.2.10:5060>".to_string(),
        rtp_host: "192.0.2.10".to_string(),
        rtp_port_base: 10_000,
        rtp_ports: 100,
        routing: vec![
            Rule {
                pattern: "3*".to_string(),
                action: Action::Trunk("mikopbx".to_string()),
                strip: None,
            },
            Rule {
                pattern: "0".to_string(),
                action: Action::Number("1002".to_string()),
                strip: None,
            },
        ],
        trunks: vec![TrunkConfig {
            name: "mikopbx".to_string(),
            peer: peer_addr(),
        }],
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

// ----- plumbing -------------------------------------------------------------

fn feed(world: &mut World, switch: &mut Switch, raw: &[u8]) -> Vec<Output> {
    feed_from(world, switch, raw, None)
}

fn feed_from(
    world: &mut World,
    switch: &mut Switch,
    raw: &[u8],
    from: Option<SocketAddr>,
) -> Vec<Output> {
    let message = parse_message(raw).expect("our messages parse");
    let outputs = switch.handle(message, world.now_ms(), from);
    world.log(format!("-> {} outputs", outputs.len()));
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

fn requests_of(outputs: &[Output], method: Method) -> Vec<Request> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::Send(Message::Request(request)) if request.method == method => {
                Some(request.clone())
            }
            _ => None,
        })
        .collect()
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

fn header_value<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn sdp_body(media: &str) -> Vec<u8> {
    let (ip, port) = media.split_once(':').expect("ip:port");
    format!(
        "v=0\r\no=phone 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=ptime:20\r\n"
    )
    .into_bytes()
}

fn register_device(world: &mut World, switch: &mut Switch, number: &str, secret: &str) {
    let contact = format!("<sip:{number}@192.0.2.1:5060>");
    let mut text = format!(
        "REGISTER {PBX_URI} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-reg-{number}\r\n\
         From: <sip:{number}@192.0.2.10>;tag=1\r\n\
         To: <sip:{number}@192.0.2.10>\r\n\
         Call-ID: reg-{number}\r\n\
         CSeq: 1 REGISTER\r\n\
         Contact: {contact}\r\n\
         Expires: 3600\r\nContent-Length: 0\r\n\r\n"
    );
    let outputs = feed(world, switch, text.as_bytes());
    let challenge = response_of(&outputs, 401);
    let value = header_value(&challenge.headers, "WWW-Authenticate").unwrap();
    let start = value.find("nonce=\"").unwrap() + 7;
    let nonce = value[start..].split('"').next().unwrap().to_string();
    let credentials = Credentials {
        username: number.to_string(),
        realm: REALM.to_string(),
        nonce: nonce.clone(),
        uri: PBX_URI.to_string(),
        response: String::new(),
        qop: None,
        nc: None,
        cnonce: None,
    };
    let response = expected_response(&credentials, secret, "REGISTER");
    text = text
        .replace("CSeq: 1 REGISTER", "CSeq: 2 REGISTER")
        .replace(
            "Content-Length: 0",
            &format!(
                "Authorization: Digest username=\"{number}\", realm=\"{REALM}\", \
                 nonce=\"{nonce}\", uri=\"{PBX_URI}\", response=\"{response}\"\r\n\
                 Content-Length: 0"
            ),
        );
    let outputs = feed(world, switch, text.as_bytes());
    assert_eq!(response_of(&outputs, 200).status, 200, "{number} registers");
}

// ----- outbound: our device calls a number on the far PBX -------------------

#[test]
fn trunk_outbound_call_is_addressed_to_the_peer() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(&mut world, &mut switch, "1001", "change-me");

    // Alice dials 3001 — a number that lives on the far PBX.
    let outputs = feed(
        &mut world,
        &mut switch,
        &invite("1001", "3001", "trunk-out", "192.0.2.1:10000"),
    );
    let toward_peer = requests_of(&outputs, Method::Invite);
    assert_eq!(
        toward_peer.len(),
        1,
        "one INVITE, toward the peer: {outputs:?}"
    );
    let invite = &toward_peer[0];

    // It goes to the peer's address (asserted by the daemon's dispatch; here
    // the important part is the addressing on the wire).
    assert_eq!(
        invite.uri, "sip:3001@192.168.77.108",
        "peer routes the number"
    );
    let to = header_value(&invite.headers, "to").unwrap();
    assert!(
        to.contains("sip:3001@192.168.77.108"),
        "peer's domain: {to}"
    );
    let from = header_value(&invite.headers, "from").unwrap();
    assert!(
        from.contains("sip:1001@"),
        "caller identity survives: {from}"
    );

    // The peer answers; we ACK it and tell Alice the call is up.
    let outputs = feed(
        &mut world,
        &mut switch,
        &response_bytes(invite, 200, "OK", "far1", &sdp_body("192.168.77.108:10000")),
    );
    assert_eq!(requests_of(&outputs, Method::Ack).len(), 1);
    assert_eq!(response_of(&outputs, 200).status, 200, "Alice hears it");
}

#[test]
fn trunk_outbound_busy_is_reported_to_the_caller() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(&mut world, &mut switch, "1001", "change-me");
    let outputs = feed(
        &mut world,
        &mut switch,
        &invite("1001", "3001", "trunk-busy", "192.0.2.1:10000"),
    );
    let invite = requests_of(&outputs, Method::Invite)[0].clone();
    let outputs = feed(
        &mut world,
        &mut switch,
        &response_bytes(&invite, 486, "Busy Here", "far1", b""),
    );
    assert_eq!(
        response_of(&outputs, 486).status,
        486,
        "busy arrives as busy: {outputs:?}"
    );
    assert_eq!(requests_of(&outputs, Method::Ack).len(), 1, "we ACK it");
    let logs = call_logs(&outputs);
    assert!(
        logs[0].contains("\"result\":\"rejected:486\""),
        "{}",
        logs[0]
    );
}

#[test]
fn trunk_outbound_hangup_bye_each_way() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(&mut world, &mut switch, "1001", "change-me");
    let outputs = feed(
        &mut world,
        &mut switch,
        &invite("1001", "3001", "trunk-bye", "192.0.2.1:10000"),
    );
    let invite = requests_of(&outputs, Method::Invite)[0].clone();
    let outputs = feed(
        &mut world,
        &mut switch,
        &response_bytes(
            &invite,
            200,
            "OK",
            "far1",
            &sdp_body("192.168.77.108:10000"),
        ),
    );
    let answered = response_of(&outputs, 200);
    let our_tag = tag_of(header_value(&answered.headers, "to").unwrap()).unwrap();

    // Alice hangs up: the peer gets a BYE, and the call logs once.
    let outputs = feed(&mut world, &mut switch, &bye("1001", "trunk-bye", our_tag));
    assert_eq!(response_of(&outputs, 200).status, 200);
    assert_eq!(
        requests_of(&outputs, Method::Bye).len(),
        1,
        "BYE toward the peer"
    );
    assert_eq!(switch.active_calls(), 0);
    let logs = call_logs(&outputs);
    assert!(logs[0].contains("\"result\":\"completed\""), "{}", logs[0]);
}

// ----- inbound: the far PBX calls one of our devices ------------------------

#[test]
fn trunk_inbound_call_rings_the_device() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(&mut world, &mut switch, "1002", "bob-secret");

    // The peer calls 1002. Its caller (3001) is NOT registered here — a trunk
    // caller is identified by its address, not by registration.
    let outputs = feed_from(
        &mut world,
        &mut switch,
        &peer_invite("3001", "1002", "trunk-in"),
        Some(peer_addr()),
    );
    assert_eq!(
        response_of(&outputs, 100).status,
        100,
        "we take the call: {outputs:?}"
    );
    let toward_device = requests_of(&outputs, Method::Invite);
    assert_eq!(toward_device.len(), 1);
    let invite = &toward_device[0];
    assert!(
        header_value(&invite.headers, "to")
            .unwrap()
            .contains("sip:1002@"),
        "rings the local device"
    );
    assert!(
        header_value(&invite.headers, "from")
            .unwrap()
            .contains("sip:3001@"),
        "the far caller's identity is carried over: {:?}",
        header_value(&invite.headers, "from")
    );

    // Bob answers; the peer gets the 200 and its ACK completes the call.
    let outputs = feed(
        &mut world,
        &mut switch,
        &response_bytes(invite, 200, "OK", "bob1", &sdp_body("192.0.2.2:20000")),
    );
    assert_eq!(requests_of(&outputs, Method::Ack).len(), 1);
    assert_eq!(response_of(&outputs, 200).status, 200, "toward the peer");
}

#[test]
fn trunk_inbound_from_a_stranger_is_refused() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(&mut world, &mut switch, "1002", "bob-secret");

    // The same INVITE from a random address: not a trunk peer, caller not
    // registered — refused as usual.
    let outputs = feed_from(
        &mut world,
        &mut switch,
        &peer_invite("3001", "1002", "stranger"),
        "10.9.9.9:5060".parse().ok(),
    );
    assert_eq!(response_of(&outputs, 403).status, 403);
    assert!(requests_of(&outputs, Method::Invite).is_empty());
}

#[test]
fn trunk_inbound_bye_from_peer_ends_the_call() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(&mut world, &mut switch, "1002", "bob-secret");
    let outputs = feed_from(
        &mut world,
        &mut switch,
        &peer_invite("3001", "1002", "trunk-in-bye"),
        Some(peer_addr()),
    );
    let invite = requests_of(&outputs, Method::Invite)[0].clone();
    let outputs = feed(
        &mut world,
        &mut switch,
        &response_bytes(&invite, 200, "OK", "bob1", &sdp_body("192.0.2.2:20000")),
    );
    let answered = response_of(&outputs, 200);
    let our_tag = tag_of(header_value(&answered.headers, "to").unwrap()).unwrap();

    // The peer hangs up (its BYE carries the callee-leg ids).
    let peer_bye = format!(
        "BYE {PBX_URI} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.168.77.108:5060;branch=z9hG4bK-pbye\r\n\
         From: <sip:3001@192.168.77.108>;tag=far1\r\n\
         To: <sip:1002@192.0.2.10>;tag={our_tag}\r\n\
         Call-ID: trunk-in-bye\r\n\
         CSeq: 5 BYE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let outputs = feed_from(
        &mut world,
        &mut switch,
        peer_bye.as_bytes(),
        Some(peer_addr()),
    );
    assert_eq!(response_of(&outputs, 200).status, 200, "{outputs:?}");
    assert_eq!(
        requests_of(&outputs, Method::Bye).len(),
        1,
        "the local device is hung up too"
    );
    assert_eq!(switch.active_calls(), 0);
}

// ----- resilience -----------------------------------------------------------

#[test]
fn trunk_lost_200_is_recovered_by_retransmission() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(&mut world, &mut switch, "1001", "change-me");
    let outputs = feed(
        &mut world,
        &mut switch,
        &invite("1001", "3001", "trunk-lost", "192.0.2.1:10000"),
    );
    let invite = requests_of(&outputs, Method::Invite)[0].clone();
    let ok = response_bytes(
        &invite,
        200,
        "OK",
        "far1",
        &sdp_body("192.168.77.108:10000"),
    );

    // First 200 is lost on the wire; the peer retransmits it later.
    let outputs = feed(&mut world, &mut switch, &ok);
    assert_eq!(requests_of(&outputs, Method::Ack).len(), 1);
    let again = feed(&mut world, &mut switch, &ok);
    assert_eq!(
        requests_of(&again, Method::Ack).len(),
        1,
        "the retransmitted 200 is re-ACKed (RFC 3261 §13.2.2.4)"
    );
}

#[test]
fn trunk_no_answer_times_out_with_408() {
    let mut world = World::with_seed(0x5EED);
    let mut switch = switch();
    register_device(&mut world, &mut switch, "1001", "change-me");
    let _ = feed(
        &mut world,
        &mut switch,
        &invite("1001", "3001", "trunk-dead", "192.0.2.1:10000"),
    );

    let mut got_408 = false;
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
                for output in switch.on_timer(&name, world.now_ms()) {
                    if let Output::Send(Message::Response(response)) = output {
                        if response.status == 408 {
                            got_408 = true;
                        }
                    }
                }
            }
        }
    }
    assert!(got_408, "the caller is told it timed out");
    assert_eq!(switch.active_calls(), 0);
}

// ----- message builders -----------------------------------------------------

fn invite(from: &str, to: &str, call_id: &str, media: &str) -> Vec<u8> {
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

/// The peer's INVITE, in its captured shape: From/To in the peer's domain.
fn peer_invite(from: &str, to: &str, call_id: &str) -> Vec<u8> {
    let body = sdp_body("192.168.77.108:10000");
    let mut text = format!(
        "INVITE sip:{to}@192.0.2.10 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.168.77.108:5060;branch=z9hG4bK-{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:{from}@192.168.77.108>;tag=far1\r\n\
         To: <sip:{to}@192.0.2.10>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:{from}@192.168.77.108:5060>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    text.push_str(&String::from_utf8(body).unwrap());
    text.into_bytes()
}

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

fn bye(from: &str, call_id: &str, to_tag: &str) -> Vec<u8> {
    format!(
        "BYE {PBX_URI} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-bye-{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:{from}@192.0.2.10>;tag=from1\r\n\
         To: <sip:3001@192.168.77.108>;tag={to_tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 2 BYE\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

fn with_tag(value: &str, tag: &str) -> String {
    sip_stack::with_tag(value, tag)
}
