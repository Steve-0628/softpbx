//! A PBX on several networks (docs/02 §4): every peer is served from the
//! local interface that holds its address, and sees that interface's address
//! in Via, Contact and SDP alike — so SIP calls and RTP work across networks.

use std::net::IpAddr;

use call::{Device, Interface, Network, Output, Switch, SwitchConfig};
use sip_stack::digest::{expected_response, Credentials};
use sip_stack::{make_response, tag_of, with_tag};
use sip_syntax::{parse_sdp, Header, Message, Method, Request, Response};

// ----- interface selection --------------------------------------------------

#[test]
fn networks_parse_and_match() {
    let network = Network::parse("192.168.1.0/24").expect("network");
    assert_eq!(network.addr, "192.168.1.0".parse::<IpAddr>().expect("addr"));
    assert_eq!(network.prefix, 24);
    assert!(network.contains("192.168.1.55".parse().expect("addr")));
    assert!(network.contains("192.168.1.255".parse().expect("addr")));
    assert!(!network.contains("192.168.2.1".parse().expect("addr")));

    // A bare address is a network of one.
    let host = Network::parse("10.0.0.7").expect("host");
    assert_eq!(host.prefix, 32);
    assert!(host.contains("10.0.0.7".parse().expect("addr")));
    assert!(!host.contains("10.0.0.8".parse().expect("addr")));

    // Everything — and nonsense that must not parse.
    let all = Network::parse("0.0.0.0/0").expect("all");
    assert!(all.contains("203.0.113.9".parse().expect("addr")));
    assert!(Network::parse("10.0.0.0/33").is_none());
    assert!(Network::parse("example.com/24").is_none());
    assert!(Network::parse("10.0.0.0/").is_none());
    assert!(Network::parse("").is_none());
}

fn interface(network: &str, sip: &str, rtp: &str) -> Interface {
    Interface {
        network: Network::parse(network).expect("network"),
        sip: sip.parse().expect("sip"),
        rtp: rtp.parse().expect("rtp"),
    }
}

#[test]
fn the_most_specific_network_serves_the_peer() {
    // A guest network nested inside the LAN.
    let interfaces = vec![
        interface("192.168.1.0/24", "192.168.1.10:5060", "192.168.1.10"),
        interface("192.168.1.128/25", "192.168.1.200:5060", "192.168.1.200"),
    ];
    let lan_peer = "192.168.1.55".parse().expect("addr");
    let guest_peer = "192.168.1.201".parse().expect("addr");
    let stranger = "10.9.9.9".parse().expect("addr");
    assert_eq!(
        call::interface_for(&interfaces, lan_peer)
            .expect("served")
            .sip,
        "192.168.1.10:5060".parse().expect("sip")
    );
    assert_eq!(
        call::interface_for(&interfaces, guest_peer)
            .expect("served")
            .sip,
        "192.168.1.200:5060".parse().expect("sip")
    );
    // No network holds the stranger: callers fall back to their first
    // interface.
    assert!(call::interface_for(&interfaces, stranger).is_none());
}

// ----- a call across two networks ------------------------------------------

/// The PBX: LAN on 192.0.2.0/24, another network on 198.51.100.0/24.
fn switch() -> Switch {
    Switch::new(SwitchConfig {
        realm: "softpbx".to_string(),
        interfaces: vec![
            interface("192.0.2.0/24", "192.0.2.10:5060", "192.0.2.10"),
            interface("198.51.100.0/24", "198.51.100.1:5060", "198.51.100.1"),
        ],
        rtp_port_base: 10_000,
        rtp_ports: 10,
        routing: vec![],
        trunks: vec![],
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

#[test]
fn each_side_of_a_call_is_served_from_its_own_network() {
    let mut switch = switch();
    // Alice lives on the LAN, Bob on the other network.
    register(
        &mut switch,
        "1001",
        "change-me",
        "<sip:alice@192.0.2.1:5060>",
    );
    register(
        &mut switch,
        "1002",
        "bob-secret",
        "<sip:bob@198.51.100.2:5060>",
    );

    // Alice (LAN) calls Bob, with media.
    let outputs = switch.handle(
        Message::Request(invite(
            "1001",
            "1002",
            "call-multi",
            &sdp_body("192.0.2.1:20000"),
        )),
        0,
        Some("192.0.2.1:5060".parse().expect("source")),
    );

    // The leg toward Bob leaves from the other network's interface.
    let callee_invite = (*requests_of(&outputs, Method::Invite)
        .first()
        .expect("INVITE toward the callee"))
    .clone();
    let via = header(&callee_invite.headers, "Via").expect("Via");
    assert!(
        via.starts_with("SIP/2.0/UDP 198.51.100.1:5060"),
        "the callee leg is served from the callee-side interface: {via}"
    );
    assert_eq!(
        header(&callee_invite.headers, "Contact"),
        Some("<sip:198.51.100.1:5060>")
    );
    let (ip, callee_port) = sdp_media(&callee_invite.body);
    assert_eq!(ip, "198.51.100.1", "media is advertised on the far side");
    assert!(callee_port >= 10_000, "from the relay range");

    // Bob answers with media of his own.
    let outputs = switch.handle(
        Message::Response(tagged_response(
            &callee_invite,
            200,
            "OK",
            "bob1",
            &sdp_body("198.51.100.2:30000"),
        )),
        10,
        None,
    );

    // The ACK toward Bob keeps the far-side address.
    let acks = requests_of(&outputs, Method::Ack);
    let ack = acks.first().expect("ACK toward the callee");
    assert!(header(&ack.headers, "Via")
        .expect("Via")
        .starts_with("SIP/2.0/UDP 198.51.100.1:5060"));
    assert_eq!(
        header(&ack.headers, "Contact"),
        Some("<sip:198.51.100.1:5060>")
    );

    // The answer toward Alice carries the LAN-side address.
    let ok = response_of(&outputs, 200);
    assert_eq!(
        header(&ok.headers, "Contact"),
        Some("<sip:192.0.2.10:5060>"),
        "the caller leg is served from the caller-side interface"
    );
    let (ip, caller_port) = sdp_media(&ok.body);
    assert_eq!(ip, "192.0.2.10", "media is advertised on the near side");
    assert!(caller_port >= 10_000, "from the relay range");
    assert_ne!(caller_port, callee_port, "each leg gets its own relay port");

    // Bob hangs up: the BYE toward Alice is served from the LAN side.
    let callee_call_id = header(&callee_invite.headers, "Call-ID")
        .expect("Call-ID")
        .to_string();
    let our_callee_tag = tag_of(header(&callee_invite.headers, "From").expect("From"))
        .expect("our tag")
        .to_string();
    let outputs = switch.handle(
        Message::Request(bye(
            &callee_call_id,
            "bob1",
            &our_callee_tag,
            "sip:198.51.100.1:5060",
        )),
        20,
        Some("198.51.100.2:5060".parse().expect("source")),
    );
    let byes = requests_of(&outputs, Method::Bye);
    assert_eq!(byes.len(), 1, "one BYE toward the caller");
    let bye = byes[0];
    assert!(
        header(&bye.headers, "Via")
            .expect("Via")
            .starts_with("SIP/2.0/UDP 192.0.2.10:5060"),
        "the caller leg hangs up on the caller-side interface"
    );
    assert_eq!(
        header(&bye.headers, "Contact"),
        Some("<sip:192.0.2.10:5060>")
    );
    assert!(
        bye.uri.starts_with("sip:1001@192.0.2.1"),
        "to Alice's contact: {}",
        bye.uri
    );
}

// ----- test plumbing --------------------------------------------------------

fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
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

fn requests_of(outputs: &[Output], method: Method) -> Vec<&Request> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::Send(Message::Request(request)) if request.method == method => Some(request),
            _ => None,
        })
        .collect()
}

/// A phone's SDP for one audio stream.
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

/// The (connection address, port) an SDP body offers for audio.
fn sdp_media(body: &[u8]) -> (String, u16) {
    let sdp = parse_sdp(body).expect("parseable SDP");
    let audio = sdp
        .media
        .iter()
        .find(|media| media.media == "audio")
        .expect("audio stream");
    (audio.connection.clone().expect("connection"), audio.port)
}

/// Registers a device the honest way: get challenged, answer.
fn register(switch: &mut Switch, number: &str, secret: &str, contact: &str) {
    let request = Request {
        method: Method::Register,
        uri: "sip:192.0.2.10".to_string(),
        headers: vec![
            Header {
                name: "Via".to_string(),
                value: format!("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-reg-{number}"),
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
                value: format!("reg-{number}"),
            },
            Header {
                name: "CSeq".to_string(),
                value: "1 REGISTER".to_string(),
            },
            Header {
                name: "Contact".to_string(),
                value: contact.to_string(),
            },
        ],
        body: Vec::new(),
    };
    let outputs = switch.handle(Message::Request(request), 0, None);
    let challenge = response_of(&outputs, 401);
    let value = header(&challenge.headers, "WWW-Authenticate").expect("challenge");
    let nonce = &value[value.find("nonce=\"").expect("nonce") + 7..];
    let nonce = &nonce[..nonce.find('"').expect("closing quote")];
    let credentials = Credentials {
        username: number.to_string(),
        realm: "softpbx".to_string(),
        nonce: nonce.to_string(),
        uri: "sip:192.0.2.10".to_string(),
        response: String::new(),
        qop: None,
        nc: None,
        cnonce: None,
    };
    let response = expected_response(&credentials, secret, "REGISTER");
    let request = Request {
        method: Method::Register,
        uri: "sip:192.0.2.10".to_string(),
        headers: vec![
            Header {
                name: "Authorization".to_string(),
                value: format!(
                    "Digest username=\"{number}\", realm=\"softpbx\", nonce=\"{nonce}\", \
                     uri=\"sip:192.0.2.10\", response=\"{response}\""
                ),
            },
            Header {
                name: "Via".to_string(),
                value: format!("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-reg2-{number}"),
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
                value: format!("reg-{number}"),
            },
            Header {
                name: "CSeq".to_string(),
                value: "2 REGISTER".to_string(),
            },
            Header {
                name: "Contact".to_string(),
                value: contact.to_string(),
            },
        ],
        body: Vec::new(),
    };
    let outputs = switch.handle(Message::Request(request), 0, None);
    assert_eq!(
        response_of(&outputs, 200).status,
        200,
        "registration of {number}"
    );
}

/// An INVITE with an SDP offer of its own.
fn invite(from: &str, to: &str, call_id: &str, body: &[u8]) -> Request {
    Request {
        method: Method::Invite,
        uri: format!("sip:{to}@192.0.2.10"),
        headers: vec![
            Header {
                name: "Via".to_string(),
                value: format!("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{call_id}"),
            },
            Header {
                name: "Max-Forwards".to_string(),
                value: "70".to_string(),
            },
            Header {
                name: "From".to_string(),
                value: format!("<sip:{from}@192.0.2.10>;tag=from1"),
            },
            Header {
                name: "To".to_string(),
                value: format!("<sip:{to}@192.0.2.10>"),
            },
            Header {
                name: "Call-ID".to_string(),
                value: call_id.to_string(),
            },
            Header {
                name: "CSeq".to_string(),
                value: "1 INVITE".to_string(),
            },
            Header {
                name: "Contact".to_string(),
                value: format!("<sip:{from}@192.0.2.1:5060>"),
            },
            Header {
                name: "Content-Type".to_string(),
                value: "application/sdp".to_string(),
            },
        ],
        body: body.to_vec(),
    }
}

/// A phone's response to a request the PBX sent it, optionally with SDP.
fn tagged_response(
    request: &Request,
    status: u16,
    reason: &str,
    to_tag: &str,
    body: &[u8],
) -> Response {
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
    response
}

/// An in-dialog BYE a phone sends.
fn bye(call_id: &str, from_tag: &str, to_tag: &str, uri: &str) -> Request {
    Request {
        method: Method::Bye,
        uri: uri.to_string(),
        headers: vec![
            Header {
                name: "Via".to_string(),
                value: "SIP/2.0/UDP 198.51.100.2:5060;branch=z9hG4bK-bye".to_string(),
            },
            Header {
                name: "Max-Forwards".to_string(),
                value: "70".to_string(),
            },
            Header {
                name: "From".to_string(),
                value: format!("<sip:1002@198.51.100.2:5060>;tag={from_tag}"),
            },
            Header {
                name: "To".to_string(),
                value: format!("<sip:1001@192.0.2.10>;tag={to_tag}"),
            },
            Header {
                name: "Call-ID".to_string(),
                value: call_id.to_string(),
            },
            Header {
                name: "CSeq".to_string(),
                value: "2 BYE".to_string(),
            },
        ],
        body: Vec::new(),
    }
}
