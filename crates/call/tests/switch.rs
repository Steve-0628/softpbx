//! Switch behavior at the edges: refusal, cancellation, unknown calls.

use call::{Device, Output, Switch, SwitchConfig};
use sip_stack::digest::{expected_response, Credentials};
use sip_stack::{make_response, with_tag};
use sip_syntax::{Header, Message, Method, Request, Response};

fn switch() -> Switch {
    Switch::new(SwitchConfig {
        realm: "softpbx".to_string(),
        pbx_uri: "sip:192.0.2.10".to_string(),
        pbx_host: "192.0.2.10:5060".to_string(),
        pbx_contact: "<sip:192.0.2.10:5060>".to_string(),
        rtp_host: "192.0.2.10".to_string(),
        rtp_port_base: 10_000,
        rtp_ports: 100,
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

fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

/// Registers a device the honest way: get challenged, answer.
fn register(switch: &mut Switch, number: &str, secret: &str, contact: &str, now_ms: u64) {
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
    let outputs = switch.handle(Message::Request(request), now_ms, None);
    let challenge = response_of(&outputs, 401);
    let value = header(&challenge.headers, "WWW-Authenticate").unwrap();
    let nonce = &value[value.find("nonce=\"").unwrap() + 7..];
    let nonce = &nonce[..nonce.find('"').unwrap()];
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
        headers: {
            let mut headers = vec![Header {
                name: "Authorization".to_string(),
                value: format!(
                    "Digest username=\"{number}\", realm=\"softpbx\", nonce=\"{nonce}\", \
                     uri=\"sip:192.0.2.10\", response=\"{response}\""
                ),
            }];
            headers.extend(vec![
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
            ]);
            headers
        },
        method: Method::Register,
        uri: "sip:192.0.2.10".to_string(),
        body: Vec::new(),
    };
    let outputs = switch.handle(Message::Request(request), now_ms, None);
    assert_eq!(
        response_of(&outputs, 200).status,
        200,
        "registration of {number}"
    );
}

fn invite(from: &str, to: &str, call_id: &str) -> Request {
    Request {
        method: Method::Invite,
        uri: format!("sip:{to}@192.0.2.10"),
        headers: vec![
            Header {
                name: "Via".to_string(),
                value: format!("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{call_id}"),
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
        ],
        body: Vec::new(),
    }
}

fn cancel_of(invite: &Request) -> Request {
    let mut request = invite.clone();
    request.method = Method::Cancel;
    for header in &mut request.headers {
        if header.name == "CSeq" {
            header.value = "1 CANCEL".to_string();
        }
    }
    request
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

fn call_logs(outputs: &[Output]) -> Vec<String> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::CallLog(line) => Some(line.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn unregistered_caller_gets_403() {
    let mut switch = switch();
    let outputs = switch.handle(
        Message::Request(invite("6666", "1002", "call-auth")),
        0,
        None,
    );
    assert_eq!(
        response_of(&outputs, 403).status,
        403,
        "strangers cannot dial"
    );
    assert_eq!(switch.active_calls(), 0);
}

#[test]
fn unknown_callee_gets_404() {
    let mut switch = switch();
    register(
        &mut switch,
        "1001",
        "change-me",
        "<sip:alice@192.0.2.1:5060>",
        0,
    );
    let outputs = switch.handle(
        Message::Request(invite("1001", "9999", "call-404")),
        0,
        None,
    );
    assert_eq!(response_of(&outputs, 404).status, 404);
    assert_eq!(switch.active_calls(), 0);
    assert!(!call_logs(&outputs).is_empty(), "the failed call is logged");
}

#[test]
fn unknown_method_gets_405_with_allow() {
    let mut switch = switch();
    let mut request = invite("1001", "1002", "call-405");
    request.method = Method::Other("PUBLISH".to_string());
    let outputs = switch.handle(Message::Request(request), 0, None);
    let response = response_of(&outputs, 405);
    let allow = header(&response.headers, "Allow").expect("Allow header");
    assert_eq!(allow, call::ALLOW);
}

#[test]
fn options_is_answered() {
    let mut switch = switch();
    let mut request = invite("1001", "1002", "call-opt");
    request.method = Method::Options;
    let outputs = switch.handle(Message::Request(request), 0, None);
    assert_eq!(response_of(&outputs, 200).status, 200);
}

#[test]
fn cancel_while_ringing_tears_down_both_legs() {
    let mut switch = switch();
    register(
        &mut switch,
        "1001",
        "change-me",
        "<sip:alice@192.0.2.1:5060>",
        0,
    );
    register(
        &mut switch,
        "1002",
        "bob-secret",
        "<sip:bob@192.0.2.2:5060>",
        0,
    );

    // Alice calls Bob; Bob's phone rings.
    let alice_invite = invite("1001", "1002", "call-cancel");
    let outputs = switch.handle(Message::Request(alice_invite.clone()), 0, None);
    let callee_invite = (*requests_of(&outputs, Method::Invite)
        .first()
        .expect("INVITE toward the callee"))
    .clone();
    let ringing = tagged_response(&callee_invite, 180, "Ringing");
    let outputs = switch.handle(Message::Response(ringing), 10, None);
    assert_eq!(
        response_of(&outputs, 180).status,
        180,
        "rings the caller too"
    );

    // Alice changes her mind.
    let outputs = switch.handle(Message::Request(cancel_of(&alice_invite)), 20, None);
    assert_eq!(
        response_of(&outputs, 200).status,
        200,
        "CANCEL acknowledged"
    );
    assert_eq!(
        response_of(&outputs, 487).status,
        487,
        "the INVITE is rejected"
    );
    let cancels = requests_of(&outputs, Method::Cancel);
    assert_eq!(cancels.len(), 1, "the callee leg is cancelled too");

    // Call is gone and logged as cancelled.
    assert_eq!(switch.active_calls(), 0);
    let logs = call_logs(&outputs);
    assert_eq!(logs.len(), 1);
    assert!(logs[0].contains("\"result\":\"cancelled\""), "{}", logs[0]);
}

#[test]
fn bye_without_a_call_gets_481() {
    let mut switch = switch();
    let mut request = invite("1001", "1002", "call-bye");
    request.method = Method::Bye;
    let outputs = switch.handle(Message::Request(request), 0, None);
    assert_eq!(response_of(&outputs, 481).status, 481);
}

#[test]
fn invite_retransmission_repeats_the_last_response() {
    let mut switch = switch();
    register(
        &mut switch,
        "1001",
        "change-me",
        "<sip:alice@192.0.2.1:5060>",
        0,
    );
    register(
        &mut switch,
        "1002",
        "bob-secret",
        "<sip:bob@192.0.2.2:5060>",
        0,
    );
    let alice_invite = invite("1001", "1002", "call-retry");
    let _ = switch.handle(Message::Request(alice_invite.clone()), 0, None);
    let outputs = switch.handle(Message::Request(alice_invite), 500, None);
    assert_eq!(
        response_of(&outputs, 100).status,
        100,
        "the retransmission gets our last response again"
    );
    assert!(
        requests_of(&outputs, Method::Invite).is_empty(),
        "and no new call is started"
    );
}

fn tagged_response(request: &Request, status: u16, reason: &str) -> Response {
    let mut response = make_response(request, status, reason);
    for header in &mut response.headers {
        if header.name == "To" {
            header.value = with_tag(&header.value, "callee1");
        }
    }
    response
}
