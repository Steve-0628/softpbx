//! Registration-mode trunks, including the MikoPBX incoming/outgoing account
//! procedure. All time and packet loss are controlled by the test.
use call::{
    Action, Device, Interface, Network, Output, Rule, Switch, SwitchConfig, TrunkAuth, TrunkConfig,
    TrunkRegistration,
};
use sip_stack::{digest, make_response};
use sip_syntax::{Header, Message, Method, Request, Response};

fn h(name: &str, value: impl ToString) -> Header {
    Header {
        name: name.into(),
        value: value.to_string(),
    }
}
fn header<'a>(headers: &'a [Header], name: &str) -> &'a str {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
        .unwrap_or("")
}
fn config(role: TrunkRegistration) -> SwitchConfig {
    SwitchConfig {
        realm: "softpbx".into(),
        interfaces: vec![Interface {
            network: Network::parse("0.0.0.0/0").unwrap(),
            sip: "192.0.2.10:5060".parse().unwrap(),
            rtp: "192.0.2.10".parse().unwrap(),
        }],
        rtp_port_base: 10000,
        rtp_ports: 20,
        routing: vec![Rule {
            pattern: "3*".into(),
            action: Action::Trunk("remote".into()),
            strip: None,
        }],
        trunks: vec![TrunkConfig {
            name: "remote".into(),
            peer: Some("192.0.2.20:5060".parse().unwrap()),
            registration: role,
            outbound: Some(TrunkAuth {
                username: "SIP-TRUNK-test".into(),
                secret: "password".into(),
            }),
            inbound: Some(TrunkAuth {
                username: "SIP-TRUNK-test".into(),
                secret: "password".into(),
            }),
        }],
        devices: vec![Device {
            number: "1001".into(),
            name: "Alice".into(),
            secret: "phone-secret".into(),
        }],
    }
}
fn outgoing() -> Switch {
    Switch::new(config(TrunkRegistration::Outgoing { expires_s: 3600 }))
}
fn requests(outputs: Vec<Output>) -> Vec<Request> {
    outputs
        .into_iter()
        .filter_map(|o| match o {
            Output::Send(Message::Request(r)) => Some(r),
            _ => None,
        })
        .collect()
}
fn response(outputs: Vec<Output>, status: u16) -> Response {
    outputs
        .into_iter()
        .find_map(|o| match o {
            Output::Send(Message::Response(r)) if r.status == status => Some(r),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {status}"))
}
fn timer(switch: &mut Switch, now: u64) -> Vec<Output> {
    let (name, due) = switch
        .timers()
        .into_iter()
        .min_by_key(|(_, due)| *due)
        .unwrap();
    assert!(due <= now, "{due} > {now}");
    switch.on_timer(&name, now)
}
fn challenge(request: &Request, status: u16) -> Response {
    let mut r = make_response(request, status, "Authenticate");
    r.headers.push(h(
        if status == 407 {
            "Proxy-Authenticate"
        } else {
            "WWW-Authenticate"
        },
        "Digest realm=\"mikopbx\", nonce=\"random\", algorithm=MD5, qop=\"auth\", opaque=\"token\"",
    ));
    r
}
fn start(switch: &mut Switch) -> Request {
    requests(timer(switch, 0)).remove(0)
}
fn feed_response(switch: &mut Switch, r: Response, now: u64) -> Vec<Output> {
    switch.handle(Message::Response(r), now, None)
}
fn authenticate(switch: &mut Switch, mut request: Request, secret: &str, now: u64) -> Response {
    let challenged = response(
        switch.handle(Message::Request(request.clone()), now, None),
        401,
    );
    let challenge =
        digest::parse_challenge(header(&challenged.headers, "WWW-Authenticate")).unwrap();
    let username = call::number_from_request(&request).unwrap();
    request.headers.push(h(
        "Authorization",
        digest::authorization_value(
            &challenge,
            &username,
            secret,
            request.method.as_str(),
            &request.uri,
        ),
    ));
    // This helper is for REGISTER. INVITEs are tested separately below.
    response(switch.handle(Message::Request(request), now, None), 200)
}
fn register(number: &str, contact: &str, cseq: u64, expires: u64) -> Request {
    Request {
        method: Method::Register,
        uri: "sip:192.0.2.10:5060".into(),
        headers: vec![
            h(
                "Via",
                format!("SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-reg-{number}-{cseq}"),
            ),
            h("From", format!("<sip:{number}@192.0.2.10>;tag=peer")),
            h("To", format!("<sip:{number}@192.0.2.10>")),
            h("Call-ID", format!("reg-{number}")),
            h("CSeq", format!("{cseq} REGISTER")),
            h("Contact", contact),
            h("Expires", expires),
        ],
        body: vec![],
    }
}
fn invite(call_id: &str) -> Request {
    Request {
        method: Method::Invite,
        uri: "sip:3001@192.0.2.10".into(),
        headers: vec![
            h(
                "Via",
                format!("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{call_id}"),
            ),
            h("From", "<sip:1001@192.0.2.10>;tag=phone"),
            h("To", "<sip:3001@192.0.2.10>"),
            h("Call-ID", call_id),
            h("CSeq", "1 INVITE"),
            h("Contact", "<sip:1001@192.0.2.1:5060>"),
            h("Max-Forwards", "70"),
        ],
        body: vec![],
    }
}

#[test]
fn outgoing_digest_refresh_and_identity() {
    for status in [401, 407] {
        let mut s = outgoing();
        let first = start(&mut s);
        assert_eq!(first.uri, "sip:192.0.2.20:5060");
        assert_eq!(
            header(&first.headers, "To"),
            "<sip:SIP-TRUNK-test@192.0.2.20:5060>"
        );
        assert_eq!(
            header(&first.headers, "Contact"),
            "<sip:SIP-TRUNK-test@192.0.2.10:5060>"
        );
        let retry = requests(feed_response(&mut s, challenge(&first, status), 10)).remove(0);
        assert_eq!(
            header(&retry.headers, "Call-ID"),
            header(&first.headers, "Call-ID")
        );
        assert_eq!(header(&retry.headers, "CSeq"), "2 REGISTER");
        assert_ne!(header(&retry.headers, "Via"), header(&first.headers, "Via"));
        let auth = header(
            &retry.headers,
            if status == 407 {
                "Proxy-Authorization"
            } else {
                "Authorization"
            },
        );
        assert!(auth.contains("opaque=\"token\""));
        let credentials = digest::parse_authorization(auth).unwrap();
        assert!(digest::verify(&credentials, "password", "REGISTER"));
        assert_eq!(credentials.qop.as_deref(), Some("auth"));
        let mut ok = make_response(&retry, 200, "OK");
        ok.headers.push(h("Expires", 3600));
        ok.headers.push(h(
            "Contact",
            format!("{};expires=120", header(&retry.headers, "Contact")),
        ));
        assert!(feed_response(&mut s, ok.clone(), 20).is_empty());
        assert!(s.trunk_registered("remote", 21));
        assert!(!s.trunk_registered("remote", 120020));
        assert!(
            feed_response(&mut s, ok, 30).is_empty(),
            "duplicate final ignored"
        );
        assert_eq!(s.timers()[0].1, 96020);
        let refresh = requests(timer(&mut s, 96020)).remove(0);
        assert_eq!(header(&refresh.headers, "CSeq"), "3 REGISTER");
        assert_eq!(
            header(&refresh.headers, "Call-ID"),
            header(&first.headers, "Call-ID")
        );
        // A registrar may reuse its nonce across refreshes. A fresh cnonce
        // prevents the new request from looking like a nonce-count replay.
        let refreshed =
            requests(feed_response(&mut s, challenge(&refresh, status), 96021)).remove(0);
        let refreshed_auth = digest::parse_authorization(header(
            &refreshed.headers,
            if status == 407 {
                "Proxy-Authorization"
            } else {
                "Authorization"
            },
        ))
        .unwrap();
        assert_ne!(refreshed_auth.cnonce, credentials.cnonce);
        assert!(digest::verify(&refreshed_auth, "password", "REGISTER"));
    }
}

#[test]
fn lost_register_retransmits_then_recovers_after_timeout() {
    let mut s = outgoing();
    let first = start(&mut s);
    assert_eq!(requests(timer(&mut s, 500)), vec![first.clone()]);
    let mut now = 500;
    while now < 32000 {
        now = s.timers()[0].1;
        let out = timer(&mut s, now);
        if now < 32000 {
            assert_eq!(requests(out), vec![first.clone()]);
        }
    }
    assert!(!s.trunk_registered("remote", now));
    assert_eq!(s.timers()[0].1, 62000);
    let next = requests(timer(&mut s, 62000)).remove(0);
    assert_eq!(header(&next.headers, "CSeq"), "2 REGISTER");
}

#[test]
fn interval_too_brief_and_failure_backoff() {
    let mut s = outgoing();
    let first = start(&mut s);
    let mut brief = make_response(&first, 423, "Interval Too Brief");
    brief.headers.push(h("Min-Expires", 7200));
    let retry = requests(feed_response(&mut s, brief, 10)).remove(0);
    assert_eq!(header(&retry.headers, "Expires"), "7200");
    let mut unavailable = make_response(&retry, 503, "Unavailable");
    unavailable.headers.push(h("Retry-After", "60;duration=60"));
    assert!(feed_response(&mut s, unavailable, 20).is_empty());
    assert_eq!(s.timers()[0].1, 60020);
    assert_eq!(requests(timer(&mut s, 60020)).len(), 1);
}

#[test]
fn authentication_failure_is_bounded_and_old_responses_are_ignored() {
    let mut s = outgoing();
    let mut request = start(&mut s);
    let old = challenge(&request, 401);
    for _ in 0..2 {
        request = requests(feed_response(&mut s, challenge(&request, 401), 0)).remove(0);
    }
    assert!(feed_response(&mut s, challenge(&request, 401), 0).is_empty());
    assert_eq!(s.timers()[0].1, 30000);
    assert!(feed_response(&mut s, old, 1).is_empty());
    assert_eq!(s.timers()[0].1, 30000);
}

#[test]
fn incoming_registration_routes_to_learned_contact_and_expires() {
    let mut cfg = config(TrunkRegistration::Incoming);
    cfg.trunks[0].peer = None;
    let mut s = Switch::new(cfg);
    authenticate(
        &mut s,
        register("1001", "<sip:1001@192.0.2.1:5060>", 1, 3600),
        "phone-secret",
        0,
    );
    response(
        s.handle(Message::Request(invite("before-registration")), 0, None),
        480,
    );
    // MikoPBX supplies a trunk AOR, independent of any extension or caller ID.
    let request = register(
        "SIP-TRUNK-test",
        "<sip:arbitrary-contact@198.51.100.20:5072>",
        1,
        120,
    );
    authenticate(&mut s, request, "password", 0);
    assert!(s.trunk_registered("remote", 1));
    assert_eq!(
        s.registered(1),
        vec!["1001"],
        "trunk must not become a local extension"
    );
    let out = requests(s.handle(Message::Request(invite("registered")), 1, None));
    assert_eq!(out[0].uri, "sip:3001@198.51.100.20:5072");
    response(
        s.handle(Message::Request(invite("expired")), 120001, None),
        480,
    );
}

#[test]
fn two_pbx_registration_exchange_and_trunk_invite_authentication() {
    let mut client = outgoing();
    let mut cfg = config(TrunkRegistration::Incoming);
    cfg.interfaces[0].sip = "192.0.2.20:5060".parse().unwrap();
    cfg.routing.clear();
    cfg.devices = vec![Device {
        number: "3001".into(),
        name: "Bob".into(),
        secret: "bob".into(),
    }];
    let mut server = Switch::new(cfg);
    let first = start(&mut client);
    let challenge = response(server.handle(Message::Request(first), 0, None), 401);
    let retry = requests(feed_response(&mut client, challenge, 1)).remove(0);
    let ok = response(server.handle(Message::Request(retry), 2, None), 200);
    assert!(feed_response(&mut client, ok, 3).is_empty());
    assert!(client.trunk_registered("remote", 3));
    assert!(server.trunk_registered("remote", 3));
    authenticate(
        &mut client,
        register("1001", "<sip:1001@192.0.2.1:5060>", 1, 3600),
        "phone-secret",
        4,
    );
    authenticate(
        &mut server,
        register("3001", "<sip:3001@192.0.2.30:5090>", 1, 3600),
        "bob",
        4,
    );
    let call = requests(client.handle(Message::Request(invite("site-call")), 5, None)).remove(0);
    let challenged = response(server.handle(Message::Request(call), 6, None), 401);
    let retry = requests(feed_response(&mut client, challenged, 7))
        .into_iter()
        .find(|r| r.method == Method::Invite)
        .unwrap();
    let ringing = requests(server.handle(Message::Request(retry), 8, None));
    assert_eq!(ringing[0].uri, "sip:3001@192.0.2.30:5090");
    let mut answer = make_response(&ringing[0], 200, "OK");
    answer
        .headers
        .push(h("Contact", "<sip:3001@192.0.2.30:5090>"));
    let toward_client = response(feed_response(&mut server, answer, 9), 200);
    response(feed_response(&mut client, toward_client, 10), 200);
    assert_eq!(
        client.call_state("site-call"),
        Some(call::CallState::Answered)
    );
}

#[test]
fn incoming_registration_rejects_wrong_credentials_and_unregisters() {
    let mut s = Switch::new(config(TrunkRegistration::Incoming));
    let mut req = register("SIP-TRUNK-test", "<sip:trunk@192.0.2.20:5060>", 1, 120);
    let ch = response(s.handle(Message::Request(req.clone()), 0, None), 401);
    let ch = digest::parse_challenge(header(&ch.headers, "WWW-Authenticate")).unwrap();
    req.headers.push(h(
        "Authorization",
        digest::authorization_value(&ch, "SIP-TRUNK-test", "wrong", "REGISTER", &req.uri),
    ));
    response(s.handle(Message::Request(req.clone()), 1, None), 401);
    assert!(!s.trunk_registered("remote", 1));
    req.headers.retain(|h| h.name != "Authorization");
    authenticate(&mut s, req, "password", 2);
    assert!(s.trunk_registered("remote", 3));
    authenticate(&mut s, register("SIP-TRUNK-test", "*", 2, 0), "password", 4);
    assert!(!s.trunk_registered("remote", 5));
}

#[test]
fn outgoing_uses_interface_for_peer_and_static_trunks_do_not_register() {
    let mut cfg = config(TrunkRegistration::Outgoing { expires_s: 3600 });
    cfg.interfaces.push(Interface {
        network: Network::parse("192.0.2.20/32").unwrap(),
        sip: "198.51.100.1:5090".parse().unwrap(),
        rtp: "198.51.100.1".parse().unwrap(),
    });
    let r = start(&mut Switch::new(cfg));
    assert!(header(&r.headers, "Via").contains("198.51.100.1:5090"));
    assert!(header(&r.headers, "Contact").contains("198.51.100.1:5090"));
    assert!(Switch::new(config(TrunkRegistration::None))
        .timers()
        .is_empty());
}

#[test]
fn outgoing_matches_its_own_contact_in_a_shared_account() {
    let mut s = outgoing();
    let req = start(&mut s);
    let mut ok = make_response(&req, 200, "OK");
    ok.headers.push(h(
        "m",
        format!(
            "<sip:other@192.0.2.30>;expires=1, {};expires=90",
            header(&req.headers, "Contact")
        ),
    ));
    feed_response(&mut s, ok, 0);
    assert!(s.trunk_registered("remote", 89999));
    assert!(!s.trunk_registered("remote", 90000));
    assert_eq!(s.timers()[0].1, 72000);
}

#[test]
fn outgoing_does_not_claim_success_for_another_contact() {
    let mut s = outgoing();
    let req = start(&mut s);
    let mut ok = make_response(&req, 200, "OK");
    ok.headers
        .push(h("Contact", "<sip:other@192.0.2.30>;expires=3600"));
    feed_response(&mut s, ok, 0);
    assert!(!s.trunk_registered("remote", 1));
    assert_eq!(s.timers()[0].1, 30000);
}

#[test]
fn incoming_negotiates_minimum_expiry_and_rejects_old_cseq() {
    let mut s = Switch::new(config(TrunkRegistration::Incoming));
    let mut req = register("SIP-TRUNK-test", "<sip:trunk@192.0.2.20:5060>", 1, 30);
    let ch = response(s.handle(Message::Request(req.clone()), 0, None), 401);
    let ch = digest::parse_challenge(header(&ch.headers, "WWW-Authenticate")).unwrap();
    req.headers.push(h(
        "Authorization",
        digest::authorization_value(&ch, "SIP-TRUNK-test", "password", "REGISTER", &req.uri),
    ));
    let too_short = response(s.handle(Message::Request(req), 0, None), 423);
    assert_eq!(header(&too_short.headers, "Min-Expires"), "60");
    assert!(!s.trunk_registered("remote", 0));
    authenticate(
        &mut s,
        register("SIP-TRUNK-test", "<sip:trunk@192.0.2.20:5060>", 3, 120),
        "password",
        1,
    );
    let mut stale = register("SIP-TRUNK-test", "*", 2, 0);
    let ch = response(s.handle(Message::Request(stale.clone()), 2, None), 401);
    let ch = digest::parse_challenge(header(&ch.headers, "WWW-Authenticate")).unwrap();
    stale.headers.push(h(
        "Authorization",
        digest::authorization_value(&ch, "SIP-TRUNK-test", "password", "REGISTER", &stale.uri),
    ));
    response(s.handle(Message::Request(stale), 2, None), 500);
    assert!(s.trunk_registered("remote", 3));
}

#[test]
fn incoming_contact_expiry_duplicate_query_and_refresh() {
    let mut s = Switch::new(config(TrunkRegistration::Incoming));
    let mut req = register(
        "SIP-TRUNK-test",
        "<sip:trunk@192.0.2.20:5060>;expires=120",
        1,
        3600,
    );
    let ch = response(s.handle(Message::Request(req.clone()), 0, None), 401);
    let ch = digest::parse_challenge(header(&ch.headers, "WWW-Authenticate")).unwrap();
    req.headers.push(h(
        "Authorization",
        digest::authorization_value(&ch, "SIP-TRUNK-test", "password", "REGISTER", &req.uri),
    ));
    let ok = response(s.handle(Message::Request(req.clone()), 0, None), 200);
    assert_eq!(
        header(&ok.headers, "Contact"),
        "<sip:trunk@192.0.2.20:5060>;expires=120"
    );
    assert_eq!(
        response(s.handle(Message::Request(req), 1000, None), 200),
        ok
    );
    let mut query = register("SIP-TRUNK-test", "", 2, 0);
    query.headers.retain(|h| h.name != "Contact");
    let queried = authenticate(&mut s, query, "password", 1000);
    assert_eq!(
        header(&queried.headers, "Contact"),
        "<sip:trunk@192.0.2.20:5060>;expires=119"
    );
    authenticate(
        &mut s,
        register("SIP-TRUNK-test", "<sip:trunk@192.0.2.21:5070>", 3, 300),
        "password",
        2000,
    );
    assert!(s.trunk_registered("remote", 301999));
    assert!(!s.trunk_registered("remote", 302000));
}

#[test]
fn incoming_authorization_is_bound_to_register_uri() {
    let mut s = Switch::new(config(TrunkRegistration::Incoming));
    let mut req = register("SIP-TRUNK-test", "<sip:trunk@192.0.2.20:5060>", 1, 120);
    let ch = response(s.handle(Message::Request(req.clone()), 0, None), 401);
    let ch = digest::parse_challenge(header(&ch.headers, "WWW-Authenticate")).unwrap();
    req.headers.push(h(
        "Authorization",
        digest::authorization_value(&ch, "SIP-TRUNK-test", "password", "REGISTER", &req.uri),
    ));
    req.uri = "sip:other.example".into();
    response(s.handle(Message::Request(req), 1, None), 401);
    assert!(!s.trunk_registered("remote", 1));
}

#[test]
fn outgoing_matches_parsed_cseq_in_responses() {
    for cseq in ["1  REGISTER", "1\tREGISTER", "0001 REGISTER"] {
        let mut s = outgoing();
        let first = start(&mut s);
        let mut challenged = challenge(&first, 401);
        challenged
            .headers
            .iter_mut()
            .find(|h| h.name == "CSeq")
            .unwrap()
            .value = cseq.into();
        let retry = requests(feed_response(&mut s, challenged, 0)).remove(0);
        assert_eq!(header(&retry.headers, "CSeq"), "2 REGISTER");
        let mut ok = make_response(&retry, 200, "OK");
        ok.headers
            .iter_mut()
            .find(|h| h.name == "CSeq")
            .unwrap()
            .value = "2\tREGISTER".into();
        ok.headers.push(h(
            "Contact",
            format!("{};expires=120", header(&retry.headers, "Contact")),
        ));
        feed_response(&mut s, ok, 1);
        assert!(s.trunk_registered("remote", 2), "{cseq}");
    }
    for cseq in ["2 REGISTER", "1 INVITE", "bad REGISTER"] {
        let mut s = outgoing();
        let first = start(&mut s);
        let mut challenged = challenge(&first, 401);
        challenged
            .headers
            .iter_mut()
            .find(|h| h.name == "CSeq")
            .unwrap()
            .value = cseq.into();
        assert!(feed_response(&mut s, challenged, 0).is_empty(), "{cseq}");
        assert_eq!(
            s.timers()[0].1,
            500,
            "unmatched response must leave the transaction pending"
        );
    }
}

#[test]
fn outgoing_honors_long_retry_after_without_overflow() {
    for (value, expected_due) in [
        ("7200;duration=60", 7_200_010),
        ("18446744073709551615", u64::MAX),
    ] {
        let mut s = outgoing();
        let first = start(&mut s);
        let mut unavailable = make_response(&first, 503, "Unavailable");
        unavailable.headers.push(h("Retry-After", value));
        assert!(feed_response(&mut s, unavailable, 10).is_empty());
        assert_eq!(s.timers()[0].1, expected_due);
        let timer_name = s.timers()[0].0.clone();
        assert!(s.on_timer(&timer_name, expected_due - 1).is_empty());
    }
}
