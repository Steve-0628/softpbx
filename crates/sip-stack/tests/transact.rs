//! Transaction behavior: retransmission, timeouts, response matching, ACKs.
//! Time is passed in explicitly, so these tests need no simulator.

use sip_stack::ClientTransaction;
use sip_stack::{
    ack_for_non_2xx, make_response, Action, ClientState, ServerState, ServerTransaction, Timer,
    GIVE_UP_MS, T1_MS, T2_MS, T4_MS, TIMER_D_MS,
};
use sip_syntax::{Header, Message, Method, Request, Response};

fn headers(method: &str, branch: &str) -> Vec<Header> {
    vec![
        Header {
            name: "Via".to_string(),
            value: format!("SIP/2.0/UDP 192.0.2.1:5060;branch={branch}"),
        },
        Header {
            name: "From".to_string(),
            value: "<sip:alice@example.com>;tag=1".to_string(),
        },
        Header {
            name: "To".to_string(),
            value: "<sip:bob@example.com>".to_string(),
        },
        Header {
            name: "Call-ID".to_string(),
            value: "call-1".to_string(),
        },
        Header {
            name: "CSeq".to_string(),
            value: format!("1 {method}"),
        },
    ]
}

fn request(method: Method, branch: &str) -> Request {
    let headers = headers(method.as_str(), branch);
    Request {
        method,
        uri: "sip:bob@example.com".to_string(),
        headers,
        body: Vec::new(),
    }
}

fn response(status: u16, method: &str, branch: &str) -> Response {
    Response {
        status,
        reason: String::new(),
        headers: headers(method, branch),
        body: Vec::new(),
    }
}

fn sends(actions: &[Action]) -> Vec<&Message> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send(message) => Some(message),
            _ => None,
        })
        .collect()
}

fn value<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

// ----- client: INVITE -------------------------------------------------------

#[test]
fn invite_client_sends_request_first() {
    let (tx, actions) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    assert_eq!(tx.state(), ClientState::Calling);
    assert_eq!(sends(&actions).len(), 1);
    assert_eq!(tx.next_timer(), Some((T1_MS, Timer::A)));
}

#[test]
fn provisional_response_stops_retransmission() {
    let (mut tx, _) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    let actions = tx.on_response(response(180, "INVITE", "z9hG4bK1"), 100);
    assert!(matches!(actions[..], [Action::DeliverResponse(_)]));
    assert_eq!(tx.state(), ClientState::Proceeding);
    // Only the give-up timer remains: no more Timer A.
    assert_eq!(tx.next_timer(), Some((GIVE_UP_MS, Timer::B)));
}

#[test]
fn invite_client_delivers_2xx_and_terminates() {
    let (mut tx, _) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    let actions = tx.on_response(response(200, "INVITE", "z9hG4bK1"), 100);
    assert!(matches!(
        actions[..],
        [Action::DeliverResponse(_), Action::Done]
    ));
    assert_eq!(tx.state(), ClientState::Terminated);
    assert_eq!(tx.next_timer(), None);
}

#[test]
fn invite_client_acks_non_2xx_final() {
    let (mut tx, _) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    let mut final_response = response(486, "INVITE", "z9hG4bK1");
    final_response.headers[2].value = "<sip:bob@example.com>;tag=2".to_string();
    let actions = tx.on_response(final_response, 100);
    let [Action::Send(Message::Request(ack)), Action::DeliverResponse(_)] = &actions[..] else {
        panic!("expected ACK + delivery, got {actions:?}");
    };
    assert_eq!(ack.method, Method::Ack);
    assert_eq!(ack.uri, "sip:bob@example.com");
    assert_eq!(
        value(&ack.headers, "to"),
        Some("<sip:bob@example.com>;tag=2")
    ); // response's To
    assert_eq!(value(&ack.headers, "cseq"), Some("1 ACK"));
    assert_eq!(tx.state(), ClientState::Completed);
    // Waiting out Timer D now.
    assert_eq!(tx.next_timer(), Some((100 + TIMER_D_MS, Timer::D)));
}

#[test]
fn retransmitted_final_response_gets_reacked() {
    let (mut tx, _) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    let _ = tx.on_response(response(486, "INVITE", "z9hG4bK1"), 100);
    let actions = tx.on_response(response(486, "INVITE", "z9hG4bK1"), 200);
    let [Action::Send(Message::Request(ack))] = &actions[..] else {
        panic!("expected a retransmitted ACK, got {actions:?}");
    };
    assert_eq!(ack.method, Method::Ack);
}

#[test]
fn invite_client_times_out_on_b() {
    let (mut tx, _) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    let actions = tx.on_timer(Timer::B, GIVE_UP_MS);
    assert!(matches!(actions[..], [Action::Timeout, Action::Done]));
    assert_eq!(tx.state(), ClientState::Terminated);
}

#[test]
fn timer_a_doubles_each_retransmission() {
    let (mut tx, _) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    assert_eq!(tx.next_timer(), Some((500, Timer::A)));
    let _ = tx.on_timer(Timer::A, 500);
    assert_eq!(tx.next_timer(), Some((1_500, Timer::A)));
    let _ = tx.on_timer(Timer::A, 1_500);
    assert_eq!(tx.next_timer(), Some((3_500, Timer::A)));
    let _ = tx.on_timer(Timer::A, 3_500);
    assert_eq!(tx.next_timer(), Some((7_500, Timer::A)));
}

#[test]
fn timer_d_fires_after_completed() {
    let (mut tx, _) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    let _ = tx.on_response(response(486, "INVITE", "z9hG4bK1"), 100);
    let actions = tx.on_timer(Timer::D, 100 + TIMER_D_MS);
    assert_eq!(actions, vec![Action::Done]);
    assert_eq!(tx.state(), ClientState::Terminated);
}

#[test]
fn unmatched_responses_are_ignored() {
    let (mut tx, _) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    assert_eq!(
        tx.on_response(response(200, "INVITE", "z9hG4bK-other"), 100),
        vec![]
    );
    // CANCEL shares the INVITE branch but has its own CSeq method.
    assert_eq!(
        tx.on_response(response(200, "CANCEL", "z9hG4bK1"), 100),
        vec![]
    );
    assert_eq!(tx.state(), ClientState::Calling);
}

// ----- client: non-INVITE ---------------------------------------------------

#[test]
fn non_invite_client_retransmits_capped_at_t2() {
    let (mut tx, actions) = ClientTransaction::new(request(Method::Options, "z9hG4bK2"), 0);
    assert_eq!(sends(&actions).len(), 1);
    assert_eq!(tx.next_timer(), Some((500, Timer::E)));
    let mut due = 500;
    let mut interval = T1_MS;
    for _ in 0..6 {
        let _ = tx.on_timer(Timer::E, due);
        interval = (interval * 2).min(T2_MS);
        due += interval;
        assert_eq!(
            tx.next_timer(),
            Some((due, Timer::E)),
            "interval {interval}"
        );
    }
}

#[test]
fn non_invite_client_times_out_on_f() {
    let (mut tx, _) = ClientTransaction::new(request(Method::Options, "z9hG4bK2"), 0);
    let actions = tx.on_timer(Timer::F, GIVE_UP_MS);
    assert!(matches!(actions[..], [Action::Timeout, Action::Done]));
    assert_eq!(tx.state(), ClientState::Terminated);
}

#[test]
fn non_invite_final_response_terminates() {
    let (mut tx, _) = ClientTransaction::new(request(Method::Options, "z9hG4bK2"), 0);
    let actions = tx.on_response(response(200, "OPTIONS", "z9hG4bK2"), 100);
    assert!(matches!(
        actions[..],
        [Action::DeliverResponse(_), Action::Done]
    ));
    assert_eq!(tx.state(), ClientState::Terminated);
}

// ----- server: INVITE -------------------------------------------------------

#[test]
fn invite_server_sends_100_and_delivers() {
    let (tx, actions) = ServerTransaction::new(request(Method::Invite, "z9hG4bK3"), 0);
    let [Action::Send(Message::Response(response)), Action::DeliverRequest(_)] = &actions[..]
    else {
        panic!("expected 100 Trying + delivery, got {actions:?}");
    };
    assert_eq!(response.status, 100);
    assert_eq!(tx.state(), ServerState::Proceeding);
}

#[test]
fn duplicate_invite_retransmits_last_response() {
    let (mut tx, _) = ServerTransaction::new(request(Method::Invite, "z9hG4bK3"), 0);
    let _ = tx.on_response_from_user(response(180, "INVITE", "z9hG4bK3"), 100);
    let actions = tx.on_request(&request(Method::Invite, "z9hG4bK3"));
    let [Action::Send(Message::Response(resent))] = &actions[..] else {
        panic!("expected retransmission, got {actions:?}");
    };
    assert_eq!(resent.status, 180);
}

#[test]
fn invite_server_retransmits_non_2xx_until_ack() {
    let (mut tx, _) = ServerTransaction::new(request(Method::Invite, "z9hG4bK3"), 0);
    let actions = tx.on_response_from_user(response(486, "INVITE", "z9hG4bK3"), 100);
    assert!(matches!(&actions[..], [Action::Send(_)]));
    assert_eq!(tx.state(), ServerState::Completed);
    assert_eq!(tx.next_timer(), Some((100 + T1_MS, Timer::G)));

    // Timer G: retransmit, interval doubles to T2.
    let actions = tx.on_timer(Timer::G, 600);
    assert!(matches!(&actions[..], [Action::Send(_)]));
    assert_eq!(tx.next_timer(), Some((600 + 2 * T1_MS, Timer::G)));

    // ACK confirms; Timer I then ends it.
    let _ = tx.on_ack(700);
    assert_eq!(tx.state(), ServerState::Confirmed);
    assert_eq!(tx.next_timer(), Some((700 + T4_MS, Timer::I)));
    assert_eq!(tx.on_timer(Timer::I, 700 + T4_MS), vec![Action::Done]);
    assert_eq!(tx.state(), ServerState::Terminated);
}

#[test]
fn invite_server_gives_up_without_ack() {
    let (mut tx, _) = ServerTransaction::new(request(Method::Invite, "z9hG4bK3"), 0);
    let _ = tx.on_response_from_user(response(486, "INVITE", "z9hG4bK3"), 100);
    let actions = tx.on_timer(Timer::H, 100 + GIVE_UP_MS);
    assert_eq!(actions, vec![Action::Done]);
    assert_eq!(tx.state(), ServerState::Terminated);
}

#[test]
fn invite_server_2xx_terminates_transaction() {
    let (mut tx, _) = ServerTransaction::new(request(Method::Invite, "z9hG4bK3"), 0);
    let actions = tx.on_response_from_user(response(200, "INVITE", "z9hG4bK3"), 100);
    assert!(matches!(&actions[..], [Action::Send(_), Action::Done]));
    assert_eq!(tx.state(), ServerState::Terminated);
}

// ----- server: non-INVITE ---------------------------------------------------

#[test]
fn non_invite_server_retransmits_final_on_duplicate_until_j() {
    let (tx, actions) = ServerTransaction::new(request(Method::Options, "z9hG4bK4"), 0);
    assert!(matches!(&actions[..], [Action::DeliverRequest(_)]));
    let mut tx = tx;
    let _ = tx.on_response_from_user(response(200, "OPTIONS", "z9hG4bK4"), 100);
    assert_eq!(tx.state(), ServerState::Completed);
    assert_eq!(tx.next_timer(), Some((100 + GIVE_UP_MS, Timer::J)));

    let actions = tx.on_request(&request(Method::Options, "z9hG4bK4"));
    assert!(matches!(&actions[..], [Action::Send(_)]));

    assert_eq!(tx.on_timer(Timer::J, 100 + GIVE_UP_MS), vec![Action::Done]);
    assert_eq!(tx.state(), ServerState::Terminated);
}

// ----- helpers --------------------------------------------------------------

#[test]
fn make_response_echoes_required_headers() {
    let response = make_response(&request(Method::Invite, "z9hG4bK5"), 100, "Trying");
    let names: Vec<&str> = response.headers.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, ["Via", "From", "To", "Call-ID", "CSeq"]);
    assert_eq!(response.status, 100);
    assert_eq!(response.reason, "Trying");
}

#[test]
fn ack_for_non_2xx_shape() {
    let invite = request(Method::Invite, "z9hG4bK5");
    let mut final_response = response(603, "INVITE", "z9hG4bK5");
    final_response.headers[2].value = "<sip:bob@example.com>;tag=9".to_string();
    let ack = ack_for_non_2xx(&invite, &final_response);
    assert_eq!(ack.method, Method::Ack);
    assert_eq!(ack.uri, invite.uri);
    assert_eq!(
        value(&ack.headers, "to"),
        Some("<sip:bob@example.com>;tag=9")
    );
    assert!(ack.body.is_empty());
}
