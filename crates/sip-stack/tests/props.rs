//! Property tests (docs/04 §3): for any sequence of responses and timer
//! firings, transactions never panic and always reach `Terminated`.
//!
//! Contract under test: a server transaction only ends once the call layer
//! sends a final response (RFC 3261 gives the server transaction no timeout of
//! its own), so the generator always finishes with one.

use proptest::prelude::*;
use sip_stack::{ClientState, ClientTransaction, ServerState, ServerTransaction};
use sip_syntax::{Header, Method, Request, Response};

fn request(method: Method, branch: &str) -> Request {
    let headers = vec![
        Header {
            name: "Via".to_string(),
            value: format!("SIP/2.0/UDP 192.0.2.1:5060;branch={branch}"),
        },
        Header {
            name: "CSeq".to_string(),
            value: format!("1 {}", method.as_str()),
        },
    ];
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
        headers: vec![
            Header {
                name: "Via".to_string(),
                value: format!("SIP/2.0/UDP 192.0.2.1:5060;branch={branch}"),
            },
            Header {
                name: "CSeq".to_string(),
                value: format!("1 {method}"),
            },
        ],
        body: Vec::new(),
    }
}

/// Fire whatever timer is next until the transaction has none left.
fn run_timers_out(tx: &mut ClientTransaction, mut now: u64) -> u64 {
    for _ in 0..16 {
        match tx.next_timer() {
            Some((due, timer)) => {
                now = now.max(due);
                let _ = tx.on_timer(timer, now);
            }
            None => break,
        }
    }
    now
}

fn run_timers_out_server(tx: &mut ServerTransaction, mut now: u64) -> u64 {
    for _ in 0..16 {
        match tx.next_timer() {
            Some((due, timer)) => {
                now = now.max(due);
                let _ = tx.on_timer(timer, now);
            }
            None => break,
        }
    }
    now
}

proptest! {
    #[test]
    fn client_invite_always_terminates(
        statuses in proptest::collection::vec(any::<u16>(), 0..32),
    ) {
        let (mut tx, _) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
        let mut now = 0u64;
        for status in statuses {
            now += 10;
            let _ = tx.on_response(response(status % 600 + 100, "INVITE", "z9hG4bK1"), now);
            if let Some((due, timer)) = tx.next_timer() {
                now = now.max(due);
                let _ = tx.on_timer(timer, now);
            }
        }
        run_timers_out(&mut tx, now);
        prop_assert_eq!(tx.state(), ClientState::Terminated);
    }

    #[test]
    fn client_non_invite_always_terminates(
        statuses in proptest::collection::vec(any::<u16>(), 0..32),
    ) {
        let (mut tx, _) = ClientTransaction::new(request(Method::Options, "z9hG4bK2"), 0);
        let mut now = 0u64;
        for status in statuses {
            now += 10;
            let _ = tx.on_response(response(status % 600 + 100, "OPTIONS", "z9hG4bK2"), now);
            if let Some((due, timer)) = tx.next_timer() {
                now = now.max(due);
                let _ = tx.on_timer(timer, now);
            }
        }
        run_timers_out(&mut tx, now);
        prop_assert_eq!(tx.state(), ClientState::Terminated);
    }

    #[test]
    fn server_invite_always_terminates(
        statuses in proptest::collection::vec(any::<u16>(), 0..32),
    ) {
        let (mut tx, _) = ServerTransaction::new(request(Method::Invite, "z9hG4bK3"), 0);
        let mut now = 0u64;
        for status in statuses {
            now += 10;
            let _ = tx.on_response_from_user(response(status % 600 + 100, "INVITE", "z9hG4bK3"), now);
            let _ = tx.on_request(&request(Method::Invite, "z9hG4bK3"));
            if status % 3 == 0 {
                let _ = tx.on_ack(now);
            }
        }
        // The call layer is obliged to eventually answer; it always does.
        now += 10;
        let _ = tx.on_response_from_user(response(486, "INVITE", "z9hG4bK3"), now);
        run_timers_out_server(&mut tx, now);
        prop_assert_eq!(tx.state(), ServerState::Terminated);
    }
}
