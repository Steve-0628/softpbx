//! Phase 2 "done when" (docs/08): timer-driven retransmission proven in
//! simulation, and the same seed producing an identical trace.

use engine_sim::{Event, World};
use sip_stack::{Action, ClientTransaction, Timer};
use sip_syntax::{parse_message, serialize_message, Header, Message, Method, Request, Response};

const PBX: &str = "pbx";
const ALICE: &str = "alice";

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

fn response_bytes(status: u16, method: &str, branch: &str) -> Vec<u8> {
    let response = Response {
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
    };
    serialize_message(&Message::Response(response))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Outcome {
    /// Times at which the transaction asked for a send.
    sends: Vec<u64>,
    /// Times at which the transaction gave up.
    timeouts: Vec<u64>,
    /// Statuses delivered to the transaction user, in order.
    delivered: Vec<u16>,
}

fn timer_of(name: &str) -> Timer {
    match name {
        "A" => Timer::A,
        "B" => Timer::B,
        "D" => Timer::D,
        "E" => Timer::E,
        "F" => Timer::F,
        "G" => Timer::G,
        "H" => Timer::H,
        "I" => Timer::I,
        "J" => Timer::J,
        other => panic!("unknown timer {other}"),
    }
}

fn name_of(timer: Timer) -> String {
    match timer {
        Timer::A => "A".to_string(),
        Timer::B => "B".to_string(),
        Timer::D => "D".to_string(),
        Timer::E => "E".to_string(),
        Timer::F => "F".to_string(),
        Timer::G => "G".to_string(),
        Timer::H => "H".to_string(),
        Timer::I => "I".to_string(),
        Timer::J => "J".to_string(),
    }
}

fn apply(world: &mut World, outcome: &mut Outcome, actions: Vec<Action>) {
    for action in actions {
        match action {
            Action::Send(message) => {
                outcome.sends.push(world.now_ms());
                let bytes = serialize_message(&message);
                world.send(PBX, ALICE, bytes);
            }
            Action::DeliverResponse(response) => {
                outcome.delivered.push(response.status);
                world.log(format!("deliver {} to call layer", response.status));
            }
            Action::DeliverRequest(_) => world.log("deliver request to call layer"),
            Action::Timeout => {
                outcome.timeouts.push(world.now_ms());
                world.log("transaction timeout");
            }
            Action::Done => world.log("transaction done"),
        }
    }
}

/// Keeps the transaction's next timer armed; runs the world to quiescence.
fn drive(world: &mut World, tx: &mut ClientTransaction, initial: Vec<Action>) -> Outcome {
    let mut outcome = Outcome::default();
    apply(world, &mut outcome, initial);
    sync_timers(world, tx);
    while let Some(event) = world.next_event() {
        match event {
            Event::Timer { name } => {
                let actions = tx.on_timer(timer_of(&name), world.now_ms());
                apply(world, &mut outcome, actions);
            }
            Event::Datagram { data, .. } => {
                if let Ok(Message::Response(response)) = parse_message(&data) {
                    let actions = tx.on_response(response, world.now_ms());
                    apply(world, &mut outcome, actions);
                }
            }
        }
        sync_timers(world, tx);
    }
    outcome
}

fn sync_timers(world: &mut World, tx: &ClientTransaction) {
    for name in ["A", "B", "D", "E", "F"] {
        world.disarm(name);
    }
    if let Some((due, timer)) = tx.next_timer() {
        world.arm(name_of(timer), due);
    }
}

#[test]
fn lost_responses_retransmit_on_schedule() {
    let mut world = World::with_seed(0x5EED);
    world.net.loss = 1.0; // nothing gets through
    let (mut tx, initial) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    let outcome = drive(&mut world, &mut tx, initial);

    // Timer A at T1 doubling, give up at 64·T1 (RFC 3261 §17.1.1).
    assert_eq!(
        outcome.sends,
        vec![0, 500, 1_500, 3_500, 7_500, 15_500, 31_500],
        "retransmission schedule"
    );
    assert_eq!(outcome.timeouts, vec![32_000]);
    assert!(outcome.delivered.is_empty());
}

#[test]
fn provisional_response_stops_retransmission() {
    let mut world = World::with_seed(0x5EED);
    let (mut tx, initial) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);

    world.net.delay_ms = 100;
    world.send(ALICE, PBX, response_bytes(180, "INVITE", "z9hG4bK1"));
    world.net.delay_ms = 200;
    world.send(ALICE, PBX, response_bytes(200, "INVITE", "z9hG4bK1"));
    world.net.delay_ms = 0;

    let outcome = drive(&mut world, &mut tx, initial);
    assert_eq!(outcome.sends, vec![0], "no retransmission after a response");
    assert_eq!(outcome.delivered, vec![180, 200]);
    assert!(outcome.timeouts.is_empty());
}

#[test]
fn non_invite_retransmits_capped_at_t2() {
    let mut world = World::with_seed(0x5EED);
    world.net.loss = 1.0;
    let (mut tx, initial) = ClientTransaction::new(request(Method::Options, "z9hG4bK2"), 0);
    let outcome = drive(&mut world, &mut tx, initial);

    // Timer E: T1 doubling, capped at T2 = 4s; Timer F gives up at 64·T1.
    assert_eq!(
        outcome.sends,
        vec![0, 500, 1_500, 3_500, 7_500, 11_500, 15_500, 19_500, 23_500, 27_500, 31_500],
        "retransmission schedule with T2 cap"
    );
    assert_eq!(outcome.timeouts, vec![32_000]);
}

/// The scenario used for determinism checks: a lossy path with responses
/// arriving at odd times.
fn lossy_scenario(seed: u64) -> (Outcome, Vec<String>) {
    let mut world = World::with_seed(seed);
    world.net.loss = 0.3;
    let (mut tx, initial) = ClientTransaction::new(request(Method::Invite, "z9hG4bK1"), 0);
    apply(&mut world, &mut Outcome::default(), initial);
    sync_timers(&mut world, &tx);

    world.net.delay_ms = 130;
    world.send(ALICE, PBX, response_bytes(180, "INVITE", "z9hG4bK1"));
    world.net.delay_ms = 2_400;
    world.send(ALICE, PBX, response_bytes(183, "INVITE", "z9hG4bK1"));
    world.net.delay_ms = 3_100;
    world.send(ALICE, PBX, response_bytes(486, "INVITE", "z9hG4bK1"));
    world.net.delay_ms = 0;

    let outcome = drive(&mut world, &mut tx, vec![]);
    (outcome, world.trace().to_vec())
}

#[test]
fn same_seed_produces_identical_trace() {
    let (outcome_a, trace_a) = lossy_scenario(0x5EED);
    let (outcome_b, trace_b) = lossy_scenario(0x5EED);

    assert!(
        trace_a.len() > 10,
        "the trace should actually record events"
    );
    assert_eq!(trace_a, trace_b, "same seed must give the identical trace");
    assert_eq!(outcome_a, outcome_b, "and the identical outcome");

    // Sanity: this scenario is not trivial (some packets survive the 30% loss).
    assert!(!outcome_a.delivered.is_empty());
}

#[test]
fn world_orders_events_deterministically() {
    let mut world = World::with_seed(1);
    world.arm("late", 300);
    world.arm("early", 100);
    world.arm("late", 200); // replaces the earlier "late"
    let fired: Vec<u64> =
        std::iter::from_fn(|| world.next_event().map(|_| world.now_ms())).collect();
    assert_eq!(fired, vec![100, 200]);
}
