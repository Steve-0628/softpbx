//! Call state machine: every transition is explicit and tested here.

use call::{transit, CallEvent, CallState, Command};

#[test]
fn happy_path() {
    let (state, commands) = transit(CallState::Offering, CallEvent::CalleeRinging);
    assert_eq!(state, CallState::Ringing);
    assert_eq!(commands, vec![Command::RingCaller]);

    let (state, commands) = transit(CallState::Ringing, CallEvent::CalleeAnswered);
    assert_eq!(state, CallState::Answered);
    assert_eq!(commands, vec![Command::AnswerCaller]);

    let (state, commands) = transit(CallState::Answered, CallEvent::CallerHungUp);
    assert_eq!(state, CallState::Terminating);
    assert_eq!(commands, vec![Command::ByeCallee, Command::CompleteCaller]);

    let (state, commands) = transit(CallState::Terminating, CallEvent::Teardown);
    assert_eq!(state, CallState::Terminated);
    assert_eq!(commands, vec![Command::Finish]);
}

#[test]
fn answered_directly_without_ringing() {
    let (state, commands) = transit(CallState::Offering, CallEvent::CalleeAnswered);
    assert_eq!(state, CallState::Answered);
    assert_eq!(commands, vec![Command::AnswerCaller]);
}

#[test]
fn rejected_while_setting_up() {
    for state in [CallState::Offering, CallState::Ringing] {
        let (next, commands) = transit(state, CallEvent::CalleeRejected(486));
        assert_eq!(next, CallState::Terminating);
        assert_eq!(commands, vec![Command::FailCaller(486)]);
    }
}

#[test]
fn no_answer_gives_up() {
    let (state, commands) = transit(CallState::Ringing, CallEvent::CalleeTimeout);
    assert_eq!(state, CallState::Terminating);
    assert_eq!(commands, vec![Command::FailCaller(408)]);
}

#[test]
fn cancel_while_setting_up() {
    for state in [CallState::Offering, CallState::Ringing] {
        let (next, commands) = transit(state, CallEvent::CallerCancelled);
        assert_eq!(next, CallState::Terminating);
        assert_eq!(commands, vec![Command::CancelCaller]);
    }
}

#[test]
fn callee_hangs_up_first() {
    let (state, commands) = transit(CallState::Answered, CallEvent::CalleeHungUp);
    assert_eq!(state, CallState::Terminating);
    assert_eq!(commands, vec![Command::ByeCaller, Command::CompleteCallee]);
}

#[test]
fn uninteresting_events_change_nothing() {
    for (state, event) in [
        (CallState::Answered, CallEvent::CalleeRinging),
        (CallState::Ringing, CallEvent::CalleeRinging), // repeated 180
        (CallState::Answered, CallEvent::CalleeAnswered), // repeated 200
        (CallState::Offering, CallEvent::CallerHungUp), // BYE before answer
        (CallState::Terminated, CallEvent::CalleeAnswered),
        (CallState::Terminated, CallEvent::Teardown),
    ] {
        let (next, commands) = transit(state, event);
        assert_eq!(next, state, "{state:?} + {event:?}");
        assert!(commands.is_empty(), "{state:?} + {event:?}");
    }
}
