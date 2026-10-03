//! The call state machine (docs/02 §4, docs/03 §3).
//!
//! Pure: `transit(state, event) -> (state, commands)`. No I/O, no time, no
//! messages — the commands are *semantic* ("ring the caller", "hang up the
//! callee"), and the environment turns them into SIP (see [`crate::Switch`]).
//! This is what makes calls testable without a phone on the desk.

/// Where a call is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// INVITE received; deciding where it goes.
    Offering,
    /// The callee is ringing.
    Ringing,
    /// The call is up.
    Answered,
    /// Teardown messages are going out.
    Terminating,
    /// Done.
    Terminated,
}

/// What happened to a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEvent {
    /// The callee leg got a provisional response.
    CalleeRinging,
    /// The callee answered.
    CalleeAnswered,
    /// The callee leg got a final non-2xx response (busy, refused, ...).
    CalleeRejected(u16),
    /// The callee never answered.
    CalleeTimeout,
    /// The caller cancelled while the call was still being set up.
    CallerCancelled,
    /// The caller hung up an answered call.
    CallerHungUp,
    /// The callee hung up an answered call.
    CalleeHungUp,
    /// The teardown messages are out; the call is over.
    Teardown,
}

/// What the environment must do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Tell the caller the callee is ringing.
    RingCaller,
    /// Tell the caller the call is answered.
    AnswerCaller,
    /// Tell the caller the call failed with this status.
    FailCaller(u16),
    /// The caller cancelled: acknowledge the CANCEL and reject the INVITE.
    CancelCaller,
    /// Send BYE toward the caller (the callee hung up).
    ByeCaller,
    /// Answer the caller's BYE.
    CompleteCaller,
    /// Send BYE toward the callee (the caller hung up).
    ByeCallee,
    /// Answer the callee's BYE.
    CompleteCallee,
    /// The call is over: release media and write the call log.
    Finish,
}

/// Pure transition: state + event → new state + commands to run.
pub fn transit(state: CallState, event: CallEvent) -> (CallState, Vec<Command>) {
    use CallEvent::*;
    use CallState::*;
    match (state, event) {
        (Offering, CalleeRinging) => (Ringing, vec![Command::RingCaller]),
        (Offering, CalleeAnswered) => (Answered, vec![Command::AnswerCaller]),
        (Ringing, CalleeAnswered) => (Answered, vec![Command::AnswerCaller]),

        (Offering | Ringing, CalleeRejected(status)) => {
            (Terminating, vec![Command::FailCaller(status)])
        }
        (Offering | Ringing, CalleeTimeout) => (Terminating, vec![Command::FailCaller(408)]),
        (Offering | Ringing, CallerCancelled) => (Terminating, vec![Command::CancelCaller]),

        (Answered, CallerHungUp) => (
            Terminating,
            vec![Command::ByeCallee, Command::CompleteCaller],
        ),
        (Answered, CalleeHungUp) => (
            Terminating,
            vec![Command::ByeCaller, Command::CompleteCallee],
        ),

        // Teardown is out; the call is over.
        (Terminating, Teardown) => (Terminated, vec![Command::Finish]),
        (Terminated, _) => (Terminated, vec![]),

        // Everything else is not news.
        (state, _) => (state, vec![]),
    }
}
