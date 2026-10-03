//! SIP protocol logic, transport-agnostic: transactions now, dialogs later.
//!
//! Pure and side-effect free (docs/02 §2): every input takes `now_ms` explicitly,
//! every output is an [`Action`] for the caller to execute. There is no clock,
//! no socket and no timer inside — the deterministic simulation (docs/04) or
//! the real runtime drives it.

mod dialog;
pub mod digest;
mod transaction;

pub use dialog::{tag_of, uri_of, with_tag, Dialog};
pub use transaction::{
    ack_for_2xx, ack_for_non_2xx, branch, cseq_parts, make_response, Action, ClientState,
    ClientTransaction, ServerState, ServerTransaction, Timer, GIVE_UP_MS, T1_MS, T2_MS, T4_MS,
    TIMER_D_MS,
};
