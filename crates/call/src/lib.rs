//! PBX call logic: registration now, the call FSM and call routing later
//! (docs/02 §2, docs/03).
//!
//! Pure and time-explicit like `sip-stack`: this crate decides *what* happens,
//! never performs I/O.

mod registration;

pub use registration::{
    number_from_request, Binding, Device, Registrar, DEFAULT_EXPIRES_S, MAX_EXPIRES_S,
    MIN_EXPIRES_S,
};
