//! PBX call logic: registration, the call state machine and the switch that
//! glues them to SIP transactions (docs/02 §2, docs/03).
//!
//! Pure and time-explicit like `sip-stack`: this crate decides *what* happens,
//! never performs I/O.

mod call;
mod registration;
mod routing;
mod switch;

pub use call::{transit, CallEvent, CallState, Command};
pub use registration::{
    number_from_request, number_from_uri, Binding, Device, Registrar, DEFAULT_EXPIRES_S,
    MAX_EXPIRES_S, MIN_EXPIRES_S,
};
pub use routing::{glob_match, route, Action, Destination, Rule};
pub use switch::{Output, Switch, SwitchConfig, TrunkConfig, ALLOW};
