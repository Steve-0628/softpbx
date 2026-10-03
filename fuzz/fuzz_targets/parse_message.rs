//! Fuzz target for the SIP parser (docs/07: arbitrary input must produce a
//! `ParseError`, never a panic).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sip_syntax::parse_message(data);
    let _ = sip_syntax::parse_sdp(data);
});
