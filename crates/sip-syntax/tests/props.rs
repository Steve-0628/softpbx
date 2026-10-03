//! Property tests (docs/04 §1). The fuzzing contract, checked on every run:
//! arbitrary input never panics; successful parses serialize stably.

use proptest::prelude::*;
use sip_syntax::{parse_message, parse_sdp, serialize_message};

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_message(&data);
        let _ = parse_sdp(&data);
    }

    #[test]
    fn serialization_is_stable(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        // If a message parses, its serialization parses back to the same bytes.
        if let Ok(message) = parse_message(&data) {
            let bytes = serialize_message(&message);
            let reparsed = parse_message(&bytes).expect("our own output must parse");
            prop_assert_eq!(serialize_message(&reparsed), bytes);
        }
    }
}
