//! Property tests for call routing (docs/04 §3): the matcher must agree with
//! a plainly-correct reference implementation on every pattern/value pair.

use call::glob_match;
use proptest::prelude::*;

/// The obviously-correct exponential matcher. Patterns are short in tests,
/// so its cost is irrelevant; its *behavior* is the oracle.
fn reference(pattern: &[u8], value: &[u8]) -> bool {
    match (pattern.split_first(), value.split_first()) {
        (None, None) => true,
        (Some((&b'*', rest)), _) => (0..=value.len()).any(|skip| reference(rest, &value[skip..])),
        (Some((&b'?', rest)), Some((_, vrest))) => reference(rest, vrest),
        (Some((&c, prest)), Some((_, vrest))) if c == *value.first().unwrap() => {
            reference(prest, vrest)
        }
        _ => false,
    }
}

fn glob_char() -> impl Strategy<Value = u8> {
    prop_oneof![Just(b'*'), Just(b'?'), b'a'..=b'z', b'0'..=b'9',]
}

proptest! {
    #[test]
    fn matches_the_reference(
        pattern in proptest::collection::vec(glob_char(), 0..8),
        value in proptest::collection::vec(b'a'..=b'z', 0..12),
    ) {
        let pattern_str = String::from_utf8(pattern.clone()).unwrap();
        let value_str = String::from_utf8(value.clone()).unwrap();
        prop_assert_eq!(
            glob_match(&pattern_str, &value_str),
            reference(&pattern, &value),
            "pattern {:?} value {:?}",
            pattern,
            value
        );
    }
}
