//! Header value helpers: URIs, tags, display names.

use sip_stack::{tag_of, uri_of, with_tag, Dialog};

#[test]
fn uri_of_skips_display_names() {
    // baresip sends quoted display names; linphone sends bare ones.
    assert_eq!(
        uri_of("\"1002\" <sip:1002@127.0.0.1:5506>"),
        "sip:1002@127.0.0.1:5506"
    );
    assert_eq!(
        uri_of("Alice <sip:alice@192.0.2.1:5060>"),
        "sip:alice@192.0.2.1:5060"
    );
    assert_eq!(uri_of("<sip:bob@192.0.2.2>"), "sip:bob@192.0.2.2");
}

#[test]
fn uri_of_strips_parameters() {
    assert_eq!(
        uri_of("<sip:alice@192.0.2.1:5060>;expires=300"),
        "sip:alice@192.0.2.1:5060"
    );
    assert_eq!(
        uri_of("sip:alice@192.0.2.1:5060;transport=udp"),
        "sip:alice@192.0.2.1:5060"
    );
}

#[test]
fn tags_round_trip() {
    assert_eq!(tag_of("<sip:a@b>;tag=88sja8x"), Some("88sja8x"));
    assert_eq!(tag_of("<sip:a@b>"), None);
    assert_eq!(with_tag("<sip:a@b>", "x"), "<sip:a@b>;tag=x");
    assert_eq!(with_tag("<sip:a@b>;tag=y", "x"), "<sip:a@b>;tag=y");
}

#[test]
fn remote_cseq_only_goes_up() {
    // RFC 3261 §12.2.2: an out-of-order request is stale — it must not move
    // dialog state (media, targets) back to where an older request left it.
    let mut dialog = Dialog::new(
        "call-1",
        "sip:pbx@192.0.2.10",
        "ours",
        "sip:bob@192.0.2.2",
        "theirs",
        "sip:bob@192.0.2.2:5060",
    );
    assert_eq!(
        dialog.remote_cseq, None,
        "the remote side has not spoken yet"
    );
    assert!(dialog.accept_remote_cseq(2));
    assert!(dialog.accept_remote_cseq(3));
    assert!(!dialog.accept_remote_cseq(3), "a repeat is stale");
    assert!(!dialog.accept_remote_cseq(2), "an older request is stale");
    assert_eq!(dialog.remote_cseq, Some(3), "and leaves no trace");
}
