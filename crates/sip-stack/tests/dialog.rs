//! Header value helpers: URIs, tags, display names.

use sip_stack::{tag_of, uri_of, with_tag};

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
