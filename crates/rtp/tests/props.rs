//! Property tests: arbitrary bytes never panic the RTP parser (docs/07).

use proptest::prelude::*;
use rtp::Packet;

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(packet) = Packet::parse(&data) {
            // A parsed packet round-trips to its exact bytes.
            prop_assert_eq!(packet.to_bytes(), &data[..]);
            let _ = packet.payload();
        }
    }

    #[test]
    fn built_packets_parse_back(
        marker in any::<bool>(),
        payload_type in proptest::num::u8::ANY,
        sequence in any::<u16>(),
        timestamp in any::<u32>(),
        ssrc in any::<u32>(),
        payload in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let packet = Packet::build(marker, payload_type, sequence, timestamp, ssrc, &payload);
        let parsed = Packet::parse(packet.to_bytes()).expect("our own packets parse");
        prop_assert_eq!(parsed.marker, marker);
        prop_assert_eq!(parsed.payload_type, payload_type & 0x7f);
        prop_assert_eq!(parsed.sequence, sequence);
        prop_assert_eq!(parsed.timestamp, timestamp);
        prop_assert_eq!(parsed.ssrc, ssrc);
        prop_assert_eq!(parsed.payload(), &payload[..]);
    }
}
