//! Audio handling: G.711 and the SDP we put on the wire (docs/02 §2).
//!
//! Deliberately small. We do not transcode (same codec on both legs wherever
//! possible) and we put no DSP on the forwarded stream (docs/02 §8) — so this
//! crate is codec *identity* and SDP, not signal processing. Mixing and
//! transcoding come later, if ever.

/// Codecs we speak (docs/07 SDP subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// G.711 µ-law, payload 0.
    Pcmu,
    /// G.711 A-law, payload 8.
    Pcma,
    /// RFC 4733 DTMF events, payload 101 (passed through, not interpreted).
    TelephoneEvent,
}

impl Codec {
    /// The static payload type number.
    pub fn payload_type(self) -> u8 {
        match self {
            Codec::Pcmu => 0,
            Codec::Pcma => 8,
            Codec::TelephoneEvent => 101,
        }
    }

    /// The codec behind a static payload type, if we support it.
    pub fn of_payload_type(payload_type: u8) -> Option<Codec> {
        match payload_type {
            0 => Some(Codec::Pcmu),
            8 => Some(Codec::Pcma),
            101 => Some(Codec::TelephoneEvent),
            _ => None,
        }
    }

    /// The `a=rtpmap` line for this codec.
    pub fn rtpmap(self) -> &'static str {
        match self {
            Codec::Pcmu => "a=rtpmap:0 PCMU/8000",
            Codec::Pcma => "a=rtpmap:8 PCMA/8000",
            Codec::TelephoneEvent => "a=rtpmap:101 telephone-event/8000",
        }
    }
}

/// The codecs we offer, in preference order (G.711 first, as docs/07 says).
pub const OUR_CODECS: [Codec; 3] = [Codec::Pcmu, Codec::Pcma, Codec::TelephoneEvent];

/// Builds the SDP body we send (offer or answer): one audio stream of G.711,
/// 10 ms packets, no silence suppression.
pub fn audio_sdp(connection_ip: &str, port: u16) -> Vec<u8> {
    build_sdp(connection_ip, port, &OUR_CODECS)
}

/// Our codecs, narrowed to the payload types a peer's SDP listed.
fn shared_codecs(offered_payload_types: &[u8]) -> Vec<Codec> {
    OUR_CODECS
        .iter()
        .copied()
        .filter(|codec| offered_payload_types.contains(&codec.payload_type()))
        .collect()
}

/// Builds an SDP answer limited to the codecs the offer actually contained
/// (RFC 3264 §6: answer with the intersection, never a codec they did not
/// offer). If the offer shares none of ours, the stream is **declined**
/// (`m=audio 0`) instead of answered with something they never offered.
pub fn audio_sdp_answer(connection_ip: &str, port: u16, offered_payload_types: &[u8]) -> Vec<u8> {
    let shared = shared_codecs(offered_payload_types);
    if shared.is_empty() {
        return format!(
            "v=0\r\n\
             o=softpbx 1 1 IN IP4 {connection_ip}\r\n\
             s=-\r\n\
             c=IN IP4 {connection_ip}\r\n\
             t=0 0\r\n\
             m=audio 0 RTP/AVP 0\r\n\r\n"
        )
        .into_bytes();
    }
    build_sdp(connection_ip, port, &shared)
}

/// Builds the SDP offer toward the far leg of a bridge, limited to the codecs
/// the near leg offered and we support. RTP is relayed without transcoding
/// (docs/02 §8), so both legs must end up on one codec: offering our whole set
/// here would let the far leg pick something the near leg never offered.
///
/// With nothing to mirror (an offer that listed no payload types we know) we
/// fall back to our own set; the answer side then still enforces the
/// intersection.
pub fn audio_sdp_offer(
    connection_ip: &str,
    port: u16,
    near_end_payload_types: &[u8],
) -> Vec<u8> {
    let shared = shared_codecs(near_end_payload_types);
    if shared.is_empty() {
        return audio_sdp(connection_ip, port);
    }
    build_sdp(connection_ip, port, &shared)
}

/// An SDP body declining media (RFC 3264 §6: `m=audio 0`).
pub fn declined_sdp(connection_ip: &str) -> Vec<u8> {
    format!(
        "v=0\r\n\
         o=softpbx 1 1 IN IP4 {connection_ip}\r\n\
         s=-\r\n\
         c=IN IP4 {connection_ip}\r\n\
         t=0 0\r\n\
         m=audio 0 RTP/AVP 0\r\n\r\n"
    )
    .into_bytes()
}

fn build_sdp(connection_ip: &str, port: u16, codecs: &[Codec]) -> Vec<u8> {
    let payload_types: Vec<String> = codecs
        .iter()
        .map(|codec| codec.payload_type().to_string())
        .collect();
    let rtpmaps: Vec<&str> = codecs.iter().map(|codec| codec.rtpmap()).collect();
    format!(
        "v=0\r\n\
         o=softpbx 1 1 IN IP4 {connection_ip}\r\n\
         s=-\r\n\
         c=IN IP4 {connection_ip}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP {}\r\n\
         {}\r\n\
         a=ptime:10\r\n\
         a=silenceSupp:off\r\n\r\n",
        payload_types.join(" "),
        rtpmaps.join("\r\n"),
    )
    .into_bytes()
}
