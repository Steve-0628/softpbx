//! Audio handling: G.711 and the SDP we put on the wire (docs/02 §2).
//!
//! Deliberately small. We do not transcode (docs/03 §1: same codec on both
//! legs wherever possible) and we put no DSP on the forwarded stream
//! (docs/02 §8) — so this crate is codec *identity* and SDP, not signal
//! processing. Mixing and transcoding come later, if ever.

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
    let payload_types: Vec<String> = OUR_CODECS
        .iter()
        .map(|codec| codec.payload_type().to_string())
        .collect();
    let rtpmaps: Vec<&str> = OUR_CODECS.iter().map(|codec| codec.rtpmap()).collect();
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
