//! RTP packets (RFC 3550) — the transparent audio pipe (docs/02 §8).
//!
//! We relay RTP between the two legs of a call without touching the payload:
//! the packet's exact wire bytes are parsed for observation and forwarded
//! unchanged. No DSP lives here (docs/02 §8): no VAD, no packet-loss
//! concealment, no jitter adaptation — that is what lets future fax and modem
//! traffic survive this path.

/// Why a packet cannot be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtpError {
    /// Fewer bytes than an RTP header.
    TooShort,
    /// The version field is not 2.
    BadVersion,
    /// The header length (CSRC count, extension) exceeds the packet.
    BadLength,
}

/// A parsed RTP packet that keeps its exact wire bytes for forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Marker bit.
    pub marker: bool,
    /// Payload type (0 = PCMU, 8 = PCMA, 101 = telephone-event, ...).
    pub payload_type: u8,
    /// Sequence number.
    pub sequence: u16,
    /// Media timestamp.
    pub timestamp: u32,
    /// Synchronization source.
    pub ssrc: u32,
    raw: Vec<u8>,
}

impl Packet {
    /// Parses one RTP packet. Tolerant in what it accepts, strict in length.
    pub fn parse(bytes: &[u8]) -> Result<Packet, RtpError> {
        if bytes.len() < 12 {
            return Err(RtpError::TooShort);
        }
        if bytes[0] >> 6 != 2 {
            return Err(RtpError::BadVersion);
        }
        let csrc_count = (bytes[0] & 0x0f) as usize;
        let header_len = 12 + 4 * csrc_count;
        if bytes.len() < header_len {
            return Err(RtpError::BadLength);
        }
        let mut body_at = header_len;
        if bytes[0] & 0x10 != 0 {
            // Header extension: 4-byte profile/length, then the data.
            if bytes.len() < body_at + 4 {
                return Err(RtpError::BadLength);
            }
            let extension_words =
                u16::from_be_bytes([bytes[body_at + 2], bytes[body_at + 3]]) as usize;
            body_at += 4 + 4 * extension_words;
            if bytes.len() < body_at {
                return Err(RtpError::BadLength);
            }
        }
        Ok(Packet {
            marker: bytes[1] & 0x80 != 0,
            payload_type: bytes[1] & 0x7f,
            sequence: u16::from_be_bytes([bytes[2], bytes[3]]),
            timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ssrc: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            raw: bytes.to_vec(),
        })
    }

    /// The exact wire bytes this packet arrived as.
    pub fn to_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The media payload (everything after the header, CSRCs and extension).
    pub fn payload(&self) -> &[u8] {
        let csrc_count = (self.raw[0] & 0x0f) as usize;
        let mut at = 12 + 4 * csrc_count;
        if self.raw[0] & 0x10 != 0 {
            let extension_words = u16::from_be_bytes([self.raw[at + 2], self.raw[at + 3]]) as usize;
            at += 4 + 4 * extension_words;
        }
        &self.raw[at..]
    }

    /// Builds a simple packet (no CSRC, no extension, no padding): used by
    /// tests and by anything that needs to originate media.
    pub fn build(
        marker: bool,
        payload_type: u8,
        sequence: u16,
        timestamp: u32,
        ssrc: u32,
        payload: &[u8],
    ) -> Packet {
        let mut raw = Vec::with_capacity(12 + payload.len());
        raw.push(0x80); // V=2
        raw.push(u8::from(marker) << 7 | payload_type & 0x7f);
        raw.extend_from_slice(&sequence.to_be_bytes());
        raw.extend_from_slice(&timestamp.to_be_bytes());
        raw.extend_from_slice(&ssrc.to_be_bytes());
        raw.extend_from_slice(payload);
        Packet {
            marker,
            payload_type,
            sequence,
            timestamp,
            ssrc,
            raw,
        }
    }
}

/// Tracks one media stream's continuity (for statistics and leak checks).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamStats {
    /// Packets seen.
    pub packets: u64,
    /// Bytes seen.
    pub bytes: u64,
    /// Sequence gaps observed (loss).
    pub gaps: u64,
    /// Out-of-order arrivals observed.
    pub reordered: u64,
}

impl StreamStats {
    /// Records one packet.
    pub fn record(&mut self, packet: &Packet) {
        self.packets += 1;
        self.bytes += packet.raw.len() as u64;
    }

    /// Records a packet and checks its sequence continuity.
    pub fn record_sequenced(&mut self, packet: &Packet, expected_next: &mut Option<u16>) {
        match expected_next {
            Some(next) => {
                if packet.sequence == *next {
                    *next = next.wrapping_add(1);
                } else if packet.sequence.wrapping_sub(*next) < 0x8000 {
                    // A gap: lost however many packets were skipped.
                    self.gaps += u64::from(packet.sequence.wrapping_sub(*next));
                    *next = packet.sequence.wrapping_add(1);
                } else {
                    // Late arrival of an old packet.
                    self.reordered += 1;
                }
            }
            None => *expected_next = Some(packet.sequence.wrapping_add(1)),
        }
        self.record(packet);
    }
}
