//! RTP / RTCP の送受信、DTMF、ジッタバッファ。
//!
//! **メディア面**（専用スレッド）から使う。`tokio` には依存しない。
//! オーディオパスでメモリ確保・ロック・ログ出力をしないこと（docs/02 §3）。

/// RTP パケットヘッダ（RFC 3550）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    /// シーケンス番号。
    pub sequence: u16,
    /// タイムスタンプ。
    pub timestamp: u32,
    /// 同期ソース識別子。
    pub ssrc: u32,
    /// ペイロードタイプ番号。
    pub payload_type: u8,
    /// マーカービット。
    pub marker: bool,
}

/// DTMF など電話イベント（RFC 4733）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelephoneEvent {
    /// イベント番号（DTMF は 0〜15）。
    pub event: u8,
    /// エンドビット。
    pub end: bool,
    /// 継続時間。
    pub duration: u16,
}

/// ジッタバッファの動作モード。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterMode {
    /// 音声: 遅延と欠損のバランスを自動調整する。
    Adaptive {
        /// 最小遅延（ms）。
        min_ms: u16,
        /// 最大遅延（ms）。
        max_ms: u16,
    },
    /// VBD（FAX/モデム）: 長さを固定し、欠損も復元しない（docs/03 §2）。
    Fixed {
        /// 固定遅延（ms）。
        delay_ms: u16,
    },
}

/// 1 本の RTP 送受信路。
///
/// メディアスレッドが所有し、コール単位でシャーディングする。
pub struct RtpSession {
    /// シーケンス番号の送信用カウンタ。
    pub next_sequence: u16,
    /// ジッタバッファのモード。
    pub jitter: JitterMode,
}

impl RtpSession {
    /// 受信パケットを取り出す。バッファが空なら `None`。
    pub fn recv(&mut self, _out: &mut [u8]) -> Option<RtpHeader> {
        // TODO(M0): recvmmsg での受信と並び順の復元、欠損検出。
        todo!()
    }

    /// 送信パケットを書き込む。周期を厳密に保つこと。
    pub fn send(&mut self, _header: &RtpHeader, _payload: &[u8]) {
        // TODO(M0): 送信はバッチより周期を優先する（docs/03 §7）。
        todo!()
    }
}
