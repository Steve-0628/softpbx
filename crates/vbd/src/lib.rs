//! 音声帯域データ（VBD）— FAX / モデムの検出とモード遷移。
//!
//! docs/03 §4 の実装。**本ソフトウェアの技術的な要**であり、
//! ここで誤ると FAX とモデムが必ず失敗する。
//!
//! - 検出: CNG / CED / V.21 プリアンブル / V.8 CM・JM / V.25 ANS
//! - 遷移: `Voice → VbdEnter → VbdActive → VbdExit → Voice`
//! - `VbdEnter` でエコー除去・VAD・DTX・CNG・PLC・AGC・DTMF 検出を**すべて停止**し、
//!   ジッタバッファを固定、ptime を短縮する
//! - `VbdActive` 中は re-INVITE を行わない

use media::DspConfig;

/// VBD の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VbdState {
    /// 通常の音声。
    Voice,
    /// モード切替中（re-INVITE の完了待ち）。
    VbdEnter,
    /// データ伝送中。
    VbdActive,
    /// 元の音声設定へ復帰中。
    VbdExit,
}

/// 検出されたデータ種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VbdKind {
    /// ファックス。
    Fax,
    /// アナログモデム。
    Modem,
    /// 3.1kHz オーディオ（指定によるもの）。
    Audio3k1,
}

/// VBD の検出器。
///
/// 帯域内のトーン解析（Goertzel）と RFC 4734 の RTP イベントを組み合わせる。
pub struct Detector {
    /// 現在の状態。
    pub state: VbdState,
}

impl Detector {
    /// 受信パケットから検出を試みる。
    ///
    /// 検出したら `Some(kind)` を返し、呼び出し側（`call`）に
    /// モード切替（DSP 設定の変更、必要なら re-INVITE）を指示する。
    pub fn observe(&mut self, _payload: &[u8]) -> Option<VbdKind> {
        // TODO(M2): CNG(1100Hz 断続) / CED / V.21 / V.8 のトーン検出。
        todo!()
    }

    /// VBD に適用する DSP 設定を返す。
    pub fn dsp_config(&self, kind: VbdKind) -> DspConfig {
        let _ = kind;
        DspConfig::voice_band_data()
    }
}

/// VBD 中のジッタバッファ設定（固定・欠損復元なし）。
pub fn jitter_for_vbd() -> rtp::JitterMode {
    // パケット周期 + 1〜2 パケット（docs/03 §2）
    rtp::JitterMode::Fixed { delay_ms: 30 }
}
