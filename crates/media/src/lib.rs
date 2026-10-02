//! コーデック、DSP（エコー除去・ミキサ）、メディアパイプライン。
//!
//! メディア面（専用スレッド）の心臓部。docs/03 を実装する。
//!
//! **鉄則**: オーディオパスでメモリ確保・ロック・ログ出力・ファイル I/O をしない。

/// コーデック。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// G.711 A-law（FAX/モデムで使用）。
    Pcma,
    /// G.711 µ-law（FAX/モデムで使用）。
    Pcmu,
    /// G.722（広帯域音声）。
    G722,
    /// Opus（`libopus` FFI を想定）。
    Opus,
}

/// DSP の設定。VBD（FAX/モデム）中は無効化するものが多い（docs/03 §4）。
#[derive(Debug, Clone)]
pub struct DspConfig {
    /// エコー除去（G.168 相当）。**VBD 中は停止**。
    pub echo_canceller: bool,
    /// 活性検出（VAD）。**VBD 中は停止**。
    pub vad: bool,
    /// 快適雑音（RFC 3389）。**VBD 中は停止**。
    pub comfort_noise: bool,
    /// パケットロス補間（PLC）。**VBD 中は停止**（欠損は復元しない）。
    pub packet_loss_concealment: bool,
    /// 自動利得調整。**VBD 中は停止**。
    pub agc: bool,
}

impl DspConfig {
    /// 通常の音声通話用。
    pub fn voice() -> Self {
        DspConfig {
            echo_canceller: true,
            vad: true,
            comfort_noise: true,
            packet_loss_concealment: true,
            agc: true,
        }
    }

    /// FAX / モデム（VBD）用。信号を壊す処理をすべて止める。
    pub fn voice_band_data() -> Self {
        DspConfig {
            echo_canceller: false,
            vad: false,
            comfort_noise: false,
            packet_loss_concealment: false,
            agc: false,
        }
    }
}

/// 1 通話分のメディアパイプライン（B2BUA の 1 レグ側）。
pub struct MediaLeg {
    /// コーデック。
    pub codec: Codec,
    /// DSP 設定。
    pub dsp: DspConfig,
}

impl MediaLeg {
    /// パケット 1 つを処理する。**1ms 以内**（docs/03 §1）。
    pub fn process(&mut self, _in: &[u8], _out: &mut [u8]) {
        // TODO(M1): 復号 → DSP → 符号化。同一コーデックなら透過。
        todo!()
    }
}

/// 会議のミキサ（数人〜十数人規模）。
pub struct Mixer {
    /// 参加者数。
    pub participants: usize,
}

impl Mixer {
    /// 参加者の音声を合成する。飽和を必ず防ぐ。
    pub fn mix(&mut self, _inputs: &[&[u8]], _out: &mut [u8]) {
        // TODO(M1): 固定小数点の整数ミキサ + 飽和処理。
        todo!()
    }
}
