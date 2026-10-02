//! ファックスサーバ — FAX を終端してイメージ化する系。
//!
//! docs/04 §5 の実装。
//!
//! - 受信: T.30 終端 → T.4/T.6 デコード → TIFF(Fax G3/G4) → PDF → メール送信
//! - 送信: PDF/TIFF → T.4/T.6 符号化 → T.30 終端 → T.38 / G.711 / アナログ
//! - 保存: `fax/inbox/`・`fax/outbox/`・`fax/spool/`（docs/02 §5）
//!
//! T.38 などの「信号を透過伝送する系」（`t38`）とは別の実装であることに注意。

/// FAX のイメージ形式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// TIFF（Fax Group 3）。
    TiffG3,
    /// TIFF（Fax Group 4 / MMR）。
    TiffG4,
    /// PDF（FAX 用の 1bit 埋め込み）。
    Pdf,
}

/// 送受信の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaxResult {
    /// 全ページ成功。
    Success {
        /// ページ数。
        pages: u32,
    },
    /// 相手が応答しない。
    NoAnswer,
    /// 能力交渉に失敗。
    NegotiationFailed,
    /// 途中で切断された。
    Disconnected,
}

/// 受信 FAX。
#[derive(Debug, Clone)]
pub struct InboundFax {
    /// 送信元（CSI/TSI）。
    pub from: String,
    /// ページ数。
    pub pages: u32,
    /// 保存先（`fax/inbox/` 配下）。
    pub path: String,
    /// 形式。
    pub format: ImageFormat,
}

/// 送信 FAX。
#[derive(Debug, Clone)]
pub struct OutboundFax {
    /// 送信先。
    pub to: String,
    /// 入力ファイル（PDF / TIFF）。
    pub source: String,
    /// 残り試行回数。
    pub retries_left: u8,
}

/// 送受信キュー（`fax/spool/`）。
///
/// 失敗時は指数バックオフで再送し、結果を通知する。
pub struct Spool {
    /// 送信待ち件数。
    pub pending: usize,
}

impl Spool {
    /// 送信をキューに入れる。
    pub fn enqueue(&mut self, _fax: OutboundFax) {
        // TODO(M3): 一時ファイルに書いて rename で登録（docs/02 §5）。
        todo!()
    }

    /// 次に送信すべき FAX を取り出す。
    pub fn pop(&mut self) -> Option<OutboundFax> {
        // TODO(M3): 同時送信数を制限する。
        todo!()
    }
}

/// TIFF を PDF へ変換する。
pub fn tiff_to_pdf(_tiff: &[u8]) -> Vec<u8> {
    // TODO(M3): 1bit イメージの埋め込み PDF で十分（OCR は不要）。
    todo!()
}

/// PDF / TIFF を FAX イメージへ変換する。
pub fn to_fax_image(_input: &[u8], _format: ImageFormat) -> Vec<u8> {
    // TODO(M3): T.4(MH/MMR) / T.6(MMR) の符号化。
    todo!()
}
