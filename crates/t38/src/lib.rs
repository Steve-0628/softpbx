//! T.38 ファックスゲートウェイ（T.30 信号 ↔ UDPTL）。
//!
//! docs/04 §2 の実装。
//!
//! - SDP の `m=image` で能力交換し、交渉できなければ G.711 パススルーへフォールバック
//! - UDPTL の冗長化（redundancy / FEC）でパケットロスに耐える
//! - 対応するモデム方式: V.21 / V.29 / V.17（V.34 は v1 対象外）
//! - ECM（誤り訂正モード）対応

/// T.38 の動作モード。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T38Mode {
    /// UDPTL 経由の中継。
    Udp,
    /// TCP 経由。
    Tcp,
}

/// UDPTL の冗長化方式（パケットロス対策）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redundancy {
    /// 冗長化なし。
    None,
    /// 直前 IFP の冗長化。
    Fec,
    /// FEC（Forward Error Correction）。
    Redundancy,
}

/// T.38 の能力（SDP で交換する値）。
#[derive(Debug, Clone)]
pub struct T38Capabilities {
    /// T.38 のバージョン。
    pub version: u16,
    /// 冗長化方式。
    pub redundancy: Redundancy,
    /// 最大ビットレート。
    pub max_bit_rate: u32,
    /// UDH の最大サイズ。
    pub max_ifp_size: u16,
}

/// T.38 のセッション（片側）。
pub struct T38Session {
    /// 動作モード。
    pub mode: T38Mode,
    /// 能力。
    pub caps: T38Capabilities,
}

impl T38Session {
    /// T.30 信号（IFP データ）を送信する。
    pub fn send_ifp(&mut self, _ifp: &[u8]) {
        // TODO(M2): UDPTL パケット化と冗長化。
        todo!()
    }

    /// UDPTL パケットを受信し、IFP データを取り出す。
    pub fn recv_ifp(&mut self, _packet: &[u8]) -> Option<Vec<u8>> {
        // TODO(M2): 冗長化の復元、欠損の扱い。
        todo!()
    }
}

/// T.30（FAX 手順）の状態機械。
///
/// 実機 FAX や `engine-sim` の疑似 FAX 機と共用する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T30State {
    /// 待機。
    Idle,
    /// 呼出し。
    Calling,
    /// 能力交換（DIS/DCS）。
    Negotiating,
    /// トレーニング（TCF）。
    Training,
    /// イメージ伝送。
    ImageTransfer,
    /// 誤り訂正（ECM）。
    ErrorCorrection,
    /// 終了。
    Finished,
}

/// T.30 のイベント。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T30Event {
    /// CNG（呼出音）。
    Cng,
    /// CED（応答音）。
    Ced,
    /// DIS（能力表示）。
    Dis,
    /// DCS（能力選択）。
    Dcs,
    /// TCF（トレーニング確認）。
    Tcf,
    /// 1 ページ送信完了。
    Eop,
    /// 終了確認。
    Ecm,
}

/// T.30 の状態遷移（純粋関数）。
///
/// 副作用を持たせないことで、`engine-sim` の疑似 FAX 機と決定的テストを成立させる。
pub fn t30_transit(state: T30State, event: T30Event) -> T30State {
    use T30Event::*;
    use T30State::*;
    match (state, event) {
        (Idle, Cng) | (Idle, Ced) => Calling,
        (Calling, Dis) => Negotiating,
        (Negotiating, Dcs) => Training,
        (Training, Tcf) => ImageTransfer,
        (ImageTransfer, Eop) => Finished,
        (ImageTransfer, Ecm) => ErrorCorrection,
        (ErrorCorrection, Eop) => Finished,
        (state, _) => state,
    }
}
