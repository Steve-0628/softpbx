//! アナログ端末ゲートウェイ（Yamaha NVR500/510 級）の制御と特性管理。
//!
//! docs/03 §5〜§6 の実装。
//!
//! アナログ端末は**外付けゲートウェイ**に接続され、本ソフトウェアからは SIP 端末として見える。
//! したがってこのクレートが担うのは次の 2 つ。
//!
//! 1. **プロビジョニング**: ゲートウェイへの設定生成・配信・状態監視
//! 2. **特性プロファイル（クイーク層）**: 機種ごとの癖を表データで保持する
//!
//! TDM クロックやライン電圧は直接制御できない。この制約を忘れないこと。

/// ゲートウェイの機種プロファイル。クイークは表データ（TOML）で保持する。
#[derive(Debug, Clone)]
pub struct GatewayProfile {
    /// 機種名（例: "yamaha-nvr510"）。
    pub model: String,
    /// 送るパケット周期（ms）。
    pub ptime_ms: u8,
    /// DTMF の通知方式。
    pub dtmf: DtmfMethod,
    /// T.38 中継に対応するか。
    pub supports_t38: bool,
    /// 発信者番号通知（FSK）の伝送方法。
    pub caller_id: CallerIdMethod,
}

/// DTMF の通知方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtmfMethod {
    /// RFC 4733（RTP 電話イベント）。
    Rfc4733,
    /// 帯域内（音声として送る）。
    InBand,
    /// SIP INFO。
    SipInfo,
}

/// 発信者番号通知の方法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerIdMethod {
    /// FSK（V.23）を RTP で伝送。
    FskOverRtp,
    /// SIP ヘッダ（From / P-Asserted-Identity）のみ。
    SipHeader,
    /// 通知しない。
    None,
}

/// ゲートウェイの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayState {
    /// 未接続。
    Offline,
    /// 接続済み・正常。
    Online,
    /// 設定適用中。
    Provisioning,
    /// 異常。
    Degraded,
}

/// ゲートウェイ 1 台の管理。
pub struct Gateway {
    /// 表示名。
    pub name: String,
    /// プロファイル。
    pub profile: GatewayProfile,
    /// 状態。
    pub state: GatewayState,
}

impl Gateway {
    /// 設定を生成して配信する。
    pub fn provision(&mut self, _config: &str) {
        // TODO(M2): HTTP / TFTP / 独自 API のいずれかは機種確定後に決める（docs/03 §6）。
        todo!()
    }

    /// 状態を監視する（OPTIONS 応答、登録状態など）。
    pub fn poll(&mut self) -> GatewayState {
        // TODO(M2): 電源断・LAN 断からの復旧時間も測る。
        todo!()
    }
}
