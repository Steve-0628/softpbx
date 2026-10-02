//! 決定的シミュレーションテスト（DST）基盤。
//!
//! docs/06 §2 の実装。**テスト専用だが本体コードと並ぶ重要性を持つ。**
//!
//! - 仮想時計（時間を明示的に進める）と仮想ネットワーク（障害を注入できる）
//! - 乱数シードを固定すれば、失敗は必ず再現される
//! - 疑似装置: SIP 端末 / アナログゲートウェイ / **疑似 FAX 機（T.30）** /
//!   疑似モデム（V.8）/ 相手 PBX（MikoPBX 相当）
//!
//! 使う前にテスト基盤を作り、以降の開発はすべてこの上に載せる。

/// 仮想時計。実時間を使わないので結果が常に再現される。
#[derive(Debug, Clone)]
pub struct VirtualClock {
    /// 現在時刻（ms）。
    pub now_ms: u64,
}

impl VirtualClock {
    /// 時間を進める。
    pub fn advance(&mut self, ms: u64) {
        self.now_ms += ms;
    }
}

/// 仮想ネットワーク。パケットロス・ジッタ・遅延・順序入れ替わりを注入できる。
#[derive(Debug, Clone)]
pub struct VirtualNetwork {
    /// パケットロス率（0.0〜1.0）。
    pub loss: f64,
    /// 追加遅延（ms）。
    pub delay_ms: u64,
    /// ジッタ（ms）。
    pub jitter_ms: u64,
}

/// 疑似 SIP 端末。
pub struct SipPhone {
    /// 内線番号。
    pub number: String,
}

/// 疑似 FAX 機（T.30 状態機械を持つ）。
pub struct SimFax {
    /// 送信するページ数。
    pub pages: u32,
    /// ECM を使うか。
    pub ecm: bool,
}

/// 疑似モデム（V.8 の能力交換とキャリア確立を模擬）。
pub struct SimModem {
    /// 確立するか（交渉失敗を再現する場合は false）。
    pub connects: bool,
}

/// 相手 PBX（MikoPBX / Asterisk 系の癖を模擬する）。
pub struct RemotePbx {
    /// 番号帯。
    pub number_range: String,
}

/// シミュレーションの世界。
pub struct World {
    /// 時計。
    pub clock: VirtualClock,
    /// ネットワーク。
    pub net: VirtualNetwork,
    /// 乱数シード。
    pub seed: u64,
}

impl World {
    /// シードを固定して作る（結果が常に再現される）。
    pub fn with_seed(seed: u64) -> Self {
        World {
            clock: VirtualClock { now_ms: 0 },
            net: VirtualNetwork {
                loss: 0.0,
                delay_ms: 0,
                jitter_ms: 0,
            },
            seed,
        }
    }

    /// シナリオを 1 ステップ進める。
    pub fn step(&mut self) {
        // TODO(M0): 予約されたイベント（タイマー・パケット）を取り出して実行する。
        todo!()
    }
}

/// シナリオの実行結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimResult {
    /// 成功したか。
    pub ok: bool,
    /// ログの全行（ゴールデンテストとバイト単位で比較する）。
    pub log_lines: Vec<String>,
}
