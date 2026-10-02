//! SIP のトランスポート・トランザクション・ダイアログ。
//!
//! 呼制御の**ロジック**は `call` クレートに置き、ここは SIP というプロトコルを扱う。
//!
//! - トランスポート: UDP / TCP / TLS（5061）。RTP のポート範囲は設定で持つ
//! - トランザクション: RFC 3261 §17（INVITE / 非 INVITE、クライアント / サーバ）
//! - ダイアログ: RFC 3261 §12、REFER（RFC 3515）、セッションタイマ（RFC 4028）
//! - **拠点間トランク**（MikoPBX 互換）の制御もここ（docs/05 §2）
//!
//! すべての状態遷移は明示的な FSM とし、純粋関数で書く（docs/02 §4）。

/// トランスポート方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// UDP（既定。5060）
    Udp,
    /// TCP（5060）
    Tcp,
    /// TLS（5061）。拠点間接続では基本
    Tls,
}

/// トランザクションの状態（RFC 3261 §17 の図に対応）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// 初期。
    Trying,
    /// 呼び出し中。
    Proceeding,
    /// 送信済み。
    Completed,
    /// 終了。
    Terminated,
}

/// ダイアログの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogState {
    /// 初期。
    Null,
    /// 早期ダイアログ（1xx + SDP）。
    Early,
    /// 確立。
    Confirmed,
    /// 終了。
    Terminated,
}

/// 通話の片側（レグ）。B2BUA なので通話ごとに 2 つ持つ。
#[derive(Debug, Clone)]
pub struct Dialog {
    /// ローカルタグ。
    pub local_tag: String,
    /// リモートタグ。
    pub remote_tag: String,
    /// Call-ID。
    pub call_id: String,
    /// ローカル CSeq。
    pub local_cseq: u32,
    /// リモート CSeq。
    pub remote_cseq: u32,
    /// 状態。
    pub state: DialogState,
}

/// トランク（拠点間接続）の設定。MikoPBX 互換の差異はクイーク層で吸収する。
#[derive(Debug, Clone)]
pub struct Trunk {
    /// 表示名。
    pub name: String,
    /// 相手ホスト。
    pub host: String,
    /// トランスポート。
    pub transport: Transport,
    /// 相手拠点の番号帯（例: "3" 始まり）。
    pub number_range: String,
    /// 認証方式。
    pub auth: TrunkAuth,
}

/// トランクの認証方式。
#[derive(Debug, Clone)]
pub enum TrunkAuth {
    /// ダイジェスト認証（ユーザー名は相手側のプロバイダー ID）。
    Digest {
        /// ユーザー名。
        username: String,
        /// パスワード。
        password: String,
    },
    /// IP 認証（許可する送信元）。
    Ip,
}

/// SIP スタックが外へ出すイベント（`call` へ渡す）。
#[derive(Debug, Clone)]
pub enum StackEvent {
    /// 着信。
    Incoming {
        /// ダイアログ。
        dialog: Dialog,
    },
    /// 応答受信。
    Response {
        /// ステータスコード。
        status: u16,
    },
    /// トランザクションのタイムアウト。
    Timeout,
}
