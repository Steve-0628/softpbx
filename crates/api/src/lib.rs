//! API — REST / WebSocket / gRPC。認証・権限・監査ログ。
//!
//! **機能はすべて API から利用可能。UI はクライアントの一つ**（docs/02 §6）。
//!
//! - REST: 設定・照会・操作
//! - WebSocket: イベント通知（着信、通話状態、FAX 結果）
//! - 認証: API キー + ログインセッション、権限はロール（管理者 / 運用 / 閲覧）
//! - 変更系 API はすべて監査ログに記録する

/// ロール。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// すべての操作が可能。
    Admin,
    /// 運用操作（通話・FAX・再起動など）。
    Operator,
    /// 閲覧のみ。
    Viewer,
}

/// API のリクエスト（REST のエンドポイントは実装時に OpenAPI で定義する）。
#[derive(Debug, Clone)]
pub enum Request {
    /// 内線の一覧。
    ListExtensions,
    /// 内線の追加。
    AddExtension,
    /// 通話状態の照会。
    CallStatus,
    /// FAX の送信。
    SendFax {
        /// 送信先。
        to: String,
        /// 入力ファイル。
        source: String,
    },
    /// 設定のロールバック。
    Rollback {
        /// 対象リビジョン。
        revision: i64,
    },
}

/// レスポンス。
#[derive(Debug, Clone)]
pub enum Response {
    /// 成功。
    Ok,
    /// データを返す。
    Data {
        /// JSON 文字列。
        json: String,
    },
    /// 拒否。
    Denied,
}

/// WebSocket で流すイベント。
#[derive(Debug, Clone)]
pub enum Event {
    /// 着信。
    Incoming,
    /// 通話状態の変化。
    CallState {
        /// 状態名。
        state: String,
    },
    /// FAX の結果。
    FaxResult {
        /// 成功したか。
        success: bool,
    },
}
