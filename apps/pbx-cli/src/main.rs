//! `pbx-cli` — 運用 CLI。
//!
//! API 経由で操作する。主な用途:
//!
//! - `pbx-cli status`            通話・端末・ゲートウェイの状態
//! - `pbx-cli config export`     設定のエクスポート
//! - `pbx-cli config import`     設定のインポート
//! - `pbx-cli config rollback`   指定リビジョンへ戻す
//! - `pbx-cli fax send`          FAX の送信
//! - `pbx-cli diag`              診断情報の収集（軽量）

fn main() {
    // TODO(M4): サブコマンドを実装する。
    println!("softpbx cli (skeleton) — see docs/02-architecture.md");
}
