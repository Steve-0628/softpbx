//! `pbx-daemon` — softpbx のメインプロセス。
//!
//! 起動の順序（docs/02 §3）:
//!
//! 1. 設定を Desired State からロードし、実行時状態へコンパイル
//! 2. メディアスレッド（コア固定・SCHED_FIFO）を起動
//! 3. SIP スタック（UDP/TCP/TLS）を起動
//! 4. API サーバ（REST / WebSocket）を起動
//! 5. ゲートウェイ・電話機のプロビジョニング監視を開始
//!
//! **制御面が停止しても確立済み通話の音声は止まらない**こと。

fn main() {
    // TODO(M0): 上の順序どおりに起動する。ここでは骨格のみ。
    println!("softpbx daemon (skeleton) — see docs/02-architecture.md");
}
