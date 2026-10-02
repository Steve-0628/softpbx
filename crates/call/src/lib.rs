//! コール処理 — B2BUA の通話 FSM とルーティング。
//!
//! docs/02 §4 の実装。**すべての状態遷移は純粋関数** [`transit`] として書く。
//! 副作用は [`Command`] として呼び出し側に押し出す（これでテストが成立する）。
//!
//! - 通話機能: 保留 / 転送 / 会議 / 同時着信
//! - ルーティング: ダイヤルプラン、番号帯ルーティング（拠点間）
//! - FAX / モデムは FSM の派生（`Answered` から `VbdFax` / `VbdModem` へ）

/// 通話の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// 未確立。
    Idle,
    /// 発呼中（INVITE 送信済み）。
    Offering,
    /// 呼出中（相手が鳴っている）。
    Ringing,
    /// 応答済み。
    Answered,
    /// 保留中。
    Held,
    /// 転送中。
    Transferring,
    /// 会議中。
    Conferencing,
    /// FAX 伝送中。
    VbdFax,
    /// モデム伝送中。
    VbdModem,
    /// 切断処理中。
    Terminating,
    /// 終了。
    Terminated,
}

/// 通話に入力されるイベント。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEvent {
    /// 発信要求。
    Dial,
    /// 着信。
    Incoming,
    /// 応答。
    Answer,
    /// 保留。
    Hold,
    /// 保留解除。
    Resume,
    /// 転送要求。
    Transfer,
    /// 会議への参加。
    JoinConference,
    /// FAX の検出。
    FaxDetected,
    /// モデムの検出。
    ModemDetected,
    /// 切断要求。
    Hangup,
    /// 相手から切断。
    RemoteHangup,
    /// タイムアウト。
    Timeout,
}

/// FSM が外へ指示する副作用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// SIP を送信する。
    SendSip,
    /// メディア路を確保する。
    AllocateMedia,
    /// メディア路を解放する。
    ReleaseMedia,
    /// 通話ログに追記する（`store`）。
    WriteCallLog,
    /// VBD モードへ切り替える（`vbd` / `media`）。
    EnterVbd,
    /// 通知（WebSocket など）。
    Notify,
}

/// 状態遷移（純粋関数）。副作用を持たせないこと。
///
/// これが満たすべき性質（`proptest` で確認する）:
/// - いかなるイベント列でもハングしない
/// - [`CallState::Terminated`] に到達したらメディア路が解放される
pub fn transit(state: CallState, event: CallEvent) -> (CallState, Vec<Command>) {
    use CallEvent::*;
    use CallState::*;
    match (state, event) {
        (Idle, Dial) => (Offering, vec![Command::AllocateMedia, Command::SendSip]),
        (Idle, Incoming) => (Ringing, vec![Command::Notify]),
        (Ringing, Answer) => (Answered, vec![Command::SendSip, Command::Notify]),
        (Answered, Hold) => (Held, vec![Command::SendSip]),
        (Held, Resume) => (Answered, vec![Command::SendSip]),
        (Answered, Transfer) => (Transferring, vec![Command::SendSip]),
        (Answered, JoinConference) => (Conferencing, vec![Command::AllocateMedia]),
        (Answered, FaxDetected) => (VbdFax, vec![Command::EnterVbd]),
        (Answered, ModemDetected) => (VbdModem, vec![Command::EnterVbd]),
        (Held | Transferring | Conferencing | VbdFax | VbdModem | Answered, Hangup | RemoteHangup | Timeout) => {
            (Terminating, vec![Command::SendSip, Command::ReleaseMedia, Command::WriteCallLog])
        }
        (Offering | Ringing, Hangup | RemoteHangup | Timeout) => {
            (Terminating, vec![Command::SendSip, Command::ReleaseMedia, Command::WriteCallLog])
        }
        (Terminating, _) => (Terminated, vec![]),
        (Terminated, _) => (Terminated, vec![]),
        (state, _) => (state, vec![]),
    }
}

/// ダイヤルプランの判定結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// 内線。
    Extension {
        /// 内線番号。
        number: String,
    },
    /// 拠点間トランク（相手拠点の番号帯）。
    Trunk {
        /// トランク名。
        trunk: String,
        /// 相手番号。
        number: String,
    },
    /// 番号不明。
    Unknown,
}

/// 番号を正規化して発信先を決める（番号帯ルーティング）。
pub fn route(_dialed: &str) -> Route {
    // TODO(M1): 番号正規化ルール（+81 / 0 / 内線）と番号帯の判定。
    todo!()
}
