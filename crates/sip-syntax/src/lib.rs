//! SIP メッセージと SDP の構文解析。
//!
//! # 責務
//!
//! - SIP リクエスト/レスポンスのパースと直列化
//! - SDP のパースと直列化（docs/05-protocol-scope.md）
//!
//! # 設計上のルール
//!
//! - **I/O を行わない。** 入力はバイト列、出力は型付きデータのみ。
//! - **依存を持たない純粋層。** ここを壊すと全部壊れるので、もっとも厚くテストする。
//! - ゼロコピーを基本とするが、雛形段階では所有型で表す（実装時に借用版へ移行）。
//! - **ファジングの主要ターゲット**（docs/06 §4）。パニックしてはならない。

/// SIP のバージョン。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// SIP/2.0 のみを扱う。
    V2,
}

/// SIP メソッド。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// 通話確立。
    Invite,
    /// INVITE の確認。
    Ack,
    /// 通話終了。
    Bye,
    /// 通話取り消し。
    Cancel,
    /// 位置登録。
    Register,
    /// 転送（RFC 3515）。
    Refer,
    /// 能力照会・キープアライブ。
    Options,
    /// 中間情報（DTMF など）。
    Info,
    /// イベント購読。
    Subscribe,
    /// イベント通知。
    Notify,
    /// メッセージ送信。
    Message,
    /// セッション更新（RFC 3311）。
    Update,
    /// 信頼できる暫定応答の確認。
    Prack,
}

impl Method {
    /// ワイヤ上の表記（"INVITE" など）を返す。
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Register => "REGISTER",
            Method::Refer => "REFER",
            Method::Options => "OPTIONS",
            Method::Info => "INFO",
            Method::Subscribe => "SUBSCRIBE",
            Method::Notify => "NOTIFY",
            Method::Message => "MESSAGE",
            Method::Update => "UPDATE",
            Method::Prack => "PRACK",
        }
    }
}

/// ヘッダフィールド（名前と値）。順序は保持する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// フィールド名（大文字小文字は無視するが、元の表記を保持する）。
    pub name: String,
    /// フィールド値（前後の空白を除いた形）。
    pub value: String,
}

/// SIP リクエスト。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// メソッド。
    pub method: Method,
    /// リクエスト URI。
    pub uri: String,
    /// ヘッダ群（出現順）。
    pub headers: Vec<Header>,
    /// ボディ。
    pub body: Vec<u8>,
}

/// SIP レスポンス。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// ステータスコード。
    pub status: u16,
    /// 理由句。
    pub reason: String,
    /// ヘッダ群（出現順）。
    pub headers: Vec<Header>,
    /// ボディ。
    pub body: Vec<u8>,
}

/// SIP メッセージ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// リクエスト。
    Request(Request),
    /// レスポンス。
    Response(Response),
}

/// 構文解析の失敗理由。
///
/// ファジングでは、この列挙型のどれかで**必ず**失敗すること（パニックしないこと）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// 入力が途中で切れている（分割到着の続きが必要）。
    Incomplete,
    /// リクエストラインが不正。
    BadStartLine,
    /// ヘッダが不正（コロン欠落、制御文字を含むなど）。
    BadHeader,
    /// Content-Length とボディ長が一致しない。
    BadBodyLength,
    /// ヘッダ数・行長などの上限を超えた（リソース保護）。
    LimitExceeded,
}

/// SIP メッセージを解析する。
///
/// 入力が足りない場合は [`ParseError::Incomplete`] を返す（呼び出し側で続きを蓄積する）。
pub fn parse_message(_input: &[u8]) -> Result<Message, ParseError> {
    // TODO(M0): RFC 3261 §7 の構文を実装する。上限値（ヘッダ数・行長・ボディ長）を必ず設ける。
    todo!()
}

/// SDP のセッション記述（docs/05）。RFC 4566。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sdp {
    /// `m=` 行のメディア記述。
    pub media: Vec<MediaDescription>,
}

/// `m=` で始まるメディア記述。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaDescription {
    /// メディア種別（"audio" / "image" / "application" など）。
    pub media: String,
    /// 送信先ポート。
    pub port: u16,
    /// トランスポート（"RTP/AVP" / "udptl" など）。
    pub transport: String,
    /// ペイロードタイプ番号。
    pub payload_types: Vec<u8>,
}

/// SDP を解析する。
pub fn parse_sdp(_input: &[u8]) -> Result<Sdp, ParseError> {
    // TODO(M0): RFC 4566 の構文を実装する。FAX/モデムでは `m=image`（T.38）を扱う。
    todo!()
}
