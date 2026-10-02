//! 保存 — Desired State とログ。**DB エンジンは使わない。**
//!
//! docs/02 §5 の実装。
//!
//! ```text
//! /var/lib/softpbx/
//! ├── config/desired/   宣言的設定（TOML、1 エンティティ 1 ファイル）
//! ├── config/history/   変更履歴（ロールバック用）
//! ├── config/compiled/  実行時状態（再生成可能）
//! ├── log/call/         発着信ログ（NDJSON、追記のみ）
//! ├── log/audit/        監査ログ（NDJSON、追記のみ）
//! ├── fax/              FAX の spool / inbox / outbox
//! └── state/            揮発的状態
//! ```
//!
//! ## ルール
//!
//! - `config/desired/` のみが信頼の単一源
//! - 書き込みは一時ファイル → `rename()` で原子的
//! - ログは追記のみ。書き換え・削除しない
//! - 書き込みは `store` タスクのみ（単一ライター）

/// 保存先のルート。
#[derive(Debug, Clone)]
pub struct StoreRoot {
    /// `/var/lib/softpbx` 相当。
    pub path: String,
}

/// Desired State のエントリ。
#[derive(Debug, Clone)]
pub struct DesiredEntry {
    /// 種別（"extension" / "trunk" / "gateway" / …）。
    pub kind: String,
    /// 識別子。
    pub id: String,
    /// 内容（TOML）。
    pub body: String,
}

/// 変更履歴（ロールバックに使う）。
#[derive(Debug, Clone)]
pub struct Revision {
    /// 変更日時（Unix 秒）。
    pub at: i64,
    /// 変更者。
    pub who: String,
    /// 変更理由。
    pub why: String,
}

/// 保存の抽象。将来 `redb` や PostgreSQL へ差し替えられるようにしておく。
pub trait Store {
    /// Desired State を書き込む（原子的）。
    fn put(&mut self, entry: &DesiredEntry) -> Result<(), StoreError>;

    /// Desired State を読む。
    fn get(&self, kind: &str, id: &str) -> Result<Option<DesiredEntry>, StoreError>;

    /// 通話ログに 1 行追記する（NDJSON、追記のみ）。
    fn append_call_log(&mut self, line: &str) -> Result<(), StoreError>;

    /// 指定リビジョンへ戻す。
    fn rollback(&mut self, revision: &Revision) -> Result<(), StoreError>;
}

/// 保存処理の失敗。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// ファイルが存在しない。
    NotFound,
    /// 書き込みに失敗した。
    Io,
    /// 内容が不正。
    Invalid,
}

/// ファイルベースの実装。
pub struct FileStore {
    /// ルート。
    pub root: StoreRoot,
}

impl Store for FileStore {
    fn put(&mut self, _entry: &DesiredEntry) -> Result<(), StoreError> {
        // TODO(M0): 一時ファイルに書いて rename。履歴にも追記する。
        todo!()
    }

    fn get(&self, _kind: &str, _id: &str) -> Result<Option<DesiredEntry>, StoreError> {
        todo!()
    }

    fn append_call_log(&mut self, _line: &str) -> Result<(), StoreError> {
        // TODO(M0): NDJSON で追記のみ。部分行は再起動時に無視する（docs/08 AC-08）。
        todo!()
    }

    fn rollback(&mut self, _revision: &Revision) -> Result<(), StoreError> {
        todo!()
    }
}
