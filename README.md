# softpbx — ソフトウェア PBX 再実装プロジェクト

既存のソフトウェア PBX（MikoPBX 系）の設計と言語が陳腐化しているため、Rust で作り直す。
**通話処理エンジン（SIP / RTP / メディア / アナログ回線制御）も自前実装**する。

- 実装言語: Rust（制御面・メディア面・ドライバ層） + TypeScript（Web UI）
- 動作環境: VM / 自社サーバ（x86_64 / aarch64 Linux）
- チーム規模: 2〜5 名
- 詳細な設計は [docs/](docs/) を参照

## スコープ（v1）

### 入れる

| 領域 | 内容 |
| --- | --- |
| 通話 | 内線通話（SIP 端末・アナログ端末）、拠点間通話、保留・転送・会議、ダイヤルプラン |
| ファックス | T.38 中継、G.711 パススルー、アナログ FAX 機の接続、ファックスサーバ（PDF 化・メール送信） |
| アナログ | 外付けゲートウェイ（Yamaha NVR500/510 級）経由でアナログ端末（電話機・FAX・モデム）を接続、3.1kHz データ伝送 |
| 拠点間 | MikoPBX 互換 SIP トランク（宅外 PBX との通話）、番号帯ルーティング、TLS/SRTP |
| 管理系 | Web UI / API、設定管理（Desired State）、電話機/ゲートウェイ自動設定、軽量保守 |

### 出す

- **録音**（通話録音・モニタリング）
- **課金**（料金計算・請求）
- **外線（公衆回線）との接続** — 拠点間は IP（SIP トランク）のみ
- **重い保守機能** — A/B 更新、フルシステムバックアップ/リストア、遠隔診�断パッケージなど
- 留守番電話（メッセージ録音を伴うため実質的に録音機能。必要なら音声応答のみ別途）

## リポジトリ構成

```
softpbx/
├── docs/                  設計ドキュメント（01〜08、番号順に読む）
├── crates/                ライブラリクレート群
│   ├── sip-syntax/        SIP メッセージ・SDP の構文解析
│   ├── sip-stack/         トランスポート・トランザクション・ダイアログ
│   ├── rtp/               RTP/RTCP、DTMF、ジッタバッファ
│   ├── media/             コーデック、ミキサ、エコー除去、DSP パイプライン
│   ├── vbd/               音声帯域データ（ファックス/モデム）検出・モード遷移
│   ├── t38/               T.38 ゲートウェイ（T.30 ↔ UDPTL）
│   ├── faxserver/         ファックスサーバ（TIFF/PDF/メール送受信）
│   ├── line-hw/           アナログ回線 HAL（FXO/FXS、クロック同期、着信信号）
│   ├── call/              コール FSM、ルーティング、通話機能
│   ├── store/             設定 Desired State、通話ログ（ファイルベース、DB 不使用）
│   ├── api/               REST / WebSocket / gRPC、認証・権限・監査
│   └── engine-sim/        決定的シミュレーションテスト基盤
├── apps/
│   ├── pbx-daemon/        メインプロセス
│   └── pbx-cli/           運用 CLI
└── ui/                    Web UI（TypeScript）
```

## ドキュメント

| ファイル | 内容 |
| --- | --- |
| [docs/01-scope.md](docs/01-scope.md) | 要件・非機能・スコープ外・要確認事項 |
| [docs/02-architecture.md](docs/02-architecture.md) | 全体アーキテクチャ・プロセス/スレッドモデル |
| [docs/03-media-and-analog.md](docs/03-media-and-analog.md) | メディア面・アナログ回線・VBD の設計 |
| [docs/04-fax.md](docs/04-fax.md) | ファックス（T.38 / パススルー / FAX 機 / サーバ）の設計 |
| [docs/05-protocol-scope.md](docs/05-protocol-scope.md) | 対応プロトコル一覧と優先度 |
| [docs/06-testing.md](docs/06-testing.md) | テスト戦略（決定的シミュレーション・ファズ・相互運用） |
| [docs/07-milestones.md](docs/07-milestones.md) | マイルストーンと出口条件 |
| [docs/08-acceptance-m0.md](docs/08-acceptance-m0.md) | M0 の受け入れテスト一覧 |

## 開発の原則

1. **メディア面のリアルタイム性を最優先する。** オーディオパスでメモリ確保・ロック・ログ出力・ファイル I/O をしない。
2. **設定は宣言的 Desired State。** 実行中の設定ファイルを直接書き換えない。
3. **すべての状態遷移は明示的な FSM として書く**（通話・ファックス・モデム・キュー）。テスト可能にするため。
4. **「動く」より「検証できる」。** 決定的シミュレーションテスト（docs/06）を実装の前に用意する。
5. **フィールド汚染（互換性クイーク）は表データで管理する。** 標準準拠コードに if を混ぜない。

## 開発の進め方

```bash
cargo check --workspace        # 型チェック
cargo clippy --workspace       # リント
cargo test  --workspace        # ユニットテスト
cargo run -p engine-sim        # 決定的シミュレーション（回帰）
```
