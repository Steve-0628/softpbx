# ui/ — Web UI

管理・運用のための Web クライアント。**機能はすべて API 経由**で、UI はクライアントの一つ。

- TypeScript + React（Vite）
- API クライアントは OpenAPI 定義（`crates/api` が生成）から自動生成する
- 通信は REST + WebSocket（イベント通知：着信、通話状態、FAX 結果）

## 含むもの

| 画面 | 内容 |
| --- | --- |
| 内線 | 内線の一覧・追加・編集、状態表示 |
| ルーティング | ダイヤルプラン、番号帯ルーティング、トランク |
| FAX | 送受信の履歴、送信（PDF/TIFF をアップロード）、結果 |
| アナログ | ゲートウェイ（NVR500/510 級）の状態と設定 |
| 設定 | Desired State の編集、変更履歴、ロールバック |
| 監視 | 通話状態、ログ、簡易メトリクス |

## 動かし方（実装後）

```bash
cd ui
npm install
npm run dev      # 開発サーバ（http://localhost:5173）
npm run build    # 静的ビルド（pbx-daemon が配信する）
```
