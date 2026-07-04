# リモート MCP サーバーに接続する

ゴール：リモートの HTTP MCP サーバーを、あたかもローカルサーバーの
ように Claude Desktop / Claude Code に登場させる——ログインは処理済み、
トークンは自動更新、トランスポートの癖は吸収済みの状態で。

## 1. まず接続確認

クライアント設定を触る前に、mcp-stdio がサーバーに届くことを確認します：

```bash
mcp-stdio --check --oauth https://mcp.example.com/mcp
```

`--check` は経路全体を一度だけ実行します——ディスカバリ、ブラウザでの
OAuth ログイン、トークン交換、MCP `initialize` の往復——そして結果を表示
します。これが成功すれば、以下のクライアント設定も動きます。

サーバーに OAuth がない場合は `--oauth` を外します。静的トークンなら
`MCP_BEARER_TOKEN` を使います（下の「バリエーション」表を参照）。

## 2. クライアントに追加

=== "Claude Desktop"

    `claude_desktop_config.json`：

    ```json
    {
      "mcpServers": {
        "my-remote-server": {
          "command": "mcp-stdio",
          "args": ["--oauth", "https://mcp.example.com/mcp"]
        }
      }
    }
    ```

=== "Claude Code"

    ```bash
    claude mcp add my-remote-server -- mcp-stdio --oauth https://mcp.example.com/mcp
    ```

クライアントを再起動します。最初のリクエストでブラウザが開いてサーバーの
ログインページが表示されます。以後トークンは
`~/.config/mcp-stdio/tokens.json`（パーミッション `0600`）に保存され、
すべてのターミナル・セッションで共有されます——refresh トークン自体が
失効・破棄されるまで再ログインは不要です。

## 何もしなくても付いてくるもの

- **自動トークンリフレッシュ** — `401` で即時に、加えて失効直前に
  バックグラウンドで先回りして更新。長いセッションがアクセストークンの
  TTL で死にません。
- **セッション回復** — 失効した MCP セッション（`404`）は透過的に
  再初期化されます。
- **クライアントのバグの遮蔽** — キャンセル競合、ページネーション、
  `Retry-After` など、実装間のギャップは中間で吸収されます。カタログは
  [WORKAROUNDS](https://github.com/shigechika/mcp-stdio/blob/main/WORKAROUNDS.md)
  へ。

## バリエーション

| こうしたい | こうする |
|---|---|
| OAuth なし、静的 Bearer トークン | `MCP_BEARER_TOKEN=… mcp-stdio https://…/mcp` |
| スコープを追加したい | `--oauth-scope "openid offline_access mcp:tools"` |
| このマシンにブラウザがない（SSH 先、コンテナ） | `--oauth-device` — 手元のスマホ / PC でユーザーコードを入力してログイン |
| サーバーが OIDC の `id_token` を要求する（Google IAP、AWS） | `--oauth-use-id-token` |
| legacy SSE サーバー（2024-11-05 トランスポート） | `--transport sse` |
| 社内プロキシ | 標準の `HTTPS_PROXY` / `NO_PROXY` 環境変数がそのまま効きます |

全フラグは `mcp-stdio --help` か
[README](https://github.com/shigechika/mcp-stdio#readme) へ。

## 例：Xquik

Xquik は X/Twitter の検索、抽出、アカウント監視、webhook、投稿ワークフローに
対応するリモート MCP サーバーです。静的 Bearer トークンの経路を使うため、
まず次のように確認します：

```bash
MCP_BEARER_TOKEN=YOUR_XQUIK_API_KEY mcp-stdio --check https://xquik.com/mcp
```

Claude Code：

```bash
claude mcp add xquik \
  -e MCP_BEARER_TOKEN=YOUR_XQUIK_API_KEY \
  -- mcp-stdio https://xquik.com/mcp
```

## トラブルシュートの早見

- **ブラウザが開かない** — authorize URL は stderr に出力されています。
  手動で開いてください（クライアントの MCP ログに出ます）。
- **Microsoft Entra ID でログインがループする / `AADSTS…` エラー** —
  `--oauth-scope` を明示してください。エラーコード別の詳細は WORKAROUNDS
  の該当項目へ。
- **昨日まで動いていたのに今日は `401`** — サーバー側で鍵のローテートや
  グラントの失効があったかもしれません。`~/.config/mcp-stdio/tokens.json`
  から該当サーバーのエントリを消して、再認可させてください。
