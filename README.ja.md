# mcp-stdio

[English](README.md) | 日本語

Stdio-to-HTTP ゲートウェイ — MCP クライアントとリモート HTTP MCP サーバーを接続します。

## 概要

[MCP](https://modelcontextprotocol.io/) クライアント（Claude Desktop, Claude Code）に対してローカルで稼働するセルフホスト MCP サーバのように振る舞いつつ、各種認証でリモート MCP サーバーへの接続を橋渡しします：

```mermaid
flowchart BT
    A[Claude<br>Desktop/Code] <-- stdio --> B(mcp-stdio)
    B <== "<b>HTTPS</b><br>Streamable HTTP / SSE<br>Bearer Token<br>Header<br>OAuth" ==> C[Remote<br>MCP Server]
    B -. "OAuth 2.1<br>(PKCE)" .-> D[Authorization<br>Server]
    D -. callback .-> B
    style B fill:#4a5,stroke:#333,color:#fff
```

Bearer token、カスタムヘッダー、OAuth 2.1 認証情報をリモートサーバーへ転送します。

## 特徴

- **両 MCP トランスポート対応** — Streamable HTTP（現行仕様、デフォルト）と SSE（MCP 2024-11-05 レガシー）を `--transport` で切り替え。SSE パーサは [WHATWG Server-Sent Events 仕様](https://html.spec.whatwg.org/multipage/server-sent-events.html) に準拠。
- **OAuth 2.1 クライアント** — 認可コードフロー（PKCE）、動的クライアント登録、トークンリフレッシュ、安全なトークン永続化を内蔵。MCP 認可仕様の関連 RFC にセクション単位で対応：
  - [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) Protected Resource Metadata
    - §3 `/.well-known/oauth-protected-resource` による認可サーバー検出
    - §3.1 パスベースのリバースプロキシ配下に対応した well-known URL 構築（ホストルートへのフォールバック付き）。リソース URL の query component も構築後の metadata URL に保持する
    - §3.3 `resource` フィールド検証（不一致は警告して続行）
    - §5.1 `WWW-Authenticate: Bearer resource_metadata=` ヒント — discovery 前にサーバーへ probe を送り、well-known パスの推測に頼らず PRM の所在を直接特定する
  - [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) Authorization Server Metadata
    - §3.1 well-known URL 構築。パス付き issuer のパス挿入ルール対応
    - §3.3 `issuer` 検証（クロスオリジンの issuer は AS mix-up 対策で拒否、同一オリジンの差異〔trailing slash / path / case〕は警告して続行）
  - [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) Resource Indicators
    - §2 `resource` パラメータを認可リクエスト・トークン交換・**リフレッシュ**に送信
  - [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) PKCE
    - §4.1–4.2 S256 `code_challenge_method`、86 文字の `code_verifier`
  - [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) Device Authorization Grant
    - §3.1 `resource` インジケータ付きデバイス認可リクエスト（RFC 8707）
    - §3.4–3.5 `authorization_pending` / `slow_down`（interval +=5 s）/ `expired_token` / `access_denied` ハンドリング
    - DCR の `grant_types` に `urn:ietf:params:oauth:grant-type:device_code` を登録（RFC 7591 §2）
  - [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) Dynamic Client Registration
    - §3 クライアント登録リクエスト。AS メタデータの `token_endpoint_auth_methods_supported` から最適な認証方式を選択（`none` → `client_secret_post` → `client_secret_basic` の優先順）
    - §3.2.1 `client_secret_expires_at` に対応、期限切れ時に自動再登録
  - [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) OAuth 2.0
    - §2.3.1 `client_secret_basic`：percent-encode した認証情報を `Authorization: Basic` ヘッダーで送信（コード交換・トークンリフレッシュ・Device Authorization Grant ポーリングに適用）
  - [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) Bearer Token の利用
    - §2.1 `Authorization: Bearer <token>` リクエストヘッダー
- **バックオフ付きリトライ** — 接続エラー時に最大3回リトライ
- **HTTP 429 / 503 対応** — `Retry-After`（delta-seconds または HTTP-date）を 60 秒上限で尊重する。対象は仕様上 `Retry-After` を伴う 429（Too Many Requests）と 503（Service Unavailable）の 2 つ（RFC 9110 §10.2.3）。上限超過時はステータスをクライアントに返して判断を委ねる（cf. modelcontextprotocol/typescript-sdk#1892）
- **自動ページネーション**（Streamable HTTP トランスポート） — `tools/list` / `resources/list` / `resources/templates/list` / `prompts/list` の `nextCursor` を透過的に追従して 1 つのレスポンスにマージ。先頭以降のページを取りこぼすクライアントでも全件を受け取れる（cf. anthropics/claude-code#39586）
- **ストリーミング耐性** — SSE レスポンスをリアルタイムで転送、ストリーム切断時に自動再接続
- **行区切り文字の安全化** — 上流レスポンス中の生の `U+2028` / `U+2029`（JSON では合法だが JavaScript の行終端文字）をエスケープし、これらを改行として扱うクライアントによるフレーム崩れを防止。ロスレス（cf. modelcontextprotocol/typescript-sdk#2155）
- **引数の正規化** — `tools/call` の `arguments` が `null` の場合は `{}` に書き換え、null 形式を拒否する厳格なサーバーでも呼び出せるようにする。デフォルト有効、`--no-normalize-arguments` で無効化（cf. modelcontextprotocol/typescript-sdk#2012）
- **キャンセル対応フィルタ** — stdin の `notifications/cancelled` でキャンセルされた id を追跡し、その id を持つ遅延レスポンスがクライアントに届く前に drop する（MCP キャンセル仕様準拠）。デフォルト有効（TTL 60 秒）、`--no-cancel-filter` で無効化（cf. anthropics/claude-code#51073）
- **セッション回復** — 404 でセッション ID をリセットして再試行
- **プロトコルバージョンヘッダー** — `initialize` 応答から交渉済みの `protocolVersion` を捕捉し、以降の Streamable HTTP リクエストすべてに `MCP-Protocol-Version` を付与（MCP 仕様 rev 2025-06-18）。このヘッダーを強制するサーバーは未送信時に初期化後リクエストを `400 Bad Request` で拒否する
- **401 時の自動トークンリフレッシュ** — セッション中に OAuth トークンが失効しても自動更新（OAuth モード時のみ）
- **403 時のステップアップ認可** — `Bearer error="insufficient_scope"` チャレンジを受けると、付与済みスコープと要求スコープの和集合で再認可（[RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) / MCP step-up、cf. anthropics/claude-code#44652）
- **Bearer token 認証** — `--bearer-token` フラグまたは `MCP_BEARER_TOKEN` 環境変数
- **カスタムヘッダー** — `-H` / `--header` で任意のヘッダーを送信
- **グレースフルシャットダウン** — SIGTERM/SIGINT ハンドリング
- **プロキシ対応** — `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` 環境変数を [httpx](https://www.python-httpx.org/) 経由でサポート
- **最小依存** — [httpx](https://www.python-httpx.org/) のみ; OAuth は stdlib のみ使用

## インストール

```bash
pip install mcp-stdio
```

[uv](https://docs.astral.sh/uv/) を使う場合：

```bash
uv tool install mcp-stdio
```

インストールせずに直接実行：

```bash
uvx mcp-stdio https://your-server.example.com:8080/mcp
```

[Homebrew](https://brew.sh/) を使う場合：

```bash
brew install shigechika/tap/mcp-stdio
```

## クイックスタート

```bash
mcp-stdio https://your-server.example.com:8080/mcp
```

Bearer token 認証付き：

```bash
# 推奨: 環境変数を使用（トークンが `ps` に表示されない）
MCP_BEARER_TOKEN=YOUR_TOKEN mcp-stdio https://your-server.example.com:8080/mcp

# または直接指定（トークンが `ps` の出力に表示される）
mcp-stdio https://your-server.example.com:8080/mcp --bearer-token YOUR_TOKEN
```

カスタムヘッダー付き：

```bash
mcp-stdio https://your-server.example.com:8080/mcp --header "X-API-Key: YOUR_KEY"
```

OAuth 2.1 認証付き（OAuth 必須のサーバー向け）：

```bash
mcp-stdio --oauth https://your-server.example.com:8080/mcp

# 事前登録済みクライアント ID を使用（動的クライアント登録をスキップ）
mcp-stdio --oauth --client-id YOUR_CLIENT_ID https://your-server.example.com:8080/mcp
```

OAuth 2.1 Device Authorization Grant（RFC 8628）— SSH・ヘッドレス環境向け：

```bash
mcp-stdio --oauth-device https://your-server.example.com:8080/mcp
```

MCP 2024-11-05 レガシーの SSE トランスポートを使うサーバー向け：

```bash
mcp-stdio --transport sse https://your-server.example.com:8080/sse
```

接続確認：

```bash
mcp-stdio --check https://your-server.example.com:8080/mcp

# SSE サーバーの場合は --transport sse を渡すと、--check は Streamable HTTP の
# プローブではなくレガシーの GET/endpoint/POST ハンドシェイクで確認する：
mcp-stdio --check --transport sse https://your-server.example.com:8080/sse
```

## Claude Desktop の設定

`claude_desktop_config.json` に追加：

```json
{
  "mcpServers": {
    "my-remote-server": {
      "command": "mcp-stdio",
      "args": ["https://your-server.example.com:8080/mcp"],
      "env": {
        "MCP_BEARER_TOKEN": "YOUR_TOKEN"
      }
    }
  }
}
```

設定ファイルの場所：
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

## Claude Code の設定

```bash
claude mcp add my-remote-server \
  -e MCP_BEARER_TOKEN=YOUR_TOKEN \
  -- mcp-stdio https://your-server.example.com:8080/mcp
```

## 使い方

```
mcp-stdio [OPTIONS] URL

引数:
  URL                    リモート MCP サーバーの URL

オプション:
  --bearer-token TOKEN   Bearer token（MCP_BEARER_TOKEN 環境変数でも指定可）
  --oauth                OAuth 2.1 認証を有効化（ブラウザフロー）
  --oauth-device         OAuth 2.1 Device Authorization Grant（RFC 8628）— ヘッドレス環境向け
  --client-id ID         事前登録済み OAuth クライアント ID（MCP_OAUTH_CLIENT_ID 環境変数でも指定可）
  --oauth-scope SCOPE    要求する OAuth スコープ
  --oauth-refresh-leeway SECONDS
                         アクセストークンを expire の何秒前に proactive refresh
                         するか（デフォルト: 60、または MCP_OAUTH_REFRESH_LEEWAY 環境変数）
  --oauth-timeout SECONDS
                         対話的 OAuth フロー（ブラウザコールバック / デバイス
                         コード確認）の待機秒数（デフォルト: 120、OAuth 時のみ有効）
  --no-resource-indicator
                         すべての OAuth リクエストから RFC 8707 resource
                         パラメータを除外する。api:// スコープを使う Microsoft
                         Entra ID v2 など、resource パラメータを拒否する AS
                         （AADSTS9010010）で必要。トークンストアに永続化され、
                         proactive refresh や step-up フローでも一貫して適用される
  -H, --header 'Key: Value'  カスタムヘッダー（複数指定可）
  --transport {streamable-http,sse}
                         トランスポート種別（デフォルト: streamable-http）
  --timeout-connect SEC  接続タイムアウト（デフォルト: 10秒）
  --timeout-read SEC     読み取りタイムアウト（デフォルト: 120秒）
  --sse-read-timeout SEC SSE GET ストリームのアイドル読み取りタイムアウト
                         （デフォルト: 300秒、0 で無効、SSE トランスポートのみ）
  --no-tcp-keepalive     HTTP ソケットの TCP keepalive を無効化する
  --no-cancel-filter     cancel-aware レスポンスフィルタを無効化する
                         （notifications/cancelled でキャンセルされた id の
                         遅延レスポンスを drop する機能）
  --no-normalize-arguments
                         tools/call リクエストの arguments:null を転送前に
                         {} へ書き換える正規化を無効化する
  --check                接続確認して終了
  -V, --version          バージョン表示
  -h, --help             ヘルプ表示
```

各フラグの詳細（プラットフォーム注記や issue 参照を含む）は `mcp-stdio --help` を実行してください。この表より詳しい説明が表示されます。

## 逆ゲートウェイ: `serve` モード

通常モードは **stdio → HTTP**（クライアント側）の橋渡しですが、`serve`
サブコマンドはその逆向き — **HTTP → stdio** — で、ローカルの stdio MCP
サーバを Streamable HTTP の MCP エンドポイントとして公開します。ローカルに
インストールしていないクライアントからネットワーク越しに到達できます:

```mermaid
flowchart LR
    A["MCP クライアント<br>Claude Code / Desktop<br>(または mcp-stdio --oauth)"]
    B("mcp-stdio serve<br><b>HTTP → stdio</b> ゲートウェイ<br>認証: なし / 静的トークン /<br>埋め込み OAuth 2.1 AS")
    C["ローカルの stdio<br>MCP サーバ"]
    A == "HTTPS · Streamable HTTP<br>Bearer / OAuth 2.1 (PKCE)" ==> B
    B -- "stdio (子プロセス起動)" --> C
```

冒頭のクライアント側の図と対になります。あちらは mcp-stdio が **stdio → HTTP**、
こちらは **HTTP → stdio** です。

```bash
mcp-stdio serve --port 8080 -- python -m my_mcp_server
```

任意の MCP クライアント（mcp-stdio 自身を含む）から接続:

```bash
mcp-stdio --check http://127.0.0.1:8080/mcp
```

- 標準ライブラリのみ（`http.server`）— ランタイム依存は増えません。
- Streamable HTTP のリクエスト/レスポンス・通知のセマンティクスに加え、
  サーバ起点メッセージ用の GET SSE チャネルを実装。
- **認証は任意・段階的:**
  - *トークン無し* — エンドポイントは素通し（TLS 終端プロキシ背後で運用）。
  - *静的トークン*（`--auth-token` / `MCP_STDIO_SERVE_TOKEN`）— OAuth リソース
    サーバとして `Authorization: Bearer <token>` を要求、401 で
    [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) Protected Resource
    Metadata（`/.well-known/oauth-protected-resource`）を広告。
  - *埋め込み OAuth AS*（`--enable-oauth`）— 最小 OAuth 2.1 認可サーバ
    （PKCE 認可コード・[RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) 動的
    クライアント登録・refresh・不透明インメモリトークン・stdlib のみ）。
    mcp-stdio クライアントの `--oauth` がこのゲートウェイ相手に通ります。
- 当面はシングルクライアント前提（JSON-RPC の id はそのまま透過）。

静的トークンの例（トークンは env 経由で `ps` に出さない）:

```bash
MCP_STDIO_SERVE_TOKEN=your-secret mcp-stdio serve --port 8080 -- python -m my_mcp_server
mcp-stdio --bearer-token your-secret --check http://127.0.0.1:8080/mcp
```

埋め込み OAuth の例。ユーザ認証は**前段リバースプロキシに委譲**し、ログイン
済みユーザをヘッダで主張させます（`--trusted-user-header`、クライアント由来の
同名ヘッダを除去するプロキシ背後でのみ信頼）。`--dev-user` はローカル検証用の
**非セキュア**な loopback 限定ショートカットです:

```bash
mcp-stdio serve --enable-oauth --public-url http://127.0.0.1:8080 \
  --dev-user alice --port 8080 -- python -m my_mcp_server
mcp-stdio --oauth http://127.0.0.1:8080/mcp
```

オプション: `--host`（既定 `127.0.0.1`）、`--port`（既定 `8080`）、`--path`
（既定 `/mcp`）、`--auth-token TOKEN`（または `MCP_STDIO_SERVE_TOKEN`、推奨）;
埋め込み AS 用: `--enable-oauth`、`--public-url URL`（issuer 固定・プロキシ背後
で推奨）、`--trusted-user-header HEADER`、`--dev-user USER`（非セキュア・検証用）、
`--access-token-ttl SECONDS`。インメモリなので再起動で発行済みトークンは失効
（クライアントは `--oauth` を再実行）。バックエンドコマンドはオプションの後に
置きます（`--` 区切りも可）。

## ワークアラウンド

Claude Code・mcp-remote・MCP SDK・Windows の既知の問題については [WORKAROUNDS.md](WORKAROUNDS.md) を参照してください。

## 仕組み

1. `--oauth`（ブラウザ）または `--oauth-device`（ヘッドレス、RFC 8628）指定時、アクセストークンを取得（キャッシュ → リフレッシュ → ブラウザ/デバイス認証）
2. stdin から JSON-RPC メッセージを読み取り（Claude Desktop/Code が送信）
3. HTTPS でリモート MCP サーバーへ転送
4. レスポンスをパースして stdout に書き出し
5. 401 で（OAuth モードのみ）アクセストークンをリフレッシュしてリトライ。静的な `--bearer-token` / `-H` 認証では 401 をそのままクライアントに返す

トランスポート別の挙動：

- **Streamable HTTP**（デフォルト）— 各メッセージを単一 POST で送信。`Mcp-Session-Id` ヘッダーでセッション状態を追跡し、404 時は自動で再初期化。交渉済みの `MCP-Protocol-Version` ヘッダーを初期化後の全リクエストに付与（仕様 rev 2025-06-18）。
- **SSE**（MCP 2024-11-05 レガシー）— 持続的な `GET` ストリームで応答と初回の `endpoint` イベント（POST 先 URL）を受信。ストリーム切断時は自動再接続。

OAuth トークンは `~/.config/mcp-stdio/tokens.json` に保存されます（パーミッション 0600）。

## ライセンス

MIT
