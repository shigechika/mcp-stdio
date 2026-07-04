# リファレンス

## CLI フラグ

### 基本的な使い方

```
mcp-stdio [OPTIONS] URL

Arguments:
  URL                    リモート MCP サーバー URL
```

### 認証

| フラグ | 環境変数 | 説明 |
|--------|---------|------|
| `--bearer-token TOKEN` | `MCP_BEARER_TOKEN` | 静的ベアラートークン認証 |
| `--oauth` | — | OAuth 2.1 認証（ブラウザフロー） |
| `--oauth-device` | — | OAuth 2.1 デバイス認可グラント（RFC 8628、ヘッドレス） |
| `--client-id ID` | `MCP_OAUTH_CLIENT_ID` | 事前登録済み OAuth クライアント ID（Dynamic Client Registration をスキップ） |
| `--client-metadata-url URL` | — | Dynamic Client Registration の代わりに使用するクライアント ID メタデータドキュメントの HTTPS URL |
| `--oauth-scope SCOPE` | — | リクエストする OAuth スコープ（繰り返し可能） |
| `--oauth-use-id-token` | — | アクセストークンの代わりに OIDC id_token をベアラー認証情報として提示（AWS Bedrock / Cognito） |
| `--oauth-eager` | — | コールドスタート：initialize をローカルで応答し、バックグラウンドでインタラクティブ OAuth を実行。長いログインがクライアントの約 60 秒のタイムアウトを超えない |
| `--oauth-refresh-leeway SECONDS` | `MCP_OAUTH_REFRESH_LEEWAY` | トークン有効期限の何秒前にプロアクティブにリフレッシュするか（デフォルト: 60） |
| `--no-proactive-refresh` | — | OAuth トークンをプロアクティブにリフレッシュするバックグラウンドタイマーを無効化 |
| `--oauth-timeout SECONDS` | — | インタラクティブ OAuth フロー（ブラウザコールバック/デバイスコード確認）がタイムアウトするまでの秒数（デフォルト: 120） |
| `--no-resource-indicator` | — | すべての OAuth リクエストから RFC 8707 resource パラメータを省略。それを拒否する認可サーバー用（例：api:// スコープ付き Microsoft Entra ID） |

### トランスポート

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `--transport {streamable-http,sse}` | `streamable-http` | トランスポートタイプ（Streamable HTTP は現在の MCP 仕様; SSE はレガシー 2024-11-05） |
| `--timeout-connect SEC` | 10 | 接続タイムアウト（秒） |
| `--timeout-read SEC` | 120 | 読み取りタイムアウト（秒） |
| `--sse-read-timeout SEC` | 300 | SSE GET ストリームのアイドル読み取りタイムアウト（SSE トランスポートのみ; 0 で無効化） |
| `--no-tcp-keepalive` | — | HTTP ソケット上の TCP キープアライブを無効化 |

### ヘッダー & プロキシ

| フラグ | 説明 |
|--------|------|
| `-H, --header 'Key: Value'` | カスタムヘッダー（繰り返し可能）；ヘッダーはすべてのリクエストに含まれます |
| — | プロキシは標準の `HTTP_PROXY`、`HTTPS_PROXY`、`NO_PROXY` 環境変数で認識されます |

### 動作

| フラグ | 説明 |
|--------|------|
| `--no-cancel-filter` | キャンセル認識レスポンスフィルターを無効化（notifications/cancelled 経由でキャンセルされたID の遅いレスポンスを削除） |
| `--no-normalize-arguments` | tools/call リクエストの arguments:null を {} に書き直して転送することを無効化 |

### ユーティリティ

| フラグ | 説明 |
|--------|------|
| `--check` | 接続をチェックして終了。全体パスを一度実行：発見、OAuth ログイン（該当する場合）、トークン交換、MCP initialize ラウンドトリップ |
| `-V, --version` | バージョンを表示 |
| `-h, --help` | ヘルプを表示 |

`mcp-stdio --help` を実行して、プラットフォーム固有の注記と issue リファレンスを含む完全なフラグごとの詳細を表示します。

---

## Serve モード

`mcp-stdio serve` はローカル stdio MCP サーバーを Streamable HTTP エンドポイントとして公開します。詳細な設定は [サーバーを公開する](guides/serve.md) を参照してください。

### 基本的な使い方

```bash
mcp-stdio serve [OPTIONS] -- COMMAND [ARGS...]

Arguments:
  COMMAND [ARGS...]    バックエンドコマンドをスポーン（例：python -m my_mcp_server）
```

### サーバー設定

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `--host HOST` | `127.0.0.1` | バインドアドレス |
| `--port PORT` | `8080` | バインドポート |
| `--path PATH` | `/mcp` | HTTP エンドポイントパス |

### 認証

| フラグ | 環境変数 | 説明 |
|--------|---------|------|
| `--auth-token TOKEN` | `MCP_STDIO_SERVE_TOKEN` | 静的ベアラートークン（OAuth リソースサーバーとして機能；オプション） |
| `--enable-oauth` | — | 組み込み OAuth 2.1 認可サーバーを有効化（PKCE auth-code、DCR、リフレッシュ） |
| `--public-url URL` | — | issuer と well-known ドキュメントをピンするパブリック HTTPS URL（リバースプロキシの背後にある場合は必須） |
| `--trusted-user-header HEADER` | — | 認証済みユーザーを含む HTTP ヘッダー名（フロントプロキシがクライアント提供のコピーをストリップするため信頼） |
| `--dev-user USER` | — | **非セキュア、テスト用のみ。** 実際の SSO なしでループバックテスト用のスタンドイン user identity |
| `--access-token-ttl SECONDS` | `3600` | アクセストークンライフタイム（秒） |
| `--allow-redirect-uri URL` | — | Dynamic Client Registration で信頼する追加リダイレクト URI（繰り返し可能；例：ウェブベースのクライアント用 `https://claude.ai/api/mcp/auth_callback`） |
| `--token-store PATH` | — | 発行済みトークン、登録、リプレイ墓石を永続化するパス。再起動時にサーバーが生存し、クライアントは有効なトークンを保持します。各 serve プロセスは独自のパスを持つ必要があります。ファイルは `0600` で作成；秘密鍵のように扱います |

### セッション管理

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `--max-sessions N` | `100` | 最大同時セッション数；上限を超えた initialize は `503` を取得します |
| `--session-idle-ttl SECONDS` | `0`（無効） | アイドルタイムアウト；非アクティブ後にセッションと子を削除。DELETE なしで接続を切ったクライアントがスロットをピンしない |

---

## 標準準拠

mcp-stdio は以下の仕様を実装しています：

### MCP（Model Context Protocol）

- [MCP 2025-11-25 仕様](https://modelcontextprotocol.io/specification/2025-11-25/)
  - Streamable HTTP トランスポート（現在）
  - SSE トランスポート（レガシー、MCP 2024-11-05）
  - 認可仕様

### OAuth 2.1 & OpenID Connect

- [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) 保護リソースメタデータ
  - §3 `/.well-known/oauth-protected-resource` 経由の認可サーバー発見
  - §3.1 パス認識 well-known URL 構築（パスベースのリバースプロキシデプロイメント向け）
  - §3.3 resource フィールド検証
  - §5.1 `WWW-Authenticate: Bearer resource_metadata=` ヒント

- [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) 認可サーバーメタデータ
  - §3.1 well-known URL 構築、path コンポーネント付き issuer 向けパス挿入を含む
  - §3.3 issuer 検証（クロスオリジンガード、同一オリジン不一致警告）
  - §3 OpenID Connect Discovery 1.0 フォールバック

- [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) リソースインジケータ
  - §2 認可、トークン交換、**およびリフレッシュ**リクエストの resource パラメータ

- [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) PKCE
  - §4.1–4.2 S256 code_challenge_method と 86 文字の code_verifier

- [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) デバイス認可グラント
  - §3.1 resource インジケータ付きデバイス認可リクエスト
  - §3.4–3.5 authorization_pending、slow_down、expired_token、access_denied 処理を使用したトークンポーリング

- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) Dynamic Client Registration
  - §3 クライアント登録リクエスト；token_endpoint_auth_method は AS メタデータから選択
  - §3.2.1 client_secret_expires_at 処理（有効期限切れ時は自動再登録）
  - application_type: RFC 8252 §8.4 に従う "native"

- [クライアント ID メタデータドキュメント](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#client-id-metadata-documents)
  - MCP 2025-11-25 / draft-ietf-oauth-client-id-metadata-document-00
  - --client-metadata-url はオペレータホストの HTTPS ドキュメントを client_id として提示

- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) OAuth 2.0
  - §2.3.1 client_secret_basic（percent エンコードされた認証情報による Authorization ヘッダー）

- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) ベアラートークン使用
  - §2.1 Authorization: Bearer リクエストヘッダー

### HTTP & レジリエンス

- [RFC 7230](https://www.rfc-editor.org/rfc/rfc7230) HTTP/1.1 メッセージ構文とルーティング
  - Retry-After ヘッダーの解析（delta-seconds および HTTP-date 形式）

- HTTP 429（Too Many Requests）および 503（Service Unavailable）— 最大 60 秒まで Retry-After を尊重

- 接続エラーに対する自動リトライと指数バックオフ（最大 3 回のリトライ）

### WHATWG サーバー送信イベント

- [Server-Sent Events 標準](https://html.spec.whatwg.org/multipage/server-sent-events.html)
  - レガシー MCP サーバー向け SSE パーサー

---

## 既知の制限

以下の既知の問題については [WORKAROUNDS.md](https://github.com/shigechika/mcp-stdio/blob/main/WORKAROUNDS.md) を参照してください：

- Claude Code の HTTP トランスポート
- mcp-remote（TypeScript MCP クライアント）
- MCP SDK（TypeScript & Python）
- Windows stdio 処理

mcp-stdio は可能な限りワイヤーレベルでこれらの問題を回避します。

---

## ファイルの場所

| コンポーネント | 場所 | パーミッション |
|--------------|------|---------------|
| OAuth トークンキャッシュ | `~/.config/mcp-stdio/tokens.json` | `0600` |
| Serve モード トークンストア | （`--token-store` 経由でユーザー指定） | `0600` |

---

## 環境変数

| 変数 | 目的 |
|------|------|
| `MCP_BEARER_TOKEN` | クライアントモード用の静的ベアラートークン |
| `MCP_OAUTH_CLIENT_ID` | 事前登録済み OAuth クライアント ID |
| `MCP_OAUTH_REFRESH_LEEWAY` | トークン有効期限の何秒前にリフレッシュを開始するか（デフォルト: 60） |
| `MCP_STDIO_SERVE_TOKEN` | Serve モード用の静的ベアラートークン |
| `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` | 標準プロキシ設定 |

---

## 終了コード

| コード | 意味 |
|--------|------|
| `0` | 成功 |
| `1` | 一般エラー（無効な引数、接続失敗など） |
| `2` | OAuth タイムアウトまたはユーザーがキャンセル |

---

## ログ

- すべてのエラーと診断情報は stderr に書き込まれます
- リモートサーバーへのリクエストはクエリ文字列を編集してログされます
- トークン交換の詳細は詳細出力でログされます
