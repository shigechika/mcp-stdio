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
| `--oauth-scope SCOPE` | — | リクエストする OAuth スコープ。複数指定する場合は1つの値の中でスペース区切り（例：`"openid offline_access"`）。付与されたスコープが以前に付与されたものと異なる場合（例：ダウングレード）、mcp-stdio は `authorization server granted scope: …` を stderr にログ出力します（変化しないリフレッシュでは出力しません） |
| `--oauth-use-id-token` | — | アクセストークンの代わりに OIDC id_token をベアラー認証情報として提示（AWS Bedrock / Cognito） |
| `--oauth-eager` | — | コールドスタート：initialize をローカルで応答し、バックグラウンドでインタラクティブ OAuth を実行。長いログインがクライアントの約 60 秒のタイムアウトを超えない |
| `--oauth-refresh-leeway SECONDS` | `MCP_OAUTH_REFRESH_LEEWAY` | トークン有効期限の何秒前にプロアクティブにリフレッシュするか（デフォルト: 60） |
| `--no-proactive-refresh` | — | OAuth トークンをプロアクティブにリフレッシュするバックグラウンドタイマーを無効化 |
| `--oauth-timeout SECONDS` | — | インタラクティブ OAuth フロー（ブラウザコールバック/デバイスコード確認）がタイムアウトするまでの秒数（デフォルト: 120） |
| `--no-resource-indicator` | — | すべての OAuth リクエストから RFC 8707 resource パラメータを省略。それを拒否する認可サーバー用（例：api:// スコープ付き Microsoft Entra ID） |
| `--oauth-resource URI` | — | server-URL 由来の値の代わりに、この RFC 8707 resource 値をすべての OAuth リクエストで送る。特定の resource 識別子を要求する AS（例：Entra ID の App ID URI `api://<app-id>`）用。トークンストアに永続化。`--no-resource-indicator` とは排他 |

### トランスポート

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `--transport {streamable-http,sse}` | `streamable-http` | トランスポートタイプ（Streamable HTTP は現在の MCP 仕様; SSE はレガシー 2024-11-05） |
| `--timeout-connect SEC` | 10 | 接続タイムアウト（秒） |
| `--timeout-read SEC` | 120 | 読み取りタイムアウト（秒） |
| `--sse-read-timeout SEC` | 300 | SSE GET ストリームのアイドル読み取りタイムアウト（SSE トランスポートのみ; 0 で無効化） |
| `--no-tcp-keepalive` | — | HTTP ソケット上の TCP キープアライブを無効化 |

<a id="modern-era-client"></a>

### 新しい MCP サーバー向け（2026-07-28）

接続先が新しい MCP 仕様で作られたサーバーのときだけ必要です。
[新しい MCP のサーバーを使う](modes.md#protocol-eras) を参照。

| フラグ | デフォルト | 説明 |
|------|---------|-------------|
| `--protocol-era {legacy,modern,auto}` | `legacy` | 相手のサーバーとの話し方。`legacy` はこれまでとまったく同じ。`auto` は起動時に一度だけ尋ねて自動判別する。`modern` は新しいサーバーだと分かっているとき、尋ねる手間を省く。`--transport sse` では警告を出して無視される |
| `--listen-read-timeout SEC` | `300` | 通知用の接続が無言のまま何秒待ったら再接続するか。新しいサーバー相手のときだけ使われる。`--sse-read-timeout` と違い `0`（無効化）は指定できない——この接続には必ずタイムアウトが要るため。`--transport sse` では警告なしに無視される |

!!! note "`--check` で分かること・分からないこと"
    `--check` はどちらのサーバーでも到達性を確認できます。従来の
    ハンドシェイクが拒否された場合は、新しいサーバー向けのやり方で
    もう一度試すので、新しいサーバー専用でも ✓ と表示されます。ただし
    あくまで疎通確認で、通知用の長時間接続など、新しい動作の残りまでは
    確かめません。


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
| `--public-url URL` | — | issuer と well-known ドキュメントをピンするパブリック HTTPS URL（リバースプロキシの背後では強く推奨。省略しても serve は起動する） |
| `--trusted-user-header HEADER` | — | 認証済みユーザーを含む HTTP ヘッダー名（フロントプロキシがクライアント提供のコピーをストリップするため信頼） |
| `--dev-user USER` | — | **非セキュア、テスト用のみ。** 実際の SSO なしでループバックテスト用のスタンドイン user identity |
| `--access-token-ttl SECONDS` | `3600` | アクセストークンライフタイム（秒） |
| `--allow-redirect-uri URL` | — | Dynamic Client Registration で信頼する追加リダイレクト URI（繰り返し可能；例：ウェブベースのクライアント用 `https://claude.ai/api/mcp/auth_callback`） |
| `--token-store PATH` | — | 発行済みトークン、登録、リプレイ墓石を永続化するパス。再起動時にサーバーが生存し、クライアントは有効なトークンを保持します。各 serve プロセスは独自のパスを持つ必要があります。ファイルは `0600` で作成；秘密鍵のように扱います |

### セッション管理

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `--max-sessions N` | `100` | 最大同時セッション数；上限を超えた initialize は `503` を取得します |
| `--session-idle-ttl SECONDS` | `0`（無効） | 古いクライアントのセッション向け（新しいクライアントには `--modern-idle-ttl`）。 アイドルタイムアウト；非アクティブ後にセッションと子を削除。DELETE なしで接続を切ったクライアントがスロットをピンしない |
| `--max-sessions-per-owner N` | `0`（無効） | 新しい initialize 時に、その OAuth ユーザーの古いセッションを `N` 件まで LRU で削除し、DELETE せず再接続するクライアントが残したゴーストを回収。static-token と open-gateway のセッションは対象外 |

<a id="modern-era-serve"></a>

### 新しい MCP クライアント向け（2026-07-28）

有効化の設定は要りません。`serve` は同じアドレスで新旧どちらの
クライアントにも自動で応答します。ここのフラグは、キャッシュの伝え方、
遊んでいるバックエンドの後始末、そして（望むなら）古いクライアントを
締め出すかどうかを調整します。

| フラグ | デフォルト | 説明 |
|------|---------|-------------|
| `--cache-ttl-ms MS` | `60000` | 新しいクライアントが `tools/list` などの一覧系の結果を何ミリ秒キャッシュしてよいか。`0` にすると「キャッシュしないで」と伝える。結果は常に非共有（ユーザー間で使い回さない）扱い。ツール実行の結果はキャッシュ対象外 |
| `--modern-idle-ttl SECONDS` | `0`（無効） | 新しいクライアント向けのバックエンドを、リクエストが無いまま何秒経ったら終了させるか。短めに設定して構いません——それらのクライアントは状態を持たないので、次回は新しいバックエンドが立ち上がるだけです。処理中のバックエンドが終了させられることはありません。古いクライアント向けの `--session-idle-ttl` とは別のつまみです |
| `--modern-only` | 無効 | 新しいクライアント**だけ**に応答します。古いクライアントにはセッションを渡さず追い返します：`GET` と `DELETE` には `405`、古いクライアントの `initialize` にはこのエンドポイントが対応するバージョンを示すエラーを返します。OAuth のディスカバリ用エンドポイントは動き続けるので、ログインの入口は塞がりません |

新しいクライアントは、ツール・プロンプト・リソースの一覧が変わったことや、
名指しした個別リソースの更新を受け取るための長時間接続も開けます（→
[一覧が変わったことをクライアントに伝える](modes.md#listchanged-serve)）。
どちらにもフラグはありません。同時に開ける本数はバックエンド単位で
**4 本**まで——`--enable-oauth` を使っている場合はこれが認証ユーザーごとの
上限になります。認証なし、または `--auth-token` を共有している場合は
全クライアントが 1 つのバックエンドを共有するため、4 本という上限は
ゲートウェイ全体での合計になります。5 本目はどのクライアントからの
接続であっても、待たせずにその場で断ります。1 接続あたり個別のリソース
URI は **256 件**まで監視でき、超過分は切り捨てて実際に受け付けた URI を
クライアントに返します。各接続は 15 秒ごとにコメントを送るのでプロキシに
切られにくく、接続が付いているバックエンドが `--modern-idle-ttl` で
回収されることはありません。

`--modern-idle-ttl` は最後の*リクエスト*からの経過時間を見ますが、
長時間接続は「終わらないリクエスト」なので、接続を開き続けている
ユーザーのバックエンドは生き続けます。これは意図した挙動です。


---

## 標準準拠

mcp-stdio は以下の仕様を実装しています：

### MCP（Model Context Protocol）

- Streamable HTTP トランスポート（現行、spec rev 2025-06-18）— `initialize` でネゴシエートされた `MCP-Protocol-Version` を以後のすべてのリクエストに付与
- Streamable HTTP transport、仕様リビジョン **2026-07-28** —— ケーパビリティの探索、リクエストごとのメタデータとヘッダ、セッション不要のリクエスト、一覧結果のキャッシュ指示、通知用の長時間接続（クライアント側と、`serve` 側も一覧変更通知および URI 単位のリソース購読に対応）、処理中のクライアントへの問い合わせ。クライアント側は `--protocol-era` でオプトイン。`serve` はひとつのエンドポイントで両方のリビジョンに応答する。python-sdk v2.0.0 に対して双方向で相互運用性を検証済み
- SSE トランスポート（レガシー、MCP 2024-11-05）
- クライアント ID メタデータドキュメント（MCP 2025-11-25 のドラフト拡張）— 詳細は下記 OAuth セクションを参照

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

- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) HTTP セマンティクス
  - §10.2.3 `Retry-After` ヘッダーの解析（delta-seconds および HTTP-date 形式；旧 RFC 7231 §7.1.3）

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

<a id="env-vars"></a>

## 環境変数

| 変数 | 目的 |
|------|------|
| `MCP_BEARER_TOKEN` | クライアントモード用の静的ベアラートークン |
| `MCP_OAUTH_CLIENT_ID` | 事前登録済み OAuth クライアント ID |
| `MCP_OAUTH_REFRESH_LEEWAY` | トークン有効期限の何秒前にリフレッシュを開始するか（デフォルト: 60） |
| `MCP_STDIO_SERVE_TOKEN` | Serve モード用の静的ベアラートークン |
| `MCP_STDIO_MRTR_STRIP` | `1` を設定すると、modern era のリモートに対してクライアントの `sampling` / `elicitation` / `roots` ケーパビリティを広告しなくなり、multi round-trip requests（MRTR）パターンを使う「招待」を取り下げる。既定では MRTR をブリッジするため、これは緊急回避用。設定してもブリッジ自体は無効化されない（送ってきたサーバーには応答する） |
| `MCP_STDIO_MRTR_REVERSE_ENABLE` | `1` を設定すると、`serve` で公開した古いサーバーが呼び出しの途中で新しいクライアントに何かを尋ねられるようになる——入力の要求、sampling の依頼、roots の一覧取得——を MRTR 経由で行う、上記 `MCP_STDIO_MRTR_STRIP` の逆方向。既定は無効。OAuth 認証済みの呼び出し元にしかブリッジしない。詳細は[サーバーからの mid-call な問い合わせに答える](modes.md#mid-call-serve)を参照 |
| `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` | 標準プロキシ設定 |

---

## 終了コード

| コード | 意味 |
|--------|------|
| `0` | 成功 |
| `1` | 実行時エラー（接続失敗、OAuth 認証失敗、起動時に検出された設定不備など） |
| `2` | コマンドライン引数が不正（標準的な `argparse` の使用方法エラー） |
| `130` | 中断（Ctrl-C / `SIGINT`） |

---

## ログ

- 診断情報はすべて stderr に書き込まれます。relay 自身の接続・リトライ・再接続メッセージには `[mcp-stdio]` プレフィックスが付きますが、起動時や OAuth のエラー・警告メッセージは `error: ...` / `warning: ...` という素のプレフィックスで出力されます
- 現時点で個別の verbose/debug ログモードはありません — 上記の stderr 出力がすべてです
