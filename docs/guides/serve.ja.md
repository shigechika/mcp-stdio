# stdio サーバーを公開する

ゴール：ホスト上の stdio MCP サーバーを HTTPS の Streamable HTTP
エンドポイントにして、リモートの MCP クライアント——Claude Desktop、
Claude Code、さらに Claude.ai のカスタムコネクタ——から使えるようにする。
各ユーザーは専用の子プロセスに隔離され、本物の OAuth 2.1 ログインで
守られます。

## 1. ループバックで動作確認

```bash
mcp-stdio serve --enable-oauth --public-url http://127.0.0.1:8080 \
  --dev-user alice --port 8080 -- python -m my_mcp_server
```

別のターミナルから、mcp-stdio 自身のクライアントモードで接続します：

```bash
mcp-stdio --check --oauth http://127.0.0.1:8080/mcp
```

`--dev-user` はループバック検証専用の**非セキュアな**代用アイデンティティ
です——本物のログインなしで OAuth フロー全体を通せます。`--check` が
`initialize` 成功を報告すればゲートウェイは動いています。ここから先は
デプロイの話だけです。

## 2. リバースプロキシの背後にデプロイ

本番ではアイデンティティは SSO から来ます。TLS 終端と認証はリバース
プロキシ（nginx、Apache など）に任せ、ログイン済みユーザーを信頼できる
ヘッダーで mcp-stdio に渡します：

```bash
mcp-stdio serve --enable-oauth \
  --public-url https://mcp.example.com \
  --trusted-user-header X-Forwarded-User \
  --token-store /var/lib/mcp-stdio/state.json \
  --session-idle-ttl 180 \
  -- python -m my_mcp_server
```

- `--public-url` は OAuth issuer を公開アドレスに固定します（プロキシ
  背後では強く推奨。無くても起動はしますが、クライアントには内部の
  アドレスが見えてしまいます）。
- `--trusted-user-header` はプロキシが設定し、**かつクライアント由来の
  同名ヘッダーを剥がす**ヘッダー名です——その剥がしこそが信頼の根拠です。
- `--token-store` は発行済みトークン・クライアント登録・replay 検知の
  台帳を永続化（`0600`）し、**再起動やデプロイで全ユーザーがログアウト
  されるのを防ぎます**。これがないとデプロイのたびに全トークンが無効に。
  パスは serve プロセスごとに 1 つ——sidecar の `.lock` が誤共有を起動時に
  拒否します。
- `--session-idle-ttl` は、切断処理なしに消えたクライアントの子プロセスを
  回収します。

接続ユーザーごとに得られるもの：専用の子プロセス（`initialize` で
spawn、切断か idle タイムアウトで破棄）、認証済みアイデンティティに
束縛されたセッション——他人のセッション id を提示しても `404` で、
越境はできません。

## 3. オプションの追加機能

| こうしたい | こうする |
|---|---|
| Claude.ai カスタムコネクタ（ブラウザベースのクライアント） | `--allow-client-id-url https://claude.ai/oauth/mcp-oauth-client-metadata`。claude.ai はこの Client ID Metadata Document の URL を client_id として名乗るようになります。「ログインなし（No sign-in）」の設定では常にこの方式です（#463）。従来の `--allow-redirect-uri https://claude.ai/api/mcp/auth_callback` で足りるのは、claude.ai が Dynamic Client Registration にフォールバックした場合だけです |
| 1 ホストに複数バックエンド | バックエンドごとに serve プロセスを分け、パススコープ issuer を使う：`--public-url https://mcp.example.com/team-a`、`…/team-b`——AS エンドポイントと well-known もプレフィックス配下に収まります。claude.ai のカスタムコネクタには使えません。claude.ai は現在、パスがちょうど `/mcp` でないエンドポイントへの接続を完了できないため（トークン発行後に MCP のリクエストが途絶える：[anthropics/claude-ai-mcp#878](https://github.com/anthropics/claude-ai-mcp/issues/878)、複数階層のパスでは 1 件も届かない：[#738](https://github.com/anthropics/claude-ai-mcp/issues/738)）、その場合はバックエンドごとにホスト名を分けてください |
| 同時ユーザー数の上限 | `--max-sessions N`（既定 100。超過した `initialize` は `503`） |
| OAuth の代わりに静的トークン | `--enable-oauth` を外して `MCP_STDIO_SERVE_TOKEN` を設定 |
| アクセストークンの寿命を調整 | `--access-token-ttl SECONDS`（既定 3600） |

## 運用者向けメモ

- 内蔵の認可サーバーは Dynamic Client Registration、PKCE（S256 のみ）、
  replay 検知付き refresh ローテーション、RFC 8707 の audience 束縛を
  実装しています。MCP クライアントは標準の well-known ドキュメント経由で
  すべてを自動発見するので、クライアント側の設定は不要です。
- Client ID Metadata Document（`--allow-client-id-url`、#463）はオプトインで、
  許可リスト方式です。取得するのは登録した URL だけで、`/authorize` の時点で
  HTTPS により公開アドレスから取得します（プライベート・ループバックなどの
  特殊用途アドレスは拒否）。リダイレクトは追わず、5 KB を上限とします。
  文書自身の `redirect_uris` がそのクライアントの登録になります（https は
  完全一致、ループバックはポートを問わず一致）。文書は自分の URL を
  `client_id` として名乗り、`client_name` を持ち、`token_endpoint_auth_method`
  が `none` である必要があります（`private_key_jwt` は未対応）。キャッシュ期間は
  `Cache-Control: max-age`（60 秒〜24 時間。指定がなければ 1 時間）です。
  再取得がネットワークの段階で失敗したときは、以前に検証済みの写しを最大
  24 時間まで延長して使います。取得はできたが検証に通らなくなった文書は
  直ちに拒否します。登録があるときは AS メタデータで
  `client_id_metadata_document_supported: true` を広告します。
- `--token-store` のファイルは秘密鍵と同様に扱ってください。`0700` の
  ディレクトリに `0600` で作成されます。
- 全リクエストはクエリ文字列を redact した形で stderr にログされます。
- `Mcp-Param-*` ヘッダ（ツールの `x-mcp-header` で指定された引数。MCP 2026-07-28）は受け取って無視します。stdio の子プロセスは HTTP ヘッダを見ないので、検証しない中継者はそのまま通してよいと仕様で認められています。serve がこれを理由に `-32020` を返すことはありません。
- MCP エンドポイントのパスとトークンの audience は、大文字・小文字を区別せずに照合します。コネクタの URL を大文字に書き換えるクライアント（claude.ai は `https://mcp.example.com/mcp` を `https://MCP.EXAMPLE.COM/MCP` として保存することがあります）でも接続できます。ただし前段にリバースプロキシがある場合は、大文字のパスもそのまま転送する設定が必要です（#456）。
- ブラウザからのリクエストは `Origin` ヘッダーで検証します（DNS rebinding
  対策、#449）。自分のホスト名を `127.0.0.1` に向け直した Web ページから、
  ループバックのゲートウェイを操作することはできません（認証なしの場合でも）。
  ループバックのオリジン（`localhost`、`*.localhost`、`127.0.0.0/8`、`[::1]`）と
  `--public-url` のオリジンは受け付けます。それ以外のブラウザのクライアントは
  `--allow-origin https://app.example.com`、ブラウザ拡張なら
  `--allow-origin chrome-extension://<id>` で追加してください（繰り返し指定可、
  完全一致）。それ以外には `403` を返します。`Origin` を送らないクライアント
  （Claude Code、Claude Desktop、mcp-stdio の relay、SDK のクライアント）には
  影響しません。`--allow-origin` はこの検証を緩めるだけで、serve は CORS
  ヘッダーを返さないため、別オリジンのブラウザクライアントには CORS ヘッダーを
  付けるプロキシも必要です。
- セッション処理は厳密かつライフサイクル準拠です：リクエストは
  `Mcp-Session-Id` のみでルーティングされ（JSON-RPC のリクエスト id では
  相関しません）、各セッションは専用の子プロセスを持ちます。新しい
  `initialize` は新規セッションを発行し、未知または終了済みの id は `404` を
  返してクリーンな再初期化を促します。応答はセッション内で JSON-RPC id に
  よって相関され、クロスワイヤは起きません：id を*逐次*再利用する
  クライアントは正しく対応付けられ、同一セッション上で既に*未処理*の id を
  **異なるペイロードで**再利用した 2 本目のリクエストは、誤った応答を配送する
  代わりに拒否されます（MCP は request id をセッション内で一意にするよう
  要求するため `409`。この拒否は衝突した id と両リクエストの method とともに
  stderr へログされます）。一方、最初のリクエストがまだ未処理のうちに**同一の**
  ペイロード（パース後の JSON として比較するため、キー順の異なる再
  シリアライズもマッチします）で同じ id のリクエストが届いた場合——再起動や
  アイドル回収の直後にクライアントの再接続バーストが自分自身と衝突する
  リクエストを再送してくる典型的なケース——はリトライとして扱われ、処理中の
  リクエストに便乗して、応答到着時に待機しているすべての waiter が同じ
  `200` 応答を受け取ります（`409` にはなりません）。注意点が 2 つあります：
  各 waiter は自分のタイムアウト期限を保持するため、共有応答の到着前に期限が
  切れた呼び出し側だけは自身の `504` を受け取ります（後から便乗したリトライは
  成功し得ます）。また、最初のリクエストの**完了直後**に届いたリトライは
  正当な逐次 id 再利用と区別できないため、新規リクエストとして再送されます——
  非冪等な呼び出しでこのウィンドウの重複排除に依存しないでください。なお、
  毎回新しいセッション id を発行するクライアントに状態を保持させることは
  できません——それはクライアント自身の挙動です。

実運用の参照例：この構成そのままで、1 ホスト配下に複数の stdio MCP
サーバーを公開し、定常的な再デプロイをユーザーに気づかれずに乗り切って
います。子プロセスの*内側*でユーザーごとの資格情報が必要なら、それは
あなたのサーバーの設計判断です——ゲートウェイは意図的にアイデンティティを
子へ注入しません。
