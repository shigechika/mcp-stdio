# トラブルシューティング

よくある問題と解決方法です。Claude Code、mcp-remote、MCP SDK の既知の回避方法の完全なリストは [WORKAROUNDS.md](https://github.com/shigechika/mcp-stdio/blob/main/WORKAROUNDS.md) を参照してください。

## 接続の問題

### OAuth ログイン時にブラウザが開かない

**問題：** `mcp-stdio --oauth` を実行しましたが、ブラウザウィンドウが開きません。

**解決方法：**
1. 標準エラー出力（stderr）を確認してください。ブラウザが自動的に開くかどうかにかかわらず、mcp-stdio は認可 URL を常にそこへ出力します。
2. その URL をブラウザに手動で貼り付けます。
3. ログインフローを完了してください。認可コードはループバックコールバックで取得されます。

### `401 Unauthorized` — 「昨日は動いていたのに今日は動かない」

**問題：** 接続は正常に機能していましたが、今日は `401` エラーが表示されます。

**原因：** サーバーがキーをローテーションしたか、グラントを取り消した可能性があります。

**解決方法：**
キャッシュされたトークンを削除して再認可してください：

```bash
rm ~/.config/mcp-stdio/tokens.json
```

その後、クライアントを再度実行してください。初回利用時にブラウザが開いてログインを求められます。以後はトークンがキャッシュされ、自動的にリフレッシュされます。

### リフレッシュトークンが有効なのに「接続の有効期限切れ」が繰り返される

**問題：** `mcp-stdio` は有効なリフレッシュトークンを保持しているのに、MCP クライアント側は繰り返し接続を期限切れとして報告します。

**原因：** mcp-stdio はデフォルトでアクセストークンの有効期限が切れる少し前にプロアクティブにリフレッシュします（`--oauth-refresh-leeway`、デフォルト 60 秒）。ただしこれが効くのは、MCP クライアントが `mcp-stdio` 経由の接続を実際に使い回している場合に限られます。

**解決方法：**
1. `--no-proactive-refresh` を渡していないことを確認してください（プロアクティブリフレッシュはデフォルトで有効です）。
2. サーバーが有効期限切れをトランスポートレベルの `401` ではなく HTTP 200 応答＋ツール結果のエラーで通知する場合（一部のエンタープライズ MCP ゲートウェイなど）、mcp-stdio はリアクティブには検知できないことがあります。プロアクティブリフレッシュが主な防御策です。それでも古いセッションが残る場合は、ゲートウェイの挙動とあわせて [issue を作成](https://github.com/shigechika/mcp-stdio/issues/new)してください（このクラスの問題の最初の報告は [shigechika/mcp-stdio#242](https://github.com/shigechika/mcp-stdio/issues/242) を参照）。
3. サーバーが `expires_in` を一切送信しない場合は、前置時間を明示的に設定します：
   ```bash
   mcp-stdio --oauth --oauth-refresh-leeway 300 https://your-server.example.com/mcp
   ```

一部の MCP クライアントには、セッション途中でトークンが失効しても認証ヘッダーのコールバックを再実行しないという既知の問題があります（Claude Code の [#53267](https://github.com/anthropics/claude-code/issues/53267)、[#65036](https://github.com/anthropics/claude-code/issues/65036) を参照）。mcp-stdio のプロアクティブ／リアクティブなリフレッシュは、まさにこのクラスの問題を回避するために存在します。トークンのライフサイクル全体を MCP クライアントではなく mcp-stdio 自身が管理しているためです。

### Microsoft Entra ID で `AADSTS9010010`

**問題：** `api://` スコープを使う Microsoft Entra ID 経由の接続で、認可が `AADSTS9010010`（audience 検証失敗）で失敗します。

**原因：** 一部の Entra ID 構成は RFC 8707 の `resource` パラメータそのものを拒否します。

**解決方法：**
```bash
mcp-stdio --oauth --no-resource-indicator https://your-server.example.com/mcp
```

これにより、認可・トークン交換・リフレッシュ・デバイスフローのすべての OAuth リクエストから `resource` パラメータが省略されます。

## ツールとリソースの問題

### 最初のページ以降のツールが見えない

**問題：** 数十個のツールが定義されていますが、クライアントには最初の約 20 個だけが表示されます。

**原因：** Claude Code は最初の `tools/list` リクエストのみを送信し、`nextCursor` を無視するため、2 ページ目以降のツールはクライアントに届きません。

**解決方法：**
設定は不要です。mcp-stdio は Streamable HTTP トランスポート上で `tools/list`・`resources/list`・`resources/templates/list`・`prompts/list` の `nextCursor` を透過的に辿り、すべてのページを 1 つのレスポンスにまとめてからクライアントに渡します。ただし `--transport sse`（レガシートランスポート）では自動ページネーションされないため、その場合はツール総数を 1 ページ以内に収めてください。

Claude Code の [#39586](https://github.com/anthropics/claude-code/issues/39586) を参照。

### 接続直後は成功するのに `tools/list` が「Invalid session ID」で失敗する

**問題：** 接続は確立され `initialize` も成功しますが、続く `tools/list` やツール呼び出しがセッション不正・不明として拒否されます。

**原因：** 一部の MCP クライアント（一部の Claude Code バージョンを含む）は、`initialize` で返された `Mcp-Session-Id` ヘッダーを以後のリクエストでエコーバックしません。そのため mcp-grafana や mcp-go のようなセッション対応サーバーが拒否します。

**解決方法：**
設定は不要です。mcp-stdio は `initialize` のレスポンス自身から `Mcp-Session-Id` を取得し、MCP クライアントの挙動にかかわらず以後のすべてのリクエストに付与します。それでも発生する場合は、サーバー側でセッションが本当に失効している可能性があります。クライアントを再起動して新しい `initialize` を強制してください。

Claude Code の [#70386](https://github.com/anthropics/claude-code/issues/70386) を参照。

### 短時間のネットワーク断や再接続後にツールが消える

**問題：** ツールは正常にリストされていたのに、短い切断・再接続の後に動かなくなる、あるいはリストから消える。

**原因：** MCP セッションが失われた（バックエンドサーバーの再起動、接続の中断など）か、一部の Claude Code バージョンでは Streamable HTTP の再接続処理自体に regression があったことがあります。

**解決方法：**
1. mcp-stdio はサーバーからの `404`（セッション未検出）応答を受けて自動的にセッションを再初期化します。
2. それでもツールが利用できない場合は、MCP クライアント（Claude Desktop / Claude Code）を再起動して新しいセッションを強制してください。

Claude Code の [#34498](https://github.com/anthropics/claude-code/issues/34498)、[#38631](https://github.com/anthropics/claude-code/issues/38631) を参照。

## 認証の問題

### スタティック Bearer トークンが送信されない

**問題：** `--bearer-token` または `MCP_BEARER_TOKEN` を設定しましたが、サーバーはトークンがないか無効だと報告します。

**原因：** mcp-stdio はすべての送信リクエストの `Authorization` ヘッダーにトークンを付与します。拒否される場合は、トークンが誤っている・失効している、あるいはサーバーが `Authorization` ヘッダー以外の場所（クエリパラメータや独自ヘッダーなど）で資格情報を期待している可能性が高いです。

**解決方法：**
1. トークンが正しく、有効期限が切れていないことを確認してください。
2. サーバーの認証ドキュメントを確認し、`Authorization: Bearer` ヘッダーを期待しているか確認してください。異なるヘッダーを期待する場合は `-H 'ヘッダー名: 値'` で明示的に渡してください。
3. mcp-stdio をフォアグラウンドで実行し、stderr で接続・リトライの診断出力を確認してください。

### OAuth スコープが反映されない

**問題：** `--oauth-scope` でスコープをリクエストしましたが、サーバーはまだスコープ不足と訴えています。

**原因：** 認可サーバーがリクエストされたスコープを拒否し、より小さいものを付与した可能性があります。

**解決方法：**
1. 実際に付与されたスコープは、認可サーバー自身のログや管理コンソールで確認してください。mcp-stdio 自体は現時点で付与されたスコープを出力しません。
2. サーバーがスコープをダウングレードした場合は、認可サーバーのポリシーを確認するか、サーバーオペレーターに連絡してください。
3. 一部のサーバーは**ステップアップ認可**をサポートしています。ツール呼び出しがより広いスコープを必要とする場合、サーバーは `403 insufficient_scope` とともに必要なスコープを返し、mcp-stdio は付与済みスコープと必要スコープの和集合で自動的に再認可（RFC 9470）してから呼び出しを再試行します。一部の MCP クライアントは、mcp-stdio がバックグラウンドでステップアップを完了した後にツール呼び出しを自動再試行しません（Claude Code [#44652](https://github.com/anthropics/claude-code/issues/44652)）。エラーが表示された場合はもう一度呼び出してみてください。

## トランスポートの問題

### 接続タイムアウトまたは遅いレスポンス

**問題：** リクエストがハングするか、頻繁にタイムアウトします。

**原因：** ネットワーク遅延、プロキシ設定ミス、またはサーバーが遅い。

**解決方法：**
1. 読み取りタイムアウトを増やしてください：
   ```bash
   mcp-stdio --timeout-read 300 https://your-server.example.com/mcp
   ```
2. mcp-stdio は標準的なプロキシ環境変数を尊重します：
   ```bash
   HTTPS_PROXY=http://proxy.example.com:8080 mcp-stdio --oauth https://your-server.example.com/mcp
   ```
   （`NO_PROXY` も同様に尊重されます。これは mcp-stdio 自身の HTTP クライアントを使うことで、一部の MCP クライアント内蔵トランスポートの既知の不具合を回避できるケースです。Claude Code の [#34804](https://github.com/anthropics/claude-code/issues/34804) を参照。）
3. 手動で接続をテストしてください：
   ```bash
   curl -v https://your-server.example.com/mcp
   ```

### `Connection reset by peer` または `SSL: CERTIFICATE_VERIFY_FAILED`

**問題：** mcp-stdio がサーバーへの接続を確立できません。

**原因：** サーバーに到達できない、TLS 証明書が無効、またはプロキシが接続をインターセプトしている。

**解決方法：**
1. サーバー URL を確認し、接続をテストしてください：
   ```bash
   curl -v https://your-server.example.com/mcp
   ```
2. curl は機能するが mcp-stdio は機能しない場合、mcp-stdio をフォアグラウンドで実行し stderr で実際のエラーを確認してください。
3. 証明書が自己署名で、サーバーを信頼する場合：
   - macOS：証明書をシステムキーチェーンに追加します。
   - Linux：`SSL_CERT_FILE` 環境変数を CA バンドルを指すように設定します。
   - Windows：証明書を Windows 証明書ストアにインポートします。

### SSE ストリームがリクエスト途中にドロップ

**問題：** レガシー SSE サーバー（`--transport sse`）を使用しており、ツール呼び出しの途中で接続が切れました。

**原因：** 1 件以上のリクエストが応答待ちのまま、SSE GET ストリームが切断されました。

**解決方法：**
設定は不要です。mcp-stdio は自動的に再接続し、切断時に応答待ちだったすべてのリクエストに対して JSON-RPC のエラー（「SSE stream disconnected before response arrived; please retry」）を合成します。クライアントを永久にハングさせる代わりに、エラーを見たら呼び出しを再試行してください。これは Claude Code の [#60061](https://github.com/anthropics/claude-code/issues/60061) で報告された故障モードと同種のものです。可能であれば、この故障モード自体が存在しない Streamable HTTP（現在の MCP 仕様）へのアップグレードを検討してください。

## ヘッドレス / SSH 環境

### SSH または CI でブラウザを開けない（OAuth）

**問題：** SSH ボックスまたはディスプレイのない CI 環境にいて、`--oauth` がブラウザを開けません。

**解決方法：**
代わりにデバイス認可グラント（RFC 8628）を使用してください：

```bash
mcp-stdio --oauth-device https://your-server.example.com/mcp
```

ユーザーコード（例：`ABCD-1234`）が出力されます。任意のデバイスのブラウザでそれを開いて確認します。その後、mcp-stdio は SSH ボックスで OAuth フローを完了します（ローカルディスプレイは不要）。承認までの制限時間やタイムアウト時の挙動を含む完全な手順は[ヘッドレスログイン](guides/device-flow.ja.md)を参照してください。

## それでも解決しない場合

1. クライアント設定に追加する前に、`--check` で接続を検証してください：
   ```bash
   mcp-stdio --check --oauth https://your-server.example.com/mcp
   ```
2. stderr で詳細なエラーメッセージを確認してください。
3. [GitHub Issues](https://github.com/shigechika/mcp-stdio/issues) でエラーを検索してください。
4. それでも解決しない場合は、[issue を作成](https://github.com/shigechika/mcp-stdio/issues/new)してください。完全なコマンドとエラー出力を含めてください。
