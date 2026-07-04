# トラブルシューティング

よくある問題と解決方法です。Claude Code、mcp-remote、MCP SDK の既知の回避方法の完全なリストは [WORKAROUNDS.md](https://github.com/shigechika/mcp-stdio/blob/main/WORKAROUNDS.md) を参照してください。

## 接続の問題

### OAuth ログイン時にブラウザが開かない

**問題：** `mcp-stdio --oauth` を実行しましたが、ブラウザウィンドウが開きません。

**解決方法：**
1. 標準エラー出力（stderr）から認可 URL を確認してください。ブラウザが自動的に開けない場合、そこに出力されます。
2. その URL をブラウザに手動で貼り付けます。
3. ログインフローを完了してください。認可コードはループバックコールバックで取得されます。

Claude Code の [#28293](https://github.com/anthropics/claude-code/issues/28293) を参照。

### Microsoft Entra ID のログインループまたは AADSTS エラー

**問題：** Microsoft Entra ID 上のサーバーに接続すると、ログインプロンプトが繰り返されるか、`AADSTS9010010` のようなエラーが表示されます。

**解決方法：**
`openid` と `offline_access` を含む明示的な OAuth スコープを設定してください：

```bash
mcp-stdio --oauth --oauth-scope "openid offline_access" https://your-server.example.com/mcp
```

異なる Entra ID テナントには異なるスコープが必要です。サーバーのドキュメントまたはエラーメッセージで必要なスコープを確認してください。

Claude Code の [#39271](https://github.com/anthropics/claude-code/issues/39271) を参照。

### `401 Unauthorized` — 「昨日は動いていたのに今日は動かない」

**問題：** 接続は正常に機能していましたが、今日は `401` エラーが表示されます。

**原因：** サーバーがキーをローテーションしたか、グラントを取り消した可能性があります。

**解決方法：**
キャッシュされたトークンを削除して再認可してください：

```bash
rm ~/.config/mcp-stdio/tokens.json
```

その後、クライアントを再度実行してください。初回利用時にブラウザが開いてログインを求められます。以後はトークンがキャッシュされ、自動的にリフレッシュされます。

### 接続が 24 時間後または固定時刻に切れる

**問題：** アクティブに使用中でも、毎日同じ時刻に接続が途切れます。

**原因：** OAuth アクセストークンが有効期限切れになり、mcp-stdio がプロアクティブにリフレッシュしていません。

**解決方法：**
mcp-stdio を長時間実行セッション（例：Claude Code を一日中動かす）で使用している場合、トークンは有効期限の直前にリフレッシュされるはずです。リフレッシュされていない場合：

1. `--no-proactive-refresh` を渡していないことを確認してください（デフォルトではプロアクティブにリフレッシュします）。
2. サーバーのトークンレスポンスに `expires_in` フィールド（または JWT の `exp`）が含まれていることを確認してください。
3. サーバーが `expires_in` を送信しない場合、リフレッシュ前置時間を手動で設定します：

```bash
mcp-stdio --oauth --oauth-refresh-leeway 300 https://your-server.example.com/mcp
```

デフォルトの 60 秒の代わりに、有効期限切れの 5 分前にリフレッシュします。

Claude Code の [#242](https://github.com/anthropics/claude-code/issues/242) を参照。

## ツールとリソースの問題

### 接続後にツールが突然消える

**問題：** 正常に接続され、ツールがリストされていますが、その後消えてしまいます。

**原因：** ほぼ確実に以下のいずれかです：
1. MCP セッションが失われました（例：サーバーが再起動）。mcp-stdio は次のリクエストでセッションを回復しますが、クライアントを再起動するまでツールは再リストされません。
2. Claude Code が後続のリクエストで `Mcp-Session-Id` ヘッダーを送信していません（下記の問題を参照）。

**解決方法：**
1. MCP クライアント（Claude Desktop / Claude Code）を再起動してください。
2. 頻繁に発生する場合は、サーバーログでセッションドロップを確認してください。

Claude Code の [#34498](https://github.com/anthropics/claude-code/issues/34498) を参照。

### ツール呼び出しで `404` が返される（リストされた後）

**問題：** ツールがリストに表示されていますが、呼び出すと `404` が返されます。

**原因：** Claude Code がツール呼び出しで `Mcp-Session-Id` ヘッダーをエコーバックしていないため、サーバーがセッションを見つけられません。

**解決方法：**
これは Claude Code のバグです。mcp-stdio は回避できません。Claude Code を再起動してセッションを再同期してください。

Claude Code の [#34008](https://github.com/anthropics/claude-code/issues/34008) を参照。

### 最初のページ以降のツールが見えない

**問題：** 数十個のツールが定義されていますが、クライアントには最初の約 20 個だけが表示されます。

**原因：** Claude Code は `tools/list` と `resources/list` のページネーションを無視し、最初のページだけを取得します。MCP サーバーが `nextCursor` を使用している場合、2 ページ目以降のツールは失われます。

**解決方法：**
これは Claude Code の HTTP トランスポートの制限です。mcp-stdio はクライアント側で回避できません。回避方法はツールの総数を 1 ページ以下に保つことです。

Claude Code の [#42470](https://github.com/anthropics/claude-code/issues/42470) を参照。

## 認証の問題

### スタティック Bearer トークンが送信されない

**問題：** `--bearer-token` または `MCP_BEARER_TOKEN` を設定しましたが、サーバーはトークンがないか無効だと報告します。

**原因：** 可能性は低い — mcp-stdio はすべてのリクエストにトークンを追加します。むしろ、サーバーがトークンを間違った場所で探している可能性が高いです（例：`Authorization` ヘッダーではなくクエリパラメータ）。

**解決方法：**
1. mcp-stdio をフォアグラウンドで実行し、stderr で送信されているリクエストをチェックして、詳細ログを有効にしてください。
2. トークンが正しく、有効期限が切れていないことを確認してください。
3. サーバーの認証ドキュメントを確認して、`Authorization: Bearer` ヘッダーを期待しているか確認してください。

### OAuth スコープが反映されない

**問題：** `--oauth-scope` でスコープをリクエストしましたが、サーバーはまだスコープ不足と訴えています。

**原因：** 認可サーバーがリクエストされたスコープを拒否し、より小さいものを付与した可能性があります。

**解決方法：**
1. 実際に付与されたスコープを確認してください。サーバーのトークンレスポンスの `scope` フィールドを確認します（詳細ログがある場合は mcp-stdio のログに出力されます）。
2. サーバーがスコープをダウングレードした場合は、認可サーバーのポリシーを確認するか、サーバーオペレーターに連絡してください。
3. 一部のサーバーは**ステップアップ認可**をサポートしています。ツールがより広いスコープを必要とする場合、`403 insufficient_scope` で必要なスコープをリストして返します。mcp-stdio は付与されたスコープと必要なスコープの和集合で自動的に再認可します。

## トランスポートの問題

### 接続タイムアウトまたは遅いレスポンス

**問題：** リクエストがハングするか、頻繁にタイムアウトします。

**原因：** ネットワーク遅延、プロキシ設定ミス、またはサーバーが遅い。

**解決方法：**
1. 読み取りタイムアウトを増やしてください：
   ```bash
   mcp-stdio --timeout-read 300 https://your-server.example.com/mcp
   ```
2. 企業プロキシの背後にいないか確認し、プロキシ環境変数を設定してください：
   ```bash
   HTTPS_PROXY=http://proxy.example.com:8080 mcp-stdio --oauth https://your-server.example.com/mcp
   ```
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
2. curl は機能するが mcp-stdio は機能しない場合、mcp-stdio でデバッグログを有効にしてください（stderr をチェック）。
3. 証明書が自己署名で、サーバーを信頼する場合：
   - macOS：証明書をシステムキーチェーンに追加します。
   - Linux：`SSL_CERT_FILE` 環境変数を CA バンドルを指すように設定します。
   - Windows：証明書を Windows 証明書ストアにインポートします。

### SSE ストリームがリクエスト途中にドロップ

**問題：** レガシー SSE サーバー（`--transport sse`）を使用しており、長いツール呼び出しがハングします。

**原因：** SSE GET ストリームが応答途中にドロップし、クライアントが応答を受信しませんでした。

**解決方法：**
mcp-stdio は自動的に再接続されますが、処理中のリクエストは失われます。これは SSE トランスポートの制限です。可能であれば、サーバーを Streamable HTTP（現在の MCP 仕様）にアップグレードしてください。

## ヘッドレス / SSH 環境

### SSH または CI でブラウザを開けない（OAuth）

**問題：** SSH ボックスまたはディスプレイのない CI 環境にいて、`--oauth` がブラウザを開けません。

**解決方法：**
代わりにデバイス認可グラント（RFC 8628）を使用してください：

```bash
mcp-stdio --oauth-device https://your-server.example.com/mcp
```

ユーザーコード（例：`ABCD-1234`）が出力されます。任意のデバイスのブラウザでそれを開いて確認します。その後、mcp-stdio は SSH ボックスで OAuth フローを完了します（ローカルディスプレイは不要）。

Claude Code の [#34804](https://github.com/anthropics/claude-code/issues/34804) を参照。

## それでも解決しない場合

1. クライアント設定に追加する前に、`--check` で接続を検証してください：
   ```bash
   mcp-stdio --check --oauth https://your-server.example.com/mcp
   ```
2. stderr で詳細なエラーメッセージと issue リファレンスを確認してください。
3. [GitHub Issues](https://github.com/shigechika/mcp-stdio/issues) でエラーを検索してください。
4. それでも解決しない場合は、[issue を作成](https://github.com/shigechika/mcp-stdio/issues/new)してください。完全なコマンドとエラー出力を含めてください。
