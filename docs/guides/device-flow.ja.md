# ヘッドレスログイン（デバイスフロー）

ゴール：ブラウザのないマシン——SSH先、コンテナ、CIランナー——で
mcp-stdio を認証する。ブラウザを持つ別のデバイス上で短いコードを
確認するだけで完了します。

## 1. `--oauth-device` で実行

```bash
mcp-stdio --oauth-device https://mcp.example.com/mcp
```

mcp-stdio は stderr に以下を表示します：

```
Device authorization required:
  Open: https://mcp.example.com/device?user_code=ABCD-1234
  Code (verify it matches): ABCD-1234

Waiting for authorization (giving up in 120s)...
```

## 2. 別のデバイスで承認

表示された URL を開きます——スマホでもラップトップでも、ブラウザが
あれば何でも構いません。ログインし、コードが一致することを確認して
承認してください。mcp-stdio はバックグラウンドでトークンエンドポイント
をポーリングしており、承認され次第すぐに処理が完了します。ヘッドレス側
のマシンで他に何かする必要はありません。

## 3. クライアントに追加

[ブラウザフロー](connect-remote.ja.md)と同じ要領で、`--oauth` を
`--oauth-device` に置き換えるだけです：

=== "Claude Desktop"

    `claude_desktop_config.json`：

    ```json
    {
      "mcpServers": {
        "my-remote-server": {
          "command": "mcp-stdio",
          "args": ["--oauth-device", "https://mcp.example.com/mcp"]
        }
      }
    }
    ```

=== "Claude Code"

    ```bash
    claude mcp add my-remote-server -- mcp-stdio --oauth-device https://mcp.example.com/mcp
    ```

トークンはブラウザフローと同じ `~/.config/mcp-stdio/tokens.json` に
保存されます——サーバーURLごとに一度ログインすれば、都合の良い場所から
実行して構わず、以後はすべてのターミナル・セッションで共有されます。

## 承認できるのは `--oauth-timeout` 秒だけ

認可サーバーはもっと長いデバイスコードの有効期限を提示してくることが
ありますが、mcp-stdio は実際の待ち時間を `--oauth-timeout`
（デフォルト **120秒**）で常に上限クランプします。これでは短すぎる
場合——デバイスの切り替えに時間がかかる、コードを手入力するなど——
延長してください：

```bash
mcp-stdio --oauth-device --oauth-timeout 600 https://mcp.example.com/mcp
```

## 時間内に承認しなかった場合

stderr に `Device authorization timed out. Please restart and try
again.` と表示され、終了コードは `1` です。単純にコマンドを再実行
してください——毎回新しいデバイスコードが要求されます。承認画面で
明示的に拒否した場合はタイムアウトを待たずに即座に失敗します：
`Device flow failed: access_denied`。

## トラブルシュートの早見

- **サーバーがデバイスフローに対応していない** ——
  `Server does not support Device Authorization Grant (no
  device_authorization_endpoint in metadata). Use --oauth for
  browser-based flow instead.` 認可サーバー自身が RFC 8628 に対応して
  いる必要があります。mcp-stdio 側だけでは追加できません。
- **Dynamic Client Registration に非対応** ——
  `Server does not support dynamic client registration. Provide a
  --client-id or --client-metadata-url instead.` 事前にサーバー運用者
  にクライアント登録を依頼して `--client-id` を渡すか、
  [Client ID Metadata Document](../reference.ja.md#oauth-21-openid-connect)
  をホストして `--client-metadata-url` を渡してください。

全フラグは `mcp-stdio --help` か
[README](https://github.com/shigechika/mcp-stdio#readme) へ。
