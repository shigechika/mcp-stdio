# mcp-stdio

MCP（Model Context Protocol）サーバーのための、最小構成の stdio ⇄ HTTP
ゲートウェイ。小さな Python パッケージひとつ、ランタイム依存は `httpx`
だけ。役割はふたつ：

- stdio しか話せない MCP クライアント（Claude Desktop、Claude Code など）を
  **リモートの HTTP MCP サーバーに接続**する——OAuth 2.1 ログイン、トークン
  保存、リフレッシュ込みで。
- ローカルの stdio MCP サーバーを、OAuth 2.1 認可サーバー内蔵の
  **Streamable HTTP エンドポイントとして公開**する——マルチユーザー、
  セッション分離で。

どちらが必要か迷ったら、まず
[ふたつの使い方](modes.md) へ。

## インストール

```bash
# Homebrew
brew install shigechika/tap/mcp-stdio

# または PyPI
pip install mcp-stdio

# インストールせずに実行
uvx mcp-stdio --help
```

## 30 秒クイックスタート

OAuth ログインが必要なリモート MCP サーバーを Claude Desktop につなぐ——
`claude_desktop_config.json` に次を追加するだけです：

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

初回利用時にブラウザが開いてログインを求められます。トークンは
`~/.config/mcp-stdio/tokens.json` にキャッシュされ、以後は自動で
リフレッシュされます。

これが「クライアント」側です。逆方向——自作の stdio MCP サーバーを
HTTPS で公開する——は
[stdio サーバーを公開する](guides/serve.md) を参照してください。

## なぜ存在するのか

MCP のクライアントとサーバーはトランスポートの解釈が常に一致するとは
限らず、OAuth の細部も実装ごとに異なり、その差は実際のデプロイで表面化
します。mcp-stdio はその中間に立って差異を吸収します：MCP 仕様と OAuth
関連 RFC に忠実に従い、
[既知の相互運用ギャップ](https://github.com/shigechika/mcp-stdio/blob/main/WORKAROUNDS.md)
を回避し、監査できる小ささを保っています。

機能一覧と標準準拠の詳細は
[README](https://github.com/shigechika/mcp-stdio#readme) へ。
