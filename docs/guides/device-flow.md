# Headless login (device flow)

Goal: authenticate mcp-stdio on a machine with no browser — an SSH box, a
container, a CI runner — by confirming a short code on any other device
that does have one.

## 1. Run with `--oauth-device`

```bash
mcp-stdio --oauth-device https://mcp.example.com/mcp
```

mcp-stdio prints to stderr:

```
Device authorization required:
  Open: https://mcp.example.com/device?user_code=ABCD-1234
  Code (verify it matches): ABCD-1234

Waiting for authorization (giving up in 120s)...
```

## 2. Confirm on any other device

Open the printed URL — phone, laptop, whatever has a browser — log in,
check the code matches, and approve. mcp-stdio polls the token endpoint
in the background and returns as soon as you approve; there is nothing
else to do on the headless box.

## 3. Add it to your client

Same as [the browser flow](connect-remote.md), just swap `--oauth` for
`--oauth-device`:

=== "Claude Desktop"

    `claude_desktop_config.json`:

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

Tokens land in the same `~/.config/mcp-stdio/tokens.json` used by the
browser flow — log in once per server URL, from wherever is convenient,
and every terminal and session shares the result.

## You only have `--oauth-timeout` seconds to confirm

The authorization server may advertise a much longer device-code
lifetime, but mcp-stdio caps the actual wait at `--oauth-timeout`
(default **120 s**) regardless. If that is too tight — switching devices
takes a while, the code has to be copied by hand — raise it:

```bash
mcp-stdio --oauth-device --oauth-timeout 600 https://mcp.example.com/mcp
```

## What happens if you don't confirm in time

`Device authorization timed out. Please restart and try again.` on
stderr, exit code `1`. Just rerun the command — a fresh device code is
requested each time. Explicitly denying the request on the confirmation
page fails immediately instead of waiting out the timeout:
`Device flow failed: access_denied`.

## Troubleshooting quickies

- **Server doesn't support device flow** —
  `Server does not support Device Authorization Grant (no
  device_authorization_endpoint in metadata). Use --oauth for
  browser-based flow instead.` The authorization server itself has to
  advertise RFC 8628 support; mcp-stdio cannot add it on the client side.
- **No dynamic client registration** —
  `Server does not support dynamic client registration. Provide a
  --client-id or --client-metadata-url instead.` Register a client with
  the server operator ahead of time and pass `--client-id`, or host a
  [Client ID Metadata Document](../reference.md#oauth-21-openid-connect)
  and pass `--client-metadata-url`.

Every flag: `mcp-stdio --help`, or the
[README](https://github.com/shigechika/mcp-stdio#readme).
