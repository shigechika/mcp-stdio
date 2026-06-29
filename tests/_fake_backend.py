"""A tiny stdio MCP-ish backend used by test_server.py.

Reads newline-delimited JSON-RPC from stdin and reacts:

- ``initialize`` (request)      -> an InitializeResult with protocolVersion
- ``echo`` (request)            -> result {"echoed": <params>, "pid": <os pid>}
- ``noreply`` (request)         -> never responds (drives the timeout path)
- ``trigger_push`` (notification) -> emits a server-initiated notification
- ``exit`` (any)                -> the process exits

Run as: ``python -m tests._fake_backend`` is not needed — it is launched as a
script path by the tests.
"""

import json
import os
import sys


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    while True:
        line = sys.stdin.readline()
        if line == "":
            break  # EOF
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize" and "id" in msg:
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "serverInfo": {"name": "fake", "version": "0"},
                        "capabilities": {},
                    },
                }
            )
        elif method == "echo" and "id" in msg:
            # pid lets a test prove two sessions hit two distinct child
            # processes (no cross-session response leakage).
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {"echoed": msg.get("params"), "pid": os.getpid()},
                }
            )
        elif method == "noreply" and "id" in msg:
            pass  # intentionally silent -> exercises the gateway timeout path
        elif method == "trigger_push":  # a notification (no id)
            _send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {"hello": "world"},
                }
            )
        elif method == "exit":
            sys.exit(0)
        # any other notification: ignore


if __name__ == "__main__":
    main()
