"""A scripted legacy (2025-06-18) stdio MCP child for the serve harness.

WHY a new file rather than `tests/_fake_backend.py` (#270 Phase 3 P3-0).
Three reasons, in order of weight:

1. That file speaks `echo`/`slow_echo`, not MCP. The pin suite — and P3-B
   after it, which stamps `resultType`/`ttlMs`/`cacheScope` onto exactly
   the six cacheable operations — needs a child whose `tools/list` and
   `tools/call` results have the real MCP shapes, because those results
   are the thing being stamped.
2. It is imported by the 1,637-test unit suite, which this PR must leave
   byte-untouched. Widening it puts that suite inside P3-0's blast
   radius for no gain.
3. `tests_integration/` already owns its peers as siblings
   (`_reference_server.py`, `_stdio_client.py`); a third one follows the
   directory's convention.

This child is deliberately DUMB and DETERMINISTIC: no randomness, no
clocks it does not control, and every reply is a pure function of the
request except `slow`, whose delay the caller passes. It implements the
legacy dialect ONLY — no `resultType`, no caching hints, no
`server/discover`. That is the point: it is the "unmodified legacy child"
that serve must keep serving byte-identically (AC2) while it grows a
modern face in front of it.

Launched as a script path (`python .../_legacy_child.py`), never
`python -m`, matching `tests/_fake_backend.py` and serve's own
`command`-list contract.
"""

from __future__ import annotations

import json
import os
import sys
import time

# The era this child speaks. Serve forwards its `initialize` result
# verbatim today, so this string is observable end to end and the pin
# suite asserts on it.
LEGACY_PROTOCOL_VERSION = "2025-06-18"

SERVER_NAME = "mcp-stdio-legacy-fake"
SERVER_VERSION = "1.2.3"

# The WHOLE `InitializeResult`, declared once and answered verbatim below.
# Exported so a test can assert serve forwards it byte-for-byte by
# comparing against this object rather than restating a few fields: a pin
# that checks `protocolVersion` and `serverInfo.name` stays green while
# serve rewrites `serverInfo.version` or the capabilities, which is
# exactly the drift AC2 exists to catch (#370 review R1F1).
INITIALIZE_RESULT: dict = {
    "protocolVersion": LEGACY_PROTOCOL_VERSION,
    # #374 widened these from a lone `tools.listChanged: False`. The
    # discover un-strip is a statement ABOUT capability flags, so a child
    # advertising none of them proves nothing either way:
    # `resources.subscribe` has to be PRESENT for "still stripped" to be
    # observable, and the three listChanged flags have to be TRUE for
    # "advertised again" to be. Both pin files compare against this
    # object rather than restating it, so widening it leaves them green —
    # which is the property the comment above is describing.
    "capabilities": {
        "tools": {"listChanged": True},
        "prompts": {"listChanged": True},
        # `--no-resource-subscribe` in argv drops `subscribe`, so a test can
        # drive serve's #381 capability gate with a child that genuinely
        # lacks the feature rather than by monkeypatching serve.
        "resources": (
            {"subscribe": True, "listChanged": True}
            if "--no-resource-subscribe" not in sys.argv
            else {"listChanged": True}
        ),
    },
    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
}

# `tools/list`'s payload, declared once so the pin suite can import and
# compare against it instead of restating it (a restatement drifts).
TOOLS: list[dict] = [
    {
        "name": "echo",
        "description": "Return the arguments it was given.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
        },
    },
    {
        "name": "slow",
        "description": "Like echo, after a caller-specified delay.",
        "inputSchema": {
            "type": "object",
            "properties": {"delay": {"type": "number"}},
        },
    },
]

# Emitted on `notifications/push`, which is how a test drives a
# server-initiated message onto serve's GET SSE stream.
PUSH_NOTIFICATION = {
    "jsonrpc": "2.0",
    "method": "notifications/message",
    "params": {"level": "info", "data": "hello from the legacy child"},
}

# Emitted on `notifications/list_changed_push` (#374), which is how a test
# drives a listChanged event out of the child and onto a
# `subscriptions/listen` stream. Separate from `notifications/push` on
# purpose: the same test needs to fire a NON-trio notification and watch
# the stream refuse it.
LIST_CHANGED_NOTIFICATION = {
    "jsonrpc": "2.0",
    "method": "notifications/tools/list_changed",
    "params": {},
}


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _result(req_id, result: dict) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "result": result})


def _error(req_id, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def _text_content(payload) -> dict:
    """A CallToolResult carrying one text block — the 2025-06-18 shape."""
    return {
        "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}],
        "isError": False,
    }


def _handle_tools_call(req_id, params: dict) -> None:
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if name == "echo":
        _result(req_id, _text_content({"echoed": arguments, "pid": os.getpid()}))
        return
    if name == "slow":
        # `started_marker` makes "the slow call is now in flight" an
        # OBSERVED event rather than a timing assumption (conftest rules 1
        # and 4). Without it a test racing to send the colliding request
        # can register the shared JSON-RPC id FIRST, in which case the slow
        # request is the one that gets rejected and nothing is ever left in
        # flight — the collision under test never happens. The file is
        # created before the sleep, so a caller that polls for it is
        # guaranteed to be inside the window.
        marker = arguments.get("started_marker")
        if marker:
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write("started")
        # The ONLY wait in this file, and the caller owns its length: it
        # exists so a test can keep one request in flight while it sends a
        # second one under the same JSON-RPC id (serve's 409 path).
        time.sleep(float(arguments.get("delay", 0.5)))
        _result(req_id, _text_content({"slept": arguments.get("delay", 0.5)}))
        return
    # -32602 Invalid params is what a 2025-06-18 server answers for an
    # unknown tool name; pinned so P3-B's result-rewrite seam cannot
    # accidentally stamp a child ERROR as a cacheable complete result.
    _error(req_id, -32602, f"unknown tool: {name!r}")


def main() -> None:
    while True:
        line = sys.stdin.readline()
        if line == "":
            break  # EOF — the gateway closed our stdin
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        req_id = msg.get("id")
        has_id = "id" in msg

        if method == "initialize" and has_id:
            _result(req_id, INITIALIZE_RESULT)
        elif method == "tools/list" and has_id:
            _result(req_id, {"tools": TOOLS})
        elif method == "tools/call" and has_id:
            _handle_tools_call(req_id, msg.get("params") or {})
        elif method == "notifications/push":  # a notification (no id)
            _send(PUSH_NOTIFICATION)
        elif method == "notifications/list_changed_push":  # a notification
            _send(LIST_CHANGED_NOTIFICATION)
        elif method in ("resources/subscribe", "resources/unsubscribe") and has_id:
            # #381. The legacy wire shape: an EMPTY result carrying no
            # per-URI confirmation of any kind — which is exactly why
            # serve drives these fire-and-forget rather than blocking its
            # ack on them.
            _result(req_id, {})
        elif method == "notifications/resource_update_push":  # a notification
            # Drives one `notifications/resources/updated` for the URI the
            # caller names, so a test can prove per-URI routing rather
            # than just "some notification arrived".
            _send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": (msg.get("params") or {}).get("uri")},
                }
            )
        elif method == "exit":
            sys.exit(0)
        elif has_id:
            # Any other REQUEST gets a method-not-found rather than
            # silence: a hang here would be indistinguishable from a
            # gateway bug, which is the opposite of what a pin suite wants.
            _error(req_id, -32601, f"method not found: {method!r}")
        # Any other notification: ignored, like a real server.


if __name__ == "__main__":
    main()
