"""Minimal 2025-06-18 JSON-RPC stdio client driving the relay subprocess.

WHY hand-written rather than reused from the SDK: the whole point of the
harness is that the DOWNSTREAM side must be a legacy (2025-06-18) stdio
client — that is the era the relay translates FROM, and the reference peer
is on the other end of the relay, not this one. Using an SDK client here
would test the SDK against itself and skip the relay's translation
entirely.

Determinism (see conftest's module docstring): one blocking-readline daemon
thread feeds a queue, every `expect_*` takes an explicit deadline, and stdout
EOF poisons the queue so a dead relay fails the next expect immediately
instead of stalling until the per-test timeout.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from typing import Any

# The era this client speaks. NOT the relay's upstream version — the relay
# negotiates 2026-07-28 with the reference peer and answers this client in
# its own dialect. That asymmetry is the subject of the whole suite.
LEGACY_PROTOCOL_VERSION = "2025-06-18"

# `elicitation: {}` is exactly what a 2025-06-18 client declares — the
# sub-capability object was added in the 2026-07-28 schema. Verified against
# the reference peer at implementation time: it accepts the bare object and
# runs form-mode resolvers, matching spec rev 2026-07-28's "declaring
# `elicitation: {}` is equivalent to declaring support for form mode only".
# Withhold it and the peer answers -32021 MissingRequiredClientCapability
# instead of an InputRequiredResult, so scenario 3 depends on this.
DEFAULT_CLIENT_CAPABILITIES: dict[str, Any] = {"elicitation": {}}

_EOF = object()


class RelayDied(RuntimeError):
    """The relay's stdout hit EOF; no further message can ever arrive."""


class StdioClient:
    """Drives one relay subprocess over its stdin/stdout pipes."""

    def __init__(
        self,
        proc: subprocess.Popen,
        *,
        stderr=None,
        default_timeout: float = 5.0,
    ) -> None:
        self.proc = proc
        self.stderr = stderr
        self.default_timeout = default_timeout
        self._next_id = 1
        self._inbox: queue.Queue = queue.Queue()
        # Messages read off the wire that no `expect_*` wanted YET. Ordered,
        # and rescanned before the queue on every expect — this is what makes
        # the MRTR interleave work: while waiting on the tool result, the
        # relay's `elicitation/create` arrives, gets parked here by nothing
        # (it is matched directly), and conversely a result that overtakes an
        # expected request is not lost.
        self._pending: list[dict[str, Any]] = []
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()

    # --- plumbing ---------------------------------------------------

    def _read_stdout(self) -> None:
        for raw in self.proc.stdout:  # blocking readline; the relay writes
            line = raw.decode("utf-8").strip()  # newline-delimited JSON-RPC
            if not line:
                continue
            try:
                self._inbox.put(json.loads(line))
            except json.JSONDecodeError:  # pragma: no cover — relay bug
                self._inbox.put({"__unparseable__": line})
        self._inbox.put(_EOF)

    def _diagnostics(self) -> str:
        parts = [f"pending={json.dumps(self._pending)[:1500]}"]
        if self.stderr is not None:
            parts.append(f"relay stderr tail:\n{self.stderr.tail()}")
        return "\n".join(parts)

    def _send(self, msg: dict[str, Any]) -> None:
        if self.proc.poll() is not None:
            raise RelayDied(
                f"relay exited with {self.proc.returncode}\n{self._diagnostics()}"
            )
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def _take(self, match, timeout: float | None, what: str) -> dict[str, Any]:
        """Deadline-bounded scan of `_pending` then the live queue (rule 1)."""
        budget = self.default_timeout if timeout is None else timeout
        deadline = time.monotonic() + budget
        for i, msg in enumerate(self._pending):
            if match(msg):
                return self._pending.pop(i)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"timed out after {budget}s waiting for {what}\n{self._diagnostics()}"
                )
            try:
                msg = self._inbox.get(timeout=remaining)
            except queue.Empty:
                continue
            if msg is _EOF:
                # Poison the queue again so every LATER expect fails fast too.
                self._inbox.put(_EOF)
                raise RelayDied(
                    f"relay stdout closed while waiting for {what}\n{self._diagnostics()}"
                )
            if match(msg):
                return msg
            self._pending.append(msg)

    # --- sends ------------------------------------------------------

    def send_request(self, method: str, params: dict[str, Any] | None = None) -> int:
        """Fire a request and return its id WITHOUT waiting for the result."""
        req_id = self._next_id
        self._next_id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)
        return req_id

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def respond(
        self, req_id: Any, result: Any = None, error: dict[str, Any] | None = None
    ) -> None:
        """Answer a RELAY-initiated request (the MRTR minted elicitation)."""
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id}
        if error is not None:
            msg["error"] = error
        else:
            msg["result"] = result
        self._send(msg)

    # --- expects ----------------------------------------------------

    def expect_result(
        self, req_id: int, timeout: float | None = None
    ) -> dict[str, Any]:
        msg = self._take(
            lambda m: m.get("id") == req_id and ("result" in m or "error" in m),
            timeout,
            f"a response for id {req_id}",
        )
        if "error" in msg:
            raise AssertionError(
                f"expected a result for id {req_id}, got {msg['error']}"
            )
        return msg["result"]

    def expect_error(self, req_id: int, timeout: float | None = None) -> dict[str, Any]:
        msg = self._take(
            lambda m: m.get("id") == req_id and ("result" in m or "error" in m),
            timeout,
            f"an error for id {req_id}",
        )
        if "error" not in msg:
            raise AssertionError(
                f"expected an error for id {req_id}, got {msg['result']}"
            )
        return msg["error"]

    def expect_request(
        self, method: str | None = None, timeout: float | None = None
    ) -> dict[str, Any]:
        """A request the RELAY initiated (e.g. a minted `elicitation/create`)."""
        return self._take(
            lambda m: (
                "id" in m
                and "method" in m
                and (method is None or m["method"] == method)
            ),
            timeout,
            f"a relay-initiated request {method or '(any)'}",
        )

    def expect_notification(
        self, method: str, timeout: float | None = None
    ) -> dict[str, Any]:
        return self._take(
            lambda m: m.get("method") == method and "id" not in m,
            timeout,
            f"a {method} notification",
        )

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        return self.expect_result(self.send_request(method, params), timeout=timeout)

    def drain(self, window: float) -> list[dict[str, Any]]:
        """Collect everything that arrives within `window` (rule 5).

        The bounded quiescence check behind every "nothing arrived"
        assertion. Returns pending + newly-read messages; the caller asserts
        on the CONTENT, never on how long it waited.

        Raises `RelayDied` on EOF, exactly like `_take` (#368 review R1F1):
        a "nothing arrived" observation is only meaningful over a LIVE
        relay. Treating EOF as successful quiescence let a relay that
        CRASHED mid-drain pass every negative assertion built on this
        method vacuously — the exact failure this harness exists to catch,
        silently turned into a false green. The sentinel is re-enqueued
        first, exactly like `_take`, so every LATER call (drain or `_take`)
        fails just as fast instead of stalling until its own timeout.
        """
        deadline = time.monotonic() + window
        collected = list(self._pending)
        self._pending.clear()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return collected
            try:
                msg = self._inbox.get(timeout=remaining)
            except queue.Empty:
                return collected
            if msg is _EOF:
                self._inbox.put(_EOF)
                raise RelayDied(
                    f"relay stdout closed during drain(window={window})\n"
                    f"{self._diagnostics()}"
                )
            collected.append(msg)

    # --- lifecycle --------------------------------------------------

    def initialize(
        self,
        protocol_version: str = LEGACY_PROTOCOL_VERSION,
        capabilities: dict[str, Any] | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """The handshake, which doubles as the relay's readiness probe.

        No separate probe is needed: on `--protocol-era auto` the relay runs
        its `server/discover` era probe BEFORE the stdin loop starts, so a
        result here proves the probe already completed. The timeout is
        larger than the default for exactly that reason — it covers process
        spawn plus one upstream round-trip.
        """
        result = self.request(
            "initialize",
            {
                "protocolVersion": protocol_version,
                "capabilities": (
                    DEFAULT_CLIENT_CAPABILITIES
                    if capabilities is None
                    else capabilities
                ),
                "clientInfo": {"name": "mcp-stdio-integration-harness", "version": "0"},
            },
            timeout=timeout,
        )
        self.notify("notifications/initialized")
        return result

    def close(self, timeout: float = 5.0) -> None:
        """Rule 6's relay half: EOF, then terminate, then kill — all bounded.

        stdin EOF is the relay's own documented shutdown path (`_STDIN_EOF`),
        so the graceful case exercises production code rather than a signal.
        """
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except OSError:  # pragma: no cover — already-dead relay
            pass
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self.proc.kill()
                self.proc.wait()
        for stream in (self.proc.stdout, self.proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:  # pragma: no cover
                pass
