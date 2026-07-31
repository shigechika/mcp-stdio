"""Harness-correctness tests for `_stdio_client.py` itself.

Not a spec scenario against the reference peer (see `test_e2e.py`'s six
scenarios) — these guard the harness's OWN correctness: the
negative-assertion machinery (conftest rule 5 — `test_drain_raises_on_relay_eof`)
and the bounded-teardown guarantee (conftest rule 6 —
`test_close_bounds_every_wait_including_the_post_kill_one`). A bug in
either would make the real scenarios lie, or hang the suite, respectively.
"""

from __future__ import annotations

import subprocess
import types

import pytest

from ._stdio_client import RelayDied, StdioClient


def test_drain_raises_on_relay_eof(dedicated_server, relay_factory):
    """#368 review R1F1: `drain` must not treat relay EOF as quiescence.

    Rule 5's bounded quiescence check ("nothing arrived within the
    window") is only meaningful over a LIVE relay. Before this fix, `drain`
    silently returned whatever it had collected on EOF — so a relay that
    CRASHED mid-drain would make every "nothing arrived" assertion built on
    it (e.g. scenario 6's "no late response for the cancelled id") pass
    VACUOUSLY, masking the exact failure this harness exists to catch.
    `_take` already raises `RelayDied` on EOF; `drain` must do the same.
    """
    harness = dedicated_server()
    client = relay_factory(harness.port)
    client.initialize()

    # Kill rather than the graceful `close()` path: this test is about the
    # CRASH case specifically, not the documented stdin-EOF shutdown.
    client.proc.kill()
    client.proc.wait(timeout=5)

    with pytest.raises(RelayDied):
        client.drain(2.0)


class _StubProc:
    """Minimal stand-in for `subprocess.Popen`, driven through `close()`.

    `stdin`/`stdout`/`stderr` are `None` (each of `close()`'s guards skips a
    `None` stream, so this alone makes those three steps no-ops). `wait()`
    records every `timeout` kwarg it was called with and raises
    `TimeoutExpired` on its first two calls — forcing `close()` through its
    full EOF -> terminate -> kill escalation, so all three `wait()` calls
    actually happen — then succeeds on the third, so `close()` returns
    normally and the test can inspect every recorded timeout afterward.
    `terminate`/`kill` are no-ops: this test is about the WAIT bounds, not
    signal delivery.
    """

    def __init__(self) -> None:
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.wait_calls: list[float | None] = []

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls.append(timeout)
        if len(self.wait_calls) < 3:
            raise subprocess.TimeoutExpired(cmd="stub", timeout=timeout)
        return 0

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass


def test_close_bounds_every_wait_including_the_post_kill_one():
    """#368 review, /code-review round: `close()`'s docstring promises "EOF,
    then terminate, then kill — all bounded", but the wait AFTER `kill()`
    had no timeout — an unbounded wait that could hang the whole suite if
    the kernel ever has the process stuck (uninterruptible I/O). That is
    unrecoverable from user space: SIGKILL is already the strongest signal
    there is, so there is nothing left for `close()` to escalate to: the
    correct response is to fail loudly, not to wait forever, exactly the
    "surface it loudly" choice `_take`/`drain` already make for their own
    unbounded-wait risk via `RelayDied`.

    Drives `_StubProc` through the full EOF -> terminate -> kill escalation
    via `close()` (no real subprocess or reader thread needed, since
    `close()` only ever touches `self.proc`) and asserts every `wait()`
    call — not just the first two — received a non-`None`, bounded
    timeout.
    """
    proc = _StubProc()
    fake_client = types.SimpleNamespace(proc=proc)

    StdioClient.close(fake_client, timeout=5.0)

    assert len(proc.wait_calls) == 3
    assert all(t is not None for t in proc.wait_calls)
