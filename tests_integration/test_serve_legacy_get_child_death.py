"""Regression test for #383: a legacy GET SSE stream must END when its
session's child dies, not leave the client waiting on a dead socket.

SEPARATE from `test_serve_legacy_pin.py` on purpose, and that placement
is the whole reason this PR needs no zero-diff exception. The pin file's
AC2 invariant is "zero diffs, ever" (see its module docstring); adding a
test there — even a purely additive one touching no existing assertion —
would put a reviewer in the position of re-deriving that no PINNED VALUE
moved. A sibling file makes "new coverage, not a changed pin" visible
from the filename alone, and costs one line in `conftest.py`'s
`_PEER_INDEPENDENT_MODULES` allow-list instead. This suite drives our own
`serve` against our own scripted child, exactly like the pin file, and
needs nothing from the python-sdk reference peer.

THE BUG (#383). `do_GET`'s SSE loop is `while not backend.closed:`, so it
can end SERVER-side when the session's child process dies — the caught
`(BrokenPipeError, ConnectionResetError, ValueError)` arm covers only the
client-goes-away endings. But the response sends
`Connection: keep-alive`, and `BaseHTTPRequestHandler.send_header` treats
that header as a COMMAND: it resets `close_connection` to False as a side
effect, undoing the intent the code states four lines earlier. An SSE
body has neither `Content-Length` nor chunked framing, so the connection
close IS its delimiter. With `close_connection` left False the handler
returns without closing the socket, and the client — which has no other
end-of-message signal — waits forever.

THE FIX: re-assert `self.close_connection = True` after `end_headers()`
in `do_GET`, the same one-line pattern `_serve_listen_stream` has carried
since #382 for the identical shape on the modern `subscriptions/listen`
path. #382 found this defect but could not touch it (AC2 kept the legacy
path byte-identical there), which is why it became #383.

WHY NO `--session-idle-ttl` LEVER. An earlier draft set a small
`--session-idle-ttl` to shrink `registry.keepalive_interval()` — the
cadence at which `do_GET`'s loop rechecks `backend.closed` — from the
default 15 s down to ~1 s, purely for speed. That is CONFOUNDED: with
idle eviction armed, both the fix and the reaper's own eviction can make
`backend.closed` true, and a test that never runs with the reaper OFF
cannot answer a reader who asks whether the reaper coincidentally tidied
something up. This version leaves the TTL at its default (0 — disabled,
so `start_reaper()` never starts a thread) and pays the real
`_SSE_KEEPALIVE_SECS = 15.0` cadence instead. That isolates the
`close_connection` re-assertion as the only mechanism in play, at a cost
of ~16-18 s of real wall clock — deliberate, and the same trade conftest
rule 3 already sanctions for outwaiting a 15 s keep-alive.
"""

from __future__ import annotations

import threading

import httpx
import pytest

from .conftest import wait_until

# server.py's `_SSE_KEEPALIVE_SECS` — the cadence `do_GET`'s loop uses to
# recheck `backend.closed` when no idle TTL is configured
# (`SessionRegistry.keepalive_interval`). Not imported: this suite runs
# the deployed `mcp-stdio serve` artifact as a subprocess rather than
# in-process, so the value is restated with a citation, the same
# convention conftest uses for its own timing constants.
_SSE_KEEPALIVE_SECS = 15.0


# Rule 3's justified override. This test pays one real
# `_SSE_KEEPALIVE_SECS` cadence by design (see the module docstring), so
# the FAILURE path — spawn, open, then the 25 s bounded wait below — runs
# to roughly 27-28 s and does not fit conftest's injected 30 s default.
# Without this the regression would surface as pytest-timeout killing the
# test, losing `wait_until`'s diagnosing TimeoutError (which carries
# serve's stderr tail) — a loud failure replaced by an opaque one. Still
# far inside the CI job's cap.
@pytest.mark.timeout(60)
def test_get_sse_stream_closes_when_the_session_child_dies(serve_factory):
    """The client must observe EOF, not an endless wait, on child death.

    The child kills ITSELF via the `exit` notification `_legacy_child.py`
    understands (`sys.exit(0)`, which closes its stdout) — the same
    technique `test_serve_modern_e2e.py` uses for the sibling regression
    on the modern `subscriptions/listen` path. Organic child death, NOT
    `DELETE`: a DELETE also tears down the registry session, which is a
    different scenario and already pinned elsewhere.

    Falling out of `resp.iter_lines()` without an exception is the
    positive signal — httpx's line iterator ends cleanly on a graceful
    TCP close (FIN), so the loop completing IS the client observing EOF.
    Before the fix that iterator never ends; `wait_until`'s own deadline
    is what turns the resulting wait into a loud, diagnosed failure
    instead of a wedged test process.
    """
    # No `--session-idle-ttl`: the default keeps the idle reaper unstarted,
    # so the only thing that can end this test is `do_GET` noticing
    # `backend.closed` at its next keepalive-cadence recheck and then
    # actually closing the socket.
    gateway = serve_factory()
    sid = gateway.open_session()

    opened = threading.Event()
    stream_ended = threading.Event()
    failures: list[str] = []

    def _read() -> None:
        try:
            with httpx.stream(
                "GET",
                gateway.url,
                headers={"Mcp-Session-Id": sid},
                timeout=_SSE_KEEPALIVE_SECS + 15.0,
            ) as resp:
                if resp.status_code != 200:
                    failures.append(f"status_code={resp.status_code}, want 200")
                    opened.set()
                    return
                if resp.headers.get("content-type") != "text/event-stream":
                    failures.append(
                        f"content-type={resp.headers.get('content-type')!r}"
                    )
                opened.set()
                for _ in resp.iter_lines():
                    pass  # drain; the loop's own END is what is under test
            # Reached only when the response body ended cleanly — i.e. this
            # reader observed the close.
            stream_ended.set()
        except httpx.HTTPError as exc:  # pragma: no cover - defensive
            failures.append(f"{type(exc).__name__}: {exc}")
            opened.set()
            # `stream_ended` too, and it means "this reader is DONE" rather
            # than "the stream closed cleanly" — `failures` is what draws
            # that distinction (#384 Copilot review). Without it, an error
            # raised from `iter_lines()` AFTER `opened` was set leaves the
            # real cause sitting in `failures` while the main thread waits
            # out its full 25 s on `stream_ended` and then reports the
            # generic "did not close after its child dies" — the true
            # diagnosis recorded and then buried under a misleading one.
            stream_ended.set()

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    try:
        wait_until(
            opened.is_set,
            10.0,
            "the GET SSE stream to open",
            diagnose=gateway.diagnose,
        )
        assert not failures, "; ".join(failures)
        # Causality pin: open AND still open immediately before the kill,
        # so a pass below cannot be a closed-for-some-other-reason artifact.
        assert not stream_ended.is_set()

        killed = gateway.post({"jsonrpc": "2.0", "method": "exit"}, sid=sid)
        assert killed.status_code == 202, (killed.status_code, killed.text)

        wait_until(
            stream_ended.is_set,
            _SSE_KEEPALIVE_SECS + 10.0,
            "the GET SSE stream to close after its child dies",
            diagnose=gateway.diagnose,
        )
    finally:
        reader.join(timeout=10)

    assert not failures, "; ".join(failures)
