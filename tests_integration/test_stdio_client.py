"""Harness-correctness tests for `_stdio_client.py` itself.

Not a spec scenario against the reference peer (see `test_e2e.py`'s six
scenarios) — a guard on the harness's OWN negative-assertion machinery
(conftest rule 5), because a bug here would make every "nothing arrived"
assertion in the real scenarios lie.
"""

from __future__ import annotations

import pytest

from ._stdio_client import RelayDied


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
