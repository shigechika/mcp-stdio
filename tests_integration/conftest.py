"""Integration-suite determinism rules (localhost network is real; time is not trusted).

1. Every wait is a bounded poll or a blocking read WITH an explicit deadline.
   Unbounded reads and unbounded joins are forbidden.
2. `time.sleep()` is forbidden in tests. The only permitted sleep is the
   fixed 10-50 ms tick inside the shared `wait_until(predicate, deadline)` /
   `expect_*(..., timeout=)` helpers.
3. Every test carries a pytest-timeout budget (default 30 s, injected by
   `pytest_collection_modifyitems`; override per test with
   `@pytest.mark.timeout(N)` only when a comment justifies the number).
   Deadline hierarchy: per-step expect timeout (default 5 s)
   < per-test timeout (30 s) < CI job `timeout-minutes: 10`.
   One test raises its budget rather than lowering it: scenario 6 must
   outwait the reference peer's 15 s SSE keep-alive interval, because on
   Linux a closed connection is not observed until the server's next write
   (see the comment at that wait). A raised budget still has to stay well
   under the job timeout, and the number must be justified by a measured
   mechanism, never by tuning until green.
4. Assert on observed events (a message arrived, a flag flipped, a process
   exited), never on elapsed wall-clock time.
5. Negative assertions ("nothing arrived") are allowed ONLY where a comment
   cites a design-record justification (the #270 PR D cancel record; the
   scenario-5 no-reconnect check per issue #367), implemented as a bounded
   quiescence check (drain the inbox for a fixed short window, e.g. 1 s).
   Anywhere else a negative wait is a bug.
6. Teardown must be unconditionally reachable: relay first (stdin EOF ->
   wait -> terminate -> kill), server second (should_exit -> join ->
   force_exit). No teardown step may block without its own timeout.
"""

# WHY this directory exists at all, and why it is a SIBLING of tests/:
# the unit suite (1,637 tests) is pinned entirely against hand-built mocks
# shaped by this project's own reading of spec rev 2026-07-28. #270 Design
# Amendment A9 showed what that blind spot costs — relay and mocks agreed
# with each other while a compliant server would have silently ignored the
# filter. This suite drives the relay end to end against python-sdk v2.0.0,
# the first official implementation of that spec revision, using real
# localhost HTTP and a real subprocess — exactly what the unit suite
# deliberately forbids. `pytest tests/` (the CI gate) never walks this
# directory, and this project ships no pytest ini, so the separation costs
# no configuration.

from __future__ import annotations

import importlib.util
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator

import pytest

# Collection guard: `pytest` with no arguments at the repository root walks
# this directory too, and the reference peer is an OPTIONAL dependency
# (`pip install -e ".[integration]"`). Skipping collection rather than
# erroring keeps a plain `pip install -e ".[dev]"` checkout usable.
if importlib.util.find_spec("mcp") is None:  # pragma: no cover — env-dependent
    collect_ignore_glob = ["test_*.py"]

_HERE = pathlib.Path(__file__).parent

# Rule 3's default per-test budget. Generous against the ~15-25 s the whole
# suite is expected to take, because its job is to turn a HANG into a loud
# failure, not to police performance.
_DEFAULT_TIMEOUT = 30.0
# Rule 2's permitted tick, in one place.
_POLL_TICK = 0.01
# Bounded readiness deadlines.
_SERVER_START_TIMEOUT = 10.0
_RELAY_STOP_TIMEOUT = 5.0


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Give every test in THIS directory a pytest-timeout budget (rule 3).

    Injected rather than configured because the project ships no pytest ini
    and #367 explicitly rejected introducing one. Items are filtered to this
    conftest's own directory: `pytest_collection_modifyitems` is a
    session-wide hook, so a bare `pytest` at the repository root would
    otherwise stamp timeouts onto the unit suite too — a behavior change to
    tests this PR must leave untouched.
    """
    for item in items:
        try:
            in_scope = pathlib.Path(str(item.fspath)).is_relative_to(_HERE)
        except (AttributeError, ValueError):  # pragma: no cover — defensive
            in_scope = False
        if in_scope and item.get_closest_marker("timeout") is None:
            item.add_marker(pytest.mark.timeout(_DEFAULT_TIMEOUT))


def wait_until(
    predicate: Callable[[], bool],
    timeout: float,
    what: str = "condition",
    diagnose: Callable[[], str] | None = None,
) -> None:
    """Block until `predicate()` is true, or fail the test (rules 1 + 2).

    The single permitted sleep in the suite lives here. Callers assert on
    the OBSERVED state afterwards (rule 4); this only bounds the wait.

    `diagnose` is called ONLY on timeout and its text is appended to the
    error. Without it a timeout here says just "it did not happen", which is
    the least useful sentence in a CI log — `StdioClient.expect_*` already
    dumps the relay's stderr tail on failure, and a wait on a SERVER-side
    condition needs the same, because the interesting question is almost
    always what the relay did (or did not) do first.
    """
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            extra = ""
            if diagnose is not None:
                try:
                    extra = f"\n{diagnose()}"
                except Exception as exc:  # noqa: BLE001 — diagnostics must not mask
                    extra = f"\n<diagnose() raised {exc!r}>"
            raise TimeoutError(f"timed out after {timeout}s waiting for {what}{extra}")
        time.sleep(_POLL_TICK)


def _clean_env() -> dict[str, str]:
    """A relay environment with every ambient MCP credential stripped.

    The harness server is unauthenticated. An `MCP_BEARER_TOKEN` in the
    developer's shell would make the relay send an Authorization header the
    server never asked for — harmless here, but the point is that the suite
    must test the same thing on a laptop and in CI.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCP_")}
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


class _StderrDrain:
    """Daemon thread draining a subprocess' stderr into a bounded deque.

    Load-bearing, not diagnostics-only: an undrained stderr pipe fills and
    blocks the relay mid-session, which would look exactly like a protocol
    hang. `maxlen` bounds the memory a chatty session can pin; the tail is
    what an `expect_*` timeout reports.
    """

    def __init__(self, stream, maxlen: int = 500) -> None:
        self.lines: deque[str] = deque(maxlen=maxlen)
        self._stream = stream
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        for raw in self._stream:  # blocking readline; ends at EOF
            self.lines.append(raw.decode("utf-8", "replace").rstrip("\n"))

    def tail(self, n: int = 40) -> str:
        return "\n".join(list(self.lines)[-n:])

    def contains(self, needle: str) -> bool:
        return any(needle in line for line in list(self.lines))


def free_port() -> tuple[socket.socket, int]:
    """A bound listening socket and its port — no bind/read-back race.

    uvicorn is handed the ALREADY-BOUND socket (`sockets=[sock]`), so the
    port cannot be stolen between `getsockname()` and the server's own bind.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    return sock, sock.getsockname()[1]


def spawn_relay(port: int, *, extra_args: list[str] | None = None):
    """Start `mcp-stdio` as a subprocess against the harness server.

    `sys.executable -m mcp_stdio` rather than the console script: it pins
    the relay to the SAME interpreter running the tests, independent of
    PATH and of whether the venv is activated.

    `--protocol-era auto` is deliberate — the era probe against a real v2
    server is scenario 1's whole subject. The transport stays the default
    streamable-http: `--protocol-era` is ignored (with a warning) under the
    legacy `--transport sse`, which would defeat every scenario here. The
    v2 server's SSE response framing is its own default (`json_response`
    off) and needs no flag on either side.
    """
    args = [
        sys.executable,
        "-m",
        "mcp_stdio",
        f"http://127.0.0.1:{port}/mcp",
        "--protocol-era",
        "auto",
    ]
    args += extra_args or []
    return subprocess.Popen(  # noqa: S603 — fixed argv, no shell
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_clean_env(),
    )


@pytest.fixture(scope="session", autouse=True)
def reference_peer_version() -> str:
    """Pin the reference peer to a 2.x wheel, loudly, once per session.

    Required change 6 of the #367 design: the extra is a RANGE, so the
    suite states which major it was written against rather than trusting
    whatever resolved. NOTE: `mcp.__version__` does not exist in v2.0.0 —
    the version lives only in distribution metadata.
    """
    from importlib.metadata import version

    resolved = version("mcp")
    assert resolved.split(".")[0] == "2", (
        f"tests_integration targets python-sdk v2 as the reference peer; got {resolved}"
    )
    return resolved


def _serve(app, sock: socket.socket):
    """Boot uvicorn on an already-bound socket, in a daemon thread.

    In-process (not a second subprocess) is load-bearing: it is what lets a
    test publish on the subscription bus and read the server-side
    cancellation side-channel directly, instead of inventing a control
    channel the SUT would then have to carry. uvicorn skips signal-handler
    installation when it is not on the main thread, which is the documented
    way to embed it.
    """
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, daemon=True
    )
    thread.start()
    port = sock.getsockname()[1]

    # `Server.started` is effectively public but not formally guaranteed,
    # so a TCP connect to the port is the fallback proof inside the SAME
    # deadline (rule 1).
    def _up() -> bool:
        if server.started:
            return True
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except OSError:
            return False

    wait_until(_up, _SERVER_START_TIMEOUT, "uvicorn to start")
    return server, thread


def _shutdown(server, thread: threading.Thread) -> None:
    """Rule 6's server half: graceful, then forced, both bounded."""
    server.should_exit = True
    thread.join(10)
    if thread.is_alive():  # pragma: no cover — only on a wedged server
        server.force_exit = True
        thread.join(5)


@pytest.fixture(scope="module")
def harness_server(reference_peer_version):
    """The shared python-sdk v2 reference peer (module-scoped).

    Booted once for the whole module because it holds no per-test state
    worth isolating and a boot costs ~0.5 s. Scenarios that STOP or disrupt
    the server take their own function-scoped instance instead
    (`dedicated_server`), so the shared one always outlives every relay
    that is talking to it — see rule 6 on teardown ordering.
    """
    from . import _reference_server

    app, extras = _reference_server.build_app()
    sock, port = free_port()
    server, thread = _serve(app, sock)
    try:
        yield _reference_server.Harness(port=port, **extras)
    finally:
        _shutdown(server, thread)


@pytest.fixture
def dedicated_server(reference_peer_version):
    """A fresh reference peer for one test (function-scoped).

    For scenarios 5 and 6, which end listen streams or stop the server
    outright: doing that to the shared instance would break every later
    test in the module.
    """
    from . import _reference_server

    made: list[tuple] = []

    def _make():
        app, extras = _reference_server.build_app()
        sock, port = free_port()
        server, thread = _serve(app, sock)
        made.append((server, thread))
        return _reference_server.Harness(port=port, **extras)

    try:
        yield _make
    finally:
        for server, thread in made:
            _shutdown(server, thread)


@pytest.fixture
def relay_factory() -> Iterator[Callable]:
    """Spawn relays bound to this test, torn down relay-FIRST (rule 6).

    Ordering matters and is the reason this is separate from the server
    fixtures: the relay holds a long-lived `subscriptions/listen` POST, so
    stopping the server first would trigger its reconnect machinery and
    make teardown nondeterministic. pytest tears fixtures down in reverse
    setup order, and `dedicated_server` is requested before this one by
    every test that needs both.
    """
    from ._stdio_client import StdioClient

    clients: list[StdioClient] = []

    def _spawn(port: int, *, extra_args: list[str] | None = None) -> StdioClient:
        proc = spawn_relay(port, extra_args=extra_args)
        client = StdioClient(proc, stderr=_StderrDrain(proc.stderr))
        clients.append(client)
        return client

    try:
        yield _spawn
    finally:
        for client in clients:
            client.close(timeout=_RELAY_STOP_TIMEOUT)
