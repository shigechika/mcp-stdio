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
import json
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

_HERE = pathlib.Path(__file__).parent

# Test modules that need NOTHING from the reference peer. #270 Phase 3
# P3-0's serve suites drive our own `mcp-stdio serve` against our own
# scripted legacy child, so the peer's absence must not silence them —
# "silently collected zero tests" is exactly the false green this
# directory exists to prevent, and a suite whose job is to be a zero-diff
# invariant is the worst possible place for it.
#
# An ALLOW-list, not a deny-list, and that direction is deliberate: a new
# peer-dependent module added later is ignored by default (safe), while
# only a module someone explicitly declares peer-independent survives.
_PEER_INDEPENDENT_MODULES = frozenset(
    {
        "test_serve_legacy_get_child_death.py",
        "test_serve_legacy_pin.py",
        "test_serve_modern_before.py",
        "test_serve_sandwich.py",
    }
)

# Collection guard: `pytest` with no arguments at the repository root walks
# this directory too, and the reference peer is an OPTIONAL dependency
# (`pip install -e ".[integration]"`). Skipping collection rather than
# erroring keeps a plain `pip install -e ".[dev]"` checkout usable.
if importlib.util.find_spec("mcp") is None:  # pragma: no cover — env-dependent
    collect_ignore = [
        path.name
        for path in sorted(_HERE.glob("test_*.py"))
        if path.name not in _PEER_INDEPENDENT_MODULES
    ]

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


def spawn_relay(
    port: int,
    *,
    extra_args: list[str] | None = None,
    protocol_era: str = "auto",
    path: str = "/mcp",
):
    """Start `mcp-stdio` as a subprocess against the harness server.

    `sys.executable -m mcp_stdio` rather than the console script: it pins
    the relay to the SAME interpreter running the tests, independent of
    PATH and of whether the venv is activated.

    `--protocol-era auto` is the DEFAULT here — the era probe against a
    real v2 server is scenario 1's whole subject. The transport stays the
    default streamable-http: `--protocol-era` is ignored (with a warning)
    under the legacy `--transport sse`, which would defeat every scenario
    here. The v2 server's SSE response framing is its own default
    (`json_response` off) and needs no flag on either side.

    `protocol_era` is a parameter rather than a constant since #270 Phase
    3 P3-0: the gateway sandwich points a LEGACY-era relay at our own
    serve, whose legacy face is the thing being pinned. Every existing
    caller keeps the `auto` default, so #367's scenarios are unchanged.
    """
    args = [
        sys.executable,
        "-m",
        "mcp_stdio",
        f"http://127.0.0.1:{port}{path}",
        "--protocol-era",
        protocol_era,
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
def reference_peer_version() -> str | None:
    """Pin the reference peer to a 2.x wheel, loudly, once per session.

    Required change 6 of the #367 design: the extra is a RANGE, so the
    suite states which major it was written against rather than trusting
    whatever resolved. NOTE: `mcp.__version__` does not exist in v2.0.0 —
    the version lives only in distribution metadata.

    Returns None when the peer is absent (#270 Phase 3 P3-0) instead of
    erroring. It is `autouse`, so it runs for the serve suites too — and
    those need nothing from the peer. The peer-dependent modules are
    collect-ignored in exactly that case (see `_PEER_INDEPENDENT_MODULES`
    above), so nothing that DOES need a 2.x wheel can reach this None.
    """
    if importlib.util.find_spec("mcp") is None:  # pragma: no cover — env-dependent
        return None
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

    def _spawn(port: int, **kwargs) -> StdioClient:
        # kwargs pass straight through to `spawn_relay` (`extra_args`,
        # `protocol_era`, `path`) rather than being enumerated here, so a
        # new relay flag needs one signature change, not two.
        proc = spawn_relay(port, **kwargs)
        client = StdioClient(proc, stderr=_StderrDrain(proc.stderr))
        clients.append(client)
        return client

    try:
        yield _spawn
    finally:
        for client in clients:
            client.close(timeout=_RELAY_STOP_TIMEOUT)


# --- serve mode: the reverse gateway under test (#270 Phase 3 P3-0) -------

# The scripted legacy child serve fronts. `sys.executable` pins it to the
# interpreter running the tests, like `spawn_relay`.
LEGACY_CHILD_COMMAND = [sys.executable, str(_HERE / "_legacy_child.py")]

_SERVE_START_TIMEOUT = 20.0
_SERVE_STOP_TIMEOUT = 5.0
# Rule 5's bounded quiescence window, in one place.
QUIESCENCE_WINDOW = 1.0


def _reserve_port() -> int:
    """An unused localhost port for a SUBPROCESS to bind.

    UNLIKE `free_port()`, which hands uvicorn the already-bound socket and
    therefore has no race at all, this one binds, reads the port and
    RELEASES it — a subprocess cannot inherit our socket, and
    `serve --port 0` is undiscoverable because `serve()` logs the
    REQUESTED port (`server.py`'s "serving … at http://host:port"), not
    `httpd.server_address`. The gap between release and the child's bind
    is therefore real.

    It is made self-detecting rather than merely unlikely: readiness is a
    full `initialize` round-trip that must come back with a minted
    `Mcp-Session-Id` (see `ServeHarness.wait_until_ready`). A foreign
    listener that stole the port answers a bare TCP connect happily and
    this probe not at all, so the race surfaces as an explicit readiness
    failure naming the port instead of a mystery timeout later.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


class ServeHarness:
    """One `mcp-stdio serve` subprocess, plus what a pin test needs to drive it.

    A SUBPROCESS, deliberately, where the unit suite uses `build_server`
    in-process: P3-0's job is to pin the deployed artifact — argv parsing,
    the `--` command split, signal-driven teardown and all — because that
    is what later Phase 3 PRs could break without any in-process test
    noticing.
    """

    def __init__(self, proc: subprocess.Popen, port: int, stderr: _StderrDrain) -> None:
        self.proc = proc
        self.port = port
        self.stderr = stderr

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def base(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def diagnose(self) -> str:
        return f"serve stderr tail:\n{self.stderr.tail()}"

    # --- requests -----------------------------------------------------

    def post(
        self,
        message: dict,
        *,
        sid: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ):
        import httpx

        merged = dict(headers or {})
        if sid is not None:
            merged["Mcp-Session-Id"] = sid
        return httpx.post(
            self.url, content=json.dumps(message), headers=merged, timeout=timeout
        )

    def delete(
        self,
        *,
        sid: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ):
        import httpx

        merged = dict(headers or {})
        if sid is not None:
            merged["Mcp-Session-Id"] = sid
        return httpx.request("DELETE", self.url, headers=merged, timeout=timeout)

    def open_session(self) -> str:
        """`initialize` a fresh session and return its minted id."""
        resp = self.post(
            {
                "jsonrpc": "2.0",
                "id": "open",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "p3-0-pin-suite", "version": "0"},
                },
            }
        )
        assert resp.status_code == 200, (resp.status_code, resp.text, self.diagnose())
        sid = resp.headers.get("mcp-session-id")
        assert sid, f"serve minted no session id\n{self.diagnose()}"
        return sid

    # --- lifecycle ----------------------------------------------------

    def wait_until_ready(self) -> None:
        """Bounded poll for OUR serve, proved by a minted session id (rule 1)."""
        import httpx

        state: dict[str, object] = {"last": "no attempt completed"}

        def _up() -> bool:
            if self.proc.poll() is not None:
                raise AssertionError(
                    f"serve exited with {self.proc.returncode} before it was ready"
                    f"\n{self.diagnose()}"
                )
            try:
                resp = httpx.post(
                    self.url,
                    content=json.dumps(
                        {"jsonrpc": "2.0", "id": "ready", "method": "initialize"}
                    ),
                    timeout=2.0,
                )
            except httpx.HTTPError as exc:
                state["last"] = f"{type(exc).__name__}: {exc}"
                return False
            sid = resp.headers.get("mcp-session-id")
            state["last"] = f"HTTP {resp.status_code}, Mcp-Session-Id={sid!r}"
            if resp.status_code == 200 and sid:
                # Leave no probe session behind: it would hold a child
                # process for the whole module and skew any test that
                # reasons about session count.
                self.delete(sid=sid)
                return True
            return False

        wait_until(
            _up,
            _SERVE_START_TIMEOUT,
            f"mcp-stdio serve on port {self.port} to answer initialize",
            diagnose=lambda: f"last probe: {state['last']}\n{self.diagnose()}",
        )

    def close(self) -> None:
        """Rule 6 for the gateway: terminate -> wait -> kill, all bounded.

        SIGTERM is serve's own documented shutdown path (`serve()` installs
        it), so the graceful case exercises production code. Child
        processes are reaped by serve's own `registry.shutdown_all()` in
        its `finally`; a kill would orphan them, which is why the
        terminate step gets the generous bound and the kill is the last
        resort.
        """
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=_SERVE_STOP_TIMEOUT)
            except subprocess.TimeoutExpired:  # pragma: no cover — wedged serve
                self.proc.kill()
                self.proc.wait(timeout=_SERVE_STOP_TIMEOUT)
        for stream in (self.proc.stdout, self.proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:  # pragma: no cover
                pass


def spawn_serve(
    *,
    command: list[str] | None = None,
    extra_args: list[str] | None = None,
) -> ServeHarness:
    """Start `mcp-stdio serve` as a subprocess and wait for it to answer.

    `sys.executable -m mcp_stdio serve` rather than the console script, for
    the same reason `spawn_relay` does it: it pins the gateway to the
    interpreter running the tests, independent of PATH and of whether the
    venv is activated. The backend command follows the options after the
    `--` separator serve documents.
    """
    port = _reserve_port()
    args = [sys.executable, "-m", "mcp_stdio", "serve", "--host", "127.0.0.1"]
    args += ["--port", str(port)]
    args += extra_args or []
    args += ["--", *(command or LEGACY_CHILD_COMMAND)]
    proc = subprocess.Popen(  # noqa: S603 — fixed argv, no shell
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_clean_env(),
    )
    harness = ServeHarness(proc, port, _StderrDrain(proc.stderr))
    try:
        harness.wait_until_ready()
    except BaseException:
        harness.close()
        raise
    return harness


@pytest.fixture(scope="module")
def serve_gateway() -> Iterator[ServeHarness]:
    """The shared `mcp-stdio serve` under test (module-scoped).

    Module-scoped for the same reason `harness_server` is: it holds no
    per-test state worth isolating — every test opens its OWN session, and
    a session is the unit of isolation serve actually provides — while a
    subprocess boot plus a readiness round-trip costs real wall-clock.
    Tests that need a gateway they may disrupt take `serve_factory`.
    """
    harness = spawn_serve()
    try:
        yield harness
    finally:
        harness.close()


@pytest.fixture
def serve_factory() -> Iterator[Callable[..., ServeHarness]]:
    """Fresh `mcp-stdio serve` instances bound to one test (function-scoped).

    For tests that stop the gateway, exhaust a cap, or need non-default
    flags — doing any of that to the shared instance would break every
    later test in the module.
    """
    made: list[ServeHarness] = []

    def _make(**kwargs) -> ServeHarness:
        harness = spawn_serve(**kwargs)
        made.append(harness)
        return harness

    try:
        yield _make
    finally:
        for harness in made:
            harness.close()
