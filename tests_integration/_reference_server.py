"""The python-sdk v2.0.0 reference peer, as an in-process ASGI app.

WHY the reference peer and not another mock: every one of the unit suite's
1,637 tests is written against hand-built mocks shaped by this project's own
reading of spec rev 2026-07-28. #270 Design Amendment A9 is the standing
proof that this can go wrong silently — the relay put `resourceSubscriptions`
at the top level of `params`, its mocks agreed, every test was green, and a
compliant server would have ignored the filter while the relay read the ack
echo as "nothing honored". python-sdk v2.0.0 (released 2026-07-28) is the
first OFFICIAL implementation of that spec revision, so driving the relay
against it upgrades the guarantee from "matches our reading" to
"interoperates with the reference".

Everything registered here maps to one scenario in `test_e2e.py`:

- `add`               plain tool                 -> scenario 2
- `guarded_op`        `Resolve`/`Elicit` resolver -> scenario 3 (MRTR)
- `wait_for_release`  async, event-gated          -> scenario 6 (cancel)
- `test://res`        subscribable resource       -> scenario 4

The MRTR tool uses the resolver DAG rather than `ctx.elicit()`: on a modern
(2026-07-28) connection the SDK forbids server-to-client requests outright
(`NoBackChannelError`), and the resolver is what the framework compiles into
an `InputRequiredResult` for that era. Template: the SDK's own
`docs_src/elicitation/tutorial004.py`.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from typing import Annotated, Any

import anyio
from mcp.server import MCPServer
from mcp.server.mcpserver import (
    AcceptedElicitation,
    Context,
    CancelledElicitation,
    DeclinedElicitation,
    Elicit,
    ElicitationResult,
    Resolve,
)
from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler
from mcp.shared.subscriptions import ResourceUpdated
from mcp.types import SubscriptionsListenRequestParams
from pydantic import BaseModel

# The URI the subscribable resource is published under. Matching is
# exact-string on the SDK side, so the test, the tool and the resource
# decorator must all name the same literal.
RESOURCE_URI = "test://res"

# Named on purpose (#367 required change 8): an unnamed MCPServer combined
# with a custom `RequestStateSecurity(audience=None)` raises `ValueError`.
# The base suite uses defaults and would not hit it, but the deferred
# torture-knob work will, and a name costs nothing today.
SERVER_NAME = "mcp-stdio-harness"


class Confirm(BaseModel):
    """The elicited payload — one boolean is enough to prove the round-trip."""

    ok: bool


async def confirm_step(path: str) -> Confirm | Elicit[Confirm]:
    """Resolver: always ask, so the scenario is deterministic.

    A resolver may also answer without a round-trip (the SDK's tutorial
    skips the prompt for an empty folder); unconditionally eliciting is what
    makes the MRTR exchange happen on every run.

    MODULE level, not a closure inside `build_app`: the SDK resolves tool
    annotations with `inspect.signature(..., eval_str=True)` against the
    function's GLOBALS, so a `Resolve(<local>)` in an annotation raises
    `InvalidSignature` under `from __future__ import annotations`. It also
    makes the `module:qualname` key the SDK derives for `inputRequests`
    stable.
    """
    return Elicit(f"Really operate on {path}?", Confirm)


@dataclass
class Harness:
    """One booted reference peer, with the handles a test needs.

    Bundled rather than passed around loose because scenarios 4-6 all need
    to reach PAST the HTTP surface — publish on the bus, close listen
    streams, read the cancellation side-channel. That is the whole reason
    the server runs in-process instead of as a second subprocess.
    """

    app: Any
    port: int
    server: Any

    # Set by the app builder; see `build_app`.
    bus: InMemorySubscriptionBus = None  # type: ignore[assignment]
    listen_handler: ListenHandler = None  # type: ignore[assignment]
    cancelled: threading.Event = None  # type: ignore[assignment]
    release: Any = None
    loop_holder: Any = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def publish_resource_updated(self, uri: str = RESOURCE_URI, timeout: float = 5.0):
        """Publish a `ResourceUpdated` from the TEST thread, safely.

        `SubscriptionBus.publish` is a coroutine and its fan-out pushes into
        anyio memory streams owned by the server's event loop, so calling it
        from the test thread directly is not safe. This hops onto the loop
        the app captured on its first request and waits for completion, so
        the caller knows the event was delivered to every listener before it
        starts expecting the forwarded notification.
        """
        loop = self.loop_holder.get(timeout=timeout)
        future = asyncio.run_coroutine_threadsafe(
            self.bus.publish(ResourceUpdated(uri=uri)), loop
        )
        return future.result(timeout=timeout)

    def end_listen_streams(self) -> None:
        """Gracefully end every open `subscriptions/listen` stream.

        `ListenHandler.close()` is the SDK's documented graceful-closure
        hook: each stream drains its backlog and sends its
        `SubscriptionsListenResult` as the final frame — "telling clients the
        stream ended deliberately rather than dropping", which is exactly
        the signal #352 PR A's graceful-end arm exists to recognize.
        """
        self.listen_handler.close()

    def release_waiter(self, timeout: float = 5.0) -> None:
        """Let a parked `wait_for_release` finish normally (cleanup path)."""
        loop = self.loop_holder.get(timeout=timeout)
        loop.call_soon_threadsafe(self.release.set)


class _LoopHolder:
    """Captures the server's running event loop on the first request.

    An ASGI wrapper rather than a lifespan hook: it depends on nothing but
    the ASGI contract, so an SDK or Starlette change to lifespan wiring
    cannot silently strand the publish helper. By the time any test
    publishes, the relay's own era probe has long since driven a request
    through.
    """

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()

    def capture(self) -> None:
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
            self._ready.set()

    def get(self, timeout: float = 5.0) -> asyncio.AbstractEventLoop:
        if not self._ready.wait(timeout):
            raise TimeoutError("the harness server never handled a request")
        assert self._loop is not None
        return self._loop


def _wrap(inner, holder: _LoopHolder):
    async def app(scope, receive, send):
        holder.capture()
        await inner(scope, receive, send)

    return app


def build_app() -> tuple[Any, dict[str, Any]]:
    """Build one independent reference peer.

    A FACTORY, not a module-level singleton: scenarios 5 and 6 need their
    own server (they end streams / stop the process), and module-level tool
    registration would make the side-channel state shared across them.
    """
    bus = InMemorySubscriptionBus()
    mcp = MCPServer(SERVER_NAME, subscriptions=bus)

    cancelled = threading.Event()
    release = anyio.Event()

    @mcp.tool()
    def add(a: int, b: int) -> int:
        """Add two integers."""
        return a + b

    @mcp.tool()
    async def guarded_op(
        path: str,
        confirm: Annotated[ElicitationResult[Confirm], Resolve(confirm_step)],
    ) -> str:
        """Operate on a path, after confirmation."""
        match confirm:
            case AcceptedElicitation(data=Confirm(ok=True)):
                return f"done {path}"
            case AcceptedElicitation():
                return "kept"
            case DeclinedElicitation():
                return "declined"
            case CancelledElicitation():
                return "cancelled"

    @mcp.tool()
    async def wait_for_release(ctx: Context) -> str:
        """Emit one progress notification, then park until released or cancelled.

        MUST be async: the SDK runs sync tools in `anyio.to_thread.run_sync`,
        where a cancel scope cannot interrupt them, so a sync version would
        never observe the cancellation scenario 6 is about. The disconnect
        chain is the SDK's `watch_disconnect`, which cancels this handler's
        scope when the POST connection sees `http.disconnect` — i.e. when
        the relay aborts the in-flight POST.

        The progress report is load-bearing, and finding that out is one of
        this harness's results. The v2 streamable-HTTP path DEFERS
        `http.response.start` until the handler emits its first notification
        or `_SSE_PING_INTERVAL` (15 s) elapses — so a tool that parks
        silently leaves the relay with no response object to close, i.e. in
        PR D's documented pre-headers window, for a full 15 seconds. Emitting
        first commits the SSE headers, which is both the realistic shape of a
        long-running tool and the state scenario 6 actually means to test.
        Requires the caller to pass a `progressToken` in `params._meta`; the
        test gates its cancel on seeing that notification come back out of
        the relay, which is the only downstream-observable proof that the
        headers landed.
        """
        await ctx.report_progress(1.0, 2.0, "parked")
        try:
            await release.wait()
            return "released"
        except anyio.get_cancelled_exc_class():
            cancelled.set()
            raise

    @mcp.resource(RESOURCE_URI)
    def resource() -> str:
        """A resource whose updates the test publishes out of band."""
        return "hello"

    # Replace the auto-registered listen handler with one this process keeps
    # a reference to. `add_request_handler` documents that it replaces any
    # existing handler for the method, and `ListenHandler` documents
    # registration through it — the only unsupported step is reaching the
    # lowlevel server, which MCPServer exposes privately. That buys
    # scenario 5 the STRONG assertion (a real graceful end, the spec's own
    # closure flow) instead of shutting the whole server down and inferring.
    listen_handler = ListenHandler(bus)
    mcp._lowlevel_server.add_request_handler(  # noqa: SLF001 — see above
        "subscriptions/listen",
        SubscriptionsListenRequestParams,
        listen_handler,
    )

    holder = _LoopHolder()
    app = _wrap(mcp.streamable_http_app(), holder)
    return app, {
        "bus": bus,
        "listen_handler": listen_handler,
        "cancelled": cancelled,
        "release": release,
        "loop_holder": holder,
    }
