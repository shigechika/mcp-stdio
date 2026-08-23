"""Reverse gateway: expose a local stdio MCP server as a Streamable HTTP endpoint.

This is the mirror image of :mod:`mcp_stdio.relay`. ``relay`` is the client
side (stdio in, HTTP out); this module is the server side (HTTP in, stdio out):
it spawns a local stdio MCP server as a child process and publishes it as a
Streamable HTTP MCP endpoint, so clients that cannot spawn the server locally
(a laptop without it installed, a remote bot) can reach it over the network.

One backend child PER SESSION. Authentication is optional and layered: with no
token the endpoint is open; ``--auth-token`` adds a static-bearer Resource
Server gate; ``--enable-oauth`` adds an embedded OAuth 2.1 Authorization
Server. The HTTP surface implements the MCP Streamable HTTP transport's
request/response and notification semantics, session management (an
``Mcp-Session-Id`` minted on ``initialize``, 404 on an unknown id, DELETE to
terminate), plus a GET SSE channel for server-initiated messages.

Stdlib only (``http.server`` + ``subprocess`` + ``threading``), matching the
project's httpx-only-runtime constraint: the server path adds no dependency.

Concurrency model: each MCP session owns a dedicated backend child (see
:class:`SessionRegistry`) that speaks newline-delimited JSON-RPC over its
stdin/stdout. Per child, a single reader thread drains stdout and routes each
message — a response (id + result/error, no method) wakes the waiting HTTP
handler keyed by the JSON-RPC id; anything server-initiated (carries
``method``) is queued for that session's GET SSE stream.

Multi-client isolation is by process boundary: concurrent clients land on
distinct sessions and distinct children, so a JSON-RPC id collision across
clients cannot cross responses (each id is unique within its own child).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import queue
import re
import secrets
import select
import signal
import socket
import subprocess
import threading
import time
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from .relay import (
    _META_CLIENT_CAPABILITIES,
    _META_PROTOCOL_VERSION,
    _META_SERVER_INFO,
    _META_SUBSCRIPTION_ID,
    _NAME_BEARING_METHODS,
    _decode_mcp_name,
    log,
)
from .token_store import _atomic_write_json_file, _read_json_object_file

# Bound how long an HTTP request waits for the backend to answer before the
# handler synthesizes a JSON-RPC error. A backend that wedges must not pin the
# HTTP connection open forever.
_BACKEND_RESPONSE_TIMEOUT_SECS = 120.0

# How long a GET SSE stream blocks on the outbound queue before emitting an
# SSE comment as a keepalive (also the cadence at which it notices shutdown).
_SSE_KEEPALIVE_SECS = 15.0

# RFC 9728 Protected Resource Metadata well-known prefix. The full metadata URL
# inserts this between origin and the resource path (RFC 9728 Sec. 3.1), e.g.
# resource ``https://h/mcp`` -> ``https://h/.well-known/oauth-protected-resource/mcp``.
_PRM_WELL_KNOWN_PREFIX = "/.well-known/oauth-protected-resource"

# Environment variable carrying the gateway's static bearer token. Preferred
# over the --auth-token flag, which would expose the token in ``ps`` output.
_SERVE_TOKEN_ENV = "MCP_STDIO_SERVE_TOKEN"

# Host characters we allow when reflecting a (possibly proxy-supplied) Host /
# X-Forwarded-Host into an absolute metadata URL. Restricting to this set keeps
# a hostile Host header from injecting a quote/space into the quoted
# ``resource_metadata`` challenge parameter or the JSON body -- CR/LF included,
# which is why CodeQL alert #9 (py/http-response-splitting on the
# WWW-Authenticate header built from this value) was dismissed as a false
# positive.
_HOST_ALLOWED = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:[]"
)


def _sanitize_host(host: str) -> str:
    """Keep only safe host[:port] characters; empty -> caller falls back."""
    return "".join(c for c in host if c in _HOST_ALLOWED)


def _classify(msg: Any) -> str:
    """Classify a parsed JSON-RPC message for routing.

    Returns one of ``"request"`` (method + id — expects a response),
    ``"notification"`` (method, no id), ``"response"`` (id + result/error,
    no method — e.g. a client answering a server-initiated request), or
    ``"invalid"`` (anything else, including non-objects and batches, which
    not handled here).
    """
    if not isinstance(msg, dict):
        return "invalid"
    has_method = "method" in msg
    has_id = "id" in msg
    if has_method and has_id:
        return "request"
    if has_method and not has_id:
        return "notification"
    if not has_method and has_id and ("result" in msg or "error" in msg):
        return "response"
    return "invalid"


def _error_body(
    message: str, req_id: Any = None, *, code: int = -32000, data: Any = None
) -> str:
    """Build a JSON-RPC error response line.

    ``code`` defaults to ``-32000`` — the implementation-defined
    server-error range — so every pre-existing call site keeps emitting
    byte-identical bytes, which is what lets #270 Phase 3 P3-A widen the
    MODERN path's codes without touching a single legacy rejection (AC2,
    and the P3-0 pin suite is the judge).

    ``data`` is attached as the optional ``error.data`` member (JSON-RPC
    2.0 §5.1) when not None — INSIDE the error object, not beside it.
    Spec rev 2026-07-28 makes it mandatory on exactly one code:
    ``-32022 UnsupportedProtocolVersion`` must carry the versions the
    server does support, so a client can renegotiate instead of guessing.

    Deliberately NOT relay's ``_error_response``: that one is
    line-oriented for the stdio wire and carries its own defaults. Same
    shape, different transport, no import.
    """
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return json.dumps({"jsonrpc": "2.0", "error": error, "id": req_id})


# --- modern (spec rev 2026-07-28) request-plane validation (#270 P3-A) ---

# The modern revisions SERVE claims to implement. Deliberately NOT reused
# from relay's `_RELAY_IMPLEMENTED_MODERN_VERSIONS`: the two gateways make
# separate conformance claims about opposite sides of the wire, and a
# future revision one of them implements first must not be advertised by
# the other for free. Fed verbatim into `-32022`'s `data.supported`.
_SERVE_IMPLEMENTED_MODERN_VERSIONS = frozenset({"2026-07-28"})

# Spec rev 2026-07-28 error codes. -32602 is JSON-RPC's own Invalid Params;
# the other two are MCP's, from the -32020..-32099 range the spec reserves
# for itself (which is also why serve mints no NEW -32002: that code is
# grandfathered for relay's cold-start gate only, obligation O18).
_JSONRPC_INVALID_REQUEST = -32600
_JSONRPC_METHOD_NOT_FOUND = -32601
_JSONRPC_INVALID_PARAMS = -32602
# The modern path's failure code. NOT a fresh -32000 mint: O18 says "new
# implementations SHOULD NOT use codes from this sub-range at all", and
# -32603 Internal error is JSON-RPC's own name for "the gateway broke".
_JSONRPC_INTERNAL_ERROR = -32603
_MCP_HEADER_MISMATCH = -32020
# O11, and #375's one code with no relay precedent to copy: "the server
# MUST return a `MissingRequiredClientCapabilityError` (-32021) whose
# `data.requiredCapabilities` lists the missing capabilities". Relay can
# never emit it — only SERVERS can — so its bridge aborts generically;
# serve IS the server in this direction, and copying relay's generic
# error here would be non-conformant.
_MCP_MISSING_CLIENT_CAPABILITY = -32021
_MCP_UNSUPPORTED_PROTOCOL_VERSION = -32022

# Headers whose value the spec mirrors from the request body, and which a
# compliant server therefore validates. A REPEATED one is ambiguous — the
# folded `headers.get()` silently returns the first — so they are checked
# for duplication before anything reads them.
_MODERN_ROUTING_HEADERS = ("MCP-Protocol-Version", "Mcp-Method", "Mcp-Name")

# The listen filter's boolean fields, and the notification method each
# one opts into. Mirrors relay's `_LISTEN_FORWARDED_NOTIFICATIONS` on the
# other side of the wire. Spec: exactly these may ride the stream —
# "Request-scoped notifications like notifications/progress and
# notifications/message are not delivered on the listen stream", so the
# table is a whitelist and everything absent from it is dropped.
_LISTEN_FILTER_METHODS = {
    "toolsListChanged": "notifications/tools/list_changed",
    "promptsListChanged": "notifications/prompts/list_changed",
    "resourcesListChanged": "notifications/resources/list_changed",
}
_LISTEN_FORWARDED_METHODS = frozenset(_LISTEN_FILTER_METHODS.values())

# The fourth filter field, and deliberately NOT a member of the table
# above (#381 §3.4). The trio's fields are booleans, so membership in
# `_LISTEN_FORWARDED_METHODS` is the whole test; `resourceSubscriptions`
# carries a URI LIST, so a stream wants this method only for the specific
# URIs it asked for. Folding it into the boolean table would make
# `wants()` true for any non-empty list and deliver every URI's update to
# every subscriber — which is exactly the "MUST NOT send notification
# types the client has not explicitly requested" violation the table
# exists to prevent, and across streams a cross-subscription leak.
# Relay hit the identical fork and resolved it the same way: its own
# `_RESOURCE_UPDATED_METHOD` gets a dedicated branch with its own gates.
_RESOURCE_UPDATED_METHOD = "notifications/resources/updated"
_LISTEN_RESOURCE_FIELD = "resourceSubscriptions"

# O16 (#270) is CLOSED BY CONSTRUCTION, and this comment is the whole
# implementation (#381 §3.7). The open question was whether serve needs a
# `io.modelcontextprotocol/logLevel` gate before emitting
# `notifications/message`. It does not, on three independent grounds:
#
# 1. Suppression on this stream is a hard MUST NOT — "notifications/
#    message is request-scoped: the server MUST NOT deliver it on a
#    subscriptions/listen stream" — and the sets above are a WHITELIST.
#    That method is not a member and never becomes one, so the rule
#    holds without any runtime check to forget or get wrong.
# 2. There is no other streaming channel on serve's modern face for it
#    to attach to even if one were wanted: modern requests are answered
#    as single JSON objects, and the legacy GET SSE stream carries no
#    per-request `_meta` to read a log level out of.
# 3. Nothing obliges a server to declare `logging` or to emit
#    `notifications/message` at all, and SEP-2577 DEPRECATED the feature
#    in 2026-07-28 ("New implementations SHOULD NOT adopt it"), so a
#    permanent decline is fully spec-legal rather than a shortfall.
#
# Revisit only if some future change introduces a genuinely new
# server->client streaming channel (#375's reverse-MRTR bridge is the
# only candidate). The legacy GET SSE path is untouched and out of scope.
_LISTEN_METHOD = "subscriptions/listen"
_LISTEN_ACK_METHOD = "notifications/subscriptions/acknowledged"

_MODERN_DISCOVER_METHOD = "server/discover"


def _request_era(kind: str, msg: dict[str, Any]) -> str:
    """Classify one parsed POST body as ``"modern"`` or ``"legacy"``.

    #270 Phase 3 decision D5, and it is deliberately CONSERVATIVE: modern
    only on POSITIVE modern evidence, everything else falls through to the
    untouched legacy path, so a legacy client can never be misclassified
    into a validation ladder it has no idea exists. That direction is what
    makes AC2 hold for shapes nobody thought to test.

    The evidence, matching the spec's own discrimination rule ("A request
    carrying modern per-request `_meta` is served statelessly … An
    `initialize` request selects legacy semantics"):

    - ``params._meta`` carries the ``protocolVersion`` key. PRESENCE, not
      validity: a malformed value must reach the ladder and earn a real
      rejection, not be quietly demoted to legacy where it would get a
      session error that says nothing about what was wrong.
    - or the method is ``server/discover``, which exists only on the
      modern wire. This arm is an mcp-stdio-local widening for
      CLASSIFICATION only — the SDK routes by header, which serve cannot
      see before parsing — and it softens nothing: a `_meta`-less
      discover classifies modern and is rejected by the ladder's first
      rung like any other modern request missing `_meta`.

    A ``response``-shaped body is never modern (spec rev 2026-07-28
    removed server-initiated requests, so clients never POST responses),
    and neither is anything that failed the shape checks upstream — both
    keep today's behavior exactly.
    """
    if kind not in ("request", "notification"):
        return "legacy"
    if msg.get("method") == _MODERN_DISCOVER_METHOD:
        return "modern"
    params = msg.get("params")
    if not isinstance(params, dict):
        return "legacy"
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return "legacy"
    return "modern" if _META_PROTOCOL_VERSION in meta else "legacy"


def _modern_name_bearing_value(msg: dict[str, Any]) -> str | None:
    """The body value ``Mcp-Name`` must mirror, or None when there is none.

    ``None`` covers both "this method has no name-bearing field" and "the
    field is absent from this body". The second is deliberate (design
    §2.2 rung 2c): a name-bearing method whose ``params`` are missing
    entirely has no body value to compare against, so the header check is
    SKIPPED and the request falls through — dispatch owns missing-param
    errors, and inventing a header mismatch for a body problem would
    report the wrong fault.

    Reads the parsed body directly rather than calling relay's
    ``_extract_method_and_name``, which takes a serialized line: the
    handler already has the object, and re-serializing to re-parse cannot
    round-trip exactly.
    """
    method = msg.get("method")
    if not isinstance(method, str):
        return None
    name_key = _NAME_BEARING_METHODS.get(method)
    if name_key is None:
        return None
    params = msg.get("params")
    if not isinstance(params, dict):
        return None
    value = params.get(name_key)
    return value if isinstance(value, str) else None


def _validate_modern(handler: Any, kind: str, msg: dict[str, Any], req_id: Any) -> bool:
    """Run the modern validation ladder; False means a 4xx was already sent.

    #270 Phase 3 P3-A, obligations O6-O10. FIRST FAILURE WINS, in the
    order python-sdk v2 uses — which is NOT the order the obligations are
    numbered in. The header rungs run BEFORE the unsupported-version rung,
    for the SDK's own stated reason: it "runs before the supported-version
    rung so a client that disagrees with itself is told so, rather than
    told the body's version is unsupported." That ordering is load-bearing
    rather than cosmetic: ``-32022`` is the one code an auto-negotiating
    client does NOT fall back from, so emitting it for a self-inconsistent
    request would strand a client that could have fixed its headers.

    NOTIFICATIONS ARE A FULL NO-OP — no `_meta` check, no header checks.
    The spec says "header requirements for notification POSTs are not
    defined by this revision" (obligation O9), so both accepting and
    rejecting are conformant, and the tie is broken by the P3-0 pin:
    `test_notification_post_needs_a_session_first` says a sessioned
    notification is 202 and a sessionless one is 400 `-32000`, today and
    after this PR. python-sdk v2 400s every notification POST; serve
    deliberately does NOT copy that (divergence ledger item i). The
    exemption is broader than O9's headers-only wording on purpose:
    validating `_meta` would 400 a sessioned notification that 202s
    today, which is exactly the behavior change D5's conservatism forbids.

    Messages NAME the offending header and never echo its value or the
    body's. The spec's value-echoing example is non-normative, and
    reflecting attacker-controlled header bytes into a response body is
    not a thing to do for a debugging nicety (the SDK makes the same
    choice). `-32020` carries no `data` at all per the schema.

    Every rejection here runs AFTER the body was drained (`do_POST` reads
    it before any early return) so the keep-alive contract holds by
    construction, and BEFORE session resolution, so `handler._session_id`
    is still None and no `Mcp-Session-Id` can leak onto a rejection.
    """
    if kind == "notification":
        return True

    def _reject(message: str, code: int, data: Any = None) -> bool:
        handler._send_json(400, _error_body(message, req_id, code=code, data=data))
        return False

    # Rung 0 — a repeated routing header (SDK step 0; the spec is silent).
    # `headers.get()` folds duplicates to the first value, so without this
    # a client could send one `Mcp-Method` that matches the body and a
    # second that does not, and serve would validate the one an
    # intermediary might not forward. Checked on the raw pairs.
    for header in _MODERN_ROUTING_HEADERS:
        values = handler.headers.get_all(header)
        if values is not None and len(values) > 1:
            return _reject(
                f"{header} header appears more than once",
                _MCP_HEADER_MISMATCH,
            )

    # Rung 1 — required `_meta` (O6). Both keys are REQUIRED; `clientInfo`
    # is SHOULD-only and is never rejected on.
    params = msg.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    if not isinstance(meta, dict):
        return _reject(
            "request params._meta is required and must be an object carrying "
            f"{_META_PROTOCOL_VERSION} and {_META_CLIENT_CAPABILITIES}",
            _JSONRPC_INVALID_PARAMS,
        )
    missing = [
        key
        for key in (_META_PROTOCOL_VERSION, _META_CLIENT_CAPABILITIES)
        if key not in meta
    ]
    if missing:
        return _reject(
            f"request params._meta is missing required key(s): {', '.join(missing)}",
            _JSONRPC_INVALID_PARAMS,
        )

    body_version = meta.get(_META_PROTOCOL_VERSION)

    # Rung 2a — header/body version agreement (O7, and P3-A's AC4).
    # ABSENCE IS A MISMATCH: the header is REQUIRED, so a missing one is a
    # HeaderMismatch condition in its own right.
    #
    # The presence test is EXPLICIT rather than folded into the equality,
    # and that is #270 P3-B commit 0 closing a P3-A advisory: `None !=
    # None` is False, so an absent header paired with a body carrying
    # `"protocolVersion": null` slipped rung 2a entirely and fell through
    # to the "unreachable" rung 3, answering -32602 for what is plainly a
    # header fault. python-sdk v2 guards it the same way, for the same
    # stated reason (`mcp/shared/inbound.py`): "Presence is checked
    # explicitly: a null body version would otherwise slip the equality
    # check (None == None) and mask the absent header."
    version_header = handler.headers.get("MCP-Protocol-Version")
    if version_header is None or version_header != body_version:
        return _reject(
            "MCP-Protocol-Version header does not match the protocol version "
            "in the request body's _meta",
            _MCP_HEADER_MISMATCH,
        )

    # Rung 2b — `Mcp-Method` mirrors `method`, compared RAW. The base64
    # sentinel is defined only for `Mcp-Name`/`Mcp-Param-{Name}` (the
    # "Server Validation" section names exactly those two), so decoding
    # here would accept an encoding no compliant client may send.
    if handler.headers.get("Mcp-Method") != msg.get("method"):
        return _reject(
            "Mcp-Method header does not match the request method",
            _MCP_HEADER_MISMATCH,
        )

    # Rung 2c — `Mcp-Name` mirrors the body's name/uri, DECODED first
    # (O8's MUST). A malformed sentinel decodes to None, which never
    # equals the body value, so a corrupt header lands here rather than
    # needing a code of its own.
    name_value = _modern_name_bearing_value(msg)
    if name_value is not None:
        if _decode_mcp_name(handler.headers.get("Mcp-Name")) != name_value:
            return _reject(
                "Mcp-Name header does not match the corresponding request body value",
                _MCP_HEADER_MISMATCH,
            )

    # Rung 3 — defensive only, and unreachable over HTTP: a non-string
    # body version cannot equal the header string, so rung 2a already
    # rejected it. Kept so the rung below can assume a string.
    if not isinstance(body_version, str):  # pragma: no cover — see above
        return _reject(
            f"{_META_PROTOCOL_VERSION} must be a string",
            _JSONRPC_INVALID_PARAMS,
        )

    # Rung 4 — the version is one serve implements (O10). `data` is
    # SCHEMA-MANDATED here, not a nicety: without `supported` a client has
    # nothing to renegotiate toward.
    if body_version not in _SERVE_IMPLEMENTED_MODERN_VERSIONS:
        return _reject(
            "Unsupported protocol version",
            _MCP_UNSUPPORTED_PROTOCOL_VERSION,
            data={
                "supported": sorted(_SERVE_IMPLEMENTED_MODERN_VERSIONS),
                "requested": body_version,
            },
        )
    return True


# --- modern dispatch: gateway-owned children (#270 Phase 3 P3-B) ---

# The id namespace serve mints into, mirroring relay's `_RELAY_ID_NAMESPACE`
# precedent. Process-global and monotonic, so two concurrent modern clients
# sharing one child can never collide on an id — which is also what makes
# `_DuplicateInFlightId` and the same-payload piggyback unreachable on this
# path. They stay, harmlessly, for the legacy one.
_SERVE_ID_NAMESPACE = "mcp-stdio/serve/"

# The revision the gateway speaks to its OWN pooled children. They are
# ordinary legacy stdio servers — the modern wire stops at serve — so the
# handshake is a 2025-06-18 one, which any unmodified child understands.
_MODERN_CHILD_HANDSHAKE_VERSION = "2025-06-18"

# Caching hints serve stamps on the six cacheable operations (§4 Q2).
# `ttlMs` is operator-tunable via --cache-ttl-ms; the spec's only hard
# constraint is ">= 0". `cacheScope` is hardcoded "private" and should
# stay that way: "public" asserts the response contains no user-specific
# data, which a gateway cannot know about an arbitrary child.
_DEFAULT_CACHE_TTL_MS = 60000
_CACHE_SCOPE = "private"

# --max-message-size (#416, CWE-770): caps the declared Content-Length this
# gateway will read into memory for one request body, so a client cannot
# make it allocate an arbitrary amount of memory just by declaring a huge
# body. Same 10 MiB default as the client-side relay's matching cap
# (relay.py's _DEFAULT_MAX_MESSAGE_SIZE) — kept as an independent constant
# rather than a cross-module import so serve's only runtime dependency stays
# stdlib (importing relay.py would pull in httpx). 0 disables the cap.
_DEFAULT_MAX_MESSAGE_SIZE = 10 * 1024 * 1024

# The six operations spec rev 2026-07-28 requires caching hints on.
# `tools/call` is deliberately ABSENT — `CallToolResult` is not a
# CacheableResult, and the v2 client's model has no ttlMs/cacheScope
# fields at all, so stamping one would be inventing wire data.
_CACHEABLE_METHODS = frozenset(
    {
        "server/discover",
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
        "resources/read",
    }
)


# Per-stream backlog. A full queue ends the stream rather than dropping a
# frame in the middle: a gap is undetectable to the client, whereas a lost
# stream is re-established with fresh state.
_LISTEN_QUEUE_MAX = 1024

# Concurrent listen streams one principal may hold on its pooled child.
# The relay peer opens at most two; the SDK's global limit is far higher.
# A cap exists so one client cannot pin unbounded handler threads.
_LISTEN_MAX_STREAMS_PER_CHILD = 4

# Resource URIs one listen stream may subscribe to (#381 §3.12, owner
# default confirmed). Mirrors relay's own `_LISTEN_MAX_SUBSCRIPTIONS`, and
# a cap rather than a TTL for the same reason: it bounds both the request
# body and the per-child state a hostile client can pin. PER STREAM, not
# per child — an aggregate cap across concurrent streams is deliberately
# left out until operational data says it matters (§4 Q2).
#
# Over the cap serve TRUNCATES and honors the subset rather than
# refusing: the ack echoes exactly what is honored, so a client that
# checks it (the spec's own SHOULD) sees precisely which URIs it got, and
# a partial subscription is strictly more useful than an error the legacy
# `resources/subscribe` never had a shape for.
_LISTEN_MAX_RESOURCE_SUBSCRIPTIONS = 256

# How long one driven `resources/subscribe`/`unsubscribe` waits, and
# deliberately NOT `_BACKEND_RESPONSE_TIMEOUT_SECS` (#388 review).
#
# These drives run under `_sub_lock`, which is held across the I/O so
# subscribe and unsubscribe cannot invert on the wire — and that same
# lock is what a DIFFERENT stream's teardown blocks on. At the ordinary
# 120 s backend timeout a hung child could pin it for 256 x 120 s, so a
# single unresponsive child would stall every other stream's teardown on
# it for hours. The reply carries no information (legacy answers an empty
# result), so waiting long buys nothing: this is bookkeeping whose
# outcome is logged, never surfaced.
#
# The batch ALSO short-circuits — see `_drive_resource_subscription`'s
# callers — so the real worst case is one timeout, not one per URI.
_RESOURCE_SUBSCRIBE_TIMEOUT_SECS = 5.0

# How long a reverse-MRTR round may stay PARKED before serve gives up on
# the client retrying, unblocks the child and drops the txn (#375 §3.8).
#
# This is a genuine gap rather than an already-covered case, and the
# comment exists so nobody "simplifies" it away on the reasoning that the
# dispatch timeout already handles it. It does not: the 120 s
# `send_request` wait belongs to the ORIGINAL handler thread. The moment
# a round parks, that HTTP request completes and its `_pending` slot
# detaches, so the 120 s clock stops governing anything. The child is
# left blocked on a reply to its OWN minted request id, which nothing
# else tracks a deadline for.
#
# Expressed as a RELATIONSHIP to the dispatch timeout, never a literal —
# #388's review round found exactly this class of ratio silently rotting
# once the general constant is bumped. A test pins the inequality.
#
# DELIBERATE POLICY INVERSION FROM RELAY'S PR C, named here because a
# reviewer who knows that code would otherwise read this as a
# contradiction: PR C refuses a TTL on its round because "a transaction
# waits on a human at an elicitation dialog, so a TTL races the user".
# Here the waiter is a POOLED SUBPROCESS holding a resource slot, not a
# human, and Server Requirements item 8 licenses abandoning it outright.
# Bounding this side is correct precisely because bounding the
# human-facing side is not.
_MRTR_PARK_TIMEOUT_SECS = _BACKEND_RESPONSE_TIMEOUT_SECS / 2


def _child_supports_resource_subscribe(init_result: Any) -> bool:
    """Does the pooled child advertise `resources.subscribe`? (#381 §3.2)

    ONE predicate, two call sites — the listen ack's honoring gate and
    discover's capability echo (§3.6). Keeping them on the same function
    is what stops serve advertising a flag it will then decline in the
    ack, or declining one it advertised: the two answers cannot drift
    because there is only one answer.

    Presence-based and truthiness-based both: an absent `resources`
    family, an absent `subscribe` key and an explicit `subscribe: false`
    all mean the same thing to a client, so they mean the same thing
    here. Every lookup degrades on a non-dict rather than raising — a
    misbehaving child forfeits the capability, never the request.
    """
    if not isinstance(init_result, dict):
        return False
    capabilities = init_result.get("capabilities")
    if not isinstance(capabilities, dict):
        return False
    resources = capabilities.get("resources")
    if not isinstance(resources, dict):
        return False
    return bool(resources.get("subscribe"))


def _honored_resource_uris(
    requested: Any, *, supported: bool
) -> tuple[list[str], bool]:
    """The URI subset this stream may subscribe to, and whether it was cut.

    Entirely LOCAL — no child round-trip — which is what makes the ack
    fire-and-forget (§3.3) correct rather than a compromise: the honored
    set is fully decided before anything is driven against the child.

    Three layers, in order:

    1. Capability gate. A child that does not advertise
       `resources.subscribe` honors nothing, and the ack OMITS the field
       rather than echoing `[]` — see the caller.
    2. Sanitize. A non-list is treated as absent; non-string elements are
       dropped silently. Relay hardened the identical read after a real
       incident: an unsanitized list containing a nested list raised
       `TypeError: unhashable type` inside a daemon thread and killed it
       (#358 review R2F1). Duplicates are collapsed, preserving first-seen
       order, so a repeated URI cannot inflate the refcount.
    3. Cap. Over `_LISTEN_MAX_RESOURCE_SUBSCRIPTIONS`, keep the first N.

    NO per-URI accept/reject. There is no servability probe to base one
    on, the reference implementation has none, and inventing one would be
    an undocumented departure — the SDK's own words are that "a
    subscription to a nonexistent resource URI is honored and never
    fires".
    """
    if not supported or not isinstance(requested, list):
        return [], False
    seen: dict[str, None] = {}
    for uri in requested:
        if isinstance(uri, str):
            seen.setdefault(uri, None)
    uris = list(seen)
    if len(uris) > _LISTEN_MAX_RESOURCE_SUBSCRIPTIONS:
        return uris[:_LISTEN_MAX_RESOURCE_SUBSCRIPTIONS], True
    return uris, False


def _accepts_sse(accept_header: str | None) -> bool:
    """Whether an `Accept` header (RFC 9110 §12) permits `text/event-stream`.

    #382 review R1F2 remainder. A prior fix casefolded the comparison but
    kept it a bare substring check, which gets two cases wrong in
    opposite directions:

    - `Accept: text/*` is a valid media RANGE that matches
      `text/event-stream` and must be honored, but does not contain the
      substring `"text/event-stream"`, so it earned a 406.
    - `Accept: text/event-stream;q=0` is an explicit REFUSAL of that
      type (RFC 9110 §12.4.2: q=0 means "not acceptable"), but the
      substring IS present, so it passed.

    Missing or empty is `True`: RFC 9110 §12.5.1 — "A request without
    any Accept header field implies that the user agent will accept any
    media type in response." Absent means accept anything, not accept
    nothing; the substring check used to get this backwards too (`""`
    contains no substring, so a client that omits Accept entirely was
    406'd).

    Each comma-separated range is matched by exact media type or by the
    `text/*` / `*/*` wildcards, case-insensitively (media types are
    case-insensitive, RFC 9110 §8.3.1). An unparsable `q` parameter is
    treated as `q=1` — lenient parsing, consistent with the rest of this
    header's handling — rather than rejected outright.

    A POSITIVE wildcard does not override a more specific explicit
    REFUSAL (#382 review R6F1). `text/event-stream;q=0, */*` used to
    accept — some matching range had `q>0` — but RFC 9110 §12.5.1 says
    the MOST SPECIFIC matching range decides a media type's quality:
    exact `text/event-stream` beats `text/*`, which beats `*/*`. So the
    effective q is looked up by specificity tier, not "any match with
    q>0": if the header explicitly refuses `text/event-stream`, a
    trailing `*/*` cannot undo that. Within one tier, the SAME range
    listed twice with different q (self-contradictory, but headers are
    attacker- or bug-supplied) takes the MAX — lenient toward
    acceptance, matching this function's other leniencies (an
    unparsable `q`, an absent header).
    """
    if not accept_header:
        return True
    tier_q: dict[str, float] = {}
    for range_spec in accept_header.split(","):
        params = range_spec.split(";")
        media_range = params[0].strip().casefold()
        if media_range not in ("text/event-stream", "text/*", "*/*"):
            continue
        q = 1.0
        for param in params[1:]:
            name, _, value = param.strip().partition("=")
            if name.strip().casefold() == "q":
                try:
                    q = float(value.strip())
                except ValueError:
                    q = 1.0
        tier_q[media_range] = max(q, tier_q.get(media_range, 0.0))
    for media_range in ("text/event-stream", "text/*", "*/*"):
        if media_range in tier_q:
            return tier_q[media_range] > 0
    return False


# How often a stream waiting for its next notification re-checks whether
# it has been told to end. A `queue.Queue` and a `threading.Event` cannot
# be waited on jointly, and BOTH endings (gateway shutdown, child death)
# are signalled from another thread — so the wait is sliced rather than
# held for the whole keepalive interval, which would otherwise delay a
# teardown by up to 15 seconds.
_LISTEN_POLL_SECS = 0.25

# How long gateway shutdown waits for the streams it just ended to flush
# their terminal frames and detach. Generous enough for a local socket
# write, short enough that a wedged client cannot hold shutdown hostage.
_LISTEN_DRAIN_SECS = 2.0


class _ListenStream:
    """One attached `subscriptions/listen` stream (#374).

    Owns the honored filter, the listen request's id (echoed verbatim as
    the subscription id — the v2 client mints strings like `"listen-1"`,
    so nothing coerces types), and a BOUNDED queue the child's reader
    thread publishes into.

    Filtering happens here, on the reader thread, so a stream's backlog
    never holds traffic that stream would refuse: "The server MUST NOT
    send notification types the client has not explicitly requested."
    Stamping happens on the handler thread instead, because each stream
    stamps its OWN id and would need its own copy regardless.
    """

    __slots__ = (
        "listen_id",
        "honored",
        "honored_resource_uris",
        "_queue",
        "_ended",
        "_end_lock",
        "_graceful",
        "overflowed",
        "torn_down",
        "subscribe_failure_logged",
    )

    def __init__(
        self,
        listen_id: Any,
        # The ack's `notifications` object verbatim, so the values are
        # mixed by design: `True` for the trio's booleans, a URI list for
        # `resourceSubscriptions` (#381). One dict, because it IS the
        # wire shape rather than a model of it.
        honored: dict[str, Any],
        honored_resource_uris: frozenset[str] = frozenset(),
    ) -> None:
        self.listen_id = listen_id
        self.honored = honored
        # #381. The SAME value the ack echoed and the refcounts were taken
        # for — computed once per stream and handed to all three, because
        # a divergence between them is invisible on the wire: the ack
        # would promise a URI nothing routes to, and the client would just
        # never see an update it was told it would get.
        self.honored_resource_uris = honored_resource_uris
        self._queue: "queue.Queue[dict[str, Any]]" = queue.Queue(_LISTEN_QUEUE_MAX)
        # Set to end the stream: "graceful" emits the terminal result
        # first, "lost" closes abruptly.
        self._ended = threading.Event()
        self._end_lock = threading.Lock()
        self._graceful = False
        self.overflowed = False
        # #381. Set by the handler's `finally` BEFORE it releases the URI
        # refs, and read by the background subscribe thread under the same
        # `_sub_lock` the refs use. That pairing is what makes the two
        # orderings both correct for a stream that dies before its
        # subscriptions land: teardown-first leaves this True so the drive
        # is skipped entirely, and drive-first sees False and subscribes,
        # with teardown's release then unsubscribing normally. Without it
        # a client that disconnects immediately after the ack could have
        # its subscribe arrive AFTER its unsubscribe, leaving the child
        # subscribed forever with no stream to deliver to.
        self.torn_down = False
        # #388 review — a once-per-stream latch, mirroring relay's own
        # `unhonored_logged` idiom (the pattern this project already uses
        # for "log this fact once per URI for the LIFE of the stream, not
        # once per attempt"). Read and written only under `_sub_lock`,
        # from `add_resource_subscriptions` — see that method's docstring
        # for why it exists even though today's single call-per-stream
        # path cannot yet observe it firing twice.
        self.subscribe_failure_logged: set[str] = set()

    def wants(self, method: str) -> bool:
        flag = next((k for k, v in _LISTEN_FILTER_METHODS.items() if v == method), None)
        return flag is not None and bool(self.honored.get(flag))

    def wants_resource_update(self, uri: Any) -> bool:
        """Whether `notifications/resources/updated` for `uri` rides this
        stream (#381 §3.4).

        EXACT string equality, no normalization. There is no child-side
        echo to normalize against — legacy `resources/subscribe` returns
        an empty result — so any rule beyond equality would be serve
        inventing wire behaviour, which this project has declined before
        for the same reason. The consequence is documented rather than
        hidden: URI variants a child might consider the same (trailing
        slash, case, percent-encoding) are separate subscriptions here,
        with separate refcounts and separate drive calls.

        Note the reference CLIENT is deliberately more lenient — it
        admits any `ResourceUpdated` once any URI was honored, since it
        cannot attribute a sub-resource URI to a subscription. Serve
        cannot copy that: it multiplexes several streams over one child,
        so "admit anything" would hand stream A the updates only stream B
        subscribed to. Exact match is also what the shared `event_matches`
        predicate uses on the SDK's own SERVER side, and what relay uses
        in this same gateway role.
        """
        return isinstance(uri, str) and uri in self.honored_resource_uris

    def publish(self, message: dict[str, Any]) -> None:
        """Enqueue a matching notification; never block the reader thread."""
        try:
            self._queue.put_nowait(message)
        except queue.Full:
            # Backlog overflow ends the stream (lost). Blocking here would
            # stall the child's reader for every other consumer, and
            # dropping one frame would leave an undetectable gap.
            self.overflowed = True
            self.signal_end(graceful=False)

    def signal_end(self, *, graceful: bool) -> None:
        """Wind the stream up, recording WHICH ending this is.

        The caller states the intent rather than the pump inferring it
        from surrounding state, because inference races: `shutdown_all`
        signals its streams and then immediately tears the children down,
        so a pump that read `backend.closed` would see a dead child and
        call an orderly shutdown "lost" — telling a compliant peer to
        reconnect to a gateway that is going away.

        THE FIRST ENDING WINS. A shutdown followed by the child's death
        is one ending with two symptoms, and the later symptom must not
        downgrade a graceful teardown the client may already have been
        told about.
        """
        with self._end_lock:
            if self._ended.is_set():
                return
            self._graceful = graceful
            self._ended.set()

    @property
    def ending(self) -> bool:
        return self._ended.is_set()

    @property
    def graceful(self) -> bool:
        """True if the ending earns a terminal result frame."""
        return self._graceful

    def next_message(self, timeout: float) -> dict[str, Any] | None:
        """The next notification, or None on ending / keepalive expiry.

        The caller re-checks `ending` — None means "nothing to write",
        not "keep waiting".
        """
        deadline = time.monotonic() + timeout
        while not self._ended.is_set():
            remaining = min(_LISTEN_POLL_SECS, deadline - time.monotonic())
            if remaining <= 0:
                return None
            try:
                return self._queue.get(timeout=remaining)
            except queue.Empty:
                continue
        return None


class ModernBackendPool:
    """Gateway-owned backend children for the modern, session-less path.

    #270 Phase 3 P3-B, decision D1. The modern wire has no sessions, so
    there is no ``Mcp-Session-Id`` to key a child on — but a child still
    has to exist, and it still needs the ``initialize`` handshake nobody
    on the modern wire performs. This holder owns both.

    KEYED ON THE AUTHENTICATED PRINCIPAL, verbatim as ``_authorized()``
    already derived it. Not a convenience: sharing one child across
    principals would leak child state across the authorization boundary,
    which is why D1 refused to defer per-principal keying. Under no-auth
    and under a static token the principal is a single constant, so those
    collapse to one shared child — consistent with how session ownership
    already treats them.

    The handshake result is CACHED because discover needs it: the child's
    ``capabilities`` and ``serverInfo`` are the only honest source for
    what serve advertises, and re-asking per request would be a
    round-trip for data that cannot change.

    The gateway offers the child ``capabilities: {}`` — D4's valve. A
    child never told the client can sample, elicit or list roots has no
    reason to ask, so the reverse-MRTR bridge P3-B does not ship is never
    needed by a well-behaved one; a misbehaving one meets the reject arm
    instead of hanging the caller.

    Spawning happens OUTSIDE the lock behind a per-principal latch, the
    shape ``SessionRegistry.create`` already uses: two concurrent first
    requests must not spawn two children, and holding the lock across a
    process spawn plus a handshake round-trip would serialise every
    unrelated principal behind it.
    """

    def __init__(
        self,
        command: list[str],
        *,
        max_children: int = 0,
        idle_ttl: float = 0.0,
        now: Any = time.monotonic,
        user_env_var: str | None = None,
    ) -> None:
        if not command:
            raise ValueError("backend command is empty")
        self._command = command
        # `now` is injectable so the reaper's TTL arithmetic can be driven
        # by a fake clock in tests, the way `SessionRegistry` already is.
        self._now = now
        self._idle_ttl = idle_ttl
        # --user-env VAR: the env var name each spawned child's identity is
        # injected under (see `_user_env_value`). None means the flag was
        # not passed -- children inherit the gateway's environment
        # unmodified, exactly as before this parameter existed.
        self._user_env_var = user_env_var
        self._reaper: threading.Thread | None = None
        self._reaper_stop = threading.Event()
        self._lock = threading.Lock()
        # principal -> entry. An entry is either READY (`backend` set) or
        # PENDING (a placeholder another thread is filling, `event` unset).
        # Both live in the same map so a racing thread finds the
        # placeholder instead of starting a second spawn.
        self._entries: dict[Any, dict[str, Any]] = {}
        self._max_children = max_children
        self._seq = 0

    def _next_handshake_id(self) -> str:
        with self._lock:
            self._seq += 1
            return f"{_SERVE_ID_NAMESPACE}init/{self._seq}"

    def _reapable_locked(self, entry: dict[str, Any]) -> bool:
        """READY, quiet and unheld — the only entries anything may drop.

        #376 §2.3. ONE predicate shared by cap-eviction and the idle
        reaper, because two copies of this rule would drift and the
        consequences differ only in which of them kills a live request.

        The three conditions, and why each is separate:

        - a PENDING placeholder has no backend yet. Dropping it detaches
          the entry the spawning thread is about to fill, and that child
          then belongs to nobody — `shutdown_all` cannot reach it, so the
          cap would leak processes rather than bound them.
        - `has_pending` is work already on the wire. Killing it fails an
          ordinary request to make room for one that has not started.
        - `holds` is a handler that has CHECKED THE CHILD OUT but has not
          sent yet (#376 §3.1). `has_pending` alone does not cover it:
          `get_or_create` returns with the pool lock released, and the
          request only becomes pending later, inside the backend's own
          lock. In that window the child looks perfectly idle.

        `holds` is also the seam #374 plugs into: a listen stream takes a
        hold for as long as it is subscribed, so a subscribed child is
        never reaped no matter how old its `used` timestamp is — which is
        exactly why this is a refcount and not another timestamp.
        """
        backend = entry.get("backend")
        return (
            backend is not None
            and not backend.has_pending
            and entry.get("holds", 0) == 0
        )

    def release(self, entry: dict[str, Any]) -> None:
        """Give back a checkout taken by `get_or_create` (#376 §3.1).

        Decrements on the entry dict the caller was handed, not on
        whatever `_entries` holds now: if the entry was replaced or
        reaped meanwhile, the decrement lands on an object nobody
        consults again, which is inert and exactly what we want. Chasing
        identity here would buy nothing and could double-decrement a
        successor.

        RE-SWEEPS the cap when this release leaves the pool over it
        (#379 review, /code-review score 100). A spawn race under
        `max_children` — two principals' FIRST requests each insert a
        PENDING placeholder before either publishes — can settle the
        pool ABOVE the cap: neither publish-time sweep (#376 §3.2) can
        evict the other, still PENDING or still held. This release is
        the THIRD moment (after the pre-insert check and the post-spawn
        re-check) a child can become evictable — the instant a handler
        that was holding it lets go — and without a sweep here that
        overshoot is PERMANENT in a fixed-principal deployment: no new
        principal ever arrives to trigger the pre-insert check, and the
        idle reaper does not save it at the default `--modern-idle-ttl
        0`. Gated on actually being over cap so the common path (pool
        within cap) costs a single integer compare, never a scan.

        The sweep is allowed to pick THIS entry, the one just released —
        there is no "exclude myself" special case, unlike the post-spawn
        re-check's (that one excludes itself for free, since its own
        hold is still 1 when it runs). Excluding the just-released entry
        here would look safer but is not: a principal holding a
        long-lived subscription (#374's hold seam) would then pin an
        overshoot forever, since its release is the only event left that
        could ever trim it.
        """
        with self._lock:
            entry["holds"] = max(0, entry.get("holds", 0) - 1)
            if (
                entry["holds"] == 0
                and self._max_children > 0
                and len(self._entries) > self._max_children
            ):
                self._evict_if_at_cap_locked(reserve=0)

    def _evict_if_at_cap_locked(self, *, reserve: int = 1) -> None:
        """Make room by dropping the idlest child (§4 Q3).

        Evicting beats refusing here in a way it does not for legacy
        sessions, and the asymmetry is principled: a modern client is
        STATELESS, so all an eviction costs it is the warm-up of a child
        it never knew about, whereas a 503 fails a request the gateway
        could have served. The legacy registry keeps the opposite policy
        for the opposite reason — an evicted session strands a client
        mid-conversation.
        """
        if self._max_children <= 0:
            return
        # `reserve` is how many slots the caller still needs. The
        # PRE-insert callers need one (the entry they are about to add),
        # which is the default and the original behaviour. The post-spawn
        # re-check (#376 §3.2) has ALREADY inserted, so it needs none —
        # passing `reserve=1` there would evict a child every time the
        # pool merely reached the cap, rather than exceeded it.
        while len(self._entries) + reserve > self._max_children:
            # ONLY a ready, quiet child may be evicted (review R1F1):
            #
            # - a PENDING entry (another thread mid-spawn) has no backend
            #   yet. Evicting it detaches the entry the spawner is about
            #   to fill, and that child then belongs to nobody —
            #   `shutdown_all` cannot reach it, so the "cap" would leak
            #   processes rather than bound them.
            # - a BUSY child is answering someone right now. `used` is
            #   last-ACQUIRED time, not in-flight work, so the idlest by
            #   that measure can still have a request on the wire;
            #   shutting it down would fail an ordinary concurrent request
            #   to make room for a new one.
            #
            # If nothing qualifies, the cap is exceeded rather than
            # enforced. That is the right way to fail: the cap is a
            # soft resource policy for a pool with no reaper until
            # 3.5-C′, and every alternative here breaks a request that
            # was already in flight.
            evictable = [
                (key, entry)
                for key, entry in self._entries.items()
                if self._reapable_locked(entry)
            ]
            if not evictable:
                log(
                    "modern pool at cap but every child is pending or busy; "
                    "exceeding the cap rather than disturbing live work"
                )
                return
            key, entry = min(evictable, key=lambda kv: kv[1].get("used", 0.0))
            self._entries.pop(key, None)
            log(f"modern pool at cap; evicting the idlest child for {key!r}")
            threading.Thread(target=entry["backend"].shutdown, daemon=True).start()

    def get_or_create(
        self, principal: Any
    ) -> tuple[BackendProcess, dict[str, Any], dict[str, Any]]:
        """The child for ``principal``, its InitializeResult, and its entry.

        THE RETURNED CHILD IS CHECKED OUT: the entry's `holds` refcount is
        incremented before this returns, and the caller MUST hand it back
        with `release(entry)` — a try/finally, since a leaked hold makes
        that child permanently unevictable and unreapable. The entry is
        returned for exactly that purpose (#376 §3.1).

        Raises ``RuntimeError`` when the child cannot be spawned or does
        not complete the handshake; the caller turns that into a JSON-RPC
        error rather than letting it reach the never-crash net.
        """
        while True:
            with self._lock:
                entry = self._entries.get(principal)
                if entry is None:
                    self._evict_if_at_cap_locked()
                    entry = {
                        "event": threading.Event(),
                        "backend": None,
                        "error": None,
                        # Checkout refcount (#376 §3.1). Non-zero means a
                        # handler is holding this child right now, which
                        # makes it untouchable by eviction and by the
                        # reaper — see `_reapable_locked`.
                        "holds": 0,
                    }
                    self._entries[principal] = entry
                    mine = True
                else:
                    mine = False
                    backend = entry.get("backend")
                    if backend is not None and not backend.closed:
                        entry["used"] = self._now()
                        entry["holds"] = entry.get("holds", 0) + 1
                        return backend, entry["init_result"], entry
                    if backend is not None:
                        # Child died. Reap it, then drop the entry and loop
                        # to respawn — the mirror of the legacy path's
                        # drop-then-reinit AND its stale.shutdown() reap.
                        # Every other cleanup path here already calls
                        # shutdown() on a leaving child (eviction, a failed
                        # spawn, shutdown_all); skipping it here leaked a
                        # zombie process on every pooled-child crash (#373
                        # review, /code-review score 100). Direct call, not
                        # the eviction daemon-thread: that pattern exists to
                        # keep a LIVE child's terminate/kill wait off the
                        # lock, but this child already exited, so
                        # shutdown()'s poll() sees it dead and returns at
                        # once.
                        self._entries.pop(principal, None)
                        backend.shutdown()
                        continue
            if not mine:
                # Another thread is spawning: wait for its outcome rather
                # than racing it to a second child.
                entry["event"].wait(_BACKEND_RESPONSE_TIMEOUT_SECS)
                if entry.get("backend") is not None and entry.get("error") is None:
                    with self._lock:
                        if self._entries.get(principal) is entry:
                            entry["used"] = self._now()
                            entry["holds"] = entry.get("holds", 0) + 1
                            return entry["backend"], entry["init_result"], entry
                    continue
                raise RuntimeError(entry.get("error") or "backend handshake failed")
            try:
                backend, init_result = self._spawn_and_handshake(principal)
            except Exception as exc:  # noqa: BLE001 — surfaced to the caller
                with self._lock:
                    if self._entries.get(principal) is entry:
                        self._entries.pop(principal, None)
                entry["error"] = str(exc)
                entry["event"].set()
                raise RuntimeError(str(exc)) from exc
            # PUBLICATION IS ATOMIC (#379 review R1F1). Backend, `used`
            # and the initial hold all land in ONE lock hold, because any
            # gap between them is a window where the entry looks READY,
            # quiet and unheld — exactly what `_reapable_locked` accepts.
            #
            # The sharp version: `backend` used to be assigned before
            # `used`, so a reaper landing in between read
            # `entry.get("used", 0.0)` and saw a child that was
            # apparently idle since the epoch. It would pop and shut down
            # a backend this call was about to return, and the caller's
            # first request then failed with a 504 against a corpse.
            # Taking the hold last does not help if the publication
            # itself is visible first.
            with self._lock:
                entry["backend"] = backend
                entry["init_result"] = init_result
                entry["used"] = self._now()
                entry["holds"] = entry.get("holds", 0) + 1
                # Re-bound the cap after the spawn race (#376 §3.2).
                # Racing first-requests each insert a PENDING placeholder
                # under the lock, and a placeholder is not evictable — so
                # once the ready-quiet victims run out, every racer logs
                # "exceeding the cap" and inserts anyway. Nothing
                # re-bounded that afterwards: the overshoot persisted
                # until the next NEW principal arrived, which in a
                # two-principal deployment is never.
                #
                # Re-checking here reclaims children that went quiet
                # while we were spawning. It is safe ONLY because the
                # hold above is already taken: the newborn this call is
                # about to return has `holds == 1`, so the sweep cannot
                # choose it — no "exclude my own key" special case
                # needed. That ordering is the reason this commit follows
                # the refcount one.
                #
                # If nothing qualifies the cap stays soft-exceeded, which
                # is the documented posture: every alternative kills work
                # already in flight. The reaper makes that exceedance
                # time-bounded rather than permanent.
                #
                # `reserve=0`: this entry is already IN the map, so the
                # sweep must trim down to the cap, not below it.
                #
                # Since `release()` grew its own sweep (#379 review), this
                # one is defense-in-depth rather than the sole backstop:
                # it only still matters for a sequence where some entry
                # became reapable with NO intervening release call to
                # have already caught it. We could not construct such a
                # sequence, but do not claim one is impossible — the cost
                # here is one locked check per spawn, not per request, so
                # it stays.
                self._evict_if_at_cap_locked(reserve=0)
            entry["event"].set()
            return backend, init_result, entry

    def reap_idle(self) -> int:
        """Drop children idle past the TTL — or already dead — and return the count.

        #376 §2.3. Two independent reasons to drop, and only one of them
        is about time:

        - `backend.closed`: reaped UNCONDITIONALLY, TTL or not, mirroring
          the legacy reaper. Without it a dead child belonging to a
          principal who never comes back pins a map slot and an unwaited
          zombie for the life of the process — the lazy cleanup in
          `get_or_create` only fires on that principal's NEXT request.
        - idle past the TTL, and `_reapable_locked` — so a child with a
          request on the wire, or one checked out but not yet sending, or
          a PENDING placeholder, is never taken. `used` is last-ACQUIRED
          time, which is why the refcount rather than the timestamp is
          what protects a long-lived hold (#374's seam).

        Selection and removal happen in ONE lock hold, so a concurrent
        re-acquire either lands first (refreshing `used`, so we skip it)
        or after the pop (finding nothing, and respawning cleanly).

        Shutdown then happens OUTSIDE the lock, and deliberately
        DIFFERENTLY from the legacy reaper's synchronous call: a live
        victim is torn down on a daemon thread, because `shutdown()`
        waits up to 5 s for a child to terminate and one wedged child
        would otherwise stall the whole sweep and delay the next tick. A
        child that is already `closed` is shut down directly — `poll()`
        sees it dead and returns at once, so a thread would be pure
        overhead.
        """
        ttl = self._idle_ttl
        now = self._now()
        dead: list[tuple[Any, BackendProcess]] = []
        idle: list[tuple[Any, BackendProcess]] = []
        # #390 review, finding 1: abandoned MRTR rounds are swept HERE,
        # on the sweep that already exists, rather than by a second timer
        # (#375 §3.8 named this or a lazy pool-touch check as equally
        # acceptable; this one already runs, already holds no locks it
        # must not, and cannot drift out of sync with child lifetime).
        #
        # It matters because a client is EXPLICITLY licensed not to come
        # back — "Servers MUST NOT assume that clients will fulfill the
        # inputRequests or retry the original request" — and an
        # unswept round leaves the legacy child blocked on a reply
        # nobody will send AND wedges that principal's pool slot for
        # good, since `mrtr_begin_dispatch` refuses while anything is
        # parked.
        #
        # Deliberately OUTSIDE the `ttl > 0` gate below: the park
        # deadline is the round's own, and a deployment that never
        # configured an idle TTL still must not strand children.
        self._sweep_abandoned_rounds()
        with self._lock:
            for key, entry in list(self._entries.items()):
                backend = entry.get("backend")
                if backend is None:
                    continue
                if backend.closed:
                    self._entries.pop(key, None)
                    dead.append((key, backend))
                    continue
                if (
                    ttl > 0
                    and now - entry.get("used", 0.0) > ttl
                    and self._reapable_locked(entry)
                ):
                    self._entries.pop(key, None)
                    idle.append((key, backend))
        for key, backend in dead:
            backend.shutdown()
            log(f"reaped dead modern child for {key!r}")
        for key, backend in idle:
            log(f"reaped idle modern child for {key!r}")
            threading.Thread(target=backend.shutdown, daemon=True).start()
        return len(dead) + len(idle)

    def _sweep_abandoned_rounds(self) -> int:
        """Unblock children whose parked round no client ever came back for.

        `mrtr_expire_parked` drops the entries and hands them back; this
        is what discharges the obligation its docstring names — a
        JSON-RPC error to each child under its OWN request id, which is
        the only thing that can un-block a subprocess sitting on a stdin
        read.

        No client-facing action is owed: that HTTP request completed the
        moment the `InputRequiredResult` went out.
        """
        swept = 0
        with self._lock:
            backends = [
                entry["backend"]
                for entry in self._entries.values()
                if entry.get("backend") is not None
            ]
        for backend in backends:
            for expired in backend.mrtr_expire_parked():
                # The DEFAULT -32000, not -32603 (#390 Copilot review).
                # This file reserves -32603 for "the gateway broke"; a
                # client that simply did not come back is an EXPECTED
                # path — Server Requirements item 8 licenses it outright
                # ("Servers MUST NOT assume that clients will fulfill the
                # inputRequests or retry") — so calling it an internal
                # error would tell the child something untrue about who
                # failed.
                backend.send_oneway(
                    _error_body(
                        "the client did not return the requested input in time",
                        expired["child_request_id"],
                    )
                )
                swept += 1
        return swept

    def start_reaper(self) -> None:
        """Start the pool's background sweep thread.

        A thread of its own rather than a tick on the legacy session
        reaper: that one does not exist when `--session-idle-ttl` is 0,
        and coupling the pool into `SessionRegistry` to borrow it would
        buy nothing.

        TWO INDEPENDENT REASONS TO RUN, and conflating them was #390's
        R3F1. Idle eviction needs `--modern-idle-ttl`; sweeping abandoned
        MRTR rounds needs only the bridge to be enabled. Gating the whole
        thread on the TTL alone meant that in the DEFAULT deployment the
        thread never started, so `reap_idle` — where the sweep lives,
        correctly placed outside its own TTL check — was never called at
        all. That is finding 1 again, one layer up: code with no
        production caller.

        `reap_idle` already gates eviction internally, so a thread
        started only for the bridge evicts nothing: `--modern-idle-ttl 0`
        still means idle eviction is OFF, exactly as before.

        The bridge flag gates STARTUP ONLY — see the comment below.
        """
        # Read ONCE, here, so this decides whether the thread starts and
        # nothing more. A previous version of this comment claimed the
        # sweep "cannot outlive the thing it sweeps", which overstated
        # it: clearing `MCP_STDIO_MRTR_REVERSE_ENABLE` afterwards does
        # not stop a thread already running (#390 Copilot review).
        #
        # That is CORRECT rather than merely harmless, and worth saying
        # so nobody "fixes" it into a per-tick check. Rounds parked
        # BEFORE the flag was cleared still have children blocked on
        # them, and the sweep is the only thing that ever unblocks them.
        # A sweep that switched itself off would strand exactly those
        # children — turning a withdrawal into a leak.
        #
        # Nothing new accumulates either way: the dispatch path reads the
        # same flag live per request, so once it is off no further round
        # is ever opened. The running sweep just drains what is left and
        # then finds nothing, which is the behaviour an operator
        # withdrawing the feature actually wants.
        bridge_enabled = bool(_modern_child_capabilities())
        if (self._idle_ttl <= 0 and not bridge_enabled) or self._reaper is not None:
            return
        if self._idle_ttl > 0:
            interval = max(1.0, min(self._idle_ttl, _MAX_REAP_INTERVAL_SECS))
        else:
            # Bridge-only: pace off the park deadline, as a RATIO rather
            # than a literal (the rule #388's review established), so a
            # change to the deadline cannot silently leave the sweep too
            # coarse to notice an abandoned round in reasonable time.
            interval = max(
                1.0, min(_MRTR_PARK_TIMEOUT_SECS / 4, _MAX_REAP_INTERVAL_SECS)
            )
        # A FRESH stop event per thread (#379 Copilot review), not a
        # shared one cleared on restart: `stop_reaper` does not join —
        # the thread is a daemon parked in `wait(interval)` — so a
        # restart that CLEARED a shared event could un-stop a predecessor
        # that had not yet observed the set, leaving two reapers sweeping
        # the same pool. Each loop closes over the event it was born
        # with, so a stop is permanent for that thread whatever happens
        # afterwards.
        stop = threading.Event()
        self._reaper_stop = stop

        def _loop() -> None:
            while not stop.wait(interval):
                try:
                    self.reap_idle()
                except Exception as e:  # pragma: no cover - defensive
                    log(f"modern pool reaper error: {e}")

        self._reaper = threading.Thread(
            target=_loop, name="modern-pool-reaper", daemon=True
        )
        self._reaper.start()

    def stop_reaper(self) -> None:
        """Signal the reaper thread to exit; it is a daemon, so no join."""
        self._reaper_stop.set()
        self._reaper = None

    def _spawn_and_handshake(
        self, principal: Any
    ) -> tuple[BackendProcess, dict[str, Any]]:
        """Spawn a child and drive the handshake the modern wire omits."""
        extra_env = _extra_env_for_principal(self._user_env_var, principal)
        backend = BackendProcess(self._command, modern_owned=True, extra_env=extra_env)
        try:
            req_id = self._next_handshake_id()
            line = backend.send_request(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": _MODERN_CHILD_HANDSHAKE_VERSION,
                            "capabilities": _modern_child_capabilities(),
                            "clientInfo": {"name": "mcp-stdio serve", "version": "0"},
                        },
                    }
                ),
                req_id,
                _BACKEND_RESPONSE_TIMEOUT_SECS,
            )
            if line is None:
                raise RuntimeError("backend did not answer initialize")
            result = json.loads(line).get("result")
            if not isinstance(result, dict):
                raise RuntimeError("backend returned no InitializeResult")
            # MANDATORY, and easy to miss because the legacy path never
            # needed it: on this path serve IS the client, and FastMCP
            # children gate post-initialize requests on this notification.
            backend.send_oneway(
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
            )
            return backend, result
        except Exception:
            backend.shutdown()
            raise

    def shutdown_all(self) -> None:
        # Stop the reaper first, mirroring `SessionRegistry.shutdown_all`:
        # a sweep racing the teardown would shut children down twice.
        # `holds` is deliberately IGNORED here — gateway shutdown
        # overrides a checkout, and an in-flight caller gets the same
        # failure the legacy path already produces at shutdown.
        self.stop_reaper()
        # #374 §3.5: end every attached listen stream FIRST, so a stream
        # emits its graceful terminal result before its child dies under
        # it. The drain is what makes that promise real rather than
        # aspirational: handler threads are daemons, so without it the
        # process can exit between the signal and the flush and a
        # compliant peer sees a stream that just stopped — which it reads
        # as LOST and reconnects to a gateway that is going away.
        # BOUNDED, so a wedged stream delays shutdown by at most
        # `_LISTEN_DRAIN_SECS` instead of deadlocking it.
        with self._lock:
            entries = list(self._entries.values())
        for entry in entries:
            backend = entry.get("backend")
            if backend is not None:
                backend.close_listeners()
        for entry in entries:
            backend = entry.get("backend")
            if backend is not None:
                backend.drain_listeners(_LISTEN_DRAIN_SECS)
        with self._lock:
            entries = list(self._entries.values())
            self._entries.clear()
        for entry in entries:
            backend = entry.get("backend")
            if backend is not None:
                backend.shutdown()

    def count(self) -> int:
        with self._lock:
            return len(self._entries)


# --- modern dispatch: id remap and the result-rewrite seam ---

_MODERN_ID_LOCK = threading.Lock()
_MODERN_ID_SEQ = 0


def _mint_modern_id() -> str:
    """A globally unique upstream id for one modern request.

    PROCESS-global and monotonic, not per-child: two concurrent modern
    clients may share one pooled child, and their own ids are whatever
    they chose — very possibly the same integer. Minting our own removes
    the collision by construction, which is also why
    `_DuplicateInFlightId` and the same-payload piggyback are unreachable
    on this path. Both stay for the legacy one, where the client's id IS
    the routing key.

    Namespaced like relay's `_RELAY_ID_NAMESPACE`, so a child that echoes
    ids into logs shows where they came from.
    """
    global _MODERN_ID_SEQ
    with _MODERN_ID_LOCK:
        _MODERN_ID_SEQ += 1
        return f"{_SERVE_ID_NAMESPACE}{_MODERN_ID_SEQ}"


def _is_reserved_client_id(req_id: Any) -> bool:
    """True when a client's own id trespasses on serve's namespace.

    Closes by construction the gap relay's PR C had to close by rule: a
    client whose id is literally `mcp-stdio/serve/7` would be
    indistinguishable from serve's own bookkeeping the moment a response
    came back, so the id is rejected where it ENTERS rather than
    disambiguated at every later consumer.
    """
    return isinstance(req_id, str) and req_id.startswith(_SERVE_ID_NAMESPACE)


# --- reverse MRTR: the signed pointer (#375 PR 1, design §3.2) -----------
#
# WHAT THIS IS NOT. The issue's original framing was that serve is
# stateless, so a round's state must live entirely inside `requestState`.
# That framing is wrong, and following it literally would misdirect the
# whole implementation: what a client's retry resumes is not a
# serializable computation but a LIVE SUBPROCESS blocked on its own stdin
# read. No amount of state in `requestState` lets a different process — or
# the same process after a restart — un-block that particular child. The
# retry MUST land back on the instance holding it. That is an affinity
# requirement inherent to the child being a real OS process, not a design
# choice this code can dissolve.
#
# So `requestState` is a signed POINTER, never a container: just enough to
# find an entry in `BackendProcess._mrtr_pending` and prove the finder is
# entitled to it. The round's real state lives in that table, which dies
# with the child for free — the same lifetime discipline `_resource_refs`
# uses (#381/#388).
#
# O5/statelessness licenses this: it forbids relying on prior CLIENT
# requests to reconstruct context (capabilities, protocol version,
# identity), and an MRTR retry carries its own full `_meta` and its own
# auth, so every piece of context is still derived fresh. Nothing in the
# spec forbids a server from keeping its own bookkeeping.
#
# O14 is what forces the signature: "servers MUST treat `requestState` as
# an attacker-controlled input ... MUST protect its integrity (e.g. HMAC
# or AEAD) and MUST reject state that fails verification". `(e.g. ...)` is
# illustrative — the spec mandates no algorithm, library or format, and
# its own worked example uses the placeholder string "AEAD-protected
# blob" — so stdlib HMAC-SHA256 satisfies it with no new dependency.
_MRTR_POINTER_VERSION = 1

# Process-lifetime only, never persisted, and that is CORRECT rather than
# a shortcut. A restart loses every in-flight round — but the alternative
# is worse: a persisted key would let a client present a perfectly-signed
# pointer to a txn that provably cannot exist any more, turning an honest
# "unknown or expired requestState" into a silent misroute. Server
# Requirements item 8 licenses the loss outright: "Servers MUST NOT assume
# that clients will fulfill the inputRequests or retry the original
# request."
_MRTR_POINTER_KEY = secrets.token_bytes(32)

# Mirrors relay's own `_MRTR_MAX_ROUNDS`; nothing in the spec constrains
# the value. It rides INSIDE the signed payload because serve keeps no
# per-client counter across requests — signing it is what stops a client
# resetting its own round count by hand-crafting `round: 1`.
_MRTR_MAX_ROUNDS = 32

# How long a signed pointer stays acceptable. Bounds how long a captured
# blob is worth replaying, independently of single-use consumption.
_MRTR_POINTER_TTL_SECS = 300.0


def _mrtr_principal_hash(principal: str | None) -> str:
    """A stable, HMAC-keyed tag for the owning principal.

    The raw value is an OAuth username; it goes nowhere near a blob the
    client holds and could inspect. A tag binds the pointer to its owner
    just as well, since the only operation ever performed on it is
    equality against a freshly-resolved principal.

    KEYED with `_MRTR_POINTER_KEY` (#389 review, score 85), not a bare
    `sha256` of the principal. The payload segment of `requestState` is
    only integrity-protected — HMAC over the whole blob, never
    encrypted — and the spec's confidentiality obligation runs the other
    way ("clients MUST NOT inspect ... its contents"), so nothing stops
    a proxy log, a client-side debug dump, or a support screenshot from
    exposing this tag to someone who was never meant to read it. OAuth
    principals are low-entropy and structurally guessable (usernames,
    emails), so an UNKEYED hash would let anyone holding a leaked blob
    run an offline dictionary attack — hash every guessed principal,
    compare — and learn exactly who opened the round. Confidentiality
    against that attack comes from the key, not from SHA-256 being
    "non-reversible": a fast, unsalted, unkeyed hash of a small
    guessable space is not a secret no matter which hash function it
    is. Reuses `_MRTR_POINTER_KEY` rather than minting a second secret —
    the same key already protects the pointer's outer MAC, and both
    encode (`_mrtr_encode_pointer`) and decode (`_mrtr_decode_pointer`)
    call this one function, so equality-check semantics are unaffected.
    """
    return hmac.new(
        _MRTR_POINTER_KEY,
        f"mcp-stdio/mrtr/{principal!r}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _mrtr_pointer_payload_bytes(payload: dict[str, Any]) -> bytes:
    """The exact bytes that get signed, and later re-signed to verify.

    Canonical: sorted keys, no incidental whitespace. The verifier never
    re-serializes a parsed payload to check the MAC — it MACs the bytes it
    received — so canonicality is about the ISSUER producing a stable
    encoding, not about the verifier trusting a round-trip.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _mrtr_encode_pointer(
    txn_id: str, principal: str | None, round_no: int, *, now: float | None = None
) -> str:
    """Mint one `requestState` value.

    Spec: "An opaque string meaningful only to the server. Clients MUST
    NOT inspect, parse, modify, or make any assumptions about its
    contents." Opaque is exactly what this is — the client's only
    obligation is to echo it back byte-for-byte.
    """
    issued = time.time() if now is None else now
    payload = {
        "v": _MRTR_POINTER_VERSION,
        "txn_id": txn_id,
        "principal": _mrtr_principal_hash(principal),
        "round": round_no,
        "issued_at": issued,
        "expires_at": issued + _MRTR_POINTER_TTL_SECS,
    }
    raw = _mrtr_pointer_payload_bytes(payload)
    mac = hmac.new(_MRTR_POINTER_KEY, raw, hashlib.sha256).digest()
    return f"{_b64url(raw)}.{_b64url(mac)}"


def _mrtr_decode_pointer(
    state: Any, principal: str | None, *, now: float | None = None
) -> tuple[dict[str, Any] | None, str]:
    """Verify and unpack a `requestState`; `(payload, "")` or `(None, why)`.

    ORDER IS THE SECURITY PROPERTY. The MAC is checked against the exact
    bytes received, with `hmac.compare_digest`, BEFORE the payload is
    parsed as JSON — never parse-then-trust. A caller that read fields out
    first and verified afterwards would already have acted on
    attacker-chosen data.

    Integrity is only ONE THIRD of the closure, and saying "HMAC prevents
    this" alone would be an incomplete claim:

    - HMAC stops FORGERY — a client cannot invent a pointer.
    - SINGLE-USE consumption (the caller pops the txn entry) stops REPLAY
      — a captured, still-validly-signed blob is worthless once used.
    - PRINCIPAL BINDING, checked here, stops CROSS-USER use of a genuine
      pointer that leaked.

    Never raises. Every malformed shape returns a reason string, because
    this parses attacker-controlled input on a request-handling path.
    """
    if not isinstance(state, str) or state.count(".") != 1:
        return None, "malformed requestState"
    raw_b64, mac_b64 = state.split(".", 1)
    try:
        raw = _b64url_decode(raw_b64)
        mac = _b64url_decode(mac_b64)
    except (ValueError, binascii.Error):
        return None, "malformed requestState encoding"
    expected = hmac.new(_MRTR_POINTER_KEY, raw, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        return None, "requestState failed integrity verification"
    # Only now is the payload trustworthy enough to parse.
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, "malformed requestState payload"
    if not isinstance(payload, dict) or payload.get("v") != _MRTR_POINTER_VERSION:
        return None, "unsupported requestState version"
    if payload.get("principal") != _mrtr_principal_hash(principal):
        # Defense in depth beyond the pool's own per-principal keying:
        # O14 says to treat this value as attacker-controlled, and a
        # genuine pointer that leaked between users is exactly the case
        # pool keying alone does not cover.
        return None, "requestState belongs to a different principal"
    expires = payload.get("expires_at")
    if not isinstance(expires, (int, float)) or (
        (time.time() if now is None else now) > expires
    ):
        return None, "requestState expired"
    round_no = payload.get("round")
    if not isinstance(round_no, int) or isinstance(round_no, bool) or round_no < 1:
        return None, "malformed requestState round"
    if round_no > _MRTR_MAX_ROUNDS:
        # Enforced HERE, at the trust boundary, as well as wherever the
        # next round is opened (#389 review). The retry handler is the
        # natural place to refuse to go further, but this decoder is what
        # decides a pointer is valid at all — so a mint-side regression
        # cannot hand out a pointer that outlives the cap. A round beyond
        # it is not a pointer worth honouring, whoever produced it.
        return None, "requestState exceeded the maximum round count"
    if not isinstance(payload.get("txn_id"), str):
        return None, "malformed requestState txn"
    return payload, ""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


# The only methods a reverse-MRTR round may ever open under. O14 scopes
# MRTR to requests that can legitimately need more input mid-flight, and
# this mirrors relay's equivalent restriction on the forward side.
_MRTR_ELIGIBLE_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})

# The three legacy out-of-band requests a child may raise mid-call, and
# the client capability each one needs. Identical to relay's own table
# (`_MRTR_REQUEST_CAPABILITY`) because the method names are the SAME on
# both sides — what MRTR rev 2026-07-28 changed is who sends them and how
# the answer travels back, not what they are called.
_MRTR_REVERSE_ENV = "MCP_STDIO_MRTR_REVERSE_ENABLE"


def _modern_child_capabilities() -> dict[str, Any]:
    """What serve advertises to a pooled child during the handshake.

    **THIS IS D4'S VALVE, and removing it is what activates the reverse
    bridge.** Everything else in #375 is inert while this returns `{}`:
    a well-behaved child does not raise `elicitation/create`,
    `sampling/createMessage` or `roots/list` at a peer that never claimed
    to support them, so the translation, the minting and the retry
    correlation all sit behind a door nobody knocks on.

    OFF BY DEFAULT, behind `MCP_STDIO_MRTR_REVERSE_ENABLE` (§4 Q3,
    mirroring relay's own `MCP_STDIO_MRTR_STRIP` caution). This is a
    genuine, observable handshake change on EVERY pooled child, so an
    operator must be able to withdraw it without a code rollback.

    `elicitation: {}` is the form-mode-equivalent posture — an empty
    declaration "is equivalent to declaring support for form mode only"
    — and `roots.listChanged: false` says roots can be listed but never
    announces changes, which is true: nothing here watches for them.

    SEP-2577 deprecates Roots and Sampling, and bridging them anyway is
    inside its own carve-out: "New implementations SHOULD NOT add support
    for deprecated features unless needed for backward compatibility with
    existing counterparts" — pre-existing legacy children reached by a
    modern client is exactly that case.

    NOTE the advertisement is per-GATEWAY while the bridge is per-request
    OAuth-only (§4 Q1). A no-auth deployment that enables the flag tells
    its child the capabilities exist and then answers `-32601` to any
    request raised under them. That is deliberate — a clean refusal the
    child already handles, and the same answer it gets today — but it is
    why the flag exists rather than the capabilities simply being on.
    """
    if os.environ.get(_MRTR_REVERSE_ENV, "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return {}
    return {
        "sampling": {},
        "elicitation": {},
        "roots": {"listChanged": False},
    }


_MRTR_REQUEST_CAPABILITY = {
    "elicitation/create": "elicitation",
    "sampling/createMessage": "sampling",
    "roots/list": "roots",
}


def _mrtr_request_to_input_entry(msg: dict[str, Any]) -> tuple[str | None, Any]:
    """Child JSON-RPC request -> one `inputRequests` entry.

    THE REVERSE of relay's `_mrtr_translate`, and the asymmetry is worth
    naming: relay receives a bare `{method, params}` and has to MINT a
    JSON-RPC envelope around it for a legacy client. Serve receives a
    full envelope from the legacy child and has to STRIP it back down,
    because "values are request objects that MUST be one of
    ElicitRequest, CreateMessageRequest, or ListRootsRequest" — bare
    objects, not JSON-RPC messages.

    Returns `(capability, entry)` or `(None, reason)`.

    Params pass through VERBATIM. NO reject arms for `mode: "url"`
    elicitation or tool-augmented sampling, and that is narrower on
    purpose rather than an oversight: relay needs them because a modern
    SERVER can express both while a legacy client cannot consume them.
    Here the CHILD is the legacy (2025-06-18) side and structurally
    cannot emit either — both are 2025-11-25+ additions. Confirmed
    against the actual fixture set as well as by construction (#375 §4
    Q6): the fixtures raise a bare `elicitation/create` (the unit fake
    child's `ask_client`) and a bare `sampling/createMessage` (the
    integration child's `ask` tool) — neither carries `mode` or `tools`,
    and neither could. Adding arms for shapes a legacy child cannot
    produce would be dead code pretending to be symmetry.
    """
    method = msg.get("method")
    # `isinstance(method, str)` BEFORE the dict lookup, and the type
    # check is load-bearing rather than tidiness (#390 Copilot review):
    # a truthy-but-unhashable `method` — `{"method": {"a": 1}}` from a
    # misbehaving or hostile child — made `.get(method)` raise
    # `TypeError: unhashable type`. This runs on the child's READER
    # thread, whose `try/except` sits OUTSIDE its `while` loop, so the
    # raise did not merely drop one message: it ended the loop, hit
    # `finally: _fail_all("backend process exited")`, and failed every
    # in-flight request on that child. One malformed field killed all
    # traffic to a live subprocess — a DoS with a two-character payload.
    #
    # A non-string method simply is not bridgeable, so it takes the
    # ordinary `capability is None` path and falls through to D4's
    # `-32601`, which is where every other unbridgeable shape already
    # goes.
    capability = (
        _MRTR_REQUEST_CAPABILITY.get(method) if isinstance(method, str) else None
    )
    if capability is None:
        return None, "the child requested an input kind this gateway cannot bridge"
    entry: dict[str, Any] = {"method": method}
    params = msg.get("params")
    if method == "roots/list":
        # ListRootsRequest carries no params at all.
        return capability, entry
    if params is not None:
        if not isinstance(params, dict):
            return None, "the child sent an input request with malformed params"
        entry["params"] = params
    return capability, entry


def _mrtr_input_response_to_reply(
    response: Any, child_request_id: Any
) -> tuple[str | None, str]:
    """One `inputResponses` entry -> the JSON-RPC reply the child awaits.

    The other half of the inversion. An `InputResponse` is the RESULT the
    client produced, not a JSON-RPC envelope, so the reply the child is
    blocked on has to be minted around it under the child's OWN request
    id — which lives in the parked-round table, never in `requestState`
    (#375 §1.1).

    A client MAY answer with an error instead of a result; that is a
    legitimate outcome (a user declining an elicitation, say), so it is
    forwarded as a JSON-RPC error rather than treated as a bridge
    failure. Anything else is malformed and reported to the caller.
    """
    if not isinstance(response, dict):
        return None, "the client sent a malformed input response"
    if "error" in response:
        # The `error` key DECIDES the shape — no fall-through (#390
        # Copilot review). A malformed value used to skip this branch and
        # land in the bare-result path below, where `.get("result",
        # response)` fell back to the whole object: `{"error": "x"}` came
        # out as a SUCCESS carrying `result: {"error": "x"}`, so a child
        # that asked a question was told its request succeeded and handed
        # the error as the answer. The docstring already promised
        # "anything else is malformed and reported to the caller"; this
        # is what makes that true.
        error = response["error"]
        # The CONTENTS, not just the type (#390 /code-review). Every
        # other error this file puts on a wire goes through
        # `_error_body`, which guarantees `code` and `message`; this one
        # is client-supplied and was forwarded to the child's stdin
        # unexamined. `{"error": {}}` or `{"error": {"code": "oops"}}`
        # is not a JSON-RPC error object, and a legacy child using a
        # strict parser can die on it — taking every in-flight request
        # on that backend with it via `_fail_all`, the same blast radius
        # as the other never-hang bugs in this PR.
        #
        # `bool` is excluded explicitly: it subclasses `int`, so
        # `{"code": true}` would otherwise pass a bare `isinstance`
        # check and reach the child as a code no peer can interpret.
        if (
            not isinstance(error, dict)
            or not isinstance(error.get("code"), int)
            or isinstance(error.get("code"), bool)
            or not isinstance(error.get("message"), str)
        ):
            return None, "the client sent a malformed input response error"
        return (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": child_request_id,
                    "error": error,
                }
            ),
            "",
        )
    # No `error` key: the whole object may itself BE the result, which is
    # the shape a client sending an `InputResponse` directly produces.
    result = response.get("result", response)
    if not isinstance(result, dict):
        return None, "the client sent an input response with no result object"
    return (
        json.dumps({"jsonrpc": "2.0", "id": child_request_id, "result": result}),
        "",
    )


def _is_genuine_per_caller_principal(principal: str | None) -> bool:
    """Whether ``principal`` actually distinguishes one caller from another.

    `None` is the open gateway and `_STATIC_PRINCIPAL` the shared
    static-token constant; `_authorized` derives both. Neither identifies a
    specific caller, so any feature that treats a principal as a per-user
    credential (reverse-MRTR binding, `--user-env` injection, ...) must
    exclude both -- shared here so each such feature stays correct if the
    other's owner changes it for unrelated reasons, rather than one feature
    silently reusing a helper scoped in its docstring to a different one.
    """
    return principal is not None and principal != _STATIC_PRINCIPAL


def _mrtr_principal_is_eligible(principal: str | None) -> bool:
    """Whether this caller may open a reverse-MRTR round at all (§4 Q1).

    **OAUTH ONLY, and this is a scope boundary rather than a TODO.**

    Principal binding is what stops one caller answering another's
    prompt, and it buys exactly nothing when the principal is a shared
    constant. Under no-auth the pool hands ONE child to every caller
    (decision D1), and a static token does the same — so a prompt raised
    by caller A's `tools/call` could be answered by whoever's retry
    happens to land next. That is a cross-caller leak, not merely a
    degraded experience.

    Both of those postures therefore keep today's behaviour exactly: a
    clean `-32601`, no bridging, nothing to leak. Only a genuine OAuth
    user — a principal that actually distinguishes callers — is eligible.
    """
    return _is_genuine_per_caller_principal(principal)


def _user_env_value(principal: Any) -> str | None:
    """The value to inject via ``--user-env`` for this principal, or `None`
    to leave the child's environment unmodified (--user-env not requested,
    open gateway, or the shared static-token principal).

    Uses the same "does this actually distinguish callers" test every
    per-user-credential feature needs (:func:`_is_genuine_per_caller_principal`):
    an open-gateway or static-token "principal" does not distinguish callers,
    so injecting it would either inject nothing meaningful or falsely claim
    a shared credential belongs to one specific user. `_STATIC_PRINCIPAL`
    itself contains a NUL byte, but the eligibility check above already
    excludes it before the NUL check would matter — the NUL check here is
    defense in depth against any OTHER principal value that happens to
    embed one: `Popen(env=...)` raises `ValueError` on an embedded NUL,
    which would otherwise fail every request for that caller.
    """
    if not _is_genuine_per_caller_principal(principal):
        return None
    if not isinstance(principal, str) or "\x00" in principal:
        return None
    return principal


# --user-env variable names CLI validation refuses outright: each is a
# dynamic-linker / interpreter search-path variable that a spawned child
# reads to locate its OWN code before it ever gets to application logic.
# Injecting an authenticated principal string under one of these names
# would silently replace it (a plain identity string is never a valid
# PATH/library-search value), breaking child spawn outright the moment the
# backend command isn't an absolute path, or -- for the *_PRELOAD/*_LIBRARIES
# variables specifically -- doing something far worse if it ever DID parse.
# Operator error, not an attack surface (the value comes from --user-env's
# CLI argument, not request data), but cheap and worth refusing at parse
# time rather than as a runtime footgun (#400 review).
_DANGEROUS_USER_ENV_NAMES = frozenset(
    {
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "NODE_OPTIONS",
    }
)


def _extra_env_for_principal(
    user_env_var: str | None, principal: Any
) -> dict[str, str] | None:
    """The ``extra_env`` a spawned child should get for this principal, or
    `None` for an unmodified environment.

    Shared by :meth:`ModernBackendPool._spawn_and_handshake` and
    :meth:`SessionRegistry.create` -- the two call sites that spawn a child
    for a specific principal/owner -- so the injection rule (variable name,
    eligibility, future changes such as an additional exemption or
    sanitization step) cannot drift between the legacy and modern paths.
    """
    if not user_env_var:
        return None
    value = _user_env_value(principal)
    if value is None:
        return None
    return {user_env_var: value}


def _stamp_modern_result(
    msg: dict[str, Any],
    method: str | None,
    *,
    server_info: Any = None,
    cache_ttl_ms: int = _DEFAULT_CACHE_TTL_MS,
) -> dict[str, Any]:
    """Add the fields a 2026-07-28 server owes, to a legacy child's result.

    #270 Phase 3 P3-B, the rewrite seam. A legacy child emits none of
    these, and serve — answering as a modern server — gets no waiver:
    "The `result` MUST include a `resultType` field", and the
    absent-means-complete leniency is explicitly a CLIENT obligation for
    EARLIER-protocol servers, which serve is not claiming to be.

    Everything is stamped IFF ABSENT, never overwritten: a child that
    already speaks the modern dialect keeps its own values, and the seam
    stays a widening rather than a rewrite.

    - `resultType: "complete"` on EVERY modern success result. Broader
      than the six cacheable ops, because O3's MUST is about every
      result — and the v2 client enforces it on the cacheable ones.
    - `ttlMs`/`cacheScope` on the SIX cacheable operations only, as
      top-level result keys (siblings of `resultType`, not `_meta`).
      NEVER on `tools/call`: `CallToolResult` is not a CacheableResult
      and the v2 client's model has no such fields at all, so stamping
      them would be inventing wire data.
    - `_meta["io.modelcontextprotocol/serverInfo"]` on every result —
      "Servers SHOULD include the following ... field in every result's
      `_meta`" — echoed verbatim from the cached child InitializeResult.
      Identity fields are "self-reported by the sender and ... not
      verified", so echoing the child's is legal and honest; inventing
      one would not be.

    ERRORS ARE NEVER STAMPED, and that is structural rather than
    policy: `resultType` is a field OF `result`, and a JSON-RPC error
    response has no `result` member to put it in.
    """
    result = msg.get("result")
    if not isinstance(result, dict):
        return msg
    result.setdefault("resultType", "complete")
    if method in _CACHEABLE_METHODS:
        result.setdefault("ttlMs", cache_ttl_ms)
        result.setdefault("cacheScope", _CACHE_SCOPE)
    if server_info is not None:
        meta = result.get("_meta")
        if not isinstance(meta, dict):
            meta = {}
            result["_meta"] = meta
        meta.setdefault(_META_SERVER_INFO, server_info)
    return msg


def _modern_response_status(msg: dict[str, Any]) -> int:
    """The HTTP status a modern JSON-RPC response rides on.

    200 for a result. For an error, the spec maps one code to its own
    status and the v2 client's own table agrees: "If the server does not
    implement the requested RPC method, it MUST respond with `404 Not
    Found` and ... `-32601`". Everything else keeps 200 and lets the
    JSON-RPC error speak — the client parses an error body at any status.

    This used to double as the carve-out `subscriptions/listen` needed
    while serve did not implement it (a legacy child answers it `-32601`,
    which had to reach the client as 404 rather than as a 200 the client
    would read as a malformed success). #374 removed that path by
    intercepting the method in `_dispatch_modern` before it can reach a
    child, so what remains here is only the general unknown-method rule
    it always was.
    """
    error = msg.get("error")
    if isinstance(error, dict) and error.get("code") == _JSONRPC_METHOD_NOT_FOUND:
        return 404
    return 200


# The capability flags discover still cannot honor. The rule (#373
# review, /code-review score 85) is the relay's C8 principle (relay.py:
# "advertise exactly what is forwarded") applied in reverse: advertise a
# family's notification flag only for a kind serve can actually deliver.
#
# #374 made three of the original four deliverable. `subscriptions/listen`
# now attaches a live stream to the pooled child and
# `_queue_server_initiated` fans the listChanged trio out to it, so
# `tools.listChanged`, `resources.listChanged` and `prompts.listChanged`
# are honest promises and were removed from this table.
#
# #381 made the fourth deliverable too, but CONDITIONALLY — which is why
# `resources.subscribe` is still listed here rather than deleted. Serve
# can honor `resourceSubscriptions` only when the child itself advertises
# `resources.subscribe`, because that is what the subscription is driven
# against. So this table stays the DEFAULT answer ("cannot honor, strip
# it") and `_synthesize_discover_result` lifts it for the one case where
# serve can, reading `_child_supports_resource_subscribe` — the same
# single predicate the listen ack's gate reads. One predicate, two call
# sites, so what discover advertises and what the ack honors cannot
# drift apart.
#
# Keyed by family -> the KEYS to strip, never the whole family object:
# spec capability semantics are presence-based, and the REQUEST surface
# of the family (`resources/read`, `resources/list`) is served today —
# only that one promise is undeliverable. `logging` is deliberately NOT
# in this table: `notifications/message` is request-scoped, so it belongs
# to whatever carries the request, not to a broadcast stream (#381).
_UNDELIVERABLE_NOTIFICATION_FLAGS: dict[str, tuple[str, ...]] = {
    "resources": ("subscribe",),
}


def _strip_undeliverable_capability_flags(
    capabilities: Any, keep: frozenset[tuple[str, str]] = frozenset()
) -> dict[str, Any]:
    """Drop the capability flags discover still cannot honor (see above).

    A non-dict `capabilities` value degrades to `{}` rather than raising
    (#373 review R3F1): `.items()` on it would otherwise crash with an
    uncaught `AttributeError` that aborts the whole HTTP request — a
    misbehaving child's protocol violation must never crash the gateway's
    request handler. Before this function existed the raw echo degraded
    the same way on the CLIENT side instead (a `DiscoverResult`
    `ValidationError` falling silently back to `initialize`, spec-tolerable
    per `_synthesize_discover_result`'s own docstring); this must degrade
    at least that gracefully. A malformed child forfeits capability
    advertisement, never the request — `capabilities` stays the REQUIRED
    object either way, so the v2 client still proceeds modern and the
    request surfaces (tools/list, resources/read, prompts/get) keep
    working regardless of what this returns.

    Non-dict FAMILY values (inside an otherwise well-formed top-level
    dict) likewise pass through un-stripped rather than crash — e.g.
    `"tools": true` — since only a dict family has keys to strip from.
    A family absent from the table passes through whole, which is what
    makes the post-#374 one-entry table work unchanged.

    `keep` names flags the caller has established serve CAN honor for
    this particular child, lifting them out of the static table for this
    call only (#381 §3.6). The table stays the default because it
    describes serve's own capability; `keep` describes the child's, and
    only the two together decide whether a promise is honest.
    """
    if not isinstance(capabilities, dict):
        return {}
    stripped: dict[str, Any] = {}
    for family, value in capabilities.items():
        flags = _UNDELIVERABLE_NOTIFICATION_FLAGS.get(family)
        if flags and keep:
            flags = tuple(f for f in flags if (family, f) not in keep)
        if flags and isinstance(value, dict):
            value = {k: v for k, v in value.items() if k not in flags}
        stripped[family] = value
    return stripped


def _synthesize_discover_result(
    init_result: dict[str, Any], *, cache_ttl_ms: int = _DEFAULT_CACHE_TTL_MS
) -> dict[str, Any]:
    """Build the DiscoverResult serve answers `server/discover` with.

    Never forwarded to the child — a legacy child has never heard of
    `server/discover` and would answer `-32601`. Serve owns the answer,
    sourced from the handshake it performed on the client's behalf.

    `supportedVersions` is SERVE's own implemented set, never the
    child's: the child speaks 2025-06-18 and the question being asked is
    what the ENDPOINT supports. `capabilities` is the child's, echoed
    almost verbatim — `_strip_undeliverable_capability_flags` removes
    `resources.subscribe` first, the one flag serve still cannot honor
    (see that function's comment). The three listChanged flags used to
    be stripped alongside it and are advertised again since #374, which
    is what makes them true: `subscriptions/listen` delivers exactly
    that trio. Every other flag, and the family objects themselves, pass
    through untouched.

    BOTH FIELDS ARE LOAD-BEARING FOR INTEROP, not decoration. The v2
    client validates this result as a `DiscoverResult` whose required
    fields are exactly `supportedVersions` and `capabilities`; a
    ValidationError makes it SILENTLY FALL BACK to `initialize` — verified
    against the real client, which on a capabilities-less result emitted
    `initialize` + `notifications/initialized` and left
    `discover_result` None. Discovery would "succeed" while the modern
    path quietly never engaged, which is why the AC1 test asserts
    `discover_result is not None` rather than that the calls worked.
    """
    result: dict[str, Any] = {
        "resultType": "complete",
        "supportedVersions": sorted(_SERVE_IMPLEMENTED_MODERN_VERSIONS),
        # `.get(...) or {}` deliberately: a child that answers with no
        # capabilities key, or a null one, still yields the OBJECT the
        # client's validation requires.
        "capabilities": _strip_undeliverable_capability_flags(
            init_result.get("capabilities") or {},
            # #381 §3.6. Advertised only when the CHILD advertises it,
            # because that is what serve drives the subscription against
            # — the same predicate the listen ack's gate uses, so the
            # advertisement and the honoring can never disagree.
            keep=(
                frozenset({("resources", "subscribe")})
                if _child_supports_resource_subscribe(init_result)
                else frozenset()
            ),
        ),
        "ttlMs": cache_ttl_ms,
        "cacheScope": _CACHE_SCOPE,
    }
    server_info = init_result.get("serverInfo")
    if server_info is not None:
        result["_meta"] = {_META_SERVER_INFO: server_info}
    instructions = init_result.get("instructions")
    if isinstance(instructions, str):
        result["instructions"] = instructions
    return result


class _DuplicateInFlightId(Exception):
    """A request reused a JSON-RPC id already in flight on the same session
    with a payload that DIFFERS from the one already outstanding.

    MCP 2025-06-18 (Base Protocol > Messages > Requests) requires that "The
    request ID MUST NOT have been previously used by the requestor within the
    same session." Two requests sharing an id *in flight at once* cannot be
    correlated — the backend's two replies both carry that id — so serve rejects
    the second instead of overwriting the pending slot (which would cross-wire
    the first reply to the second waiter).

    A same-id request with the SAME payload is treated differently: it is a
    client-side retry (e.g. the reconnect burst racing its own re-init), not a
    protocol violation, and is piggybacked onto the in-flight request's slot
    instead of raising this (see :meth:`BackendProcess.send_request`).

    Carries both requests' ``method`` names so the HTTP handler can log which
    two calls collided — the one datum that distinguishes "one client re-fired
    a request" from "two gateway-side nodes share an id counter" when a 409 is
    investigated after the fact.
    """

    def __init__(
        self,
        req_id: Any,
        in_flight_method: str | None = None,
        rejected_method: str | None = None,
    ) -> None:
        super().__init__(req_id)
        self.in_flight_method = in_flight_method
        self.rejected_method = rejected_method


class BackendProcess:
    """Manage one stdio MCP child process and route its output by JSON-RPC id.

    A single daemon reader thread consumes the child's stdout line by line.
    Each line is parsed once: a JSON-RPC *response* resolves the per-id slot a
    waiting HTTP handler is blocked on; a server-initiated *request* or
    *notification* (anything carrying ``method``) is pushed onto
    ``server_initiated`` for the GET SSE stream to deliver.
    """

    def __init__(
        self,
        command: list[str],
        *,
        modern_owned: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> None:
        if not command:
            raise ValueError("backend command is empty")
        self._command = command
        # #270 Phase 3 P3-B: True for a child the MODERN pool owns. Such a
        # child has no SSE stream and no client that could ever consume
        # `server_initiated`, so the reader's else-arm must reject or drop
        # instead of queueing forever. False keeps the legacy behavior
        # byte-identical (AC2).
        self._modern_owned = modern_owned
        self._discarded = 0
        # text mode + line buffering so the reader thread sees one JSON-RPC
        # message per iteration. errors="replace" keeps a stray non-UTF-8 byte
        # from killing the reader (matching relay's never-crash posture).
        # `env=None` (the `extra_env`-falsy default) is Popen's own "inherit
        # the current environment" behavior — byte-identical to before this
        # parameter existed, so every pre-existing call site is unaffected.
        self._proc = subprocess.Popen(  # noqa: S603 — operator-supplied argv
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # inherit: backend logs flow to the gateway's stderr
            text=True,
            bufsize=1,
            errors="replace",
            env={**os.environ, **extra_env} if extra_env else None,
        )
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        # id -> shared slot {"event": Event, "line": str|None,
        # "request_line": str, "waiters": int}; retired by its LAST waiter
        # (same-payload retries piggyback on one slot, see send_request).
        self._pending: dict[Any, dict[str, Any]] = {}
        # Server-initiated messages (requests/notifications) awaiting an SSE
        # consumer. Unbounded queue is acceptable for one client per session;
        # a later change can bound + shed.
        self.server_initiated: "queue.Queue[str]" = queue.Queue()
        # Attached `subscriptions/listen` streams (#374). A modern child is
        # SHARED, and the spec allows several concurrent streams over it,
        # so the single-consumer `server_initiated` queue above cannot
        # serve them — each listener gets its own bounded queue instead.
        # Empty is the steady state and restores the discard behaviour by
        # construction.
        self._listeners: list[Any] = []
        # #381: resource URI -> (how many attached listen streams honored
        # it, whether a drive attempt has actually reached the child).
        # Sited HERE rather than on the pool entry so it dies with the
        # child: `ModernBackendPool.get_or_create`'s died-child arm drops
        # the whole `BackendProcess`, and a respawn gets an empty map for
        # free. No explicit "clear subscriptions on death" step exists on
        # purpose — object lifetime already guarantees it, and a separate
        # step is one more thing a future edit can get out of sync.
        #
        # THE BOOL IS NOT REDUNDANT (#388 review R2F1). The count alone
        # answers "does a stream claim this URI"; it says nothing about
        # whether the child was ever actually asked. A batch that stops
        # partway (see `responsive` in `add_resource_subscriptions`)
        # still takes the reference for every named URI, including ones
        # it never got to drive — collapsing that into one int made
        # "referenced" indistinguishable from "the child was told", so a
        # later stream naming the same URI would see count > 0 and skip
        # driving FOREVER, even though nothing had ever reached the
        # child. See both methods' docstrings.
        #
        # ITS OWN LOCK, not `self._lock`. `send_request` takes `_lock`
        # internally, and this lock is deliberately HELD ACROSS that call
        # — the one place in this file where a lock spans I/O. That is
        # what keeps the refcount decision and the resulting
        # subscribe/unsubscribe in the same order on the wire: releasing
        # to do the I/O would let two streams racing on one URI invert
        # them and leave the child subscribed to nothing, or subscribed
        # forever. Acquisition order is `_sub_lock` -> `_lock`, never the
        # reverse.
        self._sub_lock = threading.Lock()
        self._resource_refs: dict[str, tuple[int, bool]] = {}
        # #375 PR 1: reverse-MRTR rounds parked on THIS child, keyed by
        # the `tools/call`'s own minted upstream id. Sited here for the
        # same reason `_resource_refs` is — the state dies with the child
        # for free, so a respawn starts clean and no separate
        # clear-on-death path exists to drift out of sync.
        #
        # This table, not `requestState`, is the single source of truth
        # for a round. The client-held blob is only a signed pointer into
        # it (see `_mrtr_encode_pointer`): duplicating the round state
        # into a wire-visible value would leak the child's own internal
        # request id to the client and enlarge what a captured blob can
        # carry, for no gain — the table has to exist regardless, because
        # correlation and eligibility need it.
        self._mrtr_lock = threading.Lock()
        self._mrtr_pending: dict[Any, dict[str, Any]] = {}
        # IN FLIGHT is not the same state as PARKED, and conflating them
        # was a real hole (#389 /code-review). A round only becomes
        # visible in `_mrtr_pending` once the child has actually asked
        # something; between "an eligible request was forwarded" and
        # that moment, the table says nothing. Two handler threads for
        # one principal could therefore both look, both see an empty
        # table, and both forward — leaving exactly the two-eligible-
        # calls-on-one-child state the invariant exists to forbid.
        #
        # So the claim is taken BEFORE the send and held until the
        # dispatch returns, under the same lock as the table.
        self._mrtr_inflight = False
        # #375 PR 2: what the reader thread needs to know about the ONE
        # eligible request currently in flight, so it can decide whether a
        # child-initiated request can be bridged back to it. A single slot
        # rather than a map because `mrtr_begin_dispatch` already
        # guarantees at most one — the invariant is what makes this shape
        # legal, and re-deriving it as a dict would quietly permit the
        # ambiguity PR 1 exists to forbid.
        #
        # Distinct from `_mrtr_pending`, deliberately: that table means
        # "a round is PARKED awaiting a client retry", which is a later
        # and different state. Conflating them was #389's top finding.
        self._mrtr_context: dict[str, Any] | None = None
        self._closed = threading.Event()
        self._reader = threading.Thread(
            target=self._read_loop, name="backend-reader", daemon=True
        )
        self._reader.start()

    @property
    def command(self) -> list[str]:
        return list(self._command)

    def _read_loop(self) -> None:
        """Drain backend stdout, routing each line until EOF."""
        stdout = self._proc.stdout
        assert stdout is not None
        try:
            # readline (not `for raw in stdout`): the iterator form read-aheads
            # an internal buffer and can withhold a completed line until more
            # arrives, delaying responses. readline returns each line as soon
            # as the child flushes it.
            while True:
                raw = stdout.readline()
                if raw == "":
                    break  # EOF: backend closed stdout / exited
                # The child speaks NDJSON; a CRLF writer (or our own LF policy)
                # may leave a trailing \r — strip both. Blank keepalive lines
                # are ignored.
                line = raw.rstrip("\r\n")
                if not line.strip():
                    continue
                self._route(line)
        except Exception as e:  # pragma: no cover - defensive
            log(f"backend reader error: {e}")
        finally:
            self._fail_all("backend process exited")

    def _queue_server_initiated(self, line: str) -> None:
        """Hand a server-initiated line to the SSE stream, or shed it.

        #270 Phase 3 P3-B, review R1F2. Every path that used to call
        ``server_initiated.put`` directly comes through here, because a
        GATEWAY-OWNED child has no SSE stream and no consumer that could
        ever drain the queue — so anything put there is retained for the
        life of the process. The obvious sources (child requests and
        notifications) were gated in the reader's else-arm, but the
        `kind == "response"` arm has its OWN put for a response whose
        waiter is gone, and repeated backend timeouts would grow that
        without bound. One gate, so a future arm cannot reintroduce it.
        """
        if not self._modern_owned:
            self.server_initiated.put(line)
            return
        # #374: with listen streams attached, a child notification is
        # FANNED OUT to every stream whose filter asked for it. Parsed
        # once here on the reader thread and matched per stream, so a
        # bounded queue never holds traffic its own stream would drop —
        # the spec's "MUST NOT send notification types the client has not
        # explicitly requested" is enforced at enqueue, not at emit.
        listeners = self._snapshot_listeners()
        if listeners:
            try:
                parsed = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                parsed = None
            method = parsed.get("method") if isinstance(parsed, dict) else None
            if isinstance(method, str) and method in _LISTEN_FORWARDED_METHODS:
                delivered = False
                for listener in listeners:
                    if listener.wants(method):
                        listener.publish(parsed)
                        delivered = True
                if delivered:
                    return
            elif method == _RESOURCE_UPDATED_METHOD:
                # #381 §3.4: its own branch, UNIONED with the trio's
                # whitelist rather than merged into it. The trio matches
                # on the method alone; this one has to match on the URI
                # inside `params`, so one update fans out only to the
                # streams that named that exact URI.
                #
                # A malformed `params` degrades to no delivery rather than
                # raising: this runs on the child's READER thread, which
                # every other consumer of that child depends on.
                params = parsed.get("params") if isinstance(parsed, dict) else None
                uri = params.get("uri") if isinstance(params, dict) else None
                delivered = False
                for listener in listeners:
                    if listener.wants_resource_update(uri):
                        listener.publish(parsed)
                        delivered = True
                if delivered:
                    return
        # No listener wanted it (or none is attached): today's bounded
        # discard, byte-identical.
        self._discarded += 1
        if self._discarded == 1:
            log(
                "modern backend produced traffic no listen stream asked for; discarding"
            )

    def attach_listener(self, listener: Any, cap: int) -> bool:
        """Atomically check the stream cap and register, or refuse (#382 review R1F1).

        #374 §3.2. Called BEFORE the ack is written, deliberately: an
        event published while the ack write is in flight has to be
        buffered rather than lost, which is the server-side form of the
        ack-first invariant.

        The count-then-attach used to be two separate steps — a caller
        checked `len(self._snapshot_listeners())` against the cap, then
        called this method separately. That is bypassable by a
        synchronized burst: N simultaneous listens each see `cap - 1`
        free slots (nobody has attached yet) and all attach, exceeding
        the cap by an arbitrary amount and pinning N handler threads —
        exactly the DoS the cap exists to stop. The check and the
        append now happen under ONE lock hold, so only `cap` streams can
        ever win the race; everyone else is told False before touching
        anything.

        This does not reintroduce the false dilemma the old comment
        posed (atomic check vs. a lock spanning the SSE headers and the
        ack write): both the count and the append here are pure
        in-memory list operations, so the lock's hold time is
        unaffected by socket I/O — the caller still does the send under
        no lock at all.
        """
        with self._lock:
            if len(self._listeners) >= cap:
                return False
            self._listeners.append(listener)
            return True

    def detach_listener(self, listener: Any) -> None:
        """Unregister a stream. Idempotent — teardown paths may overlap."""
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def close_listeners(self) -> None:
        """End every attached stream gracefully (gateway shutdown)."""
        for listener in self._snapshot_listeners():
            listener.signal_end(graceful=True)

    def drain_listeners(self, timeout: float) -> bool:
        """Wait (bounded) for every stream to finish writing and detach.

        A stream detaches in its handler's `finally`, AFTER the terminal
        frame is flushed, so an empty listener list is the observable
        proof that the graceful ending actually reached the wire. Returns
        False if the timeout won instead — the caller carries on either
        way, because a shutdown that can be stalled by one wedged client
        is a worse failure than a truncated stream.
        """
        deadline = time.monotonic() + timeout
        while self._snapshot_listeners():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def _snapshot_listeners(self) -> list[Any]:
        """The attached streams, copied so the reader never holds the lock
        while a listener's bounded queue is being written."""
        with self._lock:
            return list(self._listeners)

    def add_resource_subscriptions(
        self, uris: Iterable[str], listen_id: Any, listener: Any = None
    ) -> None:
        """Take a reference on each URI, driving `resources/subscribe` for
        any URI not yet driven.

        #381 §3.1/§3.3, #388 review R2F1. A modern child is SHARED, so N
        listen streams can name the same URI; the child must be told once
        and untold once. The refcount is what makes that true — but
        `count > 0` must not be read as "the child was told"; it only
        means "a stream has claimed this URI". Whether a drive attempt has
        actually reached the child is tracked SEPARATELY as `driven`
        (see the field's own comment), which is why a URI is driven when
        it is either brand new (`count == 0`) OR already referenced but
        never driven — not only on the first reference.

        The per-call `responsive` short-circuit below (stop driving the
        REST OF THIS BATCH once the child goes unresponsive) is
        unchanged and still correct: it bounds one call's worst case
        against a hung child, which is what `_RESOURCE_SUBSCRIBE_TIMEOUT_SECS`
        and `TestResourceSubscribeDriveIsBounded` are about. What changed
        is that skipping a URI this way no longer marks it `driven` —
        before this fix it did, via the single-int refcount, which meant
        a batch's first timeout could silently strand every LATER
        first-reference URI in that batch as "subscribed" forever: no
        later call — different stream, possibly a healthy child by
        then — could ever tell it apart from a real success, so it never
        got retried.

        Runs on a BACKGROUND thread, after the ack is already on the wire
        — see `_serve_listen_stream`. Nothing here can delay the ack or
        the start of pumping, which is the whole point: legacy
        `resources/subscribe` answers with an empty result carrying no
        per-URI confirmation, so blocking on it would buy a hang vector
        and no information.

        ON A DRIVEN BUT UNCONFIRMED OUTCOME — an error response, or
        `None` from a timeout or a dead child — the URI KEEPS its
        reference, is marked DRIVEN anyway, and stays in the ack's
        already-sent honored set. There is no unwind and no retry within
        this URI's own lifetime: the ack has shipped, a timeout does not
        say whether the child processed the request, and #374's own
        precedent is that "a subscription that never fires is still
        honored". This is deliberately DIFFERENT from a URI that was
        never driven at all (short-circuited by `responsive`): an
        attempt that reached the wire is trusted not to need a second
        try; a URI nothing was ever sent for is not the same claim.

        Logged once per URI PER STREAM, via `listener.subscribe_failure_logged`
        (#388 review) — literally once now, not "once per attempt" as
        the docstring used to (mis)claim: with only one call site today
        (see `_serve_listen_stream`), a URI is driven at most once per
        stream anyway, so this latch is defense-in-depth against a
        future path that drives the same URI twice for one stream,
        mirroring relay's own `unhonored_logged` idiom. `listener` may
        be `None` (bare unit calls) — then there is no stream to latch
        against, so it just logs. This does NOT throttle a large batch:
        each of N DIFFERENT unconfirmed URIs in one call still gets its
        own line — still worth knowing WHICH URIs failed.

        `listener.torn_down` is checked under the SAME lock the refs use,
        which is what makes a stream that dies before its subscriptions
        land come out right in both orderings — see that attribute.
        """
        with self._sub_lock:
            if listener is not None and listener.torn_down:
                # Teardown already ran and found nothing to release.
                # Taking references now would strand them: the child would
                # stay subscribed with no stream left to deliver to.
                return
            responsive = True
            for uri in uris:
                count, driven = self._resource_refs.get(uri, (0, False))
                new_count = count + 1
                self._resource_refs[uri] = (new_count, driven)
                if driven:
                    continue
                if not responsive:
                    # The child stopped answering; the refcount is still
                    # taken (the ack promised this URI) but hammering an
                    # unresponsive child 255 more times only holds
                    # `_sub_lock` — and every other stream's teardown —
                    # for longer. See `_RESOURCE_SUBSCRIBE_TIMEOUT_SECS`.
                    # `driven` stays False (#388 review R2F1): a LATER
                    # call for this URI must retry the drive, not treat
                    # this skip as a subscribe that happened.
                    continue
                outcome = self._drive_resource_subscription("resources/subscribe", uri)
                # An attempt reached the wire — mark it driven regardless
                # of the reply, including a timeout/`None`: only a URI
                # nothing was ever SENT for should be retried later.
                self._resource_refs[uri] = (new_count, True)
                if outcome is None:
                    responsive = False
                if not outcome:
                    # Once per URI per STREAM (#388 review), not once per
                    # attempt: `listener` is the only thing that lives for
                    # the stream's whole lifetime, so its own set is the
                    # latch — mirrors relay's `unhonored_logged`.
                    already_logged = (
                        listener is not None
                        and uri in listener.subscribe_failure_logged
                    )
                    if not already_logged:
                        if listener is not None:
                            listener.subscribe_failure_logged.add(uri)
                        log(
                            f"listen {listen_id!r}: the child did not confirm "
                            f"resources/subscribe for {uri!r}; keeping it honored"
                        )

    def release_resource_subscriptions(self, uris: Iterable[str]) -> None:
        """Drop a reference on each URI, unsubscribing on the last — but
        only if a subscribe ever actually reached the child.

        The mirror of `add_resource_subscriptions`, called from the listen
        handler's `finally`. Unsubscribing a child that is already gone is
        a safe no-op — `send_request` returns `None` immediately once
        closed — so this needs no liveness check of its own.

        A URI with NO reference is skipped rather than unsubscribed. That
        is the teardown-before-subscribe ordering (see
        `_ListenStream.torn_down`): the drive never ran, so there is
        nothing to undo, and sending an unsubscribe the child never had a
        subscribe for would be serve inventing traffic.

        #388 review R2F1 extends that same "nothing to undo" reasoning to
        an UNDRIVEN reference — one whose count went to zero without
        `driven` ever becoming True, because `add_resource_subscriptions`
        skipped it (unresponsive child mid-batch) rather than actually
        sending it. Before this fix a plain int refcount could not tell
        that apart from a real subscribe, so this could drive a
        `resources/unsubscribe` for a URI the child was never told about
        — and, the other direction, drop the reference on a URI whose
        drive DID silently land moments later (a timeout says the child
        did not ANSWER, not that it did not PROCESS), leaving a stale
        subscription on the child that nothing tracks anymore. Checking
        `driven` here closes the first hole outright and narrows the
        second to the same "timeout != processed" ambiguity
        `add_resource_subscriptions` already lives with.
        """
        with self._sub_lock:
            responsive = True
            for uri in uris:
                entry = self._resource_refs.get(uri)
                if entry is None:
                    continue
                count, driven = entry
                if count > 1:
                    self._resource_refs[uri] = (count - 1, driven)
                    continue
                self._resource_refs.pop(uri, None)
                if not driven:
                    # Never actually subscribed (#388 review R2F1) —
                    # there is nothing on the child to undo.
                    continue
                if not responsive:
                    # Same short-circuit as `add`, and it matters more
                    # here: this runs in the handler's `finally`, so a
                    # hung child would otherwise hold the handler thread
                    # AND `_sub_lock` once per URI.
                    continue
                if (
                    self._drive_resource_subscription("resources/unsubscribe", uri)
                    is None
                ):
                    responsive = False

    # --- reverse MRTR: the parked-round table (#375 PR 1, §3.1) --------
    #
    # NOTHING IN PR 1 OPENS A ROUND. Every method below is exercised
    # directly by unit tests and by nothing else, so the table is
    # permanently empty on every live code path and this whole seam is
    # behaviour-inert — the same discipline P3-A used to ship the modern
    # validation ladder ahead of P3-B's dispatch.

    def mrtr_round_open(
        self,
        upstream_id: Any,
        *,
        method: str,
        child_request_id: Any,
        declared_caps: dict[str, Any],
        principal: str | None,
        round_no: int = 1,
        now: float | None = None,
    ) -> str:
        """Park a round on this child and return its txn id.

        The txn id is random rather than derived: it appears inside a
        client-held blob, so a guessable value would let a client name
        another round it never opened. Guessing is not sufficient to USE
        one — the pointer still has to carry a valid MAC — but there is
        no reason to hand out the first factor for free.
        """
        txn_id = secrets.token_urlsafe(16)
        deadline = (time.monotonic() if now is None else now) + _MRTR_PARK_TIMEOUT_SECS
        with self._mrtr_lock:
            if upstream_id in self._mrtr_pending:
                # #390 review, finding 3. Overwriting would ORPHAN the
                # existing round: its txn id still rides a client-held
                # `requestState`, and the table entry that pointer names
                # would silently become a different round. Steady state
                # cannot reach here — a parked round means the handler
                # already returned and cleared the context — but a child
                # that ignores its own blocking read can, and the cost of
                # guessing here is an unredeemable pointer.
                return ""
            self._mrtr_pending[upstream_id] = {
                "txn_id": txn_id,
                "method": method,
                "child_request_id": child_request_id,
                "declared_caps": declared_caps,
                "principal": principal,
                "round": round_no,
                "park_deadline": deadline,
            }
        return txn_id

    def mrtr_round_for_txn(self, txn_id: str) -> tuple[Any, dict[str, Any]] | None:
        """The `(upstream_id, entry)` a verified pointer names, or None.

        Verification of the pointer itself happens in
        `_mrtr_decode_pointer`; this only resolves it. A caller must do
        both — a well-signed pointer to a txn that no longer exists is
        the ordinary post-restart / post-timeout case, not an attack, and
        earns a clean "unknown or expired" rather than anything louder.
        """
        with self._mrtr_lock:
            for upstream_id, entry in self._mrtr_pending.items():
                if hmac.compare_digest(str(entry["txn_id"]), str(txn_id)):
                    return upstream_id, dict(entry)
        return None

    def mrtr_round_consume(self, txn_id: str) -> dict[str, Any] | None:
        """Atomically take a round out of the table — SINGLE USE.

        This is what actually closes the replay hole. HMAC alone stops
        forgery but not the re-sending of a genuine, still-validly-signed
        blob after its round already completed; removing the entry makes
        the second attempt find nothing. Pop and read under ONE lock hold,
        so two concurrent retries cannot both observe it.
        """
        with self._mrtr_lock:
            for upstream_id, entry in list(self._mrtr_pending.items()):
                if hmac.compare_digest(str(entry["txn_id"]), str(txn_id)):
                    return {
                        **self._mrtr_pending.pop(upstream_id),
                        "upstream_id": upstream_id,
                    }
        return None

    def mrtr_has_pending(self) -> bool:
        """Whether any round is currently PARKED on this child.

        Narrower than the concurrency invariant, deliberately: this
        answers "is a round waiting for a client retry", which is only
        half of "may another eligible request be dispatched". Use
        `mrtr_begin_dispatch` for the latter — reading this alone at a
        dispatch site is the exact hole #389's review found.
        """
        with self._mrtr_lock:
            return bool(self._mrtr_pending)

    def mrtr_begin_dispatch(self, context: dict[str, Any] | None = None) -> bool:
        """Claim this child for one MRTR-eligible request, or refuse.

        THE concurrency invariant (#375 §1.2), and it has to be a single
        atomic check-and-set rather than a read followed by a separate
        act — the same lesson #382's review taught for the listen-stream
        cap, where a check-then-attach let a synchronized burst all
        squeeze past a cap each of them had seen as free.

        Why the invariant exists: a pooled child answers several callers,
        and `send_request` allows several ids in flight on it at once. A
        legacy child's out-of-band request carries NO field linking it
        back to whichever call provoked it, so with two eligible calls
        outstanding the correlation is genuinely ambiguous — not hard,
        ambiguous. Guessing would attach a user's prompt to the wrong
        request.

        REFUSES ON EITHER STATE — a claim already held, or a round
        already parked. Those are different points in one lifecycle:
        a request is claimed from just before it is forwarded until its
        dispatch returns, and if it parked a round on the way then
        `_mrtr_pending` carries the exclusion onward after the claim is
        released. Checking both is what makes the handover seamless, so
        no window opens between the two.
        """
        with self._mrtr_lock:
            if self._mrtr_inflight or self._mrtr_pending:
                return False
            self._mrtr_inflight = True
            self._mrtr_context = context
            return True

    def _mrtr_try_bridge(self, msg: dict[str, Any]) -> bool:
        """Turn a child-initiated request into an `InputRequiredResult`.

        Runs on the READER thread (#375 §3.3). Returns True when the
        child's request has been accounted for — either bridged or
        answered with a capability error — and False when the caller
        should fall through to the D4 `-32601`.

        Round-1 minting needs no new response path: `_dispatch_modern` is
        already blocked in `send_request` on the very slot this fills, so
        waking it delivers the result through the existing rekey / stamp
        / send machinery. That is one place the reverse direction is
        SIMPLER than relay's PR C, which had to mint a whole new
        out-of-band request line.
        """
        context = self.mrtr_context()
        if context is None:
            return False
        capability, translated = _mrtr_request_to_input_entry(msg)
        if capability is None:
            log(f"mrtr: {translated}")
            return False
        upstream_id = context["upstream_id"]
        child_request_id = msg.get("id")
        declared = context.get("declared_caps")
        declared = declared if isinstance(declared, dict) else {}
        if capability not in declared:
            # O11, and this is the one place the reverse direction has no
            # PR C precedent to copy: "A server MUST NOT rely on
            # capabilities the client has not declared. If processing a
            # request requires a capability the client did not include in
            # `io.modelcontextprotocol/clientCapabilities`, the server
            # MUST return a `MissingRequiredClientCapabilityError`
            # (-32021) whose `data.requiredCapabilities` lists the missing
            # capabilities." Relay can never emit this — only servers
            # can — so it aborts generically; copying that here would be
            # non-conformant.
            #
            # The round is NOT opened: there is nothing to retry into.
            answered = self.answer_pending(
                upstream_id,
                _error_body(
                    "the client did not declare a capability this request needs",
                    upstream_id,
                    code=_MCP_MISSING_CLIENT_CAPABILITY,
                    data={"requiredCapabilities": [capability]},
                ),
            )
            if not answered:
                return False
            # The child still needs an answer, or it stays blocked.
            self._write(
                _error_body(
                    "the client cannot fulfill this request",
                    child_request_id,
                    code=_JSONRPC_METHOD_NOT_FOUND,
                )
            )
            return True
        round_no = int(context.get("round", 1))
        if round_no > _MRTR_MAX_ROUNDS:
            # #390 review, finding 2. `_mrtr_decode_pointer` refuses a
            # pointer past the cap, so minting one here would hand the
            # client a `requestState` it can NEVER redeem — the round
            # would stay parked until the park timeout, and before that
            # timeout was wired (finding 1) forever. Refuse at the mint
            # instead, and tell the child so it stops waiting.
            #
            # The original caller is not given a distinct error: the
            # child, now unblocked, fails its own `tools/call` and that
            # failure propagates through the ordinary response path. The
            # gateway inventing a second, competing error for a call the
            # child is still perfectly able to answer would be worse.
            log(f"mrtr: refusing round {round_no} past the {_MRTR_MAX_ROUNDS} cap")
            self._write(
                _error_body(
                    "the input-required round limit was reached",
                    child_request_id,
                    code=_JSONRPC_INVALID_PARAMS,
                )
            )
            return True
        txn_id = self.mrtr_round_open(
            upstream_id,
            # From the CONTEXT, never from `msg`: `msg` is the child's
            # out-of-band question (`sampling/createMessage`), while a
            # round belongs to the client request that provoked it
            # (`tools/call`). Recording the former put a semantically
            # different value in a field whose only consumer compares it
            # to an incoming request's method.
            method=context.get("method", ""),
            child_request_id=child_request_id,
            declared_caps=declared,
            principal=context.get("principal"),
            round_no=round_no,
        )
        if not txn_id:
            # A round is already parked on this id (finding 3's guard).
            log("mrtr: a round is already parked for this request; refusing")
            self._write(
                _error_body(
                    "a previous input request is still outstanding",
                    child_request_id,
                    code=_JSONRPC_INVALID_PARAMS,
                )
            )
            return True
        state = _mrtr_encode_pointer(txn_id, context.get("principal"), round_no)
        result = {
            "resultType": "input_required",
            # The gateway INVENTS this key: relay mints an id from a key
            # the modern server supplied, and the reverse gets a bare
            # child id with no key at all. The mapping back to the
            # child's own id lives in the parked-round table, never in
            # `requestState` (§1.1).
            "inputRequests": {str(child_request_id): translated},
            "requestState": state,
        }
        if self.answer_pending(
            upstream_id,
            json.dumps({"jsonrpc": "2.0", "id": upstream_id, "result": result}),
        ):
            return True
        # The handler vanished between the context read and now. Drop the
        # round rather than leave it parked for a retry that can never be
        # correlated, and let the caller answer the child.
        self.mrtr_round_consume(txn_id)
        return False

    def mrtr_context(self) -> dict[str, Any] | None:
        """The in-flight eligible request's bridging context, if any."""
        with self._mrtr_lock:
            return self._mrtr_context

    def answer_pending(self, req_id: Any, line: str) -> bool:
        """Hand a synthesized response to a waiting handler thread.

        #375 §3.3, and the reason round-1 minting needs no new response
        path at all: `_dispatch_modern` is already blocked in
        `send_request` on this exact slot, so filling it and setting the
        event wakes that thread as if the child had answered. The
        existing rekey / stamp / send machinery then delivers the
        `InputRequiredResult` unchanged.

        Returns False when the slot is gone — the handler timed out or
        the client disconnected — which the caller MUST treat as "this
        cannot be bridged" rather than ignore, or the child is left
        blocked on a reply nobody will send.
        """
        with self._lock:
            slot = self._pending.get(req_id)
            if slot is None:
                return False
            slot["line"] = line
            slot["event"].set()
        return True

    def mrtr_end_dispatch(self) -> None:
        """Release the claim; idempotent.

        Clears ONLY the in-flight marker. If the dispatch parked a round,
        `_mrtr_pending` is already populated and keeps excluding new
        dispatches — which is why this can run unconditionally in a
        `finally` without reopening the gap.
        """
        with self._mrtr_lock:
            self._mrtr_inflight = False
            self._mrtr_context = None

    def mrtr_expire_parked(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Drop rounds past their park deadline; return what was dropped.

        Returning the entries rather than acting on them keeps this
        callable from a sweep without deciding policy: PR 2 writes a
        JSON-RPC error back to the child under its own
        `child_request_id`, which unblocks it and returns it to the pool.
        No client-facing action is owed — Server Requirements item 8
        licenses giving up on a retry that never came.
        """
        stamp = time.monotonic() if now is None else now
        expired: list[dict[str, Any]] = []
        with self._mrtr_lock:
            for upstream_id, entry in list(self._mrtr_pending.items()):
                if stamp <= entry["park_deadline"]:
                    continue
                # ONCE PER TRANSACTION, and the mechanism is the pop on
                # the next line rather than a latch flag (#375 §4 Q7,
                # trap 3). Expiry is checked on a POLL, so a log emitted
                # while the entry SURVIVES would repeat once per tick for
                # as long as it lasted — the flood #388's own
                # failure-logged latch exists to prevent. Here the entry
                # is removed in the same lock hold that logs it, so the
                # second sweep finds nothing to say.
                #
                # A latch was written first and deleted: with an
                # unconditional pop it could never fire twice, so it was
                # dead code AND made the guarding test vacuous — the test
                # passed with the latch removed. The test now pins the
                # property (repeated sweeps => exactly one line), which
                # catches the real regression: making expiry non-popping
                # or retry-on-failure.
                log(
                    f"mrtr: txn {entry['txn_id']!r} (round {entry['round']}) "
                    f"abandoned after {_MRTR_PARK_TIMEOUT_SECS:g}s with no "
                    "client retry; unblocking the child"
                )
                expired.append(
                    {**self._mrtr_pending.pop(upstream_id), "upstream_id": upstream_id}
                )
        return expired

    def _drive_resource_subscription(self, method: str, uri: str) -> bool | None:
        """Send one `resources/subscribe`/`unsubscribe` to the child.

        `_mint_modern_id()` supplies the id, and reusing it is deliberate
        rather than convenient: it is ALREADY the reserved namespace for
        requests serve issues on its own behalf (the same minting that
        keeps forwarded calls from colliding with a concurrent client's
        ids on this shared child). A fresh scheme here would be a second
        answer to a question that already has one.

        A REQUEST, not a oneway send: a oneway leaves the child's eventual
        response with no `_pending` waiter, so it lands in
        `_queue_server_initiated`'s unsolicited-traffic discard and logs a
        warning about traffic serve itself asked for.

        Returns True on a real reply, False on an error reply, and NONE
        when the child did not answer at all — a timeout or a closed
        child. The caller uses that third state to stop driving the rest
        of the batch, because an unresponsive child will not answer the
        next URI either and every extra attempt is `_sub_lock` held for
        another timeout.

        Caller holds `_sub_lock`; `send_request` takes `_lock` inside.
        """
        req_id = _mint_modern_id()
        line = self.send_request(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": method,
                    "params": {"uri": uri},
                }
            ),
            req_id,
            _RESOURCE_SUBSCRIBE_TIMEOUT_SECS,
        )
        if line is None:
            return None
        try:
            return "error" not in json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return False

    def _route(self, line: str) -> None:
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            # Non-JSON noise on the JSON-RPC channel: surface it on the SSE
            # stream rather than dropping silently, so a debugging operator can
            # see it. It cannot be a response (unparseable), so it never
            # correlates to a pending id.
            self._queue_server_initiated(line)
            return
        kind = _classify(msg)
        if kind == "response":
            rid = msg.get("id")
            with self._lock:
                slot = self._pending.get(rid)
                if slot is not None:
                    slot["line"] = line
                    slot["event"].set()
                    return
            # No waiter (timed-out, or an id we never sent): expose on SSE
            # rather than lose it — unless nothing can ever read it (R1F2).
            self._queue_server_initiated(line)
        elif self._modern_owned:
            # #270 Phase 3 P3-B. A gateway-owned child has NO SSE stream
            # and no client that could ever drain `server_initiated`, so
            # queueing here would grow without bound for the life of the
            # process — the "unbounded is fine for one client" assumption
            # stops holding the moment a child is pooled and long-lived.
            if kind == "request":
                # A child-initiated request (elicitation/sampling/roots
                # from a misbehaving child; a well-behaved one never asks,
                # because the gateway's handshake advertised `{}`). Answer
                # it straight from the reader thread rather than leaving
                # the child blocked forever on a reply nobody will send.
                # Also discharges O15: "The server MUST NOT send
                # independent JSON-RPC requests on this stream" — nothing
                # of the kind ever reaches a stream, because there is none.
                # `_write` is lock-guarded and its broken-pipe path is
                # already reentrant-safe, so this is safe off-thread.
                # #375 PR 2: try to bridge it into the parked handler
                # first. An ADDITION IN FRONT OF the D4 reply below, never
                # a rewrite of it — everything unbridgeable (no eligible
                # request in flight, an unbridgeable method, a capability
                # the client never declared, a handler that already went
                # away) still falls through to the same `-32601`, which
                # is what keeps the never-hang invariant the default
                # outcome rather than something the bridge has to
                # remember to preserve.
                if self._mrtr_try_bridge(msg):
                    return
                self._write(
                    _error_body(
                        "this gateway does not bridge server-initiated requests",
                        msg.get("id"),
                        code=_JSONRPC_METHOD_NOT_FOUND,
                    )
                )
                return
            # Notifications and noise: shed through the same gate.
            self._queue_server_initiated(line)
        else:
            # request / notification / invalid — all server-initiated toward
            # the client.
            self._queue_server_initiated(line)

    @staticmethod
    def _same_request(a: str, b: str) -> bool:
        """Whether two serialized request lines carry the same message.

        Byte equality first (the common case: one client re-firing the exact
        line), falling back to parsed equality so a retry re-serialized with a
        different key order or number formatting still matches.
        """
        if a == b:
            return True
        try:
            return json.loads(a) == json.loads(b)
        except (json.JSONDecodeError, TypeError):
            return False

    @staticmethod
    def _request_method(line: str) -> str | None:
        """Best-effort ``method`` of a serialized request line, for diagnostics."""
        try:
            method = json.loads(line).get("method")
        except (json.JSONDecodeError, AttributeError, TypeError):
            return None
        return method if isinstance(method, str) else None

    def _detach(self, req_id: Any, slot: dict[str, Any]) -> str | None:
        """Drop one waiter from ``slot``; the LAST one out retires it.

        Waiter-counted retirement keeps the slot registered while any
        piggybacked retry is still waiting, so a reply arriving after the
        first caller's own timeout still reaches the remaining waiter(s)
        instead of leaking to SSE, ``_fail_all`` can still wake them, and
        ``has_pending`` keeps the idle reaper away.

        Returns the response line if it has arrived (read under the lock, so
        a reply landing between this waiter's ``wait()`` expiry and now is
        still honored), else ``None``.
        """
        with self._lock:
            slot["waiters"] -= 1
            if slot["waiters"] <= 0 and self._pending.get(req_id) is slot:
                self._pending.pop(req_id, None)
            return slot["line"]

    def send_request(self, line: str, req_id: Any, timeout: float) -> str | None:
        """Forward a request line and block for its response.

        MCP forbids reusing a request id within a session; two requests
        sharing an id *in flight at once* with DIFFERENT payloads are
        unambiguously non-compliant and cannot be correlated (both replies
        would carry that id) — that case still raises
        :class:`_DuplicateInFlightId`. But a same-id request with the SAME
        payload (compared parsed, so a re-serialized retry with different key
        order still matches) arriving while the first is still outstanding is
        a client-side retry (observed after gateway restarts / idle-reclaim:
        the client's reconnect burst re-fires a request whose id collides
        with itself), not a protocol violation. Piggyback the retry onto the
        original's pending slot — every waiter still attached when the reply
        arrives observes that one backend reply — instead of sending a second
        copy to the backend or rejecting it with 409. Each waiter keeps its
        OWN deadline: one whose timeout expires before the reply lands gets
        ``None`` while a later-attached waiter can still succeed.

        Sequential reuse (the id already popped on completion) is not a
        collision here and stays tolerated, so lenient real-world clients
        that pin one id keep working. Consequently a same-payload retry that
        lands just AFTER the first copy completed is indistinguishable from
        legitimate sequential reuse and is dispatched anew — callers of
        non-idempotent methods must not rely on this window being deduplicated.

        Returns the backend's response line, or ``None`` on timeout / backend
        death (the caller then synthesizes a JSON-RPC error).
        """
        with self._lock:
            if self._closed.is_set():
                return None
            existing = self._pending.get(req_id)
            if existing is not None:
                if not self._same_request(existing["request_line"], line):
                    raise _DuplicateInFlightId(
                        req_id,
                        in_flight_method=self._request_method(existing["request_line"]),
                        rejected_method=self._request_method(line),
                    )
                # `slot` is the SAME dict object already in `_pending`, so the
                # `_route()` write to slot["line"] / slot["event"].set() below
                # is visible here too, whichever caller reads it first.
                slot = existing
                slot["waiters"] += 1
                dispatch = False
            else:
                slot = {
                    "event": threading.Event(),
                    "line": None,
                    "request_line": line,
                    "waiters": 1,
                }
                self._pending[req_id] = slot
                dispatch = True
        if dispatch and not self._write(line):
            self._detach(req_id, slot)
            return None
        slot["event"].wait(timeout)
        return self._detach(req_id, slot)

    def resume_request(
        self, reply_line: str, req_id: Any, timeout: float
    ) -> tuple[str | None, bool]:
        """Answer the child's own question, then wait for the ORIGINAL reply.

        #375 §3.5, and the shape is why this cannot just be
        `send_request`: the line written is the reply to the CHILD's
        out-of-band request, while the response waited for is the one the
        child still owes on the original `tools/call`. Two different ids,
        one round trip.

        The waiter is registered BEFORE the reply is written. A child can
        answer the instant it unblocks, and a slot created afterwards
        would miss a response already routed — the same
        register-then-write ordering `send_request` uses, for the same
        reason.

        Returns `(line, delivered)`. `delivered` is what a bare `None`
        cannot express (#390 review, finding 5): a timeout AFTER a
        successful write means the child was told and simply has not
        answered yet, so answering it again would put a second reply on
        its stream — while the early returns below mean it was never told
        and is still blocked. Conflating the two either wedges a child or
        corrupts it.
        """
        slot: dict[str, Any] = {
            "event": threading.Event(),
            "line": None,
            "request_line": reply_line,
            "waiters": 1,
        }
        with self._lock:
            if self._closed.is_set():
                # Nothing is owed: the child is gone.
                return None, True
            if req_id in self._pending:
                # The original slot should be long gone — its handler
                # returned the InputRequiredResult. If it is not, the
                # correlation is ambiguous and guessing is what this
                # whole design refuses to do. NOT delivered: the child
                # is still blocked, and the caller must answer it.
                return None, False
            self._pending[req_id] = slot
        if not self._write(reply_line):
            self._detach(req_id, slot)
            # A broken pipe makes the child unreachable rather than merely
            # untold; nothing further can be delivered to it.
            return None, True
        slot["event"].wait(timeout)
        return self._detach(req_id, slot), True

    def send_oneway(self, line: str) -> bool:
        """Forward a notification or a client->server response (no reply)."""
        return self._write(line)

    def _write(self, line: str) -> bool:
        stdin = self._proc.stdin
        if stdin is None or self._closed.is_set():
            return False
        try:
            with self._write_lock:
                stdin.write(line + "\n")
                stdin.flush()
            return True
        except (BrokenPipeError, ValueError, OSError) as e:
            # ValueError: write on a closed file. OSError/BrokenPipe: backend
            # gone. Mark closed so in-flight + future calls fail fast.
            log(f"backend write failed: {e}")
            self._fail_all("backend process exited")
            return False

    def _fail_all(self, _reason: str) -> None:
        """Mark closed and wake every waiter so none blocks forever."""
        if self._closed.is_set():
            return
        self._closed.set()
        with self._lock:
            waiters = list(self._pending.values())
            self._pending.clear()
        for slot in waiters:
            slot["event"].set()  # line stays None -> caller emits error
        # #374: a listen stream is a waiter too. Without this it would sit
        # on its queue until the next keepalive tick before noticing the
        # child is gone. LOST, not graceful: serve itself is still up, so
        # the contract is that the peer re-listens and refetches — and a
        # terminal `complete` would tell it the opposite.
        for listener in self._snapshot_listeners():
            listener.signal_end(graceful=False)

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    @property
    def has_pending(self) -> bool:
        """True while at least one request is awaiting a backend response."""
        with self._lock:
            return bool(self._pending)

    def shutdown(self) -> None:
        """Terminate the backend child, escalating to kill if needed."""
        self._fail_all("gateway shutting down")
        proc = self._proc
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception as e:  # pragma: no cover - defensive
            log(f"backend shutdown error: {e}")


# --- per-session backend registry: one child stdio server per MCP session ---

# Hard cap on concurrent sessions: a fork-bomb guard for an open (no-auth)
# gateway, since each session spawns a child process. High enough that a single
# logical client never trips it; override with ``--max-sessions``.
_DEFAULT_MAX_SESSIONS = 100

# Longest a reaper tick waits between idle sweeps. A small TTL is swept more
# often; a large one no less than once a minute.
_MAX_REAP_INTERVAL_SECS = 60.0

# Owner identity of a session created by a static-token request. It is a single
# shared principal (a static token has no per-user identity), distinct from any
# OAuth user, so on a static+OAuth gateway an OAuth user cannot ride or tear
# down a static-token session (and vice versa). The NUL prefix keeps it from
# colliding with any header-supplied OAuth username.
_STATIC_PRINCIPAL = "\x00static-token"


class _Session:
    """A live MCP session: its backend child, last activity, and owner.

    ``owner`` is the authenticated OAuth user the session is bound to (``None``
    for static-token or no-auth sessions, which carry no per-user identity).
    """

    __slots__ = ("backend", "last_active", "owner")

    def __init__(
        self, backend: BackendProcess, last_active: float, owner: str | None
    ) -> None:
        self.backend = backend
        self.last_active = last_active
        self.owner = owner

    def accessible_by(self, user: str | None) -> bool:
        """Whether a request authenticated as ``user`` may use this session.

        Unbound sessions (``owner`` None — open gateway) are accessible by
        anyone; a bound session only by its owner. Single source of truth for
        the ownership rule shared by :meth:`SessionRegistry.get` and
        :meth:`SessionRegistry.remove`.
        """
        return self.owner is None or self.owner == user


class SessionRegistry:
    """Thread-safe map of ``Mcp-Session-Id`` -> backend child process.

    Each MCP session gets its OWN stdio backend, so concurrent clients are
    isolated by process boundary rather than multiplexed onto one shared child
    (which could cross responses on a JSON-RPC id collision). A session is
    created when a client POSTs ``initialize`` (the gateway mints an id and
    spawns a dedicated :class:`BackendProcess`), looked up by that header on
    every later request, and removed on DELETE or gateway shutdown.

    The slow operations — spawning a child (``Popen`` exec) and tearing one
    down (``terminate()`` then ``wait``) — run OUTSIDE the lock; only the dict
    mutation is guarded, so one session's lifecycle never serializes another's.

    A background reaper (started by :meth:`start_reaper`) ALWAYS runs
    (#385) sweeping any session whose child has already exited — a dead
    child pins a slot forever otherwise, TTL or not — and additionally,
    when ``idle_ttl`` is set (``> 0``), sessions whose last activity is
    older than the TTL, so a client that disconnects without DELETE does
    not pin a slot forever either. ``now`` is injectable so tests can
    drive eviction on a fake clock.
    """

    def __init__(
        self,
        command: list[str],
        *,
        max_sessions: int = _DEFAULT_MAX_SESSIONS,
        idle_ttl: float = 0.0,
        max_sessions_per_owner: int = 0,
        now: Any = time.monotonic,
        user_env_var: str | None = None,
    ) -> None:
        if not command:
            raise ValueError("backend command is empty")
        self._command = command
        self._max = max_sessions
        self._idle_ttl = idle_ttl
        self._max_per_owner = max_sessions_per_owner
        self._now = now
        # --user-env VAR: see ModernBackendPool.__init__ for the contract.
        self._user_env_var = user_env_var
        self._lock = threading.Lock()
        self._sessions: dict[str, _Session] = {}
        self._reaper: threading.Thread | None = None
        self._reaper_stop = threading.Event()

    def create(self, owner: str | None = None) -> tuple[str, BackendProcess] | None:
        """Spawn a child for a new session, optionally bound to ``owner``.

        Returns ``(session_id, backend)``, or ``None`` when the concurrent-
        session cap is reached (the caller then responds 503).
        """
        # Per-owner reclamation runs BEFORE the global-cap check so a returning
        # owner reclaims its OWN ghost sessions even when --max-sessions is
        # saturated. That ordering is the point: a remote connector that opens a
        # fresh session per reconnect without DELETEing the old one leaves
        # ghosts; if the cap check ran first, a client whose own ghosts fill the
        # cap would be locked out until the idle reaper fires — exactly what this
        # feature promises to prevent. LRU-evict this owner's sessions down to
        # max_per_owner - 1 so the new one lands at exactly the cap. Only real
        # per-user (OAuth) owners are capped; the shared static-token principal
        # and the open-gateway (None) owner are exempt, since many distinct
        # clients legitimately share them.
        reclaimed: list[tuple[str, BackendProcess]] = []
        with self._lock:
            if (
                self._max_per_owner > 0
                and owner is not None
                and owner != _STATIC_PRINCIPAL
            ):
                owned = sorted(
                    (
                        (s, sess)
                        for s, sess in self._sessions.items()
                        if sess.owner == owner
                    ),
                    key=lambda item: item[1].last_active,
                )
                excess = len(owned) - (self._max_per_owner - 1)
                for s, sess in owned[: max(0, excess)]:
                    del self._sessions[s]
                    reclaimed.append((s, sess.backend))
            at_cap = len(self._sessions) >= self._max
        # shutdown() (terminate -> wait) runs OUTSIDE the lock so it never
        # serializes other sessions' creation or routing.
        for s, be in reclaimed:
            be.shutdown()
            log(f"reclaimed prior session {s[:8]}... on owner re-initialize")
        if at_cap:
            return None
        # Spawn outside the lock: a Popen exec must not serialize other
        # sessions' creation or routing.
        extra_env = _extra_env_for_principal(self._user_env_var, owner)
        backend = BackendProcess(self._command, extra_env=extra_env)
        # MCP spec: the session id SHOULD be globally unique and
        # cryptographically secure, and MUST contain only visible ASCII.
        sid = secrets.token_hex(16)
        with self._lock:
            # Re-check the cap: a burst of concurrent creates could have filled
            # it while we were spawning. Over the cap -> drop the just-spawned
            # child rather than exceed the bound.
            over_cap = len(self._sessions) >= self._max
            if not over_cap:
                self._sessions[sid] = _Session(backend, self._now(), owner)
        if over_cap:
            backend.shutdown()
            return None
        return sid, backend

    def get(self, sid: str | None, user: str | None = None) -> BackendProcess | None:
        """Resolve a session id to its backend, or None if unknown — or bound
        to a different principal than ``user``.

        Touches the session's last-activity timestamp so an actively used
        session is never idle-reaped. A bound session (``owner`` set) is only
        returned to its owner; mismatch yields None (the caller 404s, neither
        confirming the session to a different principal nor letting that
        principal route into it).
        """
        if not sid:
            return None
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is None or not sess.accessible_by(user):
                return None
            sess.last_active = self._now()
            return sess.backend

    def touch(self, sid: str | None) -> None:
        """Mark a session active without resolving it (e.g. on SSE traffic)."""
        if not sid:
            return
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is not None:
                sess.last_active = self._now()

    def remove(self, sid: str | None, user: str | None = None) -> BackendProcess | None:
        """Detach a session and return its backend (or None if unknown — or
        bound to a different principal than ``user``).

        The caller calls ``backend.shutdown()`` OUTSIDE the lock so a slow
        terminate never freezes routing for other sessions. The same ownership
        check as :meth:`get` applies, so one principal cannot DELETE another's
        session.
        """
        if not sid:
            return None
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is None or not sess.accessible_by(user):
                return None
            del self._sessions[sid]
            return sess.backend

    def reap_idle(self) -> int:
        """Drop sessions idle past the TTL — or whose child has exited — and
        shut their backends down outside the lock. Returns the count reaped."""
        ttl = self._idle_ttl
        now = self._now()
        victims: list[tuple[str, BackendProcess]] = []
        with self._lock:
            for sid, sess in list(self._sessions.items()):
                backend = sess.backend
                # Don't idle-reap a session with a request in flight: a slow
                # tool call (up to the backend-response timeout) is not idleness.
                idle = (
                    ttl > 0 and now - sess.last_active > ttl and not backend.has_pending
                )
                if backend.closed or idle:
                    del self._sessions[sid]
                    victims.append((sid, backend))
        for sid, backend in victims:
            backend.shutdown()
            log(f"reaped idle session {sid[:8]}...")
        return len(victims)

    def shutdown_all(self) -> None:
        """Tear down every session's child (gateway shutdown)."""
        self.stop_reaper()
        with self._lock:
            backends = [s.backend for s in self._sessions.values()]
            self._sessions.clear()
        for backend in backends:
            backend.shutdown()

    def keepalive_interval(self) -> float:
        """SSE keepalive/touch cadence — short enough that an open stream
        refreshes its activity before the idle reaper could evict it (so a
        connected client is never reaped even when the TTL is below the default
        keepalive)."""
        if self._idle_ttl > 0:
            return max(1.0, min(_SSE_KEEPALIVE_SECS, self._idle_ttl / 2))
        return _SSE_KEEPALIVE_SECS

    def start_reaper(self) -> None:
        """Start the background sweep thread.

        #385: ``reap_idle`` already reaps two INDEPENDENT things —
        ``backend.closed`` (a dead child, dropped UNCONDITIONALLY,
        TTL-or-not) and idle-past-TTL (only when ``idle_ttl > 0``) — but
        this method used to gate STARTING THE THREAD AT ALL on the TTL
        alone. In the default deployment (``--session-idle-ttl`` unset,
        ``0``) that meant the thread never started, so the unconditional
        dead-child sweep — correctly written, and already covering every
        code path that can leave a child dead, not just one handler — had
        no production caller: a long-lived gateway on default settings
        accumulated dead-child sessions with no way to shed them, eating
        into ``--max-sessions`` until new ``initialize`` calls got `503`
        against slots that were all corpses. Follows the SAME PATTERN as
        the fix already applied to the modern pool's analogous reaper
        (#390 R3F1, ``ModernBackendPool.start_reaper``) — separate "why
        does the thread run" from "what does each tick actually evict",
        since ``reap_idle`` was always correct on the latter — but the
        RESULT is not identical: the modern pool's ``start_reaper`` still
        gates on ``modern_idle_ttl > 0 or`` the MRTR bridge being enabled,
        so a pure-default deployment (neither set) still never starts
        that thread and still never sweeps a dead modern child. THIS
        method now starts unconditionally, with no equivalent second gate
        (#385 review R1F1).

        So this now ALWAYS starts (no-op only on a second call): the tick
        interval favors the idle TTL when one is configured (finer-grained
        eviction), and falls back to sweeping for dead children alone,
        at least once a minute, when it is not.
        """
        if self._reaper is not None:
            return
        self._reaper_stop.clear()  # allow a restart after a prior stop_reaper
        if self._idle_ttl > 0:
            interval = max(1.0, min(self._idle_ttl, _MAX_REAP_INTERVAL_SECS))
        else:
            interval = _MAX_REAP_INTERVAL_SECS

        def _loop() -> None:
            while not self._reaper_stop.wait(interval):
                try:
                    self.reap_idle()
                except Exception as e:  # pragma: no cover - defensive
                    log(f"session reaper error: {e}")

        self._reaper = threading.Thread(
            target=_loop, name="session-reaper", daemon=True
        )
        self._reaper.start()

    def stop_reaper(self) -> None:
        self._reaper_stop.set()
        reaper = self._reaper
        if reaper is not None:
            reaper.join(timeout=2)
            self._reaper = None

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._sessions)


# --- embedded OAuth 2.1 Authorization Server (stdlib only, opaque tokens) ---

_AS_METADATA_PATH = "/.well-known/oauth-authorization-server"
_AUTHORIZE_PATH = "/authorize"
_TOKEN_PATH = "/token"
_REGISTER_PATH = "/register"

_AUTH_CODE_TTL_SECS = 60.0
_DEFAULT_ACCESS_TTL_SECS = 3600.0
_REFRESH_TTL_SECS = 60.0 * 60.0 * 24.0 * 30.0  # 30 days
_STORE_CAP = 10000  # per-store entry cap (DoS bound); GC runs before the cap
_CLIENT_CAP = 1000
# Reuse of a just-consumed authorization code / rotated refresh token within
# this window is treated as a benign client retry or concurrent double-submit
# (deny without revoking); a reuse OUTSIDE the window is a theft signal and
# revokes the whole grant family. RFC 9700 Sec. 4.14.2 permits tolerating a
# brief reuse window so a racing/retrying legitimate client is not punished.
_REUSE_GRACE_SECS = 10.0

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
# RFC 7636 Sec. 4.1 code_verifier unreserved set.
_PKCE_VERIFIER_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


def _pkce_s256_challenge(verifier: str) -> str:
    """BASE64URL(SHA256(verifier)) without padding — byte-identical to the
    client's ``oauth.generate_pkce`` so a correct verifier always matches."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _valid_code_verifier(v: str) -> bool:
    return 43 <= len(v) <= 128 and all(c in _PKCE_VERIFIER_CHARS for c in v)


def _redirect_key(uri: str) -> tuple[str, str, str] | None:
    """RFC 8252 loopback redirect key (scheme, host, path), port-agnostic.

    Returns None for anything that is not an ``http://`` loopback URI, or that
    carries a fragment, query, userinfo, or CR/LF. Comparing on this key lets a
    per-run ephemeral callback port still match a registered client_id whose
    stored port differs (step-up reuse). The query is rejected (not just
    ignored): the key drops it, so accepting it would let the raw redirect_uri
    be reflected into a malformed double-``?`` Location and smuggle a second
    identity behind one registered (scheme, host, path).
    """
    if "\r" in uri or "\n" in uri:
        return None
    try:
        p = urlsplit(uri)
    except ValueError:
        return None
    if p.fragment or p.query or p.username or p.password or "@" in p.netloc:
        return None
    host = (p.hostname or "").lower()
    if p.scheme != "http" or host not in _LOOPBACK_HOSTS:
        return None
    return (p.scheme, host, p.path or "/")


def _validate_allowed_redirect_uri(uri: str) -> str:
    """Validate an operator-configured (``--allow-redirect-uri``) exact-match
    HTTPS redirect target.

    Unlike the loopback ``_redirect_key()`` path (RFC 8252, port-agnostic,
    ``http`` only, for a locally-run CLI/native client), this is for a KNOWN,
    FIXED remote callback -- e.g. a browser-based MCP client hosted on a
    public domain -- that the operator has explicitly decided to trust. It is
    matched byte-for-byte at registration/authorize time (see ``_match_key``),
    never widened or normalized, so this validation only needs to catch an
    unsafe *configuration* (a typo'd scheme, a stray fragment), not guard
    against a client-controlled bypass.

    Raises ValueError with a human-readable reason on rejection.
    """
    if "\r" in uri or "\n" in uri:
        raise ValueError(f"{uri!r}: contains CR/LF")
    try:
        p = urlsplit(uri)
    except ValueError as e:
        raise ValueError(f"{uri!r}: {e}") from e
    if p.scheme != "https":
        raise ValueError(
            f"{uri!r}: must be an https:// URL (never http for a non-loopback redirect)"
        )
    if not p.hostname:
        raise ValueError(f"{uri!r}: missing host")
    if p.username or p.password or "@" in p.netloc:
        raise ValueError(f"{uri!r}: must not contain userinfo")
    # Mirrors _redirect_key()'s query rejection: authorize()'s redirect()
    # builds the Location as `redirect_uri + "?" + urlencode(query)`, so a
    # redirect_uri that already carries a query produces a malformed
    # double-"?" Location in which "code" is swallowed into the tail of the
    # existing query's last value instead of appearing as its own parameter.
    if p.query:
        raise ValueError(f"{uri!r}: must not contain a query string")
    if p.fragment:
        raise ValueError(f"{uri!r}: must not contain a fragment")
    return uri


def _match_key(uri: str, allowed_redirects: frozenset[str]) -> tuple[Any, ...] | None:
    """Registration/authorize matching key for a ``redirect_uri``.

    Two disjoint forms are accepted, each through its own independent check --
    the exact-match form is deliberately NOT folded into ``_redirect_key()``,
    so widening one can never accidentally widen the other:

    - RFC 8252 loopback ``http``, via ``_redirect_key()``: port-agnostic.
    - An operator-configured ``--allow-redirect-uri`` entry: matched
      byte-for-byte, no normalization, so a client can never satisfy it with
      anything but the exact configured string.

    Returns None if neither applies.
    """
    rk = _redirect_key(uri)
    if rk is not None:
        return ("loopback", *rk)
    if uri in allowed_redirects:
        return ("exact", uri)
    return None


def _log_safe_uri(value: Any, *, max_len: int = 200) -> str:
    """Render a client-proposed redirect_uri for a diagnostic log line.

    ``repr`` escapes control characters (CR/LF in particular) so a hostile value
    cannot inject a forged log line, while keeping the URL human-readable so an
    operator can copy it into ``--allow-redirect-uri``. The length bound stops a
    client writing an unbounded line. A rejected redirect_uri is not a secret and
    not an issued credential, so surfacing it leaks nothing (#286).
    """
    if isinstance(value, str) and len(value) > max_len:
        value = value[:max_len] + "..."
    return repr(value)[: max_len + 8]


def _normalize_public_url(url: str) -> str:
    """Normalize --public-url to a canonical issuer ``scheme://host[:port][/path]``.

    Raises ValueError on a non-http(s) URL, a missing host, userinfo,
    CR/LF/quote/space, a non-loopback ``http://`` (a compliant client refuses
    cleartext non-loopback endpoints), a bad port, or a query/fragment (the
    RFC 8414 Sec. 2 issuer grammar forbids them). The host is lowercased, an
    explicit default port is dropped, an IPv6 literal is re-bracketed, and a
    trailing slash is stripped, so the issuer is byte-identical to what a client
    derives (RFC 8414 Sec. 3.3).

    A PATH component is RETAINED: a path-scoped issuer (``https://host/team-a``)
    lets several ``--enable-oauth`` backends share one host behind a reverse
    proxy, each owning its AS namespace under its own prefix, symmetric with the
    bundled client's RFC 8414 Sec. 3.1 / RFC 9728 Sec. 3.1 path-aware discovery
    (#245). A bare-origin URL (no path) behaves exactly as before.
    """
    if any(c in url for c in ('"', "\r", "\n", " ")):
        raise ValueError("public-url contains forbidden characters")
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("public-url must be an absolute http(s) URL with a host")
    if p.username or p.password or "@" in p.netloc:
        raise ValueError("public-url must not contain userinfo")
    if p.query or p.fragment:
        raise ValueError("public-url must not contain a query or fragment")
    host = p.hostname.lower()
    if p.scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise ValueError("a non-loopback public-url must use https")
    try:
        port = p.port
    except ValueError as e:
        raise ValueError("public-url has an invalid port") from e
    hostpart = f"[{host}]" if ":" in host else host
    default_port = 80 if p.scheme == "http" else 443
    netloc = (
        hostpart if (port is None or port == default_port) else f"{hostpart}:{port}"
    )
    # Retain the path as the issuer prefix; strip only a trailing slash so
    # "https://host/a/" and "https://host/a" canonicalize identically and a bare
    # "https://host/" collapses to the bare origin (unchanged legacy behavior).
    path = p.path.rstrip("/")
    if path:
        # The prefix is concatenated verbatim into the endpoint URLs and the
        # well-known locations, so it MUST be a canonical, traversal-free
        # absolute path: an empty ("//"), "." or ".." segment would be
        # re-normalized differently by a proxy or the client and break the
        # byte-identical-issuer contract (and could escape the intended
        # namespace). Reject rather than silently rewrite. The leading segment
        # is always "" because an authority-form URL path is "/"-rooted.
        segments = path.split("/")
        if segments[0] != "" or any(seg in ("", ".", "..") for seg in segments[1:]):
            raise ValueError(
                "public-url path must be a canonical absolute path "
                "(no empty, '.', or '..' segments)"
            )
    return f"{p.scheme}://{netloc}{path}"


def _redact_query(line: str) -> str:
    """Redact query strings from an access-log line.

    OAuth /authorize requests carry the client's single-use CSRF ``state`` (and
    error redirects can echo it); the bundled client deliberately keeps that
    nonce out of its own logs, so the gateway must not reintroduce it. Every
    ``?...`` run (up to whitespace or a quote) is redacted, covering BOTH the
    origin-form ``/authorize?...`` and the absolute-form
    ``http://host/authorize?...`` request targets (RFC 7230 allows the latter,
    e.g. via a forwarding proxy). MCP requests carry no query, so this is
    lossless here.
    """
    return re.sub(r'\?[^\s"]*', "?<redacted>", line)


# On-disk AS-state schema version (--token-store). Bump ONLY when the snapshot
# layout changes incompatibly — an unrecognized version starts empty rather
# than guessing at field meanings, which forces a fleet-wide re-auth, so an
# ADDITIVE field must keep the version (the record validators below tolerate
# unknown fields precisely so additive changes stay non-breaking).
_STATE_VERSION = 1


def _finite_num(v: Any) -> bool:
    """True for a finite int/float (bool excluded — JSON true/false must not
    pass as a timestamp)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _opt_str(v: Any) -> bool:
    return v is None or isinstance(v, str)


def _valid_client_record(v: Any) -> bool:
    return (
        isinstance(v, dict)
        and isinstance(v.get("redirect_uris"), list)
        and bool(v["redirect_uris"])
        and all(isinstance(u, str) for u in v["redirect_uris"])
        and _finite_num(v.get("created_at"))
    )


def _valid_code_record(v: Any) -> bool:
    # "resource" must be PRESENT (None is fine): the exchange path reads
    # entry["resource"] by subscript, so a key dropped by a foreign writer
    # must fail validation here, not KeyError the token endpoint later.
    return (
        isinstance(v, dict)
        and isinstance(v.get("client_id"), str)
        and isinstance(v.get("redirect_uri"), str)
        and isinstance(v.get("code_challenge"), str)
        and isinstance(v.get("user"), str)
        and bool(v["user"])
        and isinstance(v.get("scope"), str)
        and "resource" in v
        and _opt_str(v["resource"])
        and _finite_num(v.get("expires_at"))
    )


def _valid_grant_record(v: Any) -> bool:
    """An access- or refresh-token record (both share one shape).

    "resource" and "family" must be PRESENT (None is fine): the refresh path
    subscripts entry["resource"], so absence must be rejected at load time.
    """
    return (
        isinstance(v, dict)
        and isinstance(v.get("user"), str)
        and bool(v["user"])
        and isinstance(v.get("client_id"), str)
        and isinstance(v.get("scope"), str)
        and "resource" in v
        and _opt_str(v["resource"])
        and "family" in v
        and _opt_str(v["family"])
        and _finite_num(v.get("expires_at"))
    )


def _valid_tombstone_record(v: Any) -> bool:
    # "family" must be PRESENT (None is fine): the replay-detection path
    # subscripts tomb["family"] — a missing key would 500 the token endpoint
    # AND skip the RFC-mandated family revocation on the theft signal.
    return (
        isinstance(v, dict)
        and "family" in v
        and _opt_str(v["family"])
        and _finite_num(v.get("consumed_at"))
        and _finite_num(v.get("expires_at"))
    )


def _mkdir_private(directory: Path) -> None:
    """Create ``directory`` (and any missing ancestors) at 0o700, umask-proof.

    ``Path.mkdir(parents=True)`` creates the INTERMEDIATE directories at the
    umask default (commonly 0o755), which would leave a credential file's
    enclosing tree group/other-traversable — the same reasoning as
    token_store._ensure_store_dir. Only directories we create are tightened;
    a pre-existing directory is left untouched.
    """
    for ancestor in (*reversed(directory.parents), directory):
        if not ancestor.exists():
            try:
                os.mkdir(ancestor, 0o700)
            except FileExistsError:
                pass  # a concurrent process created it; leave its mode alone


def _acquire_store_lock(store_path: Path) -> Any:
    """Take a process-lifetime exclusive advisory lock guarding a token store.

    Two serve processes pointed at one --token-store would silently
    last-writer-wins clobber each other's snapshots — losing freshly issued
    tokens AND replay-detection tombstones (a revocation hole) — so the
    second process must be refused loudly at startup. The lock lives on a
    SIDECAR (``<store>.lock``) rather than the store file itself because
    flock binds to the inode and every persist ``os.replace``s the store: a
    lock on the store file would silently evaporate at the first write.

    Returns an open fd the caller must keep alive for the process lifetime
    (or None on a platform with neither fcntl nor msvcrt — best-effort, like
    the client store's advisory lock). Raises OSError when another process
    already holds the lock.
    """
    lock_path = store_path.with_name(store_path.name + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl
        except ImportError:
            fcntl = None  # type: ignore[assignment]
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        try:
            import msvcrt
        except ImportError:
            os.close(fd)
            return None
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return fd
    except OSError:
        os.close(fd)
        raise


# The six store names, also spelled out as dict-literal keys in
# _snapshot_locked and as load() calls in _apply_state_locked -- not
# unified into a single loop there because clients needs a bespoke
# transform (redirect_keys) the other five don't. _snapshot_locked
# instead asserts its dict literal's keys match this tuple, so a future
# 7th store added there but forgotten here fails loudly (in tests) rather
# than silently falling back to last-writer-wins in the merge.
_OAUTH_SNAPSHOT_DICT_KEYS = (
    "clients",
    "codes",
    "access",
    "refresh",
    "consumed_codes",
    "consumed_refresh",
)


_OAUTH_TOMBSTONE_PAIRS = (
    ("refresh", "consumed_refresh"),
    ("codes", "consumed_codes"),
)


def _merge_oauth_snapshots(
    remote: dict[str, Any] | None, local: dict[str, Any]
) -> dict[str, Any]:
    """Union-merge a freshly read Firestore snapshot with the one about to
    be written, for the (genuinely concurrent) case where another writer
    has committed since we last read/wrote this document -- see
    ``_write_firestore_snapshot_locked``, which only calls this when its
    nonce check detects that case; a lone writer instead does a plain
    overwrite so an ordinary local deletion is not resurrected by this
    function at all (#406's original fix mistakenly ran this path
    unconditionally, which broke single-writer semantics -- see the PR
    #429 review that caught it).

    Each of the six stores is merged key-by-key with LOCAL winning on
    collision: local is the freshest view of the keys it owns, since it is
    what triggered this specific write. Every key in these stores is a
    ``secrets.token_*``-derived value, so a cross-instance collision on the
    SAME key is negligible -- in practice this is a conflict-free union of
    each side's additions, not a real merge decision.

    A union alone still can't represent "this side deleted it" -- a key
    the OTHER side removed but this side's local view never learned about
    would otherwise survive. For the two stores that have a tombstone
    (``refresh``/``consumed_refresh``, ``codes``/``consumed_codes``), that
    is fixed here: after the union, any live key that also appears in the
    merged tombstone store is dropped. There is no such tombstone for
    ``access`` or for ``clients``, so a bare (non-tombstoned) removal from
    those -- ``_revoke_family_locked``, cap eviction, client recycling --
    can still be resurrected by a genuinely concurrent writer. That
    residual is deliberately out of scope for this fix; see #428.

    ``remote`` is ``None`` (no document yet) or has a missing/mismatched
    ``version`` is treated as contributing nothing -- an absent or
    incompatible remote document cannot be merged from, so ``local`` wins
    outright.
    """
    if not isinstance(remote, dict) or remote.get("version") != _STATE_VERSION:
        return local
    merged: dict[str, Any] = {**remote, **local}
    for key in _OAUTH_SNAPSHOT_DICT_KEYS:
        remote_store = remote.get(key)
        local_store = local.get(key)
        if not isinstance(remote_store, dict):
            remote_store = {}
        if not isinstance(local_store, dict):
            local_store = {}
        merged[key] = {**remote_store, **local_store}
    for live_key, tomb_key in _OAUTH_TOMBSTONE_PAIRS:
        tombstoned = merged[tomb_key].keys()
        merged[live_key] = {
            k: v for k, v in merged[live_key].items() if k not in tombstoned
        }
    return merged


class _FirestoreReadError(Exception):
    """Raised by _load_state when reading --token-store-firestore's document
    itself fails (network error, permission error, ...) -- as opposed to the
    document genuinely not existing, which is a normal clean-start and NOT
    this. Distinct from a bare RuntimeError so the CLI (serve_main) can
    single it out and abort startup instead of letting __init__ succeed
    into an empty-looking state that persist_now() would then happily
    overwrite the real (merely unread) document with.
    """


class _OAuthProvider:
    """Minimal OAuth 2.1 Authorization Server: DCR + authorization-code + PKCE
    + refresh, with opaque bearer tokens held in memory and optionally
    persisted via --token-store or --token-store-firestore (no crypto
    dependency).

    All stores share one lock; ThreadingHTTPServer serves each request on
    its own thread. ``now`` is injectable so tests can drive TTL expiry without
    sleeping. ``public_url`` (bare origin) pins the issuer; when None the caller
    passes a per-request reflected origin into the metadata builders.
    ``store_path`` (--token-store) optionally persists all state to a 0o600
    JSON file on every mutation so issued tokens survive a restart (#277);
    ``firestore_ref`` (--token-store-firestore, a ``(collection, document)``
    pair) does the same into one Firestore document instead, for a
    deployment with no durable local disk. Exactly one of the two may be
    set; both keep the tokens purely in-memory when None.
    """

    def __init__(
        self,
        *,
        public_url: str | None,
        trusted_user_header: str | None,
        dev_user: str | None,
        access_ttl: float = _DEFAULT_ACCESS_TTL_SECS,
        code_ttl: float = _AUTH_CODE_TTL_SECS,
        refresh_ttl: float = _REFRESH_TTL_SECS,
        allowed_redirect_uris: frozenset[str] = frozenset(),
        now: Any = time.time,
        store_path: Path | None = None,
        firestore_ref: tuple[str, str] | None = None,
    ) -> None:
        self.public_url = public_url
        self.trusted_user_header = trusted_user_header
        self.dev_user = dev_user
        self.access_ttl = access_ttl
        self.code_ttl = code_ttl
        self.refresh_ttl = refresh_ttl
        # Raises ValueError (surfaced by the CLI as a startup parser.error) on a
        # malformed entry -- fail fast on an operator typo rather than accepting
        # a client whose redirect the operator did not actually intend to trust.
        self.allowed_redirect_uris = frozenset(
            _validate_allowed_redirect_uri(u) for u in allowed_redirect_uris
        )
        self._now = now
        self._lock = threading.Lock()
        self._clients: dict[str, dict[str, Any]] = {}
        self._codes: dict[str, dict[str, Any]] = {}
        self._access: dict[str, dict[str, Any]] = {}
        self._refresh: dict[str, dict[str, Any]] = {}
        # Tombstones for replay detection (RFC 6749 Sec. 4.1.2 / RFC 9700
        # Sec. 4.14.2): a consumed authorization code or a rotated refresh token
        # is recorded here (token -> {"family", "expires_at"}) so a later replay
        # is detected and the whole token family it minted is revoked. Both are
        # TTL-bounded (GC'd in _gc_locked) and capped like the live stores.
        self._consumed_codes: dict[str, dict[str, Any]] = {}
        self._consumed_refresh: dict[str, dict[str, Any]] = {}
        # --token-store: when set, every state mutation snapshots the six
        # stores to this JSON file (0o600) so issued tokens, tombstones, and
        # client registrations survive a process restart (issue #277). None
        # keeps the pre-existing in-memory-only behavior.
        self._store_path = store_path
        # --token-store-firestore: same snapshot, written to one Firestore
        # document instead via a read-merge-write transaction (#406, see
        # _write_firestore_snapshot_locked). The CLI enforces store_path/
        # firestore_ref are never both set. No sidecar lock exists for this
        # backend (unlike store_path's _acquire_store_lock) -- concurrent
        # writers are tolerated via the merge, not serialized like
        # store_path's lock.
        self._firestore_ref = firestore_ref
        self._firestore_client: Any = None
        # The write_nonce of the last Firestore document we successfully
        # read or wrote (see _write_firestore_snapshot_locked). None means
        # "no document read yet" or "the read document had none" (a pre-#406
        # document, or none at all) -- either way the next persist cannot
        # assume it knows the current remote state, so it merges once.
        self._known_nonce: str | None = None
        self._warned_persist_failure = False
        # serve_main parks the sidecar-lock fd here so the advisory lock
        # (which guards against two processes sharing one store) stays alive
        # exactly as long as the provider does. Unused in Firestore mode.
        self._store_lock_fd: Any = None
        if store_path is not None or firestore_ref is not None:
            self._load_state()

    def _get_firestore_client(self) -> Any:
        """Lazily create and cache the Firestore client (--token-store-firestore
        only). Imported here, not at module scope, so a plain ``pip install
        mcp-stdio`` never needs google-cloud-firestore on disk — only a
        deployment that actually passes the flag does.
        """
        if self._firestore_client is None:
            try:
                from google.cloud import firestore
            except ImportError as e:
                raise RuntimeError(
                    "--token-store-firestore requires the google-cloud-firestore "
                    "package: pip install mcp-stdio[firestore]"
                ) from e
            self._firestore_client = firestore.Client()
        return self._firestore_client

    def _firestore_document(self) -> Any:
        assert self._firestore_ref is not None
        collection, document = self._firestore_ref
        return self._get_firestore_client().collection(collection).document(document)

    # -- state persistence (--token-store) --------------------------------

    def _load_state(self) -> None:
        """Restore AS state from ``self._store_path`` or ``self._firestore_ref``
        (exactly one is set — the CLI enforces this).

        Called from ``__init__`` only, before the HTTP server threads start,
        so no lock is needed. Defensive by construction: a missing file/
        document is a clean first start; an unreadable/corrupt/unversioned
        one starts empty with a warning (it is replaced on the next
        mutation, mirroring the client token store's overwrite-safe
        recovery); individual malformed or expired entries are dropped,
        never trusted.
        """
        if self._store_path is not None:
            source_label = str(self._store_path)
            data = _read_json_object_file(self._store_path)
            if data is None and self._store_path.exists():
                log(
                    f"warning: OAuth state file {source_label} is unreadable "
                    "or corrupt; starting empty (previously issued tokens "
                    "need a re-auth). It is replaced on the next issuance."
                )
        else:
            assert self._firestore_ref is not None
            source_label = f"{self._firestore_ref[0]}/{self._firestore_ref[1]}"
            try:
                snapshot = self._firestore_document().get()
                data = snapshot.to_dict() if snapshot.exists else None
            except Exception as e:
                # A read FAILURE (network error, permission error, ...) is
                # NOT the same as the document genuinely not existing
                # (snapshot.exists is False, handled above -- a normal
                # clean first start). Silently treating a failure the same
                # as "empty" would be actively dangerous here, unlike the
                # local-file branch above: the CLI's persist_now() call
                # right after construction would then overwrite the real
                # (merely unread) document with that empty snapshot,
                # permanently destroying every previously issued token.
                # Propagate instead, so the CLI aborts startup.
                raise _FirestoreReadError(
                    f"could not read OAuth state from Firestore {source_label}: {e}"
                ) from e
        if data is None:
            return
        if data.get("version") != _STATE_VERSION:
            log(
                f"warning: OAuth state at {source_label} has unsupported "
                f"version {data.get('version')!r}; starting empty."
            )
            return
        self._apply_state_locked(data, source_label, announce=True)
        if self._firestore_ref is not None:
            # Absent on a pre-#429 document -- None, same value a brand new
            # provider starts with, but NOT the same code path: this branch
            # only runs when a document already existed and was loaded, so
            # _write_firestore_snapshot_locked's None-vs-None guard (see its
            # docstring) makes the first persist after this restore take the
            # merge path once (harmless: nothing else has necessarily
            # changed) rather than assuming a plain overwrite is safe.
            self._known_nonce = data.get("write_nonce")

    def _apply_state_locked(
        self, data: dict[str, Any], source_label: str, *, announce: bool
    ) -> None:
        """Parse, validate, and assign the six stores from an already
        version-checked snapshot dict (``data.get("version") ==
        _STATE_VERSION``).

        Shared by two callers: ``_load_state`` (a file/document read at
        startup, no lock held yet -- nothing else can be running) and the
        Firestore merge-adopt path in ``_write_firestore_snapshot_locked``
        (caller holds ``self._lock``), which applies a just-merged document
        containing entries this process never itself shape-checked (written
        by another instance) so it goes through the same validation a fresh
        load would -- a record missing a field would otherwise only surface
        as a crash deep in request handling. ``announce`` silences the
        "restored/dropped" log lines for that second caller, where "loading"
        language doesn't fit and firing on every persist would be noisy.
        """
        now = self._now()
        dropped = 0

        def load(key: str, valid: Any) -> dict[str, dict[str, Any]]:
            nonlocal dropped
            out: dict[str, dict[str, Any]] = {}
            raw = data.get(key)
            if not isinstance(raw, dict):
                return out
            for k, v in raw.items():
                if k and valid(v) and v["expires_at"] >= now:
                    out[k] = v
                else:
                    dropped += 1
            return out

        clients: dict[str, dict[str, Any]] = {}
        raw_clients = data.get("clients")
        if isinstance(raw_clients, dict):
            for cid, rec in raw_clients.items():
                if not (cid and _valid_client_record(rec)):
                    dropped += 1
                    continue
                # redirect_keys are DERIVED state (tuples, not JSON-clean):
                # recompute them from the persisted redirect_uris against the
                # CURRENT allowlist, so an --allow-redirect-uri removed
                # between restarts stops matching immediately instead of
                # surviving via a stale persisted key. A URI that no longer
                # yields a key is skipped; a client left with none is dropped
                # (it could never authorize anyway).
                keys = {
                    key
                    for u in rec["redirect_uris"]
                    if (key := _match_key(u, self.allowed_redirect_uris)) is not None
                }
                if not keys:
                    # Name the client and the reason: this drop is usually an
                    # OPERATOR change (an --allow-redirect-uri entry removed
                    # or forgotten across the restart), not data decay, and
                    # the affected remote client will look "connected with no
                    # tools" — give the operator a breadcrumb that points at
                    # the allowlist instead of a generic dropped-count.
                    if announce:
                        log(
                            f"warning: dropping persisted client registration "
                            f"{cid}: none of its redirect_uris match the "
                            "loopback rule or the current --allow-redirect-uri "
                            "allowlist"
                        )
                    dropped += 1
                    continue
                clients[cid] = {
                    "redirect_keys": keys,
                    "redirect_uris": list(rec["redirect_uris"]),
                    "created_at": rec["created_at"],
                }
        self._clients = clients
        self._codes = load("codes", _valid_code_record)
        self._access = load("access", _valid_grant_record)
        self._refresh = load("refresh", _valid_grant_record)
        self._consumed_codes = load("consumed_codes", _valid_tombstone_record)
        self._consumed_refresh = load("consumed_refresh", _valid_tombstone_record)
        if not announce:
            return
        if dropped:
            log(
                f"note: dropped {dropped} expired or malformed entr"
                f"{'y' if dropped == 1 else 'ies'} while loading {source_label}"
            )
        log(
            f"note: restored OAuth state from {source_label}: "
            f"{len(self._access)} access / {len(self._refresh)} refresh "
            f"token(s), {len(self._clients)} client registration(s)"
        )

    def _snapshot_locked(self) -> dict[str, Any]:
        """The JSON-clean snapshot of all six stores (caller holds the lock)."""
        stores: dict[str, Any] = {
            # redirect_keys are intentionally NOT serialized (derived state,
            # recomputed on load — see _load_state).
            "clients": {
                cid: {
                    "redirect_uris": list(rec["redirect_uris"]),
                    "created_at": rec["created_at"],
                }
                for cid, rec in self._clients.items()
            },
            "codes": self._codes,
            "access": self._access,
            "refresh": self._refresh,
            "consumed_codes": self._consumed_codes,
            "consumed_refresh": self._consumed_refresh,
        }
        # A store added here but forgotten in _OAUTH_SNAPSHOT_DICT_KEYS would
        # silently fall back to last-writer-wins in _merge_oauth_snapshots
        # (which only merges keys it knows to look for) -- catch the drift
        # immediately instead.
        assert set(stores) == set(_OAUTH_SNAPSHOT_DICT_KEYS)
        return {"version": _STATE_VERSION, **stores}

    def _write_snapshot_locked(self) -> None:
        """Write the current snapshot to whichever backend is configured
        (caller holds ``self._lock``). Raises on failure; callers decide
        whether that propagates (``persist_now``) or is soft-failed
        (``_persist_locked``). A no-op when neither backend is set.
        """
        if self._store_path is not None:
            _atomic_write_json_file(self._store_path, self._snapshot_locked())
        elif self._firestore_ref is not None:
            self._write_firestore_snapshot_locked()

    def _write_firestore_snapshot_locked(self) -> None:
        """Write the snapshot to Firestore via a nonce-gated transaction
        (caller holds ``self._lock``) instead of a blind ``.set()`` (#406).

        Two Cloud Run instances can briefly overlap during a revision
        cutover, each with its own in-memory view of the six stores. A blind
        overwrite from whichever instance persists last would silently
        discard whatever the other instance added in that window (e.g. a
        token it issued or rotated).

        A naive fix -- always read-merge-write, unioning the remote
        document into every write -- turned out to be WORSE than the bug it
        fixed (caught by PR #429 review): a union cannot represent a
        deletion, so even a LONE writer's own rotation/redemption of a
        token would be resurrected by its own next persist, reading back
        its own pre-mutation document. That defeated RFC 9700 / RFC 6749
        replay detection on every restart, with no concurrency required.

        The fix is to merge ONLY when a merge is actually needed. Every
        snapshot this method writes carries a fresh ``write_nonce``, and
        ``self._known_nonce`` tracks the nonce of the document we last
        read or wrote. Inside the transaction: if the document does not
        exist yet, or its nonce still matches ``self._known_nonce``, no
        other writer has committed since we last saw this document -- our
        local snapshot is a complete, authoritative replacement, so it is
        written as a plain overwrite (identical to pre-#406 behavior,
        deletions included). Only when the nonce has moved does another
        writer's document need to be merged with ours, via
        :func:`_merge_oauth_snapshots` (union per store, local wins on key
        collision, tombstone-aware for the two stores that have one -- see
        that function for exactly what it does and does not cover). When
        that happens, the merged document -- which is richer than our own
        local snapshot -- is also ADOPTED into local state (via
        :meth:`_apply_state_locked`) before returning. Without that, the
        very next persist would see its own nonce match, take the plain-
        overwrite fast path with a local snapshot narrower than what is
        actually in Firestore, and silently re-discard everything the
        merge just pulled in.

        The full read-then-commit transaction runs under ``self._lock``,
        not just a single round trip: on contention Firestore aborts and
        the client SDK retries the whole read+commit internally (bounded by
        its default retry count, with backoff between attempts), so lock
        hold time can multiply under contention, not just add one extra
        round trip over the prior blind ``.set()``. That is a latency cost
        under real write contention -- every other AS request blocks for
        the duration -- not a new correctness risk, and it is scoped to
        exactly the brief overlap window this fix targets.
        """
        from google.cloud import firestore

        doc_ref = self._firestore_document()
        local_snapshot = self._snapshot_locked()
        known_nonce = self._known_nonce

        @firestore.transactional
        def _run(transaction: Any) -> tuple[str, dict[str, Any] | None]:
            remote_doc = doc_ref.get(transaction=transaction)
            remote = remote_doc.to_dict() if remote_doc.exists else None
            adopt: dict[str, Any] | None = None
            # known_nonce is None both when no document has ever been read
            # (remote is None, handled separately below) and when the last
            # document read/written had no write_nonce field at all -- an
            # old-code (pre-#429) writer never sets one. Those two None
            # sources must NOT be treated as matching each other: comparing
            # None == None here would wrongly treat "some other, still
            # nonce-less writer just overwrote the document" the same as
            # "confirmed nobody has written since we last saw this exact
            # document" -- silently clobbering that other writer, exactly
            # the bug this file exists to fix. Only a concrete matching
            # nonce string proves that.
            if remote is None or (
                known_nonce is not None and remote.get("write_nonce") == known_nonce
            ):
                written = dict(local_snapshot)
            else:
                written = _merge_oauth_snapshots(remote, local_snapshot)
                adopt = written
            nonce = secrets.token_hex(8)
            written["write_nonce"] = nonce
            transaction.set(doc_ref, written)
            return nonce, adopt

        # The return value, not a nonlocal, carries the result out: the SDK
        # retries _run from scratch on contention, so only the final
        # successful attempt's plain-vs-merge decision may be applied. An
        # exception here (retries exhausted, or another failure) propagates
        # before this line, same as the pre-#406 blind .set() -- a failed
        # write must not advance what we believe is "known" about the
        # remote document, nor adopt a document that was never written.
        nonce, adopt = _run(self._get_firestore_client().transaction())
        self._known_nonce = nonce
        if adopt is not None:
            self._apply_state_locked(adopt, "<Firestore merge>", announce=False)

    def persist_now(self) -> None:
        """Write the current state immediately, PROPAGATING any failure.

        Called once at startup (after the restore) so a misconfigured
        --token-store / --token-store-firestore — an unwritable path, an
        existing directory, an empty-basename path like ``.``, a missing
        google-cloud-firestore package, an unreachable project — fails fast
        at launch instead of degrading silently to in-memory-only at the
        first token issuance while the startup log claims persistence is on.
        """
        with self._lock:
            self._write_snapshot_locked()

    def _persist_locked(self) -> None:
        """Snapshot all six stores to the configured backend (caller holds
        ``self._lock``, which makes the snapshot point-in-time consistent and
        serializes concurrent writers).

        Failure is soft: the AS keeps serving from memory — availability over
        durability — with a one-shot warning so the operator knows
        restart-survival is off. Writes happen only on state mutations
        (issuance, rotation, revocation, registration), never on the
        read-heavy validation path.
        """
        if self._store_path is None and self._firestore_ref is None:
            return
        try:
            self._write_snapshot_locked()
        except Exception as e:
            if not self._warned_persist_failure:
                self._warned_persist_failure = True
                target = (
                    self._store_path
                    if self._store_path is not None
                    else f"{self._firestore_ref[0]}/{self._firestore_ref[1]}"  # type: ignore[index]
                )
                log(
                    f"warning: could not persist OAuth state to "
                    f"{target}: {e}; continuing in-memory only "
                    "(issued tokens will not survive a restart)"
                )

    # -- metadata --------------------------------------------------------

    def metadata(self, issuer: str) -> dict[str, Any]:
        md: dict[str, Any] = {
            "issuer": issuer,
            "authorization_endpoint": issuer + _AUTHORIZE_PATH,
            "token_endpoint": issuer + _TOKEN_PATH,
            "registration_endpoint": issuer + _REGISTER_PATH,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        }
        # RFC 9207 Sec. 2.3: advertise iss support only when we actually emit it
        # — i.e. for an https issuer, since Sec. 2 requires the iss value to be an
        # https URL. A loopback http dev issuer neither advertises the flag nor
        # sends iss (see authorize()), keeping the two consistent.
        if issuer.startswith("https://"):
            md["authorization_response_iss_parameter_supported"] = True
        return md

    # -- dynamic client registration (RFC 7591) --------------------------

    def register(self, raw: bytes) -> tuple[int, dict[str, Any]]:
        def bad(desc: str) -> tuple[int, dict[str, Any]]:
            return 400, {"error": "invalid_client_metadata", "error_description": desc}

        def bad_redirect(desc: str) -> tuple[int, dict[str, Any]]:
            # RFC 7591 Sec. 3.2.2 defines a dedicated error code for an invalid
            # redirection URI value; prefer it over the generic metadata error.
            return 400, {"error": "invalid_redirect_uri", "error_description": desc}

        _redirect_err = "redirect_uris must be loopback http URLs" + (
            " or an operator-allowlisted https URL"
            if self.allowed_redirect_uris
            else ""
        )

        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return bad("body must be JSON")
        if not isinstance(body, dict):
            return bad("body must be a JSON object")
        uris = body.get("redirect_uris")
        # RFC 7591 Sec. 3.2.2: a missing / empty / non-array redirect_uris is a
        # STRUCTURAL metadata error (invalid_client_metadata). invalid_redirect_uri
        # is reserved for the case where a present VALUE is invalid (the loopback
        # check below).
        if not isinstance(uris, list) or not uris:
            return bad("redirect_uris must be a non-empty array")
        keys = set()
        for u in uris:
            key = (
                _match_key(u, self.allowed_redirect_uris)
                if isinstance(u, str)
                else None
            )
            if key is None:
                # Surface the rejected value so an operator can see exactly what to
                # allowlist. Without this the client only gets an opaque 400 and the
                # server logs a bare status line, leaving the offending redirect_uri
                # invisible (#286). It is client-proposed and non-secret.
                log(
                    f"warning: rejected DCR redirect_uri {_log_safe_uri(u)}: "
                    "not an RFC 8252 loopback URI and not in the "
                    "--allow-redirect-uri allowlist"
                )
                return bad_redirect(_redirect_err)
            keys.add(key)
        client_id = secrets.token_urlsafe(32)
        now = self._now()
        with self._lock:
            self._recycle_clients_locked()
            if len(self._clients) >= _CLIENT_CAP:
                return bad("registration limit reached")
            self._clients[client_id] = {
                "redirect_keys": keys,
                "redirect_uris": list(uris),
                "created_at": now,
            }
            self._persist_locked()
        return 201, {
            "client_id": client_id,
            "redirect_uris": list(uris),
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_id_issued_at": int(now),
        }

    # -- authorization endpoint (RFC 6749 4.1 + RFC 7636) ----------------

    def authorize(
        self, params: dict[str, str], user: str | None, issuer: str
    ) -> dict[str, str]:
        """Return an instruction dict for the handler.

        ``{"kind": "bad_request", "message": ...}`` -> direct 400 (NO redirect,
        per RFC 6749 4.1.2.1 for client_id/redirect_uri errors).
        ``{"kind": "redirect", "location": ...}`` -> 302 (success, or an in-band
        error whose Location carries error= + the echoed state).

        ``issuer`` is the effective AS issuer; an https issuer is echoed back as
        the RFC 9207 ``iss`` parameter on every redirect (mix-up defence).
        """
        cid = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        with self._lock:
            client = self._clients.get(cid)
        if not cid or client is None:
            return {"kind": "bad_request", "message": "unknown or missing client_id"}
        rk = _match_key(redirect_uri, self.allowed_redirect_uris)
        if rk is None or rk not in client["redirect_keys"]:
            # Same diagnostic as register() for the /authorize path (#286): the
            # redirect_uri is not registered for this client or no longer matches
            # the allowlist. Value is client-proposed and non-secret.
            log(
                f"warning: rejected authorize redirect_uri {_log_safe_uri(redirect_uri)} "
                f"for client {cid[:8]}...: not registered for this client or not in "
                "the --allow-redirect-uri allowlist"
            )
            return {"kind": "bad_request", "message": "invalid redirect_uri"}

        state = params.get("state", "")

        def redirect(query: dict[str, str]) -> dict[str, str]:
            if state:
                query = {**query, "state": state}
            # RFC 9207 Sec. 2: include the issuer identifier in BOTH success and
            # error authorization responses so a client talking to multiple ASes
            # can detect a mix-up attack. Sec. 2 requires an https value, so a
            # loopback http dev issuer is left without iss (and metadata() omits
            # the support flag to match). Placed after state so a hostile state
            # cannot shadow it (urlencode emits both verbatim regardless).
            if issuer.startswith("https://"):
                query = {**query, "iss": issuer}
            return {
                "kind": "redirect",
                "location": redirect_uri + "?" + urlencode(query),
            }

        if params.get("response_type") != "code":
            return redirect({"error": "unsupported_response_type"})
        challenge = params.get("code_challenge", "")
        if not challenge:
            return redirect(
                {
                    "error": "invalid_request",
                    "error_description": "code_challenge required",
                }
            )
        if params.get("code_challenge_method") != "S256":
            return redirect(
                {
                    "error": "invalid_request",
                    "error_description": "code_challenge_method must be S256",
                }
            )
        if not user:
            # Fail closed: never mint a code for an empty/anonymous user.
            return redirect(
                {"error": "access_denied", "error_description": "no authenticated user"}
            )
        code = secrets.token_urlsafe(32)
        now = self._now()
        with self._lock:
            if len(self._codes) >= _STORE_CAP:
                self._gc_locked()
                self._evict_to_capacity_locked(self._codes, _STORE_CAP)
            self._codes[code] = {
                "client_id": cid,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "user": user,
                "scope": params.get("scope", ""),
                "resource": params.get("resource"),
                "expires_at": now + self.code_ttl,
            }
            self._persist_locked()
        return redirect({"code": code})

    # -- token endpoint (RFC 6749 + RFC 7636) ----------------------------

    def token(self, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
        grant = form.get("grant_type")
        if grant == "authorization_code":
            return self._token_auth_code(form)
        if grant == "refresh_token":
            return self._token_refresh(form)
        if not grant:
            # RFC 6749 Sec. 5.2: a missing required parameter is invalid_request,
            # not unsupported_grant_type (which is for an unrecognized value).
            return 400, {
                "error": "invalid_request",
                "error_description": "missing grant_type",
            }
        return 400, {"error": "unsupported_grant_type"}

    def _token_auth_code(self, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
        code = form.get("code", "")
        if not code:
            return 400, {
                "error": "invalid_request",
                "error_description": "missing code",
            }
        now = self._now()
        with self._lock:
            # Single-use: POP before validating so a replay / concurrent
            # double-POST sees None and cannot mint a second token.
            entry = self._codes.pop(code, None)
            replay_family: str | None = None
            replay_detected = False
            if entry is None:
                # RFC 6749 Sec. 4.1.2: a code used more than once MUST be denied
                # AND SHOULD revoke the tokens previously issued from it. A live
                # tombstone (set on successful issuance below) marks a real
                # reuse; outside the grace window it is a theft signal and we
                # revoke the family. Within the window it is a benign retry /
                # concurrent double-submit, so deny without revoking (falls
                # through to the plain denial). A code that never issued a token
                # (failed validation) leaves no tombstone — plain denial too.
                tomb = self._consumed_codes.get(code)
                if (
                    tomb is not None
                    and tomb["expires_at"] >= now
                    and now - tomb["consumed_at"] > _REUSE_GRACE_SECS
                ):
                    replay_detected = True
                    replay_family = tomb["family"]
                    self._revoke_family_locked(replay_family)
            if entry is not None or replay_detected:
                # The pop consumed a live code, and/or the replay revoked a
                # family — both must reach the store so a crash right after
                # this block cannot resurrect the consumed code (single-use
                # would otherwise not survive a restart).
                self._persist_locked()
        if entry is None:
            if replay_detected:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "authorization code already used; issued tokens revoked",
                }
            return 400, {
                "error": "invalid_grant",
                "error_description": "unknown or used code",
            }
        if entry["expires_at"] < now:
            return 400, {"error": "invalid_grant", "error_description": "code expired"}
        if form.get("client_id") != entry["client_id"]:
            return 400, {
                "error": "invalid_grant",
                "error_description": "client_id mismatch",
            }
        if form.get("redirect_uri") != entry["redirect_uri"]:
            return 400, {
                "error": "invalid_grant",
                "error_description": "redirect_uri mismatch",
            }
        verifier = form.get("code_verifier", "")
        if not _valid_code_verifier(verifier):
            return 400, {
                "error": "invalid_request",
                "error_description": "invalid code_verifier",
            }
        if not hmac.compare_digest(
            _pkce_s256_challenge(verifier), entry["code_challenge"]
        ):
            return 400, {
                "error": "invalid_grant",
                "error_description": "PKCE verification failed",
            }
        # Start a new grant family keyed by the code; tombstone the code under
        # the issue lock so a subsequent replay is detected and revoked.
        return self._issue(
            entry["user"],
            entry["client_id"],
            entry["scope"],
            entry["resource"],
            family=code,
            consumed_code=code,
        )

    def _token_refresh(self, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
        rt = form.get("refresh_token", "")
        if not rt:
            return 400, {
                "error": "invalid_request",
                "error_description": "missing refresh_token",
            }
        now = self._now()
        with self._lock:
            # Validate BEFORE mutating: only consume (rotate) the token once it
            # passes. A wrong/blank client_id must NOT destroy an otherwise-valid
            # 30-day token. Single-use still holds because the successful delete
            # happens under this same lock, so a concurrent double-submit of the
            # same valid token finds None on the second pass.
            entry = self._refresh.get(rt)
            if entry is None:
                # RFC 9700 Sec. 4.14.2: a replay of an already-rotated refresh
                # token OUTSIDE the grace window is a theft signal — revoke the
                # whole family so the attacker AND the racing legitimate client
                # are both cut off (the client re-runs the flow). WITHIN the
                # window it is a benign retry / concurrent double-submit: deny
                # without revoking so the winner's freshly-rotated tokens
                # survive. A token that never existed stays a plain "unknown".
                tomb = self._consumed_refresh.get(rt)
                if tomb is not None and tomb["expires_at"] >= now:
                    if now - tomb["consumed_at"] > _REUSE_GRACE_SECS:
                        self._revoke_family_locked(tomb["family"])
                        self._persist_locked()
                        return 400, {
                            "error": "invalid_grant",
                            "error_description": "refresh token reuse detected; token family revoked",
                        }
                    return 400, {
                        "error": "invalid_grant",
                        "error_description": "refresh_token already rotated",
                    }
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "unknown refresh_token",
                }
            if entry["expires_at"] < now:
                del self._refresh[rt]
                self._persist_locked()
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "refresh_token expired",
                }
            if form.get("client_id") != entry["client_id"]:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "client_id mismatch",
                }
            family = entry.get("family")
            # Rotate: tombstone the spent token (instead of a plain delete) so a
            # later replay of THIS value is detected as reuse above.
            del self._refresh[rt]
            self._consumed_refresh[rt] = {
                "family": family,
                "consumed_at": now,
                "expires_at": now + self.refresh_ttl,
            }
            # Persist the rotation before minting: a crash between this block
            # and _issue must leave the spent token tombstoned on disk, not
            # replayable after a restart.
            self._persist_locked()
        return self._issue(
            entry["user"],
            entry["client_id"],
            entry["scope"],
            entry["resource"],
            family=family,
        )

    def _issue(
        self,
        user: str,
        client_id: str,
        scope: str,
        resource: str | None,
        *,
        family: str | None = None,
        consumed_code: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Mint an access + refresh token pair.

        ``family`` tags both tokens so a later replay of the authorization code
        or a rotated refresh token can revoke the entire grant (see
        _revoke_family_locked). ``consumed_code``, when set, tombstones the
        just-spent authorization code under the same lock so a replay is
        detectable without a separate critical section.
        """
        now = self._now()
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        with self._lock:
            stores = (
                self._access,
                self._refresh,
                self._consumed_codes,
                self._consumed_refresh,
            )
            if any(len(s) >= _STORE_CAP for s in stores):
                self._gc_locked()
                for s in stores:
                    self._evict_to_capacity_locked(s, _STORE_CAP)
            self._access[access] = {
                "user": user,
                "client_id": client_id,
                "scope": scope,
                "resource": resource,
                "family": family,
                "expires_at": now + self.access_ttl,
            }
            self._refresh[refresh] = {
                "user": user,
                "client_id": client_id,
                "scope": scope,
                "resource": resource,
                "family": family,
                "expires_at": now + self.refresh_ttl,
            }
            if consumed_code is not None:
                self._consumed_codes[consumed_code] = {
                    "family": family,
                    "consumed_at": now,
                    "expires_at": now + self.refresh_ttl,
                }
            self._persist_locked()
        body: dict[str, Any] = {
            "access_token": access,
            "token_type": "Bearer",
            # Positive finite int strictly below the server TTL.
            "expires_in": max(1, int(self.access_ttl) - 1),
            "refresh_token": refresh,
        }
        if scope:
            body["scope"] = scope
        return 200, body

    # -- resource-server validation --------------------------------------

    def _live_entry(
        self, token: str, expected_resource: str | None
    ) -> dict[str, Any] | None:
        """The live access-token entry for this resource, or None.

        Encapsulates the lookup + expiry purge + RFC 8707 / MCP audience check
        shared by :meth:`validate_access_token` and :meth:`user_for_token`:
        when the token was minted for a specific ``resource`` and the caller
        passes the resource it is guarding, the two MUST match — a token issued
        for a different audience is rejected even though it is otherwise live. A
        token with no resource binding (``None``) stays accepted (lenient), as
        does a call that does not supply an expected resource.
        """
        if not token:
            return None
        now = self._now()
        with self._lock:
            entry = self._access.get(token)
            if entry is None:
                return None
            if entry["expires_at"] < now:
                del self._access[token]
                return None
            tok_resource = entry.get("resource")
            if (
                tok_resource is not None
                and expected_resource is not None
                and tok_resource.rstrip("/") != expected_resource.rstrip("/")
            ):
                return None
            return entry

    def validate_access_token(
        self, token: str, expected_resource: str | None = None
    ) -> bool:
        """True if ``token`` is a live issued access token for this resource."""
        return self._live_entry(token, expected_resource) is not None

    def user_for_token(
        self, token: str, expected_resource: str | None = None
    ) -> str | None:
        """The authenticated user bound to a live access token, else None.

        Same liveness + audience checks as :meth:`validate_access_token`, but
        returns the token's user (for per-session ownership) rather than a bool.
        """
        entry = self._live_entry(token, expected_resource)
        return entry.get("user") if entry is not None else None

    def _evict_to_capacity_locked(
        self, store: dict[str, dict[str, Any]], cap: int
    ) -> None:
        """Hard-bound a TTL store: if still at the cap after GC, evict the
        soonest-expiring entries to make room. GC alone frees nothing when every
        entry is still live, so without this the cap is not a real bound."""
        overflow = len(store) - (cap - 1)
        if overflow <= 0:
            return
        victims = sorted(store.items(), key=lambda kv: kv[1]["expires_at"])
        for k, _ in victims[:overflow]:
            del store[k]

    def _gc_locked(self) -> None:
        now = self._now()
        for store in (
            self._codes,
            self._access,
            self._refresh,
            self._consumed_codes,
            self._consumed_refresh,
        ):
            for k in [k for k, v in store.items() if v["expires_at"] < now]:
                del store[k]

    def _revoke_family_locked(self, family: str | None) -> None:
        """Revoke every live access/refresh token in a grant family.

        Called on a detected authorization-code or refresh-token replay
        (RFC 6749 Sec. 4.1.2 / RFC 9700 Sec. 4.14.2). A ``None`` family (a token
        minted before family tagging, or a code that never issued a token) is a
        no-op. The caller already holds ``self._lock``.
        """
        if family is None:
            return
        for store in (self._access, self._refresh):
            for k in [k for k, v in store.items() if v.get("family") == family]:
                del store[k]

    def _recycle_clients_locked(self) -> None:
        # Clients carry no TTL: recycle the oldest at the cap so /register never
        # permanently bricks (evict down to cap-1 to leave room for one insert).
        # Called ONLY from register() so token-issuance GC never evicts a client
        # that is not under registration pressure.
        if len(self._clients) >= _CLIENT_CAP:
            oldest = sorted(self._clients.items(), key=lambda kv: kv[1]["created_at"])
            for k, _ in oldest[: len(self._clients) - (_CLIENT_CAP - 1)]:
                del self._clients[k]


class _Handler(BaseHTTPRequestHandler):
    """Streamable HTTP MCP endpoint backed by a per-session stdio child.

    Class attributes ``registry`` and ``mcp_path`` are bound by
    :func:`build_server` before the server loop starts. The session id for the
    request in flight is held in the per-request instance attribute
    ``_session_id`` (reset at the top of each verb handler), so response
    helpers can echo it — or omit it for errors raised before a session is
    resolved.
    """

    registry: SessionRegistry
    mcp_path: str
    # None disables authentication. A non-None value enables the
    # static-bearer-token Resource Server gate.
    auth_token: str | None = None
    # None disables the embedded OAuth AS. A provider enables it:
    # /authorize /token /register + AS metadata + issued-token RS validation.
    oauth: _OAuthProvider | None = None

    # Quieter, consistent logging: route BaseHTTPRequestHandler's access log
    # through the project logger instead of stderr's default apache-style line.
    def log_message(self, fmt: str, *args: Any) -> None:
        # Redact query strings (OAuth state / code never belong in shared logs).
        log("http: " + _redact_query(fmt % args))

    protocol_version = "HTTP/1.1"

    def _send_json(
        self, status: int, body: str, *, extra_headers: dict[str, str] | None = None
    ) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        # Only `--modern-only`'s 405s pass anything here, and RFC 9110
        # §15.5.6 makes one of them mandatory: "the origin server MUST
        # generate an Allow header field in a 405 response".
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        sid = getattr(self, "_session_id", None)
        if sid is not None:
            self.send_header("Mcp-Session-Id", sid)
        self.end_headers()
        self.wfile.write(data)

    def _send_empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        sid = getattr(self, "_session_id", None)
        if sid is not None:
            self.send_header("Mcp-Session-Id", sid)
        self.end_headers()

    def _send_oauth_json(
        self, status: int, body: str, *, no_store: bool = False
    ) -> None:
        """JSON response for OAuth endpoints (no Mcp-Session-Id header).

        ``no_store`` adds the RFC 6749 Sec. 5.1/5.2 cache headers required on
        token-endpoint responses.
        """
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if no_store:
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _effective_issuer(self) -> str:
        """The pinned --public-url origin, else the (reflected) request origin.

        Drives the AS metadata issuer + endpoint URLs and the PRM
        authorization_servers/resource so all three are byte-stable per request.
        """
        if self.oauth is not None and self.oauth.public_url:
            return self.oauth.public_url
        return self._origin()

    def _issuer_origin_and_prefix(self) -> tuple[str, str]:
        """Split the effective issuer into (bare origin, path prefix).

        The prefix is ``""`` for a bare-origin issuer (the legacy behavior and
        the reflected-Host fallback) and e.g. ``"/team-a"`` for a path-scoped
        ``--public-url``. It drives the root-inserted well-known locations and
        the prefixed AS endpoint / MCP paths so a path-scoped issuer is
        byte-symmetric with the bundled client's RFC 8414 Sec. 3.1 / RFC 9728
        Sec. 3.1 construction (#245). The path prefix can only come from a pinned
        ``--public-url``; the reflected ``_origin()`` never carries one.
        """
        parsed = urlsplit(self._effective_issuer())
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return origin, parsed.path

    def _mcp_wire_path(self) -> str:
        """The on-the-wire MCP path: the issuer prefix + the configured path.

        Behind a path-multiplexing proxy the backend receives the full prefixed
        path (e.g. ``/team-a/mcp``); a bare-origin issuer leaves it ``/mcp``.
        """
        _, prefix = self._issuer_origin_and_prefix()
        return prefix + self.mcp_path

    def _wrong_path(self) -> bool:
        # Compare only the path component; ignore any query string.
        path = self.path.split("?", 1)[0]
        if path != self._mcp_wire_path():
            self._send_json(404, _error_body("not found"))
            return True
        return False

    # --- static-bearer-token Resource Server + RFC 9728 metadata ---

    def _origin(self) -> str:
        """Absolute ``scheme://host`` for building metadata URLs.

        Honors a fronting reverse proxy via ``X-Forwarded-Proto`` /
        ``X-Forwarded-Host`` (the gateway is designed to run behind one), then
        the ``Host`` header, then the bound socket. The host is sanitized so a
        hostile value cannot inject into the quoted challenge / JSON body.
        """
        proto = self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
        if proto not in ("http", "https"):
            proto = "http"
        host = self.headers.get("X-Forwarded-Host", "").split(",")[0].strip()
        if not host:
            host = self.headers.get("Host", "").strip()
        host = _sanitize_host(host)
        if not host:
            addr = self.server.server_address
            host = f"{addr[0]}:{addr[1]}"
        return f"{proto}://{host}"

    def _resource_url(self) -> str:
        return self._effective_issuer() + self.mcp_path

    def _prm_url(self) -> str:
        # RFC 9728 Sec. 3.1 path insertion: the well-known label is inserted
        # between the host and the resource's FULL path (issuer prefix +
        # mcp_path), so a path-scoped issuer yields e.g.
        # https://host/.well-known/oauth-protected-resource/team-a/mcp — byte-
        # symmetric with the client's _build_well_known_url. For a bare-origin
        # issuer (prefix "") this is identical to the legacy form. The 401 hint,
        # the PRM document, and the AS metadata thus all stay consistent (#245).
        origin, prefix = self._issuer_origin_and_prefix()
        return origin + _PRM_WELL_KNOWN_PREFIX + prefix + self.mcp_path

    def _authorized(self) -> bool:
        """True when no auth is configured, or a valid Bearer token is presented.

        Precedence: the static token is checked first (constant-time, exempt
        from expiry), then an issued access token (lookup + expiry). The
        endpoint is open only when NEITHER mechanism is configured.

        Captures the authenticated principal on ``self._principal`` for session
        ownership (:meth:`_current_user`): the shared :data:`_STATIC_PRINCIPAL`
        for a static-token request, the OAuth user for an issued token, or None
        for an open (no-auth) gateway. Deriving it HERE — once, from the same
        lookup the gate decides on — keeps the binding from ever disagreeing
        with the gate (no second resolve that could expire in between).
        """
        self._principal = None
        auth = self.headers.get("Authorization", "")
        prefix = "Bearer "
        token = auth[len(prefix) :] if auth.startswith(prefix) else ""
        if (
            self.auth_token is not None
            and token
            and hmac.compare_digest(
                token.encode("utf-8"), self.auth_token.encode("utf-8")
            )
        ):
            self._principal = _STATIC_PRINCIPAL
            return True
        if self.oauth is not None and token:
            # A valid issued token always carries a non-empty user (authorize
            # fails closed on an empty user), so user-presence == validity here;
            # if it were ever absent, treating it as unauthorized fails closed.
            user = self.oauth.user_for_token(token, self._resource_url())
            if user is not None:
                self._principal = user
                return True
        return self.auth_token is None and self.oauth is None

    def _require_auth(self) -> bool:
        """Return True if the request may proceed; else send 401 and return False."""
        if self._authorized():
            return True
        # RFC 6750 Sec. 3 / 3.1: when the request CARRIED a bearer token that
        # failed validation (wrong, expired, revoked, or wrong audience), the
        # challenge SHOULD carry error="invalid_token". When NO token was
        # presented, omit the error attribute — the bare challenge is how the
        # client discovers how to authenticate (adding error there would be a
        # spec violation). RFC 9728 Sec. 5.1: always include the
        # resource_metadata pointer.
        token_presented = self.headers.get("Authorization", "").startswith("Bearer ")
        params = []
        if token_presented:
            params.append('error="invalid_token"')
            params.append(
                'error_description="the access token is expired, revoked, malformed, '
                'or issued for another resource"'
            )
        params.append(f'resource_metadata="{self._prm_url()}"')
        challenge = "Bearer " + ", ".join(params)
        msg = "invalid access token" if token_presented else "authentication required"
        body = _error_body(msg).encode("utf-8")
        self.send_response(401)
        self.send_header("WWW-Authenticate", challenge)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def _serve_prm(self) -> None:
        """Serve RFC 9728 Protected Resource Metadata when any auth is enabled.

        ``authorization_servers`` is added ONLY when the embedded AS is on;
        a static-token-only deployment omits it.
        """
        if self.auth_token is None and self.oauth is None:
            self._send_json(404, _error_body("not found"))
            return
        body: dict[str, Any] = {"resource": self._resource_url()}
        if self.oauth is not None:
            body["authorization_servers"] = [self._effective_issuer()]
        body["bearer_methods_supported"] = ["header"]
        self._send_json(200, json.dumps(body))

    # --- embedded OAuth AS endpoint handlers ---

    def _serve_as_metadata(self) -> None:
        """RFC 8414 Authorization Server Metadata."""
        self._send_oauth_json(
            200, json.dumps(self.oauth.metadata(self._effective_issuer()))
        )

    def _resolve_user(self) -> str | None:
        """Identify the end user for /authorize. Fails closed.

        Reads the operator-opted-in trusted header (set by a fronting proxy that
        performed the real login), else falls back to --dev-user. With neither,
        returns None and /authorize denies — never an anonymous user. The header
        is trusted ONLY when --trusted-user-header is explicitly configured.
        """
        prov = self.oauth
        if prov.trusted_user_header:
            val = self.headers.get(prov.trusted_user_header, "")
            val = val.strip()
            if val and "\r" not in val and "\n" not in val and len(val) <= 256:
                return val
        return prov.dev_user or None

    def _handle_register(self, raw: bytes) -> None:
        status, body = self.oauth.register(raw)
        # RFC 7591 Sec. 3.2.1's response example carries Cache-Control: no-store;
        # send it for symmetry with the token endpoint (and in case a future
        # registration response ever carries a credential).
        self._send_oauth_json(status, json.dumps(body), no_store=True)

    def _handle_token(self, raw: bytes) -> None:
        try:
            parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            form = {k: v[0] for k, v in parsed.items()}
        except (UnicodeDecodeError, ValueError):
            self._send_oauth_json(
                400, json.dumps({"error": "invalid_request"}), no_store=True
            )
            return
        status, body = self.oauth.token(form)
        self._send_oauth_json(status, json.dumps(body), no_store=True)

    def _handle_authorize(self) -> None:
        query = urlsplit(self.path).query
        parsed = parse_qs(query, keep_blank_values=True)
        params = {k: v[0] for k, v in parsed.items()}
        user = self._resolve_user()
        result = self.oauth.authorize(params, user, self._effective_issuer())
        if result["kind"] == "bad_request":
            self._send_oauth_json(
                400,
                json.dumps(
                    {"error": "invalid_request", "error_description": result["message"]}
                ),
            )
            return
        # 302 to the validated redirect_uri (Location built via urlencode and a
        # CR/LF-free, registered redirect_uri -- loopback per _redirect_key(),
        # or an operator-allowlisted exact HTTPS match per _match_key() -- no
        # injection surface either way).
        self.send_response(302)
        self.send_header("Location", result["location"])
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _current_user(self) -> str | None:
        """The authenticated principal for this request, captured by the auth
        gate (:meth:`_authorized`): the shared static-token principal, an OAuth
        user, or None for an open gateway. Must be called after ``_require_auth``.
        """
        return getattr(self, "_principal", None)

    def _resolve_session(
        self, user: str | None = None, req_id: Any = None
    ) -> BackendProcess | None:
        """Resolve the request's session, or emit the spec error and return None.

        A missing ``Mcp-Session-Id`` -> 400 (MCP spec item 2); an unknown or
        terminated id — or one bound to a different ``user`` — -> 404 (item 3,
        which drives the client's re-initialize). On success records the id for
        the response header and returns the backend. Shared by the POST
        (non-initialize) and GET paths so both report the same status for the
        same condition.
        """
        sid = self.headers.get("Mcp-Session-Id")
        if not sid:
            self._send_json(400, _error_body("Mcp-Session-Id required", req_id))
            return None
        backend = self.registry.get(sid, user)
        if backend is None:
            self._send_json(404, _error_body("unknown or expired session", req_id))
            return None
        # registry.get() only returns non-None for an exact match against a
        # key SessionRegistry itself minted via secrets.token_hex(16), so sid
        # is provably clean (32 hex chars) by this point -- a CRLF-bearing
        # value 404s above and never reaches send_header (CodeQL alerts #7/#15,
        # dismissed as false positives).
        self._session_id = sid
        return backend

    def _serve_listen_stream(
        self,
        msg: dict[str, Any],
        req_id: Any,
        backend: BackendProcess,
        init_result: dict[str, Any],
    ) -> None:
        """Answer `subscriptions/listen` with a long-lived SSE stream (#374).

        Serve owns this method — it is never forwarded, the same posture
        `server/discover` takes, and it replaces the carve-out that used
        to let a legacy child answer `-32601` and turn it into a 404.

        SCOPE: the listChanged trio (#374) plus `resourceSubscriptions`
        (#381). The fourth field is honored only when the child
        ADVERTISES `resources.subscribe` — otherwise it is omitted from
        the ack entirely, which is spec-legal ("Notification types the
        server does not support are omitted") and honest, since serve
        would have nothing to drive the subscription against. Omitted,
        never echoed as `[]`: an empty list would claim the feature works
        and then deliver nothing.

        Order is the contract. Attach BEFORE the ack, so an event
        published while the ack write is in flight is buffered rather
        than lost; then the ack as the FIRST frame — "The server MUST
        send `notifications/subscriptions/acknowledged` as the first
        message ... and MUST NOT send any notification on the
        subscription before it."

        The honored subset is echoed at exactly `params.notifications`
        and the id at exactly `params._meta[subscriptionId]`. That
        nesting is load-bearing in both directions: a top-level echo is
        silently ignored by a compliant client, which then forwards
        nothing and reports no error. The `notifications` key is emitted
        even when empty — the v2 client reads a missing one as malformed
        and discards the whole ack.

        All three requested booleans are honored unconditionally. A
        subscription that never fires is still honored, and narrowing the
        echo to what the child advertises would make a compliant peer
        suppress events that do in fact arrive.

        URIs are honored the same way once the capability gate passes:
        all of them, up to a cap, with no per-URI accept/reject — there
        is no servability probe to base one on, and the reference
        implementation has none. The ENTIRE honored decision is local,
        which is what lets the ack go out before anything is driven
        against the child (§3.3).
        """
        # Filter shape. Absent means "subscribed to nothing", which is a
        # valid ack; present-but-not-an-object is malformed and rejected
        # BEFORE the stream is committed, as a single JSON error.
        params = msg.get("params")
        requested = params.get("notifications") if isinstance(params, dict) else None
        if requested is None:
            requested = {}
        if not isinstance(requested, dict):
            self._send_json(
                400,
                _error_body(
                    "params.notifications must be an object",
                    req_id,
                    code=_JSONRPC_INVALID_PARAMS,
                ),
            )
            return

        # The success path is an SSE stream, so a client that cannot
        # accept one gets 406 rather than a stream it will not read.
        # MEDIA-RANGE MATCHED, not a substring check (#382 review R1F2):
        # `_accepts_sse` honors `text/*`/`*/*` ranges, an explicit `q=0`
        # refusal, and an absent header (RFC 9110 says that means accept
        # anything) — see its docstring for what a substring check got
        # wrong in both directions.
        if not _accepts_sse(self.headers.get("Accept")):
            self._send_json(
                406,
                _error_body(
                    "subscriptions/listen responds with an SSE stream; "
                    "Accept must include text/event-stream",
                    req_id,
                    code=_JSONRPC_INVALID_REQUEST,
                ),
            )
            return

        honored = {
            flag: True for flag in _LISTEN_FILTER_METHODS if requested.get(flag) is True
        }
        # #381. Computed ONCE, here, and fed to all three consumers: the
        # ack echo below, the listener's routing set, and the refcounted
        # drive against the child. Any two of those disagreeing is a
        # silent failure — the ack would promise a URI nothing routes to.
        supported = _child_supports_resource_subscribe(init_result)
        resource_uris, truncated = _honored_resource_uris(
            requested.get(_LISTEN_RESOURCE_FIELD), supported=supported
        )
        if resource_uris:
            honored[_LISTEN_RESOURCE_FIELD] = resource_uris
        listener = _ListenStream(req_id, honored, frozenset(resource_uris))

        # The check and the attach are ONE atomic step (#382 review
        # R1F1): `attach_listener` takes the cap and does both under its
        # own lock, so a synchronized burst of simultaneous listens
        # cannot each see a free slot and all squeeze past — the cap is
        # HARD, not advisory. On success the buffer exists before
        # anything is written to the socket (see the docstring's
        # attach-before-ack ordering).
        if not backend.attach_listener(listener, _LISTEN_MAX_STREAMS_PER_CHILD):
            # Pre-ack rejection, single JSON: -32603 rather than a fresh
            # -32000-range mint (O18).
            self._send_json(
                503,
                _error_body(
                    "too many concurrent subscription streams for this client",
                    req_id,
                    code=_JSONRPC_INTERNAL_ERROR,
                ),
            )
            return
        # Logged unconditionally: a subscription opening is a fact an
        # operator wants in the log ("who is listening, and to what"),
        # alongside the access line the response itself produces. It is
        # also the only externally visible moment at which this stream
        # exists — the ack has not been written yet and the connection
        # stays open — which is what lets a test wait for the attach
        # rather than race it.
        log(
            f"listen {req_id!r}: streaming {sorted(honored) or 'nothing'}"
            + (f" ({len(resource_uris)} uris)" if resource_uris else "")
        )
        unhonored = sorted(set(requested) - set(honored))
        if unhonored:
            log(f"listen {req_id!r}: not honoring {unhonored}")
        if truncated:
            # Once per stream, mirroring relay's own once-latch: a client
            # that blew the cap will blow it on every reconnect, and one
            # line per URI per attempt would bury the log.
            log(
                f"listen {req_id!r}: capped resource subscriptions at "
                f"{_LISTEN_MAX_RESOURCE_SUBSCRIPTIONS}; the ack echoes the "
                "honored subset"
            )
        try:
            self.close_connection = True
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            # RE-ASSERTED, and this line is load-bearing:
            # `BaseHTTPRequestHandler.send_header` treats `Connection` as
            # a COMMAND, not a string — the `keep-alive` above silently
            # set `close_connection` back to False.
            #
            # The general rule, which is what to carry away: any
            # close-delimited SSE response that can end SERVER-side must
            # keep `close_connection` true after sending the header. An
            # SSE body has neither Content-Length nor chunked framing, so
            # the close IS its delimiter — leave this off and a stream
            # that ends normally (graceful shutdown, dead child) leaves
            # the client blocked on a socket nobody will ever write to
            # again.
            #
            # The legacy GET stream (`do_GET`) had the same shape and the
            # same omission — its `while not backend.closed` loop also
            # ends server-side on child death. #382 could not touch it
            # (AC2 kept the legacy path byte-identical there), so it was
            # filed as #383 and fixed separately; both sites now carry
            # this re-assertion.
            self.close_connection = True
            self._write_sse(
                {
                    "jsonrpc": "2.0",
                    "method": _LISTEN_ACK_METHOD,
                    "params": {
                        "notifications": honored,
                        "_meta": {_META_SUBSCRIPTION_ID: req_id},
                    },
                }
            )
            # #381 §3.3: AFTER the ack, on a background thread, and the
            # stream starts pumping without waiting for it. The honored
            # set was decided locally, so the client already has its
            # answer; driving the child is bookkeeping that must not be
            # able to delay — or fail — the stream it belongs to. A
            # daemon thread so a wedged child cannot hold up shutdown.
            if resource_uris:
                threading.Thread(
                    target=backend.add_resource_subscriptions,
                    args=(resource_uris, req_id, listener),
                    name="listen-subscribe",
                    daemon=True,
                ).start()
            self._pump_listen_stream(listener, backend)
        except (BrokenPipeError, ConnectionResetError, ValueError, OSError):
            # The client went away. On HTTP "closing the SSE response
            # stream is itself the cancellation signal and no
            # notifications/cancelled message is expected", so this is an
            # ordinary ending, not an error.
            log(f"listen {req_id!r}: client disconnected")
        finally:
            backend.detach_listener(listener)
            # Ordered BEFORE the release, and read by the background
            # subscribe thread under the refs' own lock: whichever of the
            # two runs first, the child ends up with no orphaned
            # subscription. See `_ListenStream.torn_down`.
            listener.torn_down = True
            if resource_uris:
                try:
                    backend.release_resource_subscriptions(resource_uris)
                except Exception as exc:  # noqa: BLE001 — teardown boundary
                    # This `finally` may already be unwinding from a client
                    # disconnect or a dead child. Raising here would replace
                    # the real ending with a bookkeeping error, and the refs
                    # die with the child anyway.
                    log(f"listen {req_id!r}: unsubscribe on teardown failed: {exc!r}")

    def _serve_mrtr_retry(
        self,
        msg: dict[str, Any],
        req_id: Any,
        backend: BackendProcess,
        principal: str | None,
        request_state: Any,
        params: dict[str, Any],
        init_result: dict[str, Any],
    ) -> None:
        """Resume a parked round from the client's retry (#375 §3.5).

        Spec: "If an `InputRequiredResult` contains the `requestState`
        field, the client MUST echo back the exact value of that field
        when retrying the original request."

        Three checks close three different holes, and naming only one of
        them would be an incomplete claim: the HMAC stops FORGERY, the
        single-use consume stops REPLAY of a genuine still-signed blob,
        and the principal binding stops CROSS-USER use of one that
        leaked. The round cap rides inside the signature, so a client
        cannot reset its own count by hand-crafting `round: 1`.
        """
        payload, why = _mrtr_decode_pointer(request_state, principal)
        if payload is None:
            # No spec-mandated code exists for an integrity failure — the
            # spec says only "MUST reject state that fails verification"
            # — so this follows relay's own `_mrtr_abort` precedent and
            # stays in the local -32000 range rather than inventing a
            # meaning for a reserved one (§4 Q4).
            self._send_json(400, _error_body(why, req_id))
            return
        # VALIDATE ON A PEEK, CONSUME ONLY ONCE IT MATCHES. The order is
        # the point (#390 Copilot review): consuming first meant a
        # mismatched retry destroyed a round that was still perfectly
        # valid, so its real owner could never redeem it — the check
        # rejected the impostor and took the victim down with it.
        peeked = backend.mrtr_round_for_txn(payload["txn_id"])
        if peeked is None:
            # The ordinary post-restart / post-timeout case, and a replay
            # attempt looks identical from here — deliberately, since
            # neither earns anything louder than an honest error.
            self._send_json(400, _error_body("unknown or expired requestState", req_id))
            return
        _, candidate = peeked
        if (
            candidate["round"] != payload["round"]
            or candidate["principal"] != principal
            # EXACT method match. `method in _MRTR_ELIGIBLE_METHODS` at
            # the dispatch hook only proves this request COULD have
            # opened a round; this proves it opened THIS one. Without it
            # a pointer minted by `tools/call` could be redeemed by
            # `resources/read` — both eligible — and take over a round
            # belonging to a different in-flight call.
            or candidate["method"] != msg.get("method")
        ):
            # NOT `_fail_retry`: the round is untouched and still owned
            # by someone who may yet redeem it, so the child is owed
            # nothing here. Unblocking it would be the same
            # take-the-victim-down-too mistake in a quieter form.
            self._send_json(400, _error_body("stale requestState", req_id))
            return
        entry = backend.mrtr_round_consume(payload["txn_id"])
        if entry is None:
            # Lost the race to a concurrent retry between the peek and
            # here. `mrtr_round_consume` is atomic, so exactly one won.
            self._send_json(400, _error_body("unknown or expired requestState", req_id))
            return
        # PAST THIS POINT THE ROUND IS GONE FROM THE TABLE, so nothing
        # else will ever answer the child's own request id. Every exit
        # below therefore owes the child a reply as well as the client
        # one, and `_fail_retry` is the single call that discharges both
        # — #390's review found two paths that had discharged only the
        # client's half, leaving the subprocess blocked forever.
        child_request_id = entry["child_request_id"]
        responses = params.get("inputResponses")
        if not isinstance(responses, dict) or not responses:
            self._fail_retry(
                backend,
                child_request_id,
                req_id,
                "inputResponses is required on a retry",
                400,
                code=_JSONRPC_INVALID_PARAMS,
            )
            return
        # The gateway invented this key from the child's own id, so that
        # is what the client echoes back.
        answer = responses.get(str(child_request_id))
        if answer is None and len(responses) == 1:
            # Tolerate a client that re-keyed a single-entry map: the
            # correlation is unambiguous at N=1, and refusing would be
            # pedantry that costs the user their answer.
            answer = next(iter(responses.values()))
        reply_line, translate_why = _mrtr_input_response_to_reply(
            answer, child_request_id
        )
        if reply_line is None:
            self._fail_retry(
                backend,
                child_request_id,
                req_id,
                translate_why,
                400,
                code=_JSONRPC_INVALID_PARAMS,
            )
            return
        # The next round, if the child asks again, is this one plus one.
        # Published with the claim so no window exists where a bridge
        # could see a half-built context.
        next_round = int(entry["round"]) + 1
        # #390 review, finding C: the next round's capabilities come from
        # THIS retry's own `_meta`, never from the entry. O5 makes
        # `clientCapabilities` per-request, and the retry IS a fresh,
        # separately-validated request — carrying the original's forward
        # would gate a second `input_required` mint against capabilities
        # this client may no longer (or may newly) declare, wrong in both
        # directions.
        retry_meta = params.get("_meta")
        retry_caps = (
            retry_meta.get(_META_CLIENT_CAPABILITIES)
            if isinstance(retry_meta, dict)
            else None
        )
        claimed = backend.mrtr_begin_dispatch(
            {
                "upstream_id": entry["upstream_id"],
                "declared_caps": retry_caps if isinstance(retry_caps, dict) else {},
                "principal": principal,
                # Carried forward: round N+1 belongs to the same original
                # request, so a second question must record the same
                # upstream method the first one did.
                "method": entry["method"],
                "round": next_round,
            }
        )
        if not claimed:
            # #390 review, finding A. Consuming the round left the child
            # momentarily unclaimed, and a brand-new eligible request on
            # another thread can win the claim in that window. Resuming
            # anyway would put the child back to work while someone else
            # holds the dispatch claim — and a second question from it
            # would bridge into the wrong context, which is precisely the
            # ambiguous correlation the invariant exists to forbid.
            #
            # Clean abort, matching §4 Q2's reject-don't-queue posture.
            # The original call is lost either way (both claimants cannot
            # win), so it is reported honestly rather than misrouted.
            self._fail_retry(
                backend,
                child_request_id,
                req_id,
                "the backend was claimed by a concurrent request; this "
                "retry could not be delivered",
                503,
                code=_JSONRPC_INTERNAL_ERROR,
            )
            return
        try:
            line, delivered = backend.resume_request(
                reply_line, entry["upstream_id"], _BACKEND_RESPONSE_TIMEOUT_SECS
            )
        finally:
            backend.mrtr_end_dispatch()
        if line is None:
            if not delivered:
                # The reply never reached the child, so it is still
                # blocked and this is the last chance to answer it.
                self._fail_retry(
                    backend,
                    child_request_id,
                    req_id,
                    "the input could not be delivered to the backend",
                    503,
                    code=_JSONRPC_INTERNAL_ERROR,
                )
                return
            self._send_json(
                504,
                _error_body(
                    "no response from backend after the input was delivered",
                    req_id,
                    code=_JSONRPC_INTERNAL_ERROR,
                ),
            )
            return
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        # `json.loads` raises on invalid JSON but NOT on valid non-object
        # JSON (#390 Copilot review): `[1, 2, 3]` parses cleanly to a
        # list, and the `parsed["id"] = ...` below then raises `TypeError:
        # list indices must be integers` OUTSIDE any handler — killing
        # the request with a traceback instead of an error response.
        # A JSON-RPC response is an object by definition, so anything
        # else is malformed and takes the same 502 as unparseable bytes.
        if not isinstance(parsed, dict):
            self._send_json(
                502,
                _error_body(
                    "malformed response from backend",
                    req_id,
                    code=_JSONRPC_INTERNAL_ERROR,
                ),
            )
            return
        # Re-keyed to THIS retry's own id: the client minted a fresh one,
        # and the child answered under the original upstream id.
        parsed["id"] = req_id
        _stamp_modern_result(
            parsed,
            msg.get("method"),
            # #390 review, finding 4: the child's `serverInfo`, same as
            # every other modern result. Omitting it made a RESUMED call
            # the one response missing the `_meta` the spec says servers
            # SHOULD put on every result — invisible until someone
            # compared two responses to the same tool.
            server_info=init_result.get("serverInfo"),
            cache_ttl_ms=self.cache_ttl_ms,
        )
        self._send_json(_modern_response_status(parsed), json.dumps(parsed))

    def _fail_retry(
        self,
        backend: BackendProcess,
        child_request_id: Any,
        req_id: Any,
        reason: str,
        status: int,
        *,
        code: int = -32000,
    ) -> None:
        """Fail a retry after its round was consumed — answering BOTH peers.

        One call, two obligations, deliberately fused (#390 review). Once
        `mrtr_round_consume` has popped the entry, nothing else can ever
        reply to the child's own request id, so a path that tells only
        the client leaves a subprocess blocked forever. Two such paths
        existed before this helper did; making the pair a single call is
        what stops a third appearing.
        """
        self._unblock_child(backend, child_request_id, reason, code=code)
        self._send_json(status, _error_body(reason, req_id, code=code))

    def _unblock_child(
        self,
        backend: BackendProcess,
        child_request_id: Any,
        reason: str,
        *,
        code: int = _JSONRPC_INVALID_PARAMS,
    ) -> None:
        """Answer the child so an unusable retry never leaves it blocked.

        The round has already been consumed by the time anything can fail
        here, so nothing else will ever reply to this id.
        """
        # The SAME code the client is told (#390 /code-review). This was
        # hardcoded to `-32602`, so one event reached the two peers with
        # semantically contradictory explanations — a concurrency
        # conflict arrived at the child as "your parameters are invalid",
        # which is both untrue and unactionable. The default stays
        # `-32602` for callers whose failure genuinely IS the params.
        backend.send_oneway(_error_body(reason, child_request_id, code=code))

    def _write_sse(self, message: dict[str, Any]) -> None:
        self.wfile.write(f"data: {json.dumps(message)}\n\n".encode("utf-8"))
        self.wfile.flush()

    def _peer_gone(self) -> bool:
        """Has the client closed its end of this stream?

        Waiting for a WRITE to fail is not good enough, and the number
        that proves it is 30 SECONDS: the first keepalive after a
        disconnect lands in the kernel's send buffer and succeeds, so
        only the SECOND one raises — two full keepalive intervals during
        which the stream still holds a slot against
        `_LISTEN_MAX_STREAMS_PER_CHILD` and a hold against the idle
        reaper. A client on a flaky network that drops and re-listens
        locks ITSELF out with 503s for half a minute.

        A committed SSE response has nothing left to read from the peer,
        so readable-and-empty is unambiguously EOF. Readable-with-DATA is
        a client pipelining onto a response whose framing is
        close-delimited; that is its own protocol error, but not this
        method's to answer, so it reports "still here" and the stream
        carries on.

        Fails SAFE in the other direction too: any socket error here
        means the connection is unusable, which is the same conclusion.
        """
        try:
            ready, _, _ = select.select([self.connection], [], [], 0)
            if not ready:
                return False
            return self.connection.recv(1, socket.MSG_PEEK) == b""
        except OSError:
            return True

    def _pump_listen_stream(
        self, listener: _ListenStream, backend: BackendProcess
    ) -> None:
        """Deliver matching notifications until the stream ends (#374 §3.6).

        Every frame carries the subscription id in `_meta` — the stamp is
        transport-unconditional, and the v2 client routes by it, so an
        unstamped frame never reaches the consumer.

        How a stream ends decides what the peer should do next:

        - gateway shutdown -> the empty `resultType: "complete"` result,
          stamped, then close. That is the spec's own graceful example,
          and it tells a peer not to come back.
        - child death or backlog overflow -> close with NO terminal
          frame. Serve is still alive; the contract is that the peer
          re-listens and refetches.
        - client disconnect -> nothing to send; `_peer_gone()` reads it
          directly at the top of every iteration, before any write, with
          a failed write as the backup for the race window between that
          check and the write itself.

        NEVER a server-sent `notifications/cancelled`. The spec assigns
        that message to the client->server, stdio-only direction, and the
        v2 client settles a listen route naming it as LOST — so emitting
        it would turn every graceful teardown into a failure at a
        compliant peer. (This supersedes the "emit both signals" reading
        recorded against O17 on #270.)

        RECORDED SO IT IS NOT REDISCOVERED (#381 §4 Q4): the spec is not
        self-consistent here. The subscriptions page describes the empty
        result as the graceful-close signal, which is what this code
        emits; the cancellation page is read as requiring
        `notifications/cancelled`. The two cannot both be satisfied
        toward a compliant peer, because the reference client treats that
        message as LOST. This resolution therefore favours SDK
        compatibility over one page's literal reading — a deliberate
        spec-vs-spec conflict resolution, not a corrected misreading, and
        worth filing upstream rather than quietly re-deciding next time
        someone reads the cancellation page.
        """
        last_keepalive = time.monotonic()
        while True:
            if listener.ending:
                if listener.graceful:
                    self._write_sse(
                        {
                            "jsonrpc": "2.0",
                            "id": listener.listen_id,
                            "result": {
                                "resultType": "complete",
                                "_meta": {_META_SUBSCRIPTION_ID: listener.listen_id},
                            },
                        }
                    )
                return
            if backend.closed:
                # Abrupt: no terminal frame. Reachable when the child was
                # already gone before this stream attached, so `_fail_all`
                # had nobody to signal.
                log(f"listen {listener.listen_id!r}: backend gone; closing the stream")
                return
            if self._peer_gone():
                log(f"listen {listener.listen_id!r}: client went away")
                return
            message = listener.next_message(_LISTEN_POLL_SECS)
            if message is None:
                now = time.monotonic()
                if now - last_keepalive >= _SSE_KEEPALIVE_SECS:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    last_keepalive = now
                continue
            # Copied, never mutated in place: `_queue_server_initiated`
            # parses ONCE and hands the same dict to every matching
            # stream, so stamping in place would put one stream's
            # subscription id on another's frame.
            #
            # A non-dict `params` or `_meta` DEGRADES to `{}` rather than
            # raising. `dict("oops")` is a `ValueError` on the handler
            # thread, which would kill the stream abruptly — a
            # misbehaving child must not be able to drop a well-behaved
            # client's subscription. Same posture
            # `_strip_undeliverable_capability_flags` takes for the same
            # reason (#373 review R3F1): the malformed part is forfeited,
            # never the connection. The stamp is what the client routes
            # on, so it has to survive whatever the child sent.
            stamped = dict(message)
            raw_params = stamped.get("params")
            params = dict(raw_params) if isinstance(raw_params, dict) else {}
            raw_meta = params.get("_meta")
            meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
            meta[_META_SUBSCRIPTION_ID] = listener.listen_id
            params["_meta"] = meta
            stamped["params"] = params
            self._write_sse(stamped)

    def _reject_legacy_transport(self) -> None:
        """Answer 405 on a transport verb a modern-only deployment drops.

        #376 §4.1. `--modern-only` says this endpoint serves the
        2026-07-28 revision and nothing else, and that revision has no
        session transport: no `GET` for a stream to resume, no `DELETE`
        for a session to end. The spec's own guidance to "a server that
        supports only this revision" is to answer 405 on those verbs.

        `Allow: POST` is not decoration — RFC 9110 §15.5.6 requires a 405
        to name the methods that ARE allowed, and that requirement comes
        from HTTP rather than from MCP, so it holds whatever the body
        looks like. A small JSON-RPC error body rides along so a client
        that only reads bodies still gets a reason.

        Placed after the auth gate on purpose (§6 Q3): an unauthenticated
        probe sees exactly what it saw before, so the flag does not
        change the endpoint's unauthenticated fingerprint.
        """
        self._send_json(
            405,
            _error_body(
                "this endpoint serves only MCP 2026-07-28, which has no "
                "session transport; use POST",
                code=_JSONRPC_INVALID_REQUEST,
            ),
            extra_headers={"Allow": "POST"},
        )

    def _dispatch_modern(self, kind: str, msg: dict[str, Any], req_id: Any) -> None:
        """Serve one validated modern request from a gateway-owned child.

        #270 Phase 3 P3-B. Reached only after `_validate_modern` passed,
        and it NEVER returns to the session path — which is the point.
        Branching here fixes both of P3-A's recorded interims at once:

        - a sessionless modern request no longer earns the legacy 400;
        - a modern request carrying a valid legacy `Mcp-Session-Id` no
          longer dispatches on that session. The header is IGNORED, per
          the spec's instruction to a modern-era server to "ignore it,
          and do not mint or echo session IDs" — and because this method
          never sets `self._session_id`, `_send_json`'s auto-echo cannot
          leak one back, which the tests assert on 200s as well as 4xxs.

        The v2 client never sends that header on a modern flow anyway
        (its session capture is gated on an `initialize` response, which
        a modern negotiation never produces); the ignore rule is for the
        mixed deployments D2 keeps legal.
        """
        method = msg.get("method")

        # Intake reject for an id inside serve's own namespace (§3.3).
        if kind == "request" and _is_reserved_client_id(req_id):
            self._send_json(
                400,
                _error_body(
                    f"request id must not start with {_SERVE_ID_NAMESPACE!r}: "
                    "that namespace is reserved for gateway-minted requests",
                    req_id,
                    code=_JSONRPC_INVALID_REQUEST,
                ),
            )
            return

        try:
            backend, init_result, pool_entry = self.modern_pool.get_or_create(
                self._current_user()
            )
        except RuntimeError as exc:
            log(f"modern dispatch: backend unavailable: {exc}")
            self._send_json(
                503,
                _error_body(
                    "backend unavailable", req_id, code=_JSONRPC_INTERNAL_ERROR
                ),
            )
            return

        # Everything past the checkout runs under try/finally: the child
        # is CHECKED OUT (#376 §3.1) and a leaked hold would make it
        # permanently unevictable and unreapable. Releasing here rather
        # than at each arm keeps that true for the early returns too —
        # and for anything the never-crash net catches on the way out.
        #
        # Initialised BEFORE the try, not at the point it is set: the
        # `finally` reads it on every exit path, including the arms that
        # return long before an MRTR claim could be taken (notifications,
        # listen, discover). Setting it only where it becomes true left
        # those paths raising `UnboundLocalError` out of the `finally` —
        # caught immediately by the listen suite's hold test.
        mrtr_claimed = False
        try:
            # Notifications: forward and acknowledge. The v2 client sends none
            # in the discover flow (no `initialize` means no
            # `notifications/initialized`), so this is consistency rather than
            # liveness — but leaving modern-classified traffic to fall onto a
            # legacy session error would be a worse answer than 202.
            if kind == "notification":
                if method == _LISTEN_METHOD:
                    # #374 §3.9. `subscriptions/listen` is a REQUEST: its
                    # id is what the ack stamps every frame with, so an
                    # id-less one has nowhere to route. Rejected rather
                    # than forwarded, matching the SDK's own
                    # "subscriptions/listen requires a request id".
                    self._send_json(
                        400,
                        _error_body(
                            "subscriptions/listen requires a request id",
                            code=_JSONRPC_INVALID_REQUEST,
                        ),
                    )
                    return
                backend.send_oneway(json.dumps(msg))
                self._send_empty(202)
                return

            # `server/discover` is answered HERE, never forwarded: a legacy
            # child has never heard of it and would answer -32601.
            # `subscriptions/listen` is served HERE, never forwarded —
            # the same posture discover takes, and what replaces the old
            # carve-out (child -32601 -> 404). The pool hold taken above
            # is deliberately kept for the whole stream: the `finally`
            # below releases it only when the stream ends, which is what
            # keeps the child unreapable while a client is listening.
            if method == _LISTEN_METHOD:
                # `init_result` rides along for #381's capability gate:
                # whether `resourceSubscriptions` can be honored is the
                # child's own advertised `resources.subscribe`, and the
                # pool already cached the handshake that carries it.
                self._serve_listen_stream(msg, req_id, backend, init_result)
                return

            if method == _MODERN_DISCOVER_METHOD:
                self._send_json(
                    200,
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": _synthesize_discover_result(
                                init_result, cache_ttl_ms=self.cache_ttl_ms
                            ),
                        }
                    ),
                )
                return

            # #375 §3.4: the one-MRTR-eligible-request-per-child
            # invariant.
            #
            # CLAIMED, not merely checked. An earlier version read
            # `mrtr_has_pending()` here and forwarded if it was False,
            # which #389's review showed is not the invariant at all:
            # a round only appears in `_mrtr_pending` once the child has
            # actually asked something, so two handler threads for one
            # principal could both read an empty table and both forward.
            # The claim closes that by being a single atomic
            # check-and-set — the same shape #382's review required for
            # the listen-stream cap after a check-then-attach let a
            # synchronized burst all past it.
            #
            # This is NOT inert, and that is the one deliberate
            # behavioural difference in PR 1: two genuinely concurrent
            # eligible calls on one child now get a 503 for the second.
            # Reaching it requires the same principal AND real overlap,
            # and it is the state PR 2 could not disambiguate anyway —
            # shipping the guard late would mean shipping the race.
            #
            # REJECT rather than queue (§4 Q2): queuing reintroduces the
            # stall vector D4 exists to prevent, and narrows perceived
            # concurrency in a way far harder to diagnose than an error.
            # #375 PR 2: the bridging context the reader thread needs
            # if this child asks something mid-call. Built HERE, before
            # the send, because `_meta.clientCapabilities` is a
            # PER-REQUEST field under O5 — there is no modern
            # `initialize` to have captured it from, so it is read fresh
            # off whichever request is currently live and snapshotted.
            # `isinstance` guarded: the ladder's rung 1 checks the field
            # is PRESENT, never that it is an object.
            declared_caps = (msg.get("params") or {}).get("_meta", {})
            declared_caps = (
                declared_caps.get(_META_CLIENT_CAPABILITIES)
                if isinstance(declared_caps, dict)
                else None
            )
            principal = self._current_user()
            # #375 §3.5: an MRTR RETRY, detected before the concurrency
            # claim and handled on its own path. It has to bypass that
            # claim: the round it resumes is precisely the one parked in
            # `_mrtr_pending`, so the ordinary guard would refuse the one
            # request able to clear it — a deadlock by construction.
            params_obj = msg.get("params")
            request_state = (
                params_obj.get("requestState") if isinstance(params_obj, dict) else None
            )
            # ...AND only for a method that could have OPENED one. The
            # spec's own words are "retrying the ORIGINAL request", so a
            # `requestState` riding some other method is not a retry of
            # anything (#390 Copilot review).
            #
            # Without this, `params.requestState` alone was enough: a
            # client that reused a params object — or was simply buggy —
            # could put a live pointer on, say, `resources/list` and have
            # the gateway treat it as the retry. Single-use consumption
            # then destroyed the round, so the REAL retry had nothing
            # left to resume and the original `tools/call` could never
            # be answered. The response would also carry the wrong
            # method into `_stamp_modern_result`, applying
            # `resources/list` cache semantics to a `tools/call` result.
            #
            # FALL THROUGH rather than reject, deliberately: the round
            # stays parked and a correct retry can still redeem it, so a
            # client bug costs one confused request instead of the whole
            # transaction. (An abandoned round is swept either way.)
            if request_state is not None and method in _MRTR_ELIGIBLE_METHODS:
                self._serve_mrtr_retry(
                    msg,
                    req_id,
                    backend,
                    principal,
                    request_state,
                    params_obj,
                    init_result,
                )
                return
            # §4 Q1's OAuth-only boundary, and this is where it BITES. A
            # context of None means the reader thread finds nothing to
            # bridge into and falls through to today's D4 `-32601` — so a
            # no-auth or static-token deployment keeps its behaviour
            # exactly, even after the valve comes out and the child is
            # free to ask. Principal binding is what stops one caller
            # answering another's prompt, and it buys nothing when every
            # caller shares one constant AND one pooled child.
            #
            # The concurrency CLAIM below is taken regardless of
            # principal: it guards correlation, it is not a feature gate,
            # and narrowing it would reintroduce the ambiguity for
            # exactly the deployments least able to tolerate it.
            # Minted BEFORE the context is built, so the context is
            # complete when it is published and is never mutated
            # afterwards (#390 Copilot review). `_mint_modern_id` is an
            # independent process-global counter — it does not depend on
            # the claim succeeding — so moving it earlier costs nothing
            # but an id on the paths that then reject.
            upstream_id = _mint_modern_id()
            mrtr_context = (
                {
                    "upstream_id": upstream_id,
                    "declared_caps": (
                        declared_caps if isinstance(declared_caps, dict) else {}
                    ),
                    "principal": principal,
                    # The UPSTREAM method — what the client would be
                    # retrying — not whatever the child later asks
                    # (#390 Copilot review). A round remembers the
                    # request it belongs to so a retry can be checked
                    # against it; recording the child's question instead
                    # made that check impossible to write.
                    "method": method,
                    "round": 1,
                }
                # BOTH gates, and the second one was missing (#390
                # Copilot review). `_modern_child_capabilities()` was
                # consulted only where serve ADVERTISES to a child, so
                # `MCP_STDIO_MRTR_REVERSE_ENABLE=0` withdrew the offer
                # while leaving the bridge itself live: a child that
                # ignored the advertisement and asked anyway was still
                # bridged, provided the caller was OAuth-authenticated.
                # The flag's whole purpose is that an operator can
                # withdraw this "without a code rollback", and a switch
                # that only changes what serve SAYS while the behaviour
                # stays on does not do that.
                #
                # Read live rather than captured at spawn, deliberately:
                # flipping the flag off must stop bridging on children
                # that are already running, which is what "withdraw"
                # means to an operator holding an incident.
                #
                # NOT to be confused with the O11 check further in
                # (`capability not in declared`): that one asks what the
                # CLIENT declared it can handle. This asks whether this
                # GATEWAY offers the feature at all.
                if _mrtr_principal_is_eligible(principal)
                and _modern_child_capabilities()
                else None
            )
            if method in _MRTR_ELIGIBLE_METHODS:
                if not backend.mrtr_begin_dispatch(mrtr_context):
                    self._send_json(
                        503,
                        _error_body(
                            "this backend is already handling an "
                            "input-required-capable request; retry once it "
                            "completes",
                            req_id,
                            code=_JSONRPC_INTERNAL_ERROR,
                        ),
                    )
                    return
                mrtr_claimed = True

            outbound = dict(msg)
            outbound["id"] = upstream_id
            line = backend.send_request(
                json.dumps(outbound), upstream_id, _BACKEND_RESPONSE_TIMEOUT_SECS
            )
            if line is None:
                self._send_json(
                    504,
                    _error_body(
                        "no response from backend", req_id, code=_JSONRPC_INTERNAL_ERROR
                    ),
                )
                return
            try:
                parsed = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                parsed = None
            # Same non-object hole as the retry path's (#390 Copilot
            # review found it there; this site had it too, and it is on
            # the path EVERY modern request takes). `json.loads` is happy
            # with `[1, 2, 3]`, and the rekey below would then raise
            # `TypeError` outside any handler.
            if not isinstance(parsed, dict):
                log("modern dispatch: backend returned a non-object response")
                self._send_json(
                    502,
                    _error_body(
                        "malformed response from backend",
                        req_id,
                        code=_JSONRPC_INTERNAL_ERROR,
                    ),
                )
                return

            # Rekey minted -> client id. One parse total: the same dict is
            # rekeyed and stamped, so relay's `_mrtr_rekey` (which re-parses a
            # string) would be strictly more work for the same result here.
            parsed["id"] = req_id
            _stamp_modern_result(
                parsed,
                method,
                server_info=init_result.get("serverInfo"),
                cache_ttl_ms=self.cache_ttl_ms,
            )
            self._send_json(_modern_response_status(parsed), json.dumps(parsed))
        finally:
            if mrtr_claimed:
                # Unconditional, and safe to be: if this dispatch parked a
                # round on its way out, `_mrtr_pending` is already
                # populated and keeps excluding new dispatches after the
                # claim drops. The two states hand over with no window
                # between them, which is why `mrtr_begin_dispatch` checks
                # both.
                backend.mrtr_end_dispatch()
            self.modern_pool.release(pool_entry)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        # Reset the per-request session id (the handler instance is reused
        # across keep-alive requests); responses before resolution omit it.
        self._session_id = None
        # Read (drain) the request body BEFORE any early return. On HTTP/1.1
        # keep-alive, leaving an unread body in the socket makes the handler
        # parse those leftover bytes as the next request line ("Bad request
        # syntax"). So the path / parse-error branches below run only after the
        # body is consumed.
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0:
                raise ValueError
        except ValueError:
            # Unknown body length -> we cannot safely drain it; don't reuse the
            # connection.
            self.close_connection = True
            self._send_json(400, _error_body("invalid Content-Length"))
            return
        # #416: reject an oversized body by its DECLARED length, before
        # reading a single byte of it — draining it first (to keep the
        # connection alive for the next request, the usual rule above)
        # would defeat the cap by allocating the very memory it exists to
        # bound. RFC 9110 §15.5.14 "Content Too Large"; the connection is
        # closed rather than reused since the client's oversized body is
        # still sitting unread in the socket.
        if self.max_message_size > 0 and length > self.max_message_size:
            self.close_connection = True
            self._send_json(
                413,
                _error_body(
                    f"request body exceeds --max-message-size "
                    f"({self.max_message_size} bytes)"
                ),
            )
            return
        raw = self.rfile.read(length) if length > 0 else b""
        if self.oauth is not None:
            # AS POST endpoints (DCR + token) bootstrap the token, exempt from
            # the RS gate. Match by EXACT path under the issuer prefix (empty for
            # a bare-origin issuer). Body already drained above.
            path = self.path.split("?", 1)[0]
            _, prefix = self._issuer_origin_and_prefix()
            if path == prefix + _REGISTER_PATH:
                self._handle_register(raw)
                return
            if path == prefix + _TOKEN_PATH:
                self._handle_token(raw)
                return
        if self._wrong_path():
            return
        if not self._require_auth():
            return
        try:
            text = raw.decode("utf-8")
            msg = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, _error_body("invalid JSON"))
            return

        kind = _classify(msg)
        if kind not in ("request", "notification", "response"):
            # Batches and malformed payloads are out of scope here.
            self._send_json(400, _error_body("unsupported or invalid message"))
            return
        req_id = msg.get("id") if kind == "request" else None
        if kind == "request":
            # A JSON-RPC id is a String, Number, or null. A non-scalar id
            # (object / array) is malformed AND unhashable, so using it as the
            # pending-response dict key would raise TypeError and crash the
            # handler thread — reject it up front, mirroring relay's
            # _extract_cancel_id guard and the never-crash invariant.
            if req_id is not None and not isinstance(req_id, (str, int, float)):
                self._send_json(400, _error_body("invalid JSON-RPC id"))
                return

        # --- modern request-plane validation (#270 Phase 3 P3-A) ---
        # Placed HERE, and the position is load-bearing three ways: the
        # body is parsed (so the era predicate can read `_meta`), it is
        # already DRAINED (line ~2112, so every rejection below inherits
        # the keep-alive contract by construction rather than by
        # remembering), and `self._session_id` is still None (so no
        # session header can leak onto a rejection).
        #
        # A legacy body classifies legacy and nothing below runs — the
        # whole ladder is vacuous for it, which is how AC2 holds.
        #
        # A modern request is served STATELESSLY and never reaches the
        # session code below — spec: "Servers MUST NOT rely on prior
        # requests over the same connection to establish context." P3-A
        # let a validated modern request fall through to the legacy
        # session path; P3-B (#270) replaces that seam with dispatch,
        # which is the single change that activates everything the
        # preceding commits put in place.
        if _request_era(kind, msg) == "modern":
            if not _validate_modern(self, kind, msg, req_id):
                return
            self._dispatch_modern(kind, msg, req_id)
            return

        # --- session resolution (MCP Streamable HTTP session management) ---
        # When OAuth is enabled, sessions are bound to the authenticated user so
        # a session id (a bearer-equivalent capability) cannot be used by, or
        # torn down by, a different principal.
        user = self._current_user()
        is_init = kind == "request" and msg.get("method") == "initialize"
        if is_init and self.modern_only:
            # --modern-only (#376 §4.1). A legacy `initialize` literally
            # presents a `params.protocolVersion` this posture does not
            # serve, and -32022 is the spec's own shape for exactly that
            # — actionable, because an auto-negotiating client reads
            # `data.supported` and retries at a version we do name.
            #
            # Only `initialize` is intercepted. With it refused no
            # session can ever exist, so every other legacy POST already
            # dies on the untouched sessionless-400 path below; rejecting
            # them again would duplicate an existing rejection for no
            # behavioural gain.
            log("modern-only: refusing a legacy initialize")
            self._send_json(
                400,
                _error_body(
                    "this endpoint serves only MCP 2026-07-28; send "
                    "per-request _meta instead of an initialize handshake",
                    req_id,
                    code=_MCP_UNSUPPORTED_PROTOCOL_VERSION,
                    data={"supported": sorted(_SERVE_IMPLEMENTED_MODERN_VERSIONS)},
                ),
            )
            return

        if is_init:
            # `initialize` starts a session (MCP spec item 1): spawn a fresh
            # child and mint an id, returned via the Mcp-Session-Id response
            # header. A presented (stale) id owned by this user is dropped first.
            stale_id = self.headers.get("Mcp-Session-Id")
            if stale_id:
                stale = self.registry.remove(stale_id, user)
                if stale is not None:
                    stale.shutdown()
            created = self.registry.create(owner=user)
            if created is None:
                self._send_json(503, _error_body("session limit reached", req_id))
                return
            self._session_id, backend = created
        else:
            # MCP spec items 2/3: sessionless -> 400, unknown/terminated -> 404.
            backend = self._resolve_session(user, req_id)
            if backend is None:
                return

        if kind == "request":
            if backend.closed:
                # Dead child: drop the session so the slot is reclaimed and the
                # client's next request re-initializes (404) instead of looping
                # on 503. shutdown() reaps the already-exited child.
                stale = self.registry.remove(self._session_id, user)
                if stale is not None:
                    stale.shutdown()
                self._send_json(503, _error_body("backend unavailable", req_id))
                return
            try:
                line = backend.send_request(
                    json.dumps(msg), req_id, _BACKEND_RESPONSE_TIMEOUT_SECS
                )
            except _DuplicateInFlightId as exc:
                # Client reused a JSON-RPC id already in flight on this session
                # with a DIFFERENT payload (a same-payload retry is piggybacked
                # by send_request instead of raising). It cannot be
                # correlated, so reject it rather than cross-wire a reply. 409
                # Conflict: the id conflicts with an in-flight request. Log the
                # collision (id + both methods, client-controlled so rendered
                # via _log_safe_uri) — the access log alone shows a bare 409
                # and cannot tell which two calls collided.
                log(
                    f"duplicate in-flight id {_log_safe_uri(req_id)} on session "
                    f"{self._session_id[:8]}...: "
                    f"in-flight={_log_safe_uri(exc.in_flight_method)} "
                    f"rejected={_log_safe_uri(exc.rejected_method)} -> 409"
                )
                self._send_json(
                    409,
                    _error_body(
                        "JSON-RPC id already in flight on this session; "
                        "use a distinct id per outstanding request",
                        req_id,
                    ),
                )
                return
            if line is None:
                if is_init:
                    # The freshly-spawned child never answered initialize, so it
                    # never became a usable session — don't leak its slot/child.
                    stale = self.registry.remove(self._session_id, user)
                    if stale is not None:
                        stale.shutdown()
                self._send_json(504, _error_body("no response from backend", req_id))
                return
            self._send_json(200, line)
        else:
            # Fire-and-forget toward the backend; the MCP spec returns 202 for
            # a POST that carries no request needing a reply.
            backend.send_oneway(json.dumps(msg))
            self._send_empty(202)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._session_id = None
        path = self.path.split("?", 1)[0]
        # RFC 9728 metadata is unauthenticated — it is how the client discovers
        # how to authenticate — so it is checked before the auth gate. Match the
        # exact well-known path or a path-suffixed form (".../<resource path>"),
        # NOT a mere prefix (so "...-resource-evil" does not match).
        if path == _PRM_WELL_KNOWN_PREFIX or path.startswith(
            _PRM_WELL_KNOWN_PREFIX + "/"
        ):
            self._serve_prm()
            return
        if self.oauth is not None:
            # AS endpoints bootstrap the token, so they are exempt from the RS
            # gate. The AS metadata sits at the RFC 8414 Sec. 3.1 root-inserted
            # location (well-known label + issuer prefix); /authorize lives under
            # the prefix. Both reduce to the legacy root paths when the prefix is
            # empty. Match by EXACT path (never a loose prefix).
            origin, prefix = self._issuer_origin_and_prefix()
            if path == _AS_METADATA_PATH + prefix:
                self._serve_as_metadata()
                return
            if path == prefix + _AUTHORIZE_PATH:
                self._handle_authorize()
                return
        if self._wrong_path():
            return
        if not self._require_auth():
            return
        # --modern-only: the session SSE stream is legacy transport.
        # Everything above stays reachable — PRM/AS metadata and the
        # auth gate are HTTP plumbing a modern-only deployment still
        # needs to bootstrap OAuth.
        if self.modern_only:
            self._reject_legacy_transport()
            return
        # The SSE stream carries a session's server-initiated messages, so it
        # must name an existing session: sessionless -> 400, unknown/terminated
        # (or another user's) -> 404 (drives the client's re-initialize), as on
        # the POST path.
        backend = self._resolve_session(self._current_user())
        if backend is None:
            return
        # Open an SSE stream carrying server-initiated messages (notifications
        # and server->client requests) until the client disconnects or the
        # backend dies. The stream has no Content-Length and is not chunked, so
        # mark the connection close-delimited (unambiguous framing): the body
        # ends when we close it, never reused for a follow-up request.
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("Mcp-Session-Id", self._session_id)
        self.end_headers()
        # RE-ASSERTED (#383, closing the gap #382 left open — see the
        # matching comment in `_serve_listen_stream`): the
        # `send_header("Connection", "keep-alive")` above is a COMMAND,
        # not a string, and silently reset `close_connection` to False —
        # undoing the intent stated four lines earlier. This stream is
        # close-delimited (no Content-Length, not chunked), so the general
        # rule applies: any close-delimited SSE response that can end
        # SERVER-side (here: `while not backend.closed`, on child death)
        # must keep `close_connection` True after `end_headers()`, or a
        # stream that ends normally leaves the client blocked on a socket
        # nobody will ever write to again.
        self.close_connection = True
        q = backend.server_initiated
        keepalive = self.registry.keepalive_interval()
        try:
            while not backend.closed:
                # An open SSE stream is activity: keep the session warm so the
                # idle reaper does not evict a connected-but-quiet client. The
                # cadence tracks the TTL so this holds even for a small TTL.
                self.registry.touch(self._session_id)
                try:
                    line = q.get(timeout=keepalive)
                except queue.Empty:
                    # SSE comment keepalive — also how we notice backend death.
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                payload = f"data: {line}\n\n".encode("utf-8")
                self.wfile.write(payload)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ValueError, OSError):
            # Client went away mid-stream — normal, not an error.
            #
            # `OSError` added for symmetry with `_serve_listen_stream`
            # (#383): the two named subclasses cover the common
            # disconnects, but a socket write can fail other ways
            # (ETIMEDOUT, ENOTCONN, EHOSTUNREACH), and those escaped into
            # `handle_one_request` to be logged as a traceback — noise
            # for what is an ordinary client disconnect. The only calls
            # in the loop that can raise `OSError` are the `wfile`
            # writes, so the widening stays confined to transport
            # failures. The modern path made this choice deliberately;
            # the two SSE sites having DRIFTED is what produced the bug
            # this PR fixes, so they are brought back into one shape.
            return

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        # MCP clients DELETE the endpoint to terminate a session (spec item 5).
        # Tear down that session's backend child.
        self._session_id = None
        if self._wrong_path():
            return
        if not self._require_auth():
            return
        # --modern-only: DELETE ends a session, and this posture mints
        # none. Rejected after the auth gate, like GET.
        if self.modern_only:
            self._reject_legacy_transport()
            return
        sid_header = self.headers.get("Mcp-Session-Id")
        if not sid_header:
            self._send_json(400, _error_body("Mcp-Session-Id required"))
            return
        # Ownership-checked: one user cannot DELETE another's session.
        backend = self.registry.remove(sid_header, self._current_user())
        if backend is None:
            self._send_json(404, _error_body("unknown or expired session"))
            return
        # shutdown() (terminate -> wait) runs after the dict pop, off the lock.
        backend.shutdown()
        log(f"session {sid_header[:8]}... terminated by client")
        # Same invariant as _resolve_session above: registry.remove() only
        # succeeds for an exact match against a server-minted key, so
        # sid_header is provably clean here (CodeQL alert #16, dismissed as
        # a false positive).
        self._session_id = sid_header
        self._send_empty(200)


def build_server(
    command: list[str],
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    mcp_path: str = "/mcp",
    auth_token: str | None = None,
    oauth: _OAuthProvider | None = None,
    max_sessions: int = _DEFAULT_MAX_SESSIONS,
    idle_ttl: float = 0.0,
    max_sessions_per_owner: int = 0,
    cache_ttl_ms: int = _DEFAULT_CACHE_TTL_MS,
    modern_idle_ttl: float = 0.0,
    modern_only: bool = False,
    user_env_var: str | None = None,
    max_message_size: int = _DEFAULT_MAX_MESSAGE_SIZE,
) -> tuple[ThreadingHTTPServer, SessionRegistry]:
    """Construct the HTTP server and session registry without running the loop.

    Separated from :func:`serve` so tests can drive the server on an ephemeral
    port (``port=0``) without installing signal handlers or blocking. The
    caller owns the lifecycle: run ``httpd.serve_forever()`` (typically in a
    thread), then ``registry.shutdown_all()`` + ``httpd.server_close()``.

    ``auth_token`` (when not None) enables the static-bearer-token Resource
    Server gate. ``oauth`` (when not None) enables the embedded OAuth
    Authorization Server: /authorize /token /register + AS metadata, and
    the RS gate then also accepts issued access tokens. ``idle_ttl`` (when
    ``> 0``) arms idle session eviction; the caller starts the reaper with
    ``registry.start_reaper()``. ``user_env_var`` (when not None) injects the
    authenticated principal into each spawned child's environment under this
    variable name (see :func:`_user_env_value`) -- both the per-session
    (legacy) and per-principal (modern) pools spawn one child per real
    identity already, so this is purely an env-injection concern, not a
    pooling-strategy change. ``max_message_size`` (bytes, ``0`` = unlimited,
    default 10 MiB) rejects a request whose declared ``Content-Length``
    exceeds it with ``413`` before reading any of the body (#416, CWE-770).
    """
    registry = SessionRegistry(
        command,
        max_sessions=max_sessions,
        idle_ttl=idle_ttl,
        max_sessions_per_owner=max_sessions_per_owner,
        user_env_var=user_env_var,
    )
    # #270 Phase 3 P3-B. Constructed unconditionally but SPAWNS NOTHING
    # until a modern request arrives, so a deployment that never sees one
    # pays a dict and a lock. The per-principal cap reuses the session
    # registry's per-owner value: the same operator knob answers the same
    # question ("how many children may one principal hold?") on both eras.
    modern_pool = ModernBackendPool(
        command,
        max_children=max_sessions_per_owner,
        idle_ttl=modern_idle_ttl,
        user_env_var=user_env_var,
    )
    handler = type(
        "_BoundHandler",
        (_Handler,),
        {
            "registry": registry,
            "modern_pool": modern_pool,
            "mcp_path": mcp_path,
            "auth_token": auth_token,
            "oauth": oauth,
            "cache_ttl_ms": cache_ttl_ms,
            "modern_only": modern_only,
            "max_message_size": max_message_size,
        },
    )
    httpd = ThreadingHTTPServer((host, port), handler)
    # Don't let the process hang on lingering SSE handler threads at shutdown.
    httpd.daemon_threads = True
    # Attached rather than returned: the (httpd, registry) tuple is this
    # function's published contract and `tests/test_server.py` unpacks it
    # in a dozen places. Callers that need the pool — serve()'s teardown,
    # and tests — reach it here.
    httpd.modern_pool = modern_pool
    return httpd, registry


def serve(
    command: list[str],
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    mcp_path: str = "/mcp",
    auth_token: str | None = None,
    oauth: _OAuthProvider | None = None,
    max_sessions: int = _DEFAULT_MAX_SESSIONS,
    idle_ttl: float = 0.0,
    max_sessions_per_owner: int = 0,
    cache_ttl_ms: int = _DEFAULT_CACHE_TTL_MS,
    modern_idle_ttl: float = 0.0,
    modern_only: bool = False,
    user_env_var: str | None = None,
    max_message_size: int = _DEFAULT_MAX_MESSAGE_SIZE,
) -> None:
    """Run the reverse gateway until interrupted.

    Spawns ``command`` as the backend stdio MCP server and serves it at
    ``http://host:port{mcp_path}``. Blocks until SIGINT/SIGTERM, then tears
    the backend down. ``auth_token`` enables the static-token gate;
    ``oauth`` enables the embedded Authorization Server. ``max_sessions`` caps
    concurrent sessions; ``idle_ttl`` (when ``> 0``) evicts idle sessions.
    ``user_env_var`` injects the authenticated principal into each spawned
    child's environment (see :func:`build_server`). ``max_message_size``
    bounds a single request body (see :func:`build_server`).
    """
    httpd, registry = build_server(
        command,
        host=host,
        port=port,
        mcp_path=mcp_path,
        auth_token=auth_token,
        oauth=oauth,
        max_sessions=max_sessions,
        idle_ttl=idle_ttl,
        max_sessions_per_owner=max_sessions_per_owner,
        cache_ttl_ms=cache_ttl_ms,
        modern_idle_ttl=modern_idle_ttl,
        modern_only=modern_only,
        user_env_var=user_env_var,
        max_message_size=max_message_size,
    )
    # #385: the legacy reaper now always starts (it sweeps dead children
    # unconditionally, not just idle-past-TTL ones), independent of
    # whether --session-idle-ttl is set.
    registry.start_reaper()
    # Its own thread. Unlike the legacy reaper above, the modern pool's
    # can still be a no-op (no --modern-idle-ttl and the MRTR bridge
    # disabled) — its dead-child sweep has the same residual gap #385
    # closed here, just not this issue's scope.
    httpd.modern_pool.start_reaper()

    stopping = threading.Event()

    def _stop(_signum: int, _frame: Any) -> None:
        if stopping.is_set():
            return
        stopping.set()
        log("shutting down")
        # shutdown() must run off the handler/main thread; spawn a stopper.
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    modes = []
    if auth_token:
        modes.append("static bearer token")
    if oauth is not None:
        modes.append("embedded OAuth AS")
    auth_state = " + ".join(modes) if modes else "no auth"
    posture = "modern-only" if modern_only else "dual-era"
    ttl_state = f"idle-ttl {idle_ttl:g}s" if idle_ttl > 0 else "no idle eviction"
    modern_ttl_state = (
        f", modern idle-ttl {modern_idle_ttl:g}s"
        if modern_idle_ttl > 0
        else ", no modern idle eviction"
    )
    per_owner_state = (
        f", max {max_sessions_per_owner}/owner" if max_sessions_per_owner > 0 else ""
    )
    log(
        f"serving {' '.join(command)} at "
        f"http://{host}:{port}{mcp_path} ({auth_state}; "
        f"max {max_sessions} sessions{per_owner_state}, "
        f"{ttl_state}{modern_ttl_state}, {posture})"
    )
    try:
        httpd.serve_forever()
    finally:
        registry.shutdown_all()
        # #270 Phase 3 P3-B: the modern pool's children are gateway-owned
        # and belong to no session, so `registry.shutdown_all()` cannot
        # see them. Without this they outlive the gateway.
        httpd.modern_pool.shutdown_all()
        httpd.server_close()


def serve_main(argv: list[str]) -> None:
    """Entry point for the ``mcp-stdio serve`` subcommand.

    Usage: ``mcp-stdio serve [--host H] [--port P] [--path /mcp] -- CMD [ARG...]``
    The backend command is everything after the gateway options (an optional
    ``--`` separator is supported and stripped).
    """
    parser = argparse.ArgumentParser(
        prog="mcp-stdio serve",
        description=(
            "Expose a local stdio MCP server as a Streamable HTTP MCP endpoint. "
            "Optionally protect it with a static bearer token. The backend "
            "command follows the options."
        ),
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="bind port (default: 8080)"
    )
    parser.add_argument(
        "--path", default="/mcp", help="MCP endpoint path (default: /mcp)"
    )
    parser.add_argument(
        "--auth-token",
        default=None,
        metavar="TOKEN",
        help=(
            "Require this static bearer token on MCP requests "
            f"(or set {_SERVE_TOKEN_ENV}; the env var is preferred since a flag "
            "value is visible in `ps`). Omit for no authentication."
        ),
    )
    parser.add_argument(
        "--enable-oauth",
        action="store_true",
        help=(
            "Enable the embedded OAuth 2.1 Authorization Server (PKCE auth-code, "
            "dynamic client registration, refresh). MCP requests then require an "
            "issued bearer token; the mcp-stdio client's --oauth flow works "
            "against this gateway."
        ),
    )
    parser.add_argument(
        "--public-url",
        default=None,
        metavar="URL",
        help=(
            "Canonical external issuer URL (e.g. https://gw.example.org) used to "
            "pin the OAuth issuer and all endpoint URLs. Strongly recommended "
            "behind a reverse proxy. A PATH is retained as an issuer prefix "
            "(e.g. https://gw.example.org/team-a), letting several "
            "--enable-oauth backends share one host under distinct path "
            "prefixes; the AS endpoints then live under that prefix and the "
            "well-known docs at the RFC 8414/9728 root-inserted locations. A "
            "bare-origin URL behaves as before."
        ),
    )
    parser.add_argument(
        "--trusted-user-header",
        default=None,
        metavar="HEADER",
        help=(
            "Trust this request header as the authenticated user at /authorize "
            "(e.g. X-Forwarded-User). ONLY safe behind a reverse proxy that "
            "STRIPS any client-supplied copy. Off by default (fails closed)."
        ),
    )
    parser.add_argument(
        "--dev-user",
        default=None,
        metavar="USER",
        help=(
            "INSECURE local-testing identity for /authorize when no trusted "
            "header is present. For loopback smoke tests only; never a real "
            "auth boundary."
        ),
    )
    parser.add_argument(
        "--allow-redirect-uri",
        action="append",
        default=[],
        metavar="URL",
        help=(
            "Trust this exact HTTPS redirect_uri in addition to the RFC 8252 "
            "loopback default, for a known non-loopback remote client (e.g. a "
            "browser-based MCP client's fixed OAuth callback). Repeatable. "
            "Matched byte-for-byte -- never widened to a host or prefix -- so "
            "only add a URL you have verified belongs to a client you trust; "
            "each is exactly as trusted as a hardcoded redirect target."
        ),
    )
    parser.add_argument(
        "--access-token-ttl",
        type=int,
        default=int(_DEFAULT_ACCESS_TTL_SECS),
        metavar="SECONDS",
        help="Issued access-token lifetime in seconds (default: 3600).",
    )
    parser.add_argument(
        "--token-store",
        default=None,
        metavar="PATH",
        help=(
            "Persist issued OAuth tokens and client registrations to this "
            "JSON file (created 0600) so they survive a serve restart. "
            "Without it every restart invalidates all issued tokens and every "
            "connected client must re-authorize. The file is credential "
            "material — guard it like a private key. Each serve process "
            "needs its own path (a sidecar .lock refuses accidental "
            "sharing). Requires --enable-oauth. Mutually exclusive with "
            "--token-store-firestore."
        ),
    )
    parser.add_argument(
        "--token-store-firestore",
        default=None,
        metavar="COLLECTION/DOCUMENT",
        help=(
            "Persist the same OAuth state --token-store does, but as one "
            "Firestore document at this collection/document path instead of "
            "a local file — for a deployment with no durable local disk "
            "(e.g. Cloud Run) where every restart would otherwise invalidate "
            "every issued token. The GCP project is resolved the standard "
            "google-cloud way (GOOGLE_CLOUD_PROJECT env var, or ADC on "
            "Cloud Run); there is no separate --project flag. Requires the "
            "google-cloud-firestore package (`pip install "
            "mcp-stdio[firestore]`) and --enable-oauth. Mutually exclusive "
            "with --token-store. Unlike --token-store there is no lock "
            "against two processes sharing one document, but each write goes "
            "through a read-merge-write Firestore transaction rather than a "
            "blind overwrite, so a brief overlap between two writers (e.g. a "
            "Cloud Run revision cutover) does not silently discard tokens "
            "either side issued or rotated during the overlap."
        ),
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=_DEFAULT_MAX_SESSIONS,
        metavar="N",
        help=(
            "Maximum concurrent MCP sessions, each backed by its own child "
            f"process (default: {_DEFAULT_MAX_SESSIONS}). An initialize past "
            "the cap gets 503 — a fork-bomb guard for an open gateway."
        ),
    )
    parser.add_argument(
        "--session-idle-ttl",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help=(
            "Evict a session (and its child) after this many seconds with no "
            "activity, so a client that disconnects without DELETE does not "
            "pin a slot. 0 (default) disables idle eviction."
        ),
    )
    parser.add_argument(
        "--max-sessions-per-owner",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Cap concurrent sessions per authenticated OAuth user: on a new "
            "initialize the user's older sessions are LRU-evicted down to this "
            "count, reclaiming ghost sessions left by a client that reconnects "
            "without DELETE. This decouples ghost reclamation from the idle "
            "reaper, so a longer --session-idle-ttl no longer risks ghosts "
            "filling --max-sessions. 0 (default) disables per-owner capping. "
            "Only affects OAuth-bound sessions; the shared static-token "
            "principal and open-gateway sessions are exempt."
        ),
    )
    parser.add_argument(
        "--user-env",
        default=None,
        metavar="VAR",
        help=(
            "Inject the authenticated principal into each spawned backend "
            "child's environment under this variable name, so a "
            "multi-user-aware backend can read its caller's identity "
            "without its own OAuth stack (a trusted-header pattern at the "
            "process-spawn boundary instead of the HTTP boundary). Only a "
            "genuine per-caller identity is injected -- the open-gateway "
            "(no auth) and shared static-token principals are exempt, "
            "leaving the child's environment unmodified for those, exactly "
            "as before this flag existed. Off (default) injects nothing. "
            "Refuses a search-path / dynamic-linker variable name "
            "(PATH, *PRELOAD*, *LIBRARY_PATH, PYTHONPATH, ...) that the "
            "child's own runtime needs to start."
        ),
    )
    parser.add_argument(
        "--cache-ttl-ms",
        type=int,
        default=_DEFAULT_CACHE_TTL_MS,
        help=(
            "ttlMs stamped on cacheable results served to a modern "
            f"(2026-07-28) client (default: {_DEFAULT_CACHE_TTL_MS}; 0 "
            "disables caching without violating the spec, which only "
            "requires a value >= 0)"
        ),
    )
    parser.add_argument(
        "--max-message-size",
        type=int,
        default=_DEFAULT_MAX_MESSAGE_SIZE,
        metavar="BYTES",
        help=(
            "Reject a request whose declared Content-Length exceeds this "
            "many bytes with 413, before reading any of the body "
            f"(default: {_DEFAULT_MAX_MESSAGE_SIZE}, 10 MiB; 0 disables the "
            "cap). Bounds how much memory one oversized request body can "
            "make the gateway allocate (#416)."
        ),
    )
    parser.add_argument(
        "--modern-only",
        action="store_true",
        help=(
            "Serve ONLY MCP 2026-07-28 clients. Legacy clients are turned "
            "away instead of being given a session: GET and DELETE answer "
            "405, and a legacy initialize gets -32022 naming the versions "
            "this endpoint does serve. Off by default, and off is "
            "byte-identical to not having the flag."
        ),
    )
    parser.add_argument(
        "--modern-idle-ttl",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help=(
            "Shut down a pooled backend for a modern (2026-07-28) client "
            "after this many seconds with no request, reclaiming the "
            "process. 0 (default) disables it. Separate from "
            "--session-idle-ttl on purpose: evicting a modern child costs "
            "only its warm-up, because those clients keep no session "
            "state, so this can be far more aggressive than the legacy "
            "one. A child serving a request, or handed to a request that "
            "has not sent yet, is never reaped."
        ),
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="backend stdio MCP server command (after the options)",
    )
    args = parser.parse_args(argv)

    command = list(args.command)
    if command and command[0] == "--":  # tolerate an explicit separator
        command = command[1:]
    if not command:
        parser.error("a backend command is required, e.g. serve -- python -m my_mcp")
    if not args.path.startswith("/"):
        parser.error("--path must start with '/'")
    # The path is reflected into the quoted WWW-Authenticate resource_metadata
    # and the PRM JSON; reject characters that would break that quoting or
    # inject into headers.
    if any(c in args.path for c in ('"', "\r", "\n", " ")):
        parser.error("--path must not contain quotes, spaces, or CR/LF")

    # Env var is preferred (not visible in `ps`); an explicit flag wins but
    # warns. An empty token (flag or exported-but-empty env var) normalizes to
    # None = no auth, rather than enabling an impossible-to-satisfy gate.
    auth_token = args.auth_token
    if auth_token is not None:
        log(
            "warning: --auth-token is visible in `ps`; prefer "
            f"{_SERVE_TOKEN_ENV} for production"
        )
    else:
        auth_token = os.environ.get(_SERVE_TOKEN_ENV)
    if not auth_token:
        auth_token = None

    # --- embedded OAuth AS setup ---
    oauth = None
    if args.dev_user is not None and not args.enable_oauth:
        parser.error("--dev-user requires --enable-oauth")
    if args.allow_redirect_uri and not args.enable_oauth:
        parser.error("--allow-redirect-uri requires --enable-oauth")
    if args.token_store is not None and not args.enable_oauth:
        parser.error("--token-store requires --enable-oauth")
    if args.token_store is not None and not args.token_store.strip():
        parser.error("--token-store must not be empty")
    firestore_ref: tuple[str, str] | None = None
    if args.token_store_firestore is not None:
        if args.token_store is not None:
            parser.error(
                "--token-store and --token-store-firestore are mutually exclusive"
            )
        if not args.enable_oauth:
            parser.error("--token-store-firestore requires --enable-oauth")
        parts = args.token_store_firestore.split("/")
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            parser.error(
                "--token-store-firestore must be COLLECTION/DOCUMENT "
                f"(got {args.token_store_firestore!r})"
            )
        firestore_ref = (parts[0], parts[1])
    if args.trusted_user_header is not None and any(
        c in args.trusted_user_header for c in (" ", "\r", "\n", ":")
    ):
        parser.error("--trusted-user-header must be a valid header name")
    if args.access_token_ttl <= 0:
        parser.error("--access-token-ttl must be > 0")
    if args.modern_idle_ttl < 0 or not math.isfinite(args.modern_idle_ttl):
        parser.error("--modern-idle-ttl must be a non-negative, finite number")
    if args.cache_ttl_ms < 0:
        # The spec's only constraint on the value: "Servers MUST provide a
        # ttlMs value that is >= 0."
        parser.error("--cache-ttl-ms must be >= 0")
    if args.max_message_size < 0:
        parser.error("--max-message-size must be >= 0")
    if args.max_sessions < 1:
        parser.error("--max-sessions must be >= 1")
    if args.session_idle_ttl < 0 or not math.isfinite(args.session_idle_ttl):
        parser.error("--session-idle-ttl must be a non-negative, finite number")
    if args.max_sessions_per_owner < 0:
        parser.error("--max-sessions-per-owner must be >= 0")
    if args.user_env is not None:
        if not args.enable_oauth:
            parser.error("--user-env requires --enable-oauth")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.user_env):
            parser.error(
                "--user-env must be a valid environment variable name "
                "([A-Za-z_][A-Za-z0-9_]*)"
            )
        if args.user_env.upper() in _DANGEROUS_USER_ENV_NAMES:
            parser.error(
                f"--user-env {args.user_env!r} would replace a variable the "
                "child's own runtime needs to start (search path / dynamic "
                "linker); choose an application-specific name instead"
            )
    if args.enable_oauth:
        public_url = None
        if args.public_url is not None:
            try:
                public_url = _normalize_public_url(args.public_url)
            except ValueError as e:
                parser.error(f"--public-url invalid: {e}")
            if public_url != args.public_url.rstrip("/"):
                log(f"note: --public-url normalized to {public_url}")
        else:
            log(
                "warning: --enable-oauth without --public-url; the issuer is "
                "reflected from the request Host. Set --public-url behind a proxy."
            )
        if args.trusted_user_header is None and args.dev_user is None:
            log(
                "warning: --enable-oauth without --trusted-user-header or "
                "--dev-user; /authorize will deny all users (no identity source)."
            )
        if args.dev_user is not None:
            log("warning: --dev-user is INSECURE; for loopback testing only")
        try:
            allowed_redirect_uris = frozenset(
                _validate_allowed_redirect_uri(u) for u in args.allow_redirect_uri
            )
        except ValueError as e:
            parser.error(f"--allow-redirect-uri invalid: {e}")
        for u in allowed_redirect_uris:
            log(f"note: trusting exact redirect_uri {u!r} in addition to loopback")
        store_path = None
        store_lock_fd = None  # held (referenced) for the process lifetime
        if args.token_store is not None:
            store_path = Path(args.token_store).expanduser()
            try:
                # 0o700 like the client token-store directory: the file inside
                # is credential material, so directories WE create are tight
                # from the start (a pre-existing parent is left untouched).
                _mkdir_private(store_path.parent)
            except OSError as e:
                parser.error(f"--token-store: cannot create parent directory: {e}")
            try:
                store_lock_fd = _acquire_store_lock(store_path)
            except OSError:
                parser.error(
                    f"--token-store: {store_path} is already in use by "
                    "another serve process (each process needs its own path; "
                    "sharing one store silently clobbers issued tokens)"
                )
            log(
                f"note: persisting issued OAuth state to {store_path} "
                "(credential material; created 0600)"
            )
        if firestore_ref is not None:
            log(
                f"note: persisting issued OAuth state to Firestore "
                f"{firestore_ref[0]}/{firestore_ref[1]} (credential "
                "material; writes merge via a transaction, so brief "
                "overlap between two writers is tolerated)"
            )
        try:
            oauth = _OAuthProvider(
                public_url=public_url,
                trusted_user_header=args.trusted_user_header,
                dev_user=args.dev_user,
                access_ttl=float(args.access_token_ttl),
                allowed_redirect_uris=allowed_redirect_uris,
                store_path=store_path,
                firestore_ref=firestore_ref,
            )
        except _FirestoreReadError as e:
            # A transient read failure (network blip, momentary permission
            # error) must abort startup rather than be treated like a
            # missing document: __init__ -> _load_state would otherwise
            # start empty, and the persist_now() call a few lines below
            # would then happily overwrite the (unread, but very much
            # still real) document with that empty snapshot, permanently
            # destroying every previously issued token. A genuinely
            # missing document (snapshot.exists is False) is NOT this
            # path -- that is the normal "clean first start."
            parser.error(f"--token-store-firestore: {e}")
        if store_path is not None:
            oauth._store_lock_fd = store_lock_fd
            # Fail fast on an unwritable store (existing directory, read-only
            # filesystem, empty-basename path): the first mutation-time write
            # would otherwise soft-fail into in-memory-only mode right after
            # the startup log promised persistence.
            try:
                oauth.persist_now()
            except Exception as e:
                parser.error(f"--token-store: cannot write {store_path}: {e}")
        if firestore_ref is not None:
            # Same fail-fast rationale as --token-store above: a missing
            # google-cloud-firestore package, an unreachable project, or a
            # permissions error should abort startup, not silently degrade
            # to in-memory-only after promising persistence in the log line
            # just printed.
            try:
                oauth.persist_now()
            except Exception as e:
                parser.error(
                    f"--token-store-firestore: cannot write "
                    f"{firestore_ref[0]}/{firestore_ref[1]}: {e}"
                )

    serve(
        command,
        host=args.host,
        port=args.port,
        mcp_path=args.path,
        auth_token=auth_token,
        oauth=oauth,
        max_sessions=args.max_sessions,
        idle_ttl=args.session_idle_ttl,
        max_sessions_per_owner=args.max_sessions_per_owner,
        cache_ttl_ms=args.cache_ttl_ms,
        modern_idle_ttl=args.modern_idle_ttl,
        modern_only=args.modern_only,
        user_env_var=args.user_env,
        max_message_size=args.max_message_size,
    )
