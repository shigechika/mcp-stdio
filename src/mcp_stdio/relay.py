"""Core relay logic: stdin JSON-RPC -> HTTP POST -> stdout."""

from __future__ import annotations

import base64
import copy
import email.utils
import json
import math
import re
import signal
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit
from urllib.request import parse_http_list, parse_keqv_list

import httpx

from mcp_stdio import __version__

MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds

# HTTP 429 rate-limit handling. If the server sends ``Retry-After`` we
# honour it up to the cap; beyond the cap we give up rather than make the
# client hang on an unreasonable server-requested wait. Missing
# ``Retry-After`` falls back to the same linear backoff used for
# transient connection errors. Closes the gap called out by
# modelcontextprotocol/typescript-sdk#1892.
_RATE_LIMIT_SLEEP_CAP_SECS = 60.0

# Status codes whose ``Retry-After`` we honour for a backoff-and-retry, and
# whose final value we surface as ``error.data.retryAfter`` when we give up.
# Both are spec-sanctioned Retry-After carriers (RFC 9110 §10.2.3 lists 503
# alongside 429). 429 Too Many Requests (RFC 6585 §4) is rate limiting and
# means the request was rejected at the gate, so replaying the non-idempotent
# POST is genuinely safe — no server-side work happened. 503 Service
# Unavailable (RFC 9110 §15.6.4) is a weaker guarantee: it means the server is
# *currently unable* to handle the request (transient overload / maintenance),
# which usually but does not STRICTLY guarantee no side effect occurred (a
# server could begin work, hit overload, then answer 503). We still replay it —
# retrying 503 on POST is conventional and the partial-work case is rare — but
# a server that performs non-idempotent work before it can answer 503 could see
# a duplicated effect after replay. Accepted as the conventional tradeoff.
_RETRYABLE_RATE_LIMIT_STATUSES = (429, 503)

# TCP keepalive tuning. Together (60 s idle + 4 × 15 s probes) a silent
# half-open TCP is surfaced as a socket error within ~120 s — fast enough
# to matter during a long tool call, slow enough to tolerate transient
# network blips. Used by ``_tcp_keepalive_socket_options`` below.
_KEEPALIVE_IDLE_SECS = 60
_KEEPALIVE_INTVL_SECS = 15
_KEEPALIVE_CNT = 4


def _tcp_keepalive_socket_options() -> list[tuple[int, int, int]]:
    """Return a cross-platform socket_options list for TCP keepalive.

    Portable baseline: ``SO_KEEPALIVE`` is enabled on every platform that
    supports it. The detailed idle/interval/count tuning uses platform
    branches:

    - **Linux / FreeBSD / NetBSD** — expose ``TCP_KEEPIDLE`` /
      ``TCP_KEEPINTVL`` / ``TCP_KEEPCNT`` via ``socket``. Numeric
      constant values differ across OSes but Python resolves them
      correctly per platform, so the same three tuples apply.
    - **macOS** — ``TCP_KEEPALIVE`` sets the idle time; ``TCP_KEEPINTVL``
      and ``TCP_KEEPCNT`` were added in macOS 10.15 and are used when
      available.
    - **Windows** — per-socket idle/interval tuning requires the
      ``SIO_KEEPALIVE_VALS`` ioctl which httpx's ``socket_options``
      mechanism cannot deliver. We set ``SO_KEEPALIVE`` alone; the
      OS default probe interval (~2 h) still beats the current
      forever-hang on a half-open TCP. Half-open detection under
      Windows requires an out-of-band mechanism (e.g. MCP ``ping``)
      for tighter bounds.

    Always includes ``SO_KEEPALIVE`` so the returned list is never
    empty; callers can therefore treat the absence of a keepalive
    entry as "the caller opted out" rather than "the platform is
    unsupported".
    """
    opts: list[tuple[int, int, int]] = [
        (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
    ]
    plat = sys.platform
    if plat == "linux" or plat.startswith("freebsd") or plat.startswith("netbsd"):
        for name in ("TCP_KEEPIDLE", "TCP_KEEPINTVL", "TCP_KEEPCNT"):
            if not hasattr(socket, name):
                return opts
        opts += [
            (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, _KEEPALIVE_IDLE_SECS),
            (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, _KEEPALIVE_INTVL_SECS),
            (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, _KEEPALIVE_CNT),
        ]
    elif plat == "darwin":
        # TCP_KEEPALIVE is the idle timer on darwin; without it, the
        # interval / count options alone are meaningless. Guard
        # consistently with the Linux branch above.
        if not hasattr(socket, "TCP_KEEPALIVE"):
            return opts
        opts.append((socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, _KEEPALIVE_IDLE_SECS))
        if hasattr(socket, "TCP_KEEPINTVL"):
            opts.append(
                (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, _KEEPALIVE_INTVL_SECS)
            )
        if hasattr(socket, "TCP_KEEPCNT"):
            opts.append((socket.IPPROTO_TCP, socket.TCP_KEEPCNT, _KEEPALIVE_CNT))
    # win32 / cygwin / other: only SO_KEEPALIVE. See docstring.
    return opts


def _make_httpx_transport(*, tcp_keepalive: bool) -> httpx.HTTPTransport:
    """Build the HTTPTransport used by relay clients.

    Injects TCP keepalive socket options unless the caller opted out.
    Isolated as a helper so tests can patch it and both ``run`` and
    ``run_sse`` share the same transport construction.
    """
    socket_options = _tcp_keepalive_socket_options() if tcp_keepalive else None
    return httpx.HTTPTransport(socket_options=socket_options)


# MCP spec defines four paginated list methods. Some clients (notably
# Claude Code, cf. anthropics/claude-code#39586) silently drop pages beyond
# the first; auto-paginating in the gateway hides the bug from callers.
PAGINATED_LIST_METHODS: dict[str, str] = {
    "tools/list": "tools",
    "resources/list": "resources",
    "resources/templates/list": "resourceTemplates",
    "prompts/list": "prompts",
}

# Safety cap for runaway or malicious cursor chains.
MAX_LIST_PAGES = 100


def _enforce_lf_stdio() -> None:
    """Force bare LF line endings on stdin/stdout.

    Python's default ``TextIOWrapper`` on Windows translates ``\\n`` to
    ``\\r\\n`` on output, which corrupts the NDJSON wire format used by
    MCP. A no-op on POSIX where LF is already the default. See
    modelcontextprotocol/python-sdk#2433 for the same class of bug.
    """
    if sys.platform != "win32":
        return
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(newline="")


_enforce_lf_stdio()


# Matches the userinfo of a URL: the ``//user:pass@`` between the scheme
# separator and the host. Anchored on the literal ``://`` and a required
# trailing ``@`` with a single non-backtracking ``[^/@\s]*`` in between, so it
# stays linear (no polynomial-ReDoS from a greedy scheme prefix scanned at
# every position).
_USERINFO_RE = re.compile(r"://[^/@\s]*@")


def scrub_secrets(text: str) -> str:
    """Strip URL userinfo from arbitrary text before it is logged.

    Direct URL logging goes through ``redact_url``, but URLs also reach the
    log via exception messages (httpx puts ``request.url`` — including any
    ``user:pass@`` userinfo — into its error text). This backstop removes the
    userinfo from any URL embedded anywhere in a log line.
    """
    return _USERINFO_RE.sub("://", text)


def log(msg: str) -> None:
    """Log to stderr (visible in Claude Desktop/Code logs)."""
    print(f"[mcp-stdio] {scrub_secrets(msg)}", file=sys.stderr, flush=True)


def redact_url(url: str) -> str:
    """Return a URL safe for logging: strip userinfo and query.

    The upstream URL may carry credentials (``https://user:pass@host`` or a
    bearer token in the query string), so we log only scheme/host/port/path.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port  # SplitResult.port raises ValueError on a bad port
    except ValueError:
        return "<url>"
    if ":" in host:  # IPv6 literal — .hostname drops the brackets, restore them
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    suffix = "?<redacted>" if parts.query else ""
    return f"{parts.scheme}://{netloc}{parts.path}{suffix}"


# Serializes writes to stdout. ``run_sse`` drives two writers — the SSE
# reader thread (message events via ``_emit``) and the main loop (error
# responses) — and ``print`` is not atomic across the content and its
# trailing newline, so without this lock a POST error coinciding with a
# message event could interleave mid-line and corrupt the NDJSON wire
# format. ``run`` drives concurrent writers too: the cold-start daemon's
# gate-lift ``list_changed`` notifications (#296) and the modern era's
# ``subscriptions/listen`` reader thread (#270 Phase 2) both ``_emit``
# concurrently with the stdin loop, so the lock is load-bearing on both
# transports.
_STDOUT_LOCK = threading.Lock()


def _write_line(line: str) -> None:
    """Write one line to stdout atomically (content + newline under a lock)."""
    with _STDOUT_LOCK:
        sys.stdout.write(f"{line}\n")
        sys.stdout.flush()


def _extract_id_and_presence(line: str) -> tuple[Any, bool]:
    """Return ``(id_value, has_id)`` from a SINGLE JSON parse of a line.

    The relay's per-stdin-line hot path needs both the id value AND whether an
    ``id`` key is present (a notification has none and must never receive a
    response), so this parses once rather than re-walking the JSON twice under
    load. A present ``id:null`` (a request) is distinguished from an absent id
    (a notification). A notification (no id) → ``(None, False)``; a request →
    ``(id, True)``; a non-object / unparseable line → ``(None, False)`` (no
    response synthesized).
    """
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None, False
    if not isinstance(msg, dict):
        return None, False
    return msg.get("id"), "id" in msg


_DEFAULT_SCHEME_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def _same_origin(url_a: str, url_b: str) -> bool:
    """Return True if two URLs share an RFC 6454 origin (scheme/host/port)."""
    try:
        a, b = urlsplit(url_a), urlsplit(url_b)
        oa = (
            a.scheme,
            (a.hostname or "").lower(),
            a.port if a.port is not None else _DEFAULT_SCHEME_PORTS.get(a.scheme),
        )
        ob = (
            b.scheme,
            (b.hostname or "").lower(),
            b.port if b.port is not None else _DEFAULT_SCHEME_PORTS.get(b.scheme),
        )
    except ValueError:
        return False
    return oa == ob


# MCP-Protocol-Version header (spec rev 2025-06-18, "Protocol Version Header").
# After initialization the client MUST send the negotiated protocol version on
# every subsequent HTTP request; servers that enforce it return 400 when it is
# absent. The header is a Streamable-HTTP-era construct — it is absent from the
# 2025-03-26 spec and from the 2024-11-05 legacy SSE transport — so it is
# injected on the Streamable HTTP path (``run``) only. A cheap regex pre-check
# gates the slow json.loads, mirroring ``_CANCELLED_METHOD_RE``.
_INITIALIZE_METHOD_RE = re.compile(r'"method"\s*:\s*"initialize"')


def _looks_like_initialize(line: str) -> bool:
    """Return True if ``line`` looks like a JSON-RPC ``initialize`` request.

    A cheap pre-filter so the relay only attempts to capture the negotiated
    protocol version from initialize responses. The trailing quote in the
    pattern means ``notifications/initialized`` does not match.

    Pre-filter ONLY: this is a substring regex, so a ``tools/call`` whose nested
    ``arguments`` merely contains a ``"method":"initialize"`` key also matches.
    That is fine for the response-capture use (over-triggering it is harmless —
    a non-initialize response carries no ``result.protocolVersion``), but a
    request-header MUTATION must NOT key off this; use ``_is_initialize_request``.
    """
    return bool(_INITIALIZE_METHOD_RE.search(line))


def _is_initialize_request(line: str) -> bool:
    """Authoritatively confirm ``line`` is a JSON-RPC ``initialize`` REQUEST.

    Parses the line and checks the TOP-LEVEL ``method``, mirroring
    ``_normalize_null_arguments`` / ``_detect_paginated_list``. Unlike the
    ``_looks_like_initialize`` regex pre-filter, a ``tools/call`` whose nested
    ``arguments`` contains a ``"method":"initialize"`` substring does NOT
    false-positive here — so this is safe to gate the request-header strip on,
    where a false positive would wrongly drop MCP-Protocol-Version from a real
    tool call and break it against a strict 2025-06-18 server. The cheap regex
    still short-circuits the parse for the common non-matching line.
    """
    if not _INITIALIZE_METHOD_RE.search(line):
        return False
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return False
    return isinstance(msg, dict) and msg.get("method") == "initialize"


def _extract_protocol_version(payload: str) -> str | None:
    """Return ``result.protocolVersion`` from an InitializeResult, else None.

    Accepts the JSON-RPC response payload (the text after ``data: `` for an
    SSE-framed response, or the whole JSON body otherwise). Returns None for
    anything that is not an object carrying a string ``result.protocolVersion``.
    """
    try:
        msg = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(msg, dict):
        return None
    result = msg.get("result")
    if not isinstance(result, dict):
        return None
    pv = result.get("protocolVersion")
    # Validate before this value can be injected as the MCP-Protocol-Version
    # request header on every subsequent request. Unlike
    # Mcp-Session-Id (an HTTP RESPONSE header h11 already vets for CR/LF), this
    # comes from the JSON BODY and bypasses all header validation — a malicious /
    # buggy server returning "2025-06-18\r\nEvil: 1" (or a NUL) would otherwise
    # poison the header, and httpx's send-time LocalProtocolError would brick the
    # session permanently, breaking the #11 never-crash invariant. Restrict to a
    # non-empty visible-ASCII token (0x21-0x7E: no control / CR / LF / NUL /
    # space), which every real date-form protocolVersion satisfies; anything else
    # degrades to None so the header is simply omitted (server assumes default).
    if isinstance(pv, str) and pv and all(0x21 <= ord(c) <= 0x7E for c in pv):
        return pv
    return None


# --- modern (spec rev 2026-07-28) dispatch path ---
#
# The 2026-07-28 revision removes the initialize handshake and
# Mcp-Session-Id from the wire entirely: every request instead carries its
# own per-request metadata (protocol version, capabilities, ...) as
# ``params._meta``, plus two new REQUIRED-on-every-POST headers. Everything
# in this section is used ONLY when the relay has resolved (or been forced
# via --protocol-era) onto that modern path — see ``run()``'s ``era``
# variable. The legacy path (spec rev 2025-06-18 and earlier) is completely
# untouched by any of this: it neither calls nor imports from here, so it
# stays byte-identical to pre-#270 behaviour (acceptance criterion #3).

# Default protocol version to advertise on the modern path when nothing
# better is known (no server/discover ever ran, or it returned no
# supportedVersions, or the local client's initialize omitted
# protocolVersion). This is this relay's own floor for "definitely modern",
# mirroring how "2024-11-05" already serves as the floor on the legacy path
# (_cold_start_response, _reinitialize).
_MODERN_PROTOCOL_VERSION_DEFAULT = "2026-07-28"

# The modern protocol revisions this relay actually IMPLEMENTS. Everything
# the modern dispatch path emits — the server/discover lifecycle,
# per-request ``Mcp-Method``/``Mcp-Name`` headers, ``params._meta``
# injection — is written against spec rev 2026-07-28, so that is the only
# member today. Upstream version negotiation
# (``_negotiate_modern_version``) selects EXCLUSIVELY from this set:
# "date-form and >= the floor" proves only which ERA a version belongs to,
# not that this relay speaks its wire semantics, and using era membership
# as the eligibility rule falsely negotiated future revisions the relay
# does not implement (#350 review round 9, finding 9-1). Add a revision
# here ONLY when the modern path's wire behavior has actually been updated
# to conform to it.
_RELAY_IMPLEMENTED_MODERN_VERSIONS = frozenset({_MODERN_PROTOCOL_VERSION_DEFAULT})

# Fallback ``serverInfo`` used by ``_handle_modern_special_method`` ONLY when
# the era-detection ``server/discover`` probe never yielded a real one (probe
# failed transport-level, or returned a recognized-modern JSON-RPC error with
# no result, or a compliant server simply chose not to send the SHOULD-only
# ``_meta.serverInfo`` field). The design goal (#270 revision comment) is to
# source ``serverInfo`` from real discover data "instead of inventing a
# placeholder" — this name is deliberately NOT a bare ``"mcp-stdio"`` (which
# would misrepresent this relay's own identity AS the remote server's
# self-reported identity, the exact thing #270 says not to do) but says
# plainly that the real upstream identity is unknown, while still naming the
# relay for troubleshooting. ``serverInfo`` is spec-documented as
# "self-reported... intended for display, logging, and debugging" (server/
# discover, "DiscoverResult") — never used for behavior/security decisions —
# so an honestly-labelled placeholder here is display-only degraded-mode
# behavior, not a protocol violation, as long as it does not claim to BE the
# remote's own report.
_UNKNOWN_UPSTREAM_SERVER_INFO = {
    "name": "mcp-stdio (upstream identity unknown)",
    "version": __version__,
}

# _meta keys mirrored per request/result on the modern path (spec rev
# 2026-07-28, clientInfo/serverInfo revision comment of 2026-07-27 — see the
# table in the issue: protocolVersion and clientCapabilities are REQUIRED;
# clientInfo is a SHOULD (never fabricated — see _handle_modern_special_method);
# serverInfo appears on RESULTS, nested under this same namespace, not as a
# top-level field (confirmed against server/discover's own worked example).
_META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
_META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
_META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
_META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
# Amendment added 2026-07-27: mirror a client-set logging level into _meta on
# the modern path (there is no other per-request channel for it now that
# initialize/session state is gone). See _extract_log_level.
_META_LOG_LEVEL = "io.modelcontextprotocol/logLevel"
# Correlation key a modern server stamps on every notification delivered
# over a subscriptions/listen stream (spec rev 2026-07-28, subscriptions
# pattern). Relay-internal: stripped before a forwarded notification
# reaches the legacy stdio client (see _strip_listen_subscription_id).
_META_SUBSCRIPTION_ID = "io.modelcontextprotocol/subscriptionId"

# Client capability keys whose MODERN semantics this Phase 1 relay cannot
# bridge (#350 review round 10, finding 10-1). Spec rev 2026-07-28
# (SEP-2322) REPLACED the server-initiated ``sampling``/``elicitation``/
# ``roots`` round-trips these keys advertise with MRTR: a server needing
# client input answers the request itself with an ``InputRequiredResult``
# (``resultType: "input_required"``) that the client must satisfy by
# re-issuing the request with ``inputResponses``. Translating that exchange
# back into the legacy server-initiated requests a 2025-era stdio client
# understands is #270's explicitly-phased Phase 2 work — so forwarding these
# keys upstream in ``_meta``'s ``clientCapabilities`` would ADVERTISE flows
# this relay cannot deliver: a modern server, told the client supports them,
# may legitimately answer e.g. a ``tools/call`` with an MRTR result that
# Phase 1 forwards verbatim to a client that cannot answer it (misread as an
# oddly-shaped success, or a hang). Stripping the keys at CAPTURE time
# (``_handle_modern_special_method``'s ``initialize`` interception) removes
# the invitation at every downstream use in one place — per-request
# ``_meta`` injection AND the reseed re-probe's advertised capabilities —
# and makes the reseed's "client has real capabilities" condition naturally
# correct for a client whose ONLY capabilities are un-bridgeable ones.
# Every other key (notably ``experimental``, and any future additions) does
# not map to an MRTR-replaced flow and passes through untouched. Remove
# entries here only when Phase 2 actually bridges the corresponding flow.
_MRTR_REPLACED_CLIENT_CAPABILITIES = frozenset({"sampling", "elicitation", "roots"})

# MCP request metadata headers (spec rev 2026-07-28, "Request Metadata",
# SEP-2243). Every Streamable HTTP POST on the modern path mirrors the
# request's `method` into an `Mcp-Method` header; `tools/call` /
# `resources/read` / `prompts/get` additionally mirror `params.name` (or
# `params.uri` for resources/read) into `Mcp-Name`. Sent ONLY on the modern
# path — see the module docstring above and _prepare_headers in run().
# `x-mcp-header` / `Mcp-Param-{Name}` (custom per-tool headers mirrored from
# `inputSchema` annotations) is a separate, materially larger feature — it
# requires caching each tool's schema from `tools/list` responses to know
# which call arguments to mirror — and is deliberately out of scope here.
#
# Batches: MCP removed JSON-RPC batching in spec rev 2025-06-18, and a batch
# has no single top-level `method` to mirror, so `_extract_method_and_name`
# only recognises a top-level JSON object; an array (or unparseable content)
# yields `(None, None)` and the caller sends neither header.
_NAME_BEARING_METHODS = {
    "tools/call": "name",
    "resources/read": "uri",
    "prompts/get": "name",
}


def _extract_method_and_name(line: str) -> tuple[str | None, str | None]:
    """Return ``(method, name_or_uri)`` for the ``Mcp-Method``/``Mcp-Name`` headers.

    ``name_or_uri`` is populated only for the three methods
    ``_NAME_BEARING_METHODS`` lists; every other method (``tools/list``, the
    plain list methods, notifications, ...) returns ``(method, None)`` so the
    caller sends ``Mcp-Method`` alone, matching the spec's "Required For"
    column.
    """
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None, None
    if not isinstance(msg, dict):
        return None, None  # batch array, or a scalar — no single method
    method = msg.get("method")
    if not isinstance(method, str):
        return None, None
    name_key = _NAME_BEARING_METHODS.get(method)
    if name_key is None:
        return method, None
    params = msg.get("params")
    if not isinstance(params, dict):
        return method, None
    value = params.get(name_key)
    return method, value if isinstance(value, str) else None


_BASE64_SENTINEL_RE = re.compile(r"\A=\?base64\?.*\?=\Z", re.DOTALL)


def _is_header_safe_ascii(value: str) -> bool:
    """True if ``value`` can ride an HTTP header verbatim, unencoded.

    Per RFC 9110 field-value syntax (spec rev 2026-07-28 "Value Encoding"),
    the safe set is visible ASCII (0x21-0x7E) plus space (0x20) and
    horizontal tab (0x09) — but the spec additionally forbids
    leading/trailing whitespace even though the wire grammar would allow it,
    so a value with either is NOT header-safe here and must be encoded.
    """
    if not value:
        return True
    if value[0] in (" ", "\t") or value[-1] in (" ", "\t"):
        return False
    return all(c in (" ", "\t") or 0x21 <= ord(c) <= 0x7E for c in value)


def _encode_mcp_name(value: str) -> str:
    """Encode a ``Mcp-Name`` header value per spec rev 2026-07-28 Value Encoding.

    A plain ASCII value with no leading/trailing whitespace, that does not
    itself look like the sentinel, rides verbatim. Everything else —
    non-ASCII, control characters, leading/trailing whitespace, or a value
    that would otherwise be mistaken for an already-encoded sentinel — is
    Base64-encoded as ``=?base64?{...}?=``: the exact literal markers the
    spec mandates (lowercase, no charset segment — unlike MIME
    encoded-words). ``Mcp-Method`` must NOT go through this encoder: the
    sentinel is defined only for ``Mcp-Name`` / ``Mcp-Param-{Name}`` — the
    "Server Validation" section requires servers to decode exactly those two
    before comparing against the body, so an encoded ``Mcp-Method`` would
    fail header-body validation (-32020 ``HeaderMismatch``) on a compliant
    server. A JSON-RPC ``method`` that is not itself header-safe therefore
    cannot be mirrored at all and is rejected before dispatch (#350 review
    round 5, finding 5-2 — see the gate in ``run()``'s modern branch).
    """
    if _is_header_safe_ascii(value) and not _BASE64_SENTINEL_RE.match(value):
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


def _mcp_request_headers(line: str) -> dict[str, str]:
    """Build the ``Mcp-Method``/``Mcp-Name`` headers for one dispatched line.

    Returns ``{}`` for a batch / unparseable / methodless line — there is no
    single method to mirror. Used only on the modern path (see run()'s
    ``_prepare_headers``). ``method`` rides verbatim: a non-header-safe
    method never reaches this builder — run()'s modern branch rejects it
    before dispatch, because the Base64 sentinel escape is spec-defined only
    for ``Mcp-Name``/``Mcp-Param-{Name}``, never ``Mcp-Method`` (#350 review
    round 5, finding 5-2 — see ``_encode_mcp_name``'s docstring).
    """
    method, name = _extract_method_and_name(line)
    if method is None:
        return {}
    headers = {"Mcp-Method": method}
    if name is not None:
        headers["Mcp-Name"] = _encode_mcp_name(name)
    return headers


_SET_LEVEL_METHOD_RE = re.compile(r'"method"\s*:\s*"logging/setLevel"')


def _extract_log_level(line: str) -> str | None:
    """Return ``params.level`` from a ``logging/setLevel`` REQUEST, else None.

    Tracked on BOTH eras — this is a cheap regex-gated READ, it never mutates
    what is forwarded, so calling it unconditionally in run()'s loop cannot
    change the legacy path's wire bytes. The captured level feeds the modern
    path's ``io.modelcontextprotocol/logLevel`` _meta (amendment added
    2026-07-27): a level set while the session was still on/resolving to
    legacy is not lost if a later request needs it mirrored. The legacy
    path's own forwarding of the raw ``logging/setLevel`` request is
    completely unaffected — this function never rewrites the line.
    """
    if not _SET_LEVEL_METHOD_RE.search(line):
        return None
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(msg, dict) or msg.get("method") != "logging/setLevel":
        return None
    params = msg.get("params")
    if not isinstance(params, dict):
        return None
    level = params.get("level")
    return level if isinstance(level, str) and level else None


def _negotiate_modern_version(requested: str | None, supported: list[str]) -> str:
    """Pick the ``MCP-Protocol-Version`` to advertise UPSTREAM on the modern
    path (request headers and ``params._meta``) — the actual wire version
    the remote server understands, NOT what is echoed back to the local
    stdio client (that is the client's own requested string, verbatim —
    see ``_handle_modern_special_method``, #350 review round 3).

    Only versions this relay IMPLEMENTS are eligible
    (``_RELAY_IMPLEMENTED_MODERN_VERSIONS``), which rules out BOTH
    directions of over-claim:

    - LEGACY strings (#350 review round 7): everything else this dispatch
      path does — no ``initialize`` handshake, no ``Mcp-Session-Id``,
      per-request ``Mcp-Method``/``_meta`` — is the 2026-07-28 stateless
      lifecycle, and a legacy version string on top of that wire shape is
      incoherent. A dual-mode server advertising both ``2025-06-18`` and
      ``2026-07-28`` while the local legacy client requests ``2025-06-18``
      must still get a modern version upstream.
    - FUTURE modern revisions (#350 review round 9, finding 9-1): round 7
      used era membership ("date-form and >= the floor") as the
      eligibility rule, but that proves only which ERA a version belongs
      to, not that this relay speaks its wire semantics — a server
      advertising ``["2026-07-28", "2027-01-01"]`` was answered with
      ``max()`` = ``2027-01-01``, falsely negotiating a revision whose
      (potentially incompatible) requirements this relay does not
      implement. Exact set membership also subsumes round 7's date-form
      shape check: a non-compliant server's ``"zzz"`` can never be a
      member, ASCII ordering notwithstanding.

    Selection: the client's requested version wins when it is advertised
    AND implemented; otherwise the highest advertised-and-implemented
    version; with an EMPTY intersection (a probe that never ran, a
    legacy-only ``supportedVersions``, or a future-only one), an
    implemented requested version, then this relay's own floor
    (``_MODERN_PROTOCOL_VERSION_DEFAULT``). Advertising a version the
    relay actually speaks and letting a future-only server reject it with
    ``UnsupportedProtocolVersionError`` (-32022) is honest; claiming wire
    semantics the relay does not implement is not.
    """
    eligible = [v for v in supported if v in _RELAY_IMPLEMENTED_MODERN_VERSIONS]
    if requested and requested in eligible:
        return requested
    if eligible:
        return max(eligible)
    if requested and requested in _RELAY_IMPLEMENTED_MODERN_VERSIONS:
        return requested
    return _MODERN_PROTOCOL_VERSION_DEFAULT


class _ModernState:
    """Per-session state for the modern (spec rev 2026-07-28) dispatch path.

    ``server_info`` / ``capabilities`` / ``supported_versions`` are seeded
    once from the era-detection ``server/discover`` probe (see
    ``_probe_protocol_era``) — plus at most ONE reseed retry when that
    probe left ``capabilities`` empty and the local client's real,
    non-empty capabilities have since become known
    (``discover_retry_attempted`` latches the attempt so it can never
    repeat — see ``_handle_modern_special_method``, #350 review rounds 4 +
    9). ``client_capabilities`` / ``client_info`` /
    ``negotiated_version`` are captured once from the local stdio client's
    own ``initialize`` request (see ``_handle_modern_special_method`` — the
    modern path never forwards that request upstream, so this is the only
    place those values are ever seen). ``client_capabilities`` holds the
    client's set MINUS the MRTR-replaced keys this Phase 1 relay cannot
    bridge (``_MRTR_REPLACED_CLIENT_CAPABILITIES``, #350 review round 10,
    finding 10-1) — every upstream advertisement reads this field, so the
    filter applies once, here. ``log_level`` is updated on every
    ``logging/setLevel`` line regardless of era (see ``_extract_log_level``).

    A single plain object (no lock): ``run()``'s stdin loop dispatches one
    line at a time, fully synchronously, on both eras — including the
    modern path (Phase 1 implements the "don't forward
    notifications/cancelled upstream" half of cancellation, AC #5's easy
    half; actually ABORTING an in-flight POST when a cancel arrives would
    require a second thread reading stdin concurrently with a blocking
    dispatch, which is deliberately deferred: several
    single-threaded-mutation invariants elsewhere in ``run()`` —
    ``protocol_version``, the 401/403/404 recovery ladder — depend on "at
    most one dispatch in flight" and would need re-auditing first).
    """

    __slots__ = (
        "server_info",
        "capabilities",
        "supported_versions",
        "client_capabilities",
        "client_info",
        "negotiated_version",
        "log_level",
        "discover_retry_attempted",
    )

    def __init__(self) -> None:
        self.server_info: dict[str, Any] | None = None
        self.capabilities: dict[str, Any] = {}
        self.supported_versions: list[str] = []
        self.client_capabilities: dict[str, Any] | None = None
        self.client_info: dict[str, Any] | None = None
        self.negotiated_version: str | None = None
        self.log_level: str | None = None
        self.discover_retry_attempted: bool = False


def _seed_modern_state_from_discover(
    modern_state: "_ModernState", discover_result: dict[str, Any] | None
) -> None:
    """Populate ``modern_state`` from a parsed ``server/discover`` response.

    A no-op (state keeps its empty defaults) when ``discover_result`` is
    ``None`` (probe failed / forced ``--protocol-era modern`` skipped or
    could not parse the probe) or is a JSON-RPC error rather than a result —
    the synthesized InitializeResult then falls back to
    ``_UNKNOWN_UPSTREAM_SERVER_INFO`` / empty capabilities / the client's own
    requested version. That fallback name says plainly that the real
    upstream identity is unknown (see ``_UNKNOWN_UPSTREAM_SERVER_INFO``'s own
    comment) — never a bare ``"mcp-stdio"`` that would misrepresent this
    relay's identity AS the remote's self-reported one, which is exactly
    what the #270 design says not to do ("source it from real discover data
    instead of inventing a placeholder").

    Seeding never ERASES (#350 review round 9, finding 9-2): the reseed
    retry can now fire with ``server_info``/``supported_versions`` already
    seeded by the startup probe (it re-runs whenever ``capabilities`` came
    back empty, not only when nothing seeded at all), so a reseed payload
    that omits a field — or answers it with an empty ``{}``/``[]`` — must
    keep the previously-seeded value rather than clobber it back to a
    default. Skipping an empty value is lossless on the FIRST seed too:
    the state's own defaults are exactly those empty values.
    """
    if not isinstance(discover_result, dict):
        return
    result = discover_result.get("result")
    if not isinstance(result, dict):
        return
    caps = result.get("capabilities")
    if isinstance(caps, dict) and caps:
        modern_state.capabilities = caps
    versions = result.get("supportedVersions")
    if (
        isinstance(versions, list)
        and versions
        and all(isinstance(v, str) for v in versions)
    ):
        modern_state.supported_versions = versions
    meta = result.get("_meta")
    if isinstance(meta, dict):
        server_info = meta.get(_META_SERVER_INFO)
        if isinstance(server_info, dict):
            modern_state.server_info = server_info


# Base Protocol "Error Codes" (spec rev 2026-07-28): JSON-RPC 2.0 reserves
# -32000..-32099 for implementation-defined server errors. This revision
# partitions that range further: -32000..-32019 is legacy/grandfathered
# (no new allocations), while -32020..-32099 is "reserved for the MCP
# specification... defined exclusively by the MCP specification" — currently
# -32020 (HeaderMismatch), -32021 (MissingRequiredClientCapability), -32022
# (UnsupportedProtocolVersion). Standard pre-existing JSON-RPC codes such as
# -32601 (Method not found) are OUTSIDE this range entirely (they predate
# the -32000..-32099 implementation-defined range's own sub-partitioning),
# so they can never be mistaken for a spec-defined modern error by range
# membership alone.
_MCP_RESERVED_ERROR_CODES = range(-32099, -32019)


def _is_recognized_modern_error(parsed: dict[str, Any] | None) -> bool:
    """True iff ``parsed`` is a JSON-RPC error object whose ``error.code``
    falls in ``_MCP_RESERVED_ERROR_CODES`` (see that constant's comment for
    the exact spec citation) — i.e. a "recognized modern JSON-RPC error" in
    the sense used by the Streamable HTTP "Backward Compatibility" section.

    A generic/pre-existing JSON-RPC code such as ``-32601`` (``Method not
    found``) sits outside that sub-range and is exactly what an unmodified
    LEGACY server would send for an unrecognized ``server/discover`` method
    — over HTTP 400 by some servers' conventions, or HTTP 200 by others
    (JSON-RPC-over-HTTP commonly returns 200 with the error in the body).
    Neither counts as proof the remote speaks a modern version of MCP.
    Shared by ``_probe_protocol_era``'s HTTP 200 and HTTP 400 paths so both
    are judged by the identical rule.
    """
    if not isinstance(parsed, dict):
        return False
    error = parsed.get("error")
    if not isinstance(error, dict):
        return False
    code = error.get("code")
    return isinstance(code, int) and code in _MCP_RESERVED_ERROR_CODES


def _build_discover_probe_request(
    headers: dict[str, str],
    request_id: int = 0,
    modern_state: "_ModernState | None" = None,
) -> tuple[str, dict[str, str]]:
    """Build the body + headers for a spec-compliant ``server/discover`` probe.

    Shared by ``_probe_protocol_era`` (the ``auto``/``modern`` startup probe),
    ``check_connection``'s discover retry, and ``_reseed_discover_probe``
    (the one-shot post-initialize reseed, #350 review round 4), so all send
    byte-identical request shapes instead of independently-drifting probes
    (#350 review finding 1).

    Body: ``server/discover``'s own worked example (spec rev 2026-07-28,
    "Discovery") carries ``params._meta`` with
    ``io.modelcontextprotocol/protocolVersion`` and
    ``.../clientCapabilities`` even on this very first, pre-negotiation
    request — neither field requires prior knowledge of the remote (the
    version is this relay's own advertised floor, capabilities are the
    client's own, always-known set). Reusing ``_inject_modern_meta`` against
    a throwaway, never-seeded ``_ModernState()`` produces exactly that:
    ``negotiated_version`` falls back to ``_MODERN_PROTOCOL_VERSION_DEFAULT``
    and ``client_capabilities`` falls back to ``{}`` — the same defaults
    ``_prepare_headers`` uses before any real negotiation has happened.
    ``clientInfo`` is correctly omitted (SHOULD, never fabricated — no real
    client has spoken yet at probe time). A server that treats a discover
    request lacking this ``_meta`` as a header/body mismatch (``HeaderMismatch``
    / ``MissingRequiredClientCapabilityError``, both in the spec-reserved
    ``-32020..-32099`` range) would otherwise reject an otherwise-valid probe.

    ``modern_state``: pass the session's REAL state to build a discover
    request that advertises the local client's actual
    ``clientCapabilities``/``clientInfo`` in ``params._meta`` — used by the
    reseed retry, which exists precisely because the startup probe could
    only send ``{}``. The ``MCP-Protocol-Version`` header is derived from
    the SAME state (``negotiated_version`` falling back to the modern
    floor) as the ``_meta`` version ``_inject_modern_meta`` writes, keeping
    the two equal — the spec's Server Validation section rejects a
    header/``_meta`` version mismatch with ``HeaderMismatch`` (-32020).
    Default ``None`` keeps the pre-negotiation throwaway-state behavior.

    Headers: ``Mcp-Method``/``MCP-Protocol-Version`` are REQUIRED on every
    POST (Streamable HTTP, "Standard Request Headers" / "Protocol Version
    Header") — including this one. Any case-variant the operator pinned via
    ``-H`` is dropped first so httpx never serialises two header lines for
    the same field (mirrors ``_prepare_headers``' strip-then-set discipline).

    ``Mcp-Name``/``Mcp-Session-Id`` are unconditionally STRIPPED (never
    re-added — unlike ``Mcp-Method``/``MCP-Protocol-Version`` above, this
    probe derives no replacement value for either) and any case-variant the
    operator pinned via ``-H`` is dropped too (#350 review rounds 2 AND 3,
    flagged independently by both): ``server/discover`` has no ``name``
    parameter at all — a header asserting one is exactly the header/body
    mismatch ``HeaderMismatch`` (-32020) exists to reject — and, being the
    pre-negotiation probe, must never carry a session id either. This
    mirrors ``_prepare_headers``' modern-era branch (#350 review finding 3),
    which strips both unconditionally for the identical reason.
    """
    state = modern_state if modern_state is not None else _ModernState()
    discover_msg = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "server/discover",
            "id": request_id,
            "params": {},
        }
    )
    discover_msg = _inject_modern_meta(discover_msg, state)
    probe_headers = {k: v for k, v in headers.items() if k.lower() != "mcp-method"}
    probe_headers["Mcp-Method"] = "server/discover"
    probe_headers = {
        k: v for k, v in probe_headers.items() if k.lower() != "mcp-protocol-version"
    }
    probe_headers["MCP-Protocol-Version"] = (
        state.negotiated_version or _MODERN_PROTOCOL_VERSION_DEFAULT
    )
    probe_headers = {
        k: v
        for k, v in probe_headers.items()
        if k.lower() not in ("mcp-name", "mcp-session-id")
    }
    return discover_msg, probe_headers


def _is_sse_response(resp: httpx.Response) -> bool:
    """True when ``resp`` declares an SSE body (``text/event-stream``).

    Media types are case-insensitive (RFC 9110 §8.3.1 / RFC 2045 §5.1), so
    the containment test runs against the lowercased header value — a
    compliant server answering ``Content-Type: Text/Event-Stream`` is still
    an SSE stream (#350 review round 8, finding 8-1). A case-sensitive
    compare routed such a response to the buffered plain-JSON branch, where
    ``resp.read()`` on a stream the server keeps open (the final response
    only SHOULD terminate it) blocks until the read timeout: ``auto`` then
    misclassifies the live modern server as legacy, and forced-modern
    discovery / ``--check`` stall and lose the valid response.

    Shared by ``_post_probe`` and ``_parse_streamable_response`` — the two
    detection sites THIS branch introduces — so both apply the identical
    rule. The pre-existing legacy dispatch path (``_post_and_stream``,
    ``_post_parsed``, ``_reinitialize``) shares the case-sensitive
    comparison on main but is deliberately NOT routed through this helper:
    this branch's discipline is that legacy wire behavior stays
    byte-identical (acceptance criterion #3), so those sites are left for a
    follow-up fix on their own review trail.
    """
    return "text/event-stream" in resp.headers.get("content-type", "").lower()


def _first_response_message(
    events: Iterable[tuple[str, str]],
) -> dict[str, Any] | None:
    """Return the first SSE ``message`` event that is a JSON-RPC *response*.

    A response is the message object carrying ``result`` or ``error``
    (JSON-RPC 2.0 §5). Interleaved notifications — which a compliant server
    MAY send before the final response (Streamable HTTP, "Receiving
    Messages") — plus non-``message`` frames and non-JSON payloads are
    skipped. Shared by the streaming probe reader (``_post_probe``) and the
    buffered parser (``_parse_streamable_response``) so both apply the
    identical keep-reading gate instead of independently-drifting copies.
    """
    for event_type, payload in events:
        if event_type != "message":
            continue
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and ("result" in parsed or "error" in parsed):
            return parsed
    return None


def _post_probe(
    client: httpx.Client,
    url: str,
    content: str,
    headers: dict[str, str],
) -> tuple[httpx.Response, dict[str, Any] | None]:
    """POST a one-shot probe and return ``(response, parsed_response_or_None)``.

    Streams the response instead of buffering it (#350 review round 5): a
    server answering a probe over SSE is only SHOULD-bound to close the
    stream after the response — "The final JSON-RPC *response* **SHOULD**
    terminate the stream" (Streamable HTTP, "Receiving Messages") — so a
    compliant server MAY deliver the probe's result as an SSE event and keep
    the POST stream open afterwards. A buffered ``client.post()`` would then
    block until the read timeout despite the result having already arrived:
    ``auto`` era detection would misclassify a live modern server as legacy
    (the timeout surfaces as a transport error), and a forced ``modern``
    probe / ``--check`` fallback would stall for the full timeout and lose
    the discovered capabilities. This reader instead stops at the first
    JSON-RPC response message (``_first_response_message``) and closes the
    stream — the same incremental SSE decoding the dispatch path uses
    (``_iter_sse_lines``/``_iter_sse_events``), without its stdout / retry
    state, which does not apply at probe time.

    A plain-JSON (non-SSE) body is fully read inside the stream context and
    parsed by ``_parse_streamable_response`` exactly as the buffered probes
    always did. Either way the returned (closed) response still exposes
    ``status_code`` / ``headers`` — everything probe callers inspect.
    Transport errors propagate as ``httpx.HTTPError`` for the callers'
    existing degrade-to-legacy / soft-fail handling; note a read error while
    streaming surfaces HERE (inside the iteration) rather than inside
    ``client.post()``, so callers must wrap this whole call, not just the
    POST.
    """
    with client.stream("POST", url, content=content, headers=headers) as resp:
        if _is_sse_response(resp):
            return resp, _first_response_message(
                _iter_sse_events(_iter_sse_lines(resp.iter_text()))
            )
        resp.read()
    return resp, _parse_streamable_response(resp)


def _post_discover_with_recovery(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    auth_recovery: Callable[[httpx.Response], dict[str, str] | None] | None = None,
    modern_state: "_ModernState | None" = None,
    log_prefix: str = "protocol-era probe",
) -> tuple[httpx.Response, dict[str, Any] | None]:
    """POST a ``server/discover`` probe with bounded 401/403 credential
    recovery; return the final ``(response, parsed_response_or_None)``.

    ONE implementation of the recovery loop for both probe call sites —
    ``_probe_protocol_era`` (startup) and ``_reseed_discover_probe`` (the
    one-shot post-initialize reseed) — extracted in #350 review round 8
    (finding 8-2): the reseed had NO recovery at all, so a token that
    expired between a ``-32021``-gated startup probe and the local
    ``initialize`` made the reseed 401 and permanently synthesize empty
    capabilities — and a compliant client told ``capabilities: {}`` never
    issues tools/resources/prompts requests, so the dispatch path's own
    401 recovery never even gets a request to repair. Sharing the loop
    (instead of duplicating it) follows the same rationale as
    ``_build_discover_probe_request``: byte-identical behavior at every
    call site instead of independently-drifting copies (#350 review
    finding 1).

    The loop is the round-6 shape, unchanged: recovery is bounded PER
    STAGE, not per probe — gating on "first attempt only" (the round-4
    shape) could repair a 401 but then had no attempt left when the
    refreshed token 403'd with ``insufficient_scope``, a chained challenge
    the dispatch ladder handles fine. Keying on status code lets each
    stage fire once (bounded: initial post + one per stage = three posts
    max) while a repeated same-status challenge still cannot loop. A
    recovery that declines/fails (``None``) ends the loop with the
    challenge response, identical to not having ``auth_recovery`` at all.

    ``modern_state`` is forwarded to ``_build_discover_probe_request`` on
    the initial build AND every recovery rebuild, so a reseed retry keeps
    advertising the client's REAL capabilities/info after a token refresh.
    ``log_prefix`` labels the recovery log lines with the caller's name.
    Transport errors (``httpx.HTTPError``) propagate — each caller keeps
    its own degrade path (startup: assume legacy; reseed: keep unseeded).
    """
    discover_msg, probe_headers = _build_discover_probe_request(
        headers, modern_state=modern_state
    )
    recovered_statuses: set[int] = set()
    while True:
        resp, parsed = _post_probe(client, url, discover_msg, probe_headers)
        if (
            resp.status_code in (401, 403)
            and resp.status_code not in recovered_statuses
            and auth_recovery is not None
        ):
            refreshed = auth_recovery(resp)
            if refreshed is not None:
                recovered_statuses.add(resp.status_code)
                log(
                    f"{log_prefix}: HTTP {resp.status_code} recovered; "
                    "re-probing with refreshed credentials"
                )
                discover_msg, probe_headers = _build_discover_probe_request(
                    refreshed, modern_state=modern_state
                )
                continue
        return resp, parsed


def _probe_protocol_era(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    auth_recovery: Callable[[httpx.Response], dict[str, str] | None] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """One-shot ``server/discover`` probe implementing the spec's era-detection
    algorithm (Streamable HTTP, "Backward Compatibility") for
    ``--protocol-era auto``.

    Sends a MODERN-shaped request first (``server/discover`` — the modern
    replacement for ``initialize``) and classifies the remote from the
    response:

    - HTTP 200 whose body is a JSON-RPC RESULT -> modern; the parsed body
      is returned for the caller to seed ``_ModernState`` from (via
      ``_seed_modern_state_from_discover``). A 200 with an
      empty/unparseable/result-less body is NOT proof (#350 review round
      13): a sloppy legacy endpoint or intermediary can 200 an unknown
      method with an empty body or bare ``{}``, and classifying that as
      modern would swallow the client's ``initialize`` and send stateless
      requests the server cannot process — so it falls to legacy, the
      same "empty or unrecognized" rule the 400 branch applies.
    - HTTP 200 or HTTP 400 whose body IS a recognized-modern JSON-RPC error
      per ``_is_recognized_modern_error`` -> STILL modern (spec: a modern
      server also uses 400 for ``UnsupportedProtocolVersionError`` /
      ``MissingRequiredClientCapabilityError`` / header-validation
      failures — a recognized-modern error body proves the server
      UNDERSTOOD ``server/discover`` as a method, just rejected THIS
      request, so the client should retry/correct rather than fall back).
      The same rule applies at HTTP 200 because a recognized-modern error
      code is diagnostic regardless of which HTTP status carried it.
    - HTTP 401/403 with ``auth_recovery`` provided: the challenge is
      AUTHENTICATION evidence, not protocol evidence (#350 review round 4)
      — a modern-only server with an expired cached OAuth token 401s
      before ever inspecting ``server/discover``, and classifying that as
      legacy would permanently misconfigure the session (the relay would
      later send ``initialize``, which the modern remote rejects, while
      the first real dispatch's own 401 recovery silently fixes only the
      credentials, not the era). ``auth_recovery`` is handed the raw
      response (it needs the status and any ``WWW-Authenticate``
      challenge) and returns the FULL refreshed header set on successful
      recovery — the probe is then rebuilt from those headers and
      retried. Each recovery STAGE fires at most once, keyed by status
      code (401 -> token refresh, 403 -> step-up), so a CHAINED challenge
      — 401, refresh succeeds, then the refreshed token 403s with
      ``insufficient_scope`` (#350 review round 6) — is repaired
      end-to-end exactly like the dispatch ladder would repair it, while
      a REPEATED challenge of the same status (a refresh that still
      401s) cannot loop: at most three posts total (the initial probe
      plus one per stage). A recovery that declines/fails (``None``), or
      a retry that fails with an already-recovered status, falls through
      to the conservative rules below — identical to not having
      ``auth_recovery`` at all.
    - HTTP 200 or HTTP 400 whose body is a GENERIC/unrecognized JSON-RPC
      error (e.g. ``-32601`` Method not found — the ordinary reply an
      unmodified LEGACY server sends for an unknown method), HTTP 404
      (method not recognized at all — the transport spec's mandated
      response for an unknown method), any OTHER status (unrecovered
      401/403, 5xx, ...), or a transport failure -> legacy, the
      conservative default on anything ambiguous. Spec: "If the body is
      empty or is not a recognized modern JSON-RPC error, fall back to
      `initialize` and continue with the legacy version for subsequent
      requests" (Streamable HTTP, "Backward Compatibility").

    A transport-level exception is swallowed (not propagated) so a
    detection-probe failure degrades to legacy rather than crashing startup;
    the first REAL request from the local client still surfaces a genuine
    connectivity problem through the normal legacy retry path.

    The probe request itself is built by ``_build_discover_probe_request``
    (headers AND body, including ``params._meta`` — see that function's
    docstring for why a discover probe needs ``_meta`` too, not just the
    two headers), and POSTed via ``_post_discover_with_recovery`` — the
    build + bounded-recovery loop shared with ``_reseed_discover_probe``
    (#350 review round 8, finding 8-2) — over ``_post_probe`` (#350 review
    round 5),
    which streams the response and stops at the first JSON-RPC response
    message — a server that SSE-frames the discover result and keeps the
    stream open (the final response only SHOULD terminate the stream) must
    classify as modern promptly, not block until the read timeout and fall
    through to the legacy branch above.
    """
    # The posting + bounded per-stage 401/403 recovery loop lives in
    # _post_discover_with_recovery, shared with _reseed_discover_probe
    # (#350 review round 8, finding 8-2) — see that helper's docstring for
    # the round-6 bounded-per-stage rationale it preserves verbatim.
    try:
        resp, parsed = _post_discover_with_recovery(client, url, headers, auth_recovery)
    except httpx.HTTPError as e:
        log(f"protocol-era probe failed ({e}); assuming legacy")
        return "legacy", None
    if resp.status_code == 200:
        if isinstance(parsed, dict) and "error" in parsed:
            if _is_recognized_modern_error(parsed):
                log(
                    "protocol-era probe: 200 with a recognized-modern "
                    "JSON-RPC error body; assuming modern"
                )
                return "modern", parsed
            log(
                "protocol-era probe: 200 with a generic JSON-RPC error "
                "body; assuming legacy"
            )
            return "legacy", None
        if isinstance(parsed, dict) and isinstance(parsed.get("result"), dict):
            return "modern", parsed
        # 200 with an empty/unparseable/result-less body proves nothing: a
        # sloppy legacy endpoint (or an intermediary) can 200 an unknown
        # method with an empty body or bare {}. Only a genuine
        # DiscoverResult or a recognized-modern error is proof of modern —
        # the same "empty or unrecognized -> fall back" rule the 400 branch
        # applies (#350 review round 13). The result must itself be an
        # OBJECT (#350 review round 14): a permissive legacy endpoint can
        # answer an unknown method with ``"result": null`` (or a scalar),
        # which is not a DiscoverResult shape either. Its FIELDS are
        # deliberately not schema-validated beyond that — demanding
        # resultType/supportedVersions would misclassify a slightly
        # non-compliant but genuinely modern server, while a legacy server
        # has no plausible reason to answer server/discover with an object
        # result at all.
        log("protocol-era probe: 200 with an empty/unrecognized body; assuming legacy")
        return "legacy", None
    if resp.status_code == 400:
        if _is_recognized_modern_error(parsed):
            log(
                "protocol-era probe: 400 with a recognized-modern JSON-RPC "
                "error body; assuming modern"
            )
            return "modern", parsed
        log("protocol-era probe: 400 with an empty/generic body; assuming legacy")
        return "legacy", None
    # Any other status — 404 (unknown method), an unrecovered 401/403 (no
    # auth_recovery configured, or recovery/retry failed), 5xx, ... — is the
    # conservative legacy fallback. Logged explicitly so an operator whose
    # modern-only server is being misclassified can see WHY (and knows the
    # workaround: fix credentials, or pin --protocol-era modern).
    log(f"protocol-era probe: HTTP {resp.status_code}; assuming legacy")
    return "legacy", None


def _reseed_discover_probe(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    modern_state: "_ModernState",
    auth_recovery: Callable[[httpx.Response], dict[str, str] | None] | None = None,
) -> None:
    """One-shot ``server/discover`` re-probe carrying the local client's REAL
    capabilities (#350 review round 4).

    The startup era-detection probe necessarily runs before the local stdio
    client's own ``initialize``, so it can only advertise
    ``clientCapabilities: {}``. A remote that gates ``server/discover``
    itself on a real client capability (``-32021``
    ``MissingRequiredClientCapabilityError``) is still classified modern but
    seeds nothing — and a server can equally answer the probe SUCCESSFULLY
    with ``serverInfo``/``supportedVersions`` while filtering
    ``capabilities`` down to ``{}`` against that placeholder (#350 review
    round 9, finding 9-2). Either way the lifecycle spec makes empty
    synthesized capabilities NOT cosmetic: "Both parties MUST ... Only use
    capabilities that were successfully negotiated", so a compliant client
    told ``capabilities: {}`` will never issue ``tools/list`` at all. This
    re-probe repeats discovery exactly once, now that
    ``modern_state.client_capabilities``/``client_info`` hold the client's
    real values (``_build_discover_probe_request`` puts them in
    ``params._meta``), and reseeds ``modern_state`` from the result —
    without erasing identity/version state the startup probe already
    seeded, when the reseed only needed to fill capabilities (see
    ``_seed_modern_state_from_discover``).

    Called only from ``_handle_modern_special_method``'s ``initialize``
    branch, only when the startup probe left ``capabilities`` empty AND the
    client's own capabilities are non-empty (a re-probe carrying the same
    ``{}`` the startup probe sent could not change the outcome), and at
    most once per
    session (``modern_state.discover_retry_attempted`` is latched by the
    caller BEFORE this runs) — zero cost on the common already-seeded path,
    one extra round-trip only on the rare failure path, which is exactly the
    per-session-cost objection that killed the retry-on-every-session
    variant in round 3. Any failure (transport error, non-200, JSON-RPC
    error again) is logged and leaves the state untouched, degrading to the
    round-3 documented under-report. Runs synchronously on the stdin loop
    thread, before the synthesized ``InitializeResult`` is emitted, so there
    is no race with any other dispatch.

    ``auth_recovery`` (#350 review round 8, finding 8-2): the reseed runs
    the same bounded 401/403 refresh/step-up loop as the startup probe
    (``_post_discover_with_recovery``, one shared implementation). Without
    it, a token that expired between a ``-32021``-gated startup probe and
    the local ``initialize`` made this reseed 401 and permanently
    synthesize empty capabilities — and since a compliant client told
    ``capabilities: {}`` issues no tools/resources/prompts requests at
    all, the dispatch path's own 401 recovery never got a request to
    repair the session with. Recovery declining/absent degrades to the
    same keep-unseeded behavior as before.
    """
    try:
        # _post_discover_with_recovery streams via _post_probe and stops at
        # the first JSON-RPC response message (#350 review round 5) — an
        # SSE-framed discover result on a stream the server keeps open must
        # not stall this reseed (which runs synchronously before the
        # synthesized InitializeResult is emitted) until the read timeout.
        resp, parsed = _post_discover_with_recovery(
            client,
            url,
            headers,
            auth_recovery,
            modern_state=modern_state,
            log_prefix="discover reseed probe",
        )
    except httpx.HTTPError as e:
        log(f"discover reseed probe failed ({e}); keeping unseeded state")
        return
    if resp.status_code != 200:
        log(
            f"discover reseed probe returned HTTP {resp.status_code}; "
            "keeping unseeded state"
        )
        return
    if isinstance(parsed, dict) and "error" in parsed:
        log("discover reseed probe returned a JSON-RPC error; keeping unseeded state")
        return
    _seed_modern_state_from_discover(modern_state, parsed)
    log("discover reseed probe succeeded with the client's real capabilities")


def _handle_modern_special_method(
    line: str,
    req_id: Any,
    modern_state: "_ModernState",
    discover_retry: Callable[[], None] | None = None,
    listen_seed: Callable[[], None] | None = None,
    listen_start: Callable[[], None] | None = None,
) -> tuple[bool, str | None]:
    """Intercept ``initialize`` / ``notifications/initialized`` /
    ``notifications/cancelled`` on the modern path, where none of the three
    exist on the wire to the remote: there is no initialize handshake
    (``server/discover`` replaces it, already run before the stdin loop
    starts) and no ``Mcp-Session-Id``, and cancellation is signalled by
    closing the response stream, not a forwarded notification (spec rev
    2026-07-28).

    Returns ``(True, reply_or_None)`` when the line was fully handled
    locally — the caller must NOT dispatch it upstream:

    - ``initialize`` synthesizes a legacy-SHAPED ``InitializeResult`` (the
      local stdio client still expects one) from ``modern_state``'s
      discover-seeded ``server_info``/``capabilities``/``supported_versions``
      — ``serverInfo`` falls back to ``_UNKNOWN_UPSTREAM_SERVER_INFO`` (never
      a bare ``"mcp-stdio"`` claiming to BE the remote — see that constant's
      comment) only when the probe never yielded a real one — and captures
      the client's own ``capabilities``/``clientInfo`` into ``modern_state``
      for later ``_meta`` injection (``_inject_modern_meta``) — this is the
      ONLY place those values are ever observed, since the modern path never
      forwards the request that carries them. When the era-detection probe
      left ``capabilities`` EMPTY — it seeded nothing at all (e.g. the
      remote gated ``server/discover`` itself on a real client capability,
      ``-32021``, round 4), or it returned ``serverInfo``/
      ``supportedVersions`` but a capability set filtered down to ``{}``
      against the probe's placeholder ``clientCapabilities: {}`` (#350
      review round 9, finding 9-2) — and the client's own capabilities are
      non-empty, ``discover_retry`` — when the caller provides one —
      re-runs discovery exactly ONCE, now that the client's real
      ``capabilities``/``clientInfo`` are known, before the result is
      synthesized (see ``_reseed_discover_probe``). Already-seeded
      identity/version state survives a reseed that only fills
      capabilities (``_seed_modern_state_from_discover`` never erases).
      ``modern_state.discover_retry_attempted``
      latches the attempt so a client-driven re-``initialize`` can never
      probe again; a retry that fails degrades to the same under-reporting
      as before. The client's OWN data is still never copied into
      ``server_info``/``capabilities`` — client capabilities are not server
      capabilities; only a real discover response may seed those fields.
      The returned ``protocolVersion``
      is the client's OWN ``requested`` string, not ``negotiated_version``
      (#350 review rounds 3 AND 4 — deliberate, analyzed twice; the full
      contract, so it need not be re-litigated:

      (1) What the echo promises: nothing about wire shapes. This relay
      never re-shapes request/response BODIES based on protocol version,
      and for every request type a stdio client itself SENDS through this
      relay (``tools/list``/``tools/call``, ``resources/*``, ``prompts/*``,
      ``ping``, ``completion/complete``, ``logging/setLevel``) spec rev
      2026-07-28 changes the RESULT shapes only ADDITIVELY over 2025-06-18:
      the new required ``resultType`` discriminator and the ``_meta``-nested
      ``serverInfo`` are extra fields on otherwise-unchanged result shapes
      (#270's verified change list, items 2/8 — every other 2026 change is
      transport-level: sessions, streams, headers, cancellation — all
      absorbed by this relay, never surfaced downstream). MCP result
      objects are open/extensible, so a 2025 client ignores the additions.

      (2) The ONE genuinely incompatible result shape is MRTR's
      ``InputRequiredResult`` (``resultType: "input_required"`` REPLACES
      the real result payload, SEP-2322) — it substitutes for
      server-INITIATED sampling/elicitation/roots round-trips, so a
      COMPLIANT server only initiates it when the client's advertised
      capabilities include those flows. Since round 10 (finding 10-1)
      this relay never advertises them upstream — the capture above
      strips ``_MRTR_REPLACED_CLIENT_CAPABILITIES`` — so a compliant
      modern server has no standing invitation to send MRTR at all;
      relaying/bridging it is explicitly Phase 2 (#270 "Phase 2 — MRTR
      passthrough"). A NON-compliant server that sends
      ``input_required`` unprovoked is still forwarded verbatim — a
      KNOWN residual documented in run()'s "Limitation — MRTR" section,
      not a consequence of which version this field echoes: it would be
      forwarded verbatim no matter what the echo said.

      (3) Why not report ``negotiated_version`` (the reviewer-proposed
      alternative): lifecycle spec, Version Negotiation — "If the client
      does not support the version in the server's response, it SHOULD
      disconnect." Reporting the upstream's 2026-07-28 to a 2025-only
      client makes every spec-conformant legacy client disconnect from
      every modern-only server at the handshake, destroying the additive-
      compatible majority flows in (1) to guard against the single Phase 2
      gap in (2). Rejecting the mismatch outright is the same outcome.
      Echoing the client's own ask is therefore the honest maximum this
      relay can promise — and the promise it actually keeps.)

      ``negotiated_version`` (computed below, from the
      remote's OWN advertised ``supportedVersions``) remains the version
      used UPSTREAM in headers/``_meta`` — the actual wire protocol the
      remote server understands — and is symmetric: it diverges from the
      client's ask whichever direction the mismatch runs (a legacy client
      against a modern-only remote, or a modern-savvy client against a
      remote that only advertised an older version).
    - ``notifications/initialized`` and ``notifications/cancelled`` are
      swallowed (``None`` reply — both are notifications, which never get a
      response either way).

    ``listen_seed`` / ``listen_start`` (#270 Phase 2 PR A): ``listen_seed``
    is invoked on every ``initialize`` — AFTER ``negotiated_version`` is
    computed, so the frozen listen body snapshot (C1) sees the negotiated
    state — while ``listen_start`` (the thread start) is invoked only on
    ``notifications/initialized`` (#352 review finding 1): the lifecycle
    spec (2025-06-18) has the client send ``initialized`` only after it
    received the InitializeResult, and the server "SHOULD NOT send
    requests other than pings and logging" before receiving it — starting
    the thread on ``initialize`` let a fast server deliver a
    ``list_changed`` notification to stdout BEFORE run()'s loop had even
    emitted the synthesized InitializeResult, which a lifecycle-enforcing
    client may reject or drop. Both hooks are guarded by the caller
    (``_start_listen_stream`` is latched one-shot; an ``initialized``
    with no prior ``initialize`` finds no seeded snapshot and starts
    nothing), so a client-driven re-``initialize`` or a repeated
    ``initialized`` can never spawn a second thread. The
    synthesized ``InitializeResult`` unions ``listChanged: true`` into
    ``tools``/``resources``/``prompts`` on this path (C8): the relay
    itself forwards those three ``list_changed`` notification kinds
    downstream, and forwarding one for an unadvertised capability would
    violate the lifecycle spec's "Only use capabilities that were
    successfully negotiated" — a gating client would drop it (precedent:
    ``_COLD_START_LIST_CHANGED``, which advertises the same union while
    the cold-start gate is closed).

    Returns ``(False, None)`` for every other line, which the caller
    dispatches normally (through ``_inject_modern_meta`` first).
    """
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return False, None
    if not isinstance(msg, dict):
        return False, None
    method = msg.get("method")
    if method == "initialize":
        params = msg.get("params")
        params = params if isinstance(params, dict) else {}
        requested = params.get("protocolVersion")
        requested = requested if isinstance(requested, str) and requested else None
        # Presence-based, like every other MCP capabilities object (see
        # _report_initialize's own note) — an absent/malformed capabilities
        # object becomes {} (present, empty), never omitted downstream.
        # Un-bridgeable keys are stripped HERE, at the single capture site
        # (#350 review round 10, finding 10-1): sampling/elicitation/roots
        # map to the MRTR flows Phase 1 defers to Phase 2 (see
        # _MRTR_REPLACED_CLIENT_CAPABILITIES), so advertising them upstream
        # would invite exactly the input_required results this relay can
        # only forward verbatim. Filtering at capture covers every
        # downstream use at once — _inject_modern_meta's per-request _meta
        # and the reseed re-probe — and the reseed condition below then
        # correctly treats a client whose ONLY capabilities are
        # un-bridgeable as having none to advertise. The SERVER capability
        # set echoed in the synthesized result is untouched: this filter
        # applies to what the relay claims the CLIENT can do, never to what
        # the remote reported.
        caps = params.get("capabilities")
        caps = caps if isinstance(caps, dict) else {}
        modern_state.client_capabilities = {
            k: v for k, v in caps.items() if k not in _MRTR_REPLACED_CLIENT_CAPABILITIES
        }
        client_info = params.get("clientInfo")
        modern_state.client_info = (
            client_info if isinstance(client_info, dict) else None
        )
        # Reseed retry (#350 review rounds 4 + 9): re-run discovery once,
        # now that the client's REAL capabilities are known, when the
        # startup probe left CAPABILITIES empty and the client actually
        # has capabilities to advertise. Round 4 gated this on ALL three
        # discover fields being unseeded, but seeded serverInfo/
        # supportedVersions do not prove capability negotiation was
        # complete: a server can return identity/versions fine while
        # filtering ``capabilities`` down to {} against the probe's
        # placeholder ``clientCapabilities: {}`` (finding 9-2) — and
        # capabilities is the ONE field that placeholder can plausibly
        # distort. A client that itself has no capabilities gets no
        # retry: the re-probe would carry the same ``{}`` the startup
        # probe already sent and cannot change the outcome. That includes
        # (round 10, finding 10-1) a client whose only capabilities were
        # the MRTR-replaced keys stripped at capture above — after
        # filtering it HAS nothing this relay may advertise, so the
        # re-probe would again carry ``{}``. Latch the
        # attempt BEFORE probing so neither a failed retry nor a
        # re-initialize can ever probe a second time (zero extra
        # round-trips on the common path: a non-empty capabilities seed
        # means discovery already answered).
        if (
            discover_retry is not None
            and not modern_state.discover_retry_attempted
            and not modern_state.capabilities
            and modern_state.client_capabilities
        ):
            modern_state.discover_retry_attempted = True
            discover_retry()
        # Negotiated AFTER the possible reseed, so a retry that recovered
        # the remote's real supportedVersions feeds the negotiation.
        modern_state.negotiated_version = _negotiate_modern_version(
            requested, modern_state.supported_versions
        )
        # Seed the frozen listen body snapshot (#270 Phase 2 PR A, C1) —
        # AFTER negotiation so it carries the negotiated version. Only the
        # SNAPSHOT is built here; the thread itself starts on
        # notifications/initialized (#352 review finding 1, see the
        # docstring): the InitializeResult synthesized below has not even
        # been returned to run()'s loop yet, let alone emitted, so a
        # thread started here could put a list_changed on stdout ahead of
        # the handshake reply.
        if listen_seed is not None:
            listen_seed()
        # C8 (#270 Phase 2 PR A): union `listChanged: true` into tools/
        # resources/prompts. The relay forwards exactly those three
        # list_changed notification kinds from the listen stream, so the
        # synthesized result MUST advertise them: the lifecycle spec says
        # both parties "Only use capabilities that were successfully
        # negotiated", and a client that gates on the advertisement would
        # drop an un-advertised notification. Deep-copied so the union
        # never leaks into the discover-seeded `modern_state.capabilities`
        # (which every later re-initialize re-reads). Precedent:
        # _COLD_START_LIST_CHANGED. Unconditional on the modern path —
        # the stream is default-on, and advertising listChanged when the
        # stream later turns out unsupported (the C6 terminal arm) merely
        # promises notifications that never arrive, which listChanged
        # never guarantees anyway.
        capabilities = copy.deepcopy(modern_state.capabilities)
        for key in ("tools", "resources", "prompts"):
            entry = capabilities.get(key)
            if not isinstance(entry, dict):
                entry = {}
            entry["listChanged"] = True
            capabilities[key] = entry
        result = {
            # Downstream ack: what the LOCAL client asked for (falling back
            # to the upstream-negotiated version only when the client sent
            # no usable protocolVersion at all — see this function's own
            # docstring for why these two are deliberately different).
            "protocolVersion": requested or modern_state.negotiated_version,
            "capabilities": capabilities,
            "serverInfo": modern_state.server_info or _UNKNOWN_UPSTREAM_SERVER_INFO,
        }
        return True, json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})
    if method == "notifications/initialized":
        # THE lifecycle-correct start point for the listen thread (#352
        # review finding 1): the client only sends initialized after it
        # has consumed the InitializeResult (lifecycle spec 2025-06-18:
        # "After successful initialization, the client MUST send an
        # initialized notification"), and the same spec forbids the
        # server unsolicited pre-initialized traffic ("The server SHOULD
        # NOT send requests other than pings and logging before receiving
        # the initialized notification") — so nothing the thread forwards
        # can now precede the handshake reply on stdout. One-shot latch
        # and the no-prior-initialize guard live in the caller
        # (_start_listen_stream).
        if listen_start is not None:
            listen_start()
        return True, None
    if method == "notifications/cancelled":
        return True, None
    return False, None


def _inject_modern_meta(line: str, modern_state: "_ModernState") -> str:
    """Merge the modern per-request ``_meta`` block into ``params._meta``.

    Placement follows the MCP base protocol's established ``_meta``
    convention (``params._meta`` — unchanged since 2025-03-26, already used
    for e.g. ``progressToken``), not a new location invented for spec rev
    2026-07-28.

    ``io.modelcontextprotocol/protocolVersion`` and
    ``.../clientCapabilities`` are ALWAYS present (both REQUIRED per the
    clientInfo/serverInfo revision comment — capabilities uses presence-based
    semantics like every other MCP capabilities object, so an empty client
    capabilities set is sent as ``{}`` rather than omitted).
    ``client_capabilities`` arrives here already stripped of the
    MRTR-replaced keys Phase 1 cannot bridge — the filter lives at the
    single capture site (``_handle_modern_special_method``, #350 review
    round 10, finding 10-1), never re-applied per request.
    ``.../clientInfo`` is sent only when the LOCAL client's own ``initialize``
    actually provided one (SHOULD, never fabricated — see
    ``_handle_modern_special_method``). ``.../logLevel`` is sent only once
    the client has issued a ``logging/setLevel`` (see ``_extract_log_level``).

    Returns ``line`` unchanged for a batch / unparseable / methodless line —
    mirrors ``_extract_method_and_name``'s batch exemption (a batch has no
    single top-level ``params`` to attach ``_meta`` to).
    """
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return line
    if not isinstance(msg, dict) or "method" not in msg:
        return line
    params = msg.get("params")
    params = dict(params) if isinstance(params, dict) else {}
    existing_meta = params.get("_meta")
    meta = dict(existing_meta) if isinstance(existing_meta, dict) else {}
    meta[_META_PROTOCOL_VERSION] = (
        modern_state.negotiated_version or _MODERN_PROTOCOL_VERSION_DEFAULT
    )
    meta[_META_CLIENT_CAPABILITIES] = modern_state.client_capabilities or {}
    if modern_state.client_info:
        meta[_META_CLIENT_INFO] = modern_state.client_info
    if modern_state.log_level:
        meta[_META_LOG_LEVEL] = modern_state.log_level
    params["_meta"] = meta
    msg["params"] = params
    return json.dumps(msg)


# Cancel-aware response filter (MCP cancellation spec SHOULDs).
#
# The MCP cancellation utility mandates two reciprocal SHOULDs:
# - a *receiver* must not send a response for a cancelled request;
# - a *canceller* must ignore any late response for a cancelled request.
# Both are violated in the wild (cf. anthropics/claude-code#51073 for the
# canceller side; modelcontextprotocol/python-sdk#2480 for the receiver
# side). As a stdin-to-HTTP middleman, mcp-stdio can enforce the receiver
# SHOULD on the wire by dropping any upstream response whose id has been
# cancelled by the client — see _CancelTracker and _emit below.
_CANCEL_TTL_SECS = 60.0
_CANCEL_GC_THRESHOLD = 256
_CANCELLED_METHOD_RE = re.compile(r'"method"\s*:\s*"notifications/cancelled"')


class _CancelTracker:
    """Thread-safe id→timestamp map of cancelled in-flight request ids.

    Callers on the stdin side push ids with ``add(id)`` when they see a
    ``notifications/cancelled``; the response-emit path queries with
    ``consume(id)`` and drops a matching response. ``consume`` removes the
    entry on the first match, so a cancelled id's late response is dropped
    exactly once — a later request that legitimately *reuses* the same id
    (permitted by JSON-RPC once the prior call is done) is then forwarded
    normally instead of being dropped for the whole TTL window. Entries
    expire after ``ttl`` seconds (monotonic clock — immune to NTP jumps), and
    once the map grows past ``_CANCEL_GC_THRESHOLD`` every ``add`` sweeps out
    the TTL-aged entries. The GC reclaims only entries older than ``ttl``, so
    it is not a hard size cap: the bound against an adversarial peer is "one
    TTL window of distinct-cancel throughput", which then self-expires — never
    an unbounded leak. Both transports share one instance; the SSE reader
    thread in ``run_sse`` reads concurrently with the main loop, hence the lock.
    """

    __slots__ = ("_seen", "_lock", "_ttl", "_now")

    def __init__(
        self,
        ttl: float = _CANCEL_TTL_SECS,
        now: Any = time.monotonic,
    ) -> None:
        self._seen: dict[Any, float] = {}
        self._lock = threading.Lock()
        self._ttl = ttl
        self._now = now

    def add(self, req_id: Any) -> None:
        if req_id is None:
            return
        with self._lock:
            self._seen[req_id] = self._now()
            if len(self._seen) > _CANCEL_GC_THRESHOLD:
                self._gc_locked()

    def contains(self, req_id: Any) -> bool:
        if req_id is None:
            return False
        with self._lock:
            ts = self._seen.get(req_id)
            if ts is None:
                return False
            if self._now() - ts > self._ttl:
                del self._seen[req_id]
                return False
            return True

    def consume(self, req_id: Any) -> bool:
        """Return True for a still-live cancelled id, removing it on match.

        Consuming on the first match bounds the drop to a single response per
        cancelled id, so a request that reuses the id within the TTL is not
        collateral-dropped. An expired entry is also removed and returns False.
        """
        if req_id is None:
            return False
        with self._lock:
            ts = self._seen.pop(req_id, None)
            if ts is None:
                return False
            return self._now() - ts <= self._ttl

    def discard(self, req_id: Any) -> None:
        """Untrack an id when the client forwards a fresh request reusing it.

        A new request with a previously-cancelled id supersedes the cancel
        (JSON-RPC permits id reuse once the prior call is done), so its response
        must be delivered rather than dropped as a "late cancelled response".
        """
        if req_id is None:
            return
        with self._lock:
            self._seen.pop(req_id, None)

    def _gc_locked(self) -> None:
        cutoff = self._now() - self._ttl
        expired = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in expired:
            del self._seen[k]


def _is_scalar_id(rid: Any) -> bool:
    """True when ``rid`` is a usable JSON-RPC id: a String or finite Number.

    A NON-SCALAR id (object / array) is malformed AND unhashable, so any
    set/dict tracking keyed on it would raise ``TypeError`` — and it can never
    match a real response id anyway. ``None``/``null`` is excluded: it is
    uncorrelatable (multiple requests could share it). A non-finite float
    (``json.loads`` accepts the non-standard ``NaN``/``Infinity`` literals by
    default) is excluded too: echoing it back through ``json.dumps`` would put
    invalid JSON on the wire, and ``NaN != NaN`` breaks key correlation.
    """
    if isinstance(rid, float) and not math.isfinite(rid):
        return False
    return rid is not None and isinstance(rid, (str, int, float))


def _extract_cancel_id(line: str) -> Any:
    """Return ``params.requestId`` if ``line`` is a ``notifications/cancelled``.

    Uses a cheap regex pre-check to avoid a full ``json.loads`` on every
    stdin line — only cancellation notifications go through the slow
    path. Returns ``None`` if the line is not a cancellation (malformed
    JSON, wrong method, missing params, or missing requestId).

    Only a single (non-batch) ``notifications/cancelled`` is tracked: a
    cancellation buried inside a JSON-RPC batch array is intentionally not
    extracted, consistent with the cancel filter passing batches through
    untouched (the filter's narrow scope mirrors exactly what the spec
    covers, and batch responses are forwarded verbatim).
    """
    if not _CANCELLED_METHOD_RE.search(line):
        return None
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(msg, dict) or msg.get("method") != "notifications/cancelled":
        return None
    params = msg.get("params")
    if not isinstance(params, dict):
        return None
    rid = params.get("requestId")
    # A non-scalar requestId would make the caller's ``tracker.add(rid)``
    # raise ``TypeError: unhashable type`` on the stdin hot path — drop it
    # (return None) so a malformed cancellation is a clean no-op rather than
    # an exception (see _is_scalar_id). ``null`` also returns None here and
    # is filtered by the caller's ``cid is not None`` guard.
    if rid is not None and not _is_scalar_id(rid):
        return None
    return rid


def _error_response(message: str, req_id: Any = None, data: Any = None) -> str:
    """Build a JSON-RPC error response.

    ``data`` is attached as the optional ``error.data`` member when not None
    (JSON-RPC 2.0 §5.1) — used to surface machine-readable hints such as a 429
    ``retryAfter`` alongside the human-readable message.
    """
    error: dict[str, Any] = {"code": -32000, "message": message}
    if data is not None:
        error["data"] = data
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "error": error,
            "id": req_id,
        }
    )


def _parse_retry_after(value: str | None) -> float | None:
    """Parse an HTTP ``Retry-After`` header value.

    Per RFC 9110 §10.2.3 (formerly RFC 7231 §7.1.3), ``Retry-After`` is either
    a non-negative integer number of seconds (delta-seconds) or an HTTP-date.
    Returns the number of seconds to wait, or ``None`` if the header is absent
    or unparseable. A past HTTP-date returns ``0`` (retry immediately).
    """
    if not value:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    # delta-seconds is the common case; try it first.
    try:
        secs = float(stripped)
    except ValueError:
        pass
    else:
        if math.isnan(secs) or math.isinf(secs):
            return None
        return max(0.0, secs)
    # Fall back to HTTP-date (RFC 9110 §5.6.7, formerly RFC 7231 §7.1.1.1 —
    # IMF-fixdate, obsolete RFC 850, or ANSI C's asctime()).
    try:
        dt = email.utils.parsedate_to_datetime(stripped)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = (dt - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, delta)


def _handle_rate_limit(
    resp_headers: Any,
    attempt: int,
) -> float | None:
    """Decide how long to sleep for a 429/503 before retrying.

    Status-agnostic: callers gate on ``_RETRYABLE_RATE_LIMIT_STATUSES``
    (429, 503), the two spec-sanctioned ``Retry-After`` carriers, and pass
    the response here. Returns the seconds to sleep if a retry should be
    attempted, or ``None`` if the caller should give up (wait exceeds the cap,
    or this was the last allowed attempt — caller must then surface the status).

    ``resp_headers`` accepts anything with ``.get("retry-after")``.
    ``attempt`` is the 1-based retry counter shared with the surrounding
    retry loop.
    """
    if attempt >= MAX_RETRIES:
        return None
    retry_after = _parse_retry_after(
        resp_headers.get("retry-after") if hasattr(resp_headers, "get") else None
    )
    if retry_after is None:
        # No hint from the server: reuse the transient-error backoff so
        # retry timing stays predictable across failure modes.
        return float(RETRY_DELAY * attempt)
    if retry_after > _RATE_LIMIT_SLEEP_CAP_SECS:
        # Server is asking for longer than we're willing to block. Let
        # the 429 propagate so the client can decide what to do.
        return None
    return retry_after


def _escape_js_line_separators(line: str) -> str:
    """Escape raw U+2028 / U+2029 to their JSON ``\\uXXXX`` form.

    Both are legal *unescaped* inside JSON strings but are JavaScript line
    terminators; some clients treat them as line breaks and hang or
    mis-frame the response (cf. modelcontextprotocol/typescript-sdk#2155).
    Escaping is lossless — the escaped form decodes to the identical
    character — so it is applied unconditionally, mirroring the
    no-flag, lossless ``_enforce_lf_stdio`` normalization. The cheap
    ``in`` pre-check keeps the common case allocation-free.

    Only upstream pass-through content reaches this path with raw
    separators: mcp-stdio's own responses go through ``json.dumps``
    (``ensure_ascii=True``), which already escapes them.
    """
    if "\u2028" in line or "\u2029" in line:
        return line.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return line


def _emit(line: str, tracker: "_CancelTracker | None") -> None:
    """Write one JSON-RPC line to stdout, filtering cancelled-id responses.

    Raw U+2028 / U+2029 are escaped first (``_escape_js_line_separators``)
    so a client that treats them as line terminators cannot mis-frame the
    output. The cancel filter then runs: when ``tracker`` is ``None``
    (feature disabled) the line is written unconditionally; otherwise the
    line is parsed and only proper JSON-RPC *responses* (objects with an id
    and either ``result`` or ``error``) are eligible for dropping.
    Notifications, server-initiated requests, JSON-RPC batches, and
    anything that fails to parse pass through — the filter is narrowly
    scoped to the case the spec covers.

    mcp-stdio's own synthesized error responses (``_error_response``)
    intentionally bypass this gate and call ``_write_line`` directly, so a
    cancel arriving mid-retry never leaves the client hanging without
    an answer for the line it just sent.
    """
    line = _escape_js_line_separators(line)
    if tracker is None:
        _write_line(line)
        return
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        _write_line(line)
        return
    if not isinstance(msg, dict):
        _write_line(line)
        return
    # Drop only a pure JSON-RPC RESPONSE (id + result/error, NO method — see
    # _is_pure_response, shared with _extract_response_id so the two gates
    # can never drift). A message carrying `method` is by definition a
    # request / notification, not a response — so a malformed peer that sends
    # `method` alongside result/error under a (coincidentally cancelled) id
    # must still pass through, matching this function's documented scope
    # ("server-initiated requests ... pass through"). The scalar guard is a
    # behavior no-op (a non-scalar id can never have been tracked) that keeps
    # an unhashable id out of tracker.consume's dict lookup.
    if _is_pure_response(msg):
        rid = msg["id"]
        if _is_scalar_id(rid) and tracker.consume(rid):
            log(f"dropped late response for cancelled id {rid!r}")
            return
    _write_line(line)


def _is_pure_response(msg: Any) -> bool:
    """True for a pure JSON-RPC response: an object with a non-null id, NO
    ``method``, and ``result`` or ``error`` present.

    The single source of truth for "is this a response" — shared by
    ``_emit``'s cancel gate and ``_extract_response_id`` (the SSE in-flight
    tracker) so the two can never drift apart.
    """
    return (
        isinstance(msg, dict)
        and msg.get("id") is not None
        and "method" not in msg
        and ("result" in msg or "error" in msg)
    )


def _extract_response_id(line: str) -> Any:
    """The id of a pure JSON-RPC response, or ``None``.

    ``_is_pure_response`` plus the ``_is_scalar_id`` guard, so the SSE
    in-flight tracker only ever pops keys it could have stored. Standalone
    rather than a ``_emit`` return value: ``_emit`` skips parsing entirely
    when the cancel filter is off, but in-flight tracking must work under
    ``--no-cancel-filter`` too.
    """
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if _is_pure_response(msg) and _is_scalar_id(msg["id"]):
        return msg["id"]
    return None


class _StreamResult:
    """Result of a streaming request."""

    __slots__ = (
        "session_id",
        "status_code",
        "www_authenticate",
        "protocol_version",
        "retry_after",
    )

    def __init__(
        self,
        session_id: str | None,
        status_code: int,
        www_authenticate: str | None = None,
        protocol_version: str | None = None,
        retry_after: float | None = None,
    ):
        self.session_id = session_id
        self.status_code = status_code
        self.www_authenticate = www_authenticate
        # Negotiated MCP protocol version captured from an InitializeResult
        # (only populated when the caller requests capture). See run().
        self.protocol_version = protocol_version
        # Retry-After seconds parsed from a 429 whose retries were exhausted or
        # whose wait exceeded the cap — surfaced in the synthesized error's
        # ``data.retryAfter`` so a client can back off. See #8.
        self.retry_after = retry_after


def _parse_auth_params(header: str | None) -> dict[str, str]:
    """Parse a WWW-Authenticate challenge's auth-params into a name->value dict.

    Splits with the stdlib's quote-aware helpers (``parse_http_list`` +
    ``parse_keqv_list``) rather than per-name regexes, so a ``name=value``
    pair is only recognised as a genuine auth-param. This structurally avoids
    the whole defect class of modelcontextprotocol/python-sdk#3009: a decoy
    param whose name merely ends in the target (``error_scope=``,
    ``x.resource_metadata=``) is a distinct key, and a ``scope=`` substring
    living inside another param's quoted value (an ``error_description`` in
    prose) stays part of that value and is never mistaken for the parameter.

    Names are lowercased — auth-param names are case-insensitive (RFC 9110
    §11.2 / RFC 7235 §2.1) — and quoted values are unquoted. A leading
    auth-scheme token (e.g. ``Bearer``) is dropped. Only a single challenge is
    parsed: multiple space-separated challenges in one header (RFC 7235 §4.1)
    are not disentangled by scheme, matching the narrow scope of the callers
    (they act on a single Bearer challenge).
    """
    if not header:
        return {}
    text = header.strip()
    # Drop a leading auth-scheme token ("Bearer", "Basic", ...) — it has no
    # "=", unlike an auth-param. A bare scheme with no params yields {}.
    head, sep, rest = text.partition(" ")
    if sep and "=" not in head:
        text = rest
    pairs = [item for item in parse_http_list(text) if "=" in item]
    try:
        parsed = parse_keqv_list(pairs)
    except ValueError:
        return {}
    return {name.lower(): value for name, value in parsed.items()}


def _parse_www_authenticate_scope(header: str | None) -> str | None:
    """Extract the required scope from a Bearer insufficient_scope challenge.

    Returns the scope string when the challenge signals
    ``error="insufficient_scope"`` and carries a ``scope`` parameter;
    otherwise returns ``None``.

    Used to drive RFC 9470 / MCP step-up authorization (cf.
    anthropics/claude-code#44652).
    """
    params = _parse_auth_params(header)
    if params.get("error") != "insufficient_scope":
        return None
    scope = params.get("scope")
    return scope.strip() if scope else None


# WHATWG Server-Sent Events recognises only CR, LF, and CRLF as line
# terminators. Python's ``str.splitlines()`` and httpx's ``iter_lines`` split on
# a much larger set (``\n \r \x0b \x0c \x1c \x1d \x1e \x85 U+2028 U+2029``), but
# U+2028 / U+2029 / U+0085 are legal *unescaped* inside JSON strings (RFC 8259).
# Splitting an SSE ``data:`` payload on one of them tears the JSON-RPC message in
# half — the first fragment is emitted truncated and the continuation is dropped
# as an unknown field. This is the inbound mirror of the outbound hazard
# ``_escape_js_line_separators`` already guards (typescript-sdk#2155), so the SSE
# decoders below split on CR/LF/CRLF only.
_SSE_LINE_SPLIT_RE = re.compile(r"\r\n|\r|\n")


def _split_sse_text(text: str) -> list[str]:
    """Split a fully-buffered SSE body into lines on CR / LF / CRLF only."""
    return _SSE_LINE_SPLIT_RE.split(text)


def _iter_sse_lines(chunks: Iterable[str]) -> Iterator[str]:
    """Yield SSE lines from a text-chunk stream, splitting on CR/LF/CRLF only.

    Buffers across chunk boundaries so a ``\\r\\n`` straddling two chunks counts
    as a single terminator (a trailing ``\\r`` is held back until the next chunk
    resolves whether it is a lone CR or the first half of a CRLF). The final
    unterminated remainder is yielded last. Used for the streaming SSE paths,
    where httpx's ``iter_lines`` would over-split (see ``_SSE_LINE_SPLIT_RE``).
    """
    buf = ""
    for chunk in chunks:
        if not chunk:
            continue
        buf += chunk
        hold = ""
        if buf.endswith("\r"):
            # A trailing CR may be the first half of a CRLF whose LF is in the
            # next chunk; hold it so the pair is not split into two lines.
            hold = "\r"
            buf = buf[:-1]
        parts = _SSE_LINE_SPLIT_RE.split(buf)
        buf = parts.pop() + hold
        for line in parts:
            yield line
    if buf.endswith("\r"):
        # A held CR at end of input is itself a terminator.
        buf = buf[:-1]
    if buf:
        yield buf


def _iter_sse_events(lines: Iterable[str]) -> Iterator[tuple[str, str]]:
    """Yield ``(event_type, data)`` pairs from SSE lines per the WHATWG spec.

    Implements the WHATWG Server-Sent Events line-decoding algorithm so every
    SSE-decoding site parses identically:

    - a ``data:`` field strips at most one leading U+0020 from its value, so a
      space-less ``data:{...}`` is valid (servers are not required to emit the
      conventional ``data: {...}`` with a space);
    - ``event:`` sets the event type, which defaults to ``"message"`` and resets
      after every dispatched event;
    - ``:``-prefixed comment lines and unrecognised fields are ignored;
    - the ``id:`` and ``retry:`` fields are intentionally ignored: mcp-stdio
      does not implement SSE resumption (no ``Last-Event-ID`` replay on
      reconnect) or server-driven reconnect timing for the legacy GET stream;
    - an event is dispatched on each blank-line boundary with its ``data:``
      fields concatenated by LF;
    - a final unterminated event with non-empty data is also dispatched at end
      of input, so a response body that omits the trailing blank line is not
      silently dropped.

    Callers decide which event types to act on (``message`` for JSON-RPC
    payloads, ``endpoint`` for the legacy SSE bootstrap).
    """
    event_type = "message"
    data_lines: list[str] = []
    first = True
    for line in lines:
        if first:
            first = False
            # WHATWG SSE stream-decode mandates removing ONE leading U+FEFF BOM
            # before line decoding. httpx does not strip it, so a BOM-prefixed
            # stream would otherwise parse the first field as a BOM-prefixed field
            # name (e.g. a U+FEFF before ``event``) — an unrecognised field —
            # silently misclassifying the critical first event (the legacy SSE
            # ``endpoint`` bootstrap) as a default ``message`` and breaking
            # startup. (Escape used, not a raw BOM, to keep the source ASCII.)
            if line[:1] == "\ufeff":
                line = line[1:]
        if line == "":
            # WHATWG "dispatch the event": if the data buffer is the empty
            # string the event is NOT dispatched. Gate on the joined buffer, not
            # list non-emptiness — a bare ``data:`` appends "" yet must not
            # produce a ('message', '') event a strict decoder never would.
            data = "\n".join(data_lines)
            if data:
                yield event_type, data
            event_type = "message"
            data_lines = []
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "event":
            # WHATWG SSE "dispatch the event": an EMPTY event-type buffer
            # dispatches as the default "message". A frame `event:\ndata: {...}`
            # (explicitly-empty event field) must therefore be treated as a
            # message, not silently dropped under an "" type.
            event_type = value or "message"
        elif field == "data":
            data_lines.append(value)
    data = "\n".join(data_lines)
    if data:
        yield event_type, data


def _post_and_stream(
    client: httpx.Client,
    url: str,
    content: str,
    headers: dict[str, str],
    req_id: Any,
    tracker: _CancelTracker | None = None,
    *,
    capture_init: bool = False,
    has_id: bool = True,
) -> _StreamResult | None:
    """Send a POST and stream the response to stdout with retry.

    Handles both SSE and JSON responses.  Returns a ``_StreamResult``
    on success (including non-200 status for caller to handle), or
    ``None`` when all retries are exhausted (error already printed).

    When ``capture_init`` is set the streamed payload is additionally
    parsed for ``result.protocolVersion`` (the negotiated MCP protocol
    version from an InitializeResult), surfaced via
    ``_StreamResult.protocol_version``. Parsing is read-only and never
    affects what is written to stdout.

    ``has_id`` mirrors the run() loop's notification policy one frame
    deeper: a notification (no JSON-RPC id) must never receive a
    synthesized error response, so the retry-exhausted / stream-interrupted
    error writes below are suppressed when ``has_id`` is False (the failure
    is still logged to stderr), matching the ``req_has_id`` gating in run().
    """
    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        # Tracks whether any payload has been committed to stdout on this
        # attempt. Once a byte is written to the client the non-idempotent
        # POST can no longer be safely replayed, so a mid-stream transient
        # error must surface an error instead of retrying — otherwise the
        # server re-streams and the client sees duplicate JSON-RPC responses
        # (and tools/call may execute twice server-side).
        emitted = False
        try:
            with client.stream("POST", url, content=content, headers=headers) as resp:
                session = resp.headers.get("mcp-session-id")
                www_auth = resp.headers.get("www-authenticate")

                if resp.status_code in _RETRYABLE_RATE_LIMIT_STATUSES:
                    resp.read()
                    sleep_secs = _handle_rate_limit(resp.headers, attempt)
                    if sleep_secs is None:
                        return _StreamResult(
                            session,
                            resp.status_code,
                            www_auth,
                            retry_after=_parse_retry_after(
                                resp.headers.get("retry-after")
                            ),
                        )
                    log(
                        f"attempt {attempt}/{MAX_RETRIES} got HTTP "
                        f"{resp.status_code}, sleeping {sleep_secs:.1f}s before retry"
                    )
                    time.sleep(sleep_secs)
                    continue

                if resp.status_code != 200:
                    resp.read()
                    return _StreamResult(session, resp.status_code, www_auth)

                pv: str | None = None
                content_type = resp.headers.get("content-type", "")
                if "text/event-stream" in content_type:
                    for event_type, payload in _iter_sse_events(
                        _iter_sse_lines(resp.iter_text())
                    ):
                        if event_type != "message":
                            continue
                        if capture_init and pv is None:
                            pv = _extract_protocol_version(payload)
                        # _emit -> _write_line can raise BrokenPipeError (an
                        # OSError, not an httpx.HTTPError) mid-stream if the
                        # downstream reader closed stdout. That intentionally
                        # bypasses the httpx.HTTPError handler below and unwinds
                        # to run()/run_sse()'s outer `except Exception` safety
                        # net, which swallows the re-raised write error: a dead
                        # reader cannot observe the truncated body anyway.
                        _emit(payload, tracker)
                        emitted = True
                else:
                    resp.read()
                    text = resp.text.strip()
                    if text:
                        if capture_init:
                            pv = _extract_protocol_version(text)
                        _emit(text, tracker)
                        emitted = True

                if not emitted and has_id:
                    # A 200 that delivered NO JSON-RPC payload (empty body, or
                    # only non-message SSE events) would leave a request-with-id
                    # waiting forever. Synthesize an error so the client is not
                    # left hanging, mirroring the >=400 fall-through in run().
                    # Notifications (has_id False) stay silent.
                    _write_line(_error_response("empty response from server", req_id))
                # pv is intentionally None here: no InitializeResult was
                # delivered, so an empty-200 to an `initialize` request leaves
                # the relay's protocol_version unset rather than guessing a
                # version it never negotiated. The client received
                # the synthesized error above and will re-initialize; the server
                # that answered initialize with an empty 200 is already
                # non-compliant. Contrast the partial-delivery path below, which
                # deliberately PRESERVES a pv captured before the stream broke.
                return _StreamResult(session, 200, protocol_version=pv)
        except httpx.HTTPError as e:
            # httpx.HTTPError is the broadest request-level supertype: every
            # transient transport failure (TransportError — ConnectError/
            # ReadError/Write*/timeouts/RemoteProtocolError) AND DecodingError,
            # which is a SIBLING of TransportError (not a subclass) raised when a
            # response body's Content-Encoding/charset is malformed or truncated.
            # A buggy/hostile server (e.g. ``Content-Encoding: gzip`` on a
            # non-gzip body) would otherwise propagate DecodingError out of the
            # for-line loop and crash the whole gateway mid-session, violating
            # the #11 "never crash the stdio connection" contract. Non-HTTP
            # (programming) errors still propagate.
            last_error = e
            log(f"attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if emitted:
                # Response already partially delivered to the client; replaying
                # the POST would duplicate it. Surface a stream-interrupted
                # error (at-most-once) rather than retry.
                log("upstream stream interrupted after partial delivery; not retrying")
                if has_id:
                    _write_line(
                        _error_response(f"upstream stream interrupted: {e}", req_id)
                    )
                # Return a 200 result carrying any captured protocol_version instead of None: the InitializeResult was already
                # delivered, so the client considers init complete. Returning None
                # would discard the negotiated version, leaving the relay's
                # protocol_version None and omitting MCP-Protocol-Version on every
                # subsequent request — which a strict 2025-06-18 server 400s.
                # (session/pv are bound here: emitted implies the loop ran past
                # their assignment.)
                return _StreamResult(session, 200, protocol_version=pv)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)

    log(f"request failed after retries: {last_error}")
    if has_id:
        _write_line(_error_response(str(last_error), req_id))
    return None


def _post_parsed(
    client: httpx.Client,
    url: str,
    content: str,
    headers: dict[str, str],
    req_id: Any,
    *,
    tracker: "_CancelTracker | None" = None,
    has_id: bool = True,
    emit_error_on_failure: bool = True,
) -> tuple[dict[str, Any] | None, _StreamResult | None]:
    """Send a POST and return the parsed JSON-RPC response.

    Mirrors the retry behaviour of ``_post_and_stream`` but buffers the
    response so that callers can inspect the JSON before writing anything
    to stdout. Used by the pagination helper, which needs to inspect
    ``result.nextCursor`` across multiple requests.

    Returns a tuple of ``(parsed, stream_result)``. ``parsed`` is the
    decoded response dict on success, or ``None`` on non-200 / parse
    failure. ``stream_result`` is ``None`` only when all retries are
    exhausted.

    ``has_id`` suppresses the retry-exhausted error write for a
    notification, matching ``_post_and_stream`` and the run() loop.

    ``emit_error_on_failure`` lets the pagination caller suppress the
    exhaustion error for page>=2: there the caller flushes the partial
    result it already collected, so writing an error too would emit a
    SECOND JSON-RPC response for the same id. Page 1 keeps it True (no
    partial exists, so the error is the only response).
    """
    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = client.post(url, content=content, headers=headers)
            session = resp.headers.get("mcp-session-id")
            www_auth = resp.headers.get("www-authenticate")
            if resp.status_code in _RETRYABLE_RATE_LIMIT_STATUSES:
                sleep_secs = _handle_rate_limit(resp.headers, attempt)
                if sleep_secs is None:
                    return None, _StreamResult(
                        session,
                        resp.status_code,
                        www_auth,
                        retry_after=_parse_retry_after(resp.headers.get("retry-after")),
                    )
                log(
                    f"attempt {attempt}/{MAX_RETRIES} got HTTP "
                    f"{resp.status_code}, sleeping {sleep_secs:.1f}s before retry"
                )
                time.sleep(sleep_secs)
                continue
            if resp.status_code != 200:
                return None, _StreamResult(session, resp.status_code, www_auth)

            content_type = resp.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                # A spec-compliant server MAY interleave server-initiated
                # requests and notifications on the POST's SSE stream BEFORE the
                # actual JSON-RPC response. Return only the response object (one
                # carrying ``result``/``error``); a bare notification has
                # neither, and returning it would make the pagination merge treat
                # it as the page result and drop the real list. Mirrors the
                # keep-reading gate in _check_connection_sse.
                #
                # every NON-response message event (a server-
                # initiated request / notification) must still be DELIVERED to
                # stdout — _post_and_stream emits every message event, so the
                # pagination path must too, or interleaved frames are silently
                # dropped only on the paginated methods.
                for event_type, payload in _iter_sse_events(_split_sse_text(resp.text)):
                    if event_type != "message":
                        continue
                    try:
                        parsed = json.loads(payload)
                    except json.JSONDecodeError:
                        # Non-JSON message: not the response object. Leave it to
                        # trigger the parsed=None fallback (re-POST) rather than
                        # forwarding garbage — the fallback re-fetches the real
                        # result, so dropping the malformed frame loses nothing.
                        continue
                    if isinstance(parsed, dict) and (
                        "result" in parsed or "error" in parsed
                    ):
                        return parsed, _StreamResult(session, 200)
                    # A well-formed but NON-response message (a server-initiated
                    # request / notification interleaved before the response) must
                    # be delivered, not dropped — _post_and_stream emits every
                    # message event, so the pagination path must too.
                    _emit(payload, tracker)
                return None, _StreamResult(session, 200)

            text = resp.text.strip()
            if not text:
                return None, _StreamResult(session, 200)
            try:
                return json.loads(text), _StreamResult(session, 200)
            except json.JSONDecodeError:
                return None, _StreamResult(session, 200)
        except httpx.HTTPError as e:
            # Broadest request-level supertype: covers every transient transport
            # failure AND DecodingError (a SIBLING of TransportError, not a
            # subclass) raised on a malformed/truncated Content-Encoding or
            # charset. Catching only TransportError let a DecodingError propagate
            # out of the run() loop and crash the gateway mid-session — see the
            # matching note in _post_and_stream and #11. Non-HTTP errors still
            # propagate.
            last_error = e
            log(f"attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)

    log(f"request failed after retries: {last_error}")
    if has_id and emit_error_on_failure:
        _write_line(_error_response(str(last_error), req_id))
    return None, None


# tools/call requests that serialize an empty argument map as ``null``.
# Some clients (Go/Java/C# serializers) emit ``"arguments": null``; strict
# MCP servers validate ``arguments`` as an optional object and reject the
# null form with -32603 (cf. modelcontextprotocol/typescript-sdk#2012). The
# regex is a cheap gate before the json round-trip; the parsed-structure
# check below is authoritative.
_NULL_ARGUMENTS_RE = re.compile(r'"arguments"\s*:\s*null')


def _normalize_null_arguments(line: str) -> str:
    """Rewrite a ``tools/call`` request's null ``arguments`` to ``{}``.

    ``{}`` is accepted by both optional- and required-object servers, so it
    is the safe normalization of the "no arguments" intent. Narrowly
    scoped: only a ``tools/call`` whose ``params.arguments`` key is present
    and ``null`` is rewritten — a string value that merely contains the
    literal ``"arguments":null`` is left untouched (the parsed-structure
    check, not the regex, decides). JSON-RPC batch arrays and other methods
    (e.g. ``prompts/get``, a deliberate non-goal) pass through unchanged.
    """
    if not _NULL_ARGUMENTS_RE.search(line):
        return line
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return line
    if not isinstance(msg, dict) or msg.get("method") != "tools/call":
        return line
    params = msg.get("params")
    if (
        isinstance(params, dict)
        and "arguments" in params
        and params["arguments"] is None
    ):
        params["arguments"] = {}
        return json.dumps(msg)
    return line


# CacheableResult fields (spec rev 2026-07-28, SEP-2549): ``tools/list`` /
# ``prompts/list`` / ``resources/list`` / ``resources/read`` /
# ``resources/templates/list`` results now carry ``ttlMs`` (a freshness
# hint, in milliseconds) and ``cacheScope`` (``"public"`` lets shared
# intermediaries cache the response; ``"private"`` restricts caching to the
# requesting client). Rank higher = more restrictive, so
# ``_merge_cacheable_field`` can compare across pages without special-casing
# each field's own value semantics.
_CACHE_SCOPE_RESTRICTIVENESS = {"public": 0, "private": 1}
_CACHEABLE_MERGE_FIELDS = frozenset({"ttlMs", "cacheScope"})

# Conservative fallback fed into ``_merge_cacheable_field`` by
# ``_paginate_and_stream`` for a page that OMITS the field entirely, per the
# spec's own stated behavior for absence (#350 review round 3): "Caching"
# says "If ttlMs is absent, clients SHOULD assume a default of 0 (immediately
# stale)", and separately "Servers MUST apply the same cacheScope to all
# response pages for a given list request" — an omission is therefore itself
# non-compliant and must not let another page's laxer/present value leak
# into the merged result. Both values already sit at the most-restrictive
# extreme of their own domain (0 is the global minimum ttlMs the spec allows;
# "private" is the highest ``_CACHE_SCOPE_RESTRICTIVENESS`` rank), so feeding
# them into the existing min/most-restrictive merge rule "just works"
# regardless of which page (first or later) is the one that omits the field.
_CACHEABLE_FIELD_CONSERVATIVE_DEFAULT: dict[str, Any] = {
    "ttlMs": 0,
    "cacheScope": "private",
}


def _is_valid_cacheable_value(key: str, value: Any) -> bool:
    """True iff ``value`` is a usable ``ttlMs``/``cacheScope`` per SEP-2549.

    Feeds ``_paginate_and_stream``'s per-page bookkeeping: a page whose field
    fails this check is recorded exactly like a page that OMITS the field
    (#350 review round 11) — an unknown ``cacheScope`` (``"internal"``) or a
    non-numeric/non-finite ``ttlMs`` grants no more caching permission than
    silence does, so letting it be "ignored" would leave another page's
    laxer value (``"public"``) standing in the merged result, failing OPEN
    on exactly the conservative-security semantics the round-3 merge rule
    exists to protect. ``bool`` is rejected for ``ttlMs`` despite being an
    ``int`` subclass (``True`` is not a millisecond count a compliant
    server would send); non-finite floats are rejected because ``NaN``
    poisons the min() comparison in ``_merge_cacheable_field`` (NaN < x is
    always False, so a NaN would silently survive as the merged value).
    """
    if key == "ttlMs":
        # ``>= 0`` because 0 is the spec's own floor ("If ttlMs is absent,
        # clients SHOULD assume a default of 0") — a negative value has no
        # defined meaning, and accepting it would let a malformed page
        # BEAT the conservative default in the min() merge, emitting an
        # invalid cache policy downstream (#350 review round 13).
        # ``math.isfinite`` is applied to FLOATS ONLY (#350 review round
        # 15): it converts an int argument to float first, and an
        # arbitrarily large JSON integer (``10**400`` parses fine as a
        # Python int) makes that conversion raise OverflowError — a crash
        # on untrusted response data instead of the conservative degrade
        # this function exists to deliver. Python ints are always finite,
        # so ``>= 0`` alone is the complete check for them.
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return value >= 0
        return isinstance(value, float) and math.isfinite(value) and value >= 0
    if key == "cacheScope":
        # The isinstance gate is not a type nicety: dict membership with an
        # UNHASHABLE value (a JSON array/object — ``"cacheScope": []`` is
        # valid JSON a malformed page can carry) raises TypeError instead
        # of returning False, turning the page into a failed request rather
        # than the conservative degrade this function exists to deliver
        # (#350 review round 12).
        return isinstance(value, str) and value in _CACHE_SCOPE_RESTRICTIVENESS
    return False


def _merge_cacheable_field(merged_result: dict[str, Any], key: str, value: Any) -> None:
    """Merge one page's ``ttlMs``/``cacheScope`` into ``merged_result`` in place.

    ``ttlMs``: keep the MINIMUM seen across pages — the merged list's true
    freshness bound is set by its least-fresh member, not by whichever page
    happened to be merged last. ``cacheScope``: keep the MOST RESTRICTIVE
    value seen (``"private"`` wins over ``"public"``) — a merged list that
    combines a private-scoped page with a public-scoped one must not be
    reported as publicly cacheable, or a shared intermediary could legally
    cache and leak the private page's items.

    A value of the wrong type (a non-compliant server) is ignored rather
    than raising or silently adopted — same "degrade, don't guess" posture
    as ``_extract_protocol_version``. This function itself has no notion of
    "the field was absent" — it only ever sees a VALUE, never a missing key.
    The caller (``_paginate_and_stream``) decides what value to pass for a
    page that omits the field: the conservative default
    (``_CACHEABLE_FIELD_CONSERVATIVE_DEFAULT``, #350 review round 3) when at
    least one OTHER page in the same merge did supply a value, or nothing at
    all (no call, field left absent) when the field is missing on every page
    seen — see that function for the bookkeeping.
    """
    if key == "ttlMs":
        if not isinstance(value, (int, float)):
            return
        existing = merged_result.get("ttlMs")
        if not isinstance(existing, (int, float)) or value < existing:
            merged_result["ttlMs"] = value
        return
    if key == "cacheScope":
        # Both isinstance gates guard hashability, not just type (#350
        # review round 12): ``.get()`` on an UNHASHABLE value raises
        # TypeError. ``value`` can be a JSON array/object from a malformed
        # page; ``existing`` can be the same garbage when page 1's
        # dict-copy put it into merged_result unvetted (the finalization
        # degrades it afterwards, but THIS call happens first).
        if not isinstance(value, str):
            return
        new_rank = _CACHE_SCOPE_RESTRICTIVENESS.get(value)
        if new_rank is None:
            return
        existing = merged_result.get("cacheScope")
        existing_rank = (
            _CACHE_SCOPE_RESTRICTIVENESS.get(existing, -1)
            if isinstance(existing, str)
            else -1
        )
        if new_rank > existing_rank:
            merged_result["cacheScope"] = value


def _detect_paginated_list(line: str) -> tuple[str, str] | None:
    """Return ``(method, result_key)`` if the request should auto-paginate.

    A request auto-paginates when the method is one of the spec's
    paginated list endpoints and the client did not supply ``cursor``.
    If the client already supplies ``cursor`` we pass through: they are
    driving pagination themselves and should receive the raw response.
    """
    try:
        request = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(request, dict):
        return None
    method = request.get("method")
    if method not in PAGINATED_LIST_METHODS:
        return None
    params = request.get("params")
    if isinstance(params, dict) and "cursor" in params:
        return None
    return method, PAGINATED_LIST_METHODS[method]


def _paginate_and_stream(
    client: httpx.Client,
    url: str,
    line: str,
    headers: dict[str, str],
    req_id: Any,
    result_key: str,
    tracker: _CancelTracker | None = None,
    *,
    has_id: bool = True,
) -> _StreamResult | None:
    """Transparently follow ``result.nextCursor`` and emit one merged response.

    Issues up to ``MAX_LIST_PAGES`` POSTs, threading each response's
    ``nextCursor`` into the next request's ``params.cursor``. The final
    response written to stdout contains the concatenated list items and
    no ``nextCursor``.

    Non-200 on page 1 is propagated to the caller so the outer loop can
    handle 401 / 404 recovery just like a non-paginated request. Errors
    on page 2+ return the accumulated partial result rather than losing
    items already collected.
    """
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        return _post_and_stream(
            client, url, line, headers, req_id, tracker, has_id=has_id
        )

    base_params = request.get("params")
    params: dict[str, Any] = dict(base_params) if isinstance(base_params, dict) else {}
    merged_result: dict[str, Any] | None = None
    last_session: str | None = None
    truncated = False
    # The cursor for the page we could NOT fetch (set on a mid-pagination
    # failure or the page-cap). Re-exposed as ``nextCursor`` on the merged
    # result so a truncated list is resumable instead of silently complete.
    pending_cursor: str | None = None
    # Per-CacheableResult-field bookkeeping (#350 review round 3): True once
    # ANY page seen so far omitted the field entirely. Checked after the
    # loop (below) against whether the field ended up present in
    # merged_result at all — present-and-missing-somewhere degrades to the
    # conservative default (_CACHEABLE_FIELD_CONSERVATIVE_DEFAULT); missing
    # everywhere leaves the field absent, matching a fully cache-unaware
    # (e.g. legacy) server's existing behavior unchanged.
    cacheable_missing: dict[str, bool] = dict.fromkeys(_CACHEABLE_MERGE_FIELDS, False)

    for page in range(1, MAX_LIST_PAGES + 1):
        page_request = dict(request)
        page_request["params"] = params
        page_content = json.dumps(page_request)

        parsed, stream = _post_parsed(
            client,
            url,
            page_content,
            headers,
            req_id,
            tracker=tracker,
            has_id=has_id,
            # Page 1 has no partial to flush, so its exhaustion error IS the
            # response. Page>=2 flushes the partial below, so suppress the error
            # here to avoid a duplicate JSON-RPC response for the same id.
            emit_error_on_failure=(page == 1),
        )
        if stream is None:
            if page == 1:
                return None  # error already printed
            log(f"pagination: page {page} exhausted retries, returning partial result")
            truncated = True
            pending_cursor = params.get("cursor")
            break

        if stream.session_id:
            last_session = stream.session_id

        if stream.status_code != 200:
            if page == 1:
                return stream  # let outer 401/404 recovery run
            log(
                f"pagination: page {page} returned HTTP {stream.status_code}, "
                f"returning partial result"
            )
            truncated = True
            pending_cursor = params.get("cursor")
            break

        if parsed is None:
            if page == 1:
                # Page-1 body was a 200 that did not parse: fall back to a plain
                # streamed POST so the client still gets the raw response. This
                # re-POSTs the request (the first body was buffered by
                # _post_parsed and discarded), which is only safe because
                # PAGINATED_LIST_METHODS holds idempotent reads only — keep that
                # invariant (mirrors the capture-init note in run()'s _dispatch)
                # if the table ever grows to a non-idempotent method.
                return _post_and_stream(
                    client, url, line, headers, req_id, tracker, has_id=has_id
                )
            log(
                f"pagination: page {page} response not parseable, "
                f"returning partial result"
            )
            truncated = True
            pending_cursor = params.get("cursor")
            break

        page_result = parsed.get("result")
        if not isinstance(page_result, dict):
            # Error response or unexpected shape — forward as-is from page 1,
            # otherwise stop and flush what we have.
            if page == 1:
                _emit(json.dumps(parsed), tracker)
                return stream
            truncated = True
            pending_cursor = params.get("cursor")
            break

        if merged_result is None:
            merged_result = {k: v for k, v in page_result.items() if k != "nextCursor"}
            if not isinstance(merged_result.get(result_key), list):
                merged_result[result_key] = []
            # Present-but-INVALID counts as missing (#350 review round 11):
            # page 1's values enter merged_result via the dict-copy above
            # WITHOUT passing _merge_cacheable_field's type guards, so an
            # invalid first-page value would otherwise ride through to the
            # merged output verbatim — and an invalid later-page value would
            # be "ignored", leaving a laxer prior value standing. Both fail
            # open; both now degrade via the same finalization as omission.
            for field in _CACHEABLE_MERGE_FIELDS:
                if not _is_valid_cacheable_value(field, page_result.get(field)):
                    cacheable_missing[field] = True
        else:
            items = page_result.get(result_key)
            if isinstance(items, list):
                merged_result[result_key].extend(items)
            # Preserve top-level result fields (e.g. a late ``_meta``) that arrive
            # only on a later page — last-write-wins. The accumulated list and the
            # ``nextCursor`` are managed explicitly above, so skip them here.
            #
            # ``ttlMs``/``cacheScope`` (``CacheableResult``, spec rev 2026-07-28)
            # are excluded from last-write-wins and merged via
            # ``_merge_cacheable_field`` instead: last-write-wins can UNDERSTATE
            # the true constraint on the combined list — e.g. page 1 says
            # cacheScope="private" (must not be shared-cached) but page 2 says
            # "public", and naive last-write-wins would report the merged list
            # (whose page-1-derived items are still private-scoped data) as
            # publicly cacheable, which a shared intermediary could then legally
            # cache and leak. ``ttlMs`` has the same shape of bug: the merged
            # list's true freshness bound is its LEAST fresh member, not
            # whichever page happened to arrive last.
            #
            # Handled UNCONDITIONALLY (not gated on the key being present in
            # THIS page's result, #350 review round 3): a page that OMITS
            # ttlMs/cacheScope entirely is not silence to skip over — it is
            # itself the non-compliant condition _CACHEABLE_FIELD_CONSERVATIVE_
            # DEFAULT exists to fail closed on (see cacheable_missing's
            # finalization after this loop). A page whose field is present
            # but INVALID (unknown scope, non-numeric ttlMs) is recorded the
            # same way (#350 review round 11) — an unusable value grants no
            # more caching permission than an absent one, and merely
            # "ignoring" it would leave another page's laxer value standing.
            for field in _CACHEABLE_MERGE_FIELDS:
                if not _is_valid_cacheable_value(field, page_result.get(field)):
                    cacheable_missing[field] = True
            for k, v in page_result.items():
                if k in (result_key, "nextCursor"):
                    continue
                if k in _CACHEABLE_MERGE_FIELDS:
                    _merge_cacheable_field(merged_result, k, v)
                    continue
                merged_result[k] = v

        next_cursor = page_result.get("nextCursor")
        # An empty-string nextCursor is treated as terminal alongside null /
        # absent: the MCP spec models a continuation token whose ABSENCE ends the
        # list, and an empty cursor cannot be round-tripped (it is indistinct from
        # "no cursor / first page"), so it is a degenerate, not a real, next page.
        if not next_cursor:
            break
        params["cursor"] = next_cursor
    else:
        truncated = True
        pending_cursor = params.get("cursor")
        log(f"pagination: reached MAX_LIST_PAGES={MAX_LIST_PAGES}, truncating results")

    # Defensive only / unreachable in practice: the loop always
    # runs page 1, and every path that reaches here either early-returned or
    # merged page 1's dict into merged_result first, so it is never None. Kept as
    # a belt-and-suspenders guard; intentionally not covered by a test (the state
    # cannot be constructed).
    if merged_result is None:
        merged_result = {result_key: []}

    # Finalize ttlMs/cacheScope (#350 review round 3): a field missing on AT
    # LEAST ONE processed page but present (from some OTHER page) cannot be
    # trusted at whatever value the present page(s) supplied — degrade the
    # WHOLE merged result to the conservative default. A field missing on
    # EVERY processed page is left untouched (never fabricated from nothing
    # — see test_cacheable_fields_absent_on_every_page_are_not_fabricated).
    for field, conservative in _CACHEABLE_FIELD_CONSERVATIVE_DEFAULT.items():
        if cacheable_missing[field] and field in merged_result:
            merged_result[field] = conservative

    # A truncated list (a later page failed, or the page cap was hit) must NOT be
    # reported as complete: re-expose the cursor for the unfetched page so the
    # client can RESUME pagination itself instead of silently losing the tail.
    if truncated and pending_cursor:
        merged_result["nextCursor"] = pending_cursor

    merged_response: dict[str, Any] = {
        "jsonrpc": request.get("jsonrpc", "2.0"),
        # Reuse the id run() already parsed (and tracks/discards in the cancel
        # filter) rather than re-deriving it from this second parse.
        # They are provably identical today, but keying the emitted id off req_id
        # removes a latent divergence point — _emit's cancel filter matches on the
        # BODY id, so any future drift would both mis-correlate the response and
        # defeat cancellation filtering for paginated responses.
        "id": req_id,
        "result": merged_result,
    }
    # Gate the synthesized response on has_id: a JSON-RPC notification
    # (no id key) MUST never receive a response. _detect_paginated_list keys only
    # off method + cursor-absence, so a `tools/list` sent as a notification reaches
    # here with has_id=False; emitting the merged response would deliver a spurious
    # `{"id":null,...}` frame to a strict client — the exact violation every other
    # synthesized-write path (_post_and_stream's empty-200 / interrupted / retry-
    # exhausted writes) already guards. The _StreamResult return stays unconditional
    # so session-id adoption still works for a notification.
    if has_id:
        _emit(json.dumps(merged_response), tracker)
    return _StreamResult(last_session, 200)


# --- cold-start: answer initialize locally while OAuth runs in the background ---
#
# An interactive OAuth flow (browser -> SSO -> MFA -> consent -> redirect) takes
# 30-180 s, but a client's `initialize` typically times out in ~60 s, so a cold
# (no/expired token) --oauth start fails to attach. With --oauth-eager the relay
# answers `initialize` locally (advertising listChanged so the client honours a
# later refresh), gates the other methods, and runs OAuth on a background thread;
# when it completes the gate lifts and `notifications/.../list_changed` tells the
# client to fetch the now-available lists. Streamable HTTP only (#296 / #59-adj).
_COLD_START_NOT_READY_CODE = -32002  # "server busy / not ready" (used by tools/call)

# list-method -> the empty result body returned while gated, so a client that
# fetches before OAuth completes sees an empty (not failed) list and re-fetches
# on the list_changed notification.
_COLD_START_EMPTY_LIST = {
    "tools/list": {"tools": []},
    "resources/list": {"resources": []},
    "resources/templates/list": {"resourceTemplates": []},
    "prompts/list": {"prompts": []},
}
_COLD_START_LIST_CHANGED = (
    "notifications/tools/list_changed",
    "notifications/resources/list_changed",
    "notifications/prompts/list_changed",
)


def _cold_start_response(line: str, req_id: Any, has_id: bool) -> str | None:
    """Synthesize a local reply for a pre-OAuth (gated) stdin line, or None.

    Returns the JSON-RPC line to emit to stdout, or ``None`` when the line should
    be swallowed silently (a notification that must not reach the unauthorized
    upstream). The caller never forwards a gated line upstream.

    - ``initialize`` -> a local InitializeResult echoing the client's requested
      protocolVersion (floor 2024-11-05 if absent) and advertising listChanged
      on tools/resources/prompts, so the client honours the later list_changed.
    - a list method -> an empty list result (the client re-fetches on
      list_changed once OAuth completes).
    - ``ping`` -> an empty result.
    - any other request (tools/call, resources/read, …) -> a ``-32002`` error
      ("authorizing, retry shortly").
    - any notification (incl. ``notifications/initialized``) -> swallowed.
    """
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        msg = None
    method = msg.get("method") if isinstance(msg, dict) else None

    if method == "initialize":
        requested = None
        if isinstance(msg, dict):
            params = msg.get("params")
            if isinstance(params, dict):
                pv = params.get("protocolVersion")
                if isinstance(pv, str) and pv:
                    requested = pv
        result = {
            "protocolVersion": requested or "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"listChanged": True},
                "prompts": {"listChanged": True},
            },
            "serverInfo": {"name": "mcp-stdio", "version": __version__},
        }
        return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})

    if not has_id:
        # A notification (including notifications/initialized) gets no reply and
        # must not be forwarded to the not-yet-authorized upstream — swallow it.
        return None

    if method in _COLD_START_EMPTY_LIST:
        return json.dumps(
            {"jsonrpc": "2.0", "id": req_id, "result": _COLD_START_EMPTY_LIST[method]}
        )
    if method == "ping":
        return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}})
    # Any other request needs the upstream, which is not reachable until OAuth
    # completes. Tell the client to retry shortly rather than hang.
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": _COLD_START_NOT_READY_CODE,
                "message": "authorizing with the upstream server, please retry shortly",
            },
        }
    )


def _cold_start_loop(
    *,
    login: Callable[[], dict[str, str] | None],
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    headers_lock: threading.Lock,
    tracker: "_CancelTracker | None",
    state: dict[str, Any],
    state_lock: threading.Lock,
    ready: threading.Event,
) -> None:
    """Background daemon: run interactive OAuth, then open the upstream session.

    On success: merge the auth headers (under ``headers_lock``), perform the
    upstream initialize handshake (``_reinitialize`` -> session id + protocol
    version), publish them in ``state`` (under ``state_lock``), set ``ready`` so
    the main loop lifts the gate, and emit ``list_changed`` notifications so the
    client fetches the now-available lists. Any failure leaves the gate closed
    (gated requests keep returning -32002); the thread never crashes the relay.
    """
    try:
        new_headers = login()
        if not new_headers:
            log("cold-start OAuth did not complete; gate stays closed")
            return
        with headers_lock:
            headers.update(new_headers)
            snapshot = dict(headers)
        sid, pv = _reinitialize(client, url, snapshot, None)
        if sid is None:
            log("cold-start: upstream initialize failed after OAuth")
            return
        with state_lock:
            state["session_id"] = sid
            state["protocol_version"] = pv
        ready.set()
        log("cold-start ready: OAuth complete, upstream session established")
        for method in _COLD_START_LIST_CHANGED:
            _emit(json.dumps({"jsonrpc": "2.0", "method": method}), tracker)
    except Exception as e:  # noqa: BLE001 — the daemon must never crash the relay
        log(f"cold-start background error: {e}")


# --- modern era: relay-originated subscriptions/listen stream (#270 Phase 2 PR A) ---
#
# Spec rev 2026-07-28 removed the legacy long-lived GET stream, so on the
# modern era NO server-initiated notification can reach the stdio client
# unless the relay opens a ``subscriptions/listen`` POST stream itself
# (subscriptions pattern). A legacy stdio client never sends
# ``subscriptions/listen`` — it does not know the method — so the relay
# ORIGINATES the request once the client's ``notifications/initialized``
# confirms the handshake is complete (#352 review finding 1; the body
# snapshot is seeded earlier, at ``initialize`` interception —
# ``_handle_modern_special_method`` -> run()'s ``_start_listen_stream``)
# and forwards ONLY the three ``list_changed`` notification kinds
# downstream. Resource subscriptions (``resourceSubscriptions`` +
# ``resources/subscribe`` interception) are PR B; the MRTR bridge is PR C
# (#270 Phase 2 phasing).
_LISTEN_METHOD = "subscriptions/listen"
_LISTEN_ACK_METHOD = "notifications/subscriptions/acknowledged"
# Relay-minted JSON-RPC id prefix for the listen request (C10). STRING ids
# under the relay's own "mcp-stdio/" namespace cannot collide with a
# client-minted id unless the client maliciously adopts the relay's prefix:
# _emit's cancel tracker compares ids by exact value (and `"1" == 1` is
# False in Python, so even a numeric suffix can never alias an int id) —
# and the listen request's own terminal result is swallowed here, never
# emitted, so the tracker never even sees a listen id.
_LISTEN_ID_PREFIX = "mcp-stdio/listen/"
# The notification kinds requested on every listen POST: all three
# list_changed booleans, no ``resourceSubscriptions`` until PR B. Also the
# reference set the ack's honored subset is compared against.
_LISTEN_REQUESTED_NOTIFICATIONS = {
    "toolsListChanged": True,
    "promptsListChanged": True,
    "resourcesListChanged": True,
}
# The only methods a listen stream may forward downstream (whitelist
# semantics — everything else, including the ack, the terminal result and
# ``notifications/cancelled``, is relay-internal and swallowed). Same
# three methods the cold-start gate emits, shared so they can never drift.
_LISTEN_FORWARDED_NOTIFICATIONS = frozenset(_COLD_START_LIST_CHANGED)
# Error codes that prove the remote will NEVER accept subscriptions/listen
# (C6): -32601 Method not found, plus the modern reserved codes -32020
# HeaderMismatch / -32021 MissingRequiredClientCapability / -32022
# UnsupportedProtocolVersion — all deterministic rejections of this exact
# request, so retrying at 1 Hz forever would hammer a server that will
# never say yes. One loud stderr line, then the thread exits for good.
_LISTEN_TERMINAL_ERROR_CODES = frozenset({-32601, -32020, -32021, -32022})


def _build_listen_params(modern_state: "_ModernState") -> dict[str, Any]:
    """Build the FROZEN ``subscriptions/listen`` request params (C1).

    Snapshotted at ``initialize`` interception time (re-seeded by a
    re-``initialize`` only until the thread starts on
    ``notifications/initialized`` — see ``_handle_modern_special_method``)
    and reused verbatim on every reconnect — only the JSON-RPC id is
    re-minted per attempt. ``modern_state.log_level`` is rewritten on every
    ``logging/setLevel`` stdin line and a repeat ``initialize`` rewrites
    capabilities/version, so re-deriving the body per attempt would let it
    drift mid-session; headers, by contrast, ARE re-read fresh per attempt
    (C2) so token refreshes reach the stream. ``logLevel`` is deliberately
    absent from this ``_meta`` for the same reason.

    ``_meta`` nests INSIDE ``params`` — the established MCP convention
    (``params._meta``) that ``_inject_modern_meta`` follows for every other
    modern request. ``protocolVersion`` uses the exact expression
    ``_prepare_headers``' modern branch uses for ``MCP-Protocol-Version``,
    so the two byte-match at snapshot time — and ``_listen_stream_loop``
    pins every attempt's header to THIS frozen value (#352 review finding
    2), so they keep byte-matching even after a re-``initialize``
    renegotiates the mutable state. ``clientCapabilities`` may be
    ``{}`` (presence-based, like every modern request); ``clientInfo`` only
    when the client supplied one (SHOULD, never fabricated). Nested values
    are deep-copied so later mutations of ``modern_state`` can never reach
    the frozen snapshot. No ``resourceSubscriptions`` until PR B.
    """
    meta: dict[str, Any] = {
        _META_PROTOCOL_VERSION: (
            modern_state.negotiated_version or _MODERN_PROTOCOL_VERSION_DEFAULT
        ),
        _META_CLIENT_CAPABILITIES: copy.deepcopy(modern_state.client_capabilities)
        or {},
    }
    if modern_state.client_info:
        meta[_META_CLIENT_INFO] = copy.deepcopy(modern_state.client_info)
    return {
        "_meta": meta,
        "notifications": dict(_LISTEN_REQUESTED_NOTIFICATIONS),
    }


def _strip_listen_subscription_id(msg: dict[str, Any]) -> dict[str, Any]:
    """Return ``msg`` with ``params._meta``'s subscriptionId key removed.

    ``io.modelcontextprotocol/subscriptionId`` correlates a notification to
    the listen request that subscribed to it — relay-internal state that is
    meaningless to the legacy stdio client downstream. A ``_meta`` left
    empty by the strip is dropped entirely: an empty ``_meta`` object the
    upstream never sent carries no information and would only differ from
    the legacy wire shape for nothing. Every other ``_meta`` key (e.g. a
    server-stamped ``serverInfo``) passes through untouched. Copies are
    shallow-per-level rebuilds, so the caller's parsed message is never
    mutated in place.
    """
    params = msg.get("params")
    if not isinstance(params, dict):
        return msg
    meta = params.get("_meta")
    if not isinstance(meta, dict) or _META_SUBSCRIPTION_ID not in meta:
        return msg
    meta = {k: v for k, v in meta.items() if k != _META_SUBSCRIPTION_ID}
    if meta:
        params = {**params, "_meta": meta}
    else:
        params = {k: v for k, v in params.items() if k != "_meta"}
    return {**msg, "params": params}


def _handle_listen_message(
    payload: str,
    listen_id: str,
    tracker: "_CancelTracker | None",
    state: dict[str, Any] | None,
) -> str | None:
    """Dispatch one JSON-RPC message from the listen stream.

    Returns ``"graceful"`` (server ended the stream on purpose — stop, no
    reconnect, nothing on stdout), ``"terminal"`` (the remote will never
    accept ``subscriptions/listen`` — C6: logged loudly once, stop, no
    reconnect), or ``None`` (message consumed; keep reading).

    Whitelist semantics: only the three ``list_changed`` notification
    kinds are forwarded (subscriptionId stripped first), and only as TRUE
    notifications — a whitelisted method carrying an ``id`` is a JSON-RPC
    request, not a notification, and is swallowed (#352 round-2 finding
    3: a hostile upstream must not solicit a response from the legacy
    client through the listen stream). The ack records
    the honored subset into ``state`` and logs one line iff it differs
    from the requested set. There are TWO graceful-end signals — a result
    bearing the listen id (SHOULD) and ``notifications/cancelled``
    referencing it (MUST) — and either alone counts: a server honoring
    only the MUST would otherwise look like an abrupt drop and be
    reconnect-looped forever. Everything else is swallowed. Id compares
    are type-aware by construction: the listen id is a namespaced STRING
    (``_LISTEN_ID_PREFIX``), and ``==`` between an int and a str is always
    False, so a client-style numeric id can never alias it.

    ``_emit`` may raise ``OSError``/``BrokenPipeError`` (stdout closed);
    that propagates to ``_listen_stream_loop``'s terminal handler (C12).
    """
    try:
        msg = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(msg, dict):
        return None
    method = msg.get("method")
    if method == _LISTEN_ACK_METHOD:
        params = msg.get("params")
        honored = params.get("notifications") if isinstance(params, dict) else None
        if state is not None:
            state["honored"] = honored
        if honored != _LISTEN_REQUESTED_NOTIFICATIONS:
            log(
                "listen stream: server honored a subset of the requested "
                f"notifications: {honored}"
            )
        return None
    if method in _LISTEN_FORWARDED_NOTIFICATIONS:
        # #352 round-2 finding 3: JSON-RPC 2.0 defines any message that
        # CARRIES an "id" member as a request — the sender expects a
        # response. A hostile or malformed upstream could stamp an id onto
        # a whitelisted method to smuggle a live request onto the stdio
        # wire, and the legacy client may answer it — leaking a
        # relay-internal interaction into the ordinary request path. Only a
        # true notification (id absent) is forwarded; anything else is
        # swallowed like every other non-whitelisted message.
        if "id" not in msg:
            _emit(json.dumps(_strip_listen_subscription_id(msg)), tracker)
        return None
    if method == "notifications/cancelled":
        params = msg.get("params")
        rid = params.get("requestId") if isinstance(params, dict) else None
        if rid == listen_id:
            log("listen stream: closed gracefully (notifications/cancelled)")
            return "graceful"
        return None
    if "method" not in msg and ("result" in msg or "error" in msg):
        if "error" in msg:
            error = msg.get("error")
            code = error.get("code") if isinstance(error, dict) else None
            # Any error for our id, or a deterministic-rejection code under
            # ANY id (a server may reject an unknown method with id null).
            if msg.get("id") == listen_id or code in _LISTEN_TERMINAL_ERROR_CODES:
                log(
                    "listen stream: server rejected subscriptions/listen "
                    f"({error}); list_changed forwarding disabled for this "
                    "session"
                )
                return "terminal"
            return None
        if msg.get("id") == listen_id:
            log("listen stream: closed gracefully (result for the listen request)")
            return "graceful"
        return None
    return None


def _listen_stream_loop(
    *,
    client: httpx.Client,
    url: str,
    params: dict[str, Any],
    prepare_headers: Callable[[str], dict[str, str]],
    tracker: "_CancelTracker | None",
    stop: threading.Event,
    timeout: httpx.Timeout,
    state: dict[str, Any] | None = None,
) -> None:
    """Reader thread: maintain the modern ``subscriptions/listen`` stream.

    ``client`` is this thread's own DEDICATED httpx client (#352 round-2
    finding 2) — never run()'s shared one. A read parked in
    ``iter_text()`` can outlive any bounded join by up to
    ``--listen-read-timeout`` (300 s default), so run()'s shutdown
    ACTIVELY closes this client from the main thread: the parked read
    raises a mapped ``httpx.TransportError`` at once (httpcore's pool
    close is lock-guarded and its connection close is documented as
    deliberately unilateral), the stop-set drop arm below exits silently,
    the join then succeeds fast, and only afterwards does run() close the
    shared client. The thread itself never closes this client — run()'s
    finally owns that unconditionally (``httpx.Client.close`` is
    idempotent), covering the natural exit arms too so no connection
    leaks until process exit.

    Opened once per session by run()'s ``_start_listen_stream`` on the
    client's ``notifications/initialized`` (#352 review finding 1 — never
    before the synthesized InitializeResult reached stdout). Per attempt:
    re-mint the id (``mcp-stdio/listen/1``, ``/2``, ...) into the FROZEN
    ``params`` snapshot (C1), take a FRESH ``prepare_headers`` snapshot
    (C2 — it locks internally, so token refreshes from the main loop /
    proactive daemon are picked up on reconnect) with its
    ``MCP-Protocol-Version`` re-pinned to the snapshot's frozen version
    (#352 review finding 2 — see the comment at the pin), plus this
    request's own ``Mcp-Method`` and a dual ``Accept``, and stream the
    POST with the dedicated read timeout (``--listen-read-timeout``;
    per-request override, like ``run_sse``'s ``post_timeout``).

    Raw ``client.stream`` + the shared SSE decoders — deliberately NOT
    ``_post_and_stream`` (its retry ladder and stdout plumbing must not
    run) and NOT ``_first_response_message`` (it returns at the first
    response; this stream must keep reading). A JSON (non-SSE) 200 is a
    legal immediate end, judged by its content like any stream message.

    Outcome arms:

    - graceful (either signal — see ``_handle_listen_message``): stop, no
      reconnect, nothing on stdout.
    - non-support (C6): ANY non-200 whose body is a JSON-RPC error with a
      terminal code (#352 round-3 finding 1 — a ``-32601``-bodied 404 is
      the canonical case, but a reconnect answered 400 + ``-32020`` must
      not be retried forever either; see ``_listen_error_code``), or a
      terminal error result on-stream — one loud stderr line, stop, NEVER
      retry (retrying would POST forever at 1 Hz against a server that
      will never accept).
    - abrupt drop: stream end without a signal, a non-200 without a
      terminal-code body, or any
      ``httpx.HTTPError`` — after a first successful establishment,
      reconnect forever on a fixed ``stop.wait(RETRY_DELAY)`` backoff;
      BEFORE any success, fail fast instead (C7's ``established`` split —
      the first attempt runs moments after a successful probe/initialize,
      so a first-attempt failure is far more likely non-support than a
      blip). 401/403 are EXEMPT from that fail-fast (#352 round-2
      finding 1): an auth challenge is always a retryable drop (C3),
      established or not — NO auth recovery runs on this thread
      (``_probe_auth_recovery``'s lock ordering is not safe from a
      third concurrent caller; ``_sse_reader_loop`` sets the precedent
      that a reader owns no recovery), the next attempt's fresh header
      snapshot picks up whatever the main loop / daemon refreshed.
    - dead stdout (C12): ``OSError``/``BrokenPipeError`` from ``_emit`` is
      terminal — reconnecting into a closed stdout would spin forever.
    """
    # C1 x C2 interaction guard (#352 review finding 2): the body is
    # FROZEN (C1) but prepare_headers (the modern _prepare_headers) reads
    # the MUTABLE modern_state.negotiated_version — a client-driven
    # re-initialize can renegotiate it mid-session, and a reconnect would
    # then send an MCP-Protocol-Version header disagreeing with the frozen
    # params._meta protocolVersion. A compliant server rejects that as
    # HeaderMismatch (-32020), which sits in _LISTEN_TERMINAL_ERROR_CODES:
    # the C6 terminal arm would permanently disable listening over a mere
    # renegotiation. Pin every attempt's header to the version frozen
    # inside the snapshot; everything ELSE in the fresh snapshot — the
    # credentials above all — stays fresh, which is C2's actual point.
    frozen_version = params["_meta"][_META_PROTOCOL_VERSION]
    attempt = 0
    established = False
    while not stop.is_set():
        attempt += 1
        listen_id = f"{_LISTEN_ID_PREFIX}{attempt}"
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": listen_id,
                "method": _LISTEN_METHOD,
                "params": params,
            }
        )
        req_headers = prepare_headers(body)
        # prepare_headers (the modern _prepare_headers) already derives
        # Mcp-Method from the body; set it explicitly so this thread's
        # request is correct even against a stub/legacy-shaped callable.
        # No Mcp-Name: subscriptions/listen is not a name-bearing method.
        req_headers = {k: v for k, v in req_headers.items() if k.lower() != "accept"}
        req_headers["Accept"] = "application/json, text/event-stream"
        req_headers["Mcp-Method"] = _LISTEN_METHOD
        # Frozen-version pin (#352 review finding 2, comment above the
        # loop): strip any case-variant first — the file's strip-then-set
        # discipline — so httpx never serialises two header lines.
        req_headers = {
            k: v for k, v in req_headers.items() if k.lower() != "mcp-protocol-version"
        }
        req_headers["MCP-Protocol-Version"] = frozen_version
        try:
            with client.stream(
                "POST", url, content=body, headers=req_headers, timeout=timeout
            ) as resp:
                if resp.status_code != 200:
                    resp.read()
                    # #352 round-3 finding 1: classify the BODY before the
                    # status split. Round 2 read only a 404 body, so a
                    # reconnect answered e.g. HTTP 400 with a -32020
                    # JSON-RPC body was treated as an abrupt drop and
                    # retried at 1 Hz forever — against a server rejecting
                    # THIS exact request deterministically, exactly what
                    # the C6 terminal arm exists to prevent. ANY non-200
                    # whose body parses to a terminal JSON-RPC error code
                    # (the same _LISTEN_TERMINAL_ERROR_CODES set
                    # _handle_listen_message classifies on-stream) now
                    # stops for good, established or not — and BEFORE the
                    # 401/403 exemption: a body carrying one of the
                    # reserved deterministic-rejection codes is the
                    # remote's own verdict on this request, more specific
                    # than the transport status around it. An absent or
                    # unparseable body keeps the round-2 split below
                    # exactly as it was.
                    code = _listen_error_code(resp)
                    if code in _LISTEN_TERMINAL_ERROR_CODES:
                        log(
                            "listen stream: server rejected "
                            f"subscriptions/listen (HTTP {resp.status_code}, "
                            f"JSON-RPC {code}); list_changed forwarding "
                            "disabled for this session"
                        )
                        return
                    # Three-way split (#352 round-2 finding 1): terminal
                    # codes (C6 — classified from the body above, and the
                    # terminal error results _handle_listen_message
                    # classifies) stop for good; auth challenges 401/403
                    # are ALWAYS retryable drops (C3), even before the
                    # stream was ever established — they heal EXTERNALLY
                    # (the main loop / proactive-refresh daemon refreshes
                    # credentials, and the next attempt's fresh
                    # _prepare_headers snapshot picks them up), so the
                    # fail-fast below must never eat them or a token
                    # expiring between initialize and the first listen
                    # POST would disable the stream permanently; every
                    # OTHER pre-establishment failure fails fast (C7 — a
                    # server that will never say yes must not be hammered
                    # at 1 Hz, a rationale that fits -32601/404/4xx
                    # generally but NOT auth challenges).
                    if resp.status_code in (401, 403):
                        log(
                            f"listen stream: HTTP {resp.status_code}; "
                            "reconnecting with a fresh header snapshot"
                        )
                    elif not established:
                        log(
                            f"listen stream: HTTP {resp.status_code} before the "
                            "stream was ever established; list_changed "
                            "forwarding disabled for this session"
                        )
                        return
                    else:
                        log(f"listen stream: HTTP {resp.status_code}; reconnecting")
                else:
                    established = True
                    if _is_sse_response(resp):
                        for event_type, data in _iter_sse_events(
                            _iter_sse_lines(resp.iter_text())
                        ):
                            if stop.is_set():
                                return
                            if event_type != "message":
                                continue
                            if (
                                _handle_listen_message(data, listen_id, tracker, state)
                                is not None
                            ):
                                return
                        # Stream ended with neither graceful signal.
                        log("listen stream ended without a signal; reconnecting")
                    else:
                        resp.read()
                        text = resp.text.strip()
                        if (
                            text
                            and _handle_listen_message(text, listen_id, tracker, state)
                            is not None
                        ):
                            return
                        log(
                            "listen stream: JSON 200 carried no terminal "
                            "signal; reconnecting"
                        )
        except httpx.HTTPError as e:
            if stop.is_set():
                return
            if not established:
                log(
                    f"listen stream failed before it was ever established "
                    f"({e}); list_changed forwarding disabled for this session"
                )
                return
            log(f"listen stream dropped ({e}); reconnecting")
        except OSError as e:
            if stop.is_set():
                # Shutdown teardown (#352 round-2 finding 2): run()'s
                # finally closed THIS thread's dedicated client to yank a
                # parked read, so a raw OSError surfacing now is that
                # teardown, not a stdout failure — exit silently, exactly
                # like the HTTPError stop-set arm above.
                return
            # C12: _emit's stdout write failed (BrokenPipeError is an
            # OSError) — the downstream reader is gone; reconnecting the
            # upstream stream would spin against a dead stdout.
            log(f"listen stream: stdout write failed ({e}); stopping")
            return
        if stop.wait(RETRY_DELAY):
            return


def _listen_error_code(resp: httpx.Response) -> int | None:
    """JSON-RPC error code carried by a (fully-read) response body, or None.

    Generalized from a 404-only ``-32601`` probe by #352 round-3 finding
    1: ANY non-200 the listen POST gets back may carry the remote's real
    JSON-RPC verdict (e.g. HTTP 400 with a ``-32020`` body), and only the
    code decides whether the rejection is one of the deterministic
    ``_LISTEN_TERMINAL_ERROR_CODES``. HTTP status alone stays ambiguous
    (a legacy proxy, a wrong path, a transient 5xx) — an unparseable,
    absent, or code-less body returns ``None`` and the caller falls back
    to the status-based drop/fail-fast split.
    """
    try:
        parsed = json.loads(resp.text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    error = parsed.get("error")
    code = error.get("code") if isinstance(error, dict) else None
    return code if isinstance(code, int) else None


def _reinitialize(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    protocol_version: str | None = None,
) -> tuple[str | None, str | None]:
    """Send an initialize handshake to establish a new MCP session.

    Used to recover after a session expires (server returns 404 on the
    next request). Performs the full MCP initialize handshake:

    1. POST an ``initialize`` request to get a new session ID
    2. POST a ``notifications/initialized`` notification to signal
       readiness (required by the MCP spec before any other requests)

    The re-handshake may renegotiate a different protocol version than the
    one originally captured (e.g. a downgrade), so the InitializeResult is
    parsed for ``result.protocolVersion`` and the freshly negotiated value is
    used for the ``notifications/initialized`` header and returned to the
    caller. ``notifications/initialized`` is the first "subsequent request"
    of the recovered session, so it carries ``MCP-Protocol-Version``; the
    initialize POST itself omits it — it is the (re)negotiation and predates
    a known version.

    Returns ``(new_session_id, negotiated_protocol_version)``. The session id
    is ``None`` on failure; the protocol version falls back to the passed-in
    ``protocol_version`` when the response omits ``result.protocolVersion``.

    The initialize request advertises the previously-negotiated
    ``protocol_version`` when known, rather than the 2024-11-05 floor: this
    is a *recovery* handshake, so a higher version was already in force and
    volunteering the floor would invite a silent downgrade. A first-contact
    probe (``check_connection``) legitimately requests the floor; recovery
    must not. The re-capture below still adopts whatever the server actually
    returns, so a server that genuinely dropped support degrades gracefully.
    """
    initialize_msg = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 0,
            "params": {
                "protocolVersion": protocol_version or "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-stdio", "version": __version__},
            },
        }
    )
    # An initialize request IS the (re)negotiation, so it must not advertise a
    # prior protocol version. The relay-injected MCP-Protocol-Version never
    # reaches here (the caller passes the base headers, not _prepare_headers
    # output), but an operator who pinned `-H MCP-Protocol-Version: <x>` would
    # otherwise have it ride this initialize POST — inconsistent with the
    # dispatch path, which strips it from a real initialize (see).
    # Mirror that strip so both initialize paths behave identically. Also drop a
    # pinned case-variant Mcp-Session-Id: an initialize POST establishes a FRESH
    # session, so a stale operator-pinned session id must not ride it.
    init_headers = {
        k: v
        for k, v in headers.items()
        if k.lower() not in ("mcp-protocol-version", "mcp-session-id")
    }
    try:
        resp = client.post(url, content=initialize_msg, headers=init_headers)
    except httpx.HTTPError as e:
        log(f"re-initialize request failed: {e}")
        return None, protocol_version
    if resp.status_code != 200:
        log(f"re-initialize returned HTTP {resp.status_code}")
        return None, protocol_version
    new_session_id = resp.headers.get("mcp-session-id")
    if not new_session_id:
        log("re-initialize response missing mcp-session-id header")
        return None, protocol_version

    # Re-capture the negotiated protocol version from the InitializeResult so
    # the recovered session's header matches the version actually in force.
    negotiated = protocol_version
    if "text/event-stream" in resp.headers.get("content-type", ""):
        for event_type, payload in _iter_sse_events(_split_sse_text(resp.text)):
            if event_type == "message":
                pv = _extract_protocol_version(payload)
                if pv:
                    negotiated = pv
                    break
    else:
        pv = _extract_protocol_version(resp.text.strip())
        if pv:
            negotiated = pv

    # MCP spec: send notifications/initialized before any other requests
    initialized_msg = json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    # Drop any operator-pinned case-variant before injecting, mirroring
    # _prepare_headers' strip discipline, so the notifications/initialized POST
    # never serialises two Mcp-Session-Id / MCP-Protocol-Version lines that a
    # strict 2025-06-18 server treats as a singleton field. The
    # protocol-version strip is gated on `negotiated` (only stripped when set),
    # so an operator pin still rides through if the relay negotiated none.
    initialized_headers = {
        k: v for k, v in headers.items() if k.lower() != "mcp-session-id"
    }
    initialized_headers["Mcp-Session-Id"] = new_session_id
    if negotiated:
        initialized_headers = {
            k: v
            for k, v in initialized_headers.items()
            if k.lower() != "mcp-protocol-version"
        }
        initialized_headers["MCP-Protocol-Version"] = negotiated
    try:
        resp = client.post(url, content=initialized_msg, headers=initialized_headers)
    except httpx.HTTPError as e:
        log(f"notifications/initialized failed: {e}")
        return None, protocol_version
    if resp.status_code not in (200, 202):
        log(f"notifications/initialized returned HTTP {resp.status_code}")
        return None, protocol_version
    return new_session_id, negotiated


def _format_jsonrpc_error(err: Any) -> str:
    """Render a JSON-RPC ``error`` value for a ``--check`` diagnostic log.

    The spec guarantees ``error`` is an object with a ``message`` field, but
    a non-compliant server could send anything valid-JSON there (a bare
    string, a number, ``null``...). ``.get`` on a non-dict would raise
    ``AttributeError`` — degrade instead of crashing (#350 review round
    2/3): fall back to stringifying the raw value when it is not the
    object the spec promises.
    """
    return str(err.get("message", err)) if isinstance(err, dict) else str(err)


def _report_initialize(result_data: dict[str, Any] | None) -> bool:
    """Log a parsed ``initialize`` response and return the probe verdict.

    Shared by the Streamable HTTP and SSE ``--check`` paths. Returns False
    only when the response is a JSON-RPC error; an unparseable / missing
    result still counts as "the server responded" (True).

    ``result_data`` is guarded with ``isinstance(..., dict)`` at both branch
    entries below — not just ``if result_data`` — because a non-compliant
    fallback response can be ANY valid JSON value (a bare ``1``, ``"oops"``,
    ``[]``...), which is truthy but not a mapping: ``"result" in result_data``
    on a scalar raises ``TypeError`` (#350 review round 2/3). Falling through
    to the final "could not parse" log/``True`` for a non-dict is the
    correct degrade — this function's whole contract is "never crash on
    malformed-but-JSON-valid input, only report a genuine JSON-RPC error as
    False."
    """
    if isinstance(result_data, dict) and "result" in result_data:
        result = result_data["result"]
        if not isinstance(result, dict):
            # Spec guarantees an object, but a malformed server could send a
            # scalar/array — treat as "responded" rather than crashing on .get.
            log("✓ Server responded (initialize result is not an object)")
            return True
        server_info = result.get("serverInfo") or {}
        name = server_info.get("name", "unknown")
        version = server_info.get("version", "?")
        protocol = result.get("protocolVersion", "?")
        log(f"✓ MCP initialize: server={name} v{version}, protocol={protocol}")

        caps = result.get("capabilities") or {}
        # MCP capabilities are presence-based: ``"tools": {}`` means tools ARE
        # supported (an empty object, not "disabled"). Test membership, not
        # truthiness, so an empty-but-present capability reports "yes".
        tools = "yes" if "tools" in caps else "no"
        resources = "yes" if "resources" in caps else "no"
        prompts = "yes" if "prompts" in caps else "no"
        log(f"✓ Capabilities: tools={tools}, resources={resources}, prompts={prompts}")
        return True
    if isinstance(result_data, dict) and "error" in result_data:
        log(f"✗ MCP error: {_format_jsonrpc_error(result_data['error'])}")
        return False
    log("✓ Server responded (could not parse initialize result)")
    return True


def _parse_streamable_response(resp: httpx.Response) -> dict[str, Any] | None:
    """Parse a BUFFERED Streamable HTTP POST response body (JSON or SSE).

    The probes reach this only through ``_post_probe`` (#350 review round
    5), which streams an SSE body incrementally and stops at the first
    JSON-RPC response — buffering an SSE body here would block until the
    read timeout on a server that keeps the stream open after answering, as
    the spec allows (the final response only SHOULD terminate the stream).
    ``_post_probe`` therefore only calls this on an already-read non-SSE
    body; the SSE branch below (via the shared ``_first_response_message``
    gate, so both paths skip interleaved notifications identically) is kept
    for parsing any fully-buffered response a caller already holds.

    Returns ``None`` — never a non-dict — for a body that parses as valid
    JSON but is not an object (a bare ``1``, ``"oops"``, ``[]``...): the
    return type is declared ``dict[str, Any] | None``, and the report
    helpers (``_report_initialize``/``_report_discover``) are written
    against that contract. The SSE branch already enforced this (its own
    ``isinstance`` gate); the plain-JSON branch used not to (#350 review
    round 2/3).
    """
    if _is_sse_response(resp):
        return _first_response_message(_iter_sse_events(_split_sse_text(resp.text)))
    try:
        parsed = json.loads(resp.text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _report_discover(result_data: dict[str, Any] | None) -> bool:
    """Log a parsed ``server/discover`` response and return the probe verdict.

    Mirrors ``_report_initialize``'s verdict rule: False only for a JSON-RPC
    error; a missing/unparseable result still counts as "the server
    responded" (spec rev 2026-07-28, ``server/discover``'s ``DiscoverResult``,
    whose ``serverInfo`` lives at ``_meta["io.modelcontextprotocol/serverInfo"]``
    rather than as a top-level field — see the verified research fetched
    directly from the spec's own worked example).

    ``result_data`` is guarded with ``isinstance(..., dict)`` for the same
    reason as ``_report_initialize``'s identical guard: a non-compliant
    fallback response can be any valid-JSON scalar/array, which is truthy
    but not a mapping (#350 review round 2/3).
    """
    if isinstance(result_data, dict) and "result" in result_data:
        result = result_data["result"]
        if not isinstance(result, dict):
            log("✓ Server responded (discover result is not an object)")
            return True
        meta = result.get("_meta")
        server_info = (
            meta.get("io.modelcontextprotocol/serverInfo", {})
            if isinstance(meta, dict)
            else {}
        )
        name = (
            server_info.get("name", "unknown")
            if isinstance(server_info, dict)
            else "unknown"
        )
        version = (
            server_info.get("version", "?") if isinstance(server_info, dict) else "?"
        )
        versions = result.get("supportedVersions")
        versions_str = versions if isinstance(versions, list) else "?"
        log(
            f"✓ MCP server/discover: server={name} v{version}, "
            f"supportedVersions={versions_str}"
        )
        caps = result.get("capabilities")
        caps = caps if isinstance(caps, dict) else {}
        tools = "yes" if "tools" in caps else "no"
        resources = "yes" if "resources" in caps else "no"
        prompts = "yes" if "prompts" in caps else "no"
        log(f"✓ Capabilities: tools={tools}, resources={resources}, prompts={prompts}")
        return True
    if isinstance(result_data, dict) and "error" in result_data:
        log(f"✗ MCP error: {_format_jsonrpc_error(result_data['error'])}")
        return False
    log("✓ Server responded (could not parse discover result)")
    return True


# HTTP statuses on which the legacy `initialize` probe in check_connection()
# falls back to a `server/discover` retry (spec rev 2026-07-28, "Backward
# Compatibility" / "Protocol Version Header"): 404 is what the transport spec
# mandates for an unrecognized method, which `initialize` now IS on a server
# that has fully removed the legacy handshake; 400 is what the same server
# returns when the request is also missing required per-request
# `_meta`/headers a modern-only server demands. Neither code is unique to
# "server doesn't speak legacy" — a 400/404 can equally mean a genuinely
# broken/misconfigured endpoint — so this is a best-effort diagnostic
# heuristic, not a protocol requirement: worst case, a broken endpoint gets
# one extra POST before check_connection reports it down. Every OTHER
# status (500, 503, ...) is left alone deliberately: retrying those with a
# different method would not distinguish "legacy-dropped" from "broken" any
# better, and would cost every genuinely-broken endpoint a second round-trip
# for no diagnostic gain.
_DISCOVER_FALLBACK_STATUSES = (400, 404)


def _check_connection_sse(
    url: str,
    headers: dict[str, str],
    *,
    timeout_connect: float,
    timeout_read: float,
) -> bool:
    """Check legacy SSE (2024-11-05) connectivity via the full handshake.

    Streamable HTTP can be probed with a single POST, but the legacy SSE
    transport delivers JSON-RPC responses asynchronously over the long-lived
    GET stream — a bare POST to the SSE URL would not work. This mirrors
    ``run_sse``'s bootstrap as a one-shot: open the GET stream, wait for the
    ``endpoint`` event, POST ``initialize`` to that endpoint, and read the
    response off the stream. Returns True if the server completes the
    handshake.
    """
    initialize_msg = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-stdio", "version": __version__},
            },
        }
    )

    client = httpx.Client(
        timeout=httpx.Timeout(
            connect=timeout_connect, read=timeout_read, write=30, pool=10
        )
    )

    # The GET stream read blocks in the main thread; the POST runs in a helper
    # thread. On a POST failure the helper closes the stream so the probe fails
    # fast instead of hanging until the read timeout for a response that will
    # never arrive.
    #
    # ``holder`` is shared between the two threads WITHOUT a lock, relying on
    # CPython dict item get/set being atomic under the GIL (the same convention
    # _SseState documents). ``resp`` is published before the POST thread spawns,
    # so its read is ordered. ``post_error`` is only used to pick which of two
    # diagnostic strings to log on a probe failure; a benign read-before-write
    # race there can mis-pick the message but never affects the bool verdict and
    # never touches stdout — this is the one-shot --check path, not the relay.
    holder: dict[str, Any] = {"resp": None, "post_error": None}

    def do_post(endpoint: str) -> None:
        try:
            r = client.post(endpoint, content=initialize_msg, headers=headers)
            if r.status_code not in (200, 202):
                holder["post_error"] = f"HTTP {r.status_code}"
        except Exception as e:  # noqa: BLE001 — surfaced via holder below
            holder["post_error"] = str(e)
        if holder["post_error"] is not None:
            stream = holder["resp"]
            if stream is not None:
                # this closes the GET stream from the POST helper
                # thread while the MAIN thread may be mid-iter_text(). It is the
                # intended fast-fail (don't block the read until timeout for a
                # reply that will never come), confined to the one-shot --check
                # path — never the relay loop. A cross-thread close during an
                # active read can surface as an exception rather than a clean
                # StopIteration on some httpx/httpcore versions; that is caught by
                # the outer `except Exception` and the verdict stays False, so it
                # is best-effort by design.
                try:
                    stream.close()
                except Exception:  # noqa: BLE001
                    pass

    try:
        log(f"testing SSE connection to {redact_url(url)}")
        with client.stream("GET", url, headers=headers) as resp:
            holder["resp"] = resp
            if resp.status_code != 200:
                log(f"✗ HTTP {resp.status_code}")
                return False
            log(f"✓ SSE stream open (HTTP {resp.status_code})")

            endpoint_seen = False
            for event_type, data in _iter_sse_events(_iter_sse_lines(resp.iter_text())):
                if event_type == "endpoint":
                    resolved = urljoin(url, data)
                    # Same cross-origin credential guard as the relay reader:
                    # never POST an Authorization header to a different origin.
                    has_auth = any(k.lower() == "authorization" for k in headers)
                    if has_auth and not _same_origin(resolved, url):
                        log(
                            f"✗ refusing cross-origin SSE endpoint {resolved!r} "
                            f"(differs from {url!r})"
                        )
                        return False
                    log(f"✓ SSE endpoint: {resolved}")
                    endpoint_seen = True
                    threading.Thread(
                        target=do_post, args=(resolved,), daemon=True
                    ).start()
                elif event_type == "message":
                    if not endpoint_seen:
                        continue
                    try:
                        result_data = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(result_data, dict) and (
                        "result" in result_data or "error" in result_data
                    ):
                        return _report_initialize(result_data)
                    # A server-initiated notification, not our response — keep
                    # reading until the initialize result arrives.

            # Stream ended (or was closed by the POST helper) before a response.
            if holder["post_error"] is not None:
                log(f"✗ POST to SSE endpoint failed: {holder['post_error']}")
            else:
                log("✗ SSE stream ended before initialize response")
            return False
    except Exception as e:  # noqa: BLE001
        if holder["post_error"] is not None:
            log(f"✗ POST to SSE endpoint failed: {holder['post_error']}")
        else:
            log(f"✗ Connection failed: {e}")
        return False
    finally:
        client.close()


def check_connection(
    url: str,
    headers: dict[str, str],
    *,
    timeout_connect: float = 10,
    timeout_read: float = 120,
    transport: str = "streamable-http",
) -> bool:
    """Check MCP server connectivity by sending an initialize request.

    Returns True if the server responds successfully. ``transport`` selects
    the probe: ``"streamable-http"`` (default) POSTs ``initialize`` directly,
    while ``"sse"`` runs the legacy GET/endpoint/POST handshake so the probe
    matches what ``run_sse`` would actually do.

    On the Streamable HTTP path, a 400/404 response to the ``initialize``
    probe retries once with ``server/discover`` (spec rev 2026-07-28,
    ``_DISCOVER_FALLBACK_STATUSES``) before reporting the connection down —
    a server that has dropped the legacy handshake entirely no longer
    recognizes ``initialize`` at all, and would otherwise be misreported as
    unreachable rather than "alive, modern-only". The retry is built by
    ``_build_discover_probe_request`` — the SAME modern-shaped body/headers
    (``Mcp-Method``, ``MCP-Protocol-Version``, ``params._meta``) that
    ``_probe_protocol_era`` sends, not the bare ``initialize`` probe's
    unmodified ``headers`` (#350 review finding 1: a strict modern-only
    server can reject a discovery request missing its own required
    metadata, which would make THIS retry itself misreport a live modern
    server as down).

    Both probes stream their responses via ``_post_probe`` and stop at the
    first JSON-RPC response message (#350 review round 5) — see that
    helper's docstring for why a buffered read would hang the --check until
    the read timeout on a server that SSE-frames the response and keeps the
    stream open.
    """
    if transport == "sse":
        return _check_connection_sse(
            url,
            headers,
            timeout_connect=timeout_connect,
            timeout_read=timeout_read,
        )

    initialize_msg = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-stdio", "version": __version__},
            },
        }
    )

    client = httpx.Client(
        timeout=httpx.Timeout(
            connect=timeout_connect, read=timeout_read, write=30, pool=10
        )
    )

    try:
        log(f"testing connection to {redact_url(url)}")
        # _post_probe streams both probes and stops at the first JSON-RPC
        # response message (#350 review round 5): the final response only
        # SHOULD terminate an SSE stream, so a server that keeps the POST
        # stream open after answering must report ✓ promptly, not hang the
        # --check until the read timeout.
        resp, parsed = _post_probe(client, url, initialize_msg, headers)

        if resp.status_code != 200:
            if resp.status_code in _DISCOVER_FALLBACK_STATUSES:
                log(
                    f"initialize probe got HTTP {resp.status_code}; retrying "
                    "with server/discover in case the server dropped the "
                    "legacy handshake (spec rev 2026-07-28)"
                )
                discover_msg, discover_headers = _build_discover_probe_request(
                    headers, request_id=2
                )
                try:
                    discover_resp, discover_parsed = _post_probe(
                        client, url, discover_msg, discover_headers
                    )
                except httpx.HTTPError as e:
                    log(f"✗ server/discover retry failed: {e}")
                    log(f"✗ HTTP {resp.status_code}")
                    return False
                if discover_resp.status_code != 200:
                    log(
                        f"✗ server/discover retry also failed: HTTP {discover_resp.status_code}"
                    )
                    log(f"✗ HTTP {resp.status_code}")
                    return False
                log(
                    f"✓ Connected via server/discover (HTTP {discover_resp.status_code})"
                )
                ok = _report_discover(discover_parsed)
                if "mcp-session-id" in discover_resp.headers:
                    log(f"✓ Session ID: {discover_resp.headers['mcp-session-id']}")
                return ok
            # Do not surface the response body — server error responses
            # commonly carry session IDs, stack traces, or echoed request
            # data. The status code alone is the right operational signal
            # for the --check probe. See #16.
            log(f"✗ HTTP {resp.status_code}")
            return False

        log(f"✓ Connected (HTTP {resp.status_code})")

        ok = _report_initialize(parsed)

        if "mcp-session-id" in resp.headers:
            log(f"✓ Session ID: {resp.headers['mcp-session-id']}")

        return ok
    except Exception as e:
        log(f"✗ Connection failed: {e}")
        return False
    finally:
        client.close()


# Proactive token refresh — a background timer that refreshes the OAuth access
# token shortly before it expires, independent of the request flow. Reactive
# refresh only fires on a transport-level HTTP 401; some gateways (notably
# Atlassian's MCP gateway) signal an expired token as an HTTP 200 tool-result
# error (``isError: true``) instead, so neither reactive refresh nor the
# startup-only proactive ``ensure_token`` ever fires and a long-lived --oauth
# session cannot recover until the process restarts. The timer closes that gap
# generically, without ever parsing a tool-result body (#242).
_PROACTIVE_REFRESH_RECHECK_SECONDS = 60.0
_PROACTIVE_REFRESH_MAX_SLEEP = 300.0


def _proactive_refresh_loop(
    *,
    refresher: Callable[[], dict[str, str] | None],
    expiry_getter: Callable[[], float | None],
    leeway: float,
    headers: dict[str, str],
    headers_lock: threading.Lock,
    refresh_lock: threading.Lock,
    stop: threading.Event,
    now: Any = time.time,
    recheck: float = _PROACTIVE_REFRESH_RECHECK_SECONDS,
    max_sleep: float = _PROACTIVE_REFRESH_MAX_SLEEP,
) -> None:
    """Refresh the OAuth token shortly before it expires, off the request path.

    Wakes at ``expires_at - leeway`` (the expiry is read fresh each loop via
    ``expiry_getter``, which the caller backs with ``token_store.load_token``),
    calls ``refresher`` under ``refresh_lock`` to serialise against the main
    loop's reactive 401 refresh (a concurrent refresh would race the AS's
    refresh-token rotation), and merges the returned headers under
    ``headers_lock``. The thread must never die: any exception is logged and
    retried after a ``recheck`` backoff (mirrors the structural #11 safety net).
    A ``None`` expiry (no cached token / non-expiring token) or a ``refresher``
    that returns ``None`` (no refresh_token, refresh failed) degrades to a quiet
    ``recheck``-interval poll rather than a hot loop. ``now`` is injectable for
    deterministic tests, mirroring ``_CancelTracker``.
    """
    while not stop.is_set():
        try:
            exp = expiry_getter()
            if exp is None:
                # No cached token yet, or a token with no expiry — nothing to
                # schedule against, so poll on the recheck interval and stay idle.
                wait_for = recheck
            else:
                wait_for = exp - leeway - now()
            if wait_for > 0:
                # Interruptible sleep, capped at max_sleep so a token whose
                # expires_at moved out-of-band (another refresher wrote a new
                # value) is re-evaluated promptly instead of oversleeping to a
                # stale deadline. stop.wait returns True when signalled.
                if stop.wait(min(wait_for, max_sleep)):
                    return
                continue
            # Past the refresh deadline — refresh now, serialised with the
            # reactive 401 path so the two never race the refresh-token rotation.
            with refresh_lock:
                new_headers = refresher()
                if new_headers:
                    with headers_lock:
                        headers.update(new_headers)
            if not new_headers:
                # Refresh unavailable (no refresh_token) or failed (the refresher
                # swallows network errors and returns None). Back off before
                # retrying so a persistently-failing refresh never hot-loops.
                if stop.wait(recheck):
                    return
        except Exception as e:  # noqa: BLE001 — the daemon must never die
            log(f"proactive token refresh error: {e}")
            if stop.wait(recheck):
                return


def _start_proactive_refresh(
    *,
    refresher: Callable[[], dict[str, str] | None] | None,
    expiry_getter: Callable[[], float | None] | None,
    proactive_refresh: bool,
    leeway: float,
    headers: dict[str, str],
    headers_lock: threading.Lock,
    refresh_lock: threading.Lock,
) -> tuple[threading.Thread | None, threading.Event | None]:
    """Start the proactive-refresh daemon, or no-op when not applicable.

    Returns ``(thread, stop_event)`` so the caller can stop and join it in its
    ``finally``, or ``(None, None)`` when disabled (``--no-proactive-refresh``)
    or when there is nothing to refresh (no OAuth: the refresher / expiry getter
    is ``None``).
    """
    if not (proactive_refresh and refresher is not None and expiry_getter is not None):
        return None, None
    stop = threading.Event()
    thread = threading.Thread(
        target=_proactive_refresh_loop,
        kwargs={
            "refresher": refresher,
            "expiry_getter": expiry_getter,
            "leeway": leeway,
            "headers": headers,
            "headers_lock": headers_lock,
            "refresh_lock": refresh_lock,
            "stop": stop,
        },
        daemon=True,
    )
    thread.start()
    return thread, stop


def _stop_proactive_refresh(
    thread: threading.Thread | None, stop: threading.Event | None
) -> None:
    """Signal and briefly join the proactive-refresh daemon in a relay finally.

    Mirrors ``_start_proactive_refresh``; a ``(None, None)`` pair (timer never
    started) is a no-op. The daemon flag guarantees process exit is never blocked
    even if the join times out (the thread may be parked in ``stop.wait`` for up
    to its recheck interval).
    """
    if stop is not None:
        stop.set()
        if thread is not None:
            thread.join(timeout=1.0)


def run(
    url: str,
    headers: dict[str, str],
    *,
    timeout_connect: float = 10,
    timeout_read: float = 120,
    timeout_write: float = 30,
    tcp_keepalive: bool = True,
    cancel_filter: bool = True,
    normalize_arguments: bool = True,
    token_refresher: Any = None,
    scope_upgrader: Any = None,
    token_expiry_getter: Any = None,
    proactive_refresh: bool = True,
    refresh_leeway: float = 60.0,
    cold_start_login: Any = None,
    protocol_era: str = "legacy",
    listen_read_timeout: float = 300.0,
) -> None:
    """Run the stdio-to-HTTP relay loop.

    Reads JSON-RPC messages from stdin, sends them as HTTP POST to the
    remote MCP server, and writes responses to stdout.

    Args:
        url: Remote MCP server URL
        headers: HTTP headers to send with each request
        timeout_connect: Connection timeout in seconds
        timeout_read: Read timeout in seconds
        timeout_write: Write timeout in seconds
        tcp_keepalive: When True (default), enable TCP keepalive on the
            underlying socket to detect half-open connections at the
            network layer. See ``_tcp_keepalive_socket_options`` for
            platform-specific tuning (#9).
        cancel_filter: When True (default), track ids from
            ``notifications/cancelled`` seen on stdin and drop any late
            upstream JSON-RPC response carrying one of those ids before
            it reaches stdout. Enforces the MCP cancellation spec's
            receiver-side SHOULD on behalf of non-compliant servers and
            shields the downstream client from canceller-side bugs such
            as anthropics/claude-code#51073. Disable (``False``) only
            when debugging raw upstream traffic.
        normalize_arguments: When True (default), rewrite a ``tools/call``
            request whose ``params.arguments`` is ``null`` to ``{}`` before
            forwarding, so strict servers that reject the null form
            (modelcontextprotocol/typescript-sdk#2012) accept the call.
            Disable (``False``) to forward the client request verbatim.
        token_refresher: Optional callable that returns updated headers
            on successful token refresh, or None on failure. Called when
            the server returns HTTP 401.
        scope_upgrader: Optional callable invoked when the server
            returns HTTP 403 with a ``Bearer error="insufficient_scope"``
            challenge. It receives the scope string from the challenge
            and returns updated headers containing a broader-scope
            token, or None on failure (RFC 9470 step-up authorization;
            cf. anthropics/claude-code#44652).
        token_expiry_getter: Optional callable returning the cached
            token's ``expires_at`` (Unix seconds) or None. Drives the
            proactive-refresh timer's wake schedule; the caller backs it
            with ``token_store.load_token`` so each read picks up the
            latest persisted expiry.
        proactive_refresh: When True (default), run a background timer
            that refreshes the token at ``expires_at - refresh_leeway``
            using ``token_refresher``, independent of request flow. This
            keeps a long --oauth session alive against gateways that
            signal expiry as an HTTP 200 tool-error rather than a 401
            (e.g. Atlassian's MCP gateway; #242). No-op without
            ``token_refresher`` / ``token_expiry_getter`` (i.e. no OAuth).
        refresh_leeway: Seconds before ``expires_at`` at which the
            proactive timer refreshes (default 60).
        cold_start_login: Optional callable that runs the interactive OAuth
            flow and returns updated headers (with Authorization) on success,
            or None on failure. When set (``--oauth-eager`` with a cold cache),
            the relay answers ``initialize`` locally and gates other methods
            while ``cold_start_login`` runs on a background thread, then lifts
            the gate and emits ``list_changed`` so the client fetches the
            now-available lists — so a long OAuth flow does not blow the
            client's initialize timeout (#296). Streamable HTTP only.
            Ignored (a warning is logged and cold-start is disabled) when
            ``protocol_era`` resolves to ``"modern"``: cold-start's
            ``_reinitialize`` sends a legacy ``initialize`` handshake to
            establish a session, which is meaningless on a path with no
            sessions at all (#270 Phase 1).
        protocol_era: One of ``"legacy"`` (default), ``"modern"``, or
            ``"auto"``. ``"legacy"`` is today's behaviour — the initialize
            handshake, ``Mcp-Session-Id`` tracking, and 401/403/404 recovery,
            completely unchanged (spec rev 2025-06-18 and earlier; this is
            the default specifically so an unmodified deployment's wire
            traffic never changes — see #270). ``"modern"`` forces the spec
            rev 2026-07-28 path unconditionally: no initialize handshake (the
            local stdio client's own ``initialize``/``notifications/initialized``
            are intercepted and answered/swallowed locally), no
            ``Mcp-Session-Id``, per-request ``Mcp-Method``/``Mcp-Name``
            headers and ``_meta`` (protocol version, client capabilities,
            optionally clientInfo/logLevel) on every POST. ``"auto"`` runs a
            one-shot ``server/discover`` probe before the stdin loop starts
            (``_probe_protocol_era``) and picks whichever path the probe
            indicates — this costs one extra HTTP request at startup
            compared to a pinned era, which is why it is NOT the default (see
            ``_probe_protocol_era``'s docstring for the exact classification
            rules per HTTP status).
        listen_read_timeout: Read timeout (seconds, > 0) for the modern
            era's relay-originated ``subscriptions/listen`` POST stream
            (#270 Phase 2 PR A — see ``_listen_stream_loop``). Applied as a
            per-request override on that stream only, so ``timeout_read``
            still governs every ordinary request; a quiet-but-healthy
            listen stream (servers are only encouraged to send keep-alive
            comments) must not be classified as dropped by the ordinary
            read timeout. No effect on the legacy era. Default 300, like
            ``run_sse``'s SSE read timeout — but 0 (= disable) is NOT
            honored here: the spec says clients SHOULD always enforce a
            maximum timeout, and the CLI flag (``--listen-read-timeout``)
            rejects 0 by construction.

    Limitation — JSON-RPC batches: a top-level array (a batch) is
    treated like a notification for error synthesis. ``_extract_id_and_presence``
    returns ``has_id=False`` for any non-object line, so if a batch's POST fails
    upstream (transport exhaustion, an empty 200, a >=400, or a non-compliant
    202), NO JSON-RPC error is synthesized and any requests-with-ids INSIDE the
    batch are left unanswered — a silent hang rather than a per-id error. This
    mirrors the cancel-filter's deliberate batch exemption: synthesizing an
    ``id:null`` error for a batch would itself violate JSON-RPC, and MCP removed
    batching in spec rev 2025-06-18, so the exposure is minimal. A single
    (non-batch) request always gets a synthesized error on the same failures.

    Limitation — modern discover state and the one-shot reseed retry (#350
    review rounds 3 + 4 + 9): the ``server/discover`` probe that seeds
    ``modern_state.server_info`` / ``capabilities`` / ``supported_versions``
    runs BEFORE the stdin loop starts (see above), which is necessarily
    before the local client has sent its own ``initialize`` — so the probe
    always advertises ``clientCapabilities: {}`` (see
    ``_build_discover_probe_request``). If the remote gates
    ``server/discover`` itself on a real client capability (returning the
    recognized-modern error ``-32021``
    ``MissingRequiredClientCapabilityError``), the probe still correctly
    classifies the era as ``modern`` (see ``_probe_protocol_era``) but
    seeds NOTHING — and a remote can just as well answer the probe
    successfully with ``serverInfo``/``supportedVersions`` while filtering
    ``capabilities`` down to ``{}`` against that placeholder (round 9,
    finding 9-2). Round 3 documented that outcome as a tolerable
    under-report; round 4 established it is NOT merely cosmetic — the
    lifecycle spec says both parties "MUST ... Only use capabilities that
    were successfully negotiated", so a compliant local client told
    ``capabilities: {}`` never issues ``tools/list``/``resources``/
    ``prompts`` requests at all. The fix is a NARROW retry the round-3
    analysis never evaluated (it rejected only an unconditional
    every-session second probe): when the local client's ``initialize``
    arrives with non-empty capabilities of its own and the startup probe
    left ``capabilities`` empty (round 4 required ALL discover state
    empty; round 9 widened the trigger to the one field the placeholder
    can plausibly distort), discovery is re-run
    exactly ONCE with the client's now-known real
    ``clientCapabilities``/``clientInfo`` in ``params._meta``, before the
    ``InitializeResult`` is synthesized (``_reseed_discover_probe``, hooked
    in via ``_handle_modern_special_method``'s ``discover_retry``) —
    preserving any identity/version state the startup probe already
    seeded (``_seed_modern_state_from_discover`` never erases). Cost:
    zero on the common already-seeded path; one extra round-trip only on
    the rare empty-capabilities path. It cannot loop
    (``modern_state.discover_retry_attempted`` is latched before the
    attempt, so a failed retry or a client re-``initialize`` never probes
    again) and cannot race (it runs synchronously on the stdin loop
    thread, before any other dispatch). RESIDUAL limitations: if the
    reseed retry ALSO fails, the synthesized result degrades exactly as
    round 3 documented — honest-unknown ``serverInfo`` placeholder, empty
    capabilities, an under-report that never over-claims — and the
    operator escapes remain fixing the upstream's discover-gating or
    pinning ``--protocol-era legacy``. And a remote that returns a
    NON-empty but capability-FILTERED subset against the placeholder is
    still not re-probed: from this side it is indistinguishable from a
    remote reporting its true capabilities, and detecting it would take
    exactly the unconditional every-session second probe round 3 rejected
    on cost — a knowingly-accepted under-report, never an over-claim.
    Acceptance criterion #3 (#270:
    headers/session/byte-identity) is unaffected: the legacy path never
    runs any of this.

    Limitation — MRTR (``resultType: "input_required"``) results are
    forwarded verbatim (#350 review round 4 / #270 Phase 2): a modern
    upstream that needs client input mid-request replaces the real result
    with an ``InputRequiredResult`` (SEP-2322) that the client must answer
    by re-issuing the request with ``inputResponses``. Phase 1 does not
    translate that exchange into the legacy server-initiated
    sampling/elicitation/roots requests a 2025-era stdio client would
    understand — the ``input_required`` result reaches the client
    unchanged, and a client that does not know the discriminator will
    misread it as an oddly-shaped success. Since round 10 (finding 10-1)
    the relay no longer INVITES that flow: the client capability keys MRTR
    replaced (``sampling``/``elicitation``/``roots``) are stripped before
    anything is advertised upstream (``_MRTR_REPLACED_CLIENT_CAPABILITIES``,
    applied at capture in ``_handle_modern_special_method``), and a server
    may only use "capabilities that were successfully negotiated"
    (lifecycle spec) — so a COMPLIANT modern server now has no legitimate
    reason to send ``input_required`` through this relay. The
    verbatim-forward caveat therefore covers only a NON-compliant upstream
    that initiates MRTR despite the client never advertising the flows; the
    ordinary tools/resources/prompts flows are unaffected (their 2026
    result shapes are additive-only — see
    ``_handle_modern_special_method``). MRTR passthrough is #270's
    explicitly-phased Phase 2 work, not an oversight in Phase 1.
    """

    # Graceful shutdown on SIGTERM/SIGINT
    def _shutdown(signum: int, _: Any) -> None:
        log(f"received signal {signum}, shutting down")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log(f"connecting to {redact_url(url)}")

    session_id: str | None = None
    # Negotiated MCP protocol version, captured from the InitializeResult and
    # injected as MCP-Protocol-Version on every subsequent request (spec rev
    # 2025-06-18). Streamable HTTP only — see _looks_like_initialize.
    protocol_version: str | None = None
    tracker: _CancelTracker | None = _CancelTracker() if cancel_filter else None
    client = httpx.Client(
        transport=_make_httpx_transport(tcp_keepalive=tcp_keepalive),
        timeout=httpx.Timeout(
            connect=timeout_connect,
            read=timeout_read,
            write=timeout_write,
            pool=10,
        ),
    )

    # ``run`` is otherwise single-threaded, but the proactive-refresh daemon
    # (when enabled) mutates ``headers`` concurrently. ``headers_lock`` serialises
    # every read/write of the shared ``headers`` object; ``refresh_lock`` serialises
    # the timer's refresh against the reactive 401 refresh so the two never race
    # the AS's refresh-token rotation. Both are uncontended when the timer is off.
    headers_lock = threading.Lock()
    refresh_lock = threading.Lock()

    # Resolve the protocol era BEFORE the stdin loop starts (#270 Phase 1).
    # "legacy" (the default) does NOTHING here — zero extra network traffic,
    # zero new state — so an unmodified deployment's wire bytes are
    # untouched (acceptance criterion #3). "modern" and "auto" both run the
    # server/discover probe: "modern" to SEED modern_state (serverInfo /
    # capabilities / supportedVersions for the synthesized InitializeResult)
    # while forcing the era regardless of what the probe reports; "auto" to
    # additionally CLASSIFY the era from the probe's outcome
    # (_probe_protocol_era). This is why "auto" is opt-in rather than the
    # default: it costs one extra POST at startup that a pinned era does not.
    modern_state = _ModernState()

    def _probe_auth_recovery(resp: httpx.Response) -> dict[str, str] | None:
        """Recover credentials for a 401/403 at PROBE time (#350 round 4).

        Mirrors the stdin loop's own recovery ladder — 401 -> token refresh,
        403 + parseable ``insufficient_scope`` challenge -> RFC 9470 step-up
        — so an auth challenge to the era-detection probe is repaired with
        the SAME machinery a real dispatch would use, instead of being
        misread as protocol evidence for "legacy". Returns the full updated
        header set on success (``_probe_protocol_era`` rebuilds the probe
        from it and retries once) or ``None`` to decline (probe falls back
        to the conservative legacy classification, unchanged behavior).

        Thread-safety: at STARTUP-probe time this runs before the
        proactive-refresh daemon and the cold-start thread are started
        (both are created further down), so nothing else can hold
        ``refresh_lock`` yet. But the same callback is ALSO invoked later
        in the session by the one-shot discover reseed (#350 review round
        8, finding 8-2 — ``_discover_reseed`` below, called from the stdin
        loop's ``initialize`` handling), at which point the daemon MAY be
        live: taking ``refresh_lock`` is then load-bearing, not stylistic.
        BOTH recovery stages serialise against the daemon's rotation under
        that one lock (#350 review round 10, finding 10-2 — round 8 locked
        only the 401 refresh; the 403 ``scope_upgrader`` ran bare, so a
        step-up racing the timer's refresh could fail the refresh
        mid-rotation, or let an old-scope refreshed token overwrite the
        just-upgraded credentials in the shared ``headers``). The recovered
        headers are merged into the SHARED ``headers`` dict (under
        ``headers_lock``) so the whole session (not just the probe retry)
        proceeds with the recovered credentials.
        """
        if resp.status_code == 401 and token_refresher is not None:
            log("protocol-era probe: 401, attempting token refresh")
            with refresh_lock:
                new_headers = token_refresher()
            if new_headers:
                with headers_lock:
                    headers.update(new_headers)
                    return dict(headers)
            log("protocol-era probe: token refresh failed")
            return None
        if resp.status_code == 403 and scope_upgrader is not None:
            required_scope = _parse_www_authenticate_scope(
                resp.headers.get("www-authenticate")
            )
            if required_scope is not None:
                log(
                    f"protocol-era probe: 403 insufficient_scope "
                    f"(required: {required_scope}), attempting step-up"
                )
                # Same lock as the 401 branch (#350 review round 10,
                # finding 10-2): the discover reseed can invoke this while
                # the proactive-refresh daemon is live, and an unserialised
                # step-up races the timer's token rotation — see the
                # docstring's thread-safety note.
                with refresh_lock:
                    new_headers = scope_upgrader(required_scope)
                if new_headers:
                    with headers_lock:
                        headers.update(new_headers)
                        return dict(headers)
                log("protocol-era probe: step-up authorization failed")
            return None
        return None

    if protocol_era == "modern":
        era = "modern"
        with headers_lock:
            probe_headers = dict(headers)
        _, discover_result = _probe_protocol_era(
            client, url, probe_headers, auth_recovery=_probe_auth_recovery
        )
        _seed_modern_state_from_discover(modern_state, discover_result)
        log("protocol era: modern (forced via --protocol-era)")
    elif protocol_era == "auto":
        with headers_lock:
            probe_headers = dict(headers)
        era, discover_result = _probe_protocol_era(
            client, url, probe_headers, auth_recovery=_probe_auth_recovery
        )
        _seed_modern_state_from_discover(modern_state, discover_result)
        log(f"protocol era: {era} (auto-detected)")
    else:
        era = "legacy"

    if era == "modern" and cold_start_login is not None:
        # _cold_start_loop's _reinitialize sends a legacy `initialize`
        # handshake to establish a session — meaningless on a path with no
        # sessions at all. Disable rather than silently sending a legacy
        # handshake to a modern remote.
        log(
            "cold-start (--oauth-eager) is not supported on the modern "
            "protocol era; disabling cold-start for this session"
        )
        cold_start_login = None

    def _prepare_headers(line: str) -> dict[str, str]:
        """Build per-request headers for ``line``.

        LEGACY era (the ``else`` branch below): session + protocol version,
        completely UNCHANGED from pre-#270 — this is the code that makes
        acceptance criterion #3 ("byte-identical" wire bytes against a
        legacy remote) hold structurally rather than by assertion. ``line``
        is accepted but ignored on this branch.

        MODERN era: per spec rev 2026-07-28 there is no ``Mcp-Session-Id`` at
        all (the relay's own ``session_id`` never gets set on this path — see
        run()'s three session-adoption sites, all additionally gated on
        ``era == "legacy"``); instead every request carries
        ``MCP-Protocol-Version`` (the negotiated modern version, from
        ``modern_state.negotiated_version``) plus THIS request's
        ``Mcp-Method``/``Mcp-Name`` (``_mcp_request_headers``, mirroring
        ``_extract_method_and_name``).

        Both branches drop any case-variant the operator pinned via ``-H``
        before re-adding the relay's own value, so httpx never serialises two
        header lines for the same field — a strict server treats these as
        singleton fields and would reject or mis-select. This unconditional
        strip-then-(maybe)-add applies to ``Mcp-Method``/``Mcp-Name`` exactly
        like it already does to ``Mcp-Session-Id``/``MCP-Protocol-Version``:
        an operator-pinned value is dropped regardless of whether THIS
        request derives a replacement (#350 review finding 3). Deriving no
        replacement — e.g. ``Mcp-Name`` on ``tools/list``, which has no
        ``params.name`` to mirror — must leave the header ABSENT, not
        leak a stale pinned value the request body no longer corroborates
        (Streamable HTTP "Server Validation": "Parameter not in arguments ->
        Client MUST omit the header"). A batch/methodless line similarly
        must not carry a stale pinned ``Mcp-Method`` — it ends up with NO
        ``Mcp-Method`` header at all, which is itself non-compliant with
        "Required For: All requests" (MCP removed batching in spec rev
        2025-06-18, so this is legacy-batch dead code territory; inventing
        a synthetic method value for a line with none would be worse than
        omitting the header).
        """
        with headers_lock:
            h = dict(headers)
        if era == "modern":
            h = {k: v for k, v in h.items() if k.lower() != "mcp-session-id"}
            h = {k: v for k, v in h.items() if k.lower() != "mcp-protocol-version"}
            h["MCP-Protocol-Version"] = (
                modern_state.negotiated_version or _MODERN_PROTOCOL_VERSION_DEFAULT
            )
            h = {k: v for k, v in h.items() if k.lower() != "mcp-method"}
            h = {k: v for k, v in h.items() if k.lower() != "mcp-name"}
            mcp_headers = _mcp_request_headers(line)
            if "Mcp-Method" in mcp_headers:
                h["Mcp-Method"] = mcp_headers["Mcp-Method"]
            if "Mcp-Name" in mcp_headers:
                h["Mcp-Name"] = mcp_headers["Mcp-Name"]
            return h
        # session_id / protocol_version are mutated only by this (main) thread,
        # so they need no lock; only the shared ``headers`` object is contended.
        if session_id:
            h = {k: v for k, v in h.items() if k.lower() != "mcp-session-id"}
            h["Mcp-Session-Id"] = session_id
        if protocol_version:
            h = {k: v for k, v in h.items() if k.lower() != "mcp-protocol-version"}
            h["MCP-Protocol-Version"] = protocol_version
        return h

    def _discover_reseed() -> None:
        """One-shot discover reseed hook for the modern initialize branch.

        Snapshots the SHARED ``headers`` fresh per invocation (under
        ``headers_lock``) so credentials refreshed since startup — by the
        probe-time recovery above or the proactive-refresh daemon — are
        honored, then delegates to ``_reseed_discover_probe`` (#350 review
        round 4) with the SAME ``_probe_auth_recovery`` the startup probe
        used (#350 review round 8, finding 8-2): a token that expired
        between the ``-32021``-gated startup probe and the local
        ``initialize`` would otherwise 401 this one-shot reseed and
        permanently synthesize empty capabilities. Once-only/never-loops is
        enforced by the caller (``_handle_modern_special_method`` latches
        ``modern_state.discover_retry_attempted`` first), and it runs
        synchronously on the stdin loop thread, so no dispatch can race it.
        """
        with headers_lock:
            snapshot = dict(headers)
        _reseed_discover_probe(
            client, url, snapshot, modern_state, auth_recovery=_probe_auth_recovery
        )

    # --- modern era: subscriptions/listen stream (#270 Phase 2 PR A) ---
    # ARRANGED here (era-resolution scope); the body snapshot is SEEDED by
    # each intercepted `initialize` (_handle_modern_special_method's
    # `listen_seed` hook — the snapshot needs the client's captured
    # capabilities and the negotiated version, which do not exist before
    # then) and the thread is STARTED by `notifications/initialized`
    # (`listen_start` hook, #352 review finding 1 — never before the
    # synthesized InitializeResult reached stdout). The legacy era gets NO
    # new call site (acceptance criterion #3): the only caller of either
    # hook is the era == "modern" branch in the stdin loop below, so
    # legacy wire bytes are untouched structurally.
    listen_stop = threading.Event()
    # Mutable holder shared with the thread. "thread" doubles as the
    # one-shot latch — a client-driven re-`initialize`/repeat
    # `initialized` invokes the hooks again but must never spawn a second
    # thread. "params" is the frozen C1 snapshot, seeded at initialize
    # time; None means no initialize was ever intercepted, so an orphan
    # `initialized` starts nothing. "honored" records the
    # server-acknowledged notification subset from the ack (logged on
    # divergence; consumed for real by PR B). "client" is the thread's
    # DEDICATED httpx client (#352 round-2 finding 2), created alongside
    # the thread and closed by the finally below — from the main thread —
    # to actively unblock a parked read at shutdown.
    listen_state: dict[str, Any] = {
        "thread": None,
        "params": None,
        "honored": None,
        "client": None,
    }

    def _seed_listen_snapshot() -> None:
        """Freeze the listen body snapshot (C1) at initialize time.

        Re-seeded by a re-``initialize`` only until the thread starts —
        the latest negotiation wins at start time; after that the running
        thread's snapshot stays frozen (C1).
        """
        if listen_state["thread"] is not None:
            return
        listen_state["params"] = _build_listen_params(modern_state)

    def _start_listen_stream() -> None:
        """Open the background subscriptions/listen stream, at most once.

        Invoked on ``notifications/initialized`` (#352 review finding 1).
        No seeded snapshot — an ``initialized`` with no prior
        ``initialize`` — starts nothing: the snapshot would carry an
        un-negotiated version and no captured client identity.
        """
        if listen_state["thread"] is not None or listen_state["params"] is None:
            return
        # DEDICATED client for the listen thread (#352 round-2 finding 2),
        # mirroring the shared client's construction above. The thread must
        # never touch the shared client: shutdown interrupts a read parked
        # for up to --listen-read-timeout by closing THIS client from the
        # main thread (run()'s finally), which a bounded join alone cannot
        # do — and a long-parked stream no longer holds one of the shared
        # client's pool=10 connections either.
        listen_client = httpx.Client(
            transport=_make_httpx_transport(tcp_keepalive=tcp_keepalive),
            timeout=httpx.Timeout(
                connect=timeout_connect,
                read=timeout_read,
                write=timeout_write,
                pool=10,
            ),
        )
        listen_state["client"] = listen_client
        listen_thread = threading.Thread(
            target=_listen_stream_loop,
            kwargs={
                "client": listen_client,
                "url": url,
                # Frozen body snapshot (C1) — seeded at initialize time.
                "params": listen_state["params"],
                # Fresh header snapshot per attempt (C2) — _prepare_headers
                # locks internally, so refreshed tokens reach reconnects.
                "prepare_headers": _prepare_headers,
                "tracker": tracker,
                "stop": listen_stop,
                # Per-request timeout override, built like run_sse's
                # post_timeout: same connect/write/pool, but the READ
                # timeout is the dedicated --listen-read-timeout (C9).
                "timeout": httpx.Timeout(
                    connect=timeout_connect,
                    read=listen_read_timeout,
                    write=timeout_write,
                    pool=10,
                ),
                "state": listen_state,
            },
            daemon=True,
        )
        listen_state["thread"] = listen_thread
        listen_thread.start()

    refresh_timer, refresh_stop = _start_proactive_refresh(
        refresher=token_refresher,
        expiry_getter=token_expiry_getter,
        proactive_refresh=proactive_refresh,
        leeway=refresh_leeway,
        headers=headers,
        headers_lock=headers_lock,
        refresh_lock=refresh_lock,
    )

    # Cold-start (--oauth-eager): answer initialize locally while OAuth runs on a
    # background thread. ``cold_gated`` stays True until OAuth completes AND the
    # main loop has adopted the upstream session the daemon established; while
    # gated, the stdin loop synthesizes local replies instead of POSTing upstream.
    cold_ready = threading.Event() if cold_start_login is not None else None
    cold_state: dict[str, Any] = {"session_id": None, "protocol_version": None}
    cold_state_lock = threading.Lock()
    cold_gated = cold_start_login is not None
    cold_timer: threading.Thread | None = None
    if cold_start_login is not None:
        cold_timer = threading.Thread(
            target=_cold_start_loop,
            kwargs={
                "login": cold_start_login,
                "client": client,
                "url": url,
                "headers": headers,
                "headers_lock": headers_lock,
                "tracker": tracker,
                "state": cold_state,
                "state_lock": cold_state_lock,
                "ready": cold_ready,
            },
            daemon=True,
        )
        cold_timer.start()

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            req_id, req_has_id = None, False
            try:
                if normalize_arguments:
                    line = _normalize_null_arguments(line)

                if tracker is not None:
                    cid = _extract_cancel_id(line)
                    if cid is not None:
                        tracker.add(cid)

                # Derive both the id value and its presence from one parse (the
                # hot path). A notification (no id) must never receive a response —
                # even when an upstream misbehaves and returns a 4xx/5xx to a POSTed
                # notification, synthesizing an `id:null` error to stdout would be a
                # JSON-RPC violation. Gate all synthesized error responses on
                # req_has_id.
                req_id, req_has_id = _extract_id_and_presence(line)
                if tracker is not None and req_id is not None:
                    # A request reusing a previously-cancelled id supersedes that
                    # cancel — untrack it so its response is delivered, not dropped.
                    tracker.discard(req_id)

                # Cold-start gate (--oauth-eager): until the background OAuth flow
                # completes, answer locally instead of POSTing to the not-yet-
                # authorized upstream. Once ready, adopt the upstream session the
                # daemon established and forward THIS line normally.
                if cold_gated:
                    if cold_ready.is_set():
                        with cold_state_lock:
                            session_id = cold_state["session_id"]
                            protocol_version = cold_state["protocol_version"]
                        cold_gated = False
                        log("cold-start gate lifted; forwarding to upstream")
                    else:
                        reply = _cold_start_response(line, req_id, req_has_id)
                        if reply is not None:
                            _emit(reply, tracker)
                        continue

                # Track a client-set logging level on BOTH eras (a cheap,
                # side-effect-free read — see _extract_log_level) so a level
                # set before/while still resolving is available if the modern
                # path later needs to mirror it into _meta.
                level = _extract_log_level(line)
                if level is not None:
                    modern_state.log_level = level

                if era == "modern":
                    # initialize / notifications/initialized /
                    # notifications/cancelled do not exist on the wire to a
                    # modern remote — see _handle_modern_special_method.
                    # _discover_reseed (defined once, above the loop) gives
                    # the initialize branch its one-shot reseed retry
                    # (#350 review round 4).
                    handled, modern_reply = _handle_modern_special_method(
                        line,
                        req_id,
                        modern_state,
                        discover_retry=_discover_reseed,
                        listen_seed=_seed_listen_snapshot,
                        listen_start=_start_listen_stream,
                    )
                    if handled:
                        if modern_reply is not None:
                            _emit(modern_reply, tracker)
                        continue
                    # Reject a method that cannot ride the REQUIRED Mcp-Method
                    # header (#350 review round 5, finding 5-2). JSON-RPC 2.0
                    # allows ANY string as `method`, but Streamable HTTP
                    # ("Standard Request Headers") mirrors it into Mcp-Method,
                    # whose value must satisfy RFC 9110 field-value syntax —
                    # and unlike Mcp-Name, Mcp-Method has NO escape hatch: the
                    # Base64 sentinel is defined only for Mcp-Name /
                    # Mcp-Param-{Name} ("Server Validation": servers "MUST
                    # decode an encoded Mcp-Name or Mcp-Param-{Name} value
                    # before comparing" — Mcp-Method is pointedly absent), so
                    # an encoded Mcp-Method would fail header-body validation
                    # with -32020 HeaderMismatch on a compliant server.
                    # Sending it raw is no better: httpx raises
                    # UnicodeEncodeError at request construction for a
                    # non-ASCII header value (degrading to the opaque
                    # "internal relay error" via the safety net below — the
                    # #11 never-crash contract holds, but the failure tells
                    # the client nothing), and some control characters pass
                    # httpx/h11 validation onto the wire verbatim. Such a
                    # request is unsendable on this transport, so reject it
                    # through the normal error path: a request gets a JSON-RPC
                    # error, a notification (no id) is dropped silently, and
                    # the legacy path — which mirrors nothing into headers —
                    # stays byte-identical (AC #3).
                    unsafe_method, _ = _extract_method_and_name(line)
                    if unsafe_method is not None and not _is_header_safe_ascii(
                        unsafe_method
                    ):
                        log(
                            "rejecting request: method is not a header-safe "
                            "ASCII string and cannot be mirrored into the "
                            "required Mcp-Method header (spec rev 2026-07-28)"
                        )
                        if req_has_id:
                            _write_line(
                                _error_response(
                                    "method cannot be represented in the "
                                    "required Mcp-Method header (spec rev "
                                    "2026-07-28, Request Metadata)",
                                    req_id,
                                )
                            )
                        continue
                    # Every other request/notification carries the modern
                    # per-request _meta block (protocol version, client
                    # capabilities, optionally clientInfo/logLevel). Reassigning
                    # `line` here means every dispatch call site below (initial
                    # + the 401/403 retry branches, which all re-read the SAME
                    # `line` variable) automatically sends the meta-injected
                    # body — no separate threading of the injected content
                    # through the recovery branches.
                    line = _inject_modern_meta(line, modern_state)

                req_headers = _prepare_headers(line)

                def _dispatch(content: str, h: dict[str, str]) -> _StreamResult | None:
                    nonlocal protocol_version
                    detected = _detect_paginated_list(content)
                    if detected:
                        # The pagination branch never captures protocol_version.
                        # That is correct because `initialize` is not in
                        # PAGINATED_LIST_METHODS, so an initialize request can never
                        # take this branch — keep that invariant if the table grows.
                        return _paginate_and_stream(
                            client,
                            url,
                            content,
                            h,
                            req_id,
                            detected[1],
                            tracker,
                            has_id=req_has_id,
                        )
                    # Any `initialize` request is a capture point — not just the
                    # first. A client-driven re-initialize that renegotiates a
                    # different version is adopted so the injected
                    # MCP-Protocol-Version header stays equal to the version in
                    # force (the 2025-06-18 spec requires the header to match the
                    # negotiated version). The heavier `_extract_protocol_version`
                    # still runs only inside `_post_and_stream` for lines that are
                    # actually initializes.
                    #
                    # Response-only: the version comes from the server's
                    # InitializeResult, not the client's requested version. If a
                    # (non-compliant) server omits result.protocolVersion, no
                    # header is sent rather than guessing — a server that both
                    # omits it and enforces the header would be self-contradictory.
                    #
                    # Classify the line ONCE, PARSE-authoritatively. Gating the
                    # protocol-version CAPTURE on _is_initialize_request (not the
                    # _looks_like_initialize substring) stops a tools/call whose
                    # `arguments` merely contains a "method":"initialize" key from
                    # capturing a spurious result.protocolVersion out of its tool
                    # response and then injecting a never-negotiated version on
                    # every later request. The cheap
                    # _INITIALIZE_METHOD_RE inside _is_initialize_request still
                    # short-circuits the common non-matching line without a parse.
                    capture_init = _is_initialize_request(content)
                    if protocol_version is not None and capture_init:
                        # An initialize request IS the (re)negotiation and predates a
                        # known version, so it must not advertise the prior one
                        # (2025-06-18: the header carries the negotiated version and
                        # applies to requests AFTER initialization). Strip the value
                        # _prepare_headers injected, matching _reinitialize. The gate
                        # on ``protocol_version is not None`` means we only drop the
                        # relay's OWN injected header — on a cold-start initialize
                        # (no version yet) a user-pinned ``-H MCP-Protocol-Version``
                        # is left intact. Mcp-Session-Id is untouched. Both capture
                        # and strip now share the parse-authoritative gate, so a
                        # tools/call whose arguments contains a "method":"initialize"
                        # key keeps its header.
                        h = {
                            k: v
                            for k, v in h.items()
                            if k.lower() != "mcp-protocol-version"
                        }
                    result = _post_and_stream(
                        client,
                        url,
                        content,
                        h,
                        req_id,
                        tracker,
                        capture_init=capture_init,
                        has_id=req_has_id,
                    )
                    if result is not None and result.protocol_version:
                        if result.protocol_version != protocol_version:
                            log(
                                f"negotiated MCP protocol version: "
                                f"{result.protocol_version}"
                            )
                        protocol_version = result.protocol_version
                    return result

                result = _dispatch(line, req_headers)
                if result is None:
                    # All retries exhausted on a TRANSPORT error (the error was
                    # already printed). ``None`` is never a 4xx — every non-200
                    # status returns a _StreamResult — so the server-side session was
                    # NOT invalidated; only the network blipped. KEEP session_id so
                    # the next request still carries it and can trigger 404 self-heal
                    # if the session truly expired. Clearing it here would instead
                    # defeat that recovery on a mere blip (the next 404 could not
                    # fire its recovery branch, which is gated on session_id).
                    continue

                # Adopt a server-rotated session id from THIS response before the
                # 401/403 recovery branches rebuild their retry headers, so a server
                # that rotates/assigns Mcp-Session-Id alongside an auth challenge is
                # honoured on the retry rather than re-sending the stale one. (The
                # 404 branch re-establishes its own fresh session below.)
                #
                # Gate it: adopt only when this response is a SUCCESS
                # or a 401/403 whose recovery retry actually needs the rotated id.
                # A terminal 4xx/5xx with no recovery (e.g. a bare 500) that merely
                # echoes a session id must NOT poison session_id for the next stdin
                # line — the relay would otherwise send the next request an id the
                # server just rejected.
                # The 403 disjunct mirrors its CONSUMER at line ~1853: step-up only
                # fires when _parse_www_authenticate_scope returns a scope, so adopt
                # the rotated id only when the challenge is a PARSEABLE
                # insufficient_scope one. A generic/malformed/absent-WWW-Authenticate
                # 403 (a plain authorization denial) does NOT feed a retry that
                # consumes the id — adopting it would poison session_id for the next
                # stdin line for nothing (one wasted round-trip until 404 self-heal).
                feeds_recovery = (
                    result.status_code == 401 and token_refresher is not None
                ) or (
                    result.status_code == 403
                    and scope_upgrader is not None
                    and _parse_www_authenticate_scope(result.www_authenticate)
                    is not None
                )
                # A 202-to-request is classified as an error below (req_202_hang)
                # and synthesized into a JSON-RPC error, so — like a 4xx/5xx — its
                # echoed (possibly rotated) session id must NOT be adopted: it is an
                # id the server is about to reject. The `< 400` predicate alone
                # admits 202, so exclude a 202-to-request explicitly, matching the
                # authoritative post-recovery gate's `not is_error`.
                if (
                    era == "legacy"
                    and result.session_id
                    and not (result.status_code == 202 and req_has_id)
                    and (result.status_code < 400 or feeds_recovery)
                ):
                    session_id = result.session_id

                # Recovery is single-pass and ordered auth-before-session: the three
                # branches below are sequential `if`s (not `elif`), each firing at
                # most once per stdin line. A 401/403 whose retry returns 404 flows
                # into the 404 branch and recovers ONLY when a session_id was
                # already established — the 404 branch is gated on `and session_id`
                # . A COLD 404 (no session ever existed, e.g. the
                # initialize itself 401'd) is a genuine not-found, not a session
                # expiry, so it correctly surfaces as a JSON-RPC error rather than
                # re-initializing a session that never was. The converse does NOT
                # recover either — a 404 retry that comes back 401/403 (token
                # expired during the reinit window), or a 401/403 retry that fails
                # the same way again, surfaces as a JSON-RPC error (never a hang, #11).
                # The downstream client retries at its own level. This bounded
                # single attempt is deliberate: it avoids unbounded recovery loops.
                #
                # Worst case the same line is dispatched up to 4 times in one
                # iteration (initial + 401-refresh + 403-step-up + 404-reinit, when
                # each retry returns the next branch's status). That is safe only
                # because each prior dispatch returned a non-200 with NO body
                # delivered to stdout — the at-most-once guard in _post_and_stream
                # covers replay after a partial 200, not these distinct non-200
                # recovery dispatches, which a server is not expected to have
                # executed for side effects.

                # Token expired (401) — refresh and retry once
                if result.status_code == 401 and token_refresher:
                    log("received 401, attempting token refresh")
                    # Serialise with the proactive timer's refresh so the two
                    # never race the AS's refresh-token rotation (#242).
                    with refresh_lock:
                        new_headers = token_refresher()
                    if new_headers:
                        with headers_lock:
                            headers.update(new_headers)
                        req_headers = _prepare_headers(line)
                        result = _dispatch(line, req_headers)
                        if result is None:
                            # Transport exhaustion on the refreshed retry (None is
                            # never a 4xx). Keep session_id — see the top-level None
                            # handling: a transient blip must not defeat 404 recovery.
                            continue
                        # Re-adopt a session id the server rotated alongside this 401
                        # retry's response, so a chained 403 step-up below rebuilds
                        # its retry headers from the fresh id, not the stale one.
                        # Gate it like the pre-recovery adoption (/26): adopt
                        # only when the retry SUCCEEDED, or returned a 403 that the
                        # step-up branch below will actually CONSUME — i.e. a PARSEABLE
                        # insufficient_scope challenge. A terminal status (bare 500/400,
                        # a 403 with no scope_upgrader, or a 403 whose challenge does
                        # not parse so step-up never fires) that merely echoes a session
                        # id must NOT poison session_id for the next stdin line — that
                        # id was just rejected. The parseable-scope conjunct mirrors the
                        # top-level feeds_recovery gate exactly. (A 404 is
                        # excluded: its branch reinitializes from scratch, ignoring any
                        # rotated id, and a cold 404 must stay a terminal error.)
                        if (
                            era == "legacy"
                            and result.session_id
                            and not (
                                result.status_code == 202 and req_has_id
                            )  #: a 202-to-request is errored, not adopted
                            and (
                                result.status_code < 400
                                or (
                                    result.status_code == 403
                                    and scope_upgrader is not None
                                    and _parse_www_authenticate_scope(
                                        result.www_authenticate
                                    )
                                    is not None
                                )
                            )
                        ):
                            session_id = result.session_id
                    else:
                        log("token refresh failed, returning error")
                        if req_has_id:
                            _write_line(
                                _error_response("authentication failed", req_id)
                            )
                        continue

                # Insufficient scope (403) — step-up authorization and retry once
                if result.status_code == 403 and scope_upgrader:
                    required_scope = _parse_www_authenticate_scope(
                        result.www_authenticate
                    )
                    if required_scope is not None:
                        log(
                            f"received 403 insufficient_scope "
                            f"(required: {required_scope}), attempting step-up"
                        )
                        new_headers = scope_upgrader(required_scope)
                        if new_headers:
                            with headers_lock:
                                headers.update(new_headers)
                            req_headers = _prepare_headers(line)
                            result = _dispatch(line, req_headers)
                            if result is None:
                                # Transport exhaustion on the stepped-up retry (None
                                # is never a 4xx). Keep session_id — see the top-level
                                # None handling.
                                continue
                            # Re-adopt a session id rotated alongside this step-up
                            # retry's response. Gate it like the 401 branch: adopt only on SUCCESS. After the step-up the
                            # only downstream branch is 404, which reinitializes from
                            # scratch (ignoring any rotated id), so a terminal status
                            # echoing a session id must not poison the next line.
                            if (
                                era == "legacy"
                                and result.session_id
                                and not (result.status_code == 202 and req_has_id)
                                and result.status_code < 400
                            ):  #: a 202-to-request is errored, not adopted
                                session_id = result.session_id
                        else:
                            log("step-up authorization failed, returning error")
                            if req_has_id:
                                _write_line(
                                    _error_response("authorization failed", req_id)
                                )
                            continue

                # Session expired (404) — reset, re-initialize, then retry.
                # LEGACY ONLY: this is dead code on the modern era regardless
                # (session_id can never be set there — every adoption site
                # above is gated on era == "legacy" — but the explicit
                # conjunct documents that a 404 on the modern path is a
                # genuine "not found", never a session recovery trigger).
                if era == "legacy" and result.status_code == 404 and session_id:
                    log("session expired, re-initializing and retrying")
                    session_id = None
                    with headers_lock:
                        headers_snapshot = dict(headers)
                    new_session_id, renegotiated = _reinitialize(
                        client, url, headers_snapshot, protocol_version
                    )
                    if new_session_id is None:
                        log("re-initialize failed, dropping request")
                        if req_has_id:
                            _write_line(_error_response("session lost", req_id))
                        continue
                    session_id = new_session_id
                    # Track the re-negotiated version so the MCP-Protocol-Version
                    # header on the retried request matches the recovered session.
                    if renegotiated and renegotiated != protocol_version:
                        log(f"re-negotiated MCP protocol version: {renegotiated}")
                        protocol_version = renegotiated
                    req_headers = _prepare_headers(line)
                    result = _dispatch(line, req_headers)
                    if result is None:
                        continue

                # Fall-through error for any unhandled 4xx/5xx so the MCP client
                # never hangs waiting for a response. 200 bodies were already
                # streamed by _post_and_stream. 202 is reserved for the client's own
                # responses/notifications (MCP Streamable HTTP "Sending Messages"
                # rule 4); a compliant server answers a REQUEST with 200 + an SSE /
                # JSON body (rule 5). So a 202 to a request-WITH-id is non-compliant
                # and would leave the client hanging forever (no body now, no async
                # reply on Streamable HTTP) — synthesize an error for it too, matching
                # the empty-200 guard in _post_and_stream. A 202 to a NOTIFICATION
                # (no id) stays correctly silent. See #11 and.
                req_202_hang = result.status_code == 202 and req_has_id
                is_error = result.status_code >= 400 or req_202_hang

                # Adopt a server-rotated session id only from a NON-error response.
                # A 4xx/5xx (or a non-compliant 202-to-request we are about to
                # error) can still echo an mcp-session-id header; carrying that
                # into the next request would send an id the server JUST rejected.
                # The next line's 404 recovery would self-heal it, but don't carry
                # known-bad state forward. The inline 401/403 re-adoptions above
                # stay unconditional — they feed the very next chained recovery
                # dispatch, not the next stdin line.
                if era == "legacy" and result.session_id and not is_error:
                    session_id = result.session_id

                if is_error:
                    log(f"upstream returned HTTP {result.status_code}")
                    if req_has_id:
                        # On a 429/503 whose retries were exhausted / over-cap,
                        # surface the server's Retry-After (when present) as
                        # error.data so a client can back off intelligently. See #8.
                        err_data = (
                            {"retryAfter": result.retry_after}
                            if result.status_code in _RETRYABLE_RATE_LIMIT_STATUSES
                            and result.retry_after is not None
                            else None
                        )
                        msg = (
                            f"HTTP {result.status_code} (no response body for request)"
                            if req_202_hang
                            else f"HTTP {result.status_code}"
                        )
                        _write_line(_error_response(msg, req_id, data=err_data))
            except Exception as e:  # noqa: BLE001 — never crash the gateway
                # The #11 contract is structural here, not just per-helper: an
                # unexpected non-httpx exception escaping _dispatch / the recovery
                # branches (e.g. a future parsing helper, a BrokenPipeError from
                # _write_line) must degrade THIS request to a JSON-RPC error and
                # keep the session alive, mirroring the SSE reader's own safety
                # net. A request gets one error; a notification (no id) stays silent.
                log(f"internal relay error handling request: {e}")
                if req_has_id:
                    try:
                        _write_line(_error_response("internal relay error", req_id))
                    except OSError:
                        # the original exception may itself be a
                        # BrokenPipeError from _write_line (client closed stdout).
                        # The recovery write would then re-raise it and crash out
                        # of the loop — breaking the "keep the session alive"
                        # guarantee this handler names. Swallow a second write
                        # failure (nothing can reach a dead stdout anyway); the
                        # stderr log above already recorded it.
                        pass
                continue
    finally:
        _stop_proactive_refresh(refresh_timer, refresh_stop)
        # Modern listen thread teardown (C11 + #352 round-2 finding 2), in
        # this exact order: set the stop event, CLOSE the thread's
        # dedicated client from here — a read parked in iter_text() can
        # outlast any bounded join by up to --listen-read-timeout, and
        # closing the client makes it raise immediately (httpcore's pool
        # close is lock-guarded, its connection close deliberately
        # unilateral), upon which the loop's stop-set arms exit silently —
        # THEN join (now fast; the bound stays as a belt for a thread
        # parked in connection setup, where close cannot interrupt), and
        # only after that close the shared client, which the thread never
        # touches. Closing here unconditionally also covers the thread's
        # natural exits (graceful/terminal arms) so the dedicated client
        # never leaks until process exit; httpx.Client.close is idempotent.
        listen_stop.set()
        listen_client = listen_state["client"]
        if listen_client is not None:
            listen_client.close()
        listen_thread = listen_state["thread"]
        if listen_thread is not None:
            listen_thread.join(timeout=1.0)
        # The cold-start daemon self-exits after one OAuth attempt; briefly join
        # it so a clean shutdown does not race its final emit. daemon=True keeps
        # process exit unblocked if it is still parked in the interactive flow.
        if cold_timer is not None:
            cold_timer.join(timeout=1.0)
        client.close()


# Upper bound on tracked in-flight request ids awaiting a response on the SSE
# GET stream (see _SseState.track): at the cap a NEW id is simply not tracked
# (it reverts to the pre-#272 hang-on-disconnect behavior — no new failure
# mode) so the oldest, longest-running calls keep their protection. A TTL is
# deliberately NOT used: tool calls legitimately run for many minutes, and a
# TTL-fired synthesized error followed by the real response would put TWO
# responses on the wire for one id — the framing-error class this relay
# exists to absorb.
_SSE_PENDING_MAX = 4096


class _SseState:
    """Shared state between SSE reader thread and main stdin loop.

    ``endpoint_url`` is written by the reader thread (set on the ``endpoint``
    event, cleared to ``None`` on stream end / disconnect) and read by the main
    loop. It is deliberately a plain single-word attribute relied upon to be
    atomically published under the CPython GIL — no lock — because the only
    consumer re-checks it after a local capture and emits "SSE endpoint
    unavailable" if it raced to ``None``. A stale-after-reconnect read is
    acceptable in practice: legacy SSE reconnect endpoints are stable. ``ready``
    / ``stop`` are ``threading.Event``s, which carry their own synchronization.

    ``pending`` is an insertion-ordered set (a dict with ``None`` values) of
    request ids POSTed and awaiting their async reply on the GET stream. The
    main loop ``track()``s an id BEFORE the POST — the reply can arrive on
    the GET stream before ``client.post()`` even returns, so adding
    afterwards would let the reader's pop no-op and the answered id linger
    until the next drop, where the drain would synthesize a second response
    for it — and ``untrack()``s it on every path that synthesizes an inline
    error instead. The reader thread ``untrack()``s on response delivery and
    drains on disconnect (#272). ``lock`` guards ``pending`` ONLY —
    ``endpoint_url``'s lock-free contract above is unchanged.
    """

    __slots__ = ("endpoint_url", "ready", "stop", "lock", "pending", "busy")

    def __init__(self) -> None:
        self.endpoint_url: str | None = None
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.pending: dict[Any, None] = {}
        # The id the main thread is CURRENTLY settling (between track() and
        # clear_busy()). A disconnect drain leaves it alone: the POST path
        # owns its outcome — an inline error on failure, or a ride to the
        # next drop on a POST that succeeded concurrently with the drain —
        # so the drain and the inline synthesis can never both answer it.
        self.busy: Any = None

    def track(self, rid: Any) -> bool:
        """Track an id awaiting its reply; False when the cap refused it.

        At ``_SSE_PENDING_MAX`` a NEW id is refused (left untracked — it
        merely reverts to the pre-#272 hang-on-disconnect) rather than
        evicting the oldest: the oldest entries are the longest-running
        calls, exactly the ones a stream drop hurts most (claude-code#60061),
        so they keep their protection. A re-POST of an already-tracked id is
        always accepted (it refreshes nothing; one drain error per id).

        The tracked id is also marked busy until :meth:`clear_busy`.
        """
        with self.lock:
            if rid not in self.pending and len(self.pending) >= _SSE_PENDING_MAX:
                return False
            self.pending[rid] = None
            self.busy = rid
            return True

    def clear_busy(self) -> None:
        with self.lock:
            self.busy = None

    def untrack(self, rid: Any) -> bool:
        """Remove ``rid``; True when it was still tracked.

        False means the id was already settled elsewhere — the reader
        delivered its real reply, or a disconnect drain synthesized an error
        for it — so the caller must NOT put another response on the wire.
        """
        with self.lock:
            if rid in self.pending:
                del self.pending[rid]
                return True
            return False


def _drain_pending(state: _SseState, tracker: _CancelTracker | None) -> None:
    """Synthesize error responses for requests orphaned by a stream drop.

    Requests POSTed on the SSE transport get their responses ONLY on the
    long-lived GET stream; when that stream drops, the reconnected (typically
    fresh) session never re-sends them, so without this the stdio client
    waits forever on those ids (#272, the claude-code#60061 hang class).

    Ids the client already cancelled are skipped via the NON-consuming
    ``tracker.contains`` — synthesizing a response for a cancelled id would
    hand the client the exact unsolicited-late-response it may treat as a
    framing error (claude-code#51073), and ``consume`` here would disarm the
    gate for a residual real late response. This is consistent with the
    ``_emit`` bypass convention: that protects synchronous request-reply
    synthesis for a line the client just sent, whereas this drain fires
    arbitrarily later for an id the client may have long abandoned.

    Two accepted residual windows, both narrow and self-limiting: (a) a real
    reply that still surfaces AFTER the drain (buffered on the dead socket,
    or a server that keeps the session across reconnect) is delivered as a
    second response for that id — the same undeduplicated two-responses
    window already documented at the non-2xx POST branch, made observable
    where it previously was a silent hang; (b) a cancel whose stdin line has
    not yet been processed when the drain snapshots is indistinguishable
    from a response crossing the cancel in flight — the MCP cancellation
    spec's crossing case, which the canceller ignores.

    Locking discipline: ``state.lock`` is held only for the snapshot-and-clear
    — never across stdout I/O or the tracker's internal lock. The write loop
    swallows ``OSError`` (mirroring run()'s second-write handling) because two
    call sites are inside ``except`` handlers where a ``BrokenPipeError``
    would kill the reader thread for good. The per-iteration ``stop`` check
    bounds how long a drain can keep writing after run_sse begins shutdown
    (the reader is a daemon; a clean exit should not flush errors into a
    stdout the process is abandoning).
    """
    if state.stop.is_set():
        return
    with state.lock:
        if not state.pending:
            return
        # The busy id (actively being settled by the main thread's POST
        # path) is left tracked: its owner writes the inline error on
        # failure, and a POST that succeeds concurrently with this drain
        # rides until the next drop — either way, exactly one response.
        ids = [rid for rid in state.pending if rid != state.busy]
        for rid in ids:
            del state.pending[rid]
    for rid in ids:
        if state.stop.is_set():
            return
        if tracker is not None and tracker.contains(rid):
            log(f"not synthesizing disconnect error for cancelled id {rid!r}")
            continue
        try:
            _write_line(
                _error_response(
                    "SSE stream disconnected before response arrived; please retry",
                    rid,
                )
            )
        except OSError:
            pass


def _sse_reader_loop(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    state: _SseState,
    tracker: _CancelTracker | None = None,
    headers_lock: threading.Lock | None = None,
) -> None:
    """Reader thread: maintain SSE GET stream and dispatch events.

    Parses the SSE event stream per the WHATWG Server-Sent Events
    specification (via the shared ``_iter_sse_events`` decoder). The first
    ``endpoint`` event provides the POST URL (which may be relative —
    resolved with urljoin). Subsequent ``message`` events are JSON-RPC
    responses written to stdout.

    ``headers`` is shared with the main stdin loop, which may mutate it on a
    401/403 token refresh. ``headers_lock`` (when provided) serialises the
    per-reconnect snapshot taken here against those mutations so the request
    build never iterates a dict that is changing under it.

    Refresh-propagation timing (#3): a token refresh driven by the POST path
    reaches THIS already-open GET stream only on its NEXT reconnect — the
    snapshot above is re-taken per connect, so the fresh credential is picked
    up then, but a refresh does NOT forcibly tear down a healthy live stream.
    No forced-reconnect signal is wired, by design: a token expiry severe
    enough to 401 the POST uses the SAME credential as the GET, so the server
    closes (401s) the long-lived GET too, and the resulting reconnect snapshots
    the refreshed headers. Adding a cross-thread reconnect kick for the narrow
    window where a server keeps the GET alive on an expired token would be
    over-engineering for no observed failure mode.

    The cross-origin credential guard on the endpoint event
    evaluates ``has_auth`` against this SAME per-connect snapshot, so it is only
    as fresh as the current GET connection — acceptable because Authorization is
    established at startup, not introduced mid-session: a refresh that ADDED an
    Authorization header where none existed would not reach an already-open
    stream's snapshot until reconnect, but that flow does not occur (auth is set
    once at startup), so the guard never evaluates a stale has_auth=False.

    Reconnects automatically on disconnect.
    """

    def stream_lost() -> None:
        """The shared disconnect sequence, identical at every reconnect site.

        Ordering invariant: clear ``ready`` BEFORE nulling ``endpoint_url``
        so the main loop's ready.wait() blocks out the in-progress reconnect
        instead of returning immediately on a stale set() and surfacing a
        spurious "SSE endpoint unavailable"; then drain the ids orphaned on
        the dropped stream. One definition so a future fifth reconnect path
        cannot get the order wrong or forget the drain.
        """
        state.ready.clear()
        state.endpoint_url = None
        _drain_pending(state, tracker)

    # Whether a usable endpoint was EVER established. A non-200 on the very
    # first connect is fatal (the server is unusable — fail startup fast); a
    # non-200 on a later RECONNECT is treated as a transient outage and retried,
    # so a momentary 5xx/redirect during a reconnect does not leave the reader
    # dead and the gateway unable to ever recover.
    established = False
    while not state.stop.is_set():
        try:
            if headers_lock is not None:
                with headers_lock:
                    req_headers = dict(headers)
            else:
                req_headers = dict(headers)
            with client.stream("GET", url, headers=req_headers) as resp:
                if resp.status_code != 200:
                    log(f"SSE connection failed: HTTP {resp.status_code}")
                    if not established:
                        # First connect never succeeded — unblock startup
                        # (endpoint stays None so run_sse exits) and stop.
                        state.ready.set()
                        return
                    # Reconnect failure: keep trying rather than dying.
                    stream_lost()
                    if state.stop.wait(RETRY_DELAY):
                        return
                    continue

                for event_type, data in _iter_sse_events(
                    _iter_sse_lines(resp.iter_text())
                ):
                    if state.stop.is_set():
                        return
                    if event_type == "endpoint":
                        resolved = urljoin(url, data)
                        # The endpoint event may be a relative path (resolved
                        # against the GET url) or absolute. A compromised / MITM'd
                        # stream that injects an absolute cross-origin endpoint
                        # would otherwise redirect every authenticated POST — and
                        # its Authorization header — to a different origin. Refuse
                        # a cross-origin endpoint when credentials would be sent.
                        has_auth = any(
                            k.lower() == "authorization" for k in req_headers
                        )
                        if has_auth and not _same_origin(resolved, url):
                            log(
                                f"warning: refusing cross-origin SSE endpoint "
                                f"{resolved!r} (differs from {url!r}) — would leak "
                                f"credentials. Ignoring. See #13."
                            )
                            state.ready.set()  # unblock startup; endpoint stays None
                            continue
                        state.endpoint_url = resolved
                        state.ready.set()
                        established = True
                        log(f"SSE endpoint: {resolved}")
                    elif event_type == "message":
                        # A delivered response settles its pending entry —
                        # untrack BEFORE _emit (and regardless of whether the
                        # cancel gate then drops the line: the response
                        # arrived; it will never come again), so an emit
                        # failure cannot later produce a duplicate
                        # synthesized error for an already-answered id.
                        rid = _extract_response_id(data)
                        if rid is not None:
                            state.untrack(rid)
                        _emit(data, tracker)

                if state.stop.is_set():
                    return
                log("SSE stream ended, reconnecting")
                stream_lost()
                # Responsive reconnect delay: exits immediately on stop.
                if state.stop.wait(RETRY_DELAY):
                    return
        except httpx.HTTPError as e:
            if state.stop.is_set():
                return
            log(f"SSE disconnected, reconnecting: {e}")
            stream_lost()
            if state.stop.wait(RETRY_DELAY):
                return
        except Exception as e:  # noqa: BLE001 — thread safety net
            if state.stop.is_set():
                return
            # An UNEXPECTED (non-HTTPError) exception — e.g. a decode bug in
            # _iter_sse_events on a single server-controlled malformed event, or
            # a _write_line failure surfacing through _emit. Split on `established`
            # exactly like the non-200 path above:
            if not established:
                # First connect never succeeded — fail fast: unblock run_sse's
                # startup wait() (endpoint stays None so run_sse exits) rather than
                # spin reconnecting on a deterministic startup-time bug.
                log(f"SSE reader unexpected error before first connect: {e}")
                state.ready.set()
                return
            # Established mid-session: do NOT permanently die. The earlier
            # unconditional "set ready; return" left endpoint_url non-None, so the
            # main loop's `endpoint = state.endpoint_url` stayed truthy and it kept
            # POSTing requests whose async JSON-RPC replies arrive ONLY on this
            # now-dead GET stream — every later request-with-id then hung forever
            # (silent, permanent). Mirror the disconnect paths: clear ready + null
            # endpoint_url so in-flight ids surface "SSE endpoint unavailable"
            # instead of hanging, then reconnect — a one-off bad event should not be
            # fatal (cf. the loop's stated intent above).
            log(f"SSE reader unexpected error, reconnecting: {e}")
            stream_lost()
            if state.stop.wait(RETRY_DELAY):
                return


def run_sse(
    url: str,
    headers: dict[str, str],
    *,
    timeout_connect: float = 10,
    timeout_read: float = 120,
    timeout_write: float = 30,
    sse_read_timeout: float | None = 300,
    tcp_keepalive: bool = True,
    cancel_filter: bool = True,
    normalize_arguments: bool = True,
    token_refresher: Any = None,
    scope_upgrader: Any = None,
    token_expiry_getter: Any = None,
    proactive_refresh: bool = True,
    refresh_leeway: float = 60.0,
) -> None:
    """Run the stdio-to-SSE relay loop (MCP 2024-11-05 legacy transport).

    This implements the legacy SSE transport from the MCP 2024-11-05 spec:

    1. Open a persistent ``GET`` connection to the SSE endpoint
    2. Receive the first ``endpoint`` event containing the POST URL
    3. For each stdin line, POST the JSON-RPC message to that URL
    4. Receive responses via ``message`` events on the SSE stream

    Spec references:
    - WHATWG HTML — Server-Sent Events
      https://html.spec.whatwg.org/multipage/server-sent-events.html
    - MCP 2024-11-05 — HTTP with SSE Transport
      https://modelcontextprotocol.io/specification/2024-11-05/basic/transports

    Args:
        url: Remote MCP server SSE endpoint URL
        headers: HTTP headers to send with each request
        timeout_connect: Connection timeout in seconds
        timeout_read: Read timeout for the POST request
        timeout_write: Write timeout in seconds
        sse_read_timeout: Idle read timeout (seconds) on the long-lived
            SSE GET stream. A silent half-open TCP connection (dropped by
            a proxy, NAT, or firewall during a long-running tool call)
            will raise ``httpx.ReadTimeout`` after this interval and
            trigger an automatic reconnect instead of hanging forever.
            Set to ``None`` or ``0`` to opt out of the timeout and
            restore the previous unbounded-read behaviour. Defaults to
            300 seconds, matching the MCP Python SDK (#9).
        tcp_keepalive: When True (default), enable TCP keepalive at the
            socket layer in addition to ``sse_read_timeout``. Keepalive
            detects half-open TCP faster (≈120 s on Linux/macOS/BSD) and
            works regardless of whether the server sends SSE keepalive
            comments. See ``_tcp_keepalive_socket_options`` for the
            platform-specific tuning, and #9 for the upstream context.
        cancel_filter: When True (default), track ids from
            ``notifications/cancelled`` seen on stdin and drop any late
            upstream response carrying one of those ids on the SSE
            stream before it reaches stdout. See ``run`` for the full
            rationale.
        normalize_arguments: When True (default), rewrite a ``tools/call``
            request whose ``params.arguments`` is ``null`` to ``{}`` before
            forwarding. See ``run`` for the full rationale.
        token_refresher: Optional callable that returns updated headers
            on successful token refresh, or None on failure. Called when
            the server returns HTTP 401 on POST.
        scope_upgrader: Optional callable invoked when the server returns
            HTTP 403 with a ``Bearer error="insufficient_scope"``
            challenge on POST. Receives the scope string from the
            challenge and returns updated headers containing a
            broader-scope token, or None on failure. See #17.
    """

    def _shutdown(signum: int, _: Any) -> None:
        log(f"received signal {signum}, shutting down")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log(f"connecting to {redact_url(url)} (SSE transport)")

    # SSE GET is long-lived. Give it its own read timeout so a half-open
    # TCP connection (silent mid-tool-call) surfaces as a ReadTimeout
    # rather than a forever-hang; the reader loop then reconnects on
    # its own. Both ``None`` and ``0`` mean "disabled" — ``0`` is the CLI
    # escape hatch and ``None`` is the programmatic one. POST requests
    # use the separate timeout_read below.
    effective_sse_read = None if sse_read_timeout in (None, 0) else sse_read_timeout
    client = httpx.Client(
        transport=_make_httpx_transport(tcp_keepalive=tcp_keepalive),
        timeout=httpx.Timeout(
            connect=timeout_connect,
            read=effective_sse_read,
            write=timeout_write,
            pool=10,
        ),
    )

    tracker: _CancelTracker | None = _CancelTracker() if cancel_filter else None
    state = _SseState()
    # The reader thread snapshots ``headers`` on every (re)connect while the
    # main loop below may mutate it on a 401/403 token refresh. Serialise the
    # two so the GET request build never iterates a dict mid-mutation.
    headers_lock = threading.Lock()
    # Serialises the proactive-refresh timer's refresh against the reactive 401
    # refresh below so the two never race the AS's refresh-token rotation (#242).
    refresh_lock = threading.Lock()
    reader = threading.Thread(
        target=_sse_reader_loop,
        args=(client, url, headers, state, tracker, headers_lock),
        daemon=True,
    )
    reader.start()

    if not state.ready.wait(timeout=timeout_connect):
        log("timed out waiting for SSE endpoint event")
        state.stop.set()
        client.close()
        sys.exit(1)

    if state.endpoint_url is None:
        log("SSE reader terminated before endpoint event")
        state.stop.set()
        client.close()
        sys.exit(1)

    def _snapshot_headers() -> dict[str, str]:
        """Take a consistent copy of ``headers`` under the lock for a POST.

        Symmetric with the reader thread's snapshot and the 401/403 mutations
        so every cross-thread access to the shared ``headers`` object is
        serialised — no POST ever iterates the dict while a refresh is updating
        it. The token_refresher / scope_upgrader callbacks do NOT count as a
        cross-thread access: they layer a fresh Authorization onto a build-time
        frozen copy of the base headers (see cli.py _build_token_refresher),
        never touching this live object, so the serialisation claim holds.
        """
        with headers_lock:
            return dict(headers)

    refresh_timer, refresh_stop = _start_proactive_refresh(
        refresher=token_refresher,
        expiry_getter=token_expiry_getter,
        proactive_refresh=proactive_refresh,
        leeway=refresh_leeway,
        headers=headers,
        headers_lock=headers_lock,
        refresh_lock=refresh_lock,
    )

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            req_id, req_has_id = None, False
            tracked = False
            try:
                if normalize_arguments:
                    line = _normalize_null_arguments(line)

                cid = _extract_cancel_id(line)
                if cid is not None:
                    if tracker is not None:
                        tracker.add(cid)
                    # A cancelled id has no waiter — untrack it so a later
                    # stream drop does not synthesize an unsolicited error for
                    # it (done regardless of the cancel filter: the in-flight
                    # tracker is independent of response filtering). This is
                    # the primary path; the drain's tracker.contains() check
                    # narrows the drop-concurrent-with-cancel window but a
                    # drain that snapshots before this line is processed is
                    # inherently the spec's crossing case (a response passing
                    # the cancel in flight, which the canceller ignores).
                    state.untrack(cid)

                # Derive both the id value and its presence from one parse (the
                # hot path). A notification (no id) must never receive a response —
                # even when an upstream misbehaves and returns a 4xx/5xx to a POSTed
                # notification, synthesizing an `id:null` error to stdout would be a
                # JSON-RPC violation. Gate all synthesized error responses on
                # req_has_id.
                req_id, req_has_id = _extract_id_and_presence(line)
                if tracker is not None and req_id is not None:
                    # A request reusing a previously-cancelled id supersedes that
                    # cancel — untrack it so its response is delivered, not dropped.
                    tracker.discard(req_id)
                # Resolve the POST endpoint, waiting out a reconnect in progress.
                # endpoint_url is published lock-free, so a reconnect may clear it in
                # the TOCTOU window between this check and the read below; if the
                # capture comes back None, wait on ``ready`` (up to timeout_read) and
                # re-read once before giving up, rather than failing an otherwise
                # recoverable in-flight request with a spurious error.
                #
                # NOTE: ``ready`` is a LATCHED Event. The reconnect
                # paths clear it before nulling endpoint_url, but the fail-fast
                # branches (cross-origin endpoint refusal, first-connect failure)
                # deliberately set it with endpoint_url still None to unblock this
                # wait EARLY instead of hanging the full timeout_read. So a stale
                # latched set can make the wait below return immediately with
                # endpoint still None — by design: there is genuinely no usable
                # endpoint, and "SSE endpoint unavailable" is the correct answer.
                # The wait is a best-effort grace period, not a strict barrier.
                endpoint = state.endpoint_url
                if endpoint is None:
                    if state.ready.wait(timeout=timeout_read):
                        endpoint = state.endpoint_url
                    if endpoint is None:
                        if req_has_id:
                            _write_line(
                                _error_response("SSE endpoint unavailable", req_id)
                            )
                        continue

                # Track BEFORE the POST: on this transport the reply rides the
                # GET stream and can be delivered by the reader thread before
                # client.post() even returns (a fast server) or during a
                # 401/403 refresh round-trip below — tracking afterwards would
                # let the reader's untrack no-op and the already-answered id
                # linger until the next drop, where the drain would put a
                # spurious second response on the wire. Every failure path
                # that synthesizes an inline error below untracks instead. A
                # POST that completes concurrently with a drain snapshot
                # lands after the clear and rides until the NEXT disconnect —
                # narrow and self-healing, same spirit as the endpoint TOCTOU
                # window documented above. `id:null` stays untracked
                # (uncorrelatable; a null-id response also fails
                # _extract_response_id, so it could never be untracked).
                if req_has_id and _is_scalar_id(req_id):
                    tracked = state.track(req_id)
                    if not tracked:
                        log(
                            f"in-flight tracker at cap {_SSE_PENDING_MAX}; "
                            f"not tracking id {req_id!r}"
                        )
                try:
                    post_timeout = httpx.Timeout(
                        connect=timeout_connect,
                        read=timeout_read,
                        write=timeout_write,
                        pool=10,
                    )
                    # Honour Retry-After on 429/503 up to the cap; over-cap or
                    # retries-exhausted falls through with the final status and
                    # is surfaced to the caller by the generic 4xx/5xx branch
                    # below (typescript-sdk#1892).
                    #
                    # NOTE: this time.sleep runs on the STDIN thread,
                    # so while parked here (up to the 60 s cap) the loop cannot
                    # read the next stdin line — a notifications/cancelled for the
                    # very request being rate-limit-retried sits unprocessed until
                    # the sleep ends. Accepted: the cancel only delays, never
                    # corrupts; the reader thread keeps delivering replies; and an
                    # interruptible sleep would add cross-thread signalling the
                    # project deliberately avoids. The Retry-After cap bounds it.
                    for attempt in range(1, MAX_RETRIES + 1):
                        resp = client.post(
                            endpoint,
                            content=line,
                            headers=_snapshot_headers(),
                            timeout=post_timeout,
                        )
                        if resp.status_code not in _RETRYABLE_RATE_LIMIT_STATUSES:
                            break
                        sleep_secs = _handle_rate_limit(resp.headers, attempt)
                        if sleep_secs is None:
                            break
                        log(
                            f"attempt {attempt}/{MAX_RETRIES} got HTTP "
                            f"{resp.status_code}, sleeping {sleep_secs:.1f}s before retry"
                        )
                        time.sleep(sleep_secs)

                    # NOTE: the re-POST below resends the same JSON-RPC
                    # id after a refresh/step-up. Unlike a non-2xx (which reliably
                    # means "not accepted"), a 401/403 does NOT guarantee the origin
                    # rejected the request — an edge proxy can inject the 401 while
                    # the origin already accepted and enqueued a reply. The re-POST
                    # then makes the server push a SECOND async reply for the same id
                    # on the GET stream, and the reader's _emit writes both (the same
                    # no-shared-de-dup-map window documented at the non-2xx branch
                    # below). Left undeduplicated by design — a shared seen-id set
                    # would be heavier than the project's minimalism warrants.
                    if resp.status_code == 401 and token_refresher:
                        log("received 401, attempting token refresh")
                        # Serialise with the proactive timer's refresh so the two
                        # never race the AS's refresh-token rotation (#242).
                        with refresh_lock:
                            new_headers = token_refresher()
                        if new_headers:
                            with headers_lock:
                                headers.update(new_headers)
                            # Re-read the endpoint: if the reader thread reconnected
                            # between the first POST and this retry it may have
                            # published a fresh endpoint; honour it rather than the
                            # stale capture (fall back to the captured one if the
                            # reader has it momentarily nulled mid-reconnect).
                            endpoint = state.endpoint_url or endpoint
                            resp = client.post(
                                endpoint,
                                content=line,
                                headers=_snapshot_headers(),
                                timeout=httpx.Timeout(
                                    connect=timeout_connect,
                                    read=timeout_read,
                                    write=timeout_write,
                                    pool=10,
                                ),
                            )
                        else:
                            log("token refresh failed, returning error")
                            # Skip the inline error when the id was already
                            # settled elsewhere (reader delivered the real
                            # reply mid-refresh, or a drain answered it) — a
                            # second response for one id is the framing-error
                            # class this transport works around.
                            settled = tracked and not state.untrack(req_id)
                            if req_has_id and not settled:
                                _write_line(
                                    _error_response("authentication failed", req_id)
                                )
                            continue

                    if resp.status_code == 403 and scope_upgrader:
                        required_scope = _parse_www_authenticate_scope(
                            resp.headers.get("www-authenticate")
                        )
                        if required_scope is not None:
                            log(
                                f"received 403 insufficient_scope "
                                f"(required: {required_scope}), attempting step-up"
                            )
                            new_headers = scope_upgrader(required_scope)
                            if new_headers:
                                with headers_lock:
                                    headers.update(new_headers)
                                # Honour a fresh endpoint if the reader reconnected
                                # since the first POST (see the 401 retry above).
                                endpoint = state.endpoint_url or endpoint
                                resp = client.post(
                                    endpoint,
                                    content=line,
                                    headers=_snapshot_headers(),
                                    timeout=httpx.Timeout(
                                        connect=timeout_connect,
                                        read=timeout_read,
                                        write=timeout_write,
                                        pool=10,
                                    ),
                                )
                            else:
                                log("step-up authorization failed, returning error")
                                settled = tracked and not state.untrack(req_id)
                                if req_has_id and not settled:
                                    _write_line(
                                        _error_response("authorization failed", req_id)
                                    )
                                continue

                    if resp.status_code not in (200, 202):
                        log(f"POST returned HTTP {resp.status_code}")
                        # NOTE (#1): on the legacy SSE transport the POST only
                        # carries an HTTP ack; the JSON-RPC reply arrives async on
                        # the GET stream (written by the reader via _emit). These two
                        # threads do not share a per-id de-dup map, so if a server
                        # both non-2xx's the POST AND later pushes a reply for the
                        # same id, the client can receive two responses for one id.
                        # In practice a non-2xx POST means the request was not
                        # accepted and no reply follows, so the window is narrow;
                        # mcp-stdio deliberately does not de-duplicate it (consistent
                        # with the cancel filter's narrow scope).
                        settled = tracked and not state.untrack(req_id)
                        if req_has_id and not settled:
                            err_data = None
                            if resp.status_code in _RETRYABLE_RATE_LIMIT_STATUSES:
                                secs = _parse_retry_after(
                                    resp.headers.get("retry-after")
                                )
                                if secs is not None:
                                    err_data = {"retryAfter": secs}  # See #8.
                            _write_line(
                                _error_response(
                                    f"HTTP {resp.status_code}", req_id, data=err_data
                                )
                            )
                except httpx.HTTPError as e:
                    log(f"POST failed: {e}")
                    settled = tracked and not state.untrack(req_id)
                    if req_has_id and not settled:
                        _write_line(_error_response(str(e), req_id))
            except Exception as e:  # noqa: BLE001 — never crash the gateway
                # Structural #11 guard, mirroring run() and the SSE reader: an
                # unexpected non-httpx exception (a future helper, a _write_line
                # BrokenPipeError on the endpoint-unavailable path) degrades THIS
                # request to an error and keeps the loop alive, never crashing.
                log(f"internal relay error handling request: {e}")
                settled = tracked and not state.untrack(req_id)
                if req_has_id and not settled:
                    try:
                        _write_line(_error_response("internal relay error", req_id))
                    except OSError:
                        # swallow a second write failure when the
                        # original exception was a BrokenPipeError from
                        # _write_line — mirrors run(); a dead stdout can receive
                        # nothing, and the stderr log above already recorded it.
                        pass
                continue
            finally:
                # This request is no longer being actively settled: hand the
                # id (if still pending — POST accepted, reply outstanding)
                # back to the drain's jurisdiction.
                state.clear_busy()
    finally:
        state.stop.set()
        # Set stop first, then briefly join so the reader can exit its own
        # stream context when it next reaches a checkpoint. An *idle* GET (the
        # steady state — the reader is parked in iter_text() between events)
        # never reaches a checkpoint within the join, so client.close() below
        # then tears down the pool under it; that is safe — the reader catches
        # the resulting HTTPError and, because stop is already set, returns
        # without logging a reconnect. The daemon flag guarantees process exit
        # is never blocked regardless.
        _stop_proactive_refresh(refresh_timer, refresh_stop)
        reader.join(timeout=1.0)
        client.close()
