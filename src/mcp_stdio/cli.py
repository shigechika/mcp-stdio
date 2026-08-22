"""Command-line interface for mcp-stdio."""

from __future__ import annotations

import argparse
import math
import os
import re
import sys
from typing import TYPE_CHECKING, Callable
from urllib.parse import urlparse

import httpx

from . import __version__
from .relay import (
    _ACCEPT_ENCODING_IDENTITY,
    _DEFAULT_MAX_MESSAGE_SIZE,
    _MAX_MESSAGE_SIZE_ATTR,
    check_connection,
    run,
    run_sse,
)

if TYPE_CHECKING:
    from .token_store import TokenData


def _non_negative_float(value: str) -> float:
    """argparse type for non-negative floats (rejects negative leeway)."""
    try:
        f = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc
    # float() parses "nan" / "inf" / "-inf", which silently slip
    # past the `f < 0` / `f == 0` comparisons (every comparison with nan is
    # False) and defeat the very failure mode these validators guard against — a
    # nan/inf timeout makes httpx's elapsed-vs-deadline check always False, so a
    # connect/read never times out (a silent hang); a nan refresh-leeway forces
    # a refresh every call. Reject non-finite values up front. This also covers
    # _positive_float and every flag that reuses these (one fix, six flags).
    if not math.isfinite(f):
        raise argparse.ArgumentTypeError(f"value must be finite (got {value!r})")
    if f < 0:
        raise argparse.ArgumentTypeError(f"value must be >= 0 (got {f})")
    return f


def _non_negative_int(value: str) -> int:
    """argparse type for non-negative ints (--max-message-size: 0 = unlimited)."""
    try:
        i = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from exc
    if i < 0:
        raise argparse.ArgumentTypeError(f"value must be >= 0 (got {i})")
    return i


def _positive_float(value: str) -> float:
    """argparse type for strictly-positive floats.

    For ``--timeout-connect`` / ``--timeout-read`` a value of 0 is meaningless:
    httpx treats it as an immediate timeout, so every connect/read would fail at
    once. Reject 0 at parse time. ``--listen-read-timeout`` also uses this
    validator, deliberately NOT inheriting ``--sse-read-timeout``'s 0 = disable:
    an unbounded read on the modern listen stream would violate the spec's
    "SHOULD always enforce a maximum timeout" (#270 Phase 2, C9).
    (``--sse-read-timeout`` keeps 0 = disable and
    ``--oauth-refresh-leeway`` keeps 0 = no proactive refresh, so those stay on
    ``_non_negative_float``.) See #9.
    """
    f = _non_negative_float(value)  # reuse non-numeric / negative handling
    if f == 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return f


def _https_url_with_path(value: str) -> str:
    """argparse type for a Client ID Metadata Document URL (#60).

    draft-ietf-oauth-client-id-metadata-document-00 §3 "Client Identifier"
    defines the client_id URL as: MUST use the https scheme, MUST contain a
    path component, MUST NOT contain single-dot/double-dot path segments,
    MUST NOT contain a fragment, and MUST NOT contain userinfo. Reject a
    violation here rather than surfacing an opaque AS rejection deep in the
    OAuth flow.
    """
    parsed = urlparse(value)
    path_segments = parsed.path.split("/")
    if (
        parsed.scheme != "https"
        or parsed.path in ("", "/")
        or "." in path_segments
        or ".." in path_segments
        or parsed.fragment
        # urlparse only ever sets `password` when userinfo is present, and
        # whenever it does `username` is also non-None (at minimum ""), so
        # checking `username` alone already catches every userinfo case.
        or parsed.username is not None
    ):
        raise argparse.ArgumentTypeError(
            f"must be an https:// URL with a path component, no "
            f"single-dot/double-dot path segments, no fragment, and no "
            f"userinfo (e.g. https://example.com/client.json), got {value!r}"
        )
    return value


# RFC 7230 §3.2.6 field-name = token = 1*tchar. tchar covers
# "!#$%&'*+-.^_`|~" plus DIGIT and ALPHA. Used to reject header names
# that could be misinterpreted by downstream HTTP parsers.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Characters that terminate or re-open an HTTP header and must never
# appear in a user-supplied value. CR / LF enable request smuggling and
# arbitrary header injection; NUL terminates C-string parsing.
_HEADER_VALUE_FORBIDDEN = ("\r", "\n", "\0")


def _rfc8707_resource(value: str) -> str:
    """Validate an RFC 8707 §2 ``resource`` URI for ``--oauth-resource``.

    Must be an absolute URI (has a scheme) and MUST NOT include a fragment
    (RFC 8707 §2). The scheme is intentionally not constrained to http(s):
    Microsoft Entra ID's App ID URI is ``api://<app-id>``.
    """
    parsed = urlparse(value)
    if not parsed.scheme:
        raise argparse.ArgumentTypeError(
            f"--oauth-resource must be an absolute URI with a scheme (got {value!r})"
        )
    if parsed.fragment:
        raise argparse.ArgumentTypeError(
            "--oauth-resource must not include a fragment (RFC 8707 §2)"
        )
    return value


def _bearer_header_value(token: str) -> str:
    """Build a ``Bearer <token>`` Authorization value, rejecting CR/LF/NUL.

    An OAuth authorization server is LESS trusted than the operator, so an
    AS-supplied access token gets the same control-character ban as ``-H``
    values and ``--bearer-token`` (#14): a token carrying CR/LF could otherwise
    inject / split request headers on the wire. Raises ValueError on a forbidden
    character so the caller can fail the relevant flow.
    """
    if any(c in token for c in _HEADER_VALUE_FORBIDDEN):
        raise ValueError(
            "OAuth access token contains a forbidden control character (CR/LF/NUL)"
        )
    return f"Bearer {token}"


def _effective_bearer(data: TokenData, use_id_token: bool) -> str:
    """Pick the credential to present as Bearer: id_token or access_token (#59).

    With --oauth-use-id-token, the OIDC id_token is the Bearer (AWS Bedrock
    AgentCore / Cognito expect it). Falls back to access_token when the AS
    returned no id_token, with a one-line warning, rather than presenting an
    empty credential.
    """
    if use_id_token:
        if data.id_token:
            return data.id_token
        print(
            "warning: --oauth-use-id-token set but the token response carried no "
            "id_token; falling back to access_token",
            file=sys.stderr,
        )
    return data.access_token


def _parse_header(header: str) -> tuple[str, str]:
    """Parse a header string 'Key: Value' into a tuple.

    Rejects header names that violate RFC 7230 §3.2.6 (`token` grammar)
    and values containing CR, LF, or NUL (RFC 7230 §3.2) to guard
    against CRLF / NUL injection via `-H`. See #14.
    """
    if ":" not in header:
        print(
            f"error: invalid header format (expected 'Key: Value'): {header}",
            file=sys.stderr,
        )
        sys.exit(1)
    key, _, value = header.partition(":")
    key = key.strip()
    value = value.strip()
    if not _HEADER_NAME_RE.match(key):
        print(
            f"error: invalid header name {key!r} (must match RFC 7230 token grammar)",
            file=sys.stderr,
        )
        sys.exit(1)
    for bad in _HEADER_VALUE_FORBIDDEN:
        if bad in value:
            print(
                f"error: header value for {key!r} contains "
                f"a forbidden control character",
                file=sys.stderr,
            )
            sys.exit(1)
    return key, value


def _build_token_refresher(
    server_url: str,
    headers: dict[str, str],
    timeout_connect: float,
    timeout_read: float,
    *,
    use_id_token: bool = False,
    max_message_size: int = _DEFAULT_MAX_MESSAGE_SIZE,
) -> Callable[[], dict[str, str] | None]:
    """Build a token refresher callback for the relay loop.

    Returns a callable that attempts to refresh the OAuth token
    and returns updated headers on success, or None on failure.
    ``max_message_size`` bounds this OAuth client's own responses the same
    way ``--max-message-size`` bounds the main MCP traffic (#419) — the
    token endpoint is exactly as untrusted a network peer as the MCP
    server itself.
    """
    # Freeze a private copy of the operator-supplied base headers at build time
    # . The relay passes the SAME live `headers` dict to both this
    # callback and the SSE reader thread; closing over the live object and
    # iterating it via dict(headers) would read it UNLOCKED, racing any future
    # reader-thread mutation (today none exists, so it is safe, but the relay's
    # own comment claims every cross-thread access is serialised). The callbacks
    # only ever layer a fresh Authorization onto the static base headers, so a
    # frozen snapshot is behaviourally identical AND removes the shared-object
    # aliasing entirely — no lock needed, no fragile invariant to preserve.
    base_headers = dict(headers)

    def refresher() -> dict[str, str] | None:
        from .oauth import refresh_cached_token

        client = httpx.Client(
            headers=_ACCEPT_ENCODING_IDENTITY,
            timeout=httpx.Timeout(
                connect=timeout_connect, read=timeout_read, write=30, pool=10
            ),
            # AS-controlled redirects must never be auto-followed: a validated
            # token endpoint could otherwise 302 the credential POST to a
            # cleartext / cross-origin host, bypassing the #13 endpoint
            # validators. httpx already defaults to False; pin it explicitly so
            # the safety cannot regress.
            follow_redirects=False,
        )
        setattr(client, _MAX_MESSAGE_SIZE_ATTR, max_message_size)
        try:
            data = refresh_cached_token(server_url, client)
            if data is None:
                return None
            new_headers = dict(base_headers)
            new_headers["Authorization"] = _bearer_header_value(
                _effective_bearer(data, use_id_token)
            )
            return new_headers
        except Exception as e:
            # Mirror upgrader(): a refresh failure beyond the network call
            # (e.g. save_token re-raising OSError on a full/read-only disk)
            # must degrade to None so the relay's 401 handler emits a JSON-RPC
            # auth error and keeps the session alive, instead of an uncaught
            # crash that drops the stdio connection mid-session (#11 contract).
            print(f"error: token refresh failed: {e}", file=sys.stderr)
            return None
        finally:
            client.close()

    return refresher


def _build_scope_upgrader(
    server_url: str,
    headers: dict[str, str],
    timeout_connect: float,
    timeout_read: float,
    oauth_timeout: float,
    *,
    use_id_token: bool = False,
    max_message_size: int = _DEFAULT_MAX_MESSAGE_SIZE,
) -> Callable[[str], dict[str, str] | None]:
    """Build a scope-upgrade callback for the relay loop.

    Returns a callable that triggers an RFC 9470 / MCP step-up
    authorization flow for a given challenge scope and returns updated
    headers on success, or None on failure. ``oauth_timeout`` bounds the
    interactive wait (browser callback / device-code) the same way the
    cold-start ``ensure_token`` does, so ``--oauth-timeout`` applies to a
    mid-session step-up too, not just the initial authorization.
    ``max_message_size`` bounds this OAuth client's own responses, same as
    ``_build_token_refresher`` (#419).
    """
    # Freeze the operator-supplied base headers at build time; see
    # _build_token_refresher for why the live shared dict is not closed over.
    base_headers = dict(headers)

    def upgrader(required_scope: str) -> dict[str, str] | None:
        from .oauth import step_up_authorize

        client = httpx.Client(
            headers=_ACCEPT_ENCODING_IDENTITY,
            timeout=httpx.Timeout(
                connect=timeout_connect, read=timeout_read, write=30, pool=10
            ),
            # AS-controlled redirects must never be auto-followed: a validated
            # token endpoint could otherwise 302 the credential POST to a
            # cleartext / cross-origin host, bypassing the #13 endpoint
            # validators. httpx already defaults to False; pin it explicitly so
            # the safety cannot regress.
            follow_redirects=False,
        )
        setattr(client, _MAX_MESSAGE_SIZE_ATTR, max_message_size)
        try:
            data = step_up_authorize(
                server_url, client, required_scope, timeout=oauth_timeout
            )
            new_headers = dict(base_headers)
            new_headers["Authorization"] = _bearer_header_value(
                _effective_bearer(data, use_id_token)
            )
        except Exception as e:
            print(f"error: step-up authorization failed: {e}", file=sys.stderr)
            return None
        finally:
            client.close()
        return new_headers

    return upgrader


def _build_token_expiry_getter(
    server_url: str,
) -> Callable[[], float | None]:
    """Build an ``expires_at`` getter for the proactive-refresh timer.

    Returns a callable that reads the cached token's ``expires_at`` (Unix
    seconds) via ``token_store.load_token``, or None when there is no cached
    token / no expiry. Read fresh on each call so the timer always schedules
    against the latest persisted expiry (the refresher's ``save_token`` writes
    a new one). Exceptions degrade to None — the timer treats that as "nothing
    to schedule" and quietly re-polls, never crashing the daemon thread.
    """

    def getter() -> float | None:
        from .token_store import load_token

        try:
            data = load_token(server_url)
        except Exception as e:
            print(f"error: reading cached token expiry failed: {e}", file=sys.stderr)
            return None
        return data.expires_at if data else None

    return getter


def _build_cold_start_login(
    server_url: str,
    headers: dict[str, str],
    *,
    client_id: str | None,
    client_metadata_url: str | None,
    scope: str | None,
    device_flow: bool,
    refresh_leeway: float,
    resource_indicator: bool,
    oauth_resource: str | None,
    oauth_timeout: float,
    timeout_connect: float,
    timeout_read: float,
    use_id_token: bool,
    max_message_size: int = _DEFAULT_MAX_MESSAGE_SIZE,
) -> Callable[[], dict[str, str] | None]:
    """Build the cold-start background-OAuth callback for the relay (#296).

    Returns a callable that runs the FULL interactive OAuth flow (browser /
    device code, bounded by ``oauth_timeout``) and, on success, returns the base
    headers with a fresh ``Authorization`` (id_token or access_token per #59), or
    None on failure. The relay runs it on a background thread so a long login
    does not block the locally-answered ``initialize``. Mirrors
    ``_build_token_refresher``: a frozen header snapshot, its own short-lived
    client with redirects pinned off, all exceptions degraded to None.
    ``max_message_size`` bounds this OAuth client's own responses, same as
    ``_build_token_refresher``/``_build_scope_upgrader`` (#419).
    """
    base_headers = dict(headers)

    def login() -> dict[str, str] | None:
        from .oauth import ensure_token

        client = httpx.Client(
            headers=_ACCEPT_ENCODING_IDENTITY,
            timeout=httpx.Timeout(
                connect=timeout_connect, read=timeout_read, write=30, pool=10
            ),
            follow_redirects=False,
        )
        setattr(client, _MAX_MESSAGE_SIZE_ATTR, max_message_size)
        try:
            data = ensure_token(
                server_url,
                client,
                client_id=client_id or None,
                client_metadata_url=client_metadata_url,
                scope=scope or None,
                device_flow=device_flow,
                refresh_leeway=refresh_leeway,
                resource_indicator=resource_indicator,
                oauth_resource=oauth_resource,
                timeout=oauth_timeout,
                interactive=True,  # cold-start: run the full browser/device flow
            )
            if data is None:  # interactive=True never returns None, but be safe
                return None
            new_headers = dict(base_headers)
            new_headers["Authorization"] = _bearer_header_value(
                _effective_bearer(data, use_id_token)
            )
            return new_headers
        except Exception as e:
            print(f"error: cold-start OAuth failed: {e}", file=sys.stderr)
            return None
        finally:
            client.close()

    return login


def _main() -> None:
    """CLI body. Wrapped by ``main`` for top-level interrupt handling."""
    parser = argparse.ArgumentParser(
        prog="mcp-stdio",
        description="Stdio-to-HTTP gateway for MCP servers. "
        "Connects MCP clients (stdio) to remote Streamable HTTP or SSE MCP endpoints.",
    )
    parser.add_argument(
        "url",
        help="Remote MCP server URL (e.g., https://example.com:8080/mcp)",
    )
    parser.add_argument(
        "--bearer-token",
        default=None,
        help="Bearer token for authentication (or set MCP_BEARER_TOKEN env var)",
    )
    parser.add_argument(
        "--oauth",
        action="store_true",
        help="Enable OAuth 2.1 authentication (triggers browser flow if needed)",
    )
    parser.add_argument(
        "--oauth-device",
        action="store_true",
        help=(
            "Enable OAuth 2.1 Device Authorization Grant (RFC 8628) — "
            "headless flow: displays a verification URI and code on stderr "
            "instead of opening a browser"
        ),
    )
    parser.add_argument(
        "--client-id",
        # Default None (not the env value) so an ambient MCP_OAUTH_CLIENT_ID is
        # distinguishable from an explicit flag — the env var alone must not trip
        # the "ignored without --oauth" warning below.
        default=None,
        help="Pre-registered OAuth client ID (or set MCP_OAUTH_CLIENT_ID env var)",
    )
    parser.add_argument(
        "--client-metadata-url",
        default=None,
        type=_https_url_with_path,
        metavar="URL",
        help=(
            "HTTPS URL of a Client ID Metadata Document you host "
            "(draft-ietf-oauth-client-id-metadata-document-00), used as the "
            "OAuth client_id instead of Dynamic Client Registration. Used "
            "when set, regardless of whether the AS metadata advertises "
            "client_id_metadata_document_supported (warns if it does not). "
            "Ignored if --client-id is also given. You must host the "
            "document yourself — mcp-stdio does not serve one; its "
            "redirect_uris should list mcp-stdio's loopback callback "
            "(http://127.0.0.1/callback) — the AS must accept any port for "
            "a loopback redirect (RFC 8252 §7.3/§8.4). Only used with "
            "--oauth / --oauth-device (#60)."
        ),
    )
    parser.add_argument(
        "--oauth-scope",
        default="",
        help="OAuth scope to request",
    )
    parser.add_argument(
        "--no-resource-indicator",
        action="store_true",
        help=(
            "Omit the RFC 8707 resource parameter from all OAuth requests. "
            "Required for AS that reject the parameter, such as Microsoft "
            "Entra ID v2 when using api:// scopes (AADSTS9010010). "
            "The setting is persisted in the token store so proactive "
            "refreshes and step-up flows behave consistently."
        ),
    )
    parser.add_argument(
        "--oauth-resource",
        default=None,
        type=_rfc8707_resource,
        metavar="URI",
        help=(
            "Send this exact value as the RFC 8707 resource on every OAuth "
            "request (authorization, token exchange, refresh, device flow), "
            "instead of the value derived from the server URL. Required for AS "
            "that demand a specific resource identifier, e.g. Microsoft Entra "
            "ID's App ID URI api://<app-id-guid> (which returns AADSTS9010010 "
            "when the resource is anything else). Persisted in the token store "
            "so refresh and step-up stay consistent. Mutually exclusive with "
            "--no-resource-indicator. Only used with --oauth / --oauth-device."
        ),
    )
    parser.add_argument(
        "--oauth-refresh-leeway",
        type=_non_negative_float,
        # Pass as string so argparse re-applies _non_negative_float to the
        # default — invalid env var values (negative, non-numeric) surface
        # as argparse errors instead of a raw Python ValueError on startup.
        # `or "60"` treats an exported-but-EMPTY env var (a common CI artifact
        # of `export VAR=$MAYBE_UNSET`) as unset rather than aborting startup
        # with "invalid float value: ''"; a genuinely malformed value still
        # errors.
        default=(os.environ.get("MCP_OAUTH_REFRESH_LEEWAY") or "60"),
        metavar="SECONDS",
        help=(
            "Proactively refresh access tokens this many seconds before they "
            "expire (default: 60, or MCP_OAUTH_REFRESH_LEEWAY env var). "
            "Increase for ASes with significant clock skew; decrease for "
            "deployments where short-lived tokens make a 60 s window "
            "exceed token TTL. Only used with --oauth / --oauth-device. Note: a "
            "malformed MCP_OAUTH_REFRESH_LEEWAY value aborts startup at argument "
            "parsing even on a non-OAuth run (the env default is validated eagerly "
            "so a bad value surfaces clearly rather than silently)"
        ),
    )
    parser.add_argument(
        "--oauth-eager",
        action="store_true",
        help=(
            "Start serving immediately and run the interactive OAuth flow in the "
            "background (cold-start). The relay answers the client's initialize "
            "locally and returns -32002 for tool calls until OAuth completes, "
            "then emits notifications/*/list_changed so the client fetches the "
            "now-available lists. Avoids the client's ~60 s initialize timeout "
            "when a browser/SSO/MFA login takes longer (#296). Streamable HTTP "
            "only; ignored (blocking flow) on --transport sse. A warm cache "
            "(valid/refreshable token) is unaffected. Only with --oauth / "
            "--oauth-device."
        ),
    )
    parser.add_argument(
        "--oauth-use-id-token",
        action="store_true",
        help=(
            "Present the OIDC id_token as the Bearer credential instead of the "
            "access_token. Required for servers that validate the id_token (e.g. "
            "AWS Bedrock AgentCore / Cognito). Falls back to the access_token if "
            "the AS returns no id_token. Only used with --oauth / --oauth-device "
            "(#59)."
        ),
    )
    parser.add_argument(
        "--no-proactive-refresh",
        action="store_true",
        help=(
            "Disable the background timer that proactively refreshes the OAuth "
            "access token shortly before it expires (lead time: "
            "--oauth-refresh-leeway, default 60 s). Enabled by default in OAuth "
            "mode. Without it, a long-lived session against a gateway that "
            "signals token expiry as an HTTP 200 tool-error (e.g. Atlassian's "
            "MCP gateway) rather than a transport 401 cannot recover until the "
            "process restarts (#242). Only meaningful with --oauth / "
            "--oauth-device; a no-op otherwise."
        ),
    )
    parser.add_argument(
        "--oauth-timeout",
        type=_positive_float,
        # how long the interactive OAuth flow waits for the user —
        # the browser-callback redirect (auth-code flow) or the device-code
        # confirmation. Was a hardcoded 120 s; expose it so a user who needs
        # longer (slow device-code entry) is not cut off. Distinct from the HTTP
        # --timeout-* (those bound network reads, not human interaction).
        default=120.0,
        metavar="SECONDS",
        help=(
            "Seconds to wait for the interactive OAuth flow (browser callback / "
            "device-code confirmation) before giving up (default: 120). Only "
            "used with --oauth / --oauth-device"
        ),
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        dest="headers",
        metavar="'Key: Value'",
        help="Custom header to send (can be specified multiple times)",
    )
    parser.add_argument(
        "--transport",
        choices=["streamable-http", "sse"],
        default="streamable-http",
        help="Transport type: streamable-http (default) or sse (MCP 2024-11-05 legacy)",
    )
    parser.add_argument(
        "--protocol-era",
        choices=["legacy", "modern", "auto"],
        default="legacy",
        help=(
            "MCP protocol era to speak to the remote over --transport "
            "streamable-http (ignored on --transport sse, which is always "
            "the pre-Streamable-HTTP legacy transport regardless of this "
            "flag): 'legacy' (default) is today's initialize handshake + "
            "Mcp-Session-Id (spec rev 2025-06-18 and earlier) — unchanged "
            "wire behavior, so existing deployments are unaffected. "
            "'modern' forces the spec rev 2026-07-28 path: no initialize "
            "handshake or session id, per-request Mcp-Method/Mcp-Name "
            "headers and _meta on every POST. 'auto' runs a one-shot "
            "server/discover probe before serving (one extra request at "
            "startup) and picks whichever era the probe indicates — not "
            "the default because of that extra request. See #270."
        ),
    )
    parser.add_argument(
        "--timeout-connect",
        type=_positive_float,
        # Float defaults: argparse applies ``type`` only to argv
        # strings, never to the default object, so an int default would leave
        # args.timeout_connect an int when the flag is omitted. httpx tolerates
        # both, but keep the attribute's type consistent with the validator.
        default=10.0,
        help="Connection timeout in seconds, > 0 (default: 10)",
    )
    parser.add_argument(
        "--timeout-read",
        type=_positive_float,
        default=120.0,
        help="Read timeout in seconds, > 0 (default: 120)",
    )
    parser.add_argument(
        "--sse-read-timeout",
        type=_non_negative_float,
        # Float default: argparse applies ``type`` only to argv
        # strings, never to the default object, so an int default would leave the
        # attribute an int when the flag is omitted — keep it consistent with the
        # _non_negative_float validator and the --timeout-* float defaults.
        default=300.0,
        help=(
            "Idle read timeout (seconds) on the SSE GET stream "
            "(default: 300). A silent half-open TCP connection will "
            "raise ReadTimeout and trigger auto-reconnect instead of "
            "hanging. Set to 0 to disable. Has no effect on the "
            "streamable-http transport. See #9."
        ),
    )
    parser.add_argument(
        "--listen-read-timeout",
        type=_positive_float,
        # Float default: argparse applies ``type`` only to argv strings, never
        # to the default object — keep the attribute a float like the other
        # timeout flags.
        default=300.0,
        help=(
            "Idle read timeout (seconds, > 0) on the modern protocol era's "
            "long-lived subscriptions/listen POST stream (default: 300). A "
            "silent half-open connection raises ReadTimeout and triggers "
            "auto-reconnect instead of hanging. Unlike --sse-read-timeout, 0 "
            "is rejected (the MCP spec says clients SHOULD always enforce a "
            "maximum timeout). Only meaningful with --protocol-era "
            "modern/auto. See #270."
        ),
    )
    parser.add_argument(
        "--max-message-size",
        type=_non_negative_int,
        default=_DEFAULT_MAX_MESSAGE_SIZE,
        metavar="BYTES",
        help=(
            "Cap in bytes on a single upstream response body (JSON or "
            f"cumulative SSE stream) buffered before parsing (default: "
            f"{_DEFAULT_MAX_MESSAGE_SIZE}, 10 MiB; 0 disables the cap). "
            "Protects against a malicious or misbehaving MCP server making "
            "this relay allocate an unbounded amount of memory (#416). "
            "This relay sends Accept-Encoding: identity by default (#417); "
            "-H 'Accept-Encoding: gzip' or 'deflate' opts back in and is "
            "decoded through a genuinely size-bounded decompressor (#418) "
            "— any other negotiated coding (stacked, or one this relay has "
            "no bounded decoder for) needs --max-message-size 0 to be "
            "accepted at all. Also applies to this relay's own OAuth HTTP "
            "traffic (discovery, DCR, token exchange/refresh, device-flow "
            "polling) — an authorization server is exactly as untrusted a "
            "network peer as the MCP server itself (#419)."
        ),
    )
    parser.add_argument(
        "--no-tcp-keepalive",
        action="store_true",
        help=(
            "Disable TCP keepalive on the HTTP socket. TCP keepalive is "
            "on by default (60s idle + 4 probes × 15s ≈ 120s half-open "
            "detection on Linux/macOS/FreeBSD/NetBSD; SO_KEEPALIVE-only on "
            "Windows and other platforms). "
            "Opt out for proxy/NAT paths that strip keepalive packets. "
            "See #9."
        ),
    )
    parser.add_argument(
        "--no-cancel-filter",
        action="store_true",
        help=(
            "Disable the cancel-aware response filter. By default "
            "mcp-stdio drops any late JSON-RPC response whose id was "
            "cancelled via notifications/cancelled, enforcing the MCP "
            "spec's receiver-side SHOULD on behalf of non-compliant "
            "servers and shielding clients from canceller-side bugs. "
            "See anthropics/claude-code#51073 and "
            "modelcontextprotocol/python-sdk#2480. Opt out only when "
            "debugging the raw upstream wire."
        ),
    )
    parser.add_argument(
        "--no-normalize-arguments",
        action="store_true",
        help=(
            "Disable tools/call argument normalization. By default mcp-stdio "
            "rewrites a tools/call request whose arguments field is null to "
            "an empty object {}, so strict servers that reject the null form "
            "(modelcontextprotocol/typescript-sdk#2012) accept the call. Opt "
            "out to forward the client request verbatim."
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Check connection to the MCP server and exit. Note: combined with "
            "--oauth / --oauth-device on a cold token cache this runs the FULL "
            "interactive auth first (may open a browser or print a device code "
            "and wait), so the check verifies the authenticated path end-to-end "
            "rather than being a purely non-interactive probe."
        ),
    )
    parser.add_argument(
        # Deprecated alias for --check; hidden from --help.
        # Kept for backward compatibility with v0.4.x and earlier.
        "--test",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args()

    # An explicit --bearer-token on the command line is distinct from an
    # ambient MCP_BEARER_TOKEN env var. Only the explicit flag participates in
    # the mutual-exclusion check, so leaving MCP_BEARER_TOKEN exported in the
    # shell / host config does not block --oauth (the OAuth flow then supplies
    # the Authorization header and the env token is ignored).
    bearer_from_flag = args.bearer_token is not None
    bearer_token = (
        args.bearer_token
        if bearer_from_flag
        else os.environ.get("MCP_BEARER_TOKEN", "")
    )

    # Count an explicit --bearer-token by its PRESENCE, not its truthiness, so
    # `--bearer-token '' --oauth` errors out the same as a non-empty token
    # rather than silently slipping past the mutual-exclusion check (an empty
    # bearer is still an explicit, contradictory auth choice). An ambient
    # MCP_BEARER_TOKEN (bearer_from_flag False) still does not participate.
    n_auth = sum([args.oauth, args.oauth_device, bearer_from_flag])
    if n_auth > 1:
        print(
            "error: --oauth, --oauth-device, and --bearer-token are mutually exclusive",
            file=sys.stderr,
        )
        sys.exit(1)

    # --no-resource-indicator omits the RFC 8707 resource; --oauth-resource sets
    # a specific value. Requesting both is contradictory.
    if args.no_resource_indicator and args.oauth_resource is not None:
        print(
            "error: --no-resource-indicator and --oauth-resource are mutually exclusive",
            file=sys.stderr,
        )
        sys.exit(1)

    # Resolve --client-id: the explicit flag wins; otherwise the env var. The
    # warning below only counts an EXPLICIT --client-id (args.client_id is not
    # None), so an ambient MCP_OAUTH_CLIENT_ID does not trip it.
    client_id = (
        args.client_id
        if args.client_id is not None
        else os.environ.get("MCP_OAUTH_CLIENT_ID", "")
    )

    # Warn if OAuth-only options are explicitly set without an OAuth flow — they
    # are silently ignored otherwise. client_id is presence-based (`is not None`)
    # so an explicit `--client-id ''` trips it too, matching the --bearer-token
    # discipline. oauth_scope's default is "" (not None), so an
    # explicit empty value is indistinguishable from the default and stays on the
    # truthiness check. --oauth-refresh-leeway and --oauth-timeout are also
    # OAuth-only but always carry a non-None default, so they cannot be
    # presence-detected here — their help text flags them as OAuth-only instead.
    if not (args.oauth or args.oauth_device) and (
        args.client_id is not None
        or args.client_metadata_url is not None
        or args.oauth_scope
        or args.no_resource_indicator
        or args.oauth_resource is not None
        or args.oauth_use_id_token
        or args.oauth_eager
    ):
        print(
            "warning: --client-id / --client-metadata-url / --oauth-scope / "
            "--no-resource-indicator / --oauth-resource / --oauth-use-id-token / "
            "--oauth-eager are ignored without --oauth or --oauth-device",
            file=sys.stderr,
        )

    # A pre-registered client_id (--client-id, OR an ambient MCP_OAUTH_CLIENT_ID
    # — see the resolution above) outranks --client-metadata-url (CIMD) per the
    # MCP "Client Registration Approaches" priority order (#60). Gate this on
    # the RESOLVED `client_id` (the same `client_id or None` truthiness check
    # oauth.py applies at line 811/828 below), not on `args.client_id is not
    # None`: that presence-only check missed an ambient env var silently
    # winning with no warning, and misfired on an explicit `--client-id ''`
    # (falsy — --client-metadata-url actually wins there) with a warning that
    # claimed the opposite of what happens.
    if client_id and args.client_metadata_url is not None:
        print(
            "warning: a pre-registered client_id (--client-id or "
            "MCP_OAUTH_CLIENT_ID) and --client-metadata-url were both given; "
            "the pre-registered client_id takes precedence",
            file=sys.stderr,
        )

    # An explicit but EMPTY --bearer-token counts as an auth choice for the
    # mutual-exclusion check above (presence, not truthiness), yet the header
    # build below (`if bearer_token`) would attach NO Authorization header —
    # silently unauthenticated. Surface that asymmetry so an operator whose
    # shell expansion produced '' is not misled into thinking the request is
    # authenticated.
    if bearer_from_flag and not bearer_token:
        print(
            "warning: --bearer-token is empty; sending no Authorization header",
            file=sys.stderr,
        )

    # When an OAuth flow is selected, ignore any ambient env bearer token —
    # the flow below sets the Authorization header itself.
    if args.oauth or args.oauth_device:
        bearer_token = ""

    # A bearer token reaches the wire as the Authorization header value, so it
    # must satisfy the same CR/LF/NUL ban as -H values (RFC 7230 §3.2) — a
    # newline in the token would otherwise inject arbitrary headers. See #14.
    if bearer_token and any(c in bearer_token for c in _HEADER_VALUE_FORBIDDEN):
        print(
            "error: bearer token contains a forbidden control character "
            "(CR, LF, or NUL)",
            file=sys.stderr,
        )
        sys.exit(1)

    # Build headers
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if bearer_token:
        # Route through _bearer_header_value so the "Bearer " literal and the
        # CR/LF/NUL ban live in one place. The control-char check
        # above already guarantees this cannot raise, but keeping a single
        # builder avoids the contract drifting between the two call sites.
        headers["Authorization"] = _bearer_header_value(bearer_token)
    for h in args.headers:
        key, value = _parse_header(h)
        # HTTP header names are case-insensitive (RFC 7230 §3.2). Drop any
        # existing header that differs only in case so an explicit -H overrides
        # the built-in default (e.g. -H 'authorization: ...' replaces the
        # bearer Authorization) instead of sending two same-named headers.
        for existing in [k for k in headers if k.lower() == key.lower()]:
            # when a -H 'Authorization' displaces an EXPLICIT
            # --bearer-token, warn instead of silently dropping it — mirroring
            # the OAuth path's override warning. Gated on bearer_from_flag (so
            # an ambient env token does not trip it) and on the displaced value
            # still being the bearer's, so a second -H Authorization does not
            # re-warn.
            if (
                key.lower() == "authorization"
                and bearer_from_flag
                and bearer_token
                and headers.get(existing) == _bearer_header_value(bearer_token)
            ):
                print(
                    "warning: explicit -H 'Authorization' header overrides "
                    "--bearer-token",
                    file=sys.stderr,
                )
            del headers[existing]
        headers[key] = value

    # OAuth flow (before relay starts)
    token_refresher: Callable[[], dict[str, str] | None] | None = None
    scope_upgrader: Callable[[str], dict[str, str] | None] | None = None
    token_expiry_getter: Callable[[], float | None] | None = None
    cold_start_login: Callable[[], dict[str, str] | None] | None = None
    if args.oauth or args.oauth_device:
        # NOTE: this runs BEFORE the --check branch below, and
        # ensure_token only short-circuits on a valid cached/refreshable token.
        # So `--oauth --check` on a COLD cache performs the full interactive auth
        # (browser / device code, blocking up to the flow timeout) — by design,
        # so a --check of the authenticated path is verified end-to-end. This is
        # documented in the --check help text; it is not a non-interactive probe.
        from .oauth import ensure_token

        # --oauth-eager (cold-start) is Streamable HTTP only and meaningless for a
        # one-shot --check/--test probe. When eligible, probe the cache
        # NON-interactively so a cold cache defers the browser/device flow to a
        # background thread in the relay instead of blocking startup.
        eager = args.oauth_eager and not (args.check or args.test)
        if eager and args.transport == "sse":
            print(
                "warning: --oauth-eager is ignored on --transport sse; the OAuth "
                "flow runs before the relay starts",
                file=sys.stderr,
            )
            eager = False

        client = httpx.Client(
            headers=_ACCEPT_ENCODING_IDENTITY,
            timeout=httpx.Timeout(
                connect=args.timeout_connect,
                read=args.timeout_read,
                write=30,
                pool=10,
            ),
            # Never auto-follow AS-controlled redirects on the OAuth flow — a
            # validated token endpoint could otherwise 302 the credential POST
            # (code + client_secret) to a cleartext / cross-origin host,
            # bypassing the #13 endpoint validators. Explicit despite httpx's
            # False default so the safety cannot regress.
            follow_redirects=False,
        )
        setattr(client, _MAX_MESSAGE_SIZE_ATTR, args.max_message_size)
        try:
            token_data = ensure_token(
                args.url,
                client,
                client_id=client_id or None,
                client_metadata_url=args.client_metadata_url,
                scope=args.oauth_scope or None,
                device_flow=args.oauth_device,
                refresh_leeway=args.oauth_refresh_leeway,
                resource_indicator=not args.no_resource_indicator,
                oauth_resource=args.oauth_resource,
                timeout=args.oauth_timeout,
                interactive=not eager,
            )
            if eager and token_data is None:
                # COLD path: no cached/refreshable token. Defer the interactive
                # OAuth to a background thread in the relay (it answers initialize
                # locally and gates until login completes). No Authorization is
                # set now; the cold-start daemon installs it on success.
                cold_start_login = _build_cold_start_login(
                    args.url,
                    headers,
                    client_id=client_id or None,
                    client_metadata_url=args.client_metadata_url,
                    scope=args.oauth_scope or None,
                    device_flow=args.oauth_device,
                    refresh_leeway=args.oauth_refresh_leeway,
                    resource_indicator=not args.no_resource_indicator,
                    oauth_resource=args.oauth_resource,
                    oauth_timeout=args.oauth_timeout,
                    timeout_connect=args.timeout_connect,
                    timeout_read=args.timeout_read,
                    use_id_token=args.oauth_use_id_token,
                    max_message_size=args.max_message_size,
                )
            else:
                # WARM path (token available, or non-eager blocking flow). Drop
                # any differently-cased 'authorization' header a -H supplied
                # earlier (the -H loop ran before this block), so the OAuth token
                # is the single Authorization sent rather than a duplicate pair.
                overridden = [k for k in headers if k.lower() == "authorization"]
                if overridden:
                    # Explicit -H 'Authorization: ...' AND an OAuth flow — warn
                    # that the OAuth token wins instead of silently discarding it.
                    print(
                        "warning: explicit -H 'Authorization' header is overridden "
                        "by the OAuth-acquired token",
                        file=sys.stderr,
                    )
                for existing in overridden:
                    del headers[existing]
                try:
                    headers["Authorization"] = _bearer_header_value(
                        _effective_bearer(token_data, args.oauth_use_id_token)
                    )
                except ValueError as e:
                    # The AS handed us a token with CR/LF/NUL — fail startup
                    # clearly rather than splitting headers on the wire.
                    print(f"error: {e}", file=sys.stderr)
                    sys.exit(1)
            # The relay-loop 401/403 recovery callbacks are unused by the
            # one-shot --check / --test probe (check_connection never refreshes
            # or steps up), so only build them on the real relay path. See #15.
            # They work for both warm and cold paths: the refresher/upgrader
            # rebuild Authorization from the (eventually) cached token.
            if not (args.check or args.test):
                token_refresher = _build_token_refresher(
                    args.url,
                    headers,
                    args.timeout_connect,
                    args.timeout_read,
                    use_id_token=args.oauth_use_id_token,
                    max_message_size=args.max_message_size,
                )
                scope_upgrader = _build_scope_upgrader(
                    args.url,
                    headers,
                    args.timeout_connect,
                    args.timeout_read,
                    args.oauth_timeout,
                    use_id_token=args.oauth_use_id_token,
                    max_message_size=args.max_message_size,
                )
                token_expiry_getter = _build_token_expiry_getter(args.url)
        except Exception as e:
            print(f"error: OAuth authentication failed: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            client.close()

    if args.test:
        print(
            "warning: --test is deprecated and will be removed in a future "
            "release; use --check instead",
            file=sys.stderr,
        )
        args.check = True

    if args.check:
        ok = check_connection(
            url=args.url,
            headers=headers,
            timeout_connect=args.timeout_connect,
            timeout_read=args.timeout_read,
            transport=args.transport,
            max_message_size=args.max_message_size,
        )
        sys.exit(0 if ok else 1)

    # run() ignores sse_read_timeout (that knob governs only the legacy SSE
    # transport's GET stream), so only pass it through on the SSE path. The
    # one long-lived stream run() CAN hold — the modern era's
    # subscriptions/listen POST (#270 Phase 2) — has its own dedicated knob,
    # --listen-read-timeout, passed only to run() and ignored by run_sse.
    # tcp_keepalive, cancel_filter and normalize_arguments apply to both.
    tcp_keepalive = not args.no_tcp_keepalive
    cancel_filter = not args.no_cancel_filter
    normalize_arguments = not args.no_normalize_arguments
    proactive_refresh = not args.no_proactive_refresh
    if args.transport == "sse" and args.protocol_era != "legacy":
        print(
            f"warning: --protocol-era {args.protocol_era} is ignored on "
            "--transport sse (always the pre-Streamable-HTTP legacy transport)",
            file=sys.stderr,
        )
    if args.transport == "sse":
        run_sse(
            url=args.url,
            headers=headers,
            timeout_connect=args.timeout_connect,
            timeout_read=args.timeout_read,
            sse_read_timeout=args.sse_read_timeout,
            tcp_keepalive=tcp_keepalive,
            cancel_filter=cancel_filter,
            normalize_arguments=normalize_arguments,
            token_refresher=token_refresher,
            scope_upgrader=scope_upgrader,
            token_expiry_getter=token_expiry_getter,
            proactive_refresh=proactive_refresh,
            refresh_leeway=args.oauth_refresh_leeway,
            max_message_size=args.max_message_size,
        )
    else:
        run(
            url=args.url,
            headers=headers,
            timeout_connect=args.timeout_connect,
            timeout_read=args.timeout_read,
            tcp_keepalive=tcp_keepalive,
            cancel_filter=cancel_filter,
            normalize_arguments=normalize_arguments,
            token_refresher=token_refresher,
            scope_upgrader=scope_upgrader,
            token_expiry_getter=token_expiry_getter,
            proactive_refresh=proactive_refresh,
            refresh_leeway=args.oauth_refresh_leeway,
            cold_start_login=cold_start_login,
            protocol_era=args.protocol_era,
            listen_read_timeout=args.listen_read_timeout,
            max_message_size=args.max_message_size,
        )


def main() -> None:
    """Entry point for mcp-stdio CLI.

    run() / run_sse() install their own SIGINT/SIGTERM handlers,
    but the pre-relay work — argument parsing and especially the blocking
    interactive OAuth flow (browser callback / device-code wait, up to
    --oauth-timeout) — runs before that. A Ctrl-C there would otherwise dump a
    raw KeyboardInterrupt traceback (BaseException, so the OAuth block's
    `except Exception` does not catch it). Exit cleanly with 130 instead.
    """
    try:
        # `mcp-stdio serve ...` is the reverse gateway (HTTP -> stdio); it has
        # its own argparse surface and never touches the client parser below.
        if len(sys.argv) > 1 and sys.argv[1] == "serve":
            from .server import serve_main

            serve_main(sys.argv[2:])
            return
        _main()
    except KeyboardInterrupt:
        print("\nmcp-stdio: interrupted", file=sys.stderr)
        sys.exit(130)
