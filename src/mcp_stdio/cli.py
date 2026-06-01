"""Command-line interface for mcp-stdio."""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Callable

import httpx

from . import __version__
from .relay import check_connection, run, run_sse

def _non_negative_float(value: str) -> float:
    """argparse type for non-negative floats (rejects negative leeway)."""
    try:
        f = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc
    if f < 0:
        raise argparse.ArgumentTypeError(f"value must be >= 0 (got {f})")
    return f


# RFC 7230 §3.2.6 field-name = token = 1*tchar. tchar covers
# "!#$%&'*+-.^_`|~" plus DIGIT and ALPHA. Used to reject header names
# that could be misinterpreted by downstream HTTP parsers.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Characters that terminate or re-open an HTTP header and must never
# appear in a user-supplied value. CR / LF enable request smuggling and
# arbitrary header injection; NUL terminates C-string parsing.
_HEADER_VALUE_FORBIDDEN = ("\r", "\n", "\0")


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
            f"error: invalid header name {key!r} "
            f"(must match RFC 7230 token grammar)",
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
) -> Callable[[], dict[str, str] | None]:
    """Build a token refresher callback for the relay loop.

    Returns a callable that attempts to refresh the OAuth token
    and returns updated headers on success, or None on failure.
    """

    def refresher() -> dict[str, str] | None:
        from .oauth import refresh_cached_token

        client = httpx.Client(
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
        try:
            data = refresh_cached_token(server_url, client)
            if data is None:
                return None
            new_headers = dict(headers)
            new_headers["Authorization"] = f"Bearer {data.access_token}"
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
) -> Callable[[str], dict[str, str] | None]:
    """Build a scope-upgrade callback for the relay loop.

    Returns a callable that triggers an RFC 9470 / MCP step-up
    authorization flow for a given challenge scope and returns updated
    headers on success, or None on failure.
    """

    def upgrader(required_scope: str) -> dict[str, str] | None:
        from .oauth import step_up_authorize

        client = httpx.Client(
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
        try:
            data = step_up_authorize(server_url, client, required_scope)
        except Exception as e:
            print(f"error: step-up authorization failed: {e}", file=sys.stderr)
            return None
        finally:
            client.close()
        new_headers = dict(headers)
        new_headers["Authorization"] = f"Bearer {data.access_token}"
        return new_headers

    return upgrader


def main() -> None:
    """Entry point for mcp-stdio CLI."""
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
            "exceed token TTL"
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
        "--timeout-connect",
        type=_non_negative_float,
        default=10,
        help="Connection timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--timeout-read",
        type=_non_negative_float,
        default=120,
        help="Read timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--sse-read-timeout",
        type=_non_negative_float,
        default=300,
        help=(
            "Idle read timeout (seconds) on the SSE GET stream "
            "(default: 300). A silent half-open TCP connection will "
            "raise ReadTimeout and trigger auto-reconnect instead of "
            "hanging. Set to 0 to disable. Has no effect on the "
            "streamable-http transport. See #9."
        ),
    )
    parser.add_argument(
        "--no-tcp-keepalive",
        action="store_true",
        help=(
            "Disable TCP keepalive on the HTTP socket. TCP keepalive is "
            "on by default (60s idle + 4 probes × 15s ≈ 120s half-open "
            "detection on Linux/macOS/BSD; SO_KEEPALIVE-only on Windows). "
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
        help="Check connection to the MCP server and exit",
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

    # Resolve --client-id: the explicit flag wins; otherwise the env var. The
    # warning below only counts an EXPLICIT --client-id (args.client_id is not
    # None), so an ambient MCP_OAUTH_CLIENT_ID does not trip it.
    client_id = (
        args.client_id
        if args.client_id is not None
        else os.environ.get("MCP_OAUTH_CLIENT_ID", "")
    )

    # Warn if OAuth-only options are explicitly set without an OAuth flow — they
    # are silently ignored otherwise.
    if not (args.oauth or args.oauth_device) and (
        args.client_id or args.oauth_scope or args.no_resource_indicator
    ):
        print(
            "warning: --client-id / --oauth-scope / --no-resource-indicator are "
            "ignored without --oauth or --oauth-device",
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
        headers["Authorization"] = f"Bearer {bearer_token}"
    for h in args.headers:
        key, value = _parse_header(h)
        # HTTP header names are case-insensitive (RFC 7230 §3.2). Drop any
        # existing header that differs only in case so an explicit -H overrides
        # the built-in default (e.g. -H 'authorization: ...' replaces the
        # bearer Authorization) instead of sending two same-named headers.
        for existing in [k for k in headers if k.lower() == key.lower()]:
            del headers[existing]
        headers[key] = value

    # OAuth flow (before relay starts)
    token_refresher: Callable[[], dict[str, str] | None] | None = None
    scope_upgrader: Callable[[str], dict[str, str] | None] | None = None
    if args.oauth or args.oauth_device:
        from .oauth import ensure_token

        client = httpx.Client(
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
        try:
            token_data = ensure_token(
                args.url,
                client,
                client_id=client_id or None,
                scope=args.oauth_scope or None,
                device_flow=args.oauth_device,
                refresh_leeway=args.oauth_refresh_leeway,
                resource_indicator=not args.no_resource_indicator,
            )
            # Drop any differently-cased 'authorization' header a -H supplied
            # earlier (the -H loop ran before this block), so the OAuth token is
            # the single Authorization sent rather than a duplicate header pair.
            overridden = [k for k in headers if k.lower() == "authorization"]
            if overridden:
                # The user explicitly supplied -H 'Authorization: ...' AND an
                # OAuth flow — warn that the OAuth token wins, instead of
                # silently discarding their header.
                print(
                    "warning: explicit -H 'Authorization' header is overridden "
                    "by the OAuth-acquired token",
                    file=sys.stderr,
                )
            for existing in overridden:
                del headers[existing]
            headers["Authorization"] = f"Bearer {token_data.access_token}"
            token_refresher = _build_token_refresher(
                args.url, headers, args.timeout_connect, args.timeout_read
            )
            scope_upgrader = _build_scope_upgrader(
                args.url, headers, args.timeout_connect, args.timeout_read
            )
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
        )
        sys.exit(0 if ok else 1)

    # run() ignores sse_read_timeout (Streamable HTTP doesn't hold a
    # long-lived GET), so only pass it through on the SSE path.
    # tcp_keepalive, cancel_filter and normalize_arguments apply to both.
    tcp_keepalive = not args.no_tcp_keepalive
    cancel_filter = not args.no_cancel_filter
    normalize_arguments = not args.no_normalize_arguments
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
        )
