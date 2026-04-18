"""Command-line interface for mcp-stdio."""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Callable

import httpx

from . import __version__
from .relay import check_connection, log, run, run_sse

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
            )
        )
        try:
            data = refresh_cached_token(server_url, client)
            if data is None:
                return None
            new_headers = dict(headers)
            new_headers["Authorization"] = f"Bearer {data.access_token}"
            return new_headers
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
            )
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
        default=os.environ.get("MCP_BEARER_TOKEN", ""),
        help="Bearer token for authentication (or set MCP_BEARER_TOKEN env var)",
    )
    parser.add_argument(
        "--oauth",
        action="store_true",
        help="Enable OAuth 2.1 authentication (triggers browser flow if needed)",
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("MCP_OAUTH_CLIENT_ID", ""),
        help="Pre-registered OAuth client ID (or set MCP_OAUTH_CLIENT_ID env var)",
    )
    parser.add_argument(
        "--oauth-scope",
        default="",
        help="OAuth scope to request",
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
        type=float,
        default=10,
        help="Connection timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--timeout-read",
        type=float,
        default=120,
        help="Read timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--sse-read-timeout",
        type=float,
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

    if args.oauth and args.bearer_token:
        print(
            "error: --oauth and --bearer-token are mutually exclusive",
            file=sys.stderr,
        )
        sys.exit(1)

    # Build headers
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if args.bearer_token:
        headers["Authorization"] = f"Bearer {args.bearer_token}"
    for h in args.headers:
        key, value = _parse_header(h)
        headers[key] = value

    # OAuth flow (before relay starts)
    token_refresher: Callable[[], dict[str, str] | None] | None = None
    scope_upgrader: Callable[[str], dict[str, str] | None] | None = None
    if args.oauth:
        from .oauth import ensure_token

        client = httpx.Client(
            timeout=httpx.Timeout(
                connect=args.timeout_connect,
                read=args.timeout_read,
                write=30,
                pool=10,
            )
        )
        try:
            token_data = ensure_token(
                args.url,
                client,
                client_id=args.client_id or None,
                scope=args.oauth_scope or None,
            )
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
        )
        sys.exit(0 if ok else 1)

    # run() ignores sse_read_timeout (Streamable HTTP doesn't hold a
    # long-lived GET), so only pass it through on the SSE path.
    # tcp_keepalive applies to both transports.
    tcp_keepalive = not args.no_tcp_keepalive
    if args.transport == "sse":
        run_sse(
            url=args.url,
            headers=headers,
            timeout_connect=args.timeout_connect,
            timeout_read=args.timeout_read,
            sse_read_timeout=args.sse_read_timeout,
            tcp_keepalive=tcp_keepalive,
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
            token_refresher=token_refresher,
            scope_upgrader=scope_upgrader,
        )
