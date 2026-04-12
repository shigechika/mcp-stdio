"""Command-line interface for mcp-stdio."""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Callable

import httpx

from . import __version__
from .relay import check_connection, log, run, run_sse


def _parse_header(header: str) -> tuple[str, str]:
    """Parse a header string 'Key: Value' into a tuple."""
    if ":" not in header:
        print(
            f"error: invalid header format (expected 'Key: Value'): {header}",
            file=sys.stderr,
        )
        sys.exit(1)
    key, _, value = header.partition(":")
    return key.strip(), value.strip()


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
        from .oauth import refresh_access_token
        from .token_store import load_token, save_token

        cached = load_token(server_url)
        if not cached or not cached.refresh_token or not cached.token_endpoint:
            return None

        client = httpx.Client(
            timeout=httpx.Timeout(
                connect=timeout_connect, read=timeout_read, write=30, pool=10
            )
        )
        try:
            raw = refresh_access_token(
                cached.token_endpoint,
                cached.client_id or "",
                cached.client_secret,
                cached.refresh_token,
                client,
            )
            # Update stored token
            cached.access_token = raw["access_token"]
            if "refresh_token" in raw:
                cached.refresh_token = raw["refresh_token"]
            if "expires_in" in raw:
                cached.expires_at = time.time() + raw["expires_in"]
            save_token(server_url, cached)

            new_headers = dict(headers)
            new_headers["Authorization"] = f"Bearer {cached.access_token}"
            log("token refreshed successfully")
            return new_headers
        except Exception as e:
            log(f"token refresh failed: {e}")
            return None
        finally:
            client.close()

    return refresher


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
        "--test",
        action="store_true",
        help="Test connection to the MCP server and exit",
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
        except Exception as e:
            print(f"error: OAuth authentication failed: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            client.close()

    if args.test:
        ok = check_connection(
            url=args.url,
            headers=headers,
            timeout_connect=args.timeout_connect,
            timeout_read=args.timeout_read,
        )
        sys.exit(0 if ok else 1)

    relay_fn = run_sse if args.transport == "sse" else run
    relay_fn(
        url=args.url,
        headers=headers,
        timeout_connect=args.timeout_connect,
        timeout_read=args.timeout_read,
        token_refresher=token_refresher,
    )
