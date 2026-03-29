"""Command-line interface for mcp-stdio."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .relay import run


def _parse_header(header: str) -> tuple[str, str]:
    """Parse a header string 'Key: Value' into a tuple."""
    if ":" not in header:
        print(f"error: invalid header format (expected 'Key: Value'): {header}", file=sys.stderr)
        sys.exit(1)
    key, _, value = header.partition(":")
    return key.strip(), value.strip()


def main() -> None:
    """Entry point for mcp-stdio CLI."""
    parser = argparse.ArgumentParser(
        prog="mcp-stdio",
        description="Stdio-to-HTTP relay for MCP servers. "
        "Bridges Claude Desktop/Code (stdio) to remote Streamable HTTP MCP endpoints.",
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
        "-H",
        "--header",
        action="append",
        default=[],
        dest="headers",
        metavar="'Key: Value'",
        help="Custom header to send (can be specified multiple times)",
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
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args()

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

    run(
        url=args.url,
        headers=headers,
        timeout_connect=args.timeout_connect,
        timeout_read=args.timeout_read,
    )
