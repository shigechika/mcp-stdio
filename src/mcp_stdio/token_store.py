"""Persistent token storage for OAuth 2.1 credentials."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


_STORE_DIR = Path.home() / ".config" / "mcp-stdio"
_STORE_FILE = _STORE_DIR / "tokens.json"

# Legacy path (v0.3.0 and earlier)
_LEGACY_STORE_DIR = Path.home() / ".mcp-stdio"
_LEGACY_STORE_FILE = _LEGACY_STORE_DIR / "tokens.json"


@dataclass
class TokenData:
    """OAuth token data for a single MCP server."""

    access_token: str
    token_type: str = "Bearer"
    expires_at: float | None = None
    refresh_token: str | None = None
    scope: str | None = None
    # Dynamic client registration credentials
    client_id: str | None = None
    client_secret: str | None = None
    # Server endpoints (for refresh)
    token_endpoint: str = ""
    authorization_endpoint: str = ""
    registration_endpoint: str | None = None


def _ensure_store_dir() -> None:
    """Create the store directory with secure permissions."""
    _STORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


def _migrate_legacy_store() -> None:
    """Migrate tokens from ~/.mcp-stdio/ to ~/.config/mcp-stdio/ if needed."""
    if not _LEGACY_STORE_FILE.exists():
        return
    if _STORE_FILE.exists():
        # New file already exists — just remove legacy
        _LEGACY_STORE_FILE.unlink()
    else:
        _ensure_store_dir()
        _LEGACY_STORE_FILE.rename(_STORE_FILE)
        os.chmod(_STORE_FILE, stat.S_IRUSR | stat.S_IWUSR)
    # Remove legacy directory if empty
    try:
        _LEGACY_STORE_DIR.rmdir()
    except OSError:
        pass  # Not empty or already gone


def _read_store() -> dict[str, Any]:
    """Read the token store file."""
    _migrate_legacy_store()
    if not _STORE_FILE.exists():
        return {}
    try:
        return json.loads(_STORE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _write_store(data: dict[str, Any]) -> None:
    """Write the token store file with secure permissions."""
    _ensure_store_dir()
    _STORE_FILE.write_text(json.dumps(data, indent=2))
    os.chmod(_STORE_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0o600


def load_token(server_url: str) -> TokenData | None:
    """Load token data for a server URL.

    Returns None if no token is stored.
    """
    store = _read_store()
    entry = store.get(server_url)
    if entry is None:
        return None
    try:
        return TokenData(**entry)
    except TypeError:
        return None


def save_token(server_url: str, data: TokenData) -> None:
    """Save token data for a server URL."""
    store = _read_store()
    store[server_url] = asdict(data)
    _write_store(store)


def delete_token(server_url: str) -> None:
    """Delete token data for a server URL."""
    store = _read_store()
    if server_url in store:
        del store[server_url]
        _write_store(store)
