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
    client_secret_expires_at: float | None = None  # RFC 7591 §3.2.1; None = no expiry
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
    """Write the token store file atomically with secure permissions.

    Uses a temp file created with 0o600 from the start (no umask window),
    then atomically renames it over the target file so a crash mid-write
    cannot corrupt existing tokens.
    """
    _ensure_store_dir()
    payload = json.dumps(data, indent=2).encode("utf-8")
    tmp_path = _STORE_FILE.with_suffix(_STORE_FILE.suffix + f".tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp_path, flags, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, _STORE_FILE)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


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
