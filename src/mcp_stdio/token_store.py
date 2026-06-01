"""Persistent token storage for OAuth 2.1 credentials.

Concurrency: ``save_token`` / ``delete_token`` hold a best-effort advisory
file lock (``_store_lock``) across their read-modify-write so two mcp-stdio
processes updating distinct server keys merge instead of last-writer-wins.
The lock is real on POSIX (``fcntl``) and Windows (``msvcrt``); on a platform
exposing neither it degrades to a no-op and the lost-update race remains
possible (acquisition failures are non-fatal by design).
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import sys
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


_STORE_DIR = Path.home() / ".config" / "mcp-stdio"
_STORE_FILE = _STORE_DIR / "tokens.json"

# Legacy path (v0.3.0 and earlier)
_LEGACY_STORE_DIR = Path.home() / ".mcp-stdio"
_LEGACY_STORE_FILE = _LEGACY_STORE_DIR / "tokens.json"

# Default ports folded out when normalising a server URL into a store key.
_DEFAULT_PORTS = {"https": 443, "http": 80}

# O_NOFOLLOW (POSIX) makes os.open refuse a symlink at the final path component,
# so a symlink swapped in for the store/temp/lock file cannot redirect a write
# of secrets to an attacker-chosen target. 0 on platforms without it (Windows),
# where the parent dir's 0o700 mode is the primary guard anyway.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _normalize_key(server_url: str) -> str:
    """Normalise a server URL into a stable token-store key.

    Folds cosmetically-different spellings of the same endpoint — host case,
    an explicit default port (``:443`` / ``:80``), and trailing slashes on the
    path — to one key so they share a cached token instead of triggering a
    redundant OAuth flow. Only the *store key* is normalised; oauth.py still
    uses the operator-supplied URL verbatim for the RFC 8707 resource
    indicator, so end-to-end behaviour is unchanged. Anything that does not
    parse as http(s) with a host is returned unchanged.

    The query string is preserved (``/mcp?a=1`` and ``/mcp?a=2`` are distinct
    servers); userinfo is dropped (``.hostname``). Note that a server URL
    carrying secrets in its query would therefore place them in the store key
    inside ``tokens.json`` — that file is 0o600 and MCP endpoints normally have
    no query secrets, so this is not a disclosure vector beyond the tokens it
    already holds.
    """
    # ``urlsplit`` is lazy: ``.hostname`` / ``.port`` are what actually raise
    # ValueError on a malformed authority (e.g. a non-numeric or out-of-range
    # port), so the whole parse must sit inside the try to honour the
    # return-unchanged-on-failure contract.
    try:
        parsed = urlsplit(server_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return server_url
        host = parsed.hostname  # urlsplit lowercases the host and strips userinfo
        port = parsed.port
    except ValueError:
        return server_url
    # ``hostname`` strips the brackets from an IPv6 literal; re-add them so the
    # rebuilt netloc is a valid, re-parsable URL and ``[::1]:8443`` cannot
    # collide with another address whose final hextet equals a port.
    if ":" in host:
        host = f"[{host}]"
    if port is not None and port != _DEFAULT_PORTS.get(parsed.scheme):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, netloc, path, parsed.query, ""))


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
    # Token endpoint authentication method (RFC 6749 §2.3 / RFC 8414)
    token_endpoint_auth_method: str = "none"
    # Suppress RFC 8707 resource parameter (for AS that reject it, e.g. Entra ID v2)
    no_resource_indicator: bool = False


def _ensure_store_dir() -> None:
    """Create the store directory with secure permissions.

    ``mkdir``'s ``mode`` only applies on creation, so re-assert 0o700 in case
    the directory pre-existed with looser permissions (created earlier by
    another tool, or under a permissive umask).
    """
    _STORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(_STORE_DIR, stat.S_IRWXU)  # 0o700
    except OSError:
        pass


def _migrate_legacy_store() -> None:
    """Migrate tokens from ~/.mcp-stdio/ to ~/.config/mcp-stdio/ if needed."""
    if not _LEGACY_STORE_FILE.exists():
        return
    if _STORE_FILE.exists():
        # New file already exists — just remove legacy
        _LEGACY_STORE_FILE.unlink()
    else:
        _ensure_store_dir()
        # Tighten the legacy file's mode BEFORE moving it, so the secrets never
        # sit at the new XDG path with a looser (pre-0o600) mode, even briefly:
        # rename() preserves the source inode's permission bits.
        try:
            os.chmod(_LEGACY_STORE_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        try:
            _LEGACY_STORE_FILE.rename(_STORE_FILE)
            os.chmod(_STORE_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            # rename() can fail for two reasons:
            #  - EXDEV: the legacy and XDG paths are on different filesystems.
            #  - a concurrent migration (this runs unlocked from load_token)
            #    already moved the legacy file — racer A's rename() succeeded
            #    and unlinked the source, so racer B's rename() raises ENOENT.
            # Only copy-through when the target is still ABSENT and the legacy
            # file still has REAL data. Guarding on existence is what prevents
            # the catastrophe: without it, the ENOENT racer would read the now
            # gone legacy file as {} and _write_store({}) would clobber the
            # just-migrated store, silently destroying every cached token.
            if _STORE_FILE.exists() or not _LEGACY_STORE_FILE.exists():
                pass  # another process won the migration race — leave it intact
            else:
                try:
                    data = json.loads(_LEGACY_STORE_FILE.read_text())
                except (json.JSONDecodeError, OSError):
                    data = None
                # Never write an empty/failed read over the target.
                if isinstance(data, dict) and data:
                    _write_store(data)
                    try:
                        _LEGACY_STORE_FILE.unlink()
                    except OSError:
                        pass
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
    # Opportunistically tighten the file mode on read, mirroring the directory
    # re-chmod in _ensure_store_dir. _write_store always creates the file 0o600,
    # but a tokens.json that pre-exists with looser permissions (restored from a
    # backup that lost mode bits, copied under a permissive umask, or written by
    # a third-party tool) and is only ever read would otherwise keep its mode,
    # leaving the secrets readable.
    # Don't chmod through a symlink (would alter the link target's mode).
    try:
        if not _STORE_FILE.is_symlink():
            os.chmod(_STORE_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass
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
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW
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


@contextlib.contextmanager
def _store_lock() -> Iterator[None]:
    """Best-effort advisory exclusive lock around a read-modify-write.

    Serialises ``save_token`` / ``delete_token`` across concurrent mcp-stdio
    processes so updates to distinct server keys merge rather than clobbering
    each other (last-writer-wins). Uses ``fcntl`` on POSIX and ``msvcrt`` on
    Windows; if no primitive is available or acquisition fails, it proceeds
    without the lock (the operation must never be blocked by lock trouble).
    """
    _ensure_store_dir()
    # Derive the lock path from the current _STORE_DIR (not a module constant)
    # so test monkeypatching of _STORE_DIR redirects the lock file too.
    lock_path = _STORE_DIR / "tokens.json.lock"
    try:
        fd = os.open(
            lock_path,
            os.O_WRONLY | os.O_CREAT | _O_NOFOLLOW,
            stat.S_IRUSR | stat.S_IWUSR,
        )
    except OSError:
        yield
        return
    locked = False
    try:
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX)
            locked = True
        except (OSError, ImportError, ValueError):
            pass  # best-effort: fall back to an unsynchronised write
        yield
    finally:
        if locked and sys.platform == "win32":
            try:
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        os.close(fd)


def load_token(server_url: str) -> TokenData | None:
    """Load token data for a server URL.

    Returns None if no token is stored. Looks up the normalised key first,
    then the verbatim key so entries written by older versions (which used the
    raw URL as the key) are still found.
    """
    store = _read_store()
    entry = store.get(_normalize_key(server_url))
    if entry is None:
        entry = store.get(server_url)
    if entry is None:
        return None
    try:
        return TokenData(**entry)
    except TypeError:
        return None


def save_token(server_url: str, data: TokenData) -> None:
    """Save token data for a server URL."""
    with _store_lock():
        store = _read_store()
        key = _normalize_key(server_url)
        # Drop any stale entry stored under the un-normalised key by an older
        # version so the two spellings don't both linger.
        if server_url != key:
            store.pop(server_url, None)
        store[key] = asdict(data)
        _write_store(store)


def delete_token(server_url: str) -> None:
    """Delete token data for a server URL."""
    with _store_lock():
        store = _read_store()
        removed = False
        for key in {_normalize_key(server_url), server_url}:
            if key in store:
                del store[key]
                removed = True
        if removed:
            _write_store(store)
