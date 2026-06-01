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
import errno
import json
import math
import os
import stat
import sys
import threading
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

# O_NONBLOCK so opening the store path can never BLOCK if a FIFO was pre-planted
# there (an O_RDONLY open of a pipe blocks until a writer appears). It is a no-op
# for the regular file we expect; combined with the post-open fstat regular-file
# check it turns a special-file DoS into a clean refusal. 0 where unsupported.
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

# Set once if a server URL carrying embedded userinfo is normalized into a key,
# so the credential-sharing warning is emitted only once per process.
_warned_userinfo_key = False

# Set once if the advisory lock file could not be opened because a symlink was
# planted at its path (O_NOFOLLOW -> ELOOP). That silently disables
# cross-process serialization, so the operator gets one warning per process.
_warned_lock_symlink = False


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
    # #7 (round17): userinfo is dropped from the key, so two URLs differing ONLY
    # in embedded credentials (user:pass@) fold to the same slot and silently
    # share / overwrite one cached token. MCP endpoints normally carry no
    # userinfo, so this stays a deliberate fold — but warn ONCE so an operator
    # using embedded credentials is not surprised by the token sharing.
    if parsed.username or parsed.password:
        global _warned_userinfo_key
        if not _warned_userinfo_key:
            print(
                "mcp-stdio: warning: server URL contains embedded userinfo "
                "(user:pass@host); it is dropped from the token-store key, so "
                "URLs differing only in credentials share one cached token slot.",
                file=sys.stderr,
            )
            _warned_userinfo_key = True
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
    # RFC 8414 issuer identifier of the authorization server. Persisted so the
    # RFC 9207 `iss` mix-up check survives across invocations (e.g. a step-up
    # that reconstructs OAuthMetadata from this cached entry).
    issuer: str | None = None
    # Token endpoint authentication method (RFC 6749 §2.3 / RFC 8414)
    token_endpoint_auth_method: str = "none"
    # Suppress RFC 8707 resource parameter (for AS that reject it, e.g. Entra ID v2)
    no_resource_indicator: bool = False
    # RFC 9207 §3 authorization_response_iss_parameter_supported. Persisted so a
    # step-up that reconstructs OAuthMetadata from this cached entry can keep the
    # §2.4 missing-iss MUST-reject active instead of silently defaulting to off.
    iss_parameter_supported: bool = False


# Set once if we ever fail to tighten the store dir to 0o700 and detect it is
# still group/other-accessible, so the operator warning is emitted only once.
_warned_loose_store_dir = False


def _ensure_store_dir() -> None:
    """Create the store directory with secure permissions.

    ``mkdir``'s ``mode`` only applies on creation, so re-assert 0o700 in case
    the directory pre-existed with looser permissions (created earlier by
    another tool, or under a permissive umask).
    """
    global _warned_loose_store_dir
    _STORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(_STORE_DIR, stat.S_IRWXU)  # 0o700
    except OSError:
        # #10 (round16): the chmod can genuinely fail (a dir owned by another
        # uid after a botched restore, some network mounts). The token file is
        # still written 0o600 so the secret bytes stay protected, but a loose
        # store DIR widens the listing/symlink-swap surface. Fail closed but
        # surface it ONCE so an operator on a problem filesystem is not blind to
        # it — silence here previously hid a persistently world-readable dir.
        if not _warned_loose_store_dir:
            try:
                mode = stat.S_IMODE(os.stat(_STORE_DIR).st_mode)
                if mode & (stat.S_IRWXG | stat.S_IRWXO):
                    print(
                        f"mcp-stdio: warning: could not tighten {_STORE_DIR} to "
                        f"0o700 (current mode {mode:#o}); cached tokens' directory "
                        f"is group/other-accessible.",
                        file=sys.stderr,
                    )
                    _warned_loose_store_dir = True
            except OSError:
                pass


def _read_legacy_data() -> dict[str, Any] | None:
    """Read the legacy token file via ``O_NOFOLLOW``.

    Returns the parsed dict, or ``None`` if the file is absent, unreadable,
    not valid JSON, or not a JSON object — so callers never write garbage (or
    an attacker-redirected symlink target) over the XDG store.
    """
    try:
        fd = os.open(_LEGACY_STORE_FILE, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
    except OSError:
        return None
    # Refuse a non-regular legacy file the same way _read_store does (#2
    # round27): O_NOFOLLOW blocks a symlink, but an O_RDONLY read of a
    # writer-less FIFO planted at the legacy path would block forever and hang
    # every token load / relay startup. O_NONBLOCK makes the open return at
    # once (a no-op for the regular file we expect); fstat then rejects the
    # special file before f.read() can hang on it.
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
    except OSError:
        os.close(fd)
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            data = json.loads(f.read())
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _migrate_legacy_store() -> None:
    """Migrate tokens from ~/.mcp-stdio/ to ~/.config/mcp-stdio/ if needed.

    NOTE: this runs from ``_read_store`` and therefore from ``load_token``,
    which is UNLOCKED (documented read-only). The EXDEV/ENOENT copy-through
    branch below performs a real ``_write_store`` *without* ``_store_lock``,
    so the module's lock-serialised RMW contract has one exception: during the
    one-time legacy-migration window a load-side copy-through can race a
    concurrent ``save_token`` and one ``os.replace`` wins (each write is still
    atomic — no torn file — and the existence guard prevents the empty-dict
    clobber). After migration completes the legacy file is gone and this path
    is never taken again.
    """
    if not _LEGACY_STORE_FILE.exists():
        return
    if _STORE_FILE.exists():
        # The XDG store exists — but only discard the legacy copy once it is
        # confirmed to hold usable data. A 0-byte / unreadable _STORE_FILE (an
        # interrupted external write, a stray `touch`, a backup restore that
        # left an empty placeholder) is NOT proof the migration completed;
        # unlinking the legacy file then would silently lose still-real tokens.
        try:
            xdg_has_data = _STORE_FILE.stat().st_size > 0
        except OSError:
            xdg_has_data = False
        if xdg_has_data:
            # Best-effort removal of the now-redundant legacy file. This runs
            # UNLOCKED from load_token, so the unlink can lose a TOCTOU race
            # against a concurrent migration (ENOENT) or hit a read-only /
            # permission-locked legacy FS. Neither must crash a read of the
            # already-migrated store, so guard it like every other fs op here.
            try:
                _LEGACY_STORE_FILE.unlink()
            except OSError:
                pass
        else:
            # #8 (round16): the XDG store is an EMPTY placeholder (a stray
            # `touch`, an interrupted external write, a backup restore) that
            # otherwise shadows still-valid legacy tokens forever — _read_store
            # would read {} and load_token would force a needless re-auth. Copy
            # the legacy data through into the placeholder instead of stranding
            # it. Re-stat under the same call so a placeholder that CONCURRENTLY
            # gained real data (a locked save_token) is never clobbered; the
            # residual TOCTOU is the documented one-time migration race above.
            data = _read_legacy_data()
            if data:
                try:
                    if _STORE_FILE.stat().st_size == 0:
                        _write_store(data)
                        try:
                            _LEGACY_STORE_FILE.unlink()
                        except OSError:
                            pass
                except Exception:
                    # Unlocked read path: a failed stat/write must never crash
                    # the read — leave the legacy file for a later run to retry.
                    # Catch Exception, not just OSError (#C-3 round28): _write_store
                    # runs json.dumps before its inner try, mirroring the widened
                    # save_token/delete_token contract. `data` is json.loads output
                    # so a non-OSError is unreachable today, but the symmetry keeps
                    # a future caller's non-serializable value from crashing a read.
                    pass
    else:
        _ensure_store_dir()
        # #9 (round16): re-assert 0o700 on the legacy DIR before exposing the
        # secrets to a rename/copy-through, mirroring _ensure_store_dir's
        # defensive re-chmod of the XDG dir. An older version (or permissive
        # umask) may have created ~/.mcp-stdio/ group/other-readable; if the
        # migration then fails partway the legacy tokens.json keeps living in a
        # loose-mode dir. Best-effort — the 0o600 file mode is the primary guard.
        try:
            os.chmod(_LEGACY_STORE_DIR, stat.S_IRWXU)  # 0o700
        except OSError:
            pass
        # #1 (round27): before moving the legacy file into the TRUSTED XDG store
        # path, confirm it is a REGULAR file via an O_NOFOLLOW-anchored fd.
        # Path.rename moves a SYMLINK itself, so a symlink planted at the legacy
        # path (a dotfile manager like GNU Stow, a backup/restore — not
        # necessarily an attacker) would otherwise land at
        # ~/.config/mcp-stdio/tokens.json, after which every O_NOFOLLOW read
        # ELOOPs and save/delete abort forever — a permanent token-cache DoS.
        # Open with O_NOFOLLOW (refuses a symlink: ELOOP) + O_NONBLOCK (so a FIFO
        # cannot block the open), fstat for S_ISREG, and fchmod through that fd
        # (a path-based chmod would FOLLOW a symlink and 0o600 an attacker /
        # user-chosen target). A non-regular / symlinked legacy file is left
        # untouched — never followed into the store. The residual TOCTOU between
        # this check and the path-based rename below is bounded by the legacy
        # dir's 0o700 mode (re-asserted just above), so only the owning user
        # could swap the inode, which is the self-induced dotfile-manager case.
        legacy_is_regular = False
        try:
            _lfd = os.open(
                _LEGACY_STORE_FILE, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK
            )
        except OSError:
            _lfd = -1
        if _lfd >= 0:
            try:
                legacy_is_regular = stat.S_ISREG(os.fstat(_lfd).st_mode)
            except OSError:
                legacy_is_regular = False
            if legacy_is_regular:
                # Tighten the mode BEFORE moving it, so the secrets never sit at
                # the new XDG path with a looser (pre-0o600) mode even briefly:
                # rename() preserves the source inode's permission bits. fchmod
                # is anchored to the fd, so it cannot follow a swapped-in symlink.
                _fchmod = getattr(os, "fchmod", None)
                if _fchmod is not None:
                    try:
                        _fchmod(_lfd, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
                    except OSError:
                        pass
            os.close(_lfd)
        if not legacy_is_regular:
            # Symlink / FIFO / device / vanished legacy file — do not rename or
            # copy it into the trusted store. Leave it in place; the XDG store
            # stays absent so load_token returns None (a clean re-auth).
            return
        try:
            _LEGACY_STORE_FILE.rename(_STORE_FILE)
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
                # Read the legacy file via O_NOFOLLOW (see _read_legacy_data) so
                # a symlink swapped in at the legacy path cannot redirect the
                # copy-through to read an attacker-chosen file.
                data = _read_legacy_data()
                # Never write an empty/failed read over the target.
                if data:
                    written = False
                    try:
                        _write_store(data)
                        written = True
                    except Exception:
                        # This copy-through runs UNLOCKED from load_token. A
                        # failed write (disk full, read-only FS, permission) must
                        # NOT propagate out and crash the read — leave the legacy
                        # file intact for a later run to retry the migration.
                        # Catch Exception, not just OSError (#C-3 round28), to match
                        # the widened save_token/delete_token soft-fail contract.
                        pass
                    if written:
                        try:
                            _LEGACY_STORE_FILE.unlink()
                        except OSError:
                            pass
        else:
            # rename() succeeded — re-assert 0o600 on the moved inode as a
            # belt-and-suspenders step (the line-143 pre-tighten already set
            # it). This is in its OWN guard, not the rename try, so a chmod
            # failure here is not misread as a rename/EXDEV failure and routed
            # into the copy-through recovery above.
            try:
                os.chmod(_STORE_FILE, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
    # Remove legacy directory if empty
    try:
        _LEGACY_STORE_DIR.rmdir()
    except OSError:
        pass  # Not empty or already gone


class _StoreUnreadable(Exception):
    """The store file exists but could not be READ (permission / symlink /
    I/O error) — distinct from 'absent' (→ {}) and 'corrupt JSON' (which is
    overwrite-safe). A writer must ABORT on this rather than clobber a store
    whose real contents it never saw, which would destroy every other
    server's tokens.
    """


def _read_store(*, for_write: bool = False) -> dict[str, Any]:
    """Read the token store file.

    Returns ``{}`` when the store is absent / genuinely empty. On the READ
    path any failure also degrades to ``{}`` (load_token tolerates that). On the
    WRITE path (``for_write=True``) a read failure raises ``_StoreUnreadable``
    so the caller aborts instead of overwriting a store it could not read — a
    transient EACCES, an ELOOP from a swapped-in symlink, or a backup-restore
    race would otherwise let the next save persist ONLY its one key and wipe
    every other server's cached token. A corrupt-JSON store stays overwrite-safe
    (``{}``), preserving the intentional corrupt-store-replacement behaviour.
    """
    _migrate_legacy_store()
    if not _STORE_FILE.exists():
        return {}
    # Opportunistically tighten the file mode on read, mirroring the directory
    # re-chmod in _ensure_store_dir. _write_store always creates the file 0o600,
    # but a tokens.json that pre-exists with looser permissions (restored from a
    # backup that lost mode bits, copied under a permissive umask, or written by
    # a third-party tool) and is only ever read would otherwise keep its mode,
    # leaving the secrets readable.
    #
    # Open with O_NOFOLLOW first: it refuses a symlink atomically (ELOOP), and
    # the resulting fd anchors BOTH the chmod (via fchmod) and the read to the
    # same inode — eliminating the stat-then-chmod-then-read TOCTOU window of a
    # path-based sequence. _O_NOFOLLOW is 0 where unsupported (Windows), where
    # NTFS ACLs govern access anyway.
    try:
        fd = os.open(_STORE_FILE, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
    except OSError as e:
        # The file EXISTS but we could not open it: ELOOP (a symlink swapped
        # in — refused), EACCES, or a transient I/O error. On the write path
        # this must NOT degrade to {} (which a save would then clobber over the
        # unread store); raise so the caller aborts.
        #
        # ENOENT is the exception (#9 round17): the file vanished in the TOCTOU
        # window between the exists() check above and this open (a concurrent
        # migration unlink, or an external tool). A vanished file is semantically
        # ABSENT, not unreadable — return {} so the write proceeds from a clean
        # slate, instead of aborting the save with a misleading "could not be
        # read" warning. There is nothing to clobber.
        if for_write and e.errno != errno.ENOENT:
            raise _StoreUnreadable(str(e)) from e
        return {}
    # #10 (round25): O_NOFOLLOW refuses a SYMLINK but not a FIFO / device node /
    # other special file pre-planted at the store path. A named pipe would make
    # the f.read() below BLOCK forever (no writer), hanging every load/save and
    # the relay startup. Refuse a non-regular file via the fd we already hold:
    # absent-like on read ({}), and _StoreUnreadable on write so a save never
    # clobbers (or hangs on) an unread special file.
    try:
        is_regular = stat.S_ISREG(os.fstat(fd).st_mode)
    except OSError as e:
        os.close(fd)
        if for_write:
            raise _StoreUnreadable(str(e)) from e
        return {}
    if not is_regular:
        os.close(fd)
        if for_write:
            raise _StoreUnreadable("token store path is not a regular file")
        return {}
    try:
        _fchmod = getattr(os, "fchmod", None)
        if _fchmod is not None:
            try:
                _fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0o600, fd-anchored
            except OSError:
                pass  # best-effort tighten
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        # Opened but the read itself failed — same trust problem as open failure.
        if for_write:
            raise _StoreUnreadable(str(e)) from e
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Genuinely corrupt JSON is overwrite-safe (the contents are unusable);
        # both read and write paths treat it as an empty store.
        return {}
    return data if isinstance(data, dict) else {}


def _write_store(data: dict[str, Any]) -> None:
    """Write the token store file atomically with secure permissions.

    Uses a temp file created with 0o600 from the start (no umask window),
    then atomically renames it over the target file so a crash mid-write
    cannot corrupt existing tokens. After the rename the parent directory is
    fsynced so the directory entry change is itself durable across a power
    loss (the file data fsync alone does not guarantee the rename survives).

    Note (#11 round22): a HARD kill (SIGKILL / power loss / OOM) between the temp
    file's creation and the os.replace leaves an orphaned ``tokens.json.tmp.*``
    sibling (0o600) that is never swept. This is accepted as harmless: the real
    store is untouched (os.replace is atomic), the unique random suffix prevents
    any collision with a future write, and the bytes stay 0o600. No per-write
    directory scan is done to reclaim them — that cost is not worth paying on the
    hot path for a leak that only a hard crash can produce.
    """
    _ensure_store_dir()
    # sort_keys for stable, diff-friendly on-disk output (#8 round17): without it
    # the per-server key order follows dict-insertion order and churns across the
    # read-modify-write saves, complicating inspection/diffing for no benefit.
    payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    # Per-write unique temp name. PID alone is not enough: when the advisory
    # lock degrades to a no-op (lock fs unavailable), two THREADS in one process
    # share the PID and would otherwise pick the same temp path and clobber each
    # other's in-flight write. Thread id + random make every temp file distinct,
    # leaving only the documented os.replace last-writer-wins on the final file.
    uniq = f"{os.getpid()}.{threading.get_ident()}.{os.urandom(4).hex()}"
    tmp_path = _STORE_FILE.with_suffix(_STORE_FILE.suffix + f".tmp.{uniq}")
    # O_EXCL: the random temp name should never pre-exist; if it somehow does
    # (a stale temp or a planted file/symlink), fail rather than open/truncate
    # it. With O_EXCL the kernel also refuses a symlink at the path, so the temp
    # write can never be redirected. (O_NOFOLLOW is kept for platforms where it
    # adds protection independent of O_EXCL.)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW
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
    # Make the rename durable. Best-effort: some platforms/filesystems reject a
    # directory fsync, and opening a directory fails on Windows — neither should
    # fail the write.
    try:
        dir_fd = os.open(str(_STORE_DIR), os.O_RDONLY | _O_NOFOLLOW)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


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
    except OSError as e:
        # A symlink planted at the lock path (O_NOFOLLOW -> ELOOP) silently
        # disables cross-process serialization — distinct from a benign
        # read-only / missing-dir failure that just degrades to a no-op lock.
        # Warn ONCE so the operator can notice the advisory-lock DoS, then
        # proceed unlocked (a lock failure must never block the save). The dir's
        # 0o700 mode is the primary guard against another user planting it.
        if e.errno == errno.ELOOP:
            global _warned_lock_symlink
            if not _warned_lock_symlink:
                _warned_lock_symlink = True
                print(
                    f"warning: token store lock path {lock_path} is a symlink "
                    f"(refused via O_NOFOLLOW); proceeding without cross-process "
                    f"locking — concurrent saves may last-writer-wins",
                    file=sys.stderr,
                )
        yield
        return
    # #9 (round19): the 0o600 mode above applies only on CREATION. Re-tighten a
    # pre-existing lock file via the fd (fchmod, anchored to this inode like
    # _read_store) so a lock file left group/other-writable — e.g. pre-planted by
    # a local user once the dir-tightening already failed — cannot become the
    # handle another user holds LOCK_EX on to stall every save_token. Best-effort:
    # the dir's 0o700 mode is the primary guard and a chmod failure must not block.
    _fchmod = getattr(os, "fchmod", None)
    if _fchmod is not None:
        try:
            _fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0o600, fd-anchored
        except OSError:
            pass
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
        td = TokenData(**entry)
    except TypeError:
        # Unexpected / missing keyword names (schema-shape drift, e.g. a field
        # added by a newer version). Degrade to None → re-auth.
        return None
    # A dataclass __init__ does NO value-type checking, so a corrupted store
    # (partially overwritten, truncated-then-rewritten by another tool, or a
    # bad backup restore) can yield a structurally-valid-but-type-broken entry.
    # The comparison-critical numerics would then crash ensure_token (e.g.
    # `expires_at > time.time()` on a str). Validate the load-bearing fields and
    # degrade to None rather than propagate a TypeError up the OAuth path.
    if not isinstance(td.access_token, str) or not td.access_token:
        return None
    # #9 (round23): bool is an int SUBCLASS in Python, so a corrupted
    # ``true``/``false`` in the JSON would pass an isinstance(..., (int, float))
    # check and reach ensure_token as 1/0 — a nonsensical 1970-epoch expiry.
    # Reject bool explicitly so it degrades to re-auth instead of a bogus expiry.
    # #11 (round25): json.loads parses the literals NaN / Infinity / -Infinity by
    # default, which pass isinstance(..., float) but poison the `expires_at >
    # time.time()` comparison — inf reads as never-expiring (the token is trusted
    # forever and refresh never fires), NaN as always-expired. Reject non-finite
    # values via math.isfinite so a hand-edited / third-party-written store
    # degrades to a clean re-auth.
    if td.expires_at is not None and (
        isinstance(td.expires_at, bool)
        or not isinstance(td.expires_at, (int, float))
        or not math.isfinite(td.expires_at)
    ):
        return None
    if td.client_secret_expires_at is not None and (
        isinstance(td.client_secret_expires_at, bool)
        or not isinstance(td.client_secret_expires_at, (int, float))
        or not math.isfinite(td.client_secret_expires_at)
    ):
        return None
    # The string fields are consumed via .split() (scope) or sent verbatim in
    # request bodies / headers; a non-string value from a corrupted store would
    # crash the OAuth path (e.g. cached.scope.split() on an int). Reject a
    # type-broken value rather than propagate the crash.
    for field in (
        "token_type",
        "refresh_token",
        "scope",
        "client_id",
        "client_secret",
        "token_endpoint",
        "authorization_endpoint",
        "registration_endpoint",
        "issuer",
        "token_endpoint_auth_method",
    ):
        value = getattr(td, field)
        if value is not None and not isinstance(value, str):
            return None
    if not isinstance(td.no_resource_indicator, bool):
        return None
    # #10 (round22): iss_parameter_supported is SECURITY-load-bearing — it gates
    # the RFC 9207 §2.4 missing-iss MUST-reject on the step-up cache-hit path. A
    # corrupted store flipping it to a non-bool (or a truthy string that reads as
    # enabled, or a 0 that reads as disabled) must degrade to None / re-auth, not
    # silently mis-set the defence. Validate it like no_resource_indicator.
    if not isinstance(td.iss_parameter_supported, bool):
        return None
    return td


def save_token(server_url: str, data: TokenData) -> None:
    """Save token data for a server URL."""
    with _store_lock():
        try:
            store = _read_store(for_write=True)
        except _StoreUnreadable as e:
            # The store exists but we could not read it — writing now would
            # persist only this one key and destroy every other server's token.
            # Skip the save (the token is simply not cached; the caller re-auths
            # next time) rather than corrupt the store.
            print(
                f"warning: token store exists but could not be read ({e}); "
                f"not saving to avoid overwriting other servers' tokens",
                file=sys.stderr,
            )
            return
        key = _normalize_key(server_url)
        # Drop any stale entry stored under the un-normalised key by an older
        # version so the two spellings don't both linger.
        if server_url != key:
            store.pop(server_url, None)
        store[key] = asdict(data)
        try:
            _write_store(store)
        except Exception as e:
            # #4 (round21): a write failure (full / read-only FS, permission)
            # must fail SOFT, mirroring the _StoreUnreadable read path above. The
            # token is simply not cached — the caller re-auths next time — rather
            # than the OSError propagating up the OAuth/relay path. This also fixes
            # a worse case: a refresh whose save fails would otherwise propagate
            # out of refresh_cached_token and make the relay emit an auth error
            # even though the freshly refreshed token was perfectly usable.
            # #12 (round26): catch Exception, not just OSError — _write_store's
            # json.dumps runs before its inner try, so a non-serializable value
            # injected upstream raises ValueError/TypeError that would otherwise
            # bypass this soft-fail contract and crash the relay mid-session.
            print(
                f"warning: could not write token store ({e}); token not cached, "
                f"will re-authenticate next time",
                file=sys.stderr,
            )


def delete_token(server_url: str) -> None:
    """Delete token data for a server URL."""
    with _store_lock():
        try:
            store = _read_store(for_write=True)
        except _StoreUnreadable as e:
            # Same reasoning as save_token: never write over a store we could
            # not read. The targeted entry stays (a stale token at worst), the
            # other servers' tokens are preserved.
            print(
                f"warning: token store exists but could not be read ({e}); "
                f"not deleting to avoid overwriting other servers' tokens",
                file=sys.stderr,
            )
            return
        removed = False
        for key in {_normalize_key(server_url), server_url}:
            if key in store:
                del store[key]
                removed = True
        if removed:
            try:
                _write_store(store)
            except Exception as e:
                # Fail soft like save_token (#4 round21, #12 round26): a failed
                # delete leaves the (stale) entry in place — a stale cached token
                # at worst — rather than propagating up the caller. Catch
                # Exception so a non-OSError from _write_store's pre-try
                # json.dumps also degrades. A later successful write reconciles.
                print(
                    f"warning: could not write token store ({e}); "
                    f"token not deleted",
                    file=sys.stderr,
                )
