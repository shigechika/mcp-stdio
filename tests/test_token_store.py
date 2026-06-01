"""Tests for mcp_stdio.token_store module."""

import errno
import json
import os
import stat
import sys
import threading

import pytest

from mcp_stdio.token_store import (
    TokenData,
    _normalize_key,
    delete_token,
    load_token,
    save_token,
)


class TestTokenData:
    def test_defaults(self):
        t = TokenData(access_token="abc")
        assert t.access_token == "abc"
        assert t.token_type == "Bearer"
        assert t.expires_at is None
        assert t.refresh_token is None

    def test_full(self):
        t = TokenData(
            access_token="abc",
            token_type="Bearer",
            expires_at=1234567890.0,
            refresh_token="ref",
            scope="read write",
            client_id="cid",
            client_secret="csec",
            token_endpoint="https://example.com/token",
            authorization_endpoint="https://example.com/authorize",
            registration_endpoint="https://example.com/register",
        )
        assert t.client_id == "cid"
        assert t.scope == "read write"


class TestLoadSaveDelete:
    def test_save_and_load(self, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        data = TokenData(
            access_token="tok123",
            refresh_token="ref456",
            expires_at=9999999999.0,
            token_endpoint="https://example.com/token",
            authorization_endpoint="https://example.com/authorize",
        )
        save_token("https://example.com/mcp", data)

        loaded = load_token("https://example.com/mcp")
        assert loaded is not None
        assert loaded.access_token == "tok123"
        assert loaded.refresh_token == "ref456"

    def test_load_missing(self, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        assert load_token("https://nonexistent.com/mcp") is None

    def test_delete(self, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        save_token("https://example.com/mcp", TokenData(access_token="tok"))
        delete_token("https://example.com/mcp")
        assert load_token("https://example.com/mcp") is None

    def test_delete_nonexistent(self, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        # Should not raise
        delete_token("https://nonexistent.com/mcp")

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX mode bits don't model the NTFS ACL Windows uses for access control",
    )
    def test_file_permissions(self, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        save_token("https://example.com/mcp", TokenData(access_token="tok"))
        mode = os.stat(store_file).st_mode
        assert mode & stat.S_IRWXG == 0  # no group access
        assert mode & stat.S_IRWXO == 0  # no other access

    def test_multiple_servers(self, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        save_token("https://a.com/mcp", TokenData(access_token="tok-a"))
        save_token("https://b.com/mcp", TokenData(access_token="tok-b"))

        assert load_token("https://a.com/mcp").access_token == "tok-a"
        assert load_token("https://b.com/mcp").access_token == "tok-b"

    def test_corrupt_file(self, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        store_file.write_text("not json")
        assert load_token("https://example.com/mcp") is None

    def test_save_survives_unavailable_dir_fsync(self, tmp_path, monkeypatch):
        """The post-rename parent-dir fsync is best-effort — a platform that
        rejects it (e.g. Windows) must not fail the save."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        real_open = os.open

        def open_no_dir_fsync(path, flags, *a, **k):
            # Reject opening the directory (the dir-fsync path), allow the rest.
            if os.path.isdir(path):
                raise OSError("directory fsync unsupported")
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr("mcp_stdio.token_store.os.open", open_no_dir_fsync)
        save_token("https://example.com/mcp", TokenData(access_token="t"))
        monkeypatch.setattr("mcp_stdio.token_store.os.open", real_open)
        assert load_token("https://example.com/mcp").access_token == "t"

    def test_temp_file_name_is_unique_per_write(self, tmp_path, monkeypatch):
        """#8: each write uses a distinct temp file name so two writers sharing a
        PID (the unlocked-lock fallback) cannot collide on the same temp path."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        temp_names: list[str] = []
        real_open = os.open

        def spy_open(path, flags, *a, **k):
            p = os.fspath(path)
            if ".tmp." in p:
                temp_names.append(p)
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr("mcp_stdio.token_store.os.open", spy_open)
        save_token("https://a.com/mcp", TokenData(access_token="a"))
        save_token("https://b.com/mcp", TokenData(access_token="b"))
        monkeypatch.setattr("mcp_stdio.token_store.os.open", real_open)

        assert len(temp_names) == 2
        assert temp_names[0] != temp_names[1]  # distinct temp path per write

    def test_load_unknown_future_field_returns_none(self, tmp_path, monkeypatch):
        """Forward-compat: an entry written by a newer version carrying a field
        this version doesn't know must degrade to None, not raise."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        store_file.write_text(
            '{"https://example.com/mcp": '
            '{"access_token": "t", "unknown_future_field": 1}}'
        )
        assert load_token("https://example.com/mcp") is None

    def test_load_value_type_corruption_returns_none(self, tmp_path, monkeypatch):
        """#6: a structurally-valid entry with wrong VALUE types (e.g. a string
        expires_at from a truncated/overwritten store) must degrade to None, not
        crash ensure_token's `expires_at > time.time()` comparison later."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        store_file.write_text(
            '{"https://example.com/mcp": '
            '{"access_token": "t", "expires_at": "soon"}}'
        )
        assert load_token("https://example.com/mcp") is None

    def test_load_non_string_access_token_returns_none(self, tmp_path, monkeypatch):
        """A corrupted access_token (wrong type) must not produce a usable token."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        store_file.write_text(
            '{"https://example.com/mcp": {"access_token": ["x"]}}'
        )
        assert load_token("https://example.com/mcp") is None

    def test_load_non_string_scope_returns_none(self, tmp_path, monkeypatch):
        """#6(round13): a non-string scope (corrupted store) must degrade to None
        — otherwise cached.scope.split() crashes the step-up path."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        store_file.write_text(
            '{"https://example.com/mcp": {"access_token": "t", "scope": 123}}'
        )
        assert load_token("https://example.com/mcp") is None

    def test_load_non_string_token_endpoint_returns_none(self, tmp_path, monkeypatch):
        """A non-string endpoint/credential field likewise degrades to None."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        store_file.write_text(
            '{"https://example.com/mcp": '
            '{"access_token": "t", "token_endpoint": ["x"]}}'
        )
        assert load_token("https://example.com/mcp") is None

    def test_save_over_corrupt_store_succeeds(self, tmp_path, monkeypatch):
        """A corrupt store file is replaced (not appended to) on the next save."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        store_file.write_text("not json")
        save_token("https://example.com/mcp", TokenData(access_token="fresh"))
        loaded = load_token("https://example.com/mcp")
        assert loaded is not None and loaded.access_token == "fresh"

    def test_save_aborts_when_store_unreadable(self, tmp_path, monkeypatch, capsys):
        """#3: if the store EXISTS but cannot be read (e.g. transient EACCES),
        a save must ABORT rather than clobber it with a single-key payload that
        destroys every other server's token."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        save_token("https://a.com/mcp", TokenData(access_token="tok-a"))
        save_token("https://b.com/mcp", TokenData(access_token="tok-b"))

        real_open = os.open

        def fail_store_read(path, flags, *a, **k):
            # Fail only the read-open of the store file; allow lock + temp writes.
            is_read = flags & (os.O_WRONLY | os.O_RDWR) == 0
            if is_read and os.fspath(path) == os.fspath(store_file):
                raise PermissionError(13, "store momentarily locked")
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr("mcp_stdio.token_store.os.open", fail_store_read)
        save_token("https://c.com/mcp", TokenData(access_token="tok-c"))  # must abort
        monkeypatch.setattr("mcp_stdio.token_store.os.open", real_open)

        # The pre-existing tokens survive; the unreadable-time save was skipped.
        assert load_token("https://a.com/mcp").access_token == "tok-a"
        assert load_token("https://b.com/mcp").access_token == "tok-b"
        assert load_token("https://c.com/mcp") is None
        assert "could not be read" in capsys.readouterr().err

    def test_delete_aborts_when_store_unreadable(
        self, tmp_path, monkeypatch, capsys
    ):
        """#3: delete must likewise abort on an unreadable store rather than
        overwrite it and lose the other servers' tokens."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        save_token("https://a.com/mcp", TokenData(access_token="tok-a"))
        save_token("https://b.com/mcp", TokenData(access_token="tok-b"))

        real_open = os.open

        def fail_store_read(path, flags, *a, **k):
            is_read = flags & (os.O_WRONLY | os.O_RDWR) == 0
            if is_read and os.fspath(path) == os.fspath(store_file):
                raise PermissionError(13, "store momentarily locked")
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr("mcp_stdio.token_store.os.open", fail_store_read)
        delete_token("https://a.com/mcp")  # must abort
        monkeypatch.setattr("mcp_stdio.token_store.os.open", real_open)

        # Nothing deleted (and nothing else lost).
        assert load_token("https://a.com/mcp").access_token == "tok-a"
        assert load_token("https://b.com/mcp").access_token == "tok-b"
        assert "could not be read" in capsys.readouterr().err

    def test_save_degrades_to_unlocked_when_lock_open_fails(
        self, tmp_path, monkeypatch
    ):
        """#8: if the advisory lock file cannot be opened, the save must still
        proceed (unsynchronised) — lock trouble never blocks a write."""
        store_file = tmp_path / "tokens.json"
        lock_path = tmp_path / "tokens.json.lock"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        real_open = os.open

        def fail_lock_open(path, flags, *a, **k):
            if os.fspath(path) == os.fspath(lock_path):
                raise PermissionError(13, "cannot create lock file")
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr("mcp_stdio.token_store.os.open", fail_lock_open)
        save_token("https://example.com/mcp", TokenData(access_token="t"))
        monkeypatch.setattr("mcp_stdio.token_store.os.open", real_open)

        assert load_token("https://example.com/mcp").access_token == "t"

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX mode bits don't model NTFS ACLs",
    )
    def test_store_dir_mode_reenforced_when_preexisting(self, tmp_path, monkeypatch):
        """A pre-existing store dir with loose perms is tightened to 0o700."""
        store_dir = tmp_path / "store"
        store_dir.mkdir(mode=0o755)
        store_file = store_dir / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", store_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        save_token("https://example.com/mcp", TokenData(access_token="tok"))
        mode = os.stat(store_dir).st_mode
        assert mode & stat.S_IRWXG == 0
        assert mode & stat.S_IRWXO == 0

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX mode bits don't model NTFS ACLs",
    )
    def test_preexisting_loose_file_mode_tightened_on_read(self, tmp_path, monkeypatch):
        """A tokens.json that pre-exists with loose perms (and is only read) is
        tightened to 0o600 on read, not left world-readable."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        store_file.write_text('{"https://example.com/mcp": {"access_token": "t"}}')
        os.chmod(store_file, 0o644)  # loose, as if restored from a backup

        loaded = load_token("https://example.com/mcp")  # read-only path
        assert loaded is not None and loaded.access_token == "t"
        mode = os.stat(store_file).st_mode
        assert mode & stat.S_IRWXG == 0
        assert mode & stat.S_IRWXO == 0

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX symlink semantics; NTFS differs",
    )
    def test_read_refuses_symlinked_store(self, tmp_path, monkeypatch):
        """A symlinked tokens.json is refused on read (O_NOFOLLOW), consistent
        with the O_NOFOLLOW write path — and crucially its target's mode is NOT
        altered, so a symlink-swap cannot chmod an attacker-chosen file."""
        target = tmp_path / "real.json"
        target.write_text('{"https://example.com/mcp": {"access_token": "t"}}')
        os.chmod(target, 0o644)
        link = tmp_path / "tokens.json"
        link.symlink_to(target)

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", link)

        # O_NOFOLLOW refuses to open through the link → loads as absent.
        loaded = load_token("https://example.com/mcp")
        assert loaded is None
        # The symlink target's mode must be untouched (never opened/chmod'd).
        assert os.stat(target).st_mode & stat.S_IRWXO == stat.S_IROTH

    def test_concurrent_saves_of_distinct_keys_both_persist(
        self, tmp_path, monkeypatch
    ):
        """The advisory lock serialises read-modify-write so two threads saving
        distinct server keys merge instead of last-writer-wins."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        # Seed so both threads read a non-empty baseline they each extend.
        save_token("https://seed.com/mcp", TokenData(access_token="seed"))

        barrier = threading.Barrier(2)

        def worker(n: int) -> None:
            barrier.wait()
            save_token(f"https://host{n}.com/mcp", TokenData(access_token=f"t{n}"))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert load_token("https://seed.com/mcp").access_token == "seed"
        assert load_token("https://host0.com/mcp").access_token == "t0"
        assert load_token("https://host1.com/mcp").access_token == "t1"

    def test_atomic_write_leaves_no_tempfile(self, tmp_path, monkeypatch):
        """Successful save should not leave .tmp files behind."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        save_token("https://example.com/mcp", TokenData(access_token="tok"))
        leftovers = list(tmp_path.glob("tokens.json.tmp*"))
        assert leftovers == []

    def test_write_failure_preserves_existing_tokens(self, tmp_path, monkeypatch):
        """Crash mid-write must not corrupt the existing store."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        # First write succeeds
        save_token("https://example.com/mcp", TokenData(access_token="original"))

        # Second write fails mid-way
        original_replace = os.replace

        def failing_replace(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr("mcp_stdio.token_store.os.replace", failing_replace)
        try:
            save_token("https://example.com/mcp", TokenData(access_token="new"))
        except OSError:
            pass
        monkeypatch.setattr("mcp_stdio.token_store.os.replace", original_replace)

        # Original token must still be intact
        loaded = load_token("https://example.com/mcp")
        assert loaded is not None
        assert loaded.access_token == "original"
        # Temp file must have been cleaned up
        assert list(tmp_path.glob("tokens.json.tmp*")) == []


class TestNormalizeKey:
    def test_lowercases_host(self):
        assert (
            _normalize_key("https://Example.COM/mcp") == "https://example.com/mcp"
        )

    def test_folds_default_port(self):
        assert _normalize_key("https://x.com:443/mcp") == "https://x.com/mcp"
        assert _normalize_key("http://x.com:80/mcp") == "http://x.com/mcp"

    def test_keeps_non_default_port(self):
        assert _normalize_key("https://x.com:8443/mcp") == "https://x.com:8443/mcp"

    def test_strips_trailing_slashes(self):
        assert _normalize_key("https://x.com/mcp/") == "https://x.com/mcp"
        # rstrip removes all trailing slashes, matching the docstring.
        assert _normalize_key("https://x.com/mcp///") == "https://x.com/mcp"

    def test_query_is_preserved_in_key(self):
        assert (
            _normalize_key("https://x.com/mcp?t=1") == "https://x.com/mcp?t=1"
        )

    def test_non_http_returned_unchanged(self):
        assert _normalize_key("not a url") == "not a url"

    def test_malformed_port_returned_unchanged_not_raised(self):
        """A non-numeric / out-of-range port must not raise (the ValueError
        comes from the lazy .port access) — return the URL verbatim."""
        assert (
            _normalize_key("http://example.com:notaport/mcp")
            == "http://example.com:notaport/mcp"
        )
        huge = "https://example.com:99999999999999999999/mcp"
        assert _normalize_key(huge) == huge

    def test_ipv6_brackets_preserved(self):
        """IPv6 literals keep their brackets so the key is re-parsable and two
        addresses cannot collide via the host/port colon ambiguity."""
        assert _normalize_key("https://[::1]:8443/mcp") == "https://[::1]:8443/mcp"
        # Default port still folds out, brackets retained.
        assert _normalize_key("https://[::1]:443/mcp") == "https://[::1]/mcp"

    def test_userinfo_dropped_and_warned_once(self, monkeypatch, capsys):
        """#7(round17): embedded userinfo is dropped from the key (two URLs
        differing only in credentials fold to one slot), and a one-time stderr
        warning surfaces the silent token-sharing — emitted only once."""
        monkeypatch.setattr("mcp_stdio.token_store._warned_userinfo_key", False)
        k1 = _normalize_key("https://userA:passA@example.com/mcp")
        k2 = _normalize_key("https://userB:passB@example.com/mcp")
        # userinfo dropped → both fold to the same credential-free key
        assert k1 == k2 == "https://example.com/mcp"
        err = capsys.readouterr().err
        assert err.count("embedded userinfo") == 1  # warned exactly once
        # A second normalize with userinfo does not warn again.
        _normalize_key("https://userC:passC@example.com/mcp")
        assert "embedded userinfo" not in capsys.readouterr().err

    def test_no_userinfo_no_warning(self, monkeypatch, capsys):
        """A normal URL (no userinfo) must not emit the warning."""
        monkeypatch.setattr("mcp_stdio.token_store._warned_userinfo_key", False)
        _normalize_key("https://example.com/mcp")
        assert capsys.readouterr().err == ""


class TestKeyNormalizationInStore:
    def _patch(self, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        return store_file

    def test_cosmetic_variants_share_one_entry(self, tmp_path, monkeypatch):
        """Trailing slash / host case / default port resolve to the same token."""
        self._patch(tmp_path, monkeypatch)
        save_token("https://Example.com/mcp/", TokenData(access_token="tok"))
        assert load_token("https://example.com:443/mcp").access_token == "tok"

    def test_legacy_raw_key_still_loads(self, tmp_path, monkeypatch):
        """An entry written by an older version under the verbatim URL is found
        via the raw-key fallback."""
        store_file = self._patch(tmp_path, monkeypatch)
        store_file.write_text(
            '{"https://x.com/mcp/": {"access_token": "legacy"}}'
        )
        loaded = load_token("https://x.com/mcp/")
        assert loaded is not None and loaded.access_token == "legacy"

    def test_delete_removes_normalized_and_raw(self, tmp_path, monkeypatch):
        store_file = self._patch(tmp_path, monkeypatch)
        # Pre-seed a stale raw-key entry plus a normalized one.
        store_file.write_text(
            '{"https://x.com/mcp/": {"access_token": "raw"}}'
        )
        save_token("https://x.com/mcp", TokenData(access_token="norm"))
        delete_token("https://x.com/mcp/")
        assert load_token("https://x.com/mcp") is None
        assert load_token("https://x.com/mcp/") is None

    def test_write_store_output_is_key_sorted(self, tmp_path, monkeypatch):
        """#8(round17): on-disk tokens.json keys are sorted for stable,
        diff-friendly output regardless of save order."""
        store_file = self._patch(tmp_path, monkeypatch)
        save_token("https://zebra.com/mcp", TokenData(access_token="z"))
        save_token("https://alpha.com/mcp", TokenData(access_token="a"))
        save_token("https://middle.com/mcp", TokenData(access_token="m"))
        keys = list(json.loads(store_file.read_text()).keys())
        assert keys == sorted(keys)

    def test_write_path_enoent_treated_as_absent_not_unreadable(
        self, tmp_path, monkeypatch, capsys
    ):
        """#9(round17): if the store vanishes in the TOCTOU window between
        exists() and os.open on the WRITE path, treat it as absent (the save
        proceeds from {}) rather than _StoreUnreadable (which would abort the
        save with a misleading 'could not be read' warning)."""
        store_file = self._patch(tmp_path, monkeypatch)
        save_token("https://a.com/mcp", TokenData(access_token="a"))  # store exists

        real_open = os.open

        def vanishing_read_open(path, flags, *a, **k):
            # Simulate ENOENT only on the read-open of the store file (no O_CREAT);
            # the temp-file write-open (O_CREAT) and dir fsync proceed normally.
            if os.fspath(path) == str(store_file) and not (flags & os.O_CREAT):
                raise OSError(errno.ENOENT, "No such file or directory")
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr("mcp_stdio.token_store.os.open", vanishing_read_open)
        save_token("https://b.com/mcp", TokenData(access_token="b"))  # must NOT abort
        monkeypatch.setattr("mcp_stdio.token_store.os.open", real_open)

        # The save proceeded (treated the vanished store as absent), so b persisted.
        assert load_token("https://b.com/mcp").access_token == "b"
        assert "could not be read" not in capsys.readouterr().err


class TestLegacyMigration:
    def _set_legacy_mode(self, path, mode):
        os.chmod(path, mode)

    def test_migrated_file_is_0600_even_if_legacy_was_loose(
        self, tmp_path, monkeypatch
    ):
        """rename() preserves source mode bits; migration must still leave the
        moved file at 0o600 (and never expose it looser, even transiently)."""
        if sys.platform == "win32":
            pytest.skip("POSIX mode bits don't model NTFS ACLs")
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"
        legacy_dir.mkdir()
        legacy_file.write_text('{"https://example.com/mcp": {"access_token": "old"}}')
        os.chmod(legacy_file, 0o644)  # loose legacy mode

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        assert load_token("https://example.com/mcp").access_token == "old"
        mode = os.stat(new_file).st_mode
        assert mode & stat.S_IRWXG == 0
        assert mode & stat.S_IRWXO == 0

    def test_migration_survives_cross_device_rename(self, tmp_path, monkeypatch):
        """An EXDEV (cross-filesystem) rename must not brick the store — the
        copy-through fallback persists the tokens at the new path."""
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"
        legacy_dir.mkdir()
        legacy_file.write_text('{"https://example.com/mcp": {"access_token": "old"}}')

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        real_rename = os.rename

        def exdev_rename(src, dst, *a, **k):
            raise OSError(18, "Invalid cross-device link")  # EXDEV

        monkeypatch.setattr("mcp_stdio.token_store.os.rename", exdev_rename)
        # Path.rename goes through os.rename under the hood on CPython, but
        # guard explicitly in case the implementation calls it differently.
        loaded = load_token("https://example.com/mcp")
        monkeypatch.setattr("mcp_stdio.token_store.os.rename", real_rename)

        assert loaded is not None and loaded.access_token == "old"
        assert new_file.exists()
        assert not legacy_file.exists()

    def test_exdev_copy_through_with_corrupt_legacy_writes_nothing(
        self, tmp_path, monkeypatch
    ):
        """#6(round14): the EXDEV copy-through fallback must NOT write a corrupt
        or empty legacy file through to the new path — it persists only a real
        dict; an unparseable legacy read leaves the target absent."""
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"
        legacy_dir.mkdir()
        legacy_file.write_text("{ this is not valid json")  # corrupt legacy

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        # Force the copy-through branch by making the migration rename raise
        # EXDEV. Patch Path.rename itself (the production code calls
        # _LEGACY_STORE_FILE.rename): on Python 3.10 a patch of the module's
        # os.rename does NOT reach pathlib's pre-bound accessor, so the real
        # same-fs rename would succeed and skip the branch under test.
        def exdev_rename(self, target, *a, **k):
            raise OSError(18, "Invalid cross-device link")  # EXDEV

        monkeypatch.setattr("pathlib.Path.rename", exdev_rename)
        loaded = load_token("https://example.com/mcp")  # must not raise

        assert loaded is None
        # The corrupt legacy content was NOT copied through to the new path.
        assert not new_file.exists()

    def test_copy_through_write_failure_does_not_crash_load(
        self, tmp_path, monkeypatch
    ):
        """#11(round15): if the EXDEV copy-through _write_store raises (disk
        full / read-only FS), load_token (unlocked) must NOT propagate it — it
        degrades to None and leaves the legacy file intact for a later retry."""
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"
        legacy_dir.mkdir()
        legacy_file.write_text('{"https://example.com/mcp": {"access_token": "old"}}')

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        def exdev_rename(self, target, *a, **k):
            raise OSError(18, "Invalid cross-device link")  # force copy-through

        def failing_write(_data):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr("pathlib.Path.rename", exdev_rename)
        monkeypatch.setattr("mcp_stdio.token_store._write_store", failing_write)

        loaded = load_token("https://example.com/mcp")  # must not raise

        assert loaded is None
        # The legacy tokens survive — not unlinked when the write failed.
        assert legacy_file.exists()
        assert "old" in legacy_file.read_text()

    def test_concurrent_migration_race_does_not_clobber_store(
        self, tmp_path, monkeypatch
    ):
        """If a concurrent migration already moved the legacy file (racer B's
        rename raises ENOENT after racer A migrated), the fallback must NOT
        overwrite the just-migrated store with an empty dict — the cached
        tokens must survive."""
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"
        legacy_dir.mkdir()
        legacy_file.write_text(
            '{"https://example.com/mcp": {"access_token": "SECRET"}}'
        )

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        real_rename = os.rename

        def racing_rename(src, dst, *a, **k):
            # Simulate racer A winning between our exists()-check and rename():
            # actually migrate, then raise ENOENT as racer B would observe.
            new_dir.mkdir(parents=True, exist_ok=True)
            real_rename(src, dst)
            raise FileNotFoundError(2, "No such file or directory")

        monkeypatch.setattr("mcp_stdio.token_store.os.rename", racing_rename)
        loaded = load_token("https://example.com/mcp")
        monkeypatch.setattr("mcp_stdio.token_store.os.rename", real_rename)

        # The migrated token must still be there — not clobbered to {}.
        assert loaded is not None and loaded.access_token == "SECRET"
        assert json.loads(new_file.read_text()) == {
            "https://example.com/mcp": {"access_token": "SECRET"}
        }

    def test_migrate_legacy_to_xdg(self, tmp_path, monkeypatch):
        """Legacy ~/.mcp-stdio/tokens.json is moved to new XDG path."""
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"

        legacy_dir.mkdir()
        legacy_file.write_text('{"https://example.com/mcp": {"access_token": "old"}}')

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        loaded = load_token("https://example.com/mcp")
        assert loaded is not None
        assert loaded.access_token == "old"
        assert new_file.exists()
        assert not legacy_file.exists()
        assert not legacy_dir.exists()

    def test_legacy_removed_if_new_exists(self, tmp_path, monkeypatch):
        """If new file already exists, legacy is just removed."""
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"

        legacy_dir.mkdir()
        legacy_file.write_text('{"https://example.com/mcp": {"access_token": "old"}}')
        new_dir.mkdir()
        new_file.write_text('{"https://example.com/mcp": {"access_token": "new"}}')

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        loaded = load_token("https://example.com/mcp")
        assert loaded.access_token == "new"
        assert not legacy_file.exists()

    def test_empty_xdg_store_copies_legacy_through(self, tmp_path, monkeypatch):
        """#8(round16): if the XDG store exists but is EMPTY (a 0-byte
        placeholder from an interrupted write / backup restore), the legacy
        tokens must not be stranded behind it — they are copied through into the
        placeholder (and load_token returns them), then the now-redundant legacy
        file is removed. Earlier behaviour merely preserved the legacy file,
        leaving the tokens permanently unreachable on the read path."""
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"

        legacy_dir.mkdir()
        legacy_file.write_text('{"https://example.com/mcp": {"access_token": "old"}}')
        new_dir.mkdir()
        new_file.write_text("")  # 0-byte placeholder, NOT a completed migration

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        loaded = load_token("https://example.com/mcp")
        # The legacy token is now reachable (copied through into the placeholder).
        assert loaded is not None and loaded.access_token == "old"
        assert "old" in new_file.read_text()
        # The legacy file is unlinked only because its data was safely migrated.
        assert not legacy_file.exists()

    def test_empty_xdg_copy_through_write_failure_preserves_legacy(
        self, tmp_path, monkeypatch
    ):
        """#8(round16): if the empty-placeholder copy-through write FAILS (disk
        full / read-only FS), load_token must not crash and the legacy file must
        be preserved (not unlinked) for a later run to retry."""
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"

        legacy_dir.mkdir()
        legacy_file.write_text('{"https://example.com/mcp": {"access_token": "old"}}')
        new_dir.mkdir()
        new_file.write_text("")

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        def failing_write(_data):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr("mcp_stdio.token_store._write_store", failing_write)

        loaded = load_token("https://example.com/mcp")  # must not raise
        assert loaded is None  # placeholder still empty → no token
        assert legacy_file.exists()  # legacy preserved for a later retry
        assert "old" in legacy_file.read_text()

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX mode bits don't model the NTFS ACL Windows uses",
    )
    def test_migration_tightens_legacy_dir_permissions(self, tmp_path, monkeypatch):
        """#9(round16): the legacy DIR is re-chmod'd to 0o700 before its secrets
        are exposed to a rename/copy-through, mirroring _ensure_store_dir's
        defensive re-chmod of the XDG dir."""
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"

        legacy_dir.mkdir(mode=0o755)
        legacy_file.write_text('{"https://example.com/mcp": {"access_token": "old"}}')
        # new_dir absent → migration takes the rename branch (chmods dir first)

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        chmodded: list[tuple[str, int]] = []
        real_chmod = os.chmod

        def spy_chmod(path, mode, *a, **k):
            chmodded.append((os.fspath(path), mode))
            return real_chmod(path, mode, *a, **k)

        monkeypatch.setattr("mcp_stdio.token_store.os.chmod", spy_chmod)
        load_token("https://example.com/mcp")

        assert any(
            p == str(legacy_dir) and m == stat.S_IRWXU for p, m in chmodded
        ), f"legacy dir was not tightened to 0o700; chmod calls: {chmodded!r}"

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX mode bits don't model the NTFS ACL Windows uses",
    )
    def test_ensure_store_dir_warns_once_on_unfixable_loose_perms(
        self, tmp_path, monkeypatch, capsys
    ):
        """#10(round16): if the store dir cannot be tightened and stays group/
        other-accessible, emit a single operator warning instead of failing
        silently — and only once, not on every call."""
        from mcp_stdio.token_store import _ensure_store_dir

        store_dir = tmp_path / "store"
        store_file = store_dir / "tokens.json"
        store_dir.mkdir()
        real_chmod = os.chmod
        real_chmod(store_dir, 0o755)  # genuinely loose before we block chmod

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", store_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        monkeypatch.setattr("mcp_stdio.token_store._warned_loose_store_dir", False)

        def refuse_dir_chmod(path, mode, *a, **k):
            if os.path.isdir(path):
                raise OSError("cannot tighten dir on this filesystem")
            return real_chmod(path, mode, *a, **k)

        monkeypatch.setattr("mcp_stdio.token_store.os.chmod", refuse_dir_chmod)

        _ensure_store_dir()
        _ensure_store_dir()  # second call must NOT warn again
        err = capsys.readouterr().err
        assert err.count("group/other-accessible") == 1, err

    def test_legacy_unlink_failure_when_new_exists_does_not_crash(
        self, tmp_path, monkeypatch
    ):
        """If the new store already exists, a failure to remove the redundant
        legacy file (read-only FS, or a TOCTOU race that already unlinked it)
        must NOT crash load_token — the migrated store is still readable."""
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"

        legacy_dir.mkdir()
        legacy_file.write_text('{"https://example.com/mcp": {"access_token": "old"}}')
        new_dir.mkdir()
        new_file.write_text('{"https://example.com/mcp": {"access_token": "new"}}')

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        real_unlink = os.unlink

        def failing_unlink(path, *a, **k):
            if os.fspath(path) == os.fspath(legacy_file):
                raise PermissionError(13, "read-only legacy fs")
            return real_unlink(path, *a, **k)

        monkeypatch.setattr("mcp_stdio.token_store.os.unlink", failing_unlink)

        # Must not raise — the already-migrated store is returned intact.
        loaded = load_token("https://example.com/mcp")
        assert loaded is not None and loaded.access_token == "new"

    def test_post_rename_chmod_failure_completes_migration(
        self, tmp_path, monkeypatch
    ):
        """A chmod failure after a successful rename must not abort or divert the
        migration into the copy-through recovery — the moved file stands."""
        if sys.platform == "win32":
            pytest.skip("POSIX mode bits don't model NTFS ACLs")
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"

        legacy_dir.mkdir()
        legacy_file.write_text('{"https://example.com/mcp": {"access_token": "old"}}')

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        def failing_chmod(*a, **k):
            raise PermissionError(1, "operation not permitted")

        monkeypatch.setattr("mcp_stdio.token_store.os.chmod", failing_chmod)

        loaded = load_token("https://example.com/mcp")
        assert loaded is not None and loaded.access_token == "old"
        assert new_file.exists()
        assert not legacy_file.exists()  # genuinely renamed, not copy-through

    def test_no_migration_if_no_legacy(self, tmp_path, monkeypatch):
        """No error when legacy path does not exist."""
        new_dir = tmp_path / "new"
        new_file = new_dir / "tokens.json"
        legacy_dir = tmp_path / "legacy"
        legacy_file = legacy_dir / "tokens.json"

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", new_dir)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", new_file)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_DIR", legacy_dir)
        monkeypatch.setattr("mcp_stdio.token_store._LEGACY_STORE_FILE", legacy_file)

        assert load_token("https://example.com/mcp") is None
