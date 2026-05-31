"""Tests for mcp_stdio.token_store module."""

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

    def test_save_over_corrupt_store_succeeds(self, tmp_path, monkeypatch):
        """A corrupt store file is replaced (not appended to) on the next save."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        store_file.write_text("not json")
        save_token("https://example.com/mcp", TokenData(access_token="fresh"))
        loaded = load_token("https://example.com/mcp")
        assert loaded is not None and loaded.access_token == "fresh"

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

    def test_strips_single_trailing_slash(self):
        assert _normalize_key("https://x.com/mcp/") == "https://x.com/mcp"

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
