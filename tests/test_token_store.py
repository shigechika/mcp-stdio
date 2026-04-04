"""Tests for mcp_stdio.token_store module."""

import os
import stat

from mcp_stdio.token_store import TokenData, delete_token, load_token, save_token


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


class TestLegacyMigration:
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
