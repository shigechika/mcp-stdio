"""Tests for mcp_stdio.cli module."""

import sys
from unittest.mock import patch

import pytest

from mcp_stdio.cli import _parse_header, main


class TestParseHeader:
    def test_valid_header(self):
        assert _parse_header("X-Api-Key: secret123") == ("X-Api-Key", "secret123")

    def test_header_with_extra_spaces(self):
        assert _parse_header("  Key  :  Value  ") == ("Key", "Value")

    def test_header_with_colon_in_value(self):
        assert _parse_header("Authorization: Bearer token:abc") == (
            "Authorization",
            "Bearer token:abc",
        )

    def test_empty_value(self):
        assert _parse_header("Key:") == ("Key", "")

    def test_invalid_header_exits(self):
        with pytest.raises(SystemExit):
            _parse_header("no-colon-here")


class TestMain:
    def test_version_flag(self, capsys):
        with patch("sys.argv", ["mcp-stdio", "-V"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
        output = capsys.readouterr()
        assert "mcp-stdio" in output.out

    def test_missing_url_exits(self):
        with patch("sys.argv", ["mcp-stdio"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    def test_headers_and_bearer_token(self):
        with patch("sys.argv", [
            "mcp-stdio",
            "https://example.com/mcp",
            "--bearer-token", "tok123",
            "-H", "X-Custom: val",
        ]), patch("mcp_stdio.cli.run") as mock_run:
            main()
            call_kwargs = mock_run.call_args
            headers = call_kwargs.kwargs["headers"] if call_kwargs.kwargs else call_kwargs[1]["headers"]
            # If called positionally
            if not headers:
                headers = call_kwargs[0][1]
            assert headers["Authorization"] == "Bearer tok123"
            assert headers["X-Custom"] == "val"

    def test_bearer_token_from_env(self, monkeypatch):
        monkeypatch.setenv("MCP_BEARER_TOKEN", "env-token")
        with patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]), \
             patch("mcp_stdio.cli.run") as mock_run:
            main()
            headers = mock_run.call_args[1]["headers"] if mock_run.call_args[1] else mock_run.call_args[0][1]
            assert headers["Authorization"] == "Bearer env-token"

    def test_custom_timeouts(self):
        with patch("sys.argv", [
            "mcp-stdio",
            "https://example.com/mcp",
            "--timeout-connect", "5",
            "--timeout-read", "60",
        ]), patch("mcp_stdio.cli.run") as mock_run:
            main()
            kwargs = mock_run.call_args
            assert kwargs.kwargs["timeout_connect"] == 5.0
            assert kwargs.kwargs["timeout_read"] == 60.0

    def test_oauth_and_bearer_token_mutually_exclusive(self):
        with patch("sys.argv", [
            "mcp-stdio",
            "https://example.com/mcp",
            "--oauth",
            "--bearer-token", "tok",
        ]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1
