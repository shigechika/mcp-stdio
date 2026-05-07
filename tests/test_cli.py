"""Tests for mcp_stdio.cli module."""

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

    @pytest.mark.parametrize(
        "value",
        [
            "value\r\nInjected: bad",  # classic CRLF injection
            "value\nInjected: bad",  # bare LF
            "value\rInjected: bad",  # bare CR
            "value\x00hidden",  # NUL
        ],
    )
    def test_value_with_control_chars_rejected(self, value, capsys):
        """#14: CRLF / NUL in header values must never be accepted."""
        with pytest.raises(SystemExit):
            _parse_header(f"X-Api-Key: {value}")
        assert "forbidden control character" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "name",
        [
            "bad key",  # whitespace
            "(comment)",  # parens not in tchar
            "bad\x7fkey",  # DEL
            "",  # empty after strip
        ],
    )
    def test_name_violating_token_grammar_rejected(self, name, capsys):
        """#14: RFC 7230 §3.2.6 token grammar enforcement on header names."""
        with pytest.raises(SystemExit):
            _parse_header(f"{name}: value")
        assert "invalid header name" in capsys.readouterr().err


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
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "--bearer-token",
                    "tok123",
                    "-H",
                    "X-Custom: val",
                ],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
            call_kwargs = mock_run.call_args
            headers = (
                call_kwargs.kwargs["headers"]
                if call_kwargs.kwargs
                else call_kwargs[1]["headers"]
            )
            # If called positionally
            if not headers:
                headers = call_kwargs[0][1]
            assert headers["Authorization"] == "Bearer tok123"
            assert headers["X-Custom"] == "val"

    def test_bearer_token_from_env(self, monkeypatch):
        monkeypatch.setenv("MCP_BEARER_TOKEN", "env-token")
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
            headers = (
                mock_run.call_args[1]["headers"]
                if mock_run.call_args[1]
                else mock_run.call_args[0][1]
            )
            assert headers["Authorization"] == "Bearer env-token"

    def test_custom_timeouts(self):
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "--timeout-connect",
                    "5",
                    "--timeout-read",
                    "60",
                ],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
            kwargs = mock_run.call_args
            assert kwargs.kwargs["timeout_connect"] == 5.0
            assert kwargs.kwargs["timeout_read"] == 60.0

    def test_oauth_refresh_leeway_default(self, monkeypatch):
        """#56: --oauth-refresh-leeway defaults to 60 s when env var unset and flag absent."""
        monkeypatch.delenv("MCP_OAUTH_REFRESH_LEEWAY", raising=False)
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["refresh_leeway"] == 60.0

    def test_oauth_refresh_leeway_custom_flag(self):
        """#56: --oauth-refresh-leeway flag is propagated to ensure_token."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--oauth-refresh-leeway",
                    "300",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["refresh_leeway"] == 300.0

    def test_oauth_refresh_leeway_env_var(self, monkeypatch):
        """#56: MCP_OAUTH_REFRESH_LEEWAY env var is respected when flag absent."""
        monkeypatch.setenv("MCP_OAUTH_REFRESH_LEEWAY", "120")
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["refresh_leeway"] == 120.0

    def test_oauth_refresh_leeway_negative_rejected(self, capsys):
        """#56: negative leeway values are rejected at parse time."""
        with patch(
            "sys.argv",
            [
                "mcp-stdio",
                "--oauth-refresh-leeway",
                "-1",
                "https://example.com/mcp",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2  # argparse error
        assert "must be >= 0" in capsys.readouterr().err

    def test_oauth_refresh_leeway_invalid_env_var_rejected(self, monkeypatch, capsys):
        """#56: invalid env var values surface as argparse errors, not ValueError."""
        monkeypatch.setenv("MCP_OAUTH_REFRESH_LEEWAY", "not-a-number")
        with patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        assert "invalid float value" in capsys.readouterr().err

    def test_oauth_and_bearer_token_mutually_exclusive(self):
        with patch(
            "sys.argv",
            [
                "mcp-stdio",
                "https://example.com/mcp",
                "--oauth",
                "--bearer-token",
                "tok",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_oauth_device_and_oauth_mutually_exclusive(self):
        with patch(
            "sys.argv",
            ["mcp-stdio", "https://example.com/mcp", "--oauth", "--oauth-device"],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_oauth_device_and_bearer_token_mutually_exclusive(self):
        with patch(
            "sys.argv",
            [
                "mcp-stdio",
                "https://example.com/mcp",
                "--oauth-device",
                "--bearer-token",
                "tok",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_check_flag_invokes_check_connection(self):
        """--check should call check_connection and exit with its result."""
        with (
            patch(
                "sys.argv", ["mcp-stdio", "https://example.com/mcp", "--check"]
            ),
            patch("mcp_stdio.cli.check_connection", return_value=True) as mock_check,
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
            assert mock_check.called

    def test_test_flag_deprecated_alias_works(self, capsys):
        """--test still works for backward compatibility but emits a deprecation warning."""
        with (
            patch(
                "sys.argv", ["mcp-stdio", "https://example.com/mcp", "--test"]
            ),
            patch("mcp_stdio.cli.check_connection", return_value=True) as mock_check,
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
            assert mock_check.called
            captured = capsys.readouterr()
            assert "--test is deprecated" in captured.err
            assert "--check" in captured.err

    def test_check_flag_no_deprecation_warning(self, capsys):
        """--check (the new spelling) must NOT emit any deprecation warning."""
        with (
            patch(
                "sys.argv", ["mcp-stdio", "https://example.com/mcp", "--check"]
            ),
            patch("mcp_stdio.cli.check_connection", return_value=True),
        ):
            with pytest.raises(SystemExit):
                main()
            captured = capsys.readouterr()
            assert "deprecated" not in captured.err

    def test_check_flag_failure_exits_nonzero(self):
        """--check exits with code 1 when check_connection returns False."""
        with (
            patch(
                "sys.argv", ["mcp-stdio", "https://example.com/mcp", "--check"]
            ),
            patch("mcp_stdio.cli.check_connection", return_value=False),
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_tcp_keepalive_default_on(self):
        """#9: TCP keepalive is ON by default (no flag) → run() sees True."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["tcp_keepalive"] is True

    def test_tcp_keepalive_opt_out(self):
        """#9: --no-tcp-keepalive flips the flag to False."""
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "https://example.com/mcp", "--no-tcp-keepalive"],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["tcp_keepalive"] is False

    def test_tcp_keepalive_passed_to_run_sse(self):
        """#9: --no-tcp-keepalive reaches run_sse on the sse transport."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "--transport",
                    "sse",
                    "--no-tcp-keepalive",
                ],
            ),
            patch("mcp_stdio.cli.run_sse") as mock_run_sse,
        ):
            main()
        assert mock_run_sse.call_args.kwargs["tcp_keepalive"] is False

    def test_cancel_filter_default_on(self):
        """#39: cancel filter is ON by default → run() sees True."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["cancel_filter"] is True

    def test_cancel_filter_opt_out(self):
        """#39: --no-cancel-filter flips the flag to False."""
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "https://example.com/mcp", "--no-cancel-filter"],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["cancel_filter"] is False

    def test_cancel_filter_passed_to_run_sse(self):
        """#39: --no-cancel-filter reaches run_sse on the sse transport."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "--transport",
                    "sse",
                    "--no-cancel-filter",
                ],
            ),
            patch("mcp_stdio.cli.run_sse") as mock_run_sse,
        ):
            main()
        assert mock_run_sse.call_args.kwargs["cancel_filter"] is False

    def test_no_resource_indicator_default_is_true(self):
        """By default resource_indicator=True is passed to ensure_token."""
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["resource_indicator"] is True

    def test_no_resource_indicator_flag_passes_false(self):
        """--no-resource-indicator propagates resource_indicator=False to ensure_token."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--no-resource-indicator",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["resource_indicator"] is False
