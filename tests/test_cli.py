"""Tests for mcp_stdio.cli module."""

from unittest.mock import patch

import pytest

from mcp_stdio.cli import (
    _build_scope_upgrader,
    _build_token_refresher,
    _parse_header,
    main,
)
from mcp_stdio.token_store import TokenData


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

    @pytest.mark.parametrize(
        "flag", ["--timeout-connect", "--timeout-read", "--sse-read-timeout"]
    )
    def test_negative_timeouts_rejected(self, flag, capsys):
        """Negative duration flags are rejected at parse time, consistent with
        --oauth-refresh-leeway, instead of flowing into httpx.Timeout."""
        with patch(
            "sys.argv", ["mcp-stdio", flag, "-5", "https://example.com/mcp"]
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        assert "must be >= 0" in capsys.readouterr().err

    def test_sse_read_timeout_zero_still_accepted(self):
        """--sse-read-timeout 0 (disable) must remain valid — 0 is allowed."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--transport",
                    "sse",
                    "--sse-read-timeout",
                    "0",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.cli.run_sse") as mock_run_sse,
        ):
            main()
            assert mock_run_sse.call_args.kwargs["sse_read_timeout"] == 0.0

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

    def test_env_bearer_token_does_not_block_oauth(self, monkeypatch):
        """An ambient MCP_BEARER_TOKEN must not trip the mutual-exclusion guard
        against --oauth; the OAuth flow runs and supplies the header."""
        monkeypatch.setenv("MCP_BEARER_TOKEN", "env-token")
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            mock_ensure.return_value.access_token = "oauth-tok"
            main()  # must NOT sys.exit(1)
        headers = mock_run.call_args.kwargs["headers"]
        # OAuth wins; the ambient env bearer token is ignored.
        assert headers["Authorization"] == "Bearer oauth-tok"

    def test_explicit_bearer_flag_still_conflicts_with_oauth(self, monkeypatch):
        """An explicit --bearer-token on the command line still conflicts."""
        monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
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

    def test_dash_h_overrides_bearer_authorization_case_insensitively(self):
        """A -H differing only in case from a built-in header replaces it,
        rather than sending two same-named headers (RFC 7230 §3.2)."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "--bearer-token",
                    "tok123",
                    "-H",
                    "authorization: Bearer override",
                ],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
            headers = mock_run.call_args.kwargs["headers"]
            auth_keys = [k for k in headers if k.lower() == "authorization"]
            assert auth_keys == ["authorization"]
            assert headers["authorization"] == "Bearer override"

    def test_oauth_authorization_dedups_case_variant_dash_h(self, monkeypatch):
        """--oauth together with a differently-cased -H authorization must not
        send two Authorization headers — the OAuth token is the only one."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "-H",
                    "authorization: custom",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            mock_ensure.return_value.access_token = "oauth-tok"
            main()
        headers = mock_run.call_args.kwargs["headers"]
        auth_keys = [k for k in headers if k.lower() == "authorization"]
        assert auth_keys == ["Authorization"]
        assert headers["Authorization"] == "Bearer oauth-tok"

    def test_warns_when_oauth_only_flags_set_without_oauth(self, capsys):
        """OAuth-only flags without --oauth/--oauth-device are silently ignored;
        emit a warning so the user notices."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth-scope",
                    "hr:read",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.cli.run"),
        ):
            main()
        assert "ignored without --oauth" in capsys.readouterr().err

    def test_no_warning_when_oauth_flags_with_oauth(self, capsys):
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--oauth-scope",
                    "hr:read",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert "ignored without --oauth" not in capsys.readouterr().err

    def test_env_client_id_alone_does_not_warn(self, monkeypatch, capsys):
        """An ambient MCP_OAUTH_CLIENT_ID without --oauth must NOT trip the
        'ignored without --oauth' warning (only an explicit --client-id does)."""
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "cid")
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run"),
        ):
            main()
        assert "ignored without --oauth" not in capsys.readouterr().err

    def test_explicit_client_id_without_oauth_warns(self, monkeypatch, capsys):
        monkeypatch.delenv("MCP_OAUTH_CLIENT_ID", raising=False)
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "--client-id", "cid", "https://example.com/mcp"],
            ),
            patch("mcp_stdio.cli.run"),
        ):
            main()
        assert "ignored without --oauth" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "bad", ["tok\nInjected: x", "tok\rx", "tok\x00x", "tok\r\nInjected: x"]
    )
    def test_bearer_token_control_chars_rejected(self, bad, capsys):
        """A bearer token with CR/LF/NUL must be rejected (header injection),
        the same ban -H values get."""
        with patch(
            "sys.argv", ["mcp-stdio", "--bearer-token", bad, "https://example.com/mcp"]
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1
        assert "forbidden control character" in capsys.readouterr().err

    def test_dash_h_overrides_default_content_type_case_insensitively(self):
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "-H",
                    "content-type: application/cbor",
                ],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
            headers = mock_run.call_args.kwargs["headers"]
            ct_keys = [k for k in headers if k.lower() == "content-type"]
            assert ct_keys == ["content-type"]
            assert headers["content-type"] == "application/cbor"

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

    def test_check_forwards_transport_streamable_default(self):
        """--check without --transport probes via the default streamable-http."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp", "--check"]),
            patch("mcp_stdio.cli.check_connection", return_value=True) as mock_check,
        ):
            with pytest.raises(SystemExit):
                main()
            assert mock_check.call_args.kwargs["transport"] == "streamable-http"

    def test_check_forwards_transport_sse(self):
        """#11: --check --transport sse must run the SSE-aware probe, not the
        default streamable-http POST."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/sse",
                    "--check",
                    "--transport",
                    "sse",
                ],
            ),
            patch("mcp_stdio.cli.check_connection", return_value=True) as mock_check,
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
            assert mock_check.call_args.kwargs["transport"] == "sse"

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

    def test_normalize_arguments_default_on(self):
        """tools/call argument normalization is ON by default → run() sees True."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["normalize_arguments"] is True

    def test_normalize_arguments_opt_out(self):
        """--no-normalize-arguments flips the flag to False."""
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "https://example.com/mcp", "--no-normalize-arguments"],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["normalize_arguments"] is False

    def test_normalize_arguments_passed_to_run_sse(self):
        """--no-normalize-arguments reaches run_sse on the sse transport."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "--transport",
                    "sse",
                    "--no-normalize-arguments",
                ],
            ),
            patch("mcp_stdio.cli.run_sse") as mock_run_sse,
        ):
            main()
        assert mock_run_sse.call_args.kwargs["normalize_arguments"] is False

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


class _SpyClient:
    """httpx.Client stand-in that records close() and construction kwargs."""

    instances: list["_SpyClient"] = []

    def __init__(self, *a, **k):
        self.closed = False
        self.kwargs = k
        _SpyClient.instances.append(self)

    def close(self):
        self.closed = True


class TestBuildTokenRefresher:
    """The refresher closure turns a refreshed token into relay 401-recovery
    headers. Production-wired but otherwise untested."""

    def test_returns_bearer_headers_and_closes_client(self, monkeypatch):
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)
        monkeypatch.setattr(
            "mcp_stdio.oauth.refresh_cached_token",
            lambda url, client: TokenData(access_token="fresh"),
        )
        refresher = _build_token_refresher(
            "https://example.com/mcp", {"X-Base": "1"}, 10, 120
        )
        out = refresher()
        assert out["Authorization"] == "Bearer fresh"
        assert out["X-Base"] == "1"  # base headers preserved
        assert _SpyClient.instances and _SpyClient.instances[-1].closed
        # AS-controlled redirects must not be auto-followed on the OAuth flow.
        assert _SpyClient.instances[-1].kwargs.get("follow_redirects") is False

    def test_returns_none_on_refresh_failure_and_closes(self, monkeypatch):
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)
        monkeypatch.setattr(
            "mcp_stdio.oauth.refresh_cached_token", lambda url, client: None
        )
        refresher = _build_token_refresher("https://example.com/mcp", {}, 10, 120)
        assert refresher() is None
        assert _SpyClient.instances[-1].closed


class TestBuildScopeUpgrader:
    """The upgrader closure runs RFC 9470 step-up and returns broader-scope
    headers, catching exceptions (unlike the refresher)."""

    def test_returns_bearer_headers_and_closes_client(self, monkeypatch):
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)
        monkeypatch.setattr(
            "mcp_stdio.oauth.step_up_authorize",
            lambda url, client, scope: TokenData(access_token="upgraded"),
        )
        upgrader = _build_scope_upgrader(
            "https://example.com/mcp", {"X-Base": "1"}, 10, 120
        )
        out = upgrader("hr:read hr:write")
        assert out["Authorization"] == "Bearer upgraded"
        assert out["X-Base"] == "1"
        assert _SpyClient.instances[-1].closed

    def test_returns_none_when_step_up_raises_and_closes(self, monkeypatch, capsys):
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)

        def boom(url, client, scope):
            raise RuntimeError("step-up denied")

        monkeypatch.setattr("mcp_stdio.oauth.step_up_authorize", boom)
        upgrader = _build_scope_upgrader("https://example.com/mcp", {}, 10, 120)
        assert upgrader("hr:read") is None
        assert _SpyClient.instances[-1].closed
        assert "step-up authorization failed" in capsys.readouterr().err


class TestOAuthFailureExit:
    def test_ensure_token_failure_exits_1_with_message(self, capsys):
        """A failing OAuth flow at startup prints a clear error and exits 1."""
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch(
                "mcp_stdio.oauth.ensure_token",
                side_effect=RuntimeError("browser closed"),
            ),
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1
        assert "OAuth authentication failed" in capsys.readouterr().err


class TestOAuthClientHardening:
    def test_oauth_client_disables_redirects(self, monkeypatch):
        """The OAuth flow client must not auto-follow AS-controlled redirects."""
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert _SpyClient.instances
        assert _SpyClient.instances[0].kwargs.get("follow_redirects") is False
