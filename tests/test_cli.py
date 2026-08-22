"""Tests for mcp_stdio.cli module."""

import argparse
from unittest.mock import patch

import pytest

from mcp_stdio.cli import (
    _bearer_header_value,
    _build_scope_upgrader,
    _build_token_refresher,
    _effective_bearer,
    _https_url_with_path,
    _parse_header,
    main,
)
from mcp_stdio.relay import _MAX_MESSAGE_SIZE_ATTR
from mcp_stdio.token_store import TokenData


class TestBearerHeaderValue:
    """: an OAuth AS-supplied token gets the same CR/LF/NUL ban as
    -H values and --bearer-token, so it cannot inject/split request headers."""

    def test_clean_token_builds_header(self):
        assert _bearer_header_value("abc.def-123") == "Bearer abc.def-123"

    @pytest.mark.parametrize(
        "bad",
        ["tok\r\nX-Inject: 1", "tok\nX: 1", "tok\rX: 1", "tok\x00hidden"],
    )
    def test_control_char_token_rejected(self, bad):
        with pytest.raises(ValueError, match="forbidden control character"):
            _bearer_header_value(bad)


class TestEffectiveBearer:
    """#59: --oauth-use-id-token selects the OIDC id_token as the Bearer."""

    def _data(self, **kw):
        kw.setdefault("access_token", "acc")
        return TokenData(**kw)

    def test_access_token_by_default(self):
        data = self._data(id_token="idt")
        assert _effective_bearer(data, use_id_token=False) == "acc"

    def test_id_token_when_flag_set(self):
        data = self._data(id_token="idt")
        assert _effective_bearer(data, use_id_token=True) == "idt"

    def test_falls_back_to_access_token_when_no_id_token(self, capsys):
        data = self._data(id_token=None)
        assert _effective_bearer(data, use_id_token=True) == "acc"
        assert "no id_token" in capsys.readouterr().err


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

    def test_default_timeouts_are_floats(self):
        """: with the timeout flags omitted the defaults must be
        floats — argparse applies ``type`` only to argv strings, not to the
        default object, so an int default would leak through. Keep the attribute
        type consistent with the _positive_float validator."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
            kwargs = mock_run.call_args
            assert kwargs.kwargs["timeout_connect"] == 10.0
            assert isinstance(kwargs.kwargs["timeout_connect"], float)
            assert kwargs.kwargs["timeout_read"] == 120.0
            assert isinstance(kwargs.kwargs["timeout_read"], float)

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

    def test_oauth_eager_warm_cache_no_cold_start(self):
        """#296: --oauth-eager with a warm cache probes non-interactively and
        runs normally (cold_start_login None)."""
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "--oauth", "--oauth-eager", "https://example.com/mcp"],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            mock_ensure.return_value.access_token = "tok"
            mock_ensure.return_value.id_token = None
            main()
        # Probed non-interactively, token available -> no cold-start.
        assert mock_ensure.call_args.kwargs["interactive"] is False
        assert mock_run.call_args.kwargs["cold_start_login"] is None

    def test_oauth_eager_cold_cache_defers_login(self):
        """#296: --oauth-eager with a cold cache (non-interactive probe returns
        None) defers OAuth to a background cold_start_login passed to run()."""
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "--oauth", "--oauth-eager", "https://example.com/mcp"],
            ),
            patch("mcp_stdio.oauth.ensure_token", return_value=None) as mock_ensure,
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_ensure.call_args.kwargs["interactive"] is False
        assert callable(mock_run.call_args.kwargs["cold_start_login"])

    def test_oauth_eager_ignored_on_sse(self, capsys):
        """--oauth-eager is Streamable-HTTP only: on --transport sse it warns and
        falls back to the blocking (interactive) flow before the relay starts."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--oauth-eager",
                    "--transport",
                    "sse",
                    "https://example.com/sse",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run_sse"),
        ):
            mock_ensure.return_value.access_token = "tok"
            mock_ensure.return_value.id_token = None
            main()
        assert mock_ensure.call_args.kwargs["interactive"] is True
        assert "ignored on --transport sse" in capsys.readouterr().err

    def test_oauth_timeout_default_and_flag(self):
        """: the interactive-OAuth wait is configurable via
        --oauth-timeout (default 120) and propagated to ensure_token(timeout=)."""
        # Default.
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["timeout"] == 120.0
        # Custom flag.
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--oauth-timeout",
                    "300",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["timeout"] == 300.0

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

    def test_oauth_refresh_leeway_empty_env_var_falls_back_to_default(
        self, monkeypatch
    ):
        """An exported-but-EMPTY MCP_OAUTH_REFRESH_LEEWAY (a common CI artifact
        of `export VAR=$MAYBE_UNSET`) must fall back to the 60 s default, not
        abort startup with an argparse 'invalid float value' error."""
        monkeypatch.setenv("MCP_OAUTH_REFRESH_LEEWAY", "")
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["refresh_leeway"] == 60.0

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
        with patch("sys.argv", ["mcp-stdio", flag, "-5", "https://example.com/mcp"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        assert "must be >= 0" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "flag",
        [
            "--timeout-connect",
            "--timeout-read",
            "--sse-read-timeout",
            "--listen-read-timeout",
            "--oauth-refresh-leeway",
            "--oauth-timeout",
        ],
    )
    @pytest.mark.parametrize("value", ["nan", "inf", "Infinity"])
    def test_non_finite_floats_rejected(self, flag, value, capsys):
        """: float() parses nan/inf, which slip past the < 0 / == 0
        comparisons and defeat the validators (a nan/inf timeout never fires →
        silent hang). Every float flag must reject non-finite values at parse
        time. (-inf is omitted: argparse intercepts a leading '-' as an option
        before the validator runs; it is already caught by the < 0 guard.)"""
        with patch("sys.argv", ["mcp-stdio", flag, value, "https://example.com/mcp"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        assert "must be finite" in capsys.readouterr().err

    @pytest.mark.parametrize("flag", ["--timeout-connect", "--timeout-read"])
    def test_zero_connect_read_timeout_rejected(self, flag, capsys):
        """#9: --timeout-connect 0 / --timeout-read 0 are rejected at parse time
        (httpx would treat 0 as an immediate timeout that always fails). Unlike
        --sse-read-timeout, where 0 means 'disable'."""
        with patch("sys.argv", ["mcp-stdio", flag, "0", "https://example.com/mcp"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        assert "must be > 0" in capsys.readouterr().err

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

    def test_listen_read_timeout_zero_rejected(self, capsys):
        """#270 Phase 2 PR A (C9): --listen-read-timeout deliberately does
        NOT inherit --sse-read-timeout's 0 = disable — an unbounded read on
        the modern subscriptions/listen stream would violate the spec's
        "SHOULD always enforce a maximum timeout". _positive_float rejects
        0 at parse time, by construction."""
        with patch(
            "sys.argv",
            ["mcp-stdio", "--listen-read-timeout", "0", "https://example.com/mcp"],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        assert "must be > 0" in capsys.readouterr().err

    def test_listen_read_timeout_default_and_passthrough(self):
        """#270 Phase 2 PR A: --listen-read-timeout reaches run() (default
        300.0, kept a float like the other timeout flags — argparse applies
        ``type`` only to argv strings, never to the default object)."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
            assert mock_run.call_args.kwargs["listen_read_timeout"] == 300.0
            assert isinstance(mock_run.call_args.kwargs["listen_read_timeout"], float)
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--listen-read-timeout",
                    "42.5",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
            assert mock_run.call_args.kwargs["listen_read_timeout"] == 42.5

    def test_max_message_size_default_and_passthrough(self):
        """#416: --max-message-size defaults to 10 MiB and reaches both
        run() (Streamable HTTP) and run_sse() (legacy SSE) — it is a
        client-side cap, so it applies to either transport."""
        from mcp_stdio.relay import _DEFAULT_MAX_MESSAGE_SIZE

        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
            assert (
                mock_run.call_args.kwargs["max_message_size"]
                == _DEFAULT_MAX_MESSAGE_SIZE
            )
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--transport",
                    "sse",
                    "--max-message-size",
                    "1000",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.cli.run_sse") as mock_run_sse,
        ):
            main()
            assert mock_run_sse.call_args.kwargs["max_message_size"] == 1000

    def test_max_message_size_zero_means_unlimited(self):
        """0 disables the cap, same convention as --session-idle-ttl etc."""
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "--max-message-size", "0", "https://example.com/mcp"],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
            assert mock_run.call_args.kwargs["max_message_size"] == 0

    def test_max_message_size_negative_rejected(self, capsys):
        with patch(
            "sys.argv",
            ["mcp-stdio", "--max-message-size", "-1", "https://example.com/mcp"],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
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

    def test_empty_bearer_flag_still_conflicts_with_oauth(self, monkeypatch):
        """#17: `--bearer-token '' --oauth` must error like a non-empty token —
        an explicit (even empty) bearer flag is a contradictory auth choice and
        must not slip past the mutual-exclusion check on a falsiness technicality."""
        monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
        with patch(
            "sys.argv",
            [
                "mcp-stdio",
                "https://example.com/mcp",
                "--oauth",
                "--bearer-token",
                "",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_empty_bearer_flag_alone_warns_no_auth(self, monkeypatch, capsys):
        """: `--bearer-token ''` alone (no OAuth) is counted as an
        auth choice by the mutual-exclusion check but attaches NO Authorization
        header — silently unauthenticated. Surface a stderr warning, and confirm
        no Authorization header is built."""
        monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "https://example.com/mcp", "--bearer-token", ""],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert "--bearer-token is empty" in capsys.readouterr().err
        headers = mock_run.call_args.kwargs["headers"]
        assert "Authorization" not in headers

    def test_explicit_authorization_header_with_oauth_warns(self, monkeypatch, capsys):
        """#18: an explicit -H 'Authorization: ...' overridden by the OAuth token
        emits a stderr warning instead of silently discarding it."""
        monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "-H",
                    "Authorization: Bearer mine",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run") as mock_run,
            patch("mcp_stdio.cli._build_token_refresher"),
            patch("mcp_stdio.cli._build_scope_upgrader"),
        ):
            mock_ensure.return_value.access_token = "oauth-tok"
            main()
        # The OAuth token wins and the override is announced.
        headers = mock_run.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer oauth-tok"
        assert "overridden by the OAuth-acquired token" in capsys.readouterr().err

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

    def test_dash_h_authorization_overriding_bearer_warns(self, monkeypatch, capsys):
        """: a -H 'Authorization' that displaces an EXPLICIT
        --bearer-token warns (mirroring the OAuth override warning) instead of
        silently dropping the flag's value."""
        monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "--bearer-token",
                    "tok123",
                    "-H",
                    "Authorization: Bearer override",
                ],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        headers = mock_run.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer override"  # -H wins
        assert "overrides --bearer-token" in capsys.readouterr().err

    def test_dash_h_authorization_without_bearer_flag_does_not_warn(
        self, monkeypatch, capsys
    ):
        """An ambient env MCP_BEARER_TOKEN displaced by -H must NOT warn — the
        warning is gated on an EXPLICIT --bearer-token (bearer_from_flag)."""
        monkeypatch.setenv("MCP_BEARER_TOKEN", "env-tok")
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "-H",
                    "Authorization: Bearer override",
                ],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        headers = mock_run.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer override"
        assert "overrides --bearer-token" not in capsys.readouterr().err

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

    def test_check_with_oauth_skips_relay_callbacks(self, monkeypatch):
        """: on the one-shot --check probe the relay 401/403
        recovery callbacks are not built (check_connection never uses them)."""
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "--oauth", "--check", "https://example.com/mcp"],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.check_connection", return_value=True),
            patch("mcp_stdio.cli._build_token_refresher") as mock_refresher,
            patch("mcp_stdio.cli._build_scope_upgrader") as mock_upgrader,
        ):
            mock_ensure.return_value.access_token = "tok"
            with pytest.raises(SystemExit):
                main()
        assert not mock_refresher.called
        assert not mock_upgrader.called

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

    def test_explicit_empty_client_id_without_oauth_warns(self, monkeypatch, capsys):
        """: an explicit `--client-id ''` (falsy) without an OAuth
        flow now trips the OAuth-only warning — the gate is presence-based
        (`is not None`), matching the --bearer-token discipline."""
        monkeypatch.delenv("MCP_OAUTH_CLIENT_ID", raising=False)
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "--client-id", "", "https://example.com/mcp"],
            ),
            patch("mcp_stdio.cli.run"),
        ):
            main()
        assert "ignored without --oauth" in capsys.readouterr().err


class TestHttpsUrlWithPath:
    """#60: argparse type validating a Client ID Metadata Document URL
    (draft-ietf-oauth-client-id-metadata-document-00 §3)."""

    def test_valid_url_accepted(self):
        url = "https://example.com/client.json"
        assert _https_url_with_path(url) == url

    @pytest.mark.parametrize(
        "bad",
        [
            "http://example.com/client.json",  # not https
            "https://example.com",  # no path
            "https://example.com/",  # root path only
            "https://example.com/a/./b",  # single-dot segment
            "https://example.com/a/../b",  # double-dot segment
            "https://example.com/client.json#frag",  # fragment
            "https://user:pass@example.com/client.json",  # userinfo
            "https://:pass@example.com/client.json",  # password-only userinfo
            "not a url",
        ],
    )
    def test_invalid_url_rejected(self, bad):
        with pytest.raises(argparse.ArgumentTypeError):
            _https_url_with_path(bad)


class TestClientMetadataUrlFlag:
    """#60: --client-metadata-url CLI wiring."""

    def test_ignored_without_oauth_warns(self, capsys):
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--client-metadata-url",
                    "https://app.example.com/client.json",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.cli.run"),
        ):
            main()
        assert "ignored without --oauth" in capsys.readouterr().err

    def test_no_warning_with_oauth(self, capsys):
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--client-metadata-url",
                    "https://app.example.com/client.json",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert "ignored without --oauth" not in capsys.readouterr().err

    def test_both_client_id_and_metadata_url_warns_precedence(self, capsys):
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--client-id",
                    "cid",
                    "--client-metadata-url",
                    "https://app.example.com/client.json",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        err = capsys.readouterr().err
        assert "the pre-registered client_id takes precedence" in err

    def test_ambient_env_client_id_warns_and_wins_over_metadata_url(
        self, monkeypatch, capsys
    ):
        """An ambient MCP_OAUTH_CLIENT_ID (no --client-id flag) is also a
        pre-registered client_id and must trip the precedence warning — a
        presence-only check on args.client_id missed this and let the env var
        silently override --client-metadata-url with zero diagnostic."""
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "env-cid")
        url = "https://app.example.com/client.json"
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--client-metadata-url",
                    url,
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["client_id"] == "env-cid"
        assert mock_ensure.call_args.kwargs["client_metadata_url"] == url
        assert (
            "the pre-registered client_id takes precedence" in capsys.readouterr().err
        )

    def test_empty_explicit_client_id_does_not_warn_and_metadata_url_wins(
        self, monkeypatch, capsys
    ):
        """An explicit but EMPTY --client-id '' is falsy, so --client-metadata-url
        is what's actually used — the precedence warning must not fire here
        (it previously fired with text claiming the opposite of what happens)."""
        monkeypatch.delenv("MCP_OAUTH_CLIENT_ID", raising=False)
        url = "https://app.example.com/client.json"
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--client-id",
                    "",
                    "--client-metadata-url",
                    url,
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["client_id"] is None
        assert mock_ensure.call_args.kwargs["client_metadata_url"] == url
        assert "takes precedence" not in capsys.readouterr().err

    def test_invalid_url_rejected_at_parse_time(self, capsys):
        with patch(
            "sys.argv",
            [
                "mcp-stdio",
                "--oauth",
                "--client-metadata-url",
                "http://example.com/client.json",
                "https://example.com/mcp",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        assert "must be an https" in capsys.readouterr().err

    def test_forwarded_to_ensure_token(self):
        url = "https://app.example.com/client.json"
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--client-metadata-url",
                    url,
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["client_metadata_url"] == url

    def test_max_message_size_forwarded_to_the_direct_oauth_client(self):
        """#419: the client _main() builds itself for the initial
        ensure_token() call (warm/--check path, not one of the
        _build_*-wrapped background callbacks) also gets the configured
        cap, not just --max-message-size's default."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--max-message-size",
                    "1000",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        client_arg = mock_ensure.call_args.args[1]
        assert getattr(client_arg, _MAX_MESSAGE_SIZE_ATTR, None) == 1000

    def test_forwarded_to_cold_start_login(self):
        """#296 + #60: a cold cache defers to _build_cold_start_login, which
        must also receive client_metadata_url so the background login uses it."""
        url = "https://app.example.com/client.json"
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--oauth-eager",
                    "--client-metadata-url",
                    url,
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token", return_value=None),
            patch("mcp_stdio.cli._build_cold_start_login") as mock_builder,
            patch("mcp_stdio.cli.run"),
        ):
            mock_builder.return_value = lambda: None
            main()
        assert mock_builder.call_args.kwargs["client_metadata_url"] == url

    def test_max_message_size_forwarded_to_cold_start_login(self):
        """#419: --max-message-size reaches the cold-start OAuth client too,
        not just the main MCP traffic (#416/#417)."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--oauth-eager",
                    "--max-message-size",
                    "1000",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token", return_value=None),
            patch("mcp_stdio.cli._build_cold_start_login") as mock_builder,
            patch("mcp_stdio.cli.run"),
        ):
            mock_builder.return_value = lambda: None
            main()
        assert mock_builder.call_args.kwargs["max_message_size"] == 1000

    def test_max_message_size_forwarded_to_refresher_and_upgrader(self):
        """#419: --max-message-size reaches the mid-session token-refresh
        and scope-upgrade OAuth clients too."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--max-message-size",
                    "1000",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli._build_token_refresher") as mock_refresher,
            patch("mcp_stdio.cli._build_scope_upgrader") as mock_upgrader,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_refresher.call_args.kwargs["max_message_size"] == 1000
        assert mock_upgrader.call_args.kwargs["max_message_size"] == 1000

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

    def test_oauth_token_with_control_char_exits(self, monkeypatch, capsys):
        """: an OAuth-acquired access_token carrying CR/LF/NUL (a
        compromised/malicious AS smuggling control chars) must fail startup
        (exit 1), not split request headers on the wire. Covers the initial-flow
        header-build guard, distinct from the --bearer-token and refresher paths."""
        monkeypatch.setattr(
            "mcp_stdio.oauth.ensure_token",
            lambda *a, **k: TokenData(access_token="tok\nInjected: x"),
        )
        with patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]):
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
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp", "--check"]),
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

    def test_check_forwards_max_message_size(self):
        """#417 review R1F3: --check is not a carve-out for --max-message-size."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "--check",
                    "--max-message-size",
                    "1000",
                ],
            ),
            patch("mcp_stdio.cli.check_connection", return_value=True) as mock_check,
        ):
            with pytest.raises(SystemExit):
                main()
            assert mock_check.call_args.kwargs["max_message_size"] == 1000

    def test_test_flag_deprecated_alias_works(self, capsys):
        """--test still works for backward compatibility but emits a deprecation warning."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp", "--test"]),
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
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp", "--check"]),
            patch("mcp_stdio.cli.check_connection", return_value=True),
        ):
            with pytest.raises(SystemExit):
                main()
            captured = capsys.readouterr()
            assert "deprecated" not in captured.err

    def test_check_flag_failure_exits_nonzero(self):
        """--check exits with code 1 when check_connection returns False."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp", "--check"]),
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

    def test_proactive_refresh_default_on(self):
        """#242: proactive refresh is ON by default → run() sees True."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["proactive_refresh"] is True

    def test_proactive_refresh_opt_out(self):
        """#242: --no-proactive-refresh flips the flag to False."""
        with (
            patch(
                "sys.argv",
                ["mcp-stdio", "https://example.com/mcp", "--no-proactive-refresh"],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["proactive_refresh"] is False

    def test_proactive_refresh_passed_to_run_sse(self):
        """#242: --no-proactive-refresh reaches run_sse on the sse transport."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "--transport",
                    "sse",
                    "--no-proactive-refresh",
                ],
            ),
            patch("mcp_stdio.cli.run_sse") as mock_run_sse,
        ):
            main()
        assert mock_run_sse.call_args.kwargs["proactive_refresh"] is False

    def test_refresh_leeway_default_passed_to_run(self):
        """#242: the default --oauth-refresh-leeway (60) reaches run()."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["refresh_leeway"] == 60.0

    def test_refresh_leeway_custom_passed_to_run(self):
        """#242: an explicit --oauth-refresh-leeway value reaches run()."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "https://example.com/mcp",
                    "--oauth-refresh-leeway",
                    "30",
                ],
            ),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["refresh_leeway"] == 30.0

    def test_token_expiry_getter_none_without_oauth(self):
        """#242: without --oauth there is no expiry getter (timer is a no-op)."""
        with (
            patch("sys.argv", ["mcp-stdio", "https://example.com/mcp"]),
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            main()
        assert mock_run.call_args.kwargs["token_expiry_getter"] is None

    def test_token_expiry_getter_built_with_oauth(self):
        """#242: --oauth builds an expiry getter and passes it to run()."""
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run") as mock_run,
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        getter = mock_run.call_args.kwargs["token_expiry_getter"]
        assert getter is not None and callable(getter)

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

    def test_oauth_resource_passes_value(self):
        """--oauth-resource propagates the value to ensure_token as oauth_resource."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--oauth-resource",
                    "api://app-id-guid",
                    "https://example.com/mcp",
                ],
            ),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["oauth_resource"] == "api://app-id-guid"

    def test_oauth_resource_default_none(self):
        """Without --oauth-resource, oauth_resource=None reaches ensure_token."""
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch("mcp_stdio.oauth.ensure_token") as mock_ensure,
            patch("mcp_stdio.cli.run"),
        ):
            mock_ensure.return_value.access_token = "tok"
            main()
        assert mock_ensure.call_args.kwargs["oauth_resource"] is None

    def test_oauth_resource_conflicts_with_no_resource_indicator(self, capsys):
        """--oauth-resource and --no-resource-indicator are mutually exclusive."""
        with (
            patch(
                "sys.argv",
                [
                    "mcp-stdio",
                    "--oauth",
                    "--no-resource-indicator",
                    "--oauth-resource",
                    "api://x",
                    "https://example.com/mcp",
                ],
            ),
            pytest.raises(SystemExit),
        ):
            main()
        assert "mutually exclusive" in capsys.readouterr().err

    def test_oauth_resource_validator_accepts_app_id_uri(self):
        from mcp_stdio.cli import _rfc8707_resource

        assert _rfc8707_resource("api://app-id-guid") == "api://app-id-guid"

    def test_oauth_resource_validator_rejects_fragment(self):
        import argparse

        from mcp_stdio.cli import _rfc8707_resource

        with pytest.raises(argparse.ArgumentTypeError):
            _rfc8707_resource("api://x#frag")

    def test_oauth_resource_validator_rejects_relative(self):
        import argparse

        from mcp_stdio.cli import _rfc8707_resource

        with pytest.raises(argparse.ArgumentTypeError):
            _rfc8707_resource("not-a-uri")


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

    def test_refresh_token_with_control_char_degrades_to_none(
        self, monkeypatch, capsys
    ):
        """: a refreshed token carrying CR/LF/NUL must NOT reach the
        wire — the refresher degrades to None (relay emits an auth error) rather
        than building an injectable Authorization header."""
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)
        monkeypatch.setattr(
            "mcp_stdio.oauth.refresh_cached_token",
            lambda url, client: TokenData(access_token="bad\r\nX-Inject: 1"),
        )
        refresher = _build_token_refresher("https://example.com/mcp", {}, 10, 120)
        assert refresher() is None
        assert _SpyClient.instances[-1].closed
        assert "token refresh failed" in capsys.readouterr().err

    def test_returns_none_on_refresh_failure_and_closes(self, monkeypatch):
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)
        monkeypatch.setattr(
            "mcp_stdio.oauth.refresh_cached_token", lambda url, client: None
        )
        refresher = _build_token_refresher("https://example.com/mcp", {}, 10, 120)
        assert refresher() is None
        assert _SpyClient.instances[-1].closed

    def test_does_not_alias_live_headers_dict(self, monkeypatch):
        """: the callback layers Authorization onto a build-time
        FROZEN copy of the base headers, not the live shared dict the SSE reader
        thread also holds. Mutating the caller's dict after build must not affect
        the callback's output — proving the live object is never iterated
        unlocked from the callback (no cross-thread aliasing)."""
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)
        monkeypatch.setattr(
            "mcp_stdio.oauth.refresh_cached_token",
            lambda url, client: TokenData(access_token="fresh"),
        )
        live = {"X-Base": "1"}
        refresher = _build_token_refresher("https://example.com/mcp", live, 10, 120)
        # Mutate the live dict AFTER build, as the relay main loop's
        # headers.update would (concurrently with the reader thread).
        live["X-Base"] = "MUTATED"
        live["X-New"] = "added"
        out = refresher()
        # Output reflects the frozen build-time snapshot, not the mutation.
        assert out["X-Base"] == "1"
        assert "X-New" not in out
        assert out["Authorization"] == "Bearer fresh"

    def test_returns_none_when_refresh_raises_and_closes(self, monkeypatch, capsys):
        """A refresh that RAISES (e.g. save_token re-raising OSError on a
        read-only disk) must degrade to None — not crash the relay mid-session
        — and still close the client. Symmetric with the upgrader."""
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)

        def boom(url, client):
            raise OSError("read-only file system")

        monkeypatch.setattr("mcp_stdio.oauth.refresh_cached_token", boom)
        refresher = _build_token_refresher("https://example.com/mcp", {}, 10, 120)
        assert refresher() is None
        assert _SpyClient.instances[-1].closed
        assert "token refresh failed" in capsys.readouterr().err


class TestBuildScopeUpgrader:
    """The upgrader closure runs RFC 9470 step-up and returns broader-scope
    headers; like the refresher, it catches exceptions and degrades to None."""

    def test_returns_bearer_headers_and_closes_client(self, monkeypatch):
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)
        captured = {}

        def fake_step_up(url, client, scope, *, timeout):
            captured["timeout"] = timeout
            return TokenData(access_token="upgraded")

        monkeypatch.setattr("mcp_stdio.oauth.step_up_authorize", fake_step_up)
        upgrader = _build_scope_upgrader(
            "https://example.com/mcp", {"X-Base": "1"}, 10, 120, 90
        )
        out = upgrader("hr:read hr:write")
        assert out["Authorization"] == "Bearer upgraded"
        assert out["X-Base"] == "1"
        assert _SpyClient.instances[-1].closed
        # --oauth-timeout must reach the mid-session step-up too,
        # not just the cold-start ensure_token — otherwise a step-up silently
        # falls back to step_up_authorize's hardcoded 120 s default.
        assert captured["timeout"] == 90
        # the RFC 9470 step-up path carries the same credential-leak
        # exposure as refresh, so its client must pin follow_redirects=False too
        # (an AS-controlled token endpoint could otherwise 302 the credential POST
        # to a cleartext / cross-origin host). Symmetric with the refresher test.
        assert _SpyClient.instances[-1].kwargs.get("follow_redirects") is False

    def test_does_not_alias_live_headers_dict(self, monkeypatch):
        """: like the refresher, the upgrader layers Authorization
        onto a build-time frozen copy of the base headers, not the live shared
        dict. Mutating the caller's dict after build must not affect output."""
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)
        monkeypatch.setattr(
            "mcp_stdio.oauth.step_up_authorize",
            lambda url, client, scope, *, timeout: TokenData(access_token="upgraded"),
        )
        live = {"X-Base": "1"}
        upgrader = _build_scope_upgrader("https://example.com/mcp", live, 10, 120, 90)
        live["X-Base"] = "MUTATED"
        live["X-New"] = "added"
        out = upgrader("hr:read")
        assert out["X-Base"] == "1"
        assert "X-New" not in out
        assert out["Authorization"] == "Bearer upgraded"

    def test_returns_none_when_step_up_raises_and_closes(self, monkeypatch, capsys):
        _SpyClient.instances.clear()
        monkeypatch.setattr("mcp_stdio.cli.httpx.Client", _SpyClient)

        def boom(url, client, scope, *, timeout):
            raise RuntimeError("step-up denied")

        monkeypatch.setattr("mcp_stdio.oauth.step_up_authorize", boom)
        upgrader = _build_scope_upgrader("https://example.com/mcp", {}, 10, 120, 90)
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

    def test_keyboard_interrupt_during_oauth_exits_130(self, capsys):
        """: Ctrl-C during the pre-relay OAuth flow (before run()
        installs signal handlers) exits cleanly with 130, not a raw
        KeyboardInterrupt traceback. KeyboardInterrupt is a BaseException, so the
        OAuth block's `except Exception` does not catch it — main()'s top-level
        handler must."""
        with (
            patch("sys.argv", ["mcp-stdio", "--oauth", "https://example.com/mcp"]),
            patch(
                "mcp_stdio.oauth.ensure_token",
                side_effect=KeyboardInterrupt(),
            ),
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 130
        assert "interrupted" in capsys.readouterr().err


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
