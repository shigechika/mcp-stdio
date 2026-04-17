"""Tests for mcp_stdio.relay module."""

import json
import queue
import threading
import time
from io import StringIO
from unittest.mock import patch

import httpx
import pytest
from pytest_httpx import IteratorStream

from mcp_stdio.relay import (
    MAX_LIST_PAGES,
    PAGINATED_LIST_METHODS,
    _SseState,
    _detect_paginated_list,
    _enforce_lf_stdio,
    _error_response,
    _extract_id,
    _parse_www_authenticate_scope,
    _post_and_stream,
    _sse_reader_loop,
    check_connection,
    run,
    run_sse,
)


# --- _enforce_lf_stdio ---


class TestEnforceLfStdio:
    """Guard against python-sdk#2433: CRLF translation on Windows stdio."""

    def test_noop_on_posix(self):
        """On non-Windows, reconfigure() must NOT be called."""
        mock_stdin = type("S", (), {"reconfigure": lambda self, **kw: None})()
        mock_stdout = type("S", (), {"reconfigure": lambda self, **kw: None})()
        calls = []
        mock_stdin.reconfigure = lambda **kw: calls.append(("stdin", kw))
        mock_stdout.reconfigure = lambda **kw: calls.append(("stdout", kw))
        with (
            patch("mcp_stdio.relay.sys.platform", "darwin"),
            patch("mcp_stdio.relay.sys.stdin", mock_stdin),
            patch("mcp_stdio.relay.sys.stdout", mock_stdout),
        ):
            _enforce_lf_stdio()
        assert calls == []

    def test_reconfigures_on_windows(self):
        """On Windows, both stdin and stdout must be reconfigured to newline=''."""
        calls = []

        class FakeStream:
            def reconfigure(self, **kw):
                calls.append(kw)

        with (
            patch("mcp_stdio.relay.sys.platform", "win32"),
            patch("mcp_stdio.relay.sys.stdin", FakeStream()),
            patch("mcp_stdio.relay.sys.stdout", FakeStream()),
        ):
            _enforce_lf_stdio()
        assert calls == [{"newline": ""}, {"newline": ""}]

    def test_windows_without_reconfigure_is_tolerated(self):
        """Some redirected streams lack reconfigure(); must not raise."""

        class BareStream:
            # Intentionally no reconfigure attribute
            pass

        with (
            patch("mcp_stdio.relay.sys.platform", "win32"),
            patch("mcp_stdio.relay.sys.stdin", BareStream()),
            patch("mcp_stdio.relay.sys.stdout", BareStream()),
        ):
            _enforce_lf_stdio()  # should not raise


# --- _extract_id ---


class TestExtractId:
    def test_numeric_id(self):
        line = json.dumps({"jsonrpc": "2.0", "method": "init", "id": 1})
        assert _extract_id(line) == 1

    def test_string_id(self):
        line = json.dumps({"jsonrpc": "2.0", "method": "init", "id": "abc"})
        assert _extract_id(line) == "abc"

    def test_null_id(self):
        line = json.dumps({"jsonrpc": "2.0", "method": "init", "id": None})
        assert _extract_id(line) is None

    def test_missing_id(self):
        line = json.dumps({"jsonrpc": "2.0", "method": "notify"})
        assert _extract_id(line) is None

    def test_invalid_json(self):
        assert _extract_id("not json") is None

    def test_empty_string(self):
        assert _extract_id("") is None

    def test_json_array(self):
        assert _extract_id("[1, 2, 3]") is None


# --- _error_response ---


class TestErrorResponse:
    def test_basic_error(self):
        result = json.loads(_error_response("something failed", req_id=1))
        assert result["jsonrpc"] == "2.0"
        assert result["error"]["code"] == -32000
        assert result["error"]["message"] == "something failed"
        assert result["id"] == 1

    def test_null_id(self):
        result = json.loads(_error_response("err"))
        assert result["id"] is None

    def test_string_id(self):
        result = json.loads(_error_response("err", req_id="req-42"))
        assert result["id"] == "req-42"


# --- _post_and_stream ---


class TestPostAndStream:
    def test_success_json(self, httpx_mock, capsys):
        httpx_mock.add_response(
            json={"jsonrpc": "2.0", "result": {}, "id": 1},
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        result = _post_and_stream(client, "https://example.com/mcp", '{"id":1}', {}, 1)
        assert result is not None
        assert result.status_code == 200

    def test_returns_none_after_max_retries(self, httpx_mock):
        for _ in range(3):
            httpx_mock.add_exception(httpx.ConnectError("refused"))
        client = httpx.Client()
        with patch("mcp_stdio.relay.time.sleep"):
            result = _post_and_stream(client, "https://example.com/mcp", '{"id":1}', {}, 1)
        assert result is None

    def test_non_200_returns_status(self, httpx_mock):
        httpx_mock.add_response(
            status_code=404, text="", headers={"content-type": "application/json"}
        )
        client = httpx.Client()
        result = _post_and_stream(client, "https://example.com/mcp", '{"id":1}', {}, 1)
        assert result is not None
        assert result.status_code == 404


# --- run (integration) ---


class TestRun:
    def _run_with_stdin(self, httpx_mock, stdin_lines, **kwargs):
        """Helper to run the relay with mocked stdin and capture stdout."""
        stdin_data = "\n".join(stdin_lines) + "\n"
        stdout = StringIO()
        with patch("sys.stdin", StringIO(stdin_data)), patch("sys.stdout", stdout):
            run(
                "https://example.com/mcp",
                {"Content-Type": "application/json"},
                **kwargs,
            )
        return stdout.getvalue()

    def test_json_response(self, httpx_mock):
        body = '{"jsonrpc":"2.0","result":{},"id":1}'
        httpx_mock.add_response(
            text=body,
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(httpx_mock, ['{"jsonrpc":"2.0","method":"init","id":1}'])
        assert json.loads(output.strip()) == json.loads(body)

    def test_sse_response(self, httpx_mock):
        sse_body = 'data: {"jsonrpc":"2.0","result":{},"id":1}\n\n'
        httpx_mock.add_response(
            text=sse_body,
            headers={"content-type": "text/event-stream"},
        )
        output = self._run_with_stdin(httpx_mock, ['{"jsonrpc":"2.0","method":"init","id":1}'])
        assert json.loads(output.strip())["id"] == 1

    def test_empty_lines_skipped(self, httpx_mock):
        body = '{"jsonrpc":"2.0","result":{},"id":1}'
        httpx_mock.add_response(
            text=body,
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock, ["", '{"jsonrpc":"2.0","method":"init","id":1}', ""]
        )
        assert json.loads(output.strip())["id"] == 1

    def test_session_id_tracking(self, httpx_mock):
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-123",
            },
        )
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
            ],
        )
        lines = [x for x in output.strip().splitlines() if x]
        assert len(lines) == 2

        # Verify second request included session header
        req2 = httpx_mock.get_requests()[1]
        assert req2.headers["mcp-session-id"] == "sess-123"

    def test_session_expired_triggers_reinitialize_then_retry(self, httpx_mock):
        """Reproduces the 404 -> 400 hang from FastMCP StreamableHTTP.

        Before the fix, mcp-stdio cleared the session_id on 404 and just
        re-sent the original request — but FastMCP requires an initialize
        handshake on each new session, so the retry came back 400 and the
        caller hung. The fix sends an initialize to establish a new
        session first, then replays the original request with it.
        """
        # Request 1: init — server assigns sess-old
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-old",
            },
        )
        # Request 2: tool call with sess-old — server returns 404 (expired)
        httpx_mock.add_response(
            status_code=404,
            text="",
            headers={"content-type": "application/json"},
        )
        # Request 3: _reinitialize sends a fresh initialize — server assigns sess-new
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":0}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-new",
            },
        )
        # Request 4: _reinitialize sends notifications/initialized with sess-new
        httpx_mock.add_response(status_code=202, text="")
        # Request 5: original tool call replayed with sess-new — server returns result
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":2}',
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
            ],
        )
        lines = [x for x in output.strip().splitlines() if x]
        # stdout gets the two original responses (init + call); the re-initialize
        # handshake is internal and should not leak to stdout.
        assert len(lines) == 2
        assert json.loads(lines[1])["result"] == {"ok": True}

        requests = httpx_mock.get_requests()
        assert len(requests) == 5

        # Request 2 (the call) still carried sess-old before the 404
        assert requests[1].headers.get("mcp-session-id") == "sess-old"

        # Request 3 is the re-initialize: no session header, body is initialize
        assert "mcp-session-id" not in requests[2].headers
        init_body = json.loads(requests[2].content)
        assert init_body["method"] == "initialize"

        # Request 4 is notifications/initialized with sess-new
        assert requests[3].headers.get("mcp-session-id") == "sess-new"
        notif_body = json.loads(requests[3].content)
        assert notif_body["method"] == "notifications/initialized"
        assert "id" not in notif_body  # notifications must not carry an id

        # Request 5 is the replayed tool call, now with sess-new
        assert requests[4].headers.get("mcp-session-id") == "sess-new"
        replay_body = json.loads(requests[4].content)
        assert replay_body["method"] == "call"
        assert replay_body["id"] == 2

    def test_reinitialize_failure_returns_error(self, httpx_mock):
        """If the post-404 re-initialize fails, we surface a JSON-RPC error
        instead of silently dropping the original request."""
        # Request 1: init
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-old",
            },
        )
        # Request 2: tool call -> 404
        httpx_mock.add_response(status_code=404, text="")
        # Request 3: re-initialize also fails (server still broken)
        httpx_mock.add_response(status_code=500, text="")

        output = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
            ],
        )
        lines = [x for x in output.strip().splitlines() if x]
        # First response goes through, second is an error reply (not a hang)
        assert len(lines) == 2
        err = json.loads(lines[1])
        assert err["id"] == 2
        assert err["error"]["code"] == -32000
        assert "session lost" in err["error"]["message"]

    def test_reinitialize_notifications_initialized_failure_returns_error(
        self, httpx_mock
    ):
        """If the initialize succeeds but the notifications/initialized step
        fails, we treat the whole re-init as failed and surface an error."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-old",
            },
        )
        httpx_mock.add_response(status_code=404, text="")
        # Initialize succeeds — server assigns sess-new
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":0}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-new",
            },
        )
        # notifications/initialized fails
        httpx_mock.add_response(status_code=500, text="")

        output = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
            ],
        )
        lines = [x for x in output.strip().splitlines() if x]
        assert len(lines) == 2
        err = json.loads(lines[1])
        assert err["id"] == 2
        assert err["error"]["code"] == -32000
        assert "session lost" in err["error"]["message"]

    def test_request_failure_returns_error(self, httpx_mock):
        for _ in range(3):
            httpx_mock.add_exception(httpx.ConnectError("refused"))
        with patch("mcp_stdio.relay.time.sleep"):
            output = self._run_with_stdin(httpx_mock, ['{"jsonrpc":"2.0","method":"init","id":5}'])
        result = json.loads(output.strip())
        assert result["error"]["code"] == -32000
        assert result["id"] == 5

    def test_401_triggers_token_refresh(self, httpx_mock):
        # First request returns 401
        httpx_mock.add_response(
            status_code=401,
            text="",
            headers={"content-type": "application/json"},
        )
        # Retry after refresh succeeds
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":1}',
            headers={"content-type": "application/json"},
        )

        def mock_refresher():
            return {
                "Content-Type": "application/json",
                "Authorization": "Bearer new-token",
            }

        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"init","id":1}'],
            token_refresher=mock_refresher,
        )
        result = json.loads(output.strip())
        assert result["result"]["ok"] is True
        # Verify retry used new token
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        assert requests[1].headers["authorization"] == "Bearer new-token"

    def test_401_refresh_failure_returns_error(self, httpx_mock):
        httpx_mock.add_response(
            status_code=401,
            text="",
            headers={"content-type": "application/json"},
        )

        def mock_refresher():
            return None  # refresh failed

        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"init","id":1}'],
            token_refresher=mock_refresher,
        )
        result = json.loads(output.strip())
        assert result["error"]["message"] == "authentication failed"
        assert result["id"] == 1

    @pytest.mark.parametrize("status_code", [400, 404, 409, 422, 500, 502, 503, 504])
    def test_unhandled_error_status_surfaces_jsonrpc_error(
        self, httpx_mock, status_code
    ):
        """#11: every 4xx/5xx the relay can't recover from must still produce
        one JSON-RPC error on stdout so the MCP client never hangs waiting."""
        httpx_mock.add_response(
            status_code=status_code,
            text="",
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"init","id":42}'],
        )
        result = json.loads(output.strip())
        assert result["error"]["message"] == f"HTTP {status_code}"
        assert result["id"] == 42

    def test_401_refresh_then_retry_500_emits_error(self, httpx_mock):
        """#11 sentinel: a successful token refresh followed by a 5xx on the
        retry must still surface a JSON-RPC error. Proves the fall-through
        error block fires on post-recovery failures, not just first-pass."""
        # 1st: 401 triggers refresh
        httpx_mock.add_response(
            status_code=401,
            text="",
            headers={"content-type": "application/json"},
        )
        # 2nd (after refresh): 500 — must surface as JSON-RPC error
        httpx_mock.add_response(
            status_code=500,
            text="",
            headers={"content-type": "application/json"},
        )

        def mock_refresher():
            return {
                "Content-Type": "application/json",
                "Authorization": "Bearer refreshed",
            }

        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"tools/call","id":7}'],
            token_refresher=mock_refresher,
        )
        result = json.loads(output.strip())
        assert result["error"]["message"] == "HTTP 500"
        assert result["id"] == 7
        # Refresh was attempted (second request used the new bearer)
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        assert requests[1].headers["authorization"] == "Bearer refreshed"

    def test_202_notification_produces_no_stdout(self, httpx_mock):
        """#11: 202 Accepted (MCP notification ack) is intentionally silent."""
        httpx_mock.add_response(
            status_code=202,
            text="",
            headers={"content-type": "application/json"},
        )
        # Notification has no id
        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"notifications/initialized"}'],
        )
        assert output.strip() == ""

    def test_401_without_refresher_emits_error(self, httpx_mock):
        """#11: unhandled non-2xx must never produce a silent stdin hang."""
        httpx_mock.add_response(
            status_code=401,
            text="",
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"init","id":1}'],
        )
        result = json.loads(output.strip())
        assert result["error"]["message"] == "HTTP 401"
        assert result["id"] == 1


# --- step-up authorization (anthropics/claude-code#44652) ---


class TestParseWwwAuthenticateScope:
    """Parse RFC 9470 insufficient_scope challenges."""

    def test_quoted_scope_and_error(self):
        header = 'Bearer error="insufficient_scope", scope="mcp:read hr:read"'
        assert _parse_www_authenticate_scope(header) == "mcp:read hr:read"

    def test_unquoted_scope(self):
        header = "Bearer error=insufficient_scope, scope=mcp:read"
        assert _parse_www_authenticate_scope(header) == "mcp:read"

    def test_with_realm_and_description(self):
        header = (
            'Bearer realm="mcp", error="insufficient_scope", '
            'scope="hr:read hr:write", '
            'error_description="tool requires HR access"'
        )
        assert _parse_www_authenticate_scope(header) == "hr:read hr:write"

    def test_invalid_token_error_not_triggered(self):
        """Regular 401 invalid_token challenges should not trigger step-up."""
        header = 'Bearer error="invalid_token", scope="mcp:read"'
        assert _parse_www_authenticate_scope(header) is None

    def test_insufficient_scope_without_scope_param(self):
        """Challenge missing the scope parameter is unusable for step-up."""
        header = 'Bearer error="insufficient_scope"'
        assert _parse_www_authenticate_scope(header) is None

    def test_empty_or_none(self):
        assert _parse_www_authenticate_scope(None) is None
        assert _parse_www_authenticate_scope("") is None

    def test_non_bearer_challenge_ignored(self):
        """Basic / Digest challenges must not be misread as Bearer."""
        header = 'Basic realm="private"'
        assert _parse_www_authenticate_scope(header) is None


class TestStepUpScopeChallenge:
    """403 insufficient_scope handling in run()."""

    URL = "https://example.com/mcp"

    def _run_with_stdin(self, httpx_mock, stdin_lines, **kwargs):
        stdin_data = "\n".join(stdin_lines) + "\n"
        stdout = StringIO()
        with patch("sys.stdin", StringIO(stdin_data)), patch("sys.stdout", stdout):
            run(
                self.URL,
                {"Content-Type": "application/json"},
                **kwargs,
            )
        return stdout.getvalue()

    def test_403_triggers_scope_upgrader_and_retries(self, httpx_mock):
        """Happy path: 403 insufficient_scope → step-up → retry succeeds."""
        httpx_mock.add_response(
            url=self.URL,
            status_code=403,
            text="",
            headers={
                "content-type": "application/json",
                "www-authenticate": (
                    'Bearer error="insufficient_scope", '
                    'scope="mcp:read hr:read"'
                ),
            },
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","result":{"data":"ok"},"id":1}',
            headers={"content-type": "application/json"},
        )

        seen_scopes: list[str] = []

        def mock_upgrader(required_scope: str):
            seen_scopes.append(required_scope)
            return {
                "Content-Type": "application/json",
                "Authorization": "Bearer upgraded-token",
            }

        output = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                '"params":{"name":"get_salary"}}'
            ],
            scope_upgrader=mock_upgrader,
        )

        result = json.loads(output.strip())
        assert result["result"]["data"] == "ok"
        # Upgrader was invoked with the challenge scope verbatim
        assert seen_scopes == ["mcp:read hr:read"]
        # Retry used the upgraded bearer
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        assert requests[1].headers["authorization"] == "Bearer upgraded-token"

    def test_403_without_insufficient_scope_emits_error(self, httpx_mock):
        """Plain 403 (non-scope challenge) must not invoke the upgrader but
        must still surface an error to the client (#11)."""
        httpx_mock.add_response(
            url=self.URL,
            status_code=403,
            text="",
            headers={"content-type": "application/json"},
        )

        called = []

        def mock_upgrader(_scope: str):
            called.append(True)
            return {"Authorization": "Bearer should-not-be-used"}

        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","id":1,"method":"tools/call"}'],
            scope_upgrader=mock_upgrader,
        )

        # Upgrader was not called — no scope challenge present
        assert called == []
        # But the error was surfaced, not silently dropped
        result = json.loads(output.strip())
        assert result["error"]["message"] == "HTTP 403"
        assert result["id"] == 1
        assert len(httpx_mock.get_requests()) == 1

    def test_403_without_upgrader_emits_error(self, httpx_mock):
        """If scope_upgrader is not configured, 403 surfaces as an error (#11)."""
        httpx_mock.add_response(
            url=self.URL,
            status_code=403,
            text="",
            headers={
                "content-type": "application/json",
                "www-authenticate": (
                    'Bearer error="insufficient_scope", scope="mcp:read"'
                ),
            },
        )

        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","id":1,"method":"tools/call"}'],
        )
        result = json.loads(output.strip())
        assert result["error"]["message"] == "HTTP 403"
        assert result["id"] == 1
        assert len(httpx_mock.get_requests()) == 1

    def test_upgrader_failure_returns_error(self, httpx_mock):
        """If the upgrader returns None (e.g. user aborted), emit an error."""
        httpx_mock.add_response(
            url=self.URL,
            status_code=403,
            text="",
            headers={
                "content-type": "application/json",
                "www-authenticate": (
                    'Bearer error="insufficient_scope", scope="mcp:read"'
                ),
            },
        )

        def mock_upgrader(_scope: str):
            return None

        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","id":1,"method":"tools/call"}'],
            scope_upgrader=mock_upgrader,
        )
        err = json.loads(output.strip())
        assert err["error"]["message"] == "authorization failed"
        assert err["id"] == 1
        # No retry issued after upgrader failure
        assert len(httpx_mock.get_requests()) == 1


# --- auto-pagination (anthropics/claude-code#39586) ---


class TestDetectPaginatedList:
    @pytest.mark.parametrize(
        "method,result_key",
        list(PAGINATED_LIST_METHODS.items()),
    )
    def test_detects_each_paginated_method(self, method, result_key):
        line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method})
        assert _detect_paginated_list(line) == (method, result_key)

    def test_non_paginated_method_returns_none(self):
        line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call"})
        assert _detect_paginated_list(line) is None

    def test_explicit_cursor_opts_out(self):
        """Client that drives pagination itself must get raw passthrough."""
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {"cursor": "client-driven"},
            }
        )
        assert _detect_paginated_list(line) is None

    def test_empty_params_dict_is_paginated(self):
        line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )
        assert _detect_paginated_list(line) == ("tools/list", "tools")

    def test_malformed_json_returns_none(self):
        assert _detect_paginated_list("not json") is None

    def test_non_object_returns_none(self):
        assert _detect_paginated_list("[1,2,3]") is None


class TestPagination:
    """Auto-pagination for MCP list methods (claude-code#39586)."""

    URL = "https://example.com/mcp"

    def _run_with_stdin(self, httpx_mock, stdin_lines, **kwargs):
        stdin_data = "\n".join(stdin_lines) + "\n"
        stdout = StringIO()
        with patch("sys.stdin", StringIO(stdin_data)), patch("sys.stdout", stdout):
            run(
                self.URL,
                {"Content-Type": "application/json"},
                **kwargs,
            )
        return stdout.getvalue()

    @pytest.mark.parametrize(
        "method,result_key",
        list(PAGINATED_LIST_METHODS.items()),
    )
    def test_three_pages_merged_into_one(self, httpx_mock, method, result_key):
        """Response from 3 paginated pages is merged into a single response."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                result_key: [{"name": "a"}, {"name": "b"}],
                "nextCursor": "p2",
            },
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                result_key: [{"name": "c"}],
                "nextCursor": "p3",
            },
        }
        page3 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {result_key: [{"name": "d"}, {"name": "e"}]},
        }
        for page in (page1, page2, page3):
            httpx_mock.add_response(
                url=self.URL,
                text=json.dumps(page),
                headers={"content-type": "application/json"},
            )

        request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method})
        output = self._run_with_stdin(httpx_mock, [request])

        lines = [x for x in output.strip().splitlines() if x]
        assert len(lines) == 1
        merged = json.loads(lines[0])
        assert merged["id"] == 1
        assert "nextCursor" not in merged["result"]
        names = [item["name"] for item in merged["result"][result_key]]
        assert names == ["a", "b", "c", "d", "e"]

        # Verify cursor was threaded through requests
        requests = httpx_mock.get_requests()
        assert len(requests) == 3
        assert "cursor" not in json.loads(requests[0].content).get("params", {})
        assert json.loads(requests[1].content)["params"]["cursor"] == "p2"
        assert json.loads(requests[2].content)["params"]["cursor"] == "p3"

    def test_single_page_passthrough(self, httpx_mock):
        """A list response without nextCursor still produces exactly one POST."""
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "only"}]},
        }
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(body),
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        assert merged["result"]["tools"] == [{"name": "only"}]
        assert len(httpx_mock.get_requests()) == 1

    def test_client_supplied_cursor_is_not_auto_paginated(self, httpx_mock):
        """Passing ``cursor`` explicitly opts out of auto-pagination."""
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{"name": "a"}],
                "nextCursor": "p2",  # would be followed if auto-paginating
            },
        }
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(body),
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                        "params": {"cursor": "client-driven"},
                    }
                )
            ],
        )
        raw = json.loads(output.strip())
        # nextCursor must be preserved — client is handling pagination itself
        assert raw["result"]["nextCursor"] == "p2"
        # Exactly one request, with the client-supplied cursor
        requests = httpx_mock.get_requests()
        assert len(requests) == 1
        assert json.loads(requests[0].content)["params"]["cursor"] == "client-driven"

    def test_sse_response_is_paginated(self, httpx_mock):
        """Pagination works when the server responds with SSE framing."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "nextCursor": "p2"},
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}]},
        }
        httpx_mock.add_response(
            url=self.URL,
            text=f"data: {json.dumps(page1)}\n\n",
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=f"data: {json.dumps(page2)}\n\n",
            headers={"content-type": "text/event-stream"},
        )

        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        assert [t["name"] for t in merged["result"]["tools"]] == ["a", "b"]

    def test_page_cap_truncates_runaway_cursor(self, httpx_mock, monkeypatch):
        """An endless cursor chain is bounded by MAX_LIST_PAGES."""
        # Lower the cap to keep the test fast while exercising the branch.
        monkeypatch.setattr("mcp_stdio.relay.MAX_LIST_PAGES", 3)

        def make_page(n: int) -> str:
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "tools": [{"name": f"t{n}"}],
                        "nextCursor": f"p{n + 1}",  # never terminates
                    },
                }
            )

        # Register exactly MAX_LIST_PAGES responses. If the implementation
        # forgot the cap it would send a 4th request and fail with an
        # unmatched httpx_mock response.
        for n in range(1, 4):
            httpx_mock.add_response(
                url=self.URL,
                text=make_page(n),
                headers={"content-type": "application/json"},
            )

        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        names = [t["name"] for t in merged["result"]["tools"]]
        assert names == ["t1", "t2", "t3"]  # exactly MAX_LIST_PAGES pages
        assert len(httpx_mock.get_requests()) == 3

    def test_mid_flow_error_returns_partial_result(self, httpx_mock):
        """Page N>=2 HTTP error returns the pages collected so far."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "ok1"}], "nextCursor": "p2"},
        }
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(page1),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            status_code=500,
            text="",
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        assert [t["name"] for t in merged["result"]["tools"]] == ["ok1"]
        assert "nextCursor" not in merged["result"]

    def test_first_page_401_triggers_token_refresh(self, httpx_mock):
        """401 on page 1 must go through the normal refresh path."""
        # First attempt: 401 — triggers refresh
        httpx_mock.add_response(
            url=self.URL,
            status_code=401,
            text="",
            headers={"content-type": "application/json"},
        )
        # After refresh: page 1 returns one item, no more pages
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "after-refresh"}]},
        }
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(page1),
            headers={"content-type": "application/json"},
        )

        def mock_refresher():
            return {
                "Content-Type": "application/json",
                "Authorization": "Bearer new-token",
            }

        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
            token_refresher=mock_refresher,
        )
        merged = json.loads(output.strip())
        assert merged["result"]["tools"] == [{"name": "after-refresh"}]
        requests = httpx_mock.get_requests()
        assert requests[1].headers["authorization"] == "Bearer new-token"

    def test_max_list_pages_constant_is_positive(self):
        """Sanity check on the shipped cap."""
        assert MAX_LIST_PAGES >= 1


# --- check_connection ---


class TestCheckConnection:
    URL = "https://example.com/mcp"
    HEADERS = {"Content-Type": "application/json"}

    def test_json_success(self, httpx_mock):
        """JSON initialize response with full capabilities."""
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "demo", "version": "1.2.3"},
                    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                },
            }
        )
        httpx_mock.add_response(
            text=body,
            headers={
                "content-type": "application/json",
                "mcp-session-id": "abc123",
            },
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True

    def test_sse_single_event(self, httpx_mock):
        """SSE response with one data: line."""
        body = (
            'data: {"jsonrpc":"2.0","id":1,"result":'
            '{"protocolVersion":"2024-11-05","serverInfo":{"name":"sse","version":"0.1"},'
            '"capabilities":{}}}\n\n'
        )
        httpx_mock.add_response(
            text=body,
            headers={"content-type": "text/event-stream"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True

    def test_sse_multiple_events_uses_first_valid(self, httpx_mock):
        """Multiple SSE events — parser takes the first valid data: line and stops."""
        body = (
            ": ping\n"
            "data: not-json\n\n"
            'data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}\n\n'
            'data: {"jsonrpc":"2.0","id":2,"result":{"unrelated":true}}\n\n'
        )
        httpx_mock.add_response(
            text=body,
            headers={"content-type": "text/event-stream"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True

    def test_non_200_returns_false(self, httpx_mock):
        httpx_mock.add_response(status_code=500, text="oops")
        assert check_connection(self.URL, dict(self.HEADERS)) is False

    def test_non_200_does_not_leak_body_to_stderr(self, httpx_mock, capsys):
        """#16: response body must not appear in --check stderr output.

        Error bodies regularly contain session IDs, stack traces, or
        echoed request data, and --check logs are prone to retention
        in CI / aggregation pipelines.
        """
        secret = "session=SENSITIVE-sess-id-echoed-in-500-page"
        httpx_mock.add_response(status_code=500, text=secret)
        check_connection(self.URL, dict(self.HEADERS))
        captured = capsys.readouterr()
        assert secret not in captured.err
        # Status code is still logged — that's the operational signal
        assert "HTTP 500" in captured.err

    def test_unauthorized_returns_false(self, httpx_mock):
        httpx_mock.add_response(status_code=401, text="nope")
        assert check_connection(self.URL, dict(self.HEADERS)) is False

    def test_mcp_error_returns_false(self, httpx_mock):
        """JSON-RPC error object in body → False."""
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "boom"}}
        )
        httpx_mock.add_response(
            text=body,
            headers={"content-type": "application/json"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is False

    def test_malformed_json_body_still_true(self, httpx_mock):
        """Body isn't valid JSON — HTTP 200 is enough to report the server as reachable."""
        httpx_mock.add_response(
            text="{not valid json",
            headers={"content-type": "application/json"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True

    def test_missing_result_and_error_still_true(self, httpx_mock):
        """Parsed body has neither result nor error — treated as reachable."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","id":1}',
            headers={"content-type": "application/json"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True

    def test_connect_error_returns_false(self, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        assert check_connection(self.URL, dict(self.HEADERS)) is False

    def test_session_id_header_logged(self, httpx_mock, capsys):
        """When the server returns mcp-session-id header, it should appear in stderr logs."""
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        )
        httpx_mock.add_response(
            text=body,
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-xyz",
            },
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True
        captured = capsys.readouterr()
        assert "sess-xyz" in captured.err


# --- SSE transport ---


class TestSseReaderLoop:
    """Unit tests for _sse_reader_loop (the reader thread body)."""

    URL = "https://example.com/sse"

    def _run_reader(self, httpx_mock, sse_bytes, state=None):
        """Run the reader loop against a finite SSE stream.

        Arranges for the loop to exit after consuming the provided
        bytes by setting state.stop at end-of-stream via a tail chunk.
        """
        if state is None:
            state = _SseState()

        def gen():
            for chunk in sse_bytes:
                yield chunk
            state.stop.set()

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(gen()),
            headers={"content-type": "text/event-stream"},
        )

        client = httpx.Client()
        stdout = StringIO()
        try:
            with patch("sys.stdout", stdout):
                _sse_reader_loop(client, self.URL, {}, state)
        finally:
            client.close()

        return state, stdout.getvalue()

    def test_endpoint_event_is_parsed(self, httpx_mock):
        state, _ = self._run_reader(
            httpx_mock,
            [b"event: endpoint\ndata: /messages?sessionId=abc\n\n"],
        )
        assert state.endpoint_url == "https://example.com/messages?sessionId=abc"
        assert state.ready.is_set()

    def test_absolute_endpoint_url(self, httpx_mock):
        state, _ = self._run_reader(
            httpx_mock,
            [b"event: endpoint\ndata: https://other.example.com/post\n\n"],
        )
        assert state.endpoint_url == "https://other.example.com/post"

    def test_message_event_relayed_to_stdout(self, httpx_mock):
        payload = '{"jsonrpc":"2.0","result":{},"id":1}'
        _, stdout = self._run_reader(
            httpx_mock,
            [
                b"event: endpoint\ndata: /messages?sessionId=abc\n\n",
                f"event: message\ndata: {payload}\n\n".encode(),
            ],
        )
        lines = [x for x in stdout.strip().splitlines() if x]
        assert lines == [payload]

    def test_comment_lines_ignored(self, httpx_mock):
        payload = '{"jsonrpc":"2.0","result":{},"id":2}'
        _, stdout = self._run_reader(
            httpx_mock,
            [
                b": keepalive comment\n\n"
                b"event: endpoint\ndata: /post\n\n"
                b": another comment\n"
                + f"event: message\ndata: {payload}\n\n".encode(),
            ],
        )
        assert payload in stdout

    def test_default_event_type_is_message(self, httpx_mock):
        """SSE spec: lines with only `data:` default to the `message` event."""
        payload = '{"jsonrpc":"2.0","result":{},"id":3}'
        _, stdout = self._run_reader(
            httpx_mock,
            [
                b"event: endpoint\ndata: /post\n\n",
                f"data: {payload}\n\n".encode(),
            ],
        )
        assert payload in stdout

    def test_non_200_status_sets_ready_and_returns(self, httpx_mock):
        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            status_code=401,
        )
        state = _SseState()
        client = httpx.Client()
        try:
            _sse_reader_loop(client, self.URL, {}, state)
        finally:
            client.close()
        # ready is set so run_sse's wait() unblocks on the error path
        assert state.ready.is_set()
        # endpoint_url stays None to signal failure
        assert state.endpoint_url is None

    # --- WHATWG SSE spec compliance ---

    def test_multiline_data_joined_with_newline(self, httpx_mock):
        """WHATWG SSE spec: multiple ``data:`` fields in one event are
        concatenated with a single ``\\n`` between them."""
        _, stdout = self._run_reader(
            httpx_mock,
            [
                b"event: endpoint\ndata: /post\n\n",
                b"event: message\ndata: line1\ndata: line2\ndata: line3\n\n",
            ],
        )
        assert "line1\nline2\nline3" in stdout

    def test_crlf_line_endings(self, httpx_mock):
        """WHATWG SSE spec: ``\\r\\n`` is a valid line terminator alongside
        ``\\n`` and ``\\r``."""
        payload = '{"jsonrpc":"2.0","result":{},"id":1}'
        _, stdout = self._run_reader(
            httpx_mock,
            [
                b"event: endpoint\r\ndata: /post\r\n\r\n",
                f"event: message\r\ndata: {payload}\r\n\r\n".encode(),
            ],
        )
        assert payload in stdout

    def test_multiple_consecutive_messages(self, httpx_mock):
        """Several message events in a row should all reach stdout in order."""
        _, stdout = self._run_reader(
            httpx_mock,
            [
                b"event: endpoint\ndata: /post\n\n",
                b'event: message\ndata: {"id":1}\n\n',
                b'event: message\ndata: {"id":2}\n\n',
                b'event: message\ndata: {"id":3}\n\n',
            ],
        )
        lines = [x for x in stdout.strip().splitlines() if x]
        assert lines == ['{"id":1}', '{"id":2}', '{"id":3}']

    def test_unknown_event_type_ignored(self, httpx_mock):
        """Events with unknown types (e.g. keepalive/ping) must be silently
        dropped — they should not reach stdout."""
        _, stdout = self._run_reader(
            httpx_mock,
            [
                b"event: endpoint\ndata: /post\n\n",
                b"event: ping\ndata: heartbeat\n\n",
                b"event: keepalive\ndata: noise\n\n",
                b'event: message\ndata: {"id":1}\n\n',
            ],
        )
        lines = [x for x in stdout.strip().splitlines() if x]
        assert lines == ['{"id":1}']

    def test_event_without_data_not_dispatched(self, httpx_mock):
        """An event with no ``data:`` field should not produce any output."""
        _, stdout = self._run_reader(
            httpx_mock,
            [
                b"event: endpoint\ndata: /post\n\n",
                b"event: message\n\n",
                b'event: message\ndata: {"id":1}\n\n',
            ],
        )
        lines = [x for x in stdout.strip().splitlines() if x]
        assert lines == ['{"id":1}']

    # --- Real-world edge cases from mcp-remote issues ---

    def test_relative_endpoint_with_complex_query_string(self, httpx_mock):
        """mcp-remote#196: relative endpoint URLs with query strings must be
        preserved when resolved against the base URL. Missing sessionId in
        the POST URL caused Atlassian MCP connections to fail."""
        state, _ = self._run_reader(
            httpx_mock,
            [b"event: endpoint\ndata: /v1/messages/?sessionId=abc&token=xyz\n\n"],
        )
        assert (
            state.endpoint_url
            == "https://example.com/v1/messages/?sessionId=abc&token=xyz"
        )

    def test_jsonrpc_id_type_variations_passthrough(self, httpx_mock):
        """mcp-remote#194: JSON-RPC ``id`` can be number, string, or null —
        all must pass through the SSE reader unchanged. The relay does not
        parse or interpret ids; it forwards bytes verbatim to stdout."""
        _, stdout = self._run_reader(
            httpx_mock,
            [
                b"event: endpoint\ndata: /post\n\n",
                b'event: message\ndata: {"jsonrpc":"2.0","result":{},"id":1}\n\n',
                b'event: message\ndata: {"jsonrpc":"2.0","result":{},"id":"abc"}\n\n',
                b'event: message\ndata: {"jsonrpc":"2.0","result":{},"id":null}\n\n',
            ],
        )
        assert '"id":1' in stdout
        assert '"id":"abc"' in stdout
        assert '"id":null' in stdout


class _BlockingStdin:
    """Stdin iterator that yields one line then blocks until released.

    Keeps run_sse's main loop alive after the POST so the SSE reader
    thread has time to receive and print the response event. Once the
    release event is set, the iterator raises StopIteration and the
    main loop exits cleanly.
    """

    def __init__(self, line: str, release: threading.Event):
        self._line = line
        self._emitted = False
        self._release = release

    def __iter__(self):
        return self

    def __next__(self):
        if not self._emitted:
            self._emitted = True
            return self._line
        self._release.wait(timeout=5)
        raise StopIteration


class TestRunSse:
    """End-to-end tests for run_sse driven from the main thread."""

    URL = "https://example.com/sse"

    def test_endpoint_then_post_then_message(self, httpx_mock):
        payload = '{"jsonrpc":"2.0","result":{},"id":42}'
        post_received = threading.Event()
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=xyz\n\n"
            post_received.wait(timeout=3)
            yield f"event: message\ndata: {payload}\n\n".encode()
            time.sleep(0.1)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def post_callback(request):
            post_received.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            post_callback,
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"test","id":42}\n', release_stdin
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {})

        out = stdout.getvalue()
        assert payload in out

    def test_post_401_triggers_token_refresh(self, httpx_mock):
        """On POST 401, run_sse calls token_refresher and retries."""
        post_received = threading.Event()
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=xyz\n\n"
            post_received.wait(timeout=3)
            yield b'event: message\ndata: {"jsonrpc":"2.0","result":{},"id":1}\n\n'
            time.sleep(0.1)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        call_count = {"n": 0}

        def post_callback(request):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return httpx.Response(status_code=401)
            post_received.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            post_callback,
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
            is_reusable=True,
        )

        refresher_called = {"n": 0}

        def token_refresher():
            refresher_called["n"] += 1
            return {"Authorization": "Bearer new"}

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"test","id":1}\n', release_stdin
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {}, token_refresher=token_refresher)

        assert refresher_called["n"] == 1
        assert call_count["n"] == 2

    def test_post_non_success_returns_error_response(self, httpx_mock):
        """Non-200/202 POST status maps to a JSON-RPC error response."""
        post_received = threading.Event()
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=xyz\n\n"
            post_received.wait(timeout=3)
            time.sleep(0.1)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def post_callback(request):
            post_received.set()
            return httpx.Response(status_code=500)

        httpx_mock.add_callback(
            post_callback,
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"test","id":99}\n', release_stdin
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {})

        out = stdout.getvalue().strip()
        parsed = json.loads(out)
        assert parsed["error"]["message"] == "HTTP 500"
        assert parsed["id"] == 99
