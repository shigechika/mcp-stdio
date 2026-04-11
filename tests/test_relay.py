"""Tests for mcp_stdio.relay module."""

import json
from io import StringIO
from unittest.mock import patch

import httpx

from mcp_stdio.relay import (
    _error_response,
    _extract_id,
    _post_and_stream,
    run,
)


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

    def test_401_without_refresher_passes_through(self, httpx_mock):
        # 401 without token_refresher should not crash
        httpx_mock.add_response(
            status_code=401,
            text="",
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"init","id":1}'],
        )
        # No output because 401 is non-200 and no refresher
        assert output.strip() == ""
