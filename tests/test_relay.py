"""Tests for mcp_stdio.relay module."""

import email.utils
import json
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import patch

import httpx
import pytest
from pytest_httpx import IteratorStream

from mcp_stdio.relay import (
    MAX_LIST_PAGES,
    MAX_RETRIES,
    PAGINATED_LIST_METHODS,
    _CancelTracker,
    _SseState,
    _detect_paginated_list,
    _emit,
    _enforce_lf_stdio,
    _error_response,
    _escape_js_line_separators,
    _extract_cancel_id,
    _extract_id,
    _extract_protocol_version,
    _handle_rate_limit,
    _iter_sse_events,
    _iter_sse_lines,
    _make_httpx_transport,
    _normalize_null_arguments,
    _parse_retry_after,
    _parse_www_authenticate_scope,
    _post_and_stream,
    _same_origin,
    _split_sse_text,
    _sse_reader_loop,
    _tcp_keepalive_socket_options,
    _write_line,
    check_connection,
    run,
    run_sse,
)


# --- _write_line ---


class TestWriteLine:
    """Guard the NDJSON wire format against mid-line interleaving.

    run_sse writes to stdout from two threads (the SSE reader and the main
    loop). _write_line must emit each line's content and trailing newline
    as a single atomic write so a concurrent writer can never split a line.
    """

    class _RecordingStdout:
        """stdout stub recording every write() call argument verbatim.

        Guards the record list with its own lock so the test stays correct
        even under a free-threaded interpreter, independent of the
        system-under-test's _STDOUT_LOCK. Note: this test guards the
        single-write-per-line property — a revert to a two-call print()
        would surface as bare "\\n" fragments — not _STDOUT_LOCK itself,
        which protects the underlying buffered stream the stub does not model.
        """

        def __init__(self):
            self.writes = []
            self._lock = threading.Lock()

        def write(self, s):
            with self._lock:
                self.writes.append(s)

        def flush(self):
            pass

    def test_single_write_includes_newline(self):
        """Content and newline are written in one call, never as two writes."""
        out = self._RecordingStdout()
        with patch("mcp_stdio.relay.sys.stdout", out):
            _write_line('{"id":1}')
        assert out.writes == ['{"id":1}\n']

    def test_concurrent_writers_never_interleave(self):
        """Two threads hammering _write_line yield only whole, intact lines."""
        out = self._RecordingStdout()
        per_thread = 500
        expected = {
            f'{{"t":"{tag}","n":{i}}}\n'
            for tag in ("a", "b")
            for i in range(per_thread)
        }

        def writer(tag):
            for i in range(per_thread):
                _write_line(f'{{"t":"{tag}","n":{i}}}')

        with patch("mcp_stdio.relay.sys.stdout", out):
            threads = [
                threading.Thread(target=writer, args=(tag,))
                for tag in ("a", "b")
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        # Every recorded write is exactly one complete line — no bare "\n"
        # fragments (which a two-call print() would produce) and no partials.
        assert all(w.endswith("\n") and w.count("\n") == 1 for w in out.writes)
        assert set(out.writes) == expected
        assert len(out.writes) == 2 * per_thread


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

    @pytest.mark.parametrize(
        "exc",
        [
            httpx.ConnectTimeout("connect timed out"),
            httpx.PoolTimeout("pool timed out"),
            httpx.RemoteProtocolError("server disconnected mid-response"),
            httpx.WriteError("write failed"),
        ],
    )
    def test_all_transport_errors_are_retried_not_crashed(self, httpx_mock, exc):
        """ConnectTimeout/PoolTimeout/RemoteProtocolError/WriteError are transient
        TransportError subtypes — they must be retried, never propagate and crash
        the gateway."""
        httpx_mock.add_exception(exc)
        httpx_mock.add_response(
            json={"jsonrpc": "2.0", "result": {"ok": True}, "id": 1},
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        with patch("sys.stdout", StringIO()), patch("mcp_stdio.relay.time.sleep"):
            result = _post_and_stream(
                client, "https://example.com/mcp", '{"id":1}', {}, 1
            )
        assert result is not None and result.status_code == 200
        assert len(httpx_mock.get_requests()) == 2  # retried after the transient

    def test_non_200_returns_status(self, httpx_mock):
        httpx_mock.add_response(
            status_code=404, text="", headers={"content-type": "application/json"}
        )
        client = httpx.Client()
        result = _post_and_stream(client, "https://example.com/mcp", '{"id":1}', {}, 1)
        assert result is not None
        assert result.status_code == 404

    def test_sse_data_without_space_is_parsed(self, httpx_mock):
        """WHATWG SSE: ``data:`` needs no trailing space — a compliant server
        sending ``data:{...}`` must be relayed, not silently dropped."""
        payload = '{"jsonrpc":"2.0","result":{},"id":1}'
        httpx_mock.add_response(
            stream=IteratorStream([f"data:{payload}\n\n".encode()]),
            headers={"content-type": "text/event-stream"},
        )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            result = _post_and_stream(
                client, "https://example.com/mcp", '{"id":1}', {}, 1
            )
        assert result is not None and result.status_code == 200
        assert payload in stdout.getvalue()

    def test_sse_non_message_event_not_emitted(self, httpx_mock):
        """A ``data:``-bearing non-``message`` event (ping/keepalive) must not
        be forwarded to stdout as if it were a JSON-RPC message."""
        payload = '{"jsonrpc":"2.0","result":{},"id":1}'
        body = (
            b"event: ping\ndata: heartbeat\n\n"
            + f"event: message\ndata: {payload}\n\n".encode()
        )
        httpx_mock.add_response(
            stream=IteratorStream([body]),
            headers={"content-type": "text/event-stream"},
        )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            _post_and_stream(client, "https://example.com/mcp", '{"id":1}', {}, 1)
        lines = [x for x in stdout.getvalue().strip().splitlines() if x]
        assert lines == [payload]

    def test_sse_multiline_data_joined(self, httpx_mock):
        """Multiple ``data:`` fields of one event are joined with LF, not
        emitted as separate (invalid) stdout lines."""
        httpx_mock.add_response(
            stream=IteratorStream([b"event: message\ndata: a\ndata: b\ndata: c\n\n"]),
            headers={"content-type": "text/event-stream"},
        )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            _post_and_stream(client, "https://example.com/mcp", '{"id":1}', {}, 1)
        assert stdout.getvalue().strip() == "a\nb\nc"

    def test_sse_payload_with_raw_unicode_separators_not_corrupted(self, httpx_mock):
        """A spec-compliant server SSE-framing a JSON-RPC response whose string
        value contains a raw U+2028/U+2029/U+0085 must reach stdout whole — not
        torn in half by over-eager inbound line splitting."""
        seps = "\u2028\u2029\x85"  # escapes in source; raw chars go on the wire
        payload = json.dumps(
            {"jsonrpc": "2.0", "result": {"text": f"a{seps}b"}, "id": 1},
            ensure_ascii=False,
        )
        httpx_mock.add_response(
            stream=IteratorStream([f"data:{payload}\n\n".encode()]),
            headers={"content-type": "text/event-stream"},
        )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            _post_and_stream(client, "https://example.com/mcp", '{"id":1}', {}, 1)
        out = stdout.getvalue().strip()
        # One NDJSON line (split on LF, the wire delimiter); U+2028/U+2029 are
        # escaped (the JS line terminators that break clients) and the payload
        # round-trips losslessly to all three separators intact.
        assert len(out.split("\n")) == 1
        assert "\u2028" not in out and "\u2029" not in out  # outbound-escaped
        assert json.loads(out)["result"]["text"] == f"a{seps}b"

    def test_midstream_failure_does_not_retry_or_duplicate(self, httpx_mock):
        """A transient error AFTER a payload was delivered must not replay the
        non-idempotent POST (which would duplicate the response). Instead a
        single stream-interrupted error is emitted and no second POST runs."""
        delivered = '{"jsonrpc":"2.0","result":{},"id":1}'

        def gen():
            yield f"event: message\ndata: {delivered}\n\n".encode()
            raise httpx.ReadError("connection dropped mid-stream")

        httpx_mock.add_response(
            stream=IteratorStream(gen()),
            headers={"content-type": "text/event-stream"},
        )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout), patch("mcp_stdio.relay.time.sleep"):
            result = _post_and_stream(
                client, "https://example.com/mcp", '{"id":1}', {}, 1
            )
        # No retry: the POST was issued exactly once.
        assert len(httpx_mock.get_requests()) == 1
        # Caller sees "error already printed".
        assert result is None
        lines = [json.loads(x) for x in stdout.getvalue().strip().splitlines() if x]
        # The already-delivered payload, then exactly one synthesized error
        # for the same request id — never a duplicate of the payload.
        assert lines[0]["result"] == {}
        assert lines[1]["error"]["message"].startswith("upstream stream interrupted")
        assert lines[1]["id"] == 1
        assert len(lines) == 2

    def test_preoutput_failure_still_retries(self, httpx_mock):
        """A transient error BEFORE any output (e.g. JSON body read) is still
        safely retriable — the response had not begun streaming."""
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        httpx_mock.add_response(
            json={"jsonrpc": "2.0", "result": {"ok": True}, "id": 1},
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout), patch("mcp_stdio.relay.time.sleep"):
            result = _post_and_stream(
                client, "https://example.com/mcp", '{"id":1}', {}, 1
            )
        assert result is not None and result.status_code == 200
        assert len(httpx_mock.get_requests()) == 2  # retried after the connect error
        emitted = json.loads(stdout.getvalue().strip())
        assert emitted["result"] == {"ok": True}

    def test_decoding_error_is_caught_not_crashed(self, httpx_mock):
        """#1(round15) HIGH: a 200 whose body fails to decode (bad
        Content-Encoding) raises httpx.DecodingError — a SIBLING of
        TransportError, not a subclass. It must be caught (now via HTTPError) and
        retried/surfaced, never propagate out and crash the gateway."""
        import httpx as _httpx

        # Sanity: DecodingError is an HTTPError but NOT a TransportError.
        assert issubclass(_httpx.DecodingError, _httpx.HTTPError)
        assert not issubclass(_httpx.DecodingError, _httpx.TransportError)

        for _ in range(MAX_RETRIES):
            httpx_mock.add_response(
                status_code=200,
                headers={
                    "content-type": "application/json",
                    "content-encoding": "gzip",  # body is NOT gzip → DecodingError
                },
                content=b"this is not valid gzip",
            )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout), patch("mcp_stdio.relay.time.sleep"):
            result = _post_and_stream(
                client, "https://example.com/mcp", '{"id":1}', {}, 1, has_id=True
            )
        # Retried to exhaustion (not crashed) and a JSON-RPC error was synthesized.
        assert result is None
        assert len(httpx_mock.get_requests()) == MAX_RETRIES
        err = json.loads(stdout.getvalue().strip())
        assert err["id"] == 1 and "error" in err

    def test_notification_retry_exhaustion_emits_no_error(self, httpx_mock):
        """has_id=False (a notification): retry exhaustion must NOT synthesize an
        id:null error — a notification can never receive a response."""
        for _ in range(3):
            httpx_mock.add_exception(httpx.ConnectError("net down"))
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout), patch("mcp_stdio.relay.time.sleep"):
            result = _post_and_stream(
                client,
                "https://example.com/mcp",
                '{"jsonrpc":"2.0","method":"notifications/progress"}',
                {},
                None,
                has_id=False,
            )
        assert result is None
        assert stdout.getvalue() == ""  # no id:null error written

    def test_request_retry_exhaustion_still_emits_error(self, httpx_mock):
        """has_id=True (a request): retry exhaustion still synthesizes the error
        for the request id — the gate must not suppress legitimate responses."""
        for _ in range(3):
            httpx_mock.add_exception(httpx.ConnectError("net down"))
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout), patch("mcp_stdio.relay.time.sleep"):
            result = _post_and_stream(
                client, "https://example.com/mcp", '{"id":7}', {}, 7, has_id=True
            )
        assert result is None
        emitted = json.loads(stdout.getvalue().strip())
        assert emitted["id"] == 7
        assert "error" in emitted

    def test_notification_midstream_interrupt_emits_no_error(self, httpx_mock):
        """has_id=False: a mid-stream disconnect after partial delivery passes the
        already-emitted server payload through but synthesizes NO id:null error."""
        delivered = '{"jsonrpc":"2.0","method":"server/event","params":{}}'

        def gen():
            yield f"event: message\ndata: {delivered}\n\n".encode()
            raise httpx.ReadError("dropped mid-stream")

        httpx_mock.add_response(
            stream=IteratorStream(gen()),
            headers={"content-type": "text/event-stream"},
        )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout), patch("mcp_stdio.relay.time.sleep"):
            result = _post_and_stream(
                client,
                "https://example.com/mcp",
                '{"jsonrpc":"2.0","method":"x"}',
                {},
                None,
                has_id=False,
            )
        assert result is None
        lines = [x for x in stdout.getvalue().strip().splitlines() if x]
        # The server payload is passed through; no synthesized id:null error.
        assert lines == [delivered]

    def test_empty_200_body_to_request_synthesizes_error(self, httpx_mock):
        """#4(round11): a 200 with NO JSON-RPC payload would leave a
        request-with-id hanging; synthesize an error so the client recovers."""
        httpx_mock.add_response(
            status_code=200, text="", headers={"content-type": "application/json"}
        )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            result = _post_and_stream(
                client, "https://example.com/mcp", '{"id":3}', {}, 3, has_id=True
            )
        assert result is not None and result.status_code == 200
        err = json.loads(stdout.getvalue().strip())
        assert err["id"] == 3 and "error" in err

    def test_empty_200_body_to_notification_is_silent(self, httpx_mock):
        """A notification (has_id False) getting an empty 200 stays silent."""
        httpx_mock.add_response(
            status_code=200, text="", headers={"content-type": "application/json"}
        )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            _post_and_stream(
                client,
                "https://example.com/mcp",
                '{"jsonrpc":"2.0","method":"x"}',
                {},
                None,
                has_id=False,
            )
        assert stdout.getvalue() == ""


class TestSameOrigin:
    """RFC 6454 origin comparison used by the SSE cross-origin endpoint guard."""

    def test_identical_urls_same_origin(self):
        assert _same_origin("https://h.example/sse", "https://h.example/post")

    def test_explicit_default_port_folds(self):
        assert _same_origin("https://h.example:443/a", "https://h.example/b")
        assert _same_origin("http://h.example:80/a", "http://h.example/b")

    def test_host_case_insensitive(self):
        assert _same_origin("https://H.Example/a", "https://h.example/b")

    def test_different_host_is_cross_origin(self):
        assert not _same_origin("https://a.example/x", "https://b.example/x")

    def test_different_scheme_is_cross_origin(self):
        assert not _same_origin("http://h.example/x", "https://h.example/x")

    def test_different_explicit_port_is_cross_origin(self):
        assert not _same_origin("https://h.example:8443/x", "https://h.example/x")


class TestExtractProtocolVersion:
    """_extract_protocol_version reads result.protocolVersion from an
    InitializeResult, tolerating malformed / non-object inputs."""

    def test_extracts_from_initialize_result(self):
        payload = '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}'
        assert _extract_protocol_version(payload) == "2025-06-18"

    def test_missing_result_returns_none(self):
        assert _extract_protocol_version('{"jsonrpc":"2.0","id":1}') is None

    def test_result_without_protocol_version_returns_none(self):
        assert _extract_protocol_version('{"result":{"capabilities":{}}}') is None

    def test_non_object_result_returns_none(self):
        assert _extract_protocol_version('{"result":"oops"}') is None

    def test_batch_array_returns_none(self):
        assert _extract_protocol_version('[{"result":{"protocolVersion":"x"}}]') is None

    def test_malformed_json_returns_none(self):
        assert _extract_protocol_version("{not json") is None

    def test_non_string_protocol_version_returns_none(self):
        assert _extract_protocol_version('{"result":{"protocolVersion":123}}') is None


class TestIterSseEvents:
    """WHATWG Server-Sent Events line decoder shared by all SSE-decode sites."""

    def test_data_without_space(self):
        assert list(_iter_sse_events(["data:hello", ""])) == [("message", "hello")]

    def test_data_with_single_space_stripped(self):
        assert list(_iter_sse_events(["data: hello", ""])) == [("message", "hello")]

    def test_only_one_leading_space_stripped(self):
        # WHATWG strips exactly one U+0020; further spaces are part of the value.
        assert list(_iter_sse_events(["data:  hello", ""])) == [("message", " hello")]

    def test_default_event_type_is_message(self):
        assert list(_iter_sse_events(["data:x", ""])) == [("message", "x")]

    def test_event_type_tracked_and_reset(self):
        lines = ["event:ping", "data:a", "", "data:b", ""]
        assert list(_iter_sse_events(lines)) == [("ping", "a"), ("message", "b")]

    def test_multiline_data_joined_with_lf(self):
        assert list(_iter_sse_events(["data:a", "data:b", ""])) == [("message", "a\nb")]

    def test_comment_lines_ignored(self):
        assert list(_iter_sse_events([": keepalive", "data:a", ""])) == [
            ("message", "a")
        ]

    def test_id_and_retry_fields_ignored(self):
        """#10(round17): relay deliberately forgoes Last-Event-ID resumption and
        server-driven retry timing, so the WHATWG decoder must ignore `id:` and
        `retry:` lines (fall through the field dispatch) without disturbing the
        surrounding event — pins the documented ignore-and-continue behaviour."""
        lines = ["id: 5", "retry: 1000", "data: hi", ""]
        assert list(_iter_sse_events(lines)) == [("message", "hi")]
        # interleaved between data lines too — the data buffer is unaffected
        lines = ["data:a", "id: 7", "data:b", "retry: 200", ""]
        assert list(_iter_sse_events(lines)) == [("message", "a\nb")]

    def test_trailing_event_without_blank_line_flushed(self):
        # httpx may not surface a final empty line; a complete event must still
        # be dispatched at end of input.
        assert list(_iter_sse_events(["data:a"])) == [("message", "a")]

    def test_event_without_data_not_dispatched(self):
        assert list(_iter_sse_events(["event:message", ""])) == []

    def test_empty_data_value_not_dispatched(self):
        """#2(round14): WHATWG suppresses dispatch when the data buffer is the
        empty string — a bare `data:` must not yield a ('message', '') event."""
        assert list(_iter_sse_events(["data:", ""])) == []
        # event type set but only an empty data line → still suppressed.
        assert list(_iter_sse_events(["event: endpoint", "data:", ""])) == []
        # A trailing unterminated empty-data event is likewise not dispatched.
        assert list(_iter_sse_events(["data:"])) == []

    def test_nonempty_after_empty_data_lines_dispatched(self):
        """Mixed empty + non-empty data lines still dispatch (buffer non-empty)."""
        assert list(_iter_sse_events(["data:", "data:x", ""])) == [("message", "\nx")]

    def test_leading_bom_stripped(self):
        """#2(round13): WHATWG SSE stream-decode removes ONE leading U+FEFF BOM.
        A BOM-prefixed first line must still parse as its real field, so the
        critical first `endpoint` event is recognised, not misclassified.
        (BOM written as the "\\ufeff" escape — never a raw byte in source.)"""
        lines = ["\ufeff" + "event: endpoint", "data: /messages", ""]
        assert list(_iter_sse_events(lines)) == [("endpoint", "/messages")]

    def test_only_first_line_bom_stripped(self):
        """Only ONE leading BOM at the very start is removed — a stray U+FEFF on
        a later line is left as part of that field's content."""
        lines = ["data: a", "\ufeff" + "data: b", ""]
        # First line clean; the second line's BOM makes its field unrecognised
        # (not a `data` field), so only "a" is collected.
        assert list(_iter_sse_events(lines)) == [("message", "a")]

    def test_bom_via_split_sse_text(self):
        """End-to-end through _split_sse_text: a BOM-prefixed buffered body still
        yields the endpoint event."""
        body = "\ufeff" + "event: endpoint\ndata: /m\n\n"
        assert list(_iter_sse_events(_split_sse_text(body))) == [
            ("endpoint", "/m")
        ]


class TestSseLineSplitting:
    """SSE lines split on CR/LF/CRLF only — NOT the wider str.splitlines() set
    that would tear a JSON payload containing raw U+2028/U+2029/U+0085."""

    # U+2028 LINE SEP, U+2029 PARAGRAPH SEP, U+0085 NEL, plus VT/FF/FS/GS/RS —
    # all legal unescaped inside JSON strings (RFC 8259) but split by
    # str.splitlines(). Written as escapes; the raw chars exist only at runtime.
    SEPS = "\u2028\u2029\x85\x0b\x0c\x1c\x1d\x1e"

    def test_split_sse_text_only_cr_lf_crlf(self):
        assert _split_sse_text("a\r\nb\nc\rd") == ["a", "b", "c", "d"]

    def test_split_sse_text_preserves_unicode_separators(self):
        text = f'data:{{"t":"x{self.SEPS}y"}}\n\n'
        lines = _split_sse_text(text)
        # The separators stay inside the single data: line, not split out.
        assert lines[0] == f'data:{{"t":"x{self.SEPS}y"}}'

    def test_iter_sse_lines_only_cr_lf_crlf(self):
        assert list(_iter_sse_lines(["a\r", "\nb\n", "c"])) == ["a", "b", "c"]

    def test_iter_sse_lines_crlf_across_chunk_boundary(self):
        # A \r\n straddling two chunks must count as one terminator.
        assert list(_iter_sse_lines(["line1\r", "\nline2\n"])) == ["line1", "line2"]

    def test_iter_sse_lines_lone_cr_across_chunks(self):
        assert list(_iter_sse_lines(["line1\r", "line2"])) == ["line1", "line2"]

    def test_iter_sse_lines_preserves_unicode_separators(self):
        chunks = [f'data:{{"t":"x{self.SEPS}', 'y"}\n\n']
        lines = list(_iter_sse_lines(chunks))
        assert lines[0] == f'data:{{"t":"x{self.SEPS}y"}}'

    def test_iter_sse_lines_trailing_cr_at_eof(self):
        assert list(_iter_sse_lines(["abc\r"])) == ["abc"]


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

    def test_401_retry_exhaustion_preserves_session_id(self, httpx_mock):
        """#1(round11): a 401-refresh retry exhausted by a TRANSPORT error must
        PRESERVE the session id — the blip did not invalidate the session, so the
        next request still carries it (and could trigger 404 self-heal). Clearing
        it would defeat that recovery."""
        # 1: init -> establishes sess-1
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        # 2: call -> 401 (triggers refresh)
        httpx_mock.add_response(
            status_code=401, text="", headers={"content-type": "application/json"}
        )
        # 3-5: refreshed retry exhausts all retries with connection errors
        for _ in range(MAX_RETRIES):
            httpx_mock.add_exception(httpx.ConnectError("dead"))
        # 6: a later call -> 200 (must STILL carry the session header)
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":3}',
            headers={"content-type": "application/json"},
        )

        def refresher():
            return {"Authorization": "Bearer new"}

        with patch("mcp_stdio.relay.time.sleep"):
            self._run_with_stdin(
                httpx_mock,
                [
                    '{"jsonrpc":"2.0","method":"init","id":1}',
                    '{"jsonrpc":"2.0","method":"call","id":2}',
                    '{"jsonrpc":"2.0","method":"call","id":3}',
                ],
                token_refresher=refresher,
            )

        reqs = httpx_mock.get_requests()
        # The session id survives the transient exhaustion, not cleared.
        assert reqs[-1].headers.get("mcp-session-id") == "sess-1"

    def test_403_stepup_retry_exhaustion_preserves_session_id(self, httpx_mock):
        """#1(round11): a 403 step-up retry exhausted by a TRANSPORT error
        PRESERVES the session id (symmetric with the 401 path) so the next
        request still carries it and 404 self-heal stays possible."""
        # 1: init -> sess-1
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        # 2: call -> 403 insufficient_scope (triggers step-up)
        httpx_mock.add_response(
            status_code=403,
            text="",
            headers={
                "content-type": "application/json",
                "www-authenticate": 'Bearer error="insufficient_scope", scope="extra"',
            },
        )
        # 3-5: the upgraded retry exhausts all retries with connection errors
        for _ in range(MAX_RETRIES):
            httpx_mock.add_exception(httpx.ConnectError("dead"))
        # 6: a later call -> 200 (must STILL carry the session header)
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":3}',
            headers={"content-type": "application/json"},
        )

        def upgrader(_scope):
            return {"Authorization": "Bearer broader"}

        with patch("mcp_stdio.relay.time.sleep"):
            self._run_with_stdin(
                httpx_mock,
                [
                    '{"jsonrpc":"2.0","method":"init","id":1}',
                    '{"jsonrpc":"2.0","method":"call","id":2}',
                    '{"jsonrpc":"2.0","method":"call","id":3}',
                ],
                scope_upgrader=upgrader,
            )

        reqs = httpx_mock.get_requests()
        assert reqs[-1].headers.get("mcp-session-id") == "sess-1"

    def test_404_reinit_replay_retry_exhaustion_emits_error(self, httpx_mock):
        """#13: after a successful 404 re-initialize, if the replayed request
        itself exhausts retries, the client still gets a single JSON-RPC error
        (no hang) — the recovered session does not swallow the failure."""
        # 1: init -> sess-old
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-old",
            },
        )
        # 2: call -> 404 (session expired)
        httpx_mock.add_response(status_code=404, text="")
        # 3: re-initialize -> sess-new
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":0}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-new",
            },
        )
        # 4: notifications/initialized -> 202
        httpx_mock.add_response(status_code=202, text="")
        # 5-7: the replayed call exhausts all retries with connection errors
        for _ in range(MAX_RETRIES):
            httpx_mock.add_exception(httpx.ConnectError("dead"))

        with patch("mcp_stdio.relay.time.sleep"):
            output = self._run_with_stdin(
                httpx_mock,
                [
                    '{"jsonrpc":"2.0","method":"init","id":1}',
                    '{"jsonrpc":"2.0","method":"call","id":2}',
                ],
            )
        lines = [x for x in output.strip().splitlines() if x]
        # init response + one error for the replayed call that never recovered.
        assert len(lines) == 2
        err = json.loads(lines[1])
        assert err["id"] == 2 and "error" in err

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

    def test_reinitialize_missing_session_id_returns_error(self, httpx_mock):
        """#12: a re-initialize that returns 200 with a valid InitializeResult
        but NO mcp-session-id header (a plausible broken-server bug) must
        surface 'session lost', not silently continue without a session."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-old",
            },
        )
        httpx_mock.add_response(status_code=404, text="")
        # Re-initialize: 200 OK + valid result but the session header is missing.
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":0}',
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
        err = json.loads(lines[1])
        assert err["id"] == 2
        assert "session lost" in err["error"]["message"]

    def test_reinitialize_transport_error_returns_error(self, httpx_mock):
        """#12: a transport error on the re-initialize POST must surface
        'session lost' rather than crash the gateway."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-old",
            },
        )
        httpx_mock.add_response(status_code=404, text="")
        # Re-initialize POST itself raises a transport error.
        httpx_mock.add_exception(httpx.ConnectError("reinit dead"))

        with patch("mcp_stdio.relay.time.sleep"):
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

    def test_notification_drawing_4xx_gets_no_synthesized_response(self, httpx_mock):
        """A notification (no id) that a misbehaving server answers with 4xx must
        NOT receive a synthesized id:null error — notifications expect no reply."""
        httpx_mock.add_response(
            status_code=400, text="", headers={"content-type": "application/json"}
        )
        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"notifications/progress","params":{}}'],
        )
        assert output.strip() == ""

    def test_decoding_error_does_not_crash_loop(self, httpx_mock):
        """#1(round15) HIGH end-to-end: a request whose body fails to decode
        (bad Content-Encoding) must NOT crash run() — the client gets an error
        and the loop survives to process the next stdin line."""
        for _ in range(MAX_RETRIES):  # bad-gzip request 1 → DecodingError ×3
            httpx_mock.add_response(
                status_code=200,
                headers={
                    "content-type": "application/json",
                    "content-encoding": "gzip",
                },
                content=b"not gzip",
            )
        # request 2 succeeds — proves the loop kept going after the crash-y line.
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":2}',
            headers={"content-type": "application/json"},
        )
        with patch("mcp_stdio.relay.time.sleep"):
            output = self._run_with_stdin(
                httpx_mock,
                [
                    '{"jsonrpc":"2.0","method":"tools/call","id":1}',
                    '{"jsonrpc":"2.0","method":"tools/call","id":2}',
                ],
            )
        lines = [json.loads(x) for x in output.strip().splitlines() if x]
        ids = {m.get("id") for m in lines}
        assert 1 in ids and 2 in ids  # both answered; id=1 an error, id=2 a result
        assert any(m.get("id") == 1 and "error" in m for m in lines)
        assert any(m.get("id") == 2 and "result" in m for m in lines)

    def test_notification_404_reinit_failure_gets_no_response(self, httpx_mock):
        """#5(round14): a notification whose POST 404s (with a prior session) and
        whose _reinitialize then fails must produce NO id:null 'session lost'
        error — the req_has_id gate covers the 404 recovery branch."""
        # init -> sess-1
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        # notification -> 404 (session expired)
        httpx_mock.add_response(status_code=404, text="")
        # reinit initialize -> 500 (recovery fails)
        httpx_mock.add_response(status_code=500, text="")

        output = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"notifications/progress","params":{}}',
            ],
        )
        lines = [x for x in output.strip().splitlines() if x]
        assert len(lines) == 1  # only the init response; nothing for the notif
        assert json.loads(lines[0])["id"] == 1

    def test_notification_403_stepup_failure_gets_no_response(self, httpx_mock):
        """#5(round14): a notification whose POST 403s insufficient_scope and
        whose scope_upgrader returns None must produce no id:null error."""
        httpx_mock.add_response(
            status_code=403,
            text="",
            headers={
                "content-type": "application/json",
                "www-authenticate": 'Bearer error="insufficient_scope", scope="x"',
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"notifications/progress","params":{}}'],
            scope_upgrader=lambda _s: None,
        )
        assert output.strip() == ""

    def test_request_drawing_4xx_still_gets_error(self, httpx_mock):
        """A request (with id) that draws a 4xx still gets a JSON-RPC error."""
        httpx_mock.add_response(
            status_code=400, text="", headers={"content-type": "application/json"}
        )
        output = self._run_with_stdin(
            httpx_mock, ['{"jsonrpc":"2.0","method":"tools/call","id":5}']
        )
        parsed = json.loads(output.strip())
        assert parsed["id"] == 5 and "error" in parsed

    def test_request_with_falsy_id_zero_gets_error(self, httpx_mock):
        """#6: id 0 is a valid JSON-RPC id (not absent). A 4xx must produce an
        error carrying id:0 — id=0 must not be mis-treated as a notification by
        a falsy check."""
        httpx_mock.add_response(
            status_code=400, text="", headers={"content-type": "application/json"}
        )
        output = self._run_with_stdin(
            httpx_mock, ['{"jsonrpc":"2.0","method":"tools/call","id":0}']
        )
        parsed = json.loads(output.strip())
        assert parsed["id"] == 0 and "error" in parsed

    def test_batch_request_passes_through(self, httpx_mock):
        """#11: a JSON-RPC batch array is forwarded verbatim and its batch
        response relayed end-to-end through run()."""
        batch_resp = (
            '[{"jsonrpc":"2.0","result":{},"id":1},'
            '{"jsonrpc":"2.0","result":{},"id":2}]'
        )
        httpx_mock.add_response(
            text=batch_resp, headers={"content-type": "application/json"}
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                '[{"jsonrpc":"2.0","method":"a","id":1},'
                '{"jsonrpc":"2.0","method":"b","id":2}]'
            ],
        )
        assert json.loads(output.strip()) == json.loads(batch_resp)
        # The request reached the wire as a batch array, unchanged.
        sent = json.loads(httpx_mock.get_requests()[0].read())
        assert isinstance(sent, list) and len(sent) == 2

    def test_notification_transport_failure_gets_no_synthesized_response(
        self, httpx_mock
    ):
        """End-to-end: a notification whose POST exhausts all retries with a
        transport error must NOT receive a synthesized id:null error. This
        covers the helper-level gate (_post_and_stream has_id=False), one frame
        deeper than the loop-level 4xx gate above."""
        for _ in range(3):
            httpx_mock.add_exception(httpx.ConnectError("net down"))
        with patch("mcp_stdio.relay.time.sleep"):
            output = self._run_with_stdin(
                httpx_mock,
                ['{"jsonrpc":"2.0","method":"notifications/progress","params":{}}'],
            )
        assert output.strip() == ""

    def test_request_transport_failure_still_gets_error(self, httpx_mock):
        """Contrast with the notification case: a request that exhausts retries
        with a transport error still receives its JSON-RPC error response."""
        for _ in range(3):
            httpx_mock.add_exception(httpx.ConnectError("net down"))
        with patch("mcp_stdio.relay.time.sleep"):
            output = self._run_with_stdin(
                httpx_mock, ['{"jsonrpc":"2.0","method":"tools/call","id":9}']
            )
        parsed = json.loads(output.strip())
        assert parsed["id"] == 9 and "error" in parsed

    def test_401_retry_returns_404_cascades_into_reinitialize(self, httpx_mock):
        """The documented cross-branch cascade: a 401 whose refreshed retry
        returns 404 flows into the 404 re-initialize branch and recovers."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        # tools/call -> 401
        httpx_mock.add_response(
            status_code=401, text="", headers={"content-type": "application/json"}
        )
        # refreshed retry -> 404 (session expired)
        httpx_mock.add_response(
            status_code=404, text="", headers={"content-type": "application/json"}
        )
        # reinit initialize -> sess-2
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":0}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-2"},
        )
        httpx_mock.add_response(status_code=202, text="")  # reinit initialized
        # final retry -> 200
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":2}',
            headers={"content-type": "application/json"},
        )

        def refresher():
            return {"Authorization": "Bearer new"}

        output = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2}',
            ],
            token_refresher=refresher,
        )
        lines = [json.loads(x) for x in output.strip().splitlines() if x]
        # The cascade must deliver the final result, not a synthesized error.
        assert any(m.get("result") == {"ok": True} for m in lines)
        # The retried call after reinit carried the recovered session id.
        reqs = httpx_mock.get_requests()
        assert reqs[-1].headers.get("mcp-session-id") == "sess-2"

    def test_401_response_rotated_session_id_used_on_retry(self, httpx_mock):
        """If the server assigns a NEW Mcp-Session-Id on the 401 response, the
        refreshed retry must carry it, not the stale/absent one."""
        # 1: init -> session sess-1
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        # 2: call -> 401 AND rotates the session id to sess-2
        httpx_mock.add_response(
            status_code=401,
            text="",
            headers={"content-type": "application/json", "mcp-session-id": "sess-2"},
        )
        # 3: refreshed retry -> 200
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":2}',
            headers={"content-type": "application/json"},
        )

        def mock_refresher():
            return {"Authorization": "Bearer new"}

        self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
            ],
            token_refresher=mock_refresher,
        )
        reqs = httpx_mock.get_requests()
        # The refreshed retry (req 2) must carry the rotated session id.
        assert reqs[2].headers.get("mcp-session-id") == "sess-2"

    def test_chained_401_then_403_adopts_rotated_session_id(self, httpx_mock):
        """#1(round12): a 401 whose refreshed retry returns 403 + a ROTATED
        session id must have the step-up retry carry that rotated id — the
        session adoption must repeat across chained recovery branches, not only
        on the original response."""
        # 1: init -> sess-1
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        # 2: call -> 401 (triggers refresh)
        httpx_mock.add_response(
            status_code=401, text="", headers={"content-type": "application/json"}
        )
        # 3: refreshed retry -> 403 insufficient_scope AND rotates to sess-2
        httpx_mock.add_response(
            status_code=403,
            text="",
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-2",
                "www-authenticate": 'Bearer error="insufficient_scope", scope="extra"',
            },
        )
        # 4: step-up retry -> 200
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":2}',
            headers={"content-type": "application/json"},
        )

        self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
            ],
            token_refresher=lambda: {"Authorization": "Bearer new"},
            scope_upgrader=lambda _s: {"Authorization": "Bearer broader"},
        )
        reqs = httpx_mock.get_requests()
        # The step-up retry (req 3) must carry the id rotated on the 401 retry.
        assert reqs[3].headers.get("mcp-session-id") == "sess-2"

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

    # 429 and 503 are excluded: both are Retry-After carriers the relay
    # retries (see the dedicated 503 tests below), not unrecoverable codes.
    @pytest.mark.parametrize("status_code", [400, 404, 409, 422, 500, 502, 504])
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

    def test_202_to_request_with_id_synthesizes_error(self, httpx_mock):
        """#4(round16): a non-compliant 202 to a REQUEST (with id) on Streamable
        HTTP delivers no body and no async reply, so the relay must synthesize a
        JSON-RPC error instead of leaving the client hanging — unlike the silent
        202-to-notification case above."""
        httpx_mock.add_response(
            status_code=202,
            text="",
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"tools/call","id":7}'],
        )
        result = json.loads(output.strip())
        assert result["id"] == 7
        assert "202" in result["error"]["message"]

    def test_unexpected_exception_degrades_to_error_not_crash(
        self, httpx_mock, monkeypatch
    ):
        """#1(round17): an unexpected non-httpx exception escaping dispatch must
        degrade THIS request to a JSON-RPC error and keep the stdin loop alive —
        the 'never crash the gateway' contract is structural, not per-helper."""
        import mcp_stdio.relay as relay_mod

        real = relay_mod._post_and_stream
        calls = {"n": 0}

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated unexpected bug in dispatch")
            return real(*a, **k)

        monkeypatch.setattr("mcp_stdio.relay._post_and_stream", flaky)
        # Only the SECOND line reaches the network (the first raises before it).
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":2}',
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"tools/call","id":1}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2}',
            ],
        )
        msgs = [json.loads(x) for x in output.strip().splitlines() if x]
        # First request degraded to an internal error (not an uncaught crash).
        assert any(
            m.get("id") == 1
            and "internal relay error" in m.get("error", {}).get("message", "")
            for m in msgs
        ), f"expected an internal-error response for id 1, got {msgs!r}"
        # The loop survived: the second request was still processed normally.
        assert any(
            m.get("id") == 2 and m.get("result", {}).get("ok") for m in msgs
        ), f"loop did not survive to process id 2, got {msgs!r}"

    def test_unexpected_exception_on_notification_stays_silent(
        self, httpx_mock, monkeypatch
    ):
        """#1(round17): the same guard must NOT synthesize an id:null response
        for a notification (no id) that triggers an unexpected error — it logs
        and continues silently."""
        monkeypatch.setattr(
            "mcp_stdio.relay._post_and_stream",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        )
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


# --- MCP-Protocol-Version header (spec rev 2025-06-18, issue #69) ---


class TestProtocolVersionHeader:
    """Capture the negotiated protocol version and inject it on subsequent requests.

    Per the Streamable HTTP spec (2025-06-18, "Protocol Version Header"), after
    initialization the client MUST send MCP-Protocol-Version on every subsequent
    request. mcp-stdio captures result.protocolVersion from the InitializeResult
    and injects it; the initialize POST itself carries no header.
    """

    def _run_with_stdin(self, stdin_lines):
        stdin_data = "\n".join(stdin_lines) + "\n"
        stdout = StringIO()
        with patch("sys.stdin", StringIO(stdin_data)), patch("sys.stdout", stdout):
            run("https://example.com/mcp", {"Content-Type": "application/json"})
        return stdout.getvalue()

    def test_captures_version_and_injects_on_subsequent_request(self, httpx_mock):
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":1}',
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2}',
            ]
        )
        # Capture is read-only: the initialize response must still reach stdout.
        msgs = [json.loads(x) for x in output.strip().splitlines() if x]
        assert any(
            m.get("result", {}).get("protocolVersion") == "2025-06-18" for m in msgs
        )
        reqs = httpx_mock.get_requests()
        # initialize itself carries no header (version not yet negotiated)
        assert "mcp-protocol-version" not in reqs[0].headers
        # the next request carries the negotiated version
        assert reqs[1].headers["mcp-protocol-version"] == "2025-06-18"

    def test_user_pinned_header_survives_cold_start_initialize(self, httpx_mock):
        """#12(round16): on a cold-start initialize (version not yet negotiated)
        a user-supplied -H MCP-Protocol-Version is deliberately preserved on the
        initialize POST (relay.py only strips its OWN injected header once a
        version is captured). The next request then carries the relay-injected
        NEGOTIATED version, not the pinned one. Guards the `protocol_version is
        not None` gate against a regression that stripped the cold-start header."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":1}',
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        stdin_data = (
            '{"jsonrpc":"2.0","method":"initialize","id":1}\n'
            '{"jsonrpc":"2.0","method":"tools/call","id":2}\n'
        )
        stdout = StringIO()
        with patch("sys.stdin", StringIO(stdin_data)), patch("sys.stdout", stdout):
            run(
                "https://example.com/mcp",
                {
                    "Content-Type": "application/json",
                    "MCP-Protocol-Version": "2024-11-05",
                },
            )
        reqs = httpx_mock.get_requests()
        # (a) the cold-start initialize keeps the user's pinned version
        assert reqs[0].headers["mcp-protocol-version"] == "2024-11-05"
        # (b) the next request carries the relay-injected negotiated version
        assert reqs[1].headers["mcp-protocol-version"] == "2025-06-18"

    def test_initialized_notification_carries_header(self, httpx_mock):
        """notifications/initialized is the first subsequent request — must carry it."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":1}',
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(status_code=202, text="")
        self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            ]
        )
        reqs = httpx_mock.get_requests()
        assert reqs[1].headers["mcp-protocol-version"] == "2025-06-18"

    def test_sse_framed_initialize_captures_version(self, httpx_mock):
        httpx_mock.add_response(
            text='data: {"jsonrpc":"2.0","result":{"protocolVersion":"2025-03-26"},"id":1}\n\n',
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2}',
            ]
        )
        reqs = httpx_mock.get_requests()
        assert reqs[1].headers["mcp-protocol-version"] == "2025-03-26"

    def test_sse_initialize_with_leading_noise_captures_version(self, httpx_mock):
        """capture_init skips a leading comment and a non-result data line and
        still captures protocolVersion from the InitializeResult event."""
        body = (
            ": keepalive\n"
            'data: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n'
            'data: {"jsonrpc":"2.0","result":{"protocolVersion":"2025-03-26"},"id":1}\n\n'
        )
        httpx_mock.add_response(
            text=body,
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2}',
            ]
        )
        reqs = httpx_mock.get_requests()
        assert reqs[1].headers["mcp-protocol-version"] == "2025-03-26"

    def test_no_header_when_no_initialize_seen(self, httpx_mock):
        """A request that is not preceded by an initialize carries no version header."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(['{"jsonrpc":"2.0","method":"tools/call","id":1}'])
        reqs = httpx_mock.get_requests()
        assert "mcp-protocol-version" not in reqs[0].headers

    def test_reinitialize_initialized_carries_header(self, httpx_mock):
        """After a 404, the recovered session's initialized notification carries it."""
        # 1: initialize -> negotiate 2025-06-18, session sess-1
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        # 2: tools/call -> 404 (session expired)
        httpx_mock.add_response(
            status_code=404, text="", headers={"content-type": "application/json"}
        )
        # 3: reinit initialize -> new session sess-2
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":0}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-2"},
        )
        # 4: reinit notifications/initialized -> 202
        httpx_mock.add_response(status_code=202, text="")
        # 5: tools/call retry -> 200
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2}',
            ]
        )
        reqs = httpx_mock.get_requests()
        # reqs: 0=init, 1=call(404), 2=reinit-init, 3=reinit-initialized, 4=call-retry
        assert "mcp-protocol-version" not in reqs[2].headers  # renegotiation
        assert reqs[3].headers["mcp-protocol-version"] == "2025-06-18"
        assert reqs[4].headers["mcp-protocol-version"] == "2025-06-18"

    def test_reinitialize_recaptures_renegotiated_version(self, httpx_mock):
        """If the 404-recovery handshake renegotiates a DIFFERENT version, the
        gateway must switch to it — not keep injecting the stale original."""
        # 1: initialize -> negotiate 2025-06-18, session sess-1
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        # 2: tools/call -> 404 (session expired)
        httpx_mock.add_response(
            status_code=404, text="", headers={"content-type": "application/json"}
        )
        # 3: reinit initialize -> server DOWNGRADES to 2024-11-05, new session
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":0}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-2"},
        )
        # 4: reinit notifications/initialized -> 202
        httpx_mock.add_response(status_code=202, text="")
        # 5: tools/call retry -> 200
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        # 6: a later request -> 200 (must still carry the renegotiated version)
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":3}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2}',
                '{"jsonrpc":"2.0","method":"tools/call","id":3}',
            ]
        )
        reqs = httpx_mock.get_requests()
        # reqs: 0=init, 1=call(404), 2=reinit-init, 3=reinit-initialized,
        #       4=call-retry, 5=later-call
        assert reqs[3].headers["mcp-protocol-version"] == "2024-11-05"
        assert reqs[4].headers["mcp-protocol-version"] == "2024-11-05"
        assert reqs[5].headers["mcp-protocol-version"] == "2024-11-05"

    def test_reinitialize_advertises_previously_negotiated_version(self, httpx_mock):
        """The 404-recovery initialize must request the previously-negotiated
        version, not the 2024-11-05 floor — volunteering the floor would invite
        a silent downgrade of a session that had negotiated something newer."""
        # 1: initialize -> negotiate 2025-06-18, session sess-1
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        # 2: tools/call -> 404 (session expired)
        httpx_mock.add_response(
            status_code=404, text="", headers={"content-type": "application/json"}
        )
        # 3: reinit initialize -> server keeps 2025-06-18, new session
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":0}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-2"},
        )
        httpx_mock.add_response(status_code=202, text="")  # reinit initialized
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2}',
            ]
        )
        reqs = httpx_mock.get_requests()
        # reqs[2] is the recovery initialize; its body must advertise the
        # already-negotiated version, not the floor.
        reinit_body = json.loads(reqs[2].read())
        assert reinit_body["params"]["protocolVersion"] == "2025-06-18"

    def test_client_driven_reinitialize_updates_header(self, httpx_mock):
        """#2: a client that sends a SECOND initialize renegotiating a newer
        version must have subsequent requests carry the UPDATED
        MCP-Protocol-Version, not the stale first-negotiated one."""
        # 1: initialize -> 2025-03-26
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-03-26"},"id":1}',
            headers={"content-type": "application/json"},
        )
        # 2: a second, client-driven initialize -> renegotiates 2025-06-18
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":2}',
            headers={"content-type": "application/json"},
        )
        # 3: a later request
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":3}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                '{"jsonrpc":"2.0","method":"initialize","id":2}',
                '{"jsonrpc":"2.0","method":"tools/call","id":3}',
            ]
        )
        reqs = httpx_mock.get_requests()
        # req[0] first initialize: no header (it IS the negotiation).
        assert "mcp-protocol-version" not in reqs[0].headers
        # req[1] second initialize ALSO carries no header — an initialize is the
        # (re)negotiation and must not advertise the prior version (#4).
        assert "mcp-protocol-version" not in reqs[1].headers
        # req[2] (a normal request) carries the RE-negotiated version — proof
        # the second initialize's response was re-captured.
        assert reqs[2].headers["mcp-protocol-version"] == "2025-06-18"

    def test_reinitialize_recaptures_version_from_sse_framed_response(self, httpx_mock):
        """The 404-recovery re-initialize response may itself be SSE-framed —
        the protocol version must still be re-captured and injected."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        httpx_mock.add_response(
            status_code=404, text="", headers={"content-type": "application/json"}
        )
        # reinit initialize -> SSE-framed, renegotiates 2025-03-26
        httpx_mock.add_response(
            text='data: {"jsonrpc":"2.0","result":{"protocolVersion":"2025-03-26"},"id":0}\n\n',
            headers={"content-type": "text/event-stream", "mcp-session-id": "sess-2"},
        )
        httpx_mock.add_response(status_code=202, text="")  # reinit initialized
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2}',
            ]
        )
        reqs = httpx_mock.get_requests()
        assert reqs[3].headers["mcp-protocol-version"] == "2025-03-26"  # initialized
        assert reqs[4].headers["mcp-protocol-version"] == "2025-03-26"  # retry


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


# --- tools/call arguments:null normalization (typescript-sdk#2012, issue #74) ---


class TestNormalizeNullArguments:
    """Rewrite a tools/call null `arguments` to {} for strict servers."""

    def test_rewrites_null_arguments_to_empty_object(self):
        line = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t","arguments":null}}'
        out = json.loads(_normalize_null_arguments(line))
        assert out["params"]["arguments"] == {}

    def test_absent_arguments_stays_absent(self):
        """Missing arguments must NOT be synthesized to {}."""
        line = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t"}}'
        out = json.loads(_normalize_null_arguments(line))
        assert "arguments" not in out["params"]

    def test_rewrites_null_arguments_with_id_zero(self):
        """#11(round17): the id-0 falsy-id regression class is pinned at every
        other transform layer (_emit, run, _CancelTracker); complete the symmetry
        here. Normalization keys off method/params, never the id, so id:0 must
        rewrite arguments to {} and preserve id:0 exactly."""
        line = '{"jsonrpc":"2.0","method":"tools/call","id":0,"params":{"name":"t","arguments":null}}'
        out = json.loads(_normalize_null_arguments(line))
        assert out["params"]["arguments"] == {}
        assert out["id"] == 0

    def test_rewrites_null_arguments_for_notification(self):
        """A tools/call NOTIFICATION (no id) carrying arguments:null is still
        rewritten — normalization is id-agnostic."""
        line = '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":null}}'
        out = json.loads(_normalize_null_arguments(line))
        assert out["params"]["arguments"] == {}
        assert "id" not in out

    def test_empty_object_arguments_untouched(self):
        line = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t","arguments":{}}}'
        assert _normalize_null_arguments(line) == line

    def test_populated_arguments_untouched(self):
        line = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t","arguments":{"x":1}}}'
        assert _normalize_null_arguments(line) == line

    def test_non_tools_call_with_null_arguments_untouched(self):
        line = '{"jsonrpc":"2.0","method":"prompts/get","id":1,"params":{"name":"p","arguments":null}}'
        assert _normalize_null_arguments(line) == line

    def test_false_positive_in_string_value_untouched(self):
        """A string value containing the literal "arguments":null must not be rewritten."""
        line = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t","arguments":{"note":"\\"arguments\\":null"}}}'
        out = json.loads(_normalize_null_arguments(line))
        # arguments object preserved exactly (not clobbered to {})
        assert out["params"]["arguments"] == {"note": '"arguments":null'}

    def test_batch_array_passed_through(self):
        """JSON-RPC batch arrays are out of scope and pass through unchanged."""
        line = '[{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t","arguments":null}}]'
        assert _normalize_null_arguments(line) == line

    def test_malformed_json_passed_through(self):
        line = '{"method":"tools/call","arguments":null'  # truncated
        assert _normalize_null_arguments(line) == line

    def test_null_params_with_arguments_elsewhere_passed_through(self):
        """#10(round12): the regex matches an "arguments":null nested elsewhere,
        but params itself is null (not an object). The non-dict-params branch
        must leave the line unchanged — only params.arguments is ever rewritten."""
        line = (
            '{"jsonrpc":"2.0","method":"tools/call","id":1,'
            '"params":null,"_meta":{"arguments":null}}'
        )
        assert _normalize_null_arguments(line) == line

    def test_array_params_with_arguments_elsewhere_passed_through(self):
        """params as a positional array (non-dict) likewise passes through."""
        line = (
            '{"jsonrpc":"2.0","method":"tools/call","id":1,'
            '"params":[1,2],"_meta":{"arguments":null}}'
        )
        assert _normalize_null_arguments(line) == line


class TestRunNormalizeArguments:
    """Integration: the flag controls outbound rewrite on the wire."""

    def _run(self, httpx_mock, stdin_lines, **kwargs):
        stdin_data = "\n".join(stdin_lines) + "\n"
        with patch("sys.stdin", StringIO(stdin_data)), patch("sys.stdout", StringIO()):
            run("https://example.com/mcp", {"Content-Type": "application/json"}, **kwargs)

    def test_default_rewrites_on_wire(self, httpx_mock):
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json"},
        )
        self._run(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t","arguments":null}}'],
        )
        sent = json.loads(httpx_mock.get_requests()[0].read())
        assert sent["params"]["arguments"] == {}

    def test_opt_out_forwards_verbatim(self, httpx_mock):
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json"},
        )
        self._run(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t","arguments":null}}'],
            normalize_arguments=False,
        )
        sent = json.loads(httpx_mock.get_requests()[0].read())
        assert sent["params"]["arguments"] is None


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
        # #2(round11): a truncated list keeps the pending cursor so the client
        # can RESUME, rather than being told the list is complete.
        assert merged["result"]["nextCursor"] == "p2"

    def test_page2_retry_exhaustion_returns_partial_result(self, httpx_mock):
        """#11: page 2 exhausting all retries (repeated transport error) must
        flush the page-1 items already collected, not lose them."""
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
        for _ in range(MAX_RETRIES):
            httpx_mock.add_exception(httpx.ConnectError("refused"), url=self.URL)

        with patch("mcp_stdio.relay.time.sleep"):
            output = self._run_with_stdin(
                httpx_mock,
                [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
            )
        merged = json.loads(output.strip())
        assert [t["name"] for t in merged["result"]["tools"]] == ["ok1"]
        # Truncated → pending cursor preserved for resumption (#2 round11).
        assert merged["result"]["nextCursor"] == "p2"

    def test_page2_unparseable_body_returns_partial_result(self, httpx_mock):
        """#11: page 2 returning an unparseable 200 body must flush the page-1
        items, not drop the whole response."""
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
        # page 2: HTTP 200 but the body is not valid JSON.
        httpx_mock.add_response(
            url=self.URL,
            text="{not json",
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        assert [t["name"] for t in merged["result"]["tools"]] == ["ok1"]
        # Truncated → pending cursor preserved for resumption (#2 round11).
        assert merged["result"]["nextCursor"] == "p2"

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

    def test_first_page_retry_exhaustion_emits_single_error(self, httpx_mock):
        """When page 1 exhausts all retries (repeated ConnectError), the
        buffered ``_post_parsed`` path writes exactly one JSON-RPC error for
        the request id and no partial result."""
        for _ in range(MAX_RETRIES):
            httpx_mock.add_exception(httpx.ConnectError("refused"), url=self.URL)

        with patch("mcp_stdio.relay.time.sleep"):
            output = self._run_with_stdin(
                httpx_mock,
                [json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})],
            )
        lines = [json.loads(x) for x in output.strip().splitlines() if x]
        assert len(lines) == 1
        assert lines[0]["id"] == 7
        assert "error" in lines[0]
        assert "result" not in lines[0]

    def test_sse_data_without_space_is_paginated(self, httpx_mock):
        """Pagination's buffered SSE parse accepts space-less ``data:`` framing."""
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
            text=f"data:{json.dumps(page1)}\n\n",
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=f"data:{json.dumps(page2)}\n\n",
            headers={"content-type": "text/event-stream"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        assert [t["name"] for t in merged["result"]["tools"]] == ["a", "b"]

    def test_max_list_pages_constant_is_positive(self):
        """Sanity check on the shipped cap."""
        assert MAX_LIST_PAGES >= 1

    def test_page1_jsonrpc_error_object_forwarded_verbatim(self, httpx_mock):
        """A paginated method answered on page 1 with a JSON-RPC error object
        (non-dict result) is forwarded as-is, not merged."""
        err = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32603, "message": "boom"},
        }
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(err),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        lines = [json.loads(x) for x in output.strip().splitlines() if x]
        assert len(lines) == 1
        assert lines[0]["error"]["message"] == "boom"
        assert "result" not in lines[0]

    def test_page1_unparseable_body_passes_through(self, httpx_mock):
        """A page-1 200 with an unparseable body falls back to the streaming
        passthrough (re-POST via _post_and_stream — idempotent for a list read),
        forwarding the body as-is rather than merging or crashing."""
        # Page-1 buffered parse fails, then the streaming fallback re-POSTs.
        for _ in range(2):
            httpx_mock.add_response(
                url=self.URL,
                text="{not valid json",
                headers={"content-type": "application/json"},
            )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        assert output.strip() == "{not valid json"
        assert len(httpx_mock.get_requests()) == 2

    def test_page1_sse_with_no_parseable_message_falls_back(self, httpx_mock):
        """Page-1 SSE whose only message event has a non-JSON data line (server
        bug) yields parsed=None in _post_parsed, so pagination falls back to a
        _post_and_stream re-POST and forwards the body."""
        # Page-1 buffered SSE parse finds no JSON message, then the fallback
        # re-POSTs and the streaming path emits the (now valid) body.
        httpx_mock.add_response(
            url=self.URL,
            text="event: message\ndata: not-json\n\n",
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n\n',
            headers={"content-type": "text/event-stream"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        assert json.loads(output.strip())["result"]["tools"] == []
        assert len(httpx_mock.get_requests()) == 2

    def test_page2_non_dict_result_flushes_partial(self, httpx_mock):
        """A page-2 200 with a non-dict result stops pagination and flushes the
        items accumulated from page 1."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "nextCursor": "p2"},
        }
        page2 = {"jsonrpc": "2.0", "id": 1, "result": "not-a-dict"}
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(page1),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(page2),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        assert [t["name"] for t in merged["result"]["tools"]] == ["a"]

    def test_late_top_level_result_field_preserved(self, httpx_mock):
        """#14: a top-level result field (e.g. _meta) that appears only on a
        later page must survive the merge (last-write-wins), not be dropped."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "nextCursor": "p2"},
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "_meta": {"total": 2}},
        }
        for page in (page1, page2):
            httpx_mock.add_response(
                url=self.URL,
                text=json.dumps(page),
                headers={"content-type": "application/json"},
            )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        assert [t["name"] for t in merged["result"]["tools"]] == ["a", "b"]
        assert merged["result"]["_meta"] == {"total": 2}  # late field kept
        assert "nextCursor" not in merged["result"]

    def test_page_sse_skips_interleaved_notification(self, httpx_mock):
        """#1: a server may interleave a notification on the POST's SSE stream
        BEFORE the list result. _post_parsed must skip it and return the real
        response, not mistake the notification for the page result."""
        notif = '{"jsonrpc":"2.0","method":"notifications/message","params":{}}'
        result = '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}}'
        body = (
            f"event: message\ndata: {notif}\n\n"
            f"event: message\ndata: {result}\n\n"
        )
        httpx_mock.add_response(
            url=self.URL,
            text=body,
            headers={"content-type": "text/event-stream"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        assert [t["name"] for t in merged["result"]["tools"]] == ["a"]
        # The interleaved notification must not have been forwarded as the result.
        assert "notifications/message" not in output


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

    def test_sse_data_without_space(self, httpx_mock):
        """WHATWG SSE: ``data:`` without a trailing space is valid framing and
        --check must still parse the initialize result."""
        body = (
            'data:{"jsonrpc":"2.0","id":1,"result":'
            '{"protocolVersion":"2024-11-05","serverInfo":{"name":"sse","version":"0.1"},'
            '"capabilities":{}}}\n\n'
        )
        httpx_mock.add_response(
            text=body,
            headers={"content-type": "text/event-stream"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True

    def test_sse_initialize_with_raw_unicode_separator(self, httpx_mock):
        """A raw U+2028 in the serverInfo string of an SSE-framed initialize
        must not split the buffered data: line — --check still parses it."""
        name = "demo" + chr(0x2028) + "server"  # real U+2028 on the wire
        body = (
            f'data:{{"jsonrpc":"2.0","id":1,"result":'
            f'{{"protocolVersion":"2024-11-05",'
            f'"serverInfo":{{"name":"{name}","version":"1"}},"capabilities":{{}}}}}}\n\n'
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

    def test_empty_capability_object_reports_yes(self, httpx_mock, capsys):
        """MCP capabilities are presence-based: ``"tools": {}`` means supported,
        so the probe reports tools=yes even though the object is empty."""
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}, "resources": {}},
                },
            }
        )
        httpx_mock.add_response(
            text=body, headers={"content-type": "application/json"}
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True
        err = capsys.readouterr().err
        assert "tools=yes" in err
        assert "resources=yes" in err
        assert "prompts=no" in err  # absent → no

    def test_null_capabilities_does_not_crash(self, httpx_mock):
        """A server sending ``"capabilities": null`` must not crash the probe."""
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"protocolVersion": "2024-11-05", "capabilities": None},
            }
        )
        httpx_mock.add_response(
            text=body, headers={"content-type": "application/json"}
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True

    def test_non_object_result_does_not_crash(self, httpx_mock):
        """A malformed server returning a scalar ``result`` is reported as
        reachable rather than crashing on attribute access."""
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "ok"})
        httpx_mock.add_response(
            text=body, headers={"content-type": "application/json"}
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


class TestCheckConnectionSse:
    """``check_connection(transport="sse")`` runs the legacy GET/endpoint/POST
    handshake instead of POSTing initialize directly (round-7 #11)."""

    SSE_URL = "https://example.com/sse"
    HEADERS = {"Content-Type": "application/json"}

    _INIT_RESULT = (
        '{"jsonrpc":"2.0","id":1,"result":'
        '{"protocolVersion":"2024-11-05",'
        '"serverInfo":{"name":"sse-demo","version":"9.9"},'
        '"capabilities":{"tools":{}}}}'
    )

    def test_sse_handshake_success(self, httpx_mock):
        """endpoint event → POST initialize → response on the stream → True."""
        # The GET stream carries the endpoint bootstrap and then the
        # initialize response (legacy SSE delivers POST responses on the
        # stream, not in the POST body).
        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(
                [
                    b"event: endpoint\ndata: /messages?sid=xyz\n\n",
                    f"event: message\ndata: {self._INIT_RESULT}\n\n".encode(),
                ]
            ),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url="https://example.com/messages?sid=xyz",
            method="POST",
            status_code=202,
        )
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse")
            is True
        )
        # The probe actually POSTed initialize to the resolved endpoint.
        posts = [r for r in httpx_mock.get_requests() if r.method == "POST"]
        assert len(posts) == 1
        assert str(posts[0].url) == "https://example.com/messages?sid=xyz"
        assert b'"method":"initialize"' in posts[0].read().replace(b" ", b"")

    def test_sse_reports_server_info(self, httpx_mock, capsys):
        """serverInfo / capabilities from the streamed response reach the log."""
        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(
                [
                    b"event: endpoint\ndata: /messages\n\n",
                    f"event: message\ndata: {self._INIT_RESULT}\n\n".encode(),
                ]
            ),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url="https://example.com/messages", method="POST", status_code=202
        )
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse")
            is True
        )
        err = capsys.readouterr().err
        assert "sse-demo" in err
        assert "tools=yes" in err

    def test_sse_get_non_200_returns_false(self, httpx_mock):
        """The GET stream itself failing (e.g. 401) → False, no POST attempted."""
        httpx_mock.add_response(url=self.SSE_URL, method="GET", status_code=401)
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse")
            is False
        )
        assert not [r for r in httpx_mock.get_requests() if r.method == "POST"]

    def test_sse_mcp_error_returns_false(self, httpx_mock):
        """A JSON-RPC error delivered on the stream → False."""
        err_body = '{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"boom"}}'
        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(
                [
                    b"event: endpoint\ndata: /messages\n\n",
                    f"event: message\ndata: {err_body}\n\n".encode(),
                ]
            ),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url="https://example.com/messages", method="POST", status_code=202
        )
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse")
            is False
        )

    def test_sse_stream_ends_before_response_returns_false(self, httpx_mock):
        """endpoint arrives but no initialize response before EOF → False."""
        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream([b"event: endpoint\ndata: /messages\n\n"]),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url="https://example.com/messages", method="POST", status_code=202
        )
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse")
            is False
        )

    def test_sse_post_non_2xx_reports_post_failure(self, httpx_mock, capsys):
        """#6(round15): the endpoint POST returning a non-2xx sets post_error,
        the helper closes the stream, and the probe reports the POST failure
        (not a generic 'stream ended') and returns False."""
        post_attempted = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            # Hold the stream open until the POST has been attempted, then give
            # the helper a beat to record post_error before the stream ends.
            post_attempted.wait(timeout=3)
            time.sleep(0.1)

        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def on_post(request: httpx.Request) -> httpx.Response:
            post_attempted.set()
            return httpx.Response(status_code=500)

        httpx_mock.add_callback(
            on_post, url="https://example.com/messages?sid=abc"
        )

        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse")
            is False
        )
        err = capsys.readouterr().err
        assert "POST to SSE endpoint failed" in err
        assert "HTTP 500" in err

    def test_sse_post_raises_reports_post_failure(self, httpx_mock, capsys):
        """#6(round15): the endpoint POST raising a transport error is caught in
        the helper (str(e) → post_error) and surfaced as a POST failure → False."""
        post_attempted = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            post_attempted.wait(timeout=3)
            time.sleep(0.1)

        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def on_post(request: httpx.Request) -> httpx.Response:
            post_attempted.set()
            raise httpx.ConnectError("connection refused", request=request)

        httpx_mock.add_callback(
            on_post, url="https://example.com/messages?sid=abc"
        )

        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse")
            is False
        )
        assert "POST to SSE endpoint failed" in capsys.readouterr().err

    def test_sse_cross_origin_endpoint_refused_with_credentials(
        self, httpx_mock, capsys
    ):
        """A cross-origin endpoint event is refused (no credential leak) → False,
        and the probe never POSTs the Authorization header off-origin."""
        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(
                [b"event: endpoint\ndata: https://evil.example/steal\n\n"]
            ),
            headers={"content-type": "text/event-stream"},
        )
        headers = {"Content-Type": "application/json", "Authorization": "Bearer s3cr3t"}
        assert check_connection(self.SSE_URL, headers, transport="sse") is False
        assert "cross-origin" in capsys.readouterr().err
        assert not [r for r in httpx_mock.get_requests() if r.method == "POST"]

    def test_sse_server_notification_before_response_is_skipped(self, httpx_mock):
        """A server-initiated notification on the stream is not mistaken for the
        initialize response — the probe keeps reading until the real result."""
        notif = '{"jsonrpc":"2.0","method":"notifications/message","params":{}}'
        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(
                [
                    b"event: endpoint\ndata: /messages\n\n",
                    f"event: message\ndata: {notif}\n\n".encode(),
                    f"event: message\ndata: {self._INIT_RESULT}\n\n".encode(),
                ]
            ),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url="https://example.com/messages", method="POST", status_code=202
        )
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse")
            is True
        )

    def test_sse_message_before_endpoint_is_skipped(self, httpx_mock):
        """#15(round14): a message event arriving BEFORE the endpoint event must
        be ignored (no POST can target an unknown endpoint yet); the probe POSTs
        only after the endpoint and still completes on the real result."""
        early = '{"jsonrpc":"2.0","method":"notifications/message","params":{}}'
        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(
                [
                    f"event: message\ndata: {early}\n\n".encode(),  # before endpoint
                    b"event: endpoint\ndata: /messages\n\n",
                    f"event: message\ndata: {self._INIT_RESULT}\n\n".encode(),
                ]
            ),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url="https://example.com/messages", method="POST", status_code=202
        )
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse")
            is True
        )
        # Exactly one POST, and only to the resolved endpoint (after it arrived).
        posts = [r for r in httpx_mock.get_requests() if r.method == "POST"]
        assert len(posts) == 1
        assert str(posts[0].url) == "https://example.com/messages"


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

    def _reader_with_headers(self, httpx_mock, sse_bytes, headers):
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
        try:
            with patch("sys.stdout", StringIO()):
                _sse_reader_loop(client, self.URL, headers, state)
        finally:
            client.close()
        return state

    def test_cross_origin_endpoint_refused_when_authorized(self, httpx_mock, capsys):
        """A cross-origin absolute endpoint must be refused when the GET carries
        an Authorization header — POSTing credentials there would leak them."""
        state = self._reader_with_headers(
            httpx_mock,
            [b"event: endpoint\ndata: https://evil.example/post\n\n"],
            {"Authorization": "Bearer secret"},
        )
        assert state.endpoint_url is None  # refused
        assert state.ready.is_set()  # but startup is unblocked
        assert "cross-origin" in capsys.readouterr().err

    def test_cross_origin_endpoint_allowed_without_credentials(self, httpx_mock):
        """No Authorization header → a cross-origin endpoint is allowed (nothing
        to leak)."""
        state = self._reader_with_headers(
            httpx_mock,
            [b"event: endpoint\ndata: https://other.example.com/post\n\n"],
            {},
        )
        assert state.endpoint_url == "https://other.example.com/post"

    def test_same_origin_absolute_endpoint_allowed_with_credentials(self, httpx_mock):
        state = self._reader_with_headers(
            httpx_mock,
            [b"event: endpoint\ndata: https://example.com/messages\n\n"],
            {"Authorization": "Bearer secret"},
        )
        assert state.endpoint_url == "https://example.com/messages"

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

    def test_generic_exception_safety_net_sets_ready(self, httpx_mock, monkeypatch):
        """A non-HTTP exception on the FIRST connect (before any endpoint event,
        so `established` is False) must hit the catch-all's fail-fast branch: set
        ready and return — so run_sse's startup wait() unblocks instead of hanging
        to the connect timeout. (The established-mid-session branch reconnects
        instead; see TestRunSseReaderRecovery. #1 round16.)"""
        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream([b"event: endpoint\ndata: /post\n\n"]),
            headers={"content-type": "text/event-stream"},
        )

        def boom(_lines):
            raise ValueError("unexpected reader error")

        monkeypatch.setattr("mcp_stdio.relay._iter_sse_events", boom)
        state = _SseState()
        client = httpx.Client()
        try:
            _sse_reader_loop(client, self.URL, {}, state)  # must return, not raise
        finally:
            client.close()
        assert state.ready.is_set()

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

    def test_read_timeout_triggers_reconnect(self, httpx_mock):
        """#9: a silent half-open TCP surfaces as httpx.ReadTimeout and the
        reader loop reconnects, rather than blocking forever."""
        state = _SseState()

        # First GET: silent timeout (simulates a dropped half-open connection
        # during a long-running tool call)
        httpx_mock.add_exception(httpx.ReadTimeout("idle"), url=self.URL, method="GET")

        # Second GET: a clean stream that terminates the test by setting stop
        def healthy_gen():
            yield b"event: endpoint\ndata: /messages\n\n"
            state.stop.set()

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(healthy_gen()),
            headers={"content-type": "text/event-stream"},
        )

        client = httpx.Client()
        stdout = StringIO()
        try:
            with (
                patch("sys.stdout", stdout),
                patch("mcp_stdio.relay.RETRY_DELAY", 0),
            ):
                _sse_reader_loop(client, self.URL, {}, state)
        finally:
            client.close()

        # After the reconnect, the endpoint event from the healthy stream
        # must have been parsed — proof that the loop did not abort on
        # the ReadTimeout.
        assert state.endpoint_url == "https://example.com/messages"
        assert state.ready.is_set()
        # Both GETs were issued (the first one raised, the second succeeded)
        assert len(httpx_mock.get_requests()) == 2

    def test_clean_stream_end_triggers_reconnect(self, httpx_mock):
        """A GET stream that ends *normally* (server closed it, no exception)
        must reconnect — exercising the graceful-EOF reconnect branch, not the
        HTTPError one."""
        state = _SseState()

        # First GET ends cleanly (generator returns without setting stop).
        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream([b"event: endpoint\ndata: /first\n\n"]),
            headers={"content-type": "text/event-stream"},
        )

        # Second GET re-resolves a new endpoint, then ends the test.
        def healthy_gen():
            yield b"event: endpoint\ndata: /second\n\n"
            state.stop.set()

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(healthy_gen()),
            headers={"content-type": "text/event-stream"},
        )

        client = httpx.Client()
        try:
            with (
                patch("sys.stdout", StringIO()),
                patch("mcp_stdio.relay.RETRY_DELAY", 0),
            ):
                _sse_reader_loop(client, self.URL, {}, state)
        finally:
            client.close()

        # The graceful EOF on GET #1 must have triggered GET #2.
        assert state.endpoint_url == "https://example.com/second"
        assert len(httpx_mock.get_requests()) == 2

    def test_reconnect_resnapshot_uses_refreshed_headers(self, httpx_mock):
        """When headers are mutated (as a 401 refresh would) between connects,
        the reader's per-reconnect locked snapshot picks up the new value — the
        reconnected GET carries the refreshed Authorization, not the stale one."""
        state = _SseState()
        headers = {"Authorization": "Bearer old"}
        headers_lock = threading.Lock()
        seen_auth: list[str | None] = []

        def first_gen():
            # End cleanly; simulate a mid-session token refresh by mutating the
            # shared headers under the lock before the reader re-snapshots.
            yield b"event: endpoint\ndata: /first\n\n"
            with headers_lock:
                headers["Authorization"] = "Bearer new"

        def second_gen():
            yield b"event: endpoint\ndata: /second\n\n"
            state.stop.set()

        def get_callback(request):
            seen_auth.append(request.headers.get("authorization"))
            gen = first_gen if len(seen_auth) == 1 else second_gen
            return httpx.Response(
                200,
                stream=IteratorStream(gen()),
                headers={"content-type": "text/event-stream"},
            )

        httpx_mock.add_callback(get_callback, url=self.URL, method="GET", is_reusable=True)

        client = httpx.Client()
        try:
            with (
                patch("sys.stdout", StringIO()),
                patch("mcp_stdio.relay.RETRY_DELAY", 0),
            ):
                _sse_reader_loop(
                    client, self.URL, headers, state, headers_lock=headers_lock
                )
        finally:
            client.close()

        assert seen_auth[0] == "Bearer old"
        assert seen_auth[1] == "Bearer new"  # reconnect re-snapshotted the update

    def test_non200_reconnect_after_establish_keeps_retrying(self, httpx_mock):
        """#3(round11): a non-200 on RECONNECT (after an endpoint was once
        established) must retry, not kill the reader. Before the fix the reader
        died after the first reconnect 500 (2 GETs); now it keeps reconnecting."""
        state = _SseState()
        calls = {"n": 0}

        def first_gen():
            yield b"event: endpoint\ndata: /messages\n\n"  # establish, then end

        def get_callback(request):
            calls["n"] += 1
            n = calls["n"]
            if n == 1:
                return httpx.Response(
                    200,
                    stream=IteratorStream(first_gen()),
                    headers={"content-type": "text/event-stream"},
                )
            # Reconnect attempts 500; stop after the 2nd so the loop terminates
            # while still proving it reconnected past the first failure.
            if n >= 3:
                state.stop.set()
            return httpx.Response(500)

        httpx_mock.add_callback(
            get_callback, url=self.URL, method="GET", is_reusable=True
        )

        client = httpx.Client()
        try:
            with (
                patch("sys.stdout", StringIO()),
                patch("mcp_stdio.relay.RETRY_DELAY", 0),
            ):
                _sse_reader_loop(client, self.URL, {}, state)
        finally:
            client.close()

        assert calls["n"] >= 3  # survived the first reconnect 500 and retried

    def test_non200_first_connect_is_fatal(self, httpx_mock):
        """A non-200 on the VERY FIRST connect (never established) stays fatal:
        the reader signals ready (endpoint None) and returns so run_sse exits."""
        state = _SseState()
        httpx_mock.add_response(url=self.URL, method="GET", status_code=500)
        client = httpx.Client()
        try:
            with (
                patch("sys.stdout", StringIO()),
                patch("mcp_stdio.relay.RETRY_DELAY", 0),
            ):
                _sse_reader_loop(client, self.URL, {}, state)
        finally:
            client.close()
        assert state.ready.is_set()
        assert state.endpoint_url is None
        assert len(httpx_mock.get_requests()) == 1  # did not retry


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


class TestRunSseReaderRecovery:
    """#1(round16): an unexpected (non-HTTPError) exception in the SSE reader
    must not permanently kill it. The reader nulls endpoint_url and reconnects,
    so async reply delivery recovers instead of every later request-with-id
    hanging forever on a dead stream."""

    URL = "https://example.com/sse"

    def test_reader_reconnects_after_unexpected_emit_error(
        self, httpx_mock, monkeypatch
    ):
        monkeypatch.setattr("mcp_stdio.relay.RETRY_DELAY", 0.05)
        import mcp_stdio.relay as relay_mod

        real_emit = relay_mod._emit
        emit_calls = {"n": 0}

        def flaky_emit(line, tracker):
            emit_calls["n"] += 1
            if emit_calls["n"] == 1:
                # Simulate an unexpected decode/_write_line bug on one event.
                raise RuntimeError("simulated reader-side bug on a malformed event")
            real_emit(line, tracker)

        monkeypatch.setattr("mcp_stdio.relay._emit", flaky_emit)

        release_stdin = threading.Event()
        hold_gen2 = threading.Event()

        def sse_gen_1():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            # This message triggers flaky_emit's first-call raise, which throws
            # out of the reader's for-loop into the catch-all.
            yield b'event: message\ndata: {"jsonrpc":"2.0","result":{"first":1},"id":1}\n\n'

        def sse_gen_2():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            yield b'event: message\ndata: {"jsonrpc":"2.0","result":{"recovered":1},"id":2}\n\n'
            # The recovered reply has been _emit'd to stdout by the time the
            # reader pulls the next event; let the main loop exit, then hold the
            # stream so the reader parks here (no third unmocked GET) until stop.
            release_stdin.set()
            hold_gen2.wait(timeout=2)

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen_1()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen_2()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url="https://example.com/messages?sid=abc",
            method="POST",
            status_code=202,
            is_reusable=True,
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            release_stdin,
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})

        # The reader survived the unexpected error: it reconnected (>=2 GETs)
        # and delivered the post-recovery reply — proving it did not die.
        gets = [r for r in httpx_mock.get_requests() if r.method == "GET"]
        assert len(gets) >= 2, f"expected a reconnect (>=2 GETs), got {len(gets)}"
        assert "recovered" in stdout.getvalue()


class TestRunSse:
    """End-to-end tests for run_sse driven from the main thread."""

    URL = "https://example.com/sse"

    def test_sse_read_timeout_default_and_disabled(self, monkeypatch):
        """#9: run_sse() passes sse_read_timeout through to httpx.Client.

        Default of 300 seconds surfaces as httpx.Timeout(read=300.0).
        Explicit 0 and None both disable the timeout (read=None). No
        network calls are made; the fake client intercepts Client
        construction, captures the timeout, and then returns a 404 on
        the first GET so run_sse's "SSE reader terminated before
        endpoint event" branch fires and the main thread exits
        deterministically via sys.exit(1) instead of blocking on stdin.
        """
        captured: list[httpx.Timeout] = []

        class _FakeClient:
            def __init__(self, *, timeout, **_kwargs):
                captured.append(timeout)

            def close(self):
                pass

            def stream(self, method, url, headers=None):
                # The reader sees HTTP 404 on the first GET, logs an
                # error, sets state.ready, and returns. That's enough
                # to make run_sse's post-startup endpoint check fail
                # and reach the sys.exit path the test relies on.
                class _CM:
                    status_code = 404
                    headers = {}

                    def __enter__(self_):
                        return self_

                    def __exit__(self_, *a):
                        return False

                    def iter_text(self_):
                        # Matches the production call site; never iterated here
                        # because the 404 status returns early.
                        return iter([])

                return _CM()

            def post(self, *_a, **_kw):
                return httpx.Response(status_code=404)

        monkeypatch.setattr("mcp_stdio.relay.httpx.Client", _FakeClient)

        for supplied, expected_read in [
            (None, 300),     # parameter default
            (300, 300),      # explicit default
            (60, 60),        # custom non-zero
            (0, None),       # 0 disables
        ]:
            captured.clear()
            kwargs = {} if supplied is None else {"sse_read_timeout": supplied}
            stdin = StringIO("")
            stdout = StringIO()
            with (
                patch("sys.stdin", stdin),
                patch("sys.stdout", stdout),
                pytest.raises(SystemExit),
            ):
                run_sse(self.URL, {}, **kwargs)
            assert captured, f"Client was not constructed for {supplied!r}"
            assert captured[0].read == expected_read, (
                f"sse_read_timeout={supplied!r} → expected read={expected_read}, "
                f"got {captured[0].read!r}"
            )

    def test_run_rejects_sse_read_timeout(self):
        """#9: the streamable-http path must not accept sse_read_timeout.

        Guards the transport asymmetry documented in cli.py's dispatch:
        run() has no long-lived GET to protect, so accidentally passing
        sse_read_timeout into run() should surface as a TypeError —
        future refactors that silently absorb **kwargs in run() would
        fail this test and alert the reviewer.
        """
        with pytest.raises(TypeError, match="sse_read_timeout"):
            run(
                "https://example.com/mcp",
                {},
                sse_read_timeout=300,
            )

    def test_sse_startup_timeout_exits(self, monkeypatch):
        """#7: if the SSE reader never signals ready within timeout_connect,
        run_sse must exit(1) rather than block on stdin forever."""

        def blocking_reader(
            client, url, headers, state, tracker=None, headers_lock=None
        ):
            # Never set state.ready; just park until told to stop.
            state.stop.wait(timeout=2)

        monkeypatch.setattr("mcp_stdio.relay._sse_reader_loop", blocking_reader)
        with (
            patch("sys.stdin", StringIO("")),
            patch("sys.stdout", StringIO()),
            pytest.raises(SystemExit) as exc,
        ):
            run_sse(self.URL, {}, timeout_connect=0.05)
        assert exc.value.code == 1

    def test_post_during_reconnect_window_emits_error(self, monkeypatch):
        """A stdin line arriving while the reader is mid-reconnect (endpoint
        cleared) must get a clean 'SSE endpoint unavailable' error, not hang.

        Deterministic: a one-shot ``endpoint_url`` reports the bootstrap URL
        for run_sse's startup check, then ``None`` once the main loop tries to
        POST — exactly the reconnect-window race the branch guards.
        """
        bootstrap_url = "https://example.com/messages"

        class _OneShotEndpointState:
            def __init__(self):
                self._reads = 0
                self.ready = threading.Event()
                self.stop = threading.Event()

            @property
            def endpoint_url(self):
                self._reads += 1
                return bootstrap_url if self._reads == 1 else None

            @endpoint_url.setter
            def endpoint_url(self, value):
                pass  # reader-thread writes are irrelevant to this test

        def fake_reader(client, url, headers, state, tracker=None, headers_lock=None):
            state.ready.set()
            state.stop.wait(timeout=3)

        monkeypatch.setattr("mcp_stdio.relay._SseState", _OneShotEndpointState)
        monkeypatch.setattr("mcp_stdio.relay._sse_reader_loop", fake_reader)

        stdin = StringIO('{"jsonrpc":"2.0","method":"test","id":5}\n')
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {}, timeout_read=0.05)

        msgs = [json.loads(x) for x in stdout.getvalue().strip().splitlines() if x]
        assert len(msgs) == 1
        assert msgs[0]["id"] == 5
        assert msgs[0]["error"]["message"] == "SSE endpoint unavailable"

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

    def test_arguments_null_normalized_on_sse_post(self, httpx_mock):
        """#10: run_sse must rewrite tools/call arguments:null -> {} on the wire
        before POSTing, symmetric with run() (covered for the streamable path
        by TestRunNormalizeArguments but previously untested for SSE)."""
        release_stdin = threading.Event()
        captured: dict = {}

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=xyz\n\n"
            release_stdin.wait(timeout=3)

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def post_callback(request):
            captured["body"] = json.loads(request.read())
            release_stdin.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            post_callback,
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"tools/call","id":1,'
            '"params":{"name":"t","arguments":null}}\n',
            release_stdin,
        )
        with patch("sys.stdin", stdin), patch("sys.stdout", StringIO()):
            run_sse(self.URL, {})
        assert captured["body"]["params"]["arguments"] == {}

    def test_arguments_null_opt_out_on_sse_post(self, httpx_mock):
        """--no-normalize-arguments must forward null verbatim on the SSE path."""
        release_stdin = threading.Event()
        captured: dict = {}

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=xyz\n\n"
            release_stdin.wait(timeout=3)

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def post_callback(request):
            captured["body"] = json.loads(request.read())
            release_stdin.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            post_callback,
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"tools/call","id":1,'
            '"params":{"name":"t","arguments":null}}\n',
            release_stdin,
        )
        with patch("sys.stdin", stdin), patch("sys.stdout", StringIO()):
            run_sse(self.URL, {}, normalize_arguments=False)
        assert captured["body"]["params"]["arguments"] is None

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
        seen_auth: list[str | None] = []

        def post_callback(request):
            call_count["n"] += 1
            seen_auth.append(request.headers.get("authorization"))
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
        # The retried POST must carry the refreshed token, not the stale one.
        assert seen_auth[1] == "Bearer new"
        # #18: the post-refresh upstream response must actually reach stdout —
        # pin the end-to-end happy path (refresh -> retry -> response delivered),
        # not just the header plumbing.
        assert '"id":1' in stdout.getvalue()

    def test_post_401_refresh_failure_returns_error(self, httpx_mock):
        """#10: when the POST 401 refresher returns None, run_sse must emit a
        single 'authentication failed' error for a request-with-id — symmetric
        with run()'s test_401_refresh_failure_returns_error."""
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=xyz\n\n"
            release_stdin.wait(timeout=3)

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def post_callback(request):
            # Refresh fails, so there is no retry — release stdin and 401.
            release_stdin.set()
            return httpx.Response(status_code=401)

        httpx_mock.add_callback(
            post_callback,
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
            is_reusable=True,
        )

        def token_refresher():
            return None  # user aborted re-auth / refresh token expired

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"test","id":7}\n', release_stdin
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {}, token_refresher=token_refresher)

        msgs = [json.loads(x) for x in stdout.getvalue().strip().splitlines() if x]
        assert len(msgs) == 1
        assert msgs[0]["id"] == 7
        assert msgs[0]["error"]["message"] == "authentication failed"

    def test_post_401_refresh_failure_notification_gets_no_error(self, httpx_mock):
        """#10/req_has_id gate: a notification (no id) whose POST draws a 401
        with a failing refresher must NOT receive a synthesized id:null error."""
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=xyz\n\n"
            release_stdin.wait(timeout=3)

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def post_callback(request):
            release_stdin.set()
            return httpx.Response(status_code=401)

        httpx_mock.add_callback(
            post_callback,
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
            is_reusable=True,
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n',
            release_stdin,
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {}, token_refresher=lambda: None)

        assert stdout.getvalue().strip() == ""

    def test_post_403_triggers_scope_upgrader(self, httpx_mock):
        """#17: SSE transport must run step-up on 403 insufficient_scope."""
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
        seen_auth: list[str | None] = []

        def post_callback(request):
            call_count["n"] += 1
            seen_auth.append(request.headers.get("authorization"))
            if call_count["n"] == 1:
                return httpx.Response(
                    status_code=403,
                    headers={
                        "www-authenticate": (
                            'Bearer error="insufficient_scope", '
                            'scope="hr:read hr:write"'
                        ),
                    },
                )
            post_received.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            post_callback,
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
            is_reusable=True,
        )

        seen_scopes: list[str] = []

        def mock_upgrader(required_scope: str):
            seen_scopes.append(required_scope)
            return {"Authorization": "Bearer upgraded"}

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"test","id":1}\n', release_stdin
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {}, scope_upgrader=mock_upgrader)

        assert seen_scopes == ["hr:read hr:write"]
        assert call_count["n"] == 2
        # The retried POST must carry the upgraded-scope token.
        assert seen_auth[1] == "Bearer upgraded"

    def test_post_403_without_insufficient_scope_emits_error(self, httpx_mock):
        """Plain 403 (no scope challenge) surfaces as error (#11 + #17)."""
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=xyz\n\n"
            time.sleep(0.3)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
            status_code=403,
        )

        called = []

        def mock_upgrader(_scope):
            called.append(True)
            return {"Authorization": "Bearer x"}

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"t","id":3}\n', release_stdin
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {}, scope_upgrader=mock_upgrader)

        # Upgrader was not invoked — no scope challenge to act on
        assert called == []
        parsed = json.loads(stdout.getvalue().strip())
        assert parsed["error"]["message"] == "HTTP 403"
        assert parsed["id"] == 3

    def test_post_403_upgrader_failure_returns_error(self, httpx_mock):
        """Step-up failure on SSE surfaces as JSON-RPC error (#17)."""
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=xyz\n\n"
            time.sleep(0.3)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
            status_code=403,
            headers={
                "www-authenticate": 'Bearer error="insufficient_scope", scope="x"'
            },
        )

        def mock_upgrader(_scope):
            return None  # user aborted / browser failed

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"t","id":4}\n', release_stdin
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {}, scope_upgrader=mock_upgrader)

        parsed = json.loads(stdout.getvalue().strip())
        assert parsed["error"]["message"] == "authorization failed"
        assert parsed["id"] == 4

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

    def test_post_transport_error_emits_single_error_no_retry(self, httpx_mock):
        """A POST transport error on the SSE path surfaces a single JSON-RPC
        error and is NOT retried (unlike run()'s streamable path) — pinning the
        deliberate asymmetry."""
        post_attempts = {"n": 0}
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=xyz\n\n"
            time.sleep(0.1)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def post_callback(request):
            post_attempts["n"] += 1
            raise httpx.ConnectError("dead")

        httpx_mock.add_callback(
            post_callback,
            url="https://example.com/messages?sessionId=xyz",
            method="POST",
            is_reusable=True,
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"test","id":7}\n', release_stdin
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {})

        parsed = json.loads(stdout.getvalue().strip())
        assert parsed["id"] == 7 and "error" in parsed
        assert post_attempts["n"] == 1  # no retry on SSE POST transport error

    def test_ready_wait_timeout_during_reconnect_emits_error(self, monkeypatch):
        """A stdin line arriving while the reader is mid-reconnect (endpoint
        None and ready not set) must time-bound the wait and emit a single
        'SSE endpoint unavailable' error — exercising the FIRST reconnect guard
        (the ready.wait timeout branch). Deterministic via a fake ``ready`` that
        passes startup once then reports the reconnect wait as timed out."""

        class _FakeReady:
            def __init__(self):
                self._calls = 0

            def wait(self, timeout=None):
                self._calls += 1
                return self._calls == 1  # startup True; reconnect-wait False

            def set(self):
                pass

            def clear(self):
                pass

            def is_set(self):
                return False

        class _ReconnectingState:
            def __init__(self):
                self._reads = 0
                self.ready = _FakeReady()
                self.stop = threading.Event()

            @property
            def endpoint_url(self):
                self._reads += 1
                # Bootstrap URL for startup, then None forever (mid-reconnect).
                return "https://example.com/messages" if self._reads == 1 else None

            @endpoint_url.setter
            def endpoint_url(self, value):
                pass

        def fake_reader(client, url, headers, state, tracker=None, headers_lock=None):
            state.stop.wait(timeout=3)

        monkeypatch.setattr("mcp_stdio.relay._SseState", _ReconnectingState)
        monkeypatch.setattr("mcp_stdio.relay._sse_reader_loop", fake_reader)

        stdin = StringIO('{"jsonrpc":"2.0","method":"test","id":3}\n')
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {}, timeout_read=0.05)

        msgs = [json.loads(x) for x in stdout.getvalue().strip().splitlines() if x]
        assert len(msgs) == 1
        assert msgs[0]["id"] == 3
        assert msgs[0]["error"]["message"] == "SSE endpoint unavailable"


# --- TCP keepalive (#9, step 2) ---


class TestTcpKeepaliveSocketOptions:
    """_tcp_keepalive_socket_options must always include SO_KEEPALIVE and,
    on platforms that support it, the TCP_KEEPIDLE/INTVL/CNT triplet."""

    def _so_keepalive_tuple(self, opts):
        return next(
            (t for t in opts if t[:2] == (socket.SOL_SOCKET, socket.SO_KEEPALIVE)),
            None,
        )

    @pytest.mark.skipif(
        not hasattr(socket, "TCP_KEEPIDLE"),
        reason="TCP_KEEPIDLE unavailable on this host (e.g. macOS dev box)",
    )
    def test_linux_sets_full_triplet(self, monkeypatch):
        monkeypatch.setattr("mcp_stdio.relay.sys.platform", "linux")
        opts = _tcp_keepalive_socket_options()
        assert self._so_keepalive_tuple(opts) == (
            socket.SOL_SOCKET,
            socket.SO_KEEPALIVE,
            1,
        )
        keys = [(level, opt) for (level, opt, _val) in opts]
        assert (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) in keys
        assert (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL) in keys
        assert (socket.IPPROTO_TCP, socket.TCP_KEEPCNT) in keys

    @pytest.mark.skipif(
        not hasattr(socket, "TCP_KEEPIDLE"),
        reason="TCP_KEEPIDLE unavailable on this host",
    )
    def test_freebsd_sets_full_triplet(self, monkeypatch):
        """#9: FreeBSD support relies on sys.platform.startswith('freebsd')."""
        monkeypatch.setattr("mcp_stdio.relay.sys.platform", "freebsd14")
        opts = _tcp_keepalive_socket_options()
        assert self._so_keepalive_tuple(opts) is not None
        keys = [(level, opt) for (level, opt, _val) in opts]
        assert (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) in keys

    @pytest.mark.skipif(
        not hasattr(socket, "TCP_KEEPIDLE"),
        reason="TCP_KEEPIDLE unavailable on this host",
    )
    def test_netbsd_sets_full_triplet(self, monkeypatch):
        monkeypatch.setattr("mcp_stdio.relay.sys.platform", "netbsd10")
        opts = _tcp_keepalive_socket_options()
        assert self._so_keepalive_tuple(opts) is not None
        keys = [(level, opt) for (level, opt, _val) in opts]
        assert (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) in keys

    def test_platform_without_tcp_keepidle_falls_back(self, monkeypatch):
        """On a host whose socket module lacks TCP_KEEPIDLE (e.g. macOS dev
        box running the test with sys.platform=linux monkeypatched), the
        helper degrades to SO_KEEPALIVE alone instead of raising
        AttributeError."""
        monkeypatch.setattr("mcp_stdio.relay.sys.platform", "linux")
        # Simulate a Python/OS combo that does not expose TCP_KEEPIDLE
        import mcp_stdio.relay as relay_mod

        class _FakeSocket:
            SOL_SOCKET = socket.SOL_SOCKET
            SO_KEEPALIVE = socket.SO_KEEPALIVE
            IPPROTO_TCP = socket.IPPROTO_TCP
            # Deliberately no TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT

        monkeypatch.setattr(relay_mod, "socket", _FakeSocket)
        opts = _tcp_keepalive_socket_options()
        assert opts == [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)]

    def test_darwin_uses_tcp_keepalive_constant(self, monkeypatch):
        """macOS exposes TCP_KEEPALIVE (not TCP_KEEPIDLE) for the idle timer.

        On a darwin test host ``socket.TCP_KEEPALIVE`` is available
        natively, so we assert the full expected option set. On other
        hosts the constant is absent and the helper falls back to
        SO_KEEPALIVE only — also a valid state — which this test
        treats as the coverage boundary.
        """
        monkeypatch.setattr("mcp_stdio.relay.sys.platform", "darwin")
        opts = _tcp_keepalive_socket_options()
        assert self._so_keepalive_tuple(opts) is not None
        if hasattr(socket, "TCP_KEEPALIVE"):
            keys = [(level, opt) for (level, opt, _val) in opts]
            assert (socket.IPPROTO_TCP, socket.TCP_KEEPALIVE) in keys

    def test_darwin_full_set_deterministic(self, monkeypatch):
        """Cover the darwin idle+interval+count append path on any host OS by
        faking a socket module that exposes all three constants — so the macOS
        branch has deterministic coverage on the Linux CI matrix too."""
        monkeypatch.setattr("mcp_stdio.relay.sys.platform", "darwin")
        import mcp_stdio.relay as relay_mod

        class _FakeSocket:
            SOL_SOCKET = socket.SOL_SOCKET
            SO_KEEPALIVE = socket.SO_KEEPALIVE
            IPPROTO_TCP = socket.IPPROTO_TCP
            TCP_KEEPALIVE = 0x10
            TCP_KEEPINTVL = 0x101
            TCP_KEEPCNT = 0x102

        monkeypatch.setattr(relay_mod, "socket", _FakeSocket)
        opts = _tcp_keepalive_socket_options()
        keys = [(level, opt) for (level, opt, _val) in opts]
        assert (_FakeSocket.SOL_SOCKET, _FakeSocket.SO_KEEPALIVE) in keys
        assert (_FakeSocket.IPPROTO_TCP, _FakeSocket.TCP_KEEPALIVE) in keys
        assert (_FakeSocket.IPPROTO_TCP, _FakeSocket.TCP_KEEPINTVL) in keys
        assert (_FakeSocket.IPPROTO_TCP, _FakeSocket.TCP_KEEPCNT) in keys

    def test_windows_sets_only_so_keepalive(self, monkeypatch):
        """Windows has no per-socket idle/intvl tuning via setsockopt — we
        leave those to the SIO_KEEPALIVE_VALS ioctl (not supported here)
        and rely on the OS default probe interval."""
        monkeypatch.setattr("mcp_stdio.relay.sys.platform", "win32")
        opts = _tcp_keepalive_socket_options()
        assert opts == [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)]

    def test_unknown_platform_falls_back_to_so_keepalive(self, monkeypatch):
        monkeypatch.setattr("mcp_stdio.relay.sys.platform", "aix7")
        opts = _tcp_keepalive_socket_options()
        assert opts == [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)]

    def test_darwin_without_tcp_keepalive_degrades(self, monkeypatch):
        """Guards the macOS early-return: if a future darwin build
        somehow exposes TCP_KEEPINTVL without TCP_KEEPALIVE (the idle
        timer), the helper must NOT append the interval/count options
        on their own — they're meaningless without idle."""
        monkeypatch.setattr("mcp_stdio.relay.sys.platform", "darwin")
        import mcp_stdio.relay as relay_mod

        class _FakeSocket:
            SOL_SOCKET = socket.SOL_SOCKET
            SO_KEEPALIVE = socket.SO_KEEPALIVE
            IPPROTO_TCP = socket.IPPROTO_TCP
            # TCP_KEEPALIVE deliberately absent
            TCP_KEEPINTVL = 0x101  # arbitrary — must not leak into output
            TCP_KEEPCNT = 0x102

        monkeypatch.setattr(relay_mod, "socket", _FakeSocket)
        opts = _tcp_keepalive_socket_options()
        assert opts == [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)]



class TestMakeHttpxTransport:
    def test_enabled_injects_socket_options(self, monkeypatch):
        captured: list[object] = []

        class _FakeTransport:
            def __init__(self, *, socket_options):
                captured.append(socket_options)

        monkeypatch.setattr("mcp_stdio.relay.httpx.HTTPTransport", _FakeTransport)
        _make_httpx_transport(tcp_keepalive=True)
        assert captured, "HTTPTransport was not constructed"
        opts = captured[0]
        assert isinstance(opts, list)
        # SO_KEEPALIVE must always be present when enabled
        assert any(
            t[:2] == (socket.SOL_SOCKET, socket.SO_KEEPALIVE) for t in opts
        )

    def test_disabled_passes_none(self, monkeypatch):
        captured: list[object] = []

        class _FakeTransport:
            def __init__(self, *, socket_options):
                captured.append(socket_options)

        monkeypatch.setattr("mcp_stdio.relay.httpx.HTTPTransport", _FakeTransport)
        _make_httpx_transport(tcp_keepalive=False)
        assert captured[0] is None


class TestRunRespectsTcpKeepaliveFlag:
    """End-to-end: run() / run_sse() actually call _make_httpx_transport
    with the flag the caller passed. Closes the gap between the helper
    tests and the CLI wiring tests."""

    def test_run_passes_flag_to_make_transport(self, monkeypatch):
        recorded: list[bool] = []

        def spy(*, tcp_keepalive):
            recorded.append(tcp_keepalive)
            # Raise so run() bails before touching stdin/sockets
            raise RuntimeError("sentinel")

        monkeypatch.setattr("mcp_stdio.relay._make_httpx_transport", spy)
        for flag in (True, False):
            recorded.clear()
            with pytest.raises(RuntimeError, match="sentinel"):
                run("https://example.com/mcp", {}, tcp_keepalive=flag)
            assert recorded == [flag]

    def test_run_sse_passes_flag_to_make_transport(self, monkeypatch):
        recorded: list[bool] = []

        def spy(*, tcp_keepalive):
            recorded.append(tcp_keepalive)
            raise RuntimeError("sentinel")

        monkeypatch.setattr("mcp_stdio.relay._make_httpx_transport", spy)
        for flag in (True, False):
            recorded.clear()
            with pytest.raises(RuntimeError, match="sentinel"):
                run_sse("https://example.com/sse", {}, tcp_keepalive=flag)
            assert recorded == [flag]


# ---------------------------------------------------------------------------
# Cancel-aware response filter (claude-code#51073, python-sdk#2480)
# ---------------------------------------------------------------------------


class _FakeClock:
    """Monotonic clock stub for _CancelTracker TTL tests."""

    def __init__(self, start: float = 1000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, secs: float) -> None:
        self.t += secs


class TestCancelTracker:
    def test_add_and_contains_roundtrip(self):
        t = _CancelTracker()
        t.add(7)
        assert t.contains(7)
        assert not t.contains(8)

    def test_none_is_never_contained(self):
        t = _CancelTracker()
        t.add(None)
        assert not t.contains(None)

    def test_string_id_is_supported(self):
        t = _CancelTracker()
        t.add("req-42")
        assert t.contains("req-42")

    def test_id_zero_is_tracked(self):
        t = _CancelTracker()
        t.add(0)
        assert t.contains(0)

    def test_ttl_expires_entry(self):
        clock = _FakeClock()
        t = _CancelTracker(ttl=60.0, now=clock)
        t.add(5)
        clock.advance(30)
        assert t.contains(5)
        clock.advance(31)  # past 60 s
        assert not t.contains(5)

    def test_consume_drops_once_then_id_reuse_passes(self):
        """consume() removes the entry on first match, so a cancelled id's late
        response is dropped exactly once; a reused id within the TTL passes."""
        t = _CancelTracker()
        t.add(7)
        assert t.consume(7) is True  # the cancelled request's late response
        assert t.consume(7) is False  # a reused id=7 now passes through

    def test_consume_expired_returns_false_and_removes(self):
        clock = _FakeClock()
        t = _CancelTracker(ttl=60.0, now=clock)
        t.add(5)
        clock.advance(61)
        assert t.consume(5) is False
        # entry removed even though expired
        assert t.consume(5) is False

    def test_consume_none(self):
        assert _CancelTracker().consume(None) is False

    def test_discard_untracks_so_later_response_is_delivered(self):
        """#14(round11): discard() removes a tracked id (used when a request
        REUSES a cancelled id), so the id's response is then delivered, not
        dropped. discard(None) and discarding an absent id are safe no-ops."""
        t = _CancelTracker()
        t.add(9)
        assert t.contains(9)
        t.discard(9)
        assert not t.contains(9)
        assert t.consume(9) is False  # delivered (no longer tracked)
        # Safe no-ops:
        t.discard(9)  # already absent
        t.discard(None)
        assert not t.contains(None)

    def test_gc_bounds_memory(self):
        clock = _FakeClock()
        t = _CancelTracker(ttl=10.0, now=clock)
        # Insert 200 ids at t=0, all will have expired by t=20
        for i in range(200):
            t.add(i)
        clock.advance(20)
        # Trigger GC by pushing past threshold with fresh entries
        # (threshold is 256; we add 100 more at t=20 → _seen briefly holds
        # 300 before _gc_locked prunes the 200 expired ones.)
        for i in range(200, 300):
            t.add(i)
        # Access internals to verify GC ran (all old ids should be gone)
        # We can only check indirectly via contains(): old ids must not
        # be tracked any more.
        for i in range(200):
            assert not t.contains(i), f"old id {i} still tracked after GC"
        for i in range(200, 300):
            assert t.contains(i), f"fresh id {i} lost to GC"

    def test_thread_safety(self):
        t = _CancelTracker()
        errors: list[BaseException] = []

        def worker(start: int) -> None:
            try:
                for i in range(start, start + 100):
                    t.add(i)
                    t.contains(i)
            except BaseException as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(n * 100,)) for n in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert not errors, f"threads raised: {errors!r}"
        for i in range(800):
            assert t.contains(i)


class TestExtractCancelId:
    def test_detects_cancelled_notification_int_id(self):
        line = (
            '{"jsonrpc":"2.0","method":"notifications/cancelled",'
            '"params":{"requestId":7}}'
        )
        assert _extract_cancel_id(line) == 7

    def test_detects_cancelled_notification_string_id(self):
        line = (
            '{"jsonrpc":"2.0","method":"notifications/cancelled",'
            '"params":{"requestId":"req-42"}}'
        )
        assert _extract_cancel_id(line) == "req-42"

    def test_ignores_other_notifications(self):
        line = '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
        assert _extract_cancel_id(line) is None

    def test_ignores_plain_requests(self):
        line = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{}}'
        assert _extract_cancel_id(line) is None

    def test_ignores_malformed_json(self):
        # Passes the regex pre-check by having the method substring in
        # the raw text, but json.loads will fail.
        assert _extract_cancel_id('{bad json "method":"notifications/cancelled"') is None

    def test_ignores_missing_params(self):
        line = '{"jsonrpc":"2.0","method":"notifications/cancelled"}'
        assert _extract_cancel_id(line) is None

    def test_ignores_non_dict_params(self):
        line = (
            '{"jsonrpc":"2.0","method":"notifications/cancelled",'
            '"params":["requestId",1]}'
        )
        assert _extract_cancel_id(line) is None

    def test_substring_false_positive_guard(self):
        # The regex matches on any '"method":"notifications/cancelled"'
        # substring, but the verify step ensures the top-level method is
        # actually cancelled. A message where the string appears inside
        # a params value, not as the method, must NOT be treated as a
        # cancellation.
        line = (
            '{"jsonrpc":"2.0","method":"tools/call","id":1,'
            '"params":{"note":"\\"method\\":\\"notifications/cancelled\\""}}'
        )
        assert _extract_cancel_id(line) is None


class TestEscapeJsLineSeparators:
    """Escape raw U+2028/U+2029 so clients can't mis-frame (typescript-sdk#2155)."""

    def test_clean_line_unchanged_identity(self):
        line = '{"jsonrpc":"2.0","result":{"text":"hello"},"id":1}'
        # Same object returned (no allocation) when there's nothing to escape.
        assert _escape_js_line_separators(line) is line

    def test_escapes_line_separator(self):
        line = '{"result":{"text":"a\u2028b"}}'
        out = _escape_js_line_separators(line)
        assert "\u2028" not in out
        assert "\\u2028" in out

    def test_escapes_paragraph_separator(self):
        line = '{"result":{"text":"a\u2029b"}}'
        out = _escape_js_line_separators(line)
        assert "\u2029" not in out
        assert "\\u2029" in out

    def test_escaped_form_decodes_to_identical_json(self):
        """Lossless: the escaped wire form parses back to the same value."""
        original = {"result": {"text": "line\u2028para\u2029end"}}
        wire = _escape_js_line_separators(json.dumps(original, ensure_ascii=False))
        assert "\u2028" not in wire and "\u2029" not in wire
        assert json.loads(wire) == original

    def test_emit_escapes_passthrough(self, capsys):
        _emit('{"jsonrpc":"2.0","result":{"t":"x\u2028y"},"id":1}', None)
        out = capsys.readouterr().out
        assert "\u2028" not in out
        assert "\\u2028" in out

    def test_emit_escapes_and_still_filters_cancelled(self, capsys):
        """Escaping must not defeat the cancel filter: the line still parses."""
        t = _CancelTracker()
        t.add(1)
        _emit('{"jsonrpc":"2.0","result":{"t":"x\u2028y"},"id":1}', t)
        assert capsys.readouterr().out == ""


class TestEmit:
    def test_passthrough_when_tracker_is_none(self, capsys):
        _emit('{"jsonrpc":"2.0","result":{},"id":1}', None)
        assert capsys.readouterr().out.strip() == '{"jsonrpc":"2.0","result":{},"id":1}'

    def test_drops_response_with_cancelled_id(self, capsys):
        t = _CancelTracker()
        t.add(1)
        _emit('{"jsonrpc":"2.0","result":{},"id":1}', t)
        assert capsys.readouterr().out == ""

    def test_drops_error_response_with_cancelled_id(self, capsys):
        t = _CancelTracker()
        t.add(1)
        _emit('{"jsonrpc":"2.0","error":{"code":0,"message":"x"},"id":1}', t)
        assert capsys.readouterr().out == ""

    def test_drops_response_with_cancelled_zero_id(self, capsys):
        """id 0 is the canonical falsy-id regression class: the gate uses
        `rid is not None`, so a cancelled id 0 response must still be dropped."""
        t = _CancelTracker()
        t.add(0)
        _emit('{"jsonrpc":"2.0","result":{},"id":0}', t)
        assert capsys.readouterr().out == ""

    def test_forwards_uncancelled_zero_id(self, capsys):
        """An id-0 response that was NOT cancelled passes through unchanged."""
        t = _CancelTracker()
        t.add(99)
        _emit('{"jsonrpc":"2.0","result":{},"id":0}', t)
        assert capsys.readouterr().out.strip() == '{"jsonrpc":"2.0","result":{},"id":0}'

    def test_forwards_response_with_uncancelled_id(self, capsys):
        t = _CancelTracker()
        t.add(99)
        _emit('{"jsonrpc":"2.0","result":{},"id":1}', t)
        assert capsys.readouterr().out.strip() == '{"jsonrpc":"2.0","result":{},"id":1}'

    def test_forwards_notification_without_id(self, capsys):
        t = _CancelTracker()
        t.add(1)
        line = '{"jsonrpc":"2.0","method":"notifications/progress","params":{}}'
        _emit(line, t)
        assert capsys.readouterr().out.strip() == line

    def test_forwards_server_initiated_request(self, capsys):
        # Has an id but no result / no error — this is a server-
        # initiated request (e.g. sampling/createMessage). Even if the
        # numeric id coincides with a cancelled client request id, the
        # filter must not eat it; different message direction.
        t = _CancelTracker()
        t.add(1)
        line = '{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{}}'
        _emit(line, t)
        assert capsys.readouterr().out.strip() == line

    def test_forwards_malformed_json(self, capsys):
        t = _CancelTracker()
        t.add(1)
        _emit("not json", t)
        assert capsys.readouterr().out.strip() == "not json"

    def test_forwards_json_batch(self, capsys):
        # JSON-RPC batch (list) — current MCP HTTP spec forbids batches,
        # but if one ever shows up on the wire, pass it through unchanged
        # rather than silently dropping the whole batch.
        t = _CancelTracker()
        t.add(1)
        line = '[{"jsonrpc":"2.0","result":{},"id":1}]'
        _emit(line, t)
        assert capsys.readouterr().out.strip() == line

    def test_drops_merged_paginated_result(self, capsys):
        """#2(round12): a merged paginated list result (the shape
        _paginate_and_stream flushes via _emit) is dropped when its id was
        cancelled — closing the cancel-filter × pagination coverage gap."""
        t = _CancelTracker()
        t.add(1)
        merged = (
            '{"jsonrpc":"2.0","id":1,'
            '"result":{"tools":[{"name":"a"},{"name":"b"}]}}'
        )
        _emit(merged, t)
        assert capsys.readouterr().out.strip() == ""  # cancelled → dropped


class TestRunCancelFilter:
    """End-to-end: run() drops late responses for cancelled ids."""

    def _run_with_stdin(self, httpx_mock, stdin_lines, **kwargs):
        stdin_data = "\n".join(stdin_lines) + "\n"
        stdout = StringIO()
        with patch("sys.stdin", StringIO(stdin_data)), patch("sys.stdout", stdout):
            run(
                "https://example.com/mcp",
                {"Content-Type": "application/json"},
                **kwargs,
            )
        return stdout.getvalue()

    def test_response_then_cancel_ordinary_response_is_preserved(self, httpx_mock):
        # Baseline: request→response completes fully before the cancel is
        # read from stdin. The filter only drops responses whose id was
        # cancelled *before* the response reached stdout, so this normal-
        # case response must still be delivered. The actual "late response
        # gets dropped" case requires the response to arrive after the
        # cancel has been processed on stdin — that race is only
        # reproducible on the SSE transport where the reader thread
        # emits asynchronously; see TestRunSseCancelFilter below.
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":1}',
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(status_code=202, text="")  # cancel ACK
        output = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"tools/call","id":1}',
                (
                    '{"jsonrpc":"2.0","method":"notifications/cancelled",'
                    '"params":{"requestId":1}}'
                ),
            ],
        )
        assert '"ok":true' in output

    def test_reused_id_after_cancel_is_forwarded(self, httpx_mock):
        # A request that reuses a previously-cancelled id is a brand-new call;
        # its response must be FORWARDED, not dropped (JSON-RPC permits id reuse
        # once the prior call is done). Forwarding the new request untracks the
        # cancel for that id. (The genuine "late response for an in-flight
        # cancelled request is dropped" case is async-only — see
        # TestRunSseCancelFilter.)
        httpx_mock.add_response(status_code=202, text="")  # cancel ACK
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"keep":true},"id":7}',
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                (
                    '{"jsonrpc":"2.0","method":"notifications/cancelled",'
                    '"params":{"requestId":7}}'
                ),
                '{"jsonrpc":"2.0","method":"tools/call","id":7}',
            ],
        )
        assert '"keep":true' in output

    def test_cancel_is_forwarded_upstream(self, httpx_mock):
        httpx_mock.add_response(status_code=202, text="")
        self._run_with_stdin(
            httpx_mock,
            [
                (
                    '{"jsonrpc":"2.0","method":"notifications/cancelled",'
                    '"params":{"requestId":9}}'
                ),
            ],
        )
        reqs = httpx_mock.get_requests()
        assert len(reqs) == 1
        assert b"notifications/cancelled" in reqs[0].content

    def test_synthesized_error_response_bypasses_filter(self, httpx_mock):
        """Regression guard: mcp-stdio's own synthesized error responses
        must never be dropped even if the request id has been cancelled.

        Scenario: the client cancels id=5, then issues a request with the
        same id. The upstream is flaky — three ConnectErrors in a row
        exhaust the retry budget, and _post_and_stream falls through to
        ``print(_error_response(...), flush=True)``. That synthesized
        error is the gateway's own answer to the line the client just
        sent; if _emit were ever wired into _error_response's emit path
        a future refactor could silently drop it and the client would
        hang forever waiting for id=5. Guard that boundary here.
        """
        httpx_mock.add_response(status_code=202, text="")  # cancel ACK
        httpx_mock.add_exception(httpx.ConnectError("simulated"))
        httpx_mock.add_exception(httpx.ConnectError("simulated"))
        httpx_mock.add_exception(httpx.ConnectError("simulated"))
        output = self._run_with_stdin(
            httpx_mock,
            [
                (
                    '{"jsonrpc":"2.0","method":"notifications/cancelled",'
                    '"params":{"requestId":5}}'
                ),
                '{"jsonrpc":"2.0","method":"tools/call","id":5}',
            ],
        )
        # The synthesized error response must land on stdout; otherwise
        # the client is waiting for a response that never comes.
        lines = [x for x in output.strip().splitlines() if x]
        decoded = [json.loads(line) for line in lines]
        assert any(
            d.get("id") == 5 and "error" in d for d in decoded
        ), f"synthesized error response missing from: {lines!r}"

    def test_no_cancel_filter_lets_response_through(self, httpx_mock):
        httpx_mock.add_response(status_code=202, text="")  # cancel
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"kept":true},"id":7}',
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                (
                    '{"jsonrpc":"2.0","method":"notifications/cancelled",'
                    '"params":{"requestId":7}}'
                ),
                '{"jsonrpc":"2.0","method":"tools/call","id":7}',
            ],
            cancel_filter=False,
        )
        assert '"kept":true' in output


class TestRunSseCancelFilter:
    """End-to-end: run_sse() drops late responses for cancelled ids on SSE."""

    URL = "https://example.com/sse"

    def test_cancel_then_sse_message_is_dropped(self, httpx_mock):
        payload = '{"jsonrpc":"2.0","result":{"late":true},"id":11}'
        post_received = threading.Event()
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=abc\n\n"
            # Wait until the cancel POST has been observed before
            # sending the late response — this guarantees the cancel id
            # is in the tracker by the time the SSE reader emits.
            post_received.wait(timeout=3)
            yield f"event: message\ndata: {payload}\n\n".encode()
            time.sleep(0.1)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def on_post(request: httpx.Request) -> httpx.Response:
            post_received.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            on_post,
            url="https://example.com/messages?sessionId=abc",
        )

        stdin = _BlockingStdin(
            (
                '{"jsonrpc":"2.0","method":"notifications/cancelled",'
                '"params":{"requestId":11}}'
            ),
            release_stdin,
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})

        assert "late" not in stdout.getvalue()

    def test_sse_message_without_cancel_passes_through(self, httpx_mock):
        payload = '{"jsonrpc":"2.0","result":{"kept":true},"id":21}'
        post_received = threading.Event()
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=abc\n\n"
            post_received.wait(timeout=3)
            yield f"event: message\ndata: {payload}\n\n".encode()
            time.sleep(0.1)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def on_post(request: httpx.Request) -> httpx.Response:
            post_received.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            on_post,
            url="https://example.com/messages?sessionId=abc",
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"tools/call","id":21}',
            release_stdin,
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})

        assert "kept" in stdout.getvalue()

    def test_sse_reader_escapes_raw_line_separators_end_to_end(self, httpx_mock):
        """#13(round15): a message event whose JSON payload contains a RAW
        U+2028/U+2029 must reach stdout in escaped \\uXXXX form. Proves the
        reader-thread reply path runs through _emit's escape, not just the
        unit-tested _emit — a client framing on these chars can't mis-split."""
        # Raw separators sit inside a JSON string value (legal unescaped per
        # RFC 8259) — the gateway must escape them on the wire regardless.
        payload = '{"jsonrpc":"2.0","result":{"t":"a\u2028b\u2029c"},"id":31}'
        post_received = threading.Event()
        release_stdin = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=abc\n\n"
            post_received.wait(timeout=3)
            yield f"event: message\ndata: {payload}\n\n".encode()
            time.sleep(0.1)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def on_post(request: httpx.Request) -> httpx.Response:
            post_received.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            on_post,
            url="https://example.com/messages?sessionId=abc",
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"tools/call","id":31}',
            release_stdin,
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})

        out = stdout.getvalue()
        assert "\u2028" not in out and "\u2029" not in out
        assert "\\u2028" in out and "\\u2029" in out
        # Lossless: the escaped line still parses back to the original value.
        line = next(x for x in out.splitlines() if x and "31" in x)
        assert json.loads(line)["result"]["t"] == "a\u2028b\u2029c"

    def test_sse_id_reuse_supersedes_cancel(self, httpx_mock):
        """#19: a request REUSING a previously-cancelled id supersedes the
        cancel (tracker.discard), so its later SSE response is DELIVERED, not
        dropped — the SSE analogue of the streamable-path discard."""
        payload = '{"jsonrpc":"2.0","result":{"kept":true},"id":11}'
        second_post = threading.Event()
        release_stdin = threading.Event()
        post_count = {"n": 0}

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=abc\n\n"
            # Hold the late response until BOTH the cancel and the reused-id
            # request have been POSTed — by then discard() has run.
            second_post.wait(timeout=3)
            yield f"event: message\ndata: {payload}\n\n".encode()
            time.sleep(0.1)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def on_post(request: httpx.Request) -> httpx.Response:
            post_count["n"] += 1
            if post_count["n"] >= 2:
                second_post.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            on_post,
            url="https://example.com/messages?sessionId=abc",
            is_reusable=True,
        )

        class _TwoLineStdin:
            def __init__(self) -> None:
                self._lines = [
                    '{"jsonrpc":"2.0","method":"notifications/cancelled",'
                    '"params":{"requestId":11}}\n',
                    '{"jsonrpc":"2.0","method":"tools/call","id":11}\n',
                ]
                self._i = 0

            def __iter__(self):
                return self

            def __next__(self) -> str:
                if self._i < len(self._lines):
                    line = self._lines[self._i]
                    self._i += 1
                    return line
                release_stdin.wait(timeout=5)
                raise StopIteration

        stdout = StringIO()
        with patch("sys.stdin", _TwoLineStdin()), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})

        # The reused id superseded the cancel, so the response is delivered.
        assert "kept" in stdout.getvalue()


# ---------------------------------------------------------------------------
# HTTP 429 Retry-After handling (typescript-sdk#1892)
# ---------------------------------------------------------------------------


class TestParseRetryAfter:
    def test_delta_seconds_int(self):
        assert _parse_retry_after("5") == 5.0

    def test_delta_seconds_float(self):
        # Not technically legal per RFC 7231 (non-negative integer) but
        # some servers send it; be permissive.
        assert _parse_retry_after("2.5") == 2.5

    def test_delta_seconds_zero(self):
        assert _parse_retry_after("0") == 0.0

    def test_delta_seconds_negative_is_clamped_to_zero(self):
        assert _parse_retry_after("-1") == 0.0

    def test_missing_header(self):
        assert _parse_retry_after(None) is None

    def test_empty_string(self):
        assert _parse_retry_after("") is None

    def test_whitespace_only(self):
        assert _parse_retry_after("   ") is None

    def test_garbage(self):
        assert _parse_retry_after("soon") is None

    def test_nan_and_inf_rejected(self):
        assert _parse_retry_after("nan") is None
        assert _parse_retry_after("inf") is None

    def test_http_date_future(self):
        # An IMF-fixdate 10 seconds in the future → ~10s wait
        future = datetime.now(timezone.utc) + timedelta(seconds=10)
        header = email.utils.format_datetime(future, usegmt=True)
        result = _parse_retry_after(header)
        assert result is not None
        assert 5 < result <= 10  # tolerate clock skew

    def test_http_date_past(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=30)
        header = email.utils.format_datetime(past, usegmt=True)
        assert _parse_retry_after(header) == 0.0

    def test_http_date_malformed(self):
        assert _parse_retry_after("Tue, 99 Feb 3000 25:99:99 ZZZ") is None


class TestHandleRateLimit:
    class _Hdrs:
        def __init__(self, retry_after: str | None = None):
            self._h = {"retry-after": retry_after} if retry_after is not None else {}

        def get(self, k):
            return self._h.get(k.lower())

    def test_uses_retry_after_when_present(self):
        assert _handle_rate_limit(self._Hdrs("7"), attempt=1) == 7.0

    def test_falls_back_to_exponential_backoff_when_absent(self):
        # RETRY_DELAY * attempt
        assert _handle_rate_limit(self._Hdrs(), attempt=1) == 1.0
        assert _handle_rate_limit(self._Hdrs(), attempt=2) == 2.0

    def test_over_cap_gives_up(self):
        # 120 > _RATE_LIMIT_SLEEP_CAP_SECS (60)
        assert _handle_rate_limit(self._Hdrs("120"), attempt=1) is None

    def test_at_cap_is_honoured(self):
        assert _handle_rate_limit(self._Hdrs("60"), attempt=1) == 60.0

    def test_last_attempt_returns_none(self):
        # attempt == MAX_RETRIES means no more retries
        from mcp_stdio.relay import MAX_RETRIES
        assert _handle_rate_limit(self._Hdrs("5"), attempt=MAX_RETRIES) is None


class TestRun429Retry:
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

    def test_429_with_retry_after_then_200(self, httpx_mock, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        httpx_mock.add_response(
            status_code=429,
            headers={"retry-after": "2"},
            text="",
        )
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":1}',
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"tools/call","id":1}'],
        )
        assert '"ok":true' in output
        assert 2.0 in slept, f"expected a 2.0-second sleep, got {slept!r}"

    def test_429_without_retry_after_uses_backoff_then_200(
        self, httpx_mock, monkeypatch
    ):
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        httpx_mock.add_response(status_code=429, text="")  # no retry-after
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":1}',
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"tools/call","id":1}'],
        )
        assert '"ok":true' in output
        # RETRY_DELAY * 1 == 1.0
        assert 1.0 in slept

    def test_429_over_cap_surfaces_immediately(self, httpx_mock, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        httpx_mock.add_response(
            status_code=429,
            headers={"retry-after": "999999"},
            text="",
        )
        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"tools/call","id":1}'],
        )
        # Client sees a synthesized HTTP 429 error — no sleep happens
        decoded = [json.loads(x) for x in output.strip().splitlines() if x]
        assert any(
            d.get("id") == 1 and "error" in d and "429" in d["error"]["message"]
            for d in decoded
        ), f"expected HTTP 429 error response, got {decoded!r}"
        assert slept == [], f"expected no sleep for over-cap, got {slept!r}"
        # Only one upstream POST should have been made
        assert len(httpx_mock.get_requests()) == 1

    def test_429_over_cap_surfaces_retry_after_in_error_data(
        self, httpx_mock, monkeypatch
    ):
        """#8(round14): a 429 whose wait exceeds the cap surfaces the server's
        Retry-After as error.data.retryAfter so a client can back off."""
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: None)
        httpx_mock.add_response(
            status_code=429, headers={"retry-after": "120"}, text=""
        )
        output = self._run_with_stdin(
            httpx_mock, ['{"jsonrpc":"2.0","method":"tools/call","id":1}']
        )
        err = json.loads(output.strip())
        assert err["id"] == 1 and "429" in err["error"]["message"]
        assert err["error"]["data"]["retryAfter"] == 120.0

    def test_429_repeated_exhausts_retries_and_surfaces(
        self, httpx_mock, monkeypatch
    ):
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        # MAX_RETRIES = 3 → 3 POSTs, the first two sleep, the third
        # exhausts the counter and propagates the 429.
        for _ in range(3):
            httpx_mock.add_response(
                status_code=429,
                headers={"retry-after": "1"},
                text="",
            )

        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"tools/call","id":1}'],
        )
        decoded = [json.loads(x) for x in output.strip().splitlines() if x]
        assert any(
            d.get("id") == 1 and "error" in d and "429" in d["error"]["message"]
            for d in decoded
        )
        assert slept == [1.0, 1.0]
        assert len(httpx_mock.get_requests()) == 3


class TestRun503Retry:
    """503 Service Unavailable is a Retry-After carrier (RFC 9110 §10.2.3 /
    §15.6.4), so the relay backs-off-and-retries it exactly like 429 — a 503
    means the request was not processed, so replaying the POST is safe."""

    URL = "https://example.com/mcp"

    def _run_with_stdin(self, httpx_mock, stdin_lines, **kwargs):
        stdin_data = "\n".join(stdin_lines) + "\n"
        stdout = StringIO()
        with patch("sys.stdin", StringIO(stdin_data)), patch("sys.stdout", stdout):
            run(self.URL, {"Content-Type": "application/json"}, **kwargs)
        return stdout.getvalue()

    def test_503_with_retry_after_then_200(self, httpx_mock, monkeypatch):
        """#2(round15): a 503 with Retry-After sleeps that long, then the
        retried POST's 200 is delivered normally."""
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        httpx_mock.add_response(
            status_code=503, headers={"retry-after": "2"}, text=""
        )
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":1}',
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock, ['{"jsonrpc":"2.0","method":"tools/call","id":1}']
        )
        assert '"ok":true' in output
        assert 2.0 in slept, f"expected a 2.0-second sleep, got {slept!r}"

    def test_503_without_retry_after_uses_backoff_then_200(
        self, httpx_mock, monkeypatch
    ):
        """A 503 with no Retry-After falls back to the same linear backoff as
        429 / transient errors, then succeeds on retry."""
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        httpx_mock.add_response(status_code=503, text="")  # no retry-after
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":1}',
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock, ['{"jsonrpc":"2.0","method":"tools/call","id":1}']
        )
        assert '"ok":true' in output
        assert 1.0 in slept  # RETRY_DELAY * 1

    def test_503_over_cap_surfaces_retry_after_in_error_data(
        self, httpx_mock, monkeypatch
    ):
        """A 503 whose Retry-After exceeds the cap gives up immediately and
        surfaces HTTP 503 with error.data.retryAfter — mirroring 429."""
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        httpx_mock.add_response(
            status_code=503, headers={"retry-after": "120"}, text=""
        )
        output = self._run_with_stdin(
            httpx_mock, ['{"jsonrpc":"2.0","method":"tools/call","id":1}']
        )
        err = json.loads(output.strip())
        assert err["id"] == 1 and "503" in err["error"]["message"]
        assert err["error"]["data"]["retryAfter"] == 120.0
        assert slept == [], f"expected no sleep for over-cap, got {slept!r}"
        assert len(httpx_mock.get_requests()) == 1


class TestRunSse429Retry:
    URL = "https://example.com/sse"

    def test_429_with_retry_after_then_200(self, httpx_mock, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        release_stdin = threading.Event()
        post_done = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=abc\n\n"
            post_done.wait(timeout=3)
            # no message event needed — the POST was 202 (notification)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        posts: list[int] = []

        def on_post(request: httpx.Request) -> httpx.Response:
            posts.append(len(posts) + 1)
            if len(posts) == 1:
                return httpx.Response(
                    status_code=429,
                    headers={"retry-after": "3"},
                )
            post_done.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            on_post,
            url="https://example.com/messages?sessionId=abc",
            is_reusable=True,
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            release_stdin,
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})

        assert 3.0 in slept, f"expected a 3.0-second sleep, got {slept!r}"
        assert len(posts) == 2

    def test_429_over_cap_surfaces_without_sleeping(self, httpx_mock, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        release_stdin = threading.Event()
        post_seen = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=abc\n\n"
            post_seen.wait(timeout=3)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        posts: list[int] = []

        def on_post(request: httpx.Request) -> httpx.Response:
            posts.append(len(posts) + 1)
            post_seen.set()
            return httpx.Response(
                status_code=429,
                headers={"retry-after": "999999"},
            )

        httpx_mock.add_callback(
            on_post,
            url="https://example.com/messages?sessionId=abc",
            is_reusable=True,
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"tools/call","id":7}',
            release_stdin,
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})

        # Over-cap → no sleep, POST happens exactly once, client receives
        # a synthesized HTTP 429 error response for id=7.
        assert slept == [], f"expected no sleep for over-cap, got {slept!r}"
        assert len(posts) == 1
        decoded = [json.loads(x) for x in stdout.getvalue().splitlines() if x]
        assert any(
            d.get("id") == 7 and "error" in d and "429" in d["error"]["message"]
            for d in decoded
        ), f"expected HTTP 429 error response, got {decoded!r}"

    def test_429_repeated_exhausts_and_surfaces(self, httpx_mock, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        release_stdin = threading.Event()
        last_post = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=abc\n\n"
            last_post.wait(timeout=3)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        posts: list[int] = []

        def on_post(request: httpx.Request) -> httpx.Response:
            posts.append(len(posts) + 1)
            if len(posts) >= 3:
                last_post.set()
            return httpx.Response(
                status_code=429,
                headers={"retry-after": "1"},
            )

        httpx_mock.add_callback(
            on_post,
            url="https://example.com/messages?sessionId=abc",
            is_reusable=True,
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"tools/call","id":8}',
            release_stdin,
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})

        # MAX_RETRIES = 3 → 3 POSTs, sleeps on the first two only.
        assert len(posts) == 3
        assert slept == [1.0, 1.0], f"expected two 1s sleeps, got {slept!r}"
        decoded = [json.loads(x) for x in stdout.getvalue().splitlines() if x]
        assert any(
            d.get("id") == 8 and "error" in d and "429" in d["error"]["message"]
            for d in decoded
        )


class TestRunSse503Retry:
    """The legacy SSE POST path treats 503 like 429 too (#2 round15)."""

    URL = "https://example.com/sse"

    def test_503_with_retry_after_then_202(self, httpx_mock, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        release_stdin = threading.Event()
        post_done = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=abc\n\n"
            post_done.wait(timeout=3)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        posts: list[int] = []

        def on_post(request: httpx.Request) -> httpx.Response:
            posts.append(len(posts) + 1)
            if len(posts) == 1:
                return httpx.Response(status_code=503, headers={"retry-after": "3"})
            post_done.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            on_post,
            url="https://example.com/messages?sessionId=abc",
            is_reusable=True,
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            release_stdin,
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})

        assert 3.0 in slept, f"expected a 3.0-second sleep, got {slept!r}"
        assert len(posts) == 2

    def test_503_over_cap_surfaces_retry_after_in_error_data(
        self, httpx_mock, monkeypatch
    ):
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        release_stdin = threading.Event()
        post_seen = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sessionId=abc\n\n"
            post_seen.wait(timeout=3)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        posts: list[int] = []

        def on_post(request: httpx.Request) -> httpx.Response:
            posts.append(len(posts) + 1)
            post_seen.set()
            return httpx.Response(status_code=503, headers={"retry-after": "120"})

        httpx_mock.add_callback(
            on_post,
            url="https://example.com/messages?sessionId=abc",
            is_reusable=True,
        )

        stdin = _BlockingStdin(
            '{"jsonrpc":"2.0","method":"tools/call","id":9}',
            release_stdin,
        )
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})

        assert slept == [], f"expected no sleep for over-cap, got {slept!r}"
        assert len(posts) == 1
        decoded = [json.loads(x) for x in stdout.getvalue().splitlines() if x]
        match = [d for d in decoded if d.get("id") == 9 and "error" in d]
        assert match and "503" in match[0]["error"]["message"]
        assert match[0]["error"]["data"]["retryAfter"] == 120.0


class TestPaginate429Retry:
    """_post_parsed (pagination path) honours Retry-After on 429 too."""

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

    def test_paginated_list_429_then_200(self, httpx_mock, monkeypatch):
        """A paginated tools/list request runs through _post_parsed; a 429
        on page 1 must trigger the Retry-After sleep + retry exactly like
        the streaming path, and the eventual 200 must be merged and
        emitted normally."""
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        # Page 1: 429 with Retry-After: 2
        httpx_mock.add_response(
            status_code=429,
            headers={"retry-after": "2"},
            text="",
        )
        # Page 1 retry: 200 with a single-page result (no nextCursor)
        httpx_mock.add_response(
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "tools": [
                            {"name": "t1"},
                            {"name": "t2"},
                        ]
                    },
                }
            ),
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","id":1,"method":"tools/list"}'],
        )
        assert 2.0 in slept, f"expected a 2.0-second sleep, got {slept!r}"
        decoded = [json.loads(x) for x in output.strip().splitlines() if x]
        assert len(decoded) == 1
        merged = decoded[0]
        names = [t["name"] for t in merged["result"]["tools"]]
        assert names == ["t1", "t2"]
        assert "nextCursor" not in merged["result"]

    def test_paginated_list_429_over_cap_surfaces_error_data(
        self, httpx_mock, monkeypatch
    ):
        """#12(round15): a page-1 429 whose Retry-After exceeds the cap gives
        up in _post_parsed and the pagination caller surfaces one JSON-RPC
        error carrying error.data.retryAfter (the over-cap give-up branch)."""
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        httpx_mock.add_response(
            status_code=429, headers={"retry-after": "999999"}, text=""
        )
        output = self._run_with_stdin(
            httpx_mock, ['{"jsonrpc":"2.0","id":1,"method":"tools/list"}']
        )
        err = json.loads(output.strip())
        assert err["id"] == 1 and "429" in err["error"]["message"]
        assert err["error"]["data"]["retryAfter"] == 999999.0
        assert slept == [], f"expected no sleep for over-cap, got {slept!r}"
        assert len(httpx_mock.get_requests()) == 1

    def test_paginated_list_503_then_200(self, httpx_mock, monkeypatch):
        """The pagination path honours 503 Retry-After too (#2 round15)."""
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        httpx_mock.add_response(
            status_code=503, headers={"retry-after": "2"}, text=""
        )
        httpx_mock.add_response(
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"tools": [{"name": "t1"}]},
                }
            ),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock, ['{"jsonrpc":"2.0","id":1,"method":"tools/list"}']
        )
        assert 2.0 in slept, f"expected a 2.0-second sleep, got {slept!r}"
        merged = json.loads(output.strip())
        assert [t["name"] for t in merged["result"]["tools"]] == ["t1"]
