"""Tests for mcp_stdio.relay module."""

import copy
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
    _COLD_START_LIST_CHANGED,
    _LISTEN_FORWARDED_NOTIFICATIONS,
    _LISTEN_ID_PREFIX,
    _LISTEN_MAX_SUBSCRIPTIONS,
    _LISTEN_RES_ID_PREFIX,
    _RELAY_ID_NAMESPACE,
    _RESOURCE_UPDATED_METHOD,
    _CancelTracker,
    _ModernState,
    _ResourceSubscriptions,
    _SseState,
    _build_discover_probe_request,
    _build_listen_params,
    _consume_restart,
    _detect_paginated_list,
    _drain_pending,
    _emit,
    _encode_mcp_name,
    _enforce_lf_stdio,
    _error_response,
    _escape_js_line_separators,
    _extract_cancel_id,
    _extract_id_and_presence,
    _extract_input_required,
    _extract_log_level,
    _extract_method_and_name,
    _extract_response_id,
    _extract_protocol_version,
    _handle_listen_message,
    _handle_modern_special_method,
    _handle_rate_limit,
    _inject_modern_meta,
    _listen_stream_loop,
    _log_unhonored_subscriptions,
    _is_initialize_request,
    _is_pure_response_for,
    _is_recognized_modern_error,
    _iter_sse_events,
    _iter_sse_lines,
    _looks_like_initialize,
    _make_httpx_transport,
    _mcp_request_headers,
    _negotiate_modern_version,
    _normalize_null_arguments,
    _parse_retry_after,
    _parse_auth_params,
    _parse_streamable_response,
    _parse_www_authenticate_scope,
    _post_and_stream,
    _probe_protocol_era,
    _cold_start_loop,
    _cold_start_response,
    _proactive_refresh_loop,
    _reinitialize,
    _report_discover,
    _report_initialize,
    _reseed_discover_probe,
    _seed_modern_state_from_discover,
    _start_proactive_refresh,
    _stop_proactive_refresh,
    _strip_listen_subscription_id,
    _with_resource_subscriptions,
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
                threading.Thread(target=writer, args=(tag,)) for tag in ("a", "b")
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
        """Some redirected streams lack reconfigure(); must not raise — AND the
        win32 branch must actually run the hasattr guard. The
        stream records the `reconfigure` lookup, so `checked` is True only if the
        win32 path was taken; on a non-win32 early-return it would stay False."""

        class TrackingStream:
            def __init__(self):
                self.checked = False

            def __getattr__(self, name):
                # Only `reconfigure` is missing; hasattr() probes it here.
                if name == "reconfigure":
                    self.checked = True
                raise AttributeError(name)

        stdin_stream, stdout_stream = TrackingStream(), TrackingStream()
        with (
            patch("mcp_stdio.relay.sys.platform", "win32"),
            patch("mcp_stdio.relay.sys.stdin", stdin_stream),
            patch("mcp_stdio.relay.sys.stdout", stdout_stream),
        ):
            _enforce_lf_stdio()  # must not raise
        # The win32 branch ran the hasattr guard on both streams.
        assert stdin_stream.checked and stdout_stream.checked


# --- _extract_id_and_presence ---


class TestExtractIdAndPresence:
    """The hot-path helper returns (id_value, has_id) from one parse, crucially
    distinguishing a PRESENT id:null (a request) from an ABSENT id (a
    notification) — the distinction req_has_id gating relies on."""

    def test_numeric_id(self):
        line = json.dumps({"jsonrpc": "2.0", "method": "init", "id": 1})
        assert _extract_id_and_presence(line) == (1, True)

    def test_string_id(self):
        line = json.dumps({"jsonrpc": "2.0", "method": "init", "id": "abc"})
        assert _extract_id_and_presence(line) == ("abc", True)

    def test_zero_id(self):
        # id 0 is a VALID JSON-RPC id but falsy — the helper must return int 0
        # with has_id True, not collapse it to a notification.
        line = json.dumps({"jsonrpc": "2.0", "method": "init", "id": 0})
        assert _extract_id_and_presence(line) == (0, True)

    def test_null_id_is_present(self):
        # A present id:null IS a request → (None, True), NOT a notification.
        line = json.dumps({"jsonrpc": "2.0", "method": "init", "id": None})
        assert _extract_id_and_presence(line) == (None, True)

    def test_missing_id_is_notification(self):
        line = json.dumps({"jsonrpc": "2.0", "method": "notify"})
        assert _extract_id_and_presence(line) == (None, False)

    def test_invalid_json(self):
        assert _extract_id_and_presence("not json") == (None, False)

    def test_empty_string(self):
        assert _extract_id_and_presence("") == (None, False)

    def test_json_array(self):
        assert _extract_id_and_presence("[1, 2, 3]") == (None, False)


# --- _error_response ---


class TestErrorResponse:
    def test_basic_error(self):
        result = json.loads(_error_response("something failed", req_id=1))
        assert result["jsonrpc"] == "2.0"
        assert result["error"]["code"] == -32000
        assert result["error"]["message"] == "something failed"
        assert result["id"] == 1

    def test_zero_id(self):
        # A 4xx error synthesized for a request with id 0 must echo 0, not null,
        # so the client can correlate the response (falsy-id regression class).
        result = json.loads(_error_response("err", req_id=0))
        assert result["id"] == 0

    def test_null_id(self):
        result = json.loads(_error_response("err"))
        assert result["id"] is None

    def test_string_id(self):
        result = json.loads(_error_response("err", req_id="req-42"))
        assert result["id"] == "req-42"

    def test_code_defaults_to_server_error_and_can_be_overridden(self):
        """#270 PR C: the MRTR bridge needs -32600 Invalid Request for the
        cases where the fault is in the MESSAGE (an unbridgeable
        input_required result; a client id already owning a pending
        transaction; a client request id intruding on the relay's reserved
        namespace) rather than in the relay's attempt to deliver it.
        Every pre-existing caller must keep the -32000 default."""
        assert json.loads(_error_response("e", 1))["error"]["code"] == -32000
        assert (
            json.loads(_error_response("e", 1, code=-32600))["error"]["code"] == -32600
        )
        # data and code compose.
        err = json.loads(_error_response("e", 1, data={"x": 1}, code=-32600))["error"]
        assert err["data"] == {"x": 1}
        assert err["code"] == -32600


# --- _extract_input_required (MRTR bridge, #270 Phase 2 PR C) ---


class TestExtractInputRequired:
    """The MRTR interception gate: is this streamed payload an
    InputRequiredResult for the request WE sent?"""

    def _payload(self, **over):
        msg = {
            "jsonrpc": "2.0",
            "id": 5,
            "result": {"resultType": "input_required", "requestState": "blob"},
        }
        msg.update(over)
        return json.dumps(msg)

    def test_matching_input_required_returns_the_result(self):
        assert _extract_input_required(self._payload(), 5) == {
            "resultType": "input_required",
            "requestState": "blob",
        }

    def test_id_mismatch_is_not_ours(self):
        """A retry POST carries the relay's OWN fresh id ("The JSON-RPC id
        MUST be different between the initial request and the retry" —
        MRTR client requirement 3), so id equality is the only way to tell
        our answer from an unrelated frame interleaved on the stream."""
        assert _extract_input_required(self._payload(), 6) is None

    def test_id_compare_is_type_aware(self):
        """`"5" == 5` is False in Python — the same property that makes the
        relay's string id namespaces collision-proof (C10)."""
        assert _extract_input_required(self._payload(id="5"), 5) is None

    def test_other_result_type_passes_through(self):
        """Gated EXACTLY: `resultType` is an open-ended string in the
        schema, so a future discriminator the bridge does not understand
        must fall through to verbatim forwarding, not be swallowed."""
        assert (
            _extract_input_required(
                self._payload(result={"resultType": "input_required_v2"}), 5
            )
            is None
        )
        assert (
            _extract_input_required(self._payload(result={"resultType": "cool"}), 5)
            is None
        )

    def test_error_response_is_not_an_input_required(self):
        msg = json.dumps(
            {"jsonrpc": "2.0", "id": 5, "error": {"code": -1, "message": "x"}}
        )
        assert _extract_input_required(msg, 5) is None

    def test_notification_and_server_request_pass_through(self):
        """Only a PURE response can be ours; a notification or an
        interleaved server-initiated request is not an answer to anything."""
        note = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress"})
        assert _extract_input_required(note, 5) is None
        req = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "ping",
                "result": {"resultType": "input_required"},
            }
        )
        assert _extract_input_required(req, 5) is None

    def test_malformed_and_non_object_result_pass_through(self):
        assert _extract_input_required("not json", 5) is None
        assert _extract_input_required(self._payload(result="scalar"), 5) is None
        assert _extract_input_required(json.dumps([1, 2]), 5) is None


# --- _is_pure_response_for (MRTR hook latch, #356 deep-review finding) ---


class TestIsPureResponseFor:
    """The id-match check the per-POST hook latch uses, independent of
    ``_extract_input_required``'s ``resultType`` gate and of
    ``_mrtr_rekey``'s ``upstream_id == client_id`` short-circuit (neither of
    which can tell the hook "did this payload carry the id I'm watching")."""

    def test_matching_response_is_true(self):
        payload = json.dumps({"jsonrpc": "2.0", "id": 5, "result": {"x": 1}})
        assert _is_pure_response_for(payload, 5) is True

    def test_matching_error_response_is_true(self):
        """Unlike ``_extract_input_required``, an ``error`` response still
        counts as a match — a duplicate frame under an already-matched id is
        the violation, regardless of whether it is shaped as a result or an
        error."""
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 5, "error": {"code": -1, "message": "x"}}
        )
        assert _is_pure_response_for(payload, 5) is True

    def test_id_mismatch_is_false(self):
        payload = json.dumps({"jsonrpc": "2.0", "id": 6, "result": {}})
        assert _is_pure_response_for(payload, 5) is False

    def test_id_compare_is_type_aware(self):
        payload = json.dumps({"jsonrpc": "2.0", "id": "5", "result": {}})
        assert _is_pure_response_for(payload, 5) is False

    def test_notification_and_server_request_are_false(self):
        note = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress"})
        assert _is_pure_response_for(note, 5) is False
        req = json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping", "result": {}})
        assert _is_pure_response_for(req, 5) is False

    def test_malformed_payload_is_false(self):
        assert _is_pure_response_for("not json", 5) is False
        assert _is_pure_response_for(json.dumps([1, 2]), 5) is False


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
            result = _post_and_stream(
                client, "https://example.com/mcp", '{"id":1}', {}, 1
            )
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
        # the interrupt now returns a 200 result (carrying any
        # captured protocol_version) rather than None — the payload was already
        # delivered, so its negotiated state must not be discarded.
        assert result is not None and result.status_code == 200
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
        """HIGH: a 200 whose body fails to decode (bad
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

    def test_recovery_write_brokenpipe_does_not_crash(self, httpx_mock):
        """: when the client has closed stdout, _write_line raises
        BrokenPipeError. The outer run() handler's own recovery write would then
        re-raise it and crash out of the loop — breaking the documented
        keep-the-session-alive guarantee. The recovery write must swallow a
        second OSError so run() exits cleanly instead of propagating."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json"},
        )
        stdin_data = '{"jsonrpc":"2.0","method":"call","id":1}\n'
        # Every _write_line raises a broken pipe (client gone): the response
        # write raises, the outer handler catches it, and its recovery write
        # raises again — which must be swallowed, not propagate out of run().
        with (
            patch("sys.stdin", StringIO(stdin_data)),
            patch("sys.stdout", StringIO()),
            patch(
                "mcp_stdio.relay._write_line",
                side_effect=BrokenPipeError(32, "Broken pipe"),
            ),
        ):
            # Must NOT raise.
            run("https://example.com/mcp", {"Content-Type": "application/json"})

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
        # the emitted-interrupt branch now returns a 200 result
        # (carrying any captured protocol_version) rather than None, so the
        # already-delivered payload's negotiated state is not discarded.
        assert result is not None and result.status_code == 200
        lines = [x for x in stdout.getvalue().strip().splitlines() if x]
        # The server payload is passed through; no synthesized id:null error.
        assert lines == [delivered]

    def test_initialize_interrupt_preserves_protocol_version(self, httpx_mock):
        """: an initialize SSE stream that emits the InitializeResult
        and THEN errors must still surface the captured protocolVersion (a 200
        result), so the relay keeps injecting MCP-Protocol-Version on subsequent
        requests instead of losing the negotiated version to a None return."""
        init_result = (
            '{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":1}'
        )

        def gen():
            yield f"event: message\ndata: {init_result}\n\n".encode()
            raise httpx.ReadError("dropped after the InitializeResult")

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
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                {},
                1,
                capture_init=True,
                has_id=True,
            )
        assert result is not None
        assert result.status_code == 200
        assert result.protocol_version == "2025-06-18"

    def test_sse_only_ping_event_synthesizes_error_for_request(self, httpx_mock):
        """: a 200 text/event-stream body with ONLY a non-message
        (ping) event delivers no JSON-RPC payload, so a request-with-id must get
        a synthesized 'empty response' error — the SSE arm of the empty-200
        guard, previously covered only on the JSON arm."""
        httpx_mock.add_response(
            text="event: ping\ndata: {}\n\n",
            headers={"content-type": "text/event-stream"},
        )
        client = httpx.Client()
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            result = _post_and_stream(
                client,
                "https://example.com/mcp",
                '{"jsonrpc":"2.0","method":"x","id":9}',
                {},
                9,
                has_id=True,
            )
        assert result is not None and result.status_code == 200
        err = json.loads(stdout.getvalue().strip())
        assert err["id"] == 9
        assert "empty response" in err["error"]["message"]

    def test_sse_only_ping_event_notification_stays_silent(self, httpx_mock):
        """The symmetric notification (no id) case stays silent."""
        httpx_mock.add_response(
            text="event: ping\ndata: {}\n\n",
            headers={"content-type": "text/event-stream"},
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
        assert stdout.getvalue().strip() == ""

    def test_empty_200_body_to_request_synthesizes_error(self, httpx_mock):
        """: a 200 with NO JSON-RPC payload would leave a
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

    def test_malformed_url_returns_not_same_origin(self):
        """: a malformed URL (urlsplit/.port raises ValueError, e.g. a
        non-numeric port) must be treated as NOT same-origin — the conservative,
        fail-closed answer for the SSE cross-origin credential guard."""
        assert not _same_origin("https://h.example:notaport/a", "https://h.example/b")
        assert not _same_origin("https://h.example/a", "https://h.example:99999/b")


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

    @pytest.mark.parametrize(
        "pv",
        [
            "2025-06-18\r\nEvil: 1",  # CRLF header injection
            "2025-06-18\nEvil: 1",  # bare LF
            "2025-06-18\rEvil",  # bare CR
            "2025-06-18\x00",  # NUL
            "2025 06 18",  # space (not a visible-ASCII token)
            "ver\x7fsion",  # DEL control char
            "",  # empty
        ],
    )
    def test_malformed_protocol_version_rejected(self, pv):
        """: protocolVersion comes from the JSON body and is injected
        as the MCP-Protocol-Version request header, so a value carrying CR/LF/NUL
        (or any non-visible-ASCII) must be rejected to None — otherwise it poisons
        the header and httpx's send-time LocalProtocolError bricks the session."""
        payload = json.dumps({"result": {"protocolVersion": pv}})
        assert _extract_protocol_version(payload) is None

    def test_valid_date_form_protocol_version_accepted(self):
        # The canonical date-form version is visible ASCII → accepted.
        payload = '{"result":{"protocolVersion":"2024-11-05"}}'
        assert _extract_protocol_version(payload) == "2024-11-05"


class TestIsInitializeRequest:
    """_is_initialize_request is the parse-AUTHORITATIVE gate (vs the cheap
    _looks_like_initialize substring pre-filter) used to strip the
    MCP-Protocol-Version header AND to capture the negotiated version. A false
    positive would wrongly drop the header from a real tools/call."""

    def test_real_initialize_request_is_true(self):
        assert _is_initialize_request('{"jsonrpc":"2.0","method":"initialize","id":1}')

    def test_nested_method_initialize_is_false(self):
        # The substring matches the cheap regex, but the top-level method is
        # tools/call, so the authoritative check rejects it.
        line = (
            '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":'
            '{"arguments":{"method":"initialize"}}}'
        )
        assert _looks_like_initialize(line) is True  # regex pre-filter matched
        assert _is_initialize_request(line) is False  # but parse says no

    def test_malformed_json_after_regex_match_is_false(self):
        """: the regex pre-filter matches but the line is not valid
        JSON — the json.loads-failure branch must return False, not raise. (The
        only protocol-version gate path that previously had no direct test.)"""
        line = '{"method":"initialize" broken json'
        assert _looks_like_initialize(line) is True  # regex matched the substring
        assert _is_initialize_request(line) is False  # parse failed → not an init

    def test_non_matching_line_short_circuits_to_false(self):
        # No substring → cheap regex returns False without a parse.
        assert _is_initialize_request('{"method":"tools/list","id":1}') is False


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
        """: relay deliberately forgoes Last-Event-ID resumption and
        server-driven retry timing, so the WHATWG decoder must ignore `id:` and
        `retry:` lines (fall through the field dispatch) without disturbing the
        surrounding event — pins the documented ignore-and-continue behaviour."""
        lines = ["id: 5", "retry: 1000", "data: hi", ""]
        assert list(_iter_sse_events(lines)) == [("message", "hi")]
        # interleaved between data lines too — the data buffer is unaffected
        lines = ["data:a", "id: 7", "data:b", "retry: 200", ""]
        assert list(_iter_sse_events(lines)) == [("message", "a\nb")]

    def test_empty_event_field_defaults_to_message(self):
        """: WHATWG 'dispatch the event' uses the default type
        'message' when the event-type buffer is the empty string, so an
        explicitly-empty `event:` must NOT yield a ('', data) event that the
        message-only consumers then drop."""
        assert list(_iter_sse_events(["event:", "data:hi", ""])) == [("message", "hi")]
        # An empty event: after a real one resets back to the default too.
        assert list(
            _iter_sse_events(["event: ping", "data:a", "", "event:", "data:b", ""])
        ) == [
            ("ping", "a"),
            ("message", "b"),
        ]

    def test_trailing_event_without_blank_line_flushed(self):
        # httpx may not surface a final empty line; a complete event must still
        # be dispatched at end of input.
        assert list(_iter_sse_events(["data:a"])) == [("message", "a")]

    def test_event_without_data_not_dispatched(self):
        assert list(_iter_sse_events(["event:message", ""])) == []

    def test_empty_data_value_not_dispatched(self):
        """: WHATWG suppresses dispatch when the data buffer is the
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
        """: WHATWG SSE stream-decode removes ONE leading U+FEFF BOM.
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
        assert list(_iter_sse_events(_split_sse_text(body))) == [("endpoint", "/m")]


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
        output = self._run_with_stdin(
            httpx_mock, ['{"jsonrpc":"2.0","method":"init","id":1}']
        )
        assert json.loads(output.strip()) == json.loads(body)

    def test_sse_response(self, httpx_mock):
        sse_body = 'data: {"jsonrpc":"2.0","result":{},"id":1}\n\n'
        httpx_mock.add_response(
            text=sse_body,
            headers={"content-type": "text/event-stream"},
        )
        output = self._run_with_stdin(
            httpx_mock, ['{"jsonrpc":"2.0","method":"init","id":1}']
        )
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

    def test_error_response_session_id_not_adopted(self, httpx_mock):
        """: a session id echoed on a 4xx/5xx error response must NOT
        be carried into the next request — the relay would otherwise send an id
        the server just rejected. Only a non-error response rotates session_id."""
        # Line 1: 200 establishes session "good".
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "good"},
        )
        # Line 2: 500 echoes a DIFFERENT session id — must be ignored (the relay
        # synthesizes an error and does not adopt the rejected id).
        httpx_mock.add_response(
            status_code=500,
            text="",
            headers={
                "content-type": "application/json",
                "mcp-session-id": "bad-rotated",
            },
        )
        # Line 3: 200 — must still carry "good", not "bad-rotated".
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":3}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
                '{"jsonrpc":"2.0","method":"call","id":3}',
            ],
        )
        reqs = httpx_mock.get_requests()
        assert reqs[1].headers.get("mcp-session-id") == "good"
        # The 500's "bad-rotated" was NOT adopted — request 3 still sends "good".
        assert reqs[2].headers.get("mcp-session-id") == "good"

    def test_202_to_request_session_id_not_adopted(self, httpx_mock):
        """: a 202 returned to a request-WITH-id is synthesized into a
        JSON-RPC error (a non-compliant server can't ack a request), so its echoed
        (rotated) session id must NOT be adopted — exactly like a 4xx/5xx. The
        pre-recovery `< 400` gate previously admitted 202; the next request must
        still carry the established session, not the just-rejected one."""
        # Line 1: 200 establishes session "good".
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "good"},
        )
        # Line 2: 202 to a request-with-id, echoing a ROTATED id — must be ignored
        # (the relay synthesizes an error for the 202-to-request).
        httpx_mock.add_response(
            status_code=202,
            text="",
            headers={
                "content-type": "application/json",
                "mcp-session-id": "bad-rotated",
            },
        )
        # Line 3: 200 — must still carry "good", not "bad-rotated".
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":3}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
                '{"jsonrpc":"2.0","method":"call","id":3}',
            ],
        )
        reqs = httpx_mock.get_requests()
        # The 202's "bad-rotated" was NOT adopted — request 3 still sends "good".
        assert reqs[2].headers.get("mcp-session-id") == "good"

    def test_unparseable_403_session_id_not_adopted_with_scope_upgrader(
        self, httpx_mock
    ):
        """: the pre-recovery 403 adoption gate must require a PARSEABLE
        insufficient_scope challenge. A generic 403 (no scope param) that echoes a
        rotated session id, while a scope_upgrader exists, must NOT adopt that id —
        the step-up branch will not consume it, so adopting would poison the next
        stdin line for nothing."""
        # Line 1: 200 establishes session "good".
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "good"},
        )
        # Line 2: 403 with a NON-insufficient_scope challenge (unparseable scope)
        # that rotates the session id — must be ignored. No step-up retry fires.
        httpx_mock.add_response(
            status_code=403,
            text="",
            headers={
                "content-type": "application/json",
                "www-authenticate": 'Bearer error="invalid_token"',
                "mcp-session-id": "bad-rotated",
            },
        )
        # Line 3: 200 — must still carry "good", not "bad-rotated".
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":3}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
                '{"jsonrpc":"2.0","method":"call","id":3}',
            ],
            scope_upgrader=lambda _s: {"Authorization": "Bearer broader"},
        )
        reqs = httpx_mock.get_requests()
        # The 403's "bad-rotated" was NOT adopted — request 3 still sends "good".
        assert reqs[2].headers.get("mcp-session-id") == "good"

    def test_post_refresh_retry_terminal_error_session_id_not_adopted(self, httpx_mock):
        """: the INLINE 401-retry session-id adoption must be gated
        too — a refreshed retry that returns a TERMINAL error (500) while echoing
        a rotated mcp-session-id must NOT carry that rejected id into the next
        stdin line (the downstream gate declines it, but the inline write must
        not poison session_id first)."""
        # Line 1: init -> 200, session "s1".
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "s1"},
        )
        # Line 2: call -> 401 (no session header → pre-recovery keeps "s1").
        httpx_mock.add_response(
            status_code=401, text="", headers={"content-type": "application/json"}
        )
        # 401 refresh retry -> 500 echoing a ROTATED id that must be ignored.
        httpx_mock.add_response(
            status_code=500,
            text="",
            headers={
                "content-type": "application/json",
                "mcp-session-id": "bad-rotated",
            },
        )
        # Line 3: call -> 200.
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":3}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
                '{"jsonrpc":"2.0","method":"call","id":3}',
            ],
            token_refresher=lambda: {"Authorization": "Bearer new"},
        )
        reqs = httpx_mock.get_requests()
        # Line 3's request (index 3) still carries "s1", not the 500's "bad-rotated".
        assert reqs[3].headers.get("mcp-session-id") == "s1"

    def test_inline_401_retry_unparseable_403_session_id_not_adopted(self, httpx_mock):
        """: the INLINE 401-retry re-adoption must require a PARSEABLE
        insufficient_scope challenge on a 403, mirroring the top-level
        feeds_recovery gate. A 401 retry that returns a 403 with a generic
        (unparseable) WWW-Authenticate AND a rotated session id, while a
        scope_upgrader is configured, must NOT adopt the rotated id — the step-up
        branch declines to fire (no parseable scope), so the id is never consumed
        and would poison the next stdin line."""
        # Line 1: init -> 200, session "s1".
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "s1"},
        )
        # Line 2: call -> 401 (triggers refresh).
        httpx_mock.add_response(
            status_code=401, text="", headers={"content-type": "application/json"}
        )
        # 401 refresh retry -> 403 with a NON-insufficient_scope challenge
        # (unparseable) AND a rotated id. Step-up will NOT fire; the id must not
        # be adopted.
        httpx_mock.add_response(
            status_code=403,
            text="",
            headers={
                "content-type": "application/json",
                "www-authenticate": 'Bearer realm="x"',
                "mcp-session-id": "bad-rotated",
            },
        )
        # Line 3: call -> 200.
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":3}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
                '{"jsonrpc":"2.0","method":"call","id":3}',
            ],
            token_refresher=lambda: {"Authorization": "Bearer new"},
            scope_upgrader=lambda _s: {"Authorization": "Bearer broader"},
        )
        reqs = httpx_mock.get_requests()
        # Line 3's request still carries "s1", not the 403's "bad-rotated".
        assert reqs[3].headers.get("mcp-session-id") == "s1"

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
        """: a 401-refresh retry exhausted by a TRANSPORT error must
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
        """: a 403 step-up retry exhausted by a TRANSPORT error
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

    def test_reinitialize_strips_pinned_protocol_version_from_initialize(
        self, httpx_mock
    ):
        """: an operator-pinned `-H MCP-Protocol-Version` must NOT ride
        the re-initialize's initialize POST (initialize IS the renegotiation),
        mirroring the dispatch path's strip. The post-initialize
        notifications/initialized DOES carry the freshly negotiated version."""
        # initialize -> 200, negotiates a NEW version and assigns a session.
        httpx_mock.add_response(
            text=('{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18"}}'),
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-new",
            },
        )
        # notifications/initialized -> 202.
        httpx_mock.add_response(status_code=202, text="")

        with httpx.Client() as client:
            new_session_id, negotiated = _reinitialize(
                client,
                "https://example.com/mcp",
                {
                    "Content-Type": "application/json",
                    "MCP-Protocol-Version": "2024-11-05",
                },
                "2024-11-05",
            )

        assert new_session_id == "sess-new"
        assert negotiated == "2025-06-18"
        reqs = httpx_mock.get_requests()
        # The initialize POST (req 0) dropped the pinned header...
        assert "mcp-protocol-version" not in {k.lower() for k in reqs[0].headers.keys()}
        # ...while notifications/initialized (req 1) carries the negotiated value.
        assert reqs[1].headers.get("mcp-protocol-version") == "2025-06-18"

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

    def test_reinitialize_notifications_initialized_transport_error_returns_error(
        self, httpx_mock
    ):
        """: if the initialize succeeds but the
        notifications/initialized POST RAISES a transport error (not just a
        non-200), _reinitialize's except httpx.HTTPError branch must still treat
        the re-init as failed and surface 'session lost' — exercising the
        raise-path, distinct from the non-200-status path above."""
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
        # notifications/initialized POST raises a transport error.
        httpx_mock.add_exception(httpx.ConnectError("connection reset"))

        output = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
            ],
        )
        lines = [x for x in output.strip().splitlines() if x]
        err = json.loads(lines[-1])
        assert err["id"] == 2
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
            output = self._run_with_stdin(
                httpx_mock, ['{"jsonrpc":"2.0","method":"init","id":5}']
            )
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
        """HIGH end-to-end: a request whose body fails to decode
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
        """: a notification whose POST 404s (with a prior session) and
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
        """: a notification whose POST 403s insufficient_scope and
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
        """: a 401 whose refreshed retry returns 403 + a ROTATED
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

    def test_successful_403_stepup_adopts_rotated_session_id(self, httpx_mock):
        """: a 403 step-up retry that SUCCEEDS (200) while rotating the
        mcp-session-id must adopt that rotated id for the next stdin line —
        symmetric with the 401 branch. Pins the post-step-up adoption at
        relay.py ~1904 (`if result.session_id and result.status_code < 400`),
        which the existing 403 tests leave uncovered (their retry 200 carries no
        rotated id)."""
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
        # 3: step-up retry -> 200 AND rotates the session id to sess-rotated
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"ok":true},"id":2}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-rotated",
            },
        )
        # 4: a later call -> 200 (must carry the rotated id)
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":3}',
            headers={"content-type": "application/json"},
        )

        self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"init","id":1}',
                '{"jsonrpc":"2.0","method":"call","id":2}',
                '{"jsonrpc":"2.0","method":"call","id":3}',
            ],
            scope_upgrader=lambda _s: {"Authorization": "Bearer broader"},
        )
        reqs = httpx_mock.get_requests()
        # Line 3's request (index 3) carries the id rotated on the step-up 200.
        assert reqs[3].headers.get("mcp-session-id") == "sess-rotated"

    def test_chained_403_stepup_then_404_reinitializes_and_replays(self, httpx_mock):
        """: a 403 whose step-up retry returns 404 must cascade into
        the 404 reinitialize branch — initialize a fresh session, then replay the
        original call with it. Proves the 403 step-up retry feeds the 404 reinit
        (the recovery branches are sequential ifs, not elif)."""
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
        # 3: step-up retry -> 404 (session expired during the step-up window)
        httpx_mock.add_response(
            status_code=404, text="", headers={"content-type": "application/json"}
        )
        # 4: _reinitialize's initialize -> 200, sess-new
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":0}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-new"},
        )
        # 5: _reinitialize's notifications/initialized -> 202
        httpx_mock.add_response(status_code=202, text="")
        # 6: replayed call with sess-new -> 200
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
            token_refresher=lambda: {"Authorization": "Bearer new"},
            scope_upgrader=lambda _s: {"Authorization": "Bearer broader"},
        )
        lines = [x for x in output.strip().splitlines() if x]
        # The internal reinit handshake must not leak; only init + final call.
        assert len(lines) == 2
        assert json.loads(lines[1])["result"] == {"ok": True}

        reqs = httpx_mock.get_requests()
        assert len(reqs) == 6
        # req 4 is the reinitialize's initialize (no session, initialize body)
        assert json.loads(reqs[3].content)["method"] == "initialize"
        # req 6 is the replayed call carrying the freshly-initialized session id
        assert reqs[5].headers.get("mcp-session-id") == "sess-new"
        assert json.loads(reqs[5].content)["method"] == "call"

    def test_full_401_403_404_triple_recovery_cascade(self, httpx_mock):
        """: drive the documented 4-dispatch worst case in ONE stdin
        line — initial -> 401-refresh -> 403-step-up -> 404-reinit -> replay — so
        the three sequential recovery branches (and the session-id hand-off
        between them) are pinned end-to-end. A regression that cleared session_id
        after the step-up would silently break the `and session_id`-gated 404
        self-heal, which the 2-branch tests cannot catch."""
        # 1: init -> sess-1
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        # 2: call -> 401 (triggers refresh)
        httpx_mock.add_response(
            status_code=401, text="", headers={"content-type": "application/json"}
        )
        # 3: refreshed retry -> 403 insufficient_scope (triggers step-up)
        httpx_mock.add_response(
            status_code=403,
            text="",
            headers={
                "content-type": "application/json",
                "www-authenticate": 'Bearer error="insufficient_scope", scope="extra"',
            },
        )
        # 4: step-up retry -> 404 (session expired during the recovery window)
        httpx_mock.add_response(
            status_code=404, text="", headers={"content-type": "application/json"}
        )
        # 5: _reinitialize's initialize -> 200, sess-new
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05"},"id":0}',
            headers={"content-type": "application/json", "mcp-session-id": "sess-new"},
        )
        # 6: _reinitialize's notifications/initialized -> 202
        httpx_mock.add_response(status_code=202, text="")
        # 7: replayed call with sess-new -> 200
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
            token_refresher=lambda: {"Authorization": "Bearer refreshed"},
            scope_upgrader=lambda _s: {"Authorization": "Bearer broader"},
        )
        lines = [x for x in output.strip().splitlines() if x]
        # Only init + the final replayed call reach stdout (no error, no leaked
        # reinit handshake).
        assert len(lines) == 2
        assert json.loads(lines[1])["result"] == {"ok": True}

        reqs = httpx_mock.get_requests()
        assert len(reqs) == 7
        # Each retry carried the right credential/session as the cascade advanced.
        assert reqs[2].headers.get("authorization") == "Bearer refreshed"  # 401→retry
        assert reqs[3].headers.get("authorization") == "Bearer broader"  # 403→step-up
        assert json.loads(reqs[4].content)["method"] == "initialize"  # 404→reinit
        assert reqs[6].headers.get("mcp-session-id") == "sess-new"  # replay
        assert json.loads(reqs[6].content)["method"] == "call"

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
        """: a non-compliant 202 to a REQUEST (with id) on Streamable
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
        """: an unexpected non-httpx exception escaping dispatch must
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
        assert any(m.get("id") == 2 and m.get("result", {}).get("ok") for m in msgs), (
            f"loop did not survive to process id 2, got {msgs!r}"
        )

    def test_unexpected_exception_on_notification_stays_silent(
        self, httpx_mock, monkeypatch
    ):
        """: the same guard must NOT synthesize an id:null response
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

    def test_explicit_null_id_request_error_is_emitted_not_suppressed(self, httpx_mock):
        """: a request with an EXPLICIT "id": null is a request, not a
        notification, so an unhandled non-2xx must still synthesize an error
        echoing "id": null — never silently drop it as if it were a notification.
        The contract was asserted only at the helper level (TestErrorResponse),
        never end-to-end through run()'s id extraction from a real stdin line."""
        httpx_mock.add_response(
            status_code=401,
            text="",
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"init","id":null}'],
        )
        line = output.strip()
        assert line, "an explicit-null-id request must get a response, not silence"
        result = json.loads(line)
        # "id": null is echoed (key present, value None), not dropped.
        assert "id" in result and result["id"] is None
        assert result["error"]["message"] == "HTTP 401"

    def test_legacy_response_shaped_stdin_line_is_posted_verbatim(self, httpx_mock):
        """AC 3 pin (#270 Phase 2 PR C): a RESPONSE-shaped stdin line (an
        id plus a result, no method — what a client sends when answering a
        server-initiated sampling/elicitation/roots request) is POSTed
        upstream verbatim on the legacy era, exactly as it always has been.

        Pinned BEFORE PR C touches the stdin loop, because the modern era
        gains a branch that intercepts precisely these lines (the MRTR
        bridge routes them into its transaction state instead of the
        wire). The legacy path must keep the pre-#270 behavior BYTE for
        byte, warts included: the POST body is the untouched line, no
        Mcp-Method header is derived (a response has no method), and the
        server's spec-correct 202 Accepted for a client response
        (Streamable HTTP "Sending Messages" rule 4) is turned into a
        synthesized JSON-RPC error, because `_extract_id_and_presence`
        sees the id and classifies the line as a REQUEST that was left
        unanswered. That last part is a known wart — pin it, do not fix
        it here: changing it would be a legacy-era behavior change PR C
        has no mandate for."""
        httpx_mock.add_response(status_code=202, text="")
        line = '{"jsonrpc":"2.0","id":7,"result":{"action":"decline"}}'
        output = self._run_with_stdin(httpx_mock, [line])
        requests = httpx_mock.get_requests()
        assert len(requests) == 1
        # Byte-identical body, and no request-metadata headers at all.
        assert requests[0].content.decode() == line
        assert "mcp-method" not in requests[0].headers
        assert "mcp-name" not in requests[0].headers
        # The 202 quirk, pinned verbatim.
        reply = json.loads(output.strip())
        assert reply["id"] == 7
        assert reply["error"]["message"] == "HTTP 202 (no response body for request)"


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
        """: on a cold-start initialize (version not yet negotiated)
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

    def test_tools_call_with_nested_method_initialize_keeps_header(self, httpx_mock):
        """: a tools/call whose nested ``arguments`` contains a
        ``"method":"initialize"`` key must NOT be misread as an initialize
        request — the substring matches the cheap regex, but the header strip is
        gated on a parse-authoritative top-level method check, so the negotiated
        MCP-Protocol-Version is PRESERVED on the tool call (a regression would
        strip it and break the call against a strict 2025-06-18 server)."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"},"id":1}',
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        # The tool call's arguments legitimately carry a "method" key whose value
        # is "initialize" (e.g. an HTTP/API-wrapper tool) — top-level method is
        # tools/call, so the header must survive.
        self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"initialize","id":1}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2,"params":'
                '{"name":"http","arguments":{"method":"initialize","url":"https://x"}}}',
            ]
        )
        reqs = httpx_mock.get_requests()
        # The tools/call is a post-init request → carries the negotiated header.
        assert reqs[1].headers["mcp-protocol-version"] == "2025-06-18"

    def test_tools_call_with_nested_method_initialize_does_not_capture_version(
        self, httpx_mock
    ):
        """: the CAPTURE counterpart of the strip test above. A
        tools/call whose nested ``arguments`` contains a ``"method":"initialize"``
        key must NOT capture ``result.protocolVersion`` from its tool response —
        capture is now gated on the parse-authoritative check, not the substring
        regex. Otherwise a never-negotiated version would be injected as
        MCP-Protocol-Version on every later request."""
        # The tool response happens to carry a string protocolVersion in its
        # result (e.g. a tool that proxies an MCP server / returns version info).
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{"protocolVersion":"9999-spoof"},"id":1}',
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )
        # No real initialize precedes this; both lines are top-level tools/call.
        self._run_with_stdin(
            [
                '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":'
                '{"name":"http","arguments":{"method":"initialize"}}}',
                '{"jsonrpc":"2.0","method":"tools/call","id":2}',
            ]
        )
        reqs = httpx_mock.get_requests()
        # The spurious protocolVersion was NOT captured → no injected header.
        assert "mcp-protocol-version" not in reqs[1].headers

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


class TestParseAuthParams:
    """Quote-aware WWW-Authenticate auth-param tokenizer."""

    def test_scheme_stripped_and_names_lowercased(self):
        header = 'Bearer Realm="mcp", Scope="a b"'
        assert _parse_auth_params(header) == {"realm": "mcp", "scope": "a b"}

    def test_unquoted_values(self):
        header = "Bearer error=insufficient_scope, scope=mcp:read"
        assert _parse_auth_params(header) == {
            "error": "insufficient_scope",
            "scope": "mcp:read",
        }

    def test_embedded_equals_in_quoted_value_kept(self):
        header = 'Bearer error_description="grant scope=mcp:write"'
        assert _parse_auth_params(header) == {
            "error_description": "grant scope=mcp:write"
        }

    def test_bare_scheme_only(self):
        assert _parse_auth_params("Bearer") == {}

    def test_empty_and_none(self):
        assert _parse_auth_params("") == {}
        assert _parse_auth_params(None) == {}

    def test_no_scheme_prefix(self):
        """A header that is already bare params still parses."""
        assert _parse_auth_params('realm="mcp"') == {"realm": "mcp"}


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

    def test_decoy_param_ending_in_scope_ignored(self):
        """A param name merely ending in "scope" must not shadow the real one.

        Defect class of modelcontextprotocol/python-sdk#3009: a name-suffix
        decoy (error_scope=, and the wider-tchar x.scope=) is a distinct
        auth-param, not the scope parameter.
        """
        for decoy in ("error_scope", "x.scope", "x-scope", "acme+scope"):
            header = (
                f'Bearer error="insufficient_scope", {decoy}="decoy", '
                'scope="mcp:read hr:read"'
            )
            assert _parse_www_authenticate_scope(header) == "mcp:read hr:read"

    def test_decoy_param_only_is_not_scope(self):
        """error_scope alone must not be mistaken for a scope parameter."""
        header = 'Bearer error="insufficient_scope", error_scope="decoy"'
        assert _parse_www_authenticate_scope(header) is None

    def test_unquoted_decoy_param_before_real_scope(self):
        """Unquoted form: error_scope=decoy must not shadow scope=mcp:read."""
        header = "Bearer error=insufficient_scope, error_scope=decoy, scope=mcp:read"
        assert _parse_www_authenticate_scope(header) == "mcp:read"

    def test_decoy_error_param_not_triggered(self):
        """my_error="insufficient_scope" is not the error parameter."""
        header = 'Bearer my_error="insufficient_scope", scope="mcp:read"'
        assert _parse_www_authenticate_scope(header) is None

    def test_error_value_prefix_not_matched(self):
        """error="insufficient_scope_extended" is a different error code."""
        header = 'Bearer error="insufficient_scope_extended", scope="mcp:read"'
        assert _parse_www_authenticate_scope(header) is None

    def test_scope_inside_other_param_value_ignored(self):
        """A scope= substring inside another param's quoted value is not a param.

        error_description free text often contains prose like "grant scope=…";
        that must not be extracted as the required scope.
        """
        header = (
            'Bearer error="insufficient_scope", '
            'error_description="ask admin to grant scope=mcp:write"'
        )
        assert _parse_www_authenticate_scope(header) is None

    def test_case_insensitive_param_names(self):
        """Auth-param names are case-insensitive (RFC 9110 §11.2)."""
        header = 'Bearer Error="insufficient_scope", Scope="mcp:read"'
        assert _parse_www_authenticate_scope(header) == "mcp:read"


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
                    'Bearer error="insufficient_scope", scope="mcp:read hr:read"'
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

    def test_rewrites_null_arguments_with_whitespace_around_colon(self):
        """: the cheap pre-gate regex tolerates whitespace around the
        `arguments` colon, but every other test uses the compact form — pin the
        whitespace variant so a server emitting `"arguments" : null` is rewritten."""
        line = (
            '{"jsonrpc":"2.0","method":"tools/call","id":1,'
            '"params":{"name":"t","arguments" : null}}'
        )
        out = json.loads(_normalize_null_arguments(line))
        assert out["params"]["arguments"] == {}

    def test_absent_arguments_stays_absent(self):
        """Missing arguments must NOT be synthesized to {}."""
        line = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t"}}'
        out = json.loads(_normalize_null_arguments(line))
        assert "arguments" not in out["params"]

    def test_rewrites_null_arguments_with_id_zero(self):
        """: the id-0 falsy-id regression class is pinned at every
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
        """: the regex matches an "arguments":null nested elsewhere,
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
            run(
                "https://example.com/mcp",
                {"Content-Type": "application/json"},
                **kwargs,
            )

    def test_default_rewrites_on_wire(self, httpx_mock):
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json"},
        )
        self._run(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t","arguments":null}}'
            ],
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
            [
                '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"t","arguments":null}}'
            ],
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

    def test_page1_nonlist_result_key_coerced_to_empty(self, httpx_mock):
        """: a page-1 result that has a nextCursor but whose
        result_key (here 'tools') is MISSING/not-a-list (a server bug) must be
        coerced to [] so the merge starts from an empty list, then page 2's items
        append normally. Exercises the defensive coercion branch in
        _paginate_and_stream that no test covered."""
        # Page 1: nextCursor present but no "tools" key.
        page1 = {"jsonrpc": "2.0", "id": 1, "result": {"nextCursor": "p2"}}
        # Page 2: a normal terminal page.
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}]},
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
        # Page 1 contributed an empty list (coerced); page 2 appended its item.
        assert merged["result"]["tools"] == [{"name": "a"}]

    def test_cache_scope_merge_is_most_restrictive_not_last_write(self, httpx_mock):
        """: page 1 says cacheScope="private", page 2 says "public" — the
        merged result must still report "private" (most restrictive), not
        "public" (last-write-wins), or a shared intermediary could legally cache
        and leak page 1's private-scoped items."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{"name": "a"}],
                "cacheScope": "private",
                "nextCursor": "p2",
            },
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "cacheScope": "public"},
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
        merged = json.loads(output.strip())["result"]
        assert merged["cacheScope"] == "private"
        assert merged["tools"] == [{"name": "a"}, {"name": "b"}]

    def test_cache_scope_private_survives_page_omitting_the_field(self, httpx_mock):
        """: page 1 says cacheScope="private"; page 2 OMITS cacheScope
        entirely (a page that just doesn't repeat it, not a page asserting
        "public"). The merge must not reset to unscoped/public — the private
        constraint established by page 1 must survive a later page's silence."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{"name": "a"}],
                "cacheScope": "private",
                "nextCursor": "p2",
            },
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}]},  # no cacheScope key at all
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
        merged = json.loads(output.strip())["result"]
        assert merged["cacheScope"] == "private"

    def test_ttl_ms_merge_is_minimum_not_last_write(self, httpx_mock):
        """: page 1 ttlMs=5000, page 2 ttlMs=60000 — the merged list's
        true freshness bound is its LEAST fresh member, so the merge must keep
        the MINIMUM (5000). Last-write-wins would instead report 60000 (page
        2's larger, staler-tolerant value), overstating the combined list's
        freshness. Page 1's value is deliberately the smaller one so the two
        merge strategies disagree and this test actually discriminates them."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "ttlMs": 5000, "nextCursor": "p2"},
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "ttlMs": 60000},
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
        merged = json.loads(output.strip())["result"]
        assert merged["ttlMs"] == 5000

    def test_cache_scope_public_does_not_survive_a_page_omitting_it(self, httpx_mock):
        """#350 review round 3: page 1 says cacheScope="public"; page 2
        OMITS the field entirely (not "private" — just silent). The merged
        result must NOT report "public": an omitted cacheScope on ANY page
        is not permission to treat the WHOLE merged list as safe for shared
        caching (spec rev 2026-07-28, "Caching": ttlMs/cacheScope are
        REQUIRED on every resultType:"complete" page, and "Servers MUST
        apply the same cacheScope to all response pages" — an omission is
        itself non-compliant and must degrade to the conservative value,
        not silently inherit page 1's laxer claim). This is the opposite
        pairing from test_cache_scope_private_survives_page_omitting_the_field
        above (where page 1 was ALREADY the most restrictive value, so that
        test could not have caught this bug)."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{"name": "a"}],
                "cacheScope": "public",
                "nextCursor": "p2",
            },
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}]},  # no cacheScope key at all
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
        merged = json.loads(output.strip())["result"]
        assert merged["cacheScope"] == "private"

    def test_cache_scope_public_on_a_later_page_does_not_backfill_page1s_omission(
        self, httpx_mock
    ):
        """#350 review round 3, reverse ordering: page 1 OMITS cacheScope
        entirely; page 2 supplies "public". Page 1's silence must not be
        treated as an implicit blank check that a later page's "public" can
        fill in — the merge must still degrade to "private", exactly as
        when the omission is on the LATER page. This exercises the page-1
        bookkeeping specifically: a fix that only tracks omissions
        starting from page 2 onward would pass the other ordering but miss
        this one."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "nextCursor": "p2"},
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "cacheScope": "public"},
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
        merged = json.loads(output.strip())["result"]
        assert merged["cacheScope"] == "private"

    def test_ttl_ms_does_not_survive_a_page_omitting_it(self, httpx_mock):
        """#350 review round 3: the analogous ``ttlMs`` case — page 1
        supplies ttlMs=5000, page 2 omits it entirely. Per spec ("Caching"):
        "If ttlMs is absent, clients SHOULD assume a default of 0
        (immediately stale)". The merged freshness bound must reflect that
        absence (0), not silently inherit page 1's 5000 just because page 2
        never contradicted it with a larger/smaller number."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "ttlMs": 5000, "nextCursor": "p2"},
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}]},  # no ttlMs key at all
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
        merged = json.loads(output.strip())["result"]
        assert merged["ttlMs"] == 0

    def test_cacheable_fields_absent_on_every_page_are_not_fabricated(self, httpx_mock):
        """#350 review round 3, guard against a naive fix: a server that
        never sends ttlMs/cacheScope at all (legacy, pre-2026-07-28 shaped
        responses relayed on ANY --protocol-era) must not suddenly gain
        invented cache metadata on its merged, paginated result. The
        conservative-default behavior above applies only when a field is
        present on AT LEAST ONE page but missing on another — never when it
        is absent everywhere, which must continue to leave the merged
        result with neither key at all (today's pre-existing behavior for
        cache-unaware servers)."""
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
        merged = json.loads(output.strip())["result"]
        assert "cacheScope" not in merged
        assert "ttlMs" not in merged

    def test_invalid_cache_scope_on_a_later_page_degrades_like_omission(
        self, httpx_mock
    ):
        """#350 review round 11: page 1 says cacheScope="public"; page 2
        supplies an INVALID scope ("internal" — not a spec value). The old
        behavior "ignored" the invalid value inside _merge_cacheable_field,
        which left page 1's "public" standing in the merged result — but an
        unusable value grants no more caching permission than an absent
        one, so it must degrade through the same conservative finalization
        as an omission: merged cacheScope "private"."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{"name": "a"}],
                "cacheScope": "public",
                "nextCursor": "p2",
            },
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "cacheScope": "internal"},
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
        merged = json.loads(output.strip())["result"]
        assert merged["cacheScope"] == "private"

    def test_invalid_cache_scope_on_page1_does_not_ride_through_verbatim(
        self, httpx_mock
    ):
        """#350 review round 11, the page-1 bypass half: page 1's values
        enter merged_result via a plain dict-copy WITHOUT passing
        _merge_cacheable_field's type guards, so an invalid first-page
        scope ("internal") previously rode through to the merged output
        verbatim — with a later page's valid "public" unable to displace
        it (rank lookup of the garbage value made it unrankable). The
        merged result must degrade to "private", never emit the garbage."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{"name": "a"}],
                "cacheScope": "internal",
                "nextCursor": "p2",
            },
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "cacheScope": "public"},
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
        merged = json.loads(output.strip())["result"]
        assert merged["cacheScope"] == "private"

    def test_invalid_ttl_ms_degrades_like_omission(self, httpx_mock):
        """#350 review round 11, the ttlMs analogue: a non-numeric ttlMs
        ("soon") on page 2 must not leave page 1's 5000 standing as the
        merged freshness bound — same conservative degrade as an absent
        field (0, immediately stale)."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "ttlMs": 5000, "nextCursor": "p2"},
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "ttlMs": "soon"},
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
        merged = json.loads(output.strip())["result"]
        assert merged["ttlMs"] == 0

    def test_nan_ttl_ms_is_invalid_not_a_survivor(self, httpx_mock):
        """#350 review round 11: NaN passes an isinstance(float) check but
        poisons _merge_cacheable_field's min() comparison (NaN < x is
        always False, so NaN silently survives as the merged value — and
        json.dumps would then emit non-standard bare NaN). _is_valid_
        cacheable_value must reject non-finite floats so a NaN page
        degrades the merge to the conservative 0."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "ttlMs": 5000, "nextCursor": "p2"},
        }
        # json.dumps refuses NaN only with allow_nan=False; produce the
        # non-standard literal a non-compliant server would actually send.
        page2_text = (
            '{"jsonrpc": "2.0", "id": 1,'
            ' "result": {"tools": [{"name": "b"}], "ttlMs": NaN}}'
        )
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(page1),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=page2_text,
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())["result"]
        assert merged["ttlMs"] == 0

    def test_negative_ttl_ms_degrades_to_zero_not_merged_minimum(self, httpx_mock):
        """#350 review round 13: 0 is the spec's own ttlMs floor, so a
        negative value has no defined meaning — but the min() merge would
        happily let "ttlMs": -1 BEAT every valid page's value and emit an
        invalid cache policy downstream. It must be treated like any other
        invalid value: conservative degrade to 0."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "ttlMs": 5000, "nextCursor": "p2"},
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "ttlMs": -1},
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
        merged = json.loads(output.strip())["result"]
        assert merged["ttlMs"] == 0

    def test_huge_integer_ttl_ms_does_not_crash_validation(self, httpx_mock):
        """#350 review round 15: ``math.isfinite`` converts an int argument
        to float first, and an arbitrarily large JSON integer (10**400
        parses fine as a Python int) makes that conversion raise
        OverflowError — a crash on untrusted response data. Python ints
        are always finite, so a huge int is VALID (and simply loses the
        min() merge to any smaller page); the request must succeed."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "ttlMs": 5000, "nextCursor": "p2"},
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "ttlMs": 10**400},
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
        merged = json.loads(output.strip())["result"]
        assert merged["tools"] == [{"name": "a"}, {"name": "b"}]
        assert merged["ttlMs"] == 5000

    def test_unhashable_cache_scope_degrades_instead_of_crashing(self, httpx_mock):
        """#350 review round 12: ``"cacheScope": []`` is valid JSON a
        malformed page can carry, but a JSON array is UNHASHABLE — dict
        membership/.get() on it raises TypeError, which turned the request
        into a failure instead of the conservative degrade the round-11
        bookkeeping promises. Page 2 carrying the garbage exercises both
        _is_valid_cacheable_value's membership test and
        _merge_cacheable_field's rank lookup on the incoming value."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{"name": "a"}],
                "cacheScope": "public",
                "nextCursor": "p2",
            },
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "cacheScope": []},
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
        merged = json.loads(output.strip())["result"]
        assert merged["tools"] == [{"name": "a"}, {"name": "b"}]
        assert merged["cacheScope"] == "private"

    def test_unhashable_cache_scope_on_page1_then_valid_page2_no_crash(
        self, httpx_mock
    ):
        """#350 review round 12, the existing-rank half: page 1's
        ``"cacheScope": {}`` enters merged_result via the unvetted
        dict-copy, so page 2's valid "public" hits
        _merge_cacheable_field's EXISTING-value rank lookup with the
        garbage — `.get(unhashable)` raised TypeError before the
        isinstance gate on `existing` was added. Must degrade to
        "private" (page 1's value was invalid), never crash."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{"name": "a"}],
                "cacheScope": {},
                "nextCursor": "p2",
            },
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "b"}], "cacheScope": "public"},
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
        merged = json.loads(output.strip())["result"]
        assert merged["tools"] == [{"name": "a"}, {"name": "b"}]
        assert merged["cacheScope"] == "private"

    def test_paginated_notification_no_id_produces_no_response(self, httpx_mock):
        """: a list method sent as a NOTIFICATION (no id key) must get
        NO response — the merged-response emit is gated on has_id, mirroring every
        other synthesized-write path. Otherwise a spurious {"id":null,...} frame
        would be delivered for a notification (a JSON-RPC violation)."""
        # Single page (no nextCursor) so pagination reaches the success emit.
        page = {"jsonrpc": "2.0", "result": {"tools": [{"name": "a"}]}}
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(page),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "method": "tools/list"})],  # no id key
        )
        # The notification produced no stdout line at all.
        assert output.strip() == ""
        # But the upstream POST still happened (pagination ran, just stayed silent).
        assert len(httpx_mock.get_requests()) == 1

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
        # page 3 still advertised nextCursor 'p4', so the cap path
        # MUST re-expose it on the merged result for the client to resume past
        # the cap — pinning resumability like the sibling truncation tests.
        assert merged["result"]["nextCursor"] == "p4"

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
        # a truncated list keeps the pending cursor so the client
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
        # Truncated → pending cursor preserved for resumption.
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
        # Truncated → pending cursor preserved for resumption.
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

    def test_page1_404_reinitializes_then_replays_through_pagination(self, httpx_mock):
        """: a page-1 404 on a paginated method must cascade through the
        run() 404 branch — reinitialize, then RE-ENTER _paginate_and_stream with
        the fresh session and replay the full paginated fetch. Pins the
        pagination-path re-entry (recovered session adopted, no double-emit) the
        non-paginated 404 tests do not exercise."""
        # Line 1: tools/list establishes sess-old over two pages.
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"tools": [{"name": "a"}], "nextCursor": "p2"},
                }
            ),
            headers={"content-type": "application/json", "mcp-session-id": "sess-old"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(
                {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "b"}]}}
            ),
            headers={"content-type": "application/json"},
        )
        # Line 2: tools/list page-1 -> 404 (session expired).
        httpx_mock.add_response(url=self.URL, status_code=404, text="")
        # Reinitialize: initialize -> 200 sess-new, then notifications/initialized.
        httpx_mock.add_response(
            text=('{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2024-11-05"}}'),
            headers={"content-type": "application/json", "mcp-session-id": "sess-new"},
        )
        httpx_mock.add_response(status_code=202, text="")
        # Replayed paginated tools/list over two pages with sess-new.
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {"tools": [{"name": "c"}], "nextCursor": "q2"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(
                {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "d"}]}}
            ),
            headers={"content-type": "application/json"},
        )

        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            ],
        )
        lines = [json.loads(x) for x in output.strip().splitlines() if x]
        # Exactly two merged responses (line 1: a,b; line 2: c,d), no double-emit.
        assert len(lines) == 2
        assert [t["name"] for t in lines[0]["result"]["tools"]] == ["a", "b"]
        assert [t["name"] for t in lines[1]["result"]["tools"]] == ["c", "d"]
        assert "nextCursor" not in lines[1]["result"]
        reqs = httpx_mock.get_requests()
        # req[3] is the reinitialize's initialize; req[5] is the replay page-1,
        # which must carry the freshly re-established session.
        assert json.loads(reqs[3].content)["method"] == "initialize"
        assert reqs[5].headers.get("mcp-session-id") == "sess-new"
        assert json.loads(reqs[5].content)["method"] == "tools/list"

    def test_page2_401_does_not_trigger_recovery_returns_partial(self, httpx_mock):
        """#L: a 401 on page>=2 must NOT reach run()'s token-refresh
        recovery — _paginate_and_stream flushes the accumulated partial (status
        coerced to 200) and re-exposes the cursor so the client can resume. The
        refresher is never called and exactly one response is emitted. Pins the
        page-1-only-recovery asymmetry."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "nextCursor": "p2"},
        }
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(page1),
            headers={"content-type": "application/json"},
        )
        # Page 2 -> 401 (would trigger refresh on page 1, but not on page>=2).
        httpx_mock.add_response(
            url=self.URL,
            status_code=401,
            text="",
            headers={"content-type": "application/json"},
        )

        called = {"refresh": False}

        def spy_refresher():
            called["refresh"] = True
            return {"Content-Type": "application/json", "Authorization": "Bearer new"}

        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
            token_refresher=spy_refresher,
        )
        lines = [x for x in output.strip().splitlines() if x]
        assert len(lines) == 1  # one merged response, no duplicate error
        merged = json.loads(lines[0])
        assert merged["result"]["tools"] == [{"name": "a"}]  # page-1 partial
        assert merged["result"]["nextCursor"] == "p2"  # resumable tail re-exposed
        assert called["refresh"] is False  # page-2 401 stayed inside pagination

    def test_pagination_adopts_last_page_session_id(self, httpx_mock):
        """: when the server rotates Mcp-Session-Id across pages,
        the LAST page's session is adopted (last-write-wins), so the NEXT stdin
        request carries it — preserving session continuity for the 404
        self-heal."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "nextCursor": "p2"},
        }
        page2 = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "b"}]}}
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(page1),
            headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(page2),
            headers={"content-type": "application/json", "mcp-session-id": "sess-2"},
        )
        # A later call on the next stdin line must carry sess-2 (last page's).
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","result":{},"id":2}',
            headers={"content-type": "application/json"},
        )

        self._run_with_stdin(
            httpx_mock,
            [
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call"}),
            ],
        )
        reqs = httpx_mock.get_requests()
        # reqs[2] is the line-2 tools/call; it carries the LAST page's session.
        assert reqs[2].headers.get("mcp-session-id") == "sess-2"

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

    def test_empty_string_next_cursor_is_terminal(self, httpx_mock):
        """: an empty-string nextCursor is treated as terminal (like
        null / absent) — an empty cursor cannot be round-tripped, so it is a
        degenerate end, not another page. Exactly one upstream POST, and the
        merged result carries no nextCursor. Pins the documented `if not
        next_cursor` contract distinctly from the null/absent case."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "nextCursor": ""},
        }
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(page1),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        assert merged["result"]["tools"] == [{"name": "a"}]
        assert "nextCursor" not in merged["result"]  # empty cursor not re-exposed
        assert len(httpx_mock.get_requests()) == 1  # no second-page fetch

    def test_non_string_next_cursor_is_threaded_without_crashing(self, httpx_mock):
        """: a non-compliant server may return a non-string (e.g.
        numeric) nextCursor. It is threaded back into params.cursor verbatim
        (json-serializable, so json.dumps cannot raise) and the merge stays
        well-formed — opaque-token handling, zero blast radius."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "nextCursor": 42},  # numeric
        }
        page2 = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "b"}]}}
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
        # No crash; both pages merged; page-2 POST carried cursor=42.
        assert [t["name"] for t in merged["result"]["tools"]] == ["a", "b"]
        assert "nextCursor" not in merged["result"]
        assert (
            json.loads(httpx_mock.get_requests()[1].content)["params"]["cursor"] == 42
        )

    def test_page2_nonlist_result_key_keeps_page1_and_merges_late_field(
        self, httpx_mock
    ):
        """: a page-2 dict whose result_key is present but NOT a list
        (e.g. tools:"oops") must not crash or discard page-1 items — the
        non-list value is skipped (isinstance(items, list) is False) while the
        late top-level field still merges. Complements the page-1 non-list and
        page-2 non-dict cases."""
        page1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "a"}], "nextCursor": "p2"},
        }
        page2 = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": "not-a-list", "_meta": {"x": 1}},
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
        # Page-1 items survive; page-2's non-list value is ignored, late merges.
        assert [t["name"] for t in merged["result"]["tools"]] == ["a"]
        assert merged["result"]["_meta"] == {"x": 1}
        assert "nextCursor" not in merged["result"]

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

    def test_page_sse_forwards_interleaved_notification(self, httpx_mock):
        """: a server may interleave a notification on the POST's SSE
        stream BEFORE the list result. _post_parsed must FORWARD it to stdout
        (like the streaming path _post_and_stream) AND still return the real
        response — not mistake the notification for the page result, nor drop it
        only on the paginated methods."""
        notif = '{"jsonrpc":"2.0","method":"notifications/message","params":{}}'
        result = '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}}'
        body = f"event: message\ndata: {notif}\n\nevent: message\ndata: {result}\n\n"
        httpx_mock.add_response(
            url=self.URL,
            text=body,
            headers={"content-type": "text/event-stream"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        lines = [json.loads(x) for x in output.strip().splitlines() if x]
        # The interleaved notification was DELIVERED (not dropped, not mistaken
        # for the result).
        assert any(d.get("method") == "notifications/message" for d in lines)
        # The real list result is still parsed correctly.
        merged = next(d for d in lines if "result" in d)
        assert [t["name"] for t in merged["result"]["tools"]] == ["a"]

    def test_page_sse_skips_non_message_event(self, httpx_mock):
        """: a non-`message` SSE event (e.g. event: ping) on the
        paginated POST stream is skipped and the following event: message result
        is still parsed — pins the buffered-path non-message skip branch (the
        streaming path covers the equivalent case, the buffered path did not)."""
        result = '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}}'
        body = f"event: ping\ndata: {{}}\n\nevent: message\ndata: {result}\n\n"
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

    def test_page1_empty_body_falls_back_to_streamed_post(self, httpx_mock):
        """: a page-1 200 with an EMPTY body yields (None, 200), which
        must trigger the plain-streamed-POST fallback (re-POST) so the client
        still gets a response — not a silent empty emit. Pins the buffered-path
        empty-body branch."""
        # Page 1: empty 200 body -> (None, 200) -> fallback re-POST.
        httpx_mock.add_response(
            url=self.URL, text="", headers={"content-type": "application/json"}
        )
        # The fallback re-POST returns a normal result.
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}}',
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
        )
        merged = json.loads(output.strip())
        assert merged["result"]["tools"] == [{"name": "a"}]
        assert len(httpx_mock.get_requests()) == 2  # original empty + fallback


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

    def test_sse_skips_leading_notification_and_captures_result(
        self, httpx_mock, capsys
    ):
        """: a compliant server MAY interleave a notification on the
        POST's SSE stream BEFORE the initialize result. --check must keep reading
        until a message carries result/error, not break on the first message —
        otherwise it mis-reports a valid server as 'could not parse initialize
        result' and loses the server/protocol/capabilities lines."""
        body = (
            'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n'
            'data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05",'
            '"serverInfo":{"name":"demo","version":"1"}}}\n\n'
        )
        httpx_mock.add_response(
            text=body, headers={"content-type": "text/event-stream"}
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True
        # The REAL initialize result was captured (not the leading notification).
        assert "server=demo" in capsys.readouterr().err

    def test_non_200_returns_false(self, httpx_mock):
        httpx_mock.add_response(status_code=500, text="oops")
        assert check_connection(self.URL, dict(self.HEADERS)) is False

    def test_400_falls_back_to_discover_and_succeeds(self, httpx_mock, capsys):
        """: a spec rev 2026-07-28 server that dropped the legacy
        initialize handshake answers it with 400. --check must retry with
        server/discover before reporting the connection down, and the discover
        DiscoverResult's serverInfo (nested at
        _meta["io.modelcontextprotocol/serverInfo"]) must be logged."""
        httpx_mock.add_response(status_code=400, text="")
        discover_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "resultType": "discover",
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}},
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {
                            "name": "modern-server",
                            "version": "9.9",
                        }
                    },
                },
            }
        )
        httpx_mock.add_response(
            text=discover_body, headers={"content-type": "application/json"}
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True
        err = capsys.readouterr().err
        assert "server=modern-server" in err
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        assert json.loads(requests[0].content)["method"] == "initialize"
        assert json.loads(requests[1].content)["method"] == "server/discover"

    def test_discover_retry_matches_probe_protocol_era_request_shape(self, httpx_mock):
        """#350 review finding 1: the discover retry used to POST with the
        operator's raw ``headers`` unmodified -- no Mcp-Method, no
        MCP-Protocol-Version override, no params._meta -- unlike
        _probe_protocol_era's probe. Both REQUIRED headers (Streamable HTTP,
        "Standard Request Headers": Mcp-Method is "Required For: All
        requests") must be present and params._meta must carry a
        protocolVersion matching the header, exactly like the startup
        probe."""
        httpx_mock.add_response(status_code=400, text="")
        httpx_mock.add_response(
            text=json.dumps({"jsonrpc": "2.0", "id": 2, "result": {}}),
            headers={"content-type": "application/json"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True
        discover_req = httpx_mock.get_requests()[1]
        assert discover_req.headers["mcp-method"] == "server/discover"
        assert "mcp-protocol-version" in discover_req.headers
        meta = json.loads(discover_req.content)["params"]["_meta"]
        assert (
            meta["io.modelcontextprotocol/protocolVersion"]
            == (discover_req.headers["mcp-protocol-version"])
        )
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {}

    def test_discover_retry_strips_pinned_mcp_name_and_session_id(self, httpx_mock):
        """#350 review rounds 2/3: one fix (``_build_discover_probe_request``),
        two consumers — this check_connection retry and _probe_protocol_era's
        startup probe both build their request through it, so pin both.
        An operator-pinned ``-H 'Mcp-Name: ...'`` / ``-H 'Mcp-Session-Id:
        ...'`` must not survive onto the ``server/discover`` retry: the
        method has no ``name`` parameter at all, and a pre-negotiation
        probe must never carry a session id."""
        httpx_mock.add_response(status_code=400, text="")
        httpx_mock.add_response(
            text=json.dumps({"jsonrpc": "2.0", "id": 2, "result": {}}),
            headers={"content-type": "application/json"},
        )
        pinned_headers = dict(self.HEADERS)
        pinned_headers["Mcp-Name"] = "operator-pinned"
        pinned_headers["Mcp-Session-Id"] = "old-session"
        assert check_connection(self.URL, pinned_headers) is True
        discover_req = httpx_mock.get_requests()[1]
        lowered = {k.lower() for k in discover_req.headers}
        assert "mcp-name" not in lowered
        assert "mcp-session-id" not in lowered

    def test_404_falls_back_to_discover(self, httpx_mock):
        """: 404 (unrecognized method) is the OTHER fallback trigger
        alongside 400 — a server that fully removed initialize returns 404 for
        an unrecognized method per the transport spec."""
        httpx_mock.add_response(status_code=404, text="")
        httpx_mock.add_response(
            text=json.dumps({"jsonrpc": "2.0", "id": 2, "result": {}}),
            headers={"content-type": "application/json"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True
        assert len(httpx_mock.get_requests()) == 2

    def test_initialize_sse_result_on_open_stream_reports_promptly(
        self, httpx_mock, capsys
    ):
        """#350 review round 5 (finding 5-1, adjacent pre-existing site):
        the final JSON-RPC response only SHOULD terminate an SSE stream
        (Streamable HTTP, "Receiving Messages"), so a server may answer the
        initialize probe as an SSE event and keep the POST stream open. The
        --check must report ✓ as soon as the InitializeResult arrives, not
        buffer toward EOF until the read timeout. Post-yield raise =
        tripwire for buffered reads."""
        init_result = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": "sse-srv", "version": "1"},
                    "capabilities": {"tools": {}},
                },
            }
        )

        def open_stream():
            yield f"event: message\ndata: {init_result}\n\n".encode()
            raise AssertionError(
                "check_connection kept reading past the InitializeResult"
            )

        httpx_mock.add_response(
            stream=IteratorStream(open_stream()),
            headers={"content-type": "text/event-stream"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True
        assert "server=sse-srv" in capsys.readouterr().err

    def test_discover_retry_sse_result_on_open_stream_reports_promptly(
        self, httpx_mock, capsys
    ):
        """#350 review round 5 (finding 5-1): same SSE-keeps-stream-open
        hazard on the NEW server/discover fallback this branch added — the
        retry must report the modern-only server alive promptly instead of
        hanging the --check until the read timeout."""
        discover_result = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}},
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {
                            "name": "modern-sse-srv",
                            "version": "2",
                        }
                    },
                },
            }
        )

        def open_stream():
            yield f"event: message\ndata: {discover_result}\n\n".encode()
            raise AssertionError(
                "discover retry kept reading past the JSON-RPC response"
            )

        httpx_mock.add_response(status_code=404, text="")
        httpx_mock.add_response(
            stream=IteratorStream(open_stream()),
            headers={"content-type": "text/event-stream"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is True
        assert "server=modern-sse-srv" in capsys.readouterr().err

    def test_500_does_not_retry_with_discover(self, httpx_mock):
        """: 500 is NOT in the discover-fallback set — retrying it with a
        different method would not distinguish "legacy-dropped" from "broken"
        and would cost every genuinely-broken endpoint an extra round-trip.
        Exactly one request must be sent."""
        httpx_mock.add_response(status_code=500, text="oops")
        assert check_connection(self.URL, dict(self.HEADERS)) is False
        assert len(httpx_mock.get_requests()) == 1

    def test_400_discover_retry_also_fails(self, httpx_mock):
        """: both the initialize probe AND the discover retry fail —
        the connection is genuinely down, not just legacy-dropped."""
        httpx_mock.add_response(status_code=400, text="")
        httpx_mock.add_response(status_code=400, text="")
        assert check_connection(self.URL, dict(self.HEADERS)) is False
        assert len(httpx_mock.get_requests()) == 2

    def test_400_discover_retry_gets_jsonrpc_error(self, httpx_mock):
        """: the discover retry itself may come back HTTP 200 but with a
        JSON-RPC error body (e.g. the endpoint rejects this particular
        discover request for some other reason even though it carries the
        full modern-shaped body/headers) — that is still "the server
        responded", just unhealthily, and the probe's verdict must be False
        (mirrors _report_initialize). The request-count assertion is what
        discriminates this from the no-fallback behavior: without the fix
        only ONE request is ever sent and the (unconsumed) discover mock
        would leave httpx_mock's teardown assertion failing, not this one —
        assert the count directly so the fallback path is unambiguously
        exercised."""
        httpx_mock.add_response(status_code=400, text="")
        httpx_mock.add_response(
            text=json.dumps(
                {"jsonrpc": "2.0", "id": 2, "error": {"code": -32020, "message": "bad"}}
            ),
            headers={"content-type": "application/json"},
        )
        assert check_connection(self.URL, dict(self.HEADERS)) is False
        assert len(httpx_mock.get_requests()) == 2

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
        httpx_mock.add_response(text=body, headers={"content-type": "application/json"})
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
        httpx_mock.add_response(text=body, headers={"content-type": "application/json"})
        assert check_connection(self.URL, dict(self.HEADERS)) is True

    def test_non_object_result_does_not_crash(self, httpx_mock):
        """A malformed server returning a scalar ``result`` is reported as
        reachable rather than crashing on attribute access."""
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "ok"})
        httpx_mock.add_response(text=body, headers={"content-type": "application/json"})
        assert check_connection(self.URL, dict(self.HEADERS)) is True

    def test_bare_scalar_top_level_body_does_not_report_down(self, httpx_mock, capsys):
        """#350 review round 2/3: a fallback discovery response that is
        valid JSON but not an OBJECT at all (e.g. HTTP 200 with body ``1``)
        used to raise ``TypeError`` at ``"result" in result_data`` inside
        ``_report_initialize`` — uncaught by that function itself, only
        happening to be swallowed by ``check_connection``'s own outer
        ``except Exception`` and misreported as "Connection failed: ...".
        This is a genuine verdict flip: ``_report_initialize``'s own
        docstring says an unparseable result still counts as "the server
        responded" (True), but the escaped TypeError instead reported the
        live server as DOWN. Must degrade to "could not parse" / True, not
        a Python exception message."""
        httpx_mock.add_response(text="1", headers={"content-type": "application/json"})
        assert check_connection(self.URL, dict(self.HEADERS)) is True
        err = capsys.readouterr().err
        assert "Connection failed" not in err

    def test_non_object_error_value_does_not_crash(self, httpx_mock, capsys):
        """#350 review round 2/3: a JSON-RPC error body whose ``error``
        value is a bare string rather than an object (``{"error":
        "invalid"}``) used to raise ``AttributeError`` at ``err.get(...)``
        inside ``_report_initialize`` — same escape-then-misreport failure
        mode as the scalar-body case above, just triggered from the OTHER
        branch. A malformed-but-still-an-error response must still be
        reported as a genuine JSON-RPC error (False), not crash into a
        generic connection-failed message."""
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "error": "invalid"})
        httpx_mock.add_response(text=body, headers={"content-type": "application/json"})
        assert check_connection(self.URL, dict(self.HEADERS)) is False
        err = capsys.readouterr().err
        assert "Connection failed" not in err
        assert "MCP error" in err

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


class TestParseStreamableResponseTypeContract:
    """#350 review round 2/3: ``_parse_streamable_response`` is declared
    ``-> dict[str, Any] | None`` but the plain-JSON branch used to return
    whatever ``json.loads`` produced, including a bare scalar/list — a
    contract violation its own callers (``_report_initialize`` /
    ``_report_discover``) trusted blindly."""

    def _response(self, text: str) -> httpx.Response:
        return httpx.Response(
            200, content=text.encode(), headers={"content-type": "application/json"}
        )

    def test_bare_scalar_body_returns_none_not_the_scalar(self):
        assert _parse_streamable_response(self._response("1")) is None

    def test_bare_list_body_returns_none(self):
        assert _parse_streamable_response(self._response("[]")) is None

    def test_object_body_still_returned_unchanged(self):
        parsed = _parse_streamable_response(
            self._response('{"jsonrpc":"2.0","id":1,"result":{}}')
        )
        assert parsed == {"jsonrpc": "2.0", "id": 1, "result": {}}


class TestParseStreamableResponseSseContentTypeCase:
    """#350 review round 8 (finding 8-1): media types are case-insensitive
    (RFC 9110 §8.3.1). A buffered response declaring ``Content-Type:
    Text/Event-Stream`` used to fall through to the plain-JSON branch,
    where an SSE-framed body never parses as bare JSON — the valid
    response was silently dropped (``None``)."""

    _SSE_BODY = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n'

    def _sse_response(self, content_type: str) -> httpx.Response:
        return httpx.Response(
            200,
            content=self._SSE_BODY.encode(),
            headers={"content-type": content_type},
        )

    def test_mixed_case_sse_content_type_parses_the_sse_body(self):
        parsed = _parse_streamable_response(self._sse_response("Text/Event-Stream"))
        assert parsed == {"jsonrpc": "2.0", "id": 1, "result": {}}

    def test_lowercase_sse_content_type_still_parses(self):
        parsed = _parse_streamable_response(self._sse_response("text/event-stream"))
        assert parsed == {"jsonrpc": "2.0", "id": 1, "result": {}}


class TestReportInitializeAndDiscoverMalformedInput:
    """Direct unit coverage for #350 review round 2/3: even independent of
    ``check_connection``'s own outer ``except Exception`` (which happens to
    swallow these today), ``_report_initialize``/``_report_discover`` must
    not raise on malformed-but-JSON-valid input — any other/future caller
    without that outer guard would otherwise crash outright."""

    def test_report_initialize_bare_scalar_is_responded_not_crash(self):
        assert _report_initialize(1) is True  # type: ignore[arg-type]

    def test_report_initialize_bare_list_is_responded_not_crash(self):
        assert _report_initialize([1, 2, 3]) is True  # type: ignore[arg-type]

    def test_report_initialize_string_error_value_is_false_not_crash(self):
        assert _report_initialize({"error": "invalid"}) is False

    def test_report_discover_bare_scalar_is_responded_not_crash(self):
        assert _report_discover(1) is True  # type: ignore[arg-type]

    def test_report_discover_string_error_value_is_false_not_crash(self):
        assert _report_discover({"error": "invalid"}) is False


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
        """endpoint event → POST initialize → response on the stream → True.

        The GET stream holds the INIT_RESULT event until the endpoint POST has
        been observed, so the mocked POST is deterministically requested before
        check_connection returns and closes the client. Without this, the reader
        thread could reach INIT_RESULT and return before the background POST
        thread's request landed — leaving the POST 'mocked but not requested'
        and `len(posts) == 1` failing (a thread-scheduling race that surfaced
        reliably on the Python 3.14 runner; same class as #300/#301). Legacy SSE
        delivers POST responses on the stream, not in the POST body."""
        post_attempted = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sid=xyz\n\n"
            # Release the result ONLY once the POST has actually been observed.
            # If it is somehow not seen within the timeout, do not yield the
            # result — let the stream end so check_connection returns False and
            # the test fails deterministically, rather than yielding INIT_RESULT
            # early and reintroducing the race this guard exists to remove.
            if post_attempted.wait(timeout=3):
                yield f"event: message\ndata: {self._INIT_RESULT}\n\n".encode()

        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def on_post(request: httpx.Request) -> httpx.Response:
            post_attempted.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            on_post, url="https://example.com/messages?sid=xyz", method="POST"
        )

        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is True
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
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is True
        )
        err = capsys.readouterr().err
        assert "sse-demo" in err
        assert "tools=yes" in err

    def test_sse_malformed_message_after_endpoint_is_skipped(self, httpx_mock):
        """: a non-JSON message arriving AFTER the endpoint event must
        be skipped (the json.JSONDecodeError continue) and the probe keeps reading
        until the real initialize result — still returns True."""
        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(
                [
                    b"event: endpoint\ndata: /messages\n\n",
                    b"event: message\ndata: not-json-at-all\n\n",
                    f"event: message\ndata: {self._INIT_RESULT}\n\n".encode(),
                ]
            ),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url="https://example.com/messages", method="POST", status_code=202
        )
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is True
        )

    def test_sse_generic_exception_in_stream_returns_false(
        self, httpx_mock, monkeypatch
    ):
        """: an unexpected exception raised inside the GET stream loop
        hits the outer generic-exception safety net and returns False without
        crashing (mirrors the reader-loop safety-net test)."""
        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream([b"event: endpoint\ndata: /messages\n\n"]),
            headers={"content-type": "text/event-stream"},
        )

        def boom(_lines):
            raise RuntimeError("unexpected decode bug")

        monkeypatch.setattr("mcp_stdio.relay._iter_sse_events", boom)
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is False
        )

    def test_sse_get_non_200_returns_false(self, httpx_mock):
        """The GET stream itself failing (e.g. 401) → False, no POST attempted."""
        httpx_mock.add_response(url=self.SSE_URL, method="GET", status_code=401)
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is False
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
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is False
        )

    def test_sse_stream_ends_before_response_returns_false(self, httpx_mock):
        """endpoint arrives but no initialize response before EOF → False.

        The stream is held open until the endpoint POST has been observed, so
        the mocked POST is deterministically requested. Without this, the reader
        thread's EOF could race ahead of the main thread's POST and leave the
        POST mock 'mocked but not requested' — a flaky pytest_httpx teardown
        error (it intermittently failed CI on ubuntu 3.11). The probe still
        returns False because no initialize response ever arrives."""
        post_attempted = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages\n\n"
            # Hold the stream open until the POST is in flight, then EOF with no
            # initialize response so the probe reports 'stream ended' → False.
            post_attempted.wait(timeout=3)

        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def on_post(request: httpx.Request) -> httpx.Response:
            post_attempted.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(on_post, url="https://example.com/messages")
        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is False
        )

    def test_sse_post_non_2xx_reports_post_failure(self, httpx_mock, capsys):
        """: the endpoint POST returning a non-2xx sets post_error,
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

        httpx_mock.add_callback(on_post, url="https://example.com/messages?sid=abc")

        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is False
        )
        err = capsys.readouterr().err
        assert "POST to SSE endpoint failed" in err
        assert "HTTP 500" in err

    def test_sse_post_raises_reports_post_failure(self, httpx_mock, capsys):
        """: the endpoint POST raising a transport error is caught in
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

        httpx_mock.add_callback(on_post, url="https://example.com/messages?sid=abc")

        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is False
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
        initialize response — the probe keeps reading until the real result.

        The stream holds the final INIT_RESULT event until the endpoint POST
        has been observed, so the mocked POST is deterministically requested
        before check_connection returns and closes the client. Without this,
        the reader thread could reach INIT_RESULT and return before the
        background POST thread's request landed, leaving the POST mock
        'mocked but not requested' — a flaky pytest_httpx teardown error
        (intermittently failed CI on windows-latest, see issue #300)."""
        post_attempted = threading.Event()
        notif = '{"jsonrpc":"2.0","method":"notifications/message","params":{}}'

        def sse_gen():
            yield b"event: endpoint\ndata: /messages\n\n"
            yield f"event: message\ndata: {notif}\n\n".encode()
            post_attempted.wait(timeout=3)
            yield f"event: message\ndata: {self._INIT_RESULT}\n\n".encode()

        httpx_mock.add_response(
            url=self.SSE_URL,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def on_post(request: httpx.Request) -> httpx.Response:
            post_attempted.set()
            return httpx.Response(status_code=202)

        httpx_mock.add_callback(
            on_post, url="https://example.com/messages", method="POST"
        )

        assert (
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is True
        )

    def test_sse_message_before_endpoint_is_skipped(self, httpx_mock):
        """: a message event arriving BEFORE the endpoint event must
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
            check_connection(self.SSE_URL, dict(self.HEADERS), transport="sse") is True
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
        instead; see TestRunSseReaderRecovery..)"""
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

    def test_stop_during_reconnect_wait_returns_httperror_branch(self, httpx_mock):
        """: when stop is signaled during the post-disconnect
        RETRY_DELAY wait, the HTTPError reconnect branch returns promptly instead
        of issuing another GET. (Covers the otherwise-untested stop-early-return.)"""
        state = _SseState()
        httpx_mock.add_exception(httpx.ReadError("boom"), url=self.URL, method="GET")
        # Simulate stop being signaled during the reconnect delay: wait() True.
        state.stop.wait = lambda *a, **k: True
        client = httpx.Client()
        try:
            with patch("sys.stdout", StringIO()):
                _sse_reader_loop(client, self.URL, {}, state)  # returns, no reconnect
        finally:
            client.close()
        assert len(httpx_mock.get_requests()) == 1  # no second GET after stop

    def test_stop_during_reconnect_wait_returns_graceful_eof_branch(self, httpx_mock):
        """: the graceful-EOF reconnect path likewise returns promptly
        when stop is signaled during the RETRY_DELAY wait."""
        state = _SseState()
        httpx_mock.add_response(
            url=self.URL,
            method="GET",
            stream=IteratorStream([b"event: endpoint\ndata: /m\n\n"]),
            headers={"content-type": "text/event-stream"},
        )
        state.stop.wait = lambda *a, **k: True
        client = httpx.Client()
        try:
            with patch("sys.stdout", StringIO()):
                _sse_reader_loop(client, self.URL, {}, state)
        finally:
            client.close()
        assert len(httpx_mock.get_requests()) == 1  # no reconnect after stop

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

        httpx_mock.add_callback(
            get_callback, url=self.URL, method="GET", is_reusable=True
        )

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
        """: a non-200 on RECONNECT (after an endpoint was once
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
    """Stdin iterator that yields its line(s) then blocks until released.

    Keeps run_sse's main loop alive after the POST(s) so the SSE reader
    thread has time to receive and print the response event. Once the
    release event is set, the iterator raises StopIteration and the
    main loop exits cleanly. Accepts a single line (str) or a list of
    lines, yielded in order before blocking.
    """

    def __init__(self, line: "str | list[str]", release: threading.Event):
        self._lines = [line] if isinstance(line, str) else list(line)
        self._release = release

    def __iter__(self):
        return self

    def __next__(self):
        if self._lines:
            return self._lines.pop(0)
        self._release.wait(timeout=5)
        raise StopIteration


class TestRunSseReaderRecovery:
    """: an unexpected (non-HTTPError) exception in the SSE reader
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


class TestProactiveRefresh:
    """Unit + integration tests for the proactive token-refresh timer (#242)."""

    @staticmethod
    def _loop_kwargs(**overrides):
        base = {
            "refresher": lambda: {"Authorization": "Bearer new"},
            "expiry_getter": lambda: 100.0,
            "leeway": 0.0,
            "headers": {"Authorization": "Bearer old"},
            "headers_lock": threading.Lock(),
            "refresh_lock": threading.Lock(),
            "stop": threading.Event(),
            "now": lambda: 1000.0,  # well past expiry → refresh fires immediately
            "recheck": 0.001,
            "max_sleep": 300.0,
        }
        base.update(overrides)
        return base

    def test_refreshes_when_past_deadline(self):
        """Past expiry → refresher called and headers merged under the lock."""
        stop = threading.Event()
        calls = []

        def refresher():
            calls.append(1)
            if len(calls) >= 3:
                stop.set()
            return {"Authorization": "Bearer new"}

        headers = {"Authorization": "Bearer old"}
        _proactive_refresh_loop(
            **self._loop_kwargs(refresher=refresher, headers=headers, stop=stop)
        )
        assert len(calls) == 3
        assert headers["Authorization"] == "Bearer new"

    def test_none_expiry_polls_without_refreshing(self):
        """A None expiry (no token / non-expiring) idles without refreshing."""
        stop = threading.Event()
        polls = []
        refresher_calls = []

        def expiry_getter():
            polls.append(1)
            stop.set()  # stop on the first poll so the recheck wait returns at once
            return None

        _proactive_refresh_loop(
            **self._loop_kwargs(
                expiry_getter=expiry_getter,
                refresher=lambda: refresher_calls.append(1) or {"x": "y"},
                stop=stop,
            )
        )
        assert polls == [1]
        assert refresher_calls == []  # never refreshed: nothing to schedule against

    def test_failed_refresh_backs_off_and_retries(self):
        """A refresher returning None backs off (recheck) and retries, no crash."""
        stop = threading.Event()
        calls = []

        def refresher():
            calls.append(1)
            if len(calls) >= 2:
                stop.set()
            return None  # refresh unavailable / failed

        _proactive_refresh_loop(**self._loop_kwargs(refresher=refresher, stop=stop))
        assert len(calls) == 2

    def test_prestopped_returns_immediately(self):
        """A pre-set stop event makes the loop a no-op."""
        stop = threading.Event()
        stop.set()
        calls = []
        _proactive_refresh_loop(
            **self._loop_kwargs(
                refresher=lambda: calls.append(1) or {"x": "y"}, stop=stop
            )
        )
        assert calls == []

    def test_exception_does_not_kill_loop(self):
        """An exception from getter/refresher is logged and retried, never fatal."""
        stop = threading.Event()
        calls = []

        def expiry_getter():
            calls.append(1)
            if len(calls) >= 3:
                stop.set()
            raise RuntimeError("boom")

        # Must return normally (loop survived all three raises), not propagate.
        _proactive_refresh_loop(
            **self._loop_kwargs(expiry_getter=expiry_getter, stop=stop)
        )
        assert len(calls) == 3

    def test_start_disabled_returns_none(self):
        """proactive_refresh=False → no thread started."""
        thread, stop = _start_proactive_refresh(
            refresher=lambda: None,
            expiry_getter=lambda: None,
            proactive_refresh=False,
            leeway=60.0,
            headers={},
            headers_lock=threading.Lock(),
            refresh_lock=threading.Lock(),
        )
        assert thread is None and stop is None

    def test_start_without_oauth_returns_none(self):
        """No refresher / getter (no OAuth) → no thread started even if enabled."""
        thread, stop = _start_proactive_refresh(
            refresher=None,
            expiry_getter=None,
            proactive_refresh=True,
            leeway=60.0,
            headers={},
            headers_lock=threading.Lock(),
            refresh_lock=threading.Lock(),
        )
        assert thread is None and stop is None

    def test_start_runs_and_stops(self):
        """An enabled timer starts, refreshes once, then stops/joins cleanly."""
        headers = {"Authorization": "Bearer old"}
        refreshed = threading.Event()
        calls = []

        def expiry_getter():
            calls.append(1)
            # First read is past-due (fire now); afterwards park far in the future.
            return 0.0 if len(calls) == 1 else time.time() + 3600

        def refresher():
            refreshed.set()
            return {"Authorization": "Bearer new"}

        thread, stop = _start_proactive_refresh(
            refresher=refresher,
            expiry_getter=expiry_getter,
            proactive_refresh=True,
            leeway=0.0,
            headers=headers,
            headers_lock=threading.Lock(),
            refresh_lock=threading.Lock(),
        )
        assert thread is not None and stop is not None
        try:
            assert refreshed.wait(timeout=2.0), "timer never refreshed"
        finally:
            stop.set()
            thread.join(timeout=2.0)
        assert not thread.is_alive()
        assert headers["Authorization"] == "Bearer new"

    def test_stop_none_is_noop(self):
        """_stop_proactive_refresh((None, None)) — never-started timer — no-op."""
        _stop_proactive_refresh(None, None)  # must not raise

    def test_stop_signals_and_joins(self):
        """_stop_proactive_refresh sets the stop event and joins the thread."""
        thread, stop = _start_proactive_refresh(
            refresher=lambda: None,
            expiry_getter=lambda: time.time() + 3600,  # park far out
            proactive_refresh=True,
            leeway=0.0,
            headers={},
            headers_lock=threading.Lock(),
            refresh_lock=threading.Lock(),
        )
        _stop_proactive_refresh(thread, stop)
        assert stop.is_set()
        assert not thread.is_alive()

    def test_run_proactive_timer_fires(self, httpx_mock):
        """run() starts the timer; it refreshes while the main loop parks on stdin."""
        httpx_mock.add_response(
            text='{"jsonrpc":"2.0","result":{},"id":1}',
            headers={"content-type": "application/json"},
        )
        refreshed = threading.Event()

        def refresher():
            refreshed.set()
            return {"Authorization": "Bearer refreshed"}

        calls = []

        def expiry_getter():
            calls.append(1)
            return 0.0 if len(calls) == 1 else time.time() + 3600

        headers = {"Content-Type": "application/json"}
        # _BlockingStdin releases (StopIteration) once the timer sets ``refreshed``.
        stdin = _BlockingStdin('{"jsonrpc":"2.0","method":"init","id":1}', refreshed)
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run(
                "https://example.com/mcp",
                headers,
                token_refresher=refresher,
                token_expiry_getter=expiry_getter,
                proactive_refresh=True,
                refresh_leeway=0.0,
            )
        assert refreshed.is_set()
        assert headers["Authorization"] == "Bearer refreshed"

    def test_run_sse_proactive_timer_fires(self, httpx_mock):
        """run_sse starts the timer; it refreshes while the main loop parks.

        No request line is sent (the stdin yields one empty line, skipped, then
        blocks): this test only proves the timer fires, so it avoids a POST whose
        timing would race the reader nulling the endpoint on stream end. The GET
        gen parks until the timer has fired *and* the main loop has exited, so the
        reader never reconnects mid-test (which would otherwise leave a mocked GET
        unrequested at teardown).
        """
        url = "https://example.com/sse"
        refreshed = threading.Event()
        release_stdin = threading.Event()
        gen_park = threading.Event()  # never set; bounds the gen's final wait

        def refresher():
            refreshed.set()
            return {"Authorization": "Bearer refreshed"}

        calls = []

        def expiry_getter():
            calls.append(1)
            return 0.0 if len(calls) == 1 else time.time() + 3600

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            refreshed.wait(timeout=3)  # hold the GET open until the timer fires
            release_stdin.set()  # then let the main loop exit
            gen_park.wait(timeout=3)  # stay parked so the stream never reconnects

        httpx_mock.add_response(
            url=url,
            method="GET",
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        headers = {"Content-Type": "application/json"}
        # Empty line → skipped by the main loop (no POST) → then blocks until the
        # timer fires and the gen releases it.
        stdin = _BlockingStdin("", release_stdin)
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(
                url,
                headers,
                token_refresher=refresher,
                token_expiry_getter=expiry_getter,
                proactive_refresh=True,
                refresh_leeway=0.0,
            )
        assert refreshed.is_set()
        assert headers["Authorization"] == "Bearer refreshed"


class TestColdStartResponse:
    """#296: local replies synthesized while the cold-start gate is closed."""

    def test_initialize_echoes_version_and_advertises_listchanged(self):
        line = (
            '{"jsonrpc":"2.0","id":1,"method":"initialize",'
            '"params":{"protocolVersion":"2025-06-18"}}'
        )
        out = json.loads(_cold_start_response(line, 1, True))
        assert out["id"] == 1
        assert out["result"]["protocolVersion"] == "2025-06-18"
        caps = out["result"]["capabilities"]
        assert caps["tools"]["listChanged"] is True
        assert caps["resources"]["listChanged"] is True
        assert caps["prompts"]["listChanged"] is True
        assert out["result"]["serverInfo"]["name"] == "mcp-stdio"

    def test_initialize_floor_version_when_absent(self):
        line = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
        out = json.loads(_cold_start_response(line, 1, True))
        assert out["result"]["protocolVersion"] == "2024-11-05"

    @pytest.mark.parametrize(
        "method,key",
        [
            ("tools/list", "tools"),
            ("resources/list", "resources"),
            ("resources/templates/list", "resourceTemplates"),
            ("prompts/list", "prompts"),
        ],
    )
    def test_list_methods_return_empty(self, method, key):
        line = f'{{"jsonrpc":"2.0","id":2,"method":"{method}"}}'
        out = json.loads(_cold_start_response(line, 2, True))
        assert out["result"] == {key: []}

    def test_ping_returns_empty_result(self):
        out = json.loads(
            _cold_start_response('{"jsonrpc":"2.0","id":3,"method":"ping"}', 3, True)
        )
        assert out["result"] == {}

    def test_tools_call_returns_not_ready_error(self):
        line = '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}}'
        out = json.loads(_cold_start_response(line, 4, True))
        assert out["error"]["code"] == -32002
        assert "retry" in out["error"]["message"].lower()

    def test_notifications_are_swallowed(self):
        # notifications/initialized and any other notification -> no reply.
        assert (
            _cold_start_response(
                '{"jsonrpc":"2.0","method":"notifications/initialized"}', None, False
            )
            is None
        )
        assert (
            _cold_start_response(
                '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}',
                None,
                False,
            )
            is None
        )


class TestColdStartLoop:
    """The cold-start background daemon: OAuth -> upstream session -> list_changed."""

    URL = "https://example.com/mcp"

    def test_opens_session_and_emits_list_changed(self, httpx_mock):
        # _reinitialize: initialize POST -> 200 + session id + protocolVersion,
        # then notifications/initialized -> 202.
        httpx_mock.add_response(
            url=self.URL,
            headers={"mcp-session-id": "sess-1", "content-type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": 0,
                "result": {"protocolVersion": "2025-06-18"},
            },
        )
        httpx_mock.add_response(url=self.URL, status_code=202)

        headers = {"Content-Type": "application/json"}
        state = {"session_id": None, "protocol_version": None}
        ready = threading.Event()
        stdout = StringIO()
        client = httpx.Client()
        try:
            with patch("sys.stdout", stdout):
                _cold_start_loop(
                    login=lambda: {"Authorization": "Bearer t"},
                    client=client,
                    url=self.URL,
                    headers=headers,
                    headers_lock=threading.Lock(),
                    tracker=None,
                    state=state,
                    state_lock=threading.Lock(),
                    ready=ready,
                )
        finally:
            client.close()

        assert ready.is_set()
        assert state["session_id"] == "sess-1"
        assert state["protocol_version"] == "2025-06-18"
        assert headers["Authorization"] == "Bearer t"
        out = stdout.getvalue()
        assert "notifications/tools/list_changed" in out
        assert "notifications/resources/list_changed" in out
        assert "notifications/prompts/list_changed" in out

    def test_failed_login_leaves_gate_closed(self, httpx_mock):
        """login() returning None must not set ready or POST upstream."""
        ready = threading.Event()
        state = {"session_id": None, "protocol_version": None}
        client = httpx.Client()
        try:
            _cold_start_loop(
                login=lambda: None,
                client=client,
                url=self.URL,
                headers={},
                headers_lock=threading.Lock(),
                tracker=None,
                state=state,
                state_lock=threading.Lock(),
                ready=ready,
            )
        finally:
            client.close()
        assert not ready.is_set()
        assert httpx_mock.get_requests() == []


class TestRunColdStart:
    """run() cold-start gate end-to-end (Streamable HTTP)."""

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

    def test_gates_all_methods_until_login(self, httpx_mock):
        """While OAuth has not completed (login returns None -> ready never set),
        initialize is answered locally, list methods are empty, tools/call is
        -32002, notifications are swallowed, and nothing is POSTed upstream."""
        out = self._run_with_stdin(
            httpx_mock,
            [
                '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}',
                '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
                '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}',
                '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            ],
            cold_start_login=lambda: None,  # OAuth never completes
        )
        by_id = {
            m.get("id"): m
            for m in (json.loads(x) for x in out.splitlines() if x.strip())
        }
        assert by_id[1]["result"]["capabilities"]["tools"]["listChanged"] is True
        assert by_id[1]["result"]["protocolVersion"] == "2025-06-18"
        assert by_id[2]["result"] == {"tools": []}
        assert by_id[3]["error"]["code"] == -32002
        # The notification produced no frame (no id:null).
        assert None not in by_id
        # Nothing reached the upstream while gated.
        assert httpx_mock.get_requests() == []


class TestRunSse:
    """End-to-end tests for run_sse driven from the main thread."""

    URL = "https://example.com/sse"

    def _sse_post_raises(self, httpx_mock, method_line, exc):
        """Drive run_sse with one stdin line whose endpoint POST raises ``exc``
        (a non-httpx exception), returning the captured stdout."""
        release_stdin = threading.Event()
        post_seen = threading.Event()

        def sse_gen():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            post_seen.wait(timeout=3)
            release_stdin.set()

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        def on_post(request: httpx.Request) -> httpx.Response:
            post_seen.set()
            raise exc

        httpx_mock.add_callback(
            on_post,
            url="https://example.com/messages?sid=abc",
            is_reusable=True,
        )

        stdin = _BlockingStdin(method_line, release_stdin)
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})
        return stdout.getvalue()

    def test_main_loop_unexpected_exception_degrades_request_to_error(self, httpx_mock):
        """: an unexpected NON-httpx exception escaping the run_sse
        POST path must degrade the request-with-id to an 'internal relay error'
        JSON-RPC response and keep the loop alive — the SSE-main-loop analogue of
        the run() structural #11 guard (and it did not crash the process)."""
        out = self._sse_post_raises(
            httpx_mock,
            '{"jsonrpc":"2.0","method":"tools/call","id":55}',
            RuntimeError("simulated unexpected bug in the POST path"),
        )
        decoded = [json.loads(x) for x in out.splitlines() if x]
        match = [d for d in decoded if d.get("id") == 55 and "error" in d]
        assert match, f"expected an error response for id 55, got {decoded!r}"
        assert "internal relay error" in match[0]["error"]["message"]

    def test_main_loop_unexpected_exception_on_notification_stays_silent(
        self, httpx_mock
    ):
        """The same guard must NOT synthesize an id:null response for a
        notification (no id) — it logs and continues silently."""
        out = self._sse_post_raises(
            httpx_mock,
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            RuntimeError("boom"),
        )
        assert out.strip() == ""

    def test_recovery_write_brokenpipe_does_not_crash(self, httpx_mock):
        """: when the client closed stdout, the recovery write in
        run_sse's outer handler raises BrokenPipeError too. It must be swallowed
        (mirroring run()'s guard) so the SSE loop exits cleanly instead of
        crashing the gateway — the SSE analogue of the run() BrokenPipe test."""
        with patch(
            "mcp_stdio.relay._write_line",
            side_effect=BrokenPipeError(32, "Broken pipe"),
        ):
            # The POST raises a non-httpx exception → the outer handler's recovery
            # write also raises BrokenPipeError → must be swallowed, not propagate.
            self._sse_post_raises(
                httpx_mock,
                '{"jsonrpc":"2.0","method":"tools/call","id":99}',
                RuntimeError("boom"),
            )
        # Reaching here = run_sse returned without propagating the BrokenPipeError.

    def test_cross_origin_endpoint_refused_end_to_end(self, httpx_mock):
        """: an SSE endpoint event pointing cross-origin while an
        Authorization header is set is refused at the reader (no credential
        leak). With no OTHER endpoint, run_sse has no usable endpoint, fails
        startup and exits(1) — and crucially NO POST is ever sent to the evil
        origin. Proves the credential-leak refusal holds end-to-end."""

        def sse_gen():
            yield b"event: endpoint\ndata: https://evil.example/steal\n\n"
            # Keep the stream open briefly so the reader stays parked past the
            # refusal (rather than ending and reconnecting into an unmocked GET)
            # until run_sse observes the None endpoint and exits.
            time.sleep(0.5)

        httpx_mock.add_response(
            url=self.URL,
            stream=IteratorStream(sse_gen()),
            headers={"content-type": "text/event-stream"},
        )

        stdin = StringIO('{"jsonrpc":"2.0","method":"tools/call","id":77}\n')
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            with pytest.raises(SystemExit) as exc:
                run_sse(
                    self.URL,
                    {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer s3cr3t",
                    },
                )
        assert exc.value.code == 1
        # The cross-origin endpoint was refused — no POST to ANY origin, so the
        # bearer credential never went to evil.example.
        assert not [r for r in httpx_mock.get_requests() if r.method == "POST"]

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
            (None, 300),  # parameter default
            (300, 300),  # explicit default
            (60, 60),  # custom non-zero
            (0, None),  # 0 disables
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

        class _OneShotEndpointState(_SseState):
            # Subclass the real state so the in-flight tracker API
            # (track/untrack/clear_busy) is inherited; only endpoint_url
            # reads are faked.
            __slots__ = ("_reads",)

            def __init__(self):
                super().__init__()
                self._reads = 0

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

        stdin = _BlockingStdin('{"jsonrpc":"2.0","method":"t","id":3}\n', release_stdin)
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

        stdin = _BlockingStdin('{"jsonrpc":"2.0","method":"t","id":4}\n', release_stdin)
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

        class _ReconnectingState(_SseState):
            # Subclass the real state so the in-flight tracker API
            # (track/untrack/clear_busy) is inherited; only endpoint_url
            # reads and the ready event are faked.
            __slots__ = ("_reads",)

            def __init__(self):
                super().__init__()
                self._reads = 0
                self.ready = _FakeReady()

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
        assert any(t[:2] == (socket.SOL_SOCKET, socket.SO_KEEPALIVE) for t in opts)

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

    def test_default_ttl_constant_is_60s_and_wired(self):
        """: pin the production TTL constant AND that the DEFAULT
        tracker (the one run()/run_sse() build) uses it, so an accidental change
        to _CANCEL_TTL_SECS — or a default-arg that stops referencing it — is
        caught rather than silently widening/shrinking the cancel window."""
        from mcp_stdio.relay import _CANCEL_TTL_SECS

        assert _CANCEL_TTL_SECS == 60.0
        clock = _FakeClock()
        t = _CancelTracker(now=clock)  # default ttl
        t.add(5)
        clock.advance(59)
        assert t.contains(5)  # still within the 60 s default
        clock.advance(2)  # past 60 s
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
        """: discard() removes a tracked id (used when a request
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
        """: pin the production GC bound AND prove GC actually prunes
        the internal map. The old version hardcoded 200/256/300 and asserted only
        via contains() (which lazy-expires), so it passed even if the threshold
        were widened. Derive counts from _CANCEL_GC_THRESHOLD and assert the
        internal _seen map shrank, so a silent widening is caught."""
        from mcp_stdio.relay import _CANCEL_GC_THRESHOLD

        assert _CANCEL_GC_THRESHOLD == 256  # pin the documented bound
        clock = _FakeClock()
        t = _CancelTracker(ttl=10.0, now=clock)
        # Fill PAST the threshold with ids that all expire by t=20.
        n_old = _CANCEL_GC_THRESHOLD + 1
        for i in range(n_old):
            t.add(i)
        clock.advance(20)
        # One more add crosses the threshold again, now with expired entries →
        # _gc_locked sweeps them. _seen must shrink to just the fresh id, proving
        # GC ran (not merely contains()'s lazy per-key expiry).
        t.add(n_old)
        assert len(t._seen) == 1, "GC did not prune the internal map"
        assert t.contains(n_old)
        for i in range(n_old):
            assert not t.contains(i), f"old id {i} still tracked after GC"

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

    def test_consume_under_contention_is_exactly_once(self):
        """: consume() must return True EXACTLY once per id even when
        many threads race on the SAME ids — the lock makes pop-and-check atomic.
        A broken/removed lock could let two threads both pop-and-return-True for
        one id (a double drop). Unlike test_thread_safety (disjoint ranges, which
        passes even without the lock), this contends on shared ids and asserts an
        invariant only a correct lock preserves: total True count == id count."""
        t = _CancelTracker()
        n_ids = 500
        for i in range(n_ids):
            t.add(i)

        true_counts: list[int] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            try:
                barrier.wait()  # release all threads together for max contention
                local = sum(1 for i in range(n_ids) if t.consume(i))
                true_counts.append(local)
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert not errors, f"threads raised: {errors!r}"
        # Every id consumed by exactly one thread → the True counts sum to n_ids.
        assert sum(true_counts) == n_ids, (
            f"expected exactly {n_ids} successful consumes (one per id), "
            f"got {sum(true_counts)} across {true_counts!r}"
        )
        # And every id is gone afterwards.
        assert all(not t.contains(i) for i in range(n_ids))


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

    def test_ignores_batched_cancel(self):
        """: a notifications/cancelled buried in a JSON-RPC BATCH array
        is intentionally NOT extracted (the regex pre-check matches the substring,
        but the isinstance(msg, dict) gate fails on a list → None). Pins the
        documented batch exclusion so a future refactor that iterates batch
        elements before the dict check cannot start tracking batched cancel ids
        and collateral-drop batch responses. Symmetric with test_forwards_json_batch."""
        line = (
            '[{"jsonrpc":"2.0","method":"notifications/cancelled",'
            '"params":{"requestId":7}}]'
        )
        assert _extract_cancel_id(line) is None

    def test_ignores_other_notifications(self):
        line = '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
        assert _extract_cancel_id(line) is None

    def test_ignores_plain_requests(self):
        line = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{}}'
        assert _extract_cancel_id(line) is None

    def test_ignores_malformed_json(self):
        # Passes the regex pre-check by having the method substring in
        # the raw text, but json.loads will fail.
        assert (
            _extract_cancel_id('{bad json "method":"notifications/cancelled"') is None
        )

    def test_ignores_missing_params(self):
        line = '{"jsonrpc":"2.0","method":"notifications/cancelled"}'
        assert _extract_cancel_id(line) is None

    def test_ignores_non_dict_params(self):
        line = (
            '{"jsonrpc":"2.0","method":"notifications/cancelled",'
            '"params":["requestId",1]}'
        )
        assert _extract_cancel_id(line) is None

    def test_null_request_id_returns_none(self):
        """An explicit requestId:null yields None — the caller's `cid is not None`
        guard then skips tracking, a clean no-op."""
        line = (
            '{"jsonrpc":"2.0","method":"notifications/cancelled",'
            '"params":{"requestId":null}}'
        )
        assert _extract_cancel_id(line) is None

    @pytest.mark.parametrize("request_id", ['{"a":1}', "[1,2]", "{}", "[]"])
    def test_non_scalar_request_id_returns_none_not_unhashable_crash(self, request_id):
        """: a non-scalar requestId (object/array) is malformed AND
        unhashable, so returning it verbatim would make the caller's
        tracker.add(rid) raise TypeError on the stdin hot path. _extract_cancel_id
        must drop it (return None) so a malformed cancellation is a clean no-op.
        Guard the full path: the extracted value must be safe to add to a tracker."""
        line = (
            '{"jsonrpc":"2.0","method":"notifications/cancelled",'
            f'"params":{{"requestId":{request_id}}}}}'
        )
        cid = _extract_cancel_id(line)
        assert cid is None
        # End-to-end: the value (None → skipped) never reaches an unhashable add.
        tracker = _CancelTracker()
        if cid is not None:  # mirrors the relay's guard
            tracker.add(cid)  # would raise TypeError if a dict/list slipped through

    def test_scalar_request_ids_pass_through(self):
        """A valid scalar requestId (int / float / string) is returned verbatim
        and is hashable, so the tracker accepts it."""
        for body, expected in [
            ('"requestId":5', 5),
            ('"requestId":1.5', 1.5),
            ('"requestId":"r-1"', "r-1"),
        ]:
            line = (
                '{"jsonrpc":"2.0","method":"notifications/cancelled",'
                f'"params":{{{body}}}}}'
            )
            cid = _extract_cancel_id(line)
            assert cid == expected
            _CancelTracker().add(cid)  # hashable → no crash

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

    def test_forwards_malformed_message_with_method_and_result(self, capsys):
        # a malformed peer message carrying BOTH `method` and
        # `result` under a cancelled id is a request by JSON-RPC definition
        # (method present), not a response — the filter must pass it through,
        # not eat a server-initiated request on a torn-frame technicality.
        t = _CancelTracker()
        t.add(1)
        line = '{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"result":{}}'
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
        """: a merged paginated list result (the shape
        _paginate_and_stream flushes via _emit) is dropped when its id was
        cancelled — closing the cancel-filter × pagination coverage gap."""
        t = _CancelTracker()
        t.add(1)
        merged = (
            '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"},{"name":"b"}]}}'
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

    def test_cancel_then_paginated_request_merged_result_is_forwarded(self, httpx_mock):
        """: closes the cancel x pagination coverage matrix end-to-end.
        A cancelled id reused by a paginated tools/list is a brand-new call: the
        request discards the tracked cancel before dispatch, so the MERGED
        multi-page result is FORWARDED, not dropped. (The drop case is not
        reproducible here — pagination is synchronous, so no late cancel can
        pre-empt the emit, unlike the async SSE path; the _emit drop seam itself
        is unit-covered by test_drops_merged_paginated_result.)"""
        httpx_mock.add_response(status_code=202, text="")  # cancel ACK
        httpx_mock.add_response(
            url="https://example.com/mcp",
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "result": {"tools": [{"name": "a"}], "nextCursor": "p2"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url="https://example.com/mcp",
            text=json.dumps(
                {"jsonrpc": "2.0", "id": 7, "result": {"tools": [{"name": "b"}]}}
            ),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                (
                    '{"jsonrpc":"2.0","method":"notifications/cancelled",'
                    '"params":{"requestId":7}}'
                ),
                '{"jsonrpc":"2.0","id":7,"method":"tools/list"}',
            ],
        )
        merged = json.loads(output.strip())
        assert [t["name"] for t in merged["result"]["tools"]] == ["a", "b"]

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
        assert any(d.get("id") == 5 and "error" in d for d in decoded), (
            f"synthesized error response missing from: {lines!r}"
        )

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

    def test_cancel_ttl_expired_then_sse_message_is_delivered(
        self, httpx_mock, monkeypatch
    ):
        """: the cancel-drop is TTL-bounded END-TO-END. With the
        tracker's TTL already elapsed, a cancelled id's late SSE response is
        DELIVERED, not dropped — the integration analogue of the unit
        consume-expired test. (Patch the tracker run_sse builds to a negative TTL
        so any entry is immediately past-window.)"""
        import mcp_stdio.relay as relay_mod

        real_cls = relay_mod._CancelTracker
        monkeypatch.setattr(
            "mcp_stdio.relay._CancelTracker", lambda: real_cls(ttl=-1.0)
        )

        payload = '{"jsonrpc":"2.0","result":{"late":true},"id":11}'
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
            on_post, url="https://example.com/messages?sessionId=abc"
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

        # TTL elapsed → the late response is NOT dropped.
        assert "late" in stdout.getvalue()

    def test_no_cancel_filter_lets_sse_response_through(self, httpx_mock):
        """: run_sse(..., cancel_filter=False) builds no tracker, so
        the SSE reader's None-tracker branch is taken and a late response for a
        cancelled id is DELIVERED, not dropped. The opt-out is the cancel
        filter's reason to exist, and the late-drop only reproduces on the SSE
        path, so its runtime behaviour must be pinned here (the run() side is
        already covered)."""
        payload = '{"jsonrpc":"2.0","result":{"late":true},"id":11}'
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
            on_post, url="https://example.com/messages?sessionId=abc"
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
            run_sse(self.URL, {"Content-Type": "application/json"}, cancel_filter=False)

        # With the filter disabled the cancelled id is not tracked → delivered.
        assert "late" in stdout.getvalue()

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
        """: a message event whose JSON payload contains a RAW
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

    def test_429_http_date_retry_after_then_200(self, httpx_mock, monkeypatch):
        """: an HTTP-date Retry-After flows end-to-end through
        _handle_rate_limit into the run() retry sleep — the integration analogue
        of the parser unit test. The date->delta conversion is exercised on the
        real path, not just in isolation."""
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        # Retry-After as an HTTP-date 10 s in the future (RFC 9110 §10.2.3).
        future = datetime.now(timezone.utc) + timedelta(seconds=10)
        http_date = email.utils.format_datetime(future, usegmt=True)
        httpx_mock.add_response(
            status_code=429, headers={"retry-after": http_date}, text=""
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
        # The date was parsed to a ~10 s delta and slept on, NOT the 1 s
        # no-hint backoff fallback (which would be the value if parsing failed).
        assert slept, "expected a retry sleep"
        assert max(slept) >= 5.0, f"expected a date-derived sleep, got {slept!r}"

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
        """: a 429 whose wait exceeds the cap surfaces the server's
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

    def test_429_repeated_exhausts_retries_and_surfaces(self, httpx_mock, monkeypatch):
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
        """: a 503 with Retry-After sleeps that long, then the
        retried POST's 200 is delivered normally."""
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        httpx_mock.add_response(status_code=503, headers={"retry-after": "2"}, text="")
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
    """The legacy SSE POST path treats 503 like 429 too."""

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
        """: a page-1 429 whose Retry-After exceeds the cap gives
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
        """The pagination path honours 503 Retry-After too."""
        slept: list[float] = []
        monkeypatch.setattr("mcp_stdio.relay.time.sleep", lambda s: slept.append(s))

        httpx_mock.add_response(status_code=503, headers={"retry-after": "2"}, text="")
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


# --- SSE in-flight drain (#272) ---


class TestExtractResponseId:
    """_extract_response_id applies _emit's pure-response test + scalar guard."""

    @pytest.mark.parametrize(
        "line,expected",
        [
            ('{"jsonrpc":"2.0","result":{},"id":7}', 7),
            ('{"jsonrpc":"2.0","error":{"code":1,"message":"x"},"id":"a"}', "a"),
            # method present => request/notification, never a response
            ('{"jsonrpc":"2.0","method":"ping","id":7}', None),
            ('{"jsonrpc":"2.0","method":"m","result":{},"id":7}', None),
            # id:null is uncorrelatable
            ('{"jsonrpc":"2.0","result":{},"id":null}', None),
            # non-scalar id could never have been tracked
            ('{"jsonrpc":"2.0","result":{},"id":[1]}', None),
            # non-finite ids (json.loads accepts the non-standard literals)
            # would emit invalid JSON if echoed, and NaN != NaN breaks keys
            ('{"jsonrpc":"2.0","result":{},"id":NaN}', None),
            ('{"jsonrpc":"2.0","result":{},"id":Infinity}', None),
            # batches / non-objects / garbage pass through untouched
            ('[{"jsonrpc":"2.0","result":{},"id":7}]', None),
            ("not json", None),
            ('{"jsonrpc":"2.0","id":7}', None),  # neither result nor error
        ],
    )
    def test_extraction(self, line, expected):
        assert _extract_response_id(line) == expected


class TestSseInflightDrain:
    """A stream drop synthesizes -32000 errors for ids POSTed on the dropped
    stream and still awaiting their async reply (#272) — instead of leaving
    the stdio client hanging forever (the claude-code#60061 class)."""

    URL = "https://example.com/sse"

    def _run_reader_two_streams(self, httpx_mock, first_chunks, state, tracker=None):
        """Drive _sse_reader_loop through one stream drop + one reconnect.

        The existing _run_reader helper cannot be used: its generator sets
        state.stop at end-of-stream, and the reader's stop check sits BEFORE
        the drain by design (a clean shutdown must not drain), so the drain
        would never run. Here the FIRST stream ends without stop (a real
        drop), and the SECOND stream stops the loop.
        """

        def gen1():
            yield from first_chunks

        def gen2():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            state.stop.set()

        for gen in (gen1, gen2):
            httpx_mock.add_response(
                url=self.URL,
                method="GET",
                stream=IteratorStream(gen()),
                headers={"content-type": "text/event-stream"},
            )
        client = httpx.Client()
        stdout = StringIO()
        try:
            with (
                patch("sys.stdout", stdout),
                patch("mcp_stdio.relay.RETRY_DELAY", 0),
            ):
                _sse_reader_loop(client, self.URL, {}, state, tracker)
        finally:
            client.close()
        return stdout.getvalue()

    def test_stream_end_drains_pending_to_errors(self, httpx_mock):
        state = _SseState()
        state.pending[7] = 0.0
        out = self._run_reader_two_streams(
            httpx_mock, [b"event: endpoint\ndata: /m\n\n"], state
        )
        msgs = [json.loads(x) for x in out.strip().splitlines() if x]
        errs = [m for m in msgs if m.get("id") == 7 and "error" in m]
        assert len(errs) == 1
        assert errs[0]["error"]["code"] == -32000
        assert "disconnected" in errs[0]["error"]["message"]
        assert state.pending == {}

    def test_delivered_response_pops_pending(self, httpx_mock):
        state = _SseState()
        state.pending[7] = 0.0
        state.pending[8] = 0.0
        reply = '{"jsonrpc":"2.0","result":{"ok":1},"id":7}'
        out = self._run_reader_two_streams(
            httpx_mock,
            [
                b"event: endpoint\ndata: /m\n\n",
                f"event: message\ndata: {reply}\n\n".encode(),
            ],
            state,
        )
        msgs = [json.loads(x) for x in out.strip().splitlines() if x]
        # id 7 got its real reply and must NOT get a synthesized error;
        # id 8 was still in flight at the drop and must get exactly one.
        by_id_7 = [m for m in msgs if m.get("id") == 7]
        assert by_id_7 == [json.loads(reply)]
        errs_8 = [m for m in msgs if m.get("id") == 8 and "error" in m]
        assert len(errs_8) == 1

    def test_cancelled_id_skipped_in_drain(self, httpx_mock, capsys):
        state = _SseState()
        state.pending[7] = 0.0
        tracker = _CancelTracker()
        tracker.add(7)
        out = self._run_reader_two_streams(
            httpx_mock, [b"event: endpoint\ndata: /m\n\n"], state, tracker
        )
        assert out.strip() == ""  # no unsolicited response for a cancelled id
        assert "cancelled id 7" in capsys.readouterr().err
        # Non-consuming check: the cancel entry must survive the drain so a
        # residual real late response would still be gated.
        assert tracker.contains(7)

    def test_drain_pending_is_noop_when_empty(self):
        state = _SseState()
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            _drain_pending(state, None)
        assert stdout.getvalue() == ""


class TestRunSseInflightDrain:
    """End-to-end: request POSTed, reply pending, stream drops."""

    URL = "https://example.com/sse"
    POST_URL = "https://example.com/messages?sid=abc"

    def _drive(
        self,
        httpx_mock,
        monkeypatch,
        stdin_lines,
        first_stream_tail=None,
        pending_cap=None,
    ):
        """run_sse with a two-GET stream: GET-1 ends after ALL stdin lines have
        been POSTed (so every pending add strictly precedes the drain), GET-2
        releases stdin and holds until shutdown."""
        monkeypatch.setattr("mcp_stdio.relay.RETRY_DELAY", 0.05)
        if pending_cap is not None:
            monkeypatch.setattr("mcp_stdio.relay._SSE_PENDING_MAX", pending_cap)
        release_stdin = threading.Event()
        hold_gen2 = threading.Event()
        all_posted = threading.Event()
        n_lines = len(stdin_lines)
        posts = {"n": 0}

        def post_callback(request):
            posts["n"] += 1
            if posts["n"] >= n_lines:
                all_posted.set()
            return httpx.Response(202)

        httpx_mock.add_callback(
            post_callback, url=self.POST_URL, method="POST", is_reusable=True
        )

        def sse_gen_1():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            # Wait until the main loop has POSTed (and tracked) every line —
            # only then drop the stream, so the drain is deterministic.
            # Generous timeouts: on a loaded CI runner a short wait firing
            # early would drop the stream before every id is tracked and
            # flake the assertions.
            all_posted.wait(timeout=10)
            if first_stream_tail:
                yield first_stream_tail

        def sse_gen_2():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            release_stdin.set()
            hold_gen2.wait(timeout=5)

        for gen in (sse_gen_1, sse_gen_2):
            httpx_mock.add_response(
                url=self.URL,
                method="GET",
                stream=IteratorStream(gen()),
                headers={"content-type": "text/event-stream"},
            )

        stdin = _BlockingStdin(stdin_lines, release_stdin)
        stdout = StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})
        hold_gen2.set()
        return [json.loads(x) for x in stdout.getvalue().strip().splitlines() if x]

    def test_inflight_request_gets_error_on_drop(self, httpx_mock, monkeypatch):
        msgs = self._drive(
            httpx_mock,
            monkeypatch,
            [
                '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            ],
        )
        # Exactly one synthesized error, for the request id — never for the
        # notification.
        assert len(msgs) == 1
        assert msgs[0]["id"] == 1
        assert msgs[0]["error"]["code"] == -32000
        assert "disconnected" in msgs[0]["error"]["message"]

    def test_answered_request_gets_no_error_on_drop(self, httpx_mock, monkeypatch):
        reply = '{"jsonrpc":"2.0","result":{"ok":1},"id":1}'
        msgs = self._drive(
            httpx_mock,
            monkeypatch,
            ['{"jsonrpc":"2.0","id":1,"method":"tools/list"}'],
            first_stream_tail=f"event: message\ndata: {reply}\n\n".encode(),
        )
        assert msgs == [json.loads(reply)]

    def test_cancelled_request_gets_no_error_on_drop(self, httpx_mock, monkeypatch):
        msgs = self._drive(
            httpx_mock,
            monkeypatch,
            [
                '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                '{"jsonrpc":"2.0","method":"notifications/cancelled",'
                '"params":{"requestId":1}}',
            ],
        )
        assert msgs == []  # cancelled: no waiter, no synthesized error

    def test_reply_racing_the_post_causes_no_error(self, httpx_mock, monkeypatch):
        # Deliver-before-add race regression: the reply for id 1 arrives on
        # the GET stream BEFORE client.post() returns (a fast server).
        # Tracking happens before the POST, so the reader settles the id and
        # the later drop must synthesize nothing — tracking-after-POST would
        # leave the answered id in pending and put a spurious second
        # response on the wire at the next drop.
        monkeypatch.setattr("mcp_stdio.relay.RETRY_DELAY", 0.05)
        release_stdin = threading.Event()
        hold_gen2 = threading.Event()
        post_started = threading.Event()
        post_done = threading.Event()
        stdout = StringIO()
        reply = '{"jsonrpc":"2.0","result":{"ok":1},"id":1}'

        def post_callback(request):
            post_started.set()
            # Hold the POST open until the reader has written the reply, so
            # delivery strictly precedes the POST returning.
            for _ in range(500):
                if "ok" in stdout.getvalue():
                    break
                time.sleep(0.01)
            post_done.set()
            return httpx.Response(202)

        httpx_mock.add_callback(
            post_callback, url=self.POST_URL, method="POST", is_reusable=True
        )

        def sse_gen_1():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            post_started.wait(timeout=10)
            yield f"event: message\ndata: {reply}\n\n".encode()
            post_done.wait(timeout=10)
            # Stream drops only after the POST returned: the drain must
            # find nothing for id 1.

        def sse_gen_2():
            yield b"event: endpoint\ndata: /messages?sid=abc\n\n"
            release_stdin.set()
            hold_gen2.wait(timeout=5)

        for gen in (sse_gen_1, sse_gen_2):
            httpx_mock.add_response(
                url=self.URL,
                method="GET",
                stream=IteratorStream(gen()),
                headers={"content-type": "text/event-stream"},
            )

        stdin = _BlockingStdin(
            ['{"jsonrpc":"2.0","id":1,"method":"tools/list"}'], release_stdin
        )
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            run_sse(self.URL, {"Content-Type": "application/json"})
        hold_gen2.set()
        msgs = [json.loads(x) for x in stdout.getvalue().strip().splitlines() if x]
        assert msgs == [json.loads(reply)]

    def test_pending_cap_refuses_new_ids(self, httpx_mock, monkeypatch, capsys):
        msgs = self._drive(
            httpx_mock,
            monkeypatch,
            [
                '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
            ],
            pending_cap=1,
        )
        # At the cap the NEW id is refused (reverting it to the pre-#272
        # behavior) so the oldest, longest-running call keeps its
        # protection: only id 1 gets the synthesized error.
        assert [m["id"] for m in msgs] == [1]
        assert "in-flight tracker at cap" in capsys.readouterr().err


# --- #270 Phase 1: modern (spec rev 2026-07-28) dual-mode dispatch ---


class TestExtractMethodAndName:
    def test_tools_call_extracts_name(self):
        line = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}'
        assert _extract_method_and_name(line) == ("tools/call", "echo")

    def test_resources_read_extracts_uri(self):
        line = (
            '{"jsonrpc":"2.0","id":1,"method":"resources/read",'
            '"params":{"uri":"file:///a"}}'
        )
        assert _extract_method_and_name(line) == ("resources/read", "file:///a")

    def test_prompts_get_extracts_name(self):
        line = '{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"p"}}'
        assert _extract_method_and_name(line) == ("prompts/get", "p")

    def test_tools_list_has_no_name(self):
        line = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
        assert _extract_method_and_name(line) == ("tools/list", None)

    def test_batch_array_returns_none_none(self):
        line = '[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]'
        assert _extract_method_and_name(line) == (None, None)

    def test_unparseable_returns_none_none(self):
        assert _extract_method_and_name("not json") == (None, None)


class TestEncodeMcpName:
    def test_plain_ascii_rides_verbatim(self):
        assert _encode_mcp_name("echo") == "echo"

    def test_non_ascii_is_base64_sentinel_encoded(self):
        # Spec's own worked example: "Hello, 世界" -> the exact sentinel form.
        assert _encode_mcp_name("Hello, 世界") == "=?base64?SGVsbG8sIOS4lueVjA==?="

    def test_leading_whitespace_is_encoded(self):
        encoded = _encode_mcp_name(" echo")
        assert encoded.startswith("=?base64?") and encoded.endswith("?=")

    def test_value_resembling_sentinel_is_encoded_not_passed_through(self):
        """A value that already LOOKS like the sentinel must still be encoded
        (double-wrapped) — passing it through verbatim would be
        indistinguishable on the wire from a real encoded value."""
        tricky = "=?base64?not-really-encoded?="
        encoded = _encode_mcp_name(tricky)
        assert encoded != tricky
        assert encoded.startswith("=?base64?") and encoded.endswith("?=")


class TestMcpRequestHeaders:
    def test_tools_call_gets_both_headers(self):
        line = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}'
        assert _mcp_request_headers(line) == {
            "Mcp-Method": "tools/call",
            "Mcp-Name": "echo",
        }

    def test_tools_list_gets_method_only(self):
        line = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
        assert _mcp_request_headers(line) == {"Mcp-Method": "tools/list"}

    def test_batch_gets_no_headers(self):
        assert _mcp_request_headers("[]") == {}


class TestExtractLogLevel:
    def test_extracts_level(self):
        line = '{"jsonrpc":"2.0","id":1,"method":"logging/setLevel","params":{"level":"debug"}}'
        assert _extract_log_level(line) == "debug"

    def test_non_matching_method_returns_none(self):
        assert _extract_log_level('{"jsonrpc":"2.0","id":1,"method":"ping"}') is None

    def test_missing_params_returns_none(self):
        line = '{"jsonrpc":"2.0","id":1,"method":"logging/setLevel"}'
        assert _extract_log_level(line) is None


class TestNegotiateModernVersion:
    def test_requested_version_honored_when_supported(self):
        assert _negotiate_modern_version(
            "2026-07-28", ["2025-06-18", "2026-07-28"]
        ) == ("2026-07-28")

    def test_falls_back_to_highest_supported(self):
        assert _negotiate_modern_version(
            "1999-01-01", ["2025-06-18", "2026-07-28"]
        ) == ("2026-07-28")

    def test_no_supported_versions_uses_requested(self):
        assert _negotiate_modern_version("2026-07-28", []) == "2026-07-28"

    def test_no_supported_and_no_requested_uses_floor(self):
        assert _negotiate_modern_version(None, []) == "2026-07-28"

    def test_legacy_requested_on_dual_mode_server_gets_modern_upstream(self):
        """#350 review round 7: a dual-mode server advertising both eras
        while the local legacy client requests 2025-06-18 must get a
        MODERN version upstream — everything else the modern path sends
        (no initialize, no session id, per-request _meta) is the
        2026-07-28 stateless lifecycle, and a 2025 version header on top
        of that wire shape tells a version-sensitive server to expect the
        legacy handshake this path deliberately never performs."""
        assert (
            _negotiate_modern_version("2025-06-18", ["2025-06-18", "2026-07-28"])
            == "2026-07-28"
        )

    def test_legacy_requested_with_no_supported_falls_to_floor(self):
        """Same coherence rule on the empty-supportedVersions fallback: a
        legacy requested version must never become the upstream version
        on the modern path (the old `requested or floor` fallback leaked
        it through)."""
        assert _negotiate_modern_version("2025-06-18", []) == "2026-07-28"

    def test_legacy_only_supported_falls_to_floor(self):
        assert (
            _negotiate_modern_version("2025-06-18", ["2025-03-26", "2025-06-18"])
            == "2026-07-28"
        )

    def test_non_date_form_versions_are_not_trusted_as_modern(self):
        """A non-date-form string ("zzz") from a non-compliant server
        compares above the floor by ASCII accident ("z" > "2") — round 7
        excluded it via a date-form shape check; since round 9 (finding
        9-1) exact membership in _RELAY_IMPLEMENTED_MODERN_VERSIONS
        subsumes that check: garbage can never be a member."""
        assert _negotiate_modern_version(None, ["zzz"]) == "2026-07-28"

    def test_future_advertised_version_is_not_selected(self):
        """#350 review round 9 finding 9-1 (the exact reported scenario):
        era membership (date-form >= floor) is not implementation
        support. A server advertising a future revision alongside
        2026-07-28 must get the version this relay actually implements —
        max() over the modern-ERA subset falsely negotiated 2027-01-01
        wire semantics the relay does not speak."""
        assert (
            _negotiate_modern_version("2025-06-18", ["2026-07-28", "2027-01-01"])
            == "2026-07-28"
        )

    def test_future_only_advertised_falls_to_floor(self):
        """Empty advertised-and-implemented intersection: advertising the
        relay's own floor and letting the future-only server reject it
        with UnsupportedProtocolVersionError (-32022) is honest — falsely
        claiming 2027-01-01 semantics is not."""
        assert _negotiate_modern_version(None, ["2027-01-01"]) == "2026-07-28"

    def test_future_requested_and_advertised_still_falls_to_floor(self):
        """Even a client REQUESTING the future revision the server
        advertises cannot make the relay claim semantics it does not
        implement — the relay sits on the wire between them."""
        assert _negotiate_modern_version("2027-01-01", ["2027-01-01"]) == "2026-07-28"


class TestSeedModernStateFromDiscover:
    def test_seeds_server_info_capabilities_versions(self):
        state = _ModernState()
        discover_result = {
            "jsonrpc": "2.0",
            "id": 0,
            "result": {
                "resultType": "discover",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": "srv",
                        "version": "1",
                    }
                },
            },
        }
        _seed_modern_state_from_discover(state, discover_result)
        assert state.server_info == {"name": "srv", "version": "1"}
        assert state.capabilities == {"tools": {}}
        assert state.supported_versions == ["2026-07-28"]

    def test_none_result_leaves_defaults(self):
        state = _ModernState()
        _seed_modern_state_from_discover(state, None)
        assert state.server_info is None
        assert state.capabilities == {}
        assert state.supported_versions == []

    def test_error_result_leaves_defaults(self):
        state = _ModernState()
        _seed_modern_state_from_discover(
            state,
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32020, "message": "x"}},
        )
        assert state.server_info is None

    def test_reseed_payload_missing_fields_does_not_clobber_seeded_state(self):
        """#350 review round 9 finding 9-2: the reseed retry now fires with
        server_info/supported_versions possibly already seeded by the
        startup probe (empty-capabilities trigger). A reseed payload that
        only carries capabilities must fill exactly that and preserve the
        seeded identity/version state — seeding never erases."""
        state = _ModernState()
        state.server_info = {"name": "srv", "version": "1"}
        state.supported_versions = ["2026-07-28"]
        _seed_modern_state_from_discover(
            state,
            {
                "jsonrpc": "2.0",
                "id": 0,
                "result": {
                    "resultType": "discover",
                    "capabilities": {"tools": {}},
                },
            },
        )
        assert state.capabilities == {"tools": {}}
        assert state.server_info == {"name": "srv", "version": "1"}
        assert state.supported_versions == ["2026-07-28"]

    def test_reseed_payload_empty_values_do_not_erase_seeded_state(self):
        """Same never-erase rule for a payload that answers the fields with
        EMPTY values ({} / []) rather than omitting them: an empty value is
        indistinguishable from the state's own defaults, so skipping the
        assignment is lossless on a first seed and non-destructive on a
        reseed (#350 review round 9, finding 9-2)."""
        state = _ModernState()
        state.server_info = {"name": "srv", "version": "1"}
        state.capabilities = {"tools": {}}
        state.supported_versions = ["2026-07-28"]
        _seed_modern_state_from_discover(
            state,
            {
                "jsonrpc": "2.0",
                "id": 0,
                "result": {
                    "resultType": "discover",
                    "supportedVersions": [],
                    "capabilities": {},
                },
            },
        )
        assert state.capabilities == {"tools": {}}
        assert state.supported_versions == ["2026-07-28"]
        assert state.server_info == {"name": "srv", "version": "1"}


class TestIsRecognizedModernError:
    """Base Protocol "Error Codes" (spec rev 2026-07-28): -32020..-32099 is
    "reserved for the MCP specification"; -32000..-32019 is the legacy/
    grandfathered sub-range with no new allocations; standard pre-existing
    JSON-RPC codes like -32601 sit outside -32000..-32099 entirely.
    """

    def test_reserved_range_code_is_recognized(self):
        assert _is_recognized_modern_error(
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32020, "message": "x"}}
        )

    def test_reserved_range_boundaries_are_recognized(self):
        assert _is_recognized_modern_error(
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32020, "message": "x"}}
        )
        assert _is_recognized_modern_error(
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32099, "message": "x"}}
        )

    def test_generic_jsonrpc_code_is_not_recognized(self):
        """-32601 Method not found predates this revision entirely and is
        exactly what a legacy server sends for an unrecognized method."""
        assert not _is_recognized_modern_error(
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32601, "message": "x"}}
        )

    def test_legacy_subrange_code_is_not_recognized(self):
        assert not _is_recognized_modern_error(
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32000, "message": "x"}}
        )

    def test_just_outside_reserved_range_is_not_recognized(self):
        """-32019 is the top of the legacy sub-range; -32100 is one below
        the reserved range's floor. Neither is in -32020..-32099."""
        assert not _is_recognized_modern_error(
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32019, "message": "x"}}
        )
        assert not _is_recognized_modern_error(
            {"jsonrpc": "2.0", "id": 0, "error": {"code": -32100, "message": "x"}}
        )

    def test_no_error_key_is_not_recognized(self):
        assert not _is_recognized_modern_error(
            {"jsonrpc": "2.0", "id": 0, "result": {}}
        )

    def test_none_is_not_recognized(self):
        assert not _is_recognized_modern_error(None)

    def test_non_dict_error_is_not_recognized(self):
        assert not _is_recognized_modern_error(
            {"jsonrpc": "2.0", "id": 0, "error": "oops"}
        )

    def test_non_int_code_is_not_recognized(self):
        assert not _is_recognized_modern_error(
            {"jsonrpc": "2.0", "id": 0, "error": {"code": "not-an-int"}}
        )


class TestProbeProtocolEra:
    URL = "https://example.com/mcp"

    def test_200_is_modern(self, httpx_mock):
        httpx_mock.add_response(
            text=json.dumps(
                {"jsonrpc": "2.0", "id": 0, "result": {"resultType": "discover"}}
            ),
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "modern"
        assert result["result"]["resultType"] == "discover"
        req = httpx_mock.get_requests()[0]
        assert json.loads(req.content)["method"] == "server/discover"
        assert req.headers["mcp-method"] == "server/discover"

    def test_probe_carries_meta_matching_protocol_version_header(self, httpx_mock):
        """#350 review finding 1: server/discover's own worked example (spec
        rev 2026-07-28, "Discovery") carries params._meta with
        protocolVersion/clientCapabilities even on this pre-negotiation
        probe -- and the Server Validation section requires the
        MCP-Protocol-Version HEADER to match _meta's protocolVersion FIELD
        exactly, on pain of a HeaderMismatch rejection. A probe sending
        params: {} (no _meta at all) violates that invariant."""
        httpx_mock.add_response(
            text=json.dumps(
                {"jsonrpc": "2.0", "id": 0, "result": {"resultType": "discover"}}
            ),
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        _probe_protocol_era(client, self.URL, {})
        req = httpx_mock.get_requests()[0]
        meta = json.loads(req.content)["params"]["_meta"]
        assert (
            meta["io.modelcontextprotocol/protocolVersion"]
            == (req.headers["mcp-protocol-version"])
        )
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {}
        assert "io.modelcontextprotocol/clientInfo" not in meta

    def test_404_is_legacy(self, httpx_mock):
        httpx_mock.add_response(status_code=404, text="")
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"
        assert result is None

    def test_400_with_jsonrpc_error_body_is_modern(self, httpx_mock):
        """: a 400 whose body IS a recognized JSON-RPC error proves the
        server understood server/discover as a method — the spec says stay
        modern, don't fall back to legacy."""
        httpx_mock.add_response(
            status_code=400,
            text=json.dumps(
                {"jsonrpc": "2.0", "id": 0, "error": {"code": -32020, "message": "bad"}}
            ),
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        era, _ = _probe_protocol_era(client, self.URL, {})
        assert era == "modern"

    def test_400_with_generic_jsonrpc_error_body_is_legacy(self, httpx_mock):
        """Bug regression: a legacy server's ordinary "Method not found"
        reply (-32601, a standard pre-existing JSON-RPC code — NOT in the
        -32020..-32099 sub-range this spec revision reserves for itself) to
        the unrecognized server/discover probe must fall back to legacy,
        not be mistaken for a recognized-modern error just because an
        "error" key is present."""
        httpx_mock.add_response(
            status_code=400,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"
        assert result is None

    def test_200_with_generic_jsonrpc_error_body_is_legacy(self, httpx_mock):
        """Bug regression: many legacy servers reply to an unrecognized
        method with HTTP 200 and the JSON-RPC error in the body (a common
        JSON-RPC-over-HTTP convention). A generic error code (-32601) there
        must not be treated as proof of a modern server just because the
        HTTP status was 200."""
        httpx_mock.add_response(
            status_code=200,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"
        assert result is None

    def test_200_with_recognized_modern_error_body_is_modern(self, httpx_mock):
        """A modern server that rejects this particular server/discover call
        (e.g. a missing required client capability, -32021) but replies over
        HTTP 200 rather than 400 is still proven modern by the error code
        itself, matching the 400 path's own recognized-modern rule."""
        httpx_mock.add_response(
            status_code=200,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "error": {"code": -32021, "message": "missing capability"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "modern"
        assert result["error"]["code"] == -32021

    def test_200_with_empty_body_is_legacy(self, httpx_mock):
        """#350 review round 13: a sloppy legacy endpoint (or an
        intermediary) can 200 an unknown method with an EMPTY body. That
        proves nothing about the protocol era — classifying it as modern
        would swallow the client's initialize and send stateless requests
        the server cannot process. Only a genuine result or a
        recognized-modern error is proof."""
        httpx_mock.add_response(status_code=200, text="")
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"
        assert result is None

    def test_200_with_resultless_object_body_is_legacy(self, httpx_mock):
        """#350 review round 13, the bare-{} variant: valid JSON with
        neither result nor error is not a JSON-RPC response at all, so it
        cannot prove the server understood server/discover."""
        httpx_mock.add_response(
            status_code=200,
            text="{}",
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"
        assert result is None

    def test_200_with_null_result_is_legacy(self, httpx_mock):
        """#350 review round 14: a permissive legacy JSON-RPC endpoint can
        answer an unknown method with ``"result": null`` instead of an
        error. A null (or scalar) result is not a DiscoverResult shape and
        must not be taken as proof of a modern server — only an OBJECT
        result qualifies."""
        httpx_mock.add_response(
            status_code=200,
            text=json.dumps({"jsonrpc": "2.0", "id": 0, "result": None}),
            headers={"content-type": "application/json"},
        )
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"
        assert result is None

    def test_400_with_empty_body_is_legacy(self, httpx_mock):
        httpx_mock.add_response(status_code=400, text="")
        client = httpx.Client()
        era, _ = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"

    def test_500_is_legacy(self, httpx_mock):
        """Any status outside {200, 400-with-jsonrpc-error} is treated
        conservatively as legacy — the default on anything ambiguous."""
        httpx_mock.add_response(status_code=500, text="")
        client = httpx.Client()
        era, _ = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"

    def test_transport_error_degrades_to_legacy(self, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"
        assert result is None

    def test_401_without_auth_recovery_is_legacy_and_logged(self, httpx_mock, capsys):
        """#350 review round 4 finding 3, the no-recovery half: with no
        ``auth_recovery`` configured (no OAuth), a 401 probe keeps today's
        conservative legacy fallback — one probe, no retry — but the WHY
        must be visible in the log so an operator whose modern-only server
        got misclassified can diagnose it (workaround: fix credentials or
        pin ``--protocol-era modern``)."""
        httpx_mock.add_response(status_code=401, text="")
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"
        assert result is None
        assert len(httpx_mock.get_requests()) == 1
        assert "HTTP 401; assuming legacy" in capsys.readouterr().err

    def test_401_with_auth_recovery_reprobes_and_detects_modern(self, httpx_mock):
        """#350 review round 4 finding 3: a 401 to the probe is an
        AUTHENTICATION challenge, not protocol evidence — with an expired
        cached OAuth token a modern-only server 401s before ever seeing
        ``server/discover``. The probe must invoke the same token-refresh
        recovery the dispatch path uses and re-probe once with the
        refreshed credentials, classifying the server by what it says once
        it can actually be reached."""
        httpx_mock.add_response(status_code=401, text="")
        httpx_mock.add_response(
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "result": {"supportedVersions": ["2026-07-28"]},
                }
            ),
            headers={"content-type": "application/json"},
        )
        recovered = []

        def recovery(resp):
            recovered.append(resp.status_code)
            return {"Authorization": "Bearer fresh"}

        client = httpx.Client()
        era, result = _probe_protocol_era(
            client,
            self.URL,
            {"Authorization": "Bearer stale"},
            auth_recovery=recovery,
        )
        assert era == "modern"
        assert result["result"]["supportedVersions"] == ["2026-07-28"]
        assert recovered == [401]
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        assert requests[0].headers["authorization"] == "Bearer stale"
        assert requests[1].headers["authorization"] == "Bearer fresh"
        # The retry is a full, spec-compliant probe — same builder as the
        # first attempt (body incl. params._meta, Mcp-Method header).
        assert json.loads(requests[1].content)["method"] == "server/discover"
        assert requests[1].headers["mcp-method"] == "server/discover"

    def test_401_recovery_declining_falls_back_to_legacy_single_probe(self, httpx_mock):
        """A recovery that returns None (refresh failed / no refresh_token)
        must degrade exactly like having no auth_recovery at all: one
        probe, conservative legacy."""
        httpx_mock.add_response(status_code=401, text="")
        client = httpx.Client()
        era, result = _probe_protocol_era(
            client, self.URL, {}, auth_recovery=lambda resp: None
        )
        assert era == "legacy"
        assert result is None
        assert len(httpx_mock.get_requests()) == 1

    def test_second_401_after_recovery_stays_legacy_no_loop(self, httpx_mock):
        """The recovery retry is once-only: a re-probe that 401s AGAIN must
        not invoke recovery a second time (no refresh loop at startup) —
        exactly two probes, recovery called exactly once, legacy fallback."""
        httpx_mock.add_response(status_code=401, text="")
        httpx_mock.add_response(status_code=401, text="")
        recovered = []

        def recovery(resp):
            recovered.append(resp.status_code)
            return {"Authorization": "Bearer fresh"}

        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {}, auth_recovery=recovery)
        assert era == "legacy"
        assert result is None
        assert recovered == [401]
        assert len(httpx_mock.get_requests()) == 2

    def test_403_with_auth_recovery_reprobes_and_detects_modern(self, httpx_mock):
        """403 analogue of the 401 case: the recovery callback receives the
        raw response (it needs the WWW-Authenticate challenge to decide
        whether an RFC 9470 step-up applies) and its refreshed headers
        drive one re-probe."""
        httpx_mock.add_response(
            status_code=403,
            text="",
            headers={
                "www-authenticate": (
                    'Bearer error="insufficient_scope", scope="mcp:tools"'
                )
            },
        )
        httpx_mock.add_response(
            text=json.dumps({"jsonrpc": "2.0", "id": 0, "result": {}}),
            headers={"content-type": "application/json"},
        )
        challenge_scopes = []

        def recovery(resp):
            challenge_scopes.append(
                _parse_www_authenticate_scope(resp.headers.get("www-authenticate"))
            )
            return {"Authorization": "Bearer stepped-up"}

        client = httpx.Client()
        era, _ = _probe_protocol_era(client, self.URL, {}, auth_recovery=recovery)
        assert era == "modern"
        assert challenge_scopes == ["mcp:tools"]
        assert (
            httpx_mock.get_requests()[1].headers["authorization"] == "Bearer stepped-up"
        )

    def test_chained_401_then_403_recovery_detects_modern(self, httpx_mock):
        """#350 review round 6: recovery is bounded PER STAGE, not per
        probe. An expired token 401s; the refresh succeeds; the refreshed
        token then 403s with insufficient_scope — a CHAINED challenge the
        dispatch ladder repairs end-to-end (refresh, then step-up). Gating
        recovery on "first attempt only" left no attempt for the 403 and
        misclassified a healthy modern-only server as legacy. Each stage
        (401 -> refresh, 403 -> step-up) must fire once: three posts, two
        recoveries, modern verdict."""
        httpx_mock.add_response(status_code=401, text="")
        httpx_mock.add_response(
            status_code=403,
            text="",
            headers={
                "www-authenticate": (
                    'Bearer error="insufficient_scope", scope="mcp:tools"'
                )
            },
        )
        httpx_mock.add_response(
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "result": {"supportedVersions": ["2026-07-28"]},
                }
            ),
            headers={"content-type": "application/json"},
        )
        recovered = []

        def recovery(resp):
            recovered.append(resp.status_code)
            if resp.status_code == 401:
                return {"Authorization": "Bearer fresh"}
            return {"Authorization": "Bearer stepped-up"}

        client = httpx.Client()
        era, result = _probe_protocol_era(
            client,
            self.URL,
            {"Authorization": "Bearer stale"},
            auth_recovery=recovery,
        )
        assert era == "modern"
        assert result["result"]["supportedVersions"] == ["2026-07-28"]
        assert recovered == [401, 403]
        requests = httpx_mock.get_requests()
        assert len(requests) == 3
        assert requests[0].headers["authorization"] == "Bearer stale"
        assert requests[1].headers["authorization"] == "Bearer fresh"
        assert requests[2].headers["authorization"] == "Bearer stepped-up"

    def test_chained_recovery_is_bounded_per_stage_no_loop(self, httpx_mock):
        """The per-stage bound (#350 review round 6) must not reopen the
        round-4 no-loop guarantee: after 401 -> refresh and 403 -> step-up
        have EACH fired once, a THIRD challenge of an already-recovered
        status ends the probe (legacy fallback) rather than recovering
        again — exactly three posts, two recoveries, no refresh loop."""
        httpx_mock.add_response(status_code=401, text="")
        httpx_mock.add_response(
            status_code=403,
            text="",
            headers={
                "www-authenticate": (
                    'Bearer error="insufficient_scope", scope="mcp:tools"'
                )
            },
        )
        httpx_mock.add_response(status_code=403, text="")
        recovered = []

        def recovery(resp):
            recovered.append(resp.status_code)
            return {"Authorization": "Bearer refreshed"}

        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {}, auth_recovery=recovery)
        assert era == "legacy"
        assert result is None
        assert recovered == [401, 403]
        assert len(httpx_mock.get_requests()) == 3

    def test_sse_result_on_open_stream_is_modern_without_reading_to_eof(
        self, httpx_mock
    ):
        """#350 review round 5 (finding 5-1): the final JSON-RPC response
        only SHOULD terminate an SSE stream (Streamable HTTP, "Receiving
        Messages"), so a compliant server may answer the discover probe as
        an SSE event and keep the POST stream open. The probe must stop
        reading at that event and classify modern promptly — a buffered
        read would block until the read timeout and then misclassify the
        live modern server as legacy. The generator's post-yield raise is
        the tripwire: it fires only if the probe keeps pulling chunks past
        the response event (the buffered behavior)."""
        result_body = json.dumps(
            {"jsonrpc": "2.0", "id": 0, "result": {"resultType": "discover"}}
        )

        def open_stream():
            yield f"event: message\ndata: {result_body}\n\n".encode()
            raise AssertionError(
                "probe kept reading past the JSON-RPC response on a stream "
                "the server held open"
            )

        httpx_mock.add_response(
            stream=IteratorStream(open_stream()),
            headers={"content-type": "text/event-stream"},
        )
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "modern"
        assert result["result"]["resultType"] == "discover"

    def test_sse_notification_before_result_is_skipped_then_stop(self, httpx_mock):
        """A server MAY interleave request-related notifications before the
        final response on the SSE stream (Streamable HTTP, "Receiving
        Messages"). The probe must skip past them to the actual response —
        and still stop THERE, not read on toward EOF."""
        notification = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/message", "params": {}}
        )
        result_body = json.dumps({"jsonrpc": "2.0", "id": 0, "result": {}})

        def open_stream():
            yield (
                f"event: message\ndata: {notification}\n\n"
                f"event: message\ndata: {result_body}\n\n"
            ).encode()
            raise AssertionError("probe kept reading past the JSON-RPC response")

        httpx_mock.add_response(
            stream=IteratorStream(open_stream()),
            headers={"content-type": "text/event-stream"},
        )
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "modern"
        assert result == json.loads(result_body)

    def test_sse_stream_closing_without_response_is_legacy(self, httpx_mock):
        """A 200 SSE stream that closes without ever carrying a JSON-RPC
        response parses to None — which since #350 review round 13 is NOT
        proof of a modern server (this test originally pinned the old
        200-unparseable -> modern verdict; round 13 inverted it: only a
        genuine result or recognized-modern error proves modern, and a
        response-less stream proves nothing)."""
        httpx_mock.add_response(
            stream=IteratorStream([b"event: ping\ndata: keepalive\n\n"]),
            headers={"content-type": "text/event-stream"},
        )
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "legacy"
        assert result is None

    def test_mixed_case_sse_content_type_is_modern_without_blocking(self, httpx_mock):
        """#350 review round 8 (finding 8-1): media types are
        case-insensitive (RFC 9110 §8.3.1), so ``Content-Type:
        Text/Event-Stream`` is a fully compliant way to declare SSE. A
        case-sensitive compare routed it to the buffered plain-JSON branch,
        where ``resp.read()`` on a stream the server keeps open blocks
        until the read timeout and ``auto`` misclassifies the live modern
        server as legacy. Same post-yield tripwire as the lowercase SSE
        test above: it fires only if the probe buffers past the response
        event."""
        result_body = json.dumps(
            {"jsonrpc": "2.0", "id": 0, "result": {"resultType": "discover"}}
        )

        def open_stream():
            yield f"event: message\ndata: {result_body}\n\n".encode()
            raise AssertionError(
                "probe kept reading past the JSON-RPC response on a "
                "mixed-case SSE content-type"
            )

        httpx_mock.add_response(
            stream=IteratorStream(open_stream()),
            headers={"content-type": "Text/Event-Stream"},
        )
        client = httpx.Client()
        era, result = _probe_protocol_era(client, self.URL, {})
        assert era == "modern"
        assert result["result"]["resultType"] == "discover"


class TestBuildDiscoverProbeRequestStripsAllCaseVariants:
    """#350 review rounds 2 AND 3 (flagged independently by both):
    ``_build_discover_probe_request`` stripped only ``Mcp-Method`` and
    ``MCP-Protocol-Version``, leaving an operator-pinned ``Mcp-Name`` /
    ``Mcp-Session-Id`` untouched. ``server/discover`` has no ``name``
    parameter at all (so any ``Mcp-Name`` value is unsupported by the
    request body) and, being pre-negotiation, must never carry a session
    id either — inconsistent with ``_prepare_headers``' modern-era branch,
    which unconditionally strips both. Mixed-case header keys prove the
    fix strips by ``.lower()``, not by exact string match (mirrors the
    convention at test_relay.py's pinned-Mcp-Name/Mcp-Method tests)."""

    def test_pinned_mcp_name_is_stripped(self):
        _, probe_headers = _build_discover_probe_request(
            {"Content-Type": "application/json", "mcp-name": "operator-pinned"}
        )
        assert "mcp-name" not in {k.lower() for k in probe_headers}

    def test_pinned_mcp_session_id_is_stripped(self):
        _, probe_headers = _build_discover_probe_request(
            {"Content-Type": "application/json", "Mcp-Session-Id": "old-session"}
        )
        assert "mcp-session-id" not in {k.lower() for k in probe_headers}

    def test_pinned_mixed_case_variants_of_both_are_stripped(self):
        _, probe_headers = _build_discover_probe_request(
            {
                "Content-Type": "application/json",
                "MCP-NAME": "operator-pinned",
                "mcp-SESSION-id": "old-session",
            }
        )
        lowered = {k.lower() for k in probe_headers}
        assert "mcp-name" not in lowered
        assert "mcp-session-id" not in lowered
        # The two REQUIRED headers this function itself sets must survive.
        assert probe_headers["Mcp-Method"] == "server/discover"
        assert "MCP-Protocol-Version" in probe_headers


def _with_list_changed(caps):
    """Expected synthesized-InitializeResult capabilities under the C8 union
    (#270 Phase 2 PR A), NARROWED by #352 round-3 finding 2: ``listChanged:
    true`` is set only on the tools/resources/prompts families ALREADY
    PRESENT in the discover seed — an absent family is never created, since
    a capabilities object's mere presence advertises the whole feature
    family and would send a capability-gated client after e.g.
    ``resources/list`` on an upstream that never claimed resources. With an
    empty seed the union adds nothing (and the relay-side gate then
    swallows every listen notification — the documented degraded mode).
    Every other seeded key (and every other field of a unioned family) must
    survive untouched.

    #270 Phase 2 PR B unions ``subscribe: true`` onto ``resources`` under
    exactly the same rule — the RELAY implements ``resources/subscribe``
    now, backed by the dedicated resource listen stream — so an absent
    ``resources`` family still gets nothing at all."""
    expected = copy.deepcopy(caps)
    for key in ("tools", "resources", "prompts"):
        if key not in expected:
            continue
        entry = expected[key]
        if not isinstance(entry, dict):
            entry = {}
        entry["listChanged"] = True
        if key == "resources":
            entry["subscribe"] = True
        expected[key] = entry
    return expected


class TestHandleModernSpecialMethod:
    def test_initialize_is_synthesized_locally(self):
        state = _ModernState()
        state.server_info = {"name": "srv", "version": "9"}
        state.capabilities = {"tools": {}}
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {"experimental": {"caching": {}}},
                    "clientInfo": {"name": "test-client", "version": "1.0"},
                },
            }
        )
        handled, reply = _handle_modern_special_method(line, 1, state)
        assert handled is True
        result = json.loads(reply)["result"]
        assert result["serverInfo"] == {"name": "srv", "version": "9"}
        # C8 (#270 Phase 2 PR A): listChanged unioned onto the seeded set.
        assert result["capabilities"] == _with_list_changed({"tools": {}})
        # #352 round-3 finding 2: families absent from the discover seed
        # are NOT fabricated — their presence would advertise upstream
        # feature support discover never reported.
        assert "resources" not in result["capabilities"]
        assert "prompts" not in result["capabilities"]
        assert result["protocolVersion"] == "2026-07-28"
        # The client's own capabilities/clientInfo were captured for later
        # _meta injection.
        assert state.client_capabilities == {"experimental": {"caching": {}}}
        assert state.client_info == {"name": "test-client", "version": "1.0"}

    def test_initialize_without_client_capabilities_becomes_empty_dict(self):
        """: capabilities is REQUIRED in the modern _meta, so an absent
        client capabilities object must become {} (present, empty) — never
        left as None, which _inject_modern_meta would need to guard against."""
        state = _ModernState()
        line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        _handle_modern_special_method(line, 1, state)
        assert state.client_capabilities == {}

    def _capture(self, capabilities):
        state = _ModernState()
        _handle_modern_special_method(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2026-07-28",
                        "capabilities": capabilities,
                    },
                }
            ),
            1,
            state,
        )
        return state

    def test_mrtr_replaced_client_capabilities_are_advertised_after_the_bridge(self):
        """#270 Phase 2 PR C, the un-strip. #350 review round 10 (finding
        10-1) filtered sampling/elicitation/roots out of the upstream
        advertisement, because advertising a flow Phase 1 could not deliver
        invited exactly the ``input_required`` results it could only
        forward verbatim. PR C delivers the flow, so withholding the
        declaration now costs the user the feature for nothing: a
        compliant server may "only use capabilities that were successfully
        negotiated", and one told the client cannot elicit will refuse
        rather than ask.

        Only keys the client itself declared reach the wire — the captured
        set is a copy of its own object, never a fabrication."""
        state = self._capture(
            {
                "sampling": {},
                "elicitation": {},
                "roots": {"listChanged": True},
                "experimental": {"caching": {}},
                "tools": {"quirky": True},
            }
        )
        assert state.client_capabilities == {
            "sampling": {},
            "elicitation": {},
            "roots": {"listChanged": True},
            "experimental": {"caching": {}},
            "tools": {"quirky": True},
        }
        assert state.client_capabilities_declared == state.client_capabilities

    def test_mrtr_strip_env_restores_the_pre_bridge_advertisement(self, monkeypatch):
        """The kill-switch (#270 PR C, final commit): one environment
        variable puts round 10's filter back, so a COMPLIANT server is
        again told the client cannot do these flows and has no standing
        invitation to send MRTR. Other keys — ``experimental`` and anything
        unrecognized — must survive either way: they never mapped to an
        MRTR-replaced flow.

        The DECLARED set is unaffected, which is what keeps the bridge
        working for a non-compliant server that sends `input_required`
        anyway: the client really can answer it."""
        monkeypatch.setenv("MCP_STDIO_MRTR_STRIP", "1")
        state = self._capture(
            {
                "sampling": {},
                "elicitation": {},
                "roots": {"listChanged": True},
                "experimental": {"caching": {}},
                "tools": {"quirky": True},
            }
        )
        assert state.client_capabilities == {
            "experimental": {"caching": {}},
            "tools": {"quirky": True},
        }
        assert "elicitation" in state.client_capabilities_declared

    def test_mrtr_strip_env_ignores_falsey_and_empty_values(self, monkeypatch):
        """An unset, empty or explicitly-off value must leave the bridge's
        advertisement alone — an operator who exported the name without a
        value has not asked for the old behavior back."""
        for value in ("", "0", "false", "no", "off", "  "):
            monkeypatch.setenv("MCP_STDIO_MRTR_STRIP", value)
            assert (
                "elicitation" in self._capture({"elicitation": {}}).client_capabilities
            )
        monkeypatch.setenv("MCP_STDIO_MRTR_STRIP", "TRUE")
        assert self._capture({"elicitation": {}}).client_capabilities == {}

    def test_declared_client_capabilities_retained_unfiltered(self):
        """#270 PR C design change 2: the declaration is captured
        unfiltered, whatever the advertisement does with it. This is the
        only place the relay ever sees what the local client can actually
        do — the modern path never forwards the initialize — and the MRTR
        bridge needs it to decide whether a server-requested elicitation /
        sampling / roots round-trip may legitimately be minted onto
        stdout. Phase 1 discarded it, which is why the bridge could not
        exist before this slot did."""
        state = self._capture(
            {
                "elicitation": {"form": {}},
                "roots": {"listChanged": True},
                "experimental": {"caching": {}},
            }
        )
        assert state.client_capabilities_declared == {
            "elicitation": {"form": {}},
            "roots": {"listChanged": True},
            "experimental": {"caching": {}},
        }

    def test_declared_client_capabilities_is_a_copy_not_the_params_object(
        self, monkeypatch
    ):
        """The retained declaration must not alias the advertised set (nor
        the parsed params): under the kill-switch the two legitimately
        differ, and an alias would let one be mutated through the other."""
        monkeypatch.setenv("MCP_STDIO_MRTR_STRIP", "1")
        state = self._capture({"sampling": {}})
        assert state.client_capabilities_declared == {"sampling": {}}
        state.client_capabilities_declared["sampling"] = {"mutated": True}
        assert state.client_capabilities == {}

    def test_declared_client_capabilities_defaults_to_none(self):
        """No initialize seen yet means NOTHING was declared — distinct
        from "declared an empty set". The bridge treats both as "cannot
        mint", but the None default keeps the two distinguishable in
        logs."""
        assert _ModernState().client_capabilities_declared is None

    def test_server_capability_echo_unaffected_by_client_capability_filter(self):
        """#350 review round 10, finding 10-1 (the non-goal pinned): the
        filter applies to what the relay claims the CLIENT can do upstream,
        never to the SERVER capability set echoed downstream in the
        synthesized InitializeResult — a discover-seeded server set that
        happens to share a key name with the stripped client keys must
        reach the client intact."""
        state = _ModernState()
        state.capabilities = {"tools": {}, "elicitation": {}}
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {"roots": {}},
                },
            }
        )
        _, reply = _handle_modern_special_method(line, 1, state)
        result = json.loads(reply)["result"]
        # C8 (#270 Phase 2 PR A): the listChanged union applies on top of
        # the (unfiltered) server capability echo — elicitation survives.
        # #352 round-3 finding 2: only the PRESENT tools family is
        # unioned; resources/prompts are not fabricated.
        assert result["capabilities"] == _with_list_changed(
            {"tools": {}, "elicitation": {}}
        )
        assert "resources" not in result["capabilities"]
        assert "prompts" not in result["capabilities"]

    def test_initialize_without_client_info_stays_none(self):
        """: clientInfo is a SHOULD, never fabricated — absent from the
        client's initialize means state.client_info stays None (so
        _inject_modern_meta omits the key entirely, not sending a fake one)."""
        state = _ModernState()
        line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        _handle_modern_special_method(line, 1, state)
        assert state.client_info is None

    def test_serverinfo_fallback_when_discover_never_seeded_it_is_honest(self):
        """#350 review finding 2: a forced-modern startup probe that
        transiently fails (or returns a recognized-modern error with no
        result) leaves ``state.server_info`` at its default ``None`` —
        exactly the scenario the reviewer described. The synthesized
        InitializeResult must not silently claim the remote server's
        identity IS "mcp-stdio" (the #270 design says source serverInfo
        from real discover data "instead of inventing a placeholder"); the
        fallback name must say plainly that the real upstream identity is
        unknown."""
        state = _ModernState()
        assert state.server_info is None
        line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        _, reply = _handle_modern_special_method(line, 1, state)
        server_info = json.loads(reply)["result"]["serverInfo"]
        assert server_info["name"] != "mcp-stdio"
        assert "unknown" in server_info["name"].lower()

    def test_unseeded_discover_state_is_not_backfilled_from_client_initialize(self):
        """#350 review rounds 3 + 4: when discover seeded nothing, the fix
        (round 4) is a one-shot RE-PROBE of the server with the client's
        real capabilities (``discover_retry`` — see
        TestDiscoverReseedRetry), never a local fabrication. This pins the
        invariant that survives that fix: WITHOUT a ``discover_retry`` hook
        (as here), the client's own ``capabilities``/``clientInfo`` are
        captured into ``modern_state`` for later ``_meta`` injection
        (proven below) but are NEVER copied into
        ``server_info``/``capabilities`` — client capabilities are not
        server capabilities, and only a real ``server/discover`` response
        may seed those fields. A refactor that "fixes" the under-report by
        echoing client data back as server data would be strictly worse
        than the honest under-report and must fail here."""
        state = _ModernState()
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {"experimental": {"a": {}}, "tools": {}},
                    "clientInfo": {"name": "real-client", "version": "3.0"},
                },
            }
        )
        _, reply = _handle_modern_special_method(line, 1, state)
        result = json.loads(reply)["result"]
        # Under-reports: exactly empty capabilities (#352 round-3 finding
        # 2 narrowed the C8 union to families already present, so an empty
        # seed unions nothing), honest-unknown identity.
        assert result["capabilities"] == _with_list_changed({})
        assert "unknown" in result["serverInfo"]["name"].lower()
        # The real client data WAS captured (for _meta injection on later
        # requests) — it is simply never fed back into this synthesized
        # result, which is the documented limitation, not a missed capture.
        assert state.client_capabilities == {"experimental": {"a": {}}, "tools": {}}
        assert state.client_info == {"name": "real-client", "version": "3.0"}

    def test_synthesized_protocol_version_echoes_client_request_not_upstream(self):
        """#350 review round 3: a local client that only speaks legacy
        2025-06-18 must not be told the negotiated session is 2026-07-28
        just because that is the only version the modern-only upstream
        advertised in ``server/discover``. ``_negotiate_modern_version``
        picking from the advertised-and-implemented set is correct for
        what the RELAY sends
        UPSTREAM (headers / ``_meta`` — the remote genuinely only
        understands that version), but the synthesized ``InitializeResult``
        handed back DOWNSTREAM must acknowledge what the local client
        itself asked for, or a spec-conformant client that checks the
        returned ``protocolVersion`` against its own supported set will
        reject the handshake and disconnect. The two are now separate
        values: ``modern_state.negotiated_version`` (upstream) vs. the
        client's own ``requested`` string (downstream, echoed verbatim)."""
        state = _ModernState()
        state.supported_versions = ["2026-07-28"]
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
            }
        )
        _, reply = _handle_modern_special_method(line, 1, state)
        result = json.loads(reply)["result"]
        # Downstream: exactly what the local client asked for.
        assert result["protocolVersion"] == "2025-06-18"
        # Upstream: still the real negotiated version for headers/_meta —
        # unchanged from before this fix, and symmetrically correct for the
        # REVERSE mismatch too (client asks 2026-07-28, upstream only
        # advertises an older version): negotiated_version always reflects
        # what the remote actually supports, never the client's request.
        assert state.negotiated_version == "2026-07-28"

    def test_notifications_initialized_is_swallowed(self):
        state = _ModernState()
        line = '{"jsonrpc":"2.0","method":"notifications/initialized"}'
        handled, reply = _handle_modern_special_method(line, None, state)
        assert handled is True
        assert reply is None

    def test_listen_hooks_seed_on_initialize_start_on_initialized(self):
        """#352 review finding 1: the SEED hook (frozen C1 body snapshot)
        fires at initialize time — after negotiation, so the snapshot sees
        the negotiated version — but the START hook must NOT: the
        synthesized InitializeResult has not even been returned to run()'s
        loop yet, and the lifecycle spec (2025-06-18) says the server
        "SHOULD NOT send requests other than pings and logging before
        receiving the initialized notification". The START hook fires only
        on notifications/initialized — and never on the other swallowed
        notification, notifications/cancelled."""
        state = _ModernState()
        state.supported_versions = ["2026-07-28"]
        calls = []
        hooks = {
            "listen_seed": lambda: calls.append(("seed", state.negotiated_version)),
            "listen_start": lambda: calls.append(("start", None)),
        }
        init = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2026-07-28", "capabilities": {}},
            }
        )
        handled, reply = _handle_modern_special_method(init, 1, state, **hooks)
        assert handled is True
        assert reply is not None
        # Seeded (after negotiation), NOT started.
        assert calls == [("seed", "2026-07-28")]
        cancelled = (
            '{"jsonrpc":"2.0","method":"notifications/cancelled",'
            '"params":{"requestId":1}}'
        )
        handled, reply = _handle_modern_special_method(cancelled, None, state, **hooks)
        assert handled is True
        assert calls == [("seed", "2026-07-28")]  # still not started
        initialized = '{"jsonrpc":"2.0","method":"notifications/initialized"}'
        handled, reply = _handle_modern_special_method(
            initialized, None, state, **hooks
        )
        assert handled is True
        assert reply is None
        assert calls == [("seed", "2026-07-28"), ("start", None)]

    def test_notifications_cancelled_is_swallowed(self):
        state = _ModernState()
        line = (
            '{"jsonrpc":"2.0","method":"notifications/cancelled",'
            '"params":{"requestId":1}}'
        )
        handled, reply = _handle_modern_special_method(line, None, state)
        assert handled is True
        assert reply is None

    def test_ordinary_request_is_not_handled(self):
        state = _ModernState()
        line = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
        handled, reply = _handle_modern_special_method(line, 1, state)
        assert handled is False
        assert reply is None


class TestDiscoverReseedRetry:
    """#350 review round 4 finding 2: when the startup probe seeded nothing
    (e.g. the remote gated ``server/discover`` on a real client capability,
    ``-32021``), the synthesized InitializeResult's empty ``capabilities``
    is NOT cosmetic — lifecycle spec: both parties "MUST ... Only use
    capabilities that were successfully negotiated", so a compliant client
    told ``{}`` never issues tools/resources/prompts requests at all. The
    fix is a NARROW one-shot retry of discovery inside the initialize
    interception, once the client's real capabilities are known — zero
    cost on the common already-seeded path."""

    def _initialize_line(self, req_id=1, version="2025-06-18"):
        # A BRIDGEABLE capability: the MRTR-replaced keys (sampling/
        # elicitation/roots) are stripped at capture (#350 review round 10,
        # finding 10-1) and stripped-to-empty capabilities suppress the
        # reseed — see test_no_retry_when_client_caps_all_unbridgeable.
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": {"experimental": {"caching": {}}},
                    "clientInfo": {"name": "real-client", "version": "3.0"},
                },
            }
        )

    def test_retry_runs_once_and_seeds_the_synthesized_result(self):
        state = _ModernState()
        calls = []

        def retry():
            # By the time the retry hook runs, the client's REAL
            # capabilities/clientInfo must already be captured — that is
            # the whole point of retrying at this moment and not earlier.
            calls.append((dict(state.client_capabilities), dict(state.client_info)))
            state.server_info = {"name": "reseeded-srv", "version": "2"}
            state.capabilities = {"tools": {}}
            state.supported_versions = ["2026-07-28"]

        _, reply = _handle_modern_special_method(
            self._initialize_line(), 1, state, discover_retry=retry
        )
        assert calls == [
            (
                {"experimental": {"caching": {}}},
                {"name": "real-client", "version": "3.0"},
            )
        ]
        result = json.loads(reply)["result"]
        # The reseeded discover data feeds the synthesized result...
        assert result["serverInfo"] == {"name": "reseeded-srv", "version": "2"}
        # (...through the C8 listChanged union, #270 Phase 2 PR A.)
        assert result["capabilities"] == _with_list_changed({"tools": {}})
        # ...and negotiation runs AFTER the reseed: the client asked
        # 2025-06-18, the reseeded remote advertises only 2026-07-28, so
        # the upstream negotiated version is the remote's (while the
        # downstream ack still echoes the client's own request).
        assert state.negotiated_version == "2026-07-28"
        assert result["protocolVersion"] == "2025-06-18"

    def test_no_retry_when_capabilities_were_seeded_non_empty(self):
        """A non-empty capabilities seed means capability negotiation
        already answered — re-probing would add the every-session
        round-trip round 3 rightly rejected. (Round 4 suppressed the retry
        on ANY seeded field; round 9 finding 9-2 narrowed the guard to
        capabilities, the one field the startup probe's placeholder
        clientCapabilities: {} can plausibly distort — see the two
        retry-fires tests below for the flip side.)"""
        state = _ModernState()
        state.capabilities = {"tools": {}}
        calls = []
        _handle_modern_special_method(
            self._initialize_line(), 1, state, discover_retry=lambda: calls.append(1)
        )
        assert calls == []

    def test_retry_fires_when_identity_seeded_but_capabilities_empty(self):
        """#350 review round 9 finding 9-2 (the exact reported scenario):
        the startup probe seeded serverInfo + supportedVersions but the
        server returned capabilities filtered down to {} against the
        probe's placeholder clientCapabilities: {}. Round 4's all-empty
        condition suppressed the reseed, so the synthesized
        InitializeResult reported no tools/resources/prompts and a
        compliant client (lifecycle: "MUST ... Only use capabilities that
        were successfully negotiated") never attempted them. The reseed
        must fire, fill capabilities, and PRESERVE the seeded identity/
        version state when the reseed payload omits them
        (_seed_modern_state_from_discover never erases)."""
        state = _ModernState()
        state.server_info = {"name": "srv", "version": "1"}
        state.supported_versions = ["2026-07-28"]
        calls = []

        def retry():
            calls.append(1)
            _seed_modern_state_from_discover(
                state,
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "result": {
                        "resultType": "discover",
                        "capabilities": {"tools": {}},
                    },
                },
            )

        _, reply = _handle_modern_special_method(
            self._initialize_line(), 1, state, discover_retry=retry
        )
        assert calls == [1]
        result = json.loads(reply)["result"]
        # C8 listChanged union on top of the reseeded capabilities.
        assert result["capabilities"] == _with_list_changed({"tools": {}})
        # Identity seeded by the STARTUP probe survives a reseed payload
        # that only carried capabilities.
        assert result["serverInfo"] == {"name": "srv", "version": "1"}
        assert state.supported_versions == ["2026-07-28"]

    def test_retry_fires_when_versions_seeded_but_capabilities_empty(self):
        """Same round-9 trigger with only supportedVersions seeded: any
        seeded field used to suppress the retry, but identity/version
        metadata does not prove capability negotiation was complete."""
        state = _ModernState()
        state.supported_versions = ["2026-07-28"]
        calls = []
        _handle_modern_special_method(
            self._initialize_line(), 1, state, discover_retry=lambda: calls.append(1)
        )
        assert calls == [1]

    def test_no_retry_when_client_itself_has_no_capabilities(self):
        """#350 review round 9 finding 9-2, the other bound: the reseed's
        only new information is the client's REAL capabilities. A client
        whose own capabilities are {} would make the re-probe carry exactly
        the placeholder the startup probe already sent — it cannot change
        the outcome, so no retry fires (this also keeps the round-4
        -32021-gated path from burning its one latched attempt on a probe
        that is doomed to the same rejection)."""
        state = _ModernState()
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {},
                },
            }
        )
        calls = []
        _handle_modern_special_method(
            line, 1, state, discover_retry=lambda: calls.append(1)
        )
        assert calls == []
        # Not latched either: a later re-initialize that DOES carry real
        # capabilities may still use the one reseed attempt.
        assert state.discover_retry_attempted is False

    def test_reseed_follows_the_advertised_set_not_the_declared_one(self, monkeypatch):
        """Round 9's reseed condition reads the ADVERTISED set, because
        that is what a re-probe would actually carry — so it stays correct
        as that set's contents change.

        A client whose ONLY capabilities are the MRTR-replaced keys is the
        case that moved. While #350 round 10 stripped them it had nothing
        to advertise and the re-probe would have carried the same
        placeholder {} the startup probe already sent, so no retry fired.
        #270 PR C's un-strip gives it something real to advertise, so the
        retry now DOES fire — and setting the kill-switch restores the old
        reading verbatim, condition unchanged."""
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {
                        "sampling": {},
                        "elicitation": {},
                        "roots": {"listChanged": True},
                    },
                },
            }
        )
        state = _ModernState()
        calls = []
        _handle_modern_special_method(
            line, 1, state, discover_retry=lambda: calls.append(1)
        )
        assert calls == [1]
        assert state.discover_retry_attempted is True

        monkeypatch.setenv("MCP_STDIO_MRTR_STRIP", "1")
        stripped_state = _ModernState()
        stripped_calls = []
        _handle_modern_special_method(
            line, 1, stripped_state, discover_retry=lambda: stripped_calls.append(1)
        )
        assert stripped_calls == []
        assert stripped_state.client_capabilities == {}
        # The one latched attempt is preserved for a re-initialize that
        # carries a bridgeable capability.
        assert stripped_state.discover_retry_attempted is False

    def test_failed_retry_degrades_and_never_retries_again(self):
        """A retry that seeds nothing (the remote rejected discovery again)
        degrades to exactly the pre-retry behavior — honest-unknown
        serverInfo, empty capabilities — and the attempt is latched:
        a client-driven re-initialize must NOT probe a second time."""
        state = _ModernState()
        calls = []

        def failing_retry():
            calls.append(1)  # seeds nothing

        _, reply = _handle_modern_special_method(
            self._initialize_line(), 1, state, discover_retry=failing_retry
        )
        assert calls == [1]
        result = json.loads(reply)["result"]
        # Degraded to the empty seed — modulo the C8 listChanged union.
        assert result["capabilities"] == _with_list_changed({})
        assert "unknown" in result["serverInfo"]["name"].lower()
        # Re-initialize: still no second probe.
        _, _ = _handle_modern_special_method(
            self._initialize_line(req_id=2), 2, state, discover_retry=failing_retry
        )
        assert calls == [1]

    def test_no_hook_keeps_prior_behavior(self):
        """Without a discover_retry hook (default None) the RETRY behavior
        is identical to before round 4 — the unit-level contract the older
        tests in TestHandleModernSpecialMethod still pin. (The capability
        SHAPE carries the C8 listChanged union, #270 Phase 2 PR A, which
        is orthogonal to the retry hook.)"""
        state = _ModernState()
        _, reply = _handle_modern_special_method(self._initialize_line(), 1, state)
        result = json.loads(reply)["result"]
        assert result["capabilities"] == _with_list_changed({})
        assert state.discover_retry_attempted is False


class TestReseedDiscoverProbe:
    """Unit tests for the network half of the round-4 reseed retry."""

    URL = "https://example.com/mcp"

    def _state_with_client_data(self):
        # Captured state never contains the MRTR-replaced keys (they are
        # stripped at capture, #350 review round 10, finding 10-1), so
        # model a bridgeable capability here.
        state = _ModernState()
        state.client_capabilities = {"experimental": {"caching": {}}}
        state.client_info = {"name": "real-client", "version": "3.0"}
        return state

    def test_success_sends_real_client_meta_and_seeds_state(self, httpx_mock):
        httpx_mock.add_response(
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "result": {
                        "supportedVersions": ["2026-07-28"],
                        "capabilities": {"tools": {}},
                        "_meta": {
                            "io.modelcontextprotocol/serverInfo": {
                                "name": "gated-srv",
                                "version": "1",
                            }
                        },
                    },
                }
            ),
            headers={"content-type": "application/json"},
        )
        state = self._state_with_client_data()
        _reseed_discover_probe(httpx.Client(), self.URL, {}, state)
        req = httpx_mock.get_requests()[0]
        body = json.loads(req.content)
        assert body["method"] == "server/discover"
        meta = body["params"]["_meta"]
        # The re-probe advertises the client's REAL capabilities/info —
        # the whole reason it can succeed where the startup probe's {}
        # was rejected with -32021.
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {
            "experimental": {"caching": {}}
        }
        assert meta["io.modelcontextprotocol/clientInfo"] == {
            "name": "real-client",
            "version": "3.0",
        }
        # Header and _meta versions stay equal (HeaderMismatch guard).
        assert (
            req.headers["mcp-protocol-version"]
            == meta["io.modelcontextprotocol/protocolVersion"]
        )
        assert state.server_info == {"name": "gated-srv", "version": "1"}
        assert state.capabilities == {"tools": {}}
        assert state.supported_versions == ["2026-07-28"]

    def test_non_200_keeps_state_untouched(self, httpx_mock):
        httpx_mock.add_response(status_code=401, text="")
        state = self._state_with_client_data()
        _reseed_discover_probe(httpx.Client(), self.URL, {}, state)
        assert state.server_info is None
        assert state.capabilities == {}
        assert state.supported_versions == []

    def test_jsonrpc_error_body_keeps_state_untouched(self, httpx_mock):
        httpx_mock.add_response(
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "error": {"code": -32021, "message": "still gated"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        state = self._state_with_client_data()
        _reseed_discover_probe(httpx.Client(), self.URL, {}, state)
        assert state.server_info is None
        assert state.capabilities == {}

    def test_transport_error_is_swallowed(self, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        state = self._state_with_client_data()
        _reseed_discover_probe(httpx.Client(), self.URL, {}, state)  # no raise
        assert state.server_info is None

    def test_sse_result_on_open_stream_seeds_state_promptly(self, httpx_mock):
        """#350 review round 5 (finding 5-1): the reseed runs synchronously
        before the synthesized InitializeResult is emitted, so a discover
        result SSE-framed on a stream the server keeps open must seed the
        state as soon as the response event arrives — not stall the client's
        whole initialize until the read timeout. Post-yield raise = tripwire
        for buffered reads, as in TestProbeProtocolEra."""
        result_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "result": {"capabilities": {"tools": {}}},
            }
        )

        def open_stream():
            yield f"event: message\ndata: {result_body}\n\n".encode()
            raise AssertionError("reseed probe kept reading past the JSON-RPC response")

        httpx_mock.add_response(
            stream=IteratorStream(open_stream()),
            headers={"content-type": "text/event-stream"},
        )
        state = self._state_with_client_data()
        _reseed_discover_probe(httpx.Client(), self.URL, {}, state)
        assert state.capabilities == {"tools": {}}

    def test_401_with_auth_recovery_reprobes_and_seeds_real_capabilities(
        self, httpx_mock
    ):
        """#350 review round 8 (finding 8-2), the exact reported chain:
        startup discovery was gated (-32021, nothing seeded), the token
        expires before the local ``initialize``, and the one-shot reseed
        gets 401. Without recovery the reseed permanently synthesized empty
        capabilities — and a compliant client told ``capabilities: {}``
        issues no tools/resources/prompts requests, so normal dispatch
        recovery never even gets a request to repair the token with. The
        reseed must run the SAME bounded refresh recovery as the startup
        probe and seed REAL capabilities from the re-probe."""
        httpx_mock.add_response(status_code=401, text="")
        httpx_mock.add_response(
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "result": {"capabilities": {"tools": {}}},
                }
            ),
            headers={"content-type": "application/json"},
        )
        recovered = []

        def recovery(resp):
            recovered.append(resp.status_code)
            return {"Authorization": "Bearer fresh"}

        state = self._state_with_client_data()
        _reseed_discover_probe(
            httpx.Client(),
            self.URL,
            {"Authorization": "Bearer stale"},
            state,
            auth_recovery=recovery,
        )
        assert recovered == [401]
        assert state.capabilities == {"tools": {}}
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        assert requests[0].headers["authorization"] == "Bearer stale"
        assert requests[1].headers["authorization"] == "Bearer fresh"
        # The recovery RETRY still advertises the client's REAL
        # capabilities/info — the whole point of the reseed — because the
        # shared loop rebuilds the request with the same modern_state.
        meta = json.loads(requests[1].content)["params"]["_meta"]
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {
            "experimental": {"caching": {}}
        }
        assert meta["io.modelcontextprotocol/clientInfo"] == {
            "name": "real-client",
            "version": "3.0",
        }

    def test_401_recovery_declining_keeps_state_untouched_single_post(self, httpx_mock):
        """A recovery that returns None (refresh failed / no refresh_token)
        must degrade exactly like having no auth_recovery at all — one
        post, state untouched (round-3 documented under-report)."""
        httpx_mock.add_response(status_code=401, text="")
        state = self._state_with_client_data()
        _reseed_discover_probe(
            httpx.Client(), self.URL, {}, state, auth_recovery=lambda resp: None
        )
        assert state.server_info is None
        assert state.capabilities == {}
        assert len(httpx_mock.get_requests()) == 1

    def test_repeated_401_after_recovery_is_bounded_no_loop(self, httpx_mock):
        """The reseed inherits the probe's no-loop guarantee (#350 review
        rounds 4/6 via the shared ``_post_discover_with_recovery``): a
        re-probe that 401s AGAIN must not invoke recovery a second time —
        exactly two posts, recovery called once, state untouched."""
        httpx_mock.add_response(status_code=401, text="")
        httpx_mock.add_response(status_code=401, text="")
        recovered = []

        def recovery(resp):
            recovered.append(resp.status_code)
            return {"Authorization": "Bearer fresh"}

        state = self._state_with_client_data()
        _reseed_discover_probe(
            httpx.Client(), self.URL, {}, state, auth_recovery=recovery
        )
        assert recovered == [401]
        assert len(httpx_mock.get_requests()) == 2
        assert state.capabilities == {}

    def test_chained_401_then_403_recovery_seeds_state(self, httpx_mock):
        """Chained-challenge mirror of the startup probe's round-6 test:
        401 -> refresh, then the refreshed token 403s with
        insufficient_scope -> step-up, then 200. Each stage fires once
        (three posts, two recoveries) and the reseed still succeeds."""
        httpx_mock.add_response(status_code=401, text="")
        httpx_mock.add_response(
            status_code=403,
            text="",
            headers={
                "www-authenticate": (
                    'Bearer error="insufficient_scope", scope="mcp:tools"'
                )
            },
        )
        httpx_mock.add_response(
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "result": {"capabilities": {"tools": {}}},
                }
            ),
            headers={"content-type": "application/json"},
        )
        recovered = []

        def recovery(resp):
            recovered.append(resp.status_code)
            if resp.status_code == 401:
                return {"Authorization": "Bearer fresh"}
            return {"Authorization": "Bearer stepped-up"}

        state = self._state_with_client_data()
        _reseed_discover_probe(
            httpx.Client(), self.URL, {}, state, auth_recovery=recovery
        )
        assert recovered == [401, 403]
        assert len(httpx_mock.get_requests()) == 3
        assert state.capabilities == {"tools": {}}


class TestInjectModernMeta:
    def test_injects_required_fields(self):
        state = _ModernState()
        state.negotiated_version = "2026-07-28"
        # Captured state never contains the MRTR-replaced keys (stripped at
        # capture, #350 review round 10, finding 10-1) — model a bridgeable
        # capability. _inject_modern_meta itself forwards state verbatim.
        state.client_capabilities = {"experimental": {}}
        line = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
        injected = json.loads(_inject_modern_meta(line, state))
        meta = injected["params"]["_meta"]
        assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {
            "experimental": {}
        }
        assert "io.modelcontextprotocol/clientInfo" not in meta
        assert "io.modelcontextprotocol/logLevel" not in meta

    def test_injects_client_info_and_log_level_when_present(self):
        state = _ModernState()
        state.negotiated_version = "2026-07-28"
        state.client_capabilities = {}
        state.client_info = {"name": "c", "version": "1"}
        state.log_level = "debug"
        line = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}'
        injected = json.loads(_inject_modern_meta(line, state))
        meta = injected["params"]["_meta"]
        assert meta["io.modelcontextprotocol/clientInfo"] == {
            "name": "c",
            "version": "1",
        }
        assert meta["io.modelcontextprotocol/logLevel"] == "debug"

    def test_preserves_existing_meta_keys(self):
        state = _ModernState()
        state.negotiated_version = "2026-07-28"
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "x", "_meta": {"progressToken": "abc"}},
            }
        )
        injected = json.loads(_inject_modern_meta(line, state))
        meta = injected["params"]["_meta"]
        assert meta["progressToken"] == "abc"
        assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"

    def test_batch_is_returned_unchanged(self):
        state = _ModernState()
        line = "[]"
        assert _inject_modern_meta(line, state) == line

    def test_no_params_key_gets_one_created(self):
        state = _ModernState()
        state.negotiated_version = "2026-07-28"
        line = '{"jsonrpc":"2.0","id":1,"method":"ping"}'
        injected = json.loads(_inject_modern_meta(line, state))
        assert (
            injected["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"]
            == "2026-07-28"
        )


class TestRunModernEra:
    """Integration tests: run() dispatching on the modern (spec rev
    2026-07-28) path via --protocol-era modern/auto."""

    URL = "https://example.com/mcp"

    def _run_with_stdin(self, httpx_mock, stdin_lines, headers=None, **kwargs):
        stdin_data = "\n".join(stdin_lines) + "\n"
        stdout = StringIO()
        if headers is None:
            headers = {"Content-Type": "application/json"}
        with patch("sys.stdin", StringIO(stdin_data)), patch("sys.stdout", stdout):
            run(self.URL, headers, **kwargs)
        return stdout.getvalue()

    def _discover_response(self, **extra_result):
        result = {
            "resultType": "discover",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {"tools": {}},
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": "modern-srv",
                    "version": "1",
                }
            },
        }
        result.update(extra_result)
        return json.dumps({"jsonrpc": "2.0", "id": 0, "result": result})

    def _register_listen_stream(self, httpx_mock):
        """Absorb the background subscriptions/listen POST (#270 Phase 2 PR A).

        The listen thread starts on the client's
        ``notifications/initialized`` (#352 review finding 1) and races
        run()'s shutdown, so its POST may or may not fire before the stop
        event is observed — the response must be ``is_optional`` (a
        session whose stdin never sends ``initialized`` produces no listen
        POST at all, which the optional response also absorbs). It is
        registered FIRST, guarded by an Mcp-Method matcher, so the racy
        background POST can never steal a matcher-less response registered
        for the main dispatch flow (pytest-httpx matches in registration
        order). The graceful body — a result bearing the thread's first
        listen id — ends the stream with no reconnect, keeping the test
        hermetic. Every test whose stdin contains an ``initialize`` on a
        modern-resolving era must call this before its other responses and
        assert request counts via ``_non_listen_requests``.
        """
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "subscriptions/listen"},
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "mcp-stdio/listen/1",
                    "result": {"resultType": "complete"},
                }
            ),
            headers={"content-type": "application/json"},
            is_optional=True,
            is_reusable=True,
        )

    def _non_listen_requests(self, httpx_mock):
        """Recorded requests minus the racy background listen POST(s)."""
        return [
            r
            for r in httpx_mock.get_requests()
            if r.headers.get("mcp-method") != "subscriptions/listen"
        ]

    def test_forced_modern_initialize_is_synthesized_no_post(self, httpx_mock):
        """: forcing --protocol-era modern still runs ONE discover probe
        (to seed serverInfo), but the client's own `initialize` never reaches
        the network — it is answered locally and echoes the discovered
        serverInfo."""
        self._register_listen_stream(httpx_mock)
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2026-07-28",
                            "capabilities": {},
                        },
                    }
                )
            ],
            protocol_era="modern",
        )
        reply = json.loads(output.strip())
        assert reply["result"]["serverInfo"] == {"name": "modern-srv", "version": "1"}
        # Exactly one HTTP request beyond the background listen stream
        # (#270 Phase 2 PR A, filtered by _non_listen_requests): the
        # discover probe. initialize never hit the wire.
        requests = self._non_listen_requests(httpx_mock)
        assert len(requests) == 1
        assert json.loads(requests[0].content)["method"] == "server/discover"

    def test_legacy_client_initialize_ack_vs_upstream_version_diverge(self, httpx_mock):
        """#350 review round 3: a local client speaking only legacy
        2025-06-18 against a modern-only (2026-07-28) upstream must be told
        its OWN version was accepted (or it may reject the handshake and
        disconnect — AC unrelated to this repo's own AC#3, but a real
        client-side risk), while the wire traffic to the actual remote
        still uses the version the remote itself advertised. Drives a full
        initialize -> tools/list sequence through run() so both the
        downstream reply and the upstream POST are observed from the same
        session, proving the two values coexist without one leaking into
        the other (header/_meta mismatch on the upstream side would itself
        be a HeaderMismatch -32020 per AC#4)."""
        self._register_listen_stream(httpx_mock)
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(supportedVersions=["2026-07-28"]),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}',
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                        },
                    }
                ),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            ],
            protocol_era="modern",
        )
        lines = [line for line in output.strip().split("\n") if line]
        init_reply = json.loads(lines[0])
        # Downstream: the local client's own request is acknowledged.
        assert init_reply["result"]["protocolVersion"] == "2025-06-18"

        requests = self._non_listen_requests(httpx_mock)
        assert len(requests) == 2  # discover probe + tools/list
        list_req = requests[1]
        # Upstream: the header AND _meta both carry the version the remote
        # actually advertised — the two must always agree with each other
        # (a mismatch is HeaderMismatch -32020), and neither is the
        # client's stale 2025-06-18 ask.
        assert list_req.headers["mcp-protocol-version"] == "2026-07-28"
        meta = json.loads(list_req.content)["params"]["_meta"]
        assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"

    def test_notifications_initialized_produces_no_post_no_reply(self, httpx_mock):
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            ['{"jsonrpc":"2.0","method":"notifications/initialized"}'],
            protocol_era="modern",
        )
        assert output.strip() == ""
        assert len(httpx_mock.get_requests()) == 1  # only the discover probe

    def test_tools_call_carries_mcp_method_name_and_meta_no_session(self, httpx_mock):
        """: on the modern path every POST carries Mcp-Method/Mcp-Name and
        MCP-Protocol-Version headers plus the _meta block, and NEVER
        Mcp-Session-Id — sessions do not exist on this path."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{}}',
            headers={
                "content-type": "application/json",
                # A non-compliant/legacy-ish echo — must NOT be adopted.
                "mcp-session-id": "should-be-ignored",
            },
        )
        self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "echo", "arguments": {}},
                    }
                )
            ],
            protocol_era="modern",
        )
        requests = httpx_mock.get_requests()
        assert len(requests) == 2  # discover probe + the tools/call
        call_req = requests[1]
        assert call_req.headers["mcp-method"] == "tools/call"
        assert call_req.headers["mcp-name"] == "echo"
        assert call_req.headers["mcp-protocol-version"] == "2026-07-28"
        assert "mcp-session-id" not in call_req.headers
        body = json.loads(call_req.content)
        meta = body["params"]["_meta"]
        assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {}

    def test_pinned_mcp_name_does_not_leak_onto_tools_list(self, httpx_mock):
        """#350 review finding 3: an operator-pinned ``-H 'Mcp-Name: ...'``
        must not survive on a request that derives no Mcp-Name of its own —
        ``tools/list`` has no ``params.name`` to mirror. The old code only
        stripped the operator's case-variant when THIS request supplied a
        replacement value, so a pinned value rode along unchanged on
        tools/list: a header/body mismatch (Streamable HTTP "Server
        Validation": "Parameter not in arguments -> Client MUST omit the
        header") a strict server rejects with HeaderMismatch."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{}}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})],
            headers={
                "Content-Type": "application/json",
                "Mcp-Name": "operator-pinned",
            },
            protocol_era="modern",
        )
        call_req = httpx_mock.get_requests()[1]
        assert "mcp-name" not in call_req.headers

    def test_pinned_mcp_method_does_not_leak_onto_batch_line(self, httpx_mock):
        """#350 review finding 3: a batch (top-level array) line has no
        single ``method`` to mirror (``_mcp_request_headers`` returns
        ``{}`` for it), so the OLD code never stripped an operator-pinned
        ``Mcp-Method`` for it either — a stale pinned method header would
        ride along on a methodless payload."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text="[]",
            headers={"content-type": "application/json"},
        )
        batch_line = json.dumps(
            [{"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}]
        )
        self._run_with_stdin(
            httpx_mock,
            [batch_line],
            headers={
                "Content-Type": "application/json",
                "Mcp-Method": "operator-pinned",
            },
            protocol_era="modern",
        )
        call_req = httpx_mock.get_requests()[1]
        assert "mcp-method" not in call_req.headers

    def test_second_request_still_omits_session_id_after_echoed_header(
        self, httpx_mock
    ):
        """: even after a response ECHOES mcp-session-id, the NEXT modern
        request must still omit it — session adoption is fully disabled on
        this path, not just skipped once."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{}}',
            headers={"content-type": "application/json", "mcp-session-id": "sneaky"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":3,"result":{}}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            ],
            protocol_era="modern",
        )
        requests = httpx_mock.get_requests()
        assert len(requests) == 3  # discover + 2 tools/list
        assert "mcp-session-id" not in requests[2].headers

    def test_client_info_forwarded_when_client_provided_it(self, httpx_mock):
        self._register_listen_stream(httpx_mock)
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{}}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2026-07-28",
                            "capabilities": {},
                            "clientInfo": {"name": "my-client", "version": "3"},
                        },
                    }
                ),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            ],
            protocol_era="modern",
        )
        # requests[0] is the discover probe; the client's own `initialize`
        # is intercepted locally and never dispatched (see
        # test_forced_modern_initialize_is_synthesized_no_post), so the
        # tools/list is requests[1] (background listen POSTs filtered out).
        call_req = self._non_listen_requests(httpx_mock)[1]
        meta = json.loads(call_req.content)["params"]["_meta"]
        assert meta["io.modelcontextprotocol/clientInfo"] == {
            "name": "my-client",
            "version": "3",
        }

    def test_client_info_omitted_when_client_never_sent_one(self, httpx_mock):
        """: clientInfo is SHOULD, never fabricated. No initialize with a
        clientInfo was ever sent -> the key must be entirely absent, not a
        placeholder."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{}}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})],
            protocol_era="modern",
        )
        call_req = httpx_mock.get_requests()[1]
        meta = json.loads(call_req.content)["params"]["_meta"]
        assert "io.modelcontextprotocol/clientInfo" not in meta

    def test_cancelled_notification_not_forwarded_upstream(self, httpx_mock):
        """: acceptance criterion #5 (part a — the "don't forward" half).
        On the modern path notifications/cancelled must NOT be POSTed
        upstream at all (the modern cancellation signal is closing the
        response stream, not a forwarded JSON-RPC notification)."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": {"requestId": 5},
                    }
                )
            ],
            protocol_era="modern",
        )
        assert output.strip() == ""
        # Only the discover probe — the cancel notification never hit the wire.
        assert len(httpx_mock.get_requests()) == 1

    def test_log_level_mirrored_into_meta_after_set_level(self, httpx_mock):
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":5,"result":{}}',
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":6,"result":{}}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "logging/setLevel",
                        "params": {"level": "debug"},
                    }
                ),
                json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/list"}),
            ],
            protocol_era="modern",
        )
        requests = httpx_mock.get_requests()
        # The setLevel request itself IS forwarded (it's an ordinary request
        # on the modern path, not one of the three intercepted methods) and
        # carries logLevel too (set before dispatch in the loop).
        set_level_meta = json.loads(requests[1].content)["params"]["_meta"]
        assert set_level_meta["io.modelcontextprotocol/logLevel"] == "debug"
        list_meta = json.loads(requests[2].content)["params"]["_meta"]
        assert list_meta["io.modelcontextprotocol/logLevel"] == "debug"

    def test_cold_start_disabled_on_modern_era(self, httpx_mock, capsys):
        """: --oauth-eager cold-start is disabled (with a warning) when the
        era resolves to modern — _reinitialize's legacy handshake is
        meaningless without sessions. A `ping` sent immediately must NOT get
        the cold-start's locally-synthesized empty result (that synthesis is
        legacy-only) — it is forwarded upstream like any other request."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":9,"result":{"upstream":true}}',
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"})],
            protocol_era="modern",
            cold_start_login=lambda: {"Authorization": "Bearer x"},
        )
        assert "cold-start" in capsys.readouterr().err
        reply = json.loads(output.strip())
        # This is the UPSTREAM's reply (forwarded, not the cold-start local
        # synthesis `{"result": {}}` with no "upstream" key).
        assert reply["result"] == {"upstream": True}

    def test_auto_detects_modern_and_dispatches_modern_path(self, httpx_mock):
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{}}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})],
            protocol_era="auto",
        )
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        assert requests[1].headers["mcp-method"] == "tools/list"

    def test_auto_detects_legacy_and_dispatches_legacy_path(self, httpx_mock):
        """: auto-detection against a legacy remote (discover 404s) must
        fall through to the ordinary initialize/session-tracking dispatch —
        no Mcp-Method header, session id adopted normally."""
        httpx_mock.add_response(url=self.URL, status_code=404, text="")
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}',
            headers={
                "content-type": "application/json",
                "mcp-session-id": "legacy-sess",
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"})],
            protocol_era="auto",
        )
        assert json.loads(output.strip())["id"] == 1
        requests = httpx_mock.get_requests()
        assert len(requests) == 2  # discover probe (404) + real initialize
        assert "mcp-method" not in requests[1].headers
        assert (
            "mcp-session-id" not in requests[1].headers
        )  # not yet adopted (this IS the initialize)

    def test_auto_401_probe_refreshes_token_and_detects_modern(self, httpx_mock):
        """#350 review round 4 finding 3: an expired cached OAuth token
        makes a modern-only server 401 the era probe before it ever
        inspects server/discover. auto mode must run the SAME token
        refresh the dispatch path would, re-probe once, and classify the
        server by its actual answer — not permanently latch legacy off an
        authentication challenge (which would make every later request a
        legacy `initialize` the modern remote rejects)."""
        httpx_mock.add_response(url=self.URL, status_code=401, text="")
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{}}',
            headers={"content-type": "application/json"},
        )
        refresh_calls = []

        def refresher():
            refresh_calls.append(True)
            return {"Authorization": "Bearer fresh"}

        self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})],
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer stale",
            },
            protocol_era="auto",
            token_refresher=refresher,
        )
        assert refresh_calls == [True]
        requests = httpx_mock.get_requests()
        assert len(requests) == 3  # 401 probe + refreshed probe + tools/list
        assert requests[1].headers["authorization"] == "Bearer fresh"
        # Era resolved MODERN: the real request rides the modern path...
        assert requests[2].headers["mcp-method"] == "tools/list"
        # ...and the refreshed credentials persist for the whole session
        # (merged into the shared headers, not just the probe retry).
        assert requests[2].headers["authorization"] == "Bearer fresh"

    def test_auto_401_probe_without_refresher_stays_legacy(self, httpx_mock):
        """No token_refresher configured (no OAuth): a 401 probe keeps
        today's conservative legacy fallback — the workaround for a
        modern-only server behind auth is --protocol-era modern (see
        _probe_protocol_era's log line)."""
        httpx_mock.add_response(url=self.URL, status_code=401, text="")
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"})],
            protocol_era="auto",
        )
        requests = httpx_mock.get_requests()
        assert len(requests) == 2  # one probe only, then the legacy dispatch
        # Legacy path: the client's initialize is forwarded raw, no modern
        # headers.
        assert json.loads(requests[1].content)["method"] == "initialize"
        assert "mcp-method" not in requests[1].headers

    def test_probe_403_step_up_serialized_with_refresh_lock(self, httpx_mock):
        """#350 review round 10, finding 10-2: _probe_auth_recovery's 401
        branch takes run()'s internal refresh_lock around token_refresher,
        but the 403 branch invoked scope_upgrader bare. The same callback
        serves the post-initialize discover reseed, when the
        proactive-refresh daemon may already be live — an unserialised
        step-up can race the timer's rotation (refresh fails mid-rotation,
        or an old-scope refreshed token overwrites the just-upgraded
        credentials in the shared headers). Both stages must hold the SAME
        lock. The lock is internal to run(), so this test instruments lock
        creation (precedent: patching mcp_stdio.relay.sys/time elsewhere in
        this file): a chained 401 -> 403 probe records which instrumented
        locks are held inside each fake — the refresher's held set is
        refresh_lock by construction (round 8), and the upgrader must
        observe exactly the same held lock. Removing the fix makes the
        upgrader observe none."""
        created_locks = []
        real_lock = threading.Lock

        def recording_lock():
            lock = real_lock()
            created_locks.append(lock)
            return lock

        held = {}

        def refresher():
            held["refresh"] = [id(x) for x in created_locks if x.locked()]
            return {"Authorization": "Bearer refreshed"}

        def upgrader(scope):
            assert scope == "mcp:admin"
            held["step_up"] = [id(x) for x in created_locks if x.locked()]
            return {"Authorization": "Bearer stepped-up"}

        httpx_mock.add_response(url=self.URL, status_code=401, text="")
        httpx_mock.add_response(
            url=self.URL,
            status_code=403,
            text="",
            headers={
                "www-authenticate": (
                    'Bearer error="insufficient_scope", scope="mcp:admin"'
                )
            },
        )
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        with patch("mcp_stdio.relay.threading.Lock", recording_lock):
            self._run_with_stdin(
                httpx_mock,
                [],
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer stale",
                },
                protocol_era="auto",
                token_refresher=refresher,
                scope_upgrader=upgrader,
            )
        # Each stage ran under exactly one held instrumented lock — and the
        # SAME one: the 403 step-up serialises against the proactive
        # refresh through the identical refresh_lock the 401 branch uses.
        assert len(held["refresh"]) == 1
        assert held["step_up"] == held["refresh"]
        # The chained recovery actually completed: three probes, the last
        # with the stepped-up credentials, classified modern.
        requests = httpx_mock.get_requests()
        assert len(requests) == 3
        assert requests[2].headers["authorization"] == "Bearer stepped-up"

    def test_capability_gated_discover_reseeded_once_with_real_capabilities(
        self, httpx_mock
    ):
        """#350 review round 4 finding 2, end-to-end: the startup probe is
        rejected with -32021 (recognized-modern -> era modern, but nothing
        seeded); the local client's initialize then triggers exactly ONE
        discover re-probe carrying the client's REAL
        capabilities/clientInfo, whose result seeds the synthesized
        InitializeResult — so a spec-compliant client (lifecycle: "MUST
        ... Only use capabilities that were successfully negotiated") sees
        the remote's real capabilities instead of {} and actually issues
        tools/resources/prompts requests."""
        self._register_listen_stream(httpx_mock)
        httpx_mock.add_response(
            url=self.URL,
            status_code=400,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "error": {"code": -32021, "message": "missing capability"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2026-07-28",
                            "capabilities": {"experimental": {"caching": {}}},
                            "clientInfo": {"name": "real-client", "version": "3.0"},
                        },
                    }
                )
            ],
            protocol_era="auto",
        )
        reply = json.loads(output.strip())
        # The re-probe's discover data feeds the synthesized result
        # (through the C8 listChanged union, #270 Phase 2 PR A).
        assert reply["result"]["serverInfo"] == {"name": "modern-srv", "version": "1"}
        assert reply["result"]["capabilities"] == _with_list_changed({"tools": {}})
        requests = self._non_listen_requests(httpx_mock)
        assert len(requests) == 2  # startup probe + ONE reseed re-probe
        reseed_body = json.loads(requests[1].content)
        assert reseed_body["method"] == "server/discover"
        meta = reseed_body["params"]["_meta"]
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {
            "experimental": {"caching": {}}
        }
        assert meta["io.modelcontextprotocol/clientInfo"] == {
            "name": "real-client",
            "version": "3.0",
        }

    def test_reseed_retry_failing_again_degrades_and_never_probes_again(
        self, httpx_mock
    ):
        """Round-4 retry failure path: the re-probe is ALSO rejected with
        -32021 — the synthesized result degrades to exactly the round-3
        documented under-report (empty capabilities, honest-unknown
        serverInfo), and a second client initialize does NOT probe a third
        time (the attempt is latched)."""
        self._register_listen_stream(httpx_mock)
        gated = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "error": {"code": -32021, "message": "missing capability"},
            }
        )
        httpx_mock.add_response(
            url=self.URL,
            status_code=400,
            text=gated,
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            status_code=400,
            text=gated,
            headers={"content-type": "application/json"},
        )
        init_line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {"experimental": {"caching": {}}},
                },
            }
        )
        reinit_line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {"experimental": {"caching": {}}},
                },
            }
        )
        output = self._run_with_stdin(
            httpx_mock, [init_line, reinit_line], protocol_era="auto"
        )
        lines = [json.loads(line) for line in output.strip().split("\n") if line]
        assert len(lines) == 2
        for reply in lines:
            # Degraded empty seed, modulo the C8 listChanged union.
            assert reply["result"]["capabilities"] == _with_list_changed({})
            assert "unknown" in reply["result"]["serverInfo"]["name"].lower()
        # startup probe + ONE reseed attempt — the second initialize did
        # not trigger a third (and no second listen thread either: the
        # listen hook is latched one-shot, so at most one background POST,
        # filtered out here).
        assert len(self._non_listen_requests(httpx_mock)) == 2

    def test_client_capabilities_reach_upstream_meta_unfiltered(self, httpx_mock):
        """#270 Phase 2 PR C's un-strip, end-to-end: the client declares
        sampling/elicitation/roots alongside other capabilities, and every
        upstream advertisement — the reseed re-probe's ``_meta`` AND each
        ordinary request's ``_meta`` — carries them, because the relay now
        bridges the MRTR results they invite. #350 review round 10 filtered
        them out while Phase 1 could only forward such a result verbatim;
        with a compliant server allowed to "only use capabilities that were
        successfully negotiated", withholding them now would simply lose
        the feature. The SERVER capability set echoed downstream stays
        intact either way — the advertisement decision is about what the
        relay claims the CLIENT can do."""
        self._register_listen_stream(httpx_mock)
        httpx_mock.add_response(
            url=self.URL,
            status_code=400,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "error": {"code": -32021, "message": "missing capability"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{}}',
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2026-07-28",
                            "capabilities": {
                                "sampling": {},
                                "elicitation": {},
                                "roots": {"listChanged": True},
                                "experimental": {"caching": {}},
                                "tools": {"quirky": True},
                            },
                        },
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "echo", "arguments": {}},
                    }
                ),
            ],
            protocol_era="auto",
        )
        expected_caps = {
            "sampling": {},
            "elicitation": {},
            "roots": {"listChanged": True},
            "experimental": {"caching": {}},
            "tools": {"quirky": True},
        }
        requests = self._non_listen_requests(httpx_mock)
        assert len(requests) == 3  # startup probe + reseed + tools/call
        reseed_meta = json.loads(requests[1].content)["params"]["_meta"]
        assert (
            reseed_meta["io.modelcontextprotocol/clientCapabilities"] == expected_caps
        )
        call_meta = json.loads(requests[2].content)["params"]["_meta"]
        assert call_meta["io.modelcontextprotocol/clientCapabilities"] == expected_caps
        # The synthesized InitializeResult echoes the SERVER's discover-
        # seeded capabilities untouched — the filter never applies there
        # (the C8 listChanged union does, #270 Phase 2 PR A).
        reply = json.loads(output.strip().split("\n")[0])
        assert reply["result"]["capabilities"] == _with_list_changed({"tools": {}})

    def test_mrtr_strip_env_restores_the_stripped_advertisement_end_to_end(
        self, httpx_mock, monkeypatch
    ):
        """The kill-switch end to end (#270 PR C, final commit). With
        ``MCP_STDIO_MRTR_STRIP`` set, a client declaring ONLY the
        MRTR-replaced keys has nothing this relay may advertise: the
        reseed re-probe (which exists to advertise the client's REAL
        capabilities) must not fire — it would carry exactly the
        placeholder {} the -32021-gated startup probe already sent — and
        subsequent requests advertise clientCapabilities: {}. This is
        verbatim #350 round 10's behavior, restored by one environment
        variable."""
        monkeypatch.setenv("MCP_STDIO_MRTR_STRIP", "1")
        self._register_listen_stream(httpx_mock)
        httpx_mock.add_response(
            url=self.URL,
            status_code=400,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "error": {"code": -32021, "message": "missing capability"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{}}',
            headers={"content-type": "application/json"},
        )
        self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2026-07-28",
                            "capabilities": {
                                "sampling": {},
                                "elicitation": {},
                                "roots": {},
                            },
                        },
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/list",
                    }
                ),
            ],
            protocol_era="auto",
        )
        requests = self._non_listen_requests(httpx_mock)
        # Startup probe + tools/list — NO reseed re-probe in between.
        assert len(requests) == 2
        call_meta = json.loads(requests[1].content)["params"]["_meta"]
        assert call_meta["io.modelcontextprotocol/clientCapabilities"] == {}

    def test_additive_2026_result_shape_forwarded_verbatim_to_2025_client(
        self, httpx_mock
    ):
        """#350 review round 4 finding 1, characterization of the KEPT
        (rounds 3+4) version-echo decision: for the request types a stdio
        client itself sends, spec rev 2026-07-28 changes result shapes
        only ADDITIVELY (required resultType discriminator, _meta-nested
        serverInfo) — this relay forwards them byte-identically and a 2025
        client ignores the unknown extra fields (MCP result objects are
        open/extensible). This is why echoing the client's own requested
        version is honest: no wire shape it cannot parse is created by the
        version divergence on these flows."""
        self._register_listen_stream(httpx_mock)
        upstream_result = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "resultType": "tools/call",
                    "content": [{"type": "text", "text": "hi"}],
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {
                            "name": "modern-srv",
                            "version": "1",
                        }
                    },
                },
            }
        )
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=upstream_result,
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                        },
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "echo", "arguments": {}},
                    }
                ),
            ],
            protocol_era="modern",
        )
        lines = [line for line in output.strip().split("\n") if line]
        # The 2026-shaped result reaches the 2025 client byte-identically —
        # the relay never version-translates bodies in either direction.
        assert lines[1] == upstream_result

    def test_mrtr_unbridgeable_input_required_is_cleanly_rejected(self, httpx_mock):
        """#270 Phase 2 PR C, commit 1 — THE FLIP of Phase 1's
        characterization test (which pinned the verbatim forward and said
        in so many words "so Phase 2 has a test to flip").

        An InputRequiredResult the bridge cannot carry — here the client
        never sent an `initialize` at all, so it declared NO capabilities
        and MRTR server requirement 7 ("Servers MUST NOT send an
        inputRequests that the client has not declared support for in its
        capabilities") is violated outright — must reach the client as a
        clean JSON-RPC error under its OWN id, never as the 2026 result
        shape a 2025 client misreads as an oddly-shaped success. -32600
        Invalid Request: the fault is in the server's message. This branch
        is the PERMANENT fallback for every unbridgeable MRTR shape, not a
        stepping stone."""
        mrtr_result = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "resultType": "input_required",
                    "inputRequests": {
                        "q1": {
                            "method": "elicitation/create",
                            "params": {"message": "confirm?"},
                        }
                    },
                },
            }
        )
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=mrtr_result,
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "needs-input", "arguments": {}},
                    }
                )
            ],
            protocol_era="modern",
        )
        lines = [line for line in output.strip().split("\n") if line]
        # EXACTLY one response for the one request — the swallowed
        # input_required must not also trigger the "empty response from
        # server" synthesis (_post_and_stream's emitted=False guard).
        assert len(lines) == 1
        reply = json.loads(lines[0])
        assert reply["id"] == 2
        assert reply["error"]["code"] == -32600
        assert "MRTR" in reply["error"]["message"]
        assert "resultType" not in lines[0]

    def test_non_ascii_method_rejected_with_jsonrpc_error_not_crash(self, httpx_mock):
        """#350 review round 5 (finding 5-2): JSON-RPC permits ANY string as
        `method`, but the modern path mirrors it into the REQUIRED
        Mcp-Method header (Streamable HTTP, "Standard Request Headers"),
        and the Base64 sentinel escape is spec-defined only for Mcp-Name /
        Mcp-Param-{Name} — never Mcp-Method ("Server Validation" requires
        decoding exactly those two before comparing). A non-ASCII method
        therefore cannot be sent compliantly at all; unguarded, httpx
        raises UnicodeEncodeError at request construction, which the
        per-line safety net degrades to an opaque "internal relay error".
        The relay must instead reject it with a descriptive JSON-RPC error
        and never POST it upstream."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {"jsonrpc": "2.0", "id": 7, "method": "例/tools", "params": {}}
                )
            ],
            protocol_era="modern",
        )
        reply = json.loads(output.strip())
        assert reply["id"] == 7
        assert "Mcp-Method" in reply["error"]["message"]
        # Exactly one HTTP request total: the discover probe. The unsendable
        # request never reached the wire.
        assert len(httpx_mock.get_requests()) == 1

    def test_control_character_method_rejected_with_jsonrpc_error(self, httpx_mock):
        """#350 review round 5 (finding 5-2), control-character variant: a
        CR in the method would be rejected by h11 only at send time (after
        the relay's own retry loop burned its attempts), and other C0
        controls pass httpx/h11 validation onto the wire verbatim — both
        violate RFC 9110 field-value syntax (the "Value Encoding" section's
        stated baseline). Rejected locally, before any POST."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 8,
                        "method": "tools\rlist",
                        "params": {},
                    }
                )
            ],
            protocol_era="modern",
        )
        reply = json.loads(output.strip())
        assert reply["id"] == 8
        assert "Mcp-Method" in reply["error"]["message"]
        assert len(httpx_mock.get_requests()) == 1

    def test_unsafe_method_notification_dropped_silently(self, httpx_mock, capsys):
        """A NOTIFICATION with an unsendable method must never receive a
        synthesized response (no JSON-RPC id — same gating as every other
        synthesized error in run()) and must not be POSTed either: silent
        drop, with the DESCRIPTIVE rejection logged to stderr — not the
        pre-fix path of httpx's UnicodeEncodeError tripping the per-line
        safety net's generic "internal relay error"."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [json.dumps({"jsonrpc": "2.0", "method": "例/notify", "params": {}})],
            protocol_era="modern",
        )
        assert output.strip() == ""
        assert len(httpx_mock.get_requests()) == 1
        err = capsys.readouterr().err
        assert "header-safe" in err
        assert "internal relay error" not in err

    def test_listen_post_body_and_headers_deterministic(self, httpx_mock):
        """#270 Phase 2 PR A, end-to-end wire shape: the relay ORIGINATES
        subscriptions/listen once the client's notifications/initialized
        lands (#352 review finding 1 — the stdin below therefore sends
        initialized after initialize, exactly like a lifecycle-compliant
        client; the body snapshot was frozen at initialize time). Made
        deterministic without sleeps: a response callback flags the listen
        POST and a generator-backed stdin holds run() open until it fired.
        Pins the C1 snapshot rules (no logLevel although one was set
        BEFORE the stream opened; _meta INSIDE params) and the spec item 4
        headers (dual Accept, Mcp-Method, protocolVersion byte-matching
        the MCP-Protocol-Version header, no Mcp-Name, no session id)."""
        listen_posted = threading.Event()

        def listen_callback(request):
            listen_posted.set()
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": "mcp-stdio/listen/1",
                    "result": {"resultType": "complete"},
                },
            )

        httpx_mock.add_callback(
            listen_callback,
            url=self.URL,
            match_headers={"Mcp-Method": "subscriptions/listen"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":1,"result":{}}',
            headers={"content-type": "application/json"},
        )
        set_level = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "logging/setLevel",
                "params": {"level": "debug"},
            }
        )
        init = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {"experimental": {}},
                    "clientInfo": {"name": "c", "version": "1"},
                },
            }
        )

        initialized = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )

        def stdin_lines():
            yield set_level + "\n"
            yield init + "\n"
            # The thread starts only on notifications/initialized (#352
            # review finding 1) — a lifecycle-compliant client sends it
            # right after consuming the InitializeResult.
            yield initialized + "\n"
            # Hold stdin open until the background listen POST has fired,
            # so run()'s shutdown cannot win the race (event-driven wait).
            assert listen_posted.wait(timeout=5)

        with patch("sys.stdin", stdin_lines()), patch("sys.stdout", StringIO()):
            run(self.URL, {"Content-Type": "application/json"}, protocol_era="modern")

        listen_reqs = [
            r
            for r in httpx_mock.get_requests()
            if r.headers.get("mcp-method") == "subscriptions/listen"
        ]
        assert len(listen_reqs) == 1
        req = listen_reqs[0]
        body = json.loads(req.content)
        assert body["id"] == "mcp-stdio/listen/1"
        assert body["method"] == "subscriptions/listen"
        params = body["params"]
        assert params["notifications"] == {
            "toolsListChanged": True,
            "promptsListChanged": True,
            "resourcesListChanged": True,
        }
        assert "resourceSubscriptions" not in params
        meta = params["_meta"]
        # Byte-match: the _meta version IS the header value.
        assert (
            meta["io.modelcontextprotocol/protocolVersion"]
            == req.headers["mcp-protocol-version"]
        )
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {
            "experimental": {}
        }
        assert meta["io.modelcontextprotocol/clientInfo"] == {
            "name": "c",
            "version": "1",
        }
        # logging/setLevel ran BEFORE the stream opened, yet the frozen
        # body never carries logLevel (C1).
        assert "io.modelcontextprotocol/logLevel" not in meta
        assert req.headers["accept"] == "application/json, text/event-stream"
        assert "mcp-name" not in req.headers
        assert "mcp-session-id" not in req.headers

    def test_run_seeds_advertised_families_into_listen_state(self, httpx_mock):
        """#352 round-3 finding 2: run()'s _seed_listen_snapshot freezes
        the advertised-family set — derived from the discover-seeded
        capabilities by the SAME helper the InitializeResult synthesis
        uses — into the state carrier handed to the listen thread, so the
        forwarding gate matches the advertisement. Discover seeds
        {"tools": {}} → exactly {"tools"} reaches the thread; without the
        seeding, the gate would fall back to permissive forwarding and
        the narrowing would hold only in unit tests."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        seen = {}
        exited = threading.Event()

        def stub_loop(**kwargs):
            seen["state"] = kwargs["state"]
            exited.set()

        with patch("mcp_stdio.relay._listen_stream_loop", stub_loop):
            self._run_with_stdin(
                httpx_mock,
                [
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2026-07-28",
                                "capabilities": {},
                            },
                        }
                    ),
                    json.dumps(
                        {"jsonrpc": "2.0", "method": "notifications/initialized"}
                    ),
                ],
                protocol_era="modern",
            )
        assert exited.wait(timeout=5)
        assert seen["state"]["advertised"] == frozenset({"tools"})

    def test_legacy_era_never_opens_listen_stream(self, httpx_mock):
        """AC 3 (#270): the legacy era has NO listen call site — a full
        initialize + notifications/initialized handshake (the stdin covers
        BOTH hook sites now that #352 review finding 1 moved the thread
        start to initialized) produces zero subscriptions/listen POSTs and
        the forwarded wire stays the legacy shape (no Mcp-Method header at
        all; initialized is FORWARDED upstream, never swallowed).
        Deterministic without filtering: the thread is never created, so
        no racy background POST can exist."""
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}',
            headers={"content-type": "application/json"},
        )
        # The forwarded notifications/initialized -> 202, no body.
        httpx_mock.add_response(url=self.URL, status_code=202, text="")
        self._run_with_stdin(
            httpx_mock,
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                        },
                    }
                ),
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            ],
            protocol_era="legacy",
        )
        requests = httpx_mock.get_requests()
        # The forwarded initialize + forwarded initialized, nothing else.
        assert len(requests) == 2
        assert json.loads(requests[0].content)["method"] == "initialize"
        assert json.loads(requests[1].content)["method"] == "notifications/initialized"
        assert "mcp-method" not in requests[0].headers
        assert "mcp-method" not in requests[1].headers

    def test_shutdown_joins_listen_thread_before_client_close(self, httpx_mock):
        """C11 + #352 round-2 finding 2: run()'s finally tears the listen
        machinery down in this exact order — close the thread's DEDICATED
        client (from the main thread, actively unblocking a read parked
        for up to --listen-read-timeout, which a bounded join alone cannot
        do), join the thread, and only then close the SHARED client the
        thread never touches. The stub parks like a blocked iter_text()
        and is released only by ITS OWN client's close — exactly the
        cross-thread interrupt the real loop relies on, and one the stop
        event alone must not provide — so the recorded order is
        deterministic: listen-client-close -> listen-exited (join returns
        only once the thread finished appending) -> shared-client-close."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        order = []
        created = []
        released = threading.Event()

        class RecordingClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                created.append(self)

            def close(self):
                # created[0] is run()'s shared client, created[1] the
                # dedicated listen client (built by _start_listen_stream).
                if len(created) > 1 and self is created[1]:
                    order.append("listen-client-close")
                    released.set()
                elif created and self is created[0]:
                    order.append("shared-client-close")
                super().close()

        def stub_loop(**kwargs):
            # Park like a read blocked mid-stream: only the dedicated
            # client's cross-thread close may release it.
            assert released.wait(timeout=5)
            order.append("listen-exited")

        with (
            patch("mcp_stdio.relay._listen_stream_loop", stub_loop),
            patch("mcp_stdio.relay.httpx.Client", RecordingClient),
        ):
            self._run_with_stdin(
                httpx_mock,
                [
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2026-07-28",
                                "capabilities": {},
                            },
                        }
                    ),
                    # The thread starts on notifications/initialized
                    # (#352 review finding 1).
                    json.dumps(
                        {"jsonrpc": "2.0", "method": "notifications/initialized"}
                    ),
                ],
                protocol_era="modern",
            )
        assert order == [
            "listen-client-close",
            "listen-exited",
            "shared-client-close",
        ]
        assert len(created) == 2
        assert all(c.is_closed for c in created)

    def test_shutdown_unblocks_real_loop_parked_mid_stream(self, httpx_mock, capsys):
        """#352 round-2 finding 2, end to end with the REAL loop: the
        thread is parked mid-``iter_text()`` on an SSE stream that never
        ends (no sleeps — the stream generator blocks on an event released
        only by the dedicated client's close, then raises exactly the
        mapped transport error a cross-thread socket close produces).
        run()'s finally closes the DEDICATED client, the parked read
        raises, the stop-set drop arm exits silently, and the bounded join
        reaps the thread BEFORE run() returns — while every listen POST
        went through the dedicated client and the shared client saw none
        of them."""
        streaming = threading.Event()
        released = threading.Event()
        done = threading.Event()
        created = []
        sends = []
        captured = {}

        class RecordingClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                created.append(self)

            def send(self, request, *args, **kwargs):
                sends.append((self, request))
                return super().send(request, *args, **kwargs)

            def close(self):
                # created[1] is the dedicated listen client.
                if len(created) > 1 and self is created[1]:
                    released.set()
                super().close()

        real_loop = _listen_stream_loop

        def wrapped_loop(**kwargs):
            captured["client"] = kwargs["client"]
            try:
                real_loop(**kwargs)
            finally:
                # Set INSIDE the thread just before it dies: after run()
                # returns, this being set proves the join reaped the
                # thread (a timed-out join would leave it unset).
                done.set()

        ack = {
            "jsonrpc": "2.0",
            "method": "notifications/subscriptions/acknowledged",
            "params": {
                "notifications": {
                    "toolsListChanged": True,
                    "promptsListChanged": True,
                    "resourcesListChanged": True,
                }
            },
        }

        def never_ending_stream():
            yield f"event: message\ndata: {json.dumps(ack)}\n\n".encode()
            # The thread is now parked inside the stream pull.
            streaming.set()
            assert released.wait(timeout=5)
            # What a read blocked on a socket raises when the client is
            # closed from another thread (httpcore maps the dead-socket
            # OSError to a TransportError).
            raise httpx.ReadError("connection closed while reading")

        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "subscriptions/listen"},
            stream=IteratorStream(never_ending_stream()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        init = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2026-07-28", "capabilities": {}},
            }
        )
        initialized = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )

        def stdin_lines():
            yield init + "\n"
            yield initialized + "\n"
            # Hold stdin open until the thread is provably parked
            # mid-stream, so shutdown races a LIVE blocked read.
            assert streaming.wait(timeout=5)

        with (
            patch("mcp_stdio.relay._listen_stream_loop", wrapped_loop),
            patch("mcp_stdio.relay.httpx.Client", RecordingClient),
            patch("sys.stdin", stdin_lines()),
            patch("sys.stdout", StringIO()),
        ):
            run(self.URL, {"Content-Type": "application/json"}, protocol_era="modern")

        assert done.is_set()  # join succeeded; the thread was reaped
        assert len(created) == 2
        assert captured["client"] is created[1]  # dedicated, never shared
        assert all(c.is_closed for c in created)
        listen_sends = [
            c
            for (c, r) in sends
            if r.headers.get("mcp-method") == "subscriptions/listen"
        ]
        assert listen_sends and all(c is created[1] for c in listen_sends)
        assert all(
            c is created[0]
            for (c, r) in sends
            if r.headers.get("mcp-method") != "subscriptions/listen"
        )
        err = capsys.readouterr().err
        assert "Traceback" not in err
        # The stop-set drop arm exits silently — no scary reconnect/drop
        # line during an ordinary shutdown.
        assert "listen stream dropped" not in err

    def test_shutdown_race_before_first_stream_call_exits_clean(
        self, httpx_mock, capsys
    ):
        """#352 round-5 finding 1: shutdown immediately after
        notifications/initialized can interleave with the listen thread's
        FIRST attempt — the thread passes the loop-top stop check, run()'s
        finally then sets stop and closes the dedicated client, and the
        attempt's client.stream() lands on the closed client. httpx raises
        a plain RuntimeError there ("Cannot send a request, as the client
        has been closed." — 0.28.1's ClientState.CLOSED guard in
        Client.send), which neither the HTTPError nor the OSError arm
        covers, so an otherwise clean shutdown smeared an unhandled
        daemon-thread traceback. Forced deterministically, no sleeps: the
        attempt's prepare_headers snapshot — taken BETWEEN the loop-top
        stop check and client.stream() — parks until the dedicated
        client's close (run()'s finally, which set listen_stop just
        before) releases it, guaranteeing the closed-client call."""
        entered = threading.Event()
        released = threading.Event()
        done = threading.Event()
        failures = []
        created = []

        class RecordingClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                created.append(self)

            def close(self):
                # created[1] is the dedicated listen client; its close IS
                # run()'s finally, entered after listen_stop.set().
                if len(created) > 1 and self is created[1]:
                    released.set()
                super().close()

        real_loop = _listen_stream_loop

        def wrapped_loop(**kwargs):
            real_prepare = kwargs["prepare_headers"]

            def gated_prepare(body):
                # The loop-top stop check has already passed. Hold the
                # attempt here until run()'s teardown (stop set + client
                # close) completed, then let it hit the closed client.
                entered.set()
                assert released.wait(timeout=5)
                return real_prepare(body)

            kwargs["prepare_headers"] = gated_prepare
            try:
                real_loop(**kwargs)
            except BaseException as e:  # revert detector, see assert below
                failures.append(e)
                raise
            finally:
                done.set()

        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        init = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2026-07-28", "capabilities": {}},
            }
        )
        initialized = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )

        def stdin_lines():
            yield init + "\n"
            yield initialized + "\n"
            # Hold stdin open until the first attempt is provably past
            # the loop-top stop check (parked in its header snapshot), so
            # the EOF-triggered finally races a LIVE first attempt.
            assert entered.wait(timeout=5)

        with (
            patch("mcp_stdio.relay._listen_stream_loop", wrapped_loop),
            patch("mcp_stdio.relay.httpx.Client", RecordingClient),
            patch("sys.stdin", stdin_lines()),
            patch("sys.stdout", StringIO()),
        ):
            run(self.URL, {"Content-Type": "application/json"}, protocol_era="modern")

        assert done.is_set()  # the bounded join reaped the thread
        # The closed-client RuntimeError was absorbed by the stop-set arm,
        # never propagated out of the loop (pytest's threadexception hook
        # would swallow the traceback into a warning, so THIS is the
        # deterministic revert detector, not the stderr scrape below).
        assert failures == []
        assert len(created) == 2
        assert all(c.is_closed for c in created)
        err = capsys.readouterr().err
        assert "Traceback" not in err
        assert "RuntimeError" not in err
        # The raced attempt died before the transport: no listen POST.
        assert all(
            r.headers.get("mcp-method") != "subscriptions/listen"
            for r in httpx_mock.get_requests()
        )

    def test_second_initialize_never_spawns_second_listen_thread(self, httpx_mock):
        """Spec item 2: the start hook fires on EVERY
        notifications/initialized (#352 review finding 1 moved the start
        point there, so the stdin sends initialized after each initialize)
        but is latched one-shot — neither a client-driven re-initialize
        nor a repeated initialized may spawn a second thread (a second
        concurrent listen stream would duplicate every forwarded
        notification)."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        starts = []

        def stub_loop(**kwargs):
            starts.append(threading.current_thread().name)
            assert kwargs["stop"].wait(timeout=5)

        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2026-07-28", "capabilities": {}},
        }
        reinit = {**init, "id": 2}
        initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        with patch("mcp_stdio.relay._listen_stream_loop", stub_loop):
            self._run_with_stdin(
                httpx_mock,
                [
                    json.dumps(init),
                    json.dumps(initialized),
                    json.dumps(reinit),
                    json.dumps(initialized),
                ],
                protocol_era="modern",
            )
        assert len(starts) == 1

    def test_no_listen_thread_before_initialized_notification(self, httpx_mock):
        """#352 review finding 1: a session that ends after initialize —
        without ever sending notifications/initialized — must never create
        the listen thread. Started at initialize time (the reverted
        behavior), a fast server could deliver a list_changed to stdout
        BEFORE run()'s loop emitted the synthesized InitializeResult and
        before the legacy client signalled readiness — traffic the
        lifecycle spec tells servers not to send and a gating client may
        drop. Deterministic revert detector: run()'s finally stops and
        joins any started thread before returning, so the stub's record
        is complete — no sleeps, no races."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        starts = []

        def stub_loop(**kwargs):
            starts.append(kwargs["params"])
            assert kwargs["stop"].wait(timeout=5)

        with patch("mcp_stdio.relay._listen_stream_loop", stub_loop):
            self._run_with_stdin(
                httpx_mock,
                [
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2026-07-28",
                                "capabilities": {},
                            },
                        }
                    )
                ],
                protocol_era="modern",
            )
        assert starts == []

    def test_initialized_without_prior_initialize_starts_no_thread(self, httpx_mock):
        """#352 review finding 1, ordering guard: an orphan
        notifications/initialized — no prior initialize on this session —
        starts nothing. No snapshot was seeded (listen_state["params"] is
        None), and a thread launched with an unseeded body would carry an
        un-negotiated version and no captured client identity."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        starts = []

        def stub_loop(**kwargs):
            starts.append(kwargs["params"])
            assert kwargs["stop"].wait(timeout=5)

        with patch("mcp_stdio.relay._listen_stream_loop", stub_loop):
            self._run_with_stdin(
                httpx_mock,
                ['{"jsonrpc":"2.0","method":"notifications/initialized"}'],
                protocol_era="modern",
            )
        assert starts == []

    def test_listen_read_timeout_reaches_the_stream_timeout(self, httpx_mock):
        """C9: run()'s listen_read_timeout becomes the per-request READ
        timeout of the listen stream (connect/write stay the ordinary
        values), mirroring run_sse's post_timeout override pattern."""
        httpx_mock.add_response(
            url=self.URL,
            text=self._discover_response(),
            headers={"content-type": "application/json"},
        )
        captured = {}

        def stub_loop(**kwargs):
            captured["timeout"] = kwargs["timeout"]
            assert kwargs["stop"].wait(timeout=5)

        with patch("mcp_stdio.relay._listen_stream_loop", stub_loop):
            self._run_with_stdin(
                httpx_mock,
                [
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2026-07-28",
                                "capabilities": {},
                            },
                        }
                    ),
                    # The thread starts on notifications/initialized
                    # (#352 review finding 1).
                    json.dumps(
                        {"jsonrpc": "2.0", "method": "notifications/initialized"}
                    ),
                ],
                protocol_era="modern",
                timeout_connect=7.0,
                listen_read_timeout=42.0,
            )
        assert captured["timeout"].read == 42.0
        assert captured["timeout"].connect == 7.0

    # --- resource subscriptions (#270 Phase 2 PR B) ---

    def _init_line(self, req_id=1, capabilities=None):
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": capabilities if capabilities is not None else {},
                },
            }
        )

    def _initialized_line(self):
        return json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _subscribe_line(self, req_id, uri, method="resources/subscribe"):
        return json.dumps(
            {"jsonrpc": "2.0", "id": req_id, "method": method, "params": {"uri": uri}}
        )

    def _register_discover_with_resources(self, httpx_mock):
        """Seed a discover response that advertises the resources family.

        Pinned to its OWN ``Mcp-Method``, unlike the matcher-less
        registrations elsewhere in this class. With TWO background listen
        streams (#270 Phase 2 PR B) a matcher-less response is no longer
        safe: pytest_httpx falls back to "the LAST registered matcher, if
        it is reusable" once every matcher has been called, so the second
        listen POST resolves to the (non-reusable) discover matcher and
        fails to match at all. Pinning keeps each response bound to the
        request it actually answers.
        """
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "server/discover"},
            text=self._discover_response(capabilities={"tools": {}, "resources": {}}),
            headers={"content-type": "application/json"},
        )

    def test_modern_subscribe_answered_locally_and_never_forwarded(self, httpx_mock):
        """#270 Phase 2 PR B, implementation spec 1 + base change 3. Spec
        rev 2026-07-28 has no `resources/subscribe` on the wire, so
        forwarding one could only earn a -32601 the 2025-era client never
        expected from a server that advertised `resources.subscribe`. The
        relay answers the legacy EmptyResult itself, immediately, and
        POSTs nothing for it — the only upstream traffic here is the
        discover probe and the two listen streams."""
        self._register_listen_stream(httpx_mock)
        self._register_discover_with_resources(httpx_mock)
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._init_line(),
                self._initialized_line(),
                self._subscribe_line(7, "file:///a.txt"),
                self._subscribe_line(8, "file:///a.txt", "resources/unsubscribe"),
            ],
            protocol_era="modern",
        )
        lines = [json.loads(line) for line in output.strip().split("\n") if line]
        # [0] the synthesized InitializeResult, then one EmptyResult each.
        assert lines[1] == {"jsonrpc": "2.0", "id": 7, "result": {}}
        assert lines[2] == {"jsonrpc": "2.0", "id": 8, "result": {}}
        # The synthesized handshake advertised the capability the relay
        # itself now implements.
        assert lines[0]["result"]["capabilities"]["resources"] == {
            "listChanged": True,
            "subscribe": True,
        }
        # Nothing but the discover probe left this process on the ordinary
        # dispatch path — no subscribe/unsubscribe was forwarded.
        forwarded = [
            json.loads(r.content).get("method")
            for r in self._non_listen_requests(httpx_mock)
        ]
        assert forwarded == ["server/discover"]

    def test_duplicate_subscribe_and_unknown_unsubscribe_still_answer_empty(
        self, httpx_mock
    ):
        """Base change 7 (idempotent semantics): a repeat subscribe and an
        unsubscribe for a URI that was never subscribed both succeed with
        `{}`. The legacy methods define no error for either, so inventing
        one would be a wire behavior no 2025-era client is prepared for."""
        self._register_listen_stream(httpx_mock)
        self._register_discover_with_resources(httpx_mock)
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._init_line(),
                self._initialized_line(),
                self._subscribe_line(2, "file:///a.txt"),
                self._subscribe_line(3, "file:///a.txt"),
                self._subscribe_line(4, "file:///never", "resources/unsubscribe"),
            ],
            protocol_era="modern",
        )
        lines = [json.loads(line) for line in output.strip().split("\n") if line]
        assert [line.get("id") for line in lines] == [1, 2, 3, 4]
        assert all(line["result"] == {} for line in lines[1:])

    def test_subscribe_cap_refuses_new_uris_but_still_answers_empty(
        self, httpx_mock, capsys
    ):
        """Design A6: the 256-URI cap has `_MRTR_MAX_TXNS` semantics —
        cap, never TTL; at the cap the NEW subscription is refused and
        logged while every existing one keeps working, and the client
        still gets its EmptyResult (base change 3)."""
        self._register_listen_stream(httpx_mock)
        self._register_discover_with_resources(httpx_mock)
        stdin = [self._init_line(), self._initialized_line()]
        stdin += [
            self._subscribe_line(100 + n, f"file:///r{n}")
            for n in range(_LISTEN_MAX_SUBSCRIPTIONS + 1)
        ]
        output = self._run_with_stdin(httpx_mock, stdin, protocol_era="modern")
        lines = [json.loads(line) for line in output.strip().split("\n") if line]
        # Every subscribe, over-cap one included, answered {}.
        assert len(lines) == _LISTEN_MAX_SUBSCRIPTIONS + 2
        assert lines[-1] == {
            "jsonrpc": "2.0",
            "id": 100 + _LISTEN_MAX_SUBSCRIPTIONS,
            "result": {},
        }
        err = capsys.readouterr().err
        assert f"{_LISTEN_MAX_SUBSCRIPTIONS}-subscription cap" in err

    def test_resource_stream_posts_current_uris_under_its_own_id_prefix(
        self, httpx_mock
    ):
        """Design A2 + base changes 2/4, end to end: the SECOND stream
        carries `resourceSubscriptions` with the live URI set under ids
        derived from the relay's reserved namespace, while the
        list_changed stream's body stays byte-frozen (no
        `resourceSubscriptions` key at all — the PR A invariant)."""
        posted = []
        res_posted = threading.Event()

        def listen_callback(request):
            body = json.loads(request.content)
            posted.append(body)
            if body["id"].startswith(_LISTEN_RES_ID_PREFIX):
                res_posted.set()
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {"resultType": "complete"},
                },
            )

        httpx_mock.add_callback(
            listen_callback,
            url=self.URL,
            match_headers={"Mcp-Method": "subscriptions/listen"},
            is_optional=True,
            is_reusable=True,
        )
        self._register_discover_with_resources(httpx_mock)

        def stdin_lines():
            yield self._init_line() + "\n"
            yield self._initialized_line() + "\n"
            yield self._subscribe_line(2, "file:///b.txt") + "\n"
            assert res_posted.wait(timeout=5)

        with patch("sys.stdin", stdin_lines()), patch("sys.stdout", StringIO()):
            run(self.URL, {"Content-Type": "application/json"}, protocol_era="modern")

        res = [b for b in posted if b["id"].startswith(_LISTEN_RES_ID_PREFIX)]
        plain = [b for b in posted if b["id"].startswith(_LISTEN_ID_PREFIX)]
        assert len(res) == 1
        # Design A9, end-to-end wire-shape pin: the field belongs TO the
        # `notifications` filter, never beside it. A top-level placement
        # is not an error on a compliant server — it is silently ignored
        # (the reference SDK models the filter with `extra="ignore"`), so
        # only an assertion on the serialized body can catch a regression.
        assert res[0]["params"]["notifications"] == {
            "resourceSubscriptions": ["file:///b.txt"]
        }
        assert "resourceSubscriptions" not in res[0]["params"]
        # The two prefixes are DISTINCT and both derived, so the streams
        # can never mistake each other's graceful-end signals and the
        # #356 intake rejection covers both for free.
        assert _LISTEN_RES_ID_PREFIX.startswith(_RELAY_ID_NAMESPACE)
        assert _LISTEN_RES_ID_PREFIX != _LISTEN_ID_PREFIX
        # PR A's stream is untouched by PR B (base change 1): the three
        # listChanged booleans, and no resourceSubscriptions at either
        # level.
        assert plain
        for body in plain:
            assert body["params"]["notifications"] == {
                "toolsListChanged": True,
                "promptsListChanged": True,
                "resourcesListChanged": True,
            }
            assert "resourceSubscriptions" not in body["params"]

    def test_rapid_subscribes_coalesce_into_two_opens(self, httpx_mock):
        """Base change 6 (generation coalescing, no timers): five
        subscribes that land while one attempt is open produce ONE reopen,
        not five — `Event.set` is idempotent and the next attempt's
        snapshot sees every URI at once. Deterministic without sleeps: the
        stub holds attempt 1 open until the stdin generator has fed all
        five and released it."""
        self._register_discover_with_resources(httpx_mock)
        snapshots = []
        opened = threading.Event()
        release = threading.Event()
        done = threading.Event()

        def stub_loop(**kwargs):
            provider = kwargs.get("body_provider")
            if provider is None:  # the list_changed stream
                assert kwargs["stop"].wait(timeout=5)
                return
            snapshots.append(provider()[0]["notifications"]["resourceSubscriptions"])
            opened.set()
            assert release.wait(timeout=5)
            kwargs["restart"].clear()
            snapshots.append(provider()[0]["notifications"]["resourceSubscriptions"])
            done.set()
            assert kwargs["stop"].wait(timeout=5)

        def stdin_lines():
            yield self._init_line() + "\n"
            yield self._initialized_line() + "\n"
            yield self._subscribe_line(10, "file:///r0") + "\n"
            assert opened.wait(timeout=5)
            for n in range(1, 5):
                yield self._subscribe_line(10 + n, f"file:///r{n}") + "\n"
            release.set()
            assert done.wait(timeout=5)

        with (
            patch("mcp_stdio.relay._listen_stream_loop", stub_loop),
            patch("sys.stdin", stdin_lines()),
            patch("sys.stdout", StringIO()),
        ):
            run(self.URL, {"Content-Type": "application/json"}, protocol_era="modern")

        assert len(snapshots) == 2
        assert snapshots[0] == ["file:///r0"]
        assert snapshots[1] == [f"file:///r{n}" for n in range(5)]

    def test_teardown_wakes_a_parked_resource_stream(self, httpx_mock):
        """Design A4 through run()'s finally: an unsubscribe that empties
        the URI set parks the resource thread on `restart.wait()`, and an
        `Event.wait()` is deaf to BOTH the stop event and the dedicated
        client's close — the two things that unblock every other arm. So
        the teardown sets the restart event as well, after the stop. The
        stub parks exactly the way the real loop does (see
        `TestResourceListenStreamLoop.test_empty_uri_set_parks_and_teardown_wakes_it`
        for that being a plain `restart.wait()`); without the teardown's
        set it would outlive the bounded join."""
        self._register_discover_with_resources(httpx_mock)
        parked = threading.Event()
        exited = threading.Event()

        def stub_loop(**kwargs):
            if kwargs.get("body_provider") is None:
                assert kwargs["stop"].wait(timeout=5)
                return
            parked.set()
            kwargs["restart"].wait()
            exited.set()

        def stdin_lines():
            yield self._init_line() + "\n"
            yield self._initialized_line() + "\n"
            yield self._subscribe_line(2, "file:///a") + "\n"
            assert parked.wait(timeout=5)

        with (
            patch("mcp_stdio.relay._listen_stream_loop", stub_loop),
            patch("sys.stdin", stdin_lines()),
            patch("sys.stdout", StringIO()),
        ):
            run(self.URL, {"Content-Type": "application/json"}, protocol_era="modern")

        # run() has already joined it; a still-parked thread means the
        # teardown never woke it.
        assert exited.is_set()

    def test_no_resource_stream_without_a_subscription(self, httpx_mock):
        """The second stream is LAZY: a client that never subscribes must
        not pay for a second upstream connection, so only the
        list_changed stream (no `body_provider`) is ever started."""
        self._register_discover_with_resources(httpx_mock)
        started = []

        def stub_loop(**kwargs):
            started.append(kwargs.get("body_provider") is not None)
            assert kwargs["stop"].wait(timeout=5)

        with patch("mcp_stdio.relay._listen_stream_loop", stub_loop):
            self._run_with_stdin(
                httpx_mock,
                [self._init_line(), self._initialized_line()],
                protocol_era="modern",
            )
        assert started == [False]

    def test_subscribe_before_initialized_rides_the_first_open(self, httpx_mock):
        """Base change 3: subscribes that arrive before the listen phase
        accumulate and ride the FIRST open — there is nothing to reopen
        yet, so the URI set is simply what the first attempt requests."""
        self._register_discover_with_resources(httpx_mock)
        first = {}

        def stub_loop(**kwargs):
            provider = kwargs.get("body_provider")
            if provider is not None:
                first["filter"] = provider()[0]["notifications"]
            assert kwargs["stop"].wait(timeout=5)

        with patch("mcp_stdio.relay._listen_stream_loop", stub_loop):
            self._run_with_stdin(
                httpx_mock,
                [
                    self._init_line(),
                    self._subscribe_line(2, "file:///early"),
                    self._initialized_line(),
                ],
                protocol_era="modern",
            )
        assert first["filter"] == {"resourceSubscriptions": ["file:///early"]}

    def test_resource_stream_does_not_start_before_notifications_initialized(
        self, httpx_mock
    ):
        """#358 review R1F1: `initialize` seeds BOTH streams' body snapshot
        (`_seed_listen_snapshot`), so a `resources/subscribe` landing in the
        initialize -> initialized window used to start the resource stream
        immediately — opening the upstream connection before the
        downstream handshake had even completed, while the list_changed
        stream correctly waits for `initialized` (#352 review finding 1).
        The subscribe still answers `{}` and accumulates the URI, but the
        resource stream itself must not start until `_start_listen_stream`
        runs, then rides that start with the accumulated URI in its first
        body — same outcome as
        `test_subscribe_before_initialized_rides_the_first_open`, but this
        test also pins WHEN the thread is allowed to start.

        Absence is proven with a bounded wait rather than a race: the
        resource stream's stub signals an event the instant it runs, and
        starting a thread plus running one statement takes microseconds —
        nowhere near the bound below — so a premature start would show up
        reliably."""
        self._register_discover_with_resources(httpx_mock)
        resource_stream_started = threading.Event()
        first_resource_notifications = {}

        def stub_loop(**kwargs):
            provider = kwargs.get("body_provider")
            if provider is None:
                assert kwargs["stop"].wait(timeout=5)
                return
            first_resource_notifications.update(provider()[0]["notifications"])
            resource_stream_started.set()
            assert kwargs["stop"].wait(timeout=5)

        def stdin_lines():
            yield self._init_line() + "\n"
            yield self._subscribe_line(2, "file:///early") + "\n"
            assert not resource_stream_started.wait(timeout=0.5)
            yield self._initialized_line() + "\n"
            assert resource_stream_started.wait(timeout=5)

        stdout = StringIO()
        with (
            patch("mcp_stdio.relay._listen_stream_loop", stub_loop),
            patch("sys.stdin", stdin_lines()),
            patch("sys.stdout", stdout),
        ):
            run(self.URL, {"Content-Type": "application/json"}, protocol_era="modern")

        lines = [json.loads(line) for line in stdout.getvalue().strip().split("\n")]
        assert lines[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}
        assert first_resource_notifications == {
            "resourceSubscriptions": ["file:///early"]
        }

    def test_subscribe_with_a_reserved_id_falls_through_to_the_intake_guard(
        self, httpx_mock
    ):
        """Design A1, revert-check. The PR B interception runs BEFORE
        #356's reserved-namespace intake rejection, so answering `{}` here
        would put a SECOND response on the wire for one id. The hook
        declines instead and the guard emits the single -32600 — and
        nothing is subscribed, which is what a response-only assertion
        would miss."""
        self._register_discover_with_resources(httpx_mock)
        started = []

        def stub_loop(**kwargs):
            started.append(kwargs.get("body_provider") is not None)
            assert kwargs["stop"].wait(timeout=5)

        with patch("mcp_stdio.relay._listen_stream_loop", stub_loop):
            output = self._run_with_stdin(
                httpx_mock,
                [
                    self._init_line(),
                    self._initialized_line(),
                    self._subscribe_line("mcp-stdio/listen-res/1", "file:///x"),
                ],
                protocol_era="modern",
            )
        lines = [json.loads(line) for line in output.strip().split("\n") if line]
        # EXACTLY one response for the subscribe, and it is the rejection.
        assert len(lines) == 2
        assert lines[1]["id"] == "mcp-stdio/listen-res/1"
        assert lines[1]["error"]["code"] == -32600
        assert _RELAY_ID_NAMESPACE in lines[1]["error"]["message"]
        # No subscription was recorded, so no resource stream was started.
        assert started == [False]

    def test_subscribe_reusing_a_pending_mrtr_id_falls_through_to_that_guard(
        self, httpx_mock
    ):
        """Design A1, the second guard: an id that still owns a pending
        MRTR transaction must get ONE -32600 from the reuse check, never a
        synthesized `{}` from the subscribe interception on top of it."""
        self._register_listen_stream(httpx_mock)
        self._register_discover_with_resources(httpx_mock)
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "result": {
                        "resultType": "input_required",
                        "inputRequests": {
                            "who": {
                                "method": "elicitation/create",
                                "params": {"message": "name?", "requestedSchema": {}},
                            }
                        },
                    },
                }
            ),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._init_line(capabilities={"elicitation": {}}),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "tools/call",
                        "params": {"name": "greet", "arguments": {}},
                    }
                ),
                # id 5 still owns the transaction the minted elicitation
                # is waiting on.
                self._subscribe_line(5, "file:///x"),
            ],
            protocol_era="modern",
        )
        lines = [json.loads(line) for line in output.strip().split("\n") if line]
        # [0] InitializeResult, [1] the minted elicitation/create, [2] the
        # single rejection — no `{}` for id 5 anywhere.
        assert len(lines) == 3
        assert lines[1]["method"] == "elicitation/create"
        assert lines[2]["id"] == 5
        assert lines[2]["error"]["code"] == -32600
        assert "MRTR transaction pending" in lines[2]["error"]["message"]
        assert not any(line.get("result") == {} for line in lines)

    def test_subscribe_is_not_swallowed_by_the_mrtr_response_interception(
        self, httpx_mock
    ):
        """The MRTR response interception consumes RESPONSE-shaped lines
        (id + result/error, NO method). A subscribe carries a method, so
        `_is_pure_response` rejects it by construction — this pins that,
        because a subscribe swallowed there would vanish without a
        reply."""
        self._register_listen_stream(httpx_mock)
        self._register_discover_with_resources(httpx_mock)
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._init_line(),
                self._initialized_line(),
                self._subscribe_line(6, "file:///c.txt"),
            ],
            protocol_era="modern",
        )
        lines = [json.loads(line) for line in output.strip().split("\n") if line]
        assert lines[-1] == {"jsonrpc": "2.0", "id": 6, "result": {}}

    def test_input_required_on_a_listen_response_mints_nothing(self, httpx_mock):
        """Design A3: `subscriptions/listen` is NOT MRTR-eligible (only
        prompts/get, resources/read and tools/call are), so an
        `input_required` result on a listen response is a spec violation —
        never an invitation to mint an elicitation onto stdout. The listen
        loops deliberately do not go through `_post_and_stream`, so no
        bridge hook exists on that path; this pins the consequence."""
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "subscriptions/listen"},
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "mcp-stdio/listen/1",
                    "result": {
                        "resultType": "input_required",
                        "inputRequests": {
                            "who": {
                                "method": "elicitation/create",
                                "params": {"message": "name?"},
                            }
                        },
                    },
                }
            ),
            headers={"content-type": "application/json"},
            is_optional=True,
            is_reusable=True,
        )
        self._register_discover_with_resources(httpx_mock)
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._init_line(capabilities={"elicitation": {}}),
                self._initialized_line(),
            ],
            protocol_era="modern",
        )
        assert "elicitation/create" not in output

    def test_legacy_era_forwards_subscribe_verbatim_and_touches_no_state(
        self, httpx_mock
    ):
        """AC 3 (#270): the legacy era has NO PR B call site. A
        `resources/subscribe` is POSTed verbatim — no Mcp-Method header,
        no local `{}` — and the URI-set holder is never touched, so no
        resource stream can exist to reopen."""
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}',
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text='{"jsonrpc":"2.0","id":2,"result":{}}',
            headers={"content-type": "application/json"},
        )
        recorded = []

        class SpySubscriptions(_ResourceSubscriptions):
            def add(self, uri):
                recorded.append(uri)
                return super().add(uri)

        subscribe = self._subscribe_line(2, "file:///legacy.txt")
        with patch("mcp_stdio.relay._ResourceSubscriptions", SpySubscriptions):
            self._run_with_stdin(
                httpx_mock,
                [self._init_line(), subscribe],
                protocol_era="legacy",
            )
        requests = httpx_mock.get_requests()
        assert len(requests) == 2  # forwarded initialize + forwarded subscribe
        assert requests[1].content.decode() == subscribe
        assert "mcp-method" not in requests[1].headers
        assert recorded == []


# --- modern era: MRTR bridge (#270 Phase 2 PR C) ---


class TestRunModernMrtrBridge:
    """The multi round-trip requests bridge, end to end through run().

    Spec rev 2026-07-28 made a server ANSWER the client's request with an
    InputRequiredResult instead of initiating a request of its own; these
    exercise the relay turning that back into the server-initiated
    requests a 2025-era stdio client understands, and every way the
    exchange can fail.

    None of these send ``notifications/initialized``, so the PR A listen
    thread never starts and there is no racy background POST to filter —
    request ordering in each test is exactly what the bridge did. The
    optional listen absorber is still registered so a future change to
    the thread's start point cannot turn these into flakes.
    """

    URL = "https://example.com/mcp"

    def _run_with_stdin(self, httpx_mock, stdin_lines, **kwargs):
        stdin_data = "\n".join(stdin_lines) + "\n"
        stdout = StringIO()
        with patch("sys.stdin", StringIO(stdin_data)), patch("sys.stdout", stdout):
            run(self.URL, {"Content-Type": "application/json"}, **kwargs)
        return stdout.getvalue()

    def _register_listen_stream(self, httpx_mock):
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "subscriptions/listen"},
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "mcp-stdio/listen/1",
                    "result": {"resultType": "complete"},
                }
            ),
            headers={"content-type": "application/json"},
            is_optional=True,
            is_reusable=True,
        )

    def _register_discover(self, httpx_mock):
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "result": {
                        "resultType": "discover",
                        "supportedVersions": ["2026-07-28"],
                        "capabilities": {"tools": {}},
                    },
                }
            ),
            headers={"content-type": "application/json"},
        )

    def _register_json(self, httpx_mock, body):
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            text=json.dumps(body),
            headers={"content-type": "application/json"},
        )

    def _initialize(self, capabilities):
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": capabilities,
                },
            }
        )

    def _call(self, req_id=2, name="greet"):
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": {}},
            }
        )

    def _input_required(self, req_id, requests=None, state="OPAQUE"):
        result = {"resultType": "input_required"}
        if requests is not None:
            result["inputRequests"] = requests
        if state is not None:
            result["requestState"] = state
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _elicit(self, message="name?", **extra):
        params = {"mode": "form", "message": message, "requestedSchema": {}}
        params.update(extra)
        return {"method": "elicitation/create", "params": params}

    def _out(self, output):
        return [json.loads(line) for line in output.strip().split("\n") if line]

    def _tool_calls(self, httpx_mock):
        return [
            json.loads(r.content)
            for r in httpx_mock.get_requests()
            if r.headers.get("mcp-method") == "tools/call"
        ]

    # --- happy paths, one per request kind ---

    def test_elicitation_round_trip(self, httpx_mock):
        """The whole bridge in one test: the server answers tools/call with
        an InputRequiredResult, the relay mints a legacy elicitation/create
        onto stdout, the client answers it, and the relay re-POSTs the
        ORIGINAL request with `inputResponses` + the value-exact
        `requestState` echo under a DIFFERENT id ("The JSON-RPC id MUST be
        different between the initial request and the retry"), then hands
        the final result back under the id the client is waiting on."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/1",
                "result": {"content": [{"type": "text", "text": "hi octocat"}]},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/who",
                        "result": {"action": "accept", "content": {"name": "octocat"}},
                    }
                ),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        # [0] synthesized InitializeResult, [1] minted request, [2] result.
        assert len(lines) == 3
        minted = lines[1]
        assert minted["method"] == "elicitation/create"
        assert minted["id"] == "mcp-stdio/mrtr/1/who"
        # mode:"form" is stripped — a 2025 client has never seen the field,
        # and "Clients MUST treat requests without a mode field as form
        # mode".
        assert "mode" not in minted["params"]
        assert minted["params"]["message"] == "name?"
        # The final result is re-keyed from the relay's retry id to 2.
        assert lines[2]["id"] == 2
        assert lines[2]["result"]["content"][0]["text"] == "hi octocat"
        calls = self._tool_calls(httpx_mock)
        assert len(calls) == 2
        retry = calls[1]
        assert retry["id"] == "mcp-stdio/mrtr-retry/1/1"
        assert retry["id"] != calls[0]["id"]
        assert retry["params"]["inputResponses"] == {
            "who": {"action": "accept", "content": {"name": "octocat"}}
        }
        assert retry["params"]["requestState"] == "OPAQUE"
        # Same tool, same arguments: the retry is the STORED request line,
        # not a re-derivation.
        assert retry["params"]["name"] == calls[0]["params"]["name"]

    def test_sampling_and_roots_round_trip(self, httpx_mock):
        """The other two kinds, and a multi-key round: sampling params ride
        verbatim, roots/list is minted with NO params at all
        (ListRootsRequest has none), and the retry waits for BOTH answers
        before it fires — "Always send ALL keys"."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        sampling = {
            "method": "sampling/createMessage",
            "params": {"messages": [], "maxTokens": 100},
        }
        self._register_json(
            httpx_mock,
            self._input_required(
                2, {"ask": sampling, "roots": {"method": "roots/list"}}, state=None
            ),
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/1",
                "result": {"content": []},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"sampling": {}, "roots": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/ask",
                        "result": {"role": "assistant", "content": {"type": "text"}},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/roots",
                        "result": {"roots": [{"uri": "file:///w"}]},
                    }
                ),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        minted = {line["id"]: line for line in lines[1:3]}
        assert minted["mcp-stdio/mrtr/1/ask"]["params"] == sampling["params"]
        assert "params" not in minted["mcp-stdio/mrtr/1/roots"]
        assert minted["mcp-stdio/mrtr/1/roots"]["method"] == "roots/list"
        calls = self._tool_calls(httpx_mock)
        # ONE retry, fired only after the second answer arrived.
        assert len(calls) == 2
        assert set(calls[1]["params"]["inputResponses"]) == {"ask", "roots"}
        # requestState absent from the result -> absent from the retry:
        # "If the InputRequiredResult does not contain a requestState
        # field, the client MUST NOT include one in the retry."
        assert "requestState" not in calls[1]["params"]

    def test_elicitation_decline_is_forwarded_as_a_result(self, httpx_mock):
        """An elicitation decline (and cancel) is a RESULT in the
        three-action model — {"action": "decline"} — not a JSON-RPC error,
        so it rides `inputResponses` like any other answer and the SERVER
        decides what it means. Treating it as a failure here would take
        that decision away from the only party that can make it."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/1",
                "result": {"content": [{"type": "text", "text": "ok, skipping"}]},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/who",
                        "result": {"action": "decline"},
                    }
                ),
            ],
            protocol_era="modern",
        )
        calls = self._tool_calls(httpx_mock)
        assert calls[1]["params"]["inputResponses"] == {"who": {"action": "decline"}}
        assert self._out(output)[-1]["id"] == 2

    def test_multi_round_replaces_request_state_and_keys(self, httpx_mock):
        """Round 2's requestState REPLACES round 1's and its keys are its
        own: "Both the inputRequests and requestState fields affect only
        the client's retry of the original request." A stale echo would
        replay state the server has already consumed."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock,
            self._input_required(2, {"first": self._elicit()}, state="STATE-1"),
        )
        self._register_json(
            httpx_mock,
            self._input_required(
                "mcp-stdio/mrtr-retry/1/1",
                {"second": self._elicit()},
                state="STATE-2",
            ),
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/2",
                "result": {"content": []},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/first",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/second",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
            ],
            protocol_era="modern",
        )
        calls = self._tool_calls(httpx_mock)
        assert len(calls) == 3
        assert calls[1]["params"]["requestState"] == "STATE-1"
        assert set(calls[1]["params"]["inputResponses"]) == {"first"}
        assert calls[2]["params"]["requestState"] == "STATE-2"
        # Round 2 sends ONLY round 2's key — the first answer belonged to
        # the round the server has already processed.
        assert set(calls[2]["params"]["inputResponses"]) == {"second"}
        assert self._out(output)[-1]["id"] == 2

    def test_retry_pins_the_version_of_the_stored_request(self, httpx_mock):
        """Design change 7, both halves at once: the retry is built from
        the STORED body (so `_meta` still carries round 1's negotiated
        version — `_inject_modern_meta` is NOT re-run) and its
        MCP-Protocol-Version header is pinned to that same value, even
        though `_prepare_headers` derives the header from LIVE state that a
        re-`initialize` has since moved. A header/`_meta` disagreement is
        -32020 HeaderMismatch on a compliant server, which would kill a
        transaction the user has already answered a dialog for — the same
        pinning PR A (#352) applies to listen reconnects.

        Two implemented versions are patched in, and the discover seed
        advertises none, so the negotiated version follows whatever the
        client last asked for — the only way to move it mid-session while
        the relay implements exactly one version."""
        self._register_listen_stream(httpx_mock)
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "result": {"resultType": "discover", "capabilities": {"tools": {}}},
                }
            ),
            headers={"content-type": "application/json"},
        )
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/1",
                "result": {"content": []},
            },
        )
        reinit = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2027-01-01",
                    "capabilities": {"elicitation": {}},
                },
            }
        )
        with patch(
            "mcp_stdio.relay._RELAY_IMPLEMENTED_MODERN_VERSIONS",
            frozenset({"2026-07-28", "2027-01-01"}),
        ):
            self._run_with_stdin(
                httpx_mock,
                [
                    self._initialize({"elicitation": {}}),
                    self._call(),
                    # The client renegotiates mid-transaction.
                    reinit,
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": "mcp-stdio/mrtr/1/who",
                            "result": {"action": "accept", "content": {}},
                        }
                    ),
                ],
                protocol_era="modern",
            )
        posts = [
            r
            for r in httpx_mock.get_requests()
            if r.headers.get("mcp-method") == "tools/call"
        ]
        body = json.loads(posts[1].content)
        stored_version = body["params"]["_meta"][
            "io.modelcontextprotocol/protocolVersion"
        ]
        assert stored_version == "2026-07-28"
        assert posts[1].headers["mcp-protocol-version"] == stored_version
        # And the retry still derives its own Mcp-Name from a body the
        # added params did not disturb.
        assert posts[1].headers["mcp-name"] == "greet"

    # --- the ways it ends early ---

    def test_undeclared_capability_aborts_to_the_client_id(self, httpx_mock):
        """MRTR server requirement 7: "Servers MUST NOT send an
        inputRequests that the client has not declared support for in its
        capabilities." Minting it anyway would put a question on stdout
        that the client has no handler for — an unanswerable request and a
        hang. Nothing is minted, and the client gets one error."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        output = self._run_with_stdin(
            httpx_mock,
            [self._initialize({"roots": {}}), self._call()],
            protocol_era="modern",
        )
        lines = self._out(output)
        assert len(lines) == 2
        assert lines[1]["id"] == 2
        assert lines[1]["error"]["code"] == -32600
        assert "elicitation" in lines[1]["error"]["message"]
        # One POST only: no retry was attempted.
        assert len(self._tool_calls(httpx_mock)) == 1

    def test_url_mode_elicitation_aborts(self, httpx_mock):
        """Design change 10: URL-mode elicitation loads client-side MUSTs
        (never pre-fetch, explicit consent, show the full URL, open where
        the client cannot inspect it) that a 2025-era stdio client predates
        entirely — and the spec devotes a whole section to the phishing
        attack that follows when they are not honored. Refuse rather than
        silently downgrade a credential flow to a form."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock,
            self._input_required(
                2,
                {
                    "auth": {
                        "method": "elicitation/create",
                        "params": {
                            "mode": "url",
                            "url": "https://evil.example/steal",
                            "message": "sign in",
                        },
                    }
                },
            ),
        )
        output = self._run_with_stdin(
            httpx_mock,
            [self._initialize({"elicitation": {"url": {}}}), self._call()],
            protocol_era="modern",
        )
        lines = self._out(output)
        assert len(lines) == 2
        assert lines[1]["error"]["code"] == -32600
        assert "URL-mode" in lines[1]["error"]["message"]
        # The URL never reached the client.
        assert "evil.example" not in output

    def test_tool_augmented_sampling_aborts(self, httpx_mock):
        """A 2025 client cannot produce the answer shape, so the server
        would act on a reply that silently dropped half the request."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock,
            self._input_required(
                2,
                {
                    "ask": {
                        "method": "sampling/createMessage",
                        "params": {"messages": [], "tools": [{"name": "t"}]},
                    }
                },
            ),
        )
        output = self._run_with_stdin(
            httpx_mock,
            [self._initialize({"sampling": {}}), self._call()],
            protocol_era="modern",
        )
        assert "tool-augmented sampling" in self._out(output)[1]["error"]["message"]

    def test_unknown_request_kind_aborts(self, httpx_mock):
        """ "values are request objects that MUST be one of ElicitRequest,
        CreateMessageRequest, or ListRootsRequest" — anything else has no
        legacy counterpart to mint."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock,
            self._input_required(2, {"x": {"method": "logging/setLevel"}}),
        )
        output = self._run_with_stdin(
            httpx_mock,
            [self._initialize({"elicitation": {}}), self._call()],
            protocol_era="modern",
        )
        assert "cannot bridge" in self._out(output)[1]["error"]["message"]

    def test_neither_input_requests_nor_request_state_aborts(self, httpx_mock):
        """Server requirement 6: "Servers MUST include at least one of
        inputRequests or requestState in every InputRequiredResult
        response." With neither, the retry would be byte-identical to the
        request that just failed — an infinite loop."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(httpx_mock, self._input_required(2, state=None))
        output = self._run_with_stdin(
            httpx_mock,
            [self._initialize({"elicitation": {}}), self._call()],
            protocol_era="modern",
        )
        lines = self._out(output)
        assert lines[1]["error"]["code"] == -32600
        assert len(self._tool_calls(httpx_mock)) == 1

    def test_client_error_on_a_minted_id_aborts_the_transaction(self, httpx_mock):
        """Design change 3. A partial `inputResponses` retry IS legal —
        the server "SHOULD respond with a new InputRequiredResult
        requesting the missing information again, rather than returning an
        error" — but a client that answers an elicitation with a JSON-RPC
        error cannot answer it at all, so the partial retry would only burn
        a round asking for the same key. Abandoning is equally legal:
        "Servers MUST NOT assume that clients will fulfill the
        inputRequests or retry the original request."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock,
            self._input_required(2, {"a": self._elicit(), "b": self._elicit()}),
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/a",
                        "error": {"code": -32601, "message": "no elicitation here"},
                    }
                ),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        # init, 2 minted requests, a cancel for the still-outstanding one,
        # then the error.
        cancels = [
            line for line in lines if line.get("method") == "notifications/cancelled"
        ]
        assert [c["params"]["requestId"] for c in cancels] == ["mcp-stdio/mrtr/1/b"]
        assert lines[-1]["id"] == 2
        assert lines[-1]["error"]["code"] == -32000
        assert len(self._tool_calls(httpx_mock)) == 1

    def test_request_state_only_rounds_hit_the_round_cap(self, httpx_mock):
        """Design change 4, the strongest hostile-server gap: an
        InputRequiredResult with only `requestState` needs nothing from the
        client ("the client MAY retry the original request immediately"),
        so a looping server drives the relay through unbounded POSTs with
        zero user involvement. The cap ends it with one error under the
        client's id."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        # Every tools/call gets another requestState-only result, each
        # echoing the id of the request it answers (the relay re-mints one
        # per round, and a compliant server echoes it). One MORE response
        # than the cap allows, so the cap — not the mock running dry — is
        # what stops the loop.
        for echoed in [2] + [f"mcp-stdio/mrtr-retry/1/{n}" for n in range(1, 34)]:
            httpx_mock.add_response(
                url=self.URL,
                match_headers={"Mcp-Method": "tools/call"},
                text=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": echoed,
                        "result": {"resultType": "input_required", "requestState": "s"},
                    }
                ),
                headers={"content-type": "application/json"},
                is_optional=True,
            )
        output = self._run_with_stdin(
            httpx_mock,
            [self._initialize({"elicitation": {}}), self._call()],
            protocol_era="modern",
        )
        lines = self._out(output)
        assert lines[-1]["id"] == 2
        assert lines[-1]["error"]["code"] == -32000
        assert "32 times" in lines[-1]["error"]["message"]
        # The original POST plus exactly _MRTR_MAX_ROUNDS retries. The
        # retries all carry the id the FIRST result echoed, so every one of
        # them re-triggers the hook.
        assert len(self._tool_calls(httpx_mock)) == 1 + 32

    def test_transaction_cap_fails_the_newest_request(self, httpx_mock):
        """Design change 5: a hard count cap, no TTL (a TTL races the human
        at the dialog and would put two responses on the wire for one id).
        At the cap the NEW transaction fails — the older ones already have
        dialogs in front of a user."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        stdin = [self._initialize({"elicitation": {}})]
        # 256 transactions open, then one more.
        for i in range(257):
            httpx_mock.add_response(
                url=self.URL,
                match_headers={"Mcp-Method": "tools/call"},
                text=json.dumps(self._input_required(100 + i, {"q": self._elicit()})),
                headers={"content-type": "application/json"},
            )
            stdin.append(self._call(req_id=100 + i))
        output = self._run_with_stdin(httpx_mock, stdin, protocol_era="modern")
        lines = self._out(output)
        errors = [line for line in lines if "error" in line]
        assert len(errors) == 1
        assert errors[0]["id"] == 100 + 256
        assert errors[0]["error"]["code"] == -32000
        assert "cap 256" in errors[0]["error"]["message"]

    def test_client_id_reuse_while_pending_is_rejected(self, httpx_mock):
        """Design change 6: JSON-RPC permits id reuse once the prior call
        is DONE, but a pending transaction owns minted ids, a stored body
        and a round counter under that id — a second request would clobber
        them or put two responses on the wire for one id."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        output = self._run_with_stdin(
            httpx_mock,
            [self._initialize({"elicitation": {}}), self._call(), self._call()],
            protocol_era="modern",
        )
        lines = self._out(output)
        assert lines[-1]["id"] == 2
        assert lines[-1]["error"]["code"] == -32600
        assert "pending" in lines[-1]["error"]["message"]
        # The second tools/call never reached the wire.
        assert len(self._tool_calls(httpx_mock)) == 1

    def test_cancel_drops_the_transaction_and_cancels_minted_requests(self, httpx_mock):
        """Design change 11. The client cancelled the id it is waiting on,
        so nothing is answered for it ("Not send a response for the
        cancelled request"), and every still-outstanding minted request is
        cancelled downstream — the relay issued them, they are still in
        progress, which is exactly what the spec requires of a canceller.
        Nothing is forwarded upstream: on this transport "Closing the SSE
        response stream is the cancellation signal ... No
        notifications/cancelled message is required or expected", and a
        synchronous retry POST cannot be in flight while this same thread
        reads stdin (PR D's deferred stdin handoff)."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock,
            self._input_required(2, {"a": self._elicit(), "b": self._elicit()}),
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": {"requestId": 2, "reason": "user"},
                    }
                ),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        cancels = [
            line for line in lines if line.get("method") == "notifications/cancelled"
        ]
        assert {c["params"]["requestId"] for c in cancels} == {
            "mcp-stdio/mrtr/1/a",
            "mcp-stdio/mrtr/1/b",
        }
        # No response for the cancelled id, and no retry POST.
        assert not [line for line in lines if line.get("id") == 2]
        assert len(self._tool_calls(httpx_mock)) == 1

    def test_cancel_of_a_minted_id_aborts_instead_of_hanging(self, httpx_mock):
        """The #11 never-hang contract on the OTHER cancellable id. A
        client that gives up on an input request by cancelling the MINTED
        id (rather than answering `{"action": "cancel"}`) is never sending
        that answer, so the round can never complete and the retry can
        never fire — and the transaction would sit forever holding the
        client's own id hostage, since the reuse check rejects every new
        request under it. Abort to the client's id instead, cancel the
        siblings still outstanding, and leave the id usable again."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock,
            self._input_required(2, {"a": self._elicit(), "b": self._elicit()}),
        )
        # The id must be free again afterwards, so a second tools/call
        # under it reaches the wire.
        self._register_json(
            httpx_mock, {"jsonrpc": "2.0", "id": 2, "result": {"content": []}}
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": {"requestId": "mcp-stdio/mrtr/1/a"},
                    }
                ),
                self._call(),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        cancels = [
            line for line in lines if line.get("method") == "notifications/cancelled"
        ]
        # Only the sibling still in progress is cancelled downstream.
        assert [c["params"]["requestId"] for c in cancels] == ["mcp-stdio/mrtr/1/b"]
        errors = [line for line in lines if "error" in line]
        assert len(errors) == 1
        assert errors[0]["id"] == 2
        assert "cancelled input request 'a'" in errors[0]["error"]["message"]
        # The transaction is gone: the id works again.
        assert len(self._tool_calls(httpx_mock)) == 2
        assert lines[-1] == {"jsonrpc": "2.0", "id": 2, "result": {"content": []}}

    def test_cancel_works_with_the_cancel_filter_disabled(self, httpx_mock):
        """The bridge extracts the cancel id itself rather than piggybacking
        on the cancel tracker (design change 11): `--no-cancel-filter`
        turns the tracker off, but a transaction must still be droppable —
        otherwise the id stays locked for the whole session."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(httpx_mock, self._input_required(2, {"a": self._elicit()}))
        # After the cancel the id is free again, so a second tools/call
        # under it must reach the wire.
        self._register_json(
            httpx_mock, {"jsonrpc": "2.0", "id": 2, "result": {"content": []}}
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": {"requestId": 2},
                    }
                ),
                self._call(),
            ],
            protocol_era="modern",
            cancel_filter=False,
        )
        assert len(self._tool_calls(httpx_mock)) == 2
        assert self._out(output)[-1] == {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"content": []},
        }

    def test_upstream_error_on_the_retry_surfaces_under_the_client_id(self, httpx_mock):
        """A retry that fails upstream must answer the id the CLIENT is
        waiting on, never the relay's internal retry id — the client would
        hang forever on a correlation it never issued."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            status_code=500,
            text="",
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/who",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        assert lines[-1]["id"] == 2
        assert lines[-1]["error"]["message"] == "HTTP 500"

    # --- stdin lines that are not requests ---

    def test_unknown_response_shaped_stdin_line_is_dropped_not_posted(self, httpx_mock):
        """Interception point (b): on the modern era a response-shaped line
        can only be answering a relay-minted request, because rev
        2026-07-28 "no longer supported" server-initiated requests at all.
        An unrecognised one is dropped with a log line instead of being
        POSTed as the pre-PR-C loop did — a body with no `method`, hence no
        Mcp-Method header, which "Required For: All requests" already made
        non-compliant."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                json.dumps(
                    {"jsonrpc": "2.0", "id": 99, "result": {"action": "accept"}}
                ),
                json.dumps(
                    {"jsonrpc": "2.0", "id": 98, "error": {"code": -1, "message": "x"}}
                ),
            ],
            protocol_era="modern",
        )
        # Only the discover probe ever hit the wire.
        assert len(httpx_mock.get_requests()) == 1
        # And nothing but the InitializeResult reached stdout.
        assert len(self._out(output)) == 1

    def test_stale_duplicate_response_to_a_consumed_minted_id_is_dropped(
        self, httpx_mock
    ):
        """A minted id is consumed on first answer, so a duplicate falls
        into the same drop path — it must not re-fire a retry or POST
        anything."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/1",
                "result": {"content": []},
            },
        )
        answer = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr/1/who",
                "result": {"action": "accept", "content": {}},
            }
        )
        self._run_with_stdin(
            httpx_mock,
            [self._initialize({"elicitation": {}}), self._call(), answer, answer],
            protocol_era="modern",
        )
        assert len(self._tool_calls(httpx_mock)) == 2

    def test_answered_minted_ids_are_not_cancelled_later(self, httpx_mock):
        """A minted id is retired from the transaction the moment it is
        answered, so a later abort or cancel only cancels what is still
        OUTSTANDING — "Cancellation notifications MUST only reference
        requests that ... are believed to still be in-progress". Cancelling
        a question the client already answered would be noise the spec
        calls invalid."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock,
            self._input_required(2, {"a": self._elicit(), "b": self._elicit()}),
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/a",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": {"requestId": 2},
                    }
                ),
            ],
            protocol_era="modern",
        )
        cancels = [
            line
            for line in self._out(output)
            if line.get("method") == "notifications/cancelled"
        ]
        assert [c["params"]["requestId"] for c in cancels] == ["mcp-stdio/mrtr/1/b"]

    def test_input_required_on_an_ineligible_method_is_forwarded_verbatim(
        self, httpx_mock
    ):
        """ "Servers MUST NOT send InputRequiredResult responses on any
        other client requests", so the bridge hooks only tools/call,
        resources/read and prompts/get. On anything else the Phase 1
        verbatim forward stands — swallowing it on a path the spec says
        cannot produce it would hide a server bug instead of surfacing
        it."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"resultType": "input_required", "requestState": "s"},
            }
        )
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "completion/complete"},
            text=body,
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "completion/complete",
                        "params": {},
                    }
                ),
            ],
            protocol_era="modern",
        )
        assert self._out(output)[-1] == json.loads(body)

    def test_kill_switch_withdraws_the_invitation_but_keeps_the_bridge(
        self, httpx_mock, monkeypatch
    ):
        """`MCP_STDIO_MRTR_STRIP` restores the pre-bridge advertisement, so
        a COMPLIANT server is told the client cannot elicit and has no
        standing invitation to send MRTR ("Only use capabilities that were
        successfully negotiated"). It does NOT disable the bridge: the
        minting gate reads what the client DECLARED, so a non-compliant
        server that sends `input_required` anyway is still bridged rather
        than rejected — the client really can answer it, and failing the
        call instead would serve the user worse. This is exactly the state
        PR C's own commits 2-5 were built and tested in."""
        monkeypatch.setenv("MCP_STDIO_MRTR_STRIP", "1")
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/1",
                "result": {"content": []},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/who",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
            ],
            protocol_era="modern",
        )
        calls = self._tool_calls(httpx_mock)
        # The invitation is withdrawn...
        meta = calls[0]["params"]["_meta"]
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {}
        # ...but the round trip still completes for a server that ignored
        # it.
        lines = self._out(output)
        assert lines[1]["method"] == "elicitation/create"
        assert lines[-1]["id"] == 2
        assert "inputResponses" in calls[1]["params"]

    def test_swallowed_round_does_not_synthesize_an_empty_response(self, httpx_mock):
        """`_post_and_stream` synthesizes "empty response from server" for
        a 200 that delivered no payload, so a swallowed input_required
        would otherwise put a SECOND answer on the wire for one id — the
        exact framing error this relay exists to absorb."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        output = self._run_with_stdin(
            httpx_mock,
            [self._initialize({"elicitation": {}}), self._call()],
            protocol_era="modern",
        )
        lines = self._out(output)
        # InitializeResult + the minted request. Nothing else.
        assert len(lines) == 2
        assert lines[1]["method"] == "elicitation/create"
        assert not [line for line in lines if "error" in line]

    def test_interrupt_after_a_swallowed_round_aborts_once(self, httpx_mock):
        """#356 review R1F1. The stream carrying the `input_required` breaks
        AFTER the hook swallowed it, so the transaction is alive and its
        minted request is already on the client's stdin. The generic
        "upstream stream interrupted" error would answer id 2 now — and the
        retry the client's answer then fires would answer id 2 AGAIN, the
        two-responses-one-id hazard `_SSE_PENDING_MAX` documents. A swallow
        routes the failure through `_mrtr_abort` instead: exactly one error
        under 2, one downstream cancel retiring the dialog nobody will
        collect, transaction purged — so the client's late answer is dropped
        rather than re-POSTed."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)

        def gen():
            payload = json.dumps(self._input_required(2, {"who": self._elicit()}))
            yield f"event: message\ndata: {payload}\n\n".encode()
            raise httpx.ReadError("connection dropped after the input_required")

        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            stream=IteratorStream(gen()),
            headers={"content-type": "text/event-stream"},
        )
        # Registered but not expected: with the abort funnel wired the retry
        # never fires. It exists so that REMOVING the funnel produces the
        # two-response output this test asserts against, instead of dying on
        # an unmatched request.
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "mcp-stdio/mrtr-retry/1/1",
                    "result": {"content": [{"type": "text", "text": "too late"}]},
                }
            ),
            headers={"content-type": "application/json"},
            is_optional=True,
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/who",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
            ],
            protocol_era="modern",
        )
        # The interrupted POST and nothing else: the original was never
        # replayed and the retry was never fired.
        assert len(self._tool_calls(httpx_mock)) == 1
        lines = self._out(output)
        answers = [line for line in lines if line.get("id") == 2]
        assert len(answers) == 1
        assert answers[0]["error"]["code"] == -32000
        assert answers[0]["error"]["message"].startswith("MRTR bridge: upstream stream")
        cancels = [
            line for line in lines if line.get("method") == "notifications/cancelled"
        ]
        assert [c["params"]["requestId"] for c in cancels] == ["mcp-stdio/mrtr/1/who"]

    def test_interrupt_after_an_aborted_round_does_not_answer_twice(self, httpx_mock):
        """The same interrupt when the swallowed round was UNBRIDGEABLE. The
        hook swallowed it and `_mrtr_open_round` already answered and purged
        (an undeclared capability), so re-entering the abort funnel on the
        way out would put a SECOND error on the wire for one id — the exact
        failure the funnel exists to prevent. The membership check in
        `_make_input_required_abort` is what keeps "exactly once" true."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)

        def gen():
            payload = json.dumps(self._input_required(2, {"who": self._elicit()}))
            yield f"event: message\ndata: {payload}\n\n".encode()
            raise httpx.ReadError("connection dropped after the input_required")

        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            stream=IteratorStream(gen()),
            headers={"content-type": "text/event-stream"},
        )
        output = self._run_with_stdin(
            httpx_mock,
            # No elicitation declared: the round is rejected from inside the
            # swallow before the stream ever breaks.
            [self._initialize({"roots": {}}), self._call()],
            protocol_era="modern",
        )
        answers = [line for line in self._out(output) if line.get("id") == 2]
        assert len(answers) == 1
        assert "never declared" in answers[0]["error"]["message"]

    def test_duplicate_of_the_final_retry_answer_then_interrupt_answers_once(
        self, httpx_mock
    ):
        """#356 review R5F1. The RETRY stream delivers its valid final
        answer, then a non-compliant duplicate under the SAME retry id
        (dropped by the per-POST latch, #356 deep-review finding
        minted-orphan), and only THEN does the connection drop. Pre-fix,
        the latch's `return None` for that duplicate read to
        `_post_and_stream` as a fresh swallow even though nothing was left
        pending — the transaction already had its answer — so the interrupt
        ran through `_make_input_required_abort` (R1F1) and found the
        transaction "still registered" (it was only purged later, in
        `_mrtr_run_retry`, after this whole POST returned), writing a
        SECOND response — an error — under id 2 after the valid result. The
        fix purges the transaction the moment the hook computes the
        terminal answer, so the duplicate and the interrupt both find
        nothing left to abort. Reusing id 2 for a fresh call right after
        proves the transaction really is gone, not just quiet."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )

        def gen():
            final = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "mcp-stdio/mrtr-retry/1/1",
                    "result": {"content": [{"type": "text", "text": "hi octocat"}]},
                }
            )
            duplicate = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "mcp-stdio/mrtr-retry/1/1",
                    "result": {
                        "content": [{"type": "text", "text": "hi octocat again"}]
                    },
                }
            )
            yield f"event: message\ndata: {final}\n\n".encode()
            yield f"event: message\ndata: {duplicate}\n\n".encode()
            raise httpx.ReadError("connection dropped after the duplicate")

        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            stream=IteratorStream(gen()),
            headers={"content-type": "text/event-stream"},
        )
        # id 2 is free again once the transaction is purged, so a fresh
        # call under the SAME id must be accepted, not rejected as "still
        # owns a pending MRTR transaction".
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"content": [{"type": "text", "text": "second call"}]},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/who",
                        "result": {"action": "accept", "content": {"name": "octocat"}},
                    }
                ),
                self._call(req_id=2),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        # InitializeResult, the mint, the retry's valid answer, the reused
        # call's answer. No error line anywhere.
        assert len(lines) == 4
        assert not [line for line in lines if "error" in line]
        assert [
            line for line in lines if line.get("method") == "notifications/cancelled"
        ] == []
        # The literal R5F1 claim, checked BEFORE the reuse tail is even
        # possible (id 2 is only free to reuse once the transaction is
        # purged): exactly one message under id 2 out of the R5F1 sequence
        # alone — [0] init, [1] mint, [2] the retry's answer — and it is
        # the valid result, never the dropped duplicate and never an error.
        r5f1_answers = [line for line in lines[:3] if line.get("id") == 2]
        assert len(r5f1_answers) == 1
        assert "error" not in r5f1_answers[0]
        assert r5f1_answers[0]["result"]["content"][0]["text"] == "hi octocat"
        # And the transaction really is gone, not just quiet: id 2 was
        # legitimately reused for a second call and got its own answer.
        answers = [line for line in lines if line.get("id") == 2]
        assert len(answers) == 2
        assert answers[1]["result"]["content"][0]["text"] == "second call"

    def _register_status(self, httpx_mock, status_code):
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            status_code=status_code,
            text="",
            headers={"content-type": "application/json"},
        )

    def test_retry_401_refreshes_the_token_once_and_re_posts(self, httpx_mock):
        """#356 review R1F2. A retry is USER-WORK-BEARING: the human has
        already answered the elicitation dialogs it carries. Letting a 401
        kill the transaction means "self-heals on the client's next request"
        cashes out as "the client re-asks the same questions". One bounded
        `token_refresher` refresh and one re-POST — the loop's own 401
        discipline, on the loop's own thread — saves the answers.

        The re-POST is the SAME round under the SAME retry id: the server
        answered a challenge without processing the request, exactly as when
        the loop re-dispatches the same `line`. The MUST that binds is only
        "different between the initial request and the retry"."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        self._register_status(httpx_mock, 401)
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/1",
                "result": {"content": [{"type": "text", "text": "hi octocat"}]},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/who",
                        "result": {"action": "accept", "content": {"name": "octocat"}},
                    }
                ),
            ],
            protocol_era="modern",
            token_refresher=lambda: {"Authorization": "Bearer refreshed"},
        )
        calls = self._tool_calls(httpx_mock)
        # original, the 401'd retry, the refreshed re-POST. No more: the
        # refresh is single-attempt, not a ladder.
        assert len(calls) == 3
        # Same round, same id, same collected answers — not a re-derivation
        # and not a new round.
        assert calls[1] == calls[2]
        assert calls[2]["id"] == "mcp-stdio/mrtr-retry/1/1"
        assert calls[2]["params"]["inputResponses"] == {
            "who": {"action": "accept", "content": {"name": "octocat"}}
        }
        posts = [
            r
            for r in httpx_mock.get_requests()
            if r.headers.get("mcp-method") == "tools/call"
        ]
        # The refreshed credentials reached the re-POST, and the version
        # header is still the one pinned from the stored body's _meta
        # (re-preparing headers without re-pinning would be -32020
        # HeaderMismatch on a compliant server).
        assert "authorization" not in posts[1].headers
        assert posts[2].headers["authorization"] == "Bearer refreshed"
        assert posts[2].headers["mcp-protocol-version"] == "2026-07-28"
        # The user's answers were not thrown away: one clean result under 2.
        answers = [line for line in self._out(output) if line.get("id") == 2]
        assert len(answers) == 1
        assert answers[0]["result"]["content"][0]["text"] == "hi octocat"

    def test_retry_401_with_a_failed_refresh_fails_loudly(self, httpx_mock):
        """The recovery is ONE stage wide and stays honest at its edge: a
        refresh that declines falls straight through to the single "upstream
        error on retry -> error under N, drop txn" arm, so the client gets a
        loud HTTP 401 under its own id instead of a hang or a silent second
        attempt."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        self._register_status(httpx_mock, 401)
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/who",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
            ],
            protocol_era="modern",
            token_refresher=lambda: None,
        )
        # No re-POST was attempted on a refusal.
        assert len(self._tool_calls(httpx_mock)) == 2
        answers = [line for line in self._out(output) if line.get("id") == 2]
        assert len(answers) == 1
        assert answers[0]["error"]["message"] == "HTTP 401"

    # --- the relay's reserved id namespace (#356 review R2F1) ---

    RESERVED_CALL = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "mcp-stdio/mrtr/1/who",
            "method": "tools/call",
            "params": {"name": "greet", "arguments": {}},
        }
    )

    def test_reserved_namespace_request_id_is_rejected_on_modern(self, httpx_mock):
        """#356 review R2F1. A client request whose OWN id is a minted id is
        indistinguishable from the relay's bookkeeping afterwards: a cancel
        naming it matches `mrtr_minted` and aborts ANOTHER transaction
        instead of dropping this one. The relay owns "mcp-stdio/" on this
        era, so the collision is refused where the id ENTERS — one check,
        before any state can key on it — rather than tested for in every
        consumer."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        # Registered but not expected: without the intake check the request
        # is forwarded upstream, which is what this test must be able to
        # observe rather than dying on an unmatched request.
        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "mcp-stdio/mrtr/1/who",
                    "result": {"content": []},
                }
            ),
            headers={"content-type": "application/json"},
            is_optional=True,
        )
        output = self._run_with_stdin(
            httpx_mock,
            [self._initialize({"elicitation": {}}), self.RESERVED_CALL],
            protocol_era="modern",
        )
        assert self._tool_calls(httpx_mock) == []
        reply = self._out(output)[-1]
        assert reply["id"] == "mcp-stdio/mrtr/1/who"
        assert reply["error"]["code"] == -32600
        assert "reserved" in reply["error"]["message"]

    def test_reserved_namespace_request_id_passes_through_on_legacy(self, httpx_mock):
        """AC 3: the legacy era is untouched. Server-initiated requests are
        still a real thing there, the relay mints nothing into this
        namespace on that path, and a legacy client that happens to use such
        an id keeps being forwarded byte-identically — the rejection lives
        inside `era == "modern"`."""
        httpx_mock.add_response(
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "mcp-stdio/mrtr/1/who",
                    "result": {"content": []},
                }
            ),
            headers={"content-type": "application/json"},
        )
        output = self._run_with_stdin(httpx_mock, [self.RESERVED_CALL])
        requests = httpx_mock.get_requests()
        assert len(requests) == 1
        assert requests[0].content.decode() == self.RESERVED_CALL
        assert self._out(output)[-1]["result"] == {"content": []}

    def test_cancel_of_a_client_id_leaves_other_transactions_alone(self, httpx_mock):
        """The cancel lookup tries the client's own transactions BEFORE the
        minted index (#356 review R2F1, defense in depth behind the intake
        rejection). Two live transactions, each holding one minted request:
        cancelling id 2 must cancel exactly ITS minted request downstream
        and leave transaction 3 answerable — a misrouted cancel would abort
        the wrong one and answer an id the client never cancelled."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)
        self._register_json(
            httpx_mock, self._input_required(2, {"who": self._elicit()})
        )
        self._register_json(
            httpx_mock, self._input_required(3, {"who": self._elicit()})
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/2/1",
                "result": {"content": [{"type": "text", "text": "three"}]},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                self._call(req_id=3),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": {"requestId": 2},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/2/who",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        cancels = [
            line for line in lines if line.get("method") == "notifications/cancelled"
        ]
        # Only transaction 1's dialog is retired; transaction 2's survives.
        assert [c["params"]["requestId"] for c in cancels] == ["mcp-stdio/mrtr/1/who"]
        # ...and that survivor completes normally under its own id.
        answers = [line for line in lines if line.get("id") == 3]
        assert len(answers) == 1
        assert answers[0]["result"]["content"][0]["text"] == "three"
        # The cancelled request is answered with nothing at all ("Not send a
        # response for the cancelled request").
        assert [line for line in lines if line.get("id") == 2] == []

    # --- #356 deep-review finding (minted-orphan): the per-POST latch ---

    def test_two_input_required_in_one_post_are_latched_no_orphan(self, httpx_mock):
        """A non-compliant server streams a SECOND `input_required` under
        the SAME upstream id before the client answered the first — the
        exact JSON-RPC violation `_SSE_PENDING_MAX` documents this file
        absorbing elsewhere. Without the per-POST latch this re-enters
        `_mrtr_open_round` for a still-live round, replacing it and leaving
        the first round's minted id a PERMANENT orphan in `mrtr_minted`
        (`_mrtr_purge` only ever walks the CURRENT `txn["minted"]`). With
        the latch, only the first `input_required` is minted — the second
        is dropped outright, so nothing is ever orphaned. Proven here by
        cancelling the id the orphan WOULD have used after the transaction
        completes: with no orphan, that cancel is indistinguishable from
        cancelling something that never existed — dropped silently, no
        output at all."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)

        def gen():
            first = json.dumps(
                self._input_required(2, {"a": self._elicit()}, state="S1")
            )
            second = json.dumps(
                self._input_required(2, {"b": self._elicit()}, state="S2")
            )
            yield f"event: message\ndata: {first}\n\n".encode()
            yield f"event: message\ndata: {second}\n\n".encode()

        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            stream=IteratorStream(gen()),
            headers={"content-type": "text/event-stream"},
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/1",
                "result": {"content": [{"type": "text", "text": "done"}]},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/a",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
                # The client never saw "b" — nothing minted it — but replay
                # a cancel naming where it WOULD have landed anyway.
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": {"requestId": "mcp-stdio/mrtr/1/b"},
                    }
                ),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        elicitations = [
            line for line in lines if line.get("method") == "elicitation/create"
        ]
        # Only "a" ever reached stdout; "b" was never minted at all.
        assert [line["id"] for line in elicitations] == ["mcp-stdio/mrtr/1/a"]
        # The transaction completed normally on "a" alone, and the stray
        # cancel for the never-minted "b" produced no output whatsoever —
        # no error, no downstream cancel notification, nothing beyond the
        # InitializeResult, the "a" mint, and the final answer.
        assert len(lines) == 3
        answers = [line for line in lines if line.get("id") == 2]
        assert len(answers) == 1
        assert answers[0]["result"]["content"][0]["text"] == "done"

    def test_stale_minted_id_cancel_after_reuse_touches_nothing(self, httpx_mock):
        """The full failing sequence (#356 deep-review finding,
        minted-orphan): two `input_required` results under one id in one
        POST, the transaction completes on the first key alone, and the
        client legally reuses the same id N for a brand new, UNRELATED
        transaction that is still pending when a stale
        `notifications/cancelled` arrives naming the id the never-opened
        second round would have minted. Pre-fix, that id would still be a
        live entry in `mrtr_minted` (owned by N, since `mrtr_minted` keys on
        `client_id` — not on which transaction incarnation minted it), so
        the cancel would resolve to N's CURRENT (unrelated) transaction and
        `_mrtr_abort` would kill it — or, if N's second call had already
        been answered too, write a spurious error under an id that already
        has its answer. Post-fix there is no orphan to resolve: the cancel
        is dropped, and the second transaction survives to answer
        normally."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)

        def gen():
            first = json.dumps(self._input_required(2, {"a": self._elicit()}))
            second = json.dumps(self._input_required(2, {"b": self._elicit()}))
            yield f"event: message\ndata: {first}\n\n".encode()
            yield f"event: message\ndata: {second}\n\n".encode()

        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            stream=IteratorStream(gen()),
            headers={"content-type": "text/event-stream"},
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/1",
                "result": {"content": [{"type": "text", "text": "first done"}]},
            },
        )
        # The client reuses id 2 for a second, unrelated call once the first
        # transaction is purged — a fresh MRTR transaction (seq 2) opens.
        self._register_json(httpx_mock, self._input_required(2, {"x": self._elicit()}))
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/2/1",
                "result": {"content": [{"type": "text", "text": "second done"}]},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/a",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
                self._call(req_id=2),
                # The stale cancel arrives while the SECOND, unrelated
                # transaction under the reused id 2 is still live.
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": {"requestId": "mcp-stdio/mrtr/1/b"},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/2/x",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        elicitations = [
            line for line in lines if line.get("method") == "elicitation/create"
        ]
        # "b" is never minted; only "a" (txn 1) and "x" (txn 2) are.
        assert [line["id"] for line in elicitations] == [
            "mcp-stdio/mrtr/1/a",
            "mcp-stdio/mrtr/2/x",
        ]
        # The stale cancel produced no downstream cancel notification — it
        # named an id that never existed.
        cancels = [
            line for line in lines if line.get("method") == "notifications/cancelled"
        ]
        assert cancels == []
        # Both id-2 answers arrived, in order, neither replaced by an error:
        # the reused id's own transaction was never touched by the cancel
        # meant for a different (never-opened) round of the FIRST one.
        answers = [line for line in lines if line.get("id") == 2]
        assert len(answers) == 2
        assert "error" not in answers[0]
        assert answers[0]["result"]["content"][0]["text"] == "first done"
        assert "error" not in answers[1]
        assert answers[1]["result"]["content"][0]["text"] == "second done"

    def test_input_required_then_premature_result_emits_once(self, httpx_mock):
        """Sequence 2 (#356 deep-review finding, minted-orphan): a
        non-compliant server streams an `input_required` and, in the SAME
        POST, a normal RESULT under the SAME id — as if it answered before
        the client ever replied. On the INITIAL POST `upstream_id ==
        client_id`, so `_mrtr_rekey` short-circuits before even parsing and
        the premature result would reach stdout untouched, immediately.
        Then the client's real answer fires the retry and its genuine
        result reaches stdout again under the SAME id: two responses for
        one id. The latch drops the premature frame instead, so exactly one
        response — the genuine one — is ever emitted under N."""
        self._register_listen_stream(httpx_mock)
        self._register_discover(httpx_mock)

        def gen():
            required = json.dumps(self._input_required(2, {"who": self._elicit()}))
            premature = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {"content": [{"type": "text", "text": "too early"}]},
                }
            )
            yield f"event: message\ndata: {required}\n\n".encode()
            yield f"event: message\ndata: {premature}\n\n".encode()

        httpx_mock.add_response(
            url=self.URL,
            match_headers={"Mcp-Method": "tools/call"},
            stream=IteratorStream(gen()),
            headers={"content-type": "text/event-stream"},
        )
        self._register_json(
            httpx_mock,
            {
                "jsonrpc": "2.0",
                "id": "mcp-stdio/mrtr-retry/1/1",
                "result": {"content": [{"type": "text", "text": "the real answer"}]},
            },
        )
        output = self._run_with_stdin(
            httpx_mock,
            [
                self._initialize({"elicitation": {}}),
                self._call(),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "mcp-stdio/mrtr/1/who",
                        "result": {"action": "accept", "content": {}},
                    }
                ),
            ],
            protocol_era="modern",
        )
        lines = self._out(output)
        answers = [line for line in lines if line.get("id") == 2]
        assert len(answers) == 1
        assert answers[0]["result"]["content"][0]["text"] == "the real answer"


# --- modern era: subscriptions/listen stream (#270 Phase 2 PR A) ---


class TestBuildListenParams:
    """The frozen listen body snapshot (C1)."""

    def _state(self):
        state = _ModernState()
        state.negotiated_version = "2026-07-28"
        state.client_capabilities = {"experimental": {"caching": {}}}
        state.client_info = {"name": "c", "version": "1"}
        return state

    def test_meta_nests_inside_params_with_no_log_level(self):
        """The body mirrors the modern request shape (_meta INSIDE params,
        matching _inject_modern_meta) and requests all three list_changed
        booleans — but never logLevel: modern_state.log_level is rewritten
        on every logging/setLevel stdin line, and the frozen snapshot must
        not drift with it (C1)."""
        state = self._state()
        state.log_level = "debug"
        params = _build_listen_params(state)
        assert params["notifications"] == {
            "toolsListChanged": True,
            "promptsListChanged": True,
            "resourcesListChanged": True,
        }
        # PR B territory — must not be requested yet.
        assert "resourceSubscriptions" not in params
        meta = params["_meta"]
        assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {
            "experimental": {"caching": {}}
        }
        assert meta["io.modelcontextprotocol/clientInfo"] == {
            "name": "c",
            "version": "1",
        }
        assert "io.modelcontextprotocol/logLevel" not in meta

    def test_client_info_omitted_when_never_provided(self):
        state = self._state()
        state.client_info = None
        meta = _build_listen_params(state)["_meta"]
        assert "io.modelcontextprotocol/clientInfo" not in meta

    def test_client_capabilities_default_to_empty_dict(self):
        """clientCapabilities is REQUIRED and presence-based — an uncaptured
        (None) set is sent as {} exactly like _inject_modern_meta does."""
        state = self._state()
        state.client_capabilities = None
        meta = _build_listen_params(state)["_meta"]
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {}

    def test_protocol_version_falls_back_to_modern_floor(self):
        """Byte-match contract: the same fallback expression
        _prepare_headers' modern branch uses for MCP-Protocol-Version."""
        state = self._state()
        state.negotiated_version = None
        meta = _build_listen_params(state)["_meta"]
        assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"

    def test_snapshot_immune_to_later_state_mutation(self):
        """C1: the snapshot deep-copies nested values, so a later in-place
        mutation of modern_state (a re-initialize, a capability tweak) can
        never reach the frozen body."""
        state = self._state()
        params = _build_listen_params(state)
        state.client_capabilities["experimental"]["caching"]["evil"] = True
        state.client_info["name"] = "mutated"
        meta = params["_meta"]
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {
            "experimental": {"caching": {}}
        }
        assert meta["io.modelcontextprotocol/clientInfo"]["name"] == "c"


class TestStripListenSubscriptionId:
    """subscriptionId stripping on forwarded list_changed notifications."""

    def test_strips_key_keeps_other_meta(self):
        msg = {
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/subscriptionId": "s-1",
                    "keep": 1,
                }
            },
        }
        out = _strip_listen_subscription_id(msg)
        assert out["params"]["_meta"] == {"keep": 1}

    def test_drops_meta_entirely_when_it_becomes_empty(self):
        msg = {
            "jsonrpc": "2.0",
            "method": "notifications/prompts/list_changed",
            "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": "s-1"}},
        }
        out = _strip_listen_subscription_id(msg)
        assert "_meta" not in out["params"]

    def test_message_without_params_or_meta_passes_through(self):
        msg = {"jsonrpc": "2.0", "method": "notifications/resources/list_changed"}
        assert _strip_listen_subscription_id(msg) is msg
        with_meta = {
            "jsonrpc": "2.0",
            "method": "notifications/resources/list_changed",
            "params": {"_meta": {"other": 1}},
        }
        assert _strip_listen_subscription_id(with_meta) is with_meta

    def test_original_message_never_mutated(self):
        msg = {
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": "s-1"}},
        }
        _strip_listen_subscription_id(msg)
        assert msg["params"]["_meta"] == {
            "io.modelcontextprotocol/subscriptionId": "s-1"
        }


class TestHandleListenMessage:
    """Message classification on the listen stream (whitelist semantics)."""

    LISTEN_ID = "mcp-stdio/listen/1"

    def _handle(self, msg, state=None, acked=True):
        # acked=True default: most tests exercise post-ack classification;
        # the round-7 pre-ack gate has its own dedicated tests below.
        return _handle_listen_message(
            json.dumps(msg), self.LISTEN_ID, None, state, acked=acked
        )

    def test_result_with_int_id_never_aliases_the_listen_id(self):
        """C10 type-aware compare: the listen id is a namespaced STRING, so
        a numeric client-style id — even one whose text appears inside the
        listen id — is a foreign response, swallowed, never a graceful
        end."""
        assert self._handle({"jsonrpc": "2.0", "id": 1, "result": {}}) is None

    def test_result_for_listen_id_is_graceful(self):
        assert (
            self._handle(
                {
                    "jsonrpc": "2.0",
                    "id": self.LISTEN_ID,
                    "result": {"resultType": "complete"},
                }
            )
            == "graceful"
        )

    def test_id_bearing_whitelisted_method_swallowed_never_forwarded(self):
        """#352 round-2 finding 3: JSON-RPC 2.0 defines any message that
        carries an "id" member as a REQUEST — the sender expects a
        response. A hostile or malformed upstream stamping an id onto a
        whitelisted list_changed method must not smuggle a live request
        onto the stdio wire (the legacy client might answer it). Swallowed
        — consumed, nothing on stdout."""
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            result = self._handle(
                {
                    "jsonrpc": "2.0",
                    "id": 13,
                    "method": "notifications/tools/list_changed",
                }
            )
        assert result is None
        assert stdout.getvalue() == ""

    def test_unadvertised_family_swallowed_advertised_forwarded(self):
        """#352 round-3 finding 2 (the C8 narrowing's forwarding side):
        ``state["advertised"]`` carries the family set the synthesized
        InitializeResult actually advertised listChanged on, frozen at
        listen-seed time. A notifications/resources/list_changed whose
        family was never advertised is swallowed — forwarding it would be
        exactly the un-negotiated-capability notification C8 exists to
        prevent — while an advertised family's notification still flows."""
        state = {"advertised": frozenset({"tools"})}
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            assert (
                self._handle(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/list_changed",
                    },
                    state=state,
                )
                is None
            )
        assert stdout.getvalue() == ""
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            assert (
                self._handle(
                    {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"},
                    state=state,
                )
                is None
            )
        assert (
            json.loads(stdout.getvalue())["method"]
            == "notifications/tools/list_changed"
        )

    def test_empty_advertised_set_swallows_all_three(self):
        """#352 round-3 finding 2: an empty discover seed ({} — the #350
        chicken-and-egg case) advertises no family at all, so ALL three
        list_changed kinds are swallowed — the documented degraded mode."""
        state = {"advertised": frozenset()}
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            for family in ("tools", "resources", "prompts"):
                assert (
                    self._handle(
                        {
                            "jsonrpc": "2.0",
                            "method": f"notifications/{family}/list_changed",
                        },
                        state=state,
                    )
                    is None
                )
        assert stdout.getvalue() == ""

    def test_unseeded_carrier_keeps_permissive_forwarding(self):
        """#352 round-3 finding 2, the deliberate fallback: a carrier that
        never saw a seed (state is None, or no "advertised" key — direct
        callers in tests) keeps the pre-narrowing permissive behavior.
        run() always seeds the set before the thread starts, so this arm
        is unreachable in the real pipeline."""
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            self._handle(
                {"jsonrpc": "2.0", "method": "notifications/prompts/list_changed"},
                state=None,
            )
        assert (
            json.loads(stdout.getvalue())["method"]
            == "notifications/prompts/list_changed"
        )

    def test_cancelled_with_foreign_request_id_is_swallowed(self):
        assert (
            self._handle(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": 5},
                }
            )
            is None
        )

    def test_cancelled_for_listen_id_is_graceful(self):
        assert (
            self._handle(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": self.LISTEN_ID},
                }
            )
            == "graceful"
        )

    def test_error_for_listen_id_any_code_is_terminal(self):
        assert (
            self._handle(
                {
                    "jsonrpc": "2.0",
                    "id": self.LISTEN_ID,
                    "error": {"code": -32000, "message": "nope"},
                }
            )
            == "terminal"
        )

    @pytest.mark.parametrize("code", [-32601, -32020, -32021, -32022])
    def test_terminal_codes_terminal_even_under_null_id(self, code):
        """C6: a server rejecting an unknown method may answer under id
        null — the deterministic-rejection codes are terminal regardless of
        the id they arrive under."""
        assert (
            self._handle(
                {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": "x"}}
            )
            == "terminal"
        )

    def test_foreign_error_with_ordinary_code_is_swallowed(self):
        assert (
            self._handle(
                {"jsonrpc": "2.0", "id": 7, "error": {"code": -32000, "message": "x"}}
            )
            is None
        )

    def test_ack_records_honored_subset_and_logs_divergence(self, capsys):
        state = {}
        honored = {"toolsListChanged": True}
        # "ack" (not None): the ack is consumed like any swallowed message
        # but reported distinctly — it is the protocol-valid establishment
        # evidence the loop records (#352 round-5 finding 2).
        assert (
            self._handle(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/subscriptions/acknowledged",
                    "params": {"notifications": honored},
                },
                state=state,
            )
            == "ack"
        )
        assert state["honored"] == honored
        assert "honored a subset" in capsys.readouterr().err

    def test_ack_honoring_everything_stays_silent(self, capsys):
        state = {}
        honored = {
            "toolsListChanged": True,
            "promptsListChanged": True,
            "resourcesListChanged": True,
        }
        assert (
            self._handle(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/subscriptions/acknowledged",
                    "params": {"notifications": honored},
                },
                state=state,
            )
            == "ack"
        )
        assert state["honored"] == honored
        assert "honored a subset" not in capsys.readouterr().err

    def test_id_bearing_ack_is_not_establishment_evidence(self):
        """#352 round-6 finding: an "ack" carrying an id is a JSON-RPC
        REQUEST wearing the ack's method name (the round-2 rule the
        forwarding branch enforces) — a broken/unsupported endpoint
        emitting it must not flip `established` and bypass the round-5
        pre-establishment fail-fast into reconnect-forever."""
        state = {}
        assert (
            self._handle(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "notifications/subscriptions/acknowledged",
                    "params": {"notifications": {"toolsListChanged": True}},
                },
                state=state,
            )
            is None
        )
        assert "honored" not in state

    def test_payload_less_ack_is_not_establishment_evidence(self):
        """#352 round-6 finding, the missing-payload half: a bare
        `{"method": ...acknowledged}` (no `params.notifications` object)
        carries no honored subset — not protocol-valid evidence."""
        state = {}
        for params in (None, {}, {"notifications": "yes"}, {"notifications": None}):
            msg = {
                "jsonrpc": "2.0",
                "method": "notifications/subscriptions/acknowledged",
            }
            if params is not None:
                msg["params"] = params
            assert self._handle(msg, state=state) is None
        assert "honored" not in state

    def test_envelope_less_message_is_swallowed_even_post_ack(self, capsys):
        """#352 round-8 finding 1: a payload without `jsonrpc: "2.0"` is
        not a well-formed JSON-RPC object — forwarding it could break a
        strict legacy client, and an envelope-less "ack" must not
        establish. Compliant servers always send the member, so only
        protocol-invalid traffic is swallowed."""
        assert (
            self._handle(
                {"method": "notifications/tools/list_changed"},
                acked=True,
            )
            is None
        )
        assert capsys.readouterr().out == ""
        state = {}
        assert (
            self._handle(
                {
                    "method": "notifications/subscriptions/acknowledged",
                    "params": {"notifications": {"toolsListChanged": True}},
                },
                state=state,
            )
            is None
        )
        assert "honored" not in state

    def test_unhonored_kind_is_swallowed_despite_advertisement(self, capsys):
        """#352 round-8 finding 2: the ack's honored subset is the listen
        negotiation result. A server that honored {} declared it will not
        send any kind — a tools/list_changed arriving anyway is malformed
        or misrouted and must not be forwarded, even though tools was
        advertised downstream."""
        state = {"advertised": frozenset({"tools"}), "honored": {}}
        assert (
            self._handle(
                {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"},
                state=state,
                acked=True,
            )
            is None
        )
        assert capsys.readouterr().out == ""
        state["honored"] = {"toolsListChanged": True}
        assert (
            self._handle(
                {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"},
                state=state,
                acked=True,
            )
            is None
        )
        assert "notifications/tools/list_changed" in capsys.readouterr().out

    def test_pre_ack_notification_is_swallowed_not_forwarded(self, capsys):
        """#352 round-7 finding: the spec makes the ack the mandatory FIRST
        stream message, so a whitelisted list_changed arriving BEFORE this
        attempt's ack is a protocol violation and must not reach stdout —
        forwarding it would write from a stream the loop may immediately
        afterwards declare never-established (misrouted endpoint emitting
        a matching method then closing)."""
        assert (
            self._handle(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                },
                acked=False,
            )
            is None
        )
        assert capsys.readouterr().out == ""

    def test_post_ack_notification_is_forwarded(self, capsys):
        """The acked=True counterpart pinning the gate's polarity."""
        assert (
            self._handle(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                },
                acked=True,
            )
            is None
        )
        assert "notifications/tools/list_changed" in capsys.readouterr().out

    def test_empty_honored_subset_still_establishes(self, capsys):
        """Boundary pin for the round-6 validation: `notifications: {}` is
        a VALID "nothing honored" ack — the server spoke the protocol, so
        it establishes (and logs the subset divergence)."""
        state = {}
        assert (
            self._handle(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/subscriptions/acknowledged",
                    "params": {"notifications": {}},
                },
                state=state,
            )
            == "ack"
        )
        assert state["honored"] == {}
        assert "honored a subset" in capsys.readouterr().err


class TestListenStreamLoop:
    """Unit tests for the listen reader loop, driven synchronously (no
    threads, no wall-clock sleeps — reconnect tests patch RETRY_DELAY to 0
    and the loop's stop.wait pattern honors it immediately)."""

    URL = "https://example.com/mcp"

    def _sse(self, *messages):
        return IteratorStream(
            [f"event: message\ndata: {json.dumps(m)}\n\n".encode() for m in messages]
        )

    def _ack(self, honored=None):
        return {
            "jsonrpc": "2.0",
            "method": "notifications/subscriptions/acknowledged",
            "params": {
                "notifications": honored
                if honored is not None
                else {
                    "toolsListChanged": True,
                    "promptsListChanged": True,
                    "resourcesListChanged": True,
                }
            },
        }

    def _graceful(self, attempt=1):
        return {
            "jsonrpc": "2.0",
            "id": f"mcp-stdio/listen/{attempt}",
            "result": {"resultType": "complete"},
        }

    def _default_params(self):
        state = _ModernState()
        state.negotiated_version = "2026-07-28"
        state.client_capabilities = {"experimental": {}}
        return _build_listen_params(state)

    def _run_loop(
        self,
        *,
        stop=None,
        state=None,
        prepare_headers=None,
        tracker=None,
        params=None,
    ):
        client = httpx.Client()
        try:
            _listen_stream_loop(
                client=client,
                url=self.URL,
                params=params if params is not None else self._default_params(),
                prepare_headers=prepare_headers
                or (lambda body: {"Content-Type": "application/json"}),
                tracker=tracker,
                stop=stop or threading.Event(),
                timeout=httpx.Timeout(connect=10, read=300, write=30, pool=10),
                state=state,
            )
        finally:
            client.close()

    def test_happy_path_forwards_only_stripped_list_changed(self, httpx_mock):
        """Design test 1: the ack is consumed (honored subset recorded,
        nothing on stdout for it), the three list_changed notifications
        reach stdout with subscriptionId stripped (empty _meta dropped),
        and the terminal result ends the stream silently."""
        tools_changed = {
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/subscriptionId": "s-1",
                    "keep": 1,
                }
            },
        }
        prompts_changed = {
            "jsonrpc": "2.0",
            "method": "notifications/prompts/list_changed",
            "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": "s-1"}},
        }
        resources_changed = {
            "jsonrpc": "2.0",
            "method": "notifications/resources/list_changed",
        }
        httpx_mock.add_response(
            stream=self._sse(
                self._ack(),
                tools_changed,
                prompts_changed,
                resources_changed,
                self._graceful(),
            ),
            headers={"content-type": "text/event-stream"},
        )
        stdout = StringIO()
        state = {}
        with patch("sys.stdout", stdout):
            self._run_loop(state=state)
        lines = [json.loads(line) for line in stdout.getvalue().strip().split("\n")]
        assert len(lines) == 3  # ack and the terminal result never forwarded
        assert lines[0]["method"] == "notifications/tools/list_changed"
        assert lines[0]["params"]["_meta"] == {"keep": 1}
        assert lines[1]["method"] == "notifications/prompts/list_changed"
        assert "_meta" not in lines[1]["params"]
        assert lines[2] == resources_changed
        assert state["honored"] == {
            "toolsListChanged": True,
            "promptsListChanged": True,
            "resourcesListChanged": True,
        }
        assert len(httpx_mock.get_requests()) == 1  # graceful: no reconnect

    def test_loop_swallows_unadvertised_family_forwards_advertised(self, httpx_mock):
        """#352 round-3 finding 2 through the real loop: the state carrier
        run() seeds gates forwarding — with only the tools family
        advertised, a resources list_changed on the stream is swallowed
        while the tools one reaches stdout."""
        resources_changed = {
            "jsonrpc": "2.0",
            "method": "notifications/resources/list_changed",
        }
        tools_changed = {
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
        }
        httpx_mock.add_response(
            stream=self._sse(
                self._ack(),
                resources_changed,
                tools_changed,
                self._graceful(),
            ),
            headers={"content-type": "text/event-stream"},
        )
        stdout = StringIO()
        state = {"advertised": frozenset({"tools"})}
        with patch("sys.stdout", stdout):
            self._run_loop(state=state)
        lines = [json.loads(line) for line in stdout.getvalue().strip().split("\n")]
        assert lines == [tools_changed]
        assert len(httpx_mock.get_requests()) == 1

    def test_graceful_result_stops_without_reconnect(self, httpx_mock):
        httpx_mock.add_response(
            stream=self._sse(self._graceful()),
            headers={"content-type": "text/event-stream"},
        )
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            self._run_loop()
        assert stdout.getvalue() == ""
        assert len(httpx_mock.get_requests()) == 1

    def test_graceful_cancelled_notification_stops_without_reconnect(self, httpx_mock):
        """The OTHER graceful signal (the cancellation pattern's MUST): a
        server honoring only notifications/cancelled must not look like an
        abrupt drop and be reconnect-looped."""
        cancelled = {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "mcp-stdio/listen/1"},
        }
        httpx_mock.add_response(
            stream=self._sse(cancelled),
            headers={"content-type": "text/event-stream"},
        )
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            self._run_loop()
        assert stdout.getvalue() == ""
        assert len(httpx_mock.get_requests()) == 1

    def test_json_200_graceful_result_is_a_legal_immediate_end(self, httpx_mock):
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(self._graceful()),
            headers={"content-type": "application/json"},
        )
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            self._run_loop()
        assert stdout.getvalue() == ""
        assert len(httpx_mock.get_requests()) == 1

    def test_stream_end_without_signal_reconnects_with_reminted_id(self, httpx_mock):
        """Design test 3: an abrupt drop (stream end with neither graceful
        signal) reconnects — with a re-minted id and the SAME frozen body
        (C1)."""
        httpx_mock.add_response(
            stream=self._sse(self._ack()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            stream=self._sse(self._graceful(attempt=2)),
            headers={"content-type": "text/event-stream"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop()
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        body1 = json.loads(requests[0].content)
        body2 = json.loads(requests[1].content)
        assert body1["id"] == "mcp-stdio/listen/1"
        assert body2["id"] == "mcp-stdio/listen/2"
        assert {k: v for k, v in body1.items() if k != "id"} == {
            k: v for k, v in body2.items() if k != "id"
        }

    def test_http_error_after_establishment_reconnects_forever_arm(self, httpx_mock):
        """Design test 3, exception variant: after a first successful
        establishment an httpx.HTTPError is a drop, not a death — the loop
        re-mints the id and tries again (fixed stop.wait(RETRY_DELAY)
        backoff, patched to 0 here)."""
        httpx_mock.add_response(
            stream=self._sse(self._ack()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_exception(httpx.ReadError("boom"), url=self.URL)
        httpx_mock.add_response(
            stream=self._sse(self._graceful(attempt=3)),
            headers={"content-type": "text/event-stream"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop()
        requests = httpx_mock.get_requests()
        assert len(requests) == 3
        assert json.loads(requests[2].content)["id"] == "mcp-stdio/listen/3"

    def test_http_error_before_establishment_fails_fast(self, httpx_mock, capsys):
        """C7's established split: before ANY success, a transport error is
        far more likely non-support than a blip — one POST, loud stderr,
        thread exits, no retry."""
        httpx_mock.add_exception(httpx.ConnectError("refused"), url=self.URL)
        with patch("sys.stdout", StringIO()):
            self._run_loop()
        assert len(httpx_mock.get_requests()) == 1
        assert "before it was ever established" in capsys.readouterr().err

    def test_non_200_before_establishment_fails_fast(self, httpx_mock, capsys):
        httpx_mock.add_response(url=self.URL, status_code=503, text="")
        with patch("sys.stdout", StringIO()):
            self._run_loop()
        assert len(httpx_mock.get_requests()) == 1
        assert "before the stream was ever established" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "body,content_type",
        [
            ("", "text/plain"),
            ("<html><body>It works!</body></html>", "text/html"),
            ("OK", "application/json"),
        ],
    )
    def _add_regression_escape_hatch(self, httpx_mock):
        """Bound the fail-fast tests against their own regression.

        On the fixed loop this optional graceful response is never
        consumed (the ack-less 200 fail-fasts after one POST). On a
        regressed loop — 200 counting as establishment again — attempt 2
        would otherwise find NO registered response, get pytest-httpx's
        synthesized timeout, classify it as a post-establishment drop and
        spin forever: the suite would HANG instead of failing. The hatch
        ends a regressed loop at attempt 2, so the request-count assert
        fails loudly instead."""
        httpx_mock.add_response(
            url=self.URL,
            stream=self._sse(self._graceful(attempt=2)),
            headers={"content-type": "text/event-stream"},
            is_optional=True,
        )

    @pytest.mark.parametrize(
        "body,content_type",
        [
            ("", "text/plain"),
            ("<html><body>It works!</body></html>", "text/html"),
            ("OK", "application/json"),
        ],
    )
    def test_200_without_ack_fails_fast(self, httpx_mock, capsys, body, content_type):
        """#352 round-5 finding 2: an unsupported/misrouted endpoint
        answering the listen POST with a generic 200 (empty body, a
        default HTML page, junk) used to count as "established" and flip
        the loop into the reconnect-forever arm — POSTing at 1 Hz forever
        against an endpoint that never spoke the protocol. Establishment
        is now the acknowledgement, so this is a pre-establishment
        failure: exactly one POST, one loud stderr line, no retry."""
        httpx_mock.add_response(
            url=self.URL, text=body, headers={"content-type": content_type}
        )
        self._add_regression_escape_hatch(httpx_mock)
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop()
        assert len(httpx_mock.get_requests()) == 1
        err = capsys.readouterr().err
        assert err.count("before the stream was ever established") == 1
        assert "disabled for this session" in err

    def test_200_sse_closing_without_ack_fails_fast(self, httpx_mock, capsys):
        """#352 round-5 finding 2, SSE shape: a 200 text/event-stream that
        closes without ever sending the acknowledgement — even one that
        carried unrelated messages first (a non-ack message is NOT
        establishment evidence) — is equally pre-establishment: exactly
        one POST, loud stderr once, no reconnect loop."""
        unrelated = {"jsonrpc": "2.0", "method": "notifications/message", "params": {}}
        httpx_mock.add_response(
            stream=self._sse(unrelated),
            headers={"content-type": "text/event-stream"},
        )
        self._add_regression_escape_hatch(httpx_mock)
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop()
        assert len(httpx_mock.get_requests()) == 1
        err = capsys.readouterr().err
        assert err.count("before the stream was ever established") == 1
        assert "disabled for this session" in err

    def test_established_then_ackless_junk_reconnect_keeps_retrying(
        self, httpx_mock, capsys
    ):
        """#352 round-5 finding 2, the once-per-THREAD pin: after a real
        establishment (ack observed), a reconnect answered with an
        ack-less junk 200 is a transient blip (LB flap, mid-deploy proxy
        page) from a server that already proved it speaks the protocol —
        C7's infinite patience applies, so the loop keeps retrying instead
        of fail-fasting per-attempt (a genuine loss of support still
        terminates via the C6 terminal arms)."""
        httpx_mock.add_response(
            stream=self._sse(self._ack()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url=self.URL,
            text="<html><body>503 backend flapping, says the LB</body></html>",
            headers={"content-type": "text/html"},
        )
        httpx_mock.add_response(
            stream=self._sse(self._graceful(attempt=3)),
            headers={"content-type": "text/event-stream"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop()
        requests = httpx_mock.get_requests()
        assert len(requests) == 3
        assert json.loads(requests[2].content)["id"] == "mcp-stdio/listen/3"
        assert "disabled" not in capsys.readouterr().err

    def test_auth_failures_before_establishment_retry_with_fresh_headers(
        self, httpx_mock, capsys
    ):
        """#352 round-2 finding 1 (C3 over C7): 401/403 are ALWAYS
        retryable drops, even before the stream was ever established —
        auth heals externally (the main loop / proactive-refresh daemon
        refreshes credentials) and each attempt's fresh _prepare_headers
        snapshot picks the refresh up. The pre-establishment fail-fast
        must not eat them: a token expiring between initialize and the
        first listen POST would otherwise disable the stream permanently.
        401 then 403 then 200 — the stream establishes on the third
        attempt, each carrying that attempt's fresh credentials."""
        calls = []

        def prepare_headers(body):
            calls.append(body)
            return {"Authorization": f"Bearer t{len(calls)}"}

        httpx_mock.add_response(url=self.URL, status_code=401, text="")
        httpx_mock.add_response(url=self.URL, status_code=403, text="")
        httpx_mock.add_response(
            stream=self._sse(self._graceful(attempt=3)),
            headers={"content-type": "text/event-stream"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop(prepare_headers=prepare_headers)
        requests = httpx_mock.get_requests()
        assert len(requests) == 3
        assert requests[0].headers["authorization"] == "Bearer t1"
        assert requests[1].headers["authorization"] == "Bearer t2"
        assert requests[2].headers["authorization"] == "Bearer t3"
        # Never the fail-fast/terminal wording — auth is not non-support.
        assert "disabled" not in capsys.readouterr().err

    def test_401_after_establishment_reconnects_with_fresh_headers(self, httpx_mock):
        """C2/C3: a 401 mid-session is a drop (NO auth recovery runs on
        this thread), and the next attempt's fresh _prepare_headers
        snapshot picks up whatever the main loop / proactive daemon
        refreshed in the meantime."""
        calls = []

        def prepare_headers(body):
            calls.append(body)
            return {"Authorization": f"Bearer t{len(calls)}"}

        httpx_mock.add_response(
            stream=self._sse(self._ack()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(url=self.URL, status_code=401, text="")
        httpx_mock.add_response(
            stream=self._sse(self._graceful(attempt=3)),
            headers={"content-type": "text/event-stream"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop(prepare_headers=prepare_headers)
        requests = httpx_mock.get_requests()
        assert len(requests) == 3
        assert requests[0].headers["authorization"] == "Bearer t1"
        assert requests[1].headers["authorization"] == "Bearer t2"
        assert requests[2].headers["authorization"] == "Bearer t3"

    def test_404_with_method_not_found_terminal_one_post(self, httpx_mock, capsys):
        """Design test 4 / C6: 404 + a -32601 body is the remote saying the
        method does not exist — exactly one POST, loud stderr, no retry.
        (#352 round-3 finding 1 unified the non-200 terminal wording with
        the on-stream classifier's "rejected subscriptions/listen".)"""
        httpx_mock.add_response(
            url=self.URL,
            status_code=404,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        with patch("sys.stdout", StringIO()):
            self._run_loop()
        assert len(httpx_mock.get_requests()) == 1
        assert "rejected subscriptions/listen" in capsys.readouterr().err

    def test_404_method_not_found_terminal_even_after_establishment(
        self, httpx_mock, capsys
    ):
        """C6 beats the reconnect-forever arm: a deterministic -32601
        rejection is terminal even mid-session (a server may drop the
        method on redeploy) — retrying at 1 Hz forever would hammer a
        server that will never say yes."""
        httpx_mock.add_response(
            stream=self._sse(self._ack()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url=self.URL,
            status_code=404,
            text=json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32601}}),
            headers={"content-type": "application/json"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop()
        assert len(httpx_mock.get_requests()) == 2
        assert "rejected subscriptions/listen" in capsys.readouterr().err

    def test_post_establishment_terminal_body_stops_for_good(self, httpx_mock, capsys):
        """#352 round-3 finding 1: after a successful establishment, a
        reconnect answered HTTP 400 with a -32020 JSON-RPC body is the
        server deterministically rejecting THIS request (C6), not an
        abrupt drop — round 2's split read only 404 bodies, so this exact
        response was reconnect-looped at 1 Hz forever against a server
        that will never say yes. Exactly two POSTs (establish + rejected
        reconnect), one loud stderr line, no further attempts."""
        httpx_mock.add_response(
            stream=self._sse(self._ack()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url=self.URL,
            status_code=400,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32020, "message": "header mismatch"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop()
        assert len(httpx_mock.get_requests()) == 2
        assert capsys.readouterr().err.count("rejected subscriptions/listen") == 1

    def test_post_establishment_unparseable_non_200_still_retries(self, httpx_mock):
        """#352 round-3 finding 1, the pinned complement: a non-200 whose
        body does NOT parse to a terminal JSON-RPC error keeps the round-2
        behavior exactly — post-establishment it is an abrupt drop,
        reconnected with a re-minted id."""
        httpx_mock.add_response(
            stream=self._sse(self._ack()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(url=self.URL, status_code=400, text="Bad Request")
        httpx_mock.add_response(
            stream=self._sse(self._graceful(attempt=3)),
            headers={"content-type": "text/event-stream"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop()
        requests = httpx_mock.get_requests()
        assert len(requests) == 3
        assert json.loads(requests[2].content)["id"] == "mcp-stdio/listen/3"

    def test_pre_establishment_terminal_body_logs_rejection_not_fail_fast(
        self, httpx_mock, capsys
    ):
        """#352 round-3 finding 1: the terminal-body classification runs
        BEFORE the pre-establishment fail-fast, so a first-attempt 400
        with a -32021 body is reported as the server's deterministic
        rejection (C6), not the generic fail-fast — same one-POST outcome,
        but the stderr line carries the real verdict."""
        httpx_mock.add_response(
            url=self.URL,
            status_code=400,
            text=json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32021}}),
            headers={"content-type": "application/json"},
        )
        with patch("sys.stdout", StringIO()):
            self._run_loop()
        assert len(httpx_mock.get_requests()) == 1
        err = capsys.readouterr().err
        assert "rejected subscriptions/listen" in err
        assert "before the stream was ever established" not in err

    def test_error_result_terminal_one_post(self, httpx_mock, capsys):
        """Design test 4, error-result variant: a -32601 error result on a
        200 (JSON-RPC-over-HTTP convention) is equally terminal."""
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "mcp-stdio/listen/1",
                    "error": {"code": -32601, "message": "Method not found"},
                }
            ),
            headers={"content-type": "application/json"},
        )
        with patch("sys.stdout", StringIO()):
            self._run_loop()
        assert len(httpx_mock.get_requests()) == 1
        assert "rejected subscriptions/listen" in capsys.readouterr().err

    def test_body_frozen_headers_fresh_across_reconnects(self, httpx_mock):
        """Design test 5 (C1 x C2): log_level (and even the capability set)
        mutated mid-stream must NOT change the reconnect body — only the id
        is re-minted — while the headers ARE re-read fresh per attempt."""
        state = _ModernState()
        state.negotiated_version = "2026-07-28"
        state.client_capabilities = {"experimental": {}}
        params = _build_listen_params(state)
        calls = []

        def prepare_headers(body):
            calls.append(body)
            # Simulate mid-session mutations the stdin loop performs:
            # logging/setLevel rewrites log_level on every line, and a
            # re-initialize replaces the capability set.
            state.log_level = "debug"
            state.client_capabilities = {"mutated": True}
            return {"Authorization": f"Bearer t{len(calls)}"}

        httpx_mock.add_response(
            stream=self._sse(self._ack()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            stream=self._sse(self._graceful(attempt=2)),
            headers={"content-type": "text/event-stream"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop(params=params, prepare_headers=prepare_headers)
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        body1 = json.loads(requests[0].content)
        body2 = json.loads(requests[1].content)
        assert {k: v for k, v in body1.items() if k != "id"} == {
            k: v for k, v in body2.items() if k != "id"
        }
        meta2 = body2["params"]["_meta"]
        assert "io.modelcontextprotocol/logLevel" not in meta2
        assert meta2["io.modelcontextprotocol/clientCapabilities"] == {
            "experimental": {}
        }
        assert requests[0].headers["authorization"] == "Bearer t1"
        assert requests[1].headers["authorization"] == "Bearer t2"

    def test_reconnect_header_version_pinned_to_frozen_body(self, httpx_mock):
        """#352 review finding 2 (the C1 x C2 interaction): the real
        modern _prepare_headers stamps MCP-Protocol-Version from the
        MUTABLE modern_state.negotiated_version, so after a client-driven
        re-initialize renegotiates mid-session, a reconnect's fresh header
        snapshot (C2) would carry the NEW version while the frozen body
        (C1) still carries the old one. A compliant server rejects the
        divergence as HeaderMismatch -32020 — one of the C6 terminal
        codes, so listening would be PERMANENTLY disabled by a mere
        renegotiation. Every attempt's MCP-Protocol-Version must equal the
        version frozen inside the body snapshot (any case-variant from
        the snapshot replaced — one header line only), while credentials
        from the same fresh snapshot keep flowing (C2's actual point)."""
        state = _ModernState()
        state.negotiated_version = "2026-07-28"
        state.client_capabilities = {}
        params = _build_listen_params(state)
        calls = []

        def prepare_headers(body):
            # Mimic the real modern _prepare_headers: the version comes
            # from the mutable state — renegotiated between attempts as a
            # second initialize would — under a case-variant key to also
            # pin the strip-then-set discipline.
            calls.append(body)
            state.negotiated_version = f"2099-01-0{len(calls)}"
            return {
                "Authorization": f"Bearer t{len(calls)}",
                "mcp-protocol-version": state.negotiated_version,
            }

        httpx_mock.add_response(
            stream=self._sse(self._ack()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            stream=self._sse(self._graceful(attempt=2)),
            headers={"content-type": "text/event-stream"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", StringIO()),
        ):
            self._run_loop(params=params, prepare_headers=prepare_headers)
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        for req in requests:
            # Pinned to the frozen body version — never the mutated state
            # the snapshot callable returned — and never two header lines.
            assert req.headers.get_list("mcp-protocol-version") == ["2026-07-28"]
            meta = json.loads(req.content)["params"]["_meta"]
            assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
        # C2 intact: the reconnect still picked up the fresh credentials.
        assert requests[1].headers["authorization"] == "Bearer t2"

    def test_attempt_headers_accept_override_mcp_method_no_name(self, httpx_mock):
        """Spec item 4: every attempt carries the dual Accept (any pinned
        case-variant replaced), Mcp-Method: subscriptions/listen, and no
        Mcp-Name."""
        httpx_mock.add_response(
            stream=self._sse(self._graceful()),
            headers={"content-type": "text/event-stream"},
        )
        with patch("sys.stdout", StringIO()):
            self._run_loop(
                prepare_headers=lambda body: {
                    "Content-Type": "application/json",
                    "accept": "text/plain",
                }
            )
        req = httpx_mock.get_requests()[0]
        assert req.headers.get_list("accept") == ["application/json, text/event-stream"]
        assert req.headers["mcp-method"] == "subscriptions/listen"
        assert "mcp-name" not in req.headers

    def test_stdout_oserror_is_terminal(self, httpx_mock, capsys):
        """C12: a BrokenPipeError from _emit (client closed stdout) must end
        the thread — reconnecting the upstream stream into a dead stdout
        would spin forever."""

        class _DeadStdout:
            def write(self, s):
                raise BrokenPipeError("stdout closed")

            def flush(self):
                pass

        tools_changed = {
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
        }
        httpx_mock.add_response(
            stream=self._sse(self._ack(), tools_changed),
            headers={"content-type": "text/event-stream"},
        )
        with (
            patch("mcp_stdio.relay.RETRY_DELAY", 0),
            patch("sys.stdout", _DeadStdout()),
        ):
            self._run_loop()
        assert len(httpx_mock.get_requests()) == 1
        assert "stdout write failed" in capsys.readouterr().err

    def test_unknown_messages_swallowed_not_forwarded(self, httpx_mock):
        """Whitelist semantics: an unrelated notification, a
        server-initiated request, a foreign response — and an id-bearing
        message under a WHITELISTED method, which JSON-RPC 2.0 makes a
        request, not a notification (#352 round-2 finding 3) — are all
        consumed silently; only true list_changed notifications may reach
        stdout."""
        httpx_mock.add_response(
            stream=self._sse(
                {"jsonrpc": "2.0", "method": "notifications/message", "params": {}},
                {"jsonrpc": "2.0", "id": 9, "method": "ping"},
                {"jsonrpc": "2.0", "id": 7, "result": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 13,
                    "method": "notifications/tools/list_changed",
                },
                self._graceful(),
            ),
            headers={"content-type": "text/event-stream"},
        )
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            self._run_loop()
        assert stdout.getvalue() == ""
        assert len(httpx_mock.get_requests()) == 1

    def test_stop_preset_makes_no_post(self, httpx_mock):
        """Shutdown responsiveness: a stop set before the first attempt
        produces zero network traffic (loop-top check)."""
        stop = threading.Event()
        stop.set()
        self._run_loop(stop=stop)
        assert len(httpx_mock.get_requests()) == 0

    def test_closed_client_runtimeerror_without_stop_reraises(self, httpx_mock):
        """#352 round-5 finding 1, the deliberate complement: with stop
        NOT set, a closed-client RuntimeError has no legitimate producer —
        run()'s finally is the ONLY closer of the dedicated client, and it
        sets stop before closing — so the loop re-raises it loudly instead
        of mapping it to a drop/return arm: swallowing would mask a real
        logic bug as a silent thread death."""
        client = httpx.Client()
        client.close()
        with pytest.raises(RuntimeError, match="has been closed"):
            _listen_stream_loop(
                client=client,
                url=self.URL,
                params=self._default_params(),
                prepare_headers=lambda body: {"Content-Type": "application/json"},
                tracker=None,
                stop=threading.Event(),
                timeout=httpx.Timeout(connect=10, read=300, write=30, pool=10),
                state=None,
            )
        assert len(httpx_mock.get_requests()) == 0


# --- modern era: resource subscriptions (#270 Phase 2 PR B) ---


class TestResourceSubscriptions:
    """The URI-set holder the stdin loop writes and the resource listen
    thread reads (base change 3)."""

    def test_add_bumps_the_generation_once_per_new_uri(self):
        subs = _ResourceSubscriptions()
        assert subs.generation == 0
        assert subs.add("file:///a") == "added"
        assert subs.snapshot() == (frozenset({"file:///a"}), 1)

    def test_duplicate_add_neither_changes_the_set_nor_the_generation(self):
        """The coalescing guarantee depends on this: a duplicate subscribe
        must not look like a change, or every repeat would reopen the
        stream for nothing."""
        subs = _ResourceSubscriptions()
        subs.add("file:///a")
        assert subs.add("file:///a") == "duplicate"
        assert subs.snapshot() == (frozenset({"file:///a"}), 1)

    def test_cap_refuses_new_uris_and_keeps_the_old_ones(self):
        """Design A6 — `_MRTR_MAX_TXNS` semantics: cap, not TTL; at the cap
        the NEW subscription fails and the older ones survive."""
        subs = _ResourceSubscriptions()
        for n in range(_LISTEN_MAX_SUBSCRIPTIONS):
            assert subs.add(f"file:///r{n}") == "added"
        assert subs.add("file:///over") == "refused"
        uris, generation = subs.snapshot()
        assert len(uris) == _LISTEN_MAX_SUBSCRIPTIONS
        assert "file:///over" not in uris
        assert generation == _LISTEN_MAX_SUBSCRIPTIONS  # the refusal bumped nothing

    def test_discard_reports_whether_anything_changed(self):
        subs = _ResourceSubscriptions()
        subs.add("file:///a")
        assert subs.discard("file:///never") is False
        assert subs.snapshot()[1] == 1
        assert subs.discard("file:///a") is True
        assert subs.snapshot() == (frozenset(), 2)

    def test_snapshot_is_immutable_and_wholesale(self):
        """Published as a frozenset so a racing reader sees the old set or
        the new one, never a half-mutated one (the `_SseState.endpoint_url`
        GIL-atomic-publish precedent)."""
        subs = _ResourceSubscriptions()
        subs.add("file:///a")
        first = subs.snapshot()[0]
        subs.add("file:///b")
        assert first == frozenset({"file:///a"})
        assert isinstance(first, frozenset)

    def test_close_response_closes_and_forgets_the_published_handle(self):
        closed = []

        class FakeResponse:
            def close(self):
                closed.append(True)

        subs = _ResourceSubscriptions()
        subs.publish_response(FakeResponse())
        subs.close_response()
        subs.close_response()  # nothing published any more: no second close
        assert closed == [True]

    def test_close_response_never_raises_into_the_stdin_loop(self, capsys):
        """The stdin loop must never break because a response the reader
        already finished with refused to close — the reopen still happens
        through the restart event."""

        class ExplodingResponse:
            def close(self):
                raise RuntimeError("already closed")

        subs = _ResourceSubscriptions()
        subs.publish_response(ExplodingResponse())
        subs.close_response()
        assert "already closed" in capsys.readouterr().err


class TestWithResourceSubscriptions:
    LIST_CHANGED_FILTER = {
        "toolsListChanged": True,
        "promptsListChanged": True,
        "resourcesListChanged": True,
    }

    def _base(self):
        state = _ModernState()
        state.negotiated_version = "2026-07-28"
        return _build_listen_params(state)

    def test_subscriptions_are_nested_inside_the_notifications_filter(self):
        """Design A9, the shape pin. The spec's Notification Filter table
        lists `resourceSubscriptions: string[]` as a FIELD of the
        `notifications` object — its own `subscriptions/listen` example
        nests it there, and so does the acknowledgement example. A
        top-level placement is not rejected by a compliant server, it is
        silently IGNORED, which would leave the relay subscribed to
        nothing while reading every URI back as unhonored: two silent
        no-ops that cancel out into "no updates, no diagnosis"."""
        overlaid = _with_resource_subscriptions(self._base(), frozenset({"b", "a"}))
        assert overlaid["notifications"] == {"resourceSubscriptions": ["a", "b"]}
        assert "resourceSubscriptions" not in overlaid

    def test_the_filter_is_replaced_not_merged(self):
        """Design A9's second half: this stream requests
        `resourceSubscriptions` and NOTHING else. "The server MUST NOT
        send notification types the client has not explicitly requested",
        so asking for the list_changed kinds here would invite the server
        to send — and this relay to have to drop — every one of them
        twice, once per concurrent stream."""
        base = self._base()
        assert base["notifications"] == self.LIST_CHANGED_FILTER
        overlaid = _with_resource_subscriptions(base, frozenset({"a"}))
        assert set(overlaid["notifications"]) == {"resourceSubscriptions"}

    def test_frozen_meta_is_reused_by_reference_and_the_base_untouched(self):
        """Base changes 2/4: `_meta` is carried over from the FROZEN
        snapshot because `_listen_stream_loop` pins every attempt's
        MCP-Protocol-Version header to the version inside it (#352 review
        finding 2) — a re-derived `_meta` could renegotiate the body
        version out from under the pinned header and earn a terminal
        -32020."""
        base = self._base()
        overlaid = _with_resource_subscriptions(base, frozenset({"a"}))
        assert overlaid["_meta"] is base["_meta"]
        # The frozen snapshot itself is never mutated.
        assert base["notifications"] == self.LIST_CHANGED_FILTER

    def test_empty_set_produces_an_empty_list(self):
        overlaid = _with_resource_subscriptions(self._base(), frozenset())
        assert overlaid["notifications"] == {"resourceSubscriptions": []}


class TestConsumeRestart:
    """Design A4: stop ALWAYS wins over a pending reopen."""

    def test_consumes_and_clears_a_pending_restart(self):
        stop, restart = threading.Event(), threading.Event()
        restart.set()
        assert _consume_restart(stop, restart) is True
        assert not restart.is_set()

    def test_stop_wins_and_leaves_the_restart_untouched(self):
        """Revert-check for A4: without the stop check, run()'s teardown
        (stop, then the client close, then the restart that wakes a parked
        thread) reads as a subscription change and the dying thread
        reopens against a closed client."""
        stop, restart = threading.Event(), threading.Event()
        stop.set()
        restart.set()
        assert _consume_restart(stop, restart) is False
        assert restart.is_set()

    def test_no_restart_event_is_never_a_reopen(self):
        assert _consume_restart(threading.Event(), None) is False


class TestResourceSubscriptionInterception:
    """`_handle_modern_special_method`'s PR B branches."""

    URI = "file:///a.txt"

    def _line(self, method="resources/subscribe", req_id=1, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if req_id is not None:
            msg["id"] = req_id
        msg["params"] = {"uri": self.URI} if params is None else params
        return json.dumps(msg)

    def test_subscribe_is_answered_with_the_legacy_empty_result(self):
        calls = []
        handled, reply = _handle_modern_special_method(
            self._line(),
            1,
            _ModernState(),
            resource_subscription=lambda m, u, i: calls.append((m, u, i)) or True,
        )
        assert handled is True
        assert json.loads(reply) == {"jsonrpc": "2.0", "id": 1, "result": {}}
        assert calls == [("resources/subscribe", self.URI, 1)]

    def test_unsubscribe_is_answered_the_same_way(self):
        handled, reply = _handle_modern_special_method(
            self._line(method="resources/unsubscribe", req_id=4),
            4,
            _ModernState(),
            resource_subscription=lambda m, u, i: True,
        )
        assert handled is True
        assert json.loads(reply)["result"] == {}

    def test_no_hook_keeps_the_pre_pr_b_forward_behavior(self):
        """The legacy era passes no hook, so its wire bytes are untouched
        (AC 3) — and so is any direct caller written before PR B."""
        assert _handle_modern_special_method(self._line(), 1, _ModernState()) == (
            False,
            None,
        )

    def test_a_declining_hook_falls_through_to_the_caller(self):
        """Design A1: the hook declines for an id the stdin loop's intake
        guards are about to reject, and the line must then take the
        ordinary path so exactly ONE response reaches the client."""
        assert _handle_modern_special_method(
            self._line(req_id="mcp-stdio/mrtr/1/a"),
            "mcp-stdio/mrtr/1/a",
            _ModernState(),
            resource_subscription=lambda m, u, i: False,
        ) == (False, None)

    @pytest.mark.parametrize(
        "params", [None, {}, {"uri": ""}, {"uri": 42}, "not-an-object"]
    )
    def test_malformed_uri_is_not_answered_locally(self, params):
        """A synthesized success must never stand in for a request the
        relay could not actually carry out; such a line falls through."""
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/subscribe",
                "params": params,
            }
        )
        assert _handle_modern_special_method(
            line,
            1,
            _ModernState(),
            resource_subscription=lambda m, u, i: True,
        ) == (False, None)

    def test_a_notification_shaped_subscribe_is_not_answered(self):
        """No id means no response may be written at all (JSON-RPC), so
        there is nothing to synthesize — the line falls through."""
        assert _handle_modern_special_method(
            self._line(req_id=None),
            None,
            _ModernState(),
            resource_subscription=lambda m, u, i: True,
        ) == (False, None)

    def test_subscribe_capability_unioned_only_onto_a_seeded_resources_family(self):
        """Implementation spec 2 under the C8 narrowing: `subscribe: true`
        joins `listChanged: true` on a `resources` family the discover
        seed already contained — and an absent family is still never
        fabricated, because a capabilities object's mere presence
        advertises the whole feature family."""
        seeded = _ModernState()
        seeded.capabilities = {"tools": {}, "resources": {}}
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2026-07-28", "capabilities": {}},
            }
        )
        caps = json.loads(_handle_modern_special_method(line, 1, seeded)[1])["result"][
            "capabilities"
        ]
        assert caps["resources"] == {"listChanged": True, "subscribe": True}
        assert caps["tools"] == {"listChanged": True}  # never on other families

        unseeded = _ModernState()
        unseeded.capabilities = {"tools": {}}
        caps = json.loads(_handle_modern_special_method(line, 1, unseeded)[1])[
            "result"
        ]["capabilities"]
        assert "resources" not in caps


class TestHandleListenResourceUpdated:
    """`notifications/resources/updated`'s own forwarding branch (base
    changes 4 and 6)."""

    LISTEN_ID = "mcp-stdio/listen-res/1"
    URI = "file:///a.txt"

    def _state(self, **overrides):
        state = {
            "resource_stream": True,
            "advertised": frozenset({"resources"}),
            "honored_resources": [self.URI],
            "uris": frozenset({self.URI}),
        }
        state.update(overrides)
        return state

    def _updated(self, uri=None, **extra):
        msg = {
            "jsonrpc": "2.0",
            "method": _RESOURCE_UPDATED_METHOD,
            "params": {"uri": uri if uri is not None else self.URI},
        }
        msg.update(extra)
        return json.dumps(msg)

    def _run(self, payload, state, acked=True):
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            outcome = _handle_listen_message(
                payload, self.LISTEN_ID, None, state, acked=acked
            )
        return outcome, stdout.getvalue()

    def test_forwarded_with_the_subscription_id_stripped(self):
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": _RESOURCE_UPDATED_METHOD,
                "params": {
                    "uri": self.URI,
                    "_meta": {
                        "io.modelcontextprotocol/subscriptionId": "s-1",
                        "keep": 1,
                    },
                },
            }
        )
        outcome, out = self._run(payload, self._state())
        assert outcome is None
        emitted = json.loads(out)
        assert emitted["params"]["uri"] == self.URI
        assert emitted["params"]["_meta"] == {"keep": 1}

    def test_pre_ack_notification_is_swallowed(self):
        """The acknowledgement is the spec-mandated FIRST stream message,
        so anything before it is a protocol violation — the same
        per-attempt rule the list_changed branch applies."""
        assert self._run(self._updated(), self._state(), acked=False)[1] == ""

    def test_id_bearing_message_is_swallowed(self):
        """An id makes it a JSON-RPC request the legacy client may answer,
        leaking a relay-internal interaction into the request path."""
        assert self._run(self._updated(id=9), self._state())[1] == ""

    def test_unadvertised_resources_family_is_swallowed(self):
        """The client only ever saw `subscribe: true` under a family the
        discover seed reported (the C8 narrowing) — forwarding without it
        would be exactly the un-negotiated-capability notification C8
        exists to prevent."""
        assert self._run(self._updated(), self._state(advertised=frozenset()))[1] == ""

    def test_absent_ack_echo_reads_as_unsupported(self):
        """Base change 5, defensive: the spec only defines type-level
        omission of the honored subset, so an absent `resourceSubscriptions`
        echo means the feature is unsupported and nothing is forwarded.
        This is also what makes the branch inert on the list_changed
        stream, which never records the key."""
        assert self._run(self._updated(), self._state(honored_resources=None))[1] == ""

    def test_narrowed_ack_echo_suppresses_the_unhonored_uri(self):
        state = self._state(
            honored_resources=["file:///other"],
            uris=frozenset({self.URI, "file:///other"}),
        )
        assert self._run(self._updated(), state)[1] == ""

    def test_already_unsubscribed_uri_is_swallowed(self):
        """An `updated` racing an unsubscribe must not reach a client that
        already forgot the resource."""
        assert self._run(self._updated(), self._state(uris=frozenset()))[1] == ""

    def test_unseeded_carrier_forwards_nothing(self):
        assert self._run(self._updated(), None)[1] == ""

    def test_resource_stream_never_forwards_list_changed(self):
        """With TWO streams up both request all three list_changed kinds,
        so the role flag is what keeps a server that honors them on both
        from putting every list_changed on stdout twice — and the resource
        stream reopens on every subscribe, which would multiply it."""
        payload = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
        )
        state = self._state(advertised=frozenset({"tools", "resources"}), honored=None)
        assert self._run(payload, state)[1] == ""
        # The SAME message on the list_changed stream is forwarded.
        state["resource_stream"] = False
        assert json.loads(self._run(payload, state)[1])["method"].endswith(
            "list_changed"
        )

    def test_ack_records_the_resource_echo_and_stays_quiet_on_the_subset_log(
        self, capsys
    ):
        """The resource stream over-requests all three list_changed kinds
        (it reuses the frozen body) but forwards none, so a compliant
        server honoring none is not news — and it would otherwise be
        logged on every reopen, which happens on every subscribe."""
        ack = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "notifications/subscriptions/acknowledged",
                "params": {
                    "notifications": {"resourceSubscriptions": [self.URI]},
                },
            }
        )
        state = self._state()
        assert self._run(ack, state)[0] == "ack"
        assert state["honored_resources"] == [self.URI]
        assert "honored a subset" not in capsys.readouterr().err

    def test_malformed_ack_echo_sanitizes_non_string_elements(self, capsys):
        """#358 review R2F1: an ack echo containing a non-string element —
        e.g. a nested list — used to be stored verbatim, and
        `_log_unhonored_subscriptions`'s `set(honored)` then raised
        `TypeError: unhashable type: 'list'`, killing the daemon thread (no
        except arm in `_listen_stream_loop` catches a `TypeError`). The
        store site now keeps only the `str` elements, order preserved, so a
        broken/hostile server can only narrow what is treated as honored —
        never crash the stream."""
        ack = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "notifications/subscriptions/acknowledged",
                "params": {
                    "notifications": {
                        "resourceSubscriptions": [["file:///a"], self.URI, 42]
                    },
                },
            }
        )
        state = self._state()
        assert self._run(ack, state)[0] == "ack"
        # The consumer that used to crash on the raw, unsanitized list —
        # exercised BEFORE the storage assertion below, so a revert of the
        # sanitize surfaces here as the TypeError this fix prevents, not
        # merely as a value mismatch on the next line.
        attempt_params = {"notifications": {"resourceSubscriptions": [self.URI]}}
        _log_unhonored_subscriptions(state, attempt_params, "resource listen stream")
        assert capsys.readouterr().err == ""
        assert state["honored_resources"] == [self.URI]

    def test_malformed_ack_echo_non_list_reads_as_unsupported(self):
        """A non-list echo — e.g. a server sending
        `resourceSubscriptions: "file:///a.txt,other"` (a bare string
        instead of an array) — must not let `uri in honored` fall back to
        SUBSTRING matching against that string. It stores `None`, the same
        "feature unsupported" reading an absent field gets, so the
        forwarding gate correctly refuses to treat any URI as honored."""
        ack = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "notifications/subscriptions/acknowledged",
                "params": {
                    "notifications": {"resourceSubscriptions": f"{self.URI},other"},
                },
            }
        )
        state = self._state()
        assert self._run(ack, state)[0] == "ack"
        assert state["honored_resources"] is None
        # Would have substring-matched `self.URI` out of the raw string.
        assert self._run(self._updated(), state)[1] == ""

    def test_list_changed_stream_still_logs_the_subset_divergence(self, capsys):
        ack = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "notifications/subscriptions/acknowledged",
                "params": {"notifications": {"toolsListChanged": True}},
            }
        )
        state = {"honored": None, "advertised": None}
        assert self._run(ack, state)[0] == "ack"
        assert state["honored_resources"] is None
        assert "honored a subset" in capsys.readouterr().err

    def test_updated_is_not_a_cold_start_or_whitelist_member(self):
        """Base change 4: `_LISTEN_FORWARDED_NOTIFICATIONS` is SHARED with
        the cold-start gate, which both advertises and emits its members —
        an `updated` synthesized there would name no resource the client
        ever subscribed to."""
        assert _RESOURCE_UPDATED_METHOD not in _LISTEN_FORWARDED_NOTIFICATIONS
        assert _RESOURCE_UPDATED_METHOD not in _COLD_START_LIST_CHANGED

    def test_input_required_listen_result_is_not_a_graceful_end(self, capsys):
        """Design A3: `subscriptions/listen` is NOT MRTR-eligible, so an
        InputRequiredResult here is a server-side spec violation. It must
        not ALSO be misread as the graceful end, which would silently stop
        listening for the rest of the session — swallowed instead, so the
        stream takes the ordinary reconnect path. Logged once per stream."""
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self.LISTEN_ID,
                "result": {"resultType": "input_required", "requestState": "X"},
            }
        )
        state = self._state()
        assert self._run(payload, state)[0] is None
        assert self._run(payload, state)[0] is None
        assert capsys.readouterr().err.count("input_required result") == 1

    def test_on_stream_terminal_rejection_names_the_resource_stream(self, capsys):
        """The C6 terminal arm is reachable on BOTH streams, so its stderr
        line must name what actually stopped working — telling an operator
        that list_changed forwarding died when the RESOURCE stream gave up
        would send them after the wrong thing. Mirrors the loop's own
        label/disabled split."""
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self.LISTEN_ID,
                "error": {"code": -32601, "message": "Method not found"},
            }
        )
        assert self._run(payload, self._state())[0] == "terminal"
        err = capsys.readouterr().err
        assert "resource listen stream: server rejected" in err
        assert "resources/updated forwarding disabled" in err
        # The list_changed stream keeps PR A's wording byte-for-byte.
        assert (
            self._run(payload, {"honored": None, "advertised": None})[0] == "terminal"
        )
        err = capsys.readouterr().err
        assert "listen stream: server rejected" in err
        assert "list_changed forwarding disabled" in err

    def test_an_ordinary_listen_result_is_still_the_graceful_end(self):
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self.LISTEN_ID,
                "result": {"resultType": "complete"},
            }
        )
        assert self._run(payload, self._state())[0] == "graceful"


class _RecordingStop(threading.Event):
    """A stop event that records every backoff wait without blocking.

    The reopen path must never take `RETRY_DELAY` — a subscription change
    is the relay's own doing, not a drop — and an empty `waits` list is
    the only way to assert that without a wall-clock measurement.
    """

    def __init__(self):
        super().__init__()
        self.waits = []

    def wait(self, timeout=None):
        self.waits.append(timeout)
        return super().wait(0)


class TestResourceListenStreamLoop:
    """The second stream's own mechanics (base changes 1, 2, 4 and 5)."""

    URL = "https://example.com/mcp"

    def _sse(self, *messages):
        return IteratorStream(
            [f"event: message\ndata: {json.dumps(m)}\n\n".encode() for m in messages]
        )

    def _ack(self, honored=None, resources=None):
        """The acknowledgement, with the honored subscriptions nested
        INSIDE the `notifications` filter exactly as the spec's own
        example shows (`params.notifications.resourceSubscriptions`,
        Design A9)."""
        notifications = dict(honored) if honored is not None else {}
        if resources is not None:
            notifications["resourceSubscriptions"] = resources
        return {
            "jsonrpc": "2.0",
            "method": "notifications/subscriptions/acknowledged",
            "params": {"notifications": notifications},
        }

    def _graceful(self, attempt=1):
        return {
            "jsonrpc": "2.0",
            "id": f"{_LISTEN_RES_ID_PREFIX}{attempt}",
            "result": {"resultType": "complete"},
        }

    def _base_params(self):
        state = _ModernState()
        state.negotiated_version = "2026-07-28"
        return _build_listen_params(state)

    def _run_loop(
        self,
        *,
        uris,
        snapshot_gens=None,
        live_generation=0,
        stop=None,
        restart=None,
        state=None,
    ):
        """Drive the loop with a scripted per-attempt filter snapshot.

        ``uris`` and ``snapshot_gens`` are consumed one entry per ATTEMPT
        (the last entry repeats, so a single-entry list means "unchanged
        from here on"); ``live_generation`` is what the stdin thread's
        counter would read back at the post-ack staleness check.
        """
        base = self._base_params()
        uri_seq = list(uris)
        gen_seq = list(snapshot_gens if snapshot_gens is not None else [0])
        attempts = {"n": 0}

        def _at(seq, index):
            return seq[index] if index < len(seq) else seq[-1]

        def body_provider():
            index = attempts["n"]
            attempts["n"] += 1
            return (
                _with_resource_subscriptions(base, frozenset(_at(uri_seq, index))),
                _at(gen_seq, index),
            )

        def generation_reader():
            return live_generation

        client = httpx.Client()
        try:
            _listen_stream_loop(
                client=client,
                url=self.URL,
                params=base,
                prepare_headers=lambda body: {"Content-Type": "application/json"},
                tracker=None,
                stop=stop or threading.Event(),
                timeout=httpx.Timeout(connect=10, read=300, write=30, pool=10),
                state=state,
                id_prefix=_LISTEN_RES_ID_PREFIX,
                body_provider=body_provider,
                generation_reader=generation_reader,
                publish_response=None,
                restart=restart,
                label="resource listen stream",
            )
        finally:
            client.close()

    def test_attempt_body_carries_sorted_uris_under_the_res_prefix(self, httpx_mock):
        httpx_mock.add_response(
            url=self.URL,
            text=json.dumps(self._graceful()),
            headers={"content-type": "application/json"},
        )
        self._run_loop(uris=[["file:///b", "file:///a"]])
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["id"] == f"{_LISTEN_RES_ID_PREFIX}1"
        # Design A9 wire-shape pin: INSIDE the notifications filter, and
        # the filter carries NOTHING ELSE — the list_changed kinds are the
        # first stream's job ("The server MUST NOT send notification types
        # the client has not explicitly requested").
        assert body["params"]["notifications"] == {
            "resourceSubscriptions": ["file:///a", "file:///b"]
        }
        assert "resourceSubscriptions" not in body["params"]

    def test_stale_generation_after_the_ack_reopens_without_a_backoff(self, httpx_mock):
        """Base change 6: the ack is the earliest proof the server has seen
        THIS attempt's filter, so a change that landed after the snapshot
        is caught there — immediately, with no `RETRY_DELAY` (an empty
        `waits` list is the revert-check) and without counting a drop."""
        httpx_mock.add_response(
            url=self.URL,
            stream=self._sse(self._ack()),
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(
            url=self.URL,
            stream=self._sse(self._ack(), self._graceful(attempt=2)),
            headers={"content-type": "text/event-stream"},
        )
        stop = _RecordingStop()
        self._run_loop(
            uris=[["file:///a"], ["file:///a", "file:///b"]],
            # Attempt 1 snapshots generation 0 while the live counter is
            # already at 1 (a subscribe landed after the snapshot); attempt
            # 2 snapshots 1 and is therefore current.
            snapshot_gens=[0, 1],
            live_generation=1,
            stop=stop,
            restart=threading.Event(),
            state={"advertised": frozenset({"resources"}), "resource_stream": True},
        )
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        assert json.loads(requests[1].content)["params"]["notifications"] == {
            "resourceSubscriptions": ["file:///a", "file:///b"]
        }
        assert stop.waits == []  # no reconnect backoff was ever taken

    def test_restart_on_a_dropped_attempt_reopens_even_before_establishment(
        self, httpx_mock, capsys
    ):
        """Base change 5: the stdin thread ends an attempt by closing the
        PUBLISHED RESPONSE, which surfaces as a transport error. That is
        the relay's own doing, so it must bypass C7's pre-establishment
        fail-fast instead of disabling the stream for the session."""
        httpx_mock.add_exception(httpx.ReadError("closed by the relay"))
        httpx_mock.add_response(
            url=self.URL,
            stream=self._sse(self._ack(), self._graceful(attempt=2)),
            headers={"content-type": "text/event-stream"},
        )
        restart = threading.Event()
        restart.set()
        stop = _RecordingStop()
        self._run_loop(uris=[["file:///a"]], stop=stop, restart=restart)
        assert len(httpx_mock.get_requests()) == 2
        err = capsys.readouterr().err
        assert "subscription filter changed; reopening" in err
        assert "before it was ever established" not in err
        assert stop.waits == []

    def test_stream_closed_mid_read_reopens_instead_of_re_raising(self, httpx_mock):
        """httpx raises `StreamClosed` — a RuntimeError subclass — when the
        stdin thread's `resp.close()` lands mid-read. With stop unset the
        RuntimeError arm re-raises by default (#352 round-5 finding 1); a
        pending restart is the one legitimate producer PR B adds."""
        httpx_mock.add_exception(httpx.StreamClosed())
        httpx_mock.add_response(
            url=self.URL,
            stream=self._sse(self._ack(), self._graceful(attempt=2)),
            headers={"content-type": "text/event-stream"},
        )
        restart = threading.Event()
        restart.set()
        self._run_loop(uris=[["file:///a"]], restart=restart)
        assert len(httpx_mock.get_requests()) == 2

    def test_teardown_mid_attempt_never_consumes_the_restart(self, httpx_mock):
        """Design A4, revert-check. Teardown sets stop, then closes the
        dedicated client, then sets restart to wake a parked thread — a
        thread that read `restart` without checking `stop` first would take
        that for a subscription change and reopen against a closed
        client."""
        stop = threading.Event()
        restart = threading.Event()
        restart.set()

        class TeardownRacingClient:
            def stream(self, *args, **kwargs):
                stop.set()
                raise RuntimeError(
                    "Cannot send a request, as the client has been closed."
                )

        _listen_stream_loop(
            client=TeardownRacingClient(),
            url=self.URL,
            params=self._base_params(),
            prepare_headers=lambda body: {"Content-Type": "application/json"},
            tracker=None,
            stop=stop,
            timeout=httpx.Timeout(connect=10, read=300, write=30, pool=10),
            state=None,
            id_prefix=_LISTEN_RES_ID_PREFIX,
            body_provider=lambda: (
                _with_resource_subscriptions(self._base_params(), frozenset({"a"})),
                0,
            ),
            restart=restart,
            label="resource listen stream",
        )
        assert restart.is_set()  # never consumed by the dying thread
        assert len(httpx_mock.get_requests()) == 0

    def test_empty_uri_set_parks_and_teardown_wakes_it(self, httpx_mock):
        """An `Event.wait()` is deaf to both `stop.set()` and the client
        close that unblocks a parked READ, which is why run()'s teardown
        sets the restart event too (Design A4). Without that, this thread
        would outlive the bounded join."""
        stop = threading.Event()
        restart = threading.Event()
        parked = threading.Event()

        def body_provider():
            parked.set()
            return (
                _with_resource_subscriptions(self._base_params(), frozenset()),
                0,
            )

        thread = threading.Thread(
            target=_listen_stream_loop,
            kwargs={
                "client": httpx.Client(),
                "url": self.URL,
                "params": self._base_params(),
                "prepare_headers": lambda body: {},
                "tracker": None,
                "stop": stop,
                "timeout": httpx.Timeout(connect=10, read=300, write=30, pool=10),
                "id_prefix": _LISTEN_RES_ID_PREFIX,
                "body_provider": body_provider,
                "restart": restart,
                "label": "resource listen stream",
            },
            daemon=True,
        )
        thread.start()
        assert parked.wait(timeout=5)
        stop.set()
        restart.set()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert len(httpx_mock.get_requests()) == 0

    def test_unhonored_uris_are_logged_once_across_reopens(self, httpx_mock, capsys):
        """Base change 7: the degraded mode is loud ONCE PER URI, not once
        per reconnect — the resource stream re-opens on every subscribe, so
        a per-attempt log would turn one unsupported server into a
        flood."""
        for attempt in (1, 2):
            httpx_mock.add_response(
                url=self.URL,
                stream=self._sse(
                    self._ack(resources=[]),
                    *([self._graceful(attempt=2)] if attempt == 2 else []),
                ),
                headers={"content-type": "text/event-stream"},
            )
        state = {"advertised": frozenset({"resources"}), "resource_stream": True}
        with patch("mcp_stdio.relay.RETRY_DELAY", 0):
            self._run_loop(uris=[["file:///a"]], state=state)
        err = capsys.readouterr().err
        assert err.count("did not honor") == 1
        assert "file:///a" in err

    def test_updated_reaches_stdout_through_the_real_loop(self, httpx_mock):
        """The whole PR B path in one test: ack echoes the honored URI, the
        `updated` notification is forwarded with its subscriptionId
        stripped, and the terminal result ends the stream silently."""
        updated = {
            "jsonrpc": "2.0",
            "method": _RESOURCE_UPDATED_METHOD,
            "params": {
                "uri": "file:///a",
                "_meta": {"io.modelcontextprotocol/subscriptionId": "s-1"},
            },
        }
        httpx_mock.add_response(
            url=self.URL,
            stream=self._sse(
                self._ack(resources=["file:///a"]),
                updated,
                self._graceful(),
            ),
            headers={"content-type": "text/event-stream"},
        )
        state = {
            "advertised": frozenset({"resources"}),
            "resource_stream": True,
            "uris": frozenset({"file:///a"}),
        }
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            self._run_loop(uris=[["file:///a"]], state=state)
        emitted = [json.loads(line) for line in stdout.getvalue().strip().split("\n")]
        assert len(emitted) == 1
        assert emitted[0]["method"] == _RESOURCE_UPDATED_METHOD
        assert "_meta" not in emitted[0]["params"]
        assert len(httpx_mock.get_requests()) == 1
