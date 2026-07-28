"""Tests for relay.scrub_secrets — the log-sink backstop that removes URL
userinfo from arbitrary text (e.g. httpx exception messages)."""

from mcp_stdio.relay import scrub_secrets


def test_removes_userinfo_from_embedded_url():
    out = scrub_secrets("ConnectError to https://user:secret@host.example/mcp")
    assert "secret" not in out
    assert "user" not in out
    assert out == "ConnectError to https://host.example/mcp"


def test_handles_url_with_port_and_query():
    out = scrub_secrets("401 for url https://tok:pw@host:8443/x?a=b")
    assert "pw" not in out.split("host")[0]
    assert out == "401 for url https://host:8443/x?a=b"


def test_ipv6_userinfo():
    out = scrub_secrets("fail: https://u:p@[::1]:9000/relay")
    assert out == "fail: https://[::1]:9000/relay"


def test_plain_text_unchanged():
    assert scrub_secrets("attempt 1/3 failed: timeout") == "attempt 1/3 failed: timeout"


def test_url_without_userinfo_unchanged():
    assert (
        scrub_secrets("GET https://host.example/mcp") == "GET https://host.example/mcp"
    )


def test_linear_time_on_adversarial_input():
    # regression for py/polynomial-redos: a long "://<many non-@>" with no '@'
    # must not blow up (was O(n^2) with the greedy scheme-prefix variant)
    import time

    payload = "x://" + ("a" * 200_000)
    t0 = time.perf_counter()
    out = scrub_secrets(payload)
    assert time.perf_counter() - t0 < 1.0
    assert out == payload  # nothing to redact, returned unchanged
