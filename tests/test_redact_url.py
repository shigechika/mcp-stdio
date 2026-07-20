"""Tests for relay.redact_url — must not leak credentials into logs."""

from mcp_stdio.relay import redact_url


def test_strips_userinfo():
    assert redact_url("https://user:secret@example.com/mcp") == "https://example.com/mcp"


def test_redacts_query_string():
    # a bearer token in the query must never appear verbatim
    out = redact_url("https://example.com/mcp?access_token=abc123")
    assert "abc123" not in out
    assert out == "https://example.com/mcp?<redacted>"


def test_keeps_scheme_host_port_path():
    assert redact_url("https://example.com:8443/relay") == "https://example.com:8443/relay"


def test_plain_url_unchanged():
    assert redact_url("https://example.com/mcp") == "https://example.com/mcp"


def test_userinfo_and_query_together():
    # use distinctive secret values that are not substrings of the output
    # markers (e.g. "redacted") to avoid false collisions in the assertions
    out = redact_url("https://user:SECRETPW@example.com:9000/x?token=SECRETTOK")
    assert "SECRETPW" not in out
    assert "SECRETTOK" not in out
    assert out == "https://example.com:9000/x?<redacted>"


def test_malformed_returns_placeholder():
    assert redact_url("http://[::1") == "<url>"
