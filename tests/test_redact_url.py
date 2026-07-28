"""Tests for relay.redact_url — must not leak credentials into logs."""

from mcp_stdio.relay import redact_url


def test_strips_userinfo():
    assert (
        redact_url("https://user:secret@example.com/mcp") == "https://example.com/mcp"
    )


def test_redacts_query_string():
    # a bearer token in the query must never appear verbatim
    out = redact_url("https://example.com/mcp?access_token=abc123")
    assert "abc123" not in out
    assert out == "https://example.com/mcp?<redacted>"


def test_keeps_scheme_host_port_path():
    assert (
        redact_url("https://example.com:8443/relay") == "https://example.com:8443/relay"
    )


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


def test_ipv6_host_keeps_brackets():
    assert redact_url("https://[::1]:8443/mcp") == "https://[::1]:8443/mcp"
    # userinfo stripped, brackets preserved
    assert redact_url("https://u:pw@[2001:db8::1]/x") == "https://[2001:db8::1]/x"


def test_bad_port_does_not_crash():
    # SplitResult.port raises ValueError for a non-numeric port; must not
    # propagate out of redact_url (it is called from a logging path)
    assert redact_url("https://host:notaport/x") == "<url>"
