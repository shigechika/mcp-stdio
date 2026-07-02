"""Tests for mcp_stdio.oauth module."""

import base64
import hashlib
import json
import threading
import time

import httpx
import pytest

from mcp_stdio.oauth import (
    CallbackResult,
    OAuthMetadata,
    _authorization_base_url,
    _build_well_known_url,
    _is_client_secret_expired,
    _is_loopback,
    _origin,
    _make_callback_handler,
    _parse_resource_metadata_hint,
    _parse_token_response,
    _pick_token_endpoint_auth_method,
    _probe_www_authenticate,
    _run_authorization_flow,
    _run_device_authorization_flow,
    _safe_int,
    _sanitize_oauth_error,
    _token_response_to_data,
    _validate_auth_server_url,
    _validate_endpoint_url,
    _validate_prm_hint_url,
    discover_oauth_metadata,
    ensure_token,
    exchange_code,
    generate_pkce,
    refresh_access_token,
    refresh_cached_token,
    register_client,
    step_up_authorize,
)
from mcp_stdio.token_store import TokenData

# OAuth discovery probes multiple fallback well-known URLs (RFC 8414, then the
# OpenID Connect Discovery 1.0 locations) and tolerates a 404 / unmocked probe
# at each step. Asserting that EVERY request was pre-registered is the wrong
# strictness for this fallback-probing code: a test only mocks the URLs it
# cares about, and the extra OIDC probes legitimately miss. Relax that one
# pytest-httpx check module-wide; the complementary
# assert_all_responses_were_requested (mocked-but-unused) stays on.
pytestmark = pytest.mark.httpx_mock(assert_all_requests_were_expected=False)


# --- _safe_int ---


class TestSafeInt:
    """: _safe_int coerces an AS-supplied JSON value to int and falls
    back on bad input. json.loads parses the non-standard literals Infinity /
    -Infinity / NaN by default, so an AS can put a float('inf') into expires_in /
    interval — and int(float('inf')) raises OverflowError (NOT ValueError), which
    would otherwise propagate out of the device flow and crash it. The except
    tuple must therefore include OverflowError alongside TypeError/ValueError."""

    def test_plain_int_and_numeric_string(self):
        assert _safe_int(123, 0) == 123
        assert _safe_int("123", 0) == 123
        assert _safe_int(45.9, 0) == 45  # int(float()) truncates toward zero

    def test_none_and_non_numeric_string_fall_back(self):
        assert _safe_int(None, 7) == 7
        assert _safe_int("abc", 9) == 9
        assert _safe_int({}, 11) == 11  # a JSON object is not coercible

    def test_infinity_falls_back_not_overflowerror(self):
        # int(float('inf')) raises OverflowError, not ValueError — the regression
        # this finding guards. Without OverflowError in the except tuple these
        # would propagate and crash the device flow.
        assert _safe_int(float("inf"), 1800) == 1800
        assert _safe_int(float("-inf"), 1800) == 1800

    def test_nan_falls_back(self):
        # int(float('nan')) raises ValueError — already covered, asserted for
        # completeness alongside the Infinity cases.
        assert _safe_int(float("nan"), 5) == 5


# --- _authorization_base_url ---


class TestResourceIndicator:
    """: the RFC 8707 resource value strips userinfo (it is not part
    of the resource identity and would otherwise reach the AS / its logs / the
    browser address bar) while keeping path+query and dropping any fragment."""

    @pytest.mark.parametrize(
        "url,expected",
        [
            # userinfo stripped
            ("https://user:pass@api.example.com/mcp", "https://api.example.com/mcp"),
            ("https://user@api.example.com/mcp", "https://api.example.com/mcp"),
            # idempotent when there is no userinfo
            ("https://api.example.com/mcp", "https://api.example.com/mcp"),
            # port + query kept; userinfo stripped
            ("https://u:p@host:8443/mcp?a=1", "https://host:8443/mcp?a=1"),
            # bare host stays slash-free: URL-normalizing to "https://host/"
            # is the cross-SDK failure class of typescript-sdk#1968 /
            # python-sdk#2883 / claude-code#52871 (Entra AADSTS9010010)
            ("https://host", "https://host"),
            # fragment dropped (RFC 8707 §2 MUST NOT)
            ("https://api.example.com/mcp#frag", "https://api.example.com/mcp"),
            # unparseable / non-http stays unchanged
            ("not-a-url", "not-a-url"),
        ],
    )
    def test_strips_userinfo(self, url, expected):
        from mcp_stdio.oauth import _resource_indicator

        assert _resource_indicator(url) == expected


class TestAuthorizationBaseUrl:
    def test_strips_path(self):
        assert (
            _authorization_base_url("https://api.example.com/v1/mcp")
            == "https://api.example.com"
        )

    def test_no_path(self):
        assert (
            _authorization_base_url("https://api.example.com")
            == "https://api.example.com"
        )

    def test_with_port(self):
        assert (
            _authorization_base_url("https://api.example.com:8080/mcp")
            == "https://api.example.com:8080"
        )

    def test_http(self):
        assert (
            _authorization_base_url("http://localhost:3000/mcp")
            == "http://localhost:3000"
        )

    def test_deep_path(self):
        assert (
            _authorization_base_url("https://api.example.com/v1/api/mcp")
            == "https://api.example.com"
        )

    def test_strips_embedded_userinfo(self):
        """#9: userinfo must be dropped so the synthesised default /authorize
        and /token endpoints never carry credentials (bypassing the #13
        endpoint-userinfo rejection)."""
        assert (
            _authorization_base_url("https://user:pass@api.example.com/v1/mcp")
            == "https://api.example.com"
        )

    def test_strips_userinfo_keeps_port(self):
        assert (
            _authorization_base_url("https://user:pass@api.example.com:8443/mcp")
            == "https://api.example.com:8443"
        )

    def test_ipv6_host_rebracketed(self):
        """An IPv6 literal host must keep its brackets after userinfo stripping."""
        assert (
            _authorization_base_url("https://user@[2001:db8::1]:9000/mcp")
            == "https://[2001:db8::1]:9000"
        )

    @pytest.mark.parametrize(
        "bad", ["example.com/mcp", "/just/a/path", "ftp:///nohost", ""]
    )
    def test_schemeless_or_hostless_raises(self, bad):
        """: a URL missing scheme or host must fail clearly instead of
        producing a malformed '://...' base that flows into default endpoints."""
        with pytest.raises(ValueError, match="absolute http"):
            _authorization_base_url(bad)


class TestSanitizeOAuthError:
    """: AS-supplied error strings are sanitised to the RFC 6749
    grammar and length-bounded before reaching logs / exceptions."""

    def test_plain_error_code_passes(self):
        assert _sanitize_oauth_error("invalid_scope") == "invalid_scope"

    def test_control_characters_stripped(self):
        assert _sanitize_oauth_error("bad\r\n\tinjected\x00x") == "badinjectedx"

    def test_quote_and_backslash_stripped(self):
        # 0x22 (") and 0x5C (\\) are outside the RFC 6749 error grammar.
        assert _sanitize_oauth_error('a"b\\c') == "abc"

    def test_length_bounded(self):
        assert len(_sanitize_oauth_error("x" * 5000)) == 200

    def test_empty_after_strip_is_placeholder(self):
        assert _sanitize_oauth_error("\x00\x01\x02") == "<unspecified>"

    def test_non_string_coerced(self):
        assert _sanitize_oauth_error(12345) == "12345"


# --- PKCE ---


class TestPKCE:
    def test_verifier_length(self):
        verifier, _ = generate_pkce()
        assert 43 <= len(verifier) <= 128

    def test_verifier_is_url_safe(self):
        verifier, _ = generate_pkce()
        # URL-safe base64 chars only
        import re

        assert re.fullmatch(r"[A-Za-z0-9_-]+", verifier)

    def test_challenge_is_s256(self):
        verifier, challenge = generate_pkce()
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        assert challenge == expected

    def test_challenge_has_no_padding(self):
        """Base64url encoding must strip '=' padding per RFC 7636."""
        _, challenge = generate_pkce()
        assert "=" not in challenge

    def test_unique(self):
        v1, _ = generate_pkce()
        v2, _ = generate_pkce()
        assert v1 != v2


# --- discover_oauth_metadata ---


class TestFetchAuthServerMetadataIssuer:
    """: the issuer comparison and synthesized defaults must use the
    query-stripped base — the path-scoped fallback passes the full server_url."""

    def test_query_in_url_no_spurious_mismatch_and_clean_defaults(
        self, httpx_mock, capsys
    ):
        from mcp_stdio.oauth import (
            _build_well_known_url,
            _fetch_authorization_server_metadata,
        )

        server_url = "https://ex.com/mcp?tenant=x"
        well_known = _build_well_known_url(
            server_url, "oauth-authorization-server"
        )
        # Metadata advertises the query-stripped issuer (the conformant value)
        # and no endpoints, so they are synthesized from the base.
        httpx_mock.add_response(
            url=well_known, json={"issuer": "https://ex.com/mcp"}
        )
        client = httpx.Client()
        meta = _fetch_authorization_server_metadata(server_url, client)

        assert meta is not None
        # Synthesized defaults derive from the query-stripped base — no '?tenant=x'.
        assert meta.token_endpoint == "https://ex.com/mcp/token"
        assert meta.authorization_endpoint == "https://ex.com/mcp/authorize"
        assert meta.issuer == "https://ex.com/mcp"
        # No spurious RFC 8414 §3.3 mismatch warning.
        assert "issuer mismatch" not in capsys.readouterr().err


class TestDiscoverMetadata:
    def _mock_no_prm(self, httpx_mock, base="https://api.example.com", path="/mcp"):
        """Mock RFC 9728 endpoints returning 404 (no protected resource metadata).

        Covers both the path-aware URL (RFC 9728 §3.1) and the host-root fallback.
        """
        if path:
            httpx_mock.add_response(
                url=f"{base}/.well-known/oauth-protected-resource{path}",
                status_code=404,
            )
        httpx_mock.add_response(
            url=f"{base}/.well-known/oauth-protected-resource",
            status_code=404,
        )

    def test_from_well_known(self, httpx_mock):
        self._mock_no_prm(httpx_mock, path="/v1/mcp")
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/tok",
                "registration_endpoint": "https://api.example.com/reg",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/v1/mcp", client)
        assert meta.authorization_endpoint == "https://api.example.com/auth"
        assert meta.token_endpoint == "https://api.example.com/tok"
        assert meta.registration_endpoint == "https://api.example.com/reg"

    def test_default_endpoints_no_double_slash_for_trailing_slash_as(
        self, httpx_mock
    ):
        """An AS advertised with a trailing slash whose metadata omits the
        endpoints must yield single-slash default endpoints, not '//authorize'."""
        server_url = "https://mcp.example.com/mcp"
        httpx_mock.add_response(
            url="https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": server_url,
                "authorization_servers": ["https://as.example.com/"],
            },
        )
        httpx_mock.add_response(
            url="https://as.example.com/.well-known/oauth-authorization-server",
            json={"issuer": "https://as.example.com/"},  # no endpoints declared
        )
        client = httpx.Client()
        meta = discover_oauth_metadata(server_url, client)
        assert meta.authorization_endpoint == "https://as.example.com/authorize"
        assert meta.token_endpoint == "https://as.example.com/token"
        assert "//authorize" not in meta.authorization_endpoint

    def test_path_prm_without_as_falls_through_to_host_root(self, httpx_mock):
        """: a path-aware PRM that returns 200 but yields no usable
        authorization_servers must NOT end discovery — fall through to the
        host-root PRM candidate instead of giving up."""
        server_url = "https://api.example.com/mcp"
        # Path-aware PRM: 200 but empty authorization_servers (nothing usable).
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            json={"resource": server_url, "authorization_servers": []},
        )
        # Host-root PRM: 200 with a valid AS.
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
            json={
                "resource": server_url,
                "authorization_servers": ["https://as.example.com"],
            },
        )
        httpx_mock.add_response(
            url="https://as.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://as.example.com/auth",
                "token_endpoint": "https://as.example.com/tok",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata(server_url, client)
        assert meta.authorization_endpoint == "https://as.example.com/auth"
        assert meta.token_endpoint == "https://as.example.com/tok"

    def test_phase3_defaults_target_discovered_as_origin(self, httpx_mock):
        """: when a cross-origin AS is discovered via PRM but ALL its
        RFC 8414 metadata fetches 404, the phase-3 default endpoints must target
        the DISCOVERED AS origin — not the MCP host (which would POST the
        credential exchange to the wrong origin)."""
        server_url = "https://mcp.example.com/mcp"
        # Path-aware PRM advertises a cross-origin AS (found → loop breaks).
        httpx_mock.add_response(
            url="https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": server_url,
                "authorization_servers": ["https://as.example.com"],
            },
        )
        # Every RFC 8414 metadata fetch 404s: the discovered AS, the host base,
        # and the path-scoped server URL.
        for url in (
            "https://as.example.com/.well-known/oauth-authorization-server",
            "https://mcp.example.com/.well-known/oauth-authorization-server",
            "https://mcp.example.com/.well-known/oauth-authorization-server/mcp",
        ):
            httpx_mock.add_response(url=url, status_code=404)

        client = httpx.Client()
        meta = discover_oauth_metadata(server_url, client)
        # Defaults point at the AS origin, not the MCP host.
        assert meta.authorization_endpoint == "https://as.example.com/authorize"
        assert meta.token_endpoint == "https://as.example.com/token"
        assert meta.issuer == "https://as.example.com"

    def test_fallback_on_404(self, httpx_mock):
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            status_code=404,
        )
        # Path-scoped probe (new fallback for Keycloak-style issuers)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server/mcp",
            status_code=404,
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://api.example.com/authorize"
        assert meta.token_endpoint == "https://api.example.com/token"
        assert meta.registration_endpoint == "https://api.example.com/register"
        # #3: the default-path fallback must still pin an issuer (the base it
        # synthesised endpoints from) so the RFC 9207 iss check stays active.
        assert meta.issuer == "https://api.example.com"

    def test_fallback_on_connection_error(self, httpx_mock):
        # ConnectError for: path-aware PRM, host-root PRM, host-root AS, path-scoped AS
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.token_endpoint == "https://api.example.com/token"

    def test_extra_fields_ignored(self, httpx_mock):
        """FastMCP #1388: metadata may contain unexpected fields."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "issuer": "https://api.example.com",
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/tok",
                "scopes_supported": ["read", "write"],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["none"],
                "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
                "code_challenge_methods_supported": ["S256"],
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://api.example.com/auth"
        assert meta.registration_endpoint is None  # not in response

    def test_iss_parameter_supported_parsed(self, httpx_mock):
        """: the RFC 9207 §3 flag is parsed into OAuthMetadata so the
        §2.4 missing-iss rejection can fire; a non-true value stays False."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "issuer": "https://api.example.com",
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/tok",
                "authorization_response_iss_parameter_supported": True,
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.iss_parameter_supported is True

    def test_iss_parameter_supported_defaults_false(self, httpx_mock):
        """Absent the RFC 9207 §3 flag, iss_parameter_supported is False — a
        response without iss is then accepted (present-only check)."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "issuer": "https://api.example.com",
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/tok",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.iss_parameter_supported is False

    def test_client_id_metadata_document_supported_parsed(self, httpx_mock):
        """#60: draft-ietf-oauth-client-id-metadata-document-00 §5 flag is
        parsed into OAuthMetadata."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "issuer": "https://api.example.com",
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/tok",
                "client_id_metadata_document_supported": True,
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.client_id_metadata_document_supported is True

    def test_client_id_metadata_document_supported_defaults_false(self, httpx_mock):
        """#60: absent or non-true, client_id_metadata_document_supported is
        False — a non-bool truthy value (e.g. a string) must not enable CIMD,
        mirroring the iss_parameter_supported strict-bool coercion."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "issuer": "https://api.example.com",
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/tok",
                "client_id_metadata_document_supported": "true",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.client_id_metadata_document_supported is False

    def test_partial_metadata_uses_defaults(self, httpx_mock):
        """Server returns metadata with only some endpoints."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "token_endpoint": "https://api.example.com/custom-token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://api.example.com/authorize"
        assert meta.token_endpoint == "https://api.example.com/custom-token"

    def test_invalid_json_response(self, httpx_mock):
        """Server returns 200 but invalid JSON."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            text="not json",
            status_code=200,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server/mcp",
            status_code=404,
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        # Should fallback to defaults
        assert meta.token_endpoint == "https://api.example.com/token"

    def test_server_500(self, httpx_mock):
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            status_code=500,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server/mcp",
            status_code=404,
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.token_endpoint == "https://api.example.com/token"

    def test_rfc9728_then_rfc8414(self, httpx_mock):
        """Full discovery: RFC 9728 finds auth server, RFC 8414 gets metadata."""
        # Phase 1: Protected Resource Metadata (RFC 9728 §3.1 path-aware URL)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": "https://api.example.com/mcp",
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        # Phase 2: Authorization Server Metadata (on discovered server)
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "registration_endpoint": "https://auth.example.com/register",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"
        assert meta.token_endpoint == "https://auth.example.com/token"

    def test_rfc9728_fails_falls_through_to_rfc8414(self, httpx_mock):
        """RFC 9728 returns 404, falls through to RFC 8414 on base URL."""
        self._mock_no_prm(httpx_mock, path="/mcp")
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/tok",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://api.example.com/auth"

    def test_rfc9728_non_json_404_handled(self, httpx_mock):
        """#34008 comment: non-JSON 404 from protected-resource must not crash."""
        for prm_url in (
            "https://api.example.com/.well-known/oauth-protected-resource/mcp",
            "https://api.example.com/.well-known/oauth-protected-resource",
        ):
            httpx_mock.add_response(
                url=prm_url,
                status_code=404,
                text="<html>Not Found</html>",
                headers={"content-type": "text/html"},
            )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server/mcp",
            status_code=404,
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        # Falls through to defaults
        assert meta.token_endpoint == "https://api.example.com/token"

    def test_rfc9728_non_json_200_falls_through(self, httpx_mock):
        """: a PRM candidate returning HTTP 200 with a NON-JSON body
        must be skipped (continue to the next candidate / defaults), not crash on
        the json() parse — closes the 200-non-JSON branch (the test above only
        covers the 404-non-JSON case)."""
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            status_code=200,
            text="<html>oops</html>",
            headers={"content-type": "text/html"},
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server/mcp",
            status_code=404,
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.token_endpoint == "https://api.example.com/token"

    def test_separate_auth_server_rfc8414_fails_tries_base(self, httpx_mock):
        """RFC 9728 gives auth server, but its RFC 8414 fails — try base."""
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            json={"authorization_servers": ["https://auth.broken.com"]},
        )
        httpx_mock.add_response(
            url="https://auth.broken.com/.well-known/oauth-authorization-server",
            status_code=500,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://api.example.com/authorize",
                "token_endpoint": "https://api.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://api.example.com/authorize"

    def test_rfc9728_path_based_reverse_proxy(self, httpx_mock):
        """RFC 9728 §3.1: path-aware PRM URL for path-based reverse proxy.

        Regression for the geelen/mcp-remote#249 class of bug — when an MCP
        server is mounted under a sub-path (e.g. Tailscale serve --path /mcp),
        PRM must be fetched at /.well-known/oauth-protected-resource/{path},
        not at the host root.
        """
        httpx_mock.add_response(
            url="https://proxy.example.com/.well-known/oauth-protected-resource/mcp/srv",
            json={
                "resource": "https://proxy.example.com/mcp/srv",
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://proxy.example.com/mcp/srv", client)
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"

    def test_rfc9728_preserves_query_component(self, httpx_mock):
        """RFC 9728 §3.1: the well-known suffix is inserted between the host and
        the path+query, so the resource identifier's query component is
        preserved on the constructed metadata URL.
        """
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=t1",
            json={
                "resource": "https://api.example.com/mcp?tenant=t1",
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp?tenant=t1", client)
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"

    def test_null_registration_endpoint(self, httpx_mock):
        """#38102: registration_endpoint: null should not crash."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/token",
                "registration_endpoint": None,
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://api.example.com/auth"
        assert meta.registration_endpoint is None

    def test_null_token_endpoint_uses_default(self, httpx_mock):
        """Null token_endpoint should fall back to default."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": None,
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.token_endpoint == "https://api.example.com/token"

    def test_issuer_with_path_rfc8414_path_insertion(self, httpx_mock):
        """mcp-remote #207: auth server from RFC 9728 with path uses RFC 8414 Section 3 path insertion.

        When the authorization server URL has a path component (e.g. https://auth.example.com/v2),
        the well-known metadata URL must be constructed by *inserting* the well-known prefix
        before the path, not appending it:
          correct:  https://auth.example.com/.well-known/oauth-authorization-server/v2
          wrong:    https://auth.example.com/v2/.well-known/oauth-authorization-server
        """
        # Phase 1: RFC 9728 returns auth server URL with path
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": "https://api.example.com/mcp",
                "authorization_servers": ["https://auth.example.com/v2"],
            },
        )
        # Phase 2: metadata URL with path inserted (RFC 8414 Section 3)
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server/v2",
            json={
                "authorization_endpoint": "https://auth.example.com/v2/authorize",
                "token_endpoint": "https://auth.example.com/v2/token",
                "registration_endpoint": "https://auth.example.com/v2/register",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://auth.example.com/v2/authorize"
        assert meta.token_endpoint == "https://auth.example.com/v2/token"
        assert meta.registration_endpoint == "https://auth.example.com/v2/register"

    def test_build_well_known_url_no_path(self):
        """_build_well_known_url: issuer without path."""
        assert (
            _build_well_known_url(
                "https://auth.example.com", "oauth-authorization-server"
            )
            == "https://auth.example.com/.well-known/oauth-authorization-server"
        )

    def test_build_well_known_url_with_path(self):
        """RFC 8414 §3 / RFC 9728 §3.1: suffix inserted between host and path."""
        assert (
            _build_well_known_url(
                "https://auth.example.com/v2", "oauth-authorization-server"
            )
            == "https://auth.example.com/.well-known/oauth-authorization-server/v2"
        )

    def test_build_well_known_url_with_trailing_slash(self):
        """_build_well_known_url: trailing slash on path is stripped."""
        assert (
            _build_well_known_url(
                "https://auth.example.com/v2/", "oauth-authorization-server"
            )
            == "https://auth.example.com/.well-known/oauth-authorization-server/v2"
        )

    def test_build_well_known_url_drops_query_for_as_metadata(self):
        """RFC 8414 issuer has no query component — the default drops it, so a
        sloppy authorization_servers entry with a query still discovers."""
        assert (
            _build_well_known_url(
                "https://auth.example.com/v2?foo=bar", "oauth-authorization-server"
            )
            == "https://auth.example.com/.well-known/oauth-authorization-server/v2"
        )

    def test_build_well_known_url_keeps_query_when_requested(self):
        """RFC 9728 §3.1 preserves the resource identifier's query."""
        assert (
            _build_well_known_url(
                "https://api.example.com/mcp?tenant=t1",
                "oauth-protected-resource",
                keep_query=True,
            )
            == "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=t1"
        )

    def test_build_well_known_url_deep_path(self):
        """_build_well_known_url: multi-segment path is preserved."""
        assert (
            _build_well_known_url(
                "https://auth.example.com/a/b/c", "oauth-authorization-server"
            )
            == "https://auth.example.com/.well-known/oauth-authorization-server/a/b/c"
        )

    def test_build_well_known_url_strips_userinfo(self):
        """#5: embedded userinfo must NOT be carried into the discovery GET URL
        (it would be sent as HTTP Basic auth)."""
        url = _build_well_known_url(
            "https://user:pass@api.example.com/mcp", "oauth-authorization-server"
        )
        assert "user:pass@" not in url
        assert url == (
            "https://api.example.com/.well-known/oauth-authorization-server/mcp"
        )

    def test_build_well_known_url_strips_userinfo_keeps_port(self):
        url = _build_well_known_url(
            "https://u:p@api.example.com:8443/mcp",
            "oauth-protected-resource",
            keep_query=False,
        )
        assert url == (
            "https://api.example.com:8443/.well-known/oauth-protected-resource/mcp"
        )

    def test_rfc8414_cross_origin_issuer_rejected(self, httpx_mock):
        """: RFC 8414 §3.3 — a CROSS-ORIGIN issuer (different host)
        is a mix-up / AS-spoofing signal, so the metadata is REJECTED rather
        than used. Discovery falls back to the synthesized defaults on the
        discovery origin, so the spoofed endpoints never receive a credential."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "issuer": "https://other.example.com",  # cross-origin → spoof
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/token",
            },
        )
        # Rejecting the spoofed metadata makes discovery continue to the
        # path-scoped RFC 8414 §3.1 fetch before Phase 3 — mock it as 404 so no
        # unexpected request escapes. pytest_httpx strict mode flags it at
        # TEARDOWN, where _fetch_authorization_server_metadata's broad except
        # cannot swallow it (a local run passed without this; see).
        httpx_mock.add_response(
            url=(
                "https://api.example.com/.well-known/"
                "oauth-authorization-server/mcp"
            ),
            status_code=404,
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        # The spoofed metadata's "/auth" is NOT used — the synthesized default
        # "/authorize" on the discovery origin is, proving the reject took hold.
        assert meta.authorization_endpoint == "https://api.example.com/authorize"

    def test_rfc8414_same_origin_issuer_trailing_slash_warns_but_continues(
        self, httpx_mock
    ):
        """: a SAME-origin issuer mismatch (trailing slash / path /
        case) is the slight misconfiguration real servers ship — warn, but still
        use the metadata. Only a cross-origin issuer is rejected."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "issuer": "https://api.example.com/",  # same origin, trailing /
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        # Same-origin drift is tolerated: the metadata endpoints ARE used.
        assert meta.authorization_endpoint == "https://api.example.com/auth"

    def test_phase3_refuses_cleartext_synthesized_endpoints(self, httpx_mock):
        """: when discovery falls to Phase 3 (no PRM, no RFC 8414
        metadata) and the only base is a cleartext non-loopback http:// origin,
        synthesizing default /authorize + /token would POST the code +
        client_secret in plaintext. _validate_endpoint_url rejects them and
        discover_oauth_metadata HARD-FAILS with ValueError rather than returning
        unsafe endpoints. Drives the integration path of the guard."""
        base = "http://evil.example.com"
        self._mock_no_prm(httpx_mock, base=base, path="/mcp")
        # RFC 8414 metadata absent on both the base and the path-scoped issuer.
        httpx_mock.add_response(
            url=f"{base}/.well-known/oauth-authorization-server", status_code=404
        )
        httpx_mock.add_response(
            url=f"{base}/.well-known/oauth-authorization-server/mcp",
            status_code=404,
        )
        client = httpx.Client()
        with pytest.raises(ValueError, match="refusing to synthesize"):
            discover_oauth_metadata(f"{base}/mcp", client)

    def test_rfc8414_issuer_match_no_warning(self, httpx_mock):
        """RFC 8414 §3: issuer matches — no warning, metadata returned normally."""
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "issuer": "https://api.example.com",  # matches base URL
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://api.example.com/auth"

    def test_rfc9728_resource_mismatch_warns_but_continues(self, httpx_mock):
        """RFC 9728 §3: PRM resource field mismatches server URL — warn, don't fail."""
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": "https://other.example.com/mcp",  # mismatch
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        # Should still use the auth server from PRM despite resource mismatch
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"

    def test_rfc9728_resource_match_no_warning(self, httpx_mock):
        """RFC 9728 §3: PRM resource field matches server URL — proceeds normally."""
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": "https://api.example.com/mcp",  # matches
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"

    def test_rfc9728_resource_match_ignores_userinfo_in_server_url(
        self, httpx_mock, capsys
    ):
        """: the §3.3 resource comparison uses the userinfo-STRIPPED
        identifier (the form the rest of the flow uses), so an operator server_url
        carrying user:pass@ does NOT trip a spurious mismatch warning against a
        compliant PRM resource that (correctly) omits userinfo."""
        # The PRM well-known URL is itself built from the userinfo-stripped host.
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": "https://api.example.com/mcp",  # stripped form — matches
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata(
            "https://user:pass@api.example.com/mcp", client
        )
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"
        # No spurious §3.3 mismatch warning despite the userinfo in server_url.
        assert "resource mismatch" not in capsys.readouterr().err

    @pytest.mark.parametrize("body", [[], ["https://evil"], 42, "a string"])
    def test_non_object_prm_body_skipped(self, httpx_mock, body):
        """: a PRM document whose body is not an OBJECT (a bare array
        or scalar — the PRM is fully MCP-server-controlled) would make
        prm_data.get(...) raise AttributeError and abort discovery. It must be
        skipped so the host-root PRM candidate (and Phase 2/3) still run."""
        server_url = "https://api.example.com/mcp"
        # Path-aware PRM: 200 but a non-object body → skipped.
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            json=body,
        )
        # Host-root PRM: 200 with a valid AS → discovery recovers.
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
            json={
                "resource": server_url,
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata(server_url, client)
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"

    def test_non_string_prm_resource_does_not_crash(self, httpx_mock):
        """: a non-string PRM `resource` (e.g. an integer) must not
        crash the §3.3 mismatch check on `.rstrip` — the isinstance(str) guard
        skips the warning and discovery proceeds using authorization_servers."""
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": 123,  # non-string — would crash .rstrip without guard
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"

    def test_path_scoped_issuer_keycloak_style(self, httpx_mock):
        """#53: Keycloak/Cognito path-scoped issuers advertise metadata at RFC 8414 §3
        path-insertion URL (/.well-known/oauth-authorization-server/<path>).

        When the MCP server URL IS the issuer (no separate authorization server),
        host-root RFC 8414 returns 404, but the path-insertion well-known succeeds.
        Repro: mcp-stdio --oauth-device --client-id x http://keycloak/realms/test
        """
        # No PRM (Keycloak doesn't implement RFC 9728)
        self._mock_no_prm(httpx_mock, base="https://keycloak.example.com", path="/realms/test")
        # Host-root AS metadata: 404
        httpx_mock.add_response(
            url="https://keycloak.example.com/.well-known/oauth-authorization-server",
            status_code=404,
        )
        # Path-insertion AS metadata (RFC 8414 §3): 200 with device endpoint
        httpx_mock.add_response(
            url="https://keycloak.example.com/.well-known/oauth-authorization-server/realms/test",
            json={
                "issuer": "https://keycloak.example.com/realms/test",
                "authorization_endpoint": "https://keycloak.example.com/realms/test/protocol/openid-connect/auth",
                "token_endpoint": "https://keycloak.example.com/realms/test/protocol/openid-connect/token",
                "device_authorization_endpoint": "https://keycloak.example.com/realms/test/protocol/openid-connect/auth/device",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata(
            "https://keycloak.example.com/realms/test", client
        )
        assert meta.authorization_endpoint == "https://keycloak.example.com/realms/test/protocol/openid-connect/auth"
        assert meta.token_endpoint == "https://keycloak.example.com/realms/test/protocol/openid-connect/token"
        assert meta.device_authorization_endpoint == "https://keycloak.example.com/realms/test/protocol/openid-connect/auth/device"

    def test_path_scoped_issuer_does_not_shadow_host_root_match(self, httpx_mock):
        """#53: when host-root AS metadata succeeds, path-scoped probe is not called."""
        self._mock_no_prm(httpx_mock, path="/realms/test")
        # Host-root AS metadata: 200
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/token",
            },
        )
        # Path-insertion URL must NOT be called (no extra mock registered)
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/realms/test", client)
        assert meta.authorization_endpoint == "https://api.example.com/auth"

    def test_openid_configuration_fallback_bare_origin(self, httpx_mock):
        """RFC 8414 §3: when oauth-authorization-server 404s, fall back to OpenID
        Connect /.well-known/openid-configuration (Auth0/Okta/Azure AD expose the
        OIDC form, not the OAuth one). The OIDC schema is an RFC 8414 superset."""
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        # RFC 8414 oauth-authorization-server: 404
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            status_code=404,
        )
        # OIDC discovery: 200
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/openid-configuration",
            json={
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/oauth2/v2.0/authorize",
                "token_endpoint": "https://auth.example.com/oauth2/v2.0/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://auth.example.com", client)
        assert meta.authorization_endpoint == "https://auth.example.com/oauth2/v2.0/authorize"
        assert meta.token_endpoint == "https://auth.example.com/oauth2/v2.0/token"

    def test_openid_configuration_fallback_path_append(self, httpx_mock):
        """A path-scoped issuer whose RFC 8414 locations 404 but which serves OIDC
        metadata at <issuer>/.well-known/openid-configuration (Keycloak realm,
        Azure AD tenant) — the common OIDC path-append form."""
        self._mock_no_prm(httpx_mock, base="https://idp.example.com", path="/tenant")
        # RFC 8414 host-root + path-insertion: 404
        httpx_mock.add_response(
            url="https://idp.example.com/.well-known/oauth-authorization-server",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://idp.example.com/.well-known/oauth-authorization-server/tenant",
            status_code=404,
        )
        # OIDC path-insertion on the bare origin (tried during the base fetch): 404
        httpx_mock.add_response(
            url="https://idp.example.com/.well-known/openid-configuration",
            status_code=404,
        )
        # OIDC path-append on the issuer: 200
        httpx_mock.add_response(
            url="https://idp.example.com/tenant/.well-known/openid-configuration",
            json={
                "issuer": "https://idp.example.com/tenant",
                "authorization_endpoint": "https://idp.example.com/tenant/authorize",
                "token_endpoint": "https://idp.example.com/tenant/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://idp.example.com/tenant", client)
        assert meta.authorization_endpoint == "https://idp.example.com/tenant/authorize"
        assert meta.token_endpoint == "https://idp.example.com/tenant/token"
        assert meta.issuer == "https://idp.example.com/tenant"

    def test_fetch_as_metadata_strips_userinfo_from_base(self):
        """A userinfo-bearing AS URL must NOT leak credentials into the OIDC
        path-append probe or the synthesized default endpoints (#13). Forces the
        OIDC path-append candidate to be the match so its construction is
        exercised directly."""
        from mcp_stdio.oauth import _fetch_authorization_server_metadata
        captured: dict = {}

        class _CaptureClient:
            def get(self, url):
                captured.setdefault("urls", []).append(url)
                req = httpx.Request("GET", url)
                # Only the OIDC path-append candidate answers, with metadata that
                # omits token_endpoint so a default is synthesized from the base.
                if url.endswith("/oauth/.well-known/openid-configuration"):
                    return httpx.Response(
                        200,
                        json={"issuer": "https://api.example.com/oauth"},
                        request=req,
                    )
                return httpx.Response(404, request=req)

        meta = _fetch_authorization_server_metadata(
            "https://user:pass@api.example.com/oauth", _CaptureClient()
        )
        assert meta is not None
        # Every probed URL is userinfo-free (incl. the new OIDC path-append one).
        assert captured["urls"]
        assert all("@" not in u for u in captured["urls"])
        # The synthesized default token endpoint is userinfo-free too.
        assert meta.token_endpoint == "https://api.example.com/oauth/token"


# --- register_client ---


class TestRegisterClient:
    def test_success(self, httpx_mock):
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={"client_id": "cid123", "client_secret": "csec456"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
        )
        client = httpx.Client()
        reg = register_client(meta, "http://127.0.0.1:9999/callback", client)
        assert reg.client_id == "cid123"
        assert reg.client_secret == "csec456"

        # Verify request body
        req = httpx_mock.get_requests()[0]
        body = json.loads(req.content)
        assert body["client_name"] == "mcp-stdio"
        assert "http://127.0.0.1:9999/callback" in body["redirect_uris"]
        assert body["token_endpoint_auth_method"] == "none"
        # SEP-837 / RFC 8252: a loopback-redirect client is "native".
        assert body["application_type"] == "native"

    def test_success_without_client_secret(self, httpx_mock):
        """Some servers return only client_id (public client)."""
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={"client_id": "cid123"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
        )
        client = httpx.Client()
        reg = register_client(meta, "http://127.0.0.1:9999/callback", client)
        assert reg.client_id == "cid123"
        assert reg.client_secret is None

    def test_missing_client_id_raises_clear_error(self, httpx_mock):
        """A registration response without client_id → ValueError, not a bare
        KeyError (RFC 7591 §3.2.1 REQUIRES client_id)."""
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={"client_secret": "csec"},  # no client_id
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
        )
        client = httpx.Client()
        with pytest.raises(ValueError, match="client_id"):
            register_client(meta, "http://127.0.0.1:9999/callback", client)

    @pytest.mark.parametrize(
        "reg,match",
        [
            ({"client_id": 12345}, "client_id is not a string"),
            (
                {"client_id": "cid", "client_secret": {"x": 1}},
                "client_secret is not a string",
            ),
        ],
    )
    def test_non_string_dcr_credentials_raise_clear_error(
        self, httpx_mock, reg, match
    ):
        """: a non-conformant AS returning a non-string client_id /
        client_secret must raise an actionable RFC 7591 ValueError here, not an
        opaque TypeError deep in quote() during HTTP Basic auth (or a silently
        str-coerced client_id in the authorize URL)."""
        httpx_mock.add_response(
            url="https://api.example.com/register", json=reg
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
        )
        client = httpx.Client()
        with pytest.raises(ValueError, match=match):
            register_client(meta, "http://127.0.0.1:9999/callback", client)

    def test_honours_as_assigned_auth_method(self, httpx_mock):
        """: RFC 7591 §3.2.1 — the AS MAY replace the requested
        token_endpoint_auth_method and MUST return the registered value. When the
        AS assigns a method we support that differs from the one we requested, the
        returned ClientRegistration adopts the AS-assigned value so the later
        token exchange frames credentials the way the AS expects."""
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={
                "client_id": "cid",
                "client_secret": "sec",
                "token_endpoint_auth_method": "client_secret_post",  # AS-assigned
            },
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
            # We request client_secret_basic (first supported match)...
            token_endpoint_auth_methods_supported=["client_secret_basic"],
        )
        client = httpx.Client()
        reg = register_client(meta, "http://127.0.0.1:9999/callback", client)
        # ...but the AS recorded client_secret_post — that value wins.
        assert reg.auth_method == "client_secret_post"
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["token_endpoint_auth_method"] == "client_secret_basic"

    def test_unsupported_as_assigned_auth_method_keeps_requested(
        self, httpx_mock, capsys
    ):
        """: if the AS assigns a method mcp-stdio does not implement
        (e.g. private_key_jwt), keep the requested method as the best-effort
        fallback and warn so the ensuing exchange failure is not opaque."""
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={
                "client_id": "cid",
                "client_secret": "sec",
                "token_endpoint_auth_method": "private_key_jwt",  # unsupported here
            },
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
            token_endpoint_auth_methods_supported=["client_secret_basic"],
        )
        client = httpx.Client()
        reg = register_client(meta, "http://127.0.0.1:9999/callback", client)
        assert reg.auth_method == "client_secret_basic"  # requested, unchanged
        assert "unsupported token_endpoint_auth_method" in capsys.readouterr().err

    def test_non_string_as_assigned_auth_method_ignored(self, httpx_mock):
        """A non-string token_endpoint_auth_method in the registration response is
        ignored (isinstance guard) — the requested method is kept, no crash."""
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={
                "client_id": "cid",
                "token_endpoint_auth_method": 123,  # non-string
            },
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
            token_endpoint_auth_methods_supported=["client_secret_post"],
        )
        client = httpx.Client()
        reg = register_client(meta, "http://127.0.0.1:9999/callback", client)
        assert reg.auth_method == "client_secret_post"

    def test_no_registration_endpoint(self):
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint=None,
        )
        client = httpx.Client()
        with pytest.raises(ValueError, match="dynamic client registration"):
            register_client(meta, "http://127.0.0.1:9999/callback", client)

    def test_registration_forbidden(self, httpx_mock):
        """Claude-code #3273: DCR returns 403."""
        httpx_mock.add_response(
            url="https://api.example.com/register",
            status_code=403,
            json={"error": "access_denied"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
        )
        client = httpx.Client()
        with pytest.raises(httpx.HTTPStatusError):
            register_client(meta, "http://127.0.0.1:9999/callback", client)

    def test_client_secret_expires_at_captured(self, httpx_mock):
        """RFC 7591 §3.2.1: client_secret_expires_at should be preserved."""
        future = time.time() + 86400
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={
                "client_id": "cid",
                "client_secret": "csec",
                "client_secret_expires_at": future,
            },
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
        )
        client = httpx.Client()
        reg = register_client(meta, "http://127.0.0.1:9999/callback", client)
        assert reg.client_secret_expires_at == future

    def test_client_secret_expires_at_zero_means_never(self, httpx_mock):
        """RFC 7591 §3.2.1: 0 means 'never expires' — normalize to None."""
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={
                "client_id": "cid",
                "client_secret": "csec",
                "client_secret_expires_at": 0,
            },
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
        )
        client = httpx.Client()
        reg = register_client(meta, "http://127.0.0.1:9999/callback", client)
        assert reg.client_secret_expires_at is None

    def test_client_secret_expires_at_string_zero_means_never(self, httpx_mock):
        """A non-conformant AS sending the STRING "0" must still be read as
        'never expires' — not as already-expired (which would force a needless
        re-DCR on every refresh/step-up)."""
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={
                "client_id": "cid",
                "client_secret": "csec",
                "client_secret_expires_at": "0",
            },
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
        )
        client = httpx.Client()
        reg = register_client(meta, "http://127.0.0.1:9999/callback", client)
        assert reg.client_secret_expires_at is None

    def test_client_secret_expires_at_garbage_coerced_to_none(self, httpx_mock):
        """: a non-numeric client_secret_expires_at (e.g. 'never')
        that fails float() must coerce to None (no expiry), not crash DCR — closes
        the uncovered garbage-value branch alongside the 0 / '0' / missing cases."""
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={
                "client_id": "cid",
                "client_secret": "csec",
                "client_secret_expires_at": "never",
            },
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
        )
        client = httpx.Client()
        reg = register_client(meta, "http://127.0.0.1:9999/callback", client)
        assert reg.client_secret_expires_at is None

    def test_client_secret_expires_at_missing(self, httpx_mock):
        """Field absent → None (treated as no expiry)."""
        httpx_mock.add_response(
            url="https://api.example.com/register",
            json={"client_id": "cid", "client_secret": "csec"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
            registration_endpoint="https://api.example.com/register",
        )
        client = httpx.Client()
        reg = register_client(meta, "http://127.0.0.1:9999/callback", client)
        assert reg.client_secret_expires_at is None


# --- exchange_code ---


class TestExchangeCode:
    def test_success(self, httpx_mock):
        httpx_mock.add_response(
            url="https://api.example.com/token",
            json={
                "access_token": "at123",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "rt456",
            },
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
        )
        client = httpx.Client()
        result = exchange_code(
            meta,
            "cid",
            None,
            "code123",
            "verifier",
            "http://127.0.0.1:9999/callback",
            client,
        )
        assert result["access_token"] == "at123"
        assert result["refresh_token"] == "rt456"

        # Verify request format (application/x-www-form-urlencoded)
        req = httpx_mock.get_requests()[0]
        assert b"grant_type=authorization_code" in req.content
        assert b"code_verifier=verifier" in req.content

    def test_with_client_secret(self, httpx_mock):
        httpx_mock.add_response(
            url="https://api.example.com/token",
            json={"access_token": "at"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
        )
        client = httpx.Client()
        exchange_code(
            meta,
            "cid",
            "csec",
            "code",
            "verifier",
            "http://127.0.0.1:9999/callback",
            client,
        )
        req = httpx_mock.get_requests()[0]
        assert b"client_secret=csec" in req.content

    def test_no_refresh_token_in_response(self, httpx_mock):
        """FastMCP #1356: some servers don't return refresh_token."""
        httpx_mock.add_response(
            url="https://api.example.com/token",
            json={
                "access_token": "at123",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
        )
        client = httpx.Client()
        result = exchange_code(
            meta,
            "cid",
            None,
            "code",
            "verifier",
            "http://127.0.0.1:9999/callback",
            client,
        )
        assert result["access_token"] == "at123"
        assert "refresh_token" not in result

    def test_no_expires_in(self, httpx_mock):
        """Some servers don't return expires_in."""
        httpx_mock.add_response(
            url="https://api.example.com/token",
            json={
                "access_token": "at123",
                "token_type": "Bearer",
            },
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
        )
        client = httpx.Client()
        result = exchange_code(
            meta,
            "cid",
            None,
            "code",
            "verifier",
            "http://127.0.0.1:9999/callback",
            client,
        )
        assert result["access_token"] == "at123"
        assert "expires_in" not in result

    def test_resource_parameter_included(self, httpx_mock):
        """RFC 8707: resource indicator should be included in token request."""
        httpx_mock.add_response(
            url="https://api.example.com/token",
            json={"access_token": "at", "token_type": "Bearer"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
        )
        client = httpx.Client()
        exchange_code(
            meta,
            "cid",
            None,
            "code",
            "verifier",
            "http://127.0.0.1:9999/callback",
            client,
            resource="https://api.example.com/mcp",
        )
        req = httpx_mock.get_requests()[0]
        assert b"resource=https" in req.content

    def test_token_exchange_failure(self, httpx_mock):
        """: a standard RFC 6749 §5.2 token error (4xx + error /
        error_description) surfaces the actionable error_description as a
        RuntimeError, not an opaque HTTPStatusError that drops the body."""
        httpx_mock.add_response(
            url="https://api.example.com/token",
            status_code=400,
            json={"error": "invalid_grant", "error_description": "Code expired"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
        )
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="Code expired"):
            exchange_code(
                meta,
                "cid",
                None,
                "bad-code",
                "verifier",
                "http://127.0.0.1:9999/callback",
                client,
            )

    def test_token_exchange_4xx_without_error_body_raises_http_error(
        self, httpx_mock
    ):
        """A 4xx whose body is NOT an RFC 6749 §5.2 error (no `error` key) falls
        through to raise_for_status — an honest, generic HTTP error."""
        httpx_mock.add_response(
            url="https://api.example.com/token",
            status_code=400,
            text="upstream rejected",
            headers={"content-type": "text/plain"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://api.example.com/authorize",
            token_endpoint="https://api.example.com/token",
        )
        client = httpx.Client()
        with pytest.raises(httpx.HTTPStatusError):
            exchange_code(
                meta,
                "cid",
                None,
                "bad-code",
                "verifier",
                "http://127.0.0.1:9999/callback",
                client,
            )


# --- refresh_access_token ---


class TestRefreshToken:
    def test_success(self, httpx_mock):
        httpx_mock.add_response(
            url="https://api.example.com/token",
            json={
                "access_token": "new_at",
                "expires_in": 7200,
            },
        )
        client = httpx.Client()
        result = refresh_access_token(
            "https://api.example.com/token", "cid", None, "rt123", client
        )
        assert result["access_token"] == "new_at"

        # Verify request
        req = httpx_mock.get_requests()[0]
        assert b"grant_type=refresh_token" in req.content
        assert b"refresh_token=rt123" in req.content

    def test_token_rotation(self, httpx_mock):
        """Server issues a new refresh_token (rotation)."""
        httpx_mock.add_response(
            url="https://api.example.com/token",
            json={
                "access_token": "new_at",
                "refresh_token": "new_rt",
                "expires_in": 3600,
            },
        )
        client = httpx.Client()
        result = refresh_access_token(
            "https://api.example.com/token", "cid", None, "old_rt", client
        )
        assert result["access_token"] == "new_at"
        assert result["refresh_token"] == "new_rt"

    def test_invalid_grant(self, httpx_mock):
        """Refresh token expired or revoked — an RFC 6749 §5.2 error body (here
        with no error_description) surfaces the `error` code as a RuntimeError
. On the refresh path refresh_cached_token catches it and
        degrades to None, exactly as it did for the prior HTTPStatusError."""
        httpx_mock.add_response(
            url="https://api.example.com/token",
            status_code=400,
            json={"error": "invalid_grant"},
        )
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="invalid_grant"):
            refresh_access_token(
                "https://api.example.com/token", "cid", None, "bad_rt", client
            )

    def test_server_error(self, httpx_mock):
        httpx_mock.add_response(
            url="https://api.example.com/token",
            status_code=500,
            text="Internal Server Error",
        )
        client = httpx.Client()
        with pytest.raises(httpx.HTTPStatusError):
            refresh_access_token(
                "https://api.example.com/token", "cid", None, "rt", client
            )

    def test_resource_parameter_included(self, httpx_mock):
        """RFC 8707: resource indicator must be sent in refresh token request."""
        httpx_mock.add_response(
            url="https://api.example.com/token",
            json={"access_token": "new_at", "expires_in": 3600},
        )
        client = httpx.Client()
        refresh_access_token(
            "https://api.example.com/token",
            "cid",
            None,
            "rt123",
            client,
            resource="https://api.example.com/mcp",
        )
        req = httpx_mock.get_requests()[0]
        assert b"resource=https" in req.content

    def test_resource_parameter_omitted_when_none(self, httpx_mock):
        """No resource parameter when not provided (backward compatibility)."""
        httpx_mock.add_response(
            url="https://api.example.com/token",
            json={"access_token": "new_at"},
        )
        client = httpx.Client()
        refresh_access_token(
            "https://api.example.com/token", "cid", None, "rt123", client
        )
        req = httpx_mock.get_requests()[0]
        assert b"resource=" not in req.content


# --- refresh_cached_token ---


class TestRefreshCachedToken:
    """High-level refresh wrapper used by both ensure_token and the
    relay loop's 401 handler. Guards that resource indicator (RFC 8707)
    is sent regardless of call site — a regression previously let the
    relay path skip it."""

    def test_sends_rfc8707_resource_indicator(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://api.example.com/mcp",
            TokenData(
                access_token="old_at",
                refresh_token="rt123",
                expires_at=time.time() - 10,
                client_id="cid",
                token_endpoint="https://auth.example.com/token",
                authorization_endpoint="https://auth.example.com/authorize",
            ),
        )
        httpx_mock.add_response(
            url="https://auth.example.com/token",
            json={"access_token": "new_at", "expires_in": 3600},
        )
        client = httpx.Client()
        data = refresh_cached_token("https://api.example.com/mcp", client)
        assert data is not None
        assert data.access_token == "new_at"
        req = httpx_mock.get_requests()[0]
        assert b"resource=https%3A%2F%2Fapi.example.com%2Fmcp" in req.content

    def test_refresh_200_missing_access_token_returns_none(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """: a non-compliant 200 token response with NO access_token
        (and no `error`) makes _token_response_to_data raise. refresh_cached_token
        must degrade to None per its contract — not propagate a RuntimeError that
        aborts ensure_token's clear-and-re-auth recovery (and exits cli.py with
        1). The _token_response_to_data call was outside the refresh try/except."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://api.example.com/mcp",
            TokenData(
                access_token="old_at",
                refresh_token="rt123",
                expires_at=time.time() - 10,
                client_id="cid",
                token_endpoint="https://auth.example.com/token",
                authorization_endpoint="https://auth.example.com/authorize",
            ),
        )
        # 200 but no access_token and no error → _token_response_to_data raises.
        httpx_mock.add_response(
            url="https://auth.example.com/token", json={"token_type": "Bearer"}
        )
        client = httpx.Client()
        assert refresh_cached_token("https://api.example.com/mcp", client) is None

    def test_unsafe_cached_token_endpoint_aborts_refresh(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """: defence-in-depth. A cached token_endpoint that fails the
        #13 policy (here a non-loopback cleartext HTTP URL) must be re-validated
        before the refresh re-POSTs credentials to it. refresh_cached_token must
        abort (return None → re-auth) and make NO request to the unsafe URL."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://api.example.com/mcp",
            TokenData(
                access_token="old_at",
                refresh_token="rt123",
                expires_at=time.time() - 10,
                client_id="cid",
                # Non-loopback cleartext HTTP — would leak the refresh_token and
                # client_secret in the clear if followed.
                token_endpoint="http://evil.example.com/token",
                authorization_endpoint="https://auth.example.com/authorize",
            ),
        )
        client = httpx.Client()
        # No response mocked: a credential POST would raise in strict mode. The
        # validation must short-circuit before any request is made.
        assert refresh_cached_token("https://api.example.com/mcp", client) is None
        assert httpx_mock.get_requests() == []

    def test_refresh_preserves_persisted_issuer(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """#6/#8: a refresh must not wipe the persisted AS issuer — otherwise the
        RFC 9207 iss check would silently go dark after the first refresh."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import load_token, save_token

        save_token(
            "https://api.example.com/mcp",
            TokenData(
                access_token="old_at",
                refresh_token="rt123",
                expires_at=time.time() - 10,
                client_id="cid",
                token_endpoint="https://auth.example.com/token",
                authorization_endpoint="https://auth.example.com/authorize",
                issuer="https://auth.example.com",
            ),
        )
        httpx_mock.add_response(
            url="https://auth.example.com/token",
            json={"access_token": "new_at", "expires_in": 3600},
        )
        client = httpx.Client()
        data = refresh_cached_token("https://api.example.com/mcp", client)
        assert data is not None and data.issuer == "https://auth.example.com"
        # And it survives the round-trip back to disk.
        assert load_token("https://api.example.com/mcp").issuer == (
            "https://auth.example.com"
        )

    def test_refresh_preserves_scope_when_response_omits_it(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """#1: RFC 6749 §5.1 lets a refresh response OMIT scope. The cached scope
        must be preserved, else a later step-up cannot union the granted scopes."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import load_token, save_token

        save_token(
            "https://api.example.com/mcp",
            TokenData(
                access_token="old_at",
                refresh_token="rt123",
                expires_at=time.time() - 10,
                scope="read write admin",
                client_id="cid",
                token_endpoint="https://auth.example.com/token",
                authorization_endpoint="https://auth.example.com/authorize",
            ),
        )
        # Refresh response omits "scope" entirely.
        httpx_mock.add_response(
            url="https://auth.example.com/token",
            json={"access_token": "new_at", "expires_in": 3600},
        )
        client = httpx.Client()
        data = refresh_cached_token("https://api.example.com/mcp", client)
        assert data is not None and data.scope == "read write admin"
        assert load_token("https://api.example.com/mcp").scope == "read write admin"

    def test_returns_none_when_no_cached_token(self, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        client = httpx.Client()
        assert refresh_cached_token("https://api.example.com/mcp", client) is None

    def test_returns_none_when_client_secret_expired(
        self, tmp_path, monkeypatch
    ):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://api.example.com/mcp",
            TokenData(
                access_token="old_at",
                refresh_token="rt123",
                expires_at=time.time() - 10,
                client_id="cid",
                client_secret="csec",
                client_secret_expires_at=time.time() - 1,  # expired
                token_endpoint="https://auth.example.com/token",
                authorization_endpoint="https://auth.example.com/authorize",
            ),
        )
        client = httpx.Client()
        assert refresh_cached_token("https://api.example.com/mcp", client) is None

    def test_omits_resource_when_no_resource_indicator_set(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """no_resource_indicator=True must suppress the RFC 8707 resource param on refresh."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://api.example.com/mcp",
            TokenData(
                access_token="old_at",
                refresh_token="rt123",
                expires_at=time.time() - 10,
                client_id="cid",
                token_endpoint="https://auth.example.com/token",
                authorization_endpoint="https://auth.example.com/authorize",
                no_resource_indicator=True,
            ),
        )
        httpx_mock.add_response(
            url="https://auth.example.com/token",
            json={"access_token": "new_at", "expires_in": 3600},
        )
        client = httpx.Client()
        data = refresh_cached_token("https://api.example.com/mcp", client)
        assert data is not None
        assert data.access_token == "new_at"
        req = httpx_mock.get_requests()[0]
        assert b"resource=" not in req.content
        # Flag is persisted for future refreshes
        assert data.no_resource_indicator is True

    def test_persists_no_resource_indicator_false_by_default(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """Tokens without no_resource_indicator still include the resource param."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://api.example.com/mcp",
            TokenData(
                access_token="old_at",
                refresh_token="rt123",
                expires_at=time.time() - 10,
                client_id="cid",
                token_endpoint="https://auth.example.com/token",
                authorization_endpoint="https://auth.example.com/authorize",
                # no_resource_indicator defaults to False
            ),
        )
        httpx_mock.add_response(
            url="https://auth.example.com/token",
            json={"access_token": "new_at", "expires_in": 3600},
        )
        client = httpx.Client()
        data = refresh_cached_token("https://api.example.com/mcp", client)
        assert data is not None
        req = httpx_mock.get_requests()[0]
        assert b"resource=https%3A%2F%2Fapi.example.com%2Fmcp" in req.content
        assert data.no_resource_indicator is False


# --- _token_response_to_data ---


class TestTokenResponseToData:
    META = OAuthMetadata(
        authorization_endpoint="https://ex.com/auth",
        token_endpoint="https://ex.com/token",
    )

    def test_preserves_previous_scope_when_omitted(self):
        """#1: scope omitted from the response falls back to previous_scope."""
        raw = {"access_token": "at", "expires_in": 3600}
        data = _token_response_to_data(
            raw, self.META, "cid", None, previous_scope="read write"
        )
        assert data.scope == "read write"

    def test_response_scope_overrides_previous_scope(self):
        """A scope present in the response wins over the previous one."""
        raw = {"access_token": "at", "scope": "read"}
        data = _token_response_to_data(
            raw, self.META, "cid", None, previous_scope="read write"
        )
        assert data.scope == "read"

    def test_missing_access_token_raises(self):
        """#15: a token response without access_token (RFC 6749 §5.1 REQUIRED)
        must fail loudly, not build a credential-less TokenData."""
        with pytest.raises(RuntimeError, match="access_token"):
            _token_response_to_data({"token_type": "Bearer"}, self.META, "cid", None)

    def test_captures_id_token(self):
        """#59: the OIDC id_token from the response is captured into TokenData."""
        raw = {"access_token": "at", "id_token": "eyJhbGc.payload.sig"}
        data = _token_response_to_data(raw, self.META, "cid", None)
        assert data.id_token == "eyJhbGc.payload.sig"

    def test_preserves_previous_id_token_when_omitted(self):
        """#59: a refresh response that omits id_token keeps the previous one
        (mirrors refresh_token), so --oauth-use-id-token survives a refresh."""
        raw = {"access_token": "at2"}  # refresh response without id_token
        data = _token_response_to_data(
            raw, self.META, "cid", None, previous_id_token="prev-idt"
        )
        assert data.id_token == "prev-idt"

    def test_response_id_token_overrides_previous(self):
        raw = {"access_token": "at2", "id_token": "fresh-idt"}
        data = _token_response_to_data(
            raw, self.META, "cid", None, previous_id_token="prev-idt"
        )
        assert data.id_token == "fresh-idt"

    def test_non_string_id_token_falls_back_to_previous(self):
        """A non-string / empty id_token is treated as absent (not crashed on)."""
        raw = {"access_token": "at", "id_token": 123}
        data = _token_response_to_data(
            raw, self.META, "cid", None, previous_id_token="prev-idt"
        )
        assert data.id_token == "prev-idt"
        # No previous either -> None, not the integer.
        data2 = _token_response_to_data(
            {"access_token": "at", "id_token": 123}, self.META, "cid", None
        )
        assert data2.id_token is None

    def test_persists_iss_parameter_supported_from_metadata(self):
        """: the RFC 9207 §3 flag from the discovered metadata is
        written into TokenData so a later step-up can rehydrate it. A round-trip
        through save/load preserves it."""
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
            iss_parameter_supported=True,
        )
        data = _token_response_to_data({"access_token": "at"}, meta, "cid", None)
        assert data.iss_parameter_supported is True
        # Default (metadata flag absent) stays False.
        plain = _token_response_to_data(
            {"access_token": "at"}, self.META, "cid", None
        )
        assert plain.iss_parameter_supported is False

    def test_full_response(self):
        raw = {
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rt",
            "scope": "read write",
        }
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
            registration_endpoint="https://ex.com/register",
        )
        data = _token_response_to_data(raw, meta, "cid", "csec")
        assert data.access_token == "at"
        assert data.refresh_token == "rt"
        assert data.scope == "read write"
        assert data.client_id == "cid"
        assert data.client_secret == "csec"
        assert data.token_endpoint == "https://ex.com/token"
        assert data.expires_at is not None
        assert data.expires_at > time.time()

    def test_no_expires_in(self):
        """Claude-code #26281: tokens without expires_in."""
        raw = {"access_token": "at"}
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
        )
        data = _token_response_to_data(raw, meta, "cid", None)
        assert data.access_token == "at"
        assert data.expires_at is None  # no expiry known

    def test_persists_issuer_for_rfc9207(self):
        """#6/#8: the AS issuer is persisted so the RFC 9207 iss mix-up check
        survives a step-up that reconstructs metadata from the cached token."""
        raw = {"access_token": "at", "expires_in": 3600}
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
            issuer="https://ex.com",
        )
        data = _token_response_to_data(raw, meta, "cid", None)
        assert data.issuer == "https://ex.com"

    def test_no_refresh_token(self):
        """FastMCP #1356: no refresh_token in response."""
        raw = {"access_token": "at", "expires_in": 3600}
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
        )
        data = _token_response_to_data(raw, meta, "cid", None)
        assert data.refresh_token is None

    def test_preserves_previous_refresh_token(self):
        """Python SDK #2270: server omits refresh_token on refresh; preserve old one."""
        raw = {"access_token": "new_at", "expires_in": 3600}
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
        )
        data = _token_response_to_data(
            raw,
            meta,
            "cid",
            None,
            previous_refresh_token="old_rt",
        )
        assert data.access_token == "new_at"
        assert data.refresh_token == "old_rt"

    def test_new_refresh_token_overrides_previous(self):
        """When server sends new refresh_token, use it (token rotation)."""
        raw = {"access_token": "new_at", "refresh_token": "new_rt"}
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
        )
        data = _token_response_to_data(
            raw,
            meta,
            "cid",
            None,
            previous_refresh_token="old_rt",
        )
        assert data.refresh_token == "new_rt"

    def test_string_expires_in_is_coerced(self):
        """Form-urlencoded responses (GitHub App user-to-server) deliver
        ``expires_in`` as a string; it must not crash expires_at arithmetic."""
        raw = {"access_token": "at", "expires_in": "28800"}
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
        )
        data = _token_response_to_data(raw, meta, "cid", None)
        assert data.expires_at is not None
        assert data.expires_at > time.time()

    def test_unparseable_expires_in_degrades_to_none(self):
        """A non-numeric expires_in is tolerated as 'no expiry known', not a crash."""
        raw = {"access_token": "at", "expires_in": "soon"}
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
        )
        data = _token_response_to_data(raw, meta, "cid", None)
        assert data.expires_at is None

    @pytest.mark.parametrize(
        "bad", [float("inf"), float("-inf"), float("nan"), "Infinity", "NaN"]
    )
    def test_non_finite_expires_in_degrades_to_none(self, bad):
        """: a non-finite expires_in (json.loads parses Infinity/NaN by
        default) must be treated as 'no expiry advertised', NOT set expires_at to
        inf/nan. float('inf') > 0 is True, so without the isfinite guard a hostile
        AS could pin a token as eternally fresh and suppress every future refresh."""
        raw = {"access_token": "at", "expires_in": bad}
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
        )
        data = _token_response_to_data(raw, meta, "cid", None)
        assert data.expires_at is None

    def test_non_bearer_token_type_warns(self, capsys):
        """A non-Bearer token_type (DPoP/mac) is stored but warned about, since
        mcp-stdio always presents it as a Bearer credential."""
        raw = {"access_token": "at", "token_type": "DPoP"}
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
        )
        data = _token_response_to_data(raw, meta, "cid", None)
        assert data.token_type == "DPoP"
        assert "non-Bearer token_type" in capsys.readouterr().err

    def test_bearer_token_type_no_warning(self, capsys):
        raw = {"access_token": "at", "token_type": "bearer"}  # any-case Bearer
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
        )
        _token_response_to_data(raw, meta, "cid", None)
        assert "non-Bearer" not in capsys.readouterr().err

    def test_null_token_type_defaults_to_bearer(self):
        """An explicit `"token_type": null` must not crash `.lower()` — it is
        treated as the Bearer default."""
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/auth",
            token_endpoint="https://ex.com/token",
        )
        data = _token_response_to_data(
            {"access_token": "at", "token_type": None}, meta, "cid", None
        )
        assert data.token_type == "Bearer"

    @pytest.mark.parametrize("bad", [0, -100, "0", "-5"])
    def test_non_positive_expires_in_treated_as_no_expiry(self, bad, capsys):
        """: expires_in of 0 or negative must NOT yield an
        immediately-expired token (which would force an instant re-refresh) —
        treat it as no advertised expiry (expires_at=None) and warn."""
        data = _token_response_to_data(
            {"access_token": "at", "expires_in": bad}, self.META, "cid", None
        )
        assert data.expires_at is None
        assert "non-positive expires_in" in capsys.readouterr().err

    def test_positive_expires_in_still_computes_expiry(self):
        data = _token_response_to_data(
            {"access_token": "at", "expires_in": 3600}, self.META, "cid", None
        )
        assert data.expires_at is not None and data.expires_at > 0


# --- _parse_token_response ---


class TestParseTokenResponse:
    def test_non_json_non_form_body_raises_clear_error(self, httpx_mock):
        """: a 200 with a non-JSON, non-form body (e.g. a text/html
        maintenance page) must raise a clear RuntimeError naming the
        content-type, not a raw JSONDecodeError that surfaces opaquely."""
        httpx_mock.add_response(
            url="https://example.com/token",
            text="<html>maintenance</html>",
            headers={"content-type": "text/html"},
        )
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        with pytest.raises(RuntimeError, match="non-JSON"):
            _parse_token_response(resp)

    def test_json_response(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "at", "token_type": "Bearer"},
        )
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        result = _parse_token_response(resp)
        assert result["access_token"] == "at"

    @pytest.mark.parametrize("body", [[], [1, 2], "a string", 42, True])
    def test_non_object_json_body_raises_clear_error(self, httpx_mock, body):
        """: a 200 whose JSON body is not an OBJECT (a bare array,
        scalar, bool) is non-compliant (RFC 6749 §5.1 mandates a JSON object).
        Surface a clear RuntimeError naming the type, not the opaque TypeError
        that _raise_for_body_error's `"error" in result` raises on a non-iterable
        — nor the misleading substring/membership behaviour on a str/list."""
        httpx_mock.add_response(url="https://example.com/token", json=body)
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        with pytest.raises(RuntimeError, match="non-object JSON body"):
            _parse_token_response(resp)

    def test_form_urlencoded_response(self, httpx_mock):
        """TypeScript SDK #759: GitHub returns form-urlencoded."""
        httpx_mock.add_response(
            url="https://example.com/token",
            text="access_token=at123&token_type=bearer&scope=repo",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        result = _parse_token_response(resp)
        assert result["access_token"] == "at123"
        assert result["token_type"] == "bearer"
        assert result["scope"] == "repo"

    def test_form_urlencoded_duplicate_key_collapses_to_first(self, httpx_mock):
        """: a non-conformant duplicated form field must collapse to
        its first value (a string), never leave a LIST that would flow into
        TokenData.access_token or be str()-ed by the error sanitiser."""
        httpx_mock.add_response(
            url="https://example.com/token",
            text="access_token=first&access_token=second&token_type=bearer",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        result = _parse_token_response(resp)
        assert result["access_token"] == "first"
        assert isinstance(result["access_token"], str)

    def test_http_200_with_error_body(self, httpx_mock):
        """GitHub legacy: HTTP 200 with error in body."""
        httpx_mock.add_response(
            url="https://example.com/token",
            json={
                "error": "bad_verification_code",
                "error_description": "Code expired",
            },
        )
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        with pytest.raises(RuntimeError, match="Code expired"):
            _parse_token_response(resp)

    def test_http_400_with_error_body_raises_runtime_error(self, httpx_mock):
        """: a 4xx whose body is an RFC 6749 §5.2 error surfaces the
        `error` code as a RuntimeError (actionable), not the opaque
        HTTPStatusError that drops the body."""
        httpx_mock.add_response(
            url="https://example.com/token",
            status_code=400,
            json={"error": "invalid_grant"},
        )
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        with pytest.raises(RuntimeError, match="invalid_grant"):
            _parse_token_response(resp)

    def test_http_400_without_error_body_raises_http_error(self, httpx_mock):
        """A 4xx whose body has no `error` key falls through to raise_for_status."""
        httpx_mock.add_response(
            url="https://example.com/token",
            status_code=400,
            text="plain rejection",
            headers={"content-type": "text/plain"},
        )
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        with pytest.raises(httpx.HTTPStatusError):
            _parse_token_response(resp)

    def test_form_urlencoded_200_error_body_raises_clear_error(self, httpx_mock):
        """GitHub legacy returns HTTP 200 + form-urlencoded error body. The
        in-body error check must fire here too — a clear RuntimeError, not an
        opaque downstream KeyError on access_token."""
        httpx_mock.add_response(
            url="https://example.com/token",
            text="error=bad_verification_code&error_description=Code+expired",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        with pytest.raises(RuntimeError, match="Code expired"):
            _parse_token_response(resp)

    def test_form_urlencoded_4xx_error_body_raises_clear_error(self, httpx_mock):
        """: a 4xx with a form-urlencoded RFC 6749 §5.2 error body
        surfaces the error as a RuntimeError before raise_for_status — the
        form-urlencoded 4xx branch, sibling of the JSON 4xx and form-urlencoded
        200-error cases that were already covered."""
        httpx_mock.add_response(
            url="https://example.com/token",
            status_code=400,
            text="error=invalid_grant&error_description=Refresh+expired",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        with pytest.raises(RuntimeError, match="Refresh expired"):
            _parse_token_response(resp)


# --- _run_callback_server ---


class TestCallbackServer:
    def test_receives_code(self):
        """Send a simulated redirect to the callback server."""
        cb_result = CallbackResult()
        handler_cls = _make_callback_handler(cb_result)

        from http.server import HTTPServer

        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        resp = httpx.get(
            f"http://127.0.0.1:{port}/callback?code=test_code_123&state=test_state"
        )
        assert resp.status_code == 200
        assert "Authorization successful" in resp.text

        done.set()
        server.server_close()

        assert cb_result.auth_code == "test_code_123"
        assert cb_result.state == "test_state"

    def test_callback_response_has_security_headers(self):
        """: the callback page sets Cache-Control: no-store and
        Referrer-Policy: no-referrer — defense-in-depth, since the callback URL
        carries the auth code/state."""
        cb_result = CallbackResult()
        handler_cls = _make_callback_handler(cb_result)

        from http.server import HTTPServer

        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        resp = httpx.get(f"http://127.0.0.1:{port}/callback?code=c&state=s")

        done.set()
        server.server_close()

        assert resp.headers.get("cache-control") == "no-store"
        assert resp.headers.get("referrer-policy") == "no-referrer"

    def test_bare_callback_hit_does_not_render_success(self):
        """: a /callback hit carrying neither code nor error (a
        browser prefetch, a manual GET) captured nothing — the page must NOT say
        'Authorization successful' (which could mislead a phishing victim), and
        auth_code/error stay None so the main loop keeps waiting."""
        cb_result = CallbackResult()
        handler_cls = _make_callback_handler(cb_result)

        from http.server import HTTPServer

        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        resp = httpx.get(f"http://127.0.0.1:{port}/callback")
        done.set()
        server.server_close()

        assert resp.status_code == 200
        assert "Authorization successful" not in resp.text
        assert "Waiting for authorization" in resp.text
        # Nothing captured → the main loop must keep blocking.
        assert cb_result.auth_code is None
        assert cb_result.error is None

    def test_receives_error(self):
        """Server sends an OAuth error via callback."""
        cb_result = CallbackResult()
        handler_cls = _make_callback_handler(cb_result)

        from http.server import HTTPServer

        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        resp = httpx.get(f"http://127.0.0.1:{port}/callback?error=access_denied")
        assert resp.status_code == 200
        assert "Authorization failed" in resp.text

        done.set()
        server.server_close()

        assert cb_result.error == "access_denied"
        assert cb_result.auth_code is None

    def test_error_html_escaped_against_reflected_xss(self):
        """: the OAuth error is reflected into the callback HTML page
        (do_GET serves it back), so it MUST be html.escaped — a regression that
        dropped the escape would reintroduce a reflected XSS on the loopback
        page. Pin the escaping with an HTML-metacharacter payload."""
        cb_result = CallbackResult()
        handler_cls = _make_callback_handler(cb_result)

        from http.server import HTTPServer

        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        resp = httpx.get(
            f"http://127.0.0.1:{port}/callback",
            params={"error": "<script>alert(1)</script>"},
        )
        done.set()
        server.server_close()

        assert resp.status_code == 200
        # The raw script tag must NOT appear; only its escaped form may.
        assert "<script>alert(1)</script>" not in resp.text
        assert "&lt;script&gt;" in resp.text

    def test_callback_is_single_shot(self):
        """: once the first authorization response is captured, a
        second /callback hit (refresh / prefetch / double-submit) must NOT
        overwrite it."""
        cb_result = CallbackResult()
        handler_cls = _make_callback_handler(cb_result)

        from http.server import HTTPServer

        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        r1 = httpx.get(f"http://127.0.0.1:{port}/callback?code=FIRST&state=s1")
        r2 = httpx.get(f"http://127.0.0.1:{port}/callback?code=SECOND&state=s2")

        done.set()
        server.server_close()

        assert "Authorization successful" in r1.text
        assert "Already received" in r2.text  # second hit ignored
        # The first capture stands; the second did not overwrite it.
        assert cb_result.auth_code == "FIRST"
        assert cb_result.state == "s1"

    def test_non_callback_path_returns_404_and_does_not_capture(self):
        """#15: favicon / prefetch / stray tabs must not deliver a code.

        Only requests to `/callback` may be treated as the authoritative
        authorization response; everything else is rejected.
        """
        cb_result = CallbackResult()
        handler_cls = _make_callback_handler(cb_result)

        from http.server import HTTPServer

        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        try:
            # Paths that are NOT /callback must return 404 even when they
            # carry query parameters that look like an authorization code.
            for path in (
                "/favicon.ico",
                "/?code=bogus&state=attacker",
                "/callback/extra?code=bogus&state=attacker",
                "/CALLBACK?code=bogus&state=attacker",  # case-sensitive per spec
            ):
                resp = httpx.get(f"http://127.0.0.1:{port}{path}")
                assert resp.status_code == 404, path

            # Sanity: the legitimate path still works after rejections
            resp = httpx.get(
                f"http://127.0.0.1:{port}/callback?code=good_code&state=good_state"
            )
            assert resp.status_code == 200
        finally:
            done.set()
            server.server_close()

        # The bogus codes must not have been captured
        assert cb_result.auth_code == "good_code"
        assert cb_result.state == "good_state"

    def test_rejects_non_loopback_host_header(self):
        """: a request carrying a non-loopback Host header (a DNS-
        rebinding attempt) is rejected 404 and captures nothing, even though it
        reaches the loopback-bound server with a valid-looking code+state."""
        cb_result = CallbackResult()
        handler_cls = _make_callback_handler(cb_result)

        from http.server import HTTPServer

        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        try:
            resp = httpx.get(
                f"http://127.0.0.1:{port}/callback?code=c&state=s",
                headers={"Host": "evil.example.com"},
            )
            assert resp.status_code == 404
            # A loopback Host is still accepted (allowlist includes localhost).
            ok = httpx.get(
                f"http://127.0.0.1:{port}/callback?code=good&state=s",
                headers={"Host": f"localhost:{port}"},
            )
            assert ok.status_code == 200
        finally:
            done.set()
            server.server_close()

        # The rebinding attempt captured nothing; only the loopback hit did.
        assert cb_result.auth_code == "good"

    def test_callback_sets_csrf_fields_before_gating_auth_code(self):
        """: the handler must assign the CSRF fields (state/iss) BEFORE
        the gating auth_code so the lock-free main loop never observes auth_code
        set while state is still None — which would spuriously fail the constant-
        time state compare. Verified by recording attribute-assignment order."""
        order: list[str] = []

        class RecordingResult(CallbackResult):
            def __setattr__(self, name, value):
                if name in ("state", "iss", "auth_code", "error"):
                    order.append(name)
                object.__setattr__(self, name, value)

        cb_result = RecordingResult()
        order.clear()  # ignore the dataclass __init__ default assignments
        handler_cls = _make_callback_handler(cb_result)

        from http.server import HTTPServer

        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        try:
            httpx.get(f"http://127.0.0.1:{port}/callback?code=c&state=s&iss=https://x")
        finally:
            done.set()
            server.server_close()

        # The gating field (auth_code) is assigned LAST, after state and iss.
        assert order == ["state", "iss", "auth_code"]

    def test_concurrent_flows_isolated(self):
        """Two callback handlers with separate result objects don't interfere."""
        result_a = CallbackResult()
        result_b = CallbackResult()
        handler_a = _make_callback_handler(result_a)
        handler_b = _make_callback_handler(result_b)

        from http.server import HTTPServer

        server_a = HTTPServer(("127.0.0.1", 0), handler_a)
        server_b = HTTPServer(("127.0.0.1", 0), handler_b)
        port_a = server_a.server_address[1]
        port_b = server_b.server_address[1]
        done = threading.Event()

        def serve_a():
            while not done.is_set():
                server_a.handle_request()

        def serve_b():
            while not done.is_set():
                server_b.handle_request()

        threading.Thread(target=serve_a, daemon=True).start()
        threading.Thread(target=serve_b, daemon=True).start()
        time.sleep(0.3)

        httpx.get(f"http://127.0.0.1:{port_a}/callback?code=code_a&state=state_a")
        httpx.get(f"http://127.0.0.1:{port_b}/callback?code=code_b&state=state_b")

        done.set()
        server_a.server_close()
        server_b.server_close()

        assert result_a.auth_code == "code_a"
        assert result_b.auth_code == "code_b"
        assert result_a.state == "state_a"
        assert result_b.state == "state_b"


# --- ensure_token ---


class TestEnsureToken:
    def test_uses_cached_valid_token(self, tmp_path, monkeypatch):
        """FastMCP #1764: cached tokens should be reused."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="cached_at",
                expires_at=time.time() + 3600,
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data.access_token == "cached_at"

    def test_expired_cached_token_without_refresh_token_skips_refresh(
        self, tmp_path, monkeypatch
    ):
        """: an EXPIRED cached token lacking a refresh_token must
        skip the refresh branch (its gate needs refresh_token AND token_endpoint
        AND client_id) and fall straight to the full authorization flow —
        refresh_cached_token must not even be called."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="expired_at",
                expires_at=time.time() - 10,  # already expired
                refresh_token=None,  # no refresh path available
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        called = {"refresh": False}

        def spy_refresh(*a, **k):
            called["refresh"] = True
            return None

        sentinel = TokenData(access_token="fresh_from_full_flow")
        monkeypatch.setattr("mcp_stdio.oauth.refresh_cached_token", spy_refresh)
        monkeypatch.setattr(
            "mcp_stdio.oauth._probe_www_authenticate", lambda *a, **k: None
        )
        monkeypatch.setattr(
            "mcp_stdio.oauth.discover_oauth_metadata",
            lambda *a, **k: OAuthMetadata(
                authorization_endpoint="https://example.com/authorize",
                token_endpoint="https://example.com/token",
            ),
        )
        monkeypatch.setattr(
            "mcp_stdio.oauth._run_authorization_flow", lambda *a, **k: sentinel
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data is sentinel
        assert called["refresh"] is False

    def test_client_metadata_url_forwarded_to_auth_code_flow(self, monkeypatch):
        """#60: ensure_token's client_metadata_url reaches
        _run_authorization_flow unchanged."""
        captured = {}

        def fake_flow(*_a, **kwargs):
            captured.update(kwargs)
            return TokenData(access_token="tok")

        monkeypatch.setattr(
            "mcp_stdio.oauth._probe_www_authenticate", lambda *a, **k: None
        )
        monkeypatch.setattr(
            "mcp_stdio.oauth.discover_oauth_metadata",
            lambda *a, **k: OAuthMetadata(
                authorization_endpoint="https://example.com/authorize",
                token_endpoint="https://example.com/token",
            ),
        )
        monkeypatch.setattr("mcp_stdio.oauth._run_authorization_flow", fake_flow)

        client = httpx.Client()
        data = ensure_token(
            "https://example.com/mcp",
            client,
            client_metadata_url="https://app.example.com/client.json",
        )
        assert data.access_token == "tok"
        assert (
            captured["client_metadata_url"]
            == "https://app.example.com/client.json"
        )

    def test_refresh_leeway_zero_uses_actual_expiry(self, tmp_path, monkeypatch):
        """#56: refresh_leeway=0 disables proactive refresh — token valid until literal expiry.

        Default leeway (60 s) would treat a token expiring in 30 s as expired
        and trigger refresh. With leeway=0, the cached token is used until the
        actual expires_at moment.
        """
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="short_lived_at",
                expires_at=time.time() + 30,  # within default 60 s leeway
                refresh_token="rt",
                client_id="cid",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client, refresh_leeway=0)
        assert data.access_token == "short_lived_at"  # used as-is, no refresh

    def test_refresh_leeway_large_triggers_proactive_refresh(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """#56: large refresh_leeway proactively refreshes even when token has time left."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="cached_at",
                expires_at=time.time() + 200,  # 200 s left — exceeds default leeway
                refresh_token="valid_rt",
                client_id="cid",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        # leeway=300 — 200 < 300, treated as near-expiry → refresh
        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "refreshed_at", "expires_in": 3600},
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client, refresh_leeway=300)
        assert data.access_token == "refreshed_at"

    def test_refresh_leeway_default_60s(self, tmp_path, monkeypatch, httpx_mock):
        """#56: default leeway of 60 s — token expiring in 30 s is refreshed."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="near_expiry_at",
                expires_at=time.time() + 30,  # within default leeway
                refresh_token="valid_rt",
                client_id="cid",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "refreshed_at", "expires_in": 3600},
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)  # default leeway
        assert data.access_token == "refreshed_at"

    def test_refreshes_expired_token(self, tmp_path, monkeypatch, httpx_mock):
        """Token expired but refresh_token available."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="expired_at",
                expires_at=time.time() - 100,  # expired
                refresh_token="valid_rt",
                client_id="cid",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        httpx_mock.add_response(
            url="https://example.com/token",
            json={
                "access_token": "refreshed_at",
                "expires_in": 3600,
                "refresh_token": "new_rt",
            },
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data.access_token == "refreshed_at"
        assert data.refresh_token == "new_rt"

    def test_refresh_with_token_rotation(self, tmp_path, monkeypatch, httpx_mock):
        """Server rotates refresh_token on each refresh."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token, load_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="old_at",
                expires_at=time.time() - 100,
                refresh_token="old_rt",
                client_id="cid",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        httpx_mock.add_response(
            url="https://example.com/token",
            json={
                "access_token": "new_at",
                "refresh_token": "rotated_rt",
                "expires_in": 3600,
            },
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data.access_token == "new_at"

        # Verify rotated refresh_token is persisted
        stored = load_token("https://example.com/mcp")
        assert stored.refresh_token == "rotated_rt"

    def test_no_expires_at_treated_as_valid(self, tmp_path, monkeypatch):
        """Claude-code #26281: tokens without expires_in are treated as valid."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="no_expiry_at",
                expires_at=None,  # unknown expiry
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data.access_token == "no_expiry_at"

    def test_token_near_expiry_triggers_refresh(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """Token expiring within 60s should be refreshed proactively."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="almost_expired",
                expires_at=time.time() + 30,  # within 60s threshold
                refresh_token="rt",
                client_id="cid",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "fresh_at", "expires_in": 3600},
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data.access_token == "fresh_at"

    def test_refresh_preserves_old_refresh_token(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """Python SDK #2270: refresh response omits refresh_token; keep old."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token, load_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="expired_at",
                expires_at=time.time() - 100,
                refresh_token="precious_rt",
                client_id="cid",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        # Server omits refresh_token in response
        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "new_at", "expires_in": 3600},
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data.access_token == "new_at"
        assert data.refresh_token == "precious_rt"  # preserved!

        stored = load_token("https://example.com/mcp")
        assert stored.refresh_token == "precious_rt"

    def test_refresh_failure_clears_stale_token(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """#37747: failed refresh should clear cached token to prevent retry block."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token, load_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="expired_at",
                expires_at=time.time() - 100,
                refresh_token="invalid_rt",
                client_id="cid",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        # Refresh fails with 400
        httpx_mock.add_response(
            url="https://example.com/token",
            status_code=400,
            json={"error": "invalid_grant"},
        )
        # Probe for WWW-Authenticate hint (no resource_metadata hint)
        httpx_mock.add_response(url="https://example.com/mcp", status_code=401)
        # Discovery for full flow (will be attempted after refresh fails)
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            status_code=404,
        )
        # Path-scoped probe (Keycloak-style fallback)
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server/mcp",
            status_code=404,
        )

        # Stale token should be cleared after refresh failure
        # Full OAuth flow will be attempted (and fail due to no browser),
        # but we can verify the token was deleted
        client = httpx.Client()
        with pytest.raises(Exception):
            # Full flow will fail in test (no browser), but that's OK
            ensure_token("https://example.com/mcp", client, timeout=0.5)

        # Verify stale token was cleared
        assert load_token("https://example.com/mcp") is None

    def test_double_401_recovers_via_full_flow(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """mcp-remote #256 regression: when both access_token and refresh_token
        are invalid server-side, the full authorization flow must run and
        exchange the new code. mcp-remote gets stuck because the callback code
        is received but POST /token is never called; mcp-stdio must drive the
        code exchange to completion."""
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import load_token, save_token

        # Both access and refresh tokens stale (e.g. revoked server-side after
        # 30 days of inactivity, matching the mcp-remote #256 scenario).
        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="stale_at",
                expires_at=time.time() - 100,
                refresh_token="stale_rt",
                client_id="cached_cid",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
                registration_endpoint="https://example.com/register",
            ),
        )

        # Step 1: refresh_token is rejected by the server.
        httpx_mock.add_response(
            url="https://example.com/token",
            status_code=400,
            json={"error": "invalid_grant"},
            match_content=b"grant_type=refresh_token&refresh_token=stale_rt"
            b"&client_id=cached_cid&resource=https%3A%2F%2Fexample.com%2Fmcp",
        )
        # Step 2a: probe for WWW-Authenticate hint (no resource_metadata hint)
        httpx_mock.add_response(url="https://example.com/mcp", status_code=401)
        # Step 2b: discovery for the full flow.
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "registration_endpoint": "https://example.com/register",
            },
        )
        # Step 3: the code exchange that mcp-remote #256 never reaches.
        httpx_mock.add_response(
            url="https://example.com/token",
            json={
                "access_token": "fresh_at",
                "refresh_token": "fresh_rt",
                "expires_in": 3600,
            },
            match_content=None,  # matched by the preceding refresh mock first
        )

        # Simulate the user completing the browser auth: when webbrowser.open
        # is called, hit the local callback server with a code + the state
        # parameter from the authorization URL.
        def fake_open(auth_url: str) -> bool:
            q = parse_qs(urlparse(auth_url).query)
            redirect_uri = q["redirect_uri"][0]
            state = q["state"][0]

            def hit_callback() -> None:
                cb_url = f"{redirect_uri}?code=the_code&state={state}"
                try:
                    urlopen(cb_url, timeout=5).read()
                except Exception:
                    pass

            threading.Thread(target=hit_callback, daemon=True).start()
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client, timeout=5)

        # Full recovery — the new tokens from the code exchange are returned.
        assert data.access_token == "fresh_at"
        assert data.refresh_token == "fresh_rt"

        # Both /token POSTs must have happened in order: failed refresh, then
        # authorization_code exchange. Missing the second call is exactly the
        # mcp-remote #256 symptom.
        token_calls = [
            r
            for r in httpx_mock.get_requests()
            if str(r.url) == "https://example.com/token"
        ]
        assert len(token_calls) == 2
        assert b"grant_type=refresh_token" in token_calls[0].content
        assert b"grant_type=authorization_code" in token_calls[1].content
        assert b"code=the_code" in token_calls[1].content
        # RFC 8707 resource indicator must be sent on the code exchange too.
        assert (
            b"resource=https%3A%2F%2Fexample.com%2Fmcp" in token_calls[1].content
        )

        # The cached client_id is reused — no DCR retry on the rejected token.
        register_calls = [
            r
            for r in httpx_mock.get_requests()
            if str(r.url) == "https://example.com/register"
        ]
        assert register_calls == []

        # Final persisted state has the new tokens.
        stored = load_token("https://example.com/mcp")
        assert stored.access_token == "fresh_at"
        assert stored.refresh_token == "fresh_rt"

    def test_preconfigured_client_id_skips_dcr(self, tmp_path, monkeypatch, httpx_mock):
        """#38102, #3273: pre-configured client_id should skip DCR."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        # Probe for WWW-Authenticate hint (no resource_metadata hint)
        httpx_mock.add_response(url="https://example.com/mcp", status_code=401)
        # Discovery
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "registration_endpoint": "https://example.com/register",
            },
        )

        client = httpx.Client()
        # Should attempt auth flow with provided client_id, NOT call /register
        with pytest.raises(Exception):
            # Will fail at browser step, but we verify no DCR call was made
            ensure_token(
                "https://example.com/mcp",
                client,
                client_id="preconfigured-cid",
                timeout=0.5,
            )

        # Verify /register was never called
        requests = httpx_mock.get_requests()
        urls = [str(r.url) for r in requests]
        assert "https://example.com/register" not in urls

    def test_resource_indicator_false_omits_resource_param(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """--no-resource-indicator: auth URL and code exchange must omit resource."""
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        # Probe for WWW-Authenticate hint
        httpx_mock.add_response(url="https://example.com/mcp", status_code=401)
        # Discovery
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "registration_endpoint": "https://example.com/register",
            },
        )
        httpx_mock.add_response(
            url="https://example.com/register",
            json={"client_id": "new_cid"},
        )
        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "new_at", "expires_in": 3600},
        )

        captured_auth_urls: list[str] = []

        def fake_open(auth_url: str) -> bool:
            captured_auth_urls.append(auth_url)
            q = parse_qs(urlparse(auth_url).query)
            redirect_uri = q["redirect_uri"][0]
            state = q["state"][0]

            def hit_callback() -> None:
                cb_url = f"{redirect_uri}?code=code123&state={state}"
                try:
                    urlopen(cb_url, timeout=5).read()
                except Exception:
                    pass

            threading.Thread(target=hit_callback, daemon=True).start()
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)

        client = httpx.Client()
        data = ensure_token(
            "https://example.com/mcp",
            client,
            resource_indicator=False,
            timeout=5,
        )
        assert data.access_token == "new_at"
        assert data.no_resource_indicator is True

        # Auth URL must not contain resource=
        assert len(captured_auth_urls) == 1
        auth_params = parse_qs(urlparse(captured_auth_urls[0]).query)
        assert "resource" not in auth_params

        # Code exchange must not contain resource=
        token_calls = [
            r for r in httpx_mock.get_requests()
            if str(r.url) == "https://example.com/token"
        ]
        assert len(token_calls) == 1
        assert b"resource=" not in token_calls[0].content

        # Persisted token retains the flag for future refreshes
        from mcp_stdio.token_store import load_token
        stored = load_token("https://example.com/mcp")
        assert stored.no_resource_indicator is True


# --- RFC 7591 client_secret_expires_at ---


class TestClientSecretExpiry:
    def test_is_expired_none_means_no_expiry(self):
        """None client_secret_expires_at means 'no expiry known' → never expired."""
        data = TokenData(access_token="at", client_secret_expires_at=None)
        assert _is_client_secret_expired(data) is False

    def test_is_expired_future(self):
        """Future timestamp → not expired."""
        data = TokenData(
            access_token="at", client_secret_expires_at=time.time() + 3600
        )
        assert _is_client_secret_expired(data) is False

    def test_is_expired_past(self):
        """Past timestamp → expired."""
        data = TokenData(
            access_token="at", client_secret_expires_at=time.time() - 3600
        )
        assert _is_client_secret_expired(data) is True

    def test_expired_secret_skips_refresh_and_clears_token(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """RFC 7591 §3.2.1: expired client_secret must skip refresh and delete token."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import load_token, save_token

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="expired_at",
                expires_at=time.time() - 100,
                refresh_token="valid_rt",
                client_id="cid",
                client_secret="csec",
                client_secret_expires_at=time.time() - 3600,  # expired
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        # Probe for WWW-Authenticate hint (no resource_metadata hint)
        httpx_mock.add_response(url="https://example.com/mcp", status_code=401)
        # Discovery for full flow (which will run after refresh is skipped)
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            status_code=404,
        )
        # Path-scoped probe (Keycloak-style fallback)
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server/mcp",
            status_code=404,
        )
        # Full flow re-registers (since client_secret expired, not reused)
        httpx_mock.add_response(
            url="https://example.com/register",
            json={"client_id": "new_cid", "client_secret": "new_csec"},
        )

        client = httpx.Client()
        with pytest.raises(Exception):
            # Full flow will fail at browser step, that's OK
            ensure_token("https://example.com/mcp", client, timeout=0.5)

        # /token should NOT have been called for refresh (secret expired)
        token_calls = [
            r for r in httpx_mock.get_requests()
            if str(r.url) == "https://example.com/token"
        ]
        assert len(token_calls) == 0
        # The old token should have been deleted when refresh was skipped.
        # (load_token returns None because the full flow fails before saving.)
        assert load_token("https://example.com/mcp") is None

    def test_valid_secret_allows_refresh(self, tmp_path, monkeypatch, httpx_mock):
        """Non-expired client_secret should proceed with refresh normally."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import load_token, save_token

        future_expiry = time.time() + 86400
        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="expired_at",
                expires_at=time.time() - 100,
                refresh_token="valid_rt",
                client_id="cid",
                client_secret="csec",
                client_secret_expires_at=future_expiry,
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
            ),
        )

        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "refreshed_at", "expires_in": 3600},
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data.access_token == "refreshed_at"
        # client_secret_expires_at must be preserved after refresh (not erased)
        stored = load_token("https://example.com/mcp")
        assert stored.client_secret_expires_at == future_expiry

    def test_full_flow_does_not_reuse_expired_client_id(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """When client_secret is expired, full flow must re-register, not reuse cid."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        # Cached credentials exist but client_secret is expired.
        # No access_token and no refresh_token → goes directly to full flow.
        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="",
                refresh_token=None,
                client_id="old_cid",
                client_secret="old_csec",
                client_secret_expires_at=time.time() - 3600,  # expired
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
                registration_endpoint="https://example.com/register",
            ),
        )

        # Probe for WWW-Authenticate hint (no resource_metadata hint)
        httpx_mock.add_response(url="https://example.com/mcp", status_code=401)
        # Discovery
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "registration_endpoint": "https://example.com/register",
            },
        )
        # Re-registration should occur because the cached client_secret expired
        httpx_mock.add_response(
            url="https://example.com/register",
            json={"client_id": "new_cid", "client_secret": "new_csec"},
        )

        client = httpx.Client()
        with pytest.raises(Exception):
            # Full flow will fail at browser step, that's OK
            ensure_token("https://example.com/mcp", client, timeout=0.5)

        # Verify /register WAS called (new registration, not cached reuse)
        register_calls = [
            r for r in httpx_mock.get_requests()
            if str(r.url) == "https://example.com/register"
        ]
        assert len(register_calls) == 1


# --- RFC 9470 / MCP step-up authorization (claude-code#44652) ---


class TestStepUpAuthorize:
    """Step-up re-authorization triggered by a 403 insufficient_scope challenge."""

    SERVER_URL = "https://example.com/mcp"

    def _drive_callback(self, monkeypatch, code: str = "the_code") -> None:
        """Monkeypatch webbrowser.open to complete the callback flow."""
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        def fake_open(auth_url: str) -> bool:
            q = parse_qs(urlparse(auth_url).query)
            redirect_uri = q["redirect_uri"][0]
            state = q["state"][0]

            def hit_callback() -> None:
                cb_url = f"{redirect_uri}?code={code}&state={state}"
                try:
                    urlopen(cb_url, timeout=5).read()
                except Exception:
                    pass

            threading.Thread(target=hit_callback, daemon=True).start()
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)

    def _cached_token(
        self,
        tmp_path,
        monkeypatch,
        *,
        scope: str | None = None,
        iss_parameter_supported: bool = False,
    ) -> None:
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        from mcp_stdio.token_store import save_token

        save_token(
            self.SERVER_URL,
            TokenData(
                access_token="old_at",
                expires_at=time.time() + 3600,
                refresh_token="rt",
                client_id="cached_cid",
                scope=scope,
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
                registration_endpoint="https://example.com/register",
                issuer="https://example.com",
                iss_parameter_supported=iss_parameter_supported,
            ),
        )

    def test_cache_hit_rehydrates_iss_support_and_rejects_missing_iss(
        self, tmp_path, monkeypatch
    ):
        """: when the cached token records iss_parameter_supported,
        the step-up cache-hit path rehydrates the RFC 9207 §3 flag so the §2.4
        missing-iss MUST-reject fires. The callback omits iss, so step-up must
        abort with 'issuer missing' rather than silently accepting it."""
        self._cached_token(
            tmp_path, monkeypatch, scope="mcp:connect", iss_parameter_supported=True
        )
        self._drive_callback(monkeypatch)  # the callback omits the iss parameter
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="issuer missing"):
            step_up_authorize(self.SERVER_URL, client, "hr:read", timeout=5)

    def test_cache_hit_without_iss_support_accepts_missing_iss(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """The counterpart: a cached token that did NOT record iss support still
        accepts a callback without iss (present-only check) — the flag defaults
        False and the step-up proceeds."""
        self._cached_token(
            tmp_path, monkeypatch, scope="mcp:connect", iss_parameter_supported=False
        )
        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "upgraded_at", "expires_in": 3600},
        )
        self._drive_callback(monkeypatch)
        client = httpx.Client()
        data = step_up_authorize(self.SERVER_URL, client, "hr:read", timeout=5)
        assert data.access_token == "upgraded_at"

    def test_scope_is_union_of_cached_and_required(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """Challenge scopes are merged with the previously granted scopes."""
        self._cached_token(
            tmp_path, monkeypatch, scope="mcp:connect mcp:tools:read"
        )
        self._drive_callback(monkeypatch)

        # Token exchange returns upgraded token
        httpx_mock.add_response(
            url="https://example.com/token",
            json={
                "access_token": "upgraded_at",
                "expires_in": 3600,
                "scope": "mcp:connect mcp:tools:read hr:read",
            },
        )

        captured_auth_urls: list[str] = []
        real_open = __import__(
            "mcp_stdio.oauth", fromlist=["webbrowser"]
        ).webbrowser.open

        def spying_open(auth_url: str) -> bool:
            captured_auth_urls.append(auth_url)
            return real_open(auth_url)

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", spying_open)

        client = httpx.Client()
        data = step_up_authorize(self.SERVER_URL, client, "hr:read", timeout=5)
        assert data.access_token == "upgraded_at"

        assert len(captured_auth_urls) == 1
        from urllib.parse import parse_qs, urlparse

        params = parse_qs(urlparse(captured_auth_urls[0]).query)
        scope_param = params["scope"][0]
        requested = set(scope_param.split())
        # Union: every cached and challenge scope appears exactly once
        assert requested == {"mcp:connect", "mcp:tools:read", "hr:read"}

    def test_reuses_cached_client_credentials_without_dcr(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """Cached client_id and endpoints must be reused — no DCR, no discovery."""
        self._cached_token(tmp_path, monkeypatch, scope="mcp:connect")
        self._drive_callback(monkeypatch)

        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "upgraded_at", "expires_in": 3600},
        )

        client = httpx.Client()
        step_up_authorize(self.SERVER_URL, client, "hr:read", timeout=5)

        urls = [str(r.url) for r in httpx_mock.get_requests()]
        # No discovery, no dynamic client registration — only the code exchange
        assert not any(".well-known" in u for u in urls)
        assert "https://example.com/register" not in urls

    def test_saves_new_token_with_resource_indicator(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """RFC 8707: the resource indicator must appear on the code exchange."""
        self._cached_token(tmp_path, monkeypatch)
        self._drive_callback(monkeypatch)

        httpx_mock.add_response(
            url="https://example.com/token",
            json={
                "access_token": "upgraded_at",
                "refresh_token": "new_rt",
                "expires_in": 3600,
            },
        )

        client = httpx.Client()
        data = step_up_authorize(self.SERVER_URL, client, "hr:read", timeout=5)

        assert data.refresh_token == "new_rt"

        from mcp_stdio.token_store import load_token

        stored = load_token(self.SERVER_URL)
        assert stored.access_token == "upgraded_at"

        token_calls = [
            r
            for r in httpx_mock.get_requests()
            if str(r.url) == "https://example.com/token"
        ]
        assert len(token_calls) == 1
        # RFC 8707 resource indicator on the code exchange
        assert (
            b"resource=https%3A%2F%2Fexample.com%2Fmcp" in token_calls[0].content
        )
        # The grant is authorization_code (full flow), not refresh_token
        assert b"grant_type=authorization_code" in token_calls[0].content

    def test_rediscovery_probes_www_authenticate_for_prm_hint(
        self, tmp_path, monkeypatch
    ):
        """: when the cached token lacks endpoints, step_up's
        re-discovery probes WWW-Authenticate for an RFC 9728 PRM hint FIRST and
        threads it into discovery — mirroring ensure_token — so a server
        publishing PRM at a non-standard URL is discoverable on this path too,
        not only on initial auth."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        from mcp_stdio.token_store import save_token

        # Cached token has NO token/authorization endpoints → forces re-discovery.
        save_token(
            self.SERVER_URL,
            TokenData(access_token="old_at", scope="mcp:connect"),
        )

        hint = 'Bearer resource_metadata="https://as.example/.well-known/custom"'
        probe_calls: list[str] = []

        def fake_probe(server_url, client):
            probe_calls.append(server_url)
            return hint

        discover_hints: list[str | None] = []
        sentinel_md = OAuthMetadata(
            authorization_endpoint="https://as.example/authorize",
            token_endpoint="https://as.example/token",
        )

        def fake_discover(server_url, client, www_authenticate=None):
            discover_hints.append(www_authenticate)
            return sentinel_md

        flow_md: list[object] = []

        def fake_flow(server_url, client, *, metadata, **kwargs):
            flow_md.append(metadata)
            return TokenData(access_token="upgraded_at")

        monkeypatch.setattr("mcp_stdio.oauth._probe_www_authenticate", fake_probe)
        monkeypatch.setattr("mcp_stdio.oauth.discover_oauth_metadata", fake_discover)
        monkeypatch.setattr("mcp_stdio.oauth._run_authorization_flow", fake_flow)

        client = httpx.Client()
        data = step_up_authorize(self.SERVER_URL, client, "hr:read", timeout=5)

        assert data.access_token == "upgraded_at"
        assert probe_calls == [self.SERVER_URL]  # PRM probe ran
        assert discover_hints == [hint]  # hint threaded into discovery
        assert flow_md == [sentinel_md]  # discovered metadata used by the flow

    def test_respects_cached_no_resource_indicator(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """step_up_authorize must omit resource when cached token has no_resource_indicator=True."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        from mcp_stdio.token_store import save_token

        save_token(
            self.SERVER_URL,
            TokenData(
                access_token="old_at",
                expires_at=time.time() + 3600,
                client_id="cached_cid",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
                no_resource_indicator=True,
            ),
        )
        self._drive_callback(monkeypatch)

        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "upgraded_at", "expires_in": 3600},
        )

        client = httpx.Client()
        data = step_up_authorize(self.SERVER_URL, client, "hr:read", timeout=5)
        assert data.access_token == "upgraded_at"

        token_calls = [
            r for r in httpx_mock.get_requests()
            if str(r.url) == "https://example.com/token"
        ]
        assert len(token_calls) == 1
        assert b"resource=" not in token_calls[0].content
        # auth URL must also omit resource
        # (verified indirectly — if it included an unrecognised param the AS
        # would reject state, so a successful exchange proves it was absent)

    def test_rediscovers_when_cache_is_empty(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """If the cache is gone, discovery runs before the auth flow."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        self._drive_callback(monkeypatch)

        # Step-up re-discovery now probes WWW-Authenticate first.
        # A 401 with no PRM hint makes the probe a no-op so discovery falls
        # through to the .well-known URLs below — but the request must be mocked
        # or pytest_httpx's strict assert_all_requests_were_expected fails.
        httpx_mock.add_response(
            url=self.SERVER_URL,
            method="POST",
            status_code=401,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "registration_endpoint": "https://example.com/register",
            },
        )
        # No cached client → DCR runs too
        httpx_mock.add_response(
            url="https://example.com/register",
            json={"client_id": "fresh_cid"},
        )
        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "upgraded_at", "expires_in": 3600},
        )

        client = httpx.Client()
        data = step_up_authorize(self.SERVER_URL, client, "hr:read", timeout=5)
        assert data.access_token == "upgraded_at"

    def test_unsafe_cached_endpoint_falls_through_to_discovery(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """: defence-in-depth. If the cached token_endpoint fails the
        #13 policy (here a non-loopback cleartext HTTP URL), the step-up cache-hit
        branch must be skipped and fresh discovery run instead — so the credential
        flow goes to the freshly DISCOVERED safe endpoint, never the unsafe cached
        one."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        from mcp_stdio.token_store import save_token

        save_token(
            self.SERVER_URL,
            TokenData(
                access_token="old_at",
                expires_at=time.time() + 3600,
                refresh_token="rt",
                client_id="cached_cid",  # reused → DCR skipped, no REG mock
                scope="mcp:connect",
                # Unsafe: non-loopback cleartext HTTP — must NOT be reused.
                token_endpoint="http://evil.example.com/token",
                authorization_endpoint="http://evil.example.com/authorize",
            ),
        )
        self._drive_callback(monkeypatch)

        # The cache-hit branch is skipped, so step-up re-discovers. Mirror the
        # cache-empty discovery chain (WWW-Authenticate probe → PRM 404s → 8414).
        httpx_mock.add_response(url=self.SERVER_URL, method="POST", status_code=401)
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            },
        )
        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "upgraded_at", "expires_in": 3600},
        )

        client = httpx.Client()
        data = step_up_authorize(self.SERVER_URL, client, "hr:read", timeout=5)
        assert data.access_token == "upgraded_at"
        # Definitively: nothing was ever sent to the unsafe cached host.
        assert all(
            "evil.example.com" not in str(r.url) for r in httpx_mock.get_requests()
        )


# --- RFC 9728 authorization_server validation (SSRF hardening, #13) ---


class TestOrigin:
    """_origin folds case / default ports / userinfo to one comparable tuple and
    returns a string sentinel for a malformed port so it never spuriously matches
    a valid origin ( pins the otherwise-uncovered sentinel branch)."""

    def test_malformed_port_returns_string_sentinel(self):
        from urllib.parse import urlparse

        origin = _origin(urlparse("https://h:999999/"))
        assert origin == ("https", "h", "invalid-port")
        # The third element is the string sentinel, never an int or None.
        assert isinstance(origin[2], str)

    def test_malformed_port_never_equals_a_valid_origin(self):
        from urllib.parse import urlparse

        bad = _origin(urlparse("https://h:999999/"))
        good = _origin(urlparse("https://h/"))  # same host, valid (default) port
        assert bad != good

    def test_default_port_folds_to_implicit(self):
        from urllib.parse import urlparse

        assert _origin(urlparse("https://h:443/")) == _origin(urlparse("https://h/"))


class TestIsLoopback:
    def test_localhost(self):
        assert _is_loopback("localhost") is True
        assert _is_loopback("LOCALHOST") is True

    def test_localhost_with_trailing_dot(self):
        """RFC 6761 §6.3: the FQDN form of localhost still resolves to loopback."""
        assert _is_loopback("localhost.") is True
        assert _is_loopback("LOCALHOST.") is True

    def test_ipv4_loopback_canonical(self):
        assert _is_loopback("127.0.0.1") is True

    def test_ipv4_loopback_range(self):
        """RFC 1122 §3.2.1.3: 127.0.0.0/8 is all loopback, not just .0.1."""
        for addr in ("127.0.0.2", "127.1.2.3", "127.255.255.254"):
            assert _is_loopback(addr) is True, addr

    def test_ipv6_loopback_canonical(self):
        assert _is_loopback("::1") is True

    def test_ipv6_loopback_expanded_forms(self):
        """Different textual forms of ::1 must all be recognised."""
        for form in ("0:0:0:0:0:0:0:1", "::0001", "0:0:0:0:0:0:0:0001"):
            assert _is_loopback(form) is True, form

    def test_public_hosts_are_not_loopback(self):
        assert _is_loopback("example.com") is False
        assert _is_loopback("auth.example.com") is False
        assert _is_loopback("10.0.0.1") is False  # RFC 1918 is NOT loopback
        assert _is_loopback("") is False

    def test_adjacent_ranges_are_not_loopback(self):
        """Boundary check: 126.x and 128.x must not be confused with 127/8."""
        assert _is_loopback("126.255.255.255") is False
        assert _is_loopback("128.0.0.0") is False

    def test_malformed_hosts_return_false(self):
        """Non-addresses (e.g. looks-like-ip-but-isn't) fail closed."""
        assert _is_loopback("127.0.0.1.malicious.example.com") is False
        assert _is_loopback("not-an-address") is False
        assert _is_loopback("999.999.999.999") is False


class TestValidateAuthServerUrl:
    SERVER_URL = "https://mcp.example.com/mcp"

    def test_same_origin_https_accepted(self, capsys):
        assert (
            _validate_auth_server_url(
                "https://mcp.example.com/authorize", self.SERVER_URL
            )
            is True
        )
        # No cross-origin warning on same-netloc
        assert "cross-origin" not in capsys.readouterr().err

    def test_cross_origin_https_accepted_with_warning(self, capsys):
        """RFC 9728 §2 permits federation; warn loudly but don't block."""
        assert (
            _validate_auth_server_url(
                "https://auth.example.com/authorize", self.SERVER_URL
            )
            is True
        )
        err = capsys.readouterr().err
        assert "cross-origin" in err

    def test_explicit_default_port_is_not_cross_origin(self, capsys):
        """`:443` is the implicit default for https; URLs that spell it out
        must still compare as same-origin. A false cross-origin warning
        here desensitises the user to the real one."""
        assert (
            _validate_auth_server_url(
                "https://mcp.example.com:443/authorize", self.SERVER_URL
            )
            is True
        )
        assert "cross-origin" not in capsys.readouterr().err

    def test_hostname_case_is_not_cross_origin(self, capsys):
        """DNS is case-insensitive per RFC 4343, so uppercase hostnames in
        either the PRM or the MCP URL must not trigger cross-origin."""
        assert (
            _validate_auth_server_url(
                "https://MCP.example.com/authorize", self.SERVER_URL
            )
            is True
        )
        assert "cross-origin" not in capsys.readouterr().err

    def test_userinfo_is_rejected(self, capsys):
        """#10: an authorization_server URL embedding userinfo is refused —
        it would survive into the (non-revalidated) synthesized token endpoint
        and route the credential exchange through a userinfo authority. Mirrors
        _validate_endpoint_url's userinfo rejection."""
        assert (
            _validate_auth_server_url(
                "https://user:pass@mcp.example.com/authorize", self.SERVER_URL
            )
            is False
        )
        assert "userinfo" in capsys.readouterr().err

    def test_different_port_is_cross_origin(self, capsys):
        """Different explicit ports ARE different origins per RFC 6454."""
        assert (
            _validate_auth_server_url(
                "https://mcp.example.com:8443/authorize", self.SERVER_URL
            )
            is True  # accepted, but with warning
        )
        assert "cross-origin" in capsys.readouterr().err

    def test_plaintext_http_to_public_host_rejected(self, capsys):
        assert (
            _validate_auth_server_url(
                "http://evil.example.net/authorize", self.SERVER_URL
            )
            is False
        )
        err = capsys.readouterr().err
        assert "cleartext" in err or "non-loopback" in err

    def test_plaintext_http_to_loopback_accepted(self):
        """Local development servers commonly use http://localhost."""
        assert (
            _validate_auth_server_url(
                "http://localhost:8080/authorize", self.SERVER_URL
            )
            is True
        )
        assert (
            _validate_auth_server_url(
                "http://127.0.0.1:9000/authorize", self.SERVER_URL
            )
            is True
        )

    def test_non_http_scheme_rejected(self, capsys):
        for bad in (
            "javascript:alert(1)",
            "file:///etc/passwd",
            "ftp://ftp.example.com/",
            "data:text/html,<script>",
        ):
            assert _validate_auth_server_url(bad, self.SERVER_URL) is False
        err = capsys.readouterr().err
        assert "unsupported" in err or "ignoring" in err

    def test_malformed_url_rejected(self):
        assert _validate_auth_server_url("", self.SERVER_URL) is False

    @pytest.mark.parametrize(
        "bad", ["https://host:999999/as", "https://host:notaport/as"]
    )
    def test_malformed_port_rejected_not_raised(self, bad):
        """: an out-of-range / non-numeric port makes urllib raise on
        lazy .port access — the validator must REJECT (False), not let the
        ValueError escape and abort the discovery walk."""
        assert _validate_auth_server_url(bad, self.SERVER_URL) is False

    def test_discover_skips_plaintext_auth_server_and_tries_fallback(
        self, httpx_mock
    ):
        """End-to-end: PRM advertises an HTTP auth server → validation
        rejects → discovery falls back to the base host for AS metadata."""
        server_url = "https://mcp.example.com/mcp"
        httpx_mock.add_response(
            url="https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": server_url,
                "authorization_servers": ["http://evil.example.net/authorize"],
            },
        )
        # The path-aware PRM yielded no USABLE auth server (the only entry was a
        # rejected plaintext URL), so discovery now falls through to the
        # host-root PRM candidate before the base AS-metadata fetch. See #7.
        httpx_mock.add_response(
            url="https://mcp.example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://mcp.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://mcp.example.com/authorize",
                "token_endpoint": "https://mcp.example.com/token",
            },
        )

        client = httpx.Client()
        meta = discover_oauth_metadata(server_url, client)
        assert meta.authorization_endpoint == "https://mcp.example.com/authorize"

        urls = [str(r.url) for r in httpx_mock.get_requests()]
        assert not any("evil.example.net" in u for u in urls)

    def test_discover_accepts_second_valid_entry(self, httpx_mock):
        """First entry invalid → try the next one."""
        server_url = "https://mcp.example.com/mcp"
        httpx_mock.add_response(
            url="https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": server_url,
                "authorization_servers": [
                    "http://evil.example.net/authorize",
                    "https://auth.example.com",
                ],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata(server_url, client)
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"

    def test_discover_skips_malformed_port_auth_server(self, httpx_mock):
        """: a malformed-port AS candidate must be SKIPPED, not crash
        the discovery walk. urllib parses the port lazily and raises ValueError
        on .port access, which previously propagated out of the whole OAuth flow
        — a single bad authorization_servers entry would DoS discovery."""
        server_url = "https://mcp.example.com/mcp"
        httpx_mock.add_response(
            url="https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            json={
                "resource": server_url,
                "authorization_servers": [
                    "https://evil.example.net:999999/authorize",  # out-of-range port
                    "https://auth.example.com",
                ],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        # Without the fix this raises ValueError instead of returning metadata.
        meta = discover_oauth_metadata(server_url, client)
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"


class TestValidateEndpointUrl:
    """AS-metadata endpoint URLs must pass the #13 cleartext-leak policy
    before any secret is POSTed to them, mirroring the AS base-URL check."""

    def test_https_accepted(self):
        assert (
            _validate_endpoint_url("https://as.example.com/token", label="token")
            == "https://as.example.com/token"
        )

    def test_loopback_http_accepted(self):
        assert (
            _validate_endpoint_url("http://127.0.0.1:9000/token", label="token")
            == "http://127.0.0.1:9000/token"
        )

    def test_plaintext_http_public_host_rejected(self, capsys):
        assert _validate_endpoint_url("http://evil.example/token", label="token") is None
        assert "cleartext" in capsys.readouterr().err

    def test_non_http_scheme_rejected(self, capsys):
        assert _validate_endpoint_url("javascript:alert(1)", label="token") is None
        assert "unsupported" in capsys.readouterr().err

    def test_userinfo_rejected(self, capsys):
        assert (
            _validate_endpoint_url("https://user:pass@as.example/token", label="token")
            is None
        )
        assert "userinfo" in capsys.readouterr().err

    def test_empty_and_none_pass_through_silently(self, capsys):
        assert _validate_endpoint_url(None, label="token") is None
        assert _validate_endpoint_url("", label="token") is None
        assert capsys.readouterr().err == ""

    @pytest.mark.parametrize(
        "bad", ["https://evil:999999/token", "https://evil:notaport/token"]
    )
    def test_malformed_port_returns_none(self, bad, capsys):
        """: a malformed port must be dropped (None), not returned as
        a 'valid' endpoint that later receives a credential POST and surfaces an
        opaque httpx error deep in exchange_code / refresh."""
        assert _validate_endpoint_url(bad, label="token_endpoint") is None
        assert "invalid port" in capsys.readouterr().err

    def test_discover_drops_cleartext_token_endpoint_and_uses_default(
        self, httpx_mock, capsys
    ):
        """A (validated, https) AS metadata doc declaring an http:// token
        endpoint must not be honoured — fall back to the default token path on
        the validated AS base instead of POSTing credentials in cleartext."""
        server_url = "https://mcp.example.com/mcp"
        httpx_mock.add_response(
            url="https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://mcp.example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://mcp.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://mcp.example.com/authorize",
                "token_endpoint": "http://evil.example/token",
                "registration_endpoint": "http://evil.example/register",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata(server_url, client)
        # Cleartext token endpoint dropped → default on the validated base.
        assert meta.token_endpoint == "https://mcp.example.com/token"
        # Cleartext optional endpoint dropped to None.
        assert meta.registration_endpoint is None
        assert "cleartext" in capsys.readouterr().err


# --- OAuth state CSRF check (#26) ---


class TestStateCsrfCheck:
    """`_run_authorization_flow` must reject a state that does not match
    the one we sent, without leaking timing information about the common
    prefix. Comparison uses `secrets.compare_digest`."""

    SERVER_URL = "https://example.com/mcp"

    def test_state_mismatch_raises_csrf_error(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """An attacker-supplied state at the callback must raise RuntimeError."""
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        # Token store isolation
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        # Probe for WWW-Authenticate hint (no resource_metadata hint)
        httpx_mock.add_response(url="https://example.com/mcp", status_code=401)
        # Discovery + registration mocks so we reach the auth-URL stage
        httpx_mock.add_response(
            url=(
                "https://example.com/.well-known/"
                "oauth-protected-resource/mcp"
            ),
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "registration_endpoint": "https://example.com/register",
            },
        )
        httpx_mock.add_response(
            url="https://example.com/register",
            json={"client_id": "cid"},
        )

        def fake_open(auth_url: str) -> bool:
            q = parse_qs(urlparse(auth_url).query)
            redirect_uri = q["redirect_uri"][0]
            # Deliberately ignore q["state"][0] and send a different one
            wrong_state = "attacker-supplied-state"

            def hit_callback() -> None:
                cb_url = f"{redirect_uri}?code=evil_code&state={wrong_state}"
                try:
                    urlopen(cb_url, timeout=5).read()
                except Exception:
                    pass

            threading.Thread(target=hit_callback, daemon=True).start()
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)

        client = httpx.Client()
        with pytest.raises(RuntimeError, match="state mismatch"):
            ensure_token(self.SERVER_URL, client, timeout=5)

        # The token endpoint must NEVER have been hit — the flow must
        # abort before exchanging the attacker's code.
        token_calls = [
            r
            for r in httpx_mock.get_requests()
            if str(r.url) == "https://example.com/token"
        ]
        assert token_calls == []

    def test_absent_state_raises_csrf_error(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """: a callback delivering ?code= with NO state parameter must
        still raise 'state mismatch' (not crash compare_digest with None). Pins
        the `cb_result.state or ''` defensive coalesce."""
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        httpx_mock.add_response(url="https://example.com/mcp", status_code=401)
        httpx_mock.add_response(
            url=(
                "https://example.com/.well-known/"
                "oauth-protected-resource/mcp"
            ),
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "registration_endpoint": "https://example.com/register",
            },
        )
        httpx_mock.add_response(
            url="https://example.com/register",
            json={"client_id": "cid"},
        )

        def fake_open(auth_url: str) -> bool:
            q = parse_qs(urlparse(auth_url).query)
            redirect_uri = q["redirect_uri"][0]

            def hit_callback() -> None:
                # Code present, state entirely absent → cb_result.state is None.
                cb_url = f"{redirect_uri}?code=some_code"
                try:
                    urlopen(cb_url, timeout=5).read()
                except Exception:
                    pass

            threading.Thread(target=hit_callback, daemon=True).start()
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)

        client = httpx.Client()
        with pytest.raises(RuntimeError, match="state mismatch"):
            ensure_token(self.SERVER_URL, client, timeout=5)

        token_calls = [
            r
            for r in httpx_mock.get_requests()
            if str(r.url) == "https://example.com/token"
        ]
        assert token_calls == []

    def test_uses_constant_time_comparison(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """: the CSRF state check goes through secrets.compare_digest
        on the PRODUCTION path, not ==.

        The previous version called compare_digest itself in the test body, so it
        was tautological — a refactor to `==` would not have failed it. This runs
        the real `ensure_token` flow with a spy installed and asserts the spy was
        invoked with `(callback_state, sent_state)` from the production code.
        Swapping the production comparison to `==` makes compare_digest go
        uncalled, so this test fails — the regression is now guarded.
        """
        import mcp_stdio.oauth as oauth_mod
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        calls: list[tuple[str, str]] = []
        real_compare = oauth_mod.secrets.compare_digest

        def spying_compare(a, b):
            calls.append((a, b))
            return real_compare(a, b)

        monkeypatch.setattr(oauth_mod.secrets, "compare_digest", spying_compare)

        httpx_mock.add_response(url="https://example.com/mcp", status_code=401)
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "registration_endpoint": "https://example.com/register",
            },
        )
        httpx_mock.add_response(
            url="https://example.com/register",
            json={"client_id": "cid"},
        )

        sent: dict[str, str] = {}

        def fake_open(auth_url: str) -> bool:
            q = parse_qs(urlparse(auth_url).query)
            sent["state"] = q["state"][0]
            redirect_uri = q["redirect_uri"][0]

            def hit_callback() -> None:
                cb_url = f"{redirect_uri}?code=evil&state=attacker-state"
                try:
                    urlopen(cb_url, timeout=5).read()
                except Exception:
                    pass

            threading.Thread(target=hit_callback, daemon=True).start()
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)

        client = httpx.Client()
        with pytest.raises(RuntimeError, match="state mismatch"):
            ensure_token(self.SERVER_URL, client, timeout=5)

        # The production CSRF check called compare_digest with the callback's
        # state and the state we sent — proving the constant-time path is live.
        assert ("attacker-state", sent["state"]) in calls


class TestScopeOmittedWhenUnset:
    """No configured scope -> the authorize URL carries no ``scope`` param at
    all (never an empty ``scope=``). Guards the failure class of
    claude-code#72440 (AADSTS900144 on Microsoft Entra ID). The device-flow
    twin lives in TestDeviceAuthorizationFlow."""

    SERVER_URL = "https://example.com/mcp"

    def test_authorize_url_has_no_scope_param(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        httpx_mock.add_response(url="https://example.com/mcp", status_code=401)
        httpx_mock.add_response(
            url=(
                "https://example.com/.well-known/"
                "oauth-protected-resource/mcp"
            ),
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "registration_endpoint": "https://example.com/register",
            },
        )
        httpx_mock.add_response(
            url="https://example.com/register",
            json={"client_id": "cid"},
        )
        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "at", "token_type": "Bearer"},
        )

        captured_auth_urls: list[str] = []

        def fake_open(auth_url: str) -> bool:
            captured_auth_urls.append(auth_url)
            q = parse_qs(urlparse(auth_url).query)
            redirect_uri = q["redirect_uri"][0]
            state = q["state"][0]

            def hit_callback() -> None:
                cb_url = f"{redirect_uri}?code=ok_code&state={state}"
                try:
                    urlopen(cb_url, timeout=5).read()
                except Exception:
                    pass

            threading.Thread(target=hit_callback, daemon=True).start()
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)

        client = httpx.Client()
        data = ensure_token(self.SERVER_URL, client, timeout=5)
        assert data is not None and data.access_token == "at"

        assert len(captured_auth_urls) == 1
        q = parse_qs(urlparse(captured_auth_urls[0]).query)
        assert "scope" not in q
        # Positive control: the URL is fully formed otherwise.
        assert q["resource"] == [self.SERVER_URL]


class TestAuthorizationFlowFailurePaths:
    """End-to-end failure paths of `_run_authorization_flow`: the callback
    timeout and the server-returned-error branch (both clean up the server)."""

    META = OAuthMetadata(
        authorization_endpoint="https://ex.com/authorize",
        token_endpoint="https://ex.com/token",
    )

    def test_callback_timeout_raises(self, monkeypatch):
        """No callback ever arrives → TimeoutError after the deadline."""
        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", lambda _url: True)
        client = httpx.Client()
        with pytest.raises(TimeoutError, match="callback not received"):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=self.META,
                cached=None,
                client_id_override="cid",
                timeout=0.3,
            )

    def test_authorize_url_log_redacts_state(self, monkeypatch, capsys):
        """#4: the authorize URL logged to stderr must REDACT the single-use
        CSRF state nonce (stderr persists to shareable host logs), while the
        browser still receives the full URL with the real state."""
        from urllib.parse import parse_qs, urlparse

        opened: dict[str, str] = {}

        def fake_open(url: str) -> bool:
            opened["url"] = url
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)
        client = httpx.Client()
        with pytest.raises(TimeoutError):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=self.META,
                cached=None,
                client_id_override="cid",
                timeout=0.3,
            )
        err = capsys.readouterr().err
        real_state = parse_qs(urlparse(opened["url"]).query)["state"][0]
        # Browser got the real nonce; stderr log got a redacted placeholder.
        assert "state=%3Credacted%3E" in err
        assert real_state not in err

    def test_callback_error_with_matching_state_raises_oauth_error(
        self, monkeypatch
    ):
        """A LEGITIMATE error callback echoes `state` (RFC 6749 §4.1.2.1) →
        surfaces the OAuth error, no code exchange. (: state is now
        validated before the error is acted on.)"""
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        def fake_open(auth_url: str) -> bool:
            q = parse_qs(urlparse(auth_url).query)
            redirect_uri = q["redirect_uri"][0]
            sent_state = q["state"][0]

            def hit() -> None:
                try:
                    urlopen(
                        f"{redirect_uri}?error=access_denied&state={sent_state}",
                        timeout=5,
                    ).read()
                except Exception:
                    pass

            threading.Thread(target=hit, daemon=True).start()
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="OAuth error"):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=self.META,
                cached=None,
                client_id_override="cid",
                timeout=5,
            )

    def test_callback_error_without_state_rejected_as_csrf(self, monkeypatch):
        """: an error callback that does NOT carry the matching state
        is an unauthenticated abort attempt (a local process / port-guessing page
        hitting /callback?error=... during the auth window), not a real AS error.
        State is validated first, so it is rejected as a CSRF mismatch — it
        cannot grief the flow with an attacker-chosen error."""
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        def fake_open(auth_url: str) -> bool:
            redirect_uri = parse_qs(urlparse(auth_url).query)["redirect_uri"][0]

            def hit() -> None:
                try:
                    # No state -> unauthenticated abort.
                    urlopen(f"{redirect_uri}?error=access_denied", timeout=5).read()
                except Exception:
                    pass

            threading.Thread(target=hit, daemon=True).start()
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="state mismatch"):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=self.META,
                cached=None,
                client_id_override="cid",
                timeout=5,
            )

    def test_dcr_failure_closes_callback_server(self, monkeypatch):
        """If DCR raises before the success-path close, the localhost callback
        server is still closed so its listening socket is not leaked."""
        import mcp_stdio.oauth as oauth_mod

        closed: list[bool] = []
        real_server_close = oauth_mod.HTTPServer.server_close

        def spying_close(self) -> None:
            closed.append(True)
            real_server_close(self)

        monkeypatch.setattr(oauth_mod.HTTPServer, "server_close", spying_close)

        def boom(*_args, **_kwargs):
            raise RuntimeError("registration refused")

        monkeypatch.setattr("mcp_stdio.oauth.register_client", boom)
        # No client_id_override and no cached client → DCR path is taken.
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="registration refused"):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=self.META,
                cached=None,
                client_id_override=None,
                timeout=5,
            )
        assert closed, "callback server was not closed on the DCR error path"

    def test_webbrowser_open_failure_closes_callback_server(self, monkeypatch):
        """: a failure AFTER the callback server is bound but before
        the success-path close (here webbrowser.open raising) must still close
        the server — the try/finally covers the whole listening window, not just
        DCR."""
        import mcp_stdio.oauth as oauth_mod

        closed: list[bool] = []
        real_server_close = oauth_mod.HTTPServer.server_close

        def spying_close(self) -> None:
            closed.append(True)
            real_server_close(self)

        monkeypatch.setattr(oauth_mod.HTTPServer, "server_close", spying_close)

        def boom(_url):
            raise RuntimeError("no browser available")

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", boom)
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="no browser available"):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=self.META,
                cached=None,
                client_id_override="cid",  # skip DCR; reach the webbrowser step
                timeout=5,
            )
        assert closed, "callback server was not closed on the webbrowser failure"


class TestClientIdMetadataDocument:
    """#60: Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-
    document-00) support in `_run_authorization_flow`'s client_id resolution.

    Each test captures the `client_id` query param `_run_authorization_flow`
    sends to the (mocked) authorization endpoint, then lets the flow time out
    (no callback ever arrives) — the resolution happens before the browser is
    opened, so the timeout is an inert way to end the flow without a full
    code-exchange mock.
    """

    URL = "https://app.example.com/oauth/client-metadata.json"

    def _capture_client_id(self, monkeypatch) -> dict[str, str]:
        from urllib.parse import parse_qs, urlparse

        captured: dict[str, str] = {}

        def fake_open(auth_url: str) -> bool:
            captured["client_id"] = parse_qs(urlparse(auth_url).query)["client_id"][0]
            return True

        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", fake_open)
        return captured

    def test_used_when_as_advertises_support(self, monkeypatch):
        """AS advertises support, no cached/override client_id -> the CIMD URL
        is used as client_id and DCR is never attempted."""
        captured = self._capture_client_id(monkeypatch)

        def boom(*_args, **_kwargs):
            raise AssertionError("DCR must not run when CIMD applies")

        monkeypatch.setattr("mcp_stdio.oauth.register_client", boom)
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/authorize",
            token_endpoint="https://ex.com/token",
            registration_endpoint="https://ex.com/register",
            client_id_metadata_document_supported=True,
        )
        client = httpx.Client()
        with pytest.raises(TimeoutError):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=meta,
                cached=None,
                client_metadata_url=self.URL,
                timeout=0.3,
            )
        assert captured["client_id"] == self.URL

    def test_used_with_warning_when_as_does_not_advertise_support(
        self, monkeypatch, capsys
    ):
        """An explicit --client-metadata-url is honoured even when the AS
        metadata doesn't confirm client_id_metadata_document_supported — the
        flag is an explicit opt-in and must not be silently dropped, but a
        warning is emitted so a parse miss / misconfigured AS is actionable."""
        captured = self._capture_client_id(monkeypatch)
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/authorize",
            token_endpoint="https://ex.com/token",
            # client_id_metadata_document_supported defaults to False
        )
        client = httpx.Client()
        with pytest.raises(TimeoutError):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=meta,
                cached=None,
                client_metadata_url=self.URL,
                timeout=0.3,
            )
        assert captured["client_id"] == self.URL
        assert (
            "client_id_metadata_document_supported" in capsys.readouterr().err
        )

    def test_explicit_client_id_override_wins(self, monkeypatch):
        """--client-id (a pre-registered id) outranks --client-metadata-url
        per the MCP client-registration priority order."""
        captured = self._capture_client_id(monkeypatch)
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/authorize",
            token_endpoint="https://ex.com/token",
            client_id_metadata_document_supported=True,
        )
        client = httpx.Client()
        with pytest.raises(TimeoutError):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=meta,
                cached=None,
                client_id_override="preregistered-cid",
                client_metadata_url=self.URL,
                timeout=0.3,
            )
        assert captured["client_id"] == "preregistered-cid"

    def test_overrides_cached_dcr_client_id(self, monkeypatch):
        """An explicit --client-metadata-url is used even when a cached
        (previously DCR-registered) client_id exists — the explicit flag is a
        deliberate per-invocation choice, not second-guessed by a stale cache."""
        captured = self._capture_client_id(monkeypatch)
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/authorize",
            token_endpoint="https://ex.com/token",
            client_id_metadata_document_supported=True,
        )
        cached = TokenData(
            access_token="stale",
            client_id="dcr-registered-cid",
            token_endpoint="https://ex.com/token",
            authorization_endpoint="https://ex.com/authorize",
        )
        client = httpx.Client()
        with pytest.raises(TimeoutError):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=meta,
                cached=cached,
                client_metadata_url=self.URL,
                timeout=0.3,
            )
        assert captured["client_id"] == self.URL

    def test_no_client_metadata_url_falls_back_to_dcr(self, monkeypatch):
        """Without --client-metadata-url, behaviour is unchanged: DCR still
        runs even when the AS advertises CIMD support."""
        captured = self._capture_client_id(monkeypatch)
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/authorize",
            token_endpoint="https://ex.com/token",
            registration_endpoint="https://ex.com/register",
            client_id_metadata_document_supported=True,
        )
        client = httpx.Client()

        def fake_register_client(*_args, **_kwargs):
            from mcp_stdio.oauth import ClientRegistration

            return ClientRegistration(client_id="dcr-cid")

        monkeypatch.setattr(
            "mcp_stdio.oauth.register_client", fake_register_client
        )
        with pytest.raises(TimeoutError):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=meta,
                cached=None,
                timeout=0.3,
            )
        assert captured["client_id"] == "dcr-cid"


class TestClientIdMetadataDocumentDeviceFlow:
    """#60: same Client ID Metadata Document priority order, for
    `_run_device_authorization_flow`.

    Note: the CIMD spec (draft-ietf-oauth-client-id-metadata-document-00) and
    the MCP authorization spec describe this mechanism in auth-code/redirect
    terms only — the metadata document's REQUIRED `redirect_uris` field is
    meaningless for the device grant. Sending a URL-formatted client_id on
    the device-authorization request is a client-side extrapolation (the
    value is just an opaque string to mcp-stdio); these tests verify
    mcp-stdio's own client_id-resolution logic, not that any real AS accepts
    it on this endpoint — no spec mandates that and no AS was available to
    confirm it end-to-end.
    """

    URL = "https://app.example.com/oauth/client-metadata.json"
    META = OAuthMetadata(
        authorization_endpoint="https://ex.com/authorize",
        token_endpoint="https://ex.com/token",
        device_authorization_endpoint="https://ex.com/device",
        client_id_metadata_document_supported=True,
    )

    def test_used_instead_of_dcr(self, httpx_mock):
        """The CIMD URL is sent as client_id on the device-authorization
        request, and DCR (no registration_endpoint here) is never needed."""
        httpx_mock.add_response(
            url="https://ex.com/device",
            json={
                "device_code": "dc",
                "user_code": "UC",
                "verification_uri": "https://ex.com/verify",
                "expires_in": 1,
                "interval": 1,
            },
        )
        httpx_mock.add_response(
            url="https://ex.com/token",
            status_code=400,
            json={"error": "expired_token"},
        )
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="expired_token|Device flow failed"):
            _run_device_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=self.META,
                cached=None,
                client_metadata_url=self.URL,
                timeout=5,
            )
        from urllib.parse import quote

        sent = httpx_mock.get_requests(url="https://ex.com/device")[0]
        assert f"client_id={quote(self.URL, safe='')}".encode() in sent.content

    def test_enables_device_flow_with_no_registration_endpoint(self, httpx_mock):
        """A server with NO registration_endpoint at all (no DCR support) lets
        --client-metadata-url's client_id through to the device-authorization
        request instead of raising. Whether a real AS *accepts* a URL-shaped
        client_id there is unverified (see the class docstring) — this only
        confirms mcp-stdio's own resolution logic doesn't block on missing
        DCR (mcp-remote#224 / #60)."""
        meta = OAuthMetadata(
            authorization_endpoint="https://ex.com/authorize",
            token_endpoint="https://ex.com/token",
            device_authorization_endpoint="https://ex.com/device",
            registration_endpoint=None,
            client_id_metadata_document_supported=False,  # not advertised either
        )
        httpx_mock.add_response(
            url="https://ex.com/device",
            json={
                "device_code": "dc",
                "user_code": "UC",
                "verification_uri": "https://ex.com/verify",
                "expires_in": 1,
                "interval": 1,
            },
        )
        httpx_mock.add_response(
            url="https://ex.com/token",
            status_code=400,
            json={"error": "expired_token"},
        )
        client = httpx.Client()
        with pytest.raises(RuntimeError):
            _run_device_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=meta,
                cached=None,
                client_metadata_url=self.URL,
                timeout=5,
            )
        from urllib.parse import quote

        sent = httpx_mock.get_requests(url="https://ex.com/device")[0]
        assert f"client_id={quote(self.URL, safe='')}".encode() in sent.content


class TestRfc9207IssValidation:
    """RFC 9207: validate the authorization-response `iss` parameter against the
    discovered issuer (AS mix-up defence)."""

    META = OAuthMetadata(
        authorization_endpoint="https://ex.com/authorize",
        token_endpoint="https://ex.com/token",
        issuer="https://ex.com",
    )

    def _driver(self, extra_query: str):
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        def fake_open(auth_url: str) -> bool:
            q = parse_qs(urlparse(auth_url).query)
            redirect_uri = q["redirect_uri"][0]
            state = q["state"][0]
            cb = f"{redirect_uri}?code=c&state={state}"
            if extra_query:
                cb += f"&{extra_query}"

            def hit() -> None:
                try:
                    urlopen(cb, timeout=5).read()
                except Exception:
                    pass

            threading.Thread(target=hit, daemon=True).start()
            return True

        return fake_open

    def test_iss_mismatch_raises(self, monkeypatch):
        monkeypatch.setattr(
            "mcp_stdio.oauth.webbrowser.open", self._driver("iss=https://evil.example")
        )
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="issuer mismatch"):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=self.META,
                cached=None,
                client_id_override="cid",
                timeout=5,
            )

    def test_iss_match_proceeds(self, httpx_mock, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        httpx_mock.add_response(
            url="https://ex.com/token",
            json={"access_token": "at", "token_type": "Bearer"},
        )
        monkeypatch.setattr(
            "mcp_stdio.oauth.webbrowser.open", self._driver("iss=https://ex.com")
        )
        client = httpx.Client()
        data = _run_authorization_flow(
            "https://ex.com/mcp",
            client,
            metadata=self.META,
            cached=None,
            client_id_override="cid",
            timeout=5,
        )
        assert data.access_token == "at"

    def test_trailing_slash_iss_does_not_false_mismatch(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """: the iss compare is trailing-slash tolerant, so a Phase-3
        synthesized issuer ('https://ex.com', no slash) does NOT false-mismatch an
        AS whose real iss is 'https://ex.com/' — the flow proceeds. A genuine
        mix-up (different host) is still caught (test_iss_mismatch_raises)."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        httpx_mock.add_response(
            url="https://ex.com/token",
            json={"access_token": "at", "token_type": "Bearer"},
        )
        monkeypatch.setattr(
            "mcp_stdio.oauth.webbrowser.open",
            self._driver("iss=https://ex.com/"),
        )
        client = httpx.Client()
        data = _run_authorization_flow(
            "https://ex.com/mcp",
            client,
            metadata=self.META,
            cached=None,
            client_id_override="cid",
            timeout=5,
        )
        assert data.access_token == "at"

    def test_stepup_preserves_requested_scope_when_response_omits_it(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """#2: a step-up token response that OMITS scope (RFC 6749 §5.1, when it
        equals the requested scope) must keep the requested/merged union in the
        stored TokenData — not wipe it to None and shrink the next step-up."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        # Token response deliberately omits "scope".
        httpx_mock.add_response(
            url="https://ex.com/token",
            json={"access_token": "at", "token_type": "Bearer"},
        )
        monkeypatch.setattr(
            "mcp_stdio.oauth.webbrowser.open", self._driver("iss=https://ex.com")
        )
        client = httpx.Client()
        data = _run_authorization_flow(
            "https://ex.com/mcp",
            client,
            metadata=self.META,
            cached=None,
            client_id_override="cid",
            scope="read write admin",  # the merged union a step-up requests
            timeout=5,
        )
        assert data.scope == "read write admin"

    def test_stepup_preserves_cached_refresh_token_when_response_omits_it(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """: a step-up token response that OMITS refresh_token (RFC
        6749 §5.1, OPTIONAL) must keep the CACHED refresh_token in the stored
        TokenData — not overwrite it with None, which would break every future
        silent refresh until the next interactive flow. Mirrors the scope
        preservation above and the refresh path."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        # Token response deliberately omits "refresh_token".
        httpx_mock.add_response(
            url="https://ex.com/token",
            json={"access_token": "new_at", "token_type": "Bearer"},
        )
        monkeypatch.setattr(
            "mcp_stdio.oauth.webbrowser.open", self._driver("iss=https://ex.com")
        )
        cached = TokenData(
            access_token="old_at",
            refresh_token="cached_rt",
            client_id="cid",  # reused → no DCR
            token_endpoint="https://ex.com/token",
            authorization_endpoint="https://ex.com/authorize",
        )
        client = httpx.Client()
        data = _run_authorization_flow(
            "https://ex.com/mcp",
            client,
            metadata=self.META,
            cached=cached,
            scope="read write",
            timeout=5,
        )
        assert data.access_token == "new_at"
        assert data.refresh_token == "cached_rt"  # preserved, not wiped to None
        # And it survives the round-trip to disk.
        from mcp_stdio.token_store import load_token

        assert load_token("https://ex.com/mcp").refresh_token == "cached_rt"

    def test_no_iss_skips_validation(self, httpx_mock, tmp_path, monkeypatch):
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        httpx_mock.add_response(
            url="https://ex.com/token",
            json={"access_token": "at", "token_type": "Bearer"},
        )
        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", self._driver(""))
        client = httpx.Client()
        data = _run_authorization_flow(
            "https://ex.com/mcp",
            client,
            metadata=self.META,
            cached=None,
            client_id_override="cid",
            timeout=5,
        )
        assert data.access_token == "at"

    # RFC 9207 §2.4 second MUST: reject a missing iss from an AS that advertises
    # support (authorization_response_iss_parameter_supported). #4/.
    META_ISS_SUPPORTED = OAuthMetadata(
        authorization_endpoint="https://ex.com/authorize",
        token_endpoint="https://ex.com/token",
        issuer="https://ex.com",
        iss_parameter_supported=True,
    )

    def test_missing_iss_rejected_when_as_advertises_support(self, monkeypatch):
        """An AS that advertised iss support but whose response OMITS iss must be
        rejected (a mix-up attacker could otherwise strip iss to silence the
        compare)."""
        monkeypatch.setattr("mcp_stdio.oauth.webbrowser.open", self._driver(""))
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="issuer missing"):
            _run_authorization_flow(
                "https://ex.com/mcp",
                client,
                metadata=self.META_ISS_SUPPORTED,
                cached=None,
                client_id_override="cid",
                timeout=5,
            )

    def test_present_iss_accepted_when_as_advertises_support(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """When the AS advertises iss support and the response carries a matching
        iss, the flow proceeds normally."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)
        httpx_mock.add_response(
            url="https://ex.com/token",
            json={"access_token": "at", "token_type": "Bearer"},
        )
        monkeypatch.setattr(
            "mcp_stdio.oauth.webbrowser.open", self._driver("iss=https://ex.com")
        )
        client = httpx.Client()
        data = _run_authorization_flow(
            "https://ex.com/mcp",
            client,
            metadata=self.META_ISS_SUPPORTED,
            cached=None,
            client_id_override="cid",
            timeout=5,
        )
        assert data.access_token == "at"


# --- _parse_resource_metadata_hint ---


class TestParseResourceMetadataHint:
    def test_quoted_value(self):
        """RFC 9728 §5.1: resource_metadata in double quotes."""
        header = 'Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"'
        assert (
            _parse_resource_metadata_hint(header)
            == "https://resource.example.com/.well-known/oauth-protected-resource"
        )

    def test_unquoted_value(self):
        """Unquoted resource_metadata (some servers omit quotes)."""
        header = "Bearer resource_metadata=https://resource.example.com/prm"
        assert (
            _parse_resource_metadata_hint(header)
            == "https://resource.example.com/prm"
        )

    def test_with_other_params(self):
        """resource_metadata combined with other Bearer parameters."""
        header = 'Bearer realm="example", resource_metadata="https://resource.example.com/prm", error="invalid_token"'
        assert (
            _parse_resource_metadata_hint(header)
            == "https://resource.example.com/prm"
        )

    def test_no_resource_metadata(self):
        """WWW-Authenticate without resource_metadata returns None."""
        header = 'Bearer realm="example", error="invalid_token"'
        assert _parse_resource_metadata_hint(header) is None

    def test_none_header(self):
        """None input returns None."""
        assert _parse_resource_metadata_hint(None) is None

    def test_empty_header(self):
        """Empty string returns None."""
        assert _parse_resource_metadata_hint("") is None

    def test_different_scheme_ignored(self):
        """Non-Bearer scheme without resource_metadata returns None."""
        header = "Basic realm=example"
        assert _parse_resource_metadata_hint(header) is None

    def test_decoy_param_ending_in_name_ignored(self):
        """A param name merely ending in "resource_metadata" must not win.

        Defect class of modelcontextprotocol/python-sdk#3009: a name-suffix
        decoy (x_resource_metadata=, and the wider-tchar x.resource_metadata=)
        is a distinct auth-param, not the resource_metadata hint.
        """
        for decoy in ("x_resource_metadata", "x.resource_metadata"):
            header = (
                f'Bearer {decoy}="https://decoy.example.com/prm", '
                'resource_metadata="https://resource.example.com/prm"'
            )
            assert (
                _parse_resource_metadata_hint(header)
                == "https://resource.example.com/prm"
            )

    def test_decoy_param_only_returns_none(self):
        """x_resource_metadata alone is not a resource_metadata hint."""
        header = 'Bearer x_resource_metadata="https://decoy.example.com/prm"'
        assert _parse_resource_metadata_hint(header) is None

    def test_unquoted_decoy_param_before_real_value(self):
        """Unquoted form: the decoy param must not shadow the real one."""
        header = (
            "Bearer x_resource_metadata=https://decoy.example.com/prm, "
            "resource_metadata=https://resource.example.com/prm"
        )
        assert (
            _parse_resource_metadata_hint(header)
            == "https://resource.example.com/prm"
        )

    def test_value_inside_other_param_ignored(self):
        """resource_metadata= inside another param's quoted value is not a hint."""
        header = (
            'Bearer realm="see resource_metadata=https://evil.example/prm for docs"'
        )
        assert _parse_resource_metadata_hint(header) is None

    def test_case_insensitive_param_name(self):
        """Auth-param names are case-insensitive (RFC 9110 §11.2)."""
        header = 'Bearer Resource_Metadata="https://resource.example.com/prm"'
        assert (
            _parse_resource_metadata_hint(header)
            == "https://resource.example.com/prm"
        )


# --- _validate_prm_hint_url ---


class TestValidatePrmHintUrl:
    SERVER = "https://api.example.com/mcp"

    def test_https_same_origin_valid(self):
        assert _validate_prm_hint_url("https://api.example.com/prm", self.SERVER) is True

    def test_https_cross_origin_valid_with_warning(self, capsys):
        result = _validate_prm_hint_url("https://other.example.com/prm", self.SERVER)
        assert result is True
        err = capsys.readouterr().err
        assert "cross-origin" in err

    def test_http_loopback_valid(self):
        result = _validate_prm_hint_url(
            "http://localhost/prm", "http://localhost:3000/mcp"
        )
        assert result is True

    def test_http_non_loopback_rejected(self):
        assert _validate_prm_hint_url("http://api.example.com/prm", self.SERVER) is False

    def test_unsupported_scheme_rejected(self):
        assert _validate_prm_hint_url("ftp://api.example.com/prm", self.SERVER) is False

    def test_malformed_url_rejected(self):
        assert _validate_prm_hint_url("not a url !!!", self.SERVER) is False

    def test_userinfo_rejected(self, capsys):
        """: an embedded userinfo hint is refused, parity with the
        sibling #13 validators (so HTTP Basic creds aren't sent on the GET)."""
        assert (
            _validate_prm_hint_url(
                "https://attacker:secret@api.example.com/prm", self.SERVER
            )
            is False
        )
        assert "userinfo" in capsys.readouterr().err


# --- discover_oauth_metadata with www_authenticate hint ---


class TestDiscoverMetadataWwwAuthenticate:
    def test_hint_used_as_phase0(self, httpx_mock):
        """RFC 9728 §5.1: resource_metadata hint URL is tried before well-known paths."""
        hint_url = "https://resource.example.com/.well-known/oauth-protected-resource"
        httpx_mock.add_response(
            url=hint_url,
            json={
                "resource": "https://api.example.com/mcp",
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        header = f'Bearer resource_metadata="{hint_url}"'
        meta = discover_oauth_metadata(
            "https://api.example.com/mcp", client, www_authenticate=header
        )
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"
        # Hint URL was fetched — confirm by checking request history
        urls = [str(r.url) for r in httpx_mock.get_requests()]
        assert hint_url in urls

    def test_hint_failure_falls_back_to_well_known(self, httpx_mock):
        """Phase 0 hint 404 → falls through to normal well-known discovery."""
        hint_url = "https://resource.example.com/.well-known/oauth-protected-resource"
        httpx_mock.add_response(url=hint_url, status_code=404)
        # Phase 1 well-known URLs also 404
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/token",
            },
        )
        client = httpx.Client()
        header = f'Bearer resource_metadata="{hint_url}"'
        meta = discover_oauth_metadata(
            "https://api.example.com/mcp", client, www_authenticate=header
        )
        assert meta.authorization_endpoint == "https://api.example.com/auth"

    def test_no_hint_normal_discovery(self, httpx_mock):
        """Without www_authenticate, discovery proceeds normally (no extra request)."""
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/token",
            },
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://api.example.com/auth"

    def test_invalid_hint_url_skipped(self, httpx_mock):
        """Insecure http:// hint URL is rejected; well-known discovery runs instead."""
        hint_url = "http://attacker.example.com/steal-tokens"
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/token",
            },
        )
        client = httpx.Client()
        header = f"Bearer resource_metadata={hint_url}"
        meta = discover_oauth_metadata(
            "https://api.example.com/mcp", client, www_authenticate=header
        )
        assert meta.authorization_endpoint == "https://api.example.com/auth"
        # Attacker URL must never have been fetched
        urls = [str(r.url) for r in httpx_mock.get_requests()]
        assert hint_url not in urls

    def test_hint_not_duplicated_when_same_as_well_known(self, httpx_mock):
        """When hint URL equals the well-known path, it is fetched only once."""
        # The hint happens to match the path-aware well-known URL
        hint_url = "https://api.example.com/.well-known/oauth-protected-resource/mcp"
        httpx_mock.add_response(
            url=hint_url,
            json={
                "resource": "https://api.example.com/mcp",
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        client = httpx.Client()
        header = f'Bearer resource_metadata="{hint_url}"'
        meta = discover_oauth_metadata(
            "https://api.example.com/mcp", client, www_authenticate=header
        )
        assert meta.authorization_endpoint == "https://auth.example.com/authorize"
        # The hint URL must appear exactly once in request history
        urls = [str(r.url) for r in httpx_mock.get_requests()]
        assert urls.count(hint_url) == 1


# --- _probe_www_authenticate ---


class TestProbeWwwAuthenticate:
    MCP_URL = "https://api.example.com/mcp"

    def test_returns_header_on_401(self, httpx_mock):
        """401 response with WWW-Authenticate yields the header value."""
        httpx_mock.add_response(
            url=self.MCP_URL,
            status_code=401,
            headers={
                "WWW-Authenticate": 'Bearer resource_metadata="https://resource.example.com/prm"'
            },
        )
        client = httpx.Client()
        result = _probe_www_authenticate(self.MCP_URL, client)
        assert result == 'Bearer resource_metadata="https://resource.example.com/prm"'

    def test_returns_none_on_401_without_header(self, httpx_mock):
        """401 without WWW-Authenticate header returns None."""
        httpx_mock.add_response(url=self.MCP_URL, status_code=401)
        client = httpx.Client()
        assert _probe_www_authenticate(self.MCP_URL, client) is None

    def test_returns_none_on_200(self, httpx_mock):
        """200 response (server doesn't require auth) returns None."""
        httpx_mock.add_response(url=self.MCP_URL, status_code=200, text="{}")
        client = httpx.Client()
        assert _probe_www_authenticate(self.MCP_URL, client) is None

    def test_returns_none_on_405(self, httpx_mock):
        """405 Method Not Allowed returns None."""
        httpx_mock.add_response(url=self.MCP_URL, status_code=405)
        client = httpx.Client()
        assert _probe_www_authenticate(self.MCP_URL, client) is None

    def test_returns_none_on_connection_error(self, httpx_mock):
        """Connection error silently returns None."""
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        client = httpx.Client()
        assert _probe_www_authenticate(self.MCP_URL, client) is None

    def test_probe_sends_post_with_json(self, httpx_mock):
        """Probe uses POST with Content-Type: application/json."""
        httpx_mock.add_response(url=self.MCP_URL, status_code=401)
        client = httpx.Client()
        _probe_www_authenticate(self.MCP_URL, client)
        req = httpx_mock.get_requests()[0]
        assert req.method == "POST"
        assert req.headers.get("content-type") == "application/json"
        body = json.loads(req.content)
        assert body["method"] == "initialize"


# --- Device Authorization Grant (RFC 8628) ---

MCP_URL = "https://api.example.com/mcp"
AUTH_URL = "https://api.example.com/authorize"
TOKEN_URL = "https://api.example.com/token"
REG_URL = "https://api.example.com/register"
DEVICE_AUTH_URL = "https://api.example.com/device_authorization"


def _device_meta(*, reg: bool = True) -> OAuthMetadata:
    return OAuthMetadata(
        authorization_endpoint=AUTH_URL,
        token_endpoint=TOKEN_URL,
        registration_endpoint=REG_URL if reg else None,
        device_authorization_endpoint=DEVICE_AUTH_URL,
    )


def _da_response(**kwargs: object) -> dict:
    base: dict = {
        "device_code": "DEV_CODE",
        "user_code": "ABCD-1234",
        "verification_uri": "https://example.com/activate",
        "expires_in": 1800,
        "interval": 1,
    }
    base.update(kwargs)
    return base


class TestDeviceAuthorizationFlow:
    def _patch_store(self, tmp_path: object, monkeypatch: object) -> None:
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

    def test_happy_path(self, httpx_mock, tmp_path, monkeypatch):
        """Full successful device flow: DA request → authorization_pending → token."""
        self._patch_store(tmp_path, monkeypatch)

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"error": "authorization_pending"},
            status_code=400,
        )
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={
                "access_token": "acc",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "ref",
            },
        )

        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL,
            client,
            metadata=_device_meta(),
            cached=None,
        )
        assert data.access_token == "acc"
        assert data.refresh_token == "ref"
        assert data.client_id == "cid"

    @pytest.mark.parametrize("body", [[], "nope", 7])
    def test_non_object_device_auth_body_raises(
        self, httpx_mock, tmp_path, monkeypatch, body
    ):
        """: a non-object device-authorization body (a bare array /
        scalar) would make da.get('device_code') raise AttributeError. Surface a
        clear RuntimeError naming the type instead."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=body)
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="non-object JSON body"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )

    def test_infinity_expires_in_does_not_crash(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """: the client's json.loads parses the non-standard literal
        `Infinity` into float('inf') (parse_constant defaults to it). A device-
        authorization response carrying expires_in=Infinity must NOT crash the
        flow — _safe_int catches the int(inf) OverflowError and clamps to the
        default, so the flow completes normally."""
        self._patch_store(tmp_path, monkeypatch)
        monkeypatch.setattr(time, "sleep", lambda _s: None)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        # Hand-write the raw JSON body: httpx's json= encoder is allow_nan=False
        # and would reject inf at mock-construction time. The realistic vector is
        # an AS that emits a literal `Infinity` on the wire, which the CLIENT's
        # json.loads (allow_nan=True) then parses back into float('inf').
        da_body = (
            '{"device_code": "DEV_CODE", "user_code": "ABCD-1234", '
            '"verification_uri": "https://example.com/activate", '
            '"expires_in": Infinity, "interval": Infinity}'
        )
        httpx_mock.add_response(
            url=DEVICE_AUTH_URL,
            text=da_body,
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},
        )
        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL, client, metadata=_device_meta(), cached=None
        )
        assert data.access_token == "acc"

    def test_preserves_requested_scope_when_omitted(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """: a device-flow token response that OMITS scope (RFC 6749
        §5.1) must keep the requested scope in the stored TokenData — mirrors the
        auth-code / refresh paths."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        # Token response deliberately omits "scope".
        httpx_mock.add_response(
            url=TOKEN_URL, json={"access_token": "acc", "token_type": "Bearer"}
        )

        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL,
            client,
            metadata=_device_meta(),
            cached=None,
            scope="read write",
        )
        assert data.scope == "read write"

    def test_poll_non_json_error_body_raises_http_error(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """: a poll response with a non-JSON error body must surface a
        clean HTTP error via raise_for_status, not crash on .json()."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        # Poll → 400 with an HTML (non-JSON) body.
        httpx_mock.add_response(
            url=TOKEN_URL,
            status_code=400,
            headers={"content-type": "text/html"},
            text="<html><body>Bad Request</body></html>",
        )
        client = httpx.Client()
        with pytest.raises(httpx.HTTPStatusError):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )

    def test_poll_2xx_non_json_body_fast_fails(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """: a non-200 2xx poll response (e.g. 202) with a non-JSON
        body is non-compliant (RFC 8628 §3.5 mandates 200 or 400+error) and
        retrying it never resolves — so the loop FAST-FAILS by name instead of
        spinning to the device-code deadline (the prior behavior was to
        sleep-and-continue, which wasted the whole code lifetime)."""
        self._patch_store(tmp_path, monkeypatch)
        monkeypatch.setattr(time, "sleep", lambda _s: None)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        # Poll: 202 (2xx but not 200) with a non-JSON body → fast-fail, not retry.
        httpx_mock.add_response(
            url=TOKEN_URL,
            status_code=202,
            headers={"content-type": "text/html"},
            text="<html>processing</html>",
        )

        client = httpx.Client()
        with pytest.raises(RuntimeError, match="unexpected non-JSON HTTP 202"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )

    def test_poll_2xx_valid_json_no_error_fast_fails(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """: a non-200 2xx with VALID JSON but no `error` key is the
        other spin path raise_for_status would no-op — it must also fast-fail by
        status, not loop to the deadline."""
        self._patch_store(tmp_path, monkeypatch)
        monkeypatch.setattr(time, "sleep", lambda _s: None)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(url=TOKEN_URL, status_code=202, json={})

        client = httpx.Client()
        with pytest.raises(RuntimeError, match="unexpected HTTP 202"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )

    def test_explicit_client_id_skips_dcr(self, httpx_mock, tmp_path, monkeypatch):
        """: with an explicit --client-id (client_id_override) the
        device flow uses it directly — no DCR /register POST — and the
        device-authorization POST carries that client_id."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL, json={"access_token": "acc", "token_type": "Bearer"}
        )

        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL,
            client,
            metadata=_device_meta(reg=False),  # no registration_endpoint
            cached=None,
            client_id_override="cid-from-flag",
        )
        assert data.access_token == "acc"
        assert data.client_id == "cid-from-flag"
        reqs = httpx_mock.get_requests()
        assert not any(str(r.url) == REG_URL for r in reqs)  # no DCR
        da = next(r for r in reqs if str(r.url) == DEVICE_AUTH_URL)
        assert b"client_id=cid-from-flag" in da.read()

    def test_expires_in_clamped_to_max_lifetime(
        self, httpx_mock, tmp_path, monkeypatch, capsys
    ):
        """#7: an inflated expires_in is clamped to the max device-flow lifetime
        so the poll loop cannot stay alive for years."""
        from mcp_stdio.oauth import _DEVICE_FLOW_MAX_LIFETIME_SECS

        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(
            url=DEVICE_AUTH_URL, json=_da_response(expires_in=999999999)
        )
        httpx_mock.add_response(
            url=TOKEN_URL, json={"access_token": "acc", "token_type": "Bearer"}
        )

        client = httpx.Client()
        _run_device_authorization_flow(
            MCP_URL, client, metadata=_device_meta(), cached=None
        )
        err = capsys.readouterr().err
        # No --oauth-timeout here, so the effective wait equals the clamped
        # server lifetime ( reworded the message to "giving up in").
        assert f"giving up in {_DEVICE_FLOW_MAX_LIFETIME_SECS}s" in err
        assert "999999999" not in err

    def test_verification_uri_complete_printed(self, httpx_mock, tmp_path, monkeypatch, capsys):
        """verification_uri_complete is shown when present — AND the user_code is
        STILL displayed for the user to confirm it matches (RFC 8628 §3.3.1 MUST,
        anti-phishing / device disambiguation)."""
        self._patch_store(tmp_path, monkeypatch)

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(
            url=DEVICE_AUTH_URL,
            json=_da_response(
                verification_uri_complete="https://example.com/activate?code=ABCD-1234"
            ),
        )
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},
        )

        client = httpx.Client()
        _run_device_authorization_flow(MCP_URL, client, metadata=_device_meta(), cached=None)
        err = capsys.readouterr().err
        assert "https://example.com/activate?code=ABCD-1234" in err
        # RFC 8628 §3.3.1: the user_code MUST still be shown even with the
        # complete URI, so the user can verify it against the authorizing page.
        assert "ABCD-1234" in err

    def test_user_code_printed_without_complete_uri(self, httpx_mock, tmp_path, monkeypatch, capsys):
        """When verification_uri_complete is absent, user_code is shown separately."""
        self._patch_store(tmp_path, monkeypatch)

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},
        )

        client = httpx.Client()
        _run_device_authorization_flow(MCP_URL, client, metadata=_device_meta(), cached=None)
        err = capsys.readouterr().err
        assert "ABCD-1234" in err
        assert "https://example.com/activate" in err

    def test_slow_down_increases_interval(self, httpx_mock, tmp_path, monkeypatch):
        """slow_down error extends the polling interval by 5 seconds."""
        self._patch_store(tmp_path, monkeypatch)

        intervals: list[float] = []

        def mock_sleep(secs: float) -> None:
            intervals.append(secs)

        monkeypatch.setattr(time, "sleep", mock_sleep)

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response(interval=1))
        httpx_mock.add_response(
            url=TOKEN_URL, json={"error": "slow_down"}, status_code=400
        )
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},
        )

        client = httpx.Client()
        _run_device_authorization_flow(MCP_URL, client, metadata=_device_meta(), cached=None)

        # slow_down fires on the first poll: interval becomes 6, then sleep(6).
        # Second poll succeeds immediately (no sleep).
        assert intervals == [6]

    def test_hostile_interval_is_clamped(self, httpx_mock, tmp_path, monkeypatch):
        """A huge AS-supplied interval is capped (and bounded by the deadline)
        so a single sleep cannot block for hours."""
        self._patch_store(tmp_path, monkeypatch)

        slept: list[float] = []
        monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        # interval=86400 (24h), expires_in=120 — must be clamped to <= 60 and
        # further bounded by the remaining deadline (~120s).
        httpx_mock.add_response(
            url=DEVICE_AUTH_URL, json=_da_response(interval=86400, expires_in=120)
        )
        httpx_mock.add_response(
            url=TOKEN_URL, json={"error": "authorization_pending"}, status_code=400
        )
        httpx_mock.add_response(
            url=TOKEN_URL, json={"access_token": "acc", "token_type": "Bearer"}
        )

        client = httpx.Client()
        _run_device_authorization_flow(MCP_URL, client, metadata=_device_meta(), cached=None)
        assert slept and all(s <= 60 for s in slept)

    def test_expired_token_raises(self, httpx_mock, tmp_path, monkeypatch):
        """expired_token error raises RuntimeError immediately."""
        self._patch_store(tmp_path, monkeypatch)

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL, json={"error": "expired_token"}, status_code=400
        )

        client = httpx.Client()
        with pytest.raises(RuntimeError, match="expired_token"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )

    def test_access_denied_raises(self, httpx_mock, tmp_path, monkeypatch):
        """access_denied error raises RuntimeError immediately."""
        self._patch_store(tmp_path, monkeypatch)

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL, json={"error": "access_denied"}, status_code=400
        )

        client = httpx.Client()
        with pytest.raises(RuntimeError, match="access_denied"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )

    def test_no_device_endpoint_raises(self):
        """Missing device_authorization_endpoint raises ValueError."""
        meta = OAuthMetadata(
            authorization_endpoint=AUTH_URL,
            token_endpoint=TOKEN_URL,
            device_authorization_endpoint=None,
        )
        client = httpx.Client()
        with pytest.raises(ValueError, match="device_authorization_endpoint"):
            _run_device_authorization_flow(MCP_URL, client, metadata=meta, cached=None)

    def test_no_registration_endpoint_raises(self):
        """No registration_endpoint and no cached client raises ValueError."""
        meta = OAuthMetadata(
            authorization_endpoint=AUTH_URL,
            token_endpoint=TOKEN_URL,
            registration_endpoint=None,
            device_authorization_endpoint=DEVICE_AUTH_URL,
        )
        client = httpx.Client()
        with pytest.raises(ValueError, match="--client-id"):
            _run_device_authorization_flow(MCP_URL, client, metadata=meta, cached=None)

    def test_reuses_cached_client_id(self, httpx_mock, tmp_path, monkeypatch):
        """Cached client_id is reused; DCR is skipped."""
        self._patch_store(tmp_path, monkeypatch)

        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},
        )

        cached = TokenData(
            access_token="",
            token_type="Bearer",
            token_endpoint=TOKEN_URL,
            authorization_endpoint=AUTH_URL,
            client_id="cached_cid",
        )
        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL, client, metadata=_device_meta(), cached=cached
        )
        assert data.client_id == "cached_cid"

        # No DCR request should have been made
        reqs = httpx_mock.get_requests()
        assert all(r.url.path != "/register" for r in reqs)

    def test_dcr_uses_device_code_grant_type(self, httpx_mock, tmp_path, monkeypatch):
        """DCR request must include device_code grant type (RFC 8628 §3.1)."""
        self._patch_store(tmp_path, monkeypatch)

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},
        )

        client = httpx.Client()
        _run_device_authorization_flow(MCP_URL, client, metadata=_device_meta(), cached=None)

        dcr_req = httpx_mock.get_requests()[0]
        assert dcr_req.url.path == "/register"
        body = json.loads(dcr_req.content)
        assert "urn:ietf:params:oauth:grant-type:device_code" in body["grant_types"]
        assert "redirect_uris" not in body
        # SEP-837: the headless device-flow client is also "native".
        assert body["application_type"] == "native"

    def test_device_flow_preserves_cached_id_token(self, httpx_mock, tmp_path, monkeypatch):
        """#59: a device-flow re-auth whose token response omits id_token keeps the
        cached id_token, so --oauth-use-id-token survives (matches refresh path)."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},  # no id_token
        )
        cached = TokenData(access_token="old", id_token="cached-idt")
        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL, client, metadata=_device_meta(), cached=cached
        )
        assert data.access_token == "acc"
        assert data.id_token == "cached-idt"

    def test_da_request_includes_resource_indicator(self, httpx_mock, tmp_path, monkeypatch):
        """Device Authorization Request must include resource parameter (RFC 8707)."""
        self._patch_store(tmp_path, monkeypatch)

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},
        )

        client = httpx.Client()
        _run_device_authorization_flow(MCP_URL, client, metadata=_device_meta(), cached=None)

        reqs = httpx_mock.get_requests()
        da_req = next(r for r in reqs if str(r.url).startswith(DEVICE_AUTH_URL))
        from urllib.parse import parse_qs
        body = parse_qs(da_req.content.decode())
        assert body.get("resource") == [MCP_URL]

    def test_da_request_omits_scope_when_unset(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """No scope configured -> no scope param at all (never an empty
        ``scope=``). Guards the failure class of claude-code#72440, where a
        v2.1.196 regression sent no scope on the unset path and Microsoft
        Entra ID rejected the request with AADSTS900144."""
        self._patch_store(tmp_path, monkeypatch)

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},
        )

        client = httpx.Client()
        _run_device_authorization_flow(
            MCP_URL, client, metadata=_device_meta(), cached=None
        )

        reqs = httpx_mock.get_requests()
        da_req = next(r for r in reqs if str(r.url).startswith(DEVICE_AUTH_URL))
        from urllib.parse import parse_qs
        body = parse_qs(da_req.content.decode())
        assert "scope" not in body

    def test_metadata_discovers_device_endpoint(self, httpx_mock):
        """device_authorization_endpoint is read from RFC 8414 metadata."""
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "issuer": "https://api.example.com",
                "authorization_endpoint": AUTH_URL,
                "token_endpoint": TOKEN_URL,
                "device_authorization_endpoint": DEVICE_AUTH_URL,
            },
        )

        client = httpx.Client()
        meta = discover_oauth_metadata(MCP_URL, client)
        assert meta.device_authorization_endpoint == DEVICE_AUTH_URL

    def test_omits_resource_when_resource_indicator_false(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """resource_indicator=False must suppress resource= in the DA request (Step 1)."""
        self._patch_store(tmp_path, monkeypatch)

        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer", "expires_in": 3600},
        )

        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL,
            client,
            metadata=_device_meta(),
            cached=None,
            resource_indicator=False,
        )
        assert data.access_token == "acc"
        assert data.no_resource_indicator is True

        da_reqs = [
            r for r in httpx_mock.get_requests() if str(r.url) == DEVICE_AUTH_URL
        ]
        assert len(da_reqs) == 1
        assert b"resource=" not in da_reqs[0].content

    def test_client_secret_post_carries_secret_in_body_and_scope(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """With client_secret_post auth, the device-auth POST and each poll POST
        carry client_id + client_secret in the body (not a Basic header), and a
        requested scope appears in the device-auth body."""
        from urllib.parse import parse_qs

        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL, json={"access_token": "acc", "token_type": "Bearer"}
        )
        cached = TokenData(
            access_token="",
            token_type="Bearer",
            token_endpoint=TOKEN_URL,
            authorization_endpoint=AUTH_URL,
            client_id="cid",
            client_secret="sshh",
            token_endpoint_auth_method="client_secret_post",
        )
        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL, client, metadata=_device_meta(), cached=cached, scope="hr:read"
        )
        assert data.access_token == "acc"

        reqs = httpx_mock.get_requests()
        da = next(r for r in reqs if str(r.url) == DEVICE_AUTH_URL)
        da_body = parse_qs(da.content.decode())
        assert da_body.get("client_id") == ["cid"]
        assert da_body.get("client_secret") == ["sshh"]
        assert da_body.get("scope") == ["hr:read"]
        assert "authorization" not in da.headers  # not Basic auth

        poll = next(r for r in reqs if str(r.url) == TOKEN_URL)
        poll_body = parse_qs(poll.content.decode())
        assert poll_body.get("client_id") == ["cid"]
        assert poll_body.get("client_secret") == ["sshh"]

    def test_google_verification_url_fallback(
        self, httpx_mock, tmp_path, monkeypatch, capsys
    ):
        """Google's device endpoint returns the non-standard ``verification_url``;
        the flow must accept it instead of dying with a KeyError."""
        self._patch_store(tmp_path, monkeypatch)
        da = _da_response()
        del da["verification_uri"]
        da["verification_url"] = "https://www.google.com/device"
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=da)
        httpx_mock.add_response(
            url=TOKEN_URL, json={"access_token": "acc", "token_type": "Bearer"}
        )
        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL, client, metadata=_device_meta(), cached=None
        )
        assert data.access_token == "acc"
        assert "https://www.google.com/device" in capsys.readouterr().err

    def test_missing_verification_uri_raises_clear_error(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """Neither verification_uri nor verification_url → a clear ValueError,
        not a raw KeyError."""
        self._patch_store(tmp_path, monkeypatch)
        da = _da_response()
        del da["verification_uri"]
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=da)
        client = httpx.Client()
        with pytest.raises(ValueError, match="verification_uri"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )

    def test_unsafe_verification_uri_rejected(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """A non-http(s) / cleartext verification_uri must be rejected, not
        presented to the user as an 'Open:' phishing target."""
        self._patch_store(tmp_path, monkeypatch)
        da = _da_response(verification_uri="http://phishing.example/login")
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=da)
        client = httpx.Client()
        with pytest.raises(ValueError, match="verification_uri"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )

    def test_missing_device_code_raises_clear_error(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """A device-auth response missing device_code/user_code → ValueError,
        not a bare KeyError."""
        self._patch_store(tmp_path, monkeypatch)
        da = _da_response()
        del da["device_code"]
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=da)
        client = httpx.Client()
        with pytest.raises(ValueError, match="device_code"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )

    def test_poll_deadline_exhaustion_raises_timeout(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """When the device code expires before the user authorizes, the poll
        loop raises TimeoutError. A fake clock crosses the deadline
        deterministically."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"error": "authorization_pending"},
            status_code=400,
            is_reusable=True,
        )

        clock = {"t": 0.0}
        monkeypatch.setattr(time, "monotonic", lambda: clock["t"])

        def jump_sleep(_secs: float) -> None:
            clock["t"] += 100000  # leap past the deadline after the first poll

        monkeypatch.setattr(time, "sleep", jump_sleep)

        client = httpx.Client()
        with pytest.raises(TimeoutError, match="timed out"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )

    def test_oauth_timeout_clamps_device_poll_lifetime(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """: --oauth-timeout bounds the device-code wait. With a
        timeout (5s) far below the server-advertised expires_in (1800s), the poll
        deadline is clamped to the timeout: a clock jump of 6s — past the 5s
        timeout but nowhere near the 1800s server lifetime — ends the flow with
        TimeoutError, proving the deadline was the clamped value, not 1800."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response(expires_in=1800))
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"error": "authorization_pending"},
            status_code=400,
            is_reusable=True,
        )
        clock = {"t": 0.0}
        monkeypatch.setattr(time, "monotonic", lambda: clock["t"])

        def jump_sleep(_secs: float) -> None:
            clock["t"] += 6  # past the 5s timeout, far below the 1800s expires_in

        monkeypatch.setattr(time, "sleep", jump_sleep)
        client = httpx.Client()
        with pytest.raises(TimeoutError, match="timed out"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None, timeout=5
            )
        # Exactly one token poll fired before the clamped 5s deadline was crossed;
        # without the clamp the 1800s deadline would have driven ~300 polls.
        polls = [r for r in httpx_mock.get_requests() if str(r.url) == TOKEN_URL]
        assert len(polls) == 1

    def test_oauth_timeout_does_not_extend_beyond_server_lifetime(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """: the clamp is min(timeout, expires_in) — a timeout LARGER
        than the server lifetime must not extend the wait. expires_in=10, a huge
        timeout, and a 11s clock jump (past expires_in, below timeout) still ends
        with TimeoutError: the deadline stayed at the 10s server lifetime."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response(expires_in=10))
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"error": "authorization_pending"},
            status_code=400,
            is_reusable=True,
        )
        clock = {"t": 0.0}
        monkeypatch.setattr(time, "monotonic", lambda: clock["t"])

        def jump_sleep(_secs: float) -> None:
            clock["t"] += 11  # past the 10s server lifetime, below the huge timeout

        monkeypatch.setattr(time, "sleep", jump_sleep)
        client = httpx.Client()
        with pytest.raises(TimeoutError, match="timed out"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None, timeout=99999
            )

    def test_poll_network_error_is_retried(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """A transient network error during polling must not abort the flow —
        the loop logs, sleeps, and continues to the next poll."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_exception(httpx.ConnectError("flaky"), url=TOKEN_URL)
        httpx_mock.add_response(
            url=TOKEN_URL, json={"access_token": "acc", "token_type": "Bearer"}
        )
        monkeypatch.setattr(time, "sleep", lambda _s: None)
        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL, client, metadata=_device_meta(), cached=None
        )
        assert data.access_token == "acc"

    def test_non_numeric_interval_and_expires_in_coerced(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """A float-as-string interval / expires_in from a malformed AS must be
        coerced to the default, not raise ValueError out of the flow."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(
            url=DEVICE_AUTH_URL,
            json=_da_response(interval="5.5", expires_in="not-a-number"),
        )
        httpx_mock.add_response(
            url=TOKEN_URL, json={"access_token": "acc", "token_type": "Bearer"}
        )
        monkeypatch.setattr(time, "sleep", lambda _s: None)
        client = httpx.Client()
        data = _run_device_authorization_flow(
            MCP_URL, client, metadata=_device_meta(), cached=None
        )
        assert data.access_token == "acc"

    def test_poll_unknown_error_surfaces_actionable_runtime_error(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """: a non-spec error code (e.g. invalid_client) now fast-fails
        with an actionable RuntimeError that names the AS error, instead of an
        opaque HTTPStatusError that drops the body — mirroring the
        error_description extraction the auth-code / refresh paths use."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={
                "error": "invalid_client",
                "error_description": "client authentication failed",
            },
            status_code=400,
        )
        monkeypatch.setattr(time, "sleep", lambda _s: None)
        client = httpx.Client()
        with pytest.raises(RuntimeError, match="client authentication failed"):
            _run_device_authorization_flow(
                MCP_URL, client, metadata=_device_meta(), cached=None
            )


class TestEnsureTokenDeviceFlow:
    MCP_URL = "https://api.example.com/mcp"
    WELL_KNOWN_PRM = "https://api.example.com/.well-known/oauth-protected-resource"
    WELL_KNOWN_AS = "https://api.example.com/.well-known/oauth-authorization-server"

    def _patch_store(self, tmp_path: object, monkeypatch: object) -> None:
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

    def _mock_discovery(self, httpx_mock: object) -> None:
        # path-aware PRM URL first (path component of /mcp is inserted)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        # host-root PRM URL second
        httpx_mock.add_response(url=self.WELL_KNOWN_PRM, status_code=404)
        httpx_mock.add_response(
            url=self.WELL_KNOWN_AS,
            json={
                "issuer": "https://api.example.com",
                "authorization_endpoint": AUTH_URL,
                "token_endpoint": TOKEN_URL,
                "registration_endpoint": REG_URL,
                "device_authorization_endpoint": DEVICE_AUTH_URL,
            },
        )

    def test_device_flow_flag_routes_to_device_flow(self, httpx_mock, tmp_path, monkeypatch):
        """ensure_token with device_flow=True uses Device Authorization Grant."""
        self._patch_store(tmp_path, monkeypatch)

        # probe
        httpx_mock.add_response(url=self.MCP_URL, status_code=401, headers={})
        self._mock_discovery(httpx_mock)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},
        )

        client = httpx.Client()
        data = ensure_token(self.MCP_URL, client, device_flow=True)
        assert data.access_token == "acc"

        # Verify device_authorization endpoint was actually called
        reqs = httpx_mock.get_requests()
        assert any(str(r.url).startswith(DEVICE_AUTH_URL) for r in reqs)

    def test_client_metadata_url_skips_dcr_end_to_end(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """#60: ensure_token(device_flow=True, client_metadata_url=...) against
        an AS advertising CIMD support skips DCR entirely (no request to
        REG_URL) and sends the metadata URL as client_id."""
        from urllib.parse import quote

        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=self.MCP_URL, status_code=401, headers={})
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(url=self.WELL_KNOWN_PRM, status_code=404)
        httpx_mock.add_response(
            url=self.WELL_KNOWN_AS,
            json={
                "issuer": "https://api.example.com",
                "authorization_endpoint": AUTH_URL,
                "token_endpoint": TOKEN_URL,
                "registration_endpoint": REG_URL,
                "device_authorization_endpoint": DEVICE_AUTH_URL,
                "client_id_metadata_document_supported": True,
            },
        )
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "acc", "token_type": "Bearer"},
        )

        client = httpx.Client()
        cimd_url = "https://app.example.com/client.json"
        data = ensure_token(
            self.MCP_URL,
            client,
            device_flow=True,
            client_metadata_url=cimd_url,
        )
        assert data.access_token == "acc"
        assert data.client_id == cimd_url

        reqs = httpx_mock.get_requests()
        assert not any(str(r.url).startswith(REG_URL) for r in reqs)
        da_req = next(r for r in reqs if str(r.url).startswith(DEVICE_AUTH_URL))
        assert f"client_id={quote(cimd_url, safe='')}".encode() in da_req.content


# --- _pick_token_endpoint_auth_method ---


class TestPickTokenEndpointAuthMethod:
    def test_none_when_supported_is_absent(self):
        assert _pick_token_endpoint_auth_method(None) == "none"

    def test_none_when_list_is_empty(self):
        assert _pick_token_endpoint_auth_method([]) == "none"

    def test_prefers_none_over_post(self):
        assert _pick_token_endpoint_auth_method(["none", "client_secret_post"]) == "none"

    def test_prefers_none_over_basic(self):
        assert _pick_token_endpoint_auth_method(["client_secret_basic", "none"]) == "none"

    def test_prefers_post_over_basic(self):
        assert _pick_token_endpoint_auth_method(["client_secret_basic", "client_secret_post"]) == "client_secret_post"

    def test_selects_client_secret_basic_when_only_option(self):
        assert _pick_token_endpoint_auth_method(["client_secret_basic"]) == "client_secret_basic"

    def test_selects_client_secret_post(self):
        assert _pick_token_endpoint_auth_method(["client_secret_post"]) == "client_secret_post"

    def test_falls_back_to_none_for_unsupported_methods(self, capsys):
        """AS that only advertises private_key_jwt → warn + default none."""
        result = _pick_token_endpoint_auth_method(["private_key_jwt", "tls_client_auth"])
        assert result == "none"
        # warning should have been emitted
        captured = capsys.readouterr()
        assert "warning" in captured.err.lower()


# --- token_endpoint_auth_methods_supported in discovery ---


class TestDiscoverMetadataAuthMethods:
    def test_parses_token_endpoint_auth_methods_supported(self, httpx_mock):
        """RFC 8414 token_endpoint_auth_methods_supported is captured."""
        # path-aware PRM (RFC 9728 §3.1) then host-root PRM
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
            },
        )
        meta = discover_oauth_metadata("https://example.com/mcp", httpx.Client())
        assert meta.token_endpoint_auth_methods_supported == ["client_secret_basic", "none"]

    def test_missing_field_is_none(self, httpx_mock):
        """Older AS metadata without the field → None (public client default)."""
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource/mcp",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
            json={
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            },
        )
        meta = discover_oauth_metadata("https://example.com/mcp", httpx.Client())
        assert meta.token_endpoint_auth_methods_supported is None


# --- client_secret_basic in exchange_code ---


class TestExchangeCodeBasicAuth:
    META = OAuthMetadata(
        authorization_endpoint="https://as.example.com/authorize",
        token_endpoint="https://as.example.com/token",
    )

    def test_basic_auth_header_sent(self, httpx_mock):
        """client_secret_basic: credentials in Authorization header, not body."""
        httpx_mock.add_response(
            url="https://as.example.com/token",
            json={"access_token": "at"},
        )
        client = httpx.Client()
        exchange_code(
            self.META,
            "my_client",
            "my_secret",
            "code",
            "verifier",
            "http://127.0.0.1:9/cb",
            client,
            auth_method="client_secret_basic",
        )
        req = httpx_mock.get_requests()[0]
        expected = base64.b64encode(b"my_client:my_secret").decode()
        assert req.headers.get("authorization") == f"Basic {expected}"
        assert b"client_id" not in req.content
        assert b"client_secret" not in req.content

    def test_basic_auth_with_special_chars_percent_encoded(self, httpx_mock):
        """RFC 6749 §2.3.1: client_id / client_secret are percent-encoded."""
        httpx_mock.add_response(
            url="https://as.example.com/token",
            json={"access_token": "at"},
        )
        client = httpx.Client()
        exchange_code(
            self.META,
            "c:id",
            "s:ecret",
            "code",
            "v",
            "http://127.0.0.1:9/cb",
            client,
            auth_method="client_secret_basic",
        )
        req = httpx_mock.get_requests()[0]
        # percent-encode colons: "c%3Aid:s%3Aecret"
        expected = base64.b64encode(b"c%3Aid:s%3Aecret").decode()
        assert req.headers.get("authorization") == f"Basic {expected}"

    def test_client_secret_post_sends_credentials_in_body(self, httpx_mock):
        httpx_mock.add_response(
            url="https://as.example.com/token",
            json={"access_token": "at"},
        )
        client = httpx.Client()
        exchange_code(
            self.META,
            "cid",
            "csec",
            "code",
            "v",
            "http://127.0.0.1:9/cb",
            client,
            auth_method="client_secret_post",
        )
        req = httpx_mock.get_requests()[0]
        assert b"client_id=cid" in req.content
        assert b"client_secret=csec" in req.content
        assert "authorization" not in req.headers

    def test_basic_auth_without_secret_warns_and_falls_back_to_body(
        self, httpx_mock, capsys
    ):
        """: client_secret_basic selected but no client_secret present
        (a confidential client that lost its secret / a registration race). The
        code degrades safely to body auth (client_id only) but now logs an
        actionable warning so the operator sees WHY the AS rejects it, instead of
        an opaque 401."""
        httpx_mock.add_response(
            url="https://as.example.com/token",
            json={"access_token": "at"},
        )
        client = httpx.Client()
        exchange_code(
            self.META,
            "cid",
            None,  # no secret despite client_secret_basic
            "code",
            "v",
            "http://127.0.0.1:9/cb",
            client,
            auth_method="client_secret_basic",
        )
        req = httpx_mock.get_requests()[0]
        assert "authorization" not in req.headers  # no Basic header without a secret
        assert b"client_id=cid" in req.content  # fell back to body
        assert "client_secret_basic" in capsys.readouterr().err


# --- client_secret_basic in refresh_access_token ---


class TestRefreshTokenBasicAuth:
    def test_basic_auth_header_sent(self, httpx_mock):
        httpx_mock.add_response(
            url="https://as.example.com/token",
            json={"access_token": "new_at"},
        )
        client = httpx.Client()
        refresh_access_token(
            "https://as.example.com/token",
            "my_client",
            "my_secret",
            "rt",
            client,
            auth_method="client_secret_basic",
        )
        req = httpx_mock.get_requests()[0]
        expected = base64.b64encode(b"my_client:my_secret").decode()
        assert req.headers.get("authorization") == f"Basic {expected}"
        assert b"client_id" not in req.content
        assert b"client_secret" not in req.content

    def test_none_method_sends_credentials_in_body(self, httpx_mock):
        httpx_mock.add_response(
            url="https://as.example.com/token",
            json={"access_token": "new_at"},
        )
        client = httpx.Client()
        refresh_access_token(
            "https://as.example.com/token",
            "cid",
            "csec",
            "rt",
            client,
            auth_method="none",
        )
        req = httpx_mock.get_requests()[0]
        assert b"client_id=cid" in req.content
        assert b"client_secret=csec" in req.content
        assert "authorization" not in req.headers


# --- register_client picks auth method from metadata ---


class TestRegisterClientAuthMethod:
    def test_picks_client_secret_basic_from_metadata(self, httpx_mock):
        """AS that only supports client_secret_basic → DCR registers with that method."""
        httpx_mock.add_response(
            url="https://as.example.com/register",
            json={"client_id": "cid", "client_secret": "csec"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://as.example.com/authorize",
            token_endpoint="https://as.example.com/token",
            registration_endpoint="https://as.example.com/register",
            token_endpoint_auth_methods_supported=["client_secret_basic"],
        )
        reg = register_client(meta, "http://127.0.0.1:9/cb", httpx.Client())
        assert reg.auth_method == "client_secret_basic"
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["token_endpoint_auth_method"] == "client_secret_basic"

    def test_defaults_to_none_when_field_absent(self, httpx_mock):
        httpx_mock.add_response(
            url="https://as.example.com/register",
            json={"client_id": "cid"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://as.example.com/authorize",
            token_endpoint="https://as.example.com/token",
            registration_endpoint="https://as.example.com/register",
        )
        reg = register_client(meta, "http://127.0.0.1:9/cb", httpx.Client())
        assert reg.auth_method == "none"

    def test_prefers_none_when_both_none_and_basic_supported(self, httpx_mock):
        httpx_mock.add_response(
            url="https://as.example.com/register",
            json={"client_id": "cid"},
        )
        meta = OAuthMetadata(
            authorization_endpoint="https://as.example.com/authorize",
            token_endpoint="https://as.example.com/token",
            registration_endpoint="https://as.example.com/register",
            token_endpoint_auth_methods_supported=["client_secret_basic", "none"],
        )
        reg = register_client(meta, "http://127.0.0.1:9/cb", httpx.Client())
        assert reg.auth_method == "none"


# --- token_endpoint_auth_method persisted and reused ---


class TestTokenEndpointAuthMethodPersistence:
    def test_auth_method_stored_in_token_data(self):
        """_token_response_to_data persists auth_method for subsequent refreshes."""
        meta = OAuthMetadata(
            authorization_endpoint="https://as.example.com/authorize",
            token_endpoint="https://as.example.com/token",
        )
        data = _token_response_to_data(
            {"access_token": "at", "expires_in": 3600},
            meta,
            "cid",
            "csec",
            auth_method="client_secret_basic",
        )
        assert data.token_endpoint_auth_method == "client_secret_basic"

    def test_default_auth_method_is_none(self):
        meta = OAuthMetadata(
            authorization_endpoint="https://as.example.com/authorize",
            token_endpoint="https://as.example.com/token",
        )
        data = _token_response_to_data(
            {"access_token": "at"},
            meta,
            "cid",
            None,
        )
        assert data.token_endpoint_auth_method == "none"

    def test_legacy_token_loads_with_none_default(self, tmp_path, monkeypatch):
        """TokenData(**old_entry) without token_endpoint_auth_method defaults to 'none'."""
        import json as _json
        from mcp_stdio.token_store import load_token

        store = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store)

        # Write a token entry WITHOUT token_endpoint_auth_method (legacy format)
        store.write_text(_json.dumps({
            "https://example.com/mcp": {
                "access_token": "at",
                "token_type": "Bearer",
                "expires_at": None,
                "refresh_token": "rt",
                "scope": None,
                "client_id": "cid",
                "client_secret": None,
                "client_secret_expires_at": None,
                "token_endpoint": "https://example.com/token",
                "authorization_endpoint": "https://example.com/authorize",
                "registration_endpoint": None,
            }
        }))
        loaded = load_token("https://example.com/mcp")
        assert loaded is not None
        assert loaded.token_endpoint_auth_method == "none"

    def test_refresh_cached_token_uses_stored_auth_method(
        self, tmp_path, monkeypatch, httpx_mock
    ):
        """refresh_cached_token passes token_endpoint_auth_method from cache."""
        from mcp_stdio.token_store import save_token

        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", tmp_path / "tokens.json")

        save_token(
            "https://example.com/mcp",
            TokenData(
                access_token="stale",
                expires_at=time.time() - 1,
                refresh_token="rt",
                client_id="cid",
                client_secret="csec",
                token_endpoint="https://example.com/token",
                authorization_endpoint="https://example.com/authorize",
                token_endpoint_auth_method="client_secret_basic",
            ),
        )
        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "new_at", "expires_in": 3600},
        )
        data = refresh_cached_token("https://example.com/mcp", httpx.Client())
        assert data is not None
        assert data.access_token == "new_at"
        # Verify Basic auth header was used
        req = httpx_mock.get_requests()[0]
        expected = base64.b64encode(b"cid:csec").decode()
        assert req.headers.get("authorization") == f"Basic {expected}"
        assert b"client_id" not in req.content
        # Persisted method is preserved in the refreshed token
        assert data.token_endpoint_auth_method == "client_secret_basic"


# --- client_secret_basic in device authorization request (Step 1) ---


class TestDeviceAuthStepOneBasicAuth:
    def test_device_authorization_request_uses_basic_auth(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """client_secret_basic: DA request (Step 1) puts credentials in Authorization header."""
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", tmp_path / "tokens.json")

        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL,
            json={"access_token": "at", "token_type": "Bearer", "expires_in": 3600},
        )

        # Provide cached client with client_secret_basic already selected.
        cached = TokenData(
            access_token="stale",
            client_id="da_cid",
            client_secret="da_secret",
            token_endpoint="https://api.example.com/token",
            authorization_endpoint=AUTH_URL,
            token_endpoint_auth_method="client_secret_basic",
        )
        client = httpx.Client()
        _run_device_authorization_flow(
            MCP_URL, client, metadata=_device_meta(), cached=cached
        )

        # First request is the device authorization request (Step 1).
        da_req = httpx_mock.get_requests()[0]
        assert da_req.url == DEVICE_AUTH_URL
        expected = base64.b64encode(b"da_cid:da_secret").decode()
        assert da_req.headers.get("authorization") == f"Basic {expected}"
        assert b"client_id" not in da_req.content
        assert b"client_secret" not in da_req.content
