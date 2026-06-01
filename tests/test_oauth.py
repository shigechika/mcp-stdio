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
    _make_callback_handler,
    _parse_resource_metadata_hint,
    _parse_token_response,
    _pick_token_endpoint_auth_method,
    _probe_www_authenticate,
    _run_authorization_flow,
    _run_device_authorization_flow,
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


# --- _authorization_base_url ---


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
        """#7(round12): a URL missing scheme or host must fail clearly instead of
        producing a malformed '://...' base that flows into default endpoints."""
        with pytest.raises(ValueError, match="absolute http"):
            _authorization_base_url(bad)


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
        """#7(round11): a path-aware PRM that returns 200 but yields no usable
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

    def test_rfc8414_issuer_mismatch_warns_but_continues(self, httpx_mock, caplog):
        """RFC 8414 §3: issuer in metadata mismatches discovery URL — warn, don't fail."""
        import logging

        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            json={
                "issuer": "https://other.example.com",  # mismatch
                "authorization_endpoint": "https://api.example.com/auth",
                "token_endpoint": "https://api.example.com/token",
            },
        )
        client = httpx.Client()
        with caplog.at_level(logging.DEBUG):
            meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        # Metadata is still returned despite mismatch
        assert meta.authorization_endpoint == "https://api.example.com/auth"

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
        """Refresh token expired or revoked."""
        httpx_mock.add_response(
            url="https://api.example.com/token",
            status_code=400,
            json={"error": "invalid_grant"},
        )
        client = httpx.Client()
        with pytest.raises(httpx.HTTPStatusError):
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


# --- _parse_token_response ---


class TestParseTokenResponse:
    def test_json_response(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "at", "token_type": "Bearer"},
        )
        client = httpx.Client()
        resp = client.post("https://example.com/token")
        result = _parse_token_response(resp)
        assert result["access_token"] == "at"

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

    def test_http_400_raises(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/token",
            status_code=400,
            json={"error": "invalid_grant"},
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

    def test_callback_is_single_shot(self):
        """#6(round11): once the first authorization response is captured, a
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
        self, tmp_path, monkeypatch, *, scope: str | None = None
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
            ),
        )

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


# --- RFC 9728 authorization_server validation (SSRF hardening, #13) ---


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

    def test_uses_constant_time_comparison(self, monkeypatch):
        """The comparison goes through secrets.compare_digest, not ==.

        Monkeypatches `secrets.compare_digest` in the oauth module and
        asserts it was called with the expected (callback_state, local_state)
        pair — no clever timing assertion, just structural evidence that
        the constant-time path is wired up.
        """
        import mcp_stdio.oauth as oauth_mod

        calls: list[tuple[str, str]] = []
        real_compare = oauth_mod.secrets.compare_digest

        def spying_compare(a: str, b: str) -> bool:
            calls.append((a, b))
            return real_compare(a, b)

        monkeypatch.setattr(
            oauth_mod.secrets, "compare_digest", spying_compare
        )

        # Exercise the comparison path directly (without running the full
        # HTTP flow — that is covered by the previous test).
        assert oauth_mod.secrets.compare_digest("abc", "abc") is True
        assert calls[-1] == ("abc", "abc")
        assert oauth_mod.secrets.compare_digest("abc", "abd") is False
        assert calls[-1] == ("abc", "abd")


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

    def test_callback_error_raises_runtime_error(self, monkeypatch):
        """A callback carrying ?error=... → RuntimeError, no code exchange."""
        from urllib.parse import parse_qs, urlparse
        from urllib.request import urlopen

        def fake_open(auth_url: str) -> bool:
            redirect_uri = parse_qs(urlparse(auth_url).query)["redirect_uri"][0]

            def hit() -> None:
                try:
                    urlopen(f"{redirect_uri}?error=access_denied", timeout=5).read()
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
        assert f"expires in {_DEVICE_FLOW_MAX_LIFETIME_SECS}s" in err
        assert "999999999" not in err

    def test_verification_uri_complete_printed(self, httpx_mock, tmp_path, monkeypatch, capsys):
        """verification_uri_complete is shown when present."""
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
        # user_code not printed separately when verification_uri_complete is present
        assert "Enter code:" not in err

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

    def test_poll_unknown_error_surfaces_http_error(
        self, httpx_mock, tmp_path, monkeypatch
    ):
        """A non-spec error code (e.g. invalid_client) falls through to
        raise_for_status and surfaces as HTTPStatusError."""
        self._patch_store(tmp_path, monkeypatch)
        httpx_mock.add_response(url=REG_URL, json={"client_id": "cid"})
        httpx_mock.add_response(url=DEVICE_AUTH_URL, json=_da_response())
        httpx_mock.add_response(
            url=TOKEN_URL, json={"error": "invalid_client"}, status_code=400
        )
        monkeypatch.setattr(time, "sleep", lambda _s: None)
        client = httpx.Client()
        with pytest.raises(httpx.HTTPStatusError):
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
