"""Tests for mcp_stdio.oauth module."""

import base64
import hashlib
import json
import threading
import time
from unittest.mock import patch

import httpx
import pytest

from mcp_stdio.oauth import (
    OAuthMetadata,
    _authorization_base_url,
    _CallbackHandler,
    _parse_token_response,
    _run_callback_server,
    _token_response_to_data,
    discover_oauth_metadata,
    ensure_token,
    exchange_code,
    generate_pkce,
    refresh_access_token,
    register_client,
    ClientRegistration,
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
            base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()
            )
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
    def _mock_no_prm(self, httpx_mock, base="https://api.example.com"):
        """Mock RFC 9728 endpoint returning 404 (no protected resource metadata)."""
        httpx_mock.add_response(
            url=f"{base}/.well-known/oauth-protected-resource",
            status_code=404,
        )

    def test_from_well_known(self, httpx_mock):
        self._mock_no_prm(httpx_mock)
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

    def test_fallback_on_404(self, httpx_mock):
        self._mock_no_prm(httpx_mock)
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            status_code=404,
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.authorization_endpoint == "https://api.example.com/authorize"
        assert meta.token_endpoint == "https://api.example.com/token"
        assert meta.registration_endpoint == "https://api.example.com/register"

    def test_fallback_on_connection_error(self, httpx_mock):
        # ConnectError affects both PRM and AS metadata requests
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
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        assert meta.token_endpoint == "https://api.example.com/token"

    def test_rfc9728_then_rfc8414(self, httpx_mock):
        """Full discovery: RFC 9728 finds auth server, RFC 8414 gets metadata."""
        # Phase 1: Protected Resource Metadata
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
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
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
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
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
            status_code=404,
            text="<html>Not Found</html>",
            headers={"content-type": "text/html"},
        )
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-authorization-server",
            status_code=404,
        )
        client = httpx.Client()
        meta = discover_oauth_metadata("https://api.example.com/mcp", client)
        # Falls through to defaults
        assert meta.token_endpoint == "https://api.example.com/token"

    def test_separate_auth_server_rfc8414_fails_tries_base(self, httpx_mock):
        """RFC 9728 gives auth server, but its RFC 8414 fails — try base."""
        httpx_mock.add_response(
            url="https://api.example.com/.well-known/oauth-protected-resource",
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
            meta, "cid", None, "code123", "verifier", "http://127.0.0.1:9999/callback", client
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
            meta, "cid", "csec", "code", "verifier", "http://127.0.0.1:9999/callback", client
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
            meta, "cid", None, "code", "verifier", "http://127.0.0.1:9999/callback", client
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
            meta, "cid", None, "code", "verifier", "http://127.0.0.1:9999/callback", client
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
            meta, "cid", None, "code", "verifier",
            "http://127.0.0.1:9999/callback", client,
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
                meta, "cid", None, "bad-code", "verifier",
                "http://127.0.0.1:9999/callback", client,
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


# --- _token_response_to_data ---


class TestTokenResponseToData:
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
            raw, meta, "cid", None,
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
            raw, meta, "cid", None,
            previous_refresh_token="old_rt",
        )
        assert data.refresh_token == "new_rt"


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
            json={"error": "bad_verification_code", "error_description": "Code expired"},
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


# --- _run_callback_server ---


class TestCallbackServer:
    def test_receives_code(self):
        """Send a simulated redirect to the callback server."""
        result = {}

        def run_server():
            try:
                code, state = _run_callback_server(port=0, timeout=5)
                result["code"] = code
                result["state"] = state
            except Exception as e:
                result["error"] = str(e)

        # We need to find the port, so start server in a thread,
        # then poke it with an HTTP request
        _CallbackHandler.auth_code = None
        _CallbackHandler.state = None
        _CallbackHandler.error = None

        from http.server import HTTPServer
        # Create server ourselves to know the port
        server = HTTPServer(("127.0.0.1", 0), _CallbackHandler)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        # Simulate browser redirect
        resp = httpx.get(
            f"http://127.0.0.1:{port}/callback?code=test_code_123&state=test_state"
        )
        assert resp.status_code == 200
        assert "Authorization successful" in resp.text

        done.set()
        server.server_close()

        assert _CallbackHandler.auth_code == "test_code_123"
        assert _CallbackHandler.state == "test_state"

    def test_receives_error(self):
        """Server sends an OAuth error via callback."""
        _CallbackHandler.auth_code = None
        _CallbackHandler.state = None
        _CallbackHandler.error = None

        from http.server import HTTPServer
        server = HTTPServer(("127.0.0.1", 0), _CallbackHandler)
        port = server.server_address[1]
        done = threading.Event()

        def serve():
            while not done.is_set():
                server.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.3)

        resp = httpx.get(
            f"http://127.0.0.1:{port}/callback?error=access_denied"
        )
        assert resp.status_code == 200
        assert "Authorization failed" in resp.text

        done.set()
        server.server_close()

        assert _CallbackHandler.error == "access_denied"
        assert _CallbackHandler.auth_code is None

    def test_timeout(self):
        with pytest.raises(TimeoutError):
            _run_callback_server(port=0, timeout=0.5)


# --- ensure_token ---


class TestEnsureToken:
    def test_uses_cached_valid_token(self, tmp_path, monkeypatch):
        """FastMCP #1764: cached tokens should be reused."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token("https://example.com/mcp", TokenData(
            access_token="cached_at",
            expires_at=time.time() + 3600,
            token_endpoint="https://example.com/token",
            authorization_endpoint="https://example.com/authorize",
        ))

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data.access_token == "cached_at"

    def test_refreshes_expired_token(self, tmp_path, monkeypatch, httpx_mock):
        """Token expired but refresh_token available."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token("https://example.com/mcp", TokenData(
            access_token="expired_at",
            expires_at=time.time() - 100,  # expired
            refresh_token="valid_rt",
            client_id="cid",
            token_endpoint="https://example.com/token",
            authorization_endpoint="https://example.com/authorize",
        ))

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

        save_token("https://example.com/mcp", TokenData(
            access_token="old_at",
            expires_at=time.time() - 100,
            refresh_token="old_rt",
            client_id="cid",
            token_endpoint="https://example.com/token",
            authorization_endpoint="https://example.com/authorize",
        ))

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

        save_token("https://example.com/mcp", TokenData(
            access_token="no_expiry_at",
            expires_at=None,  # unknown expiry
            token_endpoint="https://example.com/token",
            authorization_endpoint="https://example.com/authorize",
        ))

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data.access_token == "no_expiry_at"

    def test_token_near_expiry_triggers_refresh(self, tmp_path, monkeypatch, httpx_mock):
        """Token expiring within 60s should be refreshed proactively."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token

        save_token("https://example.com/mcp", TokenData(
            access_token="almost_expired",
            expires_at=time.time() + 30,  # within 60s threshold
            refresh_token="rt",
            client_id="cid",
            token_endpoint="https://example.com/token",
            authorization_endpoint="https://example.com/authorize",
        ))

        httpx_mock.add_response(
            url="https://example.com/token",
            json={"access_token": "fresh_at", "expires_in": 3600},
        )

        client = httpx.Client()
        data = ensure_token("https://example.com/mcp", client)
        assert data.access_token == "fresh_at"

    def test_refresh_preserves_old_refresh_token(self, tmp_path, monkeypatch, httpx_mock):
        """Python SDK #2270: refresh response omits refresh_token; keep old."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token, load_token

        save_token("https://example.com/mcp", TokenData(
            access_token="expired_at",
            expires_at=time.time() - 100,
            refresh_token="precious_rt",
            client_id="cid",
            token_endpoint="https://example.com/token",
            authorization_endpoint="https://example.com/authorize",
        ))

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

    def test_refresh_failure_clears_stale_token(self, tmp_path, monkeypatch, httpx_mock):
        """#37747: failed refresh should clear cached token to prevent retry block."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        from mcp_stdio.token_store import save_token, load_token

        save_token("https://example.com/mcp", TokenData(
            access_token="expired_at",
            expires_at=time.time() - 100,
            refresh_token="invalid_rt",
            client_id="cid",
            token_endpoint="https://example.com/token",
            authorization_endpoint="https://example.com/authorize",
        ))

        # Refresh fails with 400
        httpx_mock.add_response(
            url="https://example.com/token",
            status_code=400,
            json={"error": "invalid_grant"},
        )
        # Discovery for full flow (will be attempted after refresh fails)
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-protected-resource",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/oauth-authorization-server",
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

    def test_preconfigured_client_id_skips_dcr(self, tmp_path, monkeypatch, httpx_mock):
        """#38102, #3273: pre-configured client_id should skip DCR."""
        store_file = tmp_path / "tokens.json"
        monkeypatch.setattr("mcp_stdio.token_store._STORE_DIR", tmp_path)
        monkeypatch.setattr("mcp_stdio.token_store._STORE_FILE", store_file)

        # Discovery
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
