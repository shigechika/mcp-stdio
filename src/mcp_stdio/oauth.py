"""OAuth 2.1 client for MCP servers (RFC 7591, RFC 7636)."""

from __future__ import annotations

import base64
import hashlib
import html
import secrets
import threading
import time
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from .relay import log
from .token_store import TokenData, delete_token, load_token, save_token

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class OAuthMetadata:
    """Authorization server metadata (RFC 8414)."""

    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None = None


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _authorization_base_url(server_url: str) -> str:
    """Derive authorization base URL by stripping the path component.

    Per MCP spec: https://api.example.com/v1/mcp -> https://api.example.com
    """
    parsed = urlparse(server_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _fetch_authorization_server_metadata(
    auth_server_url: str, client: httpx.Client
) -> OAuthMetadata | None:
    """Fetch RFC 8414 authorization server metadata.

    Returns None on any failure (404, invalid JSON, connection error).
    """
    well_known = f"{auth_server_url}/.well-known/oauth-authorization-server"
    try:
        resp = client.get(well_known)
        if resp.status_code == 200:
            data = resp.json()
            return OAuthMetadata(
                authorization_endpoint=data.get("authorization_endpoint")
                or f"{auth_server_url}/authorize",
                token_endpoint=data.get("token_endpoint")
                or f"{auth_server_url}/token",
                registration_endpoint=data.get("registration_endpoint") or None,
            )
    except Exception:
        pass
    return None


def discover_oauth_metadata(
    server_url: str, client: httpx.Client
) -> OAuthMetadata:
    """Discover OAuth authorization server metadata.

    Follows the MCP spec discovery flow:
    1. Try RFC 9728 Protected Resource Metadata
       (/.well-known/oauth-protected-resource) to find the
       authorization server URL.
    2. Try RFC 8414 Authorization Server Metadata
       (/.well-known/oauth-authorization-server) on the
       discovered (or base) URL.
    3. Fall back to default endpoint paths.
    """
    base = _authorization_base_url(server_url)

    # Phase 1: RFC 9728 Protected Resource Metadata
    auth_server_url = base
    prm_url = f"{base}/.well-known/oauth-protected-resource"
    try:
        resp = client.get(prm_url)
        if resp.status_code == 200:
            prm_data = resp.json()
            auth_servers = prm_data.get("authorization_servers")
            if auth_servers and isinstance(auth_servers, list):
                auth_server_url = auth_servers[0]
                log(f"discovered authorization server: {auth_server_url}")
    except Exception:
        pass

    # Phase 2: RFC 8414 Authorization Server Metadata
    meta = _fetch_authorization_server_metadata(auth_server_url, client)
    if meta:
        return meta

    # If auth server differs from base, also try base as fallback
    if auth_server_url != base:
        meta = _fetch_authorization_server_metadata(base, client)
        if meta:
            return meta

    # Phase 3: Default paths
    log("OAuth metadata not found, using default endpoints")
    return OAuthMetadata(
        authorization_endpoint=f"{base}/authorize",
        token_endpoint=f"{base}/token",
        registration_endpoint=f"{base}/register",
    )


# ---------------------------------------------------------------------------
# Dynamic Client Registration (RFC 7591)
# ---------------------------------------------------------------------------


@dataclass
class ClientRegistration:
    """Result of dynamic client registration."""

    client_id: str
    client_secret: str | None = None


def register_client(
    metadata: OAuthMetadata,
    redirect_uri: str,
    client: httpx.Client,
) -> ClientRegistration:
    """Register a client via Dynamic Client Registration.

    Raises httpx.HTTPStatusError on failure.
    """
    if not metadata.registration_endpoint:
        raise ValueError(
            "Server does not support dynamic client registration. "
            "Provide a --client-id instead."
        )

    resp = client.post(
        metadata.registration_endpoint,
        json={
            "client_name": "mcp-stdio",
            "redirect_uris": [redirect_uri],
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
        },
    )
    resp.raise_for_status()
    data = resp.json()
    return ClientRegistration(
        client_id=data["client_id"],
        client_secret=data.get("client_secret"),
    )


# ---------------------------------------------------------------------------
# PKCE (RFC 7636)
# ---------------------------------------------------------------------------


def generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256).

    Returns (code_verifier, code_challenge).
    """
    verifier = secrets.token_urlsafe(64)[:96]  # 96 chars, within 43-128
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


# ---------------------------------------------------------------------------
# Localhost callback server
# ---------------------------------------------------------------------------


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures the OAuth callback."""

    auth_code: str | None = None
    state: str | None = None
    error: str | None = None

    def do_GET(self) -> None:  # noqa: N802
        params = parse_qs(urlparse(self.path).query)

        if "error" in params:
            _CallbackHandler.error = params["error"][0]
        elif "code" in params:
            _CallbackHandler.auth_code = params["code"][0]
            _CallbackHandler.state = params.get("state", [None])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        if _CallbackHandler.error:
            msg = html.escape(_CallbackHandler.error)
            body = f"<h1>Authorization failed</h1><p>{msg}</p>"
        else:
            body = "<h1>Authorization successful</h1><p>You can close this tab.</p>"
        self.wfile.write(body.encode())

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default HTTP server logs."""
        pass


def _run_callback_server(
    port: int = 0, timeout: float = 120
) -> tuple[str, str | None]:
    """Start a localhost callback server and wait for the OAuth redirect.

    Args:
        port: Port to listen on (0 = ephemeral).
        timeout: Seconds to wait for the callback.

    Returns:
        (auth_code, state) tuple.

    Raises:
        TimeoutError: If the callback is not received in time.
        RuntimeError: If the server received an error.
    """
    # Reset class state
    _CallbackHandler.auth_code = None
    _CallbackHandler.state = None
    _CallbackHandler.error = None

    server = HTTPServer(("127.0.0.1", port), _CallbackHandler)
    actual_port = server.server_address[1]
    ready = threading.Event()
    done = threading.Event()

    def serve() -> None:
        ready.set()
        while not done.is_set():
            server.handle_request()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    ready.wait()

    redirect_uri = f"http://127.0.0.1:{actual_port}/callback"

    # Wait for callback
    deadline = time.monotonic() + timeout
    while not (_CallbackHandler.auth_code or _CallbackHandler.error):
        if time.monotonic() > deadline:
            done.set()
            server.server_close()
            raise TimeoutError(
                "OAuth callback not received within timeout. "
                "Please restart and try again."
            )
        time.sleep(0.2)

    done.set()
    server.server_close()

    if _CallbackHandler.error:
        raise RuntimeError(f"OAuth error: {_CallbackHandler.error}")

    return _CallbackHandler.auth_code, _CallbackHandler.state  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Authorization + Token Exchange
# ---------------------------------------------------------------------------


def authorize(
    metadata: OAuthMetadata,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    code_challenge: str,
    scope: str | None = None,
    timeout: float = 120,
) -> str:
    """Open browser for authorization and return the auth code.

    Starts a localhost callback server, opens the browser to the
    authorization endpoint, and waits for the redirect.

    Returns the authorization code.
    """
    state = secrets.token_urlsafe(32)

    params: dict[str, str] = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if scope:
        params["scope"] = scope

    auth_url = f"{metadata.authorization_endpoint}?{urlencode(params)}"
    log(f"opening browser for authorization: {metadata.authorization_endpoint}")

    if not webbrowser.open(auth_url):
        log(f"could not open browser. Please open this URL manually:\n{auth_url}")

    # Parse port from redirect_uri to pass to callback server
    port = int(urlparse(redirect_uri).port or 0)

    code, returned_state = _run_callback_server(port=port, timeout=timeout)

    if returned_state != state:
        raise RuntimeError("OAuth state mismatch — possible CSRF attack")

    return code


def _parse_token_response(resp: httpx.Response) -> dict[str, Any]:
    """Parse a token response, handling both JSON and form-urlencoded formats.

    GitHub OAuth (and some others) may return application/x-www-form-urlencoded.
    Some servers return HTTP 200 with an error in the body (GitHub legacy).
    """
    resp.raise_for_status()

    content_type = resp.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type:
        result = dict(parse_qs(resp.text, keep_blank_values=True))
        # parse_qs returns lists; unwrap single values
        return {k: v[0] if len(v) == 1 else v for k, v in result.items()}

    result = resp.json()

    # Some providers return HTTP 200 with error in body (GitHub legacy)
    if "error" in result and "access_token" not in result:
        desc = result.get("error_description", result["error"])
        raise RuntimeError(f"OAuth token error: {desc}")

    return result


def exchange_code(
    metadata: OAuthMetadata,
    client_id: str,
    client_secret: str | None,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    client: httpx.Client,
    *,
    resource: str | None = None,
) -> dict[str, Any]:
    """Exchange authorization code for tokens.

    Args:
        resource: RFC 8707 resource indicator (the MCP server URL).

    Returns the raw token response dict.
    """
    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    if client_secret:
        data["client_secret"] = client_secret
    if resource:
        data["resource"] = resource

    resp = client.post(
        metadata.token_endpoint,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    return _parse_token_response(resp)


def refresh_access_token(
    token_endpoint: str,
    client_id: str,
    client_secret: str | None,
    refresh_token: str,
    client: httpx.Client,
) -> dict[str, Any]:
    """Refresh an access token.

    Returns the raw token response dict.
    """
    data: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    if client_secret:
        data["client_secret"] = client_secret

    resp = client.post(
        token_endpoint,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    return _parse_token_response(resp)


# ---------------------------------------------------------------------------
# High-level orchestrator
# ---------------------------------------------------------------------------


def _token_response_to_data(
    raw: dict[str, Any],
    metadata: OAuthMetadata,
    client_id: str,
    client_secret: str | None,
    *,
    previous_refresh_token: str | None = None,
) -> TokenData:
    """Convert a raw token response to TokenData.

    If the response omits refresh_token (allowed per RFC 6749 Section 6),
    the previous_refresh_token is preserved so subsequent refreshes work.
    """
    expires_at = None
    if "expires_in" in raw:
        expires_at = time.time() + raw["expires_in"]

    return TokenData(
        access_token=raw["access_token"],
        token_type=raw.get("token_type", "Bearer"),
        expires_at=expires_at,
        refresh_token=raw.get("refresh_token") or previous_refresh_token,
        scope=raw.get("scope"),
        client_id=client_id,
        client_secret=client_secret,
        token_endpoint=metadata.token_endpoint,
        authorization_endpoint=metadata.authorization_endpoint,
        registration_endpoint=metadata.registration_endpoint,
    )


def ensure_token(
    server_url: str,
    client: httpx.Client,
    *,
    client_id: str | None = None,
    scope: str | None = None,
    timeout: float = 120,
) -> TokenData:
    """Ensure a valid access token is available.

    1. Check cached token — use if not expired
    2. If expired, try refresh
    3. If no token or refresh fails, run full OAuth flow

    Returns TokenData with a valid access_token.
    """
    # 1. Check cache
    cached = load_token(server_url)
    if cached and cached.access_token:
        if cached.expires_at is None or cached.expires_at > time.time() + 60:
            log("using cached OAuth token")
            return cached

        # 2. Try refresh
        if cached.refresh_token and cached.token_endpoint and cached.client_id:
            log("access token expired, attempting refresh")
            try:
                raw = refresh_access_token(
                    cached.token_endpoint,
                    cached.client_id,
                    cached.client_secret,
                    cached.refresh_token,
                    client,
                )
                metadata = OAuthMetadata(
                    authorization_endpoint=cached.authorization_endpoint,
                    token_endpoint=cached.token_endpoint,
                    registration_endpoint=cached.registration_endpoint,
                )
                data = _token_response_to_data(
                    raw, metadata, cached.client_id, cached.client_secret,
                    previous_refresh_token=cached.refresh_token,
                )
                save_token(server_url, data)
                log("token refreshed successfully")
                return data
            except Exception as e:
                log(f"token refresh failed: {e}")
                # Clear stale token to prevent cached failure blocking retry
                # (#37747: failed auth state cached, preventing retry)
                delete_token(server_url)

    # 3. Full OAuth flow
    log("starting OAuth 2.1 authorization flow")
    metadata = discover_oauth_metadata(server_url, client)

    # Start callback server early to get the port for redirect_uri
    # Reset handler state
    _CallbackHandler.auth_code = None
    _CallbackHandler.state = None
    _CallbackHandler.error = None

    callback_server = HTTPServer(("127.0.0.1", 0), _CallbackHandler)
    port = callback_server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    # Dynamic Client Registration
    cid = client_id
    csecret: str | None = None
    if not cid:
        if cached and cached.client_id:
            cid = cached.client_id
            csecret = cached.client_secret
        else:
            log("registering OAuth client")
            reg = register_client(metadata, redirect_uri, client)
            cid = reg.client_id
            csecret = reg.client_secret
            log(f"registered client: {cid}")
    assert cid is not None

    # PKCE
    code_verifier, code_challenge = generate_pkce()

    # Authorization (RFC 8707: include resource indicator)
    state = secrets.token_urlsafe(32)
    params: dict[str, str] = {
        "client_id": cid,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "resource": server_url,
    }
    if scope:
        params["scope"] = scope

    auth_url = f"{metadata.authorization_endpoint}?{urlencode(params)}"
    log(f"authorize URL (open in browser if not auto-opened):\n{auth_url}")

    webbrowser.open(auth_url)

    # Wait for callback
    done = threading.Event()

    def serve() -> None:
        while not done.is_set():
            callback_server.handle_request()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    deadline = time.monotonic() + timeout
    while not (_CallbackHandler.auth_code or _CallbackHandler.error):
        if time.monotonic() > deadline:
            done.set()
            callback_server.server_close()
            raise TimeoutError(
                "OAuth callback not received within timeout. "
                "Please restart and try again."
            )
        time.sleep(0.2)

    done.set()
    callback_server.server_close()

    if _CallbackHandler.error:
        raise RuntimeError(f"OAuth error: {_CallbackHandler.error}")

    if _CallbackHandler.state != state:
        raise RuntimeError("OAuth state mismatch — possible CSRF attack")

    code = _CallbackHandler.auth_code
    assert code is not None

    # Token exchange (RFC 8707: include resource indicator)
    log("exchanging authorization code for token")
    raw = exchange_code(
        metadata, cid, csecret, code, code_verifier, redirect_uri, client,
        resource=server_url,
    )
    data = _token_response_to_data(raw, metadata, cid, csecret)
    save_token(server_url, data)
    log("OAuth token obtained and saved")
    return data
