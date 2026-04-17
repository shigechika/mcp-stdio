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
from urllib.parse import parse_qs, urlencode, urlparse, urlsplit, urlunsplit

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


def _build_well_known_url(resource_url: str, suffix: str) -> str:
    """Build a well-known URL by inserting the suffix between host and path.

    Used for both RFC 8414 §3 (oauth-authorization-server) and RFC 9728 §3.1
    (oauth-protected-resource). Per RFC 9728 §3.1, the well-known suffix is
    inserted between the host component and the path and/or query components
    of the resource identifier; any terminating slash following the host is
    removed first. The query string is preserved on the constructed URL:
      https://host/v2?t=1 + oauth-authorization-server ->
        https://host/.well-known/oauth-authorization-server/v2?t=1
      https://host + oauth-protected-resource ->
        https://host/.well-known/oauth-protected-resource
    """
    parsed = urlsplit(resource_url)
    path = parsed.path.rstrip("/")
    well_known_path = f"/.well-known/{suffix}{path}"
    return urlunsplit((parsed.scheme, parsed.netloc, well_known_path, parsed.query, ""))


def _fetch_authorization_server_metadata(
    auth_server_url: str, client: httpx.Client
) -> OAuthMetadata | None:
    """Fetch RFC 8414 authorization server metadata.

    Returns None on any failure (404, invalid JSON, connection error).
    """
    well_known = _build_well_known_url(auth_server_url, "oauth-authorization-server")
    try:
        resp = client.get(well_known)
        if resp.status_code == 200:
            data = resp.json()
            # RFC 8414 §3: issuer in response must match the URL used for discovery.
            # Log a warning on mismatch but continue — real servers may be slightly
            # misconfigured (trailing slash, etc.) and rejecting would be too strict.
            issuer = data.get("issuer")
            if issuer and issuer.rstrip("/") != auth_server_url.rstrip("/"):
                log(
                    f"warning: RFC 8414 §3 issuer mismatch — "
                    f"expected {auth_server_url!r}, got {issuer!r}"
                )
            return OAuthMetadata(
                authorization_endpoint=data.get("authorization_endpoint")
                or f"{auth_server_url}/authorize",
                token_endpoint=data.get("token_endpoint") or f"{auth_server_url}/token",
                registration_endpoint=data.get("registration_endpoint") or None,
            )
    except Exception:
        pass
    return None


def discover_oauth_metadata(server_url: str, client: httpx.Client) -> OAuthMetadata:
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

    # Phase 1: RFC 9728 Protected Resource Metadata.
    # Per RFC 9728 §3.1, the well-known URI is inserted between host and path
    # components of the resource identifier. Try the path-aware URL first for
    # path-based reverse-proxy deployments (cf. geelen/mcp-remote#249), then
    # fall back to host-root for servers that publish PRM at the origin.
    auth_server_url = base
    prm_candidates: list[str] = []
    path_aware = _build_well_known_url(server_url, "oauth-protected-resource")
    host_root = f"{base}/.well-known/oauth-protected-resource"
    prm_candidates.append(path_aware)
    if host_root != path_aware:
        prm_candidates.append(host_root)

    for prm_url in prm_candidates:
        try:
            resp = client.get(prm_url)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        try:
            prm_data = resp.json()
        except Exception:
            continue
        # RFC 9728 §3.3: the `resource` field in the PRM response should match
        # the server URL. Log a warning on mismatch but continue — strict
        # rejection would break servers that normalise URLs differently.
        prm_resource = prm_data.get("resource")
        if prm_resource and prm_resource.rstrip("/") != server_url.rstrip("/"):
            log(
                f"warning: RFC 9728 §3.3 resource mismatch — "
                f"expected {server_url!r}, got {prm_resource!r}"
            )
        auth_servers = prm_data.get("authorization_servers")
        if auth_servers and isinstance(auth_servers, list):
            auth_server_url = auth_servers[0]
            log(f"discovered authorization server: {auth_server_url}")
        break

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
    client_secret_expires_at: float | None = None  # RFC 7591 §3.2.1; None = no expiry


def _is_client_secret_expired(cached: TokenData) -> bool:
    """Return True if the cached client secret has expired per RFC 7591 §3.2.1."""
    if cached.client_secret_expires_at is None:
        return False
    return time.time() > cached.client_secret_expires_at


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
    # RFC 7591 §3.2.1: client_secret_expires_at = 0 means "never expires".
    # Normalize 0 to None at the source so later expiry checks don't need to
    # special-case it.
    raw_expiry = data.get("client_secret_expires_at")
    expiry: float | None = None
    if raw_expiry:
        expiry = float(raw_expiry)
    return ClientRegistration(
        client_id=data["client_id"],
        client_secret=data.get("client_secret"),
        client_secret_expires_at=expiry,
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


@dataclass
class CallbackResult:
    """Result captured by the OAuth callback handler."""

    auth_code: str | None = None
    state: str | None = None
    error: str | None = None


def _make_callback_handler(
    result: CallbackResult,
) -> type[BaseHTTPRequestHandler]:
    """Create a callback handler class bound to a specific result instance.

    Each OAuth flow gets its own result object, avoiding class-variable
    race conditions when multiple flows run concurrently.
    """

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            # Reject everything that isn't the registered redirect_uri path.
            # Browser prefetch / favicon / stray tabs on 127.0.0.1 would
            # otherwise land in this handler and — if they happened to
            # carry `code` and `state` — be treated as the authoritative
            # authorization response. See #15.
            parsed = urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return

            params = parse_qs(parsed.query)

            if "error" in params:
                result.error = params["error"][0]
            elif "code" in params:
                result.auth_code = params["code"][0]
                result.state = params.get("state", [None])[0]

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

            if result.error:
                msg = html.escape(result.error)
                body = f"<h1>Authorization failed</h1><p>{msg}</p>"
            else:
                body = "<h1>Authorization successful</h1><p>You can close this tab.</p>"
            self.wfile.write(body.encode())

        def log_message(self, format: str, *args: Any) -> None:
            pass

    return Handler


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
    *,
    resource: str | None = None,
) -> dict[str, Any]:
    """Refresh an access token.

    Args:
        resource: RFC 8707 resource indicator (the MCP server URL).

    Returns the raw token response dict.
    """
    data: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    if client_secret:
        data["client_secret"] = client_secret
    if resource:
        data["resource"] = resource

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
    client_secret_expires_at: float | None = None,
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
        client_secret_expires_at=client_secret_expires_at,
        token_endpoint=metadata.token_endpoint,
        authorization_endpoint=metadata.authorization_endpoint,
        registration_endpoint=metadata.registration_endpoint,
    )


def refresh_cached_token(
    server_url: str, client: httpx.Client
) -> TokenData | None:
    """Refresh the cached token for a server using its stored refresh_token.

    Returns updated TokenData on success, or None if no usable cached token
    exists (missing refresh_token / endpoint / client_id, or expired
    client_secret per RFC 7591 §3.2.1) or the refresh request fails. The
    refresh request always includes the RFC 8707 resource indicator.

    Does not delete stale tokens on failure — callers decide the retry
    policy.
    """
    cached = load_token(server_url)
    if not (
        cached
        and cached.refresh_token
        and cached.token_endpoint
        and cached.client_id
    ):
        return None
    if _is_client_secret_expired(cached):
        log("OAuth client_secret expired (RFC 7591 §3.2.1) — cannot refresh")
        return None
    log("access token expired, attempting refresh")
    try:
        raw = refresh_access_token(
            cached.token_endpoint,
            cached.client_id,
            cached.client_secret,
            cached.refresh_token,
            client,
            resource=server_url,
        )
    except Exception as e:
        log(f"token refresh failed: {e}")
        return None
    metadata = OAuthMetadata(
        authorization_endpoint=cached.authorization_endpoint,
        token_endpoint=cached.token_endpoint,
        registration_endpoint=cached.registration_endpoint,
    )
    data = _token_response_to_data(
        raw,
        metadata,
        cached.client_id,
        cached.client_secret,
        previous_refresh_token=cached.refresh_token,
        client_secret_expires_at=cached.client_secret_expires_at,
    )
    save_token(server_url, data)
    log("token refreshed successfully")
    return data


def _run_authorization_flow(
    server_url: str,
    client: httpx.Client,
    *,
    metadata: OAuthMetadata,
    cached: TokenData | None,
    client_id_override: str | None = None,
    scope: str | None = None,
    timeout: float = 120,
) -> TokenData:
    """Run the browser-based authorization code flow.

    Shared by both ``ensure_token`` (initial auth) and ``step_up_authorize``
    (RFC 9470 / MCP step-up for 403 insufficient_scope). Handles callback
    server setup, DCR (when no usable cached client credentials exist),
    PKCE, browser launch, code exchange, and persistence.
    """
    cb_result = CallbackResult()
    handler_cls = _make_callback_handler(cb_result)

    callback_server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = callback_server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    cid = client_id_override
    csecret: str | None = None
    cse_at: float | None = None
    if not cid:
        if cached and cached.client_id and not _is_client_secret_expired(cached):
            cid = cached.client_id
            csecret = cached.client_secret
            cse_at = cached.client_secret_expires_at
        else:
            log("registering OAuth client")
            reg = register_client(metadata, redirect_uri, client)
            cid = reg.client_id
            csecret = reg.client_secret
            cse_at = reg.client_secret_expires_at
            log(f"registered client: {cid}")
    assert cid is not None

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

    done = threading.Event()

    def serve() -> None:
        while not done.is_set():
            callback_server.handle_request()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    deadline = time.monotonic() + timeout
    while not (cb_result.auth_code or cb_result.error):
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

    if cb_result.error:
        raise RuntimeError(f"OAuth error: {cb_result.error}")

    if cb_result.state != state:
        raise RuntimeError("OAuth state mismatch — possible CSRF attack")

    code = cb_result.auth_code
    assert code is not None

    # Token exchange (RFC 8707: include resource indicator)
    log("exchanging authorization code for token")
    raw = exchange_code(
        metadata,
        cid,
        csecret,
        code,
        code_verifier,
        redirect_uri,
        client,
        resource=server_url,
    )
    data = _token_response_to_data(
        raw, metadata, cid, csecret, client_secret_expires_at=cse_at
    )
    save_token(server_url, data)
    log("OAuth token obtained and saved")
    return data


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
    cached = load_token(server_url)
    if cached and cached.access_token:
        if cached.expires_at is None or cached.expires_at > time.time() + 60:
            log("using cached OAuth token")
            return cached

        # Try refresh (skip if client_secret has expired per RFC 7591 §3.2.1)
        if cached.refresh_token and cached.token_endpoint and cached.client_id:
            refreshed = refresh_cached_token(server_url, client)
            if refreshed:
                return refreshed
            # Refresh failed or was skipped — clear stale token so the full
            # flow below isn't blocked by cached failure state
            # (cf. anthropics/claude-code#37747).
            delete_token(server_url)

    log("starting OAuth 2.1 authorization flow")
    metadata = discover_oauth_metadata(server_url, client)
    return _run_authorization_flow(
        server_url,
        client,
        metadata=metadata,
        cached=cached,
        client_id_override=client_id,
        scope=scope,
        timeout=timeout,
    )


def step_up_authorize(
    server_url: str,
    client: httpx.Client,
    required_scope: str,
    *,
    timeout: float = 120,
) -> TokenData:
    """Re-authorize with broader scopes after a 403 insufficient_scope.

    Implements the RFC 9470 / MCP spec step-up flow: the server has
    signaled that the current token lacks scopes required for the call,
    and the client must obtain a new token covering the **union** of the
    previously granted scopes and the scopes named in the challenge.

    Reuses the cached client_id (no re-DCR unless the cached client
    secret has expired per RFC 7591 §3.2.1). Endpoints come from the
    cached TokenData; if the cache is gone (rare), discovery is rerun.
    """
    cached = load_token(server_url)

    scope_parts: set[str] = set()
    if cached and cached.scope:
        scope_parts.update(cached.scope.split())
    scope_parts.update(required_scope.split())
    merged_scope = " ".join(sorted(scope_parts))
    log(f"step-up authorization requested with scope: {merged_scope}")

    if cached and cached.token_endpoint and cached.authorization_endpoint:
        metadata = OAuthMetadata(
            authorization_endpoint=cached.authorization_endpoint,
            token_endpoint=cached.token_endpoint,
            registration_endpoint=cached.registration_endpoint,
        )
    else:
        metadata = discover_oauth_metadata(server_url, client)

    return _run_authorization_flow(
        server_url,
        client,
        metadata=metadata,
        cached=cached,
        scope=merged_scope or None,
        timeout=timeout,
    )
