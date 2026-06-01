"""OAuth 2.1 client for MCP servers (RFC 7591, RFC 7636)."""

from __future__ import annotations

import base64
import hashlib
import html
import ipaddress
import re
import secrets
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import ParseResult, parse_qs, quote, urlencode, urlparse, urlsplit, urlunsplit

import httpx

from .relay import log
from .token_store import TokenData, delete_token, load_token, save_token

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


# Cap for the RFC 8628 device-flow polling interval (initial ``interval`` and
# each ``slow_down`` bump). Bounds a hostile/misconfigured AS-supplied value so
# a single sleep cannot block for hours, mirroring relay.py's Retry-After cap.
_DEVICE_POLL_CAP_SECS = 60

# Upper bound on the whole device-flow lifetime. ``expires_in`` from the AS
# drives the poll loop's deadline; the per-sleep interval is already capped, but
# without a ceiling on the total an AS returning ``expires_in: 999999999`` would
# keep the process polling the token endpoint for years. RFC 8628 device codes
# are typically ~1800 s; 3600 s is a generous bound that still kills the
# pathological case.
_DEVICE_FLOW_MAX_LIFETIME_SECS = 3600


def _safe_int(value: Any, default: int) -> int:
    """Coerce an AS-supplied JSON value to int, falling back on bad input."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


@dataclass
class OAuthMetadata:
    """Authorization server metadata (RFC 8414)."""

    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None = None
    device_authorization_endpoint: str | None = None
    token_endpoint_auth_methods_supported: list[str] | None = None
    # RFC 8414 issuer identifier — used to validate the RFC 9207 ``iss``
    # parameter on the authorization response (AS mix-up defence).
    issuer: str | None = None


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _authorization_base_url(server_url: str) -> str:
    """Derive authorization base URL by stripping the path component.

    Per MCP spec: https://api.example.com/v1/mcp -> https://api.example.com

    Any embedded userinfo (``user:pass@``) is dropped. ``_validate_endpoint_url``
    rejects AS-declared endpoints carrying userinfo as a parser-confusion /
    exfiltration vector (#13); the default ``/authorize`` and ``/token``
    endpoints synthesised from this base must not reintroduce it, or a
    ``https://user:pass@host/mcp`` server URL would cause credentials and
    authorization codes to be POSTed to ``https://user:pass@host/token``.
    """
    parsed = urlparse(server_url)
    if not parsed.scheme or not parsed.hostname:
        # A schemeless / hostless input (e.g. "example.com/mcp") otherwise
        # produces a malformed base like "://example.com/mcp" that flows
        # silently into the synthesized default endpoints. Fail clearly at the
        # source — OAuth needs an absolute http(s) URL with a host.
        raise ValueError(
            f"server URL must be an absolute http(s) URL with a host, "
            f"got {server_url!r}"
        )
    host = parsed.hostname
    # urlparse strips the brackets from an IPv6 literal host — restore them.
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port is not None else host
    return f"{parsed.scheme}://{netloc}"


# Default ports used when normalising a parsed URL into a RFC 6454 origin
# tuple for comparison. Any scheme outside this table falls through as None,
# which is fine — we only reach the cross-origin check after scheme has
# already been constrained to http/https.
_DEFAULT_PORTS = {"https": 443, "http": 80}


def _is_loopback(host: str) -> bool:
    """Return True for loopback hosts per RFC 6761 / RFC 1122 §3.2.1.3.

    Recognises ``localhost`` (with optional trailing dot per RFC 6761 §6.3),
    every textual form of the IPv6 loopback (``::1`` / ``0:0:0:0:0:0:0:1``),
    and the entire ``127.0.0.0/8`` IPv4 loopback block — not just the
    canonical ``127.0.0.1``. Parsing is delegated to ``ipaddress`` so any
    valid representation works.
    """
    if not host:
        return False
    h = host.lower().rstrip(".")
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _origin(parsed: ParseResult) -> tuple[str, str, int | None]:
    """Normalise a parsed URL to an RFC 6454 origin tuple for comparison.

    ``parsed.hostname`` already lowercases and strips userinfo; ``parsed.port``
    returns ``None`` when the authority omits an explicit port, so an explicit
    default port (``:443`` for https, ``:80`` for http) is folded back to the
    implicit form. Two URLs that differ only in case, explicit default port,
    or userinfo therefore compare equal.
    """
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port is None:
        port = _DEFAULT_PORTS.get(parsed.scheme)
    return (parsed.scheme, host, port)


def _validate_auth_server_url(auth_server_url: str, mcp_server_url: str) -> bool:
    """Validate a PRM-advertised authorization_server URL.

    Rejects the URL (returns False and logs a warning) when the scheme is
    not ``https://`` and the host is not loopback — a malicious MCP server
    could otherwise redirect the OAuth flow over plaintext HTTP and capture
    the resulting tokens. Cross-origin authorization servers are permitted
    by RFC 9728 §2 for federated setups; they produce a prominent warning
    so the user can abort before the browser opens. See #13.
    """
    try:
        parsed = urlparse(auth_server_url)
    except Exception:
        log(
            f"warning: malformed authorization_server URL "
            f"{auth_server_url!r}, ignoring"
        )
        return False

    if parsed.scheme not in ("https", "http"):
        log(
            f"warning: unsupported authorization_server scheme "
            f"{parsed.scheme!r} in {auth_server_url!r}, ignoring"
        )
        return False

    if parsed.username is not None or parsed.password is not None:
        # Mirror _validate_endpoint_url: an authorization_server carrying
        # userinfo would survive into the synthesized default token endpoint
        # (which is NOT re-validated), routing the credential exchange — code +
        # client_secret + PKCE verifier — through a userinfo authority. Refuse
        # it. See #13.
        log(
            f"warning: authorization_server URL {auth_server_url!r} embeds "
            f"userinfo (user:pass@); refusing as a credential-exfiltration / "
            f"parser-confusion vector. See #13."
        )
        return False

    if parsed.scheme == "http" and not _is_loopback(parsed.hostname or ""):
        log(
            f"warning: refusing to follow non-loopback HTTP "
            f"authorization_server {auth_server_url!r} — OAuth tokens "
            f"would traverse the wire in cleartext. Ignoring. See #13."
        )
        return False

    mcp_parsed = urlparse(mcp_server_url)
    if (
        parsed.hostname
        and mcp_parsed.hostname
        and _origin(parsed) != _origin(mcp_parsed)
    ):
        log(
            f"warning: authorization_server {auth_server_url!r} is "
            f"cross-origin to the MCP server {mcp_server_url!r}. "
            f"Tokens will be issued by a different host than the one "
            f"serving MCP. Abort if you did not expect federation."
        )

    return True


_RESOURCE_METADATA_QUOTED_RE = re.compile(r'resource_metadata\s*=\s*"([^"]+)"')
_RESOURCE_METADATA_UNQUOTED_RE = re.compile(r"resource_metadata\s*=\s*([^\s,\"]+)")


def _parse_resource_metadata_hint(header: str | None) -> str | None:
    """Extract the resource_metadata URL from a WWW-Authenticate Bearer challenge.

    RFC 9728 §5.1 defines the ``resource_metadata`` parameter as a hint
    pointing directly to the Protected Resource Metadata document URL.
    Returns the URL string when present; ``None`` otherwise.
    """
    if not header:
        return None
    match = _RESOURCE_METADATA_QUOTED_RE.search(header)
    if match:
        return match.group(1)
    match = _RESOURCE_METADATA_UNQUOTED_RE.search(header)
    if match:
        return match.group(1)
    return None


def _validate_prm_hint_url(hint_url: str, server_url: str) -> bool:
    """Validate a WWW-Authenticate resource_metadata hint URL before fetching.

    Applies the same policy as ``_validate_auth_server_url``:
    - Reject non-http/https schemes.
    - Reject plain HTTP for non-loopback hosts (tokens would be leaked).
    - Warn (but permit) cross-origin PRM URLs.

    Returns ``True`` when the URL is safe to follow, ``False`` to skip it.
    """
    try:
        parsed = urlparse(hint_url)
    except Exception:
        log(f"warning: malformed resource_metadata hint URL {hint_url!r}, ignoring")
        return False

    if parsed.scheme not in ("https", "http"):
        log(f"warning: unsupported scheme in resource_metadata hint {hint_url!r}, ignoring")
        return False

    if parsed.scheme == "http" and not _is_loopback(parsed.hostname or ""):
        log(
            f"warning: refusing resource_metadata hint {hint_url!r} "
            f"— plain HTTP over non-loopback would expose the OAuth flow. Ignoring."
        )
        return False

    mcp_parsed = urlparse(server_url)
    if (
        parsed.hostname
        and mcp_parsed.hostname
        and _origin(parsed) != _origin(mcp_parsed)
    ):
        log(
            f"warning: resource_metadata hint {hint_url!r} is cross-origin "
            f"to the MCP server {server_url!r}. "
            f"Abort if you did not expect federation."
        )

    return True


def _validate_endpoint_url(endpoint_url: str | None, *, label: str) -> str | None:
    """Validate an AS-metadata-declared endpoint URL before any secret is sent.

    The AS base URL is validated against the #13 "no plaintext token leak"
    policy, but the endpoints *inside* the fetched metadata
    (authorization/token/registration/device) are attacker-influenced: a
    hostile or compromised authorization server could declare
    ``token_endpoint="http://evil/token"`` and exfiltrate the authorization
    code, client_secret, and refresh_token in cleartext. Apply the same policy
    here — reject non-http(s) schemes, reject plain HTTP for non-loopback
    hosts, and reject embedded userinfo — returning ``None`` (with a warning) so
    the caller drops the unsafe endpoint rather than POSTing credentials to it.
    See #13.
    """
    if not endpoint_url:
        return None
    try:
        parsed = urlparse(endpoint_url)
    except Exception:
        log(f"warning: malformed {label} URL {endpoint_url!r}, ignoring")
        return None
    if parsed.username is not None or parsed.password is not None:
        # Legitimate AS metadata never embeds credentials in its declared
        # endpoints; userinfo (``user:pass@host``) is an exfiltration / parser-
        # confusion vector, so refuse it outright.
        log(f"warning: refusing {label} URL with embedded userinfo, ignoring")
        return None
    if parsed.scheme not in ("https", "http"):
        log(
            f"warning: unsupported {label} scheme {parsed.scheme!r} "
            f"in {endpoint_url!r}, ignoring"
        )
        return None
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname or ""):
        log(
            f"warning: refusing non-loopback HTTP {label} {endpoint_url!r} "
            f"— OAuth credentials would traverse the wire in cleartext. "
            f"Ignoring. See #13."
        )
        return None
    return endpoint_url


def _build_well_known_url(
    resource_url: str, suffix: str, *, keep_query: bool = False
) -> str:
    """Build a well-known URL by inserting the suffix between host and path.

    For RFC 9728 §3.1 (oauth-protected-resource) the well-known suffix is
    inserted between the host component and the path *and/or query* components
    of the resource identifier, so ``keep_query=True`` preserves the query:
      https://host/v2?t=1 + oauth-protected-resource (keep_query) ->
        https://host/.well-known/oauth-protected-resource/v2?t=1
    For RFC 8414 (oauth-authorization-server) the issuer grammar (§2) forbids a
    query/fragment, so the default ``keep_query=False`` drops it. Any
    terminating slash after the host is removed first.
    """
    parsed = urlsplit(resource_url)
    path = parsed.path.rstrip("/")
    well_known_path = f"/.well-known/{suffix}{path}"
    query = parsed.query if keep_query else ""
    # Drop any embedded userinfo so credentials in a ``user:pass@host`` server
    # URL are not sent as HTTP Basic auth on the discovery GET — consistent with
    # the userinfo stripping in _authorization_base_url and the #13 validators.
    host = parsed.hostname or ""
    if host:
        if ":" in host:
            host = f"[{host}]"  # re-bracket an IPv6 literal
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = f"{host}:{port}" if port is not None else host
    else:
        netloc = parsed.netloc  # no parseable host — preserve verbatim
    return urlunsplit((parsed.scheme, netloc, well_known_path, query, ""))


def _fetch_authorization_server_metadata(
    auth_server_url: str, client: httpx.Client
) -> OAuthMetadata | None:
    """Fetch RFC 8414 authorization server metadata.

    Returns None on any failure (404, invalid JSON, connection error).
    """
    # RFC 8414 issuer has no query component, so do not carry one through.
    well_known = _build_well_known_url(auth_server_url, "oauth-authorization-server")
    try:
        resp = client.get(well_known)
        if resp.status_code == 200:
            data = resp.json()
            # RFC 8414 §3.3: the issuer in the response MUST be identical to the
            # URL used for discovery. We log a warning on mismatch but continue
            # (the spec says reject) — real servers may be slightly misconfigured
            # (trailing slash, etc.) and rejecting would be too strict.
            issuer = data.get("issuer")
            if issuer and issuer.rstrip("/") != auth_server_url.rstrip("/"):
                log(
                    f"warning: RFC 8414 §3.3 issuer mismatch — "
                    f"expected {auth_server_url!r}, got {issuer!r}"
                )
            methods = data.get("token_endpoint_auth_methods_supported")
            # Strip a trailing slash before building default endpoints so an AS
            # URL like "https://as/" does not yield "https://as//authorize".
            base = auth_server_url.rstrip("/")
            # Validate every endpoint the metadata declares against the #13
            # cleartext-leak policy before it can receive a secret. An unsafe
            # authorization/token endpoint falls back to the default path on
            # the already-validated AS base URL; an unsafe optional endpoint is
            # dropped to None.
            return OAuthMetadata(
                authorization_endpoint=_validate_endpoint_url(
                    data.get("authorization_endpoint"), label="authorization_endpoint"
                )
                or f"{base}/authorize",
                token_endpoint=_validate_endpoint_url(
                    data.get("token_endpoint"), label="token_endpoint"
                )
                or f"{base}/token",
                registration_endpoint=_validate_endpoint_url(
                    data.get("registration_endpoint"), label="registration_endpoint"
                ),
                device_authorization_endpoint=_validate_endpoint_url(
                    data.get("device_authorization_endpoint"),
                    label="device_authorization_endpoint",
                ),
                token_endpoint_auth_methods_supported=methods if isinstance(methods, list) else None,
                issuer=issuer or auth_server_url,
            )
    except Exception:
        pass
    return None


def discover_oauth_metadata(
    server_url: str,
    client: httpx.Client,
    www_authenticate: str | None = None,
) -> OAuthMetadata:
    """Discover OAuth authorization server metadata.

    Follows the MCP spec discovery flow:
    0. If ``www_authenticate`` is provided and contains a ``resource_metadata``
       URL (RFC 9728 §5.1), try that URL first as the highest-priority PRM hint.
    1. Try RFC 9728 Protected Resource Metadata
       (/.well-known/oauth-protected-resource) to find the
       authorization server URL.
    2. Try RFC 8414 Authorization Server Metadata
       (/.well-known/oauth-authorization-server) on the
       discovered (or base) URL.
    3. Fall back to default endpoint paths.
    """
    base = _authorization_base_url(server_url)

    # Phase 0: RFC 9728 §5.1 — resource_metadata hint from WWW-Authenticate.
    # When the server already told us where its PRM lives, use that URL first
    # instead of guessing the well-known path.
    auth_server_url = base
    prm_candidates: list[str] = []
    hint = _parse_resource_metadata_hint(www_authenticate)
    if hint and _validate_prm_hint_url(hint, server_url):
        log(f"using resource_metadata hint from WWW-Authenticate: {hint}")
        prm_candidates.append(hint)

    # Phase 1: RFC 9728 Protected Resource Metadata.
    # Per RFC 9728 §3.1, the well-known URI is inserted between host and path
    # components of the resource identifier. Try the path-aware URL first for
    # path-based reverse-proxy deployments (cf. geelen/mcp-remote#249), then
    # fall back to host-root for servers that publish PRM at the origin.
    # RFC 9728 §3.1 preserves the resource identifier's query component.
    path_aware = _build_well_known_url(
        server_url, "oauth-protected-resource", keep_query=True
    )
    host_root = f"{base}/.well-known/oauth-protected-resource"
    if path_aware not in prm_candidates:
        prm_candidates.append(path_aware)
    if host_root != path_aware and host_root not in prm_candidates:
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
        found = False
        if auth_servers and isinstance(auth_servers, list):
            # Walk the list and pick the first entry that passes validation.
            # A malicious or misconfigured MCP server might otherwise send
            # us at a plaintext / cross-origin authorization server we
            # should never follow. See #13.
            for candidate in auth_servers:
                if isinstance(candidate, str) and _validate_auth_server_url(
                    candidate, server_url
                ):
                    auth_server_url = candidate
                    log(f"discovered authorization server: {auth_server_url}")
                    found = True
                    break
        if found:
            break
        # A 200 PRM doc that yielded no usable authorization_servers (missing /
        # empty / all entries rejected) must NOT end discovery — fall through to
        # the next candidate (e.g. the host-root PRM) instead of giving up here.

    # Phase 2: RFC 8414 Authorization Server Metadata
    meta = _fetch_authorization_server_metadata(auth_server_url, client)
    if meta:
        return meta

    # If auth server differs from base, also try base as fallback
    if auth_server_url != base:
        meta = _fetch_authorization_server_metadata(base, client)
        if meta:
            return meta

    # Path-scoped issuers (Keycloak realm URLs, AWS Cognito user pools, etc.)
    # publish metadata at /.well-known/oauth-authorization-server/<path> per
    # RFC 8414 §3 path-insertion. Try the original server_url when it has a
    # path component that neither the PRM-discovered AS nor the base URL tried.
    if server_url not in (auth_server_url, base):
        meta = _fetch_authorization_server_metadata(server_url, client)
        if meta:
            return meta

    # Phase 3: Default paths
    log("OAuth metadata not found, using default endpoints")
    return OAuthMetadata(
        authorization_endpoint=f"{base}/authorize",
        token_endpoint=f"{base}/token",
        registration_endpoint=f"{base}/register",
        # No metadata was validated on this fallback, so it is the LEAST
        # trustworthy discovery outcome — keep the RFC 9207 iss mix-up check
        # active by pinning the issuer to the base the endpoints derive from.
        # Otherwise an AS returning `iss` would be compared against None and
        # the defence would silently no-op precisely here.
        issuer=base,
    )


# ---------------------------------------------------------------------------
# Dynamic Client Registration (RFC 7591)
# ---------------------------------------------------------------------------

# Methods supported by mcp-stdio, in preference order (most-compatible first).
# "none" covers public clients; "client_secret_post" and "client_secret_basic"
# cover confidential clients per RFC 6749 §2.3.
_SUPPORTED_AUTH_METHODS = ("none", "client_secret_post", "client_secret_basic")


def _pick_token_endpoint_auth_method(supported: list[str] | None) -> str:
    """Pick the best token endpoint auth method from AS-advertised list.

    Returns the first entry of ``_SUPPORTED_AUTH_METHODS`` that the AS also
    supports.  Falls back to ``"none"`` when the AS list is absent (pre-RFC 8414
    servers) or only advertises methods that mcp-stdio does not implement
    (e.g. ``private_key_jwt``), with a warning in the latter case.
    """
    if not supported:
        return "none"
    for method in _SUPPORTED_AUTH_METHODS:
        if method in supported:
            return method
    log(
        f"warning: AS token_endpoint_auth_methods_supported {supported!r} "
        f"contains no methods supported by mcp-stdio "
        f"({', '.join(_SUPPORTED_AUTH_METHODS)}); defaulting to 'none'"
    )
    return "none"


@dataclass
class ClientRegistration:
    """Result of dynamic client registration."""

    client_id: str
    client_secret: str | None = None
    client_secret_expires_at: float | None = None  # RFC 7591 §3.2.1; None = no expiry
    auth_method: str = "none"


def _is_client_secret_expired(cached: TokenData) -> bool:
    """Return True if the cached client secret has expired per RFC 7591 §3.2.1."""
    if cached.client_secret_expires_at is None:
        return False
    return time.time() > cached.client_secret_expires_at


def register_client(
    metadata: OAuthMetadata,
    redirect_uri: str,
    client: httpx.Client,
    *,
    device_flow: bool = False,
) -> ClientRegistration:
    """Register a client via Dynamic Client Registration.

    When ``device_flow=True``, registers with the device code grant type
    (RFC 8628 §3.1) instead of the authorization code flow.

    Raises httpx.HTTPStatusError on failure.
    """
    if not metadata.registration_endpoint:
        raise ValueError(
            "Server does not support dynamic client registration. "
            "Provide a --client-id instead."
        )

    auth_method = _pick_token_endpoint_auth_method(
        metadata.token_endpoint_auth_methods_supported
    )
    if device_flow:
        body: dict[str, object] = {
            "client_name": "mcp-stdio",
            "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
            "token_endpoint_auth_method": auth_method,
        }
    else:
        body = {
            "client_name": "mcp-stdio",
            "redirect_uris": [redirect_uri],
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": auth_method,
        }
    resp = client.post(
        metadata.registration_endpoint,
        json=body,
    )
    resp.raise_for_status()
    data = resp.json()
    # RFC 7591 §3.2.1: client_secret_expires_at = 0 means "never expires".
    # Normalize 0 to None at the source so later expiry checks don't need to
    # special-case it.
    raw_expiry = data.get("client_secret_expires_at")
    expiry: float | None = None
    # Coerce defensively and treat 0 as "never expires" regardless of JSON type.
    # RFC 7591 specifies a number, but a non-conformant AS sending the string
    # "0" would be truthy here — float("0") == 0.0 would then read as
    # already-expired and force an unnecessary re-DCR on every refresh/step-up.
    try:
        v = float(raw_expiry) if raw_expiry is not None else 0.0
        expiry = v if v else None
    except (TypeError, ValueError):
        expiry = None
    # RFC 7591 §3.2.1 REQUIRES client_id; use .get() with an explicit error so a
    # malformed registration response is actionable, not a bare KeyError.
    client_id = data.get("client_id")
    if not client_id:
        raise ValueError(
            "Client registration response is missing client_id (RFC 7591 §3.2.1)."
        )
    return ClientRegistration(
        client_id=client_id,
        client_secret=data.get("client_secret"),
        client_secret_expires_at=expiry,
        auth_method=auth_method,
    )


# ---------------------------------------------------------------------------
# PKCE (RFC 7636)
# ---------------------------------------------------------------------------


def generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256).

    Returns (code_verifier, code_challenge).
    """
    verifier = secrets.token_urlsafe(64)[:96]  # ~86 chars, capped well within 43-128
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
    iss: str | None = None  # RFC 9207 issuer identifier, if the AS returned it


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

            # Single-shot capture: once the first authorization response is
            # recorded, ignore any subsequent /callback hit (browser refresh,
            # link prefetch, double-submit) so it cannot overwrite the captured
            # code/error in the race window before the main loop consumes it.
            if result.auth_code is not None or result.error is not None:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<h1>Already received</h1><p>You can close this tab.</p>"
                )
                return

            if "error" in params:
                result.error = params["error"][0]
            elif "code" in params:
                result.auth_code = params["code"][0]
                result.state = params.get("state", [None])[0]
                result.iss = params.get("iss", [None])[0]

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


def _raise_for_body_error(result: dict[str, Any]) -> None:
    """Raise RuntimeError if a 200 token response carries an in-body OAuth error.

    Some providers (GitHub legacy) return HTTP 200 with ``error`` /
    ``error_description`` instead of a token. Applies to both JSON and
    form-urlencoded bodies — GitHub legacy is precisely the provider that
    returns the form-urlencoded variant, so skipping the check there would
    surface as an opaque ``KeyError: 'access_token'`` downstream.
    """
    if "error" in result and "access_token" not in result:
        desc = result.get("error_description", result["error"])
        raise RuntimeError(f"OAuth token error: {desc}")


def _parse_token_response(resp: httpx.Response) -> dict[str, Any]:
    """Parse a token response, handling both JSON and form-urlencoded formats.

    GitHub OAuth (and some others) may return application/x-www-form-urlencoded.
    Some servers return HTTP 200 with an error in the body (GitHub legacy).
    """
    resp.raise_for_status()

    content_type = resp.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type:
        parsed = dict(parse_qs(resp.text, keep_blank_values=True))
        # parse_qs returns lists; unwrap single values
        result = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        _raise_for_body_error(result)
        return result

    result = resp.json()
    _raise_for_body_error(result)
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
    auth_method: str = "none",
) -> dict[str, Any]:
    """Exchange authorization code for tokens.

    Args:
        resource: RFC 8707 resource indicator (the MCP server URL).
        auth_method: Token endpoint authentication method (RFC 6749 §2.3).
            ``"client_secret_basic"`` sends credentials in an ``Authorization:
            Basic`` header per RFC 6749 §2.3.1; ``"none"`` / ``"client_secret_post"``
            keep them in the request body.

    Returns the raw token response dict.
    """
    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    req_headers: dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    if auth_method == "client_secret_basic" and client_secret:
        # URL-encode client_id and client_secret before base64-encoding for HTTP
        # Basic auth. RFC 6749 §2.3.1 specifies the form-urlencoded algorithm
        # (space -> '+'); we use strict percent-encoding (space -> %20), which
        # real client credentials never exercise and servers accept.
        creds = base64.b64encode(
            f"{quote(client_id, safe='')}:{quote(client_secret, safe='')}".encode()
        ).decode()
        req_headers["Authorization"] = f"Basic {creds}"
    else:
        data["client_id"] = client_id
        if client_secret:
            data["client_secret"] = client_secret
    if resource:
        data["resource"] = resource

    resp = client.post(
        metadata.token_endpoint,
        data=data,
        headers=req_headers,
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
    auth_method: str = "none",
) -> dict[str, Any]:
    """Refresh an access token.

    Args:
        resource: RFC 8707 resource indicator (the MCP server URL).
        auth_method: Token endpoint authentication method (RFC 6749 §2.3).

    Returns the raw token response dict.
    """
    data: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    req_headers: dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    if auth_method == "client_secret_basic" and client_secret:
        creds = base64.b64encode(
            f"{quote(client_id, safe='')}:{quote(client_secret, safe='')}".encode()
        ).decode()
        req_headers["Authorization"] = f"Basic {creds}"
    else:
        data["client_id"] = client_id
        if client_secret:
            data["client_secret"] = client_secret
    if resource:
        data["resource"] = resource

    resp = client.post(
        token_endpoint,
        data=data,
        headers=req_headers,
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
    previous_scope: str | None = None,
    client_secret_expires_at: float | None = None,
    auth_method: str = "none",
    no_resource_indicator: bool = False,
) -> TokenData:
    """Convert a raw token response to TokenData.

    If the response omits refresh_token (allowed per RFC 6749 Section 6),
    the previous_refresh_token is preserved so subsequent refreshes work.
    Likewise ``scope`` is OPTIONAL in a token response (RFC 6749 §5.1: it
    may be omitted when identical to the requested scope, which refreshes
    routinely do), so ``previous_scope`` is preserved — otherwise a refresh
    would wipe the granted scope and a later step-up could not union it.
    """
    if not raw.get("access_token"):
        # RFC 6749 §5.1 makes access_token REQUIRED. A response missing it is
        # not a usable token; fail loudly here instead of constructing a
        # TokenData with a None/empty credential that fails opaquely later.
        raise RuntimeError("token response missing access_token (RFC 6749 §5.1)")

    expires_at = None
    if "expires_in" in raw:
        # ``expires_in`` is numeric in JSON responses but a string in
        # form-urlencoded ones (GitHub-legacy path via _parse_token_response).
        # Coerce defensively so a string value cannot crash the whole flow.
        try:
            expires_at = time.time() + float(raw["expires_in"])
        except (TypeError, ValueError):
            expires_at = None

    # `.get(default)` only substitutes when the key is ABSENT; a provider that
    # returns an explicit `"token_type": null` (or a non-string) would otherwise
    # crash `.lower()` below. Treat null / empty / non-string as the Bearer
    # default (RFC 6749 §5.1 makes token_type REQUIRED, so this is non-conformant
    # input we tolerate rather than abort the whole flow on).
    tt = raw.get("token_type")
    token_type = tt if isinstance(tt, str) and tt else "Bearer"
    if token_type.lower() != "bearer":
        # mcp-stdio always sends the access token as an Authorization: Bearer
        # credential, so a non-Bearer token_type (e.g. DPoP / mac, RFC 9449)
        # would be presented in a form the resource server did not issue.
        # It fails closed (the RS rejects it), but warn so the misconfiguration
        # is visible instead of a silent downgrade. See RFC 6749 §7.1.
        log(
            f"warning: non-Bearer token_type {token_type!r}; "
            f"mcp-stdio sends it as a Bearer credential anyway"
        )

    return TokenData(
        access_token=raw["access_token"],
        token_type=token_type,
        expires_at=expires_at,
        refresh_token=raw.get("refresh_token") or previous_refresh_token,
        scope=raw.get("scope") or previous_scope,
        client_id=client_id,
        client_secret=client_secret,
        client_secret_expires_at=client_secret_expires_at,
        token_endpoint=metadata.token_endpoint,
        authorization_endpoint=metadata.authorization_endpoint,
        registration_endpoint=metadata.registration_endpoint,
        issuer=metadata.issuer,
        token_endpoint_auth_method=auth_method,
        no_resource_indicator=no_resource_indicator,
    )


def refresh_cached_token(
    server_url: str, client: httpx.Client
) -> TokenData | None:
    """Refresh the cached token for a server using its stored refresh_token.

    Returns updated TokenData on success, or None if no usable cached token
    exists (missing refresh_token / endpoint / client_id, or expired
    client_secret per RFC 7591 §3.2.1) or the refresh request fails.

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
    auth_method = cached.token_endpoint_auth_method
    no_resource_indicator = cached.no_resource_indicator
    try:
        raw = refresh_access_token(
            cached.token_endpoint,
            cached.client_id,
            cached.client_secret,
            cached.refresh_token,
            client,
            resource=None if no_resource_indicator else server_url,
            auth_method=auth_method,
        )
    except Exception as e:
        log(f"token refresh failed: {e}")
        return None
    metadata = OAuthMetadata(
        authorization_endpoint=cached.authorization_endpoint,
        token_endpoint=cached.token_endpoint,
        registration_endpoint=cached.registration_endpoint,
        # Carry the persisted issuer through so a refresh does not wipe it
        # (_token_response_to_data now writes metadata.issuer into TokenData).
        issuer=cached.issuer,
    )
    data = _token_response_to_data(
        raw,
        metadata,
        cached.client_id,
        cached.client_secret,
        previous_refresh_token=cached.refresh_token,
        previous_scope=cached.scope,
        client_secret_expires_at=cached.client_secret_expires_at,
        auth_method=auth_method,
        no_resource_indicator=no_resource_indicator,
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
    resource_indicator: bool = True,
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
    auth_method = "none"
    if not cid:
        if cached and cached.client_id and not _is_client_secret_expired(cached):
            cid = cached.client_id
            csecret = cached.client_secret
            cse_at = cached.client_secret_expires_at
            auth_method = cached.token_endpoint_auth_method
        else:
            log("registering OAuth client")
            # DCR runs before the callback server is closed on the success path
            # below; close it on failure so the listening socket does not leak.
            try:
                reg = register_client(metadata, redirect_uri, client)
            except BaseException:
                callback_server.server_close()
                raise
            cid = reg.client_id
            csecret = reg.client_secret
            cse_at = reg.client_secret_expires_at
            auth_method = reg.auth_method
            log(f"registered client: {cid}")
    if cid is None:  # -O-safe invariant (every branch above sets cid)
        raise RuntimeError("no client_id available for authorization")

    code_verifier, code_challenge = generate_pkce()

    # Authorization URL params; RFC 8707 resource indicator included by default
    state = secrets.token_urlsafe(32)
    params: dict[str, str] = {
        "client_id": cid,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if resource_indicator:
        params["resource"] = server_url
    if scope:
        params["scope"] = scope

    auth_url = f"{metadata.authorization_endpoint}?{urlencode(params)}"
    # Log a STATE-REDACTED URL. The user still needs a clickable URL when the
    # browser does not auto-open, but the single-use CSRF ``state`` nonce does
    # not need to land in stderr — MCP host logs (Claude Desktop/Code) persist
    # to files that may be shared in bug reports. The browser receives the full
    # URL below; the PKCE secret (``code_verifier``) is never in the URL and the
    # S256 ``code_challenge`` is public, so only ``state`` is worth redacting.
    log_url = f"{metadata.authorization_endpoint}?{urlencode({**params, 'state': '<redacted>'})}"
    log(f"authorize URL (open in browser if not auto-opened):\n{log_url}")

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

    # Use a constant-time comparison so the rejection path does not leak the
    # common-prefix length of the two state tokens via timing. Over a
    # loopback callback the attack is theoretical, but every mainstream
    # OAuth client does this and the line carries a CSRF-facing comment —
    # we want it to hold up to scrutiny without caveats. See #26.
    if not secrets.compare_digest(cb_result.state or "", state):
        raise RuntimeError("OAuth state mismatch — possible CSRF attack")

    # RFC 9207 §2.4: if the authorization response carries an `iss` parameter,
    # the client MUST validate it with a simple string comparison against the
    # issuer the metadata was fetched from. This is the AS mix-up defence — it
    # stops a code issued by AS-A from being exchanged at AS-B. Both values come
    # from the same AS (its metadata `issuer` and its callback `iss`) so they are
    # byte-identical; an exact compare (per §2.4, no normalisation) is correct.
    # Only checked when both are present; PKCE + state already cover the common
    # attacks, so this is defence-in-depth.
    if (
        cb_result.iss is not None
        and metadata.issuer
        and cb_result.iss != metadata.issuer
    ):
        raise RuntimeError(
            "OAuth issuer mismatch (RFC 9207) — possible AS mix-up attack"
        )

    code = cb_result.auth_code
    if code is None:  # -O-safe; the callback error path raises before here
        raise RuntimeError("authorization callback returned no code")

    log("exchanging authorization code for token")
    raw = exchange_code(
        metadata,
        cid,
        csecret,
        code,
        code_verifier,
        redirect_uri,
        client,
        resource=server_url if resource_indicator else None,
        auth_method=auth_method,
    )
    data = _token_response_to_data(
        raw,
        metadata,
        cid,
        csecret,
        # RFC 6749 §5.1 lets the AS omit `scope` when it equals the requested
        # scope — exactly what a step-up does (requested == merged union). Fall
        # back to the requested `scope` so the stored TokenData.scope is not
        # wiped to None, which would shrink the union on the NEXT step-up. On
        # initial auth `scope` is None, which is the correct fallback there too.
        previous_scope=scope,
        client_secret_expires_at=cse_at,
        auth_method=auth_method,
        no_resource_indicator=not resource_indicator,
    )
    save_token(server_url, data)
    log("OAuth token obtained and saved")
    return data


def _run_device_authorization_flow(
    server_url: str,
    client: httpx.Client,
    *,
    metadata: OAuthMetadata,
    cached: TokenData | None,
    client_id_override: str | None = None,
    scope: str | None = None,
    resource_indicator: bool = True,
) -> TokenData:
    """Run RFC 8628 Device Authorization Grant flow.

    Displays a ``verification_uri`` + ``user_code`` on stderr so the user can
    authorize on a separate device, then polls the token endpoint until the
    device code expires or the user grants access.
    """
    if not metadata.device_authorization_endpoint:
        raise ValueError(
            "Server does not support Device Authorization Grant "
            "(no device_authorization_endpoint in metadata). "
            "Use --oauth for browser-based flow instead."
        )

    cid = client_id_override
    csecret: str | None = None
    cse_at: float | None = None
    auth_method = "none"
    if not cid:
        if cached and cached.client_id and not _is_client_secret_expired(cached):
            cid = cached.client_id
            csecret = cached.client_secret
            cse_at = cached.client_secret_expires_at
            auth_method = cached.token_endpoint_auth_method
        elif metadata.registration_endpoint:
            log("registering OAuth client for device flow")
            reg = register_client(metadata, "", client, device_flow=True)
            cid = reg.client_id
            csecret = reg.client_secret
            cse_at = reg.client_secret_expires_at
            auth_method = reg.auth_method
            log(f"registered client: {cid}")
        else:
            raise ValueError(
                "Server does not support dynamic client registration. "
                "Provide a --client-id instead."
            )
    if cid is None:  # -O-safe invariant (every branch above sets cid)
        raise RuntimeError("no client_id available for device authorization")

    # Step 1: Device Authorization Request (RFC 8628 §3.1)
    da_params: dict[str, str] = {}
    if resource_indicator:
        da_params["resource"] = server_url
    if scope:
        da_params["scope"] = scope
    da_headers: dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    if auth_method == "client_secret_basic" and csecret:
        creds = base64.b64encode(
            f"{quote(cid, safe='')}:{quote(csecret, safe='')}".encode()
        ).decode()
        da_headers["Authorization"] = f"Basic {creds}"
    else:
        da_params["client_id"] = cid
        if csecret:
            da_params["client_secret"] = csecret

    da_resp = client.post(
        metadata.device_authorization_endpoint,
        data=da_params,
        headers=da_headers,
    )
    da_resp.raise_for_status()
    da = da_resp.json()

    # RFC 8628 §3.2 REQUIRED fields. Use .get() with an explicit error so a
    # malformed AS response yields an actionable message, not a bare KeyError.
    device_code = da.get("device_code")
    user_code = da.get("user_code")
    if not device_code or not user_code:
        raise ValueError(
            "Device authorization response is missing device_code/user_code "
            "(RFC 8628 §3.2)."
        )
    # RFC 8628 §3.2 mandates ``verification_uri``; Google's device endpoint
    # historically returns the non-standard ``verification_url``. Accept either
    # so the advertised --oauth-device flow works against Google. Validate the
    # scheme/origin (the URL is presented to the user as an actionable "Open:"
    # instruction) so a hostile AS cannot phish via a cleartext / non-http(s)
    # verification URL — mirroring the AS-endpoint validation. See #13.
    verification_uri = _validate_endpoint_url(
        da.get("verification_uri") or da.get("verification_url"),
        label="verification_uri",
    )
    if not verification_uri:
        raise ValueError(
            "Device authorization response is missing or has an unsafe "
            "verification_uri (RFC 8628 §3.2)."
        )
    verification_uri_complete = _validate_endpoint_url(
        da.get("verification_uri_complete") or da.get("verification_url_complete"),
        label="verification_uri_complete",
    )
    # Coerce defensively: a JSON float-as-string or non-numeric value from a
    # malformed/hostile AS must fall back to the default, not raise ValueError
    # out of the flow. Clamp to a max lifetime so an inflated expires_in cannot
    # keep the poll loop (and the process) alive indefinitely — the per-sleep
    # interval cap above does not bound the overall deadline on its own.
    expires_in = max(
        1, min(_safe_int(da.get("expires_in"), 1800), _DEVICE_FLOW_MAX_LIFETIME_SECS)
    )
    # Clamp the AS-supplied polling interval to a sane window so a hostile or
    # misconfigured AS cannot make a single time.sleep block for hours (or
    # raise on a negative value), mirroring the cap-gated Retry-After sleep in
    # relay.py. RFC 8628 §3.5 only mandates the +5 s slow_down bump (also capped).
    poll_interval = max(1, min(_safe_int(da.get("interval"), 5), _DEVICE_POLL_CAP_SECS))

    # Display instructions on stderr (visible even when stdout is piped to MCP client)
    print("\nDevice authorization required:", file=sys.stderr)
    if verification_uri_complete:
        print(f"  Open: {verification_uri_complete}", file=sys.stderr)
    else:
        print(f"  Open: {verification_uri}", file=sys.stderr)
        print(f"  Enter code: {user_code}", file=sys.stderr)
    print(f"\nWaiting for authorization (expires in {expires_in}s)...", file=sys.stderr)

    # Step 2: Poll token endpoint (RFC 8628 §3.4 request / §3.5 response)
    # Sleep is at the end of each iteration so the first poll is immediate.
    deadline = time.monotonic() + expires_in

    def _poll_sleep() -> None:
        # Never sleep past the deadline — a slow_down-inflated interval must not
        # overshoot the device-code expiry by a whole interval.
        time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))

    while time.monotonic() < deadline:
        poll_data: dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
        }
        poll_headers: dict[str, str] = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if auth_method == "client_secret_basic" and csecret:
            creds = base64.b64encode(
                f"{quote(cid, safe='')}:{quote(csecret, safe='')}".encode()
            ).decode()
            poll_headers["Authorization"] = f"Basic {creds}"
        else:
            poll_data["client_id"] = cid
            if csecret:
                poll_data["client_secret"] = csecret

        try:
            tok_resp = client.post(
                metadata.token_endpoint,
                data=poll_data,
                headers=poll_headers,
            )
        except Exception as exc:
            log(f"device flow poll error: {exc}")
            _poll_sleep()
            continue

        if tok_resp.status_code == 200:
            raw = _parse_token_response(tok_resp)
            data = _token_response_to_data(
                raw,
                metadata,
                cid,
                csecret,
                client_secret_expires_at=cse_at,
                auth_method=auth_method,
                no_resource_indicator=not resource_indicator,
            )
            save_token(server_url, data)
            log("device flow token obtained and saved")
            return data

        try:
            err = tok_resp.json().get("error", "")
        except Exception:
            tok_resp.raise_for_status()
            _poll_sleep()
            continue

        if err == "authorization_pending":
            pass
        elif err == "slow_down":
            # RFC 8628 §3.5: increase interval by 5 seconds (capped)
            poll_interval = min(poll_interval + 5, _DEVICE_POLL_CAP_SECS)
        elif err in ("expired_token", "access_denied"):
            raise RuntimeError(f"Device flow failed: {err}")
        else:
            tok_resp.raise_for_status()

        _poll_sleep()

    raise TimeoutError(
        "Device authorization timed out. Please restart and try again."
    )


def ensure_token(
    server_url: str,
    client: httpx.Client,
    *,
    client_id: str | None = None,
    scope: str | None = None,
    timeout: float = 120,
    device_flow: bool = False,
    refresh_leeway: float = 60.0,
    resource_indicator: bool = True,
) -> TokenData:
    """Ensure a valid access token is available.

    1. Check cached token — use if not expired (with ``refresh_leeway`` margin)
    2. If expired, try refresh
    3. If no token or refresh fails, run OAuth flow:
       - ``device_flow=True``: Device Authorization Grant (RFC 8628)
       - ``device_flow=False``: Authorization Code flow with PKCE (default)

    ``refresh_leeway`` is the proactive-refresh window in seconds: a cached
    token is considered expired when its actual expiry is within this many
    seconds from now. Default 60 s absorbs typical clock skew. Tune via
    ``--oauth-refresh-leeway`` for ASes that issue extremely short-lived
    access tokens or for deployments with larger clock skew.

    When ``resource_indicator=False`` the RFC 8707 ``resource`` parameter is
    omitted from all requests. Use ``--no-resource-indicator`` for AS that
    reject the parameter (e.g. Microsoft Entra ID v2 with api:// scopes).

    Returns TokenData with a valid access_token.
    """
    cached = load_token(server_url)
    if cached and cached.access_token:
        if cached.expires_at is None or cached.expires_at > time.time() + refresh_leeway:
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
    # Probe the MCP server for a WWW-Authenticate resource_metadata hint
    # (RFC 9728 §5.1) before running discovery. Servers that publish PRM at
    # a non-standard URL advertise it here, letting us skip the well-known
    # guessing. Best-effort — failures silently fall back to normal discovery.
    www_authenticate = _probe_www_authenticate(server_url, client)
    metadata = discover_oauth_metadata(server_url, client, www_authenticate=www_authenticate)
    if device_flow:
        return _run_device_authorization_flow(
            server_url,
            client,
            metadata=metadata,
            cached=cached,
            client_id_override=client_id,
            scope=scope,
            resource_indicator=resource_indicator,
        )
    return _run_authorization_flow(
        server_url,
        client,
        metadata=metadata,
        cached=cached,
        client_id_override=client_id,
        scope=scope,
        timeout=timeout,
        resource_indicator=resource_indicator,
    )


def _probe_www_authenticate(server_url: str, client: httpx.Client) -> str | None:
    """Send a minimal MCP initialize request and return the WWW-Authenticate header.

    Used before OAuth discovery to extract a ``resource_metadata`` hint
    (RFC 9728 §5.1). Servers that check authentication before parsing the
    request body will respond with 401, revealing their PRM URL. Any failure
    (connection error, non-401 status, missing header) silently returns ``None``.
    """
    probe_body = (
        '{"jsonrpc":"2.0","id":0,"method":"initialize","params":'
        '{"protocolVersion":"2024-11-05","capabilities":{},'
        '"clientInfo":{"name":"mcp-stdio-probe","version":"0"}}}'
    )
    try:
        resp = client.post(
            server_url,
            content=probe_body,
            headers={"Content-Type": "application/json"},
            timeout=10.0,
        )
        if resp.status_code == 401:
            return resp.headers.get("WWW-Authenticate")
    except Exception:
        pass
    return None


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
            # Rehydrate the persisted issuer so the RFC 9207 `iss` mix-up check
            # in _run_authorization_flow stays active on this cache-hit path —
            # step-up runs a full browser+callback flow, the case most exposed
            # to AS mix-up, so the defence must not silently no-op here.
            issuer=cached.issuer,
        )
    else:
        metadata = discover_oauth_metadata(server_url, client)

    resource_indicator = not (cached.no_resource_indicator if cached else False)
    return _run_authorization_flow(
        server_url,
        client,
        metadata=metadata,
        cached=cached,
        scope=merged_scope or None,
        timeout=timeout,
        resource_indicator=resource_indicator,
    )
