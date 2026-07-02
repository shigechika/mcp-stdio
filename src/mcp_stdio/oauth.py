"""OAuth 2.1 client for MCP servers (RFC 7591, RFC 7636)."""

from __future__ import annotations

import base64
import hashlib
import html
import ipaddress
import math
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

from .relay import _parse_auth_params, log
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
    except (TypeError, ValueError, OverflowError):
        # OverflowError: json.loads parses the non-standard literal
        # Infinity / -Infinity by default, and int(float('inf')) raises
        # OverflowError (not ValueError). Without this, a hostile / misconfigured
        # AS returning {"expires_in": Infinity} would crash the device flow with
        # an opaque traceback and DEFEAT the _DEVICE_FLOW_MAX_LIFETIME_SECS clamp
        # this very helper feeds. (NaN already lands in ValueError.) Mirrors the
        # math.isfinite guard token_store applies to cached expiries.
        return default


# RFC 6749 error / error_description grammar (NQSCHAR): printable ASCII
# excluding double-quote (0x22) and backslash (0x5C). The ABNF is defined in
# Appendix A.7 (`error = 1*NQSCHAR`) and A.8 (`error-description = 1*NQSCHAR`);
# §4.1.2.1 / §5.2 are where those parameters are used. Anything outside it is
# stripped from an AS-supplied error before it reaches a log / exception, so a
# hostile AS cannot inject control characters or megabytes of text into the
# operator's logs. See #12.
_OAUTH_ERROR_DISALLOWED_RE = re.compile(r"[^\x20\x21\x23-\x5B\x5D-\x7E]")


def _sanitize_oauth_error(value: Any, *, max_len: int = 200) -> str:
    """Sanitise an AS-supplied error/description to the RFC 6749 grammar.

    Strips out-of-grammar characters and bounds the length so the value is safe
    to embed in an exception message or log line.
    """
    cleaned = _OAUTH_ERROR_DISALLOWED_RE.sub("", str(value))[:max_len]
    return cleaned or "<unspecified>"


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
    # RFC 9207 §3 metadata flag. When the AS advertises this true, RFC 9207 §2.4
    # makes the client MUST reject an authorization response that lacks ``iss``.
    iss_parameter_supported: bool = False
    # MCP 2025-11-25 "Client ID Metadata Documents" / RFC 8414 extension
    # (draft-ietf-oauth-client-id-metadata-document-00 §5 "Authorization Server
    # Metadata"). When the AS advertises this true, an HTTPS URL pointing to a
    # client metadata document may be used as ``client_id`` in place of DCR or
    # a pre-registered id (#60).
    client_id_metadata_document_supported: bool = False


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _authorization_base_url(server_url: str) -> str:
    """Derive the authorization-server ORIGIN by stripping the path component.

    e.g. https://api.example.com/v1/mcp -> https://api.example.com

    This is NOT the PRM discovery rule: current MCP / RFC 9728 discovery is
    path-aware (``_build_well_known_url(..., keep_query=True)`` preserves the
    resource path). This helper only derives an http(s) origin used as the AS
    base and the host-root PRM *fallback* — it deliberately does not influence
    the path-aware PRM lookup.

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


def _resource_indicator(server_url: str) -> str:
    """Return the RFC 8707 ``resource`` value for ``server_url``.

    Strips embedded userinfo (``user:pass@``) — RFC 8707 §2 defines the resource
    as a target-service URI and the credentials are not part of that identity;
    leaving them in would send them verbatim in the token/authorize form body,
    the authorize URL (and the browser address bar), and the AS's request logs.
    Mirrors the userinfo-strip discipline of ``_authorization_base_url`` /
    ``_build_well_known_url``. Keeps the path and query (they distinguish
    resources) but drops any fragment (RFC 8707 §2 MUST NOT). Returns the input
    unchanged if it does not parse as an http(s) URL with a host.
    """
    try:
        parsed = urlparse(server_url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return server_url
    if not parsed.scheme or not host:
        return server_url
    if ":" in host:  # re-bracket an IPv6 literal host (urlparse strips brackets)
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    resource = f"{parsed.scheme}://{netloc}{parsed.path}"
    if parsed.query:
        resource += f"?{parsed.query}"
    return resource


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


def _origin(parsed: ParseResult) -> tuple[str, str, int | str | None]:
    """Normalise a parsed URL to an RFC 6454 origin tuple for comparison.

    ``parsed.hostname`` already lowercases and strips userinfo; ``parsed.port``
    returns ``None`` when the authority omits an explicit port, so an explicit
    default port (``:443`` for https, ``:80`` for http) is folded back to the
    implicit form. Two URLs that differ only in case, explicit default port,
    or userinfo therefore compare equal.
    """
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        # urllib parses the port LAZILY and raises ValueError on a
        # non-numeric / out-of-range port (e.g. ``host:999999``) only on access.
        # Guard it like _authorization_base_url / _build_well_known_url so a
        # malformed-port URL never crashes a caller mid-discovery; return a
        # string sentinel that can never equal a valid (scheme, host, int|None)
        # origin, so such a URL reads as a distinct, non-matching origin. The
        # #13 validators reject malformed-port URLs up front, so this is
        # defense-in-depth for any other _origin caller.
        return (parsed.scheme, host, "invalid-port")
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

    Reachability of internal / private-network HTTPS hosts is intentional and
    not filtered: mcp-stdio is built to serve MCP servers (and their federated
    authorization servers) on private networks, so applying an RFC 1918 address
    block would break that supported case. The operator's choice to trust this
    MCP server URL is the trust anchor, and the discovery requests these
    validators gate are GETs that carry NO caller credential (the bearer token
    is dropped before the OAuth client is built) and do not follow redirects —
    a host reached here is probed for metadata, never handed a secret, and every
    candidate endpoint is independently re-validated before any token exchange.
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

    try:
        parsed.port  # force the lazy port parse; raises on out-of-range/non-numeric
    except ValueError:
        # a malformed port makes this URL unusable AND would crash
        # the _origin() comparison below. Skip the candidate (return False) so the
        # discovery walk advances to the next authorization_server instead of
        # letting a single bad entry abort the whole OAuth flow with a ValueError.
        log(
            f"warning: authorization_server URL {auth_server_url!r} has an "
            f"invalid port, ignoring"
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


def _parse_resource_metadata_hint(header: str | None) -> str | None:
    """Extract the resource_metadata URL from a WWW-Authenticate Bearer challenge.

    RFC 9728 §5.1 defines the ``resource_metadata`` parameter as a hint
    pointing directly to the Protected Resource Metadata document URL.
    Returns the URL string when present; ``None`` otherwise. Uses the shared
    quote-aware auth-param parser (``_parse_auth_params``), so a decoy param
    ending in ``resource_metadata`` or a URL embedded in another param's
    quoted value is not mis-extracted (cf. modelcontextprotocol/python-sdk#3009).
    """
    return _parse_auth_params(header).get("resource_metadata") or None


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

    if parsed.username is not None or parsed.password is not None:
        # Parity with the sibling #13 validators (_validate_auth_server_url,
        # _validate_endpoint_url): refuse embedded userinfo so this attacker-
        # influenced hint cannot send HTTP Basic credentials to a userinfo
        # authority on the discovery GET.
        log(
            f"warning: resource_metadata hint {hint_url!r} embeds userinfo "
            f"(user:pass@); refusing. See #13."
        )
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
    try:
        parsed.port  # force the lazy port parse; raises on out-of-range/non-numeric
    except ValueError:
        # a malformed port (e.g. ``host:999999``) is unusable and
        # must be dropped here — otherwise this attacker-influenced endpoint
        # passes validation and a credential POST surfaces an opaque httpx error
        # deep in exchange_code / refresh instead of a clean validation drop.
        log(f"warning: malformed {label} URL {endpoint_url!r} (invalid port), ignoring")
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


def _parse_as_metadata_response(
    data: Any, auth_server_base: str
) -> OAuthMetadata | None:
    """Build OAuthMetadata from an RFC 8414 / OpenID Connect discovery body.

    The schema is shared: OpenID Connect Discovery 1.0 is a superset of RFC 8414,
    so one parser serves both well-known forms. Returns None when the body is
    unusable (non-object) or its issuer is a CROSS-ORIGIN mix-up signal, so the
    caller can skip to the next discovery candidate; a same-origin issuer
    mismatch is downgraded to a warning and still used.
    """
    if not isinstance(data, dict):
        return None
    # RFC 8414 §3.3: the issuer in the response MUST be identical to the URL used
    # for discovery. We split the spec's MUST-reject by ORIGIN:
    #   - A cross-ORIGIN issuer (different scheme/host/port) is a mix-up /
    #     AS-spoofing signal — REJECT (return None) so this metadata is never
    #     used. Otherwise it would anchor the RFC 9207 `iss` check (see issuer=
    #     below) on a FOREIGN origin: an adversarial AS that returns a different
    #     issuer AND echoes that same `iss` on the callback would self-satisfy
    #     the mix-up defence.
    #   - A SAME-origin mismatch (trailing slash, path, case) is the kind of
    #     slight misconfiguration real servers ship, so warn and continue.
    issuer = data.get("issuer")
    if issuer and _origin(urlparse(issuer)) != _origin(urlparse(auth_server_base)):
        log(
            f"warning: RFC 8414 §3.3 issuer ORIGIN mismatch — expected "
            f"the origin of {auth_server_base!r}, got {issuer!r}; "
            f"refusing this authorization-server metadata (mix-up guard)"
        )
        return None
    if issuer and issuer.rstrip("/") != auth_server_base.rstrip("/"):
        log(
            f"warning: RFC 8414 §3.3 issuer mismatch (same origin) — "
            f"expected {auth_server_base!r}, got {issuer!r}; continuing"
        )
    methods = data.get("token_endpoint_auth_methods_supported")
    # Strip a trailing slash before building default endpoints so an AS
    # URL like "https://as/" does not yield "https://as//authorize".
    base = auth_server_base.rstrip("/")
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
        issuer=issuer or auth_server_base,
        # RFC 9207 §3: a true value makes a missing `iss` on the
        # authorization response a MUST-reject (§2.4). Coerce strictly to
        # bool so a non-bool JSON value cannot accidentally enable the
        # stricter check off a truthy string.
        iss_parameter_supported=(
            data.get("authorization_response_iss_parameter_supported") is True
        ),
        # draft-ietf-oauth-client-id-metadata-document-00 §5: same strict-bool
        # coercion as iss_parameter_supported, for the same reason — a non-bool
        # JSON value must not accidentally enable the CIMD client_id path.
        client_id_metadata_document_supported=(
            data.get("client_id_metadata_document_supported") is True
        ),
    )


def _fetch_authorization_server_metadata(
    auth_server_url: str, client: httpx.Client
) -> OAuthMetadata | None:
    """Fetch RFC 8414 / OpenID Connect authorization server metadata.

    Tries, in order, the RFC 8414 well-known location (the well-known string
    inserted between host and path per §3.1), then the OpenID Connect Discovery
    1.0 locations: path-append (``<issuer>/.well-known/openid-configuration`` —
    the common form, used by Azure AD, Keycloak realms, etc.) then path-insertion.
    OIDC discovery is the RFC 8414 §3 transitional fallback that many real-world
    ASes (Auth0, Okta, Azure AD, Google) expose INSTEAD of the OAuth form, whose
    metadata schema is a superset of RFC 8414's. Returns None when every
    candidate fails (404, invalid JSON, connection error, or a cross-origin
    issuer mix-up signal).
    """
    # RFC 8414 issuer has no query/fragment/userinfo; _build_well_known_url
    # already strips all three when forming the discovery URL, so the issuer
    # comparison, the OIDC path-append candidate, and the synthesized default
    # endpoints must use the SAME stripped base. Otherwise a server_url like
    # ``https://host/mcp?tenant=x`` (passed on the Phase-2 path-scoped fallback)
    # produces a spurious §3.3 mismatch warning and a malformed default, and a
    # ``https://user:pass@host/mcp`` would leak credentials into the OIDC GET and
    # the default token endpoint (the #13 cleartext/credential-leak policy strips
    # userinfo everywhere else). Drop any userinfo (everything before the last
    # ``@``) from the netloc; host[:port] and an IPv6 literal pass through.
    _asp = urlsplit(auth_server_url)
    _netloc = _asp.netloc.rsplit("@", 1)[-1]
    auth_server_base = urlunsplit((_asp.scheme, _netloc, _asp.path, "", ""))
    base_noslash = auth_server_base.rstrip("/")
    # Most-authoritative first, de-duplicated (the OIDC path-append and
    # path-insertion forms coincide for a bare-origin issuer).
    candidates: list[str] = []
    for url in (
        _build_well_known_url(auth_server_url, "oauth-authorization-server"),
        f"{base_noslash}/.well-known/openid-configuration",
        _build_well_known_url(auth_server_url, "openid-configuration"),
    ):
        if url and url not in candidates:
            candidates.append(url)
    for well_known in candidates:
        try:
            resp = client.get(well_known)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except Exception:
            continue
        meta = _parse_as_metadata_response(data, auth_server_base)
        if meta is not None:
            return meta
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
        # The PRM document is fully MCP-server-controlled. A non-object body
        # (e.g. a bare array or scalar) would make prm_data.get(...) raise
        # AttributeError and abort the whole flow — skip to the next candidate
        # (host-root PRM / Phase 2/3) instead of crashing the multi-candidate
        # fallback. Symmetric with the isinstance(candidate, str) guard on the
        # authorization_servers walk below.
        if not isinstance(prm_data, dict):
            continue
        # RFC 9728 §3.3 actually says the `resource` value MUST be identical to
        # the protected-resource identifier and, if it is not, "the data
        # contained in the response MUST NOT be used" (an impersonation guard).
        # We deliberately downgrade that to warn-and-continue: strict rejection
        # would break servers that normalise the identifier differently (trailing
        # slash, case, default port) than the operator-supplied server_url. The
        # impersonation risk the MUST guards against is independently closed
        # downstream — every `authorization_servers` candidate is re-checked by
        # _validate_auth_server_url (#13) before any credential is sent, and the
        # PRM URL itself derives from the operator-trusted server_url — so the
        # softening does not widen the trust boundary, only the citation's letter.
        prm_resource = prm_data.get("resource")
        # Guard the type too: a non-string `resource` (e.g. 123)
        # would make .rstrip raise. A non-string is simply not a usable
        # identifier — skip the mismatch warning rather than crash.
        #
        # Compare against the userinfo-STRIPPED identifier:
        # a compliant PRM `resource` never carries userinfo, and the rest of the
        # flow already uses the stripped form (_resource_indicator /
        # _build_well_known_url / _authorization_base_url). Comparing the raw
        # server_url would emit a misleading §3.3 mismatch warning whenever the
        # operator passed `https://user:pass@host/mcp` against a correct PRM
        # advertising `https://host/mcp`.
        expected_resource = _resource_indicator(server_url)
        if (
            isinstance(prm_resource, str)
            and prm_resource.rstrip("/") != expected_resource.rstrip("/")
        ):
            log(
                f"warning: RFC 9728 §3.3 resource mismatch — "
                f"expected {expected_resource!r}, got {prm_resource!r}"
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

    # If auth server differs from base, also try base as fallback.
    #
    # when PRM advertised a CROSS-ORIGIN AS whose own RFC 8414
    # metadata fetch failed, this fetches metadata from the MCP-host base — the
    # endpoints returned then derive from the MCP host, not the PRM-advertised
    # AS. This is a deliberate tradeoff, NOT the Phase-3 default-endpoint pinning
    # below: the overwhelmingly common "AS == resource server" self-hosting
    # deployment relies on this base fallback to find the co-located metadata,
    # and any endpoints returned still pass _validate_endpoint_url (no cleartext
    # leak). Phase 3, by contrast, has no live metadata to anchor on and so pins
    # synthesized defaults to the PRM-advertised AS. The fallback is bounded to
    # the operator-trusted MCP host, so it does not widen the trust boundary.
    if auth_server_url != base:
        meta = _fetch_authorization_server_metadata(base, client)
        if meta:
            # Surface the origin re-anchoring: the token/authorize
            # endpoints now come from the MCP host, not the PRM-advertised AS the
            # operator may have expected. Benign for the common co-located
            # deployment, but in a genuine federated setup this is worth seeing.
            log(
                f"warning: PRM-advertised authorization server {auth_server_url!r} "
                f"returned no RFC 8414 metadata; using the MCP-host base {base!r} "
                f"instead — endpoints are sourced from the resource server's origin"
            )
            return meta

    # Path-scoped issuers (Keycloak realm URLs, AWS Cognito user pools, etc.)
    # publish metadata at /.well-known/oauth-authorization-server/<path> per
    # RFC 8414 §3 (the well-known string is inserted between the host and the
    # issuer's path component; §3.1 illustrates it for the metadata request).
    # Try the original server_url when it has a path component that neither the
    # PRM-discovered AS nor the base URL tried.
    if server_url not in (auth_server_url, base):
        meta = _fetch_authorization_server_metadata(server_url, client)
        if meta:
            return meta

    # Phase 3: Default paths
    log("OAuth metadata not found, using default endpoints")
    # Derive the default endpoints from the DISCOVERED authorization server when
    # PRM advertised one (auth_server_url differs from the MCP-host base). A
    # cross-origin AS that published no reachable RFC 8414 metadata would
    # otherwise have its credential/code exchange POSTed to the MCP host — the
    # wrong origin entirely. When no PRM AS was found, auth_server_url == base,
    # so this reduces to the previous MCP-host defaults.
    as_base = auth_server_url.rstrip("/")
    # re-validate the synthesized endpoints through the same #13
    # policy the metadata path applies (no cleartext / no userinfo), so this
    # fallback enforces the credential-leak guard too. as_base was already
    # validated upstream (_validate_auth_server_url or _authorization_base_url),
    # so this is defense-in-depth — but if that upstream check ever weakened we
    # must not silently POST code + client_secret + PKCE verifier to an unsafe
    # endpoint. Hard-fail instead.
    authorize_ep = _validate_endpoint_url(
        f"{as_base}/authorize", label="default authorization_endpoint"
    )
    token_ep = _validate_endpoint_url(
        f"{as_base}/token", label="default token_endpoint"
    )
    if not authorize_ep or not token_ep:
        raise ValueError(
            f"refusing to synthesize default OAuth endpoints from an unsafe "
            f"authorization-server base {as_base!r}"
        )
    return OAuthMetadata(
        authorization_endpoint=authorize_ep,
        token_endpoint=token_ep,
        registration_endpoint=_validate_endpoint_url(
            f"{as_base}/register", label="default registration_endpoint"
        ),
        # No metadata was validated on this fallback, so it is the LEAST
        # trustworthy discovery outcome — keep the RFC 9207 iss mix-up check
        # active by pinning the issuer to the base the endpoints derive from.
        # Otherwise an AS returning `iss` would be compared against None and
        # the defence would silently no-op precisely here.
        issuer=as_base,
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


def _warn_if_basic_auth_lacks_secret(
    auth_method: str, client_secret: str | None
) -> None:
    """Warn when client_secret_basic is selected but no client_secret is present.

    The callers then fall back to sending only client_id in the request body,
    which an AS expecting HTTP Basic credentials for a confidential client
    rejects. Surfacing the inconsistency turns an opaque AS 401 into an
    actionable message.
    """
    if auth_method == "client_secret_basic" and not client_secret:
        log(
            "warning: token_endpoint_auth_method is 'client_secret_basic' but no "
            "client_secret is available — sending client_id only; the AS will "
            "likely reject this. Re-registration (RFC 7591) may be needed."
        )


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
            "Provide a --client-id or --client-metadata-url instead."
        )

    auth_method = _pick_token_endpoint_auth_method(
        metadata.token_endpoint_auth_methods_supported
    )
    # SEP-837 / RFC 8252 §8.4: mcp-stdio is a NATIVE client — the auth-code flow
    # uses a loopback (http://127.0.0.1:<port>/callback) redirect and the device
    # flow is a headless native grant. SEP-837 requires DCR to specify an
    # appropriate application_type (loopback/localhost -> "native"); the RFC 7591
    # default is "web", so omitting it lets an AS reject or mis-treat the loopback
    # redirect. Send "native" explicitly on both paths.
    if device_flow:
        body: dict[str, object] = {
            "client_name": "mcp-stdio",
            "application_type": "native",
            "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
            "token_endpoint_auth_method": auth_method,
        }
    else:
        body = {
            "client_name": "mcp-stdio",
            "application_type": "native",
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
    # Type-validate the AS-supplied credentials. A non-conformant
    # AS returning a non-string client_id / client_secret would otherwise be
    # str()-coerced into the authorize URL or raise an OPAQUE TypeError deep in
    # quote() during HTTP Basic auth. Convert it to an actionable RFC 7591 error
    # here, matching the missing-client_id guard above and the str validation
    # load_token / _parse_token_response already apply to AS-supplied values.
    client_secret = data.get("client_secret")
    if not isinstance(client_id, str):
        raise ValueError(
            "Client registration response client_id is not a string (RFC 7591 §3.2.1)."
        )
    if client_secret is not None and not isinstance(client_secret, str):
        raise ValueError(
            "Client registration response client_secret is not a string "
            "(RFC 7591 §3.2.1)."
        )
    # RFC 7591 §3.2.1: "The authorization server MAY reject or replace any of the
    # client's requested metadata values ... and substitute them with suitable
    # values", and MUST return all registered metadata about the client. So the
    # token_endpoint_auth_method the AS records in the registration RESPONSE is
    # authoritative and may differ from the one we requested (L812). Honour the
    # AS-assigned value when we implement it, so the subsequent token exchange
    # frames credentials the way the AS expects (Basic header vs request body)
    # instead of the way we asked — otherwise the exchange fails with an opaque
    # AS rejection.
    assigned_method = data.get("token_endpoint_auth_method")
    if isinstance(assigned_method, str) and assigned_method != auth_method:
        if assigned_method in _SUPPORTED_AUTH_METHODS:
            log(
                f"AS assigned token_endpoint_auth_method {assigned_method!r} "
                f"(requested {auth_method!r}); using the AS-assigned value per "
                f"RFC 7591 §3.2.1"
            )
            auth_method = assigned_method
        else:
            # The AS recorded a method we do not implement (e.g. private_key_jwt).
            # We cannot frame credentials that way, so keep our requested method
            # as the best-effort fallback but surface the mismatch — otherwise the
            # ensuing exchange failure looks like a generic auth error.
            log(
                f"warning: AS assigned unsupported token_endpoint_auth_method "
                f"{assigned_method!r} (requested {auth_method!r}); mcp-stdio "
                f"cannot honour it and the token exchange may fail"
            )
    return ClientRegistration(
        client_id=client_id,
        client_secret=client_secret,
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
    # token_urlsafe(64) is always 86 chars (64 bytes base64url, unpadded) = 512
    # bits of entropy, within the RFC 7636 §4.1 43-128 range and well above the
    # OAuth 2.1 256-bit floor. (: a former [:96] slice was a dead
    # no-op — 86 < 96 — and is dropped; nothing is truncated.)
    verifier = secrets.token_urlsafe(64)
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

            # Reject a Host header that is not the loopback callback:
            # DNS-rebinding defense-in-depth (RFC 8252 §8.x native-app guidance).
            # The server binds 127.0.0.1, so a legitimate browser redirect carries
            # ``Host: 127.0.0.1:<port>`` (or localhost). A hostile page that rebound
            # a hostname it controls to 127.0.0.1 to reach this callback would carry
            # that hostname in Host; refuse it. The captured code is single-use and
            # useless without the in-process PKCE verifier, so this only closes the
            # class at negligible cost. Parse via urlparse("//host") so an IPv6
            # ``[::1]:port`` / a portless Host / case are handled uniformly.
            host_header = self.headers.get("Host", "")
            try:
                host_only = urlparse(f"//{host_header}").hostname
            except ValueError:
                host_only = None
            if host_only not in ("127.0.0.1", "localhost", "::1"):
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
                # the callback URL carries the auth code/state, so
                # no-store keeps the browser from caching the response and
                # no-referrer keeps any (future) sub-resource from leaking the
                # URL via the Referer header. The page has no sub-resources
                # today, so this is defense-in-depth / standard callback hygiene.
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(
                    b"<h1>Already received</h1><p>You can close this tab.</p>"
                )
                return

            # Write ordering matters: the main loop gates on
            # ``cb_result.auth_code or cb_result.error`` and, the instant it
            # observes either, breaks out and reads ``cb_result.state`` for the
            # CSRF compare. CallbackResult is lock-free, so the CSRF-relevant
            # fields (state / iss) MUST be stored BEFORE the gating field —
            # otherwise a GIL switch between two separate attribute stores lets
            # the main thread observe auth_code set while state is still None and
            # spuriously fail the state compare (fails closed, but wrongly). Set
            # the gating field LAST in each branch.
            if "error" in params:
                # Capture state on the error branch too so the flow
                # can bind an error response to the CSRF state before acting on
                # it. RFC 6749 §4.1.2.1 requires a compliant AS to echo `state`
                # on error responses; an error callback WITHOUT the matching
                # state is an unauthenticated abort attempt, not a real AS error.
                result.state = params.get("state", [None])[0]
                result.error = params["error"][0]  # gating field — set LAST
            elif "code" in params:
                result.state = params.get("state", [None])[0]
                result.iss = params.get("iss", [None])[0]
                result.auth_code = params["code"][0]  # gating field — set LAST

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "no-store")  #
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()

            if result.error:
                msg = html.escape(result.error)
                body = f"<h1>Authorization failed</h1><p>{msg}</p>"
            elif result.auth_code is not None:
                body = "<h1>Authorization successful</h1><p>You can close this tab.</p>"
            else:
                # a bare /callback hit with neither code nor error
                # (a browser prefetch, a manual GET) captured nothing — the main
                # loop is still waiting. Don't render "successful": a misleading
                # success page could let an attacker convince a victim that a
                # stray request "worked". Show a neutral waiting page instead.
                body = (
                    "<h1>Waiting for authorization...</h1>"
                    "<p>No authorization response was received on this request.</p>"
                )
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
        raise RuntimeError(f"OAuth token error: {_sanitize_oauth_error(desc)}")


def _parse_token_response(resp: httpx.Response) -> dict[str, Any]:
    """Parse a token response, handling both JSON and form-urlencoded formats.

    GitHub OAuth (and some others) may return application/x-www-form-urlencoded.
    Some servers return HTTP 200 with an error in the body (GitHub legacy).
    """
    # RFC 6749 §5.2 — a token error is a 4xx carrying
    # ``{"error": ..., "error_description": ...}``. Surface that actionable
    # description BEFORE raise_for_status() collapses it into an opaque
    # ``HTTPStatusError`` (which omits the body), mirroring the 200-with-error
    # handling in _raise_for_body_error. Best-effort: an unparseable / error-less
    # 4xx body falls through to raise_for_status (an honest but generic HTTP
    # error). On the refresh path the resulting RuntimeError degrades to None
    # exactly as the HTTPStatusError did, so only the interactive auth-code
    # exchange gains the better message.
    if resp.status_code >= 400:
        body: dict[str, Any] | None = None
        try:
            if "application/x-www-form-urlencoded" in resp.headers.get(
                "content-type", ""
            ):
                _qs = dict(parse_qs(resp.text, keep_blank_values=True))
                body = {k: (v[0] if v else "") for k, v in _qs.items()}
            else:
                body = resp.json()
        except Exception:
            body = None
        if isinstance(body, dict) and "error" in body:
            desc = body.get("error_description", body["error"])
            raise RuntimeError(f"OAuth token error: {_sanitize_oauth_error(desc)}")

    resp.raise_for_status()

    content_type = resp.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type:
        parsed = dict(parse_qs(resp.text, keep_blank_values=True))
        # parse_qs returns lists; take the FIRST value for every key.
        # A non-conformant duplicate (e.g. access_token=a&access_token=b) must NOT
        # leave a LIST in result — that would flow into TokenData.access_token or
        # be str()-ed by _sanitize_oauth_error. No real provider emits duplicates;
        # fail closed to a string. (load_token's type check is the final backstop.)
        result = {k: (v[0] if v else "") for k, v in parsed.items()}
        _raise_for_body_error(result)
        return result

    # a 200 with any other content-type (text/plain, text/html, or
    # a missing content-type over a non-JSON body) would otherwise raise a raw
    # json.JSONDecodeError out of resp.json() — fine on the refresh path (caught,
    # degrades to None) but it propagates as an opaque error on the auth-code
    # path. Raise a clear RuntimeError naming the unexpected content-type instead,
    # matching the explicit-error style of the missing-access_token guard below.
    try:
        result = resp.json()
    except ValueError as exc:  # json.JSONDecodeError is a ValueError subclass
        ct = resp.headers.get("content-type", "<none>")
        raise RuntimeError(
            f"token endpoint returned a non-JSON, non-form-urlencoded body "
            f"(content-type {ct!r})"
        ) from exc
    # A 200 whose JSON body is not an OBJECT (a scalar / bool / null / array) is
    # non-compliant (RFC 6749 §5.1 mandates a JSON object). Surface a clear error
    # rather than the opaque TypeError that `_raise_for_body_error`'s
    # `"error" in result` would raise on a non-iterable — or the misleading
    # substring/list behaviour, or a later AttributeError on result.get.
    if not isinstance(result, dict):
        raise RuntimeError(
            f"token endpoint returned a non-object JSON body "
            f"({type(result).__name__})"
        )
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
    _warn_if_basic_auth_lacks_secret(auth_method, client_secret)
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
    _warn_if_basic_auth_lacks_secret(auth_method, client_secret)
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
    previous_id_token: str | None = None,
    client_secret_expires_at: float | None = None,
    auth_method: str = "none",
    no_resource_indicator: bool = False,
) -> TokenData:
    """Convert a raw token response to TokenData.

    If the response omits refresh_token (it is OPTIONAL per RFC 6749 §5.1;
    §6 only covers how an issued refresh_token is later used), the
    previous_refresh_token is preserved so subsequent refreshes work.
    Likewise ``scope`` is OPTIONAL in a token response (RFC 6749 §5.1: it
    may be omitted when identical to the requested scope, which refreshes
    routinely do), so ``previous_scope`` is preserved — otherwise a refresh
    would wipe the granted scope and a later step-up could not union it.
    The OIDC ``id_token`` is likewise commonly omitted on a refresh response,
    so ``previous_id_token`` is preserved for --oauth-use-id-token (#59).
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
            expires_in = float(raw["expires_in"])
        except (TypeError, ValueError):
            expires_in = None
        # a non-positive expires_in (0 or negative — malformed or
        # hostile) would make expires_at <= now, so ensure_token would treat the
        # FRESHLY obtained token as already expired and immediately re-refresh /
        # re-run the whole flow instead of using it once. Treat it as "no expiry
        # advertised" (expires_at = None) and warn, rather than burning the token.
        # also reject a NON-FINITE expires_in. json.loads parses the
        # non-standard literals Infinity / NaN by default, and `float("inf") > 0`
        # is True — so without isfinite a hostile/buggy AS sending
        # `"expires_in": Infinity` would set expires_at = now + inf = inf, and
        # ensure_token's `expires_at > now + leeway` would then ALWAYS be True,
        # pinning the token as eternally fresh and suppressing every future
        # refresh. Mirrors _safe_int's finiteness defence on the device-flow path
        # (which catches the OverflowError int(inf) raises) and token_store's
        # cached-expiry isfinite check.
        if expires_in is not None and math.isfinite(expires_in) and expires_in > 0:
            expires_at = time.time() + expires_in
        elif expires_in is not None:
            log(
                f"warning: ignoring non-finite/non-positive expires_in "
                f"({expires_in!r}); treating the token as having no advertised "
                f"expiry"
            )

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

    # OIDC id_token is a string JWT; tolerate a non-string / empty value (treat
    # as absent) and preserve the previous one when the response omits it, so a
    # refresh that does not re-issue the id_token keeps --oauth-use-id-token
    # working.
    _idt = raw.get("id_token")
    id_token = _idt if isinstance(_idt, str) and _idt else previous_id_token

    return TokenData(
        access_token=raw["access_token"],
        token_type=token_type,
        expires_at=expires_at,
        refresh_token=raw.get("refresh_token") or previous_refresh_token,
        id_token=id_token,
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
        # Persist the RFC 9207 §3 flag so a later step-up that reconstructs
        # metadata from this cached entry keeps the §2.4 missing-iss MUST-reject
        # active (otherwise it silently defaults off).
        iss_parameter_supported=metadata.iss_parameter_supported,
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
    # Defence-in-depth: the cached token_endpoint was validated at
    # persist time, but re-validate before re-POSTing credentials to it. The
    # store is 0o600, so this is not an exploitable path today — but it mirrors
    # the discovery-path validation so a tampered/legacy store cannot redirect
    # the refresh to a cleartext or userinfo-bearing URL. See #13.
    if not _validate_endpoint_url(cached.token_endpoint, label="cached token_endpoint"):
        return None
    auth_method = cached.token_endpoint_auth_method
    no_resource_indicator = cached.no_resource_indicator
    try:
        raw = refresh_access_token(
            cached.token_endpoint,
            cached.client_id,
            cached.client_secret,
            cached.refresh_token,
            client,
            resource=None if no_resource_indicator else _resource_indicator(server_url),
            auth_method=auth_method,
        )
    except Exception as e:
        # Sanitise the interpolated exception text: today's reachable exceptions
        # (httpx.HTTPStatusError, _raise_for_body_error's RuntimeError) carry no
        # token or raw AS body, but a future exception type embedding resp.text
        # would otherwise leak AS-controlled bytes into the log. Bound it
        # defensively so no exception type can write an unbounded/raw log line.
        log(f"token refresh failed: {_sanitize_oauth_error(e)}")
        return None
    metadata = OAuthMetadata(
        authorization_endpoint=cached.authorization_endpoint,
        token_endpoint=cached.token_endpoint,
        registration_endpoint=cached.registration_endpoint,
        # Carry the persisted issuer through so a refresh does not wipe it
        # (_token_response_to_data now writes metadata.issuer into TokenData).
        issuer=cached.issuer,
        # Carry the RFC 9207 §3 flag through too so a refresh round-trip does not
        # reset it to False in the re-persisted TokenData. Refresh
        # has no authorization callback, so it is not load-bearing here — but it
        # keeps the cached flag intact for the next step-up.
        iss_parameter_supported=cached.iss_parameter_supported,
    )
    try:
        data = _token_response_to_data(
            raw,
            metadata,
            cached.client_id,
            cached.client_secret,
            previous_refresh_token=cached.refresh_token,
            previous_scope=cached.scope,
            previous_id_token=cached.id_token,
            client_secret_expires_at=cached.client_secret_expires_at,
            auth_method=auth_method,
            no_resource_indicator=no_resource_indicator,
        )
    except Exception as e:
        # a non-compliant 200 token response MISSING access_token
        # (e.g. {"token_type":"Bearer"} with no `error`) slips past
        # _parse_token_response and makes _token_response_to_data raise. This
        # call was outside the try above, so the RuntimeError propagated out of
        # refresh_cached_token — violating its "returns None on failure" contract
        # and, worse, aborting ensure_token's recovery (it expects None to clear
        # the stale token and re-auth, but the RuntimeError reached cli.py and
        # exited 1). Degrade to None like every other refresh failure.
        log(f"token refresh failed: {_sanitize_oauth_error(e)}")
        return None
    save_token(server_url, data)
    log("token refreshed successfully")
    return data


def _resolve_cimd_client_id(
    client_metadata_url: str | None, metadata: OAuthMetadata
) -> str | None:
    """Resolve a Client ID Metadata Document URL into a client_id (#60).

    Shared by ``_run_authorization_flow`` and ``_run_device_authorization_flow``
    so the warn-and-use logic lives in one place. Returns ``client_metadata_url``
    unchanged (a CIMD client_id IS just a URL) when given, or ``None`` when not.
    An explicit ``--client-metadata-url`` always wins over cache/DCR — the same
    explicit-opt-in rule as ``client_id_override`` — so this never second-
    guesses the caller; it only warns when the AS metadata doesn't (yet)
    confirm support, so a parse miss or a misconfigured AS is still actionable.
    """
    if not client_metadata_url:
        return None
    if not metadata.client_id_metadata_document_supported:
        log(
            "warning: --client-metadata-url is set but the authorization "
            "server does not advertise client_id_metadata_document_supported "
            "(draft-ietf-oauth-client-id-metadata-document-00 §5); using it "
            "anyway"
        )
    log(f"using Client ID Metadata Document as client_id: {client_metadata_url}")
    return client_metadata_url


def _run_authorization_flow(
    server_url: str,
    client: httpx.Client,
    *,
    metadata: OAuthMetadata,
    cached: TokenData | None,
    client_id_override: str | None = None,
    client_metadata_url: str | None = None,
    scope: str | None = None,
    timeout: float = 120,
    resource_indicator: bool = True,
) -> TokenData:
    """Run the browser-based authorization code flow.

    Shared by both ``ensure_token`` (initial auth) and ``step_up_authorize``
    (RFC 9470 / MCP step-up for 403 insufficient_scope). Handles callback
    server setup, client_id resolution (pre-registered override, Client ID
    Metadata Document, or DCR — in that priority order, per the MCP
    "Client Registration Approaches" priority list), PKCE, browser launch,
    code exchange, and persistence.

    ``client_metadata_url`` (``--client-metadata-url``, #60) is an operator-
    hosted HTTPS URL to a Client ID Metadata Document
    (draft-ietf-oauth-client-id-metadata-document-00); when set it is an
    explicit opt-in and is used as ``client_id`` even if the AS metadata does
    not (yet) advertise ``client_id_metadata_document_supported`` — mirroring
    how an explicit ``client_id_override`` is never second-guessed.
    """
    cb_result = CallbackResult()
    handler_cls = _make_callback_handler(cb_result)

    # Bind 127.0.0.1 (NOT "" / "0.0.0.0"): the callback carries the auth code and
    # state, so only the LOCAL browser may reach /callback. This loopback-only
    # bind is the premise the single-shot + state-binding CSRF model rests on —
    # do not widen it. The ephemeral port (0) further narrows the attack window.
    callback_server = HTTPServer(("127.0.0.1", 0), handler_cls)
    # bound handle_request()'s block so the serve() daemon below
    # re-checks ``done`` between requests instead of parking forever in
    # select(None) after the single callback. Without this the thread stays
    # alive for the whole (long-lived) relay process — one leaked thread + a
    # half-closed selector per interactive auth / step-up. handle_timeout() is a
    # no-op, so a short timeout just loops back to the ``while not done`` guard.
    callback_server.timeout = 0.5
    port = callback_server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    cid = client_id_override or _resolve_cimd_client_id(client_metadata_url, metadata)
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

    # From here the callback server is listening. Any failure between now and
    # the close below (generate_pkce, webbrowser.open, thread.start, timeout)
    # must still close it, or the loopback listening socket leaks for the
    # process lifetime — so the whole window is guarded and closed on any exit.
    done = threading.Event()
    try:
        code_verifier, code_challenge = generate_pkce()

        # Authorization URL params; RFC 8707 resource indicator on by default
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
            params["resource"] = _resource_indicator(server_url)
        if scope:
            params["scope"] = scope

        auth_url = f"{metadata.authorization_endpoint}?{urlencode(params)}"
        # Log a STATE-REDACTED URL. The user still needs a clickable URL when the
        # browser does not auto-open, but the single-use CSRF ``state`` nonce
        # does not need to land in stderr — MCP host logs (Claude Desktop/Code)
        # persist to files that may be shared in bug reports. The browser
        # receives the full URL below; the PKCE secret (``code_verifier``) is
        # never in the URL and the S256 ``code_challenge`` is public, so only
        # ``state`` is worth redacting.
        log_url = (
            f"{metadata.authorization_endpoint}"
            f"?{urlencode({**params, 'state': '<redacted>'})}"
        )
        log(f"authorize URL (open in browser if not auto-opened):\n{log_url}")

        webbrowser.open(auth_url)

        def serve() -> None:
            while not done.is_set():
                callback_server.handle_request()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        deadline = time.monotonic() + timeout
        while not (cb_result.auth_code or cb_result.error):
            if time.monotonic() > deadline:
                raise TimeoutError(
                    "OAuth callback not received within timeout. "
                    "Please restart and try again."
                )
            time.sleep(0.2)
    finally:
        done.set()
        callback_server.server_close()

    # Validate state BEFORE acting on EITHER a code or an error.
    # Use a constant-time comparison so the rejection path does not leak the
    # common-prefix length of the two state tokens via timing. Over a loopback
    # callback the attack is theoretical, but every mainstream OAuth client does
    # this and the line carries a CSRF-facing comment — we want it to hold up to
    # scrutiny without caveats. See #26. Checking state FIRST also binds the
    # ERROR path: an unauthenticated local process (or a port-guessing page) that
    # hits /callback?error=... during the auth window to GRIEF the flow does not
    # carry the matching state, so it is rejected here as a CSRF mismatch instead
    # of aborting the flow with an attacker-chosen error. A compliant AS echoes
    # `state` on error responses (RFC 6749 §4.1.2.1), so a legitimate error still
    # passes this and surfaces just below.
    if not secrets.compare_digest(cb_result.state or "", state):
        raise RuntimeError("OAuth state mismatch — possible CSRF attack")

    if cb_result.error:
        raise RuntimeError(f"OAuth error: {_sanitize_oauth_error(cb_result.error)}")

    # RFC 9207 §2.4: if the authorization response carries an `iss` parameter,
    # the client MUST validate it against the issuer the metadata was fetched
    # from. This is the AS mix-up defence — it stops a code issued by AS-A from
    # being exchanged at AS-B. On the metadata path both values come from the
    # same AS (its metadata `issuer` and its callback `iss`) so they are
    # byte-identical and the comparison is exact. The trailing-slash tolerance
    # below is a no-op there, but matters on the PHASE-3 fallback
    # where `metadata.issuer` is a SYNTHESIZED guess (`as_base`, an origin with
    # no path/slash): a real AS whose issuer is `https://as/` would otherwise
    # false-mismatch and block a legitimate flow. A genuine mix-up always differs
    # by HOST, which rstrip does not mask, so the defence is preserved.
    #
    # Honest deviation note: RFC 9207 §2.4 specifies a SIMPLE
    # STRING comparison (RFC 3986 §6.2.1), i.e. byte-exact. The rstrip("/")
    # tolerance is a deliberate, security-preserving relaxation of that letter
    # (same spirit as the RFC 9728 §3.3 / RFC 8414 §3.3 warn-and-continue
    # relaxations) — it only collapses a trailing slash, never a host/scheme/port
    # difference, so no mix-up the strict comparison would catch slips through.
    #
    # §2.4 has a SECOND MUST: a client MUST reject a response that OMITS `iss`
    # from an AS that advertises iss support (the RFC 9207 §3 metadata flag) —
    # otherwise a mix-up attacker could simply strip `iss` to silence the compare
    # above. Enforce that when the AS advertised support. (When it did NOT
    # advertise, a missing `iss` is accepted: PKCE + state already cover the
    # common attacks, so this whole check is defence-in-depth.)
    if metadata.iss_parameter_supported and cb_result.iss is None:
        raise RuntimeError(
            "OAuth issuer missing (RFC 9207 §2.4) — the authorization server "
            "advertises iss support but its response omitted iss; possible AS "
            "mix-up attack"
        )
    if (
        cb_result.iss is not None
        and metadata.issuer
        and cb_result.iss.rstrip("/") != metadata.issuer.rstrip("/")
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
        resource=_resource_indicator(server_url) if resource_indicator else None,
        auth_method=auth_method,
    )
    data = _token_response_to_data(
        raw,
        metadata,
        cid,
        csecret,
        # RFC 6749 §5.1 makes refresh_token OPTIONAL in a token response, so a
        # step-up (which reuses this auth-code path for a full re-authorization)
        # against an AS that omits it would otherwise overwrite the cached
        # TokenData's still-valid refresh_token with None — breaking every future
        # silent refresh until the next interactive flow. Carry the cached token
        # through, mirroring the refresh path (refresh_cached_token). Harmless on
        # initial auth, where `cached` is None or carries no refresh_token.
        previous_refresh_token=cached.refresh_token if cached else None,
        # Preserve a cached id_token when the step-up/credential response omits
        # one, mirroring refresh_token, so --oauth-use-id-token survives a step-up.
        previous_id_token=cached.id_token if cached else None,
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
    client_metadata_url: str | None = None,
    scope: str | None = None,
    resource_indicator: bool = True,
    timeout: float | None = None,
) -> TokenData:
    """Run RFC 8628 Device Authorization Grant flow.

    Displays a ``verification_uri`` + ``user_code`` on stderr so the user can
    authorize on a separate device, then polls the token endpoint until the
    device code expires or the user grants access.

    ``timeout`` (when not ``None``) is the operator's ``--oauth-timeout`` and
    bounds how long this waits for the user to confirm the device code — the
    effective poll lifetime is ``min(timeout, server-advertised expires_in)``.
    A direct caller passing ``None`` keeps the full RFC 8628 server lifetime.

    ``client_metadata_url`` (#60) mirrors ``_run_authorization_flow``'s Client
    ID Metadata Document support — see that function's docstring.
    """
    if not metadata.device_authorization_endpoint:
        raise ValueError(
            "Server does not support Device Authorization Grant "
            "(no device_authorization_endpoint in metadata). "
            "Use --oauth for browser-based flow instead."
        )

    cid = client_id_override or _resolve_cimd_client_id(client_metadata_url, metadata)
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
                "Provide a --client-id or --client-metadata-url instead."
            )
    if cid is None:  # -O-safe invariant (every branch above sets cid)
        raise RuntimeError("no client_id available for device authorization")

    # Step 1: Device Authorization Request (RFC 8628 §3.1)
    da_params: dict[str, str] = {}
    if resource_indicator:
        da_params["resource"] = _resource_indicator(server_url)
    if scope:
        da_params["scope"] = scope
    da_headers: dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    # Covers both this device-authorization request and the token poll below:
    # both reuse this auth_method/csecret, so one warning here suffices.
    _warn_if_basic_auth_lacks_secret(auth_method, csecret)
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
    # A non-object device-authorization body would make da.get(...) below raise
    # AttributeError; surface a clear error instead.
    if not isinstance(da, dict):
        raise RuntimeError(
            f"device authorization endpoint returned a non-object JSON body "
            f"({type(da).__name__})"
        )

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
    # so the advertised --oauth-device flow works against Google. The URL is
    # presented to the user as an actionable "Open:" instruction, so
    # ``_validate_endpoint_url`` enforces the SCHEME guard (rejects non-http(s),
    # userinfo, and non-loopback cleartext) — a hostile AS cannot point the user
    # at a plaintext / parser-confusing URL. It is NOT origin-pinned to the
    # discovered AS: RFC 8628 verification URIs legitimately live on a separate
    # user-facing host (e.g. google.com/device vs oauth2.googleapis.com), so an
    # origin check would break compliant flows. The §3.3.1/§5.4 user_code
    # confirmation below is the anti-phishing / device-disambiguation mitigation.
    # See #13.
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
    # Honour the operator's --oauth-timeout as an UPPER bound on the human wait
    #. The CLI help promises --oauth-timeout covers "device-code
    # confirmation", but it was never plumbed here, so the device flow silently
    # ran on the server-advertised lifetime alone. Clamp the effective poll
    # lifetime to min(timeout, expires_in) so the documented contract holds; a
    # longer device window simply needs a larger --oauth-timeout. timeout=None
    # (a direct caller) keeps the full RFC 8628 lifetime. floor at 1 s so a tiny
    # timeout still allows the immediate first poll.
    effective_lifetime = expires_in
    if timeout is not None:
        effective_lifetime = max(1, min(expires_in, int(timeout)))
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
    # RFC 8628 §3.3.1: clients MUST STILL display the user_code even when a
    # verification_uri_complete (which embeds it) is used — the AS asks the user
    # to confirm the code matches, as a device-disambiguation / remote-phishing
    # mitigation (§5.4). So show it unconditionally, not only on the no-complete
    # branch.
    print(f"  Code (verify it matches): {user_code}", file=sys.stderr)
    print(
        f"\nWaiting for authorization (giving up in {effective_lifetime}s)...",
        file=sys.stderr,
    )

    # Step 2: Poll token endpoint (RFC 8628 §3.4 request / §3.5 response)
    # Sleep is at the end of each iteration so the first poll is immediate.
    deadline = time.monotonic() + effective_lifetime

    def _poll_sleep() -> None:
        # Never sleep past the deadline — a slow_down-inflated interval must not
        # overshoot the device-code expiry by a whole interval.
        time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))

    while time.monotonic() < deadline:
        # No RFC 8707 ``resource`` is sent on the poll, unlike exchange_code /
        # refresh_access_token. The Device Authorization Request already carried
        # it (see the device-authorization POST above), so the AS has bound the
        # audience to this ``device_code``; RFC 8707 §2.2 phrases the token-request
        # ``resource`` as optional ("the client CAN indicate ... by way of the
        # resource parameter") and lets the AS scope to the original grant — it
        # does not require resending it on the device_code exchange. The omission
        # is therefore intentional, mirroring the auth-method divergence below.
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
            # a registered client_secret is always sent as a body
            # credential here even when auth_method is "none" (the AS advertised
            # no token_endpoint_auth_methods_supported but DCR still issued a
            # secret). That is effectively client_secret_post and is the
            # more-likely-to-succeed choice — a confidential client that holds a
            # secret should present it — so the "none" label and the wire
            # behaviour diverge deliberately. Consistent with exchange_code /
            # refresh_access_token. A truly public client gets no csecret, so
            # this branch then sends client_id alone.
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
            # Sanitise like the refresh path: today's reachable
            # exception is an httpx transport error whose str() carries only the
            # operator-trusted token-endpoint URL (no AS body), but bounding it
            # keeps any future exception type that embeds resp.text from writing
            # raw AS-controlled bytes to the log.
            log(f"device flow poll error: {_sanitize_oauth_error(exc)}")
            _poll_sleep()
            continue

        if tok_resp.status_code == 200:
            raw = _parse_token_response(tok_resp)
            data = _token_response_to_data(
                raw,
                metadata,
                cid,
                csecret,
                # Preserve the requested scope when the AS omits it from the
                # token response (RFC 6749 §5.1) — mirrors the auth-code and
                # refresh paths so a device-flow token's scope is not wiped.
                previous_scope=scope,
                # Likewise keep a cached id_token when the device-flow response
                # omits one, so --oauth-use-id-token survives a device re-auth
                # (symmetric with the auth-code / refresh paths; #59).
                previous_id_token=cached.id_token if cached else None,
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
            # Non-JSON body. raise_for_status fails a 4xx/5xx; a non-compliant
            # 2xx-non-200 / 3xx (which raise_for_status would NOT catch, being
            # <400) would otherwise spin to the device-code deadline — fast-fail
            # it by name instead of wasting the code's whole lifetime.
            tok_resp.raise_for_status()
            raise RuntimeError(
                f"Device flow failed: unexpected non-JSON HTTP "
                f"{tok_resp.status_code} from the token endpoint"
            )

        if err == "authorization_pending":
            pass
        elif err == "slow_down":
            # RFC 8628 §3.5: increase interval by 5 seconds (capped)
            poll_interval = min(poll_interval + 5, _DEVICE_POLL_CAP_SECS)
        elif err in ("expired_token", "access_denied"):
            raise RuntimeError(f"Device flow failed: {err}")
        else:
            # An unknown error code, or a non-200 status with no recognized
            # error. FAST-FAIL with an actionable message — never spin to the
            # device-code deadline on a status retrying cannot resolve (RFC 8628
            # §3.5 mandates 200 or 400+error; a non-compliant 2xx-non-200 / 3xx
            # would otherwise no-op raise_for_status and loop).
            # Surface the AS error_description when present, mirroring the
            # _parse_token_response extraction the auth-code / refresh paths use.
            desc = ""
            try:
                body = tok_resp.json()
                if isinstance(body, dict):
                    desc = body.get("error_description") or body.get("error") or ""
            except Exception:
                pass
            if desc:
                raise RuntimeError(
                    f"Device flow failed: {_sanitize_oauth_error(desc)}"
                )
            tok_resp.raise_for_status()  # 4xx/5xx with no body → honest HTTP error
            raise RuntimeError(
                f"Device flow failed: unexpected HTTP {tok_resp.status_code} "
                f"from the token endpoint"
            )

        _poll_sleep()

    raise TimeoutError(
        "Device authorization timed out. Please restart and try again."
    )


def ensure_token(
    server_url: str,
    client: httpx.Client,
    *,
    client_id: str | None = None,
    client_metadata_url: str | None = None,
    scope: str | None = None,
    timeout: float = 120,
    device_flow: bool = False,
    refresh_leeway: float = 60.0,
    resource_indicator: bool = True,
    interactive: bool = True,
) -> TokenData | None:
    """Ensure a valid access token is available.

    1. Check cached token — use if not expired (with ``refresh_leeway`` margin)
    2. If expired, try refresh
    3. If no token or refresh fails, run OAuth flow:
       - ``device_flow=True``: Device Authorization Grant (RFC 8628)
       - ``device_flow=False``: Authorization Code flow with PKCE (default)

    ``client_metadata_url`` (``--client-metadata-url``, #60) is used as the
    OAuth ``client_id`` (a Client ID Metadata Document URL) when no
    ``client_id`` override applies — see ``_run_authorization_flow`` /
    ``_run_device_authorization_flow`` for the full priority order.

    When ``interactive=False``, step 3 is skipped: if no cached/refreshable
    token is available the function returns ``None`` instead of opening a
    browser / device-code flow. The ``--oauth-eager`` cold-start uses this to
    decide, without blocking, whether the warm path applies (token available)
    or the cold path (run OAuth on a background thread). With the default
    ``interactive=True`` the function always returns a TokenData or raises.

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

    if not interactive:
        # Non-interactive probe (--oauth-eager warm check): no cached/refreshable
        # token, and the caller does not want to block on a browser/device flow.
        return None

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
            client_metadata_url=client_metadata_url,
            scope=scope,
            resource_indicator=resource_indicator,
            # honour --oauth-timeout for the device-code wait too,
            # matching the auth-code branch below and the CLI help text.
            timeout=timeout,
        )
    return _run_authorization_flow(
        server_url,
        client,
        metadata=metadata,
        cached=cached,
        client_id_override=client_id,
        client_metadata_url=client_metadata_url,
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

    # Defence-in-depth: re-validate the cached endpoints before
    # reusing them for the full browser+callback flow + token exchange. They were
    # validated at persist time and the store is 0o600 (not an exploitable path
    # today), but a tampered/legacy store must not redirect this credential-
    # bearing flow to a cleartext or userinfo-bearing URL. On failure both come
    # back falsy and we fall through to fresh discovery below. See #13.
    cached_authz_ep = (
        _validate_endpoint_url(
            cached.authorization_endpoint, label="cached authorization_endpoint"
        )
        if cached
        else None
    )
    cached_token_ep = (
        _validate_endpoint_url(cached.token_endpoint, label="cached token_endpoint")
        if cached
        else None
    )
    if cached and cached_token_ep and cached_authz_ep:
        metadata = OAuthMetadata(
            authorization_endpoint=cached_authz_ep,
            token_endpoint=cached_token_ep,
            registration_endpoint=_validate_endpoint_url(
                cached.registration_endpoint, label="cached registration_endpoint"
            ),
            # Rehydrate the persisted issuer AND the RFC 9207 §3 iss-support flag
            # so BOTH halves of the §2.4 mix-up defence stay active on this
            # cache-hit path — step-up runs a full browser+callback flow, the case
            # most exposed to AS mix-up. Without the flag the missing-iss
            # MUST-reject would silently no-op precisely here; the
            # iss MISMATCH check needs only the rehydrated issuer.
            issuer=cached.issuer,
            iss_parameter_supported=cached.iss_parameter_supported,
        )
    else:
        # Mirror ensure_token's discovery (the _probe_www_authenticate call
        # above): probe the server's WWW-Authenticate for an RFC 9728
        # resource_metadata hint FIRST, so a server publishing its PRM at a
        # non-standard URL is discoverable on this step-up re-discovery path too,
        # not only on initial auth. Every endpoint is still re-validated by the
        # discovery validators, so no credential can be routed to an unsafe host.
        #
        www_authenticate = _probe_www_authenticate(server_url, client)
        metadata = discover_oauth_metadata(
            server_url, client, www_authenticate=www_authenticate
        )

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
