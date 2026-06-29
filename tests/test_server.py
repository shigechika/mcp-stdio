"""Tests for the reverse gateway (``mcp-stdio serve``) — server.py."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from mcp_stdio import oauth as client_oauth
from mcp_stdio import server

_BACKEND = [sys.executable, os.path.join(os.path.dirname(__file__), "_fake_backend.py")]


@pytest.fixture()
def gateway():
    """Start the gateway on an ephemeral port; yield its base MCP URL."""
    httpd, registry = server.build_server(_BACKEND, host="127.0.0.1", port=0)
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{port}/mcp"
    try:
        yield url, registry
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.server_close()


def _post(url: str, msg: dict, sid: str | None = None) -> httpx.Response:
    headers = {"Mcp-Session-Id": sid} if sid else {}
    return httpx.post(url, content=json.dumps(msg), headers=headers, timeout=10)


def _init(url: str, headers: dict | None = None) -> tuple[str | None, httpx.Response]:
    """POST ``initialize`` to open a session; return (session_id, response)."""
    resp = httpx.post(
        url,
        content=json.dumps({"jsonrpc": "2.0", "id": "init", "method": "initialize"}),
        headers=headers or {},
        timeout=10,
    )
    return resp.headers.get("mcp-session-id"), resp


def test_request_response(gateway):
    url, _ = gateway
    sid, _ = _init(url)
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"a": 1}}, sid)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    body = resp.json()
    assert body["id"] == 1
    assert body["result"]["echoed"] == {"a": 1}


def test_initialize_returns_protocol_version(gateway):
    url, _ = gateway
    _, resp = _init(url)
    assert resp.status_code == 200
    assert resp.json()["result"]["protocolVersion"] == "2025-06-18"


def test_initialize_assigns_session(gateway):
    url, registry = gateway
    sid, resp = _init(url)
    assert resp.status_code == 200
    assert sid  # the gateway minted an Mcp-Session-Id
    assert registry.count == 1


def test_session_id_per_initialize(gateway):
    # Each initialize starts a NEW session with its own id (was a constant id
    # under the old single-backend model).
    url, registry = gateway
    sid1, _ = _init(url)
    sid2, _ = _init(url)
    assert sid1 and sid2 and sid1 != sid2
    assert registry.count == 2


def test_two_initializes_distinct_children(gateway):
    # Two sessions -> two distinct child processes (process-boundary isolation).
    url, _ = gateway
    sid1, _ = _init(url)
    sid2, _ = _init(url)
    p1 = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, sid1).json()["result"]["pid"]
    p2 = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, sid2).json()["result"]["pid"]
    assert p1 != p2


def test_no_cross_session_id_leak(gateway):
    # Two sessions both use JSON-RPC id=1; each must get ITS OWN child's
    # response, never the other's (the single-backend model could cross them).
    url, _ = gateway
    sid_a, _ = _init(url)
    sid_b, _ = _init(url)
    ra = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"who": "A"}}, sid_a).json()
    rb = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"who": "B"}}, sid_b).json()
    assert ra["result"]["echoed"] == {"who": "A"}
    assert rb["result"]["echoed"] == {"who": "B"}
    assert ra["result"]["pid"] != rb["result"]["pid"]


def test_notification_returns_202(gateway):
    url, _ = gateway
    sid, _ = _init(url)
    resp = _post(url, {"jsonrpc": "2.0", "method": "somenotify"}, sid)
    assert resp.status_code == 202


def test_client_response_returns_202(gateway):
    # A client answering a server-initiated request is a JSON-RPC response
    # (id + result, no method): the gateway forwards it one-way -> 202.
    url, _ = gateway
    sid, _ = _init(url)
    resp = _post(url, {"jsonrpc": "2.0", "id": 99, "result": {"ok": True}}, sid)
    assert resp.status_code == 202


def test_sessionless_non_init_returns_400(gateway):
    # MCP spec: a non-initialize request without an Mcp-Session-Id -> 400.
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"})
    assert resp.status_code == 400


def test_unknown_session_returns_404(gateway):
    # MCP spec: an unknown/terminated session id -> 404 (drives re-initialize).
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, "deadbeef" * 4)
    assert resp.status_code == 404


def test_batch_is_rejected(gateway):
    url, _ = gateway
    resp = httpx.post(url, content=json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "echo"}]), timeout=10)
    assert resp.status_code == 400


def test_invalid_json_returns_400(gateway):
    url, _ = gateway
    resp = httpx.post(url, content="{not json", timeout=10)
    assert resp.status_code == 400


def test_non_scalar_id_returns_400(gateway):
    # A non-scalar (unhashable) JSON-RPC id must not reach the pending-response
    # dict key (TypeError -> handler crash); the gateway rejects it as 400.
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": [1, 2], "method": "echo"})
    assert resp.status_code == 400


def test_wrong_path_returns_404(gateway):
    url, _ = gateway
    base = url.rsplit("/mcp", 1)[0]
    resp = httpx.post(base + "/nope", content="{}", timeout=10)
    assert resp.status_code == 404


def test_backend_timeout_returns_504(gateway, monkeypatch):
    url, _ = gateway
    monkeypatch.setattr(server, "_BACKEND_RESPONSE_TIMEOUT_SECS", 0.4)
    sid, _ = _init(url)
    resp = _post(url, {"jsonrpc": "2.0", "id": 7, "method": "noreply"}, sid)
    assert resp.status_code == 504
    assert resp.json()["id"] == 7
    assert resp.json()["error"]["code"] == -32000


def test_get_sse_delivers_server_initiated(gateway):
    url, _ = gateway
    sid, _ = _init(url)
    received: list[str] = []
    ready = threading.Event()

    def reader():
        with httpx.stream(
            "GET", url, headers={"Mcp-Session-Id": sid}, timeout=10
        ) as r:
            ready.set()
            for line in r.iter_lines():
                if line.startswith("data: "):
                    received.append(line[len("data: ") :])
                    return

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    ready.wait(5)
    time.sleep(0.2)  # let the GET stream attach before we trigger a push
    _post(url, {"jsonrpc": "2.0", "method": "trigger_push"}, sid)
    t.join(5)
    assert received, "no SSE message received"
    msg = json.loads(received[0])
    assert msg["method"] == "notifications/message"
    assert msg["params"] == {"hello": "world"}


def test_get_sse_unknown_session_returns_404(gateway):
    url, _ = gateway
    resp = httpx.get(url, headers={"Mcp-Session-Id": "nope" * 8}, timeout=10)
    assert resp.status_code == 404


def test_get_sse_without_session_returns_400(gateway):
    # MCP spec item 2: a sessionless GET (like a sessionless POST) -> 400.
    url, _ = gateway
    resp = httpx.get(url, timeout=10)
    assert resp.status_code == 400


def test_delete_reaps_session(gateway):
    url, registry = gateway
    sid, _ = _init(url)
    assert registry.count == 1
    resp = httpx.request("DELETE", url, headers={"Mcp-Session-Id": sid}, timeout=10)
    assert resp.status_code == 200
    assert registry.count == 0
    # The terminated session id is now unknown -> 404.
    again = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, sid)
    assert again.status_code == 404


def test_delete_without_session_id_returns_400(gateway):
    url, _ = gateway
    resp = httpx.request("DELETE", url, timeout=10)
    assert resp.status_code == 400


def test_delete_unknown_session_returns_404(gateway):
    url, _ = gateway
    resp = httpx.request("DELETE", url, headers={"Mcp-Session-Id": "x" * 32}, timeout=10)
    assert resp.status_code == 404


def test_backend_death_then_request_fails(gateway):
    url, registry = gateway
    sid, _ = _init(url)
    backend = registry.get(sid)
    # Tell the backend to exit, then give the reader thread a moment to notice.
    _post(url, {"jsonrpc": "2.0", "method": "exit"}, sid)
    deadline = time.time() + 5
    while not backend.closed and time.time() < deadline:
        time.sleep(0.05)
    assert backend.closed
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, sid)
    assert resp.status_code == 503
    assert resp.json()["id"] == 1
    # The dead session is reaped, so the slot is reclaimed and the next request
    # on that id gets 404 (the client then re-initializes) rather than 503.
    assert registry.count == 0
    again = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "echo"}, sid)
    assert again.status_code == 404


def test_registry_cap_rejects_beyond_max():
    # Unit-level: the registry returns None past the concurrent-session cap.
    reg = server.SessionRegistry(_BACKEND, max_sessions=2)
    try:
        assert reg.create() is not None
        assert reg.create() is not None
        assert reg.create() is None  # cap reached
        assert reg.count == 2
    finally:
        reg.shutdown_all()
    assert reg.count == 0


def test_session_cap_returns_503():
    # HTTP-level: an initialize past the cap gets 503.
    httpd, registry = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, max_sessions=1
    )
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{port}/mcp"
    try:
        sid1, r1 = _init(url)
        assert r1.status_code == 200 and sid1
        _, r2 = _init(url)
        assert r2.status_code == 503
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.server_close()


# --- unit-level checks that don't need the HTTP server ---


def test_classify():
    assert server._classify({"method": "m", "id": 1}) == "request"
    assert server._classify({"method": "m"}) == "notification"
    assert server._classify({"id": 1, "result": {}}) == "response"
    assert server._classify({"id": 1, "error": {}}) == "response"
    assert server._classify({"id": 1}) == "invalid"
    assert server._classify([1, 2]) == "invalid"
    assert server._classify("x") == "invalid"


def test_serve_main_requires_command():
    with pytest.raises(SystemExit):
        server.serve_main(["--port", "9"])  # no backend command


def test_serve_main_rejects_bad_path():
    with pytest.raises(SystemExit):
        server.serve_main(["--path", "mcp", "--", "true"])  # path missing leading /


# --- static-bearer-token Resource Server + RFC 9728 metadata ---

_TOKEN = "s3cr3t-token"


@pytest.fixture()
def auth_gateway():
    """A gateway protected by a static bearer token."""
    httpd, registry = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, auth_token=_TOKEN
    )
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{port}/mcp"
    try:
        yield url, registry
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.server_close()


def _base(url: str) -> str:
    return url.rsplit("/mcp", 1)[0]


def test_auth_missing_token_returns_401_with_metadata_hint(auth_gateway):
    url, _ = auth_gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"})
    assert resp.status_code == 401
    wa = resp.headers.get("www-authenticate", "")
    assert wa.startswith("Bearer ")
    assert "resource_metadata=" in wa
    assert "/.well-known/oauth-protected-resource/mcp" in wa


def test_auth_wrong_token_returns_401(auth_gateway):
    url, _ = auth_gateway
    resp = httpx.post(
        url,
        content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "echo"}),
        headers={"Authorization": "Bearer nope"},
        timeout=10,
    )
    assert resp.status_code == 401


def test_auth_valid_token_returns_200(auth_gateway):
    url, _ = auth_gateway
    auth = {"Authorization": f"Bearer {_TOKEN}"}
    sid, _ = _init(url, headers=auth)
    resp = httpx.post(
        url,
        content=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"a": 1}}
        ),
        headers={**auth, "Mcp-Session-Id": sid},
        timeout=10,
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["echoed"] == {"a": 1}


def test_get_sse_requires_auth(auth_gateway):
    url, _ = auth_gateway
    resp = httpx.get(url, timeout=10)  # no token on the MCP path
    assert resp.status_code == 401


def test_prm_served_without_token(auth_gateway):
    url, _ = auth_gateway
    base = _base(url)
    # Path-specific form (RFC 9728 Sec. 3.1).
    resp = httpx.get(base + "/.well-known/oauth-protected-resource/mcp", timeout=10)
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"].endswith("/mcp")
    assert body["bearer_methods_supported"] == ["header"]
    assert "authorization_servers" not in body  # none without the embedded AS
    # Bare form is also served.
    resp2 = httpx.get(base + "/.well-known/oauth-protected-resource", timeout=10)
    assert resp2.status_code == 200


def test_prm_404_when_auth_disabled(gateway):
    url, _ = gateway
    resp = httpx.get(_base(url) + "/.well-known/oauth-protected-resource/mcp", timeout=10)
    assert resp.status_code == 404


def test_prm_prefix_overmatch_not_served(auth_gateway):
    # A path that merely shares the well-known prefix (".../-resource-evil")
    # must NOT be treated as the metadata endpoint.
    url, _ = auth_gateway
    resp = httpx.get(_base(url) + "/.well-known/oauth-protected-resource-evil", timeout=10)
    assert resp.status_code == 404
    assert "bearer_methods_supported" not in resp.text


def test_serve_main_rejects_path_with_quote():
    with pytest.raises(SystemExit):
        server.serve_main(["--path", '/m"cp', "--", "true"])


def test_prm_honors_forwarded_headers(auth_gateway):
    url, _ = auth_gateway
    resp = httpx.get(
        _base(url) + "/.well-known/oauth-protected-resource/mcp",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "gw.example.org"},
        timeout=10,
    )
    assert resp.json()["resource"] == "https://gw.example.org/mcp"


def test_no_auth_fixture_still_open(gateway):
    # The default fixture has no token: a request without Authorization is 200.
    url, _ = gateway
    _, resp = _init(url)
    assert resp.status_code == 200


def test_sanitize_host():
    assert server._sanitize_host("gw.example.org:8443") == "gw.example.org:8443"
    # quote / CR / LF / space are stripped (header-injection guard)
    assert server._sanitize_host('evil"\r\n host') == "evilhost"


def test_authorized_constant_time_paths():
    # Build a handler instance is heavy; exercise the token compare via a
    # lightweight stand-in object carrying the attributes _authorized reads.
    class Fake:
        auth_token = "tok"
        oauth = None
        def __init__(self, hdr):
            self.headers = {"Authorization": hdr}
    Fake._authorized = server._Handler._authorized
    assert Fake("Bearer tok")._authorized() is True
    assert Fake("Bearer no")._authorized() is False
    assert Fake("")._authorized() is False
    Fake.auth_token = None
    assert Fake("")._authorized() is True


# --- embedded OAuth 2.1 Authorization Server ---

_REDIRECT = "http://127.0.0.1:5555/callback"


@contextlib.contextmanager
def _run(*, auth_token=None, oauth=None):
    """Start a gateway with the given auth config; yield (base_url, registry)."""
    httpd, registry = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, auth_token=auth_token, oauth=oauth
    )
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://{host}:{port}", registry
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.server_close()


def _provider(**kw):
    kw.setdefault("public_url", None)
    kw.setdefault("trusted_user_header", None)
    kw.setdefault("dev_user", "alice")
    return server._OAuthProvider(**kw)


@pytest.fixture()
def oauth_gateway():
    """A gateway with the embedded AS enabled and --dev-user=alice."""
    with _run(oauth=_provider()) as (base, registry):
        yield base, registry


def _register(base, redirect=_REDIRECT):
    return httpx.post(
        base + "/register",
        json={
            "client_name": "test",
            "redirect_uris": [redirect],
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
        },
        timeout=10,
    )


def _authorize(base, client_id, challenge, *, redirect=_REDIRECT, state="st-123",
               method="S256", response_type="code", headers=None, drop=None):
    params = {
        "client_id": client_id,
        "response_type": response_type,
        "redirect_uri": redirect,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": method,
        "resource": base + "/mcp",
    }
    for k in (drop or []):
        params.pop(k, None)
    return httpx.get(base + "/authorize", params=params, headers=headers or {},
                     follow_redirects=False, timeout=10)


def _redirect_params(resp):
    return {k: v[0] for k, v in parse_qs(urlsplit(resp.headers["location"]).query).items()}


def _token(base, data):
    return httpx.post(base + "/token", data=data, timeout=10)


def _authed_mcp(base, token, mid=1):
    """An authenticated MCP call with the given bearer token.

    Uses ``initialize`` so a valid token gets 200 (and opens a session) while
    an invalid one is rejected by the auth gate (401) before session creation —
    exactly the status distinction these tests assert.
    """
    return httpx.post(
        base + "/mcp",
        content=json.dumps({"jsonrpc": "2.0", "id": mid, "method": "initialize"}),
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )


def _full_flow(base, redirect=_REDIRECT, headers=None):
    cid = _register(base, redirect).json()["client_id"]
    verifier, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge, redirect=redirect, headers=headers)
    assert az.status_code == 302, az.text
    code = _redirect_params(az)["code"]
    tok = _token(base, {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": redirect, "client_id": cid, "code_verifier": verifier,
    })
    return cid, verifier, challenge, code, tok


# -- metadata / registration --

def test_pkce_s256_matches_client():
    # The server transform MUST equal what the client's generate_pkce produced.
    verifier, challenge = client_oauth.generate_pkce()
    assert server._pkce_s256_challenge(verifier) == challenge


def test_as_metadata(oauth_gateway):
    base, _ = oauth_gateway
    md = httpx.get(base + "/.well-known/oauth-authorization-server", timeout=10).json()
    assert md["issuer"].startswith("http://127.0.0.1:")
    assert md["authorization_endpoint"] == md["issuer"] + "/authorize"
    assert md["token_endpoint"] == md["issuer"] + "/token"
    assert md["registration_endpoint"] == md["issuer"] + "/register"
    assert md["response_types_supported"] == ["code"]
    assert md["code_challenge_methods_supported"] == ["S256"]
    assert md["token_endpoint_auth_methods_supported"] == ["none"]


def test_prm_has_authorization_servers_when_oauth(oauth_gateway):
    base, _ = oauth_gateway
    prm = httpx.get(base + "/.well-known/oauth-protected-resource/mcp", timeout=10).json()
    assert prm["authorization_servers"] == [prm["resource"].rsplit("/mcp", 1)[0]]


def test_as_metadata_no_iss_flag_for_http_issuer(oauth_gateway):
    """RFC 9207 Sec. 2 requires an https iss; a loopback http issuer must NOT
    advertise iss support (it also never emits iss — see authorize tests)."""
    base, _ = oauth_gateway
    md = httpx.get(base + "/.well-known/oauth-authorization-server", timeout=10).json()
    assert "authorization_response_iss_parameter_supported" not in md


def test_https_issuer_advertises_and_emits_iss():
    """RFC 9207: an https issuer advertises iss support AND echoes iss on the
    authorization redirect (success path), so a multi-AS client can detect
    a mix-up attack."""
    issuer = "https://gw.example.org"
    with _run(oauth=_provider(public_url=issuer)) as (base, _):
        md = httpx.get(
            base + "/.well-known/oauth-authorization-server", timeout=10
        ).json()
        assert md["authorization_response_iss_parameter_supported"] is True
        cid = _register(base).json()["client_id"]
        _, challenge = client_oauth.generate_pkce()
        az = _authorize(base, cid, challenge)
        assert az.status_code == 302, az.text
        params = _redirect_params(az)
        assert params["iss"] == issuer
        assert "code" in params  # success response still carries the code


def test_https_issuer_emits_iss_on_error_redirect():
    """RFC 9207 Sec. 2: iss appears on error authorization responses too."""
    issuer = "https://gw.example.org"
    with _run(oauth=_provider(public_url=issuer)) as (base, _):
        cid = _register(base).json()["client_id"]
        _, challenge = client_oauth.generate_pkce()
        az = _authorize(base, cid, challenge, response_type="token")
        assert az.status_code == 302, az.text
        params = _redirect_params(az)
        assert params["error"] == "unsupported_response_type"
        assert params["iss"] == issuer


def test_register_response_is_no_store(oauth_gateway):
    """RFC 7591 Sec. 3.2.1: the registration response carries no-store."""
    base, _ = oauth_gateway
    r = _register(base)
    assert r.status_code == 201
    assert "no-store" in r.headers.get("cache-control", "")


def test_register_public_client(oauth_gateway):
    base, _ = oauth_gateway
    r = _register(base)
    assert r.status_code == 201
    body = r.json()
    assert isinstance(body["client_id"], str) and body["client_id"]
    assert "client_secret" not in body
    assert body["token_endpoint_auth_method"] == "none"


def test_register_rejects_non_loopback(oauth_gateway):
    base, _ = oauth_gateway
    r = _register(base, redirect="https://evil.example.com/callback")
    assert r.status_code == 400
    # RFC 7591 Sec. 3.2.2: an invalid redirect URI uses the dedicated error code.
    assert r.json()["error"] == "invalid_redirect_uri"


def test_register_missing_redirect_uris_is_client_metadata_error(oauth_gateway):
    """RFC 7591 Sec. 3.2.2: a missing/empty redirect_uris is a STRUCTURAL
    metadata error (invalid_client_metadata), not invalid_redirect_uri."""
    base, _ = oauth_gateway
    r = httpx.post(base + "/register", json={"client_name": "x"}, timeout=10)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_client_metadata"
    r2 = httpx.post(base + "/register", json={"redirect_uris": []}, timeout=10)
    assert r2.status_code == 400
    assert r2.json()["error"] == "invalid_client_metadata"


def test_register_rejects_non_json(oauth_gateway):
    base, _ = oauth_gateway
    r = httpx.post(base + "/register", content="not json", timeout=10)
    assert r.status_code == 400


# -- full flow + RS --

def test_full_auth_code_flow_and_use_token(oauth_gateway):
    base, _ = oauth_gateway
    cid, verifier, challenge, code, tok = _full_flow(base)
    assert tok.status_code == 200, tok.text
    body = tok.json()
    assert body["token_type"] == "Bearer"
    assert isinstance(body["access_token"], str) and body["access_token"]
    assert body["expires_in"] > 0
    assert body["refresh_token"]
    assert tok.headers.get("cache-control") == "no-store"
    # use the issued token on an MCP request
    auth = {"Authorization": f"Bearer {body['access_token']}"}
    sid, _ = _init(base + "/mcp", headers=auth)
    r = httpx.post(base + "/mcp",
                   content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"x": 1}}),
                   headers={**auth, "Mcp-Session-Id": sid}, timeout=10)
    assert r.status_code == 200
    assert r.json()["result"]["echoed"] == {"x": 1}
    # without the token -> 401
    r2 = httpx.post(base + "/mcp",
                    content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "echo"}), timeout=10)
    assert r2.status_code == 401


def test_redirect_uri_port_agnostic(oauth_gateway):
    # RFC 8252: registered :5555, authorize with :6666 (same scheme/host/path) ok.
    base, _ = oauth_gateway
    cid = _register(base, "http://127.0.0.1:5555/callback").json()["client_id"]
    verifier, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge, redirect="http://127.0.0.1:6666/callback")
    assert az.status_code == 302


# -- authorize negatives --

def test_authorize_unknown_client_400_no_redirect(oauth_gateway):
    base, _ = oauth_gateway
    _, challenge = client_oauth.generate_pkce()
    az = _authorize(base, "nope", challenge)
    assert az.status_code == 400  # NOT a redirect (RFC 6749 4.1.2.1)


def test_authorize_bad_redirect_uri_400(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    _, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge, redirect="http://127.0.0.1:5555/evil")
    assert az.status_code == 400


def test_authorize_missing_code_challenge_redirects_error(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    az = _authorize(base, cid, "x", drop=["code_challenge"])
    assert az.status_code == 302
    p = _redirect_params(az)
    assert p["error"] == "invalid_request"
    assert p["state"] == "st-123"  # state echoed on error


def test_authorize_plain_method_rejected(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    _, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge, method="plain")
    assert az.status_code == 302
    assert _redirect_params(az)["error"] == "invalid_request"


def test_authorize_unsupported_response_type(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    _, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge, response_type="token")
    assert az.status_code == 302
    assert _redirect_params(az)["error"] == "unsupported_response_type"


def test_authorize_fail_closed_without_user():
    # No dev_user, no trusted header: a client-set X-Forwarded-User must NOT
    # authenticate -> access_denied (never mint a code for a spoofed user).
    with _run(oauth=_provider(dev_user=None)) as (base, _):
        cid = _register(base).json()["client_id"]
        _, challenge = client_oauth.generate_pkce()
        az = _authorize(base, cid, challenge, headers={"X-Forwarded-User": "attacker"})
        assert az.status_code == 302
        assert _redirect_params(az)["error"] == "access_denied"


def test_trusted_header_used_when_configured():
    with _run(oauth=_provider(dev_user=None, trusted_user_header="X-Forwarded-User")) as (base, _):
        cid = _register(base).json()["client_id"]
        _, challenge = client_oauth.generate_pkce()
        az = _authorize(base, cid, challenge, headers={"X-Forwarded-User": "bob"})
        assert az.status_code == 302
        assert "code" in _redirect_params(az)


# -- token negatives --

def test_token_pkce_mismatch_invalid_grant(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    _, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge)
    code = _redirect_params(az)["code"]
    bad_verifier = "B" * 64
    r = _token(base, {"grant_type": "authorization_code", "code": code,
                      "redirect_uri": _REDIRECT, "client_id": cid, "code_verifier": bad_verifier})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_token_code_replay_invalid_grant(oauth_gateway):
    base, _ = oauth_gateway
    cid, verifier, challenge, code, tok = _full_flow(base)
    assert tok.status_code == 200
    # replay the same code
    r = _token(base, {"grant_type": "authorization_code", "code": code,
                      "redirect_uri": _REDIRECT, "client_id": cid, "code_verifier": verifier})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_token_redirect_uri_mismatch(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    verifier, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge)
    code = _redirect_params(az)["code"]
    r = _token(base, {"grant_type": "authorization_code", "code": code,
                      "redirect_uri": "http://127.0.0.1:9999/callback", "client_id": cid,
                      "code_verifier": verifier})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_token_unsupported_grant(oauth_gateway):
    base, _ = oauth_gateway
    r = _token(base, {"grant_type": "password", "username": "x"})
    assert r.status_code == 400
    assert r.json()["error"] == "unsupported_grant_type"


def test_token_missing_grant(oauth_gateway):
    base, _ = oauth_gateway
    r = _token(base, {"foo": "bar"})
    assert r.status_code == 400


def test_refresh_rotates(oauth_gateway):
    base, _ = oauth_gateway
    cid, verifier, challenge, code, tok = _full_flow(base)
    rt = tok.json()["refresh_token"]
    r = _token(base, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid})
    assert r.status_code == 200
    assert r.json()["access_token"]
    new_rt = r.json()["refresh_token"]
    assert new_rt and new_rt != rt
    # old refresh token is invalidated (rotation)
    again = _token(base, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid})
    assert again.status_code == 400


def test_concurrent_token_single_use(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    verifier, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge)
    code = _redirect_params(az)["code"]
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": _REDIRECT,
            "client_id": cid, "code_verifier": verifier}
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: _token(base, data).status_code, range(8)))
    assert results.count(200) == 1
    assert results.count(400) == 7


def test_issued_token_expires():
    clock = [1000.0]
    prov = _provider(access_ttl=30, now=lambda: clock[0])
    with _run(oauth=prov) as (base, _):
        _, _, _, _, tok = _full_flow(base)
        at = tok.json()["access_token"]
        ok = httpx.post(base + "/mcp",
                        content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
                        headers={"Authorization": f"Bearer {at}"}, timeout=10)
        assert ok.status_code == 200
        clock[0] += 100  # advance past TTL
        expired = httpx.post(base + "/mcp",
                             content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "echo"}),
                             headers={"Authorization": f"Bearer {at}"}, timeout=10)
        assert expired.status_code == 401


# -- coexistence / disabled --

def test_coexistence_static_and_oauth():
    with _run(auth_token="static-tok", oauth=_provider()) as (base, _):
        # static token authorizes
        r1 = httpx.post(base + "/mcp",
                        content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
                        headers={"Authorization": "Bearer static-tok"}, timeout=10)
        assert r1.status_code == 200
        # issued token authorizes
        _, _, _, _, tok = _full_flow(base)
        at = tok.json()["access_token"]
        r2 = httpx.post(base + "/mcp",
                        content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "initialize"}),
                        headers={"Authorization": f"Bearer {at}"}, timeout=10)
        assert r2.status_code == 200
        # PRM advertises authorization_servers
        prm = httpx.get(base + "/.well-known/oauth-protected-resource/mcp", timeout=10).json()
        assert "authorization_servers" in prm


def test_as_endpoints_404_when_disabled(gateway):
    url, _ = gateway
    base = _base(url)
    for p in ("/.well-known/oauth-authorization-server", "/authorize"):
        assert httpx.get(base + p, timeout=10).status_code == 404
    for p in ("/register", "/token"):
        assert httpx.post(base + p, content="{}", timeout=10).status_code == 404


# -- issuer pinning --

def test_public_url_pins_issuer():
    with _run(oauth=_provider(public_url="https://gw.example.org")) as (base, _):
        md = httpx.get(base + "/.well-known/oauth-authorization-server", timeout=10).json()
        assert md["issuer"] == "https://gw.example.org"
        assert md["authorization_endpoint"] == "https://gw.example.org/authorize"
        prm = httpx.get(base + "/.well-known/oauth-protected-resource/mcp", timeout=10).json()
        assert prm["authorization_servers"] == ["https://gw.example.org"]


# -- path-scoped issuer (#245): multiple --enable-oauth backends behind one host --

_PREFIXED = "https://gw.example.org/team-a"


def test_path_scoped_as_metadata_root_inserted():
    """A path-scoped issuer serves AS metadata at the RFC 8414 Sec. 3.1
    root-inserted location, advertising prefixed endpoints; the bare-origin
    location 404s so two backends never collide there."""
    with _run(oauth=_provider(public_url=_PREFIXED)) as (base, _):
        # Root-inserted well-known: /.well-known/oauth-authorization-server/team-a
        md = httpx.get(
            base + "/.well-known/oauth-authorization-server/team-a", timeout=10
        ).json()
        assert md["issuer"] == _PREFIXED
        assert md["authorization_endpoint"] == _PREFIXED + "/authorize"
        assert md["token_endpoint"] == _PREFIXED + "/token"
        assert md["registration_endpoint"] == _PREFIXED + "/register"
        # The bare-origin AS metadata path must NOT serve this backend.
        assert httpx.get(
            base + "/.well-known/oauth-authorization-server", timeout=10
        ).status_code == 404


def test_path_scoped_prm_root_inserted():
    """PRM is root-inserted with the full resource path (prefix + mcp_path),
    byte-symmetric with the client's _build_well_known_url."""
    with _run(oauth=_provider(public_url=_PREFIXED)) as (base, _):
        prm = httpx.get(
            base + "/.well-known/oauth-protected-resource/team-a/mcp", timeout=10
        ).json()
        assert prm["resource"] == _PREFIXED + "/mcp"
        assert prm["authorization_servers"] == [_PREFIXED]


def test_path_scoped_bare_as_endpoints_404():
    """With a prefix pinned, the bare-origin AS endpoints 404 (isolation)."""
    with _run(oauth=_provider(public_url=_PREFIXED)) as (base, _):
        assert httpx.get(base + "/authorize", timeout=10).status_code == 404
        assert httpx.post(base + "/register", content="{}", timeout=10).status_code == 404
        assert httpx.post(base + "/token", content="x=1", timeout=10).status_code == 404
        # The MCP endpoint also lives under the prefix now.
        assert httpx.post(base + "/mcp", content="{}", timeout=10).status_code == 404


def test_path_scoped_full_flow():
    """End-to-end under a path prefix: DCR -> PKCE authorize -> token -> MCP."""
    prefix = "/team-a"
    with _run(oauth=_provider(public_url=_PREFIXED)) as (base, _):
        # DCR under the prefix.
        cid = httpx.post(
            base + prefix + "/register",
            json={
                "client_name": "test",
                "redirect_uris": [_REDIRECT],
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "none",
            },
            timeout=10,
        ).json()["client_id"]
        verifier, challenge = client_oauth.generate_pkce()
        az = httpx.get(
            base + prefix + "/authorize",
            params={
                "client_id": cid,
                "response_type": "code",
                "redirect_uri": _REDIRECT,
                "state": "st-1",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": _PREFIXED + "/mcp",
            },
            follow_redirects=False,
            timeout=10,
        )
        assert az.status_code == 302, az.text
        code = _redirect_params(az)["code"]
        tok = httpx.post(
            base + prefix + "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _REDIRECT,
                "client_id": cid,
                "code_verifier": verifier,
            },
            timeout=10,
        ).json()
        access = tok["access_token"]
        # The issued token authorizes a real MCP call at the prefixed path.
        r = httpx.post(
            base + prefix + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            headers={"Authorization": f"Bearer {access}"},
            timeout=10,
        )
        assert r.status_code == 200
        # An unauthenticated prefixed MCP call is challenged with the
        # root-inserted PRM hint.
        chal = httpx.post(
            base + prefix + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "echo"}),
            timeout=10,
        )
        assert chal.status_code == 401
        assert "/.well-known/oauth-protected-resource/team-a/mcp" in chal.headers[
            "WWW-Authenticate"
        ]


def test_two_path_scoped_backends_do_not_collide():
    """Two prefixes route to disjoint AS-metadata / endpoint paths."""
    a = "https://gw.example.org/team-a"
    b = "https://gw.example.org/team-b"
    with _run(oauth=_provider(public_url=a)) as (base_a, _):
        with _run(oauth=_provider(public_url=b)) as (base_b, _):
            # Each backend answers only at its own root-inserted metadata path.
            assert httpx.get(
                base_a + "/.well-known/oauth-authorization-server/team-a", timeout=10
            ).json()["issuer"] == a
            assert httpx.get(
                base_a + "/.well-known/oauth-authorization-server/team-b", timeout=10
            ).status_code == 404
            assert httpx.get(
                base_b + "/.well-known/oauth-authorization-server/team-b", timeout=10
            ).json()["issuer"] == b
            assert httpx.get(
                base_b + "/.well-known/oauth-authorization-server/team-a", timeout=10
            ).status_code == 404


def test_normalize_public_url():
    # A bare origin is unchanged (legacy behavior).
    assert server._normalize_public_url("https://gw.example.org") == "https://gw.example.org"
    assert server._normalize_public_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    # A path is RETAINED as the issuer prefix (#245), trailing slash stripped.
    assert server._normalize_public_url("https://gw.example.org/team-a") == "https://gw.example.org/team-a"
    assert server._normalize_public_url("https://gw.example.org/team-a/") == "https://gw.example.org/team-a"
    assert server._normalize_public_url("https://gw.example.org/a/b") == "https://gw.example.org/a/b"
    # A bare host with only a trailing slash collapses to the bare origin.
    assert server._normalize_public_url("https://gw.example.org/") == "https://gw.example.org"
    # canonicalization: lowercase host, drop explicit default port, keep path
    assert server._normalize_public_url("https://EXAMPLE.com:443/x") == "https://example.com/x"
    assert server._normalize_public_url("http://LOCALHOST:80") == "http://localhost"
    for bad in ("ftp://h", "https://", 'https://h"x', "https://user@h",
                "http://gw.example.org",  # non-loopback http is rejected
                "https://gw.example.org/a?q=1",  # query forbidden in an issuer
                "https://gw.example.org/a#f",  # fragment forbidden in an issuer
                "https://gw.example.org/../admin",  # traversal segment rejected
                "https://gw.example.org/a/../b",  # interior traversal rejected
                "https://gw.example.org/a//b",  # empty segment rejected
                "https://gw.example.org/a/./b"):  # "." segment rejected
        with pytest.raises(ValueError):
            server._normalize_public_url(bad)


# -- CLI flag validation (error paths return before serve() blocks) --

def test_serve_main_dev_user_requires_oauth():
    with pytest.raises(SystemExit):
        server.serve_main(["--dev-user", "x", "--", "true"])


def test_serve_main_bad_public_url():
    with pytest.raises(SystemExit):
        server.serve_main(["--enable-oauth", "--public-url", "ftp://x", "--dev-user", "a", "--", "true"])


def test_serve_main_bad_trusted_header():
    with pytest.raises(SystemExit):
        server.serve_main(["--enable-oauth", "--trusted-user-header", "bad header", "--", "true"])


# -- real-client interop: drive mcp_stdio.oauth.ensure_token end to end --

def test_real_client_ensure_token(monkeypatch, tmp_path):
    # Point the client token store at a temp dir (no touching real ~/.config).
    from mcp_stdio import token_store
    monkeypatch.setattr(token_store, "_STORE_DIR", tmp_path)
    monkeypatch.setattr(token_store, "_STORE_FILE", tmp_path / "tokens.json")
    monkeypatch.setattr(token_store, "_LEGACY_STORE_DIR", tmp_path / "legacy")
    monkeypatch.setattr(token_store, "_LEGACY_STORE_FILE", tmp_path / "legacy" / "tokens.json")

    with _run(oauth=_provider(dev_user="alice")) as (base, _):
        # The client opens a browser at auth_url then waits for its loopback
        # callback. Simulate the browser in a BACKGROUND thread (a synchronous
        # GET would deadlock: the callback server's serve() thread starts only
        # AFTER webbrowser.open returns).
        def fake_open(auth_url):
            def drive():
                r = httpx.get(auth_url, follow_redirects=False, timeout=10)
                if r.status_code == 302:
                    httpx.get(r.headers["location"], timeout=10)
            threading.Thread(target=drive, daemon=True).start()

        monkeypatch.setattr(client_oauth.webbrowser, "open", fake_open)

        with httpx.Client(timeout=10) as client:
            td = client_oauth.ensure_token(base + "/mcp", client, timeout=15)
        assert td.access_token
        # the obtained token authorizes a real MCP call
        r = httpx.post(base + "/mcp",
                       content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
                       headers={"Authorization": f"Bearer {td.access_token}"}, timeout=10)
        assert r.status_code == 200


# --- adversarial-review fixes ---

def test_store_cap_is_a_hard_bound(monkeypatch):
    # GC frees only expired entries; the cap must still bound live tokens.
    monkeypatch.setattr(server, "_STORE_CAP", 5)
    prov = _provider()
    for i in range(30):
        prov._issue(f"u{i}", "c", "", None)
    assert len(prov._access) <= 5
    assert len(prov._refresh) <= 5


def test_client_cap_recycles_not_bricks(monkeypatch):
    # /register must never permanently lock out: at the cap the oldest client
    # is recycled rather than rejected.
    monkeypatch.setattr(server, "_CLIENT_CAP", 3)
    prov = _provider()
    last = None
    for i in range(8):
        status, body = prov.register(
            json.dumps({"redirect_uris": [f"http://127.0.0.1:{1000 + i}/callback"]}).encode()
        )
        assert status == 201, body
        last = body["client_id"]
    assert len(prov._clients) <= 3
    assert last in prov._clients  # newest registration survives


def test_redirect_key_rejects_query_userinfo_fragment():
    assert server._redirect_key("http://127.0.0.1:5/cb") == ("http", "127.0.0.1", "/cb")
    assert server._redirect_key("http://127.0.0.1:5/cb?next=x") is None
    assert server._redirect_key("http://u:p@127.0.0.1:5/cb") is None
    assert server._redirect_key("http://127.0.0.1:5/cb#frag") is None
    assert server._redirect_key("https://127.0.0.1:5/cb") is None
    assert server._redirect_key("http://evil.example.com/cb") is None


def test_register_rejects_query_bearing_redirect(oauth_gateway):
    base, _ = oauth_gateway
    r = _register(base, redirect="http://127.0.0.1:5555/callback?next=x")
    assert r.status_code == 400
    # RFC 7591 Sec. 3.2.2: an invalid redirect URI uses the dedicated error code.
    assert r.json()["error"] == "invalid_redirect_uri"


def test_refresh_wrong_client_id_preserves_token(oauth_gateway):
    base, _ = oauth_gateway
    cid, _, _, _, tok = _full_flow(base)
    rt = tok.json()["refresh_token"]
    # a wrong client_id must be rejected WITHOUT destroying the valid token
    bad = _token(base, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": "wrong"})
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"
    good = _token(base, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid})
    assert good.status_code == 200


def test_token_missing_grant_is_invalid_request(oauth_gateway):
    base, _ = oauth_gateway
    r = _token(base, {"foo": "bar"})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"


def test_401_hint_uses_pinned_issuer():
    with _run(oauth=_provider(public_url="https://gw.example.org")) as (base, _):
        r = httpx.post(base + "/mcp",
                       content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "echo"}), timeout=10)
        assert r.status_code == 401
        assert ('resource_metadata="https://gw.example.org/.well-known/'
                'oauth-protected-resource/mcp"') in r.headers["www-authenticate"]


def test_redact_query():
    out = server._redact_query('"GET /authorize?state=SECRET&x=1 HTTP/1.1" 302 -')
    assert out == '"GET /authorize?<redacted> HTTP/1.1" 302 -'
    assert "SECRET" not in out
    # absolute-form request target (RFC 7230, e.g. via a forwarding proxy) too
    out2 = server._redact_query(
        '"GET http://gw.example.org/authorize?state=SECRET&code=ABC HTTP/1.1" 404 -'
    )
    assert out2 == '"GET http://gw.example.org/authorize?<redacted> HTTP/1.1" 404 -'
    assert "SECRET" not in out2 and "ABC" not in out2
    # a query-less line is unchanged
    assert server._redact_query('"POST /mcp HTTP/1.1" 200 -') == '"POST /mcp HTTP/1.1" 200 -'


def test_concurrent_refresh_single_use(oauth_gateway):
    # The same refresh token submitted concurrently must rotate exactly once.
    base, _ = oauth_gateway
    cid, _, _, _, tok = _full_flow(base)
    rt = tok.json()["refresh_token"]
    data = {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid}
    with ThreadPoolExecutor(max_workers=8) as ex:
        codes = list(ex.map(lambda _: _token(base, data).status_code, range(8)))
    assert codes.count(200) == 1
    assert codes.count(400) == 7


def test_refresh_token_expires():
    clock = [1000.0]
    prov = _provider(refresh_ttl=50, now=lambda: clock[0])
    with _run(oauth=prov) as (base, _):
        cid, _, _, _, tok = _full_flow(base)
        rt = tok.json()["refresh_token"]
        clock[0] += 100  # advance past refresh_ttl
        r = _token(base, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"


# -- RFC 6750 invalid_token challenge (audit fix A) --

def test_invalid_token_challenge_has_error(oauth_gateway):
    """RFC 6750 Sec. 3.1: a presented-but-invalid bearer token yields
    error="invalid_token" in the challenge."""
    base, _ = oauth_gateway
    r = _authed_mcp(base, "bogus-token")
    assert r.status_code == 401
    wa = r.headers.get("www-authenticate", "")
    assert 'error="invalid_token"' in wa
    assert "resource_metadata=" in wa


def test_no_token_challenge_omits_error(oauth_gateway):
    """RFC 6750 Sec. 3: with NO token presented, the error attribute is omitted
    (the bare challenge is how the client learns to authenticate)."""
    base, _ = oauth_gateway
    r = _post(base + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "echo"})
    assert r.status_code == 401
    wa = r.headers.get("www-authenticate", "")
    assert "error=" not in wa
    assert "resource_metadata=" in wa


# -- RFC 8707 / MCP audience binding (audit fix H) --

def test_validate_access_token_audience():
    """A token minted for resource A is rejected when guarding resource B."""
    prov = _provider()
    _, body = prov._issue("u", "c", "", "https://api.example.com/mcp", family="f")
    token = body["access_token"]
    assert prov.validate_access_token(token, "https://api.example.com/mcp") is True
    # trailing-slash difference tolerated
    assert prov.validate_access_token(token, "https://api.example.com/mcp/") is True
    # a different audience is rejected even though the token is live
    assert prov.validate_access_token(token, "https://other.example.com/mcp") is False
    # no expected resource supplied -> lenient (back-compat)
    assert prov.validate_access_token(token, None) is True


def test_validate_access_token_no_audience_binding():
    """A token with no resource binding is accepted for any resource."""
    prov = _provider()
    _, body = prov._issue("u", "c", "", None, family="f")
    token = body["access_token"]
    assert prov.validate_access_token(token, "https://api.example.com/mcp") is True


def test_mcp_call_rejects_token_for_other_audience():
    """End-to-end: a token bound to a different resource cannot call this MCP."""
    with _run(oauth=_provider()) as (base, _):
        cid = _register(base).json()["client_id"]
        verifier, challenge = client_oauth.generate_pkce()
        # Authorize with a resource that is NOT this gateway's MCP endpoint.
        az = httpx.get(
            base + "/authorize",
            params={
                "client_id": cid, "response_type": "code",
                "redirect_uri": _REDIRECT, "state": "s",
                "code_challenge": challenge, "code_challenge_method": "S256",
                "resource": "https://other.example.com/mcp",
            },
            follow_redirects=False, timeout=10,
        )
        code = _redirect_params(az)["code"]
        tok = _token(base, {
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": _REDIRECT, "client_id": cid, "code_verifier": verifier,
        })
        access = tok.json()["access_token"]
        # The token is live but bound to other.example.com -> this RS rejects it.
        assert _authed_mcp(base, access).status_code == 401


# -- authorization-code replay revocation (audit fix F, RFC 6749 Sec. 4.1.2) --

def test_auth_code_replay_revokes_family():
    clock = [1000.0]
    prov = _provider(now=lambda: clock[0])
    with _run(oauth=prov) as (base, _):
        cid, verifier, challenge, code, tok = _full_flow(base)
        assert tok.status_code == 200
        access = tok.json()["access_token"]
        assert _authed_mcp(base, access).status_code == 200
        # Past the reuse grace window, replaying the code is a theft signal.
        clock[0] += _grace() + 5
        replay = _token(base, {
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": _REDIRECT, "client_id": cid, "code_verifier": verifier,
        })
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"
        assert "revoked" in replay.json()["error_description"]
        # The previously-issued token is now revoked.
        assert _authed_mcp(base, access).status_code == 401


# -- refresh-token reuse revocation (audit fix G, RFC 9700 Sec. 4.14.2) --

def test_refresh_reuse_revokes_family():
    clock = [1000.0]
    prov = _provider(now=lambda: clock[0])
    with _run(oauth=prov) as (base, _):
        cid, _, _, _, tok = _full_flow(base)
        rt0 = tok.json()["refresh_token"]
        # Rotate rt0 -> rt1.
        r1 = _token(base, {"grant_type": "refresh_token", "refresh_token": rt0, "client_id": cid})
        assert r1.status_code == 200
        access1 = r1.json()["access_token"]
        rt1 = r1.json()["refresh_token"]
        assert _authed_mcp(base, access1).status_code == 200
        # Within the grace window, reusing rt0 is denied but does NOT revoke.
        benign = _token(base, {"grant_type": "refresh_token", "refresh_token": rt0, "client_id": cid})
        assert benign.status_code == 400
        assert benign.json()["error_description"] == "refresh_token already rotated"
        assert _authed_mcp(base, access1).status_code == 200  # survives
        # Past the grace window, reusing rt0 is theft -> revoke the whole family.
        clock[0] += _grace() + 5
        theft = _token(base, {"grant_type": "refresh_token", "refresh_token": rt0, "client_id": cid})
        assert theft.status_code == 400
        assert "reuse detected" in theft.json()["error_description"]
        # access1 and rt1 (same family) are now revoked.
        assert _authed_mcp(base, access1).status_code == 401
        r3 = _token(base, {"grant_type": "refresh_token", "refresh_token": rt1, "client_id": cid})
        assert r3.status_code == 400


def _grace():
    return server._REUSE_GRACE_SECS
