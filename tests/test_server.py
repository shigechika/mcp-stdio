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
    httpd, backend = server.build_server(_BACKEND, host="127.0.0.1", port=0)
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{port}/mcp"
    try:
        yield url, backend
    finally:
        httpd.shutdown()
        backend.shutdown()
        httpd.server_close()


def _post(url: str, msg: dict) -> httpx.Response:
    return httpx.post(url, content=json.dumps(msg), timeout=10)


def test_request_response(gateway):
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"a": 1}})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    body = resp.json()
    assert body["id"] == 1
    assert body["result"]["echoed"] == {"a": 1}


def test_initialize_returns_protocol_version(gateway):
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": "init", "method": "initialize"})
    assert resp.status_code == 200
    assert resp.json()["result"]["protocolVersion"] == "2025-06-18"


def test_session_id_header_present_and_stable(gateway):
    url, _ = gateway
    r1 = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"})
    r2 = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "echo"})
    sid1 = r1.headers.get("mcp-session-id")
    sid2 = r2.headers.get("mcp-session-id")
    assert sid1 and sid1 == sid2


def test_notification_returns_202(gateway):
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "method": "somenotify"})
    assert resp.status_code == 202


def test_client_response_returns_202(gateway):
    # A client answering a server-initiated request is a JSON-RPC response
    # (id + result, no method): the gateway forwards it one-way -> 202.
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": 99, "result": {"ok": True}})
    assert resp.status_code == 202


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
    resp = _post(url, {"jsonrpc": "2.0", "id": 7, "method": "noreply"})
    assert resp.status_code == 504
    assert resp.json()["id"] == 7
    assert resp.json()["error"]["code"] == -32000


def test_get_sse_delivers_server_initiated(gateway):
    url, _ = gateway
    received: list[str] = []
    ready = threading.Event()

    def reader():
        with httpx.stream("GET", url, timeout=10) as r:
            ready.set()
            for line in r.iter_lines():
                if line.startswith("data: "):
                    received.append(line[len("data: ") :])
                    return

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    ready.wait(5)
    time.sleep(0.2)  # let the GET stream attach before we trigger a push
    _post(url, {"jsonrpc": "2.0", "method": "trigger_push"})
    t.join(5)
    assert received, "no SSE message received"
    msg = json.loads(received[0])
    assert msg["method"] == "notifications/message"
    assert msg["params"] == {"hello": "world"}


def test_delete_returns_200(gateway):
    url, _ = gateway
    resp = httpx.request("DELETE", url, timeout=10)
    assert resp.status_code == 200


def test_backend_death_then_request_fails(gateway):
    url, backend = gateway
    # Tell the backend to exit, then give the reader thread a moment to notice.
    _post(url, {"jsonrpc": "2.0", "method": "exit"})
    deadline = time.time() + 5
    while not backend.closed and time.time() < deadline:
        time.sleep(0.05)
    assert backend.closed
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"})
    assert resp.status_code == 503
    assert resp.json()["id"] == 1


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


# --- M2: static-bearer-token Resource Server + RFC 9728 metadata ---

_TOKEN = "s3cr3t-token"


@pytest.fixture()
def auth_gateway():
    """A gateway protected by a static bearer token."""
    httpd, backend = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, auth_token=_TOKEN
    )
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{port}/mcp"
    try:
        yield url, backend
    finally:
        httpd.shutdown()
        backend.shutdown()
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
    resp = httpx.post(
        url,
        content=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"a": 1}}
        ),
        headers={"Authorization": f"Bearer {_TOKEN}"},
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
    assert "authorization_servers" not in body  # none until M3
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
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"})
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


# --- M3: embedded OAuth 2.1 Authorization Server ---

_REDIRECT = "http://127.0.0.1:5555/callback"


@contextlib.contextmanager
def _run(*, auth_token=None, oauth=None):
    """Start a gateway with the given auth config; yield (base_url, backend)."""
    httpd, backend = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, auth_token=auth_token, oauth=oauth
    )
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://{host}:{port}", backend
    finally:
        httpd.shutdown()
        backend.shutdown()
        httpd.server_close()


def _provider(**kw):
    kw.setdefault("public_url", None)
    kw.setdefault("trusted_user_header", None)
    kw.setdefault("dev_user", "alice")
    return server._OAuthProvider(**kw)


@pytest.fixture()
def oauth_gateway():
    """A gateway with the embedded AS enabled and --dev-user=alice."""
    with _run(oauth=_provider()) as (base, backend):
        yield base, backend


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
    assert r.json()["error"] == "invalid_client_metadata"


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
    r = httpx.post(base + "/mcp",
                   content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"x": 1}}),
                   headers={"Authorization": f"Bearer {body['access_token']}"}, timeout=10)
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
                        content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "echo"}),
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
                        content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "echo"}),
                        headers={"Authorization": "Bearer static-tok"}, timeout=10)
        assert r1.status_code == 200
        # issued token authorizes
        _, _, _, _, tok = _full_flow(base)
        at = tok.json()["access_token"]
        r2 = httpx.post(base + "/mcp",
                        content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "echo"}),
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


def test_normalize_public_url():
    assert server._normalize_public_url("https://gw.example.org/mcp") == "https://gw.example.org"
    assert server._normalize_public_url("http://h:8080") == "http://h:8080"
    for bad in ("ftp://h", "https://", 'https://h"x', "https://user@h"):
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
                       content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "echo"}),
                       headers={"Authorization": f"Bearer {td.access_token}"}, timeout=10)
        assert r.status_code == 200
