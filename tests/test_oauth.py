"""Exercise actual OAuth HTTP routes, PKCE and tenant boundaries without real passwords."""

import base64
import hashlib
from urllib.parse import urlsplit, parse_qs

import pytest
from cryptography.fernet import Fernet
from fastmcp import FastMCP
from starlette.testclient import TestClient

import lanhu_auth
from lanhu_auth import LanhuOAuthProvider


@pytest.fixture
def provider(tmp_path):
    return LanhuOAuthProvider("https://lanhu.mcp.paxcq.com", tmp_path, Fernet.generate_key().decode())


@pytest.fixture
def http(provider, monkeypatch):
    async def login(account, password):
        return {"subject": account, "cookie": "session=" + account, "name": account}

    monkeypatch.setattr(lanhu_auth, "login", login)
    server = FastMCP("OAuth test", auth=provider)
    with TestClient(
        server.http_app(path="/mcp", stateless_http=True), base_url=provider.public_url, follow_redirects=False
    ) as client:
        yield client


def register(http):
    r = http.post(
        "/register",
        json={
            "client_name": "Test IDE",
            "redirect_uris": ["http://127.0.0.1:19876/callback"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def authorize(http, client_id, account="alice"):
    verifier = "a" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    r = http.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:19876/callback",
            "response_type": "code",
            "code_challenge_method": "S256",
            "code_challenge": challenge,
            "state": "original-state",
            "scope": "lanhu",
            "resource": "https://lanhu.mcp.paxcq.com/mcp",
        },
    )
    assert r.status_code in (302, 303), r.text
    url = r.headers["location"]
    tx = parse_qs(urlsplit(url).query)["tx"][0]
    r = http.get(url)
    assert r.status_code == 200
    csrf = http.cookies.get("lanhu_csrf")
    r = http.post("/login", data={"tx": tx, "csrf": csrf, "action": "allow", "account": account, "password": "test"})
    assert r.status_code == 303, r.text
    query = parse_qs(urlsplit(r.headers["location"]).query)
    assert query["state"] == ["original-state"]
    return query["code"][0], verifier


def exchange(http, cid, code, verifier):
    return http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": cid,
            "code": code,
            "redirect_uri": "http://127.0.0.1:19876/callback",
            "code_verifier": verifier,
        },
    )


def test_complete_flow_pkce_refresh_and_revoke(http, provider):
    assert http.get("/.well-known/oauth-authorization-server").json()["registration_endpoint"].endswith("/register")
    assert http.post("/mcp", json={}).status_code == 401
    cid = register(http)
    code, verifier = authorize(http, cid)
    assert exchange(http, cid, code, "wrong" * 12).status_code in (400, 401)
    r = exchange(http, cid, code, verifier)
    assert r.status_code == 200, r.text
    tokens = r.json()
    assert exchange(http, cid, code, verifier).status_code in (400, 401)
    refresh = http.post(
        "/token", data={"grant_type": "refresh_token", "client_id": cid, "refresh_token": tokens["refresh_token"]}
    )
    assert refresh.status_code == 200, refresh.text
    assert http.post(
        "/token", data={"grant_type": "refresh_token", "client_id": cid, "refresh_token": tokens["refresh_token"]}
    ).status_code in (400, 401)
    assert http.post("/revoke", data={"client_id": cid, "token": refresh.json()["access_token"]}).status_code == 200
    assert provider.store.get("access", refresh.json()["access_token"]) is None


def test_two_users_and_clients_are_isolated(http, provider, monkeypatch, tmp_path):
    import lanhu_mcp_server as server
    from fastmcp.server import dependencies

    cid = register(http)
    grants = []
    for account in ["alice", "bob"]:
        code, verifier = authorize(http, cid, account)
        tokens = exchange(http, cid, code, verifier).json()
        saved = provider.store.get("access", tokens["access_token"])
        grants.append(lanhu_auth.AccessToken.model_validate(saved))
    monkeypatch.setattr(server, "_oauth_provider", provider)
    monkeypatch.setattr(server, "DATA_DIR", tmp_path)
    monkeypatch.setattr(dependencies, "get_access_token", lambda: grants[0])
    first_dir = server._current_data_dir()
    server._set_cached_metadata("same-project", {"private": "alice"})
    assert server._current_cookie() == "session=alice"
    monkeypatch.setattr(dependencies, "get_access_token", lambda: grants[1])
    assert server._current_cookie() == "session=bob"
    assert server._current_data_dir() != first_dir
    assert server._get_cached_metadata("same-project") is None
    with pytest.raises(Exception):
        server._current_design_service().artifact("alice-snapshot", "preview", "anything")
    monkeypatch.setattr(dependencies, "get_access_token", lambda: None)
    with pytest.raises(PermissionError):
        server._current_cookie()


def test_csrf_and_client_binding(http, provider):
    cid = register(http)
    code, verifier = authorize(http, cid)
    other = register(http)
    assert exchange(http, other, code, verifier).status_code in (400, 401)
    assert exchange(http, cid, code, verifier).status_code == 200
    r = http.post("/login", data={"tx": "missing", "csrf": "bad"})
    assert r.status_code in (400, 401)
    assert http.get("/login?tx=missing").status_code in (400, 401)


def test_encrypted_persistence_and_expiry(provider):
    provider.store.put("user", "secret-key", {"cookie": "secret-cookie"})
    assert b"secret-cookie" not in provider.store.path.read_bytes()
    assert b"secret-key" not in provider.store.path.read_bytes()
    assert provider.store.get("user", "secret-key", consume=True)["cookie"] == "secret-cookie"
    assert provider.store.get("user", "secret-key", consume=True) is None
    provider.store.put("access", "expired", {"token": "x"}, ttl=-1)
    assert provider.store.get("access", "expired") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("via_redirect", [False, True])
@pytest.mark.parametrize("auth_mobile", [False, True])
async def test_lanhu_sso_protocol_encryption_and_cookie_exchange(monkeypatch, via_redirect, auth_mobile):
    import httpx
    from lanhu_auth import upstream

    calls = []
    real_client = httpx.AsyncClient

    def handler(request):
        import json

        calls.append(request)
        if request.url.path == "/api/passport/login":
            payload = json.loads(request.content)
            assert payload["mobile_or_email"] == "alice@example.com"
            assert payload["password"] != "plain-password"
            assert len(base64.b64decode(payload["password"])) == 256
            return httpx.Response(
                200, json={"code": 0, "data": {"ticket": "one-time-ticket", "auth_mobile": auth_mobile}}
            )
        if request.url.path == "/api/auth":
            if via_redirect:
                return httpx.Response(
                    302, headers={"location": "https://lanhuapp.com/dashboard/#/item?sso_token=lanhu-secret"}
                )
            assert request.url.params["sso_ticket"] == "one-time-ticket"
            return httpx.Response(
                302,
                headers={
                    "set-cookie": "user_token=lanhu-secret; Domain=.lanhuapp.com; Path=/; HttpOnly",
                    "location": "https://lanhuapp.com/dashboard/",
                },
            )
        assert request.url.path == "/api/account/entry"
        assert request.headers["cookie"] == "user_token=lanhu-secret"
        return httpx.Response(200, json={"code": "00000", "data": {"id": "alice-id", "name": "Alice"}})

    monkeypatch.setattr(
        upstream.httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw)
    )
    result = await upstream.login("alice@example.com", "plain-password")
    assert result == {"subject": "alice-id", "cookie": "user_token=lanhu-secret", "name": "Alice"}
    assert len(calls) == 3


def test_real_mcp_tool_receives_authenticated_subject(provider, monkeypatch):
    from fastmcp.server.dependencies import get_access_token

    server = FastMCP("identity-test", auth=provider)

    @server.tool()
    def whoami():
        return {"subject": get_access_token().subject, "cookie": provider.session()[1]["cookie"]}

    async def login(account, password):
        return {"subject": account, "cookie": "session=" + account, "name": account}

    monkeypatch.setattr(lanhu_auth, "login", login)
    with TestClient(
        server.http_app(path="/mcp", stateless_http=True), base_url=provider.public_url, follow_redirects=False
    ) as client:
        cid = register(client)
        code, verifier = authorize(client, cid)
        token = exchange(client, cid, code, verifier).json()["access_token"]
        response = client.post(
            "/mcp",
            headers={"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "whoami", "arguments": {}}},
        )
        assert response.status_code == 200, response.text
        assert "session=alice" in response.text


def test_storage_paths_cannot_escape_tenant_directory():
    import lanhu_mcp_server as server

    for bad in ("../../auth/session", "/tmp/other", "a/b", "..", "%2e%2e%2f"):
        with pytest.raises(ValueError):
            server.MessageStore(bad)


def test_csrf_rejection_and_explicit_denial(http, provider):
    cid = register(http)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(b"a" * 64).digest()).decode().rstrip("=")
    r = http.get(
        "/authorize",
        params={
            "client_id": cid,
            "redirect_uri": "http://127.0.0.1:19876/callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "lanhu",
            "state": "deny-state",
        },
    )
    url = r.headers["location"]
    tx = parse_qs(urlsplit(url).query)["tx"][0]
    http.get(url)
    assert (
        http.post(
            "/login", data={"tx": tx, "csrf": "forged", "action": "allow", "account": "alice", "password": "test"}
        ).status_code
        == 403
    )
    csrf = http.cookies.get("lanhu_csrf")
    r = http.post("/login", data={"tx": tx, "csrf": csrf, "action": "deny"})
    assert r.status_code == 303
    assert parse_qs(urlsplit(r.headers["location"]).query) == {"error": ["access_denied"], "state": ["deny-state"]}
    assert provider.store.get("pending", tx) is None


@pytest.mark.asyncio
async def test_browser_form_preserves_origin(http, provider):
    import asyncio
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from playwright.async_api import async_playwright, Error

    cid = register(http)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(b"a" * 64).digest()).decode().rstrip("=")
    response = http.get(
        "/authorize",
        params={
            "client_id": cid,
            "redirect_uri": "http://127.0.0.1:19876/callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "lanhu",
        },
    )
    login_url = response.headers["location"]
    rendered = http.get(login_url)
    assert rendered.headers["referrer-policy"] == "same-origin"
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch()
        except Error as exc:
            if "Executable doesn't exist" in str(exc):
                pytest.skip("Chromium is not installed")
            raise
        try:

            class CallbackHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Returned to MCP client")

                def log_message(self, *args):
                    pass

            callback_server = ThreadingHTTPServer(("127.0.0.1", 19876), CallbackHandler)
            callback_thread = threading.Thread(target=callback_server.serve_forever, daemon=True)
            callback_thread.start()
            page = await browser.new_page()
            submitted = asyncio.get_running_loop().create_future()

            async def route_request(route):
                if route.request.method == "GET":
                    await route.fulfill(status=200, headers=dict(rendered.headers), body=rendered.text)
                else:
                    headers = await route.request.all_headers()
                    result = http.post(
                        "/login",
                        content=route.request.post_data,
                        headers={
                            "Origin": headers.get("origin", ""),
                            "Content-Type": headers["content-type"],
                            "Cookie": headers.get("cookie", ""),
                        },
                    )
                    submitted.set_result((headers, result))
                    await route.fulfill(status=result.status_code, headers=dict(result.headers), body=result.content)

            await page.route("**/login*", route_request)
            await page.goto(login_url)
            await page.get_by_role("button", name="取消授权").click()
            headers, result = await asyncio.wait_for(submitted, timeout=10)
            await page.wait_for_url("http://127.0.0.1:19876/callback*", timeout=5000)
            assert headers["origin"] == provider.public_url
            assert "lanhu_csrf=" in headers["cookie"]
            assert result.status_code == 303, result.text
            assert parse_qs(urlsplit(result.headers["location"]).query)["error"] == ["access_denied"]
        finally:
            await browser.close()
            if "callback_server" in locals():
                callback_server.shutdown()
                callback_server.server_close()
                callback_thread.join(timeout=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["no_ticket", "no_session", "identity_denied", "http_denied"])
async def test_mobile_prompt_never_bypasses_upstream_authentication(monkeypatch, failure):
    import httpx
    from lanhu_auth import upstream

    real_client = httpx.AsyncClient

    def handler(request):
        if request.url.path == "/api/passport/login":
            data = {"auth_mobile": True}
            if failure != "no_ticket":
                data["ticket"] = "upstream-issued-ticket"
            return httpx.Response(200, json={"code": 0, "data": data})
        if request.url.path == "/api/auth":
            headers = {"location": "https://lanhuapp.com/dashboard/"}
            if failure != "no_session":
                headers["set-cookie"] = "user_token=upstream-session; Domain=.lanhuapp.com; Path=/"
            return httpx.Response(302, headers=headers)
        assert request.url.path == "/api/account/entry"
        if failure == "http_denied":
            return httpx.Response(403)
        return httpx.Response(200, json={"code": 30001, "data": {}})

    monkeypatch.setattr(
        upstream.httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw)
    )
    with pytest.raises(upstream.LoginError):
        await upstream.login("alice@example.com", "test-password")
