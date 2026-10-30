"""OAuth 2.1 login for remote MCP clients, backed by independent Lanhu sessions."""

import html
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

import httpx
from fastmcp.server.auth import OAuthProvider, AccessToken
from mcp.server.auth.provider import AuthorizationCode, RefreshToken, TokenError, RegistrationError
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from .store import Store
from .upstream import login, LoginError

SESSION_TTL = 7 * 86400


def redirect_with(uri, **values):
    parts = urlsplit(str(uri))
    query = list(parse_qsl(parts.query)) + [(k, v) for k, v in values.items() if v is not None]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


class LanhuOAuthProvider(OAuthProvider):
    def __init__(self, base_url: str, root: Path, key: str):
        super().__init__(
            base_url=base_url,
            required_scopes=["lanhu"],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=["lanhu"], default_scopes=["lanhu"]
            ),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.store = Store(root / "auth", key)
        self.public_url = base_url.rstrip("/")

    async def get_client(self, client_id):
        data = self.store.get("client", client_id)
        return OAuthClientInformationFull.model_validate(data) if data else None

    async def register_client(self, client_info):
        # Prevent ambiguous consent labels and prohibit non-loopback cleartext redirects.
        for uri in client_info.redirect_uris or []:
            parts = urlsplit(str(uri))
            if (
                parts.fragment
                or parts.username
                or parts.password
                or not (
                    parts.scheme == "https"
                    or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1"))
                )
            ):
                raise RegistrationError(
                    "invalid_redirect_uri", "Redirect URI must use HTTPS or a local loopback address"
                )
        self.store.put("client", client_info.client_id, client_info.model_dump(mode="json"), 365 * 86400)

    async def authorize(self, client, params):
        if params.resource and params.resource.rstrip("/") != self.public_url + "/mcp":
            from mcp.server.auth.provider import AuthorizeError

            raise AuthorizeError("invalid_request", "Unexpected resource")
        tx = secrets.token_urlsafe(32)
        self.store.put("pending", tx, {"client_id": client.client_id, "params": params.model_dump(mode="json")}, 600)
        return f'{self.public_url}/login?{urlencode({"tx": tx})}'

    async def load_authorization_code(self, client, authorization_code):
        record = self.store.get("code", authorization_code)
        if record and record["client_id"] == client.client_id:
            return AuthorizationCode.model_validate(record)
        return None

    def _issue(self, client_id, subject, scopes, resource):
        if not self.store.get("user", subject):
            raise TokenError("invalid_grant", "Lanhu session expired; please authorize again")
        access, refresh = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
        common = dict(client_id=client_id, subject=subject, scopes=scopes, resource=resource)
        self.store.put("access", access, dict(common, token=access, expires_at=int(time.time()) + 3600), 3600)
        self.store.put(
            "refresh", refresh, dict(common, token=refresh, expires_at=int(time.time()) + SESSION_TTL), SESSION_TTL
        )
        return OAuthToken(
            access_token=access, refresh_token=refresh, token_type="Bearer", expires_in=3600, scope=" ".join(scopes)
        )

    async def exchange_authorization_code(self, client, authorization_code):
        saved = self.store.get("code", authorization_code.code, consume=True)
        if not saved or saved["client_id"] != client.client_id:
            raise TokenError("invalid_grant", "Authorization code expired or already used")
        return self._issue(client.client_id, saved["subject"], saved["scopes"], saved.get("resource"))

    async def load_refresh_token(self, client, refresh_token):
        saved = self.store.get("refresh", refresh_token)
        if saved and saved["client_id"] == client.client_id:
            return RefreshToken.model_validate(saved)
        return None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        saved = self.store.get("refresh", refresh_token.token, consume=True)
        if not saved or saved["client_id"] != client.client_id or not set(scopes).issubset(saved["scopes"]):
            raise TokenError("invalid_grant", "Refresh token expired or already used")
        return self._issue(client.client_id, saved["subject"], scopes, saved.get("resource"))

    async def load_access_token(self, token):
        saved = self.store.get("access", token)
        if saved and self.store.get("user", saved["subject"]):
            return AccessToken.model_validate(saved)
        return None

    async def revoke_token(self, token):
        self.store.delete("refresh" if isinstance(token, RefreshToken) else "access", token.token)

    def session(self):
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
        if not token or not token.subject:
            raise PermissionError("Authenticated Lanhu user required")
        user = self.store.get("user", token.subject)
        if not user:
            raise PermissionError("Lanhu session expired; authorize again")
        return token.subject, user

    def get_routes(self, mcp_path=None):
        routes = [r for r in super().get_routes(mcp_path) if r.path != "/revoke"]
        return routes + [
            Route("/revoke", self.revoke_endpoint, methods=["POST"]),
            Route("/login", self.login_page, methods=["GET", "POST"]),
            Route("/", self.home),
            Route("/healthz", lambda request: JSONResponse({"status": "ok"})),
        ]

    async def revoke_endpoint(self, request):
        # SDK 1.30's revocation model incorrectly requires client_secret for public clients.
        from mcp.server.auth.middleware.client_auth import ClientAuthenticator, AuthenticationError

        try:
            client = await ClientAuthenticator(self).authenticate_request(request)
        except AuthenticationError:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        form = await request.form()
        token = str(form.get("token", ""))
        if not token:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        for kind in ("access", "refresh"):
            saved = self.store.get(kind, token)
            if saved and saved["client_id"] == client.client_id:
                self.store.delete(kind, token)
        return JSONResponse({}, headers={"Cache-Control": "no-store"})

    async def home(self, request):
        return HTMLResponse(
            '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>蓝湖 MCP</title><h1>蓝湖 MCP</h1><p>在支持 OAuth 的 MCP 客户端添加此地址，客户端会自动打开登录授权页：</p><code>'
            + html.escape(self.public_url)
            + "/mcp</code></html>",
            headers={"Cache-Control": "no-store"},
        )

    def _page(self, tx, csrf, client, error="", status=200):
        name = html.escape((client.client_name or "MCP 客户端")[:100])
        # Explicitly show the destination so a misleading DCR name cannot hide it.
        pending = self.store.get("pending", tx) or {}
        callback_uri = str(pending.get("params", {}).get("redirect_uri", ""))
        redirect = html.escape(callback_uri[:300])
        body = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>授权连接蓝湖 MCP</title>
<style>body{margin:0;background:#f4f6fb;color:#18213a;font:16px/1.6 system-ui,sans-serif}main{box-sizing:border-box;max-width:460px;margin:7vh auto;padding:36px;background:white;border:1px solid #e3e8f2;border-radius:20px;box-shadow:0 20px 60px #2333500a}small{color:#64718a}h1{font-size:26px;line-height:1.3}label{display:block;margin-top:18px}input{box-sizing:border-box;display:block;width:100%;padding:12px;border:1px solid #cdd5e4;border-radius:8px;font:inherit}button{width:100%;padding:13px;margin-top:24px;border:0;border-radius:8px;background:#2867ed;color:white;font:inherit;cursor:pointer}.error{color:#b3261e}code{overflow-wrap:anywhere;font-size:12px}p{margin:16px 0}.cancel{background:#edf1f7;color:#34435d;margin-top:10px}@media(max-width:500px){main{margin:20px 12px;padding:24px}}</style></head><body><main>
<small>LANHU · MCP 授权</small><h1>连接你的蓝湖账号</h1><p><strong>CLIENT</strong> 请求使用你的蓝湖权限读取项目、需求与设计资源，并使用项目协作工具。</p><small>回调地址：<code>REDIRECT</code></small><p>仅能访问该蓝湖账号有权访问的数据。账号密码仅用于本次向蓝湖验证，不会保存；授权会话有效期为 7 天。</p><p class="error" role="alert">ERROR</p>
<form method="post" action="/login"><input type="hidden" name="tx" value="TX"><input type="hidden" name="csrf" value="CSRF"><label>蓝湖手机号或邮箱<input name="account" autocomplete="username" maxlength="254" required></label><label>密码<input type="password" name="password" autocomplete="current-password" maxlength="200" required></label><button name="action" value="allow">登录蓝湖并授权</button><button class="cancel" name="action" value="deny" formnovalidate>取消授权</button></form><p><small>本服务为第三方集成。需要验证码、企业 SSO 或手机号验证时，请先在蓝湖官网完成相应操作。</small></p></main></body></html>"""
        for key, value in [
            ("CLIENT", name),
            ("REDIRECT", redirect),
            ("ERROR", html.escape(error)),
            ("TX", html.escape(tx)),
            ("CSRF", html.escape(csrf)),
        ]:
            body = body.replace(key, value)
        response = HTMLResponse(
            body,
            status_code=status,
            headers={
                "Cache-Control": "no-store",
                # no-referrer makes browsers serialize a same-origin POST's Origin as null.
                # same-origin preserves the form's Origin without leaking tx to OAuth callbacks.
                "Referrer-Policy": "same-origin",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
                "X-Content-Type-Options": "nosniff",
            },
        )
        response.set_cookie(
            "lanhu_csrf",
            csrf,
            secure=self.public_url.startswith("https:"),
            httponly=True,
            samesite="lax",
            max_age=600,
            path="/login",
        )
        return response

    def _return_to_client(self, destination):
        # Commit a document before navigating: Chromium checks every HTTP redirect
        # after a form POST against form-action, including client-owned redirects.
        # The destination comes only from the validated authorization transaction.
        escaped = html.escape(destination, quote=True)
        return HTMLResponse(
            '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
            f'<meta http-equiv="refresh" content="0;url={escaped}">'
            '<title>返回 MCP 客户端</title></head><body><p>正在返回 MCP 客户端…</p>'
            f'<a href="{escaped}" rel="noreferrer">点击返回客户端</a></body></html>',
            headers={
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
                "X-Content-Type-Options": "nosniff",
            },
        )

    async def login_page(self, request):
        if request.method == "POST":
            if int(request.headers.get("content-length", "0")) > 8192:
                return HTMLResponse("Request too large", status_code=413)
            form = await request.form(max_fields=8, max_files=0)
            tx = str(form.get("tx", ""))
        else:
            form = None
            tx = request.query_params.get("tx", "")
        pending = self.store.get("pending", tx)
        if not pending:
            return HTMLResponse("授权请求已过期，请返回 MCP 客户端重新连接。", status_code=400)
        client = await self.get_client(pending["client_id"])
        if not client:
            return HTMLResponse("Unknown client", status_code=400)
        if form is None:
            csrf = secrets.token_urlsafe(32)
            self.store.put("csrf", tx, csrf, 600)
            return self._page(tx, csrf, client)
        csrf = str(form.get("csrf", ""))
        saved_csrf = self.store.get("csrf", tx)
        origin = request.headers.get("origin")
        if (
            not saved_csrf
            or not secrets.compare_digest(csrf, saved_csrf)
            or not secrets.compare_digest(csrf, request.cookies.get("lanhu_csrf", ""))
            or (origin and origin != self.public_url)
        ):
            return HTMLResponse("授权校验失败，请返回客户端重试。", status_code=403)
        params = pending["params"]
        if form.get("action") == "deny":
            self.store.get("pending", tx, consume=True)
            return self._return_to_client(
                redirect_with(params["redirect_uri"], error="access_denied", state=params["state"])
            )
        # Bound failed login attempts per authorization transaction and remote IP.
        remote = request.client.host if request.client else "unknown"
        for key, limit in [(tx, 5), ("ip:" + remote, 30)]:
            attempts = self.store.get("attempts", key) or 0
            if attempts >= limit:
                return self._page(tx, csrf, client, "尝试次数过多，请稍后重新授权。", 429)
            self.store.put("attempts", key, attempts + 1, 600)
        try:
            user = await login(str(form.get("account", "")).strip(), str(form.get("password", "")))
        except LoginError as exc:
            return self._page(tx, csrf, client, str(exc), 400)
        except (httpx.HTTPError, ValueError, KeyError):
            return self._page(tx, csrf, client, "蓝湖暂时无法连接，请稍后重试。", 502)
        if not self.store.get("pending", tx, consume=True):
            return HTMLResponse("授权请求已使用，请重新连接。", status_code=400)
        # A grant has its own identity, so reauthorizing one client does not replace another's cookies.
        subject = secrets.token_hex(24)
        self.store.put("user", subject, user, SESSION_TTL)
        code = secrets.token_urlsafe(40)
        record = dict(
            params,
            code=code,
            scopes=params.get("scopes") or ["lanhu"],
            expires_at=time.time() + 120,
            client_id=client.client_id,
            subject=subject,
        )
        self.store.put("code", code, record, 120)
        self.store.delete("csrf", tx)
        return self._return_to_client(
            redirect_with(params["redirect_uri"], code=code, state=params["state"])
        )
