"""Lanhu's current web SSO protocol, verified against its production frontend."""

import base64
import logging
from urllib.parse import urlsplit, parse_qs, urljoin
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# SSO tickets travel in an upstream query string; keep transport URLs out of logs.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

PUBLIC_KEY = b"""-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAuOPxjgRR1vm2WCmVFlBa8SsaFo4F1dHg3ArwdPt7sbmK/suiRT41
9bYL5ya40bxDUxUswmvh+9LePK9KGONC+3zHY//ggCh5ldiVIjCke+38EWOkq4h8
sCf/Nl21ZetdMsPyjgBgEoABTw3qj01u3/9DKIa7opc5+Euq5ORNVxk23LRE4hjP
AzjKgmRBFl+g2lmxVcfw6cW8tGIlmynaVO9a2i8ITES/zsXPxziODGu0gq0PZFOm
2gihnttAV4Fuqcnu1Bb48Me3U4YjBp5r3Q33rJRMVwZxtUCF+UFZsO7WpH4f4Jxz
I/bFoBsL0IEbxyI+jeootPrcbEk2fllbeQIDAQAB
-----END RSA PUBLIC KEY-----"""


class LoginError(Exception):
    pass


async def login(account: str, password: str) -> dict:
    if not account or not password or len(account) > 254 or len(password.encode()) > 245:
        raise LoginError("请输入有效的蓝湖账号和密码。")
    encrypted = serialization.load_pem_public_key(PUBLIC_KEY).encrypt(password.encode(), padding.PKCS1v15())
    async with httpx.AsyncClient(
        timeout=25,
        follow_redirects=False,
        headers={
            "User-From": "lanhuapp",
            "Referer": "https://lanhuapp.com/sso/",
            "User-Agent": "Mozilla/5.0",
            "request-from": "web",
        },
    ) as client:
        response = await client.post(
            "https://lanhuapp.com/api/passport/login",
            json={
                "mobile_or_email": account,
                "password": base64.b64encode(encrypted).decode(),
            },
        )
        response.raise_for_status()
        body = response.json()
        if body.get("code") != 0:
            if body.get("code") in (2401, 2403):
                raise LoginError("蓝湖要求安全验证，请先在蓝湖官网完成验证后重试。")
            raise LoginError("蓝湖登录失败，请检查账号密码或在蓝湖官网确认账号状态。")
        data = body.get("data") or {}
        if data.get("auth_mobile"):
            raise LoginError("蓝湖要求绑定或验证手机号，请先在官网完成后重试。")
        if not data.get("ticket"):
            raise LoginError("蓝湖未返回登录票据，请重试。")
        response = await client.get(
            "https://lanhuapp.com/api/auth",
            params={
                "request_from": "web",
                "sso_ticket": data["ticket"],
                "redirect_uri": "https://lanhuapp.com/dashboard/",
                "action": data.get("action", "login"),
                "action_type": data.get("action_type", "password"),
            },
        )
        # The dashboard also supports receiving sso_token in its redirect URL.
        if response.status_code not in (200, 301, 302, 303, 307, 308):
            raise LoginError("蓝湖会话兑换失败，请重试。")
        location = response.headers.get("location", "")
        if location:
            target = urlsplit(urljoin("https://lanhuapp.com", location))
            if target.scheme != "https" or target.hostname not in ("lanhuapp.com", "www.lanhuapp.com"):
                raise LoginError("蓝湖返回了无效的会话跳转地址。")
            params = parse_qs(target.query)
            params.update(parse_qs(target.fragment.partition("?")[2]))
            token = (params.get("sso_token") or [None])[0]
            if token:
                client.cookies.set("user_token", token, domain=".lanhuapp.com", path="/")
        cookie = "; ".join(
            f"{c.name}={c.value}"
            for c in client.cookies.jar
            if c.domain.lstrip(".") in ("lanhuapp.com", "www.lanhuapp.com")
        )
        if not cookie:
            raise LoginError("蓝湖未签发会话，请重试。")
        response = await client.get("https://lanhuapp.com/api/account/entry", headers={"Cookie": cookie})
        response.raise_for_status()
        profile = response.json()
        user = profile.get("data") or profile.get("result") or {}
        uid = user.get("id") or user.get("user_id")
        if str(profile.get("code")) not in ("0", "00000") or not uid:
            raise LoginError("无法验证蓝湖用户身份，请重试。")
        return {"subject": str(uid), "cookie": cookie, "name": str(user.get("name") or user.get("username") or account)}
