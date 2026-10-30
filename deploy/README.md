# 多用户 MCP OAuth 部署

客户端只需添加 `https://lanhu.mcp.paxcq.com/mcp`。支持 MCP OAuth 的客户端收到 401 后，通过发现接口注册自身并打开网页登录；用户输入蓝湖手机号/邮箱、密码，明确确认授权后返回客户端。使用 Authorization Code + PKCE S256，访问令牌 1 小时，刷新令牌轮换，授权最长 7 天。

蓝湖接口为当前网页版 SSO 接口：RSA PKCS1v15 加密密码 → `/api/passport/login` → `/api/auth` 兑换 Cookie → `/api/account/entry` 验证身份。密码不落盘、不出现在 MCP 工具参数中。需要安全验证、手机号绑定、企业 SSO 或扫码时，当前流程提示用户先在蓝湖官网处理；它不绕过验证码，也没有声称蓝湖提供第三方 OAuth。客户端使用的是本服务提供的 OAuth。

## 启动

1. 将项目放到服务器 `/opt/lanhu-mcp`。
2. 在 `deploy/.env` 写入 `LANHU_AUTH_KEY=<Fernet 密钥>`，权限设为 600，备份密钥。
3. `docker compose -f deploy/compose.oauth.yml up -d --build`。
4. 让域名指向服务器，申请证书，使用 `deploy/nginx.conf` 配置反向代理。
5. Docker 仅发布 `127.0.0.1:5188`，对外通过 HTTPS 访问。

健康检查 `/healthz`，授权元数据 `/.well-known/oauth-authorization-server`，保护资源元数据 `/.well-known/oauth-protected-resource/mcp`。`/mcp` 未登录返回 401 和授权发现地址。

每次授权有独立会话、文件目录、元数据缓存和设计资源服务；不回退到管理员 Cookie。SQLite 内的 OAuth 客户端、蓝湖 Cookie 和令牌记录使用 Fernet 加密，查找键使用 SHA256，令牌不记录在 URL 中。`data/auth/oauth.sqlite3` 与密钥需要共同备份。无需配置全局 `LANHU_COOKIE`。

配置示例：

```json
{"mcpServers":{"lanhu":{"url":"https://lanhu.mcp.paxcq.com/mcp"}}}
```

客户端必须支持远程 HTTP MCP OAuth。仅支持静态 Bearer 或 stdio 的客户端不会自动弹出授权网页。原来的本地 stdio/Cookie 用法保持不变，不要在本地 stdio 模式启用 `LANHU_AUTH_ENABLED`。

## 运维

查看状态：`docker compose -f deploy/compose.oauth.yml ps`。
查看日志：`docker compose -f deploy/compose.oauth.yml logs --tail=100`。
升级：上传源码后重新执行启动命令，保留 `data` 与 `deploy/.env`。
终止授权可通过 OAuth `/revoke` 撤销相应令牌；清空授权数据库或更换密钥会使全部授权失效。

当前不提供蓝湖扫码/短信交互，也不实现 OAuth client ID metadata URL；采用动态客户端注册。上线需使用真实蓝湖账号完成一次端到端验证，自动测试使用模拟蓝湖响应，避免对真实账号发起登录操作。

## Cursor 登录后提示 CSP form-action 拦截

若浏览器控制台出现 `Sending form data ... violates ... form-action`，这是授权网页的导航被浏览器拦截，不能据此判断蓝湖账号或密码错误。Chromium 会检查表单提交后的整条 HTTP 重定向链；即使已允许客户端回调域名，客户端后续跨域跳转仍可能触发拦截。

登录与取消授权均先返回本站中转页，再自动导航至经过校验的客户端回调地址，并提供手动返回链接。上传更新后的源码，执行 `docker compose -f deploy/compose.oauth.yml up -d --build`，然后从 Cursor 重新发起连接，使用新的授权页面。无需关闭浏览器 CSP。
