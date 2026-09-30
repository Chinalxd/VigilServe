"""网络设备「WEB管理」页签的服务端反向代理（方案 B）——独立源部署形态。

为什么单独一个进程（2026-09-20 定稿）
--------------------------------------
代理回来的设备页面跟我们主站是**同一个源**时，只能靠 iframe `sandbox` 去掉
`allow-same-origin` 来防它读 `parent.localStorage` 里的管理员令牌。沙箱能防住
嵌入式访问，**防不住"新窗口打开"**——那是顶层窗口，跟主站同源，设备页面（万一被
入侵）可以直接读走令牌。

根治办法只有一个：让代理**换一个源**。本模块就是把 `routes/network_web.py` 里
那套代理逻辑挂到独立端口（默认 8009）上重建一个极小 app：

    https://<本机>:8009/web/{ticket}/…            ← 跨源，读不到主站 localStorage

复用而非重写
------------
路由实现一行都不复制：直接 import `routes.network_web` 里的 handler，注册到本 app
上。`raw_prefix` 也显式改成 `"/web/"`——票据仍然落在**路径首段**（这条不能动，
`<base>` 带不了 query，改了就退化成 ORB 白屏，见 network_web 模块顶部说明）。

鉴权
----
票据里的 `server_id` 是签名载荷的一部分，`verify()` 比对的就是它。但本 app 的
`/web/{ticket}/…` 里没有 `{server_id}` 路径参数，所以 `_user_from_ticket()` 里
那次比对会恒失败。做法是在本模块内**重挂一层**：

  * `network_web.PROXY_ID_FROM_TICKET = True`（模块级开关，只影响本进程）
  * `_user_from_ticket` 走 `ticket_lib.peek_server_id()` 取 server_id 再校验

主进程不打开这个开关，行为一字不变。

TLS
---
默认复用主服务端那把**同一 CA 签出**的证书（`services/tls.py`），所以浏览器只需
信任一次；而"自签名/未信任证书"在跨源 iframe 里会被**静默拦截**（没有"继续访问"
可点），所以另设 `VIGILSERVE_WEBPROXY_TLS=0` 可退回 HTTP —— 仅在明确知道自己
在干什么（例如前端也是 http）时使用。
"""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.gzip import GZipMiddleware

from routes import network_web
from services import net_guard

logger = logging.getLogger("backend.webproxy")

DEFAULT_PORT = 8009


def _proxy_port() -> int:
    try:
        port = int(os.environ.get("VIGILSERVE_WEBPROXY_PORT", DEFAULT_PORT))
    except ValueError:
        port = DEFAULT_PORT
    return port if 1 <= port <= 65535 else DEFAULT_PORT


DEFAULT_PREFIX = "/web/"


async def _bare_web_hint():
    """没有票据的裸访问：给一句人话，而不是一屏 404。"""
    return Response(
        content="缺少访问票据：请从主站「设备管理 - 网络设备 - WEB管理」进入。",
        status_code=401, media_type="text/plain; charset=utf-8",
    )


def create_app() -> FastAPI:
    """建独立源的代理 app：只有 /web/{ticket}/… 与 /healthz 两条路。"""
    # 🔑 本进程内允许"从票据里取 server_id"（主进程不开，行为不变）
    network_web.PROXY_ID_FROM_TICKET = True
    prefix = (os.environ.get("VIGILSERVE_WEBPROXY_PREFIX") or DEFAULT_PREFIX).strip() or DEFAULT_PREFIX
    if not prefix.startswith("/"):
        prefix = "/" + prefix
    if not prefix.endswith("/"):
        prefix += "/"
    os.environ["VIGILSERVE_WEBPROXY_PREFIX"] = prefix
    route = prefix + "{path:path}"

    app = FastAPI(
        title="VigilServe Network Web Proxy",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(GZipMiddleware, minimum_size=500)

    # 只对代理路径放行跨源预检（设备页在我们的独立源里仍是沙箱 iframe，
    # 源还是 null，XHR 照样要预检）——见 network_web.WebProxyCorsMiddleware 的说明
    network_web.install_preflight(app)

    # 来源白名单（2026-09-23 动态审计 D-2）：放在最后 = 最外层，比上面的
    # 跨源预检中间件更早生效。未配 VIGILSERVE_ALLOWED_CIDRS 时不介入。
    app.add_middleware(net_guard.make_source_guard_middleware())

    @app.get("/healthz")
    async def healthz():
        return JSONResponse({"ok": True, "service": "network-web-proxy"})

    app.add_api_route(
        route,
        network_web.web_proxy,
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        name="network-web-proxy",
    )
    app.add_api_route(prefix.rstrip("/"), _bare_web_hint, methods=["GET"], include_in_schema=False)

    @app.get("/")
    async def root_hint():
        return Response(
            content="VigilServe 网络设备 WEB 管理代理。请从主站「设备管理 - 网络设备 - WEB管理」进入，"
                    "不要直接访问这个地址（没有票据打不开任何设备页面）。",
            media_type="text/plain; charset=utf-8",
        )

    # ⚠️ 兜底路由必须**最后**注册 —— `/{path:path}` 连根路径都能匹配，放前面会把
    # 上面几条全吃掉。
    # 设备 JS 用 `location.hostname` 硬拼绝对地址时（华为登录成功后跳首页就是这么干的），
    # 路径里的 `/web/<ticket>/` 会被丢掉。前端拦不住（Chrome 的 location.href 是
    # 不可伪造属性，原型补丁静默失效），只能在这里按 Referer 把票据捞回来再重定向。
    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        include_in_schema=False,
    )
    async def lost_ticket_fallback(path: str, request: Request):
        if os.environ.get("VIGILSERVE_WEBPROXY_DEBUG"):
            logger.warning(f"[DBG] {path} headers={dict(request.headers)}")
        fixed = network_web.recover_redirect(request, path)
        if fixed is not None:
            return fixed
        # 拿不到 Referer 时（沙箱 iframe 是不透明源，Chrome 不发）退到客户端自救：
        # 给一页会自己从 window.name 把票据补回来的 HTML —— 但只给**导航**，
        # XHR 拿到 HTML 会让设备 JS 解析失败，那种还是老实 401。
        if network_web.is_navigation(request):
            return network_web.lost_ticket_page()
        return await _bare_web_hint()

    return app


# 模块级 app 实例必须在 create_app() 之后建（uvicorn 若不传对象就会来找它）
app = create_app()


def _tls_kwargs() -> dict:
    """复用主服务端的本地 CA 证书；`VIGILSERVE_WEBPROXY_TLS=0` 可退回 HTTP。"""
    if os.environ.get("VIGILSERVE_WEBPROXY_TLS", "1") != "1":
        logger.warning("[WebProxy] 已通过 VIGILSERVE_WEBPROXY_TLS=0 关闭 TLS，以 HTTP 提供服务")
        return {}
    try:
        from services import tls as _tls

        if not _tls.tls_enabled():
            return {}
        info = _tls.ensure_server_cert()
        logger.info(f"[WebProxy] HTTPS 已启用，SAN={info.get('sans')}")
        return {"ssl_certfile": info["server_cert"], "ssl_keyfile": info["server_key"]}
    except Exception as e:  # noqa: BLE001
        # 证书准备失败时不静默降级成 HTTP：那会让浏览器里的跨源 iframe 直接空白，
        # 而且"为什么空白"极难看出来。宁可起不来，日志里说清楚。
        logger.error(f"[WebProxy] 证书准备失败：{e}")
        raise


if __name__ == "__main__":
    import uvicorn

    _port = _proxy_port()
    # 2026-09-23 动态审计 D-2：监听地址可配（VIGILSERVE_BIND_HOST），默认仍 0.0.0.0。
    _host = net_guard.bind_host()
    logger.info(f"[WebProxy] 独立源代理启动于 {_host}:{_port}，前缀 "
                f"{(os.environ.get('VIGILSERVE_WEBPROXY_PREFIX') or DEFAULT_PREFIX)}{{ticket}}/…")
    # proxy_headers=False：关掉 uvicorn 自带的 ProxyHeadersMiddleware。否则它会按
    # X-Forwarded-For 改写 ASGI scope 里的 client，而我们的审计/限速/白名单读的正是
    # 那个值 —— 等于把来源 IP 交给客户端自己填。XFF 的解释权统一归
    # services/client_ip.py（见 backend/main.py 的 _no_proxy_headers_kwargs 说明）。
    uvicorn.run(app, host=_host, port=_port, **_tls_kwargs(), proxy_headers=False)
