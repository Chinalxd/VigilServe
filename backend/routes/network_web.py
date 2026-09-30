"""网络设备「WEB管理」页签的服务端反向代理（方案 B）。

为什么不直接 `<iframe src="https://设备IP">`
-------------------------------------------------
1. 设备的 Web 服务几乎都是**自签名证书**，浏览器会拦 —— 而 iframe 里没有
   "继续访问"的地方可以点；
2. 本系统跑在 HTTPS 上，HTTPS 页面里嵌 HTTP 子框架属于**混合内容**，浏览器直接拦；
3. 不少设备（尤其防火墙）会回 `X-Frame-Options` / `Content-Security-Policy:
   frame-ancestors` **拒绝被嵌**。

走服务端代理，这三条一并解决：

    浏览器 ──同源 https──▶ /api/servers/{id}/web/… ──▶ 设备 http(s)://IP:端口

### 两条必须一起解决的副作用

**① iframe 必须沙箱、且不能给 allow-same-origin。** 代理回来的页面跟我们同源，
给了 allow-same-origin 它就能读 `parent.localStorage`，把管理员登录令牌端走。

**② 但沙箱又不让浏览器存任何 Cookie**（实测：不带 allow-same-origin 的框里，
下发与接收的 Cookie 全部丢弃），而设备界面全靠会话 Cookie 认人。于是：

* 鉴权改用**写在 URL 里的窄票据**（`services/web_proxy_ticket.py`）：只在这一个
  前缀下有效、绑定用户与设备、30 分钟过期，偷到也换不出登录令牌；
* 设备自己的会话 Cookie 由**服务端保管**（`services/web_proxy_cookies.py`），
  浏览器全程不接触，下次转发时替它带上；
* 还差一层：不透明源里读 `document.cookie` / `localStorage` / `sessionStorage`
  **直接抛 SecurityError**，设备页面的脚本一碰就挂（NAS 的登录框整个停在
  `display:none`，页面看着就是白的）。所以注入的 shim 里带一段**存储垫片** ——
  只在原生 API 抛错时补个内存实现，顶层窗口（"新窗口打开"）下原生 API 正常，
  一个字节都不会被改写。垫片纯内存、不落盘，也不改变凭据的存放位置。

### 正文改写

响应里的 X-Frame-Options / CSP / HSTS 一律剥掉（不然嵌不进来），HTML / CSS 里的地址
（绝对地址、根相对 `/x`、相对 `x`、CSS `url()` 与 `@import`、meta refresh 跳转）统一
折算到代理前缀并带上票据，再注入 `<base>` 与一小段 shim。

### 票据为什么必须落在**路径**里（2026-09-20 血泪）

早先票据只写在 query（`?t=…`），并由 shim 给 `fetch` / `XHR` / `sendBeacon` 补上。
**这漏掉了浏览器自己发起的那一大类子资源请求**，典型是 webpack 运行时按 publicPath
动态插进去的分片：

    <script src="{publicPath}dsm.login.bundle.xxx.207.js">
    <link  href="{publicPath}207.style.css">

它们既不经过 shim，也带不上 `?t=`（`<base>` 只能补路径、补不了 query）。代理只好回
401 + `application/json` —— 而 Chrome 的 **ORB（Opaque Response Blocking）** 对
不透明源（沙箱 iframe）发出的 no-cors 脚本/样式请求，看到 JSON/HTML 正文就直接拦：
`net::ERR_BLOCKED_BY_ORB`，页面白屏。NAS 的登录页 100 多个分片全栽在这上面。

所以现在把票据放进**路径首段**：

    /api/servers/2/web/{ticket}/webman/login/dist/207.style.css

好处是 `<base href="/api/servers/2/web/{ticket}/…">` 一改，**所有**相对地址
（webpack 分片、CSS 里相对的 `url()`、JS 里 `fetch('api/x')`）自动带上票据，
不需要逐个 shim。`?t=` 仍然接受（首次进入的那一发、以及"新窗口打开"），
但页内一切后续地址都走路径形态。

安全性不变：票据本来就是写在 URL 里的窄凭据（见 `services/web_proxy_ticket.py`），
路径和 query 的可见性完全一样。

### 另外两个"登录不了"的坑（2026-09-20 真机坐实）

**① 根相对地址不能用本页目录拼。** 做法见 `_map_url`：`/login.cgi` 这类**根相对**
地址必须拼到"票据根"（`{prefix}{ticket}/`），只有 `../util/a.js` 这种**相对**地址才
拼本页目录。华为交换机的 `HTTP.loginUrl = conncetIP + "/login.cgi?"`（`conncetIP`
是空串）就是根相对；拼错后登录 POST 被送到 `/simple/view/login.cgi`，设备回一句
"用户名或密码错误"。

**② 预检会被应用级 CORS 中间件截胡。** 沙箱 iframe 的源是 `null`，设备页的 XHR 全被
浏览器当跨源，先发 `OPTIONS`；而 `main.py` 的 CORSMiddleware 白名单为空（只允许同源），
直接回 `400 Disallowed CORS origin`，**本路由根本没被调用**。设备页探测会话的 XHR 全挂，
脚本走自己的错误分支把 iframe 导航到了我们站点根 —— 表现就是登录页一闪就没。
解法是 `WebProxyCorsMiddleware`（本模块内）挂到最外层，只给这个前缀放行预检；
`main.py` 里在注册完 CORSMiddleware 之后调 `network_web.install_preflight(app)`。

 代理目标**不是**调用方能任意指定的：地址固定是这台设备的管理 IP，协议与端口由
管理员在「主机管理 - 网络设备」里维护，所以不存在"借它扫内网"的问题。
"""
import asyncio
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple

import requests as _requests
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from database import get_db
from models import Server
from routes.auth import require_login, has_perm, can_manage_server
from services import web_proxy_cookies as cookie_jar
from services import web_proxy_ticket as ticket_lib
from services import web_auto_login as auto_login
from services import device_tls_pin
from services.audit_logger import log_operation

logger = logging.getLogger("backend")

router = APIRouter(prefix="/api/servers", tags=["network-web"])

# 连设备走独立会话，且**不认环境里的 HTTP(S)_PROXY**：那些代理是给上外网用的，
# 让它掺一脚会把请求发到互联网出口，换回一句看不懂的 502。requests 默认读
# http_proxy 环境变量，这里必须显式关掉（实测见过 "upstream connect failed"）。
_SESSION = _requests.Session()
_SESSION.trust_env = False

# 连接池必须放大（2026-09-20 实测 NAS 首屏慢）
# webpack 分片，浏览器对它自己的域并发约 6 条，每条都落到我们这条到设备的连接上；
# 池子只有 10 且**用完即阻塞**（pool_block=False 时超出的连接会新建、但旧的不复用），
# 结果是每个分片都在重新做 TLS 握手，叠起来就是"点一下要等好几秒"。
_ADAPTER = _requests.adapters.HTTPAdapter(
    pool_connections=64, pool_maxsize=64, pool_block=False, max_retries=0,
)
_SESSION.mount("http://", _ADAPTER)
_SESSION.mount("https://", _ADAPTER)

# 上限放宽到 128：单台设备首屏可能有几十个并发分片，池子小了又会退化成排队。
_THREAD_POOL = ThreadPoolExecutor(max_workers=128, thread_name_prefix="webproxy")


async def _run_in_thread(fn):
    """在专用线程池里跑阻塞调用；拿不到运行中的 loop 时退回默认执行器。"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_THREAD_POOL, fn)

# 独立源上没有 {server_id} 路径参数，只能从票据里取。**只由那个进程打开**，
# 主进程保持 False，行为一字不变（独立源部署下浏览器读不到主站 localStorage，
# 票据被设备页读走也只能再访问它自己，不构成新增风险）。
PROXY_ID_FROM_TICKET = False

# 读可以慢一点（登录页拉一堆 JS）；连接也不能太快判死，华为交换机的 HTTPS
# 用的是 connect 那个超时），握手一超时我们回 502，设备 JS 就弹「连接服务器失败」。
# 别再调回 5：真机（某台华为交换机）2026-09-21 已复现。
CONNECT_TIMEOUT = 15
READ_TIMEOUT = 25
# 证书指纹探测用与正常连接相同的握手超时，别让设备慢的时候先超时 fasle 判定
device_tls_pin.set_probe_timeout(CONNECT_TIMEOUT)

# 逐跳首部不能往下游传（RFC 7230 §6.1）；Content-Length / Content-Encoding 也一并
# 去掉，我们对正文做过改写，长度和压缩方式都变了，留着会让浏览器解析失败
_DROP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-length", "content-encoding",
    # 这三个是"不许被嵌 / 只允许本域访问"，站在代理的立场上全部作废
    "x-frame-options", "content-security-policy", "content-security-policy-report-only",
    # 设备给自家域名签的 HSTS，套到我们域名上是自找麻烦
    "strict-transport-security",
    "set-cookie",
}

try:  # 自签名证书 unavoidable，别刷屏
    import urllib3

    urllib3.disable_warnings()
except Exception:  # noqa: BLE001
    pass

_URL_ATTR_RE = re.compile(
    r'(\b(?:href|src|action|formaction|poster|data|cite|background)\s*=\s*)(["\'])(.*?)\2',
    re.I | re.S,
)
_CSS_URL_RE = re.compile(r"url\(\s*([\"']?)([^)\"']*)\1\s*\)", re.I)
_CSS_IMPORT_RE = re.compile(r"(@import\s+(?:url\(\s*)?)([\"'])([^\"']+)\2", re.I)
# meta refresh 的 `url=` **只能在 <meta> 标签里找**（2026-09-21 修华为交换机
# 以前这条正则是裸的 `(url\s*=\s*)(...)` 带 re.I 扫**全文**，于是把内联 JS 里的
#，`/web/` 被解析成正则字面量，后面的票据整串成了"标志位"，
_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.I | re.S)
_REFRESH_IN_META_RE = re.compile(r"(\burl\s*=\s*)([^;\"'>]+)", re.I)


# 眼里一律算跨源，没有 CORS 头的话，设备界面里的 AJAX 全部 "Failed to fetch"。
# 这一层只放开代理路径，而且凭据走 URL 票据、不靠 Cookie，所以 `*` 就够、也不涉及
# Cookie 泄露（任何一个网站拿着这个 `*` 也拿不到数据，它没有票据）。
_CORS_HEADERS = {
    # 为什么只能是 `*`，不能换成回显 Origin（交付审查复核结论，2026-09-23）
    # 沙箱 iframe 的文档源是**不透明源**，它发出的请求带的 Origin 头是字面量 `null`。
    # 白名单写法（回显 Origin）在这里会恒不匹配 预检失败 设备页的 XHR 全挂。
    # 所以 `*`（或字面量 `null`）是让沙箱 iframe 能工作的**必要条件**，不是偷懒。
    # 它可控在两点上：① 本中间件只在代理路径前缀上生效（见 WebProxyCorsMiddleware
    # 的 `_PROXY_PATH_RE` 判定），其它接口一律照旧；② 不设
    # Access-Control-Allow-Credentials，所以不存在 Cookie 凭据被跨站带出的可能；
    # 真正的请求仍然必须带 URL 票据。
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Max-Age": "600",
    # 应答随 Origin 变化（此处为通配），不声明 Vary 的话中间缓存/浏览器可能把
    # 给 A 站的应答复用给 B 站。
    "Vary": "Origin",
}

# 早先这里写的是 `unsafe-url`，实测下来它是**纯负收益**（2026-09-23 复核）
# * 而它真正生效的场景是「新窗口打开」的顶层窗口，在那里它会把**含票据的完整
# * 顶层窗口内跳我们自己的代理路径 = 同源 仍发完整 Referer，`recover_redirect()`
_REFERRER_POLICY = "strict-origin-when-cross-origin"

_PROXY_PATH_RE = re.compile(r"^/api/servers/\d+/web/|^/web/")
_CORS_LOWER = [(k.lower().encode("latin-1"), v.encode("latin-1"))
               for k, v in _CORS_HEADERS.items()]


class WebProxyCorsMiddleware:
    """只给「WEB管理」代理路径放行跨源预检，并保证错误响应也带 CORS 头。

 为什么必须盖在应用级 CORSMiddleware **外面**（2026-09-20 血泪）：
    沙箱 iframe 里的文档源是 `null`（不透明源），它发出的 fetch/XHR 在浏览器眼里一律
    跨源，会先发一发 `OPTIONS` 预检。而 `main.py` 那套 CORSMiddleware 白名单是空的
    （只允许同源），预检被它直接截成 `400 Disallowed CORS origin` —— **路由根本轮不到**。
    设备页的会话探测 XHR 因此全挂，脚本走了自己的错误分支，干脆把 iframe 导航到我们
    站点根去了（表现为登录页一闪就没）。华为交换机与 NAS 都栽在这一条上。

    放行范围严格限死在 `/api/servers/{id}/web/` 之下，其它接口一律照旧。预检应答里
    没有任何数据，真正的请求照样要 URL 票据，所以放开它不降低安全性；反过来，代理
    自身的 401/502 也补上 CORS 头，设备页才读得到我们的中文错误提示。
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not _PROXY_PATH_RE.match(scope.get("path") or ""):
            return await self.app(scope, receive, send)

        if scope.get("method") == "OPTIONS":
            await send({"type": "http.response.start", "status": 204,
                        "headers": list(_CORS_LOWER)})
            await send({"type": "http.response.body", "body": b""})
            return

        async def _send(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                if not any(k.lower() == b"access-control-allow-origin" for k, _ in headers):
                    headers.extend(_CORS_LOWER)
            await send(message)

        await self.app(scope, receive, _send)


def install_preflight(app) -> None:
    """挂上 `WebProxyCorsMiddleware`。

 必须在 `app.add_middleware(CORSMiddleware, …)` **之后**调用：Starlette 把每次都
    插到最前面，最后插的才是最外层，只有最外层才拦得住 CORS 中间件。
    """
    app.add_middleware(WebProxyCorsMiddleware)



def _prefix(server_id) -> str:
    """**本进程实际提供服务**的路径前缀（不含票据），只用于拼 `<base>`。

 这里必须回答的问题是"这份 HTML 是从哪个路径下发出去的"，因为相对地址会按
    它去解析。所以只认 `PROXY_ID_FROM_TICKET`（本进程就是独立源代理）→ `/web/`；
    主站进程一律 `/api/servers/{id}/web/`。

 2026-09-20 踩过：一度让主站进程在看见 `VIGILSERVE_WEBPROXY_PORT` 时也返回
    `/web/`，结果主站真被请求到时（旧前端 / 「新窗口打开」），`<base>` 指向主站
    根本不存在的 `/web/` → 回落 SPA 首页 → 登录框全空白。
    「前端该往哪个源发」是另一回事，见 `_frontend_prefix()`。
    """
    if PROXY_ID_FROM_TICKET:
        return _proxy_base_path()
    return f"/api/servers/{int(server_id)}/web/"


def _frontend_prefix(server_id) -> str:
    """前端拼 iframe / 新窗口地址用的路径前缀（接在 `proxy_base_url` 后面）。

    * 配了独立源代理端口 → `/web/`（前端会接到独立源上，不会打到主站）
    * 没配 → 主站同源形态 `/api/servers/{id}/web/`
    """
    if _proxy_port_configured():
        return _proxy_base_path()
    return f"/api/servers/{int(server_id)}/web/"


def _proxy_port_configured() -> bool:
    """是否配置了独立源代理端口（`VIGILSERVE_WEBPROXY_PORT` / `_HINT`）。"""
    for key in ("VIGILSERVE_WEBPROXY_PORT", "VIGILSERVE_WEBPROXY_PORT_HINT"):
        raw = (os.environ.get(key) or "").strip()
        if raw:
            try:
                if 1 <= int(raw) <= 65535:
                    return True
            except ValueError:
                pass
    return False


def _proxy_base_path() -> str:
    """独立源进程用的前缀，由 `VIGILSERVE_WEBPROXY_PREFIX` 指定（默认 `/web/`）。"""
    custom = (os.environ.get("VIGILSERVE_WEBPROXY_PREFIX") or "").strip()
    if not custom:
        custom = "/web/"
    return custom if custom.endswith("/") else custom + "/"


def _raw_prefix(base_href: str) -> str:
    """从带票据的 base 里剥出**不含票据**的前缀，给 shim 判"这已经是我们代理的地址"。

 两种形态都要剥对（2026-09-20 血泪）：
      * 主站同源：`/api/servers/3/web/<ticket>/…` → `/api/servers/3/web/`
      * 独立源  ：`/web/<ticket>/…`             → `/web/`

    剥错的后果不是"少补一次前缀"，而是**反复叠加**：设备请求 `/web/<t>/config.cgi`
    落在本页目录**之外**，判重失败 → shim 每过一次钩子（fetch / XHR / setAttribute）
    就再叠一层 → 真机日志里就是
    `/web/<t>/web/<t>/web/<t>/config.cgi` → 400 → 设备弹「系统超时或用户已被下线」。
    """
    m = _RAW_PREFIX_RE.match(base_href)
    if m:
        return m.group(1)
    m2 = re.match(r"^(/[^/]+/web/)", base_href)
    if m2:
        return m2.group(1)
    m3 = re.match(r"^(.*?/web/)[^/]+/", base_href)
    return m3.group(1) if m3 else base_href


def _target(server) -> Tuple[str, str, int]:
    """这台设备的 WEB 管理入口：(协议, 地址, 端口)。"""
    scheme = (server.web_protocol or "https").strip().lower()
    if scheme not in ("http", "https"):
        scheme = "https"

    host = (server.ip_address or "").strip()
    host = re.sub(r"^https?://", "", host, flags=re.I).split("/")[0].strip()
    port = int(server.web_port or 443)
    if not host.startswith("[") and ":" in host:
        _h, _, _p = host.partition(":")
        host = _h
        try:
            if _p:
                port = int(_p)
        except ValueError:  # noqa: BLE001
            pass
    if not (1 <= port <= 65535):
        port = 443
    return scheme, host, port



def _map_url(raw: str, base_href: str, root_href: str, host: str) -> Optional[str]:
    """把一个页面内的地址折算到代理前缀下；不需要改写就返回 None。

    两个基准**不能混用**（2026-09-20 血泪）：
      * `root_href` = `带票据的前缀 + "/"` —— 给**根相对**地址（`/login.cgi`）和
        **绝对**地址用。根相对是相对**站点根**解析的，拼上本页目录就错了。
      * `base_href` = `带票据的前缀 + 本页所在目录` —— 只给**相对**地址（`../util/a.js`）用。

    华为交换机的 `HTTP.loginUrl = conncetIP + "/login.cgi?"`（`conncetIP` 是空串）就是
    根相对；早先两边都按 `base_href` 拼，登录 POST 被送到 `/simple/view/login.cgi`，
    设备回一句"用户名或密码错误"。
    """
    url = (raw or "").strip()
    if not url:
        return None
    low = url.lower()
    if low.startswith(("#", "data:", "javascript:", "mailto:", "tel:", "about:", "blob:")):
        return None
    if low.startswith("//") or re.match(r"^https?://", low):
        m = re.match(r"^(?:https?:)?//([^/]*)(/.*)?$", url, re.I)
        if not m:
            return None
        authority = m.group(1).split("@")[-1]
        if authority.split(":")[0].lower() != host.lower():
            return None
        return root_href + (m.group(2) or "/").lstrip("/")
    if url.startswith("/"):
        return root_href + url.lstrip("/")
    return base_href + url


def _rewrite_html(body: bytes, base_href: str, root_href: str, host: str,
                  fragment: bool = False) -> bytes:
    """把设备页面里的地址全部折算到代理前缀（路径自带票据），并补上 <base> 与 shim。

 `fragment=True`（2026-09-21 修华为交换机"只剩菜单 / 连接服务器失败"）：
       设备会 **XHR 拉一个 HTML 片段**再塞进主页面 —— 例如
       `/simple/view/dashboard/dashboard/getScriptXXX.html` 里写着
       `<script src="../../lib/dashboard/dashboard/dashboardLib.js">`。

       片段里的相对地址**不是按片段自己的目录解析的**：它被插进 main.html 之后，
       浏览器按**主页面的 base**（`/simple/view/main/`）解析，`../../` 才退得到
       `/simple/` —— 直连时设备没有 `<base>`，文档 base 就是 main.html 的目录，
       所以设备上是对的。

       我们原先按**片段自己的目录**拼前缀（`base_dir` 取自被请求路径），等于少退一层：
       `/web/<票>/simple/view/dashboard/dashboard/` + `../../lib/...`
         → `/web/<票>/simple/view/lib/...` → 设备 404 → 我们回一个 **HTML 错误页** →
       设备 JS 把它当脚本 eval → `Invalid regular expression flags` → SPA 当场死，
       于是"只剩菜单"；再点菜单就是「连接服务器失败」。

       所以片段**只改写绝对 / 根相对地址**，相对地址原样返回给浏览器自己解析；
       并且**不注入 `<base>` 和 shim**（片段被插进 DOM 会污染主页面的 base）。
    """
    enc = "utf-8"
    m = re.search(rb"charset=[\"']?([\w-]+)", body[:4096], re.I)
    if m:
        enc = m.group(1).decode("ascii", "ignore")
    try:
        text = body.decode(enc, errors="surrogateescape")
    except LookupError:
        enc, text = "utf-8", body.decode("utf-8", errors="surrogateescape")

    def _map_here(raw: str) -> Optional[str]:
        """片段里的相对地址**不改写**（原因见函数头注释）。"""
        if fragment:
            low = (raw or "").strip().lower()
            if low and not low.startswith("/") and not re.match(r"^(?:https?:)?//", low):
                return None
        return _map_url(raw, base_href, root_href, host)

    def _attr(mo):
        mapped = _map_here(mo.group(3))
        if mapped is None:
            return mo.group(0)
        return f"{mo.group(1)}{mo.group(2)}{mapped}{mo.group(2)}"

    def _css(mo):
        mapped = _map_here(mo.group(2))
        if mapped is None:
            return mo.group(0)
        return f"url({mo.group(1)}{mapped}{mo.group(1)})"

    def _meta(mo):
        """只改 `<meta http-equiv="refresh" content="...url=...">` 里的跳转地址。"""
        tag = mo.group(0)
        if not re.search(r"http-equiv\s*=\s*[\"']?refresh", tag, re.I):
            return tag

        def _u(u):
            mapped = _map_here(u.group(2))
            return u.group(1) + (mapped if mapped is not None else u.group(2))

        return _REFRESH_IN_META_RE.sub(_u, tag)

    text = _URL_ATTR_RE.sub(_attr, text)
    text = _CSS_URL_RE.sub(_css, text)
    text = _META_TAG_RE.sub(_meta, text)

    # 注入 <base> 与 shim：base 管住运行期拼出来的相对地址，shim 给脚本发起的请求补前缀
    inject = (f'<base href="{base_href}">'
              + _SHIM_TMPL.replace("__BASE__", json.dumps(base_href))
                          .replace("__ROOT__", json.dumps(root_href))
                          .replace("__PREFIX__", json.dumps(_raw_prefix(base_href))))
    if fragment:
        # 片段会被插进主页面：注入 <base> 会改掉主页面的文档 base，shim 也会被重复装一遍
        pass
    elif "<base" not in text[:4096].lower():
        head = re.search(r"<head[^>]*>", text, re.I)
        if head:
            text = text[: head.end()] + inject + text[head.end():]
        else:
            text = inject + text

    if enc.lower() not in ("utf-8", "utf8"):
        # 改过编码了，页面里的 charset 声明得跟着改，否则浏览器按老编码解出乱码
        text = re.sub(
            r"(charset=[\"']?)" + re.escape(enc), lambda mo: mo.group(1) + "utf-8",
            text, count=2, flags=re.I,
        )
    return text.encode("utf-8", errors="surrogateescape")


_RAW_PREFIX_RE = re.compile(r"^(/api/servers/\d+/web/)")
# 这里原本还有**第二份 `_raw_prefix()`**（只认上面这条主站正则），
# 同名把上面那份覆盖掉了（Python 取最后定义），独立源形态下它就原样返回 base_href，
# 于是 shim 的 `R` 变成"整页目录"，判重失效、票据被反复叠加。
# 已于 2026-09-20 删除，只保留上面那一份（两种形态都剥）。改这块代码时**别再写第二份**。


_TICKET_IN_PATH_RE = re.compile(r"/web/([A-Za-z0-9._\-]+)(?:/|$)")


def ticket_from_referer(request: Request) -> Optional[str]:
    """从 Referer 里把票据捞回来。

    设备 JS 常拿 `location.hostname` 硬拼绝对地址 —— 华为登录成功后跳首页就是
    `"https://" + location.hostname + port + "/simple/view/main/main.html"`，
    host 是代理源自己，路径却是设备路径，`/web/<ticket>/` 就这么被丢了。
 前端拦不住：Chrome 的 `location.href` 是**不可伪造属性**，原型补丁无效
    （见 `install_preflight` 上面那段注释）。但导航请求一定会带 Referer，
    里面有上一页的完整路径 —— 票据就在那儿。

    验签后再用（`peek_server_id` 会校 HMAC 和有效期），不信任 Referer 本身。
    """
    ref = (request.headers.get("referer") or request.headers.get("referrer") or "").strip()
    if not ref:
        return None
    for m in _TICKET_IN_PATH_RE.finditer(ref):
        t = m.group(1)
        if ticket_lib.peek_server_id(t) is not None:
            return t
    return None


def recover_redirect(request: Request, path: str) -> Optional[Response]:
    """票据被设备 JS 拼丢的导航请求 → 补回带票据的路径，307 重定向。

    命中返回 `RedirectResponse`，没命中返回 None（交给调用方走它自己的兜底）。
    用 307 是为了保住方法：表单提交也可能是被拼丢地址的 POST。
    """
    ticket = ticket_from_referer(request)
    if not ticket:
        return None
    sid = ticket_lib.peek_server_id(ticket)
    if not sid:
        return None
    prefix = _proxy_base_path() if PROXY_ID_FROM_TICKET \
        else f"/api/servers/{int(sid)}/web/"
    target = f"{prefix}{ticket}/{path.lstrip('/')}"
    if request.url.query:
        target += "?" + request.url.query
    logger.info(f"[WebAdmin] 票据被设备 JS 拼丢，按 Referer 补回：{target}")
    return RedirectResponse(target, status_code=307)


# 2026-09-20 真机实测：沙箱 iframe（不给 allow-same-origin）是**不透明源**，
# 剩下这条路只能靠 `window.name`：它跟着**浏览上下文**走，同一框架里跨任意次导航
# 都还在，且不透明源里照样能读写（不像 cookie / localStorage）。shim 每页开头都会
# 把票据根写进去，丢了票据的那次跳转落地后再读回来拼成完整路径。
_RECOVER_NAME_JS = (
    "(function(){try{"
    "var n=window.name||'';if(!n)return false;"
    # 兼容早先"只放票据根"的纯路径写法
    "var b=n.charAt(0)==='/'?n:(function(){"
    "try{var o=JSON.parse(n);return (o&&o.b)||''}catch(e){return ''}})();"
    # 不是我们写的票据根（/web/<t>/ 或 /api/servers/N/web/<t>/）就别动
    "if(b.charAt(0)!=='/'||b.indexOf('/web/')<0)return false;"
    "var p=location.pathname||'/';"
    "if(p.indexOf(b)===0)return false;"          # 本来就在票据路径下，防死循环
    "location.replace(b+p.slice(1)+location.search+location.hash);"
    "return true}catch(e){return false}})()"
)


def is_navigation(request: Request) -> bool:
    """是不是一次"页面导航"（而不是 XHR / 取资源的请求）。

    只有导航才配拿到自救页 —— XHR 拿到 HTML 会让设备 JS 解析失败，不如直接 401。
    """
    dest = (request.headers.get("sec-fetch-dest") or "").lower()
    if dest in ("document", "iframe", "object", "embed"):
        return True
    if dest:
        return False
    return "text/html" in (request.headers.get("accept") or "").lower()


def lost_ticket_page() -> Response:
    """票据被拼丢的导航 → 一页会自己把票据补回来的 HTML（独立源代理用）。"""
    style = "font:14px/1.6 system-ui,sans-serif;color:#666;padding:24px"
    html = (
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        "<title>正在恢复设备页面…</title></head><body>"
        f"<p style=\"{style}\">正在恢复设备页面…</p>"
        "<script>document.__vsRecovered=(" + _RECOVER_NAME_JS + ");"
        "setTimeout(function(){try{"
        "if(!document.__vsRecovered){document.body.innerHTML="
        f"'<p style=\"{style}\">无法恢复设备页面：请从主站「设备管理 - 网络设备 - WEB 管理」重新打开。"
        "（如果是通过书签或历史记录直接进来的，票据已经过期。）</p>'}"
        "}catch(e){}},800);</script></body></html>"
    )
    return Response(
        content=html, media_type="text/html; charset=utf-8",
        headers={"Cache-Control": "no-store", "Referrer-Policy": _REFERRER_POLICY},
    )


def inject_recover_js(html: str) -> str:
    """把自救脚本塞进主站 SPA 首页（主站同源形态用）。

    SPA 页面自己的 `window.name` 是空的，脚本会瞬间 return false —— 对正常页面零影响；
    只有在**设备 iframe 丢票据落回 SPA** 时才会读到票据根并跳回去。
    """
    if "__vsRecovered" in html:
        return html
    tag = "<script>document.__vsRecovered=(" + _RECOVER_NAME_JS + ");</script>"
    m = re.search(r"<head[^>]*>", html, re.I)
    if m:
        return html[: m.end()] + tag + html[m.end():]
    return tag + html


def _rewrite_css(body: bytes, base_href: str, root_href: str, host: str) -> bytes:
    """样式表里的 `url()` / `@import` 也要折算。

    样式表是**浏览器自己**按 `<link>` 拉的，不经过 shim；它内部若写的是根相对
    `/webman/x.png`，不折算就会打到我们自己的站点根上去（404）。相对地址因为
    样式表本身就在带票据的路径下，浏览器能正确解析，不会走到这里。
    """
    text = body.decode("utf-8", errors="surrogateescape")

    def _css(mo):
        mapped = _map_url(mo.group(2), base_href, root_href, host)
        if mapped is None:
            return mo.group(0)
        return f"url({mo.group(1)}{mapped}{mo.group(1)})"

    def _imp(mo):
        mapped = _map_url(mo.group(3), base_href, root_href, host)
        if mapped is None:
            return mo.group(0)
        return f"{mo.group(1)}{mo.group(2)}{mapped}{mo.group(2)}"

    text = _CSS_URL_RE.sub(_css, text)
    text = _CSS_IMPORT_RE.sub(_imp, text)
    return text.encode("utf-8", errors="surrogateescape")


# 设备界面里用 JS 拼地址的地方（`fetch('/api/x')`、webpack 插分片），shim 负责补前缀。
# 页面内的 <a>/<form>/<link>/<script> 已经在服务端改写过了，这里兜住脚本发起的那部分。
# data: / blob: / 已经是代理地址的一律不能碰：早先只判了 `//` 开头，结果把
_SHIM_TMPL = (
    '<script data-vigils-web-proxy="1">(function(){'
    # P = 本页目录（带票据） 给**相对**地址；B = 票据根 给**根相对**地址；
    # R = 无票据前缀 只用来判"这条已经是我们代理的地址了"。
    # 根相对绝不能拿 P 拼：设备的 HTTP.loginUrl 是 "/login.cgi"，按页面目录拼会变成
    # "/…/simple/view/login.cgi"，登录直接打空（2026-09-20 真机坐实）。
    'var P=__BASE__,R=__PREFIX__,B=__ROOT__;'
    # 票据根写进 window.name：设备 JS 用 location.hostname 硬拼绝对地址时，
    # `/web/<ticket>/` 会被整段丢掉，而 Chrome 的 location.href 不可伪造、沙箱
    # iframe 又不发 Referer，唯一还能跟着浏览上下文活下来的载体就是 window.name，
    # 丢票据的那次跳转落地后由 `lost_ticket_page()` 读回来补成完整路径。
    # `window.name` 在这里**身兼两职**
    # ① 票据根，设备 JS 用 location.hostname 硬拼绝对地址时会把 /web/<ticket>/ 丢掉，
    # Chrome 的 location.href 不可伪造、沙箱 iframe 又不发 Referer，落地后只能靠
    # `lost_ticket_page()` 从这儿读回来补路径；
    # ② **跨导航存活的存储后援**，见下面 VS / vsLoad / vsSave。
    'var VS={b:B,c:"",ls:{},ss:{}};'
    'function vsLoad(){try{var n=window.name||"";if(!n)return;'
    'if(n.charAt(0)==="/"){VS.b=n;return;}'
    'var o=JSON.parse(n);if(o&&typeof o==="object"){'
    'VS.b=o.b||B;VS.c=o.c||"";VS.ls=o.ls||{};VS.ss=o.ss||{}}}catch(e){}}'
    'function vsSave(){try{var s=JSON.stringify(VS);'
    'if(s.length<300000)window.name=s}catch(e){}}'
    'vsLoad();VS.b=B;vsSave();'
    # `document.cookie = "k=v; expires=…"` 的语义得自己实现：同名覆盖、过期即删
    'function vsCookie(cur,v){try{'
    'var s=String(v),ps=s.split(";"),kv=ps[0]||"",i=kv.indexOf("="),'
    'nm=(i<0?kv:kv.slice(0,i)).replace(/^\\s+|\\s+$/g,"");'
    'if(!nm)return cur;'
    'var val=i<0?"":kv.slice(i+1),out=[],arr=cur?String(cur).split(";"):[];'
    'for(var k=0;k<arr.length;k++){var a=arr[k],j=a.indexOf("="),'
    'an=(j<0?a:a.slice(0,j)).replace(/^\\s+|\\s+$/g,"");'
    'if(an!==nm&&a)out.push(a.replace(/^\\s+|\\s+$/g,""))}'
    'var m=/expires=([^;]+)/i.exec(s),dead=false;'
    'if(m){var t=Date.parse(m[1]);if(!isNaN(t)&&t<Date.now())dead=true}'
    'if(!dead)out.push(nm+"="+val);'
    'return out.join("; ")}catch(e){return cur}}'
    # 存储垫片（ 必须跨导航存活，不能只是"不崩"）
    # 沙箱不给 allow-same-origin 时是不透明源，读 document.cookie / localStorage /
    # sessionStorage 一律抛 SecurityError。华为登录成功后是这么干的（真机抓到的代码）
    # WEB.setCookie('Token', msg_arr[1].split("=")[1]);
    # location.href = protocol + location.hostname + port + mainLocation;
    # 会话 Token 写在 **document.cookie** 里，不是 HTTP Set-Cookie，服务端保管箱代持不到。
    # 早先的内存版一导航就归零 新页面 `WEB.getCookie('Token')` 读不到
    # 设备判定未登录 **"登录成功 跳首页 秒退登录页"**。
    # 不透明源里唯一跨导航还在的就是 window.name，所以 cookie 与两个 storage 全落进去。
    # 顶层窗口（"新窗口打开"）原生 API 正常，一个字节都不会被改写。
    'function store(key){var m=VS[key]||(VS[key]={});return{'
    'getItem:function(k){k=String(k);'
    'return Object.prototype.hasOwnProperty.call(m,k)?m[k]:null},'
    'setItem:function(k,v){m[String(k)]=String(v);vsSave()},'
    'removeItem:function(k){delete m[String(k)];vsSave()},'
    'clear:function(){for(var k in m)delete m[k];vsSave()},'
    'key:function(i){var a=Object.keys(m);return i>=0&&i<a.length?a[i]:null},'
    'get length(){return Object.keys(m).length}};}'
    "try{void document.cookie}catch(e){try{"
    "Object.defineProperty(Document.prototype,'cookie',{configurable:true,"
    "get:function(){return VS.c},"
    "set:function(v){VS.c=vsCookie(VS.c,v);vsSave()}});"
    '}catch(e2){}}'
    'function pick(name,make){try{void window[name]}catch(e){try{'
    'var got=null;Object.defineProperty(window,name,{configurable:true,'
    'get:function(){return got||(got=make())}});'
    '}catch(e2){}}}'
    "pick('localStorage',function(){return store('ls')});"
    "pick('sessionStorage',function(){return store('ss')});"
    'var H=(location.hostname||"").toLowerCase();'
    # 设备 JS 常拿 location.hostname 硬拼出**绝对**地址：华为登录成功后就是
    # `"https://"+location.hostname+port+"/simple/view/main/main.html"`。
    # 它拼出来的 host 是**我们代理源自己**，路径却是设备路径，票据前缀 /web/<ticket>/
    # 就这么被丢掉了。后果：主站形态下跳到站点根、落回 SPA（就是"登录后页面空白"）；
    # 独立源形态下根上没有这条路由，直接 404 `{"detail":"Not Found"}`。
    # 所以凡是 host 等于本代理源的绝对地址，一律剥成路径再走票据根。
    'function own(s){try{'
    r"var m=/^https?:\/\/([^\/]+)([\s\S]*)$/i.exec(String(s));"
    'if(!m)return null;'
    "var a=m[1].split('@').pop().split(':')[0].toLowerCase();"
    'if(a!==H)return null;'
    r"var p=m[2]||'/';"
    'if(p.indexOf(R)===0)return p;'
    r"return B+p.replace(/^\//,'');"
    '}catch(e){return null}}'
    'function fix(u){try{'
    'var s=String(u);if(!s)return u;'
    "if(s.slice(0,2)==='//')return u;"
    'var o=own(s);if(o!==null)return o;'
    "if(/^[a-z][a-z0-9+.\\-]*:/i.test(s))return u;"
    # 已经是代理地址就别再加一次（R 是 P/B 的公共前缀，判它就够）
    "if(s.indexOf(R)===0)return s;"
    # 根相对 票据根；相对 本页目录。两者不能混。
    "return s.charAt(0)==='/'?B+s.slice(1):P+s;"
    '}catch(e){return u}}'
    'var f=window.fetch;'
    'if(f){window.fetch=function(i,o){try{'
    "if(typeof i==='string'){i=fix(i)}else if(i&&i.url){i=new Request(fix(i.url),i)}"
    '}catch(e){}return f.call(this,i,o)}}'
    'var x=XMLHttpRequest.prototype.open;'
    'XMLHttpRequest.prototype.open=function(m,u){try{arguments[1]=fix(u)}catch(e){}'
    'return x.apply(this,arguments)};'
    'var b=navigator.sendBeacon;'
    'if(b){navigator.sendBeacon=function(u,d){try{u=fix(u)}catch(e){}'
    'return b.call(navigator,u,d)}}'
    'var sa=Element.prototype.setAttribute;'
    'Element.prototype.setAttribute=function(n,v){try{'
    "if(typeof v==='string'&&/^(?:src|href|action|poster|data)$/i.test(n))v=fix(v)"
    '}catch(e){}return sa.call(this,n,v)};'
    'function patch(proto,prop){try{'
    'var d=Object.getOwnPropertyDescriptor(proto,prop);'
    'if(!d||!d.set)return;'
    'Object.defineProperty(proto,prop,{configurable:true,enumerable:d.enumerable,'
    'get:d.get,set:function(v){try{v=fix(v)}catch(e){}return d.set.call(this,v)}});'
    '}catch(e){}}'
    '[[window.HTMLScriptElement,"src"],[window.HTMLImageElement,"src"],'
    '[window.HTMLIFrameElement,"src"],[window.HTMLSourceElement,"src"],'
    '[window.HTMLMediaElement,"src"],[window.HTMLLinkElement,"href"],'
    '[window.HTMLFormElement,"action"]].forEach(function(pair){'
    'if(pair[0])patch(pair[0].prototype,pair[1])});'
    # 导航（location.href = …）**别指望在 JS 层拦**：Chrome 把 href 做成 location
    # 实例上的 [LegacyUnforgeable] 属性，`Object.getOwnPropertyDescriptor(
    # Location.prototype,'href')` 直接是 undefined，原型补丁静默失效（2026-09-20 实测）。
    # 这类跳转只能事后补：有 Referer 走 `recover_redirect()`，没有（沙箱 iframe 不发
    # Referer）走 `window.name` 自救，见 `lost_ticket_page()`。
    '})();</script>'
)


# 鉴权

def _user_from_ticket(db: Session, ticket: str, server_id: int) -> dict:
    """票据 → 用户（重新查库取角色，权限每次现算，不信任票据里的任何内容）。

    独立源部署（`PROXY_ID_FROM_TICKET`）下路径里没有 {server_id}，改从票据载荷里取，
    再用它做完整校验 —— 票据签名本来就覆盖了 server_id，取出来只是换个来源，
    鉴权强度不变。
    """
    if PROXY_ID_FROM_TICKET:
        sid = ticket_lib.peek_server_id(ticket)
        if not sid:
            return {}
        server_id = sid
    uid = ticket_lib.verify(ticket, server_id)
    if not uid:
        return {}
    from models import Role, User

    u = db.query(User).filter(User.id == uid).first()
    if u is None or (u.status or "") != "active":
        return {}
    role = None
    if getattr(u, "role_id", None):
        role = db.query(Role).filter(Role.id == u.role_id).first()
    if role is None:
        role = db.query(Role).filter(Role.code == (u.role or "viewer")).first()
    return {
        "user_id": u.id,
        "username": u.username or "",
        "role": role.code if role else (u.role or "viewer"),
        "role_id": role.id if role else None,
        "is_admin": bool(role.is_admin) if role else False,
        "status": u.status,
    }


def _auth_user(request: Request, token: Optional[str], ticket: Optional[str],
               server_id: int, db: Session) -> dict:
    """三种入口共用一套校验：Authorization 头、`?token=`（接口调用）、`?t=`（页内跳转）。"""
    authorization = request.headers.get("authorization")
    if not authorization and token:
        authorization = f"Bearer {token}"
    if authorization:
        return require_login(authorization, db)
    if ticket:
        user = _user_from_ticket(db, ticket, server_id)
        if user:
            return user
    raise HTTPException(
        status_code=401,
        detail="未登录或会话已失效，请重新登录",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _friendly_error(e: Exception, target: str) -> str:
    """把 requests 的异常翻成人能看懂的原因。

 不能直接把 `str(e)` 拼回去 —— 那是一坨 HTTPConnectionPool / NewConnectionError
    的英文堆栈，管理员看不懂，而且会把内网结构一起带出去。日志里保留原文，给人看的
    只说"该怎么查"。
    """
    name = type(e).__name__
    if "Timeout" in name:
        return f"访问设备超时（{target}）"
    if "SSLError" in name:
        return f"与设备的 TLS 握手失败（{target}）—— 协议多半填反了（设备是 HTTP 却勾了 HTTPS）"
    if "TooManyRedirects" in name:
        return f"设备的重定向次数过多（{target}）"
    if "ConnectionError" in name:
        return f"连不上设备（{target}）—— 端口没开、设备未启用 Web 管理，或路径被防火墙挡了"
    return f"访问设备失败（{target}）：{name}"


def _gate(db: Session, user: dict, server: Server, server_id: int) -> None:
    from services.device_status import device_kind_of

    # 独立源形态下 server_id 来自票据；这里一并把它回填给调用方用
    if PROXY_ID_FROM_TICKET and not server_id:
        server_id = int(server.id or 0)
    # 2026-09-29 S-8：判定顺序原来是「先设备类型、后权限/归属」。业务上等价，
    # 但响应码泄露了信息，无权用户拿 400/403 就能区分"这个 id 是不是网络设备"
    # （实测 id=1/4 是服务器 400，id=3 是交换机 403），等于白送一份资产清单。
    # 改成先鉴权、后业务：无权一律 403，设备类型只在已授权后才判。
    if not has_perm(db, user, "host", "webadmin", "edit", "connect"):
        raise HTTPException(status_code=403, detail="当前角色没有打开设备 WEB 管理页面的权限")
    if not can_manage_server(db, user, server_id):
        raise HTTPException(status_code=403, detail="当前角色的管理范围不包含这台设备")
    if device_kind_of(server) != "network":
        raise HTTPException(status_code=400, detail="WEB 管理只对网络设备提供")



@router.post("/{server_id}/web/repin-tls")
def repin_device_tls(
    server_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    """重钉设备证书 —— 设备重装 / 换过证书后由运维**显式**触发。

    为什么必须显式：如果代码在指纹不一致时自动接受新指纹，中间人只要等到一次
    换证就能把自己挤进来。所以只有带着管理员身份点这一下才会撤销旧指纹，
    下一次连接重新 TOFU。
    """
    user = _auth_user(request, None, None, server_id, db)
    s = db.query(Server).filter(Server.id == server_id).first()
    if s is None:
        raise HTTPException(status_code=404, detail="设备不存在")
    _gate(db, user, s, server_id)
    if not has_perm(db, user, "sys", "network_devices", "edit", "edit"):
        raise HTTPException(status_code=403, detail="无权限重钉设备证书")

    old = device_tls_pin.pin_info(server_id)
    device_tls_pin.clear_pin(server_id)
    device_tls_pin.forget_cached(server_id)

    # 撤销后立刻重新握一次手，把新指纹钉上：这样接口返回即可用，不用等下次打开页面
    scheme, host, port = _target(s)
    new_fp = None
    err = ""
    if (scheme or "").lower() == "https" and host:
        try:
            new_fp, subject = device_tls_pin.probe(host, port)
            device_tls_pin.set_pin(server_id, new_fp, subject)
        except Exception as exc:  # noqa: BLE001
            err = str(exc)
    log_operation(
        db, category="server", action="network_web_repin_tls",
        username=user.get("username", ""), user_id=user.get("user_id"),
        target_type="server", target_id=str(s.id),
        message=f"用户 {user.get('username', '未知')} 重钉了网络设备 {s.name} 的证书指纹",
        details={"old": (old or {}).get("sha256", ""), "new": new_fp or "", "error": err},
    )
    return {
        "message": "已重钉证书指纹" if new_fp else (f"已撤销旧指纹，但重新握手失败：{err}"
                                                if err else "已撤销旧指纹（该设备不是 HTTPS，无需钉扎）"),
        "fingerprint": new_fp,
        "previous": (old or {}).get("sha256"),
    }


@router.get("/{server_id}/web-config")
def web_config(
    server_id: int,
    request: Request,
    token: Optional[str] = Query(None, description="登录令牌（iframe 场景用 query 传）"),
    db: Session = Depends(get_db),
):
    """「WEB管理」页签要用的入口信息：地址、端口，以及页内跳转用的窄票据。

    顺便记一条审计 —— 打开别人的设备管理页面是动作不小的事，出事要有据可查。
    """
    user = _auth_user(request, token, None, server_id, db)
    s = db.query(Server).filter(Server.id == server_id).first()
    if s is None:
        raise HTTPException(status_code=404, detail="设备不存在")
    _gate(db, user, s, server_id)

    scheme, host, port = _target(s)
    enabled = bool(host)
    log_operation(
        db, category="server", action="network_web_open",
        username=user.get("username", ""), user_id=user.get("user_id"),
        target_type="server", target_id=str(s.id),
        message=f"用户 {user.get('username', '未知')} 打开网络设备 {s.name} 的 WEB 管理页面",
        details={"protocol": scheme, "host": host, "port": port},
    )
    ticket = ticket_lib.mint(user["user_id"], server_id)
    return JSONResponse(content={
        "device_kind": s.device_kind or "host",
        "enabled": enabled,
        "protocol": scheme,
        "host": host,
        "port": port,
        "url": f"{scheme}://{host}:{port}/" if enabled else "",
        # 给前端拼地址用（可能接在独立源上），不是本进程的服务前缀
        "proxy_prefix": _frontend_prefix(server_id),
        # 独立源部署时给前端的绝对地址（含协议+端口），前端优先用它；
        # 为空则退回同源相对前缀（主站形态）
        "proxy_base_url": _proxy_public_base(request),
        # 帧内所有后续请求都靠它认人（浏览器 Cookie 在沙箱里存不住）
        "ticket": ticket,
        # 账号口令自动填充：前端拿它决定要不要在页签上提示
        # "这台没开自动填充 / 厂商暂不支持"（字段名沿用 auto_login，改库字段不值当）
        "auto_login": {
            "enabled": bool(int(getattr(s, "web_auto_login", 0) or 0)),
            # 有适配器 = 这台设备的厂商我们认得，存了账号口令就能填进登录页
            "supported": auto_login.supported(s),
            "configured": bool((getattr(s, "web_username", "") or "").strip()
                               and (getattr(s, "web_password", "") or "")),
            "vendor": getattr(s, "device_vendor", "") or "",
        },
    })


def _proxy_public_base(request: Request) -> str:
    """独立源代理的对外基址（含协议+端口），没配就返回空串。

    端口从 `VIGILSERVE_WEBPROXY_PORT`（面板/托盘下发的真实值）或
    `VIGILSERVE_WEBPROXY_PORT_HINT`（兼容用）取；两者都没有 = 没启用独立源形态，
    前端退回同源相对前缀。主机名用**用户当前访问的主机名**，他从哪台机器进来就用哪个。
    """
    port_raw = (os.environ.get("VIGILSERVE_WEBPROXY_PORT")
                or os.environ.get("VIGILSERVE_WEBPROXY_PORT_HINT") or "").strip()
    if not port_raw:
        return ""
    try:
        port = int(port_raw)
    except ValueError:
        return ""
    if not (1 <= port <= 65535):
        return ""
    scheme = "http" if os.environ.get("VIGILSERVE_WEBPROXY_TLS", "1") != "1" else "https"
    host = (request.url.hostname or "").strip() or (request.headers.get("host") or "").split(":")[0]
    if not host:
        return ""
    default_port = 443 if scheme == "https" else 80
    suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _maybe_auto_login(request: Request, db: Session, s: Server, user: dict,
                      server_id: int, ticket: str, content: bytes,
                      is_fragment: bool) -> bytes:
    """设备返回登录页 + 这台设备存了凭据 → 附一段「把账号口令填好」的脚本。

 触发条件里最关键的一条是「**设备返回了登录页**」：有会话时设备直接给主页，
    根本走不到这里，所以它既是"该不该填"也是"有没有会话"的判定 —— 我们因此
    不需要（也拿不到，见 `web_auto_login` 模块说明）额外的会话状态。

 **只填不提交**（2026-09-22 起）：绝不点登录按钮。填错口令会锁死设备账号
    （华为"输入错误密码次数达到上限"、群晖同样会锁），而"填好之后由人按一下登录"
    本来就只值一下鼠标 —— 这个风险不值得担。详见 `web_auto_login` 模块 docstring。

    `ticket` 必须由调用方（`web_proxy`）传进来：下面的凭据地址要拼成
    `{前缀}{ticket}/__vs_cred`，而票据是 `web_proxy` 按当前用户/设备现签的局部变量。
 2026-09-23 修复：P1-1 改成"口令不进页面、脚本按需取回"时，这里直接引用了
    `web_proxy` 里的 `ticket` 却没加参数 → 每次打开设备登录页都
    `NameError: name 'ticket' is not defined` → WEB 管理页签整个 500。
    因为只在"设备返回登录页"时才走到，平时（有会话、直接给主页）不触发，很难发现。
    """
    if is_fragment or not is_navigation(request):
        return content
    if not int(getattr(s, "web_auto_login", 0) or 0):
        return content
    adapter = auto_login.adapter_for(s)
    if adapter is None:
        # 厂商认不出来就不动手，乱提交表单有可能把设备账号锁死
        return content
    username = (getattr(s, "web_username", "") or "").strip()
    password = (s.web_password_plain or "") if hasattr(s, "web_password_plain") else ""
    if not username or not password:
        return content

    # 编码嗅探与 _rewrite_html 保持一致（设备页面基本都是 UTF-8，个别是 GBK）
    enc = "utf-8"
    m = re.search(rb"charset=[\"']?([\w-]+)", content[:4096], re.I)
    if m:
        enc = m.group(1).decode("ascii", "ignore")
    try:
        text = content.decode(enc, errors="surrogateescape")
    except LookupError:
        text = content.decode("utf-8", errors="surrogateescape")

    if not adapter.is_login_page("", text):
        return content

    # P1-1：口令**不进页面源码**，只发一个随机 cred_id 给它，真正的口令由脚本
    # 运行时向下面的 `__vs_cred` 端点按需取回（要求有效票据 + 该设备的权限）。
    # 于是 HTML 源码 / 浏览器缓存 / 页面截图里都不再有明文口令。
    cred_id = auto_login.issue_cred(server_id, user["user_id"], username, password)
    cred_url = f"{_frontend_prefix(server_id)}{ticket}/{auto_login.CRED_PATH}?c={cred_id}"
    logger.info(f"[WebAdmin {server_id}] 账号口令自动填充：把保存的账号 {username} "
                f"填进设备登录页（不提交登录；口令由脚本按需取回，不写入页面）")
    log_operation(
        db, category="server", action="network_web_autologin",
        username=user.get("username", ""), user_id=user["user_id"],
        target_type="server", target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 打开 {s.name} 的 WEB 管理页面，"
                f"已把保存的账号 {username} 填进设备登录页（不代替提交）",
    )
    # 填充脚本 + 一条说明横幅：横幅是给人看"我们只填了、登录得你点"
    snippet = adapter.script(username, cred_url) + auto_login.filled_banner()
    return auto_login.inject(text, snippet).encode(enc, errors="surrogateescape")


@router.api_route(
    "/{server_id}/web/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def web_proxy(
    server_id: int = 0,
    path: str = "",
    request: Request = None,
    token: Optional[str] = Query(None, description="登录令牌（接口调用用）"),
    t: Optional[str] = Query(None, description="页内跳转票据（由 web-config 下发）"),
    db: Session = Depends(get_db),
):
    """把设备自带的 Web 管理界面搬到这个路径底下（见模块顶部说明）。

    `server_id` 在主站形态下来自路径；**独立源形态**（`web_proxy_server.py` 把本函数
    挂在 `/web/{path:path}` 上）路径里没有它，默认 0，实际值从票据里取（见
    `PROXY_ID_FROM_TICKET` / `_user_from_ticket`）。
    """
    # 票据有两个形态：路径首段（页内一切子资源，绕开 ORB 的关键）与 query `?t=`（首次进入）
    clean_path = (path or "").lstrip("/")
    path_ticket = None
    if clean_path:
        seg, _, rest = clean_path.partition("/")
        # 先做密码学校验再认定，免得把设备真实路径的第一段误吃
        if seg and ticket_lib.peek_server_id(seg) is not None:
            path_ticket = seg
            clean_path = rest
            if PROXY_ID_FROM_TICKET and not server_id:
                server_id = ticket_lib.peek_server_id(seg) or 0

    user = _auth_user(request, token, t or path_ticket, server_id, db)
    s = db.query(Server).filter(Server.id == server_id).first()
    if s is None:
        raise HTTPException(status_code=404, detail="设备不存在")
    _gate(db, user, s, server_id)

    scheme, host, port = _target(s)
    if not host:
        raise HTTPException(status_code=400, detail="这台设备没有管理地址（ip_address 为空）")

    # TLS 指纹钉扎（TOFU）：转发给设备之前先比对证书指纹。
    # 以前这里只有 verify=False 一个开关，内网里谁做一次中间人就能读到我们替设备
    # 带上的会话 Cookie 和自动填的登录口令。详见 services/device_tls_pin.py。
    _pin_ok, _pin_err = device_tls_pin.before_request(server_id, scheme, host, port)
    if not _pin_ok:
        logger.warning(f"[WebAdmin {server_id}] 证书指纹校验未通过：{_pin_err}")
        raise HTTPException(
            status_code=502,
            detail=f"已中止连接 —— {_pin_err}",
        )

    if request.method == "OPTIONS":
        return Response(status_code=204, headers=dict(_CORS_HEADERS))

    prefix = _prefix(server_id)
    # 票据：来到手上的那张继续用（还能用就不重发），接口调用进来的现开一张
    incoming = t or path_ticket
    # 独立源形态下 server_id 来自票据，所以这里必须按 user_id 判断续用/重发，
    # 不能再依赖"票据里的 server_id == 路径参数"（路径里根本没有它）
    ticket = incoming if (incoming and ticket_lib.verify(incoming, server_id) == user["user_id"]) \
        else ticket_lib.mint(user["user_id"], server_id)

    # P1-1：设备页面的填充脚本来取账号口令。这是**我们自己**的保留路径，
    # 不能转发给设备（设备根本不认识它）。
    if clean_path.strip("/") == auto_login.CRED_PATH:
        cred = auto_login.take_cred(
            (request.query_params.get("c") or "").strip(), server_id, user["user_id"])
        if not cred:
            # 注意：`take_cred` 刻意不消费（页面要重试补填），所以这里说的
            # 是"凭据本身不可再用"，不是"已经被取走一次"。
            raise HTTPException(status_code=404, detail="凭据不可用或已过期")
        return JSONResponse(
            {"u": cred["u"], "p": cred["p"]},
            headers={"Cache-Control": "no-store", **_CORS_HEADERS},
        )

    base_dir = ""
    if "/" in clean_path:
        base_dir = clean_path.rsplit("/", 1)[0] + "/"
    # 带票据的基址（含本页目录）：改写后的相对地址用
    base_href = f"{prefix}{ticket}/{base_dir}"
    # 带票据的根：改写后的根相对/绝对地址用（见 _map_url 的说明）
    root_href = f"{prefix}{ticket}/"

    # 转发给设备的查询串：token / t 是我们自己的，不能跟着走
    params = [(k, v) for k, v in request.query_params.multi_items() if k not in ("token", "t")]
    upstream = f"{scheme}://{host}:{port}/{clean_path}"

    headers = {}
    for k, v in request.headers.items():
        low = k.lower()
        if low in ("host", "authorization", "content-length", "cookie"):
            continue
        if low in _DROP_HEADERS:
            continue
        headers[k] = v
    # 设备自己的会话 Cookie 由服务端保管，替它带上（浏览器在沙箱里存不住）
    jar = cookie_jar.header_for(user["user_id"], server_id)
    if jar:
        headers["Cookie"] = jar

    body = None
    if request.method not in ("GET", "HEAD"):
        body = await request.body()

    # 必须丢到线程池里跑（2026-09-20 NAS 慢的根因）
    # 本函数是 `async def`，而 requests 是**同步阻塞**的。直接在协程里调用它，等设备
    # 响应期间整个事件循环被卡死，浏览器那 6 条并发分片请求会**排成一队**，
    # 每条各等一次完整往返，叠起来就是"点一下要等好几秒"。
    # 丢进线程池后，多个设备请求真正并行，首屏从 ~5s 降到 1s 量级。
    def _do_request():
        return _SESSION.request(
            request.method, upstream,
            params=params, data=body, headers=headers,
            # 重定向交回浏览器处理（Location 已被改写成代理前缀），否则 requests
            # 会自己去连重定向里的内网地址，路径就串了
            allow_redirects=False,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            verify=False,  # 设备基本都是自签名证书
        )

    try:
        up = await _run_in_thread(_do_request)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[WebAdmin {server_id}] 连接 {upstream} 失败：{e!r}")
        raise HTTPException(
            status_code=502,
            detail=f"打不开设备的 WEB 管理页面 —— {_friendly_error(e, f'{scheme}://{host}:{port}')}。"
                   f"协议与端口可在「主机管理 - 网络设备」的编辑弹窗里改。",
        )

    try:
        raw_cookies = up.raw.headers.get_all("Set-Cookie") or []
    except Exception:  # noqa: BLE001
        raw_cookies = []
    cookie_jar.store(user["user_id"], server_id, list(raw_cookies))

    content = up.content or b""
    ctype = (up.headers.get("content-type") or "").lower()

    out_headers = {}
    for k, v in up.headers.items():
        if k.lower() in _DROP_HEADERS:
            continue
        out_headers[k] = v

    # Location：跳回代理前缀（带票据），别让浏览器跳去设备原生地址
    loc = out_headers.get("Location")
    if loc:
        if loc.startswith(prefix):
            # 已经是代理地址：补上票据（老形态带的是 query，这里统一成路径形态）
            rest = loc[len(prefix):]
            mapped = f"{prefix}{ticket}/{rest.lstrip('/')}" if not rest.startswith(ticket) else loc
        else:
            mapped = _map_url(loc, base_href, root_href, host)
        if mapped:
            out_headers["Location"] = mapped

    if "html" in ctype:
        # XHR/fetch 拉回来的是**片段**（会被插进主页面），不能按本页目录改写相对地址
        #，详见 _rewrite_html 的 fragment 说明。Sec-Fetch-Dest=empty 就是 XHR/fetch；
        # 老浏览器没有这个头，退回认 jQuery 的 X-Requested-With。
        _dest = (request.headers.get("sec-fetch-dest") or "").strip().lower()
        _xhr = (request.headers.get("x-requested-with") or "").strip().lower() == "xmlhttprequest"
        is_fragment = _dest == "empty" or (_xhr and not _dest)
        content = _rewrite_html(content, base_href, root_href, host, fragment=is_fragment)
        # 账号口令自动填充：只有在设备把登录页递给我们时才动手（= 当前没会话），
        # 见 `_maybe_auto_login` 的说明。返回的是 bytes，可能已被追加脚本。
        content = _maybe_auto_login(request, db, s, user, server_id, ticket,
                                    content, is_fragment)
        out_headers["Referrer-Policy"] = _REFERRER_POLICY
    elif "css" in ctype:
        content = _rewrite_css(content, base_href, root_href, host)
    out_headers["Cache-Control"] = "no-store"
    out_headers.update(_CORS_HEADERS)

    return Response(content=content, status_code=up.status_code, headers=out_headers)
