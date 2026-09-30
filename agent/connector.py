"""Agent connector — communicate with server via HTTP + AES encryption.

安全加固阶段 2：服务端启用 HTTPS 后，这里用随包内置的 CA 校验证书
（`tls_util`），并在发现"服务端已升级到 https"时自动改写本地配置。
"""
import json, hashlib, time
from urllib import request, error
from urllib.parse import urlparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import tls_util
except Exception:  # noqa: BLE001 （理论上不会发生，兜底成不校验证书）
    tls_util = None

try:
    import identity as _identity
except Exception:  # noqa: BLE001 （老安装缺 identity.py，退回遗留 token 认证）
    _identity = None

# 自动探测 https 的最小间隔（秒），服务端还是 http 时不必每轮心跳都探一次
_HTTPS_PROBE_COOLDOWN = 300

# 服务端是旧版本（没有 /api/agent/enroll）时置位，免得每个周期都白撞一次
_ENROLL_UNSUPPORTED = False

# 必须与服务端 `main.py` 里 agent 路由的 prefix 一致，请求签名签的就是这个路径，
# 差一个字符签名就验不过（服务端用 request.url.path，带 prefix）。
_AGENT_API_PREFIX = "/api/agent"


def _agent_version() -> str:
    """返回本 Agent 的版本号，给心跳带上（详见 heartbeat 里的注释）。

    延迟导入 `api_server.AGENT_VERSION` —— 它是版本号的唯一真源
    （`verify_version.py` 照它校验另外 10 处），这里**绝不**另写一份字面量，
    否则就会多出第 12 处需要手工同步的版本号。

    拿不到时返回空字符串而不是抛异常：版本号只用于"是否顺延完整性基线"的判断，
    拿不到顶多退化成旧行为，绝不能因此让心跳失败（心跳挂了等于主机掉线）。
    """
    try:
        from api_server import AGENT_VERSION
        return str(AGENT_VERSION)
    except Exception:  # noqa: BLE001
        return ""


def _encrypt_payload(plaintext: bytes, secret: str) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt. Returns (ciphertext, iv)."""
    key = hashlib.sha256(secret.encode()).digest()
    aesgcm = AESGCM(key)
    iv = __import__('os').urandom(12)
    ct = aesgcm.encrypt(iv, plaintext, None)
    return ct, iv


class AgentConnector:
    """Communicate with the central VigilServe backend."""
    
    def __init__(self, server_url: str, server_id: int = 0, token: str = "",
                 node_id: str = "", update_key: str = ""):
        self.server_url = server_url.rstrip("/")
        self.server_id = server_id
        self.token = token
        # 2026-09-23 开源加固 ④：更新包验签密钥（与 token 分离，见 config.py）
        self.update_key = update_key
        self.node_id = node_id or self._load_node_id()
        self.secret = ""
        self._last_probe = 0.0
        self._last_identity_msg = ""

    @staticmethod
    def _load_node_id() -> str:
        """本地已有 node_id 就复用；没有现造一个（会落盘，下次还是这台机）。"""
        if not _identity:
            return ""
        try:
            return _identity.ensure_node_id()
        except Exception:  # noqa: BLE001
            return ""

    def _headers(self, endpoint: str = "") -> dict:
        """构造请求头。

        方案 A（1.1.51）：**每个请求都用私钥签名**，这是上行的**唯一**身份凭据。
        `X-Server-Id` / `X-Auth-Token` 仍然带上，但服务端**不再拿它们认证** ——
        它们只用于服务端回调本机 9998（下行）时识别是哪台主机、以及老服务端兼容。
        以前"没证书就不签名、退回 token"的那条分支已经没了：那正是「同一台机器
        有时候能连有时候不能」的根源（认不认取决于本地有没有证书，而证书和服务端
        是不是同一台又对不上）。现在只有一条路。
        """
        headers = {
            "Content-Type": "application/json",
            "X-Server-Id": str(self.server_id),
            "X-Auth-Token": self.token,
        }
        if not (self.node_id and _identity):
            return headers
        try:
            headers.update(
                _identity.sign_headers("POST", f"{_AGENT_API_PREFIX}/{endpoint}", self.node_id)
            )
        except Exception as _e:  # noqa: BLE001
            # 签名失败不能把整个上报搞挂，但不带签名头服务端一定会拒，
            # 所以这里要留下痕迹，否则会变成"一直掉线却没有任何线索"。
            try:
                import logging
                logging.getLogger(__name__).warning(
                    f"[identity] 请求签名失败，本次上报会被服务端拒绝：{_e}")
            except Exception:
                pass
        return headers

    def _ssl_context(self):
        if tls_util is None or not self.server_url.startswith("https://"):
            return None
        try:
            return tls_util.context_from_disk()
        except Exception:  # noqa: BLE001
            return None

    def _post(self, endpoint: str, data: dict, timeout: float = 30) -> dict:
        # `timeout` 只给「卸载上报」这类一次性调用用，它跑在卸载流程里，
        # 不能占着默认的 30 秒。心跳等常驻路径不传，行为与以前完全一致。
        result = self._post_once(endpoint, data, timeout)
        # 兜底：服务端已切 HTTPS、而本地配置里还留着 http 时，http 请求会被对端
        # 直接断开（RemoteDisconnected: Remote end closed connection without
        # response）。这里立刻改用 https 重试一次，**成功才落盘**，
        # 比干等 maybe_upgrade_to_https 那个 5 分钟冷却的探测可靠得多。
        # 只对"连接层"错误重试：带 code 的是 HTTPError（401/404 等），重试无意义。
        if (result.get("error") and result.get("code") is None
                and self.server_url.startswith("http://")):
            _prev = self.server_url
            self.server_url = "https://" + self.server_url[len("http://"):]
            retry = self._post_once(endpoint, data, timeout)
            # 回滚条件必须是"https 连都没连上"，**不能**是"https 也报错"。
            # 401/403/404 这类带 code 的响应恰恰证明 TLS 已通、协议是对的；
            # 若因为 token 失效、设备待审核就把协议回滚回 http，会陷入
            # 「http 断开 https 拿 401 回滚 http 再断开」的死循环，
            # 界面上就永远停在 "Remote end closed connection without response"。
            if retry.get("error") and retry.get("code") is None:
                self.server_url = _prev      # https 也不通 退回，别把本地状态搞脏
                return result
            self._persist_scheme()
            return retry
        return result

    def _post_once(self, endpoint: str, data: dict, timeout: float = 30) -> dict:
        url = f"{self.server_url}/{_AGENT_API_PREFIX.lstrip('/')}/{endpoint}"
        body = json.dumps(data).encode("utf-8")
        req = request.Request(url, data=body, headers=self._headers(endpoint), method="POST")
        ctx = self._ssl_context()
        try:
            with request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return json.loads(resp.read().decode())
        except error.HTTPError as e:
            err_body = e.read().decode() if e.fp else str(e)
            return {"error": True, "code": e.code, "message": err_body[:200]}
        except Exception as e:
            return {"error": True, "message": str(e)[:200]}

    def _persist_scheme(self) -> None:
        """把当前 server_url 的协议写回配置，让后续重启也直接用对。"""
        try:
            import config as _cfg_mod
            scheme = "https" if self.server_url.startswith("https://") else "http"
            cfg = _cfg_mod.load() or {}
            if str(cfg.get("server_scheme") or "").strip().lower() == scheme:
                return
            cfg["server_scheme"] = scheme
            _cfg_mod.save(cfg)
        except Exception:  # noqa: BLE001
            pass

    def maybe_upgrade_to_https(self) -> bool:
        """server_url 还是 http 时，探测同端口的 https；可用则改写配置。

        服务端切到 HTTPS 后旧配置会连不上，这一步让 Agent 自己找回来
        （也是"一刀切"切换能自动恢复的关键）。返回是否发生了切换。
        """
        if tls_util is None or not self.server_url.startswith("http://"):
            return False
        now = time.time()
        if now - self._last_probe < _HTTPS_PROBE_COOLDOWN:
            return False
        self._last_probe = now
        try:
            u = urlparse(self.server_url)
            host, port = u.hostname, u.port
        except Exception:  # noqa: BLE001
            return False
        if not host or not port:
            return False
        if not tls_util.probe_https(host, port):
            return False
        self.server_url = "https://" + self.server_url[len("http://"):]
        self._persist_scheme()
        return True
    
    def register(self, info: dict) -> tuple[bool, str]:
        """设备入户入口。**方案 A 下内部直接转给 `enroll()`**。

        1.1.51 之前这里有两条路：`/register`（只领 server_id + token）和 `/enroll`
        （领客户端证书）。两条路都能让设备"看起来在线"，于是"这台机器到底靠什么
        被认证"成了薛定谔状态 —— 证书在不在、是不是这台服务端签的，全影响结果。

        现在只有一条：`/enroll` 登记公钥。保留 `register` 这个名字是因为主循环和
        配置面板还在调它，改名会牵动一堆调用点；它现在只是 `enroll` 的薄壳。
        """
        resp = self.enroll(info)
        if resp.get("error"):
            return False, str(resp.get("message") or resp.get("detail") or resp)[:200]
        if not resp.get("server_id"):
            return False, str(resp.get("issue_error")
                              or resp.get("message") or resp.get("detail") or resp)[:200]
        self.server_id = resp["server_id"]
        if resp.get("token"):
            self.token = resp["token"]
        if resp.get("update_key"):
            self.update_key = resp["update_key"]
        self.apply_api_certificate(resp)
        self.apply_certificate(resp)
        return True, ""

    def _legacy_register(self, info: dict) -> tuple[bool, str]:
        """（不再使用）老的 `/register` 直连。保留仅供排障时对照。"""
        payload = dict(info)
        if self.server_id and self.token:
            payload["server_id"] = self.server_id
            payload["token"] = self.token
        # （换了 IP 的已纳管主机不会掉出去、也不会在待审核队列里多一条副本）。
        if not payload.get("node_id"):
            try:
                if _identity is not None:
                    payload["node_id"] = self.node_id or _identity.ensure_node_id()
            except Exception:  # noqa: BLE001
                pass
        # P1-1：register 路径也申请 9998 服务器证书（与 token 同级信任，注册即签）
        try:
            if _identity is not None and payload.get("node_id"):
                if _identity.needs_api_cert():
                    payload["api_csr"] = _identity.build_api_csr(payload["node_id"])
        except Exception:  # noqa: BLE001
            pass
        resp = self._post("register", payload)
        if resp.get("server_id"):
            self.server_id = resp["server_id"]
            self.token = resp["token"]
            if resp.get("update_key"):
                self.update_key = resp["update_key"]
            self.apply_api_certificate(resp)
            return True, ""
        err = resp.get("message") or resp.get("detail") or str(resp)
        return False, err[:200]

    # 设备入户（客户端证书身份）
    # 这台机器第一次报到：带上 node_id + CSR（用私钥签名），服务端把它放进
    # "待审核队列"；管理员在「注册管理」点「加入管理」并核对配对码之后，
    # 下一次入户请求就会拿回一张客户端证书。证书90天到期，剩余不足30天自动续。

    def enroll(self, info: dict) -> dict:
        """向服务端登记本机公钥。返回服务端响应原文。

        方案 A（1.1.51）：送 `pub_key_pem`（裸公钥）而不是 CSR —— 服务端登记它就
        完成了"认设备"，不需要 CA 签发任何东西。同时仍带 `csr`（同一把公钥），
        这样**老服务端**也能认。

        P1-1：顺带申请 9998 API 的服务器证书（独立密钥对，同一 node_id）。
        """
        global _ENROLL_UNSUPPORTED
        if _identity is None:
            return {"error": True, "message": "缺少 identity 模块，无法启用设备身份"}
        if _ENROLL_UNSUPPORTED:
            return {"error": True, "unsupported": True, "message": "服务端不支持 /api/agent/enroll"}
        try:
            self.node_id = self.node_id or _identity.ensure_node_id()
            payload = dict(info)
            payload["node_id"] = self.node_id
            payload["pub_key_pem"] = _identity.public_key_pem()
            try:
                payload["csr"] = _identity.build_csr(self.node_id, info.get("hostname", ""))
            except Exception:  # noqa: BLE001 老服务端兼容字段，失败不影响主流程
                pass
            payload["machine_fingerprint"] = _identity.fingerprint_hash(
                _identity.machine_fingerprint())
            try:
                payload["fingerprint_parts"] = _identity.fingerprint_parts()
            except Exception:  # noqa: BLE001 老 identity 模块没有这个函数
                pass
            # P1-1：需要（无证 / 快到期）才带上 9998 服务器证书的 CSR，
            # 服务端签好会以 api_cert 回传，见 apply_api_certificate。
            try:
                if _identity.needs_api_cert():
                    payload["api_csr"] = _identity.build_api_csr(self.node_id)
            except Exception:  # noqa: BLE001 申请失败不影响客户端证书流程
                pass
            if self.server_id and self.token:
                payload["server_id"] = self.server_id
                payload["token"] = self.token
            resp = self._post("enroll", payload)
            if resp.get("error") and resp.get("code") in (404, 405):
                _ENROLL_UNSUPPORTED = True
                resp["unsupported"] = True
            return resp
        except Exception as e:  # noqa: BLE001
            return {"error": True, "message": str(e)[:200]}

    @staticmethod
    def apply_certificate(resp: dict) -> bool:
        """记录服务端是否已登记本机公钥。

        1.1.51 方案 A：服务端不再回证书，改用 `enrolled` / `identity_state` 表明
        "公钥登记好了没有"。旧的 `client_cert` 兼容分支保留 —— 万一连的是老服务端。
        """
        if _identity is None:
            return False
        if resp.get("client_cert"):        # 老服务端：仍然发证书
            try:
                _identity.save_cert(resp["client_cert"],
                                    resp.get("cert_not_after", ""), resp.get("cert_serial", ""))
            except Exception:  # noqa: BLE001
                pass
        if resp.get("enrolled") or resp.get("identity_state") == "authorized":
            try:
                _identity.mark_authorized(True)
            except Exception:  # noqa: BLE001
                return False
            return True
        return False

    @staticmethod
    def apply_api_certificate(resp: dict) -> bool:
        """把服务端签回来的 9998 服务器证书落盘（P1-1）。"""
        pem = resp.get("api_cert") or ""
        if not pem or _identity is None:
            return False
        try:
            _identity.save_api_cert(pem, resp.get("api_cert_not_after", ""))
            return True
        except Exception:  # noqa: BLE001
            return False

    def ensure_certificate(self, info: dict) -> tuple[bool, str]:
        """需要就去要证书。返回 `(是否可以继续, 说明)`。

        调用方每轮循环都调一次，绝大多数时候这里会在第一行就返回。
        """
        if _identity is None:
            return True, "缺少身份模块，无法使用设备身份"
        need, why = _identity.needs_enroll()
        # 1.1.53：客户端证书有效但从未领过 9998 服务器证书（1.1.51 存量主机
        # 已知问题）时也走一次 enroll，把 api_csr 送上去，否则服务端对
        # 9998 的 CA 校验会一直失败，推送升级等回调通道永久不可用。
        try:
            need = need or _identity.needs_api_cert()
        except Exception:  # noqa: BLE001 老版本 identity 模块兜底
            pass
        if not need:
            return True, ""

        resp = self.enroll(info)
        if resp.get("unsupported"):
            return True, "服务端尚未支持设备身份（请升级服务端）"
        if resp.get("error"):
            return False, f"入户请求失败：{resp.get('message', '')}"
        if not resp.get("server_id"):
            return False, f"入户失败：{resp.get('message') or resp.get('detail') or resp}"

        if resp.get("server_id"):
            self.server_id = resp["server_id"]
        if resp.get("token"):
            self.token = resp["token"]
        if resp.get("update_key"):
            self.update_key = resp["update_key"]

        # P1-1：顺带落盘 9998 服务器证书（有就收，没有不影响）
        self.apply_api_certificate(resp)

        if self.apply_certificate(resp):
            msg = "设备身份已登记（公钥已被服务端接受）"
        else:
            msg = resp.get("issue_error") or "等待管理员在「注册管理」批准"
            if resp.get("pairing_code"):
                msg += f"（本机配对码 {resp['pairing_code']}）"

        # 这个方法每个采集周期都会调用一次，而"还没批准"这种状态可能连续存在几天。
        # 状态没变化就返回空串，让调用方不必重复刷同一句日志。
        if msg == self._last_identity_msg:
            return True, ""
        self._last_identity_msg = msg
        return True, msg

    def identity_summary(self) -> dict:
        """给 UI / 日志看的身份摘要。"""
        if _identity is None:
            return {"node_id": self.node_id or "", "has_cert": False, "not_after": ""}
        try:
            info = _identity.short_summary()
        except Exception:  # noqa: BLE001
            info = {}
        info["node_id"] = self.node_id or info.get("node_id", "")
        return info

    def push(self, data: dict) -> bool:
        """Push collected metrics to server."""
        if not self.server_id or not self.token:
            return False
        resp = self._post("push", data)
        return "error" not in resp
    
    def heartbeat(self, ip_address: str = "", api_port: int = 9998, install_path: str = "",
                  mesh_node_id: str = "") -> dict:
        """Send heartbeat. Returns server response dict so the agent can
        detect IP mismatches and re-register when necessary.

        ``mesh_node_id`` carries this host's MeshCentral node id (empty when the
        MeshAgent is not installed) so the backend can build a deep link that
        opens remote desktop straight on this machine.
        """
        if not self.server_id:
            return {"error": True, "message": "no server_id"}
        payload = {
            "ip_address": ip_address,
            "api_port": api_port,
            "install_path": install_path,
            "mesh_node_id": mesh_node_id,
            # 2026-09-23：这个字段以前**根本没发**，后果很严重，
            # 服务端判断"Agent 是否被改造"时，靠版本号区分两种指纹变化
            # 版本变了 合法升级，顺手把完整性基线挪到新版本（不误报）
            # 版本没变、指纹却变 记 agent_tamper_suspected
            # 版本号一直是空字符串，于是第二条分支永远成立、第一条永远不生效
            # 只要重新打包（哪怕源码一行没改以外的任何改动），现网机器就
            # 每 5 秒刷一条"疑似被改造"。实测 3 台主机各刷了 30+ 条。
            # 版本号取 `api_server.AGENT_VERSION`（它是唯一真源，
            # `verify_version.py` 就是照它校验其余 10 处的），
            # 延迟导入避免与 api_server 形成模块级循环。
            "agent_version": _agent_version(),
        }
        # S3 漂移分级：心跳是唯一每 5 秒都走的通道，换 IP / 换主板都得靠它发现。
        # 分项指纹只发哈希（序列号、MAC 不出本机），主机名明文（本来就在报）。
        try:
            if _identity is not None:
                payload["fingerprint_parts"] = _identity.fingerprint_parts()
                payload["machine_fingerprint"] = _identity.fingerprint_hash(
                    _identity.machine_fingerprint())
        except Exception:  # noqa: BLE001 指纹采集失败不影响存活上报
            pass
        # 证书仍有效、ensure_certificate 不触发）在这里补送 api_csr，服务端
        # 签好随心跳响应回传；落盘后 api_server 的 TLS watcher 10 秒内热切换。
        try:
            if _identity is not None and _identity.needs_api_cert():
                payload["api_csr"] = _identity.build_api_csr(self.node_id or "")
                if self.node_id:
                    payload["node_id"] = self.node_id
        except Exception:  # noqa: BLE001 领证失败不影响存活上报
            pass
        # 2026-09-23 开源加固 ⑥：上报本机 Agent 代码的完整性指纹（对标
        # MeshCentral 的 agentTampering）。进程内缓存，不是每 5 秒重算一遍。
        try:
            import self_check
            _d = self_check.self_digest()
            if _d.get("digest"):
                payload["self_digest"] = _d["digest"]
                payload["self_digest_files"] = _d.get("files", 0)
                payload["self_digest_mode"] = _d.get("mode", "")
        except Exception:  # noqa: BLE001 算不出来不影响存活上报
            pass
        # 2026-09-23 开源加固 ④：本机还没有 update_key（老版本注册上来的存量 Agent）
        # 时，**要一次**就够，拿到后立刻落盘，之后每 5 秒一次的心跳不再重复传输，
        # 免得把这把钥匙反复放到网络上。
        if not self.update_key:
            payload["need_update_key"] = True
        resp = self._post("heartbeat", payload)
        if isinstance(resp, dict):
            self.apply_api_certificate(resp)
            if resp.get("update_key"):
                self.update_key = resp["update_key"]
            # 开源加固 ⑤：服务端轮换过密钥时，心跳会把新 token 带回来
            if resp.get("token") and resp["token"] != self.token:
                self.token = resp["token"]
                resp["token_rotated"] = True
        return resp

    def fetch_config(self) -> dict:
        """Pull server-side config (interval, thresholds)."""
        if not self.server_id:
            return {}
        return self._post("config", {})
