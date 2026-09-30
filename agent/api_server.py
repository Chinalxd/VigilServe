"""Agent-side HTTP API for file operations, terminal and web config UI.

Runs on port 9998 (configurable) alongside the main agent loop. Endpoints
mirror the backend's file-explorer API so the backend can transparently
proxy requests when a server uses the agent protocol.
"""
import os
import sys
import time
import ctypes
import hmac
import hashlib
import ipaddress
import ssl
import subprocess
import shutil
import io
import zipfile
import json
import socket
import stat
import threading
from urllib.parse import parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from logger import get_logger
from config import DEFAULTS

_api_log = get_logger("api")

try:
    from winpty import PtyProcess as WinPtyProcess, Backend as WinBackend
except Exception:
    WinPtyProcess = None
    WinBackend = None

AGENT_VERSION = "1.1.68"

# ── 9998 接口鉴权（安全加固阶段 1） ───────────────────────────────────
# 免鉴权白名单：
# ⚠ /config **不再是**白名单成员（第二轮复查 R-7）。以前它是"只要来自 127.0.0.1
#   就无条件放行"，但 Agent 通常以 SYSTEM / 管理员权限运行 ⇒ 本机**任意一个**
#   用户态进程都能无凭据读写它的配置（改服务端地址、改 token）。现在要求同时满足
_OPEN_PATHS = {"/ping"}

# ── 绑定地址与来源白名单（2026-09-23 动态审计 D-2）──────────────────────
# 背景：Agent API 原来把监听地址**硬编码成 0.0.0.0**，等于对任何可达的网络开放，
# 而它装在每一台被监控机上（含生产服务器）。防护全靠外部防火墙。
# ⚠ 为什么**不能**简单改成只听 127.0.0.1：Agent 是**分布式**部署的，服务端会
#   **主动**来连每台机器的这个端口（电源操作、主机信息采集、远程桌面…）。
# 正确的收紧姿势是这两条（都不配 = 维持原行为，不影响现有部署）。
# ⚠ 2026-09-23：第一条**直到今天才真的生效** —— `_build_tls_server()` 里写死了
_AGENT_BIND_ENV = "VIGILSERVE_AGENT_BIND_HOST"

# 更新包签名的时间戳新鲜性窗口（秒）。必须与服务端
# `services/agent_auth.UPDATE_TS_TOLERANCE` 保持一致，否则会出现"服务端刚签完、
# Agent 就说超时"的怪现象。两边都容忍 ±5 分钟，覆盖常见的时钟漂移。
UPDATE_TS_TOLERANCE = 300


_AGENT_CIDRS_ENV = "VIGILSERVE_AGENT_ALLOWED_CIDRS"
_AGENT_NET_CACHE: dict = {"raw": None, "nets": ()}


def _agent_bind_host() -> str:
    """Agent API 的监听地址。默认 0.0.0.0（服务端需远程可达，见上方说明）。"""
    return (os.environ.get(_AGENT_BIND_ENV) or "").strip() or "0.0.0.0"


def _agent_allowed_networks():
    """解析来源白名单（空元组 = 不限制来源）。"""
    raw = (os.environ.get(_AGENT_CIDRS_ENV) or "").strip()
    if _AGENT_NET_CACHE["raw"] != raw:
        nets = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                _api_log.warning(
                    f"[net_guard] {_AGENT_CIDRS_ENV} 里的 {part!r} 不是合法 IP/CIDR，已忽略")
        _AGENT_NET_CACHE["nets"] = tuple(nets)
        _AGENT_NET_CACHE["raw"] = raw
    return _AGENT_NET_CACHE["nets"]


_LOCAL_TOKEN_CACHE: dict = {"val": ""}


def _local_token() -> str:
    """本机配置页口令：没有就现场生成一个并落盘（见 `paths.LOCAL_TOKEN_PATH`）。

    只在第一次需要时生成，之后一直复用 —— 换掉它等于把"用手输 URL 进配置页"的
    人踢出去，没必要自找麻烦。口令落在本机配置目录（%LOCALAPPDATA% 下），
    Windows 按用户隔离，别的账户读不到。
    """
    if _LOCAL_TOKEN_CACHE["val"]:
        return _LOCAL_TOKEN_CACHE["val"]
    from paths import LOCAL_TOKEN_PATH
    try:
        with open(LOCAL_TOKEN_PATH, "r", encoding="utf-8") as f:
            val = f.read().strip()
    except OSError:
        val = ""
    if not val:
        val = os.urandom(32).hex()
        try:
            os.makedirs(os.path.dirname(LOCAL_TOKEN_PATH), exist_ok=True)
            with open(LOCAL_TOKEN_PATH, "w", encoding="utf-8") as f:
                f.write(val)
            try:
                # Windows 上 chmod 只能收紧到"仅当前用户"，效果有限但聊胜于无
                os.chmod(LOCAL_TOKEN_PATH, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        except OSError as exc:
            _api_log.warning(f"[auth] 本机配置口令落盘失败：{exc!r}")
    _LOCAL_TOKEN_CACHE["val"] = val
    return val

_CFG_CACHE: dict = {"mtime": None, "cfg": {}}


def _agent_cfg() -> dict:
    """读 Agent 本地配置（带 mtime 缓存 —— 每个请求都要看 token，不能每次读盘）。"""
    try:
        import config as _cfg_mod
        path = _cfg_mod.CONFIG_PATH
    except Exception:
        return {}
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    if _CFG_CACHE["mtime"] != mtime:
        try:
            import config as _cfg_mod
            _CFG_CACHE["cfg"] = _cfg_mod.load() or {}
            _CFG_CACHE["mtime"] = mtime
        except Exception:
            pass
    return _CFG_CACHE["cfg"]

_rdp_controller: dict = {"fn": None}


def set_rdp_controller(fn):
    """Register callback fn(active: bool) used by /rdp/start and /rdp/stop."""
    _rdp_controller["fn"] = fn
def verify_update_package(data: bytes, version: str, sha_hdr: str, sig_hdr: str,
                          ts_hdr: str, now: int | None = None) -> tuple[bool, str]:
    """校验推送下来的更新包。**fail-closed**：任何一项不过都返回 (False, 原因)。

    签名口径（必须与服务端 `services/agent_auth.sign_update_package` 逐字节一致）：
        X-Pkg-Sha256    = 包内容的 hex sha256
        X-Pkg-Timestamp = 签发时刻（Unix 秒）
        X-Pkg-Signature = hmac_sha256(**update_key**, "{version}:{sha256}:{timestamp}")

    🚨 2026-09-23 开源加固 ④ 的两处改动，都是对着"一次泄露 = 永久 RCE"来的：

    1. **密钥从 token 换成了独立的 update_key**。token 是 9998 的认证头，每次
       服务端↔Agent 调用都在网络上跑，抓一次包就能拿到 —— 而以前它同时又是
       更新包的签名密钥，等于"看到一次 token = 能永久给本机签任意安装包"。
       现在必须**同时**持有 token（过认证）和 update_key（过验签）才能执行代码。
    2. **签名串里加了 timestamp**。原来只有 `{version}:{sha256}`，同一个包在
       任何时刻的签名都一模一样，截获一次就能无限次重放。

    ⚠ 不做旧口径回退（用户 2026-09-23 拍板）：旧服务端推来的包会被拒绝。

    :param now: 仅测试用，注入"当前时间"以验证时间窗口。
    """
    sha_hdr = (sha_hdr or "").strip()
    sig_hdr = (sig_hdr or "").strip()
    ts_hdr = (ts_hdr or "").strip()
    if not sha_hdr or not sig_hdr or not ts_hdr:
        return False, "缺少签名头（需服务端带 update_key 签名的新版本，请先升级服务端或手动安装）"
    local_sha = hashlib.sha256(data).hexdigest()
    if local_sha.lower() != sha_hdr.lower():
        return False, "包内容与声明的 SHA256 不一致（传输损坏或被篡改）"

    # 新鲜性：超窗（默认 ±300s，容忍时钟漂移）的签名一律不认
    try:
        pkg_ts = int(ts_hdr)
    except ValueError:
        return False, "签名时间戳格式非法"
    _now = int(time.time()) if now is None else int(now)
    if abs(_now - pkg_ts) > UPDATE_TS_TOLERANCE:
        return False, (f"签名时间戳不在允许窗口内（±{UPDATE_TS_TOLERANCE}s），"
                       "请检查本机与服务端时钟是否同步")

    _update_key = str(_agent_cfg().get("update_key") or "").strip()
    if not _update_key:
        return False, ("本机没有 update_key（未从新服务端注册/入户过），"
                       "不接受推送更新。请重新入户后再试")
    _expected_sig = hmac.new(
        _update_key.encode(),
        f"{version}:{sha_hdr.lower()}:{pkg_ts}".encode(),
        "sha256",
    ).hexdigest()
    if not hmac.compare_digest(_expected_sig, sig_hdr):
        return False, "签名不匹配（包非本主机的服务端所签）"
    return True, ""




class AgentAPIHandler(BaseHTTPRequestHandler):
    """Handles /drives, /files, /files/download, /files/download-multi,
    /files/upload, /status, /config, and /ws/terminal."""

    server_version = "VigilServeAgent/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, detail):
        self._json({"detail": detail}, status)

    # ── 鉴权 ──────────────────────────────────────────────────────
    def _client_is_loopback(self) -> bool:
        host = (self.client_address[0] if self.client_address else "") or ""
        return host in ("127.0.0.1", "::1", "localhost")

    def _client_allowed(self) -> bool:
        """来源白名单（2026-09-23 动态审计 D-2）。

        `VIGILSERVE_AGENT_ALLOWED_CIDRS` 为空 = 不限制（默认，行为与改动前一致）。
        配了之后，名单外的来源**任何路径都拒绝** —— 包括 `/ping`，因为 /ping
        本身也是暴露面（能被用来探活、判断机器是否在网）。

        这是 Agent 侧最有效的一层收紧：它的访问令牌是长期有效的固定值
        （见 D-5），所以「谁能连上来」比「连上来带什么令牌」更值得先卡住。
        """
        nets = _agent_allowed_networks()
        if not nets:
            return True
        host = (self.client_address[0] if self.client_address else "") or ""
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(addr in n for n in nets)

    def _local_token_ok(self) -> bool:
        """比对本机配置页口令（R-7）。"""
        expected = _local_token()
        if not expected:
            return False
        got = (self.headers.get("X-Local-Token") or "").strip()
        if not got:
            qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            got = (qs.get("t") or [""])[0].strip()
        if not got:
            return False
        return hmac.compare_digest(got, expected)

    def _authorized(self, path: str) -> bool:
        """校验 X-Auth-Token；返回 False 时调用方须直接回 401。"""
        # 来源白名单先于一切路径判断（2026-09-23 动态审计 D-2）：没配就不介入。
        if not self._client_allowed():
            _api_log.warning(
                f"[auth] 拒绝来源不在 {_AGENT_CIDRS_ENV} 白名单内的访问：path={path} "
                f"from={self.client_address[0] if self.client_address else '?'}"
                f"（若这是服务端，请把它的地址加进 {_AGENT_CIDRS_ENV}）")
            return False
        if path in _OPEN_PATHS:
            return True
        # 本机配置页（GET/POST /config）：第二轮复查 R-7 —— 见 `_local_token()` 的说明。
        # 口令两个来源：`?t=`（托盘打开的 URL 首进带）与 `X-Local-Token`（页面里
        # fetch 提交时带，免得口令留在浏览器历史/Referer 里）。
        if path == "/config" and self._client_is_loopback():
            return self._local_token_ok()
        expected = str(_agent_cfg().get("token") or "").strip()
        if not expected:
            # 2026-09-22 P0-3：这里原本**无条件放行**（fail-open），理由是"没 token
            #   就没法比对，否则主机永远注册不上"。但注册是 Agent 主动 outbound 到
            #   服务端完成的（connector.py 打 /api/agent/register、/api/agent/enroll），
            #   服务端并不需要回调本机 9998，所以放行不是注册必需的，却让同网段任意
            #   机器匿名访问 /files/*、/ws/terminal（直起 cmd.exe）、/power。
            # 2026-09-29 S-3：上一版收成"只放行 loopback"，但**没限定路径** ——
            #   Agent 常以 SYSTEM 运行，本机任意用户态进程仍可白嫖 /ws/terminal
            #   与 /power。本版取消按来源放行。
            # token 丢失时 Agent 会自动重新 enroll 领新 token，不会把自己锁死。
            _api_log.warning(
                f"[auth] 拒绝未注册状态下的访问：path={path} "
                f"from={self.client_address[0] if self.client_address else '?'} "
                f"（Agent 尚未取得服务端 token，请确认已完成注册）")
            return False
        got = (self.headers.get("X-Auth-Token") or "").strip()
        if not got:
            return False
        # 全量比对：原来只比前 32 字符，等于把有效长度砍半（2026-09-22 P0-3）
        return hmac.compare_digest(got, expected)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        qs = parse_qs(self.path.split("?")[1] if "?" in self.path else "")
        if not self._authorized(path):
            _api_log.warning(
                f"401 unauthorized GET {path} from "
                f"{(self.client_address[0] if self.client_address else '?')}")
            if path == "/config" and self._client_is_loopback():
                # R-7：手敲 URL 进配置页的人会撞到这里，给句人话
                return self._error(401, "本机配置页需要口令，请通过托盘「打开配置页」进入")
            return self._error(401, "Invalid credentials")
        if path == "/drives":
            self._handle_drives()
        elif path == "/ping":
            # 免鉴权的存活探测：只回状态，不泄露主机名/版本/配置
            self._json({"status": "ok"})
        elif path == "/files":
            self._handle_files(qs)
        elif path == "/files/download":
            self._handle_download(qs)
        elif path == "/files/download-multi":
            self._handle_download_multi(qs)
        elif path == "/files/read":
            self._handle_read_text(qs)
        elif path == "/status":
            self._json(get_status())
        elif path == "/processes":
            self._handle_processes()
        elif path == "/config":
            self._handle_config_get()
        elif path == "/system-info":
            self._handle_system_info()
        elif path == "/applications":
            self._handle_applications()
        elif path == "/applications/updates":
            self._handle_app_updates()
        elif path == "/startup":
            self._handle_startup_list()
        elif path == "/event-logs":
            self._handle_event_logs(qs)
        elif path == "/ws/terminal":
            self._handle_ws_terminal()
        else:
            self._error(404, "Not Found")

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        qs = parse_qs(self.path.split("?")[1] if "?" in self.path else "")
        if not self._authorized(path):
            _api_log.warning(
                f"401 unauthorized POST {path} from "
                f"{(self.client_address[0] if self.client_address else '?')}")
            if path == "/config" and self._client_is_loopback():
                return self._error(401, "本机配置页需要口令，请通过托盘「打开配置页」进入")
            return self._error(401, "Invalid credentials")
        if path == "/files/upload":
            self._handle_upload(qs)
        elif path == "/files/copy":
            self._handle_copy()
        elif path == "/files/delete":
            self._handle_delete()
        elif path == "/files/mkdir":
            self._handle_mkdir()
        elif path == "/files/rename":
            self._handle_rename()
        elif path == "/files/write":
            self._handle_write_text()
        elif path == "/files/create":
            self._handle_create_file()
        elif path == "/files/zip":
            self._handle_zip()
        elif path == "/files/unzip":
            self._handle_unzip()
        elif path == "/rdp/start":
            self._handle_rdp_control(True)
        elif path == "/rdp/stop":
            self._handle_rdp_control(False)
        elif path == "/config":
            self._handle_config_post()
        elif path == "/update":
            self._handle_update(qs)
        elif path == "/power":
            self._handle_power()
        elif path == "/applications/uninstall":
            self._handle_app_uninstall()
        elif path.startswith("/startup/") and path.endswith("/toggle"):
            self._handle_startup_toggle(path[len("/startup/"):-len("/toggle")])
        else:
            self._error(404, "Not Found")

    def _handle_processes(self):
        try:
            from collector_v2 import list_all_processes
            procs = list_all_processes()
            self._json({"count": len(procs), "processes": procs})
        except Exception as e:
            _api_log.error(f"processes endpoint failed: {e}")
            self._error(500, f"Failed to list processes: {e}")

    def _handle_drives(self):
        import psutil, shutil
        drives = []
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            if "cdrom" in opts:
                continue
            mp = part.mountpoint
            if not mp or not os.path.exists(mp):
                continue
            try:
                usage = shutil.disk_usage(mp)
                if sys.platform == "win32":
                    letter = mp.rstrip(":\\").rstrip(":")
                    name = f"{letter}:" if letter.isalpha() else mp
                    path = f"{letter}:\\" if letter.isalpha() else mp
                else:
                    name = mp
                    path = mp
                drives.append({
                    "name": name, "path": path, "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024**3), 1),
                    "used_gb": round(usage.used / (1024**3), 1),
                    "free_gb": round(usage.free / (1024**3), 1),
                })
            except (PermissionError, OSError):
                continue
        self._json({"drives": drives})

    def _is_hidden_or_system(self, entry) -> bool:
        """Return True for Windows hidden/system files and protected OS directories."""
        if sys.platform != "win32":
            return False
        name = getattr(entry, "name", "")
        if name in ("System Volume Information", "$Recycle.Bin", "pagefile.sys", "swapfile.sys", "hiberfil.sys"):
            return True
        try:
            st = entry.stat()
            if hasattr(st, "st_file_attributes"):
                attrs = st.st_file_attributes
                return bool(attrs & (stat.FILE_ATTRIBUTE_HIDDEN | stat.FILE_ATTRIBUTE_SYSTEM))
        except (OSError, AttributeError):
            pass
        return False

    def _handle_files(self, qs):
        raw = qs.get("path", [""])[0]
        path = os.path.normpath(raw) if raw else os.path.expanduser("~")
        if not os.path.exists(path):
            return self._error(404, f"Path not found: {path}")
        if not os.path.isdir(path):
            return self._error(400, f"Not a directory: {path}")
        from datetime import datetime
        items = []
        try:
            with os.scandir(path) as entries:
                for entry in sorted(entries, key=lambda e: e.name.lower()):
                    if self._is_hidden_or_system(entry):
                        continue
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                        st = entry.stat()
                        sz = 0 if is_dir else st.st_size
                        mt = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
                    except OSError:
                        sz, mt = 0, ""
                    items.append({
                        "name": entry.name, "is_dir": is_dir,
                        "size": sz, "mtime": mt,
                        "ext": os.path.splitext(entry.name)[1].lower() if not is_dir else "",
                    })
        except PermissionError:
            pass
        total = len(items)
        if sys.platform == "win32":
            drive_root = os.path.splitdrive(path)[0] + "\\"
            parent_dir = os.path.dirname(path)
            parent = parent_dir if (parent_dir != path and path != drive_root) else None
        else:
            parent_dir = os.path.dirname(path)
            parent = parent_dir if parent_dir != path else None
        self._json({
            "path": path, "parent": parent,
            "items": items, "total": total,
        })

    def _handle_download(self, qs):
        raw = qs.get("path", [""])[0]
        path = os.path.normpath(raw)
        if not os.path.exists(path):
            return self._error(404, "File not found")
        if os.path.isdir(path):
            return self._error(400, "Cannot download directory")
        filename = os.path.basename(path)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    break

    def _handle_download_multi(self, qs):
        raw = qs.get("paths", [""])[0]
        raw_paths = [p for p in raw.split("|") if p.strip()]
        if not raw_paths:
            return self._error(400, "No files selected")
        if len(raw_paths) > 200:
            return self._error(400, "Too many files selected")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in raw_paths:
                p = os.path.normpath(p)
                if not os.path.exists(p):
                    continue
                if os.path.isdir(p):
                    base = os.path.basename(p) or p
                    for root, _dirs, files in os.walk(p):
                        for fn in files:
                            full = os.path.join(root, fn)
                            arc = os.path.join(base, os.path.relpath(full, p)).replace("\\", "/")
                            try:
                                zf.write(full, arc)
                            except (PermissionError, OSError):
                                pass
                else:
                    try:
                        zf.write(p, os.path.basename(p))
                    except (PermissionError, OSError):
                        pass
        buf.seek(0)
        data = buf.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", 'attachment; filename="download.zip"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _handle_upload(self, qs):
        raw = qs.get("path", [""])[0]
        path = os.path.normpath(raw) if raw else os.path.expanduser("~")
        if not os.path.isdir(path):
            return self._error(400, "Upload target must be a directory")
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return self._error(400, "Empty file")
        if content_length > 500 * 1024 * 1024:
            return self._error(413, "File too large (max 500MB)")
        ct = self.headers.get("Content-Type", "")
        fname = qs.get("filename", ["uploaded_file"])[0]
        dest = os.path.join(path, fname)
        if os.path.exists(dest):
            base, ext = os.path.splitext(fname)
            dest = os.path.join(path, f"{base}_1{ext}")
        data = self.rfile.read(content_length)
        if b"multipart/form-data" in ct.encode():
            boundary = ct.split("boundary=")[-1].strip().encode()
            boundary = boundary.strip(b'"')
            parts = data.split(boundary)
            if len(parts) >= 2:
                for part in parts:
                    if b"\r\n\r\n" in part:
                        headers, body = part.split(b"\r\n\r\n", 1)
                        if b"filename=" in headers:
                            data = body.rstrip(b"\r\n--")
                            break
        with open(dest, "wb") as f:
            f.write(data)
        self._json({"message": f"Uploaded to {dest}"})

    def _handle_update(self, qs):
        """Receive an installer package and start a silent upgrade."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return self._error(400, "Empty package")
        if content_length > 500 * 1024 * 1024:
            return self._error(413, "Package too large (max 500MB)")

        ct = self.headers.get("Content-Type", "")
        version = (qs.get("version") or [""])[0]

        # read-only for non-admin users. Fall back to the install directory if needed.
        from paths import CONFIG_DIR, INSTALL_DIR
        update_dir = os.path.join(CONFIG_DIR, "update")
        try:
            os.makedirs(update_dir, exist_ok=True)
        except Exception as e:
            _api_log.warning(f"Failed to create config update dir {update_dir}: {e}; falling back to install dir")
            update_dir = os.path.join(INSTALL_DIR, "update")
            try:
                os.makedirs(update_dir, exist_ok=True)
            except Exception as e2:
                return self._error(500, f"无法创建更新目录: {e2}")

        data = self.rfile.read(content_length)
        form_fields: dict = {}
        pkg_body = b""
        if b"multipart/form-data" in ct.encode():
            boundary = ct.split("boundary=")[-1].strip().encode()
            boundary = boundary.strip(b'"')
            parts = data.split(boundary)
            if len(parts) >= 2:
                # 🚨 requests 的 `data={"version": ...}` 是 multipart 表单字段，
                # 不是 URL query；只读 qs 会拿到空版本，签名串变成 ":<sha>"，
                # 与服务端的 "1.1.53:<sha>" 不符 → "签名不匹配"（2026-09-22 现场）。
                for part in parts:
                    if b"\r\n\r\n" not in part:
                        continue
                    phead, pbody = part.split(b"\r\n\r\n", 1)
                    if b'filename="' in phead or b"filename=" in phead:
                        pkg_body = pbody.rstrip(b"\r\n--")
                        continue
                    if b'name="' in phead:
                        _n = phead.split(b'name="', 1)[1].split(b'"', 1)[0]
                        form_fields[_n.decode("utf-8", "ignore")] = \
                            pbody.rstrip(b"\r\n--").decode("utf-8", "ignore").strip()
                if pkg_body:
                    data = pkg_body

        version = version or form_fields.get("version", "")
        filename = f"VigilServeAgent-Setup-{version}.exe" if version else "VigilServeAgent-Setup.exe"
        dest = os.path.join(update_dir, filename)
        try:
            with open(dest, "wb") as f:
                f.write(data)
        except Exception as e:
            return self._error(500, f"保存安装包失败: {e}")

        # P1-2（更新包验签，fail-closed）+ 2026-09-23 开源加固 ④：
        # 服务端签名头缺失、哈希不符、时间戳不新鲜或签名校验失败，
        # 一律删除已落盘的包并拒绝执行 —— 防止被篡改/伪造的包在本机静默提权执行。
        # 具体校验见 `verify_update_package()`（抽成模块级函数就是为了能单测）。
        def _reject_pkg(reason: str):
            try:
                os.remove(dest)
            except OSError:
                pass
            _api_log.warning(f"Update package rejected and deleted: {reason} ({dest})")
            return self._error(400, f"更新包校验失败: {reason}")

        _ok, _reason = verify_update_package(
            data, version,
            self.headers.get("X-Pkg-Sha256", ""),
            self.headers.get("X-Pkg-Signature", ""),
            self.headers.get("X-Pkg-Timestamp", ""),
        )
        if not _ok:
            return _reject_pkg(_reason)

        _api_log.info(f"Agent update package saved to {dest} ({len(data)} bytes, signature verified)")

        def _is_admin() -> bool:
            try:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False

        def _run_installer():
            try:
                time.sleep(1)
                if not sys.platform.startswith("win"):
                    _api_log.warning("Linux agent self-update is not implemented")
                    return

                params = "/SILENT /FORCECLOSEAPPLICATIONS /RESTARTAPPLICATIONS /UPDATEFLOW"
                if _is_admin():
                    args = [dest, "/SILENT", "/FORCECLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS", "/UPDATEFLOW"]
                    _api_log.info(f"Starting installer: {' '.join(args)}")
                    subprocess.Popen(
                        args,
                        shell=False,
                        close_fds=True,
                        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                    )
                else:
                    # overwrite files under Program Files. The user must confirm
                    # the UAC prompt on the target machine.
                    _api_log.info(f"Requesting elevation to run installer: {dest} {params}")
                    import ctypes
                    SW_SHOW_NORMAL = 1
                    ret = ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", dest, params, None, SW_SHOW_NORMAL
                    )
                    if ret <= 32:
                        _api_log.error(f"ShellExecute runas failed with code {ret}")
                        return

                time.sleep(2)
                os._exit(0)
            except Exception as e:
                _api_log.error(f"Failed to start installer: {e}")

        threading.Thread(target=_run_installer, daemon=True).start()
        self._json({
            "success": True,
            "message": "安装包已接收，正在执行静默升级",
            "package_path": dest,
            "new_version": version,
        })

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8")
            return json.loads(raw)
        except Exception:
            return {}

    def _handle_power(self):
        data = self._read_json_body()
        action = (data.get("action") or "").lower()
        if action not in ("restart", "shutdown"):
            return self._error(400, "action must be 'restart' or 'shutdown'")

        _api_log.info(f"Power action requested: {action}")
        try:
            if sys.platform.startswith("win"):
                if action == "restart":
                    subprocess.Popen(["shutdown", "/r", "/t", "5", "/f"],
                                     shell=False, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
                else:
                    subprocess.Popen(["shutdown", "/s", "/t", "5", "/f"],
                                     shell=False, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
            else:
                if action == "restart":
                    subprocess.Popen(["shutdown", "-r", "+0"], shell=False, close_fds=True)
                else:
                    subprocess.Popen(["shutdown", "-h", "now"], shell=False, close_fds=True)
        except Exception as e:
            _api_log.error(f"Failed to execute power action {action}: {e}")
            return self._error(500, f"执行{('重启' if action == 'restart' else '关机')}命令失败: {e}")

        label = "重启" if action == "restart" else "关机"
        self._json({"success": True, "message": f"{label}命令已下发，目标主机将在 5 秒后执行{label}"})

    def _handle_system_info(self):
        try:
            from host_info import collect_host_info
            self._json(collect_host_info())
        except Exception as e:  # noqa: BLE001
            _api_log.error(f"system-info endpoint failed: {e}")
            self._error(500, f"采集主机信息失败: {e}")

    def _handle_applications(self):
        try:
            from host_info import list_applications
            self._json({"items": list_applications()})
        except Exception as e:  # noqa: BLE001
            _api_log.error(f"applications endpoint failed: {e}")
            self._error(500, f"读取已安装应用失败: {e}")

    def _handle_app_updates(self):
        try:
            from host_info import list_system_updates
            self._json({"items": list_system_updates()})
        except Exception as e:  # noqa: BLE001
            _api_log.error(f"application updates endpoint failed: {e}")
            self._error(500, f"读取系统更新失败: {e}")

    def _handle_app_uninstall(self):
        data = self._read_json_body()
        ids = data.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return self._error(400, "ids 不能为空")
        try:
            from host_info import uninstall_applications
            res = uninstall_applications(ids)
        except Exception as e:  # noqa: BLE001
            _api_log.error(f"uninstall endpoint failed: {e}")
            return self._error(500, f"卸载失败: {e}")
        if res.get("ok"):
            self._json(res)
        else:
            self._json(res, 200)

    def _handle_startup_list(self):
        try:
            from host_info import list_startup_items
            self._json({"items": list_startup_items()})
        except Exception as e:  # noqa: BLE001
            _api_log.error(f"startup list endpoint failed: {e}")
            self._error(500, f"读取启动项失败: {e}")

    def _handle_startup_toggle(self, raw_id):
        from urllib.parse import unquote as _unquote
        item_id = _unquote(raw_id or "")
        if not item_id:
            return self._error(400, "缺少启动项标识")
        data = self._read_json_body()
        enabled = data.get("enabled")
        if not isinstance(enabled, bool):
            return self._error(400, "enabled 必须为布尔值")
        try:
            from host_info import set_startup_enabled
            res = set_startup_enabled(item_id, enabled)
        except Exception as e:  # noqa: BLE001
            _api_log.error(f"startup toggle endpoint failed: {e}")
            return self._error(500, f"切换启动项状态失败: {e}")
        if not res.get("ok"):
            return self._error(400, res.get("detail") or "切换启动项状态失败")
        self._json(res)

    def _handle_event_logs(self, qs):
        level = (qs.get("level", [""])[0] or "").strip()
        try:
            limit = int(qs.get("limit", ["200"])[0])
        except (TypeError, ValueError):
            limit = 200
        start = (qs.get("start", [""])[0] or "").strip()
        end = (qs.get("end", [""])[0] or "").strip()
        try:
            from host_info import list_event_logs
            self._json({"items": list_event_logs(level, limit, start, end)})
        except Exception as e:  # noqa: BLE001
            _api_log.error(f"event-logs endpoint failed: {e}")
            self._error(500, f"读取事件日志失败: {e}")

    def _handle_copy(self):
        data = self._read_json_body()
        sources = data.get("sources") or []
        target = data.get("target", "")
        if not sources:
            return self._error(400, "未选择要复制的文件")
        target = os.path.normpath(target)
        if not os.path.isdir(target):
            return self._error(400, f"Target is not a directory: {target}")
        copied = []
        errors = []
        for src in sources:
            src = os.path.normpath(src)
            if not os.path.exists(src):
                errors.append(f"{src}: 不存在")
                continue
            name = os.path.basename(src) or src
            dest = os.path.join(target, name)
            if os.path.exists(dest):
                base, ext = os.path.splitext(name)
                dest = os.path.join(target, f"{base}_副本{ext}")
            try:
                if os.path.isdir(src):
                    shutil.copytree(src, dest)
                else:
                    shutil.copy2(src, dest)
                copied.append(dest)
            except (PermissionError, OSError) as e:
                errors.append(f"{src}: {e}")
        self._json({"copied": copied, "errors": errors})

    def _handle_delete(self):
        data = self._read_json_body()
        paths = data.get("paths") or []
        if not paths:
            return self._error(400, "未选择要删除的文件")
        deleted = []
        errors = []
        for p in paths:
            p = os.path.normpath(p)
            if not os.path.exists(p):
                errors.append(f"{p}: 不存在")
                continue
            try:
                if os.path.isdir(p):
                    shutil.rmtree(p)
                else:
                    os.remove(p)
                deleted.append(p)
            except (PermissionError, OSError) as e:
                errors.append(f"{p}: {e}")
        self._json({"deleted": deleted, "errors": errors})

    def _handle_mkdir(self):
        data = self._read_json_body()
        path = data.get("path", "")
        if not path:
            return self._error(400, "未指定目录路径")
        path = os.path.normpath(path)
        if os.path.exists(path):
            return self._error(400, f"已存在: {path}")
        try:
            os.makedirs(path, exist_ok=False)
            self._json({"created": path})
        except (PermissionError, OSError) as e:
            self._error(500, str(e))

    def _handle_rename(self):
        data = self._read_json_body()
        source = data.get("source", "")
        target = data.get("target", "")
        if not source or not target:
            return self._error(400, "源路径和目标路径不能为空")
        source = os.path.normpath(source)
        target = os.path.normpath(target)
        if not os.path.exists(source):
            return self._error(404, f"源文件不存在: {source}")
        if os.path.exists(target):
            return self._error(400, f"目标已存在: {target}")
        try:
            os.rename(source, target)
            self._json({"renamed": target})
        except (PermissionError, OSError) as e:
            self._error(500, str(e))

    MAX_TEXT_BYTES = 2 * 1024 * 1024

    @staticmethod
    def _unique_path(path):
        """Return path with ' (2)', ' (3)'... suffix if it already exists."""
        if not os.path.exists(path):
            return path
        base, ext = os.path.splitext(path)
        i = 2
        while os.path.exists(f"{base} ({i}){ext}"):
            i += 1
        return f"{base} ({i}){ext}"

    def _handle_read_text(self, qs):
        raw = qs.get("path", [""])[0]
        if not raw:
            return self._error(400, "未指定文件路径")
        path = os.path.normpath(raw)
        if not os.path.isfile(path):
            return self._error(404, f"文件不存在: {path}")
        size = os.path.getsize(path)
        if size > self.MAX_TEXT_BYTES:
            return self._error(400, "文件超过 2MB，不支持在线编辑")
        try:
            with open(path, "rb") as f:
                raw_bytes = f.read()
        except (PermissionError, OSError) as e:
            return self._error(500, str(e))
        for enc in ("utf-8-sig", "utf-8", "gbk"):
            try:
                return self._json({"path": path, "content": raw_bytes.decode(enc), "size": size})
            except UnicodeDecodeError:
                continue
        self._json({"path": path, "content": raw_bytes.decode("utf-8", errors="replace"), "size": size})

    def _handle_write_text(self):
        data = self._read_json_body()
        path = data.get("path", "")
        content = data.get("content", "")
        if not path:
            return self._error(400, "未指定文件路径")
        path = os.path.normpath(path)
        if not os.path.isfile(path):
            return self._error(404, f"文件不存在: {path}")
        if len(content.encode("utf-8")) > self.MAX_TEXT_BYTES:
            return self._error(400, "内容超过 2MB，拒绝写入")
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(content)
            self._json({"written": path})
        except (PermissionError, OSError) as e:
            self._error(500, str(e))

    def _handle_create_file(self):
        data = self._read_json_body()
        path = data.get("path", "")
        if not path:
            return self._error(400, "未指定文件路径")
        path = os.path.normpath(path)
        if os.path.exists(path):
            return self._error(400, f"已存在: {path}")
        try:
            with open(path, "w", encoding="utf-8") as f:
                pass
            self._json({"created": path})
        except (PermissionError, OSError) as e:
            self._error(500, str(e))

    def _handle_zip(self):
        data = self._read_json_body()
        paths = data.get("paths") or []
        target_dir = data.get("target_dir", "")
        zip_name = data.get("zip_name", "")
        if not paths:
            return self._error(400, "未选择要压缩的文件")
        if not target_dir:
            return self._error(400, "未指定压缩包保存目录")
        target_dir = os.path.normpath(target_dir)
        if not os.path.isdir(target_dir):
            return self._error(400, f"目标目录不存在: {target_dir}")
        base = os.path.basename(zip_name or "archive")
        if not base or base in (".", ".."):
            base = "archive"
        if not base.lower().endswith(".zip"):
            base += ".zip"
        dest = self._unique_path(os.path.join(target_dir, base))
        count = 0
        try:
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
                for p in paths:
                    p = os.path.normpath(p)
                    if not os.path.exists(p):
                        continue
                    if os.path.isdir(p):
                        root_name = os.path.basename(p.rstrip("\\/")) or "folder"
                        for root, _dirs, files in os.walk(p):
                            for fn in files:
                                full = os.path.join(root, fn)
                                arc = os.path.join(root_name, os.path.relpath(full, p)).replace("\\", "/")
                                try:
                                    zf.write(full, arc)
                                    count += 1
                                except (PermissionError, OSError):
                                    pass
                    else:
                        try:
                            zf.write(p, os.path.basename(p))
                            count += 1
                        except (PermissionError, OSError):
                            pass
            _api_log.info(f"zip endpoint: {len(paths)} paths -> {dest} ({count} files)")
            self._json({"zip_path": dest, "count": count})
        except (PermissionError, OSError) as e:
            self._error(500, str(e))

    def _handle_unzip(self):
        data = self._read_json_body()
        raw = data.get("path", "")
        if not raw:
            return self._error(400, "未指定要解压的文件")
        path = os.path.normpath(raw)
        if not os.path.exists(path) or not zipfile.is_zipfile(path):
            return self._error(400, f"不是有效的 zip 文件: {path}")
        parent = os.path.dirname(path)
        stem = os.path.splitext(os.path.basename(path))[0]
        dest = self._unique_path(os.path.join(parent, stem))
        try:
            os.makedirs(dest, exist_ok=True)
            dest_real = os.path.realpath(dest)
            with zipfile.ZipFile(path, "r") as zf:
                for member in zf.namelist():
                    target = os.path.realpath(os.path.join(dest, member))
                    if not (target == dest_real or target.startswith(dest_real + os.sep)):
                        continue
                zf.extractall(dest)
            _api_log.info(f"unzip endpoint: {path} -> {dest}")
            self._json({"dest": dest})
        except (PermissionError, OSError, zipfile.BadZipFile) as e:
            self._error(500, str(e))

    def _handle_rdp_control(self, active: bool):
        fn = _rdp_controller.get("fn")
        if fn is None:
            return self._json({"ok": False, "message": "远程桌面控制器未注册"})
        try:
            fn(active)
            self._json({"ok": True, "active": active})
        except Exception as e:  # noqa: BLE001
            _api_log.error(f"rdp control endpoint failed: {e}")
            self._error(500, f"设置远程桌面状态失败: {e}")

    def _handle_config_get(self):
        try:
            import config as _cfg
            cfg = _cfg.load()
        except Exception:
            cfg = {}
        html = _render_config_html(cfg, _local_token())
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_config_post(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0 or length > 64 * 1024:
                return self._error(400, "Empty or too large payload")
            raw = self.rfile.read(length).decode("utf-8")
            data = parse_qs(raw)
            import config as _cfg
            cfg = _cfg.load()
            if "server_host" in data:
                cfg["server_host"] = data["server_host"][0].strip()
                cfg["server_url"] = ""
            if "server_port" in data:
                try:
                    cfg["server_port"] = int(data["server_port"][0])
                except ValueError:
                    pass
            if "api_port" in data:
                try:
                    cfg["api_port"] = int(data["api_port"][0])
                except ValueError:
                    pass
            if "auto_start" in data:
                cfg["auto_start"] = data["auto_start"][0] in ("1", "true", "on", "yes")
            _cfg.save(cfg)
            try:
                from config import set_auto_start as _setas
                _setas(cfg.get("auto_start", False))
            except Exception:
                pass
            self._json({"message": "配置已保存，请重启 agent 使 API 端口生效", "config": cfg})
        except Exception as e:
            self._error(500, f"Save failed: {e}")

    def _handle_ws_terminal(self):
        upgrade = self.headers.get("Upgrade", "").lower()
        if upgrade != "websocket":
            return self._error(400, "WebSocket upgrade required")
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            return self._error(400, "Missing Sec-WebSocket-Key")
        import hashlib
        import base64
        magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept = base64.b64encode(hashlib.sha1(key.encode() + magic).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

        if sys.platform != "win32" or WinPtyProcess is None:
            ws_send(self, b"\r\n\x1b[31mPTY terminal requires Windows + pywinpty.\x1b[0m")
            return

        cwd = os.path.expanduser("~")
        backend = WinBackend.WinPTY if WinBackend else 1
        try:
            proc = WinPtyProcess.spawn(
                ["cmd.exe", "/K", "prompt $P$G"],
                cwd=cwd,
                dimensions=(24, 80),
                backend=backend,
            )
        except Exception as e:
            import traceback as _tb
            _tb.print_exc()
            ws_send(self, f"\r\n\x1b[31mPTY spawn failed: {e}\x1b[0m".encode("utf-8"))
            return

        import threading as _th
        import queue as _queue
        out_q = _queue.Queue(maxsize=4096)
        stop = _th.Event()
        _SENTINEL = object()

        def pty_reader():
            """Read from PTY and push to output queue."""
            try:
                while not stop.is_set() and proc.isalive():
                    try:
                        chunk = proc.read(4096)
                    except EOFError:
                        break
                    if chunk:
                        out_q.put(chunk)
            except Exception:
                pass
            finally:
                out_q.put(_SENTINEL)

        def pty_writer():
            """Read from WebSocket and write to PTY."""
            try:
                while not stop.is_set() and proc.isalive():
                    try:
                        opcode, payload = ws_recv(self)
                    except ConnectionError:
                        break
                    if opcode == 0x9:
                        continue
                    if opcode == 0x1 and payload:
                        try:
                            msg = json.loads(payload.decode("utf-8"))
                        except Exception:
                            continue
                        mtype = msg.get("type")
                        if mtype == "resize":
                            try:
                                proc.setwinsize(int(msg["rows"]), int(msg["cols"]))
                            except Exception:
                                pass
                        elif mtype == "ping":
                            try:
                                ws_send(self, json.dumps({"type": "pong"}).encode("utf-8"), opcode=0x81)
                            except Exception:
                                pass
                        continue
                    if opcode == 0x2 and payload:
                        try:
                            proc.write(payload.decode("utf-8", errors="replace"))
                        except Exception:
                            break
            except Exception:
                pass
            finally:
                stop.set()

        def ws_sender():
            """Drain output queue and send to WebSocket."""
            try:
                while True:
                    chunk = out_q.get()
                    if chunk is _SENTINEL:
                        break
                    try:
                        ws_send(self, chunk.encode("utf-8", errors="replace"))
                    except Exception:
                        break
            except Exception:
                pass
            finally:
                stop.set()

        def _get_cmd_windows_ver():
            try:
                result = subprocess.run(
                    ["cmd.exe", "/c", "ver"],
                    capture_output=True, text=True, timeout=5, check=False
                )
                for line in result.stdout.splitlines():
                    import re

                    m = re.search(r"\[\s*(?:版本|Version)?\s*([\d.]+)\s*\]", line)
                    if m:
                        return m.group(1)
            except Exception:
                pass
            return f"{sys.getwindowsversion().major}.{sys.getwindowsversion().minor}.{sys.getwindowsversion().build}"

        win_ver = _get_cmd_windows_ver()
        banner = f"\r\n\x1b[32mVigilServe Agent Terminal\x1b[0m - {socket.gethostname()} [版本 {win_ver}]\r\n".encode("utf-8")
        ws_send(self, banner, opcode=0x82)

        t_reader = _th.Thread(target=pty_reader, daemon=True)
        t_writer = _th.Thread(target=pty_writer, daemon=True)
        t_sender = _th.Thread(target=ws_sender, daemon=True)
        t_reader.start()
        t_writer.start()
        t_sender.start()

        while not stop.is_set():
            stop.wait(0.1)

        try:
            proc.terminate(force=True)
        except Exception:
            pass


def _render_config_html(cfg, local_token=""):
    """Same fields as the tkinter window, served as HTML.

    `local_token` 是本页自己的口令（R-7），只写进页面里的那句 fetch —— 页面
    提交配置时要回带给服务端，否则会被 `/config` 的口令校验挡掉。
    """
    import html as _h
    host = cfg.get("server_host", "").strip()
    port = cfg.get("server_port", 8001)
    if not host and cfg.get("server_url"):
        legacy = cfg["server_url"].strip()
        if legacy:
            from urllib.parse import urlparse
            parsed = urlparse(legacy)
            host = parsed.hostname or legacy.replace("http://", "").replace("https://", "").rstrip("/")
            port = parsed.port or 8001
    host = _h.escape(host)
    sp = port
    ap = cfg.get("api_port") or DEFAULTS["api_port"]
    au = "checked" if cfg.get("auto_start") else ""
    sid = cfg.get("server_id", 0)
    tok = cfg.get("token", "") or ""
    # 本机浏览器就能打开这个页面，token 不能明文显示（只留后 4 位便于比对）
    tok_show = ("*" * 12 + tok[-4:]) if len(tok) > 4 else ("*" * len(tok))
    if not tok_show:
        tok_show = "(未注册)"
    hostname = socket.gethostname()
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VigilServe Agent 配置</title>
<style>
body {{ font-family: -apple-system, "Microsoft YaHei", sans-serif; background:#f8f9fa; margin:0; padding:30px; }}
.card {{ max-width: 480px; margin: 0 auto; background:#fff; border:1px solid #dee2e6; border-radius:8px; padding:30px; }}
h1 {{ margin:0 0 4px; font-size:24px; color:#4361ee; }}
.sub {{ color:#6c757d; font-size:12px; margin-bottom:24px; }}
label {{ display:block; font-size:14px; margin-bottom:6px; color:#212529; }}
input[type=text], input[type=number] {{ padding:8px; border:1px solid #dee2e6; border-radius:4px; font-size:14px; box-sizing:border-box; }}
input[type=text] {{ width: 66%; }}
input[type=number] {{ width: 90px; }}
.row {{ margin-bottom:16px; }}
.flex {{ display:flex; align-items:center; gap:12px; }}
.info {{ background:#e9ecef; padding:10px; border-radius:4px; font-family:Consolas,monospace; font-size:13px; margin-bottom:16px; word-break:break-all; }}
.btn {{ background:#4361ee; color:#fff; border:none; border-radius:4px; padding:10px 20px; font-size:14px; cursor:pointer; margin-right:8px; }}
.btn:hover {{ background:#3a56d4; }}
#msg {{ margin-top:12px; color:#06d6a0; font-size:13px; }}
.check {{ margin-top:6px; }}
</style></head>
<body>
<div class="card">
  <h1>VigilServe Agent</h1>
  <div class="sub">VigilServe 客户端配置 — {hostname}</div>
  <form method="POST" action="/config" onsubmit="return saveCfg(event)">
    <div class="row">
      <label>服务端地址</label>
      <div class="flex">
        <input type="text" name="server_host" value="{host}" placeholder="">
        <label style="margin:0;white-space:nowrap;">服务端口</label>
        <input type="number" name="server_port" value="{sp}" min="1" max="65535">
      </div>
    </div>
    <div class="row">
      <label>API 端口（文件浏览/终端）</label>
      <input type="number" name="api_port" value="{ap}" min="1024" max="65535" style="width:90px;">
    </div>
    <div class="row check">
      <label><input type="checkbox" name="auto_start" value="1" {au}> 开机自动启动</label>
    </div>
    <div class="info">Server ID: {sid}<br>Token: {tok_show}</div>
    <button class="btn" type="submit">保存配置</button>
    <span id="msg"></span>
  </form>
</div>
<script>
async function saveCfg(e) {{
  e.preventDefault();
  const fd = new FormData(e.target);
  const res = await fetch('/config', {{ method:'POST', body: fd,
    headers: {{ 'X-Local-Token': '{local_token}' }} }});
  const data = await res.json();
  document.getElementById('msg').textContent = data.message || (res.ok ? '已保存' : '失败');
  return false;
}}
</script>
</body></html>"""



def ws_send(handler, payload, opcode=0x82):
    """Send a WebSocket frame. Default opcode 0x82 = binary; 0x81 = text."""
    data = bytearray()
    data.append(opcode | 0x80)
    ln = len(payload)
    if ln < 126:
        data.append(ln)
    elif ln < 65536:
        data.append(126)
        data.extend(ln.to_bytes(2, "big"))
    else:
        data.append(127)
        data.extend(ln.to_bytes(8, "big"))
    data.extend(payload)
    try:
        handler.wfile.write(bytes(data))
        handler.wfile.flush()
    except Exception:
        pass


def ws_recv(handler, timeout=0.05):
    """Receive a WebSocket frame. Returns (opcode, payload).

    opcode 0x1 = text, 0x2 = binary, 0x8 = close, 0x9 = ping.
    For ping frames an automatic pong is sent and (0x9, b"") is returned.
    For close frames ConnectionError is raised.
    """
    import select
    ready, _, _ = select.select([handler.rfile], [], [], timeout)
    if not ready:
        return 0x2, b""
    first = handler.rfile.read(2)
    if not first or len(first) < 2:
        raise ConnectionError("WS closed")
    fin, opcode = (first[0] & 0x80) != 0, first[0] & 0x0F
    masked = (first[1] & 0x80) != 0
    length = first[1] & 0x7F
    if length == 126:
        length = int.from_bytes(handler.rfile.read(2), "big")
    elif length == 127:
        length = int.from_bytes(handler.rfile.read(8), "big")
    mask_key = handler.rfile.read(4) if masked else b""
    payload = bytearray(handler.rfile.read(length))
    if masked:
        for i in range(len(payload)):
            payload[i] ^= mask_key[i % 4]
    if opcode == 0x8:
        raise ConnectionError("WS closed")
    if opcode == 0x9:
        pong = bytearray(b"\x8A\x00")
        try:
            handler.wfile.write(bytes(pong))
            handler.wfile.flush()
        except Exception:
            raise ConnectionError("WS closed")
        return 0x9, b""
    return opcode, bytes(payload)



def get_status():
    try:
        import config as _cfg_mod
        cfg = _cfg_mod.load()
    except Exception:
        cfg = {}
    return {
        "hostname": socket.gethostname(),
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "api_port": int(cfg.get("api_port") or 9998),
        "server_url": cfg.get("server_url", ""),
        "server_id": cfg.get("server_id", 0),
        "auto_start": cfg.get("auto_start", False),
        "version": AGENT_VERSION,
        "agent_version": AGENT_VERSION,
    }


def open_web_config_browser(port):
    import threading
    import webbrowser
    def _open():
        import time; time.sleep(0.5)
        try:
            # P1-1：9998 已全链路 TLS（本机自签/服务端签发），浏览器打开需 https。
            # R-7：URL 里带上本机配置口令 —— 这是唯一一次明文出现在地址栏，
            # 之后的提交走 X-Local-Token 头，不留历史/Referer。
            webbrowser.open(f"https://127.0.0.1:{port}/config?t={_local_token()}")
        except: pass
    threading.Thread(target=_open, daemon=True).start()


def _is_admin() -> bool:
    """Return True if the current process has administrator privileges."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _server_host_ip() -> str:
    """配置里的 VigilServe 服务端 IPv4（用于把防火墙规则限定到该来源）。

    域名/主机名不返回 —— netsh 的 remoteip 需要 IP，写域名会导致规则非法。
    """
    try:
        import config as _cfg_mod
        cfg = _cfg_mod.load() or {}
    except Exception:
        return ""
    host = (cfg.get("server_host") or "").strip()
    if not host:
        legacy = (cfg.get("server_url") or "").strip()
        if legacy:
            from urllib.parse import urlparse
            host = (urlparse(legacy).hostname or "")
    host = host.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip()
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return host
    return ""


def _firewall_rule_state(name: str) -> tuple[bool, str]:
    """返回 (规则是否存在, netsh 原始输出)。"""
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f'name={name}'],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        out = (result.stdout or "") + (result.stderr or "")
        return (result.returncode == 0 and name in out), out
    except Exception:
        return False, ""


def _firewall_rule_exists(name: str) -> bool:
    return _firewall_rule_state(name)[0]


def _firewall_rule_matches(state_out: str, remoteip: str, port: int) -> bool:
    """规则是否已经是我们想要的样子（限定来源 IP + 仅 API 端口）。"""
    text = (state_out or "").replace(" ", "")
    if remoteip and remoteip not in text:
        return False
    if port and str(port) not in text:
        return False
    return True


def _netsh_add_rule(program_path: str, remoteip: str, port: int) -> tuple[bool, str]:
    args = [
        "advfirewall", "firewall", "add", "rule",
        f'name={_FIREWALL_RULE}',
        'dir=in',
        'action=allow',
        f'program="{program_path}"',
        'protocol=TCP',
        f'localport={port}',
        'enable=yes',
        'profile=any',
    ]
    if remoteip:
        args.append(f'remoteip={remoteip}')
    try:
        r = subprocess.run(["netsh"] + args, capture_output=True, text=True,
                           timeout=30, check=False)
        out = (r.stdout or "") + (r.stderr or "")
        return r.returncode == 0, out.strip()
    except Exception as e:  # noqa: BLE001
        return False, str(e)


_FIREWALL_RULE = "VigilServe Agent"


def _ensure_firewall_rule(program_path: str, port: int = 9998):
    """为 Agent API 端口加一条**来源受限**的入站规则（安全加固阶段 1）。

    与旧版的区别：
      - 只放行服务端 IP（remoteip），不再对整个网段开口
      - 只放行 TCP 的 Agent API 端口，而不是该程序的全部端口
      - 规则存在但作用域不对（例如旧版遗留的全网段规则）时，删除后按新策略重建
    非管理员时弹一次 UAC 提权。
    """
    if not sys.platform.startswith("win"):
        return

    remoteip = _server_host_ip()
    exists, out = _firewall_rule_state(_FIREWALL_RULE)
    if exists and _firewall_rule_matches(out, remoteip, port):
        _api_log.info("Windows Firewall inbound rule already exists and is correctly scoped")
        return
    if exists and not remoteip:
        # 取不到服务端 IP 时无法收窄，保持原样（避免把已能工作的连通性弄坏）
        _api_log.warning("Firewall rule exists but server IP unknown; leaving it unchanged")
        return

    action_desc = "重建（作用域不符）" if exists else "创建"
    if not _is_admin():
        _api_log.info("Agent is not running as administrator; requesting elevation for firewall rule")
        try:
            del_part = f'advfirewall firewall delete rule name="{_FIREWALL_RULE}" & ' if exists else ""
            params = (
                f'/c {del_part}'
                f'netsh advfirewall firewall add rule name="{_FIREWALL_RULE}" '
                f'dir=in action=allow program="{program_path}" protocol=TCP localport={port} '
                + (f'remoteip={remoteip} ' if remoteip else '')
                + 'enable=yes profile=any'
            )
            SW_HIDE = 0
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", params, None, SW_HIDE)
            if ret <= 32:
                _api_log.warning(f"Failed to request elevation for firewall rule: code {ret}")
            else:
                _api_log.info("UAC prompt shown for one-time firewall rule creation")
        except Exception as e:  # noqa: BLE001
            _api_log.warning(f"Could not request elevation for firewall rule: {e}")
        return

    if exists:
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                            f'name={_FIREWALL_RULE}'], capture_output=True, text=True,
                           timeout=20, check=False)
        except Exception as e:  # noqa: BLE001
            _api_log.warning(f"Could not delete stale firewall rule: {e}")
    ok, msg = _netsh_add_rule(program_path, remoteip, port)
    if ok:
        _api_log.info(f"Firewall inbound rule {action_desc}完成：program={program_path} "
                      f"port={port} remoteip={remoteip or '(未限定)'}")
    else:
        _api_log.warning(f"Failed to add firewall rule: {msg}")


def _allow_plaintext_api() -> bool:
    """是否允许 9998 在没有 TLS 的情况下以**明文**监听（默认否）。

    交付审查补漏：以前证书材料拿不到就直接退明文，而这个 listener 绑的是
    0.0.0.0 —— 等于把 Agent 的远程操作接口（含认证头）整条链路裸在网里，
    而且日志只是一行 error，运维很难注意到。现在默认 fail closed：宁可这个
    端口起不来，也不要悄悄明文。真要临时放行显式设
    VIGILSERVE_AGENT_ALLOW_PLAINTEXT=1。
    """
    return os.environ.get("VIGILSERVE_AGENT_ALLOW_PLAINTEXT", "0") == "1"


def _pick_api_tls_material():
    """选 9998 的 TLS 材料：服务端 CA 签发的正式证书优先，否则本地自签兜底。

    返回 (cert_path, key_path)；都拿不到返回 (None, None)
    —— 此时是否还监听取决于 `_allow_plaintext_api()`，见 `_build_tls_server`。
    """
    try:
        import identity as _identity
        if _identity.load_api_cert_pem() and os.path.isfile(_identity.API_KEY_PATH):
            return _identity.API_CERT_PATH, _identity.API_KEY_PATH
        # 没有正式证书 → 自签一张，保证通道加密（服务端会因 CA 链不符而拒绝，等领证后热切换）
        cert, key = _identity.ensure_self_signed_cert()
        return cert, key
    except Exception as e:  # noqa: BLE001
        _api_log.error(f"无法准备 9998 TLS 材料：{e}")
        return None, None


def _build_tls_server(port: int):
    """建一个按当前最优证书包了 TLS 的 ThreadingHTTPServer。

    拿不到任何可用证书时**默认不监听**（返回 (None, None)），而不是退明文 ——
    详见 `_allow_plaintext_api()` 的说明。
    """
    # ⚠ 2026-09-23 开源加固 ③：这里**曾经硬编码 0.0.0.0**，于是下面那套
    #   `VIGILSERVE_AGENT_BIND_HOST` 说明写了半天、`_agent_bind_host()` 却是**死代码**
    #   （全仓库没有任何调用点）—— 运维照文档配了环境变量，端口照样对外全开。
    #   现在真正接上。默认值仍是 0.0.0.0：Agent 是分布式部署的，服务端要**主动**
    #   来连这个端口做电源操作 / 文件管理 / 远程桌面，改成回环会直接切断远程管理能力
    #   （用户 2026-09-23 拍板：只接开关，默认不动）。
    server = ThreadingHTTPServer((_agent_bind_host(), port), AgentAPIHandler)
    cert, key = _pick_api_tls_material()
    if cert and key:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            _api_log.info(f"Agent API (port {port}) running over TLS (cert: {cert})")
            return server, cert
        except Exception as e:  # noqa: BLE001
            # 证书与私钥不配（例如重装丢了 key 但正式证书还在）→ 退自签再试一次
            _api_log.warning(f"加载 9998 TLS 证书失败（{e}），改用本地自签兜底")
            try:
                import identity as _identity
                sc, sk = _identity.ensure_self_signed_cert()
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(sc, sk)
                server.server_close()
                server2 = ThreadingHTTPServer((_agent_bind_host(), port), AgentAPIHandler)
                server2.socket = ctx.wrap_socket(server2.socket, server_side=True)
                _api_log.info(f"Agent API (port {port}) running over TLS (self-signed fallback)")
                return server2, sc
            except Exception as e2:  # noqa: BLE001
                _api_log.error(f"自签证书也不可用：{e2}")
                return _no_tls_fallback(server, port)
    _api_log.error(f"Agent API (port {port}) 无任何可用 TLS 材料")
    return _no_tls_fallback(server, port)


def _no_tls_fallback(server, port: int):
    """拿不到证书时的收尾：默认关掉监听，只有显式放行才继续明文跑。"""
    if _allow_plaintext_api():
        _api_log.error(f"⚠ 按 VIGILSERVE_AGENT_ALLOW_PLAINTEXT=1，Agent API (port {port}) "
                       "以**明文 HTTP** 监听，仅排障使用")
        return server, None
    _api_log.error(f"拒绝在无 TLS 的情况下监听 {port}（该 listener 绑 {_agent_bind_host()}，"
                   "明文等于把远程操作接口裸在网里）。临时放行请设 "
                   "VIGILSERVE_AGENT_ALLOW_PLAINTEXT=1")
    try:
        server.server_close()
    except Exception:  # noqa: BLE001
        pass
    return None, None


# 模块级状态：当前 9998 server 实例 + 在用的证书路径（热切换 watcher 用）
_api_httpd = None
_api_port = None
_api_tls_cert = None
_tls_watcher_started = False


def reload_tls_if_updated():
    """正式证书落盘后热切换 9998 的 TLS 材料（P1-1）。

    Agent 启动时往往还没有服务端签发的证书（要等 register/enroll 带回来），
    watcher 每 10 秒对一次账：在用证书不是当前最优 → 关旧 listener 换新的。
    另外，启动那会儿因为拿不到 TLS 材料而**没起来**的 listener（fail closed，
    见 `_allow_plaintext_api`）也在这里补起 —— 否则那台机器会永久失去远程操作。
    """
    global _api_httpd, _api_tls_cert
    if _api_port is None:
        return
    if _api_httpd is None:
        try:
            start_api_server(_api_port)
        except Exception:  # noqa: BLE001  下一轮再试
            pass
        return
    try:
        import identity as _identity
        has_formal = bool(_identity.load_api_cert_pem()) and os.path.isfile(_identity.API_KEY_PATH)
    except Exception:  # noqa: BLE001
        return
    if has_formal and _api_tls_cert != _identity.API_CERT_PATH:
        _api_log.info("检测到服务端签发的 9998 证书，热切换 TLS listener ...")
        try:
            old = _api_httpd
            _api_httpd, _api_tls_cert = None, None
            old.shutdown()
            old.server_close()
        except Exception as e:  # noqa: BLE001
            _api_log.warning(f"关闭旧 9998 listener 失败：{e}")
        try:
            start_api_server(_api_port)
            _api_log.info("9998 已切换到服务端 CA 签发的证书")
        except Exception as e:  # noqa: BLE001
            _api_log.error(f"热切换 9998 失败：{e}")


def _tls_watcher():
    while True:
        time.sleep(10)
        try:
            reload_tls_if_updated()
        except Exception:  # noqa: BLE001
            pass


def start_api_server(port=9998):
    # 必须是多线程：单线程 + HTTP/1.1 keep-alive 时，一个长连接就会把整个服务占住，
    # 主机信息 / 应用列表这类要跑十几秒的采集会把心跳和其它接口全部堵死。
    # P1-1：socket 层包 TLS —— 正式证书（服务端 CA 签发）优先，自签兜底。
    global _api_httpd, _api_port, _api_tls_cert, _tls_watcher_started
    server, cert = _build_tls_server(int(port or 9998))
    _api_httpd = server
    _api_port = int(port or 9998)
    _api_tls_cert = cert
    # 证书热切换 watcher（每 10 秒；daemon 线程，随进程退出）。
    # 只起一次：本函数会被 watcher 反复回调来补起 listener，每次都起会漏线程。
    if not _tls_watcher_started:
        _tls_watcher_started = True
        threading.Thread(target=_tls_watcher, daemon=True).start()
    if server is None:
        # fail closed：没有 TLS 材料就不监听（见 _allow_plaintext_api）。
        # 证书领到之后由 _tls_watcher 自动补起这个 listener。
        _api_log.error(f"Agent API server 未在端口 {port} 上启动：无可用 TLS 材料")
        return None
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    _api_log.info(f"Agent API server listening on port {port} (TLS={'on' if cert else 'OFF'})")
    try:
        exe = sys.executable
        if getattr(sys, "frozen", False):
            exe = os.path.abspath(sys.executable)
        _ensure_firewall_rule(exe, int(port or 9998))
    except Exception as e:
        _api_log.warning(f"Firewall rule setup failed: {e}")
    return server
