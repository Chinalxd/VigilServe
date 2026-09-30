"""VigilServe Agent — system tray resident, no console, log to file."""
import os, sys, time, threading, subprocess
from datetime import datetime, timezone

VERSION = "1.1.68"  # 开源加固 ④⑤⑥⑦：更新包签名密钥独立化、静态 token 可轮换、完整性自检、换机部署后一键信任服务端 CA

from paths import INSTALL_DIR as APP_DIR, ICON_PATH, CONFIG_PATH
from config import load, save, set_auto_start, DEFAULTS, build_server_url

from logger import get_logger, logger as log

from connector import AgentConnector

import meshagent

from remote_desktop import RemoteDesktopController

import pystray
from PIL import Image, ImageDraw

from single_instance import (
    acquire_agent_mutex,
    acquire_config_mutex,
    bring_config_to_front,
    is_agent_running,
    release_agent_mutex,
    release_config_mutex,
)

def _load_ico_frame(path, size=32):
    """Load the ICO frame closest to *size* and resize if necessary."""
    img = Image.open(path)
    frames = []
    n = getattr(img, "n_frames", 1)
    for i in range(n):
        img.seek(i)
        frames.append((i, img.size[0], img.size[1]))
    exact = [f for f in frames if f[1] == size]
    if exact:
        best = exact[0]
    else:
        larger = [f for f in frames if f[1] >= size]
        if larger:
            best = min(larger, key=lambda f: f[1])
        else:
            best = max(frames, key=lambda f: f[1])
    img.seek(best[0])
    img = img.convert("RGBA")
    if img.size != (size, size):
        img = img.resize((size, size), Image.LANCZOS)
    return img


def _fallback_icon(size=32):
    """A simple blue shield used when the logo file cannot be loaded."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    m = max(1, size // 10)
    color = (0, 136, 204, 255)
    draw.pieslice([m, m, size - m, int(size * 0.75)], 0, 180, fill=color)
    draw.polygon(
        [
            (m, size // 3),
            (size // 2, size - m),
            (size - m, size // 3),
            (size - m, size // 5),
            (size // 2, m),
            (m, size // 5),
        ],
        fill=color,
    )
    return img


def _add_status_dot(img, color):
    """Draw a status dot at the bottom-right of the icon."""
    size = img.size[0]
    overlay = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    outer_r = max(2, size // 5)
    inner_r = max(1, outer_r // 2)
    cx = size - outer_r - 1
    cy = size - outer_r - 1
    draw.ellipse(
        [cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r],
        fill=color,
    )
    draw.ellipse(
        [cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r],
        fill=(255, 255, 255, 180),
    )
    return Image.alpha_composite(img, overlay)


def _status_color(status, registered):
    """Choose status dot color based on connection/registration state."""
    if status == "running":
        return (6, 214, 160) if registered else (255, 209, 102)
    if status == "error":
        return (239, 71, 111)
    if status == "connecting":
        return (255, 209, 102)
    return (108, 117, 125) if not registered else (6, 214, 160)


def create_icon(status="idle", registered=False):
    """Return the VigilServe logo as the tray icon with a registration dot.

    Uses the pre-generated status icons (green=registered+running,
    yellow=connecting/unregistered, red=error, gray=idle/unregistered).
    Falls back to drawing the dot on the base logo if a status icon is missing.
    """
    size = 32
    base_dir = os.path.dirname(ICON_PATH)

    if status == "running":
        icon_name = "tray_running.ico" if registered else "tray_connecting.ico"
    elif status == "error":
        icon_name = "tray_error.ico"
    elif status == "connecting":
        icon_name = "tray_connecting.ico"
    else:
        icon_name = "tray_running.ico" if registered else "tray_idle.ico"

    try:
        p = os.path.join(base_dir, icon_name)
        if os.path.exists(p):
            return _load_ico_frame(p, size=size)
    except Exception as e:
        log.warning(f"Failed to load status icon {icon_name}: {e}")

    try:
        if os.path.exists(ICON_PATH):
            img = _load_ico_frame(ICON_PATH, size=size)
            return _add_status_dot(img, _status_color(status, registered))
    except Exception as e:
        log.warning(f"Failed to load logo icon {ICON_PATH}: {e}")

    img = _fallback_icon(size)
    return _add_status_dot(img, _status_color(status, registered))

class TrayAgent:
    def __init__(self):
        self.cfg = load()
        self.connector = AgentConnector(
            build_server_url(self.cfg),
            self.cfg.get("server_id", 0),
            self.cfg.get("token", ""),
            update_key=self.cfg.get("update_key", ""),   
        )
        self.running = False
        self.thread = None
        self.tray_icon = None
        self.status = "未连接"
        self.config_window_open = False
        self.last_collect_time = 0.0
        # 服务端是否已登记本机公钥（= 已加入管理）。心跳响应里的 `authorized`
        # 字段回写到这里：为假时心跳照走（服务端据此显示在线），但不上报数据。
        self._authorized = True
        self._log_main = get_logger("main")
        self._log_collect = get_logger("collect")
        self._log_connector = get_logger("connector")
        self._log_api = get_logger("api")
        self._log_config = get_logger("config")
        self.rdp = RemoteDesktopController(log=lambda msg: self._log(msg, "main"))

    def _log(self, msg, task="main"):
        {
            "main": self._log_main,
            "collect": self._log_collect,
            "connector": self._log_connector,
            "api": self._log_api,
            "config": self._log_config,
        }.get(task, self._log_main).info(msg)

    def _can_update_status(self):
        return self.config_window_open is False

    def _update_tooltip(self):
        if self.tray_icon:
            try:
                self.tray_icon.title = f"VigilServe Agent\n{self.status}"
            except:
                pass

    def _run_loop(self):
        server_url = build_server_url(self.cfg)
        self._log(f"Agent 启动, 服务端: {server_url}", "main")
        self.status = "启动中..."
        self._update_tooltip()

        while self.running:
            try:
                self.cfg = load()
                server_url = build_server_url(self.cfg)
                self.connector.server_url = server_url
                self.connector.server_id = self.cfg.get("server_id", 0)
                self.connector.token = self.cfg.get("token", "")

                # 阶段 2：服务端切到 HTTPS 后自动找回（仅 http 时探测，最多每 5 分钟一次）
                try:
                    if self.connector.maybe_upgrade_to_https():
                        self.cfg = load()
                        server_url = build_server_url(self.cfg)
                        self.connector.server_url = server_url
                        self._log("检测到服务端已启用 HTTPS，已自动切换连接方式", "connector")
                except Exception as _e:
                    self._log(f"HTTPS 探测跳过: {_e}", "connector")

                if not server_url:
                    self.status = "未配置服务端地址"
                    self._log("未配置服务端地址，等待配置...", "connector")
                    self._update_tooltip()
                    self._update_icon("error")
                    time.sleep(5)
                    continue

                interval = self.cfg.get("interval_seconds", 60)
                server_cfg = None
                if self.connector.server_id and self.connector.token:
                    try:
                        server_cfg = self.connector.fetch_config()
                        if server_cfg and not server_cfg.get("error"):
                            interval = server_cfg.get("collect_interval", interval)
                            self.rdp.configure(server_url, self.connector.server_id,
                                               self.cfg.get("token", ""))
                            self.rdp.set_active(bool(server_cfg.get("remote_desktop_active")))
                    except Exception as exc:
                        self._log(f"获取配置失败: {exc}", "connector")

                monitored_services = server_cfg.get("monitored_services") if server_cfg else None
                whitelist = server_cfg.get("service_whitelist") if server_cfg else None
                blacklist = server_cfg.get("service_blacklist") if server_cfg else None
                pending_terminate = server_cfg.get("pending_terminate") if server_cfg else None
                debug_push_processes = bool(server_cfg.get("debug_push_processes")) if server_cfg else False
                from collector_v2 import collect_all_v2
                self._log("开始采集主机/服务指标", "collect")
                info = collect_all_v2(
                    monitored_services=monitored_services,
                    sample_seconds=1.0,
                    whitelist=whitelist,
                    blacklist=blacklist,
                    pending_terminate=pending_terminate,
                    debug_raw_processes=debug_push_processes,
                )
                info["business_system"] = self.cfg.get("business_system", "")
                info["agent_version"] = VERSION
                info["api_port"] = int(self.cfg.get("api_port") or 9998)
                info["install_path"] = APP_DIR
                info["mesh_node_id"] = meshagent.detect_node_id()

                # 设备身份：必要时向服务端申请 / 续签客户端证书
                # 第一次报到会拿到「待审核 + 配对码」，管理员批准后下一个周期自动拿到证书。
                _ok_id, _id_msg = self.connector.ensure_certificate(info)
                if _id_msg:
                    self._log(f"身份：{_id_msg}", "connector")
                if not _ok_id:
                    self._log("设备证书处理失败，本次按遗留方式上报", "connector")
                elif self.connector.server_id and (
                        self.cfg.get("server_id") != self.connector.server_id
                        or self.cfg.get("token") != self.connector.token
                        or self.cfg.get("update_key") != self.connector.update_key):
                    self.cfg["server_id"] = self.connector.server_id
                    self.cfg["token"] = self.connector.token
                    # 开源加固 ④：更新包验签密钥（与 token 分离）
                    self.cfg["update_key"] = self.connector.update_key
                    save(self.cfg)

                if not self.connector.server_id or not self.cfg.get("token"):
                    self.status = "注册中..."
                    self._update_tooltip()
                    self._update_icon("connecting")
                    ok, err = self.connector.register(info)
                    if ok:
                        self.cfg["server_id"] = self.connector.server_id
                        self.cfg["token"] = self.connector.token
                        # 开源加固 ④：更新包验签密钥（与 token 分离）
                        self.cfg["update_key"] = self.connector.update_key
                        save(self.cfg)
                        self.status = f"已连接 (ID:{self.connector.server_id})"
                        self._log(f"注册成功 ServerID={self.connector.server_id}", "connector")
                        self._update_tooltip()
                        self._update_icon("running")
                    else:
                        self.status = f"注册失败: {err}"
                        self._log(f"注册失败: {self.connector.server_url} 错误: {err}", "connector")
                        self._update_tooltip()
                        self._update_icon("error")
                else:
                    hb = self.connector.heartbeat(
                        info.get("ip_address", ""),
                        api_port=info.get("api_port", 9998),
                        install_path=info.get("install_path", ""),
                        mesh_node_id=meshagent.detect_node_id(),
                    )
                    # 开源加固 ④：存量 Agent 缺 update_key 时，心跳会补发一次，
                    # 拿到就落盘，否则这台机器将永远收不到新安装包。
                    # 加固 ⑤：服务端轮换过密钥时，心跳也会把新 token 带回来。
                    _changed = False
                    if self.connector.update_key and \
                            self.cfg.get("update_key") != self.connector.update_key:
                        self.cfg["update_key"] = self.connector.update_key
                        _changed = True
                    if self.connector.token != self.cfg.get("token"):
                        self.cfg["token"] = self.connector.token
                        _changed = True
                    if _changed:
                        save(self.cfg)
                    if not hb or "error" in hb:
                        # 把服务端给的拒绝原因原样露出来。以前这里只写一句
                        # "心跳失败，清除本地注册信息"，而服务端其实**已经**把原因
                        # 放在 401 的 detail 里了（未知 node_id / IP mismatch /
                        # 时间戳超差 / 证书不是本 CA 签的 …… 十几种）。看不到它，
                        # 排障就只能靠猜，phenomenon 一样、根因完全不同。
                        _why = ""
                        if isinstance(hb, dict):
                            _why = str(hb.get("message") or hb.get("detail") or "")[:150]
                        self.status = f"心跳失败{'：' + _why if _why else ''}，重新注册"
                        self._log(
                            f"心跳失败，清除本地注册信息（服务端原因：{_why or '未返回'}）",
                            "connector")
                        self.rdp.stop()
                        self._update_tooltip()
                        self._update_icon("error")
                        self.connector.server_id = 0
                        self.connector.token = ""
                        self.connector.update_key = ""
                        self.cfg["server_id"] = 0
                        self.cfg["token"] = ""
                        self.cfg["update_key"] = ""
                        save(self.cfg)
                        continue

                    # 服务端还没把本机公钥登记进库（= 未加入管理）：心跳通说明
                    # 网络是通的、服务端也已显示在线，但指标上报会被拒。
                    # 这里直接跳过上报，否则每 60 秒刷一条"推送失败"、托盘图标
                    # 一直红着，表现类似 Agent 坏了，实际是还没被批准。
                    _authz = hb.get("authorized")
                    _authz = True if _authz is None else bool(_authz)
                    if _authz != self._authorized:
                        self._authorized = _authz
                        self._log(
                            "设备身份已登记，开始上报数据" if _authz else
                            "等待管理员在服务端「主机管理」中加入管理（期间只发送心跳）",
                            "connector")
                    if not _authz:
                        self.status = "待加入管理"
                        self._update_icon("connecting")
                    elif self.connector.push(info):
                        self.status = f"运行中 (ID:{self.connector.server_id})"
                        svc_count = len(info.get('service_metrics', []))
                        self._log(f"推送成功 CPU={info['metrics']['cpu_percent']}% MEM={info['metrics']['memory_percent']}% service_metrics={svc_count}", "connector")
                        self._update_icon("running")
                    else:
                        self.status = "推送失败"
                        self._log("推送失败", "connector")
                        self._update_icon("error")
                    self._update_tooltip()

                self.last_collect_time = time.time()

                import os as _os
                _cfg_mtime = _os.path.getmtime(CONFIG_PATH) if _os.path.exists(CONFIG_PATH) else 0
                for slept in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    try:
                        if _os.path.exists(CONFIG_PATH) and _os.path.getmtime(CONFIG_PATH) != _cfg_mtime:
                            self._log("配置文件变更，立即重新加载", "config")
                            break
                    except Exception:
                        pass
                    # 未加入管理时跳过：`/config` 也要过签名准入，未准入会被 401，
                    # 每 5 秒一次纯属白刷请求。心跳已经覆盖"报活"这件事。
                    if slept % 5 == 0 and self._authorized and \
                            self.connector.server_id and self.cfg.get("token"):
                        try:
                            poll_cfg = self.connector.fetch_config()
                            if poll_cfg and not poll_cfg.get("error"):
                                # 远程桌面的开流开关必须在这里复查，不能只靠外层循环
                                # 外层间隔默认 60 秒，实测用户点开远程桌面要等约 45 秒
                                # 才有画面（看着就像"连接后卡死/黑屏"）。这里 5 秒一次，
                                # 与后端注释承诺的"约 5 秒内开流"一致。
                                # 注意只在配置有效时下发，避免一次网络抖动就把正在
                                self.rdp.configure(server_url, self.connector.server_id,
                                                   self.cfg.get("token", ""))
                                self.rdp.set_active(
                                    bool(poll_cfg.get("remote_desktop_active")))
                                trigger_at = poll_cfg.get("trigger_collect_at")
                            else:
                                trigger_at = None
                            if trigger_at:
                                from datetime import datetime, timezone
                                try:
                                    ts = datetime.fromisoformat(trigger_at.replace("Z", "+00:00"))
                                    if ts.tzinfo is None:
                                        ts = ts.replace(tzinfo=timezone.utc)
                                    if ts.timestamp() > self.last_collect_time:
                                        self._log("收到即时采集指令", "connector")
                                        break
                                except Exception:
                                    pass
                        except Exception:
                            pass
            except Exception as exc:
                self._log(f"运行循环异常: {exc}", "main")
                self.status = f"运行异常: {exc}"
                self._update_tooltip()
                self._update_icon("error")
                for _ in range(min(interval, 60)):
                    if not self.running:
                        break
                    time.sleep(1)

    def _is_registered(self):
        return bool(self.connector.server_id) and bool(self.cfg.get("token"))

    def _update_icon(self, status):
        if self.tray_icon:
            try:
                self.tray_icon.icon = create_icon(status, registered=self._is_registered())
            except:
                pass

    def start(self):
        if self.running:
            return
        self.running = True
        try:
            if self.cfg.get("auto_start"):
                set_auto_start(True)
        except:
            pass
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        try:
            from api_server import start_api_server, set_rdp_controller
            port = int(self.cfg.get("api_port") or 9998)

            def _rdp_ctl(active):
                try:
                    self.rdp.configure(self.connector.server_url,
                                       self.connector.server_id or 0,
                                       self.cfg.get("token", ""))
                    self.rdp.set_active(bool(active))
                except Exception as e:
                    self._log(f"RDP 直控回调失败: {e}", "rdp")

            set_rdp_controller(_rdp_ctl)
            start_api_server(port)
            self._log(f"Agent API server 已启动 (port {port})", "api")
        except Exception as e:
            self._log(f"Agent API server 启动失败: {e}", "api")

    def stop(self):
        self.running = False
        try:
            self.rdp.stop()
        except Exception:
            pass
        self._log("Agent 已停止", "main")

    def open_config(self):
        """Open the tkinter config dialog.

        Only one config window is allowed at a time. Repeated clicks focus
        the existing window instead of spawning new processes.
        """
        if self.config_window_open:
            log.info("Config window already open; focusing existing window")
            bring_config_to_front()
            return

        self.config_window_open = True
        try:
            if getattr(sys, 'frozen', False):
                cmd = [sys.executable, "--config"]
            else:
                cmd = [sys.executable, __file__, "--config"]
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=flags,
            )
            log.info("Config launched OK")

            def _monitor():
                try:
                    proc.wait(timeout=30)
                except Exception:
                    pass
                self.config_window_open = False
            threading.Thread(target=_monitor, daemon=True).start()
        except Exception as e:
            self.config_window_open = False
            log.error(f"Failed to open config: {e}")


def _set_window_icon(root):
    try:
        if getattr(sys, 'frozen', False):
            icon_path = os.path.join(APP_DIR, "agent_icon.ico")
        else:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_icon.ico")
        if os.path.exists(icon_path):
            root.iconbitmap(icon_path)
    except Exception:
        pass


def show_config_window():
    """Inline config window — no external module needed."""
    import tkinter as tk
    from tkinter import messagebox
    import urllib.request
    import json as json_mod

    cfg = load()
    root = tk.Tk(className="VigilServeAgentConfig")
    root.title(f"VigilServe Agent - v{VERSION}")
    root.geometry("480x560")
    root.resizable(False, False)
    root.configure(bg="#f8f9fa")
    _set_window_icon(root)

    _LBL = {"font": ("Microsoft YaHei", 10), "bg": "#f8f9fa", "anchor": "w"}
    _ENT = {"font": ("Consolas", 10), "relief": "solid", "bd": 1}

    host_var = tk.StringVar(value=(cfg.get("server_host") or "").strip())
    server_port_var = tk.StringVar(value=str(cfg.get("server_port") or DEFAULTS["server_port"]))
    api_port_var = tk.StringVar(value=str(cfg.get("api_port") or DEFAULTS["api_port"]))
    # WEB 代理端口：默认与服务端一致（8009）；默认端口冲突时两端改成同一个新端口
    _wp_port = int(cfg.get("web_proxy_port") or DEFAULTS["web_proxy_port"])
    web_port_var = tk.StringVar(value=str(_wp_port))
    auto_var = tk.BooleanVar(value=cfg.get("auto_start", True))

    # 服务端地址：协议固定 https（http 已随 HTTPS 一刀切废弃）
    frm_host = tk.Frame(root, bg="#f8f9fa")
    frm_host.pack(fill="x", padx=25, pady=(16, 4))
    tk.Label(frm_host, text="服务端地址", **_LBL).pack(fill="x")
    frm_host_row = tk.Frame(frm_host, bg="#f8f9fa")
    frm_host_row.pack(fill="x")
    tk.Label(frm_host_row, text="https://", font=("Consolas", 10), bg="#f8f9fa",
             fg="#495057").pack(side="left", padx=(0, 4))
    tk.Entry(frm_host_row, textvariable=host_var, width=30, **_ENT).pack(side="left", ipady=4)

    # 两者都是"本机监听/连接的端口号"，语义同级，拆成两行只会把面板拉长。
    frm_ports = tk.Frame(root, bg="#f8f9fa")
    frm_ports.pack(fill="x", padx=25, pady=4)

    frm_sport = tk.Frame(frm_ports, bg="#f8f9fa")
    frm_sport.pack(side="left", padx=(0, 18))
    tk.Label(frm_sport, text="服务端口", **_LBL).pack(anchor="w")
    tk.Entry(frm_sport, textvariable=server_port_var, width=10, **_ENT).pack(anchor="w", ipady=4)

    frm_port = tk.Frame(frm_ports, bg="#f8f9fa")
    frm_port.pack(side="left")
    tk.Label(frm_port, text="API 端口（文件/终端）", **_LBL).pack(anchor="w")
    tk.Entry(frm_port, textvariable=api_port_var, width=10, **_ENT).pack(anchor="w", ipady=4)

    # WEB 代理端口（2026-09-22 加）
    # 与本机 WEB 管理相关的本地监听端口，分发后由用户按现场情况指定；
    # 留空 = 未启用（不改变任何现有行为）。
    frm_wport = tk.Frame(frm_ports, bg="#f8f9fa")
    frm_wport.pack(side="left", padx=(18, 0))
    tk.Label(frm_wport, text="WEB 代理端口", **_LBL).pack(anchor="w")
    tk.Entry(frm_wport, textvariable=web_port_var, width=10, **_ENT).pack(anchor="w", ipady=4)

    # 本机配对码（人工准入：管理员要在服务端「主机管理」核对同一串码）
    frm_pair = tk.Frame(root, bg="#f8f9fa")
    frm_pair.pack(fill="x", padx=25, pady=4)
    # 标题会跟着状态变：未加入管理时写「本机配对码」，已授权时改成「设备身份状态」
    pair_title = tk.Label(frm_pair, text="本机配对码", **_LBL)
    pair_title.pack(fill="x")
    pair_label = tk.Label(
        frm_pair, text="读取中...", font=("Consolas", 13), bg="#e9ecef", fg="#495057",
        relief="solid", bd=1, anchor="center"
    )
    pair_label.pack(fill="x", ipady=6, padx=2)
    # 指路：设备尚未加入管理时，告诉操作员下一步去哪里做（不占高度，无内容时留空）
    pair_hint = tk.Label(frm_pair, text="", font=("Microsoft YaHei", 9),
                         bg="#f8f9fa", fg="#856404", anchor="w", wraplength=430,
                         justify="left")
    pair_hint.pack(fill="x", padx=2)

    frm_reg = tk.Frame(root, bg="#f8f9fa")
    frm_reg.pack(fill="x", padx=25, pady=8)
    tk.Label(frm_reg, text="注册信息", font=("Microsoft YaHei", 10), bg="#f8f9fa", anchor="w").pack(fill="x")
    sid = cfg.get("server_id", 0)
    tok = (cfg.get("token", "") or "")
    tok_show = tok[:20] + "..." if len(tok) > 20 else tok
    reg_label = tk.Label(
        frm_reg,
        text=f"Server ID: {sid}  |  Token: {tok_show if tok else '(未注册)'}",
        font=("Consolas", 9), bg="#e9ecef", fg="#495057",
        relief="solid", bd=1, anchor="w"
    )
    reg_label.pack(fill="x", ipady=4, padx=2)

    frm_status = tk.Frame(root, bg="#f8f9fa")
    frm_status.pack(fill="x", padx=25, pady=4)
    tk.Label(frm_status, text="状态", font=("Microsoft YaHei", 9),
             bg="#f8f9fa", fg="#495057").pack(anchor="w")
    status_label = tk.Label(frm_status, text="", font=("Microsoft YaHei", 9),
                            relief="solid", bd=1, bg="#fff", fg="#495057", anchor="w")
    status_label.pack(fill="x", ipady=4, pady=(2, 0))

    frm_auto = tk.Frame(root, bg="#f8f9fa")
    frm_auto.pack(fill="x", padx=25, pady=4)
    tk.Checkbutton(frm_auto, text="开机自动启动", variable=auto_var,
                   font=("Microsoft YaHei", 10), bg="#f8f9fa", activebackground="#f8f9fa").pack(anchor="w")

    def update_status(text, color="#d4edda", fg="#155724"):
        status_label.config(text=f"当前状态: {text}", bg=color, fg=fg)
        root.update_idletasks()

    def _read_ports():
        try:
            s_port = int(server_port_var.get())
        except ValueError:
            s_port = DEFAULTS["server_port"]
        try:
            a_port = int(api_port_var.get())
        except ValueError:
            a_port = DEFAULTS["api_port"]
        # WEB 代理端口：留空或非法一律回落默认值（8009），保证两端默认一致
        _wp_raw = web_port_var.get().strip()
        try:
            w_port = int(_wp_raw) if _wp_raw else DEFAULTS["web_proxy_port"]
        except ValueError:
            w_port = DEFAULTS["web_proxy_port"]
        return s_port, a_port, w_port

    # 后台线程要结果、主线程轮询刷新标签，避免跨线程直接碰 tkinter 控件。
    _pair_state = {"title": "本机配对码", "text": "读取中...", "bg": "#e9ecef", "fg": "#495057",
                   "hint": ""}
    # 设备已与服务端握手、但尚未被管理员纳管时的指路（问题 5）。
    # 只在这一态显示，别的状态一律留空，常驻的提示会被当成背景噪音忽略掉。
    _PENDING_HINT = "待加入管理：请在服务端「主机管理」中加入管理，并核对配对码。"

    def _poll_pair():
        try:
            if not root.winfo_exists():
                return
            pair_title.config(text=_pair_state["title"])
            pair_label.config(text=_pair_state["text"], bg=_pair_state["bg"],
                              fg=_pair_state["fg"])
            pair_hint.config(text=_pair_state.get("hint") or "")
        except Exception:  # noqa: BLE001 窗口已销毁
            return
        root.after(300, _poll_pair)

    def _fetch_pairing(host: str, s_port: int):
        """走一次入户接口拿本机配对码。

        管理员在服务端「注册管理」看到的那串码，必须和这里显示的一致才批准 ——
        这是人工准入里防"冒名顶替主机"的唯一凭据，所以 Agent 侧必须能看见。
        """
        try:
            host = (host or "").replace("http://", "").replace("https://", "").strip().rstrip("/")
            if not host:
                _pair_state.update(text="请填写服务端地址", bg="#f8d7da", fg="#721c24",
                                   hint="")
                return
            from collector_v2 import get_os_info
            from connector import AgentConnector
            os_info = get_os_info()
            info = {
                "hostname": os_info["hostname"],
                "ip_address": os_info["ip_address"],
                "os_type": os_info["os_type"],
                "os_version": os_info["os_version"],
                "services": [],
                "api_port": _read_ports()[1],
            }
            latest = load()
            conn = AgentConnector(f"https://{host}:{s_port}",
                                  latest.get("server_id", 0), latest.get("token", ""),
                                  update_key=latest.get("update_key", ""))
            resp = conn.enroll(info)
            # 判断顺序有讲究：**先看本机公钥有没有被登记**，再看服务端给没给
            # 配对码。只看"这次有没有回东西"的话，早就准入的设备每次都会显示
            # 配对码，管理员会以为点错了地方。
            # （1.1.51 方案 A：不再有证书，判据就是 `identity_state` / `enrolled`。）
            if resp.get("identity_state") == "authorized" or resp.get("enrolled"):
                _pair_state.update(
                    title="设备身份状态",
                    text="公钥已登记，设备已授权",
                    bg="#d4edda", fg="#155724", hint="")
            elif (resp.get("pairing_code") or "").strip():
                _pair_state.update(title="本机配对码",
                                   text=resp["pairing_code"].strip(),
                                   bg="#fff3cd", fg="#856404",
                                   hint=_PENDING_HINT)
            elif resp.get("error"):
                _pair_state.update(title="设备身份状态",
                                   text=(resp.get("message") or "获取失败")[:30],
                                   bg="#f8d7da", fg="#721c24", hint="")
            else:
                # 到这一步说明既没登记公钥、也没拿到配对码，只能靠服务端的
                # issue_error 区分：是"还没被纳管"，还是别的登记错误。
                _err = (resp.get("issue_error") or "").strip()
                if "尚未加入管理" in _err or not _err:
                    _pair_state.update(title="设备身份状态", text="待加入管理",
                                       bg="#fff3cd", fg="#856404",
                                       hint=_PENDING_HINT)
                else:
                    _pair_state.update(title="设备身份状态", text=_err[:30],
                                       bg="#e9ecef", fg="#495057", hint="")
        except Exception as e:  # noqa: BLE001
            _pair_state.update(text=f"读取失败: {str(e)[:26]}", bg="#f8d7da", fg="#721c24",
                               hint="")

    def refresh_pairing(host: str = "", s_port: int = 0):
        h = host or host_var.get().strip()
        p = s_port or _read_ports()[0]
        _pair_state.update(text="读取中...", bg="#e9ecef", fg="#495057", hint="")
        threading.Thread(target=_fetch_pairing, args=(h, p), daemon=True).start()

    def on_test():
        """Test connection AND register with server."""
        host = host_var.get().strip()
        if not host:
            update_status("请先填写服务端地址", "#f8d7da", "#721c24")
            return
        s_port, a_port, w_port = _read_ports()
        host_clean = host.replace('http://', '').replace('https://', '').rstrip('/')
        # 协议固定 https：http 已随服务端 HTTPS 一刀切废弃，不再从配置里取 server_scheme
        # （留着那个 http 默认值，就等于拿明文 HTTP 去打 HTTPS 端口 RemoteDisconnected）。
        url = f"https://{host_clean}:{s_port}"
        update_status(f"正在测试 {url}...", "#fff3cd", "#856404")

        def _persist_https():
            """把 https 写回配置，让心跳/上报立刻用对协议。

 save() 是全量写盘，必须以 load() 为底，否则会抹掉 server_id 等字段。
            """
            try:
                latest = load()
                if str(latest.get("server_scheme") or "").strip().lower() == "https":
                    return
                latest["server_scheme"] = "https"
                save(latest)
                cfg.update(latest)
            except Exception:  # noqa: BLE001
                pass

        try:
            # Step 1: ping（HTTPS 下必须带随包内置的 CA，否则自签证书必然校验失败）
            # 必须用 resolve_base_url 拿回**真正连通的那个 url**，别拿自己拼的
            # url 直接往下走，拼错协议等于拿明文 HTTP 去打 HTTPS 端口，服务端直接
            # 断开连接，界面上就显示 "Remote end closed connection without response"。
            import tls_util
            _ok, _msg, _base = tls_util.resolve_base_url(url)
            if not _ok:
                # 证书不认识是本机的事，不是网络的事，明确告诉用户下一步点哪里，
                # 否则现场只会反复重填地址（这是新部署最容易卡住的一步）。
                if tls_util.is_ca_untrusted(_msg):
                    _msg += "　→ 点「信任服务端证书」"
                update_status(_msg, "#f8d7da", "#721c24")
                return
            if _base and _base != url:
                url = _base
            _persist_https()
            sys.path.insert(0, APP_DIR)
            from collector_v2 import get_os_info
            os_info = get_os_info()
            info = {
                "hostname": os_info["hostname"],
                "ip_address": os_info["ip_address"],
                "os_type": os_info["os_type"],
                "os_version": os_info["os_version"],
                "services": [],
                "api_port": a_port,
            }
            body = json_mod.dumps(info).encode("utf-8")
            req = urllib.request.Request(
                f"{url}/api/agent/register",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # HTTPS 同样要带 CA，否则注册这一步又会栽在证书校验上
            resp = json_mod.loads(urllib.request.urlopen(
                req, timeout=10, context=tls_util.request_context(url)).read().decode())
            if resp.get("server_id"):
                latest = load()
                # 以 latest 为底：save() 全量写盘，不能把 server_scheme=https 抹掉
                new_cfg = dict(latest)
                new_cfg.update({
                    "server_host": host,
                    "server_port": s_port,
                    "server_url": "",
                    "api_port": a_port,
                    "web_proxy_port": w_port,
                    "server_id": resp["server_id"],
                    "token": resp["token"],
                    # 开源加固 ④：更新包验签密钥（与 token 分离）
                    "update_key": resp.get("update_key", ""),
                    "auto_start": auto_var.get(),
                })
                save(new_cfg)
                cfg.update(new_cfg)
                tok_show = resp["token"][:20] + "..." if len(resp["token"]) > 20 else resp["token"]
                reg_label.config(text=f"Server ID: {resp['server_id']}  |  Token: {tok_show}")
                # 区分「注册成功但还没被纳管」与「已纳管」：只说"注册成功"会让
                # 操作员以为接入已完成，实际还差服务端「加入管理」这一步。
                if resp.get("managed"):
                    update_status(f"连接正常，已加入管理 — Server ID: {resp['server_id']}",
                                  "#d4edda", "#155724")
                else:
                    update_status(f"注册成功，待加入管理 — Server ID: {resp['server_id']}",
                                  "#fff3cd", "#856404")
                # 注册完就有了身份凭据，立刻把配对码刷出来给管理员核对
                refresh_pairing(host_clean, s_port)
            else:
                update_status(f"服务端返回异常: {resp}", "#f8d7da", "#721c24")
        except Exception as e:
            update_status(f"连接失败 — {str(e)[:60]}", "#f8d7da", "#721c24")

    def on_trust_ca():
        """首次信任服务端证书（TOFU）。

        为什么需要这一步：服务端的本地 CA 是它**首次启动时自己生成的**，Agent 安装包里
        预置的那把只对打包那台机器有效。换台机器部署服务端，Agent 必然报
        「证书未被信任（缺少本地 CA）」，而这时它还没有任何凭据、走不通任何需要登录的
        接口 —— 只能由人点一下把 CA 取回来。

        取 CA 的那次请求本身不校验证书（没有信任根就没法校验，鸡生蛋），所以
        **必须**把指纹摆给操作员核对后再落盘；服务端同一串指纹在
        「系统设置 - 安全设置 - 服务端证书」里。
        """
        host = host_var.get().strip().replace('http://', '').replace('https://', '').rstrip('/')
        if not host:
            update_status("请先填写服务端地址", "#f8d7da", "#721c24")
            return
        s_port, _a_port, _w_port = _read_ports()
        base = f"https://{host}:{s_port}"
        update_status(f"正在从 {base} 获取证书...", "#fff3cd", "#856404")

        def _work():
            import tls_util
            ok, msg, data = tls_util.fetch_server_ca(base)
            if not ok:
                root.after(0, lambda: update_status(f"获取失败 — {msg}", "#f8d7da", "#721c24"))
                return
            pem = data.get("ca_pem") or ""
            fp = tls_util.fingerprint_of_pem(pem) or (data.get("fingerprint") or "")

            def _ask():
                if not messagebox.askyesno(
                        "信任服务端证书",
                        f"即将信任来自 {base} 的本地 CA 证书。\n\n"
                        f"SHA-256 指纹：\n{fp}\n\n"
                        "请与服务端「系统设置 - 安全设置 - 服务端证书」中显示的指纹核对；\n"
                        "一致方可继续，不一致则可能存在中间人，请勿信任。\n\n"
                        "确认信任并保存到本机？",
                        parent=root):
                    update_status("已取消，未做任何修改", "#e9ecef", "#495057")
                    return
                try:
                    path = tls_util.trust_ca_pem(pem)
                except Exception as e:  # noqa: BLE001
                    update_status(f"保存失败 — {str(e)[:60]}", "#f8d7da", "#721c24")
                    return
                log.info(f"Trusted server CA -> {path}")
                update_status(f"已信任服务端证书（指纹 {fp[:17]}…），正在重新测试...",
                              "#d4edda", "#155724")
                on_test()

            root.after(0, _ask)

        threading.Thread(target=_work, daemon=True).start()

    def on_save():
        host = host_var.get().strip()
        s_port, a_port, w_port = _read_ports()
        latest = load()
        # 以 latest 为底：save() 全量写盘，不能把 server_scheme=https 抹掉
        new_cfg = dict(latest)
        new_cfg.update({
            "server_host": host,
            "server_port": s_port,
            "server_url": "",
            "auto_start": auto_var.get(),
            "api_port": a_port,
            "web_proxy_port": w_port,
            "server_id": latest.get("server_id", 0),
            "token": latest.get("token", ""),
        })
        save(new_cfg)
        cfg.update(new_cfg)
        set_auto_start(auto_var.get())
        update_status("保存成功！", "#d4edda", "#155724")

    frm_btn = tk.Frame(root, bg="#f8f9fa")
    frm_btn.pack(fill="x", padx=25, pady=16)
    inner = tk.Frame(frm_btn, bg="#f8f9fa")
    inner.pack(anchor="center")
    btn_style = {
        "font": ("Microsoft YaHei", 10),
        "bg": "#e9ecef",
        "fg": "#212529",
        "activebackground": "#dee2e6",
        "activeforeground": "#212529",
        "relief": "raised",
        "bd": 2,
        "padx": 24,
        "pady": 5,
        "cursor": "hand2",
    }
    # 「信任服务端证书」：换台机器部署服务端后第一次连接的唯一出路（见 on_trust_ca）。
    # 平时不用它也无害，只在证书不认识时才真正需要点。
    tk.Button(inner, text="信任服务端证书", command=on_trust_ca, **btn_style).pack(side="left", padx=10)
    tk.Button(inner, text="测试连接", command=on_test, **btn_style).pack(side="left", padx=10)
    tk.Button(inner, text="保存配置", command=on_save, **btn_style).pack(side="left", padx=10)

    # 打开配置面板就把配对码取回来，这是管理员核对主机身份的第一步
    # 窗口高度按内容自适应：按钮下方只保留一行空白（原先固定 560 会留一大块空白）
    root.update_idletasks()
    # 宽度也要跟随内容：按钮加到三个之后，死写 480 会把最右边那个挤掉
    root.geometry(f"{max(480, root.winfo_reqwidth())}x{root.winfo_reqheight()}")

    root.after(300, _poll_pair)
    refresh_pairing()

    root.mainloop()


def _spawn_background_agent() -> bool:
    """Start the tray-resident agent in a detached process.

    为什么需要：配置面板这条进程分支（--config）本身**不跑采集循环**，它只弹窗。
    而所有开面板的入口现在都直接走 --config（安装结束、桌面快捷方式、托盘双击），
    全新安装时就再没有任何东西会把后台 Agent 拉起来 —— 用户填完服务端地址保存，
    Agent 依然是离线的。所以开面板前先看一眼后台有没有人，没有就顺手带起来。
    """
    if getattr(sys, "frozen", False):
        cmd = [sys.executable]
    else:
        cmd = [sys.executable, os.path.abspath(__file__)]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    try:
        subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=flags,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        log.error(f"Failed to start background agent: {exc}")
        return False


def main():
    # 必须放在**互斥量与托盘初始化之前**：卸载时 Agent 进程可能正在被结束，
    # 抢不到单实例锁也不该影响上报；更不能用托盘模式跑（那是常驻的）。
    # 安装脚本在删配置之前调用它，配置一删，私钥和服务端地址就没了。
    if "--report-uninstall" in sys.argv:
        try:
            from uninstall_report import report_uninstall
            report_uninstall(purge="--purge" in sys.argv)
        except Exception as exc:  # noqa: BLE001
            log.error(f"Uninstall report failed: {exc}")
        return

    is_config = "--config" in sys.argv
    if is_config:
        if not acquire_config_mutex():
            bring_config_to_front()
            return
        # 面板不跑采集逻辑：后台没人就一并拉起来，避免「配完了还是离线」。
        if not is_agent_running():
            _spawn_background_agent()
    else:
        if not acquire_agent_mutex():
            log.info("Another VigilServe Agent instance is already running; exiting.")
            return

    if is_config:
        try:
            show_config_window()
        finally:
            release_config_mutex()
        return

    agent = TrayAgent()
    agent.start()

    def on_config(icon, item):
        agent.open_config()

    def on_quit(icon, item):
        agent.stop()
        icon.stop()

    # 一个菜单里只能有一个 default。多写不会报错（Menu.__call__ 用 next() 取第一个，
    # 后面的静默失效），所以写错了没有任何提示，只会双击停在第一个上。
    menu = pystray.Menu(
        pystray.MenuItem("配置连接", on_config, default=True),
        pystray.MenuItem("退出", on_quit),
    )

    icon = pystray.Icon(
        "VigilServeAgent",
        icon=create_icon("idle", registered=False),
        title="VigilServe Agent\n启动中...",
        menu=menu,
    )
    agent.tray_icon = icon

    log.info("Tray icon started")
    try:
        icon.run()
    except Exception as exc:
        log.error(f"Agent tray loop crashed: {exc}", exc_info=True)
    finally:
        release_agent_mutex()


if __name__ == "__main__":
    main()
