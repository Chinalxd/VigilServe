"""VigilServe Agent — headless mode only (for server deployments)."""
import time
import threading
import traceback

from config import load as load_config, save as save_config, set_auto_start as set_reg_autostart, build_server_url
from paths import CONFIG_PATH, INSTALL_DIR as APP_DIR
from logger import get_logger

from connector import AgentConnector
import tls_util

import meshagent

from remote_desktop import RemoteDesktopController

VERSION = "1.1.68"  # 开源加固 ④⑤⑥⑦：更新包签名密钥独立化、静态 token 可轮换、完整性自检、换机部署后一键信任服务端 CA


class HeadlessAgent:
    def __init__(self):
        self.cfg = load_config()
        self.connector = AgentConnector(
            build_server_url(self.cfg),
            self.cfg.get("server_id", 0),
            self.cfg.get("token", ""),
            update_key=self.cfg.get("update_key", ""),   # 开源加固 ④
        )
        self.running = False
        self.status = "未连接"
        # 服务端是否已登记本机公钥（= 已加入管理）。心跳响应里的 `authorized`
        # 回写到这里：为假时心跳照走（服务端据此显示在线），但不上报数据。
        self._authorized = True
        self._log_main = get_logger("main")
        self._log_collect = get_logger("collect")
        self._log_connector = get_logger("connector")
        self._log_api = get_logger("api")
        self._consecutive_errors = 0
        self.rdp = RemoteDesktopController(log=lambda msg: self._log(msg, "main"))

    def _log(self, msg, task="main"):
        logger = {"main": self._log_main, "collect": self._log_collect, "connector": self._log_connector, "api": self._log_api}.get(task, self._log_main)
        logger.info(msg)
        print(f"[{time.strftime('%H:%M:%S')}] [{task}] {msg}", flush=True)

    def _run_loop(self):
        self.status = "启动中..."
        self._log(f"Agent 启动, 服务端: {build_server_url(self.cfg)}", "main")
        while self.running:
            loop_start = time.time()
            try:
                self.cfg = load_config()
                server_url = build_server_url(self.cfg)
                self.connector.server_url = server_url
                self.connector.server_id = self.cfg.get("server_id", 0)
                self.connector.token = self.cfg.get("token", "")

                # 阶段 2：服务端切到 HTTPS 后自动找回（仅 http 时探测，最多每 5 分钟一次）
                try:
                    if self.connector.maybe_upgrade_to_https():
                        self.cfg = load_config()
                        server_url = build_server_url(self.cfg)
                        self.connector.server_url = server_url
                        self._log("检测到服务端已启用 HTTPS，已自动切换连接方式", "connector")
                except Exception as _e:
                    self._log(f"HTTPS 探测跳过: {_e}", "connector")

                if not server_url:
                    self.status = "未配置服务端地址"
                    self._log("未配置服务端地址，等待配置...", "connector")
                    try:
                        self.rdp.set_active(False)
                    except Exception:
                        pass
                    time.sleep(5)
                    continue

                interval = self.cfg.get("interval_seconds", 60)
                server_cfg = None
                trigger_now = False
                # ⚠ 未加入管理时跳过：`/config` 也要过签名准入，未准入会被 401。
                if self._authorized and self.connector.server_id and self.connector.token:
                    try:
                        server_cfg = self.connector.fetch_config()
                        if server_cfg and not server_cfg.get("error"):
                            interval = server_cfg.get("collect_interval", interval)
                            trigger_at = server_cfg.get("trigger_collect_at")
                            if trigger_at:
                                try:
                                    from datetime import datetime, timezone
                                    ts = datetime.fromisoformat(str(trigger_at).replace("Z", "+00:00"))
                                    age = (datetime.now(timezone.utc) - ts).total_seconds()
                                    if age < 120:
                                        trigger_now = True
                                except Exception:
                                    trigger_now = True
                    except Exception as exc:
                        self._log(f"获取配置失败: {exc}", "connector")

                if trigger_now:
                    interval = 1
                    self._log("服务端触发立即采集", "collect")

                monitored_services = server_cfg.get("monitored_services") if server_cfg else None
                whitelist = server_cfg.get("service_whitelist") if server_cfg else None
                blacklist = server_cfg.get("service_blacklist") if server_cfg else None
                pending_terminate = server_cfg.get("pending_terminate") if server_cfg else None
                debug_push_processes = bool(server_cfg.get("debug_push_processes")) if server_cfg else False

                info = None
                try:
                    self._log("开始采集主机/服务指标", "collect")
                    from collector_v2 import collect_all_v2
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
                except Exception as exc:
                    self._log(f"采集指标失败: {exc}\n{traceback.format_exc()}", "collect")
                    info = None

                try:
                    # 设备身份：必要时向服务端申请 / 续签客户端证书。
                    # 第一次报到得到「待审核 + 配对码」，管理员批准后下个周期自动拿证。
                    _ok_id, _id_msg = self.connector.ensure_certificate(info or {})
                    if _id_msg:
                        self._log(f"身份：{_id_msg}", "connector")
                    if self.connector.server_id and (
                            self.cfg.get("server_id") != self.connector.server_id
                            or self.cfg.get("token") != self.connector.token
                            or self.cfg.get("update_key") != self.connector.update_key):
                        self.cfg["server_id"] = self.connector.server_id
                        self.cfg["token"] = self.connector.token
                        self.cfg["update_key"] = self.connector.update_key   # 加固 ④
                        save_config(self.cfg)

                    if not self.connector.server_id or not self.cfg.get("token"):
                        ok, err = self.connector.register(info or {})
                        if ok:
                            self.cfg["server_id"] = self.connector.server_id
                            self.cfg["token"] = self.connector.token
                            self.cfg["update_key"] = self.connector.update_key
                            save_config(self.cfg)
                            self._log(f"注册成功 ServerID={self.connector.server_id}", "connector")
                            self._consecutive_errors = 0
                        else:
                            self._log(f"注册失败: {self.connector.server_url} 错误: {err}", "connector")
                            _ca_hint = tls_util.cert_error_hint(err)
                            if _ca_hint:
                                self._log(_ca_hint, "connector")
                            self._consecutive_errors += 1
                    else:
                        hb_ip = info.get("ip_address", "") if info else ""
                        hb_port = info.get("api_port", 9998) if info else 9998
                        hb_path = info.get("install_path", "") if info else ""
                        _hb = self.connector.heartbeat(
                            hb_ip,
                            api_port=hb_port,
                            install_path=hb_path,
                            mesh_node_id=meshagent.detect_node_id(),
                        )
                        # 加固 ④：存量 Agent 缺 update_key 时心跳会补发一次，拿到就落盘
                        # 加固 ⑤：服务端轮换过密钥时，心跳也会把新 token 带回来
                        _changed = False
                        if self.connector.update_key and \
                                self.cfg.get("update_key") != self.connector.update_key:
                            self.cfg["update_key"] = self.connector.update_key
                            _changed = True
                        if self.connector.token != self.cfg.get("token"):
                            self.cfg["token"] = self.connector.token
                            _changed = True
                        if _changed:
                            save_config(self.cfg)
                        # 🚨 判据必须是 `not _hb or "error" in _hb`，不能只写 `not _hb`：
                        # `connector.heartbeat()` 失败时返回的是**非空** dict
                        # （`{"error": True, "code": 401, ...}`），只判空的话这个分支
                        # 永远进不去 —— 无托盘模式下心跳失败既不清注册也不自愈，
                        # 界面上看不出异常、服务端却一直显示离线。（agent.py 一直是对的）
                        if not _hb or "error" in _hb:
                            # 🚨 把服务端给的拒绝原因原样露出来（理由同 agent.py）：
                            # 401 的 detail 里已经写了具体原因，不显示就只能靠猜。
                            _why = ""
                            if isinstance(_hb, dict):
                                _why = str(_hb.get("message")
                                            or _hb.get("detail") or "")[:150]
                            self._log(
                                f"心跳失败，清除本地注册信息（服务端原因：{_why or '未返回'}）",
                                "connector")
                            self.connector.server_id = 0
                            self.connector.token = ""
                            self.connector.update_key = ""
                            self.cfg["server_id"] = 0
                            self.cfg["token"] = ""
                            self.cfg["update_key"] = ""
                            save_config(self.cfg)
                            self._consecutive_errors += 1
                            continue

                        # 服务端还没登记本机公钥（= 未加入管理）：心跳通说明网络是通
                        # 的、服务端也已显示在线，但推送会被拒。跳过上报，别在日志里
                        # 每 60 秒刷一条"推送失败"。
                        # 🚨 这里**不能** `continue`：未准入是个会持续很久的正常状态，
                        #    而 `continue` 会跳过本循环底部的自适应休眠 → 满载空转。
                        _authz = _hb.get("authorized")
                        _authz = True if _authz is None else bool(_authz)
                        if _authz != self._authorized:
                            self._authorized = _authz
                            self._log(
                                "设备身份已登记，开始上报数据" if _authz else
                                "等待管理员在服务端「主机管理」中加入管理（期间只发送心跳）",
                                "connector")
                        if not _authz:
                            self.status = "待加入管理"
                            self._consecutive_errors = 0
                        elif info and self.connector.push(info):
                            self._log(f"推送成功 CPU={info['metrics']['cpu_percent']}% MEM={info['metrics']['memory_percent']}% services={len(info.get('services', []))}", "connector")
                            self._consecutive_errors = 0
                        else:
                            self._log("推送失败" if info else "推送跳过（采集失败）", "connector")
                            self._consecutive_errors += 1
                except Exception as exc:
                    self._log(f"通信失败: {exc}\n{traceback.format_exc()}", "connector")
                    _ca_hint = tls_util.cert_error_hint(exc)
                    if _ca_hint:
                        self._log(_ca_hint, "connector")
                    self._consecutive_errors += 1

            except Exception as exc:
                self._log(f"主循环异常: {exc}\n{traceback.format_exc()}", "main")
                self._consecutive_errors += 1

            sleep_interval = self.cfg.get("interval_seconds", 60)
            if self._consecutive_errors >= 10:
                sleep_interval = 300
            elif self._consecutive_errors >= 3:
                sleep_interval = min(sleep_interval * 2, 300)

            elapsed = time.time() - loop_start
            remaining = max(1, sleep_interval - int(elapsed))
            import os as _os
            _cfg_mtime = _os.path.getmtime(CONFIG_PATH) if _os.path.exists(CONFIG_PATH) else 0
            for _ in range(remaining):
                if not self.running:
                    break
                time.sleep(1)
                # ⚠ 未加入管理时跳过：`/config` 也要过签名准入，未准入会被 401，
                #   每 5 秒一次纯属白刷请求。
                if _ % 5 == 0 and self._authorized and self.connector.server_id and self.cfg.get("token"):
                    try:
                        sc = self.connector.fetch_config()
                        self.rdp.configure(build_server_url(self.cfg), self.connector.server_id,
                                           self.cfg.get("token", ""))
                        self.rdp.set_active(bool(sc.get("remote_desktop_active")))
                    except Exception:
                        pass
                try:
                    if _os.path.exists(CONFIG_PATH) and _os.path.getmtime(CONFIG_PATH) != _cfg_mtime:
                        self._log("配置文件变更，立即重新加载", "config")
                        break
                except Exception:
                    pass

    def start(self):
        if self.running:
            return
        self.running = True
        try:
            if self.cfg.get("auto_start"):
                set_reg_autostart(True)
        except:
            pass
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        try:
            from api_server import start_api_server, set_rdp_controller
            port = int(self.cfg.get("api_port") or 9998)

            def _rdp_ctl(active):
                try:
                    self.rdp.configure(build_server_url(self.cfg),
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

if __name__ == "__main__":
    agent = HeadlessAgent()
    agent.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
