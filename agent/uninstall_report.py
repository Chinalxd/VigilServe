"""卸载上报 —— Agent 在被卸载前向服务端通报「本机 Agent 要没了」。

为什么要单独发这一条，而不是让服务端等心跳超时：
  · 在线判定看的是 `last_seen`，它只在心跳里更新。Agent 没了之后要等
    「采集周期 × 2.5」才判离线，这段时间主机列表上它还是绿的，管理员点
    「加入管理」看到的都是假象；
  · 「卸载时是否清除本机配置」是个只有本机才知道的事实，服务端猜不出来
    —— 保留配置只是暂时离线，清了配置则设备身份（私钥 + node_id）一起
    消失，必须移出管理。这两件事的结局完全不同，只能由本机上报。

调用方：安装脚本 `installer/VigilServeAgent.iss` 的 `InitializeUninstall()`
执行 `{app}\\VigilServeAgent.exe --report-uninstall [--purge]`。

🚨 时序铁律：**必须在删除本机配置之前发出**。签名要用
`identity/node.key` 里的私钥，服务端地址要从 `agent_config.json` 里读，
两者都在配置目录里 —— 先删配置就什么都发不出去了（服务端只能干等超时）。
"""
import sys

# 卸载流程里的一次性调用，超时要短：服务端连不上也不该让卸载卡住。
_REPORT_TIMEOUT = 6.0


def _log(msg: str) -> None:
    """写日志文件（窗口程序没有 stdout，不写就完全没有痕迹）。"""
    try:
        from logger import logger as log
        log.info(f"[uninstall] {msg}")
    except Exception:  # noqa: BLE001
        pass


def report_uninstall(purge: bool = False, timeout: float = _REPORT_TIMEOUT) -> bool:
    """上报卸载。返回是否上报成功。

    失败一律**静默**：卸载不该因为服务端不可达就报错或卡住，最坏的结果
    只是主机晚几分钟才显示离线（`last_seen` 超时那套兜底还在）。
    """
    try:
        import config as _cfg
        from connector import AgentConnector

        cfg = _cfg.load() or {}
        url = (_cfg.build_server_url(cfg) or "").strip().rstrip("/")
        if not url:
            _log("本地未配置服务端地址，跳过卸载上报")
            return False

        conn = AgentConnector(
            server_url=url,
            server_id=int(cfg.get("server_id") or 0),
            token=str(cfg.get("token") or ""),
            update_key=str(cfg.get("update_key") or ""),
        )
        if not conn.node_id:
            _log("本机没有设备身份（node_id），跳过卸载上报")
            return False

        resp = conn._post("uninstall-report", {"purge_config": bool(purge)}, timeout)
        if resp.get("error"):
            # 401 也要记一句：意味着服务端没认这台设备，管理员会看到
            # 「明明卸了却还显示在线」，日志是唯一的线索。
            _log(f"卸载上报失败：code={resp.get('code')} {resp.get('message', '')[:200]}")
            return False
        _log(f"卸载上报成功（purge={purge}）")
        return True
    except Exception as e:  # noqa: BLE001  卸载上报绝不能影响卸载本身
        _log(f"卸载上报异常：{e}")
        return False


def main(argv=None) -> int:
    """命令行入口：`--report-uninstall [--purge]`。

    返回值一律 0 —— 安装程序不看它，报错也别把卸载流程带歪。
    """
    argv = list(argv if argv is not None else sys.argv[1:])
    if "--report-uninstall" not in argv:
        return 0
    report_uninstall(purge="--purge" in argv)
    return 0
