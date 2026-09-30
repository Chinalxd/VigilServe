"""方案 B：统一的「采集周期」与「在线判定」。

为什么要单独拎出来
──────────────────
改造之前在线判定是散在各处硬编码的：

* ``services/collector.py``：Agent 主机 180 秒没心跳 = 离线
* 前端 ``RegisterManagement.jsx``：5 分钟没心跳 = 离线

两套阈值对不上，同一台机器在调度器眼里已经离线、在页面上还显示在线。
网络设备上线后更明显 —— SNMP 5 分钟才采一次，用 3 分钟阈值判它**永远离线**。

所以统一成一条规则：

    距上次数据（last_seen）超过「采集周期 × 2.5」= 离线

×2.5 是给网络抖动留的重试余量（差一步半到两轮），一次丢包不会立刻翻成离线，
但连续两轮不通就如实报离线 —— 不会像 ×5 那样「明明断了还显示在线很久」。

周期取值优先级
──────────────
1. ``Server.collect_interval_sec``（单台覆盖，0 = 不覆盖）
2. 全局配置：
   * Agent 主机    → ``agent_collect_interval``（Agent 推送间隔，默认 60s）
   * 非 Agent 主机 → ``collect_interval``（服务端主动采集间隔，默认 60s）
   * 网络设备      → ``snmp_collect_interval``（默认 300s）
3. 兜底常量（配置读不出来时）
"""
from __future__ import annotations

from datetime import datetime, timezone

ONLINE_FACTOR = 2.5

FALLBACK_PERIOD = {
    "agent": 60,
    "host": 60,
    "network": 300,
}

CONFIG_KEY = {
    "agent": "agent_collect_interval",
    "host": "collect_interval",
    "network": "snmp_collect_interval",
}


def _int(value, default: int) -> int:
    try:
        v = int(str(value).strip())
        return v if v > 0 else default
    except Exception:  # noqa: BLE001
        return default


def device_kind_of(server) -> str:
    """``host`` / ``network``。老数据没这个字段时按 protocol 推断。"""
    kind = str(getattr(server, "device_kind", "") or "").strip().lower()
    if kind in ("host", "network"):
        return kind
    # 兜底：SNMP 协议的一定是网络设备（协议本身就是新增设备时写的）
    if str(getattr(server, "protocol", "") or "").lower() == "snmp":
        return "network"
    return "host"


def _bucket(server) -> str:
    """决定用哪个全局配置项：agent / host / network。"""
    if device_kind_of(server) == "network":
        return "network"
    if str(getattr(server, "protocol", "") or "").lower() == "agent":
        return "agent"
    return "host"


def load_config(db=None) -> dict:
    """读全局配置字典。读失败返回空 dict —— 后面会用兜底常量，不能让列表挂掉。"""
    try:
        from routes.config import get_config_dict

        if db is None:
            from database import SessionLocal

            own = SessionLocal()
            try:
                return get_config_dict(own) or {}
            finally:
                own.close()
        return get_config_dict(db) or {}
    except Exception:  # noqa: BLE001
        return {}


def collect_period(server, cfg: dict = None) -> int:
    """这台设备的采集周期（秒）。"""
    override = _int(getattr(server, "collect_interval_sec", 0), 0)
    if override > 0:
        return override
    bucket = _bucket(server)
    cfg = cfg if isinstance(cfg, dict) else {}
    node = cfg.get(CONFIG_KEY[bucket]) or {}
    if isinstance(node, dict):
        return _int(node.get("value"), FALLBACK_PERIOD[bucket])
    return _int(node, FALLBACK_PERIOD[bucket])


def offline_after(server, cfg: dict = None) -> float:
    """超过多少秒没数据算离线。"""
    return collect_period(server, cfg) * ONLINE_FACTOR


def is_online(server, cfg: dict = None, now: datetime = None) -> bool:
    """统一在线判定。没有 last_seen（从来没通过）一律离线。"""
    last_seen = getattr(server, "last_seen", None)
    if not last_seen:
        return False
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return (now - last_seen).total_seconds() <= offline_after(server, cfg)
