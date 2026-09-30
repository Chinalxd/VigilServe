"""主机信息「按需采集（Pull 模式）」—— TTL 缓存 + 真异步采集队列。

采集的三层模型（2026-09-20 与用户定稿）：

1. **定时采集（Agent / Push）—— 主力**：Agent 按固定间隔（30s / 60s）主动推
   CPU / 内存 / 磁盘 / 进程等到服务端，写库。这一层本来就存在，本模块不碰。

2. **按需采集（Pull）—— 辅助**：系统信息、应用列表这种**几分钟都不变**的数据，
   不该每次开页面都去跑一轮 WMI（一次要好几秒，应用列表能到几十秒）。
   做法是：结果进 TTL 缓存（默认 300s），页面直接读缓存；
   用户点「刷新」时不让 HTTP 请求干等 —— 丢进线程池异步采，前端拿 `task_id`
   轮询，采完再拉结果。

3. **事件驱动（Trap / Webhook）—— 实时**：见 `routes/traps.py`。

🚨 两个容易踩的坑：
   · 采集跑在工作线程里，**必须自己开 DB session**（请求线程的 session 不是
     线程安全的，而且请求早就返回了，session 可能已关闭）。
   · 同一个 (server_id, kind) 已经有任务在跑就**直接复用那个 task_id**，
     不要重复打 Agent —— 1.1.36 之前的 Agent 是单线程 HTTPServer，
     并发一上来就把整台机器的 Agent 占死（ping / 升级包全堵住）。
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests as _requests

logger = logging.getLogger(__name__)

KIND_ENDPOINTS = {
    "system-info": "/system-info",
    "applications": "/applications",
    "app-updates": "/applications/updates",
}

# 缓存有效期：应用列表 / 系统信息几分钟内不会变，5 分钟够了
CACHE_TTL_SEC = 300
# 缓存条目多久没人访问就不再后台续采（防止给几百台离线机器白跑）
HOT_WINDOW_SEC = 900
_REFRESH_TICK_SEC = 60
_TASK_TTL_SEC = 600
_COLLECT_TIMEOUT = 120

_lock = threading.RLock()

_cache: dict[tuple[int, str], dict] = {}

_tasks: dict[str, dict] = {}
_inflight: dict[tuple[int, str], str] = {}

_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="hostinfo")

# 访问 Agent 是内网直连，必须绕开系统代理（HTTP_PROXY 会把请求劫走 → 502）
_SESSION = _requests.Session()
_SESSION.trust_env = False
# P1-1：Agent 9998 全链路 TLS —— 用服务端本地 CA 校验 Agent 的服务器证书
try:
    from services.agent_auth import agent_ca_verify as _agent_ca_verify
    _SESSION.verify = _agent_ca_verify()
except Exception:  # noqa: BLE001
    pass


def _now() -> float:
    return time.time()


def kind_endpoint(kind: str) -> str | None:
    return KIND_ENDPOINTS.get(kind)


def cache_get(server_id: int, kind: str):
    """返回**新鲜**的缓存（未过期且有数据），否则 None。"""
    with _lock:
        e = _cache.get((int(server_id), kind))
        if not e or not e.get("ok") or e.get("data") is None:
            return None
        if _now() - e["ts"] > CACHE_TTL_SEC:
            return None
        e["last_access"] = _now()
        return e["data"]


def cache_entry(server_id: int, kind: str):
    """返回缓存条目（含是否过期 / 采集时间），没有就 None。

    缓存过期但仍有一份旧数据时，前端可以先渲染旧数据 + 打上"更新中"，
    比白屏等一轮 WMI 体验好得多。
    """
    with _lock:
        e = _cache.get((int(server_id), kind))
        if not e:
            return None
        e["last_access"] = _now()
        return dict(e)


def cache_put(server_id: int, kind: str, data, ok: bool = True, error: str = "") -> None:
    with _lock:
        _cache[(int(server_id), kind)] = {
            "data": data,
            "ts": _now(),
            "at": datetime.now(timezone.utc).isoformat(),
            "ok": ok,
            "error": error or "",
            "last_access": _now(),
        }


def cache_invalidate(server_id: int, kind: str | None = None) -> None:
    """整台主机的缓存失效（kind=None 表示全部）。

    写操作之后必须调：卸载应用 / 改启动项之后，应用列表和启动项都是脏的，
    继续喂缓存会给用户看一张"明明卸了还在列表里"的表。
    """
    with _lock:
        if kind:
            _cache.pop((int(server_id), kind), None)
        else:
            for k in list(_cache.keys()):
                if k[0] == int(server_id):
                    _cache.pop(k, None)


def _collect_from_agent(server_id: int, kind: str) -> tuple[bool, object, str]:
    """真正去 Agent 上拉一次。返回结果 (ok, data, error)。

    跑在工作线程里：自己开 session 拿 Server，自己发 HTTP。
    """
    endpoint = kind_endpoint(kind)
    if not endpoint:
        return False, None, f"未知的采集项：{kind}"

    from database import SessionLocal
    from models import Server
    from services.agent_auth import agent_headers

    db = SessionLocal()
    try:
        server = db.query(Server).filter(Server.id == int(server_id)).first()
        if not server:
            return False, None, "主机不存在"
        if (server.protocol or "") != "agent":
            return False, None, "仅支持通过 Agent 协议管理的主机"
        url = f"https://{server.ip_address}:{server.agent_port or 9998}{endpoint}"
        try:
            resp = _SESSION.get(url, headers=agent_headers(server), timeout=_COLLECT_TIMEOUT)
        except _requests.ConnectionError:
            return False, None, f"无法连接到 Agent {server.ip_address}:{server.agent_port or 9998}"
        except _requests.Timeout:
            return False, None, "Agent 响应超时"
        except _requests.RequestException as e:
            return False, None, f"Agent 请求失败：{e}"

        if not resp.ok:
            return False, None, f"Agent 返回错误：{resp.status_code}"
        try:
            return True, resp.json(), ""
        except Exception as e:  # noqa: BLE001
            return False, None, f"Agent 返回内容无法解析：{e}"
    finally:
        db.close()


def collect_sync(server_id: int, kind: str) -> tuple[bool, object, str]:
    """同步采一次（首次打开页面、缓存还没有任何数据时用）。

    只在**没有旧数据可显示**时走这条路：HTTP 请求会一直等到 Agent 采完
    （应用列表能到几十秒），但总比开页面看到一片空白好。
    """
    ok, data, err = _collect_from_agent(server_id, kind)
    if ok:
        cache_put(server_id, kind, data, ok=True)
    return ok, data, err


def _run_task(task_id: str, server_id: int, kind: str) -> None:
    with _lock:
        t = _tasks.get(task_id)
        if t:
            t["status"] = "running"
            t["started_at"] = datetime.now(timezone.utc).isoformat()
    try:
        ok, data, err = _collect_from_agent(server_id, kind)
    except Exception as e:  # noqa: BLE001  兜住，别让工作线程把任务永久卡在 running
        logger.exception("主机信息异步采集异常 server=%s kind=%s", server_id, kind)
        ok, data, err = False, None, f"{type(e).__name__}: {e}"

    if ok:
        cache_put(server_id, kind, data, ok=True)
    with _lock:
        t = _tasks.get(task_id)
        if t:
            t["status"] = "done" if ok else "error"
            t["error"] = "" if ok else err
            t["finished_at"] = datetime.now(timezone.utc).isoformat()
        _inflight.pop((int(server_id), kind), None)


def _gc_tasks() -> None:
    """清掉过期任务记录（任务字典会一直涨，不然是个内存泄漏）。"""
    cutoff = _now() - _TASK_TTL_SEC
    with _lock:
        for tid in list(_tasks.keys()):
            t = _tasks[tid]
            fin = t.get("finished_at") or t.get("submitted_at") or ""
            try:
                ts = datetime.fromisoformat(fin).timestamp()
            except Exception:  # noqa: BLE001
                ts = 0
            if t.get("status") in ("pending", "running"):
                continue
            if ts and ts < cutoff:
                _tasks.pop(tid, None)


def submit(server_id: int, kind: str) -> str:
    """提交一次异步采集，立刻返回 task_id（不阻塞 HTTP 请求）。

    同一 (server_id, kind) 已有在途任务时复用它的 task_id —— 见文件头
    「1.1.36 之前 Agent 是单线程」那条。
    """
    key = (int(server_id), kind)
    _gc_tasks()
    with _lock:
        existing = _inflight.get(key)
        if existing and existing in _tasks:
            st = _tasks[existing].get("status")
            if st in ("pending", "running"):
                return existing
        task_id = uuid.uuid4().hex[:16]
        _tasks[task_id] = {
            "task_id": task_id,
            "server_id": int(server_id),
            "kind": kind,
            "status": "pending",
            "error": "",
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "started_at": None,
            "finished_at": None,
        }
        _inflight[key] = task_id
    _pool.submit(_run_task, task_id, int(server_id), kind)
    return task_id


def get_task(task_id: str):
    with _lock:
        t = _tasks.get(task_id)
        return dict(t) if t else None


def _sweep_once() -> None:
    """把过期但最近还有人访问的缓存条目排进采集队列。

    只在有人看的时候续采：不给几百台没人打开的机器白跑 WMI。
    """
    now = _now()
    targets = []
    with _lock:
        for (sid, kind), e in _cache.items():
            if now - e.get("last_access", 0) > HOT_WINDOW_SEC:
                continue
            if now - e.get("ts", 0) <= CACHE_TTL_SEC:
                continue
            if (sid, kind) in _inflight:
                continue
            targets.append((sid, kind))
    for sid, kind in targets:
        submit(sid, kind)


def _sweep_loop() -> None:
    while True:
        try:
            _sweep_once()
            _gc_tasks()
        except Exception:  # noqa: BLE001  巡检线程绝不能死
            logger.exception("主机信息缓存巡检异常")
        time.sleep(_REFRESH_TICK_SEC)


_started = False


def start() -> None:
    """启动后台巡检线程（main.py 启动时调一次，重复调用安全）。"""
    global _started
    with _lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_sweep_loop, name="hostinfo-sweeper", daemon=True).start()
    logger.info("主机信息按需采集：后台巡检线程已启动（TTL=%ss）", CACHE_TTL_SEC)
