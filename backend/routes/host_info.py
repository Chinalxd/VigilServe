"""主机信息 / 应用管理 / 启动项 / 事件日志 后端路由。

所有数据都由 **被监控主机上的 VigilServe Agent 采集**，后端只做：

1. 鉴权（RBAC 权限点 + 主机可见性白名单）
2. 转发到 Agent 的本地 HTTP 服务（默认 9998）
3. 写操作（卸载应用、切换启动项）落操作日志

权限点（见 services/rbac.py）：
    host/info   view                     主机信息页签
    host/apps   view                     应用管理页签
    host/apps   edit + op=uninstall      一键卸载
    host/apps   edit + op=startup        启动项启用/禁用
    host/events view                     事件日志页签
"""
from __future__ import annotations

from typing import Optional

import requests as _requests
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from database import get_db
from models import Server
from routes.auth import can_manage_server, get_current_user_full, has_perm
from services import cpu_model as cpu_util
from services.audit_logger import log_operation
from services.client_ip import get_client_ip

router = APIRouter(prefix="/api/servers", tags=["host-info"])

# 主机信息采集要跑一轮 WMI，耗时明显高于普通接口
PROXY_TIMEOUT = 120
# 卸载是同步等待型操作：Agent 侧会等着卸载程序跑完并复查注册表（单个最长 180s、
# 整批预算 600s），代理侧的读超时必须比它更宽，否则请求会在卸载完成前被掐断。
UNINSTALL_TIMEOUT = 900


class UninstallBody(BaseModel):
    ids: list[str]


class StartupToggleBody(BaseModel):
    enabled: bool


def _current_user(authorization: Optional[str], db: Session) -> dict:
    return get_current_user_full(authorization, db)


def _client_ip(request: Request) -> str:
    """ 2026-09-23 动态审计 D-1：取值规则已统一到 `services/client_ip.py`
    （默认不信任 X-Forwarded-For，只认直连 IP；确实走了反向代理时用
    `VIGILSERVE_TRUSTED_PROXIES` 显式声明代理地址）。"""
    return get_client_ip(request)


def _get_server(server_id: int, db: Session) -> Server:
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="主机不存在")
    if server.protocol != "agent":
        raise HTTPException(status_code=400, detail="仅支持通过 Agent 协议管理的主机")
    return server


def _agent_url(server: Server, endpoint: str) -> str:
    return f"https://{server.ip_address}:{server.agent_port or 9998}{endpoint}"


# 后端访问被监控主机的 Agent 是**内网直连**，必须绕开系统 HTTP 代理
# 若服务器环境配置了 HTTP_PROXY，请求会被发到代理服务器上，Agent 侧永远收不到，
_SESSION = _requests.Session()
_SESSION.trust_env = False
# P1-1：Agent 9998 全链路 TLS，用服务端本地 CA 校验 Agent 的服务器证书
try:
    from services.agent_auth import agent_ca_verify as _agent_ca_verify
    _SESSION.verify = _agent_ca_verify()
except Exception:  # noqa: BLE001
    pass

# 必须短连接：1.1.36 之前的 Agent 是**单线程** HTTPServer + keep-alive，
# 后端这边只要保持一条空闲长连接，就把那个 Agent 整个占死（ping/hello/上传全部无响应，
# 连升级包都推不进去）。显式 Connection: close 让每次请求处理完就断开。
# X-Auth-Token 由 services.agent_auth 按 server 算出（安全加固阶段 1）。
_AGENT_HEADERS = {"Connection": "close"}


def _headers_for(server: Server) -> dict:
    from services.agent_auth import agent_headers
    return agent_headers(server)


def _proxy_get(server: Server, endpoint: str, params: dict | None = None):
    try:
        return _SESSION.get(_agent_url(server, endpoint), params=params or {},
                            headers=_headers_for(server), timeout=PROXY_TIMEOUT)
    except _requests.ConnectionError:
        raise HTTPException(status_code=503, detail=f"无法连接到 Agent {server.ip_address}:{server.agent_port or 9998}")
    except _requests.Timeout:
        raise HTTPException(status_code=504, detail="Agent 响应超时")
    except _requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Agent 请求失败：{e}")


def _proxy_post(server: Server, endpoint: str, payload: dict, timeout: int | None = None):
    try:
        return _SESSION.post(_agent_url(server, endpoint), json=payload,
                             headers=_headers_for(server), timeout=timeout or PROXY_TIMEOUT)
    except _requests.ConnectionError:
        raise HTTPException(status_code=503, detail=f"无法连接到 Agent {server.ip_address}:{server.agent_port or 9998}")
    except _requests.Timeout:
        raise HTTPException(status_code=504, detail="Agent 响应超时")
    except _requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Agent 请求失败：{e}")


def _audit(db: Session, *, message: str, category: str, action: str, level: str,
           user: dict, server: Server, server_id: int, client_ip: str,
           status: str, details: dict | None = None) -> None:
    try:
        log_operation(
            db,
            message=message,
            category=category,
            action=action,
            level=level,
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=client_ip,
            status=status,
            target_type="server",
            target_id=str(server_id),
            details=details or {},
        )
    except Exception:  # noqa: BLE001 — 审计写失败不能影响主流程
        pass


def _require_view(db: Session, user: dict, server_id: int, page: str) -> None:
    # 第三轮审计 N-5（2026-09-23）：**先判登录，再判权限**。
    # 以前直接把 `get_current_user_full()` 的结果（未登录时是 None）丢给
    # `has_perm()`，于是匿名请求拿到的是 **403 无权限查看该页签**，而不是 401。
    # 权限判定本身没放水（数据一样没给），但语义错了：前端无法区分
    # "没权限"与"要重新登录"，会话过期后表现为空白列表而不是跳登录页。
    # 放在这里而不是逐个端点改，本文件所有走 `_require_view` 的接口一并生效。
    if not user:
        raise HTTPException(
            status_code=401,
            detail="未登录或会话已失效，请重新登录",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not has_perm(db, user, "host", page, "view"):
        raise HTTPException(status_code=403, detail="无权限查看该页签")
    if not can_manage_server(db, user, server_id):
        raise HTTPException(status_code=403, detail="该主机不在当前角色的管理范围内")


def _sync_cpu_model(db: Session, server: Server, data: dict) -> None:
    """顺手把 Agent 采到的真实 CPU 型号回写到 server.extra_config。

    心跳里的 cpu_model 来自轻量采集（老版本 Agent 在 Windows 上只会给出
    "Intel64 Family 6 Model 165 Stepping 3, GenuineIntel" 这种 CPUID 代号），
    而主机信息页的 WMI 结果是完整品牌型号。用户看过一次主机信息后，
    主机监控页的「型号」也就跟着正确了 —— 不需要额外请求，也不需要等 Agent 升级。
    """
    try:
        model = cpu_util.clean((data.get("cpu") or {}).get("model"))
        if not model or cpu_util.is_cpuid_code(model):
            return
        cfg = dict(server.extra_config or {})
        if cfg.get("cpu_model") == model:
            return
        cfg["cpu_model"] = model
        server.extra_config = cfg
        flag_modified(server, "extra_config")
        db.commit()
    except Exception:  # noqa: BLE001 回写失败不影响主机信息展示
        db.rollback()


# kind 权限页签（刷新接口要按采集项校验对应页签的权限，不能只看一个）
_KIND_PAGE = {
    "system-info": "info",
    "applications": "apps",
    "app-updates": "apps",
}


def _serve_cached(db: Session, server: Server, kind: str, sync_cpu: bool = False):
    """缓存优先；没有新鲜缓存才同步采一次。

    返回体里塞两个下划线开头的字段告诉前端"这份数据是几分钟前采的"，
    下划线是刻意的 —— 前端现有的 `d.items || []` 之类的取法不受影响。
    """
    from services import host_info_async as hia

    data = hia.cache_get(server.id, kind)
    if data is not None:
        entry = hia.cache_entry(server.id, kind) or {}
        out = dict(data) if isinstance(data, dict) else data
        if isinstance(out, dict):
            out["_cached"] = True
            out["_cached_at"] = entry.get("at", "")
        return out

    ok, payload, err = hia.collect_sync(server.id, kind)
    if not ok:
        raise HTTPException(status_code=502, detail=err or "采集失败")
    if sync_cpu and isinstance(payload, dict):
        _sync_cpu_model(db, server, payload)
    out = dict(payload) if isinstance(payload, dict) else payload
    if isinstance(out, dict):
        out["_cached"] = False
        out["_cached_at"] = ""
    return out


@router.get("/{server_id}/system-info")
def get_system_info(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    user = _current_user(authorization, db)
    _require_view(db, user, server_id, "info")
    server = _get_server(server_id, db)
    return _serve_cached(db, server, "system-info", sync_cpu=True)


@router.get("/{server_id}/applications")
def get_applications(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    user = _current_user(authorization, db)
    _require_view(db, user, server_id, "apps")
    server = _get_server(server_id, db)
    return _serve_cached(db, server, "applications")


@router.get("/{server_id}/applications/updates")
def get_application_updates(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    user = _current_user(authorization, db)
    _require_view(db, user, server_id, "apps")
    server = _get_server(server_id, db)
    return _serve_cached(db, server, "app-updates")


@router.post("/{server_id}/host-info/refresh")
def refresh_host_info(
    server_id: int,
    kind: str = Query("system-info", description="system-info / applications / app-updates"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """触发一次异步采集，HTTP 请求**不等采集结果**。

    前端拿返回的 task_id 去轮询 `/{server_id}/host-info/task/{task_id}`，
    状态变成 done 后再重新拉一次列表。这样点刷新不会把页面卡死在
    "正在采集…"上（应用列表走一轮 WMI 能到几十秒）。
    """
    from services import host_info_async as hia

    page = _KIND_PAGE.get(kind)
    if not page:
        raise HTTPException(status_code=400, detail=f"不支持的采集项：{kind}")
    user = _current_user(authorization, db)
    _require_view(db, user, server_id, page)
    server = _get_server(server_id, db)   # 顺带校验 protocol == agent
    return {
        "task_id": hia.submit(server.id, kind),
        "status": "pending",
        "server_id": server.id,
        "kind": kind,
    }


@router.get("/{server_id}/host-info/task/{task_id}")
def get_host_info_task(
    server_id: int,
    task_id: str,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """查异步采集任务状态：pending / running / done / error。"""
    from services import host_info_async as hia

    user = _current_user(authorization, db)
    t = hia.get_task(task_id)
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在或已过期")
    # 防越权：任务必须属于这台主机，且用户得能看对应页签
    if int(t.get("server_id") or -1) != int(server_id):
        raise HTTPException(status_code=404, detail="任务不存在或已过期")
    _require_view(db, user, server_id, _KIND_PAGE.get(t.get("kind", ""), "info"))
    return t


@router.post("/{server_id}/applications/uninstall")
def uninstall_applications(
    server_id: int,
    body: UninstallBody,
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    user = _current_user(authorization, db)
    if not has_perm(db, user, "host", "apps", "edit", "uninstall"):
        raise HTTPException(status_code=403, detail="无权限卸载应用")
    if not can_manage_server(db, user, server_id):
        raise HTTPException(status_code=403, detail="该主机不在当前角色的管理范围内")
    server = _get_server(server_id, db)
    ids = [i for i in (body.ids or []) if i]
    if not ids:
        raise HTTPException(status_code=400, detail="请先选择要卸载的应用")
    client_ip = _client_ip(request)

    resp = _proxy_post(server, "/applications/uninstall", {"ids": ids},
                       timeout=UNINSTALL_TIMEOUT)
    ok = resp.ok
    payload = {}
    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001
        payload = {}

    results = payload.get("results") or []
    names = ", ".join(str(r.get("message", r.get("id"))) for r in results[:5])
    # resp.ok 只代表「代理链路通不通」；每个应用是否真的卸载成功看 results 里的 ok。
    failed = [r for r in results if not r.get("ok")]
    all_ok = ok and not failed
    _audit(
        db,
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 卸载应用（{len(ids)} 个，"
                f"成功 {len(results) - len(failed)} / 失败 {len(failed)}）",
        category="host_app",
        action="uninstall_app",
        level="info" if all_ok else "error",
        user=user,
        server=server,
        server_id=server_id,
        client_ip=client_ip,
        status="success" if all_ok else "failed",
        details={
            "server_name": server.name,
            "agent_ip": server.ip_address,
            "ids": ids,
            "results": results,
            "summary": names,
            "failed": [r.get("id") for r in failed],
            "response_status": resp.status_code,
        },
    )
    if not ok:
        raise HTTPException(status_code=502, detail=payload.get("detail") or f"Agent 返回错误：{resp.status_code}")
    # 卸完之后应用列表已经变了，缓存必须失效，否则用户刷新页面看到的还是
    # "明明卸掉了却还在列表里"的旧数据（缓存 TTL 有 5 分钟）。
    try:
        from services import host_info_async as hia
        hia.cache_invalidate(server.id)
    except Exception:  # noqa: BLE001 缓存失效失败不能让卸载结果丢失
        pass
    return payload


@router.get("/{server_id}/startup")
def get_startup_items(
    server_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    user = _current_user(authorization, db)
    _require_view(db, user, server_id, "apps")
    server = _get_server(server_id, db)
    resp = _proxy_get(server, "/startup")
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"Agent 返回错误：{resp.status_code}")
    return resp.json()


@router.post("/{server_id}/startup/{item_id}/toggle")
def toggle_startup_item(
    server_id: int,
    item_id: str,
    body: StartupToggleBody,
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    user = _current_user(authorization, db)
    if not has_perm(db, user, "host", "apps", "edit", "startup"):
        raise HTTPException(status_code=403, detail="无权限修改启动项")
    if not can_manage_server(db, user, server_id):
        raise HTTPException(status_code=403, detail="该主机不在当前角色的管理范围内")
    server = _get_server(server_id, db)
    client_ip = _client_ip(request)

    resp = _proxy_post(server, f"/startup/{item_id}/toggle", {"enabled": bool(body.enabled)})
    ok = resp.ok
    payload = {}
    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001
        payload = {}

    label = "启用" if body.enabled else "禁用"
    _audit(
        db,
        message=f"用户 {user.get('username', '未知')} {label}主机 {server.name} 的启动项",
        category="host_startup",
        action="startup_toggle",
        level="info" if ok else "error",
        user=user,
        server=server,
        server_id=server_id,
        client_ip=client_ip,
        status="success" if ok else "failed",
        details={
            "server_name": server.name,
            "agent_ip": server.ip_address,
            "item_id": item_id,
            "enabled": bool(body.enabled),
            "response_status": resp.status_code,
            "detail": payload.get("detail"),
        },
    )
    if not ok:
        raise HTTPException(status_code=502, detail=payload.get("detail") or f"Agent 返回错误：{resp.status_code}")
    return payload


@router.get("/{server_id}/event-logs")
def get_event_logs(
    server_id: int,
    level: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    start: Optional[str] = Query(None, description="起始时间 YYYY-MM-DD HH:MM:SS（留空=默认近 3 天）"),
    end: Optional[str] = Query(None, description="结束时间 YYYY-MM-DD HH:MM:SS（留空=到现在）"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    user = _current_user(authorization, db)
    _require_view(db, user, server_id, "events")
    server = _get_server(server_id, db)
    resp = _proxy_get(server, "/event-logs", {
        "level": level or "",
        "limit": limit,
        # 旧版 Agent 不认这两个参数，多传无害（它只取自己认识的 key）
        "start": (start or "").strip(),
        "end": (end or "").strip(),
    })
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"Agent 返回错误：{resp.status_code}")
    return resp.json()
