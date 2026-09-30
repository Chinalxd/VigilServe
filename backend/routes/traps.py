"""事件驱动（Trap / Webhook）接收器。

定时采集和按需采集都有延迟 —— 进程崩溃、服务停止、端口 DOWN 这类**状态突变**
等不到下一轮心跳，必须由 Agent / 设备检测到后立刻主动 POST 上来。

接口：
    POST /api/traps/ingest            上报（Agent 签名 / 遗留 HMAC 鉴权）
    GET  /api/traps                   列表（按主机可见范围过滤）
    GET  /api/servers/{id}/traps      某台主机的实时事件
    POST /api/traps/{id}/ack          确认 / 消除

🚨 鉴权复用 `routes/agent.py::_authenticate()`：Agent 上行请求本来就带签名
（客户端证书）或遗留 HMAC，没必要再发明一套口令。拿到了 Server 就用它，
拿不到一律 401 —— **绝不接受请求体里自称的 server_id**，否则任何人都能
往别人的主机上灌事件。
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import Server, TrapEvent
from routes.auth import can_manage_server, get_current_user_full, has_perm
from services.audit_logger import log_operation
from services.client_ip import get_client_ip

logger = logging.getLogger("backend")

router = APIRouter(prefix="/api", tags=["traps"])

# 单次上报最多收多少条：防止 Agent 出 bug 时把服务端写爆
MAX_EVENTS_PER_REQUEST = 50
MAX_MESSAGE_LEN = 2000

_ALLOWED_LEVELS = ("info", "warning", "critical")


class TrapItem(BaseModel):
    event_type: str = "custom"
    level: str = "warning"
    message: str = ""
    payload: dict | None = None
    occurred_at: str | None = None


class TrapIngestBody(BaseModel):
    # 兼容两种写法：直接给一条事件，或给 events 数组
    events: list[TrapItem] | None = None
    event_type: str | None = None
    level: str | None = None
    message: str | None = None
    payload: dict | None = None
    occurred_at: str | None = None


def _parse_occurred(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    try:
        d = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001  时间解析失败不影响事件入库
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def _norm_level(v: Optional[str]) -> str:
    s = str(v or "").strip().lower()
    return s if s in _ALLOWED_LEVELS else "warning"


def _client_ip(request: Request) -> str:
    """⚠ 2026-09-23 动态审计 D-1：取值规则已统一到 `services/client_ip.py`
    （默认不信任 X-Forwarded-For，只认直连 IP；确实走了反向代理时用
    `VIGILSERVE_TRUSTED_PROXIES` 显式声明代理地址）。"""
    return get_client_ip(request)


@router.post("/traps/ingest")
def ingest_traps(
    body: TrapIngestBody,
    request: Request,
    db: Session = Depends(get_db),
):
    """接收 Agent / 设备主动上报的实时事件。"""
    # 复用 Agent 上行鉴权：拿不到 Server 就 401，不认请求体里的 server_id
    try:
        from routes.agent import _authenticate
    except Exception as e:  # noqa: BLE001
        logger.error(f"traps: 无法加载 Agent 鉴权模块：{e}")
        raise HTTPException(status_code=500, detail="鉴权模块不可用")
    server, how = _authenticate(request, db)
    if not server:
        raise HTTPException(status_code=401, detail=f"上报鉴权失败：{how}")

    items = list(body.events or [])
    if body.event_type or body.message:
        items.insert(0, TrapItem(
            event_type=body.event_type or "custom",
            level=body.level or "warning",
            message=body.message or "",
            payload=body.payload,
            occurred_at=body.occurred_at,
        ))
    if not items:
        raise HTTPException(status_code=400, detail="没有要上报的事件")
    if len(items) > MAX_EVENTS_PER_REQUEST:
        items = items[:MAX_EVENTS_PER_REQUEST]

    saved = []
    for it in items:
        ev = TrapEvent(
            server_id=server.id,
            source="agent",
            event_type=(it.event_type or "custom")[:50],
            level=_norm_level(it.level),
            message=(it.message or "")[:MAX_MESSAGE_LEN],
            payload=it.payload or {},
            occurred_at=_parse_occurred(it.occurred_at),
            received_at=datetime.now(timezone.utc),
            acknowledged=0,
        )
        db.add(ev)
        saved.append(ev)
    db.commit()

    critical = [e for e in saved if e.level == "critical"]
    logger.info(
        f"traps: 主机 {server.name}(id={server.id}) 上报 {len(saved)} 条事件"
        f"（critical {len(critical)}），鉴权方式 {how}"
    )

    # 关键事件落一条审计，管理员在「日志管理」里能直接看到，不用专门来翻这张表
    for e in critical:
        try:
            log_operation(
                db,
                message=f"主机 {server.name} 上报紧急事件：{e.message[:160]}",
                category="device_trap",
                action="trap_critical",
                level="error",
                username="agent",
                user_id=None,
                ip_address=_client_ip(request),
                status="success",
                target_type="server",
                target_id=str(server.id),
                details={"event_type": e.event_type, "level": e.level, "trap_id": e.id},
            )
        except Exception:  # noqa: BLE001  审计写失败不能让上报失败
            db.rollback()

    return {"ok": True, "received": len(saved), "ids": [e.id for e in saved]}


def _require_events_view(db: Session, user: dict, server_id: int | None) -> None:
    if not has_perm(db, user, "host", "events", "view"):
        raise HTTPException(status_code=403, detail="无权限查看事件")
    if server_id and not can_manage_server(db, user, server_id):
        raise HTTPException(status_code=403, detail="该主机不在当前角色的管理范围内")


def _dump(e: TrapEvent) -> dict:
    return {
        "id": e.id,
        "server_id": e.server_id,
        "server_name": getattr(e.server, "name", "") or "",
        "source": e.source,
        "event_type": e.event_type,
        "level": e.level,
        "message": e.message,
        "payload": e.payload or {},
        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
        "received_at": e.received_at.isoformat() if e.received_at else None,
        "acknowledged": bool(e.acknowledged),
        "acknowledged_by": e.acknowledged_by or "",
        "acknowledged_at": e.acknowledged_at.isoformat() if e.acknowledged_at else None,
    }


@router.get("/traps")
def list_traps(
    server_id: Optional[int] = None,
    level: Optional[str] = None,
    unacked: int = 0,
    limit: int = 100,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    user = get_current_user_full(authorization, db)
    _require_events_view(db, user, server_id)

    q = db.query(TrapEvent)
    if server_id:
        q = q.filter(TrapEvent.server_id == server_id)
    if level:
        q = q.filter(TrapEvent.level == level)
    if unacked:
        q = q.filter(TrapEvent.acknowledged == 0)
    rows = q.order_by(TrapEvent.received_at.desc()).limit(max(1, min(int(limit), 500))).all()

    # 没指定主机时，还要按角色可见范围再过滤一遍（不能让人看见范围外的主机）
    out = []
    for e in rows:
        if server_id is None and not can_manage_server(db, user, e.server_id):
            continue
        out.append(_dump(e))
    return out


@router.get("/servers/{server_id}/traps")
def list_server_traps(
    server_id: int,
    unacked: int = 0,
    limit: int = 100,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    if not db.query(Server).filter(Server.id == server_id).first():
        raise HTTPException(status_code=404, detail="主机不存在")
    user = get_current_user_full(authorization, db)
    _require_events_view(db, user, server_id)

    q = db.query(TrapEvent).filter(TrapEvent.server_id == server_id)
    if unacked:
        q = q.filter(TrapEvent.acknowledged == 0)
    rows = q.order_by(TrapEvent.received_at.desc()).limit(max(1, min(int(limit), 500))).all()
    return [_dump(e) for e in rows]


@router.post("/traps/{trap_id}/ack")
def ack_trap(
    trap_id: int,
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    ev = db.query(TrapEvent).filter(TrapEvent.id == trap_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="事件不存在")
    user = get_current_user_full(authorization, db)
    _require_events_view(db, user, ev.server_id)

    ev.acknowledged = 1
    ev.acknowledged_by = user.get("username", "") or ""
    ev.acknowledged_at = datetime.now(timezone.utc)
    db.commit()

    try:
        log_operation(
            db,
            message=f"用户 {user.get('username', '未知')} 确认事件 #{trap_id}（{ev.event_type}）",
            category="device_trap",
            action="trap_ack",
            level="info",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=_client_ip(request),
            status="success",
            target_type="server",
            target_id=str(ev.server_id),
            details={"trap_id": trap_id, "event_type": ev.event_type},
        )
    except Exception:  # noqa: BLE001
        db.rollback()
    return {"ok": True, "id": trap_id}
