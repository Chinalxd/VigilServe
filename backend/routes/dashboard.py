"""Dashboard API routes — aggregates data from all servers."""
from typing import Optional

from fastapi import APIRouter, Depends, Header
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import get_db
from models import Server, MetricSnapshot, Alert
from routes.auth import require_login, allowed_server_ids

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/")
def get_dashboard(authorization: Optional[str] = Header(None),
                  db: Session = Depends(get_db)):
    """Aggregate dashboard data: all servers summary + overall stats.

    安全加固阶段 3：以前这个接口零鉴权，匿名者就能拿到全网主机清单与告警。
    交付审查补漏：之前只验登录就返回**全网**数据，非管理员角色能看到自己
    管辖范围外的主机与告警明细。现在统一按 ``allowed_server_ids`` 收敛 ——
    系统管理员返回全部，其余角色只看得到角色「管理主机」里显式添加的主机。
    """
    user = require_login(authorization, db)
    all_ids = [r[0] for r in db.query(Server.id).all()]
    allowed = allowed_server_ids(db, user, all_ids)
    # 管理员恒为全部，这里就不用给查询加 IN 条件了（避免空列表/长列表两种退化）
    scoped = not user.get("is_admin")

    q = db.query(Server).filter(
        ~(Server.protocol == "agent") | (Server.status != "registered")
    )
    if scoped:
        q = q.filter(Server.id.in_(allowed))
    servers = q.order_by(Server.id).all()

    total_servers = len(servers)
    online = sum(1 for s in servers if s.status in ("online", "monitored"))
    warning = sum(1 for s in servers if s.status == "warning")
    critical = sum(1 for s in servers if s.status == "critical")
    offline = sum(1 for s in servers if s.status == "offline")

    _alerts_q = db.query(func.count(Alert.id)).filter(Alert.acknowledged == 0)
    if scoped:
        _alerts_q = _alerts_q.filter(Alert.server_id.in_(allowed))
    total_alerts = _alerts_q.scalar() or 0

    server_summaries = []
    for s in servers:
        latest = (
            db.query(MetricSnapshot)
            .filter(MetricSnapshot.server_id == s.id)
            .order_by(MetricSnapshot.timestamp.desc())
            .first()
        )
        alert_count = (
            db.query(func.count(Alert.id))
            .filter(Alert.server_id == s.id, Alert.acknowledged == 0)
            .scalar() or 0
        )
        server_summaries.append({
            "id": s.id,
            "name": s.name,
            "os_type": s.os_type,
            "network_env": s.network_env,
            "business_system": s.business_system,
            "status": s.status,
            "cpu_percent": latest.cpu_percent if latest else 0,
            "memory_percent": latest.memory_percent if latest else 0,
            "disk_percent": latest.disk_percent if latest else 0,
            "network_in_mbps": latest.network_in_mbps if latest else 0,
            "network_out_mbps": latest.network_out_mbps if latest else 0,
            "alerts": alert_count,
        })

    _recent_q = db.query(Alert)
    if scoped:
        _recent_q = _recent_q.filter(Alert.server_id.in_(allowed))
    recent_alerts = _recent_q.order_by(Alert.timestamp.desc()).limit(10).all()

    return {
        "summary": {
            "total": total_servers,
            "online": online,
            "warning": warning,
            "critical": critical,
            "offline": offline,
            "total_alerts": total_alerts,
        },
        "servers": server_summaries,
        "recent_alerts": [
            {
                "id": a.id,
                "server_name": a.server.name if a.server else "Unknown",
                "timestamp": a.timestamp.isoformat(),
                "level": a.level,
                "title": a.title,
                "message": a.message,
                "acknowledged": a.acknowledged,
            }
            for a in recent_alerts
        ],
    }
