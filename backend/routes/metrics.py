"""Metrics API routes."""
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session
from database import get_db
from models import MetricSnapshot
from routes.auth import get_current_user_full, can_manage_server
from datetime import datetime, timezone, timedelta
from collections import defaultdict

router = APIRouter(prefix="/api/metrics", tags=["metrics"])

RANGE_CONFIG = {
    "1h":  {"delta": timedelta(hours=1),   "bucket": 60},
    "6h":  {"delta": timedelta(hours=6),   "bucket": 300},
    "12h": {"delta": timedelta(hours=12),  "bucket": 600},
    "1d":  {"delta": timedelta(days=1),    "bucket": 1200},
    "3d":  {"delta": timedelta(days=3),    "bucket": 3600},
    "7d":  {"delta": timedelta(weeks=1),   "bucket": 7200},
    "14d": {"delta": timedelta(days=14),   "bucket": 10800},
}


@router.get("/{server_id}/history")
def get_metric_history(
    server_id: int,
    range: str = Query("1h", description="Time range: 1h,6h,12h,1d,3d,7d,14d,custom"),
    start: str = Query(None, description="ISO datetime for custom range start"),
    end: str = Query(None, description="ISO datetime for custom range end"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    # 安全加固阶段 3：历史曲线以前零鉴权，匿名即可拖走任意主机的资源走势。
    # 第二轮复查 R-1（2026-09-23）：只验登录**还不够**，任意低权限账号遍历
    # `server_id` 就能读全网主机的 CPU/内存/磁盘/流量走势（内网横向侦察的高价值素材）。
    # 漏网原因：P0-1 那批"补主机归属校验"的范围只写了 servers.py，而这条在 metrics.py。
    # 管理员恒通过（见 routes.auth.can_manage_server），所以对管理员行为完全不变。
    user = get_current_user_full(authorization, db)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    if not can_manage_server(db, user, server_id):
        raise HTTPException(status_code=403, detail="该主机不在当前角色的管理范围内")
    if range == "custom" and start and end:
        try:
            since = datetime.fromisoformat(start.replace('Z', '+00:00'))
            until = datetime.fromisoformat(end.replace('Z', '+00:00'))
        except ValueError:
            since = datetime.utcnow() - timedelta(days=1)
            until = datetime.utcnow()
        total_sec = max((until - since).total_seconds(), 60)
        bucket_sec = max(int(total_sec / 50), 60)
    else:
        config = RANGE_CONFIG.get(range, RANGE_CONFIG["1h"])
        delta = config["delta"]
        bucket_sec = config["bucket"]
        since = datetime.utcnow() - delta
        until = datetime.utcnow()

    if range == "custom" and start and end:
        metrics = (
            db.query(MetricSnapshot)
            .filter(
                MetricSnapshot.server_id == server_id,
                MetricSnapshot.timestamp >= since,
                MetricSnapshot.timestamp <= until,
            )
            .order_by(MetricSnapshot.timestamp.asc())
            .all()
        )
    else:
        metrics = (
            db.query(MetricSnapshot)
            .filter(
                MetricSnapshot.server_id == server_id,
                MetricSnapshot.timestamp >= since,
            )
            .order_by(MetricSnapshot.timestamp.asc())
            .all()
        )

    if not metrics:
        return []

    buckets = defaultdict(lambda: {"cpu": [], "mem": [], "disk": [], "net_in": [], "net_out": [], "disk_io_read": [], "disk_io_write": [], "tcp_conn": [], "ts": None})
    for m in metrics:
        ts_aware = m.timestamp if m.timestamp.tzinfo else m.timestamp.replace(tzinfo=timezone.utc)
        epoch = int(ts_aware.timestamp())
        bucket_key = (epoch // bucket_sec) * bucket_sec
        b = buckets[bucket_key]
        b["cpu"].append(m.cpu_percent)
        b["mem"].append(m.memory_percent)
        b["disk"].append(m.disk_percent)
        b["net_in"].append(m.network_in_mbps)
        b["net_out"].append(m.network_out_mbps)
        b["disk_io_read"].append(m.disk_io_read_mbps)
        b["disk_io_write"].append(m.disk_io_write_mbps)
        b["tcp_conn"].append(m.tcp_connections)
        if b["ts"] is None:
            b["ts"] = ts_aware

    result = []
    for bucket_key in sorted(buckets.keys()):
        b = buckets[bucket_key]
        ts = datetime.fromtimestamp(bucket_key + bucket_sec // 2, tz=timezone.utc)
        result.append({
            "timestamp": ts.isoformat(),
            # 网络设备不提供 CPU / 内存时存的是 NULL，必须跳过再取平均，否则
            # 要么 sum(None) 直接抛 TypeError，要么把"没这个指标"平均成一条 0 线。
            "cpu_percent": _bucket_avg(b["cpu"], 1),
            "memory_percent": _bucket_avg(b["mem"], 1),
            "disk_percent": _bucket_avg(b["disk"], 1),
            "network_in_mbps": _bucket_avg(b["net_in"], 2),
            "network_out_mbps": _bucket_avg(b["net_out"], 2),
            "disk_io_read_mbps": _bucket_avg(b["disk_io_read"], 2),
            "disk_io_write_mbps": _bucket_avg(b["disk_io_write"], 2),
            "tcp_connections": _bucket_avg(b["tcp_conn"], 0),
        })

    return result


def _bucket_avg(values, digits: int):
    """桶内取平均，跳过 None；整桶都是 None 就返回 None（前端画线时断开，不假造 0）。"""
    vals = [v for v in values if v is not None]
    if not vals:
        return None
    avg = sum(vals) / len(vals)
    return round(avg, digits) if digits > 0 else round(avg)
