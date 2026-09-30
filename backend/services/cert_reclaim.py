"""S4：失联主机的设备证书自动回收（评估文档 §4.3）。

为什么需要
──────────
证书 90 天到期，但**到期不等于失效** —— 一台离职/报废/被搬走的机器，只要配置目录还在
（或者说只要有人把那份 node.key 复制走），它就能一直续期。人工不可能每天盯着「哪些机器
三个月没心跳了」，所以要有定时任务兜底。

判定
────
心跳超过 `cert_reclaim_days` 天（默认 90，配置 `cert_reclaim_days`，0 = 关闭）→ 自动吊销。

几条刻意留的余地
────────────────
* **只看「曾经在线过」的主机**：`last_seen` 为空说明它压根没成功上报过，
  拿不到可靠基线，不吊销（否则一台从没接上的机器会被反复吊销）。
* **吊销 = 与管理员手工吊销完全一致的语义**：保留 `client_cert` 当审计证据
  （清空会让 Agent 回落遗留 HMAC，等于把被吊销的机器又放进来），
  换一把新配对码，好让它哪天真回来了还能走人工准入。
* **幂等**：已经吊销的、还没发证的，一律跳过。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _cfg_days(db, default: int = 90) -> int:
    try:
        from models import GlobalConfig

        row = db.query(GlobalConfig).filter(GlobalConfig.key == "cert_reclaim_days").first()
        if row is None:
            return default
        return int(str(row.value or "0").strip() or 0)
    except Exception:  # noqa: BLE001
        return default


def reclaim_lost_certificates(db, days: int | None = None) -> dict:
    """吊销所有「失联超过 N 天」且仍持有已登记公钥的主机。

    返回 `{"checked": n, "reclaimed": n, "skipped": n, "days": d}`，
    方便定时任务写日志、也方便冒烟脚本断言。
    """
    from models import AgentKey, Alert, Server
    from services.audit_logger import log_operation

    if days is None:
        days = _cfg_days(db)
    if not days or days <= 0:
        return {"checked": 0, "reclaimed": 0, "skipped": 0, "days": days, "disabled": True}

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    rows = (
        db.query(AgentKey, Server)
        .join(Server, Server.id == AgentKey.server_id)
        # 1.1.51 方案 A：判据从"有没有证书"改成"有没有登记公钥"。
        # 不改的话这条定时任务对新入户的机器**完全不生效**（它们没有 client_cert），
        # 失联主机再也不会被自动吊销，是个会静默失效的坑。
        .filter(AgentKey.pub_key.isnot(None), AgentKey.pub_key != "")
        .all()
    )

    checked = reclaimed = skipped = 0
    for key, server in rows:
        checked += 1
        if key.revoked:
            skipped += 1
            continue
        last = server.last_seen or server.offline_time
        if last is None:
            skipped += 1
            continue
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last >= cutoff:
            skipped += 1
            continue

        # 与管理员手工吊销保持同一套语义（见 routes/servers.py::revoke_server_cert）
        try:
            from services import agent_identity as aid

            key.pairing_code = aid.new_pairing_code()
        except Exception:  # noqa: BLE001
            pass
        key.revoked = 1
        key.revoked_at = datetime.now(timezone.utc)
        key.revoked_reason = f"失联超过 {days} 天，设备身份自动吊销"
        key.identity_state = "revoked"
        reclaimed += 1

        db.add(Alert(
            server_id=server.id,
            level="critical",
            title=f"设备身份已自动吊销：{server.name}",
            message=(
                f"该主机已失联超过 {days} 天（最后上报 {last.isoformat()}），"
                f"设备身份已自动吊销。若这台机器仍在使用，请先排查它的网络 / Agent 进程，"
                f"再在「注册管理」点「加入管理」并核对新配对码重新准入。"
            ),
            metric_type="identity",
        ))
        log_operation(
            db,
            category="identity",
            action="cert_auto_reclaim",
            level="warning",
            # 这是「按策略成功吊销了证书」，不是操作失败（warning 指严重程度）。
            status="success",
            message=f"主机 {server.name} 失联超过 {days} 天，设备证书已自动吊销",
            target_type="server",
            target_id=str(server.id),
            details={"days": days, "last_seen": last.isoformat(), "node_id": key.node_id or ""},
        )

    if reclaimed:
        db.commit()
    return {"checked": checked, "reclaimed": reclaimed, "skipped": skipped, "days": days}
