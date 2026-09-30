"""Central operation-log writer for audit trails."""
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from models import OperationLog


def log_operation(
    db: Session,
    message: str,
    category: str = "system",
    action: str = "",
    level: str = "info",
    username: str = "",
    user_id: int | None = None,
    ip_address: str = "",
    status: str = "success",
    target_type: str = "",
    target_id: str = "",
    details: dict | None = None,
) -> OperationLog:
    """Persist an operation log entry and return the created record."""
    # status 只由调用方决定，这里不做任何推断（2026-09-23 动态审计 D-3）
    # 原来这里有一句「status 还是默认的 success、而 level 是 error 自动改成 failed」。
    # ① **漏判**：登录失败用的是 `level="warning"`（不是 error），所以
    # 「登录失败 / 账号被禁用 / 账号过期 / 设备命令行登录失败 / 越权拒绝」
    # 这些最关键的入侵信号**全部被记成 status="success"**。
    # 生产库里 272 条日志中 warning 级 7 条无一例外，另有 19 条 message
    # 写着"失败/拒绝/无权限"却标 success，按「状态=失败」筛选一条都筛不出来，
    # 审计形同虚设。
    # ② **覆写显式意图**：`routes/traps.py` 的 `trap_critical` 明确传了
    # `status="success"`（语义是"紧急事件已成功接收"，不是"操作失败"），
    # 却被那句悄悄改成了 failed。
    # 现在改成：不传就是 success，要标失败就**显式传** `status="failed"`。
    # 所有"操作失败"的调用点已逐处补齐（本轮按语义逐条核对过，
    # 而不是按 level 一刀切，因为 level 表达的是"严重程度"，
    # 与"这次操作成没成"是两件事：`ssh_host_key_changed` 是 critical 且算失败，
    # 而 `drift_l2` / `cert_auto_reclaim` 是 warning 却是正常完成的系统动作）。
    effective_status = (status or "success").lower()
    entry = OperationLog(
        timestamp=datetime.now(timezone.utc),
        level=level,
        category=category,
        action=action,
        username=username or "",
        user_id=user_id,
        ip_address=ip_address or "",
        status=effective_status,
        target_type=target_type or "",
        target_id=str(target_id) if target_id is not None else "",
        message=message or "",
        details=details or {},
    )
    db.add(entry)
    db.commit()
    return entry
