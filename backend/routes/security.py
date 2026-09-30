"""安全设置（系统设置 - 安全设置页签）。

读写 `global_config` 里 `security.*` 前缀的策略项，见 `services/security_policy.py`。
只有拥有「系统设置 / 安全设置」操作点（或系统管理员）的人能改；**所有人都可以读**
—— 登录页/前端要按口令规则给出提示，读接口不泄露任何凭据。
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from services import security_policy
from services.audit_logger import log_operation

router = APIRouter(prefix="/api/security", tags=["security"])


class PolicyUpdate(BaseModel):
    """只接受已登记的策略键；未登记的键静默忽略，避免被塞脏数据。"""
    login_max_attempts: Optional[int] = None
    login_lock_minutes: Optional[int] = None
    session_idle_minutes: Optional[int] = None
    session_max_hours: Optional[int] = None
    pwd_min_length: Optional[int] = None
    pwd_require_upper: Optional[int] = None
    pwd_require_lower: Optional[int] = None
    pwd_require_digit: Optional[int] = None
    pwd_require_symbol: Optional[int] = None
    pwd_max_age_days: Optional[int] = None
    force_reset_first_login: Optional[int] = None


def _require_manage(authorization: Optional[str], db: Session) -> dict:
    from routes.auth import get_current_user_full, require_perm
    user = get_current_user_full(authorization, db)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    require_perm(db, user, "sys", "settings", "edit", "security_manage",
                 "无权限，仅系统管理员可修改安全设置")
    return user


@router.get("/policy")
def get_policy(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    """当前安全策略 + 取值范围（供前端渲染下拉/提示文案）。"""
    from routes.auth import get_current_user_full
    if not get_current_user_full(authorization, db):
        raise HTTPException(status_code=401, detail="未登录")
    return {
        "policy": security_policy.get_policy(fresh=True),
        "bounds": security_policy.BOUNDS,
        "defaults": security_policy.DEFAULTS,
    }


@router.get("/password-rules")
def password_rules(authorization: Optional[str] = Header(None),
                   db: Session = Depends(get_db)):
    """口令组成规则（一句话 + 结构化字段），给"密码输入框下方的规则提示"用。

 这里刻意 `enforce_password_reset=False`：首登被强制改密的账号带着
    `must_reset_password=1`，走默认鉴权的话**所有**接口都 403 —— 包括本接口，
    而那正是最需要看规则提示的页面（用户正卡在改密窗口里）。

    只回口令组成规则，不回登录失败锁定/会话超时那些策略 —— 对一个还没改完
    初始口令的账号，没必要把整份安全策略摊开。
    """
    from routes.auth import get_current_user_full
    if not get_current_user_full(authorization, db, enforce_password_reset=False):
        raise HTTPException(status_code=401, detail="未登录")
    policy = security_policy.get_policy(fresh=True)
    return {
        "hint": security_policy.describe_password_rules(policy),
        "rules": {k: int(policy.get(k, 0) or 0)
                  for k in security_policy.password_rule_keys()},
    }


@router.put("/policy")
def update_policy(data: PolicyUpdate, request: Request,
                  authorization: Optional[str] = Header(None),
                  db: Session = Depends(get_db)):
    user = _require_manage(authorization, db)
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    old = security_policy.get_policy(fresh=True)
    new = security_policy.set_policy(updates)
    changed = {k: {"old": old.get(k), "new": new.get(k)}
               for k in updates if old.get(k) != new.get(k)}
    if changed:
        log_operation(
            db,
            category="config",
            action="security_policy_update",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=request.client.host if request.client else "",
            target_type="config",
            target_id="security",
            message=f"用户 {user.get('username', '未知')} 修改了安全策略",
            details={"changed": changed},
        )
    return {"policy": new, "changed": changed}


@router.post("/unlock/{username}")
def unlock_user(username: str, request: Request,
                authorization: Optional[str] = Header(None),
                db: Session = Depends(get_db)):
    """管理员手动解锁被登录失败锁定住的账号（失败计数只存在进程内存里）。"""
    user = _require_manage(authorization, db)
    security_policy.clear_failures(username)
    log_operation(
        db,
        category="user",
        action="unlock",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        ip_address=request.client.host if request.client else "",
        target_type="user",
        target_id=username,
        message=f"用户 {user.get('username', '未知')} 手动解锁账号 {username}",
    )
    return {"message": f"已解锁 {username}"}
