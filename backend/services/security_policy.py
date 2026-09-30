"""统一安全策略：登录失败锁定 / 会话超时 / 口令规则 / 口令有效期 / 首登强制改密。

配置存在 `global_config` 表（key 前缀 `security.`），与「周期配置/告警配置」同一套
存储，不新增表。所有默认值都写在 `DEFAULTS` 里，**读不到就按默认值走**，所以老
库升级上来不会因为缺行而锁死登录。

生效位置：
  * 登录失败锁定  -> routes/auth.py::login（失败计数 + 锁定窗口）
  * 会话超时      -> routes/auth.py 的 create_token / get_current_user_full
  * 口令规则      -> 建用户 / 改口令（含首登强制改密那次）
  * 口令有效期    -> 登录时比对 password_changed_at
  * 首登强制改密  -> 登录时看 last_login_at 是否为空
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

_PREFIX = "security."

# 默认值（升级安全失败：宁可宽松也不能把人锁在门外）
DEFAULTS: dict[str, int] = {
    "login_max_attempts": 5,
    "login_lock_minutes": 15,
    # 登录超时：空闲 N 分钟自动登出（0 = 不限制） / 会话最长 N 小时（0 = 不限制）
    "session_idle_minutes": 120,
    "session_max_hours": 24,
    "pwd_min_length": 8,
    "pwd_require_upper": 1,
    "pwd_require_lower": 1,
    "pwd_require_digit": 1,
    "pwd_require_symbol": 0,
    # 密码有效期：N 天后必须改（0 = 永不过期）
    "pwd_max_age_days": 0,
    "force_reset_first_login": 1,
}

BOUNDS: dict[str, tuple[int, int]] = {
    "login_max_attempts": (0, 99),
    "login_lock_minutes": (0, 1440),
    "session_idle_minutes": (0, 1440),
    "session_max_hours": (0, 720),
    "pwd_min_length": (4, 64),
    "pwd_require_upper": (0, 1),
    "pwd_require_lower": (0, 1),
    "pwd_require_digit": (0, 1),
    "pwd_require_symbol": (0, 1),
    "pwd_max_age_days": (0, 3650),
    "force_reset_first_login": (0, 1),
}

_CACHE: dict = {"ts": 0.0, "policy": dict(DEFAULTS)}
_CACHE_TTL = 10.0  # 秒：会话校验每次请求都要读，别每请求打一次库

# 登录失败计数（进程内）。重启会清空——这是可接受的：持久化失败计数需要额外的
# 表与清理任务，而攻击者更在意"能不能撞库"，重启清空并不削弱锁定效果。
_LOGIN_FAILS: dict[str, dict] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clamp(key: str, value: int) -> int:
    lo, hi = BOUNDS.get(key, (0, 10 ** 6))
    return max(lo, min(hi, value))



def get_policy(fresh: bool = False) -> dict:
    """返回完整策略（含默认值补齐）。

    10 秒级缓存：会话空闲判定每次请求都会调，但策略本身几乎不变。
    """
    if not fresh and time.time() - _CACHE["ts"] < _CACHE_TTL:
        return dict(_CACHE["policy"])

    policy = dict(DEFAULTS)
    try:
        from database import SessionLocal
        from models import GlobalConfig
        db = SessionLocal()
        try:
            rows = db.query(GlobalConfig).filter(
                GlobalConfig.key.like(f"{_PREFIX}%")).all()
            for row in rows:
                key = (row.key or "")[len(_PREFIX):]
                if key not in DEFAULTS:
                    continue
                try:
                    policy[key] = _clamp(key, int(str(row.value).strip()))
                except (TypeError, ValueError):
                    continue
        finally:
            db.close()
    except Exception:  # noqa: BLE001  库还没建好/查询失败 -> 用默认值，不能影响登录
        pass

    _CACHE["ts"] = time.time()
    _CACHE["policy"] = policy
    return dict(policy)


def set_policy(updates: dict) -> dict:
    """写回策略（只接受 DEFAULTS 里登记过的键），返回写之后的完整策略。"""
    clean = {}
    for key, raw in (updates or {}).items():
        if key not in DEFAULTS:
            continue
        try:
            clean[key] = _clamp(key, int(raw))
        except (TypeError, ValueError):
            continue
    if not clean:
        return get_policy(fresh=True)

    from database import SessionLocal
    from models import GlobalConfig
    db = SessionLocal()
    try:
        for key, value in clean.items():
            full_key = _PREFIX + key
            row = db.query(GlobalConfig).filter(GlobalConfig.key == full_key).first()
            if row:
                row.value = str(value)
                row.updated_at = _now()
            else:
                db.add(GlobalConfig(key=full_key, value=str(value),
                                    description=f"安全策略：{key}"))
        db.commit()
    finally:
        db.close()
    return get_policy(fresh=True)



def session_ttl_seconds() -> int:
    """会话绝对时长（秒）。0 = 不限制（内部转成 10 年）。"""
    hours = get_policy().get("session_max_hours", 24)
    if not hours:
        return 10 * 365 * 24 * 3600
    return int(hours) * 3600


def session_idle_seconds() -> int:
    """空闲多久算超时（秒）。0 = 不限制。"""
    minutes = get_policy().get("session_idle_minutes", 120)
    return int(minutes) * 60 if minutes else 0



def _fail_key(username: str) -> str:
    return (username or "").strip().lower()


def _ip_key(ip: str) -> str:
    return "ip:" + (ip or "").strip()


# 2026-09-22 P1-7：登录失败的**第二个维度** —— 来源 IP。
# 只按用户名计数时，攻击者可以拿同一个 IP 去撞 N 个用户名（每个都还在阈值内），
# 也就是"横向撞库"永远触发不了锁定。加上 IP 维度才能挡住。
# IP 维度的阈值放宽 _IP_FACTOR 倍：内网常见多人共用出口 NAT（或都在同一个
_IP_FACTOR = 4


def _key_remaining(key: str) -> int:
    """某个维度（用户名或 IP）还剩多少秒解锁；0 = 没被锁。

    ⚠️ 只在**真的锁过**且锁定期已过时才清记录。早期版本把"没锁"也当成
    "锁定期已过"顺手 pop 掉了，结果计数永远停在 1，锁定功能形同虚设。
    """
    info = _LOGIN_FAILS.get(key)
    if not info:
        return 0
    until = float(info.get("locked_until", 0) or 0)
    if until <= 0:
        return 0
    left = int(until - time.time())
    if left <= 0:
        _LOGIN_FAILS.pop(key, None)
        return 0
    return left


def lock_remaining(username: Optional[str] = None, ip: Optional[str] = None) -> int:
    """用户名维度或 IP 维度任一被锁，都返回剩余秒数；0 = 没被锁。

    username 为 None 表示"这个账号不存在"（此时不该按用户名查表）。
    """
    if username:
        left = _key_remaining(_fail_key(username))
        if left > 0:
            return left
    if ip:
        return _key_remaining(_ip_key(ip))
    return 0


def _register_one(key: str, max_attempts: int, lock_minutes: int) -> int:
    info = _LOGIN_FAILS.setdefault(key, {"count": 0, "locked_until": 0})
    info["count"] = int(info.get("count", 0)) + 1
    if info["count"] >= max_attempts:
        if lock_minutes > 0:
            info["locked_until"] = time.time() + lock_minutes * 60
            info["count"] = 0
            return lock_minutes * 60
        return 0
    return 0


def register_failure(username: Optional[str] = None, ip: Optional[str] = None) -> int:
    """记一次登录失败，返回还需锁定多少秒（0 = 未触发）。

    username=None 表示"账号不存在" —— 此时**只记 IP 维度**：
    若也按用户名记，攻击者用任意字符串当用户名就能把这张内存表撑爆。
    """
    policy = get_policy()
    max_attempts = int(policy.get("login_max_attempts", 0) or 0)
    if max_attempts <= 0:
        return 0
    lock_minutes = int(policy.get("login_lock_minutes", 0) or 0)
    left = 0
    if username:
        left = _register_one(_fail_key(username), max_attempts, lock_minutes)
    if ip:
        ip_left = _register_one(_ip_key(ip), max_attempts * _IP_FACTOR, lock_minutes)
        left = max(left, ip_left)
    return left


def clear_failures(username: str, ip: Optional[str] = None) -> None:
    """登录成功：两个维度的失败计数都清掉。"""
    _LOGIN_FAILS.pop(_fail_key(username), None)
    if ip:
        _LOGIN_FAILS.pop(_ip_key(ip), None)


def failure_count(username: str) -> int:
    return int(_LOGIN_FAILS.get(_fail_key(username), {}).get("count", 0))



def validate_password(password: str, policy: Optional[dict] = None) -> tuple[bool, str]:
    """按当前策略校验口令，返回 (是否通过, 不通过的原因)。"""
    policy = policy or get_policy()
    pw = password or ""
    min_len = int(policy.get("pwd_min_length", 0) or 0)
    if len(pw) < min_len:
        return False, f"密码长度不能少于 {min_len} 位"
    if int(policy.get("pwd_require_upper", 0)) and not re.search(r"[A-Z]", pw):
        return False, "密码必须包含大写字母"
    if int(policy.get("pwd_require_lower", 0)) and not re.search(r"[a-z]", pw):
        return False, "密码必须包含小写字母"
    if int(policy.get("pwd_require_digit", 0)) and not re.search(r"[0-9]", pw):
        return False, "密码必须包含数字"
    if int(policy.get("pwd_require_symbol", 0)) and not re.search(r"[^A-Za-z0-9]", pw):
        return False, "密码必须包含特殊字符"
    return True, ""


_PWD_CLASS_LABELS = (
    ("pwd_require_upper", "大写字母"),
    ("pwd_require_lower", "小写字母"),
    ("pwd_require_digit", "数字"),
    ("pwd_require_symbol", "特殊字符"),
)


def describe_password_rules(policy: Optional[dict] = None) -> str:
    """把口令组成规则拼成一句人话，给界面做"输入框下方的规则提示"。

    为什么要由后端出这句话：规则是可配置的（系统设置 - 安全设置），前端写死一句
    "至少 8 位含大小写数字"，管理员一改规则提示就成了假的 —— 用户照着提示输还是
    过不去，比没有提示更糟。这里跟 `validate_password` 读的是同一份 policy，
    所以提示与实际拦截口径**永远一致**。

    例：`长度至少 8 位，且必须包含大写字母、小写字母、数字`
    """
    policy = policy or get_policy()
    min_len = int(policy.get("pwd_min_length", 0) or 0)
    need = [label for key, label in _PWD_CLASS_LABELS if int(policy.get(key, 0) or 0)]
    if need:
        return f"长度至少 {min_len} 位，且必须包含{'、'.join(need)}"
    return f"长度至少 {min_len} 位"


def password_rule_keys() -> tuple:
    """口令组成规则涉及的全部键（只暴露这些，别把登录锁定策略一起发出去）。"""
    return ("pwd_min_length",) + tuple(k for k, _ in _PWD_CLASS_LABELS)


def password_expired(user, policy: Optional[dict] = None) -> bool:
    """口令是否已过有效期。

    只在 `password_changed_at` 有值时才判——老账号没有这个时间戳，一律视为
    未过期，否则一升级就把所有人锁在改密页上。
    """
    policy = policy or get_policy()
    days = int(policy.get("pwd_max_age_days", 0) or 0)
    if days <= 0:
        return False
    changed = getattr(user, "password_changed_at", None)
    if not changed:
        return False
    if changed.tzinfo is None:
        changed = changed.replace(tzinfo=timezone.utc)
    return _now() > changed + timedelta(days=days)


def password_age_days(user) -> Optional[int]:
    changed = getattr(user, "password_changed_at", None)
    if not changed:
        return None
    if changed.tzinfo is None:
        changed = changed.replace(tzinfo=timezone.utc)
    return max(0, (_now() - changed).days)


def account_expired(user) -> bool:
    """账户有效期到了没（valid_until 为空 = 长期有效）。"""
    until = getattr(user, "valid_until", None)
    if not until:
        return False
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    return _now() > until
