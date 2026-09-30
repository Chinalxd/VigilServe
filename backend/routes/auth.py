"""Auth and user management API."""
import logging
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel, Field
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from database import get_db
from models import User
from services.audit_logger import log_operation
from services.client_ip import get_client_ip
# 2026-09-23：MeshCentral 集成整体下线（用户拍板删除），原先这里导入的
import secrets
import time
from datetime import datetime, timezone
import json
import os  # used by _initial_password_path()/seed_admin; was missing and made the FIRST login on a fresh database 500

logger = logging.getLogger("backend")

router = APIRouter(prefix="/api/auth", tags=["auth"])

TOKENS: dict[str, dict] = {}

# 同一账号只允许一处在线，新登录会把旧 token 从 TOKENS 删掉；这里保留一小段
# 时间，好让「那台被踢的电脑」在下次轮询时能问到原因，从而给出明确提示，
REVOKED: dict[str, dict] = {}
REVOKED_TTL = 300

DEFAULT_ADMIN_USERNAME = "admin"

# 2026-09-23 开源加固 ②：**这里曾经是 `DEFAULT_ADMIN_PASSWORD = "admin123"`**，
# 而且前端登录页还把「默认管理员账号：admin / admin123」直接印在页面上
# 现成的后台钥匙，部署实例只要没改过口令就能直接进。
# 别再把任何固定口令加回来，也别在前端/文档里印初始口令。
PW_RESET_REQUIRED_MSG = "首次登录必须先修改密码"


def generate_initial_password() -> str:
    """首次启动生成的一次性管理员口令。

    token_urlsafe(16) → 22 个字符、约 128 bit 熵。选 urlsafe 而不是
    ``choice(全部可打印字符)`` 是刻意的：这个口令要被人工从 txt 里复制粘贴，
    带上 ``/ + =`` 之外的怪字符只会增加抄错的概率，安全性并无实质差别。
    """
    return secrets.token_urlsafe(16)


def _check_password_policy(password: str) -> tuple[bool, str]:
    """按「系统设置 - 安全设置」的口令规则校验；策略模块不可用时放行。"""
    try:
        from services import security_policy
        return security_policy.validate_password(password)
    except Exception:  # noqa: BLE001
        return True, ""


def _client_ip(request: Request) -> str:
    """ 2026-09-23 动态审计 D-1：取来源 IP 的规则已统一到 `services/client_ip.py`。

    原来这里（以及另外 5 个路由模块各写的一份**逐字相同**的副本）无条件采信
    `X-Forwarded-For`。而本项目服务端直接监听 0.0.0.0:8001、前面没有反向代理，
    这个头是**客户端可以随便写**的，于是：

      · 审计日志的 ip_address 能被伪造成任意值（实测写成了 203.0.113.9）；
      · 每次请求换一个 XFF，登录失败锁定的「IP 维度」就永远不累积（实测连撞
        7 次不触发，而固定 IP 撞 5 次就锁）。

    现在默认**只认直连 IP**；确实走了反向代理时，用环境变量
    `VIGILSERVE_TRUSTED_PROXIES` 显式声明代理地址，之后才会从 XFF 里取值
    （且从右往左取，跳过代理，拿到的是代理亲眼看到的那个地址）。

    这里保留同名薄封装，是为了不动散落在各路由里的 60+ 处
    `ip_address=_client_ip(request)`；`host_groups` / `roles` 也是从这个模块
    import `_client_ip` 的，所以改这一处即全部生效。
    """
    return get_client_ip(request)


def hash_pw(pw: str) -> str:
    """安全加固阶段 3：bcrypt 优先，缺包回退标准库 scrypt（都不再是无盐 sha256）。"""
    from services.password_hash import hash_password
    return hash_password(pw)


def verify_pw(pw: str, hashed: str) -> bool:
    from services.password_hash import verify_password
    return verify_password(pw, hashed)


def _rehash_if_needed(user: "User", plain: str, db: Session) -> None:
    """老口令（无盐 sha256）登录成功后就地升级成加盐慢哈希。"""
    try:
        from services.password_hash import needs_rehash, algo_of
        if not needs_rehash(user.password or ""):
            return
        old = algo_of(user.password or "")
        user.password = hash_pw(plain)
        db.commit()
        logger.info(f"[auth] 用户 {user.username} 的口令哈希已从 {old} 升级为加盐慢哈希")
    except Exception as exc:  # noqa: BLE001 升级失败不影响本次登录
        logger.warning(f"[auth] 口令哈希升级失败（用户 {getattr(user, 'username', '')}）：{exc}")
        db.rollback()


def _session_ttl() -> int:
    """会话绝对时长（秒），来自安全策略；策略读取失败退回 24 小时。"""
    try:
        from services import security_policy
        return int(security_policy.session_ttl_seconds())
    except Exception:  # noqa: BLE001
        return 86400


def _revoke_user_tokens(user_id: int, reason: str = "replaced") -> int:
    """作废某个账号当前所有在线会话，返回被顶掉的数量。

    需求：同一账号只允许一台设备在线，第二台登录时第一台立刻下线。
    墓碑（REVOKED）只记原因与时间 —— **不记账号名和登录 IP**，避免把
    "谁在哪台机器登录"泄露给其他人，被踢的那台只收到一句笼统提示。
    """
    now = time.time()
    killed = 0
    for t in list(TOKENS.keys()):
        if TOKENS[t].get("user_id") == user_id:
            TOKENS.pop(t, None)
            REVOKED[t] = {"reason": reason, "at": now}
            killed += 1
    for t in list(REVOKED.keys()):
        if now - REVOKED[t]["at"] > REVOKED_TTL:
            REVOKED.pop(t, None)
    # 会话都作废了，该账号已经发出去的「WEB管理」代理票据也必须一起失效，
    # 否则退出登录后，票据在 URL 里还能再用满 30 分钟（票据是窄凭据，但设备后台
    # 照样能操作）。详见 services/web_proxy_ticket.py 顶部的「会话吊销」说明。
    # 这里覆盖到：登录挤掉旧会话、改密码、改角色、停用/启用、删除账号。
    try:
        from services import web_proxy_ticket
        web_proxy_ticket.bump_epoch(user_id)
    except Exception as exc:  # noqa: BLE001 吊销失败不能让登录/改密本身失败
        logger.warning(f"[auth] 吊销 WEB 代理票据失败（用户 {user_id}）：{exc}")
    return killed


def create_token(user_id: int, role: str, role_id: Optional[int] = None,
                 is_admin: bool = False, ip: str = "") -> str:
    token = secrets.token_hex(32)
    # 单会话：先踢掉该账号已有的在线会话，再发放新 token
    _revoke_user_tokens(user_id, reason="replaced")
    TOKENS[token] = {
        "user_id": user_id,
        "login_at": time.time(),
        "login_ip": ip or "",
        # ``role`` 保留为角色 code，兼容历史判定；真正的权限以 role_id 对应的 Role 为准
        "role": role or "viewer",
        "role_id": role_id,
        "is_admin": bool(is_admin),
        # 会话绝对时长取自「系统设置 - 安全设置」的登录超时策略
        "expires_at": time.time() + _session_ttl(),
        "last_seen": time.time(),
    }
    for t in list(TOKENS.keys()):
        if TOKENS[t]["expires_at"] < time.time():
            del TOKENS[t]
    return token


def _load_role(db: Session, user: dict):
    """按 token 里的 role_id 取出角色对象。"""
    if not user:
        return None
    from models import Role
    rid = user.get("role_id")
    if not rid:
        return db.query(Role).filter(Role.code == (user.get("role") or "viewer")).first()
    return db.query(Role).filter(Role.id == rid).first()


def permissions_of(db: Session, user: dict) -> dict:
    """当前用户的权限表（系统管理员恒为全开）。"""
    from services import rbac
    if not user:
        return rbac.empty_permissions()
    if user.get("is_admin"):
        return rbac.full_permissions()
    role = _load_role(db, user)
    if role is None:
        return rbac.empty_permissions()
    return rbac.normalize(role.permissions)


def has_perm(db: Session, user: dict, scope: str, page: str, action: str, op: Optional[str] = None) -> bool:
    """统一权限判定。系统管理员恒通过；未知权限点一律拒绝。"""
    if not user:
        return False
    if user.get("is_admin"):
        return True
    from services import rbac
    return rbac.can(permissions_of(db, user), scope, page, action, op)


def allowed_server_ids(db: Session, user: dict, all_ids: list) -> list:
    """当前用户可管理的主机 ID 列表。

    严格白名单：系统管理员 = 全部；其余角色 = **只返回角色「管理主机」列表里显式添加的主机**，
    列表为空则该角色看不到任何主机。
    """
    if not user:
        return []
    if user.get("is_admin"):
        return list(all_ids)
    from models import RoleServer
    role = _load_role(db, user)
    if role is None:
        return []
    return [
        rs.server_id
        for rs in db.query(RoleServer).filter(RoleServer.role_id == role.id).all()
    ]


def can_manage_server(db: Session, user: dict, server_id) -> bool:
    """该主机是否在用户所属角色的管理范围内。"""
    if not user or user.get("is_admin"):
        return True
    try:
        sid = int(server_id)
    except (TypeError, ValueError):
        return False
    return sid in allowed_server_ids(db, user, [sid])


def require_perm(db: Session, user: dict, scope: str, page: str, action: str,
                 op: Optional[str] = None, detail: str = "无权限执行该操作"):
    if not has_perm(db, user, scope, page, action, op):
        raise HTTPException(status_code=403, detail=detail)
    return user


def require_login(authorization: Optional[str], db: Session) -> dict:
    """解析当前登录用户；未登录或会话已失效一律 401。

    与 servers.py 的 `_require_user` 同源。历史上多个路由用「未登录返回空 dict」
    的写法，导致一批业务接口匿名可读（系统配置、邮件配置、日志、Agent 升级等），
    统一改用本函数截断。
    """
    user = get_current_user_full(authorization, db)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="未登录或会话已失效，请重新登录",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization[7:]
    data = TOKENS.get(token)
    if not data or data["expires_at"] < time.time():
        return None
    # 空闲超时：任何一次带 token 的请求都算活跃，超过策略时长就踢下线。
    # 只在每次校验时滑动 last_seen，不额外打库（策略本身有 10s 缓存）。
    try:
        from services import security_policy
        idle = int(security_policy.session_idle_seconds())
    except Exception:  # noqa: BLE001
        idle = 0
    now = time.time()
    if idle > 0 and now - float(data.get("last_seen", now)) > idle:
        TOKENS.pop(token, None)
        return None
    data["last_seen"] = now
    return data


def get_current_user_full(
    authorization: Optional[str],
    db: Session,
    enforce_password_reset: bool = True,
) -> dict:
    """Return current user dict enriched with username/full_name from the database.

 2026-09-23 开源加固 ②：`enforce_password_reset=True`（默认）时，账号只要
    带着 `must_reset_password=1`，**除改密/登出外一律 403**。

    为什么加在这里而不是散到各路由：`require_login` / `require_admin_full` /
    `file_explorer` 的依赖 / `main.py` 的 WebSocket 握手，全部都会走到本函数，
    加一处即全站生效。

    为什么必须服务端强制：改之前只是把 `must_reset_password` 字段**返回给前端**，
    指望前端自己跳转改密 —— 而前端压根没读这个字段（`grep mustReset frontend/src`
    零命中）。于是"首登强制改密"形同虚设：拿到初始口令的人可以一直用下去。

    :param enforce_password_reset: 置 False 表示"我知道这个账号待改密，别拦我"
        —— 只有 `POST /api/auth/change-password` 和 `/logout` 该用，
        否则待改密的用户连改密和退出都做不到，会被彻底锁死。
    """
    user = get_current_user(authorization)
    if not user:
        return {}
    username = ""
    full_name = ""
    must_reset = 0
    try:
        db_user = db.query(User).filter(User.id == user["user_id"]).first()
        if db_user:
            username = db_user.username or ""
            full_name = db_user.full_name or ""
            must_reset = int(db_user.must_reset_password or 0)
    except Exception as exc:  # noqa: BLE001 查不到用户名不该让鉴权失败，但要留痕
        logger.warning(f"[auth] 补全用户信息失败（user_id={user.get('user_id')}）：{exc}")
    if must_reset and enforce_password_reset:
        raise HTTPException(status_code=403, detail=PW_RESET_REQUIRED_MSG)
    return {**user, "username": username, "full_name": full_name,
            "must_reset_password": must_reset}


def require_admin(authorization: Optional[str] = Header(None)) -> dict:
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    if not user.get("is_admin") and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="无权限，仅管理员可操作")
    return user


def require_admin_full(authorization: Optional[str], db: Session) -> dict:
    """Require admin and return user dict enriched with username."""
    user = get_current_user_full(authorization, db)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    if not user.get("is_admin") and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="无权限，仅管理员可操作")
    return user


class LoginData(BaseModel):
    username: str
    password: str


def parse_valid_until(raw) -> Optional[datetime]:
    """把前端传来的有效期解析成 naive UTC datetime。

    接受 ISO 字符串（`2026-12-31` / `2026-12-31T23:59`）和 `null`/空串（= 长期有效）。
    解析失败抛 400 —— 静默忽略会让管理员以为设上了其实没设。
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"有效期格式不正确：{raw}")
    if dt.tzinfo is None:
        # 前端按本地时间填，视为本机时区；统一存 UTC naive，与库里其它时间列一致
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _dt_iso(dt) -> Optional[str]:
    return dt.isoformat() if dt else None


class UserCreate(BaseModel):
    username: str
    full_name: str = ""
    password: str
    email: str = ""
    role: str = "viewer"          # 兼容字段：角色 code
    role_id: Optional[int] = None
    valid_until: Optional[str] = None


class UserUpdate(BaseModel):
    username: Optional[str] = None
    full_name: Optional[str] = None
    password: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    role_id: Optional[int] = None
    status: Optional[str] = None
    valid_until: Optional[str] = None


def _initial_password_path() -> str:
    """Path where the one-time generated admin password is persisted.

    Stored under ``backend/data/`` so it lives next to the database file and
    is removed automatically by the cleanup pass on each rebuild.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "data", "initial_admin_password.txt")


def _is_builtin_admin(user) -> bool:
    """是否为系统默认管理员（seed_admin 建出来的第一个账号）。

    判据用 ``id == 1`` 而不是 ``username == 'admin'``：2026-09-24 起登录名
    允许修改，改名后按名字判断会漏；反过来别人之后新建的账号完全可以取名
    ``admin``，按名字判断又会误伤。id 建号时分配、不随改名变化，是这个
    场景里唯一稳定的标记。
    """
    return getattr(user, "id", None) == 1


def seed_admin(db: Session):
    """Ensure a default admin account exists.

    On the very first run we create ``admin`` with a **randomly generated**
    one-time password (2026-09-23 之前是硬编码的 ``admin123``，见文件顶部说明),
    write it to ``backend/data/initial_admin_password.txt`` for reference and flag
    the account so the operator is forced to set their own password on first login
    — 这个"强制"现在由 `get_current_user_full` 在服务端截断，不再指望前端自觉。

    On subsequent runs (database already populated), this is a no-op.
    """
    admin = db.query(User).filter(User.username == DEFAULT_ADMIN_USERNAME).first()
    if admin:
        return
    try:
        from routes.roles import seed_roles
        seed_roles(db)
    except Exception as exc:
        logger.warning(f"[auth] seed_roles failed: {exc}")

    from models import Role
    admin_role = db.query(Role).filter(Role.code == "admin").first()
    initial_pw = generate_initial_password()
    admin = User(
        username=DEFAULT_ADMIN_USERNAME,
        password=hash_pw(initial_pw),
        role="admin",
        role_id=admin_role.id if admin_role else None,
        status="active",
        must_reset_password=1,
    )
    db.add(admin)
    db.commit()

    pw_path = _initial_password_path()
    try:
        os.makedirs(os.path.dirname(pw_path), exist_ok=True)
        with open(pw_path, "w", encoding="utf-8") as f:
            f.write(
                "VigilServe initial administrator password\n"
                "----------------------------------------\n"
                f"Username : {DEFAULT_ADMIN_USERNAME}\n"
                f"Password : {initial_pw}\n"
                "\n"
                "Please log in with the password above and change it immediately.\n"
                "This file is removed automatically once the password is changed.\n"
            )
        # Restrict file permissions on POSIX systems so only the owner can read it
        try:
            os.chmod(pw_path, 0o600)
        except Exception as exc:  # noqa: BLE001 Windows 上 chmod 无效属正常
            logger.debug(f"[auth] 设置初始口令文件权限失败（可忽略）：{exc}")
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[auth] 写初始管理员口令文件失败：{exc}")

    logger.info("[auth] Initial administrator account created.")
    # 明文口令**只写进上面那个文件**，不再打到 stdout，服务端的 stdout 通常被
    # 重定向进 backend.log，再被日志收集一并带走，等于又多了一份明文口令副本。
    # 要拿初始口令就去读那个文件，读完改完它会自己删掉。
    logger.info(f"[auth] 初始管理员账号已创建：用户名 {DEFAULT_ADMIN_USERNAME}，"
                f"初始口令见 {pw_path}，首次登录后请立即修改")


@router.post("/login")
def login(data: LoginData, request: Request, db: Session = Depends(get_db)):
    # 兜底：正常情况 admin 在启动时就已由 lifespan 建好，这里是"上次启动建号失败
    # （库锁 / 权限）"时的补偿，admin 已存在时是空操作。
    seed_admin(db)
    user = db.query(User).filter(User.username == data.username).first()
    ip = _client_ip(request)

    # ① 登录失败锁定：先查锁定窗口，再验口令。锁定期间即使口令正确也拒绝，
    # 否则"边撞库边重试"永远不会触发锁定。
    try:
        from services import security_policy
    except Exception:  # noqa: BLE001
        security_policy = None  # type: ignore
    # 注意：这里**故意不区分"账号不存在"**，无论 user 是否为 None 都照常走
    # 下面的口令校验流程，返回一模一样的 401。否则"账号不存在"和"口令错"
    # 两种响应不同，就成了免费的用户名枚举器。
    if security_policy is not None:
        left = security_policy.lock_remaining(data.username, ip)
        if left > 0:
            minutes = max(1, (left + 59) // 60)
            log_operation(
                db, category="login", action="login_locked", level="warning",
                username=data.username, ip_address=ip, status="failed",
                message=f"用户 {data.username}（来源 {ip}）登录失败：连续失败次数过多，已锁定（剩余约 {minutes} 分钟）",
            )
            # 2026-09-22 P1-7：锁定的响应与"口令错误"**完全一致**（同 401 同文案）。
            # 原实现返回 429 + "连续登录失败次数过多"，据此可枚举用户名
            # 存在的账号被撞够了才 429，不存在的永远 401。锁定信息只在审计日志里留。
            raise HTTPException(status_code=401, detail="用户名或密码错误")

    if not user or not verify_pw(data.password, user.password):
        if security_policy is not None:
            # 用户名维度：只对**存在**的账号计数（不存在的用户名不建 key，
            # 否则用任意字符串当用户名就能撑爆内存表）；
            # IP 维度：总是计数，挡"同一 IP 撞一堆用户名"的横向撞库。
            security_policy.register_failure(data.username if user is not None else None, ip)
        log_operation(
            db,
            category="login",
            action="login_failed",
            level="warning",
            status="failed",
            username=data.username,
            ip_address=ip,
            message=f"用户 {data.username} 登录失败：用户名或密码错误",
        )
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    if security_policy is not None:
        security_policy.clear_failures(data.username, ip)

    if security_policy is not None and security_policy.account_expired(user):
        log_operation(
            db, category="login", action="login_failed", level="warning",
            status="failed",
            username=data.username, user_id=user.id, ip_address=ip,
            message=f"用户 {data.username} 登录失败：账号已过有效期",
        )
        raise HTTPException(status_code=403, detail="账号已过有效期，请联系管理员")

    if user.status != "active":
        log_operation(
            db,
            category="login",
            action="login_failed",
            level="warning",
            status="failed",
            username=data.username,
            user_id=user.id,
            ip_address=ip,
            message=f"用户 {data.username} 登录失败：账号已被禁用",
        )
        raise HTTPException(status_code=403, detail="账号已被禁用")
    # 老的无盐 sha256 口令在这里静默升级（不改密码、用户无感）
    _rehash_if_needed(user, data.password, db)

    # ③ 首登强制改密 / 口令到期：都通过 must_reset_password 表达，前端已有强制改密流程
    first_login = user.last_login_at is None
    if security_policy is not None:
        policy = security_policy.get_policy()
        if first_login and int(policy.get("force_reset_first_login", 0)):
            user.must_reset_password = 1
        if security_policy.password_expired(user, policy):
            user.must_reset_password = 1
    try:
        user.last_login_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as exc:  # noqa: BLE001 记时间失败不影响登录
        logger.warning(f"[auth] 记录登录时间失败（用户 {user.username}）：{exc}")
        db.rollback()

    from models import Role
    role = None
    if getattr(user, "role_id", None):
        role = db.query(Role).filter(Role.id == user.role_id).first()
    if role is None:
        role = db.query(Role).filter(Role.code == (user.role or "viewer")).first()
    token = create_token(
        user.id,
        role.code if role else (user.role or "viewer"),
        role.id if role else None,
        bool(role.is_admin) if role else False,
        ip,
    )
    log_operation(
        db,
        category="login",
        action="login",
        level="info",
        username=user.username,
        user_id=user.id,
        ip_address=ip,
        message=f"用户 {user.username} 登录系统",
    )
    return {
        "token": token,
        "username": user.username,
        "full_name": user.full_name or "",
        "role": role.code if role else (user.role or "viewer"),
        "role_id": role.id if role else None,
        "role_name": role.name if role else "",
        "is_admin": bool(role.is_admin) if role else False,
        "status": user.status,
        "must_reset_password": int(user.must_reset_password or 0),
    }


@router.post("/logout")
def logout(request: Request, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    # 待改密的账号也必须能退出（否则它连"改完再重新登录"这条路都走不通）
    user = get_current_user_full(authorization, db, enforce_password_reset=False)
    ip = _client_ip(request)
    if user:
        log_operation(
            db,
            category="login",
            action="logout",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=ip,
            message=f"用户 {user.get('username', '')} 退出登录",
        )
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        TOKENS.pop(token, None)
    # 主动登出同样要吊销该账号的 WEB 代理票据（上面 pop 只影响本进程内存里的
    # 登录令牌，管不到已经写进 URL 发出去的票据）
    if user:
        try:
            from services import web_proxy_ticket
            web_proxy_ticket.bump_epoch(user.get("user_id"))
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"[auth] 登出时吊销 WEB 代理票据失败：{exc}")
    return {"message": "已退出登录"}


class ChangePasswordIn(BaseModel):
    old_password: str = Field(..., description="当前口令")
    new_password: str = Field(..., description="新口令")


# 2026-09-23 开源加固 ②：这个接口是「首登强制改密」能成立的**前提**。
# 之前系统里根本没有自助改密入口，用户只能求管理员在「用户管理」里代改；
# 而 seed 出来的 admin 就是唯一的管理员，一旦服务端强制改密，新装用户会被
# 彻底锁死。所以强制与自助入口必须同一批上线。
@router.post("/change-password")
def change_password(
    data: ChangePasswordIn,
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    # 豁免强制改密检查，本接口就是用来解除那个状态的
    user = get_current_user_full(authorization, db, enforce_password_reset=False)
    if not user or not user.get("user_id"):
        raise HTTPException(
            status_code=401,
            detail="未登录或会话已失效，请重新登录",
            headers={"WWW-Authenticate": "Bearer"},
        )
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="账号不存在或已被删除")
    if db_user.status and db_user.status != "active":
        raise HTTPException(status_code=403, detail="账号已被禁用，无法修改口令")
    if not verify_pw(data.old_password, db_user.password):
        ip = _client_ip(request)
        log_operation(
            db,
            category="user",
            action="change_password_failed",
            level="warning",
            status="failed",
            username=db_user.username,
            user_id=db_user.id,
            ip_address=ip,
            message=f"用户 {db_user.username} 修改口令失败：原口令不正确",
        )
        raise HTTPException(status_code=400, detail="原口令不正确")
    if data.new_password == data.old_password:
        raise HTTPException(status_code=400, detail="新口令不能与当前口令相同")
    ok, why = _check_password_policy(data.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail=why)

    db_user.password = hash_pw(data.new_password)
    db_user.password_changed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    had_flag = int(db_user.must_reset_password or 0)
    db_user.must_reset_password = 0
    db.commit()

    # 初始口令文件里是**明文**，改完密必须删掉，留着就是个后门
    if had_flag:
        pw_path = _initial_password_path()
        try:
            if os.path.exists(pw_path):
                os.remove(pw_path)
        except Exception as exc:  # noqa: BLE001
            logger.error(f"[auth] 改密后删除初始口令文件失败，请手工删除 {pw_path}：{exc}")

    log_operation(
        db,
        category="user",
        action="change_password",
        level="info",
        username=db_user.username,
        user_id=db_user.id,
        ip_address=_client_ip(request),
        message=f"用户 {db_user.username} 修改了登录口令",
    )
    return {"message": "口令已修改", "must_reset_password": 0}


@router.get("/session")
def get_session(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = get_current_user(authorization)
    if not user:
        # 区分「被其他设备顶下线」和「未登录 / 已过期」：前端据此给出明确提示，
        # 而不是静默跳回登录页。
        token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
        info = REVOKED.get(token) if token else None
        if info:
            # 单会话被顶下线：只说"账号在别处登录了"，**不回传账号名和登录 IP**
            return {
                "authenticated": False,
                "reason": info.get("reason") or "revoked",
                "message": "该账号已在其他设备登录，当前会话已下线",
            }
        return {"authenticated": False}
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not db_user:
        return {"authenticated": False}
    from models import Role
    role = _load_role(db, user)
    return {
        "authenticated": True,
        "username": db_user.username,
        "full_name": db_user.full_name or "",
        "role": role.code if role else (db_user.role or "viewer"),
        "role_id": role.id if role else None,
        "role_name": role.name if role else "",
        "is_admin": bool(role.is_admin) if role else False,
        "status": db_user.status,
        "must_reset_password": int(db_user.must_reset_password or 0),
        "online": True,
        "online_devices": 1,
        "login_at": user.get("login_at"),
        "login_ip": user.get("login_ip") or "",
    }


# User CRUD (admin only)
@router.get("/users")
def list_users(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    require_admin(authorization)
    from models import Role
    from routes.roles import seed_roles
    seed_roles(db)
    roles = {r.id: r for r in db.query(Role).all()}
    users = db.query(User).order_by(User.id).all()
    out = []
    for u in users:
        role = roles.get(getattr(u, "role_id", None))
        if role is None:
            role = next((r for r in roles.values() if r.code == (u.role or "")), None)
        out.append({
            "id": u.id, "username": u.username, "full_name": u.full_name or "",
            "email": u.email or "",
            "role": role.code if role else (u.role or "viewer"),
            "role_id": role.id if role else None,
            "role_name": role.name if role else "",
            "status": u.status, "created_at": u.created_at.isoformat(),
            "valid_until": _dt_iso(getattr(u, "valid_until", None)),
            "last_login_at": _dt_iso(getattr(u, "last_login_at", None)),
        })
    return out


@router.post("/users")
def create_user(data: UserCreate, request: Request, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    admin = require_admin_full(authorization, db)
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="登录名已存在")
    from models import Role
    from routes.roles import seed_roles
    seed_roles(db)
    role = db.query(Role).filter(Role.id == data.role_id).first() if data.role_id else None
    if role is None:
        role = db.query(Role).filter(Role.code == (data.role or "viewer")).first()
    if role is None:
        raise HTTPException(status_code=400, detail="所选角色不存在")
    ok, why = _check_password_policy(data.password)
    if not ok:
        raise HTTPException(status_code=400, detail=why)
    user = User(username=data.username, full_name=data.full_name or "", password=hash_pw(data.password), email=data.email or "", role=role.code, role_id=role.id, status="active")
    user.valid_until = parse_valid_until(data.valid_until)
    user.password_changed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_operation(
        db,
        category="user",
        action="create",
        username=admin.get("username", ""),
        user_id=admin.get("user_id"),
        ip_address=_client_ip(request),
        target_type="user",
        target_id=str(user.id),
        message=f"管理员 {admin.get('username', '')} 创建用户 {user.username}（角色 {role.name}）",
        details={"username": user.username, "role": role.code, "role_id": role.id, "email": data.email},
    )
    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name or "",
        "email": user.email or "",
        "role": role.code,
        "role_id": role.id,
        "role_name": role.name,
        "status": user.status,
        "message": "User created",
    }


@router.put("/users/{user_id}")
def update_user(user_id: int, data: UserUpdate, request: Request, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    admin = require_admin_full(authorization, db)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    changes = {}
    # 2026-09-24：登录名改为可改（含系统默认用户）。以前一刀切拒绝，导致
    # 部署方拿到内置的 `admin` 只能一直用下去，而这个登录名是公开在源码里的，
    # 不改就等于给爆破者省掉一半工作量。允许改，但要做唯一性校验。
    if data.username is not None:
        new_username = (data.username or "").strip()
        if not new_username:
            raise HTTPException(status_code=400, detail="登录名不能为空")
        if new_username != user.username:
            clash = db.query(User).filter(
                User.username == new_username, User.id != user.id).first()
            if clash:
                raise HTTPException(status_code=400, detail="登录名已存在")
            changes["username"] = {"old": user.username, "new": new_username}
            user.username = new_username
    if data.full_name is not None and data.full_name != user.full_name:
        changes["full_name"] = {"old": user.full_name, "new": data.full_name}
        user.full_name = data.full_name
    if data.password:
        ok, why = _check_password_policy(data.password)
        if not ok:
            raise HTTPException(status_code=400, detail=why)
        changes["password"] = {"old": "******", "new": "******"}
        user.password = hash_pw(data.password)
        user.password_changed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        # Clear the "must reset" flag and remove the on-disk password file
        if user.must_reset_password:
            user.must_reset_password = 0
            pw_path = _initial_password_path()
            try:
                if os.path.exists(pw_path):
                    os.remove(pw_path)
            except Exception as exc:  # noqa: BLE001
                # 删不掉要留痕：这个文件里是明文初始口令，留着就是个后门
                logger.error(f"[auth] 改密后删除初始口令文件失败，请手工删除 {pw_path}：{exc}")
    if (data.role_id is not None or data.role is not None):
        from models import Role
        new_role = db.query(Role).filter(Role.id == data.role_id).first() if data.role_id else None
        if new_role is None and data.role:
            new_role = db.query(Role).filter(Role.code == data.role).first()
        if new_role is not None and new_role.id != user.role_id:
            # 2026-09-24：系统默认用户的管理员角色**服务端强制锁死**。
            # 以前只在前端把下拉框置灰，接口本身不拦，改个请求就能把内置
            # admin 降权，一旦成功就再也进不去后台（没人有管理员权限了）。
            if _is_builtin_admin(user):
                raise HTTPException(
                    status_code=400,
                    detail="系统默认用户的管理员角色不可修改（登录名可以改）")
            changes["role"] = {"old": user.role, "new": new_role.code}
            user.role = new_role.code
            user.role_id = new_role.id
    if data.email is not None and data.email != user.email:
        changes["email"] = {"old": user.email, "new": data.email}
        user.email = data.email
    if "valid_until" in getattr(data, "model_fields_set", set()):
        # 显式传 null/空串 = 改成长期有效；传具体时间 = 设有效期
        new_until = parse_valid_until(data.valid_until)
        old_until = _dt_iso(getattr(user, "valid_until", None))
        if _dt_iso(new_until) != old_until:
            changes["valid_until"] = {"old": old_until or "长期有效", "new": _dt_iso(new_until) or "长期有效"}
            user.valid_until = new_until
    if data.status and data.status != user.status:
        changes["status"] = {"old": user.status, "new": data.status}
        old_status = user.status
        user.status = data.status
    # 2026-09-22 P1-5：口令 / 状态 / 角色**任一**变更 旧会话立刻失效。
    # 修复前只有 create_token（单会话）会踢线，改密、禁用、改角色都不踢，
    # 旧 token 最长还能用 24 小时（security_policy.session_max_hours），
    # 而 token 里存的是**旧角色**，等于"降权/禁用"要等一天才真正生效。
    # reason 沿用 "replaced"：前端只在 reason==='replaced' 时显示被顶下线提示，
    # 换别的值用户会静默掉线、不知道发生了什么。
    if any(k in changes for k in ("password", "status", "role")):
        _revoke_user_tokens(user_id, reason="replaced")
    db.commit()
    if changes:
        log_operation(
            db,
            category="user",
            action="update",
            username=admin.get("username", ""),
            user_id=admin.get("user_id"),
            ip_address=_client_ip(request),
            target_type="user",
            target_id=str(user_id),
            message=f"管理员 {admin.get('username', '')} 更新用户 {user.username}",
            details={"changes": changes},
        )
    return {"message": "User updated"}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    admin = require_admin_full(authorization, db)
    if user_id == 1:
        raise HTTPException(status_code=400, detail="不能删除默认管理员")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    username = user.username
    # 2026-09-22 P1-5：删号也要踢线（修复前删了号，旧 token 还能用到自然过期）
    _revoke_user_tokens(user_id, reason="replaced")
    db.delete(user)
    db.commit()
    log_operation(
        db,
        category="user",
        action="delete",
        username=admin.get("username", ""),
        user_id=admin.get("user_id"),
        ip_address=_client_ip(request),
        target_type="user",
        target_id=str(user_id),
        message=f"管理员 {admin.get('username', '')} 删除用户 {username}",
        details={"deleted_username": username},
    )
    return {"message": "User deleted"}




class PreferencesUpdate(BaseModel):
    sidebar_groups: Optional[list] = Field(None)


@router.get("/preferences")
def get_preferences(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="用户不存在")
    prefs = db_user.preferences or {}
    if isinstance(prefs, str):
        try:
            prefs = json.loads(prefs)
        except Exception:
            prefs = {}
    return {"preferences": prefs}


@router.put("/preferences")
def update_preferences(data: PreferencesUpdate, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="用户不存在")
    prefs = db_user.preferences or {}
    if isinstance(prefs, str):
        try:
            prefs = json.loads(prefs)
        except Exception:
            prefs = {}
    update = data.model_dump(exclude_unset=True) if hasattr(data, "model_dump") else data.dict(exclude_unset=True)
    new_prefs = {**prefs, **update}
    db_user.preferences = new_prefs
    flag_modified(db_user, "preferences")
    db.commit()
    return {"preferences": new_prefs}
