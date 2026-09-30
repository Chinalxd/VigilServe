"""角色管理 API：角色 CRUD、权限点清单、可管理主机绑定。"""
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import or_
from sqlalchemy.orm import Session

from database import get_db
from models import GlobalConfig, Role, RoleServer, Server, User
from routes.auth import (
    get_current_user,
    get_current_user_full,
    require_admin_full,
    require_login,
    require_perm,
    log_operation,
    _client_ip,
)
from services import rbac

router = APIRouter(prefix="/api/roles", tags=["roles"])

BUILTIN_ADMIN = "admin"
BUILTIN_VIEWER = "viewer"


class RoleCreate(BaseModel):
    name: str
    code: str
    description: str = ""
    permissions: Optional[dict] = None
    server_ids: Optional[list] = None


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[dict] = None
    server_ids: Optional[list] = None



DEFAULT_ROLES_FLAG = "roles_default_seeded"


def seed_roles(db: Session):
    """角色初始化。

    - 系统管理员：内置角色，始终保证存在，不可删除、不可修改权限
    - 普通用户：仅在默认角色**第一次初始化**时创建；被删除后不再自动重建
      （初始化状态记录在 global_config.roles_default_seeded）
    """
    admin = db.query(Role).filter(Role.code == BUILTIN_ADMIN).first()
    if admin is None:
        admin = Role(
            code=BUILTIN_ADMIN, name="系统管理员", builtin=1, is_admin=1,
            description="拥有全部权限，不可删除、不可修改权限",
            permissions=rbac.full_permissions(),
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)

    # 历史库迁移：「普通用户」取消内置，允许编辑权限与删除
    viewer = db.query(Role).filter(Role.code == BUILTIN_VIEWER).first()
    if viewer is not None and viewer.builtin:
        viewer.builtin = 0
        db.commit()

    migrate_new_permissions(db)

    flag = db.query(GlobalConfig).filter(GlobalConfig.key == DEFAULT_ROLES_FLAG).first()
    if flag is None:
        if viewer is None:
            db.add(Role(
                code=BUILTIN_VIEWER, name="普通用户", builtin=0, is_admin=0,
                description="默认角色，仅可查看，不可操作",
                permissions=rbac.readonly_permissions(),
            ))
        db.add(GlobalConfig(
            key=DEFAULT_ROLES_FLAG, value="1",
            description="默认角色已初始化；「普通用户」角色被删除后不再自动重建",
        ))
        db.commit()


def migrate_new_permissions(db: Session) -> int:
    """把「新增的权限点」补进既有角色的权限表里。

    rbac.normalize() 对缺失项一律按**关闭**处理，所以不写库也不会报错，
    但那样老角色会静默丢掉新页签 / 新操作项。这里按角色既有意图补齐：

    * 管理员角色：全开；
    * 「看得见所有旧主机页签」的只读型角色：新页签也给 view（edit/ops 仍关闭）；
    * 其余角色：保持关闭，由管理员在角色管理里显式勾选。

    幂等：补齐后角色权限里已含该页签，后续启动不会再改。
    """
    updated = 0
    for role in db.query(Role).all():
        raw = role.permissions if isinstance(role.permissions, dict) else {}
        host = raw.get("host") if isinstance(raw.get("host"), dict) else {}
        if role.is_admin:
            wanted = rbac.full_permissions()
            if wanted == rbac.normalize(raw):
                continue
        else:
            missing = [p for p in rbac.page_codes("host") if p not in host]
            missing += [p for p in rbac.page_codes("sys") if p not in (raw.get("sys") or {})]
            if not missing:
                continue
            wanted = rbac.normalize(raw)
            # 只读型：旧页签全部可查看 新页签同样只给查看
            old_host = [p for p in host if p in host]
            see_all = bool(old_host) and all(
                bool((host.get(p) or {}).get("view")) for p in old_host
            )
            if see_all:
                for scope in ("host", "sys"):
                    for p in missing:
                        if p in wanted[scope]:
                            wanted[scope][p]["view"] = True
        role.permissions = wanted
        updated += 1
    if updated:
        db.commit()
    return updated


def resolve_role(db: Session, user: User) -> Optional[Role]:
    """取用户所属角色。没有 role_id 时按旧的 role 字段回退到内置角色。"""
    if getattr(user, "role_id", None):
        role = db.query(Role).filter(Role.id == user.role_id).first()
        if role:
            return role
    legacy = (user.role or "").strip()
    if legacy:
        role = db.query(Role).filter(Role.code == legacy).first()
        if role:
            return role
    return db.query(Role).filter(Role.code == BUILTIN_VIEWER).first()


def _role_out(db: Session, role: Role) -> dict:
    servers = db.query(RoleServer).filter(RoleServer.role_id == role.id).all()
    return {
        "id": role.id,
        "code": role.code,
        "name": role.name,
        "description": role.description or "",
        "builtin": int(role.builtin or 0),
        "is_admin": int(role.is_admin or 0),
        "permissions": rbac.normalize(role.permissions),
        "server_ids": [rs.server_id for rs in servers],
        "user_count": _role_user_count(db, role),
        "created_at": role.created_at.isoformat() if role.created_at else "",
    }


def _role_user_count(db: Session, role: Role) -> int:
    """引用该角色的用户数（role_id 外键 + 旧的 role code 两种引用方式都算）。"""
    return db.query(User).filter(
        or_(User.role_id == role.id, User.role == role.code)
    ).count()



@router.get("/manifest")
def get_manifest(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    """权限点清单（供前端渲染勾选界面）。

    交付审查补漏：以前这个接口**连登录都不验**，匿名就能拿到整套权限点结构
    （等于把"本系统有哪些页面、哪些按钮可授权"直接对外公布，便于针对性构造
    越权请求）。现在要求已登录；权限点清单本身不含任何主机/用户数据，
    所以登录即可读，不必再叠加管理员权限。
    """
    if not get_current_user_full(authorization, db):
        raise HTTPException(status_code=401, detail="未登录")
    return {"scopes": rbac.manifest()}


@router.get("/")
def list_roles(request: Request, db: Session = Depends(get_db)):
    """角色列表。需要「系统设置 - 角色管理」操作权限（系统管理员恒通过）。"""
    # 第三轮审计 N-5（2026-09-23）：原来写的是
    # `get_current_user_full(...) or {}`，未登录时把**空 dict** 交给权限判定，
    # 于是匿名请求得到的是 **403 无权限**，而不是 401 未登录。
    # 数据当然没泄露（`has_perm` 对空 dict 恒 False），但语义错了：前端与
    # 日志都分不清"没权限"和"会话已失效"。改成先 `require_login` 再判权限。
    user = require_login(request.headers.get("authorization"), db)
    require_perm(
        db, user,
        "sys", "settings", "edit", "roles_manage",
        detail="无权限查看角色列表",
    )
    seed_roles(db)
    roles = db.query(Role).order_by(Role.id).all()
    return [_role_out(db, r) for r in roles]


@router.get("/{role_id}")
def get_role(role_id: int, request: Request, db: Session = Depends(get_db)):
    require_perm(
        db, get_current_user_full(request.headers.get("authorization"), db) or {},
        "sys", "settings", "edit", "roles_manage",
        detail="无权限查看角色详情",
    )
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="角色不存在")
    return _role_out(db, role)



@router.post("/")
def create_role(data: RoleCreate, request: Request, db: Session = Depends(get_db)):
    admin = require_admin_full(request.headers.get("authorization"), db)
    name = (data.name or "").strip()
    code = (data.code or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="角色名称为必填项")
    if not code:
        raise HTTPException(status_code=400, detail="角色标识为必填项")
    if db.query(Role).filter(Role.code == code).first():
        raise HTTPException(status_code=400, detail="角色标识已存在")
    if db.query(Role).filter(Role.name == name).first():
        raise HTTPException(status_code=400, detail="角色名称已存在")

    role = Role(
        code=code, name=name, description=data.description or "",
        builtin=0, is_admin=0,
        permissions=rbac.normalize(data.permissions if data.permissions is not None else rbac.empty_permissions()),
    )
    db.add(role)
    db.commit()
    db.refresh(role)
    _set_servers(db, role, data.server_ids or [])
    db.commit()
    log_operation(
        db, category="role", action="create",
        username=admin.get("username", ""), user_id=admin.get("user_id"),
        ip_address=_client_ip(request), target_type="role", target_id=str(role.id),
        message=f"管理员 {admin.get('username', '')} 创建角色 {role.name}",
        details={"code": role.code},
    )
    return _role_out(db, role)



@router.put("/{role_id}")
def update_role(role_id: int, data: RoleUpdate, request: Request, db: Session = Depends(get_db)):
    admin = require_admin_full(request.headers.get("authorization"), db)
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="角色不存在")
    if role.builtin and role.code == BUILTIN_ADMIN:
        raise HTTPException(status_code=400, detail="系统管理员角色不可修改")
    if role.builtin and data.permissions is not None:
        raise HTTPException(status_code=400, detail="内置角色的权限不可修改")

    changes = {}
    if data.name is not None and data.name.strip() and data.name.strip() != role.name:
        if db.query(Role).filter(Role.name == data.name.strip(), Role.id != role.id).first():
            raise HTTPException(status_code=400, detail="角色名称已存在")
        changes["name"] = {"old": role.name, "new": data.name.strip()}
        role.name = data.name.strip()
    if data.description is not None and data.description != (role.description or ""):
        changes["description"] = {"old": role.description, "new": data.description}
        role.description = data.description
    if data.permissions is not None:
        changes["permissions"] = "已更新"
        role.permissions = rbac.normalize(data.permissions)
    if data.server_ids is not None:
        changes["server_ids"] = {"new": data.server_ids}
        _set_servers(db, role, data.server_ids)
    db.commit()
    if changes:
        log_operation(
            db, category="role", action="update",
            username=admin.get("username", ""), user_id=admin.get("user_id"),
            ip_address=_client_ip(request), target_type="role", target_id=str(role_id),
            message=f"管理员 {admin.get('username', '')} 更新角色 {role.name}",
            details={"changes": changes},
        )
    return _role_out(db, role)



@router.delete("/{role_id}")
def delete_role(role_id: int, request: Request, db: Session = Depends(get_db)):
    admin = require_admin_full(request.headers.get("authorization"), db)
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="角色不存在")
    if role.builtin:
        raise HTTPException(status_code=400, detail="内置角色不可删除")

    in_use = _role_user_count(db, role)
    if in_use:
        raise HTTPException(status_code=400, detail="该角色已被用户引用，请解除引用后再删除")

    db.query(RoleServer).filter(RoleServer.role_id == role.id).delete()
    db.delete(role)
    db.commit()
    log_operation(
        db, category="role", action="delete",
        username=admin.get("username", ""), user_id=admin.get("user_id"),
        ip_address=_client_ip(request), target_type="role", target_id=str(role_id),
        message=f"管理员 {admin.get('username', '')} 删除角色 {role.name}",
        details={"code": role.code},
    )
    return {"message": "角色已删除"}



@router.get("/me/scope")
def my_scope(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    """返回当前登录用户的角色权限与可管理主机，前端据此控制菜单/页签/按钮。"""
    from routes.auth import get_current_user

    seed_roles(db)
    user = get_current_user(authorization)
    if not user:
        return {"authenticated": False}
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not db_user:
        return {"authenticated": False}
    role = resolve_role(db, db_user)
    if role is None:
        return {"authenticated": False}
    all_ids = [s.id for s in db.query(Server).all()]
    return {
        "authenticated": True,
        "role_id": role.id,
        "role_code": role.code,
        "role_name": role.name,
        "is_admin": bool(role.is_admin),
        "permissions": rbac.normalize(role.permissions),
        # R-13：哪些操作项是「只读」性质、不需要页面 edit 总开关（前端按钮显隐
        # 要按同一套口径算，否则会与后端判定错位）。详见 services/rbac.py。
        "op_no_edit": rbac.ops_without_edit(),
        "server_ids": visible_server_ids(db, role, all_ids),
    }


def _set_servers(db: Session, role: Role, server_ids: list):
    db.query(RoleServer).filter(RoleServer.role_id == role.id).delete()
    for sid in server_ids or []:
        try:
            sid_int = int(sid)
        except (TypeError, ValueError):
            continue
        if not db.query(Server).filter(Server.id == sid_int).first():
            continue
        db.add(RoleServer(role_id=role.id, server_id=sid_int))


def visible_server_ids(db: Session, role: Optional[Role], all_ids: list) -> list:
    """角色可管理的主机 ID。

    严格白名单：管理员 = 全部；其余角色 = 只返回「管理主机」列表里显式添加的主机，
    列表为空则看不到任何主机。
    """
    if role is None:
        return []
    if role.is_admin:
        return list(all_ids)
    return [rs.server_id for rs in db.query(RoleServer).filter(RoleServer.role_id == role.id).all()]
