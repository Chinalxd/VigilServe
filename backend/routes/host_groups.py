"""全局主机分组 API。

分组由管理员在「主机管理 - 分组管理」维护，所有用户共享；
侧边栏「主机列表」只展示分组及其中的主机。

权限：读取需要登录且能看到主机；增删改需要「主机管理」页的编辑权限（sys.register.edit），
且只能把当前角色有权管理的主机加入分组。
"""
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import GlobalConfig, HostGroup, HostGroupMember, Server
from routes.auth import (
    allowed_server_ids,
    get_current_user_full,
    log_operation,
    require_perm,
    _client_ip,
)

router = APIRouter(prefix="/api/host-groups", tags=["host-groups"])


class GroupCreate(BaseModel):
    name: str
    description: str = ""
    server_ids: Optional[list] = None


class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    server_ids: Optional[list] = None


class GroupMove(BaseModel):
    server_ids: list
    target_group_id: int


# 2026-09-17 起按用户要求彻底取消：所有分组一律等同对待，都能重命名、都能删除，
# 不再自动创建「默认分组」，新加入管理的主机留在「未分组」，由用户手动建组拖入。
# 老库里已经存在的同名分组保留为一个普通分组；`default_host_group_id` 配置键
# 只保留读取（用于老数据兼容），删除该分组时会一并清掉，且**不再自动重建**。
DEFAULT_GROUP_KEY = "default_host_group_id"
DEFAULT_GROUP_NAME = "默认分组"
DEFAULT_GROUP_DESC = "系统默认分组：新加入管理的主机自动归入，可编辑但不可删除"


def _default_group_id(db: Session) -> Optional[int]:
    row = db.query(GlobalConfig).filter(GlobalConfig.key == DEFAULT_GROUP_KEY).first()
    if not row:
        return None
    try:
        return int(row.value)
    except (TypeError, ValueError):
        return None


def add_to_default_group(db: Session, server_id: int) -> None:
    """历史钩子：主机加入管理时自动挂到默认分组。

    默认分组机制已取消 —— 这里不再建组、不再挂载，新主机保持「未分组」。
    保留空实现是为了不动 routes/servers.py 的两处调用点。
    """
    return None


def _current_user(authorization: Optional[str], db: Session) -> dict:
    return get_current_user_full(authorization, db) or {}


def _require_group_edit(db: Session, authorization: Optional[str], op: str):
    """分组写操作按操作项鉴权（sys/主机管理分组管理/edit/<op>）。"""
    user = _current_user(authorization, db)
    require_perm(
        db, user, "sys", "host_groups", "edit", op,
        detail={"create": "无权限创建主机分组", "edit": "无权限编辑主机分组",
                "delete": "无权限删除主机分组"}.get(op, "无权限管理主机分组"),
    )
    return user


def _clean_server_ids(db: Session, user: dict, server_ids: list) -> list:
    """只保留当前用户有权管理、且真实存在的主机。"""
    all_ids = [s.id for s in db.query(Server).all()]
    allowed = set(allowed_server_ids(db, user, all_ids))
    out = []
    for sid in server_ids or []:
        try:
            sid_int = int(sid)
        except (TypeError, ValueError):
            continue
        if sid_int in allowed and sid_int not in out:
            out.append(sid_int)
    return out


def _group_out(db: Session, group: HostGroup, default_id: Optional[int] = None) -> dict:
    members = db.query(HostGroupMember).filter(HostGroupMember.group_id == group.id).all()
    if default_id is None:
        default_id = _default_group_id(db)
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description or "",
        "server_ids": [m.server_id for m in members],
        "is_default": group.id == default_id,
        "created_at": group.created_at.isoformat() if group.created_at else "",
    }


@router.get("/")
def list_groups(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    """分组列表。所有登录用户可读；非管理员只能看到自己有权管理的主机。"""
    user = _current_user(authorization, db)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    # 默认分组机制已取消：不再按需创建，只读配置里残留的标记用于老数据兼容
    default_group_id = _default_group_id(db)
    all_ids = [s.id for s in db.query(Server).all()]
    # 自愈：主机被删除后可能留下孤儿成员行，读取时顺手清掉
    orphans = db.query(HostGroupMember).all() if not all_ids else \
        db.query(HostGroupMember).filter(~HostGroupMember.server_id.in_(all_ids)).all()
    if orphans:
        for m in orphans:
            db.delete(m)
        db.commit()
    allowed = set(allowed_server_ids(db, user, all_ids))
    out = []
    for g in db.query(HostGroup).order_by(HostGroup.id).all():
        item = _group_out(db, g, default_group_id)
        item["server_ids"] = [sid for sid in item["server_ids"] if sid in allowed]
        out.append(item)
    out.sort(key=lambda g: (not g["is_default"], g["id"]))
    return out


@router.post("/")
def create_group(data: GroupCreate, request: Request,
                 authorization: Optional[str] = Header(None),
                 db: Session = Depends(get_db)):
    user = _require_group_edit(db, authorization, "create")
    name = (data.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="分组名称为必填项")
    if db.query(HostGroup).filter(HostGroup.name == name).first():
        raise HTTPException(status_code=400, detail="分组名称已存在")
    group = HostGroup(name=name, description=data.description or "")
    db.add(group)
    db.commit()
    db.refresh(group)
    for sid in _clean_server_ids(db, user, data.server_ids or []):
        db.add(HostGroupMember(group_id=group.id, server_id=sid))
    db.commit()
    log_operation(
        db, category="host_group", action="create",
        username=user.get("username", ""), user_id=user.get("user_id"),
        ip_address=_client_ip(request), target_type="host_group", target_id=str(group.id),
        message=f"用户 {user.get('username', '')} 创建主机分组 {group.name}",
        details={"server_ids": data.server_ids or []},
    )
    return _group_out(db, group)


@router.put("/{group_id}")
def update_group(group_id: int, data: GroupUpdate, request: Request,
                 authorization: Optional[str] = Header(None),
                 db: Session = Depends(get_db)):
    user = _require_group_edit(db, authorization, "edit")
    group = db.query(HostGroup).filter(HostGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="分组不存在")

    changes = {}
    if data.name is not None:
        name = data.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="分组名称为必填项")
        if name != group.name:
            if db.query(HostGroup).filter(HostGroup.name == name, HostGroup.id != group.id).first():
                raise HTTPException(status_code=400, detail="分组名称已存在")
            changes["name"] = {"old": group.name, "new": name}
            group.name = name
    if data.description is not None and data.description != (group.description or ""):
        changes["description"] = {"old": group.description, "new": data.description}
        group.description = data.description
    if data.server_ids is not None:
        ids = _clean_server_ids(db, user, data.server_ids)
        db.query(HostGroupMember).filter(HostGroupMember.group_id == group.id).delete()
        for sid in ids:
            db.add(HostGroupMember(group_id=group.id, server_id=sid))
        changes["server_ids"] = {"new": ids}
    db.commit()
    if changes:
        log_operation(
            db, category="host_group", action="update",
            username=user.get("username", ""), user_id=user.get("user_id"),
            ip_address=_client_ip(request), target_type="host_group", target_id=str(group_id),
            message=f"用户 {user.get('username', '')} 更新主机分组 {group.name}",
            details={"changes": changes},
        )
    return _group_out(db, group)


@router.delete("/{group_id}")
def delete_group(group_id: int, request: Request,
                 authorization: Optional[str] = Header(None),
                 db: Session = Depends(get_db)):
    user = _require_group_edit(db, authorization, "delete")
    group = db.query(HostGroup).filter(HostGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="分组不存在")
    member_count = db.query(HostGroupMember).filter(
        HostGroupMember.group_id == group.id).count()
    # 级联清成员：成员行删掉后，这些主机在侧边栏自动回到「未分组」
    db.query(HostGroupMember).filter(HostGroupMember.group_id == group.id).delete()
    db.delete(group)
    # 如果删的正是老机制标记的「默认分组」，连同配置键一起清掉，
    # 避免它后面又被当成默认分组建回来（默认分组机制已废弃）。
    db.query(GlobalConfig).filter(
        GlobalConfig.key == DEFAULT_GROUP_KEY,
        GlobalConfig.value == str(group_id)).delete(synchronize_session=False)
    db.commit()
    log_operation(
        db, category="host_group", action="delete",
        username=user.get("username", ""), user_id=user.get("user_id"),
        ip_address=_client_ip(request), target_type="host_group", target_id=str(group_id),
        message=f"用户 {user.get('username', '')} 删除主机分组 {group.name}（{member_count} 台主机回到未分组）",
    )
    return {"message": "分组已删除", "moved_out": member_count}


@router.post("/{group_id}/move")
def move_hosts(group_id: int, data: GroupMove, request: Request,
               authorization: Optional[str] = Header(None),
               db: Session = Depends(get_db)):
    """把勾选的主机从当前分组「移动」到另一个分组：源分组移除 + 目标分组加入。"""
    user = _require_group_edit(db, authorization, "edit")
    src = db.query(HostGroup).filter(HostGroup.id == group_id).first()
    if not src:
        raise HTTPException(status_code=404, detail="分组不存在")
    dst = db.query(HostGroup).filter(HostGroup.id == data.target_group_id).first()
    if not dst:
        raise HTTPException(status_code=404, detail="目标分组不存在")
    if dst.id == src.id:
        raise HTTPException(status_code=400, detail="目标分组不能是当前分组")
    ids = _clean_server_ids(db, user, data.server_ids or [])
    if not ids:
        raise HTTPException(status_code=400, detail="请先勾选要移动的主机")
    db.query(HostGroupMember).filter(
        HostGroupMember.group_id == src.id,
        HostGroupMember.server_id.in_(ids),
    ).delete(synchronize_session=False)
    in_dst = {m.server_id for m in
              db.query(HostGroupMember).filter(HostGroupMember.group_id == dst.id).all()}
    for sid in ids:
        if sid not in in_dst:
            db.add(HostGroupMember(group_id=dst.id, server_id=sid))
    db.commit()
    log_operation(
        db, category="host_group", action="move",
        username=user.get("username", ""), user_id=user.get("user_id"),
        ip_address=_client_ip(request), target_type="host_group", target_id=str(src.id),
        message=f"用户 {user.get('username', '')} 把 {len(ids)} 台主机从分组 {src.name} 移动到 {dst.name}",
        details={"from": src.name, "to": dst.name, "server_ids": ids},
    )
    return {
        "message": f"已移动 {len(ids)} 台主机到「{dst.name}」",
        "server_ids": ids,
        "source": _group_out(db, src),
        "target": _group_out(db, dst),
    }
