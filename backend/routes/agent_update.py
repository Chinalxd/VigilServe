"""Agent auto-update management.

Provides endpoints to push the latest agent installer to managed hosts and
track the upgrade progress. Currently supports the AGENT protocol natively;
WinRM/SSH hosts are flagged so an administrator can update them manually.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
import threading
from datetime import datetime, timezone

import requests
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.orm import Session

from database import SessionLocal, get_db
from models import AgentUpdateTask, Server, AgentKey
from services.audit_logger import log_operation
from services.client_ip import get_client_ip
from routes.auth import (
    get_current_user_full,
    allowed_server_ids,
    require_perm,
    require_login,
    can_manage_server,
)

router = APIRouter(prefix="/api/agent-update", tags=["agent-update"])


def _client_ip(request: Request) -> str:
    """ 2026-09-23 动态审计 D-1：取值规则已统一到 `services/client_ip.py`
    （默认不信任 X-Forwarded-For，只认直连 IP；确实走了反向代理时用
    `VIGILSERVE_TRUSTED_PROXIES` 显式声明代理地址）。这里保留同名薄封装，
    是为了不动本文件里散落的 `ip_address=_client_ip(request)`。"""
    return get_client_ip(request)


DEFAULT_PACKAGE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "agent", "installer", "output"
)


def _extract_version(filename: str) -> str:
    """Extract a version like 1.1.3 from the installer filename."""
    m = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", filename)
    return m.group(0) if m else ""


def _task_to_dict(task: AgentUpdateTask) -> dict:
    return {
        "id": task.id,
        "server_id": task.server_id,
        "server_name": task.server.name if task.server else "",
        "server_ip": task.server.ip_address if task.server else "",
        "server_protocol": task.server.protocol if task.server else "",
        "package_path": task.package_path,
        "target_version": task.target_version,
        "status": task.status,
        "progress": task.progress,
        "stage": task.stage,
        "error": task.error,
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "updated_at": task.updated_at.isoformat() if task.updated_at else None,
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
    }


def _agent_api_port(server: Server) -> int:
    if server.agent_port:
        return server.agent_port
    extra = server.extra_config or {}
    if isinstance(extra, dict):
        try:
            return int(extra.get("agent_api_port") or extra.get("api_port") or 9998)
        except (ValueError, TypeError):
            pass
    return 9998


def _update_task(db: Session, task: AgentUpdateTask, **kwargs) -> None:
    """Update task fields in place and commit."""
    for key, value in kwargs.items():
        setattr(task, key, value)
    task.updated_at = datetime.now(timezone.utc)
    if task.status in ("success", "failed") and not task.completed_at:
        task.completed_at = datetime.now(timezone.utc)
    db.commit()


def _run_agent_update(task_id: int) -> None:
    """Background worker that pushes the installer to an AGENT-protocol host."""
    db = SessionLocal()
    try:
        task = db.query(AgentUpdateTask).filter(AgentUpdateTask.id == task_id).first()
        if not task:
            return
        server = task.server
        if not server:
            _update_task(db, task, status="failed", progress=0, stage="主机不存在", error="关联主机已被删除")
            return

        _update_task(db, task, status="running", progress=5, stage="准备分发安装包")
        package_path = task.package_path
        if not os.path.exists(package_path):
            _update_task(db, task, status="failed", progress=0, stage="安装包不存在",
                         error=f"服务端安装包路径不存在: {package_path}")
            return

        if (server.protocol or "").upper() != "AGENT":
            _update_task(db, task, status="failed", progress=0,
                         stage=f"{server.protocol} 协议暂不支持自动推送",
                         error="请在该主机上手动运行最新安装包，或改用 AGENT 协议")
            return

        port = _agent_api_port(server)
        # version 必须同时放进 **URL query**：Agent 侧 `_handle_update` 用
        # `qs.get("version")`（URL 参数）取值，而 requests 的 `data={"version":...}`
        # 是 multipart 表单字段，只发表单会让 Agent 拿到空版本，签名串变成
        # ":<sha>" 与服务端的 "1.1.53:<sha>" 不符 "签名不匹配（2026-09-22 现场）"。
        agent_url = f"https://{server.ip_address}:{port}/update?version={task.target_version}"
        filename = os.path.basename(package_path)
        # 安全加固阶段 1：Agent 9998 需要 X-Auth-Token
        from services.agent_auth import agent_headers, agent_ca_verify
        _hdrs = agent_headers(server)
        _ca = agent_ca_verify()

        # P1-2（更新包 HMAC 验签）+ 2026-09-23 开源加固 ④
        # 推送的安装包带完整性签名，Agent 侧 fail-closed 校验，防止被篡改/伪造的
        # 包在目标主机静默执行。
        # X-Pkg-Sha256 = 包内容的 hex sha256
        # X-Pkg-Timestamp = 签发时刻（Unix 秒），供 Agent 判断新鲜性
        # X-Pkg-Signature = hmac_sha256(update_key, "{version}:{sha256}:{timestamp}")
        # 密钥**不再复用 token**：token 是 9998 的认证头，每次调用都在网络上跑，
        # 抓一次包就能永久伪造更新包。现在用 `secret_key` 派生的独立 update_key。
        # （Agent 侧同步改造；用户 2026-09-23 拍板：不做双签过渡期。）
        from services.agent_auth import compute_update_key, sign_update_package
        _agent_key = db.query(AgentKey).filter(AgentKey.server_id == server.id).first()
        if not _agent_key or not _agent_key.secret_key:
            _update_task(db, task, status="failed", progress=20,
                         stage="无法构造签名",
                         error="未找到该主机的 AgentKey（secret_key 缺失），无法签名更新包。"
                               "请让该主机重新注册，或改为手动安装。")
            return
        _h = hashlib.sha256()
        with open(package_path, "rb") as f:
            for _chunk in iter(lambda: f.read(1024 * 1024), b""):
                _h.update(_chunk)
        _pkg_sha = _h.hexdigest()
        _pkg_ts = int(time.time())
        _hdrs["X-Pkg-Sha256"] = _pkg_sha
        _hdrs["X-Pkg-Timestamp"] = str(_pkg_ts)
        _hdrs["X-Pkg-Signature"] = sign_update_package(
            compute_update_key(_agent_key.secret_key, server.id),
            task.target_version, _pkg_sha, _pkg_ts,
        )

        _update_task(db, task, progress=20, stage=f"正在上传 {filename} 到 Agent")
        try:
            with open(package_path, "rb") as f:
                resp = requests.post(
                    agent_url,
                    files={"package": (filename, f, "application/octet-stream")},
                    data={"version": task.target_version},
                    headers=_hdrs,
                    verify=_ca,
                    timeout=120,
                )
            status = resp.status_code
            if status >= 400:
                if status == 404:
                    detail = f"Agent ({agent_url}) 返回 404，当前版本不支持自动更新。请先在目标主机手动安装一次最新安装包。"
                else:
                    detail = f"Agent 返回错误 {status}: {resp.text[:200]}"
                _update_task(db, task, status="failed", progress=20,
                             stage="上传异常", error=detail)
                return
            data = resp.json()
        except requests.exceptions.SSLError:
            # 1.1.38：Agent 9998 跑的是自签证书（1.1.51 存量主机已知问题，
            # 客户端证书有效导致从未领取 CA 签发的 9998 证书）。推送通道本身
            # 已坏，无法用推送自愈：目标主机需手动安装一次最新安装包（1.1.53+），
            # 启动后首个心跳自动领证，推送随即恢复。
            _update_task(db, task, status="failed", progress=20,
                         stage="连接 Agent 失败",
                         error=(f"Agent ({agent_url}) 证书校验失败：该主机的 Agent"
                                "（1.1.51 已知问题）尚未领取服务端签发的 9998 证书。"
                                "请在目标主机手动安装一次最新 Agent 安装包（1.1.53+），"
                                "装好后会自动领证，推送通道随即恢复。"))
            return
        except requests.exceptions.ConnectionError as exc:
            err = str(exc)
            if "10053" in err or "10054" in err or "aborted" in err.lower():
                detail = f"Agent ({agent_url}) 可能版本过旧，不支持自动更新。请先在目标主机手动安装一次最新安装包。"
            else:
                detail = f"无法连接到 {agent_url}: {exc}"
            _update_task(db, task, status="failed", progress=20,
                         stage="连接 Agent 失败", error=detail)
            return
        except requests.exceptions.Timeout:
            _update_task(db, task, status="failed", progress=20,
                         stage="上传超时", error="Agent 120 秒内未响应，请检查网络")
            return
        except Exception as exc:
            _update_task(db, task, status="failed", progress=20,
                         stage="上传异常", error=str(exc))
            return

        if not data.get("success"):
            _update_task(db, task, status="failed", progress=50,
                         stage="Agent 处理失败", error=data.get("error") or "未知错误")
            return

        _update_task(db, task, progress=80, stage="安装包已送达，Agent 正在执行升级")

        new_version = data.get("new_version") or task.target_version
        saw_online = False
        last_version = ""
        for attempt in range(1, 31):
            time.sleep(2)
            try:
                status_url = f"https://{server.ip_address}:{port}/status"
                r = requests.get(status_url, timeout=5, headers=_hdrs, verify=_ca)
                if r.status_code == 200:
                    body = r.json()
                    saw_online = True
                    current_version = body.get("agent_version") or body.get("version", "")
                    last_version = current_version
                    if current_version and new_version and current_version == new_version:
                        _update_task(db, task, status="success", progress=100,
                                     stage=f"升级完成，当前版本 {current_version}")
                        return
                    _update_task(db, task, progress=min(95, 80 + attempt),
                                 stage=f"Agent 已重启，等待版本确认 (当前上报: {current_version or '未知'})")
            except Exception:
                _update_task(db, task, progress=min(95, 80 + attempt),
                             stage="等待 Agent 重启并重新注册...")

        # came back, which must be reported as a failure.
        if saw_online:
            if last_version and new_version and last_version == new_version:
                _update_task(db, task, status="success", progress=100,
                             stage=f"升级完成，当前版本 {last_version}")
            else:
                _update_task(db, task, status="failed", progress=80,
                             stage="Agent 已重新上线但版本未变更",
                             error=f"目标版本 {new_version}，但 Agent 重新上线后上报版本为 {last_version or '未知'}，"
                                   f"可能是安装程序权限不足或被杀软拦截。请在目标主机手动以管理员身份运行最新安装包。")
        else:
            _update_task(db, task, status="failed", progress=80,
                         stage="Agent 未重新上线",
                         error=f"安装包已送达并执行，但 {60} 秒内未检测到 Agent 重新上线，请检查目标主机网络/防火墙/进程状态")

    except Exception as exc:
        if task:
            _update_task(db, task, status="failed", progress=0, stage="执行异常", error=str(exc))
    finally:
        db.close()


def _list_packages() -> list[dict]:
    """Return available installer packages on the server."""
    pkg_dir = DEFAULT_PACKAGE_DIR
    if not os.path.isdir(pkg_dir):
        return []
    packages = []
    for fn in sorted(os.listdir(pkg_dir), reverse=True):
        if not fn.lower().endswith(".exe"):
            continue
        path = os.path.join(pkg_dir, fn)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        version = _extract_version(fn)
        packages.append({
            "filename": fn,
            "path": path,
            "version": version,
            "size": size,
            "size_mb": round(size / (1024 * 1024), 1),
        })
    return packages


@router.get("/packages")
def list_packages(authorization: str = Header(None), db: Session = Depends(get_db)):
    """Return available agent installer packages on the server."""
    require_login(authorization, db)
    return {"packages": _list_packages(), "directory": DEFAULT_PACKAGE_DIR}


@router.get("/servers")
def list_managed_servers(authorization: str = Header(None), db: Session = Depends(get_db)):
    """Return managed servers with their current agent version.

    按当前用户所属角色的「管理主机」列表收敛：未加入列表的主机一律不返回。
    """
    servers = db.query(Server).filter(
        Server.protocol == "agent",
        Server.status.in_(("online", "monitored", "offline", "warning", "critical")),
    ).all()
    # 第三轮审计 N-5（2026-09-23）：原来是 `if not user: return []`，
    # 数据确实没给（安全失败，这点没问题），但**状态码是 200**，前端 `res.ok`
    # 为真，会话过期后会显示"没有可升级的主机"而不是跳登录页。
    # 改成 `require_login` 直接 401，与同文件 `/packages` 的写法统一。
    user = require_login(authorization, db)
    allowed = set(allowed_server_ids(db, user, [s.id for s in servers]))
    servers = [s for s in servers if s.id in allowed]
    result = []
    for s in servers:
        extra = s.extra_config or {}
        result.append({
            "id": s.id,
            "name": s.name,
            "ip_address": s.ip_address,
            "protocol": s.protocol or "SSH",
            "status": s.status or "unknown",
            "os_type": s.os_type or "",
            "agent_version": extra.get("agent_version") or "unknown",
            "install_path": s.install_path or "",
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
        })
    return result


@router.post("/tasks")
def create_update_task(
    data: dict,
    request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Create update tasks for the selected servers and run them in background."""
    user = get_current_user_full(authorization, db)
    require_perm(
        db, user, "sys", "agent_update", "edit", "update",
        detail="无权限执行 Agent 一键更新",
    )
    server_ids = data.get("server_ids", [])
    package_path = data.get("package_path", "")

    # 主机范围双闸门：只允许对本角色可管理的主机下发更新
    all_ids = [s.id for s in db.query(Server).all()]
    allowed = set(allowed_server_ids(db, user, all_ids))
    cleaned_ids = []
    for sid in server_ids:
        try:
            sid_int = int(sid)
        except (TypeError, ValueError):
            continue
        if sid_int in allowed and sid_int not in cleaned_ids:
            cleaned_ids.append(sid_int)
    server_ids = cleaned_ids

    if not server_ids:
        raise HTTPException(status_code=400, detail="请选择至少一台主机")
    if not package_path or not os.path.exists(package_path):
        raise HTTPException(status_code=400, detail="安装包路径不存在")

    target_version = _extract_version(os.path.basename(package_path))
    tasks = []
    server_names = []
    for sid in server_ids:
        server = db.query(Server).filter(Server.id == sid).first()
        if not server:
            continue
        server_names.append(f"{server.name}({server.ip_address})")
        task = AgentUpdateTask(
            server_id=sid,
            package_path=package_path,
            target_version=target_version,
            status="pending",
            progress=0,
            stage="等待执行",
        )
        db.add(task)
        db.commit()
        db.refresh(task)
        tasks.append(task)
        threading.Thread(target=_run_agent_update, args=(task.id,), daemon=True).start()

    log_operation(
        db,
        category="agent",
        action="push_install",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        ip_address=_client_ip(request),
        target_type="agent",
        target_id=",".join(str(t.id) for t in tasks),
        message=f"用户 {user.get('username', '未知')} 推送 Agent 安装/升级到 {len(tasks)} 台主机",
        details={"target_version": target_version, "package_path": package_path, "servers": server_names},
    )

    return {"tasks": [_task_to_dict(t) for t in tasks], "count": len(tasks)}


@router.get("/tasks")
def list_tasks(limit: int = 100, authorization: str = Header(None),
               db: Session = Depends(get_db)):
    """Return recent update tasks ordered by creation time.

    第二轮复查 R-2：以前只 `require_login` —— 任意一个登录账号就能看到**全部**更新
    任务，里面带着主机 IP、Agent 安装路径、以及升级包在服务器上的绝对路径。
    现在按角色可管理主机收敛（管理员恒通过，行为不变）。
    """
    user = get_current_user_full(authorization, db)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    all_ids = [s.id for s in db.query(Server).all()]
    allowed = set(allowed_server_ids(db, user, all_ids))
    if not allowed:
        return []
    tasks = (
        db.query(AgentUpdateTask)
        .filter(AgentUpdateTask.server_id.in_(allowed))
        .order_by(AgentUpdateTask.created_at.desc())
        .limit(limit)
        .all()
    )
    return [_task_to_dict(t) for t in tasks]


@router.get("/tasks/{task_id}")
def get_task(task_id: int, authorization: str = Header(None),
             db: Session = Depends(get_db)):
    """Return one update task by id.

    第二轮复查 R-2：以前只 `require_login`，而 `task_id` 可以枚举 —— 等于能一条条
    把别的主机的更新任务（IP / 安装路径 / 升级包绝对路径）捞出来。
    现在补主机归属校验，403 语义与下面的 `retry` 接口保持一致。
    """
    user = get_current_user_full(authorization, db)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    task = db.query(AgentUpdateTask).filter(AgentUpdateTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not can_manage_server(db, user, task.server_id):
        raise HTTPException(status_code=403, detail="该主机不在当前角色的管理范围内")
    return _task_to_dict(task)


@router.post("/tasks/{task_id}/retry")
def retry_task(task_id: int, request: Request,
               authorization: str = Header(None),
               db: Session = Depends(get_db)):
    user = get_current_user_full(authorization, db)
    require_perm(
        db, user, "sys", "agent_update", "edit", "retry",
        detail="无权限重试 Agent 更新任务",
    )
    task = db.query(AgentUpdateTask).filter(AgentUpdateTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not can_manage_server(db, user, task.server_id):
        raise HTTPException(status_code=403, detail="该主机不在当前角色的管理范围内")
    task.status = "pending"
    task.progress = 0
    task.stage = "等待执行"
    task.error = ""
    task.completed_at = None
    task.updated_at = datetime.now(timezone.utc)
    db.commit()
    threading.Thread(target=_run_agent_update, args=(task.id,), daemon=True).start()
    return _task_to_dict(task)
