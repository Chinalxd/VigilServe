"""File explorer API — remote file browser (Windows + Linux)."""
import os, shutil, sys, stat, zipfile, io
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Request, Header
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy.orm import Session
from urllib.parse import quote
import requests as _requests

from database import get_db
from models import Server
from services.audit_logger import log_operation
from services.client_ip import get_client_ip
from routes.auth import get_current_user_full, can_manage_server, require_perm

def _require_login(authorization: str = Header(None), db: Session = Depends(get_db)):
    """安全加固阶段 3：文件管理路由的**路由级**登录门禁。

    这个模块以前只有写操作（`_require_admin`）校验了身份，所有**读**接口
    （列目录、下载、读取文件内容）都不校验 —— 未登录者只要知道 server_id
    就能列出并下载被监控服务器上的任意文件，属于可直接拿下主机的危急漏洞。
    放在 router 依赖里，新增端点自动生效，不会再漏。
    """
    if not _current_user(authorization, db):
        raise HTTPException(status_code=401, detail="未登录")


def _require_server_access(server_id: int, authorization: str = Header(None),
                           db: Session = Depends(get_db)):
    """安全加固（P1-3）：文件管理路由的**主机级** RBAC 门禁。

    修复前本模块所有读接口（列目录/下载/读文件）只验登录、不验主机归属，
    任何已登录的低权限用户只要遍历 server_id 就能读取全部被监控主机的
    任意文件 —— 越权读等同于拿下主机。本依赖放在 router 级，所有
    `/{server_id}/...` 端点自动生效；与 /ws/terminal 的校验口径一致。
    """
    user = get_current_user_full(authorization, db)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    if not can_manage_server(db, user, server_id):
        raise HTTPException(status_code=403, detail="该主机不在当前角色的管理范围内")


def _require_resources_view(authorization: str = Header(None),
                            db: Session = Depends(get_db)):
    """「资源管理」**页面可见**门禁（第二轮复查 R-13）。

    放在 router 依赖里，本模块所有端点自动生效 —— 包括列目录与取盘符这两个
    以前只验"登录 + 主机归属"、没验页面权限的读接口（只勾了别的页签的角色
    照样能列被监控主机的目录）。
    """
    user = get_current_user_full(authorization, db)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    require_perm(db, user, "host", "resources", "view", detail="无权限查看资源管理")


router = APIRouter(prefix="/api/servers", tags=["file-explorer"],
                   dependencies=[Depends(_require_login), Depends(_require_server_access),
                                 Depends(_require_resources_view)])


def _client_ip(request: Request) -> str:
    """⚠ 2026-09-23 动态审计 D-1：取值规则已统一到 `services/client_ip.py`
    （默认不信任 X-Forwarded-For，只认直连 IP；确实走了反向代理时用
    `VIGILSERVE_TRUSTED_PROXIES` 显式声明代理地址）。这里保留同名薄封装，
    是为了不动本文件里散落的 `ip_address=_client_ip(request)`。"""
    return get_client_ip(request)


def _current_user(authorization, db: Session):
    return get_current_user_full(authorization, db)


MAX_UPLOAD = 500 * 1024 * 1024
# multipart 的边界/头部开销，判断 Content-Length 时留出来，免得刚好卡线的文件被误拒
_UPLOAD_SLACK = 64 * 1024
_UPLOAD_CHUNK = 1024 * 1024
_UPLOAD_MB = MAX_UPLOAD // (1024 * 1024)


def _enforce_upload_limit(request: Optional[Request], size: int) -> None:
    """累计写入超过上限就报 413。

    🚨 以前这里是 `f.write(await file.read(MAX_UPLOAD))` —— `read(n)` 只保证**最多**
    读 n 字节，超出的部分被**静默丢弃**：客户端认为上传成功，落地的文件其实被截断
    了。现在改成边读边计数，超限直接拒绝，不留半个坏文件。
    """
    if size > MAX_UPLOAD:
        mb = size / (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"文件超过 {_UPLOAD_MB} MB 上限（约 {mb:.1f} MB），已中止上传",
        )


def _reject_oversized_request(request: Optional[Request]) -> None:
    """能在读正文之前拒绝的就别往下读（Content-Length 已声明且明显超限）。"""
    if request is None:
        return
    raw = request.headers.get("content-length")
    if raw and raw.isdigit() and int(raw) > MAX_UPLOAD + _UPLOAD_SLACK:
        raise HTTPException(
            status_code=413,
            detail=f"文件超过 {_UPLOAD_MB} MB 上限，服务端未接收",
        )

_cache: dict[str, tuple[float, any]] = {}

def _cache_get(key: str, ttl: float = 5.0):
    import time
    now = time.time()
    if key in _cache:
        ts, val = _cache[key]
        if now - ts < ttl:
            return val
        del _cache[key]
    return None


# agents are never blocked by a lingering keep-alive socket.
_PROXY_SESSION = _requests.Session()
_PROXY_SESSION.trust_env = False
# P1-1：Agent 9998 全链路 TLS —— 用服务端本地 CA 校验 Agent 的服务器证书
try:
    from services.agent_auth import agent_ca_verify as _agent_ca_verify
    _PROXY_SESSION.verify = _agent_ca_verify()
except Exception:  # noqa: BLE001
    pass


def _proxy_to_agent(server_ip: str, port: int, server_id: int, method: str, endpoint: str, **kwargs):
    """Forward a request to the Agent's internal API server."""
    url = f"https://{server_ip}:{port}{endpoint}"
    headers = dict(kwargs.pop("headers", {}) or {})
    headers.setdefault("Connection", "close")
    if not headers.get("X-Auth-Token"):
        try:
            from services.agent_auth import agent_headers_by_ip
            headers.update(agent_headers_by_ip(server_ip, port, server_id=server_id))
        except Exception:  # noqa: BLE001
            pass
    try:
        if method == "GET":
            resp = _PROXY_SESSION.get(url, timeout=30, headers=headers, **kwargs)
        elif method == "POST":
            resp = _PROXY_SESSION.post(url, timeout=30, headers=headers, **kwargs)
        else:
            raise ValueError(f"Unsupported method: {method}")
        return resp
    except _requests.ConnectionError:
        raise HTTPException(status_code=503, detail=f"Agent {server_ip} 文件服务不可达")
    except _requests.Timeout:
        raise HTTPException(status_code=504, detail=f"Agent {server_ip} 响应超时")


def _cache_set(key: str, val, ttl: float = 5.0):
    import time
    _cache[key] = (time.time(), val)


def _cache_invalidate_server(server_id: int):
    """Drop all cached listings for a server after any write operation.

    Called by upload/copy/delete/mkdir/rename (and the new write/create/zip/
    unzip endpoints) so the next list request always reflects the real state
    of the remote host immediately (MeshCentral-style instant sync).
    """
    file_prefix = f"files:{server_id}:"
    drive_key = f"drives:{server_id}"
    for key in [k for k in _cache if k.startswith(file_prefix) or k == drive_key]:
        del _cache[key]


def _get_server(server_id: int, db: Session) -> Server:
    """Get server by ID, 404 if not found."""
    s = db.query(Server).filter(Server.id == server_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    return s


def _try_agent_api(server: Server, endpoint: str, path: str, **kw):
    """Try to call agent's local file API. Falls back to local filesystem for test."""
    ip = server.ip_address
    port = server.agent_port or 9998
    if ip in ('0.0.0.0', '127.0.0.1') or server.protocol != 'agent':
        return None
    try:
        import urllib.request, json
        url = f"https://{ip}:{port}/api/file/{endpoint}"
        import urllib.parse
        url += f"?path={urllib.parse.quote(path)}"
        req = urllib.request.Request(url, method='GET')
        from services.agent_auth import agent_ssl_context as _agent_ssl_ctx
        with urllib.request.urlopen(req, timeout=5, context=_agent_ssl_ctx()) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _is_hidden_or_system(entry) -> bool:
    """Return True for Windows hidden/system files and protected OS directories."""
    if sys.platform != "win32":
        return False
    name = getattr(entry, "name", "")
    if name in ("System Volume Information", "$Recycle.Bin", "pagefile.sys", "swapfile.sys", "hiberfil.sys"):
        return True
    try:
        st = entry.stat()
        if hasattr(st, "st_file_attributes"):
            attrs = st.st_file_attributes
            return bool(attrs & (stat.FILE_ATTRIBUTE_HIDDEN | stat.FILE_ATTRIBUTE_SYSTEM))
    except (OSError, AttributeError):
        pass
    return False


# Paths that must never be deleted, even by administrators. This guards
_PROTECTED_PATHS_WIN = {
    "C:\\",
    "C:\\Windows",
    "C:\\Windows\\System32",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\Users",
}


def _is_protected_path(path: str) -> bool:
    """Return True if the path targets a directory we never want to delete."""
    norm = os.path.normpath(path).rstrip(os.sep).upper()
    if sys.platform == "win32":
        for prot in _PROTECTED_PATHS_WIN:
            if norm == prot.rstrip(os.sep).upper():
                return True
    return False


def _require_file_perm(db: Session, user: dict, op: str, action: str):
    """按**具体操作**校验资源管理权限（第二轮复查 R-13）。

    以前这里是一句 `if not is_admin: 403` —— 非管理员连下载、查看文件内容都做不了，
    「资源管理」页签对非管理员形同虚设（那是 P0-2 把读类抬到管理员留下的副作用）。

    现在改成查 `host/resources` 页的具体操作项（注册表见 `services/rbac.py`）：
        read / rename / copy / mkdir / upload / write / delete
    页面级的 `view` 管"能不能看到"（见下面的 `_require_resources_view`）。

    管理员恒通过（`has_perm` 对 `is_admin` 恒真），所以管理员行为完全不变。
    """
    require_perm(db, user, "host", "resources", "view", op, detail=f"无权限{action}")




def _list_local_dir(path: str, page: int = 1, size: int = 200) -> dict:
    """List directory contents on the local machine with pagination."""
    path = os.path.normpath(path)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")
    if not os.path.isdir(path):
        raise HTTPException(status_code=400, detail=f"Not a directory: {path}")

    from datetime import datetime

    items = []
    total = 0
    try:
        with os.scandir(path) as entries:
            visible_entries = [
                e for e in sorted(entries, key=lambda e: e.name.lower())
                if not _is_hidden_or_system(e)
            ]
            total = len(visible_entries)
            start = (page - 1) * size
            end = start + size
            page_entries = visible_entries[start:end]

            for entry in page_entries:
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    st = entry.stat()
                    item_size = 0 if is_dir else st.st_size
                    mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
                except OSError:
                    is_dir = entry.is_dir()
                    item_size = 0
                    mtime = ""
                items.append({
                    "name": entry.name,
                    "is_dir": is_dir,
                    "size": item_size,
                    "mtime": mtime,
                    "ext": os.path.splitext(entry.name)[1].lower() if not is_dir else "",
                })
    except PermissionError:
        pass

    if sys.platform == "win32":
        drive_root = os.path.splitdrive(path)[0] + "\\"
        is_root = path == drive_root
        parent_dir = os.path.dirname(path)
        parent = parent_dir if (parent_dir != path and path != drive_root) else None
    else:
        parent_dir = os.path.dirname(path)
        parent = parent_dir if parent_dir != path else None

    return {
        "path": path,
        "parent": parent,
        "items": items,
        "total": total,
        "page": page,
        "size": size,
    }


def _get_local_drives() -> list[dict]:
    """List fixed drives/mount-points (cross-platform)."""
    import psutil
    drives = []
    for part in psutil.disk_partitions(all=False):
        opts = (part.opts or '').lower()
        if 'cdrom' in opts:
            continue
        mp = part.mountpoint
        if not mp or not os.path.exists(mp):
            continue

        if sys.platform == "win32":
            letter = mp.rstrip(':\\').rstrip(':')
            if not letter.isalpha():
                continue
            name = f"{letter}:"
            path = f"{letter}:\\"
        else:
            name = mp
            path = mp

        try:
            usage = shutil.disk_usage(mp)
            drives.append({
                "name": name,
                "path": path,
                "fstype": getattr(part, 'fstype', '') or '',
                "total_gb": round(usage.total / (1024**3), 1),
                "used_gb": round(usage.used / (1024**3), 1),
                "free_gb": round(usage.free / (1024**3), 1),
            })
        except (PermissionError, OSError):
            continue
    return drives


@router.get("/{server_id}/drives")
def list_drives(server_id: int, db: Session = Depends(get_db)):
    """List all disk drives on the server."""
    cache_key = f"drives:{server_id}"
    cached = _cache_get(cache_key, ttl=10.0)
    if cached:
        return cached

    server = _get_server(server_id, db)
    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')
    result = None
    if server.ip_address in local_ips or server.protocol != 'agent':
        result = {"drives": _get_local_drives()}
    else:
        try:
            resp = _proxy_to_agent(server.ip_address, server.agent_port, server.id, "GET", "/drives")
            result = resp.json()
        except Exception:
            result = None
        if not result and server.disk_partitions:
            drives = []
            for d in server.disk_partitions:
                drives.append({
                    "name": d.get("name", ""),
                    "path": d.get("mount", d.get("name", "")),
                    "total_gb": d.get("total_gb", 0),
                    "used_gb": d.get("used_gb", 0),
                    "free_gb": d.get("free_gb", 0),
                    "fstype": d.get("fstype", ""),
                })
            result = {"drives": drives}
            result = {"drives": drives}
    if result is None:
        result = {"drives": []}
    _cache_set(cache_key, result)
    return result


@router.get("/{server_id}/files")
def list_files(server_id: int, path: str = Query("C:\\"), page: int = Query(1, ge=1),
               size: int = Query(200, ge=10, le=2000), db: Session = Depends(get_db)):
    """List files in a directory on the server (paginated)."""
    cache_key = f"files:{server_id}:{path.lower()}:full"
    full_result = _cache_get(cache_key, ttl=5.0)
    server = _get_server(server_id, db)
    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')

    if full_result is None:
        if server.ip_address in local_ips or server.protocol != 'agent':
            full_result = _list_local_dir(path, page=1, size=99999)
        else:
            try:
                resp = _proxy_to_agent(server.ip_address, server.agent_port, server.id, "GET", f"/files?path={quote(path)}&page=1&size=99999")
                full_result = resp.json()
            except HTTPException:
                raise
            except Exception:
                full_result = None
            if not full_result:
                raise HTTPException(status_code=503, detail="Agent 文件服务不可达")
        if full_result:
            _cache_set(cache_key, full_result, ttl=5.0)

    if not full_result:
        return {"path": path, "parent": None, "items": [], "total": 0, "page": 1, "size": size}

    all_items = full_result.get("items", [])
    total = len(all_items)
    start = (page - 1) * size
    paged = all_items[start:start + size]

    return {
        "path": full_result.get("path", path),
        "parent": full_result.get("parent"),
        "items": paged,
        "total": total,
        "page": page,
        "size": size,
    }


@router.get("/{server_id}/files/download")
def download_file(
    server_id: int,
    request: Request,
    path: str = Query(...),
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Download a file from the server."""
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "read", "下载文件")
    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')

    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(server.ip_address, server.agent_port, server.id, "GET", f"/files/download?path={quote(path)}")
        log_operation(
            db,
            category="resource",
            action="download",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=_client_ip(request),
            target_type="server",
            target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 从主机 {server.name} 下载文件: {os.path.basename(path)}",
            details={"server_name": server.name, "path": path},
        )
        return StreamingResponse(
            resp.iter_content(chunk_size=65536),
            media_type=resp.headers.get("Content-Type", "application/octet-stream"),
            headers={"Content-Disposition": resp.headers.get("Content-Disposition", "attachment")},
        )

    path = os.path.normpath(path)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found")
    if os.path.isdir(path):
        raise HTTPException(status_code=400, detail="Cannot download directory")
    filename = os.path.basename(path)
    log_operation(
        db,
        category="resource",
        action="download",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        ip_address=_client_ip(request),
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 从主机 {server.name} 下载文件: {filename}",
        details={"server_name": server.name, "path": path, "filename": filename},
    )
    return FileResponse(path, filename=filename, media_type="application/octet-stream")


@router.get("/{server_id}/files/download-multi")
def download_multi(
    server_id: int,
    request: Request,
    paths: str = Query(...),
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Download multiple files/dirs as a single ZIP archive.

    `paths` is a single string with entries separated by `|` (chosen because
    Windows paths often contain spaces and colons). Each entry is URL-decoded
    by FastAPI's query parser.
    """
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "read", "批量下载文件")
    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')

    raw_paths = [p for p in paths.split("|") if p.strip()]
    if not raw_paths:
        raise HTTPException(status_code=400, detail="No files selected")
    if len(raw_paths) > 200:
        raise HTTPException(status_code=400, detail="Too many files selected (max 200)")

    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(server.ip_address, server.agent_port, server.id, "GET", f"/files/download-multi?paths={quote(paths)}")
        log_operation(
            db,
            category="resource",
            action="download-multi",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=_client_ip(request),
            target_type="server",
            target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 从主机 {server.name} 批量下载 {len(raw_paths)} 个文件/目录",
            details={"server_name": server.name, "paths": raw_paths},
        )
        return StreamingResponse(
            resp.iter_content(chunk_size=65536),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=\"download.zip\""},
        )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in raw_paths:
            p = os.path.normpath(p)
            if not os.path.exists(p):
                continue
            if os.path.isdir(p):
                base = os.path.basename(p) or p
                for root, _dirs, files in os.walk(p):
                    for fn in files:
                        full = os.path.join(root, fn)
                        arc = os.path.join(base, os.path.relpath(full, p))
                        try:
                            zf.write(full, arc.replace("\\", "/"))
                        except (PermissionError, OSError):
                            pass
            else:
                arc = os.path.basename(p)
                try:
                    zf.write(p, arc)
                except (PermissionError, OSError):
                    pass

    buf.seek(0)
    log_operation(
        db,
        category="resource",
        action="download-multi",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        ip_address=_client_ip(request),
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 从主机 {server.name} 批量下载 {len(raw_paths)} 个文件/目录",
        details={"server_name": server.name, "paths": raw_paths},
    )
    headers = {
        "Content-Disposition": "attachment; filename=\"download.zip\"",
        "Content-Type": "application/zip",
    }
    return StreamingResponse(buf, headers=headers, media_type="application/zip")


@router.post("/{server_id}/files/upload")
async def upload_file(
    server_id: int,
    request: Request,
    path: str = Query("C:\\"),
    file: UploadFile = File(...),
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Upload a file to the server."""
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "upload", "上传文件")
    _reject_oversized_request(request)
    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')

    if server.ip_address not in local_ips and server.protocol == 'agent':
        content = await file.read(MAX_UPLOAD + 1)
        _enforce_upload_limit(request, len(content))
        resp = _proxy_to_agent(server.ip_address, server.agent_port, server.id, "POST",
            f"/files/upload?path={quote(path)}&filename={quote(file.filename)}",
            data=content,
            headers={"Content-Type": "application/octet-stream"})
        _cache_invalidate_server(server_id)
        log_operation(
            db,
            category="resource",
            action="upload",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=_client_ip(request) if request else "",
            target_type="server",
            target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 上传文件到主机 {server.name}: {file.filename}",
            details={"server_name": server.name, "path": path, "filename": file.filename},
        )
        return _agent_json(resp)

    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Directory not found")
    safe_name = os.path.basename(file.filename or "")
    if not safe_name or safe_name in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")
    dest = os.path.join(path, safe_name)
    written = 0
    try:
        with open(dest, "wb") as f:
            while True:
                chunk = await file.read(_UPLOAD_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                _enforce_upload_limit(request, written)
                f.write(chunk)
    except HTTPException:
        # 超限：删掉写了一半的文件，别在地上留一个坏文件
        try:
            os.remove(dest)
        except OSError:
            pass
        raise
    _cache_invalidate_server(server_id)
    log_operation(
        db,
        category="resource",
        action="upload",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        ip_address=_client_ip(request) if request else "",
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 上传文件到主机 {server.name}: {file.filename}",
        details={"server_name": server.name, "path": path, "filename": file.filename, "dest": dest},
    )
    return {"message": f"Uploaded to {dest}", "filename": safe_name}


def _copy_local(sources: list[str], target: str) -> dict:
    """Copy files/directories locally."""
    target = os.path.normpath(target)
    if not os.path.isdir(target):
        raise HTTPException(status_code=400, detail=f"Target is not a directory: {target}")
    copied = []
    errors = []
    for src in sources:
        src = os.path.normpath(src)
        if not os.path.exists(src):
            errors.append(f"{src}: 不存在")
            continue
        name = os.path.basename(src) or src
        dest = os.path.join(target, name)
        if os.path.exists(dest):
            base, ext = os.path.splitext(name)
            dest = os.path.join(target, f"{base}_副本{ext}")
        try:
            if os.path.isdir(src):
                shutil.copytree(src, dest)
            else:
                shutil.copy2(src, dest)
            copied.append(dest)
        except (PermissionError, OSError) as e:
            errors.append(f"{src}: {e}")
    return {"copied": copied, "errors": errors}


def _delete_local(paths: list[str]) -> dict:
    """Delete files/directories locally."""
    deleted = []
    errors = []
    for p in paths:
        p = os.path.normpath(p)
        if not os.path.exists(p):
            errors.append(f"{p}: 不存在")
            continue
        try:
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
            deleted.append(p)
        except (PermissionError, OSError) as e:
            errors.append(f"{p}: {e}")
    return {"deleted": deleted, "errors": errors}


def _mkdir_local(path: str) -> dict:
    """Create a directory locally."""
    path = os.path.normpath(path)
    if os.path.exists(path):
        return {"created": "", "error": f"已存在: {path}"}
    try:
        os.makedirs(path, exist_ok=False)
        return {"created": path}
    except (PermissionError, OSError) as e:
        return {"created": "", "error": str(e)}


def _rename_local(source: str, target: str) -> dict:
    """Rename/move a file or directory locally."""
    source = os.path.normpath(source)
    target = os.path.normpath(target)
    if not os.path.exists(source):
        return {"renamed": "", "error": f"源文件不存在: {source}"}
    if os.path.exists(target):
        return {"renamed": "", "error": f"目标已存在: {target}"}
    try:
        os.rename(source, target)
        return {"renamed": target}
    except (PermissionError, OSError) as e:
        return {"renamed": "", "error": str(e)}


@router.post("/{server_id}/files/copy")
def copy_files(
    server_id: int,
    request: Request,
    data: dict,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Copy files/directories to a target directory.

    Body: {"sources": ["C:\\src\\a.txt"], "target": "C:\\dest"}
    """
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "copy", "复制文件/目录")
    sources = data.get("sources") or []
    target = data.get("target", "")
    if not sources:
        raise HTTPException(status_code=400, detail="未选择要复制的文件")
    if not target:
        raise HTTPException(status_code=400, detail="未指定目标目录")

    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')
    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(
            server.ip_address, server.agent_port, server.id, "POST",
            "/files/copy",
            json={"sources": sources, "target": target},
        )
        _cache_invalidate_server(server_id)
        log_operation(
            db,
            category="resource",
            action="copy",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=_client_ip(request) if request else "",
            target_type="server",
            target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 复制文件",
            details={"server_name": server.name, "sources": sources, "target": target},
        )
        return _agent_json(resp)

    result = _copy_local(sources, target)
    _cache_invalidate_server(server_id)
    log_operation(
        db,
        category="resource",
        action="copy",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        ip_address=_client_ip(request) if request else "",
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 复制文件",
        details={"server_name": server.name, "sources": sources, "target": target, "result": result},
    )
    return result


@router.post("/{server_id}/files/delete")
def delete_files(
    server_id: int,
    request: Request,
    data: dict,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Delete files/directories.

    Body: {"paths": ["C:\\a.txt", "C:\\b"]}
    """
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "delete", "删除文件/目录")
    paths = data.get("paths") or []
    if not paths:
        raise HTTPException(status_code=400, detail="未选择要删除的文件")

    for p in paths:
        if _is_protected_path(p):
            raise HTTPException(
                status_code=403,
                detail=f"禁止删除系统关键目录: {p}",
            )

    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')
    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(
            server.ip_address, server.agent_port, server.id, "POST",
            "/files/delete",
            json={"paths": paths},
        )
        _cache_invalidate_server(server_id)
        log_operation(
            db,
            category="resource",
            action="delete",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=_client_ip(request) if request else "",
            target_type="server",
            target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 删除文件/目录",
            details={"server_name": server.name, "paths": paths},
        )
        return _agent_json(resp)

    result = _delete_local(paths)
    _cache_invalidate_server(server_id)
    log_operation(
        db,
        category="resource",
        action="delete",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        ip_address=_client_ip(request) if request else "",
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 删除文件/目录",
        details={"server_name": server.name, "paths": paths, "result": result},
    )
    return result


@router.post("/{server_id}/files/mkdir")
def make_directory(
    server_id: int,
    request: Request,
    data: dict,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Create a new directory.

    Body: {"path": "C:\\target\\newfolder"}
    """
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "mkdir", "新建文件夹")
    path = data.get("path", "")
    if not path:
        raise HTTPException(status_code=400, detail="未指定目录路径")

    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')
    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(
            server.ip_address, server.agent_port, server.id, "POST",
            "/files/mkdir",
            json={"path": path},
        )
        _cache_invalidate_server(server_id)
        log_operation(
            db,
            category="resource",
            action="mkdir",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=_client_ip(request) if request else "",
            target_type="server",
            target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 创建目录",
            details={"server_name": server.name, "path": path},
        )
        return _agent_json(resp)

    result = _mkdir_local(path)
    _cache_invalidate_server(server_id)
    log_operation(
        db,
        category="resource",
        action="mkdir",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        ip_address=_client_ip(request) if request else "",
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 创建目录",
        details={"server_name": server.name, "path": path, "result": result},
    )
    return result


@router.post("/{server_id}/files/rename")
def rename_file(
    server_id: int,
    request: Request,
    data: dict,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Rename or move a file/directory.

    Body: {"source": "C:\\target\\old", "target": "C:\\target\\new"}
    """
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "rename", "重命名文件/目录")
    source = data.get("source", "")
    target = data.get("target", "")
    if not source or not target:
        raise HTTPException(status_code=400, detail="源路径和目标路径不能为空")

    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')
    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(
            server.ip_address, server.agent_port, server.id, "POST",
            "/files/rename",
            json={"source": source, "target": target},
        )
        _cache_invalidate_server(server_id)
        log_operation(
            db,
            category="resource",
            action="rename",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=_client_ip(request) if request else "",
            target_type="server",
            target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 重命名文件/目录",
            details={"server_name": server.name, "source": source, "target": target},
        )
        return _agent_json(resp)

    result = _rename_local(source, target)
    _cache_invalidate_server(server_id)
    log_operation(
        db,
        category="resource",
        action="rename",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        ip_address=_client_ip(request) if request else "",
        target_type="server",
        target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 重命名文件/目录",
        details={"server_name": server.name, "source": source, "target": target, "result": result},
    )
    return result



MAX_TEXT_BYTES = 2 * 1024 * 1024


def _agent_json(resp):
    """Parse an agent HTTP response; propagate 4xx/5xx as HTTPException.

    Agent error handlers return {"detail": msg} (sometimes {"error": msg});
    without this the backend would happily answer 200 with an error body and
    the frontend would show a false "success" status.
    """
    try:
        data = resp.json()
    except Exception:
        data = None
    if resp.status_code >= 400:
        detail = ""
        if isinstance(data, dict):
            detail = data.get("detail") or data.get("error") or ""
        raise HTTPException(status_code=resp.status_code, detail=detail or "Agent 操作失败")
    return data if isinstance(data, dict) else {}


def _unique_path(path: str) -> str:
    """Return path with ' (2)', ' (3)'... suffix if it already exists."""
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    i = 2
    while os.path.exists(f"{base} ({i}){ext}"):
        i += 1
    return f"{base} ({i}){ext}"


def _read_local(path: str, max_bytes: int = MAX_TEXT_BYTES) -> dict:
    path = os.path.normpath(path)
    if not os.path.isfile(path):
        return {"path": path, "content": "", "size": 0, "error": f"文件不存在: {path}"}
    size = os.path.getsize(path)
    if size > max_bytes:
        return {"path": path, "content": "", "size": size, "error": "文件超过 2MB，不支持在线编辑"}
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "utf-8", "gbk"):
        try:
            return {"path": path, "content": raw.decode(enc), "size": size}
        except UnicodeDecodeError:
            continue
    return {"path": path, "content": raw.decode("utf-8", errors="replace"), "size": size}


def _write_local(path: str, content: str) -> dict:
    path = os.path.normpath(path)
    try:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        return {"written": path}
    except (PermissionError, OSError) as e:
        return {"written": "", "error": str(e)}


def _create_local(path: str) -> dict:
    path = os.path.normpath(path)
    if os.path.exists(path):
        return {"created": "", "error": f"已存在: {path}"}
    try:
        with open(path, "w", encoding="utf-8") as f:
            pass
        return {"created": path}
    except (PermissionError, OSError) as e:
        return {"created": "", "error": str(e)}


def _zip_local(paths: list[str], target_dir: str, zip_name: str = "") -> dict:
    """Zip selected files/directories into target_dir (auto-dedup name)."""
    if not os.path.isdir(target_dir):
        return {"zip_path": "", "count": 0, "error": f"目标目录不存在: {target_dir}"}
    base = os.path.basename(zip_name or "archive")
    if not base or base in (".", ".."):
        base = "archive"
    if not base.lower().endswith(".zip"):
        base += ".zip"
    dest = _unique_path(os.path.join(target_dir, base))
    count = 0
    try:
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in paths:
                p = os.path.normpath(p)
                if not os.path.exists(p):
                    continue
                if os.path.isdir(p):
                    root_name = os.path.basename(p.rstrip("\\/")) or "folder"
                    for root, _dirs, files in os.walk(p):
                        for fn in files:
                            full = os.path.join(root, fn)
                            arc = os.path.join(root_name, os.path.relpath(full, p))
                            try:
                                zf.write(full, arc.replace("\\", "/"))
                                count += 1
                            except (PermissionError, OSError):
                                pass
                else:
                    try:
                        zf.write(p, os.path.basename(p))
                        count += 1
                    except (PermissionError, OSError):
                        pass
    except (PermissionError, OSError) as e:
        return {"zip_path": "", "count": 0, "error": str(e)}
    return {"zip_path": dest, "count": count}


def _unzip_local(zip_path: str) -> dict:
    """Extract a zip into a sibling folder named after the archive."""
    zip_path = os.path.normpath(zip_path)
    if not os.path.exists(zip_path) or not zipfile.is_zipfile(zip_path):
        return {"dest": "", "error": f"不是有效的 zip 文件: {zip_path}"}
    parent = os.path.dirname(zip_path)
    stem = os.path.splitext(os.path.basename(zip_path))[0]
    dest = _unique_path(os.path.join(parent, stem))
    try:
        os.makedirs(dest, exist_ok=True)
        dest_real = os.path.realpath(dest)
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                target = os.path.realpath(os.path.join(dest, member))
                if not (target == dest_real or target.startswith(dest_real + os.sep)):
                    continue
            zf.extractall(dest)
        return {"dest": dest}
    except (PermissionError, OSError, zipfile.BadZipFile) as e:
        return {"dest": "", "error": str(e)}


@router.get("/{server_id}/files/read")
def read_text_file(
    server_id: int,
    request: Request,
    path: str = Query(...),
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Read a small text file for online editing."""
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "read", "查看文件")
    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')

    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(server.ip_address, server.agent_port, server.id, "GET", f"/files/read?path={quote(path)}")
        result = _agent_json(resp)
        log_operation(
            db, category="resource", action="read",
            username=user.get("username", ""), user_id=user.get("user_id"),
            ip_address=_client_ip(request), target_type="server", target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 在线查看文件: {os.path.basename(path)}",
            details={"server_name": server.name, "path": path},
        )
        return result

    result = _read_local(path)
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    log_operation(
        db, category="resource", action="read",
        username=user.get("username", ""), user_id=user.get("user_id"),
        ip_address=_client_ip(request), target_type="server", target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 在线查看文件: {os.path.basename(path)}",
        details={"server_name": server.name, "path": path},
    )
    return result


@router.post("/{server_id}/files/write")
def write_text_file(
    server_id: int,
    request: Request,
    data: dict,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Save edited text content back to the file."""
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "write", "编辑文件")
    path = data.get("path", "")
    content = data.get("content", "")
    if not path:
        raise HTTPException(status_code=400, detail="未指定文件路径")

    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')
    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(
            server.ip_address, server.agent_port, server.id, "POST",
            "/files/write", json={"path": path, "content": content},
        )
        _cache_invalidate_server(server_id)
        log_operation(
            db, category="resource", action="write",
            username=user.get("username", ""), user_id=user.get("user_id"),
            ip_address=_client_ip(request) if request else "",
            target_type="server", target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 在线编辑保存: {os.path.basename(path)}",
            details={"server_name": server.name, "path": path},
        )
        return _agent_json(resp)

    result = _write_local(path, content)
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    _cache_invalidate_server(server_id)
    log_operation(
        db, category="resource", action="write",
        username=user.get("username", ""), user_id=user.get("user_id"),
        ip_address=_client_ip(request) if request else "",
        target_type="server", target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 在线编辑保存: {os.path.basename(path)}",
        details={"server_name": server.name, "path": path, "result": result},
    )
    return result


@router.post("/{server_id}/files/create")
def create_file(
    server_id: int,
    request: Request,
    data: dict,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Create a new empty file."""
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "write", "新建文件")
    path = data.get("path", "")
    if not path:
        raise HTTPException(status_code=400, detail="未指定文件路径")

    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')
    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(
            server.ip_address, server.agent_port, server.id, "POST",
            "/files/create", json={"path": path},
        )
        _cache_invalidate_server(server_id)
        log_operation(
            db, category="resource", action="create-file",
            username=user.get("username", ""), user_id=user.get("user_id"),
            ip_address=_client_ip(request) if request else "",
            target_type="server", target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 新建文件: {os.path.basename(path)}",
            details={"server_name": server.name, "path": path},
        )
        return _agent_json(resp)

    result = _create_local(path)
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    _cache_invalidate_server(server_id)
    log_operation(
        db, category="resource", action="create-file",
        username=user.get("username", ""), user_id=user.get("user_id"),
        ip_address=_client_ip(request) if request else "",
        target_type="server", target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 新建文件: {os.path.basename(path)}",
        details={"server_name": server.name, "path": path, "result": result},
    )
    return result


@router.post("/{server_id}/files/zip")
def zip_files(
    server_id: int,
    request: Request,
    data: dict,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Zip selected files/directories on the host.

    Body: {"paths": ["C:\\a.txt", "C:\\dir"], "target_dir": "C:\\data", "zip_name": "backup"}
    """
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "read", "压缩文件")
    paths = data.get("paths") or []
    target_dir = data.get("target_dir", "")
    zip_name = data.get("zip_name", "")
    if not paths:
        raise HTTPException(status_code=400, detail="未选择要压缩的文件")
    if not target_dir:
        raise HTTPException(status_code=400, detail="未指定压缩包保存目录")

    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')
    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(
            server.ip_address, server.agent_port, server.id, "POST",
            "/files/zip",
            json={"paths": paths, "target_dir": target_dir, "zip_name": zip_name},
        )
        _cache_invalidate_server(server_id)
        log_operation(
            db, category="resource", action="zip",
            username=user.get("username", ""), user_id=user.get("user_id"),
            ip_address=_client_ip(request) if request else "",
            target_type="server", target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 压缩 {len(paths)} 个文件/目录",
            details={"server_name": server.name, "paths": paths, "target_dir": target_dir},
        )
        return _agent_json(resp)

    result = _zip_local(paths, target_dir, zip_name)
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    _cache_invalidate_server(server_id)
    log_operation(
        db, category="resource", action="zip",
        username=user.get("username", ""), user_id=user.get("user_id"),
        ip_address=_client_ip(request) if request else "",
        target_type="server", target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 压缩 {len(paths)} 个文件/目录",
        details={"server_name": server.name, "paths": paths, "target_dir": target_dir, "result": result},
    )
    return result


@router.post("/{server_id}/files/unzip")
def unzip_file(
    server_id: int,
    request: Request,
    data: dict,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Extract a zip archive into a sibling folder on the host.

    Body: {"path": "C:\\data\\backup.zip"}
    """
    server = _get_server(server_id, db)
    user = _current_user(authorization, db)
    _require_file_perm(db, user, "write", "解压文件")
    path = data.get("path", "")
    if not path:
        raise HTTPException(status_code=400, detail="未指定要解压的文件")

    local_ips = ('0.0.0.0', '127.0.0.1', 'localhost')
    if server.ip_address not in local_ips and server.protocol == 'agent':
        resp = _proxy_to_agent(
            server.ip_address, server.agent_port, server.id, "POST",
            "/files/unzip", json={"path": path},
        )
        _cache_invalidate_server(server_id)
        log_operation(
            db, category="resource", action="unzip",
            username=user.get("username", ""), user_id=user.get("user_id"),
            ip_address=_client_ip(request) if request else "",
            target_type="server", target_id=str(server_id),
            message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 解压文件: {os.path.basename(path)}",
            details={"server_name": server.name, "path": path},
        )
        return _agent_json(resp)

    result = _unzip_local(path)
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    _cache_invalidate_server(server_id)
    log_operation(
        db, category="resource", action="unzip",
        username=user.get("username", ""), user_id=user.get("user_id"),
        ip_address=_client_ip(request) if request else "",
        target_type="server", target_id=str(server_id),
        message=f"用户 {user.get('username', '未知')} 在主机 {server.name} 解压文件: {os.path.basename(path)}",
        details={"server_name": server.name, "path": path, "result": result},
    )
    return result
