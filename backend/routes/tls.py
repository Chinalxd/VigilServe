"""TLS / 证书管理 API（安全加固阶段 2）。

    GET  /api/tls/status      当前证书状态（是否需要重签、CA 指纹、SAN、到期时间）
    GET  /api/tls/ca.crt      下载本地 CA 证书（PEM）—— 操作员导入浏览器/系统信任库用
    POST /api/tls/regenerate  重新签发服务器证书（管理员；IP/主机名变化后调用）

CA 证书本身是公开信息（它只用于"验签"，不含私钥），因此下载只要求登录、
不要求管理员；但 ca.key 永远不出服务器，也不提供任何下载接口。
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy.orm import Session

from database import get_db
from routes.auth import get_current_user_full, require_admin_full
from services.audit_logger import log_operation
from services import tls as tls_svc

router = APIRouter(prefix="/api/tls", tags=["tls"])


def _user(authorization: Optional[str], db: Session) -> dict:
    u = get_current_user_full(authorization, db)
    if not u:
        raise HTTPException(status_code=401, detail="未登录")
    return u


@router.get("/status")
def tls_status(authorization: Optional[str] = Header(None),
               db: Session = Depends(get_db)):
    _user(authorization, db)
    try:
        return tls_svc.describe()
    except Exception as e:  # noqa: BLE001
        return {"enabled": False, "error": str(e)}


@router.get("/ca.crt")
def download_ca(authorization: Optional[str] = Header(None),
                db: Session = Depends(get_db)):
    # 第二轮复查 R-9：这是内网**信任根**的分发口，导入它等于信任本服务端签出的
    # 所有证书。以前登录即可下载。CA 公钥本身不敏感，但"随手把信任根发出去"
    # 不合适，收紧到管理员。前端没有任何地方调它（纯人工排障用），无兼容风险。
    require_admin_full(authorization, db)
    if not tls_svc.CA_CERT.exists():
        raise HTTPException(status_code=404, detail="本地 CA 尚未生成（服务器未启用 HTTPS）")
    data = tls_svc.CA_CERT.read_bytes()
    return Response(
        content=data,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="vigilserve-ca.crt"'},
    )


@router.post("/regenerate")
def regenerate(request: Request,
               authorization: Optional[str] = Header(None),
               db: Session = Depends(get_db)):
    user = require_admin_full(authorization, db)
    try:
        info = tls_svc.ensure_server_cert(force=True)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"重签失败：{e}")
    log_operation(
        db, category="system", action="update",
        username=user.get("username", ""), user_id=user.get("user_id"),
        ip_address=(request.client.host if request.client else ""),
        target_type="tls", target_id="server_cert",
        message=f"用户 {user.get('username', '')} 重新签发服务器证书（SAN={info.get('sans')}）",
    )
    return {"message": "服务器证书已重签，请重启服务端使其生效", **info}
