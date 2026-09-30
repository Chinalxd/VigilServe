"""S5：SSH 主机密钥钉扎（防中间人）。

问题
────
`remote_agent.py::_connect_ssh` 原本用的是 `paramiko.WarningPolicy()` —— 只往日志打一行
警告就放行，**不落盘、不比对**。也就是说第一次连谁都信，之后换了一台机器（DNS 劫持 / ARP
欺骗 / IP 漂到别的设备上）也一样连，口令照样送过去。这就是典型的中间人入口。

钉什么、怎么钉
──────────────
* 钉的是**主机出示的 SSH 主机密钥**（不是用户密钥），按 server_id 一行，见 `models.SSHHostKey`。
* 比对必须在**认证之前**完成 —— 认证一旦发生，口令已经交给对面了，再发现密钥不对也晚了。
  所以走 paramiko 的 known_hosts 机制：把已钉扎的公钥塞进 `SSHClient.get_host_keys()`，
  密钥不符时 paramiko 会在 `connect()` 里抛 `SSHException`，此时还没开始认证。
* **双保险**：`connect()` 之后再取一次 `get_remote_server_key()` 比对。正常情况下第一道就拦住了，
  这一道是防止 paramiko 版本行为变化导致漏检 —— 真漏了也绝不会带着错误密钥去跑命令。

首连策略（配置 `ssh_host_key_policy`）
──────────────────────────────────────
* `tofu`（默认）：首次连接记录指纹并放行，同时写一条 info 级提示「已首次钉扎，请复核指纹」。
  选它是因为现有主机从没钉过，切 strict 会让它们全部连不上。
* `strict`：没有预置指纹就直接拒绝，必须管理员先在页面确认该设备的指纹。

密钥变了怎么办
──────────────
**不覆盖旧指纹**（与 S3 漂移分级 L3 一致：留证据）。新观察到的指纹放进 `pending_*`，
置 `status="changed"`，连接**拒绝**，并生成 critical 告警；管理员核对确是设备重装/换密钥后，
调 `repin_host_key()` 才转正。这样「真换了设备」和「被人顶替」在审计里都有据可查。
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone


_KEY_CLASSES = {
    "ssh-rsa": "RSAKey",
    "ssh-dss": "DSSKey",
    "ssh-ed25519": "Ed25519Key",
    "ecdsa-sha2-nistp256": "ECDSAKey",
    "ecdsa-sha2-nistp384": "ECDSAKey",
    "ecdsa-sha2-nistp521": "ECDSAKey",
}


class HostKeyRejected(Exception):
    """主机密钥不符合钉扎记录，连接被拒绝。"""




def fingerprint_of(key) -> str:
    """OpenSSH 风格指纹：`SHA256:<base64 去 padding>`。人工比对看这个。"""
    try:
        raw = key.asbytes()
    except Exception:  # noqa: BLE001
        raw = key.get_base64().encode()
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return "SHA256:" + digest


def key_b64_of(key) -> str:
    try:
        return key.get_base64()
    except Exception:  # noqa: BLE001
        return base64.b64encode(key.asbytes()).decode()


def key_from_record(key_type: str, b64: str):
    """把库里的 (key_type, base64) 重建回 paramiko PKey；失败返回 None。"""
    import paramiko

    cls_name = _KEY_CLASSES.get(str(key_type or "").strip())
    if not cls_name or not b64:
        return None
    cls = getattr(paramiko, cls_name, None)
    if cls is None:
        return None
    try:
        return cls(data=base64.b64decode(b64))
    except Exception:  # noqa: BLE001
        return None


def _host_aliases(host: str, port: int) -> list:
    """paramiko 查 known_hosts 时可能用带端口的名字（非 22 端口），两个都塞进去。"""
    if not port or int(port) == 22:
        return [host]
    return [host, f"[{host}]:{int(port)}"]




def _policy_mode(db) -> str:
    try:
        from models import GlobalConfig

        row = db.query(GlobalConfig).filter(GlobalConfig.key == "ssh_host_key_policy").first()
        if row is not None and str(row.value or "").strip():
            return str(row.value).strip().lower()
    except Exception:  # noqa: BLE001
        pass
    return "tofu"


def _session():
    from database import SessionLocal

    return SessionLocal()




def _load_pin(db, server_id: int):
    from models import SSHHostKey

    return db.query(SSHHostKey).filter(SSHHostKey.server_id == server_id).first()


def prepare_client(client, server, db=None, port: int = None) -> None:
    """在 `client.connect()` 之前调用：装好已知密钥 + 首连策略。

    * 有钉扎记录 → 公钥注入 known_hosts，未命中一律拒绝（RejectPolicy）
    * 无记录     → `tofu` 放行并在 `missing_host_key` 里落库；`strict` 直接拒绝

    `port` 用于网络设备：它的 CLI 端口在 `cli_port` 上（22 以外很常见），
    而钉扎记录是按「主机 : 端口」存的，不传就会拿 `connection_port`（=SNMP 语义）
    去比对，永远对不上。主机侧不传即沿用 `connection_port`。
    """
    import paramiko

    own_db = db is None
    db = db or _session()
    try:
        pin = _load_pin(db, server.id)
        host = server.ip_address
        port = int(port or server.connection_port or 22)

        if pin is not None and pin.public_key_b64 and pin.status == "pinned":
            key = key_from_record(pin.key_type, pin.public_key_b64)
            if key is not None:
                hk = client.get_host_keys()
                for name in _host_aliases(host, port):
                    try:
                        hk.add(name, pin.key_type, key)
                    except Exception:  # noqa: BLE001
                        pass
            # 已钉扎 任何未命中的密钥都不许过（含密钥类型换了的情况）
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(
                _FirstContactPolicy(server.id, host, port, strict=(_policy_mode(db) == "strict"))
            )
    finally:
        if own_db:
            db.close()


class _FirstContactPolicy:
    """paramiko 的 MissingHostKeyPolicy：决定「第一次见这台设备」时怎么办。

    故意不继承 `paramiko.MissingHostKeyPolicy` —— 只需要 duck type 出 `missing_host_key()`，
    继承反而会在 paramiko 版本间带来构造签名差异。
    """

    def __init__(self, server_id: int, host: str, port: int, strict: bool):
        self.server_id = server_id
        self.host = host
        self.port = port
        self.strict = strict

    def missing_host_key(self, client, hostname, key):
        fp = fingerprint_of(key)
        if self.strict:
            raise HostKeyRejected(
                f"主机 {self.host} 没有预置的 SSH 主机密钥指纹（当前策略 strict），拒绝连接。"
                f"如确认是可信设备，请先在主机详情「网络」页签核对并确认指纹：{fp}"
            )
        _record_first_contact(self.server_id, self.host, self.port, key, fp)


def _record_first_contact(server_id: int, host: str, port: int, key, fp: str) -> None:
    from models import Alert, SSHHostKey
    from services.audit_logger import log_operation

    db = _session()
    try:
        now = datetime.now(timezone.utc)
        pin = _load_pin(db, server_id)
        if pin is None:
            pin = SSHHostKey(server_id=server_id, pinned_at=now)
            db.add(pin)
        elif pin.status == "changed":
            db.commit()
            return
        pin.hostname = host
        pin.port = port
        pin.key_type = key.get_name()
        pin.fingerprint = fp
        pin.public_key_b64 = key_b64_of(key)
        pin.status = "pinned"
        pin.pending_key_type = ""
        pin.pending_fingerprint = ""
        pin.pending_public_key_b64 = ""
        pin.pending_first_seen = None
        pin.last_verified_at = now
        if pin.pinned_at is None:
            pin.pinned_at = now
        db.commit()

        from models import Server

        srv = db.query(Server).filter(Server.id == server_id).first()
        db.add(Alert(
            server_id=server_id,
            level="info",
            title=f"已首次钉扎 SSH 主机密钥：{(srv.name if srv else host)}",
            message=(
                f"该主机此前没有 SSH 主机密钥记录，已按 TOFU 策略记录本次指纹并放行：\n"
                f"{key.get_name()} {fp}\n"
                f"请核对它与设备实际指纹一致（如不符，可能是连到了别的设备，"
                f"请在主机详情「网络」页签清除后重新确认）。"
            ),
            metric_type="identity",
        ))
        log_operation(
            db,
            category="identity",
            action="ssh_host_key_pin",
            level="info",
            message=f"主机 {(srv.name if srv else host)} SSH 主机密钥首次钉扎",
            target_type="server",
            target_id=str(server_id),
            details={"key_type": key.get_name(), "fingerprint": fp, "host": host, "port": port},
        )
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
    finally:
        db.close()




def verify_after_connect(server, client, db=None, port: int = None) -> dict:
    """连接建立后复核一次。正常情况第一道就拦住了；这里是兜底。

    不符 → 立刻断开 + 记 pending + critical 告警 + 审计 + 抛 `HostKeyRejected`。
    `port` 语义同 `prepare_client()`。
    """
    own_db = db is None
    db = db or _session()
    try:
        try:
            key = client.get_transport().get_remote_server_key()
        except Exception:  # noqa: BLE001
            return {"state": "unknown"}
        fp = fingerprint_of(key)
        pin = _load_pin(db, server.id)
        now = datetime.now(timezone.utc)

        if pin is None or not pin.fingerprint:
            _record_first_contact(server.id, server.ip_address, int(port or server.connection_port or 22), key, fp)
            return {"state": "pinned", "fingerprint": fp}

        if fp == pin.fingerprint:
            pin.last_verified_at = now
            db.commit()
            return {"state": "pinned", "fingerprint": fp}

        if pin.status != "changed" or pin.pending_fingerprint != fp:
            pin.status = "changed"
            pin.pending_key_type = key.get_name()
            pin.pending_fingerprint = fp
            pin.pending_public_key_b64 = key_b64_of(key)
            pin.pending_first_seen = now
            pin.last_change_at = now
            db.commit()
            _raise_change_alert(server.id, pin.fingerprint, fp)
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
        raise HostKeyRejected(
            f"SSH 主机密钥与钉扎记录不符，已断开连接（疑似中间人或设备已重装）。"
            f"原指纹 {pin.fingerprint} → 现指纹 {fp}。"
            f"确认是设备重装/换密钥后，请在主机详情「网络」页签点「确认新指纹」。"
        )
    finally:
        if own_db:
            db.close()


def note_connect_failure(server, client) -> None:
    """`connect()` 抛错时调用：把「对方出示了什么」记进 pending 并告警。

    paramiko 在认证前拦下不匹配密钥时会抛 `SSHException`，但它不会告诉我们新指纹是什么 ——
    而管理员恰恰最需要这个（「对面现在是 SHA256:xxx」）。这里趁 transport 还在，
    把远端密钥取出来记下，**不抛异常**（外层要按原样 re-raise 原始错误）。
    """
    try:
        t = client.get_transport()
        if t is None:
            return
        key = t.get_remote_server_key()
    except Exception:  # noqa: BLE001
        return
    if key is None:
        return

    db = _session()
    try:
        fp = fingerprint_of(key)
        pin = _load_pin(db, server.id)
        if pin is None or not pin.fingerprint:
            return
        if fp == pin.fingerprint:
            return  # 密钥没问题，是别的原因（口令/网络）
        if pin.status != "changed" or pin.pending_fingerprint != fp:
            now = datetime.now(timezone.utc)
            pin.status = "changed"
            pin.pending_key_type = key.get_name()
            pin.pending_fingerprint = fp
            pin.pending_public_key_b64 = key_b64_of(key)
            pin.pending_first_seen = now
            pin.last_change_at = now
            db.commit()
            _raise_change_alert(server.id, pin.fingerprint, fp)
    except Exception:  # noqa: BLE001
        db.rollback()
    finally:
        db.close()


def _raise_change_alert(server_id: int, old_fp: str, new_fp: str) -> None:
    from models import Alert, Server
    from services.audit_logger import log_operation

    db = _session()
    try:
        srv = db.query(Server).filter(Server.id == server_id).first()
        db.add(Alert(
            server_id=server_id,
            level="critical",
            title=f"SSH 主机密钥变更，连接已拒绝：{(srv.name if srv else server_id)}",
            message=(
                f"该主机出示的 SSH 主机密钥与钉扎记录不一致，为避免中间人攻击，连接已被拒绝：\n"
                f"原指纹：{old_fp}\n现指纹：{new_fp}\n"
                f"若确为设备重装 / 重新生成了主机密钥，请在主机详情「网络」页签点「确认新指纹」；"
                f"否则请立即排查该 IP 是否已被别的设备占用。"
            ),
            metric_type="identity",
        ))
        log_operation(
            db,
            category="identity",
            action="ssh_host_key_changed",
            level="critical",
            status="failed",
            message=f"主机 {(srv.name if srv else server_id)} SSH 主机密钥变更，连接已拒绝",
            target_type="server",
            target_id=str(server_id),
            details={"old_fingerprint": old_fp, "new_fingerprint": new_fp},
        )
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
    finally:
        db.close()




def get_pin(db, server_id: int) -> dict:
    pin = _load_pin(db, server_id)
    if pin is None:
        return {"pinned": False, "status": "none", "policy": _policy_mode(db)}
    return {
        "pinned": True,
        "status": pin.status,
        "hostname": pin.hostname or "",
        "port": pin.port or 22,
        "key_type": pin.key_type or "",
        "fingerprint": pin.fingerprint or "",
        "pinned_at": pin.pinned_at.isoformat() if pin.pinned_at else None,
        "last_verified_at": pin.last_verified_at.isoformat() if pin.last_verified_at else None,
        "last_change_at": pin.last_change_at.isoformat() if pin.last_change_at else None,
        "pending_key_type": pin.pending_key_type or "",
        "pending_fingerprint": pin.pending_fingerprint or "",
        "pending_first_seen": pin.pending_first_seen.isoformat() if pin.pending_first_seen else None,
        "policy": _policy_mode(db),
    }


def repin_host_key(db, server_id: int, fingerprint: str = "") -> dict:
    """把 pending 的新指纹转正（管理员确认设备确实换过密钥）。

    `fingerprint` 为空 = 接受当前 pending；给了值则必须与 pending 一致，防止确认错对象。
    """
    from services.audit_logger import log_operation

    pin = _load_pin(db, server_id)
    if pin is None:
        raise ValueError("该主机没有 SSH 主机密钥记录")
    if not pin.pending_fingerprint:
        raise ValueError("该主机当前没有待确认的新指纹")
    if fingerprint and fingerprint != pin.pending_fingerprint:
        raise ValueError("待确认指纹与传入值不一致")

    old_fp = pin.fingerprint
    pin.key_type = pin.pending_key_type or pin.key_type
    pin.fingerprint = pin.pending_fingerprint
    pin.public_key_b64 = pin.pending_public_key_b64 or pin.public_key_b64
    pin.pending_key_type = ""
    pin.pending_fingerprint = ""
    pin.pending_public_key_b64 = ""
    pin.pending_first_seen = None
    pin.status = "pinned"
    pin.pinned_at = datetime.now(timezone.utc)
    pin.last_verified_at = pin.pinned_at

    from models import Server

    srv = db.query(Server).filter(Server.id == server_id).first()
    log_operation(
        db,
        category="identity",
        action="ssh_host_key_repin",
        level="warning",
        # 「已确认新指纹」是一次成功的操作，warning 表示"身份基线变了、值得留意"。
        status="success",
        message=f"已确认主机 {(srv.name if srv else server_id)} 的新 SSH 主机密钥",
        target_type="server",
        target_id=str(server_id),
        details={"old_fingerprint": old_fp, "new_fingerprint": pin.fingerprint},
    )
    db.commit()
    return get_pin(db, server_id)


def unpin_host_key(db, server_id: int) -> None:
    """清除钉扎记录（下次连接重新走首连流程）。设备重装后常用。"""
    from services.audit_logger import log_operation

    pin = _load_pin(db, server_id)
    if pin is None:
        return
    from models import Server

    srv = db.query(Server).filter(Server.id == server_id).first()
    log_operation(
        db,
        category="identity",
        action="ssh_host_key_unpin",
        level="warning",
        # 「清除钉扎」是一次成功的操作（下次连接会重新走首连流程）。
        status="success",
        message=f"已清除主机 {(srv.name if srv else server_id)} 的 SSH 主机密钥钉扎",
        target_type="server",
        target_id=str(server_id),
        details={"old_fingerprint": pin.fingerprint or ""},
    )
    db.delete(pin)
    db.commit()
