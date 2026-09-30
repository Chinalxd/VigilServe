"""Agent 侧设备身份：node_id + RSA 密钥对 + CSR + 请求签名（安全演进 S1）。

存放位置（走 `paths.CONFIG_DIR`，而不是安装目录）：
    <CONFIG_DIR>/identity/node.key    私钥 PEM（0600）
    <CONFIG_DIR>/identity/node.pub    公钥 PEM
    <CONFIG_DIR>/identity/node.csr    证书签发请求 PEM
    <CONFIG_DIR>/identity/client.crt  服务端签回来的客户端证书 PEM
    <CONFIG_DIR>/identity/meta.json   {node_id, machine_fingerprint, not_after, ...}

为什么放 CONFIG_DIR 而不放安装目录：
    卸载会把安装目录整个删掉 —— 身份跟着没了的话，重装一次就是一台新设备，
    管理员手里那条"已批准的主机"也得重批一遍。

为将来的 Linux / NAS 预留：
    本模块刻意不 import winreg / ctypes，指纹采集走跨平台路径
    （/etc/machine-id → 注册表 MachineGuid → MAC 兜底），拿到以后也只存哈希。

 `canonical_string()` 必须与 `backend/services/agent_identity.py` 里的同名函数
   **逐字节一致**，否则签名永远验不过。`.workbuddy/tools/t_s1_identity.py` 钉住这点。
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import secrets
import socket
import time

try:
    from paths import CONFIG_DIR
except Exception:  # noqa: BLE001 （单文件调试 / 单元测试环境）
    CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))

IDENTITY_DIR = os.path.join(CONFIG_DIR, "identity")
KEY_PATH = os.path.join(IDENTITY_DIR, "node.key")
PUB_PATH = os.path.join(IDENTITY_DIR, "node.pub")
CSR_PATH = os.path.join(IDENTITY_DIR, "node.csr")
CERT_PATH = os.path.join(IDENTITY_DIR, "client.crt")
META_PATH = os.path.join(IDENTITY_DIR, "meta.json")

KEY_SIZE = 2048
RENEW_AHEAD_DAYS = 30


def _crypto():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID

    return {
        "x509": x509, "hashes": hashes, "serialization": serialization,
        "padding": padding, "rsa": rsa, "NameOID": NameOID,
    }


def _ensure_dir() -> None:
    os.makedirs(IDENTITY_DIR, exist_ok=True)


def _write_private(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001 （Windows 上多半无效，忽略）
        pass



def new_node_id() -> str:
    return "vnode-" + secrets.token_hex(8)



def ensure_keypair() -> str:
    """没有密钥对就生成一把并落盘；返回私钥 PEM。"""
    _ensure_dir()
    if os.path.isfile(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read().decode("utf-8")
    c = _crypto()
    key = c["rsa"].generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    priv = key.private_bytes(c["serialization"].Encoding.PEM,
                             c["serialization"].PrivateFormat.PKCS8,
                             c["serialization"].NoEncryption())
    pub = key.public_key().public_bytes(c["serialization"].Encoding.PEM,
                                        c["serialization"].PublicFormat.SubjectPublicKeyInfo)
    _write_private(KEY_PATH, priv)
    with open(PUB_PATH, "wb") as f:
        f.write(pub)
    return priv.decode("utf-8")


def load_private_key():
    """读私钥；没有就先生成。"""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    pem = ensure_keypair()
    return load_pem_private_key(pem.encode("utf-8"), password=None)


def public_key_pem() -> str:
    """本机公钥 PEM —— 方案 A 里这就是**设备身份本身**，送给服务端登记。

    私钥永远不出本机（`node.key`），服务端只存这把公钥，之后每次请求用它验签。
    """
    ensure_keypair()
    if os.path.isfile(PUB_PATH):
        try:
            with open(PUB_PATH, "rb") as f:
                return f.read().decode("utf-8")
        except Exception:  # noqa: BLE001
            pass
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return load_private_key().public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")


def build_csr(node_id: str, hostname: str = ""):
    """（兼容保留）生成 CSR。

    1.1.51 方案 A 起身份改用**裸公钥**登记（`public_key_pem()`），不再需要 CA 签发
    证书。保留这个函数只为了让**老服务端**还能认 —— 老服务端只认 `csr` 字段，
    它自己会从 CSR 里取同一把公钥出来。
    """
    c = _crypto()
    key = load_private_key()
    csr = (
        c["x509"].CertificateSigningRequestBuilder()
        .subject_name(c["x509"].Name([
            c["x509"].NameAttribute(c["NameOID"].COMMON_NAME, node_id[:64]),
            c["x509"].NameAttribute(c["NameOID"].ORGANIZATION_NAME, "VigilServe Agent"),
        ]))
        .add_extension(c["x509"].BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, c["hashes"].SHA256())
    )
    pem = csr.public_bytes(c["serialization"].Encoding.PEM).decode("utf-8")
    _ensure_dir()
    with open(CSR_PATH, "w", encoding="utf-8") as f:
        f.write(pem)
    return pem


# 授权状态（方案 A：不再有"证书"，只有"服务端登记过我的公钥没有"）

def authorized() -> bool:
    """服务端是否已经登记了本机公钥。"""
    return bool((load_meta() or {}).get("authorized"))


def mark_authorized(value: bool = True) -> None:
    """记录授权状态。

    以前这里存的是一张 90 天的证书 + 到期时间，还得判续期、判是不是别家 CA 签的。
    方案 A 下只有一件事要记：服务端认不认这把公钥。
    """
    meta = load_meta()
    meta["authorized"] = bool(value)
    meta["authorized_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    save_meta(meta)


def needs_enroll() -> tuple[bool, str]:
    """是否需要向服务端登记公钥。返回 (是否要, 原因)。

    方案 A 下判据只有一条：**服务端登记过没有**。不再有证书有效期、续期窗口、
    「这张证是不是当前服务端 CA 签的」这些概念 —— 换服务端、重装服务端都不会
    留下"看着有效其实不被认"的僵尸身份。

 这条**只针对客户端身份**（node.key 那把锁）。9998 的**服务器证书**是另一回事：
    它由服务端 CA 签发、由服务端校验，所以仍要同时判有效期和 CA 归属 ——
    见下面 `api_cert_signed_by_current_ca()`。别照着上面这段把那条判据删掉。
    """
    if not authorized():
        return True, "本机尚未被服务端登记公钥"
    return False, ""

# Agent 9998 API 的服务器证书（P1-1：反向通道全链路 TLS）
# 与上面的客户端证书（node.key / client.crt，Agent 向服务端证明身份）是**两把锁**
# 这里是服务端调用本机 9998 时校验对端用的服务器证书，由服务端 CA 签发。
# 这 6 个常量曾经被一次改动**连带删掉**（它们原本就贴在 `needs_enroll()` 下面），
# 而所有调用点都包在 `except Exception: pass`（"申请失败不影响主流程"）里，
# 于是整条 9998 证书申领/续签链路**静默失效**，只在服务端表现为
API_TLS_DIR = os.path.join(CONFIG_DIR, "api_tls")
API_KEY_PATH = os.path.join(API_TLS_DIR, "server.key")
API_CSR_PATH = os.path.join(API_TLS_DIR, "server.csr")
API_CERT_PATH = os.path.join(API_TLS_DIR, "server.crt")
API_SELF_CERT = os.path.join(API_TLS_DIR, "self-signed.crt")
API_SELF_KEY = os.path.join(API_TLS_DIR, "self-signed.key")


def _api_tls_ensure_dir() -> None:
    os.makedirs(API_TLS_DIR, exist_ok=True)


def build_api_csr(node_id: str) -> str:
    """生成 9998 服务器证书的 CSR（独立密钥对，CN=node_id）。

    服务端据此签发服务器证书 —— 私钥永远不出本机，CSR 签名即持有证明。
    """
    c = _crypto()
    if os.path.isfile(API_KEY_PATH):
        with open(API_KEY_PATH, "rb") as f:
            pem = f.read().decode("utf-8")
    else:
        key = c["rsa"].generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
        pem = key.private_bytes(c["serialization"].Encoding.PEM,
                                c["serialization"].PrivateFormat.PKCS8,
                                c["serialization"].NoEncryption()).decode("utf-8")
        _api_tls_ensure_dir()
        _write_private(API_KEY_PATH, pem.encode("utf-8"))
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(pem.encode("utf-8"), password=None)
    csr = (
        c["x509"].CertificateSigningRequestBuilder()
        .subject_name(c["x509"].Name([
            c["x509"].NameAttribute(c["NameOID"].COMMON_NAME, node_id[:64]),
            c["x509"].NameAttribute(c["NameOID"].ORGANIZATION_NAME, "VigilServe Agent API"),
        ]))
        .add_extension(c["x509"].BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, c["hashes"].SHA256())
    )
    csr_pem = csr.public_bytes(c["serialization"].Encoding.PEM).decode("utf-8")
    with open(API_CSR_PATH, "w", encoding="utf-8") as f:
        f.write(csr_pem)
    return csr_pem


def save_api_cert(cert_pem: str, not_after: str = "") -> None:
    _api_tls_ensure_dir()
    with open(API_CERT_PATH, "w", encoding="utf-8") as f:
        f.write(cert_pem)


def load_api_cert_pem() -> str:
    if not os.path.isfile(API_CERT_PATH):
        return ""
    try:
        with open(API_CERT_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:  # noqa: BLE001
        return ""


def api_cert_not_after():
    pem = load_api_cert_pem()
    if not pem:
        return None
    try:
        from cryptography import x509
        return x509.load_pem_x509_certificate(pem.encode("utf-8")).not_valid_after_utc
    except Exception:  # noqa: BLE001
        return None


def api_cert_signed_by_current_ca():
    """本地这张 9998 证书是不是**当前信任的服务端 CA** 签的。

    返回 `True` / `False`；**判不出来时返回 `None`**（调用方按"不折腾"处理）。

 为什么必须有这条判据（2026-09-28 现场事故）：
    服务端**重装 / 重建 CA** 之后，本机手里那张证书并没有到期
    （`AGENT_API_DAYS = 365`，签一次能撑一年），只看有效期的 `needs_api_cert()`
    会长期返回 False → `api_csr` 永不上送 → 服务端拿**当前 CA** 校验 9998 必然失败。
    而服务端把这种失败归成 `ConnectionError`，界面上只写
    「无法连接到 Agent {ip}:9998」，完全看不出是证书链不信任 —— 现场就在这里耗了很久。
    同理，`api_server` 的推送升级也走 9998，通道断了连升级包都推不下去。

    CA 取 `tls_util.ca_path()`：TOFU 取回的那把**优先于**随包内置的，
    所以"换了一台服务端"这件事本身就会被这条判据捕获。
    """
    pem = load_api_cert_pem()
    if not pem:
        return False          # 没证书的情况由 needs_api_cert 的"文件不存在"分支管
    try:
        import tls_util as _tls
    except Exception:         # noqa: BLE001 单文件调试 / 单测环境
        return None
    try:
        ca_path = _tls.ca_path()
        if not ca_path or not os.path.isfile(ca_path):
            return None       # 连 CA 都拿不到，判不了，别据此瞎申请
        with open(ca_path, "rb") as f:
            ca_pem = f.read()
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

        ca_cert = x509.load_pem_x509_certificate(ca_pem)
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        if cert.issuer != ca_cert.subject:
            return False
        key = ca_cert.public_key()
        alg = cert.signature_hash_algorithm
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes,
                       padding.PKCS1v15(), alg)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(alg))
        else:
            return None
        return True
    except Exception:         # noqa: BLE001
        return None


def needs_api_cert() -> bool:
    """是否需要向服务端申请 / 续签 9998 服务器证书。"""
    pem = load_api_cert_pem()
    if not pem:
        return True
    # 判据不能只有"到期没有"。服务端重装/重建 CA 后，本地这张证依然"没到期"，
    # 但服务端已经验不过了（9998 全断，界面只写「无法连接到 Agent」）。
    # 所以"是不是当前信任的 CA 签的"必须一起判，见上面函数的注释。
    if api_cert_signed_by_current_ca() is False:
        return True
    na = api_cert_not_after()
    if na is None:
        return True
    left = na - _dt.datetime.now(_dt.timezone.utc)
    return left.total_seconds() <= RENEW_AHEAD_DAYS * 86400


def ensure_self_signed_cert() -> tuple[str, str]:
    """没有服务端签发的证书时，本地自签一张兜底（保证 9998 始终 HTTPS）。

    自签证书服务端不认（CA 链校验失败），但通道是加密的；等 register/enroll
    拿回正式证书后会自动热切换（见 api_server.reload_tls_if_updated）。
    返回 (cert_path, key_path)。
    """
    if os.path.isfile(API_SELF_CERT) and os.path.isfile(API_SELF_KEY):
        return API_SELF_CERT, API_SELF_KEY
    c = _crypto()
    key = c["rsa"].generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    now = _dt.datetime.now(_dt.timezone.utc)
    subject = c["x509"].Name([
        c["x509"].NameAttribute(c["NameOID"].COMMON_NAME, "VigilServeAgent-local"),
        c["x509"].NameAttribute(c["NameOID"].ORGANIZATION_NAME, "VigilServe Agent"),
    ])
    try:
        import ipaddress as _ipa
        sans = [c["x509"].DNSName("localhost"), c["x509"].IPAddress(_ipa.ip_address("127.0.0.1"))]
    except Exception:  # noqa: BLE001
        sans = [c["x509"].DNSName("localhost")]
    cert = (
        c["x509"].CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(c["x509"].random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=3650))
        .add_extension(c["x509"].SubjectAlternativeName(sans), critical=False)
        .add_extension(c["x509"].BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, c["hashes"].SHA256())
    )
    _api_tls_ensure_dir()
    _write_private(API_SELF_KEY, key.private_bytes(
        c["serialization"].Encoding.PEM, c["serialization"].PrivateFormat.PKCS8,
        c["serialization"].NoEncryption()))
    with open(API_SELF_CERT, "wb") as f:
        f.write(cert.public_bytes(c["serialization"].Encoding.PEM))
    return API_SELF_CERT, API_SELF_KEY



def load_meta() -> dict:
    if not os.path.isfile(META_PATH):
        return {}
    try:
        with open(META_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def save_meta(meta: dict) -> None:
    _ensure_dir()
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


def ensure_node_id() -> str:
    """拿 node_id（没有就生成并持久化），顺带把密钥对也准备好。"""
    ensure_keypair()
    meta = load_meta()
    nid = (meta.get("node_id") or "").strip()
    if not nid:
        nid = new_node_id()
        meta["node_id"] = nid
        save_meta(meta)
    return nid


# 采集原始值而不存储：**服务端只保存 sha256**，将来做 L2 漂移检测时够用，

def machine_fingerprint() -> dict:
    """尽最大努力采集机器稳定特征；采不到就退化成 hostname（由服务端容忍）。

    S3：`board`（主板序列号）是这一版新加的分量。评估文档 §3.3 明确指出
    machine-id 在克隆 / sysprep 镜像上会重复，单独一条不足以判身份漂移，
    必须和主板序列号、主网卡 MAC 一起看。
    """
    info: dict = {"host": _hostname()}
    mid = _machine_id()
    if mid:
        info["mid"] = mid
    board = _board_serial()
    if board:
        info["board"] = board
    mac = _primary_mac()
    if mac:
        info["mac"] = mac
    return info


def fingerprint_parts() -> dict:
    """分项指纹 —— 服务端按分量比对才能做 L1/L2/L3 分级。

    `host` 保持明文：主机名本来就在注册 / 心跳里明文上报，再哈希一次纯属自欺。
    `mid` / `board` / `mac` 只留哈希前 16 位：序列号和 MAC 属于不该到处明文落库的
    信息，服务端只需要能判断「这一项变了没有」。

    采不到的分量留空字符串，服务端会把空值当「未采集」跳过比对 —— 否则一台
    采不到主板序列号的虚拟机会永远在报漂移。
    """
    raw = machine_fingerprint()
    parts: dict = {"host": str(raw.get("host") or "")}
    for k in ("mid", "board", "mac"):
        v = str(raw.get(k) or "").strip()
        parts[k] = hashlib.sha256(v.encode("utf-8")).hexdigest()[:16] if v else ""
    return parts


def _hostname() -> str:
    try:
        return socket.gethostname() or ""
    except Exception:  # noqa: BLE001
        return ""


def _machine_id() -> str:
    """Linux/NAS：`/etc/machine-id`；Windows：注册表 MachineGuid。

 评估里提醒过：克隆 / sysprep 出来的镜像 machine-id 会重复，
    所以它单独一条不足以判断身份漂移，必须与公钥指纹一起看。
    """
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            if os.path.isfile(p):
                v = open(p, "r", encoding="utf-8").read().strip()
                if v:
                    return v
        except Exception:  # noqa: BLE001
            pass
    try:  # pragma: no cover （Windows 分支）
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as k:
            v, _ = winreg.QueryValueEx(k, "MachineGuid")
            return str(v or "")
    except Exception:  # noqa: BLE001
        return ""


def _primary_mac() -> str:
    try:
        import uuid
        v = uuid.getnode()
        if v and (v >> 40) % 2 == 0:
            return uuid.UUID(int=v).hex[-12:]
    except Exception:  # noqa: BLE001
        pass
    return ""


def _board_serial() -> str:
    """主板序列号。

 很多虚拟机 / 云主机 / 容器这一项读出来是 "None" / "To be filled by O.E.M."
    这类占位值，必须当成「没采到」丢掉，否则所有虚拟机会共享同一个"序列号"，
    L2 判据反而失效（评估文档 §3.3 提醒的正是这类重复值问题）。

    采集顺序（全部带超时，绝不让采集卡住心跳）：
      Linux/NAS：/sys/class/dmi/id/board_serial（最常见，且不需要 root）
      Windows  ：PowerShell CIM Win32_BaseBoard（wmic 在新系统上已弃用）
    """
    _PLACEHOLDERS = {
        "", "none", "null", "n/a", "na", "0", "-", "unknown", "default string",
        "to be filled by o.e.m.", "to be filled by o.e.m", "not specified",
        "0000000000", "1234567890",
    }

    def _clean(v: str) -> str:
        v = (v or "").strip()
        return "" if v.lower() in _PLACEHOLDERS else v

    for p in ("/sys/class/dmi/id/board_serial", "/sys/class/dmi/id/product_serial"):
        try:
            if os.path.isfile(p):
                v = _clean(open(p, "r", encoding="utf-8", errors="ignore").read())
                if v:
                    return v
        except Exception:  # noqa: BLE001
            pass

    try:  # pragma: no cover
        import subprocess
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Get-CimInstance Win32_BaseBoard -ErrorAction Stop).SerialNumber"],
            capture_output=True, text=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return _clean((out.stdout or "").strip())
    except Exception:  # noqa: BLE001
        return ""


def fingerprint_hash(info: dict) -> str:
    raw = "|".join(f"{k}={info.get(k, '')}" for k in sorted(info))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()



def canonical_string(method: str, path: str, node_id: str, ts: str, nonce: str) -> str:
    """被签名的规范串 —— 与服务端 `agent_identity.canonical_string` 必须一致。"""
    return "\n".join([
        (method or "").upper(),
        path or "",
        node_id or "",
        str(ts or ""),
        nonce or "",
    ])


def now_ts() -> int:
    return int(time.time())


def new_nonce() -> str:
    return secrets.token_hex(8)


def sign_headers(method: str, path: str, node_id: str) -> dict:
    """给一次请求生成身份头。"""
    c = _crypto()
    key = load_private_key()
    ts = str(now_ts())
    nonce = new_nonce()
    msg = canonical_string(method, path, node_id, ts, nonce).encode("utf-8")
    sig = key.sign(msg, c["padding"].PSS(mgf=c["padding"].MGF1(c["hashes"].SHA256()),
                                         salt_length=c["padding"].PSS.DIGEST_LENGTH),
                   c["hashes"].SHA256())
    return {
        "X-VS-Node": node_id,
        "X-VS-Ts": ts,
        "X-VS-Nonce": nonce,
        "X-VS-Sig": base64.b64encode(sig).decode("ascii"),
    }


def short_summary() -> dict:
    """给 UI / 日志用的一句话身份摘要。

    方案 A 之后**客户端证书已经不存在**了，所以旧版这里调的 `load_cert_pem()` /
    `cert_not_after()` 会直接 NameError（两个函数已删）。现按新语义重写：
    "有没有证书"→"服务端登记过公钥没有"，并额外给出 9998 服务器证书的
    到期时间与 CA 归属 —— 后者正是"服务端回调连不上"时第一个要看的字段。
    键名保持兼容，不删旧字段。
    """
    nid = ensure_node_id()
    _auth = authorized()
    _api_na = api_cert_not_after()
    return {
        "node_id": nid,
        "has_cert": _auth,          # 兼容旧字段名；语义已是"公钥已被服务端登记"
        "not_after": "",            # 客户端证书已取消（方案 A），不再有到期日
        "authorized": _auth,
        "api_cert_trusted": api_cert_signed_by_current_ca(),
        "api_not_after": _api_na.isoformat() if _api_na else "",
        "identity_dir": IDENTITY_DIR,
    }
