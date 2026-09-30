"""自签 CA 与服务器证书（安全加固阶段 2：全链路 HTTPS）。

思路（MeshCentral 同款）：
  - VigilServe 服务端自己生成一个本地 CA（10 年）与一张服务器证书（3 年）；
  - 服务器证书的 SAN 覆盖：主机名、localhost、127.0.0.1、本机所有 IPv4，
    以及 `certs/san-extra.txt` 里手工追加的 IP/域名（服务器有多网卡/走 NAT 时用得上）；
  - Agent 安装包内置 `ca.crt`，连接服务器时用它校验（不再是"接受一切"）；
  - 操作员的浏览器首次访问会提示自签证书，导入一次 `ca.crt` 即可永久信任。

所有文件落在 `backend/certs/`：
    ca.crt / ca.key        本地 CA（ca.key 是信任根，务必只留在服务器上）
    server.crt / server.key 服务器证书
    san-extra.txt          追加 SAN（可选，一行一个 IP 或域名）

幂等：证书还在有效期（剩余 > 30 天）且 SAN 覆盖当前主机名/IP 时直接复用。
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import logging
import os
import socket
from pathlib import Path

logger = logging.getLogger("backend")

CERT_DIR = Path(__file__).resolve().parent.parent / "certs"
CA_CERT = CERT_DIR / "ca.crt"
CA_KEY = CERT_DIR / "ca.key"
SERVER_CERT = CERT_DIR / "server.crt"
SERVER_KEY = CERT_DIR / "server.key"
SAN_EXTRA = CERT_DIR / "san-extra.txt"

CA_CN = "VigilServe Local CA"
CA_DAYS = 3650
SERVER_DAYS = 1095
RENEW_AHEAD_DAYS = 30

_cryptography = None


def _crypto():
    """惰性导入 cryptography（打包环境缺它时由调用方降级为 HTTP）。"""
    global _cryptography
    if _cryptography is None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        _cryptography = {
            "x509": x509, "hashes": hashes, "serialization": serialization,
            "rsa": rsa, "EKU": ExtendedKeyUsageOID, "NameOID": NameOID,
        }
    return _cryptography



def local_ipv4s() -> list[str]:
    """本机所有 IPv4（含通过默认路由探测到的主 IP）。"""
    ips: set[str] = {"127.0.0.1"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
        finally:
            s.close()
    except Exception:  # noqa: BLE001
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:  # noqa: BLE001
        pass
    return sorted(i for i in ips if i and not i.startswith("127.0.0.1")) + ["127.0.0.1"]


def _extra_hosts() -> list[str]:
    if not SAN_EXTRA.exists():
        return []
    try:
        lines = SAN_EXTRA.read_text(encoding="utf-8").splitlines()
    except Exception:  # noqa: BLE001
        return []
    out = []
    for line in lines:
        v = line.split("#", 1)[0].strip()
        if v:
            out.append(v)
    return out


def _hostnames() -> list[str]:
    names = {"localhost"}
    try:
        h = socket.gethostname()
        if h:
            names.add(h)
            names.add(h.split(".")[0])
    except Exception:  # noqa: BLE001
        pass
    for v in _extra_hosts():
        try:
            ipaddress.ip_address(v)
        except ValueError:
            names.add(v)
    return sorted(names)


def _ips() -> list[str]:
    ips = set(local_ipv4s())
    for v in _extra_hosts():
        try:
            ips.add(str(ipaddress.ip_address(v)))
        except ValueError:
            continue
    return sorted(ips)



def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001  （Windows 上多半无效，忽略）
        pass


def _load_or_create_ca():
    c = _crypto()
    x509, rsa, serialization = c["x509"], c["rsa"], c["serialization"]
    if CA_CERT.exists() and CA_KEY.exists():
        try:
            cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
            key = serialization.load_pem_private_key(CA_KEY.read_bytes(), password=None)
            if cert.not_valid_after_utc > _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=RENEW_AHEAD_DAYS):
                return cert, key
            logger.warning("本地 CA 即将过期，重新生成（Agent 安装包需要同步刷新 ca.crt）")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"读取本地 CA 失败，重新生成：{e}")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _dt.datetime.now(_dt.timezone.utc)
    name = x509.Name([
        x509.NameAttribute(c["NameOID"].COMMON_NAME, CA_CN),
        x509.NameAttribute(c["NameOID"].ORGANIZATION_NAME, "VigilServe"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, c["hashes"].SHA256())
    )
    _write_private(CA_KEY, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    _write_private(CA_CERT, cert.public_bytes(serialization.Encoding.PEM))
    logger.info(f"已生成本地 CA：{CA_CERT}")
    return cert, key


def _current_sans() -> list[str]:
    return _hostnames() + _ips()


def _cert_sans(cert) -> list[str]:
    try:
        from cryptography import x509 as _x
        ext = cert.extensions.get_extension_for_class(_x.SubjectAlternativeName)
        return sorted(
            (list(ext.value.get_values_for_type(_x.DNSName))
             + [str(i) for i in ext.value.get_values_for_type(_x.IPAddress)])
        )
    except Exception:  # noqa: BLE001
        return []


def ensure_server_cert(force: bool = False) -> dict:
    """确保证书就绪；返回 {ok, ca_cert, server_cert, server_key, sans, ...}。"""
    c = _crypto()
    x509, rsa, serialization = c["x509"], c["rsa"], c["serialization"]
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    ca_cert, ca_key = _load_or_create_ca()

    want = _current_sans()
    if not force and SERVER_CERT.exists() and SERVER_KEY.exists():
        try:
            cert = x509.load_pem_x509_certificate(SERVER_CERT.read_bytes())
            left = cert.not_valid_after_utc - _dt.datetime.now(_dt.timezone.utc)
            have = set(_cert_sans(cert))
            missing = [s for s in want if s not in have]
            if left > _dt.timedelta(days=RENEW_AHEAD_DAYS) and not missing:
                return {"ok": True, "reused": True, "reason": "",
                        "ca_cert": str(CA_CERT), "server_cert": str(SERVER_CERT),
                        "server_key": str(SERVER_KEY), "sans": sorted(have),
                        "not_after": cert.not_valid_after_utc.isoformat()}
            logger.info(f"服务器证书需重签：剩余 {left.days} 天，缺少 SAN {missing}")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"读取服务器证书失败，重签：{e}")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _dt.datetime.now(_dt.timezone.utc)
    try:
        hostname = socket.gethostname() or "vigilserve"
    except Exception:  # noqa: BLE001
        hostname = "vigilserve"
    subject = x509.Name([
        x509.NameAttribute(c["NameOID"].COMMON_NAME, hostname[:64]),
        x509.NameAttribute(c["NameOID"].ORGANIZATION_NAME, "VigilServe"),
    ])
    san_names = []
    san_ips = []
    for v in want:
        try:
            san_ips.append(ipaddress.ip_address(v))
        except ValueError:
            san_names.append(v)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=SERVER_DAYS))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(n) for n in san_names] + [x509.IPAddress(i) for i in san_ips]),
            critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([c["EKU"].SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, c["hashes"].SHA256())
    )
    _write_private(SERVER_KEY, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    _write_private(SERVER_CERT, cert.public_bytes(serialization.Encoding.PEM))
    logger.info(f"服务器证书已签发：SAN={sorted(want)}")
    return {"ok": True, "reused": False, "reason": "",
            "ca_cert": str(CA_CERT), "server_cert": str(SERVER_CERT),
            "server_key": str(SERVER_KEY), "sans": sorted(want),
            "not_after": cert.not_valid_after_utc.isoformat()}


def tls_enabled() -> bool:
    """环境变量 VIGILSERVE_TLS=0 可显式关闭（仅用于排障）。"""
    return os.environ.get("VIGILSERVE_TLS", "1") != "0"


# ── 客户端证书（设备身份，安全演进 S1）────────────────────────────────
# 上面那段管的是服务器证书（浏览器 / Agent 校验服务端身份）；这里是**另一套**：
# 给每台受管设备签一张客户端证书，身份锚是 node_id + 公钥，**与 IP / 主机名彻底解耦**。
NODE_URN_PREFIX = "urn:vigilserve:node:"
CLIENT_DAYS = 90            # 证书有效期（评估 §2 拍板：不要 lease，90 天 + 自动续期）
CLIENT_RENEW_AHEAD_DAYS = 30


def load_ca():
    """返回 (ca_cert, ca_key)。缺册（全新安装）时自动先建 CA。"""
    return _load_or_create_ca()


def _csr_signature_ok(csr) -> bool:
    """手工验 CSR 签名，避免依赖 `is_signature_valid`（不同版本可用性不一致）。"""
    from cryptography.hazmat.primitives.asymmetric import padding

    try:
        csr.public_key().verify(
            csr.signature, csr.tbs_certrequest_bytes,
            padding.PKCS1v15(), csr.signature_hash_algorithm,
        )
        return True
    except Exception:  # noqa: BLE001
        return False


def cert_issued_by_current_ca(cert_pem: str) -> bool:
    """这张证书是不是**当前本地 CA** 签的。

    🚨 为什么要单独判这一条（2026-09-28 现场事故）：
    `cert_needs_renew()` **只看日期**。服务端重装 / 重建 CA 之后，库里存着的那份
    Agent 9998 证书虽然"还没到期"，却已经不是当前 CA 签的了 —— 原样发回去，Agent 的
    9998 就永久挂在 CA 链校验失败上。服务端侧把这种失败归成 `ConnectionError`，
    界面上只写「无法连接到 Agent {ip}:9998」，看不出是证书问题。
    """
    if not cert_pem:
        return False
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

        ca_cert, _ = load_ca()
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
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
            return False
        return True
    except Exception:  # noqa: BLE001  判不出来一律当作"不归本 CA"，宁可重签
        return False


def sign_client_cert(csr_pem, node_id: str, days: int = CLIENT_DAYS) -> dict:
    """给一台**已通过人工审核**的设备签发客户端证书。

    为什么坚持要 CSR 而不是「扔个公钥过来我就给你签」：
       CSR 是用私钥签过名的，服务端能当场证明「申请者确实持有这把私钥」，
       否则任何人只要知道别人的 node_id 就能骗一张证书把真机挤掉。

    细节（评估 §7 的修正项）：
      - EKU 必须是 **CLIENT_AUTH**（别抄服务器证书的 SERVER_AUTH，语义完全不同）
      - SAN 不塞裸 UUID，统一放进 URN 命名空间，排障时 `openssl x509 -text` 能读
      - notBefore 前拨 24h，容忍两端时钟差
    """
    c = _crypto()
    x509, serialization = c["x509"], c["serialization"]
    ca_cert, ca_key = load_ca()

    raw = csr_pem.encode("utf-8") if isinstance(csr_pem, str) else bytes(csr_pem)
    csr = x509.load_pem_x509_csr(raw)
    if not _csr_signature_ok(csr):
        raise ValueError("CSR 签名无效：对方不持有这把私钥")

    now = _dt.datetime.now(_dt.timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(c["NameOID"].COMMON_NAME, (NODE_URN_PREFIX + node_id)[:64]),
        x509.NameAttribute(c["NameOID"].ORGANIZATION_NAME, "VigilServe Agent"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(
            [x509.UniformResourceIdentifier(NODE_URN_PREFIX + node_id)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([c["EKU"].CLIENT_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, c["hashes"].SHA256())
    )
    return {
        "ok": True,
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "fingerprint": cert.fingerprint(c["hashes"].SHA256()).hex(),
    }


def cert_needs_renew(not_after) -> bool:
    """证书是否该续了（剩余不足 `CLIENT_RENEW_AHEAD_DAYS` 天就算该续）。

    传 None 也返回 True —— 压根没证，当然要签一张。
    """
    if not_after is None:
        return True
    if not_after.tzinfo is None:
        import datetime as _dt2
        not_after = not_after.replace(tzinfo=_dt2.timezone.utc)
    left = not_after - _dt.datetime.now(_dt.timezone.utc)
    return left.total_seconds() <= CLIENT_RENEW_AHEAD_DAYS * 86400


# ── Agent 9998 服务器证书（P1-1：反向通道全链路 TLS）─────────────────
# 上面 sign_client_cert 签的是**客户端证书**（Agent → 服务端证明身份）；
# 这里签的是 Agent 本地 9998 API 的**服务器证书**（服务端 → Agent 校验对端），
AGENT_API_DAYS = 365


def sign_agent_server_cert(csr_pem, node_id: str, agent_ip: str = "",
                           days: int = AGENT_API_DAYS) -> dict:
    """给 Agent 的 9998 API 签一张服务器证书（服务端凭 CA 校验它）。

    信任级别与 register 时下发的 HMAC token 一致（注册不设人工审核，
    所以这里同样不设 —— 防伪靠 CSR 私钥持有证明 + 服务端调用时的 CA 链校验）。
    """
    c = _crypto()
    x509, serialization = c["x509"], c["serialization"]
    ca_cert, ca_key = load_ca()

    raw = csr_pem.encode("utf-8") if isinstance(csr_pem, str) else bytes(csr_pem)
    csr = x509.load_pem_x509_csr(raw)
    if not _csr_signature_ok(csr):
        raise ValueError("CSR 签名无效：对方不持有这把私钥")

    now = _dt.datetime.now(_dt.timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(c["NameOID"].COMMON_NAME, (NODE_URN_PREFIX + node_id)[:64]),
        x509.NameAttribute(c["NameOID"].ORGANIZATION_NAME, "VigilServe Agent API"),
    ])
    sans = [x509.UniformResourceIdentifier(NODE_URN_PREFIX + node_id)]
    if agent_ip:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(agent_ip)))
        except ValueError:
            pass
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([c["EKU"].SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, c["hashes"].SHA256())
    )
    return {
        "ok": True,
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "serial": format(cert.serial_number, "x"),
        "not_after": cert.not_valid_after_utc,
        "fingerprint": cert.fingerprint(c["hashes"].SHA256()).hex(),
    }


def verify_client_cert(cert_pem, expected_node_id: str = "") -> dict:
    """校验证书链 + 有效期 + EKU，并取回 node_id。

    注意这里是**应用层校验**（`verify_directly_issued_by`），不是 TLS 握手层：
    因为 uvicorn 无法把对端证书暴露给 FastAPI，而 8001 还同时服务浏览器 UI，
    真做 mTLS 要么浏览器被锁在门外（CERT_REQUIRED），要么等于零验证（OPTIONAL）。
    """
    c = _crypto()
    x509 = c["x509"]
    ca_cert, _ = load_ca()
    raw = cert_pem.encode("utf-8") if isinstance(cert_pem, str) else bytes(cert_pem)
    cert = x509.load_pem_x509_certificate(raw)
    now = _dt.datetime.now(_dt.timezone.utc)

    try:
        cert.verify_directly_issued_by(ca_cert)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"不是本服务 CA 签出的证书：{e}")

    if cert.not_valid_before_utc > now:
        raise ValueError(f"证书尚未生效：notBefore={cert.not_valid_before_utc.isoformat()}")
    if cert.not_valid_after_utc < now:
        raise ValueError(f"证书已过期：notAfter={cert.not_valid_after_utc.isoformat()}")

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if c["EKU"].CLIENT_AUTH not in eku:
            raise ValueError(f"缺少 clientAuth 用途：{[str(o) for o in eku]}")
    except ValueError:
        raise
    except Exception:  # noqa: BLE001
        raise ValueError("读取 EKU 失败")

    node_id = ""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
            if uri.startswith(NODE_URN_PREFIX):
                node_id = uri[len(NODE_URN_PREFIX):]
                break
    except Exception:  # noqa: BLE001
        node_id = ""

    if expected_node_id and node_id != expected_node_id:
        raise ValueError(f"证书 node_id 不符：期望 {expected_node_id}，实际 {node_id or '(空)'}")

    return {
        "ok": True,
        "node_id": node_id,
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "serial": format(cert.serial_number, "x"),
        "fingerprint": cert.fingerprint(c["hashes"].SHA256()).hex(),
    }


def describe() -> dict:
    """状态摘要（给 /api/tls/status 与启动日志用）。"""
    c = _crypto()
    info: dict = {"enabled": tls_enabled(), "cert_dir": str(CERT_DIR),
                  "ca_exists": CA_CERT.exists(), "server_exists": SERVER_CERT.exists(),
                  "sans": [], "not_after": "", "ca_fingerprint": ""}
    if CA_CERT.exists():
        try:
            cert = c["x509"].load_pem_x509_certificate(CA_CERT.read_bytes())
            fp = cert.fingerprint(c["hashes"].SHA256()).hex()
            info["ca_fingerprint"] = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)).upper()
            info["ca_not_after"] = cert.not_valid_after_utc.isoformat()
        except Exception:  # noqa: BLE001
            pass
    if SERVER_CERT.exists():
        try:
            cert = c["x509"].load_pem_x509_certificate(SERVER_CERT.read_bytes())
            info["sans"] = _cert_sans(cert)
            info["not_after"] = cert.not_valid_after_utc.isoformat()
            info["subject"] = cert.subject.rfc4514_string()
        except Exception:  # noqa: BLE001
            pass
    return info
