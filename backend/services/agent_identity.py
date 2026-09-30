"""设备身份：node_id + 客户端证书 + HTTP 请求签名（安全演进 S1）。

为什么这套东西长这样，以及为什么它不在 TLS 握手层做 mTLS：

  1. uvicorn 做客户端证书校验时**拿不到对端证书**（ASGI scope 里没有这个字段），
     配了也白配 —— FastAPI 侧读不到 CN/SAN，就无从得知 node_id。
  2. 8001 同时服务浏览器 UI 和 Agent。开 `CERT_REQUIRED` 会把浏览器锁在门外，
     开 `CERT_OPTIONAL` 又等于零验证（谁都可以不带证书连进来）。
  3.     因此：**X.509 证书只做「身份文档」**（可吊销、可续期、`openssl x509 -text`
     可排障），**「私钥持有证明」放在应用层** —— 每个请求用私钥对一个规范串签名，
     服务端拿证书里的公钥验。这一层不依赖 TLS 版本 / 密码套件 / SNI，
     所以用户提的那 6 项兼容性预检全部塌缩成「现有 HTTPS 还通不通」。

速率敏感点：
  RSA-2048 验签约 0.05ms，签一次约 1~2ms。Agent 每 5~60 秒才请求一次，
  完全不构成负担，因此不需要引入"先用证书换一个短期 bearer token"那一层状态。

重放防护：
  时间戳 ±300s + nonce 去重（TTL 600s）。同一 nonce 在窗口内二次出现直接拒。
 2026-09-23 开源加固 ⑦：nonce 已**落库**（`models.AgentNonce`），跨后端重启
    依然有效 —— 以前只在内存里，重启一次就能把截获的合法请求重放进来。
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from typing import Optional

from services import tls as tls_util

logger = logging.getLogger("backend")

NODE_HEADER = "x-vs-node"
TS_HEADER = "x-vs-ts"
NONCE_HEADER = "x-vs-nonce"
SIG_HEADER = "x-vs-sig"

SIGN_SKEW_SEC = 300
NONCE_TTL_SEC = 600
_NONCE_SEEN: dict[str, float] = {}



def new_node_id() -> str:
    """生成全局唯一且**便于人工核对**的设备标识（8 字节随机 hex）。

    刻意不用裸 UUID：
      - 太长，电话里核对念不完；
      - UUID 带版本位，容易被误当成"含时间戳 / 含 MAC"的信息泄露出去。
    """
    return "vnode-" + secrets.token_hex(8)


def node_urn(node_id: str) -> str:
    return tls_util.NODE_URN_PREFIX + node_id


def new_pairing_code() -> str:
    """8 位配对码，格式 `XXXX-XXXX`。

    字母表剔除了 0/O/1/I/L 这些容易念混的字符 —— 它是给**人念给另一个人听**的，
    不是给机器扫的。
    """
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    half = "".join(secrets.choice(alphabet) for _ in range(4))
    half2 = "".join(secrets.choice(alphabet) for _ in range(4))
    return f"{half}-{half2}"


def normalize_pairing_code(value: str) -> str:
    return (value or "").strip().upper().replace(" ", "").replace("-", "")


def fingerprint(value: str) -> str:
    """统一指纹算法：把任意字符串折成 sha256 前缀，便于人工比对。"""
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def pubkey_fingerprint(spki_der: bytes) -> str:
    return hashlib.sha256(spki_der).hexdigest()


# 这个函数的定义必须和 `agent/identity.py::canonical_string()` **逐字节一致**，
# 否则线上会出现"签名永远不过"的诡异故障。`.workbuddy/tools/t_s1_identity.py`

def canonical_string(method: str, path: str, node_id: str, ts: str, nonce: str) -> str:
    """被签名的规范串。

    刻意**不包含 body 哈希**：
      要拿到 raw body 就得把 push/heartbeat/config 改成 `async def`，
      而这三个端点里全是同步 SQLAlchemy —— 放进事件循环会把整个服务端
      在这几百毫秒里堵死（单 worker）。body 的完整性本来由 HTTPS 保证，
      这里签的是「谁 + 哪个端点 + 什么时候 + 一次性随机数」，目的是身份+抗重放。
    """
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


def signature_headers(method: str, path: str, node_id: str, private_key) -> dict:
    """Agent 侧：给一次请求生成签名头。"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    ts = str(now_ts())
    nonce = new_nonce()
    msg = canonical_string(method, path, node_id, ts, nonce).encode("utf-8")
    # 是 `padding.PSS.DIGEST_LENGTH`，不是 `padding.DigestLength`（后者不存在）。
    # 两端必须用同一个 salt 长度，否则验签会随机失败。
    sig = private_key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.DIGEST_LENGTH),
                           hashes.SHA256())
    return {
        "X-VS-Node": node_id,
        "X-VS-Ts": ts,
        "X-VS-Nonce": nonce,
        "X-VS-Sig": base64.b64encode(sig).decode("ascii"),
    }


def _prune_nonces(now: float) -> None:
    """内存层的老 nonce 清理（只作一级缓存，真凭实据在库里）。"""
    if len(_NONCE_SEEN) > 5000:
        for k in [k for k, seen in _NONCE_SEEN.items() if now - seen >= NONCE_TTL_SEC]:
            _NONCE_SEEN.pop(k, None)


# 库层面的清理节流：每 5 分钟最多清一次，不必每个请求都扫表
_LAST_DB_PRUNE: dict = {"at": 0.0}
_DB_PRUNE_INTERVAL = 300


def _prune_nonces_db(db, now: float, own_session: bool = True) -> None:
    if now - _LAST_DB_PRUNE["at"] < _DB_PRUNE_INTERVAL:
        return
    _LAST_DB_PRUNE["at"] = now
    try:
        from models import AgentNonce
        db.query(AgentNonce).filter(AgentNonce.seen_at < now - NONCE_TTL_SEC).delete(
            synchronize_session=False)
        # 与 `check_nonce()` 同一口径：会话是借来的就只 flush，不替调用方提交。
        db.commit() if own_session else db.flush()
    except Exception:  # noqa: BLE001 清理失败不影响本次请求
        db.rollback()


def check_nonce(node_id: str, nonce: str, db=None) -> Optional[str]:
    """返回错误原因，None 表示通过。

 2026-09-23 开源加固 ⑦：nonce **落库**（以前只在进程内存里）。

    不改的后果很具体：签名的防重放完全依赖"这个 nonce 我用过了"这件事，而
    内存字典一重启就清空。攻击者截获一个合法签名请求后，只要等到后端重启
    （发版、改配置、崩一次都行）就能原样重放一遍，服务端照单全收。
    落库之后，重放窗口跨重启依然有效。

    :param db: 可选的 SQLAlchemy Session；不传就自己开一个（调用方是同步路由，
        直接传进来可以省一次连接开销）。借来的会话只 flush，不替调用方提交
        （见函数体里 S-4 的说明）。
    """
    nonce = (nonce or "").strip()
    if not (8 <= len(nonce) <= 64):
        return "nonce 长度不合法"
    now = time.time()
    key = f"{node_id}|{nonce}"

    seen = _NONCE_SEEN.get(key)
    if seen is not None and now - seen < NONCE_TTL_SEC:
        return "nonce 已被使用（重放）"
    _NONCE_SEEN[key] = now
    _prune_nonces(now)

    _own = db is None
    if _own:
        try:
            from database import SessionLocal
            db = SessionLocal()
        except Exception:  # noqa: BLE001 拿不到 session 就只靠内存，不要拖垮认证
            return None
    try:
        from models import AgentNonce
        row = db.query(AgentNonce).filter(AgentNonce.nonce_key == key).first()
        if row is not None:
            if now - float(row.seen_at or 0) < NONCE_TTL_SEC:
                return "nonce 已被使用（重放）"
            row.seen_at = now
        else:
            db.add(AgentNonce(nonce_key=key, seen_at=now))
        # 2026-09-29 S-4：这里原本无条件 `db.commit()`。但 `db` 常常是路由
        # `Depends(get_db)` 传进来的**业务会话**，在认证路径里提前提交，等于把
        # 路由还没写完的改动一起落盘，之后 `db.rollback()` 再也撤不回来
        #（最坏的场景：请求最终被判 401 拒掉，副作用却已经提交了）。
        # 现在：会话是借来的就只 flush，由路由自己的 commit 一并落盘；
        # 会话是本函数开的（db=None）才提交。
        if _own:
            db.commit()
        else:
            db.flush()
        _prune_nonces_db(db, now, own_session=_own)
    except Exception as exc:  # noqa: BLE001
        # 这里是**失败即放行**：nonce 表出问题不该让整批 Agent 掉线。
        # 但它必须留下痕迹，否则"防重放悄悄失效了"永远没人知道。
        try:
            db.rollback()
        except Exception:
            pass
        logger.warning(f"nonce 落库失败（防重放降级为仅内存）：{exc}")
    finally:
        if _own:
            try:
                db.close()
            except Exception:
                pass
    return None


# 证书链校验结果缓存：{证书内容哈希|node_id: True/False}
# 只在"第一次见到这张证书"时真做一次 X.509 全链校验，之后走字典，否则每个
# 心跳都要解析一遍证书，白白烧 CPU。
_CERT_TRUST_CACHE: dict[str, bool] = {}
_CERT_TRUST_CACHE_DETAIL: dict[str, str] = {}


def cert_is_trusted(cert_pem: str, node_id: str = "") -> tuple[bool, str]:
    """这张证书是不是**本服务 CA 签的、还有效、用途是 clientAuth、node_id 也对**。

 2026-09-29 S-7：**不参与认证路径**，仅供存量数据排查与回归脚本使用
    （`t_round4_cert_nonce.py` 在测它）。1.1.51 方案 A 之后，认证改为
    「库里登记的公钥」验签（`load_public_key`），不再经 X.509 证书链，
    所以本函数零业务调用点是**预期行为**，不是漏接。

    背景（2026-09-23 开源加固 ⑦）：它接的是 `services/tls.verify_client_cert()`。
    当初的论证是"认证时只取公钥验签、不问谁签的，改库就能永久冒充"。该论证在
    方案 A 下已不成立 —— 自签 CA 场景中「CA 签过」等价于「库里记了一行」，
    证书不额外提供信任；防冒充靠的是私钥签名证明。
    """
    if not cert_pem:
        return False, "证书为空"
    cache_key = hashlib.sha256(cert_pem.encode("utf-8")).hexdigest()[:32] + "|" + (node_id or "")
    cached = _CERT_TRUST_CACHE.get(cache_key)
    if cached is not None:
        return cached, _CERT_TRUST_CACHE_DETAIL.get(cache_key, "")
    try:
        from services import tls as tls_util
        tls_util.verify_client_cert(cert_pem, node_id)
        ok, detail = True, ""
    except Exception as e:  # noqa: BLE001
        ok, detail = False, str(e)[:200]
    if len(_CERT_TRUST_CACHE) > 1000:
        _CERT_TRUST_CACHE.clear()
        _CERT_TRUST_CACHE_DETAIL.clear()
    _CERT_TRUST_CACHE[cache_key] = ok
    _CERT_TRUST_CACHE_DETAIL[cache_key] = detail
    return ok, detail


# 公钥对象缓存。2026-09-29 S-10：原来 `load_public_key()`（公钥 PEM）与
# `cert_public_key()`（证书 PEM）共用同一个字典。两者产出的对象类型不同
# （前者是公钥、后者是从 X.509 解出的公钥），一旦哈希撞到同一槽位就会拿到
# 错误类型的对象。虽然撞的是内容哈希、概率极低，但拆开是零成本的。
_PUBKEY_CACHE: dict[str, object] = {}
_CERT_PUBKEY_CACHE: dict[str, object] = {}


def load_public_key(pem: str):
    """从**公钥 PEM** 取公钥对象（带缓存）。

    方案 A（1.1.51）：设备身份就是服务端库里登记的这把公钥，不再经 X.509 证书
    这道手。为什么可以不要证书，见 `docs/认证体系简化评估.md` —— 一句话：自签 CA
    场景下「CA 签过」等价于「服务端库里记了一行」，证书不多提供任何信任；而真正
    防冒充的**私钥持有证明**（请求签名）这一层两种方案完全一样。
    """
    if not pem:
        return None
    cache_key = hashlib.sha256(pem.encode("utf-8")).hexdigest()[:32]
    cached = _PUBKEY_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        pub = load_pem_public_key(pem.encode("utf-8"))
        if len(_PUBKEY_CACHE) > 500:
            _PUBKEY_CACHE.clear()
        _PUBKEY_CACHE[cache_key] = pub
        return pub
    except Exception:  # noqa: BLE001
        return None


def cert_public_key(cert_pem: str):
    """从证书 PEM 取公钥（按证书内容缓存，避免每个请求重新解析一遍 X.509）。

 1.1.51 起**认证不再走这里**（改走 `load_public_key`）。保留是因为
    `services/cert_reclaim.py` 等存量数据的清理/迁移路径还会读旧字段。
    """
    if not cert_pem:
        return None
    cache_key = hashlib.sha256(cert_pem.encode("utf-8")).hexdigest()[:32]
    cached = _CERT_PUBKEY_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        pub = cert.public_key()
        if len(_CERT_PUBKEY_CACHE) > 500:
            _CERT_PUBKEY_CACHE.clear()
        _CERT_PUBKEY_CACHE[cache_key] = pub
        return pub
    except Exception:  # noqa: BLE001
        return None


def verify_signature(public_key, signature_b64: str, message: str) -> bool:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        sig = base64.b64decode(signature_b64 or "", validate=True)
    except Exception:  # noqa: BLE001
        return False
    try:
        public_key.verify(sig, message.encode("utf-8"),
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.DIGEST_LENGTH),
                          hashes.SHA256())
        return True
    except Exception:  # noqa: BLE001
        return False
