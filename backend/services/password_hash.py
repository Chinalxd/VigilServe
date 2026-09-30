"""密码哈希（安全加固阶段 3）。

历史包袱：早期版本把密码存成**无盐 SHA256**（`hashlib.sha256(pw).hexdigest()`），
彩虹表一查就中，等同于明文。现在换成：

  * **bcrypt**（优先，带盐、慢哈希、抗 GPU/ASIC）——需要 `bcrypt` 包；
  * **scrypt**（回退，Python 标准库 `hashlib.scrypt`，同样带盐且内存硬）——
    打包环境缺 `bcrypt` 时自动用它，绝不退回无盐哈希。

哈希串带算法前缀，方便识别与平滑迁移：
    bcrypt$<bcrypt 标准串>
    scrypt$<n>$<r>$<p>$<salt_hex>$<dk_hex>
    <64 位 hex>            ← 旧的无盐 SHA256（登录成功时自动重算）

迁移策略：老口令**不改密码也能自动升级** —— 用户登录时用旧算法校验通过，
立即用新算法重算并写回数据库（`needs_rehash()` 判定）。
"""
from __future__ import annotations

import hashlib
import hmac
import logging

logger = logging.getLogger("backend")

_BCRYPT_PREFIX = "bcrypt$"
_SCRYPT_PREFIX = "scrypt$"
_BCRYPT_ROUNDS = 12
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_SALT = 16

_bcrypt = None
_bcrypt_tried = False


def _get_bcrypt():
    global _bcrypt, _bcrypt_tried
    if _bcrypt_tried:
        return _bcrypt
    _bcrypt_tried = True
    try:
        import bcrypt as _b  # type: ignore
        _bcrypt = _b
    except Exception:  # noqa: BLE001
        _bcrypt = None
        logger.warning("bcrypt 不可用，密码哈希回退到标准库 scrypt（仍在加盐慢哈希，只是抗 ASIC 弱一些）")
    return _bcrypt


def _legacy_sha256(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def _scrypt_hash(pw: str) -> str:
    import os
    salt = os.urandom(_SCRYPT_SALT)
    dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                        p=_SCRYPT_P, dklen=_SCRYPT_DKLEN, maxmem=64 * 1024 * 1024)
    return (f"{_SCRYPT_PREFIX}{_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}$"
            f"{salt.hex()}${dk.hex()}")


def _scrypt_verify(pw: str, stored: str) -> bool:
    try:
        body = stored[len(_SCRYPT_PREFIX):]
        n_s, r_s, p_s, salt_hex, dk_hex = body.split("$")
        dk = hashlib.scrypt(pw.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                            n=int(n_s), r=int(r_s), p=int(p_s), dklen=len(dk_hex) // 2,
                            maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:  # noqa: BLE001
        return False


def hash_password(pw: str) -> str:
    """生成新密码的哈希串（带算法前缀）。"""
    b = _get_bcrypt()
    if b is not None:
        try:
            # bcrypt 只吃前 72 字节，超长口令先 sha256 再 base64，避免静默截断
            raw = pw.encode("utf-8")
            if len(raw) > 72:
                import base64
                raw = base64.b64encode(hashlib.sha256(raw).digest())
            return _BCRYPT_PREFIX + b.hashpw(raw, b.gensalt(rounds=_BCRYPT_ROUNDS)).decode()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"bcrypt 哈希失败，回退 scrypt：{e}")
    return _scrypt_hash(pw)


def verify_password(pw: str, stored: str) -> bool:
    """校验口令；兼容三种存储格式（bcrypt / scrypt / 旧无盐 sha256）。"""
    if not stored:
        return False
    if stored.startswith(_BCRYPT_PREFIX):
        b = _get_bcrypt()
        if b is None:
            return False
        try:
            raw = pw.encode("utf-8")
            if len(raw) > 72:
                import base64
                raw = base64.b64encode(hashlib.sha256(raw).digest())
            return b.checkpw(raw, stored[len(_BCRYPT_PREFIX):].encode())
        except Exception:  # noqa: BLE001
            return False
    if stored.startswith(_SCRYPT_PREFIX):
        return _scrypt_verify(pw, stored)
    return hmac.compare_digest(_legacy_sha256(pw), stored)


def needs_rehash(stored: str) -> bool:
    """存储格式是否需要升级（旧无盐 sha256 → 新的加盐慢哈希）。"""
    if not stored:
        return True
    if stored.startswith(_BCRYPT_PREFIX):
        return False
    if stored.startswith(_SCRYPT_PREFIX):
        # bcrypt 可用时继续升级到 bcrypt（抗 ASIC 更强）
        return _get_bcrypt() is not None
    return True


def algo_of(stored: str) -> str:
    if not stored:
        return "empty"
    if stored.startswith(_BCRYPT_PREFIX):
        return "bcrypt"
    if stored.startswith(_SCRYPT_PREFIX):
        return "scrypt"
    if len(stored) == 64 and all(c in "0123456789abcdef" for c in stored.lower()):
        return "sha256-legacy"
    return "unknown"
