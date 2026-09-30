"""主机凭据的静态加密存储（安全审计 P0：Server.password 明文入库）。

`servers.password` 存的是**被监控主机的管理员口令**（WinRM / SSH），早期版本明文
落库，任何人拿到 `monitor.db`（备份、拷贝、拖库）就能直接横扫内网。现在改成
Fernet 对称加密，密钥放在库外的 `backend/data/secret.key`：

  * 库里只有密文，`monitor.db` 单独泄露无法还原口令；
  * 密钥文件权限 600，且**不随安装包分发**（installer 的 FORBIDDEN 名单已排除），
    每台部署机独立一把，杜绝"一个包出去所有机器口令全可解"；
  * 兼容旧数据：读的时候认不出 `enc1$` 前缀就当明文原样返回，写入时才升级成密文，
    所以老库不用停机迁移，改一次主机口令就自动加密。

⚠️ 这是"防拖库"而不是"防本机管理员"——服务端进程本身必须能解密才能去连主机，
所以拿到服务器整机权限的人依然能解。要彻底根治只能改用域账号 / 密钥认证。
"""

from __future__ import annotations

import os
import stat
import threading

_PREFIX = "enc1$"
_KEY_FILE = "secret.key"

_lock = threading.Lock()
_cipher = None


def _key_path() -> str:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(here, "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, _KEY_FILE)


def _cipher_obj():
    """惰性加载（并按需生成）Fernet 密钥。"""
    global _cipher
    if _cipher is not None:
        return _cipher
    with _lock:
        if _cipher is not None:
            return _cipher
        from cryptography.fernet import Fernet

        path = _key_path()
        key = b""
        if os.path.exists(path):
            with open(path, "rb") as fh:
                key = fh.read().strip()
        if not key:
            key = Fernet.generate_key()
            with open(path, "wb") as fh:
                fh.write(key)
            try:
                # 仅本机服务账号可读（Windows 上 chmod 是尽力而为，失败不致命）
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        _cipher = Fernet(key)
        return _cipher


def encrypt_secret(plain: str) -> str:
    """加密后返回带前缀的字符串；空串原样返回（"没设口令"和"空口令"要分得开）。"""
    if not plain:
        return plain
    return _PREFIX + _cipher_obj().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt_secret(stored: str) -> str:
    """解密；无法识别为密文时按旧明文返回（迁移路径）。"""
    if not stored:
        return ""
    if not stored.startswith(_PREFIX):
        return stored  # 历史明文数据，原样使用
    try:
        return _cipher_obj().decrypt(stored[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except Exception:  # noqa: BLE001  密钥换了 / 数据坏了，宁可空也别抛到调用方
        return ""


def is_encrypted(stored: str) -> bool:
    return bool(stored) and stored.startswith(_PREFIX)


def derived_key(purpose: str) -> bytes:
    """从主密钥派生一把**用途隔离**的对称密钥（目前给 WEB 代理票据签名用）。

    不直接复用 Fernet key：一把钥匙串到多个用途上，任何一处的实现缺陷都会外溢。
    这里用 sha256(master | purpose) 做域分离，等价于最简版 HKDF。
    """
    import hashlib

    path = _key_path()
    if not os.path.exists(path):
        _cipher_obj()
    with open(path, "rb") as fh:
        base = fh.read().strip()
    return hashlib.sha256(base + b"|" + purpose.encode("utf-8")).digest()
