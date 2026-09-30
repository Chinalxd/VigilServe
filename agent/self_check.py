"""Agent 自身完整性自检（对标 MeshCentral 的 `agentTampering`）。

开源之后，任何人都能拿到源码。真正危险的不是"读"，而是有人改几行（例如把采集
数据偷偷转发到别处、或者把服务端的指令过滤掉）再重新打包，伪装成官方 Agent 接进
来 —— 界面上它跟正常机器一模一样，`agent_version` 也还是那个号。

MeshCentral 的做法是让 Agent 自己算一遍二进制的哈希报上去，服务端跟基线比。
这里照做，口径如下：

    冻结模式（PyInstaller onedir）:
        <_MEIPASS>/*.pyz                    Python 代码归档（若打包时编译进 PYZ）
        <_MEIPASS>/*.py                     **顶层明文投放的源码模块**
    源码模式（开发机直接跑 .py）:
        agent/*.py                          全部源码文件

 两个**刻意排除**的对象，都是踩过之后才排除的：

1. **`sys.executable`（主启动器）不算**。PyInstaller 产出的 exe **不是字节可复现的**
   （内嵌构建期数据）—— 实测同一份源码连打两次，14 个 .py 逐字节一致，只有 exe 变了，
   于是指纹从 `67d8a3e6…` 变成 `08b3e7da…`。把它算进去的后果是：管理员**重装同一个
   版本**的 Agent 时，版本号没变、指纹却变了，服务端会记一条 `agent_tamper_suspected`
   —— 纯属误报，而且每重打一次包误报一批，很快就没人在乎这个告警了。
   排除它的代价：理论上看不到"只 patch 了 exe"，但 exe 是 C bootloader，
   Agent 的业务逻辑全在下面这些 `.py` 里，改它既难又没用。
2. **`.pyd` / `.dll` / `base_library.zip` 不算** —— 见下面那段。

 为什么必须包含 `_MEIPASS` 下的 **.py**：本项目的 spec 把 `api_server.py` /
   `connector.py` / `self_check.py` 等**以源码形式**投放在 `_internal/` 顶层
   （`VigilServeAgent.spec` 的 `datas`），它们并没有被编译进 PYZ。
   第一版只哈希 exe + .pyz，实测 `_internal` 里 `.pyz` 有 **0 个**、最终只算到
   1 个文件 —— 于是有人直接改 `api_server.py` 再重启 Agent，指纹纹丝不动，
   完整性自检完全失效。这才有了下面这条规则。

 刻意**不**包含 `_internal` 下的 .pyd / .dll 和 `base_library.zip`：
   前者是 tkinter / PIL / 密码库等第三方二进制，几百 MB，全算一遍既慢又无意义
   （改它们也改不出一个"听话的 Agent"）；后者随 **PyInstaller 版本**变化，
   而 Agent 版本号不变 —— 把它算进去，每次升级构建工具都会误报"被改造"。
 同理：`_MEIPASS` 只取**顶层**，不要递归进 numpy / PIL / cryptography 这些
   第三方包目录（同样的理由）。

只在**进程启动时算一次**并缓存 —— 心跳 5 秒一次，每 5 秒扫一遍几 MB 的文件
纯属浪费。
"""
from __future__ import annotations

import hashlib
import os
import sys
import threading

_CACHE: dict = {"digest": "", "count": 0, "mode": ""}
_LOCK = threading.Lock()


def _hash_file(path: str) -> bytes | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 256), b""):
                h.update(chunk)
        return h.digest()
    except Exception:  # noqa: BLE001 读不到的文件（被占用/被删）跳过即可
        return None


def _collect_files() -> tuple[list[str], str]:
    """返回 (待哈希文件列表, 运行模式)。"""
    if getattr(sys, "frozen", False):
        # 刻意**不**把 sys.executable 算进指纹，见模块顶部说明：PyInstaller
        # 产出的启动器不是字节可复现的，把它算进去会导致"同一份源码重打一次包，
        # 指纹就变"，于是管理员重装同版本 Agent 会被误判成"疑似被改造"。
        files = []
        meipass = getattr(sys, "_MEIPASS", "") or ""
        if meipass and os.path.isdir(meipass):
            try:
                for name in sorted(os.listdir(meipass)):
                    low = name.lower()
                    if low.endswith(".pyz") or (low.endswith(".py")
                                                and os.path.isfile(os.path.join(meipass, name))):
                        files.append(os.path.join(meipass, name))
            except Exception:  # noqa: BLE001
                pass
        return files, "frozen"

    here = os.path.dirname(os.path.abspath(__file__))
    files = []
    try:
        for name in sorted(os.listdir(here)):
            if name.endswith(".py"):
                files.append(os.path.join(here, name))
    except Exception:  # noqa: BLE001
        pass
    return files, "source"


def self_digest(force: bool = False) -> dict:
    """本机 Agent 代码的完整性指纹。结果缓存在进程内。

    返回 {"digest": hex, "files": 文件数, "mode": frozen|source}。
    拿不到任何文件时 digest 为空 —— 服务端会跳过基线登记而不是误报篡改。
    """
    with _LOCK:
        if _CACHE["digest"] and not force:
            return dict(_CACHE)

    files, mode = _collect_files()
    acc = hashlib.sha256()
    n = 0
    for p in files:
        d = _hash_file(p)
        if d:
            # 把文件名也拌进去：只增删文件、内容不变时哈希也该变
            acc.update(os.path.basename(p).encode("utf-8", "ignore"))
            acc.update(d)
            n += 1

    out = {"digest": acc.hexdigest() if n else "", "files": n, "mode": mode}
    with _LOCK:
        _CACHE.update(out)
    return out


if __name__ == "__main__":
    import json
    print(json.dumps(self_digest(), indent=2, ensure_ascii=False))
