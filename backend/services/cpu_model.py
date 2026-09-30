"""CPU 型号规范化。

Windows 上 ``platform.processor()`` 只会返回 CPUID 代号，例如

    Intel64 Family 6 Model 165 Stepping 3, GenuineIntel

这不是用户想看的型号（真实型号是 "12th Gen Intel(R) Core(TM) i5-12400F"）。
Agent 侧已改为优先读注册表 ``ProcessorNameString``；这里再做一层后端兜底：

* ``is_cpuid_code()`` 判定一个名字是不是 CPUID 代号，供各处决定要不要采用/覆盖；
* ``clean()`` 统一去掉多余空白，避免注册表值里的连续空格带到界面上。
"""
from __future__ import annotations

import re

_CPUID_CODE_RE = re.compile(
    r"^\s*(?:Intel|AMD|ARM|Hygon|Centaur|Unknown)\s*\d*\s+Family\s+\d+",
    re.IGNORECASE,
)


def is_cpuid_code(name: str | None) -> bool:
    """True 表示这是 CPUID 代号，而不是用户看得懂的 CPU 型号名。"""
    return bool(_CPUID_CODE_RE.match(str(name or "")))


def clean(name: str | None) -> str:
    """压缩空白（注册表 ProcessorNameString 常见前导/连续空格）。"""
    return " ".join(str(name or "").split())
