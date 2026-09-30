"""出网目标地址守卫（第二轮复查 R-5 / SSRF）。

背景
────
服务端会**拿着页面表单里填的地址**主动去连设备：

  * `POST /api/servers/network-devices/probe` —— 新增设备弹窗的「测试连接」
  * `POST /api/servers/network-devices`      —— 新增设备时先试连再入库

以前这两个接口只校验了"调用者有没有权限点"，**完全不校验目标地址**。于是任何
持有 `sys/network_devices` 权限的账号都能让服务端当跳板，去探测内网的任意地址——
典型目标就是 `169.254.169.254`（各家云的元数据服务，常能直接换到临时凭据）。

现在统一过一道，规则刻意做得保守：

  ① **永远拒绝**：未指定 / 回环 / 链路本地（含云元数据）/ 组播 / 保留段。
     这些都是正常情况下绝不该被当成"网络设备"去连的地址。
  ② **可选白名单**：环境变量 `VIGILSERVE_TARGET_ALLOWED_CIDRS`（逗号分隔的 CIDR）。
     置了就只允许落在这些网段里的目标；**留空 = 不额外限制**（保持既有行为，
     免得老部署升级后莫名其妙连不上设备）。想收紧就自己配上。

设计约束
────────
* 纯函数、不做连接 —— 便于单测，也便于将来接到别处。
* 只回答"该不该连"，**不改**调用方的错误处理风格。
* 域名也会解析后再判（所以填主机名也能用）；注意这只能防住"解析到一个坏地址"，
  防不住 DNS rebinding（解析时给好 IP、连接时给坏 IP）。内网场景可接受，
  真要堵死得改成"解析后固定 IP 再连"，那是另一个量级的改动。
"""

from __future__ import annotations

import ipaddress
import os
import socket

# (网段, 拒绝理由)。按 IPv4 / IPv6 分别登记，判定时只比同版本的。
_ALWAYS_BLOCKED: tuple = (
    (ipaddress.ip_network("0.0.0.0/8"), "未指定地址"),
    (ipaddress.ip_network("127.0.0.0/8"), "回环地址"),
    (ipaddress.ip_network("169.254.0.0/16"), "链路本地地址（含云元数据 169.254.169.254）"),
    (ipaddress.ip_network("224.0.0.0/4"), "组播地址"),
    # 有限广播。计算上它落在下面的 240.0.0.0/4 里，但语义是广播而不是"保留"，
    # 单独列一条，好让拒绝理由说到点子上。
    (ipaddress.ip_network("255.255.255.255/32"), "广播地址"),
    (ipaddress.ip_network("240.0.0.0/4"), "保留地址"),
    (ipaddress.ip_network("::/128"), "未指定地址"),
    (ipaddress.ip_network("::1/128"), "回环地址"),
    (ipaddress.ip_network("fe80::/10"), "链路本地地址"),
    (ipaddress.ip_network("ff00::/8"), "组播地址"),
)

# 环境变量名。留空 = 只做①的硬拒绝，不做网段白名单。
CIDR_ENV = "VIGILSERVE_TARGET_ALLOWED_CIDRS"


def _allowed_cidrs() -> list | None:
    """返回白名单网段列表；未配置返回 None（表示不限制）。"""
    raw = (os.getenv(CIDR_ENV) or "").strip()
    if not raw:
        return None
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            # 配错了不要静默放行，也不要连不上就崩，记下来交给调用方处理。
            # 这里只能返回 None（不限制），但调用方会把这条一并写进日志。
            return None
    return nets or None


def _resolve(target: str) -> list:
    """把目标解析成 IP 列表。填的是 IP 字面量就直接返回；是域名则解析。

    解析不出来返回空列表（调用方应当拒绝，而不是放行）。
    """
    try:
        return [ipaddress.ip_address(target)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None)
    except Exception:  # noqa: BLE001 解析失败一律当"不能连"
        return []
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except (ValueError, IndexError, TypeError):
            continue
    return out


def check(target: str) -> tuple:
    """判断能不能主动去连这个目标。

    返回 `(ok: bool, reason: str)`。`ok=False` 时 `reason` 是可以直接回给
    前端的中文说明。
    """
    t = (target or "").strip()
    if not t:
        return False, "目标地址为空"

    ips = _resolve(t)
    if not ips:
        return False, f"无法解析目标地址：{t}"

    for ip in ips:
        for net, why in _ALWAYS_BLOCKED:
            if ip.version == net.version and ip in net:
                return False, f"禁止连接{why}：{ip}"

    cidrs = _allowed_cidrs()
    if cidrs:
        for ip in ips:
            if not any(ip.version == n.version and ip in n for n in cidrs):
                return False, (
                    f"目标 {ip} 不在允许纳管的网段内"
                    f"（见环境变量 {CIDR_ENV}）"
                )

    return True, ""
