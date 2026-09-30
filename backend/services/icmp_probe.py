"""ICMP 探测（延迟 / 丢包）—— 和 SNMP 并列的第二条"设备还活着吗"证据。

为什么不能只看 SNMP：SNMP 走 UDP 161，由设备的 SNMP 代理进程应答；ICMP 由内核
应答。设备 CPU 打满时 SNMP 会超时但 ICMP 照通（说明"链路在、控制面卡了"），
反过来 ICMP 被 ACL 挡掉而 SNMP 正常也很常见。两条路分开看才分得清是"设备挂了"
还是"代理卡了"。

🚨 直接调系统的 ping 子进程，**不自己造 ICMP 包**：造原始套接字在 Windows 要
   管理员、在 Linux 要 CAP_NET_RAW，本服务两种都没有。
🚨 只发 3 个包、每包 1 秒超时，整个探测 5 秒内必回。采集周期是 5 分钟，
   这里多花两三秒无所谓，但**绝不能**拖成几十秒 —— 一轮采集里有几十台设备时
   会直接把周期撑爆。
"""
from __future__ import annotations

import platform
import re
import subprocess

COUNT = 3
TIMEOUT_SEC = 1


def _ping_args(ip: str, count: int, timeout: int) -> list:
    if platform.system().lower().startswith("win"):
        return ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
    return ["ping", "-c", str(count), "-W", str(timeout), ip]


def _decode(raw: bytes) -> str:
    """ping 的输出编码随系统区域变（中文 Windows 是 GBK），逐个试。"""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def probe_icmp(ip: str, count: int = COUNT, timeout: int = TIMEOUT_SEC) -> dict:
    """ping 一次。返回 dict，**不抛异常**（采集链路不能因为 ping 失败就断）。

    返回体：
      ok           至少收到一个回包
      sent         发出的包数
      received     收到的包数
      loss_percent 丢包率
      avg_ms       平均往返时延（收不到包时是 None）
      min_ms / max_ms
      error        中文说明（正常时是空串）
    """
    if not ip:
        return {"ok": False, "sent": 0, "received": 0, "loss_percent": 100.0,
                "avg_ms": None, "min_ms": None, "max_ms": None, "error": "设备没有 IP"}
    try:
        proc = subprocess.run(
            _ping_args(ip, count, timeout),
            capture_output=True,
            timeout=count * timeout + 4,   # 子进程自己的兜底超时，防 ping 卡死
            check=False,
        )
        out = _decode(proc.stdout or b"") + "\n" + _decode(proc.stderr or b"")
    except subprocess.TimeoutExpired:
        return {"ok": False, "sent": count, "received": 0, "loss_percent": 100.0,
                "avg_ms": None, "min_ms": None, "max_ms": None, "error": "ping 超时"}
    except FileNotFoundError:
        return {"ok": False, "sent": 0, "received": 0, "loss_percent": 100.0,
                "avg_ms": None, "min_ms": None, "max_ms": None, "error": "系统没有 ping 命令"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "sent": 0, "received": 0, "loss_percent": 100.0,
                "avg_ms": None, "min_ms": None, "max_ms": None,
                "error": f"{type(e).__name__}: {e}"}

    # 数"回包行"比解析"丢包百分比"稳：百分比那行在中文/英文 Windows 上分别是
    # "丢失" / "loss"，编码一错就匹配不到；回包行里的时间数字是 ASCII，永远好认。
    #   中文 Windows：来自 <ip> 的回复: 字节=32 时间=1ms TTL=64
    #   Linux/macOS ：64 bytes from <ip>: icmp_seq=1 ttl=64 time=1.23 ms
    reply_lines = [ln for ln in out.splitlines()
                   if ("回复" in ln) or re.search(r"\breply\b", ln, re.I)
                   or re.search(r"bytes from", ln, re.I)]
    times = []
    for ln in reply_lines:
        m = re.search(r"(?:时间|time)\s*[=<]\s*(\d+(?:\.\d+)?)\s*ms", ln, re.I)
        if m:
            times.append(float(m.group(1)))
        elif re.search(r"(?:时间|time)\s*<\s*1\s*ms", ln, re.I):
            times.append(0.5)

    received = len(reply_lines)
    sent = count
    loss = round((sent - received) * 100.0 / sent, 1) if sent else 100.0

    res = {
        "ok": received > 0,
        "sent": sent,
        "received": received,
        "loss_percent": loss,
        "avg_ms": round(sum(times) / len(times), 2) if times else None,
        "min_ms": round(min(times), 2) if times else None,
        "max_ms": round(max(times), 2) if times else None,
        "error": "" if received else "没有收到回包（设备不通或 ICMP 被拦）",
    }
    return res
