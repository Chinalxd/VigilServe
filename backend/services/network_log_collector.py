"""路线 A：只读 SSH 轮询，把网络设备的内部运行日志拉回服务端存档。

为什么是这条路线
────────────────
设备肚子里是有日志的（华为 logbuffer / trapbuffer），但它们**只活在内存里**：
    · 缓冲区是环形的 —— 实测 1024 条容量已经被覆盖 2207 次；
    · 交换机一重启就全没；
    · 设备默认**没有**配 syslog 主机（`display info-center` 的 Log host 为空），
      也就是说现在这些日志哪儿都没去，只在设备上自生自灭。

四条候选路线里选 A 的理由：
    A 只读 SSH 轮询（本文件）—— **不改设备任何配置**，复用已有的 CLI 凭据与
      主机密钥钉扎，今天就能上线。
    B 设备 → UDP 514 syslog  —— 实时性好，但要动设备配置 + 服务端加 514 监听。
    C SNMP Trap → UDP 162    —— 同上，且 Trap 只覆盖"通知类"，没有 logbuffer 全。
    D 拉 flash 上的 dblg.zip —— 只能事后翻账。

只读，具体怎么保证
──────────────────
全程只发三条命令，全部是 `display` 类：
    screen-length 0 temporary    关闭分页（否则 500+ 行会被 ---- More ---- 切碎）
    display logbuffer            日志缓冲区
    display trapbuffer           Trap 缓冲区
不进 system-view、不下任何配置、不 save。连 `screen-length 0 temporary` 都是
"temporary"，只对本次会话生效，断线即失效。

命令集留了厂商分支：华为 / 华三走 VRP，思科走 IOS，别的设备返回"暂不支持"，
**绝不拿华为的命令去捅思科**（`show` 在 VRP 上不是命令，反过来 `display` 在 IOS
上也不是，乱发只会拿到一堆错误回显）。
"""
from __future__ import annotations

import hashlib
import re
import time
from datetime import datetime, timedelta, timezone

MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# 华为 / 华三（VRP）日志行。**logbuffer 和 trapbuffer 是两套格式**，必须都认：
#     #Sep 21 2026 16:03:04+08:00 HUAWEI LINE/5/VTYUSERLOGIN:OID 1.3.6.1.4.1.2011.5.25.207.2.2 A user login. (…)
#   ④ trapbuffer 在冒号后**插了一段 `OID x.x.x.x`**（这段要剥掉，否则正文全被 OID 糊住）。
VRP_LINE = re.compile(
    r"^#?\s*(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<year>\d{4})\s+"
    r"(?P<hm>\d{2}:\d{2}:\d{2})(?P<tz>[+-]\d{2}:?\d{2})?\s+"
    r"(?P<host>\S+)\s+(?:%%\d{2})?(?P<module>[A-Za-z0-9_]+)/(?P<level>\d)/"
    r"(?P<mnemonic>[A-Za-z0-9_]+)"
    r"(?:\((?P<flags>[a-z])\))?"
    r"(?:\[(?P<seq>\d+)\])?\s*:\s*"
    r"(?:OID\s+[0-9.]+\s+)?"
    r"(?P<msg>.*)$"
)

# 级别码 → 归一化级别名（华为 0~7，越大越不严重）
LEVEL_NAMES = {
    0: "critical", 1: "critical", 2: "critical",
    3: "error",
    4: "warning",
    5: "info", 6: "info", 7: "info",
}
LEVEL_CODE_NAMES = {
    0: "EMERG", 1: "ALERT", 2: "CRIT", 3: "ERROR",
    4: "WARN", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

# 每次最多往回存多少条（新的在前）。设备缓冲区上限也就 1024，这个数字够用。
MAX_PER_COLLECT = 1200
# 每台设备保留多少条。设备日志量不大但会持续累积，不设上限迟早撑爆库。
KEEP_PER_SERVER = 5000

# 🚨 **key 必须是中文厂商名** —— `device_profile.py` 认出来的厂商是中文
# 直接落到"暂不支持"分支 —— 真机上就是这个坑。
VENDOR_CMDS = {
    "华为": [("logbuffer", "display logbuffer"),
             ("trapbuffer", "display trapbuffer")],
    "华三": [("logbuffer", "display logbuffer"),
             ("trapbuffer", "display trapbuffer")],
    "锐捷": [("logbuffer", "show logging")],
    "思科": [("logbuffer", "show logging")],
    "中兴": [("logbuffer", "show logbuffer")],
    # 英文别名：device_vendor 可能被人工改成英文，或由别的路径写进来
    "huawei": [("logbuffer", "display logbuffer"),
               ("trapbuffer", "display trapbuffer")],
    "h3c": [("logbuffer", "display logbuffer"),
            ("trapbuffer", "display trapbuffer")],
    "ruijie": [("logbuffer", "show logging")],
    "cisco": [("logbuffer", "show logging")],
}

# ── NAS / 存储类设备：明确记成「不支持」，并把原因写清楚 ──────────────
# 🚨 2026-09-21 踩到：`device_vendor` 对 NAS 存的是 **英文** `Synology`
# （企业号 6574 → "群晖"，但这个字段被人工/其它路径改成了英文型号名），
# 查表时 `"synology"` 有登记所以返回了 `[]` —— **行为是对的，但前端只拿到
# 一句"暂不支持"，看不出是"设备本身没这类日志"还是"命令集还没写"**。
# 真正的原因（读 Syslog 服务的设计就能确认）：群晖 DSM 的运行日志**不放在
# 没有华为那种 `display logbuffer` 的内存环形缓冲。所以不是该写命令没写，
# 是**这类设备根本没有可轮询的 CLI 日志源** —— 要采集只能走
# 需要动设备配置并在服务端起监听，不在本模块职责内。
# 这里不返回空列表而是返回**带原因的结构**，让页面能如实说清"为什么不行"。
UNSUPPORTED_VENDORS = {
    "群晖": "群晖 DSM 的运行日志是文件（/var/log/messages、/var/log/synolog/），"
            "没有命令行可轮询的内存环形缓冲，无法用只读 SSH 拉取",
    "qnap": "QNAP 同为文件式日志（/var/log/），没有可轮询的命令行缓冲区",
    "synology": "群晖 DSM 的运行日志是文件（/var/log/messages、/var/log/synolog/），"
                "没有命令行可轮询的内存环形缓冲，无法用只读 SSH 拉取",
    "net-snmp": "该设备只暴露 SNMP，没有对应的命令行日志缓冲区",
}

# 没识别出厂商时的兜底：国内机房绝大多数是 VRP（华为 / 华三）。
FALLBACK_CMDS = VENDOR_CMDS["华为"]


def collect_plan(server) -> dict:
    """这台设备能不能采、用哪些命令采、不能采是为什么。

    返回 ``{supported, cmds, reason, vendor}``。前端「拉取设备日志」按钮靠它
    决定禁用与提示文案 —— 按钮灰掉必须能说出**为什么**，不然用户只能瞎猜。
    """
    vendor = str(getattr(server, "device_vendor", "") or "").strip()
    key = vendor.lower()
    if key in UNSUPPORTED_VENDORS:
        return {"supported": False, "cmds": [], "vendor": vendor,
                "reason": UNSUPPORTED_VENDORS[key]}
    cmds = VENDOR_CMDS.get(key)
    if cmds:
        return {"supported": True, "cmds": cmds, "vendor": vendor, "reason": ""}
    if not vendor:
        return {"supported": False, "cmds": [], "vendor": "",
                "reason": "还没识别出设备厂商，无法确定用哪套命令采集内部日志"}
    return {"supported": False, "cmds": [], "vendor": vendor,
            "reason": f"「{vendor}」的命令行日志格式还没有适配"}

PROMPT_RE = re.compile(r"[\r\n]\s*(?:\x1b\[[0-9;]*[A-Za-z])*[<\[][^\]>]{0,40}[>\]]\s*$")


def _fingerprint(device_time: str, module: str, mnemonic: str, msg: str) -> str:
    """去重键。

    🚨 **不能用设备的日志序号 seq** —— 它是环形缓冲区的下标，设备重启或从
    缓冲区绕回时会归零，拿它去重会把新日志误判成"已经有了"而丢掉。
    """
    base = "|".join([device_time or "", module or "", mnemonic or "", (msg or "")[:400]])
    return hashlib.sha1(base.encode("utf-8", "replace")).hexdigest()


def parse_vrp_line(line: str):
    """解析一行 VRP 日志（logbuffer 与 trapbuffer 两套格式都认）。

    不是日志行（表头 / 空行 / 命令回显）时返回 None。
    🚨 别用 `if "%%" in line` 做前置过滤 —— trapbuffer 的行没有 `%%`，
    那样会把整个 trapbuffer 全滤掉。
    """
    if not line or not line.strip():
        return None
    m = VRP_LINE.match(line.strip())
    if not m:
        return None
    mon = MONTHS.get(m.group("mon").lower())
    if not mon:
        return None
    device_time = (f"{m.group('year')}-{mon:02d}-{int(m.group('day')):02d} "
                   f"{m.group('hm')}{m.group('tz') or ''}")
    occurred = None
    try:
        occurred = datetime(
            int(m.group("year")), mon, int(m.group("day")),
            *[int(x) for x in m.group("hm").split(":")]
        )
        tz = m.group("tz")
        if tz:
            sign = 1 if tz[0] == "+" else -1
            hh, mm = int(tz[1:3]), int(tz[-2:])
            from datetime import timezone as _tz
            occurred = occurred.replace(tzinfo=_tz(sign * timedelta(hours=hh, minutes=mm)))
    except Exception:  # noqa: BLE001
        occurred = None
    code = int(m.group("level"))
    return {
        "device_time": device_time,
        "occurred_at": occurred,
        "level_code": code,
        "level": LEVEL_NAMES.get(code, "info"),
        "level_name": LEVEL_CODE_NAMES.get(code, str(code)),
        "module": m.group("module") or "",
        "mnemonic": m.group("mnemonic") or "",
        "message": (m.group("msg") or "").strip(),
        "seq": int(m.group("seq") or 0),
        "raw": line.strip(),
    }


def _drain(sess, seconds: float = 0.4) -> str:
    """把 channel 里现有的输出读干净（用于吞掉 banner 和命令回显）。"""
    buf = b""
    end = time.time() + seconds
    while time.time() < end:
        try:
            chunk = sess.recv(65535)
        except Exception:  # noqa: BLE001
            break
        if chunk:
            buf += chunk
        else:
            time.sleep(0.05)
    return buf.decode("utf-8", "replace")


def _run_cmd(sess, cmd: str, timeout: float = 30.0) -> str:
    """发一条命令，一直读到设备把提示符吐回来为止。

    判据是"末尾出现提示符"，不是"没数据了" —— 设备在两个包之间可能静默几百毫秒，
    纯靠 recv 返回空就收尾会截断长输出。
    """
    sess.send((cmd + "\n").encode())
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = sess.recv(65535)
        except Exception:  # noqa: BLE001
            break
        if chunk:
            buf += chunk
            text = buf.decode("utf-8", "replace")
            if PROMPT_RE.search(text) or text.rstrip().endswith((">", "]")):
                break
        else:
            time.sleep(0.05)
    return buf.decode("utf-8", "replace")


def collect_device_logs(db, server, sources=None, keep=KEEP_PER_SERVER) -> dict:
    """拉一台设备的内部日志并入库。失败不抛，返回 {"ok":False,"error":...}。

    `server` 需要已经配好 CLI 凭据（cli_username / cli_password）—— 走的是
    「WEB终端」那套登录，顺带复用 SSH 主机密钥钉扎，不另开一条认证通道。
    """
    from models import DeviceLogEntry
    from services.network_cli import CliError, open_cli_session

    plan = collect_plan(server)
    if not plan["supported"]:
        return {"ok": False, "error": plan["reason"] or "该设备不支持采集内部日志",
                "unsupported": True}
    cmds = plan["cmds"]
    if sources:
        cmds = [c for c in cmds if c[0] in sources]
    if not cmds:
        return {"ok": False, "error": f"暂不支持采集「{plan['vendor'] or '未知厂商'}」设备的内部日志"}

    try:
        sess = open_cli_session(server, cols=200, rows=200, db=db, timeout=15)
    except CliError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    try:
        _drain(sess, 0.8)
        # 🚨 必须关分页。不关的话 512 行的 logbuffer 会被 ---- More ---- 切成几十段，
        # 每段都要等，最后拿到的还是缺的。temporary = 只对本次会话生效。
        _run_cmd(sess, "screen-length 0 temporary", timeout=10)
        _drain(sess, 0.3)

        parsed = []
        raw_blobs = {}
        for src, cmd in cmds:
            out = _run_cmd(sess, cmd, timeout=40)
            raw_blobs[src] = out
            for line in out.splitlines():
                item = parse_vrp_line(line)
                if item:
                    item["source"] = src
                    parsed.append(item)

        if not parsed:
            return {
                "ok": True, "inserted": 0, "skipped": 0, "total": 0,
                "note": "设备上没有解析到日志行（缓冲区可能是空的，或厂商命令不匹配）",
            }

        parsed.sort(key=lambda x: (x["occurred_at"] or datetime.min.replace(tzinfo=timezone.utc)),
                    reverse=True)
        parsed = parsed[:MAX_PER_COLLECT]

        since = datetime.now(timezone.utc) - timedelta(days=7)
        known = {
            r[0] for r in db.query(DeviceLogEntry.fingerprint).filter(
                DeviceLogEntry.server_id == server.id,
                DeviceLogEntry.collected_at >= since,
            ).all()
        }

        inserted = 0
        for item in parsed:
            fp = _fingerprint(item["device_time"], item["module"],
                              item["mnemonic"], item["message"])
            if fp in known:
                continue
            known.add(fp)
            db.add(DeviceLogEntry(
                server_id=server.id,
                source=item["source"],
                level_code=item["level_code"],
                level=item["level"],
                module=item["module"],
                mnemonic=item["mnemonic"],
                message=item["message"],
                raw=item["raw"],
                device_time=item["device_time"],
                occurred_at=item["occurred_at"],
                seq=item["seq"],
                fingerprint=fp,
            ))
            inserted += 1
        db.commit()
        _prune(db, server.id, keep)

        return {
            "ok": True,
            "inserted": inserted,
            "skipped": len(parsed) - inserted,
            "total": len(parsed),
            "sources": [c[0] for c in cmds],
        }
    except Exception as e:  # noqa: BLE001
        db.rollback()
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        try:
            sess.close()
        except Exception:  # noqa: BLE001
            pass


def _prune(db, server_id: int, keep: int = KEEP_PER_SERVER) -> int:
    """每台设备只留最新的 keep 条。返回删掉的行数。

    设备的日志缓冲区本身就只有 1024 条，但拉回来是**持续累积**的 —— 不设上限，
    一年下来就是几十万行，而这里存的价值主要是"出事时能回溯"，太久的没必要留。
    """
    from models import DeviceLogEntry
    from sqlalchemy import select

    ids = [r[0] for r in db.execute(
        select(DeviceLogEntry.id)
        .where(DeviceLogEntry.server_id == server_id)
        .order_by(DeviceLogEntry.id.desc())
        .offset(keep)
    ).all()]
    if not ids:
        return 0
    db.query(DeviceLogEntry).filter(DeviceLogEntry.id.in_(ids)).delete(
        synchronize_session=False)
    db.commit()
    return len(ids)


def record_state(db, server, res: dict) -> None:
    """把一次采集的结果记到 extra_config['device_logs']，供页面显示「上次采集」。

    和 SNMP 那条链路分开存 —— 两条链路凭据不同、失败原因不同，混在一个字段里
    排查时根本分不清是谁挂了。
    """
    extra = dict(server.extra_config or {})
    extra["device_logs"] = {
        "last_attempt_at": datetime.now(timezone.utc).isoformat(),
        "ok": bool(res.get("ok")),
        "error": res.get("error", ""),
        "total": int(res.get("total") or 0),
        "inserted": int(res.get("inserted") or 0),
        # 「不支持」和「支持但采集失败」是两种性质，前端要分开说 ——
        # 前者点了按钮也没用（按钮该灰掉），后者是凭据/网络问题（要找原因修）。
        "unsupported": bool(res.get("unsupported")),
    }
    server.extra_config = extra
    db.commit()


def supported(server) -> bool:
    """这台设备能不能采内部日志（厂商有没有对应的命令集）。

    调度器靠它跳过 NAS 这类"设备是网络设备、但没有 CLI 日志可拉"的对象 ——
    不然每 15 分钟给每台 NAS 报一次"暂不支持"，日志会被噪音淹掉。
    """
    return bool(collect_plan(server)["supported"])


def collect_all_device_logs(db) -> dict:
    """调度入口：采所有「网络设备 + 配了 CLI 凭据」的设备的内部日志。"""
    from models import Server

    servers = db.query(Server).filter(
        Server.device_kind == "network",
        Server.cli_username != "",
    ).all()
    ok = fail = inserted = skipped = skipped_unsupported = 0
    errors = []
    for s in servers:
        plan = collect_plan(s)
        if not plan["supported"]:
            # 🚨 不支持的设备**也要记一次状态**：早先这里只 `continue`，
            # 结果页面上「上次采集」永远停在手动点过的那一次，
            # 用户看不出"调度器其实一直在跳过它"。
            skipped_unsupported += 1
            try:
                record_state(db, s, {"ok": False, "unsupported": True,
                                     "error": plan["reason"]})
            except Exception:  # noqa: BLE001
                db.rollback()
            continue
        try:
            r = collect_device_logs(db, s)
        except Exception as e:  # noqa: BLE001
            r = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        try:
            record_state(db, s, r)
        except Exception:  # noqa: BLE001
            db.rollback()
        if r.get("ok"):
            ok += 1
            inserted += int(r.get("inserted") or 0)
            skipped += int(r.get("skipped") or 0)
        else:
            fail += 1
            if r.get("error"):
                errors.append(f"{s.name}: {r['error']}")
    return {
        "checked": len(servers), "ok": ok, "failed": fail,
        "inserted": inserted, "skipped": skipped,
        "skipped_unsupported": skipped_unsupported, "errors": errors,
    }
