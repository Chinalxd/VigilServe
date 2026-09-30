"""方案 B：网络设备自动识别（厂商 / 型号 / 类别）。

为什么不让管理员手填
──────────────────
网络设备的型号命名长得离谱（``S5720-28X-SI-AC``、``CE6881-48S6CQ``），
让管理员照着设备标签敲一遍既慢又容易错。SNMP 的 ``sysObjectID`` 和
``sysDescr`` 里这些信息本来就有，直接读出来更准，管理员只需要核对/纠错。

两套手段，互为兜底
──────────────────
1. **sysObjectID 的企业号**（``1.3.6.1.4.1.<enterprise>``）—— IANA 统一分配，
   最权威。华为 2011、华三 25506、思科 9、锐捷 4881 ...
2. **sysDescr 关键字** —— 设备自述的那句话（``Huawei Versatile Routing
   Platform Software ...``）。企业号没登记的新厂商靠它兜底。

型号只能从 sysDescr 里正则抠：MIB 里没有「型号」这个标准节点，各家把型号
写在自述串的不同位置，所以下面是「按厂商优先级排的一串正则」，命中即用。

识别不出来怎么办
────────────────
返回 ``vendor=''`` / ``category='other'``，**不猜**。页面上显示「未识别」，
管理员可以手填 —— 宁可空着，也不要拿一个错误型号误导后面看的人。
"""
from __future__ import annotations

import re

# 只列国内机房常见的。没登记的走 sysDescr 关键字，识别不出就留空。
ENTERPRISE_VENDOR = {
    "2011": "华为",
    "25506": "华三",
    "43": "华三",
    "3902": "中兴",
    "9": "思科",
    "4881": "锐捷",
    "2636": "Juniper",
    "14988": "MikroTik",
    "12356": "飞塔",
    "31624": "深信服",
    "35047": "山石",
    "6574": "群晖",
    "24681": "QNAP",
    "4526": "NETGEAR",
    "11": "惠普",
    "232": "惠普",
    "674": "戴尔",
    "8072": "net-snmp",
    "2021": "net-snmp",
}

VENDOR_KEYWORDS = [
    ("huawei", "华为"),
    ("vrp", "华为"),
    ("h3c", "华三"),
    ("comware", "华三"),
    ("cisco", "思科"),
    ("ruijie", "锐捷"),
    ("rgos", "锐捷"),
    ("juniper", "Juniper"),
    ("junos", "Juniper"),
    ("mikrotik", "MikroTik"),
    ("routeros", "MikroTik"),
    ("fortinet", "飞塔"),
    ("fortigate", "飞塔"),
    ("sangfor", "深信服"),
    ("hillstone", "山石"),
    ("zte", "中兴"),
    ("maipu", "迈普"),
    ("aruba", "Aruba"),
    ("hpe", "惠普"),
    ("hp ", "惠普"),
    ("tplink", "TP-LINK"),
    ("tp-link", "TP-LINK"),
    ("d-link", "D-Link"),
    ("netgear", "NETGEAR"),
    ("synology", "群晖"),
    ("qnap", "QNAP"),
]

# 类别判定：关键字 类别
# 顺序即优先级：防火墙要在交换机之前判（华为 USG 的 sysDescr 里也带 "Switch" 字样
# 的情况不多，但 FortiGate 一类确实会同时命中，防火墙语义更强，放前面）。
CATEGORY_KEYWORDS = [
    ("firewall", [
        "firewall", "usg", "secpath", "fortigate", "ngfw", "防火墙",
        "asa", "palo alto", "pan-os", "srx", "screenos",
    ]),
    ("ap", [
        "access point", "wireless ap", "wap", "无线接入", "wlan ap",
        "aironet", "unifi",
    ]),
    ("router", [
        "router", "路由器", "msr", "isr", "ar1", "ar2", "ar6", "neighbor",
        "routeros", "cloud engine router",
    ]),
    ("switch", [
        "switch", "交换机", "catalyst", "nexus", "ethernet switch",
        "rg-nbs", "rg-s", "ce6", "ce5", "ce88",
    ]),
    ("storage", [
        "synology", "diskstation", "qnap", "nas ", "storage", "存储",
    ]),
    ("server", [
        "linux", "windows", "freebsd", "esxi", "vmware", "server",
    ]),
]

# 类别 中文名（页面展示用）
CATEGORY_LABELS = {
    "switch": "交换机",
    "router": "路由器",
    "firewall": "防火墙",
    "ap": "无线 AP",
    "storage": "存储 / NAS",
    "server": "服务器",
    "other": "其他设备",
}

# 每条都按"命中里取最长"来用（见 `_extract_model`）：同一串文本里同一个型号常常
# 收尾一律用 `(?![A-Za-z0-9])` 而不是 `\b`：群晖的 `DS920+` 末尾那个 + 是非单词
MODEL_PATTERNS = [
    r"\b(RG-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",      # 锐捷 RG-S5750-28GT4XS
    r"\b(FortiGate[-\s]?[A-Za-z0-9]+)(?![A-Za-z0-9])",
    r"\b(WS-C[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",     
    r"\b(USG[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",      # 华为防火墙 USG6525E
    r"\b(CE[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",       # 华为数据中心交换机 CE6881-48S6CQ
    r"\b(MSR[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",
    r"\b(SR[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",
    r"\b(S\d{3,5}[A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])", # 华为/H3C 交换机 S5720-28X-SI
    r"\b(AR\d{3,4}[A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",
    r"\b(F\d{3,4}[A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])", # H3C 防火墙 F1000-AK
    r"\b(C\d{3,4}[A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",
    r"\b(N[23579]K[A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",
    r"\b(AP\d{3,4}[A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",
    r"\b(DS\d{3,4}[A-Za-z0-9]*\+?)(?![A-Za-z0-9])",
    r"\b(TS-[A-Za-z0-9]+)(?![A-Za-z0-9])",
]

# 这一层比 sysDescr 关键字可靠得多：华为交换机的自述串里根本没有 "Switch"
# 这个词（"Huawei Versatile Routing Platform Software ... S5720-28X-SI"），
# 光靠关键字会全落进 other。各家的型号首字母是有规律的，所以先看型号。
# 顺序即优先级（防火墙 / AP 要靠前，避免被交换机规则抢走）。
MODEL_CATEGORY_RULES = [
    ("firewall", r"^(USG\d?|F\d{3,4}|ASA\d*|SRX\d*|PA-\d|FORTIGATE|FG-\d|NGFW)"),
    ("ap", r"^(AP\d{3,4}|WA\d{3,4}|AIR-[A-Z]?\d|AIRONET|RG-AP|EAP\d*)"),
    ("router", r"^(AR\d{3,4}|MSR\d*|SR\d{2,4}|ISR\d*|ASR\d*|NE\d{2,4}|RG-EG|EG\d*|ER\d*|RG-RSR)"),
    ("switch", r"^(S\d{3,5}|CE\d{3,4}|WS-C\d|C\d{3,4}|N[23579]K|NEXUS|RG-S\d*|RG-NBS)"),
    ("storage", r"^(DS\d{3,4}|RS\d{3,4}|TS-\d)"),
]

MODEL_NOISE = {
    "SNMP", "SNMPV2", "SNMPV3", "MIB", "CPU", "RAM", "GB", "MB", "SSH",
    "SSL", "TLS", "AES", "SHA", "MD5", "DES", "IPV4", "IPV6", "TCP", "UDP",
    "HTTP", "HTTPS", "FTP", "TFTP", "NTP", "SYSLOG", "VLAN", "LACP", "STP",
    "OSPF", "BGP", "RIP", "ISIS", "NAT", "ACL", "QOS", "DHCP", "DNS", "AAA",
}


def enterprise_number(sys_object_id: str) -> str:
    """从 sysObjectID 里取 IANA 企业号。

    两种常见写法都兼容：
    * ``1.3.6.1.4.1.2011.2.3.4``      —— 数字形式（pysnmp 关闭 MIB 解析时给这个）
    * ``SNMPv2-SMI::enterprises.2011.2.3`` —— 名字形式
    """
    raw = str(sys_object_id or "").strip()
    if not raw:
        return ""
    parts = [p for p in re.split(r"[.:]+", raw) if p]
    for i, p in enumerate(parts):
        if p.lower() == "enterprises" and i + 1 < len(parts) and parts[i + 1].isdigit():
            return parts[i + 1]
    head = ["1", "3", "6", "1", "4", "1"]
    if len(parts) > len(head) and parts[:len(head)] == head and parts[len(head)].isdigit():
        return parts[len(head)]
    return ""


def _match_keywords(text: str, table) -> str:
    for kw, value in table:
        if kw in text:
            return value
    return ""


def _match_category(text: str) -> str:
    for category, keywords in CATEGORY_KEYWORDS:
        for kw in keywords:
            if kw in text:
                return category
    return ""


def _extract_model(text: str) -> str:
    """抠型号。命中多条时取**最长**的那条。

    Cisco 的自述串里 "C2960" 和 "C2960-LANBASEK9-M" 会同时出现，取第一个只能
    拿到被截短的前者 —— 所以这里不"命中即用"，而是把所有候选比一遍。
    """
    best = ""
    for pattern in MODEL_PATTERNS:
        for m in re.finditer(pattern, text):
            cand = m.group(1).strip()
            if cand.upper() in MODEL_NOISE:
                continue
            if len(cand) < 3:
                continue
            if len(cand) > len(best):
                best = cand
    return best


def _category_from_model(model: str) -> str:
    """型号前缀 → 类别。识别不出返回 ''（交给后面的关键字 / 端口数兜底）。"""
    m = str(model or "").upper()
    if not m:
        return ""
    for category, pattern in MODEL_CATEGORY_RULES:
        if re.match(pattern, m):
            return category
    return ""


def identify(sys_object_id: str = "", sys_descr: str = "", interface_count: int = 0) -> dict:
    """识别设备档案。

    返回 ``{vendor, category, model, category_label, sys_object_id}``。
    识别不出来的字段是空串 / ``other``，**不猜**。
    """
    oid = str(sys_object_id or "").strip()
    descr = str(sys_descr or "")
    descr_lower = descr.lower()

    ent = enterprise_number(oid)
    vendor = ENTERPRISE_VENDOR.get(ent, "") if ent else ""
    if vendor == "net-snmp":
        # 不说明厂商，交给关键字（可能识别出群晖 / QNAP）
        vendor = ""
    if not vendor:
        vendor = _match_keywords(descr_lower, VENDOR_KEYWORDS)

    model = _extract_model(descr)

    # 3) 类别：型号前缀 > sysDescr 关键字 > 端口数反推
    # 型号优先是因为华为/华三的自述串里压根不写 "Switch" 这个词。
    category = _category_from_model(model) or _match_category(descr_lower)
    if not category:
        if interface_count >= 16:
            category = "switch"
        elif interface_count >= 4:
            category = "router"
        else:
            category = "other"

    return {
        "vendor": vendor,
        "category": category,
        "category_label": CATEGORY_LABELS.get(category, "其他设备"),
        "model": model,
        "sys_object_id": oid,
        "sys_descr": descr,
    }


def profile_from_snmp(result: dict) -> dict:
    """直接吃 `snmp_collector.collect_snmp_device()` 的返回体。"""
    if not isinstance(result, dict) or not result.get("ok"):
        return {}
    return identify(
        sys_object_id=result.get("sys_object_id", ""),
        sys_descr=result.get("sys_descr", ""),
        interface_count=len(result.get("interfaces") or []),
    )
