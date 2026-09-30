"""S5.2：SNMPv3 采集（网络设备：交换机 / 路由器 / 防火墙）。

为什么走 SNMP
────────────
Agent 装不进交换机，而交换机恰恰是最该被监控的设备（端口 down 了整个网段就断）。
SNMP 是这类设备的通用语言：**被管设备上不需要装任何东西**，服务端持凭据主动去问。

只做 v3
───────
v1/v2c 的团体名是明文在网线上跑的，抓个包就拿到"只读密码"。既然是新做的模块，
不给自己留这个口子 —— `snmp_version` 字段留着，但只实现 3。
v3 的 USM：用户名 + 鉴权（HMAC-SHA/MD5）+ 可选加密（AES/DES）。

采什么（通用 MIB 优先，厂商无关）
────────────────────────────────
* 系统组 `1.3.6.1.2.1.1`      —— sysDescr / sysName / sysUpTime / sysLocation
* 接口表 IF-MIB `1.3.6.1.2.1.2.2.1` + ifXTable `1.3.6.1.2.1.31.1.1.1`
  —— 端口名 / 状态 / 流量 / 错包 / 速率 / 描述
  —— 流量优先取 **ifHCInOctets（64 位）**：千兆口跑满几分钟就把 32 位计数器绕回来了，
     32 位值在高速口上算出来的速率是错的（这是 SNMP 监控最经典的坑）。
* HOST-RESOURCES `1.3.6.1.2.1.25` —— hrProcessorLoad（CPU）/ hrStorageTable（内存）
  —— 交换机不一定实现，取不到就当"该设备不提供"，不臆造。

怎么跑
──────
`collect_snmp_device(server)` 是**同步**入口（APScheduler 的线程里调）。
pysnmp 7 是全异步 API，所以内部用 `asyncio.run()` 包一层 —— 运行在调度线程里，
不会碰 FastAPI 的事件循环（后端是同步 SQLAlchemy，绝不能让它进主循环）。
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"

IFX_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IFX_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IFX_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IFX_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IFX_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

OID_HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"
OID_HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
OID_HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
OID_HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"
OID_HR_STORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"
OID_HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
OID_HR_STORAGE_UNITS = "1.3.6.1.2.1.25.2.3.1.4"

# Linux / 群晖 NAS 的补充指标（2026-09-21 现场反馈加）
# NAS（Linux）会把空闲内存拿去做磁盘缓存，hrStorageTable 算出来的"内存使用率"
# 常年 90%+，那不是告警，是缓存。真正要盯的是"应用实际占用"
# 分项只有 net-snmp 自带的 UCD-SNMP-MIB 给得起。
OID_UCD_MEM_TOTAL = "1.3.6.1.4.1.2021.4.5"
OID_UCD_MEM_AVAIL = "1.3.6.1.4.1.2021.4.6"
OID_UCD_MEM_BUFFER = "1.3.6.1.4.1.2021.4.14"
OID_UCD_MEM_CACHED = "1.3.6.1.4.1.2021.4.15"

# 每一列的含义是 2026-09-21 在 RISUN NAS（DSM，sysObjectID 报的是 net-snmp 的
SYNO_DISK_NAME = "1.3.6.1.4.1.6574.2.1.1.2"
SYNO_DISK_MODEL = "1.3.6.1.4.1.6574.2.1.1.3"
SYNO_DISK_STATUS = "1.3.6.1.4.1.6574.2.1.1.5"
SYNO_DISK_TEMP = "1.3.6.1.4.1.6574.2.1.1.6"
SYNO_RAID_NAME = "1.3.6.1.4.1.6574.3.1.1.2"
SYNO_RAID_STATUS = "1.3.6.1.4.1.6574.3.1.1.3"
# 群晖没公开完整的状态枚举，实测"正常"是 1。**只认 1 为正常**，其余一律报异常
# 并把原始值带上，不认识的取值不许自己编文案说它正常。
SYNO_STATUS_OK = "1"

# 硬件健康：电源 / 风扇 / 温度 / 整机功率（2026-09-21 现场探 + 华为官方文档核对）
# ③ 标准 ENTITY-SENSOR-MIB（1.3.6.1.2.1.99），华为和这台 NAS 都没开，
# 但思科 / H3C / 锐捷常见，留着给别的设备用
# 温度 1.1.1.1.11 = 当前温度(℃) .12 = 温度阈值(℃)，只有主控板那一行有值，其余行是 0
# 风扇 10.1：.1 槽位 .2 编号 .3 已注册 .4 调速模式 .5 转速(满速百分比) .6 在位 .7 状态(1正常/2异常)
# 电源 18.1：.1 槽位 .2 编号 .4 交直流 .5 在位 .6 状态(1供电/2不供电/3休眠/4未知)
OID_HW_TEMP = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11"
OID_HW_TEMP_THRESHOLD = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.12"
OID_HW_FAN_TABLE = "1.3.6.1.4.1.2011.5.25.31.1.1.10.1"
OID_HW_PWR_TABLE = "1.3.6.1.4.1.2011.5.25.31.1.1.18.1"
OID_HW_POWER_TABLE = "1.3.6.1.4.1.2011.5.25.31.1.1.14.1"
HW_FAN_SN, HW_FAN_SPEED, HW_FAN_PRESENT, HW_FAN_STATE = "2", "5", "6", "7"
HW_PWR_SN, HW_PWR_STATE = "2", "6"
HW_POWER_TOTAL, HW_POWER_USED, HW_POWER_REMAIN = "2", "3", "4"

# .4.N = 第 N 个风扇的状态。实测"正常"都是 1（和磁盘/RAID 那条一样，只认 1）。
SYNO_SYS_STATUS = "1.3.6.1.4.1.6574.1.1.0"
SYNO_SYS_TEMP = "1.3.6.1.4.1.6574.1.2.0"
SYNO_SYS_POWER = "1.3.6.1.4.1.6574.1.3.0"
SYNO_FAN_TABLE = "1.3.6.1.4.1.6574.1.4"

# 思科 ENVMON（部分国产设备也兼容）：1=normal 2=warning 3=critical 4=shutdown
OID_CISCO_TEMP_STATUS = "1.3.6.1.4.1.9.9.13.1.3.1.3"
OID_CISCO_FAN_STATUS = "1.3.6.1.4.1.9.9.13.1.4.1.3"
OID_CISCO_PSU_STATUS = "1.3.6.1.4.1.9.9.13.1.5.1.3"
CISCO_ENV_OK = "1"

# 通用 ENTITY-MIB：物理实体的类别 + 运行状态（1=up 2=down 6=notPresent …）
OID_ENT_PHYSICAL_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
OID_ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
OID_ENT_PHYSICAL_OPER = "1.3.6.1.2.1.47.1.1.1.1.16"
ENT_CLASS_PSU, ENT_CLASS_FAN = "6", "7"
ENT_OPER_OK = "1"

TIMEOUT = 5
RETRIES = 1
MAX_REPETITIONS = 25


# 采集熔断（2026-09-21 加）
# 起因（真机实证）：某台采集机曾带着错误的 SNMPv3 参数去采华为 S5731S，
# 这台服务器被反复锁了 34 轮。华为的 "SNMP 登录攻击防御" 是**一次认证失败就锁源 IP
# 约 10 秒，锁定期内静默丢包，且在锁定期内继续打会把锁越续越长**。
# 而调度器当时是每 5 分钟无条件重试一次：凭据错 失败 5 分钟后再错 再锁，
# 永远停不下来。所以必须在**采集器这一侧**自己踩刹车，不能指望设备宽容。
# 分两类处理，因为两类错误的"重试成本"完全不同
# · auth（用户名/口令/鉴权协议/加密协议不对），**重试毫无意义且必然继续锁 IP**，
# 所以阈值很低，一确认就长时间停采，等管理员改对凭据。
# · network（超时/不可达），可能只是抖动或设备重启，阈值放宽；
# 但连续失败也可能是"被锁了"，所以同样要有上限，不能无限打。
AUTH_FAIL_TRIP = 2
NET_FAIL_TRIP = 5
# 熔断时长（分钟），按"这台设备已经被熔断过几次"递增，反复犯同一个错就罚得更久。
PAUSE_MINUTES_AUTH = (30, 120, 480)
PAUSE_MINUTES_NET = (15, 30, 60)

# 那段文案是这里自己生成的，稳定可控，不用去猜设备回的英文原话。
_AUTH_ERROR_KEYS = (
    "鉴权失败",
    "解密失败",
    "没有这个 snmpv3 用户名",
    "不接受这组 snmpv3 参数",
    "不支持这个安全级别",
)

_NET_ERROR_KEYS = (
    "没有响应",
    "连接超时",
    "超时",
    "不可达",
    "拒绝连接",
    "地址解析失败",
    "时间窗",
)


def classify_snmp_error(msg: str) -> str:
    """把采集失败归成 auth / network / other，供熔断判断用。

    返回 'auth' 时**严禁继续重试** —— 凭据错就是凭据错，再打只会把源 IP 锁得更久。
    """
    low = str(msg or "").lower()
    if any(k in low for k in _AUTH_ERROR_KEYS):
        return "auth"
    if any(k in low for k in _NET_ERROR_KEYS):
        return "network"
    return "other"


def snmp_pause_state(snmp_info: dict):
    """读熔断状态。返回 (是否仍在熔断中, 截止时间的 iso 串 or None)。

    熔断截止时间存在 extra_config['snmp']['paused_until'] 里 —— 沿用已有的
    extra_config，不再加数据库列（省一次迁移，也避免动生产表结构）。
    """
    until = (snmp_info or {}).get("paused_until")
    if not until:
        return False, None
    try:
        dt = datetime.fromisoformat(until)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return False, None
    return datetime.now(timezone.utc) < dt, until


def _pause_minutes(kind: str, pause_count: int) -> int:
    table = PAUSE_MINUTES_AUTH if kind == "auth" else PAUSE_MINUTES_NET
    idx = max(0, int(pause_count or 0))
    return table[min(idx, len(table) - 1)]


# 凭据 pysnmp 的 USM 对象


def _auth_protocol(name: str):
    from pysnmp.hlapi.v3arch.asyncio import (
        usmHMAC128SHA224AuthProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol,
        usmHMAC384SHA512AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        usmNoAuthProtocol,
    )

    return {
        "MD5": usmHMACMD5AuthProtocol,
        "SHA": usmHMACSHAAuthProtocol,
        "SHA1": usmHMACSHAAuthProtocol,
        "SHA224": usmHMAC128SHA224AuthProtocol,
        "SHA256": usmHMAC192SHA256AuthProtocol,
        "SHA384": usmHMAC256SHA384AuthProtocol,
        "SHA512": usmHMAC384SHA512AuthProtocol,
        "NONE": usmNoAuthProtocol,
    }.get(str(name or "").upper(), usmHMACSHAAuthProtocol)


def _priv_protocol(name: str):
    """加密协议名 → pysnmp 的 priv 协议常量。

 **AES192 / AES256 在 RFC 3826 里根本没有定义**（3826 只有 AES-128），业界
    有 **两种互不兼容的密钥扩展方言**，加密密钥算出来不一样，用错就解不开：

      * **Reeder**（思科系）—— pysnmp 叫 `usmAesCfb192Protocol` / `usmAesCfb256Protocol`，
        文档里也写 "Also known as AES-256-Cisco"
      * **Blumenthal**（华为 / 惠普 / H3C 系）—— `usmAesBlumenthalCfb192/256Protocol`

    用错方言时设备回的是 `Ciphering services not available or ciphertext is broken`
    （**不是**"口令错"，非常容易被误读）。真机实证 2026-09-20：华为 S5731S 配
    `privacy-mode aes256`，填 AES256 走 Reeder 必失败、走 Blumenthal 才通。

    所以这里把两套方言**都收成可选项**，采集时按 `_usm_candidates()` 给出的顺序自动试。
    """
    from pysnmp.hlapi.v3arch.asyncio import (
        usmAesBlumenthalCfb192Protocol,
        usmAesBlumenthalCfb256Protocol,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
        usm3DESEDEPrivProtocol,
        usmDESPrivProtocol,
        usmNoPrivProtocol,
    )

    return {
        "DES": usmDESPrivProtocol,
        "3DES": usm3DESEDEPrivProtocol,
        "AES": usmAesCfb128Protocol,
        "AES128": usmAesCfb128Protocol,
        "AES192": usmAesCfb192Protocol,
        "AES256": usmAesCfb256Protocol,
        "AES192-BLUMENTHAL": usmAesBlumenthalCfb192Protocol,
        "AES256-BLUMENTHAL": usmAesBlumenthalCfb256Protocol,
        "NONE": usmNoPrivProtocol,
    }.get(str(name or "").upper(), usmAesCfb128Protocol)


# **首选必须放 Blumenthal，不能放 Reeder。** 这不是口味问题，是踩出来的
# 华为交换机有"SNMP 登录攻击防御"，**一次登录失败就把源 IP 锁 10 秒左右，
# 锁定期间所有 SNMP 请求被静默丢弃（回都不回）**；而且在锁定期内继续重试
# 会把锁**越续越长**（实测被续到过 5 分钟）。所以"先试错的方言、失败了再换"
# 这条路走不通，换的那次必定落在锁窗口里，只会把 IP 锁得更久。
# 一次失败计数都不产生。Reeder 只作为思科系的兜底，见 _DIALECT_RETRY_DELAY。
_PRIV_DIALECTS = {
    "AES192": ("AES192-BLUMENTHAL", "AES192"),
    "AES256": ("AES256-BLUMENTHAL", "AES256"),
}

# 换方言重试前的冷却。必须大于设备的 SNMP 失败锁定窗口（华为实测 ~10s），
# 否则重试的包正好撞在锁里被丢掉，白跑一趟还续锁。只对 AES192/256 的备选生效，
# 正常采集中命中概率极低（只有思科系设备才会走到这次重试）。
_DIALECT_RETRY_DELAY = 12


# 凭据的本地前置校验
# 有两类凭据问题**本机就能判定**，不必发包。pysnmp 自己也会拒，但拒法极难排查
# 2026-09-30 实测钉死：对着**不可达地址**（RFC 5737 的 192.0.2.1）也照样
# 在发包前抛出同一个错，换用户名、换鉴权协议都不变；口令一到 8 位就正常发出。
# 也就是说它 100% 是本机校验，把管理员引到设备侧纯属误导。
# RFC 3414 本来就要求 passphrase 至少 8 个八位组，这是标准约束，不是 pysnmp 的怪癖。
# 空格、`@#$%`、纯数字等都是**合法**口令（实测 8 位即可正常发出），所以这里只拦上面两类，
_MIN_PASSPHRASE_LEN = 8


class SnmpCredentialError(ValueError):
    """凭据本身不满足 SNMPv3 的硬性要求 —— 本机即可判定，问题不在设备上。"""


def _check_passphrase(label: str, value: str, required: bool) -> None:
    if not required:
        return
    value = value or ""
    if not value:
        raise SnmpCredentialError(f"{label}不能为空")
    if not value.isascii():
        raise SnmpCredentialError(
            f"{label}只能用 ASCII 字符（不支持中文或其他非 ASCII 字符）"
        )
    if len(value) < _MIN_PASSPHRASE_LEN:
        raise SnmpCredentialError(
            f"{label}至少 {_MIN_PASSPHRASE_LEN} 位（RFC 3414 要求），当前只有 {len(value)} 位"
        )


def validate_credentials(server) -> None:
    """发包前拦掉本就能判定的凭据问题；不满足就抛 `SnmpCredentialError`。

    安全级别的判定口径与 `build_usm()` 保持一致（空值按 authPriv 处理）。
    """
    level = str(getattr(server, "snmp_security_level", "") or "authPriv").lower()
    if level == "noauthnopriv":
        return
    _check_passphrase("鉴权口令", getattr(server, "snmp_auth_password_plain", "") or "", True)
    if level == "authpriv":
        _check_passphrase("加密口令", getattr(server, "snmp_priv_password_plain", "") or "", True)


def build_usm(server, priv_proto: str = None):
    """Server → `UsmUserData`。口令从 Fernet 密文解出来（唯一入口在模型属性上）。

    `priv_proto` 用来**临时覆盖**设备上存的加密协议（只影响这一次调用，不写库），
    供 `_usm_candidates()` 试方言用。
    """
    from pysnmp.hlapi.v3arch.asyncio import UsmUserData

    level = str(server.snmp_security_level or "authPriv").lower()
    auth_pwd = server.snmp_auth_password_plain
    priv_pwd = server.snmp_priv_password_plain

    if level == "noauthnopriv":
        return UsmUserData(server.snmp_username or "")
    if level == "authnopriv":
        return UsmUserData(
            server.snmp_username or "",
            authKey=auth_pwd or None,
            authProtocol=_auth_protocol(server.snmp_auth_proto),
        )
    return UsmUserData(
        server.snmp_username or "",
        authKey=auth_pwd or None,
        privKey=priv_pwd or None,
        authProtocol=_auth_protocol(server.snmp_auth_proto),
        privProtocol=_priv_protocol(priv_proto or server.snmp_priv_proto),
    )


def _usm_candidates(server) -> list:
    """本次采集要按顺序试的 USM 列表（通常只有一个）。

    AES192 / AES256 有 Blumenthal / Reeder 两套方言，**没法从设备侧先问出来**
    （只有发一次才知道对不对），所以这两项给两个候选：先试华为系（Blumenthal），
    失败且报的是解密类错误时再试思科系（Reeder）。其余协议只有一项，行为不变。
    """
    level = str(getattr(server, "snmp_security_level", "") or "authPriv").lower()
    if level != "authpriv":
        return [build_usm(server)]      # 不加密的级别没有方言问题
    pair = _PRIV_DIALECTS.get(str(getattr(server, "snmp_priv_proto", "") or "").upper())
    if not pair:
        return [build_usm(server)]
    out = []
    for name in pair:
        try:
            out.append(build_usm(server, name))
        except SnmpCredentialError:
            # 凭据本身不合法，不该被"换个方言再试"吞掉、再拿另一个方言去撞设备
            raise
        except Exception:  # noqa: BLE001
            pass
    return out or [build_usm(server)]


def _is_priv_dialect_error(err) -> bool:
    """判断错误是不是"加密方言/密钥扩展不一致"造成的（这种才值得换方言重试）。

 只认这一种字样。**鉴权失败（Wrong SNMP PDU digest）绝不能触发重试** ——
    那是口令问题，换方言白搭，而且华为交换机有 SNMP 限流，多打几次反而更容易被丢包。
    """
    low = str(err or "").lower()
    return ("ciphering services not available" in low
            or "ciphertext is broken" in low)


# 把 pysnmp / 网络层的原始报错翻译成管理员能照着排查的话。原始信息**同时保留**
# （截断后附在括号里），因为排障时它是唯一能拿去搜索的线索。
# 唯一的例外是 `WrongValueError`，它是**本机**错误，见 friendly_snmp_error()，
# 绝不能附"（设备返回：一堆 OID）"，那会把人引到设备侧。
# （2026-09-30 更正：此前这里记的是"v3 用户名不存在时会抛 WrongValueError"。
# 对着不可达地址实测后确认那个归因是错的，用户名不存在时 pysnmp 回的是
_ERROR_HINTS = (
    # 这条里必须带上"源 IP 被锁"的可能性：华为等设备有 SNMP 登录攻击防御，
    # **连续认证失败后会临时锁定源 IP，锁定期内静默丢包（一个包都不回）**，
    # 表现和"IP 不通 / 端口 161 错"一模一样。更要命的是在锁定期内继续点重试
    # 会把锁**越续越长**（实测被续到 5 分钟），所以文案要劝管理员"停手等一等"。
    ("no snmp response received before timeout",
     "设备没有响应（核对 IP / UDP 端口 161 / 防火墙；若刚才反复失败过，"
     "可能是设备把本机 IP 临时锁了 —— 华为这类设备锁定期会静默丢包，停手等几分钟再试，"
     "越点重试锁得越久）"),
    ("request timed out",
     "设备没有响应（核对 IP / UDP 端口 161；也可能因连续失败被设备临时锁了源 IP，"
     "等几分钟再试）"),
    ("requesttimedout",
     "设备没有响应（核对 IP / UDP 端口 161；也可能因连续失败被设备临时锁了源 IP，"
     "等几分钟再试）"),
    ("unknown usm user", "设备上没有这个 SNMPv3 用户名 —— 请核对设备上的 usm-user 配置"),
    ("unknown user name", "设备上没有这个 SNMPv3 用户名 —— 请核对设备上的 usm-user 配置"),
    # "wrongvalueerror" 不在这张表里，它必须单独处理，见 friendly_snmp_error()
    # 它实际是**本机**抛的（口令短于 8 位），映射成"设备不接受参数"会把管理员
    # 引到设备侧白查一轮。
    ("authentication failure", "SNMPv3 鉴权失败：鉴权口令不对，或鉴权协议与设备不一致"),
    # 华为交换机鉴权不过时回的就是 "Wrong SNMP PDU digest"（中间有空格，
    # 拼不成 "wrongdigest"），实测漏掉这条就会原样把英文砸到弹窗上。
    ("wrong snmp pdu digest", "SNMPv3 鉴权失败：鉴权口令不对，或鉴权协议与设备不一致"),
    ("wrongdigest", "SNMPv3 鉴权失败：鉴权口令不对，或鉴权协议与设备不一致"),
    ("decryption error", "SNMPv3 解密失败：加密口令不对，或加密协议与设备不一致"),
    ("encryption error", "SNMPv3 解密失败：加密口令不对，或加密协议与设备不一致"),
    # 设备回这句常见于三种情况，**都不是"口令错"**，所以文案不能只写口令
    # ① 两边 AES 位数不一样（界面选 AES128、设备配的是 aes256 最常见）
    # ② AES192/256 的密钥扩展方言不一样（华为系 vs 思科系，互不兼容）
    # ③ 加密口令确实填错了
    # 第二个原因系统会自动换另一套方言重试一次，两条都试完还失败才把这句话递到界面上。
    ("ciphering services not available",
     "SNMPv3 解密失败：加密协议与设备不一致（先核对设备上是 aes128 / aes192 / aes256，"
     "再把「加密协议」选成对应项；华为系与思科系的 AES192/256 密钥扩展方式互不兼容，"
     "系统已自动换另一种试过）"),
    ("ciphertext is broken",
     "SNMPv3 解密失败：加密口令不对，或加密协议与设备不一致"
     "（核对设备上是 aes128 / aes192 / aes256）"),
    ("unsupported security level", "设备不支持这个安全级别（可试 authNoPriv 或 authPriv）"),
    ("not in time window", "设备认为时间戳超窗 —— 检查两端时钟是否一致"),
    ("network is unreachable", "网络不可达 —— 本机没有到该地址的路由"),
    ("host is down", "目标主机不可达"),
    ("timed out", "连接超时 —— 地址不可达或被防火墙拦"),
    ("connection refused", "设备拒绝连接"),
    ("name or service not known", "地址解析失败，请检查 IP / 主机名"),
    ("certificate", "TLS 证书校验失败"),
)


# 错误归属：界面靠它决定"要不要提示网络类原因"
# 为什么要有这个：以前不管什么错，失败框下面都固定挂着一段
# 「常见原因：IP 不通 / UDP 161 被防火墙挡了 / 用户名或口令不对 / 安全级别与设备端
# 这段话**只在"设备根本没响应"时才成立**。设备明明回了错（unknownUserName、
# 鉴权失败、errorStatus…）时还挂着它，等于把人往网络方向带，2026-09-30 现场
# 就是这么被带偏的（真正的错在设备的 errorStatus 里，却去查了防火墙）。
# 所以：**设备有没有回应**这件事必须由后端判定，不能让界面猜文案。
KIND_NO_RESPONSE = "no-response"
KIND_DEVICE_REPLY = "device-reply"
KIND_LOCAL = "local"

_NO_RESPONSE_MARKERS = (
    "timeout", "timed out", "no snmp response",
    "network is unreachable", "host is down", "no route to host",
    "connection refused", "name or service not known",
)

# 这些**只可能是本机抛的**，设备永远不会"说"出这些词：缺依赖、库版本不对、
# 以及 pysnmp 在**发包之前**就拒掉的凭据（口令太短 / 含非 ASCII / 空口令）。
# 判成 local 的关键是界面会据此提示"查本机 / 改凭据"，而不是去查网络或设备。
_LOCAL_ERROR_MARKERS = (
    "modulenotfounderror", "no module named", "importerror",
    "attributeerror", "typeerror", "nameerror", "notimplementederror",
    "pyasn1unicodeencodeerror", "zerodivisionerror", "wrongvalueerror",
)


def error_kind(text) -> str:
    """原始报错 → 归属分类（见上面常量）。判不出来时按"设备回了错"处理。

    判定顺序：**local → no-response → device-reply**。
    local 必须最先判：`ModuleNotFoundError` 这类本机问题里也可能出现别的词，
    归属错了界面就会提示完全相反的方向（本机缺依赖却让人去查设备凭据）。

    宁可判成 device-reply：那样界面就不显示网络类提示。少提示一句没损失，
    而对着已经回了错的设备去提示"查防火墙"是会真把人带偏的。
    """
    low = str(text or "").lower()
    for mk in _LOCAL_ERROR_MARKERS:
        if mk in low:
            return KIND_LOCAL
    for mk in _NO_RESPONSE_MARKERS:
        if mk in low:
            return KIND_NO_RESPONSE
    return KIND_DEVICE_REPLY


# 不翻译的话界面上就是一串裸 OID（如 `1.3.6.1.6.3.11.2.1.3`），等于什么都没说。
# 2026-09-30 现场正是撞到这一串，它实际是设备的一句明确的话，而且是**好消息**
# 能走到 USM 之后的报告，说明用户名存在、鉴权通过、加密也没问题。
# 下面两张表是 RFC 3412（MPD 消息处理层）与 RFC 3414（USM 安全层）定义的全部计数器。
_REPORT_OID_HINTS = {
    # SNMP-MPD-MIB（1.3.6.1.6.3.11.2.1）
    "1.3.6.1.6.3.11.2.1.1": "设备不认识这个安全模型（安全模型号不对）",
    "1.3.6.1.6.3.11.2.1.2": "设备认为这个报文里有非法或自相矛盾的字段",
    "1.3.6.1.6.3.11.2.1.3": (
        "设备说：这个 PDU 没有应用能处理 —— **用户名、鉴权口令、鉴权协议都已经通过了**，"
        "问题在设备侧：这个 SNMPv3 用户多半没绑到有效的 group / MIB 视图，"
        "或者需要指定上下名（华为、华三上通常是 usm-user 没给 read-view）"),
    # SNMP-USER-BASED-SM-MIB（1.3.6.1.6.3.15.1.1）
    "1.3.6.1.6.3.15.1.1.1": "设备不支持这个安全级别（核对设备上是 authNoPriv 还是 authPriv）",
    "1.3.6.1.6.3.15.1.1.2": "设备认为时间戳超窗 —— 检查两端时钟是否一致",
    "1.3.6.1.6.3.15.1.1.3": (
        "设备上没有这个 SNMPv3 用户名 —— 请核对设备上的 usm-user 配置"
        "（注意大小写、前后空格，以及 usm-user 上有没有绑 ACL）"),
    "1.3.6.1.6.3.15.1.1.4": (
        "设备不认这个 engineID（正常握手的第一次探测也会触发一次，pysnmp 会自动带上真 "
        "engineID 重试；一直报就要查设备侧）"),
    "1.3.6.1.6.3.15.1.1.5": "SNMPv3 鉴权失败：鉴权口令不对，或鉴权协议与设备不一致",
    "1.3.6.1.6.3.15.1.1.6": "SNMPv3 解密失败：加密口令不对，或加密协议 / 方言与设备不一致",
}


def friendly_snmp_error(raw) -> str:
    """SNMP 原始报错 → 中文可操作提示（保留截断后的原文供搜索）。"""
    text = str(raw or "").strip()
    if not text:
        return "设备无响应"
    # 这**不是**本机错误，是设备的一句原话，必须翻出来。
    if text.startswith("1.3.6.1."):
        hint = (_REPORT_OID_HINTS.get(text)
                or _REPORT_OID_HINTS.get(text.rstrip(".0")))
        if hint:
            return f"{hint}（设备返回：{text}）"
        return (f"设备回了一份报告 PDU，计数器 OID {text}"
                "（这一串还没收录，把它发给我们就能补进去）")
    low = text.lower()
    # 单独拦这一条，且**不附原文**：`WrongValueError` 是本机抛的（pysnmp 只把自家
    # MIB 的 OID 塞在里面），跟设备一点关系都没有，对着不可达地址也照样报它。
    # 配上"（设备返回：…）"会让人去查设备，实测就是这么被带偏的。
    # 正常情况下 `validate_credentials()` 已经先拦掉了，这里是兜底。
    if "wrongvalueerror" in low:
        return (f"SNMPv3 口令不满足要求：鉴权／加密口令至少 {_MIN_PASSPHRASE_LEN} 位，"
                "且只能使用 ASCII 字符（这是本机校验，与设备无关）")
    if "pyasn1unicodeencodeerror" in low:
        return "SNMPv3 口令只能用 ASCII 字符，不支持中文或其他非 ASCII 字符（本机校验，与设备无关）"
    for key, msg in _ERROR_HINTS:
        if key in low:
            return msg if text.lower() == key else f"{msg}（设备返回：{text[:70]}）"
    return f"SNMP 交互失败：{text[:100]}"


# 这是**设备明确回了一个错**，和"超时 / 没响应"完全是两码事，但以前这里
# 设备明明说了话 我们当它没说话 界面上显示「设备未返回 sysDescr」
# 2026-09-30 现场就是被这句话带偏的：管理员照着"IP 不通 / 端口被挡 / 口令不对"
# 查了一圈，其实设备早就把真正的原因写在 status 里了。设备说了什么就照实转达。
_ERROR_STATUS_HINTS = {
    1: ("tooBig", "设备说回应包太大（tooBig）"),
    2: ("noSuchName", "设备说没有这个 OID（noSuchName）—— 老设备是 SNMPv1 语义，"
                     "多半是 SNMPv3 用户绑的 MIB 视图里不含这个对象"),
    3: ("badValue", "设备说这是错误的值（badValue）"),
    4: ("readOnly", "设备说这个变量是只读的（readOnly）"),
    5: ("genErr", "设备内部错误（genErr）—— 一般是设备侧 SNMP 代理异常，"
                  "重启设备的 SNMP 服务或稍后再试"),
    6: ("noAccess", "设备说这个 OID 无权访问（noAccess）—— "
                    "SNMPv3 用户没有被授予该 MIB 视图"),
    7: ("wrongType", "设备说值的类型不对（wrongType）"),
    8: ("wrongLength", "设备说值的长度不对（wrongLength）"),
    9: ("wrongEncoding", "设备说编码不对（wrongEncoding）"),
    10: ("wrongValue", "设备说值不对（wrongValue）"),
    11: ("noCreation", "设备说不能新建该对象（noCreation）"),
    12: ("inconsistentValue", "设备说值不一致（inconsistentValue）"),
    13: ("resourceUnavailable", "设备资源不足（resourceUnavailable）"),
    14: ("commitFailed", "设备提交失败（commitFailed）"),
    15: ("undoFailed", "设备回滚失败（undoFailed）"),
    16: ("authorizationError", "设备拒绝了这次访问（authorizationError）—— "
                              "SNMPv3 用户没有对应 MIB 视图的权限"),
    17: ("notWritable", "设备说这个变量不可写（notWritable）"),
    18: ("inconsistentName", "设备说对象名不一致（inconsistentName）"),
}


def _status_code(status) -> int:
    """errorStatus → int。0 = noError；解析不出来按 0 处理（不因它改变主流程）。"""
    try:
        return int(status)
    except Exception:  # noqa: BLE001
        return 0


def error_status_hint(status, idx=None) -> str:
    """errorStatus ≠ 0 → 中文提示。**这是设备的原话**，必须原样带到界面上。"""
    code = _status_code(status)
    named = _ERROR_STATUS_HINTS.get(code)
    label = f"{named[0]}({code})" if named else str(code)
    tail = f"，出错位置是第 {int(idx)+1} 个 varbind" if idx not in (None, "", 0) else ""
    if named:
        return (f"{named[1]} —— 这是设备在回应包里回的 errorStatus={label}{tail}"
                "（设备收到了请求并作出了回应）")
    return (f"设备在回应包里回了未预期的 errorStatus={label}{tail}"
            "（设备收到了请求并作出了回应）")


def describe_varbind(var_binds) -> str:
    """把"实际拿到的是什么"说清楚。

    以前只写一句「设备未返回 sysDescr」，既看不出拿到的是空字符串还是别的类型，
    也看不出回应里到底有几个 varbind —— 排查时等于没有信息。
    """
    if not var_binds:
        return "回应包里一个 varbind 都没有"
    try:
        _name, value = var_binds[0]
    except Exception:  # noqa: BLE001
        return "varbind 结构异常"
    try:
        shown = repr(value.prettyPrint())
    except Exception:  # noqa: BLE001
        shown = repr(value)
    return f"{type(value).__name__} = {shown}（回应里共 {len(var_binds)} 个 varbind）"




def _scalar(result):
    """pysnmp 的 varBind 值 → Python 原生（字符串/整数/None）。

 OctetString **不能**直接用 `prettyPrint()`：只要里面有一个字节不是可打印
    ASCII，pysnmp 就把整串打成十六进制（实测 `to-办公区接入交换机` →
    `0x746f2de58a9e...`）。中文端口描述 / 中文 sysLocation 在国内部署里很常见，
    全都会变成一串看不懂的东西。所以字符串一律自己按字节解码。
    """
    if result is None:
        return None
    try:
        from pysnmp.proto.rfc1902 import OctetString

        if isinstance(result, OctetString):
            return _decode_octets(bytes(result))
        return result.prettyPrint()
    except Exception:  # noqa: BLE001
        return None


def _decode_octets(raw: bytes) -> str:
    """字节 → 文本。设备端的编码不统一，UTF-8 优先，回退 GBK（国产设备常见），
    再不行按 latin-1 兜底（不会失败，最多不美观）。"""
    for enc in ("utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def _to_int(v, default=0) -> int:
    try:
        return int(str(v).strip())
    except Exception:  # noqa: BLE001
        return default


async def _walk_column(engine, usm, target, ctx, oid) -> dict:
    """walk 一列，返回 {ifIndex: 值字符串}。取不到返回空 dict（不抛）。

    pysnmp 7 里 `bulk_walk_cmd` 是 async generator（老的 `bulk_cmd` 只做单次 GETBULK）。

 **`lexicographicMode=False` 绝对不能省** —— 这个参数**默认是 `True`**，
    意思是"从起点一路走到 MIB 尽头"（pysnmp 源码 `options.get("lexicographicMode", True)`）。
    不传它，walk `ifX ifName` 就会顺着字典序继续走 ifDescr → ifType → …… 把整个
    `1.3.6.1.2.1.31` 乃至后面所有子树全部拉回来，我们只是**本地丢弃**不匹配的条目，
    线上却打了几千个 PDU —— 真机实测：一次采集 **20 分钟都跑不完**，
    而单发 sysDescr 只要 1 秒。当时注释里写的"默认就限定在给定 OID 前缀内"是错的。
    传 `False` 后，走出这个 OID 前缀它自己就停（`initialVars[0].isPrefixOf(...)`）。
    """
    from pysnmp.hlapi.v3arch.asyncio import bulk_walk_cmd, ObjectIdentity, ObjectType

    out = {}
    prefix = oid + "."
    try:
        it = bulk_walk_cmd(
            engine, usm, target, ctx,
            0, MAX_REPETITIONS,
            ObjectType(ObjectIdentity(oid)),
            # 不要让 pysnmp 把 OID 解析成 MIB 名字（那样前缀比较就没法做了）
            lookupMib=False,
            # 走出这一列就停，别顺着字典序把整棵 MIB 走完（见上面注释）
            lexicographicMode=False,
        )
        async for _ind, _status, _idx, var_binds in it:
            for vb in var_binds:
                try:
                    name = str(vb[0])
                    # GETBULK 会把前缀之后的下一批 OID 一起带回来（这是协议行为，
                    # 不是设备的问题），所以必须自己限定前缀，否则 hrStorage 的值
                    # 会被当成端口数据（实测：ifName 的 walk 里混进了 hrStorageUsed）。
                    if not name.startswith(prefix):
                        continue
                    suffix = name[len(prefix):]
                    if "." in suffix or not suffix.isdigit():
                        continue
                    out[int(suffix)] = _scalar(vb[1])
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        return out
    return out


async def _walk_subtree(engine, usm, target, ctx, oid) -> dict:
    """走一整棵子树，返回 {后缀字符串: 值}。

    和 `_walk_column` 的差别只在**后缀允许带点**：华为的风扇表 / 电源表索引是
    "<槽位>.<编号>" 两段（实测 `10.1.2.0.7` = 第 2 列、槽位 0、编号 7），而
    `_walk_column` 见到带点的后缀就直接丢掉，这两张表会整个空掉。
    同样必须传 `lexicographicMode=False`，否则会顺着字典序把后面的子树全走完。
    """
    from pysnmp.hlapi.v3arch.asyncio import bulk_walk_cmd, ObjectIdentity, ObjectType

    out = {}
    prefix = oid + "."
    try:
        it = bulk_walk_cmd(
            engine, usm, target, ctx,
            0, MAX_REPETITIONS,
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False,
            lexicographicMode=False,
        )
        async for _ind, _status, _idx, var_binds in it:
            for vb in var_binds:
                try:
                    name = str(vb[0])
                    if not name.startswith(prefix):
                        continue
                    out[name[len(prefix):]] = _scalar(vb[1])
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        return out
    return out


async def _get_many(engine, usm, target, ctx, oids) -> dict:
    from pysnmp.hlapi.v3arch.asyncio import get_cmd, ObjectIdentity, ObjectType

    out = {}
    try:
        _ind, _status, _idx, var_binds = await get_cmd(
            engine, usm, target, ctx,
            *[ObjectType(ObjectIdentity(o)) for o in oids],
            # 同一原因：不解析 MIB 名，返回体的 key 才是我们传进去的那个数字 OID
            lookupMib=False,
        )
        for vb in var_binds:
            try:
                out[str(vb[0])] = _scalar(vb[1])
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return out


async def _collect_async(server) -> dict:
    """采集入口：按 `_usm_candidates()` 顺序试，第一个通的就用它的结果。

    这里**每次尝试都新建一个 SnmpEngine** —— pysnmp 的 USM 用户是注册在引擎上的，
    同一个引擎上先后注册"同名用户 + 不同加密协议"会互相踩，换引擎最干净。
    非 AES192/256 时候选只有一个，等于退化成原来的单次采集。
    """
    from pysnmp.hlapi.v3arch.asyncio import ContextData, SnmpEngine, UdpTransportTarget

    # 最后一个能"在发包前拦住"的位置（`collect_snmp_device` 是调度、测试连接、
    # 新增/编辑设备三条路线的共同入口）。口令短于 8 位或含非 ASCII 时，
    # pysnmp 会在本地抛一个只带自家 MIB OID 的 WrongValueError，见上方
    # `_check_passphrase` 的说明。提前拦掉，顺带省掉一次注定失败的发包。
    validate_credentials(server)

    # pysnmp 7：地址不在 __init__ 里给，要用异步工厂 create()（它会解析地址再回填）
    target = await UdpTransportTarget.create(
        (server.ip_address, int(server.snmp_port or 161)),
        timeout=TIMEOUT,
        retries=RETRIES,
    )
    ctx = ContextData(contextName=(server.snmp_context or ""))

    candidates = _usm_candidates(server)
    result = {"ok": False, "error": "未开始采集", "kind": KIND_DEVICE_REPLY}
    first_result = None
    for idx, usm in enumerate(candidates):
        engine = SnmpEngine()
        raw_err = None
        try:
            result, raw_err = await _collect_once(engine, usm, target, ctx)
        except Exception as e:  # noqa: BLE001
            etext = friendly_snmp_error(f"{type(e).__name__}: {e}")
            result = {"ok": False, "error": etext, "kind": error_kind(etext)}
        finally:
            try:
                engine.close_dispatcher()
            except Exception:  # noqa: BLE001
                pass
        if result.get("ok"):
            return result
        if first_result is None:
            first_result = result
        # 只有"加密方言不对"才值得换另一套再试。口令错（Wrong SNMP PDU digest）/
        # 超时 / 用户不存在这几种换方言毫无意义，而且华为交换机有 SNMP 限流，
        # 白打一顿反而更容易被丢包，直接返回，别重试。
        if idx + 1 >= len(candidates) or not _is_priv_dialect_error(raw_err):
            break
        # 换方言前必须先等一等：设备（华为实测）一次登录失败就把源 IP 锁 ~10s，
        # 锁定期内静默丢包。立刻重试等于往锁上撞，不但这轮采集白跑，还会把锁**续长**。
        await asyncio.sleep(_DIALECT_RETRY_DELAY)
    # 换方言那次又失败时，报**第一次**（用户配的那套协议）的错误
    # 重试失败多半是限流/抖动的噪音，而"解密方式不一致"才是真正要用户去改的东西。
    return first_result or result


async def _collect_once(engine, usm, target, ctx):
    """用给定的 USM 采一轮。返回 (结果 dict, 原始错误串 or None)。

    原始错误串单独返回，是为了让上层判断"值不值得换加密方言重试" ——
    中文提示是给人看的，判断重试要看设备原话。
    """
    from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity, ObjectType, get_cmd

    try:
        # 1) 系统组：先探一次，连不上就早退（省掉后面一堆 walk 的超时）
        _ind, status, _idx, var_binds = await get_cmd(
            engine, usm, target, ctx,
            ObjectType(ObjectIdentity(OID_SYS_DESCR)),
            lookupMib=False,
        )
        if _ind is not None:
            return ({"ok": False, "error": friendly_snmp_error(_ind),
                     "kind": error_kind(_ind)}, str(_ind))
        # errorStatus ≠ 0，设备**明确回了错**。不拦这一下的话，按 RFC 3416 它的
        # varbind 值是 unSpecified（pysnmp 里就是 `Null('')`），会一路掉进下面的
        # "未返回 sysDescr" 分支，把设备写在 status 里的真正原因整个丢掉。
        if _status_code(status):
            raw = f"errorStatus={_status_code(status)}"
            return ({"ok": False, "error": error_status_hint(status, _idx),
                     "kind": KIND_DEVICE_REPLY}, raw)
        sys_descr = _scalar(var_binds[0][1]) if var_binds else None
        if sys_descr is None or not str(sys_descr).strip():
            return ({"ok": False,
                     "error": f"设备未返回 sysDescr（实际拿到：{describe_varbind(var_binds)}）",
                     # 能走到这说明设备把这个请求答完了，属于"设备回了错"，不是没响应
                     "kind": KIND_DEVICE_REPLY},
                    None)

        sysinfo = await _get_many(engine, usm, target, ctx, [
            OID_SYS_NAME, OID_SYS_UPTIME, OID_SYS_LOCATION, OID_SYS_OBJECT_ID,
        ])

        names = await _walk_column(engine, usm, target, ctx, IFX_NAME)
        hc_in = await _walk_column(engine, usm, target, ctx, IFX_HC_IN_OCTETS)
        hc_out = await _walk_column(engine, usm, target, ctx, IFX_HC_OUT_OCTETS)
        high_speed = await _walk_column(engine, usm, target, ctx, IFX_HIGH_SPEED)
        alias = await _walk_column(engine, usm, target, ctx, IFX_ALIAS)

        descr = await _walk_column(engine, usm, target, ctx, IF_DESCR)
        if_type = await _walk_column(engine, usm, target, ctx, IF_TYPE)
        speed32 = await _walk_column(engine, usm, target, ctx, IF_SPEED)
        admin = await _walk_column(engine, usm, target, ctx, IF_ADMIN_STATUS)
        oper = await _walk_column(engine, usm, target, ctx, IF_OPER_STATUS)
        in32 = await _walk_column(engine, usm, target, ctx, IF_IN_OCTETS)
        out32 = await _walk_column(engine, usm, target, ctx, IF_OUT_OCTETS)
        in_err = await _walk_column(engine, usm, target, ctx, IF_IN_ERRORS)
        out_err = await _walk_column(engine, usm, target, ctx, IF_OUT_ERRORS)

        indices = sorted(set(names) | set(descr))
        ifaces = []
        for i in indices:
            op_raw = str(oper.get(i, "") or "")
            ad_raw = str(admin.get(i, "") or "")
            ifaces.append({
                "if_index": i,
                "if_name": str(names.get(i) or descr.get(i) or f"if{i}"),
                "if_descr": str(descr.get(i) or ""),
                "if_alias": str(alias.get(i) or ""),
                "if_type": str(if_type.get(i) or ""),
                "if_speed_mbps": _speed_mbps(high_speed.get(i), speed32.get(i)),
                "admin_status": _status_name(ad_raw),
                "oper_status": _status_name(op_raw),
                # 64 位优先（低速口无所谓，高速口必须用 64 位）
                "in_octets": _pick_counter(hc_in.get(i), in32.get(i)),
                "out_octets": _pick_counter(hc_out.get(i), out32.get(i)),
                "in_errors": _to_int(in_err.get(i)),
                "out_errors": _to_int(out_err.get(i)),
            })

        cpu = await _cpu_percent(engine, usm, target, ctx)
        mem = await _memory_percent(engine, usm, target, ctx)
        # 全是 0.0，一条 NULL 都没有），并不等于"没实现"。真实占用在华为私有 MIB
        # 里，标准表给不出东西时再去那儿拿一次。
        # 只在 sysObjectID 属于华为（1.3.6.1.4.1.2011）时才试，不然每台设备
        # 每轮都要白打两个不存在的 OID，白白加重设备限流风险。
        if _is_huawei(sysinfo.get(OID_SYS_OBJECT_ID)) and (not cpu or not mem):
            if not cpu:
                cpu = await _huawei_cpu_percent(engine, usm, target, ctx)
            if not mem:
                mem = await _huawei_memory_percent(engine, usm, target, ctx)
            # 两套都拿不到（标准表恒 0 + 设备没开私有 MIB 视图） 剩下的 0 **不是真实值**，
            # 按"未提供"处理，别在卡片上摆一个假的 0%。
            # 只在这一支里动 0，别的设备真采到 0 还是 0，不乱改。
            if not cpu:
                cpu = None
            if not mem:
                mem = None

        total_in = sum(_to_int(i.get("in_octets")) for i in ifaces)
        total_out = sum(_to_int(i.get("out_octets")) for i in ifaces)

        return {
            "ok": True,
            "sys_descr": str(sys_descr),
            "sys_name": str(sysinfo.get(OID_SYS_NAME) or ""),
            "sys_location": str(sysinfo.get(OID_SYS_LOCATION) or ""),
            "sys_object_id": str(sysinfo.get(OID_SYS_OBJECT_ID) or ""),
            "uptime": _uptime_seconds(sysinfo.get(OID_SYS_UPTIME)),
            "cpu_percent": cpu,
            "memory_percent": mem,
            "interfaces": ifaces,
            "total_in_octets": total_in,
            "total_out_octets": total_out,
            # Linux / NAS 才有（存储池、磁盘健康、内存缓存分项）；交换机上是 None
            "nas": await _nas_detail(engine, usm, target, ctx, sys_descr),
            # ENTITY-SENSOR 三条路子自动挑，一条都取不到就是 None（卡片不显示）
            "env": await _env_detail_safe(engine, usm, target, ctx, sys_descr,
                                          sysinfo.get(OID_SYS_OBJECT_ID)),
        }, None
    except Exception as e:  # noqa: BLE001
        raw = f"{type(e).__name__}: {e}"
        return {"ok": False, "error": friendly_snmp_error(raw)}, raw


def _pick_counter(high: object, low32: object) -> int:
    """64 位计数器优先，但**只在它非零时才优先**。

    华为有些口（实测 S5731 的 GigabitEthernet0/0/9）会回 ``ifHCInOctets = 0`` ——
    这不是"这口没跑过流量"，而是"这口的 64 位计数器没实现"，真值还躺在 32 位的
    ``ifInOctets`` 里。原来的写法只用 ``is not None`` 判断，于是 0 被当成真值、
    32 位的真值被丢掉，端口表上就出现"入向 0 B、出向 26.4 GB"这种物理上说不通的行
    （2026-09-21 修）。
    两边都是 0（口真的闲着 / 口 DOWN）时结果不变，还是 0。
    """
    v64 = _to_int(high, 0)
    if v64 > 0:
        return v64
    return _to_int(low32, 0)


def _port_rate_mbps(prev, idx, cur_in, cur_out, dt):
    """单端口速率（Mbps）。`prev` 是上一轮的 {if_index: [in_bytes, out_bytes]}。

    返回 `(in_mbps, out_mbps)`；**算不出来返回 (None, None)，绝不返回 0** ——
    0 会被前端当成"这口真的没流量"，而实际是"这轮还没基线"（和 CPU / 内存那条
    教训一样：没采到的东西不许写成 0）。

    算不出来的三种情况：没基线、间隔非正、设备重启或计数器回绕导致差值为负。
    """
    if dt <= 0 or not prev:
        return None, None
    p = prev.get(str(idx)) or prev.get(idx)
    if not p:
        return None, None
    try:
        pin, pout = int(p[0]), int(p[1])
    except Exception:  # noqa: BLE001
        return None, None
    din = cur_in - pin
    dout = cur_out - pout
    # 回绕 / 重启会让差值变负，或者大得离谱；这一轮算不出来就报 None
    if din < 0 or dout < 0 or din > 10 ** 13 or dout > 10 ** 13:
        return None, None
    return round(din * 8 / dt / 1_000_000, 3), round(dout * 8 / dt / 1_000_000, 3)


def _speed_mbps(high_speed, speed32) -> float:
    """ifHighSpeed（Mb/s）优先；没有就用 ifSpeed（b/s）换算。"""
    hs = _to_int(high_speed, 0)
    if hs > 0:
        return float(hs)
    s32 = _to_int(speed32, 0)
    return round(s32 / 1_000_000.0, 2) if s32 > 0 else 0.0


def _status_name(raw: str) -> str:
    raw = str(raw or "").strip()
    return {"1": "up", "2": "down", "3": "testing",
            "4": "unknown", "5": "dormant", "6": "notPresent",
            "7": "lowerLayerDown"}.get(raw, raw or "unknown")


def _uptime_seconds(raw) -> int:
    """sysUpTime 是 TimeTicks（百分之一秒），也可能被 prettyPrint 成 '1:23:45:00.00'。"""
    if raw is None:
        return 0
    s = str(raw).strip()
    try:
        if ":" in s or "." in s:
            import re

            days = 0
            m = re.search(r"(\d+)\s*day", s)
            if m:
                days = int(m.group(1))
            parts = [p for p in re.findall(r"\d+", s.split(",")[-1])]
            if len(parts) >= 3:
                h, mi, sec = int(parts[-3]), int(parts[-2]), int(parts[-1])
                return days * 86400 + h * 3600 + mi * 60 + sec
        return int(s) // 100
    except Exception:  # noqa: BLE001
        return 0


async def _cpu_percent(engine, usm, target, ctx):
    """hrProcessorLoad 多核取平均；设备没实现就返回 None（不臆造）。"""
    loads = await _walk_column(engine, usm, target, ctx, OID_HR_PROCESSOR_LOAD)
    vals = [_to_int(v, -1) for v in loads.values()]
    vals = [v for v in vals if 0 <= v <= 100]
    if not vals:
        return None
    return round(sum(vals) / len(vals), 1)


# 返回 0，hrStorageTable 的 RAM 行也算不出占用率。真实的 CPU / 内存占用在华为
# 自己的 MIB 里，索引是实体号（MPU、交换网板、接口板各一行），大部分行给 0
# 或不支持，只有主控板那几行是真值，所以取**非零行**的平均。
OID_HW_ENTITY_CPU = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5"
OID_HW_ENTITY_MEM = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7"
OID_HW_ENTERPRISE = "1.3.6.1.4.1.2011."


def _is_huawei(sys_object_id) -> bool:
    return str(sys_object_id or "").startswith(OID_HW_ENTERPRISE)


async def _huawei_entity_avg(engine, usm, target, ctx, oid):
    """华为实体表里取一列的平均值：丢掉 0 / 越界 / 解析不出来的行。"""
    col = await _walk_column(engine, usm, target, ctx, oid)
    nums = []
    for v in col.values():
        n = _to_int(v, -1)
        if 0 < n <= 100:
            nums.append(n)
    if not nums:
        return None
    return round(sum(nums) / len(nums), 1)


async def _huawei_cpu_percent(engine, usm, target, ctx):
    return await _huawei_entity_avg(engine, usm, target, ctx, OID_HW_ENTITY_CPU)


async def _huawei_memory_percent(engine, usm, target, ctx):
    return await _huawei_entity_avg(engine, usm, target, ctx, OID_HW_ENTITY_MEM)


async def _memory_percent(engine, usm, target, ctx):
    """hrStorageTable 里 hrStorageType=RAM 的那一行：used / size。"""
    types = await _walk_column(engine, usm, target, ctx, OID_HR_STORAGE_TYPE)
    sizes = await _walk_column(engine, usm, target, ctx, OID_HR_STORAGE_SIZE)
    used = await _walk_column(engine, usm, target, ctx, OID_HR_STORAGE_USED)
    for idx, t in types.items():
        if OID_HR_STORAGE_RAM not in str(t):
            continue
        size = _to_int(sizes.get(idx), 0)
        u = _to_int(used.get(idx), 0)
        if size > 0:
            return round(u * 100.0 / size, 1)
    return None


def _is_linux(sys_descr) -> bool:
    """是不是 Linux 系设备（决定要不要去问 UCD-SNMP / 群晖私有 MIB）。

 **不能靠 sysObjectID 认**：群晖 DSM 的 sysObjectID 报的是 net-snmp 的
    `1.3.6.1.4.1.8072.3.2.10`，根本不是群晖自己的 6574；但它的 sysDescr 一定是
    "Linux <主机名> 4.4.302+ ..."。拿 sysObjectID 去认群晖，百分之百认不出来。
    """
    return "linux" in str(sys_descr or "").lower()


async def _walk_scalar(engine, usm, target, ctx, oid):
    """走一个标量列（形如 ...2021.4.5.0），取第一个值；没有就 None。"""
    col = await _walk_column(engine, usm, target, ctx, oid)
    for v in col.values():
        return _to_int(v, 0)
    return None


async def _linux_memory_detail(engine, usm, target, ctx):
    """UCD-SNMP 的内存分项 + "应用实际占用"。

    返回 None 表示"这台设备给不出完整分项" —— 缺一项就整段放弃，绝不拿残缺数据
    算百分比（算出来的数看着像真的，其实是假的）。
    """
    total = await _walk_scalar(engine, usm, target, ctx, OID_UCD_MEM_TOTAL)
    avail = await _walk_scalar(engine, usm, target, ctx, OID_UCD_MEM_AVAIL)
    cached = await _walk_scalar(engine, usm, target, ctx, OID_UCD_MEM_CACHED)
    buf = await _walk_scalar(engine, usm, target, ctx, OID_UCD_MEM_BUFFER)
    if not total or avail is None or cached is None:
        return None
    buf = buf or 0
    # 缓存 + buffer 是"可回收"的，内存紧张时内核自己会吐出来，不算应用占用
    app = max(0, total - avail - cached - buf)
    return {
        "total_kb": total,
        "app_kb": app,
        "cached_kb": cached,
        "buffer_kb": buf,
        "percent": round((total - avail) * 100.0 / total, 1),      # 含缓存（旧口径）
        "app_percent": round(app * 100.0 / total, 1),
    }


async def _linux_storage(engine, usm, target, ctx):
    """hrStorageTable 里挑最大的那个卷当"存储池"。

 群晖上 /volume1 会重复出现七八次（@docker、@appdata/… 这些子卷都报同一份
    容量），**取最大那个、只留一行**，别把 16 TB 加七遍算成 112 TB。
    返回 None 表示没找到任何挂载点。
    """
    descr = await _walk_column(engine, usm, target, ctx, OID_HR_STORAGE_DESCR)
    units = await _walk_column(engine, usm, target, ctx, OID_HR_STORAGE_UNITS)
    sizes = await _walk_column(engine, usm, target, ctx, OID_HR_STORAGE_SIZE)
    used = await _walk_column(engine, usm, target, ctx, OID_HR_STORAGE_USED)
    best = None
    for idx, d in descr.items():
        name = str(d or "").strip()
        if not name.startswith("/"):
            continue
        u = _to_int(units.get(idx), 0)
        sz = _to_int(sizes.get(idx), 0)
        if sz <= 0 or u <= 0:
            continue
        total_gb = sz * u / 1024 ** 3
        if best is None or total_gb > best["total_gb"]:
            best = {
                "name": name,
                "total_gb": round(total_gb, 2),
                "used_gb": round(_to_int(used.get(idx), 0) * u / 1024 ** 3, 2),
            }
    if not best:
        return None
    best["percent"] = round(best["used_gb"] * 100.0 / best["total_gb"], 1) if best["total_gb"] else 0.0
    return best


async def _synology_health(engine, usm, target, ctx):
    """群晖的磁盘表 + RAID 表。没开群晖 MIB 时返回 None（不返回空列表冒充"0 块盘"）。"""
    names = await _walk_column(engine, usm, target, ctx, SYNO_DISK_NAME)
    if not names:
        return None
    models = await _walk_column(engine, usm, target, ctx, SYNO_DISK_MODEL)
    status = await _walk_column(engine, usm, target, ctx, SYNO_DISK_STATUS)
    temps = await _walk_column(engine, usm, target, ctx, SYNO_DISK_TEMP)

    def _idx_key(k):
        try:
            return int(k)
        except Exception:  # noqa: BLE001
            return 10 ** 9

    disks = []
    for i in sorted(names, key=_idx_key):
        st = str(status.get(i) or "").strip()
        disks.append({
            "name": str(names.get(i) or f"Disk {i}"),
            "model": str(models.get(i) or ""),
            "ok": st == SYNO_STATUS_OK,
            "status_raw": st,
            "temp_c": _to_int(temps.get(i), None) if temps.get(i) is not None else None,
        })

    raid = None
    r_names = await _walk_column(engine, usm, target, ctx, SYNO_RAID_NAME)
    if r_names:
        r_status = await _walk_column(engine, usm, target, ctx, SYNO_RAID_STATUS)
        r0 = sorted(r_names, key=_idx_key)[0]
        rs = str(r_status.get(r0) or "").strip()
        raid = {"name": str(r_names.get(r0) or ""), "ok": rs == SYNO_STATUS_OK, "status_raw": rs}

    return {"disks": disks, "raid": raid}


async def _nas_detail(engine, usm, target, ctx, sys_descr):
    """Linux / NAS 设备的补充指标。非 Linux 一律不问（省掉一堆注定空的 walk）。"""
    if not _is_linux(sys_descr):
        return None
    out = {}
    mem = await _linux_memory_detail(engine, usm, target, ctx)
    if mem:
        out["memory"] = mem
    st = await _linux_storage(engine, usm, target, ctx)
    if st:
        out["storage"] = st
    syno = await _synology_health(engine, usm, target, ctx)
    if syno:
        out["disks"] = syno.get("disks") or []
        out["raid"] = syno.get("raid")
    return out or None


# ENTITY-SENSOR-MIB（标准 1.3.6.1.2.1.99）：entPhySensorType 8=celsius 10=rpm
OID_ENT_SENSOR_TYPE = "1.3.6.1.2.1.99.1.1.1.1"
OID_ENT_SENSOR_SCALE = "1.3.6.1.2.1.99.1.1.1.2"
OID_ENT_SENSOR_PRECISION = "1.3.6.1.2.1.99.1.1.1.3"
OID_ENT_SENSOR_VALUE = "1.3.6.1.2.1.99.1.1.1.4"
OID_ENT_SENSOR_STATUS = "1.3.6.1.2.1.99.1.1.1.5"
ENT_SENSOR_CELSIUS, ENT_SENSOR_RPM = "8", "10"
ENT_SENSOR_OK = "1"


def _split_table(raw: dict) -> dict:
    """把 {"<列号>.<索引>": 值} 拆成 {索引: {列号: 值}}。

 华为风扇表 / 电源表的索引是**两段**（槽位.编号，实测 `10.1.2.0.7`），
    群晖风扇表是一段加个 .0（`6574.1.4.1.0`）。统一按"第一段是列号、剩下的是索引"切。
    """
    out = {}
    for k, v in raw.items():
        parts = str(k).split(".")
        if len(parts) < 2:
            continue
        out.setdefault(".".join(parts[1:]), {})[parts[0]] = str(v)
    return out


def _max_in_range(raw: dict, lo: int, hi: int):
    """一列值里挑落在 [lo, hi] 的最大值；一个都没有返回 None。

    华为的温度列 83 行里只有主控板那一行是真值，其余全是 0 —— 0 是"这行没这个传感器"
    不是"0 ℃"。所以按范围过滤再取**最大**（最热的那颗才是要盯的）。
    """
    vals = [n for n in (_to_int(v, 0) for v in raw.values()) if lo <= n <= hi]
    return max(vals) if vals else None


async def _huawei_env(engine, usm, target, ctx) -> dict:
    """华为 ENTITY-EXTENT-MIB：温度 / 风扇 / 电源模块 / 整机功率。"""
    out = {}
    temp = _max_in_range(await _walk_subtree(engine, usm, target, ctx, OID_HW_TEMP), 1, 150)
    if temp is not None:
        out["temperature"] = {
            "c": temp,
            "threshold_c": _max_in_range(
                await _walk_subtree(engine, usm, target, ctx, OID_HW_TEMP_THRESHOLD), 1, 200),
        }

    fans = _split_table(await _walk_subtree(engine, usm, target, ctx, OID_HW_FAN_TABLE))
    if fans:
        out["fan"] = _fan_block([
            {"name": idx.replace(".", "/"),
             "ok": cols.get(HW_FAN_STATE) == "1",
             "present": cols.get(HW_FAN_PRESENT) == "1",
             "speed_percent": (_to_int(cols[HW_FAN_SPEED], None)
                               if HW_FAN_SPEED in cols else None)}
            for idx, cols in sorted(fans.items())
        ])

    pwrs = _split_table(await _walk_subtree(engine, usm, target, ctx, OID_HW_PWR_TABLE))
    if pwrs:
        items = []
        for idx, cols in sorted(pwrs.items()):
            st = cols.get(HW_PWR_STATE)
            # 1=供电 2=不供电 3=休眠 4=未知（华为文档枚举）；只认 1 为正常
            items.append({"name": idx.replace(".", "/"), "ok": st == "1", "state_raw": st})
        out["power"] = {"total": len(items), "ok": sum(1 for i in items if i["ok"]), "items": items}

    pw = _split_table(await _walk_subtree(engine, usm, target, ctx, OID_HW_POWER_TABLE))
    for cols in pw.values():
        total = _to_int(cols.get(HW_POWER_TOTAL), 0)
        used = _to_int(cols.get(HW_POWER_USED), 0)
        if total > 0 or used > 0:
            out["power_usage"] = {"total_w": total, "used_w": used,
                                  "remain_w": _to_int(cols.get(HW_POWER_REMAIN), 0)}
        break
    return out


def _fan_block(items: list) -> dict:
    """把风扇条目打包成统一形状；转速取平均值（多台风扇一般同速）。"""
    speeds = [i.get("speed_percent") for i in items if i.get("speed_percent")]
    return {
        "total": len(items),
        "ok": sum(1 for i in items if i.get("ok")),
        "speed_percent": round(sum(speeds) / len(speeds)) if speeds else None,
        "items": items,
    }


async def _synology_env(engine, usm, target, ctx) -> dict:
    """群晖 SYSTEM MIB：整机状态 / 系统温度 / 电源状态 / 每个风扇的状态。"""
    out = {}
    got = await _get_many(engine, usm, target, ctx,
                          [SYNO_SYS_STATUS, SYNO_SYS_TEMP, SYNO_SYS_POWER])
    if not got:
        return out
    st = got.get(SYNO_SYS_STATUS)
    if st is not None:
        out["system"] = {"ok": str(st).strip() == SYNO_STATUS_OK, "state_raw": str(st).strip()}
    t = got.get(SYNO_SYS_TEMP)
    if t is not None and _to_int(t, 0) > 0:
        out["temperature"] = {"c": _to_int(t), "threshold_c": None}
    p = got.get(SYNO_SYS_POWER)
    if p is not None:
        ok = str(p).strip() == SYNO_STATUS_OK
        out["power"] = {"total": 1, "ok": 1 if ok else 0,
                        "items": [{"name": "系统电源", "ok": ok, "state_raw": str(p).strip()}]}

    fans = await _walk_subtree(engine, usm, target, ctx, SYNO_FAN_TABLE)
    if fans:
        items = []
        for k in sorted(fans, key=lambda x: _to_int(str(x).split(".")[0], 0)):
            v = str(fans[k]).strip()
            items.append({"name": f"风扇 {str(k).split('.')[0]}", "ok": v == SYNO_STATUS_OK,
                          "state_raw": v})
        out["fan"] = _fan_block(items)
    return out


async def _cisco_env(engine, usm, target, ctx) -> dict:
    """思科 ENVMON-MIB（9.9.13.1）：只给状态枚举不给数值，所以只有电源和风扇。"""
    out = {}
    for key, oid in (("power", OID_CISCO_PSU_STATUS), ("fan", OID_CISCO_FAN_STATUS)):
        col = await _walk_column(engine, usm, target, ctx, oid)
        if not col:
            continue
        items = [{"name": f"{'电源' if key == 'power' else '风扇'} {i}",
                  "ok": str(v).strip() == CISCO_ENV_OK, "state_raw": str(v).strip()}
                 for i, v in sorted(col.items())]
        out[key] = {"total": len(items), "ok": sum(1 for i in items if i["ok"]), "items": items}
    return out


async def _entity_env(engine, usm, target, ctx) -> dict:
    """兜底：ENTITY-MIB 的 entPhysicalClass（6=电源 7=风扇）+ entPhysicalOperStatus。

    这台华为交换机（S5731S）的实体表里**只有** chassis / container / module / port，
    根本没有电源风扇实体，所以华为走不到这儿；思科 / H3C / 锐捷多数能走到。
    """
    classes = await _walk_column(engine, usm, target, ctx, OID_ENT_PHYSICAL_CLASS)
    if not classes:
        return {}
    psu = [i for i, c in classes.items() if str(c).strip() == ENT_CLASS_PSU]
    fan = [i for i, c in classes.items() if str(c).strip() == ENT_CLASS_FAN]
    if not (psu or fan):
        return {}
    names = await _walk_column(engine, usm, target, ctx, OID_ENT_PHYSICAL_NAME)
    oper = await _walk_column(engine, usm, target, ctx, OID_ENT_PHYSICAL_OPER)

    def build(idxs):
        items = [{"name": str(names.get(i) or f"#{i}"),
                  "ok": str(oper.get(i) or "").strip() == ENT_OPER_OK,
                  "state_raw": str(oper.get(i) or "").strip()}
                 for i in sorted(idxs)]
        return {"total": len(items), "ok": sum(1 for i in items if i["ok"]), "items": items}

    out = {}
    if psu:
        out["power"] = build(psu)
    if fan:
        out["fan"] = build(fan)
    return out


async def _sensor_env(engine, usm, target, ctx) -> dict:
    """最后一条路子：标准 ENTITY-SENSOR-MIB 的摄氏度 / 转速传感器。

 本机两台设备（NAS 的 net-snmp、华为 S5731S）都**没开**这张表，这条分支
    没能真机验证过，只按 RFC 3433 的换算规则实现：
        real = value × 10^((scale − 9) × 3) ÷ 10^precision
    （scale 枚举 9=units，每档 10^3；precision 是小数位数）
    没数据时返回空 dict，不影响别的分支。
    """
    types = await _walk_column(engine, usm, target, ctx, OID_ENT_SENSOR_TYPE)
    if not types:
        return {}
    values = await _walk_column(engine, usm, target, ctx, OID_ENT_SENSOR_VALUE)
    scales = await _walk_column(engine, usm, target, ctx, OID_ENT_SENSOR_SCALE)
    precs = await _walk_column(engine, usm, target, ctx, OID_ENT_SENSOR_PRECISION)
    temps, rpms = [], []
    for i, t in types.items():
        raw = _to_int(values.get(i), None) if values.get(i) is not None else None
        if raw is None:
            continue
        scale = _to_int(scales.get(i), 9)
        prec = _to_int(precs.get(i), 0)
        # scale 是 1..17 的枚举（9=units）、precision 是小数位数；越界一律当这行坏了丢掉，
        # 不然 `10 ** ((scale-9)*3)` 会算出天文数字 float 溢出 整轮采集一起挂掉
        if not (1 <= scale <= 17) or not (0 <= prec <= 9):
            continue
        try:
            real = raw * (10 ** ((scale - 9) * 3)) / (10 ** prec)
        except Exception:  # noqa: BLE001
            continue
        if real != real or real in (float("inf"), float("-inf")):
            continue
        if str(t).strip() == ENT_SENSOR_CELSIUS and -100 <= real <= 200:
            temps.append(round(real, 1))
        elif str(t).strip() == ENT_SENSOR_RPM and 0 <= real <= 100000:
            rpms.append(int(real))
    out = {}
    if temps:
        out["temperature"] = {"c": max(temps), "threshold_c": None}
    if rpms:
        out["fan"] = {"total": len(rpms), "ok": None, "speed_percent": None,
                      "items": [{"name": f"风扇 {n + 1}", "ok": None, "rpm": r}
                                for n, r in enumerate(rpms)]}
    return out


async def _env_detail(engine, usm, target, ctx, sys_descr, sys_object_id) -> dict:
    """硬件健康总入口：温度 / 电源 / 风扇 / 整机功率，按"谁先给数据就用谁"往下试。

    返回 None 表示这台设备一条都给不出（卡片就不显示，不摆假的 0）。
    """
    out = {}
    source = None
    if _is_huawei(sys_object_id):
        out = await _huawei_env(engine, usm, target, ctx)
        source = "huawei" if out else None
    if not out:
        out = await _synology_env(engine, usm, target, ctx)
        source = "synology" if out else None
    if not out:
        out = await _cisco_env(engine, usm, target, ctx)
        source = "cisco-envmon" if out else None
    if not out:
        out = await _entity_env(engine, usm, target, ctx)
        source = "entity-mib" if out else None
    # 温度可能只有标准传感器表里有（电源风扇已由上面给出）
    if out and "temperature" not in out:
        sen = await _sensor_env(engine, usm, target, ctx)
        if sen.get("temperature"):
            out["temperature"] = sen["temperature"]
    if not out:
        return None
    out["source"] = source
    return out


async def _env_detail_safe(engine, usm, target, ctx, sys_descr, sys_object_id):
    """`_env_detail` 的"永不抛"外壳。

    硬件健康是**附加信息**：`_env_detail` 挂在 `_collect_once` 的主 try 里，它要是抛了，
    整台设备这一轮会被判成**采集失败** —— 端口、流量、CPU 全都不更新，还可能触发离线告警。
    拿一个"看不到温度"去换"整台设备采集失败"完全不划算，所以这里兜住：
    出任何问题就当这台设备没有硬件健康数据（卡片不显示），别的指标照常。
    """
    try:
        return await _env_detail(engine, usm, target, ctx, sys_descr, sys_object_id)
    except Exception:  # noqa: BLE001
        return None


def collect_snmp_device(server) -> dict:
    """同步入口（调度线程里调）。pysnmp 7 是异步 API，这里用 asyncio.run 包一层。"""
    try:
        try:
            return asyncio.run(_collect_async(server))
        except RuntimeError:
            # 已经在事件循环里（理论上不会：调度器跑在独立线程）
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(_collect_async(server))
            finally:
                loop.close()
    except SnmpCredentialError as e:
        # 凭据不满足 SNMPv3 硬性要求，这是本机就能判定、且管理员照着改就行的结论，
        # 原样递上去；不要再套 "SNMP 交互失败："，也不要附 pysnmp 的原始 OID 字典。
        return {"ok": False, "error": str(e), "kind": KIND_LOCAL}
    except ImportError as e:
        # 根本没装 pysnmp。这不是设备的问题，也不是网络的问题，
        # 必须说清"查哪一台机器"：是**装服务端的这台**。
        return {"ok": False,
                "error": f"服务端缺少 SNMP 依赖（pysnmp）：{e}"
                         " —— 问题出在**装 VigilServe 服务端的这台机器**上，"
                         "请重新安装或修复服务端（pysnmp 随包分发，正常安装不该缺）",
                "kind": KIND_LOCAL}
    except Exception as e:  # noqa: BLE001
        etext = friendly_snmp_error(f"{type(e).__name__}: {e}")
        return {"ok": False, "error": etext, "kind": error_kind(etext)}


def build_probe_from_values(ip: str, cfg: dict):
    """从「还没入库的裸凭据」构造采集视图（新增设备时的「测试连接」用）。

    与 `build_probe()` 的区别：那个是基于已存在的 Server 做覆盖，这个完全来自
    页面表单 —— 设备还没建，自然也没有"库里的旧值"可以兜底。
    """
    from types import SimpleNamespace

    c = cfg or {}

    def _num(key, default):
        try:
            return int(c.get(key) or default)
        except Exception:  # noqa: BLE001
            return default

    return SimpleNamespace(
        ip_address=str(ip or "").strip(),
        snmp_version="3",
        snmp_port=_num("snmp_port", 161),
        snmp_username=str(c.get("snmp_username") or ""),
        snmp_security_level=str(c.get("snmp_security_level") or "authPriv"),
        snmp_auth_proto=str(c.get("snmp_auth_proto") or "SHA"),
        snmp_priv_proto=str(c.get("snmp_priv_proto") or "AES"),
        snmp_context=str(c.get("snmp_context") or ""),
        snmp_auth_password_plain=str(c.get("snmp_auth_password") or ""),
        snmp_priv_password_plain=str(c.get("snmp_priv_password") or ""),
    )


def build_probe(server, overrides: dict = None):
    """构造一个「本次采集专用」的轻量视图（不写库）。

    页面上的「测试连接」往往是在凭据**还没保存**的时候点的，直接改 Server 会
    把库里的旧值冲掉（万一测试失败也回不来了）。这里返回一个只带采集所需字段
    的对象，覆盖值只影响这一次请求。

    口令传掩码（******）视为"沿用库里存的"，与编辑主机时的规矩一致。
    """
    from types import SimpleNamespace

    ov = overrides or {}

    def _pwd(key, stored_plain):
        v = str(ov.get(key) or "").strip()
        if not v or v == "******":
            return stored_plain
        return v

    return SimpleNamespace(
        ip_address=ov.get("ip_address") or server.ip_address,
        snmp_version="3",
        snmp_port=int(ov.get("snmp_port") or server.snmp_port or 161),
        snmp_username=ov.get("snmp_username") or server.snmp_username or "",
        snmp_security_level=ov.get("snmp_security_level") or server.snmp_security_level or "authPriv",
        snmp_auth_proto=ov.get("snmp_auth_proto") or server.snmp_auth_proto or "SHA",
        snmp_priv_proto=ov.get("snmp_priv_proto") or server.snmp_priv_proto or "AES",
        snmp_context=ov.get("snmp_context") or server.snmp_context or "",
        snmp_auth_password_plain=_pwd("snmp_auth_password", server.snmp_auth_password_plain),
        snmp_priv_password_plain=_pwd("snmp_priv_password", server.snmp_priv_password_plain),
    )




def collect_and_store(db, server) -> dict:
    """采一台设备 + 落库（端口表 + 指标 + extra_config 里的设备信息）。

    失败不抛 —— 调度任务不能因为一台设备不通就整体挂掉。
    """
    from models import MetricSnapshot, NetworkInterface
    from services.audit_logger import log_operation

    now = datetime.now(timezone.utc)
    extra = dict(server.extra_config or {})
    # 必须**在原有 snmp 字典上改**，不能整个换掉，否则 consecutive_failures
    # 每次都从 0 重新开始，「连续 3 次失败才告警」永远不会触发。
    snmp_info = dict(extra.get("snmp") or {})

    # 熔断检查（2026-09-21）：在**发第一个包之前**先看有没有被自己停下
    # 这一步必须早于 collect_snmp_device()。凭据错的时候设备已经在锁我们了，
    # 熔断期内再打一个包就是往锁上再撞一次，会把锁续长（华为实测能续到 5 分钟）。
    paused, until_iso = snmp_pause_state(snmp_info)
    if paused:
        return {
            "ok": False,
            "paused": True,
            "pause_until": until_iso,
            "pause_reason": snmp_info.get("pause_reason", ""),
            "error": f"采集已暂停至 {until_iso[:19].replace('T', ' ')}（{snmp_info.get('pause_reason', '连续采集失败')}）"
                     f"—— 暂停期间不再发包，避免继续把本机 IP 锁死。改好凭据后到设备页点「恢复采集」。",
        }

    res = collect_snmp_device(server)
    # ICMP 探测：SNMP 由设备的代理进程应答，ICMP 由内核应答，两条路分开看才能分清
    # "设备挂了"和"SNMP 代理卡了"。**放在 SNMP 成败判断之前**，恰恰是 SNMP 不通
    # 的时候最需要知道"那 ping 通不通"。
    try:
        from services.icmp_probe import probe_icmp
        snmp_info["icmp"] = probe_icmp(server.ip_address)
    except Exception as e:  # noqa: BLE001
        snmp_info["icmp"] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    snmp_info.update({
        "last_attempt_at": now.isoformat(),
        "ok": bool(res.get("ok")),
        "error": res.get("error", ""),
    })
    extra["snmp"] = snmp_info

    if not res.get("ok"):
        snmp_info["consecutive_failures"] = int(snmp_info.get("consecutive_failures", 0)) + 1
        streak = snmp_info["consecutive_failures"]
        err = res.get("error", "")
        kind = classify_snmp_error(err)

        # auth：凭据错就是凭据错，重试只会让设备一次次锁我们 阈值低、停得久。
        # network：可能是抖动，也可能是被锁了 阈值高一些，但同样不能无限打。
        trip = (kind == "auth" and streak >= AUTH_FAIL_TRIP) or \
               (kind == "network" and streak >= NET_FAIL_TRIP)
        if trip:
            pause_count = int(snmp_info.get("pause_count", 0))
            minutes = _pause_minutes(kind, pause_count)
            until = now + timedelta(minutes=minutes)
            snmp_info["paused_until"] = until.isoformat()
            snmp_info["pause_count"] = pause_count + 1
            snmp_info["pause_reason"] = (
                "SNMP 认证失败（用户名 / 口令 / 鉴权或加密协议与设备不一致）"
                if kind == "auth" else "设备无响应（超时或不可达）"
            )
            res["paused"] = True
            res["pause_until"] = until.isoformat()
            res["pause_minutes"] = minutes

        server.extra_config = extra
        db.commit()

        from models import Alert

        # 连续 3 次不通才告警，单次抖动就告警，48 台设备能把告警页淹掉
        if streak == 3 or trip:
            is_auth = kind == "auth"
            title = (f"SNMP 认证失败，已暂停采集：{server.name}" if trip and is_auth
                     else f"SNMP 采集连续失败：{server.name}")
            msg = f"该设备已连续 {streak} 次 SNMP 采集失败：{err}"
            if trip:
                msg += (f"。已暂停采集 {minutes} 分钟（至 {until.isoformat()[:19].replace('T', ' ')}），"
                        f"期间不再向设备发包 —— 设备（华为/华三这类）会在认证失败后锁定源 IP，"
                        f"继续重试只会把锁越续越长。请核对设备上的 SNMPv3 用户名 / 鉴权协议 / "
                        f"加密协议 / 口令，改好后到设备页点「恢复采集」。")
            db.add(Alert(
                server_id=server.id,
                level="warning" if not (trip and is_auth) else "error",
                title=title,
                message=msg,
                metric_type="snmp",
            ))
            log_operation(
                db, category="server", action="snmp_collect_failed", level="warning",
                status="failed",
                message=f"主机 {server.name} SNMP 采集连续失败 {streak} 次"
                        + (f"，已熔断 {minutes} 分钟" if trip else ""),
                target_type="server", target_id=str(server.id),
                details={"error": err, "kind": kind, "paused": bool(trip)},
            )
            db.commit()
        return res

    # 采通了就把熔断解除，说明凭据是对的、设备也在应答，没必要继续罚它。
    snmp_info["paused_until"] = None
    snmp_info["pause_count"] = 0
    snmp_info["pause_reason"] = ""

    snmp_info.update({
        "consecutive_failures": 0,
        "sys_descr": res.get("sys_descr", ""),
        "sys_name": res.get("sys_name", ""),
        "sys_location": res.get("sys_location", ""),
        "sys_object_id": res.get("sys_object_id", ""),
        "uptime_seconds": res.get("uptime", 0),
        "interface_count": len(res.get("interfaces", [])),
        # 交换机那台是 None，前端靠"有没有这个键"决定要不要显示那几张卡片。
        "nas": res.get("nas"),
        "env": res.get("env"),
    })
    server.extra_config = extra
    server.last_seen = now
    # 采通了就把"离线"翻回"在管"，离线是采集侧判出来的，恢复也该由采集侧判。
    # 但「断开」（管理员主动停采集）不动：那是人下的决定，不能因为设备还通着就自作主张恢复。
    if server.status in ("offline", "unknown"):
        server.status = "monitored"
        server.online_time = now
        server.offline_time = None

    # 单端口速率的基线：上一轮每个口的累计字节 + 时间戳。
    # 没有基线 / 间隔算不出来 dt_if 保持 0，本轮所有口写 NULL（不是 0）。
    prev_if_raw = (server.extra_config or {}).get("snmp", {}).get("if_counters") or {}
    prev_if = prev_if_raw.get("c") or {}
    dt_if = 0.0
    if prev_if_raw.get("at"):
        try:
            t0 = datetime.fromisoformat(prev_if_raw["at"])
            if t0.tzinfo is None:
                t0 = t0.replace(tzinfo=timezone.utc)
            dt_if = (now - t0).total_seconds()
        except Exception:  # noqa: BLE001
            dt_if = 0.0

    existing = {
        r.if_index: r
        for r in db.query(NetworkInterface).filter(
            NetworkInterface.server_id == server.id).all()
    }
    cur_if = {}
    seen = set()
    for it in res.get("interfaces", []):
        idx = int(it.get("if_index") or 0)
        seen.add(idx)
        cur_in = int(it.get("in_octets") or 0)
        cur_out = int(it.get("out_octets") or 0)
        cur_if[str(idx)] = [cur_in, cur_out]
        row = existing.get(idx)
        if row is None:
            row = NetworkInterface(server_id=server.id, if_index=idx)
            db.add(row)
        row.if_name = it.get("if_name", "") or ""
        row.if_descr = it.get("if_descr", "") or ""
        row.if_alias = it.get("if_alias", "") or ""
        row.if_type = it.get("if_type", "") or ""
        row.if_speed_mbps = float(it.get("if_speed_mbps") or 0)
        row.admin_status = it.get("admin_status", "") or ""
        row.oper_status = it.get("oper_status", "") or ""
        row.in_octets = int(it.get("in_octets") or 0)
        row.out_octets = int(it.get("out_octets") or 0)
        row.in_errors = int(it.get("in_errors") or 0)
        row.out_errors = int(it.get("out_errors") or 0)
        ri, ro = _port_rate_mbps(prev_if, idx, cur_in, cur_out, dt_if)
        row.in_rate_mbps = ri
        row.out_rate_mbps = ro
        row.updated_at = now
    # 设备上下线端口会变，采不到的就删掉（否则端口表只增不减）
    for idx, row in existing.items():
        if idx not in seen:
            db.delete(row)

    # 必须重新赋值一次：snmp_info 是在 server.extra_config 里就地改的，
    # JSON 列对"原地修改"不敏感，不重新赋值这一轮可能不落库。
    snmp_info["if_counters"] = {"at": now.isoformat(), "c": cur_if}
    server.extra_config = extra

    # 指标：与 Agent 上报的主机写同一张表，交换机就能进仪表盘和图表
    in_mbps, out_mbps = _rate_mbps(db, server, res.get("total_in_octets", 0),
                                   res.get("total_out_octets", 0), now)
    # CPU / 内存**不能把"没采到"写成 0**：交换机大多不实现 HOST-RESOURCES-MIB
    # （华为 S5731 就是，62 个端口全采得到，hrProcessorLoad / hrStorageTable 一个都没有）。
    # 以前 `float(res.get("cpu_percent") or 0)` 把 None 压成 0.0 存库，前端 `cpu == null`
    # 永远不成立 卡片显示成"CPU 0%"，表现类似设备快饿死了，实际是没这个指标。
    # 现在设备不给就存 NULL，前端显示"未提供"。
    _cpu = res.get("cpu_percent")
    _mem = res.get("memory_percent")
    db.add(MetricSnapshot(
        server_id=server.id,
        timestamp=now,
        cpu_percent=None if _cpu is None else float(_cpu),
        memory_percent=None if _mem is None else float(_mem),
        network_in_mbps=in_mbps,
        network_out_mbps=out_mbps,
    ))
    db.commit()
    res["network_in_mbps"] = in_mbps
    res["network_out_mbps"] = out_mbps
    return res


def _rate_mbps(db, server, total_in: int, total_out: int, now) -> tuple:
    """用上一次的累计字节数算速率。SNMP 只给累计值，速率必须自己差分。

    首次采集没有基线 → 返回 0（不能拿累计值当速率，那会显示成几个 T）。
    """
    prev = (server.extra_config or {}).get("snmp", {}).get("counters") or {}
    extra = dict(server.extra_config or {})
    snmp = dict(extra.get("snmp") or {})
    snmp["counters"] = {"in": total_in, "out": total_out, "at": now.isoformat()}
    extra["snmp"] = snmp
    server.extra_config = extra

    if not prev or not prev.get("at"):
        return 0.0, 0.0
    try:
        t0 = datetime.fromisoformat(prev["at"])
        if t0.tzinfo is None:
            t0 = t0.replace(tzinfo=timezone.utc)
        dt = (now - t0).total_seconds()
    except Exception:  # noqa: BLE001
        return 0.0, 0.0
    if dt <= 0:
        return 0.0, 0.0
    din = max(0, total_in - int(prev.get("in") or 0))
    dout = max(0, total_out - int(prev.get("out") or 0))
    # 计数器回绕（设备重启 / 32 位绕回） 这一轮算不出来就报 0，别报负数或天文数字
    if din > 10 ** 13 or dout > 10 ** 13:
        return 0.0, 0.0
    return round(din * 8 / dt / 1_000_000, 3), round(dout * 8 / dt / 1_000_000, 3)


def collect_all_snmp_devices(db) -> dict:
    """调度入口：采所有开了 SNMP 的主机。"""
    from models import Server

    servers = db.query(Server).filter(Server.snmp_enabled == 1).all()
    ok = fail = skipped = 0
    for s in servers:
        try:
            r = collect_and_store(db, s)
            if r.get("ok"):
                ok += 1
            elif r.get("paused"):
                # 熔断中：不是"失败"，是本轮一个包都没发。单独计数，日志里才看得出来
                # 采集器是在按设计刹车，而不是又挂了一台。
                skipped += 1
            else:
                fail += 1
        except Exception:  # noqa: BLE001
            fail += 1
    return {"checked": len(servers), "ok": ok, "failed": fail, "skipped": skipped}
