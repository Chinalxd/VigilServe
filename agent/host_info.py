"""主机信息 / 应用管理 / 启动项 / 事件日志 采集模块（Windows 为主）。

对外接口（与前端 services/hostInfoMock.js 的数据契约一一对应）：

    collect_host_info()            -> dict
    list_applications()            -> list[dict]
    list_system_updates()          -> list[dict]
    uninstall_applications(ids)    -> {"ok": bool, "results": [{"id","ok","message"}]}
    list_startup_items()           -> list[dict]
    set_startup_enabled(item_id, enabled) -> {"ok": bool, "enabled": bool}
    list_event_logs(level, limit, start, end) -> list[dict]  （start/end 默认近 3 天）

设计原则
--------
1. **每个分项独立 try/except**：某一项采集失败只影响该项（前端显示「—」），不影响整页。
2. **采集不到就是 None / []**，绝不臆造数据。
3. Windows 上用 CIM/WMI + 注册表 + 少量 Win32 API；全程只读（除启动项开关与卸载）。
4. 结果带 60 秒 TTL 缓存，避免页面频繁切换时反复跑 WMI。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

try:
    from logger import get_logger
    _log = get_logger("host_info")
except Exception:  # pragma: no cover
    _log = None


def _warn(msg: str) -> None:
    if _log:
        _log.warning(msg)


IS_WIN = sys.platform == "win32"

_CACHE: dict = {}
_CACHE_TTL = 60.0


def _cached(key: str, fn):
    now = time.time()
    hit = _CACHE.get(key)
    if hit and now - hit[0] < _CACHE_TTL:
        return hit[1]
    val = fn()
    _CACHE[key] = (now, val)
    return val


def invalidate() -> None:
    _CACHE.clear()


_PS_EXE = None


def _ps_exe() -> str:
    global _PS_EXE
    if _PS_EXE:
        return _PS_EXE
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    cand = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    if os.path.exists(cand):
        _PS_EXE = cand
    else:
        _PS_EXE = "powershell.exe"
    return _PS_EXE


_PS_PRELUDE = """$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
"""


def _ps_json(script: str, timeout: int = 40):
    """执行一段 PowerShell，返回解析后的 JSON（失败返回 None）。

    用 -EncodedCommand(UTF-16LE base64) 传参，规避引号与编码问题；
    脚本内把 Console 输出编码设成 UTF-8，保证中文正常回传。
    """
    if not IS_WIN:
        return None
    body = _PS_PRELUDE + script
    encoded = base64.b64encode(body.encode("utf-16-le")).decode("ascii")
    try:
        proc = subprocess.run(
            [_ps_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", encoded],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        _warn("host_info: powershell script timed out")
        return None
    except Exception as exc:  # noqa: BLE001
        _warn(f"host_info: powershell exec failed: {exc!r}")
        return None
    out = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    if out.startswith("\ufeff"):
        out = out[1:]
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception as exc:  # noqa: BLE001
        _warn(f"host_info: powershell json parse failed: {exc!r}; head={out[:120]!r}")
        return None


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, dict):
        return [v]
    return []


def _s(v):
    """转字符串：去掉首尾空白与不可见控制字符，空值归一化为 None。

    部分硬件把固件/序列号填成含 \\u0000 之类的原始字节，直接返回会让
    前端 JSON 里出现乱码方框。
    """
    if v is None:
        return None
    t = "".join(ch for ch in str(v) if ch == "\t" or ord(ch) >= 0x20)
    t = t.strip()
    return t or None


def _i(v):
    try:
        if v is None or v == "":
            return None
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _f(v, nd=1):
    try:
        if v is None or v == "":
            return None
        return round(float(v), nd)
    except (TypeError, ValueError):
        return None


def _gb(v, nd=1):
    try:
        if v is None or v == "":
            return None
        return round(float(v) / (1024 ** 3), nd)
    except (TypeError, ValueError):
        return None


def _stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


_PS_MACHINE = r"""
$r = @{}
try {
  $cs  = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
  $bb  = Get-CimInstance Win32_BaseBoard -EA SilentlyContinue
  $bio = Get-CimInstance Win32_BIOS -EA SilentlyContinue
  $osw = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
  $enc = Get-CimInstance Win32_SystemEnclosure -EA SilentlyContinue
  $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue
  $tz  = Get-TimeZone -EA SilentlyContinue

  $r['computer_name'] = if ($cs) { $cs.Name } else { $env:COMPUTERNAME }
  $r['domain']        = if ($cs) { $cs.Domain } else { $env:USERDOMAIN }
  $r['manufacturer']  = if ($cs) { $cs.Manufacturer } else { $null }
  $r['model']         = if ($cs) { $cs.Model } else { $null }
  $r['serial']        = if ($bio) { $bio.SerialNumber } else { $null }
  $r['chassis_raw']   = if ($enc -and $enc.ChassisTypes) { [int]$enc.ChassisTypes[0] } else { 0 }

  $r['bios_vendor']  = if ($bio) { $bio.Manufacturer } else { $null }
  $r['bios_version'] = if ($bio) { $bio.SMBIOSBIOSVersion } else { $null }
  $r['bios_date']    = $null
  if ($bio -and $bio.ReleaseDate) {
    try { $r['bios_date'] = ([datetime]$bio.ReleaseDate).ToString('yyyy-MM-dd') } catch {
      $d = [string]$bio.ReleaseDate
      if ($d.Length -ge 8 -and $d -notlike '*-*') { $r['bios_date'] = $d.Substring(0,4) + '-' + $d.Substring(4,2) + '-' + $d.Substring(6,2) }
    }
  }
  $r['bios_mode'] = $null
  try { if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State') { $r['bios_mode'] = 'UEFI' } else { $r['bios_mode'] = 'Legacy' } } catch {}

  $r['mb_manufacturer'] = if ($bb) { $bb.Manufacturer } else { $null }
  $r['mb_model']        = if ($bb) { $bb.Product } else { $null }
  $r['mb_serial']       = if ($bb) { $bb.SerialNumber } else { $null }

  $r['os_name'] = if ($reg) { $reg.ProductName } else { $(if ($osw) { $osw.Caption } else { $null }) }
  # Win11 注册表 ProductName 仍写 "Windows 10 ..."（微软从未更新），须按 Build>=22000 判 11；
  # Win32_OperatingSystem.Caption 在早期 Win11 上同样是 "Windows 10"，一并覆盖。
  if ($r['os_name'] -and $reg -and $reg.CurrentBuildNumber) {
    try {
      if ([int]$reg.CurrentBuildNumber -ge 22000 -and $r['os_name'] -match '^Windows 10(\s|$)') {
        $r['os_name'] = $r['os_name'] -replace '^Windows 10', 'Windows 11'
      }
    } catch {}
  }
  $r['os_version'] = $null
  if ($reg) {
    if ($reg.CurrentMajorVersionNumber -ne $null) { $r['os_version'] = [string]$reg.CurrentMajorVersionNumber + '.' + [string]$reg.CurrentMinorVersionNumber }
    elseif ($reg.DisplayVersion) { $r['os_version'] = [string]$reg.DisplayVersion }
  }
  if (-not $r['os_version']) { try { $r['os_version'] = [System.Environment]::OSVersion.Version.ToString(2) } catch {} }
  $r['os_build'] = $null
  if ($reg) {
    $ubr = (Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -EA SilentlyContinue)
    if ($reg.CurrentBuildNumber) { $r['os_build'] = ([string]$reg.CurrentBuildNumber + '.' + [string]$ubr).TrimEnd('.') }
  }
  $r['os_edition']   = if ($reg) { $reg.EditionID } else { $null }
  $r['os_arch']      = if ($osw) { $osw.OSArchitecture } else { $null }
  $r['install_date'] = $null
  $r['last_boot']    = $null
  $r['uptime_sec']   = $null
  if ($osw) {
    if ($osw.InstallDate)  { $r['install_date'] = $osw.InstallDate.ToString('yyyy-MM-dd HH:mm:ss') }
    if ($osw.LastBootUpTime) {
      $r['last_boot'] = $osw.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')
      $r['uptime_sec'] = [int]((Get-Date) - $osw.LastBootUpTime).TotalSeconds
    }
  }
  $r['timezone']   = if ($tz) { $tz.DisplayName } else { $null }
  $r['system_dir'] = if ($osw) { $osw.SystemDirectory } else { $null }
  $r['product_id'] = if ($reg) { $reg.ProductId } else { $null }
  $r['locale']     = (Get-Culture).Name
} catch {}
$r | ConvertTo-Json -Compress -Depth 5
"""

_CHASSIS = {
    1: "其他", 2: "未知", 3: "台式机", 4: "薄型台式机", 5: "薄型(Pizza Box)",
    6: "迷你立式", 7: "塔式", 8: "便携式", 9: "笔记本", 10: "笔记本",
    11: "手持设备", 12: "扩展底座", 13: "一体机", 14: "子笔记本", 15: "节省空间",
    16: "手提箱", 17: "主机", 18: "扩展机箱", 19: "子机箱", 20: "总线扩展机箱",
    21: "外设机箱", 22: "存储机箱", 23: "机架式", 24: "密封式",
}


def _collect_machine_os() -> tuple[dict, dict]:
    d = _ps_json(_PS_MACHINE, timeout=30) or {}
    arch = _s(d.get("os_arch"))
    if not arch:
        m = platform.machine().upper()
        arch = {"AMD64": "x64", "X86": "x86", "ARM64": "ARM64"}.get(m, m)
    elif "64" in arch:
        arch = "x64"
    elif "32" in arch or "86" in arch:
        arch = "x86"

    machine = {
        "computer_name": _s(d.get("computer_name")) or platform.node(),
        "domain": _s(d.get("domain")),
        "manufacturer": _s(d.get("manufacturer")),
        "model": _s(d.get("model")),
        "serial": _s(d.get("serial")),
        "chassis_type": _CHASSIS.get(_i(d.get("chassis_raw")) or 0),
        "bios": {
            "vendor": _s(d.get("bios_vendor")),
            "version": _s(d.get("bios_version")),
            "date": _s(d.get("bios_date")),
            "mode": _s(d.get("bios_mode")),
        },
        "motherboard": {
            "manufacturer": _s(d.get("mb_manufacturer")),
            "model": _s(d.get("mb_model")),
            "chipset": None,
            "serial": _s(d.get("mb_serial")),
        },
    }
    os_info = {
        "name": _s(d.get("os_name")),
        "version": _s(d.get("os_version")),
        "build": _s(d.get("os_build")),
        "edition": _s(d.get("os_edition")),
        "arch": arch,
        "install_date": _s(d.get("install_date")),
        "last_boot": _s(d.get("last_boot")),
        "uptime_seconds": _i(d.get("uptime_sec")),
        "timezone": _s(d.get("timezone")),
        "system_dir": _s(d.get("system_dir")),
        "product_id": _s(d.get("product_id")),
        "locale": _s(d.get("locale")),
    }
    if not IS_WIN:
        os_info["name"] = os_info["name"] or f"{platform.system()} {platform.release()}"
        os_info["version"] = os_info["version"] or platform.version()
        if psutil:
            os_info["last_boot"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(psutil.boot_time()))
            os_info["uptime_seconds"] = int(time.time() - psutil.boot_time())
    return machine, os_info


# 2. 系统安全软件状态
_PS_SECURITY = r"""
$r = @{}
try {
  $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -EA SilentlyContinue
  $r['uac_enabled'] = if ($pol) { [int]$pol.EnableLUA } else { $null }
  $r['uac_prompt']  = if ($pol) { [int]$pol.ConsentPromptBehaviorAdmin } else { $null }
} catch {}

$r['secure_boot'] = $null
try { $r['secure_boot'] = [bool](Confirm-SecureBootUEFI) } catch {}

$r['tpm_present'] = $null; $r['tpm_ready'] = $null; $r['tpm_version'] = $null
try {
  $t = Get-Tpm -EA SilentlyContinue
  if ($t) { $r['tpm_present'] = [bool]$t.TpmPresent; $r['tpm_ready'] = [bool]$t.TpmReady }
  $w = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -EA SilentlyContinue
  if ($w -and $w.SpecVersion) { $r['tpm_version'] = ([string]$w.SpecVersion).Split(',')[0].Trim() }
} catch {}

$r['fw_domain'] = $null; $r['fw_private'] = $null; $r['fw_public'] = $null
try {
  foreach ($p in (Get-NetFirewallProfile -EA SilentlyContinue)) {
    switch -Wildcard ($p.Name) {
      'Domain'  { $r['fw_domain']  = [bool]$p.Enabled }
      'Private' { $r['fw_private'] = [bool]$p.Enabled }
      'Public'  { $r['fw_public']  = [bool]$p.Enabled }
    }
  }
} catch {}

$r['defender'] = $null
try {
  $m = Get-MpComputerStatus -EA SilentlyContinue
  if ($m) {
    $qs = $null; $fs = $null
    if ($m.QuickScanEndTime) { $qs = $m.QuickScanEndTime.ToString('yyyy-MM-dd HH:mm:ss') }
    if ($m.FullScanEndTime)  { $fs = $m.FullScanEndTime.ToString('yyyy-MM-dd HH:mm:ss') }
    $r['defender'] = @{
      name = 'Windows Defender 防病毒'
      enabled = [bool]$m.AntivirusEnabled
      realtime_protection = [bool]$m.RealTimeProtectionEnabled
      tamper_protection = [bool]$m.IsTamperProtected
      cloud_protection = [bool]($m.MAPSReporting -ne 0)
      antispyware = [bool]$m.AntispywareEnabled
      antivirus = [bool]$m.AntivirusEnabled
      engine_version = [string]$m.AMEngineVersion
      signature_version = [string]$m.AntivirusSignatureVersion
      signature_updated = $(if ($m.AntivirusSignatureLastUpdated) { $m.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm:ss') } else { $null })
      quick_scan = $qs
      full_scan = $fs
      product_version = [string]$m.AMProductVersion
    }
  }
} catch {}

$r['bitlocker'] = @()
try {
  foreach ($v in (Get-BitLockerVolume -EA SilentlyContinue)) {
    $r['bitlocker'] += @{
      drive = [string]$v.MountPoint
      status = switch ($v.VolumeStatus) { 0 { '已解密' } 1 { '已加密' } 2 { '加密中' } 3 { '解密中' } 4 { '已暂停' } default { [string]$v.VolumeStatus } }
      protection = switch ($v.ProtectionStatus) { 0 { '关闭' } 1 { '开启' } default { '未知' } }
      encryption = switch ([string]$v.EncryptionMethod) {
        'None' { '无' } 'Aes128' { 'AES 128' } 'Aes256' { 'AES 256' }
        'XtsAes128' { 'XTS-AES 128' } 'XtsAes256' { 'XTS-AES 256' }
        default { [string]$v.EncryptionMethod }
      }
    }
  }
} catch {}

$r | ConvertTo-Json -Compress -Depth 6
"""

_UAC_TEXT = {
    0: "从不通知（自动提升）",
    1: "在安全桌面上提示凭据",
    2: "在安全桌面上提示同意",
    3: "提示凭据",
    4: "提示同意",
    5: "默认 — 仅在应用尝试更改计算机时通知",
}


def _bool_cn(v):
    if v is None:
        return None
    return "已启用" if v else "已关闭"


def _collect_security() -> dict:
    d = _ps_json(_PS_SECURITY, timeout=40) or {}
    uac = None
    if _i(d.get("uac_enabled")) == 0:
        uac = "已禁用"
    else:
        uac = _UAC_TEXT.get(_i(d.get("uac_prompt")))

    dv = d.get("defender") or {}
    last_scan, last_scan_type = None, None
    qs, fs = _s(dv.get("quick_scan")), _s(dv.get("full_scan"))
    if qs or fs:
        if qs and fs:
            if qs >= fs:
                last_scan, last_scan_type = qs, "快速扫描"
            else:
                last_scan, last_scan_type = fs, "完整扫描"
        elif qs:
            last_scan, last_scan_type = qs, "快速扫描"
        else:
            last_scan, last_scan_type = fs, "完整扫描"

    defender = None
    if dv:
        defender = {
            "name": _s(dv.get("name")) or "Windows Defender 防病毒",
            "enabled": dv.get("enabled"),
            "realtime_protection": dv.get("realtime_protection"),
            "tamper_protection": dv.get("tamper_protection"),
            "cloud_protection": dv.get("cloud_protection"),
            "antispyware": dv.get("antispyware"),
            "antivirus": dv.get("antivirus"),
            "engine_version": _s(dv.get("engine_version")),
            "signature_version": _s(dv.get("signature_version")),
            "signature_updated": _s(dv.get("signature_updated")),
            "last_scan": last_scan,
            "last_scan_type": last_scan_type,
        }

    products = []
    if defender:
        products.append({"type": "防病毒", "name": defender["name"],
                         "state": "已启用" if defender.get("enabled") else "已关闭",
                         "up_to_date": True if defender.get("signature_version") else None})
        if defender.get("antispyware"):
            products.append({"type": "反间谍软件", "name": defender["name"],
                             "state": "已启用" if defender.get("enabled") else "已关闭",
                             "up_to_date": None})
    fw_all = [d.get("fw_domain"), d.get("fw_private"), d.get("fw_public")]
    if any(v is not None for v in fw_all):
        products.append({"type": "防火墙", "name": "Windows 防火墙",
                         "state": "已启用" if all(v for v in fw_all if v is not None) else "部分启用",
                         "up_to_date": None})

    return {
        "uac": uac,
        "secure_boot": ("已启用" if d.get("secure_boot") else "未启用") if d.get("secure_boot") is not None else None,
        "tpm": {
            "present": d.get("tpm_present"),
            "version": _s(d.get("tpm_version")),
            "ready": d.get("tpm_ready"),
        },
        "firewall": {
            "domain": _bool_cn(d.get("fw_domain")),
            "private": _bool_cn(d.get("fw_private")),
            "public": _bool_cn(d.get("fw_public")),
        },
        "defender": defender,
        "products": products,
        "bitlocker": _as_list(d.get("bitlocker")),
    }


_PS_UPDATES = r"""
$r = @{}
$r['au_options'] = $null
$r['au_source'] = $null
$r['no_auto_update'] = $null
$r['last_check'] = $null
$r['last_install'] = $null
$r['wu_service'] = $null
$r['wu_startup'] = $null

# 1) Windows Update 服务状态（AUOptions 读不到时的兜底依据）
try {
  $svc = Get-Service -Name wuauserv -EA SilentlyContinue
  if ($svc) { $r['wu_service'] = [string]$svc.Status }
} catch {}
try {
  $cs = Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -EA SilentlyContinue
  if ($cs) { $r['wu_startup'] = [string]$cs.StartMode }
} catch {}

# 2) 注册表（非策略路径）
try {
  $p = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -EA SilentlyContinue
  if ($p -and $p.AUOptions -ne $null) { $r['au_options'] = [int]$p.AUOptions; $r['au_source'] = 'registry' }
  $d = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect' -EA SilentlyContinue
  if ($d -and $d.LastSuccessTime) { $r['last_check'] = ([datetime]$d.LastSuccessTime).ToString('yyyy-MM-dd HH:mm:ss') }
  $i = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -EA SilentlyContinue
  if ($i -and $i.LastSuccessTime) { $r['last_install'] = ([datetime]$i.LastSuccessTime).ToString('yyyy-MM-dd HH:mm:ss') }
} catch {}

# 3) 组策略（优先级高于上面的注册表）
try {
  $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -EA SilentlyContinue
  if ($pol) {
    if ($pol.NoAutoUpdate -ne $null) { $r['no_auto_update'] = [int]$pol.NoAutoUpdate }
    if ($pol.AUOptions -ne $null) { $r['au_options'] = [int]$pol.AUOptions; $r['au_source'] = 'policy' }
  }
} catch {}

# 4) Windows Update COM（最权威：拿到的是系统实际生效的设置）
try {
  $au = New-Object -ComObject Microsoft.Update.AutoUpdate
  if ($au.Settings) {
    $nl = [int]$au.Settings.NotificationLevel
    if ($nl -gt 0) { $r['au_options'] = $nl; $r['au_source'] = 'com' }
  }
  if ($au.Results) {
    try { if ($au.Results.LastSearchSuccessDate) { $r['last_check'] = ([datetime]$au.Results.LastSearchSuccessDate).ToString('yyyy-MM-dd HH:mm:ss') } } catch {}
    try { if ($au.Results.LastInstallationSuccessDate) { $r['last_install'] = ([datetime]$au.Results.LastInstallationSuccessDate).ToString('yyyy-MM-dd HH:mm:ss') } } catch {}
  }
} catch {}

$recent = @()
try {
  $recent = @(Get-HotFix -EA SilentlyContinue | Where-Object { $_.InstalledOn } |
    Sort-Object -Property InstalledOn -Descending | Select-Object -First 8 |
    ForEach-Object {
      @{ kb = [string]$_.HotFixID; title = [string]$_.Description
         installed_on = $(try { ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd HH:mm:ss') } catch { $null }) }
    })
} catch {}
$r['installed_recent'] = $recent
$r | ConvertTo-Json -Compress -Depth 6
"""

_PS_PENDING = r"""
$pending = @()
try {
  $s = New-Object -ComObject Microsoft.Update.Session
  $se = $s.CreateUpdateSearcher()
  $se.Online = $false
  $res = $se.Search('IsInstalled=0 and IsHidden=0')
  foreach ($u in $res.Updates) {
    $kbs = @()
    foreach ($k in $u.KBArticleIDs) { $kbs += ('KB' + $k) }
    $cats = @()
    foreach ($c in $u.Categories) { $cats += [string]$c.Name }
    $sev = [string]$u.MsrcSeverity
    $rel = $null
    if ($u.LastDeploymentChangeTime) { $rel = ([datetime]$u.LastDeploymentChangeTime).ToString('yyyy-MM-dd') }
    $pending += @{
      kb = ($kbs -join ',')
      title = [string]$u.Title
      severity = $(if ($sev) { $sev } else { $null })
      released = $rel
      category = $(if ($cats.Count -gt 0) { $cats[0] } else { $null })
      reboot_required = [bool]$u.RebootRequired
    }
  }
} catch {}
@{ pending = $pending } | ConvertTo-Json -Compress -Depth 6
"""

_AU_TEXT = {
    1: "从不检查更新",
    2: "自动下载并计划安装",
    3: "下载更新但由我选择是否安装",
    4: "自动下载并计划安装",
    5: "允许本地管理员选择配置",
}

_SEVERITY_CN = {
    "critical": "严重", "important": "重要", "moderate": "中等",
    "low": "低", "unspecified": "未指定", "": None, "null": None,
}


def _collect_pending_updates() -> list:
    """待安装更新（Windows Update COM 搜索，耗时较长 → 单独并发执行）。"""
    pd = _ps_json(_PS_PENDING, timeout=100) or {}
    pending = []
    for p in _as_list(pd.get("pending")):
        sev = _s(p.get("severity"))
        pending.append({
            "kb": _s(p.get("kb")),
            "title": _s(p.get("title")),
            "severity": _SEVERITY_CN.get((sev or "").lower(), sev),
            "released": _s(p.get("released")),
            "category": _s(p.get("category")),
            "reboot_required": bool(p.get("reboot_required")),
        })
    return pending


def _auto_update_state(d: dict) -> str | None:
    """自动更新「是否开启」：多来源判定，给不出结论才返回 None。

    判定顺序：
      1. 组策略 NoAutoUpdate=1 或 AUOptions=1（从不检查）→ 已关闭
      2. AUOptions >= 2 → 已开启
      3. AUOptions 读不到时，看 wuauserv 服务启动类型是否被禁用
    """
    au = _i(d.get("au_options"))
    no_auto = _i(d.get("no_auto_update"))
    startup = (_s(d.get("wu_startup")) or "").lower()
    if no_auto == 1 or au == 1:
        return "已关闭"
    if au and au >= 2:
        return "已开启"
    if startup == "disabled":
        return "已关闭"
    if startup in ("auto", "manual"):
        return "已开启"
    if _s(d.get("last_check")) or _s(d.get("last_install")):
        # 有过成功检测/安装记录，说明更新功能实际在用
        return "已开启"
    return None


def _collect_updates_base() -> dict:
    d = _ps_json(_PS_UPDATES, timeout=40) or {}
    recent = []
    for r in _as_list(d.get("installed_recent")):
        recent.append({
            "kb": _s(r.get("kb")),
            "title": _s(r.get("title")),
            "installed_on": _s(r.get("installed_on")),
        })
    if not d.get("last_install") and recent:
        d["last_install"] = recent[0].get("installed_on")
    return {
        # 主机信息页只展示「系统更新是否开启」，所以这里必须给出明确的是/否，
        # 而不是把 AUOptions 档位文本直接丢给前端（多数机器读不到 AUOptions 空白）
        "auto_update": _auto_update_state(d),
        "auto_update_detail": _AU_TEXT.get(_i(d.get("au_options"))),
        "auto_update_source": _s(d.get("au_source")),
        "last_check": _s(d.get("last_check")),
        "last_installed": _s(d.get("last_install")),
        "pending_count": None,
        "pending": [],
        "installed_recent": recent,
        "failed": [],
    }


def _collect_updates() -> dict:
    """基础更新状态 + 待安装更新（两者并发，见 collect_host_info）。"""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_base = ex.submit(_collect_updates_base)
        f_pending = ex.submit(_collect_pending_updates)
        data = f_base.result()
        try:
            pending = f_pending.result()
        except Exception:  # noqa: BLE001
            pending = []
    data["pending"] = pending
    data["pending_count"] = len(pending)
    return data


_PS_USERS = r"""
$r = @{}
$admins = @()
try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -EA SilentlyContinue | ForEach-Object { [string]$_.Name }) } catch {}
$list = @()
try {
  foreach ($u in (Get-LocalUser -EA SilentlyContinue)) {
    $ll = $null
    if ($u.LastLogon) { $ll = ([datetime]$u.LastLogon).ToString('yyyy-MM-dd HH:mm:ss') }
    $list += @{
      name = [string]$u.Name
      full_name = $(if ($u.FullName) { [string]$u.FullName } else { $null })
      enabled = [bool]$u.Enabled
      locked = [bool]$u.LockedOut
      password_expires = (-not $u.PasswordNeverExpires)
      last_logon = $ll
      description = $(if ($u.Description) { [string]$u.Description } else { $null })
    }
  }
} catch {}
foreach ($a in $admins) {
  $short = $a.Split('\')[-1]
  foreach ($u in $list) { if ($u.name -eq $short) { $u['admin'] = $true } }
}
$r['accounts'] = $list

$r['cur_name'] = $null; $r['cur_domain'] = $null; $r['cur_logon'] = $null; $r['cur_session'] = $null
try {
  $cs = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
  if ($cs -and $cs.UserName) {
    $parts = ([string]$cs.UserName).Split('\')
    if ($parts.Count -ge 2) { $r['cur_domain'] = $parts[0]; $r['cur_name'] = $parts[1] } else { $r['cur_name'] = [string]$cs.UserName }
  } else {
    $r['cur_name'] = $env:USERNAME; $r['cur_domain'] = $env:USERDOMAIN
  }
  $ls = Get-CimInstance Win32_LogonSession -EA SilentlyContinue | Where-Object { $_.LogonType -eq 2 -or $_.LogonType -eq 10 } | Sort-Object -Property StartTime -Descending | Select-Object -First 1
  if ($ls) {
    $r['cur_logon'] = $ls.StartTime.ToString('yyyy-MM-dd HH:mm:ss')
    $r['cur_session'] = switch ([int]$ls.LogonType) { 2 { '控制台' } 10 { '远程桌面' } default { '网络' } }
  }
} catch {}
$r['elevated'] = $false
try {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $r['elevated'] = [bool]((New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
} catch {}
$r | ConvertTo-Json -Compress -Depth 6
"""


def _collect_users() -> dict:
    d = _ps_json(_PS_USERS, timeout=40) or {}
    accounts = []
    for a in _as_list(d.get("accounts")):
        accounts.append({
            "name": _s(a.get("name")),
            "full_name": _s(a.get("full_name")),
            "enabled": bool(a.get("enabled")),
            "admin": bool(a.get("admin")),
            "locked": bool(a.get("locked")),
            "password_expires": bool(a.get("password_expires")),
            "last_logon": _s(a.get("last_logon")) or "从未",
            "description": _s(a.get("description")),
        })
    current = None
    if _s(d.get("cur_name")):
        current = {
            "name": _s(d.get("cur_name")),
            "domain": _s(d.get("cur_domain")),
            "logon_time": _s(d.get("cur_logon")),
            "session": _s(d.get("cur_session")),
            "elevated": bool(d.get("elevated")),
        }
    return {"current": current, "accounts": accounts}


_PS_SHARES = r"""
$out = @()
try {
  $smb = @(Get-SmbShare -EA SilentlyContinue)
  if ($smb.Count -gt 0) {
    foreach ($s in $smb) {
      $acc = @()
      try {
        foreach ($a in (Get-SmbShareAccess -Name $s.Name -EA SilentlyContinue)) {
          $acc += ([string]$a.AccountName + ':' + $(switch ([string]$a.AccessControlType) { 'Allow' { '允许' } 'Deny' { '拒绝' } default { [string]$a.AccessControlType } }) + $([string]$a.AccessRight))
        }
      } catch {}
      $out += @{ name = [string]$s.Name; path = [string]$s.Path; description = $(if ($s.Description) { [string]$s.Description } else { $null })
                 access = $(if ($acc.Count -gt 0) { ($acc -join '; ') } else { $null }); hidden = [bool]($s.Special -or ([string]$s.Name).EndsWith('$')) }
    }
  } else {
    foreach ($s in (Get-CimInstance Win32_Share -EA SilentlyContinue)) {
      $out += @{ name = [string]$s.Name; path = [string]$s.Path; description = $(if ($s.Caption) { [string]$s.Caption } else { $null })
                 access = $null; hidden = [bool](([string]$s.Name).EndsWith('$')) }
    }
  }
} catch {}
@{ shares = $out } | ConvertTo-Json -Compress -Depth 5
"""


def _collect_shares() -> list:
    d = _ps_json(_PS_SHARES, timeout=30) or {}
    out = []
    for s in _as_list(d.get("shares")):
        out.append({
            "name": _s(s.get("name")),
            "path": _s(s.get("path")),
            "description": _s(s.get("description")),
            "access": _s(s.get("access")),
            "hidden": bool(s.get("hidden")),
        })
    return out


_PS_CPU = r"""
$r = @{}
try {
  $p = @(Get-CimInstance Win32_Processor -EA SilentlyContinue)[0]
  if ($p) {
    $r['model'] = [string]$p.Name
    $r['vendor'] = [string]$p.Manufacturer
    $r['cores'] = [int]$p.NumberOfCores
    $r['threads'] = [int]$p.NumberOfLogicalProcessors
    $r['max_mhz'] = [int]$p.MaxClockSpeed
    $r['current_mhz'] = [int]$p.CurrentClockSpeed
    $r['l2_kb'] = $(if ($p.L2CacheSize) { [int]$p.L2CacheSize } else { $null })
    $r['l3_kb'] = $(if ($p.L3CacheSize) { [int]$p.L3CacheSize } else { $null })
    $r['vt'] = [bool]$p.VirtualizationFirmwareEnabled
    $r['load'] = $(if ($p.LoadPercentage -ne $null) { [int]$p.LoadPercentage } else { $null })
  }
  $r['sockets'] = @(Get-CimInstance Win32_Processor -EA SilentlyContinue).Count
} catch {}
try {
  $t = @(Get-CimInstance -Namespace 'root\WMI' -ClassName MSAcpi_ThermalZoneTemperature -EA SilentlyContinue | Select-Object -First 1)
  if ($t.Count -gt 0) { $r['temp'] = [math]::Round((($t[0].CurrentTemperature / 10) - 273.15), 1) } else { $r['temp'] = $null }
} catch { $r['temp'] = $null }
$r | ConvertTo-Json -Compress -Depth 5
"""


def _kb(v):
    if not v:
        return None
    if v >= 1024:
        return f"{round(v / 1024)} MB" if v % 1024 == 0 else f"{round(v / 1024, 1)} MB"
    return f"{v} KB"


def _collect_cpu() -> dict:
    d = _ps_json(_PS_CPU, timeout=30) or {}
    cores = _i(d.get("cores"))
    threads = _i(d.get("threads"))
    sockets = _i(d.get("sockets")) or 1

    # 逻辑处理器数 / 物理核数的比值。指令集扩展（AES-NI/AVX2 等）在不跑
    # CPUID 的前提下无法可靠判定，宁可留空也不臆造。
    feats = []
    if d.get("vt"):
        feats.append("虚拟化已启用 (VT-x/AMD-V)")
    if cores and threads and threads > cores:
        feats.append(f"超线程 ({cores} 核 {threads} 线程)")

    usage, per_core = None, []
    if psutil:
        try:
            usage = psutil.cpu_percent(interval=0.4)
            per_core = [round(x, 1) for x in psutil.cpu_percent(interval=0.4, percpu=True)]
            per_core = [int(x) if float(x).is_integer() else x for x in per_core]
        except Exception:
            pass

    return {
        "model": _s(d.get("model")),
        "vendor": _s(d.get("vendor")),
        "sockets": sockets,
        "cores": cores,
        "threads": threads,
        "base_mhz": _i(d.get("max_mhz")),
        "current_mhz": _i(d.get("current_mhz")),
        "max_mhz": _i(d.get("max_mhz")),
        "cache": {
            "l1d": None,
            "l1i": None,
            "l2": (f"{cores} × {_kb(round(_i(d.get('l2_kb')) / cores))}" if (_i(d.get("l2_kb")) and cores) else (_kb(_i(d.get("l2_kb"))))),
            "l3": _kb(_i(d.get("l3_kb"))),
        },
        "temperature": _f(d.get("temp")),
        "package_power": None,
        "usage": round(usage, 1) if usage is not None else None,
        "process": None,
        "features": feats,
        "load_per_core": per_core,
    }


_PS_MEM = r"""
$r = @{}
$mods = @()
try {
  foreach ($m in (Get-CimInstance Win32_PhysicalMemory -EA SilentlyContinue)) {
    $ecc = $false
    if ($m.TotalWidth -and $m.DataWidth) { $ecc = ([int]$m.TotalWidth - [int]$m.DataWidth) -ge 8 }
    $mods += @{
      slot = $(if ($m.DeviceLocator) { [string]$m.DeviceLocator } else { [string]$m.BankLabel })
      capacity_gb = [math]::Round(([double]$m.Capacity / 1GB), 1)
      speed_mhz = $(if ($m.ConfiguredClockSpeed) { [int]$m.ConfiguredClockSpeed } else { $(if ($m.Speed) { [int]$m.Speed } else { $null }) })
      raw_speed = $(if ($m.Speed) { [int]$m.Speed } else { $null })
      smbios_type = $(if ($m.SMBIOSMemoryType) { [int]$m.SMBIOSMemoryType } else { $null })
      manufacturer = $(if ($m.Manufacturer) { [string]$m.Manufacturer } else { $null })
      part_number = $(if ($m.PartNumber) { [string]$m.PartNumber } else { $null })
      voltage = $(if ($m.ConfiguredVoltage) { [math]::Round(([int]$m.ConfiguredVoltage / 1000.0), 2) } else { $null })
      ecc = [bool]$ecc
    }
  }
} catch {}
$r['modules'] = $mods
try {
  $arr = @(Get-CimInstance Win32_PhysicalMemoryArray -EA SilentlyContinue)
  $total = 0
  foreach ($a in $arr) { $total += [int]$a.MemoryDevices }
  $r['slots_total'] = $total
} catch { $r['slots_total'] = $null }
$r | ConvertTo-Json -Compress -Depth 6
"""

_MEM_TYPE = {20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM", 24: "DDR3", 26: "DDR4", 34: "DDR5", 0: None}


def _collect_memory() -> dict:
    d = _ps_json(_PS_MEM, timeout=30) or {}
    mods = []
    for m in _as_list(d.get("modules")):
        speed = _i(m.get("speed_mhz")) or _i(m.get("raw_speed"))
        mtype = _MEM_TYPE.get(_i(m.get("smbios_type")) or 0)
        mods.append({
            "slot": _s(m.get("slot")),
            "capacity_gb": _f(m.get("capacity_gb")),
            "type": (f"{mtype}-{speed}" if (mtype and speed) else mtype),
            "speed_mhz": speed,
            "manufacturer": _s(m.get("manufacturer")),
            "part_number": _s(m.get("part_number")),
            "voltage": _f(m.get("voltage"), 2),
            "temperature": None,
            "ecc": bool(m.get("ecc")),
        })
    total_gb, usage = None, None
    if psutil:
        try:
            vm = psutil.virtual_memory()
            total_gb = round(vm.total / (1024 ** 3), 1)
            usage = round(vm.percent, 1)
        except Exception:
            pass
        if total_gb is None:
            total_gb = round(sum(m["capacity_gb"] or 0 for m in mods), 1) or None

    n = len(mods)
    channels = {1: "单通道", 2: "双通道", 3: "三通道", 4: "四通道", 6: "六通道", 8: "八通道"}.get(n)
    speed = mods[0]["speed_mhz"] if mods else None
    mtype = (mods[0]["type"] or "").split("-")[0] if mods else None

    return {
        "total_gb": total_gb,
        "slots_used": n or None,
        "slots_total": _i(d.get("slots_total")),
        "type": mtype or None,
        "channels": channels,
        "speed_mhz": speed,
        "usage": usage,
        "modules": mods,
    }


_PS_STORAGE = r"""
$out = @()
try {
  $phys = @(Get-PhysicalDisk -EA SilentlyContinue)
  if ($phys.Count -gt 0) {
    foreach ($d in $phys) {
      $rel = Get-StorageReliabilityCounter -PhysicalDisk $d -EA SilentlyContinue
      $smart = $null
      if ($rel) {
        $smart = @{
          power_on_hours = $(if ($rel.PowerOnHours -ne $null) { [int]$rel.PowerOnHours } else { $null })
          power_cycle_count = $null
          reallocated_sectors = $null
          wear_leveling = $(if ($rel.Wear -ne $null) { ([string]$rel.Wear + '%') } else { $null })
          temperature = $(if ($rel.Temperature -ne $null) { [int]$rel.Temperature } else { $null })
        }
      }
      $parts = @()
      try {
        foreach ($p in (Get-Partition -DiskNumber ([int]$d.DeviceId) -EA SilentlyContinue)) {
          if (-not $p.DriveLetter) { continue }
          $letter = ([char]([int]$p.DriveLetter)) + ':'
          $label = $null; $fs = $null
          $v = Get-Volume -Partition $p -EA SilentlyContinue
          if ($v) { $label = [string]$v.FileSystemLabel; $fs = [string]$v.FileSystem }
          $parts += @{ letter = $letter; label = $label; fs = $fs; size_gb = [math]::Round(([double]$p.Size / 1GB), 1) }
        }
      } catch {}
      $out += @{
        model = [string]$d.FriendlyName
        bus = [string]$d.BusType
        media_type = [string]$d.MediaType
        size_gb = [math]::Round(([double]$d.Size / 1GB), 1)
        serial = [string]$d.SerialNumber
        firmware = [string]$d.FirmwareVersion
        health = [string]$d.HealthStatus
        smart = $smart
        partitions = $parts
      }
    }
  } else {
    foreach ($d in (Get-CimInstance Win32_DiskDrive -EA SilentlyContinue)) {
      $out += @{
        model = [string]$d.Model
        bus = [string]$d.InterfaceType
        media_type = [string]$d.MediaType
        size_gb = [math]::Round(([double]$d.Size / 1GB), 1)
        serial = $(if ($d.SerialNumber) { ([string]$d.SerialNumber).Trim() } else { $null })
        firmware = [string]$d.FirmwareRevision
        health = $null
        smart = $null
        partitions = @()
      }
    }
  }
} catch {}
@{ disks = $out } | ConvertTo-Json -Compress -Depth 6
"""

_HEALTH_CN = {"Healthy": "良好", "Warning": "警告", "Unhealthy": "不正常", "Unknown": "未知", "": None}
_MEDIA_CN = {"SSD": "SSD", "HDD": "HDD", "Unspecified": None, "SCM": "SCM", "": None}
_BUS_CN = {"SATA": "SATA", "NVMe": "NVMe", "SAS": "SAS", "USB": "USB", "RAID": "RAID",
           "SCSI": "SCSI", "iSCSI": "iSCSI", "File Backed Virtual": "虚拟磁盘", "": None}


def _collect_storage() -> list:
    d = _ps_json(_PS_STORAGE, timeout=45) or {}
    out = []
    for dk in _as_list(d.get("disks")):
        smart = dk.get("smart") or {}
        temp = None
        if smart:
            temp = _i(smart.get("temperature"))
        parts = []
        for p in _as_list(dk.get("partitions")):
            letter = _s(p.get("letter"))
            used = free = pct = None
            if letter and psutil:
                try:
                    u = psutil.disk_usage(letter)
                    used = round(u.used / (1024 ** 3), 1)
                    free = round(u.free / (1024 ** 3), 1)
                    pct = u.percent
                except Exception:
                    pass
            parts.append({
                "letter": letter,
                "label": _s(p.get("label")),
                "fs": _s(p.get("fs")),
                "size_gb": _f(p.get("size_gb")),
                "used_gb": used,
                "free_gb": free,
                "percent": round(pct, 1) if pct is not None else None,
            })
        out.append({
            "model": _s(dk.get("model")),
            "interface": _BUS_CN.get(_s(dk.get("bus")) or "", _s(dk.get("bus"))),
            "media_type": _MEDIA_CN.get(_s(dk.get("media_type")) or "", _s(dk.get("media_type"))),
            "size_gb": _f(dk.get("size_gb")),
            "serial": _s(dk.get("serial")),
            "firmware": _s(dk.get("firmware")),
            "temperature": temp,
            "health": _HEALTH_CN.get(_s(dk.get("health")) or "", _s(dk.get("health"))),
            "smart": {
                "power_on_hours": _i(smart.get("power_on_hours")) if smart else None,
                "power_cycle_count": None,
                "reallocated_sectors": None,
                "wear_leveling": _s(smart.get("wear_leveling")) if smart else None,
            } if smart else None,
            "partitions": parts,
        })
    return out


_PS_NET = r"""
$out = @()
try {
  foreach ($a in (Get-NetAdapter -EA SilentlyContinue)) {
    if ($a.Status -eq 'Not Present') { continue }
    $cfg = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -EA SilentlyContinue
    $ipif = Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -EA SilentlyContinue
    $v4 = @(); $v6 = @(); $gw = @(); $dns = @()
    if ($cfg) {
      foreach ($x in @($cfg.IPv4Address)) { if ($x.IPAddress) { $v4 += ($x.IPAddress + '/' + $x.PrefixLength) } }
      foreach ($x in @($cfg.IPv6Address)) { if ($x.IPAddress) { $v6 += [string]$x.IPAddress } }
      foreach ($x in @($cfg.IPv4DefaultGateway)) { if ($x.NextHop) { $gw += [string]$x.NextHop } }
      foreach ($x in @($cfg.DNSServer)) { if ($x.AddressFamily -eq 2) { foreach ($s in $x.ServerAddresses) { $dns += [string]$s } } }
    }
    $media = [string]$a.PhysicalMediaType
    if (-not $media -or $media -eq 'Unspecified') { $media = [string]$a.MediaType }
    $out += @{
      name = [string]$a.InterfaceDescription
      alias = [string]$a.Name
      media = $media
      mac = [string]$a.MacAddress
      ipv4 = $v4; ipv6 = $v6; gateway = $gw; dns = $dns
      dhcp = $(if ($ipif) { ([string]$ipif.Dhcp) -eq 'Enabled' } else { $null })
      speed = [string]$a.LinkSpeed
      mtu = $(if ($a.MtuSize) { [int]$a.MtuSize } else { $null })
      status = [string]$a.Status
    }
  }
} catch {}
@{ adapters = $out } | ConvertTo-Json -Compress -Depth 6
"""

_NET_STATUS_CN = {"Up": "已连接", "Disconnected": "已断开", "Disabled": "已禁用", "Dormant": "休眠中", "": None}
_NET_MEDIA_CN = {"802.3": "以太网", "Native 802.11": "无线局域网", "Wireless WAN": "移动网络",
                 "Bluetooth": "蓝牙", "": None}


def _collect_network() -> list:
    d = _ps_json(_PS_NET, timeout=30) or {}
    out = []
    for a in _as_list(d.get("adapters")):
        media = _s(a.get("media"))
        out.append({
            "name": _s(a.get("name")) or _s(a.get("alias")),
            "type": _NET_MEDIA_CN.get(media, media),
            "mac": _s(a.get("mac")),
            "ipv4": [x for x in _as_list(a.get("ipv4")) if x],
            "ipv6": [x for x in _as_list(a.get("ipv6")) if x],
            "gateway": [x for x in _as_list(a.get("gateway")) if x],
            "dns": [x for x in _as_list(a.get("dns")) if x],
            "dhcp": a.get("dhcp"),
            "speed": _s(a.get("speed")),
            "mtu": _i(a.get("mtu")),
            "status": _NET_STATUS_CN.get(_s(a.get("status")) or "", _s(a.get("status"))),
            "vlan": None,
        })
    if not out:
        for a in _collect_network_psutil():
            out.append(a)
    return out


def _collect_network_psutil() -> list:
    if not psutil:
        return []
    out = []
    try:
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            st = stats.get(name)
            v4, v6, mac = [], [], None
            for ad in addrs:
                if ad.family.name == "AF_INET":
                    v4.append(ad.address)
                elif ad.family.name == "AF_INET6":
                    v6.append(ad.address.split("%")[0])
                elif ad.family.name == "AF_LINK":
                    mac = ad.address
            out.append({
                "name": name, "type": None, "mac": mac, "ipv4": v4, "ipv6": v6,
                "gateway": [], "dns": [], "dhcp": None,
                "speed": (f"{st.speed} Mbps" if st and st.speed else None),
                "mtu": (st.mtu if st else None),
                "status": ("已连接" if st and st.isup else "已断开"),
                "vlan": None,
            })
    except Exception:
        pass
    return out


def _collect_displays() -> list:
    """用 EnumDisplayMonitors + GetMonitorInfo + EnumDisplaySettings 采集真实物理排列。"""
    if not IS_WIN:
        return []
    import ctypes
    from ctypes import wintypes

    out = []
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)

        class RECT(ctypes.Structure):
            _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                        ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

        class MONITORINFOEX(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", RECT), ("rcWork", RECT),
                        ("dwFlags", wintypes.DWORD), ("szDevice", wintypes.WCHAR * 32)]

        class DEVMODE(ctypes.Structure):
            _fields_ = [
                ("dmDeviceName", wintypes.WCHAR * 32), ("dmSpecVersion", wintypes.WORD),
                ("dmDriverVersion", wintypes.WORD), ("dmSize", wintypes.WORD),
                ("dmDriverExtra", wintypes.WORD), ("dmFields", wintypes.DWORD),
                ("dmPositionX", ctypes.c_long), ("dmPositionY", ctypes.c_long),
                ("dmDisplayOrientation", wintypes.DWORD), ("dmDisplayFixedOutput", wintypes.DWORD),
                ("dmColor", ctypes.c_short), ("dmDuplex", ctypes.c_short),
                ("dmYResolution", ctypes.c_short), ("dmTTOption", ctypes.c_short),
                ("dmCollate", ctypes.c_short), ("dmFormName", wintypes.WCHAR * 32),
                ("dmLogPixels", wintypes.WORD), ("dmBitsPerPel", wintypes.DWORD),
                ("dmPelsWidth", wintypes.DWORD), ("dmPelsHeight", wintypes.DWORD),
                ("dmDisplayFlags", wintypes.DWORD), ("dmDisplayFrequency", wintypes.DWORD),
            ]

        monitors = []
        MONITORENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                                             ctypes.POINTER(RECT), ctypes.c_double)

        def _cb(hmon, hdc, lprc, data):
            monitors.append(ctypes.c_ulong(hmon).value)
            return 1

        if not user32.EnumDisplayMonitors(None, None, MONITORENUMPROC(_cb), 0):
            return []

        dm_count = ctypes.c_ulong(0)
        get_names = True
        try:
            dxva2 = ctypes.WinDLL("dxva2", use_last_error=True)

            class PHYSICAL_MONITOR(ctypes.Structure):
                _fields_ = [("hPhysicalMonitor", wintypes.HANDLE),
                            ("szPhysicalMonitorDescription", wintypes.WCHAR * 128)]

            class _PHYS_MON(ctypes.Structure):
                _fields_ = [("hPhysicalMonitor", wintypes.HANDLE),
                            ("szPhysicalMonitorDescription", wintypes.WCHAR * 128)]

            dxva2.GetNumberOfPhysicalMonitorsFromHMONITOR.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ulong)]
            dxva2.GetNumberOfPhysicalMonitorsFromHMONITOR.restype = wintypes.BOOL
            dxva2.GetPhysicalMonitorsFromHMONITOR.argtypes = [
                wintypes.HANDLE, ctypes.c_ulong, ctypes.POINTER(_PHYS_MON)]
            dxva2.GetPhysicalMonitorsFromHMONITOR.restype = wintypes.BOOL
            dxva2.DestroyPhysicalMonitors.argtypes = [ctypes.c_ulong, ctypes.POINTER(_PHYS_MON)]
            dxva2.DestroyPhysicalMonitors.restype = wintypes.BOOL
        except Exception:
            get_names = False

        get_dpi = True
        try:
            shcore = ctypes.WinDLL("shcore", use_last_error=True)
            shcore.GetDpiForMonitor.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                ctypes.POINTER(ctypes.c_uint),
                                                ctypes.POINTER(ctypes.c_uint)]
            shcore.GetDpiForMonitor.restype = ctypes.HRESULT
        except Exception:
            get_dpi = False

        user32.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MONITORINFOEX)]
        user32.GetMonitorInfoW.restype = wintypes.BOOL
        user32.EnumDisplaySettingsW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD,
                                                ctypes.POINTER(DEVMODE)]
        user32.EnumDisplaySettingsW.restype = wintypes.BOOL

        MONITORINFOF_PRIMARY = 0x00000001
        ENUM_CURRENT_SETTINGS = 0xFFFFFFFF
        MDT_EFFECTIVE_DPI = 0
        ORIENT = {0: "横向", 1: "纵向", 2: "横向(翻转)", 3: "纵向(翻转)"}

        for idx, hmon in enumerate(sorted(monitors), start=1):
            mi = MONITORINFOEX()
            mi.cbSize = ctypes.sizeof(MONITORINFOEX)
            if not user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
                continue
            dm = DEVMODE()
            if not user32.EnumDisplaySettingsW(mi.szDevice, ENUM_CURRENT_SETTINGS, ctypes.byref(dm)):
                continue
            name = None
            if get_names:
                try:
                    cnt = ctypes.c_ulong(0)
                    if dxva2.GetNumberOfPhysicalMonitorsFromHMONITOR(hmon, ctypes.byref(cnt)) and cnt.value:
                        arr = (_PHYS_MON * cnt.value)()
                        if dxva2.GetPhysicalMonitorsFromHMONITOR(hmon, cnt, arr):
                            name = (arr[0].szPhysicalMonitorDescription or "").strip() or None
                        try:
                            dxva2.DestroyPhysicalMonitors(cnt, arr)
                        except Exception:
                            pass
                except Exception:
                    pass
            scale = None
            if get_dpi:
                try:
                    dx = ctypes.c_uint(0)
                    dy = ctypes.c_uint(0)
                    if shcore.GetDpiForMonitor(hmon, MDT_EFFECTIVE_DPI,
                                               ctypes.byref(dx), ctypes.byref(dy)) == 0:
                        scale = int(round(dx.value * 100 / 96))
                except Exception:
                    pass
            orient = ORIENT.get(int(dm.dmDisplayOrientation), None)
            out.append({
                "index": idx,
                "name": name or _s(mi.szDevice),
                "primary": bool(mi.dwFlags & MONITORINFOF_PRIMARY),
                "x": int(dm.dmPositionX),
                "y": int(dm.dmPositionY),
                "width": int(dm.dmPelsWidth),
                "height": int(dm.dmPelsHeight),
                "refresh": int(dm.dmDisplayFrequency) or None,
                "scale": scale,
                "orientation": orient,
                "connection": None,
            })
    except Exception as exc:  # noqa: BLE001
        _warn(f"host_info: display collect failed: {exc!r}")
        return []
    return out


_PS_DEVICES = r"""
$out = @()
try {
  foreach ($d in (Get-CimInstance Win32_PnPEntity -EA SilentlyContinue)) {
    if (-not $d.Name) { continue }
    $cls = [string]$d.PNPClass
    if (-not $cls -or $cls -eq 'System') { continue }
    $out += @{
      cls = $cls
      name = [string]$d.Name
      vendor = $(if ($d.Manufacturer) { [string]$d.Manufacturer } else { $null })
      status = [string]$d.Status
    }
  }
} catch {}
@{ devices = $out } | ConvertTo-Json -Compress -Depth 5
"""

_DEVICE_CLASS_CN = {
    "Display": "显示适配器", "Net": "网络适配器", "DiskDrive": "磁盘驱动器",
    "Keyboard": "键盘", "Mouse": "鼠标", "USB": "USB 设备", "Printer": "打印机",
    "Battery": "电池/UPS", "Monitor": "监视器", "MEDIA": "声音设备",
    "Sound": "声音设备", "AudioEndpoint": "声音设备", "HIDClass": "HID 设备",
    "SCSIAdapter": "存储控制器", "HDC": "存储控制器", "Processor": "处理器",
    "Computer": "计算机", "SecurityDevices": "安全设备", "FDC": "软盘控制器",
    "Ports": "端口", "Image": "图像设备", "Bluetooth": "蓝牙", "Modem": "调制解调器",
    "SmartCardReader": "智能卡读卡器", "Biometric": "生物识别设备", "Firmware": "固件",
    "WPD": "便携设备", "Cameras": "照相机", "Unknown": None, "": None,
}
_DEVICE_CLASS_ORDER = [
    "显示适配器", "存储控制器", "磁盘驱动器", "网络适配器", "声音设备", "处理器",
    "键盘", "鼠标", "HID 设备", "监视器", "USB 设备", "打印机", "电池/UPS",
    "安全设备", "蓝牙", "图像设备", "智能卡读卡器", "便携设备", "照相机", "端口",
]

_DEVICE_STATUS_CN = {"OK": "正常", "Error": "异常", "Degraded": "降级",
                     "Unknown": "未知", "Pred Fail": "即将失效", "Starting": "启动中",
                     "Stopped": "已停止", "Service": "服务中", "Stressed": "压力",
                     "NonRecover": "不可恢复", "No Contact": "无连接",
                     "Lost Comm": "通信丢失", "": None}


def _collect_devices(motherboard: dict) -> list:
    d = _ps_json(_PS_DEVICES, timeout=40) or {}
    buckets: dict[str, list] = {}
    for dev in _as_list(d.get("devices")):
        cn = _DEVICE_CLASS_CN.get(_s(dev.get("cls")) or "", _s(dev.get("cls")))
        if not cn:
            continue
        name = _s(dev.get("name"))
        if not name:
            continue
        buckets.setdefault(cn, []).append({
            "category": cn,
            "name": name,
            "vendor": _s(dev.get("vendor")),
            "status": _DEVICE_STATUS_CN.get(_s(dev.get("status")) or "", _s(dev.get("status"))),
            "details": "",
        })

    out = []
    if motherboard.get("model"):
        out.append({"category": "主板", "name": motherboard.get("model"),
                    "vendor": motherboard.get("manufacturer"), "status": "正常", "details": ""})
    seen = set()
    for cat in _DEVICE_CLASS_ORDER:
        for item in buckets.get(cat, [])[:6]:
            key = (item["category"], item["name"])
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    for cat, items in buckets.items():
        if cat in _DEVICE_CLASS_ORDER:
            continue
        for item in items[:3]:
            key = (item["category"], item["name"])
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return out[:80]


def _reg_iter(hive, subkey, flags):
    import winreg
    try:
        h = winreg.OpenKey(hive, subkey, 0, flags)
    except OSError:
        return
    index = 0
    try:
        while True:
            try:
                name = winreg.EnumKey(h, index)
            except OSError:
                break
            index += 1
            try:
                with winreg.OpenKey(h, name, 0, flags) as sk:
                    vals = {}
                    i = 0
                    while True:
                        try:
                            n, v, _t = winreg.EnumValue(sk, i)
                        except OSError:
                            break
                        i += 1
                        vals[n] = v
                    yield name, vals
            except OSError:
                continue
    finally:
        try:
            winreg.CloseKey(h)
        except OSError:
            pass


def list_applications() -> list:
    """带 60 秒缓存；卸载时需要最新清单请调用 _scan_applications()。"""
    return _cached("applications", _scan_applications)


# 「系统应用」判定：**只有操作系统自带 / 运行时 / 驱动 / 补丁才算**。
# ToDesk、Node.js、WPS、酷狗音乐、多可档案这类第三方软件错分进系统应用。
_SYS_APP_NAME_RE = [
    re.compile(r"^kb\d+", re.I),
    re.compile(r"\b(hotfix|service pack)\b", re.I),
    re.compile(r"^(security update|update for|累积更新|安全更新)", re.I),
    re.compile(r"^microsoft (visual c\+\+|visual basic|visual studio)", re.I),
    re.compile(r"^microsoft (\.net|asp\.net)", re.I),
    re.compile(r"^microsoft windows desktop runtime", re.I),
    re.compile(r"^microsoft (edge|update health)", re.I),
    re.compile(r"^microsoft (silverlight|xna|web deploy)", re.I),
    re.compile(r"^windows (sdk|defender|malicious|malware)", re.I),
    re.compile(r"^windows (安装助手|电脑健康状况检查|更新)", re.I),
    re.compile(r"^windows (11|10)", re.I),
    re.compile(r"^windows driver package", re.I),
]

_SYS_APP_LOC_RE = [
    re.compile(r"^[a-z]:\\windows\\", re.I),
    re.compile(r"\\windows\\system32\\spool\\drivers", re.I),
    re.compile(r"\\windows\\system32\\driverstore", re.I),
]


def _is_system_app(name: str | None, location: str | None = None) -> bool:
    n = (name or "").strip()
    if not n:
        return False
    loc = (location or "").replace("/", "\\")
    if any(rx.search(n) for rx in _SYS_APP_NAME_RE):
        return True
    if loc and any(rx.search(loc) for rx in _SYS_APP_LOC_RE):
        return True
    if re.search(r"driver", n, re.I) and loc and any(rx.search(loc) for rx in _SYS_APP_LOC_RE):
        return True
    return False


def _scan_applications() -> list:
    if not IS_WIN:
        return []
    import winreg
    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         winreg.KEY_READ | winreg.KEY_WOW64_64KEY, "system"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         winreg.KEY_READ | winreg.KEY_WOW64_32KEY, "system"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         winreg.KEY_READ | winreg.KEY_WOW64_64KEY, "user"),
    ]
    apps = []
    seen = set()
    for hive, sub, flags, scope in paths:
        try:
            for key, v in _reg_iter(hive, sub, flags):
                name = _s(v.get("DisplayName"))
                if not name:
                    continue
                if _i(v.get("SystemComponent")) == 1:
                    continue
                if _s(v.get("ParentKeyName")):
                    continue
                if (_s(v.get("ReleaseType")) or "").lower() in ("security update", "update", "hotfix", "service pack"):
                    continue
                ver = _s(v.get("DisplayVersion"))
                ident = f"{scope}|{name}|{ver}".lower()
                if ident in seen:
                    continue
                seen.add(ident)
                # UninstallString 是「拉起界面」的那条，静默参数得靠我们按卸载器类型补。
                raw_uninstall = _s(v.get("UninstallString"))
                quiet_uninstall = _s(v.get("QuietUninstallString"))
                uninstall = quiet_uninstall or raw_uninstall
                size = _i(v.get("EstimatedSize"))
                inst = _s(v.get("InstallDate"))
                if inst and len(inst) == 8 and inst.isdigit():
                    inst = f"{inst[0:4]}-{inst[4:6]}-{inst[6:8]}"
                location = _s(v.get("InstallLocation"))
                apps.append({
                    "id": hashlib.md5(f"{scope}|{key}".encode("utf-8")).hexdigest()[:16],
                    "name": name,
                    "version": ver,
                    "publisher": _s(v.get("Publisher")),
                    "installed_on": inst,
                    "scope": scope,
                    # 系统/用户分类：按「是否系统组件」判定，而不是按装在哪
                    "is_system": _is_system_app(name, location),
                    "size_mb": round(size / 1024, 1) if size else None,
                    "install_location": location,
                    "uninstall_cmd": uninstall,
                    "uninstall_string": raw_uninstall,
                    "quiet_uninstall": quiet_uninstall,
                    "uninstallable": bool(uninstall),
                    "source": "registry",
                })
        except Exception as exc:  # noqa: BLE001
            _warn(f"host_info: app scan failed: {exc!r}")
    apps.sort(key=lambda a: (a["name"] or "").lower())
    return apps


_PS_WU_HISTORY = r"""
$out = @()
try {
  $s = New-Object -ComObject Microsoft.Update.Session
  $se = $s.CreateUpdateSearcher()
  $total = $se.GetTotalHistoryCount()
  if ($total -gt 0) {
    $n = [Math]::Min($total, 300)
    foreach ($h in ($se.QueryHistory(0, $n))) {
      if ($h.Operation -ne 1) { continue }
      if ($h.ResultCode -ne 2) { continue }
      $kb = $null
      if ($h.Title -match 'KB\d{5,}') { $kb = $Matches[0] }
      $out += @{
        kb = $kb
        title = [string]$h.Title
        installed_on = $(try { ([datetime]$h.Date).ToString('yyyy-MM-dd HH:mm:ss') } catch { $null })
        client = [string]$h.ClientApplicationID
      }
    }
  }
} catch {}
@{ updates = $out } | ConvertTo-Json -Compress -Depth 5
"""


def _classify_update(title: str) -> tuple[str, str]:
    t = (title or "").lower()
    if "恶意软件删除工具" in t or "malicious software removal" in t:
        return "工具", "低"
    if "definition" in t or "定义更新" in t:
        return "安全更新", "低"
    if "security" in t or "安全" in t:
        return "安全更新", "重要"
    if "critical" in t or "严重" in t:
        return "重要更新", "严重"
    if "cumulative" in t or "累积" in t or "rollup" in t:
        return "累积更新", "中等"
    if "driver" in t or "驱动" in t:
        return "驱动更新", "中等"
    if "feature" in t or "功能" in t:
        return "功能更新", "中等"
    return "更新", "中等"


def list_system_updates() -> list:
    if not IS_WIN:
        return []
    d = _ps_json(_PS_WU_HISTORY, timeout=60) or {}
    out = []
    seen = set()
    for u in _as_list(d.get("updates")):
        title = _s(u.get("title"))
        if not title:
            continue
        kb = _s(u.get("kb"))
        key = kb or title
        if key in seen:
            continue
        seen.add(key)
        cat, sev = _classify_update(title)
        cmdtxt = f"wusa /uninstall /kb:{kb[2:]}" if (kb and kb.upper().startswith("KB") and kb[2:].isdigit()) else None
        out.append({
            "id": hashlib.md5((kb or title).encode("utf-8")).hexdigest()[:16],
            "kb": kb,
            "title": title,
            "category": cat,
            "installed_on": _s(u.get("installed_on")),
            "severity": sev,
            "uninstall_cmd": cmdtxt,
        })
    if not out:
        for h in (_ps_json(_PS_UPDATES, timeout=40) or {}).get("installed_recent") or []:
            kb = _s(h.get("kb"))
            title = _s(h.get("title")) or kb
            cat, sev = _classify_update(title)
            out.append({
                "id": hashlib.md5((kb or title or "").encode("utf-8")).hexdigest()[:16],
                "kb": kb, "title": title, "category": cat,
                "installed_on": _s(h.get("installed_on")),
                "severity": sev,
                "uninstall_cmd": (f"wusa /uninstall /kb:{kb[2:]}" if (kb and kb.upper().startswith("KB") and kb[2:].isdigit()) else None),
            })
    out.sort(key=lambda x: (x.get("installed_on") or ""), reverse=True)
    return out


# 只把卸载程序拉起来是不够的：Agent 跑在服务/后台会话里，没人去点卸载向导的「下一步」，
# 应用永远不会真的被卸载。这里按卸载器类型补静默参数 等待进程退出 复查注册表确认条目消失；
# 认不出类型的卸载器**不猜参数**，回退到原命令（拉起界面）并把原因回报给前端。
_UNINSTALL_WAIT = 180
_UNINSTALL_BUDGET = 600
_UNINSTALL_VERIFY_WAIT = 20

_DETACHED = (getattr(subprocess, "DETACHED_PROCESS", 0) |
             getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))


def _split_cmd(cmd: str) -> tuple:
    """把命令行拆成 (可执行文件, 参数)。路径未加引号但含空格时也能拆对。"""
    c = (cmd or "").strip()
    if not c:
        return "", ""
    m = re.match(r'^"([^"]+)"\s*(.*)$', c) or re.match(r"^'([^']+)'\s*(.*)$", c)
    if m:
        return m.group(1), m.group(2).strip()
    m = re.match(r"^(\S+?\.exe)\s*(.*)$", c, re.I)
    if m:
        return m.group(1), m.group(2).strip()
    idx = c.lower().find(".exe")
    if idx > 0:
        return c[:idx + 4], c[idx + 4:].strip()
    parts = c.split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def _with_args(exe: str, args: str, *extra: str) -> str:
    """补静默参数（已存在的不重复补），返回最终命令行。"""
    out = (args or "").strip()
    low = out.lower()
    for a in extra:
        if a.lower() in low:
            continue
        out = f"{out} {a}".strip()
    head = f'"{exe}"' if (" " in exe and not exe.startswith('"')) else exe
    return f"{head} {out}".strip()


def _silent_uninstall_cmd(uninstall: str, quiet: str) -> str:
    """按卸载器类型生成静默卸载命令；无法识别时返回 ""（绝不瞎猜参数）。"""
    for raw in (quiet, uninstall):
        c = (raw or "").strip()
        if not c:
            continue
        exe, args = _split_cmd(c)
        if not exe:
            continue
        base = os.path.basename(exe.replace("/", "\\")).lower()
        low = args.lower()

        if base.startswith("msiexec"):
            m = re.search(r"\{[0-9a-fA-F-]{36}\}", args)
            if not m:
                continue
            quiet_mode = "/qb" if "/qb" in low else "/qn"
            return f"msiexec.exe /X{m.group(0)} {quiet_mode} /norestart"

        if re.match(r"^unins\d*\.exe$", base):
            return _with_args(exe, args, "/VERYSILENT", "/NORESTART",
                              "/SUPPRESSMSGBOXES", "/SP-")

        # 必须带 _?=<安装目录>，否则 NSIS 会把自己复制到临时目录后立刻返回，等不到结束。
        if base in ("au_.exe", "un_a.exe") or "uninstall" in base or re.match(r"^uninst", base):
            extra = ["/S"]
            inst_dir = os.path.dirname(exe.rstrip("\\/"))
            if inst_dir and "_?=" not in args:
                extra.append(f"_?={inst_dir}")
            return _with_args(exe, args, *extra)

        if base == "unwise.exe":
            return _with_args(exe, args, "/S")

        if base in ("setup.exe", "isuninst.exe", "ikernel.exe") or "installshield" in exe.lower():
            return _with_args(exe, args, "/s", "/SMS")

        if base.startswith("wusa"):
            return _with_args(exe, args, "/quiet", "/norestart")
    return ""


def _app_id_set() -> set:
    try:
        return {a["id"] for a in _scan_applications()}
    except Exception as exc:  # noqa: BLE001
        _warn(f"host_info: rescan apps failed: {exc!r}")
        return set()


# 卸载命令来自注册表里的 UninstallString，HKCU\\…\\Uninstall 是**普通用户可写**
# 就替它执行了第二条。所以这里**绝不能给 shell=True**
# 当命令行，不经过 cmd.exe，`& | > < ^` 这些不再被当成操作符，只是普通参数。
# 兼容性几乎无损（引号解析规则一致），代价只是不再展开 %VAR%、不支持 cmd 内置
_UNINSTALL_SHELL = False


def _run_uninstall(cmd: str, wait: int) -> tuple:
    """执行卸载命令并等待结束，返回 (是否按时结束, 退出码, 说明)。"""
    try:
        proc = subprocess.Popen(cmd, shell=_UNINSTALL_SHELL, close_fds=True,
                                creationflags=_DETACHED)
    except Exception as exc:  # noqa: BLE001
        return False, None, f"启动卸载程序失败：{exc}"
    try:
        return True, proc.wait(timeout=wait), ""
    except subprocess.TimeoutExpired:
        return False, None, f"等待 {wait} 秒仍未结束"
    except Exception as exc:  # noqa: BLE001
        return False, None, f"等待卸载程序结束失败：{exc}"


def _wait_removed(app_id: str) -> bool:
    """复查注册表：条目消失即视为卸载完成（部分卸载器收尾慢，最多等 20 秒）。"""
    deadline = time.time() + _UNINSTALL_VERIFY_WAIT
    while True:
        if app_id not in _app_id_set():
            return True
        if time.time() >= deadline:
            return False
        time.sleep(2)


def _launch_detached(cmd: str) -> str:
    """回退：原样拉起卸载程序（界面模式），不等待。返回错误说明（成功为空串）。"""
    try:
        subprocess.Popen(cmd, shell=_UNINSTALL_SHELL, close_fds=True,
                         creationflags=_DETACHED)
        return ""
    except Exception as exc:  # noqa: BLE001
        return f"启动卸载程序失败：{exc}"


def uninstall_applications(ids: list) -> dict:
    """卸载应用：静默执行 + 等待结束 + 复查注册表校验。

    返回 {"ok": bool, "results": [{"id","ok","mode","message"}]}；
    mode = silent（自动完成）/ ui（回退到界面，需人工收尾）/ none（未执行）。
    """
    if not IS_WIN:
        return {"ok": False, "results": [
            {"id": i, "ok": False, "mode": "none", "message": "仅 Windows 支持卸载"}
            for i in (ids or [])
        ]}
    apps = {a["id"]: a for a in _scan_applications()}
    results = []
    ok_all = True
    deadline_all = time.time() + _UNINSTALL_BUDGET
    for aid in (ids or []):
        app = apps.get(aid)
        if not app:
            results.append({"id": aid, "ok": False, "mode": "none", "message": "未找到该应用"})
            ok_all = False
            continue
        name = app.get("name") or aid
        if not app.get("uninstall_cmd"):
            results.append({"id": aid, "ok": False, "mode": "none",
                            "message": f"{name} 未提供卸载命令"})
            ok_all = False
            continue
        if time.time() >= deadline_all:
            results.append({"id": aid, "ok": False, "mode": "none",
                            "message": f"{name} 未执行：本次批量卸载等待已达上限，请分批重试"})
            ok_all = False
            continue

        cmd = _silent_uninstall_cmd(app.get("uninstall_string") or "",
                                    app.get("quiet_uninstall") or "")
        if not cmd:
            err = _launch_detached(app["uninstall_cmd"])
            ok_all = False
            results.append({"id": aid, "ok": False, "mode": "ui",
                            "message": f"{name} 的卸载程序不支持已知的静默参数，"
                                       + (err if err else "已拉起卸载界面，请在主机上手动完成")})
            continue

        wait = max(5, min(_UNINSTALL_WAIT, int(deadline_all - time.time())))
        finished, code, note = _run_uninstall(cmd, wait)
        if not finished:
            ok_all = False
            results.append({"id": aid, "ok": False, "mode": "silent",
                            "message": f"{name} 静默卸载未完成（{note}），请稍后在主机上确认"})
            continue
        if _wait_removed(aid):
            results.append({"id": aid, "ok": True, "mode": "silent",
                            "message": f"{name} 已卸载完成（退出码 {code}）"})
            continue
        # 静默执行了但条目还在：回退拉起界面，让人工收尾
        err = _launch_detached(app["uninstall_cmd"])
        ok_all = False
        results.append({"id": aid, "ok": False, "mode": "ui",
                        "message": f"{name} 静默卸载未生效（退出码 {code}）"
                                   + (err if err else "，已拉起卸载界面，请在主机上手动完成")})
    invalidate()
    return {"ok": ok_all, "results": results}


_RUN_ROOTS = [
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 1),
    ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0),
]
_APPROVED = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"


def _hive(name: str):
    import winreg
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[name]


def _open_key(hive_name: str, sub: str, wow32: bool, access=None, create=False):
    import winreg
    flags = access if access is not None else winreg.KEY_READ
    if wow32:
        flags |= winreg.KEY_WOW64_32KEY
    else:
        flags |= winreg.KEY_WOW64_64KEY
    fn = winreg.CreateKeyEx if create else winreg.OpenKey
    return fn(_hive(hive_name), sub, 0, flags)


def _startup_id(hive: str, sub: str, name: str) -> str:
    raw = f"{hive}|{sub}|{name}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def _startup_decode(item_id: str):
    try:
        pad = "=" * (-len(item_id) % 4)
        raw = base64.urlsafe_b64decode((item_id or "") + pad).decode("utf-8")
        hive, sub, name = raw.split("|", 2)
        if hive not in ("HKLM", "HKCU"):
            return None
        if "StartupApproved" in sub or "Explorer" in sub:
            return None
        if sub.count("\\") < 3:
            return None
        return hive, sub, name
    except Exception:
        return None


def _approved_state(hive_name: str, name: str):
    """读 StartupApproved 状态：True 启用 / False 禁用 / None 未记录(默认启用)。"""
    import winreg
    for wow32 in (False, True):
        try:
            with _open_key(hive_name, _APPROVED, wow32) as k:
                try:
                    data, _t = winreg.QueryValueEx(k, name)
                except OSError:
                    continue
                if isinstance(data, (bytes, bytearray)) and len(data) >= 4:
                    return data[0] != 0x03
                return None
        except OSError:
            continue
    return None


def list_startup_items() -> list:
    if not IS_WIN:
        return []
    import winreg
    out = []
    seen = set()
    for hive_name, sub, wow32 in _RUN_ROOTS:
        try:
            with _open_key(hive_name, sub, wow32) as k:
                i = 0
                while True:
                    try:
                        n, v, _t = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    key = f"{hive_name}|{n}".lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    state = _approved_state(hive_name, n)
                    out.append({
                        "id": _startup_id(hive_name, sub, n),
                        "name": _s(n),
                        "command": _s(v),
                        "location": f"{hive_name}\\{sub}" + (" (32 位)" if wow32 else ""),
                        "enabled": True if state is None else state,
                        "impact": None,
                    })
        except OSError:
            continue
        except Exception as exc:  # noqa: BLE001
            _warn(f"host_info: startup scan failed: {exc!r}")
    out.sort(key=lambda x: (not x["enabled"], (x["name"] or "").lower()))
    return out


def set_startup_enabled(item_id: str, enabled: bool) -> dict:
    if not IS_WIN:
        return {"ok": False, "detail": "仅 Windows 支持启动项管理"}
    import winreg
    decoded = _startup_decode(item_id)
    if not decoded:
        return {"ok": False, "detail": "启动项标识无效"}
    hive_name, sub, name = decoded
    try:
        with _open_key(hive_name, sub, False) as k:
            winreg.QueryValueEx(k, name)
    except OSError:
        return {"ok": False, "detail": "该启动项已不存在，请刷新后重试"}
    data = (b"\x02" if enabled else b"\x03") + b"\x00" * 11
    try:
        with _open_key(hive_name, _APPROVED, False, winreg.KEY_WRITE, create=True) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, data)
    except OSError as exc:
        return {"ok": False, "detail": f"写入启动项状态失败：{exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": f"写入启动项状态失败：{exc}"}
    invalidate()
    return {"ok": True, "enabled": bool(enabled)}


_LEVEL_CN = {1: "严重", 2: "错误", 3: "警告", 4: "信息", 5: "详细"}
_LEVEL_FILTER = {"严重": 1, "错误": 2, "警告": 3, "信息": 4}
# 中文日志名 英文原名（旧数据没有 log 字段时的回推）
_LOG_CN_TO_EN = {"系统": "System", "应用程序": "Application", "安全": "Security", "安装": "Setup"}

# 注意：不要用 param(...)，调用方会在脚本最前面插入输出编码设置，
# param 块必须位于脚本首行，否则整段脚本解析失败（事件日志恒返回 0 条）。
_PS_EVENTS = r"""
$out = @()
# 时间范围：Get-WinEvent 的 StartTime/EndTime 只认 DateTime，
# 且不接受与 LogName 之外的非法组合，解析失败就退化成不限制（不返回空）。
$st = $null
$en = $null
if ($Start -and $Start -ne '') {
  try { $st = [datetime]::ParseExact([string]$Start, 'yyyy-MM-dd HH:mm:ss', $null) } catch { $st = $null }
}
if ($End -and $End -ne '') {
  try { $en = [datetime]::ParseExact([string]$End, 'yyyy-MM-dd HH:mm:ss', $null) } catch { $en = $null }
}
# 逐个日志查询：安全/安装日志可能为空或需管理员权限，失败时不影响其它日志
# 每个日志**均分**配额：否则某个活跃日志（如 Setup）会把其它日志全部挤掉，
# 前端切到 System / Security 就是空的。
$logs = @('System','Application','Security','Setup')
$per = [math]::Ceiling($Limit / $logs.Count)
foreach ($lg in $logs) {
  $ht = @{ LogName = $lg }
  if ($Level -gt 0) { $ht['Level'] = $Level }
  if ($st) { $ht['StartTime'] = $st }
  if ($en) { $ht['EndTime'] = $en }
  try {
    $ev = Get-WinEvent -FilterHashtable $ht -MaxEvents $per -EA SilentlyContinue
    foreach ($e in $ev) {
      $msg = [string]$e.Message
      if ($msg.Length -gt 600) { $msg = $msg.Substring(0, 600) + '...' }
      $msg = $msg -replace "`r`n", ' ' -replace "`n", ' '
      $out += @{
        id = ([string]$e.LogName) + '-' + ([string]$e.RecordId)
        time = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        source = [string]$e.ProviderName
        event_id = [int]$e.Id
        level = [int]$e.Level
        # log 是英文原名（前端按 System/Application/Security/Setup 分类用）
        log = [string]$e.LogName
        category = switch ([string]$e.LogName) { 'System' { '系统' } 'Application' { '应用程序' } 'Security' { '安全' } 'Setup' { '安装' } default { [string]$e.LogName } }
        message = $msg
      }
    }
  } catch {}
}
$out = @($out | Sort-Object -Property time -Descending | Select-Object -First $Limit)
@{ items = $out } | ConvertTo-Json -Compress -Depth 4
"""


# 事件日志默认回溯窗口（天）。前端/后端不传起止时间时用这个，
# 否则 Windows 机器上一拉就是几个月前的上万条。
EVENT_LOG_DEFAULT_DAYS = 3


def _norm_event_time(s) -> str:
    """把 'YYYY-MM-DD HH:MM:SS' / 'YYYY-MM-DDTHH:MM' / 日期 统一成 PS 认识的格式。"""
    s = (s or "").strip()
    if not s:
        return ""
    s = s.replace("T", " ")
    if len(s) == 10:
        return s
    if len(s) == 16:
        return s + ":00"
    return s[:19]


def list_event_logs(level: str | None = None, limit: int = 200,
                    start: str | None = None, end: str | None = None) -> list:
    if not IS_WIN:
        return []
    lv = _LEVEL_FILTER.get((level or "").strip(), 0) if level not in (None, "", "all") else 0
    try:
        limit = max(1, min(int(limit or 200), 2000))
    except (TypeError, ValueError):
        limit = 200

    st = _norm_event_time(start)
    en = _norm_event_time(end)
    if not st and not en:
        from datetime import datetime, timedelta
        st = (datetime.now() - timedelta(days=EVENT_LOG_DEFAULT_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    elif len(st) == 10:
        st = st + " 00:00:00"
    if len(en) == 10:
        en = en + " 23:59:59"

    head = (
        f"$Limit = {limit}\n"
        f"$Level = {lv}\n"
        f"$Start = '{st}'\n"
        f"$End = '{en}'\n"
    )
    d = _ps_json(head + _PS_EVENTS, timeout=60) or {}
    out = []
    for e in _as_list(d.get("items")):
        out.append({
            "id": _s(e.get("id")),
            "time": _s(e.get("time")),
            "source": _s(e.get("source")),
            "event_id": _i(e.get("event_id")),
            "level": _LEVEL_CN.get(_i(e.get("level")), "信息"),
            "log": _s(e.get("log")) or _LOG_CN_TO_EN.get(_s(e.get("category")), _s(e.get("category"))),
            "category": _s(e.get("category")),
            "message": _s(e.get("message")),
        })
    return out


def _agent_version() -> str | None:
    try:
        from api_server import AGENT_VERSION  # noqa: WPS433
        return AGENT_VERSION
    except Exception:
        return None


def collect_host_info() -> dict:
    """采集主机信息。

    各分项之间无依赖（只有 devices 需要 machine 里的主板信息），
    而每一项都要起一个 PowerShell 进程跑 WMI，串行会到 40 秒量级 →
    全部并发执行，单项失败降级为 None/[]，不影响整页。
    """
    def _build():
        from concurrent.futures import ThreadPoolExecutor

        machine, os_info = _collect_machine_os()
        with ThreadPoolExecutor(max_workers=8) as ex:
            f_sec = ex.submit(_collect_security)
            f_upd = ex.submit(_collect_updates)
            f_usr = ex.submit(_collect_users)
            f_shr = ex.submit(_collect_shares)
            f_cpu = ex.submit(_collect_cpu)
            f_mem = ex.submit(_collect_memory)
            f_sto = ex.submit(_collect_storage)
            f_net = ex.submit(_collect_network)
            f_dis = ex.submit(_collect_displays)
            f_dev = ex.submit(_collect_devices, machine.get("motherboard") or {})
            f_sta = ex.submit(list_startup_items)
            return {
                "collected_at": _stamp(),
                "agent_version": _agent_version(),
                "machine": machine,
                "os": os_info,
                "security": f_sec.result(),
                "updates": f_upd.result(),
                "users": f_usr.result(),
                "startup": f_sta.result(),
                "shares": f_shr.result(),
                "cpu": f_cpu.result(),
                "memory": f_mem.result(),
                "storage": f_sto.result(),
                "network": f_net.result(),
                "displays": f_dis.result(),
                "devices": f_dev.result(),
            }

    return _cached("host_info", _build)
