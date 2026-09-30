"""VigilServe 版本号一致性自检。

用法：
    python verify_version.py              # 人 readable 报告
    python verify_version.py --json       # 机器可读，便于接到 CI / 构建前

为什么需要它
------------
版本号分散在 8 个文件里（共 15 个校验点），改的时候靠人肉记得同步。历史上有三个真实后果：

  * 侧边栏左下角显示的版本号是前端写死的 v1.1.35，服务端其实早就 1.1.4x 了，
    排障时按界面上的号去找代码，找错版本；
  * installer/source/ 里躺着上一次构建留下的旧副本，打出来的安装包
    「服务端 1.1.43 + Agent 1.1.49」，装完两边对不上；
  * version_info.txt 里同时存在「StringTable 字符串」和「FixedFileInfo 数值」
    两套版本号，升版时只改了前者，于是 1.1.54 的托盘 exe 顶着 1.1.52 的
    FixedFileInfo 和 1.1.53 的 ProductVersion 发了两轮 —— 资源管理器属性页
    的「产品版本」一直是错的。现在两处都强制校验。

真源只有两个：
  * 服务端版本号 = backend/main.py 里 FastAPI(version=...)
  * Agent 版本号  = agent/api_server.py 里的 AGENT_VERSION

其余位置都应当跟随这两处。不一致就退出码 1。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _backend_version() -> str:
    """服务端版本号的真源：backend/main.py 的 FastAPI(version="x.y.z")。"""
    m = re.search(r'^\s*version\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
                  _read(ROOT / "backend" / "main.py"), re.M)
    return m.group(1) if m else ""


def _agent_version() -> str:
    """Agent 版本号的真源：agent/api_server.py 的 AGENT_VERSION。"""
    m = re.search(r'^AGENT_VERSION\s*=\s*["\']([^"\']+)["\']',
                  _read(ROOT / "agent" / "api_server.py"), re.M)
    return m.group(1) if m else ""


def _iss_version(rel: str) -> str:
    m = re.search(r'#define\s+MyAppVersion\s+"([^"]+)"', _read(ROOT / rel))
    return m.group(1) if m else ""


def _py_const(rel: str, name: str) -> str:
    m = re.search(rf'^{name}\s*=\s*["\']([^"\']+)["\']', _read(ROOT / rel), re.M)
    return m.group(1) if m else ""


def _version_info_txt(rel: str) -> str:
    """version_info.txt 里的 FileVersion（形如 1.1.43.0 → 取前三段）。"""
    return _version_info_str(rel, "FileVersion")


def _version_info_str(rel: str, key: str) -> str:
    """version_info.txt 的 StringTable 里某个字段（形如 1.1.43.0 → 取前三段）。"""
    m = re.search(rf"StringStruct\(u?'{key}',\s*u?'([^']+)'\)", _read(ROOT / rel))
    if not m:
        return ""
    parts = m.group(1).split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else m.group(1)


def _version_info_ffi(rel: str) -> str:
    """version_info.txt 的 FixedFileInfo 数值版本。

    2026-09-28 补：以往升版只改了 StringTable 里的 FileVersion 字符串，
    filevers / prodvers 两个数值没跟着动，于是 exe 的资源里是
    「FixedFileInfo=1.1.52.0 + FileVersion=1.1.54.0」的混合体 —— 资源管理器
    属性页的「产品版本」显示成上一个版本。这里把两处数值都钉住。
    返回 "" 表示文件缺失或解析不到；返回 "filevers≠prodvers" 表示两者互不相同。
    """
    txt = _read(ROOT / rel)
    if not txt:
        return ""
    out = []
    for key in ("filevers", "prodvers"):
        m = re.search(rf"{key}=\((\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)", txt)
        out.append(".".join(m.groups()[:3]) if m else "")
    if any(not v for v in out):
        return ""
    return out[0] if out[0] == out[1] else f"{out[0]}≠{out[1]}"


def _package_json() -> str:
    m = re.search(r'"version"\s*:\s*"([^"]+)"', _read(ROOT / "frontend" / "package.json"))
    return m.group(1) if m else ""


def _mock_agent_version() -> str:
    """hostInfoMock.js 里写死的 agent_version（假数据，但会显示在界面上）。"""
    m = re.search(r"agent_version:\s*'([^']+)'",
                  _read(ROOT / "frontend" / "src" / "services" / "hostInfoMock.js"))
    return m.group(1) if m else ""


def collect() -> list[dict]:
    sv = _backend_version()
    av = _agent_version()
    # (分组, 说明, 文件相对路径, 期望值, 实际值, 是否强制)
    rows = [
        ("服务端", "backend/main.py（真源）", "backend/main.py", sv, sv, True),
        ("服务端", "installer/setup.iss 的 MyAppVersion", "installer/setup.iss",
         sv, _iss_version("installer/setup.iss"), True),
        ("服务端", "tray/tray_app.py 的 TRAY_VERSION", "tray/tray_app.py",
         sv, _py_const("tray/tray_app.py", "TRAY_VERSION"), True),
        ("服务端", "tray/version_info.txt 的 FileVersion", "tray/version_info.txt",
         sv, _version_info_txt("tray/version_info.txt"), True),
        ("服务端", "tray/version_info.txt 的 ProductVersion", "tray/version_info.txt",
         sv, _version_info_str("tray/version_info.txt", "ProductVersion"), True),
        ("服务端", "tray/version_info.txt 的 FixedFileInfo", "tray/version_info.txt",
         sv, _version_info_ffi("tray/version_info.txt"), True),
        ("Agent", "agent/api_server.py（真源）", "agent/api_server.py", av, av, True),
        ("Agent", "agent/agent.py 的 VERSION", "agent/agent.py",
         av, _py_const("agent/agent.py", "VERSION"), True),
        ("Agent", "agent/agent_headless.py 的 VERSION", "agent/agent_headless.py",
         av, _py_const("agent/agent_headless.py", "VERSION"), True),
        ("Agent", "agent/version_info.txt 的 FileVersion", "agent/version_info.txt",
         av, _version_info_txt("agent/version_info.txt"), True),
        ("Agent", "agent/version_info.txt 的 ProductVersion", "agent/version_info.txt",
         av, _version_info_str("agent/version_info.txt", "ProductVersion"), True),
        ("Agent", "agent/version_info.txt 的 FixedFileInfo", "agent/version_info.txt",
         av, _version_info_ffi("agent/version_info.txt"), True),
        ("Agent", "agent/installer/VigilServeAgent.iss 的 MyAppVersion",
         "agent/installer/VigilServeAgent.iss", av,
         _iss_version("agent/installer/VigilServeAgent.iss"), True),
        # 下面两处历史上长期忘记同步：先按 WARN 报出来，不阻断构建
        ("前端", "frontend/package.json 的 version", "frontend/package.json",
         sv, _package_json(), False),
        ("前端", "hostInfoMock.js 写死的 agent_version",
         "frontend/src/services/hostInfoMock.js", av, _mock_agent_version(), False),
    ]
    out = []
    for group, desc, rel, want, got, hard in rows:
        out.append({
            "group": group, "desc": desc, "path": rel,
            "expected": want, "actual": got,
            "ok": bool(want) and want == got, "blocking": hard,
        })
    return out


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    rows = collect()
    bad = [r for r in rows if not r["ok"]]
    hard_bad = [r for r in bad if r["blocking"]]

    if as_json:
        print(json.dumps({"rows": rows, "ok": not bad, "blocking_fail": bool(hard_bad)},
                         ensure_ascii=False, indent=2))
        return 1 if hard_bad else 0

    sv = _backend_version()
    av = _agent_version()
    print(f"服务端真源 {sv}    Agent 真源 {av}\n")
    width = max(len(r["desc"]) for r in rows)
    for r in rows:
        mark = "OK  " if r["ok"] else ("FAIL" if r["blocking"] else "WARN")
        tail = "" if r["ok"] else f"  (期望 {r['expected']} / 实际 {r['actual'] or '未解析到'})"
        print(f"  [{mark}] {r['desc']:<{width}}{tail}")

    if hard_bad:
        print(f"\n✗ {len(hard_bad)} 处版本号不一致（必须修）")
        return 1
    if bad:
        print(f"\n⚠ {len(bad)} 处版本号未跟随（不阻断构建，建议同步）")
        return 0
    print("\n✓ 全部一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
