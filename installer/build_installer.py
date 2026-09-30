"""One-step build script for the VigilServe server installer.

Usage:
    python build_installer.py [--allow-stale]

This script:
  1. Cleans stale / sensitive files from the project tree so they don't
     leak into the installer source tree (e.g. monitor.db, backend.log,
     __pycache__).
  2. Re-stages the installer/source/ tree from the latest builds:
       backend/  (Python source, no DB / no logs)
       frontend/dist/
       tray/VigilServeTray.exe
       agent/VigilServeAgent/  (onedir build) + agent_config.json
       start.bat / start_tray.bat / install.bat / setup_autostart.bat ...
  3. Refreshes installer/branding/installer.ico from F:\\VigilServe\\logo_定稿.png
     so the logo is always current.
  4. Regenerates installer/license.txt from the user agreement docx in
     F:\\VigilServe\\VigilServe用户协议.docx.
  5. Invokes ISCC.exe to compile the Inno Setup installer.
  6. Copies the resulting server installer and the latest agent installer
     into F:\\VigilServe. The tray exe is bundled INSIDE the server installer
     (installed to {app}\\tray\\VigilServeTray.exe), so it is NOT shipped as
     a separate deliverable.

Guards added after the 1.1.43 delivery review (the installer previously
shipped a 1.1.43 backend next to a 1.1.49 Agent because a stale build
artifact was silently reused):

  * phase 3.5 - required build artifacts must exist (frontend/dist,
    tray exe, agent onedir exe, agent_config.json). Missing => abort,
    unless --allow-stale is passed.
  * phase 4.5 - the staged tree's backend version and AGENT_VERSION must
    equal the source tree's, and setup.iss MyAppVersion must equal the
    backend version. Any mismatch => abort.
  * phase 4.0 - the portable Python runtime must satisfy the CURRENT
    backend/requirements.txt (version pins + dependency closure + import
    smoke, straight from build_python_runtime.py). Missing => abort.

  最后这条是 2026-09-30 补的：`portable_runtime/` 只会由人工跑一次
  `build_python_runtime.py` 产出，而打包脚本原先只把它原样复制 —— requirements
  事后新增的依赖（`pysnmp` / `pyasn1`）没人检查，安装包就静默带着缺包的运行时出
  去了，现场表现为网络设备"测试连接"报 `No module named 'pysnmp'`。

`installer/source/` is a build artifact, not a hand-maintained snapshot:
stage_source_tree() wipes and rebuilds it every run. A stale version there
always means an upstream build step was skipped, never that it needs a
manual edit.

The script is idempotent and safe to re-run.
"""
from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALLER_DIR = ROOT / "installer"
SOURCE_DIR = INSTALLER_DIR / "source"
BRAND_DIR = INSTALLER_DIR / "branding"
OUTPUT_DIR = INSTALLER_DIR / "output"

PORTABLE_RUNTIME_DIR = INSTALLER_DIR / "portable_runtime"

# 而它们在两个不同的函数里，用模块级变量比层层传参干净。
ALLOW_STALE = False

TARGET_DIR = Path(r"F:\VigilServe")

# 而不是需要手工维护。构建末尾会校验二者一致，不一致直接失败。
BACKEND_MAIN_SRC = ROOT / "backend" / "main.py"
AGENT_MAIN_SRC = ROOT / "agent" / "api_server.py"
AGENT_MAIN_STAGED = SOURCE_DIR / "agent" / "VigilServeAgent" / "_internal" / "api_server.py"
SETUP_ISS = INSTALLER_DIR / "setup.iss"

# 构建必需产物。缺任何一个都说明构建链路断了，默认直接失败，
# 否则打出来的安装包会"服务端是新代码、Agent/前端还是上个月的"，
# 且安装后版本号与实际代码不符，排障时极难发现。
REQUIRED_ARTIFACTS = [
    (ROOT / "frontend" / "dist", "dir", "npm run build（frontend/）"),
    # 托盘没有 build.py，用 spec 构建；构建脚本只校验产物在不在、不代劳重建。
    (ROOT / "tray" / "dist" / "VigilServeTray.exe", "file",
     "cd tray && <tray-build venv>/python -m PyInstaller VigilServeTray.spec --noconfirm"),
    (ROOT / "agent" / "dist" / "VigilServeAgent" / "VigilServeAgent.exe", "file",
     "python agent/build_installer.py"),
    (ROOT / "agent" / "agent_config.json", "file", "agent/agent_config.json（应随源码提交）"),
]

F_BRAND = Path(r"F:\VigilServe")
LOGO = F_BRAND / "logo_定稿.png"
AGREEMENT_DOCX = F_BRAND / "VigilServe用户协议.docx"

ISCC = Path(r"C:\Program Files\Inno Setup 7\ISCC.exe")

# Files / directories that should never make it into an installer
FORBIDDEN_BASENAMES = {
    "__pycache__", "build", ".git", "node_modules", ".vite", "dist_new",
    "dist_new7", "build_new", "build_new7", "dist_old",
    "data",
    ".deps_installed",
    # 安全加固阶段 2：本地 CA 与服务器证书必须在**每台机器上首次启动时生成**。
    # 把 ca.key（信任根私钥）打进安装包 = 所有部署共用同一把根密钥，
    # 任何一台机器被攻破即可签出任意受信任证书。这里整目录排除。
    "certs",
}

SENSITIVE_SUFFIXES = (".log", ".db", ".db-shm", ".db-wal", ".pyc", ".tmp")

SENSITIVE_BASENAMES = {
    "thumbs.db", "desktop.ini", ".ds_store",
    "initial_admin_password.txt",
    "ca.key",                      # 本地 CA 私钥，绝不能离开服务器
    "server.key",                  # 服务器证书私钥，同上
    "secret.key",
    # 第三轮审计 N-1（2026-09-23）：MeshCentral Login Token 的 **80 字节 AES 主密钥**。
    # 它原先只在开发机上生成过一次，随后被 stage_source_tree() 整目录拷进
    # installer/source/backend/，每个拿到安装包的部署都共用同一把密钥。
    # 排除之后由 `meshcentral_client.ensure_default_keyfile()` 在**目标机器上首次
    # 生成**，与上面 ca.key / server.key 的处理口径完全一致。
    "meshcentral-key.txt",
}


def step(msg: str) -> None:
    print(f"[build] {msg}", flush=True)


def safe_rmtree(p: Path | str) -> None:
    p = Path(p)
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def _is_sensitive_filename(name: str) -> bool:
    n = name.lower()
    if n in SENSITIVE_BASENAMES:
        return True
    return any(n.endswith(s) for s in SENSITIVE_SUFFIXES)


def clean_tree(root: Path) -> None:
    """Remove __pycache__ / *.log / *.db* / .deps_installed / thumbs.db etc."""
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in FORBIDDEN_BASENAMES]
        for f in filenames:
            if _is_sensitive_filename(f):
                victim = Path(dirpath) / f
                try:
                    victim.unlink()
                    step(f"  removed sensitive: {victim.relative_to(ROOT)}")
                except FileNotFoundError:
                    pass


def rebuild_logo_brand():
    """Build installer/branding/installer.ico from F:\\VigilServe\\logo_定稿.png."""
    from PIL import Image

    BRAND_DIR.mkdir(parents=True, exist_ok=True)
    src = Image.open(LOGO).convert("RGBA")
    sizes = [16, 24, 32, 48, 64, 128, 256]
    buf = io.BytesIO()
    src.save(buf, format="ICO", sizes=[(s, s) for s in sizes])
    out = BRAND_DIR / "installer.ico"
    out.write_bytes(buf.getvalue())
    step(f"  wrote {out.relative_to(ROOT)} ({out.stat().st_size:,d} bytes)")


def rebuild_license_text():
    """Convert F:\\VigilServe\\VigilServe用户协议.docx into plain text."""
    import re, html
    with zipfile.ZipFile(AGREEMENT_DOCX) as z:
        xml = z.read("word/document.xml").decode("utf-8", errors="ignore")
    paras = []
    for chunk in re.split(r"</w:p>", xml):
        texts = re.findall(r"<w:t[^>]*>([^<]*)</w:t>", chunk)
        if texts:
            line = "".join(texts)
            line = html.unescape(line).strip()
            if line:
                paras.append(line)
    out = INSTALLER_DIR / "license.txt"
    out.write_text("\n".join(paras) + "\n", encoding="utf-8")
    step(f"  wrote {out.relative_to(ROOT)} ({out.stat().st_size:,d} bytes, {len(paras)} paragraphs)")


def stage_source_tree():
    """Rebuild installer/source/ from the current project state."""
    safe_rmtree(SOURCE_DIR)
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)

    # 2026-09-23 第三轮审计 N-1：`SENSITIVE_BASENAMES` 里的文件**必须**出现在这里。
    # 历史上靠 `clean_tree()` 在 stage 之后扫掉，但 phase 1 早已把它摘掉
    # （源码树不能扫），而这份 IGNORE 只带了 FORBIDDEN_BASENAMES，结果
    # `initial_admin_password.txt` 靠重复写一遍侥幸还在，
    # `ca.key` / `server.key` / `secret.key` / `meshcentral-key.txt` **全都拦不住**，
    # 会原样打进安装包（meshcentral-key.txt 已在 installer/source/ 里实测存在）。
    # 现在把两份名单合并，一套口径覆盖全部敏感文件。
    IGNORE = shutil.ignore_patterns(
        *FORBIDDEN_BASENAMES,
        *SENSITIVE_BASENAMES,
        "*.log", "*.db*", "*.pyc",
        "initial_admin_password.txt", ".deps_installed",
    )

    shutil.copytree(ROOT / "backend", SOURCE_DIR / "backend", ignore=IGNORE)
    if (ROOT / "frontend" / "dist").is_dir():
        shutil.copytree(ROOT / "frontend" / "dist", SOURCE_DIR / "frontend" / "dist")
    else:
        step("  WARN: frontend/dist missing - run `npm run build` first")

    tray_dst = SOURCE_DIR / "tray"
    tray_dst.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "tray" / "dist" / "VigilServeTray.exe", tray_dst / "VigilServeTray.exe")

    agent_src = ROOT / "agent" / "dist" / "VigilServeAgent"
    agent_dst = SOURCE_DIR / "agent" / "VigilServeAgent"
    safe_rmtree(agent_dst)
    if agent_src.exists():
        shutil.copytree(agent_src, agent_dst)
    else:
        step("  WARN: agent/dist/VigilServeAgent missing - rebuild via agent/build_installer.py")
    shutil.copy2(ROOT / "agent" / "agent_config.json", SOURCE_DIR / "agent" / "agent_config.json")

    # only need to land in installer/scripts/
    SCRIPTS_DIR = INSTALLER_DIR / "scripts"
    if SCRIPTS_DIR.is_dir():
        for name in ("start.bat", "start_tray.bat", "install.bat",
                     "setup_autostart.bat", "remove_autostart.bat",
                     "reset_admin_password.bat",
                     # 卸载前精确停服（无窗口 python 进程用的，见脚本头注释）
                     "stop_services.bat"):
            src = SCRIPTS_DIR / name
            dst = SOURCE_DIR / name
            if src.exists():
                shutil.copy2(src, dst)
                # Defense in depth: cmd.exe's line-continuation (`^`) only
                # works with CRLF endings. The previous installer hung at
                # ~100% progress because setup_autostart.bat was saved with
                # LF-only line endings, which broke the multi-line
                # PowerShell command and silently triggered a `pause` prompt.
                _ensure_crlf(dst)

    stage_python_runtime()


def _ensure_crlf(path: Path) -> None:
    """Rewrite a text file in place so every newline is CRLF."""
    data = path.read_bytes()
    text = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").decode("utf-8")
    new = text.replace("\n", "\r\n").encode("utf-8")
    if new != data:
        # `.bat` 刚 copytree 出来就会被 Defender 抓去扫描，扫的瞬间独占句柄，
        # 写入抛 PermissionError: [Errno 13]，2026-09-30 实测卡在
        # reset_admin_password.bat，重跑一次又自己好了（典型的瞬时锁）。
        # 这里退避重试几次；真锁死（只读属性等）才把异常抛出去。
        for attempt in range(5):
            try:
                path.write_bytes(new)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.4 * (attempt + 1))
        step(f"  normalized CRLF endings -> {path.name}")


def _dir_size_mb(p: Path) -> float:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(p):
        for f in filenames:
            try:
                total += (Path(dirpath) / f).stat().st_size
            except OSError:
                pass
    return round(total / (1024 * 1024), 2)


def _verify_runtime_requirements(py: Path) -> None:
    """Gate the staged runtime against the CURRENT backend/requirements.txt.

 为什么必须有这道闸门（2026-09-30 现场故障）：
    `portable_runtime/` 是 `build_python_runtime.py` **手工跑一次**产出的，
    之后 `stage_python_runtime()` 只是把它原样复制进安装包 —— 谁也不检查它
    是否还满足当前的 `backend/requirements.txt`。
    于是当 requirements 事后加了新依赖（`pysnmp` / `pyasn1`，SNMPv3 采集网络设备），
    运行时没有被重跑，安装包就**静默**带着一个缺包的运行时出去了：
    网络设备"测试连接"报 `ModuleNotFoundError: No module named 'pysnmp'`，
    而版本号、接口、界面全部正常，从任何一处都看不出是打包问题。

    这里直接复用 `build_python_runtime.py` 自己的三道检查
    （版本钉住 / 依赖闭包 / 导入冒烟），它们才是"运行时是否可用"的唯一判据。
    """
    sys.path.insert(0, str(INSTALLER_DIR))
    try:
        import build_python_runtime as bpr
    finally:
        sys.path.pop(0)

    reqs = bpr.parse_requirements(bpr.REQUIREMENTS)
    # `probe_requirements()` 返回的是**全部条目**（每项带一个 `ok` 布尔），
    # 不是"未满足的那些"。不过滤就会把 18 项全列成"不合格"，哪怕版本完全
    # 对得上，闸门也会把打包拦下来（2026-09-30 实测踩到）。
    unmet = [m for m in bpr.probe_requirements(py, reqs) if not m.get("ok")]
    if unmet:
        lines = "\n".join(
            f"  - {m.get('name')}: 已装 {m.get('got') or '（未安装）'}，要求 {m.get('want') or '任意'}"
            for m in unmet
        )
        if ALLOW_STALE:
            step(f"  WARN: portable_runtime 缺 {len(unmet)} 个依赖，--allow-stale 已指定，继续打包")
            for line in lines.splitlines():
                step(f"  {line.strip()}")
            return
        raise SystemExit(
            "portable_runtime 不满足 backend/requirements.txt，已中止打包：\n"
            + lines
            + "\n\n  requirements 里加过新依赖之后，**必须重跑一次运行时构建**：\n"
              "      python installer\\build_python_runtime.py\n"
              "  （该脚本是幂等的：会复用现有运行时并只补齐缺失的包）\n"
              "  修好后重跑本脚本。要强行跳过用 --allow-stale。"
        )
    bpr.verify_runtime(py)


def stage_python_runtime() -> None:
    """Copy the portable Python runtime into the installer source tree.

    The runtime is built once by `installer/build_python_runtime.py` and then
    shipped verbatim, so the installer lands it at `{app}\\python_runtime\\`
    and the tray can start the backend without any host-installed Python.

    This is skipped with a warning rather than failing the build: an installer
    without the runtime still works on hosts that happen to have Python.
    """
    dst = SOURCE_DIR / "python_runtime"
    safe_rmtree(dst)
    if not (PORTABLE_RUNTIME_DIR / "python.exe").is_file():
        step("  WARN: installer/portable_runtime/python.exe missing")
        step("        the installer will then REQUIRE a host-installed Python")
        step("        build the runtime with: python installer\\build_python_runtime.py")
        return
    # 先验后拷：验的是**将要装进去的那份**，避免"拷完才发现缺包"。
    _verify_runtime_requirements(PORTABLE_RUNTIME_DIR / "python.exe")
    shutil.copytree(PORTABLE_RUNTIME_DIR, dst,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    step(f"  staged python_runtime ({_dir_size_mb(dst)} MB)")


def check_required_artifacts(allow_stale: bool) -> None:
    """构建前置产物必须齐备，否则打出来的包是"半新半旧"的混合体。

    这些产物此前只打 WARN 就继续，结果 installer/source/ 会静默沿用上一次
    构建留下的旧副本（曾出现服务端 1.1.43、Agent 仍是 1.1.49 的安装包）。
    现在默认缺一个就退出；确实要打旧包时显式加 --allow-stale。
    """
    missing = []
    for path, kind, howto in REQUIRED_ARTIFACTS:
        ok = path.is_dir() if kind == "dir" else path.is_file()
        if not ok:
            missing.append((path, howto))
    if not missing:
        step("  required artifacts: all present")
        return

    for path, howto in missing:
        step(f"  MISSING: {path}")
        step(f"           rebuild with: {howto}")
    if allow_stale:
        step("  --allow-stale 已指定：继续构建，产物可能包含旧版本组件")
        return
    print("ERROR: 构建前置产物缺失，拒绝出包（加 --allow-stale 可强制继续）", file=sys.stderr)
    sys.exit(1)


def check_tray_exe_fresh(allow_stale: bool) -> None:
    """托盘 exe 内嵌的版本必须与 tray_app.py 的 TRAY_VERSION 一致。

 2026-09-30 现场：1.1.63 / 1.1.64 只改了 `tray_app.py` 里的版本常量，
    **没有重新打包托盘** —— 托盘 exe 在 `REQUIRED_ARTIFACTS` 里只校验"在不在"，
    构建脚本并不重建它（它得单独跑 PyInstaller）。结果是：安装包是新的、
    后端代码是新的，**托盘界面上却还写着 1.1.62**，而这条链路上没有任何告警。

    托盘 exe 的版本资源由 `tray/version_info.txt` 经 PyInstaller 写进去，
    所以比对它的 FileVersion 就能抓出"exe 没跟着代码走"。
    """
    m = re.search(r'TRAY_VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
                  _read_text(ROOT / "tray" / "tray_app.py"))
    exe = ROOT / "tray" / "dist" / "VigilServeTray.exe"
    if not m or not exe.is_file():
        return
    want = m.group(1) + ".0"
    raw = exe.read_bytes()
    found: set[str] = set()
    for chunk in re.finditer(rb"(?:[0-9]\x00|\.\x00){4,}", raw):
        try:
            s = chunk.group().decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        found.update(x.group() for x in re.finditer(r"\d+\.\d+\.\d+\.\d+", s))
    if want in found:
        step(f"  tray exe version: {want}（与 tray_app.py 一致）")
        return
    step(f"  STALE TRAY: tray_app.py 要 {want}，dist 里的 exe 是 {sorted(found) or '未知'}")
    if allow_stale:
        step("  --allow-stale 已指定：继续构建，托盘界面会显示旧版本号")
        return
    print("ERROR: 托盘 exe 还是旧版本。先重建再打包：\n"
          "       cd tray && <tray-build venv> -m PyInstaller VigilServeTray.spec --noconfirm",
          file=sys.stderr)
    sys.exit(1)


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def _extract_backend_version(py_path: Path) -> str:
    """从 backend/main.py 的 FastAPI(version="x.y.z") 取服务端版本号。"""
    m = re.search(r'^\s*version\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
                  _read_text(py_path), re.M)
    return m.group(1) if m else ""


def _extract_agent_version(py_path: Path) -> str:
    """从 agent api_server.py 的 AGENT_VERSION 常量取 Agent 版本号。"""
    m = re.search(r'^AGENT_VERSION\s*=\s*["\']([^"\']+)["\']',
                  _read_text(py_path), re.M)
    return m.group(1) if m else ""


def _extract_iss_version(iss_path: Path) -> str:
    """从 setup.iss 的 `#define MyAppVersion "x.y.z"` 取安装包版本号。"""
    m = re.search(r'#define\s+MyAppVersion\s+"([^"]+)"', _read_text(iss_path))
    return m.group(1) if m else ""


def verify_versions() -> dict:
    """校验 staged 树、setup.iss、源码树三处版本号一致。

    setup.iss 的 MyAppVersion 必须等于源码 backend 版本（它是安装包的
    对外版本号、也写进注册表）；staged 的 backend / agent 必须等于源码树，
    用来兜住"copytree 拿错目录 / 前置产物没重新构建"这类静默错误。
    """
    v = {
        "backend_src": _extract_backend_version(BACKEND_MAIN_SRC),
        "backend_staged": _extract_backend_version(SOURCE_DIR / "backend" / "main.py"),
        "agent_src": _extract_agent_version(AGENT_MAIN_SRC),
        "agent_staged": _extract_agent_version(AGENT_MAIN_STAGED),
        "iss": _extract_iss_version(SETUP_ISS),
        "tray_iss": "",
    }
    problems = []

    if not v["backend_src"]:
        problems.append(f"无法从 {BACKEND_MAIN_SRC} 解析服务端版本号")
    if not v["agent_src"]:
        problems.append(f"无法从 {AGENT_MAIN_SRC} 解析 AGENT_VERSION")
    if not v["iss"]:
        problems.append(f"无法从 {SETUP_ISS} 解析 #define MyAppVersion")

    if v["backend_src"] and v["iss"] and v["backend_src"] != v["iss"]:
        problems.append(
            f"setup.iss MyAppVersion={v['iss']} 与 backend/main.py version="
            f"{v['backend_src']} 不一致 —— 改了服务端版本号要同步 setup.iss"
        )
    if v["backend_src"] and v["backend_staged"] and v["backend_src"] != v["backend_staged"]:
        problems.append(
            f"staged backend 版本 {v['backend_staged']} != 源码 {v['backend_src']}"
            " —— installer/source 未从最新源码重建"
        )
    if v["agent_src"] and v["agent_staged"] and v["agent_src"] != v["agent_staged"]:
        problems.append(
            f"staged agent 版本 {v['agent_staged']} != 源码 {v['agent_src']}"
            " —— agent/dist 是旧的，请先重新打包 Agent"
        )

    step(f"  versions: backend={v['backend_src']} (staged {v['backend_staged']}) | "
         f"agent={v['agent_src']} (staged {v['agent_staged']}) | iss={v['iss']}")
    if problems:
        for p in problems:
            print(f"ERROR: {p}", file=sys.stderr)
        sys.exit(1)
    return v


def compile_inno_setup() -> Path:
    if not ISCC.exists():
        print(f"ERROR: Inno Setup compiler not found at {ISCC}", file=sys.stderr)
        sys.exit(1)
    iss = INSTALLER_DIR / "setup.iss"
    cmd = [str(ISCC), str(iss)]
    step(f"  {' '.join(cmd)}")
    subprocess.run(cmd, check=True, cwd=str(INSTALLER_DIR))
    exe = _pick_latest_installer(list(OUTPUT_DIR.glob("VigilServe-Setup-*.exe")))
    if exe is None:
        print(f"ERROR: no installer produced in {OUTPUT_DIR}", file=sys.stderr)
        sys.exit(1)
    return exe


def _pick_latest_installer(paths: list):
    """从一批安装包里挑**版本号最大**的那个，而不是 mtime 最新的那个。

    output/ 里往往同时躺着好几个版本。按 mtime 取"最新"有个很阴的失效方式：旧包
    只要被复制、备份还原、杀毒软件扫过，mtime 就变成现在，于是它会盖过真正的最新
    版被发布出去 —— 版本号和里面的代码对不上，装完还看不出来。

 与 agent/build_installer.py 里的同名函数保持一致：两边是同一套规则。
    """
    def _ver(p):
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", p.name)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    if not paths:
        return None
    return sorted(paths, key=lambda p: (_ver(p), p.stat().st_mtime))[-1]


def stage_outputs(exe: Path) -> None:
    """Copy the freshly-built installer + companion artifacts into F:\\VigilServe."""
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    dst = TARGET_DIR / exe.name
    shutil.copy2(exe, dst)
    step(f"  copied server installer -> {dst}")

    dst_tray = TARGET_DIR / "VigilServeTray.exe"
    if dst_tray.exists():
        dst_tray.unlink()
        step(f"  removed standalone tray exe -> {dst_tray}")

    agent_inst = _pick_latest_installer(
        list((ROOT / "agent" / "installer" / "output").glob("VigilServeAgent-Setup-*.exe")))
    if agent_inst:
        dst_agent = TARGET_DIR / agent_inst.name
        if not dst_agent.exists():
            shutil.copy2(agent_inst, dst_agent)
            step(f"  copied agent installer -> {dst_agent}")
        else:
            step(f"  agent installer already staged -> {dst_agent.name}")


def main(argv: list[str] | None = None) -> int:
    global ALLOW_STALE
    argv = list(sys.argv[1:] if argv is None else argv)
    allow_stale = "--allow-stale" in argv
    ALLOW_STALE = allow_stale
    unknown = [a for a in argv if a not in ("--allow-stale",)]
    if unknown:
        print(f"ERROR: 未识别的参数 {unknown}", file=sys.stderr)
        print("usage: python build_installer.py [--allow-stale]", file=sys.stderr)
        return 1

    # NOTE: 绝不能对 ROOT(源码树) 执行 clean_tree()，源码树里的 backend/monitor.db
    # 是正在运行的生产库，删掉会导致数据丢失且 secret.key 丢失后库内密文永久无法解密。
    # 敏感文件的排除已由 stage_source_tree() 全覆盖：staging 目录整体 safe_rmtree 重建，
    # copytree 的 ignore=IGNORE 已排除 *.db / *.log / data/ / certs/ 等敏感内容。
    step("phase 1: (removed) source tree is staged via copytree ignore, no direct cleaning")

    step("phase 2: regenerate branding assets")
    rebuild_logo_brand()

    step("phase 3: regenerate license.txt from docx")
    rebuild_license_text()

    step("phase 3.5: verify build prerequisites")
    check_required_artifacts(allow_stale)
    check_tray_exe_fresh(allow_stale)

    step("phase 4: stage installer/source/ from latest builds")
    stage_source_tree()

    step("phase 4.5: verify staged versions match the source tree")
    verify_versions()

    step("phase 5: compile Inno Setup installer")
    exe = compile_inno_setup()

    step("phase 6: stage outputs into F:\\VigilServe")
    stage_outputs(exe)

    step("ALL DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())