"""One-step build script for the VigilServe Agent installer.

Usage:
    python build_installer.py

This script:
  1. Builds the VigilServeAgent executable with PyInstaller.
  2. Compiles the Inno Setup installer.
  3. Removes the standalone executable so only the installer package remains.

Only the generated installer (agent/installer/output/VigilServeAgent-Setup-X.X.X.exe)
should be distributed.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "dist"
BUILD_DIR = ROOT / "build" / "VigilServeAgent"
SPEC = ROOT / "VigilServeAgent.spec"
ISS = ROOT / "installer" / "VigilServeAgent.iss"

def resolve_pyinstaller() -> str | None:
    """定位 PyInstaller：环境变量 -> PATH -> None(退化成 `python -m PyInstaller`)。

    IMPORTANT: 这个解释器**必须自带 tkinter**。曾经用过一个没有 tkinter 的
    Python 构建，PyInstaller 照样出包，但打出来的 Agent `import tkinter` 恒失败，
    于是配置窗口退化成网页版 —— 打包成功、运行才发现，非常隐蔽。
    """
    env = os.environ.get("VIGILSERVE_PYINSTALLER")
    if env and Path(env).exists():
        return env
    found = shutil.which("pyinstaller")
    if found:
        return found
    return None


PYINSTALLER = resolve_pyinstaller()
ISCC = Path(r"C:\Program Files\Inno Setup 7\ISCC.exe")


def run(cmd, **kw):
    print(f"[build] {' '.join(str(c) for c in cmd)}")
    subprocess.run(cmd, check=True, **kw)


def verify_tkinter_bundled() -> None:
    """Fail the build when tkinter was not collected into the bundle.

    A missing tkinter does not break the build, but it makes the shipped Agent
    fall back to the browser-based config panel — a regression that is very
    easy to miss because everything still "works". Assert it here so such a
    package can never be produced unnoticed.

    PyInstaller's tkinter packaging varies across versions and Python builds.
    On Python 3.14 with PyInstaller 6.x, the tkinter source files are split
    into a ``_tk_data`` / ``_tcl_data`` namespace package instead of the older
    ``tkinter/`` directory. We therefore check the canonical runtime pieces
    (``_tkinter.pyd``, ``tcl*.dll``, ``tk*.dll``, ``tcl8/``) which are always
    required for the native config dialog to launch.
    """
    internal = DIST_DIR / "VigilServeAgent" / "_internal"
    if not internal.is_dir():
        print(f"ERROR: bundle directory not found: {internal}", file=sys.stderr)
        sys.exit(1)

    names = {p.name for p in internal.iterdir()}
    problems: list[str] = []
    if not any(n.startswith("_tkinter") and n.endswith(".pyd") for n in names):
        problems.append("_tkinter.pyd (C extension) is missing")
    if not any(n.startswith("tcl") and n.endswith(".dll") for n in names):
        problems.append("tcl*.dll (Tcl runtime) is missing")
    if not any(n.startswith("tk") and n.endswith(".dll") for n in names):
        problems.append("tk*.dll (Tk runtime) is missing")
    if "tcl8" not in names and "_tcl_data" not in names:
        problems.append("tcl8/ runtime directory is missing")
    if "_tk_data" not in names and "_tcl_data" not in names:
        problems.append("_tk_data/_tcl_data (Tk/Tcl library data) is missing")

    if problems:
        print("ERROR: bundled Agent is missing tkinter components:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            "  The Agent would silently fall back to the web config panel.\n"
            "  确认用于打包的 Python 自带 tkinter（可用 VIGILSERVE_PYINSTALLER 指定）。",
            file=sys.stderr,
        )
        sys.exit(1)

    print("[build] tkinter bundle verified OK (native config dialog available)")


def verify_crypto_bundled() -> None:
    """Fail the build when ``cryptography`` was not collected into the bundle.

    ``connector.py`` performs ``from cryptography.hazmat.primitives.ciphers.aead
    import AESGCM`` at module level, so a bundle without the package makes the
    shipped Agent die immediately at startup with::

        ModuleNotFoundError: No module named 'cryptography'

    PyInstaller does *not* fail in that case — it only appends a line to
    ``build/<name>/warn-<name>.txt`` and keeps going. This happened in the
    1.1.24 build (the ``agent-build-314`` venv lacked the package) and shipped
    a broken Agent. Assert it here so it can never happen unnoticed again.
    """
    internal = DIST_DIR / "VigilServeAgent" / "_internal"
    if not internal.is_dir():
        print(f"ERROR: bundle directory not found: {internal}", file=sys.stderr)
        sys.exit(1)

    names = {p.name for p in internal.iterdir()}
    problems: list[str] = []
    if "cryptography" not in names:
        problems.append("cryptography/ package directory is missing")

    rust_ext = internal / "cryptography" / "hazmat" / "bindings" / "_rust.pyd"
    if "cryptography" in names and not rust_ext.is_file():
        problems.append("cryptography/hazmat/bindings/_rust.pyd (native AES) is missing")

    if problems:
        print("ERROR: bundled Agent is missing cryptography components:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            "  The Agent would crash at startup with\n"
            "    ModuleNotFoundError: No module named 'cryptography'\n"
            "  Install it into the build venv and rebuild:\n"
            "    <venv>\\Scripts\\python.exe -m pip install cryptography",
            file=sys.stderr,
        )
        sys.exit(1)

    print("[build] cryptography bundle verified OK (payload encryption available)")


def stage_ca_cert() -> None:
    """把服务端本地 CA 复制进 `agent/ca/`，让安装包内置它。

    安全加固阶段 2 之后服务端只讲 HTTPS，Agent 必须用这份 CA 校验证书。
    CA 是公开信息（只用于验签，不含私钥），可以随包分发。
    """
    src = ROOT.parent / "backend" / "certs" / "ca.crt"
    dst_dir = ROOT / "ca"
    dst = dst_dir / "vigilserve-ca.crt"
    if not src.is_file():
        # 服务端还没跑过 现场生成一次（这样第一个安装包也能带上 CA）
        print(f"[build] CA not found at {src}; generating one via backend/services/tls.py")
        subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, r'%s'); "
             "from services import tls; print(tls.ensure_server_cert()['ca_cert'])"
             % str(ROOT.parent / "backend")],
            check=True, cwd=str(ROOT.parent / "backend"),
        )
    if not src.is_file():
        print("ERROR: 仍无法得到本地 CA，中止打包（否则 Agent 无法校验 HTTPS 服务端）",
              file=sys.stderr)
        sys.exit(1)
    dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    print(f"[build] 内置 CA: {dst}")


def verify_ca_bundled() -> None:
    internal = DIST_DIR / "VigilServeAgent" / "_internal" / "ca"
    ca = internal / "vigilserve-ca.crt"
    if not ca.is_file():
        print("ERROR: 打包结果缺少 ca/vigilserve-ca.crt —— Agent 将无法校验服务端 HTTPS 证书",
              file=sys.stderr)
        sys.exit(1)
    print("[build] CA bundle verified OK (HTTPS 证书校验可用)")


# 打包态下完整性自检至少要覆盖这么多个文件。
# 现在的实测值是 14（`_internal` 顶层全部 .py）。注意 `sys.executable` **不算在内**
SELF_CHECK_MIN_FILES = 10


def verify_self_check_coverage() -> None:
    """Fail the build when the packaged integrity self-check covers too few files.

    `agent/self_check.py` 让 Agent 自己算一遍代码的哈希报给服务端，服务端跟基线比，
    对不上就记「疑似被改造」。**这个机制可以静默失效**：文件收录规则一旦退化到只
    算 1 个文件（启动器），有人改几行 `api_server.py` 再重新打包，指纹纹丝不动，
    而界面上依然显示"自检正常"——比不做还糟，因为它给了假的安全感。

    这事真的发生过：第一版只哈希 `sys.executable` + `_MEIPASS/*.pyz`，但本项目的
    spec 把 Python 代码通过 `datas` 以**明文 .py 投放在 `_internal/` 顶层**，
    `_internal` 下 `.pyz` 实测 **0 个** → 最终只收集到 1 个文件。

    这里把打包结果摆在 `self_check` 面前，冒充冻结运行时（`sys.frozen` /
    `sys._MEIPASS` / `sys.executable`）跑一次 `_collect_files()`，断言覆盖足够。

 注意收录范围是有意为之：只看 `_MEIPASS` **顶层**，不递归进 numpy / PIL /
    cryptography 等第三方包目录，也不算 `.pyd` / `.dll` / `base_library.zip`
    （后者随 **PyInstaller 版本**变化而 Agent 版本号不变，算进去每次升级构建工具
    都会误报篡改）。所以这里的阈值也不能按"文件越多越好"来定。
    """
    internal = DIST_DIR / "VigilServeAgent" / "_internal"
    if not internal.is_dir():
        print(f"ERROR: bundle directory not found: {internal}", file=sys.stderr)
        sys.exit(1)
    exe = DIST_DIR / "VigilServeAgent" / "VigilServeAgent.exe"

    # 不存在（本脚本以普通 .py 运行），所以要在 finally 里按"原来有没有"分别还原。
    import importlib
    had_frozen = hasattr(sys, "frozen")
    had_meipass = hasattr(sys, "_MEIPASS")
    saved_frozen = getattr(sys, "frozen", None)
    saved_meipass = getattr(sys, "_MEIPASS", None)
    saved_exe = sys.executable
    try:
        sys.frozen = True
        sys._MEIPASS = str(internal)
        sys.executable = str(exe)
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        sc = importlib.import_module("self_check")
        importlib.reload(sc)  # 拿到的必须是磁盘上的最新版，不是别的测试留下的缓存
        files, mode = sc._collect_files()
        digest = sc.self_digest(force=True)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: 无法在打包态下计算完整性自检指纹: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        sys.executable = saved_exe
        if had_meipass:
            sys._MEIPASS = saved_meipass
        elif hasattr(sys, "_MEIPASS"):
            del sys._MEIPASS
        if had_frozen:
            sys.frozen = saved_frozen
        elif hasattr(sys, "frozen"):
            del sys.frozen

    problems: list[str] = []
    if mode != "frozen":
        problems.append(f"运行模式识别为 {mode!r}（应为 frozen）—— _MEIPASS 没生效")
    if len(files) < SELF_CHECK_MIN_FILES:
        problems.append(
            f"只收集到 {len(files)} 个文件（要求 ≥ {SELF_CHECK_MIN_FILES}）"
        )
    missing = [f for f in files if not os.path.isfile(f)]
    if missing:
        problems.append(f"收集到了不存在的文件: {missing[:3]}")
    if not digest.get("digest"):
        problems.append("算出来的指纹为空（文件一个都没读到）")

    if problems:
        print("ERROR: 打包结果的完整性自检覆盖不足:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            "  这样的包发出去，`self_check` 形同虚设：改几行源码重新打包也测不出来，\n"
            "  而页面照样显示「自检正常」。\n"
            "  最常见的原因是 `_collect_files()` 的收录规则没覆盖到本项目的投放方式\n"
            "  —— Python 代码是**明文 .py 放在 `_internal/` 顶层**，不是 .pyz。",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[build] self_check coverage verified OK "
          f"（{len(files)} 个文件，digest={digest['digest'][:12]}…）")


def _pick_latest_installer(paths: list):
    """从一批安装包里挑**版本号最大**的那个，而不是 mtime 最新的那个。

    output/ 里往往同时躺着好几个版本（1.1.53、1.1.54 …）。按 mtime 取"最新"有个
    很阴的失效方式：旧包只要被复制、备份还原、杀毒软件扫过，mtime 就变成现在，
    于是它会盖过真正的最新版被发布出去 —— 版本号和里面的代码对不上，装完还看
    不出来，只有出问题查版本时才对不上账。

    文件名里本来就带版本号（`VigilServeAgent-Setup-1.1.54.exe`），直接按它排；
    版本号相同时才用 mtime 兜底。

 与 installer/build_installer.py 里的同名函数保持一致：两边是同一套规则。
    """
    def _ver(p):
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", p.name)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    if not paths:
        return None
    return sorted(paths, key=lambda p: (_ver(p), p.stat().st_mtime))[-1]


def main():
    if PYINSTALLER is None:
        print("[build] 未找到 pyinstaller 可执行文件，改用 `python -m PyInstaller`", flush=True)
    elif not Path(PYINSTALLER).exists():
        print(f"ERROR: PyInstaller not found at {PYINSTALLER}", file=sys.stderr)
        sys.exit(1)
    if not ISCC.exists():
        print(f"ERROR: Inno Setup compiler not found at {ISCC}", file=sys.stderr)
        sys.exit(1)

    for pycache in ROOT.rglob("__pycache__"):
        shutil.rmtree(pycache, ignore_errors=True)
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR, ignore_errors=True)

    # 1a. 内置服务端本地 CA（Agent 校验证书用）
    stage_ca_cert()

    env = os.environ.copy()
    env["PYTHONPATH"] = ""
    pyi_cmd = [str(PYINSTALLER)] if PYINSTALLER else [sys.executable, "-m", "PyInstaller"]
    run(pyi_cmd + ["--clean", "-y", str(SPEC)], cwd=str(ROOT), env=env)

    exe = DIST_DIR / "VigilServeAgent" / "VigilServeAgent.exe"
    if not exe.exists():
        print(f"ERROR: Expected executable not found: {exe}", file=sys.stderr)
        sys.exit(1)

    verify_tkinter_bundled()

    verify_crypto_bundled()

    verify_ca_bundled()

    verify_self_check_coverage()

    run([str(ISCC), str(ISS)])

    # 3. Remove only the PyInstaller build cache; leave dist/ in place.
    # Deleting the full dist tree triggers bulk-delete guards and is not
    # necessary because the installer already consumed the files it needs.
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR, ignore_errors=True)
        print(f"[build] Removed PyInstaller build cache: {BUILD_DIR}")

    output_dir = ROOT / "installer" / "output"
    picked = _pick_latest_installer(list(output_dir.glob("VigilServeAgent-Setup-*.exe")))
    if picked:
        print(f"[build] Installer ready: {picked}")
    else:
        print("[build] Installer output not found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
