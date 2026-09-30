"""Build the self-contained portable Python runtime that ships inside the
VigilServe server installer.

Why this exists
---------------
The tray program needs a Python interpreter to launch the backend
(`python main.py`). Relying on whatever Python happens to be installed on the
target machine is fragile:

  * plenty of Windows hosts have no Python at all;
  * the Microsoft Store ships a 0-byte `python.exe` *app-execution alias* under
    %LOCALAPPDATA%\\Microsoft\\WindowsApps, which `shutil.which()` finds happily
    but which exits with code 9009 and no output when spawned; and
  * a machine-wide Python may be a different minor version with a different ABI
    than the wheels we ship.

So we ship our own: a copy of a clean CPython installation with the backend
requirements pre-installed into its own `Lib\\site-packages`. It is staged to
`installer\\portable_runtime\\`, then `build_installer.py` copies it into the
installer source tree as `python_runtime\\`. After installation the tray finds
it at `{app}\\python_runtime\\python.exe` -- the entry
`tray/config.py::_resolve_python()` already looks for -- with no pre-requisite
on the host.

Usage
-----
    python build_python_runtime.py              # reuse if already built
    python build_python_runtime.py --force      # full rebuild from scratch
    python build_python_runtime.py --base D:\\Python313

The script is idempotent: re-running it reuses an existing runtime and only
verifies it (plus tops up anything missing from requirements.txt).

Two rules learned the hard way -- please keep them
--------------------------------------------------
1. **Every child interpreter runs with the user site disabled**
   (`PYTHONNOUSERSITE=1`, see `child_env`). Otherwise `python -m pip install`
   sees packages from the *build machine's* `%APPDATA%\\Python\\PythonXY\\
   site-packages`, decides they are "already satisfied", and never copies them
   into the runtime. The runtime then looks complete to every metadata-based
   check -- `pip check` included, since it resolves against the same polluted
   path -- and only dies on a clean target machine. This is exactly how the
   1.1.21 runtime shipped without `six`.

2. **A release is only valid when the closure check AND the import smoke test
   both pass** (`verify_closure`, `verify_imports`). Version-pinning checks only
   cover the 13 names in requirements.txt; `six` (needed by apscheduler) and
   `tzdata` (needed by tzlocal on Windows) are transitive and invisible to them.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALLER_DIR = ROOT / "installer"
RUNTIME_DIR = INSTALLER_DIR / "portable_runtime"
REQUIREMENTS = ROOT / "backend" / "requirements.txt"
INFO_FILE = RUNTIME_DIR / ".runtime_info.txt"

COPY_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")

STALE_ROOT_FILES = (".extracted",)

PIP_TIMEOUT = 1800

# `sys.path` includes the user site-packages directory whenever the interpreter
NO_USER_SITE_ENV = {"PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"}

SMOKE_MODULES = (
    "sqlite3",
    "ssl",
    "ctypes",
    "zoneinfo",
    "fastapi",
    "uvicorn",
    "sqlalchemy",
    "apscheduler.schedulers.background",
    "websockets",
    "pydantic",
    "multipart",
    "jinja2",
    "winrm",
    "paramiko",
    "winpty",
    "psutil",
    "requests",
    # 光 import "pysnmp" 是空包（顶层不导出任何东西），必须冒烟真正的子模块。
    "pysnmp.hlapi.v3arch.asyncio",
    "pyasn1",
)

# it loads fine without `tzdata` and only explodes when apscheduler asks it for
SMOKE_STATEMENTS = (
    "from apscheduler.schedulers.background import BackgroundScheduler",
    "from tzlocal import get_localzone\nget_localzone()",
)


def step(msg: str) -> None:
    print(f"[runtime] {msg}", flush=True)


def child_env(extra: dict | None = None) -> dict:
    """Environment for every interpreter we spawn: no user site, ever."""
    env = os.environ.copy()
    env.update(NO_USER_SITE_ENV)
    if extra:
        env.update(extra)
    return env



def find_base(explicit: str | None = None) -> Path:
    """Locate a clean CPython installation to copy."""
    if explicit:
        p = Path(explicit)
        if (p / "python.exe").is_file():
            return p
        raise SystemExit(f"--base {explicit} does not contain python.exe")

    env = os.environ.get("VIGILSERVE_RUNTIME_BASE")
    if env:
        p = Path(env)
        if (p / "python.exe").is_file():
            return p
        raise SystemExit(f"VIGILSERVE_RUNTIME_BASE={env} does not contain python.exe")

    versions_dir = Path.home() / ".workbuddy" / "binaries" / "python" / "versions"
    if versions_dir.is_dir():
        cands = [
            c for c in versions_dir.iterdir()
            if (c / "python.exe").is_file() and (c / "Lib" / "site-packages").is_dir()
        ]
        # may be half-removed. They must not win the pick: plain name sorting
        # would choose "3.13.12.old.17552" over "3.13.12" because the longer
        fresh = [c for c in cands if ".old" not in c.name.lower()]
        pool = fresh or cands
        if pool:
            return sorted(pool, key=lambda p: p.name, reverse=True)[0]

    raise SystemExit(
        "No portable Python base found.\n"
        "Pass one explicitly:  python build_python_runtime.py --base C:\\Python313"
    )



def runtime_python() -> Path:
    return RUNTIME_DIR / "python.exe"


def run(py: Path, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(py), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=child_env(),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def dir_size_mb(p: Path) -> float:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(p):
        for f in filenames:
            try:
                total += (Path(dirpath) / f).stat().st_size
            except OSError:
                pass
    return round(total / (1024 * 1024), 2)


def report_stale_trash() -> None:
    """Point out runtimes parked by earlier rebuilds.

    They are never deleted automatically: a runtime is ~2000 files, and in
    environments that guard bulk deletions an `rmtree` can be refused outright
    or block on an interactive confirmation prompt. Since a parked directory
    is inert, the user can delete these whenever convenient.
    """
    stale = sorted(INSTALLER_DIR.glob(f"{RUNTIME_DIR.name}.trash-*"))
    if not stale:
        return
    step(f"  note: {len(stale)} parked runtime(s) still on disk (safe to delete):")
    for p in stale:
        step(f"    {p.name}  ({dir_size_mb(p)} MB)")


def remove_runtime() -> None:
    """Move the staged runtime aside so a rebuild starts from a clean path.

    Renaming is used instead of `rmtree` deliberately. A half-deleted tree is
    the worst possible outcome — you end up with a runtime that has no
    python.exe — and large deletions are exactly what bulk-delete guards
    interfere with. `os.replace` is atomic, immune to content-based guards,
    and cannot hang. The parked directory is never staged into the installer.
    """
    if not RUNTIME_DIR.exists():
        return

    trash = RUNTIME_DIR.with_name(f"{RUNTIME_DIR.name}.trash-{os.getpid()}")
    n = 1
    while trash.exists():
        n += 1
        trash = RUNTIME_DIR.with_name(f"{RUNTIME_DIR.name}.trash-{os.getpid()}-{n}")

    try:
        os.replace(RUNTIME_DIR, trash)
    except OSError as exc:
        raise SystemExit(
            f"Could not move {RUNTIME_DIR} aside:\n  {exc}\n"
            "Close anything using it (a running backend?) and re-run."
        ) from exc

    step(f"  parked previous runtime -> {trash.name} (delete it any time)")


def parse_requirements(path: Path) -> list[tuple[str, str]]:
    """Return [(distribution_name, specifier), ...] from a requirements file.

    Extras are stripped (`uvicorn[standard]` -> `uvicorn`) because
    `importlib.metadata.version()` only knows the distribution name.
    """
    out: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        out.append((m.group(1), m.group(2).strip()))
    return out


# Executed by the *target* runtime. Prints a JSON report so the caller only
_PROBE_SNIPPET = r"""
import json, sys
from importlib.metadata import version, PackageNotFoundError

reqs = json.loads(sys.argv[1])
report = []
for name, spec in reqs:
    try:
        actual = version(name)
    except PackageNotFoundError:
        report.append({"name": name, "want": spec, "got": None, "ok": False})
        continue
    ok = True
    if spec.startswith("=="):
        want = spec[2:].strip()
        # Compare the release segment only; `1.0` vs `1.0.0` should not fail.
        def norm(v):
            return tuple(int(x) for x in v.split("+")[0].split(".") if x.isdigit())
        ok = norm(actual) == norm(want)
    report.append({"name": name, "want": spec, "got": actual, "ok": ok})
print(json.dumps(report))
"""


def probe_requirements(py: Path, reqs: list[tuple[str, str]]) -> list[dict]:
    if not reqs:
        return []
    proc = run(py, ["-c", _PROBE_SNIPPET, json.dumps(reqs)], timeout=180)
    if proc.returncode != 0:
        raise SystemExit(
            "Failed to probe installed packages with the portable runtime:\n"
            f"{proc.stdout}\n{proc.stderr}"
        )
    line = proc.stdout.strip().splitlines()[-1]
    return json.loads(line)


_SMOKE_SNIPPET = r"""
import importlib, json, sys

spec = json.loads(sys.argv[1])
failures = []
for name in spec["modules"]:
    try:
        importlib.import_module(name)
    except BaseException as exc:
        failures.append([name, "%s: %s" % (type(exc).__name__, exc)])
for stmt in spec["statements"]:
    try:
        exec(compile(stmt, "<smoke>", "exec"), {})
    except BaseException as exc:
        failures.append([stmt.replace("\n", "; "), "%s: %s" % (type(exc).__name__, exc)])
print(json.dumps(failures, ensure_ascii=True))
"""


def verify_imports(py: Path) -> list[list[str]]:
    """Import the backend's dependency closure and report what breaks.

    Returns ``[[module_or_statement, reason], ...]``; empty means everything
    loaded. This is the check that catches a missing *transitive* dependency,
    which no amount of version pinning can see.
    """
    payload = json.dumps({
        "modules": list(SMOKE_MODULES),
        "statements": list(SMOKE_STATEMENTS),
    })
    proc = run(py, ["-c", _SMOKE_SNIPPET, payload], timeout=300)
    if proc.returncode != 0:
        raise SystemExit(
            "Import smoke test could not run at all:\n"
            f"{proc.stdout}\n{proc.stderr}"
        )
    line = proc.stdout.strip().splitlines()[-1]
    return json.loads(line)


def verify_closure(py: Path) -> list[str]:
    """Return the unmet requirements of every distribution in the runtime.

    `pip check` is the tool for this, but only when the user site is disabled:
    on the build machine it otherwise resolves against packages living in
    %APPDATA%\\Python and reports a clean bill of health for a runtime that is
    missing them. `child_env()` handles that.
    """
    proc = run(py, ["-m", "pip", "check"], timeout=300)
    if proc.returncode == 0:
        return []
    text = (proc.stdout or "") + (proc.stderr or "")
    return [
        l.strip() for l in text.splitlines()
        if l.strip() and not l.strip().startswith("WARNING")
    ]



def copy_base(base: Path, force: bool) -> None:
    if RUNTIME_DIR.exists() and not (RUNTIME_DIR / "python.exe").is_file():
        step("  existing runtime is incomplete (python.exe missing) - rebuilding")
        force = True

    if RUNTIME_DIR.exists():
        if force:
            step(f"  --force: removing existing {RUNTIME_DIR.relative_to(ROOT)}")
            remove_runtime()
        else:
            step(f"  reusing existing {RUNTIME_DIR.relative_to(ROOT)}")
            return

    step(f"  copying base interpreter from {base}")
    RUNTIME_DIR.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(base, RUNTIME_DIR, ignore=COPY_IGNORE)
    for name in STALE_ROOT_FILES:
        victim = RUNTIME_DIR / name
        if victim.exists():
            victim.unlink()
            step(f"  dropped stale marker: {name}")
    step(f"  base copied ({dir_size_mb(RUNTIME_DIR)} MB)")


def verify_portability() -> str:
    """The copy must resolve `sys.prefix` to its own directory."""
    proc = run(runtime_python(), ["-I", "-c", "import sys; print(sys.prefix); print(sys.version)"])
    if proc.returncode != 0:
        raise SystemExit(f"Portable runtime failed to start:\n{proc.stdout}\n{proc.stderr}")
    lines = [l.strip() for l in proc.stdout.strip().splitlines() if l.strip()]
    prefix, version = lines[0], lines[1]
    if Path(prefix).resolve() != RUNTIME_DIR.resolve():
        raise SystemExit(
            "Portable runtime is NOT relocatable: sys.prefix resolved to\n"
            f"  {prefix}\nbut the runtime lives in\n  {RUNTIME_DIR}\n"
            "Check for a stray pyvenv.cfg / python*._pth in the base install."
        )
    step(f"  portability OK (sys.prefix = {prefix})")
    step(f"  interpreter: {version}")
    return version


def install_requirements(reqs: list[tuple[str, str]]) -> None:
    """Install anything from requirements.txt that is missing or mismatched."""
    py = runtime_python()
    report = probe_requirements(py, reqs)
    missing = [r for r in report if not r["ok"]]
    for r in missing:
        want = r["want"] or "(any)"
        got = r["got"] or "not installed"
        step(f"  needs install: {r['name']} want={want} got={got}")

    # The fast path is only taken when the runtime is genuinely *complete*, not
    # merely when the pinned names resolve. Version checks cannot see transitive
    # gaps, so both gates must agree before pip is skipped -- that is how a
    # runtime missing `six` used to slip through.
    if not missing:
        closure = verify_closure(py)
        smoke = verify_imports(py)
        if not closure and not smoke:
            step("  all requirements satisfied, closure and imports verified - skipping pip")
            return
        for line in closure:
            step(f"  closure problem: {line}")
        for name, why in smoke:
            step(f"  import failed:  {name} -> {why}")
        step("  runtime is not actually usable - re-running pip to repair it")

    if not (py.parent / "Lib" / "site-packages" / "pip").is_dir():
        step("  pip missing in runtime - bootstrapping via ensurepip")
        bp = run(py, ["-m", "ensurepip", "--upgrade"], timeout=600)
        if bp.returncode != 0:
            raise SystemExit(f"ensurepip failed:\n{bp.stdout}\n{bp.stderr}")

    cmd = [
        str(py), "-m", "pip", "install",
        "--disable-pip-version-check",
        "--no-warn-script-location",
        "--no-input",
        "--upgrade",
        "-r", str(REQUIREMENTS),
    ]
    step(f"  {' '.join(cmd)}")
    t0 = time.time()
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=PIP_TIMEOUT,
        env=child_env(),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    elapsed = time.time() - t0
    if proc.returncode != 0:
        tail = "\n".join((proc.stdout or "").splitlines()[-25:])
        raise SystemExit(
            f"pip install failed after {elapsed:.0f}s (rc={proc.returncode}):\n{tail}\n"
            f"stderr:\n{(proc.stderr or '')[-2000:]}"
        )
    step(f"  pip install finished in {elapsed:.0f}s")

    after = probe_requirements(py, reqs)
    bad = [r for r in after if not r["ok"]]
    if bad:
        detail = "\n".join(f"  - {r['name']} want={r['want']} got={r['got']}" for r in bad)
        raise SystemExit(f"{len(bad)} requirement(s) still unsatisfied:\n{detail}")
    step(f"  all {len(reqs)} pinned requirement(s) resolve")


def verify_runtime(py: Path) -> tuple[list[str], list[list[str]]]:
    """Run both gates and fail the build if either is unhappy."""
    closure = verify_closure(py)
    if closure:
        raise SystemExit(
            "The packaged runtime does not satisfy its own dependency closure:\n"
            + "\n".join(f"  {l}" for l in closure)
            + "\n  (did pip skip a package because it was found in the build "
              "machine's user site?)"
        )
    step("  closure OK (every declared dependency is present in the runtime)")

    smoke = verify_imports(py)
    if smoke:
        raise SystemExit(
            "Imports that the backend needs are broken in the runtime:\n"
            + "\n".join(f"  - {name}: {why}" for name, why in smoke)
        )
    step(
        f"  imports OK ({len(SMOKE_MODULES)} modules + "
        f"{len(SMOKE_STATEMENTS)} statements)"
    )
    return closure, smoke


def write_info(base: Path, version: str, reqs: list[tuple[str, str]]) -> None:
    report = probe_requirements(runtime_python(), reqs)
    lines = [
        "VigilServe portable Python runtime",
        "=" * 40,
        f"built_at      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"base          : {base}",
        f"interpreter   : {runtime_python()}",
        f"version       : {version}",
        f"size_mb       : {dir_size_mb(RUNTIME_DIR)}",
        f"requirements  : {REQUIREMENTS.relative_to(ROOT)} ({len(reqs)} entries)",
        f"closure check : OK (pip check, user site disabled)",
        f"import smoke  : OK ({len(SMOKE_MODULES)} modules + "
        f"{len(SMOKE_STATEMENTS)} statements)",
        "",
        "installed distributions:",
    ]
    for r in report:
        mark = "OK " if r["ok"] else "BAD"
        lines.append(f"  [{mark}] {r['name']:<20} {r['got'] or '(missing)':<12} want {r['want'] or '(any)'}")
    lines += [
        "",
        "notes:",
        "  Built with PYTHONNOUSERSITE=1 so packages from the build machine's",
        "  %APPDATA%\\Python user site cannot mask a missing dependency.",
        "  Do not ship a runtime whose closure/import gates did not pass.",
    ]
    INFO_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    step(f"  wrote {INFO_FILE.relative_to(ROOT)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", help="clean CPython install to copy (contains python.exe)")
    ap.add_argument("--force", action="store_true", help="rebuild from scratch")
    args = ap.parse_args()

    if not REQUIREMENTS.is_file():
        raise SystemExit(f"requirements file not found: {REQUIREMENTS}")

    step("phase 1: locate base interpreter")
    base = find_base(args.base)
    step(f"  base = {base}")

    step("phase 2: stage portable runtime")
    report_stale_trash()
    copy_base(base, args.force)

    step("phase 3: verify relocatability")
    version = verify_portability()

    step("phase 4: install backend requirements")
    reqs = parse_requirements(REQUIREMENTS)
    step(f"  parsed {len(reqs)} entries from {REQUIREMENTS.relative_to(ROOT)}")
    install_requirements(reqs)

    step("phase 5: verify dependency closure and imports")
    verify_runtime(runtime_python())

    step("phase 6: write build info")
    write_info(base, version, reqs)

    step(f"DONE - {RUNTIME_DIR.relative_to(ROOT)} ({dir_size_mb(RUNTIME_DIR)} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
