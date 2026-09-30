@echo off
REM ============================================================
REM  VigilServe - Stop all running services of THIS installation
REM  - Called by the uninstaller (and safe to double-click by hand)
REM  - Stops: tray program, backend API (8001), device WEB proxy (8009)
REM  - Never kills Python processes that do not belong to this install
REM
REM  Why this script exists:
REM    backend\main.py (8001) 与 backend\web_proxy_server.py (8009) 都是
REM    **无窗口**的 python 进程。Inno Setup 自带的 CloseApplications 只会给
REM    「有窗口」的程序发 WM_CLOSE，对它们完全无效；卸载脚本里原来的
REM      taskkill /F /IM python.exe /FI "WINDOWTITLE eq VigilServe*"
REM    同样无效——没有窗口就没有窗口标题，过滤器永远匹配不上。结果就是
REM    python_runtime\python.exe 一直占着文件，卸载卡在「无法删除文件」。
REM
REM  How it stays safe:
REM    三道筛子，全部只认「属于本安装目录」的进程。绝不使用
REM    `taskkill /F /IM python.exe` —— 那会杀掉机器上所有 Python。
REM      1) 按进程名 + 进程树：VigilServeTray.exe /T（托盘拉起的 python
REM         都是它的子进程，/T 会一并结束）
REM      2) 按映像路径：python 的 Path 落在 <安装目录> 下（便携运行时）
REM      3) 按监听端口兜底：8001 / 8009，且先确认占用者是 python 才动手
REM         （托盘没在跑、或 python 来自系统 PATH 时靠这一条）
REM
REM  IMPORTANT: 不要在本脚本里 pause —— 它由卸载程序隐藏调用，
REM             pause 会把卸载挂死。
REM ============================================================

setlocal
REM APP_DIR 默认取脚本自身所在目录。安装程序**也会**把安装目录作为 %1 传进来：
REM 覆盖安装（升级）时新文件还没落地、而旧版本里可能根本没有这份脚本，
REM 只能先从 {tmp} 里跑，此时 %~dp0 是临时目录，必须靠 %1 才知道该清理谁。
set "APP_DIR=%~dp0"
if not "%~1"=="" set "APP_DIR=%~1"
REM 统一补上结尾反斜杠：StartsWith 比对没有它的话，
REM "...\VigilServe" 会把 "...\VigilServe2\" 下的进程也算进来。
if not "%APP_DIR:~-1%"=="\" set "APP_DIR=%APP_DIR%\"
set "VS_APP_DIR=%APP_DIR%"

REM 提示语一律用 ASCII：.bat 是 UTF-8，而中文 Windows 的控制台默认 GBK(936)，
REM echo 中文会变乱码（REM 注释不显示，所以注释里可以放心写中文）。
echo [VigilServe] Stopping services...

REM ---- 1. 托盘程序及其子进程树 ----
REM /T 很关键：后端与 WEB 代理都是托盘 Popen 拉起的子进程，
REM 只杀托盘会留下两个孤儿 python 继续占着文件。
taskkill /F /T /IM VigilServeTray.exe >nul 2>&1

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell"
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "Get-Process python,pythonw -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($env:VS_APP_DIR,'OrdinalIgnoreCase') } | Stop-Process -Force -ErrorAction SilentlyContinue"

call :kill_by_port 8001
call :kill_by_port 8009

ping -n 3 127.0.0.1 >nul 2>&1

echo [VigilServe] Services stopped.
endlocal & exit /b 0

:kill_by_port
setlocal
set "PORT=%~1"
if "%PORT%"=="" endlocal & exit /b 0
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%PORT% " ^| findstr /I "LISTENING"') do (
    call :kill_pid_if_python %%p
)
endlocal & exit /b 0

:kill_pid_if_python
setlocal
set "PID=%~1"
if "%PID%"=="" endlocal & exit /b 0
tasklist /FI "PID eq %PID%" /FI "IMAGENAME eq python.exe" /NH | findstr /I "python.exe" >nul
if not errorlevel 1 taskkill /F /PID %PID% >nul 2>&1
tasklist /FI "PID eq %PID%" /FI "IMAGENAME eq pythonw.exe" /NH | findstr /I "pythonw.exe" >nul
if not errorlevel 1 taskkill /F /PID %PID% >nul 2>&1
endlocal & exit /b 0
