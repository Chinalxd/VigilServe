@echo off
REM ============================================================
REM  VigilServe Agent - Stop running Agent processes of THIS install
REM  - Called by the installer (before files land) and by the uninstaller
REM  - Safe to double-click by hand
REM  - Never kills processes that do not belong to this install directory
REM
REM  Why this script exists:
REM    VigilServeAgent.exe 常驻系统托盘（pystray），主窗口平时是隐藏的。
REM    Inno 自带的 CloseApplications / RestartApplications 只对「有窗口」的
REM    程序发 WM_CLOSE，对只留托盘图标的 Agent 并不可靠 —— 覆盖安装（升级）
REM    时表现为「无法替换文件 / 文件被占用」，卸载时表现为卸不干净。
REM
REM  How it stays safe:
REM    两道筛子，且只在需要时动手：
REM      1) 按进程名 + 进程树：VigilServeAgent.exe /T（连子进程一起结束）
REM      2) 按映像路径兜底：进程 Path 落在本安装目录下
REM    Agent 装在 %LocalAppData%（每用户一份），且安装器不提权
REM    （PrivilegesRequired=lowest），本来也杀不到别的用户的进程。
REM
REM  🚨 2026-09-28：结束之后必须**再数一遍**进程，数为 0 才算成功，返回值：
REM      0 = 已全部结束；1 = 还有残留进程（调用方据此提示用户手动退出）
REM    为什么：taskkill 撞上权限问题（Agent 以管理员身份启动过）时只会把错误
REM    吞掉，/F 也救不了；旧脚本不管有没有杀掉都 `exit /b 0`，于是安装/卸载
REM    程序以为成功了，文件却被占用 —— 表现为卸载后残留 exe/dll，
REM    或弹「部分文件无法删除」。
REM
REM  IMPORTANT: 不要在本脚本里 pause —— 它由安装/卸载程序隐藏调用，
REM             pause 会把安装挂死。
REM ============================================================

setlocal
REM APP_DIR 默认取脚本自身所在目录；安装程序从 {tmp} 调用时会把安装目录作为
REM %1 传进来（升级时 {app} 里还没有这份脚本，只能先落到 {tmp} 再跑）。
set "APP_DIR=%~dp0"
if not "%~1"=="" set "APP_DIR=%~1"
REM 统一补上结尾反斜杠，避免 "...\Agent" 把 "...\Agent2\" 下的进程也算进来。
if not "%APP_DIR:~-1%"=="\" set "APP_DIR=%APP_DIR%\"
set "VS_APP_DIR=%APP_DIR%"

echo [VigilServe Agent] Stopping agent processes...

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell"
set /a VS_TRY=0

:vs_kill
set /a VS_TRY+=1

taskkill /F /T /IM VigilServeAgent.exe >nul 2>&1

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "Get-Process VigilServeAgent -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($env:VS_APP_DIR,'OrdinalIgnoreCase') } | Stop-Process -Force -ErrorAction SilentlyContinue"

ping -n 2 127.0.0.1 >nul 2>&1

"%PS_EXE%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "exit (Get-Process -Name VigilServeAgent -ErrorAction SilentlyContinue | Measure-Object).Count" >nul 2>&1
if not errorlevel 1 goto vs_done
if %VS_TRY% LSS 3 goto vs_kill

echo [VigilServe Agent] Agent is still running (permission denied?).
endlocal & exit /b 1

:vs_done
echo [VigilServe Agent] Agent stopped.
endlocal & exit /b 0
