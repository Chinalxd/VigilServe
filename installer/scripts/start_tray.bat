@echo off
REM ============================================================
REM  Launch the VigilServe tray control program (VigilServeTray.exe)
REM ============================================================

setlocal
set "SCRIPT_DIR=%~dp0"
REM --panel：装完直接把控制面板窗口弹出来，而不是只在托盘里放个图标
start "" "%SCRIPT_DIR%tray\VigilServeTray.exe" --panel
endlocal