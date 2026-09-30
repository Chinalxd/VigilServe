@echo off
REM ============================================================
REM  Remove the VigilServe startup shortcut.
REM ============================================================

setlocal
set "SHORTCUT=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\VigilServe.lnk"

if exist "%SHORTCUT%" (
    del /f /q "%SHORTCUT%" >nul 2>&1
    echo [VigilServe] Startup shortcut removed.
) else (
    echo [VigilServe] No startup shortcut found.
)
endlocal