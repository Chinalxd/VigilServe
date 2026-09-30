@echo off
REM ============================================================
REM  VigilServe - Reset administrator password (interactive)
REM  - Auto-detects Python (WorkBuddy venv -> bundled -> PATH)
REM  - Prompts for username and new password (hidden input)
REM  - Backs up monitor.db, then rewrites the password hash
REM
REM  NOTE: this script is meant to be double-clicked by a human,
REM  so it DOES end with `pause` (unlike start.bat, which must not
REM  block when Inno Setup invokes it from a [Run] entry).
REM ============================================================

setlocal
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

set "PYTHON_EXE="
set "WB_PY=%LOCALAPPDATA%\..\..\..\WorkBuddy\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
if exist "%WB_PY%" set "PYTHON_EXE=%WB_PY%"

if "%PYTHON_EXE%"=="" (
    if exist "python_runtime\python.exe" (
        set "PYTHON_EXE=%SCRIPT_DIR%python_runtime\python.exe"
    )
)

if "%PYTHON_EXE%"=="" (
    where python >nul 2>&1 && (
        for /f "delims=" %%p in ('where python') do (
            set "PYTHON_EXE=%%p"
            goto :found
        )
    )
    where py >nul 2>&1 && (
        for /f "delims=" %%p in ('where py') do (
            set "PYTHON_EXE=%%p"
            goto :found
        )
    )
)

:found
if "%PYTHON_EXE%"=="" (
    echo [VigilServe] Python not found. Please install Python 3.10+ and retry.
    echo.
    pause
    endlocal & exit /b 1
)

cd /d "%SCRIPT_DIR%backend"
"%PYTHON_EXE%" reset_admin_password.py
set "RC=%ERRORLEVEL%"

echo.
if not "%RC%"=="0" (
    echo [VigilServe] Reset failed with exit code %RC%.
) else (
    echo [VigilServe] Done. Please RESTART the VigilServe service.
)
echo.
pause
endlocal & exit /b %RC%
