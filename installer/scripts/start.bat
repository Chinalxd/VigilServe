@echo off
REM ============================================================
REM  VigilServe server start script (installed version)
REM  - Auto-detects Python (WorkBuddy venv -> bundled -> PATH)
REM  - First-run: installs backend\requirements.txt
REM  - Then: starts uvicorn on port 8001
REM
REM  IMPORTANT: no `pause` calls. Inno Setup would otherwise hang
REM  on this script when it is invoked as a [Run] entry.
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
    endlocal & exit /b 1
)

if not exist "backend\.deps_installed" (
    echo [VigilServe] First run - installing backend dependencies, please wait...
    "%PYTHON_EXE%" -m pip install --disable-pip-version-check -r backend\requirements.txt
    if errorlevel 1 (
        echo [VigilServe] Dependency installation failed.
        endlocal & exit /b 1
    )
    type nul > "backend\.deps_installed"
)

cd /d "%SCRIPT_DIR%backend"
"%PYTHON_EXE%" -m uvicorn main:app --host 0.0.0.0 --port 8001
endlocal