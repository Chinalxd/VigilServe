@echo off
REM ============================================================
REM  Install Python dependencies for the VigilServe backend.
REM  Run this once before the first start.bat invocation, or when
REM  backend\requirements.txt changes.
REM ============================================================

setlocal
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

set "PYTHON_EXE="
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

:found
if "%PYTHON_EXE%"=="" (
    echo [VigilServe] Python not found. Please install Python 3.10+ first.
    pause
    exit /b 1
)

echo Installing backend dependencies...
"%PYTHON_EXE%" -m pip install --disable-pip-version-check -r backend\requirements.txt
if errorlevel 1 (
    echo [VigilServe] Dependency installation failed.
    pause
    exit /b 1
)
type nul > "backend\.deps_installed"
echo [VigilServe] Dependencies installed.
pause
endlocal