@echo off
REM ============================================================
REM  Create a Windows startup-folder shortcut that launches
REM  start.bat on user logon.
REM
REM  NOTE: this batch file is kept for manual use only. The
REM  VigilServe installer no longer calls it (it would block
REM  waiting for the batch to terminate). The installer creates
REM  the Startup-folder shortcut natively via Inno [Icons].
REM ============================================================

setlocal
set "SCRIPT_DIR=%~dp0"
set "SHORTCUT=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\VigilServe.lnk"
set "TARGET=%SCRIPT_DIR%start.bat"
set "WORKDIR=%SCRIPT_DIR%"

powershell -NoProfile -Command ^
    "$ws = New-Object -ComObject WScript.Shell; ^
     $s  = $ws.CreateShortcut('%SHORTCUT%'); ^
     $s.TargetPath = '%TARGET%'; ^
     $s.WorkingDirectory = '%WORKDIR%'; ^
     $s.WindowStyle = 7; ^
     $s.Description = 'VigilServe - launch on Windows logon'; ^
     $s.Save()"

set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%