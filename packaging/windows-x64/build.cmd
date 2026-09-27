@echo off
setlocal
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo Windows PowerShell 5.1 was not found in PATH.
  endlocal & exit /b 9009
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
set "p2p_exit_code=%ERRORLEVEL%"
endlocal & exit /b %p2p_exit_code%
