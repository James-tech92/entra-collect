@echo off
setlocal
cd /d "%~dp0"

where node >nul 2>&1
if errorlevel 1 (
  echo Node.js not found on PATH. Install LTS from https://nodejs.org/
  exit /b 1
)

if not exist "node_modules\playwright" (
  echo Running npm install...
  call npm install
  if errorlevel 1 exit /b 1
)

echo.
echo Entra Collect — Windows launcher
echo   auth=auto  (Azure CLI / Graph PowerShell if available, else browser)
echo   Recommended for MFA/passkeys:
echo     login-edge.cmd
echo     node collect.js --auth browser --cdp http://127.0.0.1:9222
echo   Help: node collect.js --help
echo.

node collect.js --auth auto %*
set ERR=%ERRORLEVEL%
echo.
if %ERR% neq 0 (
  echo Collector exited with code %ERR%
  exit /b %ERR%
)
echo Open the latest output_*\00_REPORT.html
echo   Excel workbook: output_*\00_Remediation_Plan.xlsx
echo   Rebuild: node report.js output_YYYY-MM-DD_HHMM
exit /b 0
