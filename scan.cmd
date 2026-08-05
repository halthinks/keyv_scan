@echo off
setlocal
where node >nul 2>nul
if errorlevel 1 (
  echo Error: Node.js 18 or newer is required. 1>&2
  exit /b 2
)
for /f %%V in ('node -p "process.versions.node"') do set "NODE_VERSION=%%V"
for /f "tokens=1 delims=." %%V in ("%NODE_VERSION%") do set "NODE_MAJOR=%%V"
if %NODE_MAJOR% LSS 18 (
  echo Error: Node.js 18 or newer is required; found %NODE_VERSION%. 1>&2
  exit /b 2
)
node "%~dp0bin\keyv-scan.js" scan %*
exit /b %ERRORLEVEL%
