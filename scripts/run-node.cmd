@echo off
REM Start a local Hassan node (loopback API + Tor-only dial by default).
REM Usage: run-node.cmd [archive^|validator^|light] [extra args...]
setlocal
set "HERE=%~dp0"
if exist "%HERE%hassan.exe" (
  set "BIN=%HERE%hassan.exe"
) else if exist "%HERE%..\target\release\hassan.exe" (
  set "BIN=%HERE%..\target\release\hassan.exe"
  set "HERE=%HERE%..\"
) else if exist "%HERE%target\release\hassan.exe" (
  set "BIN=%HERE%target\release\hassan.exe"
) else (
  echo hassan.exe not found. Build first:
  echo   cargo build --release --bin hassan
  exit /b 1
)

set "ROLE=validator"
if not "%~1"=="" (
  if /I "%~1"=="archive" set "ROLE=%~1" & shift
  if /I "%~1"=="validator" set "ROLE=%~1" & shift
  if /I "%~1"=="light" set "ROLE=%~1" & shift
  if /I "%~1"=="full" set "ROLE=archive" & shift
)

if "%HASSAN_DATA_DIR%"=="" set "HASSAN_DATA_DIR=%HERE%hassan-data"
if "%HASSAN_API_BIND%"=="" set "HASSAN_API_BIND=127.0.0.1:8080"

if not exist "%HASSAN_DATA_DIR%" mkdir "%HASSAN_DATA_DIR%"
echo role:  %ROLE%
echo data:  %HASSAN_DATA_DIR%
echo api:   http://%HASSAN_API_BIND%/
echo bin:   %BIN%
"%BIN%" %ROLE% %*
