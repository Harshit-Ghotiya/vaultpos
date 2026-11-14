@echo off
setlocal
title VaultPOS Launcher
echo Starting VaultPOS Thermal Receipt POS in Native Windows App Mode...
set "APP_FILE=%~dp0VaultPOS_POS.html"
if not exist "%APP_FILE%" (
  echo VaultPOS_POS.html not found in this folder! Please keep both files in the same folder.
  pause
  exit /b 1
)
set "EDGE_EXE="
for %%E in (msedge.exe) do set "EDGE_EXE=%%~$PATH:E"
if not defined EDGE_EXE if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" set "EDGE_EXE=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
if not defined EDGE_EXE if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" set "EDGE_EXE=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if not defined EDGE_EXE (
  echo Microsoft Edge was not found. Install or repair Microsoft Edge, then retry.
  pause
  exit /b 1
)
tasklist /FI "IMAGENAME eq msedge.exe" 2>NUL | find /I "msedge.exe" >NUL
if not errorlevel 1 (
  echo Notice: Microsoft Edge is already running. If silent kiosk printing does not trigger, close all Edge windows and re-run this launcher.
)
set "APP_URL=file:///%APP_FILE:\=/%"
setlocal EnableDelayedExpansion
set "APP_URL=!APP_URL:#=%%23!"
set "APP_URL=!APP_URL: =%%20!"
start "" "!EDGE_EXE!" --app="!APP_URL!" --kiosk-printing --disable-session-crashed-bubble
endlocal
exit /b 0
