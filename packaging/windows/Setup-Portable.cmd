@echo off
rem WezCrypt Aegis portable setup.
rem Grants the Windows sandbox's low-privilege AppContainer read/execute access
rem to this folder (required for sandboxed Chromium processes). Run once after
rem extracting the portable archive.
setlocal
set "APPDIR=%~dp0"
icacls "%APPDIR%." /grant "*S-1-15-2-2:(OI)(CI)(RX)" >nul
if errorlevel 1 (
  echo Could not update folder permissions. Extract WezCrypt Aegis to a folder you own and retry.
  exit /b 1
)
echo WezCrypt Aegis portable folder prepared. Start WezCryptAegis.exe.
endlocal
