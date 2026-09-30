@echo off
REM ============================================================
REM  Builds OpenPrimeAgent.msi
REM
REM  Prereq (once, on any Windows box):
REM    winget install WixToolset.WixToolset      (WiX v3.14)
REM    ...or download from https://wixtoolset.org/releases/
REM
REM  Then from this folder:
REM    build.cmd
REM
REM  Output: OpenPrimeAgent.msi
REM ============================================================
setlocal

set WIX_BIN=%WIX%bin
if not exist "%WIX_BIN%\candle.exe" set WIX_BIN=C:\Program Files (x86)\WiX Toolset v3.14\bin
if not exist "%WIX_BIN%\candle.exe" set WIX_BIN=C:\Program Files (x86)\WiX Toolset v3.11\bin
if not exist "%WIX_BIN%\candle.exe" (
    echo ERROR: WiX Toolset v3 not found. Install it first: winget install WixToolset.WixToolset
    exit /b 1
)

REM agent.ps1 must sit next to this script for packaging
if not exist agent.ps1 copy ..\agent.ps1 agent.ps1 >nul

"%WIX_BIN%\candle.exe" -nologo -arch x64 Product.wxs -out Product.wixobj || exit /b 1
"%WIX_BIN%\light.exe"  -nologo -ext WixUtilExtension Product.wixobj -out OpenPrimeAgent.msi || exit /b 1

del Product.wixobj *.wixpdb 2>nul
echo.
echo Built OpenPrimeAgent.msi
echo.
echo Deploy silently with:
echo   msiexec /i OpenPrimeAgent.msi SERVERURL=https://rmm.yourmsp.com ENROLLKEY=YOUR-KEY ORGNAME="Customer Name" /qn /l*v install.log
endlocal
