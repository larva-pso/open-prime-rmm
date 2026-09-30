@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "TASKNAME=OpenPrime RMM Agent"
set "AGENTDIR=C:\Program Files\OpenPrime"
set "DATADIR=C:\ProgramData\OpenPrime"
set "WORKROOT=C:\Windows\Temp"
set "OUTNAME=OpenPrimeRMM-Diagnostics-%COMPUTERNAME%"
set "OUTDIR=%WORKROOT%\%OUTNAME%"
set "ZIPFILE=%WORKROOT%\%OUTNAME%.zip"

fltmc >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Run this diagnostics tool as Administrator or SYSTEM.
  exit /b 1
)

rmdir /s /q "%OUTDIR%" >nul 2>&1
del /q "%ZIPFILE%" >nul 2>&1
mkdir "%OUTDIR%" >nul 2>&1

> "%OUTDIR%\README.txt" echo OpenPrimeRMM endpoint diagnostics
>> "%OUTDIR%\README.txt" echo Computer: %COMPUTERNAME%
>> "%OUTDIR%\README.txt" echo Collected: %DATE% %TIME%
>> "%OUTDIR%\README.txt" echo IMPORTANT: config.json and agent tokens are intentionally excluded.

ver > "%OUTDIR%\windows-version.txt" 2>&1
whoami /all > "%OUTDIR%\whoami.txt" 2>&1
systeminfo > "%OUTDIR%\systeminfo.txt" 2>&1
ipconfig /all > "%OUTDIR%\network.txt" 2>&1

schtasks.exe /Query /TN "%TASKNAME%" /V /FO LIST > "%OUTDIR%\agent-task.txt" 2>&1
schtasks.exe /Query /TN "%TASKNAME%" /XML > "%OUTDIR%\agent-task.xml" 2>&1
schtasks.exe /Query /TN "OpenPrime Tray" /V /FO LIST > "%OUTDIR%\tray-task.txt" 2>&1

if exist "%AGENTDIR%\agent.ps1" findstr /C:"$AgentVersion" "%AGENTDIR%\agent.ps1" > "%OUTDIR%\agent-version.txt" 2>&1
if exist "%AGENTDIR%\tray.ps1" findstr /C:"$TrayVersion" "%AGENTDIR%\tray.ps1" > "%OUTDIR%\tray-version.txt" 2>&1
if exist "%AGENTDIR%\agent.ps1" certutil.exe -hashfile "%AGENTDIR%\agent.ps1" SHA256 > "%OUTDIR%\agent-sha256.txt" 2>&1
if exist "%AGENTDIR%\tray.ps1" certutil.exe -hashfile "%AGENTDIR%\tray.ps1" SHA256 > "%OUTDIR%\tray-sha256.txt" 2>&1

if exist "%DATADIR%\agent.log" powershell.exe -NoProfile -NonInteractive -Command "Get-Content -LiteralPath '%DATADIR%\agent.log' -Tail 500" > "%OUTDIR%\agent-log-tail.txt" 2>&1
if exist "%DATADIR%\monitor_report.json" copy /y "%DATADIR%\monitor_report.json" "%OUTDIR%\monitor_report.json" >nul 2>&1
if exist "%DATADIR%\heartbeat.txt" copy /y "%DATADIR%\heartbeat.txt" "%OUTDIR%\heartbeat.txt" >nul 2>&1

if exist "%DATADIR%\config.json" powershell.exe -NoProfile -NonInteractive -Command "$c=Get-Content -Raw -LiteralPath '%DATADIR%\config.json'|ConvertFrom-Json; [pscustomobject]@{ServerUrl=$c.ServerUrl;AgentId=$c.AgentId;AgentToken='[REDACTED]'}|ConvertTo-Json" > "%OUTDIR%\config-redacted.json" 2>&1

wevtutil.exe qe Microsoft-Windows-TaskScheduler/Operational /c:80 /rd:true /f:text > "%OUTDIR%\task-scheduler-events.txt" 2>&1
wevtutil.exe qe "Windows PowerShell" /c:80 /rd:true /f:text > "%OUTDIR%\powershell-events.txt" 2>&1
sc.exe query state= all > "%OUTDIR%\services.txt" 2>&1
tasklist /v > "%OUTDIR%\processes.txt" 2>&1

powershell.exe -NoProfile -NonInteractive -Command "$p='%DATADIR%\config.json'; if(Test-Path $p){$u=(Get-Content -Raw $p|ConvertFrom-Json).ServerUrl; if($u){try{$r=Invoke-WebRequest -UseBasicParsing -Method Head -Uri $u -TimeoutSec 15; 'URL='+$u; 'HTTP='+[int]$r.StatusCode}catch{'URL='+$u; 'ERROR='+$_.Exception.Message}}}" > "%OUTDIR%\server-connectivity.txt" 2>&1

where tar.exe >nul 2>&1
if not errorlevel 1 (
  tar.exe -a -c -f "%ZIPFILE%" -C "%WORKROOT%" "%OUTNAME%" >nul 2>&1
  if exist "%ZIPFILE%" (
    echo [OK] Diagnostics created:
    echo      %ZIPFILE%
    echo.
    echo The package excludes config.json and the agent token.
    exit /b 0
  )
)

echo [WARNING] ZIP creation was unavailable. Diagnostics folder created:
echo           %OUTDIR%
exit /b 0
