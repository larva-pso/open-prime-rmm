@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "TASKNAME=OpenPrime RMM Agent"
set "AGENT=C:\Program Files\OpenPrime\agent.ps1"
set "DATADIR=C:\ProgramData\OpenPrime"
set "CONFIG=%DATADIR%\config.json"
set "RUNAGENT=%DATADIR%\run-agent.cmd"
set "WORKDIR=C:\Windows\Temp\OpenPrimeRMM"
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

fltmc >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Run this repair tool as Administrator or SYSTEM.
  exit /b 1
)

if not exist "%AGENT%" (
  echo [ERROR] Agent file not found: %AGENT%
  echo Run the Stable Agent Recovery tool first.
  exit /b 1
)
if not exist "%CONFIG%" (
  echo [ERROR] Enrolled configuration not found: %CONFIG%
  echo This tool will not create a new identity.
  exit /b 1
)
if not exist "%DATADIR%" mkdir "%DATADIR%" >nul 2>&1
if not exist "%WORKDIR%" mkdir "%WORKDIR%" >nul 2>&1

echo ============================================================
echo OpenPrimeRMM - Scheduled Task Repair
echo Computer: %COMPUTERNAME%
echo ============================================================
echo.

echo [1/5] Stopping and removing the existing task...
schtasks.exe /End /TN "%TASKNAME%" >nul 2>&1
schtasks.exe /Delete /TN "%TASKNAME%" /F >nul 2>&1

echo [2/5] Creating the SYSTEM launcher...
> "%RUNAGENT%" echo @echo off
>> "%RUNAGENT%" echo "%PSEXE%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%AGENT%"
if errorlevel 1 (
  echo [ERROR] Could not create %RUNAGENT%.
  exit /b 1
)

echo [3/5] Registering the one-minute SYSTEM task...
schtasks.exe /Create /TN "%TASKNAME%" /SC MINUTE /MO 1 /TR "%SystemRoot%\System32\cmd.exe /d /c %RUNAGENT%" /RU SYSTEM /RL HIGHEST /F >"%WORKDIR%\task-create.log" 2>&1
if errorlevel 1 (
  type "%WORKDIR%\task-create.log"
  echo [ERROR] Scheduled-task registration failed.
  exit /b 1
)

echo [4/5] Verifying the task...
schtasks.exe /Query /TN "%TASKNAME%" /V /FO LIST >"%WORKDIR%\task-query.txt" 2>&1
if errorlevel 1 (
  type "%WORKDIR%\task-query.txt"
  echo [ERROR] Scheduled-task verification failed.
  exit /b 1
)

echo [5/5] Starting the agent...
schtasks.exe /Run /TN "%TASKNAME%" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Task exists but could not be started.
  exit /b 1
)

echo.
echo [OK] The OpenPrimeRMM agent task was recreated and started.
echo      Device identity and token were not changed.
echo      Review: schtasks /Query /TN "%TASKNAME%" /V /FO LIST
exit /b 0
