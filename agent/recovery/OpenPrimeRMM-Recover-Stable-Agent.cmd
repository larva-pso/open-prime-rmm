@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "SERVERURL=https://rmm.example.com"
if /I "%~1"=="/server" if not "%~2"=="" set "SERVERURL=%~2"
if not "%~1"=="" if /I not "%~1"=="/server" set "SERVERURL=%~1"

set "TASKNAME=OpenPrime RMM Agent"
set "AGENTDIR=C:\Program Files\OpenPrime"
set "DATADIR=C:\ProgramData\OpenPrime"
set "AGENT=%AGENTDIR%\agent.ps1"
set "CONFIG=%DATADIR%\config.json"
set "RUNAGENT=%DATADIR%\run-agent.cmd"
set "WORKDIR=C:\Windows\Temp\OpenPrimeRMM"
set "TMPAGENT=%WORKDIR%\agent-stable-1.12.6.ps1"
set "BACKUP=%AGENTDIR%\agent.pre-recovery.ps1"
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

fltmc >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Run this recovery tool as Administrator or SYSTEM.
  exit /b 1
)

if not exist "%CONFIG%" (
  echo [ERROR] The enrolled device configuration is missing:
  echo         %CONFIG%
  echo.
  echo This tool intentionally will not re-enroll the computer.
  echo Use Fleet ^> Add device only after confirming the original identity cannot be recovered.
  exit /b 1
)

if not exist "%AGENTDIR%" mkdir "%AGENTDIR%" >nul 2>&1
if not exist "%DATADIR%" mkdir "%DATADIR%" >nul 2>&1
if not exist "%WORKDIR%" mkdir "%WORKDIR%" >nul 2>&1

where curl.exe >nul 2>&1
if errorlevel 1 (
  echo [ERROR] curl.exe is not available on this computer.
  exit /b 1
)

if not exist "%PSEXE%" (
  echo [ERROR] Windows PowerShell 5.1 was not found:
  echo         %PSEXE%
  exit /b 1
)

echo ============================================================
echo OpenPrimeRMM - Stable Agent Recovery
echo Computer: %COMPUTERNAME%
echo Server:   %SERVERURL%
echo Preserves: %CONFIG%
echo ============================================================
echo.

echo [1/7] Stopping the current agent task...
schtasks.exe /End /TN "%TASKNAME%" >nul 2>&1

echo [2/7] Downloading pinned stable agent 1.12.6...
del /q "%TMPAGENT%" >nul 2>&1
curl.exe -fL --retry 2 --connect-timeout 15 "%SERVERURL%/downloads/recovery/agent-stable-1.12.6.ps1" -o "%TMPAGENT%"
if errorlevel 1 (
  echo [ERROR] Could not download the pinned stable agent.
  exit /b 1
)

findstr /C:"$AgentVersion = '1.12.6'" "%TMPAGENT%" >nul
if errorlevel 1 (
  echo [ERROR] The downloaded file is not pinned agent version 1.12.6.
  findstr /C:"$AgentVersion" "%TMPAGENT%"
  del /q "%TMPAGENT%" >nul 2>&1
  exit /b 1
)

echo [3/7] Backing up the installed agent...
if exist "%AGENT%" copy /y "%AGENT%" "%BACKUP%" >nul

echo [4/7] Replacing the agent without changing device identity...
copy /y "%TMPAGENT%" "%AGENT%" >nul
if errorlevel 1 (
  echo [ERROR] Could not replace %AGENT%.
  echo Check Bitdefender quarantine/exclusions and file permissions.
  exit /b 1
)
del /q "%TMPAGENT%" >nul 2>&1

echo [5/7] Rebuilding the safe SYSTEM launcher...
> "%RUNAGENT%" echo @echo off
>> "%RUNAGENT%" echo "%PSEXE%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%AGENT%"
if errorlevel 1 (
  echo [ERROR] Could not create %RUNAGENT%.
  exit /b 1
)

echo [6/7] Verifying or repairing the scheduled task...
schtasks.exe /Query /TN "%TASKNAME%" >nul 2>&1
if errorlevel 1 (
  schtasks.exe /Create /TN "%TASKNAME%" /SC MINUTE /MO 1 /TR "%SystemRoot%\System32\cmd.exe /d /c %RUNAGENT%" /RU SYSTEM /RL HIGHEST /F >"%WORKDIR%\task-create.log" 2>&1
  if errorlevel 1 (
    type "%WORKDIR%\task-create.log"
    echo [ERROR] The scheduled task could not be recreated.
    exit /b 1
  )
)

schtasks.exe /Change /TN "%TASKNAME%" /ENABLE >nul 2>&1

echo [7/7] Starting the recovered agent...
schtasks.exe /Run /TN "%TASKNAME%" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] The agent file was recovered, but the task could not be started.
  echo Run the Task Repair tool from OpenPrimeRMM Recovery Center.
  exit /b 1
)

echo.
findstr /C:"$AgentVersion" "%AGENT%"
echo [OK] Stable agent recovery completed.
echo      Device identity and token were preserved.
echo      Expected dashboard recovery time: 1-2 minutes.
echo      Log: %DATADIR%\agent.log
echo.
echo Do NOT delete %CONFIG% during a normal rollback.
exit /b 0
