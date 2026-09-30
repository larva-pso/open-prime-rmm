@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem ---------------------------------------------------------------------------
rem OpenPrimeRMM native CMD bootstrap installer
rem Downloads and enrolls without invoking PowerShell during installation.
rem The installed OpenPrimeRMM endpoint agent is still a PowerShell agent and
rem is launched later by Windows Task Scheduler.
rem ---------------------------------------------------------------------------

set "ServerUrl="
set "EnrollKey="
set "OrgName="
set "IntervalMinutes=1"
set "Uninstall=0"
set "TaskName=OpenPrime RMM Agent"
set "InstallRoot=%ProgramFiles%"
if defined ProgramW6432 set "InstallRoot=%ProgramW6432%"
set "InstallDir=%InstallRoot%\OpenPrime"
set "DataDir=%ProgramData%\OpenPrime"
set "AgentFile=%InstallRoot%\OpenPrime\agent.ps1"
set "RunAgent=%ProgramData%\OpenPrime\run-agent.cmd"
set "PowerShellExe=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "EnrollTmp=%TEMP%\OpenPrime-enroll-%RANDOM%-%RANDOM%.tmp"
set "AgentTmp=%TEMP%\OpenPrime-agent-%RANDOM%-%RANDOM%.ps1"
set "TaskLog=%TEMP%\OpenPrime-task-%RANDOM%-%RANDOM%.log"

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="/server" (
    if "%~2"=="" goto usage
    set "ServerUrl=%~2"
    shift
    shift
    goto parse_args
)
if /I "%~1"=="/key" (
    if "%~2"=="" goto usage
    set "EnrollKey=%~2"
    shift
    shift
    goto parse_args
)
if /I "%~1"=="/org" (
    if "%~2"=="" goto usage
    set "OrgName=%~2"
    shift
    shift
    goto parse_args
)
if /I "%~1"=="/interval" (
    if "%~2"=="" goto usage
    set "IntervalMinutes=%~2"
    shift
    shift
    goto parse_args
)
if /I "%~1"=="/uninstall" (
    set "Uninstall=1"
    shift
    goto parse_args
)
if /I "%~1"=="/?" goto usage
if /I "%~1"=="/help" goto usage
echo [ERROR] Unknown option: %~1
goto usage

:args_done
rem Administrative access is still required to write Program Files and create
rem a SYSTEM scheduled task. A native CMD installer cannot bypass Windows UAC.
fltmc.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Access denied. Open Command Prompt with "Run as administrator".
    exit /b 1
)

if "%Uninstall%"=="1" goto uninstall

if not defined ServerUrl goto usage
if not defined EnrollKey goto usage
if "%ServerUrl:~-1%"=="/" set "ServerUrl=%ServerUrl:~0,-1%"

set "InvalidInterval="
for /f "delims=0123456789" %%A in ("%IntervalMinutes%") do set "InvalidInterval=%%A"
if defined InvalidInterval (
    echo [ERROR] /interval must be a whole number from 1 through 60.
    exit /b 2
)
set /a IntervalNumber=%IntervalMinutes% >nul 2>&1
if errorlevel 1 (
    echo [ERROR] /interval is not a valid decimal whole number.
    exit /b 2
)
if %IntervalNumber% LSS 1 (
    echo [ERROR] /interval must be at least 1 minute.
    exit /b 2
)
if %IntervalNumber% GTR 60 (
    echo [ERROR] /interval cannot exceed 60 minutes.
    exit /b 2
)
set "IntervalMinutes=%IntervalNumber%"

where curl.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] curl.exe is required. It is included with supported Windows 10 and Windows 11 releases.
    exit /b 1
)

if not exist "%PowerShellExe%" (
    echo [ERROR] Windows PowerShell 5.1 was not found. The OpenPrimeRMM endpoint agent requires it.
    exit /b 1
)

if /I "%ServerUrl:~0,7%"=="http://" (
    echo [WARNING] The server URL uses unencrypted HTTP. Use HTTPS before production deployment.
)

echo ============================================================
echo OpenPrimeRMM Native CMD Installer
echo Computer: %COMPUTERNAME%
echo Server:   %ServerUrl%
if defined OrgName echo Customer: %OrgName%
echo ============================================================
echo.

echo [1/6] Preparing installation folders...
if not exist "%InstallDir%" (
    mkdir "%InstallDir%" >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Could not create "%InstallDir%".
        goto failed
    )
)
if not exist "%DataDir%" (
    mkdir "%DataDir%" >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Could not create "%DataDir%".
        goto failed
    )
)

echo [2/6] Downloading the endpoint agent...
curl.exe -fL --retry 2 --retry-delay 2 --connect-timeout 15 --max-time 120 ^
    "%ServerUrl%/downloads/agent.ps1" -o "%AgentTmp%"
if errorlevel 1 (
    echo [ERROR] Agent download failed. Check DNS, TLS, firewall, and the server URL.
    goto failed
)
for %%F in ("%AgentTmp%") do if %%~zF LSS 1000 (
    echo [ERROR] The downloaded agent file is unexpectedly small.
    goto failed
)
copy /y "%AgentTmp%" "%AgentFile%" >nul
if errorlevel 1 (
    echo [ERROR] Could not write "%AgentFile%".
    goto failed
)
del /q "%AgentTmp%" >nul 2>&1

echo [3/6] Reading Windows version...
set "ProductName=Microsoft Windows"
set "DisplayVersion="
set "BuildNumber="
for /f "tokens=2,*" %%A in ('reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName 2^>nul') do set "ProductName=%%B"
for /f "tokens=2,*" %%A in ('reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion 2^>nul') do set "DisplayVersion=%%B"
for /f "tokens=2,*" %%A in ('reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber 2^>nul') do set "BuildNumber=%%B"
set "OsVersion=%ProductName% %DisplayVersion% (Build %BuildNumber%)"
set "MachineGuid="
for /f "tokens=2,*" %%A in ('reg.exe query "HKLM\SOFTWARE\Microsoft\Cryptography" /v MachineGuid 2^>nul') do set "MachineGuid=%%B"
if not defined MachineGuid echo [WARNING] Windows MachineGuid could not be read; using customer + hostname fallback.
set "ExistingAgentId="
if not exist "%DataDir%\config.json" goto existing_agent_id_done
for /f "tokens=2 delims=:," %%A in ('findstr.exe /I /C:"AgentId" "%DataDir%\config.json" 2^>nul') do set "ExistingAgentId=%%~A"
set "ExistingAgentId=%ExistingAgentId: =%"
set "ExistingAgentId=%ExistingAgentId:"=%"
:existing_agent_id_done

echo [4/6] Enrolling with OpenPrimeRMM...
curl.exe -fS --retry 2 --retry-delay 2 --connect-timeout 15 --max-time 60 ^
    -X POST ^
    --data-urlencode "enroll_key=%EnrollKey%" ^
    --data-urlencode "hostname=%COMPUTERNAME%" ^
    --data-urlencode "machine_guid=%MachineGuid%" ^
    --data-urlencode "existing_agent_id=%ExistingAgentId%" ^
    --data-urlencode "os_version=%OsVersion%" ^
    --data-urlencode "org=%OrgName%" ^
    "%ServerUrl%/api/agent/enroll-cmd" -o "%EnrollTmp%"
if errorlevel 1 (
    echo [ERROR] Enrollment failed. Confirm the enrollment key and server URL.
    goto failed
)

set "AgentId="
set "AgentToken="
for /f "usebackq tokens=1,* delims==" %%A in ("%EnrollTmp%") do (
    if /I "%%A"=="AGENT_ID" set "AgentId=%%B"
    if /I "%%A"=="AGENT_TOKEN" set "AgentToken=%%B"
)
del /q "%EnrollTmp%" >nul 2>&1

if not defined AgentId (
    echo [ERROR] Enrollment response did not contain an agent ID.
    goto failed
)
if not defined AgentToken (
    echo [ERROR] Enrollment response did not contain an agent token.
    goto failed
)

> "%DataDir%\config.json.tmp" echo {
>> "%DataDir%\config.json.tmp" echo   "ServerUrl": "%ServerUrl%",
>> "%DataDir%\config.json.tmp" echo   "AgentId": "%AgentId%",
>> "%DataDir%\config.json.tmp" echo   "AgentToken": "%AgentToken%"
>> "%DataDir%\config.json.tmp" echo }
move /y "%DataDir%\config.json.tmp" "%DataDir%\config.json" >nul
if errorlevel 1 (
    echo [ERROR] Could not save the agent configuration.
    goto failed
)

rem Restrict the token directory to Local System and local Administrators.
icacls.exe "%DataDir%" /inheritance:r ^
    /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >nul
if errorlevel 1 (
    echo [ERROR] Could not secure "%DataDir%".
    goto failed
)

echo [5/6] Creating the SYSTEM launcher...
> "%RunAgent%" echo @echo off
>> "%RunAgent%" echo "%PowerShellExe%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%AgentFile%"
if errorlevel 1 (
    echo [ERROR] Could not create "%RunAgent%".
    goto failed
)

echo [6/6] Registering the scheduled task...
rem Use the native schtasks MINUTE schedule directly. This is the most
rem compatible registration method across supported Windows 10/11 and Server
rem builds and avoids XML encoding/parser differences between Windows releases.
schtasks.exe /Delete /TN "%TaskName%" /F >nul 2>&1
schtasks.exe /Create /TN "%TaskName%" /SC MINUTE /MO %IntervalMinutes% ^
    /TR "%SystemRoot%\System32\cmd.exe /d /c %RunAgent%" ^
    /RU SYSTEM /RL HIGHEST /F >"%TaskLog%" 2>&1
if errorlevel 1 (
    type "%TaskLog%"
    echo [ERROR] Scheduled task registration failed.
    goto failed
)
del /q "%TaskLog%" >nul 2>&1

schtasks.exe /Query /TN "%TaskName%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Scheduled task verification failed.
    goto failed
)

schtasks.exe /Run /TN "%TaskName%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] The task was created but could not be started.
    goto failed
)

echo.
echo [OK] OpenPrimeRMM installed successfully.
echo      Device: %COMPUTERNAME%
echo      Logs:   %DataDir%\agent.log
echo      The dashboard should update within about one minute.
exit /b 0

:uninstall
schtasks.exe /Delete /TN "%TaskName%" /F >nul 2>&1
schtasks.exe /Delete /TN "OpenPrime Tray" /F >nul 2>&1
rmdir /s /q "%InstallDir%" >nul 2>&1
rmdir /s /q "%DataDir%" >nul 2>&1
echo [OK] OpenPrimeRMM agent removed.
exit /b 0

:failed
del /q "%AgentTmp%" "%EnrollTmp%" "%TaskLog%" >nul 2>&1
echo.
echo [FAILED] OpenPrimeRMM was not fully installed.
echo Review the error above. This installer does not report success after failure.
exit /b 1

:usage
echo.
echo Usage:
echo   Install-Agent.cmd /server "https://rmm.example.com" /key "ENROLL-KEY" [/org "Customer"] [/interval 1]
echo   Install-Agent.cmd /uninstall
echo.
exit /b 2
