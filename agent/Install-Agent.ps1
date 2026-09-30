<#
.SYNOPSIS
  Installs (or removes) the OpenPrime RMM agent on a Windows workstation.

.EXAMPLE
  # One-liner (run as Administrator):
  irm https://rmm.example.com/downloads/Install-Agent.ps1 -OutFile $env:TEMP\Install-Agent.ps1
  & $env:TEMP\Install-Agent.ps1 -ServerUrl https://rmm.example.com -EnrollKey 'YOUR-ENROLL-KEY' -OrgName 'Acme Dental'

.EXAMPLE
  & .\Install-Agent.ps1 -Uninstall
#>
param(
    [string]$ServerUrl,
    [string]$EnrollKey,
    [string]$OrgName = '',
    [int]$IntervalMinutes = 1,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$InstallDir = 'C:\Program Files\OpenPrime'
$DataDir    = 'C:\ProgramData\OpenPrime'
$TaskName   = 'OpenPrime RMM Agent'

# --- admin check -----------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this script as Administrator.'
    exit 1
}

# --- uninstall -------------------------------------------------------------
if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'OpenPrime Tray' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $InstallDir, $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'OpenPrime agent removed.' -ForegroundColor Green
    exit 0
}

if (-not $ServerUrl -or -not $EnrollKey) {
    Write-Error 'Usage: Install-Agent.ps1 -ServerUrl https://rmm.example.com -EnrollKey <key>'
    exit 1
}
$ServerUrl = $ServerUrl.TrimEnd('/')

# --- fetch agent script from the server -------------------------------------
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir    -Force | Out-Null

Write-Host "Downloading agent from $ServerUrl ..."
Invoke-WebRequest -Uri "$ServerUrl/downloads/agent.ps1" `
    -OutFile (Join-Path $InstallDir 'agent.ps1') -UseBasicParsing

# --- enroll ------------------------------------------------------------------
Write-Host 'Enrolling with server...'
$os = Get-CimInstance Win32_OperatingSystem
$existingAgentId = ''
$existingConfig = Join-Path $DataDir 'config.json'
if (Test-Path $existingConfig) {
    try {
        $existingAgentId = (Get-Content $existingConfig -Raw | ConvertFrom-Json).AgentId
    } catch {
        Write-Warning 'Existing OpenPrimeRMM configuration could not be read; using tenant-scoped enrollment.'
    }
}
$machineGuid = ''
try {
    $machineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
        -Name MachineGuid -ErrorAction Stop).MachineGuid
} catch {
    Write-Warning 'Windows MachineGuid could not be read; enrollment will use customer + hostname fallback.'
}
$body = @{
    enroll_key  = $EnrollKey
    hostname    = $env:COMPUTERNAME
    machine_guid = $machineGuid
    existing_agent_id = $existingAgentId
    os_version  = "$($os.Caption) ($($os.Version))"
    org         = $OrgName
} | ConvertTo-Json
$resp = Invoke-RestMethod -Method POST -Uri "$ServerUrl/api/agent/enroll" `
    -Body $body -ContentType 'application/json' -TimeoutSec 60

@{
    ServerUrl  = $ServerUrl
    AgentId    = $resp.agent_id
    AgentToken = $resp.agent_token
} | ConvertTo-Json | Set-Content -Path (Join-Path $DataDir 'config.json') -Encoding UTF8

# Lock the config down: agent token should only be readable by SYSTEM + Admins
icacls $DataDir /inheritance:r /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' | Out-Null

# --- scheduled task ----------------------------------------------------------
Write-Host "Registering scheduled task (every $IntervalMinutes min, as SYSTEM)..."

$runAgent = Join-Path $DataDir 'run-agent.cmd'
$powerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
@(
    '@echo off'
    ('"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{1}"' -f `
        $powerShellExe, (Join-Path $InstallDir 'agent.ps1'))
) | Set-Content -Path $runAgent -Encoding Ascii

try {
    & "$env:SystemRoot\System32\schtasks.exe" /Delete /TN $TaskName /F 2>$null | Out-Null

    $taskAction = "$env:SystemRoot\System32\cmd.exe /d /c $runAgent"
    & "$env:SystemRoot\System32\schtasks.exe" /Create /TN $TaskName `
        /SC MINUTE /MO $IntervalMinutes /TR $taskAction `
        /RU SYSTEM /RL HIGHEST /F | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "schtasks.exe returned exit code $LASTEXITCODE."
    }

    $registered = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    if (-not $registered) {
        throw "Scheduled task '$TaskName' was not created."
    }

    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
}
catch {
    Write-Error "Agent files were downloaded and enrollment completed, but the scheduled task could not be created: $($_.Exception.Message)"
    Write-Host "Run this once to test the downloaded agent manually:" -ForegroundColor Yellow
    Write-Host "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\agent.ps1`"" -ForegroundColor Yellow
    exit 1
}

Write-Host ''
Write-Host "Installed. '$env:COMPUTERNAME' will appear on the dashboard within ~1 minute." -ForegroundColor Green
Write-Host "Logs: $DataDir\agent.log"
