<#
.SYNOPSIS
  Called by the OpenPrime Agent MSI custom actions. Not usually run by hand
  (use Install-Agent.ps1 for manual installs).

  Install/upgrade : enrolls with the server (if an EnrollKey is given or the
                    machine is not yet enrolled) and registers the scheduled task.
  Upgrade w/o key : keeps the existing config.json and just refreshes the task.
  -Uninstall      : removes the scheduled task and all agent data.
#>
param(
    [string]$ServerUrl,
    [string]$EnrollKey,
    [string]$OrgName = '',
    [int]$IntervalMinutes = 5,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path   # e.g. C:\Program Files\OpenPrime
$DataDir    = 'C:\ProgramData\OpenPrime'
$ConfigPath = Join-Path $DataDir 'config.json'
$TaskName   = 'OpenPrime RMM Agent'

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output 'OpenPrime agent task and data removed.'
    exit 0
}

New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

# --- enrollment --------------------------------------------------------------
$haveConfig = Test-Path $ConfigPath

if ($EnrollKey) {
    if (-not $ServerUrl) { Write-Error 'ServerUrl is required with EnrollKey.'; exit 1 }
    $ServerUrl = $ServerUrl.TrimEnd('/')
    Write-Output "Enrolling $env:COMPUTERNAME with $ServerUrl ..."
    $os = Get-CimInstance Win32_OperatingSystem
    $existingAgentId = ''
    if (Test-Path $ConfigPath) {
        try {
            $existingAgentId = (Get-Content $ConfigPath -Raw | ConvertFrom-Json).AgentId
        } catch {
            Write-Warning 'Existing OpenPrimeRMM configuration could not be read; using tenant-scoped enrollment.'
        }
    }
    $machineGuid = ''
    try {
        $machineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
            -Name MachineGuid -ErrorAction Stop).MachineGuid
    } catch {
        Write-Warning 'Windows MachineGuid could not be read; using customer + hostname fallback.'
    }
    $body = @{
        enroll_key      = $EnrollKey
        hostname        = $env:COMPUTERNAME
        machine_guid    = $machineGuid
        existing_agent_id = $existingAgentId
        os_version      = "$($os.Caption) ($($os.Version))"
        org             = $OrgName
    } | ConvertTo-Json
    $resp = Invoke-RestMethod -Method POST -Uri "$ServerUrl/api/agent/enroll" `
        -Body $body -ContentType 'application/json' -TimeoutSec 60

    @{
        ServerUrl  = $ServerUrl
        AgentId    = $resp.agent_id
        AgentToken = $resp.agent_token
    } | ConvertTo-Json | Set-Content -Path $ConfigPath -Encoding UTF8

    icacls $DataDir /inheritance:r /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' | Out-Null
    Write-Output 'Enrolled.'
}
elseif ($haveConfig) {
    Write-Output 'Existing enrollment found - keeping current config (upgrade path).'
}
else {
    Write-Error 'No ENROLLKEY provided and this machine is not enrolled. Pass SERVERURL and ENROLLKEY to msiexec.'
    exit 1
}

# --- scheduled task -----------------------------------------------------------
Write-Output "Registering scheduled task (every $IntervalMinutes min, as SYSTEM)..."
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `
    "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallDir\agent.ps1`""

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 4)

$principalTask = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principalTask | Out-Null

Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Write-Output 'OpenPrime agent installed and running.'
