<# Isolated process launcher with a hard timeout and process-tree termination. #>
param(
    [ValidateSet('Scan','Install','Restore')]
    [string]$Mode = 'Scan',
    [int]$TimeoutSec = 180
)

$ErrorActionPreference = 'Stop'
$LabDir = 'C:\ProgramData\OpenPrime\wu-lab'
$Worker = 'C:\Program Files\OpenPrime\OpenPrimeRMM-WU-Lab-Worker.ps1'
$LogPath = Join-Path $LabDir 'launcher.log'
$ReportPath = Join-Path $LabDir 'worker-report.json'
$ActiveInstallPath = Join-Path $LabDir 'active-install.json'
$ResultDir = Join-Path $LabDir 'install-results'
if (-not (Test-Path $LabDir)) { New-Item -ItemType Directory -Path $LabDir -Force | Out-Null }
if (-not (Test-Path $ResultDir)) { New-Item -ItemType Directory -Path $ResultDir -Force | Out-Null }

function Log([string]$Message) {
    try { Add-Content $LogPath ("{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Mode, $Message) -Encoding UTF8 } catch {}
}
function WriteJson([string]$Path, $Value) {
    $tmp = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmp, ($Value | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
    Move-Item $tmp $Path -Force
}

if (-not (Test-Path $Worker)) { Log "Worker missing: $Worker"; exit 2 }
$proc = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"`"$Worker`"",'-Mode',$Mode) -WindowStyle Hidden -PassThru
$null = $proc.Handle
Log "Started worker PID $($proc.Id), timeout ${TimeoutSec}s."
if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
    Log "TIMEOUT: killing worker process tree PID $($proc.Id)."
    & "$env:SystemRoot\System32\taskkill.exe" /PID $proc.Id /T /F 2>&1 | Out-Null
    if ($Mode -eq 'Scan') {
        WriteJson $ReportPath @{ lab_build='WU-PROD-1'; worker_status='timeout'; mode='unknown'; compliant=$false; checked_at=[DateTimeOffset]::Now.ToUnixTimeSeconds(); errors=@("Windows Update worker exceeded ${TimeoutSec} seconds and was terminated. Core RMM agent remained active.") }
    } elseif ($Mode -eq 'Install' -and (Test-Path $ActiveInstallPath)) {
        try {
            $active = Get-Content $ActiveInstallPath -Raw | ConvertFrom-Json
            if ($active.job_id) {
                $failedIds = @()
                if ($active.queue_path -and (Test-Path $active.queue_path)) {
                    try {
                        $queued = Get-Content $active.queue_path -Raw | ConvertFrom-Json
                        $failedIds = @($queued.payload.update_ids)
                    } catch {}
                }
                WriteJson (Join-Path $ResultDir "$($active.job_id).json") @{ job_id=[string]$active.job_id; completed_at=[DateTimeOffset]::Now.ToUnixTimeSeconds(); result=@{ ok=$false; exit_code=-2; output="Windows Update installation exceeded ${TimeoutSec} seconds and was terminated by the isolated-worker watchdog."; failed_update_ids=$failedIds; reboot_required=$false } }
                if ($active.queue_path) { Remove-Item $active.queue_path -Force -ErrorAction SilentlyContinue }
            }
        } catch {}
        Remove-Item $ActiveInstallPath -Force -ErrorAction SilentlyContinue
    }
    exit 124
}
$proc.WaitForExit()
Log "Worker exited with code $($proc.ExitCode)."
exit $proc.ExitCode
