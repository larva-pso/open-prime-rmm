<#
.SYNOPSIS
  OpenPrime RMM agent - isolated Windows Update lab client.
  Runs as SYSTEM. Windows Update work is delegated to separately timed worker processes.

.DESCRIPTION
  1. Collects hostname, OS version, reboot-pending flag, and pending Windows Updates
     (Windows Update Agent COM API  -  no modules required).
  2. POSTs everything to the server; receives any queued jobs.
  3. Executes jobs sequentially:
       run_script        -  writes payload to a temp .ps1, runs it, captures output
       install_updates   -  downloads + installs the approved updates by UpdateID
  4. POSTs each job result back.

  Config lives at C:\ProgramData\OpenPrime\config.json  (created by the installer):
     { "ServerUrl": "https://rmm.example.com", "AgentId": "...", "AgentToken": "..." }
#>

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$AgentVersion = '1.13.7'
$LabBuild     = 'SAFE-REBOOT-1'
$DisableSelfUpdate = $false
$DataDir      = 'C:\ProgramData\OpenPrime'
# Staging area for downloads/temp scripts. Lives under DataDir (which the
# installer locks to SYSTEM+Administrators, and children inherit that), NOT
# C:\Windows\Temp - staging executables in Temp is classic malware behavior
# and is exactly what got the agent quarantined by Bitdefender ATC (1.11.1).
$StageDir     = Join-Path $DataDir 'staging'
if (-not (Test-Path $StageDir)) {
    New-Item -ItemType Directory -Path $StageDir -Force -ErrorAction SilentlyContinue | Out-Null
}
$ConfigPath   = Join-Path $DataDir 'config.json'
$LogPath      = Join-Path $DataDir 'agent.log'
$MaxOutput    = 100000   # chars of job output sent to server
$WuLabDir     = Join-Path $DataDir 'wu-lab'
$WuQueueDir   = Join-Path $WuLabDir 'install-queue'
$WuResultDir  = Join-Path $WuLabDir 'install-results'
foreach ($d in @($WuLabDir, $WuQueueDir, $WuResultDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force -ErrorAction SilentlyContinue | Out-Null }
}

function Write-Log([string]$Message) {
    $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    try {
        Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
        # keep log under ~2 MB
        if ((Get-Item $LogPath -ErrorAction SilentlyContinue).Length -gt 2MB) {
            Get-Content $LogPath -Tail 2000 | Set-Content $LogPath
        }
    } catch {}
}


function Read-JsonSafe([string]$Path, $Default) {
    if (-not (Test-Path $Path)) { return $Default }
    try { return (Get-Content $Path -Raw -ErrorAction Stop | ConvertFrom-Json) }
    catch { Write-Log "Invalid JSON at ${Path}: $($_.Exception.Message)"; return $Default }
}

function Write-JsonAtomic([string]$Path, $Value, [int]$Depth = 8) {
    try {
        $tmp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
        $json = $Value | ConvertTo-Json -Depth $Depth
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -Path $tmp -Destination $Path -Force
    } catch { Write-Log "Atomic JSON write failed for ${Path}: $($_.Exception.Message)" }
}

function Get-CachedPendingUpdates {
    $path = Join-Path $WuLabDir 'updates-cache.json'
    $cache = Read-JsonSafe $path $null
    if ($cache -and $cache.updates) { return ,@($cache.updates) }
    if ($cache -is [System.Array]) { return ,@($cache) }
    return ,@()
}

function Get-WuWorkerReport {
    $path = Join-Path $WuLabDir 'worker-report.json'
    $report = Read-JsonSafe $path $null
    if ($report) { return $report }
    return [pscustomobject]@{
        lab_build=$LabBuild; worker_status='awaiting-first-run'; mode='unknown';
        compliant=$false; checked_at=0; errors=@('Isolated Windows Update worker has not completed its first run.')
    }
}

function Save-WuDesiredState($Response) {
    try {
        $local = Read-JsonSafe (Join-Path $WuLabDir 'lab-settings.json') ([pscustomobject]@{ mode='observe' })
        $serverSpec = $Response.update_management
        $desiredPath = Join-Path $WuLabDir 'desired.json'
        $oldDesired = Read-JsonSafe $desiredPath $null
        $desired = @{
            received_at=[DateTimeOffset]::Now.ToUnixTimeSeconds()
            include_preview=[bool]$Response.include_preview
            denied_updates=@($Response.denied_updates)
            server_managed_requested=[bool]($serverSpec -and $serverSpec.managed)
            local_mode=[string]$local.mode
        }
        $oldComparable = if ($oldDesired) {
            @{ include_preview=[bool]$oldDesired.include_preview; denied_updates=@($oldDesired.denied_updates);
               server_managed_requested=[bool]$oldDesired.server_managed_requested; local_mode=[string]$oldDesired.local_mode } |
               ConvertTo-Json -Depth 8 -Compress
        } else { '' }
        $newComparable = @{ include_preview=$desired.include_preview; denied_updates=$desired.denied_updates;
                            server_managed_requested=$desired.server_managed_requested; local_mode=$desired.local_mode } |
                            ConvertTo-Json -Depth 8 -Compress
        Write-JsonAtomic $desiredPath $desired 8
        if ($oldComparable -ne $newComparable) {
            New-Item -ItemType File -Path (Join-Path $WuLabDir 'force-scan.flag') -Force | Out-Null
            Write-Log 'Windows Update desired state changed; requested immediate isolated scan.'
        }
    } catch { Write-Log "Unable to save Windows Update desired state: $($_.Exception.Message)" }
}

function Start-WuTask([string]$TaskName) {
    try {
        $out = & "$env:SystemRoot\System32\schtasks.exe" /Run /TN $TaskName 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Unable to start '$TaskName' (exit $LASTEXITCODE): $out"
            return $false
        }
        return $true
    } catch { Write-Log "Unable to start '$TaskName': $($_.Exception.Message)"; return $false }
}

function Start-WuScanIfDue {
    try {
        $force = Join-Path $WuLabDir 'force-scan.flag'
        $reportPath = Join-Path $WuLabDir 'worker-report.json'
        $due = $true
        if (Test-Path $reportPath) {
            $age = ((Get-Date) - (Get-Item $reportPath).LastWriteTime).TotalMinutes
            $due = ($age -ge 15)
        }
        if (Test-Path $force) { $due = $true; Remove-Item $force -Force -ErrorAction SilentlyContinue }
        if ($due) { [void](Start-WuTask 'OpenPrimeRMM WU Lab Scan') }
    } catch { Write-Log "WU scan scheduler check failed: $($_.Exception.Message)" }
}

function Start-WuInstallIfQueued {
    try {
        $queued = @(Get-ChildItem $WuQueueDir -Filter '*.json' -File -ErrorAction SilentlyContinue)
        if (-not $queued.Count) { return }
        $task = Get-ScheduledTask -TaskName 'OpenPrimeRMM WU Lab Install' -ErrorAction SilentlyContinue
        if ($task -and $task.State -ne 'Running') { [void](Start-WuTask 'OpenPrimeRMM WU Lab Install') }
    } catch { Write-Log "WU install queue scheduler check failed: $($_.Exception.Message)" }
}

function Queue-WuInstallJob($Job) {
    try {
        $path = Join-Path $WuQueueDir ("$($Job.id).json")
        if (-not (Test-Path $path)) {
            Write-JsonAtomic $path @{ job_id=[string]$Job.id; queued_at=[DateTimeOffset]::Now.ToUnixTimeSeconds(); payload=$Job.payload } 8
        }
        [void](Start-WuTask 'OpenPrimeRMM WU Lab Install')
        Write-Log "Queued update job $($Job.id) for isolated worker."
        return @{ deferred=$true }
    } catch {
        return @{ deferred=$false; ok=$false; exit_code=-1; output="Unable to queue isolated update job: $($_.Exception.Message)" }
    }
}

function Post-CompletedWuInstallJobs {
    foreach ($file in @(Get-ChildItem $WuResultDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
        try {
            $record = Read-JsonSafe $file.FullName $null
            if (-not $record -or -not $record.job_id -or -not $record.result) { continue }
            Invoke-Api -Method POST -Path "/api/agent/jobs/$($record.job_id)/result" -Body $record.result | Out-Null
            Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
            Write-Log "Posted isolated update result for job $($record.job_id)."
        } catch { Write-Log "Posting isolated update result failed for $($file.Name): $($_.Exception.Message)" }
    }
}

if (-not (Test-Path $ConfigPath)) {
    Write-Log "No config at $ConfigPath  -  agent not enrolled. Exiting."
    exit 1
}
$Config  = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$BaseUrl = $Config.ServerUrl.TrimEnd('/')
$Headers = @{ 'X-Agent-Id' = $Config.AgentId; 'X-Agent-Token' = $Config.AgentToken }

function Invoke-Api([string]$Method, [string]$Path, $Body) {
    $params = @{
        Method      = $Method
        Uri         = "$BaseUrl$Path"
        Headers     = $Headers
        ContentType = 'application/json; charset=utf-8'
        TimeoutSec  = 120
    }
    if ($null -ne $Body) {
        # PS 5.1 Invoke-RestMethod encodes STRING bodies as Latin-1, which breaks
        # the server's UTF-8 JSON parsing whenever output contains non-ASCII or
        # binary bytes. Encoding to UTF-8 bytes ourselves guarantees a valid body
        # (unencodable chars become '?', never invalid byte sequences).
        $json = $Body | ConvertTo-Json -Depth 6 -Compress
        $params.Body = [System.Text.Encoding]::UTF8.GetBytes($json)
    }
    return Invoke-RestMethod @params
}

# ---------------------------------------------------------------------------
# Inventory helpers
# ---------------------------------------------------------------------------

function Test-RebootRequired {
    # Core heartbeat path: registry-only and bounded. Never instantiate Windows
    # Update COM objects here; all WUA work belongs to the isolated worker.
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    )
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
    try {
        $sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($sm.PendingFileRenameOperations) { return $true }
    } catch {}
    return $false
}

function Ensure-PSWindowsUpdate {
    # Returns $true if the PSWindowsUpdate module is available for use.
    # Installs it from the PowerShell Gallery on first run if missing.
    if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
        return $true
    }
    try {
        Write-Log "PSWindowsUpdate not found - attempting install from PSGallery..."
        # NuGet provider + trust the gallery so Install-Module runs unattended as SYSTEM
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Get-PackageProvider -Name NuGet -ForceBootstrap -ErrorAction SilentlyContinue | Out-Null
        if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
            Register-PSRepository -Default -ErrorAction SilentlyContinue
        }
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers `
            -AllowClobber -ErrorAction Stop
        Import-Module PSWindowsUpdate -ErrorAction Stop
        Write-Log "PSWindowsUpdate installed successfully."
        return $true
    } catch {
        Write-Log "PSWindowsUpdate install failed: $($_.Exception.Message)"
        return $false
    }
}

function Get-DeniedKbs {
    # Denied KBs are cached locally from the previous check-in response so the
    # scan can hide them without a chicken-and-egg dependency on the server.
    $path = Join-Path $DataDir 'denied.json'
    if (Test-Path $path) {
        try { return @((Get-Content $path -Raw | ConvertFrom-Json)) } catch { return @() }
    }
    return @()
}

function Get-IncludePreview {
    $path = Join-Path $DataDir 'include_preview.flag'
    return (Test-Path $path)
}

function Get-PendingUpdates {
    # Uses PSWindowsUpdate (Microsoft Update service). Windows exposes the
    # optional "Download & install" channel as BrowseOnly updates, so when the
    # policy enables Preview / Optional updates we must run BOTH searches and
    # merge the results.
    $list = @()
    if (-not (Ensure-PSWindowsUpdate)) {
        Write-Log "Update scan skipped - PSWindowsUpdate unavailable."
        return ,$list
    }
    $deniedKbs = Get-DeniedKbs
    try {
        $includePreview = Get-IncludePreview
        if ($includePreview) {
            $standardUpdates = @(Get-WindowsUpdate -MicrosoftUpdate -IgnoreReboot -ErrorAction Stop)
            $optionalUpdates = @()
            try {
                $optionalUpdates = @(Get-WindowsUpdate -MicrosoftUpdate -BrowseOnly -IgnoreReboot -ErrorAction Stop)
            } catch {
                # Do not lose the normal scan merely because the optional channel
                # failed. Log it clearly so the dashboard diagnostic is useful.
                Write-Log "Optional/Preview update scan failed: $($_.Exception.Message)"
            }
            $updates = @($standardUpdates) + @($optionalUpdates)
            Write-Log "Update scan policy includes Preview/Optional: standard=$($standardUpdates.Count), optional=$($optionalUpdates.Count)."
        } else {
            # Preview updates offered as BrowseOnly are never queried here. The
            # title filter also excludes any Preview update returned normally.
            $updates = @(Get-WindowsUpdate -MicrosoftUpdate -IgnoreReboot -NotTitle 'Preview' -ErrorAction Stop)
        }

        # The same update can occasionally be returned by more than one search.
        # De-duplicate it before reporting to the server.
        $seen = @{}
        foreach ($u in $updates) {
            $kb = [string]$u.KB
            if ($kb -and $kb -notmatch '^KB') { $kb = "KB$kb" }
            $uid = if ($kb) { $kb } elseif ($u.Identity) { [string]$u.Identity.UpdateID } else { [string]$u.Title }
            if (-not $uid -or $seen.ContainsKey($uid)) { continue }
            $seen[$uid] = $true

            # Skip anything the server has denied.
            if ($deniedKbs -contains $uid -or ($kb -and $deniedKbs -contains $kb)) { continue }
            $sizeMb = 0
            if ($u.Size) {
                try { $sizeMb = [math]::Round(([double]$u.Size) / 1MB, 1) } catch { $sizeMb = 0 }
            }
            $list += @{
                update_id = $uid
                kb        = $kb
                title     = [string]$u.Title
                severity  = [string]$u.MsrcSeverity
                size_mb   = $sizeMb
            }
        }
    } catch {
        Write-Log "Update scan failed: $($_.Exception.Message)"
    }
    return ,$list
}

function Get-ScreenConnectInfo {
    # Best-effort discovery of the locally installed ScreenConnect / ConnectWise
    # Control Access client. The service ImagePath contains the session ID as
    # the "s" launch parameter. If discovery fails, the server keeps any
    # manually saved session ID rather than clearing it.
    $result = @{ session_id = ''; service_name = '' }
    try {
        $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
        $keys = @(Get-ChildItem $svcRoot -ErrorAction Stop | Where-Object {
            $_.PSChildName -like 'ScreenConnect Client (*' -or
            $_.PSChildName -like 'ConnectWise Control Client (*'
        })
        foreach ($key in $keys) {
            $imagePath = [string]$key.GetValue('ImagePath')
            if (-not $imagePath) { continue }
            $sid = ''
            if ($imagePath -match '(?:[?&]s=)([^&"\s]+)') {
                $sid = [uri]::UnescapeDataString([string]$Matches[1])
            }
            if ($sid -and $sid -match '^[0-9a-fA-F-]{36}$') {
                $result.session_id = $sid.ToLowerInvariant()
                $result.service_name = [string]$key.PSChildName
                break
            }
        }
    } catch {
        Write-Log "ScreenConnect discovery failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-HardwareInventory {
    $inv = @{ serial = ''; model = ''; cpu = ''; ram_gb = 0; memory_used_pct = $null; last_user = ''; local_ip = ''; disks = @(); macs = @(); screenconnect_session_id = ''; screenconnect_service_name = '' }
    try {
        $sc = Get-ScreenConnectInfo
        $inv.screenconnect_session_id = [string]$sc.session_id
        $inv.screenconnect_service_name = [string]$sc.service_name
    } catch {}
    try {
        $inv.macs = @(Get-NetAdapter -Physical -ErrorAction Stop |
                      Where-Object { $_.Status -eq 'Up' -and $_.MacAddress } |
                      ForEach-Object { $_.MacAddress -replace '-', ':' })
    } catch {
        try {
            $inv.macs = @(Get-CimInstance Win32_NetworkAdapter -Filter 'NetEnabled=true' |
                          Where-Object { $_.MACAddress } | ForEach-Object { $_.MACAddress })
        } catch {}
    }
    try {
        $cs   = Get-CimInstance Win32_ComputerSystem
        $bios = Get-CimInstance Win32_BIOS
        $cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
        $inv.serial    = [string]$bios.SerialNumber
        $inv.model     = ("{0} {1}" -f $cs.Manufacturer, $cs.Model).Trim()
        $inv.cpu       = [string]$cpu.Name
        $inv.ram_gb    = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        $inv.last_user = [string]$cs.UserName
        # Primary local IPv4: the address on the interface with the default route
        try {
            $ip = Get-NetIPConfiguration -ErrorAction Stop |
                  Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
                  Select-Object -First 1 -ExpandProperty IPv4Address |
                  Select-Object -First 1 -ExpandProperty IPAddress
            if ($ip) { $inv.local_ip = [string]$ip }
        } catch {
            # Fallback for older systems without Get-NetIPConfiguration
            try {
                $inv.local_ip = (Get-CimInstance Win32_NetworkAdapterConfiguration |
                    Where-Object { $_.IPEnabled -and $_.DefaultIPGateway } |
                    Select-Object -First 1 -ExpandProperty IPAddress |
                    Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } |
                    Select-Object -First 1)
            } catch {}
        }
        $disks = @()
        foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3")) {
            $disks += @{
                letter   = $d.DeviceID
                total_gb = [math]::Round($d.Size / 1GB, 1)
                free_gb  = [math]::Round($d.FreeSpace / 1GB, 1)
            }
        }
        $inv.disks = $disks
        # Physical disk health: HealthStatus from the Storage subsystem plus
        # SMART predictive-failure - the early warning before a drive dies.
        $dh = @()
        try {
            $smartFail = 0
            try {
                $smartFail = @(Get-CimInstance -Namespace root\wmi MSStorageDriver_FailurePredictStatus -ErrorAction Stop |
                               Where-Object { $_.PredictFailure }).Count
            } catch {}
            foreach ($pd in (Get-PhysicalDisk -ErrorAction Stop)) {
                $dh += @{
                    name    = [string]$pd.FriendlyName
                    media   = [string]$pd.MediaType
                    size_gb = [math]::Round($pd.Size / 1GB, 1)
                    health  = [string]$pd.HealthStatus
                }
            }
            $inv.smart_failures = $smartFail
        } catch {}
        $inv.disk_health = $dh
        # Recent disk error events (bad blocks / IO failures / NTFS corruption)
        # from the System event log - IDs 7/51/153 (disk) and 55 (Ntfs).
        try {
            $errs = @(Get-WinEvent -FilterHashtable @{
                          LogName = 'System'; Id = @(7, 51, 153, 55)
                          StartTime = (Get-Date).AddHours(-24)
                      } -MaxEvents 50 -ErrorAction Stop |
                      Where-Object { $_.ProviderName -in @('disk', 'Disk', 'Ntfs', 'volmgr', 'iaStorA', 'iaStorAC', 'storahci', 'stornvme') })
            if ($errs.Count -gt 0) {
                $last = $errs[0]
                $msg = [string]$last.Message
                if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
                $inv.disk_events = @{
                    count     = $errs.Count
                    last      = ($msg -replace "[\r\n]+", ' ')
                    last_time = $last.TimeCreated.ToString('yyyy-MM-dd HH:mm')
                }
            }
        } catch {}   # 'no events found' throws - that just means the disks are clean

        # Installed software (both registry hives, 64- and 32-bit).
        try {
            $paths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
            $seen = @{}
            $sw = @()
            foreach ($pp in $paths) {
                foreach ($k in (Get-ItemProperty $pp -ErrorAction SilentlyContinue)) {
                    $n = $k.DisplayName
                    if (-not $n -or $k.SystemComponent -eq 1 -or $k.ParentKeyName) { continue }
                    $key = "$n|$($k.DisplayVersion)"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true
                    $sw += @{ name = [string]$n; version = [string]$k.DisplayVersion
                              publisher = [string]$k.Publisher }
                }
            }
            $inv.software = $sw
        } catch {}


        # ---- Extended inventory (1.13.2) -------------------------------
        # Every collector is independently guarded: a failure on one machine
        # (missing cmdlet, disabled service, older Windows) must never cost
        # the rest of the inventory or the check-in.
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $inv.last_boot = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
            $inv.uptime_hours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
            $inv.os_install_date = $os.InstallDate.ToString('yyyy-MM-dd')
            $inv.os_arch = [string]$os.OSArchitecture
            $totalKb = [double]$os.TotalVisibleMemorySize
            $freeKb = [double]$os.FreePhysicalMemory
            if ($totalKb -gt 0 -and $freeKb -ge 0) {
                $usedPct = (($totalKb - $freeKb) / $totalKb) * 100
                $inv.memory_used_pct = [math]::Round([math]::Max(0, [math]::Min(100, $usedPct)), 1)
            }
        } catch {}
        try {
            $cs2 = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            $inv.domain = [string]$cs2.Domain
            $inv.domain_joined = [bool]$cs2.PartOfDomain
        } catch {}
        try {
            $bios2 = Get-CimInstance Win32_BIOS -ErrorAction Stop
            $inv.bios_version = [string]$bios2.SMBIOSBIOSVersion
            if ($bios2.ReleaseDate) { $inv.bios_date = $bios2.ReleaseDate.ToString('yyyy-MM-dd') }
        } catch {}
        try { $inv.timezone = [string](Get-TimeZone -ErrorAction Stop).Id } catch {}
        try {
            $bl = @()
            foreach ($v in (Get-BitLockerVolume -ErrorAction Stop)) {
                $bl += @{ mount = [string]$v.MountPoint
                          status = [string]$v.ProtectionStatus
                          method = [string]$v.EncryptionMethod
                          percent = [int]$v.EncryptionPercentage }
            }
            $inv.bitlocker = $bl
        } catch {}
        try {
            $fw = @()
            foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
                $fw += @{ profile = [string]$p.Name; enabled = [bool]$p.Enabled }
            }
            $inv.firewall = $fw
        } catch {}
        try {
            $ad = @()
            foreach ($n in (Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })) {
                $cfg = $null
                try { $cfg = Get-NetIPConfiguration -InterfaceIndex $n.ifIndex -ErrorAction Stop } catch {}
                $v4 = ''
                $gw = ''
                $dhcp = ''
                if ($cfg) {
                    try { $v4 = [string]($cfg.IPv4Address | Select-Object -First 1 -ExpandProperty IPAddress) } catch {}
                    try { $gw = [string]($cfg.IPv4DefaultGateway | Select-Object -First 1 -ExpandProperty NextHop) } catch {}
                }
                try { $dhcp = [string](Get-NetIPInterface -InterfaceIndex $n.ifIndex -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Dhcp) } catch {}
                $ad += @{ name = [string]$n.Name
                          description = [string]$n.InterfaceDescription
                          mac = [string]$n.MacAddress
                          speed_mbps = [math]::Round($n.LinkSpeed / 1000000, 0)
                          ipv4 = $v4; gateway = $gw; dhcp = $dhcp }
            }
            $inv.adapters = $ad
        } catch {}
        try {
            $hf = @()
            foreach ($h in (Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 40)) {
                $when = ''
                if ($h.InstalledOn) { $when = $h.InstalledOn.ToString('yyyy-MM-dd') }
                $hf += @{ kb = [string]$h.HotFixID; type = [string]$h.Description; installed = $when }
            }
            $inv.hotfixes = $hf
        } catch {}
        try {
            $la = @()
            foreach ($m in (Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)) {
                $la += [string]$m.Name
            }
            $inv.local_admins = @($la | Select-Object -First 20)
        } catch {}

        try {
            # Backup engine status (Macrium / Veeam) from Windows event logs.
            # Event queries are comparatively heavy, so results are cached and
            # refreshed at most every 30 minutes; the cached copy is reported
            # on the in-between check-ins.
            $bkCache = Join-Path $WuLabDir '..\backup-status.json'
            $bkFresh = $false
            if (Test-Path $bkCache) {
                try {
                    $cached = Get-Content $bkCache -Raw | ConvertFrom-Json
                    if ($cached.collected_at -and ((Get-Date) - [datetime]$cached.collected_at).TotalMinutes -lt 30) {
                        $inv.backup = @($cached.products)
                        $bkFresh = $true
                    }
                } catch {}
            }
            if (-not $bkFresh) {
                $bkSince = (Get-Date).AddDays(-14)
                $bkEvents = @()
                try {
                    $bkEvents += @(Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$bkSince} -MaxEvents 4000 -ErrorAction Stop |
                        Where-Object { $_.ProviderName -match 'Macrium|Veeam' })
                } catch {}
                foreach ($bkLog in @('Macrium Reflect','Veeam Agent','Veeam Endpoint Backup')) {
                    try { $bkEvents += @(Get-WinEvent -FilterHashtable @{LogName=$bkLog; StartTime=$bkSince} -MaxEvents 1000 -ErrorAction Stop) } catch {}
                }
                $bkProducts = @()
                foreach ($bkName in @('Macrium','Veeam')) {
                    $pe = @($bkEvents | Where-Object { ($_.ProviderName -match $bkName) -or ($_.LogName -match $bkName) })
                    if ($pe.Count -eq 0) { continue }
                    $succ = @($pe | Where-Object { $_.Level -eq 4 -and $_.Message -match 'success|completed' } | Sort-Object TimeCreated -Descending)
                    $fail = @($pe | Where-Object { ($_.Level -eq 2) -or ($_.Level -eq 3 -and $_.Message -match 'fail|error|abort') } | Sort-Object TimeCreated -Descending)
                    $entry = @{ product = $bkName }
                    if ($succ.Count -gt 0) { $entry.last_success = $succ[0].TimeCreated.ToString('yyyy-MM-dd HH:mm') }
                    if ($fail.Count -gt 0) {
                        $entry.last_failure = $fail[0].TimeCreated.ToString('yyyy-MM-dd HH:mm')
                        $note = [string]($fail[0].Message -split "`n")[0].Trim()
                        if ($note.Length -gt 160) { $note = $note.Substring(0,160) }
                        $entry.failure_note = $note
                    }
                    $bkProducts += $entry
                }
                $inv.backup = $bkProducts
                try {
                    @{ collected_at = (Get-Date).ToString('o'); products = $bkProducts } |
                        ConvertTo-Json -Depth 4 | Set-Content -Path $bkCache -Encoding UTF8
                } catch {}
            }
        } catch {}

        # Attach isolated Windows Update worker verification. The worker can
        # time out or fail without blocking the core RMM check-in path.
        try { $inv.windows_update_management = Get-WuWorkerReport } catch {}

        # Attach last cycle's service-monitor results (written after the previous check-in)
        try {
            $mrPath = Join-Path $DataDir 'monitor_report.json'
            if (Test-Path $mrPath) {
                $inv.service_monitor_report = (Get-Content $mrPath -Raw | ConvertFrom-Json)
            }
        } catch {}
    } catch {
        Write-Log "Inventory collection failed: $($_.Exception.Message)"
    }
    return $inv
}

# ---------------------------------------------------------------------------
# Job handlers
# ---------------------------------------------------------------------------

# NinjaOne-style power safety: enumerate real Windows Terminal Services user
# sessions instead of relying on explorer.exe, Win32_ComputerSystem.UserName,
# or localized quser.exe text. Active *and disconnected* interactive sessions
# count as logged in. Detection errors fail closed and suppress power actions.
$SessionGuardSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace OpenPrimeRMMSessionGuard {
    public static class NativeSessionGuard {
        private enum WTS_CONNECTSTATE_CLASS {
            WTSActive, WTSConnected, WTSConnectQuery, WTSShadow,
            WTSDisconnected, WTSIdle, WTSListen, WTSReset, WTSDown, WTSInit
        }
        private enum WTS_INFO_CLASS { WTSInitialProgram, WTSApplicationName, WTSWorkingDirectory,
            WTSOEMId, WTSSessionId, WTSUserName, WTSWinStationName, WTSDomainName }
        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO {
            public int SessionID;
            public IntPtr pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }
        [DllImport("wtsapi32.dll", SetLastError=true)]
        private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version,
            out IntPtr sessions, out int count);
        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr memory);
        [DllImport("wtsapi32.dll", SetLastError=true)]
        private static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId,
            WTS_INFO_CLASS infoClass, out IntPtr buffer, out int bytesReturned);

        private static string QueryString(int sessionId, WTS_INFO_CLASS infoClass) {
            IntPtr buffer = IntPtr.Zero;
            int bytes = 0;
            try {
                if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out buffer, out bytes))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return buffer == IntPtr.Zero ? "" : (Marshal.PtrToStringUni(buffer) ?? "");
            } finally {
                if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
            }
        }

        public static bool HasInteractiveUser() {
            IntPtr sessions = IntPtr.Zero;
            int count = 0;
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out sessions, out count))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                for (int i = 0; i < count; i++) {
                    IntPtr current = new IntPtr(sessions.ToInt64() + (long)i * size);
                    WTS_SESSION_INFO info = (WTS_SESSION_INFO)Marshal.PtrToStructure(current, typeof(WTS_SESSION_INFO));
                    if (info.State == WTS_CONNECTSTATE_CLASS.WTSListen ||
                        info.State == WTS_CONNECTSTATE_CLASS.WTSDown ||
                        info.State == WTS_CONNECTSTATE_CLASS.WTSInit) continue;
                    string user = QueryString(info.SessionID, WTS_INFO_CLASS.WTSUserName).Trim();
                    if (!String.IsNullOrEmpty(user)) return true;
                }
                return false;
            } finally {
                if (sessions != IntPtr.Zero) WTSFreeMemory(sessions);
            }
        }
    }
}
'@

function Test-InteractiveUserLoggedOn {
    try {
        if (-not ('OpenPrimeRMMSessionGuard.NativeSessionGuard' -as [type])) {
            Add-Type -TypeDefinition $SessionGuardSource -Language CSharp -ErrorAction Stop
        }
        return [OpenPrimeRMMSessionGuard.NativeSessionGuard]::HasInteractiveUser()
    } catch {
        Write-Log "Interactive-session detection failed closed: $($_.Exception.Message)"
        return $true
    }
}

function Test-ScriptMayReboot($Payload) {
    $impact = [string]$Payload.reboot_impact
    if ($impact -in @('possible','yes')) { return $true }
    $content = [string]$Payload.content
    if (-not $content) { return $false }
    return [bool]($content -match '(?im)\bRestart-Computer\b|\bshutdown(?:\.exe)?\s+(?:/r|-r)\b|\bWin32Shutdown\b|\bExitWindowsEx\b')
}

function Invoke-ScriptJob($Payload) {
    $timeout = 900
    if ($Payload.timeout_sec) { $timeout = [int]$Payload.timeout_sec }

    $tmpBase = Join-Path $StageDir ("job_" + [guid]::NewGuid().ToString('N'))
    $outFile = "$tmpBase.out"
    $errFile = "$tmpBase.err"
    $envVarsSet = @()

    # Shell selection: 'powershell' (default), 'cmd', or 'bash'. Existing script
    # jobs have no shell field, so they default to PowerShell unchanged.
    $shell = 'powershell'
    if ($Payload.shell) { $shell = [string]$Payload.shell }
    switch ($shell) {
        'cmd'  { $scriptFile = "$tmpBase.bat" }
        'bash' { $scriptFile = "$tmpBase.sh" }
        default { $scriptFile = "$tmpBase.ps1" }
    }

    try {
        # Write BOM-less UTF-8. Set-Content -Encoding UTF8 in Windows PowerShell
        # 5.1 prepends a UTF-8 BOM (EF BB BF); cmd.exe and bash then try to run
        # those bytes as part of the first command ("'ï»¿ipconfig' is not
        # recognized"). .NET's UTF8Encoding($false) writes no BOM. Normalize to
        # CRLF for cmd/ps and LF for bash so line endings don't bite either.
        $content = [string]$Payload.content
        if ($shell -eq 'bash') {
            $content = $content -replace "`r`n", "`n"
        } elseif ($content -notmatch "`r`n") {
            $content = $content -replace "`n", "`r`n"
        }
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($scriptFile, $content, $utf8NoBom)

        # Script variables: the server sends { env = { calculatedName = value } }.
        # Set each one in this process so the child inherits them -
        # identical to NinjaOne, so scripts reading $env:someCalculatedName work
        # unchanged (empty optional variables arrive as the literal string "null").
        if ($Payload.env) {
            foreach ($prop in $Payload.env.PSObject.Properties) {
                if ($prop.Name -match '^[A-Za-z_][A-Za-z0-9_]*$') {
                    [Environment]::SetEnvironmentVariable($prop.Name, [string]$prop.Value, 'Process')
                    $envVarsSet += $prop.Name
                }
            }
        }

        switch ($shell) {
            'cmd' {
                $exe = "$env:SystemRoot\System32\cmd.exe"
                $args = @('/c', "`"$scriptFile`"")
            }
            'bash' {
                $bash = (Get-Command bash.exe -ErrorAction SilentlyContinue).Source
                if (-not $bash) { $bash = "$env:SystemRoot\System32\bash.exe" }
                if (-not (Test-Path $bash)) {
                    return @{ ok = $false; exit_code = -1
                              output = 'bash is not available on this machine (install WSL or Git Bash).' }
                }
                $exe = $bash
                $args = @("`"$scriptFile`"")
            }
            default {
                $exe = 'powershell.exe'
                $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$scriptFile`"")
            }
        }

        $proc = Start-Process -FilePath $exe -ArgumentList $args `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile `
            -WindowStyle Hidden -PassThru

        # Cache the process handle IMMEDIATELY. Without this, .NET frequently
        # fails to populate .ExitCode after the child exits (returns $null),
        # which made successful runs report as failed.
        $null = $proc.Handle

        $finished = $proc.WaitForExit($timeout * 1000)
        if (-not $finished) {
            try { $proc.Kill() } catch {}
            Start-Sleep -Seconds 1
            $partial = ''
            if (Test-Path $outFile) { $partial = [string](Get-Content $outFile -Raw) }
            return @{ ok = $false; exit_code = -1
                      output = "TIMED OUT after $timeout seconds.`n--- partial output ---`n$partial" }
        }
        $proc.WaitForExit()   # no-arg overload: guarantees exit code + redirected output are final

        $out = ''; $err = ''
        if (Test-Path $outFile) { $out = [string](Get-Content $outFile -Raw) }
        if (Test-Path $errFile) { $err = [string](Get-Content $errFile -Raw) }
        $combined = $out
        if ($err) { $combined += "`n--- stderr ---`n$err" }
        if ($combined.Length -gt $MaxOutput) {
            $combined = $combined.Substring(0, $MaxOutput) + "`n...[truncated]"
        }
        $code = $proc.ExitCode
        if ($null -eq $code) { $code = 0 }   # process exited cleanly but .NET lost the code
        return @{ ok = ($code -eq 0); exit_code = $code; output = $combined }
    }
    catch {
        return @{ ok = $false; exit_code = -1; output = "Agent error: $($_.Exception.Message)" }
    }
    finally {
        foreach ($k in $envVarsSet) {
            [Environment]::SetEnvironmentVariable($k, $null, 'Process')
        }
        Remove-Item $scriptFile, $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-InstallUpdatesJob($Payload) {
    $wanted = @($Payload.update_ids)
    $lines  = New-Object System.Collections.Generic.List[string]
    $failed = @()

    if (-not (Ensure-PSWindowsUpdate)) {
        return @{ ok = $false; exit_code = -1; failed_update_ids = $wanted
                  reboot_required = (Test-RebootRequired)
                  output = 'PSWindowsUpdate module unavailable - cannot install updates.' }
    }

    try {
        # Re-scan so we act on the current list, then match the ones the server
        # approved. Optional/Preview updates require a BrowseOnly search and
        # must retain that marker for the installation call.
        $available = @()
        $standardUpdates = @(Get-WindowsUpdate -MicrosoftUpdate -IgnoreReboot -ErrorAction Stop)
        foreach ($u in $standardUpdates) {
            $available += [pscustomobject]@{ Update = $u; BrowseOnly = $false }
        }
        if (Get-IncludePreview) {
            try {
                $optionalUpdates = @(Get-WindowsUpdate -MicrosoftUpdate -BrowseOnly -IgnoreReboot -ErrorAction Stop)
                foreach ($u in $optionalUpdates) {
                    $available += [pscustomobject]@{ Update = $u; BrowseOnly = $true }
                }
            } catch {
                Write-Log "Optional/Preview install re-scan failed: $($_.Exception.Message)"
            }
        }

        $toInstall = @()
        $seenInstall = @{}
        foreach ($entry in $available) {
            $u = $entry.Update
            $kb  = [string]$u.KB
            if ($kb -and $kb -notmatch '^KB') { $kb = "KB$kb" }
            $uid = if ($kb) { $kb } elseif ($u.Identity) { [string]$u.Identity.UpdateID } else { [string]$u.Title }
            if ($wanted -contains $uid -and -not $seenInstall.ContainsKey($uid)) {
                $seenInstall[$uid] = $true
                $toInstall += $entry
            }
        }

        if ($toInstall.Count -eq 0) {
            return @{ ok = $true; exit_code = 0; reboot_required = (Test-RebootRequired)
                      output = 'No matching updates still pending (already installed or superseded).'
                      failed_update_ids = @() }
        }

        $lines.Add("Installing $($toInstall.Count) update(s) via PSWindowsUpdate...")
        # Install by KB where possible. BrowseOnly must be specified for the
        # optional "Download & install" channel or the cmdlet will not select it.
        foreach ($entry in $toInstall) {
            $u = $entry.Update
            $isBrowseOnly = [bool]$entry.BrowseOnly
            $kb = [string]$u.KB
            if ($kb -and $kb -notmatch '^KB') { $kb = "KB$kb" }
            try {
                if ($kb) {
                    if ($isBrowseOnly) {
                        $res = Install-WindowsUpdate -MicrosoftUpdate -KBArticleID $kb -BrowseOnly `
                            -AcceptAll -IgnoreReboot -Confirm:$false -ErrorAction Stop
                    } else {
                        $res = Install-WindowsUpdate -MicrosoftUpdate -KBArticleID $kb `
                            -AcceptAll -IgnoreReboot -Confirm:$false -ErrorAction Stop
                    }
                } else {
                    if ($isBrowseOnly) {
                        $res = Install-WindowsUpdate -MicrosoftUpdate -Title $u.Title -BrowseOnly `
                            -AcceptAll -IgnoreReboot -Confirm:$false -ErrorAction Stop
                    } else {
                        $res = Install-WindowsUpdate -MicrosoftUpdate -Title $u.Title `
                            -AcceptAll -IgnoreReboot -Confirm:$false -ErrorAction Stop
                    }
                }
                # Inspect result rows for this KB; PSWindowsUpdate sets Result = Installed/Failed
                $rowOk = $true
                foreach ($row in @($res)) {
                    if ($row.Result -and $row.Result -notmatch 'Install') { $rowOk = $false }
                }
                if ($rowOk) {
                    $lines.Add("[OK]   $($u.Title)")
                } else {
                    $lines.Add("[FAIL] $($u.Title)")
                    $uidFail = if ($kb) { $kb } else { [string]$u.Title }
                    $failed += $uidFail
                }
            } catch {
                $lines.Add("[FAIL] $($u.Title) - $($_.Exception.Message)")
                $uidFail = if ($kb) { $kb } else { [string]$u.Title }
                $failed += $uidFail
            }
        }

        $reboot = Test-RebootRequired
        if ($reboot) { $lines.Add('A reboot is required to finish installation.') }

        return @{
            ok                = ($failed.Count -eq 0)
            exit_code         = $failed.Count
            output            = ($lines -join "`n")
            reboot_required   = $reboot
            failed_update_ids = $failed
        }
    }
    catch {
        return @{ ok = $false; exit_code = -1; failed_update_ids = $wanted
                  reboot_required = (Test-RebootRequired)
                  output = ($lines -join "`n") + "`nAgent error: $($_.Exception.Message)" }
    }
}

function Invoke-WakeJob($Payload) {
    # Broadcast a Wake-on-LAN magic packet for each target MAC. This agent acts
    # as the "sender" on its local network to wake sleeping neighbors at the
    # same site (the server cannot reach a client LAN directly).
    $targets = @($Payload.macs)
    if (-not $targets -or $targets.Count -eq 0) {
        return @{ ok = $false; exit_code = 1; output = 'No target MAC addresses provided.' }
    }
    $sent = 0
    $log = New-Object System.Collections.Generic.List[string]
    foreach ($mac in $targets) {
        try {
            $clean = ($mac -replace '[^0-9A-Fa-f]', '')
            if ($clean.Length -ne 12) { $log.Add("Skipped invalid MAC: $mac"); continue }
            $bytes = for ($i = 0; $i -lt 12; $i += 2) { [Convert]::ToByte($clean.Substring($i, 2), 16) }
            # Magic packet = 6x 0xFF followed by the MAC repeated 16 times
            $packet = New-Object byte[] 102
            for ($i = 0; $i -lt 6; $i++) { $packet[$i] = 0xFF }
            for ($i = 6; $i -lt 102; $i += 6) { [Array]::Copy($bytes, 0, $packet, $i, 6) }
            $udp = New-Object System.Net.Sockets.UdpClient
            $udp.EnableBroadcast = $true
            # Send to the subnet broadcast on the common WoL ports
            foreach ($port in @(9, 7)) {
                $udp.Send($packet, $packet.Length, (New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Broadcast, $port))) | Out-Null
            }
            $udp.Close()
            $sent++
            $log.Add("Sent magic packet to $mac")
        } catch {
            $log.Add("Failed for ${mac}: $($_.Exception.Message)")
        }
    }
    return @{ ok = ($sent -gt 0); exit_code = if ($sent -gt 0) { 0 } else { 1 }
              output = ($log -join "`n") }
}

function Invoke-SelfRemovalJob($payload) {
    # Server-ordered FULL removal of OpenPrimeRMM from this computer.
    # The job is acknowledged immediately; the removal itself runs DETACHED
    # about two minutes later (one-shot SYSTEM task) so this process can
    # finish posting the result before the agent is deleted. Handles both
    # MSI installs (authorized msiexec /x with the supplied token; the MSI
    # cleanup restores Windows Update and unhides tracked updates) and
    # script installs (task + folder cleanup with a basic policy restore).
    try {
        $token = [string]$payload.uninstall_token
        if (-not $token) { return @{ ok = $false; exit_code = -1; output = 'No uninstall token supplied.' } }
        $cmdPath = Join-Path $env:SystemRoot 'Temp\pnc-self-remove.cmd'
        $lines = @(
            '@echo off',
            'setlocal EnableExtensions',
            ('set "T=' + $token + '"'),
            'set "LOG=%SystemRoot%\Temp\pnc-remove.log"',
            'echo [%date% %time%] OpenPrimeRMM self-removal started >> "%LOG%"',
            'set "PC="',
            'for /f "delims=" %%K in (''reg.exe query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "OpenPrimeRMM Agent" /d 2^>nul ^| findstr /I /R "^HKEY_.*Uninstall.*{"'') do set "PC=%%~nxK"',
            'if defined PC (',
            '    echo [%date% %time%] MSI product %PC% - authorized uninstall >> "%LOG%"',
            '    msiexec.exe /x %PC% UNINSTALLTOKEN=%T% PURGECONFIG=1 /qn /norestart /l*v "%SystemRoot%\Temp\pnc-remove-msi.log"',
            ') else (',
            '    echo [%date% %time%] No MSI product registered - script-install cleanup >> "%LOG%"',
            ')',
            'for %%N in ("OpenPrime RMM Agent" "OpenPrime Tray" "OpenPrimeRMM WU Lab Scan" "OpenPrimeRMM WU Lab Install") do (',
            '    schtasks.exe /End /TN %%N >nul 2>&1',
            '    schtasks.exe /Delete /TN %%N /F >nul 2>&1',
            ')',
            'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "foreach($p in @(,@(''HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'',''NoAutoUpdate''),@(''HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'',''AUOptions''),@(''HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'',''SetDisableUXWUAccess''),@(''HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'',''SetDisablePauseUXAccess'')){ if(Test-Path $p[0]){ Remove-ItemProperty -Path $p[0] -Name $p[1] -ErrorAction SilentlyContinue } }" >> "%LOG%" 2>&1',
            'rmdir /s /q "%ProgramFiles%\OpenPrime" >nul 2>&1',
            'rmdir /s /q "%ProgramData%\OpenPrime" >nul 2>&1',
            'schtasks.exe /Delete /TN "OpenPrimeRMM SelfRemove" /F >nul 2>&1',
            'echo [%date% %time%] OpenPrimeRMM self-removal finished >> "%LOG%"',
            'del /f /q "%~f0" >nul 2>&1',
            'exit /b 0'
        )
        Set-Content -Path $cmdPath -Value ($lines -join "`r`n") -Encoding Ascii -Force
        $runAt = (Get-Date).AddMinutes(2)
        $taskArgs = @('/Create','/TN','OpenPrimeRMM SelfRemove','/SC','ONCE',
                      '/SD', $runAt.ToString('MM/dd/yyyy'), '/ST', $runAt.ToString('HH:mm'),
                      '/TR', ('"' + $env:SystemRoot + '\System32\cmd.exe" /d /c "' + $cmdPath + '"'),
                      '/RU','SYSTEM','/RL','HIGHEST','/F')
        $taskOut = & "$env:SystemRoot\System32\schtasks.exe" $taskArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            return @{ ok = $false; exit_code = $LASTEXITCODE; output = "Could not schedule removal: $taskOut" }
        }
        Write-Log "Full self-removal ordered by the server; executing in about two minutes."
        return @{ ok = $true; exit_code = 0
                  output = 'Removal scheduled: MSI/script uninstall, all OpenPrimeRMM tasks removed, Windows Update policy restored, folders deleted. This device will stop reporting.' }
    } catch {
        return @{ ok = $false; exit_code = -1; output = "Self-removal error: $($_.Exception.Message)" }
    }
}

function Invoke-RebootJob($Payload) {
    # Managed reboot/shutdown actions expire; only explicit force_reboot on a
    # reboot (never shutdown) bypasses the logged-in user guard:
    #   * stale/legacy payloads are suppressed;
    #   * by default any active OR disconnected session suppresses the action;
    #   * a detached bounded worker waits out the requested delay, then checks
    #     the session again unless the reboot was explicitly forced;
    #     and only then invokes shutdown.exe with no additional countdown.
    # This mirrors NinjaOne's "Logged in user: Do nothing" behavior and keeps a
    # delayed action from firing after somebody signs in during the countdown.
    $delay = 60
    if ($null -ne $Payload.delay_sec) { $delay = [int]$Payload.delay_sec }
    $delay = [Math]::Max(0, [Math]::Min(3600, $delay))
    $mode = 'reboot'
    if ($Payload.mode) { $mode = [string]$Payload.mode }
    $isShutdown = ($mode -eq 'shutdown')
    $forceReboot = ($Payload.force_reboot -is [bool]) -and ($Payload.force_reboot -eq $true)
    if ($isShutdown) { $forceReboot = $false }
    $flag = if ($isShutdown) { '/s' } else { '/r' }
    $word = if ($isShutdown) { 'Shutdown' } else { 'Reboot' }
    $msg = "OpenPrime-RMM: scheduled maintenance $($word.ToLower())"
    if ($Payload.message) { $msg = [string]$Payload.message }

    if ($Payload.suppress_if_user_logged_in -ne $true) {
        return @{ ok = $true; exit_code = 0
                  output = "$word suppressed because the job did not contain the mandatory logged-in-user safety policy." }
    }

    $expiresAt = 0L
    try { $expiresAt = [int64]$Payload.expires_at } catch { $expiresAt = 0L }
    $nowUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($expiresAt -le $nowUnix) {
        return @{ ok = $true; exit_code = 0
                  output = "$word suppressed because the maintenance window expired before endpoint execution." }
    }
    if ((-not $forceReboot) -and (Test-InteractiveUserLoggedOn)) {
        return @{ ok = $true; exit_code = 0
                  output = "$word suppressed because an interactive user is logged in (active or disconnected session)." }
    }

    try {
        $workerPath = Join-Path $StageDir ("safe_power_" + [guid]::NewGuid().ToString('N') + '.ps1')
        $unicode = [System.Text.Encoding]::Unicode
        $guardB64 = if ($forceReboot) { '' } else { [Convert]::ToBase64String($unicode.GetBytes($SessionGuardSource)) }
        $messageB64 = [Convert]::ToBase64String($unicode.GetBytes($msg))
        $logB64 = [Convert]::ToBase64String($unicode.GetBytes($LogPath))
        $forceLiteral = if ($forceReboot) { '$true' } else { '$false' }
        $worker = @"
`$ErrorActionPreference = 'Stop'
`$forceReboot = $forceLiteral
`$guard = if (`$forceReboot) { '' } else { [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$guardB64')) }
`$message = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$messageB64'))
`$log = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$logB64'))
function Write-SafePowerLog([string]`$text) {
    try { Add-Content -LiteralPath `$log -Value ("{0} [safe-power] {1}" -f (Get-Date -Format s), `$text) -Encoding UTF8 } catch {}
}
try {
    Start-Sleep -Seconds $delay
    if ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge $expiresAt) {
        Write-SafePowerLog '$word suppressed: maintenance window expired during delay.'
        exit 0
    }
    if (-not `$forceReboot) {
        Add-Type -TypeDefinition `$guard -Language CSharp -ErrorAction Stop
        if ([OpenPrimeRMMSessionGuard.NativeSessionGuard]::HasInteractiveUser()) {
            Write-SafePowerLog '$word suppressed: interactive user logged in during delay.'
            exit 0
        }
    }
    `$shutdownArgs = @('$flag','/t','0','/c',("`"" + `$message + "`""))
    if (`$forceReboot) { `$shutdownArgs += '/f' }
    Write-SafePowerLog ('$word executing: force override=' + `$forceReboot)
    Start-Process -FilePath 'shutdown.exe' -ArgumentList `$shutdownArgs -WindowStyle Hidden
} catch {
    Write-SafePowerLog ("$word failed closed: " + `$_.Exception.Message)
} finally {
    Remove-Item -LiteralPath `$PSCommandPath -Force -ErrorAction SilentlyContinue
}
"@
        [System.IO.File]::WriteAllText($workerPath, $worker, (New-Object System.Text.UTF8Encoding($false)))
        Start-Process -FilePath 'powershell.exe' `
            -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"`"$workerPath`"") `
            -WindowStyle Hidden | Out-Null
        return @{ ok = $true; exit_code = 0
                  output = "$word worker armed for $delay seconds; force reboot=$forceReboot. Execution is confirmed only after the device checks in following a new boot." }
    } catch {
        return @{ ok = $false; exit_code = -1; output = "$word failed: $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# Run a list of jobs handed back by check-in or the live poll, posting each
# result with retries. Shared by interval mode and live (long-poll) mode.
# ---------------------------------------------------------------------------
function Invoke-JobList($jobs) {
    foreach ($job in $jobs) {
        Write-Log "Running job $($job.id) [$($job.type)]"
        $deferred = $false
        try {
            switch ($job.type) {
                'run_script'      {
                    if ((Test-ScriptMayReboot $job.payload) -and (Test-InteractiveUserLoggedOn)) {
                        $result = @{ ok = $true; exit_code = 0
                                     output = 'Automation/script suppressed because it can reboot and an interactive user is logged in.' }
                    } else {
                        $result = Invoke-ScriptJob $job.payload
                    }
                }
                'wake'            { $result = Invoke-WakeJob        $job.payload }
                'install_updates' {
                    $result = Queue-WuInstallJob $job
                    $deferred = [bool]$result.deferred
                }
                'reboot'          { $result = Invoke-RebootJob       $job.payload }
                'uninstall_agent' { $result = Invoke-SelfRemovalJob $job.payload }
                default           { $result = @{ ok = $false; exit_code = -1; output = "Unknown job type '$($job.type)'" } }
            }
        } catch {
            # Belt and braces: job handlers catch their own errors, but if anything
            # ever escapes, still send SOMETHING so the job never sticks at 'running'.
            $result = @{ ok = $false; exit_code = -1
                         output = "Agent error (outer): $($_.Exception.Message)" }
        }
        if ($deferred) {
            Write-Log "Job $($job.id) handed to isolated Windows Update worker; result will be posted on a later check-in."
            continue
        }
        Write-Log "Job $($job.id) executed (ok=$($result.ok), exit=$($result.exit_code)) - posting result..."
        $posted = $false
        for ($try = 1; $try -le 3 -and -not $posted; $try++) {
            try {
                Invoke-Api -Method POST -Path "/api/agent/jobs/$($job.id)/result" -Body $result | Out-Null
                $posted = $true
                Write-Log "Job $($job.id) result posted (attempt $try)."
            } catch {
                Write-Log "Result post attempt $try for job $($job.id) failed: $($_.Exception.Message)"
                if ($try -lt 3) { Start-Sleep -Seconds (5 * $try) }
            }
        }
        if (-not $posted) {
            Write-Log "GAVE UP posting result for job $($job.id) - server watchdog will mark it stale."
        }
    }
}

# ---------------------------------------------------------------------------
# Main  -  one check-in cycle. Returns the server response ($resp) so the
# caller (interval or live loop) can act on live_mode etc. Wrapped in a function
# so live mode can re-run it periodically without exiting the process.
# ---------------------------------------------------------------------------
function Invoke-AgentCycle {
    $script:LastResp = $null

try {
    # Deferred update-install results are posted before any new work. This path
    # does not perform Windows Update operations and remains fast/reliable.
    Post-CompletedWuInstallJobs
    $os = Get-CimInstance Win32_OperatingSystem
    $inv = Get-HardwareInventory
    $script:checkin = @{
        hostname        = $env:COMPUTERNAME
        os_version      = "$($os.Caption) ($($os.Version))"
        agent_version   = $AgentVersion
        reboot_required = (Test-RebootRequired)
        updates         = (Get-CachedPendingUpdates)
        inventory       = $inv
    }
    $resp = Invoke-Api -Method POST -Path '/api/agent/checkin' -Body $script:checkin
    Write-Log "Check-in OK [${LabBuild}] - $($script:checkin.updates.Count) cached pending update(s), $($resp.jobs.Count) job(s) queued."

    # Cache the server's denied list so the NEXT scan hides them.
    try {
        $deniedForCache = @()
        if ($resp.denied_update_ids) { $deniedForCache += $resp.denied_update_ids }
        if ($resp.denied_kbs) { $deniedForCache += $resp.denied_kbs }
        $deniedForCache | Select-Object -Unique | ConvertTo-Json | Set-Content (Join-Path $DataDir 'denied.json')
    } catch {}

    # Toggle the preview-updates flag file per the server's policy for this machine.
    try {
        $flag = Join-Path $DataDir 'include_preview.flag'
        if ($resp.include_preview) {
            if (-not (Test-Path $flag)) { New-Item -ItemType File -Path $flag -Force | Out-Null }
        } else {
            if (Test-Path $flag) { Remove-Item $flag -Force }
        }
    } catch {}

    # Hand Windows Update policy, deny rules, and scan preferences to the
    # isolated worker. The core agent never waits for Windows Update COM calls.
    Save-WuDesiredState $resp
    Start-WuScanIfDue
    Start-WuInstallIfQueued

    # Enforce service monitors the server asked us to watch. Report state back
    # on the NEXT check-in via a cached file that Get-Inventory reads.
    try {
        $report = @{}
        foreach ($mon in @($resp.service_monitors)) {
            if (-not $mon.service) { continue }
            $svc = Get-Service -Name $mon.service -ErrorAction SilentlyContinue
            if (-not $svc) { $report[$mon.service] = 'not-found'; continue }
            if ($svc.Status -eq 'Running') { $report[$mon.service] = 'running'; continue }
            if ($mon.auto_restart) {
                try {
                    Start-Service -Name $mon.service -ErrorAction Stop
                    Start-Sleep -Seconds 2
                    $svc.Refresh()
                    $report[$mon.service] = if ($svc.Status -eq 'Running') { 'restarted' } else { 'restarted-failed' }
                    Write-Log "Service monitor: $($mon.service) was down, restart $($report[$mon.service])"
                } catch { $report[$mon.service] = 'restarted-failed' }
            } else {
                $report[$mon.service] = 'stopped'
            }
        }
        $report | ConvertTo-Json -Compress | Set-Content (Join-Path $DataDir 'monitor_report.json')
    } catch {}
}
catch {
    Write-Log "Check-in failed: $($_.Exception.Message)"
    $script:LastResp = $null
    return
}

Invoke-JobList $resp.jobs

# ---------------------------------------------------------------------------
# Self-update: if the server ships a newer agent, replace this file in place.
# The scheduled task runs the file fresh every cycle, so it takes effect on the
# next run. Sanity checks guard against replacing ourselves with an error page.
# ---------------------------------------------------------------------------
if ((-not $DisableSelfUpdate) -and $resp.latest_agent_version -and ($resp.latest_agent_version -ne $AgentVersion)) {
    try {
        $tmp = Join-Path $StageDir ("agent_" + [guid]::NewGuid().ToString('N') + ".ps1")
        Invoke-WebRequest -Uri "$BaseUrl/downloads/agent.ps1" -OutFile $tmp -UseBasicParsing -TimeoutSec 120
        $okSize   = (Get-Item $tmp).Length -gt 2KB
        $okMarker = Select-String -Path $tmp -Pattern 'OpenPrime RMM agent' -Quiet
        if ($okSize -and $okMarker) {
            Copy-Item -Path $tmp -Destination $PSCommandPath -Force
            Write-Log "Self-updated agent $AgentVersion -> $($resp.latest_agent_version)"
            $script:RestartRequested = $true
        } else {
            Write-Log "Self-update aborted: downloaded file failed sanity checks."
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Self-update failed: $($_.Exception.Message)"
    }
}

if ($DisableSelfUpdate -and $resp.latest_agent_version -and ($resp.latest_agent_version -ne $AgentVersion)) {
    Write-Log "Lab build is pinned locally; ignored server agent version $($resp.latest_agent_version)."
}

# ---------------------------------------------------------------------------
# Self-heal the agent's OWN scheduled task settings. Older installs had a
# 4-hour execution limit and no restart-on-failure, so a single hung run could
# take the machine permanently offline. Fix those settings in place (cheap,
# runs every cycle, idempotent). Guarded so it can never throw into the loop.
# ---------------------------------------------------------------------------
try {
    $selfTask = Get-ScheduledTask -TaskName 'OpenPrime RMM Agent' -ErrorAction SilentlyContinue
    if ($selfTask) {
        # Live mode runs a persistent process, so it must NOT have a finite
        # execution limit (Task Scheduler would kill it). Interval mode keeps the
        # 10-minute guard against a hung one-shot run.
        $wantLimit = if ($script:LiveActive) { 'PT0S' } else { 'PT10M' }
        $needsFix = $selfTask.Settings.ExecutionTimeLimit -ne $wantLimit -or `
                    $selfTask.Settings.RestartCount -lt 3
        # Interval reconciliation: follow the server's interval_hint_minutes so
        # cadence is a SERVER-side dial (no reinstall, reversible). 1 min makes
        # the command console usable; guard rails 1..60.
        $hintMin = 0
        try { $hintMin = [int]$resp.interval_hint_minutes } catch {}
        $wantRI = if ($hintMin -ge 1 -and $hintMin -le 60) { "PT$($hintMin)M" } else { '' }
        $curRI  = ''
        try { $curRI = [string]$selfTask.Triggers[0].Repetition.Interval } catch {}
        if ($wantRI -and $curRI -and ($curRI -ne $wantRI)) {
            $selfTask.Triggers[0].Repetition.Interval = $wantRI
            $needsFix = $true
            Write-Log "Adjusting check-in interval $curRI -> $wantRI (server hint)."
        }
        if ($needsFix) {
            $selfTask.Settings.ExecutionTimeLimit = $wantLimit
            $selfTask.Settings.RestartCount = 3
            $selfTask.Settings.RestartInterval = 'PT1M'
            $selfTask.Settings.MultipleInstances = 'IgnoreNew'
            Set-ScheduledTask -InputObject $selfTask -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Repaired agent task settings (execution limit + restart-on-failure)."
        }
    }
} catch {}

# ---------------------------------------------------------------------------
# Windows Update worker self-provisioning (production 1.13.0).
# The fleet receives this agent as a single file through self-update, so the
# agent carries its isolated worker components (SHA-256 verified) and
# provisions the files and scheduled tasks itself. Fully guarded: a
# provisioning failure is logged and never affects check-in or jobs.
# ---------------------------------------------------------------------------
try {
    $wuInstallDir = Split-Path $PSCommandPath -Parent
    $wuComponents = @(
        @{ Path = (Join-Path $wuInstallDir 'OpenPrimeRMM-WU-Lab-Worker.ps1');   Sha = 'F5BF72AFED834C27CDD6F1F7CA7D28A8AF47871674DE3309F99AA02EDA19A1A3'; B64 = 'PCMKLlNZTk9QU0lTCiAgT3BlblByaW1lUk1NIGlzb2xhdGVkIFdpbmRvd3MgVXBkYXRlIGxhYjUgd29ya2VyLgoKLkRFU0NSSVBUSU9OCiAgUnVucyBvdXRzaWRlIHRoZSBjb3JlIFJNTSBhZ2VudC4gVGhlIGxhdW5jaGVyIGVuZm9yY2VzIGEgaGFyZCB0aW1lb3V0IGFuZAogIHRlcm1pbmF0ZXMgdGhpcyBwcm9jZXNzIHRyZWUgaWYgV2luZG93cyBVcGRhdGUgQWdlbnQgb3BlcmF0aW9ucyBzdGFsbC4KCiAgTGFiNSB1c2VzIG9uZSBNaWNyb3NvZnQgVXBkYXRlIEFnZW50IGNhdGFsb2cgZm9yIGRpc2NvdmVyeSwgY2xhc3NpZmljYXRpb24sCiAgZGVueSBtYXRjaGluZywgaGlkZSwgdW5oaWRlLCB2ZXJpZmljYXRpb24sIGFuZCBhcHByb3ZlZCBpbnN0YWxsYXRpb24uCgogIE1vZGVzOgogICAgU2NhbiAgICAtIGFwcGx5L3ZlcmlmeSBsb2NhbCBsYWIgcG9saWN5LCBlbmZvcmNlIGRlbmllZCB2aXNpYmlsaXR5LCBpbnZlbnRvcnkKICAgICAgICAgICAgICBhbGwgdXBkYXRlIGNhdGVnb3JpZXMsIGFuZCB3cml0ZSBjYWNoZSBmaWxlcyBmb3IgdGhlIGNvcmUgYWdlbnQuCiAgICBJbnN0YWxsIC0gcHJvY2VzcyBvbmUgYXBwcm92ZWQtdXBkYXRlIGpvYiB0aHJvdWdoIHRoZSBzYW1lIE1pY3Jvc29mdCBVcGRhdGUKICAgICAgICAgICAgICBjYXRhbG9nIGFuZCB3cml0ZSBhIGRlZmVycmVkIGpvYiByZXN1bHQuCiAgICBSZXN0b3JlIC0gcmVzdG9yZSBwcmUtbGFiIFdpbmRvd3MgVXBkYXRlIHBvbGljeSBhbmQgdW5oaWRlIG9ubHkgdXBkYXRlcyB0aGF0CiAgICAgICAgICAgICAgdGhpcyBsYWIgd29ya2VyIHByZXZpb3VzbHkgaGlkLgojPgoKcGFyYW0oCiAgICBbVmFsaWRhdGVTZXQoJ1NjYW4nLCdJbnN0YWxsJywnUmVzdG9yZScpXQogICAgW3N0cmluZ10kTW9kZSA9ICdTY2FuJwopCgokRXJyb3JBY3Rpb25QcmVmZXJlbmNlID0gJ1N0b3AnCltOZXQuU2VydmljZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgPSBbTmV0LlNlY3VyaXR5UHJvdG9jb2xUeXBlXTo6VGxzMTIKCiRMYWJCdWlsZCA9ICdXVS1QUk9ELTEnCiRMYWJWZXJzaW9uID0gJzEuMTMuMCcKJE1pY3Jvc29mdFVwZGF0ZVNlcnZpY2VJZCA9ICc3OTcxZjkxOC1hODQ3LTQ0MzAtOTI3OS00YTUyZDFlZmUxOGQnCiREYXRhRGlyID0gJ0M6XFByb2dyYW1EYXRhXE9wZW5QcmltZScKJExhYkRpciA9IEpvaW4tUGF0aCAkRGF0YURpciAnd3UtbGFiJwokUXVldWVEaXIgPSBKb2luLVBhdGggJExhYkRpciAnaW5zdGFsbC1xdWV1ZScKJFJlc3VsdERpciA9IEpvaW4tUGF0aCAkTGFiRGlyICdpbnN0YWxsLXJlc3VsdHMnCiREZXNpcmVkUGF0aCA9IEpvaW4tUGF0aCAkTGFiRGlyICdkZXNpcmVkLmpzb24nCiRTZXR0aW5nc1BhdGggPSBKb2luLVBhdGggJExhYkRpciAnbGFiLXNldHRpbmdzLmpzb24nCiRVcGRhdGVzQ2FjaGVQYXRoID0gSm9pbi1QYXRoICRMYWJEaXIgJ3VwZGF0ZXMtY2FjaGUuanNvbicKJEludmVudG9yeVBhdGggPSBKb2luLVBhdGggJExhYkRpciAndXBkYXRlLWludmVudG9yeS5qc29uJwokTGVnYWN5SW52ZW50b3J5UGF0aCA9IEpvaW4tUGF0aCAkTGFiRGlyICdpbnZlbnRvcnktY2FjaGUuanNvbicKJFJlcG9ydFBhdGggPSBKb2luLVBhdGggJExhYkRpciAnd29ya2VyLXJlcG9ydC5qc29uJwokQmFja3VwUGF0aCA9IEpvaW4tUGF0aCAkTGFiRGlyICdwb2xpY3ktYmFja3VwLmpzb24nCiRQb2xpY3lPd25lclBhdGggPSBKb2luLVBhdGggJExhYkRpciAncG9saWN5LW93bmVkLmZsYWcnCiRIaWRkZW5TdGF0ZVBhdGggPSBKb2luLVBhdGggJExhYkRpciAnaGlkZGVuLWJ5LXBjb3JlLmpzb24nCiRBY3RpdmVJbnN0YWxsUGF0aCA9IEpvaW4tUGF0aCAkTGFiRGlyICdhY3RpdmUtaW5zdGFsbC5qc29uJwokTG9nUGF0aCA9IEpvaW4tUGF0aCAkTGFiRGlyICd3b3JrZXIubG9nJwoKZm9yZWFjaCAoJGRpciBpbiBAKCRMYWJEaXIsICRRdWV1ZURpciwgJFJlc3VsdERpcikpIHsKICAgIGlmICgtbm90IChUZXN0LVBhdGggJGRpcikpIHsgTmV3LUl0ZW0gLUl0ZW1UeXBlIERpcmVjdG9yeSAtUGF0aCAkZGlyIC1Gb3JjZSB8IE91dC1OdWxsIH0KfQoKZnVuY3Rpb24gV3JpdGUtV3VMb2coW3N0cmluZ10kTWVzc2FnZSkgewogICAgJGxpbmUgPSAiezB9ICBbezF9XSB7Mn0iIC1mIChHZXQtRGF0ZSAtRm9ybWF0ICd5eXl5LU1NLWRkIEhIOm1tOnNzJyksICRNb2RlLlRvVXBwZXJJbnZhcmlhbnQoKSwgJE1lc3NhZ2UKICAgIHRyeSB7CiAgICAgICAgQWRkLUNvbnRlbnQgLVBhdGggJExvZ1BhdGggLVZhbHVlICRsaW5lIC1FbmNvZGluZyBVVEY4IC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlCiAgICAgICAgJGl0ZW0gPSBHZXQtSXRlbSAkTG9nUGF0aCAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZQogICAgICAgIGlmICgkaXRlbSAtYW5kICRpdGVtLkxlbmd0aCAtZ3QgMTA0ODU3NikgewogICAgICAgICAgICBHZXQtQ29udGVudCAkTG9nUGF0aCAtVGFpbCAxNTAwIHwgU2V0LUNvbnRlbnQgJExvZ1BhdGggLUVuY29kaW5nIFVURjgKICAgICAgICB9CiAgICB9IGNhdGNoIHt9Cn0KCmZ1bmN0aW9uIFJlYWQtSnNvbkZpbGUoW3N0cmluZ10kUGF0aCwgJERlZmF1bHQpIHsKICAgIGlmICgtbm90IChUZXN0LVBhdGggJFBhdGgpKSB7IHJldHVybiAkRGVmYXVsdCB9CiAgICB0cnkgeyByZXR1cm4gKEdldC1Db250ZW50ICRQYXRoIC1SYXcgLUVycm9yQWN0aW9uIFN0b3AgfCBDb252ZXJ0RnJvbS1Kc29uKSB9CiAgICBjYXRjaCB7IFdyaXRlLVd1TG9nICJJbnZhbGlkIEpTT04gYXQgJHtQYXRofTogJCgkXy5FeGNlcHRpb24uTWVzc2FnZSkiOyByZXR1cm4gJERlZmF1bHQgfQp9CgpmdW5jdGlvbiBXcml0ZS1Kc29uQXRvbWljKFtzdHJpbmddJFBhdGgsICRWYWx1ZSwgW2ludF0kRGVwdGggPSAxMCkgewogICAgJHRtcCA9ICIkUGF0aC4kKFtndWlkXTo6TmV3R3VpZCgpLlRvU3RyaW5nKCdOJykpLnRtcCIKICAgICRqc29uID0gJFZhbHVlIHwgQ29udmVydFRvLUpzb24gLURlcHRoICREZXB0aAogICAgW1N5c3RlbS5JTy5GaWxlXTo6V3JpdGVBbGxUZXh0KCR0bXAsICRqc29uLCAoTmV3LU9iamVjdCBTeXN0ZW0uVGV4dC5VVEY4RW5jb2RpbmcoJGZhbHNlKSkpCiAgICBNb3ZlLUl0ZW0gLVBhdGggJHRtcCAtRGVzdGluYXRpb24gJFBhdGggLUZvcmNlCn0KCmZ1bmN0aW9uIEdldC1FcG9jaCB7IHJldHVybiBbRGF0ZVRpbWVPZmZzZXRdOjpOb3cuVG9Vbml4VGltZVNlY29uZHMoKSB9CgpmdW5jdGlvbiBDb252ZXJ0VG8tVXBkYXRlS2V5KFtzdHJpbmddJFZhbHVlKSB7CiAgICBpZiAoLW5vdCAkVmFsdWUpIHsgcmV0dXJuICcnIH0KICAgICRjbGVhbiA9ICgkVmFsdWUgLXJlcGxhY2UgJ15LQlxzKicsICdLQicpIC1yZXBsYWNlICdccysnLCAnICcKICAgIHJldHVybiAkY2xlYW4uVHJpbSgpLlRvVXBwZXJJbnZhcmlhbnQoKQp9CgpmdW5jdGlvbiBHZXQtS2JGcm9tVXBkYXRlKCRVcGRhdGUpIHsKICAgICRrYiA9ICcnCiAgICB0cnkgewogICAgICAgIGlmICgkVXBkYXRlLktCQXJ0aWNsZUlEcyAtYW5kICRVcGRhdGUuS0JBcnRpY2xlSURzLkNvdW50IC1ndCAwKSB7CiAgICAgICAgICAgICRrYiA9IFtzdHJpbmddJFVwZGF0ZS5LQkFydGljbGVJRHMuSXRlbSgwKQogICAgICAgIH0KICAgIH0gY2F0Y2gge30KICAgIGlmICgtbm90ICRrYikgewogICAgICAgIHRyeSB7ICRrYiA9IFtzdHJpbmddJFVwZGF0ZS5LQiB9IGNhdGNoIHt9CiAgICB9CiAgICBpZiAoJGtiIC1hbmQgJGtiIC1ub3RtYXRjaCAnXktCJykgeyAka2IgPSAiS0Ika2IiIH0KICAgIHJldHVybiAka2IKfQoKZnVuY3Rpb24gR2V0LUNhdGVnb3J5TmFtZXMoJFVwZGF0ZSkgewogICAgJG5hbWVzID0gQCgpCiAgICB0cnkgewogICAgICAgIGZvciAoJGkgPSAwOyAkaSAtbHQgJFVwZGF0ZS5DYXRlZ29yaWVzLkNvdW50OyAkaSsrKSB7CiAgICAgICAgICAgICRuYW1lID0gW3N0cmluZ10kVXBkYXRlLkNhdGVnb3JpZXMuSXRlbSgkaSkuTmFtZQogICAgICAgICAgICBpZiAoJG5hbWUpIHsgJG5hbWVzICs9ICRuYW1lIH0KICAgICAgICB9CiAgICB9IGNhdGNoIHt9CiAgICByZXR1cm4gQCgkbmFtZXMgfCBTb3J0LU9iamVjdCAtVW5pcXVlKQp9CgpmdW5jdGlvbiBHZXQtVXBkYXRlSWRlbnRpdHkoJFVwZGF0ZSkgewogICAgJGtiID0gR2V0LUtiRnJvbVVwZGF0ZSAkVXBkYXRlCiAgICAkdWlkID0gJycKICAgICRyZXZpc2lvbiA9IDAKICAgIHRyeSB7CiAgICAgICAgJHVpZCA9IFtzdHJpbmddJFVwZGF0ZS5JZGVudGl0eS5VcGRhdGVJRAogICAgICAgICRyZXZpc2lvbiA9IFtpbnRdJFVwZGF0ZS5JZGVudGl0eS5SZXZpc2lvbk51bWJlcgogICAgfSBjYXRjaCB7fQogICAgaWYgKC1ub3QgJHVpZCkgeyAkdWlkID0gaWYgKCRrYikgeyAka2IgfSBlbHNlIHsgW3N0cmluZ10kVXBkYXRlLlRpdGxlIH0gfQogICAgcmV0dXJuIFtwc2N1c3RvbW9iamVjdF1AewogICAgICAgIHVwZGF0ZV9pZCA9ICR1aWQKICAgICAgICByZXZpc2lvbiA9ICRyZXZpc2lvbgogICAgICAgIGtiID0gJGtiCiAgICAgICAgdGl0bGUgPSBbc3RyaW5nXSRVcGRhdGUuVGl0bGUKICAgIH0KfQoKZnVuY3Rpb24gR2V0LVVwZGF0ZUNsYXNzaWZpY2F0aW9uKCRVcGRhdGUpIHsKICAgICR0aXRsZSA9IFtzdHJpbmddJFVwZGF0ZS5UaXRsZQogICAgJGNhdGVnb3JpZXMgPSBAKEdldC1DYXRlZ29yeU5hbWVzICRVcGRhdGUpCiAgICAkY2F0ZWdvcnlUZXh0ID0gKCRjYXRlZ29yaWVzIC1qb2luICcgfCAnKQogICAgJHR5cGVOdW1iZXIgPSAwCiAgICB0cnkgeyAkdHlwZU51bWJlciA9IFtpbnRdJFVwZGF0ZS5UeXBlIH0gY2F0Y2gge30KICAgICRicm93c2VPbmx5ID0gJGZhbHNlCiAgICB0cnkgeyAkYnJvd3NlT25seSA9IFtib29sXSRVcGRhdGUuQnJvd3NlT25seSB9IGNhdGNoIHt9CgogICAgJGlzRHJpdmVyID0gKCR0eXBlTnVtYmVyIC1lcSAyIC1vciAkY2F0ZWdvcnlUZXh0IC1tYXRjaCAnKD9pKURyaXZlcnM/JykKICAgICRpc0Zpcm13YXJlID0gKCR0aXRsZSAtbWF0Y2ggJyg/aSlmaXJtd2FyZXxzeXN0ZW0gZmlybXdhcmV8Ymlvc3x1ZWZpJyAtb3IgJGNhdGVnb3J5VGV4dCAtbWF0Y2ggJyg/aSlmaXJtd2FyZScpCiAgICAkaXNGZWF0dXJlID0gKCR0aXRsZSAtbWF0Y2ggJyg/aSleRmVhdHVyZSB1cGRhdGUgdG8gV2luZG93c3xVcGdyYWRlIHRvIFdpbmRvd3N8V2luZG93cyAxWzAxXSwgdmVyc2lvbiBcZHsyfUhcZCcgLW9yICRjYXRlZ29yeVRleHQgLW1hdGNoICcoP2kpVXBncmFkZXMnKQogICAgJGlzUHJldmlldyA9ICgkdGl0bGUgLW1hdGNoICcoP2kpUHJldmlldycpCiAgICAkaXNPcHRpb25hbCA9ICgkYnJvd3NlT25seSAtb3IgJGlzUHJldmlldykKCiAgICAkY2xhc3MgPSAnc3RhbmRhcmQnCiAgICBpZiAoJGlzRmlybXdhcmUpIHsgJGNsYXNzID0gJ2Zpcm13YXJlJyB9CiAgICBlbHNlaWYgKCRpc0RyaXZlcikgeyAkY2xhc3MgPSAnZHJpdmVyJyB9CiAgICBlbHNlaWYgKCRpc0ZlYXR1cmUpIHsgJGNsYXNzID0gJ2ZlYXR1cmUnIH0KICAgIGVsc2VpZiAoJGlzT3B0aW9uYWwpIHsgJGNsYXNzID0gJ29wdGlvbmFsJyB9CgogICAgcmV0dXJuIFtwc2N1c3RvbW9iamVjdF1AewogICAgICAgIGNsYXNzID0gJGNsYXNzCiAgICAgICAgdXBkYXRlX3R5cGUgPSBpZiAoJHR5cGVOdW1iZXIgLWVxIDIpIHsgJ0RyaXZlcicgfSBlbHNlIHsgJ1NvZnR3YXJlJyB9CiAgICAgICAgYnJvd3NlX29ubHkgPSAkYnJvd3NlT25seQogICAgICAgIGlzX3ByZXZpZXcgPSAkaXNQcmV2aWV3CiAgICAgICAgaXNfZHJpdmVyID0gJGlzRHJpdmVyCiAgICAgICAgaXNfZmlybXdhcmUgPSAkaXNGaXJtd2FyZQogICAgICAgIGlzX2ZlYXR1cmUgPSAkaXNGZWF0dXJlCiAgICAgICAgY2F0ZWdvcmllcyA9ICRjYXRlZ29yaWVzCiAgICB9Cn0KCmZ1bmN0aW9uIENvbnZlcnRUby1EZXRhaWxlZFVwZGF0ZSgkVXBkYXRlLCBbYm9vbF0kSGlkZGVuLCBbYm9vbF0kTWFuYWdlZEhpZGRlbikgewogICAgJGlkID0gR2V0LVVwZGF0ZUlkZW50aXR5ICRVcGRhdGUKICAgICRjbGFzcyA9IEdldC1VcGRhdGVDbGFzc2lmaWNhdGlvbiAkVXBkYXRlCiAgICAkc2l6ZUJ5dGVzID0gMAogICAgdHJ5IHsgJHNpemVCeXRlcyA9IFtkb3VibGVdJFVwZGF0ZS5NYXhEb3dubG9hZFNpemUgfSBjYXRjaCB7fQogICAgaWYgKC1ub3QgJHNpemVCeXRlcykgeyB0cnkgeyAkc2l6ZUJ5dGVzID0gW2RvdWJsZV0kVXBkYXRlLk1pbkRvd25sb2FkU2l6ZSB9IGNhdGNoIHt9IH0KICAgICRkb3dubG9hZGVkID0gJGZhbHNlCiAgICAkbWFuZGF0b3J5ID0gJGZhbHNlCiAgICAkYXV0b1NlbGVjdGVkID0gJGZhbHNlCiAgICAkc2V2ZXJpdHkgPSAnJwogICAgdHJ5IHsgJGRvd25sb2FkZWQgPSBbYm9vbF0kVXBkYXRlLklzRG93bmxvYWRlZCB9IGNhdGNoIHt9CiAgICB0cnkgeyAkbWFuZGF0b3J5ID0gW2Jvb2xdJFVwZGF0ZS5Jc01hbmRhdG9yeSB9IGNhdGNoIHt9CiAgICB0cnkgeyAkYXV0b1NlbGVjdGVkID0gW2Jvb2xdJFVwZGF0ZS5BdXRvU2VsZWN0T25XZWJTaXRlcyB9IGNhdGNoIHt9CiAgICB0cnkgeyAkc2V2ZXJpdHkgPSBbc3RyaW5nXSRVcGRhdGUuTXNyY1NldmVyaXR5IH0gY2F0Y2gge30KCiAgICByZXR1cm4gW3BzY3VzdG9tb2JqZWN0XUB7CiAgICAgICAgdXBkYXRlX2lkID0gW3N0cmluZ10kaWQudXBkYXRlX2lkCiAgICAgICAgcmV2aXNpb24gPSBbaW50XSRpZC5yZXZpc2lvbgogICAgICAgIGtiID0gW3N0cmluZ10kaWQua2IKICAgICAgICB0aXRsZSA9IFtzdHJpbmddJGlkLnRpdGxlCiAgICAgICAgc2V2ZXJpdHkgPSAkc2V2ZXJpdHkKICAgICAgICBzaXplX21iID0gW21hdGhdOjpSb3VuZCgkc2l6ZUJ5dGVzIC8gMTA0ODU3NiwgMSkKICAgICAgICBjbGFzcyA9IFtzdHJpbmddJGNsYXNzLmNsYXNzCiAgICAgICAgdXBkYXRlX3R5cGUgPSBbc3RyaW5nXSRjbGFzcy51cGRhdGVfdHlwZQogICAgICAgIGJyb3dzZV9vbmx5ID0gW2Jvb2xdJGNsYXNzLmJyb3dzZV9vbmx5CiAgICAgICAgaXNfcHJldmlldyA9IFtib29sXSRjbGFzcy5pc19wcmV2aWV3CiAgICAgICAgY2F0ZWdvcmllcyA9IEAoJGNsYXNzLmNhdGVnb3JpZXMpCiAgICAgICAgaXNfaGlkZGVuID0gW2Jvb2xdJEhpZGRlbgogICAgICAgIGhpZGRlbl9ieV9wcmltZW5ldGNvcmUgPSBbYm9vbF0kTWFuYWdlZEhpZGRlbgogICAgICAgIGlzX21hbmRhdG9yeSA9ICRtYW5kYXRvcnkKICAgICAgICBpc19kb3dubG9hZGVkID0gJGRvd25sb2FkZWQKICAgICAgICBhdXRvX3NlbGVjdGVkID0gJGF1dG9TZWxlY3RlZAogICAgfQp9CgpmdW5jdGlvbiBDb252ZXJ0VG8tU2VydmVyVXBkYXRlKCREZXRhaWxlZCkgewogICAgcmV0dXJuIEB7CiAgICAgICAgdXBkYXRlX2lkID0gW3N0cmluZ10kRGV0YWlsZWQudXBkYXRlX2lkCiAgICAgICAga2IgPSBbc3RyaW5nXSREZXRhaWxlZC5rYgogICAgICAgIHRpdGxlID0gW3N0cmluZ10kRGV0YWlsZWQudGl0bGUKICAgICAgICBzZXZlcml0eSA9IFtzdHJpbmddJERldGFpbGVkLnNldmVyaXR5CiAgICAgICAgc2l6ZV9tYiA9IFtkb3VibGVdJERldGFpbGVkLnNpemVfbWIKICAgICAgICBjYXRlZ29yeSA9IFtzdHJpbmddJERldGFpbGVkLmNsYXNzCiAgICAgICAgYnJvd3NlX29ubHkgPSBbYm9vbF0kRGV0YWlsZWQuYnJvd3NlX29ubHkKICAgICAgICByZXZpc2lvbiA9IFtpbnRdJERldGFpbGVkLnJldmlzaW9uCiAgICB9Cn0KCmZ1bmN0aW9uIFRlc3QtUnVsZUVxdWl2YWxlbnQoJExlZnQsICRSaWdodCkgewogICAgJGxpZCA9IENvbnZlcnRUby1VcGRhdGVLZXkgKFtzdHJpbmddJExlZnQudXBkYXRlX2lkKQogICAgJGxrYiA9IENvbnZlcnRUby1VcGRhdGVLZXkgKFtzdHJpbmddJExlZnQua2IpCiAgICAkbHRpdGxlID0gQ29udmVydFRvLVVwZGF0ZUtleSAoW3N0cmluZ10kTGVmdC50aXRsZSkKICAgICRyaWQgPSBDb252ZXJ0VG8tVXBkYXRlS2V5IChbc3RyaW5nXSRSaWdodC51cGRhdGVfaWQpCiAgICAkcmtiID0gQ29udmVydFRvLVVwZGF0ZUtleSAoW3N0cmluZ10kUmlnaHQua2IpCiAgICAkcnRpdGxlID0gQ29udmVydFRvLVVwZGF0ZUtleSAoW3N0cmluZ10kUmlnaHQudGl0bGUpCiAgICByZXR1cm4gKCgkbGlkIC1hbmQgKCRsaWQgLWVxICRyaWQgLW9yICRsaWQgLWVxICRya2IpKSAtb3IKICAgICAgICAgICAgKCRsa2IgLWFuZCAoJGxrYiAtZXEgJHJpZCAtb3IgJGxrYiAtZXEgJHJrYikpIC1vcgogICAgICAgICAgICAoJGx0aXRsZSAtYW5kICRydGl0bGUgLWFuZCAkbHRpdGxlIC1lcSAkcnRpdGxlKSkKfQoKZnVuY3Rpb24gVGVzdC1SdWxlTWF0Y2goJFVwZGF0ZSwgJFJ1bGUpIHsKICAgICRpZGVudGl0eSA9IEdldC1VcGRhdGVJZGVudGl0eSAkVXBkYXRlCiAgICByZXR1cm4gKFRlc3QtUnVsZUVxdWl2YWxlbnQgJGlkZW50aXR5ICRSdWxlKQp9CgpmdW5jdGlvbiBUZXN0LVdhbnRlZE1hdGNoKCRVcGRhdGUsICRXYW50ZWRJZHMpIHsKICAgICRpZCA9IEdldC1VcGRhdGVJZGVudGl0eSAkVXBkYXRlCiAgICAka2V5cyA9IEAoCiAgICAgICAgKENvbnZlcnRUby1VcGRhdGVLZXkgKFtzdHJpbmddJGlkLnVwZGF0ZV9pZCkpLAogICAgICAgIChDb252ZXJ0VG8tVXBkYXRlS2V5IChbc3RyaW5nXSRpZC5rYikpLAogICAgICAgIChDb252ZXJ0VG8tVXBkYXRlS2V5IChbc3RyaW5nXSRpZC50aXRsZSkpCiAgICApCiAgICBmb3JlYWNoICgkd2FudGVkIGluIEAoJFdhbnRlZElkcykpIHsKICAgICAgICBpZiAoJGtleXMgLWNvbnRhaW5zIChDb252ZXJ0VG8tVXBkYXRlS2V5IChbc3RyaW5nXSR3YW50ZWQpKSkgeyByZXR1cm4gJHRydWUgfQogICAgfQogICAgcmV0dXJuICRmYWxzZQp9CgpmdW5jdGlvbiBHZXQtUmVnaXN0cnlTdGF0ZShbc3RyaW5nXSRQYXRoLCBbc3RyaW5nXSROYW1lKSB7CiAgICAkZXhpc3RzID0gJGZhbHNlCiAgICAkdmFsdWUgPSAkbnVsbAogICAgJGtpbmQgPSAnRFdvcmQnCiAgICB0cnkgewogICAgICAgIGlmIChUZXN0LVBhdGggJFBhdGgpIHsKICAgICAgICAgICAgJGl0ZW0gPSBHZXQtSXRlbSAtUGF0aCAkUGF0aCAtRXJyb3JBY3Rpb24gU3RvcAogICAgICAgICAgICBpZiAoQCgkaXRlbS5HZXRWYWx1ZU5hbWVzKCkpIC1jb250YWlucyAkTmFtZSkgewogICAgICAgICAgICAgICAgJGV4aXN0cyA9ICR0cnVlCiAgICAgICAgICAgICAgICAkdmFsdWUgPSAkaXRlbS5HZXRWYWx1ZSgkTmFtZSwgJG51bGwsICdEb05vdEV4cGFuZEVudmlyb25tZW50TmFtZXMnKQogICAgICAgICAgICAgICAgdHJ5IHsgJGtpbmQgPSBbc3RyaW5nXSRpdGVtLkdldFZhbHVlS2luZCgkTmFtZSkgfSBjYXRjaCB7fQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfSBjYXRjaCB7fQogICAgcmV0dXJuIEB7IHBhdGg9JFBhdGg7IG5hbWU9JE5hbWU7IGV4aXN0cz0kZXhpc3RzOyB2YWx1ZT0kdmFsdWU7IGtpbmQ9JGtpbmQgfQp9CgpmdW5jdGlvbiBTZXQtUmVnaXN0cnlEd29yZChbc3RyaW5nXSRQYXRoLCBbc3RyaW5nXSROYW1lLCBbaW50XSRWYWx1ZSkgewogICAgaWYgKC1ub3QgKFRlc3QtUGF0aCAkUGF0aCkpIHsgTmV3LUl0ZW0gLVBhdGggJFBhdGggLUZvcmNlIHwgT3V0LU51bGwgfQogICAgTmV3LUl0ZW1Qcm9wZXJ0eSAtUGF0aCAkUGF0aCAtTmFtZSAkTmFtZSAtVmFsdWUgJFZhbHVlIC1Qcm9wZXJ0eVR5cGUgRFdvcmQgLUZvcmNlIHwgT3V0LU51bGwKfQoKZnVuY3Rpb24gR2V0LVBvbGljeVRhcmdldHMgewogICAgcmV0dXJuIEAoCiAgICAgICAgQCgnSEtMTTpcU09GVFdBUkVcUG9saWNpZXNcTWljcm9zb2Z0XFdpbmRvd3NcV2luZG93c1VwZGF0ZScsJ1NldERpc2FibGVVWFdVQWNjZXNzJyksCiAgICAgICAgQCgnSEtMTTpcU09GVFdBUkVcUG9saWNpZXNcTWljcm9zb2Z0XFdpbmRvd3NcV2luZG93c1VwZGF0ZScsJ1NldERpc2FibGVQYXVzZVVYQWNjZXNzJyksCiAgICAgICAgQCgnSEtMTTpcU09GVFdBUkVcUG9saWNpZXNcTWljcm9zb2Z0XFdpbmRvd3NcV2luZG93c1VwZGF0ZVxBVScsJ05vQXV0b1VwZGF0ZScpLAogICAgICAgIEAoJ0hLTE06XFNPRlRXQVJFXFBvbGljaWVzXE1pY3Jvc29mdFxXaW5kb3dzXFdpbmRvd3NVcGRhdGVcQVUnLCdBVU9wdGlvbnMnKQogICAgKQp9CgpmdW5jdGlvbiBCYWNrdXAtUG9saWN5T25jZSB7CiAgICBpZiAoVGVzdC1QYXRoICRCYWNrdXBQYXRoKSB7IHJldHVybiB9CiAgICAkc2F2ZWQgPSBAKCkKICAgIGZvcmVhY2ggKCR0YXJnZXQgaW4gR2V0LVBvbGljeVRhcmdldHMpIHsgJHNhdmVkICs9IEdldC1SZWdpc3RyeVN0YXRlICR0YXJnZXRbMF0gJHRhcmdldFsxXSB9CiAgICBXcml0ZS1Kc29uQXRvbWljICRCYWNrdXBQYXRoICRzYXZlZCA2CiAgICBXcml0ZS1XdUxvZyAnU2F2ZWQgb3JpZ2luYWwgV2luZG93cyBVcGRhdGUgcG9saWN5IHZhbHVlcy4nCn0KCmZ1bmN0aW9uIFJlc3RvcmUtUG9saWN5IHsKICAgIGlmICgtbm90IChUZXN0LVBhdGggJFBvbGljeU93bmVyUGF0aCkgLWFuZCAtbm90IChUZXN0LVBhdGggJEJhY2t1cFBhdGgpKSB7IHJldHVybiAkdHJ1ZSB9CiAgICBpZiAoLW5vdCAoVGVzdC1QYXRoICRCYWNrdXBQYXRoKSkgewogICAgICAgIFdyaXRlLVd1TG9nICdQb2xpY3kgb3duZXJzaGlwIG1hcmtlciBleGlzdHMgd2l0aG91dCBhIGJhY2t1cDsgcmVtb3Zpbmcgb25seSB0aGUgZm91ciBsYWItb3duZWQgdmFsdWVzLicKICAgICAgICBmb3JlYWNoICgkdGFyZ2V0IGluIEdldC1Qb2xpY3lUYXJnZXRzKSB7CiAgICAgICAgICAgIGlmIChUZXN0LVBhdGggJHRhcmdldFswXSkgewogICAgICAgICAgICAgICAgUmVtb3ZlLUl0ZW1Qcm9wZXJ0eSAtUGF0aCAkdGFyZ2V0WzBdIC1OYW1lICR0YXJnZXRbMV0gLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlCiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgUmVtb3ZlLUl0ZW0gJFBvbGljeU93bmVyUGF0aCAtRm9yY2UgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUKICAgICAgICByZXR1cm4gJHRydWUKICAgIH0KICAgIHRyeSB7CiAgICAgICAgJHNhdmVkID0gQChSZWFkLUpzb25GaWxlICRCYWNrdXBQYXRoIEAoKSkKICAgICAgICBmb3JlYWNoICgkZW50cnkgaW4gJHNhdmVkKSB7CiAgICAgICAgICAgIGlmICgkZW50cnkuZXhpc3RzKSB7CiAgICAgICAgICAgICAgICBpZiAoLW5vdCAoVGVzdC1QYXRoICRlbnRyeS5wYXRoKSkgeyBOZXctSXRlbSAtUGF0aCAkZW50cnkucGF0aCAtRm9yY2UgfCBPdXQtTnVsbCB9CiAgICAgICAgICAgICAgICAka2luZCA9IFtNaWNyb3NvZnQuV2luMzIuUmVnaXN0cnlWYWx1ZUtpbmRdOjpEV29yZAogICAgICAgICAgICAgICAgdHJ5IHsgJGtpbmQgPSBbTWljcm9zb2Z0LldpbjMyLlJlZ2lzdHJ5VmFsdWVLaW5kXShbRW51bV06OlBhcnNlKFtNaWNyb3NvZnQuV2luMzIuUmVnaXN0cnlWYWx1ZUtpbmRdLCBbc3RyaW5nXSRlbnRyeS5raW5kKSkgfSBjYXRjaCB7fQogICAgICAgICAgICAgICAgKEdldC1JdGVtICRlbnRyeS5wYXRoKS5TZXRWYWx1ZShbc3RyaW5nXSRlbnRyeS5uYW1lLCAkZW50cnkudmFsdWUsICRraW5kKQogICAgICAgICAgICB9IGVsc2VpZiAoVGVzdC1QYXRoICRlbnRyeS5wYXRoKSB7CiAgICAgICAgICAgICAgICBSZW1vdmUtSXRlbVByb3BlcnR5IC1QYXRoICRlbnRyeS5wYXRoIC1OYW1lICRlbnRyeS5uYW1lIC1Gb3JjZSAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIFJlbW92ZS1JdGVtICRCYWNrdXBQYXRoIC1Gb3JjZSAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZQogICAgICAgIFJlbW92ZS1JdGVtICRQb2xpY3lPd25lclBhdGggLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlCiAgICAgICAgV3JpdGUtV3VMb2cgJ1Jlc3RvcmVkIG9yaWdpbmFsIFdpbmRvd3MgVXBkYXRlIHBvbGljeSB2YWx1ZXMuJwogICAgICAgIHJldHVybiAkdHJ1ZQogICAgfSBjYXRjaCB7CiAgICAgICAgV3JpdGUtV3VMb2cgIlBvbGljeSByZXN0b3JlIGZhaWxlZDogJCgkXy5FeGNlcHRpb24uTWVzc2FnZSkiCiAgICAgICAgcmV0dXJuICRmYWxzZQogICAgfQp9CgpmdW5jdGlvbiBSZXNvbHZlLURlc2lyZWRTdGF0ZSB7CiAgICAkc2VydmVyID0gUmVhZC1Kc29uRmlsZSAkRGVzaXJlZFBhdGggKFtwc2N1c3RvbW9iamVjdF1Ae30pCiAgICAkbG9jYWwgPSBSZWFkLUpzb25GaWxlICRTZXR0aW5nc1BhdGggKFtwc2N1c3RvbW9iamVjdF1Ae30pCiAgICAkbW9kZSA9IChbc3RyaW5nXSRsb2NhbC5tb2RlKS5Ub0xvd2VySW52YXJpYW50KCkKICAgIHJldHVybiBbcHNjdXN0b21vYmplY3RdQHsKICAgICAgICBtYW5hZ2VkID0gKCRtb2RlIC1lcSAnbWFuYWdlZCcpCiAgICAgICAgYmxvY2tfdXNlcl91cGRhdGVfYWNjZXNzID0gaWYgKCRudWxsIC1uZSAkbG9jYWwuYmxvY2tfdXNlcl91cGRhdGVfYWNjZXNzKSB7IFtib29sXSRsb2NhbC5ibG9ja191c2VyX3VwZGF0ZV9hY2Nlc3MgfSBlbHNlIHsgJHRydWUgfQogICAgICAgIGJsb2NrX3BhdXNlX3VwZGF0ZXMgPSBpZiAoJG51bGwgLW5lICRsb2NhbC5ibG9ja19wYXVzZV91cGRhdGVzKSB7IFtib29sXSRsb2NhbC5ibG9ja19wYXVzZV91cGRhdGVzIH0gZWxzZSB7ICR0cnVlIH0KICAgICAgICBoaWRlX2RlbmllZF91cGRhdGVzID0gaWYgKCRudWxsIC1uZSAkbG9jYWwuaGlkZV9kZW5pZWRfdXBkYXRlcykgeyBbYm9vbF0kbG9jYWwuaGlkZV9kZW5pZWRfdXBkYXRlcyB9IGVsc2UgeyAkdHJ1ZSB9CiAgICAgICAgaW5jbHVkZV9vcHRpb25hbF91cGRhdGVzID0gaWYgKCRudWxsIC1uZSAkbG9jYWwuaW5jbHVkZV9vcHRpb25hbF91cGRhdGVzKSB7IFtib29sXSRsb2NhbC5pbmNsdWRlX29wdGlvbmFsX3VwZGF0ZXMgfSBlbHNlIHsgJHRydWUgfQogICAgICAgIGluY2x1ZGVfZHJpdmVyX3VwZGF0ZXMgPSBpZiAoJG51bGwgLW5lICRsb2NhbC5pbmNsdWRlX2RyaXZlcl91cGRhdGVzKSB7IFtib29sXSRsb2NhbC5pbmNsdWRlX2RyaXZlcl91cGRhdGVzIH0gZWxzZSB7ICR0cnVlIH0KICAgICAgICBpbmNsdWRlX2Zpcm13YXJlX3VwZGF0ZXMgPSBpZiAoJG51bGwgLW5lICRsb2NhbC5pbmNsdWRlX2Zpcm13YXJlX3VwZGF0ZXMpIHsgW2Jvb2xdJGxvY2FsLmluY2x1ZGVfZmlybXdhcmVfdXBkYXRlcyB9IGVsc2UgeyAkdHJ1ZSB9CiAgICAgICAgaW5jbHVkZV9mZWF0dXJlX3VwZGF0ZXMgPSBpZiAoJG51bGwgLW5lICRsb2NhbC5pbmNsdWRlX2ZlYXR1cmVfdXBkYXRlcykgeyBbYm9vbF0kbG9jYWwuaW5jbHVkZV9mZWF0dXJlX3VwZGF0ZXMgfSBlbHNlIHsgJHRydWUgfQogICAgICAgIHNlcnZlcl9pbmNsdWRlX3ByZXZpZXcgPSBbYm9vbF0kc2VydmVyLmluY2x1ZGVfcHJldmlldwogICAgICAgIGRlbmllZF91cGRhdGVzID0gQCgkc2VydmVyLmRlbmllZF91cGRhdGVzKQogICAgICAgIHNlcnZlcl9tYW5hZ2VkX3JlcXVlc3RlZCA9IFtib29sXSRzZXJ2ZXIuc2VydmVyX21hbmFnZWRfcmVxdWVzdGVkCiAgICAgICAgcmVjZWl2ZWRfYXQgPSBbaW50NjRdJHNlcnZlci5yZWNlaXZlZF9hdAogICAgfQp9CgpmdW5jdGlvbiBBcHBseS1BbmQtVmVyaWZ5UG9saWN5KCREZXNpcmVkKSB7CiAgICAkZXJyb3JzID0gTmV3LU9iamVjdCBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0W3N0cmluZ10KICAgICR3dSA9ICdIS0xNOlxTT0ZUV0FSRVxQb2xpY2llc1xNaWNyb3NvZnRcV2luZG93c1xXaW5kb3dzVXBkYXRlJwogICAgJGF1ID0gSm9pbi1QYXRoICR3dSAnQVUnCiAgICB0cnkgewogICAgICAgIGlmICgkRGVzaXJlZC5tYW5hZ2VkKSB7CiAgICAgICAgICAgIEJhY2t1cC1Qb2xpY3lPbmNlCiAgICAgICAgICAgIE5ldy1JdGVtIC1JdGVtVHlwZSBGaWxlIC1QYXRoICRQb2xpY3lPd25lclBhdGggLUZvcmNlIHwgT3V0LU51bGwKICAgICAgICAgICAgU2V0LVJlZ2lzdHJ5RHdvcmQgJHd1ICdTZXREaXNhYmxlVVhXVUFjY2VzcycgKCQoaWYgKCREZXNpcmVkLmJsb2NrX3VzZXJfdXBkYXRlX2FjY2VzcykgeyAxIH0gZWxzZSB7IDAgfSkpCiAgICAgICAgICAgIFNldC1SZWdpc3RyeUR3b3JkICR3dSAnU2V0RGlzYWJsZVBhdXNlVVhBY2Nlc3MnICgkKGlmICgkRGVzaXJlZC5ibG9ja19wYXVzZV91cGRhdGVzKSB7IDEgfSBlbHNlIHsgMCB9KSkKICAgICAgICAgICAgU2V0LVJlZ2lzdHJ5RHdvcmQgJGF1ICdOb0F1dG9VcGRhdGUnIDAKICAgICAgICAgICAgU2V0LVJlZ2lzdHJ5RHdvcmQgJGF1ICdBVU9wdGlvbnMnIDIKICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBbdm9pZF0oUmVzdG9yZS1Qb2xpY3kpCiAgICAgICAgfQogICAgfSBjYXRjaCB7ICRlcnJvcnMuQWRkKCJQb2xpY3kgYXBwbGljYXRpb24gZmFpbGVkOiAkKCRfLkV4Y2VwdGlvbi5NZXNzYWdlKSIpIH0KCiAgICAkdXggPSBHZXQtUmVnaXN0cnlTdGF0ZSAkd3UgJ1NldERpc2FibGVVWFdVQWNjZXNzJwogICAgJHBhdXNlID0gR2V0LVJlZ2lzdHJ5U3RhdGUgJHd1ICdTZXREaXNhYmxlUGF1c2VVWEFjY2VzcycKICAgICRub0F1dG8gPSBHZXQtUmVnaXN0cnlTdGF0ZSAkYXUgJ05vQXV0b1VwZGF0ZScKICAgICRhdU9wdGlvbnMgPSBHZXQtUmVnaXN0cnlTdGF0ZSAkYXUgJ0FVT3B0aW9ucycKICAgICRjb21wbGlhbnQgPSBpZiAoJERlc2lyZWQubWFuYWdlZCkgewogICAgICAgICgoISREZXNpcmVkLmJsb2NrX3VzZXJfdXBkYXRlX2FjY2VzcyAtb3IgKCR1eC5leGlzdHMgLWFuZCBbaW50XSR1eC52YWx1ZSAtZXEgMSkpIC1hbmQKICAgICAgICAgKCEkRGVzaXJlZC5ibG9ja19wYXVzZV91cGRhdGVzIC1vciAoJHBhdXNlLmV4aXN0cyAtYW5kIFtpbnRdJHBhdXNlLnZhbHVlIC1lcSAxKSkgLWFuZAogICAgICAgICAoJG5vQXV0by5leGlzdHMgLWFuZCBbaW50XSRub0F1dG8udmFsdWUgLWVxIDApIC1hbmQKICAgICAgICAgKCRhdU9wdGlvbnMuZXhpc3RzIC1hbmQgW2ludF0kYXVPcHRpb25zLnZhbHVlIC1lcSAyKSAtYW5kCiAgICAgICAgICRlcnJvcnMuQ291bnQgLWVxIDApCiAgICB9IGVsc2UgeyAkZXJyb3JzLkNvdW50IC1lcSAwIH0KCiAgICByZXR1cm4gW3BzY3VzdG9tb2JqZWN0XUB7CiAgICAgICAgY29tcGxpYW50ID0gW2Jvb2xdJGNvbXBsaWFudAogICAgICAgIGVycm9ycyA9IEAoJGVycm9ycykKICAgICAgICB1c2VyX2FjY2Vzc19ibG9ja2VkID0gW2Jvb2xdKCR1eC5leGlzdHMgLWFuZCBbaW50XSR1eC52YWx1ZSAtZXEgMSkKICAgICAgICBwYXVzZV9ibG9ja2VkID0gW2Jvb2xdKCRwYXVzZS5leGlzdHMgLWFuZCBbaW50XSRwYXVzZS52YWx1ZSAtZXEgMSkKICAgICAgICBub19hdXRvX3VwZGF0ZSA9IGlmICgkbm9BdXRvLmV4aXN0cykgeyBbc3RyaW5nXSRub0F1dG8udmFsdWUgfSBlbHNlIHsgJ25vdCBjb25maWd1cmVkJyB9CiAgICAgICAgYXVfb3B0aW9ucyA9IGlmICgkYXVPcHRpb25zLmV4aXN0cykgeyBbc3RyaW5nXSRhdU9wdGlvbnMudmFsdWUgfSBlbHNlIHsgJ25vdCBjb25maWd1cmVkJyB9CiAgICB9Cn0KCmZ1bmN0aW9uIEVuc3VyZS1NaWNyb3NvZnRVcGRhdGVTZXJ2aWNlIHsKICAgICRtYW5hZ2VyID0gTmV3LU9iamVjdCAtQ29tT2JqZWN0ICdNaWNyb3NvZnQuVXBkYXRlLlNlcnZpY2VNYW5hZ2VyJwogICAgJGZvdW5kID0gJGZhbHNlCiAgICB0cnkgewogICAgICAgIGZvciAoJGkgPSAwOyAkaSAtbHQgJG1hbmFnZXIuU2VydmljZXMuQ291bnQ7ICRpKyspIHsKICAgICAgICAgICAgJHNlcnZpY2UgPSAkbWFuYWdlci5TZXJ2aWNlcy5JdGVtKCRpKQogICAgICAgICAgICBpZiAoW3N0cmluZ10kc2VydmljZS5TZXJ2aWNlSUQgLWVxICRNaWNyb3NvZnRVcGRhdGVTZXJ2aWNlSWQpIHsgJGZvdW5kID0gJHRydWU7IGJyZWFrIH0KICAgICAgICB9CiAgICB9IGNhdGNoIHt9CiAgICBpZiAoLW5vdCAkZm91bmQpIHsKICAgICAgICBXcml0ZS1XdUxvZyAnTWljcm9zb2Z0IFVwZGF0ZSBzZXJ2aWNlIHdhcyBub3QgcmVnaXN0ZXJlZDsgcmVnaXN0ZXJpbmcgaXQgZm9yIHRoZSBpc29sYXRlZCB3b3JrZXIuJwogICAgICAgIFt2b2lkXSRtYW5hZ2VyLkFkZFNlcnZpY2UyKCRNaWNyb3NvZnRVcGRhdGVTZXJ2aWNlSWQsIDcsICcnKQogICAgfQogICAgcmV0dXJuICR0cnVlCn0KCmZ1bmN0aW9uIE5ldy1NaWNyb3NvZnRVcGRhdGVTZXNzaW9uIHsKICAgIFt2b2lkXShFbnN1cmUtTWljcm9zb2Z0VXBkYXRlU2VydmljZSkKICAgICRzZXNzaW9uID0gTmV3LU9iamVjdCAtQ29tT2JqZWN0ICdNaWNyb3NvZnQuVXBkYXRlLlNlc3Npb24nCiAgICB0cnkgeyAkc2Vzc2lvbi5DbGllbnRBcHBsaWNhdGlvbklEID0gIk9wZW5QcmltZVJNTSAkTGFiVmVyc2lvbiIgfSBjYXRjaCB7fQogICAgcmV0dXJuICRzZXNzaW9uCn0KCmZ1bmN0aW9uIFNlYXJjaC1NaWNyb3NvZnRVcGRhdGVzKFtib29sXSRIaWRkZW4pIHsKICAgICRzZXNzaW9uID0gTmV3LU1pY3Jvc29mdFVwZGF0ZVNlc3Npb24KICAgICRzZWFyY2hlciA9ICRzZXNzaW9uLkNyZWF0ZVVwZGF0ZVNlYXJjaGVyKCkKICAgICRzZWFyY2hlci5TZXJ2ZXJTZWxlY3Rpb24gPSAzCiAgICAkc2VhcmNoZXIuU2VydmljZUlEID0gJE1pY3Jvc29mdFVwZGF0ZVNlcnZpY2VJZAogICAgJHNlYXJjaGVyLkluY2x1ZGVQb3RlbnRpYWxseVN1cGVyc2VkZWRVcGRhdGVzID0gJGZhbHNlCiAgICAkY3JpdGVyaWEgPSAiSXNJbnN0YWxsZWQ9MCBhbmQgSXNIaWRkZW49IiArICgkKGlmICgkSGlkZGVuKSB7ICcxJyB9IGVsc2UgeyAnMCcgfSkpCiAgICAkcmVzdWx0ID0gJHNlYXJjaGVyLlNlYXJjaCgkY3JpdGVyaWEpCiAgICAkdXBkYXRlcyA9IEAoKQogICAgZm9yICgkaSA9IDA7ICRpIC1sdCAkcmVzdWx0LlVwZGF0ZXMuQ291bnQ7ICRpKyspIHsgJHVwZGF0ZXMgKz0gJHJlc3VsdC5VcGRhdGVzLkl0ZW0oJGkpIH0KICAgIHJldHVybiBbcHNjdXN0b21vYmplY3RdQHsKICAgICAgICBzZXNzaW9uID0gJHNlc3Npb24KICAgICAgICB1cGRhdGVzID0gQCgkdXBkYXRlcykKICAgICAgICByZXN1bHRfY29kZSA9IFtpbnRdJHJlc3VsdC5SZXN1bHRDb2RlCiAgICAgICAgY3JpdGVyaWEgPSAkY3JpdGVyaWEKICAgICAgICBzZXJ2aWNlX2lkID0gJE1pY3Jvc29mdFVwZGF0ZVNlcnZpY2VJZAogICAgfQp9CgpmdW5jdGlvbiBMb2FkLUhpZGRlbkJ5VXMgewogICAgJHN0YXRlID0gUmVhZC1Kc29uRmlsZSAkSGlkZGVuU3RhdGVQYXRoICRudWxsCiAgICBpZiAoJHN0YXRlIC1hbmQgJHN0YXRlLnJ1bGVzKSB7IHJldHVybiBAKCRzdGF0ZS5ydWxlcykgfQogICAgcmV0dXJuIEAoKQp9CgpmdW5jdGlvbiBTYXZlLUhpZGRlbkJ5VXMoJFJ1bGVzKSB7CiAgICBXcml0ZS1Kc29uQXRvbWljICRIaWRkZW5TdGF0ZVBhdGggQHsKICAgICAgICBsYWJfYnVpbGQgPSAkTGFiQnVpbGQKICAgICAgICBydWxlcyA9IEAoJFJ1bGVzKQogICAgICAgIGhpZGRlbl9jb3VudCA9IEAoJFJ1bGVzKS5Db3VudAogICAgICAgIHVwZGF0ZWRfYXQgPSBHZXQtRXBvY2gKICAgIH0gMTAKfQoKZnVuY3Rpb24gRmluZC1NYXRjaGVzKCRVcGRhdGVzLCAkUnVsZSkgewogICAgJG1hdGNoZXMgPSBAKCkKICAgIGZvcmVhY2ggKCR1cGRhdGUgaW4gQCgkVXBkYXRlcykpIHsKICAgICAgICBpZiAoVGVzdC1SdWxlTWF0Y2ggJHVwZGF0ZSAkUnVsZSkgeyAkbWF0Y2hlcyArPSAkdXBkYXRlIH0KICAgIH0KICAgIHJldHVybiBAKCRtYXRjaGVzKQp9CgoKZnVuY3Rpb24gU2V0LVVwZGF0ZUhpZGRlblByb3BlcnR5KCRVcGRhdGUsIFtib29sXSRWYWx1ZSkgewogICAgIyBMYWI3OiBpZiBwbHVtYmluZyBldmVyIGhhbmRzIHRoaXMgYW55dGhpbmcgb3RoZXIgdGhhbiBhIHNpbmdsZSB1cGRhdGUgQ09NCiAgICAjIG9iamVjdCwgZmFpbCBmYXN0IHdpdGggdGhlIHJlYWwgdHlwZSBpbnN0ZWFkIG9mIGEgbWlzbGVhZGluZyBDT00gZXJyb3IuCiAgICBpZiAoJG51bGwgLWVxICRVcGRhdGUpIHsKICAgICAgICByZXR1cm4gW3BzY3VzdG9tb2JqZWN0XUB7IG9rID0gJGZhbHNlOyBtZXRob2QgPSAnZmFpbGVkJzsgZXJyb3IgPSAnSW50ZXJuYWwgZXJyb3I6IHNldHRlciByZWNlaXZlZCAkbnVsbCBpbnN0ZWFkIG9mIGEgc2luZ2xlIHVwZGF0ZSBDT00gb2JqZWN0LicgfQogICAgfQogICAgaWYgKCRVcGRhdGUgLWlzIFtTeXN0ZW0uQXJyYXldKSB7CiAgICAgICAgcmV0dXJuIFtwc2N1c3RvbW9iamVjdF1AeyBvayA9ICRmYWxzZTsgbWV0aG9kID0gJ2ZhaWxlZCc7IGVycm9yID0gIkludGVybmFsIGVycm9yOiBzZXR0ZXIgcmVjZWl2ZWQgYW4gYXJyYXkgb2YgJChAKCRVcGRhdGUpLkNvdW50KSBlbGVtZW50KHMpIGluc3RlYWQgb2YgYSBzaW5nbGUgdXBkYXRlIENPTSBvYmplY3QuIiB9CiAgICB9CiAgICAkdXBkYXRlVHlwZU5hbWUgPSAndW5rbm93bicKICAgIHRyeSB7ICR1cGRhdGVUeXBlTmFtZSA9IFtzdHJpbmddJFVwZGF0ZS5HZXRUeXBlKCkuRnVsbE5hbWUgfSBjYXRjaCB7fQogICAgJGRpcmVjdEVycm9yID0gJG51bGwKICAgIHRyeSB7CiAgICAgICAgIyBOb3JtYWwgV2luZG93cyBQb3dlclNoZWxsIENPTSBsYXRlIGJpbmRpbmcuCiAgICAgICAgJFVwZGF0ZS5Jc0hpZGRlbiA9ICRWYWx1ZQogICAgICAgIHJldHVybiBbcHNjdXN0b21vYmplY3RdQHsKICAgICAgICAgICAgb2sgPSAkdHJ1ZQogICAgICAgICAgICBtZXRob2QgPSAnZGlyZWN0JwogICAgICAgICAgICBlcnJvciA9ICcnCiAgICAgICAgfQogICAgfSBjYXRjaCB7CiAgICAgICAgJGRpcmVjdEVycm9yID0gJF8uRXhjZXB0aW9uLk1lc3NhZ2UKICAgIH0KCiAgICB0cnkgewogICAgICAgICMgU29tZSBXaW5kb3dzIGJ1aWxkcyByZXR1cm4gYSBDT00gd3JhcHBlciB3aG9zZSBzZXR0ZXIgaXMgbm90IHN1cmZhY2VkCiAgICAgICAgIyB0aHJvdWdoIHRoZSBQb3dlclNoZWxsIGFkYXB0ZXIuIEludm9rZSB0aGUgQ09NIHByb3BlcnR5IHRocm91Z2ggSURpc3BhdGNoLgogICAgICAgICRmbGFncyA9IFtTeXN0ZW0uUmVmbGVjdGlvbi5CaW5kaW5nRmxhZ3NdOjpTZXRQcm9wZXJ0eQogICAgICAgICRjdWx0dXJlID0gW1N5c3RlbS5HbG9iYWxpemF0aW9uLkN1bHR1cmVJbmZvXTo6SW52YXJpYW50Q3VsdHVyZQogICAgICAgIFt2b2lkXSRVcGRhdGUuR2V0VHlwZSgpLkludm9rZU1lbWJlcigKICAgICAgICAgICAgJ0lzSGlkZGVuJywKICAgICAgICAgICAgJGZsYWdzLAogICAgICAgICAgICAkbnVsbCwKICAgICAgICAgICAgJFVwZGF0ZSwKICAgICAgICAgICAgQChbb2JqZWN0XSRWYWx1ZSksCiAgICAgICAgICAgICRjdWx0dXJlCiAgICAgICAgKQogICAgICAgIHJldHVybiBbcHNjdXN0b21vYmplY3RdQHsKICAgICAgICAgICAgb2sgPSAkdHJ1ZQogICAgICAgICAgICBtZXRob2QgPSAnaWRpc3BhdGNoJwogICAgICAgICAgICBlcnJvciA9ICcnCiAgICAgICAgfQogICAgfSBjYXRjaCB7CiAgICAgICAgJGZhbGxiYWNrRXJyb3IgPSAkXy5FeGNlcHRpb24uTWVzc2FnZQogICAgICAgIHJldHVybiBbcHNjdXN0b21vYmplY3RdQHsKICAgICAgICAgICAgb2sgPSAkZmFsc2UKICAgICAgICAgICAgbWV0aG9kID0gJ2ZhaWxlZCcKICAgICAgICAgICAgZXJyb3IgPSAiT2JqZWN0IHR5cGU6ICR1cGRhdGVUeXBlTmFtZSB8IERpcmVjdCBzZXR0ZXI6ICRkaXJlY3RFcnJvciB8IElEaXNwYXRjaCBzZXR0ZXI6ICRmYWxsYmFja0Vycm9yIgogICAgICAgIH0KICAgIH0KfQoKZnVuY3Rpb24gR2V0LVZpc2liaWxpdHlTbmFwc2hvdCB7CiAgICAkdmlzaWJsZVNlYXJjaCA9IFNlYXJjaC1NaWNyb3NvZnRVcGRhdGVzICRmYWxzZQogICAgJGhpZGRlblNlYXJjaCA9IFNlYXJjaC1NaWNyb3NvZnRVcGRhdGVzICR0cnVlCiAgICByZXR1cm4gW3BzY3VzdG9tb2JqZWN0XUB7CiAgICAgICAgdmlzaWJsZV9zZWFyY2ggPSAkdmlzaWJsZVNlYXJjaAogICAgICAgIGhpZGRlbl9zZWFyY2ggPSAkaGlkZGVuU2VhcmNoCiAgICAgICAgdmlzaWJsZV91cGRhdGVzID0gQCgkdmlzaWJsZVNlYXJjaC51cGRhdGVzKQogICAgICAgIGhpZGRlbl91cGRhdGVzID0gQCgkaGlkZGVuU2VhcmNoLnVwZGF0ZXMpCiAgICB9Cn0KCmZ1bmN0aW9uIFdyaXRlLUludmVudG9yeVNuYXBzaG90KCRJbnZlbnRvcnksICRWaXNpYmlsaXR5LCAkRGVzaXJlZCwgJEVycm9ycywgJFdhcm5pbmdzLCBbc3RyaW5nXSRQaGFzZSkgewogICAgJHBheWxvYWQgPSBAewogICAgICAgIGxhYl9idWlsZCA9ICRMYWJCdWlsZAogICAgICAgIGxhYl92ZXJzaW9uID0gJExhYlZlcnNpb24KICAgICAgICBwaGFzZSA9ICRQaGFzZQogICAgICAgIHNlcnZpY2UgPSAnTWljcm9zb2Z0IFVwZGF0ZScKICAgICAgICBzZXJ2aWNlX2lkID0gJE1pY3Jvc29mdFVwZGF0ZVNlcnZpY2VJZAogICAgICAgIHNjYW5uZWRfYXQgPSBHZXQtRXBvY2gKICAgICAgICBsb2NhbF9wb2xpY3kgPSBAewogICAgICAgICAgICBpbmNsdWRlX29wdGlvbmFsX3VwZGF0ZXMgPSBbYm9vbF0kRGVzaXJlZC5pbmNsdWRlX29wdGlvbmFsX3VwZGF0ZXMKICAgICAgICAgICAgaW5jbHVkZV9kcml2ZXJfdXBkYXRlcyA9IFtib29sXSREZXNpcmVkLmluY2x1ZGVfZHJpdmVyX3VwZGF0ZXMKICAgICAgICAgICAgaW5jbHVkZV9maXJtd2FyZV91cGRhdGVzID0gW2Jvb2xdJERlc2lyZWQuaW5jbHVkZV9maXJtd2FyZV91cGRhdGVzCiAgICAgICAgICAgIGluY2x1ZGVfZmVhdHVyZV91cGRhdGVzID0gW2Jvb2xdJERlc2lyZWQuaW5jbHVkZV9mZWF0dXJlX3VwZGF0ZXMKICAgICAgICAgICAgc2VydmVyX2luY2x1ZGVfcHJldmlldyA9IFtib29sXSREZXNpcmVkLnNlcnZlcl9pbmNsdWRlX3ByZXZpZXcKICAgICAgICB9CiAgICAgICAgY291bnRzID0gQHsKICAgICAgICAgICAgdmlzaWJsZSA9IFtpbnRdJEludmVudG9yeS52aXNpYmxlX2NvdW50CiAgICAgICAgICAgIHJlcG9ydGVkID0gW2ludF0kSW52ZW50b3J5LnJlcG9ydGVkX2NvdW50CiAgICAgICAgICAgIGV4Y2x1ZGVkID0gW2ludF0kSW52ZW50b3J5LmV4Y2x1ZGVkX2NvdW50CiAgICAgICAgICAgIHN0YW5kYXJkID0gW2ludF0kSW52ZW50b3J5LnN0YW5kYXJkX2NvdW50CiAgICAgICAgICAgIG9wdGlvbmFsID0gW2ludF0kSW52ZW50b3J5Lm9wdGlvbmFsX2NvdW50CiAgICAgICAgICAgIGRyaXZlciA9IFtpbnRdJEludmVudG9yeS5kcml2ZXJfY291bnQKICAgICAgICAgICAgZmlybXdhcmUgPSBbaW50XSRJbnZlbnRvcnkuZmlybXdhcmVfY291bnQKICAgICAgICAgICAgZmVhdHVyZSA9IFtpbnRdJEludmVudG9yeS5mZWF0dXJlX2NvdW50CiAgICAgICAgICAgIGhpZGRlbl9ieV9wcmltZW5ldGNvcmUgPSBbaW50XSRWaXNpYmlsaXR5LmhpZGRlbl9jb3VudAogICAgICAgIH0KICAgICAgICB2aXNpYmxlX3VwZGF0ZXMgPSBAKCRJbnZlbnRvcnkudmlzaWJsZV9pbnZlbnRvcnkpCiAgICAgICAgaGlkZGVuX2J5X3ByaW1lbmV0Y29yZSA9IEAoJEludmVudG9yeS5oaWRkZW5faW52ZW50b3J5KQogICAgICAgIGV4Y2x1ZGVkX2J5X3BvbGljeSA9IEAoJEludmVudG9yeS5leGNsdWRlZF9pbnZlbnRvcnkpCiAgICAgICAgZXJyb3JzID0gQCgkRXJyb3JzKQogICAgICAgIHdhcm5pbmdzID0gQCgkV2FybmluZ3MpCiAgICB9CgogICAgIyBDYW5vbmljYWwgZG9jdW1lbnRlZCBuYW1lLgogICAgV3JpdGUtSnNvbkF0b21pYyAkSW52ZW50b3J5UGF0aCAkcGF5bG9hZCAxMgogICAgIyBDb21wYXRpYmlsaXR5IGFsaWFzIGZvciBsYWI1IHNjcmlwdHMgYW5kIHByaW9yIGRvY3VtZW50YXRpb24uCiAgICBXcml0ZS1Kc29uQXRvbWljICRMZWdhY3lJbnZlbnRvcnlQYXRoICRwYXlsb2FkIDEyCn0KCmZ1bmN0aW9uIFNldC1EZW5pZWRWaXNpYmlsaXR5KCREZXNpcmVkUnVsZXMsIFtib29sXSRFbmZvcmNlSGlkZSkgewogICAgJGRlc2lyZWQgPSBpZiAoJEVuZm9yY2VIaWRlKSB7IEAoJERlc2lyZWRSdWxlcykgfSBlbHNlIHsgQCgpIH0KICAgICR0cmFja2VkID0gQChMb2FkLUhpZGRlbkJ5VXMpCiAgICAkZXJyb3JzID0gTmV3LU9iamVjdCBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0W3N0cmluZ10KICAgICR3YXJuaW5ncyA9IE5ldy1PYmplY3QgU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdFtzdHJpbmddCiAgICAkZGVueU1hdGNoZXMgPSAwCiAgICAkZGVueU5vdEZvdW5kID0gMAogICAgJGhpZGVBdHRlbXB0ZWQgPSAwCiAgICAkaGlkZVN1Y2NlZWRlZCA9IDAKICAgICRoaWRlVmVyaWZpZWQgPSAwCiAgICAkaGlkZURpcmVjdCA9IDAKICAgICRoaWRlRmFsbGJhY2sgPSAwCiAgICAkaGlkZVNldHRlckZhaWxlZCA9IDAKICAgICR1bmhpZGVBdHRlbXB0ZWQgPSAwCiAgICAkdW5oaWRlU3VjY2VlZGVkID0gMAogICAgJHVuaGlkZVZlcmlmaWVkID0gMAogICAgJHVuaGlkZURpcmVjdCA9IDAKICAgICR1bmhpZGVGYWxsYmFjayA9IDAKICAgICR1bmhpZGVTZXR0ZXJGYWlsZWQgPSAwCgogICAgJHZpc2libGVTZWFyY2ggPSBTZWFyY2gtTWljcm9zb2Z0VXBkYXRlcyAkZmFsc2UKICAgICRoaWRkZW5TZWFyY2ggPSBTZWFyY2gtTWljcm9zb2Z0VXBkYXRlcyAkdHJ1ZQogICAgJHZpc2libGUgPSBAKCR2aXNpYmxlU2VhcmNoLnVwZGF0ZXMpCiAgICAkaGlkZGVuID0gQCgkaGlkZGVuU2VhcmNoLnVwZGF0ZXMpCgogICAgZm9yZWFjaCAoJHJ1bGUgaW4gJGRlc2lyZWQpIHsKICAgICAgICAkdmlzaWJsZU1hdGNoZXMgPSBAKEZpbmQtTWF0Y2hlcyAkdmlzaWJsZSAkcnVsZSkKICAgICAgICAkaGlkZGVuTWF0Y2hlcyA9IEAoRmluZC1NYXRjaGVzICRoaWRkZW4gJHJ1bGUpCiAgICAgICAgaWYgKCR2aXNpYmxlTWF0Y2hlcy5Db3VudCAtZXEgMCAtYW5kICRoaWRkZW5NYXRjaGVzLkNvdW50IC1lcSAwKSB7CiAgICAgICAgICAgICRkZW55Tm90Rm91bmQrKwogICAgICAgICAgICBXcml0ZS1XdUxvZyAiRGVuaWVkIHJ1bGUgbm90IGZvdW5kIGluIGN1cnJlbnQgY2F0YWxvZyAoaW5zdGFsbGVkLCBzdXBlcnNlZGVkLCBvciBub3QgYXBwbGljYWJsZSk6ICQoW3N0cmluZ10kcnVsZS50aXRsZSkiCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgfQogICAgICAgICRkZW55TWF0Y2hlcysrCiAgICAgICAgaWYgKCRoaWRkZW5NYXRjaGVzLkNvdW50IC1ndCAwKSB7IGNvbnRpbnVlIH0KICAgICAgICBmb3JlYWNoICgkdXBkYXRlIGluICR2aXNpYmxlTWF0Y2hlcykgewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgJGhpZGVBdHRlbXB0ZWQrKwogICAgICAgICAgICAgICAgaWYgKFtib29sXSR1cGRhdGUuSXNNYW5kYXRvcnkpIHsgdGhyb3cgJ1dpbmRvd3MgbWFya3MgdGhpcyB1cGRhdGUgbWFuZGF0b3J5OyBpdCBjYW5ub3QgYmUgaGlkZGVuLicgfQogICAgICAgICAgICAgICAgJHNldFJlc3VsdCA9IFNldC1VcGRhdGVIaWRkZW5Qcm9wZXJ0eSAkdXBkYXRlICR0cnVlCiAgICAgICAgICAgICAgICBpZiAoLW5vdCAkc2V0UmVzdWx0Lm9rKSB7CiAgICAgICAgICAgICAgICAgICAgJGhpZGVTZXR0ZXJGYWlsZWQrKwogICAgICAgICAgICAgICAgICAgIHRocm93ICRzZXRSZXN1bHQuZXJyb3IKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGlmICgkc2V0UmVzdWx0Lm1ldGhvZCAtZXEgJ2RpcmVjdCcpIHsgJGhpZGVEaXJlY3QrKyB9IGVsc2UgeyAkaGlkZUZhbGxiYWNrKysgfQogICAgICAgICAgICAgICAgJGhpZGVTdWNjZWVkZWQrKwogICAgICAgICAgICAgICAgJGlkZW50aXR5ID0gR2V0LVVwZGF0ZUlkZW50aXR5ICR1cGRhdGUKICAgICAgICAgICAgICAgIGlmICgtbm90IEAoJHRyYWNrZWQgfCBXaGVyZS1PYmplY3QgeyBUZXN0LVJ1bGVFcXVpdmFsZW50ICRfICRpZGVudGl0eSB9KS5Db3VudCkgewogICAgICAgICAgICAgICAgICAgICR0cmFja2VkICs9ICRpZGVudGl0eQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9IGNhdGNoIHsKICAgICAgICAgICAgICAgICRlcnJvcnMuQWRkKCJIaWRlIGZhaWxlZDogJChbc3RyaW5nXSR1cGRhdGUuVGl0bGUpIC0gJCgkXy5FeGNlcHRpb24uTWVzc2FnZSkiKQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfQoKICAgICRyZW1vdmVkID0gQCgkdHJhY2tlZCB8IFdoZXJlLU9iamVjdCB7CiAgICAgICAgJHJlY29yZCA9ICRfCiAgICAgICAgLW5vdCBAKCRkZXNpcmVkIHwgV2hlcmUtT2JqZWN0IHsgVGVzdC1SdWxlRXF1aXZhbGVudCAkXyAkcmVjb3JkIH0pLkNvdW50CiAgICB9KQogICAgZm9yZWFjaCAoJHJlY29yZCBpbiAkcmVtb3ZlZCkgewogICAgICAgICRtYXRjaGVzID0gQChGaW5kLU1hdGNoZXMgJGhpZGRlbiAkcmVjb3JkKQogICAgICAgIGlmICgtbm90ICRtYXRjaGVzLkNvdW50KSB7CiAgICAgICAgICAgICR3YXJuaW5ncy5BZGQoIlByZXZpb3VzbHkgaGlkZGVuIHVwZGF0ZSBpcyBubyBsb25nZXIgaW4gdGhlIGhpZGRlbiBjYXRhbG9nOyBpdCBtYXkgYmUgaW5zdGFsbGVkIG9yIHN1cGVyc2VkZWQ6ICQoW3N0cmluZ10kcmVjb3JkLnRpdGxlKSIpCiAgICAgICAgICAgICR0cmFja2VkID0gQCgkdHJhY2tlZCB8IFdoZXJlLU9iamVjdCB7IC1ub3QgKFRlc3QtUnVsZUVxdWl2YWxlbnQgJF8gJHJlY29yZCkgfSkKICAgICAgICAgICAgY29udGludWUKICAgICAgICB9CiAgICAgICAgZm9yZWFjaCAoJHVwZGF0ZSBpbiAkbWF0Y2hlcykgewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgJHVuaGlkZUF0dGVtcHRlZCsrCiAgICAgICAgICAgICAgICAkc2V0UmVzdWx0ID0gU2V0LVVwZGF0ZUhpZGRlblByb3BlcnR5ICR1cGRhdGUgJGZhbHNlCiAgICAgICAgICAgICAgICBpZiAoLW5vdCAkc2V0UmVzdWx0Lm9rKSB7CiAgICAgICAgICAgICAgICAgICAgJHVuaGlkZVNldHRlckZhaWxlZCsrCiAgICAgICAgICAgICAgICAgICAgdGhyb3cgJHNldFJlc3VsdC5lcnJvcgogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgaWYgKCRzZXRSZXN1bHQubWV0aG9kIC1lcSAnZGlyZWN0JykgeyAkdW5oaWRlRGlyZWN0KysgfSBlbHNlIHsgJHVuaGlkZUZhbGxiYWNrKysgfQogICAgICAgICAgICAgICAgJHVuaGlkZVN1Y2NlZWRlZCsrCiAgICAgICAgICAgIH0gY2F0Y2ggewogICAgICAgICAgICAgICAgJGVycm9ycy5BZGQoIlVuaGlkZSBmYWlsZWQ6ICQoW3N0cmluZ10kdXBkYXRlLlRpdGxlKSAtICQoJF8uRXhjZXB0aW9uLk1lc3NhZ2UpIikKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KCiAgICBpZiAoJGhpZGVBdHRlbXB0ZWQgLWd0IDAgLW9yICR1bmhpZGVBdHRlbXB0ZWQgLWd0IDApIHsKICAgICAgICAkdmlzaWJsZVNlYXJjaCA9IFNlYXJjaC1NaWNyb3NvZnRVcGRhdGVzICRmYWxzZQogICAgICAgICRoaWRkZW5TZWFyY2ggPSBTZWFyY2gtTWljcm9zb2Z0VXBkYXRlcyAkdHJ1ZQogICAgICAgICR2aXNpYmxlID0gQCgkdmlzaWJsZVNlYXJjaC51cGRhdGVzKQogICAgICAgICRoaWRkZW4gPSBAKCRoaWRkZW5TZWFyY2gudXBkYXRlcykKICAgIH0KCiAgICBmb3JlYWNoICgkcnVsZSBpbiAkZGVzaXJlZCkgewogICAgICAgIGlmIChAKEZpbmQtTWF0Y2hlcyAkaGlkZGVuICRydWxlKS5Db3VudCAtZ3QgMCkgewogICAgICAgICAgICAkaGlkZVZlcmlmaWVkKysKICAgICAgICB9IGVsc2VpZiAoQChGaW5kLU1hdGNoZXMgJHZpc2libGUgJHJ1bGUpLkNvdW50IC1ndCAwKSB7CiAgICAgICAgICAgICRlcnJvcnMuQWRkKCJEZW5pZWQgdXBkYXRlIHJlbWFpbnMgdmlzaWJsZSBhZnRlciBoaWRlIGVuZm9yY2VtZW50OiAkKFtzdHJpbmddJHJ1bGUudGl0bGUpIikKICAgICAgICB9CiAgICB9CgogICAgZm9yZWFjaCAoJHJlY29yZCBpbiAkcmVtb3ZlZCkgewogICAgICAgIGlmIChAKEZpbmQtTWF0Y2hlcyAkdmlzaWJsZSAkcmVjb3JkKS5Db3VudCAtZ3QgMCkgewogICAgICAgICAgICAkdW5oaWRlVmVyaWZpZWQrKwogICAgICAgICAgICAkdHJhY2tlZCA9IEAoJHRyYWNrZWQgfCBXaGVyZS1PYmplY3QgeyAtbm90IChUZXN0LVJ1bGVFcXVpdmFsZW50ICRfICRyZWNvcmQpIH0pCiAgICAgICAgfSBlbHNlaWYgKEAoRmluZC1NYXRjaGVzICRoaWRkZW4gJHJlY29yZCkuQ291bnQgLWd0IDApIHsKICAgICAgICAgICAgJGVycm9ycy5BZGQoIlJlc3RvcmVkIHVwZGF0ZSByZW1haW5zIGhpZGRlbiBhZnRlciB1bmhpZGUgZW5mb3JjZW1lbnQ6ICQoW3N0cmluZ10kcmVjb3JkLnRpdGxlKSIpCiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgJHRyYWNrZWQgPSBAKCR0cmFja2VkIHwgV2hlcmUtT2JqZWN0IHsgLW5vdCAoVGVzdC1SdWxlRXF1aXZhbGVudCAkXyAkcmVjb3JkKSB9KQogICAgICAgIH0KICAgIH0KCiAgICAjIEtlZXAgb25seSByZWNvcmRzIHRoYXQgYXJlIHN0aWxsIGRlc2lyZWQgYW5kIHZlcmlmaWVkIGhpZGRlbi4KICAgICR2ZXJpZmllZFRyYWNrZWQgPSBAKCkKICAgIGZvcmVhY2ggKCRyZWNvcmQgaW4gJHRyYWNrZWQpIHsKICAgICAgICAkc3RpbGxEZXNpcmVkID0gQCgkZGVzaXJlZCB8IFdoZXJlLU9iamVjdCB7IFRlc3QtUnVsZUVxdWl2YWxlbnQgJF8gJHJlY29yZCB9KS5Db3VudCAtZ3QgMAogICAgICAgICRzdGlsbEhpZGRlbiA9IEAoRmluZC1NYXRjaGVzICRoaWRkZW4gJHJlY29yZCkuQ291bnQgLWd0IDAKICAgICAgICBpZiAoJHN0aWxsRGVzaXJlZCAtYW5kICRzdGlsbEhpZGRlbikgeyAkdmVyaWZpZWRUcmFja2VkICs9ICRyZWNvcmQgfQogICAgfQogICAgU2F2ZS1IaWRkZW5CeVVzICR2ZXJpZmllZFRyYWNrZWQKCiAgICAkbWFuYWdlZEhpZGRlbkNvdW50ID0gMAogICAgZm9yZWFjaCAoJHVwZGF0ZSBpbiAkaGlkZGVuKSB7CiAgICAgICAgaWYgKEAoJHZlcmlmaWVkVHJhY2tlZCB8IFdoZXJlLU9iamVjdCB7IFRlc3QtUnVsZU1hdGNoICR1cGRhdGUgJF8gfSkuQ291bnQgLWd0IDApIHsgJG1hbmFnZWRIaWRkZW5Db3VudCsrIH0KICAgIH0KCiAgICByZXR1cm4gW3BzY3VzdG9tb2JqZWN0XUB7CiAgICAgICAgdmlzaWJsZV91cGRhdGVzID0gQCgkdmlzaWJsZSkKICAgICAgICBoaWRkZW5fdXBkYXRlcyA9IEAoJGhpZGRlbikKICAgICAgICBkZW55X3J1bGVzX3JlY2VpdmVkID0gQCgkZGVzaXJlZCkuQ291bnQKICAgICAgICBkZW55X21hdGNoZXNfZm91bmQgPSAkZGVueU1hdGNoZXMKICAgICAgICBkZW55X25vdF9mb3VuZCA9ICRkZW55Tm90Rm91bmQKICAgICAgICBoaWRlX2F0dGVtcHRlZCA9ICRoaWRlQXR0ZW1wdGVkCiAgICAgICAgaGlkZV9zdWNjZWVkZWQgPSAkaGlkZVN1Y2NlZWRlZAogICAgICAgIGhpZGVfdmVyaWZpZWQgPSAkaGlkZVZlcmlmaWVkCiAgICAgICAgaGlkZV9kaXJlY3QgPSAkaGlkZURpcmVjdAogICAgICAgIGhpZGVfZmFsbGJhY2sgPSAkaGlkZUZhbGxiYWNrCiAgICAgICAgaGlkZV9zZXR0ZXJfZmFpbGVkID0gJGhpZGVTZXR0ZXJGYWlsZWQKICAgICAgICB1bmhpZGVfYXR0ZW1wdGVkID0gJHVuaGlkZUF0dGVtcHRlZAogICAgICAgIHVuaGlkZV9zdWNjZWVkZWQgPSAkdW5oaWRlU3VjY2VlZGVkCiAgICAgICAgdW5oaWRlX3ZlcmlmaWVkID0gJHVuaGlkZVZlcmlmaWVkCiAgICAgICAgdW5oaWRlX2RpcmVjdCA9ICR1bmhpZGVEaXJlY3QKICAgICAgICB1bmhpZGVfZmFsbGJhY2sgPSAkdW5oaWRlRmFsbGJhY2sKICAgICAgICB1bmhpZGVfc2V0dGVyX2ZhaWxlZCA9ICR1bmhpZGVTZXR0ZXJGYWlsZWQKICAgICAgICBoaWRkZW5fY291bnQgPSAkbWFuYWdlZEhpZGRlbkNvdW50CiAgICAgICAgdHJhY2tlZF9ydWxlcyA9IEAoJHZlcmlmaWVkVHJhY2tlZCkKICAgICAgICBlcnJvcnMgPSBAKCRlcnJvcnMpCiAgICAgICAgd2FybmluZ3MgPSBAKCR3YXJuaW5ncykKICAgICAgICBzZXJ2aWNlX2lkID0gW3N0cmluZ10kdmlzaWJsZVNlYXJjaC5zZXJ2aWNlX2lkCiAgICB9Cn0KCmZ1bmN0aW9uIFRlc3QtVXBkYXRlQWxsb3dlZCgkRGV0YWlsZWQsICREZXNpcmVkKSB7CiAgICBzd2l0Y2ggKFtzdHJpbmddJERldGFpbGVkLmNsYXNzKSB7CiAgICAgICAgJ29wdGlvbmFsJyB7IHJldHVybiBbYm9vbF0kRGVzaXJlZC5pbmNsdWRlX29wdGlvbmFsX3VwZGF0ZXMgfQogICAgICAgICdkcml2ZXInIHsgcmV0dXJuIFtib29sXSREZXNpcmVkLmluY2x1ZGVfZHJpdmVyX3VwZGF0ZXMgfQogICAgICAgICdmaXJtd2FyZScgeyByZXR1cm4gW2Jvb2xdJERlc2lyZWQuaW5jbHVkZV9maXJtd2FyZV91cGRhdGVzIH0KICAgICAgICAnZmVhdHVyZScgeyByZXR1cm4gW2Jvb2xdJERlc2lyZWQuaW5jbHVkZV9mZWF0dXJlX3VwZGF0ZXMgfQogICAgICAgIGRlZmF1bHQgeyByZXR1cm4gJHRydWUgfQogICAgfQp9CgpmdW5jdGlvbiBCdWlsZC1JbnZlbnRvcnkoJFZpc2libGVVcGRhdGVzLCAkSGlkZGVuVXBkYXRlcywgJFRyYWNrZWRSdWxlcywgJERlc2lyZWQpIHsKICAgICR2aXNpYmxlRGV0YWlsZWQgPSBAKCkKICAgICRoaWRkZW5EZXRhaWxlZCA9IEAoKQogICAgJHJlcG9ydGVkID0gQCgpCiAgICAkZXhjbHVkZWQgPSBAKCkKICAgICRjb3VudHMgPSBAeyBzdGFuZGFyZD0wOyBvcHRpb25hbD0wOyBkcml2ZXI9MDsgZmlybXdhcmU9MDsgZmVhdHVyZT0wIH0KICAgICRzZWVuID0gQHt9CgogICAgZm9yZWFjaCAoJHVwZGF0ZSBpbiBAKCRWaXNpYmxlVXBkYXRlcykpIHsKICAgICAgICAkZGV0YWlsID0gQ29udmVydFRvLURldGFpbGVkVXBkYXRlICR1cGRhdGUgJGZhbHNlICRmYWxzZQogICAgICAgICRrZXkgPSAoQ29udmVydFRvLVVwZGF0ZUtleSAoW3N0cmluZ10kZGV0YWlsLnVwZGF0ZV9pZCkpICsgJ3wnICsgW3N0cmluZ10kZGV0YWlsLnJldmlzaW9uCiAgICAgICAgaWYgKCRzZWVuLkNvbnRhaW5zS2V5KCRrZXkpKSB7IGNvbnRpbnVlIH0KICAgICAgICAkc2Vlblska2V5XSA9ICR0cnVlCiAgICAgICAgJHZpc2libGVEZXRhaWxlZCArPSAkZGV0YWlsCiAgICAgICAgaWYgKCRjb3VudHMuQ29udGFpbnNLZXkoW3N0cmluZ10kZGV0YWlsLmNsYXNzKSkgeyAkY291bnRzW1tzdHJpbmddJGRldGFpbC5jbGFzc10rKyB9CiAgICAgICAgaWYgKFRlc3QtVXBkYXRlQWxsb3dlZCAkZGV0YWlsICREZXNpcmVkKSB7CiAgICAgICAgICAgICRyZXBvcnRlZCArPSBDb252ZXJ0VG8tU2VydmVyVXBkYXRlICRkZXRhaWwKICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAkZXhjbHVkZWQgKz0gJGRldGFpbAogICAgICAgIH0KICAgIH0KCiAgICBmb3JlYWNoICgkdXBkYXRlIGluIEAoJEhpZGRlblVwZGF0ZXMpKSB7CiAgICAgICAgJG1hbmFnZWQgPSBAKCRUcmFja2VkUnVsZXMgfCBXaGVyZS1PYmplY3QgeyBUZXN0LVJ1bGVNYXRjaCAkdXBkYXRlICRfIH0pLkNvdW50IC1ndCAwCiAgICAgICAgaWYgKC1ub3QgJG1hbmFnZWQpIHsgY29udGludWUgfQogICAgICAgICRoaWRkZW5EZXRhaWxlZCArPSBDb252ZXJ0VG8tRGV0YWlsZWRVcGRhdGUgJHVwZGF0ZSAkdHJ1ZSAkdHJ1ZQogICAgfQoKICAgIHJldHVybiBbcHNjdXN0b21vYmplY3RdQHsKICAgICAgICByZXBvcnRlZF91cGRhdGVzID0gQCgkcmVwb3J0ZWQpCiAgICAgICAgdmlzaWJsZV9pbnZlbnRvcnkgPSBAKCR2aXNpYmxlRGV0YWlsZWQpCiAgICAgICAgaGlkZGVuX2ludmVudG9yeSA9IEAoJGhpZGRlbkRldGFpbGVkKQogICAgICAgIGV4Y2x1ZGVkX2ludmVudG9yeSA9IEAoJGV4Y2x1ZGVkKQogICAgICAgIHN0YW5kYXJkX2NvdW50ID0gW2ludF0kY291bnRzLnN0YW5kYXJkCiAgICAgICAgb3B0aW9uYWxfY291bnQgPSBbaW50XSRjb3VudHMub3B0aW9uYWwKICAgICAgICBkcml2ZXJfY291bnQgPSBbaW50XSRjb3VudHMuZHJpdmVyCiAgICAgICAgZmlybXdhcmVfY291bnQgPSBbaW50XSRjb3VudHMuZmlybXdhcmUKICAgICAgICBmZWF0dXJlX2NvdW50ID0gW2ludF0kY291bnRzLmZlYXR1cmUKICAgICAgICB2aXNpYmxlX2NvdW50ID0gQCgkdmlzaWJsZURldGFpbGVkKS5Db3VudAogICAgICAgIHJlcG9ydGVkX2NvdW50ID0gQCgkcmVwb3J0ZWQpLkNvdW50CiAgICAgICAgZXhjbHVkZWRfY291bnQgPSBAKCRleGNsdWRlZCkuQ291bnQKICAgIH0KfQoKZnVuY3Rpb24gVGVzdC1SZWJvb3RSZXF1aXJlZCB7CiAgICBmb3JlYWNoICgka2V5IGluIEAoCiAgICAgICAgJ0hLTE06XFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFdpbmRvd3NVcGRhdGVcQXV0byBVcGRhdGVcUmVib290UmVxdWlyZWQnLAogICAgICAgICdIS0xNOlxTT0ZUV0FSRVxNaWNyb3NvZnRcV2luZG93c1xDdXJyZW50VmVyc2lvblxDb21wb25lbnQgQmFzZWQgU2VydmljaW5nXFJlYm9vdFBlbmRpbmcnCiAgICApKSB7IGlmIChUZXN0LVBhdGggJGtleSkgeyByZXR1cm4gJHRydWUgfSB9CiAgICB0cnkgeyByZXR1cm4gW2Jvb2xdKE5ldy1PYmplY3QgLUNvbU9iamVjdCAnTWljcm9zb2Z0LlVwZGF0ZS5TeXN0ZW1JbmZvJykuUmVib290UmVxdWlyZWQgfQogICAgY2F0Y2ggeyByZXR1cm4gJGZhbHNlIH0KfQoKZnVuY3Rpb24gUnVuLVNjYW4gewogICAgJHN0YXJ0ZWQgPSBHZXQtRXBvY2gKICAgICRkZXNpcmVkID0gUmVzb2x2ZS1EZXNpcmVkU3RhdGUKICAgICRwb2xpY3kgPSBBcHBseS1BbmQtVmVyaWZ5UG9saWN5ICRkZXNpcmVkCgogICAgIyBBbHdheXMgY3JlYXRlIGFuIGludmVudG9yeSBiZWZvcmUgaGlkZS91bmhpZGUgZW5mb3JjZW1lbnQuIEEgV2luZG93cyBDT00KICAgICMgc2V0dGVyIGNvbXBhdGliaWxpdHkgcHJvYmxlbSBtdXN0IG5ldmVyIHN1cHByZXNzIHVwZGF0ZSBkaXNjb3ZlcnkuCiAgICAkcHJlRXJyb3JzID0gQCgkcG9saWN5LmVycm9ycykKICAgICRwcmVXYXJuaW5ncyA9IEAoKQogICAgJHRyYWNrZWRCZWZvcmUgPSBAKExvYWQtSGlkZGVuQnlVcykKCiAgICB0cnkgewogICAgICAgICRzbmFwc2hvdCA9IEdldC1WaXNpYmlsaXR5U25hcHNob3QKICAgICAgICAkcHJlSW52ZW50b3J5ID0gQnVpbGQtSW52ZW50b3J5ICRzbmFwc2hvdC52aXNpYmxlX3VwZGF0ZXMgJHNuYXBzaG90LmhpZGRlbl91cGRhdGVzICR0cmFja2VkQmVmb3JlICRkZXNpcmVkCiAgICAgICAgJHByZVZpc2liaWxpdHkgPSBbcHNjdXN0b21vYmplY3RdQHsKICAgICAgICAgICAgaGlkZGVuX2NvdW50ID0gQCgkcHJlSW52ZW50b3J5LmhpZGRlbl9pbnZlbnRvcnkpLkNvdW50CiAgICAgICAgfQogICAgICAgIFdyaXRlLUludmVudG9yeVNuYXBzaG90ICRwcmVJbnZlbnRvcnkgJHByZVZpc2liaWxpdHkgJGRlc2lyZWQgJHByZUVycm9ycyAkcHJlV2FybmluZ3MgJ3ByZS1lbmZvcmNlbWVudCcKICAgIH0gY2F0Y2ggewogICAgICAgICRwcmVFcnJvcnMgKz0gIkluaXRpYWwgaW52ZW50b3J5IGZhaWxlZDogJCgkXy5FeGNlcHRpb24uTWVzc2FnZSkiCiAgICAgICAgV3JpdGUtV3VMb2cgIkluaXRpYWwgaW52ZW50b3J5IGZhaWxlZDogJCgkXy5FeGNlcHRpb24uTWVzc2FnZSkiCiAgICB9CgogICAgdHJ5IHsKICAgICAgICAkdmlzaWJpbGl0eSA9IFNldC1EZW5pZWRWaXNpYmlsaXR5ICRkZXNpcmVkLmRlbmllZF91cGRhdGVzIChbYm9vbF0oJGRlc2lyZWQubWFuYWdlZCAtYW5kICRkZXNpcmVkLmhpZGVfZGVuaWVkX3VwZGF0ZXMpKQogICAgfSBjYXRjaCB7CiAgICAgICAgIyBQcmVzZXJ2ZSBpbnZlbnRvcnkgYW5kIHJlcG9ydCBhIGRlZ3JhZGVkIGVuZm9yY2VtZW50IHN0YXRlIGluc3RlYWQgb2YKICAgICAgICAjIGZhaWxpbmcgdGhlIHdob2xlIHNjYW4uCiAgICAgICAgJGVuZm9yY2VtZW50RXJyb3IgPSAiVmlzaWJpbGl0eSBlbmZvcmNlbWVudCBmYWlsZWQ6ICQoJF8uRXhjZXB0aW9uLk1lc3NhZ2UpIgogICAgICAgIFdyaXRlLVd1TG9nICRlbmZvcmNlbWVudEVycm9yCiAgICAgICAgJGZhbGxiYWNrU25hcHNob3QgPSBHZXQtVmlzaWJpbGl0eVNuYXBzaG90CiAgICAgICAgJHZpc2liaWxpdHkgPSBbcHNjdXN0b21vYmplY3RdQHsKICAgICAgICAgICAgdmlzaWJsZV91cGRhdGVzID0gQCgkZmFsbGJhY2tTbmFwc2hvdC52aXNpYmxlX3VwZGF0ZXMpCiAgICAgICAgICAgIGhpZGRlbl91cGRhdGVzID0gQCgkZmFsbGJhY2tTbmFwc2hvdC5oaWRkZW5fdXBkYXRlcykKICAgICAgICAgICAgZGVueV9ydWxlc19yZWNlaXZlZCA9IEAoJGRlc2lyZWQuZGVuaWVkX3VwZGF0ZXMpLkNvdW50CiAgICAgICAgICAgIGRlbnlfbWF0Y2hlc19mb3VuZCA9IDAKICAgICAgICAgICAgZGVueV9ub3RfZm91bmQgPSAwCiAgICAgICAgICAgIGhpZGVfYXR0ZW1wdGVkID0gMAogICAgICAgICAgICBoaWRlX3N1Y2NlZWRlZCA9IDAKICAgICAgICAgICAgaGlkZV92ZXJpZmllZCA9IDAKICAgICAgICAgICAgaGlkZV9kaXJlY3QgPSAwCiAgICAgICAgICAgIGhpZGVfZmFsbGJhY2sgPSAwCiAgICAgICAgICAgIGhpZGVfc2V0dGVyX2ZhaWxlZCA9IDEKICAgICAgICAgICAgdW5oaWRlX2F0dGVtcHRlZCA9IDAKICAgICAgICAgICAgdW5oaWRlX3N1Y2NlZWRlZCA9IDAKICAgICAgICAgICAgdW5oaWRlX3ZlcmlmaWVkID0gMAogICAgICAgICAgICB1bmhpZGVfZGlyZWN0ID0gMAogICAgICAgICAgICB1bmhpZGVfZmFsbGJhY2sgPSAwCiAgICAgICAgICAgIHVuaGlkZV9zZXR0ZXJfZmFpbGVkID0gMAogICAgICAgICAgICBoaWRkZW5fY291bnQgPSAwCiAgICAgICAgICAgIHRyYWNrZWRfcnVsZXMgPSBAKExvYWQtSGlkZGVuQnlVcykKICAgICAgICAgICAgZXJyb3JzID0gQCgkZW5mb3JjZW1lbnRFcnJvcikKICAgICAgICAgICAgd2FybmluZ3MgPSBAKCkKICAgICAgICAgICAgc2VydmljZV9pZCA9ICRNaWNyb3NvZnRVcGRhdGVTZXJ2aWNlSWQKICAgICAgICB9CiAgICB9CgogICAgJGludmVudG9yeSA9IEJ1aWxkLUludmVudG9yeSAkdmlzaWJpbGl0eS52aXNpYmxlX3VwZGF0ZXMgJHZpc2liaWxpdHkuaGlkZGVuX3VwZGF0ZXMgJHZpc2liaWxpdHkudHJhY2tlZF9ydWxlcyAkZGVzaXJlZAoKICAgICRlcnJvcnMgPSBAKCRwb2xpY3kuZXJyb3JzKSArIEAoJHZpc2liaWxpdHkuZXJyb3JzKQogICAgJHdhcm5pbmdzID0gQCgkdmlzaWJpbGl0eS53YXJuaW5ncykKICAgICRzdGF0dXMgPSBpZiAoJGVycm9ycy5Db3VudCkgeyAnZGVncmFkZWQnIH0gZWxzZWlmICgkd2FybmluZ3MuQ291bnQpIHsgJ3dhcm5pbmcnIH0gZWxzZSB7ICdvaycgfQoKICAgIFdyaXRlLUpzb25BdG9taWMgJFVwZGF0ZXNDYWNoZVBhdGggQHsKICAgICAgICBsYWJfYnVpbGQgPSAkTGFiQnVpbGQKICAgICAgICBzdGF0dXMgPSAkc3RhdHVzCiAgICAgICAgc2Nhbm5lZF9hdCA9IEdldC1FcG9jaAogICAgICAgIHVwZGF0ZXMgPSBAKCRpbnZlbnRvcnkucmVwb3J0ZWRfdXBkYXRlcykKICAgICAgICBlcnJvcnMgPSBAKCRlcnJvcnMpCiAgICAgICAgd2FybmluZ3MgPSBAKCR3YXJuaW5ncykKICAgICAgICBzdGFuZGFyZF9jb3VudCA9IFtpbnRdJGludmVudG9yeS5zdGFuZGFyZF9jb3VudAogICAgICAgIG9wdGlvbmFsX2NvdW50ID0gW2ludF0kaW52ZW50b3J5Lm9wdGlvbmFsX2NvdW50CiAgICAgICAgZHJpdmVyX2NvdW50ID0gW2ludF0kaW52ZW50b3J5LmRyaXZlcl9jb3VudAogICAgICAgIGZpcm13YXJlX2NvdW50ID0gW2ludF0kaW52ZW50b3J5LmZpcm13YXJlX2NvdW50CiAgICAgICAgZmVhdHVyZV9jb3VudCA9IFtpbnRdJGludmVudG9yeS5mZWF0dXJlX2NvdW50CiAgICAgICAgZXhjbHVkZWRfY291bnQgPSBbaW50XSRpbnZlbnRvcnkuZXhjbHVkZWRfY291bnQKICAgIH0gMTAKCiAgICBXcml0ZS1JbnZlbnRvcnlTbmFwc2hvdCAkaW52ZW50b3J5ICR2aXNpYmlsaXR5ICRkZXNpcmVkICRlcnJvcnMgJHdhcm5pbmdzICdwb3N0LWVuZm9yY2VtZW50JwoKICAgICRyZXBvcnQgPSBAewogICAgICAgIGxhYl9idWlsZCA9ICRMYWJCdWlsZAogICAgICAgIGxhYl92ZXJzaW9uID0gJExhYlZlcnNpb24KICAgICAgICB3b3JrZXJfc3RhdHVzID0gJHN0YXR1cwogICAgICAgIG1vZGUgPSBpZiAoJGRlc2lyZWQubWFuYWdlZCkgeyAnbWFuYWdlZCcgfSBlbHNlIHsgJ29ic2VydmUnIH0KICAgICAgICBjb21wbGlhbnQgPSBbYm9vbF0oJHBvbGljeS5jb21wbGlhbnQgLWFuZCAkdmlzaWJpbGl0eS5lcnJvcnMuQ291bnQgLWVxIDApCiAgICAgICAgY2hlY2tlZF9hdCA9IEdldC1FcG9jaAogICAgICAgIHN0YXJ0ZWRfYXQgPSAkc3RhcnRlZAogICAgICAgIGNhdGFsb2cgPSAnTWljcm9zb2Z0IFVwZGF0ZScKICAgICAgICBjYXRhbG9nX3NlcnZpY2VfaWQgPSAkTWljcm9zb2Z0VXBkYXRlU2VydmljZUlkCiAgICAgICAgaW52ZW50b3J5X2ZpbGUgPSAkSW52ZW50b3J5UGF0aAogICAgICAgIHVzZXJfYWNjZXNzX2Jsb2NrZWQgPSBbYm9vbF0kcG9saWN5LnVzZXJfYWNjZXNzX2Jsb2NrZWQKICAgICAgICBwYXVzZV9ibG9ja2VkID0gW2Jvb2xdJHBvbGljeS5wYXVzZV9ibG9ja2VkCiAgICAgICAgbm9fYXV0b191cGRhdGUgPSBbc3RyaW5nXSRwb2xpY3kubm9fYXV0b191cGRhdGUKICAgICAgICBhdV9vcHRpb25zID0gW3N0cmluZ10kcG9saWN5LmF1X29wdGlvbnMKICAgICAgICB2aXNpYmxlX2NvdW50ID0gW2ludF0kaW52ZW50b3J5LnZpc2libGVfY291bnQKICAgICAgICBwZW5kaW5nX2NvdW50ID0gW2ludF0kaW52ZW50b3J5LnJlcG9ydGVkX2NvdW50CiAgICAgICAgZXhjbHVkZWRfY291bnQgPSBbaW50XSRpbnZlbnRvcnkuZXhjbHVkZWRfY291bnQKICAgICAgICBzY2FuX3N0YW5kYXJkX2NvdW50ID0gW2ludF0kaW52ZW50b3J5LnN0YW5kYXJkX2NvdW50CiAgICAgICAgc2Nhbl9vcHRpb25hbF9jb3VudCA9IFtpbnRdJGludmVudG9yeS5vcHRpb25hbF9jb3VudAogICAgICAgIHNjYW5fZHJpdmVyX2NvdW50ID0gW2ludF0kaW52ZW50b3J5LmRyaXZlcl9jb3VudAogICAgICAgIHNjYW5fZmlybXdhcmVfY291bnQgPSBbaW50XSRpbnZlbnRvcnkuZmlybXdhcmVfY291bnQKICAgICAgICBzY2FuX2ZlYXR1cmVfY291bnQgPSBbaW50XSRpbnZlbnRvcnkuZmVhdHVyZV9jb3VudAogICAgICAgIGRlbnlfcnVsZXNfcmVjZWl2ZWQgPSBbaW50XSR2aXNpYmlsaXR5LmRlbnlfcnVsZXNfcmVjZWl2ZWQKICAgICAgICBkZW55X21hdGNoZXNfZm91bmQgPSBbaW50XSR2aXNpYmlsaXR5LmRlbnlfbWF0Y2hlc19mb3VuZAogICAgICAgIGRlbnlfbm90X2ZvdW5kID0gW2ludF0kdmlzaWJpbGl0eS5kZW55X25vdF9mb3VuZAogICAgICAgIGhpZGVfYXR0ZW1wdGVkID0gW2ludF0kdmlzaWJpbGl0eS5oaWRlX2F0dGVtcHRlZAogICAgICAgIGhpZGVfc3VjY2VlZGVkID0gW2ludF0kdmlzaWJpbGl0eS5oaWRlX3N1Y2NlZWRlZAogICAgICAgIGhpZGVfdmVyaWZpZWQgPSBbaW50XSR2aXNpYmlsaXR5LmhpZGVfdmVyaWZpZWQKICAgICAgICBoaWRlX2RpcmVjdCA9IFtpbnRdJHZpc2liaWxpdHkuaGlkZV9kaXJlY3QKICAgICAgICBoaWRlX2ZhbGxiYWNrID0gW2ludF0kdmlzaWJpbGl0eS5oaWRlX2ZhbGxiYWNrCiAgICAgICAgaGlkZV9zZXR0ZXJfZmFpbGVkID0gW2ludF0kdmlzaWJpbGl0eS5oaWRlX3NldHRlcl9mYWlsZWQKICAgICAgICBoaWRkZW5fY291bnQgPSBbaW50XSR2aXNpYmlsaXR5LmhpZGRlbl9jb3VudAogICAgICAgIHVuaGlkZV9hdHRlbXB0ZWQgPSBbaW50XSR2aXNpYmlsaXR5LnVuaGlkZV9hdHRlbXB0ZWQKICAgICAgICB1bmhpZGVfc3VjY2VlZGVkID0gW2ludF0kdmlzaWJpbGl0eS51bmhpZGVfc3VjY2VlZGVkCiAgICAgICAgdW5oaWRlX3ZlcmlmaWVkID0gW2ludF0kdmlzaWJpbGl0eS51bmhpZGVfdmVyaWZpZWQKICAgICAgICB1bmhpZGVfZGlyZWN0ID0gW2ludF0kdmlzaWJpbGl0eS51bmhpZGVfZGlyZWN0CiAgICAgICAgdW5oaWRlX2ZhbGxiYWNrID0gW2ludF0kdmlzaWJpbGl0eS51bmhpZGVfZmFsbGJhY2sKICAgICAgICB1bmhpZGVfc2V0dGVyX2ZhaWxlZCA9IFtpbnRdJHZpc2liaWxpdHkudW5oaWRlX3NldHRlcl9mYWlsZWQKICAgICAgICBzZXJ2ZXJfaW5jbHVkZV9wcmV2aWV3ID0gW2Jvb2xdJGRlc2lyZWQuc2VydmVyX2luY2x1ZGVfcHJldmlldwogICAgICAgIHNlcnZlcl9tYW5hZ2VkX3JlcXVlc3RlZCA9IFtib29sXSRkZXNpcmVkLnNlcnZlcl9tYW5hZ2VkX3JlcXVlc3RlZAogICAgICAgIGVycm9ycyA9IEAoJGVycm9ycykKICAgICAgICB3YXJuaW5ncyA9IEAoJHdhcm5pbmdzKQogICAgfQogICAgV3JpdGUtSnNvbkF0b21pYyAkUmVwb3J0UGF0aCAkcmVwb3J0IDEyCiAgICBXcml0ZS1XdUxvZyAiU2NhbiBjb21wbGV0ZWQ6IHN0YXR1cz0kc3RhdHVzLCBtb2RlPSQoJHJlcG9ydC5tb2RlKSwgdmlzaWJsZT0kKCRyZXBvcnQudmlzaWJsZV9jb3VudCksIHJlcG9ydGVkPSQoJHJlcG9ydC5wZW5kaW5nX2NvdW50KSwgb3B0aW9uYWw9JCgkcmVwb3J0LnNjYW5fb3B0aW9uYWxfY291bnQpLCBkcml2ZXJzPSQoJHJlcG9ydC5zY2FuX2RyaXZlcl9jb3VudCksIGhpZGRlbj0kKCRyZXBvcnQuaGlkZGVuX2NvdW50KSwgaGlkZV9mYWxsYmFjaz0kKCRyZXBvcnQuaGlkZV9mYWxsYmFjayksIGVycm9ycz0kKCRlcnJvcnMuQ291bnQpLCB3YXJuaW5ncz0kKCR3YXJuaW5ncy5Db3VudCkuIgp9CgpmdW5jdGlvbiBHZXQtTmV4dEluc3RhbGxSZXF1ZXN0IHsKICAgICRpdGVtcyA9IEAoR2V0LUNoaWxkSXRlbSAkUXVldWVEaXIgLUZpbHRlciAnKi5qc29uJyAtRmlsZSAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZSB8IFNvcnQtT2JqZWN0IExhc3RXcml0ZVRpbWUpCiAgICBpZiAoLW5vdCAkaXRlbXMuQ291bnQpIHsgcmV0dXJuICRudWxsIH0KICAgIHJldHVybiAkaXRlbXNbMF0KfQoKZnVuY3Rpb24gV3JpdGUtSW5zdGFsbFJlc3VsdChbc3RyaW5nXSRKb2JJZCwgJFJlc3VsdCkgewogICAgV3JpdGUtSnNvbkF0b21pYyAoSm9pbi1QYXRoICRSZXN1bHREaXIgIiRKb2JJZC5qc29uIikgQHsKICAgICAgICBqb2JfaWQgPSAkSm9iSWQKICAgICAgICBjb21wbGV0ZWRfYXQgPSBHZXQtRXBvY2gKICAgICAgICByZXN1bHQgPSAkUmVzdWx0CiAgICB9IDEwCn0KCmZ1bmN0aW9uIEdldC1XdWFSZXN1bHROYW1lKFtpbnRdJENvZGUpIHsKICAgIHN3aXRjaCAoJENvZGUpIHsKICAgICAgICAwIHsgcmV0dXJuICdOb3RTdGFydGVkJyB9CiAgICAgICAgMSB7IHJldHVybiAnSW5Qcm9ncmVzcycgfQogICAgICAgIDIgeyByZXR1cm4gJ1N1Y2NlZWRlZCcgfQogICAgICAgIDMgeyByZXR1cm4gJ1N1Y2NlZWRlZFdpdGhFcnJvcnMnIH0KICAgICAgICA0IHsgcmV0dXJuICdGYWlsZWQnIH0KICAgICAgICA1IHsgcmV0dXJuICdBYm9ydGVkJyB9CiAgICAgICAgZGVmYXVsdCB7IHJldHVybiAiVW5rbm93bigkQ29kZSkiIH0KICAgIH0KfQoKZnVuY3Rpb24gSW5zdGFsbC1PbmVVcGRhdGUoJFNlc3Npb24sICRVcGRhdGUpIHsKICAgICRsaW5lcyA9IE5ldy1PYmplY3QgU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdFtzdHJpbmddCiAgICB0cnkgewogICAgICAgIGlmICgtbm90IFtib29sXSRVcGRhdGUuRXVsYUFjY2VwdGVkKSB7ICRVcGRhdGUuQWNjZXB0RXVsYSgpIH0KICAgICAgICAkY29sbGVjdGlvbiA9IE5ldy1PYmplY3QgLUNvbU9iamVjdCAnTWljcm9zb2Z0LlVwZGF0ZS5VcGRhdGVDb2xsJwogICAgICAgIFt2b2lkXSRjb2xsZWN0aW9uLkFkZCgkVXBkYXRlKQoKICAgICAgICBpZiAoLW5vdCBbYm9vbF0kVXBkYXRlLklzRG93bmxvYWRlZCkgewogICAgICAgICAgICAkZG93bmxvYWRlciA9ICRTZXNzaW9uLkNyZWF0ZVVwZGF0ZURvd25sb2FkZXIoKQogICAgICAgICAgICAkZG93bmxvYWRlci5VcGRhdGVzID0gJGNvbGxlY3Rpb24KICAgICAgICAgICAgJGRvd25sb2FkUmVzdWx0ID0gJGRvd25sb2FkZXIuRG93bmxvYWQoKQogICAgICAgICAgICAkZG93bmxvYWRDb2RlID0gW2ludF0kZG93bmxvYWRSZXN1bHQuUmVzdWx0Q29kZQogICAgICAgICAgICAkbGluZXMuQWRkKCJEb3dubG9hZDogJChHZXQtV3VhUmVzdWx0TmFtZSAkZG93bmxvYWRDb2RlKSIpCiAgICAgICAgICAgIGlmICgkZG93bmxvYWRDb2RlIC1ub3RpbiBAKDIsMykpIHsKICAgICAgICAgICAgICAgIHJldHVybiBbcHNjdXN0b21vYmplY3RdQHsgb2s9JGZhbHNlOyBsaW5lcz1AKCRsaW5lcyk7IHJlc3VsdF9jb2RlPSRkb3dubG9hZENvZGUgfQogICAgICAgICAgICB9CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgJGxpbmVzLkFkZCgnRG93bmxvYWQ6IGFscmVhZHkgZG93bmxvYWRlZCcpCiAgICAgICAgfQoKICAgICAgICAkaW5zdGFsbGVyID0gJFNlc3Npb24uQ3JlYXRlVXBkYXRlSW5zdGFsbGVyKCkKICAgICAgICAkaW5zdGFsbGVyLlVwZGF0ZXMgPSAkY29sbGVjdGlvbgogICAgICAgIHRyeSB7ICRpbnN0YWxsZXIuRm9yY2VRdWlldCA9ICR0cnVlIH0gY2F0Y2gge30KICAgICAgICB0cnkgeyAkaW5zdGFsbGVyLkFsbG93U291cmNlUHJvbXB0cyA9ICRmYWxzZSB9IGNhdGNoIHt9CiAgICAgICAgJGluc3RhbGxSZXN1bHQgPSAkaW5zdGFsbGVyLkluc3RhbGwoKQogICAgICAgICRyb3cgPSAkaW5zdGFsbFJlc3VsdC5HZXRVcGRhdGVSZXN1bHQoMCkKICAgICAgICAkY29kZSA9IFtpbnRdJHJvdy5SZXN1bHRDb2RlCiAgICAgICAgJGxpbmVzLkFkZCgiSW5zdGFsbDogJChHZXQtV3VhUmVzdWx0TmFtZSAkY29kZSk7IEhSRVNVTFQ9JChbaW50XSRyb3cuSFJlc3VsdCkiKQogICAgICAgIHJldHVybiBbcHNjdXN0b21vYmplY3RdQHsgb2s9KCRjb2RlIC1lcSAyKTsgbGluZXM9QCgkbGluZXMpOyByZXN1bHRfY29kZT0kY29kZSB9CiAgICB9IGNhdGNoIHsKICAgICAgICAkbGluZXMuQWRkKCJFeGNlcHRpb246ICQoJF8uRXhjZXB0aW9uLk1lc3NhZ2UpIikKICAgICAgICByZXR1cm4gW3BzY3VzdG9tb2JqZWN0XUB7IG9rPSRmYWxzZTsgbGluZXM9QCgkbGluZXMpOyByZXN1bHRfY29kZT0tMSB9CiAgICB9Cn0KCmZ1bmN0aW9uIFJ1bi1JbnN0YWxsIHsKICAgICRpdGVtID0gR2V0LU5leHRJbnN0YWxsUmVxdWVzdAogICAgaWYgKC1ub3QgJGl0ZW0pIHsgV3JpdGUtV3VMb2cgJ05vIHF1ZXVlZCBpbnN0YWxsIGpvYi4nOyByZXR1cm4gfQogICAgJHJlcXVlc3QgPSBSZWFkLUpzb25GaWxlICRpdGVtLkZ1bGxOYW1lICRudWxsCiAgICBpZiAoLW5vdCAkcmVxdWVzdCAtb3IgLW5vdCAkcmVxdWVzdC5qb2JfaWQpIHsKICAgICAgICBSZW1vdmUtSXRlbSAkaXRlbS5GdWxsTmFtZSAtRm9yY2UgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUKICAgICAgICByZXR1cm4KICAgIH0KCiAgICAkam9iSWQgPSBbc3RyaW5nXSRyZXF1ZXN0LmpvYl9pZAogICAgJHdhbnRlZCA9IEAoJHJlcXVlc3QucGF5bG9hZC51cGRhdGVfaWRzKQogICAgV3JpdGUtSnNvbkF0b21pYyAkQWN0aXZlSW5zdGFsbFBhdGggQHsgam9iX2lkPSRqb2JJZDsgcXVldWVfcGF0aD0kaXRlbS5GdWxsTmFtZTsgc3RhcnRlZF9hdD0oR2V0LUVwb2NoKSB9IDUKICAgICRsaW5lcyA9IE5ldy1PYmplY3QgU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdFtzdHJpbmddCiAgICAkZmFpbGVkID0gQCgpCgogICAgdHJ5IHsKICAgICAgICAkZGVzaXJlZCA9IFJlc29sdmUtRGVzaXJlZFN0YXRlCiAgICAgICAgJHNlYXJjaCA9IFNlYXJjaC1NaWNyb3NvZnRVcGRhdGVzICRmYWxzZQogICAgICAgICRtYXRjaGVzID0gQCgpCiAgICAgICAgJHNlZW4gPSBAe30KICAgICAgICBmb3JlYWNoICgkdXBkYXRlIGluIEAoJHNlYXJjaC51cGRhdGVzKSkgewogICAgICAgICAgICBpZiAoLW5vdCAoVGVzdC1XYW50ZWRNYXRjaCAkdXBkYXRlICR3YW50ZWQpKSB7IGNvbnRpbnVlIH0KICAgICAgICAgICAgaWYgKEAoJGRlc2lyZWQuZGVuaWVkX3VwZGF0ZXMgfCBXaGVyZS1PYmplY3QgeyBUZXN0LVJ1bGVNYXRjaCAkdXBkYXRlICRfIH0pLkNvdW50KSB7CiAgICAgICAgICAgICAgICAkbGluZXMuQWRkKCJbU0tJUC1ERU5JRURdICQoW3N0cmluZ10kdXBkYXRlLlRpdGxlKSIpCiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICB9CiAgICAgICAgICAgICRpZCA9IEdldC1VcGRhdGVJZGVudGl0eSAkdXBkYXRlCiAgICAgICAgICAgICRrZXkgPSBDb252ZXJ0VG8tVXBkYXRlS2V5IChbc3RyaW5nXSRpZC51cGRhdGVfaWQpCiAgICAgICAgICAgIGlmICgtbm90ICRzZWVuLkNvbnRhaW5zS2V5KCRrZXkpKSB7ICRzZWVuWyRrZXldID0gJHRydWU7ICRtYXRjaGVzICs9ICR1cGRhdGUgfQogICAgICAgIH0KCiAgICAgICAgaWYgKC1ub3QgJG1hdGNoZXMuQ291bnQpIHsKICAgICAgICAgICAgV3JpdGUtSW5zdGFsbFJlc3VsdCAkam9iSWQgQHsKICAgICAgICAgICAgICAgIG9rID0gJHRydWUKICAgICAgICAgICAgICAgIGV4aXRfY29kZSA9IDAKICAgICAgICAgICAgICAgIG91dHB1dCA9ICdObyBhcHByb3ZlZCBtYXRjaGluZyB1cGRhdGVzIHJlbWFpbiB2aXNpYmxlOyB0aGV5IG1heSBiZSBpbnN0YWxsZWQsIHN1cGVyc2VkZWQsIGRlbmllZCwgb3Igbm8gbG9uZ2VyIGFwcGxpY2FibGUuJwogICAgICAgICAgICAgICAgZmFpbGVkX3VwZGF0ZV9pZHMgPSBAKCkKICAgICAgICAgICAgICAgIHJlYm9vdF9yZXF1aXJlZCA9IFRlc3QtUmVib290UmVxdWlyZWQKICAgICAgICAgICAgfQogICAgICAgICAgICByZXR1cm4KICAgICAgICB9CgogICAgICAgICRsaW5lcy5BZGQoIkluc3RhbGxpbmcgJCgkbWF0Y2hlcy5Db3VudCkgdXBkYXRlKHMpIHRocm91Z2ggdGhlIGlzb2xhdGVkIE1pY3Jvc29mdCBVcGRhdGUgd29ya2VyLi4uIikKICAgICAgICBmb3JlYWNoICgkdXBkYXRlIGluICRtYXRjaGVzKSB7CiAgICAgICAgICAgICRkZXNpcmVkID0gUmVzb2x2ZS1EZXNpcmVkU3RhdGUKICAgICAgICAgICAgJGlkID0gR2V0LVVwZGF0ZUlkZW50aXR5ICR1cGRhdGUKICAgICAgICAgICAgaWYgKEAoJGRlc2lyZWQuZGVuaWVkX3VwZGF0ZXMgfCBXaGVyZS1PYmplY3QgeyBUZXN0LVJ1bGVNYXRjaCAkdXBkYXRlICRfIH0pLkNvdW50KSB7CiAgICAgICAgICAgICAgICAkbGluZXMuQWRkKCJbU0tJUC1ERU5JRURdICQoW3N0cmluZ10kdXBkYXRlLlRpdGxlKSIpCiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICB9CiAgICAgICAgICAgICRyZXN1bHQgPSBJbnN0YWxsLU9uZVVwZGF0ZSAkc2VhcmNoLnNlc3Npb24gJHVwZGF0ZQogICAgICAgICAgICBmb3JlYWNoICgkbGluZSBpbiBAKCRyZXN1bHQubGluZXMpKSB7ICRsaW5lcy5BZGQoIlskKFtzdHJpbmddJGlkLmtiKV0gJGxpbmUiKSB9CiAgICAgICAgICAgIGlmICgkcmVzdWx0Lm9rKSB7ICRsaW5lcy5BZGQoIltPS10gJChbc3RyaW5nXSR1cGRhdGUuVGl0bGUpIikgfQogICAgICAgICAgICBlbHNlIHsgJGxpbmVzLkFkZCgiW0ZBSUxdICQoW3N0cmluZ10kdXBkYXRlLlRpdGxlKSIpOyAkZmFpbGVkICs9IFtzdHJpbmddJGlkLnVwZGF0ZV9pZCB9CiAgICAgICAgfQoKICAgICAgICAkcmVib290ID0gVGVzdC1SZWJvb3RSZXF1aXJlZAogICAgICAgIGlmICgkcmVib290KSB7ICRsaW5lcy5BZGQoJ0EgcmVib290IGlzIHJlcXVpcmVkIHRvIGZpbmlzaCBpbnN0YWxsYXRpb24uJykgfQogICAgICAgIFdyaXRlLUluc3RhbGxSZXN1bHQgJGpvYklkIEB7CiAgICAgICAgICAgIG9rID0gKCRmYWlsZWQuQ291bnQgLWVxIDApCiAgICAgICAgICAgIGV4aXRfY29kZSA9ICRmYWlsZWQuQ291bnQKICAgICAgICAgICAgb3V0cHV0ID0gKCRsaW5lcyAtam9pbiAiYG4iKQogICAgICAgICAgICBmYWlsZWRfdXBkYXRlX2lkcyA9IEAoJGZhaWxlZCkKICAgICAgICAgICAgcmVib290X3JlcXVpcmVkID0gJHJlYm9vdAogICAgICAgIH0KICAgIH0gY2F0Y2ggewogICAgICAgICRsaW5lcy5BZGQoIldvcmtlciBlcnJvcjogJCgkXy5FeGNlcHRpb24uTWVzc2FnZSkiKQogICAgICAgIFdyaXRlLUluc3RhbGxSZXN1bHQgJGpvYklkIEB7CiAgICAgICAgICAgIG9rID0gJGZhbHNlCiAgICAgICAgICAgIGV4aXRfY29kZSA9IC0xCiAgICAgICAgICAgIG91dHB1dCA9ICgkbGluZXMgLWpvaW4gImBuIikKICAgICAgICAgICAgZmFpbGVkX3VwZGF0ZV9pZHMgPSBAKCR3YW50ZWQpCiAgICAgICAgICAgIHJlYm9vdF9yZXF1aXJlZCA9IFRlc3QtUmVib290UmVxdWlyZWQKICAgICAgICB9CiAgICB9IGZpbmFsbHkgewogICAgICAgIFJlbW92ZS1JdGVtICRpdGVtLkZ1bGxOYW1lIC1Gb3JjZSAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZQogICAgICAgIFJlbW92ZS1JdGVtICRBY3RpdmVJbnN0YWxsUGF0aCAtRm9yY2UgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUKICAgICAgICBOZXctSXRlbSAtSXRlbVR5cGUgRmlsZSAtUGF0aCAoSm9pbi1QYXRoICRMYWJEaXIgJ2ZvcmNlLXNjYW4uZmxhZycpIC1Gb3JjZSB8IE91dC1OdWxsCiAgICB9Cn0KCmZ1bmN0aW9uIFJ1bi1SZXN0b3JlIHsKICAgIFt2b2lkXShSZXN0b3JlLVBvbGljeSkKICAgICR2aXNpYmlsaXR5ID0gU2V0LURlbmllZFZpc2liaWxpdHkgQCgpICRmYWxzZQogICAgJGVycm9ycyA9IEAoJHZpc2liaWxpdHkuZXJyb3JzKQogICAgJHdhcm5pbmdzID0gQCgkdmlzaWJpbGl0eS53YXJuaW5ncykKICAgICRzdGF0dXMgPSBpZiAoJGVycm9ycy5Db3VudCkgeyAnZGVncmFkZWQnIH0gZWxzZWlmICgkd2FybmluZ3MuQ291bnQpIHsgJ3dhcm5pbmcnIH0gZWxzZSB7ICdyZXN0b3JlZCcgfQogICAgV3JpdGUtSnNvbkF0b21pYyAkUmVwb3J0UGF0aCBAewogICAgICAgIGxhYl9idWlsZCA9ICRMYWJCdWlsZAogICAgICAgIGxhYl92ZXJzaW9uID0gJExhYlZlcnNpb24KICAgICAgICB3b3JrZXJfc3RhdHVzID0gJHN0YXR1cwogICAgICAgIG1vZGUgPSAnb2JzZXJ2ZScKICAgICAgICBjb21wbGlhbnQgPSAoJGVycm9ycy5Db3VudCAtZXEgMCkKICAgICAgICBjaGVja2VkX2F0ID0gR2V0LUVwb2NoCiAgICAgICAgY2F0YWxvZyA9ICdNaWNyb3NvZnQgVXBkYXRlJwogICAgICAgIHVzZXJfYWNjZXNzX2Jsb2NrZWQgPSAkZmFsc2UKICAgICAgICBwYXVzZV9ibG9ja2VkID0gJGZhbHNlCiAgICAgICAgbm9fYXV0b191cGRhdGUgPSAncmVzdG9yZWQnCiAgICAgICAgYXVfb3B0aW9ucyA9ICdyZXN0b3JlZCcKICAgICAgICBoaWRkZW5fY291bnQgPSBbaW50XSR2aXNpYmlsaXR5LmhpZGRlbl9jb3VudAogICAgICAgIHVuaGlkZV9hdHRlbXB0ZWQgPSBbaW50XSR2aXNpYmlsaXR5LnVuaGlkZV9hdHRlbXB0ZWQKICAgICAgICB1bmhpZGVfc3VjY2VlZGVkID0gW2ludF0kdmlzaWJpbGl0eS51bmhpZGVfc3VjY2VlZGVkCiAgICAgICAgdW5oaWRlX3ZlcmlmaWVkID0gW2ludF0kdmlzaWJpbGl0eS51bmhpZGVfdmVyaWZpZWQKICAgICAgICBlcnJvcnMgPSBAKCRlcnJvcnMpCiAgICAgICAgd2FybmluZ3MgPSBAKCR3YXJuaW5ncykKICAgIH0gMTAKICAgIFdyaXRlLVd1TG9nICJSZXN0b3JlIGNvbXBsZXRlZDsgdW5oaWRlX3ZlcmlmaWVkPSQoJHZpc2liaWxpdHkudW5oaWRlX3ZlcmlmaWVkKSwgZXJyb3JzPSQoJGVycm9ycy5Db3VudCksIHdhcm5pbmdzPSQoJHdhcm5pbmdzLkNvdW50KS4iCn0KCiRtdXRleCA9IE5ldy1PYmplY3QgU3lzdGVtLlRocmVhZGluZy5NdXRleCgkZmFsc2UsICdHbG9iYWxcT3BlblByaW1lUk1NV3VMYWJXb3JrZXInKQokaGFzTXV0ZXggPSAkZmFsc2UKdHJ5IHsKICAgICR3YWl0TXMgPSBpZiAoJE1vZGUgLWVxICdJbnN0YWxsJykgeyA2MDAwMCB9IGVsc2VpZiAoJE1vZGUgLWVxICdSZXN0b3JlJykgeyAxNTAwMCB9IGVsc2UgeyAwIH0KICAgICRoYXNNdXRleCA9ICRtdXRleC5XYWl0T25lKCR3YWl0TXMpCiAgICBpZiAoLW5vdCAkaGFzTXV0ZXgpIHsKICAgICAgICBXcml0ZS1XdUxvZyAnQW5vdGhlciBXaW5kb3dzIFVwZGF0ZSB3b3JrZXIgaXMgYWN0aXZlOyB0aGlzIHJ1biB3aWxsIHJldHJ5IGxhdGVyLicKICAgICAgICBleGl0IDc1CiAgICB9CiAgICBXcml0ZS1XdUxvZyAnV29ya2VyIHN0YXJ0ZWQuJwogICAgc3dpdGNoICgkTW9kZSkgewogICAgICAgICdTY2FuJyB7IFJ1bi1TY2FuIH0KICAgICAgICAnSW5zdGFsbCcgeyBSdW4tSW5zdGFsbCB9CiAgICAgICAgJ1Jlc3RvcmUnIHsgUnVuLVJlc3RvcmUgfQogICAgfQogICAgV3JpdGUtV3VMb2cgJ1dvcmtlciBleGl0ZWQgbm9ybWFsbHkuJwogICAgZXhpdCAwCn0gY2F0Y2ggewogICAgV3JpdGUtV3VMb2cgIkZhdGFsIHdvcmtlciBlcnJvcjogJCgkXy5FeGNlcHRpb24uTWVzc2FnZSkiCiAgICBpZiAoJE1vZGUgLWVxICdTY2FuJykgewogICAgICAgIFdyaXRlLUpzb25BdG9taWMgJFJlcG9ydFBhdGggQHsKICAgICAgICAgICAgbGFiX2J1aWxkID0gJExhYkJ1aWxkCiAgICAgICAgICAgIGxhYl92ZXJzaW9uID0gJExhYlZlcnNpb24KICAgICAgICAgICAgd29ya2VyX3N0YXR1cyA9ICdmYWlsZWQnCiAgICAgICAgICAgIG1vZGUgPSAndW5rbm93bicKICAgICAgICAgICAgY29tcGxpYW50ID0gJGZhbHNlCiAgICAgICAgICAgIGNoZWNrZWRfYXQgPSBHZXQtRXBvY2gKICAgICAgICAgICAgZXJyb3JzID0gQCgkXy5FeGNlcHRpb24uTWVzc2FnZSkKICAgICAgICAgICAgd2FybmluZ3MgPSBAKCkKICAgICAgICB9IDgKICAgIH0KICAgIGV4aXQgMQp9IGZpbmFsbHkgewogICAgaWYgKCRoYXNNdXRleCkgeyB0cnkgeyAkbXV0ZXguUmVsZWFzZU11dGV4KCkgfSBjYXRjaCB7fSB9CiAgICAkbXV0ZXguRGlzcG9zZSgpCn0K' },
        @{ Path = (Join-Path $wuInstallDir 'OpenPrimeRMM-WU-Lab-Launcher.ps1'); Sha = 'AAC38576776E548811951389A545E051DA9ED37C7D708AB68DEDFF28A1C61569'; B64 = 'PCMgSXNvbGF0ZWQgcHJvY2VzcyBsYXVuY2hlciB3aXRoIGEgaGFyZCB0aW1lb3V0IGFuZCBwcm9jZXNzLXRyZWUgdGVybWluYXRpb24uICM+CnBhcmFtKAogICAgW1ZhbGlkYXRlU2V0KCdTY2FuJywnSW5zdGFsbCcsJ1Jlc3RvcmUnKV0KICAgIFtzdHJpbmddJE1vZGUgPSAnU2NhbicsCiAgICBbaW50XSRUaW1lb3V0U2VjID0gMTgwCikKCiRFcnJvckFjdGlvblByZWZlcmVuY2UgPSAnU3RvcCcKJExhYkRpciA9ICdDOlxQcm9ncmFtRGF0YVxPcGVuUHJpbWVcd3UtbGFiJwokV29ya2VyID0gJ0M6XFByb2dyYW0gRmlsZXNcT3BlblByaW1lXE9wZW5QcmltZVJNTS1XVS1MYWItV29ya2VyLnBzMScKJExvZ1BhdGggPSBKb2luLVBhdGggJExhYkRpciAnbGF1bmNoZXIubG9nJwokUmVwb3J0UGF0aCA9IEpvaW4tUGF0aCAkTGFiRGlyICd3b3JrZXItcmVwb3J0Lmpzb24nCiRBY3RpdmVJbnN0YWxsUGF0aCA9IEpvaW4tUGF0aCAkTGFiRGlyICdhY3RpdmUtaW5zdGFsbC5qc29uJwokUmVzdWx0RGlyID0gSm9pbi1QYXRoICRMYWJEaXIgJ2luc3RhbGwtcmVzdWx0cycKaWYgKC1ub3QgKFRlc3QtUGF0aCAkTGFiRGlyKSkgeyBOZXctSXRlbSAtSXRlbVR5cGUgRGlyZWN0b3J5IC1QYXRoICRMYWJEaXIgLUZvcmNlIHwgT3V0LU51bGwgfQppZiAoLW5vdCAoVGVzdC1QYXRoICRSZXN1bHREaXIpKSB7IE5ldy1JdGVtIC1JdGVtVHlwZSBEaXJlY3RvcnkgLVBhdGggJFJlc3VsdERpciAtRm9yY2UgfCBPdXQtTnVsbCB9CgpmdW5jdGlvbiBMb2coW3N0cmluZ10kTWVzc2FnZSkgewogICAgdHJ5IHsgQWRkLUNvbnRlbnQgJExvZ1BhdGggKCJ7MH0gW3sxfV0gezJ9IiAtZiAoR2V0LURhdGUgLUZvcm1hdCAneXl5eS1NTS1kZCBISDptbTpzcycpLCAkTW9kZSwgJE1lc3NhZ2UpIC1FbmNvZGluZyBVVEY4IH0gY2F0Y2gge30KfQpmdW5jdGlvbiBXcml0ZUpzb24oW3N0cmluZ10kUGF0aCwgJFZhbHVlKSB7CiAgICAkdG1wID0gIiRQYXRoLnRtcCIKICAgIFtTeXN0ZW0uSU8uRmlsZV06OldyaXRlQWxsVGV4dCgkdG1wLCAoJFZhbHVlIHwgQ29udmVydFRvLUpzb24gLURlcHRoIDgpLCAoTmV3LU9iamVjdCBTeXN0ZW0uVGV4dC5VVEY4RW5jb2RpbmcoJGZhbHNlKSkpCiAgICBNb3ZlLUl0ZW0gJHRtcCAkUGF0aCAtRm9yY2UKfQoKaWYgKC1ub3QgKFRlc3QtUGF0aCAkV29ya2VyKSkgeyBMb2cgIldvcmtlciBtaXNzaW5nOiAkV29ya2VyIjsgZXhpdCAyIH0KJHByb2MgPSBTdGFydC1Qcm9jZXNzIC1GaWxlUGF0aCAncG93ZXJzaGVsbC5leGUnIC1Bcmd1bWVudExpc3QgQCgnLU5vUHJvZmlsZScsJy1Ob25JbnRlcmFjdGl2ZScsJy1FeGVjdXRpb25Qb2xpY3knLCdCeXBhc3MnLCctRmlsZScsImAiJFdvcmtlcmAiIiwnLU1vZGUnLCRNb2RlKSAtV2luZG93U3R5bGUgSGlkZGVuIC1QYXNzVGhydQokbnVsbCA9ICRwcm9jLkhhbmRsZQpMb2cgIlN0YXJ0ZWQgd29ya2VyIFBJRCAkKCRwcm9jLklkKSwgdGltZW91dCAke1RpbWVvdXRTZWN9cy4iCmlmICgtbm90ICRwcm9jLldhaXRGb3JFeGl0KCRUaW1lb3V0U2VjICogMTAwMCkpIHsKICAgIExvZyAiVElNRU9VVDoga2lsbGluZyB3b3JrZXIgcHJvY2VzcyB0cmVlIFBJRCAkKCRwcm9jLklkKS4iCiAgICAmICIkZW52OlN5c3RlbVJvb3RcU3lzdGVtMzJcdGFza2tpbGwuZXhlIiAvUElEICRwcm9jLklkIC9UIC9GIDI+JjEgfCBPdXQtTnVsbAogICAgaWYgKCRNb2RlIC1lcSAnU2NhbicpIHsKICAgICAgICBXcml0ZUpzb24gJFJlcG9ydFBhdGggQHsgbGFiX2J1aWxkPSdXVS1QUk9ELTEnOyB3b3JrZXJfc3RhdHVzPSd0aW1lb3V0JzsgbW9kZT0ndW5rbm93bic7IGNvbXBsaWFudD0kZmFsc2U7IGNoZWNrZWRfYXQ9W0RhdGVUaW1lT2Zmc2V0XTo6Tm93LlRvVW5peFRpbWVTZWNvbmRzKCk7IGVycm9ycz1AKCJXaW5kb3dzIFVwZGF0ZSB3b3JrZXIgZXhjZWVkZWQgJHtUaW1lb3V0U2VjfSBzZWNvbmRzIGFuZCB3YXMgdGVybWluYXRlZC4gQ29yZSBSTU0gYWdlbnQgcmVtYWluZWQgYWN0aXZlLiIpIH0KICAgIH0gZWxzZWlmICgkTW9kZSAtZXEgJ0luc3RhbGwnIC1hbmQgKFRlc3QtUGF0aCAkQWN0aXZlSW5zdGFsbFBhdGgpKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgJGFjdGl2ZSA9IEdldC1Db250ZW50ICRBY3RpdmVJbnN0YWxsUGF0aCAtUmF3IHwgQ29udmVydEZyb20tSnNvbgogICAgICAgICAgICBpZiAoJGFjdGl2ZS5qb2JfaWQpIHsKICAgICAgICAgICAgICAgICRmYWlsZWRJZHMgPSBAKCkKICAgICAgICAgICAgICAgIGlmICgkYWN0aXZlLnF1ZXVlX3BhdGggLWFuZCAoVGVzdC1QYXRoICRhY3RpdmUucXVldWVfcGF0aCkpIHsKICAgICAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgICAgICAkcXVldWVkID0gR2V0LUNvbnRlbnQgJGFjdGl2ZS5xdWV1ZV9wYXRoIC1SYXcgfCBDb252ZXJ0RnJvbS1Kc29uCiAgICAgICAgICAgICAgICAgICAgICAgICRmYWlsZWRJZHMgPSBAKCRxdWV1ZWQucGF5bG9hZC51cGRhdGVfaWRzKQogICAgICAgICAgICAgICAgICAgIH0gY2F0Y2gge30KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIFdyaXRlSnNvbiAoSm9pbi1QYXRoICRSZXN1bHREaXIgIiQoJGFjdGl2ZS5qb2JfaWQpLmpzb24iKSBAeyBqb2JfaWQ9W3N0cmluZ10kYWN0aXZlLmpvYl9pZDsgY29tcGxldGVkX2F0PVtEYXRlVGltZU9mZnNldF06Ok5vdy5Ub1VuaXhUaW1lU2Vjb25kcygpOyByZXN1bHQ9QHsgb2s9JGZhbHNlOyBleGl0X2NvZGU9LTI7IG91dHB1dD0iV2luZG93cyBVcGRhdGUgaW5zdGFsbGF0aW9uIGV4Y2VlZGVkICR7VGltZW91dFNlY30gc2Vjb25kcyBhbmQgd2FzIHRlcm1pbmF0ZWQgYnkgdGhlIGlzb2xhdGVkLXdvcmtlciB3YXRjaGRvZy4iOyBmYWlsZWRfdXBkYXRlX2lkcz0kZmFpbGVkSWRzOyByZWJvb3RfcmVxdWlyZWQ9JGZhbHNlIH0gfQogICAgICAgICAgICAgICAgaWYgKCRhY3RpdmUucXVldWVfcGF0aCkgeyBSZW1vdmUtSXRlbSAkYWN0aXZlLnF1ZXVlX3BhdGggLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlIH0KICAgICAgICAgICAgfQogICAgICAgIH0gY2F0Y2gge30KICAgICAgICBSZW1vdmUtSXRlbSAkQWN0aXZlSW5zdGFsbFBhdGggLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlCiAgICB9CiAgICBleGl0IDEyNAp9CiRwcm9jLldhaXRGb3JFeGl0KCkKTG9nICJXb3JrZXIgZXhpdGVkIHdpdGggY29kZSAkKCRwcm9jLkV4aXRDb2RlKS4iCmV4aXQgJHByb2MuRXhpdENvZGUK' },
        @{ Path = (Join-Path $WuLabDir 'run-scan.cmd');    Sha = 'FD64260F2C4949CC885C29EF18B47A4634C64238169B95048FB18D6488772C6E'; B64 = 'QGVjaG8gb2ZmCiIlU3lzdGVtUm9vdCVcU3lzdGVtMzJcV2luZG93c1Bvd2VyU2hlbGxcdjEuMFxwb3dlcnNoZWxsLmV4ZSIgLU5vUHJvZmlsZSAtTm9uSW50ZXJhY3RpdmUgLUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVdpbmRvd1N0eWxlIEhpZGRlbiAtRmlsZSAiQzpcUHJvZ3JhbSBGaWxlc1xPcGVuUHJpbWVcT3BlblByaW1lUk1NLVdVLUxhYi1MYXVuY2hlci5wczEiIC1Nb2RlIFNjYW4gLVRpbWVvdXRTZWMgMTgwCmV4aXQgL2IgJWVycm9ybGV2ZWwlCg==' },
        @{ Path = (Join-Path $WuLabDir 'run-install.cmd'); Sha = 'C17EF76B4AABEC9214187F03118F0FC8F820052DFA57EF60E67524F497C532ED'; B64 = 'QGVjaG8gb2ZmCiIlU3lzdGVtUm9vdCVcU3lzdGVtMzJcV2luZG93c1Bvd2VyU2hlbGxcdjEuMFxwb3dlcnNoZWxsLmV4ZSIgLU5vUHJvZmlsZSAtTm9uSW50ZXJhY3RpdmUgLUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVdpbmRvd1N0eWxlIEhpZGRlbiAtRmlsZSAiQzpcUHJvZ3JhbSBGaWxlc1xPcGVuUHJpbWVcT3BlblByaW1lUk1NLVdVLUxhYi1MYXVuY2hlci5wczEiIC1Nb2RlIEluc3RhbGwgLVRpbWVvdXRTZWMgNTQwMApleGl0IC9iICVlcnJvcmxldmVsJQo=' }
    )
    foreach ($wuComponent in $wuComponents) {
        $wuNeedsWrite = $true
        if (Test-Path $wuComponent.Path) {
            try {
                $wuCurrentHash = (Get-FileHash -Path $wuComponent.Path -Algorithm SHA256 -ErrorAction Stop).Hash
                $wuNeedsWrite = ($wuCurrentHash -ne $wuComponent.Sha)
            } catch { $wuNeedsWrite = $true }
        }
        if ($wuNeedsWrite) {
            [System.IO.File]::WriteAllBytes($wuComponent.Path, [Convert]::FromBase64String($wuComponent.B64))
            Write-Log "WU provisioning: wrote $(Split-Path $wuComponent.Path -Leaf)."
        }
    }
    $wuTaskSpecs = @(
        @{ Name = 'OpenPrimeRMM WU Lab Scan'
           Args = @('/Create','/TN','OpenPrimeRMM WU Lab Scan','/SC','MINUTE','/MO','15','/TR',(Join-Path $WuLabDir 'run-scan.cmd'),'/RU','SYSTEM','/RL','HIGHEST','/F') },
        @{ Name = 'OpenPrimeRMM WU Lab Install'
           Args = @('/Create','/TN','OpenPrimeRMM WU Lab Install','/SC','ONSTART','/TR',(Join-Path $WuLabDir 'run-install.cmd'),'/RU','SYSTEM','/RL','HIGHEST','/F') }
    )
    foreach ($wuTaskSpec in $wuTaskSpecs) {
        $wuExistingTask = Get-ScheduledTask -TaskName $wuTaskSpec.Name -ErrorAction SilentlyContinue
        if ($wuExistingTask) { continue }
        $wuCreateOut = & "$env:SystemRoot\System32\schtasks.exe" $wuTaskSpec.Args 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "WU provisioning: could not create '$($wuTaskSpec.Name)' (exit ${LASTEXITCODE}): $wuCreateOut"
            continue
        }
        Write-Log "WU provisioning: registered task '$($wuTaskSpec.Name)'."
        try {
            $wuCreatedTask = Get-ScheduledTask -TaskName $wuTaskSpec.Name -ErrorAction Stop
            $wuCreatedTask.Settings.DisallowStartIfOnBatteries = $false
            $wuCreatedTask.Settings.StopIfGoingOnBatteries = $false
            $wuCreatedTask.Settings.MultipleInstances = 'IgnoreNew'
            Set-ScheduledTask -InputObject $wuCreatedTask -ErrorAction Stop | Out-Null
        } catch {
            Write-Log "WU provisioning: optional settings for '$($wuTaskSpec.Name)': $($_.Exception.Message)"
        }
    }
} catch {
    try { Write-Log "WU provisioning skipped: $($_.Exception.Message)" } catch {}
}

# The tray runs in the USER session via a logon scheduled task; the agent
# (SYSTEM) keeps its files and config current. tray.json intentionally
# contains no secrets - just the server URL, this device id, and the brand.
# ---------------------------------------------------------------------------
try {
    $trayDir  = Split-Path $PSCommandPath -Parent
    $trayPs1  = Join-Path $trayDir 'tray.ps1'
    $trayVbs  = Join-Path $trayDir 'tray.vbs'   # legacy (pre-1.11.1) - removed below
    $trayCfg  = Join-Path $DataDir 'tray.json'

    @{ base_url = $BaseUrl; agent_id = $Config.AgentId
       brand = [string]$resp.brand } | ConvertTo-Json -Compress | Set-Content $trayCfg -Encoding UTF8
    # DataDir is locked to SYSTEM+Administrators, but the tray runs as the
    # logged-in USER and must read tray.json - grant Users read on that one
    # file only (S-1-5-32-545 = builtin Users, locale-independent).
    try { & icacls $trayCfg /grant '*S-1-5-32-545:R' 2>&1 | Out-Null } catch {}

    # Cache the brand icon (best-effort; tray falls back to a system icon)
    try {
        $icoPath = Join-Path $trayDir 'tray.ico'
        if (-not (Test-Path $icoPath)) {
            Invoke-WebRequest -Uri "$BaseUrl/downloads/tray.ico" -OutFile $icoPath -UseBasicParsing -TimeoutSec 30
        }
    } catch {}

    $localTrayVer = ''
    if (Test-Path $trayPs1) {
        $m = Select-String -Path $trayPs1 -Pattern 'TrayVersion = ' | Select-Object -First 1
        if ($m) { $localTrayVer = ($m.Line -split [string][char]39)[1] }
    }
    # Download the tray if it's missing, or if the server advertises a newer
    # version. The "missing" case does NOT depend on the server sending a
    # version field, so the tray still installs against older servers.
    $needTray = (-not (Test-Path $trayPs1)) -or `
                ($resp.latest_tray_version -and ($resp.latest_tray_version -ne $localTrayVer))
    # One task-XML template used by install AND self-heal. The tray launches as
    # powershell.exe -WindowStyle Hidden DIRECTLY - the old wscript.exe->hidden
    # PowerShell chain (tray.vbs) is a textbook malware pattern and was flagged
    # by Bitdefender ATC. Worst case now is a sub-second window flash at logon.
    $trayTaskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>OpenPrime RMM support tray</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author">
    <GroupId>S-1-5-32-545</GroupId><RunLevel>LeastPrivilege</RunLevel>
  </Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled><Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>conhost.exe</Command>
    <Arguments>--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File &quot;$trayPs1&quot;</Arguments></Exec>
  </Actions>
</Task>
"@
    function Register-TrayTask {
        $xmlPath = Join-Path $StageDir 'tray_task.xml'
        Set-Content -Path $xmlPath -Value $trayTaskXml -Encoding Unicode
        & schtasks.exe /Create /TN 'OpenPrime Tray' /XML $xmlPath /F 2>&1 | Out-Null
        Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
    }
    function Stop-TrayProcesses {
        # Kill any running tray instance so a freshly-downloaded tray.ps1 can
        # take over WITHOUT a logoff/reboot. The tray holds a single-instance
        # mutex (Local\OpenPrimeTray), so a new launch would otherwise exit
        # immediately while the OLD form keeps showing. We match on the tray.ps1
        # command line only - never a blanket powershell kill. Runs as SYSTEM so
        # it can terminate the user-session process. Guarded and only called on
        # the version-change path, so it never runs on a normal check-in.
        try {
            $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
                     Where-Object { $_.CommandLine -and $_.CommandLine -match 'tray\.ps1' }
            foreach ($p in $procs) {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                Write-Log "Stopped old tray process (PID $($p.ProcessId)) for live update."
            }
        } catch { Write-Log "Stop-TrayProcesses skipped: $($_.Exception.Message)" }
    }
    function Start-TrayTask {
        # Direct call operator, NOT Start-Process: in Windows PowerShell 5.1,
        # Start-Process -ArgumentList joins elements with spaces WITHOUT
        # quoting, so 'OpenPrime Tray' became two arguments and schtasks failed
        # silently on every kick (bug in <=1.11.2). The & operator quotes
        # arguments containing spaces correctly, and we log the real exit code
        # instead of swallowing failures.
        try {
            $out = & "$env:SystemRoot\System32\schtasks.exe" /Run /TN 'OpenPrime Tray' 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Log "Tray kick failed (exit $LASTEXITCODE): $out"
                return $false
            }
            return $true
        } catch {
            Write-Log "Tray kick failed: $($_.Exception.Message)"
            return $false
        }
    }

    if ($needTray) {
        $tmp = Join-Path $StageDir ("tray_" + [guid]::NewGuid().ToString('N') + ".ps1")
        Invoke-WebRequest -Uri "$BaseUrl/downloads/tray.ps1" -OutFile $tmp -UseBasicParsing -TimeoutSec 120
        if ((Get-Item $tmp).Length -gt 1KB -and (Select-String -Path $tmp -Pattern 'OpenPrime tray' -Quiet)) {
            Copy-Item $tmp -Destination $trayPs1 -Force
            Write-Log "Tray script downloaded to $trayPs1"
            # Register a per-logon task so the tray starts for every user at sign-in.
            # Built with schtasks XML (more reliable from SYSTEM than
            # Register-ScheduledTask with a group principal on some Windows builds).
            Register-TrayTask
            # NOTE: the live-swap (stop old + kick new) is handled by the
            # version-marker reconciliation in the self-heal section below, NOT
            # here - so it fires correctly even when this download happened under
            # the OLD agent code and the new logic only runs next cycle.
            Write-Log "Tray installed/updated to $($resp.latest_tray_version)"
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }

    # One-time cleanup: remove the legacy tray.vbs left by pre-1.11.1 agents.
    # Nothing references it anymore, and leaving a hidden-launcher .vbs around
    # is precisely the artifact AV heuristics dislike.
    if (Test-Path $trayVbs) {
        Remove-Item $trayVbs -Force -ErrorAction SilentlyContinue
        Write-Log "Removed legacy tray.vbs (1.11.1 launches PowerShell directly)."
    }

    # Self-heal: make sure the logon task exists, AND that it's the new direct-
    # PowerShell version (upgraders from <=1.11.0 still have a wscript task
    # pointing at the now-deleted vbs, so we re-register unconditionally when the
    # action still mentions wscript). Cheap query, no session/WMI calls that
    # could hang the agent.
    if (Test-Path $trayPs1) {
        $needReg = $true
        try {
            $existing = schtasks.exe /Query /TN 'OpenPrime Tray' /XML 2>$null | Out-String
            if ($existing) {
                # Re-register unless the task is already the current headless
                # form. Catches BOTH the old wscript tasks and the 1.11.1-1.11.6
                # powershell-direct tasks that pop a Windows Terminal window.
                $needReg = ($existing -notmatch 'headless')
            }
        } catch {}
        if ($needReg) {
            Register-TrayTask
            Write-Log "Tray logon task (re)registered as windowless (conhost --headless)."
            # A task shape change means any running tray is under the OLD task;
            # stop it so the next kick relaunches windowless.
            Stop-TrayProcesses
            Start-Sleep -Milliseconds 500
        }

        # Live-swap on version change (no logoff/reboot needed). The running tray
        # holds a single-instance mutex, so simply kicking won't replace an
        # already-running OLD tray - we must stop it first. We drive this off a
        # marker of the last version we activated, compared to the version now on
        # disk. Because it runs every check-in (not just on the download cycle),
        # it fires correctly even when the tray was downloaded under the previous
        # agent build and this new logic only took effect the next run. Fires
        # exactly once per version, then stays quiet.
        try {
            $diskVer = ''
            $mm = Select-String -Path $trayPs1 -Pattern 'TrayVersion = ' | Select-Object -First 1
            if ($mm) { $diskVer = ($mm.Line -split [string][char]39)[1] }
            $activeMarker = Join-Path $DataDir 'tray_active_version.txt'
            $activeVer = if (Test-Path $activeMarker) {
                (Get-Content $activeMarker -Raw -ErrorAction SilentlyContinue).Trim()
            } else { '' }
            if ($diskVer -and ($diskVer -ne $activeVer)) {
                Stop-TrayProcesses          # release the old mutex
                Start-Sleep -Milliseconds 500
                if (Start-TrayTask) {
                    Set-Content -Path $activeMarker -Value $diskVer -ErrorAction SilentlyContinue
                    Write-Log "Live-swapped tray $activeVer -> $diskVer (no logoff needed)."
                }
            }
        } catch { Write-Log "Tray version reconcile skipped: $($_.Exception.Message)" }

        # Ensure the tray is actually running. The logon trigger only fires at
        # sign-in, so a task created/repaired mid-session never launches until
        # the user logs off/on - and a crashed (or AV-killed) tray would stay
        # dead until reboot. So each check-in: if the task exists but is not in
        # the Running state, kick it. Locale-independent (State is an enum, not
        # parsed text). If no user is logged on, the kick harmlessly no-ops.
        # The tray's own mutex guarantees a single instance per session, and
        # 1.11.2 removed the old once-per-boot marker (tray_launched.txt) that
        # could swallow the kick after a mid-session repair.
        try {
            $tt = Get-ScheduledTask -TaskName 'OpenPrime Tray' -ErrorAction SilentlyContinue
            if ($tt -and $tt.State -ne 'Running') {
                if (Start-TrayTask) { Write-Log "Tray task was not running - kicked it." }
            }
            $marker = Join-Path $DataDir 'tray_launched.txt'
            if (Test-Path $marker) { Remove-Item $marker -Force -ErrorAction SilentlyContinue }
        } catch {}
    }
} catch {
    Write-Log "Tray maintenance failed: $($_.Exception.Message)"
}

# Approved update jobs run asynchronously in the isolated worker. The worker
# creates force-scan.flag after completion; the next core cycle triggers a new
# bounded scan without ever blocking the RMM heartbeat.

    $script:LastResp = $resp
}   # end Invoke-AgentCycle

# ===========================================================================
# Dispatcher: run one cycle, then either enter persistent LIVE mode (long-poll)
# or do the bounded interval fast-repoll and exit.
# ===========================================================================
$script:RestartRequested = $false
$script:LiveActive       = $false

Invoke-AgentCycle | Out-Null
$resp = $script:LastResp

if ($resp -and $resp.live_mode) {
    # ---- LIVE MODE: persistent long-poll -----------------------------------
    # Hold a request open to /api/agent/poll (~25s server-side); the server
    # releases it the instant a command is queued, so jobs run in ~1-2s. A full
    # check-in cycle still runs about once a minute for inventory/updates/tray/
    # self-update. The scheduled task's every-minute trigger is harmlessly
    # ignored while we're running (MultipleInstances=IgnoreNew) and doubles as a
    # watchdog: if this process ever dies, the next trigger starts a fresh one.
    $script:LiveActive = $true
    Write-Log "Entering LIVE mode (persistent long-poll)."
    # Ensure this instance won't be killed by a finite execution limit.
    try {
        $lt = Get-ScheduledTask -TaskName 'OpenPrime RMM Agent' -ErrorAction SilentlyContinue
        if ($lt -and $lt.Settings.ExecutionTimeLimit -ne 'PT0S') {
            $lt.Settings.ExecutionTimeLimit = 'PT0S'
            Set-ScheduledTask -InputObject $lt -ErrorAction SilentlyContinue | Out-Null
        }
    } catch {}

    $lastCycle = Get-Date
    $pollBody  = @{ agent_version = $AgentVersion }
    while ($true) {
        # Heartbeat for observability / future watchdog.
        try { (Get-Date).ToString('o') | Set-Content (Join-Path $DataDir 'heartbeat.txt') -ErrorAction SilentlyContinue } catch {}

        $pr = $null
        try {
            $pr = Invoke-Api -Method POST -Path '/api/agent/poll' -Body $pollBody
        } catch {
            # Network blip or server restart: back off briefly and retry. The
            # loop is the resilience - we never exit on a transient error.
            Start-Sleep -Seconds 5
        }
        if ($pr -and $pr.jobs -and $pr.jobs.Count -gt 0) {
            Invoke-JobList $pr.jobs
        }
        if ($pr -and ($pr.PSObject.Properties.Name -contains 'live_mode') -and (-not $pr.live_mode)) {
            Write-Log "Server turned LIVE mode off - reverting to interval."
            break
        }

        if (((Get-Date) - $lastCycle).TotalSeconds -ge 300) {
            Invoke-AgentCycle | Out-Null
            $rc = $script:LastResp
            $lastCycle = Get-Date
            if ($script:RestartRequested) {
                Write-Log "Agent updated - exiting so the task relaunches new code."
                break
            }
            # Only leave live mode if a SUCCESSFUL cycle says it's off. A failed
            # cycle ($rc = null) is transient - stay live and keep long-polling.
            if ($rc -and (-not $rc.live_mode)) {
                Write-Log "LIVE mode no longer effective - reverting to interval."
                break
            }
        }
    }
    # Leaving live mode: restore the interval execution limit for the next run.
    $script:LiveActive = $false
    try {
        $lt = Get-ScheduledTask -TaskName 'OpenPrime RMM Agent' -ErrorAction SilentlyContinue
        if ($lt -and $lt.Settings.ExecutionTimeLimit -ne 'PT10M') {
            $lt.Settings.ExecutionTimeLimit = 'PT10M'
            Set-ScheduledTask -InputObject $lt -ErrorAction SilentlyContinue | Out-Null
        }
    } catch {}
}
else {
    # ---- INTERVAL MODE: bounded fast re-poll, then exit --------------------
    # When the server set recheck_seconds (a command was just queued), keep
    # polling quickly for a short window so output returns in seconds instead of
    # waiting for the next scheduled run. Bounded by try count AND wall clock so
    # we always finish well inside the task's execution limit.
    $recheckTries = 0
    $recheckStart = Get-Date
    while ($resp.recheck_seconds -gt 0 -and $recheckTries -lt 40 -and `
           ((Get-Date) - $recheckStart).TotalSeconds -lt 150) {
        $recheckTries++
        Start-Sleep -Seconds ([Math]::Max(1, [int]$resp.recheck_seconds))
        try {
            $resp = Invoke-Api -Method POST -Path '/api/agent/checkin' -Body $script:checkin
        } catch { break }
        if ($resp.jobs -and $resp.jobs.Count -gt 0) { Invoke-JobList $resp.jobs }
    }
}
