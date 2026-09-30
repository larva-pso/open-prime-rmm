<#
.SYNOPSIS
  OpenPrime RMM agent  -  one check-in cycle.
  Runs as SYSTEM via a scheduled task every 5 minutes (see Install-Agent.ps1).

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

$AgentVersion = '1.12.6'
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
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    )
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
    try {
        $si = New-Object -ComObject 'Microsoft.Update.SystemInfo'
        return [bool]$si.RebootRequired
    } catch { return $false }
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
    $inv = @{ serial = ''; model = ''; cpu = ''; ram_gb = 0; last_user = ''; local_ip = ''; disks = @(); macs = @(); screenconnect_session_id = ''; screenconnect_service_name = '' }
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

function Invoke-RebootJob($Payload) {
    # Report success BEFORE rebooting, then schedule the reboot with a short delay
    # so the result POST has time to reach the server.
    $delay = 60
    if ($Payload.delay_sec) { $delay = [int]$Payload.delay_sec }
    $msg = 'OpenPrime-RMM: scheduled maintenance reboot'
    if ($Payload.message) { $msg = [string]$Payload.message }
    try {
        Start-Process -FilePath 'shutdown.exe' `
            -ArgumentList @('/r', '/t', "$delay", '/c', "`"$msg`"") `
            -WindowStyle Hidden
        return @{ ok = $true; exit_code = 0
                  output = "Reboot scheduled in $delay seconds. Message: $msg" }
    } catch {
        return @{ ok = $false; exit_code = -1; output = "Reboot failed: $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# Run a list of jobs handed back by check-in or the live poll, posting each
# result with retries. Shared by interval mode and live (long-poll) mode.
# ---------------------------------------------------------------------------
function Invoke-JobList($jobs) {
    foreach ($job in $jobs) {
        Write-Log "Running job $($job.id) [$($job.type)]"
        try {
            switch ($job.type) {
                'run_script'      { $result = Invoke-ScriptJob      $job.payload }
                'wake'            { $result = Invoke-WakeJob        $job.payload }
                'install_updates' { $result = Invoke-InstallUpdatesJob $job.payload }
                'reboot'          { $result = Invoke-RebootJob       $job.payload }
                default           { $result = @{ ok = $false; exit_code = -1; output = "Unknown job type '$($job.type)'" } }
            }
        } catch {
            # Belt and braces: job handlers catch their own errors, but if anything
            # ever escapes, still send SOMETHING so the job never sticks at 'running'.
            $result = @{ ok = $false; exit_code = -1
                         output = "Agent error (outer): $($_.Exception.Message)" }
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
    $os = Get-CimInstance Win32_OperatingSystem
    $inv = Get-HardwareInventory
    $script:checkin = @{
        hostname        = $env:COMPUTERNAME
        os_version      = "$($os.Caption) ($($os.Version))"
        agent_version   = $AgentVersion
        reboot_required = (Test-RebootRequired)
        updates         = (Get-PendingUpdates)
        inventory       = $inv
    }
    $resp = Invoke-Api -Method POST -Path '/api/agent/checkin' -Body $script:checkin
    Write-Log "Check-in OK  -  $($script:checkin.updates.Count) pending update(s), $($resp.jobs.Count) job(s) queued."

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
if ($resp.latest_agent_version -and ($resp.latest_agent_version -ne $AgentVersion)) {
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

# If we installed updates, immediately re-report so the dashboard reflects reality
if ($resp.jobs | Where-Object { $_.type -eq 'install_updates' }) {
    try {
        $script:checkin.updates         = (Get-PendingUpdates)
        $script:checkin.reboot_required = (Test-RebootRequired)
        Invoke-Api -Method POST -Path '/api/agent/checkin' -Body $script:checkin | Out-Null
    } catch {}
}

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
