"""OpenPrimeRMM built-in MSP workstation script pack.

Seeded once into the editable Script Library. Existing scripts with the same
name are never overwritten, and the pack marker prevents deleted scripts from
being recreated on every server restart.
"""

import json
import time

PACK_VERSION = "2026.08.02-v2"
PACK_SETTING_KEY = "builtin_msp_workstation_script_pack"
METADATA_SETTING_KEY = "builtin_msp_workstation_script_safety_v1"


# Safety metadata is intentionally separate from script content so existing
# technician edits are never overwritten. Only scripts whose names match the
# built-in pack receive these classifications.
MSP_SCRIPT_SAFETY = {
    "[MSP] Workstation Health Summary": ("diagnostic", True, False, "no"),
    "[MSP] Pending Reboot Check": ("diagnostic", True, False, "no"),
    "[MSP] Network & DNS Diagnostics": ("diagnostic", True, False, "no"),
    "[MSP] Test TCP Port": ("diagnostic", False, False, "no"),
    "[MSP] Recent Critical Event Log Summary": ("diagnostic", True, False, "no"),
    "[MSP] Automatic Services Not Running": ("diagnostic", True, False, "no"),
    "[MSP] Top CPU & Memory Processes": ("diagnostic", True, False, "no"),
    "[MSP] Disk & SMART Health": ("diagnostic", True, False, "no"),
    "[MSP] Local Administrators Audit": ("diagnostic", True, False, "no"),
    "[MSP] Security Posture Quick Audit": ("diagnostic", True, False, "no"),
    "[MSP] BitLocker Status": ("diagnostic", True, False, "no"),
    "[MSP] Installed Software Inventory": ("diagnostic", True, False, "no"),
    "[MSP] Driver Problem Devices": ("diagnostic", True, False, "no"),
    "[MSP] User Profile Disk Usage": ("diagnostic", True, False, "no"),
    "[MSP] Windows Update History": ("diagnostic", True, False, "no"),
    "[MSP] Battery Health Summary": ("diagnostic", True, False, "no"),
    "[MSP] OpenPrimeRMM Agent Health Check": ("diagnostic", True, False, "no"),
    "[MSP] ScreenConnect Health Check": ("diagnostic", True, False, "no"),
    "[MSP] Safe Temporary File Cleanup": ("safe_remediation", False, True, "no"),
    "[MSP] Repair Windows Image (DISM + SFC)": ("safe_remediation", False, True, "possible"),
    "[MSP] Restart Print Spooler & Clear Queue": ("disruptive", False, True, "no"),
    "[MSP] Repair Windows Time Sync": ("safe_remediation", False, True, "no"),
    "[MSP] Refresh Group Policy": ("safe_remediation", False, True, "no"),
    "[MSP] Reset Windows Update Components": ("disruptive", False, True, "possible"),
    "[MSP] Reset Winsock & TCP-IP Stack": ("disruptive", False, True, "yes"),
    "[MSP] Restart Service by Name": ("safe_remediation", False, True, "no"),
    "[MSP] Flush DNS Cache": ("safe_remediation", False, True, "no"),
    "[MSP] Component Store Cleanup": ("safe_remediation", False, True, "possible"),
}


def apply_msp_script_metadata(conn, force=False):
    """Apply built-in safety metadata once without touching script content.

    The marker matters: technicians remain free to reclassify a built-in script
    later and OpenPrimeRMM will not silently overwrite that choice on restart.
    """
    marker = conn.execute("SELECT value FROM settings WHERE key=?", (METADATA_SETTING_KEY,)).fetchone()
    if marker and not force:
        return 0
    updated = 0
    for name, (safety, auto_allowed, changes_system, reboot_impact) in MSP_SCRIPT_SAFETY.items():
        cur = conn.execute(
            "UPDATE scripts SET safety_class=?, ai_auto_allowed=?, changes_system=?, reboot_impact=? "
            "WHERE lower(name)=lower(?)",
            (safety, 1 if auto_allowed else 0, 1 if changes_system else 0, reboot_impact, name),
        )
        updated += cur.rowcount
    conn.execute(
        "INSERT OR REPLACE INTO settings(key,value) VALUES (?,?)",
        (METADATA_SETTING_KEY, PACK_VERSION),
    )
    return updated


def _var(name, calc, vtype="text", description="", default="", mandatory=False, options=None):
    return {
        "name": name,
        "calc": calc,
        "type": vtype,
        "description": description,
        "default": str(default),
        "mandatory": bool(mandatory),
        "options": list(options or []),
    }


MSP_SCRIPTS = [
    {
        "name": "[MSP] Workstation Health Summary",
        "description": "Read-only workstation snapshot: OS, uptime, CPU/RAM, disks, logged-on user, pending reboot, network, and key service state.",
        "shell": "powershell",
        "timeout_sec": 180,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
function Section($Name) { Write-Output "`n=== $Name ===" }

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$boot = $os.LastBootUpTime
$uptime = (Get-Date) - $boot

Section 'System'
Write-Output "Computer: $env:COMPUTERNAME"
Write-Output "OS: $($os.Caption) $($os.Version) build $($os.BuildNumber)"
Write-Output "Architecture: $($os.OSArchitecture)"
Write-Output "Manufacturer/Model: $($cs.Manufacturer) / $($cs.Model)"
Write-Output "CPU: $($cpu.Name)"
Write-Output ("RAM: {0:N1} GB" -f ($cs.TotalPhysicalMemory / 1GB))
Write-Output ("Uptime: {0} day(s), {1} hour(s), {2} minute(s)" -f $uptime.Days,$uptime.Hours,$uptime.Minutes)
Write-Output "Last boot: $boot"
Write-Output "Logged-on user: $($cs.UserName)"

Section 'Storage'
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $freePct = if ($_.Size) { [math]::Round(($_.FreeSpace / $_.Size) * 100,1) } else { 0 }
    Write-Output ("{0}  Size={1:N1} GB  Free={2:N1} GB ({3}%)" -f $_.DeviceID,($_.Size/1GB),($_.FreeSpace/1GB),$freePct)
}

Section 'Pending reboot'
$reboot = $false
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reboot = $true }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reboot = $true }
$sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
if ($sm.PendingFileRenameOperations) { $reboot = $true }
Write-Output "Pending reboot: $reboot"

Section 'Network'
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object {
    Write-Output "Adapter: $($_.Description)"
    Write-Output "  IP: $($_.IPAddress -join ', ')"
    Write-Output "  Gateway: $($_.DefaultIPGateway -join ', ')"
    Write-Output "  DNS: $($_.DNSServerSearchOrder -join ', ')"
}

Section 'Key services'
foreach ($name in 'Dnscache','W32Time','BITS','wuauserv','Spooler') {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($s) { Write-Output ("{0}: {1} / start={2}" -f $name,$s.Status,$s.StartType) }
}
exit 0
''',
    },
    {
        "name": "[MSP] Pending Reboot Check",
        "description": "Read-only check for Windows servicing, Windows Update, pending file rename, domain join, and computer rename reboot indicators.",
        "shell": "powershell",
        "timeout_sec": 90,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$reasons = New-Object System.Collections.Generic.List[string]

if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
    $reasons.Add('Component Based Servicing: RebootPending')
}
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
    $reasons.Add('Windows Update: RebootRequired')
}
$sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
if ($sm.PendingFileRenameOperations) { $reasons.Add('PendingFileRenameOperations') }
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\JoinDomain') { $reasons.Add('Pending domain join') }
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\AvoidSpnSet') { $reasons.Add('Pending domain operation') }
$active = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction SilentlyContinue
$pending = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue
if ($active.ComputerName -and $pending.ComputerName -and $active.ComputerName -ne $pending.ComputerName) {
    $reasons.Add("Computer rename pending: $($active.ComputerName) -> $($pending.ComputerName)")
}

if ($reasons.Count -eq 0) {
    Write-Output 'Pending reboot: NO'
} else {
    Write-Output 'Pending reboot: YES'
    $reasons | ForEach-Object { Write-Output " - $_" }
}
exit 0
''',
    },
    {
        "name": "[MSP] Network & DNS Diagnostics",
        "description": "Read-only network diagnostic: adapters, routes, DNS servers/cache, default gateway reachability, DNS resolution, and HTTPS connectivity.",
        "shell": "powershell",
        "timeout_sec": 180,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
function Section($Name) { Write-Output "`n=== $Name ===" }

Section 'IP configuration'
Get-NetIPConfiguration | ForEach-Object {
    Write-Output "Interface: $($_.InterfaceAlias)"
    Write-Output "  IPv4: $($_.IPv4Address.IPAddress -join ', ')"
    Write-Output "  Gateway: $($_.IPv4DefaultGateway.NextHop -join ', ')"
    Write-Output "  DNS: $($_.DNSServer.ServerAddresses -join ', ')"
}

Section 'Default route'
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 5 InterfaceAlias,NextHop,RouteMetric | Format-Table -AutoSize | Out-String | Write-Output

Section 'Gateway test'
$gateways = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -ExpandProperty NextHop -Unique
foreach ($gw in $gateways) {
    $ok = Test-Connection -ComputerName $gw -Count 2 -Quiet
    Write-Output "Gateway $gw reachable: $ok"
}

Section 'DNS resolution'
foreach ($hostName in 'rmm.example.com','www.microsoft.com') {
    try {
        $ans = Resolve-DnsName $hostName -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress
        Write-Output "$hostName -> $($ans -join ', ')"
    } catch { Write-Output "$hostName -> FAILED: $($_.Exception.Message)" }
}

Section 'HTTPS test'
$t = Test-NetConnection -ComputerName 'rmm.example.com' -Port 443 -WarningAction SilentlyContinue
Write-Output "rmm.example.com:443 TcpTestSucceeded=$($t.TcpTestSucceeded) RemoteAddress=$($t.RemoteAddress)"

Section 'DNS cache sample'
Get-DnsClientCache | Select-Object -First 25 Entry,RecordName,RecordType,Data | Format-Table -AutoSize | Out-String | Write-Output
exit 0
''',
    },
    {
        "name": "[MSP] Test TCP Port",
        "description": "Tests DNS resolution and TCP connectivity to a technician-supplied host and port.",
        "shell": "powershell",
        "timeout_sec": 120,
        "variables": [
            _var("Target host", "targetHost", "text", "DNS name or IP address to test.", "rmm.example.com", True),
            _var("TCP port", "targetPort", "integer", "TCP port to test.", "443", True),
        ],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'Stop'
$hostName = $env:targetHost
$port = [int]$env:targetPort
if (-not $hostName -or $hostName -eq 'null') { throw 'targetHost is required.' }

Write-Output "Target: $hostName`:$port"
try {
    $resolved = Resolve-DnsName $hostName -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique
    Write-Output "Resolved: $($resolved -join ', ')"
} catch {
    Write-Output "DNS resolution failed: $($_.Exception.Message)"
}
$t = Test-NetConnection -ComputerName $hostName -Port $port -WarningAction SilentlyContinue
$t | Select-Object ComputerName,RemoteAddress,RemotePort,InterfaceAlias,SourceAddress,TcpTestSucceeded | Format-List | Out-String | Write-Output
if (-not $t.TcpTestSucceeded) { exit 2 }
exit 0
''',
    },
    {
        "name": "[MSP] Recent Critical Event Log Summary",
        "description": "Read-only summary of recent Critical/Error events from System and Application logs, grouped by provider and event ID.",
        "shell": "powershell",
        "timeout_sec": 180,
        "variables": [
            _var("Hours to review", "hoursBack", "integer", "How far back to inspect System and Application logs.", "24", True),
        ],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$hours = [int]$env:hoursBack
if ($hours -lt 1) { $hours = 24 }
$start = (Get-Date).AddHours(-$hours)

Write-Output "Reviewing Critical/Error events since $start"
$events = foreach ($log in 'System','Application') {
    Get-WinEvent -FilterHashtable @{LogName=$log; Level=1,2; StartTime=$start} -ErrorAction SilentlyContinue |
        Select-Object @{N='Log';E={$log}},TimeCreated,Id,ProviderName,Message
}

if (-not $events) {
    Write-Output 'No Critical/Error events found in the selected period.'
    exit 0
}

Write-Output "`n=== Top event groups ==="
$events | Group-Object Log,ProviderName,Id | Sort-Object Count -Descending | Select-Object -First 25 Count,Name | Format-Table -AutoSize | Out-String | Write-Output

Write-Output "`n=== Most recent events ==="
$events | Sort-Object TimeCreated -Descending | Select-Object -First 30 | ForEach-Object {
    $msg = ($_.Message -replace '[\r\n]+',' ')
    if ($msg.Length -gt 350) { $msg = $msg.Substring(0,350) + '...' }
    Write-Output ("{0:u} [{1}] {2}/{3}: {4}" -f $_.TimeCreated,$_.Log,$_.ProviderName,$_.Id,$msg)
}
exit 0
''',
    },
    {
        "name": "[MSP] Automatic Services Not Running",
        "description": "Read-only audit of Automatic services that are currently stopped. Trigger-start and delayed-start behavior may make some findings normal.",
        "shell": "powershell",
        "timeout_sec": 120,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$services = Get-CimInstance Win32_Service | Where-Object {
    $_.StartMode -eq 'Auto' -and $_.State -ne 'Running'
} | Sort-Object DisplayName

if (-not $services) {
    Write-Output 'All services configured for Automatic start are running.'
    exit 0
}
Write-Output "Automatic services not running: $($services.Count)"
$services | Select-Object Name,DisplayName,State,StartMode,ExitCode,ProcessId | Format-Table -AutoSize | Out-String | Write-Output
Write-Output 'Note: trigger-start services can legitimately be stopped even when configured Automatic.'
exit 0
''',
    },
    {
        "name": "[MSP] Top CPU & Memory Processes",
        "description": "Read-only snapshot of highest CPU-time and working-set processes, including PID and executable path where available.",
        "shell": "powershell",
        "timeout_sec": 90,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$procs = Get-Process | ForEach-Object {
    $path = $null
    try { $path = $_.Path } catch {}
    [pscustomobject]@{
        Process = $_.ProcessName
        PID = $_.Id
        CPU_s = [math]::Round([double]$_.CPU,1)
        Memory_MB = [math]::Round($_.WorkingSet64 / 1MB,1)
        Handles = $_.Handles
        Path = $path
    }
}
Write-Output '=== Top by CPU time ==='
$procs | Sort-Object CPU_s -Descending | Select-Object -First 20 | Format-Table -AutoSize | Out-String | Write-Output
Write-Output '=== Top by memory ==='
$procs | Sort-Object Memory_MB -Descending | Select-Object -First 20 | Format-Table -AutoSize | Out-String | Write-Output
exit 0
''',
    },
    {
        "name": "[MSP] Disk & SMART Health",
        "description": "Read-only physical/logical disk health, storage reliability counters when available, and free-space summary.",
        "shell": "powershell",
        "timeout_sec": 180,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
Write-Output '=== Physical disks ==='
$physical = Get-PhysicalDisk -ErrorAction SilentlyContinue
if ($physical) {
    $physical | Select-Object FriendlyName,SerialNumber,MediaType,BusType,HealthStatus,OperationalStatus,@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}} | Format-Table -AutoSize | Out-String | Write-Output
    Write-Output '=== Reliability counters ==='
    foreach ($d in $physical) {
        try {
            $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop
            Write-Output "Disk: $($d.FriendlyName)"
            $r | Select-Object Temperature,Wear,ReadErrorsTotal,WriteErrorsTotal,PowerOnHours | Format-List | Out-String | Write-Output
        } catch { Write-Output "Disk: $($d.FriendlyName) - reliability counters unavailable" }
    }
} else {
    Write-Output 'Get-PhysicalDisk returned no data; using Win32_DiskDrive.'
    Get-CimInstance Win32_DiskDrive | Select-Object Model,SerialNumber,Status,@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}} | Format-Table -AutoSize | Out-String | Write-Output
}
Write-Output '=== Volumes ==='
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,VolumeName,FileSystem,@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}},@{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,1)}},@{N='FreePct';E={if($_.Size){[math]::Round(($_.FreeSpace/$_.Size)*100,1)}else{0}}} | Format-Table -AutoSize | Out-String | Write-Output
exit 0
''',
    },
    {
        "name": "[MSP] Local Administrators Audit",
        "description": "Read-only listing of members of the local Administrators group, including domain/AzureAD accounts when Windows resolves them.",
        "shell": "powershell",
        "timeout_sec": 120,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
try {
    $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
    $members | Select-Object Name,ObjectClass,PrincipalSource,SID | Format-Table -AutoSize | Out-String | Write-Output
} catch {
    Write-Output "Get-LocalGroupMember unavailable/failed: $($_.Exception.Message)"
    Write-Output 'Fallback via ADSI:'
    $group = [ADSI]("WinNT://$env:COMPUTERNAME/Administrators,group")
    @($group.psbase.Invoke('Members')) | ForEach-Object {
        $flags = [System.Reflection.BindingFlags]::GetProperty
        $name = $_.GetType().InvokeMember('Name',$flags,$null,$_,$null)
        $class = $_.GetType().InvokeMember('Class',$flags,$null,$_,$null)
        Write-Output "$name [$class]"
    }
}
exit 0
''',
    },
    {
        "name": "[MSP] Security Posture Quick Audit",
        "description": "Read-only workstation security snapshot: Firewall, Defender registration/status, TPM, Secure Boot, BitLocker, SMBv1, UAC, and Remote Desktop state.",
        "shell": "powershell",
        "timeout_sec": 180,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
function Section($Name) { Write-Output "`n=== $Name ===" }

Section 'Windows Firewall'
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize | Out-String | Write-Output

Section 'Security Center antivirus products'
try {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName,productState,pathToSignedProductExe | Format-Table -AutoSize | Out-String | Write-Output
} catch { Write-Output 'SecurityCenter2 antivirus inventory unavailable.' }

Section 'Microsoft Defender'
try {
    Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,BehaviorMonitorEnabled,RealTimeProtectionEnabled,NISEnabled,AntivirusSignatureLastUpdated | Format-List | Out-String | Write-Output
} catch { Write-Output 'Defender cmdlets unavailable or Defender is managed by another product.' }

Section 'TPM'
try { Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,ManufacturerIdTxt | Format-List | Out-String | Write-Output } catch { Write-Output 'TPM information unavailable.' }

Section 'Secure Boot'
try { Write-Output "Secure Boot enabled: $(Confirm-SecureBootUEFI)" } catch { Write-Output 'Secure Boot status unavailable (legacy BIOS or unsupported).' }

Section 'BitLocker'
try { Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod | Format-Table -AutoSize | Out-String | Write-Output } catch { Write-Output 'BitLocker cmdlets unavailable.' }

Section 'SMBv1'
$feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($feat) { Write-Output "SMB1Protocol state: $($feat.State)" } else { Write-Output 'SMB1Protocol feature not present.' }

Section 'UAC'
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
Write-Output "EnableLUA: $($uac.EnableLUA)"
Write-Output "ConsentPromptBehaviorAdmin: $($uac.ConsentPromptBehaviorAdmin)"

Section 'Remote Desktop'
$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
Write-Output "RDP enabled: $([bool]($ts.fDenyTSConnections -eq 0))"
exit 0
''',
    },
    {
        "name": "[MSP] BitLocker Status",
        "description": "Read-only BitLocker status for all volumes. Does not expose recovery passwords.",
        "shell": "powershell",
        "timeout_sec": 120,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
try {
    $vols = Get-BitLockerVolume -ErrorAction Stop
    $vols | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod,AutoUnlockEnabled | Format-Table -AutoSize | Out-String | Write-Output
    foreach ($v in $vols) {
        Write-Output "`n$($v.MountPoint) key protector types: $((@($v.KeyProtector).KeyProtectorType | Sort-Object -Unique) -join ', ')"
    }
} catch {
    Write-Output "BitLocker cmdlets unavailable or failed: $($_.Exception.Message)"
}
exit 0
''',
    },
    {
        "name": "[MSP] Installed Software Inventory",
        "description": "Read-only installed application inventory from registry uninstall keys. Avoids Win32_Product and its repair side effects.",
        "shell": "powershell",
        "timeout_sec": 180,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$paths = @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = foreach ($path in $paths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        [pscustomobject]@{
            Name = $_.DisplayName
            Version = $_.DisplayVersion
            Publisher = $_.Publisher
            InstallDate = $_.InstallDate
            InstallLocation = $_.InstallLocation
        }
    }
}
$apps | Sort-Object Name,Version -Unique | Format-Table -AutoSize | Out-String -Width 240 | Write-Output
Write-Output "Application count: $(@($apps | Sort-Object Name,Version -Unique).Count)"
exit 0
''',
    },
    {
        "name": "[MSP] Driver Problem Devices",
        "description": "Read-only list of Plug-and-Play devices reporting a non-zero ConfigManager error code, plus signed driver details where available.",
        "shell": "powershell",
        "timeout_sec": 180,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$bad = Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
if (-not $bad) {
    Write-Output 'No Plug-and-Play devices report ConfigManager errors.'
    exit 0
}
Write-Output "Devices with problems: $($bad.Count)"
$bad | Select-Object Name,PNPClass,Status,ConfigManagerErrorCode,DeviceID | Format-Table -AutoSize | Out-String -Width 260 | Write-Output
Write-Output '`nMatching signed driver records:'
$ids = @($bad.DeviceID)
Get-CimInstance Win32_PnPSignedDriver | Where-Object { $ids -contains $_.DeviceID } | Select-Object DeviceName,DriverProviderName,DriverVersion,DriverDate,InfName | Format-Table -AutoSize | Out-String -Width 220 | Write-Output
exit 0
''',
    },
    {
        "name": "[MSP] User Profile Disk Usage",
        "description": "Read-only size summary for local user profile folders. Useful for locating unusually large profiles before cleanup or migration.",
        "shell": "powershell",
        "timeout_sec": 900,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -and (Test-Path $_.LocalPath) }
$result = foreach ($p in $profiles) {
    $bytes = 0L
    try {
        $bytes = (Get-ChildItem -LiteralPath $p.LocalPath -Force -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    } catch {}
    [pscustomobject]@{
        Profile = $p.LocalPath
        Loaded = $p.Loaded
        LastUse = $p.LastUseTime
        SizeGB = [math]::Round($bytes / 1GB,2)
    }
}
$result | Sort-Object SizeGB -Descending | Format-Table -AutoSize | Out-String | Write-Output
exit 0
''',
    },
    {
        "name": "[MSP] Windows Update History",
        "description": "Read-only installed hotfix/update history for the selected number of days. Does not initiate a Windows Update scan.",
        "shell": "powershell",
        "timeout_sec": 180,
        "variables": [
            _var("Days to review", "daysBack", "integer", "Show installed hotfixes from this many days back.", "30", True),
        ],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$days = [int]$env:daysBack
if ($days -lt 1) { $days = 30 }
$cutoff = (Get-Date).AddDays(-$days)
$hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Where-Object {
    $_.InstalledOn -and $_.InstalledOn -ge $cutoff
} | Sort-Object InstalledOn -Descending
if ($hotfixes) {
    $hotfixes | Select-Object HotFixID,Description,InstalledBy,InstalledOn | Format-Table -AutoSize | Out-String | Write-Output
} else {
    Write-Output "No Get-HotFix entries found in the last $days day(s)."
}
exit 0
''',
    },
    {
        "name": "[MSP] Battery Health Summary",
        "description": "Read-only laptop battery status and Windows battery-report location. Desktop systems safely report that no battery was detected.",
        "shell": "powershell",
        "timeout_sec": 180,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$batteries = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
if (-not $batteries) {
    Write-Output 'No Win32_Battery device detected; this is likely a desktop or battery telemetry is unavailable.'
    exit 0
}
$batteries | Select-Object Name,Status,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,Chemistry,DesignVoltage | Format-List | Out-String | Write-Output
$report = 'C:\Windows\Temp\OpenPrimeRMM-BatteryReport.html'
& powercfg.exe /batteryreport /output $report 2>&1 | Out-String | Write-Output
if (Test-Path $report) { Write-Output "Detailed battery report created at: $report" }
exit 0
''',
    },
    {
        "name": "[MSP] OpenPrimeRMM Agent Health Check",
        "description": "Read-only OpenPrimeRMM endpoint self-check: agent/tray versions, enrollment presence without exposing tokens, scheduled task status, launcher, and recent log activity.",
        "shell": "powershell",
        "timeout_sec": 120,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$agent = 'C:\Program Files\OpenPrime\agent.ps1'
$tray = 'C:\Program Files\OpenPrime\tray.ps1'
$config = 'C:\ProgramData\OpenPrime\config.json'
$launcher = 'C:\ProgramData\OpenPrime\run-agent.cmd'
$log = 'C:\ProgramData\OpenPrime\agent.log'

Write-Output '=== Files ==='
foreach ($p in $agent,$tray,$config,$launcher,$log) { Write-Output "$p : $(Test-Path $p)" }
if (Test-Path $agent) {
    $v = Select-String -Path $agent -Pattern '^\s*\$AgentVersion\s*=' | Select-Object -First 1
    Write-Output "Agent: $($v.Line.Trim())"
}
if (Test-Path $tray) {
    $v = Select-String -Path $tray -Pattern '^\s*\$TrayVersion\s*=' | Select-Object -First 1
    Write-Output "Tray: $($v.Line.Trim())"
}
if (Test-Path $config) {
    try {
        $c = Get-Content $config -Raw | ConvertFrom-Json
        Write-Output "Enrollment config readable: True"
        if ($c.agent_id) { Write-Output "Agent ID present: True" }
        if ($c.agent_token) { Write-Output "Agent token present: True (redacted)" }
        if ($c.server_url) { Write-Output "Server URL: $($c.server_url)" }
    } catch { Write-Output "Enrollment config readable: False - $($_.Exception.Message)" }
}

Write-Output '`n=== Scheduled task ==='
$t = Get-ScheduledTask -TaskName 'OpenPrime RMM Agent' -ErrorAction SilentlyContinue
if ($t) {
    $i = Get-ScheduledTaskInfo -TaskName 'OpenPrime RMM Agent' -ErrorAction SilentlyContinue
    Write-Output "State: $($t.State)"
    Write-Output "LastRunTime: $($i.LastRunTime)"
    Write-Output "LastTaskResult: $($i.LastTaskResult)"
    Write-Output "NextRunTime: $($i.NextRunTime)"
    Write-Output "UserId: $($t.Principal.UserId)"
} else { Write-Output 'Task missing.' }

Write-Output '`n=== Recent agent log ==='
if (Test-Path $log) { Get-Content $log -Tail 25 }
exit 0
''',
    },
    {
        "name": "[MSP] ScreenConnect Health Check",
        "description": "Read-only discovery of ScreenConnect / ConnectWise Control services, process state, startup type, and installed service executable paths.",
        "shell": "powershell",
        "timeout_sec": 120,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$services = Get-CimInstance Win32_Service | Where-Object {
    $_.Name -match 'ScreenConnect|ConnectWiseControl' -or $_.DisplayName -match 'ScreenConnect|ConnectWise Control'
}
if (-not $services) {
    Write-Output 'No ScreenConnect / ConnectWise Control service found.'
    exit 0
}
$services | Select-Object Name,DisplayName,State,StartMode,ProcessId,PathName | Format-List | Out-String | Write-Output
foreach ($s in $services) {
    if ($s.ProcessId -gt 0) {
        $p = Get-Process -Id $s.ProcessId -ErrorAction SilentlyContinue
        if ($p) { Write-Output "Process $($p.ProcessName) PID=$($p.Id) started=$($p.StartTime)" }
    }
}
exit 0
''',
    },
    {
        "name": "[MSP] Safe Temporary File Cleanup",
        "description": "Removes old files from Windows/user temp locations. Defaults to DRY RUN. Optional recycle-bin cleanup is disabled by default.",
        "shell": "powershell",
        "timeout_sec": 1800,
        "variables": [
            _var("Age in days", "daysOld", "integer", "Only items older than this many days are candidates.", "7", True),
            _var("Dry run", "dryRun", "checkbox", "When true, report candidates without deleting them.", "true", False),
            _var("Clear recycle bin", "clearRecycleBin", "checkbox", "Also empty recycle bins when not in dry-run mode.", "false", False),
        ],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'SilentlyContinue'
$days = [int]$env:daysOld
if ($days -lt 1) { $days = 7 }
$dry = $env:dryRun -eq 'true'
$clearBin = $env:clearRecycleBin -eq 'true'
$cutoff = (Get-Date).AddDays(-$days)
$paths = New-Object System.Collections.Generic.List[string]
$paths.Add('C:\Windows\Temp')
Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Join-Path $_.FullName 'AppData\Local\Temp'
    if (Test-Path $p) { $paths.Add($p) }
}

$totalBytes = 0L
$totalFiles = 0
foreach ($root in $paths | Sort-Object -Unique) {
    Write-Output "Scanning: $root"
    $files = Get-ChildItem -LiteralPath $root -Force -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff }
    foreach ($f in $files) {
        $totalFiles++
        $totalBytes += $f.Length
        if (-not $dry) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
    }
    if (-not $dry) {
        Get-ChildItem -LiteralPath $root -Force -Recurse -Directory -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Where-Object { $_.LastWriteTime -lt $cutoff } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}
Write-Output ("Candidates: {0} files / {1:N2} GB" -f $totalFiles,($totalBytes/1GB))
Write-Output "Dry run: $dry"
if ($clearBin -and -not $dry) {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Output 'Recycle Bin cleanup requested.'
}
exit 0
''',
    },
    {
        "name": "[MSP] Repair Windows Image (DISM + SFC)",
        "description": "Runs DISM RestoreHealth followed by SFC /scannow. Long-running repair; does not reboot automatically.",
        "shell": "powershell",
        "timeout_sec": 7200,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'Continue'
Write-Output '=== DISM /Online /Cleanup-Image /RestoreHealth ==='
& dism.exe /Online /Cleanup-Image /RestoreHealth
$dismCode = $LASTEXITCODE
Write-Output "DISM exit code: $dismCode"

Write-Output '`n=== SFC /scannow ==='
& sfc.exe /scannow
$sfcCode = $LASTEXITCODE
Write-Output "SFC exit code: $sfcCode"

if ($dismCode -ne 0 -or $sfcCode -notin 0,1,2,3) {
    Write-Output 'One or more repair commands returned an unexpected exit code.'
    exit 1
}
exit 0
''',
    },
    {
        "name": "[MSP] Restart Print Spooler & Clear Queue",
        "description": "Stops Print Spooler, removes queued spool files, and starts the service. WARNING: deletes all currently queued print jobs.",
        "shell": "powershell",
        "timeout_sec": 300,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'Stop'
$spool = 'C:\Windows\System32\spool\PRINTERS'
Write-Output 'Stopping Print Spooler...'
Stop-Service Spooler -Force -ErrorAction Stop
Start-Sleep -Seconds 2
$count = 0
if (Test-Path $spool) {
    $items = Get-ChildItem $spool -Force -ErrorAction SilentlyContinue
    $count = @($items).Count
    $items | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
}
Write-Output "Removed $count queued spool item(s)."
Start-Service Spooler -ErrorAction Stop
Write-Output "Spooler state: $((Get-Service Spooler).Status)"
exit 0
''',
    },
    {
        "name": "[MSP] Repair Windows Time Sync",
        "description": "Repairs Windows Time service and resyncs. Domain members use domain hierarchy; workgroup machines use time.windows.com.",
        "shell": "powershell",
        "timeout_sec": 300,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'Continue'
$cs = Get-CimInstance Win32_ComputerSystem
Set-Service W32Time -StartupType Automatic -ErrorAction SilentlyContinue
Restart-Service W32Time -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if ($cs.PartOfDomain) {
    Write-Output "Domain member: $($cs.Domain) - configuring domain hierarchy."
    & w32tm.exe /config /syncfromflags:domhier /update
} else {
    Write-Output 'Workgroup computer - configuring time.windows.com.'
    & w32tm.exe /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /update
}
Restart-Service W32Time -Force -ErrorAction SilentlyContinue
& w32tm.exe /resync /rediscover
Write-Output '`n=== Status ==='
& w32tm.exe /query /status
Write-Output '`n=== Source ==='
& w32tm.exe /query /source
exit 0
''',
    },
    {
        "name": "[MSP] Refresh Group Policy",
        "description": "Runs gpupdate /force for computer and user policy. Useful on domain-managed endpoints; harmlessly reports errors on workgroup PCs.",
        "shell": "powershell",
        "timeout_sec": 600,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'Continue'
$cs = Get-CimInstance Win32_ComputerSystem
Write-Output "Part of domain: $($cs.PartOfDomain)"
Write-Output "Domain/workgroup: $($cs.Domain)"
& gpupdate.exe /force /wait:120
$code = $LASTEXITCODE
Write-Output "gpupdate exit code: $code"
if ($code -ne 0) { exit $code }
exit 0
''',
    },
    {
        "name": "[MSP] Reset Windows Update Components",
        "description": "Repairs a stuck Windows Update cache by stopping update services and rotating SoftwareDistribution/Catroot2. Does not change OpenPrimeRMM update-management policy and does not reboot.",
        "shell": "powershell",
        "timeout_sec": 1800,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$services = 'bits','wuauserv','cryptsvc'
Write-Output 'Stopping Windows Update services...'
foreach ($s in $services) { Stop-Service $s -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 3

$sd = 'C:\Windows\SoftwareDistribution'
$cr = 'C:\Windows\System32\catroot2'
if (Test-Path $sd) {
    $new = "SoftwareDistribution.pcore-$stamp"
    Rename-Item $sd $new -ErrorAction SilentlyContinue
    Write-Output "Rotated SoftwareDistribution -> $new"
}
if (Test-Path $cr) {
    $new = "catroot2.pcore-$stamp"
    Rename-Item $cr $new -ErrorAction SilentlyContinue
    Write-Output "Rotated catroot2 -> $new"
}

foreach ($s in 'cryptsvc','bits','wuauserv') {
    Start-Service $s -ErrorAction SilentlyContinue
    Write-Output "$s : $((Get-Service $s -ErrorAction SilentlyContinue).Status)"
}
Write-Output 'Windows Update cache reset completed. A subsequent scan will rebuild the cache.'
exit 0
''',
    },
    {
        "name": "[MSP] Reset Winsock & TCP-IP Stack",
        "description": "Resets Winsock and TCP/IP stack. WARNING: may disrupt networking and normally requires a reboot to fully apply; does not reboot automatically.",
        "shell": "powershell",
        "timeout_sec": 300,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'Continue'
Write-Output 'WARNING: Resetting Winsock and TCP/IP. Network connectivity may be interrupted; reboot is recommended.'
& netsh.exe winsock reset
$winsock = $LASTEXITCODE
& netsh.exe int ip reset
$ip = $LASTEXITCODE
Write-Output "Winsock reset exit code: $winsock"
Write-Output "TCP/IP reset exit code: $ip"
Write-Output 'Reboot required/recommended: YES'
if ($winsock -ne 0 -or $ip -ne 0) { exit 1 }
exit 0
''',
    },
    {
        "name": "[MSP] Restart Service by Name",
        "description": "Restarts one Windows service by service name or display name and verifies the resulting state.",
        "shell": "powershell",
        "timeout_sec": 300,
        "variables": [
            _var("Service name", "serviceName", "text", "Example: Spooler, W32Time, or a display name.", "", True),
        ],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'Stop'
$name = $env:serviceName
if (-not $name -or $name -eq 'null') { throw 'serviceName is required.' }
$svc = Get-Service -Name $name -ErrorAction SilentlyContinue
if (-not $svc) { $svc = Get-Service -DisplayName $name -ErrorAction SilentlyContinue }
if (-not $svc) { throw "Service '$name' was not found." }
Write-Output "Service: $($svc.Name) / $($svc.DisplayName)"
Write-Output "Before: $($svc.Status)"
Restart-Service -Name $svc.Name -Force -ErrorAction Stop
$svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(45))
$svc.Refresh()
Write-Output "After: $($svc.Status)"
exit 0
''',
    },
    {
        "name": "[MSP] Flush DNS Cache",
        "description": "Flushes the Windows DNS resolver cache and restarts the DNS Client service only when Windows permits it.",
        "shell": "powershell",
        "timeout_sec": 120,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'Continue'
Clear-DnsClientCache -ErrorAction SilentlyContinue
& ipconfig.exe /flushdns
Write-Output 'DNS resolver cache flush requested.'
try {
    Restart-Service Dnscache -Force -ErrorAction Stop
    Write-Output 'DNS Client service restarted.'
} catch {
    Write-Output "DNS Client service was not restarted (often protected by Windows): $($_.Exception.Message)"
}
exit 0
''',
    },
    {
        "name": "[MSP] Component Store Cleanup",
        "description": "Runs DISM StartComponentCleanup to reduce superseded Windows component-store files. Does not use /ResetBase and preserves update uninstall capability.",
        "shell": "powershell",
        "timeout_sec": 3600,
        "variables": [],
        "content": r'''#requires -version 5.1
$ErrorActionPreference = 'Continue'
Write-Output 'Running safe component-store cleanup (no /ResetBase)...'
& dism.exe /Online /Cleanup-Image /StartComponentCleanup
$code = $LASTEXITCODE
Write-Output "DISM exit code: $code"
if ($code -ne 0) { exit $code }
exit 0
''',
    },
]


def seed_msp_script_pack(conn):
    """Seed the built-in workstation pack once, without overwriting user edits."""
    marker = conn.execute("SELECT value FROM settings WHERE key=?", (PACK_SETTING_KEY,)).fetchone()
    if marker:
        return {"seeded": 0, "skipped": len(MSP_SCRIPTS), "version": marker["value"]}

    now = time.time()
    seeded = 0
    skipped = 0
    for script in MSP_SCRIPTS:
        existing = conn.execute(
            "SELECT id FROM scripts WHERE lower(name)=lower(?) LIMIT 1", (script["name"],)
        ).fetchone()
        if existing:
            skipped += 1
            continue
        safety, auto_allowed, changes_system, reboot_impact = MSP_SCRIPT_SAFETY.get(
            script["name"], ("unclassified", False, True, "possible")
        )
        conn.execute(
            "INSERT INTO scripts (name, description, content, shell, timeout_sec, variables, updated_at, "
            "safety_class, ai_auto_allowed, changes_system, reboot_impact) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                script["name"], script["description"], script["content"], script["shell"],
                int(script["timeout_sec"]), json.dumps(script.get("variables", [])), now,
                safety, 1 if auto_allowed else 0, 1 if changes_system else 0, reboot_impact,
            ),
        )
        seeded += 1

    conn.execute(
        "INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)",
        (PACK_SETTING_KEY, PACK_VERSION),
    )
    return {"seeded": seeded, "skipped": skipped, "version": PACK_VERSION}
