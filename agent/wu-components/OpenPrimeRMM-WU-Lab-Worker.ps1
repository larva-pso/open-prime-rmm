<#
.SYNOPSIS
  OpenPrimeRMM isolated Windows Update lab5 worker.

.DESCRIPTION
  Runs outside the core RMM agent. The launcher enforces a hard timeout and
  terminates this process tree if Windows Update Agent operations stall.

  Lab5 uses one Microsoft Update Agent catalog for discovery, classification,
  deny matching, hide, unhide, verification, and approved installation.

  Modes:
    Scan    - apply/verify local lab policy, enforce denied visibility, inventory
              all update categories, and write cache files for the core agent.
    Install - process one approved-update job through the same Microsoft Update
              catalog and write a deferred job result.
    Restore - restore pre-lab Windows Update policy and unhide only updates that
              this lab worker previously hid.
#>

param(
    [ValidateSet('Scan','Install','Restore')]
    [string]$Mode = 'Scan'
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LabBuild = 'WU-PROD-1'
$LabVersion = '1.13.0'
$MicrosoftUpdateServiceId = '7971f918-a847-4430-9279-4a52d1efe18d'
$DataDir = 'C:\ProgramData\OpenPrime'
$LabDir = Join-Path $DataDir 'wu-lab'
$QueueDir = Join-Path $LabDir 'install-queue'
$ResultDir = Join-Path $LabDir 'install-results'
$DesiredPath = Join-Path $LabDir 'desired.json'
$SettingsPath = Join-Path $LabDir 'lab-settings.json'
$UpdatesCachePath = Join-Path $LabDir 'updates-cache.json'
$InventoryPath = Join-Path $LabDir 'update-inventory.json'
$LegacyInventoryPath = Join-Path $LabDir 'inventory-cache.json'
$ReportPath = Join-Path $LabDir 'worker-report.json'
$BackupPath = Join-Path $LabDir 'policy-backup.json'
$PolicyOwnerPath = Join-Path $LabDir 'policy-owned.flag'
$HiddenStatePath = Join-Path $LabDir 'hidden-by-pcore.json'
$ActiveInstallPath = Join-Path $LabDir 'active-install.json'
$LogPath = Join-Path $LabDir 'worker.log'

foreach ($dir in @($LabDir, $QueueDir, $ResultDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Write-WuLog([string]$Message) {
    $line = "{0}  [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Mode.ToUpperInvariant(), $Message
    try {
        Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
        $item = Get-Item $LogPath -ErrorAction SilentlyContinue
        if ($item -and $item.Length -gt 1048576) {
            Get-Content $LogPath -Tail 1500 | Set-Content $LogPath -Encoding UTF8
        }
    } catch {}
}

function Read-JsonFile([string]$Path, $Default) {
    if (-not (Test-Path $Path)) { return $Default }
    try { return (Get-Content $Path -Raw -ErrorAction Stop | ConvertFrom-Json) }
    catch { Write-WuLog "Invalid JSON at ${Path}: $($_.Exception.Message)"; return $Default }
}

function Write-JsonAtomic([string]$Path, $Value, [int]$Depth = 10) {
    $tmp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $json = $Value | ConvertTo-Json -Depth $Depth
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $Path -Force
}

function Get-Epoch { return [DateTimeOffset]::Now.ToUnixTimeSeconds() }

function ConvertTo-UpdateKey([string]$Value) {
    if (-not $Value) { return '' }
    $clean = ($Value -replace '^KB\s*', 'KB') -replace '\s+', ' '
    return $clean.Trim().ToUpperInvariant()
}

function Get-KbFromUpdate($Update) {
    $kb = ''
    try {
        if ($Update.KBArticleIDs -and $Update.KBArticleIDs.Count -gt 0) {
            $kb = [string]$Update.KBArticleIDs.Item(0)
        }
    } catch {}
    if (-not $kb) {
        try { $kb = [string]$Update.KB } catch {}
    }
    if ($kb -and $kb -notmatch '^KB') { $kb = "KB$kb" }
    return $kb
}

function Get-CategoryNames($Update) {
    $names = @()
    try {
        for ($i = 0; $i -lt $Update.Categories.Count; $i++) {
            $name = [string]$Update.Categories.Item($i).Name
            if ($name) { $names += $name }
        }
    } catch {}
    return @($names | Sort-Object -Unique)
}

function Get-UpdateIdentity($Update) {
    $kb = Get-KbFromUpdate $Update
    $uid = ''
    $revision = 0
    try {
        $uid = [string]$Update.Identity.UpdateID
        $revision = [int]$Update.Identity.RevisionNumber
    } catch {}
    if (-not $uid) { $uid = if ($kb) { $kb } else { [string]$Update.Title } }
    return [pscustomobject]@{
        update_id = $uid
        revision = $revision
        kb = $kb
        title = [string]$Update.Title
    }
}

function Get-UpdateClassification($Update) {
    $title = [string]$Update.Title
    $categories = @(Get-CategoryNames $Update)
    $categoryText = ($categories -join ' | ')
    $typeNumber = 0
    try { $typeNumber = [int]$Update.Type } catch {}
    $browseOnly = $false
    try { $browseOnly = [bool]$Update.BrowseOnly } catch {}

    $isDriver = ($typeNumber -eq 2 -or $categoryText -match '(?i)Drivers?')
    $isFirmware = ($title -match '(?i)firmware|system firmware|bios|uefi' -or $categoryText -match '(?i)firmware')
    $isFeature = ($title -match '(?i)^Feature update to Windows|Upgrade to Windows|Windows 1[01], version \d{2}H\d' -or $categoryText -match '(?i)Upgrades')
    $isPreview = ($title -match '(?i)Preview')
    $isOptional = ($browseOnly -or $isPreview)

    $class = 'standard'
    if ($isFirmware) { $class = 'firmware' }
    elseif ($isDriver) { $class = 'driver' }
    elseif ($isFeature) { $class = 'feature' }
    elseif ($isOptional) { $class = 'optional' }

    return [pscustomobject]@{
        class = $class
        update_type = if ($typeNumber -eq 2) { 'Driver' } else { 'Software' }
        browse_only = $browseOnly
        is_preview = $isPreview
        is_driver = $isDriver
        is_firmware = $isFirmware
        is_feature = $isFeature
        categories = $categories
    }
}

function ConvertTo-DetailedUpdate($Update, [bool]$Hidden, [bool]$ManagedHidden) {
    $id = Get-UpdateIdentity $Update
    $class = Get-UpdateClassification $Update
    $sizeBytes = 0
    try { $sizeBytes = [double]$Update.MaxDownloadSize } catch {}
    if (-not $sizeBytes) { try { $sizeBytes = [double]$Update.MinDownloadSize } catch {} }
    $downloaded = $false
    $mandatory = $false
    $autoSelected = $false
    $severity = ''
    try { $downloaded = [bool]$Update.IsDownloaded } catch {}
    try { $mandatory = [bool]$Update.IsMandatory } catch {}
    try { $autoSelected = [bool]$Update.AutoSelectOnWebSites } catch {}
    try { $severity = [string]$Update.MsrcSeverity } catch {}

    return [pscustomobject]@{
        update_id = [string]$id.update_id
        revision = [int]$id.revision
        kb = [string]$id.kb
        title = [string]$id.title
        severity = $severity
        size_mb = [math]::Round($sizeBytes / 1048576, 1)
        class = [string]$class.class
        update_type = [string]$class.update_type
        browse_only = [bool]$class.browse_only
        is_preview = [bool]$class.is_preview
        categories = @($class.categories)
        is_hidden = [bool]$Hidden
        hidden_by_primenetcore = [bool]$ManagedHidden
        is_mandatory = $mandatory
        is_downloaded = $downloaded
        auto_selected = $autoSelected
    }
}

function ConvertTo-ServerUpdate($Detailed) {
    return @{
        update_id = [string]$Detailed.update_id
        kb = [string]$Detailed.kb
        title = [string]$Detailed.title
        severity = [string]$Detailed.severity
        size_mb = [double]$Detailed.size_mb
        category = [string]$Detailed.class
        browse_only = [bool]$Detailed.browse_only
        revision = [int]$Detailed.revision
    }
}

function Test-RuleEquivalent($Left, $Right) {
    $lid = ConvertTo-UpdateKey ([string]$Left.update_id)
    $lkb = ConvertTo-UpdateKey ([string]$Left.kb)
    $ltitle = ConvertTo-UpdateKey ([string]$Left.title)
    $rid = ConvertTo-UpdateKey ([string]$Right.update_id)
    $rkb = ConvertTo-UpdateKey ([string]$Right.kb)
    $rtitle = ConvertTo-UpdateKey ([string]$Right.title)
    return (($lid -and ($lid -eq $rid -or $lid -eq $rkb)) -or
            ($lkb -and ($lkb -eq $rid -or $lkb -eq $rkb)) -or
            ($ltitle -and $rtitle -and $ltitle -eq $rtitle))
}

function Test-RuleMatch($Update, $Rule) {
    $identity = Get-UpdateIdentity $Update
    return (Test-RuleEquivalent $identity $Rule)
}

function Test-WantedMatch($Update, $WantedIds) {
    $id = Get-UpdateIdentity $Update
    $keys = @(
        (ConvertTo-UpdateKey ([string]$id.update_id)),
        (ConvertTo-UpdateKey ([string]$id.kb)),
        (ConvertTo-UpdateKey ([string]$id.title))
    )
    foreach ($wanted in @($WantedIds)) {
        if ($keys -contains (ConvertTo-UpdateKey ([string]$wanted))) { return $true }
    }
    return $false
}

function Get-RegistryState([string]$Path, [string]$Name) {
    $exists = $false
    $value = $null
    $kind = 'DWord'
    try {
        if (Test-Path $Path) {
            $item = Get-Item -Path $Path -ErrorAction Stop
            if (@($item.GetValueNames()) -contains $Name) {
                $exists = $true
                $value = $item.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
                try { $kind = [string]$item.GetValueKind($Name) } catch {}
            }
        }
    } catch {}
    return @{ path=$Path; name=$Name; exists=$exists; value=$value; kind=$kind }
}

function Set-RegistryDword([string]$Path, [string]$Name, [int]$Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Get-PolicyTargets {
    return @(
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate','SetDisableUXWUAccess'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate','SetDisablePauseUXAccess'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','NoAutoUpdate'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','AUOptions')
    )
}

function Backup-PolicyOnce {
    if (Test-Path $BackupPath) { return }
    $saved = @()
    foreach ($target in Get-PolicyTargets) { $saved += Get-RegistryState $target[0] $target[1] }
    Write-JsonAtomic $BackupPath $saved 6
    Write-WuLog 'Saved original Windows Update policy values.'
}

function Restore-Policy {
    if (-not (Test-Path $PolicyOwnerPath) -and -not (Test-Path $BackupPath)) { return $true }
    if (-not (Test-Path $BackupPath)) {
        Write-WuLog 'Policy ownership marker exists without a backup; removing only the four lab-owned values.'
        foreach ($target in Get-PolicyTargets) {
            if (Test-Path $target[0]) {
                Remove-ItemProperty -Path $target[0] -Name $target[1] -Force -ErrorAction SilentlyContinue
            }
        }
        Remove-Item $PolicyOwnerPath -Force -ErrorAction SilentlyContinue
        return $true
    }
    try {
        $saved = @(Read-JsonFile $BackupPath @())
        foreach ($entry in $saved) {
            if ($entry.exists) {
                if (-not (Test-Path $entry.path)) { New-Item -Path $entry.path -Force | Out-Null }
                $kind = [Microsoft.Win32.RegistryValueKind]::DWord
                try { $kind = [Microsoft.Win32.RegistryValueKind]([Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$entry.kind)) } catch {}
                (Get-Item $entry.path).SetValue([string]$entry.name, $entry.value, $kind)
            } elseif (Test-Path $entry.path) {
                Remove-ItemProperty -Path $entry.path -Name $entry.name -Force -ErrorAction SilentlyContinue
            }
        }
        Remove-Item $BackupPath -Force -ErrorAction SilentlyContinue
        Remove-Item $PolicyOwnerPath -Force -ErrorAction SilentlyContinue
        Write-WuLog 'Restored original Windows Update policy values.'
        return $true
    } catch {
        Write-WuLog "Policy restore failed: $($_.Exception.Message)"
        return $false
    }
}

function Resolve-DesiredState {
    $server = Read-JsonFile $DesiredPath ([pscustomobject]@{})
    $local = Read-JsonFile $SettingsPath ([pscustomobject]@{})
    $mode = ([string]$local.mode).ToLowerInvariant()
    return [pscustomobject]@{
        managed = ($mode -eq 'managed')
        block_user_update_access = if ($null -ne $local.block_user_update_access) { [bool]$local.block_user_update_access } else { $true }
        block_pause_updates = if ($null -ne $local.block_pause_updates) { [bool]$local.block_pause_updates } else { $true }
        hide_denied_updates = if ($null -ne $local.hide_denied_updates) { [bool]$local.hide_denied_updates } else { $true }
        include_optional_updates = if ($null -ne $local.include_optional_updates) { [bool]$local.include_optional_updates } else { $true }
        include_driver_updates = if ($null -ne $local.include_driver_updates) { [bool]$local.include_driver_updates } else { $true }
        include_firmware_updates = if ($null -ne $local.include_firmware_updates) { [bool]$local.include_firmware_updates } else { $true }
        include_feature_updates = if ($null -ne $local.include_feature_updates) { [bool]$local.include_feature_updates } else { $true }
        server_include_preview = [bool]$server.include_preview
        denied_updates = @($server.denied_updates)
        server_managed_requested = [bool]$server.server_managed_requested
        received_at = [int64]$server.received_at
    }
}

function Apply-And-VerifyPolicy($Desired) {
    $errors = New-Object System.Collections.Generic.List[string]
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $au = Join-Path $wu 'AU'
    try {
        if ($Desired.managed) {
            Backup-PolicyOnce
            New-Item -ItemType File -Path $PolicyOwnerPath -Force | Out-Null
            Set-RegistryDword $wu 'SetDisableUXWUAccess' ($(if ($Desired.block_user_update_access) { 1 } else { 0 }))
            Set-RegistryDword $wu 'SetDisablePauseUXAccess' ($(if ($Desired.block_pause_updates) { 1 } else { 0 }))
            Set-RegistryDword $au 'NoAutoUpdate' 0
            Set-RegistryDword $au 'AUOptions' 2
        } else {
            [void](Restore-Policy)
        }
    } catch { $errors.Add("Policy application failed: $($_.Exception.Message)") }

    $ux = Get-RegistryState $wu 'SetDisableUXWUAccess'
    $pause = Get-RegistryState $wu 'SetDisablePauseUXAccess'
    $noAuto = Get-RegistryState $au 'NoAutoUpdate'
    $auOptions = Get-RegistryState $au 'AUOptions'
    $compliant = if ($Desired.managed) {
        ((!$Desired.block_user_update_access -or ($ux.exists -and [int]$ux.value -eq 1)) -and
         (!$Desired.block_pause_updates -or ($pause.exists -and [int]$pause.value -eq 1)) -and
         ($noAuto.exists -and [int]$noAuto.value -eq 0) -and
         ($auOptions.exists -and [int]$auOptions.value -eq 2) -and
         $errors.Count -eq 0)
    } else { $errors.Count -eq 0 }

    return [pscustomobject]@{
        compliant = [bool]$compliant
        errors = @($errors)
        user_access_blocked = [bool]($ux.exists -and [int]$ux.value -eq 1)
        pause_blocked = [bool]($pause.exists -and [int]$pause.value -eq 1)
        no_auto_update = if ($noAuto.exists) { [string]$noAuto.value } else { 'not configured' }
        au_options = if ($auOptions.exists) { [string]$auOptions.value } else { 'not configured' }
    }
}

function Ensure-MicrosoftUpdateService {
    $manager = New-Object -ComObject 'Microsoft.Update.ServiceManager'
    $found = $false
    try {
        for ($i = 0; $i -lt $manager.Services.Count; $i++) {
            $service = $manager.Services.Item($i)
            if ([string]$service.ServiceID -eq $MicrosoftUpdateServiceId) { $found = $true; break }
        }
    } catch {}
    if (-not $found) {
        Write-WuLog 'Microsoft Update service was not registered; registering it for the isolated worker.'
        [void]$manager.AddService2($MicrosoftUpdateServiceId, 7, '')
    }
    return $true
}

function New-MicrosoftUpdateSession {
    [void](Ensure-MicrosoftUpdateService)
    $session = New-Object -ComObject 'Microsoft.Update.Session'
    try { $session.ClientApplicationID = "OpenPrimeRMM $LabVersion" } catch {}
    return $session
}

function Search-MicrosoftUpdates([bool]$Hidden) {
    $session = New-MicrosoftUpdateSession
    $searcher = $session.CreateUpdateSearcher()
    $searcher.ServerSelection = 3
    $searcher.ServiceID = $MicrosoftUpdateServiceId
    $searcher.IncludePotentiallySupersededUpdates = $false
    $criteria = "IsInstalled=0 and IsHidden=" + ($(if ($Hidden) { '1' } else { '0' }))
    $result = $searcher.Search($criteria)
    $updates = @()
    for ($i = 0; $i -lt $result.Updates.Count; $i++) { $updates += $result.Updates.Item($i) }
    return [pscustomobject]@{
        session = $session
        updates = @($updates)
        result_code = [int]$result.ResultCode
        criteria = $criteria
        service_id = $MicrosoftUpdateServiceId
    }
}

function Load-HiddenByUs {
    $state = Read-JsonFile $HiddenStatePath $null
    if ($state -and $state.rules) { return @($state.rules) }
    return @()
}

function Save-HiddenByUs($Rules) {
    Write-JsonAtomic $HiddenStatePath @{
        lab_build = $LabBuild
        rules = @($Rules)
        hidden_count = @($Rules).Count
        updated_at = Get-Epoch
    } 10
}

function Find-Matches($Updates, $Rule) {
    $matches = @()
    foreach ($update in @($Updates)) {
        if (Test-RuleMatch $update $Rule) { $matches += $update }
    }
    return @($matches)
}


function Set-UpdateHiddenProperty($Update, [bool]$Value) {
    # Lab7: if plumbing ever hands this anything other than a single update COM
    # object, fail fast with the real type instead of a misleading COM error.
    if ($null -eq $Update) {
        return [pscustomobject]@{ ok = $false; method = 'failed'; error = 'Internal error: setter received $null instead of a single update COM object.' }
    }
    if ($Update -is [System.Array]) {
        return [pscustomobject]@{ ok = $false; method = 'failed'; error = "Internal error: setter received an array of $(@($Update).Count) element(s) instead of a single update COM object." }
    }
    $updateTypeName = 'unknown'
    try { $updateTypeName = [string]$Update.GetType().FullName } catch {}
    $directError = $null
    try {
        # Normal Windows PowerShell COM late binding.
        $Update.IsHidden = $Value
        return [pscustomobject]@{
            ok = $true
            method = 'direct'
            error = ''
        }
    } catch {
        $directError = $_.Exception.Message
    }

    try {
        # Some Windows builds return a COM wrapper whose setter is not surfaced
        # through the PowerShell adapter. Invoke the COM property through IDispatch.
        $flags = [System.Reflection.BindingFlags]::SetProperty
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        [void]$Update.GetType().InvokeMember(
            'IsHidden',
            $flags,
            $null,
            $Update,
            @([object]$Value),
            $culture
        )
        return [pscustomobject]@{
            ok = $true
            method = 'idispatch'
            error = ''
        }
    } catch {
        $fallbackError = $_.Exception.Message
        return [pscustomobject]@{
            ok = $false
            method = 'failed'
            error = "Object type: $updateTypeName | Direct setter: $directError | IDispatch setter: $fallbackError"
        }
    }
}

function Get-VisibilitySnapshot {
    $visibleSearch = Search-MicrosoftUpdates $false
    $hiddenSearch = Search-MicrosoftUpdates $true
    return [pscustomobject]@{
        visible_search = $visibleSearch
        hidden_search = $hiddenSearch
        visible_updates = @($visibleSearch.updates)
        hidden_updates = @($hiddenSearch.updates)
    }
}

function Write-InventorySnapshot($Inventory, $Visibility, $Desired, $Errors, $Warnings, [string]$Phase) {
    $payload = @{
        lab_build = $LabBuild
        lab_version = $LabVersion
        phase = $Phase
        service = 'Microsoft Update'
        service_id = $MicrosoftUpdateServiceId
        scanned_at = Get-Epoch
        local_policy = @{
            include_optional_updates = [bool]$Desired.include_optional_updates
            include_driver_updates = [bool]$Desired.include_driver_updates
            include_firmware_updates = [bool]$Desired.include_firmware_updates
            include_feature_updates = [bool]$Desired.include_feature_updates
            server_include_preview = [bool]$Desired.server_include_preview
        }
        counts = @{
            visible = [int]$Inventory.visible_count
            reported = [int]$Inventory.reported_count
            excluded = [int]$Inventory.excluded_count
            standard = [int]$Inventory.standard_count
            optional = [int]$Inventory.optional_count
            driver = [int]$Inventory.driver_count
            firmware = [int]$Inventory.firmware_count
            feature = [int]$Inventory.feature_count
            hidden_by_primenetcore = [int]$Visibility.hidden_count
        }
        visible_updates = @($Inventory.visible_inventory)
        hidden_by_primenetcore = @($Inventory.hidden_inventory)
        excluded_by_policy = @($Inventory.excluded_inventory)
        errors = @($Errors)
        warnings = @($Warnings)
    }

    # Canonical documented name.
    Write-JsonAtomic $InventoryPath $payload 12
    # Compatibility alias for lab5 scripts and prior documentation.
    Write-JsonAtomic $LegacyInventoryPath $payload 12
}

function Set-DeniedVisibility($DesiredRules, [bool]$EnforceHide) {
    $desired = if ($EnforceHide) { @($DesiredRules) } else { @() }
    $tracked = @(Load-HiddenByUs)
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $denyMatches = 0
    $denyNotFound = 0
    $hideAttempted = 0
    $hideSucceeded = 0
    $hideVerified = 0
    $hideDirect = 0
    $hideFallback = 0
    $hideSetterFailed = 0
    $unhideAttempted = 0
    $unhideSucceeded = 0
    $unhideVerified = 0
    $unhideDirect = 0
    $unhideFallback = 0
    $unhideSetterFailed = 0

    $visibleSearch = Search-MicrosoftUpdates $false
    $hiddenSearch = Search-MicrosoftUpdates $true
    $visible = @($visibleSearch.updates)
    $hidden = @($hiddenSearch.updates)

    foreach ($rule in $desired) {
        $visibleMatches = @(Find-Matches $visible $rule)
        $hiddenMatches = @(Find-Matches $hidden $rule)
        if ($visibleMatches.Count -eq 0 -and $hiddenMatches.Count -eq 0) {
            $denyNotFound++
            Write-WuLog "Denied rule not found in current catalog (installed, superseded, or not applicable): $([string]$rule.title)"
            continue
        }
        $denyMatches++
        if ($hiddenMatches.Count -gt 0) { continue }
        foreach ($update in $visibleMatches) {
            try {
                $hideAttempted++
                if ([bool]$update.IsMandatory) { throw 'Windows marks this update mandatory; it cannot be hidden.' }
                $setResult = Set-UpdateHiddenProperty $update $true
                if (-not $setResult.ok) {
                    $hideSetterFailed++
                    throw $setResult.error
                }
                if ($setResult.method -eq 'direct') { $hideDirect++ } else { $hideFallback++ }
                $hideSucceeded++
                $identity = Get-UpdateIdentity $update
                if (-not @($tracked | Where-Object { Test-RuleEquivalent $_ $identity }).Count) {
                    $tracked += $identity
                }
            } catch {
                $errors.Add("Hide failed: $([string]$update.Title) - $($_.Exception.Message)")
            }
        }
    }

    $removed = @($tracked | Where-Object {
        $record = $_
        -not @($desired | Where-Object { Test-RuleEquivalent $_ $record }).Count
    })
    foreach ($record in $removed) {
        $matches = @(Find-Matches $hidden $record)
        if (-not $matches.Count) {
            $warnings.Add("Previously hidden update is no longer in the hidden catalog; it may be installed or superseded: $([string]$record.title)")
            $tracked = @($tracked | Where-Object { -not (Test-RuleEquivalent $_ $record) })
            continue
        }
        foreach ($update in $matches) {
            try {
                $unhideAttempted++
                $setResult = Set-UpdateHiddenProperty $update $false
                if (-not $setResult.ok) {
                    $unhideSetterFailed++
                    throw $setResult.error
                }
                if ($setResult.method -eq 'direct') { $unhideDirect++ } else { $unhideFallback++ }
                $unhideSucceeded++
            } catch {
                $errors.Add("Unhide failed: $([string]$update.Title) - $($_.Exception.Message)")
            }
        }
    }

    if ($hideAttempted -gt 0 -or $unhideAttempted -gt 0) {
        $visibleSearch = Search-MicrosoftUpdates $false
        $hiddenSearch = Search-MicrosoftUpdates $true
        $visible = @($visibleSearch.updates)
        $hidden = @($hiddenSearch.updates)
    }

    foreach ($rule in $desired) {
        if (@(Find-Matches $hidden $rule).Count -gt 0) {
            $hideVerified++
        } elseif (@(Find-Matches $visible $rule).Count -gt 0) {
            $errors.Add("Denied update remains visible after hide enforcement: $([string]$rule.title)")
        }
    }

    foreach ($record in $removed) {
        if (@(Find-Matches $visible $record).Count -gt 0) {
            $unhideVerified++
            $tracked = @($tracked | Where-Object { -not (Test-RuleEquivalent $_ $record) })
        } elseif (@(Find-Matches $hidden $record).Count -gt 0) {
            $errors.Add("Restored update remains hidden after unhide enforcement: $([string]$record.title)")
        } else {
            $tracked = @($tracked | Where-Object { -not (Test-RuleEquivalent $_ $record) })
        }
    }

    # Keep only records that are still desired and verified hidden.
    $verifiedTracked = @()
    foreach ($record in $tracked) {
        $stillDesired = @($desired | Where-Object { Test-RuleEquivalent $_ $record }).Count -gt 0
        $stillHidden = @(Find-Matches $hidden $record).Count -gt 0
        if ($stillDesired -and $stillHidden) { $verifiedTracked += $record }
    }
    Save-HiddenByUs $verifiedTracked

    $managedHiddenCount = 0
    foreach ($update in $hidden) {
        if (@($verifiedTracked | Where-Object { Test-RuleMatch $update $_ }).Count -gt 0) { $managedHiddenCount++ }
    }

    return [pscustomobject]@{
        visible_updates = @($visible)
        hidden_updates = @($hidden)
        deny_rules_received = @($desired).Count
        deny_matches_found = $denyMatches
        deny_not_found = $denyNotFound
        hide_attempted = $hideAttempted
        hide_succeeded = $hideSucceeded
        hide_verified = $hideVerified
        hide_direct = $hideDirect
        hide_fallback = $hideFallback
        hide_setter_failed = $hideSetterFailed
        unhide_attempted = $unhideAttempted
        unhide_succeeded = $unhideSucceeded
        unhide_verified = $unhideVerified
        unhide_direct = $unhideDirect
        unhide_fallback = $unhideFallback
        unhide_setter_failed = $unhideSetterFailed
        hidden_count = $managedHiddenCount
        tracked_rules = @($verifiedTracked)
        errors = @($errors)
        warnings = @($warnings)
        service_id = [string]$visibleSearch.service_id
    }
}

function Test-UpdateAllowed($Detailed, $Desired) {
    switch ([string]$Detailed.class) {
        'optional' { return [bool]$Desired.include_optional_updates }
        'driver' { return [bool]$Desired.include_driver_updates }
        'firmware' { return [bool]$Desired.include_firmware_updates }
        'feature' { return [bool]$Desired.include_feature_updates }
        default { return $true }
    }
}

function Build-Inventory($VisibleUpdates, $HiddenUpdates, $TrackedRules, $Desired) {
    $visibleDetailed = @()
    $hiddenDetailed = @()
    $reported = @()
    $excluded = @()
    $counts = @{ standard=0; optional=0; driver=0; firmware=0; feature=0 }
    $seen = @{}

    foreach ($update in @($VisibleUpdates)) {
        $detail = ConvertTo-DetailedUpdate $update $false $false
        $key = (ConvertTo-UpdateKey ([string]$detail.update_id)) + '|' + [string]$detail.revision
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $visibleDetailed += $detail
        if ($counts.ContainsKey([string]$detail.class)) { $counts[[string]$detail.class]++ }
        if (Test-UpdateAllowed $detail $Desired) {
            $reported += ConvertTo-ServerUpdate $detail
        } else {
            $excluded += $detail
        }
    }

    foreach ($update in @($HiddenUpdates)) {
        $managed = @($TrackedRules | Where-Object { Test-RuleMatch $update $_ }).Count -gt 0
        if (-not $managed) { continue }
        $hiddenDetailed += ConvertTo-DetailedUpdate $update $true $true
    }

    return [pscustomobject]@{
        reported_updates = @($reported)
        visible_inventory = @($visibleDetailed)
        hidden_inventory = @($hiddenDetailed)
        excluded_inventory = @($excluded)
        standard_count = [int]$counts.standard
        optional_count = [int]$counts.optional
        driver_count = [int]$counts.driver
        firmware_count = [int]$counts.firmware
        feature_count = [int]$counts.feature
        visible_count = @($visibleDetailed).Count
        reported_count = @($reported).Count
        excluded_count = @($excluded).Count
    }
}

function Test-RebootRequired {
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    )) { if (Test-Path $key) { return $true } }
    try { return [bool](New-Object -ComObject 'Microsoft.Update.SystemInfo').RebootRequired }
    catch { return $false }
}

function Run-Scan {
    $started = Get-Epoch
    $desired = Resolve-DesiredState
    $policy = Apply-And-VerifyPolicy $desired

    # Always create an inventory before hide/unhide enforcement. A Windows COM
    # setter compatibility problem must never suppress update discovery.
    $preErrors = @($policy.errors)
    $preWarnings = @()
    $trackedBefore = @(Load-HiddenByUs)

    try {
        $snapshot = Get-VisibilitySnapshot
        $preInventory = Build-Inventory $snapshot.visible_updates $snapshot.hidden_updates $trackedBefore $desired
        $preVisibility = [pscustomobject]@{
            hidden_count = @($preInventory.hidden_inventory).Count
        }
        Write-InventorySnapshot $preInventory $preVisibility $desired $preErrors $preWarnings 'pre-enforcement'
    } catch {
        $preErrors += "Initial inventory failed: $($_.Exception.Message)"
        Write-WuLog "Initial inventory failed: $($_.Exception.Message)"
    }

    try {
        $visibility = Set-DeniedVisibility $desired.denied_updates ([bool]($desired.managed -and $desired.hide_denied_updates))
    } catch {
        # Preserve inventory and report a degraded enforcement state instead of
        # failing the whole scan.
        $enforcementError = "Visibility enforcement failed: $($_.Exception.Message)"
        Write-WuLog $enforcementError
        $fallbackSnapshot = Get-VisibilitySnapshot
        $visibility = [pscustomobject]@{
            visible_updates = @($fallbackSnapshot.visible_updates)
            hidden_updates = @($fallbackSnapshot.hidden_updates)
            deny_rules_received = @($desired.denied_updates).Count
            deny_matches_found = 0
            deny_not_found = 0
            hide_attempted = 0
            hide_succeeded = 0
            hide_verified = 0
            hide_direct = 0
            hide_fallback = 0
            hide_setter_failed = 1
            unhide_attempted = 0
            unhide_succeeded = 0
            unhide_verified = 0
            unhide_direct = 0
            unhide_fallback = 0
            unhide_setter_failed = 0
            hidden_count = 0
            tracked_rules = @(Load-HiddenByUs)
            errors = @($enforcementError)
            warnings = @()
            service_id = $MicrosoftUpdateServiceId
        }
    }

    $inventory = Build-Inventory $visibility.visible_updates $visibility.hidden_updates $visibility.tracked_rules $desired

    $errors = @($policy.errors) + @($visibility.errors)
    $warnings = @($visibility.warnings)
    $status = if ($errors.Count) { 'degraded' } elseif ($warnings.Count) { 'warning' } else { 'ok' }

    Write-JsonAtomic $UpdatesCachePath @{
        lab_build = $LabBuild
        status = $status
        scanned_at = Get-Epoch
        updates = @($inventory.reported_updates)
        errors = @($errors)
        warnings = @($warnings)
        standard_count = [int]$inventory.standard_count
        optional_count = [int]$inventory.optional_count
        driver_count = [int]$inventory.driver_count
        firmware_count = [int]$inventory.firmware_count
        feature_count = [int]$inventory.feature_count
        excluded_count = [int]$inventory.excluded_count
    } 10

    Write-InventorySnapshot $inventory $visibility $desired $errors $warnings 'post-enforcement'

    $report = @{
        lab_build = $LabBuild
        lab_version = $LabVersion
        worker_status = $status
        mode = if ($desired.managed) { 'managed' } else { 'observe' }
        compliant = [bool]($policy.compliant -and $visibility.errors.Count -eq 0)
        checked_at = Get-Epoch
        started_at = $started
        catalog = 'Microsoft Update'
        catalog_service_id = $MicrosoftUpdateServiceId
        inventory_file = $InventoryPath
        user_access_blocked = [bool]$policy.user_access_blocked
        pause_blocked = [bool]$policy.pause_blocked
        no_auto_update = [string]$policy.no_auto_update
        au_options = [string]$policy.au_options
        visible_count = [int]$inventory.visible_count
        pending_count = [int]$inventory.reported_count
        excluded_count = [int]$inventory.excluded_count
        scan_standard_count = [int]$inventory.standard_count
        scan_optional_count = [int]$inventory.optional_count
        scan_driver_count = [int]$inventory.driver_count
        scan_firmware_count = [int]$inventory.firmware_count
        scan_feature_count = [int]$inventory.feature_count
        deny_rules_received = [int]$visibility.deny_rules_received
        deny_matches_found = [int]$visibility.deny_matches_found
        deny_not_found = [int]$visibility.deny_not_found
        hide_attempted = [int]$visibility.hide_attempted
        hide_succeeded = [int]$visibility.hide_succeeded
        hide_verified = [int]$visibility.hide_verified
        hide_direct = [int]$visibility.hide_direct
        hide_fallback = [int]$visibility.hide_fallback
        hide_setter_failed = [int]$visibility.hide_setter_failed
        hidden_count = [int]$visibility.hidden_count
        unhide_attempted = [int]$visibility.unhide_attempted
        unhide_succeeded = [int]$visibility.unhide_succeeded
        unhide_verified = [int]$visibility.unhide_verified
        unhide_direct = [int]$visibility.unhide_direct
        unhide_fallback = [int]$visibility.unhide_fallback
        unhide_setter_failed = [int]$visibility.unhide_setter_failed
        server_include_preview = [bool]$desired.server_include_preview
        server_managed_requested = [bool]$desired.server_managed_requested
        errors = @($errors)
        warnings = @($warnings)
    }
    Write-JsonAtomic $ReportPath $report 12
    Write-WuLog "Scan completed: status=$status, mode=$($report.mode), visible=$($report.visible_count), reported=$($report.pending_count), optional=$($report.scan_optional_count), drivers=$($report.scan_driver_count), hidden=$($report.hidden_count), hide_fallback=$($report.hide_fallback), errors=$($errors.Count), warnings=$($warnings.Count)."
}

function Get-NextInstallRequest {
    $items = @(Get-ChildItem $QueueDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
    if (-not $items.Count) { return $null }
    return $items[0]
}

function Write-InstallResult([string]$JobId, $Result) {
    Write-JsonAtomic (Join-Path $ResultDir "$JobId.json") @{
        job_id = $JobId
        completed_at = Get-Epoch
        result = $Result
    } 10
}

function Get-WuaResultName([int]$Code) {
    switch ($Code) {
        0 { return 'NotStarted' }
        1 { return 'InProgress' }
        2 { return 'Succeeded' }
        3 { return 'SucceededWithErrors' }
        4 { return 'Failed' }
        5 { return 'Aborted' }
        default { return "Unknown($Code)" }
    }
}

function Install-OneUpdate($Session, $Update) {
    $lines = New-Object System.Collections.Generic.List[string]
    try {
        if (-not [bool]$Update.EulaAccepted) { $Update.AcceptEula() }
        $collection = New-Object -ComObject 'Microsoft.Update.UpdateColl'
        [void]$collection.Add($Update)

        if (-not [bool]$Update.IsDownloaded) {
            $downloader = $Session.CreateUpdateDownloader()
            $downloader.Updates = $collection
            $downloadResult = $downloader.Download()
            $downloadCode = [int]$downloadResult.ResultCode
            $lines.Add("Download: $(Get-WuaResultName $downloadCode)")
            if ($downloadCode -notin @(2,3)) {
                return [pscustomobject]@{ ok=$false; lines=@($lines); result_code=$downloadCode }
            }
        } else {
            $lines.Add('Download: already downloaded')
        }

        $installer = $Session.CreateUpdateInstaller()
        $installer.Updates = $collection
        try { $installer.ForceQuiet = $true } catch {}
        try { $installer.AllowSourcePrompts = $false } catch {}
        $installResult = $installer.Install()
        $row = $installResult.GetUpdateResult(0)
        $code = [int]$row.ResultCode
        $lines.Add("Install: $(Get-WuaResultName $code); HRESULT=$([int]$row.HResult)")
        return [pscustomobject]@{ ok=($code -eq 2); lines=@($lines); result_code=$code }
    } catch {
        $lines.Add("Exception: $($_.Exception.Message)")
        return [pscustomobject]@{ ok=$false; lines=@($lines); result_code=-1 }
    }
}

function Run-Install {
    $item = Get-NextInstallRequest
    if (-not $item) { Write-WuLog 'No queued install job.'; return }
    $request = Read-JsonFile $item.FullName $null
    if (-not $request -or -not $request.job_id) {
        Remove-Item $item.FullName -Force -ErrorAction SilentlyContinue
        return
    }

    $jobId = [string]$request.job_id
    $wanted = @($request.payload.update_ids)
    Write-JsonAtomic $ActiveInstallPath @{ job_id=$jobId; queue_path=$item.FullName; started_at=(Get-Epoch) } 5
    $lines = New-Object System.Collections.Generic.List[string]
    $failed = @()

    try {
        $desired = Resolve-DesiredState
        $search = Search-MicrosoftUpdates $false
        $matches = @()
        $seen = @{}
        foreach ($update in @($search.updates)) {
            if (-not (Test-WantedMatch $update $wanted)) { continue }
            if (@($desired.denied_updates | Where-Object { Test-RuleMatch $update $_ }).Count) {
                $lines.Add("[SKIP-DENIED] $([string]$update.Title)")
                continue
            }
            $id = Get-UpdateIdentity $update
            $key = ConvertTo-UpdateKey ([string]$id.update_id)
            if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $matches += $update }
        }

        if (-not $matches.Count) {
            Write-InstallResult $jobId @{
                ok = $true
                exit_code = 0
                output = 'No approved matching updates remain visible; they may be installed, superseded, denied, or no longer applicable.'
                failed_update_ids = @()
                reboot_required = Test-RebootRequired
            }
            return
        }

        $lines.Add("Installing $($matches.Count) update(s) through the isolated Microsoft Update worker...")
        foreach ($update in $matches) {
            $desired = Resolve-DesiredState
            $id = Get-UpdateIdentity $update
            if (@($desired.denied_updates | Where-Object { Test-RuleMatch $update $_ }).Count) {
                $lines.Add("[SKIP-DENIED] $([string]$update.Title)")
                continue
            }
            $result = Install-OneUpdate $search.session $update
            foreach ($line in @($result.lines)) { $lines.Add("[$([string]$id.kb)] $line") }
            if ($result.ok) { $lines.Add("[OK] $([string]$update.Title)") }
            else { $lines.Add("[FAIL] $([string]$update.Title)"); $failed += [string]$id.update_id }
        }

        $reboot = Test-RebootRequired
        if ($reboot) { $lines.Add('A reboot is required to finish installation.') }
        Write-InstallResult $jobId @{
            ok = ($failed.Count -eq 0)
            exit_code = $failed.Count
            output = ($lines -join "`n")
            failed_update_ids = @($failed)
            reboot_required = $reboot
        }
    } catch {
        $lines.Add("Worker error: $($_.Exception.Message)")
        Write-InstallResult $jobId @{
            ok = $false
            exit_code = -1
            output = ($lines -join "`n")
            failed_update_ids = @($wanted)
            reboot_required = Test-RebootRequired
        }
    } finally {
        Remove-Item $item.FullName -Force -ErrorAction SilentlyContinue
        Remove-Item $ActiveInstallPath -Force -ErrorAction SilentlyContinue
        New-Item -ItemType File -Path (Join-Path $LabDir 'force-scan.flag') -Force | Out-Null
    }
}

function Run-Restore {
    [void](Restore-Policy)
    $visibility = Set-DeniedVisibility @() $false
    $errors = @($visibility.errors)
    $warnings = @($visibility.warnings)
    $status = if ($errors.Count) { 'degraded' } elseif ($warnings.Count) { 'warning' } else { 'restored' }
    Write-JsonAtomic $ReportPath @{
        lab_build = $LabBuild
        lab_version = $LabVersion
        worker_status = $status
        mode = 'observe'
        compliant = ($errors.Count -eq 0)
        checked_at = Get-Epoch
        catalog = 'Microsoft Update'
        user_access_blocked = $false
        pause_blocked = $false
        no_auto_update = 'restored'
        au_options = 'restored'
        hidden_count = [int]$visibility.hidden_count
        unhide_attempted = [int]$visibility.unhide_attempted
        unhide_succeeded = [int]$visibility.unhide_succeeded
        unhide_verified = [int]$visibility.unhide_verified
        errors = @($errors)
        warnings = @($warnings)
    } 10
    Write-WuLog "Restore completed; unhide_verified=$($visibility.unhide_verified), errors=$($errors.Count), warnings=$($warnings.Count)."
}

$mutex = New-Object System.Threading.Mutex($false, 'Global\OpenPrimeRMMWuLabWorker')
$hasMutex = $false
try {
    $waitMs = if ($Mode -eq 'Install') { 60000 } elseif ($Mode -eq 'Restore') { 15000 } else { 0 }
    $hasMutex = $mutex.WaitOne($waitMs)
    if (-not $hasMutex) {
        Write-WuLog 'Another Windows Update worker is active; this run will retry later.'
        exit 75
    }
    Write-WuLog 'Worker started.'
    switch ($Mode) {
        'Scan' { Run-Scan }
        'Install' { Run-Install }
        'Restore' { Run-Restore }
    }
    Write-WuLog 'Worker exited normally.'
    exit 0
} catch {
    Write-WuLog "Fatal worker error: $($_.Exception.Message)"
    if ($Mode -eq 'Scan') {
        Write-JsonAtomic $ReportPath @{
            lab_build = $LabBuild
            lab_version = $LabVersion
            worker_status = 'failed'
            mode = 'unknown'
            compliant = $false
            checked_at = Get-Epoch
            errors = @($_.Exception.Message)
            warnings = @()
        } 8
    }
    exit 1
} finally {
    if ($hasMutex) { try { $mutex.ReleaseMutex() } catch {} }
    $mutex.Dispose()
}
