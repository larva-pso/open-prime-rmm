# OpenPrime tray - end-user systray icon with a support request form.
# Runs in the USER session (started by a logon task the agent creates).
# Reads only C:\ProgramData\OpenPrime\tray.json (base_url, agent_id, brand) -
# it never sees the agent's API token.
$TrayVersion = '1.3.1'

$ErrorActionPreference = 'SilentlyContinue'

# Belt-and-suspenders: if this process somehow got a console window (e.g. a
# Windows build that ignores conhost --headless), hide it immediately so the
# user never sees a terminal and can't close it to kill the tray. Harmless
# no-op when launched windowless (GetConsoleWindow returns 0).
try {
    $wapi = Add-Type -PassThru -Name OpenPrimeWin -Namespace Native -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr h, int n);
'@
    $cw = $wapi::GetConsoleWindow()
    if ($cw -ne [System.IntPtr]::Zero) { $wapi::ShowWindow($cw, 0) | Out-Null }  # 0 = SW_HIDE
} catch {}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Single instance per user session
$mutex = New-Object System.Threading.Mutex($false, "Local\OpenPrimeTray")
if (-not $mutex.WaitOne(0, $false)) { exit }

$cfgPath = 'C:\ProgramData\OpenPrime\tray.json'
if (-not (Test-Path $cfgPath)) { exit }
$cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
$brand = if ($cfg.brand) { [string]$cfg.brand } else { 'IT Support' }

function Submit-Request($fields) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
    $payload = @{
        agent_id   = [string]$cfg.agent_id
        first_name = $fields.first; last_name = $fields.last
        email      = $fields.email; phone     = $fields.phone
        subject    = $fields.subject; body    = $fields.body
        username   = "$env:USERDOMAIN\$env:USERNAME"
    }
    if ($fields.attachPath -and (Test-Path -LiteralPath $fields.attachPath)) {
        $bytes = [IO.File]::ReadAllBytes($fields.attachPath)
        if ($bytes.Length -le 10MB) {
            $ext = ([IO.Path]::GetExtension($fields.attachPath)).ToLower()
            $mime = switch ($ext) {
                '.png'  { 'image/png' }; '.jpg' { 'image/jpeg' }; '.jpeg' { 'image/jpeg' }
                '.gif'  { 'image/gif' }; '.bmp' { 'image/bmp' };  '.webp' { 'image/webp' }
                '.pdf'  { 'application/pdf' }; '.txt' { 'text/plain' }
                '.log'  { 'text/plain' }; default { 'application/octet-stream' }
            }
            $payload.attach_data = [Convert]::ToBase64String($bytes)
            $payload.attach_name = [IO.Path]::GetFileName($fields.attachPath)
            $payload.attach_mime = $mime
        }
    }
    $body = $payload | ConvertTo-Json -Compress
    $bytes2 = [System.Text.Encoding]::UTF8.GetBytes($body)
    Invoke-RestMethod -Method POST -Uri "$($cfg.base_url)/api/support-request" `
        -ContentType 'application/json; charset=utf-8' -Body $bytes2 -TimeoutSec 60 | Out-Null
}

function Show-SupportForm {
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "$brand - Request support"
    $f.Size = New-Object System.Drawing.Size(440, 560)
    $f.StartPosition = 'CenterScreen'
    $f.FormBorderStyle = 'FixedDialog'
    $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.TopMost = $true

    $y = 15
    $inputs = @{}
    foreach ($def in @(
        @{k='first';  label='First name*'; },
        @{k='last';   label='Last name*'; },
        @{k='email';  label='Your email*'; },
        @{k='phone';  label='Phone'; },
        @{k='subject';label='Subject*'; }
    )) {
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $def.label; $l.Location = New-Object System.Drawing.Point(15, $y)
        $l.Size = New-Object System.Drawing.Size(110, 20)
        $f.Controls.Add($l)
        $t = New-Object System.Windows.Forms.TextBox
        $t.Location = New-Object System.Drawing.Point(130, ($y - 2))
        $t.Size = New-Object System.Drawing.Size(280, 22)
        $f.Controls.Add($t)
        $inputs[$def.k] = $t
        $y += 32
    }
    $l = New-Object System.Windows.Forms.Label
    $l.Text = 'Describe the problem*'; $l.Location = New-Object System.Drawing.Point(15, $y)
    $l.Size = New-Object System.Drawing.Size(300, 20)
    $f.Controls.Add($l)
    $y += 24
    $bodyBox = New-Object System.Windows.Forms.TextBox
    $bodyBox.Multiline = $true; $bodyBox.ScrollBars = 'Vertical'
    $bodyBox.Location = New-Object System.Drawing.Point(15, $y)
    $bodyBox.Size = New-Object System.Drawing.Size(395, 110)
    $f.Controls.Add($bodyBox)
    $y += 122

    # Attachment row: capture-now + pick-a-file, both feed $script:attachPath
    $script:attachPath = ''
    $script:attachTemp = ''   # set when WE created the file, so we clean it up

    $shotBtn = New-Object System.Windows.Forms.Button
    $shotBtn.Text = '📷 Capture screenshot'
    $shotBtn.Location = New-Object System.Drawing.Point(15, $y)
    $shotBtn.Size = New-Object System.Drawing.Size(160, 26)
    $f.Controls.Add($shotBtn)

    $attachBtn = New-Object System.Windows.Forms.Button
    $attachBtn.Text = 'Attach file...'
    $attachBtn.Location = New-Object System.Drawing.Point(180, $y)
    $attachBtn.Size = New-Object System.Drawing.Size(100, 26)
    $f.Controls.Add($attachBtn)

    $attachLbl = New-Object System.Windows.Forms.Label
    $attachLbl.Text = 'No file attached'
    $attachLbl.Location = New-Object System.Drawing.Point(15, ($y + 30))
    $attachLbl.Size = New-Object System.Drawing.Size(395, 18)
    $attachLbl.ForeColor = [System.Drawing.Color]::DimGray
    $f.Controls.Add($attachLbl)

    # Capture the full virtual desktop (all monitors) to a PNG in temp, then
    # attach it. Hides this dialog briefly so it isn't in the shot.
    $shotBtn.Add_Click({
        try {
            $f.Opacity = 0; $f.Hide()
            Start-Sleep -Milliseconds 300
            $vs = [System.Windows.Forms.SystemInformation]::VirtualScreen
            $bmp = New-Object System.Drawing.Bitmap($vs.Width, $vs.Height)
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            $g.CopyFromScreen($vs.Location, [System.Drawing.Point]::Empty, $vs.Size)
            $g.Dispose()
            $shotPath = Join-Path $env:TEMP ("support_shot_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".png")
            $bmp.Save($shotPath, [System.Drawing.Imaging.ImageFormat]::Png)
            $bmp.Dispose()
            if ((Get-Item -LiteralPath $shotPath).Length -gt 10MB) {
                Remove-Item -LiteralPath $shotPath -Force -ErrorAction SilentlyContinue
                $script:attachPath = ''; $script:attachTemp = ''
                $attachLbl.ForeColor = [System.Drawing.Color]::Firebrick
                $attachLbl.Text = 'Screenshot too large (max 10 MB) - try attaching one window instead.'
            } else {
                $script:attachPath = $shotPath
                $script:attachTemp = $shotPath
                $attachLbl.ForeColor = [System.Drawing.Color]::SeaGreen
                $attachLbl.Text = 'Screenshot captured: ' + [IO.Path]::GetFileName($shotPath)
            }
        } catch {
            $attachLbl.ForeColor = [System.Drawing.Color]::Firebrick
            $attachLbl.Text = 'Could not capture screenshot.'
        } finally {
            $f.Show(); $f.Opacity = 1; $f.Activate()
        }
    })

    $attachBtn.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'Images and documents|*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.webp;*.pdf;*.txt;*.log|All files|*.*'
        $dlg.Title = 'Attach a screenshot or file'
        if ($dlg.ShowDialog() -eq 'OK') {
            $len = (Get-Item -LiteralPath $dlg.FileName).Length
            if ($len -gt 10MB) {
                $attachLbl.ForeColor = [System.Drawing.Color]::Firebrick
                $attachLbl.Text = 'File too large (max 10 MB)'
                $script:attachPath = ''; $script:attachTemp = ''
            } else {
                $script:attachPath = $dlg.FileName
                $script:attachTemp = ''   # user's own file - don't delete it
                $attachLbl.ForeColor = [System.Drawing.Color]::SeaGreen
                $attachLbl.Text = [IO.Path]::GetFileName($dlg.FileName)
            }
        }
    })
    $y += 52

    $status = New-Object System.Windows.Forms.Label
    $status.Location = New-Object System.Drawing.Point(15, $y)
    $status.Size = New-Object System.Drawing.Size(250, 30)
    $status.ForeColor = [System.Drawing.Color]::Firebrick
    $f.Controls.Add($status)

    $send = New-Object System.Windows.Forms.Button
    $send.Text = 'Send request'
    $send.Location = New-Object System.Drawing.Point(300, $y)
    $send.Size = New-Object System.Drawing.Size(110, 30)
    $f.Controls.Add($send)
    $f.AcceptButton = $send

    $send.Add_Click({
        foreach ($k in @('first','last','email','subject')) {
            if (-not $inputs[$k].Text.Trim()) { $status.Text = 'Please fill the required (*) fields.'; return }
        }
        if (-not $bodyBox.Text.Trim()) { $status.Text = 'Please describe the problem.'; return }
        $send.Enabled = $false; $status.ForeColor = [System.Drawing.Color]::DimGray
        $status.Text = 'Sending...'
        try {
            Submit-Request @{ first=$inputs['first'].Text.Trim(); last=$inputs['last'].Text.Trim()
                              email=$inputs['email'].Text.Trim(); phone=$inputs['phone'].Text.Trim()
                              subject=$inputs['subject'].Text.Trim(); body=$bodyBox.Text.Trim()
                              attachPath=$script:attachPath }
            if ($script:attachTemp -and (Test-Path -LiteralPath $script:attachTemp)) {
                Remove-Item -LiteralPath $script:attachTemp -Force -ErrorAction SilentlyContinue
            }
            [System.Windows.Forms.MessageBox]::Show(
                "Your request was sent to $brand. We'll get back to you shortly.",
                "$brand", 'OK', 'Information') | Out-Null
            $f.Close()
        } catch {
            $send.Enabled = $true; $status.ForeColor = [System.Drawing.Color]::Firebrick
            $status.Text = 'Could not send - check your connection and try again.'
        }
    })
    $f.ShowDialog() | Out-Null
    $f.Dispose()
}

function Show-DeviceInfo {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 |
           Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } |
           Select-Object -First 1).IPAddress
    [System.Windows.Forms.MessageBox]::Show(
        "Computer: $env:COMPUTERNAME`nUser: $env:USERDOMAIN\$env:USERNAME`nIP: $ip",
        "$brand - Device info", 'OK', 'Information') | Out-Null
}

$icon = New-Object System.Windows.Forms.NotifyIcon
try {
    $icoFile = Join-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) 'tray.ico'
    if (Test-Path $icoFile) {
        $icon.Icon = New-Object System.Drawing.Icon($icoFile)
    }
} catch {}
if (-not $icon.Icon) {
    try { $icon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon("$env:SystemRoot\System32\UserAccountControlSettings.exe") } catch {}
}
if (-not $icon.Icon) { $icon.Icon = [System.Drawing.SystemIcons]::Information }
$icon.Text = "$brand"

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$mi1 = $menu.Items.Add('Request support...')
$mi1.Add_Click({ Show-SupportForm })
$mi2 = $menu.Items.Add('Device info')
$mi2.Add_Click({ Show-DeviceInfo })
$menu.Items.Add('-') | Out-Null
$ver = $menu.Items.Add("$brand agent")
$ver.Enabled = $false
$icon.ContextMenuStrip = $menu
$icon.Add_DoubleClick({ Show-SupportForm })
$icon.Visible = $true

[System.Windows.Forms.Application]::Run()
