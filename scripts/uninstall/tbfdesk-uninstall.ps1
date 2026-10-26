<#
  TBFDesk uninstaller (Windows) - GUI component picker for the client and the server.

  Cleanly removes a TBFDesk install and lets you selectively wipe settings, the device
  ID + encryption keypair, the device key / cached secrets, logs and (server) the
  signing keys / database / policy state, so the next install comes up fresh.

  Usage (from an elevated PowerShell, or it will self-elevate):
     powershell -ExecutionPolicy Bypass -File tbfdesk-uninstall.ps1
     powershell -ExecutionPolicy Bypass -File tbfdesk-uninstall.ps1 -Mode server
     powershell -ExecutionPolicy Bypass -File tbfdesk-uninstall.ps1 -DryRun

  Nothing is deleted until you tick components and confirm; -DryRun previews only.
#>
param(
  [ValidateSet('client','server')] [string]$Mode = 'client',
  [switch]$DryRun,
  [string]$DataDir = 'C:\ProgramData\rustdesk-server',  # server data dir override
  [switch]$NoGui,                                        # headless: no form, no confirm dialog
  [string]$Components = 'all'                            # -NoGui selection: 'all' or e.g. 'app,settings'
)

$ErrorActionPreference = 'Continue'
$AppName = 'TBFDesk'

# ---- self-elevate (needed to stop services / remove Program Files + HKLM) ------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  if ($NoGui) {
    Write-Warning 'Not elevated: service/Program Files/HKLM removal may fail; user-level config removal still works.'
  } else {
    $argline = "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -Mode $Mode"
    if ($DryRun) { $argline += ' -DryRun' }
    Start-Process powershell -Verb RunAs -ArgumentList $argline
    return
  }
}

if (-not $NoGui) { Add-Type -AssemblyName System.Windows.Forms, System.Drawing }

# ---- resolve the real paths ----------------------------------------------------
$pf  = ${env:ProgramFiles}
$pfx = ${env:ProgramFiles(x86)}
$cfgRoots = @(
  (Join-Path $env:APPDATA $AppName),                                                    # interactive user
  "C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\$AppName",                   # LocalService svc
  "C:\Windows\System32\config\systemprofile\AppData\Roaming\$AppName"                   # SYSTEM svc
) | Where-Object { $_ }

function Component-Client {
  @(
    @{ Key='app';      Text='Application, service, registry entry & shortcuts';                 Checked=$true },
    @{ Key='settings'; Text='Settings & preferences';                                           Checked=$true },
    @{ Key='identity'; Text='Device ID & encryption keypair  (-> new ID next install)';          Checked=$true },
    @{ Key='devkey';   Text='Device key & cached management secrets';                           Checked=$true },
    @{ Key='logs';     Text='Logs';                                                             Checked=$true }
  )
}
function Component-Server {
  @(
    @{ Key='svc';     Text='Stop, disable & remove hbbs/hbbr services';                         Checked=$true },
    @{ Key='bins';    Text='Remove hbbs/hbbr binaries';                                         Checked=$true },
    @{ Key='keys';    Text='Signing keys id_ed25519(.pub)  (-> NEW server identity)';            Checked=$true },
    @{ Key='db';      Text='Database (db_v2.sqlite3 - registered peers)';                       Checked=$true },
    @{ Key='tls';     Text='Management TLS cert & key (nemo-api-cert/key.pem)';                 Checked=$true },
    @{ Key='policy';  Text='Policy / integration / session state (nemo_*.json, token)';         Checked=$true },
    @{ Key='updates'; Text='Published client-update packages (nemo_updates)';                   Checked=$true }
  )
}

# ---- the checklist form --------------------------------------------------------
function Show-Picker($items, $title) {
  $f = New-Object Windows.Forms.Form
  $f.Text = "$AppName Uninstaller"; $f.Size = '560,420'; $f.StartPosition = 'CenterScreen'
  $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false
  $lbl = New-Object Windows.Forms.Label; $lbl.Text = $title; $lbl.AutoSize=$true; $lbl.Location='15,12'; $f.Controls.Add($lbl)
  $sub = New-Object Windows.Forms.Label; $sub.Text='Untick anything you want to KEEP.'; $sub.AutoSize=$true; $sub.Location='15,32'; $sub.ForeColor='Gray'; $f.Controls.Add($sub)
  $y = 60; $boxes = @{}
  foreach ($it in $items) {
    $cb = New-Object Windows.Forms.CheckBox
    $cb.Text = $it.Text; $cb.Checked = $it.Checked; $cb.Location = "25,$y"; $cb.AutoSize=$true
    $f.Controls.Add($cb); $boxes[$it.Key] = $cb; $y += 34
  }
  if ($DryRun) { $d=New-Object Windows.Forms.Label; $d.Text='DRY RUN - nothing will be deleted'; $d.AutoSize=$true; $d.Location="25,$y"; $d.ForeColor='DarkOrange'; $f.Controls.Add($d); $y+=28 }
  $ok = New-Object Windows.Forms.Button; $ok.Text='Delete selected'; $ok.Location="300,330"; $ok.Size='110,30'; $ok.DialogResult='OK'; $f.Controls.Add($ok)
  $no = New-Object Windows.Forms.Button; $no.Text='Cancel'; $no.Location="420,330"; $no.Size='100,30'; $no.DialogResult='Cancel'; $f.Controls.Add($no)
  $f.AcceptButton=$ok; $f.CancelButton=$no
  if ($f.ShowDialog() -ne 'OK') { return $null }
  return ($boxes.GetEnumerator() | Where-Object { $_.Value.Checked } | ForEach-Object { $_.Key })
}

# ---- removal engine ------------------------------------------------------------
$Plan = [System.Collections.ArrayList]::new()
# Each step: a Desc, an optional Pre scriptblock (service stop / process kill), and a list
# of Paths to delete. Paths are removed by Remove-Target from the top-level run loop, so there are no
# string-built scriptblocks or closures that could mis-scope `Remove-Target` at run time.
function Step($desc, [string[]]$paths = @(), [scriptblock]$pre = $null) {
  [void]$Plan.Add([pscustomobject]@{ Desc=$desc; Paths=$paths; Pre=$pre })
}
function Remove-Target($path) {
  # Delete a file, directory tree, registry key, or wildcard set. Uses .NET for the
  # filesystem because `Remove-Item -Recurse -Force` throws a NullReferenceException on
  # some directory trees under Windows PowerShell 5.1. Retries a few times so a handle a
  # just-terminated process still holds is released; never blocks indefinitely.
  if ([string]::IsNullOrWhiteSpace($path)) { return }
  if ($path -match '[*?]') {                                  # wildcard -> expand, recurse
    foreach ($it in @(Get-Item -Path $path -Force -ErrorAction SilentlyContinue)) { Remove-Target $it.FullName }
    return
  }
  for ($i = 0; $i -lt 6; $i++) {
    try {
      if ($path -like 'HK*') {                                # registry key
        if (-not (Test-Path -LiteralPath $path)) { return }
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
      } elseif (Test-Path -LiteralPath $path -PathType Container) {
        [System.IO.Directory]::Delete($path, $true)
      } elseif (Test-Path -LiteralPath $path) {
        [System.IO.File]::Delete($path)
      } else { return }                                       # already gone
    } catch { }
    if (-not (Test-Path -LiteralPath $path)) { return }
    Start-Sleep -Milliseconds 500
  }
}

function Build-Client($sel) {
  $wipeAll = @('settings','identity','devkey','logs') | ForEach-Object { $sel -contains $_ } | Where-Object { -not $_ } | Measure-Object | ForEach-Object { $_.Count -eq 0 }
  if ($sel -contains 'app') {
    Step 'Stop & delete the TBFDesk/RustDesk Windows service' @() {
      foreach ($s in 'TBFDesk','RustDesk') { if (Get-Service $s -ErrorAction SilentlyContinue) { Stop-Service $s -Force -EA SilentlyContinue; sc.exe delete $s | Out-Null } } }
    Step 'Kill running tbfdesk/rustdesk processes' @() {
      $p = Get-Process tbfdesk,rustdesk,RuntimeBroker_rustdesk -EA SilentlyContinue
      if ($p) { $p | Stop-Process -Force -EA SilentlyContinue; $p | Wait-Process -Timeout 10 -EA SilentlyContinue; Start-Sleep -Milliseconds 800 } }
    $inst = @("$pf\$AppName"); if ($pfx) { $inst += "$pfx\$AppName" }
    Step "Remove install dir ($pf\$AppName)" $inst
    Step 'Remove Add/Remove-Programs registry entry' @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$AppName","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$AppName")
    Step 'Remove Start-Menu / Desktop / Startup shortcuts' @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$AppName","$env:PUBLIC\Desktop\$AppName.lnk","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\$AppName Tray.lnk")
  }
  foreach ($root in $cfgRoots) {
    $cfg = Join-Path $root 'config'
    if ($wipeAll) { Step "Wipe entire config ($root): settings, ID, keypair, device key, logs" @($root); continue }
    if ($sel -contains 'identity') { Step "Remove device ID & keypair ($cfg\$AppName.toml)" @("$cfg\$AppName.toml") }
    if ($sel -contains 'devkey')   { Step "Remove device key & policy cache ($cfg\${AppName}2.toml)" @("$cfg\${AppName}2.toml") }
    if ($sel -contains 'settings') { Step "Remove local settings & peer cache" @("$cfg\${AppName}_local.toml","$cfg\peers") }
    if ($sel -contains 'logs')     { Step "Remove logs" @("$root\log") }
  }
}

function Build-Server($sel) {
  if ($sel -contains 'svc') {
    Step 'Stop & delete hbbs/hbbr services' @() { foreach ($s in 'hbbs','hbbr','rustdesk-hbbs','rustdesk-hbbr') { if (Get-Service $s -EA SilentlyContinue) { Stop-Service $s -Force -EA SilentlyContinue; sc.exe delete $s | Out-Null } } }
  }
  if ($sel -contains 'bins')    { Step "Remove hbbs/hbbr binaries ($pf\$AppName-Server)" @("$pf\$AppName-Server\hbbs.exe","$pf\$AppName-Server\hbbr.exe") }
  if ($sel -contains 'keys')    { Step "Remove signing keys ($DataDir\id_ed25519*)" @("$DataDir\id_ed25519","$DataDir\id_ed25519.pub") }
  if ($sel -contains 'db')      { Step "Remove database ($DataDir\db_v2.sqlite3*)" @("$DataDir\db_v2.sqlite3*") }
  if ($sel -contains 'tls')     { Step 'Remove management TLS cert & key' @("$DataDir\nemo-api-cert.pem","$DataDir\nemo-api-key.pem") }
  if ($sel -contains 'policy')  { Step 'Remove policy/integration/session state' @("$DataDir\nemo_*.json*","$DataDir\token") }
  if ($sel -contains 'updates') { Step 'Remove published update packages' @("$DataDir\nemo_updates") }
}

# ---- main ----------------------------------------------------------------------
$items = if ($Mode -eq 'server') { Component-Server } else { Component-Client }

if ($NoGui) {
  $sel = if ($Components -eq 'all' -or [string]::IsNullOrWhiteSpace($Components)) { $items | ForEach-Object { $_.Key } }
         else { $Components -split '\s*,\s*' }
} else {
  $sel = Show-Picker $items "Select what to remove from the TBFDesk $($Mode.ToUpper()):"
  if (-not $sel) { [Windows.Forms.MessageBox]::Show('Cancelled - nothing was removed.','TBFDesk Uninstaller') | Out-Null; return }
}

if ($Mode -eq 'server') { Build-Server $sel } else { Build-Client $sel }
if ($Plan.Count -eq 0) { if ($NoGui) { Write-Output 'Nothing to do.' } else { [Windows.Forms.MessageBox]::Show('Nothing to do.','TBFDesk Uninstaller') | Out-Null }; return }

$summary = "The following will be removed:`n`n" + (($Plan | ForEach-Object { "  - " + $_.Desc }) -join "`n") + "`n`nThis cannot be undone."
if ($DryRun) { $summary += "`n`n(DRY RUN - nothing will actually be deleted.)" }
if (-not $NoGui) {
  $ans = [Windows.Forms.MessageBox]::Show($summary, "$AppName Uninstaller", 'OKCancel', 'Warning')
  if ($ans -ne 'OK') { return }
} else {
  Write-Output $summary
}

$log = foreach ($step in $Plan) {
  if ($DryRun) { "[dry-run] $($step.Desc)" }
  else {
    try {
      if ($step.Pre) { & $step.Pre }
      foreach ($p in $step.Paths) { Remove-Target $p }
      "OK  $($step.Desc)"
    } catch { "ERR $($step.Desc): $($_.Exception.Message)" }
  }
}
if ($NoGui) { Write-Output ''; Write-Output ($log -join "`n") }
else { [Windows.Forms.MessageBox]::Show(("Done.`n`n" + ($log -join "`n")), "$AppName Uninstaller") | Out-Null }
