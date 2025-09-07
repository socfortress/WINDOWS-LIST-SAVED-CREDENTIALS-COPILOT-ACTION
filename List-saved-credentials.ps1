[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\List-Saved-Credentials.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep  = 5
$runStart = Get-Date

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"; $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function NowISO { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString('N')))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

Rotate-Log
Write-Log "=== SCRIPT START : Scan Windows Credential Manager ==="

$ts = NowISO
$lines = New-Object System.Collections.ArrayList

try {
  $creds = @()
  $foundCmdKey = $false
  $foundVault  = $false
  $cmdkeyExit  = $null
  $vaultExit   = $null

  # ---- cmdkey
  try {
    $cmdOutput = cmdkey /list 2>&1
    $cmdkeyExit = $LASTEXITCODE
    if ($cmdOutput) {
      $foundCmdKey = $true
      foreach ($line in $cmdOutput) {
        if ($line -match 'Target:\s*(.+)$') {
          $target = $Matches[1].Trim()
          Write-Log "Found generic credential: $target"
          $creds += [pscustomobject]@{ type='Generic'; target=$target; source='cmdkey'; flagged_reasons=@() }
        }
      }
    }
  } catch {
    Write-Log ("cmdkey failed: {0}" -f $_.Exception.Message) 'WARN'
  }

  # ---- vaultcmd
  try {
    $vaultOutput = vaultcmd /list 2>&1
    $vaultExit = $LASTEXITCODE
    if ($vaultOutput) {
      $foundVault = $true
      foreach ($line in $vaultOutput) {
        if ($line -match 'Vault:\s*(.+)$') {
          $vault = $Matches[1].Trim()
          Write-Log "Found vault entry: $vault"
          $creds += [pscustomobject]@{ type='Vault'; target=$vault; source='vaultcmd'; flagged_reasons=@() }
        }
      }
    }
  } catch {
    Write-Log ("vaultcmd failed: {0}" -f $_.Exception.Message) 'WARN'
  }

  # Normalize & flag
  $creds = $creds | Sort-Object target,type -Unique
  foreach ($c in $creds) {
    if ($c.target -match 'MicrosoftAccount|WindowsLive') {
      $c.flagged_reasons += 'Microsoft/Windows account stored'
      Write-Log "Flagged: $($c.target) -> Microsoft/Windows account" 'WARN'
    }
    if ($c.target -match 'git:|github') {
      $c.flagged_reasons += 'Source control credential'
      Write-Log "Flagged: $($c.target) -> Git/Source Control" 'WARN'
    }
    if ($c.type -eq 'Vault') {
      $c.flagged_reasons += 'Stored in Windows Vault'
      Write-Log "Flagged: $($c.target) -> Windows Vault entry" 'WARN'
    }
  }

  $flagged = $creds | Where-Object { $_.flagged_reasons.Count -gt 0 }

  # verify_source record
  [void]$lines.Add( (@{
    timestamp      = $ts
    host           = $HostName
    action         = 'scan_saved_credentials'
    copilot_action = $true
    item           = 'verify_source'
    description    = 'Tool presence and exit codes'
    cmdkey_present = $foundCmdKey
    cmdkey_exit    = $cmdkeyExit
    vaultcmd_present = $foundVault
    vaultcmd_exit    = $vaultExit
  } | ConvertTo-Json -Compress -Depth 5) )

  # per-credential records
  foreach ($c in $creds) {
    [void]$lines.Add( (@{
      timestamp       = $ts
      host            = $HostName
      action          = 'scan_saved_credentials'
      copilot_action  = $true
      item            = 'credential'
      description     = "Saved credential discovered"
      type            = $c.type
      target          = $c.target
      source          = $c.source
      flagged         = ($c.flagged_reasons.Count -gt 0)
      flagged_reasons = $c.flagged_reasons
    } | ConvertTo-Json -Compress -Depth 6) )
  }

  # summary (prepend)
  $summary = @{
    timestamp        = $ts
    host             = $HostName
    action           = 'scan_saved_credentials'
    copilot_action   = $true
    item             = 'summary'
    description      = 'Run summary and counts'
    credential_count = $creds.Count
    flagged_count    = $flagged.Count
    duration_s       = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }
  $lines = ,(@($summary | ConvertTo-Json -Compress -Depth 5)) + $lines

  # write NDJSON
  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'

  # Console report
  Write-Host "`n=== Saved Credential Report ==="
  Write-Host "Host: $HostName"
  Write-Host "Total Credentials Found: $($creds.Count)"
  Write-Host "Flagged Credentials: $($flagged.Count)`n"
  if ($creds.Count -gt 0) {
    $creds | Select-Object type,target,source | Format-Table -AutoSize
  } else {
    Write-Host "No saved credentials found."
  }
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = @(
    (@{
      timestamp      = NowISO
      host           = $HostName
      action         = 'scan_saved_credentials'
      copilot_action = $true
      item           = 'error'
      description    = 'Unhandled error'
      error          = $_.Exception.Message
    } | ConvertTo-Json -Compress -Depth 4)
  )
  Write-NDJSONLines -JsonLines $err -Path $ARLog
  Write-Log "Error NDJSON written to $ARLog" 'INFO'
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
