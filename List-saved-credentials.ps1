[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\List-Saved-Credentials.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level = 'INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"
        $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

Rotate-Log

try {
  if (Test-Path $ARLog) {
    Remove-Item -Path $ARLog -Force -ErrorAction Stop
  }
  New-Item -Path $ARLog -ItemType File -Force | Out-Null
  Write-Log "Active response log cleared for fresh run."
} catch {
  Write-Log "Failed to clear ${ARLog}: $($_.Exception.Message)" 'WARN'
}

$Start = Get-Date
Write-Log "=== SCRIPT START : Scan Windows Credential Manager ==="

try {
  $Creds = @()
  $cmdOutput = cmdkey /list 2>&1
  foreach ($line in $cmdOutput) {
    if ($line -match 'Target: (.+)$') {
      $target = $Matches[1].Trim()
      Write-Log "Found generic credential: $target"
      $Creds += [PSCustomObject]@{
        type = "Generic"
        target = $target
        source = "cmdkey"
        flagged_reasons = @()
      }
    }
  }
  $vaultOutput = vaultcmd /list 2>&1
  foreach ($line in $vaultOutput) {
    if ($line -match 'Vault:\s*(.+)$') {
      $vault = $Matches[1].Trim()
      Write-Log "Found vault entry: $vault"
      $Creds += [PSCustomObject]@{
        type = "Vault"
        target = $vault
        source = "vaultcmd"
        flagged_reasons = @()
      }
    }
  }
  $Creds = $Creds | Sort-Object target,type -Unique
  foreach ($c in $Creds) {
    if ($c.target -match 'MicrosoftAccount|WindowsLive') {
      $c.flagged_reasons += "Microsoft/Windows account stored"
      Write-Log "Flagged: $($c.target) -> Microsoft/Windows account" "WARN"
    }
    if ($c.target -match 'git:|github') {
      $c.flagged_reasons += "Source control credential"
      Write-Log "Flagged: $($c.target) -> Git/Source Control" "WARN"
    }
    if ($c.type -eq "Vault") {
      $c.flagged_reasons += "Stored in Windows Vault"
      Write-Log "Flagged: $($c.target) -> Windows Vault entry" "WARN"
    }
  }
  $timestamp = (Get-Date).ToString('o')
  $FullReport = @{
    host = $HostName
    timestamp = $timestamp
    action = "scan_saved_credentials"
    credential_count = $Creds.Count
    credentials = $Creds
  }
  $FlaggedReport = @{
    host = $HostName
    timestamp = $timestamp
    action = "scan_saved_credentials_flagged"
    flagged_count = ($Creds | Where-Object { $_.flagged_reasons.Count -gt 0 }).Count
    flagged_credentials = $Creds | Where-Object { $_.flagged_reasons.Count -gt 0 }
  }
  $FullReport   | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  $FlaggedReport| ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "JSON reports (full + flagged) written to $ARLog"
  Write-Host "`n=== Saved Credential Report ==="
  Write-Host "Host: $HostName"
  Write-Host "Total Credentials Found: $($Creds.Count)"
  Write-Host "Flagged Credentials: $($FlaggedReport.flagged_count)`n"
  $Creds | Select-Object type,target,source | Format-Table -AutoSize
} catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorLog = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host = $HostName
    action = "scan_saved_credentials_error"
    status = "error"
    error = $_.Exception.Message
  }
  $errorLog | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
} finally {
  $dur = [int]((Get-Date) - $Start).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
