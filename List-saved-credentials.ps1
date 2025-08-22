[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\List-Saved-Credentials.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep  = 5

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i=$LogKeep-1; $i -ge 0; $i--) {
        $old="$LogPath.$i"; $new="$LogPath."+($i+1)
        if (Test-Path $old) {Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

Rotate-Log

$Start = Get-Date
Write-Log "=== SCRIPT START : Scan Windows Credential Manager ==="

try {
  $Creds=@()
  $cmdOutput = cmdkey /list 2>&1
  foreach($line in $cmdOutput){
    if($line -match 'Target: (.+)$'){
      $target=$Matches[1].Trim()
      Write-Log "Found generic credential: $target"
      $Creds += [pscustomobject]@{
        type='Generic'
        target=$target
        source='cmdkey'
        flagged_reasons=@()
      }
    }
  }

  $vaultOutput = vaultcmd /list 2>&1
  foreach($line in $vaultOutput){
    if($line -match 'Vault:\s*(.+)$'){
      $vault=$Matches[1].Trim()
      Write-Log "Found vault entry: $vault"
      $Creds += [pscustomobject]@{
        type='Vault'
        target=$vault
        source='vaultcmd'
        flagged_reasons=@()
      }
    }
  }

  $Creds = $Creds | Sort-Object target,type -Unique
  foreach($c in $Creds){
    if($c.target -match 'MicrosoftAccount|WindowsLive'){
      $c.flagged_reasons += 'Microsoft/Windows account stored'
      Write-Log "Flagged: $($c.target) -> Microsoft/Windows account" 'WARN'
    }
    if($c.target -match 'git:|github'){
      $c.flagged_reasons += 'Source control credential'
      Write-Log "Flagged: $($c.target) -> Git/Source Control" 'WARN'
    }
    if($c.type -eq 'Vault'){
      $c.flagged_reasons += 'Stored in Windows Vault'
      Write-Log "Flagged: $($c.target) -> Windows Vault entry" 'WARN'
    }
  }

  $timestamp = (Get-Date).ToString('o')
  $flaggedOnly = $Creds | Where-Object { $_.flagged_reasons.Count -gt 0 }

  # Prepare NDJSON lines
  $lines=@()

  # First, add a summary NDJSON line
  $lines += ([pscustomobject]@{
    timestamp       = $timestamp
    host            = $HostName
    action          = 'scan_saved_credentials_summary'
    credential_count= $Creds.Count
    flagged_count   = $flaggedOnly.Count
    copilot_action  = $true
  } | ConvertTo-Json -Compress -Depth 3)

  # Then, one line per credential
  foreach($c in $Creds){
    $lines += ([pscustomobject]@{
      timestamp      = $timestamp
      host           = $HostName
      action         = 'scan_saved_credentials'
      type           = $c.type
      target         = $c.target
      source         = $c.source
      flagged        = $c.flagged_reasons.Count -gt 0
      flagged_reasons= if($c.flagged_reasons.Count){$c.flagged_reasons -join ', '}else{$null}
      copilot_action = $true
    } | ConvertTo-Json -Compress -Depth 4)
  }

  $ndjson=[string]::Join("`n",$lines)
  $tempFile="$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force

  $recordCount=$lines.Count
  try{
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Wrote $recordCount NDJSON record(s) to $ARLog" 'INFO'
  }catch{
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
    Write-Log "ARLog locked; wrote to $($ARLog).new" 'WARN'
  }

  Write-Host "`n=== Saved Credential Report ==="
  Write-Host "Host: $HostName"
  Write-Host "Total Credentials Found: $($Creds.Count)"
  Write-Host "Flagged Credentials: $($flaggedOnly.Count)`n"
  $Creds | Select-Object type,target,source | Format-Table -AutoSize
}
catch{
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj=[pscustomobject]@{
    timestamp=(Get-Date).ToString('o')
    host=$HostName
    action='scan_saved_credentials_error'
    status='error'
    error=$_.Exception.Message
    copilot_action=$true
  }
  $ndjson=($errorObj | ConvertTo-Json -Compress -Depth 3)
  $tempFile="$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force
  try{
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Error JSON written to $ARLog" 'INFO'
  }catch{
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
    Write-Log "ARLog locked; wrote error to $($ARLog).new" 'WARN'
  }
}
finally{
  $dur=[int]((Get-Date)-$Start).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
