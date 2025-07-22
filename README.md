# PowerShell Scan Saved Credentials Template

This repository provides a template for PowerShell-based active response scripts for security automation and incident response. The template ensures consistent logging, error handling, and execution flow for scanning Windows Credential Manager and Vault for saved credentials.

---

## Overview

The `Scan-Saved-Credentials.ps1` script inventories all saved credentials in Windows Credential Manager and Vault, flags sensitive or risky entries (such as Microsoft accounts, source control credentials, or vault entries), and logs all actions, results, and errors in both a script log and an active-response log. This makes it suitable for integration with SOAR platforms, SIEMs, and incident response workflows.

---

## Template Structure

### Core Components

- **Parameter Definitions**: Configurable script parameters
- **Logging Framework**: Consistent logging with timestamps and rotation
- **Flagging Logic**: Identifies sensitive or risky credentials
- **JSON Output**: Standardized response format
- **Execution Timing**: Performance monitoring

---

## How Scripts Are Invoked

### Command Line Execution

```powershell
.\Scan-Saved-Credentials.ps1 [-LogPath <string>] [-ARLog <string>]
```

### Parameters

| Parameter | Type   | Default Value                                                    | Description                                  |
|-----------|--------|------------------------------------------------------------------|----------------------------------------------|
| `LogPath` | string | `$env:TEMP\List-Saved-Credentials.log`                           | Path for execution logs                      |
| `ARLog`   | string | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Path for active response JSON output         |

---

### Example Invocations

```powershell
# Basic execution with default parameters
.\Scan-Saved-Credentials.ps1

# Custom log path
.\Scan-Saved-Credentials.ps1 -LogPath "C:\Logs\SavedCreds.log"

# Integration with OSSEC/Wazuh active response
.\Scan-Saved-Credentials.ps1 -ARLog "C:\ossec\active-responses.log"
```

---

## Template Functions

### `Write-Log`
**Purpose**: Standardized logging with severity levels and console output.

**Parameters**:
- `Message` (string): The log message
- `Level` (ValidateSet): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'

**Features**:
- Timestamped output
- Color-coded console output
- File logging
- Verbose/debug support

**Usage**:
```powershell
Write-Log "Found generic credential: $target"
Write-Log "Flagged: $($c.target) -> Microsoft/Windows account" "WARN"
Write-Log "JSON reports (full + flagged) appended to $ARLog"
```

---

### `Rotate-Log`
**Purpose**: Manages log file size and rotation.

**Features**:
- Monitors log file size (default: 100KB)
- Maintains a configurable number of backups (default: 5)
- Rotates logs automatically

**Configuration Variables**:
- `$LogMaxKB`: Max log file size in KB
- `$LogKeep`: Number of rotated logs to retain

---

## Script Execution Flow

1. **Initialization**
   - Parameter validation and assignment
   - Error action preference
   - Log rotation
   - Start time logging

2. **Execution**
   - Enumerates credentials using `cmdkey` and `vaultcmd`
   - Flags credentials based on:
     - Microsoft/Windows account stored
     - Source control credentials (git/github)
     - Stored in Windows Vault
   - Logs findings

3. **Completion**
   - Outputs full inventory and flagged credentials as JSON to the active response log
   - Logs script end and duration
   - Displays summary in console

4. **Error Handling**
   - Catches and logs exceptions
   - Outputs error details as JSON

---

## JSON Output Format

### Full Report Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "scan_saved_credentials",
  "credential_count": 5,
  "credentials": [
    {
      "type": "Generic",
      "target": "git:https://github.com/user/repo",
      "source": "cmdkey",
      "flagged_reasons": ["Source control credential"]
    }
  ]
}
```

### Flagged Credentials Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "scan_saved_credentials_flagged",
  "flagged_count": 2,
  "flagged_credentials": [
    {
      "type": "Vault",
      "target": "MicrosoftAccount:user@example.com",
      "source": "vaultcmd",
      "flagged_reasons": ["Microsoft/Windows account stored", "Stored in Windows Vault"]
    }
  ]
}
```

### Error Example

```json
{
  "timestamp": "2025-07-22T10:31:10.456Z",
  "host": "HOSTNAME",
  "action": "scan_saved_credentials_error",
  "status": "error",
  "error": "Access is denied"
}
```

---

## Implementation Guidelines

1. Use the provided logging and error handling functions.
2. Customize the flagging logic as needed for your environment.
3. Ensure JSON output matches your SOAR/SIEM requirements.
4. Test thoroughly in a non-production environment.

---

## Security Considerations

- Run with the minimum required privileges.
- Validate all input parameters.
- Secure log files and output locations.
- Monitor for errors and failed inventory.

---

## Troubleshooting

- **Permission Errors**: Run as Administrator.
- **Command Not Found**: Ensure `cmdkey` and `vaultcmd` are available.
- **Log Output**: Check file permissions and disk space.

---

## License

This template is provided as-is for security automation
