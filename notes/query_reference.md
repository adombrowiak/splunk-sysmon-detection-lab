# Query Reference

## Purpose
This document serves as a structured reference of all commands, queries, and troubleshooting steps used throughout the Splunk + Sysmon detection lab.

It is intended to:
- Document how the lab was built
- Capture detection development steps
- Provide a reusable reference for future analysis

---

## Lab Context

- Data Source: Sysmon Event ID 1 (Process Creation)
- Log Format: Raw XML (not fully field-parsed by default)
- Platform:
  - Windows 11 (endpoint)
  - Ubuntu (Splunk server)
- Log Forwarding: Splunk Universal Forwarder

---

## 1. Attack Simulation Commands (Windows)

These commands were executed on the Windows endpoint to generate telemetry.

### Suspicious PowerShell (Hidden Execution)
Simulates stealthy execution often used by attackers.

```powershell
powershell -nop -w hidden -c "Get-Process | Select-Object -First 5"
```

---

### Encoded PowerShell Execution
Simulates obfuscated command execution.

```powershell
$cmd = 'Write-Output "Hello from encoded PowerShell"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$enc = [Convert]::ToBase64String($bytes)
powershell -enc $enc
```

---

### rundll32 Execution (LOLBin)
Simulates signed binary proxy execution.

```cmd
rundll32.exe shell32.dll,Control_RunDLL
```

---

### cmd Spawning PowerShell
Simulates process chaining behavior.

```cmd
cmd.exe /c powershell.exe -nop -c "Get-Date"
```

---

## 2. Splunk Server / Forwarder Commands

### Enable Splunk Receiver Port

```bash
sudo /opt/splunk/bin/splunk enable listen 9997
```

---

### Verify Listening Port

```bash
sudo ss -tulnp | grep 9997
```

---

### Restart Universal Forwarder (Windows)

```cmd
net stop splunkforwarder
net start splunkforwarder
```

---

### Verify Sysmon Events on Endpoint

```cmd
wevtutil qe Microsoft-Windows-Sysmon/Operational /c:5 /f:text
```

---

### Verify Forwarder Configuration

```cmd
"C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" btool inputs list "WinEventLog://Microsoft-Windows-Sysmon/Operational" --debug
```

---

## 3. Splunk Queries (Detection & Analysis)

### Verify Data Ingestion

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| table _time host source
| head 15
```

---

### Confirm Process Creation Events

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
```

---

### XML-Based Event Filtering (Raw Logs)

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
```

---

### Extract Process Image (proc_image)

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
| rex field=_raw "Name=['\"]Image['\"]>(?<proc_image>[^<]+)<"
| table _time proc_image
| head 20
```

---

### Extract Command Line Arguments

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
| rex field=_raw "Name=['\"]Image['\"]>(?<proc_image>[^<]+)<"
| rex field=_raw "Name=['\"]CommandLine['\"]>(?<cmdline>[^<]+)<"
| table _time proc_image cmdline
| sort - _time
```

---

### Parent-Child Process Relationships

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
| rex field=_raw "Name=['\"]Image['\"]>(?<proc_image>[^<]+)<"
| rex field=_raw "Name=['\"]ParentImage['\"]>(?<parent_image>[^<]+)<"
| stats count by parent_image proc_image
| sort - count
```

---

### PowerShell Execution Detection

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
| rex field=_raw "Name=['\"]Image['\"]>(?<proc_image>[^<]+)<"
| search proc_image="*powershell*"
| stats count by proc_image
```

---

## 4. Troubleshooting Notes

### Issue: No Results from `stats`
- Root cause: Field extraction failed (rex mismatch)
- Resolution: Adjusted regex to match XML structure

---

### Issue: Commands Not Appearing in Splunk
- Root causes:
  - Time range too narrow
  - Forwarder delay
  - Incorrect search filter

- Resolution:
  - Set time range to **All Time**
  - Verified forwarder service status
  - Used raw XML search (`<EventID>1</EventID>`)

---

### Key Learning

Sysmon logs in Splunk may not be normalized by default.  
Detection engineering often requires parsing raw XML using `rex`.

---
