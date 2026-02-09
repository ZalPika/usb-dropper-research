# Detection Guide - USB Dropper with Discord C2

This guide provides comprehensive detection methods for identifying USB dropper malware with Discord command-and-control capabilities.

---

## 🎯 Detection Strategy Overview

Effective detection requires a **multi-layered approach**:

1. **Behavioral Analysis** - Monitor suspicious activities
2. **File System Monitoring** - Track file modifications
3. **Network Analysis** - Identify C2 communications
4. **Registry Monitoring** - Detect persistence mechanisms
5. **Process Analysis** - Identify malicious processes

---

## 🔍 Behavioral Indicators of Compromise (IOCs)

### High-Confidence Indicators

| Behavior | Severity | Detection Method |
|----------|----------|------------------|
| PowerShell Add-MpPreference execution | 🔴 Critical | EDR / SIEM |
| Registry Run key modification | 🔴 Critical | Sysinternals Autoruns |
| Execution from removable media | 🟡 Medium | USB monitoring |
| Discord API traffic from non-browser process | 🔴 Critical | Network monitoring |
| File operations in C:\ProgramData\ | 🟡 Medium | File integrity monitoring |
| Keylogger file creation in TEMP | 🔴 Critical | File system monitoring |

### Behavioral Patterns

**Pattern 1: Initial Infection**
```
1. USB device insertion
2. User executes .bat or .exe file
3. PowerShell process spawned with elevated privileges
4. File copied to C:\ProgramData\
5. Registry modification (Run key)
6. Defender exclusion added
7. Executable launched
```

**Pattern 2: C2 Communication**
```
1. Python process or compiled executable starts
2. Outbound HTTPS connection to Discord API
3. Persistent connection maintained
4. Periodic heartbeat traffic
5. Command execution via Discord messages
6. Data exfiltration via Discord CDN
```

---

## 📁 File System Indicators

### File Locations

**Primary Installation:**
```
C:\ProgramData\SystemHelper\
├── systemhelper.exe          # Main payload
└── [potential additional files]
```

**Temporary Files:**
```
C:\Users\[Username]\AppData\Local\Temp\
├── helpmenu.txt              # Help menu output
├── output.txt                # Command output buffer
├── key_log.txt               # Keylogger data
└── monitor.png               # Screenshot captures
```

### File Characteristics

**systemhelper.exe:**
- **Type:** PE32 executable (Windows)
- **Size:** Typically 5-15 MB (PyInstaller bundle)
- **Signature:** Usually unsigned
- **Creation time:** Matches installation timestamp
- **Entropy:** High (due to PyInstaller compression)

**Batch File (install.bat):**
- **Type:** Windows batch script
- **Size:** <1 KB
- **Contains:**
  - Registry manipulation commands
  - PowerShell execution
  - Defender exclusion commands

### File Hashes (Example)

```
MD5:    [Variable - changes with each compilation]
SHA1:   [Variable - changes with each compilation]
SHA256: [Variable - changes with each compilation]
```

**Note:** Hashes change with each compilation. Focus on behavioral detection.

### YARA Rules

```yara
rule USB_Dropper_Discord_C2 {
    meta:
        description = "Detects USB dropper with Discord C2"
        author = "Security Research"
        date = "2024-12-22"
        severity = "high"
    
    strings:
        $discord1 = "discord.com" ascii wide
        $discord2 = "discordapp.com" ascii wide
        $discord3 = "discord.Client" ascii wide
        
        $registry = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $defender = "Add-MpPreference" ascii wide
        $systemhelper = "SystemHelper" ascii wide
        
        $keylog1 = "key_log.txt" ascii wide
        $keylog2 = "pynput" ascii wide
        
        $commands1 = "!help" ascii wide
        $commands2 = "!sysinfo" ascii wide
        $commands3 = "!exec" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($discord*) and 1 of ($registry, $defender, $systemhelper)) or
            (1 of ($discord*) and 2 of ($keylog*)) or
            (2 of ($discord*) and 2 of ($commands*))
        )
}
```

---

## 🔐 Registry Indicators

### Persistence Mechanisms

**Run Key Entry:**
```
Key:   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value: SystemHelper
Data:  C:\ProgramData\SystemHelper\systemhelper.exe
```

**Detection Command:**
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SystemHelper
```

**PowerShell Detection:**
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object SystemHelper
```

### Defender Exclusions

**Exclusion Path:**
```
C:\ProgramData\SystemHelper
```

**Detection Command:**
```powershell
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

---

## 🌐 Network Indicators

### Discord API Traffic

**Primary Endpoints:**
```
discord.com/api/*
discordapp.com/api/*
cdn.discordapp.com/*
```

**Traffic Characteristics:**
- **Protocol:** HTTPS (TLS 1.2/1.3)
- **Port:** 443
- **Frequency:** Persistent connection with periodic heartbeats
- **User-Agent:** Python-based (discord.py library)
- **Content-Type:** application/json

### Network Detection Methods

**1. Monitor Discord Traffic from Non-Browser Processes**

```bash
# Netstat monitoring
netstat -anb | findstr "443"

# Look for python.exe or systemhelper.exe making HTTPS connections
```

**2. DNS Monitoring**

```
Query patterns:
- discord.com
- discordapp.com
- api.ipify.org (IP lookup)
```

**3. TLS Certificate Inspection**

```
Certificate Issuer: Let's Encrypt / Cloudflare
SNI: discord.com, discordapp.com
```

### Suricata Rules

```
alert tls any any -> any any (msg:"Possible Discord C2 - Non-browser TLS to Discord"; tls_sni; content:"discord"; pcre:"/discord(app)?\.com/"; flow:established,to_server; sid:1000001; rev:1;)

alert http any any -> any any (msg:"Discord API Access from Suspicious Process"; http.uri; content:"/api/"; http.host; content:"discord"; sid:1000002; rev:1;)
```

---

## 🖥️ Process Analysis

### Suspicious Process Indicators

**Normal Discord Usage:**
```
Process: Discord.exe, DiscordApp.exe, or browser
Parent:  explorer.exe
Network: HTTPS to Discord
```

**Malicious C2:**
```
Process: systemhelper.exe, python.exe, pythonw.exe
Parent:  explorer.exe (initial), or runs standalone
Network: HTTPS to Discord API
```

### Process Monitoring Commands

**List Python Processes:**
```cmd
tasklist | findstr python
wmic process where "name like '%python%'" get processid,commandline
```

**Process Tree Analysis:**
```powershell
Get-Process | Where-Object {$_.ProcessName -match "python|systemhelper"} | Select-Object Name, Id, Path
```

---

## 🔬 Windows Event Log Analysis

### Key Event IDs

| Event ID | Source | Description |
|----------|--------|-------------|
| 4688 | Security | Process creation |
| 4657 | Security | Registry value modification |
| 7045 | System | Service installation |
| 5001 | Windows Defender | Defender disabled |
| 5007 | Windows Defender | Configuration changed |
| 11 | Sysmon | File created |
| 13 | Sysmon | Registry value set |

### Event Log Queries

**PowerShell Event Log:**
```powershell
# PowerShell script execution
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match "Add-MpPreference"}
```

**Registry Modifications:**
```powershell
# Registry Run key changes
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4657} | Where-Object {$_.Message -match "CurrentVersion\\Run"}
```

---

## 🛡️ Endpoint Detection Rules

### Microsoft Defender ATP

**Custom Detection Rule:**
```kql
// Detect PowerShell adding Defender exclusions
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "Add-MpPreference"
| where ProcessCommandLine contains "ExclusionPath"
```

### Sysmon Configuration

```xml
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- Detect file creation in ProgramData -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">ProgramData\SystemHelper</TargetFilename>
    </FileCreate>
    
    <!-- Detect registry Run key modification -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">CurrentVersion\Run\SystemHelper</TargetObject>
    </RegistryEvent>
    
    <!-- Detect Discord API network connections -->
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">discord</DestinationHostname>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

---

## 🧪 Forensic Analysis

### Memory Forensics

**Volatility Commands:**
```bash
# List processes
volatility -f memory.dmp pslist

# Network connections
volatility -f memory.dmp netscan | grep discord

# Process command lines
volatility -f memory.dmp cmdline -p [PID]

# Dump process memory
volatility -f memory.dmp memdump -p [PID] -D output/
```

### Disk Forensics

**File Timeline:**
```bash
# MFT analysis
analyzeMFT.py -f $MFT -o timeline.csv

# Filter for SystemHelper
grep "SystemHelper" timeline.csv
```

**Registry Forensics:**
```bash
# Extract Run keys
regripper.exe -r NTUSER.DAT -p run

# Check for Defender exclusions
regripper.exe -r SOFTWARE -p defender
```

---

## 📊 SIEM Detection Rules

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security"
(EventCode=4688 AND Image="*python*" AND CommandLine="*discord*")
OR (EventCode=4657 AND ObjectName="*CurrentVersion\\Run*")
OR (EventCode=5007 AND Message="*ExclusionPath*")
| stats count by ComputerName, EventCode, User
```

### Elastic/ELK Query

```json
{
  "query": {
    "bool": {
      "should": [
        {
          "match": {
            "process.name": "python.exe"
          }
        },
        {
          "match": {
            "network.protocol": "https"
          }
        },
        {
          "match": {
            "destination.domain": "discord.com"
          }
        }
      ],
      "minimum_should_match": 2
    }
  }
}
```

---

## 🚨 Automated Detection Script

### PowerShell Detection Script

```powershell
# USB Dropper Detection Script
# Run as Administrator

Write-Host "=== USB Dropper Detection Tool ===" -ForegroundColor Cyan

# Check for SystemHelper directory
if (Test-Path "C:\ProgramData\SystemHelper") {
    Write-Host "[!] ALERT: SystemHelper directory found" -ForegroundColor Red
}

# Check Run registry key
$runKey = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
if ($runKey.SystemHelper) {
    Write-Host "[!] ALERT: SystemHelper in Run registry" -ForegroundColor Red
    Write-Host "    Path: $($runKey.SystemHelper)"
}

# Check Defender exclusions
$exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
if ($exclusions -contains "C:\ProgramData\SystemHelper") {
    Write-Host "[!] ALERT: Defender exclusion found" -ForegroundColor Red
}

# Check for suspicious processes
$processes = Get-Process | Where-Object {$_.ProcessName -match "python|systemhelper"}
if ($processes) {
    Write-Host "[!] ALERT: Suspicious processes running" -ForegroundColor Red
    $processes | Format-Table Name, Id, Path
}

# Check for Discord connections from non-Discord processes
$connections = Get-NetTCPConnection -State Established | Where-Object {$_.RemotePort -eq 443}
foreach ($conn in $connections) {
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    if ($proc.ProcessName -notmatch "Discord|chrome|firefox|edge" -and $proc.ProcessName -match "python|systemhelper") {
        Write-Host "[!] ALERT: Suspicious Discord connection" -ForegroundColor Red
        Write-Host "    Process: $($proc.ProcessName) (PID: $($proc.Id))"
    }
}

# Check for keylogger files
if (Test-Path "$env:TEMP\key_log.txt") {
    Write-Host "[!] ALERT: Keylogger file detected" -ForegroundColor Red
}

Write-Host "`n=== Detection Complete ===" -ForegroundColor Cyan
```

---

## 📈 Detection Maturity Model

### Level 1: Basic Detection
- ✅ Antivirus signatures
- ✅ Known file hashes
- ✅ Simple network filtering

### Level 2: Behavioral Detection
- ✅ Registry monitoring
- ✅ Process behavior analysis
- ✅ Network traffic patterns

### Level 3: Advanced Detection
- ✅ EDR integration
- ✅ Memory forensics
- ✅ Machine learning anomaly detection

### Level 4: Threat Hunting
- ✅ Proactive IOC searching
- ✅ Hypothesis-driven investigation
- ✅ Custom detection engineering

---

## 🎯 Recommended Detection Stack

**Minimum:**
- Windows Defender ATP / EDR solution
- Sysmon with proper configuration
- Network monitoring (firewall logs)

**Recommended:**
- SIEM (Splunk, Elastic, Sentinel)
- EDR (CrowdStrike, SentinelOne, Carbon Black)
- Network detection (IDS/IPS)
- User behavior analytics (UBA)

**Optimal:**
- Full detection stack above
- Threat intelligence integration
- Automated response capabilities
- Regular threat hunting exercises

---

## 📚 Additional Resources

### Tools
- **Sysinternals Suite** - Process monitoring
- **Sysmon** - Enhanced logging
- **Volatility** - Memory forensics
- **YARA** - Malware detection rules

### References
- MITRE ATT&CK Framework - T1091, T1059, T1547
- SANS FOR508 - Advanced Incident Response
- Mandiant APT Reports
- Kaspersky Threat Intelligence

---

**Remember:** Detection is an ongoing process. Regularly update detection rules and test effectiveness.
