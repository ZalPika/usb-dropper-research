# Prevention & Mitigation Guide

Comprehensive strategies to prevent USB dropper attacks and mitigate Discord C2 threats.

---

## 🎯 Prevention Strategy Overview

**Defense in Depth Approach:**

```
┌──────────────────────────────────────────┐
│         Physical Security (Layer 1)      │  Prevent USB access
├──────────────────────────────────────────┤
│         Device Control (Layer 2)         │  Restrict USB devices
├──────────────────────────────────────────┤
│      Endpoint Protection (Layer 3)       │  Detect and block malware
├──────────────────────────────────────────┤
│      Network Controls (Layer 4)          │  Block C2 communications
├──────────────────────────────────────────┤
│      User Awareness (Layer 5)            │  Human firewall
└──────────────────────────────────────────┘
```

---

## 🔒 Layer 1: Physical Security

### Access Controls

**Facility Security:**
- ✅ Badge access to sensitive areas
- ✅ Security cameras monitoring workspaces
- ✅ Visitor escort policies
- ✅ Clean desk policies

**Workstation Security:**
- ✅ Cable locks for laptops
- ✅ USB port locks (physical blockers)
- ✅ Locked USB ports when not in use
- ✅ Monitor screen privacy filters

### USB Port Management

**Hardware Solutions:**
```
Option 1: Physical USB locks (Smart Keeper, Lindy)
Option 2: Epoxy-filled ports (permanent)
Option 3: Port blockers with keys
Option 4: Chassis intrusion detection
```

---

## 💾 Layer 2: USB Device Control

### Group Policy Configuration

**Disable USB Storage Devices:**

```
Group Policy Path:
Computer Configuration
└── Administrative Templates
    └── System
        └── Removable Storage Access

Settings to Enable:
✅ All Removable Storage classes: Deny all access
✅ Removable Disks: Deny read access
✅ Removable Disks: Deny write access
✅ Removable Disks: Deny execute access
```

**Registry Configuration:**
```reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR]
"Start"=dword:00000004

; 3 = Manual, 4 = Disabled
```

**PowerShell Command:**
```powershell
# Disable USB storage
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4

# Verify
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" | Select-Object Start
```

### Device Whitelisting

**USB Device Control Solution Options:**

1. **Microsoft Defender for Endpoint**
   ```
   - Device control policies
   - Hardware ID whitelisting
   - Read-only access mode
   - Audit mode for monitoring
   ```

2. **Third-Party Solutions:**
   - Endpoint Protector
   - DeviceLock
   - GFI EndPointSecurity
   - Symantec Endpoint Protection

**Example Policy:**
```json
{
  "Policy": "USB Device Control",
  "DefaultAction": "Block",
  "Whitelist": [
    {
      "VendorID": "046D",
      "ProductID": "C52B",
      "Description": "Logitech Mouse",
      "Action": "Allow"
    }
  ],
  "Logging": "All"
}
```

---

## 🛡️ Layer 3: Endpoint Protection

### Windows Defender Configuration

**1. Enable Tamper Protection:**
```powershell
Set-MpPreference -DisableTamperProtection $false
```

**2. Configure Real-Time Protection:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false
```

**3. Block Suspicious Scripts:**
```powershell
# Enable ASR rules
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled

# Block credential stealing
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
```

**4. Cloud-Delivered Protection:**
```powershell
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples
```

### User Account Control (UAC)

**Maximum Security Configuration:**
```
secpol.msc → Security Settings → Local Policies → Security Options

Setting: User Account Control: Behavior of the elevation prompt for administrators
Value: Prompt for credentials on the secure desktop

Setting: User Account Control: Detect application installations
Value: Enabled
```

**Registry Configuration:**
```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"ConsentPromptBehaviorAdmin"=dword:00000001
"ConsentPromptBehaviorUser"=dword:00000001
"EnableLUA"=dword:00000001
"PromptOnSecureDesktop"=dword:00000001
```

### Application Whitelisting

**AppLocker Configuration:**

```xml
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="[GUID]" Name="Allow Windows" 
                  Description="Allow all files in Windows folder">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
    
    <FilePathRule Id="[GUID]" Name="Block ProgramData" 
                  Description="Block execution from ProgramData">
      <Conditions>
        <FilePathCondition Path="%PROGRAMDATA%\*"/>
      </Conditions>
      <Exceptions>
        <FilePathCondition Path="%PROGRAMDATA%\Microsoft\*"/>
      </Exceptions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
```

### EDR/XDR Solutions

**Recommended Features:**
- ✅ Behavioral analysis
- ✅ Memory scanning
- ✅ Script execution monitoring
- ✅ Network traffic inspection
- ✅ Automated response capabilities

**Leading Solutions:**
- CrowdStrike Falcon
- SentinelOne
- Microsoft Defender for Endpoint
- Carbon Black
- Palo Alto Cortex XDR

---

## 🌐 Layer 4: Network Controls

### DNS Filtering

**Block Discord Domains:**
```
Blocked Domains:
- discord.com
- discordapp.com
- discord.gg
- cdn.discordapp.com
- gateway.discord.gg

Exceptions (if needed for business):
- Allow only from approved devices/users
- Require authentication
```

**DNS Filtering Solutions:**
- Cisco Umbrella
- Cloudflare Gateway
- NextDNS
- Pi-hole (for small networks)

### Firewall Rules

**Block Non-Business Chat Applications:**

```
Rule: Block Discord
Direction: Outbound
Action: Block
Destination:
  - discord.com (443, 80)
  - discordapp.com (443, 80)
Application: * (all except approved browsers)
```

**Allow List Approach:**
```
1. Block all outbound HTTPS by default
2. Whitelist approved applications
3. Whitelist approved destinations
4. Log all blocked attempts
```

### TLS Inspection

**Decrypt and Inspect HTTPS:**

```
Benefits:
✅ See encrypted C2 traffic
✅ Detect malware in TLS
✅ Block data exfiltration

Considerations:
⚠️  Privacy concerns
⚠️  Certificate management
⚠️  Performance impact
⚠️  Bypass for banking/healthcare
```

**Implementation:**
- Palo Alto Networks NGFW
- Cisco Firepower
- Zscaler Internet Access
- Forcepoint Web Security

### Network Segmentation

**Isolate Critical Systems:**

```
Network Design:
┌────────────────┐
│ Guest Network  │ VLAN 10 (Internet only)
├────────────────┤
│ User Network   │ VLAN 20 (Limited access)
├────────────────┤
│ Server Network │ VLAN 30 (No internet)
├────────────────┤
│ Management     │ VLAN 99 (Admin only)
└────────────────┘
```

---

## 👥 Layer 5: User Awareness & Training

### Security Awareness Program

**Training Topics:**
1. **USB Device Risks**
   - Never plug in found USB devices
   - Only use company-provided USBs
   - Report suspicious devices

2. **Social Engineering**
   - "Free USB" drops are attacks
   - Verify sender identity
   - Think before clicking

3. **Incident Reporting**
   - How to report suspicious activity
   - No-blame culture
   - Quick response importance

### Phishing Simulations

**USB Drop Simulation:**
```
Scenario: Place deactivated USBs in parking lot
Label: "Salary Information 2024" or "Confidential"
Track: How many employees plug them in
Train: Those who failed the test
```

### Security Policies

**USB Policy Example:**

```
Company USB Device Policy

1. Prohibition
   - Employees MAY NOT use personal USB devices
   - Only company-issued USBs are permitted
   - Found USBs must be reported to IT

2. Approved Usage
   - Request USB from IT department
   - USB will be scanned before issuance
   - Return USB when no longer needed

3. Violations
   - First offense: Written warning
   - Second offense: Disciplinary action
   - Intentional violation: Termination

4. Exceptions
   - Must be approved by CISO
   - Documented in writing
   - Regular review required
```

---

## 🚨 Incident Response Plan

### Detection Phase

**1. Alert Triggered**
```
Indicator: USB device connected
Action:
- Capture device details
- Identify user
- Check if approved device
```

**2. Potential Infection**
```
Indicator: Suspicious process or network traffic
Action:
- Isolate workstation
- Capture memory dump
- Preserve evidence
```

### Containment Phase

**Immediate Actions:**
```powershell
# Disconnect from network
Disable-NetAdapter -Name "*"

# Kill suspicious processes
Stop-Process -Name "systemhelper" -Force
Stop-Process -Name "python*" -Force

# Block network at firewall
# Remove machine from network VLAN
```

### Eradication Phase

**Removal Steps:**

1. **Safe Mode Boot:**
   ```
   - Boot to Safe Mode with Networking
   - Prevents malware autostart
   ```

2. **Remove Persistence:**
   ```powershell
   # Remove registry entry
   Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SystemHelper"
   
   # Remove Defender exclusion
   Remove-MpPreference -ExclusionPath "C:\ProgramData\SystemHelper"
   ```

3. **Delete Files:**
   ```powershell
   # Remove installation directory
   Remove-Item -Path "C:\ProgramData\SystemHelper" -Recurse -Force
   
   # Clean temp files
   Remove-Item -Path "$env:TEMP\*.txt" -Force
   Remove-Item -Path "$env:TEMP\*.png" -Force
   ```

4. **Full Scan:**
   ```powershell
   # Run Windows Defender full scan
   Start-MpScan -ScanType FullScan
   ```

### Recovery Phase

**System Restoration:**
```
Option 1: Clean reimaging (recommended)
- Backup user data (scan first!)
- Reimage system from known-good source
- Restore data after verification

Option 2: In-place cleanup
- Full antivirus scan
- Rootkit scan (GMER, Malwarebytes)
- Verify no persistence
- Monitor for 7 days
```

### Post-Incident

**Documentation:**
- Timeline of events
- IOCs discovered
- Actions taken
- Lessons learned

**Follow-Up:**
- Update detection rules
- Improve preventive controls
- User retraining if needed
- Review policy effectiveness

---

## 🔧 Hardening Checklist

### Windows 11 Security Hardening

**System Level:**
- [ ] Enable BitLocker encryption
- [ ] Configure Windows Defender optimally
- [ ] Enable Credential Guard
- [ ] Configure UAC to maximum
- [ ] Disable unnecessary services
- [ ] Enable Windows Firewall
- [ ] Configure LAPS for admin passwords

**User Level:**
- [ ] Use standard user accounts (not admin)
- [ ] Require strong passwords
- [ ] Enable MFA for all accounts
- [ ] Disable guest accounts
- [ ] Lock screen after 5 minutes

**Application Level:**
- [ ] Keep all software updated
- [ ] Remove unnecessary software
- [ ] Configure application whitelisting
- [ ] Disable macros by default
- [ ] Use sandboxing for browsers

**Network Level:**
- [ ] Disable SMBv1
- [ ] Enable network-level authentication
- [ ] Configure host-based firewall
- [ ] Disable unnecessary network protocols
- [ ] Use VPN for remote access

---

## 📊 Effectiveness Measurement

### Key Performance Indicators (KPIs)

**Detection Metrics:**
| Metric | Target | Measurement |
|--------|--------|-------------|
| Time to Detect | < 5 minutes | SIEM alerting |
| Detection Rate | > 95% | Purple team testing |
| False Positives | < 5% | SOC ticket analysis |

**Prevention Metrics:**
| Metric | Target | Measurement |
|--------|--------|-------------|
| USB Compliance | 100% | Device inventory |
| Patch Compliance | > 95% | Vulnerability scan |
| Training Completion | 100% | LMS tracking |

### Regular Testing

**Purple Team Exercises:**
```
Frequency: Quarterly
Scope:
- USB drop test
- Social engineering
- Network controls
- Detection rules
- Response procedures

Outcome:
- Update defenses
- Retrain staff
- Improve processes
```

---

## 🎯 Quick Win Recommendations

### Immediate Actions (< 1 day)

1. **Enable Tamper Protection**
   ```powershell
   Set-MpPreference -DisableTamperProtection $false
   ```

2. **Configure UAC Maximum**
   ```
   Set to "Always Notify"
   ```

3. **Block Discord (if not business-critical)**
   ```
   DNS filtering or firewall rule
   ```

### Short-Term Actions (< 1 week)

1. **Deploy USB device control**
2. **Configure attack surface reduction rules**
3. **Enable cloud-delivered protection**
4. **Implement network monitoring**

### Long-Term Actions (< 1 month)

1. **Full EDR deployment**
2. **Security awareness program**
3. **Incident response plan**
4. **Regular security assessments**

---

## 📚 Additional Resources

### Microsoft Resources
- **Windows Security Baselines**
- **Defender for Endpoint documentation**
- **Attack Surface Reduction rules guide**

### Industry Standards
- **NIST Cybersecurity Framework**
- **CIS Controls**
- **SANS Critical Controls**

### Training
- **SANS SEC401** - Security Essentials
- **SANS SEC504** - Incident Handling
- **CompTIA Security+**

---

**Remember:** No single control is perfect. Defense in depth is essential for effective protection.

**Prevention is cheaper than detection. Detection is cheaper than incident response.**
