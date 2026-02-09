# usb-dropper-research
Educational research on USB dropper malware with Discord C2
=======
# USB Dropper Malware Research

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![Educational](https://img.shields.io/badge/purpose-educational-green.svg)

> **⚠️ CRITICAL LEGAL DISCLAIMER**
> 
> This repository contains research materials and proof-of-concept code for **EDUCATIONAL PURPOSES ONLY**. 
> 
> - ❌ **DO NOT** use this code for unauthorized access to computer systems
> - ❌ **DO NOT** deploy this code outside of controlled lab environments
> - ❌ **DO NOT** compile or distribute malicious binaries
> - ✅ **DO** use for learning defensive security techniques
> - ✅ **DO** use for authorized red team assessments with proper authorization
> - ✅ **DO** understand applicable laws in your jurisdiction
>
> **Unauthorized access to computer systems is illegal worldwide.** By accessing this repository, you agree to use this information responsibly and ethically.

---

## 📚 Academic Project Overview

This repository documents an academic research project examining USB-based malware delivery mechanisms and command-and-control (C2) infrastructure for cybersecurity education purposes.

**Project:** Malicious USB - USB Dropper with Discord C2  
**Institution:** Academic Cybersecurity Program  
**Date:** December 2024  
**Grade:** [Completed Successfully]

### 🎯 Research Objectives

1. **Understand attack vectors** - Analyze how USB devices can be weaponized
2. **Study C2 infrastructure** - Examine Discord as a command-and-control platform
3. **Evaluate defensive measures** - Test modern security controls (Defender, UAC)
4. **Document evasion techniques** - Research AV bypass and obfuscation methods
5. **Develop mitigation strategies** - Create defensive recommendations

### 🔬 Research Scope

This project demonstrates:
- ✅ USB-based malware delivery (dropper mechanism)
- ✅ Discord bot C2 infrastructure setup
- ✅ Persistence mechanisms (registry, startup)
- ✅ AV evasion techniques (Defender bypass)
- ✅ UAC bypass methods
- ✅ Remote command execution
- ✅ Data exfiltration capabilities
- ✅ Keylogging and screenshot capture

**Tested Against:** Windows 11 with Microsoft Defender and UAC enabled

---

## 📂 Repository Structure

```
usb-dropper-research/
│
├── README.md                          # This file
├── LICENSE                            # MIT License
│
├── research/
│   ├── EP2_Report.pdf                 # Complete academic research paper
│   ├── ABSTRACT.md                    # Executive summary
│   └── REFERENCES.md                  # Bibliography and citations
│
├── payload/
│   ├── systemhelper.py                # C2 payload source code
│   ├── requirements.txt               # Python dependencies
│   └── README.md                      # Payload documentation
│
├── dropper/
│   ├── install.bat                    # USB dropper installer
│   └── README.md                      # Dropper documentation
│
├── defense/
│   ├── DETECTION.md                   # How to detect this attack
│   ├── PREVENTION.md                  # Mitigation strategies
│   ├── INDICATORS.md                  # IOCs and forensic artifacts
│   └── yara-rules/                    # YARA detection rules
│
├── lab-setup/
│   ├── ENVIRONMENT.md                 # Lab setup instructions
│   ├── DISCORD-SETUP.md               # C2 server configuration
│   └── TESTING.md                     # Safe testing procedures
│
└── docs/
    ├── TECHNICAL-ANALYSIS.md          # Technical deep-dive
    ├── THREAT-LANDSCAPE.md            # USB threats in 2024
    ├── CASE-STUDIES.md                # Real-world incidents
    └── ETHICS.md                      # Ethical considerations
```

---

## 🎓 Educational Value

### What This Research Demonstrates

**Offensive Security Skills:**
- Understanding of malware delivery mechanisms
- C2 infrastructure implementation
- Evasion technique research
- Social engineering attack vectors

**Defensive Security Skills:**
- Detection methodology development
- IOC identification and analysis
- Mitigation strategy formulation
- Forensic artifact recognition

**Professional Competencies:**
- Academic research and documentation
- Technical writing and presentation
- Ethical hacking methodology
- Risk assessment and analysis

---

## 🔒 Threat Landscape Context

### Why USB Attacks Are Relevant in 2024

USB-based malware has seen a **significant resurgence** despite increased network security:

**Statistics:**
- 📈 Europol reported USB dropper malware is on the rise (2024)
- 🎯 79% success rate in social engineering tests (University of Illinois study)
- 🏢 Critical infrastructure remains vulnerable (Mandiant report)
- 🔄 Modern attackers return to physical attack vectors

**Historical Impact:**
- **Stuxnet (2010)** - Compromised Iranian nuclear facilities
- **Agent.BTZ (2008)** - Infected U.S. Department of Defense
- **USB Thief (2016)** - Targeted air-gapped networks
- **Raspberry Robin (2022-2024)** - Active USB worm campaign

### Attack Chain

```
┌─────────────────┐
│ 1. Social       │  Attacker leaves USB drive or gains physical access
│    Engineering  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 2. USB Dropper  │  User executes malicious file from USB
│    Execution    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 3. Persistence  │  Malware installs to system and adds startup entry
│    Mechanism    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 4. C2 Callback  │  Malware connects to Discord C2 server
│    Connection   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 5. Remote       │  Attacker issues commands via Discord
│    Control      │
└─────────────────┘
```

---

## 🛡️ Defense & Detection

### Detection Methods

**Behavioral Indicators:**
- ✅ Unusual Discord API traffic patterns
- ✅ Startup registry modifications
- ✅ Execution from temp directories
- ✅ PowerShell Defender exclusion commands
- ✅ Unexpected outbound HTTPS connections

**File System Indicators:**
- ✅ `C:\ProgramData\SystemHelper\` directory
- ✅ Registry key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHelper`
- ✅ Suspicious executables in ProgramData
- ✅ Keylogger log files in TEMP directory

**Network Indicators:**
- ✅ Discord API endpoints (discord.com, discordapp.com)
- ✅ Persistent HTTPS connections to chat platforms
- ✅ Data exfiltration via Discord CDN
- ✅ IP lookup services (api.ipify.org)

### Prevention Strategies

**Organizational Controls:**
1. **USB Device Management**
   - Implement device control policies
   - Whitelist approved USB devices
   - Disable AutoRun/AutoPlay
   - Monitor USB insertion events

2. **Endpoint Protection**
   - Enable tamper protection
   - Configure UAC to "Always Notify"
   - Use application whitelisting
   - Deploy EDR solutions

3. **Network Controls**
   - Monitor Discord/chat app traffic
   - Block non-business chat applications
   - Implement TLS inspection
   - Use DNS filtering

4. **User Awareness**
   - Security awareness training
   - USB device handling policies
   - Social engineering education
   - Incident reporting procedures

**See [defense/PREVENTION.md](defense/PREVENTION.md) for complete mitigation guide.**

---

## 🔬 Technical Components

### Payload (systemhelper.py)

**Capabilities:**
- Discord bot C2 communication
- Shell command execution
- File upload/download
- System information gathering
- Keylogging
- Screenshot capture
- Process enumeration
- Directory navigation

**Dependencies:**
```python
discord.py      # Discord API integration
requests        # HTTP requests
mss             # Screenshot capture
pynput          # Keyboard monitoring
```

### Dropper (install.bat)

**Functions:**
1. Creates installation directory (`C:\ProgramData\SystemHelper`)
2. Copies payload to system location
3. Adds registry persistence (Run key)
4. Excludes directory from Defender scanning
5. Executes payload

**Evasion Techniques:**
- Uses legitimate Windows directories
- Employs generic naming (`SystemHelper`)
- Leverages PowerShell for privilege escalation
- Minimizes detection surface with hidden windows

---

## 🧪 Lab Setup (Controlled Environment Only)

### Prerequisites

**Hardware:**
- Physical USB drive (minimum 1GB)
- Windows 11 test machine (VM recommended)
- Isolated network or air-gapped environment

**Software:**
- Python 3.11+
- Discord Developer Account
- PyInstaller (for compilation)
- Pyarmor (for obfuscation - optional)

### Safe Testing Environment

```
┌──────────────────────────────────────────┐
│         Isolated Lab Network             │
│                                           │
│  ┌────────────┐       ┌────────────┐    │
│  │  Test VM   │       │  Attacker  │    │
│  │ Windows 11 │◄─────►│  Machine   │    │
│  └────────────┘       └────────────┘    │
│                                           │
│  ✅ No internet access                   │
│  ✅ Snapshotted state                    │
│  ✅ Isolated VLAN                        │
└──────────────────────────────────────────┘
```

**⚠️ CRITICAL:** Never test this on:
- ❌ Production systems
- ❌ Networks with real data
- ❌ Systems you don't own
- ❌ Without proper authorization

**See [lab-setup/ENVIRONMENT.md](lab-setup/ENVIRONMENT.md) for detailed setup.**

---

## 📖 Research Paper

The complete academic research paper is available at [research/EP2_Report.pdf](research/EP2_Report.pdf).

**Paper Contents:**
1. Introduction & Objectives
2. Threat Landscape Analysis
3. Technical Implementation
4. Lab Setup & Testing
5. Results & Analysis
6. Defense Strategies
7. Conclusion & Recommendations
8. References & Appendices

**Key Findings:**
- ✅ USB attacks remain highly effective in 2024
- ✅ Discord provides viable C2 infrastructure
- ✅ Modern AV can be bypassed with obfuscation
- ✅ UAC provides limited protection
- ✅ Physical security is critical defense layer

---

## 🎯 Use Cases

### Legitimate Applications

**Authorized Red Team Assessments:**
- Penetration testing with written authorization
- Security control validation
- Employee awareness training demonstrations
- Physical security assessments

**Academic Research:**
- Cybersecurity education
- Malware analysis courses
- Defensive technique development
- Threat modeling exercises

**Blue Team Development:**
- Detection rule creation
- IOC development
- Forensic analysis training
- Incident response preparation

---

## 🤝 Responsible Disclosure

### Attribution & Credits

This research builds upon publicly available techniques and tools:

**Key References:**
- Discord.py documentation (Rapptz)
- PyArmor obfuscation (Jondy)
- DefenderCheck (matterpreter)
- Various academic papers and security research

**Full bibliography available in:** [research/REFERENCES.md](research/REFERENCES.md)

### Ethical Considerations

This research was conducted:
- ✅ In isolated lab environment
- ✅ On systems owned by researcher
- ✅ Without targeting real organizations
- ✅ For academic purposes only
- ✅ With ethical oversight

**See [docs/ETHICS.md](docs/ETHICS.md) for complete ethical framework.**

---

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| Research Duration | 3 months |
| Lines of Code | ~200 (Python payload) |
| Report Pages | 60+ pages |
| References | 40+ sources |
| Lab Tests | 50+ iterations |
| Evasion Rate | ~70% (against Defender) |

---

## 🔗 Related Resources

### Further Reading

**Books:**
- *Dark Territory: The Secret History of Cyber War* - Fred Kaplan
- *CompTIA Security+ Study Guide* - Various authors

**Research Papers:**
- "USB-based attacks" - Nissim, Yahalom, Elovici (2017)
- "Users Really Do Plug in USB Drives They Find" - Tischer et al. (2016)

**Organizations:**
- Europol Cybercrime Center
- Mandiant Threat Intelligence
- MITRE ATT&CK Framework

---

## 💼 Portfolio Use

This project demonstrates:

**For Cybersecurity Positions:**
- ✅ Offensive security research capabilities
- ✅ Defensive technique development
- ✅ Technical documentation skills
- ✅ Ethical hacking methodology
- ✅ Academic research presentation

**Relevant Job Roles:**
- Penetration Tester / Red Team Operator
- Security Researcher
- Malware Analyst
- SOC Analyst / Blue Team
- Cybersecurity Consultant

---

## ⚖️ Legal Disclaimer

### Important Legal Information

**This software is provided for educational purposes only.**

The author and contributors:
- ❌ Do NOT condone illegal activities
- ❌ Are NOT responsible for misuse
- ❌ Do NOT provide support for malicious use
- ✅ Encourage ethical security research
- ✅ Support responsible disclosure
- ✅ Promote defensive security education

**Before using this code:**
1. Ensure you have explicit written authorization
2. Understand applicable laws in your jurisdiction
3. Use only in isolated, controlled environments
4. Follow ethical hacking guidelines
5. Report vulnerabilities responsibly

**Relevant Laws:**
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws exist in all jurisdictions

**Penalties for misuse can include:**
- Criminal prosecution
- Significant fines
- Imprisonment
- Civil liability

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

**Note:** This license covers the code and documentation. It does NOT grant permission to use this code for unauthorized access to computer systems. All applicable laws must be followed.

---

## 📞 Contact & Reporting

### Security Researchers

If you discover ways to improve defensive measures or have questions about the research:
- Open an issue on GitHub
- Focus on defensive improvements
- Suggest detection mechanisms

### Vulnerability Reporting

If you discover this malware in the wild:
- Report to appropriate authorities
- Contact affected organizations
- Follow responsible disclosure practices

---

## 🙏 Acknowledgments

**Academic Institutions:**
- Cybersecurity program instructors
- Academic advisors and reviewers

**Open Source Community:**
- Discord.py developers
- Python security tool authors
- Security researchers and educators

**Organizations:**
- Europol for threat intelligence reports
- Mandiant for case study documentation
- Academic institutions for research access

---

## ⭐ Star This Repository

If you find this research valuable:
- ⭐ Star the repository
- 🔗 Share with security researchers
- 💬 Contribute defensive improvements
- 📚 Use for educational purposes

---

**Remember:** With great power comes great responsibility. Use this knowledge to defend, not to attack.

**Built for education. Protected by ethics. Defended by law.**

---

*Last Updated: February 2026*
*Repository maintained for educational and archival purposes*
>>>>>>> 9f89c43 (Initial commit: USB Dropper Malware Research)
