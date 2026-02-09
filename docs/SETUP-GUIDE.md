# Repository Structure Guide - USB Dropper Research

Complete guide for organizing your USB dropper research repository.

---

## 📁 Recommended Directory Structure

```
usb-dropper-research/
│
├── README.md                          # Main repository overview
├── LICENSE                            # MIT License
├── .gitignore                         # Git ignore patterns
│
├── research/
│   ├── README.md                      # Research overview
│   ├── EP2_Report.pdf                 # Your full academic report
│   ├── ABSTRACT.md                    # Executive summary
│   ├── KEY-FINDINGS.md                # Main research conclusions
│   └── REFERENCES.md                  # Complete bibliography
│
├── payload/
│   ├── README.md                      # Payload documentation
│   ├── systemhelper.py                # Discord C2 payload
│   ├── requirements.txt               # Python dependencies
│   └── COMPILATION.md                 # How to compile (educational)
│
├── dropper/
│   ├── README.md                      # Dropper mechanism docs
│   ├── install.bat                    # USB dropper installer
│   └── MECHANICS.md                   # How the dropper works
│
├── defense/
│   ├── README.md                      # Defense overview
│   ├── DETECTION.md                   # Detection methods
│   ├── PREVENTION.md                  # Prevention strategies
│   ├── INDICATORS.md                  # IOCs and forensic artifacts
│   ├── RESPONSE.md                    # Incident response guide
│   └── yara-rules/
│       └── usb_dropper_discord.yara   # YARA detection rules
│
├── lab-setup/
│   ├── README.md                      # Lab overview
│   ├── ENVIRONMENT.md                 # VM and network setup
│   ├── DISCORD-SETUP.md               # C2 server configuration
│   ├── TESTING.md                     # Safe testing procedures
│   └── CLEANUP.md                     # How to clean up after tests
│
├── docs/
│   ├── TECHNICAL-ANALYSIS.md          # Deep technical dive
│   ├── THREAT-LANDSCAPE.md            # USB threats in 2024
│   ├── CASE-STUDIES.md                # Real-world incidents
│   ├── ETHICS.md                      # Ethical considerations
│   └── FAQ.md                         # Frequently asked questions
│
└── examples/
    ├── screenshots/                   # Demo screenshots
    │   ├── c2-interface.png
    │   ├── dropper-execution.png
    │   └── detection-alert.png
    └── logs/                          # Example log outputs
        ├── defender-log-example.txt
        └── network-traffic-example.pcap
```

---

## 🚀 Setup Instructions

### Step 1: Create Local Repository

```bash
# Create project directory
cd ~/Projects
mkdir usb-dropper-research
cd usb-dropper-research

# Initialize git
git init

# Create directory structure
mkdir -p research payload dropper defense/yara-rules lab-setup docs examples/{screenshots,logs}
```

### Step 2: Add Files

```bash
# Copy main README
cp /path/to/README-usb-dropper.md README.md

# Copy research materials
cp /path/to/EP2_Report_Henning_Bakke.docx research/
# (Convert to PDF if needed)

# Copy payload files
cp /path/to/systemhelper_github.py payload/systemhelper.py
cat > payload/requirements.txt << 'EOF'
discord.py>=2.0.0
requests>=2.31.0
mss>=9.0.1
pynput>=1.7.6
EOF

# Copy dropper script
cp /path/to/install_systemhelper_github.bat dropper/install.bat

# Copy defense documentation
cp /path/to/DETECTION.md defense/
cp /path/to/PREVENTION.md defense/
```

### Step 3: Create .gitignore

```bash
cat > .gitignore << 'EOF'
# Compiled files - NEVER commit binaries!
*.exe
*.dll
*.so
*.dylib
*.pyc
__pycache__/

# Sensitive data
*.key
*.token
config.local
secrets/

# Test artifacts
test-results/
*.pcap
memory-dumps/

# OS files
.DS_Store
Thumbs.db
._*

# IDE files
.vscode/
.idea/
*.swp
*.swo

# Logs
*.log
logs/*.log

# Temporary files
*.tmp
*.bak
*~

# Virtual environments
venv/
env/
.env

# Personal notes (if any)
notes.txt
TODO.md
EOF
```

### Step 4: Create LICENSE

```bash
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2024 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

ADDITIONAL TERMS:

This software is provided for EDUCATIONAL PURPOSES ONLY. The author does not 
condone or support the use of this software for any illegal activities.

By using this software, you agree to:
1. Use only in authorized, controlled environments
2. Comply with all applicable laws and regulations
3. Not use for unauthorized access to computer systems
4. Take full responsibility for any consequences of use

Unauthorized computer access is illegal worldwide and may result in criminal
prosecution, civil liability, and other penalties.
EOF
```

---

## 📝 Content for Individual READMEs

### research/README.md

```markdown
# Research Documentation

This directory contains the complete academic research paper and supporting materials.

## Contents

- **EP2_Report.pdf** - Full academic paper (60+ pages)
- **ABSTRACT.md** - Executive summary
- **KEY-FINDINGS.md** - Main research conclusions
- **REFERENCES.md** - Complete bibliography

## Research Highlights

**Objective:** Demonstrate USB-based malware delivery with Discord C2

**Key Findings:**
- ✅ USB attacks remain highly effective (79% success rate)
- ✅ Discord provides viable C2 infrastructure
- ✅ Modern AV can be bypassed with obfuscation
- ✅ UAC provides limited protection
- ✅ Physical security is critical defense layer

**Tested Against:** Windows 11 with Defender and UAC enabled

## Citation

If you reference this research, please cite:
```
Bakke, H. (2024). Malicious USB: USB Dropper with Discord C2. 
Academic Cybersecurity Research Project. [Institution Name].
```

For full repository information, see [main README](../README.md).
```

### payload/README.md

```markdown
# Payload Documentation

Discord-based C2 payload for educational research.

## ⚠️ WARNING

This is malicious code for EDUCATIONAL PURPOSES ONLY.
- Never compile this outside of research
- Never deploy on unauthorized systems
- Always use in isolated lab environments

## Overview

**File:** `systemhelper.py`  
**Type:** Discord bot C2 client  
**Language:** Python 3.11+  
**Size:** ~200 lines of code

## Capabilities

- Remote shell command execution
- File upload/download
- System information gathering
- Keylogging
- Screenshot capture
- Process enumeration
- Persistence mechanism

## Dependencies

See `requirements.txt` for Python packages:
- discord.py - Discord API integration
- requests - HTTP requests
- mss - Screenshot capture
- pynput - Keyboard monitoring

## Installation (Lab Only!)

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure token
# Edit systemhelper.py and replace YOUR_TOKEN_HERE
```

## Configuration

1. Create Discord bot at https://discord.com/developers
2. Copy bot token
3. Replace `token = "YOUR_TOKEN_HERE"` in code
4. Set up Discord server with proper permissions

## Compilation (Educational)

See `COMPILATION.md` for details on:
- PyInstaller usage
- Obfuscation techniques (PyArmor)
- AV evasion methods

**Remember:** Only compile in isolated lab environments!

For detection methods, see [../defense/DETECTION.md](../defense/DETECTION.md).
```

### dropper/README.md

```markdown
# USB Dropper Mechanism

Documentation for the USB dropper delivery system.

## ⚠️ WARNING

This batch script is malicious code for EDUCATIONAL PURPOSES ONLY.

## Overview

**File:** `install.bat`  
**Type:** Windows batch script  
**Purpose:** Deploy payload and establish persistence

## Functionality

The dropper performs these actions:
1. Creates installation directory (`C:\ProgramData\SystemHelper`)
2. Copies payload to system location
3. Adds registry Run key for persistence
4. Excludes directory from Windows Defender
5. Launches payload

## Technical Details

**Persistence Method:**
```
Registry Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value Name: SystemHelper
Value Data: C:\ProgramData\SystemHelper\systemhelper.exe
```

**AV Evasion:**
```powershell
Add-MpPreference -ExclusionPath "C:\ProgramData\SystemHelper"
```

**Execution Flow:**
```
USB Insertion → User Executes → Dropper Runs → Payload Installed → C2 Callback
```

## Detection

This dropper is detectable by:
- Registry monitoring (Run key modification)
- PowerShell execution monitoring
- Defender exclusion changes
- File creation in ProgramData

See [../defense/DETECTION.md](../defense/DETECTION.md) for details.

## Mitigation

Prevent this attack by:
- USB device control policies
- UAC configured to maximum
- Tamper protection enabled
- Application whitelisting

See [../defense/PREVENTION.md](../defense/PREVENTION.md) for details.
```

---

## ✅ Pre-Commit Checklist

Before committing to GitHub:

- [ ] README.md includes all disclaimers
- [ ] No compiled binaries (.exe files)
- [ ] No real Discord tokens
- [ ] .gitignore configured properly
- [ ] LICENSE file included
- [ ] All sensitive data removed
- [ ] Documentation complete
- [ ] Defense guides included

---

## 📤 Push to GitHub

### Step 1: Create GitHub Repository

```bash
# On GitHub.com:
1. Click "New repository"
2. Name: usb-dropper-research
3. Description: "Educational research on USB dropper malware with Discord C2"
4. Public repository (if you want visibility)
5. DO NOT initialize with README (you already have one)
6. Create repository
```

### Step 2: Connect and Push

```bash
# Add remote
git remote add origin git@github.com:YourUsername/usb-dropper-research.git

# Stage all files
git add .

# Commit
git commit -m "Initial commit: USB dropper malware research project

- Complete academic research paper
- Payload and dropper source code
- Comprehensive defense documentation
- Lab setup guides
- Educational disclaimers"

# Push
git branch -M main
git push -u origin main
```

### Step 3: Add Topics

On GitHub web interface:
```
Repository → About → Settings (gear icon) → Topics

Add:
cybersecurity, malware-research, educational, discord-c2, 
usb-security, red-team, blue-team, threat-research, 
windows-security, incident-response, security-research
```

### Step 4: Create Release

```bash
# Tag first version
git tag -a v1.0.0 -m "Initial Release: USB Dropper Research Project

Complete academic research on USB-based malware delivery with Discord C2.

Includes:
- Full research paper
- Source code (educational)
- Defense documentation
- Lab setup guides"

# Push tag
git push origin v1.0.0
```

Then on GitHub:
- Go to Releases
- Draft new release
- Choose tag v1.0.0
- Add release notes
- Publish release

---

## 🎯 Repository Settings

### Description

```
Academic research on USB dropper malware with Discord C2. 
Educational cybersecurity project demonstrating attack vectors 
and defense strategies. For authorized testing only.
```

### Website (optional)

Link to your portfolio or LinkedIn

### Topics

```
cybersecurity, malware-research, educational, discord-c2, 
usb-security, red-team, blue-team, security-research
```

### Features

- [x] Issues (for questions/discussion)
- [x] Wiki (for additional docs)
- [ ] Projects (not needed)
- [ ] Discussions (optional)

---

## 📊 After Publishing

### Monitor

- ⭐ Star count
- 👁️ Watch activity
- 🔗 Forks
- 💬 Issues/questions

### Maintain

- Respond to issues professionally
- Update documentation as needed
- Add defensive improvements
- Keep disclaimers visible

### Promote (Responsibly)

**LinkedIn Post Example:**
```
📚 Just published my cybersecurity research project!

Completed an academic study on USB-based malware delivery 
mechanisms and Discord C2 infrastructure. The research 
demonstrates modern attack vectors and provides comprehensive 
defense strategies.

Key contributions:
✅ 60+ page research paper
✅ Technical implementation analysis
✅ Detection and prevention guides
✅ Lab setup documentation

This project showcases both offensive and defensive security 
skills, conducted ethically in controlled environments.

🔗 [Link to GitHub]

#Cybersecurity #InfoSec #MalwareResearch #RedTeam #BlueTeam
```

---

## 🎓 Portfolio Integration

### CV/Resume

```
USB Dropper Malware Research | Academic Project | Dec 2024
- Conducted comprehensive research on USB-based attack vectors
- Implemented Discord C2 infrastructure for educational purposes
- Developed detection rules and prevention strategies
- Authored 60+ page technical research paper
- Technologies: Python, PowerShell, Windows Security, Network Analysis

GitHub: https://github.com/YourUsername/usb-dropper-research
```

### Portfolio Website

```html
<div class="project">
  <h3>USB Dropper Malware Research</h3>
  <p>Academic cybersecurity research project examining USB-based 
     malware delivery with Discord C2 infrastructure.</p>
  <ul>
    <li>Comprehensive threat analysis</li>
    <li>Proof-of-concept implementation</li>
    <li>Defense strategy development</li>
  </ul>
  <a href="https://github.com/YourUsername/usb-dropper-research">
    View on GitHub
  </a>
</div>
```

---

## ✨ Success Criteria

Your repository is ready when:

- ✅ All code is documented
- ✅ Defense guides are comprehensive
- ✅ Disclaimers are prominent
- ✅ No sensitive data exposed
- ✅ Structure is clear and professional
- ✅ Ready to show employers

---

**This is professional-grade security research. Structure it accordingly!**
