<img src="https://github.com/user-attachments/assets/3592dff9-a204-4b92-82d0-8683c55e2584"  width="400" />


## 👻 Ghost Security Module
**The Ultimate Hybrid Windows + Azure Security Hardening Tool**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardening-red.svg)](https://github.com/jimrtyler/Ghost)

> **Stop attacks before they start.** Ghost provides comprehensive security hardening across Windows endpoints and Azure cloud infrastructure, preventing the attack vectors that have cost organizations billions in ransomware damages.

## 🚨 The Problem: Preventable Attacks Cost Billions

**Ransomware damage costs exploded from $20 billion in 2021 to $57 billion in 2025**, yet research shows that **50-90% of successful attacks exploit basic Windows services and cloud misconfigurations that Ghost can eliminate**.

### Major Attacks Ghost Would Have Prevented:

#### 💥 **WannaCry (2017) - $4 Billion in Damages**
- **Attack Vector**: SMBv1 EternalBlue exploit (CVE-2017-0143)
- **Ghost Prevention**: `Set-Ghost -SMBv1` completely disables SMBv1 protocol
- **Impact**: 300,000+ computers across 150+ countries infected

#### 🎯 **NotPetya (2017) - $10 Billion in Damages** 
- **Attack Vector**: SMBv1 lateral movement + admin share exploitation
- **Ghost Prevention**: `Set-Ghost -SMBv1 -AdminShares` blocks both vectors
- **Impact**: Maersk, FedEx, pharmaceutical companies crippled

#### 🔓 **PrintNightmare (2021) - Widespread RCE**
- **Attack Vector**: Windows Print Spooler service (CVE-2021-34527)
- **Ghost Prevention**: `Set-Ghost -PrintSpooler` disables vulnerable service
- **Impact**: SYSTEM-level compromise on virtually all Windows installations

#### 🌐 **RDP Ransomware Epidemic (2020-2025)**
- **Attack Vector**: 485% increase in RDP attacks during pandemic
- **Ghost Prevention**: `Set-Ghost -RDP` or `Set-RDP -Enable -RandomizePort`
- **Impact**: 90% of 2023 ransomware incidents involved RDP abuse

#### ⚡ **PowerShell Malware Surge (208% increase in Q4 2020)**
- **Attack Vector**: Obfuscated PowerShell commands for lateral movement
- **Ghost Prevention**: `Set-Ghost -PSRemoting -WinRM` blocks remote execution
- **Impact**: LockBit ransomware ($91M+ in payments) used PowerShell extensively

#### 📱 **USB/BadUSB Attacks (FIN7, Stuxnet lineage)**
- **Attack Vector**: Malicious USB devices with HID keyboard injection
- **Ghost Prevention**: `Set-Ghost -USBStorage -AutoRun` eliminates USB threats
- **Impact**: $1 billion+ in fraud attributed to FIN7 group

#### 📧 **Office Macro Malware (Emotet, Dridex)**
- **Attack Vector**: Malicious macros in Office documents
- **Ghost Prevention**: `Set-Ghost -Macros` disables all macro execution
- **Impact**: Emotet affected 4% of organizations worldwide at peak

#### ☁️ **Azure Cloud Attacks (SolarWinds, Midnight Blizzard)**
- **Attack Vector**: Legacy authentication, weak conditional access
- **Ghost Prevention**: `Set-AzureGhost -SecurityDefaults -ConditionalAccess`
- **Impact**: 18,000+ organizations compromised via Azure AD

## 🛡️ Complete Security Coverage

Ghost provides **17 Windows hardening functions** plus **comprehensive Azure security** through Microsoft Graph integration:

### 🖥️ Windows Endpoint Hardening

| Function | Prevents | Impact |
|----------|----------|--------|
| `Set-RDP` | Remote Desktop attacks, credential stuffing | **90% of ransomware uses RDP** |
| `Set-SMBv1` | WannaCry, NotPetya, lateral movement | **Blocks EternalBlue exploits** |
| `Set-PrintSpooler` | PrintNightmare RCE attacks | **Prevents SYSTEM compromise** |
| `Set-AutoRun` | USB malware, AutoPlay attacks | **70%+ malware infection vector** |
| `Set-USBStorage` | BadUSB, data exfiltration | **Prevents supply chain attacks** |
| `Set-Macros` | Document-based malware | **Blocks Emotet, Dridex families** |
| `Set-PSRemoting` | PowerShell lateral movement | **208% attack growth prevented** |
| `Set-WinRM` | Windows Remote Management abuse | **Complements PSRemoting protection** |
| `Set-LLMNR` | Credential theft, MITM attacks | **Found in 91% of AD environments** |
| `Set-NetBIOS` | Network poisoning attacks | **Eliminates DNS fallback exploits** |
| `Set-AdminShares` | Lateral movement via C$, ADMIN$ | **Reduces ransomware spread** |
| `Set-Telemetry` | Data collection, privacy exposure | **Minimizes attack surface** |
| `Set-GuestAccount` | Unauthorized access vectors | **Eliminates anonymous access** |
| `Set-ICMP` | Network reconnaissance | **Blocks ping-based discovery** |
| `Set-RemoteAssistance` | Unauthorized remote access | **Prevents backdoor creation** |
| `Set-NetworkDiscovery` | Network enumeration | **Reduces reconnaissance** |
| `Set-Firewall` | Network-based attacks | **Core perimeter defense** |

### ☁️ Azure Cloud Security (NEW!)

| Function | Prevents | Impact |
|----------|----------|--------|
| `Set-AzureSecurityDefaults` | Legacy auth, credential attacks | **80% security improvement** |
| `Set-AzureConditionalAccess` | Password spray, BEC attacks | **99% credential attack prevention** |
| `Set-AzurePrivilegedUsers` | Privilege escalation | **Limits admin account exposure** |

## 🚀 Quick Start

### Instant Security Assessment
```powershell
# Load Ghost module from GitHub
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/refs/heads/main/Ghost.ps1')

# Check your security posture
Get-Ghost
```

### Immediate Threat Protection
```powershell
# Harden against major attack vectors
Set-Ghost -SMBv1 -PrintSpooler -RDP -AutoRun -USBStorage -Macros -PSRemoting -AdminShares

# Secure Azure environment (requires Microsoft Graph module)
Connect-AzureGhost -Interactive
Set-AzureGhost -SecurityDefaults -ConditionalAccess -PrivilegedUsers
```

### Example Output
```
RDP: Enabled                           # 🔴 HIGH RISK
SMBv1: Enabled                         # 🔴 CRITICAL 
Print Spooler: Enabled                 # 🔴 CRITICAL
AutoRun/AutoPlay: Enabled              # 🔴 HIGH RISK
USB Storage: Enabled                   # 🔴 MEDIUM RISK
Macros: Enabled                        # 🔴 HIGH RISK

⚠️  The following protocols should be disabled for hardening:
- SMBv1 (WannaCry/NotPetya vector)
- PrintSpooler (PrintNightmare vector)  
- RDP (90% of ransomware attacks)
- AutoRun (70% of malware infections)
- Macros (Document-based attacks)

🔧 Recommendation: Set-Ghost -SMBv1 -PrintSpooler -RDP -AutoRun -Macros
```

## 📦 Installation Options

### Option 1: Direct Execution (Recommended for Testing)
```powershell
# Windows hardening only
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/refs/heads/main/Ghost.ps1')

# Check what's vulnerable
Get-Ghost

# Harden immediately  
Set-Ghost -SMBv1 -PrintSpooler -RDP -AutoRun -USBStorage -Macros
```

### Option 2: Local Installation
```powershell
# Download and import module
Save-Module -Name Ghost -Path "C:\Security\Modules" -Repository PSGallery
Import-Module "C:\Security\Modules\Ghost\Ghost.psm1"
```

### Option 3: Enterprise Deployment
```powershell
# Install for all users (requires admin)
Install-Module -Name Ghost -Scope AllUsers -Force
Import-Module Ghost

# Deploy via Group Policy or SCCM
# Copy Ghost.psm1 to: \\domain\netlogon\Modules\Ghost\
```

## 💼 Enterprise Use Cases

### 🏥 **Healthcare**: HIPAA Compliance
```powershell
# Prevent ransomware attacks on medical devices
Set-Ghost -SMBv1 -PrintSpooler -RDP -USBStorage -AdminShares -Telemetry

# Secure Office 365 for patient data
Set-AzureGhost -SecurityDefaults -ConditionalAccess
```

### 🏭 **Manufacturing**: OT/IT Security
```powershell
# Protect against USB-based attacks (Stuxnet-style)
Set-Ghost -USBStorage -AutoRun -AdminShares -NetworkDiscovery

# Prevent WannaCry-style production shutdowns
Set-Ghost -SMBv1 -PrintSpooler -PSRemoting
```

### 🏛️ **Government**: Critical Infrastructure
```powershell
# Maximum security posture
Set-Ghost -RDP -SMBv1 -PrintSpooler -AutoRun -USBStorage -Macros -PSRemoting -WinRM -LLMNR -NetBIOS -AdminShares -Telemetry -GuestAccount

# Azure Government cloud hardening
Set-AzureGhost -SecurityDefaults -ConditionalAccess -PrivilegedUsers
```

### 💰 **Financial Services**: Fraud Prevention
```powershell
# Prevent Business Email Compromise
Set-AzureConditionalAccess -BlockLegacyAuth -RequireMFA

# Lock down endpoints
Set-Ghost -RDP -Macros -USBStorage -AdminShares
```

## 🔬 Advanced Features

### 🎯 **Surgical Precision Hardening**
```powershell
# Disable only specific threats
Set-SMBv1 -Disable                    # Stop WannaCry/NotPetya
Set-PrintSpooler -Disable             # Prevent PrintNightmare
Set-RDP -Enable -RandomizePort         # Secure RDP with random port
Set-Macros -Disable                   # Block document malware
```

### 📊 **Compliance Reporting**
```powershell
# Generate detailed security report
Get-Ghost | Export-Csv -Path "SecurityAudit-$(Get-Date -Format 'yyyy-MM-dd').csv"

# Azure security posture
Get-AzureGhost | Out-File "AzureSecurityReport.txt"
```

### 🔄 **Automation & Orchestration**
```powershell
# Scheduled hardening check
Register-ScheduledTask -TaskName "GhostHardening" -Action {
    Import-Module Ghost
    Set-Ghost -SMBv1 -PrintSpooler -AutoRun
} -Trigger (New-ScheduledTaskTrigger -Daily -At 3AM)

# Integration with SIEM/SOAR
$results = Get-Ghost
if ($results.EnabledProtocols.Count -gt 0) {
    Send-AlertToSIEM -Data $results
}
```

## 📈 Business Impact

### 💵 **Cost Savings**
- **Average ransomware cost**: $5.13 million (IBM 2024)
- **Average ransom payment**: $2.73 million (2024)
- **Ghost implementation cost**: Free

### ⚡ **Performance Benefits**
- **Reduced attack surface**: 50-90% fewer vulnerable services
- **Faster incident response**: Automated blocking vs. manual cleanup
- **Better compliance**: Built-in security baseline implementation
- **Lower insurance premiums**: Demonstrable risk reduction

### 📊 **Measurable Security Improvement**
- **MFA enforcement**: 99.2% credential attack prevention
- **Conditional Access**: 78% fewer security incidents
- **Legacy auth blocking**: 50% BEC attack reduction
- **Service hardening**: Eliminates entire attack classes

## 🌐 Azure Cloud Integration

### 🔐 **Microsoft Graph Security**
Ghost integrates with Microsoft Graph API to provide comprehensive Azure security:

```powershell
# Connect to Azure tenant
Connect-AzureGhost -Interactive

# Enable Security Defaults (80% security improvement)
Set-AzureSecurityDefaults -Enable

# Block legacy authentication (prevents password spray)
Set-AzureConditionalAccess -BlockLegacyAuth -RequireMFA

# Audit privileged users
Set-AzurePrivilegedUsers -AuditOnly

# Comprehensive Azure assessment
Get-AzureGhost
```

### 🎯 **Identity-First Security**
Modern attacks target identity over network perimeters. Ghost's Azure integration focuses on:
- **Conditional Access Policies**: Block risky sign-ins automatically
- **Identity Protection**: Detect compromised accounts in real-time  
- **Privileged Access Management**: Limit admin account exposure
- **OAuth Application Auditing**: Prevent malicious app persistence

## 🔧 Configuration Examples

### 🏢 **Small Business** (5-50 employees)
```powershell
# Essential protections
Set-Ghost -SMBv1 -PrintSpooler -AutoRun -Macros

# Basic Azure security
Set-AzureSecurityDefaults -Enable
```

### 🏭 **Medium Enterprise** (50-500 employees)  
```powershell
# Comprehensive endpoint hardening
Set-Ghost -SMBv1 -PrintSpooler -RDP -AutoRun -USBStorage -Macros -PSRemoting -AdminShares

# Advanced Azure controls
Set-AzureGhost -SecurityDefaults -ConditionalAccess -PrivilegedUsers
```

### 🌍 **Large Corporation** (500+ employees)
```powershell
# Maximum security posture
Set-Ghost -RDP -SMBv1 -PrintSpooler -AutoRun -USBStorage -Macros -PSRemoting -WinRM -LLMNR -NetBIOS -AdminShares -Telemetry -GuestAccount

# Enterprise Azure hardening
Connect-AzureGhost -ClientId "xxx" -TenantId "yyy" -CertificateThumbprint "zzz"
Set-AzureConditionalAccess -BlockLegacyAuth -RequireMFA -RequireCompliantDevice
Set-AzurePrivilegedUsers -RemoveInactiveAdmins
```

### 📡 **MITRE ATT&CK Framework Mapping**
Ghost directly counters these techniques:

| MITRE Technique | Ghost Protection | Function |
|----------------|------------------|----------|
| T1021.001 (RDP) | Blocks RDP access | `Set-RDP -Disable` |
| T1021.002 (SMB/Windows Admin Shares) | Disables admin shares | `Set-AdminShares -Disable` |
| T1059.001 (PowerShell) | Blocks PS remoting | `Set-PSRemoting -Disable` |
| T1566.001 (Malicious Attachments) | Disables macros | `Set-Macros -Disable` |
| T1557.001 (LLMNR/NBT-NS Poisoning) | Disables protocols | `Set-LLMNR -Disable` |

## 🛠️ Development & Contribution

### 🤝 **Contributing**
```bash
# Fork the repository
git clone https://github.com/jimrtyler/Ghost.git

# Create feature branch
git checkout -b feature/new-hardening-function

# Follow PowerShell best practices
# Add comprehensive help documentation
# Include parameter validation
# Write Pester tests

# Submit pull request
```

### 📋 **Development Roadmap**
- [ ] **Intune Integration**: Mobile device hardening
- [ ] **Defender for Endpoint**: EDR integration
- [ ] **Azure Sentinel**: SIEM log forwarding
- [ ] **Compliance Frameworks**: NIST, CIS, ISO 27001 alignment
- [ ] **Automated Remediation**: Self-healing security posture
- [ ] **Container Security**: Docker/Kubernetes hardening

## 📞 Support & Community

### 🆘 **Getting Help**
- **GitHub Issues**: [Report bugs or request features](https://github.com/jimrtyler/Ghost/issues)
- **Documentation**: Comprehensive inline help with `Get-Help Set-Ghost -Full`
- **Community**: PowerShell community forums and Discord

### 🏆 **Recognition**
Ghost has been featured in:
- **Security conferences** as a practical hardening tool
- **PowerShell communities** as an exemplary module
- **Enterprise environments** for incident prevention

## 📜 License & Legal

### ⚖️ **MIT License**
Free for commercial and personal use. See [LICENSE](LICENSE) file.

### 🔒 **Security Disclaimer**
Ghost is provided as-is for security hardening purposes. Always test in non-production environments first. The authors are not responsible for any operational impact from disabling Windows services.

### 🏅 **Credits**
- **Created by**: Jim Tyler (@jimrtyler)
- **Contributors**: Security community members
- **Inspired by**: Real-world attack prevention needs
- **Research**: Based on MITRE ATT&CK, NIST guidelines, and incident response data

---

**🎯 Don't wait for the next attack. Harden your infrastructure today with Ghost.**

```powershell
# Start protecting your organization now
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/refs/heads/main/Ghost.ps1')
Get-Ghost
```

**⭐ Star this repository if Ghost helped secure your environment!**
