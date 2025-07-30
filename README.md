<img src="https://github.com/user-attachments/assets/3592dff9-a204-4b92-82d0-8683c55e2584"  width="400" />

## 👻 Ghost Security Module
**Practical Windows + Azure Security Hardening Tool**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardening-red.svg)](https://github.com/jimrtyler/Ghost)

> **Reduce your attack surface quickly and effectively.** Ghost provides practical security hardening across Windows endpoints and Azure cloud infrastructure, addressing common attack vectors with a simple, verifiable approach.

## ⚠️ Important Disclaimers

- **No Security Guarantees**: Ghost reduces attack surface but cannot prevent all attacks or guarantee security
- **Test First**: Always test in non-production environments to assess business impact
- **Operational Impact**: Some functions disable services that may be required for business operations
- **Part of Defense Strategy**: Ghost is one component of a comprehensive security approach
- **Professional Consultation**: Consider consulting security professionals for enterprise deployments
- **Your Responsibility**: You are responsible for understanding the impact of changes in your environment

## 📊 The Reality: Preventable Attack Vectors

According to security research from NIST, FBI, and Microsoft, many successful attacks exploit commonly enabled Windows services and cloud misconfigurations that can be addressed through basic hardening measures.

### Historical Attack Vectors Ghost Can Address:

#### 💥 **SMBv1-Based Attacks (WannaCry, NotPetya)**
- **Attack Vector**: SMBv1 EternalBlue exploit (CVE-2017-0143)
- **Ghost Mitigation**: `Set-Ghost -SMBv1` disables SMBv1 protocol
- **Context**: Microsoft recommended disabling SMBv1 in 2014, yet many systems remained vulnerable

#### 🎯 **Administrative Share Exploitation**
- **Attack Vector**: Lateral movement via C$, ADMIN$ shares in post-compromise scenarios
- **Ghost Mitigation**: `Set-Ghost -AdminShares` disables administrative shares
- **Context**: Commonly observed in ransomware lateral movement patterns

#### 🌐 **RDP-Based Attacks**
- **Attack Vector**: Credential stuffing, brute force attacks on Remote Desktop
- **Ghost Options**: `Set-Ghost -RDP` (disable) or `Set-RDP -Enable -RandomizePort` (secure)
- **Context**: FBI reports show significant increase in RDP attacks, particularly since 2020

#### ⚡ **PowerShell Remoting Abuse**
- **Attack Vector**: Lateral movement using PowerShell remoting capabilities
- **Ghost Mitigation**: `Set-Ghost -PSRemoting -WinRM` blocks remote execution vectors
- **Context**: Frequently observed in advanced persistent threat campaigns

#### 📱 **USB-Based Malware**
- **Attack Vector**: AutoRun malware, malicious USB devices with payload delivery
- **Ghost Mitigation**: `Set-Ghost -USBStorage -AutoRun` prevents USB-based infection vectors
- **Context**: Remains effective attack vector against unprepared systems

#### 📧 **Macro-Based Malware**
- **Attack Vector**: Malicious macros in Office documents as malware delivery mechanism
- **Ghost Mitigation**: `Set-Ghost -Macros` disables macro execution
- **Context**: Common delivery mechanism for trojans and ransomware families

#### ☁️ **Azure Authentication Attacks**
- **Attack Vector**: Legacy authentication protocols, weak conditional access policies
- **Ghost Mitigation**: `Set-AzureGhost -SecurityDefaults -ConditionalAccess`
- **Context**: Password spray and credential stuffing attacks against cloud services

## 🛡️ Security Coverage

Ghost provides **16 Windows hardening functions** plus **comprehensive Azure security** through Microsoft Graph integration:

### 🖥️ Windows Endpoint Hardening

| Function | Addresses | Operational Impact |
|----------|-----------|-------------------|
| `Set-RDP` | Remote Desktop attacks | ⚠️ Blocks remote desktop access |
| `Set-SMBv1` | Legacy SMB exploits | ✅ Minimal impact (legacy protocol) |
| `Set-AutoRun` | USB malware, AutoPlay attacks | ⚠️ May affect legitimate removable media |
| `Set-USBStorage` | USB-based attacks, data exfiltration | ⚠️ Prevents all USB storage devices |
| `Set-Macros` | Document-based malware | ⚠️ Disables Office macro functionality |
| `Set-PSRemoting` | PowerShell lateral movement | ⚠️ Blocks PowerShell remoting |
| `Set-WinRM` | Windows Remote Management abuse | ⚠️ Blocks WinRM-based management |
| `Set-LLMNR` | Credential theft, MITM attacks | ✅ Minimal impact (fallback protocol) |
| `Set-NetBIOS` | Network poisoning attacks | ✅ Minimal impact (legacy protocol) |
| `Set-AdminShares` | Lateral movement via shares | ⚠️ May affect some admin tools |
| `Set-Telemetry` | Data collection, privacy exposure | ✅ Minimal operational impact |
| `Set-GuestAccount` | Unauthorized access vectors | ✅ Minimal impact (rarely used) |
| `Set-ICMP` | Network reconnaissance | ⚠️ Blocks ping functionality |
| `Set-RemoteAssistance` | Unauthorized remote access | ⚠️ Disables remote assistance features |
| `Set-NetworkDiscovery` | Network enumeration | ⚠️ May affect network browsing |
| `Set-Firewall` | Network-based attacks | ⚠️ Core security control - test carefully |

### ☁️ Azure Cloud Security

| Function | Addresses | Requirements |
|----------|-----------|-------------|
| `Set-AzureSecurityDefaults` | Legacy auth, basic attacks | Azure AD tenant |
| `Set-AzureConditionalAccess` | Advanced authentication attacks | Azure AD Premium |
| `Set-AzurePrivilegedUsers` | Privilege escalation | Azure AD Premium |

## 🚀 Quick Start

### Security Assessment
```powershell
# Load Ghost module from GitHub
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/refs/heads/main/Ghost.ps1')

# Check your current security posture
Get-Ghost
```

### Basic Hardening (Test First!)
```powershell
# Address common attack vectors with minimal business impact
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -GuestAccount

# For environments where USB and macros aren't needed
Set-Ghost -USBStorage -AutoRun -Macros

# Deploy via Group Policy for domain-wide enforcement
Set-Ghost -SMBv1 -AutoRun -Macros -GroupPolicy

# Deploy via Intune for cloud-managed devices
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -ICMP -Intune

# Secure Azure environment (requires Microsoft Graph module)
Connect-AzureGhost -Interactive
Set-AzureGhost -SecurityDefaults
```

### Example Output
```
RDP: Enabled                           # Consider impact before disabling
SMBv1: Enabled                         # Safe to disable (legacy protocol)
AutoRun/AutoPlay: Enabled              # Consider business USB usage
USB Storage: Enabled                   # Evaluate data transfer needs
Macros: Enabled                        # Assess Office macro requirements

📋 Protocols that can typically be safely disabled:
- SMBv1 (legacy protocol, security risk)
- LLMNR (fallback protocol, rarely needed)
- NetBIOS (legacy protocol)
- Telemetry (privacy enhancement)

⚠️ Protocols requiring business impact assessment:
- RDP (remote access method)
- USB Storage (may affect legitimate usage)
- Macros (may affect Office workflows)

🔧 Suggested safe start: Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry
```

## 🏢 Deployment Options: Choose Your Approach

Ghost provides **three deployment methods** to match your environment and needs:

### **🚀 Direct Configuration (Ghost Classic)**
```powershell
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry
```
- ✅ **5 minutes** to deploy and verify
- ✅ Works on any Windows system (domain, workgroup, cloud)
- ✅ Immediate results and verification
- ✅ No licensing or infrastructure requirements
- ✅ Perfect for incident response and testing

### **🏛️ Group Policy Deployment**
```powershell
Set-Ghost -RDP -SMBv1 -AutoRun -Macros -GroupPolicy
```
- ✅ **Domain-wide enforcement** with centralized management
- ✅ Automatic reapplication and inheritance
- ✅ Built-in audit trails and compliance reporting
- ✅ Prevents local administrator override
- ✅ Ideal for traditional Active Directory environments

### **☁️ Microsoft Intune Deployment**
```powershell
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -ICMP -Intune
```
- ✅ **Cloud-scale deployment** to thousands of devices
- ✅ Modern device management for Azure AD joined systems
- ✅ Cross-platform support (Windows, mobile devices)
- ✅ Built-in compliance dashboards and reporting
- ✅ Perfect for modern, cloud-first organizations

### **📊 Deployment Method Comparison**

| Feature | Direct | Group Policy | Intune |
|---------|--------|-------------|--------|
| **Setup Time** | 5 minutes | 2-4 hours | 1-2 hours |
| **Expertise Required** | Basic PowerShell | GP Administration | Intune Management |
| **Infrastructure** | None | Active Directory | Microsoft 365/Intune |
| **Device Coverage** | Single device | Domain computers | Cloud-managed devices |
| **Enforcement** | One-time | Continuous | Continuous |
| **Rollback** | Individual functions | Remove GP objects | Delete policies |
| **Audit Trail** | Manual logging | GP logs | Intune compliance |
| **Licensing Cost** | Free | Windows licensing | Intune licensing |

### **🎯 When to Use Each Approach:**

**Direct Configuration is ideal for:**
- Small businesses (5-50 endpoints)
- Immediate security improvements needed
- Mixed environments (domain + workgroup + cloud)
- Incident response scenarios
- Proof-of-concept implementations
- Systems without policy infrastructure

**Group Policy is best for:**
- Traditional Active Directory environments
- Organizations with existing GP infrastructure
- Need for granular OU-based targeting
- Compliance requirements for detailed audit trails
- Large enterprises with dedicated GP administrators

**Intune deployment excels for:**
- Modern cloud-first organizations
- Azure AD joined devices
- Remote/hybrid workforce
- Cross-platform device management
- Organizations using Microsoft 365
- Need for cloud-based compliance reporting

## 📦 Installation Options

### Option 1: Direct Execution (Recommended for Testing)
```powershell
# Load and test Ghost
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/refs/heads/main/Ghost.ps1')

# Assess current state
Get-Ghost

# Apply low-impact hardening first  
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry
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

# Deploy via Group Policy for domain environments
Set-Ghost -SMBv1 -AutoRun -Macros -GroupPolicy
gpupdate /force

# Deploy via Intune for cloud-managed devices  
Connect-IntuneGhost -Interactive
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -Intune

# Test with pilot group before broad deployment
```

## 💼 Practical Use Cases

### 🏥 **Healthcare**: Compliance Support
```powershell
# Address common vulnerabilities with minimal workflow impact
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -GuestAccount

# Deploy via Group Policy for consistent domain enforcement
Set-Ghost -SMBv1 -AutoRun -USBStorage -GroupPolicy

# Deploy via Intune for cloud-managed medical devices
Set-Ghost -RDP -USBStorage -AutoRun -Intune

# Secure Office 365 for patient data (requires evaluation)
Set-AzureGhost -SecurityDefaults
```

### 🏭 **Manufacturing**: OT/IT Security
```powershell
# Prevent network-based lateral movement
Set-Ghost -SMBv1 -LLMNR -NetBIOS -AdminShares

# Deploy via Group Policy for consistent OT/IT network protection
Set-Ghost -SMBv1 -LLMNR -NetBIOS -AdminShares -GroupPolicy

# Use Intune for office systems, avoid production systems
Set-Ghost -RDP -USBStorage -AutoRun -Intune

# Evaluate USB controls based on operational needs
# Some manufacturing equipment may require USB access
```

### 🏛️ **Government**: Risk Reduction
```powershell
# Comprehensive assessment first
Get-Ghost

# Apply controls based on mission requirements (direct)
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -GuestAccount

# Apply via Group Policy for classified networks
Set-Ghost -RDP -SMBv1 -AutoRun -USBStorage -Macros -GroupPolicy

# Use Intune for unclassified cloud systems
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -Telemetry -Intune

# Additional controls require operational impact assessment
```

### 💰 **Financial Services**: Fraud Prevention
```powershell
# Focus on identity and access controls
Set-AzureConditionalAccess -BlockLegacyAuth -RequireMFA

# Endpoint controls based on business processes
Set-Ghost -SMBv1 -LLMNR -NetBIOS

# Deploy via Intune for consistent branch office management
Set-Ghost -RDP -USBStorage -AutoRun -Macros -Intune

# Use Group Policy for trading floor systems
Set-Ghost -SMBv1 -LLMNR -NetBIOS -AdminShares -GroupPolicy
```

## 🔬 Advanced Features

### 🎯 **Selective Hardening**
```powershell
# Address specific threats individually
Set-SMBv1 -Disable                    # Block SMBv1 exploits
Set-RDP -Enable -RandomizePort         # Secure RDP with random port
Set-Macros -Disable                   # Block document malware
Set-LLMNR -Disable                    # Prevent credential theft

# Apply individual settings via Group Policy
Set-RDP -Disable -GroupPolicy         # Domain-wide RDP blocking
Set-SMBv1 -Disable -GroupPolicy       # Enterprise SMBv1 removal

# Deploy specific settings via Intune
Connect-IntuneGhost -Interactive
$Settings = @{ RDP = $true; SMBv1 = $true; USBStorage = $true }
Set-IntuneGhost -Settings $Settings
```

### 📊 **Assessment and Documentation**
```powershell
# Generate security assessment report
Get-Ghost | Export-Csv -Path "SecurityAssessment-$(Get-Date -Format 'yyyy-MM-dd').csv"

# Azure security posture
Get-AzureGhost | Out-File "AzureSecurityReport.txt"
```

### 🔄 **Verification and Rollback**
```powershell
# Verify changes (works with all deployment methods)
Get-Ghost

# Check Group Policy application
gpresult /r

# Monitor Intune policy deployment
# (Check Intune admin center for compliance status)

# Rollback specific changes if needed
Set-RDP -Enable          # Re-enable RDP
Set-USBStorage -Enable   # Re-enable USB storage
Set-Macros -Enable       # Re-enable Office macros
```

## 📈 Business Impact

### 💵 **Cost Considerations**
- **Typical security incident costs**: Range from thousands to millions depending on scale and industry
- **Ghost implementation cost**: Free open-source tool
- **Time investment**: 5 minutes for basic hardening vs. weeks for policy deployment

### ⚡ **Performance Benefits**
- **Reduced attack surface**: Fewer services and protocols available for exploitation
- **Faster incident response**: Proactive blocking vs. reactive cleanup
- **Simplified security posture**: Clear visibility into enabled/disabled services
- **Compliance support**: Demonstrable security improvements

### 📊 **Measurable Security Improvement**
- **Service reduction**: Eliminates entire classes of network-based attacks
- **Protocol hardening**: Addresses commonly exploited legacy protocols
- **Identity protection**: Azure integration provides cloud security controls
- **Verification capability**: Built-in assessment and reporting functions

## 🌐 Azure Cloud Integration

### 🔐 **Microsoft Graph Security**
Ghost integrates with Microsoft Graph API to provide Azure security assessment and hardening:

```powershell
# Connect to Azure tenant (requires appropriate permissions)
Connect-AzureGhost -Interactive

# Enable Security Defaults (basic protection)
Set-AzureSecurityDefaults -Enable

# Configure Conditional Access (requires Azure AD Premium)
Set-AzureConditionalAccess -BlockLegacyAuth -RequireMFA

# Audit privileged users
Set-AzurePrivilegedUsers -AuditOnly

# Comprehensive Azure assessment
Get-AzureGhost
```

### 🎯 **Identity-Focused Security**
Modern attacks often target identity systems. Ghost's Azure integration addresses:
- **Conditional Access Policies**: Control access based on risk signals
- **Legacy Authentication**: Block older, less secure authentication methods
- **Privileged Access**: Monitor and control administrative accounts
- **Security Defaults**: Microsoft's baseline security recommendations

## 🔧 Configuration Examples

### 🏢 **Small Business** (5-50 employees)
```powershell
# Start with safe, high-impact changes
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry

# Basic Azure security (if using Office 365)
Set-AzureSecurityDefaults -Enable

# For Office 365 Business Premium with Intune
Set-Ghost -USBStorage -AutoRun -Intune
```

### 🏭 **Medium Enterprise** (50-500 employees)  
```powershell
# Comprehensive assessment first
Get-Ghost

# Apply controls based on business requirements
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -GuestAccount

# Deploy via Group Policy for domain-wide consistency
Set-Ghost -RDP -SMBv1 -AutoRun -USBStorage -GroupPolicy

# Use Intune for remote/cloud-managed devices
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -Intune

# Advanced Azure controls (requires Azure AD Premium)
Set-AzureGhost -SecurityDefaults -ConditionalAccess
```

### 🌍 **Large Corporation** (500+ employees)
```powershell
# Use Ghost for assessment and pilot testing
Get-Ghost

# Pilot with select systems (direct configuration)
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -GuestAccount

# Deploy via Group Policy for domain infrastructure
Set-Ghost -RDP -SMBv1 -AutoRun -USBStorage -Macros -GroupPolicy
gpupdate /force

# Deploy via Intune for cloud-managed devices
Connect-IntuneGhost -ClientId "xxx" -TenantId "yyy" -CertificateThumbprint "zzz"
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -ICMP -Intune

# Enterprise Azure hardening (certificate-based auth)
Set-AzureConditionalAccess -BlockLegacyAuth -RequireMFA
```

### 📡 **MITRE ATT&CK Framework Alignment**
Ghost addresses these commonly observed techniques:

| MITRE Technique | Ghost Function | Impact Assessment |
|----------------|----------------|-------------------|
| T1021.001 (RDP) | `Set-RDP -Disable` | High - blocks remote access |
| T1021.002 (SMB/Admin Shares) | `Set-AdminShares -Disable` | Medium - may affect admin tools |
| T1059.001 (PowerShell) | `Set-PSRemoting -Disable` | Medium - blocks PS remoting |
| T1566.001 (Malicious Attachments) | `Set-Macros -Disable` | Medium - disables Office macros |
| T1557.001 (LLMNR Poisoning) | `Set-LLMNR -Disable` | Low - minimal business impact |

## 🛠️ Development & Contribution

### 🤝 **Contributing**
```bash
# Fork the repository
git clone https://github.com/jimrtyler/Ghost.git

# Create feature branch
git checkout -b feature/new-hardening-function

# Follow PowerShell best practices
# Add comprehensive help documentation
# Include parameter validation and error handling
# Test in multiple environments

# Submit pull request with detailed description
```

### 📋 **Development Roadmap**
- [ ] **Enhanced Reporting**: Detailed compliance and risk assessment reports
- [ ] **Intune Policy Templates**: Pre-built policy configurations for different industries
- [ ] **Group Policy ADMX Templates**: Administrative templates for easier GP deployment
- [ ] **SIEM Integration**: Export findings to security information systems
- [ ] **Compliance Frameworks**: Alignment with CIS, NIST, and ISO standards
- [ ] **Automated Testing**: Continuous validation of hardening effectiveness
- [ ] **PowerShell DSC**: Desired State Configuration modules
- [ ] **Configuration Manager**: SCCM integration for enterprise deployment

## 📞 Support & Community

### 🆘 **Getting Help**
- **GitHub Issues**: [Report bugs or request features](https://github.com/jimrtyler/Ghost/issues)
- **Documentation**: Comprehensive inline help with `Get-Help Set-Ghost -Full`
- **Testing**: Always test in non-production environments first

### 🔍 **Troubleshooting**
```powershell
# Check current status (works with all deployment methods)
Get-Ghost

# Verify specific function results
Get-Help Set-RDP -Examples

# Check Group Policy application
gpresult /r
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Check Intune policy deployment
Get-MgContext  # Verify Graph connection
# Monitor deployment in Intune admin center

# Roll back changes if needed
Set-RDP -Enable
Set-USBStorage -Enable
```

## 📜 License & Legal

### ⚖️ **MIT License**
Free for commercial and personal use. See [LICENSE](LICENSE) file for full terms.

### 🔒 **Security Disclaimer**
- Ghost is provided as-is for security hardening purposes
- No warranties or guarantees regarding security effectiveness
- Users are responsible for testing and validation in their environments
- Authors are not responsible for operational impact or service disruption
- This tool does not replace comprehensive security planning and professional consultation

### 🏅 **Credits**
- **Created by**: Jim Tyler (@jimrtyler)
- **Contributors**: Security community members and testers
- **Research**: Based on public security research, vendor recommendations, and community feedback
- **Standards**: Aligned with industry best practices from NIST, Microsoft, and security community

---

**🎯 Start with assessment, choose your deployment method, then harden systematically.**

```powershell
# Begin with a security assessment
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/refs/heads/main/Ghost.ps1')
Get-Ghost

# Choose your deployment approach:

# Direct (immediate, single device)
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry

# Group Policy (domain-wide enforcement)  
Set-Ghost -RDP -SMBv1 -AutoRun -Macros -GroupPolicy

# Intune (cloud-managed devices)
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -Intune
```

**⭐ Star this repository if Ghost helped improve your security posture!**
