<img src="https://github.com/user-attachments/assets/3592dff9-a204-4b92-82d0-8683c55e2584"  width="400" />

## Ghost Security Module
**Practical Windows Security Hardening Tool**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardening-red.svg)](https://github.com/jimrtyler/Ghost)

> **Reduce your attack surface quickly and effectively.** Ghost provides practical security hardening across Windows endpoints with 33 exported functions covering direct configuration, Group Policy enforcement, and Microsoft Intune cloud deployment.

## Important Disclaimers

- **No Security Guarantees**: Ghost reduces attack surface but cannot prevent all attacks or guarantee security
- **Test First**: Always test in non-production environments to assess business impact. Use `-WhatIf` on `Set-Ghost` to preview changes before applying.
- **Operational Impact**: Some functions disable services that may be required for business operations
- **Part of Defense Strategy**: Ghost is one component of a comprehensive security approach
- **Professional Consultation**: Consider consulting security professionals for enterprise deployments
- **Your Responsibility**: You are responsible for understanding the impact of changes in your environment

## The Reality: Preventable Attack Vectors

According to security research from NIST, FBI, and Microsoft, many successful attacks exploit commonly enabled Windows services and misconfigurations that can be addressed through basic hardening measures.

### Historical Attack Vectors Ghost Can Address:

#### SMBv1-Based Attacks (WannaCry, NotPetya)
- **Attack Vector**: SMBv1 EternalBlue exploit (CVE-2017-0143)
- **Ghost Mitigation**: `Set-Ghost -SMBv1` disables SMBv1 protocol
- **Context**: Microsoft recommended disabling SMBv1 in 2014, yet many systems remained vulnerable

#### Administrative Share Exploitation
- **Attack Vector**: Lateral movement via C$, ADMIN$ shares in post-compromise scenarios
- **Ghost Mitigation**: `Set-Ghost -AdminShares` disables administrative shares
- **Context**: Commonly observed in ransomware lateral movement patterns

#### RDP-Based Attacks
- **Attack Vector**: Credential stuffing, brute force attacks on Remote Desktop
- **Ghost Options**: `Set-Ghost -RDP` (disable) or `Set-RDP -Enable -RandomizePort` (secure with random port)
- **Context**: FBI reports show significant increase in RDP attacks, particularly since 2020

#### PowerShell Remoting Abuse
- **Attack Vector**: Lateral movement using PowerShell remoting capabilities
- **Ghost Mitigation**: `Set-Ghost -PSRemoting -WinRM` blocks remote execution vectors
- **Context**: Frequently observed in advanced persistent threat campaigns

#### USB-Based Malware
- **Attack Vector**: AutoRun malware, malicious USB devices with payload delivery
- **Ghost Mitigation**: `Set-Ghost -USBStorage -AutoRun` prevents USB-based infection vectors
- **Context**: Remains effective attack vector against unprepared systems

#### Macro-Based Malware
- **Attack Vector**: Malicious macros in Office documents as malware delivery mechanism
- **Ghost Mitigation**: `Set-Ghost -Macros` disables macro execution
- **Context**: Common delivery mechanism for trojans and ransomware families

#### Network Reconnaissance
- **Attack Vector**: LLMNR/NetBIOS poisoning, UPnP discovery, IPv6 probing, anonymous enumeration
- **Ghost Mitigation**: `Set-Ghost -LLMNR -NetBIOS -UPnP -IPv6Privacy -AnonymousAccess`
- **Context**: Commonly used for initial network reconnaissance and credential theft

## Security Coverage

Ghost provides **22 standalone hardening functions**, a bulk `Set-Ghost` command, an assessment function `Get-Ghost`, **6 Intune integration functions**, and **3 scheduled task management functions** (33 exported functions total).

### Windows Endpoint Hardening

| Function | Addresses | `-Enable` | `-GroupPolicy` | Operational Impact |
|----------|-----------|:---------:|:--------------:|-------------------|
| `Set-RDP` | Remote Desktop attacks | Yes | Yes | Blocks remote desktop access |
| `Set-SMBv1` | Legacy SMB exploits | Yes | Yes | Minimal (legacy protocol) |
| `Set-AutoRun` | USB malware, AutoPlay attacks | Yes | Yes | May affect legitimate removable media |
| `Set-USBStorage` | USB-based attacks, data exfiltration | Yes | Yes | Prevents all USB storage devices |
| `Set-Macros` | Document-based malware | Yes | Yes | Disables Office macro functionality |
| `Set-PSRemoting` | PowerShell lateral movement | Yes | -- | Blocks PowerShell remoting |
| `Set-WinRM` | Windows Remote Management abuse | Yes | -- | Blocks WinRM-based management |
| `Set-LLMNR` | Credential theft, MITM attacks | Yes | -- | Minimal (fallback protocol) |
| `Set-NetBIOS` | Network poisoning attacks | Yes | -- | Minimal (legacy protocol) |
| `Set-LDAP` | LDAP service exposure | Yes | -- | May affect directory services |
| `Set-AdminShares` | Lateral movement via shares | Yes | Yes | May affect some admin tools |
| `Set-Telemetry` | Data collection, privacy exposure | Yes | Yes | Minimal operational impact |
| `Set-GuestAccount` | Unauthorized access vectors | Yes | Yes | Minimal (rarely used) |
| `Set-ICMP` | Network reconnaissance | Yes | Yes | Blocks ping functionality |
| `Set-RemoteAssistance` | Unauthorized remote access | Yes | -- | Disables remote assistance features |
| `Set-NetworkDiscovery` | Network enumeration | Yes | -- | May affect network browsing |
| `Set-Firewall` | Network-based attacks | Yes | -- | Core security control - test carefully |
| `Set-UPnP` | UPnP/SSDP discovery attacks | Yes | Yes | May affect device discovery |
| `Set-WindowsTimeService` | NTP reconnaissance | Harden/Default | Yes | Minimal operational impact |
| `Set-ServiceBanners` | Information disclosure | Harden/Default | Yes | Minimal operational impact |
| `Set-IPv6Privacy` | IPv6 reconnaissance vectors | Yes | Yes | Minimal operational impact |
| `Set-AnonymousAccess` | Anonymous enumeration (LSA) | Restrict/Allow | Yes | May affect anonymous access workflows |

> **Note**: `Set-RDP` also supports `-RandomizePort` to change the RDP listening port to a random value between 3390-65535.

### Microsoft Intune Integration

| Function | Purpose |
|----------|---------|
| `Connect-IntuneGhost` | Authenticates to Microsoft Graph for Intune management |
| `Set-IntuneGhost` | Deploys hardening settings as Intune policies |
| `New-IntuneDeviceRestrictionPolicy` | Creates device restriction policies in Intune |
| `New-IntuneEndpointSecurityPolicy` | Creates endpoint security policies in Intune |
| `New-IntuneOfficePolicy` | Creates Office configuration policies in Intune |
| `New-IntunePowerShellScript` | Uploads PowerShell scripts to Intune for deployment |

### Scheduled Task Management

| Function | Purpose |
|----------|---------|
| `Set-GhostTask` | Creates obfuscated scheduled tasks for Ghost operations (daily, weekly, monthly) |
| `Get-GhostTask` | Lists all Ghost-managed scheduled tasks |
| `Remove-GhostTask` | Removes Ghost-managed scheduled tasks |

### Assessment & Bulk Operations

| Function | Purpose |
|----------|---------|
| `Get-Ghost` | Scans and reports the current security posture of all monitored settings |
| `Set-Ghost` | Disables multiple protocols/services in one command. Supports `-GroupPolicy`, `-Intune`, and `-WhatIf` |

## Quick Start

### Security Assessment
```powershell
# Load Ghost module
Import-Module ./Ghost.psm1

# Check your current security posture
Get-Ghost
```

### Basic Hardening (Test First!)
```powershell
# Preview changes before applying (WhatIf support)
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -WhatIf

# Apply low-impact hardening
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -GuestAccount

# For environments where USB and macros aren't needed
Set-Ghost -USBStorage -AutoRun -Macros

# Apply advanced hardening (UPnP, IPv6, anonymous access, service banners)
Set-Ghost -UPnP -IPv6Privacy -AnonymousAccess -ServiceBanners -WindowsTimeService

# Deploy via Group Policy for domain-wide enforcement
Set-Ghost -SMBv1 -AutoRun -Macros -GroupPolicy

# Deploy via Intune for cloud-managed devices
Connect-IntuneGhost -Interactive
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -ICMP -Intune
```

### Example Output
```
Get-Ghost scans your system and reports the status of each setting:

RDP: Enabled
ICMP: Enabled
LLMNR: Enabled
NetBIOS: Enabled
SMBv1: Enabled
AutoRun/AutoPlay: Enabled
USB Storage: Enabled
Office Macros: Enabled
Telemetry: Enabled
Guest Account: Enabled
Administrative Shares: Enabled
UPnP (Device Host / SSDP): Enabled
IPv6 / Privacy Extensions: Enabled
Anonymous Access (LSA): Enabled
...

The following settings, features or services appear to be enabled and are candidates for hardening:
 - RDP
 - ICMP
 - LLMNR
 - SMBv1
 ...

Suggestion: Set-Ghost -RDP -ICMP -LLMNR -SMBv1 ...
```

## Deployment Options: Choose Your Approach

Ghost provides **three deployment methods** to match your environment and needs:

### Direct Configuration
```powershell
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry
```
- Works on any Windows system (domain, workgroup, cloud)
- Immediate results and verification
- No licensing or infrastructure requirements
- Perfect for incident response and testing

### Group Policy Deployment
```powershell
Set-Ghost -RDP -SMBv1 -AutoRun -Macros -GroupPolicy
```
- **Domain-wide enforcement** with centralized management
- Automatic reapplication and inheritance
- Built-in audit trails and compliance reporting
- Prevents local administrator override
- Ideal for traditional Active Directory environments

### Microsoft Intune Deployment
```powershell
Connect-IntuneGhost -Interactive
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -ICMP -Intune
```
- **Cloud-scale deployment** to thousands of devices
- Modern device management for Azure AD joined systems
- Built-in compliance dashboards and reporting
- Perfect for modern, cloud-first organizations

### Deployment Method Comparison

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

### When to Use Each Approach:

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

## Installation Options

### Option 1: Direct Import
```powershell
# Clone and import
git clone https://github.com/jimrtyler/Ghost.git
Import-Module ./Ghost/Ghost.psm1

# Assess current state
Get-Ghost

# Apply low-impact hardening first
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry
```

### Option 2: PSGallery Installation
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
```

## Practical Use Cases

### Healthcare: Compliance Support
```powershell
# Address common vulnerabilities with minimal workflow impact
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -GuestAccount

# Deploy via Group Policy for consistent domain enforcement
Set-Ghost -SMBv1 -AutoRun -USBStorage -GroupPolicy

# Deploy via Intune for cloud-managed medical devices
Connect-IntuneGhost -Interactive
Set-Ghost -RDP -USBStorage -AutoRun -Intune
```

### Manufacturing: OT/IT Security
```powershell
# Prevent network-based lateral movement
Set-Ghost -SMBv1 -LLMNR -NetBIOS -AdminShares

# Deploy via Group Policy for consistent OT/IT network protection
Set-Ghost -SMBv1 -LLMNR -NetBIOS -AdminShares -GroupPolicy

# Use Intune for office systems, avoid production systems
Connect-IntuneGhost -Interactive
Set-Ghost -RDP -USBStorage -AutoRun -Intune

# Evaluate USB controls based on operational needs
# Some manufacturing equipment may require USB access
```

### Government: Risk Reduction
```powershell
# Comprehensive assessment first
Get-Ghost

# Apply controls based on mission requirements (direct)
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -GuestAccount

# Apply via Group Policy for classified networks
Set-Ghost -RDP -SMBv1 -AutoRun -USBStorage -Macros -GroupPolicy

# Use Intune for unclassified cloud systems
Connect-IntuneGhost -Interactive
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -Telemetry -Intune
```

### Financial Services: Fraud Prevention
```powershell
# Endpoint controls based on business processes
Set-Ghost -SMBv1 -LLMNR -NetBIOS -AnonymousAccess -ServiceBanners

# Deploy via Intune for consistent branch office management
Connect-IntuneGhost -Interactive
Set-Ghost -RDP -USBStorage -AutoRun -Macros -Intune

# Use Group Policy for trading floor systems
Set-Ghost -SMBv1 -LLMNR -NetBIOS -AdminShares -GroupPolicy
```

## Advanced Features

### Selective Hardening
```powershell
# Address specific threats individually
Set-SMBv1 -Disable                    # Block SMBv1 exploits
Set-RDP -Enable -RandomizePort         # Secure RDP with random port
Set-Macros -Disable                   # Block document malware
Set-LLMNR -Disable                    # Prevent credential theft
Set-UPnP -Disable                     # Prevent UPnP discovery attacks
Set-AnonymousAccess -Restrict          # Block anonymous enumeration
Set-ServiceBanners -Harden             # Minimize information disclosure
Set-IPv6Privacy -Disable               # Disable IPv6 recon vectors

# Re-enable settings when needed
Set-LLMNR -Enable                     # Restore LLMNR
Set-NetBIOS -Enable                   # Restore NetBIOS
Set-PSRemoting -Enable                # Restore PowerShell Remoting

# Apply individual settings via Group Policy
Set-RDP -Disable -GroupPolicy         # Domain-wide RDP blocking
Set-SMBv1 -Disable -GroupPolicy       # Enterprise SMBv1 removal
Set-UPnP -Disable -GroupPolicy        # Enterprise UPnP removal

# Deploy specific settings via Intune
Connect-IntuneGhost -Interactive
$Settings = @{ RDP = $true; SMBv1 = $true; USBStorage = $true }
Set-IntuneGhost -Settings $Settings
```

### Preview Changes with WhatIf
```powershell
# Preview what Set-Ghost would do without making changes
Set-Ghost -RDP -SMBv1 -LLMNR -NetBIOS -Macros -WhatIf

# Then apply when ready
Set-Ghost -RDP -SMBv1 -LLMNR -NetBIOS -Macros
```

### Scheduled Task Management
```powershell
# Create a daily task to kill all RDP sessions at 3:00 AM
Set-GhostTask -KillAllSessions -Frequency Daily -Time "03:00"

# Create a weekly task every Sunday at 2:00 AM
Set-GhostTask -KillAllSessions -Frequency Weekly -Time "02:00" -DayOfWeek Sunday

# Create a monthly task on the 1st of each month
Set-GhostTask -KillAllSessions -Frequency Monthly -Time "01:00" -DayOfMonth 1

# List all Ghost scheduled tasks
Get-GhostTask

# Remove Ghost scheduled tasks
Remove-GhostTask
```

> **Note**: Ghost scheduled tasks use obfuscated names (disguised as common application update services) and are stored in `C:\Scripts`.

### Intune Policy Management
```powershell
# Connect to Microsoft Graph (interactive or certificate-based)
Connect-IntuneGhost -Interactive
Connect-IntuneGhost -ClientId "xxx" -TenantId "yyy" -CertificateThumbprint "zzz"

# Create individual Intune policies
New-IntuneDeviceRestrictionPolicy     # Device restriction settings
New-IntuneEndpointSecurityPolicy      # Endpoint security baselines
New-IntuneOfficePolicy                # Office configuration policies
New-IntunePowerShellScript            # Upload PowerShell scripts to Intune
```

### Verification and Rollback
```powershell
# Verify changes (works with all deployment methods)
Get-Ghost

# Check Group Policy application
gpresult /r
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Check Intune policy deployment
Get-MgContext  # Verify Graph connection
# Monitor deployment in Intune admin center

# Rollback specific changes if needed
Set-RDP -Enable          # Re-enable RDP
Set-USBStorage -Enable   # Re-enable USB storage
Set-Macros -Enable       # Re-enable Office macros
Set-LLMNR -Enable        # Re-enable LLMNR
Set-NetBIOS -Enable      # Re-enable NetBIOS
Set-PSRemoting -Enable   # Re-enable PowerShell Remoting
```

## Configuration Examples

### Small Business (5-50 employees)
```powershell
# Preview changes first
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -WhatIf

# Start with safe, high-impact changes
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry

# For Office 365 Business Premium with Intune
Connect-IntuneGhost -Interactive
Set-Ghost -USBStorage -AutoRun -Intune
```

### Medium Enterprise (50-500 employees)
```powershell
# Comprehensive assessment first
Get-Ghost

# Apply controls based on business requirements
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -GuestAccount

# Deploy via Group Policy for domain-wide consistency
Set-Ghost -RDP -SMBv1 -AutoRun -USBStorage -GroupPolicy

# Use Intune for remote/cloud-managed devices
Connect-IntuneGhost -Interactive
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -Intune
```

### Large Corporation (500+ employees)
```powershell
# Use Ghost for assessment and pilot testing
Get-Ghost

# Pilot with select systems (direct configuration)
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry -GuestAccount -WhatIf

# Deploy via Group Policy for domain infrastructure
Set-Ghost -RDP -SMBv1 -AutoRun -USBStorage -Macros -GroupPolicy
gpupdate /force

# Deploy via Intune for cloud-managed devices
Connect-IntuneGhost -ClientId "xxx" -TenantId "yyy" -CertificateThumbprint "zzz"
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -ICMP -Intune

# Apply advanced hardening
Set-Ghost -UPnP -IPv6Privacy -AnonymousAccess -ServiceBanners -WindowsTimeService
```

### MITRE ATT&CK Framework Alignment
Ghost addresses these commonly observed techniques:

| MITRE Technique | Ghost Function | Impact Assessment |
|----------------|----------------|-------------------|
| T1021.001 (RDP) | `Set-RDP -Disable` | High - blocks remote access |
| T1021.002 (SMB/Admin Shares) | `Set-AdminShares -Disable` | Medium - may affect admin tools |
| T1059.001 (PowerShell) | `Set-PSRemoting -Disable` | Medium - blocks PS remoting |
| T1566.001 (Malicious Attachments) | `Set-Macros -Disable` | Medium - disables Office macros |
| T1557.001 (LLMNR Poisoning) | `Set-LLMNR -Disable` | Low - minimal business impact |

## Complete Function Reference

### Hardening Functions (22)
| Function | Parameters |
|----------|-----------|
| `Set-ICMP` | `-Enable`, `-Disable`, `-GroupPolicy` |
| `Set-RDP` | `-Enable`, `-Disable`, `-RandomizePort`, `-GroupPolicy` |
| `Set-SMBv1` | `-Enable`, `-Disable`, `-GroupPolicy` |
| `Set-AutoRun` | `-Enable`, `-Disable`, `-GroupPolicy` |
| `Set-Macros` | `-Enable`, `-Disable`, `-GroupPolicy` |
| `Set-LLMNR` | `-Enable`, `-Disable` |
| `Set-NetBIOS` | `-Enable`, `-Disable` |
| `Set-LDAP` | `-Enable`, `-Disable` |
| `Set-PSRemoting` | `-Enable`, `-Disable` |
| `Set-Firewall` | `-Enable`, `-Disable` |
| `Set-RemoteAssistance` | `-Enable`, `-Disable` |
| `Set-NetworkDiscovery` | `-Enable`, `-Disable` |
| `Set-USBStorage` | `-Enable`, `-Disable`, `-GroupPolicy` |
| `Set-WinRM` | `-Enable`, `-Disable` |
| `Set-AdminShares` | `-Enable`, `-Disable`, `-GroupPolicy` |
| `Set-Telemetry` | `-Enable`, `-Disable`, `-GroupPolicy` |
| `Set-GuestAccount` | `-Enable`, `-Disable`, `-GroupPolicy` |
| `Set-UPnP` | `-Enable`, `-Disable`, `-GroupPolicy` |
| `Set-WindowsTimeService` | `-Harden`, `-Default`, `-GroupPolicy` |
| `Set-ServiceBanners` | `-Harden`, `-Default`, `-GroupPolicy` |
| `Set-IPv6Privacy` | `-Enable`, `-Disable`, `-GroupPolicy` |
| `Set-AnonymousAccess` | `-Restrict`, `-Allow`, `-GroupPolicy` |

### Bulk & Assessment (2)
| Function | Parameters |
|----------|-----------|
| `Set-Ghost` | All 22 hardening switches + `-GroupPolicy`, `-Intune`, `-WhatIf` |
| `Get-Ghost` | _(no parameters - scans and reports all settings)_ |

### Intune Integration (6)
| Function | Purpose |
|----------|---------|
| `Connect-IntuneGhost` | `-Interactive`, `-ClientId`, `-TenantId`, `-CertificateThumbprint` |
| `Set-IntuneGhost` | `-Settings` (hashtable of hardening options) |
| `New-IntuneDeviceRestrictionPolicy` | Creates device restriction policies |
| `New-IntuneEndpointSecurityPolicy` | Creates endpoint security policies |
| `New-IntuneOfficePolicy` | Creates Office configuration policies |
| `New-IntunePowerShellScript` | Uploads PowerShell scripts to Intune |

### Scheduled Tasks (3)
| Function | Parameters |
|----------|-----------|
| `Set-GhostTask` | `-KillAllSessions`, `-Frequency`, `-Time`, `-DayOfWeek`, `-DayOfMonth` |
| `Get-GhostTask` | _(lists all Ghost tasks)_ |
| `Remove-GhostTask` | _(removes Ghost tasks)_ |

## Development & Contribution

### Contributing
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

### Development Roadmap
- [ ] **Enhanced Reporting**: Detailed compliance and risk assessment reports
- [ ] **Intune Policy Templates**: Pre-built policy configurations for different industries
- [ ] **Group Policy ADMX Templates**: Administrative templates for easier GP deployment
- [ ] **SIEM Integration**: Export findings to security information systems
- [ ] **Compliance Frameworks**: Alignment with CIS, NIST, and ISO standards
- [ ] **Automated Testing**: Continuous validation of hardening effectiveness
- [ ] **PowerShell DSC**: Desired State Configuration modules
- [ ] **Configuration Manager**: SCCM integration for enterprise deployment

## Support & Community

### Getting Help
- **GitHub Issues**: [Report bugs or request features](https://github.com/jimrtyler/Ghost/issues)
- **Documentation**: Comprehensive inline help with `Get-Help Set-Ghost -Full`
- **Testing**: Always test in non-production environments first

### Troubleshooting
```powershell
# Check current status (works with all deployment methods)
Get-Ghost

# Verify specific function results
Get-Help Set-RDP -Examples

# Preview changes before applying
Set-Ghost -SMBv1 -LLMNR -NetBIOS -WhatIf

# Check Group Policy application
gpresult /r
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Check Intune policy deployment
Get-MgContext  # Verify Graph connection
# Monitor deployment in Intune admin center

# Roll back changes if needed
Set-RDP -Enable
Set-USBStorage -Enable
Set-LLMNR -Enable
```

## License & Legal

### MIT License
Free for commercial and personal use. See [LICENSE](LICENSE) file for full terms.

### Security Disclaimer
- Ghost is provided as-is for security hardening purposes
- No warranties or guarantees regarding security effectiveness
- Users are responsible for testing and validation in their environments
- Authors are not responsible for operational impact or service disruption
- This tool does not replace comprehensive security planning and professional consultation

### Credits
- **Created by**: Jim Tyler (@jimrtyler)
- **Contributors**: Security community members and testers
- **Research**: Based on public security research, vendor recommendations, and community feedback
- **Standards**: Aligned with industry best practices from NIST, Microsoft, and security community

---

**Start with assessment, choose your deployment method, then harden systematically.**

```powershell
# Begin with a security assessment
Import-Module ./Ghost.psm1
Get-Ghost

# Choose your deployment approach:

# Direct (immediate, single device)
Set-Ghost -SMBv1 -LLMNR -NetBIOS -Telemetry

# Group Policy (domain-wide enforcement)
Set-Ghost -RDP -SMBv1 -AutoRun -Macros -GroupPolicy

# Intune (cloud-managed devices)
Connect-IntuneGhost -Interactive
Set-Ghost -RDP -SMBv1 -USBStorage -AutoRun -Intune
```
