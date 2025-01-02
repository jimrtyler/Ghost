<img src="https://github.com/user-attachments/assets/3592dff9-a204-4b92-82d0-8683c55e2584"  width="400" />

# Ghost PowerShell Module

The **Ghost** PowerShell module is designed to enhance the security of Windows servers by providing functionality to disable or assess the status of various protocols and settings. This includes features like PowerShell Remoting, ICMP, NetBIOS, SMBv1, LLMNR, and more. The module offers two primary cmdlets:

- **`Get-Ghost`**: Assesses the current configuration of protocols and security settings.
- **`Set-Ghost`**: Disables insecure protocols and services to harden the system.

##Usage Without Downloading
[code]
#View What Protocols are Enabled or Disabled
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/refs/heads/main/Ghost.ps1')
Get-Ghost

#Actively Disable Protocols
Set-Ghost -ICMP -LLMNR -RDP -NetBIOS -SMBv1 -RemoteAssistance -NetworkDiscovery -PSRemoting 
[/code]

## Installation

1. Save the Ghost module (`Ghost.psm1`) to a folder on your system.
2. Import the module into your PowerShell session:
   ```powershell
   Import-Module "Path\To\Ghost.psm1"
