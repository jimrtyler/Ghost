function Set-ICMP {
    <#
    .SYNOPSIS
    Enables or disables ICMP (ping) for the server.
   
    .DESCRIPTION
    This function manages ICMP by adding or removing firewall rules that block ICMP packets.
    Use `-Enable` to allow ICMP traffic or `-Disable` to block ICMP traffic.
   
    .PARAMETER Enable
    Allows ICMP traffic.

    .PARAMETER Disable
    Blocks ICMP traffic.

    .EXAMPLE
    Set-ICMP -Enable
    Enables ICMP traffic.

    .EXAMPLE
    Set-ICMP -Disable
    Disables ICMP traffic.
    #>
    param(
        [Switch]$Enable,
        [Switch]$Disable
    )
    if ($Enable -and $Disable) {
        throw "Specify either -Enable or -Disable, not both."
    }

    if ($Enable) {
        Remove-NetFirewallRule -DisplayName "Disable ICMPv4-In" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "Disable ICMPv6-In" -ErrorAction SilentlyContinue
        Write-Host "ICMP enabled"
    } elseif ($Disable) {
        New-NetFirewallRule -DisplayName "Disable ICMPv4-In" -Protocol ICMPv4 -IcmpType 8 -Action Block
        New-NetFirewallRule -DisplayName "Disable ICMPv6-In" -Protocol ICMPv6 -Action Block
        Write-Host "ICMP disabled"
    } else {
        throw "Specify either -Enable or -Disable."
    }
}

function Set-RDP {
    <#
    .SYNOPSIS
    Enables or disables Remote Desktop Protocol (RDP).

    .DESCRIPTION
    This function configures RDP settings by modifying registry values and controlling the TermService service.
    Use `-Enable` to allow RDP access or `-Disable` to block RDP access.

    .PARAMETER Enable
    Enables RDP access.

    .PARAMETER Disable
    Disables RDP access.

    .EXAMPLE
    Set-RDP -Enable
    Enables RDP access.

    .EXAMPLE
    Set-RDP -Disable
    Disables RDP access.
    #>
    param(
        [Switch]$Enable,
        [Switch]$Disable
    )
    if ($Enable -and $Disable) {
        throw "Specify either -Enable or -Disable, not both."
    }

    if ($Enable) {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
        #Start-Service -Name "TermService"
        Set-Service -Name "TermService" -StartupType Automatic
        Write-Host "RDP enabled"
    } elseif ($Disable) {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
        Stop-Service -Name "TermService" -Force
        Set-Service -Name "TermService" -StartupType Disabled
        Write-Host "RDP disabled"
    } else {
        throw "Specify either -Enable or -Disable."
    }
}

function Set-LLMNR {
    <#
    .SYNOPSIS
    Disables Link-Local Multicast Name Resolution (LLMNR).

    .DESCRIPTION
    This function configures the registry to disable LLMNR by setting the `EnableMulticast` value to `0`.
    If the required registry path does not exist, it creates the path before setting the value.

    .EXAMPLE
    Set-LLMNR -Disable
    Disables LLMNR on the system.
    #>
    param(
        [Switch]$Disable
    )

    if ($Disable) {
        Write-Host "Disabling LLMNR..."
        $RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $RegistryPath)) {
            Write-Host "Registry path '$RegistryPath' does not exist. Creating path..."
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
        }

        Set-ItemProperty -Path $RegistryPath -Name "EnableMulticast" -Value 0
        Write-Host "LLMNR has been disabled."
    } else {
        Write-Host "No action taken. Use -Disable to disable LLMNR."
    }
}


# Additional functions for Set-NetBIOS, Set-LDAP, Set-PSRemoting, Set-SMBv1,
# Set-Firewall, Set-RemoteAssistance, and Set-NetworkDiscovery follow the same
# structure as the above examples. Detailed comments and -Enable/-Disable
# parameters are included for consistency.



function Set-NetBIOS {
    <#
    .SYNOPSIS
    Disables NetBIOS over TCP/IP on all network adapters.

    .DESCRIPTION
    This function disables NetBIOS by configuring the CIM class `Win32_NetworkAdapterConfiguration`.
    It ensures that all adapters have NetBIOS set to `Disabled`.

    .EXAMPLE
    Set-NetBIOS -Disable
    Disables NetBIOS over TCP/IP on all network adapters.
    #>
    param(
        [Switch]$Disable
    )

    if ($Disable) {
        # Disable NetBIOS on all network interfaces
        try {
            # Retrieve all network adapters where IP is enabled
            $Adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }

            if ($Adapters) {
                Write-Host "Disabling NetBIOS on all network interfaces..." -ForegroundColor Yellow
                foreach ($Adapter in $Adapters) {
                    # Call SetTcpipNetbios method with positional argument 2 (Disable NetBIOS)
                    $Result = $Adapter | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 }
                    
                    if ($Result.ReturnValue -eq 0) {
                        Write-Host "NetBIOS successfully disabled on adapter: $($Adapter.Description)" -ForegroundColor Green
                    } else {
                        Write-Host "Failed to disable NetBIOS on adapter: $($Adapter.Description)" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "No network interfaces found with IP enabled." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "An error occurred while disabling NetBIOS: $_" -ForegroundColor Red
        }
}

}



function Set-LDAP {
    <#
    .SYNOPSIS
    Enables or disables the LDAP service on the server.

    .DESCRIPTION
    This function starts or stops the LDAP (NTDS) service and adjusts its startup type.
    Use `-Enable` to start the service or `-Disable` to stop it.

    .PARAMETER Enable
    Enables the LDAP service.

    .PARAMETER Disable
    Disables the LDAP service.

    .EXAMPLE
    Set-LDAP -Enable
    Enables LDAP.

    .EXAMPLE
    Set-LDAP -Disable
    Disables LDAP.
    #>
    param(
        [Switch]$Enable,
        [Switch]$Disable
    )
    if ($Enable -and $Disable) {
        throw "Specify either -Enable or -Disable, not both."
    }

    if ($Enable) {
        #Start-Service -Name "NTDS"
        Set-Service -Name "NTDS" -StartupType Automatic
        Write-Host "LDAP enabled"
    } elseif ($Disable) {
        Stop-Service -Name "NTDS" -Force
        Set-Service -Name "NTDS" -StartupType Disabled
        Write-Host "LDAP disabled"
    } else {
        throw "Specify either -Enable or -Disable."
    }
}


function Set-PSRemoting {
    <#
    .SYNOPSIS
    Disables PowerShell Remoting.

    .DESCRIPTION
    This function disables PowerShell Remoting by configuring the WSMan service. It also accounts for cases
    where the WSMan provider or configuration cannot be detected.

    .PARAMETER Disable
    Disables PowerShell Remoting.

    .EXAMPLE
    Set-PSRemoting -Disable
    Disables PowerShell Remoting.
    #>
    param(
        [Switch]$Disable
    )

    if ($Disable) {
        Write-Host "Attempting to disable PowerShell Remoting..."

        # Check if WSMan provider is available
        if (-not (Test-Path "WSMan:\localhost\Service")) {
            Write-Host "PowerShell Remoting status cannot be detected. WSMan provider not available." -ForegroundColor Yellow
            return
        }

        try {
            # Check current status of PowerShell Remoting
            $PSRemotingStatus = (Get-Item -Path "WSMan:\localhost\Service").Enabled -eq $true

            if ($PSRemotingStatus) {
                Write-Host "PowerShell Remoting is currently enabled. Disabling..."
                Disable-PSRemoting -Force
                Write-Host "PowerShell Remoting has been disabled." -ForegroundColor Green
            } else {
                Write-Host "PowerShell Remoting is already disabled." -ForegroundColor Green
            }
        } catch {
            Write-Host "An error occurred while attempting to disable PowerShell Remoting: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "No action taken. Use -Disable to disable PowerShell Remoting."
    }
}





function Set-SMBv1 {
    <#
    .SYNOPSIS
    Enables or disables SMBv1 protocol.

    .DESCRIPTION
    This function modifies SMB server configuration to enable or disable SMBv1.
    Use `-Enable` to allow SMBv1 or `-Disable` to block it.

    .PARAMETER Enable
    Enables SMBv1.

    .PARAMETER Disable
    Disables SMBv1.

    .EXAMPLE
    Set-SMBv1 -Enable
    Enables SMBv1.

    .EXAMPLE
    Set-SMBv1 -Disable
    Disables SMBv1.
    #>
    param(
        [Switch]$Enable,
        [Switch]$Disable
    )
    if ($Enable -and $Disable) {
        throw "Specify either -Enable or -Disable, not both."
    }

    if ($Enable) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
        Write-Host "SMBv1 enabled"
    } elseif ($Disable) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-Host "SMBv1 disabled"
    } else {
        throw "Specify either -Enable or -Disable."
    }
}



function Set-Firewall {
    <#
    .SYNOPSIS
    Enables or disables Windows Firewall.

    .DESCRIPTION
    This function adjusts the state of the firewall for all profiles (Domain, Private, Public).
    Use `-Enable` to turn the firewall on or `-Disable` to turn it off.

    .PARAMETER Enable
    Enables the Windows Firewall.

    .PARAMETER Disable
    Disables the Windows Firewall.

    .EXAMPLE
    Set-Firewall -Enable
    Enables the firewall.

    .EXAMPLE
    Set-Firewall -Disable
    Disables the firewall.
    #>
    param(
        [Switch]$Enable,
        [Switch]$Disable
    )
    if ($Enable -and $Disable) {
        throw "Specify either -Enable or -Disable, not both."
    }

    if ($Enable) {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
        Write-Host "Firewall enabled"
    } elseif ($Disable) {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
        Write-Host "Firewall disabled"
    } else {
        throw "Specify either -Enable or -Disable."
    }
}



function Set-RemoteAssistance {
    <#
    .SYNOPSIS
    Enables or disables Remote Assistance.

    .DESCRIPTION
    This function modifies registry values to enable or disable Remote Assistance.
    Use `-Enable` to allow it or `-Disable` to block it.

    .PARAMETER Enable
    Enables Remote Assistance.

    .PARAMETER Disable
    Disables Remote Assistance.

    .EXAMPLE
    Set-RemoteAssistance -Enable
    Enables Remote Assistance.

    .EXAMPLE
    Set-RemoteAssistance -Disable
    Disables Remote Assistance.
    #>
    param(
        [Switch]$Enable,
        [Switch]$Disable
    )
    if ($Enable -and $Disable) {
        throw "Specify either -Enable or -Disable, not both."
    }

    if ($Enable) {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 1
        Write-Host "Remote Assistance enabled"
    } elseif ($Disable) {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
        Write-Host "Remote Assistance disabled"
    } else {
        throw "Specify either -Enable or -Disable."
    }
}


function Set-NetworkDiscovery {
    <#
    .SYNOPSIS
    Enables or disables Network Discovery.

    .DESCRIPTION
    This function controls services related to network discovery (FDResPub and SSDPDiscovery).
    Use `-Enable` to start these services or `-Disable` to stop them.

    .PARAMETER Enable
    Enables Network Discovery.

    .PARAMETER Disable
    Disables Network Discovery.

    .EXAMPLE
    Set-NetworkDiscovery -Enable
    Enables Network Discovery.

    .EXAMPLE
    Set-NetworkDiscovery -Disable
    Disables Network Discovery.
    #>
    param(
        [Switch]$Enable,
        [Switch]$Disable
    )
    if ($Enable -and $Disable) {
        throw "Specify either -Enable or -Disable, not both."
    }

    if ($Enable) {
        Set-Service -Name "FDResPub" -StartupType Automatic
        Set-Service -Name "SSDPDiscovery" -StartupType Automatic
        #Start-Service -Name "FDResPub"
        #Start-Service -Name "SSDPDiscovery"
        Write-Host "Network Discovery enabled"
    } elseif ($Disable) {
        Stop-Service -Name "FDResPub"
        Stop-Service -Name "SSDPDiscovery"
        Set-Service -Name "FDResPub" -StartupType Disabled
        Set-Service -Name "SSDPDiscovery" -StartupType Disabled
        Write-Host "Network Discovery disabled"
    } else {
        throw "Specify either -Enable or -Disable."
    }
}









function Set-Ghost {
    <#
    .SYNOPSIS
    Disables various protocols and services for hardening the server.

    .DESCRIPTION
    This function disables specific protocols and services for increased security. Supported features include RDP,
    ICMP, LLMNR, NetBIOS, LDAP, PowerShell Remoting, SMBv1, Remote Assistance, and Network Discovery. Written by Jim Tyler.

    .PARAMETER RDP
    Disables Remote Desktop Protocol (RDP).

    .PARAMETER ICMP
    Disables ICMP (ping).

    .PARAMETER LLMNR
    Disables Link-Local Multicast Name Resolution.

    .PARAMETER NetBIOS
    Disables NetBIOS over TCP/IP.

    .PARAMETER LDAP
    Disables LDAP service.

    .PARAMETER PSRemoting
    Disables PowerShell Remoting.

    .PARAMETER SMBv1
    Disables SMBv1 protocol.

    .PARAMETER RemoteAssistance
    Disables Remote Assistance.

    .PARAMETER NetworkDiscovery
    Disables Network Discovery.

    .EXAMPLE
    Set-Ghost -RDP -ICMP -LLMNR
    Disables RDP, ICMP, and LLMNR.

    .EXAMPLE
    Set-Ghost -SMBv1 -PSRemoting
    Disables SMBv1 and PowerShell Remoting.
    #>





    param(
        [Switch]$RDP,
        [Switch]$ICMP,
        [Switch]$LLMNR,
        [Switch]$NetBIOS,
        [Switch]$LDAP,
        [Switch]$PSRemoting,
        [Switch]$SMBv1,
        [Switch]$RemoteAssistance,
        [Switch]$NetworkDiscovery
    )


    Write-Host "Status prior to disabling:"
    Get-Ghost

    if ($RDP) {
        Write-Host "Disabling RDP..."
        Set-RDP -Disable
    }

    if ($ICMP) {
        Write-Host "Disabling ICMP..."
        Set-ICMP -Disable
    }

    if ($LLMNR) {
        Write-Host "Disabling LLMNR..."
        Set-LLMNR -Disable
    }

    if ($NetBIOS) {
        Write-Host "Disabling NetBIOS..."
        Set-NetBIOS -Disable
    }

    if ($LDAP) {
        Write-Host "Disabling LDAP..."
        Set-LDAP -Disable
    }

    if ($PSRemoting) {
        Write-Host "Disabling PowerShell Remoting..."
        Set-PSRemoting -Disable
    }

    if ($SMBv1) {
        Write-Host "Disabling SMBv1..."
        Set-SMBv1 -Disable
    }

    if ($RemoteAssistance) {
        Write-Host "Disabling Remote Assistance..."
        Set-RemoteAssistance -Disable
    }

    if ($NetworkDiscovery) {
        Write-Host "Disabling Network Discovery..."
        Set-NetworkDiscovery -Disable
    }

    Write-Host "Protocol and service disabling complete."


    Write-Host "Status after disabling:"
    Get-Ghost
}





function Write-Status {
    param(
        [string]$ServiceName,
        [AllowNull()]$IsEnabled
    )

    # Handle non-Boolean values
    if ($IsEnabled -eq $true) {
        Write-Host "${ServiceName}: Enabled" -ForegroundColor Red
    } elseif ($IsEnabled -eq $false) {
        Write-Host "${ServiceName}: Disabled" -ForegroundColor Green
    } elseif ([string]::IsNullOrEmpty($IsEnabled)) {
        Write-Host "${ServiceName}: Status Unknown (Empty Value)" -ForegroundColor Yellow
    } else {
        Write-Host "${ServiceName}: Status Unknown (Invalid Value)" -ForegroundColor Yellow
    }
}




function Get-Ghost {
    <#
    .SYNOPSIS
    Retrieves the status of various protocols and services and provides recommendations for hardening.

    .DESCRIPTION
    This cmdlet checks the status of specific protocols and services, such as RDP, ICMP, LLMNR, NetBIOS, LDAP,
    PowerShell Remoting, SMBv1, Remote Assistance, and Network Discovery. Enabled services are displayed in red,
    while disabled services are displayed in green. If a service or setting is not available, it provides a status message in yellow.
    At the end, it suggests executing `Set-Ghost` to disable any enabled protocols or services.

    .EXAMPLE
    Get-Ghost
    Displays the status of all supported protocols and services and suggests further actions.
    #>

    # Initialize an array to hold enabled protocols for recommendations
    $EnabledProtocols = @()

    # Check RDP Status
    if (Test-Path "HKLM:\System\CurrentControlSet\Control\Terminal Server") {
        $RDPStatus = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections -eq 0
    } else {
        $RDPStatus = $null
    }
    if (Write-Status -ServiceName "RDP" -IsEnabled $RDPStatus) {
        $EnabledProtocols += "RDP"
    }

    # Check ICMP Status
    $ICMPRule = Get-NetFirewallRule -DisplayName "Disable ICMPv4-In" -ErrorAction SilentlyContinue
    $ICMPStatus = if ($ICMPRule) { $false } else { $true }
    if (Write-Status -ServiceName "ICMP" -IsEnabled $ICMPStatus) {
        $EnabledProtocols += "ICMP"
    }

    # Check LLMNR Status
    if (Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient") {
        $LLMNRStatus = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast -ne 0
    } else {
        $LLMNRStatus = $null
    }
    if (Write-Status -ServiceName "LLMNR" -IsEnabled $LLMNRStatus) {
        $EnabledProtocols += "LLMNR"
    }

# Check NetBIOS Status
try {
    # Retrieve network adapters and check their NetBIOS settings
    $NetBIOSAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }

    # Set NetBIOSStatus explicitly based on all adapters
    if ($NetBIOSAdapters) {
        # Check if any adapter does NOT have TcpipNetbiosOptions set to 2 (Disabled)
        $NetBIOSStatus = $NetBIOSAdapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
        if ($NetBIOSStatus.Count -gt 0) {
            # If any adapter has NetBIOS not disabled, set status to $true (enabled)
            $NetBIOSStatus = $true
        } else {
            # If all adapters have NetBIOS disabled, set status to $false
            $NetBIOSStatus = $false
        }
    } else {
        # No adapters found, assume status unknown
        $NetBIOSStatus = $null
    }
} catch {
    # Handle errors gracefully
    $NetBIOSStatus = $null
}

# Pass the explicitly set Boolean or $null to Write-Status
if (Write-Status -ServiceName "NetBIOS" -IsEnabled $NetBIOSStatus) {
    $EnabledProtocols += "NetBIOS"
}



    # Check LDAP Status
    if (Get-Service -Name "NTDS" -ErrorAction SilentlyContinue) {
        $LDAPStatus = (Get-Service -Name "NTDS" -ErrorAction SilentlyContinue).Status -eq "Running"
    } else {
        $LDAPStatus = $null
    }
    if (Write-Status -ServiceName "LDAP" -IsEnabled $LDAPStatus) {
        $EnabledProtocols += "LDAP"
    }

    # Check PowerShell Remoting Status
    try {
        # Check if the WinRM service exists and its current status
        $WinRMService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue

        if ($WinRMService -and $WinRMService.Status -eq "Running") {
            # If WinRM is running, assume PowerShell Remoting is enabled
            $PSRemotingStatus = $true
        } elseif ($WinRMService -and $WinRMService.Status -ne "Running") {
            # If WinRM exists but is not running, assume PowerShell Remoting is disabled
            $PSRemotingStatus = $false
        } else {
            # If WinRM service is not found, status is unknown
            $PSRemotingStatus = $null
        }
    } catch {
        # Handle any errors gracefully
        $PSRemotingStatus = $null
    }

    if (Write-Status -ServiceName "PowerShell Remoting" -IsEnabled $PSRemotingStatus) {
        $EnabledProtocols += "PSRemoting"
    }



    # Check SMBv1 Status
    try {
        $SMBv1Status = (Get-SmbServerConfiguration).EnableSMB1Protocol
    } catch {
        $SMBv1Status = $null
    }
    if (Write-Status -ServiceName "SMBv1" -IsEnabled $SMBv1Status) {
        $EnabledProtocols += "SMBv1"
    }

    # Check Remote Assistance Status
    if (Test-Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance") {
        $RemoteAssistanceStatus = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp -eq 1
    } else {
        $RemoteAssistanceStatus = $null
    }
    if (Write-Status -ServiceName "Remote Assistance" -IsEnabled $RemoteAssistanceStatus) {
        $EnabledProtocols += "Remote Assistance"
    }

    # Check Network Discovery Status
    $FDResPubStatus = if (Get-Service -Name "FDResPub" -ErrorAction SilentlyContinue) { (Get-Service -Name "FDResPub").Status -eq "Running" } else { $null }
    $SSDPDiscoveryStatus = if (Get-Service -Name "SSDPDiscovery" -ErrorAction SilentlyContinue) { (Get-Service -Name "SSDPDiscovery").Status -eq "Running" } else { $null }
    $NetworkDiscoveryStatus = if ($FDResPubStatus -or $SSDPDiscoveryStatus) { $true } elseif ($FDResPubStatus -eq $null -and $SSDPDiscoveryStatus -eq $null) { $null } else { $false }
    if (Write-Status -ServiceName "Network Discovery" -IsEnabled $NetworkDiscoveryStatus) {
        $EnabledProtocols += "Network Discovery"
    }

    # Check PowerShell Execution Policy
    try {
        $ExecutionPolicy = Get-ExecutionPolicy -Scope LocalMachine
        if ($ExecutionPolicy -eq "Unrestricted" -or $ExecutionPolicy -eq "Bypass") {
            Write-Host "Execution Policy: $ExecutionPolicy (Consider setting to a more restrictive policy)" -ForegroundColor Red
            $EnabledProtocols += "ExecutionPolicy"
        } else {
            Write-Host "Execution Policy: $ExecutionPolicy (Adequately secure)" -ForegroundColor Green
        }
    } catch {
        Write-Host "Execution Policy: Status Unknown (Error encountered: $_)" -ForegroundColor Yellow
    }



    # Suggest Actions Based on Enabled Protocols
    if ($EnabledProtocols.Count -gt 0) {
        Write-Host "`nThe following protocols are enabled and should be disabled for hardening:" -ForegroundColor Yellow
        $EnabledProtocols | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }

        Write-Host "`nSuggestion: Run the following command to disable the enabled protocols:" -ForegroundColor Yellow
        $Command = "Set-Ghost" + ($EnabledProtocols | ForEach-Object { " -$_" })
        Write-Host $Command -ForegroundColor Cyan
    } else {
        Write-Host "`nAll protocols are already disabled. No action needed." -ForegroundColor Green
    }
}