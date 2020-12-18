# Author: Nash King / @gammacapricorni and bigmudcake
# By default, this script creates an -AllUserConnection in the public phonebook
# This is due to specific needs of my primary customers.
# To make a single user connection, do the following:
#   change $AllUsers below to 'n' or '' to prompt user.

# Return True if this script is "Run as Administrator" or from an administrator account
$IsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

# Declare each variable for tidiness.
$Continue = $Holder = $PresharedKey = $ServerAddress = $VpnExists = $RootPbkPath = $DesktopPath = ''
$Subnets = @()


############################################################################################################
################### PLEASE ADJUST THE VALUES BELOW TO MATCH YOUR VPN REQUIREMENTS ##########################

# Set $ConnectionName to a predetermined name and automatically delete existing connection with same name. 
# Leave as '' to prompt user.
$ConnectionName = ''

# Set $ServerAddress to a FQDN of the VPN server or its public IP address. 
# Leave as '' to prompt user.
$ServerAddress = ''

# Set $PresharedKey to a predetermined VPN secret shared key. 
# Leave as '' to prompt user.
$PresharedKey = ''

# Set $SplitTunnel below to 'y' or 'n' to enable/disable Split Tunnelling without prompting the user. 
# Leave as '' to prompt user.
$SplitTunnel = ''

# Set $MoreRoutes below to 'n' if your using a DHCP server to pass routes to the VPN client at runtime 
# as DHCP option 249 (classless address), and you do not wish to prompt the user to enter extra IP routes.  
# It is recommended you set to 'n' and setup a DHCP server for routes as it shields complexity from users. 
# Leave as '' to prompt user to add static IP routes.
$MoreRoutes = 'n'

# Set $AllUsers below to enable creation of VPN Connection for All Users ('y') 
# or Local User only ('n') without prompting the user.
# If you set this to 'y' then this script must be run with administrator rights.
# Leave as '' to prompt user.
$AllUsers = ''

# Set $CreateShortcut below to 'y' to allow script to create a shortcut to the VPN Connection on the Desktop.
# When a shortcut is created, users can start the VPN Connection by double-clicking on its icon.
# Set as '' or 'n' for no  Shortcut. Users must click on network/wifi in tray, then select the VPN Connection from listing.
$CreateShortcut = 'y'

# Set below to a full file path to the Windows Application that you want to trigger the VPN Connection to start automatically.
# Ignored if VPN creation is set 'y' for All Users.
# Leave empty to always start VPN Connection manually.
$TriggerApp = '' 

# Set below to a DNS suffix used for the internal network that is matched against the active primary network 
# connection so the VPN connection IS NOT triggered when the application specified in $TriggerApp is run. 
# Ignored if VPN creation is set 'y' for All Users.
# Leave emty to always trigger VPN connection on all primary networks.
$TriggerSuffix = ''

# Set any extra settings to be applied for the new VPN connection.
# AuthenticationMethod either be "Pap", "Chap", "MSChapv2", "Eap", or "MachineCertificate".
$VPNExtraArguments = @{ 
	TunnelType = 'L2tp'
	AuthenticationMethod = 'MSChapv2' 
	EncryptionLevel = 'Optional' 
	RememberCredential = $False
}

################# END OF VALUES TO ADJUST - DO NOT CHANGE ANYTHING BELOW THIS LINE #########################
############################################################################################################





# override AllUserCheck if there are no Administrator Rights as VPN can then only be created for Local User.
if ($IsAdmin -eq $False) {
	$AllUsers = 'n'
}
else {
	Write-Host -ForegroundColor Yellow "`nNOTE: This script is running with Administrator Rights."
}

# Set whether VPN Connection is created for All Users or Local User only
Do {
    # only Prompt for $AllUsers if not already set.
    If (($AllUsers -ne 'y') -and ($AllUsers -ne 'n')) {
        $AllUsers = Read-Host -Prompt "`nCreate this VPN Connection for All Users? (y/n)"
	}
	If ($AllUsers -eq 'y') {
		# Set paths and variables for all users scope (requires script run with administrator rights)
		Write-Host -ForegroundColor Yellow "`nAbout to create a VPN Connection for All Users of this Computer."
		$AllUsers = $True
		$RootPbkPath = $env:PROGRAMDATA
		$DesktopPath = "$env:Public\Desktop"
	}
	elseif ($AllUsers -eq 'n') {
		# Set paths and variables for this user only
		Write-Host -ForegroundColor Yellow "`nAbout to create a VPN Connection for this Windows User only."
		$AllUsers = $False
		$RootPbkPath = $env:APPDATA
		$DesktopPath = [Environment]::GetFolderPath("Desktop") # allows for redirected desktops
	}
} Until (($AllUsers -eq $True) -or ($AllUsers -eq $False))


# Abort if AllUserCheck is set to 'y' and there are no Administrator Rights on this script
if (($IsAdmin -eq $False) -and ($AllUsers -eq 'y')) {
	Write-Host -ForegroundColor Red "`nERROR: This script must be run with Administrator Rights if VPN Connection is created in 'All User' mode!"
	Pause
	exit
}


# Phonebook path for all user connections.
$PbkPath = "$RootPbkPath\Microsoft\Network\Connections\Pbk\rasphone.pbk"

# If no VPNs, rasphone.pbk may not already exist
# If file does not exist, then create an empty placeholder.

# Placeholder will be overwritten when new VPN is created.
If ((Test-Path $PbkPath) -eq $False) {
    $PbkFolder = "$RootPbkPath\Microsoft\Network\Connections\pbk\"
    if ((Test-Path $PbkFolder) -eq $True) {
        New-Item -path $PbkFolder -name "rasphone.pbk" -ItemType "file" | Out-Null
    }
    else {
        $ConnectionFolder = "$RootPbkPath\Microsoft\Network\Connections\"
        New-Item -path $ConnectionFolder -name "pbk" -ItemType "directory" | Out-Null
        New-Item -path $PbkFolder -name "rasphone.pbk" -ItemType "file" | Out-Null
    }
}

# Reminder so looping prompts doesn't confuse user.
Write-Host -ForegroundColor Yellow "Prompts will loop until you enter a valid response."

# Overwrite existing connection without prompting if name has been preset at start of script
If ($ConnectionName -ne '') {
	$Continue = 'y'
}

# Get VPN connection name if not preset at start of script.
Do {
	If ($ConnectionName -eq '') {
		$ConnectionName = Read-Host -Prompt "`nName of VPN Connection"
	}
	$ConnectionName = $ConnectionName.Trim()
} While ($ConnectionName -eq '')

# Create a hash table for splatting with common base parameters
$HashBase = @{ 
	Name = $ConnectionName 
	AllUserConnection = $AllUsers
}

# Check if matching VPN already exists.
$HashSearch = @{ Pattern = "[$ConnectionName]"; }
$VpnExists = (Get-Content $PbkPath | Select-String @HashSearch -SimpleMatch -Quiet)

# If VPN exists
If ($VpnExists -eq $True) {
    Do {
		# Ask to overwrite
		if (($Continue -ne 'n') -and ($Continue -ne 'y')) {
			$Continue = Read-Host -Prompt "`nVPN already exists. Overwrite? (y/n)"
		}
        Switch ($Continue) {
            'y' {
                Try {
                    Remove-VpnConnection @HashBase -Force
                    Write-Host -ForegroundColor Yellow "`nDeleted old VPN Connection: $ConnectionName"
                }
                Catch {
					Write-Host -ForegroundColor Red "`nERROR: Unable to delete connection named $ConnectionName"
					Pause
                    exit
                }
            }
            'n' {
				Write-Host -ForegroundColor Yellow "`nKeeping old VPN. Exiting script..."
				Pause
                exit
                }
            }
    } Until ($Continue -eq 'n' -or $Continue -eq 'y')
}


# Prompt for FQDN of VPN server or its public IP address.
Do {
	If ($ServerAddress -eq '') {
		$ServerAddress = Read-Host -Prompt "`nHost name or IP address"
	}
	$ServerAddress = $ServerAddress.Trim()
} While ($ServerAddress -eq '')

Do {
	If ($PresharedKey -eq '') {
		$PresharedKey = Read-Host -Prompt "`nPre-shared key"
	}
	$PresharedKey = $PresharedKey.Trim()
} While ($PresharedKey -eq '')

# Ask if split or full tunnel
Do {
    # only Prompt for $SplitTunnel if not already set at top of script.
    If (($SplitTunnel -ne 'y') -and ($SplitTunnel -ne 'n')) {
        $SplitTunnel = Read-Host -Prompt "`nSplit tunnel? (y/n)"
    }
    if ($SplitTunnel -eq 'y') {
		$SplitTunnel = $True
	}
	elseif ($SplitTunnel -eq 'n') {
		$SplitTunnel = $False
	}
} Until (($SplitTunnel -eq $True) -or ($SplitTunnel -eq $False))


# Create the new VPN connection 
# Splatting parameters with hash tables and extra arguments defined at top of script
$HashArguments = @{ 
	Force = $True
	PassThru = $True
}
Try {
	Add-VpnConnection @HashBase @VPNExtraArguments @HashArguments
}
Catch {
	Write-Host -ForegroundColor Red "`nERROR: Unable to create connection named `"$ConnectionName`""
	Pause
	exit
}
Write-Host -ForegroundColor Yellow "VPN Connection Created for `"$ConnectionName`""

# Note: Some PCs get angry w/o a short rest after processing Add-VPNConnection
Start-Sleep -m 100

# If split tunnel, you may need to add routes for the remote subnets
# Use CIDR format: 192.168.5.0/24
If (($SplitTunnel -eq $True) -and ($MoreRoutes -eq '')) {
    # Loop until at least one valid route is created
    Do {
        # Prompt for the subnet
        Do {
            # Loop until non-blank result given
            Do {
                $Holder = Read-Host -Prompt "`nVPN Subnet (e.g. 192.168.5.0/24)"
				$Holder = $Holder.Trim()
			} Until ($Holder -ne '')

            # Prompt user to review and approve route
            Do {
                $RouteCheck = Read-Host -Prompt "`nAdd subnet $Holder (y/n)"
			} Until (($RouteCheck -eq 'n') -or ($RouteCheck -eq 'y'))
			
			# Create subnet hash for splatting DestinationPrefix parameter
			$HashSubnet = @{ DestinationPrefix = $Holder; }

            # If route is approved, try to add
            if ($RouteCheck -eq 'y') {
                Try {
                    Add-Vpnconnectionroute @HashBase @HashSubnet
                    Write-Host "`nAdding subnet: $Holder"
                    $Subnets += $Holder
                }
                Catch {
                    Write-Host -ForegroundColor Red "`nInvalid route: $Holder."
                    If ($Subnets.count -eq 0) {
                        Write-Host -ForegroundColor Yellow "`nWARNING: No valid subnets have been added to $ConnectionName"
                    }
                }
            }
            $Holder = ''
            # Prompt to add another route
            Do {
                $MoreRoutes = Read-Host -Prompt "`nAdd another route? (y/n)"
            } Until ($MoreRoutes -eq 'y' -or $MoreRoutes -eq 'n')
        # End loop after no more routes
        } While ($MoreRoutes -eq 'y')

    # End the loop only once at least one valid subnet has been added
    } Until ($Subnets.count -ge 1)
}

# Load the RASphone.pbk file into a line-by-line array
$Phonebook = (Get-Content -path $PbkPath)

# Index for line where the connection starts.
$ConnectionIndex = 0

# Locate the array index for the [$ConnectionName] saved connection.
# Ensures that we only edit settings for this particular connection.
for ($counter=0; $counter -lt $Phonebook.Length; $counter++) {
    if($Phonebook[$counter] -eq "[$ConnectionName]") {
        # Set $ConnectionIndex var since $counter only exists inside loop
        $ConnectionIndex = $counter
        # Break since we've got our index now
        break
    }
}


# Starting at the $ConnectionName connection:
# 1. Set connection to use Windows Credential (UseRasCredentials)
# 2. Force client to use VPN-provided DNS first (IpInterfaceMetric)
#      Some companies have local domains that overlap with valid domains
#        on the Internet. If VPN-provided DNS can resolve names on the local domain,
#        then end user PC will get the correct IP addresses for private servers.
# 3. Disable "File and Printer Sharing for Microsoft Networks" on VPN Connection.

for ($counter=$ConnectionIndex; $counter -lt $Phonebook.Length; $counter++) {
    # Set RASPhone.pbk so that the Windows credential is used to
    # authenticate to servers.
    if ($Phonebook[$counter] -eq 'UseRasCredentials=1') {
        $Phonebook[$counter] = 'UseRasCredentials=0'
    }
    # Set RASPhone.pbk so that VPN adapters are highest priority for routing traffic.
    # Comment out if you don't want to use VPN-provided DNS for Internet domains.
    elseif ($Phonebook[$counter] -eq 'IpInterfaceMetric=0') {
        $Phonebook[$counter] = 'IpInterfaceMetric=1'
	}
	# Disable "File and Printer Sharing for Microsoft Networks" on VPN Connection
    elseif ($Phonebook[$counter] -eq 'ms_server=1') {
        $Phonebook[$counter] = 'ms_server=0'
	}
	# break out of loop at end of entries for this VPN connection
	elseif ($Phonebook[$counter] -eq 'AreaCode=') {
		break
	}
}
# Save modified phonebook overtop of RASphone.pbk
Set-Content -Path $PbkPath -Value $Phonebook


# Set Auto Triggering of the VPN via a specified Application 
if (($TriggerApp -ne '') -or ($TriggerSuffix -ne '')) {
	if ($AllUsers -eq $True) {
		Write-Host -ForegroundColor Yellow "`nAll User setup specified, Ignoring setup of VPN Connection Triggers"
	}
	else {
		Write-Host -ForegroundColor Yellow "`nSetup VPN Connection Triggers for Local User"
		$HashTriggerParams = @{ 
			ConnectionName = $ConnectionName
			Force = $True
			PassThru = $False
		}
		Try {
			If (($TriggerApp -ne '') -and ((Test-Path $TriggerApp) -eq $True)) {
				$HashTriggerApp = @{ ApplicationID = $TriggerApp; }
				Add-VpnConnectionTriggerApplication @HashTriggerParams @HashTriggerApp
			}
			if ($TriggerSuffix -ne '') {
				$HashTriggerSuffix = @{ DnsSuffix = $TriggerSuffix; }
				Add-VpnConnectionTriggerTrustedNetwork @HashTriggerParams @HashTriggerSuffix
			}
		}
		Catch {
			Write-Host -ForegroundColor Red "`nUnable to Add Trigger Settings for VPN Connection."
		} 
	}
}
if ($AllUsers -eq $False) {
	Get-VpnConnectionTrigger -ConnectionName $ConnectionName
}

# Create desktop shortcut that uses using rasphone.exe
# Provides a static box for end users to type their user name/password into.
# Avoids Windows 10 overlay problems such as showing "Connecting..." even
# after a successful connection.
if ($CreateShortcut -eq 'y') {
	Try {
		$ShortcutFile = "$DesktopPath\$ConnectionName.lnk"
		$WScriptShell = New-Object -ComObject WScript.Shell
		$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
		$Shortcut.TargetPath = "rasphone.exe"
		$Shortcut.Arguments = "-d `"$ConnectionName`""
		$ShortCut.WorkingDirectory = "$env:SystemRoot\System32\"
		$Shortcut.Save()
		Write-Host -ForegroundColor Yellow "Created VPN Shortcut on the Desktop. Please use this Shortcut to start your VPN"
	}
	Catch {
		Write-Host -ForegroundColor Red "`nUnable to create VPN shortcut."
	}
}
else {
	Write-Host -ForegroundColor Yellow "To Start VPN Connection click Network/Wifi icon on Taskbar and select it from Network List"
}

# Prevent Windows 10 problem with NAT-Traversal (often on hotspots)
# See https://documentation.meraki.com/MX/Client_VPN/Troubleshooting_Client_VPN#Windows_Error_809
# for more details
# Splatting hash table with Registry Parameters
$HashRegistryParams = @{ 
	Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent'
	Name = 'AssumeUDPEncapsulationContextOnSendRule'
	Value = '2'
	PropertyType = 'DWORD'
}
if ($IsAdmin -eq $True) {
	Try {
		# First create registry path if it doesnt exist
		IF(!(Test-Path $HashRegistryParams['Path'])) {
			New-Item -Path $HashRegistryParams['Path'] -Force | Out-Null
		}
		# Update registry key with necessary value
	    New-ItemProperty @HashRegistryParams -Force | Out-Null
	    Write-Host -ForegroundColor Yellow "`nIf this is the first time a Windows 10 client VPN has been setup, reboot computer to finish setup."
	}
	Catch {
	    Write-Host -ForegroundColor Red "`nUnable to create registry key."
	}
}
else {
	Write-Host -ForegroundColor Yellow "`nIf this is the first time a Windows 10 client VPN has been setup,`n please add the following to the System Registry"
	$HashRegistryParams.GetEnumerator() | ForEach-Object{
        $message = "     {0} = {1}" -f $_.key, $_.value
        Write-Host $message 
	}
}
Pause
exit