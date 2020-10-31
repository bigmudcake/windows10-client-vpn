# Better Windows10 VPN Creation
PowerShell scripts for setting up Client VPN on Windows 10

Windows 10 only provides rudimentry setup when creating a client VPN with its builtin tools, and misses important operational settings.

These scripts attempt to:
  1. Pre-emptively fix issues with NAT-Traversal. Commonly pops up when clients use cellphone hotspots.
  2. Simplify creating a split tunnel connection.
  3. Prevent Windows from authenticating to network resources with the VPN credential.
  4. Create a rasphone desktop shortcut. It seems to behave better, and users find it easier to enter credentials into.
  5. Create the connection for all users. Especially useful for shared laptops or users prone to Windows user profile corruption.
  6. Set the VPN interface's metric to 1, so that the PC will use the VPN's DNS preferentially. Avoids problems where the local domain is the same as a public domain.

TIP: Remind your end users to not save their VPN password. Saving credentials can trigger the password protocol to change.

Please read the comments on the scripts before running them.

<b>Add_Windows10_VPN_WithPrompts.ps1:</b> Handy when you administer multiple client VPNs, such as at an MSP's help desk.    
  It will prompt for:

  1. VPN connection name.
      A new name will create a new connection. An existing name prompts for permission to delete and recreate.
  2. VPN concentrator address
  3. Pre-shared key
  4. Routes if enabled, and if asked, you pick split tunnel.

<b>Add_Windows10_VPN.ps1:</b> Edit the variables in the script yourself and then run. Good for large deployments. 
