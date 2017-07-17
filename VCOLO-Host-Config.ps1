### Working Verison - Powercli build of vColo Host Using 10 Gbps
### Date: 07/11/14
### Maintained By: fbanasic
### Version: 1.3

### Purpose: This PowerClI script is intended to be used for partial configuration of vColo "Seattle" Hosts 5.X.  Script will configure 
#            network services for FT, Storage, vMotion and necessary virtual machine networks.  
#
#  Assumptions: Script assumes that VMNIC0, VMNIC1, VMNIC2 and VMNIC3 are availabe uplinks on the host. 
#               The R730 hardware will use these vmnic's to refer to Intel 825999 10 Gbps a.k.a. X520 Network Adapter 
#  
#  NOTE: The following guide should be used to match vSwitch to VMNIC uplink.  
#        vSwitch0 - VMNIC0 & VMNIC2 - Host Management, Host vMotion, Host Fault Tolerance, and Guest VM Networks. 
#        vSwitch1 - VMNIC1 & VMNIC3 - Host Connectivity to Storage
#        vSwitch2 - NO NETWORK ADAPTERS - ZZ_InternalOnly or no network connectivity is expected!

#
# Recent modifications - fbanasic - Added new line (NearLine#:160) sets default Syslog error level reporting to 'warning' 
#                      - fbanasic - Add Nimble connection settings for iSCSI line:134to139
#                      - fbanasic - Added SSH start, SSH Host policy On during startup, SSH warning suppression
#                      - fbanasic - Added ESXi CoreDump to vCenter Server IP
#                      - fbanasic - Added detection for VMkernel Port Bindings and selections
#
            
### Unique Variable Declaration 
$Host_Server = "XXX.fhcrc.org"
$Host_Server_IQN = "iqn.1998-01.com.vmware:XXXXX"
$Host_vMotion01_IP = "10.111.88.XXX"
# $Host_vMotion02_IP = "10.111.88.XXX"
$Host_iSCSI01_IP = "10.111.134.XXX"
$Host_iSCSI02_IP = "10.111.134.XXX"
$Host_FT_IP = "172.26.10.XXX" 


### Network VLAN Variable Declaration
$Network_vMotion_VLANID = 42
$Network_iSCSI_VLANID = 42
$Network_Mgmt_VLANID = 42
$Network_FT_VLANID = 642
$Network_VM_Network_VLANID = 42
$Network_Scharp_VLANID = 3042

### Connect to Host Server
Write-Host ""
Write-Host "          Attempting to Connect to Host --> "$Host_Server -foregroundcolor green -backgroundcolor black
Write-Host ""
Connect-VIServer -Server $Host_Server 

If ((Get-VMhost $Host_Server).state -ne 'Maintenance') { 
Write-Host ""
Write-Host $Host_Server "is not in expected host state (Maintenance).  Attempting to set maintenance mode..." 
Set-VMHost -VMhost $Host_Server -State “Maintenance” -confirm:$false
Write-Host ""
}

### Management Network - Configure
Write-Host ""
Write-host "          Configuring Management Network..." -foregroundcolor green -backgroundcolor black
Write-Host ""
Set-VirtualSwitch vSwitch0 -Nic vmnic0,vmnic2 -confirm:$false
# Detect default installation settings.  
if ((Get-VMhost $Host_Server | Get-VirtualPortGroup -Name "VM Network" -ErrorAction SilentlyContinue)-ne $null) { 
Write-Host "Detected Default Configurations" 
Get-VirtualPortGroup -Name "VM Network" | Remove-VirtualPortGroup -confirm:$false
Write-Host "The Default 'VM Network' Portgroup was located and removed" 
Write-Host ""
}

### Host Connectivity to STORAGE - Configure - VSWITCH1
Write-Host ""
Write-Host "          Configuring Storage Settings..." -foregroundcolor green -backgroundcolor black
Write-Host ""
# Create vSwitch1
New-VirtualSwitch -VMHost $Host_Server -Name vSwitch1 -Nic vmnic1,vmnic3

# Create iSCSI-01, Set IP address, Set Active NIC, and Set VLANID
New-VMHostNetworkAdapter -VMHost $Host_Server -PortGroup iSCSI-01 -VirtualSwitch vSwitch1 -IP $Host_iSCSI01_IP -SubnetMask 255.255.255.0 
Get-VirtualPortGroup -name iSCSI-01 | Get-NicTeamingPolicy | Set-NicTeamingPolicy -MakeNicActive vmnic1
$iSCSI_01_PG = Get-VirtualPortGroup -Name iSCSI-01
Set-VirtualPortGroup -VirtualPortGroup $iSCSI_01_PG -VlanId $Network_iSCSI_VLANID

# Create iSCSI-02, Set IP address, Set Active NIC, and Set VLANID
New-VMHostNetworkAdapter -VMHost $Host_Server -PortGroup iSCSI-02 -VirtualSwitch vSwitch1 -IP $Host_iSCSI02_IP -SubnetMask 255.255.255.0 
Get-VirtualPortGroup -name iSCSI-02 | Get-NicTeamingPolicy | Set-NicTeamingPolicy -MakeNicActive vmnic3
$iSCSI_02_PG = Get-VirtualPortGroup -Name iSCSI-02
Set-VirtualPortGroup -VirtualPortGroup $iSCSI_02_PG -VlanId $Network_iSCSI_VLANID

### Host Fault Tolerance - Configure/Enable - VSWITCH0
Write-Host ""
Write-Host "          Configuring Host Fault Tolerance ..." -foregroundcolor green -backgroundcolor black
Write-Host ""
# Create FT Portgroup, Set IP address, Enable FT logging, and Set VLANID
New-VMHostNetworkAdapter -VMHost $Host_Server -PortGroup Host_FT -VirtualSwitch vSwitch0 -IP $Host_FT_IP -SubnetMask 255.255.255.0 
Get-VMHostNetworkAdapter | where {$_.PortGroupName -eq "Host_FT"} | Set-VMHostNetworkAdapter -FaultToleranceLoggingEnabled $true -confirm:$false
$Host_FT_PG = Get-VirtualPortGroup -Name Host_FT
Set-VirtualPortGroup -VirtualPortGroup $Host_FT_PG -VlanId $Network_FT_VLANID

### Host vMotion - Configure/Enable - VSWITCH0
Write-Host ""
Write-Host "          Configuring vMotion Settings..." -foregroundcolor green -backgroundcolor black
Write-Host ""
# Create vMotion-01 Portgroup, Set IP Address, Enable vMotion Service, and Set VLANID
New-VMHostNetworkAdapter -VMHost $Host_Server -PortGroup vMotion-01 -VirtualSwitch vSwitch0 -IP $Host_vMotion01_IP -SubnetMask 255.255.255.0 
Get-VMHostNetworkAdapter | where {$_.PortGroupName -eq "vMotion-01"} | Set-VMHostNetworkAdapter -VMotionEnabled $true -confirm:$false
$vMotion_01_PG = Get-VirtualPortGroup -Name vMotion-01
Set-VirtualPortGroup -VirtualPortGroup $vMotion_01_PG -VlanId $Network_vMotion_VLANID

### THE FOLLOWING SECTION HAS NOT BEEN CLEARED FOR PRODUCTION USE
#
# Multiple VMkernel vMotion Configuration - VSWITCH0 
#
# Create vMotion-02 Portgroup, Set IP Address, Enable vMotion Service, and Set VLANID
#New-VMHostNetworkAdapter -VMHost $Host_Server -PortGroup vMotion-02 -VirtualSwitch vSwitch0 -IP $Host_vMotion02_IP -SubnetMask 255.255.255.0
#Get-VMHostNetworkAdapter | where {$_.PortGroupName -eq "vMotion-02"} | Set-VMHostNetworkAdapter -VMotionEnabled $true -confirm:$false
#$vMotion_02_PG = Get-VirtualPortGroup -Name vMotion-02
#Set-VirtualPortGroup -VirtualPortGroup $vMotion_02_PG -VlanId $Network_vMotion_VLANID
#
# Set NIC Teaming Policy for vMotion Portgroups
#Get-VirtualPortGroup -name vMotion-01 | Get-NicTeamingPolicy | Set-NicTeamingPolicy -MakeNicActive vmnic0 
#Get-VirtualPortGroup -name vMotion-02 | Get-NicTeamingPolicy | Set-NicTeamingPolicy -MakeNicActive vmnic2


### Guest Virtual Machine Network - Configure - VSWITCH0
Write-Host ""
Write-Host "          Configuring Guest VM_Networks..." -foregroundcolor green -backgroundcolor black
Write-Host ""
Get-VirtualSwitch -Name vSwitch0 | New-VirtualPortGroup -Name "VM_Network" -VLANID $Network_VM_Network_VLANID
Get-VirtualSwitch -Name vSwitch0 | New-VirtualPortGroup -Name "Scharp" -VLANID $Network_Scharp_VLANID

### Guest VM Isolation Network - Configure - VSWITCH2
Write-Host ""
Write-Host "          Configuring InternalOnly Network..." -foregroundcolor green -backgroundcolor black
Write-Host ""
New-VirtualSwitch -VMHost $Host_Server -Name vSwitch2
Get-VirtualSwitch -Name vSwitch2 | New-VirtualPortGroup -Name "ZZ_InternalOnly"

### Software iSCSI/IQN - Configure
Write-Host ""
Write-Host "          Configuring Software iSCSI..." -foregroundcolor green -backgroundcolor black
Write-Host ""
Get-VMHostStorage -VMHost $Host_Server | Set-VMHostStorage -SoftwareIScsiEnabled $True
Get-VMHostHba -VMHost $Host_Server -Type IScsi | Set-VMHostHBA -IScsiName $Host_Server_IQN

#Identifies HBA number for the iSCSI Software Adapter and Assigns VMKernel Port Bindings
$HBANumber = Get-VMHostHba -VMHost $Host_Server -Type iSCSI | %{$_.Device}
$esxcli.iscsi.networkportal.add($HBANumber, $true, 'vmk1')
$esxcli.iscsi.networkportal.add($HBANumber, $true, 'vmk2')

#### Storage - Configure iSCSI with Nimble SAN connection settings(LoginTimeout/NoopOutTimeout/NoopOutInterval)
$hbahost = Get-VMHostHba -VMHost $Host_Server -Type iScsi | Where {$_.Model -eq "iSCSI Software Adapter"}
$esxcli = Get-EsxCli -VMhost $Host_Server
$esxcli.iscsi.adapter.param.set($hbahost.device,$false,'LoginTimeout','30')
$esxcli.iscsi.adapter.param.set($hbahost.device,$false,'NoopOutTimeout','30')
$esxcli.iscsi.adapter.param.set($hbahost.device,$false,'NoopOutInterval','30')
$esxcli.storage.nmp.satp.rule.add($null, $null, “Nimble Storage Policy”, $null, $null, $null, “NimbleSAN”, $null, “VMW_PSP_RR”, “iops=1”, “VMW_SATP_ALUA”, $null, $null, “Nimble”)

### Storage - Attach to Nimble
Write-Host ""
Write-Host "          Attaching to iSCSI Storage..." -foregroundcolor green -backgroundcolor black
Write-Host ""
Get-VMHost | Get-VMHostHba -Type iScsi | New-IScsiHbaTarget -Address "10.111.134.62"
Get-VMHost | Get-VMHostStorage -RescanAllHba

### Storage - Configure Round Robin
Write-Host ""
Write-Host "          Configuring RoundRobin Policy on Storage..." -foregroundcolor green -backgroundcolor black
Write-Host ""
Get-VMhost | Get-ScsiLun -CanonicalName "eui.*" -LunType disk | Set-ScsiLun -MultipathPolicy "RoundRobin"

### NTP - Configure
Write-Host ""
Write-Host "          Configuring NTP settings..." -foregroundcolor green -backgroundcolor black
Write-Host ""
Add-VmHostNtpServer -NtpServer "clock.fhcrc.org"
Get-VMHostFirewallException "NTP Client" | Set-VMHostFirewallException -enabled:$true
Get-VmHostService -VMHost $Host_Server | Where-Object {$_.key -eq “ntpd“} | Start-VMHostService

### SysLog to Junoite - Configure "Warning" level reporting
Write-Host ""
Write-Host "          Configuring SysLog to Junoite..." -foregroundcolor green -backgroundcolor black
Write-Host ""
Get-VMHost | Get-VMHostFirewallException |?{$_.Name -eq 'syslog'} | Set-VMHostFirewallException -Enabled:$true
Set-VMHostSysLogServer -SysLogServer 'loghost.fhcrc.org:514' -VMHost $Host_Server -confirm:$false
Set-VMHostAdvancedConfiguration -VMHost $Host_Server -NameValue @{'Config.HostAgent.log.level'='warning'}

### Enable SNMP and add Community Info
Write-Host ""
Write-Host "          Configuring SNMP and Community Info..." -foregroundcolor green -backgroundcolor black
Write-Host ""
Get-VMHostsnmp | Set-VMHostsnmp -readonlycommunity 'rrcesowas'
Get-VMHostsnmp | Set-VMHostsnmp -Enabled:$True

### Enable SSH, Ensure SSH starts up with Host and suppress ssh console warning messages. 
Write-Host ""
Write-Host "          Configuring SSH..." -foregroundcolor green -backgroundcolor black
Write-Host ""
Get-VMHost $Host_Server | Get-VMHostService | Where { $_.Key -eq “TSM-SSH”} | Start-VMHostService
Get-VMHost $Host_Server | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"} | Set-VMHostService -policy "on" -Confirm:$false
Get-VMHost $Host_Server | Set-VmHostAdvancedConfiguration -Name UserVars.SuppressShellWarning -Value 1 -Confirm:$false

### Enable ESXi CoreDump to vCenter Server IP
Write-Host ""
Write-Host "          Configuring ESXi CoreDump..." -foregroundcolor green -backgroundcolor black
Write-Host ""
$esxcli = Get-EsxCli -VMhost $Host_Server
$esxcli.system.coredump.network.set($null,"vmk0","140.107.88.150",6500)
$esxcli.system.coredump.network.set(1)
$esxcli.system.coredump.network.get()


### Clearing ad-hoc variables...
$Host_FT_PG = $null
$iSCSI_01_PG = $null
$iSCSI_02_PG = $null
$vMotion_01_PG = $null
$vMotion_02_PG = $null

### Restart Host
Write-Host ""
Write-Host "          Script processing completed.   The host "$Host_Server "has initiated reboot..." -foregroundcolor yellow -backgroundcolor red
Write-Host ""
If ((Get-VMhost $Host_Server).state -ne 'maintenance') { 
Set-VMHost -VMhost $Host_Server -State “Maintenance” -confirm:$false
}
Restart-VMHost -VMhost $Host_Server
Disconnect-VIServer $Host_Server -confirm:$false
### Script End