#------------------------------------------------------------------------------  
#  
# PowerShell Source Code  
#  
# NAME:  
#    Get-appAccessPolicySettings.ps1 
#  
# VERSION:
#    1.0
#
# Author: Sean Hurley (sean.c.hurley@disney.com)
#         
# Usage: 
#
# 
#------------------------------------------------------------------------------  

Param
(
    [Parameter(Mandatory=$true)][alias('ApplicationID')][string]$azureappid
)

$appScopeGroup = Get-DistributionGroup -erroraction silentlycontinue `$appScope_$azureappid
$appAccessPolicy = Get-ApplicationAccessPolicy | ?{$_.ScopeName -like "*$azureappid"}

if(!$appScopeGroup){
	Write-host -foregroundcolor red "Application Access Scope Not found for"
	Write-host -foregroundcolor yellow "AppID: $azureappid"
	break
	}
else{	
	write-host -foregroundcolor green "Application Access Scope Group Found: " 
	Write-Host -foregroundcolor Yellow $appscopegroup.identity
	Write-host ""

	$AppScopeMailboxes = Get-DistributionGroupMember $appscopegroup.identity
	Write-host -foregroundcolor green "Application Access Mailboxes: "
	$appscopemailboxes | select name,PrimarySmtpAddress,Title
	}
	
if(!$appAccessPolicy){
	Write-host -foregroundcolor red "Application Access Policy Not found for"
	Write-host -foregroundcolor yellow "AppID: $azureappid"
	break
	}
else{	
	write-host -foregroundcolor green "Application Access Policy Found: " 
	Write-Host -foregroundcolor Yellow $appAccessPolicy.ScopeName
	Write-host ""
	}
