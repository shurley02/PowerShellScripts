#------------------------------------------------------------------------------  
#  
# PowerShell Source Code  
#  
# NAME:  
#    get-SPNReport.ps1 
#  
# VERSION:
#    1.2
#	3/11/2020 (Added the ability to search trusting domain with
#	-targetdomain switch - Sean Hurley)
#    1.1
#	3/11/2020 (Added the ability to search trusting forests with
#	-targetforest switch - Sean Hurley)
#    1.0
#	 5/17/2019
#
# Author: Sean Hurley (sean.c.hurley@disney.com)
#         
# Usage: get-SPNReport.ps1 -targetforest <forest name> (Can search any trusting forest)
#		 get-SPNReport.ps1 -targetdomain <domain name> (Will search specific trusting domain)
#		 get-SPNReport.ps1 without targetforest will search current logged in forest
#
# Description: This script when run with a user context in an active directory
# domain will search for all User accounts that have SPN objects for all
# domains in the forest.  
#------------------------------------------------------------------------------  

Param
(
    [Parameter(Mandatory=$false)][alias('forest')][string]$targetforest,
	[Parameter(Mandatory=$false)][alias('domain')][string]$targetdomain
)


function Get-Active-Directory-Forest-Object ([string]$ForestName, [System.Management.Automation.PsCredential]$Credential)
{    
    #if forest is not specified, get current context forest
    If (!$ForestName)     
    {        $ForestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name.ToString()    
    }        

    If ($Credential)     
    {        
        $credentialUser = $Credential.UserName.ToString()
        $credentialPassword = $Credential.GetNetworkCredential().Password.ToString()
        $adCtx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("forest", $ForestName, $credentialUser, $credentialPassword )
    }    
    Else     
    {        
        $adCtx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("forest", $ForestName)    
    }        

    $output = ([System.DirectoryServices.ActiveDirectory.Forest]::GetForest($adCtx))    

    Return $output
}


$script:report = @()


if($targetdomain -and $targetforest){
	write-host "You can only target a domain or a forest"
	break
	}
elseif($targetforest){
	$forest = Get-Active-Directory-Forest-Object $targetforest
	$domains = $forest.Domains.name
	$schema = $forest.schema.name
	}
elseif($targetdomain){
	$adCtx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain", $targetdomain)
	$output = ([System.DirectoryServices.ActiveDirectory.domain]::Getdomain($adCtx))
	$domaindn = $output.name
	$schema = (Get-Active-Directory-Forest-Object $output.forest).schema.name
	}
else{	
	$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
	$domains = $forest.Domains.name
	$schema = $forest.schema.name
	}
	


function getspns ($domainDN){
	Write-Progress -id 2 -Activity "Searching Domain for SPN's"
	$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domaindn")
	$search.filter = "(&(servicePrincipalName=*)(objectcategory=CN=Person,$schema))"
	$search.SearchScope = "Subtree"
	$results = $search.Findall()
	foreach( $object in $results ) {
		$objname = $object.name
		Write-Progress -id 3 -Activity "Getting Results"
		$obj = New-Object PSObject
		[string]$name = $object.properties.name
		[string]$dn = $object.Properties.distinguishedname
		[string]$ObjCat = $object.properties.objectcategory
		[string]$spn = $object.properties.serviceprincipalname
		[string]$Useraccountcontrol = $object.properties.useraccountcontrol
		[string]$pwdlastset = (w32tm.exe /ntte ($object.properties.pwdlastset)).split("-")[1]
		[string]$lastlogondate = (w32tm.exe /ntte ($object.properties.lastlogontimestamp)).split("-")[1]
		$obj | Add-Member NoteProperty 'Name'($name)
		$obj | Add-Member NoteProperty 'PasswordLastSet' ($pwdlastset)
		$obj | Add-Member NoteProperty 'LastLogonDate'($lastlogondate)
		$obj | Add-Member NoteProperty 'DN' ($dn)
		$obj | Add-Member NoteProperty 'Object Catagory' ($ObjCat)
		$obj | Add-Member NoteProperty 'servicePrincipalNames'($spn)
		$obj | Add-Member NoteProperty 'useraccountcontrol'($useraccountcontrol)
		
		$script:report += @($obj)
		Write-progress -id 3 -activity "Blash" -complete
	}
	Write-progress -id 2 -activity "Blash" -complete
}

if($targetdomain){
	write-Progress -id 1 -activity "Checking domain: $domaindn"
	getspns $domaindn
}

else{
	foreach ($domain in $domains){
		$currentdomain = $forest.Domains | ? {$_.Name -eq $domain}
		$domaindn = $currentdomain.GetDirectoryEntry().distinguishedName
		write-Progress -id 1 -activity "Checking domain: $domaindn"
		getspns $domaindn
	}
}

$date=(Get-Date -uformat "%m-%d-%Y-%H-%M")
$script:report | Export-CSV spnreport-$date.csv -NoTypeInformation
