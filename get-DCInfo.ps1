$Inventory = New-Object System.Collections.ArrayList

$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() 
$domains = $forest.domains
$numofdomains = $domains.count
$domainprog = 1

#Gather Data for All DC’s
foreach ($domain in $domains){
	$DCs = $domain.DomainControllers
	$numofDCs = $DCs.count
	$dcprog = 1
	write-Progress -id 1 -activity "Gathering DC's in: $domain" -Status "$domainprog of $numofdomains" -percentcomplete (($domainprog/$numofdomains)*100)
	Foreach ($domaincontroller in $DCs) {
		$dcname = $domaincontroller.name
		write-Progress -id 2 -activity "Checking computer: $dcname" -Status "$dcprog of $numofDCs" -percentcomplete (($dcprog/$numofDCs)*100)
		$Connection = Test-Connection $dcname -Count 1
		if($connection){
			#Get DC Info from computer that reported alive
			$DCInfo = New-Object System.Object
			$DCos = $domaincontroller.OSVersion
			$DCdomain = $domaincontroller.domain
			$DCsite = $domaincontroller.sitename
			$DCRoles = $domaincontroller.roles
			$DCIP = $domaincontroller.IPAddress
			#Write Data to temp VAR
			$DCInfo | Add-Member -MemberType NoteProperty -Name "Name" -Value $dcname
			$DCInfo | Add-Member -MemberType NoteProperty -Name "Alive" -Value $alive		
			$DCInfo | Add-Member -MemberType NoteProperty -Name "Domain" -Value $DCdomain
			$DCInfo | Add-Member -MemberType NoteProperty -Name "OperatingSystem" -Value $DCos
			$DCInfo | Add-Member -MemberType NoteProperty -Name "Site" -Value $DCsite
			$DCInfo | Add-Member -MemberType NoteProperty -Name "roles" -Value $DCRoles
			$DCInfo | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value $DCIP
		}

	#Write Data to Inventory VAR
	$Inventory.Add($DCInfo) | Out-Null
		$dcprog++
	}
	$domainprog ++
}

#Write Data to report
$date=(Get-Date -uformat "%m-%d-%Y-%H-%M")
$inventory | Export-CSV  DCInfo-$date.csv -NoTypeInformation
