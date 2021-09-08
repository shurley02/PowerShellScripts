[cmdletbinding()]            
param(
    [switch] $reportvalid
)

Write-Host 'Gathering app information...'
$applications = Get-AzADApplication

Write-host "Gathering application expiration information..."
$appWithCredentials = @()
$appWithoutCredentials  = @()
$appcount = $applications.count
$appprog = 1

foreach($app in $applications){
	$appname = $app.displayname
	write-Progress -id 1 -activity "Fetching information for application $appname" -Status "$appprog of $appcount" -percentcomplete (($appprog/$appcount)*100)
	$appcreds = Get-AzADAppCredential -ApplicationId $app.applicationid | Select-Object -Property @{Name = 'DisplayName'; Expression = { $app.DisplayName } }, @{Name = 'ObjectId'; Expression = { $app.ObjectId } }, @{Name = 'ApplicationId'; Expression = { $app.ApplicationId } }, @{Name = 'KeyId'; Expression = { $_.KeyId } }, @{Name = 'Type'; Expression = { $_.Type } }, @{Name = 'StartDate'; Expression = { $_.StartDate -as [datetime] } }, @{Name = 'EndDate'; Expression = { $_.EndDate -as [datetime] } }
	if($appcreds){
		$appWithCredentials += $appcreds}
	else{
		$appWithoutCredentials += $appcreds}
	$azappOwners = Get-AzureADApplicationOwner -ObjectId $app.ObjectId
	if($azappOwners){
		$appowners = @()
		foreach($appowner in $azappOwners){$appowners += $appowner.Userprincipalname}
		$appcreds | Add-Member -MemberType NoteProperty -Name 'Application_Owners' -Value ($appOwners| Out-String).Trim()
		}
	else{$appcreds | Add-Member -MemberType NoteProperty -Name 'Application_Owners' -Value "No Application Owners"}
	$azadserviceprincipal = Get-AzADServicePrincipal -ApplicationId $app.applicationid
	if($azadserviceprincipal){
		$spobjectid = $azadserviceprincipal.id
		$azSPOwners = Get-AzureADServicePrincipalOwner -ObjectId $spobjectid
		if($azSPOwners){
			$spowners = @()
			foreach($spowner in $azSPOwners){$spOwners += $spowner.userprincipalname -join ','}
			$appcreds | Add-Member -MemberType NoteProperty -Name 'ServicePrincipal_Owners' -Value ($SPOwners| Out-String).Trim()
			}
		else{$appcreds | Add-Member -MemberType NoteProperty -Name 'ServicePrincipal_Owners' -Value "No Service Principal Owners"}
		$appcreds | Add-Member -MemberType NoteProperty -Name 'ServicePrincipal_ObjectID' -Value $spobjectid}
	else{$appcreds | Add-Member -MemberType NoteProperty -Name 'ServicePrincipal_ObjectID' -Value "No Service Principal"}
	$appprog ++
	}


 
Write-Host 'Validating expiration data...'
$today = (Get-Date).ToUniversalTime()
$limitDate = $today.AddDays(30)
$longDate = $today.AddDays(730)
$appWithCredentials | Sort-Object EndDate | % {
    if ($_.EndDate -lt $today) {
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Expired'
    }
    elseif ($_.EndDate -le $limitDate) {
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'ExpiringSoon'
    }
	elseif ($_.EndDate -ge $longdate) {
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'ExpirationTooLong'
    }
    else {
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Valid'
    }
}

$date=(Get-Date -uformat "%m-%d-%Y-%H-%M")

if($reportvalid){
	$validAppCredentials = $appWithCredentials | ? { $_.Status -eq 'valid'} | Sort-Object -Property DisplayName
	$validAppCredentials | export-csv c:\users\3hurls018\desktop\validreport.csv
	}
else{
	#$ExpiringAppCredentials = $appWithCredentials #| ? { $_.Status -eq 'Expired' -or $_.Status -eq 'ExpiringSoon' -or $_.Status -eq 'ExpirationTooLong'} | Sort-Object -Property DisplayName
	#$appWithoutCredentials | export-csv c:\users\3hurls018\desktop\nocreds.csv
	$appWithCredentials | Select * | export-csv c:\users\3hurls018\desktop\AppCredentialReport-$date.csv
}
