# Ensure the AzureAD module is installed and imported
Import-Module AzureAD

# Connect to Azure AD if not already connected
if (-not (Get-AzureADTenantDetail -ErrorAction SilentlyContinue)) {
    Connect-AzureAD
}

# Retrieve all enterprise applications
$apps = Get-AzureADServicePrincipal -All $true
$total = $apps.Count
$counter = 0

# Initialize an array to store results
$enterpriseApps = @()

foreach ($app in $apps) {
    $counter++
    
    # Retrieve owners of the application with error handling
    try {
        $owners = Get-AzureADServicePrincipalOwner -ObjectId $app.ObjectId -ErrorAction Stop | Select-Object DisplayName, UserPrincipalName
    } catch {
        $owners = @()
    }
    
    $ownerNames = if ($owners) { $owners.DisplayName -join ", " } else { "No Owners" }
    $ownerEmails = if ($owners) { $owners.UserPrincipalName -join ", " } else { "No Emails" }
    
    # Store app details in an object
    $appDetails = [PSCustomObject]@{
        Name     = $app.DisplayName
        Owner    = $ownerNames
        OwnerEmail = $ownerEmails
        AppId    = $app.AppId
        ObjectId = $app.ObjectId
    }
    
    # Add to results array
    $enterpriseApps += $appDetails
    
    # Update progress bar
    $percentComplete = [math]::Round(($counter / $total) * 100, 2)
    Write-Progress -Activity "Retrieving Enterprise Applications" -Status "Processing $counter of $total" -PercentComplete $percentComplete
}

# Output the collected data
$enterpriseApps
