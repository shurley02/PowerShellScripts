$appRegistrations = Get-AzureADApplication -All $true   

# Initialize an empty array to store the results
$results = @()

# Get the total number of application registrations for progress bar
$totalApps = $appRegistrations.Count

# Initialize a counter for progress tracking
$counter = 0

# Loop through each application registration
foreach ($app in $appRegistrations) {
    # Increment the counter
    $counter++

    # Display the progress bar
    Write-Progress -Activity "Processing Application Registrations" -Status "Processing $counter out of $totalApps" -PercentComplete (($counter / $totalApps) * 100)

    # Get the owners of the application
    $owners = Get-AzureADApplicationOwner -ObjectId $app.ObjectId

    # Filter applications that have no API permissions
    if ($app.RequiredResourceAccess.Count -eq 0) {
         # Create a custom object to store the application details and owners
         $appDetails = [PSCustomObject]@{
             ObjectId             = $app.ObjectId
             DisplayName          = $app.DisplayName
             RequiredResourceAccess = $app.RequiredResourceAccess
             CreatedDateTime      = $app.CreatedDateTime
             Owners               = ($owners | Select-Object -ExpandProperty DisplayName) -join ", "
         }
         # Add the custom object to the results array
         $results += $appDetails
     }
 }
