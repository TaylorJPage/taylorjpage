# Get a list of all services
$services = Get-Service

# Create an empty array to store the results
$results = @()

# Loop through each service
foreach ($service in $services) {
    # Get the service's binary path name
    $binaryPathName = $service.BinaryPathName

    # If there are no quotes around the binary path name, add them
    if ($binaryPathName -notlike '"*' -and $binaryPathName -notlike '*"' -and $binaryPathName -like "* *") {
        # Add quotes around the binary path name
        $binaryPathName = '"' + $binaryPathName + '"'

        # Set the service's binary path name to the new value
        Set-Service -Name $service.Name -BinaryPathName $binaryPathName

        # Add the service to the results array
        $results += New-Object PSObject -Property @{
            ServiceName = $service.Name
            BinaryPathName = $binaryPathName
            Status = "Fixed"
        }
    }
}

# Export the results to a .txt file
$results | Out-File -FilePath "C:\Temp\UnquotedServicePaths.txt"
