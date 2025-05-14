# Set the output file path
$outputFile = "C:\Windows\Temp\permissions.txt"

# Get the list of installed services with a non-System32 file path
$services = Get-WmiObject -Query "SELECT PathName FROM Win32_Service WHERE NOT PathName LIKE '%System32%'"

# Iterate over each service and write its file path to the output file
foreach ($service in $services) {
    $service.PathName | Out-File -Append -FilePath $outputFile
}

# Iterate over each file path in the output file and apply permissions using icacls
foreach ($path in Get-Content -Path $outputFile) {
    # Get the permissions and ownership information for each file and subdirectory within the specified path
    $output = cmd.exe /c "icacls $path /T"

    # Parse the output to extract the name and type of the user who has full control
    $user = $output | ForEach-Object {
        if ($_ -like "*(F)*") {
            $matches = ($_ -split "`t")[-2]
            $matches = $matches -replace "^\(.*\) ", ""
            $matches = $matches -replace "\s*$", ""
            $matches
        }
    }
    $type = $output | ForEach-Object {
        if ($_ -like "*(F)*") {
            $matches = ($_ -split "`t")[-1]
            $matches = $matches -replace "^\(.*\) ", ""
            $matches = $matches -replace "\s*$", ""
            $matches
        }
    }

    # Write the name and type of the user with full control to the output file
    Add-Content -Path $outputFile -Value "Full control for: $user ($type)"
    Add-Content -Path $outputFile -Value "`n"
}
