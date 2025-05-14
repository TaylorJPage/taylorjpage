# Define the SCCM namespace
$sccmNamespace = "root\CCM"

# Get all the software updates on the client machine
$softwareUpdates = Get-WmiObject -Namespace $sccmNamespace -Class CCM_SoftwareUpdateAction

# Loop through each software update and download and install it
foreach ($softwareUpdate in $softwareUpdates) {
    Write-Host "Downloading and installing software update $($softwareUpdate.Name)"
    $softwareUpdate.Download()
    $softwareUpdate.Install()
}

# Get all the software packages on the client machine
$softwarePackages = Get-WmiObject -Namespace $sccmNamespace -Class CCM_SoftwarePackage

# Loop through each software package and download and install it
foreach ($softwarePackage in $softwarePackages) {
    Write-Host "Downloading and installing software package $($softwarePackage.Name)"
    $softwarePackage.Download()
    $softwarePackage.Install()
}
