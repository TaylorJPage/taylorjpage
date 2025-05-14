# Get the folder path from the user
$folderPath = Read-Host "Enter folder path"

# Get the ACL for the folder
$acl = Get-Acl -Path $folderPath

# Create a custom object with the ACL information
$permissions = $acl.Access | Select-Object IdentityReference, FileSystemRights

# Display the information in a grid view
$permissions | Out-GridView -Title "Folder Permissions for $folderPath"