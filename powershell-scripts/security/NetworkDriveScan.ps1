# Load the Active Directory module
Import-Module ActiveDirectory

# Define the network drive path
$networkDrive = "\\***"

# Create an Excel COM object
$excel = New-Object -ComObject Excel.Application
$workbook = $excel.Workbooks.Add()
$worksheet = $workbook.Worksheets.Add()

# Set the initial row for writing data
$row = 1

# Function to list security groups for a folder in separate columns
function List-SecurityGroups($folder) {
    $acl = Get-Acl $folder.FullName
    $columnIndex = 2  # Starting from column B (2nd column)
    
    foreach ($ace in $acl.Access) {
        if ($ace.IdentityReference -like "BUILTIN\*" -or $ace.IdentityReference -like "NT AUTHORITY\*") {
            continue
        }

        $securityGroup = $ace.IdentityReference.Value

        # Check if the security group already has a column, if not, add a new column
        if ($worksheet.Cells.Item(1, $columnIndex).Value -eq $null) {
            $worksheet.Cells.Item(1, $columnIndex).Value = $securityGroup
            $worksheet.Cells.Item(1, $columnIndex).Font.Bold = $true
            $columnIndex++
        }

        # Find the row for the current folder and populate the corresponding column
        $rowIndex = $rowHash[$folder.FullName]
        $worksheet.Cells.Item($rowIndex, $columnIndex).Value = "X"  # Use "X" to indicate access
    }
}

# Recursive function to scan folders and subfolders
function Scan-Folders($folderPath) {
    $folder = Get-Item $folderPath
    List-SecurityGroups $folder
    $subfolders = Get-ChildItem -Path $folderPath -Directory
    foreach ($subfolder in $subfolders) {
        Scan-Folders $subfolder.FullName
    }
}

# Set column headers for Folder and each security group
$worksheet.Cells.Item(1, 1) = "Folder"

# Initialize a hashtable to track the row index for each folder
$rowHash = @{}

# Start the scanning process
Scan-Folders $networkDrive

# Save the Excel file
$excelFilePath = "C:\Temp\List.xlsx"
$workbook.SaveAs($excelFilePath)
$workbook.Close()
$excel.Quit()

# Release the Excel COM object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel)

Write-Host "Scanning and export complete. Results saved to $excelFilePath"
