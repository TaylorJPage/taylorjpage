$serverInstance = ""
$databaseName = ""
$backupPath = "C:\Backups" #change this filepath when svcaccount is running the task on local machine to somewhere on the shared drive
$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$thirtyDaysAgo = (Get-Date).AddDays(-30)

Backup-SqlDatabase -ServerInstance $serverInstance -Database $databaseName -BackupFile "$backupPath\AccessControl_$dateTime.bak" -Initialize -CompressionOption On
$backupFiles = Get-ChildItem -Path $backupPath -Filter "AccessControl*.bak"

$backupFiles | ForEach-Object -Begin { $i = 0 } -Process {
    if ((Get-Date) - $_.CreationTime -gt [System.TimeSpan]::FromDays(30)){
        Remove-Item $_.FullName
    }
    $i++
}


#This script will backup the AccessControl SQL Database onto the shared drive (after modification), then delete backups older than 30 days to save drive space.