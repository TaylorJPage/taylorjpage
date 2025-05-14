# Define the list of computers to query
$computers = @("")

foreach ($computer in $computers) {
  Write-Host "Local Administrators on $computer"
  $result = Invoke-Command -ComputerName $computer -ScriptBlock { Get-LocalGroupMember -Group "Administrators" }
  foreach ($admin in $result) {
    Write-Host "  - $($admin.Name)"
  }
}

$username = ""

foreach ($computer in $computers) {
  Invoke-Command -ComputerName $computer -ScriptBlock {
    Remove-LocalGroupMember -Group "Administrators" -Member $using:username
  }
}