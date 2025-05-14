Stop-Service -Name wuauserv -Force
Stop-Service -Name BITS -Force
Stop-Service -Name CryptSvc -Force

Rename-Item -Path "C:\windows\SoftwareDistribution" -NewName "SoftwareDistribution.old" -Force
Rename-Item -Path "C:\windows\system32\catroot2" -NewName "catroot2.old" -Force

Start-Service -Name wuauserv
Start-Service -Name BITS
Start-Service -Name CryptSvc

Get-Service -Name wuauserv, bits, cryptsvc