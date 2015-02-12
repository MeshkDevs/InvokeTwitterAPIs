$webclient = New-Object System.Net.WebClient
$url = "https://github.com/MeshkDevs/InvokeTwitterAPIs/archive/master.zip"
Write-Host "Downloading InvokeTwitterAPIs PowerShell Module from $url" -ForegroundColor Cyan
$file = "$($env:TEMP)\InvokeTwitterAPIs.zip"
$webclient.DownloadFile($url,$file)
$targetondisk = "$($env:USERPROFILE)\Documents\WindowsPowerShell\Modules"
New-Item -ItemType Directory -Force -Path $targetondisk | out-null
$shell_app=new-object -com shell.application
$zip_file = $shell_app.namespace($file)
$destination = $shell_app.namespace($targetondisk)
$destination.Copyhere($zip_file.items(), 0x10)
Rename-Item -Path ($targetondisk+"\InvokeTwitterAPIs-master") -NewName "InvokeTwitterAPIs" -Force
Import-Module -Name InvokeTwitterAPIs
Get-Command -Module InvokeTwitterAPIs