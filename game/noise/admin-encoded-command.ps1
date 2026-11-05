<#
.SYNOPSIS
    An admin tool runs a harmless encoded command, as some management software does.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Date'))
& powershell.exe -NoProfile -EncodedCommand $encoded | Out-Null
if ($LASTEXITCODE -ne 0) { throw "PowerShell exited with $LASTEXITCODE" }
