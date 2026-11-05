<#
.SYNOPSIS
    Adds the fake license entry with PowerShell instead of a cmd redirect.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

& powershell.exe -NoProfile -Command "Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value '127.0.0.1 license.fakequest.invalid'"
if ($LASTEXITCODE -ne 0) { throw "PowerShell exited with $LASTEXITCODE" }
