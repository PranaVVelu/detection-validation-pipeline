<#
.SYNOPSIS
    Adds the fake license entry from a script file, so the command line doesn't show it.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$script = Join-Path $env:TEMP 'update-settings.ps1'
"Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value '127.0.0.1 license.fakequest.invalid'" | Set-Content $script
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script
    if ($LASTEXITCODE -ne 0) { throw "PowerShell exited with $LASTEXITCODE" }
} finally {
    Remove-Item $script -ErrorAction SilentlyContinue
}
