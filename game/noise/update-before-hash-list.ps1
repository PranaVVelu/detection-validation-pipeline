<#
.SYNOPSIS
    An official update changes the game's file before its hash reaches the official list.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$folder = Join-Path $GameDir 'update'
$updated = Join-Path $folder 'FakeQuest.exe'
New-Item -ItemType Directory -Force -Path $folder | Out-Null
try {
    & (Join-Path $PSScriptRoot '..\scenarios\New-BootlegCopy.ps1') -Official (Join-Path $GameDir 'FakeQuest.exe') -Destination $updated
    & $updated 2
    if ($LASTEXITCODE -ne 0) { throw "The updated game exited with $LASTEXITCODE" }
} finally {
    Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue
}
