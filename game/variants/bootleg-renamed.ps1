<#
.SYNOPSIS
    Runs the modified copy of the game under a different file name.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$folder = Join-Path $GameDir 'bootleg'
$copy = Join-Path $folder 'Quest.exe'
New-Item -ItemType Directory -Force -Path $folder | Out-Null
try {
    & (Join-Path $PSScriptRoot '..\scenarios\New-BootlegCopy.ps1') -Official (Join-Path $GameDir 'FakeQuest.exe') -Destination $copy
    & $copy 2
    if ($LASTEXITCODE -ne 0) { throw "The copy exited with $LASTEXITCODE" }
} finally {
    Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue
}
