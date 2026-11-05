<#
.SYNOPSIS
    Plants the DLL next to a copy of the game with a different file name.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$folder = Join-Path $GameDir 'renamed'
New-Item -ItemType Directory -Force -Path $folder | Out-Null
try {
    Copy-Item (Join-Path $GameDir 'FakeQuest.exe') (Join-Path $folder 'Quest.exe')
    Copy-Item 'C:\Windows\System32\winmm.dll' (Join-Path $folder 'winmm.dll')
    & (Join-Path $folder 'Quest.exe') 2
    if ($LASTEXITCODE -ne 0) { throw "The renamed game exited with $LASTEXITCODE" }
} finally {
    Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue
}
