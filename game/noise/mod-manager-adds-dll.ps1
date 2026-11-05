<#
.SYNOPSIS
    A mod manager adds a DLL to the game's folder, the same way a crack would.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$mod = Join-Path $GameDir 'winmm.dll'
Copy-Item 'C:\Windows\System32\winmm.dll' $mod
try {
    & (Join-Path $GameDir 'FakeQuest.exe') 2
    if ($LASTEXITCODE -ne 0) { throw "FakeQuest exited with $LASTEXITCODE" }
} finally {
    Remove-Item $mod -ErrorAction SilentlyContinue
}
