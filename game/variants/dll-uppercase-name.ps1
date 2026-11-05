<#
.SYNOPSIS
    Plants the DLL with an uppercase name, since Windows treats file names as case-insensitive.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$planted = Join-Path $GameDir 'WINMM.DLL'
Copy-Item 'C:\Windows\System32\winmm.dll' $planted
try {
    & (Join-Path $GameDir 'FakeQuest.exe') 2
    if ($LASTEXITCODE -ne 0) { throw "FakeQuest exited with $LASTEXITCODE" }
} finally {
    Remove-Item $planted -ErrorAction SilentlyContinue
}
