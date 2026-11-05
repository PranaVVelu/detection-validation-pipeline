<#
.SYNOPSIS
    Runs the fake game with and without a planted DLL. Only run on a disposable VM.
.DESCRIPTION
    The planted DLL is an unmodified copy of the signed Windows file, so it behaves
    normally. What's being tested is where it loads from.
#>
param(
    [Parameter(Mandatory)][ValidateSet('attack', 'benign')][string]$Scenario,
    [Parameter(Mandatory)][string]$GameDir
)
$ErrorActionPreference = 'Stop'

$planted = Join-Path $GameDir 'winmm.dll'
if ($Scenario -eq 'attack') {
    Copy-Item 'C:\Windows\System32\winmm.dll' $planted
}
try {
    & (Join-Path $GameDir 'FakeQuest.exe') 2
    if ($LASTEXITCODE -ne 0) { throw "FakeQuest exited with $LASTEXITCODE" }
} finally {
    if (Test-Path $planted) { Remove-Item $planted }
}
