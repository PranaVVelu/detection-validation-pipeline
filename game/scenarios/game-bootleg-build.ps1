<#
.SYNOPSIS
    Runs the official fake game, or a modified copy of it. Only run on a disposable VM.
.DESCRIPTION
    The copy is patched from the official file because every compile has a different
    hash, so compiling a second build wouldn't prove anything.
#>
param(
    [Parameter(Mandatory)][ValidateSet('attack', 'benign')][string]$Scenario,
    [Parameter(Mandatory)][string]$GameDir
)
$ErrorActionPreference = 'Stop'

$official = Join-Path $GameDir 'FakeQuest.exe'
if ($Scenario -eq 'benign') {
    & $official 2
    if ($LASTEXITCODE -ne 0) { throw "FakeQuest exited with $LASTEXITCODE" }
    return
}

$folder = Join-Path $GameDir 'bootleg'
$copy = Join-Path $folder 'FakeQuest.exe'
New-Item -ItemType Directory -Force -Path $folder | Out-Null
try {
    & (Join-Path $PSScriptRoot 'New-BootlegCopy.ps1') -Official $official -Destination $copy

    $output = & $copy 2
    if ($LASTEXITCODE -ne 0) { throw "The copy exited with $LASTEXITCODE" }
    if ("$output" -notmatch 'a copy') { throw "The copy printed the wrong message: $output" }
    $output
} finally {
    Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue
}
