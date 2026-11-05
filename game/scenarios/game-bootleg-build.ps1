<#
.SYNOPSIS
    Runs the official fake game, or a modified copy of it. Only run on a disposable VM.
.DESCRIPTION
    The copy has one word changed in its startup message, which changes its hash
    without touching how the game behaves. It's patched from the official file
    because every compile has a different hash, so compiling a second build wouldn't
    prove anything.
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
    # Latin-1 maps each byte to one character, so text positions match file positions.
    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $bytes = [IO.File]::ReadAllBytes($official)
    $from = $latin1.GetString([Text.Encoding]::Unicode.GetBytes('a stub'))
    $offset = $latin1.GetString($bytes).IndexOf($from, [StringComparison]::Ordinal)
    if ($offset -lt 0) { throw 'The startup message was not found in FakeQuest.exe' }
    $patch = [Text.Encoding]::Unicode.GetBytes('a copy')
    [Array]::Copy($patch, 0, $bytes, $offset, $patch.Length)
    [IO.File]::WriteAllBytes($copy, $bytes)

    $output = & $copy 2
    if ($LASTEXITCODE -ne 0) { throw "The copy exited with $LASTEXITCODE" }
    if ("$output" -notmatch 'a copy') { throw "The copy printed the wrong message: $output" }
    $output
} finally {
    Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue
}
