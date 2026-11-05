<#
.SYNOPSIS
    Writes a copy of the fake game with one word changed in its startup message.
.DESCRIPTION
    The change gives the copy a different hash without touching how the game behaves.
#>
param(
    [Parameter(Mandatory)][string]$Official,
    [Parameter(Mandatory)][string]$Destination
)
$ErrorActionPreference = 'Stop'

# Latin-1 maps each byte to one character, so text positions match file positions.
$latin1 = [Text.Encoding]::GetEncoding(28591)
$bytes = [IO.File]::ReadAllBytes($Official)
$from = $latin1.GetString([Text.Encoding]::Unicode.GetBytes('a stub'))
$offset = $latin1.GetString($bytes).IndexOf($from, [StringComparison]::Ordinal)
if ($offset -lt 0) { throw 'The startup message was not found in FakeQuest.exe' }
$patch = [Text.Encoding]::Unicode.GetBytes('a copy')
[Array]::Copy($patch, 0, $bytes, $offset, $patch.Length)
[IO.File]::WriteAllBytes($Destination, $bytes)
