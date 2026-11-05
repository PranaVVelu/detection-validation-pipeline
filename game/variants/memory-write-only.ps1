<#
.SYNOPSIS
    Requests only the rights needed to write, without the right to read. MemoryPeek closes the handle without using it.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$game = Start-Process -FilePath (Join-Path $GameDir 'FakeQuest.exe') -ArgumentList '15' -PassThru -NoNewWindow
try {
    Start-Sleep -Seconds 2
    & (Join-Path $GameDir 'MemoryPeek.exe') $game.Id 0x0028
    if ($LASTEXITCODE -ne 0) { throw "MemoryPeek exited with $LASTEXITCODE" }
} finally {
    Stop-Process -Id $game.Id -Force -ErrorAction SilentlyContinue
}
