<#
.SYNOPSIS
    Requests full access, which is more than the rule's list of values covers. MemoryPeek closes the handle without using it.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$game = Start-Process -FilePath (Join-Path $GameDir 'FakeQuest.exe') -ArgumentList '15' -PassThru -NoNewWindow
try {
    Start-Sleep -Seconds 2
    & (Join-Path $GameDir 'MemoryPeek.exe') $game.Id 0x1FFFFF
    if ($LASTEXITCODE -ne 0) { throw "MemoryPeek exited with $LASTEXITCODE" }
} finally {
    Stop-Process -Id $game.Id -Force -ErrorAction SilentlyContinue
}
