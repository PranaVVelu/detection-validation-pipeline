<#
.SYNOPSIS
    An overlay asks for the same access to the game as a memory cheat, then closes the handle unused.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$overlay = Join-Path $GameDir 'GameOverlay.exe'
Copy-Item (Join-Path $GameDir 'MemoryPeek.exe') $overlay
$game = Start-Process -FilePath (Join-Path $GameDir 'FakeQuest.exe') -ArgumentList '8' -PassThru -NoNewWindow
try {
    Start-Sleep -Seconds 2
    & $overlay $game.Id 0x0438
    if ($LASTEXITCODE -ne 0) { throw "The overlay exited with $LASTEXITCODE" }
} finally {
    Stop-Process -Id $game.Id -Force -ErrorAction SilentlyContinue
    Remove-Item $overlay -ErrorAction SilentlyContinue
}
