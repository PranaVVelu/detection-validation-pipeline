<#
.SYNOPSIS
    A normal session: play the game, check the task list and network, and look up the game's process.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

& (Join-Path $GameDir 'FakeQuest.exe') 2
if ($LASTEXITCODE -ne 0) { throw "FakeQuest exited with $LASTEXITCODE" }

foreach ($command in 'tasklist', 'ipconfig', 'dir C:\Windows\System32\drivers\etc') {
    & cmd.exe /c "$command" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $command" }
}

$game = Start-Process -FilePath (Join-Path $GameDir 'FakeQuest.exe') -ArgumentList '8' -PassThru -NoNewWindow
try {
    Start-Sleep -Seconds 2
    & (Join-Path $GameDir 'MemoryPeek.exe') $game.Id 0x1000
    if ($LASTEXITCODE -ne 0) { throw "MemoryPeek exited with $LASTEXITCODE" }
} finally {
    Stop-Process -Id $game.Id -Force -ErrorAction SilentlyContinue
}
