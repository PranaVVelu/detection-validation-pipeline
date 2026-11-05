<#
.SYNOPSIS
    Requests a handle to the fake game's process. Only run on a disposable VM.
.DESCRIPTION
    The attack side asks for read and write access, as a memory cheat would, but
    MemoryPeek closes the handle without using it. The benign side asks only for
    basic information, as a task manager would.
#>
param(
    [Parameter(Mandatory)][ValidateSet('attack', 'benign')][string]$Scenario,
    [Parameter(Mandatory)][string]$GameDir
)
$ErrorActionPreference = 'Stop'

# PROCESS_QUERY_INFORMATION | VM_OPERATION | VM_READ | VM_WRITE, or PROCESS_QUERY_LIMITED_INFORMATION.
$access = if ($Scenario -eq 'attack') { '0x0438' } else { '0x1000' }

$game = Start-Process -FilePath (Join-Path $GameDir 'FakeQuest.exe') -ArgumentList '15' -PassThru -NoNewWindow
try {
    Start-Sleep -Seconds 2
    & (Join-Path $GameDir 'MemoryPeek.exe') $game.Id $access
    if ($LASTEXITCODE -ne 0) { throw "MemoryPeek exited with $LASTEXITCODE" }
} finally {
    Stop-Process -Id $game.Id -Force -ErrorAction SilentlyContinue
}
