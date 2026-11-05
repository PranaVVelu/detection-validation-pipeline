<#
.SYNOPSIS
    A launcher starts the game and stops it, which gives the launcher full access to it.
#>
param([Parameter(Mandatory)][string]$GameDir)
$ErrorActionPreference = 'Stop'

$game = Join-Path $GameDir 'FakeQuest.exe'
& powershell.exe -NoProfile -Command "`$p = Start-Process -FilePath '$game' -ArgumentList '8' -PassThru -NoNewWindow; Start-Sleep -Seconds 3; Stop-Process -Id `$p.Id -Force"
if ($LASTEXITCODE -ne 0) { throw "The launcher exited with $LASTEXITCODE" }
