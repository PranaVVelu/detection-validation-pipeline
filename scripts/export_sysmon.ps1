<#
.SYNOPSIS
    Exports the Sysmon events rules can use as raw XML, one event per line.
#>
param(
    [Parameter(Mandatory)][datetime]$Since,
    [Parameter(Mandatory)][string]$OutFile
)

$ErrorActionPreference = 'Stop'
$filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 7, 10; StartTime = $Since }

$lines = Get-WinEvent -FilterHashtable $filter -Oldest |
    ForEach-Object { $_.ToXml() -replace "\r?\n", '&#10;' }

[System.IO.File]::WriteAllLines($OutFile, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
