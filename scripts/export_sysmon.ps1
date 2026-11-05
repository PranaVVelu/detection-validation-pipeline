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

# Sysmon writes asynchronously, so "nothing yet" is a normal answer for the caller
# to poll on. Get-WinEvent reports it as an error.
try {
    $lines = @(Get-WinEvent -FilterHashtable $filter -Oldest |
        ForEach-Object { $_.ToXml() -replace "\r?\n", '&#10;' })
} catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    $lines = @()
}

[System.IO.File]::WriteAllLines($OutFile, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
