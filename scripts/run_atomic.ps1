<#
.SYNOPSIS
    Runs one Atomic Red Team test with Invoke-AtomicTest.
.DESCRIPTION
    Executes the test for real, so only run it on a disposable machine. The
    process ID of this script is the root of the process tree that the pipeline
    labels as attack telemetry.
#>
param(
    [Parameter(Mandatory)][string]$Technique,
    [Parameter(Mandatory)][string]$TestGuid,
    [Parameter(Mandatory)][string]$AtomicsPath
)

$ErrorActionPreference = 'Stop'
Import-Module Invoke-AtomicRedTeam -Force

Invoke-AtomicTest $Technique -TestGuids $TestGuid -PathToAtomicsFolder $AtomicsPath -TimeoutSeconds 60
