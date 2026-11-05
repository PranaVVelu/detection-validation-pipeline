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

# Windows PowerShell inherits PowerShell 7's module paths when started from it,
# so it can't find modules in its usual folders. Load from an explicit one.
if ($env:ATOMIC_MODULES) {
    $env:PSModulePath = "$env:ATOMIC_MODULES;$env:PSModulePath"
}
Import-Module Invoke-AtomicRedTeam -Force

Invoke-AtomicTest $Technique -TestGuids $TestGuid -PathToAtomicsFolder $AtomicsPath -TimeoutSeconds 60
