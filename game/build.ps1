<#
.SYNOPSIS
    Compiles the fake game and its test tool into game\bin.
#>
$ErrorActionPreference = 'Stop'

$csc = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
$bin = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null

foreach ($name in 'FakeQuest', 'MemoryPeek') {
    & $csc /nologo /optimize /platform:x64 "/out:$bin\$name.exe" "$PSScriptRoot\src\$name.cs"
    if ($LASTEXITCODE -ne 0) { throw "Failed to compile $name" }
}
