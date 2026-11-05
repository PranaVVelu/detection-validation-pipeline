<#
.SYNOPSIS
    Compiles the fake game and its test tool into game\bin, and records the official hash.
.DESCRIPTION
    Each compile produces a different hash, so the official hash can't be written
    into a rule. It's recorded here instead, the way a release process would publish it.
#>
$ErrorActionPreference = 'Stop'

$csc = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
$bin = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null

foreach ($name in 'FakeQuest', 'MemoryPeek') {
    & $csc /nologo /optimize /platform:x64 "/out:$bin\$name.exe" "$PSScriptRoot\src\$name.cs"
    if ($LASTEXITCODE -ne 0) { throw "Failed to compile $name" }
}

$hash = (Get-FileHash (Join-Path $bin 'FakeQuest.exe') -Algorithm SHA256).Hash
"official_fakequest_hashes:`n  - SHA256=$hash`n" | Set-Content -Path (Join-Path $bin 'placeholders.yml') -Encoding ascii -NoNewline
