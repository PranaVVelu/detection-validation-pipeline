<#
.SYNOPSIS
    Points the fake game's license server at localhost. Only run on a disposable VM.
#>
param(
    [Parameter(Mandatory)][ValidateSet('attack', 'benign')][string]$Scenario,
    [Parameter(Mandatory)][string]$GameDir
)
$ErrorActionPreference = 'Stop'

$commands = if ($Scenario -eq 'attack') {
    # .invalid is reserved and never resolves, so this can't affect a real service.
    , 'echo 127.0.0.1 license.fakequest.invalid>> C:\Windows\System32\drivers\etc\hosts'
} else {
    'type C:\Windows\System32\drivers\etc\hosts',
    'findstr license C:\Windows\System32\drivers\etc\hosts & exit /b 0',
    'echo 127.0.0.1 dev.local>> C:\Windows\System32\drivers\etc\hosts'
}

foreach ($command in $commands) {
    & cmd.exe /c "$command"
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $command" }
}
