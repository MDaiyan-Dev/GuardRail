[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Command,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$demoRoot = Join-Path $repoRoot "demo"

$targetScript = switch ($Command) {
    "doctor" { Join-Path $demoRoot "doctor.ps1" }
    "bootstrap" { Join-Path $demoRoot "bootstrap.ps1" }
    "demo" { Join-Path $demoRoot "guardrail_demo.ps1" }
    default { $null }
}

if (-not $targetScript) {
    Write-Host "Usage: .\guardrail.ps1 doctor|bootstrap|demo" -ForegroundColor Yellow
    throw "Unknown GuardRail command."
}

if (-not (Test-Path $targetScript -PathType Leaf)) {
    throw ("Missing script: {0}" -f $targetScript)
}

if ($RemainingArgs) {
    & $targetScript @RemainingArgs
}
else {
    & $targetScript
}
