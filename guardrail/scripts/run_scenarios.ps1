$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$artifactsDir = Join-Path $projectRoot "artifacts"
$pipeline = Join-Path $PSScriptRoot "pipeline.py"

function Invoke-Scenario {
    param(
        [string]$Name,
        [string[]]$Args,
    [bool]$ExpectAllow,
    [string]$ExpectedReason = "",
    [string]$RunId
    )

    Write-Host ""
    Write-Host "=== Scenario: $Name ==="

    $allArgs = @("--run-id", $RunId) + $Args
    & python $pipeline @allArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: pipeline execution failed"
        & docker ps
        return
    }

    $policyPath = Join-Path (Join-Path $artifactsDir $RunId) "policy_decision.json"
    $decision = Get-Content $policyPath | ConvertFrom-Json

    $pass = $false
    if ($ExpectAllow) {
        $pass = [bool]$decision.allow
    } else {
        $reasons = @($decision.reasons)
        $pass = (-not [bool]$decision.allow) -and ($ExpectedReason -eq "" -or $reasons -contains $ExpectedReason)
    }

    if ($pass) {
        Write-Host "PASS"
    } else {
        Write-Host "FAIL"
    }

    & docker ps
    Write-Host "policy_decision.json: $policyPath"
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"

Invoke-Scenario -Name "safe deps" -Args @("--deps", "safe") -ExpectAllow $true -RunId "safe_$stamp"
Invoke-Scenario -Name "vuln deps" -Args @("--deps", "vuln") -ExpectAllow $false -ExpectedReason "vulns_found" -RunId "vuln_$stamp"
Invoke-Scenario -Name "safe deps + missing_sbom" -Args @("--deps", "safe", "--simulate", "missing_sbom") -ExpectAllow $false -ExpectedReason "sbom_missing" -RunId "missing_sbom_$stamp"
