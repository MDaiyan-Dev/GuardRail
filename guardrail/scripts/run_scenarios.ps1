$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$artifactsDir = Join-Path $projectRoot "artifacts"
$pipeline = Join-Path $PSScriptRoot "pipeline.py"
$summaryPath = Join-Path $artifactsDir "phase2_test_summary.txt"
$summaryLines = New-Object System.Collections.Generic.List[string]

function Invoke-Scenario {
    param(
        [string]$ScenarioName,
        [string]$RunId,
        [string[]]$PipelineArgs
    )

    Write-Host ""
    Write-Host "=== Scenario: $ScenarioName ==="

    $runDir = Join-Path $artifactsDir $RunId
    if (Test-Path $runDir) {
        Remove-Item -Recurse -Force $runDir
    }

    & python $pipeline @PipelineArgs
    $exitCode = $LASTEXITCODE

    $policyPath = Join-Path $runDir "policy_decision.json"
    $policyText = if (Test-Path $policyPath) {
        Get-Content $policyPath -Raw
    } else {
        "{`"missing`": true}"
    }

    $dockerPsOutput = docker ps

    Write-Host "Run ID: $RunId"
    Write-Host "policy_decision.json:"
    Write-Host $policyText
    Write-Host "docker ps:"
    $dockerPsOutput | ForEach-Object { Write-Host $_ }

    $summaryLines.Add("Scenario: $ScenarioName")
    $summaryLines.Add("Run ID: $RunId")
    $summaryLines.Add("Exit Code: $exitCode")
    $summaryLines.Add("Policy Decision Path: $policyPath")
    $summaryLines.Add("Policy Decision:")
    $summaryLines.Add($policyText.TrimEnd())
    $summaryLines.Add("docker ps:")
    foreach ($line in $dockerPsOutput) {
        $summaryLines.Add($line)
    }
    $summaryLines.Add("")
}

Invoke-Scenario -ScenarioName "Safe pass deploy" -RunId "phase2_safe_pass" -PipelineArgs @("--deps", "safe", "--run-id", "phase2_safe_pass")
Invoke-Scenario -ScenarioName "Vulnerable dependency blocked" -RunId "phase2_vuln_block" -PipelineArgs @("--deps", "vuln", "--run-id", "phase2_vuln_block")
Invoke-Scenario -ScenarioName "Missing SBOM blocked" -RunId "phase2_missing_sbom_block" -PipelineArgs @("--deps", "safe", "--simulate", "missing_sbom", "--run-id", "phase2_missing_sbom_block")

$summaryHeader = @(
    "GuardRail Phase 2 Test Summary"
    "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
    ""
)

($summaryHeader + $summaryLines) | Set-Content -Path $summaryPath
Write-Host ""
Write-Host "Summary written to: $summaryPath"
