[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = Join-Path $repoRoot "guardrail"
$bootstrapScript = Join-Path $PSScriptRoot "bootstrap.ps1"
$pipelineScript = Join-Path $projectRoot "scripts\pipeline.py"
$collectResultsScript = Join-Path $projectRoot "scripts\collect_results.py"
$artifactsDir = Join-Path $projectRoot "artifacts"
$summaryPath = Join-Path $artifactsDir "phase2_results_summary.md"
$script:UnexpectedScenarioCount = 0

$scenarios = @(
    [pscustomobject]@{
        Name = "Safe pass deploy"
        RunId = "phase2_safe_pass"
        Deps = "safe"
        Simulate = $null
        ExpectedResult = "allow=true and deployed"
        ExpectedAllow = $true
        ExpectedReason = "none"
        ExpectedDeployStatus = "deployed"
    },
    [pscustomobject]@{
        Name = "Vulnerable dependency blocked"
        RunId = "phase2_vuln_block"
        Deps = "vuln"
        Simulate = $null
        ExpectedResult = "allow=false due to vulns_found"
        ExpectedAllow = $false
        ExpectedReason = "vulns_found"
        ExpectedDeployStatus = "blocked"
    },
    [pscustomobject]@{
        Name = "Missing SBOM blocked"
        RunId = "phase2_missing_sbom_block"
        Deps = "safe"
        Simulate = "missing_sbom"
        ExpectedResult = "allow=false due to sbom_missing"
        ExpectedAllow = $false
        ExpectedReason = "sbom_missing"
        ExpectedDeployStatus = "blocked"
    }
)

function Write-Step {
    param(
        [string]$Message
    )

    Write-Host ""
    Write-Host ("== {0} ==" -f $Message) -ForegroundColor Cyan
}

function Invoke-NativeCommand {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory = $null
    )

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    try {
        $process = Start-Process `
            -FilePath $FilePath `
            -ArgumentList $Arguments `
            -WorkingDirectory $(if ($WorkingDirectory) { $WorkingDirectory } else { $repoRoot }) `
            -NoNewWindow `
            -PassThru `
            -Wait `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath

        $stdout = if ((Test-Path $stdoutPath) -and (Get-Item $stdoutPath).Length -gt 0) { Get-Content $stdoutPath } else { @() }
        $stderr = if ((Test-Path $stderrPath) -and (Get-Item $stderrPath).Length -gt 0) { Get-Content $stderrPath } else { @() }
        return @{
            ExitCode = $process.ExitCode
            StdOut = @($stdout)
            StdErr = @($stderr)
            Output = @($stdout + $stderr)
        }
    }
    finally {
        Remove-Item $stdoutPath, $stderrPath -ErrorAction SilentlyContinue
    }
}

function Write-CommandOutput {
    param(
        $Result
    )

    foreach ($line in $Result.Output) {
        $text = [string]$line
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            Write-Host $text
        }
    }
}

function Read-JsonFile {
    param(
        [string]$Path
    )

    if (-not (Test-Path $Path -PathType Leaf)) {
        return $null
    }

    return Get-Content -Path $Path -Raw | ConvertFrom-Json
}

function Get-ReasonsText {
    param(
        $PolicyDecision
    )

    if (-not $PolicyDecision) {
        return "missing policy_decision.json"
    }

    if (-not $PolicyDecision.reasons) {
        return "none"
    }

    $reasons = @($PolicyDecision.reasons)
    if ($reasons.Count -eq 0) {
        return "none"
    }

    return ($reasons -join ", ")
}

function Get-ActualResultText {
    param(
        $PolicyDecision,
        $DeployInfo
    )

    if (-not $PolicyDecision) {
        return "policy decision missing"
    }

    $allow = $PolicyDecision.allow
    $reasonsText = Get-ReasonsText -PolicyDecision $PolicyDecision
    $deployStatus = if ($DeployInfo -and $DeployInfo.status) { [string]$DeployInfo.status } else { "missing" }

    if ($allow -eq $true -and $deployStatus -eq "deployed") {
        return "allow=true and deployed"
    }

    if ($allow -eq $false -and $reasonsText -ne "none") {
        return ("allow=false due to {0}" -f $reasonsText)
    }

    if ($allow -eq $false) {
        return "allow=false"
    }

    return ("allow={0} and deploy={1}" -f $allow, $deployStatus)
}

function Invoke-HealthCheck {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -TimeoutSec 10
        if ($response.status) {
            return ("healthy ({0})" -f $response.status)
        }

        return "healthy"
    }
    catch {
        return ("unreachable ({0})" -f $_.Exception.Message)
    }
}

function Invoke-Scenario {
    param(
        $Scenario
    )

    $runDir = Join-Path $artifactsDir $Scenario.RunId
    if (Test-Path $runDir) {
        Remove-Item -Recurse -Force $runDir
    }

    Write-Step ("Running {0}" -f $Scenario.Name)

    $pipelineArgs = @(
        $pipelineScript,
        "--deps",
        $Scenario.Deps,
        "--run-id",
        $Scenario.RunId
    )

    if ($Scenario.Simulate) {
        $pipelineArgs += @("--simulate", $Scenario.Simulate)
    }

    $pipelineResult = Invoke-NativeCommand -FilePath "python" -Arguments $pipelineArgs -WorkingDirectory $projectRoot
    Write-CommandOutput -Result $pipelineResult
    $pipelineExitCode = $pipelineResult.ExitCode

    $policyPath = Join-Path $runDir "policy_decision.json"
    $deployPath = Join-Path $runDir "deploy.json"
    $policyDecision = Read-JsonFile -Path $policyPath
    $deployInfo = Read-JsonFile -Path $deployPath

    $actualResult = Get-ActualResultText -PolicyDecision $policyDecision -DeployInfo $deployInfo
    $actualReason = Get-ReasonsText -PolicyDecision $policyDecision
    $deployStatus = if ($deployInfo -and $deployInfo.status) { [string]$deployInfo.status } else { "missing" }
    $healthCheck = if ($deployStatus -eq "deployed") { Invoke-HealthCheck } else { "not deployed" }

    $matchesExpectation = (
        $pipelineExitCode -eq 0 -and
        $policyDecision -and
        $policyDecision.allow -eq $Scenario.ExpectedAllow -and
        $actualReason -eq $Scenario.ExpectedReason -and
        $deployStatus -eq $Scenario.ExpectedDeployStatus
    )

    if (-not $matchesExpectation) {
        $script:UnexpectedScenarioCount++
    }

    Write-Host ("Scenario name: {0}" -f $Scenario.Name) -ForegroundColor White
    Write-Host ("Expected result: {0}" -f $Scenario.ExpectedResult) -ForegroundColor White
    Write-Host ("Actual result: {0}" -f $actualResult) -ForegroundColor White
    Write-Host ("Reason: {0}" -f $actualReason) -ForegroundColor White
    Write-Host ("Deploy status: {0}" -f $deployStatus) -ForegroundColor White
    Write-Host ("Health check: {0}" -f $healthCheck) -ForegroundColor White
    Write-Host ("Artifact path: {0}" -f $runDir) -ForegroundColor White

    if ($pipelineExitCode -ne 0) {
        Write-Host ("Pipeline exited with code {0} for scenario {1}." -f $pipelineExitCode, $Scenario.RunId) -ForegroundColor Yellow
    }

    if ($matchesExpectation) {
        Write-Host "Outcome matched the expected Phase 2 behavior." -ForegroundColor Green
    }
    else {
        Write-Host "Outcome did not match the expected Phase 2 behavior." -ForegroundColor Red
    }
}

function Invoke-CheckedPython {
    param(
        [string]$ScriptPath
    )

    $result = Invoke-NativeCommand -FilePath "python" -Arguments @($ScriptPath) -WorkingDirectory $projectRoot
    Write-CommandOutput -Result $result
    if ($result.ExitCode -ne 0) {
        throw ("Python command failed with exit code {0}: {1}" -f $result.ExitCode, $ScriptPath)
    }
}

Write-Step "Bootstrapping GuardRail demo environment"
& $bootstrapScript

foreach ($scenario in $scenarios) {
    Invoke-Scenario -Scenario $scenario
}

Write-Step "Collecting consolidated Phase 2 results"
Invoke-CheckedPython -ScriptPath $collectResultsScript

if (-not (Test-Path $summaryPath -PathType Leaf)) {
    throw ("Expected summary file was not created: {0}" -f $summaryPath)
}

Write-Host ""
Write-Host ("Phase 2 summary: {0}" -f $summaryPath) -ForegroundColor Green

if ($script:UnexpectedScenarioCount -gt 0) {
    throw ("GuardRail demo finished with {0} unexpected scenario result(s)." -f $script:UnexpectedScenarioCount)
}

Write-Host "GuardRail demo completed with the expected Phase 2 outcomes." -ForegroundColor Green
