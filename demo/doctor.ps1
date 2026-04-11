[CmdletBinding()]
param(
    [switch]$Fix
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = Join-Path $repoRoot "guardrail"
$script:FailureCount = 0
$script:DockerAvailable = $false
$script:DockerDaemonRunning = $false
$script:DockerContainers = @()

function Write-Pass {
    param(
        [string]$CheckName,
        [string]$Detail
    )

    Write-Host ("[PASS] {0} - {1}" -f $CheckName, $Detail) -ForegroundColor Green
}

function Write-Fail {
    param(
        [string]$CheckName,
        [string]$Detail,
        [string]$Remediation
    )

    Write-Host ("[FAIL] {0} - {1}" -f $CheckName, $Detail) -ForegroundColor Red
    if ($Remediation) {
        Write-Host ("       Fix: {0}" -f $Remediation) -ForegroundColor Yellow
    }
    $script:FailureCount++
}

function Invoke-CapturedCommand {
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

function Get-DockerContainerSnapshot {
    if (-not $script:DockerDaemonRunning) {
        return @()
    }

    $result = Invoke-CapturedCommand -FilePath "docker" -Arguments @("ps", "--format", "{{.Names}}|{{.Ports}}")
    if ($result.ExitCode -ne 0) {
        return @()
    }

    $containers = foreach ($line in $result.Output) {
        $text = [string]$line
        if ([string]::IsNullOrWhiteSpace($text)) {
            continue
        }

        $parts = $text -split "\|", 2
        [pscustomobject]@{
            Name = $parts[0].Trim()
            Ports = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
        }
    }

    return @($containers)
}

function Remove-GuardRailAppContainer {
    if (-not ($script:DockerAvailable -and $script:DockerDaemonRunning)) {
        return
    }

    $result = Invoke-CapturedCommand -FilePath "docker" -Arguments @("ps", "-a", "--filter", "name=^guardrail-app$", "--format", "{{.Names}}")
    if ($result.ExitCode -ne 0) {
        Write-Fail "guardrail-app cleanup" "Could not inspect Docker containers." "Start Docker Desktop and rerun .\guardrail.ps1 doctor -Fix."
        return
    }

    $containerNames = @(
        $result.Output |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    if ($containerNames.Count -eq 0) {
        Write-Pass "guardrail-app cleanup" "No stale guardrail-app container was found."
        return
    }

    $removeResult = Invoke-CapturedCommand -FilePath "docker" -Arguments @("rm", "-f", "guardrail-app")
    if ($removeResult.ExitCode -ne 0) {
        Write-Fail "guardrail-app cleanup" "Docker could not remove the stale guardrail-app container." "Run docker rm -f guardrail-app, then rerun the doctor check."
        return
    }

    Write-Pass "guardrail-app cleanup" "Removed stale guardrail-app container because -Fix was requested."
}

function Get-PortOwner {
    param(
        [int]$Port
    )

    try {
        $connection = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    catch {
        $connection = $null
    }

    if (-not $connection) {
        return $null
    }

    $processName = "PID $($connection.OwningProcess)"
    try {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction Stop
        $processName = $process.ProcessName
    }
    catch {
    }

    return [pscustomobject]@{
        ProcessName = $processName
        ProcessId = $connection.OwningProcess
    }
}

function Get-ExpectedDockerPortOwner {
    param(
        [int]$Port
    )

    $portMarker = ":{0}->" -f $Port
    foreach ($container in $script:DockerContainers) {
        if ($container.Ports -notlike "*$portMarker*") {
            continue
        }

        if ($Port -eq 5000 -and $container.Name -match "(^|[-_])registry($|[-_])") {
            return $container
        }

        if ($Port -eq 8000 -and $container.Name -match "^guardrail[-_]app($|[-_])") {
            return $container
        }
    }

    return $null
}

function Test-Port {
    param(
        [int]$Port
    )

    $expectedOwner = Get-ExpectedDockerPortOwner -Port $Port
    $owner = Get-PortOwner -Port $Port

    if (-not $owner) {
        Write-Pass "port $Port" "Port $Port is available."
        return
    }

    if ($expectedOwner) {
        Write-Pass "port $Port" ("Port $Port is already held by GuardRail-managed container '{0}'." -f $expectedOwner.Name)
        return
    }

    $remediation = "Stop the process using port $Port and rerun the doctor check."
    if ($Port -eq 8000) {
        $remediation = "Stop the process using port 8000, or rerun .\guardrail.ps1 doctor -Fix if it is a stale GuardRail app container."
    }

    Write-Fail "port $Port" ("Port $Port is already in use by {0}." -f $owner.ProcessName) $remediation
}

function Test-RequiredPath {
    param(
        [string]$DisplayPath,
        [ValidateSet("File", "Directory")] [string]$PathType
    )

    $relativePath = $DisplayPath.TrimEnd("/") -replace "/", "\"
    $fullPath = Join-Path $projectRoot $relativePath

    if ($PathType -eq "File" -and (Test-Path $fullPath -PathType Leaf)) {
        Write-Pass $DisplayPath ("Found at {0}" -f $fullPath)
        return
    }

    if ($PathType -eq "Directory" -and (Test-Path $fullPath -PathType Container)) {
        Write-Pass $DisplayPath ("Found at {0}" -f $fullPath)
        return
    }

    if ($Fix -and $PathType -eq "Directory" -and $DisplayPath -in @("artifacts/", "keys/")) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        Write-Pass $DisplayPath ("Created missing directory at {0}" -f $fullPath)
        return
    }

    $remediation = switch ($DisplayPath) {
        "scripts/pipeline.py" { "Verify the GuardRail project is checked out correctly under .\guardrail\scripts\pipeline.py." }
        "scripts/collect_results.py" { "Verify the GuardRail project is checked out correctly under .\guardrail\scripts\collect_results.py." }
        "app/" { "Restore or recreate the .\guardrail\app folder before running the demo." }
        "artifacts/" { "Create .\guardrail\artifacts, or rerun .\guardrail.ps1 doctor -Fix." }
        "keys/" { "Create .\guardrail\keys, or rerun .\guardrail.ps1 doctor -Fix." }
        default { "Restore the missing path and rerun the doctor check." }
    }

    Write-Fail $DisplayPath ("Missing required {0}." -f $PathType.ToLowerInvariant()) $remediation
}

Write-Host "GuardRail doctor running from $repoRoot" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $projectRoot -PathType Container)) {
    Write-Fail "guardrail/" ("Project folder not found at {0}" -f $projectRoot) "Run this script from the repository root so the nested .\guardrail project folder is available."
}
else {
    Write-Pass "guardrail/" ("Found project root at {0}" -f $projectRoot)
}

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCommand) {
    $pythonVersion = Invoke-CapturedCommand -FilePath "python" -Arguments @("--version")
    if ($pythonVersion.ExitCode -eq 0) {
        $versionLines = @(
            $pythonVersion.StdOut |
                ForEach-Object { ([string]$_).Trim() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        if ($versionLines.Count -eq 0) {
            $versionLines = @(
                $pythonVersion.Output |
                    ForEach-Object { ([string]$_).Trim() } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
        }
        $versionLine = if ($versionLines.Count -gt 0) { $versionLines[-1] } else { "python available" }
        Write-Pass "python available" $versionLine
    }
    else {
        Write-Fail "python available" "The 'python' command exists but could not report its version." "Reinstall Python or repair the PATH entry so 'python --version' succeeds."
    }
}
else {
    Write-Fail "python available" "The 'python' command was not found on PATH." "Install Python and ensure 'python' works from Windows PowerShell."
}

$dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCommand) {
    $script:DockerAvailable = $true
    $dockerVersion = Invoke-CapturedCommand -FilePath "docker" -Arguments @("--version")
    if ($dockerVersion.ExitCode -eq 0) {
        $versionLines = @(
            $dockerVersion.StdOut |
                ForEach-Object { ([string]$_).Trim() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        if ($versionLines.Count -eq 0) {
            $versionLines = @(
                $dockerVersion.Output |
                    ForEach-Object { ([string]$_).Trim() } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
        }
        $versionLine = if ($versionLines.Count -gt 0) { $versionLines[-1] } else { "docker available" }
        Write-Pass "docker available" $versionLine
    }
    else {
        Write-Fail "docker available" "The 'docker' command exists but could not report its version." "Repair Docker Desktop so 'docker --version' succeeds from PowerShell."
    }
}
else {
    Write-Fail "docker available" "The 'docker' command was not found on PATH." "Install Docker Desktop and ensure the docker CLI works from PowerShell."
}

if ($script:DockerAvailable) {
    $daemonCheck = Invoke-CapturedCommand -FilePath "docker" -Arguments @("info")
    if ($daemonCheck.ExitCode -eq 0) {
        $script:DockerDaemonRunning = $true
        Write-Pass "docker daemon running" "Docker Desktop is reachable."
    }
    else {
        Write-Fail "docker daemon running" "Docker Desktop is installed but the daemon is not reachable." "Start Docker Desktop and wait for the engine to finish starting."
    }

    $composeCheck = Invoke-CapturedCommand -FilePath "docker" -Arguments @("compose", "version")
    if ($composeCheck.ExitCode -eq 0) {
        $composeLines = @(
            $composeCheck.StdOut |
                ForEach-Object { ([string]$_).Trim() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        if ($composeLines.Count -eq 0) {
            $composeLines = @(
                $composeCheck.Output |
                    ForEach-Object { ([string]$_).Trim() } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
        }
        $composeLine = if ($composeLines.Count -gt 0) { $composeLines[-1] } else { "docker compose available" }
        Write-Pass "docker compose available" $composeLine
    }
    else {
        Write-Fail "docker compose available" "The 'docker compose' subcommand is not available." "Update Docker Desktop to a build that includes Docker Compose v2."
    }
}

if ($Fix) {
    Remove-GuardRailAppContainer
}

if ($script:DockerDaemonRunning) {
    $script:DockerContainers = Get-DockerContainerSnapshot
}

Test-Port -Port 5000
Test-Port -Port 8000

Test-RequiredPath -DisplayPath "scripts/pipeline.py" -PathType File
Test-RequiredPath -DisplayPath "scripts/collect_results.py" -PathType File
Test-RequiredPath -DisplayPath "app/" -PathType Directory
Test-RequiredPath -DisplayPath "artifacts/" -PathType Directory
Test-RequiredPath -DisplayPath "keys/" -PathType Directory

Write-Host ""
if ($script:FailureCount -gt 0) {
    Write-Host ("GuardRail doctor found {0} issue(s)." -f $script:FailureCount) -ForegroundColor Red
    throw "GuardRail doctor failed."
}

Write-Host "GuardRail doctor passed. Environment looks ready." -ForegroundColor Green
