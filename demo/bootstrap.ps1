[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = Join-Path $repoRoot "guardrail"
$doctorScript = Join-Path $PSScriptRoot "doctor.ps1"
$keysDir = Join-Path $projectRoot "keys"
$signingConfigPath = Join-Path $keysDir "signing_config.json"
$toolImages = @(
    "registry:2",
    "python:3.11-slim",
    "semgrep/semgrep",
    "zricethezav/gitleaks:latest",
    "ghcr.io/google/osv-scanner:latest",
    "anchore/syft:latest",
    "ghcr.io/sigstore/cosign/cosign:latest"
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

function Invoke-CheckedCommand {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory = $null
    )

    $result = Invoke-NativeCommand -FilePath $FilePath -Arguments $Arguments -WorkingDirectory $WorkingDirectory
    Write-CommandOutput -Result $result
    if ($result.ExitCode -ne 0) {
        throw ("Command failed with exit code {0}: {1} {2}" -f $result.ExitCode, $FilePath, ($Arguments -join " "))
    }
}

function Get-CommandOutput {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory = $null
    )

    $result = Invoke-NativeCommand -FilePath $FilePath -Arguments $Arguments -WorkingDirectory $WorkingDirectory
    if ($result.ExitCode -ne 0) {
        Write-CommandOutput -Result $result
        throw ("Command failed with exit code {0}: {1} {2}" -f $result.ExitCode, $FilePath, ($Arguments -join " "))
    }

    return @($result.Output)
}

function Ensure-SigningConfig {
    $payload = @{
        mediaType = "application/vnd.dev.sigstore.signingconfig.v0.2+json"
        caUrls = @()
        oidcUrls = @()
        rekorTlogUrls = @()
        tsaUrls = @()
    }

    $json = $payload | ConvertTo-Json -Depth 3
    Set-Content -Path $signingConfigPath -Value $json -Encoding utf8
    Write-Host ("Signing config ready at {0}" -f $signingConfigPath) -ForegroundColor Green
}

function Ensure-CosignKeys {
    $privateKeyPath = Join-Path $keysDir "cosign.key"
    $publicKeyPath = Join-Path $keysDir "cosign.pub"

    if ((Test-Path $privateKeyPath -PathType Leaf) -and (Test-Path $publicKeyPath -PathType Leaf)) {
        Write-Host "Cosign key pair already present." -ForegroundColor Green
        return
    }

    $resolvedKeysDir = (Resolve-Path $keysDir).Path
    $keysMount = "{0}:/keys" -f $resolvedKeysDir

    Invoke-CheckedCommand -FilePath "docker" -Arguments @(
        "run",
        "--rm",
        "-e",
        "COSIGN_PASSWORD=",
        "-v",
        $keysMount,
        "ghcr.io/sigstore/cosign/cosign:latest",
        "generate-key-pair",
        "--output-key-prefix",
        "/keys/cosign"
    )

    Write-Host "Cosign key pair created successfully." -ForegroundColor Green
}

function Remove-ExistingDemoContainers {
    $appContainer = Get-CommandOutput -FilePath "docker" -Arguments @("ps", "-a", "--filter", "name=^guardrail-app$", "--format", "{{.Names}}")
    $appContainerNames = @(
        $appContainer |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    if ($appContainerNames.Count -gt 0) {
        Invoke-CheckedCommand -FilePath "docker" -Arguments @("rm", "-f", "guardrail-app")
        Write-Host "Removed existing guardrail-app container." -ForegroundColor Green
    }
    else {
        Write-Host "No existing guardrail-app container to remove." -ForegroundColor DarkGray
    }

    $composeAppIds = Get-CommandOutput -FilePath "docker" -Arguments @("compose", "ps", "-a", "-q", "app") -WorkingDirectory $projectRoot
    $composeAppIds = @(
        $composeAppIds |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    if ($composeAppIds.Count -gt 0) {
        Invoke-CheckedCommand -FilePath "docker" -Arguments @("compose", "rm", "-sf", "app") -WorkingDirectory $projectRoot
        Write-Host "Removed existing Docker Compose app service container." -ForegroundColor Green
    }
    else {
        Write-Host "No Docker Compose app service container to remove." -ForegroundColor DarkGray
    }
}

Write-Step "Running environment doctor"
& $doctorScript -Fix

Write-Step "Cleaning prior demo containers"
Remove-ExistingDemoContainers

Write-Step "Starting local registry"
Invoke-CheckedCommand -FilePath "docker" -Arguments @("compose", "up", "-d", "registry") -WorkingDirectory $projectRoot

Write-Step "Pre-pulling GuardRail images"
foreach ($image in $toolImages) {
    Write-Host ("Pulling {0}" -f $image) -ForegroundColor DarkGray
    Invoke-CheckedCommand -FilePath "docker" -Arguments @("pull", $image)
}

Write-Step "Preparing signing config and keys"
Ensure-SigningConfig
Ensure-CosignKeys

Write-Host ""
Write-Host "READY: GuardRail demo environment is prepared." -ForegroundColor Green
Write-Host "Next step: .\guardrail.ps1 demo" -ForegroundColor Green
