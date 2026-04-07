# GuardRail

GuardRail is a course-scale software supply chain security demonstrator built around a containerized FastAPI application and a Python release pipeline. The project shows how a build can be scanned, documented with evidence, signed, evaluated by policy, and either deployed or blocked.

## Current Implementation

The implemented system includes:

- A minimal FastAPI demo app with `GET /health` and `GET /hello`
- A local Docker registry used as the release target
- A Python pipeline orchestrator in `guardrail/scripts/pipeline.py`
- Containerized security tooling for:
  - Semgrep
  - Gitleaks
  - OSV-Scanner
  - Syft
  - Cosign
- Per-run evidence artifacts written under `guardrail/artifacts/<run_id>/`
- A Python policy gate that decides whether deployment is allowed
- A PowerShell runner and Python results collector for the canonical Phase 2 scenarios

The active pipeline flow is:

`build -> scan -> sbom -> sign -> provenance -> policy gate -> deploy/block`

The repository also contains an OPA policy placeholder in `guardrail/policy/guardrail.rego`, but the enforced release gate in the current implementation is intentionally implemented in Python for simplicity and reproducibility.

## Prerequisites

The project is designed for Windows + PowerShell + Docker Desktop.

Required:

- Windows PowerShell
- Docker Desktop running locally
- Python 3.11+ available as `python`
- Internet access the first time container images or Python packages are pulled

Not required:

- `make` is present in the repo for earlier scaffolding, but the current workflow does not depend on it
- Local installs of Semgrep, Gitleaks, OSV-Scanner, Syft, or Cosign

## Repository Layout

The active project lives under `guardrail/`.

Key paths:

- `guardrail/app/`
  - FastAPI app source and Dockerfile
- `guardrail/scripts/pipeline.py`
  - Main build, scan, evidence, and deploy/block pipeline
- `guardrail/scripts/run_scenarios.ps1`
  - Phase 2 evidence-generation runner
- `guardrail/scripts/collect_results.py`
  - Summary generator for scenario results
- `guardrail/policy/guardrail.rego`
  - Placeholder OPA policy file
- `guardrail/artifacts/`
  - Per-run evidence folders and generated summaries
- `guardrail/keys/`
  - Locally generated Cosign keys and signing config for the demo
- `guardrail/docs/`
  - Report-support documentation

## Quick Start

From the repository root:

```powershell
Set-Location .\guardrail
python .\scripts\pipeline.py --deps safe
Invoke-RestMethod http://localhost:8000/health
Invoke-RestMethod http://localhost:8000/hello
```

If the run is allowed by policy, the app is deployed as `guardrail-app` on port `8000`.

## Pipeline Usage

The pipeline entrypoint is:

```powershell
python .\scripts\pipeline.py --deps safe|vuln [--simulate missing_sbom] [--run-id <id>]
```

Supported modes:

- Safe dependency profile:

```powershell
python .\scripts\pipeline.py --deps safe
```

- Intentionally vulnerable dependency profile:

```powershell
python .\scripts\pipeline.py --deps vuln
```

- Negative test for missing SBOM:

```powershell
python .\scripts\pipeline.py --deps safe --simulate missing_sbom
```

The pipeline automatically:

1. Starts the local registry with Docker Compose
2. Selects the requested dependency profile
3. Builds and pushes the app image
4. Runs Semgrep, Gitleaks, and OSV-Scanner
5. Generates an SBOM with Syft
6. Signs and verifies the image with Cosign
7. Writes provenance and evidence summaries
8. Evaluates the Python policy gate
9. Deploys the app or blocks release

## Evidence Artifacts

Each run creates a folder:

`guardrail/artifacts/<run_id>/`

The pipeline generates the following evidence set:

- `sast.json`
- `secrets.json`
- `sca.json`
- `sbom.json`
- `provenance.json`
- `cosign_verify.json`
- `evidence.json`
- `policy_decision.json`
- `deploy.json`
- `run.log`

The most important decision files are:

- `policy_decision.json`
  - final allow/block decision and reasons
- `evidence.json`
  - normalized evidence used by the policy gate
- `deploy.json`
  - records whether the app was deployed or blocked

## Canonical Phase 2 Scenarios

The official evidence-generation runner executes exactly three scenarios:

- `phase2_safe_pass`
- `phase2_vuln_block`
- `phase2_missing_sbom_block`

Run them with:

```powershell
Set-Location .\guardrail
powershell -ExecutionPolicy Bypass -File .\scripts\run_scenarios.ps1
python .\scripts\collect_results.py
```

This produces:

- `guardrail/artifacts/phase2_test_summary.txt`
- `guardrail/artifacts/phase2_results_summary.md`
- `guardrail/artifacts/phase2_results_summary.json`

## Expected Policy Behavior

The current policy gate denies deployment when any of the following is true:

- `secrets_found > 0`
- `vulns_found > 0`
- `sbom_present == false`
- `signature_verified == false`

As implemented, the scenarios are expected to behave as follows:

- `phase2_safe_pass`
  - `allow = true`
  - deploy status = `deployed`
- `phase2_vuln_block`
  - `allow = false`
  - reason = `vulns_found`
- `phase2_missing_sbom_block`
  - `allow = false`
  - reason = `sbom_missing`

## Implementation Notes

- `guardrail/app/requirements.txt` is generated by the pipeline and should not be edited manually
- `guardrail/app/requirements_safe.txt` is the passing dependency profile
- `guardrail/app/requirements_vuln.txt` is intentionally vulnerable for the OSV-Scanner demo
- Semgrep findings are recorded, but Semgrep is intentionally non-blocking in the current policy
- Gitleaks uses a local config to ignore generated artifacts and demo key material
- The local registry is HTTP-only, so Syft and Cosign use explicit insecure-registry handling for this demo
- Cosign keys are generated locally in `guardrail/keys/`; this is acceptable for the course demo but not a production key-management model

## Documentation

Supporting report documentation is available in:

- `guardrail/docs/phase2_verification_testing.md`

That file summarizes the implemented architecture, verification strategy, traceability, detailed test cases, results, and limitations for the Phase 2 submission.
