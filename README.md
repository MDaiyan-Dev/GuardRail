# GuardRail

Minimal software supply chain security demo using FastAPI and a Docker-based evidence pipeline.

## Quickstart

From the repository root:

```powershell
Set-Location .\guardrail
python scripts/pipeline.py --deps safe
Invoke-RestMethod http://localhost:8000/health
```

## Pipeline Scenarios

```powershell
Set-Location .\guardrail
python scripts/pipeline.py --deps safe
python scripts/pipeline.py --deps vuln
python scripts/pipeline.py --deps safe --simulate missing_sbom
Invoke-RestMethod http://localhost:8000/health
```

## Phase 2 Plan

The next phase will add a lightweight supply chain pipeline that runs:

`build -> scan (semgrep/gitleaks/osv) -> sbom (syft) -> sign (cosign) -> provenance -> policy gate (OPA) -> deploy/block`

## Windows Notes

- The pipeline uses Docker Desktop containers for Semgrep, Gitleaks, OSV-Scanner, Syft, and Cosign.
- Evidence for each run is written to `guardrail/artifacts/<run_id>/`.
- The helper script `guardrail/scripts/run_scenarios.ps1` exercises the safe, vulnerable, and missing-SBOM flows.
