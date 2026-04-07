"""Collect GuardRail Phase 2 scenario outputs into report artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
MARKDOWN_PATH = ARTIFACTS_DIR / "phase2_results_summary.md"
JSON_PATH = ARTIFACTS_DIR / "phase2_results_summary.json"

SCENARIOS = [
    {
        "id": "phase2_safe_pass",
        "name": "Safe pass deploy",
        "expected": "allow=true and deployed",
        "validates": "Safe dependency set passes policy and deploys the app.",
    },
    {
        "id": "phase2_vuln_block",
        "name": "Vulnerable dependency blocked",
        "expected": "allow=false due to vulns_found",
        "validates": "Known vulnerable dependency set is blocked by the policy gate.",
    },
    {
        "id": "phase2_missing_sbom_block",
        "name": "Missing SBOM blocked",
        "expected": "allow=false due to sbom_missing",
        "validates": "SBOM absence blocks deployment even when dependencies are otherwise safe.",
    },
]

TESTS = [
    ("T01", "Safe pass deploy", "Safe scenario deploys when all required evidence passes."),
    ("T02", "Vulnerable dependency blocked", "Vulnerable dependencies produce a block decision."),
    ("T03", "Missing SBOM blocked", "Missing SBOM produces a block decision."),
    ("T04", "Safe pass deploy", "Signature verification artifact is generated for the passing scenario."),
    ("T05", "All scenarios", "Evidence files are generated for each pipeline run."),
    ("T06", "Blocked scenarios", "Policy decisions contain explicit deny reasons."),
]


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def collect_scenario(scenario: dict[str, str]) -> dict[str, Any]:
    run_id = scenario["id"]
    run_dir = ARTIFACTS_DIR / run_id
    policy = read_json(run_dir / "policy_decision.json")
    evidence = read_json(run_dir / "evidence.json")
    deploy = read_json(run_dir / "deploy.json")

    return {
        "run_id": run_id,
        "scenario_name": scenario["name"],
        "expected_result": scenario["expected"],
        "allow": policy.get("allow"),
        "reasons": policy.get("reasons", []),
        "sbom_exists": (run_dir / "sbom.json").exists(),
        "cosign_verify_exists": (run_dir / "cosign_verify.json").exists(),
        "deploy_status": deploy.get("status", "missing"),
        "run_log": str(run_dir / "run.log"),
        "policy_decision_path": str(run_dir / "policy_decision.json"),
        "evidence_path": str(run_dir / "evidence.json"),
        "deploy_path": str(run_dir / "deploy.json"),
        "signature_verified": evidence.get("signature_verified"),
        "provenance_present": evidence.get("provenance_present"),
        "secrets_found": evidence.get("secrets_found"),
        "vulns_found": evidence.get("vulns_found"),
    }


def markdown_table(rows: list[list[str]]) -> str:
    header = "| " + " | ".join(rows[0]) + " |"
    divider = "| " + " | ".join("---" for _ in rows[0]) + " |"
    body = ["| " + " | ".join(row) + " |" for row in rows[1:]]
    return "\n".join([header, divider] + body)


def build_markdown(results: list[dict[str, Any]]) -> str:
    lines = [
        "# GuardRail Phase 2 Results Summary",
        "",
        "## Scenario Results",
        "",
    ]

    for result in results:
        reasons = ", ".join(result["reasons"]) if result["reasons"] else "none"
        lines.extend(
            [
                f"### {result['scenario_name']}",
                f"- Expected result: {result['expected_result']}",
                f"- Actual allow value: {result['allow']}",
                f"- Reasons: {reasons}",
                f"- sbom.json exists: {result['sbom_exists']}",
                f"- cosign_verify.json exists: {result['cosign_verify_exists']}",
                f"- deploy.json status: {result['deploy_status']}",
                f"- run.log path: `{result['run_log']}`",
                "",
            ]
        )

    lines.extend(
        [
            "## Requirements To Tests",
            "",
            markdown_table(
                [
                    ["Test ID", "Scenario", "What it validates"],
                    *[[test_id, scenario, validates] for test_id, scenario, validates in TESTS],
                ]
            ),
            "",
        ]
    )

    return "\n".join(lines)


def main() -> None:
    results = [collect_scenario(scenario) for scenario in SCENARIOS]

    summary_json = {
        "scenarios": results,
        "tests": [
            {
                "test_id": test_id,
                "scenario": scenario,
                "validates": validates,
            }
            for test_id, scenario, validates in TESTS
        ],
    }

    MARKDOWN_PATH.write_text(build_markdown(results), encoding="utf-8")
    JSON_PATH.write_text(json.dumps(summary_json, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
