"""GuardRail Phase C supply-chain pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
APP_DIR = REPO_ROOT / "app"
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
KEYS_DIR = REPO_ROOT / "keys"
CONTAINER_NAME = "guardrail-app"
HOST_REGISTRY = "localhost:5000"
CONTAINER_REGISTRY = "host.docker.internal:5000"


class ToolFailure(RuntimeError):
    def __init__(self, tool_name: str, message: str) -> None:
        super().__init__(message)
        self.tool_name = tool_name


class PipelineLogger:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.log_path.open("a", encoding="utf-8")

    def write(self, message: str) -> None:
        self.handle.write(message)
        self.handle.flush()

    def section(self, title: str) -> None:
        stamp = datetime.now(timezone.utc).isoformat()
        self.write(f"\n[{stamp}] {title}\n")

    def close(self) -> None:
        self.handle.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the GuardRail evidence pipeline.")
    parser.add_argument("--deps", choices=["safe", "vuln"], required=True)
    parser.add_argument("--simulate", choices=["missing_sbom"])
    parser.add_argument("--run-id")
    return parser.parse_args()


def make_run_id(explicit_run_id: str | None) -> str:
    if explicit_run_id:
        return explicit_run_id
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def run_command(
    command: list[str],
    logger: PipelineLogger,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    logger.section(f"COMMAND {' '.join(command)}")
    completed = subprocess.run(
        command,
        cwd=str(cwd or REPO_ROOT),
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        shell=False,
    )
    if completed.stdout:
        logger.write("--- stdout ---\n")
        logger.write(completed.stdout)
        if not completed.stdout.endswith("\n"):
            logger.write("\n")
    if completed.stderr:
        logger.write("--- stderr ---\n")
        logger.write(completed.stderr)
        if not completed.stderr.endswith("\n"):
            logger.write("\n")
    logger.write(f"--- exit_code: {completed.returncode} ---\n")
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"Command failed ({completed.returncode}): {' '.join(command)}"
        )
    return completed


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def count_gitleaks_findings(payload: Any) -> int:
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        for key in ("findings", "Leaks", "leaks", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return len(value)
    return 0


def count_osv_findings(payload: Any) -> int:
    count = 0
    if isinstance(payload, dict):
        results = payload.get("results")
        if isinstance(results, list):
            for result in results:
                if isinstance(result, dict):
                    packages = result.get("packages")
                    if isinstance(packages, list):
                        for package in packages:
                            if isinstance(package, dict):
                                vulns = package.get("vulnerabilities")
                                if isinstance(vulns, list):
                                    count += len(vulns)
                    vulns = result.get("vulnerabilities")
                    if isinstance(vulns, list):
                        count += len(vulns)
        if count:
            return count
        vulns = payload.get("vulnerabilities")
        if isinstance(vulns, list):
            return len(vulns)
    if isinstance(payload, list):
        return len(payload)
    return 0


def best_effort_version(
    command: list[str], logger: PipelineLogger, *, cwd: Path | None = None
) -> str:
    try:
        completed = run_command(command, logger, cwd=cwd, check=False)
    except Exception:
        return "unknown"
    output = (completed.stdout or completed.stderr).strip()
    return output.splitlines()[0] if output else "unknown"


def ensure_artifact_directories() -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


def ensure_registry(logger: PipelineLogger) -> None:
    run_command(["docker", "compose", "up", "-d", "registry"], logger, cwd=REPO_ROOT)


def reset_generated_keys(logger: PipelineLogger) -> None:
    for path in (KEYS_DIR / "cosign.key", KEYS_DIR / "cosign.pub"):
        if path.exists():
            path.unlink()
            logger.section(f"Removed stale generated key {path.name}")


def select_requirements(deps: str, logger: PipelineLogger) -> Path:
    source = APP_DIR / f"requirements_{deps}.txt"
    target = APP_DIR / "requirements.txt"
    shutil.copyfile(source, target)
    logger.section(f"Copied dependencies from {source.name} to requirements.txt")
    logger.write(target.read_text(encoding="utf-8"))
    if not target.read_text(encoding="utf-8").endswith("\n"):
        logger.write("\n")
    return target


def build_and_push(image_ref_host: str, logger: PipelineLogger) -> None:
    run_command(["docker", "build", "-t", image_ref_host, "app"], logger, cwd=REPO_ROOT)
    run_command(["docker", "push", image_ref_host], logger, cwd=REPO_ROOT)


def docker_volume_arg(host_path: Path, container_path: str) -> str:
    return f"{host_path}:{container_path}"


def run_semgrep(artifact_dir: Path, logger: PipelineLogger) -> Path:
    output = artifact_dir / "sast.json"
    repo_mount = docker_volume_arg(REPO_ROOT, "/src")
    completed = run_command(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            repo_mount,
            "-w",
            "/src",
            "semgrep/semgrep",
            "semgrep",
            "scan",
            "--config",
            "p/default",
            "--json",
            "--output",
            f"/src/artifacts/{artifact_dir.name}/sast.json",
            "app",
            "scripts",
            "policy",
        ],
        logger,
        cwd=REPO_ROOT,
        check=False,
    )
    if completed.returncode != 0 or not output.exists():
        write_json(
            output,
            {
                "tool": "semgrep",
                "status": "failed",
                "returncode": completed.returncode,
                "note": "non-blocking in this demo",
            },
        )
        logger.section(
            f"Semgrep non-blocking failure handled with placeholder report (exit {completed.returncode})"
        )
    return output


def run_gitleaks(artifact_dir: Path, logger: PipelineLogger) -> Path:
    output = artifact_dir / "secrets.json"
    repo_mount = docker_volume_arg(REPO_ROOT, "/repo")
    completed = run_command(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            repo_mount,
            "zricethezav/gitleaks:latest",
            "detect",
            "--config",
            "/repo/.gitleaks.toml",
            "--no-git",
            "--source",
            "/repo",
            "--no-banner",
            "--report-format",
            "json",
            "--report-path",
            f"/repo/artifacts/{artifact_dir.name}/secrets.json",
            "--exit-code",
            "0",
        ],
        logger,
        cwd=REPO_ROOT,
        check=False,
    )
    if completed.returncode != 0 or not output.exists():
        raise ToolFailure(
            "gitleaks",
            f"gitleaks failed or did not produce output (exit {completed.returncode})",
        )
    return output


def run_osv_scan(requirements_file: Path, artifact_dir: Path, logger: PipelineLogger) -> Path:
    output = artifact_dir / "sca.json"
    repo_mount = docker_volume_arg(REPO_ROOT, "/src")
    completed = run_command(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            repo_mount,
            "ghcr.io/google/osv-scanner:latest",
            "scan",
            "source",
            "--no-resolve",
            "--lockfile",
            f"requirements.txt:/src/app/{requirements_file.name}",
            "--format",
            "json",
            "--output-file",
            f"/src/artifacts/{artifact_dir.name}/sca.json",
        ],
        logger,
        cwd=REPO_ROOT,
        check=False,
    )
    if completed.returncode not in (0, 1) or not output.exists():
        raise ToolFailure(
            "osv_scanner",
            f"osv-scanner failed or did not produce output (exit {completed.returncode})",
        )
    return output


def generate_sbom(image_ref_container: str, artifact_dir: Path, logger: PipelineLogger) -> Path:
    output = artifact_dir / "sbom.json"
    repo_mount = docker_volume_arg(REPO_ROOT, "/workspace")
    completed = run_command(
        [
            "docker",
            "run",
            "--rm",
            "-e",
            "SYFT_REGISTRY_INSECURE_USE_HTTP=true",
            "-e",
            "SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true",
            "-v",
            repo_mount,
            "anchore/syft:latest",
            "--from",
            "registry",
            image_ref_container,
            "-o",
            f"cyclonedx-json=/workspace/artifacts/{artifact_dir.name}/sbom.json",
        ],
        logger,
        cwd=REPO_ROOT,
        check=False,
    )
    if completed.returncode != 0 or not output.exists():
        raise ToolFailure(
            "syft",
            f"syft failed or did not produce output (exit {completed.returncode})",
        )
    return output


def ensure_signing_config() -> Path:
    config_path = KEYS_DIR / "signing_config.json"
    write_json(
        config_path,
        {
            "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
            "caUrls": [],
            "oidcUrls": [],
            "rekorTlogUrls": [],
            "tsaUrls": [],
        },
    )
    return config_path


def ensure_cosign_keys(logger: PipelineLogger) -> tuple[Path, Path, Path]:
    private_key = KEYS_DIR / "cosign.key"
    public_key = KEYS_DIR / "cosign.pub"
    signing_config = ensure_signing_config()
    if private_key.exists() and public_key.exists():
        return private_key, public_key, signing_config

    keys_mount = docker_volume_arg(KEYS_DIR, "/keys")
    env = os.environ.copy()
    env["COSIGN_PASSWORD"] = ""
    run_command(
        [
            "docker",
            "run",
            "--rm",
            "-e",
            "COSIGN_PASSWORD=",
            "-v",
            keys_mount,
            "ghcr.io/sigstore/cosign/cosign:latest",
            "generate-key-pair",
            "--output-key-prefix",
            "/keys/cosign",
        ],
        logger,
        cwd=REPO_ROOT,
        env=env,
    )
    return private_key, public_key, signing_config


def cosign_sign_and_verify(
    image_ref_host: str, image_digest: str, artifact_dir: Path, logger: PipelineLogger
) -> tuple[bool, Path]:
    _, _, signing_config = ensure_cosign_keys(logger)
    keys_mount = docker_volume_arg(KEYS_DIR, "/keys")
    env = os.environ.copy()
    env["COSIGN_PASSWORD"] = ""
    image_repo = image_ref_host.rsplit(":", 1)[0]
    digest_ref = f"{image_repo}@{image_digest}"

    sign_completed = run_command(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "-e",
            "COSIGN_PASSWORD=",
            "-v",
            keys_mount,
            "ghcr.io/sigstore/cosign/cosign:latest",
            "sign",
            "--yes",
            "--allow-insecure-registry",
            "--signing-config",
            f"/keys/{signing_config.name}",
            "--key",
            "/keys/cosign.key",
            digest_ref,
        ],
        logger,
        cwd=REPO_ROOT,
        env=env,
        check=False,
    )
    if sign_completed.returncode != 0:
        raise ToolFailure(
            "cosign_sign",
            f"cosign sign failed with exit {sign_completed.returncode}",
        )

    verify_output = artifact_dir / "cosign_verify.json"
    completed = run_command(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "-e",
            "COSIGN_PASSWORD=",
            "-v",
            keys_mount,
            "ghcr.io/sigstore/cosign/cosign:latest",
            "verify",
            "--allow-insecure-registry",
            "--key",
            "/keys/cosign.pub",
            "--insecure-ignore-tlog=true",
            digest_ref,
        ],
        logger,
        cwd=REPO_ROOT,
        env=env,
        check=False,
    )
    verify_output.write_text(completed.stdout or completed.stderr or "", encoding="utf-8")
    return completed.returncode == 0, verify_output


def get_git_commit(logger: PipelineLogger) -> str:
    completed = run_command(
        ["git", "rev-parse", "HEAD"], logger, cwd=REPO_ROOT, check=False
    )
    commit = (completed.stdout or "").strip()
    return commit or "unknown"


def get_image_digest(image_ref_host: str, logger: PipelineLogger) -> str:
    completed = run_command(
        [
            "docker",
            "image",
            "inspect",
            image_ref_host,
            "--format",
            "{{index .RepoDigests 0}}",
        ],
        logger,
        cwd=REPO_ROOT,
        check=False,
    )
    repo_digest = (completed.stdout or "").strip()
    if "@" in repo_digest:
        return repo_digest.split("@", 1)[1]
    return repo_digest or "unknown"


def collect_hashes(paths: dict[str, Path | None]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for name, path in paths.items():
        if path and path.exists():
            hashes[name] = sha256_file(path)
    return hashes


def write_provenance(
    artifact_dir: Path,
    logger: PipelineLogger,
    *,
    run_id: str,
    image_ref_host: str,
    image_ref_container: str,
    image_digest: str,
    file_hashes: dict[str, str],
) -> Path:
    versions = {
        "docker": best_effort_version(["docker", "--version"], logger, cwd=REPO_ROOT),
        "semgrep": best_effort_version(
            ["docker", "run", "--rm", "semgrep/semgrep", "semgrep", "--version"], logger
        ),
        "gitleaks": best_effort_version(
            ["docker", "run", "--rm", "zricethezav/gitleaks:latest", "version"], logger
        ),
        "osv_scanner": best_effort_version(
            ["docker", "run", "--rm", "ghcr.io/google/osv-scanner:latest", "--version"],
            logger,
        ),
        "syft": best_effort_version(
            ["docker", "run", "--rm", "anchore/syft:latest", "version"], logger
        ),
        "cosign": best_effort_version(
            ["docker", "run", "--rm", "ghcr.io/sigstore/cosign/cosign:latest", "version"],
            logger,
        ),
    }
    provenance = {
        "run_id": run_id,
        "git_commit": get_git_commit(logger),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "image_ref_host": image_ref_host,
        "image_ref_container": image_ref_container,
        "image_digest": image_digest,
        "sha256": file_hashes,
        "tool_versions": versions,
    }
    path = artifact_dir / "provenance.json"
    write_json(path, provenance)
    return path


def build_evidence(
    artifact_dir: Path,
    *,
    signature_verified: bool,
    sbom_path: Path,
    provenance_path: Path,
    secrets_path: Path,
    sca_path: Path,
) -> tuple[dict[str, Any], Path]:
    secrets_payload = load_json(secrets_path)
    sca_payload = load_json(sca_path)
    evidence = {
        "signature_verified": signature_verified,
        "sbom_present": sbom_path.exists(),
        "provenance_present": provenance_path.exists(),
        "secrets_found": count_gitleaks_findings(secrets_payload),
        "vulns_found": count_osv_findings(sca_payload),
    }
    path = artifact_dir / "evidence.json"
    write_json(path, evidence)
    return evidence, path


def write_failure_outputs(
    artifact_dir: Path,
    logger: PipelineLogger,
    *,
    run_id: str,
    image_ref_host: str,
    image_ref_container: str,
    reason: str,
) -> None:
    logger.section(f"Writing failure outputs for reason: {reason}")
    evidence = {
        "signature_verified": False,
        "sbom_present": (artifact_dir / "sbom.json").exists(),
        "provenance_present": (artifact_dir / "provenance.json").exists(),
        "secrets_found": 0,
        "vulns_found": 0,
    }
    write_json(artifact_dir / "evidence.json", evidence)
    write_json(
        artifact_dir / "policy_decision.json",
        {
            "allow": False,
            "reasons": [reason],
            "run_id": run_id,
            "image_ref_host": image_ref_host,
            "image_ref_container": image_ref_container,
        },
    )
    remove_container(logger)
    write_json(artifact_dir / "deploy.json", {"status": "blocked"})


def evaluate_policy(
    artifact_dir: Path,
    *,
    run_id: str,
    image_ref_host: str,
    image_ref_container: str,
    evidence: dict[str, Any],
) -> tuple[dict[str, Any], Path]:
    reasons: list[str] = []
    if evidence["secrets_found"] > 0:
        reasons.append("secrets_found")
    if evidence["vulns_found"] > 0:
        reasons.append("vulns_found")
    if not evidence["sbom_present"]:
        reasons.append("sbom_missing")
    if not evidence["signature_verified"]:
        reasons.append("signature_not_verified")
    decision = {
        "allow": not reasons,
        "reasons": reasons,
        "run_id": run_id,
        "image_ref_host": image_ref_host,
        "image_ref_container": image_ref_container,
    }
    path = artifact_dir / "policy_decision.json"
    write_json(path, decision)
    return decision, path


def remove_container(logger: PipelineLogger) -> None:
    run_command(["docker", "rm", "-f", CONTAINER_NAME], logger, cwd=REPO_ROOT, check=False)


def deploy_or_block(
    artifact_dir: Path, logger: PipelineLogger, *, allow: bool, image_ref_host: str
) -> Path:
    remove_container(logger)
    path = artifact_dir / "deploy.json"
    if allow:
        completed = run_command(
            [
                "docker",
                "run",
                "-d",
                "--name",
                CONTAINER_NAME,
                "-p",
                "8000:8000",
                image_ref_host,
            ],
            logger,
            cwd=REPO_ROOT,
        )
        deploy = {
            "status": "deployed",
            "container_id": (completed.stdout or "").strip(),
            "port": 8000,
        }
    else:
        deploy = {"status": "blocked"}
    write_json(path, deploy)
    return path


def main() -> int:
    args = parse_args()
    ensure_artifact_directories()
    run_id = make_run_id(args.run_id)
    artifact_dir = ARTIFACTS_DIR / run_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    logger = PipelineLogger(artifact_dir / "run.log")

    image_ref_host = f"{HOST_REGISTRY}/guardrail-app:{run_id}"
    image_ref_container = f"{CONTAINER_REGISTRY}/guardrail-app:{run_id}"

    try:
        reset_generated_keys(logger)
        ensure_registry(logger)
        requirements_file = select_requirements(args.deps, logger)
        build_and_push(image_ref_host, logger)
        image_digest = get_image_digest(image_ref_host, logger)

        sast_path = run_semgrep(artifact_dir, logger)
        secrets_path = run_gitleaks(artifact_dir, logger)
        sca_path = run_osv_scan(requirements_file, artifact_dir, logger)
        sbom_path = generate_sbom(image_ref_container, artifact_dir, logger)

        if args.simulate == "missing_sbom" and sbom_path.exists():
            sbom_path.unlink()
            logger.section("Simulated missing SBOM by deleting sbom.json")

        signature_verified, cosign_verify_path = cosign_sign_and_verify(
            image_ref_host, image_digest, artifact_dir, logger
        )

        file_hashes = collect_hashes(
            {
                "sast.json": sast_path,
                "secrets.json": secrets_path,
                "sca.json": sca_path,
                "sbom.json": sbom_path if sbom_path.exists() else None,
                "cosign_verify.json": cosign_verify_path,
            }
        )
        provenance_path = write_provenance(
            artifact_dir,
            logger,
            run_id=run_id,
            image_ref_host=image_ref_host,
            image_ref_container=image_ref_container,
            image_digest=image_digest,
            file_hashes=file_hashes,
        )
        evidence, _ = build_evidence(
            artifact_dir,
            signature_verified=signature_verified,
            sbom_path=sbom_path,
            provenance_path=provenance_path,
            secrets_path=secrets_path,
            sca_path=sca_path,
        )
        decision, _ = evaluate_policy(
            artifact_dir,
            run_id=run_id,
            image_ref_host=image_ref_host,
            image_ref_container=image_ref_container,
            evidence=evidence,
        )
        deploy_or_block(
            artifact_dir, logger, allow=bool(decision["allow"]), image_ref_host=image_ref_host
        )

        print(f"RUN_ID={run_id}")
        print(f"ALLOW={str(decision['allow']).lower()}")
        print(f"REASONS={','.join(decision['reasons']) if decision['reasons'] else 'none'}")
        print(f"ARTIFACT_PATH={artifact_dir}")
        return 0
    except ToolFailure as exc:
        write_failure_outputs(
            artifact_dir,
            logger,
            run_id=run_id,
            image_ref_host=image_ref_host,
            image_ref_container=image_ref_container,
            reason=f"tool_failure:{exc.tool_name}",
        )
        print(f"RUN_ID={run_id}")
        print("ALLOW=false")
        print(f"REASONS=tool_failure:{exc.tool_name}")
        print(f"ARTIFACT_PATH={artifact_dir}")
        return 1
    except Exception as exc:
        logger.section(f"PIPELINE ERROR: {exc}")
        write_failure_outputs(
            artifact_dir,
            logger,
            run_id=run_id,
            image_ref_host=image_ref_host,
            image_ref_container=image_ref_container,
            reason="pipeline_error",
        )
        print(f"RUN_ID={run_id}")
        print("ALLOW=false")
        print("REASONS=pipeline_error")
        print(f"ARTIFACT_PATH={artifact_dir}")
        return 1
    finally:
        logger.close()


if __name__ == "__main__":
    sys.exit(main())
