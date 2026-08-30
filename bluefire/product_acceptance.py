"""Locked, sequential, receipt-backed release acceptance for BlueFire Nexus."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Sequence

from .product_acceptance_artifacts import contained_regular_file, inspect_regular_file
from .product_acceptance_contract import (
    _ALLOWED_PROOF_KINDS,
    _SAFE_IDENTIFIER,
    CONTRACT_SCHEMA_VERSION,
    EXPECTED_GATE_IDS,
    RECEIPT_SCHEMA_VERSION,
    RELEASE_CONTRACT_SHA256,
    AcceptanceContractError,
    GateAssertion,
    GateDefinition,
    ReleaseContract,
    _canonical_json_bytes,
    _sha256_bytes,
    contract_from_mapping,
    load_release_contract,
)
from .product_acceptance_postflight import (
    apply_gate_failures as _apply_postflight_gate_failures,
)
from .product_acceptance_postflight import (
    bind_gate_12_assessment as _bind_postflight_assessment,
)
from .product_acceptance_postflight import (
    final_artifact_failures as _verify_final_artifact_hashes,
)
from .product_acceptance_postflight import (
    persist_result_assessment as _persist_result_postflight,
)
from .product_acceptance_postflight import repository_state as _repository_state
from .product_acceptance_process import (
    _PLAYWRIGHT_BROWSER_RESOURCE_ENV,
    _cargo_cache_home_path,
    _execute_workflow,
    _isolated_workflow_environment,
    _playwright_browsers_path,
    _process_containment_limitations,
    _redact_runtime_paths,
    _sanitize_gate_receipt,
    _sanitize_workflow_log,
    _write_gate_assessment,
)
from .product_acceptance_run_bundle import (
    acceptance_run_binding as _acceptance_run_binding,
)
from .product_acceptance_run_bundle import (
    validated_run_bundle as _validated_run_bundle,
)
from .product_acceptance_schema import (
    RESULT_SCHEMA_VERSION,
    derive_result_failure_reason,
    validate_result_contract,
)
from .product_acceptance_schema import (
    result_schema_document as result_schema_document,
)
from .product_acceptance_schema import (
    validate_result_structure as _validate_result_structure,
)
from .product_acceptance_verifier import verify_result_file


class AcceptanceFailure(RuntimeError):
    """Carries a complete failed release result to a command-line caller."""

    def __init__(self, result: Mapping[str, Any]) -> None:
        super().__init__(str(result.get("failure_reason") or "release acceptance failed"))
        self.result = dict(result)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def validate_acceptance_result(
    result: Mapping[str, Any],
    *,
    contract: ReleaseContract | None = None,
) -> None:
    """Validate structure and exact locked-contract semantics together."""

    expected = contract or load_release_contract()
    _validate_result_structure(result)
    validate_result_contract(result, expected.document, expected.digest)


def discover_repository_root(start: Path | None = None) -> Path:
    candidate = (start or Path.cwd()).resolve()
    for path in (candidate, *candidate.parents):
        if (path / "pyproject.toml").is_file() and (path / ".git").exists():
            return path
    raise ValueError("run release acceptance from a BlueFire Nexus checkout")


def _render_command(
    gate: GateDefinition,
    *,
    repository: Path,
    run_dir: Path,
    gate_dir: Path,
    receipt: Path,
) -> list[str]:
    values = {
        "python": os.fspath(Path(sys.executable).resolve()),
        "repository": os.fspath(repository),
        "run_dir": os.fspath(run_dir),
        "gate_dir": os.fspath(gate_dir),
        "receipt": os.fspath(receipt),
    }
    return [token.format_map(values) for token in gate.command]


def _relative_artifact(run_dir: Path, path: Path, role: str) -> dict[str, Any]:
    relative = path.absolute().relative_to(run_dir.resolve()).as_posix()
    inspection = inspect_regular_file(
        run_dir,
        relative,
        label=f"{role} evidence artifact",
    )
    if inspection.contains_private_path:
        raise ValueError(f"{role} evidence artifact discloses a local absolute path")
    return {
        "path": relative,
        "sha256": inspection.sha256,
        "size_bytes": inspection.size_bytes,
        "role": role,
    }


def _safe_declared_artifact(gate_dir: Path, raw: Any) -> Path:
    if not isinstance(raw, str) or not raw or len(raw) > 1024:
        raise ValueError("evidence artifact path must be non-empty bounded text")
    portable = PurePosixPath(raw.replace("\\", "/"))
    if portable.is_absolute() or PureWindowsPath(raw).is_absolute() or ".." in portable.parts:
        raise ValueError("evidence artifact path must stay inside its gate directory")
    return contained_regular_file(gate_dir, raw, label="evidence artifact")


def _receipt_proof(
    raw: Any,
    *,
    gate_dir: Path,
    run_dir: Path,
    assertions: Mapping[str, str],
    expected_binding: Mapping[str, str],
    not_before: datetime,
    not_after: datetime,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[str]]:
    issues: list[str] = []
    artifacts: list[dict[str, Any]] = []
    required_fields = {
        "kind",
        "status",
        "test_id",
        "assertion_ids",
        "evidence_artifacts",
        "run_ids",
        "run_bundles",
        "environment_limitations",
    }
    if not isinstance(raw, Mapping) or set(raw) != required_fields:
        return None, artifacts, ["receipt proof must be an object"]
    kind = raw.get("kind")
    status = raw.get("status")
    test_id = raw.get("test_id")
    if kind not in _ALLOWED_PROOF_KINDS:
        issues.append("receipt proof kind must be dynamic or structural")
    if status != "passed":
        issues.append("receipt proof status must be passed")
    if not isinstance(test_id, str) or not _SAFE_IDENTIFIER.fullmatch(test_id):
        issues.append("receipt proof test_id is invalid")

    assertion_ids = raw.get("assertion_ids")
    if not isinstance(assertion_ids, Sequence) or isinstance(assertion_ids, (str, bytes)):
        issues.append("receipt proof assertion_ids must be a list")
        assertion_ids = []
    elif not assertion_ids or any(
        not isinstance(item, str) or not _SAFE_IDENTIFIER.fullmatch(item) for item in assertion_ids
    ):
        issues.append("receipt proof assertion_ids must contain valid identifiers")
    elif len(assertion_ids) != len(set(assertion_ids)):
        issues.append("receipt proof assertion_ids must be unique")
    else:
        unknown = sorted(set(assertion_ids) - set(assertions))
        mismatched = sorted(
            item for item in set(assertion_ids) & set(assertions) if assertions[item] != kind
        )
        if unknown:
            issues.append("receipt proof contains unknown assertions: " + ", ".join(unknown))
        if mismatched:
            issues.append("receipt proof kind does not match assertions: " + ", ".join(mismatched))

    run_ids = raw.get("run_ids", [])
    if not isinstance(run_ids, Sequence) or isinstance(run_ids, (str, bytes)):
        issues.append("receipt proof run_ids must be a list")
        run_ids = []
    elif any(not isinstance(item, str) or not _SAFE_IDENTIFIER.fullmatch(item) for item in run_ids):
        issues.append("receipt proof contains an invalid run_id")
    elif len(run_ids) != len(set(run_ids)):
        issues.append("receipt proof run_ids must be unique")

    raw_run_bundles = raw.get("run_bundles", [])
    run_bundles: list[dict[str, Any]] = []
    if not isinstance(raw_run_bundles, Sequence) or isinstance(raw_run_bundles, (str, bytes)):
        issues.append("receipt proof run_bundles must be a list")
    else:
        bundle_ids: list[str] = []
        for raw_bundle in raw_run_bundles:
            try:
                bundle, bundle_artifact = _validated_run_bundle(
                    gate_dir,
                    run_dir,
                    raw_bundle,
                    expected_binding=expected_binding,
                    not_before=not_before,
                    not_after=not_after,
                )
                bundle_inspection = inspect_regular_file(
                    run_dir,
                    bundle_artifact["path"],
                    label="validated run bundle manifest",
                )
                if bundle_inspection.contains_private_path:
                    raise ValueError(
                        "validated run bundle manifest discloses a local absolute path"
                    )
                if (
                    bundle_inspection.sha256 != bundle_artifact["sha256"]
                    or bundle_inspection.size_bytes != bundle_artifact["size_bytes"]
                ):
                    raise ValueError("validated run bundle manifest changed during validation")
            except (OSError, ValueError) as exc:
                issues.append(str(exc))
                continue
            run_bundles.append(bundle)
            bundle_ids.append(bundle["run_id"])
            artifacts.append(bundle_artifact)
        if len(bundle_ids) != len(set(bundle_ids)):
            issues.append("receipt proof run bundles must be unique")
        if set(bundle_ids) != set(run_ids):
            issues.append("every claimed run ID must bind exactly one validated run bundle")

    limitations = raw.get("environment_limitations", [])
    if not isinstance(limitations, Sequence) or isinstance(limitations, (str, bytes)):
        issues.append("receipt proof environment_limitations must be a list")
        limitations = []
    elif any(not isinstance(item, str) or len(item) > 2000 for item in limitations):
        issues.append("receipt proof contains an invalid environment limitation")

    evidence = raw.get("evidence_artifacts")
    if not isinstance(evidence, Sequence) or isinstance(evidence, (str, bytes)):
        issues.append("receipt proof evidence_artifacts must be a list")
    else:
        for item in evidence:
            try:
                artifacts.append(
                    _relative_artifact(
                        run_dir,
                        _safe_declared_artifact(gate_dir, item),
                        "declared-proof",
                    )
                )
            except (OSError, ValueError) as exc:
                issues.append(str(exc))

    unique_artifacts = {artifact["path"]: artifact for artifact in artifacts}
    artifacts = list(unique_artifacts.values())
    if not artifacts:
        issues.append("receipt proof must reference at least one validated artifact")
    if issues:
        return None, artifacts, issues
    normalized = {
        "kind": kind,
        "status": status,
        "test_id": test_id,
        "assertion_ids": sorted(set(assertion_ids)),
        "evidence_artifacts": [artifact["path"] for artifact in artifacts],
        "run_ids": list(run_ids),
        "run_bundles": run_bundles,
        "environment_limitations": list(limitations),
    }
    return normalized, artifacts, issues


def _read_receipt(
    gate: GateDefinition,
    *,
    receipt_path: Path,
    gate_dir: Path,
    run_dir: Path,
    acceptance_id: str,
    contract_digest: str,
    repository_commit: str,
    repository_tree: str,
    release: bool,
    gate_started_at: datetime,
    gate_finished_at: datetime,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], str | None]:
    issues: list[str] = []
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [], [], [f"gate receipt is unavailable or invalid: {exc}"], None
    if not isinstance(receipt, Mapping):
        return [], [], ["gate receipt must be an object"], None
    required_fields = {
        "schema_version",
        "gate_id",
        "acceptance_id",
        "contract_sha256",
        "repository_commit",
        "repository_tree",
        "release",
        "harness_assessment",
        "timestamp",
        "status",
        "failure_reason",
        "proofs",
    }
    if set(receipt) != required_fields:
        issues.append("gate receipt fields do not match the receipt schema")
    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        issues.append("gate receipt schema_version is invalid")
    if receipt.get("gate_id") != gate.gate_id:
        issues.append("gate receipt gate_id does not match the executed gate")
    if receipt.get("acceptance_id") != acceptance_id:
        issues.append("gate receipt acceptance_id does not match this acceptance run")
    if receipt.get("contract_sha256") != contract_digest:
        issues.append("gate receipt contract digest does not match the locked contract")
    if receipt.get("repository_commit") != repository_commit:
        issues.append("gate receipt repository commit does not match the tested commit")
    if receipt.get("repository_tree") != repository_tree:
        issues.append("gate receipt repository tree does not match the tested tree")
    if receipt.get("release") is not release:
        issues.append("gate receipt release mode does not match this acceptance run")
    if receipt.get("harness_assessment") is not None:
        issues.append("gate receipt harness assessment slot must be empty before validation")

    receipt_timestamp = receipt.get("timestamp")
    if not isinstance(receipt_timestamp, str) or not receipt_timestamp.endswith("Z"):
        issues.append("gate receipt timestamp is invalid")
    else:
        try:
            parsed_timestamp = datetime.fromisoformat(
                receipt_timestamp.removesuffix("Z") + "+00:00"
            )
        except ValueError:
            issues.append("gate receipt timestamp is invalid")
        else:
            if not gate_started_at <= parsed_timestamp <= gate_finished_at:
                issues.append("gate receipt timestamp is outside the workflow invocation")

    if receipt.get("status") != "passed":
        issues.append("gate receipt status is not passed")
    failure_reason = receipt.get("failure_reason")
    if failure_reason is not None and (
        not isinstance(failure_reason, str) or not failure_reason or len(failure_reason) > 2000
    ):
        issues.append("gate receipt failure_reason is invalid")
        failure_reason = None
    if receipt.get("status") == "passed" and failure_reason is not None:
        issues.append("passed gate receipt cannot contain a failure_reason")
    raw_proofs = receipt.get("proofs")
    if not isinstance(raw_proofs, Sequence) or isinstance(raw_proofs, (str, bytes)):
        return [], [], [*issues, "gate receipt proofs must be a list"], failure_reason

    proofs: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    expected_binding = _acceptance_run_binding(
        acceptance_id,
        gate.gate_id,
        contract_digest,
        repository_commit,
        repository_tree,
        "true" if release else "false",
    )
    for raw in raw_proofs:
        proof, proof_artifacts, proof_issues = _receipt_proof(
            raw,
            gate_dir=gate_dir,
            run_dir=run_dir,
            assertions={assertion.assertion_id: assertion.proof for assertion in gate.assertions},
            expected_binding=expected_binding,
            not_before=gate_started_at,
            not_after=gate_finished_at,
        )
        artifacts.extend(proof_artifacts)
        issues.extend(proof_issues)
        if proof is not None:
            proofs.append(proof)
    return proofs, artifacts, issues, failure_reason


def _run_gate(
    gate: GateDefinition,
    *,
    repository: Path,
    run_dir: Path,
    acceptance_id: str,
    contract_digest: str,
    repository_commit: str,
    repository_tree: str,
    release: bool,
) -> dict[str, Any]:
    gate_dir = run_dir / gate.gate_id.lower()
    gate_dir.mkdir(parents=True, exist_ok=False)
    receipt_path = gate_dir / "gate-receipt.json"
    stdout_path = gate_dir / "workflow.stdout.log"
    stderr_path = gate_dir / "workflow.stderr.log"
    runtime_home = gate_dir / "runtime-home"
    runtime_temp = gate_dir / "runtime-temp"
    cargo_target = gate_dir / "runtime-cargo-target"
    runtime_home.mkdir()
    runtime_temp.mkdir()
    command = _render_command(
        gate,
        repository=repository,
        run_dir=run_dir,
        gate_dir=gate_dir,
        receipt=receipt_path,
    )
    environment = _isolated_workflow_environment(
        runtime_home=runtime_home,
        runtime_temp=runtime_temp,
        cargo_target=cargo_target,
    )
    if gate.gate_id in {"GATE-07", "GATE-08", "GATE-09", "GATE-12"}:
        playwright_browsers = _playwright_browsers_path()
        if playwright_browsers is not None:
            environment[_PLAYWRIGHT_BROWSER_RESOURCE_ENV] = os.fspath(playwright_browsers)
    if gate.gate_id == "GATE-12":
        cargo_cache_home = _cargo_cache_home_path()
        if cargo_cache_home is not None:
            environment["CARGO_HOME"] = os.fspath(cargo_cache_home)
    if gate.gate_id in {"GATE-03", "GATE-11"}:
        wheelhouse = os.environ.get("BLUEFIRE_GATE11_LINUX_WHEELHOUSE")
        if isinstance(wheelhouse, str) and 0 < len(wheelhouse) <= 4_096 and "\0" not in wheelhouse:
            environment["BLUEFIRE_GATE11_LINUX_WHEELHOUSE"] = wheelhouse
    environment.update(
        {
            "BLUEFIRE_ACCEPTANCE_ID": acceptance_id,
            "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256": contract_digest,
            "BLUEFIRE_ACCEPTANCE_GATE_ID": gate.gate_id,
            "BLUEFIRE_ACCEPTANCE_GATE_DIR": os.fspath(gate_dir),
            "BLUEFIRE_ACCEPTANCE_RECEIPT": os.fspath(receipt_path),
            "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT": repository_commit,
            "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE": repository_tree,
            "BLUEFIRE_ACCEPTANCE_RELEASE": "true" if release else "false",
        }
    )

    gate_started_at = datetime.now(timezone.utc)
    started = time.monotonic()
    outcome = _execute_workflow(
        command,
        repository=repository,
        environment=environment,
        timeout_seconds=gate.timeout_seconds,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
    duration_ms = max(0, round((time.monotonic() - started) * 1000))
    gate_finished_at = datetime.now(timezone.utc)
    _sanitize_workflow_log(stdout_path, repository=repository, run_dir=run_dir)
    _sanitize_workflow_log(stderr_path, repository=repository, run_dir=run_dir)
    if receipt_path.is_file():
        _sanitize_gate_receipt(receipt_path, repository=repository, run_dir=run_dir)

    proofs: list[dict[str, Any]] = []
    declared_artifacts: list[dict[str, Any]] = []
    issues: list[str] = []
    public_artifacts = [
        (stdout_path, "workflow-stdout"),
        (stderr_path, "workflow-stderr"),
    ]
    if receipt_path.is_file():
        public_artifacts.append((receipt_path, "gate-receipt"))
    for public_path, role in public_artifacts:
        try:
            _relative_artifact(run_dir, public_path, role)
        except (OSError, ValueError) as exc:
            issues.append(str(exc))
    receipt_failure: str | None = None
    if outcome.failure_reason is not None:
        issues.append(
            _redact_runtime_paths(
                outcome.failure_reason,
                repository=repository,
                run_dir=run_dir,
            )
        )
    if receipt_path.is_file():
        proofs, declared_artifacts, receipt_issues, receipt_failure = _read_receipt(
            gate,
            receipt_path=receipt_path,
            gate_dir=gate_dir,
            run_dir=run_dir,
            acceptance_id=acceptance_id,
            contract_digest=contract_digest,
            repository_commit=repository_commit,
            repository_tree=repository_tree,
            release=release,
            gate_started_at=gate_started_at,
            gate_finished_at=gate_finished_at,
        )
        issues.extend(receipt_issues)
    else:
        issues.append("workflow did not emit the required gate receipt")

    for proof in proofs:
        proof["environment_limitations"] = [
            _redact_runtime_paths(item, repository=repository, run_dir=run_dir)
            for item in proof["environment_limitations"]
        ]
    if receipt_failure:
        receipt_failure = _redact_runtime_paths(
            receipt_failure,
            repository=repository,
            run_dir=run_dir,
        )
        issues.append("gate workflow reported: " + receipt_failure)

    proof_types = sorted({proof["kind"] for proof in proofs})
    missing_proof = sorted(set(gate.required_proof) - set(proof_types))
    if missing_proof:
        issues.append("missing required proof types: " + ", ".join(missing_proof))
    test_ids = sorted({proof["test_id"] for proof in proofs})
    if len(test_ids) != len(proofs):
        issues.append("each assertion proof must have a unique test ID")
    if any(len(proof["assertion_ids"]) != 1 for proof in proofs):
        issues.append("each proof must cover exactly one locked assertion")
    required_assertion_ids = sorted(assertion.assertion_id for assertion in gate.assertions)
    covered_assertion_ids = sorted(
        {assertion_id for proof in proofs for assertion_id in proof["assertion_ids"]}
    )
    missing_assertion_ids = sorted(set(required_assertion_ids) - set(covered_assertion_ids))
    duplicate_assertions = sorted(
        {
            assertion_id
            for assertion_id in covered_assertion_ids
            if sum(assertion_id in proof["assertion_ids"] for proof in proofs) > 1
        }
    )
    if duplicate_assertions:
        issues.append("assertions have duplicate proofs: " + ", ".join(duplicate_assertions))
    if missing_assertion_ids:
        issues.append("missing required assertions: " + ", ".join(missing_assertion_ids))
    run_ids = sorted({run_id for proof in proofs for run_id in proof["run_ids"]})
    limitations = sorted(
        {
            _redact_runtime_paths(item, repository=repository, run_dir=run_dir)
            for proof in proofs
            for item in proof["environment_limitations"]
        }
    )
    unique_declared = {artifact["path"]: artifact for artifact in declared_artifacts}
    if len(unique_declared) < gate.minimum_evidence_artifacts:
        issues.append(
            f"declared evidence count {len(unique_declared)} is below required minimum {gate.minimum_evidence_artifacts}"
        )
    if len(run_ids) < gate.minimum_run_ids:
        issues.append(
            f"run ID count {len(run_ids)} is below required minimum {gate.minimum_run_ids}"
        )
    if len(test_ids) < gate.minimum_test_ids:
        issues.append(
            f"test ID count {len(test_ids)} is below required minimum {gate.minimum_test_ids}"
        )

    issues = [
        _redact_runtime_paths(issue, repository=repository, run_dir=run_dir) for issue in issues
    ]
    failure_reason = "; ".join(dict.fromkeys(issues)) if issues else None
    status = "passed" if failure_reason is None else "failed"
    if receipt_path.is_file():
        try:
            _write_gate_assessment(
                receipt_path,
                {
                    "schema_version": "bluefire.product-gate-assessment.v1",
                    "status": status,
                    "failure_reason": failure_reason,
                    "workflow_exit_code": outcome.exit_code,
                    "proof_sha256": _sha256_bytes(_canonical_json_bytes(proofs)),
                    "postflight": None,
                },
            )
        except (OSError, ValueError) as exc:
            failure_reason = "; ".join(
                dict.fromkeys([*issues, f"gate assessment could not be persisted: {exc}"])
            )
            status = "failed"

    artifacts = list(unique_declared.values())
    artifacts.append(_relative_artifact(run_dir, stdout_path, "workflow-stdout"))
    artifacts.append(_relative_artifact(run_dir, stderr_path, "workflow-stderr"))
    if receipt_path.is_file():
        artifacts.append(_relative_artifact(run_dir, receipt_path, "gate-receipt"))
    artifacts = sorted(
        {item["path"]: item for item in artifacts}.values(), key=lambda item: item["path"]
    )
    return {
        "gate_id": gate.gate_id,
        "title": gate.title,
        "required": gate.required,
        "status": status,
        "workflow": {
            "command": list(gate.command),
            "command_sha256": _sha256_bytes(_canonical_json_bytes(gate.command)),
            "working_directory": ".",
            "exit_code": outcome.exit_code,
            "duration_ms": duration_ms,
            "started_at": gate_started_at.isoformat().replace("+00:00", "Z"),
            "finished_at": gate_finished_at.isoformat().replace("+00:00", "Z"),
            "stdout_path": stdout_path.resolve().relative_to(run_dir.resolve()).as_posix(),
            "stderr_path": stderr_path.resolve().relative_to(run_dir.resolve()).as_posix(),
            "receipt_path": (
                receipt_path.resolve().relative_to(run_dir.resolve()).as_posix()
                if receipt_path.is_file()
                else None
            ),
        },
        "evidence_artifacts": artifacts,
        "run_ids": run_ids,
        "hashes": {artifact["path"]: artifact["sha256"] for artifact in artifacts},
        "test_ids": test_ids,
        "required_assertion_ids": required_assertion_ids,
        "covered_assertion_ids": covered_assertion_ids,
        "missing_assertion_ids": missing_assertion_ids,
        "proof_types": proof_types,
        "proofs": proofs,
        "environment_limitations": limitations,
        "timestamp": _utc_now(),
        "failure_reason": failure_reason,
    }


def run_acceptance(
    contract: ReleaseContract,
    *,
    repository_root: Path,
    output_dir: Path,
    release: bool,
) -> dict[str, Any]:
    """Execute every required gate sequentially and persist a complete result."""

    repository = repository_root.resolve()
    output_base = output_dir.resolve()
    initial_repository = _repository_state(repository)
    containment_limitations = _process_containment_limitations()
    if release and containment_limitations:
        raise ValueError("release acceptance requires kernel-backed whole-tree process isolation")
    if release and not initial_repository["available"]:
        raise ValueError("release acceptance requires a Git checkout")
    if release and not initial_repository["clean"]:
        raise ValueError("release acceptance refuses to execute an uncommitted worktree")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    commit_prefix = (initial_repository.get("commit") or "uncommitted")[:12]
    acceptance_id = f"acceptance-{timestamp}-{commit_prefix}-{uuid.uuid4().hex[:8]}"
    run_dir = output_base / acceptance_id
    run_dir.mkdir(parents=True, exist_ok=False)
    contract_snapshot = run_dir / "contract.json"
    contract_snapshot.write_text(
        json.dumps(contract.document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    contract_snapshot_hash = _sha256_file(contract_snapshot)

    started_at = _utc_now()
    repository_commit = initial_repository.get("commit") or "unavailable"
    repository_tree = initial_repository.get("tree") or "unavailable"
    gates = [
        _run_gate(
            gate,
            repository=repository,
            run_dir=run_dir,
            acceptance_id=acceptance_id,
            contract_digest=contract.digest,
            repository_commit=repository_commit,
            repository_tree=repository_tree,
            release=release,
        )
        for gate in contract.gates
    ]
    postflight_failures = _verify_final_artifact_hashes(run_dir, gates)
    try:
        final_contract_snapshot_hash = _sha256_file(contract_snapshot)
    except OSError:
        final_contract_snapshot_hash = None
    if final_contract_snapshot_hash != contract_snapshot_hash:
        postflight_failures.setdefault("GATE-12", []).append(
            "release workflows changed the acceptance contract snapshot"
        )
        contract_snapshot.write_text(
            json.dumps(contract.document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    _apply_postflight_gate_failures(run_dir, gates, postflight_failures)
    final_repository = _repository_state(repository)
    repository_result = {
        "commit": initial_repository.get("commit"),
        "tree": initial_repository.get("tree"),
        "commit_after": final_repository.get("commit"),
        "tree_after": final_repository.get("tree"),
        "clean_before": initial_repository.get("clean", False),
        "clean_after": final_repository.get("clean", False),
    }
    failure_reason = derive_result_failure_reason(
        release=release,
        repository=repository_result,
        gates=gates,
    )
    status = "passed" if failure_reason is None else "failed"
    _bind_postflight_assessment(
        run_dir,
        gates,
        repository=repository_result,
        status=status,
        failure_reason=failure_reason,
    )
    result: dict[str, Any] = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "acceptance_id": acceptance_id,
        "contract_id": contract.contract_id,
        "contract_sha256": contract.digest,
        "release": release,
        "status": status,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "repository": repository_result,
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "executable": Path(sys.executable).name,
            "limitations": sorted(
                set(containment_limitations).union(
                    item for gate in gates for item in gate["environment_limitations"]
                )
            ),
        },
        "evidence": {
            "contract_path": contract_snapshot.resolve().relative_to(run_dir.resolve()).as_posix(),
            "contract_file_sha256": contract_snapshot_hash,
            "postflight_path": "postflight.json",
            "postflight_file_sha256": "sha256:" + "0" * 64,
        },
        "gates": gates,
        "failure_reason": failure_reason,
    }
    _persist_result_postflight(run_dir, result)
    validate_acceptance_result(result, contract=contract)
    result_path = run_dir / "acceptance-result.json"
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    result_path.write_text(payload, encoding="utf-8")
    (run_dir / "acceptance-result.sha256").write_text(
        _sha256_file(result_path).removeprefix("sha256:") + "  acceptance-result.json\n",
        encoding="ascii",
    )
    return result


def run_release_acceptance(
    *,
    repository_root: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    contract = load_release_contract()
    repository = discover_repository_root(repository_root)
    result = run_acceptance(
        contract,
        repository_root=repository,
        output_dir=output_dir or repository / "build" / "product-acceptance",
        release=True,
    )
    if result["status"] != "passed":
        raise AcceptanceFailure(result)
    return result


def verify_release_result(result_path: Path) -> dict[str, Any]:
    """Independently verify a persisted result against the packaged locked contract."""

    contract = load_release_contract()
    result = verify_result_file(
        result_path,
        contract=contract.document,
        contract_digest=contract.digest,
        require_release=True,
    )
    if not isinstance(result, dict):
        raise AcceptanceContractError("release result verifier returned an invalid document")
    return result


__all__ = [
    "AcceptanceContractError",
    "AcceptanceFailure",
    "CONTRACT_SCHEMA_VERSION",
    "EXPECTED_GATE_IDS",
    "GateAssertion",
    "GateDefinition",
    "RECEIPT_SCHEMA_VERSION",
    "RELEASE_CONTRACT_SHA256",
    "ReleaseContract",
    "contract_from_mapping",
    "discover_repository_root",
    "load_release_contract",
    "result_schema_document",
    "run_acceptance",
    "run_release_acceptance",
    "validate_acceptance_result",
    "verify_release_result",
]
