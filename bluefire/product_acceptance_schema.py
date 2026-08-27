"""Generated JSON Schema and structural validation for product acceptance results."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Sequence

RESULT_SCHEMA_VERSION = "bluefire.product-acceptance-result.v1"
EXPECTED_GATE_IDS = tuple(f"GATE-{index:02d}" for index in range(1, 13))
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _unique_text_list(value: Any, field: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a text list")
    if nonempty and not value:
        raise ValueError(f"{field} cannot be empty")
    if len(value) != len(set(value)):
        raise ValueError(f"{field} must contain unique values")
    return value


def _relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a relative path")
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise ValueError(f"{field} cannot disclose an absolute path")
    if ".." in PurePosixPath(value.replace("\\", "/")).parts:
        raise ValueError(f"{field} cannot escape its result directory")
    return value


def _utc_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} must be a UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise ValueError(f"{field} must be a UTC timestamp")
    return parsed


def derive_result_failure_reason(
    *,
    release: bool,
    repository: Mapping[str, Any],
    gates: Sequence[Mapping[str, Any]],
) -> str | None:
    """Derive the only valid top-level verdict reason from persisted facts."""

    failures: list[str] = []
    if release:
        if not repository.get("clean_after"):
            failures.append("release workflows changed the committed worktree")
        if repository.get("commit") != repository.get("commit_after"):
            failures.append("release workflows changed HEAD")
        if repository.get("tree") != repository.get("tree_after"):
            failures.append("release workflows changed the committed tree")
    failed_gates = [gate.get("gate_id") for gate in gates if gate.get("status") != "passed"]
    if failed_gates:
        failures.append("required gates failed: " + ", ".join(str(item) for item in failed_gates))
    return "; ".join(failures) if failures else None


def result_postflight_assessment(result: Mapping[str, Any]) -> dict[str, Any]:
    """Build the canonical harness-owned binding for the complete result subject."""

    evidence = result["evidence"]
    subject = {key: value for key, value in result.items() if key != "evidence"}
    subject["evidence"] = {
        "contract_path": evidence["contract_path"],
        "contract_file_sha256": evidence["contract_file_sha256"],
    }
    return {
        "schema_version": "bluefire.product-postflight-assessment.v1",
        "acceptance_id": result["acceptance_id"],
        "contract_sha256": result["contract_sha256"],
        "repository": dict(result["repository"]),
        "status": result["status"],
        "failure_reason": result["failure_reason"],
        "result_subject_sha256": _canonical_sha256(subject),
    }


def _validate_artifact(raw: Any, gate_id: str) -> tuple[str, str]:
    if not isinstance(raw, Mapping) or set(raw) != {"path", "sha256", "size_bytes", "role"}:
        raise ValueError(f"{gate_id} artifact is malformed")
    path = _relative_path(raw["path"], f"{gate_id} artifact path")
    digest = raw["sha256"]
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError(f"{gate_id} artifact hash is invalid")
    if type(raw["size_bytes"]) is not int or raw["size_bytes"] < 0:
        raise ValueError(f"{gate_id} artifact size is invalid")
    if not isinstance(raw["role"], str) or not raw["role"]:
        raise ValueError(f"{gate_id} artifact role is invalid")
    return path, digest


def validate_result_structure(result: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "acceptance_id",
        "contract_id",
        "contract_sha256",
        "release",
        "status",
        "started_at",
        "finished_at",
        "repository",
        "environment",
        "evidence",
        "gates",
        "failure_reason",
    }
    if set(result) != required:
        raise ValueError("acceptance result fields do not match the public schema")
    if result["schema_version"] != RESULT_SCHEMA_VERSION:
        raise ValueError("acceptance result schema version is invalid")
    if not isinstance(result["acceptance_id"], str) or not _IDENTIFIER.fullmatch(
        result["acceptance_id"]
    ):
        raise ValueError("acceptance result ID is invalid")
    if not isinstance(result["contract_id"], str) or not result["contract_id"]:
        raise ValueError("acceptance contract ID is invalid")
    if not isinstance(result["contract_sha256"], str) or not _SHA256.fullmatch(
        result["contract_sha256"]
    ):
        raise ValueError("acceptance contract hash is invalid")
    if type(result["release"]) is not bool or result["status"] not in {"passed", "failed"}:
        raise ValueError("acceptance release or status field is invalid")
    started_at = _utc_timestamp(result["started_at"], "acceptance started_at")
    finished_at = _utc_timestamp(result["finished_at"], "acceptance finished_at")
    if finished_at < started_at:
        raise ValueError("acceptance timestamps are out of order")
    gates = result.get("gates")
    if not isinstance(gates, list):
        raise ValueError("acceptance result gates must be a list")
    if (
        len(gates) != 12
        or tuple(gate.get("gate_id") for gate in gates if isinstance(gate, Mapping))
        != EXPECTED_GATE_IDS
    ):
        raise ValueError("acceptance result does not contain the exact gate set")
    previous_gate_at = started_at
    for expected_gate_id, gate in zip(EXPECTED_GATE_IDS, gates, strict=True):
        if not isinstance(gate, Mapping):
            raise ValueError("acceptance gate result must be an object")
        gate_required = {
            "gate_id",
            "title",
            "required",
            "status",
            "workflow",
            "evidence_artifacts",
            "run_ids",
            "hashes",
            "test_ids",
            "required_assertion_ids",
            "covered_assertion_ids",
            "missing_assertion_ids",
            "proof_types",
            "proofs",
            "environment_limitations",
            "timestamp",
            "failure_reason",
        }
        if set(gate) != gate_required:
            raise ValueError(f"{expected_gate_id} result fields do not match the schema")
        _validate_gate_result(gate, expected_gate_id)
        workflow = gate["workflow"]
        workflow_started = _utc_timestamp(
            workflow["started_at"], f"{expected_gate_id} workflow started_at"
        )
        workflow_finished = _utc_timestamp(
            workflow["finished_at"], f"{expected_gate_id} workflow finished_at"
        )
        gate_at = _utc_timestamp(gate["timestamp"], f"{expected_gate_id} timestamp")
        if not previous_gate_at <= workflow_started <= workflow_finished <= gate_at <= finished_at:
            raise ValueError("acceptance gate workflow timestamps are not sequential")
        previous_gate_at = gate_at

    repository = result["repository"]
    if not isinstance(repository, Mapping) or set(repository) != {
        "commit",
        "tree",
        "commit_after",
        "tree_after",
        "clean_before",
        "clean_after",
    }:
        raise ValueError("acceptance repository binding is invalid")
    for field in ("commit", "tree", "commit_after", "tree_after"):
        value = repository[field]
        if value is not None and (
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
        ):
            raise ValueError(f"acceptance repository {field} is invalid")
    if type(repository["clean_before"]) is not bool or type(repository["clean_after"]) is not bool:
        raise ValueError("acceptance repository cleanliness is invalid")
    if result["release"] and (
        repository["commit"] is None or repository["tree"] is None or not repository["clean_before"]
    ):
        raise ValueError("release acceptance must start from a clean committed tree")
    expected_failure = derive_result_failure_reason(
        release=result["release"],
        repository=repository,
        gates=gates,
    )
    expected_status = "failed" if expected_failure is not None else "passed"
    if result["status"] != expected_status or result["failure_reason"] != expected_failure:
        raise ValueError("acceptance status and failure reason do not match the derived verdict")

    environment = result["environment"]
    if not isinstance(environment, Mapping) or set(environment) != {
        "platform",
        "python",
        "executable",
        "limitations",
    }:
        raise ValueError("acceptance environment is invalid")
    if any(
        not isinstance(environment[field], str) for field in ("platform", "python", "executable")
    ):
        raise ValueError("acceptance environment text is invalid")
    executable = environment["executable"]
    if (
        not executable
        or PurePosixPath(executable).name != executable
        or PureWindowsPath(executable).name != executable
    ):
        raise ValueError("acceptance environment cannot disclose an executable path")
    _unique_text_list(environment["limitations"], "acceptance environment limitations")

    evidence = result["evidence"]
    if not isinstance(evidence, Mapping) or set(evidence) != {
        "contract_path",
        "contract_file_sha256",
        "postflight_path",
        "postflight_file_sha256",
    }:
        raise ValueError("acceptance contract evidence is invalid")
    _relative_path(evidence["contract_path"], "acceptance contract evidence path")
    if evidence["postflight_path"] != "postflight.json":
        raise ValueError("acceptance postflight assessment path is not canonical")
    if not isinstance(evidence["contract_file_sha256"], str) or not _SHA256.fullmatch(
        evidence["contract_file_sha256"]
    ):
        raise ValueError("acceptance contract evidence hash is invalid")
    if not isinstance(evidence["postflight_file_sha256"], str) or not _SHA256.fullmatch(
        evidence["postflight_file_sha256"]
    ):
        raise ValueError("acceptance postflight assessment hash is invalid")


def _validate_gate_result(gate: Mapping[str, Any], gate_id: str) -> None:
    if gate["gate_id"] != gate_id or gate["required"] is not True:
        raise ValueError(f"{gate_id} identity or required status is invalid")
    if not isinstance(gate["title"], str) or not gate["title"]:
        raise ValueError(f"{gate_id} title is invalid")
    if gate["status"] not in {"passed", "failed"}:
        raise ValueError(f"{gate_id} status is invalid")
    _utc_timestamp(gate["timestamp"], f"{gate_id} timestamp")

    artifact_rows = gate["evidence_artifacts"]
    if not isinstance(artifact_rows, list):
        raise ValueError(f"{gate_id} evidence artifacts must be a list")
    artifact_pairs = [_validate_artifact(row, gate_id) for row in artifact_rows]
    artifact_paths = [path for path, _digest in artifact_pairs]
    if len(artifact_paths) != len(set(artifact_paths)):
        raise ValueError(f"{gate_id} evidence paths must be unique")
    hashes = gate["hashes"]
    if not isinstance(hashes, Mapping) or hashes != dict(artifact_pairs):
        raise ValueError(f"{gate_id} hash index does not match its artifacts")

    required_assertions = _unique_text_list(
        gate["required_assertion_ids"], f"{gate_id} required assertions", nonempty=True
    )
    covered_assertions = _unique_text_list(
        gate["covered_assertion_ids"], f"{gate_id} covered assertions"
    )
    missing_assertions = _unique_text_list(
        gate["missing_assertion_ids"], f"{gate_id} missing assertions"
    )
    if any(
        not _IDENTIFIER.fullmatch(assertion_id) or not assertion_id.startswith(gate_id + "-")
        for assertion_id in required_assertions + covered_assertions + missing_assertions
    ):
        raise ValueError(f"{gate_id} assertion ID is invalid")
    if not set(covered_assertions) <= set(required_assertions):
        raise ValueError(f"{gate_id} proof covers an assertion outside the contract")
    if set(missing_assertions) != set(required_assertions) - set(covered_assertions):
        raise ValueError(f"{gate_id} assertion coverage is contradictory")

    proofs = gate["proofs"]
    if not isinstance(proofs, list):
        raise ValueError(f"{gate_id} proofs must be a list")
    proof_test_ids: list[str] = []
    proof_run_ids: list[str] = []
    proof_assertions: list[str] = []
    proof_kinds: list[str] = []
    proof_limitations: list[str] = []
    for proof in proofs:
        if not isinstance(proof, Mapping) or set(proof) != {
            "kind",
            "status",
            "test_id",
            "assertion_ids",
            "evidence_artifacts",
            "run_ids",
            "run_bundles",
            "environment_limitations",
        }:
            raise ValueError(f"{gate_id} proof is malformed")
        if proof["kind"] not in {"dynamic", "structural"} or proof["status"] != "passed":
            raise ValueError(f"{gate_id} proof classification is invalid")
        if not isinstance(proof["test_id"], str) or not _IDENTIFIER.fullmatch(proof["test_id"]):
            raise ValueError(f"{gate_id} proof test ID is invalid")
        assertion_ids = _unique_text_list(
            proof["assertion_ids"], f"{gate_id} proof assertions", nonempty=True
        )
        if len(assertion_ids) != 1:
            raise ValueError(f"{gate_id} proof must cover exactly one assertion")
        if not set(assertion_ids) <= set(required_assertions):
            raise ValueError(f"{gate_id} proof assertion is outside the contract")
        evidence_paths = _unique_text_list(
            proof["evidence_artifacts"], f"{gate_id} proof evidence", nonempty=True
        )
        if not set(evidence_paths) <= set(artifact_paths):
            raise ValueError(f"{gate_id} proof references evidence outside its artifact index")
        run_ids = _unique_text_list(proof["run_ids"], f"{gate_id} proof run IDs")
        if any(not _IDENTIFIER.fullmatch(run_id) for run_id in run_ids):
            raise ValueError(f"{gate_id} proof run ID is invalid")
        run_bundles = proof["run_bundles"]
        if not isinstance(run_bundles, list):
            raise ValueError(f"{gate_id} proof run bundles do not match its run IDs")
        bundle_ids = [item.get("run_id") for item in run_bundles if isinstance(item, Mapping)]
        if (
            len(bundle_ids) != len(run_bundles)
            or any(not isinstance(bundle_id, str) for bundle_id in bundle_ids)
            or len(bundle_ids) != len(set(bundle_ids))
            or set(bundle_ids) != set(run_ids)
        ):
            raise ValueError(f"{gate_id} proof run bundles do not match its run IDs")
        for bundle in run_bundles:
            if not isinstance(bundle, Mapping) or set(bundle) != {
                "run_id",
                "path",
                "manifest_sha256",
            }:
                raise ValueError(f"{gate_id} run bundle binding is malformed")
            bundle_path = _relative_path(bundle["path"], f"{gate_id} run bundle path")
            normalized_bundle_path = PurePosixPath(bundle_path.replace("\\", "/"))
            if normalized_bundle_path.name != bundle["run_id"]:
                raise ValueError(f"{gate_id} run bundle path does not match its run ID")
            if not isinstance(bundle["manifest_sha256"], str) or not _SHA256.fullmatch(
                bundle["manifest_sha256"]
            ):
                raise ValueError(f"{gate_id} run bundle manifest hash is invalid")
            manifest_path = (
                PurePosixPath(gate_id.lower()) / normalized_bundle_path / "manifest.json"
            ).as_posix()
            artifact_index = {row["path"]: row for row in artifact_rows if isinstance(row, Mapping)}
            manifest_artifact = artifact_index.get(manifest_path)
            if (
                not isinstance(manifest_artifact, Mapping)
                or manifest_artifact.get("sha256") != bundle["manifest_sha256"]
                or manifest_artifact.get("role") != "validated-run-bundle-manifest"
            ):
                raise ValueError(f"{gate_id} run bundle manifest is not bound as evidence")
        limitations = _unique_text_list(
            proof["environment_limitations"], f"{gate_id} proof limitations"
        )
        proof_test_ids.append(proof["test_id"])
        proof_run_ids.extend(run_ids)
        proof_assertions.extend(assertion_ids)
        proof_kinds.append(proof["kind"])
        proof_limitations.extend(limitations)

    if len(proof_test_ids) != len(set(proof_test_ids)):
        raise ValueError(f"{gate_id} proof test IDs must be unique")
    if len(proof_assertions) != len(set(proof_assertions)):
        raise ValueError(f"{gate_id} assertions cannot have duplicate proofs")
    expected_indexes = {
        "test_ids": sorted(proof_test_ids),
        "run_ids": sorted(set(proof_run_ids)),
        "covered_assertion_ids": sorted(set(proof_assertions)),
        "proof_types": sorted(set(proof_kinds)),
        "environment_limitations": sorted(set(proof_limitations)),
    }
    for field, expected in expected_indexes.items():
        if gate[field] != expected:
            raise ValueError(f"{gate_id} {field} index is contradictory")

    workflow = gate["workflow"]
    workflow_fields = {
        "command",
        "command_sha256",
        "working_directory",
        "exit_code",
        "duration_ms",
        "started_at",
        "finished_at",
        "stdout_path",
        "stderr_path",
        "receipt_path",
    }
    if not isinstance(workflow, Mapping) or set(workflow) != workflow_fields:
        raise ValueError(f"{gate_id} workflow result is malformed")
    command = workflow["command"]
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(item, str) for item in command)
    ):
        raise ValueError(f"{gate_id} workflow command is invalid")
    if any(
        PurePosixPath(item).is_absolute() or PureWindowsPath(item).is_absolute() for item in command
    ):
        raise ValueError(f"{gate_id} workflow command discloses an absolute path")
    if workflow["command_sha256"] != _canonical_sha256(command):
        raise ValueError(f"{gate_id} workflow command hash is invalid")
    if workflow["working_directory"] != ".":
        raise ValueError(f"{gate_id} workflow directory is invalid")
    if workflow["exit_code"] is not None and type(workflow["exit_code"]) is not int:
        raise ValueError(f"{gate_id} workflow exit code is invalid")
    if type(workflow["duration_ms"]) is not int or workflow["duration_ms"] < 0:
        raise ValueError(f"{gate_id} workflow duration is invalid")
    workflow_started = _utc_timestamp(workflow["started_at"], f"{gate_id} workflow started_at")
    workflow_finished = _utc_timestamp(workflow["finished_at"], f"{gate_id} workflow finished_at")
    if workflow_finished < workflow_started:
        raise ValueError(f"{gate_id} workflow timestamps are out of order")
    artifact_index = {row["path"].replace("\\", "/"): row for row in artifact_rows}
    for field, role in (("stdout_path", "workflow-stdout"), ("stderr_path", "workflow-stderr")):
        path = _relative_path(workflow[field], f"{gate_id} workflow {field}")
        expected_path = f"{gate_id.lower()}/workflow.{field.removesuffix('_path')}.log"
        artifact = artifact_index.get(path.replace("\\", "/"))
        if (
            path != expected_path
            or not artifact
            or artifact.get("path") != expected_path
            or artifact.get("role") != role
        ):
            raise ValueError(f"{gate_id} workflow log path or role is invalid")
    receipt_path = workflow["receipt_path"]
    canonical_receipt = f"{gate_id.lower()}/gate-receipt.json"
    receipt_artifact = artifact_index.get(canonical_receipt)
    if receipt_path is not None:
        receipt_path = _relative_path(receipt_path, f"{gate_id} receipt path")
        if (
            receipt_path != canonical_receipt
            or not receipt_artifact
            or receipt_artifact.get("path") != canonical_receipt
            or receipt_artifact.get("role") != "gate-receipt"
        ):
            raise ValueError(f"{gate_id} receipt path or role is invalid")
    elif receipt_artifact is not None:
        raise ValueError(f"{gate_id} receipt artifact exists without a receipt path")

    if gate["status"] == "passed":
        if (
            workflow["exit_code"] != 0
            or receipt_path is None
            or gate["failure_reason"] is not None
            or missing_assertions
            or set(covered_assertions) != set(required_assertions)
            or not proofs
        ):
            raise ValueError(f"{gate_id} passed state is contradictory")
    elif not isinstance(gate["failure_reason"], str) or not gate["failure_reason"]:
        raise ValueError(f"{gate_id} failed state needs an exact reason")


def validate_result_contract(
    result: Mapping[str, Any],
    contract: Mapping[str, Any],
    contract_digest: str,
) -> None:
    """Bind a structurally valid result to every locked contract requirement."""

    if (
        result.get("contract_id") != contract.get("contract_id")
        or result.get("contract_sha256") != contract_digest
    ):
        raise ValueError("acceptance result does not match the locked contract identity")
    raw_gates = contract.get("gates")
    result_gates = result.get("gates")
    if not isinstance(raw_gates, list) or not isinstance(result_gates, list):
        raise ValueError("acceptance contract gates are unavailable")
    if len(raw_gates) != len(result_gates):
        raise ValueError("acceptance result gate count does not match the locked contract")

    for raw_gate, gate in zip(raw_gates, result_gates, strict=True):
        if not isinstance(raw_gate, Mapping) or not isinstance(gate, Mapping):
            raise ValueError("acceptance contract gate binding is malformed")
        gate_id = raw_gate.get("id")
        raw_assertions = raw_gate.get("assertions")
        workflow = raw_gate.get("workflow")
        if (
            not isinstance(gate_id, str)
            or not isinstance(raw_assertions, list)
            or not isinstance(workflow, Mapping)
        ):
            raise ValueError("acceptance contract gate binding is malformed")
        assertion_kinds: dict[str, str] = {}
        for raw_assertion in raw_assertions:
            if not isinstance(raw_assertion, Mapping):
                raise ValueError(f"{gate_id} contract assertions are malformed")
            assertion_id = raw_assertion.get("id")
            proof_kind = raw_assertion.get("proof")
            if (
                not isinstance(assertion_id, str)
                or not isinstance(proof_kind, str)
                or proof_kind not in {"dynamic", "structural"}
                or assertion_id in assertion_kinds
            ):
                raise ValueError(f"{gate_id} contract assertions are malformed")
            assertion_kinds[assertion_id] = proof_kind
        expected_assertions = sorted(assertion_kinds)
        gate_workflow = gate.get("workflow")
        if (
            gate.get("gate_id") != gate_id
            or gate.get("title") != raw_gate.get("title")
            or gate.get("required_assertion_ids") != expected_assertions
            or not isinstance(gate_workflow, Mapping)
            or gate_workflow.get("command") != workflow.get("command")
        ):
            raise ValueError(f"{gate_id} result does not match its locked contract")
        for proof in gate.get("proofs", []):
            assertion_id = proof["assertion_ids"][0]
            if assertion_kinds.get(assertion_id) != proof["kind"]:
                raise ValueError(f"{gate_id} proof kind contradicts its locked assertion")
        if gate.get("status") != "passed":
            continue
        required_proof = raw_gate.get("required_proof")
        evidence_paths = {path for proof in gate["proofs"] for path in proof["evidence_artifacts"]}
        floors = (
            (len(evidence_paths), raw_gate.get("minimum_evidence_artifacts")),
            (len(gate["run_ids"]), raw_gate.get("minimum_run_ids")),
            (len(gate["test_ids"]), raw_gate.get("minimum_test_ids")),
        )
        if not isinstance(required_proof, list) or not set(required_proof) <= set(
            gate["proof_types"]
        ):
            raise ValueError(f"{gate_id} result is missing a locked proof class")
        if any(type(minimum) is not int or actual < minimum for actual, minimum in floors):
            raise ValueError(f"{gate_id} result is below a locked evidence floor")


def result_schema_document() -> dict[str, Any]:
    """Return the generated public JSON Schema for acceptance results."""

    identifier_pattern = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
    relative_path_pattern = r"^(?![/\\])(?![A-Za-z]:[/\\])(?!.*(?:^|[/\\])\.\.(?:[/\\]|$)).+$"
    command_token_pattern = r"^(?![/\\])(?![A-Za-z]:[/\\]).+$"
    artifact = {
        "type": "object",
        "additionalProperties": False,
        "required": ["path", "sha256", "size_bytes", "role"],
        "properties": {
            "path": {"type": "string", "pattern": relative_path_pattern},
            "sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "size_bytes": {"type": "integer", "minimum": 0},
            "role": {"type": "string", "minLength": 1},
        },
    }
    proof = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "kind",
            "status",
            "test_id",
            "assertion_ids",
            "evidence_artifacts",
            "run_ids",
            "run_bundles",
            "environment_limitations",
        ],
        "properties": {
            "kind": {"enum": ["dynamic", "structural"]},
            "status": {"const": "passed"},
            "test_id": {"type": "string", "pattern": identifier_pattern},
            "assertion_ids": {
                "type": "array",
                "items": {"type": "string", "pattern": identifier_pattern},
                "minItems": 1,
                "maxItems": 1,
                "uniqueItems": True,
            },
            "evidence_artifacts": {
                "type": "array",
                "items": {"type": "string", "pattern": relative_path_pattern},
                "minItems": 1,
                "uniqueItems": True,
            },
            "run_ids": {
                "type": "array",
                "items": {"type": "string", "pattern": identifier_pattern},
                "uniqueItems": True,
            },
            "run_bundles": {
                "type": "array",
                "uniqueItems": True,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["run_id", "path", "manifest_sha256"],
                    "properties": {
                        "run_id": {"type": "string", "pattern": identifier_pattern},
                        "path": {"type": "string", "pattern": relative_path_pattern},
                        "manifest_sha256": {
                            "type": "string",
                            "pattern": "^sha256:[0-9a-f]{64}$",
                        },
                    },
                },
            },
            "environment_limitations": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
        },
    }
    gate = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "gate_id",
            "title",
            "required",
            "status",
            "workflow",
            "evidence_artifacts",
            "run_ids",
            "hashes",
            "test_ids",
            "required_assertion_ids",
            "covered_assertion_ids",
            "missing_assertion_ids",
            "proof_types",
            "proofs",
            "environment_limitations",
            "timestamp",
            "failure_reason",
        ],
        "properties": {
            "gate_id": {"type": "string", "pattern": "^GATE-(0[1-9]|1[0-2])$"},
            "title": {"type": "string", "minLength": 1},
            "required": {"const": True},
            "status": {"enum": ["passed", "failed"]},
            "workflow": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "command",
                    "command_sha256",
                    "working_directory",
                    "exit_code",
                    "duration_ms",
                    "started_at",
                    "finished_at",
                    "stdout_path",
                    "stderr_path",
                    "receipt_path",
                ],
                "properties": {
                    "command": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "pattern": command_token_pattern},
                    },
                    "command_sha256": {
                        "type": "string",
                        "pattern": "^sha256:[0-9a-f]{64}$",
                    },
                    "working_directory": {"const": "."},
                    "exit_code": {"type": ["integer", "null"]},
                    "duration_ms": {"type": "integer", "minimum": 0},
                    "started_at": {"type": "string", "format": "date-time"},
                    "finished_at": {"type": "string", "format": "date-time"},
                    "stdout_path": {"type": "string", "pattern": relative_path_pattern},
                    "stderr_path": {"type": "string", "pattern": relative_path_pattern},
                    "receipt_path": {
                        "type": ["string", "null"],
                        "pattern": relative_path_pattern,
                    },
                },
            },
            "evidence_artifacts": {
                "type": "array",
                "items": {"$ref": "#/$defs/artifact"},
                "minItems": 2,
                "uniqueItems": True,
            },
            "run_ids": {
                "type": "array",
                "items": {"type": "string", "pattern": identifier_pattern},
                "uniqueItems": True,
            },
            "hashes": {
                "type": "object",
                "minProperties": 2,
                "additionalProperties": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            },
            "test_ids": {
                "type": "array",
                "items": {"type": "string", "pattern": identifier_pattern},
                "uniqueItems": True,
            },
            "required_assertion_ids": {
                "type": "array",
                "items": {"type": "string", "pattern": identifier_pattern},
                "minItems": 1,
                "uniqueItems": True,
            },
            "covered_assertion_ids": {
                "type": "array",
                "items": {"type": "string", "pattern": identifier_pattern},
                "uniqueItems": True,
            },
            "missing_assertion_ids": {
                "type": "array",
                "items": {"type": "string", "pattern": identifier_pattern},
                "uniqueItems": True,
            },
            "proof_types": {
                "type": "array",
                "items": {"enum": ["dynamic", "structural"]},
                "uniqueItems": True,
            },
            "proofs": {"type": "array", "items": {"$ref": "#/$defs/proof"}},
            "environment_limitations": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "timestamp": {"type": "string", "format": "date-time"},
            "failure_reason": {"type": ["string", "null"]},
        },
        "allOf": [
            {
                "if": {"properties": {"status": {"const": "passed"}}},
                "then": {
                    "properties": {
                        "failure_reason": {"type": "null"},
                        "missing_assertion_ids": {"maxItems": 0},
                        "proofs": {"minItems": 1},
                        "workflow": {
                            "properties": {
                                "exit_code": {"const": 0},
                                "receipt_path": {"type": "string", "minLength": 1},
                            }
                        },
                    }
                },
            },
            {
                "if": {"properties": {"status": {"const": "failed"}}},
                "then": {"properties": {"failure_reason": {"type": "string", "minLength": 1}}},
            },
        ],
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://bluefire.local/schemas/product-acceptance-result.v1.json",
        "title": "BlueFire Nexus product acceptance result",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "acceptance_id",
            "contract_id",
            "contract_sha256",
            "release",
            "status",
            "started_at",
            "finished_at",
            "repository",
            "environment",
            "evidence",
            "gates",
            "failure_reason",
        ],
        "properties": {
            "schema_version": {"const": RESULT_SCHEMA_VERSION},
            "acceptance_id": {"type": "string", "pattern": identifier_pattern},
            "contract_id": {"type": "string", "minLength": 1},
            "contract_sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "release": {"type": "boolean"},
            "status": {"enum": ["passed", "failed"]},
            "started_at": {"type": "string", "format": "date-time"},
            "finished_at": {"type": "string", "format": "date-time"},
            "repository": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "commit",
                    "tree",
                    "commit_after",
                    "tree_after",
                    "clean_before",
                    "clean_after",
                ],
                "properties": {
                    "commit": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
                    "tree": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
                    "commit_after": {
                        "type": ["string", "null"],
                        "pattern": "^[0-9a-f]{40}$",
                    },
                    "tree_after": {
                        "type": ["string", "null"],
                        "pattern": "^[0-9a-f]{40}$",
                    },
                    "clean_before": {"type": "boolean"},
                    "clean_after": {"type": "boolean"},
                },
            },
            "environment": {
                "type": "object",
                "additionalProperties": False,
                "required": ["platform", "python", "executable", "limitations"],
                "properties": {
                    "platform": {"type": "string"},
                    "python": {"type": "string"},
                    "executable": {"type": "string", "pattern": "^[^/\\\\]+$"},
                    "limitations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "uniqueItems": True,
                    },
                },
            },
            "evidence": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "contract_path",
                    "contract_file_sha256",
                    "postflight_path",
                    "postflight_file_sha256",
                ],
                "properties": {
                    "contract_path": {"type": "string", "pattern": relative_path_pattern},
                    "contract_file_sha256": {
                        "type": "string",
                        "pattern": "^sha256:[0-9a-f]{64}$",
                    },
                    "postflight_path": {"const": "postflight.json"},
                    "postflight_file_sha256": {
                        "type": "string",
                        "pattern": "^sha256:[0-9a-f]{64}$",
                    },
                },
            },
            "gates": {
                "type": "array",
                "minItems": 12,
                "maxItems": 12,
                "prefixItems": [
                    {
                        "allOf": [
                            {"$ref": "#/$defs/gate"},
                            {"properties": {"gate_id": {"const": gate_id}}},
                        ]
                    }
                    for gate_id in EXPECTED_GATE_IDS
                ],
                "items": False,
            },
            "failure_reason": {"type": ["string", "null"]},
        },
        "allOf": [
            {
                "if": {"properties": {"status": {"const": "passed"}}},
                "then": {
                    "properties": {"failure_reason": {"type": "null"}},
                    "not": {
                        "properties": {
                            "gates": {
                                "contains": {
                                    "type": "object",
                                    "properties": {"status": {"const": "failed"}},
                                    "required": ["status"],
                                }
                            }
                        },
                        "required": ["gates"],
                    },
                },
            },
            {
                "if": {"properties": {"status": {"const": "failed"}}},
                "then": {"properties": {"failure_reason": {"type": "string", "minLength": 1}}},
            },
            {
                "if": {
                    "properties": {"release": {"const": True}},
                    "required": ["release"],
                },
                "then": {
                    "properties": {
                        "repository": {
                            "properties": {
                                "commit": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                                "tree": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                                "clean_before": {"const": True},
                            }
                        }
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "release": {"const": True},
                        "status": {"const": "passed"},
                    },
                    "required": ["release", "status"],
                },
                "then": {
                    "properties": {
                        "repository": {
                            "properties": {
                                "clean_after": {"const": True},
                                "commit_after": {
                                    "type": "string",
                                    "pattern": "^[0-9a-f]{40}$",
                                },
                                "tree_after": {
                                    "type": "string",
                                    "pattern": "^[0-9a-f]{40}$",
                                },
                            }
                        }
                    }
                },
            },
        ],
        "$defs": {"artifact": artifact, "proof": proof, "gate": gate},
    }


def write_result_schema(path: Path) -> None:
    path.write_text(
        json.dumps(result_schema_document(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


__all__ = [
    "RESULT_SCHEMA_VERSION",
    "derive_result_failure_reason",
    "result_postflight_assessment",
    "result_schema_document",
    "validate_result_contract",
    "validate_result_structure",
    "write_result_schema",
]
