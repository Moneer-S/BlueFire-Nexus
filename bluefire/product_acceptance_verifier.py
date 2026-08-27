"""Independent on-disk verification for BlueFire product acceptance results."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from .product_acceptance_run_bundle import acceptance_run_binding, validated_run_bundle
from .product_acceptance_schema import (
    result_postflight_assessment,
    validate_result_contract,
    validate_result_structure,
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _contained_file(root: Path, raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{label} path is invalid")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} path escapes the acceptance directory")
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"{label} is not a contained regular file")
    return path


def _utc_timestamp(raw: Any, label: str, *, require_z: bool = False) -> datetime:
    if not isinstance(raw, str) or (require_z and not raw.endswith("Z")):
        raise ValueError(f"{label} is invalid")
    try:
        value = datetime.fromisoformat(
            raw.removesuffix("Z") + ("+00:00" if raw.endswith("Z") else "")
        )
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} is not UTC")
    return value


def _gate_artifact(root: Path, gate_dir: Path, raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{label} path is invalid")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} path escapes its gate directory")
    path = (gate_dir / relative).resolve(strict=True)
    if not path.is_relative_to(gate_dir) or not path.is_file():
        raise ValueError(f"{label} is not a contained regular file")
    return path.relative_to(root).as_posix()


def _reconcile_receipt_proofs(
    *,
    root: Path,
    gate_dir: Path,
    gate_id: str,
    raw_proofs: Any,
    result_proofs: Any,
    expected_binding: Mapping[str, str],
    not_before: datetime,
    not_after: datetime,
) -> None:
    if not isinstance(raw_proofs, list) or not isinstance(result_proofs, list):
        raise ValueError(f"{gate_id} receipt proofs are invalid")
    if len(raw_proofs) != len(result_proofs):
        raise ValueError(f"{gate_id} receipt proof count does not match the result")
    proof_fields = {
        "kind",
        "status",
        "test_id",
        "assertion_ids",
        "evidence_artifacts",
        "run_ids",
        "run_bundles",
        "environment_limitations",
    }
    for index, (raw, normalized) in enumerate(zip(raw_proofs, result_proofs, strict=True)):
        label = f"{gate_id} receipt proof {index + 1}"
        if not isinstance(raw, Mapping) or set(raw) != proof_fields:
            raise ValueError(f"{label} fields do not match the receipt schema")
        list_fields = (
            "assertion_ids",
            "evidence_artifacts",
            "run_ids",
            "run_bundles",
            "environment_limitations",
        )
        if any(not isinstance(raw[field], list) for field in list_fields):
            raise ValueError(f"{label} lists are invalid")
        assertion_ids = raw["assertion_ids"]
        if (
            not assertion_ids
            or any(not isinstance(item, str) for item in assertion_ids)
            or len(assertion_ids) != len(set(assertion_ids))
        ):
            raise ValueError(f"{label} assertion IDs are invalid or duplicated")

        bundle_bindings: list[dict[str, Any]] = []
        evidence_paths: list[str] = []
        for raw_bundle in raw["run_bundles"]:
            binding, artifact = validated_run_bundle(
                gate_dir,
                root,
                raw_bundle,
                expected_binding=expected_binding,
                not_before=not_before,
                not_after=not_after,
            )
            bundle_bindings.append(binding)
            evidence_paths.append(artifact["path"])
        evidence_paths.extend(
            _gate_artifact(root, gate_dir, raw_path, label)
            for raw_path in raw["evidence_artifacts"]
        )
        expected = {
            "kind": raw["kind"],
            "status": raw["status"],
            "test_id": raw["test_id"],
            "assertion_ids": sorted(assertion_ids),
            "evidence_artifacts": list(dict.fromkeys(evidence_paths)),
            "run_ids": list(raw["run_ids"]),
            "run_bundles": bundle_bindings,
            "environment_limitations": list(raw["environment_limitations"]),
        }
        if expected != normalized:
            raise ValueError(f"{label} does not match the normalized result proof")


def _verify_gate_receipt(
    root: Path,
    result: Mapping[str, Any],
    gate: Mapping[str, Any],
    receipt_schema_version: Any,
) -> None:
    gate_id = gate["gate_id"]
    receipt_relative = gate["workflow"]["receipt_path"]
    expected_relative = f"{gate_id.lower()}/gate-receipt.json"
    if receipt_relative is None:
        if gate["proofs"] or (root / expected_relative).exists():
            raise ValueError(f"{gate_id} has proofs or a receipt file without a receipt path")
        return
    if receipt_relative.replace("\\", "/") != expected_relative:
        raise ValueError(f"{gate_id} receipt is not at the canonical path")
    receipt_artifact = next(
        (
            item
            for item in gate["evidence_artifacts"]
            if item["path"].replace("\\", "/") == expected_relative
        ),
        None,
    )
    if not isinstance(receipt_artifact, Mapping) or receipt_artifact.get("role") != "gate-receipt":
        raise ValueError(f"{gate_id} receipt artifact role is invalid")
    receipt_path = _contained_file(root, receipt_relative, f"{gate_id} receipt")
    try:
        raw_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{gate_id} receipt is not valid UTF-8 JSON") from exc
    fields = {
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
    if not isinstance(raw_receipt, Mapping) or set(raw_receipt) != fields:
        raise ValueError(f"{gate_id} receipt fields do not match the receipt schema")
    repository = result["repository"]
    bindings = {
        "schema_version": receipt_schema_version,
        "gate_id": gate_id,
        "acceptance_id": result["acceptance_id"],
        "contract_sha256": result["contract_sha256"],
        "repository_commit": repository["commit"] or "unavailable",
        "repository_tree": repository["tree"] or "unavailable",
        "release": result["release"],
    }
    if any(raw_receipt[field] != value for field, value in bindings.items()):
        raise ValueError(f"{gate_id} receipt identity does not match the acceptance result")

    workflow = gate["workflow"]
    started = _utc_timestamp(workflow["started_at"], f"{gate_id} workflow started_at")
    finished = _utc_timestamp(workflow["finished_at"], f"{gate_id} workflow finished_at")
    gate_timestamp = _utc_timestamp(gate["timestamp"], f"{gate_id} timestamp")
    receipt_timestamp = _utc_timestamp(
        raw_receipt["timestamp"], f"{gate_id} receipt timestamp", require_z=True
    )
    if not started <= receipt_timestamp <= finished <= gate_timestamp:
        raise ValueError(f"{gate_id} receipt timestamp is outside its acceptance interval")

    status = raw_receipt["status"]
    failure_reason = raw_receipt["failure_reason"]
    if status == "passed":
        if failure_reason is not None:
            raise ValueError(f"{gate_id} passed receipt contains a failure reason")
    elif status == "failed":
        if gate["status"] != "failed" or not isinstance(failure_reason, str) or not failure_reason:
            raise ValueError(f"{gate_id} failed receipt is inconsistent with the result")
        if "gate workflow reported: " + failure_reason not in gate["failure_reason"]:
            raise ValueError(f"{gate_id} receipt failure is absent from the result")
    else:
        raise ValueError(f"{gate_id} receipt status is invalid")
    expected_exit_code = 0 if status == "passed" else 1
    if workflow["exit_code"] != expected_exit_code:
        raise ValueError(f"{gate_id} receipt status does not match the workflow exit code")
    assessment = raw_receipt["harness_assessment"]
    expected_assessment = {
        "schema_version": "bluefire.product-gate-assessment.v1",
        "status": gate["status"],
        "failure_reason": gate["failure_reason"],
        "workflow_exit_code": workflow["exit_code"],
        "proof_sha256": _canonical_digest(gate["proofs"]),
        "postflight": (
            {
                "schema_version": "bluefire.product-postflight-assessment.v1",
                "repository": dict(result["repository"]),
                "status": result["status"],
                "failure_reason": result["failure_reason"],
            }
            if gate_id == "GATE-12"
            else None
        ),
    }
    if not isinstance(assessment, Mapping) or dict(assessment) != expected_assessment:
        raise ValueError(f"{gate_id} harness assessment does not match the gate result")
    _reconcile_receipt_proofs(
        root=root,
        gate_dir=(root / gate_id.lower()).resolve(strict=True),
        gate_id=gate_id,
        raw_proofs=raw_receipt["proofs"],
        result_proofs=gate["proofs"],
        expected_binding=acceptance_run_binding(
            result["acceptance_id"],
            gate_id,
            result["contract_sha256"],
            repository["commit"] or "unavailable",
            repository["tree"] or "unavailable",
            "true" if result["release"] else "false",
        ),
        not_before=started,
        not_after=finished,
    )


def verify_result_file(
    result_path: Path,
    *,
    contract: Mapping[str, Any],
    contract_digest: str,
    require_release: bool = False,
) -> dict[str, Any]:
    """Verify schema, contract semantics, companion hash, and every artifact byte."""

    resolved_result = result_path.resolve(strict=True)
    if not resolved_result.is_file() or resolved_result.name != "acceptance-result.json":
        raise ValueError("acceptance result must be an acceptance-result.json file")
    root = resolved_result.parent.resolve(strict=True)
    try:
        value = json.loads(resolved_result.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("acceptance result is not valid UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise ValueError("acceptance result must contain a JSON object")
    result = dict(value)
    validate_result_structure(result)
    validate_result_contract(result, contract, contract_digest)
    if require_release and result["release"] is not True:
        raise ValueError("release verifier requires a release-mode acceptance result")

    companion = root / "acceptance-result.sha256"
    expected_line = _sha256_file(resolved_result).removeprefix("sha256:")
    expected_line += "  acceptance-result.json\n"
    try:
        companion_text = companion.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise ValueError("acceptance result companion hash is unavailable") from exc
    if companion_text != expected_line:
        raise ValueError("acceptance result companion hash does not match")

    evidence = result["evidence"]
    contract_path = _contained_file(root, evidence["contract_path"], "contract snapshot")
    if _sha256_file(contract_path) != evidence["contract_file_sha256"]:
        raise ValueError("acceptance contract snapshot hash does not match")
    try:
        contract_snapshot = json.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("acceptance contract snapshot is invalid") from exc
    if _canonical_digest(contract_snapshot) != contract_digest or contract_snapshot != contract:
        raise ValueError("acceptance contract snapshot is not the locked contract")

    for gate in result["gates"]:
        gate_id = gate["gate_id"]
        expected_prefix = gate_id.lower() + "/"
        for artifact in gate["evidence_artifacts"]:
            if not artifact["path"].replace("\\", "/").startswith(expected_prefix):
                raise ValueError(f"{gate_id} artifact is outside its gate evidence directory")
            path = _contained_file(root, artifact["path"], f"{gate_id} artifact")
            if path.stat().st_size != artifact["size_bytes"]:
                raise ValueError(f"{gate_id} artifact size does not match")
            if _sha256_file(path) != artifact["sha256"]:
                raise ValueError(f"{gate_id} artifact hash does not match")
        _verify_gate_receipt(root, result, gate, contract.get("receipt_schema_version"))

    postflight_path = _contained_file(root, evidence["postflight_path"], "postflight assessment")
    if _sha256_file(postflight_path) != evidence["postflight_file_sha256"]:
        raise ValueError("acceptance postflight assessment hash does not match")
    try:
        postflight = json.loads(postflight_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("acceptance postflight assessment is invalid") from exc
    if postflight != result_postflight_assessment(result):
        raise ValueError("acceptance postflight assessment does not match the result")
    return result


__all__ = ["verify_result_file"]
