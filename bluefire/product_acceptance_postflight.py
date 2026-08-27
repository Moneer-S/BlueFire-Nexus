"""Harness-owned postflight integrity bindings for product acceptance."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from .product_acceptance_process import _write_gate_assessment
from .product_acceptance_schema import result_postflight_assessment


def repository_state(repository: Path) -> dict[str, Any]:
    """Return the commit, tree, and worktree state without raising on non-Git roots."""

    def git(*arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
        )

    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    available = head.returncode == 0 and tree.returncode == 0 and status.returncode == 0
    return {
        "available": available,
        "commit": head.stdout.decode("utf-8", "replace").strip() if head.returncode == 0 else None,
        "tree": tree.stdout.decode("utf-8", "replace").strip() if tree.returncode == 0 else None,
        "clean": available and not status.stdout.strip(),
        "status": (
            status.stdout.decode("utf-8", "replace").splitlines() if status.returncode == 0 else []
        ),
    }


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


def final_artifact_failures(
    run_dir: Path, gates: Sequence[Mapping[str, Any]]
) -> dict[str, list[str]]:
    """Find evidence changed after its owning gate was assessed."""

    failures: dict[str, list[str]] = {}
    for gate in gates:
        for artifact in gate.get("evidence_artifacts", []):
            path = run_dir / artifact["path"]
            try:
                digest = _sha256_file(path)
            except OSError:
                failures.setdefault(gate["gate_id"], []).append(
                    f"{gate['gate_id']} evidence disappeared after validation: {artifact['path']}"
                )
                continue
            if digest != artifact["sha256"]:
                failures.setdefault(gate["gate_id"], []).append(
                    f"{gate['gate_id']} evidence changed after validation: {artifact['path']}"
                )
    return failures


def _refresh_gate_artifacts(run_dir: Path, gates: Sequence[dict[str, Any]]) -> None:
    root = run_dir.resolve()
    for gate in gates:
        for artifact in gate["evidence_artifacts"]:
            path = (root / artifact["path"]).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                continue
            artifact["sha256"] = _sha256_file(path)
            artifact["size_bytes"] = path.stat().st_size
        gate["hashes"] = {
            artifact["path"]: artifact["sha256"] for artifact in gate["evidence_artifacts"]
        }


def _assessment(gate: Mapping[str, Any], *, postflight: Mapping[str, Any] | None) -> dict:
    return {
        "schema_version": "bluefire.product-gate-assessment.v1",
        "status": gate["status"],
        "failure_reason": gate["failure_reason"],
        "workflow_exit_code": gate["workflow"]["exit_code"],
        "proof_sha256": _canonical_digest(gate["proofs"]),
        "postflight": dict(postflight) if postflight is not None else None,
    }


def apply_gate_failures(
    run_dir: Path,
    gates: Sequence[dict[str, Any]],
    failures: Mapping[str, Sequence[str]],
) -> None:
    """Bind postflight integrity failures into harness-owned gate assessments."""

    root = run_dir.resolve()
    for gate in gates:
        gate_failures = list(failures.get(gate["gate_id"], ()))
        if not gate_failures:
            continue
        prior_reason = gate.get("failure_reason")
        reasons = ([prior_reason] if isinstance(prior_reason, str) else []) + gate_failures
        gate["failure_reason"] = "; ".join(dict.fromkeys(reasons))
        gate["status"] = "failed"
        receipt_relative = gate["workflow"].get("receipt_path")
        if not isinstance(receipt_relative, str):
            continue
        receipt_path = (root / receipt_relative).resolve()
        if not receipt_path.is_relative_to(root) or not receipt_path.is_file():
            continue
        try:
            _write_gate_assessment(receipt_path, _assessment(gate, postflight=None))
        except (OSError, ValueError):
            gate["failure_reason"] += "; gate assessment could not be finalized"

    _refresh_gate_artifacts(root, gates)


def bind_gate_12_assessment(
    run_dir: Path,
    gates: Sequence[dict[str, Any]],
    *,
    repository: Mapping[str, Any],
    status: str,
    failure_reason: str | None,
) -> None:
    """Add final repository and verdict facts to the canonical GATE-12 receipt."""

    gate = next(item for item in gates if item["gate_id"] == "GATE-12")
    receipt_relative = gate["workflow"].get("receipt_path")
    if not isinstance(receipt_relative, str):
        return
    root = run_dir.resolve()
    receipt_path = (root / receipt_relative).resolve()
    if not receipt_path.is_relative_to(root) or not receipt_path.is_file():
        return
    postflight = {
        "schema_version": "bluefire.product-postflight-assessment.v1",
        "repository": dict(repository),
        "status": status,
        "failure_reason": failure_reason,
    }
    _write_gate_assessment(receipt_path, _assessment(gate, postflight=postflight))
    _refresh_gate_artifacts(root, [gate])


def persist_result_assessment(run_dir: Path, result: dict[str, Any]) -> None:
    """Persist and index the mandatory whole-result postflight assessment."""

    evidence = result["evidence"]
    path = run_dir / "postflight.json"
    path.write_text(
        json.dumps(
            result_postflight_assessment(result),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    evidence["postflight_file_sha256"] = _sha256_file(path)


__all__ = [
    "apply_gate_failures",
    "bind_gate_12_assessment",
    "final_artifact_failures",
    "persist_result_assessment",
    "repository_state",
]
