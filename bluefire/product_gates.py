"""Static release-gate workflow dispatcher.

Gate implementations are registered in source, never loaded from package entry
points or model output. Until a gate has a real implementation the dispatcher
emits a bound failed receipt; it cannot manufacture passing proof.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .product_acceptance import GateDefinition, load_release_contract


@dataclass(frozen=True)
class GateWorkflowResult:
    status: str
    proofs: tuple[Mapping[str, Any], ...]
    failure_reason: str | None = None


GateWorkflow = Callable[[GateDefinition, Path], GateWorkflowResult]


def _gate_01_workflow(gate: GateDefinition, evidence_dir: Path) -> GateWorkflowResult:
    from .install_gate import run_gate_01

    outcome = run_gate_01(gate, evidence_dir)
    return GateWorkflowResult(
        status=outcome.status,
        proofs=outcome.proofs,
        failure_reason=outcome.failure_reason,
    )


def _gate_02_workflow(gate: GateDefinition, evidence_dir: Path) -> GateWorkflowResult:
    from .provider_gate import run_gate_02

    outcome = run_gate_02(gate, evidence_dir)
    return GateWorkflowResult(
        status=outcome.status,
        proofs=outcome.proofs,
        failure_reason=outcome.failure_reason,
    )


def _gate_04_workflow(gate: GateDefinition, evidence_dir: Path) -> GateWorkflowResult:
    from .defense_frontier_gate import run_gate_04

    outcome = run_gate_04(gate, evidence_dir)
    return GateWorkflowResult(
        status=outcome.status,
        proofs=outcome.proofs,
        failure_reason=outcome.failure_reason,
    )


def _gate_05_workflow(gate: GateDefinition, evidence_dir: Path) -> GateWorkflowResult:
    from .collector_gate import run_gate_05

    outcome = run_gate_05(gate, evidence_dir)
    return GateWorkflowResult(
        status=outcome.status,
        proofs=outcome.proofs,
        failure_reason=outcome.failure_reason,
    )


def _gate_10_workflow(gate: GateDefinition, evidence_dir: Path) -> GateWorkflowResult:
    # Import lazily so the generic dispatcher remains cheap and so the
    # architecture auditor can be exercised independently by focused tests.
    from .architecture_gate import run_gate_10

    outcome = run_gate_10(gate, evidence_dir)
    return GateWorkflowResult(
        status=outcome.status,
        proofs=outcome.proofs,
        failure_reason=outcome.failure_reason,
    )


# Gate implementations are added here only after their dynamic workflow and
# focused tests exist. Missing gates retain the explicit failing baseline.
_WORKFLOWS: dict[str, GateWorkflow] = {
    "GATE-01": _gate_01_workflow,
    "GATE-02": _gate_02_workflow,
    "GATE-04": _gate_04_workflow,
    "GATE-05": _gate_05_workflow,
    "GATE-10": _gate_10_workflow,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"required acceptance binding {name} is unavailable")
    return value


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def run_gate_workflow(
    gate_id: str,
    *,
    receipt_path: Path,
    evidence_dir: Path,
    release: bool,
) -> int:
    if not release:
        raise ValueError("product gate workflows require the explicit --release flag")
    contract = load_release_contract()
    gates = {gate.gate_id: gate for gate in contract.gates}
    try:
        gate = gates[gate_id]
    except KeyError as exc:
        raise ValueError("unknown locked release gate") from exc

    gate_dir = evidence_dir.resolve(strict=True)
    receipt = receipt_path.resolve()
    if not gate_dir.is_dir() or receipt.parent != gate_dir or receipt.name != "gate-receipt.json":
        raise ValueError("gate receipt must use the harness-owned evidence directory")
    if _required_environment("BLUEFIRE_ACCEPTANCE_GATE_ID") != gate_id:
        raise ValueError("gate environment binding does not match the requested gate")
    if Path(_required_environment("BLUEFIRE_ACCEPTANCE_GATE_DIR")).resolve() != gate_dir:
        raise ValueError("gate evidence directory binding does not match")
    if Path(_required_environment("BLUEFIRE_ACCEPTANCE_RECEIPT")).resolve() != receipt:
        raise ValueError("gate receipt binding does not match")
    if _required_environment("BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256") != contract.digest:
        raise ValueError("gate contract binding does not match the locked contract")

    acceptance_id = _required_environment("BLUEFIRE_ACCEPTANCE_ID")
    repository_commit = _required_environment("BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT")
    repository_tree = _required_environment("BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE")
    release_binding = _required_environment("BLUEFIRE_ACCEPTANCE_RELEASE")
    if release_binding not in {"true", "false"}:
        raise ValueError("gate release-mode binding is invalid")
    workflow = _WORKFLOWS.get(gate_id)
    if workflow is None:
        result = GateWorkflowResult(
            status="failed",
            proofs=(),
            failure_reason=(
                f"{gate_id} has no registered release workflow; unproven assertions: "
                + ", ".join(assertion.assertion_id for assertion in gate.assertions)
            ),
        )
    else:
        result = workflow(gate, gate_dir)
    if result.status not in {"passed", "failed"}:
        raise ValueError("gate workflow returned an invalid status")
    if result.status == "passed" and result.failure_reason is not None:
        raise ValueError("passing gate workflow cannot return a failure reason")
    if result.status == "failed" and not result.failure_reason:
        raise ValueError("failed gate workflow must return an exact failure reason")

    _write_receipt(
        receipt,
        {
            "schema_version": "bluefire.product-gate-receipt.v1",
            "gate_id": gate_id,
            "acceptance_id": acceptance_id,
            "contract_sha256": contract.digest,
            "repository_commit": repository_commit,
            "repository_tree": repository_tree,
            "release": release_binding == "true",
            "harness_assessment": None,
            "timestamp": _utc_now(),
            "status": result.status,
            "failure_reason": result.failure_reason,
            "proofs": list(result.proofs),
        },
    )
    return 0 if result.status == "passed" else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="product_gates.py")
    parser.add_argument("--gate", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--release", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        return run_gate_workflow(
            args.gate,
            receipt_path=args.receipt,
            evidence_dir=args.evidence_dir,
            release=args.release,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["GateWorkflowResult", "main", "run_gate_workflow"]
