from __future__ import annotations

import copy
import json
import os
import shutil
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.product_gates as product_gates
import bluefire.replay_gate as replay_gate
from bluefire.product_acceptance import load_release_contract
from bluefire.replay_gate_validation import (
    CHECK_NAMES,
    ReplayGateValidationError,
    validate_persisted_replay_gate,
)
from bluefire.replay_journey import (
    COMPARISON_REPORT,
    JOURNEY_REPORT,
    REPORT_PATHS,
    produce_replay_gate_evidence,
)
from bluefire.util import canonical_json_bytes, content_hash, file_hash

pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Gate 06 executes the packaged Windows runner artifact",
)


@pytest.fixture(scope="module")
def replay_evidence_template(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Mapping[str, object]]:
    evidence = tmp_path_factory.mktemp("gate06-template") / "evidence"
    evidence.mkdir()
    summary = produce_replay_gate_evidence(Path.cwd(), evidence)
    return evidence, summary


@pytest.fixture
def replay_evidence(
    replay_evidence_template: tuple[Path, Mapping[str, object]],
    tmp_path: Path,
) -> tuple[Path, Mapping[str, object]]:
    template, summary = replay_evidence_template
    evidence = tmp_path / "evidence"
    shutil.copytree(template, evidence)
    return evidence, summary


def _write_bundle_json(
    evidence_dir: Path,
    run_id: str,
    name: str,
    value: Mapping[str, Any],
) -> None:
    bundle = evidence_dir / "runs" / run_id
    target = bundle / name
    target.write_bytes(canonical_json_bytes(value) + b"\n")
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][name] = {
        "hash": file_hash(target),
        "size_bytes": target.stat().st_size,
    }
    manifest["bundle_hash"] = content_hash(manifest["files"])
    manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")


def _journey(evidence_dir: Path) -> dict[str, Any]:
    value = json.loads((evidence_dir / JOURNEY_REPORT).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_replay_journey_produces_four_real_verified_runs(
    replay_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, summary = replay_evidence
    checks, bundles = validate_persisted_replay_gate(Path.cwd(), evidence)

    assert summary == {
        "schema_version": "bluefire.gate-06-helper.v1",
        "status": "passed",
        "reports": list(REPORT_PATHS),
        "run_count": 4,
    }
    assert len(bundles) == 4
    assert set(checks) == CHECK_NAMES
    assert all(checks.values())


def test_replay_gate_workflow_is_registered() -> None:
    assert product_gates._WORKFLOWS["GATE-06"] is product_gates._gate_06_workflow


def test_replay_helper_preserves_exact_windows_architecture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    captured: dict[str, str] = {}

    def bounded_helper(
        _command: list[str],
        *,
        repository: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> tuple[int, bytes]:
        assert repository == Path.cwd()
        assert timeout_seconds == 420
        captured.update(environment)
        return 0, json.dumps(
            {
                "schema_version": "bluefire.gate-06-helper.v1",
                "status": "passed",
                "reports": list(REPORT_PATHS),
                "run_count": 4,
            }
        ).encode("utf-8")

    monkeypatch.setattr(replay_gate, "_run_bounded_helper_process", bounded_helper)
    outcome = replay_gate._run_helper(Path.cwd(), evidence)

    assert outcome["passed"] is True
    assert captured["PROCESSOR_ARCHITECTURE"] in {"AMD64", "ARM64"}


def test_replay_validation_refuses_rehashed_checkpoint_corruption(
    replay_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = replay_evidence
    journey = _journey(evidence)
    source_run_id = journey["roles"]["source"]
    result_path = evidence / "runs" / source_run_id / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    selected = next(
        row
        for row in result["replay_checkpoints"]
        if row["checkpoint_before_step_id"] == journey["restart_step_id"]
    )
    selected["manifest_hash"] = "sha256:" + "0" * 64
    _write_bundle_json(evidence, source_run_id, "result.json", result)

    with pytest.raises(ReplayGateValidationError, match="checkpoint failed validation"):
        validate_persisted_replay_gate(Path.cwd(), evidence)


def test_replay_validation_refuses_a_rehashed_foreign_source_binding(
    replay_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = replay_evidence
    journey = _journey(evidence)
    source_run_id = journey["roles"]["source"]
    result_path = evidence / "runs" / source_run_id / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    selected = next(
        row
        for row in result["replay_checkpoints"]
        if row["checkpoint_before_step_id"] == journey["restart_step_id"]
    )
    selected["source_binding_hash"] = "sha256:" + "c" * 64
    body = {
        key: value
        for key, value in selected.items()
        if key not in {"checkpoint_id", "manifest_hash"}
    }
    selected["manifest_hash"] = content_hash(body)
    selected["checkpoint_id"] = "checkpoint-" + selected["manifest_hash"].removeprefix("sha256:")
    _write_bundle_json(evidence, source_run_id, "result.json", result)

    with pytest.raises(ReplayGateValidationError, match="checkpoint failed validation"):
        validate_persisted_replay_gate(Path.cwd(), evidence)


def test_replay_validation_refuses_rewritten_materialization_approval(
    replay_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = replay_evidence
    journey = _journey(evidence)
    replay_run_id = journey["roles"]["exact_restart"]
    result_path = evidence / "runs" / replay_run_id / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["checkpoint_materialization"]["approval_id"] = "approval-rewritten"
    _write_bundle_json(evidence, replay_run_id, "result.json", result)

    with pytest.raises(ReplayGateValidationError, match="checkpoint, plan, and approval"):
        validate_persisted_replay_gate(Path.cwd(), evidence)


def test_replay_validation_refuses_incomplete_comparison_dimensions(
    replay_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = replay_evidence
    comparison_path = evidence / COMPARISON_REPORT
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    comparison["summaries"][0]["dimensions"].pop("assessment")
    comparison_path.write_text(
        json.dumps(comparison, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ReplayGateValidationError, match="does not match canonical"):
        validate_persisted_replay_gate(Path.cwd(), evidence)


def test_replay_gate_emits_one_exact_proof_per_assertion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    gate = next(gate for gate in load_release_contract().gates if gate.gate_id == "GATE-06")
    bundles = tuple(
        {"run_id": f"run-proof-{index}", "path": f"runs/run-proof-{index}"} for index in range(4)
    )
    checks = {name: True for name in CHECK_NAMES}

    monkeypatch.setattr(
        replay_gate,
        "_run_helper",
        lambda _repository, _destination: {
            "passed": True,
            "exit_code": 0,
            "command": ["{python}", "tools/run_replay_gate_journey.py", "{fixed-arguments}"],
            "protocol_valid": True,
        },
    )
    monkeypatch.setattr(
        replay_gate,
        "_run_pytest_suite",
        lambda *_args, **_kwargs: {"passed": True, "suite_id": "materialized-replay-contracts"},
    )
    monkeypatch.setattr(
        replay_gate,
        "validate_persisted_replay_gate",
        lambda _repository, _destination: (checks, bundles),
    )
    monkeypatch.setattr(replay_gate, "_acceptance_binding", lambda: {"gate_id": "GATE-06"})
    monkeypatch.setattr(
        replay_gate,
        "validated_run_bundle",
        lambda _gate, _root, raw, **_kwargs: (dict(raw), {}),
    )

    outcome = replay_gate.run_gate_06(gate, evidence, repository_root=Path.cwd())

    assert outcome.status == "passed"
    assert outcome.failure_reason is None
    assert len(outcome.proofs) == 13
    assert len({proof["test_id"] for proof in outcome.proofs}) == 13
    assert {proof["kind"] for proof in outcome.proofs} == {"dynamic", "structural"}
    assert all(
        set(proof)
        == {
            "kind",
            "status",
            "test_id",
            "assertion_ids",
            "evidence_artifacts",
            "run_ids",
            "run_bundles",
            "environment_limitations",
        }
        and len(proof["assertion_ids"]) == 1
        and len(proof["run_ids"]) == 4
        and len(proof["run_bundles"]) == 4
        for proof in outcome.proofs
    )


def test_replay_gate_failure_redacts_private_paths() -> None:
    outcome = replay_gate._failure((r"C:\private\operator\checkpoint.json failed",))

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "C:\\private" not in str(outcome.failure_reason)
    assert "private-path-redacted" in str(outcome.failure_reason)


def test_replay_journey_report_cannot_be_mutated_without_detection(
    replay_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = replay_evidence
    journey = _journey(evidence)
    rewritten = copy.deepcopy(journey)
    rewritten["approval_ids"][1] = rewritten["approval_ids"][0]
    (evidence / JOURNEY_REPORT).write_text(
        json.dumps(rewritten, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ReplayGateValidationError, match="approvals"):
        validate_persisted_replay_gate(Path.cwd(), evidence)
