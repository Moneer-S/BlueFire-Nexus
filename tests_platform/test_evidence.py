from __future__ import annotations

from pathlib import Path

import pytest

from bluefire.evidence import (
    EvidenceError,
    EvidenceGraph,
    EvidenceProvenance,
    EvidenceRecord,
    SandboxObserver,
)


def _record(**overrides):
    values = {
        "run_id": "run-test",
        "step_id": "deliver",
        "behavior_id": "fixture.deliver.v1",
        "action_id": "sandbox.fixture.create.v1",
        "provenance": EvidenceProvenance.EXECUTED,
        "producer": "runner.test",
        "runner_profile_id": "profile.test",
        "content": {"artifact_type": "file", "path": "fixture/input.txt"},
        "target_scope_ref": "runner-profile:profile.test",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    values.update(overrides)
    return EvidenceRecord.create(**values)


def test_provenance_is_explicit_and_hashes_are_stable() -> None:
    first = _record()
    second = _record()
    assert first == second
    assert first.to_dict()["provenance"] == "executed"
    assert first.content_hash.startswith("sha256:")
    assert first.record_hash.startswith("sha256:")


def test_evidence_rehydration_verifies_content_record_and_identity_hashes() -> None:
    record = _record()
    assert EvidenceRecord.from_mapping(record.to_dict()) == record

    tampered = record.to_dict()
    tampered["content"] = {"artifact_type": "file", "path": "staged/tampered.txt"}
    with pytest.raises(EvidenceError, match="content hash"):
        EvidenceRecord.from_mapping(tampered)


def test_evidence_graph_rejects_dangling_parent() -> None:
    graph = EvidenceGraph()
    child = _record(parent_evidence_ids=("missing",))
    with pytest.raises(EvidenceError, match="unknown parents"):
        graph.add(child)


def test_evidence_graph_rejects_parent_from_another_run() -> None:
    graph = EvidenceGraph()
    parent = _record(run_id="run-first")
    graph.add(parent)

    with pytest.raises(EvidenceError, match="another run"):
        graph.add(_record(run_id="run-second", parent_evidence_ids=(parent.evidence_id,)))


def test_sandbox_observer_records_independent_file_state(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    path = root / "staged" / "artifact.txt"
    path.parent.mkdir(parents=True)
    path.write_text("benign fixture", encoding="utf-8")
    parent = _record()

    observed = SandboxObserver(root).observe_file(
        relative_path="staged/artifact.txt",
        run_id="run-test",
        step_id="stage",
        behavior_id="collection.stage_fixture.v1",
        action_id="sandbox.collection.stage.v1",
        runner_profile_id="profile.test",
        parent_evidence_ids=(parent.evidence_id,),
    )

    assert observed.provenance is EvidenceProvenance.OBSERVED
    assert observed.content["size_bytes"] == len("benign fixture")
    assert observed.content["sha256"]


def test_sandbox_observer_refuses_escape(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    observer = SandboxObserver(root)

    with pytest.raises(EvidenceError):
        observer.observe_file(
            relative_path="../outside.txt",
            run_id="run-test",
            step_id="stage",
            behavior_id="collection.stage_fixture.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test",
        )


def test_sandbox_observer_enforces_file_size_bound(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    (root / "large.bin").write_bytes(b"12345")
    observer = SandboxObserver(root, max_file_bytes=4)

    with pytest.raises(EvidenceError, match="byte limit"):
        observer.observe_file(
            relative_path="large.bin",
            run_id="run-test",
            step_id="collect",
            behavior_id="collection.stage_fixture.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test",
        )
