from __future__ import annotations

import json
from pathlib import Path

import pytest

from bluefire.run_store import RunStore, RunStoreError


def _create(store: RunStore):
    return store.create_run(
        scenario={"schema_version": "bluefire.scenario.v1", "id": "test"},
        plan={"schema_version": "bluefire.plan.v1", "steps": []},
        policy={"schema_version": "bluefire.policy.v1", "allowed": True},
        profile=None,
    )


def test_run_ids_are_generated_and_contained(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    handle = _create(store)

    assert handle.path.parent == store.root
    assert handle.path.name == handle.run_id
    assert store.get_run(handle.run_id)["run_id"] == handle.run_id

    for invalid in ("../escape", "run-x", str(tmp_path.resolve()), ""):
        with pytest.raises(RunStoreError):
            store.get_run(invalid)


def test_acceptance_binding_is_environment_owned_and_finalized_into_bundle(
    tmp_path: Path,
    monkeypatch,
) -> None:
    environment = {
        "BLUEFIRE_ACCEPTANCE_ID": "acceptance-test",
        "BLUEFIRE_ACCEPTANCE_GATE_ID": "GATE-03",
        "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256": "sha256:" + "1" * 64,
        "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT": "2" * 40,
        "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE": "3" * 40,
        "BLUEFIRE_ACCEPTANCE_RELEASE": "true",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    store = RunStore(tmp_path / "runs")
    handle = _create(store)
    store.finalize(
        handle.run_id,
        result={
            "schema_version": "bluefire.run-result.v1",
            "status": "completed",
            "created_at": handle.created_at,
        },
        evidence=[],
        detections=[],
    )

    assert store.get_run(handle.run_id)["acceptance_binding"] == {
        "schema_version": "bluefire.product-acceptance-run-binding.v1",
        "acceptance_id": "acceptance-test",
        "gate_id": "GATE-03",
        "contract_sha256": "sha256:" + "1" * 64,
        "repository_commit": "2" * 40,
        "repository_tree": "3" * 40,
        "release": "true",
    }


def test_duplicate_generated_id_never_reuses_a_bundle(tmp_path: Path, monkeypatch) -> None:
    store = RunStore(tmp_path / "runs")
    values = iter(
        [
            "run-20260101T000000Z-0000000000000001",
            "run-20260101T000000Z-0000000000000001",
            "run-20260101T000000Z-0000000000000002",
        ]
    )
    monkeypatch.setattr(store, "_new_run_id", lambda: next(values))

    first = _create(store)
    second = _create(store)

    assert first.run_id != second.run_id
    assert first.path.is_dir() and second.path.is_dir()


def test_event_stream_is_monotonic_and_bundle_detects_tampering(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    handle = _create(store)
    assert store.append_event(handle.run_id, "step.started", {"step_id": "one"}) == 2
    assert store.append_event(handle.run_id, "step.finished", {"step_id": "one"}) == 3
    events = store.read_events(handle.run_id)
    assert [row["sequence"] for row in events] == [1, 2, 3]
    assert events[0]["previous_event_hash"] is None
    assert events[1]["previous_event_hash"] == events[0]["event_hash"]

    manifest = store.finalize(
        handle.run_id,
        result={"schema_version": "bluefire.run.v1", "status": "success"},
        evidence=[],
        detections=[],
    )
    assert manifest["bundle_hash"].startswith("sha256:")
    assert store.validate_bundle(handle.run_id)["valid"] is True

    result_path = handle.path / "result.json"
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["status"] = "tampered"
    result_path.write_text(json.dumps(value), encoding="utf-8")
    validation = store.validate_bundle(handle.run_id)
    assert validation["valid"] is False
    assert "result.json" in validation["mismatches"]


def test_finalized_bundle_integrity_gates_detail_and_list_summary(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    handle = _create(store)
    store.finalize(
        handle.run_id,
        result={"schema_version": "bluefire.run.v1", "status": "completed"},
        evidence=[],
        detections=[],
    )

    result_path = handle.path / "result.json"
    tampered = json.loads(result_path.read_text(encoding="utf-8"))
    tampered["status"] = "attacker-controlled"
    tampered["untrusted_result"] = {"claim": "success"}
    result_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(RunStoreError, match="integrity validation.*result.json"):
        store.get_run(handle.run_id)

    assert store.list_runs() == [
        {
            "run_id": handle.run_id,
            "status": "corrupted",
            "integrity": {"valid": False, "mismatches": ["result.json"]},
        }
    ]


def test_unfinalized_run_detail_and_list_behavior_is_preserved(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    handle = _create(store)

    assert store.get_run(handle.run_id)["status"] == "created"
    assert store.list_runs() == [
        {
            "schema_version": "1.0",
            "run_id": handle.run_id,
            "created_at": handle.created_at,
            "status": "created",
            "replay": None,
        }
    ]


def test_finalized_recovery_journal_is_atomic_independent_and_tamper_evident(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "runs")
    handle = _create(store)
    store.finalize(
        handle.run_id,
        result={"schema_version": "bluefire.run.v1", "status": "completed"},
        evidence=[],
        detections=[],
    )
    original_manifest = (handle.path / "manifest.json").read_bytes()
    original_result = (handle.path / "result.json").read_bytes()
    recovery = {
        "schema_version": "bluefire.cleanup-recovery.v1",
        "status": "completed",
        "remaining_receipt_count": 0,
    }

    first = store.append_recovery_record(handle.run_id, recovery)
    duplicate = store.append_recovery_record(handle.run_id, recovery)

    assert first["recovery_id"] == duplicate["recovery_id"]
    assert (handle.path / "manifest.json").read_bytes() == original_manifest
    assert (handle.path / "result.json").read_bytes() == original_result
    assert store.validate_bundle(handle.run_id)["valid"] is True
    detail = store.get_run(handle.run_id)
    assert len(detail["recovery_journal"]) == 1
    assert detail["cleanup_recovery"]["status"] == "completed"

    record_path = handle.path / str(first["recovery_id"]) / "record.json"
    changed = json.loads(record_path.read_text(encoding="utf-8"))
    changed["status"] = "tampered"
    record_path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(RunStoreError, match="recovery bundle failed integrity"):
        store.get_run(handle.run_id)
    assert store.list_runs()[0]["status"] == "corrupted"


def test_partial_recovery_staging_directory_never_changes_finalized_bundle(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "runs")
    handle = _create(store)
    store.finalize(
        handle.run_id,
        result={"schema_version": "bluefire.run.v1", "status": "completed"},
        evidence=[],
        detections=[],
    )
    original_manifest = (handle.path / "manifest.json").read_bytes()
    stale = handle.path / ".recovery-tmp-interrupted"
    stale.mkdir()
    (stale / "record.json").write_text('{"partial":true}', encoding="utf-8")

    assert store.get_run(handle.run_id)["status"] == "completed"
    assert store.read_recovery_records(handle.run_id) == []
    assert (handle.path / "manifest.json").read_bytes() == original_manifest
    assert store.validate_bundle(handle.run_id)["valid"] is True


def test_event_pages_are_bounded_and_cursor_based(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    handle = _create(store)
    for index in range(5):
        store.append_event(handle.run_id, "progress", {"index": index})

    first = store.read_event_page(handle.run_id, limit=3)
    second = store.read_event_page(
        handle.run_id,
        after_sequence=first["next_sequence"],
        limit=3,
    )

    assert [row["sequence"] for row in first["items"]] == [1, 2, 3]
    assert first["has_more"] is True
    assert [row["sequence"] for row in second["items"]] == [4, 5, 6]
    assert second["has_more"] is False


def test_event_stream_hash_chain_detects_content_tampering(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    handle = _create(store)
    store.append_event(handle.run_id, "progress", {"index": 1})
    events_path = handle.path / "events.jsonl"
    rows = events_path.read_text(encoding="utf-8").splitlines()
    row = json.loads(rows[0])
    row["data"]["status"] = "tampered"
    rows[0] = json.dumps(row)
    events_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    with pytest.raises(RunStoreError, match="hash"):
        store.read_events(handle.run_id)


def test_restart_recovery_marks_only_unfinalized_created_runs(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    interrupted = _create(store)
    completed = _create(store)
    store.finalize(
        completed.run_id,
        result={"schema_version": "bluefire.run.v1", "status": "completed"},
        evidence=[],
        detections=[],
    )

    assert store.recover_interrupted_runs() == 1
    assert store.get_run(interrupted.run_id)["status"] == "interrupted"
    assert store.get_run(completed.run_id)["status"] == "completed"


def test_bundle_file_symlink_is_refused(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    handle = _create(store)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    target = handle.path / "policy.json"
    target.unlink()
    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are unavailable to this test account")

    with pytest.raises(RunStoreError, match="symbolic"):
        store.read_json(handle.run_id, "policy.json")


def test_json_writer_rejects_non_finite_values(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    handle = _create(store)
    with pytest.raises(ValueError):
        store.write_json(handle.run_id, "comparison.json", {"score": float("nan")})
