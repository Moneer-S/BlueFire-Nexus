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
