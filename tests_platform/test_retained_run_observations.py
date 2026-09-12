"""Unsealed display reads never become canonical run or execution authority."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bluefire import retained_run_observations as retained
from bluefire.api import APIError
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.run_store import RunStore, RunStoreError
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_api import RUN_ID, StubService, json_body, request, running_server


def create(store):
    scenario = {"schema_version": "bluefire.scenario.v1", "id": "fixture", "steps": []}
    return store.create_run(
        scenario=scenario,
        plan={
            "scenario_id": "fixture",
            "scenario_digest": content_hash(scenario),
            "mode": "simulate",
            "steps": [],
        },
        policy={},
        profile=None,
    )


def evidence(run_id, **changes):
    return EvidenceRecord.create(
        run_id=run_id,
        step_id="observe",
        behavior_id="observe.host.v1",
        provenance=EvidenceProvenance.SYNTHETIC,
        producer="software-test",
        content=changes.pop("content", {"fixture": True}),
        target_scope_ref="sandbox.workspace",
        **changes,
    ).to_dict()


def snapshot(path):
    return {
        item.name: (item.read_bytes(), item.stat().st_mtime_ns)
        for item in path.iterdir()
        if item.is_file()
    }


@pytest.mark.parametrize("failure_stage", ["event", "manifest", "torn_event", "torn_utf8"])
def test_failed_finalization_displays_same_session_without_changing_authority(
    tmp_path, monkeypatch, failure_stage
):
    store = RunStore(tmp_path / "runs")
    handle = create(store)
    original_write, original_event = store.write_json, store.append_event

    def write(run_id, name, value):
        if name == "manifest.json":
            raise OSError("private finalization failure")
        return original_write(run_id, name, value)

    def event(run_id, event_type, data):
        if event_type == "run.finalized":
            if failure_stage in {"torn_event", "torn_utf8"}:
                with (handle.path / "events.jsonl").open("ab") as stream:
                    stream.write(
                        b'{"partial":' if failure_stage == "torn_event" else b'{"partial":"\xe2'
                    )
            raise OSError("private finalization failure")
        return original_event(run_id, event_type, data)

    with monkeypatch.context() as patch:
        patch.setattr(
            store,
            "write_json" if failure_stage == "manifest" else "append_event",
            write if failure_stage == "manifest" else event,
        )
        with pytest.raises(OSError):
            store.finalize(
                handle.run_id,
                result={
                    "status": "completed",
                    "steps": [{"step_id": "observe", "status": "success"}],
                },
                evidence=[evidence(handle.run_id)],
                detections=[],
            )
    before = snapshot(handle.path)
    response = retained.retained_observations(store, handle.run_id)
    assert response["record_state"] == "unsealed"
    assert response["display_only"] is True
    assert response["canonical"] is response["replay_available"] is False
    assert response["events_complete"] is (failure_stage not in {"torn_event", "torn_utf8"})
    assert response["observations"]["status"] == "completed"
    assert response["observations"]["evidence"]["records"][0]["provenance"] == "synthetic"
    assert "manifest" not in response["observations"]
    with pytest.raises(RunStoreError, match="not sealed"):
        store.get_run(handle.run_id)
    assert snapshot(handle.path) == before


@pytest.mark.parametrize("manifest", [b"{}", b"not-json"])
def test_existing_manifest_is_never_bypassed(tmp_path, manifest):
    store = RunStore(tmp_path / "runs")
    handle = create(store)
    (handle.path / "manifest.json").write_bytes(manifest)
    before = snapshot(handle.path)
    with pytest.raises(RunStoreError):
        retained.retained_observations(store, handle.run_id)
    assert snapshot(handle.path) == before


def test_valid_sealed_record_uses_only_canonical_route(tmp_path):
    store = RunStore(tmp_path / "runs")
    handle = create(store)
    store.finalize(handle.run_id, result={"status": "completed"}, evidence=[], detections=[])
    assert store.get_run(handle.run_id)["manifest"]
    with pytest.raises(RunStoreError):
        retained.retained_observations(store, handle.run_id)


@pytest.mark.parametrize(
    "change",
    [
        "foreign_result",
        "foreign_evidence",
        "tampered_evidence",
        "plaintext",
        "scenario_digest",
        "authority_overlay",
        "duplicate_json",
        "nonfinite",
        "event_identity",
        "event_corruption",
        "oversize",
    ],
)
def test_invalid_or_private_display_data_is_refused(tmp_path, change):
    store = RunStore(tmp_path / "runs")
    handle = create(store)
    if change == "foreign_result":
        store.write_json(handle.run_id, "result.json", {"run_id": RUN_ID, "status": "created"})
    elif change in {"foreign_evidence", "tampered_evidence", "plaintext"}:
        row = evidence(
            RUN_ID if change == "foreign_evidence" else handle.run_id,
            content=(
                {"password": "private-fixture-value"}
                if change == "plaintext"
                else {"fixture": True}
            ),
        )
        if change == "tampered_evidence":
            row["content"] = {"fixture": False}
        store.write_json(handle.run_id, "evidence.json", {"records": [row]})
    elif change in {"scenario_digest", "authority_overlay"}:
        name = "plan.json" if change == "scenario_digest" else "result.json"
        value = dict(store.read_json(handle.run_id, name))
        value["scenario_digest" if change == "scenario_digest" else "manifest"] = {}
        store.write_json(handle.run_id, name, value)
    elif change in {"duplicate_json", "nonfinite", "oversize"}:
        (handle.path / "profile.json").write_bytes(
            {
                "duplicate_json": b'{"x":1,"x":2}',
                "nonfinite": b'{"x":NaN}',
                "oversize": b" " * (retained.MAX_FILE_BYTES + 1),
            }[change]
        )
    elif change == "event_identity":
        store.append_event(handle.run_id, "fixture", {"run_id": RUN_ID})
    else:
        with (handle.path / "events.jsonl").open("ab") as stream:
            stream.write(b'{"broken":true}\n')
    before = snapshot(handle.path)
    with pytest.raises(RunStoreError):
        retained.retained_observations(store, handle.run_id)
    assert snapshot(handle.path) == before


def test_hardlinked_file_is_not_read(tmp_path):
    store = RunStore(tmp_path / "runs")
    handle = create(store)
    os.link(handle.path / "profile.json", tmp_path / "private-link.json")
    with pytest.raises(RunStoreError):
        retained.retained_observations(store, handle.run_id)


def test_posix_ordinary_file_open_is_nonblocking_before_type_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(retained.sys, "platform", "linux")
    for name, value in (
        ("O_NOFOLLOW", 0x100000),
        ("O_CLOEXEC", 0x200000),
        ("O_NONBLOCK", 0x400000),
    ):
        monkeypatch.setattr(retained.os, name, value, raising=False)
    calls = []

    def open_file(path, flags, *, dir_fd):
        calls.append((path, flags, dir_fd))
        return 123

    monkeypatch.setattr(retained.os, "open", open_file)
    assert retained._open(tmp_path / "profile.json", 42, directory=False) == 123
    assert calls == [
        ("profile.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 42)
    ]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO fixture")
@pytest.mark.timeout(2)
def test_posix_fifo_is_refused_without_waiting_for_a_writer(tmp_path):
    store = RunStore(tmp_path / "runs")
    handle = create(store)
    (handle.path / "profile.json").unlink()
    os.mkfifo(handle.path / "profile.json")
    with pytest.raises(RunStoreError):
        retained.retained_observations(store, handle.run_id)


def test_changed_open_file_is_refused(tmp_path, monkeypatch):
    store = RunStore(tmp_path / "runs")
    handle = create(store)
    original = retained._state
    states = {}

    def changed(descriptor, *, directory):
        value = original(descriptor, directory=directory)
        if not directory:
            count = states.get(descriptor, 0)
            states[descriptor] = count + 1
            if count:
                return (*value[:-1], value[-1] + 1)
        return value

    monkeypatch.setattr(retained, "_state", changed)
    with pytest.raises(RunStoreError):
        retained.retained_observations(store, handle.run_id)


def test_descriptor_identity_checks_keep_full_volume_and_file_id(tmp_path, monkeypatch):
    store = RunStore(tmp_path / "runs")
    handle = create(store)
    original = retained.descriptor_identity
    seen = set()

    def replaced(descriptor, *, directory=False):
        value = original(descriptor, directory=directory)
        if not directory:
            if descriptor in seen:
                # A high-bit-only difference must never collapse to st_dev or
                # a truncated Windows volume/file identifier on Python 3.11.
                return value[0] ^ (1 << 48), value[1] ^ (1 << 96)
            seen.add(descriptor)
        return value

    monkeypatch.setattr(retained, "descriptor_identity", replaced)
    with pytest.raises(RunStoreError):
        retained.retained_observations(store, handle.run_id)


def test_total_read_budget_is_enforced_without_truncation(tmp_path, monkeypatch):
    store = RunStore(tmp_path / "runs")
    handle = create(store)
    monkeypatch.setattr(retained, "MAX_TOTAL_BYTES", 1)
    with pytest.raises(RunStoreError):
        retained.retained_observations(store, handle.run_id)


def test_manifest_appearing_during_capture_is_not_promoted(tmp_path, monkeypatch):
    store = RunStore(tmp_path / "runs")
    handle = create(store)
    original = retained._manifest_absent
    calls = 0

    def publish(path, parent):
        nonlocal calls
        calls += 1
        if calls == 2:
            (path / "manifest.json").write_text("{}", encoding="utf-8")
        original(path, parent)

    monkeypatch.setattr(retained, "_manifest_absent", publish)
    with pytest.raises(RunStoreError):
        retained.retained_observations(store, handle.run_id)
    assert (handle.path / "manifest.json").read_text(encoding="utf-8") == "{}"


@pytest.mark.parametrize("value", ["../outside", "run-invalid", ""])
def test_run_path_traversal_refused(tmp_path, value):
    with pytest.raises(RunStoreError):
        retained.retained_observations(RunStore(tmp_path / "runs"), value)


class RetainedStub(StubService):
    def retained_observations(self, run_id):
        self.calls.append(("retained_observations", run_id))
        return {"schema_version": "bluefire.retained-run-observations.v1", "run_id": run_id}


def test_explicit_route_dispatches_only_display_reader():
    with running_server(RetainedStub()) as (server, service):
        status, _, body = request(server, "GET", f"/api/v1/runs/{RUN_ID}/retained-observations")
    assert status == 200
    assert json_body(body)["run_id"] == RUN_ID
    assert service.calls == [("retained_observations", RUN_ID)]


@pytest.mark.parametrize(
    "method,authenticated,origin,suffix,expected",
    [
        ("GET", False, "same", "", 401),
        ("POST", True, "same", "", 405),
        ("GET", True, "same", "?authority=1", 400),
        ("POST", True, "https://unrelated.invalid", "", 403),
    ],
)
def test_display_route_preserves_http_guards(method, authenticated, origin, suffix, expected):
    with running_server(RetainedStub()) as (server, service):
        status, _, _ = request(
            server,
            method,
            f"/api/v1/runs/{RUN_ID}/retained-observations{suffix}",
            body={} if method == "POST" else None,
            authenticated=authenticated,
            origin=origin,
        )
    assert status == expected
    assert not service.calls


def test_service_masks_reader_error_details(tmp_path, monkeypatch):
    service = object.__new__(BlueFireService)
    service.store = RunStore(tmp_path / "runs")

    def failure(*args):
        raise RunStoreError("private/path password=private-value")

    monkeypatch.setattr(retained, "retained_observations", failure)
    with pytest.raises(APIError) as caught:
        service.retained_observations(RUN_ID)
    assert caught.value.code == "retained_observations_unavailable"
    assert "private" not in str(caught.value)


@pytest.mark.parametrize("failure_stage", ["event", "manifest"])
def test_real_service_failed_job_retains_observations_before_restart(
    tmp_path, monkeypatch, failure_stage
):
    service = BlueFireService(
        project_root=Path(__file__).resolve().parents[1],
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
    )
    original_event, original_write = service.store.append_event, service.store.write_json

    def event(run_id, event_type, data):
        if event_type == "run.finalized":
            raise OSError("private event failure")
        return original_event(run_id, event_type, data)

    def write(run_id, name, value):
        if name == "manifest.json":
            raise OSError("private manifest failure")
        return original_write(run_id, name, value)

    try:
        monkeypatch.setattr(
            service.store,
            "append_event" if failure_stage == "event" else "write_json",
            event if failure_stage == "event" else write,
        )
        submitted = service.submit_run(
            {
                "scenario_id": "scenario.sandbox.research.chain.v1",
                "mode": "simulate",
                "autonomy": "off",
                "target_scope": {"scope_refs": ["sandbox.workspace"]},
            }
        )
        job = service.job_controller.wait(submitted["job"]["job_id"], timeout=10)
        assert job["state"] == "failed"
        assert job["result_ref"] is None
        run_id = job["progress"]["run_id"]
        before = snapshot(service.store.root / run_id)
        view = service.retained_observations(run_id)
        assert view["observations"]["steps"]
        assert view["observations"]["evidence"]["records"]
        assert view["canonical"] is False
        with pytest.raises(APIError):
            service.detail(run_id)
        with pytest.raises((APIError, RunStoreError)):
            service.prepare_replay(run_id, {"mode": "simulate", "autonomy": "off"})
        assert snapshot(service.store.root / run_id) == before
        assert service.product_store.get_job(job["job_id"])["result_ref"] is None
    finally:
        service.close()
