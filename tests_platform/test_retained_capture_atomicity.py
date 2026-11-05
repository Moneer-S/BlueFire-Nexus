"""Crash-safe retained capture custody and receipt publication checks."""

from __future__ import annotations

import ctypes
import os
import uuid
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import retained_artifacts as retained
from bluefire import windows_owner_acl as owner_acl
from bluefire.capability_resources import METHODS
from bluefire.composition_jobs import CompositionJobs
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.run_store import RunStore, RunStoreError
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_capability_composition import state as state
from tests_platform.test_product_store_capability_grants import (
    register,
    start,
)
from tests_platform.test_product_store_capability_grants import (
    saved as _saved_fixture,
)
from tests_platform.test_retained_artifact_execution import generated_bytes
from tests_platform.test_windows_owner_acl import _different_sid

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def saved_state(state, tmp_path):
    return _saved_fixture.__wrapped__(state, tmp_path)


def _capture(store: RunStore):
    handle = store.create_run(scenario={}, plan={}, policy={}, profile={})
    payload = generated_bytes()
    producer = EvidenceRecord.create(
        run_id=handle.run_id,
        step_id="stage",
        behavior_id=METHODS[4],
        action_id=METHODS[4],
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        runner_profile_id="test-profile",
        target_scope_ref="runner-profile:test-profile",
        content={"runner_status": "success", "request_hash": content_hash("stage")},
    )
    observation = EvidenceRecord.create(
        run_id=handle.run_id,
        step_id="stage",
        behavior_id=METHODS[4],
        action_id=METHODS[4],
        provenance=EvidenceProvenance.OBSERVED,
        producer="sandbox-observer.v1",
        runner_profile_id="test-profile",
        target_scope_ref="runner-profile:test-profile",
        parent_evidence_ids=(producer.evidence_id,),
        content={
            "path": "staged/bundle.jsonl",
            "sha256": sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        },
    )
    artifact = {
        "type": "artifact.sandbox.bundle.v1",
        "format": "jsonl",
        "path": "staged/bundle.jsonl",
        "sha256": sha256(payload).hexdigest(),
        "size": len(payload),
        "receipt_ids": ["a" * 64],
    }
    prepared = retained._capture_documents(
        run_id=handle.run_id,
        attempt_id="attempt-" + "b" * 32,
        lineage_id="lineage-atomic",
        job_id="job-" + "c" * 32,
        step=SimpleNamespace(step_id="stage", action_id=METHODS[4]),
        artifact=artifact,
        payload=payload,
        producer_record=producer.to_dict(),
        observation_record=observation.to_dict(),
    )
    return handle.run_id, payload, prepared


def _publish(store: RunStore, run_id: str, payload: bytes, prepared):
    return store.publish_retained_capture(
        run_id,
        payload=payload,
        capture=prepared["publication"],
        artifacts=prepared["artifacts"],
        event=prepared["event"],
    )


def test_exact_retry_reopens_one_private_capture_and_one_event(tmp_path):
    store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(store)
    first = _publish(store, run_id, payload, prepared)
    second = _publish(RunStore(store.root), run_id, payload, prepared)
    assert first == second == prepared["publication"]
    assert RunStore(store.root).read_retained_payload(run_id) == payload
    events = [row for row in store.read_events(run_id) if row["event_type"] == "artifact.retained"]
    assert len(events) == 1
    assert events[0]["data"]["capture_digest"] == prepared["receipt"]["capture_digest"]


def test_conflicting_retry_preserves_first_capture(tmp_path):
    store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(store)
    _publish(store, run_id, payload, prepared)
    changed = payload.replace(b"synthetic-redacted", b"synthetic-replaced")
    with pytest.raises(RunStoreError):
        _publish(RunStore(store.root), run_id, changed, prepared)
    assert RunStore(store.root).read_retained_payload(run_id) == payload
    assert RunStore(store.root).retained_capture(run_id) == prepared["publication"]


@pytest.mark.parametrize("projection", ["artifacts", "event"])
def test_conflicting_public_projection_is_preserved_and_refused(tmp_path, projection):
    store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(store)
    _publish(store, run_id, payload, prepared)
    run_path = store.root / run_id
    if projection == "artifacts":
        target = run_path / "artifacts.json"
        conflicting = b'{"foreign":"preserve"}\n'
    else:
        target = run_path / "events.jsonl"
        rows = store.read_events(run_id)
        body = {key: value for key, value in rows[-1].items() if key != "event_hash"}
        body["data"] = {**body["data"], "foreign": "preserve"}
        rows[-1] = {**body, "event_hash": content_hash(body)}
        conflicting = b"".join(canonical_json_bytes(row) + b"\n" for row in rows)
    target.write_bytes(conflicting)
    with pytest.raises(RunStoreError, match="projection|event"):
        _publish(RunStore(store.root), run_id, payload, prepared)
    assert target.read_bytes() == conflicting
    assert RunStore(store.root).read_retained_payload(run_id) == payload


def test_partial_private_capture_is_preserved_and_refused(tmp_path):
    store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(store)
    directory = store.root / run_id / "retained"
    directory.mkdir()
    store._harden_retained_entry(directory, directory=True)
    target = directory / "bundle.jsonl"
    store._atomic_write(target, payload)
    store._harden_retained_entry(target, directory=False)
    with pytest.raises(RunStoreError, match="inventory"):
        _publish(RunStore(store.root), run_id, payload, prepared)
    assert target.read_bytes() == payload
    assert sorted(path.name for path in directory.iterdir()) == ["bundle.jsonl"]


@pytest.mark.parametrize(
    "boundary",
    ["payload", "directory_ack", "metadata_ack", "event_ack"],
)
def test_each_publication_boundary_recovers_exactly_after_reopen(tmp_path, monkeypatch, boundary):
    store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(store)
    if boundary == "payload":
        original = store._atomic_write
        failed = False

        def fail_once(path, value):
            nonlocal failed
            if not failed and path.name == "bundle.jsonl":
                failed = True
                raise OSError("injected payload failure")
            return original(path, value)

        monkeypatch.setattr(store, "_atomic_write", fail_once)
    else:
        name = {
            "directory_ack": "_publish_retained_directory",
            "metadata_ack": "_publish_exact_file",
            "event_ack": "_append_exact_retained_event",
        }[boundary]
        original = getattr(store, name)
        failed = False

        def lost_ack(*args, **kwargs):
            nonlocal failed
            result = original(*args, **kwargs)
            if not failed:
                failed = True
                raise RunStoreError("injected lost acknowledgement")
            return result

        monkeypatch.setattr(store, name, lost_ack)
    with pytest.raises((OSError, RunStoreError)):
        _publish(store, run_id, payload, prepared)
    reopened = RunStore(store.root)
    assert _publish(reopened, run_id, payload, prepared) == prepared["publication"]
    assert reopened.read_retained_payload(run_id) == payload
    assert (
        len(
            [
                row
                for row in reopened.read_events(run_id)
                if row["event_type"] == "artifact.retained"
            ]
        )
        == 1
    )


def _receipt_state(saved_state):
    store, state, compiled, _ = saved_state
    submission = uuid.uuid4()
    token = submission.hex
    run_id = "run-20261104T000000Z-" + token[:16]
    marker = {
        "parent_job_id": state["parent_job_id"],
        "grant_id": state["grant"]["grant_id"],
        "grant_digest": state["grant"]["grant_digest"],
        "attempt_id": "attempt-" + token,
        "compiled_digest": compiled["compiled_digest"],
        "run_id": run_id,
    }
    request = {"composition_attempt": marker}
    store.create_idempotent_job(
        "composition.attempt",
        request,
        submission_id=str(submission),
        intent_digest=content_hash(request),
    )
    lease = store.reserve_capability_attempt(
        state["grant"]["grant_id"],
        compiled,
        expected_compiled_digest=compiled["compiled_digest"],
        attempt_id=marker["attempt_id"],
        job_id="job-" + token,
        run_id=run_id,
        plan_digest=content_hash("exact-plan"),
        native_envelope_digest=content_hash("exact-envelope"),
        current_environment=state["current_environment"],
        now_ms=3000,
    )
    start(saved_state, lease)
    task = register(saved_state, lease, task_id="task-stage", step_id="stage")
    store.record_capability_task_terminal(
        task["task_id"],
        request_hash=task["request_hash"],
        terminal_digest=content_hash("stage-terminal"),
    )
    with store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET state='running' WHERE job_id=?", (lease["job_id"],))
    source_body = {
        "run_id": lease["run_id"],
        "attempt_id": lease["attempt_id"],
        "lineage_id": lease["lineage_id"],
        "step_id": "stage",
        "artifact": "bundle",
        "artifact_type": "artifact.sandbox.bundle.v1",
        "sha256": "d" * 64,
        "size_bytes": 1,
    }
    source = {**source_body, "source_ref": content_hash(source_body)}
    body = {
        "schema_version": "bluefire.retained-artifact-capture-intent.v1",
        "job_id": lease["job_id"],
        "run_id": lease["run_id"],
        "attempt_id": lease["attempt_id"],
        "lineage_id": lease["lineage_id"],
        "step_id": "stage",
        "source": source,
        "artifacts_digest": content_hash("artifacts"),
        "producer_evidence_id": "evidence-producer",
        "producer_record_hash": content_hash("producer"),
        "observation_evidence_id": "evidence-observation",
        "observation_record_hash": content_hash("observation"),
    }
    intent = {**body, "intent_digest": content_hash(body)}
    receipt_body = {
        "schema_version": "bluefire.retained-artifact-capture.v1",
        "source": source,
        "producer_record_hash": body["producer_record_hash"],
        "observation_record_hash": body["observation_record_hash"],
    }
    receipt = {**receipt_body, "capture_digest": content_hash(receipt_body)}
    return store, lease, intent, receipt


def test_receipt_commit_lost_ack_reopens_exactly(saved_state, monkeypatch):
    store, lease, intent, receipt = _receipt_state(saved_state)
    store.begin_retained_artifact_capture(lease["job_id"], intent)
    original = store.commit_retained_artifact_capture

    def lost_ack(*args, **kwargs):
        original(*args, **kwargs)
        raise ProductStoreError("injected lost acknowledgement")

    monkeypatch.setattr(store, "commit_retained_artifact_capture", lost_ack)
    with pytest.raises(ProductStoreError, match="lost acknowledgement"):
        store.commit_retained_artifact_capture(lease["job_id"], receipt)
    reopened = ProductStore(store.path)
    assert reopened.commit_retained_artifact_capture(lease["job_id"], receipt) == receipt
    assert reopened.get_retained_artifact_capture(lease["attempt_id"]) == receipt
    with reopened._connection() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM capability_retained_capture_receipts"
            ).fetchone()[0]
            == 1
        )


def test_completed_capture_intent_exact_retry_and_pending_filter(saved_state):
    store, lease, intent, receipt = _receipt_state(saved_state)
    store.begin_retained_artifact_capture(lease["job_id"], intent)
    store.commit_retained_artifact_capture(lease["job_id"], receipt)
    with store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET state='completed' WHERE job_id=?", (lease["job_id"],))
    reopened = ProductStore(store.path)
    assert reopened.begin_retained_artifact_capture(lease["job_id"], intent) == intent
    assert reopened.list_retained_artifact_capture_intents() == []


def test_intent_lost_ack_reopens_exactly_before_filesystem_publication(saved_state, monkeypatch):
    store, lease, intent, _receipt = _receipt_state(saved_state)
    original = store.begin_retained_artifact_capture

    def lost_ack(*args, **kwargs):
        original(*args, **kwargs)
        raise ProductStoreError("injected intent acknowledgement loss")

    monkeypatch.setattr(store, "begin_retained_artifact_capture", lost_ack)
    with pytest.raises(ProductStoreError, match="acknowledgement loss"):
        store.begin_retained_artifact_capture(lease["job_id"], intent)
    reopened = ProductStore(store.path)
    assert reopened.begin_retained_artifact_capture(lease["job_id"], intent) == intent
    with reopened._connection() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM capability_retained_capture_intents"
            ).fetchone()[0]
            == 1
        )


@pytest.mark.parametrize("mutation", ["source_extra", "artifacts_digest"])
def test_intent_contract_refuses_noncanonical_source_and_digest(saved_state, mutation):
    store, lease, intent, _receipt = _receipt_state(saved_state)
    changed = {**intent}
    if mutation == "source_extra":
        changed["source"] = {**intent["source"], "extra": True}
    else:
        changed["artifacts_digest"] = "not-a-digest"
    changed["intent_digest"] = content_hash(
        {key: value for key, value in changed.items() if key != "intent_digest"}
    )
    with pytest.raises(ProductStoreError, match="binding"):
        store.begin_retained_artifact_capture(lease["job_id"], changed)


def test_receipt_without_intent_is_refused_as_partial_state(saved_state):
    store, lease, _intent, receipt = _receipt_state(saved_state)
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO capability_retained_capture_receipts VALUES(?,?,?,?)",
            (
                lease["attempt_id"],
                content_hash("missing-intent"),
                canonical_json(receipt),
                content_hash(receipt),
            ),
        )
    with pytest.raises(ProductStoreError, match="lost its exact intent"):
        store.get_retained_artifact_capture(lease["attempt_id"])


def test_append_only_receipt_refuses_conflicting_progress_mirror(saved_state):
    store, lease, intent, receipt = _receipt_state(saved_state)
    store.begin_retained_artifact_capture(lease["job_id"], intent)
    store.commit_retained_artifact_capture(lease["job_id"], receipt)
    changed = {**receipt, "capture_digest": content_hash("changed")}
    with store._connection(write=True) as connection:
        job = store.get_job(lease["job_id"])
        progress = {**job["progress"], "retained_artifact_capture": changed}
        connection.execute(
            "UPDATE jobs SET progress_json=? WHERE job_id=?",
            (canonical_json(progress), lease["job_id"]),
        )
    with pytest.raises(ProductStoreError, match="mirror"):
        store.get_retained_artifact_capture(lease["attempt_id"])
    with pytest.raises(ProductStoreError, match="mirror"):
        store.commit_retained_artifact_capture(lease["job_id"], receipt)
    with store._connection() as connection:
        persisted = connection.execute(
            "SELECT document_json FROM capability_retained_capture_receipts WHERE attempt_id=?",
            (lease["attempt_id"],),
        ).fetchone()[0]
    assert receipt["capture_digest"] in persisted
    assert changed["capture_digest"] not in persisted


def test_restart_reconciliation_commits_journal_without_native_replay(tmp_path):
    run_store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(run_store)
    _publish(run_store, run_id, payload, prepared)
    source = prepared["source"]
    evidence = prepared["publication"]["evidence"]
    entry = prepared["artifacts"]["artifacts"][0]
    run_store.finalize(
        run_id,
        result={
            "status": "failed",
            "mode": "execute",
            "steps": [
                {
                    "step_id": source["step_id"],
                    "action_id": METHODS[4],
                    "status": "success",
                    "request_hash": content_hash("stage"),
                    "runner_task_id": "task-stage",
                    "evidence_ids": [
                        evidence["producer"]["evidence_id"],
                        evidence["observation"]["evidence_id"],
                    ],
                    "artifacts": {
                        "bundle": {
                            "type": source["artifact_type"],
                            "format": "jsonl",
                            "path": "staged/bundle.jsonl",
                            "sha256": source["sha256"],
                            "size": source["size_bytes"],
                            "receipt_ids": entry["producer_receipt_ids"],
                        }
                    },
                }
            ],
            "cleanup": {"success": True, "outstanding_receipt_count": 0},
        },
        evidence=[evidence["producer"], evidence["observation"]],
        detections=[],
    )
    calls = []
    receipts = {}

    class Store:
        def get_capability_attempt(self, attempt_id):
            calls.append(("load", attempt_id))
            return {
                "lease": {
                    key: prepared["intent"][key]
                    for key in ("attempt_id", "run_id", "lineage_id", "job_id")
                }
            }

        def begin_retained_artifact_capture(self, job_id, intent):
            calls.append(("begin", job_id))
            return intent

        def commit_retained_artifact_capture(self, job_id, receipt):
            calls.append(("commit", job_id))
            receipts[job_id] = receipt
            return receipt

        def list_retained_artifact_capture_intents(self):
            return [prepared["intent"]]

    jobs = SimpleNamespace(
        store=Store(),
        service=SimpleNamespace(detection_lab=SimpleNamespace(run_store=RunStore(run_store.root))),
    )
    assert retained.reconcile_captures(jobs) == {
        "examined": 1,
        "reconciled": 1,
        "pending": 0,
        "refused": 0,
    }
    assert calls == [
        ("load", prepared["intent"]["attempt_id"]),
        ("begin", prepared["intent"]["job_id"]),
        ("commit", prepared["intent"]["job_id"]),
    ]
    assert receipts[prepared["intent"]["job_id"]] == prepared["receipt"]


def test_receipt_requires_exact_sealed_evidence_records(tmp_path):
    store = RunStore(tmp_path / "runs")
    _run_id, _payload, prepared = _capture(store)
    publication = prepared["publication"]
    producer = publication["evidence"]["producer"]
    observation = publication["evidence"]["observation"]
    sealed = {"evidence": {"records": [producer, observation]}}
    retained._verify_capture_evidence(sealed, publication)
    changed = {"evidence": {"records": [{**producer, "record_hash": "0" * 64}, observation]}}
    with pytest.raises(retained.CapabilityContractError, match="sealed evidence"):
        retained._verify_capture_evidence(changed, publication)


def test_corrupt_sealed_evidence_is_refused_without_aborting_recovery(tmp_path, monkeypatch):
    run_store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(run_store)
    _publish(run_store, run_id, payload, prepared)

    class Store:
        def list_retained_artifact_capture_intents(self):
            return [prepared["intent"]]

        def get_capability_attempt(self, _attempt_id):
            return {
                "lease": {
                    key: prepared["intent"][key]
                    for key in ("attempt_id", "run_id", "lineage_id", "job_id")
                }
            }

        def begin_retained_artifact_capture(self, *_args):
            raise AssertionError("corrupt evidence must never gain a receipt")

        commit_retained_artifact_capture = begin_retained_artifact_capture

    def corrupt_evidence(_store, _source):
        raise ValueError("injected corrupt sealed evidence")

    monkeypatch.setattr(retained, "resolve_metadata", corrupt_evidence)
    reopened = RunStore(run_store.root)
    monkeypatch.setattr(reopened, "get_run", lambda *_args, **_kwargs: {"status": "failed"})
    jobs = SimpleNamespace(
        store=Store(),
        service=SimpleNamespace(detection_lab=SimpleNamespace(run_store=reopened)),
    )
    assert retained.reconcile_captures(jobs) == {
        "examined": 1,
        "reconciled": 0,
        "pending": 1,
        "refused": 1,
    }


def test_manifestless_restart_preserves_pending_capture_without_certifying_or_replay(tmp_path):
    run_store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(run_store)
    _publish(run_store, run_id, payload, prepared)
    assert run_store.recover_interrupted_runs() == 1
    calls = []

    class Store:
        def get_capability_attempt(self, attempt_id):
            calls.append(("load", attempt_id))
            return {
                "lease": {
                    key: prepared["intent"][key]
                    for key in ("attempt_id", "run_id", "lineage_id", "job_id")
                }
            }

        def begin_retained_artifact_capture(self, job_id, intent):
            calls.append(("begin", job_id))
            raise AssertionError("an unsealed run must not gain a trusted capture intent")

        def commit_retained_artifact_capture(self, job_id, receipt):
            calls.append(("commit", job_id))
            raise AssertionError("an unsealed run must not gain a trusted capture receipt")

        def list_retained_artifact_capture_intents(self):
            return [prepared["intent"]]

    jobs = SimpleNamespace(
        store=Store(),
        service=SimpleNamespace(detection_lab=SimpleNamespace(run_store=RunStore(run_store.root))),
    )
    assert retained.reconcile_captures(jobs) == {
        "examined": 1,
        "reconciled": 0,
        "pending": 1,
        "refused": 0,
    }
    assert calls == [("load", prepared["intent"]["attempt_id"])]
    assert RunStore(run_store.root).read_retained_payload(run_id) == payload


def test_orphan_journal_cannot_retroactively_create_intent_or_repair_projection(tmp_path):
    run_store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(run_store)
    _publish(run_store, run_id, payload, prepared)
    artifacts_path = run_store.root / run_id / "artifacts.json"
    artifacts_path.unlink()

    class Store:
        def list_retained_artifact_capture_intents(self):
            return []

        def get_capability_attempt(self, _attempt_id):
            raise AssertionError("orphan journal must not look up or create authority")

    jobs = SimpleNamespace(
        store=Store(),
        service=SimpleNamespace(detection_lab=SimpleNamespace(run_store=RunStore(run_store.root))),
    )
    assert retained.reconcile_captures(jobs) == {
        "examined": 1,
        "reconciled": 0,
        "pending": 0,
        "refused": 1,
    }
    assert not artifacts_path.exists()
    assert run_store.read_retained_payload(run_id) == payload


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative custody")
def test_posix_equal_length_mutation_before_open_is_refused(tmp_path, monkeypatch):
    store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(store)
    _publish(store, run_id, payload, prepared)
    target = store.root / run_id / "retained" / "bundle.jsonl"
    original_open = os.open
    changed = False

    def mutate_before_open(path, flags, *args, **kwargs):
        nonlocal changed
        if path == "bundle.jsonl" and "dir_fd" in kwargs and not changed:
            changed = True
            target.write_bytes(payload[:-1] + (b"x" if payload[-1:] != b"x" else b"y"))
            details = target.stat()
            os.utime(target, ns=(details.st_atime_ns, details.st_mtime_ns + 1_000_000_000))
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", mutate_before_open)
    with pytest.raises(RunStoreError, match="changed"):
        store.read_retained_payload(run_id)
    assert changed


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative custody")
def test_posix_private_directory_swap_during_inventory_is_refused(tmp_path, monkeypatch):
    store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(store)
    _publish(store, run_id, payload, prepared)
    run_path = store.root / run_id
    retained_path = run_path / "retained"
    moved_path = run_path / "retained-moved"
    original_scandir = os.scandir
    swapped = False

    def swap_before_inventory(path):
        nonlocal swapped
        if isinstance(path, int) and not swapped:
            swapped = True
            retained_path.rename(moved_path)
            retained_path.mkdir(mode=0o700)
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", swap_before_inventory)
    with pytest.raises(RunStoreError, match="directory changed"):
        _publish(store, run_id, payload, prepared)
    assert swapped
    assert (moved_path / "bundle.jsonl").read_bytes() == payload


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative custody")
def test_posix_same_root_run_alias_is_refused(tmp_path):
    store = RunStore(tmp_path / "runs")
    first, _payload, _prepared = _capture(store)
    second, _payload_two, _prepared_two = _capture(store)
    (store.root / first).rename(store.root / "moved-run")
    (store.root / first).symlink_to(store.root / second, target_is_directory=True)
    with pytest.raises(RunStoreError, match="escapes the configured output root"):
        store.read_retained_payload(first)


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative custody")
def test_posix_run_swap_between_read_and_reconciliation_is_refused(tmp_path, monkeypatch):
    store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(store)
    _publish(store, run_id, payload, prepared)
    original_publish = store.publish_retained_capture
    switched = False

    def swap_before_publish(*args, **kwargs):
        nonlocal switched
        if not switched:
            switched = True
            (store.root / run_id).rename(store.root / "moved-run")
            (store.root / run_id).mkdir(mode=0o700)
        return original_publish(*args, **kwargs)

    monkeypatch.setattr(store, "publish_retained_capture", swap_before_publish)
    with pytest.raises(RunStoreError, match="namespace changed"):
        store.retained_capture(run_id)
    assert switched
    assert not (store.root / run_id / "artifacts.json").exists()


def test_service_startup_invokes_retained_capture_reconciliation(tmp_path, monkeypatch):
    expected = {"examined": 2, "reconciled": 1, "pending": 1, "refused": 0}
    calls = []

    def reconcile(composition):
        calls.append(composition)
        return expected

    monkeypatch.setattr(CompositionJobs, "recover_retained_captures", reconcile)
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "bluefire.sqlite3",
    )
    try:
        assert calls == [service.composition]
        assert service.retained_capture_recovery == expected
    finally:
        service.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL contract")
@pytest.mark.parametrize(
    ("relative", "directory"),
    [
        ((), True),
        (("retained",), True),
        (("retained", "bundle.jsonl"), False),
    ],
)
def test_windows_broadened_private_dacl_is_refused(tmp_path, relative, directory):
    import msvcrt

    store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(store)
    _publish(store, run_id, payload, prepared)
    path = store.root / run_id
    for part in relative:
        path /= part
    descriptor = owner_acl._windows_open_descriptor(path, directory=directory, write_dac=True)
    advapi32, kernel32 = owner_acl._configure_apis()
    sid = owner_acl.current_user_sid()
    seeded = owner_acl._converted_descriptor(
        advapi32, f"D:P(A;;FA;;;{sid})(A;;FR;;;{_different_sid(sid)})"
    )
    try:
        status = advapi32.SetSecurityInfo(
            ctypes.c_void_p(msvcrt.get_osfhandle(descriptor)),
            owner_acl._SE_FILE_OBJECT,
            owner_acl._DACL_SECURITY_INFORMATION | owner_acl._PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            owner_acl._descriptor_dacl(advapi32, seeded),
            None,
        )
        assert status == 0
    finally:
        kernel32.LocalFree(seeded)
        os.close(descriptor)
    try:
        with pytest.raises(RunStoreError, match="DACL"):
            RunStore(store.root).read_retained_payload(run_id)
    finally:
        descriptor = owner_acl._windows_open_descriptor(path, directory=directory, write_dac=True)
        try:
            owner_acl.apply_owner_private_acl(descriptor, directory=directory)
            owner_acl.verify_owner_private_acl(descriptor, directory=directory)
        finally:
            os.close(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL contract")
@pytest.mark.parametrize("boundary", ["apply", "verify"])
def test_windows_dacl_hardening_failure_refuses_publication(tmp_path, monkeypatch, boundary):
    store = RunStore(tmp_path / "runs")
    run_id, payload, prepared = _capture(store)

    def fail(*_args, **_kwargs):
        raise owner_acl.WindowsOwnerAclError("injected private DACL failure")

    monkeypatch.setattr(f"bluefire.run_store.{boundary}_owner_private_acl", fail)
    with pytest.raises(RunStoreError, match="permissions|DACL"):
        _publish(store, run_id, payload, prepared)
    run_path = store.root / run_id
    assert not (run_path / "retained").exists()
    assert not (run_path / "artifacts.json").exists()
    assert [event["event_type"] for event in store.read_events(run_id)] == ["run.created"]
