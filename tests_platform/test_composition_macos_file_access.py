"""Coordinator boundaries for Darwin composition settlement and task terminals."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from bluefire import composition_macos_file_access as composition
from bluefire import macos_file_access_method as method
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash


class _Store:
    def __init__(self):
        self.calls = []
        self.closure = None

    def bind_macos_capability_file_access(self, attempt_id):
        self.calls.append(("bind", attempt_id))
        return {"attempt_id": attempt_id, "binding_digest": "sha256:binding"}

    def record_macos_capability_terminal(self, task_id, *, result):
        self.calls.append(("terminal", task_id, result))

    def close_macos_capability_attempt(self, attempt_id, *, cleanup_task_id, result):
        self.calls.append(("close", attempt_id, cleanup_task_id, result))
        self.closure = {"attempt_id": attempt_id, "cleanup_task_id": cleanup_task_id}
        return self.closure

    def get_macos_capability_closure(self, attempt_id):
        if self.closure is None:
            raise ProductStoreError("missing closure")
        return self.closure

    def settle_capability_attempt(self, attempt_id, receipt):
        self.calls.append(("settle", attempt_id, receipt))

    def get_capability_attempt(self, attempt_id):
        return {"attempt_id": attempt_id}


class _Jobs:
    def __init__(self, store):
        self.store = store
        self.published = []
        self.verified_calls = 0

    def _publish(self, job_id, progress):
        self.published.append((job_id, progress))

    def _verified_result(self, attempt):
        self.verified_calls += 1
        return {"attempt_id": attempt["attempt_id"]}


def test_prepare_binds_and_publishes_the_store_dependency():
    store = _Store()
    jobs = _Jobs(store)

    composition.prepare(jobs, "job-1", "attempt-1", {})

    assert store.calls == [("bind", "attempt-1")]
    assert jobs.published == [
        (
            "job-1",
            {
                "prepare_started": True,
                "phase": "verifying_macos_file_access",
                "macos_file_access_dependency": {
                    "attempt_id": "attempt-1",
                    "binding_digest": "sha256:binding",
                },
            },
        )
    ]


def test_business_terminal_is_recorded_without_generic_cleanup_claims():
    store = _Store()
    jobs = _Jobs(store)
    result = {"status": "success", "output": {"macos_receipt": {"state": "complete"}}}
    manifest = {"action_id": method.PROBE_ACTION}

    composition.record_terminal(
        jobs, "job-1", "attempt-1", {}, object(), manifest, "task-1", result
    )

    assert store.calls == [("terminal", "task-1", result)]
    assert jobs.published == []


def test_close_terminal_is_recorded_before_separate_attempt_closure():
    store = _Store()
    jobs = _Jobs(store)
    result = {"status": "success", "output": {"attempt_closure": {"state": "closed"}}}

    composition.record_terminal(
        jobs,
        "job-1",
        "attempt-1",
        {},
        object(),
        {"action_id": method.CLOSE_ACTION},
        "task-close",
        result,
    )

    assert [call[0] for call in store.calls] == ["terminal", "close"]
    assert jobs.published == [
        (
            "job-1",
            {
                "macos_attempt_closure": store.closure,
                "macos_attempt_closure_digest": content_hash(store.closure),
                "macos_file_access_request_state": "verified_closed",
            },
        )
    ]


def test_unsuccessful_close_terminal_stays_unknown_without_producer_closure():
    store = _Store()
    jobs = _Jobs(store)
    result = {"schema_version": "bluefire.task-not-sent.v1", "task_id": "task-close"}

    composition.record_terminal(
        jobs,
        "job-1",
        "attempt-1",
        {},
        object(),
        {"action_id": method.CLOSE_ACTION},
        "task-close",
        result,
    )

    assert store.calls == []
    assert store.closure is None
    assert jobs.published == [("job-1", {"macos_file_access_request_state": "unknown"})]


def test_generic_cleanup_cannot_replace_missing_macos_closure():
    store = _Store()
    jobs = _Jobs(store)
    marker = {"attempt_id": "attempt-1", "run_id": "run-1"}

    composition.settle(
        jobs,
        marker,
        "job-1",
        {"lease_digest": "sha256:lease"},
        {"run_id": "run-1"},
        {"digest": "sha256:generic-cleanup"},
    )

    assert store.calls == []
    assert jobs.verified_calls == 0
    assert jobs.published == [
        (
            "job-1",
            {"settlement": "pending_cleanup", "macos_file_access_request_state": "unknown"},
        )
    ]


def test_settlement_and_verified_result_require_a_finalized_run(monkeypatch):
    store = _Store()
    store.closure = {"attempt_id": "attempt-1", "closure_digest": "sha256:closure"}
    jobs = _Jobs(store)
    receipts = []
    monkeypatch.setitem(
        sys.modules,
        "bluefire.product_store_macos_settlement",
        SimpleNamespace(
            receipt=lambda target, attempt_id: receipts.append((target, attempt_id))
            or {"attempt_id": attempt_id}
        ),
    )

    composition.settle(
        jobs,
        {"attempt_id": "attempt-1", "run_id": "run-1"},
        "job-1",
        {"lease_digest": "sha256:lease"},
        None,
        None,
    )

    assert receipts == [(store, "attempt-1")]
    assert store.calls == [("settle", "attempt-1", {"attempt_id": "attempt-1"})]
    assert jobs.verified_calls == 0
    assert jobs.published[-1] == (
        "job-1",
        {"settlement": "settled", "macos_file_access_request_state": "verified_closed"},
    )


def test_finalized_run_is_the_only_path_that_publishes_a_verified_result(monkeypatch):
    store = _Store()
    store.closure = {"attempt_id": "attempt-1", "closure_digest": "sha256:closure"}
    jobs = _Jobs(store)
    monkeypatch.setitem(
        sys.modules,
        "bluefire.product_store_macos_settlement",
        SimpleNamespace(receipt=lambda target, attempt_id: {"attempt_id": attempt_id}),
    )

    composition.settle(
        jobs,
        {"attempt_id": "attempt-1", "run_id": "run-1"},
        "job-1",
        {"lease_digest": "sha256:lease"},
        {"run_id": "run-1", "finalized": True},
        None,
    )

    assert jobs.verified_calls == 1
    assert jobs.published[-1] == (
        "job-1",
        {
            "verified_result": {"attempt_id": "attempt-1"},
            "verified_result_digest": content_hash({"attempt_id": "attempt-1"}),
        },
    )


def test_verified_mac_result_uses_shared_objective_key_after_join(monkeypatch):
    resource = {"sha256": "fake-content-digest", "record_count": 2}
    binding = {"resource": resource}
    dependency = {
        "control_owner_id": "control-1",
        "control_revision": 2,
        "control_digest": "fake-control-digest",
        "binding_digest": content_hash(binding),
        "resource_digest": content_hash(resource),
        "resource_generation": "generation-1",
        "probe_step_id": "probe",
        "owner_step_id": "owner",
        "cleanup_step_id": "close",
    }
    lease = {
        "attempt_id": "attempt-1",
        "run_id": "run-1",
        "grant_id": "grant-1",
        "lease_digest": "fake-lease-digest",
        "compiled_digest": "fake-compiled-digest",
        "created_at_ms": 1000,
        "business_expires_at_ms": 9000,
    }
    tasks = {
        step: {"step_id": step, "task_id": "task-" + step, "request_hash": "request-" + step}
        for step in ("probe", "owner", "close")
    }
    receipts = {
        "non_owner": {"terminals": [{"outcome": "denied"}]},
        "owner": {"terminals": [{"outcome": "allowed", "fresh_read": resource}]},
    }
    observations = {}
    events = {}
    terminals = {}
    dispatches = {"task-close": {"request": "fake-close-dispatch"}}
    artifacts = {}
    for step, reader in (("probe", "non_owner"), ("owner", "owner")):
        task = tasks[step]
        intent = {"task_id": task["task_id"]}
        observation = {
            "attempt_id": "attempt-1",
            "run_id": "run-1",
            "step_id": step,
            "request_hash": task["request_hash"],
            "binding": binding,
            "reader": reader,
            "intent": intent,
            "outcome": "denied" if step == "probe" else "allowed",
            "observed_at_ms": 2000 if step == "probe" else 2001,
            "probe_task_id": "task-probe",
            "probe_receipt_digest": (
                None if step == "probe" else content_hash(receipts["non_owner"])
            ),
        }
        observations[step] = observation
        dispatches[task["task_id"]] = {
            "intent": intent,
            "request_hash": task["request_hash"],
            "step_id": step,
            "transport_request_hash": "transport-" + step,
        }
        events[step] = {
            **task,
            "state": "complete",
            "native_receipt_digest": content_hash(receipts[reader]),
            "observation_digest": content_hash(observation),
            "transport_request_hash": "transport-" + step,
            "terminal_digest": "terminal-" + step,
        }
        terminals[task["task_id"]] = {
            **task,
            "attempt_id": "attempt-1",
            "terminal_digest": "terminal-" + step,
        }
        artifacts[step] = {
            "observation": observation,
            "native_receipt_digest": content_hash(receipts[reader]),
            "observation_digest": content_hash(observation),
        }
    terminals["task-close"] = {"terminal_digest": "terminal-close"}
    closure = {
        "attempt_id": "attempt-1",
        "run_id": "run-1",
        "cleanup_task_id": "task-close",
        "binding_digest": dependency["binding_digest"],
        "task_closures": [],
        "attempt_artifacts": "not_created",
        "whole_enrollment_cleanup": False,
        "original_workers": "retained",
    }
    proofs = {
        phase: {
            "schema_version": "bluefire.macos-file-access-empty-workspace.v1",
            "attempt_id": "attempt-1",
            "lease_digest": lease["lease_digest"],
            "compiled_digest": lease["compiled_digest"],
            "phase": phase,
            "entry_count": 0,
            "state": "verified_empty",
            "workspace_path_digest": "fake-path-digest",
            "workspace_identity_digest": "fake-identity-digest",
        }
        for phase in ("reserve", "pre_close", "post_close")
    }
    closure_row = {
        "closure_digest": content_hash(closure),
        "attempt_id": "attempt-1",
        "lease_digest": lease["lease_digest"],
        "compiled_digest": lease["compiled_digest"],
        "cleanup_task_id": "task-close",
        "cleanup_dispatch_digest": content_hash(dispatches["task-close"]),
        "cleanup_terminal_digest": "terminal-close",
        "task_closures_digest": content_hash([]),
        "artifact_state": "not_created",
        "pre_close_workspace_attestation_digest": content_hash(proofs["pre_close"]),
        "workspace_attestation_digest": content_hash(proofs["post_close"]),
    }
    settlement = {
        "attempt_id": "attempt-1",
        "lease_digest": lease["lease_digest"],
        "run_id": "run-1",
        "macos_closure_digest": content_hash(closure_row),
    }
    store = SimpleNamespace(
        get_file_access_control_revision=lambda *args: {
            "document_digest": dependency["control_digest"],
            "document": {"binding": binding, "revision": 2, "status": "hardened"},
        },
        get_macos_capability_closure=lambda attempt_id: closure_row,
        get_capability_grant=lambda *args, **kwargs: {"document": {"grant_id": "grant-1"}},
    )
    monkeypatch.setattr(composition, "validate_binding", lambda value: value)
    monkeypatch.setattr(method, "validate_read_receipt", lambda value, *args: value)
    monkeypatch.setattr(method, "validate_metadata", lambda value, *args: value)
    monkeypatch.setattr(method, "validate_closure", lambda value: value)
    monkeypatch.setattr(composition, "_source_binding", lambda *args: {"source": "fake-run"})
    monkeypatch.setattr(
        composition,
        "_exact_task_evidence",
        lambda records, task, *args: SimpleNamespace(
            content={
                "output": {
                    "macos_receipt": receipts[
                        "non_owner" if task["step_id"] == "probe" else "owner"
                    ],
                    "observation": observations[task["step_id"]],
                }
            }
        ),
    )
    monkeypatch.setattr(
        composition,
        "_terminal_events",
        lambda *args: (
            events,
            terminals,
            dispatches,
            {
                ("workspace_reserved", "attempt-1"): proofs["reserve"],
                ("workspace_pre_close", "task-close"): proofs["pre_close"],
                ("workspace_post_close", "task-close"): proofs["post_close"],
            },
        ),
    )
    objective = {"established": True, "checks": {"fake_authenticated_join": True}}
    monkeypatch.setattr(composition.macos_pack, "objective_result", lambda *args: objective)
    monkeypatch.setitem(
        sys.modules,
        "bluefire.product_store_macos_settlement",
        SimpleNamespace(receipt=lambda *args: settlement),
    )
    run = {
        "run_id": "run-1",
        "steps": [
            {"step_id": "probe", "artifacts": {"probe": artifacts["probe"]}},
            {"step_id": "owner", "artifacts": {"verification": artifacts["owner"]}},
            {
                "step_id": "close",
                "artifacts": {
                    "closure": {
                        "type": method.CLOSURE_TYPE,
                        "closure_digest": content_hash(closure),
                        "attempt_closure": closure,
                    }
                },
            },
        ],
    }

    result = composition.verified_result(
        SimpleNamespace(store=store, clock=lambda: 3000),
        {
            "lease": lease,
            "compiled": {"macos_file_access": dependency},
            "tasks": list(tasks.values()),
        },
        run,
        [],
        [],
    )

    assert result["objective"] == objective
    assert "objective_result" not in result
    assert result["macos_file_access_result"]["request_closure"] == "verified_closed"
    assert result["cleanup"]["whole_enrollment"] is False
