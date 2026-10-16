"""Pure routing tests for the Mac composition job integration."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from bluefire import (
    composition_file_access,
    composition_jobs,
    composition_macos_file_access,
    macos_file_access_peer,
)
from bluefire.util import content_hash


class _Store:
    def __init__(self, progress):
        self.progress = progress

    def get_job(self, job_id):
        return {"progress": self.progress}


def test_settlement_routes_mac_dependency_to_mac_receipt_path(monkeypatch):
    jobs = object.__new__(composition_jobs.CompositionJobs)
    jobs.store = _Store({"macos_file_access_dependency": {"attempt_id": "attempt-1"}})
    calls = []
    monkeypatch.setattr(
        composition_macos_file_access,
        "settle",
        lambda *args: calls.append(("macos", args)),
    )
    monkeypatch.setattr(
        composition_file_access,
        "settle",
        lambda *args: calls.append(("linux", args)),
    )
    marker = {"attempt_id": "attempt-1"}
    lease = {"lease_digest": "sha256:lease"}

    jobs._settle_attempt(marker, "job-1", lease, {"run_id": "run-1"}, None)

    assert len(calls) == 1
    assert calls[0][0] == "macos"
    assert calls[0][1][1:4] == (marker, "job-1", lease)


def test_verified_result_routes_compiled_mac_pack_to_mac_join(monkeypatch):
    jobs = object.__new__(composition_jobs.CompositionJobs)
    jobs.store = _Store({})
    jobs.service = SimpleNamespace(detection_lab=object())
    scenario = {"steps": []}
    plan = {"autonomy": "off"}
    verified_claim = {"grant_id": "grant-1"}
    run = {
        "scenario": scenario,
        "mode": "execute",
        "plan": plan,
        "policy": {"grant_attempt": verified_claim},
    }
    attempt = {
        "state": "settled",
        "lease": {
            "job_id": "job-1",
            "run_id": "run-1",
            "plan_digest": content_hash(plan),
        },
        "compiled": {"scenario": scenario, "macos_file_access": {}},
        "claim": {"document": {}, "document_digest": "sha256:claim"},
    }
    calls = []
    monkeypatch.setattr(
        composition_jobs,
        "_source",
        lambda lab, run_id: (run, ["executed-records"], ["observed-records"]),
    )
    monkeypatch.setattr(
        composition_jobs,
        "_verified_grant_attempt",
        lambda document, *, expected_document_digest: SimpleNamespace(
            to_dict=lambda: verified_claim
        ),
    )
    monkeypatch.setattr(
        composition_macos_file_access,
        "verified_result",
        lambda *args: calls.append(("macos", args)) or {"macos_file_access_result": {}},
    )
    monkeypatch.setattr(
        composition_file_access,
        "verified_result",
        lambda *args: calls.append(("linux", args)) or {},
    )

    result = jobs._verified_result(attempt)

    assert result == {"macos_file_access_result": {}}
    assert len(calls) == 1
    assert calls[0][0] == "macos"
    assert calls[0][1][1] is attempt
    assert calls[0][1][2] is run


def test_mac_proposal_context_uses_the_fixed_proposal_without_receiver_context(monkeypatch):
    jobs = object.__new__(composition_jobs.CompositionJobs)
    grant = {"grant_id": "grant-1", "objective": {"question": "Mac only"}, "snapshot": {}}
    facts = {"facts": [], "facts_digest": "sha256:" + "f" * 64}
    scenario = {"id": "fixed-mac-scenario"}
    checked = []
    jobs.clock = lambda: 2000
    jobs._owner = lambda owner_id: owner_id
    jobs._current = lambda owner: (grant, {})
    jobs._facts = lambda document, prior: facts
    jobs.validate_proposal = lambda owner, proposal: checked.append((owner, proposal)) or {
        "scenario": scenario
    }
    monkeypatch.setattr(composition_jobs, "validate_facts", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        composition_jobs, "grant_pack", lambda document: composition_jobs.MACOS_FILE_ACCESS_PACK
    )

    result = jobs.proposal_context("owner-1")

    initial = composition_jobs.capability_macos_file_access.initial_proposal()
    assert checked == [("owner-1", initial)]
    assert result == {
        "schema_version": "bluefire.composition-proposal-context.v1",
        "grant_id": "grant-1",
        "objective": grant["objective"],
        "snapshot": grant["snapshot"],
        "facts": facts,
        "initial_proposal": initial,
        "initial_scenario": scenario,
    }


@pytest.mark.parametrize("allow_exhausted", [False, True])
def test_established_mac_objective_closes_business_before_grant_lookup(allow_exhausted):
    jobs = object.__new__(composition_jobs.CompositionJobs)
    attempt = {"compiled": {"macos_file_access": {}}}
    verified = {"macos_file_access_result": {}, "objective": {"established": True}}
    checked = []
    jobs._children = lambda owner_id: [
        {
            "progress": {"settlement": "settled", "verified_result": verified},
            "request": {"composition_attempt": {"attempt_id": "attempt-1"}},
        }
    ]
    jobs.store = SimpleNamespace(
        get_capability_attempt=lambda attempt_id: attempt,
        get_capability_grant=lambda *args, **kwargs: pytest.fail("business gate did not close"),
    )
    jobs._verified_result = lambda value: checked.append(value) or verified
    owner = {
        "job_id": "owner-1",
        "state": "completed",
        "progress": {"admission": {"accepted": True, "problem": None}},
    }

    with pytest.raises(composition_jobs.ProductStoreError, match="objective is established"):
        jobs._current(owner, allow_exhausted=allow_exhausted)

    assert checked == [attempt]


@pytest.mark.parametrize("failure", ["run", "monitor", "publish", "settle", "index"])
def test_mac_guard_is_released_even_when_final_reporting_fails(monkeypatch, failure):
    released = []

    def fail():
        raise RuntimeError("injected " + failure)

    class Event:
        stopped = False

        def set(self):
            self.stopped = True

        def is_set(self):
            return self.stopped

    class Thread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            pass

        def join(self, **kwargs):
            pass

        def is_alive(self):
            return failure == "monitor"

    current = {
        "sandbox": "fake-original-sandbox",
        "current_environment": {},
        "profile": "fake-profile",
        "collector_runtime": None,
        "collector_ids": (),
        "runner_readiness": {},
        "run_intent": {"target_scope": {}},
    }
    jobs = object.__new__(composition_jobs.CompositionJobs)
    jobs.clock = lambda: 2000
    jobs.store = SimpleNamespace(
        start_capability_preparation=lambda *args, **kwargs: None,
        release_macos_attempt_workspace=lambda attempt_id: released.append(attempt_id),
    )
    jobs.service = SimpleNamespace(
        _index_run=lambda value: fail() if failure == "index" else None,
    )
    jobs._owner = lambda owner_id: owner_id
    jobs._current = lambda *args, **kwargs: ({}, current)
    jobs._publish = lambda *args: fail() if failure == "publish" else None
    jobs._settle_attempt = lambda *args: fail() if failure == "settle" else None
    jobs._orchestrator = lambda *args, **kwargs: SimpleNamespace(
        run=lambda *args, **kwargs: fail() if failure == "run" else {"run_id": "run-1"}
    )
    monkeypatch.setattr(composition_jobs, "threading", SimpleNamespace(Event=Event, Thread=Thread))
    monkeypatch.setattr(macos_file_access_peer, "darwin_clock_ns", lambda: 2000000000)
    monkeypatch.setattr(
        composition_jobs, "_verified_grant_attempt", lambda *args, **kwargs: object()
    )
    monkeypatch.setattr(
        composition_jobs, "grant_pack", lambda grant: composition_jobs.MACOS_FILE_ACCESS_PACK
    )
    monkeypatch.setattr(composition_macos_file_access, "prepare", lambda *args: None)
    monkeypatch.setattr(
        composition_macos_file_access, "create_workspace", lambda *args: "fake-owned-workspace"
    )
    ctx = SimpleNamespace(job_id="job-1", cancellation_event=Event(), checkpoint=lambda: None)

    with pytest.raises((RuntimeError, composition_jobs.ProductStoreError)):
        jobs._run_attempt(
            ctx,
            {"attempt_id": "attempt-1", "parent_job_id": "owner-1", "run_id": "run-1"},
            {"action_implementations": {}},
            {},
            current,
            object(),
            {},
            {"created_at_ms": 1000, "business_expires_at_ms": 9000},
            {"document": {}, "document_digest": "unused-fake"},
        )

    assert released == ["attempt-1"]
