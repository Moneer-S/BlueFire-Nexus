"""File-only checkpoint fixtures exercise real review and job admission, never runner effects."""

from __future__ import annotations

import uuid
from copy import deepcopy

import pytest

from bluefire.application_errors import APIError
from bluefire.approvals import execution_approval_binding
from bluefire.config import AutonomyLevel
from bluefire.contracts import ExecutionMode
from bluefire.orchestrator import Orchestrator
from bluefire.replay_checkpoint import build_checkpoint
from bluefire.replay_checkpoint_binding import checkpoint_source_binding_hash
from tests_platform.test_replay_checkpoint import _artifacts
from tests_platform.test_replay_jobs import awaiting
from tests_platform.test_replay_preparation import SCOPE, block_effects, forbid
from tests_platform.test_replay_preparation import service as service


def checkpoint_source(service):
    scenario = service._scenario_or_api_error({"scenario_id": "scenario.sandbox.research.chain.v1"})
    profile = service._profile("sandbox-execute.v1", ExecutionMode.EXECUTE)
    provider = service._ai_provider_metadata(AutonomyLevel.OFF, "deterministic-offline.v1")
    _, _, readiness = service._execute_readiness_boundary(profile)
    plan = (
        Orchestrator(service.registry, service.store)
        .planner.compile(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            autonomy=AutonomyLevel.OFF,
            ai_provider=provider,
        )
        .to_dict()
    )
    authority = service._catalog_snapshot.to_dict()
    binding = execution_approval_binding(
        registry=service.registry,
        scenario=scenario,
        plan=plan,
        profile=profile,
        target_scope=SCOPE,
        autonomy=AutonomyLevel.OFF,
        ai_provider=provider,
        runner_readiness=readiness,
        catalog_authority=authority,
    )
    handle = service.store.create_run(
        scenario=scenario.to_dict(),
        plan=plan,
        policy={"approval_binding": binding, "preflight": {"catalog_authority": authority}},
        profile=profile.to_dict(),
    )
    artifacts = _artifacts()
    prefix = [
        {**step, "status": "success", "artifacts": artifacts[step["step_id"]]}
        for step in plan["steps"][:2]
    ]
    checkpoint = build_checkpoint(
        source_run_id=handle.run_id,
        source_binding_hash=checkpoint_source_binding_hash(
            source_run_id=handle.run_id,
            scenario=scenario.to_dict(),
            plan=plan,
            approval_binding=binding,
        ),
        scenario=scenario.to_dict(),
        plan=plan,
        checkpoint_before_step_id="discover_records",
        executed_steps=prefix,
        artifacts=artifacts,
        material_files=[
            {
                "relative_path": "fixtures/transformed.jsonl",
                "kind": "file",
                "sha256": "a" * 64,
                "size_bytes": 24,
                "source_step_id": "transform_fixture",
                "artifact_name": "fixture",
            }
        ],
        source_authority={
            "profile": profile.to_dict(),
            "target_scope": SCOPE,
            "catalog_authority": authority,
            "runner_readiness": readiness,
        },
        source_cleanup={"attempted": True, "success": True, "outstanding_receipt_count": 0},
    )
    service.store.finalize(
        handle.run_id,
        result={
            "status": "completed",
            "mode": "execute",
            "scenario_id": scenario.id,
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "ai_provider": provider,
            "target_scope": SCOPE,
            "replay_checkpoints": [checkpoint],
            "steps": [*prefix, {**plan["steps"][2], "status": "success", "artifacts": {}}],
        },
        evidence=[],
        detections=[],
    )
    return service.store.get_run(handle.run_id)


def request(prepared, submission_id=None):
    return {
        **prepared["replay_request"],
        "preparation_id": prepared["preparation_id"],
        "preparation_context": prepared["preparation_context"],
        "submission_id": submission_id or str(uuid.uuid4()),
    }


def test_checkpoint_preparation_binds_restoration_without_approval_or_effects(service, monkeypatch):
    source = checkpoint_source(service)
    original = deepcopy(source)
    block_effects(service, monkeypatch)
    prepared = service.prepare_replay(
        source["run_id"], {"from_step_id": "discover_records", "target_scope": SCOPE}
    )
    assert prepared["replay_extent"] == prepared["binding"]["replay_extent"] == "from_step"
    restoration = prepared["binding"]["resolution"]["restoration_plan"]
    assert restoration["checkpoint_before_step_id"] == "discover_records"
    assert restoration["prefix_step_ids"] == ["create_fixture", "transform_fixture"]
    assert restoration["plan_hash"] == prepared["lineage"]["restoration_plan_hash"]
    assert restoration["verification"]["require_fresh_approval"] is True
    assert restoration["verification"]["reuse_source_receipts"] is False
    assert service.store.get_run(source["run_id"]) == original
    assert prepared == service.prepare_replay(source["run_id"], prepared["replay_request"])


@pytest.mark.parametrize("change", ["source", "checkpoint", "prefix", "scope", "restoration"])
def test_changed_checkpoint_review_refuses_job_before_approval(service, monkeypatch, change):
    source = checkpoint_source(service)
    prepared = service.prepare_replay(
        source["run_id"], {"from_step_id": "discover_records", "target_scope": SCOPE}
    )
    payload = request(prepared)
    if change in {"source", "checkpoint"}:
        original = service.store.get_run

        def changed(run_id):
            value = deepcopy(original(run_id))
            if change == "source":
                value["source_changed"] = True
            else:
                value["replay_checkpoints"][0]["material_files"][0]["sha256"] = "b" * 64
            return value

        monkeypatch.setattr(service.store, "get_run", changed)
    elif change == "prefix":
        payload["parameter_overrides"] = {"create_fixture": {"record_count": 3}}
    elif change == "scope":
        payload["target_scope"] = {"scope_refs": []}
    else:
        from bluefire import service as service_module

        original = service_module.resolved_restoration_plan

        def changed(*args, **kwargs):
            value = dict(original(*args, **kwargs))
            value["plan_hash"] = "sha256:" + "b" * 64
            return value

        monkeypatch.setattr(service_module, "resolved_restoration_plan", changed)
    block_effects(service, monkeypatch)
    with pytest.raises(APIError):
        service.submit_replay(source["run_id"], payload)


def test_cancelled_checkpoint_submission_keeps_one_identity_and_never_dispatches(
    service, monkeypatch
):
    source = checkpoint_source(service)
    monkeypatch.setattr(service, "_replay_locked", forbid)
    prepared = service.prepare_replay(
        source["run_id"], {"from_step_id": "discover_records", "target_scope": SCOPE}
    )
    payload = request(prepared)
    created = service.submit_replay(source["run_id"], payload)
    job_id = created["job"]["job_id"]
    awaiting(service, job_id)
    # A lost response followed by retry returns the original pending approval.
    again = service.submit_replay(source["run_id"], deepcopy(payload))
    assert again["job"]["job_id"] == job_id
    assert again["approval_request"]["approval_id"] == created["approval_request"]["approval_id"]
    service.cancel_job(job_id)
    assert service.job_controller.wait(job_id, timeout=10)["state"] == "cancelled"
    assert service.submit_replay(source["run_id"], payload)["job"]["job_id"] == job_id
    resolved = service.resolve_replay_submission(source["run_id"], payload)
    assert resolved["outcome"] == "existing" and resolved["job"]["state"] == "cancelled"
    with pytest.raises(APIError):
        service.approve_job(job_id, {"approved_by": "stale"})
    assert len(service.store.list_runs()) == 1


def test_checkpoint_review_matches_final_approval_context(service, monkeypatch):
    source = checkpoint_source(service)
    prepared = service.prepare_replay(
        source["run_id"], {"from_step_id": "discover_records", "target_scope": SCOPE}
    )
    block_effects(service, monkeypatch)

    class ReachedApproval(BaseException):
        pass

    def inspect(**values):
        assert values["context"]["resume_from_step_id"] == "discover_records"
        assert (
            values["context"]["restoration_plan"]
            == prepared["binding"]["resolution"]["restoration_plan"]
        )
        binding = execution_approval_binding(
            registry=values["orchestrator"].registry,
            scenario=values["scenario"],
            plan=prepared["preflight"]["plan"],
            profile=values["profile"],
            target_scope=values["target_scope"],
            autonomy=values["autonomy"],
            ai_provider=values["ai_provider"],
            context=values["context"],
            runner_readiness=values["runner_readiness"],
            catalog_authority=values["orchestrator"].catalog_authority,
        )
        assert binding == prepared["preflight"]["approval_binding"]
        raise ReachedApproval

    monkeypatch.setattr(service, "_bind_and_consume_approval", inspect)
    payload = request(prepared)
    payload.pop("submission_id")
    with pytest.raises(ReachedApproval):
        service.replay(
            source["run_id"],
            {**payload, "approval": {"confirmed": True, "approved_by": "reviewer"}},
        )


@pytest.mark.parametrize("phase", ["approval", "dispatch"])
def test_checkpoint_drift_after_job_creation_never_reaches_effects(service, monkeypatch, phase):
    source = checkpoint_source(service)
    prepared = service.prepare_replay(
        source["run_id"], {"from_step_id": "discover_records", "target_scope": SCOPE}
    )
    created = service.submit_replay(source["run_id"], request(prepared))
    job_id = created["job"]["job_id"]
    awaiting(service, job_id)
    original = service.store.get_run

    def changed(run_id):
        value = deepcopy(original(run_id))
        value["replay_checkpoints"][0]["material_files"][0]["sha256"] = "b" * 64
        return value

    monkeypatch.setattr(service, "_replay_locked", forbid)
    if phase == "approval":
        monkeypatch.setattr(service.store, "get_run", changed)
        with pytest.raises(APIError):
            service.approve_job(job_id, {"approved_by": "reviewer"})
        assert service.job(job_id)["approval_request"]["status"] == "pending"
    else:
        original_execute = service._execute_replay_job

        def change_after_release(*args, **kwargs):
            monkeypatch.setattr(service.store, "get_run", changed)
            return original_execute(*args, **kwargs)

        monkeypatch.setattr(service, "_execute_replay_job", change_after_release)
        service.approve_job(job_id, {"approved_by": "reviewer"})
        assert service.job_controller.wait(job_id, timeout=10)["state"] == "failed"
