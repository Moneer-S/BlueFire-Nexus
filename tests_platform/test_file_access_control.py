"""Pure retained-control admission and recovery checks; no enrolled worker runs."""

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire.adaptive_dispatch import operation_identity, reviewed_operation
from bluefire.config import load_config
from bluefire.file_access_execution import _plan, plan_step, recipe
from bluefire.orchestrator import Orchestrator
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.registry import load_builtin_registry
from bluefire.runner_adapter import RunnerActionAdapter
from bluefire.runner_client import execution_task_identity
from bluefire.runner_contracts import build_execution_manifest, build_runner_profile, seal_manifest
from bluefire.util import content_hash


@pytest.fixture
def operation(tmp_path):
    store = ProductStore(tmp_path / "control.db")
    registry = load_builtin_registry()
    profile = next(
        p
        for p in load_config(
            Path(__file__).resolve().parents[1] / "config/bluefire.example.yaml"
        ).runner_profiles
        if p.id == "sandbox-execute.v1"
    )
    root = str((tmp_path / "retained").resolve())
    enrollment = {
        "enrollment_id": "file-enrollment-" + "b" * 32,
        "root": {"path": root},
        "expires_at_ms": 1800000,
    }
    enrolled_digest = content_hash(enrollment)
    store.save_file_access_enrollment(enrollment, expected_document_digest=enrolled_digest)
    context = {
        "enrollment_digest": enrolled_digest,
        "profile_digest": content_hash(profile.to_dict()),
        "profile_id": profile.id,
        "implementations": {},
        "control_digest": None,
        "recipe": recipe("create"),
    }
    body = {
        "schema_version": "bluefire.file-access-control-review.v1",
        "operation": "create",
        "control_owner_id": None,
        "context_digest": content_hash(context),
        "enrollment_digest": enrolled_digest,
        "control_digest": None,
        "expires_at_ms": 1800000,
        "effect": "authored test",
    }
    review = {**body, "review_digest": content_hash(body)}
    request = {
        "submission_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "review": {"operation": "create", "control_owner_id": None},
        "review_digest": review["review_digest"],
        "reviewed_by": "Authored operator",
    }
    job, _ = store.create_file_access_operation(
        request,
        review_document=review,
        review_context=context,
        enrollment_id=enrollment["enrollment_id"],
        now_ms=1000,
    )
    engine = Orchestrator(registry, SimpleNamespace())
    _, plan = _plan(engine, {"registry": registry, "profile": profile}, "create")
    envelope = {
        "schema_version": "bluefire.reviewed-execution.v1",
        "authorization_digest": review["review_digest"],
        "operations": [operation_identity(step) for step in plan.steps],
    }
    sealed = build_runner_profile(
        profile,
        sandbox_root=root,
        filesystem_scope=engine._filesystem_scope(plan),
        reviewed_execution=envelope,
    )
    prepared = {
        "schema_version": "bluefire.file-access-operation-preparation.v1",
        "job_id": job["job_id"],
        "run_id": "run-authored-control",
        "context_digest": review["context_digest"],
        "enrollment_digest": enrolled_digest,
        "recipe": recipe("create"),
        "plan": plan.to_dict(),
        "source": None,
        "prior": None,
        "target_binding": None,
        "target_binding_digest": content_hash(None),
        "revision": 1,
        "roots": {"retained": root},
        "profiles": {"retained": sealed},
        "profile_document": profile.to_dict(),
        "approval": {
            "approved_by": request["reviewed_by"],
            "approved_at": "1970-01-01T00:00:01Z",
            "expires_at": "1970-01-01T00:30:00Z",
        },
    }
    return SimpleNamespace(
        store=store,
        job=job,
        request=request,
        review=review,
        context=context,
        enrollment=enrollment,
        prepared=prepared,
        registry=registry,
        engine=engine,
        profile=profile,
    )


def manifest_for(operation, index=0):
    prepared = operation.prepared
    step = plan_step(prepared["plan"]["steps"][index])
    profile = prepared["profiles"]["retained"]
    adapted = RunnerActionAdapter().adapt(step, bound_inputs={}, receipt_ids=[])
    manifest = build_execution_manifest(
        run_id=prepared["run_id"],
        step_id=step.step_id,
        behavior_id=step.behavior_id,
        action=operation.registry.get_action(step.action_id),
        runner_profile=profile,
        params=adapted.params,
        filesystem_scope=adapted.filesystem_scope,
        approval_record=prepared["approval"],
        reviewed_operation=reviewed_operation(step, profile),
        now=datetime.fromtimestamp(2, timezone.utc),
    )
    return manifest, profile


def claim(operation, manifest=None, profile=None):
    if manifest is None:
        manifest, profile = manifest_for(operation)
    task_id, _ = execution_task_identity(manifest, profile)
    operation.store.register_file_access_task(
        operation.job["job_id"],
        task_id=task_id,
        step_id=manifest["step_id"],
        manifest=manifest,
        runner_profile=profile,
        now_ms=2000,
        validate_context=lambda: None,
    )
    return task_id


def test_preparation_and_exact_payload_claim_are_durable(operation):
    operation.store.prepare_file_access_operation(operation.job["job_id"], operation.prepared)
    task_id = claim(operation)
    saved = operation.store.file_access_operation_records(operation.job["job_id"])
    task = saved["tasks"][0]["task"]
    assert saved["preparation"] == operation.prepared
    assert task["task_id"] == task_id
    assert (
        task["transport_request_hash"]
        == execution_task_identity(task["manifest"], task["runner_profile"])[1]
    )
    assert task["transport_request_hash"] != task["request_hash"]


@pytest.mark.parametrize("change", ["recipe", "source", "preimage", "profile", "root", "approval"])
def test_changed_preparation_refuses_atomically(operation, change):
    changed = deepcopy(operation.prepared)
    if change == "recipe":
        changed["recipe"][0]["parameters"]["record_count"] = 9
    elif change == "source":
        changed["source"] = {"fixture": {"path": "other"}}
    elif change == "preimage":
        changed["prior"] = {"revision": 9}
    elif change == "profile":
        changed["profiles"]["retained"]["limits"]["max_files"] += 1
    elif change == "root":
        changed["roots"]["retained"] += "-other"
    else:
        changed["approval"]["approved_by"] = "Another operator"
    with pytest.raises((ProductStoreError, ValueError)):
        operation.store.prepare_file_access_operation(operation.job["job_id"], changed)
    assert (
        operation.store.file_access_operation_records(operation.job["job_id"])["preparation"]
        is None
    )


@pytest.mark.parametrize("change", ["params", "scope", "profile", "approval", "sequence"])
def test_resealed_foreign_task_refuses_before_claim(operation, change):
    operation.store.prepare_file_access_operation(operation.job["job_id"], operation.prepared)
    manifest, profile = manifest_for(operation)
    profile = deepcopy(profile)
    if change == "params":
        manifest["params"]["record_count"] = 9
    elif change == "scope":
        manifest["target_scope"]["filesystem"] = ["other"]
    elif change == "profile":
        profile["sandbox_root"] += "-other"
    elif change == "approval":
        manifest["approval"]["approved_by"] = "Another operator"
    else:
        manifest["step_id"] = "transform"
    with pytest.raises((ProductStoreError, ValueError)):
        claim(operation, seal_manifest(manifest), profile)
    assert operation.store.file_access_operation_records(operation.job["job_id"])["tasks"] == []


def test_stop_wins_before_pre_send_claim(operation):
    operation.store.prepare_file_access_operation(operation.job["job_id"], operation.prepared)
    operation.store.transition_job(operation.job["job_id"], "cancelled")
    with pytest.raises(ProductStoreError, match="no longer admits"):
        claim(operation)
    assert operation.store.file_access_operation_records(operation.job["job_id"])["tasks"] == []


def test_claim_cannot_skip_unresolved_predecessor(operation):
    operation.store.prepare_file_access_operation(operation.job["job_id"], operation.prepared)
    claim(operation)
    with pytest.raises(ProductStoreError):
        claim(operation)


def test_zero_task_preparation_failure_records_no_effect(operation, monkeypatch):
    from bluefire import file_access_execution

    def fail(*args):
        raise ProductStoreError("preparation failed")

    monkeypatch.setattr(file_access_execution, "_execute", fail)
    control = SimpleNamespace(store=operation.store, _publish=lambda *args: None)
    with pytest.raises(ProductStoreError):
        file_access_execution.execute(
            control, SimpleNamespace(job_id=operation.job["job_id"]), operation.request
        )
    assert (
        operation.store.file_access_operation_records(operation.job["job_id"])["outcome"]["state"]
        == "refused_no_effect"
    )
