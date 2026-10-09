"""Deterministic original-task recovery; no native process or worker is launched."""

import hashlib
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import file_access_context, file_access_execution
from bluefire import file_access_recovery as recovery
from bluefire.adaptive_dispatch import operation_identity
from bluefire.evidence import SandboxObserver
from bluefire.file_access_control import FileAccessControl
from bluefire.file_access_reconciliation import reconcile
from bluefire.product_store_errors import ProductStoreError
from bluefire.runner_client import RunnerTransportError
from bluefire.runner_contracts import build_runner_profile
from bluefire.util import content_hash
from tests_platform.test_file_access_control import claim
from tests_platform.test_file_access_control import operation as operation


@pytest.fixture
def interrupted(operation, monkeypatch):
    store, job_id = operation.store, operation.job["job_id"]
    store.prepare_file_access_operation(job_id, operation.prepared)
    claim(operation)
    task = store.file_access_operation_records(job_id)["tasks"][0]["task"]
    root = Path(operation.prepared["roots"]["retained"])
    (root / "fixtures").mkdir()
    payload = b'{"synthetic":true}\n' * 8
    (root / "fixtures/input.jsonl").write_bytes(payload)
    sha = hashlib.sha256(payload).hexdigest()
    receipt = {
        "schema_version": "bluefire.receipt/v1",
        "receipt_id": "a" * 64,
        "request_hash": task["request_hash"],
        "action_id": task["manifest"]["action_id"],
        "runner_profile_id": task["runner_profile"]["profile_id"],
        "workspace_id": "b" * 64,
        "created_at": "1970-01-01T00:00:02Z",
        "paths": [
            {
                "relative_path": "fixtures/input.jsonl",
                "kind": "file",
                "sha256": sha,
                "size": len(payload),
            }
        ],
    }
    snapshot = {"documents": {receipt["receipt_id"]: receipt}, "committed": [receipt["receipt_id"]]}
    manifest = task["manifest"]
    result = {
        "schema_version": "bluefire.runner-result.v1",
        **{
            key: manifest[key]
            for key in (
                "request_id",
                "run_id",
                "step_id",
                "behavior_id",
                "action_id",
                "runner_id",
                "runner_profile_id",
                "request_hash",
                "policy_digest",
                "platform",
            )
        },
        "status": "success",
        "receipt_ids": [receipt["receipt_id"]],
        "output": {
            "artifact": "fixtures/input.jsonl",
            "sha256": sha,
            "size": len(payload),
            "template": "telemetry-seed",
            "record_count": 8,
            "format": "jsonl",
        },
    }
    calls = []

    def recover(task_id, request_hash):
        calls.append((task_id, request_hash))
        return {
            "state": "completed",
            "original_task_id": task_id,
            "original_request_hash": request_hash,
            "result": deepcopy(result),
        }

    def discover(root, *, _documents=None, require_commit=False, **kwargs):
        if _documents is not None:
            _documents.update(deepcopy(snapshot["documents"]))
        return tuple(snapshot["committed"] if require_commit else snapshot["documents"])

    monkeypatch.setattr(operation.engine, "_discover_runner_receipts", discover)
    control = FileAccessControl(SimpleNamespace(product_store=store), clock=lambda: 3000)
    enrolled = {
        "document": operation.enrollment,
        "document_digest": content_hash(operation.enrollment),
    }
    current = {
        "profile": operation.profile,
        "enrollment": enrolled,
        "runner": SimpleNamespace(recover=recover),
        "implementation_digests": operation.context["implementations"],
    }
    monkeypatch.setattr(control, "_enrollment", lambda: enrolled)
    monkeypatch.setattr(file_access_context, "execution", lambda *args: current)
    monkeypatch.setattr(file_access_execution, "_engine", lambda *args: operation.engine)
    store.finish_file_access_operation(
        job_id, outcome={"state": "unknown", "evidence_digest": content_hash("interrupted")}
    )
    store.transition_job(
        job_id,
        "failed",
        error={"code": "authored_interruption", "message": "Authored lost response"},
    )
    return SimpleNamespace(
        operation=operation,
        task=task,
        root=root,
        result=result,
        snapshot=snapshot,
        control=control,
        current=current,
        calls=calls,
        discover=discover,
    )


def request_for(interrupted):
    saved = interrupted.operation.store.file_access_operation_records(
        interrupted.operation.job["job_id"]
    )
    return {
        "submission_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "expected_outcome_digest": saved["outcome_digest"],
        "reviewed_by": "Authored operator",
    }


def test_seed_only_recovery_is_append_only_reset_only(interrupted):
    operation = interrupted.operation
    response = reconcile(interrupted.control, operation.job["job_id"], request_for(interrupted))
    assert response["job"]["state"] == "failed"
    assert response["reconciliation"]["state"] == "settled_partial"
    assert response["control"]["status"] == "recovery_required"
    assert response["control"]["allowed_operations"] == ["reset"]
    assert response["control"]["resource"] is None
    assert response["control"]["baseline"] is None
    assert "verified_observation" not in response["job"]["progress"]
    assert interrupted.calls == [
        (interrupted.task["task_id"], interrupted.task["transport_request_hash"])
    ]
    saved = operation.store.file_access_operation_records(operation.job["job_id"])
    assert saved["tasks"][0]["terminal"]["receipt_snapshot"] == interrupted.snapshot
    retained = operation.store.get_file_access_control(operation.job["job_id"])["document"]
    assert file_access_execution.recipe("reset", retained)[0]["step_id"] == "reset_retained"
    with operation.store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM file_access_outcomes").fetchone()[0] == 2
    again = reconcile(
        interrupted.control,
        operation.job["job_id"],
        response["reconciliation_receipt"]["submitted_request"],
    )
    assert again == response
    assert len(interrupted.calls) == 1


@pytest.mark.parametrize(
    "change", ["task", "hash", "result", "receipt", "workspace", "source_bytes", "implementation"]
)
def test_changed_original_evidence_remains_unknown(interrupted, monkeypatch, change):
    original = interrupted.current["runner"].recover
    if change in {"task", "hash", "result"}:

        def altered(*args):
            value = original(*args)
            if change == "task":
                value["original_task_id"] = "execute-" + "f" * 64
            elif change == "hash":
                value["original_request_hash"] = interrupted.task["request_hash"]
            else:
                value["result"]["policy_digest"] = content_hash("other profile")
            return value

        interrupted.current["runner"].recover = altered
    elif change == "receipt":
        interrupted.snapshot["documents"]["a" * 64]["request_hash"] = content_hash(
            "foreign request"
        )
    elif change == "workspace":
        interrupted.snapshot["documents"]["a" * 64]["runner_profile_id"] = "foreign.v1"

        def refuse(*args, **kwargs):
            raise RunnerTransportError("foreign profile")

        monkeypatch.setattr(interrupted.operation.engine, "_discover_runner_receipts", refuse)
    elif change == "implementation":
        interrupted.current["implementation_digests"] = {"native": content_hash("changed binary")}
    else:
        (interrupted.root / "fixtures/input.jsonl").write_bytes(b"replaced data")
    response = reconcile(
        interrupted.control, interrupted.operation.job["job_id"], request_for(interrupted)
    )
    assert response["reconciliation"]["state"] == "unknown"
    assert response["control"] is None
    assert (
        response["reconciliation_receipt"]["problem"]["code"]
        == "file_access_reconciliation_unresolved"
    )


def test_reset_review_detects_replaced_retained_inventory(interrupted):
    reconcile(interrupted.control, interrupted.operation.job["job_id"], request_for(interrupted))
    control = interrupted.operation.store.get_file_access_control(
        interrupted.operation.job["job_id"]
    )["document"]
    inventory = control["source"]["recovery"]
    assert recovery.validate_inventory(interrupted.operation.engine, inventory) == inventory
    (interrupted.root / "fixtures/input.jsonl").write_bytes(b"replacement")
    with pytest.raises(ProductStoreError):
        recovery.validate_inventory(interrupted.operation.engine, inventory)


@pytest.mark.parametrize("after_outcome", [False, True])
def test_same_reconciliation_resumes_after_interrupted_receipt(
    interrupted, monkeypatch, after_outcome
):
    operation = interrupted.operation
    request = request_for(interrupted)
    if after_outcome:
        original = operation.store.finish_file_access_reconciliation
        monkeypatch.setattr(
            operation.store,
            "finish_file_access_reconciliation",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("authored process exit")),
        )
        with pytest.raises(RuntimeError, match="process exit"):
            reconcile(interrupted.control, operation.job["job_id"], request)
        monkeypatch.setattr(operation.store, "finish_file_access_reconciliation", original)
    else:
        operation.store.begin_file_access_reconciliation(operation.job["job_id"], request)
    assert (
        operation.store.get_file_access_reconciliation(
            operation.job["job_id"], request["submission_id"]
        )["state"]
        == "pending"
    )
    response = reconcile(interrupted.control, operation.job["job_id"], request)
    assert response["reconciliation_receipt"]["state"] == "completed"
    assert response["reconciliation"]["state"] == "settled_partial"
    assert len(interrupted.calls) == 1


def test_missing_original_receipt_does_not_settle_partial(interrupted):
    operation = interrupted.operation
    operation.store.record_file_access_task_terminal(
        interrupted.task["task_id"],
        request_hash=interrupted.task["request_hash"],
        result=interrupted.result,
        receipt_snapshot=deepcopy(interrupted.snapshot),
    )
    interrupted.snapshot["documents"].clear()
    interrupted.snapshot["committed"].clear()
    response = reconcile(interrupted.control, operation.job["job_id"], request_for(interrupted))
    assert response["reconciliation"]["state"] == "unknown"
    assert interrupted.calls == []


def test_public_operation_hides_proof_until_job_terminal(operation):
    control = FileAccessControl(SimpleNamespace(product_store=operation.store))
    control._publish(operation.job["job_id"], {"verified_observation": {"authored": True}})
    assert (
        "verified_observation" not in control.operation(operation.job["job_id"])["job"]["progress"]
    )


def test_cancelled_before_callback_has_durable_no_effect(operation):
    operation.store.transition_job(operation.job["job_id"], "cancelled")
    control = FileAccessControl(SimpleNamespace(product_store=operation.store))
    response = control.operation(operation.job["job_id"])
    assert response["job"]["state"] == "cancelled"
    assert response["reconciliation"]["state"] == "refused_no_effect"


def test_zero_task_unknown_reconciliation_needs_no_runtime(operation):
    operation.store.finish_file_access_operation(
        operation.job["job_id"], outcome={"state": "unknown", "evidence_digest": content_hash([])}
    )
    operation.store.transition_job(operation.job["job_id"], "failed")
    control = FileAccessControl(SimpleNamespace(product_store=operation.store))
    expected = operation.store.file_access_operation_records(operation.job["job_id"])[
        "outcome_digest"
    ]
    response = reconcile(
        control,
        operation.job["job_id"],
        {
            "submission_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "expected_outcome_digest": expected,
            "reviewed_by": "Authored operator",
        },
    )
    assert response["reconciliation"]["state"] == "refused_no_effect"


def test_explicit_partial_reset_uses_existing_single_task_pipeline(interrupted, monkeypatch):
    from bluefire import policy, runner_contracts

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(2, tz or timezone.utc)

    monkeypatch.setattr(policy, "datetime", FixedDatetime)
    monkeypatch.setattr(runner_contracts, "datetime", FixedDatetime)
    operation = interrupted.operation
    reconcile(interrupted.control, operation.job["job_id"], request_for(interrupted))
    prior = operation.store.get_file_access_control(operation.job["job_id"])
    rows = file_access_execution.recipe("reset", prior["document"])
    context = {**operation.context, "control_digest": prior["document_digest"], "recipe": rows}
    body = {key: value for key, value in operation.review.items() if key != "review_digest"}
    body.update(
        operation="reset",
        control_owner_id=operation.job["job_id"],
        control_digest=prior["document_digest"],
        context_digest=content_hash(context),
    )
    review = {**body, "review_digest": content_hash(body)}
    request = {
        **operation.request,
        "submission_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        "review": {"operation": "reset", "control_owner_id": operation.job["job_id"]},
        "review_digest": review["review_digest"],
    }
    job, _ = operation.store.create_file_access_operation(
        request,
        review_document=review,
        review_context=context,
        enrollment_id=operation.enrollment["enrollment_id"],
        now_ms=2000,
    )
    _, plan = file_access_execution._plan(
        operation.engine,
        {"registry": operation.registry, "profile": operation.profile, "control": prior},
        "reset",
    )
    envelope = {
        "schema_version": "bluefire.reviewed-execution.v1",
        "authorization_digest": review["review_digest"],
        "operations": [operation_identity(step) for step in plan.steps],
    }
    profile = build_runner_profile(
        operation.profile,
        sandbox_root=str(interrupted.root),
        filesystem_scope=operation.engine._filesystem_scope(plan),
        reviewed_execution=envelope,
    )
    approval = {
        **operation.prepared["approval"],
        "approval_id": "authored-approval",
        "nonce": "authored-nonce",
    }
    prepared = {
        **operation.prepared,
        "job_id": job["job_id"],
        "run_id": "run-authored-reset",
        "context_digest": review["context_digest"],
        "recipe": rows,
        "plan": plan.to_dict(),
        "source": prior["document"]["source"],
        "prior": prior["document"],
        "revision": 2,
        "profiles": {"retained": profile},
        "approval": approval,
    }
    operation.store.prepare_file_access_operation(job["job_id"], prepared)
    called = []

    def execute_task(manifest, sealed_profile, **kwargs):
        called.append((deepcopy(manifest), deepcopy(sealed_profile)))
        assert manifest["params"] == {"receipt_ids": ["a" * 64]}
        assert sealed_profile["sandbox_root"] == str(interrupted.root)
        assert manifest["action_id"] == "sandbox.cleanup.v1"
        assert (
            operation.store.file_access_operation_records(job["job_id"])["tasks"][0]["terminal"]
            is None
        )
        (interrupted.root / "fixtures/input.jsonl").unlink()
        interrupted.snapshot["documents"].clear()
        interrupted.snapshot["committed"].clear()
        report = {
            "requested_receipts": 1,
            "removed_paths": ["fixtures/input.jsonl"],
            "already_absent_receipts": [],
            "retained_paths": [],
            "errors": [],
            "verification_performed": True,
            "verified_removed_paths": 1,
            "verified_absent_paths": 0,
            "verified_receipts": 1,
        }
        return {
            "schema_version": "bluefire.runner-result.v1",
            **{
                key: manifest[key]
                for key in (
                    "request_id",
                    "run_id",
                    "step_id",
                    "behavior_id",
                    "action_id",
                    "runner_id",
                    "runner_profile_id",
                    "request_hash",
                    "policy_digest",
                    "platform",
                )
            },
            "status": "success",
            "receipt_ids": [],
            "output": report,
            "cleanup": report,
        }

    def before_task(step, inputs, manifest, task_id):
        operation.store.register_file_access_task(
            job["job_id"],
            task_id=task_id,
            step_id=step.step_id,
            manifest=manifest,
            runner_profile=profile,
            now_ms=2000,
            validate_context=lambda: recovery.validate_inventory(
                operation.engine, prepared["source"]["recovery"]
            ),
        )

    def after_task(step, manifest, task_id, result, **kwargs):
        operation.store.record_file_access_task_terminal(
            task_id,
            request_hash=manifest["request_hash"],
            result=result,
            receipt_snapshot=recovery.receipt_snapshot(operation.engine, profile),
        )

    operation.engine.runner = SimpleNamespace(execute_task=execute_task)
    operation.engine.store = SimpleNamespace(root=interrupted.root.parent)
    step = plan.steps[0]
    row, _, _, _ = operation.engine._execute_step(
        run_id=prepared["run_id"],
        step=step,
        bound_inputs={},
        parent_ids=(),
        profile=operation.profile,
        runner_profile=profile,
        observer=SandboxObserver(interrupted.root),
        approved_by=request["reviewed_by"],
        approval_record=approval,
        authorized_target_scope={"scope_refs": ["sandbox.workspace"]},
        receipt_ids=file_access_execution._receipts(step.step_id, {}, prepared["source"]),
        cancel_event=threading.Event(),
        task_lifecycle=SimpleNamespace(before_task=before_task, after_task=after_task),
    )
    assert row["status"] == "success"
    file_access_execution._finish(
        interrupted.control,
        job["job_id"],
        {**request, "review": review},
        prepared,
        interrupted.current,
        operation.engine,
        {step.step_id: row["artifacts"]},
    )
    final = interrupted.control.operation(job["job_id"])
    assert final["reconciliation"]["state"] == "complete"
    assert final["control"]["status"] == "reset"
    assert final["control"]["allowed_operations"] == []
    assert len(called) == 1
