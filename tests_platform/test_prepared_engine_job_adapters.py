from __future__ import annotations

from typing import Any, Mapping, cast

import pytest

from bluefire.engine_controller_jobs import EngineControllerJobError, EngineControllerJobs
from bluefire.engine_experiment_jobs import EngineExperimentJobError, EngineExperimentJobs
from bluefire.job_runtime import JobQueueFull
from bluefire.util import content_hash

SUBMISSION_ID = "11111111-1111-4111-8111-111111111111"
JOB_ID = "job-" + SUBMISSION_ID.replace("-", "")
DIGEST = "sha256:" + "1" * 64


class _NoEffects:
    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"unexpected authority or execution access: {name}")


class _Gate:
    def __init__(self, *, full: bool = False) -> None:
        self.calls: list[dict[str, Any]] = []
        self.full = full

    def submit(self, kind: str, request: Mapping[str, Any], **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append({"kind": kind, "request": dict(request), **kwargs})
        if self.full:
            raise JobQueueFull("full")
        assert kwargs["callback"] is not None
        job, _created = kwargs["submission_factory"]()
        return cast(Mapping[str, Any], job)


def _engine_request() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-attempt-job.v1",
        "experiment_id": "experiment-" + "1" * 32,
        "attempt_id": "engine-attempt-" + "2" * 32,
        "binding_digest": DIGEST,
        "delegation_digest": DIGEST,
        "execution_approval_digest": DIGEST,
        "execution_approval_id": "approval-" + "3" * 32,
    }


def _defense_request() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-defense-operation-job.v1",
        "experiment_id": "experiment-" + "1" * 32,
        "experiment_revision": 1,
        "experiment_digest": DIGEST,
        "change_id": "defense-change-" + "4" * 32,
        "change_digest": DIGEST,
        "operation": "apply",
        "originating_job_id": None,
        "originating_operation_receipt_digest": None,
    }


def _check_request() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-controller-check-job.v1",
        "experiment_id": "experiment-" + "1" * 32,
        "experiment_revision": 1,
        "experiment_digest": DIGEST,
        "check_id": "controller-check-" + "4" * 32,
        "run_id": "run-20261104T120000Z-" + "5" * 16,
        "role": "retained_reproducer",
        "performer": "bluefire.controller",
        "mechanism_ref": DIGEST,
        "target_snapshot_ref": DIGEST,
        "input_digest": DIGEST,
        "reserved_at": "2026-11-04T12:00:00Z",
    }


def _engine(gate: _Gate, *, available: bool = True) -> EngineExperimentJobs:
    return EngineExperimentJobs(
        controller=gate,
        repository=cast(Any, _NoEffects()),
        runtime=cast(Any, _NoEffects()) if available else None,
        clock=lambda: "2026-11-04T12:00:00Z",
    )


def _controller(gate: _Gate, *, available: bool = True) -> EngineControllerJobs:
    return EngineControllerJobs(
        controller=gate,
        repository=cast(Any, _NoEffects()),
        defense_executor=cast(Any, _NoEffects()) if available else None,
        check_executor=cast(Any, _NoEffects()) if available else None,
        clock=lambda: "2026-11-04T12:00:00Z",
    )


@pytest.mark.parametrize(
    ("adapter", "request_factory", "kind"),
    [
        (_engine, _engine_request, "engine-attempt"),
        (_controller, _defense_request, "engine-controller-operation"),
        (_controller, _check_request, "engine-controller-check"),
    ],
)
def test_prepared_adapter_uses_one_existing_gate_and_exact_inner_intent(
    adapter: Any, request_factory: Any, kind: str
) -> None:
    gate = _Gate()
    jobs = adapter(gate)
    request = request_factory()
    intent = content_hash(request)
    accepted = {"job_id": JOB_ID, "kind": kind, "state": "queued"}
    factory_calls = []

    def reserve():
        factory_calls.append(True)
        return accepted, True

    assert (
        jobs.submit_prepared(
            request=request,
            submission_id=SUBMISSION_ID,
            intent_digest=intent,
            submission_factory=reserve,
        )
        == accepted
    )
    assert factory_calls == [True]
    assert len(gate.calls) == 1
    assert gate.calls[0]["kind"] == kind
    assert gate.calls[0]["request"] == request
    assert gate.calls[0]["intent_digest"] == intent
    assert gate.calls[0]["submission_id"] == SUBMISSION_ID
    assert gate.calls[0].get("requires_approval", False) is False


@pytest.mark.parametrize(
    ("adapter", "request_factory", "error"),
    [
        (_engine, _engine_request, EngineExperimentJobError),
        (_controller, _defense_request, EngineControllerJobError),
        (_controller, _check_request, EngineControllerJobError),
    ],
)
def test_unavailable_runtime_never_calls_gate_or_acceptance(
    adapter: Any, request_factory: Any, error: Any
) -> None:
    gate = _Gate()
    jobs = adapter(gate, available=False)
    request = request_factory()
    with pytest.raises(error, match="unavailable"):
        jobs.submit_prepared(
            request=request,
            submission_id=SUBMISSION_ID,
            intent_digest=content_hash(request),
            submission_factory=lambda: pytest.fail("approval advanced without runtime"),
        )
    assert gate.calls == []


@pytest.mark.parametrize(
    ("adapter", "request_factory", "error"),
    [
        (_engine, _engine_request, EngineExperimentJobError),
        (_controller, _defense_request, EngineControllerJobError),
        (_controller, _check_request, EngineControllerJobError),
    ],
)
@pytest.mark.parametrize("mutation", ["extra", "missing", "wrapper", "digest", "submission"])
def test_prepared_adapter_refuses_changed_request_before_gate(
    adapter: Any, request_factory: Any, error: Any, mutation: str
) -> None:
    gate = _Gate()
    jobs = adapter(gate)
    request = request_factory()
    intent = content_hash(request)
    submission = SUBMISSION_ID
    if mutation == "extra":
        request["approved_by"] = "browser"
    elif mutation == "missing":
        del request["experiment_id"]
    elif mutation == "wrapper":
        request["_submission"] = {
            "schema_version": "bluefire.job-submission.v1",
            "submission_id": submission,
            "intent_digest": intent,
        }
    elif mutation == "digest":
        intent = "sha256:" + "9" * 64
    elif mutation == "submission":
        submission = SUBMISSION_ID.replace("1", "A")
    with pytest.raises(error):
        jobs.submit_prepared(
            request=request,
            submission_id=submission,
            intent_digest=intent,
            submission_factory=lambda: pytest.fail("invalid request reached acceptance"),
        )
    assert gate.calls == []


@pytest.mark.parametrize("operation", ["reconcile_application", "reconcile_rollback"])
def test_prepared_controller_reconciliation_remains_unavailable(operation: str) -> None:
    gate = _Gate()
    jobs = _controller(gate)
    request = {**_defense_request(), "operation": operation}
    with pytest.raises(EngineControllerJobError, match="reconciliation is unavailable"):
        jobs.submit_prepared(
            request=request,
            submission_id=SUBMISSION_ID,
            intent_digest=content_hash(request),
            submission_factory=lambda: pytest.fail("reconciliation reached acceptance"),
        )
    assert gate.calls == []


@pytest.mark.parametrize(
    ("adapter", "request_factory"),
    [(_engine, _engine_request), (_controller, _defense_request), (_controller, _check_request)],
)
def test_capacity_gate_refusal_never_runs_acceptance(adapter: Any, request_factory: Any) -> None:
    gate = _Gate(full=True)
    jobs = adapter(gate)
    request = request_factory()
    with pytest.raises(JobQueueFull):
        jobs.submit_prepared(
            request=request,
            submission_id=SUBMISSION_ID,
            intent_digest=content_hash(request),
            submission_factory=lambda: pytest.fail("capacity refusal advanced approval"),
        )
    assert len(gate.calls) == 1
