from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.job_runtime import (
    JobContext,
    JobQueueFull,
    JobResult,
    JobRuntimeClosed,
    JobState,
    RunJobController,
)
from bluefire.product_store import ProductStore


class RecordingStore(ProductStore):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.transition_states: list[str] = []

    def transition_job(
        self,
        job_id: str,
        state: str,
        *,
        progress: Mapping[str, Any] | None = None,
        result_ref: str | None = None,
        error: Mapping[str, Any] | None = None,
        completion_confirmed: bool = False,
    ) -> Mapping[str, Any]:
        snapshot = super().transition_job(
            job_id,
            state,
            progress=progress,
            result_ref=result_ref,
            error=error,
            completion_confirmed=completion_confirmed,
        )
        self.transition_states.append(state)
        return snapshot


def _job_id(snapshot: Mapping[str, Any]) -> str:
    return str(snapshot["job_id"])


def test_job_persists_lifecycle_progress_and_result(tmp_path: Path) -> None:
    store = RecordingStore(tmp_path / "bluefire.db")

    def execute(context: JobContext, request: Mapping[str, Any]) -> JobResult:
        assert request == {"scenario_id": "scenario.example.v1"}
        context.report_progress({"completed_steps": 1, "total_steps": 2})
        return JobResult(
            result_ref="run-example-01",
            progress={"completed_steps": 2, "total_steps": 2},
        )

    with RunJobController(store, execute, max_workers=1) as controller:
        queued = controller.submit(
            "scenario.run",
            {"scenario_id": "scenario.example.v1"},
        )
        completed = controller.wait(_job_id(queued), timeout=2)

    assert completed["state"] == JobState.COMPLETED.value
    assert completed["result_ref"] == "run-example-01"
    assert completed["progress"] == {
        "completed_steps": 2,
        "phase": "completed",
        "total_steps": 2,
    }
    assert store.transition_states[0] == JobState.PLANNING.value
    assert JobState.RUNNING.value in store.transition_states
    assert store.transition_states[-1] == JobState.COMPLETED.value
    assert ProductStore(tmp_path / "bluefire.db").get_job(_job_id(queued)) == completed


def test_approval_gate_blocks_callback_until_resumed(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    invoked = threading.Event()

    def execute(context: JobContext, request: Mapping[str, Any]) -> str:
        invoked.set()
        context.checkpoint({"approved_execution": True})
        return "run-approved"

    with RunJobController(store, execute, max_workers=1) as controller:
        queued = controller.submit("scenario.run", {"mode": "execute"}, requires_approval=True)
        job_id = _job_id(queued)
        awaiting = controller.wait_for_state(
            job_id,
            {JobState.AWAITING_APPROVAL},
            timeout=2,
        )

        assert awaiting["progress"]["phase"] == "awaiting_approval"
        assert not invoked.is_set()

        running = controller.approve(job_id, approval_ref="approval-example")
        assert running["state"] == JobState.RUNNING.value
        completed = controller.wait(job_id, timeout=2)

    assert invoked.is_set()
    assert completed["state"] == JobState.COMPLETED.value
    assert completed["progress"]["approval_ref"] == "approval-example"


def test_callback_created_review_gate_resumes_or_rejects_durably(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    calls: dict[str, int] = {}

    def execute(context: JobContext, request: Mapping[str, Any]) -> JobResult:
        calls[context.job_id] = calls.get(context.job_id, 0) + 1
        if calls[context.job_id] == 1:
            return JobResult(
                result_ref="run-before-review",
                progress={"proposal_record_id": "proposal-review-example"},
                awaiting_approval=True,
            )
        return JobResult(result_ref="run-after-review")

    with RunJobController(store, execute, max_workers=1) as controller:
        resumed_job = controller.submit("scenario.run", {"mode": "simulate"})
        resumed_id = _job_id(resumed_job)
        awaiting = controller.wait_for_state(
            resumed_id,
            {JobState.AWAITING_APPROVAL},
            timeout=2,
        )
        assert awaiting["result_ref"] == "run-before-review"
        controller.approve(resumed_id, approval_ref="proposal-review-example")
        completed = controller.wait(resumed_id, timeout=2)

        rejected_job = controller.submit("scenario.run", {"mode": "simulate"})
        rejected_id = _job_id(rejected_job)
        controller.wait_for_state(
            rejected_id,
            {JobState.AWAITING_APPROVAL},
            timeout=2,
        )
        controller.reject_approval(
            rejected_id,
            decision_ref="proposal-review-rejected",
        )
        rejected = controller.wait(rejected_id, timeout=2)

    assert completed["state"] == "completed"
    assert completed["result_ref"] == "run-after-review"
    assert rejected["state"] == "completed"
    assert rejected["result_ref"] == "run-before-review"
    assert rejected["progress"]["proposal_decision"] == "rejected"


def test_callback_created_review_gate_can_be_cancelled(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")

    def execute(context: JobContext, request: Mapping[str, Any]) -> JobResult:
        return JobResult(result_ref="run-pending", awaiting_approval=True)

    with RunJobController(store, execute, max_workers=1) as controller:
        queued = controller.submit("scenario.run", {"mode": "simulate"})
        job_id = _job_id(queued)
        controller.wait_for_state(job_id, {JobState.AWAITING_APPROVAL}, timeout=2)
        controller.cancel(job_id)
        cancelled = controller.wait(job_id, timeout=2)

    assert cancelled["state"] == "cancelled"


def test_pause_and_resume_are_acknowledged_at_checkpoint(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    started = threading.Event()
    finish = threading.Event()

    def execute(context: JobContext, request: Mapping[str, Any]) -> None:
        started.set()
        tick = 0
        while not finish.is_set():
            tick += 1
            context.checkpoint({"tick": tick})
            context.cooperative_wait(0.05)

    with RunJobController(store, execute, max_workers=1) as controller:
        queued = controller.submit("scenario.run", {"mode": "simulate"})
        job_id = _job_id(queued)
        controller.wait_for_state(job_id, {JobState.RUNNING}, timeout=2)
        assert started.wait(1)

        requested = controller.pause(job_id)
        assert requested["state"] == JobState.RUNNING.value
        paused = controller.wait_for_state(job_id, {JobState.PAUSED}, timeout=2)
        paused_tick = int(paused["progress"]["tick"])

        resumed = controller.resume(job_id)
        assert resumed["state"] == JobState.RUNNING.value
        finish.set()
        completed = controller.wait(job_id, timeout=2)

    assert completed["state"] == JobState.COMPLETED.value
    assert int(completed["progress"]["tick"]) >= paused_tick


def test_running_cancellation_is_cooperative_and_durable(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    started = threading.Event()
    callback_exited = threading.Event()

    def execute(context: JobContext, request: Mapping[str, Any]) -> None:
        started.set()
        try:
            while True:
                context.cooperative_wait(1)
        finally:
            callback_exited.set()

    with RunJobController(store, execute, max_workers=1) as controller:
        queued = controller.submit("scenario.run", {"mode": "execute"})
        job_id = _job_id(queued)
        controller.wait_for_state(job_id, {JobState.RUNNING}, timeout=2)
        assert started.wait(1)

        cancelling = controller.cancel(job_id)
        assert cancelling["state"] == JobState.CANCELLING.value
        cancelled = controller.wait(job_id, timeout=2)

    assert cancelled["state"] == JobState.CANCELLED.value
    assert callback_exited.is_set()


def test_running_cancellation_sets_shared_external_signal(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    signal_observed = threading.Event()

    def execute(context: JobContext, request: Mapping[str, Any]) -> None:
        assert not context.cancellation_event.is_set()
        assert context.cancellation_event.wait(2)
        signal_observed.set()
        context.checkpoint()

    with RunJobController(store, execute, max_workers=1) as controller:
        queued = controller.submit("scenario.run", {"mode": "execute"})
        job_id = _job_id(queued)
        controller.wait_for_state(job_id, {JobState.RUNNING}, timeout=2)
        assert controller.cancel(job_id)["state"] == JobState.CANCELLING.value
        cancelled = controller.wait(job_id, timeout=2)

    assert signal_observed.is_set()
    assert cancelled["state"] == JobState.CANCELLED.value


def test_durably_confirmed_completion_wins_cancellation_race(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    effect_completed = threading.Event()
    return_result = threading.Event()

    def execute(context: JobContext, request: Mapping[str, Any]) -> JobResult:
        effect_completed.set()
        assert return_result.wait(2)
        return JobResult(
            result_ref="run-confirmed",
            progress={"effect_state": "completed"},
            completion_confirmed=True,
        )

    with RunJobController(store, execute, max_workers=1) as controller:
        queued = controller.submit("scenario.run", {"mode": "execute"})
        job_id = _job_id(queued)
        controller.wait_for_state(job_id, {JobState.RUNNING}, timeout=2)
        assert effect_completed.wait(1)
        assert controller.cancel(job_id)["state"] == JobState.CANCELLING.value
        return_result.set()
        completed = controller.wait(job_id, timeout=2)

    assert completed["state"] == JobState.COMPLETED.value
    assert completed["result_ref"] == "run-confirmed"
    assert completed["progress"] == {
        "effect_state": "completed",
        "phase": JobState.COMPLETED.value,
    }


def test_queued_cancellation_never_invokes_callback(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    release_first = threading.Event()
    second_invoked = threading.Event()

    def execute(context: JobContext, request: Mapping[str, Any]) -> str:
        if request["ordinal"] == 1:
            while not release_first.is_set():
                context.cooperative_wait(0.1)
        else:
            second_invoked.set()
        return f"run-{request['ordinal']}"

    with RunJobController(
        store,
        execute,
        max_workers=1,
        max_pending_jobs=2,
    ) as controller:
        first = controller.submit("scenario.run", {"ordinal": 1})
        controller.wait_for_state(_job_id(first), {JobState.RUNNING}, timeout=2)
        second = controller.submit("scenario.run", {"ordinal": 2})
        cancelled = controller.cancel(_job_id(second))

        assert cancelled["state"] == JobState.CANCELLED.value
        release_first.set()
        assert controller.wait(_job_id(first), timeout=2)["state"] == "completed"

    assert not second_invoked.is_set()


def test_callback_failure_is_sanitized_and_persisted(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")

    def execute(context: JobContext, request: Mapping[str, Any]) -> None:
        raise RuntimeError("credential-shaped-sensitive-detail")

    with RunJobController(store, execute, max_workers=1) as controller:
        queued = controller.submit("scenario.run", {"mode": "simulate"})
        failed = controller.wait(_job_id(queued), timeout=2)

    assert failed["state"] == JobState.FAILED.value
    assert failed["error"] == {
        "code": "execution_callback_failed",
        "exception_type": "RuntimeError",
        "message": "execution callback failed",
    }
    assert "sensitive" not in str(failed)


def test_recovery_marks_previous_in_flight_job_interrupted(tmp_path: Path) -> None:
    database = tmp_path / "bluefire.db"
    first_process = ProductStore(database)
    job = first_process.create_job("scenario.run", {"mode": "execute"})
    job_id = _job_id(job)
    first_process.transition_job(job_id, "planning")
    first_process.transition_job(job_id, "running", progress={"completed_steps": 3})

    restarted_store = ProductStore(database)
    with RunJobController(restarted_store, max_workers=1) as controller:
        assert controller.recovered_jobs == 1
        recovered = controller.snapshot(job_id)

    assert recovered["state"] == JobState.INTERRUPTED.value
    assert recovered["progress"] == {"completed_steps": 3}


def test_capacity_is_bounded_and_shutdown_joins_workers(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    entered = threading.Event()
    thread_prefix = "bluefire-job-shutdown-test"

    def execute(context: JobContext, request: Mapping[str, Any]) -> None:
        entered.set()
        while True:
            context.cooperative_wait(1)

    controller = RunJobController(
        store,
        execute,
        max_workers=1,
        max_pending_jobs=1,
        thread_name_prefix=thread_prefix,
    )
    queued = controller.submit("scenario.run", {"ordinal": 1})
    controller.wait_for_state(_job_id(queued), {JobState.RUNNING}, timeout=2)
    assert entered.wait(1)

    with pytest.raises(JobQueueFull, match="capacity"):
        controller.submit("scenario.run", {"ordinal": 2})

    controller.shutdown()

    assert controller.snapshot(_job_id(queued))["state"] == JobState.CANCELLED.value
    assert not any(
        thread.name.startswith(thread_prefix) and thread.is_alive()
        for thread in threading.enumerate()
    )
    with pytest.raises(JobRuntimeClosed, match="shutting down"):
        controller.submit("scenario.run", {"ordinal": 3})
