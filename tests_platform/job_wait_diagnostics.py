"""Finite timeout evidence from the existing wait frame; no store or lock reads."""

import json
import sys
from contextlib import contextmanager
from itertools import islice

from bluefire.job_runtime import JobState, JobWaitTimeout, RunJobController

STAGES = {
    "graph_parent",
    "graph_child",
    "replay_approval",
    "replay_terminal",
    "assist_rejection_approval",
    "assist_cancellation_approval",
}
STATES = {state.value for state in JobState}
ERROR_CODES = {
    "execution_callback_failed",
    "job_scheduling_failed",
    "run_record_incomplete",
    "replay_record_incomplete",
    "run_cleanup_deferred",
    "replay_cleanup_deferred",
}
ERROR_TYPES = {
    "APIError",
    "ProductStoreError",
    "RunStoreError",
    "AIProviderError",
    "AIProviderCancelled",
    "JobCancelled",
    "JobStateError",
    "AssertionError",
    "OSError",
    "PermissionError",
    "ValueError",
    "KeyError",
    "TypeError",
    "RuntimeError",
}
FUNCTIONS = {
    "wait",
    "join",
    "_worker",
    "run",
    "_run_job",
    "wait_for_state",
    "_checkpoint",
    "_transition",
    "_finish_failed",
    "_plan",
    "_fresh",
    "suggest_plan",
    "_advance",
    "_advance_graph",
    "submit",
    "read",
    "_propose",
    "propose_step_edit",
    "post",
    "propose",
    "_execute_job",
    "_execute_job_inner",
    "_execute_replay_job",
    "_review_replay_job",
    "_replay_catalog_lease",
    "_replay_locked",
    "_resolve_replay_source_locked",
    "_index_run",
    "_simulate_step",
    "create_ai_proposal_review",
    "finalize",
    "validate_bundle",
    "get_run",
    "get_job",
    "_connection",
}


def _label(value, allowed):
    return value if type(value) is str and value in allowed else "unknown"


def _report(timeout, stage):
    evidence = {"stage": _label(stage, STAGES), "last_wait_job": {"available": False}}
    trace = timeout.__traceback__
    for _ in range(32):
        if trace is None:
            break
        if trace.tb_frame.f_code is RunJobController.wait_for_state.__code__:
            snapshot = trace.tb_frame.f_locals.get("snapshot")
            if type(snapshot) is dict:
                progress = snapshot.get("progress")
                progress = progress if type(progress) is dict else {}
                error = snapshot.get("error")
                error = error if type(error) is dict else {}
                evidence["last_wait_job"] = {
                    "available": True,
                    "state": _label(snapshot.get("state"), STATES),
                    "phase": _label(
                        progress.get("phase"), STATES | {"materializing_checkpoint", "finalizing"}
                    ),
                    "error_code": _label(error.get("code"), ERROR_CODES),
                    "error_type": _label(error.get("exception_type"), ERROR_TYPES),
                    "has_error": snapshot.get("error") is not None,
                    "has_result_ref": snapshot.get("result_ref") is not None,
                    "has_plan_field": "plan" in progress,
                    "has_children_field": "children" in progress,
                    "has_proposal_review_field": "proposal_record_id" in progress,
                }
            break
        trace = trace.tb_next
    # These are process-thread snapshots, not proof of this job's worker ownership.
    process_frames = sys._current_frames()
    stacks = []
    for frame in islice(process_frames.values(), 8):
        functions = []
        for _ in range(24):
            functions.append(_label(frame.f_code.co_name, FUNCTIONS))
            frame = frame.f_back
            if frame is None:
                break
        stacks.append(functions)
    evidence["process_thread_functions"] = stacks
    evidence["process_threads_truncated"] = len(process_frames) > 8
    return json.dumps(evidence, sort_keys=True)


@contextmanager
def diagnose_job_wait(stage, add_report_section=None):
    try:
        yield
    except JobWaitTimeout as timeout:
        try:
            payload = _report(timeout, stage)
            if add_report_section is None:
                print("Job wait diagnostic: " + payload, flush=True)
            else:
                add_report_section("call", "Job wait diagnostic", payload)
        except BaseException:
            # Even a failed diagnostic must preserve the original wait exception.
            pass
        raise
