"""Finite timeout evidence from the existing wait frame; no store or lock reads."""

import json
import sys
from contextlib import contextmanager
from itertools import islice

from bluefire.job_runtime import JobState, JobWaitTimeout, RunJobController
from bluefire.product_store import ProductStore
from bluefire.service import BlueFireService

STAGES = {
    "graph_parent",
    "graph_child",
    "replay_approval",
    "replay_terminal",
    "receiver_terminal",
    "receiver_baseline_terminal",
    "receiver_protected_terminal",
    "receiver_legitimate_terminal",
    "service_terminal",
    "assist_rejection_approval",
    "assist_cancellation_approval",
}
STATES = {state.value for state in JobState}
# Only the reviewed public fixture step IDs may appear in timeout diagnostics.
DIAGNOSTIC_STEP_IDS = {
    "create_fixture",
    "inspect_fixture_metadata",
    "stage_records",
    "transform_fixture",
    "authorized_peer_handoff",
    "cleanup_workspace",
}
MAX_DIAGNOSTIC_STEP_COUNT = 256
RECEIVER_EXECUTE_CODE = BlueFireService._execute_job.__code__
MAX_EXECUTE_LINE_OFFSET = 128
REPLAY_EXECUTE_CODE = BlueFireService._execute_replay_job.__code__
MAX_REPLAY_EXECUTE_LINE_OFFSET = 128
REPLAY_CALLBACK_INNER_CODE = BlueFireService._execute_job_inner.__code__
MAX_REPLAY_CALLBACK_INNER_LINE_OFFSET = 256
PROPOSAL_CONTINUATION_CODE = BlueFireService._run_ai_proposal_continuation_locked.__code__
MAX_PROPOSAL_CONTINUATION_LINE_OFFSET = 256
REPLAY_LOCKED_CODE = BlueFireService._replay_locked.__code__
MAX_REPLAY_LOCKED_LINE_OFFSET = 384
PRODUCT_STORE_CONNECTION_CODE = ProductStore._connection.__wrapped__.__code__
MAX_PRODUCT_STORE_CONNECTION_LINE_OFFSET = 40
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
    "_run_ai_proposal_continuation",
    "_run_ai_proposal_continuation_locked",
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


def _step_count(value):
    if type(value) is int and 0 <= value <= MAX_DIAGNOSTIC_STEP_COUNT:
        return value
    return "unknown"


def _process_thread_sample():
    # These are process-thread snapshots, not proof of this job's worker ownership.
    process_frames = sys._current_frames()
    stacks = []
    receiver_execute_offsets = []
    replay_execute_offsets = []
    replay_callback_inner_offsets = []
    proposal_continuation_offsets = []
    replay_locked_offsets = []
    product_store_connection_offsets = []
    for frame in islice(process_frames.values(), 8):
        functions = []
        receiver_execute_offset = None
        replay_execute_offset = None
        replay_callback_inner_offset = None
        proposal_continuation_offset = None
        replay_locked_offset = None
        product_store_connection_offset = None
        for _ in range(24):
            functions.append(_label(frame.f_code.co_name, FUNCTIONS))
            if frame.f_code is RECEIVER_EXECUTE_CODE and receiver_execute_offset is None:
                offset = frame.f_lineno - RECEIVER_EXECUTE_CODE.co_firstlineno
                if type(offset) is int and 0 <= offset <= MAX_EXECUTE_LINE_OFFSET:
                    receiver_execute_offset = offset
            if frame.f_code is REPLAY_EXECUTE_CODE and replay_execute_offset is None:
                offset = frame.f_lineno - REPLAY_EXECUTE_CODE.co_firstlineno
                if type(offset) is int and 0 <= offset <= MAX_REPLAY_EXECUTE_LINE_OFFSET:
                    replay_execute_offset = offset
            if frame.f_code is REPLAY_CALLBACK_INNER_CODE and replay_callback_inner_offset is None:
                offset = frame.f_lineno - REPLAY_CALLBACK_INNER_CODE.co_firstlineno
                if type(offset) is int and 0 <= offset <= MAX_REPLAY_CALLBACK_INNER_LINE_OFFSET:
                    replay_callback_inner_offset = offset
            if frame.f_code is PROPOSAL_CONTINUATION_CODE and proposal_continuation_offset is None:
                offset = frame.f_lineno - PROPOSAL_CONTINUATION_CODE.co_firstlineno
                if type(offset) is int and 0 <= offset <= MAX_PROPOSAL_CONTINUATION_LINE_OFFSET:
                    proposal_continuation_offset = offset
            if frame.f_code is REPLAY_LOCKED_CODE and replay_locked_offset is None:
                offset = frame.f_lineno - REPLAY_LOCKED_CODE.co_firstlineno
                if type(offset) is int and 0 <= offset <= MAX_REPLAY_LOCKED_LINE_OFFSET:
                    replay_locked_offset = offset
            if (
                frame.f_code is PRODUCT_STORE_CONNECTION_CODE
                and product_store_connection_offset is None
            ):
                offset = frame.f_lineno - PRODUCT_STORE_CONNECTION_CODE.co_firstlineno
                if type(offset) is int and 0 <= offset <= MAX_PRODUCT_STORE_CONNECTION_LINE_OFFSET:
                    product_store_connection_offset = offset
            frame = frame.f_back
            if frame is None:
                break
        stacks.append(functions)
        if receiver_execute_offset is not None:
            receiver_execute_offsets.append(receiver_execute_offset)
        if replay_execute_offset is not None:
            replay_execute_offsets.append(replay_execute_offset)
        if replay_callback_inner_offset is not None:
            replay_callback_inner_offsets.append(replay_callback_inner_offset)
        if proposal_continuation_offset is not None:
            proposal_continuation_offsets.append(proposal_continuation_offset)
        if replay_locked_offset is not None:
            replay_locked_offsets.append(replay_locked_offset)
        if product_store_connection_offset is not None:
            product_store_connection_offsets.append(product_store_connection_offset)
    return {
        "process_thread_functions": stacks,
        "process_threads_truncated": len(process_frames) > 8,
        "receiver_execute_line_offsets": receiver_execute_offsets,
        "replay_execute_line_offsets": replay_execute_offsets,
        "replay_callback_inner_line_offsets": replay_callback_inner_offsets,
        "proposal_continuation_line_offsets": proposal_continuation_offsets,
        "replay_locked_line_offsets": replay_locked_offsets,
        "product_store_connection_line_offsets": product_store_connection_offsets,
    }


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
                completed_steps = _step_count(progress.get("completed_steps"))
                total_steps = _step_count(progress.get("total_steps"))
                if (
                    type(completed_steps) is int
                    and type(total_steps) is int
                    and completed_steps > total_steps
                ):
                    completed_steps = total_steps = "unknown"
                evidence["last_wait_job"] = {
                    "available": True,
                    "state": _label(snapshot.get("state"), STATES),
                    "phase": _label(
                        progress.get("phase"), STATES | {"materializing_checkpoint", "finalizing"}
                    ),
                    "current_step_id": _label(
                        progress.get("current_step_id"), DIAGNOSTIC_STEP_IDS
                    ),
                    "completed_steps": completed_steps,
                    "total_steps": total_steps,
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
    evidence.update(_process_thread_sample())
    return json.dumps(evidence, sort_keys=True)


def report_replay_callback_entry(add_report_section=None):
    """Emit bounded process-thread evidence after the replay callback-entry wait fails."""
    try:
        evidence = {"stage": "replay_callback_entry", **_process_thread_sample()}
        payload = json.dumps(evidence, sort_keys=True)
        if add_report_section is None:
            print("Replay callback-entry diagnostic: " + payload, flush=True)
        else:
            add_report_section("call", "Replay callback-entry diagnostic", payload)
    except BaseException:
        # A diagnostic failure must not replace the rendezvous assertion.
        pass


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
