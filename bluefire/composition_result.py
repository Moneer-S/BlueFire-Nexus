"""Finalized composition result joins across retained platform-specific evidence."""

from . import composition_file_access, composition_macos_file_access
from .capability_grant import objective_result
from .detection_evaluations import _source, _source_binding
from .product_store_errors import ProductStoreError
from .receiver_session_contract import validate_terminal
from .runner_contracts import _verified_grant_attempt
from .util import content_hash


def verified_result(jobs, attempt, *, source=_source, verify=_verified_grant_attempt):
    lease, compiled = attempt["lease"], attempt["compiled"]
    state = jobs.store.get_job(lease["job_id"])["progress"]
    run, records, observed = source(jobs.service.detection_lab, lease["run_id"])
    if (
        attempt["state"] != "settled"
        or run["scenario"] != compiled["scenario"]
        or run["mode"] != "execute"
        or run["plan"]["autonomy"] != "off"
        or content_hash(run["plan"]) != lease["plan_digest"]
        or run["policy"].get("grant_attempt")
        != verify(
            attempt["claim"]["document"],
            expected_document_digest=attempt["claim"]["document_digest"],
        ).to_dict()
    ):
        raise ProductStoreError("The actual finalized run differs from its grant-owned attempt.")
    if "macos_file_access" in compiled:
        return composition_macos_file_access.verified_result(jobs, attempt, run, records, observed)
    if "file_access" in compiled:
        return composition_file_access.verified_result(jobs, attempt, run, records, observed)
    session, task, observation = (
        state["session"],
        state["task_binding"],
        state["receiver_observation"],
    )
    expected_task = {"kind": "bind", "review_digest": session["review_digest"], **task}
    if (
        observation.get("state") != "verified"
        or observation.get("review_binding") != session
        or observation.get("task_binding") != expected_task
    ):
        raise ProductStoreError("The exact authenticated receiver observation is unavailable.")
    terminal = validate_terminal(observation["terminal"], session, expected_task)
    decision = terminal["decision"]
    exit_receipt = observation.get("process_exit", {})
    if (
        decision is None
        or decision["decision"] not in {"accepted", "policy_refused"}
        or exit_receipt.get("returncode") != 0
        or exit_receipt.get("process_id") != session["receiver_process_id"]
        or exit_receipt.get("creation_identity") != session["creation_identity"]
    ):
        raise ProductStoreError("The receiver lacks a bound terminal and clean process exit.")
    steps = {row["step_id"]: row for row in run["steps"]}
    handoff = compiled["handoff"]
    stage, peer = steps[handoff["stage_step_id"]], steps[handoff["step_id"]]
    bundle = stage.get("artifacts", {}).get("bundle", {})
    if (
        peer.get("runner_task_id") != task["task_id"]
        or peer.get("action_id") != "sandbox.peer.handoff.v1"
        or bundle.get("type") != "artifact.sandbox.bundle.v1"
        or bundle.get("format") != "jsonl"
        or bundle.get("sha256") != task["sha256"]
        or bundle.get("size") != task["size_bytes"]
    ):
        raise ProductStoreError(
            "Authenticated receiver bytes do not match the staged native artifact."
        )
    grant = jobs.store.get_capability_grant(lease["grant_id"], now_ms=jobs.clock())["document"]
    semantics = decision["semantics"]
    receiver_result = {
        "decision": decision["decision"],
        "policy_digest": decision["policy_digest"],
        **{
            key: semantics[key]
            for key in (
                "record_count",
                "redacted_record_count",
                "retained_record_count",
                "empty_record_count",
            )
        },
    }
    cleanup = {
        "run": (
            "complete"
            if run.get("cleanup", {}).get("success") is True
            and run["cleanup"].get("outstanding_receipt_count") == 0
            else "incomplete"
        ),
        "receiver": "verified_closed" if state.get("receiver_closed") is True else "uncertain",
    }
    outcome = objective_result(
        grant,
        {
            **receiver_result,
            "receiver_verified": True,
            "data_class": "generated_public_jsonl",
            "run_cleanup": cleanup["run"],
            "receiver_cleanup": cleanup["receiver"],
        },
    )
    return {
        "run_id": lease["run_id"],
        "source_binding": _source_binding(run, records, observed),
        "receiver_result": receiver_result,
        "cleanup": cleanup,
        "objective": outcome,
    }
