"""Truthful read-only parent guidance for a retained native run operation."""

from typing import Any, Mapping


def apply_view(
    envelope: Mapping[str, Any], view: dict[str, Any], current: Mapping[str, Any]
) -> None:
    child = envelope["job"]
    path = "/runs?assistance_job=" + child["job_id"]
    decision = envelope["decision"]
    run = envelope["run_job"]
    inspection = envelope["inspection_job"]
    if decision and decision["decision"] == "reject" and run is None and inspection is None:
        view.update(
            status="blocked",
            message="The native preparation was declined. No run or inspection was submitted.",
            next_action={"kind": "new_turn", "label": "Start a new turn", "native_path": None},
            can_start_new_turn=True,
        )
    elif envelope["review_ready"]:
        view.update(
            status="awaiting_review",
            next_action={
                "kind": "review_run",
                "label": "Review native run preparation",
                "native_path": path,
            },
        )
    elif run is not None and run["state"] == "awaiting_approval":
        ai = run["progress"].get("approval_kind") == "ai_proposal"
        view.update(
            status="awaiting_review" if ai else "awaiting_execute_approval",
            next_action={
                "kind": "review_run" if ai else "review_execute",
                "label": "Review runtime proposal" if ai else "Review Execute approval",
                "native_path": "/runs?job=" + run["job_id"],
            },
        )
    elif (
        decision
        and decision["decision"] in {"accept", "policy"}
        and not child["progress"].get("stopped")
        and (
            run is None
            or (
                run["state"] in {"completed", "failed", "interrupted"}
                and run.get("result_ref")
                and (inspection is None or inspection["state"] in {"failed", "interrupted"})
            )
        )
    ):
        view.update(
            status="ready_to_continue",
            message="The retained run needs its next handoff recovered. Recovery never resubmits a completed or uncertain run.",
            next_action={
                "kind": "continue",
                "label": "Recover retained operation",
                "native_path": None,
            },
        )
    elif current["state"] in {"completed", "failed", "cancelled", "interrupted"}:
        view.update(
            status="blocked",
            message="Review the retained native run receipt. A failed or uncertain run is never repeated automatically.",
            next_action={
                "kind": "review_run",
                "label": "Review native run receipt",
                "native_path": path,
            },
        )
    else:
        view.update(status="working", next_action=None)
