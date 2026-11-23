"""Truthful parent state for native initial source review and application."""

from typing import Any, Mapping


def apply_view(
    envelope: Mapping[str, Any], view: dict[str, Any], current: Mapping[str, Any]
) -> None:
    job, decision, app = envelope["job"], envelope["decision"], envelope["application_job"]
    action = {
        "kind": "review_detection_create",
        "label": "Review initial rule source",
        "native_path": current["native_path"],
    }
    if envelope["review_ready"]:
        view.update(status="awaiting_review", next_action=action)
    elif job["progress"].get("stopped") or (decision and decision["decision"] == "reject"):
        view.update(
            status="blocked",
            message="Initial source creation was stopped or declined. No rule was saved.",
            next_action=action,
            can_start_new_turn=True,
        )
    elif (
        decision
        and decision["decision"] == "accept"
        and (app is None or app["state"] == "interrupted")
    ):
        view.update(
            status="blocked",
            message="The exact reviewed decision is retained. Reopen native review to recover its application; no model request is repeated.",
            next_action=action,
        )
    elif current["state"] in {"failed", "cancelled", "interrupted"}:
        view.update(
            status="blocked",
            message="Initial source creation needs attention. Review its retained receipt; no rule is implied by a failed proposal or application.",
            next_action=action,
        )
    else:
        view.update(status="working", next_action=None)
