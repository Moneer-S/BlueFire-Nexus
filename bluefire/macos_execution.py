"""Attempt-local closure through the existing step executor, not filesystem cleanup."""

from __future__ import annotations

from typing import Any

CLOSE_ACTION = "macos.file_access.close_attempt.v1"


def emergency_attempt_close(engine, *, plan, run_id: str, **arguments: Any) -> None:
    """Try once without masking interruption; the committed store claim remains the gate."""
    if engine.macos_file_access_binding is None or engine._macos_close_attempted:
        return
    step = next((row for row in plan.steps if row.action_id == CLOSE_ACTION), None)
    if step is None:
        return
    summary = {
        "attempted": True,
        "success": False,
        "scope": "attempt_request_usage_only",
        "native_filesystem_receipts": False,
        "whole_enrollment_cleanup": False,
    }
    try:
        row, records, _decision, _receipts = engine._execute_step(
            run_id=run_id, step=step, bound_inputs={}, parent_ids=(), receipt_ids=[], **arguments
        )
        summary["success"] = row["status"] == "success"
        current = engine.store.read_json(run_id, "evidence.json")
        engine.store.write_json(
            run_id,
            "evidence.json",
            {**current, "records": [*current.get("records", []), *(r.to_dict() for r in records)]},
        )
        engine.store.append_event(run_id, "attempt_closure.emergency.result", row)
    except BaseException:
        pass
    try:
        result = engine.store.read_json(run_id, "result.json")
        engine.store.write_json(run_id, "result.json", {**result, "attempt_closure": summary})
        engine.store.append_event(run_id, "attempt_closure.emergency", summary)
    except BaseException:
        pass
