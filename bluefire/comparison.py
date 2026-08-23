"""Run-to-run comparison over normalized bundle data."""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from .run_store import RunStore
from .util import content_hash


class ComparisonError(ValueError):
    pass


def compare_runs(store: RunStore, run_ids: Sequence[str]) -> Mapping[str, Any]:
    if len(run_ids) < 2:
        raise ComparisonError("comparison requires at least two runs")
    if len(run_ids) != len(set(run_ids)):
        raise ComparisonError("comparison run IDs must be unique")
    snapshots = [store.get_run(run_id) for run_id in run_ids]
    summaries = [_summarize(snapshot) for snapshot in snapshots]
    baseline = summaries[0]
    deltas = [_delta(baseline, candidate) for candidate in summaries[1:]]
    body = {
        "schema_version": "bluefire.comparison.v1",
        "run_ids": list(run_ids),
        "baseline_run_id": run_ids[0],
        "summaries": summaries,
        "deltas": deltas,
    }
    return dict(body, comparison_id="comparison-" + content_hash(body)[7:27])


def _summarize(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    steps = snapshot.get("steps")
    if steps is None:
        steps = (
            snapshot.get("result", {}).get("steps", [])
            if isinstance(snapshot.get("result"), dict)
            else []
        )
    if not isinstance(steps, list):
        steps = []
    path: list[str] = []
    outcomes: dict[str, str] = {}
    first_blocked: str | None = None
    telemetry: set[str] = set()
    controls: set[str] = set()
    cleanup_success: bool | None = None
    for row in steps:
        if not isinstance(row, Mapping):
            continue
        step_id = str(row.get("step_id", ""))
        if step_id:
            path.append(step_id)
            outcomes[step_id] = str(row.get("status", "unknown"))
        if first_blocked is None and row.get("status") in {"blocked", "control_blocked", "refused"}:
            first_blocked = step_id or None
        for item in row.get("telemetry", []) if isinstance(row.get("telemetry"), list) else []:
            telemetry.add(str(item))
        policy = row.get("policy")
        if isinstance(policy, Mapping) and policy.get("status") in {"control_blocked", "refused"}:
            controls.add(str(policy.get("status")))
        if step_id and "cleanup" in step_id:
            cleanup_success = row.get("status") == "success"

    evidence_doc = snapshot.get("evidence", {})
    records = evidence_doc.get("records", []) if isinstance(evidence_doc, Mapping) else []
    provenance = Counter(
        str(row.get("provenance", "unknown")) for row in records if isinstance(row, Mapping)
    )
    detections_doc = snapshot.get("detections", {})
    candidates = detections_doc.get("candidates", []) if isinstance(detections_doc, Mapping) else []
    detection_states = Counter(
        str(row.get("state", "unknown")) for row in candidates if isinstance(row, Mapping)
    )
    objective_reached = bool(snapshot.get("objective_reached", False))
    return {
        "run_id": snapshot.get("run_id"),
        "mode": snapshot.get("mode"),
        "profile_id": snapshot.get("runner_profile_id"),
        "path": path,
        "outcomes": outcomes,
        "first_blocked_step": first_blocked,
        "objective_reached": objective_reached,
        "evidence_provenance": dict(sorted(provenance.items())),
        "detection_states": dict(sorted(detection_states.items())),
        "telemetry": sorted(telemetry),
        "controls": sorted(controls),
        "cleanup_success": cleanup_success,
        "counterfactual_steps": [
            row.get("step_id")
            for row in steps
            if isinstance(row, Mapping) and row.get("execution_disposition") == "counterfactual"
        ],
    }


def _delta(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    baseline_path = list(baseline["path"])
    candidate_path = list(candidate["path"])
    first_divergence: int | None = None
    for index in range(max(len(baseline_path), len(candidate_path))):
        left = baseline_path[index] if index < len(baseline_path) else None
        right = candidate_path[index] if index < len(candidate_path) else None
        if left != right:
            first_divergence = index
            break
    baseline_evidence = Counter(baseline["evidence_provenance"])
    candidate_evidence = Counter(candidate["evidence_provenance"])
    keys = sorted(set(baseline_evidence) | set(candidate_evidence))
    evidence_delta = {key: candidate_evidence[key] - baseline_evidence[key] for key in keys}
    baseline_detection = Counter(baseline["detection_states"])
    candidate_detection = Counter(candidate["detection_states"])
    detection_keys = sorted(set(baseline_detection) | set(candidate_detection))
    detection_delta = {
        key: candidate_detection[key] - baseline_detection[key] for key in detection_keys
    }
    return {
        "from_run_id": baseline["run_id"],
        "to_run_id": candidate["run_id"],
        "first_path_divergence": first_divergence,
        "first_blocked_changed": baseline["first_blocked_step"] != candidate["first_blocked_step"],
        "objective_changed": baseline["objective_reached"] != candidate["objective_reached"],
        "cleanup_changed": baseline["cleanup_success"] != candidate["cleanup_success"],
        "evidence_delta": evidence_delta,
        "detection_delta": detection_delta,
        "telemetry_added": sorted(set(candidate["telemetry"]) - set(baseline["telemetry"])),
        "telemetry_removed": sorted(set(baseline["telemetry"]) - set(candidate["telemetry"])),
        "controls_added": sorted(set(candidate["controls"]) - set(baseline["controls"])),
        "controls_removed": sorted(set(baseline["controls"]) - set(candidate["controls"])),
    }


__all__ = ["ComparisonError", "compare_runs"]
