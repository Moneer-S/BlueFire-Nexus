"""Run-to-run comparison over normalized bundle data."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
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
    snapshots = []
    for run_id in run_ids:
        integrity = store.validate_bundle(run_id)
        if not integrity.get("valid"):
            raise ComparisonError(f"run bundle failed integrity validation: {run_id}")
        snapshots.append(store.get_run(run_id))
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
    policy_states: Counter[str] = Counter()
    outcome_counts: Counter[str] = Counter()
    cleanup_success: bool | None = None
    for row in steps:
        if not isinstance(row, Mapping):
            continue
        step_id = str(row.get("step_id", ""))
        if step_id:
            path.append(step_id)
            outcome = str(row.get("status", "unknown"))
            outcomes[step_id] = outcome
            outcome_counts[outcome] += 1
        if first_blocked is None and row.get("status") in {"blocked", "control_blocked", "refused"}:
            first_blocked = step_id or None
        for item in row.get("telemetry", []) if isinstance(row.get("telemetry"), list) else []:
            telemetry.add(str(item))
        policy = row.get("policy")
        if isinstance(policy, Mapping):
            policy_status = str(policy.get("status", "unknown"))
            policy_states[policy_status] += 1
            if policy_status in {"control_blocked", "refused"}:
                controls.add(policy_status)
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
    detection_matches = sum(
        int(row.get("match_count", 0))
        for row in candidates
        if isinstance(row, Mapping) and isinstance(row.get("match_count", 0), int)
    )
    benign_matches = sum(
        int(row.get("benign_match_count", 0))
        for row in candidates
        if isinstance(row, Mapping) and isinstance(row.get("benign_match_count", 0), int)
    )
    ai_proposals = snapshot.get("ai_proposals", [])
    if not isinstance(ai_proposals, list):
        ai_proposals = []
    ai_applications = Counter(
        str(row.get("application_status", row.get("application", "unknown")))
        for row in ai_proposals
        if isinstance(row, Mapping)
    )
    decisions = snapshot.get("planner_decisions", [])
    if not isinstance(decisions, list):
        decisions = []
    remaining_budgets = {}
    if decisions and isinstance(decisions[-1], Mapping):
        budget_value = decisions[-1].get("remaining_budgets")
        if isinstance(budget_value, Mapping):
            remaining_budgets = {
                str(key): int(value)
                for key, value in budget_value.items()
                if isinstance(value, int) and not isinstance(value, bool)
            }
    objective_reached = bool(snapshot.get("objective_reached", False))
    return {
        "run_id": snapshot.get("run_id"),
        "mode": snapshot.get("mode"),
        "profile_id": snapshot.get("runner_profile_id"),
        "path": path,
        "outcomes": outcomes,
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "first_blocked_step": first_blocked,
        "objective_reached": objective_reached,
        "evidence_provenance": dict(sorted(provenance.items())),
        "detection_states": dict(sorted(detection_states.items())),
        "detection_matches": detection_matches,
        "benign_matches": benign_matches,
        "telemetry": sorted(telemetry),
        "controls": sorted(controls),
        "cleanup_success": cleanup_success,
        "policy_states": dict(sorted(policy_states.items())),
        "autonomy": snapshot.get("autonomy", "off"),
        "ai_provider_id": _provider_id(snapshot.get("ai_provider")),
        "ai_proposal_count": len(ai_proposals),
        "ai_applications": dict(sorted(ai_applications.items())),
        "remaining_budgets": remaining_budgets,
        "duration_ms": _duration_ms(snapshot),
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
    baseline_outcomes = Counter(baseline["outcome_counts"])
    candidate_outcomes = Counter(candidate["outcome_counts"])
    outcome_keys = sorted(set(baseline_outcomes) | set(candidate_outcomes))
    signals: list[str] = []
    if not baseline["objective_reached"] and candidate["objective_reached"]:
        signals.append("objective_recovered")
    elif baseline["objective_reached"] and not candidate["objective_reached"]:
        signals.append("objective_regressed")
    if baseline["cleanup_success"] is False and candidate["cleanup_success"] is True:
        signals.append("cleanup_recovered")
    elif baseline["cleanup_success"] is True and candidate["cleanup_success"] is False:
        signals.append("cleanup_regressed")
    observed_delta = candidate_evidence["observed"] - baseline_evidence["observed"]
    if observed_delta > 0:
        signals.append("observed_evidence_increased")
    elif observed_delta < 0:
        signals.append("observed_evidence_decreased")
    detection_match_delta = candidate["detection_matches"] - baseline["detection_matches"]
    benign_match_delta = candidate["benign_matches"] - baseline["benign_matches"]
    if detection_match_delta > 0:
        signals.append("detection_matches_increased")
    elif detection_match_delta < 0:
        signals.append("detection_matches_decreased")
    if benign_match_delta > 0:
        signals.append("benign_matches_increased")
    elif benign_match_delta < 0:
        signals.append("benign_matches_decreased")
    assessment = _assessment(signals)
    return {
        "from_run_id": baseline["run_id"],
        "to_run_id": candidate["run_id"],
        "first_path_divergence": first_divergence,
        "first_blocked_changed": baseline["first_blocked_step"] != candidate["first_blocked_step"],
        "objective_changed": baseline["objective_reached"] != candidate["objective_reached"],
        "cleanup_changed": baseline["cleanup_success"] != candidate["cleanup_success"],
        "evidence_delta": evidence_delta,
        "detection_delta": detection_delta,
        "detection_match_delta": detection_match_delta,
        "benign_match_delta": benign_match_delta,
        "outcome_delta": {
            key: candidate_outcomes[key] - baseline_outcomes[key] for key in outcome_keys
        },
        "telemetry_added": sorted(set(candidate["telemetry"]) - set(baseline["telemetry"])),
        "telemetry_removed": sorted(set(baseline["telemetry"]) - set(candidate["telemetry"])),
        "controls_added": sorted(set(candidate["controls"]) - set(baseline["controls"])),
        "controls_removed": sorted(set(baseline["controls"]) - set(candidate["controls"])),
        "autonomy_changed": baseline["autonomy"] != candidate["autonomy"],
        "ai_provider_changed": baseline["ai_provider_id"] != candidate["ai_provider_id"],
        "ai_proposal_delta": candidate["ai_proposal_count"] - baseline["ai_proposal_count"],
        "duration_delta_ms": _number_delta(
            baseline.get("duration_ms"), candidate.get("duration_ms")
        ),
        "assessment": assessment,
        "signals": signals,
    }


def _provider_id(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        selected = value.get("provider_id") or value.get("requested_provider_id")
        return str(selected) if isinstance(selected, str) and selected else None
    return None


def _duration_ms(snapshot: Mapping[str, Any]) -> int | None:
    created = snapshot.get("created_at")
    finalized = snapshot.get("finalized_at")
    if not isinstance(created, str) or not isinstance(finalized, str):
        return None
    try:
        start = datetime.fromisoformat(created.replace("Z", "+00:00"))
        end = datetime.fromisoformat(finalized.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, round((end - start).total_seconds() * 1000))


def _number_delta(baseline: Any, candidate: Any) -> int | None:
    if isinstance(baseline, int) and isinstance(candidate, int):
        return candidate - baseline
    return None


def _assessment(signals: Sequence[str]) -> str:
    regressed = any(
        signal.endswith("regressed")
        or signal in {"observed_evidence_decreased", "benign_matches_increased"}
        for signal in signals
    )
    improved = any(
        signal.endswith("recovered")
        or signal
        in {
            "observed_evidence_increased",
            "detection_matches_increased",
            "benign_matches_decreased",
        }
        for signal in signals
    )
    if improved and not regressed:
        return "improved"
    if regressed and not improved:
        return "regressed"
    if signals:
        return "mixed"
    return "no_material_change"


__all__ = ["ComparisonError", "compare_runs"]
