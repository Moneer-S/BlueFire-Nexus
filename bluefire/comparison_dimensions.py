"""Bounded projections and deltas for the locked comparison dimensions."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .util import content_hash

_DIMENSION_KEYS = (
    "planner",
    "scope",
    "implementation",
    "evidence",
    "detection",
    "cleanup",
    "budgets",
    "assessment",
)
_MAX_DIMENSION_ROWS = 256
_MAX_DIMENSION_TEXT = 200
_MAX_BUDGET_KEYS = 64
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def summary_dimensions(
    snapshot: Mapping[str, Any],
    decisions: Sequence[Any],
    summary: Mapping[str, Any],
    *,
    error_type: type[ValueError],
) -> dict[str, Any]:
    """Expose the locked comparison dimensions without raw run documents.

    Planner rationales, provider payloads, action constants, and defense-change
    text are deliberately excluded. Every included string or collection is
    bounded before it becomes part of the stable comparison record.
    """

    planner = _planner_dimension(decisions)
    implementation = _implementation_dimension(snapshot, summary)
    budgets = _budget_dimension(decisions, summary.get("remaining_budgets"))
    result = {
        "planner": planner,
        "scope": dict(_mapping_or_empty(summary.get("target_scope"))),
        "implementation": implementation,
        "evidence": {
            "provenance": dict(_mapping_or_empty(summary.get("evidence_provenance"))),
            "details": dict(_mapping_or_empty(summary.get("evidence_details"))),
            "collector_session": dict(_mapping_or_empty(summary.get("collector_session"))),
        },
        "detection": {
            "states": dict(_mapping_or_empty(summary.get("detection_states"))),
            "matches": _safe_nonnegative_int(summary.get("detection_matches")),
            "observed_matches": _safe_optional_nonnegative_int(
                summary.get("observed_detection_matches")
            ),
            "fixture_matches": _safe_optional_nonnegative_int(
                summary.get("fixture_detection_matches")
            ),
            "benign_matches": _safe_nonnegative_int(summary.get("benign_matches")),
        },
        "cleanup": dict(_mapping_or_empty(summary.get("cleanup"))),
        "budgets": budgets,
        "assessment": {
            "state": (
                "objective_reached"
                if summary.get("objective_reached") is True
                else "objective_not_reached"
            ),
            "objective_reached": summary.get("objective_reached") is True,
            "first_blocked_step": _safe_dimension_text(summary.get("first_blocked_step")),
        },
    }
    if tuple(result) != _DIMENSION_KEYS:  # pragma: no cover - local invariant
        raise error_type("comparison dimension inventory changed")
    return result


def delta_dimensions(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    delta: Mapping[str, Any],
    *,
    error_type: type[ValueError],
) -> dict[str, Any]:
    baseline_dimensions = _mapping_or_empty(baseline.get("dimensions"))
    candidate_dimensions = _mapping_or_empty(candidate.get("dimensions"))
    baseline_planner = _mapping_or_empty(baseline_dimensions.get("planner"))
    candidate_planner = _mapping_or_empty(candidate_dimensions.get("planner"))
    baseline_implementation = _mapping_or_empty(baseline_dimensions.get("implementation"))
    candidate_implementation = _mapping_or_empty(candidate_dimensions.get("implementation"))
    baseline_budgets = _mapping_or_empty(baseline_dimensions.get("budgets"))
    candidate_budgets = _mapping_or_empty(candidate_dimensions.get("budgets"))
    result = {
        "planner": _planner_dimension_delta(baseline_planner, candidate_planner),
        "scope": {
            "changed": delta.get("target_scope_changed") is True,
            "from": dict(_mapping_or_empty(baseline_dimensions.get("scope"))),
            "to": dict(_mapping_or_empty(candidate_dimensions.get("scope"))),
        },
        "implementation": _implementation_dimension_delta(
            baseline_implementation,
            candidate_implementation,
        ),
        "evidence": {
            "changed": _mapping_has_nonzero(delta.get("evidence_delta"))
            or _evidence_detail_changed(delta.get("evidence_detail_delta"))
            or delta.get("collector_session_changed") is True,
            "provenance_delta": dict(_mapping_or_empty(delta.get("evidence_delta"))),
            "details": dict(_mapping_or_empty(delta.get("evidence_detail_delta"))),
            "collector_session": dict(_mapping_or_empty(delta.get("collector_session_delta"))),
        },
        "detection": {
            "changed": _mapping_has_nonzero(delta.get("detection_delta"))
            or _nonzero_number(delta.get("detection_match_delta"))
            or _nonzero_number(delta.get("observed_detection_match_delta"))
            or _nonzero_number(delta.get("fixture_detection_match_delta"))
            or _nonzero_number(delta.get("benign_match_delta")),
            "state_delta": dict(_mapping_or_empty(delta.get("detection_delta"))),
            "match_delta": delta.get("detection_match_delta"),
            "observed_match_delta": delta.get("observed_detection_match_delta"),
            "fixture_match_delta": delta.get("fixture_detection_match_delta"),
            "benign_match_delta": delta.get("benign_match_delta"),
        },
        "cleanup": {
            "changed": delta.get("cleanup_changed") is True
            or baseline_dimensions.get("cleanup") != candidate_dimensions.get("cleanup"),
            "from": dict(_mapping_or_empty(baseline_dimensions.get("cleanup"))),
            "to": dict(_mapping_or_empty(candidate_dimensions.get("cleanup"))),
        },
        "budgets": _budget_dimension_delta(baseline_budgets, candidate_budgets),
        "assessment": {
            "classification": _safe_assessment(delta.get("assessment")),
            "signals": _safe_dimension_text_list(delta.get("signals")),
        },
    }
    if tuple(result) != _DIMENSION_KEYS:  # pragma: no cover - local invariant
        raise error_type("comparison delta dimension inventory changed")
    return result


def _planner_dimension(decisions: Sequence[Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    source_count = len(decisions)
    for raw in decisions[:_MAX_DIMENSION_ROWS]:
        if not isinstance(raw, Mapping):
            continue
        edge = raw.get("selected_edge")
        safe_edge = None
        if isinstance(edge, Mapping):
            candidate_edge = {
                "from_step": _safe_dimension_text(edge.get("from_step")),
                "outcome": _safe_dimension_text(edge.get("outcome")),
                "to_step": _safe_dimension_text(edge.get("to_step")),
            }
            if all(value is not None for value in candidate_edge.values()):
                safe_edge = candidate_edge
        disposition = _safe_dimension_text(raw.get("execution_disposition"))
        if disposition not in {
            "simulate",
            "execute",
            "request_approval",
            "counterfactual",
            "stop",
        }:
            disposition = "unknown"
        rows.append(
            {
                "decision_id": _safe_dimension_text(raw.get("decision_id")),
                "selected_step_id": _safe_dimension_text(raw.get("selected_step_id")),
                "selected_behavior_id": _safe_dimension_text(raw.get("selected_behavior_id")),
                "selected_action_id": _safe_dimension_text(raw.get("selected_action_id")),
                "selected_edge": safe_edge,
                "execution_disposition": disposition,
            }
        )
    semantic_rows = [
        {key: value for key, value in row.items() if key != "decision_id"} for row in rows
    ]
    return {
        "decision_count": len(rows),
        "source_count": min(source_count, _MAX_DIMENSION_ROWS + 1),
        "truncated": source_count > _MAX_DIMENSION_ROWS,
        "decisions": rows,
        "decision_digest": content_hash(semantic_rows),
    }


def _implementation_dimension(
    snapshot: Mapping[str, Any], summary: Mapping[str, Any]
) -> dict[str, Any]:
    plan = snapshot.get("plan")
    raw_steps = plan.get("steps") if isinstance(plan, Mapping) else None
    source = "plan"
    if not isinstance(raw_steps, list) or not raw_steps:
        raw_steps = summary.get("execution_path")
        source = "execution_path"
    rows: dict[str, dict[str, str | None]] = {}
    invalid_or_duplicate = 0
    source_count = len(raw_steps) if isinstance(raw_steps, list) else 0
    for raw in (raw_steps[:_MAX_DIMENSION_ROWS] if isinstance(raw_steps, list) else []):
        if not isinstance(raw, Mapping):
            invalid_or_duplicate += 1
            continue
        step_id = _safe_dimension_text(raw.get("step_id"))
        if step_id is None or step_id in rows:
            invalid_or_duplicate += 1
            continue
        rows[step_id] = {
            "step_id": step_id,
            "behavior_id": _safe_dimension_text(raw.get("behavior_id")),
            "action_id": _safe_dimension_text(raw.get("action_id")),
            "simulation_id": _safe_dimension_text(raw.get("simulation_id")),
        }
    steps = [rows[step_id] for step_id in sorted(rows)]
    profile_id = _safe_dimension_text(summary.get("profile_id"))
    authority = _mapping_or_empty(summary.get("catalog_authority"))
    authority_digest = _digest_or_none(authority.get("authority_record_digest"))
    identity = {
        "profile_id": profile_id,
        "catalog_authority_digest": authority_digest,
        "steps": steps,
    }
    return {
        "source": source,
        "step_count": len(steps),
        "source_count": min(source_count, _MAX_DIMENSION_ROWS + 1),
        "truncated": source_count > _MAX_DIMENSION_ROWS,
        "invalid_or_duplicate_step_count": invalid_or_duplicate,
        **identity,
        "implementation_digest": content_hash(identity),
    }


def _budget_dimension(decisions: Sequence[Any], fallback: Any) -> dict[str, Any]:
    snapshots: list[dict[str, Any]] = []
    for raw in decisions[:_MAX_DIMENSION_ROWS]:
        if not isinstance(raw, Mapping):
            continue
        remaining = _safe_budget_mapping(raw.get("remaining_budgets"))
        if remaining:
            snapshots.append(
                {
                    "decision_id": _safe_dimension_text(raw.get("decision_id")),
                    "remaining": remaining,
                }
            )
    remaining = dict(snapshots[-1]["remaining"]) if snapshots else _safe_budget_mapping(fallback)
    body = {
        "snapshots": [dict(row["remaining"]) for row in snapshots],
        "remaining": remaining,
    }
    return {
        "snapshot_count": len(snapshots),
        "snapshots": snapshots,
        "remaining": remaining,
        "budget_digest": content_hash(body),
    }


def _planner_dimension_delta(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> dict[str, Any]:
    baseline_rows = baseline.get("decisions")
    candidate_rows = candidate.get("decisions")
    before = baseline_rows if isinstance(baseline_rows, list) else []
    after = candidate_rows if isinstance(candidate_rows, list) else []
    before_steps = {
        row.get("selected_step_id")
        for row in before
        if isinstance(row, Mapping) and isinstance(row.get("selected_step_id"), str)
    }
    after_steps = {
        row.get("selected_step_id")
        for row in after
        if isinstance(row, Mapping) and isinstance(row.get("selected_step_id"), str)
    }
    before_count = _safe_nonnegative_int(baseline.get("decision_count"))
    after_count = _safe_nonnegative_int(candidate.get("decision_count"))
    return {
        "changed": baseline.get("decision_digest") != candidate.get("decision_digest"),
        "from_digest": _digest_or_none(baseline.get("decision_digest")),
        "to_digest": _digest_or_none(candidate.get("decision_digest")),
        "decision_count_delta": after_count - before_count,
        "selected_steps_added": sorted(after_steps - before_steps),
        "selected_steps_removed": sorted(before_steps - after_steps),
    }


def _implementation_dimension_delta(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> dict[str, Any]:
    before = _implementation_step_index(baseline.get("steps"))
    after = _implementation_step_index(candidate.get("steps"))
    step_ids = sorted(set(before) | set(after))
    return {
        "changed": baseline.get("implementation_digest") != candidate.get("implementation_digest"),
        "from_digest": _digest_or_none(baseline.get("implementation_digest")),
        "to_digest": _digest_or_none(candidate.get("implementation_digest")),
        "profile_changed": baseline.get("profile_id") != candidate.get("profile_id"),
        "from_profile_id": _safe_dimension_text(baseline.get("profile_id")),
        "to_profile_id": _safe_dimension_text(candidate.get("profile_id")),
        "steps_added": [step_id for step_id in step_ids if step_id not in before],
        "steps_removed": [step_id for step_id in step_ids if step_id not in after],
        "steps_changed": [
            step_id
            for step_id in step_ids
            if step_id in before and step_id in after and before[step_id] != after[step_id]
        ],
    }


def _budget_dimension_delta(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> dict[str, Any]:
    before = _safe_budget_mapping(baseline.get("remaining"))
    after = _safe_budget_mapping(candidate.get("remaining"))
    keys = sorted(set(before) | set(after))
    numeric_delta: dict[str, int | None] = {}
    for key in keys:
        left = before.get(key)
        right = after.get(key)
        numeric_delta[key] = right - left if left is not None and right is not None else None
    return {
        "changed": baseline.get("budget_digest") != candidate.get("budget_digest"),
        "from_digest": _digest_or_none(baseline.get("budget_digest")),
        "to_digest": _digest_or_none(candidate.get("budget_digest")),
        "from_remaining": before,
        "to_remaining": after,
        "remaining_delta": numeric_delta,
    }


def _implementation_step_index(value: Any) -> dict[str, Mapping[str, Any]]:
    rows = value if isinstance(value, list) else []
    return {
        str(row["step_id"]): row
        for row in rows[:_MAX_DIMENSION_ROWS]
        if isinstance(row, Mapping) and isinstance(row.get("step_id"), str)
    }


def _safe_budget_mapping(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    rows: list[tuple[str, int]] = []
    for key, amount in value.items():
        safe_key = _safe_dimension_text(key)
        if (
            safe_key is not None
            and _IDENTIFIER.fullmatch(safe_key) is not None
            and isinstance(amount, int)
            and not isinstance(amount, bool)
            and 0 <= amount <= 2**63 - 1
        ):
            rows.append((safe_key, int(amount)))
    return dict(sorted(rows)[:_MAX_BUDGET_KEYS])


def _safe_dimension_text(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_DIMENSION_TEXT
        or not value.isascii()
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        return None
    return value


def _safe_dimension_text_list(value: Any) -> list[str]:
    rows = value if isinstance(value, list) else []
    return [
        safe
        for item in rows[:_MAX_DIMENSION_ROWS]
        if (safe := _safe_dimension_text(item)) is not None
    ]


def _safe_nonnegative_int(value: Any) -> int:
    return (
        int(value) if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0
    )


def _safe_optional_nonnegative_int(value: Any) -> int | None:
    if value is None:
        return None
    return _safe_nonnegative_int(value)


def _mapping_or_empty(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mapping_has_nonzero(value: Any) -> bool:
    return isinstance(value, Mapping) and any(_nonzero_number(item) for item in value.values())


def _nonzero_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value != 0


def _evidence_detail_changed(value: Any) -> bool:
    details = _mapping_or_empty(value)
    return any(
        bool(details.get(field))
        for field in (
            "observed_artifacts_added",
            "observed_artifacts_removed",
            "observed_artifacts_changed",
            "evidence_gaps_added",
            "evidence_gaps_removed",
        )
    ) or _mapping_has_nonzero(details.get("producer_delta"))


def _safe_assessment(value: Any) -> str:
    return value if value in {"improved", "regressed", "mixed", "no_material_change"} else "mixed"


def _digest_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and _DIGEST.fullmatch(value) is not None else None
