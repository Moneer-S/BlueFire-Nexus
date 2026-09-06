"""Material comparison changes come from effective state and results, not ancestry."""

from __future__ import annotations

from typing import Any, Mapping


def configuration_changes(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    catalog_changed: bool,
    collector_settings_changed: bool,
) -> list[str]:
    """Compare the configuration actually used by each run.

    Replay declarations describe changes relative to a replay's own source.
    They cannot establish a difference between the two runs being compared.
    """

    before = baseline.get("dimensions", {}).get("implementation", {})
    after = candidate.get("dimensions", {}).get("implementation", {})
    changed = {
        "catalog_authority": catalog_changed,
        "target_scope": baseline.get("target_scope") != candidate.get("target_scope"),
        "action_implementations": before.get("steps") != after.get("steps"),
        "collectors": collector_settings_changed,
        "scenario": baseline.get("scenario_digest") != candidate.get("scenario_digest"),
        "profile": baseline.get("profile_id") != candidate.get("profile_id"),
        "mode": baseline.get("mode") != candidate.get("mode"),
        "autonomy": baseline.get("autonomy") != candidate.get("autonomy"),
        "ai_provider": baseline.get("ai_provider_id") != candidate.get("ai_provider_id"),
    }
    return [name for name, differs in changed.items() if differs]


def material_delta_fields(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    delta: Mapping[str, Any],
) -> list[str]:
    """Retain substantive configuration, security, and outcome differences.

    Duration, run IDs, replay source IDs, and defense-change notes remain
    available as descriptive metadata without proving a material result.
    """

    dimensions = delta.get("dimensions", {})
    changed = {
        "configuration": bool(delta.get("material_configuration_changed")),
        "path": baseline.get("execution_path") != candidate.get("execution_path"),
        "outcomes": baseline.get("outcomes") != candidate.get("outcomes"),
        "first_prevention": baseline.get("first_block") != candidate.get("first_block"),
        "objective": baseline.get("objective_reached") != candidate.get("objective_reached"),
        "controls": baseline.get("controls") != candidate.get("controls")
        or baseline.get("policy_states") != candidate.get("policy_states"),
        "telemetry": baseline.get("telemetry") != candidate.get("telemetry"),
        "ai_proposals": baseline.get("ai_proposal_count") != candidate.get("ai_proposal_count")
        or baseline.get("ai_applications") != candidate.get("ai_applications"),
        "counterfactual": baseline.get("counterfactual_steps")
        != candidate.get("counterfactual_steps"),
    }
    for name in ("planner", "implementation", "evidence", "detection", "cleanup", "budgets"):
        changed[name] = dimensions.get(name, {}).get("changed") is True
    return [name for name, differs in changed.items() if differs]
