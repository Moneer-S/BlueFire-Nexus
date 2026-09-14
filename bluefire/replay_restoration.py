"""Shared read-only restoration validation for replay review and dispatch."""

from __future__ import annotations

from typing import Any, Mapping

from .contracts import ExecutionMode
from .replay import ReplayError
from .replay_checkpoint import CheckpointError, build_restoration_plan
from .util import content_hash


def resolved_restoration_plan(
    resolved: Mapping[str, Any],
    plan: Mapping[str, Any],
    actions: Mapping[str, str],
    target_scope: Mapping[str, Any],
    runner_readiness: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    prepared = resolved["prepared"]
    mode, profile = resolved["mode"], resolved["profile"]
    exact = resolved["exact"]
    replay_catalog_authority = resolved["replay_catalog_authority"]
    resolved_replay_actions = actions
    restoration_plan: Mapping[str, Any] | None = None
    if prepared.checkpoint is not None:
        if mode is not ExecutionMode.EXECUTE or profile is None:
            raise ReplayError("materialized checkpoint replay requires Execute mode")
        if not isinstance(replay_catalog_authority, Mapping):
            raise ReplayError("checkpoint replay requires catalog authority")
        source_authority = prepared.checkpoint.get("source_authority")
        if not isinstance(source_authority, Mapping):
            raise ReplayError("checkpoint source authority is absent")
        source_scope = source_authority.get("target_scope")
        if exact and (
            not isinstance(source_scope, Mapping)
            or source_scope.get("scope_hash")
            != content_hash({"scope_refs": sorted(target_scope.get("scope_refs", []))})
        ):
            raise ReplayError("exact checkpoint replay requires the source target scope")
        original_actions = prepared.lineage.get("action_implementations_from")
        changed_action_steps = sorted(
            step_id
            for step_id, action_id in resolved_replay_actions.items()
            if not isinstance(original_actions, Mapping)
            or original_actions.get(step_id) != action_id
        )
        source_plan = prepared.checkpoint.get("source_plan")
        source_autonomy = source_plan.get("autonomy") if isinstance(source_plan, Mapping) else None
        source_profile = source_authority.get("profile")
        source_profile_id = (
            source_profile.get("profile_id") if isinstance(source_profile, Mapping) else None
        )
        variant_impact = {
            "parameter_steps": sorted((prepared.lineage.get("parameter_overrides") or {}).keys()),
            "behavior_steps": (
                [prepared.lineage["swap_step_id"]]
                if isinstance(prepared.lineage.get("swap_step_id"), str)
                else []
            ),
            "action_steps": changed_action_steps,
            "autonomy_changed": str(plan["autonomy"]) != source_autonomy,
            "profile_changed": profile.id != source_profile_id,
            "defense_change": prepared.lineage.get("defense_change"),
        }
        try:
            restoration_plan = build_restoration_plan(
                prepared.checkpoint,
                target_scenario=prepared.scenario.to_dict(),
                target_plan=dict(plan),
                target_profile=profile.to_dict(),
                target_scope=target_scope,
                target_catalog_authority=replay_catalog_authority,
                target_runner_readiness=dict(runner_readiness or {}),
                variant_impact=variant_impact,
                registry=resolved["replay_catalog"].registry,
            )
        except CheckpointError as exc:
            raise ReplayError(str(exc)) from exc
    return restoration_plan
