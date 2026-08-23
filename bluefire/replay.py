"""Replay preparation without mutating the original scenario snapshot."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from .contracts import ScenarioDefinition
from .registry import BehaviorRegistry
from .run_store import RunStore
from .util import content_hash


class ReplayError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReplayRequest:
    source_run_id: str
    exact: bool = False
    from_step_id: str | None = None
    swap_step_id: str | None = None
    swap_behavior_id: str | None = None
    ai_enabled: bool | None = None
    runner_profile_id: str | None = None
    defense_change: str | None = None

    def __post_init__(self) -> None:
        changes = (
            self.from_step_id,
            self.swap_step_id,
            self.swap_behavior_id,
            self.ai_enabled,
            self.runner_profile_id,
            self.defense_change,
        )
        if self.exact and any(value is not None for value in changes):
            raise ReplayError("exact replay cannot include variants")
        if (self.swap_step_id is None) != (self.swap_behavior_id is None):
            raise ReplayError("node swaps require both step and behavior IDs")


@dataclass(frozen=True, slots=True)
class PreparedReplay:
    scenario: ScenarioDefinition
    resume_from_step_id: str | None
    seed_artifacts: Mapping[str, Any]
    ai_enabled: bool
    runner_profile_id: str | None
    lineage: Mapping[str, Any]


def prepare_replay(
    store: RunStore,
    registry: BehaviorRegistry,
    request: ReplayRequest,
) -> PreparedReplay:
    source = store.get_run(request.source_run_id)
    raw_scenario = source.get("scenario")
    if not isinstance(raw_scenario, Mapping):
        raise ReplayError("source run has no immutable scenario snapshot")
    scenario = ScenarioDefinition.from_mapping(raw_scenario)
    registry.validate_scenario(scenario)

    if request.from_step_id is not None:
        try:
            scenario.step(request.from_step_id)
        except KeyError as exc:
            raise ReplayError(f"unknown replay start step: {request.from_step_id}") from exc

    if request.swap_step_id and request.swap_behavior_id:
        step = scenario.step(request.swap_step_id)
        if request.swap_behavior_id not in step.alternates:
            compatible = registry.compatible_behaviors(step.behavior_id)
            if request.swap_behavior_id not in compatible:
                raise ReplayError("replacement behavior is not contract-compatible")
        replacement = registry.get_behavior(request.swap_behavior_id)
        replacement.validate_parameters(step.parameters, "replay swap parameters")
        steps = tuple(
            replace(item, behavior_id=replacement.id) if item.id == request.swap_step_id else item
            for item in scenario.steps
        )
        scenario = replace(scenario, steps=steps)
        registry.validate_scenario(scenario)

    source_steps = source.get("steps", [])
    seed_artifacts: dict[str, Any] = {}
    if request.from_step_id and isinstance(source_steps, list):
        for row in source_steps:
            if not isinstance(row, Mapping):
                continue
            step_id = row.get("step_id")
            if step_id == request.from_step_id:
                break
            artifacts = row.get("artifacts")
            if isinstance(step_id, str) and isinstance(artifacts, Mapping):
                seed_artifacts[step_id] = dict(artifacts)

    lineage = {
        "schema_version": "bluefire.replay-lineage.v1",
        "source_run_id": request.source_run_id,
        "source_scenario_digest": content_hash(raw_scenario),
        "exact": request.exact,
        "from_step_id": request.from_step_id,
        "swap_step_id": request.swap_step_id,
        "swap_behavior_id": request.swap_behavior_id,
        "ai_changed": request.ai_enabled is not None,
        "profile_changed": request.runner_profile_id is not None,
        "defense_change": request.defense_change,
    }
    return PreparedReplay(
        scenario=scenario,
        resume_from_step_id=request.from_step_id,
        seed_artifacts=seed_artifacts,
        ai_enabled=(
            request.ai_enabled
            if request.ai_enabled is not None
            else bool(source.get("ai_enabled", False))
        ),
        runner_profile_id=request.runner_profile_id or source.get("runner_profile_id"),
        lineage=lineage,
    )


__all__ = ["PreparedReplay", "ReplayError", "ReplayRequest", "prepare_replay"]
