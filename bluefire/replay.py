"""Replay preparation without mutating the original scenario snapshot."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from .config import AutonomyLevel
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
    parameter_overrides: Mapping[str, Mapping[str, Any]] | None = None
    action_implementations: Mapping[str, str] | None = None
    autonomy: AutonomyLevel | None = None
    ai_provider_id: str | None = None
    ai_enabled: bool | None = None
    runner_profile_id: str | None = None
    defense_change: str | None = None

    def __post_init__(self) -> None:
        changes = (
            self.from_step_id,
            self.swap_step_id,
            self.swap_behavior_id,
            self.parameter_overrides,
            self.action_implementations,
            self.autonomy,
            self.ai_provider_id,
            self.ai_enabled,
            self.runner_profile_id,
            self.defense_change,
        )
        if self.exact and any(value is not None for value in changes):
            raise ReplayError("exact replay cannot include variants")
        if (self.swap_step_id is None) != (self.swap_behavior_id is None):
            raise ReplayError("node swaps require both step and behavior IDs")
        if self.autonomy is not None and self.ai_enabled is not None:
            raise ReplayError("use autonomy or legacy ai_enabled, not both")
        if self.parameter_overrides is not None:
            if (
                not isinstance(self.parameter_overrides, Mapping)
                or len(self.parameter_overrides) > 100
            ):
                raise ReplayError("parameter overrides must be a bounded step mapping")
            for step_id, parameters in self.parameter_overrides.items():
                if (
                    not isinstance(step_id, str)
                    or not step_id
                    or not isinstance(parameters, Mapping)
                ):
                    raise ReplayError("parameter overrides must map step IDs to parameter objects")
        if self.action_implementations is not None:
            if (
                not isinstance(self.action_implementations, Mapping)
                or len(self.action_implementations) > 100
                or not all(
                    isinstance(step_id, str)
                    and bool(step_id)
                    and isinstance(action_id, str)
                    and bool(action_id)
                    for step_id, action_id in self.action_implementations.items()
                )
            ):
                raise ReplayError("action implementations must be a bounded step mapping")


@dataclass(frozen=True, slots=True)
class PreparedReplay:
    scenario: ScenarioDefinition
    resume_from_step_id: str | None
    seed_artifacts: Mapping[str, Any]
    autonomy: AutonomyLevel
    ai_provider_id: str | None
    runner_profile_id: str | None
    action_implementations: Mapping[str, str]
    lineage: Mapping[str, Any]

    @property
    def ai_enabled(self) -> bool:
        return self.autonomy is not AutonomyLevel.OFF


def prepare_replay(
    store: RunStore,
    registry: BehaviorRegistry,
    request: ReplayRequest,
) -> PreparedReplay:
    integrity = store.validate_bundle(request.source_run_id)
    if not integrity.get("valid"):
        raise ReplayError("source run bundle failed integrity validation")
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

    if request.parameter_overrides:
        replacements = {str(key): dict(value) for key, value in request.parameter_overrides.items()}
        unknown_steps = sorted(set(replacements) - {step.id for step in scenario.steps})
        if unknown_steps:
            raise ReplayError("unknown parameter override step: " + ", ".join(unknown_steps))
        updated_steps = []
        for step in scenario.steps:
            changes = replacements.get(step.id)
            if changes is None:
                updated_steps.append(step)
                continue
            parameters = {**dict(step.parameters), **changes}
            registry.get_behavior(step.behavior_id).validate_parameters(
                parameters,
                f"replay parameters for {step.id}",
            )
            updated_steps.append(replace(step, parameters=parameters))
        scenario = replace(scenario, steps=tuple(updated_steps))
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

    source_autonomy = _source_autonomy(source)
    requested_autonomy = request.autonomy
    if requested_autonomy is None and request.ai_enabled is not None:
        requested_autonomy = AutonomyLevel.ASSIST if request.ai_enabled else AutonomyLevel.OFF
    autonomy = requested_autonomy or source_autonomy
    source_provider = _source_provider_id(source)
    provider_id = request.ai_provider_id or source_provider
    source_plan = source.get("plan")
    source_action_implementations = {
        str(step["step_id"]): str(step["action_id"])
        for step in (source_plan.get("steps", []) if isinstance(source_plan, Mapping) else [])
        if isinstance(step, Mapping)
        and isinstance(step.get("step_id"), str)
        and isinstance(step.get("action_id"), str)
    }
    original_source_action_implementations = dict(source_action_implementations)
    action_reselection_steps: list[str] = []
    if request.swap_step_id is not None and request.swap_step_id not in (
        request.action_implementations or {}
    ):
        source_action_implementations.pop(request.swap_step_id, None)
        action_reselection_steps.append(request.swap_step_id)
    action_implementations = {
        **source_action_implementations,
        **dict(request.action_implementations or {}),
    }
    unknown_action_steps = sorted(
        set(action_implementations) - {step.id for step in scenario.steps}
    )
    if unknown_action_steps:
        raise ReplayError("unknown action implementation step: " + ", ".join(unknown_action_steps))

    lineage = {
        "schema_version": "bluefire.replay-lineage.v1",
        "source_run_id": request.source_run_id,
        "source_scenario_digest": content_hash(raw_scenario),
        "exact": request.exact,
        "from_step_id": request.from_step_id,
        "swap_step_id": request.swap_step_id,
        "swap_behavior_id": request.swap_behavior_id,
        "parameter_overrides": (
            {key: dict(value) for key, value in request.parameter_overrides.items()}
            if request.parameter_overrides
            else None
        ),
        "action_implementations_from": original_source_action_implementations,
        "action_implementation_overrides": dict(request.action_implementations or {}),
        "action_implementations_to": action_implementations,
        "action_implementations_changed": bool(request.action_implementations),
        "action_reselection_steps": action_reselection_steps,
        "ai_changed": requested_autonomy is not None,
        "autonomy_from": source_autonomy.value,
        "autonomy_to": autonomy.value,
        "ai_provider_changed": request.ai_provider_id is not None,
        "ai_provider_from": source_provider,
        "ai_provider_to": provider_id,
        "profile_changed": request.runner_profile_id is not None,
        "defense_change": request.defense_change,
    }
    return PreparedReplay(
        scenario=scenario,
        resume_from_step_id=request.from_step_id,
        seed_artifacts=seed_artifacts,
        autonomy=autonomy,
        ai_provider_id=provider_id,
        runner_profile_id=request.runner_profile_id or source.get("runner_profile_id"),
        action_implementations=action_implementations,
        lineage=lineage,
    )


def _source_autonomy(source: Mapping[str, Any]) -> AutonomyLevel:
    raw = source.get("autonomy")
    if raw is None and isinstance(source.get("plan"), Mapping):
        raw = source["plan"].get("autonomy")
    if raw is not None:
        try:
            return AutonomyLevel(str(raw))
        except ValueError as exc:
            raise ReplayError("source run has an invalid autonomy value") from exc
    return AutonomyLevel.ASSIST if bool(source.get("ai_enabled", False)) else AutonomyLevel.OFF


def _source_provider_id(source: Mapping[str, Any]) -> str | None:
    raw = source.get("ai_provider")
    if raw is None and isinstance(source.get("plan"), Mapping):
        raw = source["plan"].get("ai_provider")
    if isinstance(raw, Mapping):
        nested = raw.get("provider")
        if isinstance(nested, Mapping):
            raw = nested
        value = raw.get("provider_id") or raw.get("requested_provider_id")
        return str(value) if isinstance(value, str) and value else None
    return str(raw) if isinstance(raw, str) and raw else None


__all__ = ["PreparedReplay", "ReplayError", "ReplayRequest", "prepare_replay"]
