"""Replay preparation without mutating the original scenario snapshot."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Mapping

from .config import AutonomyLevel
from .contracts import ExecutionMode, ScenarioDefinition
from .registry import BehaviorRegistry
from .replay_checkpoint import CheckpointError, checkpoint_for_step, validate_checkpoint
from .replay_checkpoint_binding import (
    CheckpointBindingError,
    checkpoint_source_binding_hash,
)
from .run_store import RunStore
from .util import content_hash, json_clone

_MAX_DEFENSE_CHANGE_CHARS = 512
_MAX_REPLAY_STEPS = 10_000
_MAX_REPLAY_ID_CHARS = 200
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[ _-]?key|authorization|credential|password|private[ _-]?key|secret|token)"
    r"\s*[:=]\s*\S+"
)
_BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/-]{8,}")
_PRIVATE_KEY_BLOCK = re.compile(r"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


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
        if type(self.exact) is not bool:
            raise ReplayError("exact replay flag must be a boolean")
        for value, label in (
            (self.source_run_id, "source run ID"),
            (self.from_step_id, "replay start step"),
            (self.swap_step_id, "swap step"),
            (self.swap_behavior_id, "swap behavior"),
            (self.ai_provider_id, "AI provider ID"),
            (self.runner_profile_id, "runner profile ID"),
        ):
            if value is not None and (
                not isinstance(value, str)
                or not value
                or len(value) > _MAX_REPLAY_ID_CHARS
                or "\x00" in value
            ):
                raise ReplayError(f"{label} is invalid")
        if self.autonomy is not None and not isinstance(self.autonomy, AutonomyLevel):
            raise ReplayError("replay autonomy is invalid")
        if self.ai_enabled is not None and type(self.ai_enabled) is not bool:
            raise ReplayError("legacy AI enabled flag must be a boolean")
        if self.defense_change is not None:
            object.__setattr__(
                self,
                "defense_change",
                _normalized_defense_change(self.defense_change),
            )
        changes = (
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
    checkpoint: Mapping[str, Any] | None
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
    try:
        source_mode = ExecutionMode(source.get("mode"))
    except (TypeError, ValueError) as exc:
        raise ReplayError("source run has no valid immutable execution mode") from exc
    raw_scenario = source.get("scenario")
    if not isinstance(raw_scenario, Mapping):
        raise ReplayError("source run has no immutable scenario snapshot")
    scenario = ScenarioDefinition.from_mapping(raw_scenario)
    registry.validate_scenario(scenario)

    checkpoint: Mapping[str, Any] | None = None
    source_prefix: tuple[Mapping[str, Any], ...] = ()
    checkpoint_prefix_ids: tuple[str, ...] = ()
    if request.from_step_id is not None:
        try:
            scenario.step(request.from_step_id)
        except KeyError as exc:
            raise ReplayError(f"unknown replay start step: {request.from_step_id}") from exc
        source_prefix = _source_prefix(source, request.from_step_id)
        if source_mode is ExecutionMode.EXECUTE:
            raw_checkpoints = source.get("replay_checkpoints")
            if not isinstance(raw_checkpoints, (list, tuple)):
                raise ReplayError("Execute node restart requires trusted replay checkpoints")
            source_plan_snapshot = source.get("plan")
            source_policy = source.get("policy")
            source_approval_binding = (
                source_policy.get("approval_binding")
                if isinstance(source_policy, Mapping)
                else None
            )
            if not isinstance(source_plan_snapshot, Mapping) or not isinstance(
                source_approval_binding, Mapping
            ):
                raise ReplayError("Execute node restart source binding is unavailable")
            try:
                expected_source_binding_hash = checkpoint_source_binding_hash(
                    source_run_id=request.source_run_id,
                    scenario=raw_scenario,
                    plan=source_plan_snapshot,
                    approval_binding=source_approval_binding,
                )
                selected = checkpoint_for_step(raw_checkpoints, request.from_step_id)
                checkpoint = validate_checkpoint(
                    selected,
                    expected_source_run_id=request.source_run_id,
                    expected_step_id=request.from_step_id,
                    expected_source_binding_hash=expected_source_binding_hash,
                )
            except (CheckpointBindingError, CheckpointError) as exc:
                raise ReplayError(
                    "Execute node restart checkpoint is unavailable or invalid"
                ) from exc
            checkpoint_scenario = checkpoint.get("source_scenario")
            if not isinstance(checkpoint_scenario, Mapping) or checkpoint_scenario.get(
                "scenario_hash"
            ) != content_hash(raw_scenario):
                raise ReplayError("Execute node restart checkpoint scenario binding is invalid")
            checkpoint_prefix_ids = _checkpoint_prefix_ids(checkpoint)
            source_prefix_ids = tuple(str(row["step_id"]) for row in source_prefix)
            if checkpoint_prefix_ids != source_prefix_ids:
                raise ReplayError("checkpoint prefix does not match the executed source path")
            _reject_checkpoint_prefix_mutations(request, checkpoint_prefix_ids)

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

    seed_artifacts: dict[str, Any] = {}
    if request.from_step_id and source_mode is ExecutionMode.SIMULATE:
        seed_artifacts = _simulate_seed_artifacts(
            source_prefix,
            scenario=scenario,
            registry=registry,
        )

    source_autonomy = _source_autonomy(source)
    requested_autonomy = request.autonomy
    if requested_autonomy is None and request.ai_enabled is not None:
        requested_autonomy = AutonomyLevel.ASSIST if request.ai_enabled else AutonomyLevel.OFF
    autonomy = requested_autonomy or source_autonomy
    source_provider = _source_provider_id(source)
    provider_id = request.ai_provider_id if request.ai_provider_id is not None else source_provider
    source_profile = _source_profile_id(source)
    profile_id = (
        request.runner_profile_id if request.runner_profile_id is not None else source_profile
    )
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

    defense_change = request.defense_change
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
        "ai_changed": autonomy != source_autonomy,
        "autonomy_from": source_autonomy.value,
        "autonomy_to": autonomy.value,
        "ai_provider_changed": provider_id != source_provider,
        "ai_provider_from": source_provider,
        "ai_provider_to": provider_id,
        "profile_from": source_profile,
        "profile_to": profile_id,
        "profile_changed": profile_id != source_profile,
        "checkpoint_id": checkpoint.get("checkpoint_id") if checkpoint is not None else None,
        "checkpoint_manifest_hash": (
            checkpoint.get("manifest_hash") if checkpoint is not None else None
        ),
        "checkpoint_materialization_mode": (
            "deterministic_prefix_recreation" if checkpoint is not None else None
        ),
        "defense_change": defense_change,
        "defense_change_declared": defense_change is not None,
        "defense_change_digest": (
            content_hash({"defense_change": defense_change}) if defense_change is not None else None
        ),
    }
    return PreparedReplay(
        scenario=scenario,
        resume_from_step_id=request.from_step_id,
        checkpoint=checkpoint,
        seed_artifacts=seed_artifacts,
        autonomy=autonomy,
        ai_provider_id=provider_id,
        runner_profile_id=profile_id,
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
    legacy = source.get("ai_enabled", False)
    if type(legacy) is not bool:
        raise ReplayError("source run has an invalid legacy AI enabled flag")
    return AutonomyLevel.ASSIST if legacy else AutonomyLevel.OFF


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


def _source_profile_id(source: Mapping[str, Any]) -> str | None:
    value = source.get("runner_profile_id")
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_REPLAY_ID_CHARS
        or "\x00" in value
    ):
        raise ReplayError("source run has an invalid runner profile identity")
    return value


def _source_prefix(
    source: Mapping[str, Any],
    target_step_id: str,
) -> tuple[Mapping[str, Any], ...]:
    rows = source.get("steps")
    if not isinstance(rows, list) or len(rows) > _MAX_REPLAY_STEPS:
        raise ReplayError("source run has no bounded executed step path")
    normalized: list[Mapping[str, Any]] = []
    target_positions: list[int] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ReplayError("source run executed step path is invalid")
        step_id = row.get("step_id")
        if (
            not isinstance(step_id, str)
            or not step_id
            or len(step_id) > _MAX_REPLAY_ID_CHARS
            or "\x00" in step_id
        ):
            raise ReplayError("source run executed step identity is invalid")
        normalized.append(row)
        if step_id == target_step_id:
            target_positions.append(index)
    if len(target_positions) != 1:
        raise ReplayError("replay start step must occur exactly once in the source path")
    prefix = normalized[: target_positions[0]]
    prefix_ids = [str(row["step_id"]) for row in prefix]
    if len(prefix_ids) != len(set(prefix_ids)):
        raise ReplayError("source replay prefix contains an ambiguous repeated step")
    return tuple(prefix)


def _checkpoint_prefix_ids(checkpoint: Mapping[str, Any]) -> tuple[str, ...]:
    prefix = checkpoint.get("executed_steps")
    if not isinstance(prefix, list) or len(prefix) > _MAX_REPLAY_STEPS:
        raise ReplayError("checkpoint has no bounded ordered prefix")
    step_ids: list[str] = []
    for row in prefix:
        if not isinstance(row, Mapping):
            raise ReplayError("checkpoint prefix row is invalid")
        step_id = row.get("step_id")
        if not isinstance(step_id, str) or not step_id:
            raise ReplayError("checkpoint prefix step identity is invalid")
        step_ids.append(step_id)
    if len(step_ids) != len(set(step_ids)):
        raise ReplayError("checkpoint prefix contains an ambiguous repeated step")
    return tuple(step_ids)


def _reject_checkpoint_prefix_mutations(
    request: ReplayRequest,
    prefix_step_ids: tuple[str, ...],
) -> None:
    prefix = set(prefix_step_ids)
    changed: set[str] = set()
    if request.swap_step_id in prefix:
        assert request.swap_step_id is not None
        changed.add(request.swap_step_id)
    if request.parameter_overrides is not None:
        changed.update(prefix.intersection(request.parameter_overrides))
    if request.action_implementations is not None:
        changed.update(prefix.intersection(request.action_implementations))
    if changed:
        raise ReplayError(
            "checkpoint prefix cannot be changed by a node-restart replay: "
            + ", ".join(sorted(changed))
        )


def _simulate_seed_artifacts(
    prefix: tuple[Mapping[str, Any], ...],
    *,
    scenario: ScenarioDefinition,
    registry: BehaviorRegistry,
) -> dict[str, Any]:
    seeds: dict[str, Any] = {}
    for row in prefix:
        step_id = str(row["step_id"])
        try:
            scenario_step = scenario.step(step_id)
        except KeyError as exc:
            raise ReplayError("source replay prefix contains an unknown scenario step") from exc
        artifacts = row.get("artifacts")
        if not isinstance(artifacts, Mapping):
            raise ReplayError("Simulate replay prefix contains invalid artifact metadata")
        output_specs = {
            output.name: output
            for output in registry.get_behavior(scenario_step.behavior_id).outputs
        }
        if set(artifacts) - set(output_specs):
            raise ReplayError("Simulate replay prefix contains undeclared artifact metadata")
        for name, value in artifacts.items():
            spec = output_specs[str(name)]
            values = value if spec.multiple else [value]
            if not isinstance(values, list) or any(
                not isinstance(item, Mapping) or item.get("type") != spec.type for item in values
            ):
                raise ReplayError("Simulate replay prefix artifact type is invalid")
        try:
            cloned = json_clone(dict(artifacts))
        except (TypeError, ValueError, RecursionError) as exc:
            raise ReplayError("Simulate replay prefix artifacts are not bounded JSON") from exc
        if not isinstance(cloned, dict):
            raise ReplayError("Simulate replay prefix artifacts are invalid")
        seeds[step_id] = cloned
    return seeds


def _normalized_defense_change(value: Any) -> str:
    if not isinstance(value, str):
        raise ReplayError("defense change metadata must be a string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ReplayError("defense change metadata must be bounded printable text")
    normalized = " ".join(value.split())
    if (
        not normalized
        or len(normalized) > _MAX_DEFENSE_CHANGE_CHARS
        or len(normalized.encode("utf-8")) > _MAX_DEFENSE_CHANGE_CHARS * 4
    ):
        raise ReplayError("defense change metadata must be bounded printable text")
    if (
        _SECRET_ASSIGNMENT.search(normalized)
        or _BEARER_VALUE.search(normalized)
        or _PRIVATE_KEY_BLOCK.search(normalized)
    ):
        raise ReplayError("defense change metadata must not contain secret-shaped values")
    return normalized


__all__ = ["PreparedReplay", "ReplayError", "ReplayRequest", "prepare_replay"]
