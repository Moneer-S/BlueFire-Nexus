"""Explicit, finite method choices authored as part of a saved experiment."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


class AdaptiveContractError(ValueError):
    """An adaptive experiment contains malformed or expanded authority."""


def _object(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AdaptiveContractError(f"{context} must have exactly {', '.join(sorted(fields))}")
    return value


def _identity(value: Any, *, step: bool = False) -> str:
    pattern = r"[a-z][a-z0-9_]*" if step else r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*"
    if not isinstance(value, str) or len(value) > 200 or re.fullmatch(pattern, value) is None:
        raise AdaptiveContractError("adaptive method identity is invalid")
    return value


@dataclass(frozen=True, slots=True)
class AdaptiveMethod:
    behavior_id: str
    action_id: str

    @classmethod
    def from_mapping(cls, value: Any) -> "AdaptiveMethod":
        data = _object(value, {"behavior_id", "action_id"}, "adaptive method")
        return cls(_identity(data["behavior_id"]), _identity(data["action_id"]))

    def to_dict(self) -> dict[str, str]:
        return {"behavior_id": self.behavior_id, "action_id": self.action_id}


@dataclass(frozen=True, slots=True)
class AdaptiveStep:
    step_id: str
    methods: tuple[AdaptiveMethod, ...]
    max_retries: int | None = None

    @classmethod
    def from_mapping(
        cls, value: Any, *, schema_version: str = "bluefire.adaptive-execution.v1"
    ) -> "AdaptiveStep":
        if schema_version not in (
            "bluefire.adaptive-execution.v1",
            "bluefire.adaptive-execution.v2",
        ):
            raise AdaptiveContractError("adaptive execution schema version is unsupported")
        version_two = schema_version == "bluefire.adaptive-execution.v2"
        fields = {"step_id", "methods"} | ({"max_retries"} if version_two else set())
        data = _object(value, fields, "adaptive step")
        methods = data["methods"]
        if not isinstance(methods, list) or not 2 <= len(methods) <= 4:
            raise AdaptiveContractError("adaptive step must contain 2..4 exact methods")
        parsed = tuple(AdaptiveMethod.from_mapping(method) for method in methods)
        if len(set(parsed)) != len(parsed):
            raise AdaptiveContractError("adaptive step contains duplicate methods")
        maximum = data["max_retries"] if version_two else None
        if version_two and (
            type(maximum) is not int or not 1 <= maximum <= min(3, len(parsed) - 1)
        ):
            raise AdaptiveContractError(
                "adaptive step retry cap must be 1..min(3, methods minus one)"
            )
        return cls(_identity(data["step_id"], step=True), parsed, maximum)

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "step_id": self.step_id,
            "methods": [method.to_dict() for method in self.methods],
        }
        if self.max_retries is not None:
            document["max_retries"] = self.max_retries
        return document


@dataclass(frozen=True, slots=True)
class AdaptiveExecution:
    steps: tuple[AdaptiveStep, ...]
    eligible_outcomes: tuple[str, ...]
    max_retries: int
    on_provider_failure: str
    schema_version: str = "bluefire.adaptive-execution.v1"

    @classmethod
    def from_mapping(cls, value: Any) -> "AdaptiveExecution":
        data = _object(
            value,
            {"schema_version", "steps", "eligible_outcomes", "max_retries", "on_provider_failure"},
            "adaptive execution",
        )
        version = data["schema_version"]
        if version not in ("bluefire.adaptive-execution.v1", "bluefire.adaptive-execution.v2"):
            raise AdaptiveContractError("adaptive execution schema version is unsupported")
        raw_steps = data["steps"]
        if not isinstance(raw_steps, list) or not 1 <= len(raw_steps) <= 64:
            raise AdaptiveContractError("adaptive execution must contain 1..64 steps")
        steps = tuple(AdaptiveStep.from_mapping(step, schema_version=version) for step in raw_steps)
        if len({step.step_id for step in steps}) != len(steps):
            raise AdaptiveContractError("adaptive execution contains duplicate steps")
        outcomes = data["eligible_outcomes"]
        if (
            not isinstance(outcomes, list)
            or not 1 <= len(outcomes) <= 3
            or any(
                not isinstance(item, str) or item not in {"blocked", "failed", "partial"}
                for item in outcomes
            )
            or len(set(outcomes)) != len(outcomes)
        ):
            raise AdaptiveContractError(
                "adaptive eligible outcomes must be a unique nonempty subset of blocked, failed, partial"
            )
        maximum = data["max_retries"]
        if version == "bluefire.adaptive-execution.v1":
            if type(maximum) is not int or maximum != 1:
                raise AdaptiveContractError("adaptive execution v1 permits exactly one retry")
        elif (
            type(maximum) is not int
            or not 1 <= maximum <= 8
            or maximum > sum(step.max_retries or 0 for step in steps)
        ):
            raise AdaptiveContractError(
                "adaptive lineage retry cap must be 1..8 within the step caps"
            )
        if data["on_provider_failure"] not in ("stop", "deterministic"):
            raise AdaptiveContractError(
                "adaptive provider failure must stop or use configured deterministic fallback"
            )
        return cls(steps, tuple(outcomes), maximum, data["on_provider_failure"], version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "steps": [step.to_dict() for step in self.steps],
            "eligible_outcomes": list(self.eligible_outcomes),
            "max_retries": self.max_retries,
            "on_provider_failure": self.on_provider_failure,
        }


__all__ = ["AdaptiveContractError", "AdaptiveExecution", "AdaptiveMethod", "AdaptiveStep"]
