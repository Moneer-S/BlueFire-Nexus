"""Reviewed v2 pivot reservations retained across proposal continuations.

A reservation consumes allowance before effects. Its presence does not claim
execution or success. Only the service's verified source and approval context
may seed a continuation; this data is not a bearer capability.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, cast

from .adaptive_execution_contract import AdaptiveExecution
from .util import content_hash, json_clone

SCHEMA = "bluefire.adaptive-retry-budget.v2"
_IDENTITY = {"step_id", "behavior_id", "action_id"}
_FIELDS = {
    "schema_version",
    "policy_digest",
    "maximum",
    "used",
    "remaining",
    "per_step",
    "reservations",
    "attempted_methods",
}


def _policy(policy: AdaptiveExecution) -> AdaptiveExecution:
    parsed = AdaptiveExecution.from_mapping(policy.to_dict())
    if parsed.schema_version != "bluefire.adaptive-execution.v2":
        raise ValueError("Explicit v2 policy is required for a pivot budget")
    return parsed


def _key(value: Mapping[str, Any]) -> tuple[str, str, str]:
    if set(value) != _IDENTITY or any(type(value[key]) is not str for key in _IDENTITY):
        raise ValueError("Pivot budget method identity is invalid")
    return value["step_id"], value["behavior_id"], value["action_id"]


def method_identity(step: Mapping[str, Any]) -> dict[str, str]:
    result = {key: step.get(key) for key in _IDENTITY}
    _key(result)
    return cast(dict[str, str], result)


def _document(
    policy: AdaptiveExecution,
    reservations: list[dict[str, str]],
    attempts: list[dict[str, str]],
) -> dict[str, Any]:
    counts = Counter(row["step_id"] for row in reservations)
    step_limits = {}
    for step in policy.steps:
        if type(step.max_retries) is not int:
            raise ValueError("An explicit per-step pivot limit is required")
        step_limits[step.step_id] = {
            "maximum": step.max_retries,
            "used": counts[step.step_id],
            "remaining": step.max_retries - counts[step.step_id],
        }
    return {
        "schema_version": SCHEMA,
        "policy_digest": content_hash(policy.to_dict()),
        "maximum": policy.max_retries,
        "used": len(reservations),
        "remaining": policy.max_retries - len(reservations),
        "per_step": step_limits,
        "reservations": reservations,
        "attempted_methods": attempts,
    }


def new_budget(policy: AdaptiveExecution) -> dict[str, Any]:
    return _document(_policy(policy), [], [])


def initial_budget(
    policy: AdaptiveExecution | None, replay: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    if policy is None or policy.schema_version != "bluefire.adaptive-execution.v2":
        if replay is not None and "adaptive_budget" in replay:
            raise ValueError("Legacy execution cannot inherit a v2 pivot budget")
        return None
    if replay is None:
        return new_budget(policy)
    return validate_budget(replay.get("adaptive_budget"), policy)


def validate_budget(value: Any, policy: AdaptiveExecution) -> dict[str, Any]:
    policy = _policy(policy)
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise ValueError("Pivot budget fields are invalid")
    permitted = {
        (step.step_id, method.behavior_id, method.action_id)
        for step in policy.steps
        for method in step.methods
    }
    checked: dict[str, list[dict[str, str]]] = {}
    for field, maximum in (
        ("reservations", policy.max_retries),
        ("attempted_methods", len(permitted)),
    ):
        rows = value.get(field)
        if not isinstance(rows, list) or len(rows) > maximum:
            raise ValueError("Pivot budget history exceeds its reviewed limit")
        seen = set()
        checked[field] = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise ValueError("Pivot budget method is invalid")
            key = _key(row)
            if key not in permitted or key in seen:
                raise ValueError("Pivot budget contains an unreviewed or repeated method")
            seen.add(key)
            checked[field].append(dict(row))
    reservations, attempts = checked["reservations"], checked["attempted_methods"]
    if not {_key(row) for row in reservations}.issubset({_key(row) for row in attempts}):
        raise ValueError("Pivot reservations cannot disappear from method history")
    reserved_counts = Counter(row["step_id"] for row in reservations)
    attempt_counts = Counter(row["step_id"] for row in attempts)
    if any(count > reserved_counts[step_id] + 1 for step_id, count in attempt_counts.items()):
        raise ValueError("Attempted alternatives must retain their pivot reservations")
    expected = _document(policy, reservations, attempts)
    # Canonical JSON comparison rejects bool-as-int and any forged aggregate.
    if content_hash(value) != content_hash(expected):
        raise ValueError("Pivot budget does not match its reviewed policy and reservations")
    if any(row["remaining"] < 0 for row in expected["per_step"].values()):
        raise ValueError("Pivot budget exceeds a reviewed step limit")
    return dict(json_clone(expected))


def record_attempt(
    value: Mapping[str, Any], policy: AdaptiveExecution, step: Mapping[str, Any]
) -> dict[str, Any]:
    budget = validate_budget(value, policy)
    if step.get("step_id") not in budget["per_step"]:
        return budget
    identity = method_identity(step)
    if identity not in budget["attempted_methods"]:
        budget["attempted_methods"].append(identity)
    return validate_budget(budget, policy)


def reserve_method(
    value: Mapping[str, Any], policy: AdaptiveExecution, step: Mapping[str, Any]
) -> dict[str, Any]:
    budget = validate_budget(value, policy)
    identity = method_identity(step)
    limit = budget["per_step"].get(identity["step_id"])
    if (
        limit is None
        or limit["remaining"] <= 0
        or budget["remaining"] <= 0
        or identity in budget["attempted_methods"]
    ):
        raise ValueError(
            "Reviewed pivot allowance is exhausted or the method was already attempted"
        )
    return validate_budget(
        _document(
            policy, [*budget["reservations"], identity], [*budget["attempted_methods"], identity]
        ),
        policy,
    )
