"""Finite operation identities carried across the sealed native boundary."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .runner_inventory import BUILTIN_RUNNER_ACTION_IDS
from .util import content_hash

REVIEWED_EXECUTION_SCHEMA = "bluefire.reviewed-execution.v1"
MAX_REVIEWED_OPERATIONS = 512
_IDENTIFIER = re.compile(r"[A-Za-z0-9._:/-]{1,128}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_OPERATION_FIELDS = frozenset({"step_id", "behavior_id", "action_id", "execution_binding_digest"})


class ReviewedExecutionError(ValueError):
    """A submitted operation differs from finite reviewed execution authority."""


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def canonical_reviewed_operation(value: Any, *, authorized: bool = False) -> dict[str, Any]:
    fields = _OPERATION_FIELDS | ({"authorization_digest"} if authorized else set())
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ReviewedExecutionError("reviewed operation fields are invalid")
    operation = dict(value)
    for field in ("step_id", "behavior_id", "action_id"):
        item = operation[field]
        if not isinstance(item, str) or _IDENTIFIER.fullmatch(item) is None:
            raise ReviewedExecutionError(f"reviewed operation {field} is invalid")
    digest = operation["execution_binding_digest"]
    if digest is not None and not _digest(digest):
        raise ReviewedExecutionError("reviewed operation execution binding digest is invalid")
    if authorized and not _digest(operation["authorization_digest"]):
        raise ReviewedExecutionError("reviewed operation authorization digest is invalid")
    return operation


def _key(operation: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        operation["step_id"],
        operation["behavior_id"],
        operation["action_id"],
        operation["execution_binding_digest"] or "",
    )


def canonical_reviewed_execution(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "authorization_digest",
        "operations",
    }:
        raise ReviewedExecutionError("reviewed execution fields are invalid")
    if value["schema_version"] != REVIEWED_EXECUTION_SCHEMA:
        raise ReviewedExecutionError("reviewed execution schema is unsupported")
    if not _digest(value["authorization_digest"]):
        raise ReviewedExecutionError("reviewed execution authorization digest is invalid")
    raw = value["operations"]
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_REVIEWED_OPERATIONS:
        raise ReviewedExecutionError("reviewed execution must contain 1..512 operations")
    operations = sorted((canonical_reviewed_operation(item) for item in raw), key=_key)
    if len({_key(item) for item in operations}) != len(operations):
        raise ReviewedExecutionError("reviewed execution contains duplicate operations")
    return {
        "schema_version": REVIEWED_EXECUTION_SCHEMA,
        "authorization_digest": value["authorization_digest"],
        "operations": operations,
    }


def reviewed_action_ids(profile: Mapping[str, Any]) -> set[str]:
    """Return exact logical actions and backing opcodes after checking every binding."""
    authority = canonical_reviewed_execution(profile["reviewed_execution"])
    native = profile.get("action_bindings", [])
    providers = profile.get("provider_bindings", [])
    bindings = [*native, *providers]
    required: set[str] = set()
    used_bindings: set[str] = set()
    for operation in authority["operations"]:
        action = operation["action_id"]
        required.add(action)
        matching = [
            binding
            for binding in bindings
            if binding["logical_behavior_id"] == operation["behavior_id"]
            and binding["logical_action_id"] == action
        ]
        digest = operation["execution_binding_digest"]
        if digest is None:
            if action not in BUILTIN_RUNNER_ACTION_IDS or matching:
                raise ReviewedExecutionError("reviewed operation is missing its execution binding")
        elif len(matching) != 1 or content_hash(matching[0]) != digest:
            raise ReviewedExecutionError(
                "reviewed operation execution binding differs from profile"
            )
        else:
            binding = matching[0]
            used_bindings.add(digest)
            if "runner_opcode" in binding:
                required.add(binding["runner_opcode"])
    if any(content_hash(binding) not in used_bindings for binding in bindings):
        raise ReviewedExecutionError("runner profile contains an unreviewed execution binding")
    if required.intersection(profile.get("control_blocked_actions", [])):
        raise ReviewedExecutionError("reviewed execution includes a blocked action or opcode")
    return required


def validate_reviewed_profile(profile: Mapping[str, Any]) -> None:
    if "reviewed_execution" not in profile:
        return
    expected = reviewed_action_ids(profile)
    allowed = profile.get("allowed_actions")
    if (
        not isinstance(allowed, list)
        or any(not isinstance(item, str) for item in allowed)
        or len(allowed) != len(set(allowed))
        or set(allowed) != expected
    ):
        raise ReviewedExecutionError(
            "runner allowed_actions must exactly cover reviewed operations"
        )


def validate_reviewed_manifest(manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    if "reviewed_execution" not in profile:
        if "reviewed_operation" in manifest:
            raise ReviewedExecutionError(
                "legacy runner profile has no reviewed execution authority"
            )
        return
    validate_reviewed_profile(profile)
    authority = canonical_reviewed_execution(profile["reviewed_execution"])
    selected = canonical_reviewed_operation(manifest.get("reviewed_operation"), authorized=True)
    if selected.pop("authorization_digest") != authority["authorization_digest"]:
        raise ReviewedExecutionError("reviewed operation authorization digest differs from profile")
    binding = manifest.get("execution_binding", manifest.get("provider_binding"))
    actual = {
        "step_id": manifest["step_id"],
        "behavior_id": manifest["behavior_id"],
        "action_id": manifest["action_id"],
        "execution_binding_digest": None if binding is None else content_hash(binding),
    }
    if selected != actual or selected not in authority["operations"]:
        raise ReviewedExecutionError("manifest operation is outside reviewed execution authority")
