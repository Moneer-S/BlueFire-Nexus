"""Pure permission-bit objective binding and independent observation semantics."""

from __future__ import annotations

from typing import Any, Mapping

from .file_permissions import PERMISSION_FIELDS, permission_fields_valid

ACTION_ID = "sandbox.permission.chmod.v1"
MODES = frozenset({"0600", "0640", "0660", "0666"})


def permission_objective_evidence(
    action_id: str | None, parameters: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind the independent objective to compiled parameters, including aliases."""
    if action_id != ACTION_ID:
        return {}
    return {"permission_method": ACTION_ID, "expected_permission_mode": parameters.get("mode")}


def permission_observation_status(
    expected_mode: Any,
    output: Mapping[str, Any],
    error: Any,
    fields: Mapping[str, Any] | None,
) -> str:
    """Evaluate mode bits only; reported mode never substitutes for observation."""
    if not isinstance(expected_mode, str) or expected_mode not in MODES:
        return "unknown"
    if (
        (isinstance(error, Mapping) and error.get("code") == "objective_not_established")
        or output.get("requested_mode") != expected_mode
        or output.get("after_mode") != expected_mode
        or type(output.get("exit_code")) is not int
        or output["exit_code"] != 0
    ):
        return "not_established"
    if fields is None:
        return "unknown"
    permissions = {key: fields[key] for key in PERMISSION_FIELDS if key in fields}
    if permissions.get("permission_status") != "available" or not permission_fields_valid(
        permissions
    ):
        return "unknown"
    return "verified" if permissions["permission_mode_octal"] == expected_mode else "mismatch"
