"""Strict terminal-status validation for runner watchdog recovery."""

from __future__ import annotations

import re
from typing import Any, cast

from .runner_transport_errors import RunnerTransportError

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_WATCHDOG_STATUS_SCHEMA = "bluefire.runner-watchdog-status.v2"
# A v1 watchdog may outlive the host during a rolling upgrade. Its private,
# already-published terminal record remains readable; every new v2
# cancellation must carry the complete proof fields below.
_LEGACY_WATCHDOG_STATUS_SCHEMA = "bluefire.runner-watchdog-status.v1"
_WATCHDOG_CANCELLATION_FIELDS = frozenset(
    {
        "cooperative_requested",
        "cooperative_acknowledged",
        "forced_tree_termination",
        "control_cleanup_verified",
    }
)


def validate_runner_watchdog_terminal_status(
    status: object,
    *,
    task_id: str,
) -> dict[str, Any]:
    """Return one exact v1/v2 terminal record or reject it fail closed."""

    if not isinstance(status, dict):
        raise RunnerTransportError("runner watchdog status is invalid")
    common = {
        "schema_version",
        "task_id",
        "state",
        "error_code",
        "watchdog_pid",
    }
    state = status.get("state")
    error_code = status.get("error_code")
    watchdog_pid = status.get("watchdog_pid")
    schema_version = status.get("schema_version")
    if (
        schema_version not in {_WATCHDOG_STATUS_SCHEMA, _LEGACY_WATCHDOG_STATUS_SCHEMA}
        or status.get("task_id") != task_id
        or state not in {"succeeded", "failed", "cancelled"}
        or isinstance(watchdog_pid, bool)
        or not isinstance(watchdog_pid, int)
        or not 1 <= watchdog_pid <= 2**31 - 1
    ):
        raise RunnerTransportError("runner watchdog status is invalid")
    if state == "succeeded":
        result_digest = status.get("result_digest")
        if (
            set(status) != common | {"result_digest"}
            or error_code is not None
            or not isinstance(result_digest, str)
            or _DIGEST.fullmatch(result_digest) is None
        ):
            raise RunnerTransportError("runner watchdog status is invalid")
    elif state == "cancelled":
        expected_fields = (
            common | _WATCHDOG_CANCELLATION_FIELDS
            if schema_version == _WATCHDOG_STATUS_SCHEMA
            else common
        )
        if (
            set(status) != expected_fields
            or error_code != "cancelled"
            or (
                schema_version == _WATCHDOG_STATUS_SCHEMA
                and (
                    any(
                        type(status.get(field)) is not bool
                        for field in _WATCHDOG_CANCELLATION_FIELDS
                    )
                    or (
                        status.get("cooperative_acknowledged") is True
                        and status.get("cooperative_requested") is not True
                    )
                    or status.get("control_cleanup_verified") is not True
                )
            )
        ):
            raise RunnerTransportError("runner watchdog status is invalid")
    elif (
        set(status) != common
        or not isinstance(error_code, str)
        or not 1 <= len(error_code) <= 64
        or error_code == "cancelled"
    ):
        raise RunnerTransportError("runner watchdog status is invalid")
    return cast(dict[str, Any], status)


__all__ = ["validate_runner_watchdog_terminal_status"]
