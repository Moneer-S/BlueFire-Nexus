"""Execution-neutral validation for untrusted structured payloads."""

from __future__ import annotations

from typing import Any, Mapping

from .domain_errors import RunnerTransportError
from .util import content_hash

FORBIDDEN_EXECUTION_KEYS = frozenset(
    {
        "command",
        "cmd",
        "shell",
        "script",
        "script_body",
        "payload",
        "binary",
        "shellcode",
        "interpreter",
        "executable",
    }
)


class ExecutionContractError(ValueError):
    """Raised when untrusted data attempts to carry executable authority."""


def reject_forbidden_execution_keys(value: Any, *, path: str = "$") -> None:
    """Recursively reject free-form executable content in structured data."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().casefold().replace("-", "_")
            if normalized in FORBIDDEN_EXECUTION_KEYS:
                raise ExecutionContractError(f"forbidden execution field at {path}.{key}")
            reject_forbidden_execution_keys(child, path=f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, child in enumerate(value):
            reject_forbidden_execution_keys(child, path=f"{path}[{index}]")


def execution_task_identity(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> tuple[str, str]:
    """Bind one task identifier to the exact canonical execute payload."""

    request_hash = content_hash({"manifest": dict(manifest), "profile": dict(profile)})
    return "execute-" + request_hash.removeprefix("sha256:"), request_hash


def reject_runner_execution_keys(value: Any, *, path: str = "$") -> None:
    """Preserve the transport-facing error while sharing neutral validation."""

    try:
        reject_forbidden_execution_keys(value, path=path)
    except ExecutionContractError as exc:
        raise RunnerTransportError(str(exc)) from exc


__all__ = [
    "ExecutionContractError",
    "FORBIDDEN_EXECUTION_KEYS",
    "reject_forbidden_execution_keys",
]
