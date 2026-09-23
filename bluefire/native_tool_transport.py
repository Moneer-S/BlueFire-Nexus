"""Small transport adapters for the authenticated native-tool inspection call."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

from .contracts import ContractError
from .native_tool_candidate import validate_candidate_inspection
from .native_tool_execution_readiness import (
    reviewed_native_tool_descriptor,
    validated_compiled_tool_row,
)
from .native_tool_installations import NativeToolInstallation, canonical_native_tool_candidate
from .native_tool_readiness import validate_native_tool_inspection
from .runner_transport_errors import RunnerTransportError
from .util import canonical_json_bytes

INSPECTION_OPERATIONS = frozenset({"inspect_native_tool", "inspect_native_tool_candidate"})


def inspect_server_tool(
    server: Any,
    request: Mapping[str, Any],
    enrollment: Any,
    *,
    refusal: Callable[[str], BaseException],
) -> Mapping[str, Any]:
    candidate = request.get("operation") == "inspect_native_tool_candidate"
    field = "candidate" if candidate else "installation"
    supplied = server._require_payload(request, frozenset({field}))
    try:
        installation = (
            canonical_native_tool_candidate(supplied[field])
            if candidate
            else NativeToolInstallation.from_mapping(supplied[field]).to_dict()
        )
    except ContractError:
        raise refusal("request_invalid") from None
    server._verified_runner_binary_digest()
    inventory, canonical = server._validated_inventory(enrollment)
    try:
        if candidate:
            reviewed_native_tool_descriptor(
                inventory, canonical["actions"], action_id=installation["action_id"]
            )
        else:
            validated_compiled_tool_row(
                NativeToolInstallation.from_mapping(installation),
                inventory,
                canonical["actions"],
            )
    except (ContractError, TypeError, ValueError):
        raise refusal("runner_failure") from None
    inspect = getattr(
        server.runner, "inspect_native_tool_candidate" if candidate else "inspect_native_tool", None
    )
    if not callable(inspect):
        raise refusal("request_invalid")
    try:
        with server._verified_runner_binary_guard():
            result = inspect(installation)
        validate = validate_candidate_inspection if candidate else validate_native_tool_inspection
        return {"inspection": dict(validate(installation, result))}
    except (ContractError, OSError, RunnerTransportError, TypeError, ValueError):
        raise refusal("runner_failure") from None


def inspect_client_tool(
    client: Any, record: Mapping[str, Any], *, candidate: bool = False
) -> Mapping[str, Any]:
    document = (
        canonical_native_tool_candidate(record)
        if candidate
        else NativeToolInstallation.from_mapping(record).to_dict()
    )
    operation = "inspect_native_tool_candidate" if candidate else "inspect_native_tool"
    payload = client._call(
        operation,
        {"candidate" if candidate else "installation": document},
        task_id=client._random_task("inspect-native-tool"),
    )
    result = payload.get("inspection")
    if not isinstance(result, Mapping) or set(payload) != {"inspection"}:
        from .runner_transport_errors import RunnerAuthenticationError

        raise RunnerAuthenticationError("Native tool inspection response is invalid.")
    validate = validate_candidate_inspection if candidate else validate_native_tool_inspection
    return validate(document, result)


class NativeToolInspectionClient:
    """Shared optional inspection capability of the authenticated client."""

    def inspect_native_tool(self, record: Mapping[str, Any]) -> Mapping[str, Any]:
        return inspect_client_tool(self, record)

    def inspect_native_tool_candidate(self, record: Mapping[str, Any]) -> Mapping[str, Any]:
        return inspect_client_tool(self, record, candidate=True)


def inspect_subprocess_tool(
    runner: Any, record: Mapping[str, Any], *, candidate: bool = False
) -> Mapping[str, Any]:
    document = (
        canonical_native_tool_candidate(record)
        if candidate
        else NativeToolInstallation.from_mapping(record).to_dict()
    )
    field = "candidate" if candidate else "installation"
    command = "inspect-native-tool-candidate" if candidate else "inspect-native-tool"
    with tempfile.TemporaryDirectory(prefix="inspection-", dir=runner.work_root) as directory:
        path = Path(directory) / f"{field}.json"
        path.write_bytes(canonical_json_bytes(document) + b"\n")
        output = runner._invoke(
            [str(runner.runner_binary), command, f"--{field}", str(path), "--json"]
        )
    result = runner._decode_json(output, "native tool inspection")
    validate = validate_candidate_inspection if candidate else validate_native_tool_inspection
    return validate(document, result)


__all__ = [
    "inspect_client_tool",
    "inspect_server_tool",
    "reviewed_native_tool_descriptor",
]
