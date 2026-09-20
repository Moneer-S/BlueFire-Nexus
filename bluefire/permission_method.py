"""Bounded permission-bit method over the runner-owned transformed fixture."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .runner_provider_values import RunnerAdapterError
from .tool_adapters.chmod import CONTRACT

ACTION_ID = "sandbox.permission.chmod.v1"
BEHAVIOR_ID = "sandbox.permission.relax.v1"
FIXTURE_PATH = "fixtures/transformed.jsonl"
FIXTURE_TYPE = "artifact.sandbox.fixture.v1"
OUTPUT_TYPE = FIXTURE_TYPE
MODES = frozenset({"0600", "0640", "0660", "0666"})
_HEX = frozenset("0123456789abcdef")


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        raise RunnerAdapterError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _receipt(value: Any, label: str) -> str:
    return _sha(value, label)


def _fixture(bound_inputs: Mapping[str, Any]) -> tuple[Mapping[str, Any], str]:
    fixture = bound_inputs.get("fixture")
    if not isinstance(fixture, Mapping) or fixture.get("type") != FIXTURE_TYPE:
        raise RunnerAdapterError("permission method requires a typed transformed fixture")
    if fixture.get("path") != FIXTURE_PATH:
        raise RunnerAdapterError("permission method accepts only the transformed fixture path")
    _sha(fixture.get("sha256"), "fixture.sha256")
    size = fixture.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 64 * 1024 * 1024:
        raise RunnerAdapterError("fixture.size must be between 1 and 67108864 bytes")
    receipts = fixture.get("receipt_ids")
    if not isinstance(receipts, list) or len(receipts) != 1:
        raise RunnerAdapterError("fixture must carry exactly one source receipt ID")
    return fixture, _receipt(receipts[0], "fixture.receipt_ids[0]")


def adapt_permission_method(
    parameters: Mapping[str, Any],
    *,
    bound_inputs: Mapping[str, Any],
    available_receipt_ids: Sequence[str],
) -> dict[str, Any]:
    """Compile the reviewed logical ``mode`` into fixed runner parameters."""
    if set(parameters) != {"mode"}:
        raise RunnerAdapterError("permission method accepts only the reviewed mode parameter")
    mode = parameters.get("mode")
    if not isinstance(mode, str) or mode not in MODES:
        raise RunnerAdapterError("mode must be one of 0600, 0640, 0660, 0666")
    fixture, receipt_id = _fixture(bound_inputs)
    available = {_receipt(item, "available receipt ID") for item in available_receipt_ids}
    if receipt_id not in available:
        raise RunnerAdapterError("fixture receipt is not available in this run")
    return {
        "source_fixture_id": "transformed",
        "source_sha256": fixture["sha256"],
        "source_receipt_id": receipt_id,
        "source_size": fixture["size"],
        "mode": mode,
    }


def permission_outputs(
    parameters: Mapping[str, Any],
    *,
    bound_inputs: Mapping[str, Any],
    runner_output: Any,
    available_receipt_ids: Sequence[str],
) -> dict[str, Any]:
    """Validate the Rust outcome and return the typed permission artifact."""
    runner_params = adapt_permission_method(
        parameters, bound_inputs=bound_inputs, available_receipt_ids=available_receipt_ids
    )
    if tuple(available_receipt_ids) != (runner_params["source_receipt_id"],):
        raise RunnerAdapterError("permission output must retain exactly its source cleanup receipt")
    if not isinstance(runner_output, Mapping):
        raise RunnerAdapterError("permission method output must be an object")
    expected = {
        "artifact",
        "sha256",
        "size",
        "requested_mode",
        "before_mode",
        "after_mode",
        "tool",
        "exit_code",
        "stdout_bytes",
        "stderr_bytes",
    }
    if set(runner_output) != expected:
        raise RunnerAdapterError("permission method output shape is invalid")
    if runner_output.get("artifact") != FIXTURE_PATH:
        raise RunnerAdapterError("permission method output changed the bound fixture")
    output_sha = _sha(runner_output.get("sha256"), "permission output.sha256")
    if output_sha != runner_params["source_sha256"]:
        raise RunnerAdapterError("permission method output changed fixture content")
    size = runner_output.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size != runner_params["source_size"]:
        raise RunnerAdapterError("permission method output changed fixture size")
    if runner_output.get("requested_mode") != runner_params["mode"]:
        raise RunnerAdapterError("permission method output changed requested mode")
    for name in ("before_mode", "after_mode"):
        if not isinstance(runner_output.get(name), str) or not re.fullmatch(
            r"[0-7]{4}", runner_output[name]
        ):
            raise RunnerAdapterError(f"permission output {name} must be four octal digits")
    tool = runner_output.get("tool")
    if (
        not isinstance(tool, Mapping)
        or set(tool) != {"installation_digest", "adapter_contract_digest", "tool_version"}
        or not isinstance(tool.get("installation_digest"), str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", tool["installation_digest"])
        or tool.get("adapter_contract_digest") != CONTRACT.digest
        or not isinstance(tool.get("tool_version"), str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,63}", tool["tool_version"])
    ):
        raise RunnerAdapterError("permission output tool identity is invalid")
    for name, minimum, maximum in (
        ("exit_code", 0, 255),
        ("stdout_bytes", 0, 8192),
        ("stderr_bytes", 0, 8192),
    ):
        value = runner_output.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise RunnerAdapterError(f"permission output {name} is out of bounds")
    if runner_output["exit_code"] != 0:
        raise RunnerAdapterError("permission output must report successful completion")
    fixture_result = dict(bound_inputs["fixture"])
    fixture_result.update(
        {
            "type": OUTPUT_TYPE,
            "path": FIXTURE_PATH,
            "sha256": output_sha,
            "size": size,
            "requested_mode": runner_output["requested_mode"],
            "before_mode": runner_output["before_mode"],
            "after_mode": runner_output["after_mode"],
            "tool": dict(tool),
            "exit_code": runner_output["exit_code"],
            "stdout_bytes": runner_output["stdout_bytes"],
            "stderr_bytes": runner_output["stderr_bytes"],
            "receipt_ids": [runner_params["source_receipt_id"]],
        }
    )
    return {"fixture": fixture_result}


def existing_cleanup_receipts(
    action_id: str, params: Mapping[str, Any], available_receipt_ids: Sequence[str]
) -> tuple[str, ...]:
    """Declare existing ownership only for the fixed metadata-only opcode.

    This action creates no file. Its content and inode remain pinned by Rust;
    deleting the original receipt-owned fixture removes the permission effect.
    The coordinator must independently verify this receipt is committed in the
    current workspace before dispatch and before accepting the result. All
    file-creating actions still require fresh current-request receipts.
    """
    if action_id != ACTION_ID:
        return ()
    if set(params) != {
        "source_fixture_id",
        "source_sha256",
        "source_receipt_id",
        "source_size",
        "mode",
    }:
        raise RunnerAdapterError("permission cleanup binding is invalid")
    if params["source_fixture_id"] != "transformed":
        raise RunnerAdapterError("permission cleanup fixture is invalid")
    rebound = adapt_permission_method(
        {"mode": params["mode"]},
        bound_inputs={
            "fixture": {
                "type": FIXTURE_TYPE,
                "path": FIXTURE_PATH,
                "sha256": params["source_sha256"],
                "size": params["source_size"],
                "receipt_ids": [params["source_receipt_id"]],
            }
        },
        available_receipt_ids=available_receipt_ids,
    )
    return (rebound["source_receipt_id"],)


__all__ = [
    "ACTION_ID",
    "BEHAVIOR_ID",
    "FIXTURE_PATH",
    "MODES",
    "adapt_permission_method",
    "permission_outputs",
]
