"""Pure binding and inspection gate for one reviewed native action."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Mapping

from .contracts import ContractError
from .native_tool_installations import NativeToolInstallation
from .native_tool_readiness import validate_native_tool_inspection
from .tool_adapters.chmod import ADAPTER_ID, CONTRACT, TOOL_ID, VERSION
from .util import content_hash

_BINDING_FIELDS = frozenset({"adapter_id", "adapter_version", "adapter_contract_digest", "tool_id"})


def _refuse(message: str) -> ContractError:
    return ContractError(f"native tool execution readiness: {message}")


def validated_compiled_tool_row(
    installation: NativeToolInstallation,
    raw_inventory: Mapping[str, Any],
    canonical_rows: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    """Validate the fixed compiled chmod binding without inspecting the host."""

    if installation is not None and not isinstance(installation, NativeToolInstallation):
        raise _refuse("installation record is invalid")
    descriptor, canonical = reviewed_native_tool_descriptor(
        raw_inventory, canonical_rows, action_id=ADAPTER_ID
    )
    if installation is None:
        raise _refuse("installation record is invalid")
    record = installation.to_dict()
    if record["adapter_id"] != ADAPTER_ID or record["platform"] != "linux":
        raise _refuse("installation binding is unsupported")
    installation.check_binding(
        expected_adapter_id=ADAPTER_ID,
        expected_adapter_version=VERSION,
        expected_adapter_contract_digest=CONTRACT.digest,
        expected_tool_id=TOOL_ID,
        expected_platform="linux",
        expected_architecture=record["architecture"],
    )
    return record, canonical


def reviewed_native_tool_descriptor(
    raw_inventory: Mapping[str, Any],
    canonical_rows: Sequence[Mapping[str, Any]],
    *,
    action_id: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Validate the exact compiled descriptor before setup identity is known."""

    if action_id != ADAPTER_ID:
        raise _refuse("compiled native action is unsupported")
    if not isinstance(raw_inventory, Mapping) or raw_inventory.get("platform") != "linux":
        raise _refuse("runner inventory platform is unsupported")
    raw_actions = raw_inventory.get("actions")
    if not isinstance(raw_actions, list):
        raise _refuse("runner inventory actions are invalid")
    if not isinstance(canonical_rows, (list, tuple)):
        raise _refuse("canonical action rows are invalid")
    descriptors = [
        action
        for action in raw_actions
        if isinstance(action, Mapping) and action.get("action_id") == ADAPTER_ID
    ]
    if len(descriptors) != 1:
        raise _refuse("compiled native action is missing or duplicated")
    descriptor = descriptors[0]
    binding = descriptor.get("native_tool_binding")
    if (
        not isinstance(binding, Mapping)
        or set(binding) != _BINDING_FIELDS
        or dict(binding)
        != {
            "adapter_id": ADAPTER_ID,
            "adapter_version": VERSION,
            "adapter_contract_digest": CONTRACT.digest,
            "tool_id": TOOL_ID,
        }
    ):
        raise _refuse("compiled native action binding is invalid")
    raw_readiness = descriptor.get("readiness")
    if (
        descriptor.get("action_version") != VERSION
        or not isinstance(raw_readiness, str)
        or raw_readiness not in {"structural", "ready"}
    ):
        raise _refuse("compiled native action version is invalid")
    matching_rows = [
        row
        for row in canonical_rows
        if isinstance(row, Mapping) and row.get("action_id") == ADAPTER_ID
    ]
    if len(matching_rows) != 1:
        raise _refuse("canonical native action row is missing or duplicated")
    canonical = matching_rows[0]
    if (
        canonical.get("action_version") != VERSION
        or canonical.get("readiness") != raw_readiness
        or canonical.get("readiness") not in {"structural", "ready"}
        or canonical.get("contract_digest") != content_hash(dict(descriptor))
    ):
        raise _refuse("canonical native action row is not eligible")
    return descriptor, canonical


def inspected_tool_rows(
    runner: Any,
    installations: Sequence[NativeToolInstallation],
    raw_inventory: Mapping[str, Any],
    canonical_rows: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Return ready overrides only after host inspection verifies each record.

    The caller owns transport identity and inventory freshness.  This helper has
    no filesystem, process, or network access of its own.
    """

    if not isinstance(installations, (list, tuple)):
        raise _refuse("installation records are invalid")
    if not installations:
        return {}
    if len(installations) > 16:
        raise _refuse("installation records exceed the limit")
    if any(not isinstance(item, NativeToolInstallation) for item in installations):
        raise _refuse("installation record is invalid")
    records = [item.to_dict() for item in installations]
    adapter_ids = [str(item["adapter_id"]) for item in records]
    if len(adapter_ids) != len(set(adapter_ids)):
        raise _refuse("installation records are duplicated")

    rows: dict[str, dict[str, Any]] = {}
    for installation, record in zip(installations, records, strict=True):
        if record["adapter_id"] in rows:
            raise _refuse("installation adapter is duplicated")
        record, canonical = validated_compiled_tool_row(installation, raw_inventory, canonical_rows)
        inspector = getattr(runner, "inspect_native_tool", None)
        if not callable(inspector):
            raise _refuse("native tool inspection is unavailable")
        try:
            inspected = validate_native_tool_inspection(record, inspector(record))
        except (ContractError, OSError, TypeError, ValueError):
            raise _refuse("native tool inspection failed") from None
        if inspected.get("status") != "ready" or inspected.get("code") != "verified":
            raise _refuse("native tool inspection did not verify the installation")
        rows[ADAPTER_ID] = {
            **dict(canonical),
            "readiness": "ready",
            "native_tool_installation_digest": installation.digest,
            "tool_inspection": inspected,
        }
    return rows


__all__ = [
    "inspected_tool_rows",
    "reviewed_native_tool_descriptor",
    "validated_compiled_tool_row",
]
