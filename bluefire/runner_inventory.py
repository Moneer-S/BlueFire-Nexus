"""Cycle-safe authority for the compiled built-in runner inventory."""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from types import MappingProxyType
from typing import Any

from .util import content_hash

RUNNER_INVENTORY_SCHEMA_VERSION = "bluefire.runner-inventory.v1"
RUNNER_ACTION_SDK_SCHEMA_VERSION = "bluefire.runner-action-sdk.v1"

# This is the single Python authority for the exact compiled contracts that the
# product can dispatch. Breaking native parameter or result semantics require a
# version change here before packaging, orchestration, or package activation can
# accept the runner.
BUILTIN_RUNNER_ACTION_VERSIONS: Mapping[str, str] = MappingProxyType(
    {
        "endpoint.discovery.processes.v1": "1.0.0",
        "endpoint.discovery.system.v1": "1.0.0",
        "sandbox.archive.tar.v1": "1.0.0",
        "sandbox.cleanup.v1": "1.1.0",
        "sandbox.collection.stage.v1": "2.0.0",
        "sandbox.discovery.list.v1": "2.0.0",
        "sandbox.discovery.metadata.v1": "2.0.0",
        "sandbox.discovery.recursive.v1": "1.0.0",
        "sandbox.export.local.v1": "2.0.0",
        "sandbox.fixture.create.v1": "2.0.0",
        "sandbox.fixture.transform.v1": "2.0.0",
        "sandbox.network.loopback.v1": "1.0.0",
        "sandbox.restricted.persistence-marker.v1": "1.0.0",
    }
)
BUILTIN_RUNNER_ACTION_IDS = frozenset(BUILTIN_RUNNER_ACTION_VERSIONS)

_ACTION_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_READINESS_VALUES = frozenset({"ready", "structural", "unavailable"})
_CANONICAL_INVENTORY_KEYS = frozenset(
    {
        "schema_version",
        "runner_id",
        "runner_version",
        "action_sdk_version",
        "receipt_protocol",
        "platform",
        "source_digest",
        "actions",
    }
)
_CANONICAL_ACTION_KEYS = frozenset({"action_id", "action_version", "readiness", "contract_digest"})
_MAX_ACTIONS = 512


class RunnerInventoryAuthorityError(ValueError):
    """Raised when runner action identity cannot satisfy local authority."""


def validate_builtin_action_inventory(
    inventory: Mapping[str, Any],
    *,
    required_action_ids: Collection[str],
    require_exact_catalog: bool = False,
) -> Mapping[str, Mapping[str, str]]:
    """Validate raw descriptors or a canonical inventory snapshot.

    The native CLI returns full raw action descriptors. Those rows carry the
    action-SDK schema and their canonical digest is derived here. Persisted
    approval snapshots contain only normalized identity fields, so those rows
    must instead carry exact source and contract digests.
    """

    if not isinstance(inventory, Mapping):
        raise RunnerInventoryAuthorityError("runner inventory must be an object")
    if inventory.get("schema_version") != RUNNER_INVENTORY_SCHEMA_VERSION:
        raise RunnerInventoryAuthorityError("runner inventory schema is unsupported")
    if inventory.get("action_sdk_version") != RUNNER_ACTION_SDK_SCHEMA_VERSION:
        raise RunnerInventoryAuthorityError("runner inventory action SDK is unsupported")
    raw_actions = inventory.get("actions")
    if not isinstance(raw_actions, list) or not raw_actions or len(raw_actions) > _MAX_ACTIONS:
        raise RunnerInventoryAuthorityError("runner inventory action list is invalid")

    requested = frozenset(required_action_ids)
    if not requested or not requested <= BUILTIN_RUNNER_ACTION_IDS:
        raise RunnerInventoryAuthorityError("required runner action set is invalid")

    canonical_shape = "source_digest" in inventory or any(
        isinstance(row, Mapping) and "contract_digest" in row for row in raw_actions
    )
    if canonical_shape:
        if set(inventory) != _CANONICAL_INVENTORY_KEYS or not _valid_digest(
            inventory.get("source_digest")
        ):
            raise RunnerInventoryAuthorityError("canonical runner inventory digest is invalid")

    normalized: dict[str, Mapping[str, str]] = {}
    for row in raw_actions:
        if not isinstance(row, Mapping):
            raise RunnerInventoryAuthorityError("runner action descriptor is invalid")
        action_id = row.get("action_id")
        action_version = row.get("action_version")
        readiness = row.get("readiness")
        if (
            not isinstance(action_id, str)
            or _ACTION_ID.fullmatch(action_id) is None
            or not isinstance(action_version, str)
            or _SEMVER.fullmatch(action_version) is None
            or not isinstance(readiness, str)
            or readiness not in _READINESS_VALUES
            or action_id in normalized
        ):
            raise RunnerInventoryAuthorityError("runner action identity is invalid")

        if canonical_shape:
            contract_digest = row.get("contract_digest")
            if set(row) != _CANONICAL_ACTION_KEYS or not _valid_digest(contract_digest):
                raise RunnerInventoryAuthorityError("runner action contract digest is invalid")
            digest = str(contract_digest)
        else:
            if row.get("schema_version") != RUNNER_ACTION_SDK_SCHEMA_VERSION:
                raise RunnerInventoryAuthorityError("runner action SDK schema is unsupported")
            try:
                digest = content_hash(dict(row))
            except (TypeError, ValueError) as exc:
                raise RunnerInventoryAuthorityError(
                    "runner action descriptor is not canonical JSON"
                ) from exc
            if not _valid_digest(digest):  # Defensive assertion at the trust boundary.
                raise RunnerInventoryAuthorityError("runner action contract digest is invalid")

        normalized[action_id] = MappingProxyType(
            {
                "action_id": action_id,
                "action_version": action_version,
                "readiness": readiness,
                "contract_digest": digest,
            }
        )

    observed = frozenset(normalized)
    if require_exact_catalog and observed != BUILTIN_RUNNER_ACTION_IDS:
        raise RunnerInventoryAuthorityError("runner action catalog is not exact")
    if not requested <= observed:
        raise RunnerInventoryAuthorityError("runner inventory lacks required actions")

    checked = BUILTIN_RUNNER_ACTION_IDS if require_exact_catalog else requested
    for action_id in checked:
        row = normalized[action_id]
        if row["action_version"] != BUILTIN_RUNNER_ACTION_VERSIONS[action_id]:
            raise RunnerInventoryAuthorityError("runner action version is incompatible")
        if row["readiness"] != "ready":
            raise RunnerInventoryAuthorityError("runner action is not ready")
        if not _valid_digest(row["contract_digest"]):
            raise RunnerInventoryAuthorityError("runner action contract digest is invalid")

    return MappingProxyType(normalized)


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


__all__ = [
    "BUILTIN_RUNNER_ACTION_IDS",
    "BUILTIN_RUNNER_ACTION_VERSIONS",
    "RUNNER_ACTION_SDK_SCHEMA_VERSION",
    "RUNNER_INVENTORY_SCHEMA_VERSION",
    "RunnerInventoryAuthorityError",
    "validate_builtin_action_inventory",
]
