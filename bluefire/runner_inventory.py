"""Cycle-safe authority for the compiled built-in runner inventory."""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from types import MappingProxyType
from typing import Any

from .util import canonical_json_bytes, content_hash

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
        "sandbox.execution.native-canary.v1": "1.0.0",
        "sandbox.export.local.v1": "2.0.0",
        "sandbox.fixture.create.v1": "2.0.0",
        "sandbox.fixture.transform.v1": "2.0.0",
        "sandbox.identity-material.inspect.v1": "1.0.0",
        "sandbox.identity-material.seed.v1": "1.0.0",
        "sandbox.network.loopback.v1": "1.0.0",
        "sandbox.observability.variant.v1": "1.0.0",
        "sandbox.peer.handoff.v1": "1.0.0",
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
_CANONICAL_PROVIDER_INVENTORY_KEYS = _CANONICAL_INVENTORY_KEYS | {"provider_runtimes"}
_CANONICAL_ACTION_KEYS = frozenset({"action_id", "action_version", "readiness", "contract_digest"})
_CANONICAL_PROVIDER_RUNTIME_KEYS = frozenset(
    {
        "kind",
        "abi_version",
        "runtime_version",
        "readiness",
        "no_host_imports",
        "hard_limits",
        "contract_digest",
    }
)
_PROVIDER_LIMIT_KEYS = frozenset(
    {
        "max_module_bytes",
        "max_memory_bytes",
        "max_input_bytes",
        "max_output_bytes",
        "fuel",
    }
)
_MAX_ACTIONS = 512
_MAX_PROVIDER_RUNTIMES = 8
_MAX_INVENTORY_BYTES = 2 * 1024 * 1024
_INVENTORY_PLATFORMS = frozenset({"linux", "macos", "windows"})


class RunnerInventoryAuthorityError(ValueError):
    """Raised when runner action identity cannot satisfy local authority."""


def canonical_runner_inventory(inventory: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate and normalize one bounded, identity-bearing runner inventory."""

    if not isinstance(inventory, Mapping):
        raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
    if inventory.get("schema_version") != RUNNER_INVENTORY_SCHEMA_VERSION:
        raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
    runner_id = _inventory_token(inventory.get("runner_id"), maximum=128)
    runner_version = _inventory_token(inventory.get("runner_version"), maximum=128)
    action_sdk_version = _inventory_token(inventory.get("action_sdk_version"), maximum=128)
    receipt_protocol = _inventory_token(inventory.get("receipt_protocol"), maximum=128)
    platform = inventory.get("platform")
    raw_actions = inventory.get("actions")
    raw_provider_runtimes = inventory.get("provider_runtimes", ())
    if (
        runner_id is None
        or runner_version is None
        or action_sdk_version is None
        or receipt_protocol is None
        or not isinstance(platform, str)
        or platform not in _INVENTORY_PLATFORMS
        or not isinstance(raw_actions, list)
        or len(raw_actions) > _MAX_ACTIONS
        or not isinstance(raw_provider_runtimes, (list, tuple))
        or len(raw_provider_runtimes) > _MAX_PROVIDER_RUNTIMES
    ):
        raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")

    try:
        source_bytes = canonical_json_bytes(dict(inventory))
    except (TypeError, ValueError) as exc:
        raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.") from exc
    if len(source_bytes) > _MAX_INVENTORY_BYTES:
        raise RunnerInventoryAuthorityError("Runner inventory exceeds the readiness size limit.")

    actions: list[dict[str, str]] = []
    action_ids: set[str] = set()
    for raw_action in raw_actions:
        if not isinstance(raw_action, Mapping):
            raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
        action_id = _inventory_token(raw_action.get("action_id"), maximum=200)
        action_version = _inventory_token(raw_action.get("action_version"), maximum=64)
        readiness = raw_action.get("readiness")
        if (
            action_id is None
            or _ACTION_ID.fullmatch(action_id) is None
            or action_version is None
            or not isinstance(readiness, str)
            or readiness not in _READINESS_VALUES
            or action_id in action_ids
        ):
            raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
        action_ids.add(action_id)
        actions.append(
            {
                "action_id": action_id,
                "action_version": action_version,
                "readiness": readiness,
                "contract_digest": content_hash(dict(raw_action)),
            }
        )
    actions.sort(key=lambda item: item["action_id"])

    provider_runtimes: list[dict[str, Any]] = []
    provider_runtime_ids: set[tuple[str, str]] = set()
    for raw_runtime in raw_provider_runtimes:
        if (
            not isinstance(raw_runtime, Mapping)
            or set(raw_runtime) != _CANONICAL_PROVIDER_RUNTIME_KEYS
        ):
            raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
        kind = _inventory_token(raw_runtime.get("kind"), maximum=32)
        abi_version = _inventory_token(raw_runtime.get("abi_version"), maximum=128)
        runtime_version = _inventory_token(raw_runtime.get("runtime_version"), maximum=128)
        readiness = raw_runtime.get("readiness")
        no_host_imports = raw_runtime.get("no_host_imports")
        raw_limits = raw_runtime.get("hard_limits")
        contract_digest = raw_runtime.get("contract_digest")
        if (
            kind != "wasm"
            or abi_version is None
            or _ACTION_ID.fullmatch(abi_version) is None
            or runtime_version is None
            or readiness not in _READINESS_VALUES
            or no_host_imports is not True
            or not isinstance(raw_limits, Mapping)
            or set(raw_limits) != _PROVIDER_LIMIT_KEYS
            or not _valid_digest(contract_digest)
        ):
            raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
        identity = (kind, abi_version)
        if identity in provider_runtime_ids:
            raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
        provider_runtime_ids.add(identity)
        limits: dict[str, int] = {}
        for field in sorted(_PROVIDER_LIMIT_KEYS):
            limit = raw_limits.get(field)
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or not 1 <= limit <= (1 << 63) - 1
            ):
                raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
            limits[field] = limit
        contract = {
            "kind": kind,
            "abi_version": abi_version,
            "runtime_version": runtime_version,
            "readiness": readiness,
            "no_host_imports": no_host_imports,
            "hard_limits": limits,
        }
        if content_hash(contract) != contract_digest:
            raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
        provider_runtimes.append({**contract, "contract_digest": contract_digest})
    provider_runtimes.sort(key=lambda item: (str(item["kind"]), str(item["abi_version"])))

    canonical: dict[str, Any] = {
        "schema_version": RUNNER_INVENTORY_SCHEMA_VERSION,
        "runner_id": runner_id,
        "runner_version": runner_version,
        "action_sdk_version": action_sdk_version,
        "receipt_protocol": receipt_protocol,
        "platform": platform,
        "source_digest": content_hash(dict(inventory)),
        "actions": actions,
    }
    if "provider_runtimes" in inventory:
        canonical["provider_runtimes"] = provider_runtimes
    try:
        encoded = canonical_json_bytes(canonical)
    except (TypeError, ValueError) as exc:
        raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.") from exc
    if len(encoded) > _MAX_INVENTORY_BYTES:
        raise RunnerInventoryAuthorityError("Runner inventory exceeds the readiness size limit.")
    return canonical


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
        if set(inventory) not in {
            _CANONICAL_INVENTORY_KEYS,
            _CANONICAL_PROVIDER_INVENTORY_KEYS,
        } or not _valid_digest(inventory.get("source_digest")):
            raise RunnerInventoryAuthorityError("canonical runner inventory digest is invalid")
        _validate_canonical_provider_runtimes(inventory.get("provider_runtimes", []))

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


def _validate_canonical_provider_runtimes(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 8:
        raise RunnerInventoryAuthorityError("canonical provider-runtime inventory is invalid")
    identities: set[tuple[str, str]] = set()
    previous: tuple[str, str] | None = None
    for row in value:
        if not isinstance(row, Mapping) or set(row) != _CANONICAL_PROVIDER_RUNTIME_KEYS:
            raise RunnerInventoryAuthorityError("canonical provider-runtime inventory is invalid")
        kind = row.get("kind")
        abi_version = row.get("abi_version")
        runtime_version = row.get("runtime_version")
        readiness = row.get("readiness")
        no_host_imports = row.get("no_host_imports")
        limits = row.get("hard_limits")
        contract_digest = row.get("contract_digest")
        identity = (str(kind), str(abi_version))
        if (
            kind != "wasm"
            or not isinstance(abi_version, str)
            or _ACTION_ID.fullmatch(abi_version) is None
            or not isinstance(runtime_version, str)
            or not runtime_version
            or readiness not in _READINESS_VALUES
            or no_host_imports is not True
            or not isinstance(limits, Mapping)
            or set(limits) != _PROVIDER_LIMIT_KEYS
            or any(
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or not 1 <= limit <= (1 << 63) - 1
                for limit in limits.values()
            )
            or not _valid_digest(contract_digest)
            or identity in identities
            or (previous is not None and previous >= identity)
        ):
            raise RunnerInventoryAuthorityError("canonical provider-runtime inventory is invalid")
        contract = {key: row[key] for key in row if key != "contract_digest"}
        if content_hash(contract) != contract_digest:
            raise RunnerInventoryAuthorityError("canonical provider-runtime digest is invalid")
        identities.add(identity)
        previous = identity


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _inventory_token(value: Any, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not 1 <= len(token) <= maximum or any(ord(character) < 32 for character in token):
        return None
    return token


__all__ = [
    "BUILTIN_RUNNER_ACTION_IDS",
    "BUILTIN_RUNNER_ACTION_VERSIONS",
    "RUNNER_ACTION_SDK_SCHEMA_VERSION",
    "RUNNER_INVENTORY_SCHEMA_VERSION",
    "RunnerInventoryAuthorityError",
    "canonical_runner_inventory",
    "validate_builtin_action_inventory",
]
