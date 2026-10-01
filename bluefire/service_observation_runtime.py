"""Closed installation metadata for the fixed system/session-bus topology.

These declarations authenticate no process, socket, dependency or live state.
The runtime contract digest must eventually commit reviewed provider/daemon
builds and their dependency/configuration closure. No production contract has
completed that review. Neither an arbitrary digest nor a root-owned ELF is a
supported runtime. System/session endpoints and roles are implementation-fixed;
callers cannot supply a transport choice, PID, bus name or acquisition budget.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any, Mapping

from .contracts import ContractError
from .native_tool_installations import NativeToolInstallation

SCHEMA = "bluefire.owned-service-observation-runtime.v1"
SUPPORTED_CONTRACT_DIGESTS: frozenset[str] = frozenset()
_ROLES = {
    "broker": ("owned.service.observation.broker.v1", "owned.service.observation.broker.binary.v1"),
    "systemd_daemon": (
        "owned.service.observation.systemd.v1",
        "owned.service.observation.systemd.binary.v1",
    ),
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _text(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(f"invalid {label}")
    return value


def canonical_installation_reference(value: Any, label: str) -> dict[str, str]:
    """Preserve the existing four-field service installation reference."""
    if not isinstance(value, Mapping) or set(value) != {
        "installation_id",
        "path",
        "digest",
        "content_sha256",
    }:
        raise ContractError(f"{label} must contain exactly its declared fields")
    path = value["path"]
    if not isinstance(path, str) or not path.startswith("/") or "\\" in path:
        raise ContractError(f"invalid {label} path")
    parsed = PurePosixPath(path)
    if str(parsed) != path or any(part in {".", ".."} for part in parsed.parts):
        raise ContractError(f"invalid {label} path")
    if not re.fullmatch(r"/[A-Za-z0-9._+/-]+", path):
        raise ContractError(f"{label} path contains unsupported systemd ExecStart characters")
    return {
        "installation_id": _text(value["installation_id"], _ID, f"{label} ID"),
        "path": path,
        "digest": _text(value["digest"], _DIGEST, f"{label} digest"),
        "content_sha256": _text(value["content_sha256"], _DIGEST, f"{label} content digest"),
    }


def canonical_observation_runtime(value: Any) -> dict[str, Any]:
    """Validate metadata only; this does not recognize a supported installation."""
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "contract_digest",
        "system_broker_uid",
        "installations",
    }:
        raise ContractError("observation runtime must contain exactly its declared fields")
    if value["schema_version"] != SCHEMA:
        raise ContractError("unsupported observation runtime schema")
    uid = value["system_broker_uid"]
    if type(uid) is not int or not 0 <= uid < 2**32 - 1:
        raise ContractError("invalid system broker UID")
    records = value["installations"]
    if not isinstance(records, Mapping) or set(records) != set(_ROLES):
        raise ContractError("observation runtime requires exactly its two installation roles")
    references = {}
    for role, (_, tool_id) in _ROLES.items():
        reference = canonical_installation_reference(records[role], f"{role} installation")
        if reference["installation_id"] != tool_id:
            raise ContractError("observation runtime installation role differs")
        references[role] = reference
    return {
        "schema_version": SCHEMA,
        "contract_digest": _text(value["contract_digest"], _DIGEST, "runtime contract digest"),
        "system_broker_uid": uid,
        "installations": references,
    }


def require_supported_observation_runtime(value: Any) -> None:
    """Refuse acquisition for metadata lacking a compiled reviewed contract.

    This check supplies neither live identity nor an acquisition authority token.
    The native protected boundary must independently enforce its own inventory.
    """
    runtime = canonical_observation_runtime(value)
    if runtime["contract_digest"] not in SUPPORTED_CONTRACT_DIGESTS:
        raise ContractError("reviewed observation runtime is unavailable")


def _matches(reference: Mapping[str, Any], record: NativeToolInstallation) -> bool:
    actual = record.to_dict()
    return bool(
        actual["tool_id"] == reference["installation_id"]
        and actual["installation_location"] == reference["path"]
        and record.digest == reference["digest"]
        and actual["content_sha256"] == reference["content_sha256"]
    )


def validate_scope_installations(
    scope: Mapping[str, Any], records: Any, *, configured: bool
) -> None:
    """Bind exact profile references, retaining the legacy v1 validation rules."""
    if not isinstance(records, (tuple, list) if configured else list):
        raise ContractError(
            "configured profile has no native installation records"
            if configured
            else "sealed profile has no protected native installations"
        )
    for role in ("manager", "payload"):
        matches = []
        for raw in records:
            try:
                installed = NativeToolInstallation.from_mapping(raw)
            except ContractError as exc:
                if configured:
                    raise ContractError("configured native installation is invalid") from exc
                continue
            if _matches(scope["installations"][role], installed):
                matches.append(installed)
        if len(matches) != 1:
            raise ContractError(
                f"{role} installation does not exactly match one configured protected install"
                if configured
                else f"sealed profile does not contain the exact {role} installation"
            )
    if "observation_runtime" not in scope:
        return
    runtime = canonical_observation_runtime(scope["observation_runtime"])
    if len(records) > 16:
        raise ContractError("observation runtime profile exceeds its installation bound")
    parsed = [NativeToolInstallation.from_mapping(raw) for raw in records]
    adapters = [record.to_dict()["adapter_id"] for record in parsed]
    if len(set(adapters)) != len(adapters):
        raise ContractError("observation runtime profile has duplicate installation adapters")
    for role, (adapter_id, tool_id) in _ROLES.items():
        matches = [record for record in parsed if _matches(runtime["installations"][role], record)]
        if len(matches) != 1:
            raise ContractError("observation runtime installation differs from its profile")
        actual = matches[0].to_dict()
        if (
            actual["adapter_id"] != adapter_id
            or actual["tool_id"] != tool_id
            or actual["adapter_version"] != "1.0.0"
            or actual["platform"] != "linux"
            or actual["architecture"] != "x86_64"
        ):
            raise ContractError("observation runtime installation binding differs")
