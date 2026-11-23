"""Strict identity records for reviewed, preinstalled native tools.

This module parses and hashes setup metadata only.  It deliberately does not
inspect the filesystem, establish readiness, or dispatch an executable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, cast

from .contracts import ContractError
from .util import content_hash, json_clone

SCHEMA = "bluefire.native-tool-installation.v1"
_FIELDS = frozenset(
    {
        "schema_version",
        "adapter_id",
        "adapter_version",
        "adapter_contract_digest",
        "tool_id",
        "tool_version",
        "platform",
        "architecture",
        "content_sha256",
        "size_bytes",
        "installation_location",
    }
)
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$", re.ASCII)
_TOOL_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$", re.ASCII)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ARCHITECTURES = frozenset({"x86_64", "aarch64"})
_MAX_SIZE = 128 * 1024 * 1024
CANDIDATE_SCHEMA = "bluefire.native-tool-candidate.v1"


def _text(value: Any, name: str, pattern: re.Pattern[str]) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 256
        or pattern.fullmatch(value) is None
        or any(ord(char) < 32 for char in value)
    ):
        raise ContractError(f"native tool installation {name} is invalid")
    return value


def _location(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise ContractError("native tool installation location is invalid")
    if not value.startswith("/") or value.startswith("//"):
        raise ContractError("native tool installation location must be absolute POSIX")
    if len(value) > 1 and value.endswith("/"):
        raise ContractError("native tool installation location is not canonical")
    if "\\" in value or any(
        ord(char) < 32 or 127 <= ord(char) < 160 or 0xD800 <= ord(char) <= 0xDFFF for char in value
    ):
        raise ContractError("native tool installation location contains unsafe characters")
    components = value.split("/")[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        raise ContractError("native tool installation location is not canonical")
    return value


def canonical_native_tool_candidate(value: Any) -> dict[str, str]:
    """Validate read-only setup inputs without claiming installed identity."""
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "action_id",
        "installation_location",
        "tool_version",
    }:
        raise ContractError("native tool candidate has an unsupported shape")
    if value["schema_version"] != CANDIDATE_SCHEMA:
        raise ContractError("native tool candidate schema is unsupported")
    return {
        "schema_version": CANDIDATE_SCHEMA,
        "action_id": _text(value["action_id"], "action_id", _STABLE_ID),
        "installation_location": _location(value["installation_location"]),
        "tool_version": _text(value["tool_version"], "tool_version", _TOOL_VERSION),
    }


@dataclass(frozen=True, slots=True, repr=False)
class NativeToolInstallation:
    """Immutable setup identity; trust is supplied by the caller's setup path."""

    _canonical: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> "NativeToolInstallation":
        if not isinstance(value, Mapping) or set(value) != _FIELDS:
            raise ContractError("native tool installation must contain exactly its declared fields")
        if value["schema_version"] != SCHEMA:
            raise ContractError("native tool installation schema is unsupported")
        data = {
            "schema_version": SCHEMA,
            "adapter_id": _text(value["adapter_id"], "adapter_id", _STABLE_ID),
            "adapter_version": _text(value["adapter_version"], "adapter_version", _VERSION),
            "adapter_contract_digest": _text(
                value["adapter_contract_digest"], "adapter_contract_digest", _DIGEST
            ),
            "tool_id": _text(value["tool_id"], "tool_id", _STABLE_ID),
            "tool_version": _text(value["tool_version"], "tool_version", _TOOL_VERSION),
            "platform": value["platform"],
            "architecture": value["architecture"],
            "content_sha256": _text(value["content_sha256"], "content_sha256", _DIGEST),
            "size_bytes": value["size_bytes"],
            "installation_location": _location(value["installation_location"]),
        }
        if data["platform"] != "linux":
            raise ContractError("native tool installation platform is unsupported")
        if (
            not isinstance(data["platform"], str)
            or not isinstance(data["architecture"], str)
            or data["architecture"] not in _ARCHITECTURES
        ):
            raise ContractError("native tool installation architecture is unsupported")
        if (
            isinstance(data["size_bytes"], bool)
            or not isinstance(data["size_bytes"], int)
            or not 1 <= data["size_bytes"] <= _MAX_SIZE
        ):
            raise ContractError("native tool installation size_bytes is invalid")
        return cls(MappingProxyType(json_clone(data)))

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json_clone(dict(self._canonical)))

    @property
    def digest(self) -> str:
        return content_hash(dict(self._canonical))

    def check_binding(
        self,
        *,
        expected_adapter_id: str,
        expected_adapter_version: str,
        expected_adapter_contract_digest: str,
        expected_tool_id: str,
        expected_platform: str,
        expected_architecture: str,
    ) -> None:
        expected = {
            "adapter_id": expected_adapter_id,
            "adapter_version": expected_adapter_version,
            "adapter_contract_digest": expected_adapter_contract_digest,
            "tool_id": expected_tool_id,
            "platform": expected_platform,
            "architecture": expected_architecture,
        }
        for field, value in expected.items():
            if self._canonical[field] != value:
                raise ContractError(f"native tool installation {field} does not match binding")


__all__ = ["NativeToolInstallation", "SCHEMA"]


def canonical_native_tool_installations(
    value: Any, *, platform: str, allowed_actions: Any
) -> list[dict[str, Any]]:
    """Seal finite setup records; compiled-method admission remains runner-owned."""
    if not isinstance(value, (list, tuple)) or len(value) > 16:
        raise ContractError("native tool installations must be a list of at most 16 records")
    if not value:
        return []
    if not isinstance(allowed_actions, (list, tuple)) or any(
        not isinstance(action, str) for action in allowed_actions
    ):
        raise ContractError("native tool installations require explicit allowed actions")
    records = [NativeToolInstallation.from_mapping(item).to_dict() for item in value]
    identities = set()
    for record in records:
        if record["platform"] != platform or record["adapter_id"] not in allowed_actions:
            raise ContractError("native tool installation is outside its runner profile")
        if record["adapter_id"] in identities:
            raise ContractError("native tool installation adapter is duplicated")
        identities.add(record["adapter_id"])
    return sorted(records, key=lambda record: str(record["adapter_id"]))
