"""Versioned review metadata for fixed, supervised native tool adapters.

Parsing establishes shape, never trust, installation readiness, or approval.
Only reviewed compiled adapters may consume this contract. There is deliberately
no script, executable path, argument vector, installer, or dispatch function.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, cast
from urllib.parse import urlsplit

from ..contracts import ContractError
from ..util import canonical_json_bytes
from .parameters import normalized_parameters, parameter_specs

SCHEMA = "bluefire.tool-adapter.v1"
_ID = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_LIMITS = {
    "timeout_ms": 3_600_000,
    "max_input_bytes": 64 * 1024 * 1024,
    "max_output_bytes": 64 * 1024 * 1024,
    "max_diagnostic_bytes": 1024 * 1024,
    "max_artifacts": 1024,
    "max_artifact_bytes": 64 * 1024 * 1024,
    "max_processes": 64,
    "max_attempts": 16,
}


def _object(value: Any, fields: str, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields.split()):
        raise ContractError(f"{label} must contain exactly its declared fields")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or value != value.strip()
        or any(ord(char) < 32 for char in value)
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise ContractError(f"{label} is invalid")
    return value


def _choices(value: Any, choices: set[str], label: str) -> None:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or item not in choices for item in value)
        or len(value) != len(set(value))
    ):
        raise ContractError(f"{label} must contain distinct supported choices")


@dataclass(frozen=True, slots=True)
class ToolAdapterContract:
    """Immutable canonical snapshot: caller mutation cannot change its digest."""

    _canonical: bytes

    @classmethod
    def from_mapping(cls, value: Any) -> ToolAdapterContract:
        data = _object(
            value,
            "schema_version adapter_id adapter_version tool_id source action_id action_version "
            "behavior_id implementation_id implementation_version compatibility parameters "
            "supervision limits result",
            "tool adapter",
        )
        if data["schema_version"] != SCHEMA:
            raise ContractError("unsupported tool-adapter schema")
        for name in ("adapter_id", "tool_id", "action_id", "behavior_id", "implementation_id"):
            _text(data[name], name, _ID)
        for name in ("adapter_version", "action_version", "implementation_version"):
            _text(data[name], name, _VERSION)
        source = _object(
            data["source"], "project reference revision content_digest license", "source"
        )
        for name in ("project", "reference", "revision", "license"):
            _text(source[name], f"source {name}")
        try:
            reference = urlsplit(source["reference"])
            hostname = reference.hostname or ""
            port = reference.port
            try:
                ipaddress.ip_address(hostname)
                valid_host = "%" not in hostname
            except ValueError:
                ascii_host = hostname.encode("idna").decode("ascii").removesuffix(".")
                labels = ascii_host.split(".")
                valid_host = (
                    len(ascii_host) <= 253
                    and len(labels) >= 2
                    and all(
                        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                        for label in labels
                    )
                )
        except ValueError as exc:
            raise ContractError("source reference is malformed") from exc
        if (
            reference.scheme != "https"
            or any(char.isspace() for char in source["reference"])
            or not valid_host
            or port == 0
            or reference.netloc.endswith(":")
            or reference.username is not None
            or reference.password is not None
        ):
            raise ContractError(
                "source reference must be a public HTTPS identity without credentials"
            )
        _text(source["content_digest"], "source content digest", _DIGEST)
        compatibility = _object(
            data["compatibility"],
            "platforms architectures target_type prerequisite_ids",
            "compatibility",
        )
        _choices(compatibility["platforms"], {"linux", "windows", "macos"}, "platforms")
        _choices(compatibility["architectures"], {"x86_64", "aarch64"}, "architectures")
        if compatibility["target_type"] != "owned_endpoint":
            raise ContractError(
                "v1 requires an owned endpoint; remote target families need a later contract"
            )
        prerequisites = compatibility["prerequisite_ids"]
        if not isinstance(prerequisites, list) or not 1 <= len(prerequisites) <= 32:
            raise ContractError("adapter requires explicit prerequisite identities")
        for prerequisite in prerequisites:
            _text(prerequisite, "prerequisite", _ID)
        if len(prerequisites) != len(set(prerequisites)):
            raise ContractError("duplicate adapter prerequisite")
        parameter_specs(data["parameters"])
        supervision = _object(
            data["supervision"],
            "invocation_id installation_binding network privilege working_directory "
            "environment cancellation filesystem cleanup_action_id",
            "supervision",
        )
        _text(supervision["invocation_id"], "fixed invocation", _ID)
        for field, expected in {
            "installation_binding": "verified-version-and-digest",
            "network": "none",
            "privilege": "current-user",
            "working_directory": "private-adapter-workspace",
            "environment": "adapter-allowlist",
            "cancellation": "terminate-owned-process-tree",
        }.items():
            if supervision[field] != expected:
                raise ContractError(f"unsupported adapter v1 {field} policy")
        if supervision["filesystem"] not in ("read-only", "receipt-owned-workspace"):
            raise ContractError("unsupported adapter filesystem policy")
        _text(supervision["cleanup_action_id"], "cleanup action", _ID)
        limits = _object(data["limits"], " ".join(_LIMITS), "limits")
        for name, maximum in _LIMITS.items():
            if type(limits[name]) is not int or not 1 <= limits[name] <= maximum:
                raise ContractError(f"adapter {name} must be positive and within the v1 ceiling")
        result = _object(data["result"], "parser_id artifact_types observation_schema", "result")
        _text(result["parser_id"], "result parser", _ID)
        _text(result["observation_schema"], "observation schema", _ID)
        artifacts = result["artifact_types"]
        if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 32:
            raise ContractError("adapter requires bounded artifact type declarations")
        for artifact in artifacts:
            _text(artifact, "artifact type", _ID)
        if len(artifacts) != len(set(artifacts)):
            raise ContractError("duplicate adapter artifact type")
        try:
            canonical = canonical_json_bytes(data)
        except (TypeError, ValueError) as exc:
            raise ContractError("adapter must be finite JSON") from exc
        if len(canonical) > 32 * 1024:
            raise ContractError("adapter contract exceeds 32 KiB")
        return cls(canonical)

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self._canonical).hexdigest()

    def validate_parameters(self, values: Mapping[str, Any]) -> Mapping[str, Any]:
        """Normalize only declared logical values; this does not authorize effects."""
        return normalized_parameters(parameter_specs(self.to_dict()["parameters"]), values)
