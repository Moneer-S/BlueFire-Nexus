"""Strict validation for the one-shot native-tool inspection result."""

from __future__ import annotations

from typing import Any, Mapping

from .contracts import ContractError
from .native_tool_installations import NativeToolInstallation

SCHEMA = "bluefire.native-tool-inspection.v1"
_FIELDS = frozenset(
    {
        "schema_version",
        "installation_digest",
        "status",
        "code",
        "content_sha256",
        "size_bytes",
        "platform",
        "architecture",
    }
)
_CODES = frozenset(
    {
        "verified",
        "binding_mismatch",
        "invalid_installation",
        "unsupported_platform",
        "inspection_unavailable",
        "unsafe_installation",
        "size_mismatch",
        "installation_changed",
        "digest_mismatch",
        "unsupported_binary",
        "inspection_timeout",
        "architecture_mismatch",
        "capabilities_unknown",
        "unexpected_privilege",
        "unrecognized_tool_build",
    }
)
_PLATFORMS = frozenset({"linux", "macos", "windows"})
_ARCHITECTURES = frozenset({"x86_64", "aarch64"})


def validate_native_tool_inspection(
    record: Mapping[str, Any], result: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate and bind a Rust inspection result to one canonical record."""

    installation = NativeToolInstallation.from_mapping(record)
    if not isinstance(result, Mapping) or set(result) != _FIELDS:
        raise ContractError("native tool inspection result has an unsupported shape")
    if result.get("schema_version") != SCHEMA:
        raise ContractError("native tool inspection result schema is unsupported")
    if result.get("installation_digest") != installation.digest:
        raise ContractError("native tool inspection digest does not match the record")
    status = result.get("status")
    code = result.get("code")
    if (
        not isinstance(status, str)
        or not isinstance(code, str)
        or status not in {"ready", "unavailable"}
        or code not in _CODES
    ):
        raise ContractError("native tool inspection status is invalid")
    platform = result.get("platform")
    architecture = result.get("architecture")
    if (
        not isinstance(platform, str)
        or not isinstance(architecture, str)
        or platform not in _PLATFORMS
        or architecture not in _ARCHITECTURES
    ):
        raise ContractError("native tool inspection host identity is invalid")
    if status == "ready":
        if code != "verified":
            raise ContractError("ready native tool inspection must be verified")
        if platform != installation.to_dict()["platform"]:
            raise ContractError("native tool inspection platform does not match the record")
        if architecture != installation.to_dict()["architecture"]:
            raise ContractError("native tool inspection architecture does not match the record")
        if result.get("content_sha256") != installation.to_dict()["content_sha256"]:
            raise ContractError("native tool inspection content digest does not match")
        if (
            type(result.get("size_bytes")) is not int
            or result.get("size_bytes") != installation.to_dict()["size_bytes"]
        ):
            raise ContractError("native tool inspection size does not match")
    else:
        if (
            code == "verified"
            or result.get("content_sha256") is not None
            or result.get("size_bytes") is not None
        ):
            raise ContractError("unavailable native tool inspection contains success evidence")
    return dict(result)


__all__ = ["SCHEMA", "validate_native_tool_inspection"]
