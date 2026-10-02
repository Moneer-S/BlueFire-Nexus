"""Validate read-only setup evidence before it can become a reviewed binding."""

from __future__ import annotations

from typing import Any, Mapping

from .contracts import ContractError
from .native_tool_installations import NativeToolInstallation, canonical_native_tool_candidate
from .native_tool_readiness import SCHEMA as INSPECTION_SCHEMA
from .native_tool_readiness import validate_native_tool_inspection
from .tool_adapters.registry import adapter_for
from .util import content_hash

SCHEMA = "bluefire.native-tool-candidate-inspection.v1"


def validate_candidate_inspection(candidate: Mapping[str, Any], result: Any) -> dict[str, Any]:
    candidate = canonical_native_tool_candidate(candidate)
    try:
        spec = adapter_for(candidate["action_id"])
    except ContractError:
        raise ContractError("native tool candidate action is unsupported") from None
    if not isinstance(result, Mapping) or set(result) != {
        "schema_version",
        "candidate_digest",
        "status",
        "code",
        "installation",
        "platform",
        "architecture",
    }:
        raise ContractError("native tool candidate inspection has an unsupported shape")
    if result["schema_version"] != SCHEMA or result["candidate_digest"] != content_hash(candidate):
        raise ContractError("native tool candidate inspection identity changed")
    status, code = result["status"], result["code"]
    if result["platform"] not in ("linux", "windows", "macos") or result["architecture"] not in (
        "x86_64",
        "aarch64",
    ):
        raise ContractError("native tool candidate host identity is unsupported")
    if status == "unavailable":
        # Failure codes are shared with exact inspection; no identity record or
        # filesystem data may leak through a refused candidate response.
        from .native_tool_readiness import _CODES

        if (
            not isinstance(code, str)
            or code not in _CODES - {"verified"}
            or result["installation"] is not None
        ):
            raise ContractError("unavailable candidate inspection contains success evidence")
        return dict(result)
    if status != "ready" or code != "verified":
        raise ContractError("native tool candidate inspection status is invalid")
    installation = NativeToolInstallation.from_mapping(result["installation"])
    record = installation.to_dict()
    installation.check_binding(
        expected_adapter_id=spec.ADAPTER_ID,
        expected_adapter_version=spec.VERSION,
        expected_adapter_contract_digest=spec.CONTRACT.digest,
        expected_tool_id=spec.TOOL_ID,
        expected_platform="linux",
        expected_architecture=result["architecture"],
    )
    if (
        record["installation_location"] != candidate["installation_location"]
        or record["tool_version"] != candidate["tool_version"]
    ):
        raise ContractError("native tool candidate inspection changed the setup request")
    validate_native_tool_inspection(
        record,
        {
            "schema_version": INSPECTION_SCHEMA,
            "installation_digest": installation.digest,
            "status": status,
            "code": code,
            "platform": result["platform"],
            "architecture": result["architecture"],
            "content_sha256": record["content_sha256"],
            "size_bytes": record["size_bytes"],
        },
    )
    return {**dict(result), "installation": record}
