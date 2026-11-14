"""Descriptor-only, offline review candidates from exact Strix wire requests.

This utility never starts Strix, imports its SDK, or enrolls a serving profile.
The caller declares the pinned source identity; the resulting candidate does
not attest that the request came from an installed runtime. Prompts, tool
results, request headers, and the raw request are never returned or written.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .strix_tool_conformance import (
    BASE_TOOL_NAMES,
    MODEL_ID,
    NONSTRICT_TOOL_NAMES,
    PROFILE_ID,
    PROFILE_SCHEMA,
    PROVIDER_ID,
    SDK_VERSION,
    SOURCE_COMMIT,
    SOURCE_TREE,
    OfflineRootToolProfile,
    ToolConformanceError,
    canonical_json,
    digest_json,
)

CAPTURE_SCHEMA = "bluefire.strix-tool-capture-candidate.v1"
MAX_CAPTURE_REQUEST_BYTES = 1_048_576
MAX_CAPTURE_DEPTH = 32
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_REQUEST_FIELDS = frozenset(
    {
        "model",
        "messages",
        "tools",
        "stream",
        "parallel_tool_calls",
        "tool_choice",
        "stream_options",
        "temperature",
        "top_p",
        "max_tokens",
        "max_completion_tokens",
        "stop",
        "seed",
    }
)
_CANDIDATE_FIELDS = frozenset(
    {
        "schema_version",
        "capture_kind",
        "approval_state",
        "installed_runtime_proof",
        "live_model_proof",
        "source_provenance",
        "profile",
        "profile_digest",
        "tools_digest",
        "chat_completions_tools",
        "candidate_digest",
    }
)


class ToolCaptureError(ValueError):
    """Static, safe capture failure; no request content belongs in this error."""


def _reject_constant(_value: str) -> None:
    raise ToolCaptureError("capture JSON contains a non-finite number")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ToolCaptureError("capture JSON contains a duplicate field")
        result[name] = value
    return result


def _bounded_json(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_CAPTURE_DEPTH:
        raise ToolCaptureError("capture JSON exceeds its depth bound")
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ToolCaptureError("capture JSON has an invalid object field")
        for item in value.values():
            _bounded_json(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            _bounded_json(item, depth=depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ToolCaptureError("capture JSON contains a non-finite number")
    elif value is not None and type(value) not in {str, bool, int, float}:
        raise ToolCaptureError("capture JSON has an invalid value")


def _parse_request(body: bytes) -> Mapping[str, Any]:
    if not isinstance(body, bytes) or not 1 <= len(body) <= MAX_CAPTURE_REQUEST_BYTES:
        raise ToolCaptureError("capture request exceeds its byte bound")
    parsed: Any = None
    try:
        parsed = json.loads(body, object_pairs_hook=_object, parse_constant=_reject_constant)
        _bounded_json(parsed)
    except ToolCaptureError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        pass
    if not isinstance(parsed, Mapping):
        raise ToolCaptureError("capture request is not a bounded JSON object")
    if (
        set(parsed) - _REQUEST_FIELDS
        or not {"model", "messages", "tools"} <= set(parsed)
        or not isinstance(parsed["messages"], list)
        or not 1 <= len(parsed["messages"]) <= 64
        or any(not isinstance(message, Mapping) for message in parsed["messages"])
    ):
        raise ToolCaptureError("capture request envelope is unsupported")
    return parsed


def _scan_material(value: Any, forbidden_material: Sequence[str]) -> None:
    if isinstance(value, Mapping):
        for name, item in value.items():
            _scan_material(name, forbidden_material)
            _scan_material(item, forbidden_material)
    elif isinstance(value, list):
        for item in value:
            _scan_material(item, forbidden_material)
    elif isinstance(value, str):
        decoded = value
        for _ in range(MAX_CAPTURE_DEPTH):
            if any(material in decoded for material in forbidden_material):
                raise ToolCaptureError("capture descriptors contain protected material")
            expanded = _UNICODE_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), decoded)
            if expanded == decoded:
                return
            decoded = expanded
        raise ToolCaptureError("capture descriptor material encoding is ambiguous")


def _provenance(
    *, source_commit: str, source_tree: str, sdk_version: str, model_id: str, provider_id: str
) -> dict[str, str]:
    values = {
        "source_commit": source_commit,
        "source_tree": source_tree,
        "sdk_version": sdk_version,
        "model_id": model_id,
        "provider_id": provider_id,
    }
    if values != {
        "source_commit": SOURCE_COMMIT,
        "source_tree": SOURCE_TREE,
        "sdk_version": SDK_VERSION,
        "model_id": MODEL_ID,
        "provider_id": PROVIDER_ID,
    }:
        raise ToolCaptureError("capture source identity differs from the pinned runtime")
    return {"identity_status": "caller_declared_pinned", **values}


def capture_tool_profile(
    body: bytes,
    *,
    source_commit: str,
    source_tree: str,
    sdk_version: str,
    model_id: str,
    provider_id: str,
    forbidden_material: Sequence[str] = (),
) -> dict[str, Any]:
    """Return exact descriptors plus a review candidate, never an enrollment.

    The protected caller should supply every known credential in
    ``forbidden_material``. They are checked against decoded descriptor keys and
    values before anything is returned. No credential can be inferred from an
    arbitrary schema description, so this utility is not a secret-discovery
    service. Request metadata and messages are discarded unconditionally.
    """
    provenance = _provenance(
        source_commit=source_commit,
        source_tree=source_tree,
        sdk_version=sdk_version,
        model_id=model_id,
        provider_id=provider_id,
    )
    if (
        not isinstance(forbidden_material, Sequence)
        or isinstance(forbidden_material, (str, bytes))
        or len(forbidden_material) > 32
        or any(
            not isinstance(item, str) or not 1 <= len(item) <= 8192 for item in forbidden_material
        )
    ):
        raise ToolCaptureError("capture protected-material scan is invalid")
    request = _parse_request(body)
    if request["model"] != model_id:
        raise ToolCaptureError("capture model differs from the pinned runtime")
    tools = request["tools"]
    if not isinstance(tools, list) or not 46 <= len(tools) <= 48:
        raise ToolCaptureError("capture tool roster is incomplete")
    bindings: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, Mapping) or set(tool) != {"type", "function"}:
            raise ToolCaptureError("capture tool descriptor is unsupported")
        function = tool["function"]
        if (
            tool["type"] != "function"
            or not isinstance(function, Mapping)
            or set(function) - {"name", "description", "parameters", "strict"}
            or not {"name", "description", "parameters"} <= set(function)
            or not isinstance(function["name"], str)
            or not isinstance(function["description"], str)
            or not 1 <= len(function["description"]) <= 32_768
            or not isinstance(function["parameters"], Mapping)
            or not (
                function.get("strict") is True
                or (
                    function["name"] in NONSTRICT_TOOL_NAMES
                    and (function.get("strict") is False or "strict" not in function)
                )
            )
        ):
            raise ToolCaptureError("capture tool descriptor is unsupported")
        _scan_material(tool, forbidden_material)
        bindings.append(
            {
                "name": function["name"],
                "parameters_digest": digest_json(function["parameters"]),
                "function_digest": digest_json(function),
                "strict": function.get("strict"),
            }
        )
    suffix = [binding["name"] for binding in bindings[len(BASE_TOOL_NAMES) + 1 :]]
    profile: dict[str, Any] = {
        "schema_version": PROFILE_SCHEMA,
        "profile_id": PROFILE_ID,
        **{
            name: provenance[name]
            for name in ("source_commit", "source_tree", "sdk_version", "provider_id", "model_id")
        },
        "is_root": True,
        "interactive": False,
        "coverage_tools": True,
        "chat_completions_tools": True,
        "strict_tool_schemas": True,
        "supports_images": "view_image" in suffix,
        "tool_roster": bindings,
        "unsupported_sandbox_tools": suffix,
    }
    try:
        parsed = OfflineRootToolProfile.from_mapping(profile)
        parsed.check_request_roster(tools)
    except ToolConformanceError:
        raise ToolCaptureError("capture tool roster differs from the pinned runtime") from None
    candidate: dict[str, Any] = {
        "schema_version": CAPTURE_SCHEMA,
        "capture_kind": "offline_exact_wire_descriptors",
        "approval_state": "independent_code_review_required",
        "installed_runtime_proof": False,
        "live_model_proof": False,
        "source_provenance": provenance,
        "profile": profile,
        "profile_digest": parsed.profile_digest,
        "tools_digest": digest_json(tools),
        "chat_completions_tools": tools,
    }
    candidate["candidate_digest"] = digest_json(candidate)
    # Return a detached descriptor-only object, never references into a caller's
    # request object or the raw request bytes.
    return json.loads(canonical_json(candidate))  # type: ignore[no-any-return]


def verify_tool_profile_capture(candidate: Mapping[str, Any], body: bytes) -> None:
    """Require unchanged exact descriptors and provenance on a later capture.

    Integrity is not approval: a newly created, self-consistent candidate still
    requires independent fixture review and a separate enrollment code change.
    """
    if not isinstance(candidate, Mapping) or set(candidate) != _CANDIDATE_FIELDS:
        raise ToolCaptureError("capture candidate fields are invalid")
    source = candidate.get("source_provenance")
    if (
        not isinstance(source, Mapping)
        or set(source)
        != {
            "identity_status",
            "source_commit",
            "source_tree",
            "sdk_version",
            "model_id",
            "provider_id",
        }
        or source["identity_status"] != "caller_declared_pinned"
    ):
        raise ToolCaptureError("capture candidate provenance is invalid")
    fresh = capture_tool_profile(
        body,
        source_commit=source["source_commit"],
        source_tree=source["source_tree"],
        sdk_version=source["sdk_version"],
        model_id=source["model_id"],
        provider_id=source["provider_id"],
    )
    try:
        equal = canonical_json(candidate) == canonical_json(fresh)
    except (TypeError, ValueError, RecursionError):
        equal = False
    if not equal:
        raise ToolCaptureError("capture candidate or exact tool descriptors changed")
