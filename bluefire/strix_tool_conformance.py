"""Offline conformance boundary for the pinned Strix root agent's tool surface.

The source fixes the base tool order, but the OpenAI Agents SDK expands the
filesystem and shell capabilities at runtime and serializes their schemas.
Consequently a profile parsed here is only a review candidate. Serving requires
its digest to be independently enrolled in ``APPROVED_PROFILE_DIGESTS``.

Source: usestrix/strix@6b7ae2e, strix/agents/factory.py and
strix/tools/finish/tool.py; openai/openai-agents-python@v0.19.0,
src/agents/sandbox/capabilities/{filesystem,shell}.py.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

PROFILE_SCHEMA = "bluefire.strix-root-tool-conformance.v1"
PROFILE_ID = "strix-root-chat-completions-6b7ae2e.v1"
SOURCE_COMMIT = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"  # pragma: allowlist secret
SOURCE_TREE = "23c06e4a0e58bdf3b4979863d7623230e4091332"  # pragma: allowlist secret
SDK_VERSION = "0.19.0"
PROVIDER_ID = "controlled-strix-mechanics.v1"
MODEL_ID = "bluefire-controlled-strix-mechanics-v1"

# factory.py's 43 _BASE_TOOLS, in declaration order. Its root branch adds finish_scan.
BASE_TOOL_NAMES = (
    "think",
    "load_skill",
    "create_todo",
    "list_todos",
    "update_todo",
    "mark_todo_done",
    "mark_todo_pending",
    "delete_todo",
    "create_note",
    "list_notes",
    "get_note",
    "update_note",
    "delete_note",
    "record_coverage",
    "update_coverage",
    "list_coverage",
    "get_threat_model",
    "save_threat_model",
    "amend_threat_model",
    "web_search",
    "web_get_contents",
    "create_vulnerability_report",
    "create_dependency_report",
    "update_vulnerability_report",
    "delete_vulnerability_report",
    "list_reports",
    "get_report",
    "list_requests",
    "view_request",
    "repeat_request",
    "list_sitemap",
    "view_sitemap_entry",
    "scope_rules",
    "list_mcps",
    "search_mcp_tools",
    "get_mcp_tool_schema",
    "describe_mcp",
    "call_mcp",
    "view_agent_graph",
    "send_message_to_agent",
    "wait_for_agents",
    "create_agent",
    "stop_agent",
)

# SDK v0.19.0 Filesystem is followed by Shell; view_image may be disabled by
# the model catalog, and write_stdin depends on the session's PTY support.
SANDBOX_SUFFIXES = frozenset(
    {
        ("view_image", "apply_patch", "exec_command", "write_stdin"),
        ("view_image", "apply_patch", "exec_command"),
        ("apply_patch", "exec_command", "write_stdin"),
        ("apply_patch", "exec_command"),
    }
)
# The pinned factory converts these custom tools with strict_json_schema=False.
# The SDK may omit the wire `strict` field for such a descriptor. Capture its
# exact presence rather than silently normalizing it to a strict descriptor.
NONSTRICT_TOOL_NAMES = frozenset({"repeat_request", "apply_patch"})
FINISH_FIELDS = frozenset(
    {"executive_summary", "methodology", "technical_analysis", "recommendations"}
)
CONTROLLED_FINISH_ARGUMENTS: Mapping[str, str] = {
    "executive_summary": "Test provider mechanics only; no target assessment was performed.",
    "methodology": "A controller-owned finite tool sequence exercised the tool-turn transport. No security testing was performed.",
    "technical_analysis": "No target requests, vulnerabilities, defenses, or coverage were assessed by a live model.",
    "recommendations": "Review the mechanics record separately. An authorized live-model assessment is required for security conclusions.",
}
TARGET_MECHANICS_FINISH_ARGUMENTS: Mapping[str, str] = {
    "executive_summary": "Test provider transport, tool, and lifecycle mechanics only; no autonomous discovery or security assessment was performed.",
    "methodology": "A deterministic controller-owned sequence requested one replay of a controller-preseeded, attempt-bound Caido request, then finished. Tool-result content was not interpreted.",
    "technical_analysis": "A requested replay and paired tool result demonstrate mechanics only. They do not establish target success, findings, coverage, or live-model decision quality.",
    "recommendations": "Review the replay and lifecycle evidence independently. An authorized live-model assessment is required for security conclusions.",
}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")

# Enrollment must be a separately reviewed code change. A digest supplied in
# the attempt-local manifest never authorizes itself. There is no reviewed
# capture of the SDK-generated wire schemas for this pinned runtime yet.
APPROVED_PROFILE_DIGESTS: frozenset[str] = frozenset()


class ToolConformanceError(ValueError):
    """An offline candidate is malformed or is not an enrolled serving profile."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def digest_json(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class ToolBinding:
    name: str
    parameters_digest: str
    function_digest: str
    strict: bool | None


@dataclass(frozen=True, slots=True)
class OfflineRootToolProfile:
    """A complete, bounded candidate capture; never an approval by itself."""

    tool_bindings: tuple[ToolBinding, ...]
    unsupported_sandbox_tools: tuple[str, ...]
    strict_tool_schemas: bool
    supports_images: bool
    profile_digest: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OfflineRootToolProfile":
        expected = {
            "schema_version",
            "profile_id",
            "source_commit",
            "source_tree",
            "sdk_version",
            "provider_id",
            "model_id",
            "is_root",
            "interactive",
            "coverage_tools",
            "chat_completions_tools",
            "strict_tool_schemas",
            "supports_images",
            "tool_roster",
            "unsupported_sandbox_tools",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ToolConformanceError("profile fields are invalid")
        fixed = {
            "schema_version": PROFILE_SCHEMA,
            "profile_id": PROFILE_ID,
            "source_commit": SOURCE_COMMIT,
            "source_tree": SOURCE_TREE,
            "sdk_version": SDK_VERSION,
            "provider_id": PROVIDER_ID,
            "model_id": MODEL_ID,
            "is_root": True,
            "interactive": False,
            "coverage_tools": True,
            "chat_completions_tools": True,
            "strict_tool_schemas": True,
        }
        if any(
            value[name] != expected_value
            or (isinstance(expected_value, bool) and type(value[name]) is not bool)
            for name, expected_value in fixed.items()
        ):
            raise ToolConformanceError("profile source or route identity changed")
        if type(value["supports_images"]) is not bool:
            raise ToolConformanceError("profile model capabilities are invalid")
        raw_roster = value["tool_roster"]
        if not isinstance(raw_roster, list) or not 46 <= len(raw_roster) <= 48:
            raise ToolConformanceError("profile tool roster is incomplete")
        bindings: list[ToolBinding] = []
        for raw_tool in raw_roster:
            if not isinstance(raw_tool, Mapping) or set(raw_tool) != {
                "name",
                "parameters_digest",
                "function_digest",
                "strict",
            }:
                raise ToolConformanceError("profile tool binding is invalid")
            name = raw_tool["name"]
            parameters_digest = raw_tool["parameters_digest"]
            function_digest = raw_tool["function_digest"]
            strict = raw_tool["strict"]
            if (
                not isinstance(name, str)
                or _NAME.fullmatch(name) is None
                or not isinstance(parameters_digest, str)
                or _DIGEST.fullmatch(parameters_digest) is None
                or not isinstance(function_digest, str)
                or _DIGEST.fullmatch(function_digest) is None
                or not (
                    strict is True
                    or (name in NONSTRICT_TOOL_NAMES and (strict is False or strict is None))
                )
            ):
                raise ToolConformanceError("profile tool binding is invalid")
            bindings.append(ToolBinding(name, parameters_digest, function_digest, strict))
        names = tuple(binding.name for binding in bindings)
        suffix = names[len(BASE_TOOL_NAMES) + 1 :]
        if (
            names[: len(BASE_TOOL_NAMES)] != BASE_TOOL_NAMES
            or names[len(BASE_TOOL_NAMES)] != "finish_scan"
            or suffix not in SANDBOX_SUFFIXES
            or len(names) != len(set(names))
        ):
            raise ToolConformanceError("profile root tool order changed")
        unsupported = value["unsupported_sandbox_tools"]
        if not isinstance(unsupported, list) or tuple(unsupported) != suffix:
            raise ToolConformanceError("sandbox tools must be explicitly unsupported")
        if value["supports_images"] is not ("view_image" in suffix):
            raise ToolConformanceError("image capability and roster disagree")
        try:
            profile_digest = digest_json(value)
        except (RecursionError, TypeError, ValueError) as exc:
            raise ToolConformanceError("profile serialization is invalid") from exc
        return cls(
            tuple(bindings),
            suffix,
            value["strict_tool_schemas"],
            value["supports_images"],
            profile_digest,
        )

    def require_enrolled(self) -> None:
        if self.profile_digest not in APPROVED_PROFILE_DIGESTS:
            raise ToolConformanceError(
                "pinned Strix wire tool profile is not independently enrolled"
            )

    def check_request_roster(self, value: Any) -> dict[str, Mapping[str, Any]]:
        if not isinstance(value, list) or len(value) != len(self.tool_bindings):
            raise ToolConformanceError("request tool roster differs from reviewed profile")
        roster: dict[str, Mapping[str, Any]] = {}
        for supplied, expected in zip(value, self.tool_bindings, strict=True):
            if not isinstance(supplied, Mapping) or set(supplied) != {"type", "function"}:
                raise ToolConformanceError("request tool roster differs from reviewed profile")
            function = supplied.get("function")
            if supplied.get("type") != "function" or not isinstance(function, Mapping):
                raise ToolConformanceError("request tool roster differs from reviewed profile")
            if (
                function.get("name") != expected.name
                or not isinstance(function.get("parameters"), Mapping)
                or set(function)
                != (
                    {"name", "description", "parameters"}
                    if expected.strict is None
                    else {"name", "description", "parameters", "strict"}
                )
                or not isinstance(function.get("description"), str)
                or not 1 <= len(function["description"]) <= 32_768
                or function.get("strict") is not expected.strict
            ):
                raise ToolConformanceError("request tool roster differs from reviewed profile")
            try:
                parameters_digest = digest_json(function["parameters"])
                function_digest = digest_json(function)
            except (RecursionError, TypeError, ValueError) as exc:
                raise ToolConformanceError("request tool serialization is invalid") from exc
            if (
                parameters_digest != expected.parameters_digest
                or function_digest != expected.function_digest
            ):
                raise ToolConformanceError("request tool schema differs from reviewed profile")
            roster[expected.name] = function
        return roster


def validate_finish_arguments(value: Any, *, target_mechanics: bool = False) -> None:
    """Keep the terminal report truthful about mechanics-only coverage."""
    if not isinstance(value, Mapping) or set(value) != FINISH_FIELDS:
        raise ToolConformanceError("finish_scan arguments do not match the pinned signature")
    expected = (
        TARGET_MECHANICS_FINISH_ARGUMENTS if target_mechanics else CONTROLLED_FINISH_ARGUMENTS
    )
    if dict(value) != expected:
        raise ToolConformanceError("finish_scan report must disclose unassessed mechanics exactly")


def validate_phase_parameters(tool_name: str, value: Any) -> None:
    """Check the pinned phase signatures before accepting their wire digests."""
    if tool_name not in {"view_agent_graph", "repeat_request", "finish_scan"} or not isinstance(
        value, Mapping
    ):
        raise ToolConformanceError("phase tool schema is unsupported")
    if tool_name == "repeat_request":
        # Source signature is (request_id: str, modifications: dict | None=None),
        # strict_mode=False. Full installed descriptor/digest enrollment remains
        # mandatory; this semantic check never blesses a guessed wire schema.
        properties = value.get("properties")
        required = value.get("required")
        if (
            set(value)
            - {"type", "properties", "required", "additionalProperties", "title", "description"}
            or value.get("type") != "object"
            or value.get("additionalProperties", False) is not False
            or not isinstance(properties, Mapping)
            or set(properties) != {"request_id", "modifications"}
            or required not in (["request_id"], ["request_id", "modifications"])
        ):
            raise ToolConformanceError("repeat_request schema differs from the pinned signature")
        request_id = properties["request_id"]
        modifications = properties["modifications"]
        if (
            not isinstance(request_id, Mapping)
            or set(request_id) - {"type", "title", "description"}
            or request_id.get("type") != "string"
            or not isinstance(modifications, Mapping)
            or set(modifications) - {"anyOf", "default", "title", "description"}
            or modifications.get("default") is not None
            or modifications.get("anyOf")
            != [{"additionalProperties": True, "type": "object"}, {"type": "null"}]
        ):
            raise ToolConformanceError("repeat_request parameter signature is unsupported")
        return
    if (
        set(value)
        - {"type", "properties", "required", "additionalProperties", "title", "description"}
        or value.get("type") != "object"
        or value.get("additionalProperties") is not False
    ):
        raise ToolConformanceError("phase tool schema differs from the pinned signature")
    properties = value.get("properties")
    required = value.get("required")
    if not isinstance(properties, Mapping) or not isinstance(required, list):
        raise ToolConformanceError("phase tool schema differs from the pinned signature")
    if tool_name == "view_agent_graph":
        if properties or required:
            raise ToolConformanceError("view_agent_graph must take no arguments")
        return
    if set(properties) != FINISH_FIELDS or required != list(CONTROLLED_FINISH_ARGUMENTS):
        raise ToolConformanceError("finish_scan schema does not require the pinned fields")
    if any(
        not isinstance(field_schema, Mapping)
        or set(field_schema) - {"type", "title", "description"}
        or field_schema.get("type") != "string"
        for field_schema in properties.values()
    ):
        raise ToolConformanceError("finish_scan fields must be strings")


_ALLOWED_SCHEMA_KEYWORDS = frozenset(
    {
        "$schema",
        "additionalProperties",
        "anyOf",
        "const",
        "default",
        "description",
        "enum",
        "examples",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "nullable",
        "properties",
        "required",
        "title",
        "type",
    }
)


class ControlledProviderError(ValueError):
    """Bounded protocol failure that is safe to return to the test client."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.safe_message = message


def _schema_depth(value: Any, *, limit: int, depth: int = 0) -> int:
    if depth > limit:
        raise ControlledProviderError(422, "schema_too_deep", "tool schema is too deep")
    if isinstance(value, Mapping):
        return max(
            [depth] + [_schema_depth(item, limit=limit, depth=depth + 1) for item in value.values()]
        )
    if isinstance(value, list):
        return max([depth] + [_schema_depth(item, limit=limit, depth=depth + 1) for item in value])
    return depth


def _validate_schema_value(value: Any, schema: Any, *, depth: int, limit: int) -> None:
    if depth > limit or not isinstance(schema, Mapping):
        raise ControlledProviderError(422, "unsupported_tool_schema", "tool schema is unsupported")
    unknown = set(schema) - _ALLOWED_SCHEMA_KEYWORDS
    if unknown:
        raise ControlledProviderError(422, "unsupported_tool_schema", "tool schema is unsupported")
    if "anyOf" in schema:
        variants = schema["anyOf"]
        if not isinstance(variants, list) or not 1 <= len(variants) <= 8:
            raise ControlledProviderError(
                422, "unsupported_tool_schema", "tool schema is unsupported"
            )
        for variant in variants:
            try:
                _validate_schema_value(value, variant, depth=depth + 1, limit=limit)
            except ControlledProviderError:
                continue
            return
        raise ControlledProviderError(422, "invalid_tool_arguments", "tool arguments are invalid")

    if "const" in schema and value != schema["const"]:
        raise ControlledProviderError(422, "invalid_tool_arguments", "tool arguments are invalid")
    if "enum" in schema:
        options = schema["enum"]
        if not isinstance(options, list) or value not in options:
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )

    declared = schema.get("type")
    if schema.get("nullable") is True and value is None:
        return
    if isinstance(declared, list):
        allowed = set(declared)
        if not allowed or not allowed <= {
            "array",
            "boolean",
            "integer",
            "null",
            "number",
            "object",
            "string",
        }:
            raise ControlledProviderError(
                422, "unsupported_tool_schema", "tool schema is unsupported"
            )
        if value is None and "null" in allowed:
            return
        matches = [kind for kind in allowed if kind != "null" and _matches_type(value, kind)]
        if not matches:
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
        declared = matches[0]
    elif declared is None:
        if "properties" in schema or "required" in schema:
            declared = "object"
        else:
            raise ControlledProviderError(
                422, "unsupported_tool_schema", "tool schema is unsupported"
            )
    elif not isinstance(declared, str) or declared not in {
        "array",
        "boolean",
        "integer",
        "null",
        "number",
        "object",
        "string",
    }:
        raise ControlledProviderError(422, "unsupported_tool_schema", "tool schema is unsupported")

    if not _matches_type(value, declared):
        raise ControlledProviderError(422, "invalid_tool_arguments", "tool arguments are invalid")

    if declared == "object":
        assert isinstance(value, Mapping)
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if (
            not isinstance(properties, Mapping)
            or not isinstance(required, list)
            or not all(isinstance(name, str) for name in required)
        ):
            raise ControlledProviderError(
                422, "unsupported_tool_schema", "tool schema is unsupported"
            )
        missing = set(required) - set(value)
        if missing:
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
        extras = set(value) - set(properties)
        additional = schema.get("additionalProperties", True)
        if extras and additional is False:
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
        if extras and additional is not True:
            if not isinstance(additional, Mapping):
                raise ControlledProviderError(
                    422, "unsupported_tool_schema", "tool schema is unsupported"
                )
            for name in extras:
                _validate_schema_value(value[name], additional, depth=depth + 1, limit=limit)
        for name, item in value.items():
            if name in properties:
                _validate_schema_value(item, properties[name], depth=depth + 1, limit=limit)
    elif declared == "array":
        assert isinstance(value, list)
        minimum = schema.get("minItems", 0)
        maximum = schema.get("maxItems", 1_024)
        if (
            not isinstance(minimum, int)
            or not isinstance(maximum, int)
            or not minimum <= len(value) <= maximum
        ):
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
        items = schema.get("items")
        if items is None:
            raise ControlledProviderError(
                422, "unsupported_tool_schema", "tool schema is unsupported"
            )
        for item in value:
            _validate_schema_value(item, items, depth=depth + 1, limit=limit)
    elif declared == "string":
        assert isinstance(value, str)
        minimum = schema.get("minLength", 0)
        maximum = schema.get("maxLength", 1_000_000)
        if (
            not isinstance(minimum, int)
            or not isinstance(maximum, int)
            or not minimum <= len(value) <= maximum
        ):
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
    elif declared in {"integer", "number"}:
        assert isinstance(value, (int, float)) and not isinstance(value, bool)
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and (not isinstance(minimum, (int, float)) or value < minimum):
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
        if maximum is not None and (not isinstance(maximum, (int, float)) or value > maximum):
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )


def _matches_type(value: Any, kind: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, Mapping),
        "string": isinstance(value, str),
    }[kind]


def _reject_nonfinite(value: str) -> None:
    raise ControlledProviderError(400, "invalid_json", f"non-finite JSON value {value} is invalid")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ControlledProviderError(400, "invalid_json", "duplicate JSON field is invalid")
        value[name] = item
    return value


def _bounded_text(value: Any, label: str, *, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ControlledProviderError(422, "invalid_manifest", f"{label} is invalid")
    return value


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ControlledProviderError(422, "invalid_manifest", f"{label} is outside its bound")
    return int(value)
