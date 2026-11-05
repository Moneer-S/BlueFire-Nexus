"""Synthetic wire descriptors for unit tests only.

These schemas are deliberately *not* claimed to be Strix/SDK output and their
profile digest is not enrolled by product code. They exercise the validator and
SSE state machine without importing or executing the pinned Strix package.
"""

from __future__ import annotations

from typing import Any

from bluefire.controlled_strix_provider import MANIFEST_SCHEMA
from bluefire.strix_tool_conformance import (
    BASE_TOOL_NAMES,
    CONTROLLED_FINISH_ARGUMENTS,
    MODEL_ID,
    PROFILE_ID,
    PROFILE_SCHEMA,
    PROVIDER_ID,
    SDK_VERSION,
    SOURCE_COMMIT,
    SOURCE_TREE,
    digest_json,
)

ATTEMPT_ID = "engine-attempt-" + "a" * 32
TOKEN = "t" * 48


def synthetic_tools() -> list[dict[str, Any]]:
    names = (*BASE_TOOL_NAMES, "finish_scan", "view_image", "apply_patch", "exec_command")
    tools: list[dict[str, Any]] = []
    for name in names:
        parameters: dict[str, Any] = {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        }
        if name == "finish_scan":
            parameters = {
                "type": "object",
                "properties": {field: {"type": "string"} for field in CONTROLLED_FINISH_ARGUMENTS},
                "required": list(CONTROLLED_FINISH_ARGUMENTS),
                "additionalProperties": False,
            }
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": f"Synthetic {name} unit-test descriptor",
                    "parameters": parameters,
                    "strict": True,
                },
            }
        )
    return tools


def synthetic_profile(tools: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    descriptors = synthetic_tools() if tools is None else tools
    return {
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
        "supports_images": True,
        "tool_roster": [
            {
                "name": tool["function"]["name"],
                "parameters_digest": digest_json(tool["function"]["parameters"]),
                "function_digest": digest_json(tool["function"]),
                "strict": tool["function"]["strict"],
            }
            for tool in descriptors
        ],
        "unsupported_sandbox_tools": ["view_image", "apply_patch", "exec_command"],
    }


def synthetic_manifest(*, attempt_id: str = ATTEMPT_ID) -> dict[str, Any]:
    tools = synthetic_tools()
    by_name = {tool["function"]["name"]: tool["function"] for tool in tools}
    return {
        "schema_version": MANIFEST_SCHEMA,
        "attempt_id": attempt_id,
        "model_id": MODEL_ID,
        "profile": synthetic_profile(tools),
        "max_requests": 2,
        "max_request_bytes": 131_072,
        "max_response_bytes": 65_536,
        "max_messages": 32,
        "max_tools": len(tools),
        "max_schema_depth": 16,
        "max_input_tokens": 32_768,
        "max_output_tokens": 8_192,
        "max_total_tokens": 40_960,
        "phases": [
            {
                "phase_id": "inspect_graph",
                "tool_name": "view_agent_graph",
                "tool_schema_digest": digest_json(by_name["view_agent_graph"]["parameters"]),
                "parameters_schema": by_name["view_agent_graph"]["parameters"],
                "arguments": {},
            },
            {
                "phase_id": "finish",
                "tool_name": "finish_scan",
                "tool_schema_digest": digest_json(by_name["finish_scan"]["parameters"]),
                "parameters_schema": by_name["finish_scan"]["parameters"],
                "arguments": dict(CONTROLLED_FINISH_ARGUMENTS),
            },
        ],
    }
