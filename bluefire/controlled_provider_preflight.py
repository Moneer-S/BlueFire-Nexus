"""Narrow no-tools request used by the pinned Strix CLI model preflight.

This is a source-backed compatibility grammar, not a captured installed SDK
schema or a model response. Tool turns use their separate enrollment boundary.
"""

from __future__ import annotations

from typing import Any, Mapping

from .strix_tool_conformance import MODEL_ID

PREFLIGHT_MESSAGES = (
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Reply with just 'OK'."},
)
PREFLIGHT_FINGERPRINT = "bluefire-test-provider-fixture-estimate"
_FIELDS = frozenset(
    {
        "model",
        "messages",
        "tools",
        "stream",
        "parallel_tool_calls",
        "tool_choice",
        "temperature",
        "top_p",
        "max_tokens",
        "max_completion_tokens",
        "store",
    }
)


def validate_preflight_request(value: Mapping[str, Any], *, max_output_tokens: int) -> None:
    """Accept only the pinned no-tools probe, never arbitrary inference input."""
    if (
        set(value) - _FIELDS
        or value.get("model") != MODEL_ID
        or value.get("messages") != list(PREFLIGHT_MESSAGES)
        or value.get("tools", []) != []
        or ("stream" in value and value["stream"] is not False)
        or ("parallel_tool_calls" in value and value["parallel_tool_calls"] is not False)
        or value.get("tool_choice") not in (None, "none")
        or ("store" in value and value["store"] is not False)
        or {"max_tokens", "max_completion_tokens"} <= set(value)
    ):
        raise ValueError("pinned Strix no-tools preflight differs")
    # Reject bool/int equality and extra message fields, including hidden data.
    if not isinstance(value.get("messages"), list) or any(
        not isinstance(row, dict) or set(row) != {"role", "content"} for row in value["messages"]
    ):
        raise ValueError("pinned Strix preflight messages differ")
    for name in ("max_tokens", "max_completion_tokens"):
        if name in value and (
            type(value[name]) is not int or not 1 <= value[name] <= max_output_tokens
        ):
            raise ValueError("pinned Strix preflight token cap differs")
    for name, maximum in (("temperature", 2), ("top_p", 1)):
        if name in value and (
            type(value[name]) not in (int, float) or not 0 <= value[name] <= maximum
        ):
            raise ValueError("pinned Strix preflight tuning differs")


def preflight_response(
    *, attempt_id: str, sequence: int, created: int, input_tokens: int
) -> dict[str, Any]:
    return {
        "id": f"chatcmpl-{attempt_id[-12:]}-{sequence:04d}",
        "object": "chat.completion",
        "created": created,
        "model": MODEL_ID,
        "system_fingerprint": PREFLIGHT_FINGERPRINT,
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}
        ],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": 1,
            "total_tokens": input_tokens + 1,
        },
    }


def validate_preflight_response(
    value: Mapping[str, Any],
    *,
    attempt_id: str,
    sequence: int,
    max_input_tokens: int,
    max_output_tokens: int,
) -> tuple[int, int]:
    """Check exact deterministic response and usage, including scalar types."""
    created = value.get("created")
    usage = value.get("usage")
    if (
        type(created) is not int
        or not 0 <= created <= 4_294_967_295
        or not isinstance(usage, Mapping)
        or set(usage) != {"prompt_tokens", "completion_tokens", "total_tokens"}
        or type(usage.get("prompt_tokens")) is not int
        or not 1 <= usage["prompt_tokens"] <= max_input_tokens
        or type(usage.get("completion_tokens")) is not int
        or usage["completion_tokens"] != 1
        or max_output_tokens < 1
        or type(usage.get("total_tokens")) is not int
    ):
        raise ValueError("controlled preflight response usage is invalid")
    expected = preflight_response(
        attempt_id=attempt_id,
        sequence=sequence,
        created=created,
        input_tokens=usage["prompt_tokens"],
    )
    if dict(value) != expected:
        raise ValueError("controlled preflight response differs")
    index = value["choices"][0]["index"]
    if type(index) is not int:
        raise ValueError("controlled preflight response index is invalid")
    return usage["prompt_tokens"], 1
