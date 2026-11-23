"""Explicit structured-output wire dialects; no vendor/model substitution.

Contract references (checked 2026-09-06):
https://developers.openai.com/api/docs/guides/migrate-to-responses
https://developers.openai.com/api/docs/guides/structured-outputs
https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create
"""

from __future__ import annotations

from typing import Any, Mapping

from .config import AIProviderConfig, AIProviderKind
from .util import json_clone


class AIProviderError(ValueError):
    """The provider could not produce trustworthy structured output."""


class AIProviderTransportError(AIProviderError):
    def __init__(self, message: str, *, retryable: bool, code: str = "transport_failed") -> None:
        super().__init__(message)
        self.retryable = retryable
        self.code = code


class AIProviderCancelled(AIProviderTransportError):
    """Cancellation ends the operation; it is never a fallback opportunity."""

    def __init__(self) -> None:
        super().__init__(
            "Provider request was cancelled", retryable=False, code="request_cancelled"
        )


class AIWireError(AIProviderError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def structured_request(
    config: AIProviderConfig,
    *,
    instructions: str,
    input_text: str,
    name: str,
    schema: Mapping[str, Any],
) -> dict[str, Any]:
    format_spec = {"name": name, "strict": True, "schema": json_clone(schema)}
    if config.kind is AIProviderKind.OPENAI_RESPONSES:
        return {
            "model": config.model,
            "instructions": instructions,
            "input": input_text,
            "max_output_tokens": config.max_output_tokens,
            "store": False,
            "parallel_tool_calls": False,
            "tools": [],
            "tool_choice": "none",
            "text": {"format": {"type": "json_schema", **format_spec}},
        }
    if config.kind is AIProviderKind.CHAT_COMPLETIONS:
        return {
            "model": config.model,
            "messages": [
                {"role": "system", "content": instructions},
                {"role": "user", "content": input_text},
            ],
            "max_completion_tokens": config.max_output_tokens,
            "store": False,
            "stream": False,
            "n": 1,
            "response_format": {"type": "json_schema", "json_schema": format_spec},
        }
    raise AIWireError("configuration_invalid", "Select an explicit remote API style.")


def response_output_text(response: Mapping[str, Any]) -> str:
    if response.get("status") != "completed" or response.get("error") is not None:
        raise AIWireError("response_incomplete", "Responses request did not complete.")
    if response.get("incomplete_details") is not None:
        raise AIWireError("response_incomplete", "Responses output is incomplete.")
    direct = response.get("output_text")
    output = response.get("output")
    # Some compatible endpoints expose the SDK convenience field alone. When
    # raw items exist they are authoritative and must agree with that field.
    if output is None:
        if isinstance(direct, str) and direct:
            return direct
        raise AIWireError("response_invalid", "Response contains no structured text.")
    if not isinstance(output, list):
        raise AIWireError("response_invalid", "Response output must be an item array.")
    messages = []
    for item in output:
        if not isinstance(item, Mapping):
            raise AIWireError("response_invalid", "Response output item is invalid.")
        if item.get("type") == "reasoning":
            continue
        if item.get("type") != "message":
            raise AIWireError("response_invalid", "Unexpected tool or output item.")
        messages.append(item)
    if len(messages) != 1:
        raise AIWireError("response_invalid", "Expected one structured assistant message.")
    message = messages[0]
    if (
        message.get("role", "assistant") != "assistant"
        or message.get("status", "completed") != "completed"
    ):
        raise AIWireError("response_invalid", "Assistant message is not complete.")
    content = message.get("content")
    if not isinstance(content, list) or not content:
        raise AIWireError("response_invalid", "Assistant content is invalid.")
    if any(isinstance(block, Mapping) and block.get("type") == "refusal" for block in content):
        raise AIWireError("provider_refused", "Provider refused the structured request.")
    if (
        len(content) != 1
        or not isinstance(content[0], Mapping)
        or content[0].get("type") != "output_text"
    ):
        raise AIWireError("response_invalid", "Expected one structured text block.")
    text = content[0].get("text")
    if not isinstance(text, str) or not text:
        raise AIWireError("response_invalid", "Structured text is missing.")
    if direct is not None and direct != text:
        raise AIWireError("response_invalid", "Response text fields disagree.")
    return text


def chat_output_text(response: Mapping[str, Any]) -> str:
    if response.get("error") is not None:
        raise AIWireError("response_invalid", "Chat Completions returned an error.")
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], Mapping):
        raise AIWireError("response_invalid", "Expected exactly one completion choice.")
    choice = choices[0]
    message = choice.get("message")
    if not isinstance(message, Mapping) or message.get("role") != "assistant":
        raise AIWireError("response_invalid", "Expected an assistant completion.")
    if message.get("refusal"):
        raise AIWireError("provider_refused", "Provider refused the structured request.")
    if choice.get("finish_reason") != "stop":
        raise AIWireError("response_incomplete", "Completion did not finish normally.")
    if message.get("tool_calls") or message.get("function_call"):
        raise AIWireError("response_invalid", "Tool calls are not structured proposals.")
    text = message.get("content")
    if not isinstance(text, str) or not text:
        raise AIWireError("response_invalid", "Structured completion text is missing.")
    return text


def structured_output(response: Mapping[str, Any], kind: AIProviderKind) -> str:
    return (
        chat_output_text(response)
        if kind is AIProviderKind.CHAT_COMPLETIONS
        else response_output_text(response)
    )


def response_usage(value: Any, max_output_tokens: int, kind: AIProviderKind) -> Mapping[str, int]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AIWireError("response_invalid", "Response usage must be an object.")
    names = (
        {
            "prompt_tokens": "input_tokens",
            "completion_tokens": "output_tokens",
            "total_tokens": "total_tokens",
        }
        if kind is AIProviderKind.CHAT_COMPLETIONS
        else {name: name for name in ("input_tokens", "output_tokens", "total_tokens")}
    )
    result = {}
    for source, destination in names.items():
        raw = value.get(source)
        if raw is None:
            continue
        if type(raw) is not int or raw < 0:
            raise AIWireError("response_invalid", "Usage must contain non-negative integers.")
        result[destination] = raw
    if result.get("output_tokens", 0) > max_output_tokens:
        raise AIWireError("response_invalid", "Response exceeded the output-token budget.")
    return result


def credential_value(config: AIProviderConfig, environ: Mapping[str, str]) -> str:
    if config.api_key is None:
        return ""
    value = environ.get(config.api_key.env, "")
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or len(value) > 4096 or any(not 33 <= ord(char) <= 126 for char in value):
        return ""
    return value


def request_headers(api_key: str) -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "bluefire-nexus/0.1",
        **({"Authorization": f"Bearer {api_key}"} if api_key else {}),
    }
