from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from tools.controlled_strix_provider import (
    ControlledProviderError,
    ControlledProviderManifest,
    ControlledProviderState,
    _write_all,
    _write_private_exclusive,
    build_handler,
)

ATTEMPT_ID = "engine-attempt-" + "a" * 32
TOKEN = "t" * 48
MODEL = "bluefire-controlled-strix-mechanics-v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _schemas() -> dict[str, dict[str, Any]]:
    return {
        "observe_fixture": {
            "type": "object",
            "properties": {
                "observation": {
                    "type": "string",
                    "enum": ["read generated fixture metadata"],
                }
            },
            "required": ["observation"],
            "additionalProperties": False,
        },
        "finish_scan": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "maxLength": 120},
                "critical_issues": {"type": "string", "maxLength": 120},
                "coverage": {"type": "string", "maxLength": 120},
                "next_steps": {"type": "string", "maxLength": 120},
            },
            "required": ["summary", "critical_issues", "coverage", "next_steps"],
            "additionalProperties": False,
        },
    }


def _manifest_mapping(*, max_requests: int = 4) -> dict[str, Any]:
    schemas = _schemas()
    return {
        "schema_version": "bluefire.controlled-strix-mechanics.v1",
        "attempt_id": ATTEMPT_ID,
        "model_id": MODEL,
        "max_requests": max_requests,
        "max_request_bytes": 64 * 1024,
        "max_response_bytes": 64 * 1024,
        "max_messages": 32,
        "max_tools": 16,
        "max_schema_depth": 16,
        "phases": [
            {
                "phase_id": "inspect",
                "tool_name": "observe_fixture",
                "tool_schema_digest": _digest(schemas["observe_fixture"]),
                "arguments": {"observation": "read generated fixture metadata"},
            },
            {
                "phase_id": "finish",
                "tool_name": "finish_scan",
                "tool_schema_digest": _digest(schemas["finish_scan"]),
                "arguments": {
                    "summary": "Controlled mechanics fixture completed.",
                    "critical_issues": "Not evaluated by a live model.",
                    "coverage": "Finite test-provider path only.",
                    "next_steps": "Run separate authorized live-model evaluation.",
                },
            },
        ],
    }


def _tools(*, drift: bool = False) -> list[dict[str, Any]]:
    schemas = _schemas()
    if drift:
        schemas["observe_fixture"]["properties"]["unexpected"] = {"type": "string"}
    return [
        {
            "type": "function",
            "function": {"name": name, "description": "Test fixture tool", "parameters": schema},
        }
        for name, schema in schemas.items()
    ]


def _request(
    *,
    messages: list[dict[str, Any]] | None = None,
    tools: list[dict[str, Any]] | None = None,
    model: str = MODEL,
) -> bytes:
    return _canonical(
        {
            "model": model,
            "messages": messages or [{"role": "user", "content": "untrusted prompt secret"}],
            "tools": tools or _tools(),
            "stream": True,
            "parallel_tool_calls": False,
            "tool_choice": "auto",
            "stream_options": {"include_usage": True},
        }
    )


def _sse_payload(payload: bytes) -> list[dict[str, Any] | str]:
    values: list[dict[str, Any] | str] = []
    for row in payload.decode().splitlines():
        if not row:
            continue
        assert row.startswith("data: ")
        data = row.removeprefix("data: ")
        values.append(data if data == "[DONE]" else json.loads(data))
    return values


def _tool_call(payload: bytes) -> dict[str, Any]:
    values = _sse_payload(payload)
    assert values[-1] == "[DONE]"
    first = values[0]
    assert isinstance(first, dict)
    return first["choices"][0]["delta"]["tool_calls"][0]


def test_manifest_requires_finish_scan_as_terminal_phase() -> None:
    mapping = _manifest_mapping()
    mapping["phases"][-1]["tool_name"] = "not_finish"
    with pytest.raises(ControlledProviderError, match="final manifest phase"):
        ControlledProviderManifest.from_mapping(mapping)


def test_state_emits_manifest_calls_and_pairs_exact_tool_result(tmp_path: Path) -> None:
    audit = tmp_path / "private" / "provider.jsonl"
    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN, audit_path=audit
    )

    first_payload = state.respond(_request())
    first_call = _tool_call(first_payload)
    assert first_call["function"] == {
        "name": "observe_fixture",
        "arguments": '{"observation":"read generated fixture metadata"}',
    }
    assert state.pending_call_id == first_call["id"]

    messages = [
        {"role": "user", "content": "untrusted prompt secret"},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": first_call["id"],
                    "type": "function",
                    "function": first_call["function"],
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": first_call["id"],
            "content": "raw tool output secret",
        },
    ]
    second_call = _tool_call(state.respond(_request(messages=messages)))
    assert second_call["function"]["name"] == "finish_scan"
    assert second_call["id"] != first_call["id"]

    audit_text = audit.read_text(encoding="utf-8")
    assert len(audit_text.splitlines()) == 2
    assert TOKEN not in audit_text
    assert "untrusted prompt secret" not in audit_text
    assert "raw tool output secret" not in audit_text
    assert '"provider_label":"Test provider"' in audit_text
    assert '"fixture_usage_estimate":true' in audit_text


def test_pending_call_rejects_replay_without_result() -> None:
    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    state.respond(_request())
    with pytest.raises(ControlledProviderError) as error:
        state.respond(_request())
    assert (error.value.status, error.value.code) == (409, "unexpected_history")


def test_tool_result_requires_exact_preceding_assistant_call() -> None:
    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    first_call = _tool_call(state.respond(_request()))
    messages = [
        {"role": "user", "content": "fixture"},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": first_call["id"],
                    "type": "function",
                    "function": {"name": "wrong_tool", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "tool_call_id": first_call["id"], "content": "result"},
    ]
    with pytest.raises(ControlledProviderError) as error:
        state.respond(_request(messages=messages))
    assert (error.value.status, error.value.code) == (409, "unexpected_history")
    assert state.pending_call_id == first_call["id"]

    messages[-2]["tool_calls"][0]["function"] = {
        "name": "observe_fixture",
        "arguments": '{"observation":"mutated"}',
    }
    with pytest.raises(ControlledProviderError) as arguments:
        state.respond(_request(messages=messages))
    assert (arguments.value.status, arguments.value.code) == (409, "unexpected_history")
    assert state.pending_call_id == first_call["id"]


def test_completed_tool_result_history_cannot_be_omitted() -> None:
    mapping = _manifest_mapping(max_requests=5)
    mapping["phases"].insert(
        1,
        {
            "phase_id": "corroborate",
            "tool_name": "observe_fixture",
            "tool_schema_digest": _digest(_schemas()["observe_fixture"]),
            "arguments": {"observation": "read generated fixture metadata"},
        },
    )
    state = ControlledProviderState(ControlledProviderManifest.from_mapping(mapping), TOKEN)
    first = _tool_call(state.respond(_request()))
    first_message_call = {
        "id": first["id"],
        "type": "function",
        "function": first["function"],
    }
    first_history = [
        {"role": "user", "content": "fixture"},
        {"role": "assistant", "tool_calls": [first_message_call]},
        {"role": "tool", "tool_call_id": first["id"], "content": "first result"},
    ]
    second = _tool_call(state.respond(_request(messages=first_history)))
    second_message_call = {
        "id": second["id"],
        "type": "function",
        "function": second["function"],
    }
    incomplete_history = [
        {"role": "user", "content": "fixture"},
        {"role": "assistant", "tool_calls": [second_message_call]},
        {"role": "tool", "tool_call_id": second["id"], "content": "second result"},
    ]
    with pytest.raises(ControlledProviderError) as error:
        state.respond(_request(messages=incomplete_history))
    assert (error.value.status, error.value.code) == (409, "unexpected_history")
    assert state.pending_call_id == second["id"]


def test_schema_drift_fails_without_emitting_a_call() -> None:
    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    with pytest.raises(ControlledProviderError) as error:
        state.respond(_request(tools=_tools(drift=True)))
    assert (error.value.status, error.value.code) == (422, "tool_schema_drift")
    assert state.pending_call_id is None


def test_request_limit_and_cancellation_are_distinct() -> None:
    capped = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping(max_requests=1)), TOKEN
    )
    capped.respond(_request())
    with pytest.raises(ControlledProviderError) as limited:
        capped.respond(_request())
    assert (limited.value.status, limited.value.code) == (429, "request_limit")

    cancelled = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    cancelled.cancel()
    with pytest.raises(ControlledProviderError) as stopped:
        cancelled.respond(_request())
    assert (stopped.value.status, stopped.value.code) == (409, "attempt_cancelled")


def test_tool_arguments_are_validated_against_dynamic_request_schema() -> None:
    mapping = _manifest_mapping()
    mapping["phases"][0]["arguments"] = {"observation": "not admitted"}
    state = ControlledProviderState(ControlledProviderManifest.from_mapping(mapping), TOKEN)
    with pytest.raises(ControlledProviderError) as error:
        state.respond(_request())
    assert (error.value.status, error.value.code) == (422, "invalid_tool_arguments")


def test_http_endpoint_requires_exact_token_and_returns_sse() -> None:
    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"
    try:
        wrong = urllib.request.Request(
            endpoint,
            data=_request(),
            headers={"Authorization": "Bearer wrong", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with pytest.raises(urllib.error.HTTPError) as unauthorized:
                urllib.request.urlopen(wrong, timeout=2)  # noqa: S310 - owned loopback fixture
        except urllib.error.URLError as error:
            if isinstance(error.reason, PermissionError):
                pytest.skip("sandbox blocks owned loopback connections")
            raise
        assert unauthorized.value.code == 401
        error = json.loads(unauthorized.value.read())
        assert error["error"]["code"] == "invalid_authorization"

        valid = urllib.request.Request(
            endpoint,
            data=_request(),
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(valid, timeout=2) as response:  # noqa: S310
            assert response.status == 200
            assert response.headers["X-BlueFire-Provider"] == "Test provider"
            call = _tool_call(response.read())
        assert call["function"]["name"] == "observe_fixture"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unknown_fields_and_tool_choice_conflicts_fail_closed() -> None:
    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    unknown = json.loads(_request())
    unknown["unreviewed"] = True
    with pytest.raises(ControlledProviderError) as shape:
        state.respond(_canonical(unknown))
    assert (shape.value.status, shape.value.code) == (400, "unsupported_request")

    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    conflict = json.loads(_request())
    conflict["tool_choice"] = {"type": "function", "function": {"name": "finish_scan"}}
    with pytest.raises(ControlledProviderError) as choice:
        state.respond(_canonical(conflict))
    assert (choice.value.status, choice.value.code) == (422, "tool_choice_conflict")

    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    extra_choice = json.loads(_request())
    extra_choice["tool_choice"] = {
        "type": "function",
        "function": {"name": "observe_fixture"},
        "extra": True,
    }
    with pytest.raises(ControlledProviderError) as extra:
        state.respond(_canonical(extra_choice))
    assert (extra.value.status, extra.value.code) == (422, "tool_choice_conflict")

    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    invalid_tuning = json.loads(_request())
    invalid_tuning["temperature"] = "maximum"
    with pytest.raises(ControlledProviderError) as tuning:
        state.respond(_canonical(invalid_tuning))
    assert (tuning.value.status, tuning.value.code) == (400, "unsupported_request")


def test_failure_after_pairing_does_not_advance_state(tmp_path: Path) -> None:
    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()),
        TOKEN,
        audit_path=tmp_path / "audit.jsonl",
    )
    first_call = _tool_call(state.respond(_request()))
    messages = [
        {"role": "user", "content": "fixture"},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": first_call["id"],
                    "type": "function",
                    "function": first_call["function"],
                }
            ],
        },
        {"role": "tool", "tool_call_id": first_call["id"], "content": "result"},
    ]
    invalid = json.loads(_request(messages=messages))
    invalid["stream_options"] = {"include_usage": "yes"}
    with pytest.raises(ControlledProviderError) as error:
        state.respond(_canonical(invalid))
    assert (error.value.status, error.value.code) == (400, "unsupported_request")
    assert state.pending_call_id == first_call["id"]

    next_call = _tool_call(state.respond(_request(messages=messages)))
    assert next_call["function"]["name"] == "finish_scan"


def test_audit_failure_does_not_publish_pending_call(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit-path-is-a-directory"
    audit_path.mkdir()
    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()),
        TOKEN,
        audit_path=audit_path,
    )
    with pytest.raises(ControlledProviderError) as error:
        state.respond(_request())
    assert (error.value.status, error.value.code) == (409, "audit_unavailable")
    assert state.pending_call_id is None


def test_nonfinite_json_is_rejected() -> None:
    mapping = _manifest_mapping()
    mapping["phases"][0]["arguments"] = {"observation": float("nan")}
    with pytest.raises(ControlledProviderError, match="tool arguments are invalid"):
        ControlledProviderManifest.from_mapping(mapping)

    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    with pytest.raises(ControlledProviderError) as error:
        state.respond(b'{"model":NaN}')
    assert (error.value.status, error.value.code) == (400, "invalid_json")

    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    with pytest.raises(ControlledProviderError) as duplicate:
        state.respond(b'{"model":"one","model":"two"}')
    assert (duplicate.value.status, duplicate.value.code) == (400, "invalid_json")


def test_ready_file_is_exclusive_and_atomically_published(tmp_path: Path) -> None:
    ready = tmp_path / "ready.json"
    payload = b'{"ready":true}\n'
    try:
        _write_private_exclusive(ready, payload)
    except PermissionError:
        pytest.skip("sandbox blocks atomic file publication")
    assert ready.read_bytes() == payload
    with pytest.raises(FileExistsError):
        _write_private_exclusive(ready, b'{"ready":false}\n')
    assert ready.read_bytes() == payload
    assert list(tmp_path.glob(".ready.json.*.tmp")) == []


def test_write_all_rejects_a_short_write(monkeypatch: pytest.MonkeyPatch) -> None:
    writes = iter((2, 0))
    monkeypatch.setattr("tools.controlled_strix_provider.os.write", lambda _fd, _data: next(writes))
    with pytest.raises(OSError, match="short write"):
        _write_all(123, b"abcd")


def test_handler_applies_socket_deadline_before_request_parsing() -> None:
    state = ControlledProviderState(
        ControlledProviderManifest.from_mapping(_manifest_mapping()), TOKEN
    )
    handler_type = build_handler(state)
    assert handler_type.request_deadline_seconds == 5.0
    assert "setup" in handler_type.__dict__
