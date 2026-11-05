from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from copy import deepcopy
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import pytest

import bluefire.strix_tool_conformance as conformance
from bluefire.controlled_strix_provider import (
    ControlledProviderError,
    ControlledProviderManifest,
    ControlledProviderState,
    _write_all,
    _write_private_exclusive,
    build_handler,
)
from bluefire.strix_tool_conformance import (
    BASE_TOOL_NAMES,
    CONTROLLED_FINISH_ARGUMENTS,
    OfflineRootToolProfile,
    ToolConformanceError,
    canonical_json,
    digest_json,
)
from tests_platform.strix_provider_profile_fixture import (
    ATTEMPT_ID,
    TOKEN,
    synthetic_manifest,
    synthetic_profile,
    synthetic_tools,
)


def _enroll_for_protocol_test(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, Any]) -> None:
    """Only tests replace the deliberately empty product enrollment set."""
    digest = OfflineRootToolProfile.from_mapping(mapping["profile"]).profile_digest
    monkeypatch.setattr(conformance, "APPROVED_PROFILE_DIGESTS", frozenset({digest}))


def _state(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mapping: dict[str, Any] | None = None,
    audit_path: Path | None = None,
) -> ControlledProviderState:
    candidate = synthetic_manifest() if mapping is None else mapping
    _enroll_for_protocol_test(monkeypatch, candidate)
    return ControlledProviderState(
        ControlledProviderManifest.from_mapping(candidate), TOKEN, audit_path=audit_path
    )


def _request(
    *, messages: list[dict[str, Any]] | None = None, tools: list[dict[str, Any]] | None = None
) -> bytes:
    return canonical_json(
        {
            "model": conformance.MODEL_ID,
            "messages": (
                messages if messages is not None else [{"role": "user", "content": "prompt secret"}]
            ),
            "tools": tools if tools is not None else synthetic_tools(),
            "stream": True,
            "parallel_tool_calls": False,
            "tool_choice": "auto",
            "stream_options": {"include_usage": True},
        }
    )


def _sse(payload: bytes) -> list[dict[str, Any] | str]:
    rows: list[dict[str, Any] | str] = []
    for line in payload.decode("utf-8").splitlines():
        if line:
            assert line.startswith("data: ")
            data = line.removeprefix("data: ")
            rows.append(data if data == "[DONE]" else json.loads(data))
    return rows


def _call(payload: bytes) -> dict[str, Any]:
    rows = _sse(payload)
    assert len(rows) == 4
    assert rows[-1] == "[DONE]"
    first = rows[0]
    assert isinstance(first, dict)
    return cast(dict[str, Any], first["choices"][0]["delta"]["tool_calls"][0])


def _history(first: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"role": "user", "content": "prompt secret"},
        {
            "role": "assistant",
            "tool_calls": [{"id": first["id"], "type": "function", "function": first["function"]}],
        },
        {"role": "tool", "tool_call_id": first["id"], "content": "graph result secret"},
    ]


def test_pinned_factory_name_order_and_unsupported_sdk_capabilities() -> None:
    assert len(BASE_TOOL_NAMES) == 43
    assert BASE_TOOL_NAMES[:2] == ("think", "load_skill")
    assert BASE_TOOL_NAMES[-2:] == ("create_agent", "stop_agent")
    profile = OfflineRootToolProfile.from_mapping(synthetic_manifest()["profile"])
    assert tuple(binding.name for binding in profile.tool_bindings) == (
        *BASE_TOOL_NAMES,
        "finish_scan",
        "view_image",
        "apply_patch",
        "exec_command",
    )
    assert profile.unsupported_sandbox_tools == ("view_image", "apply_patch", "exec_command")


@pytest.mark.parametrize("image_enabled,pty_enabled", [(True, True), (False, False)])
def test_offline_profile_binds_supported_sdk_suffix_variants(
    image_enabled: bool, pty_enabled: bool
) -> None:
    tools = synthetic_tools()
    if not image_enabled:
        tools = [tool for tool in tools if tool["function"]["name"] != "view_image"]
    if pty_enabled:
        shell = deepcopy(tools[-1])
        shell["function"]["name"] = "write_stdin"
        tools.append(shell)
    profile = synthetic_profile(tools)
    profile["supports_images"] = image_enabled
    profile["unsupported_sandbox_tools"] = [
        tool["function"]["name"] for tool in tools[len(BASE_TOOL_NAMES) + 1 :]
    ]
    parsed = OfflineRootToolProfile.from_mapping(profile)
    assert parsed.unsupported_sandbox_tools == tuple(profile["unsupported_sandbox_tools"])


def test_unreviewed_profile_cannot_start_provider() -> None:
    assert not conformance.APPROVED_PROFILE_DIGESTS
    manifest = ControlledProviderManifest.from_mapping(synthetic_manifest())
    with pytest.raises(ValueError, match="not independently enrolled"):
        ControlledProviderState(manifest, TOKEN)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(source_commit="0" * 40),
        lambda p: p.update(is_root=1),
        lambda p: p.update(interactive=0),
        lambda p: p.update(strict_tool_schemas=False),
        lambda p: p["tool_roster"][10].update(strict=False),
        lambda p: p["tool_roster"].reverse(),
        lambda p: p["tool_roster"].pop(),
        lambda p: p["tool_roster"].append(deepcopy(p["tool_roster"][-1])),
        lambda p: p["unsupported_sandbox_tools"].remove("exec_command"),
    ],
)
def test_offline_profile_rejects_source_identity_order_and_capability_drift(mutation: Any) -> None:
    profile = synthetic_manifest()["profile"]
    mutation(profile)
    with pytest.raises(ToolConformanceError):
        OfflineRootToolProfile.from_mapping(profile)


def test_self_consistent_nonstrict_descriptor_is_not_a_strict_profile() -> None:
    tools = synthetic_tools()
    tools[10]["function"]["strict"] = False
    with pytest.raises(ToolConformanceError, match="binding"):
        OfflineRootToolProfile.from_mapping(synthetic_profile(tools))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: m.update(schema_version="bluefire.controlled-strix-mechanics.v1"),
        lambda m: m.update(model_id="different-model"),
        lambda m: m.update(max_tools=16),
        lambda m: m.update(max_requests=8),
        lambda m: m.update(max_request_bytes=1_048_576),
        lambda m: m.update(max_output_tokens=100_000),
        lambda m: m["phases"][0].update(tool_name="exec_command"),
        lambda m: m["phases"][-1].update(arguments={"summary": "fiction"}),
        lambda m: m["phases"][-1]["arguments"].update(technical_analysis="A target was tested."),
        lambda m: m["phases"].reverse(),
    ],
)
def test_manifest_rejects_fictional_or_unbounded_phase_plan(mutation: Any) -> None:
    mapping = synthetic_manifest()
    mutation(mapping)
    with pytest.raises(ControlledProviderError):
        ControlledProviderManifest.from_mapping(mapping)


@pytest.mark.parametrize(
    "phase_index,schema",
    [
        (0, {"type": "object", "properties": {}, "required": [], "additionalProperties": True}),
        (1, {"type": "object", "properties": {}, "required": [], "additionalProperties": False}),
        (1, {"type": "object"}),
    ],
)
def test_phase_signature_rejects_self_consistent_permissive_digest(
    phase_index: int, schema: dict[str, Any]
) -> None:
    mapping = synthetic_manifest()
    phase = mapping["phases"][phase_index]
    phase["parameters_schema"] = schema
    phase["tool_schema_digest"] = digest_json(schema)
    binding = next(
        item for item in mapping["profile"]["tool_roster"] if item["name"] == phase["tool_name"]
    )
    binding["parameters_digest"] = digest_json(schema)
    with pytest.raises(ControlledProviderError, match="pinned|require"):
        ControlledProviderManifest.from_mapping(mapping)


def test_manifest_rejects_nonmapping_input() -> None:
    with pytest.raises(ControlledProviderError, match="manifest fields"):
        ControlledProviderManifest.from_mapping([{"schema_version": "v2"}])  # type: ignore[arg-type]


def test_streamed_tool_turns_pair_exact_history_and_audit_only_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    audit = tmp_path / "private" / "provider.jsonl"
    state = _state(monkeypatch, audit_path=audit)
    first = _call(state.respond(_request()))
    assert first["function"] == {"name": "view_agent_graph", "arguments": "{}"}
    assert state.pending_call_id == first["id"]
    second = _call(state.respond(_request(messages=_history(first))))
    assert second["function"] == {
        "name": "finish_scan",
        "arguments": canonical_json(CONTROLLED_FINISH_ARGUMENTS).decode("ascii"),
    }
    assert second["id"] != first["id"]
    rows = audit.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 2
    assert TOKEN not in "".join(rows)
    assert "prompt secret" not in "".join(rows)
    assert "graph result secret" not in "".join(rows)
    assert json.loads(rows[-1])["fixture_usage_estimate"] is True

    replay_state = _state(monkeypatch)
    replay_state.respond(_request())
    with pytest.raises(ControlledProviderError) as replay:
        replay_state.respond(_request())
    assert replay.value.code == "unexpected_history"


@pytest.mark.parametrize("drift", ["remove", "reorder", "schema", "description", "strict", "extra"])
def test_full_ordered_roster_drift_fails_before_first_call(
    monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    state = _state(monkeypatch)
    tools = synthetic_tools()
    if drift == "remove":
        tools.pop(10)
    elif drift == "reorder":
        tools[0], tools[1] = tools[1], tools[0]
    elif drift == "schema":
        tools[10]["function"]["parameters"]["properties"]["extra"] = {"type": "string"}
    elif drift == "description":
        tools[10]["function"]["description"] = "changed"
    elif drift == "strict":
        tools[10]["function"]["strict"] = False
    else:
        tools.append(deepcopy(tools[-1]))
    with pytest.raises(ControlledProviderError) as error:
        state.respond(_request(tools=tools))
    assert error.value.code == "tool_roster_drift"
    assert state.pending_call_id is None


def test_wrong_tool_result_and_request_usage_bounds_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(monkeypatch)
    first = _call(state.respond(_request()))
    wrong = _history(first)
    wrong[-2]["tool_calls"][0]["function"]["name"] = "exec_command"
    with pytest.raises(ControlledProviderError) as history:
        state.respond(_request(messages=wrong))
    assert history.value.code == "unexpected_history"
    assert state.pending_call_id == first["id"]

    state = _state(monkeypatch)
    request = json.loads(_request())
    request["max_tokens"] = 8_193
    with pytest.raises(ControlledProviderError) as cap:
        state.respond(canonical_json(request))
    assert cap.value.code == "unsupported_request"

    mapping = synthetic_manifest()
    mapping["max_input_tokens"] = 1
    state = _state(monkeypatch, mapping=mapping)
    with pytest.raises(ControlledProviderError) as estimate:
        state.respond(_request())
    assert estimate.value.code == "usage_limit"
    assert state.pending_call_id is None


def test_rejection_after_pairing_does_not_publish_next_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(monkeypatch)
    first = _call(state.respond(_request()))
    request = json.loads(_request(messages=_history(first)))
    request["stream_options"] = {"include_usage": False}
    with pytest.raises(ControlledProviderError) as error:
        state.respond(canonical_json(request))
    assert error.value.code == "unsupported_request"
    assert state.pending_call_id == first["id"]


def test_audit_failure_does_not_publish_a_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_directory = tmp_path / "audit-is-directory"
    audit_directory.mkdir()
    state = _state(monkeypatch, audit_path=audit_directory)
    with pytest.raises(ControlledProviderError) as error:
        state.respond(_request())
    assert error.value.code == "audit_unavailable"
    assert state.pending_call_id is None


@pytest.mark.parametrize("drift", ["unknown", "conflicting_choice", "extra_choice"])
def test_unknown_request_fields_and_tool_choice_conflicts_fail_closed(
    monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    state = _state(monkeypatch)
    request = json.loads(_request())
    if drift == "unknown":
        request["unreviewed"] = True
    elif drift == "conflicting_choice":
        request["tool_choice"] = {"type": "function", "function": {"name": "finish_scan"}}
    else:
        request["tool_choice"] = {
            "type": "function",
            "function": {"name": "view_agent_graph"},
            "extra": True,
        }
    with pytest.raises(ControlledProviderError) as error:
        state.respond(canonical_json(request))
    assert error.value.code == (
        "unsupported_request" if drift == "unknown" else "tool_choice_conflict"
    )
    assert state.pending_call_id is None


def test_preflight_is_not_a_streamed_tool_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _state(monkeypatch)
    request = json.loads(_request())
    request["tools"] = []
    request["stream"] = False
    with pytest.raises(ControlledProviderError) as preflight:
        state.respond(canonical_json(request))
    assert preflight.value.code == "stream_required"
    assert state.pending_call_id is None

    streamed = json.loads(_request())
    streamed["tools"] = []
    with pytest.raises(ControlledProviderError) as no_tools:
        state.respond(canonical_json(streamed))
    assert no_tools.value.code == "tool_roster_drift"
    assert state.pending_call_id is None


def test_request_limit_cancellation_and_json_rejections(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _state(monkeypatch)
    state.respond(_request())
    with pytest.raises(ControlledProviderError) as invalid:
        state.respond(b'{"model":NaN}')
    assert invalid.value.code == "invalid_json"
    with pytest.raises(ControlledProviderError) as capped:
        state.respond(_request())
    assert capped.value.code == "request_limit"

    state = _state(monkeypatch)
    state.cancel()
    with pytest.raises(ControlledProviderError) as stopped:
        state.respond(_request())
    assert stopped.value.code == "attempt_cancelled"

    state = _state(monkeypatch)
    with pytest.raises(ControlledProviderError) as duplicate:
        state.respond(b'{"model":"one","model":"two"}')
    assert duplicate.value.code == "invalid_json"


def test_http_handler_requires_bearer_and_emits_real_sse_grammar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(monkeypatch)
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
                urllib.request.urlopen(wrong, timeout=2)  # noqa: S310 - owned loopback
        except urllib.error.URLError as error:
            if isinstance(error.reason, PermissionError):
                pytest.skip("sandbox blocks owned loopback connections")
            raise
        assert unauthorized.value.code == 401
        assert json.loads(unauthorized.value.read())["error"]["code"] == "invalid_authorization"

        valid = urllib.request.Request(
            endpoint,
            data=_request(),
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(valid, timeout=2) as response:  # noqa: S310
            assert response.status == 200
            assert response.headers["X-BlueFire-Provider"] == "Test provider"
            assert _call(response.read())["function"]["name"] == "view_agent_graph"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_ready_publication_short_write_and_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready = tmp_path / "ready.json"
    try:
        _write_private_exclusive(ready, b'{"ready":true}\n')
    except PermissionError:
        pytest.skip("sandbox blocks atomic file publication")
    with pytest.raises(FileExistsError):
        _write_private_exclusive(ready, b'{"ready":false}\n')
    assert ready.read_bytes() == b'{"ready":true}\n'
    assert list(tmp_path.glob(".ready.json.*.tmp")) == []
    writes = iter((2, 0))
    monkeypatch.setattr(
        "bluefire.controlled_strix_provider.os.write", lambda _fd, _data: next(writes)
    )
    with pytest.raises(OSError, match="short write"):
        _write_all(123, b"abcd")

    import bluefire.controlled_strix_provider as installed_provider
    import tools.controlled_strix_provider as wrapper

    assert wrapper.main is installed_provider.main
    assert ATTEMPT_ID.startswith("engine-attempt-")
    handler_type = build_handler(_state(monkeypatch))
    assert handler_type.__dict__["request_deadline_seconds"] == 5.0
    assert "setup" in handler_type.__dict__
