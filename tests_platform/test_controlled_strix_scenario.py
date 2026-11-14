"""Synthetic wire tests; these descriptors are not installed Strix proof."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest

import bluefire.controlled_strix_scenario as scenario_module
from bluefire.controlled_strix_provider import ControlledProviderError
from bluefire.controlled_strix_scenario import (
    ControlledScenarioManifest,
    ControlledScenarioProviderState,
    ScenarioObservationRequest,
    ScenarioRootToolProfile,
    VerifiedScenarioObservation,
)
from bluefire.strix_tool_conformance import MODEL_ID
from tests_platform.strix_provider_profile_fixture import (
    TOKEN,
    synthetic_profile,
    synthetic_tools,
)

ATTEMPT = "engine-attempt-" + "a" * 32
ORIGIN = "http://bf-target-" + "a" * 32 + ":8080"
DIGEST = "sha256:" + "b" * 64
TENANT = "tenant-start-0001"
OTHER = "tenant-other-0001"
OWN_RECORD = "record-own-0001"
OTHER_RECORD = "record-other-0001"


def _tools() -> list[dict[str, Any]]:
    tools = synthetic_tools()
    shell = next(item["function"] for item in tools if item["function"]["name"] == "exec_command")
    shell["parameters"] = {
        "type": "object",
        "properties": {
            "cmd": {"type": "string"},
            "yield_time_ms": {"type": "integer"},
        },
        "required": ["cmd", "yield_time_ms"],
        "additionalProperties": False,
    }
    return tools


def _manifest(tools: list[dict[str, Any]]) -> dict[str, Any]:
    profile = synthetic_profile(tools)
    profile.update(
        schema_version=scenario_module.SCENARIO_PROFILE_SCHEMA,
        profile_id=scenario_module.SCENARIO_PROFILE_ID,
        provider_id=scenario_module.SCENARIO_PROVIDER_ID,
        supported_sandbox_tools=["exec_command"],
        unsupported_sandbox_tools=["view_image", "apply_patch"],
    )
    return {
        "schema_version": scenario_module.SCENARIO_MANIFEST_SCHEMA,
        "attempt_id": ATTEMPT,
        "model_id": MODEL_ID,
        "profile": profile,
        "max_requests": 4,
        "max_request_bytes": 131_072,
        "max_response_bytes": 65_536,
        "max_messages": 32,
        "max_tools": len(tools),
        "max_schema_depth": 16,
        "max_input_tokens": 32_768,
        "max_output_tokens": 8_192,
        "max_total_tokens": 40_960,
        "scenario": {
            "schema_version": scenario_module.SCENARIO_BINDING_SCHEMA,
            "observation_source_ref": DIGEST,
            "engine_brief": {
                "schema_version": "bluefire.tenant-record-engine-brief.v1",
                "case_ref": DIGEST,
                "experiment_ref": DIGEST,
                "attempt_id": ATTEMPT,
                "attempt_role": "baseline",
                "objective": scenario_module._BRIEF_OBJECTIVE,
                "asset_ref": DIGEST,
                "environment_ref": DIGEST,
                "scope_ref": DIGEST,
                "condition_ref": DIGEST,
                "target_snapshot_ref": DIGEST,
                "service_generation": "service-generation-0001",
                "starting_identity": {"kind": "tenant", "tenant_id": TENANT},
                "target_origin": ORIGIN,
                "authorized_url_set_ref": DIGEST,
                "discovery": {"method": "GET", "target": ORIGIN + "/openapi.json"},
                "delegation": {
                    "permitted_effects": list(scenario_module._PERMITTED_EFFECTS),
                    "target_assets": [DIGEST],
                    "identities": [TENANT],
                    "isolation": "owned_disposable_tenant_lab",
                    "max_http_calls": 16,
                    "max_total_response_bytes": 16 * 65_536,
                    "max_runtime_seconds": 300,
                },
                "success_evaluation": scenario_module._EVALUATION_TEXT,
            },
        },
    }


class _ObservedSource:
    binding_ref = DIGEST

    def __init__(
        self,
        *,
        first_status: int = 200,
        first_returns_foreign: bool = True,
        returned_record_override: str | None = None,
    ) -> None:
        self.first_status = first_status
        self.first_returns_foreign = first_returns_foreign
        self.returned_record_override = returned_record_override
        self.requests: list[ScenarioObservationRequest] = []

    def verify(self, request: ScenarioObservationRequest) -> VerifiedScenarioObservation:
        if request.model_result != f"captured:{request.phase_id}":
            raise ControlledProviderError(409, "observation_unverified", "tool output differs")
        self.requests.append(request)
        discovery = request.phase_id == "discover_target"
        route = (
            "metadata" if discovery else request.phase_id.removeprefix("try_")
        )
        status = 200 if discovery else self.first_status if route == "record_lookup" else 401
        return VerifiedScenarioObservation(
            request_ref=request.digest,
            attempt_id=request.attempt_id,
            scenario_ref=request.scenario_ref,
            phase_id=request.phase_id,
            call_id=request.call_id,
            tool_name=request.tool_name,
            arguments_digest=request.arguments_digest,
            model_result_digest=request.model_result_digest,
            model_result_bytes=request.model_result_bytes,
            execution_admission_ref=DIGEST,
            dispatch_ref=DIGEST,
            attachment_ref=DIGEST,
            terminal_ref=DIGEST,
            target_response_ref=DIGEST,
            independent_evidence_ref="sha256:" + f"{len(self.requests):064x}",
            evidence_retention_ref="sha256:" + f"{len(self.requests) + 100:064x}",
            target_snapshot_ref=DIGEST,
            admitted_target_url=request.target_url,
            authorized_url_set_ref=request.authorized_url_set_ref,
            service_generation="service-generation-0001",
            target_request_id="request-" + f"{len(self.requests):024x}",
            target_audit_ref=DIGEST,
            target_route=route,
            kind="discovery" if discovery else "target_response",
            status_code=status,
            routes=(
                ("record_lookup", "/records/{record_id}"),
                ("bounded_export", "/exports?tenant={tenant_id}"),
            ) if discovery else (),
            starting_tenant_id=TENANT if discovery else None,
            own_record_ids=(OWN_RECORD,) if discovery else (),
            known_tenants=(TENANT, OTHER) if discovery else (),
            record_directory=(OWN_RECORD, OTHER_RECORD) if discovery else (),
            returned_record_ids=((self.returned_record_override or OTHER_RECORD),) if (
                not discovery and status == 200 and self.first_returns_foreign
            ) else (),
        )


def _state(monkeypatch: pytest.MonkeyPatch, source: _ObservedSource):
    tools = _tools()
    mapping = _manifest(tools)
    digest = ScenarioRootToolProfile.from_mapping(mapping["profile"]).profile_digest
    monkeypatch.setattr(
        scenario_module, "APPROVED_SCENARIO_PROFILE_DIGESTS", frozenset({digest})
    )
    manifest = ControlledScenarioManifest.from_mapping(mapping)
    return ControlledScenarioProviderState(manifest, TOKEN, observation_source=source), tools


def _request(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        {
            "model": MODEL_ID,
            "messages": messages,
            "tools": tools,
            "stream": True,
            "parallel_tool_calls": False,
            "tool_choice": "auto",
            "stream_options": {"include_usage": True},
        },
        separators=(",", ":"),
    ).encode()


def _call(payload: bytes) -> dict[str, Any]:
    for line in payload.decode().splitlines():
        if line.startswith("data: {"):
            value = json.loads(line[6:])
            calls = value["choices"][0]["delta"].get("tool_calls", [])
            if calls:
                return calls[0]
    raise AssertionError("no tool call")


def _append_result(messages: list[dict[str, Any]], call: dict[str, Any], phase: str):
    messages.extend(
        [
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": call["id"], "type": "function", "function": call["function"]}
                ],
            },
            {"role": "tool", "tool_call_id": call["id"], "content": f"captured:{phase}"},
        ]
    )


@pytest.mark.parametrize(
    "first_status, first_returns_foreign, expected_routes",
    [
        (200, True, ("record_lookup",)),
        (200, False, ("record_lookup", "bounded_export")),
        (401, False, ("record_lookup", "bounded_export")),
    ],
)
def test_synthetic_observed_target_turns_select_and_finish(
    monkeypatch: pytest.MonkeyPatch,
    first_status: int,
    first_returns_foreign: bool,
    expected_routes: tuple[str, ...],
) -> None:
    source = _ObservedSource(
        first_status=first_status, first_returns_foreign=first_returns_foreign
    )
    state, tools = _state(monkeypatch, source)
    history: list[dict[str, Any]] = [{"role": "user", "content": "authorized lab"}]

    first = _call(state.respond(_request(history, tools)))
    assert first["function"]["name"] == "exec_command"
    assert "/openapi.json" in first["function"]["arguments"]
    assert len(source.requests) == 0
    _append_result(history, first, "discover_target")

    second = _call(state.respond(_request(history, tools)))
    assert "/records/" in second["function"]["arguments"]
    assert OTHER_RECORD in second["function"]["arguments"]
    _append_result(history, second, "try_record_lookup")

    third = _call(state.respond(_request(history, tools)))
    if not first_returns_foreign:
        assert third["function"]["name"] == "exec_command"
        assert "/exports?tenant=" in third["function"]["arguments"]
        _append_result(history, third, "try_bounded_export")
        third = _call(state.respond(_request(history, tools)))
    assert third["function"]["name"] == "finish_scan"
    assert state.trace().status == "finishing"
    assert state.trace().attempted_routes == expected_routes
    assert len(source.requests) == 1 + len(expected_routes)
    assert len(state.trace().completed_observation_refs) == len(source.requests)
    assert len(state.trace().independent_evidence_refs) == len(source.requests)
    assert len(state.trace().evidence_retention_refs) == len(source.requests)


def test_changed_or_missing_controller_observation_stops_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _ObservedSource()
    state, tools = _state(monkeypatch, source)
    history: list[dict[str, Any]] = [{"role": "user", "content": "authorized lab"}]
    first = _call(state.respond(_request(history, tools)))
    _append_result(history, first, "discover_target")
    history[-1]["content"] = "fabricated success"

    with pytest.raises(ControlledProviderError, match="tool output differs"):
        state.respond(_request(history, tools))
    assert state.trace().status == "unknown"
    with pytest.raises(ControlledProviderError, match="unresolved"):
        state.respond(_request(history, tools))


def test_scenario_binding_requires_generation_and_full_attempt_origin() -> None:
    mapping = _manifest(_tools())
    assert ControlledScenarioManifest.from_mapping(mapping).scenario.target_origin == ORIGIN
    del mapping["scenario"]["engine_brief"]["target_snapshot_ref"]
    with pytest.raises(ControlledProviderError, match="engine brief"):
        ControlledScenarioManifest.from_mapping(mapping)


def test_out_of_directory_returned_record_cannot_end_search(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _ObservedSource(returned_record_override="record-not-advertised-0001")
    state, tools = _state(monkeypatch, source)
    history: list[dict[str, Any]] = [{"role": "user", "content": "authorized lab"}]
    first = _call(state.respond(_request(history, tools)))
    _append_result(history, first, "discover_target")
    second = _call(state.respond(_request(history, tools)))
    _append_result(history, second, "try_record_lookup")

    with pytest.raises(ControlledProviderError, match="observed directory"):
        state.respond(_request(history, tools))
    assert state.trace().status == "unknown"


def test_missing_retention_receipt_or_changed_admitted_url_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BadSource(_ObservedSource):
        def verify(self, request: ScenarioObservationRequest) -> VerifiedScenarioObservation:
            observed = super().verify(request)
            return replace(observed, evidence_retention_ref="not-retained")

    source = BadSource()
    state, tools = _state(monkeypatch, source)
    history: list[dict[str, Any]] = [{"role": "user", "content": "authorized lab"}]
    first = _call(state.respond(_request(history, tools)))
    _append_result(history, first, "discover_target")
    with pytest.raises(ControlledProviderError, match="observation reference"):
        state.respond(_request(history, tools))
    assert state.trace().status == "unknown"

    class WrongUrlSource(_ObservedSource):
        def verify(self, request: ScenarioObservationRequest) -> VerifiedScenarioObservation:
            observed = super().verify(request)
            return replace(observed, admitted_target_url=ORIGIN + "/health")

    wrong = WrongUrlSource()
    state, tools = _state(monkeypatch, wrong)
    history = [{"role": "user", "content": "authorized lab"}]
    first = _call(state.respond(_request(history, tools)))
    _append_result(history, first, "discover_target")
    with pytest.raises(ControlledProviderError, match="tool observation differs"):
        state.respond(_request(history, tools))
