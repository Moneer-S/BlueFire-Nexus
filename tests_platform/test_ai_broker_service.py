"""Ordinary service journeys through a deterministic broker, with no network/effects."""

from __future__ import annotations

import base64
import copy
import json
import sys
import threading
import time
from concurrent.futures import Future
from dataclasses import replace
from itertools import islice
from pathlib import Path

import pytest

from bluefire.ai import PROPOSAL_JSON_SCHEMA, build_ai_provider
from bluefire.ai_broker import BrokeredAIProviderAccess
from bluefire.ai_broker_contract import BrokerEnrollment, schema_identity, validate_broker_request
from bluefire.ai_drafts import graph_draft_json_schema
from bluefire.ai_probe import _SCHEMA
from bluefire.ai_wire import AIProviderCancelled, AIProviderTransportError, structured_request
from bluefire.config import AIProviderKind, AutonomyLevel, load_config
from bluefire.job_runtime import RunJobController, _JobControl
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.ai_live_authorization_support import authorize_service
from tests_platform.job_wait_diagnostics import FUNCTIONS, _label
from tests_platform.test_ai import CONFIG_PATH
from tests_platform.test_ai import _request as proposal_request
from tests_platform.test_ai_drafts import _model_draft
from tests_platform.test_ai_drafts import _request as draft_request
from tests_platform.test_ai_integration import _request as run_request
from tests_platform.test_ai_wire_runtime import _ai_config, _envelope, _provider_config

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def forbid_http_or_credentials(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Broker tests may not launch HTTP workers or resolve environment credentials")

    monkeypatch.setattr("bluefire.ai_transport.subprocess.Popen", forbidden)
    monkeypatch.setattr("bluefire.ai_provider_access.credential_value", forbidden)


class DeterministicBroker:
    """Deterministic schema fixture; actual worker consent is checked in separate wire tests."""

    def __init__(self, enrollment):
        self.enrollment = enrollment
        self.requests = []
        self.seen = set()
        self.closed = False
        self.block = False
        self.entered = threading.Event()
        self.response_change = None

    def exchange(self, request, *, cancellation, timeout_seconds):
        assert not self.closed
        body = validate_broker_request(self.enrollment, request)
        assert request["request_id"] not in self.seen
        self.seen.add(request["request_id"])
        self.requests.append(copy.deepcopy(request))
        result = {
            "kind": "readiness" if body is None else "result",
            "session_id": request["session_id"],
            "binding_digest": request["binding_digest"],
            "request_id": request["request_id"],
            "request_digest": content_hash(request),
        }
        if request["kind"] in {"authorize", "revoke"}:
            result.update(
                kind="authorization",
                authorization_id=(
                    request["authorization"]["authorization_id"]
                    if request["kind"] == "authorize"
                    else request["authorization_id"]
                ),
                status="active" if request["kind"] == "authorize" else "revoked",
            )
            return result
        if body is None:
            result["credential_state"] = (
                "ready" if self.enrollment.config.api_key else "not_required"
            )
            return result
        self.entered.set()
        if self.block:
            assert cancellation.wait(2), "test never sent cancellation"
            # Intentionally return a late otherwise-valid result: the client must reject it.
        purpose, _digest = schema_identity(body, self.enrollment.config.kind)
        if purpose == "bluefire_connection_check":
            output = {"ok": True}
        elif purpose == "bluefire_ai_graph_draft":
            output = _model_draft()
        else:
            output = {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "no_change",
                "selected_step_id": None,
                "selected_behavior_id": None,
                "selected_action_id": None,
                "selected_edge": None,
                "parameter_changes": [],
                "rationale": "Keep the reviewed graph.",
                "alternatives": [],
                "confidence": 0.8,
                "requires_operator_review": True,
            }
        result["body"] = base64.b64encode(
            canonical_json_bytes(_envelope(self.enrollment.config.kind, output))
        ).decode()
        if self.response_change:
            self.response_change(result)
        return result

    def close(self):
        self.closed = True


def setup(tmp_path, kind=AIProviderKind.OPENAI_RESPONSES, *, local=False):
    provider = replace(_provider_config(kind, authenticated=not local), max_retries=0)
    draft = draft_request()
    enrollment = BrokerEnrollment.create(
        provider,
        session_id="a" * 64,
        expires_at_ms=time.time_ns() // 1_000_000 + 60_000,
        schemas=(
            ("bluefire_connection_check", content_hash(_SCHEMA)),
            ("bluefire_ai_proposal", content_hash(PROPOSAL_JSON_SCHEMA)),
            ("bluefire_ai_graph_draft", content_hash(graph_draft_json_schema(draft))),
        ),
        destination_policy="explicit_endpoint" if local else "public_https",
    )
    channel = DeterministicBroker(enrollment)
    access = BrokeredAIProviderAccess(enrollment, channel)
    config = replace(load_config(CONFIG_PATH), ai=_ai_config(provider))
    service = BlueFireService(
        project_root=ROOT,
        config=config,
        runs_dir=tmp_path / "runs",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "managed"),
        ai_provider_access=access,
    )
    authorize_service(service, provider, purposes=[name for name, _ in enrollment.schemas])
    # Bootstrap performs a real readiness check through the same access owner.
    channel.requests.clear()
    return provider, service, access, channel


@pytest.mark.parametrize("kind", [AIProviderKind.OPENAI_RESPONSES, AIProviderKind.CHAT_COMPLETIONS])
def test_normal_setup_graph_and_proposal_service_paths_keep_real_identity_without_credentials(
    tmp_path, kind
):
    provider, service, access, channel = setup(tmp_path, kind)
    try:
        health = service.catalog()["ai"]["providers"]
        enrolled_health = next(row["health"] for row in health if row["provider_id"] == provider.id)
        assert enrolled_health["lab_session_expires_at_ms"] == access.enrollment.expires_at_ms
        checked = service.check_ai_provider({"provider": provider.to_dict(), "connect": False})
        assert checked["credential_owner"] == "broker"
        assert checked["credential_state"] == "ready" and checked["attempts"] == 0
        assert checked["connectivity"] == "not_tested"
        assert all(row["kind"] == "readiness" for row in channel.requests)
        connected = service.check_ai_provider({"provider": provider.to_dict(), "connect": True})
        assert connected["code"] == "probe_passed" and connected["used_fallback"] is False
        assert connected["provider_id"] == provider.id and connected["model"] == provider.model
        draft = service.draft_ai_graph(
            {
                "objective": draft_request().objective,
                "provider_id": provider.id,
                "max_nodes": 6,
                "max_edges": 8,
            }
        )
        assert draft["saved"] is False
        assert draft["audit"]["validation"]["execution_authority_absent"] is True
        result = service.run(run_request("assist", provider.id))
        assert result["mode"] == "simulate" and result["status"] == "completed"
        assert result["ai_proposals"]
        assert all(
            row["provider"]["effective_provider_id"] == provider.id
            for row in result["ai_proposals"]
        ), [row["provider"] for row in result["ai_proposals"]]
        assert all(row["provider"]["used_fallback"] is False for row in result["ai_proposals"])
        assert all(
            row["proposal"]["proposal_type"] == "no_change" for row in result["ai_proposals"]
        )
        assert checked["broker_binding_digest"] == access.enrollment.digest
        for frame in channel.requests:
            assert not {"url", "endpoint", "headers", "Authorization", "api_key"} & set(frame)
            assert provider.endpoint not in json.dumps(frame)
    finally:
        service.close()
    assert channel.closed


def test_explicit_local_provider_is_representable_without_lending_target_network_authority(
    tmp_path,
):
    provider, service, access, _channel = setup(tmp_path, local=True)
    try:
        assert access.enrollment.destination_policy == "explicit_endpoint"
        assert provider.endpoint.startswith("http://127.0.0.1:")
        result = service.check_ai_provider({"provider": provider.to_dict(), "connect": True})
        assert result["code"] == "probe_passed" and result["credential_state"] == "not_required"
        with pytest.raises(AIProviderTransportError):
            replace(access.enrollment, destination_policy="public_https")
    finally:
        service.close()


def test_deterministic_mode_remains_available_without_broker_enrollment(tmp_path):
    _provider, service, _access, channel = setup(tmp_path)
    try:
        checked = service.check_ai_provider(
            {
                "provider": service.config.ai.fallback.to_dict(),
                "connect": True,
            }
        )
        assert checked["code"] == "deterministic_no_network"
        assert checked["credential_state"] == "not_required"
        assert checked["attempts"] == 0 and checked["connectivity"] == "not_tested"
        assert channel.requests == []
    finally:
        service.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("endpoint", "https://elsewhere.example/v1/responses"),
        ("model", "another-model"),
        ("api_key", {"env": "ANOTHER_REFERENCE"}),
        ("max_output_tokens", 900),
    ],
)
def test_unsaved_setup_changes_cannot_rebind_broker_authority(tmp_path, field, value):
    provider, service, _access, channel = setup(tmp_path)
    document = provider.to_dict()
    document[field] = value
    try:
        result = service.check_ai_provider({"provider": document, "connect": True})
        assert result["code"] == "broker_binding_required" and result["attempts"] == 0
        assert result["connectivity"] == "not_tested"
        assert channel.requests == []
    finally:
        service.close()


def test_cancellation_rejects_late_broker_result_without_deterministic_fallback(tmp_path):
    provider, service, access, channel = setup(tmp_path)
    cancel = threading.Event()
    channel.block = True
    selected = build_ai_provider(_ai_config(provider), access=access, cancel_event=cancel)
    results = []

    def call():
        try:
            results.append(selected.propose(proposal_request(AutonomyLevel.ASSIST)))
        except Exception as exc:
            results.append(exc)

    thread = threading.Thread(target=call)
    try:
        thread.start()
        assert channel.entered.wait(2)
        cancel.set()
        thread.join(2)
        assert not thread.is_alive()
        assert len(results) == 1 and isinstance(results[0], AIProviderCancelled)
        assert sum(row["kind"] == "post" for row in channel.requests) == 1
    finally:
        cancel.set()
        thread.join(2)
        service.close()


@pytest.mark.parametrize("tamper", ["model", "headers", "schema", "tools", "stream"])
def test_broker_rejects_caller_wire_authority_changes_before_channel(tmp_path, tamper):
    provider, service, access, channel = setup(tmp_path)
    value = structured_request(
        provider,
        instructions="test",
        input_text="{}",
        name="bluefire_ai_proposal",
        schema=PROPOSAL_JSON_SCHEMA,
    )
    if tamper == "model":
        value["model"] = "other"
    elif tamper == "schema":
        value["text"]["format"]["schema"] = {"type": "string"}
    else:
        value[tamper] = {"Authorization": "test-only"} if tamper == "headers" else True
    try:
        with pytest.raises(AIProviderTransportError):
            access.post(provider, body=canonical_json_bytes(value), timeout_seconds=1)
        assert channel.requests == []
    finally:
        service.close()


def test_mismatched_response_identity_never_reaches_provider_parser_as_success(tmp_path):
    provider, service, _access, channel = setup(tmp_path)
    channel.response_change = lambda response: response.update(request_id="b" * 64)
    try:
        result = service.check_ai_provider({"provider": provider.to_dict(), "connect": True})
        assert result["code"] == "broker_unavailable" and result["connectivity"] == "failed"
        assert result["used_fallback"] is False
    finally:
        service.close()


def _broker_entry_evidence(service, access, channel, control, job_id):
    controller = service.job_controller
    selected = control if type(control) is _JobControl else None
    controls = controller._controls if type(controller) is RunJobController else None
    future = selected.future if selected is not None else None

    def boolean(value):
        return value if type(value) is bool else None

    def event_flag(value):
        return boolean(value._flag) if type(value) is threading.Event else None

    evidence = {
        "stage": "broker_proposal_entry",
        "observation": "cached_nonatomic",
        "job_outcome": "not_observed",
        "control_available": selected is not None,
        "control_registered": (
            controls.get(job_id) is selected
            if selected is not None and type(controls) is dict and type(job_id) is str
            else None
        ),
        "future_state_cached": _label(
            future._state if type(future) is Future else None,
            {"PENDING", "RUNNING", "CANCELLED", "CANCELLED_AND_NOTIFIED", "FINISHED"},
        ),
        "cancel_requested": boolean(selected.cancel_requested) if selected is not None else None,
        "control_cancel_flag": event_flag(selected.cancel_event) if selected is not None else None,
        "slot_released": boolean(selected.slot_released) if selected is not None else None,
        "controller_closed": (
            boolean(controller._closed) if type(controller) is RunJobController else None
        ),
        "broker_cancel_flag": (
            event_flag(access._cancel) if type(access) is BrokeredAIProviderAccess else None
        ),
        "channel_closed": boolean(channel.closed),
        "entered_flag_now": event_flag(channel.entered),
    }
    requests = channel.requests
    counts = {kind: 0 for kind in ("readiness", "post", "authorize", "revoke", "unknown")}
    if type(requests) is list:
        for row in requests[:32]:
            kind = _label(row.get("kind") if type(row) is dict else None, set(counts) - {"unknown"})
            counts[kind] += 1
    evidence.update(
        request_counts=counts,
        request_list_available=type(requests) is list,
        requests_truncated=len(requests) > 32 if type(requests) is list else None,
        enrollment_expired=None,
    )
    enrollment = channel.enrollment
    if type(enrollment) is BrokerEnrollment and type(enrollment.expires_at_ms) is int:
        evidence["enrollment_expired"] = time.time_ns() // 1_000_000 >= enrollment.expires_at_ms

    # Only code-and-object-identity matched worker frames can contribute labels.
    # FINISHED is an executor state, not evidence of a durable successful job.
    frames = sys._current_frames()
    functions = []
    matched = False
    frame_truncated = False
    allowed = FUNCTIONS | {
        "exchange",
        "_exchange",
        "require_current",
        "validate_broker_request",
        "readiness",
        "transition_job",
        "__enter__",
        "__exit__",
    }
    for frame in islice(frames.values(), 8):
        labels = []
        selected_stack = False
        for _ in range(24):
            labels.append(_label(frame.f_code.co_name, allowed))
            if selected is not None and frame.f_code is RunJobController._run_job.__code__:
                selected_stack |= (
                    frame.f_locals.get("self") is controller
                    and frame.f_locals.get("control") is selected
                )
            frame = frame.f_back
            if frame is None:
                break
        frame_truncated |= frame is not None
        if selected_stack and not matched:
            matched, functions = True, labels
    evidence.update(
        selected_worker_observed=matched,
        selected_worker_functions=functions,
        thread_scan_truncated=len(frames) > 8,
        frame_scan_truncated=frame_truncated,
    )
    return evidence


def _report_broker_entry(service, access, channel, control, job_id):
    encoded = json.dumps(
        _broker_entry_evidence(service, access, channel, control, job_id), sort_keys=True
    )
    output = "Broker entry diagnostic: " + encoded
    if len(output) <= 4095:
        print(output, flush=True)


@pytest.mark.parametrize("signal", ["cancel", "close"])
def test_normal_job_cancellation_drains_broker_without_publishing_a_late_proposal(tmp_path, signal):
    provider, service, _access, channel = setup(tmp_path)
    channel.block = True
    submitted = service.submit_run(run_request("assist", provider.id))
    job_id = submitted["job"]["job_id"]
    try:
        controls = service.job_controller._controls
        control = controls.get(job_id) if type(controls) is dict else None
        try:
            assert channel.entered.wait(3), "normal job did not reach broker proposal request"
        except AssertionError:
            try:
                _report_broker_entry(service, _access, channel, control, job_id)
            except BaseException:
                # Diagnostics must not replace this assertion or prevent finally cleanup.
                pass
            raise
        if signal == "cancel":
            service.cancel_job(job_id)
        else:
            service.close()
        result = service.job_controller.wait(job_id, timeout=3)
        assert result["state"] == "cancelled"
        run = service.store.get_run(result["progress"]["run_id"])
        assert not any(event["event_type"] == "ai.proposal" for event in run["events"])
        assert sum(row["kind"] == "post" for row in channel.requests) == 1
        if signal == "cancel":
            channel.block = False
            checked = service.check_ai_provider({"provider": provider.to_dict(), "connect": True})
            assert checked["code"] == "probe_passed"
    finally:
        service.close()


def test_service_close_rejects_late_graph_draft_without_saving_or_fallback(tmp_path):
    provider, service, _access, channel = setup(tmp_path)
    channel.block = True
    results = []

    def draft():
        try:
            results.append(
                service.draft_ai_graph(
                    {
                        "objective": draft_request().objective,
                        "provider_id": provider.id,
                        "max_nodes": 6,
                        "max_edges": 8,
                    }
                )
            )
        except Exception as exc:
            results.append(exc)

    thread = threading.Thread(target=draft)
    try:
        thread.start()
        assert channel.entered.wait(3)
        service.close()
        thread.join(3)
        assert not thread.is_alive()
        assert len(results) == 1 and isinstance(results[0], AIProviderCancelled)
        assert sum(row["kind"] == "post" for row in channel.requests) == 1
    finally:
        service.close()
        thread.join(3)
