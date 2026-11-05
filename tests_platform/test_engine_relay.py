from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from bluefire.engine_network_policy import EngineNetworkPlan
from bluefire.engine_relay import (
    BoundedRelayAudit,
    ControlledModelGateway,
    EngineRelayError,
    FixedTargetRelay,
    GatewayRevocationReceipt,
    ModelForwardRequest,
    ModelGatewayPolicy,
    ModelGatewayRequest,
    ProtectedModelResult,
    ProtectedRevocationResult,
    ProtectedTargetResult,
    ProtectedUpstreamUnknown,
    RelayAuditRecord,
    TargetOperation,
    TargetRelayPolicy,
    TargetRelayRequest,
    model_gateway_authorization_ref,
)
from bluefire.tenant_record_service import TenantResponse
from bluefire.util import content_hash

ATTEMPT_ID = "engine-attempt-0123456789abcdef0123456789abcdef"
CREATED_AT = "2026-11-04T12:00:00Z"
EXPIRES_AT = "2026-11-04T12:30:00Z"
TOKEN = "ephemeral-gateway-token-0123456789abcdef"
PROTECTED_SECRET = "durable-provider-secret-must-not-leak"


def _digest(label: str) -> str:
    return content_hash({"label": label})


def _byte_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("ascii")).hexdigest()


AUTHORIZATION_REF = model_gateway_authorization_ref(ATTEMPT_ID, _byte_digest(TOKEN))


class FakeClock:
    def __init__(self) -> None:
        self.wall = datetime(2026, 11, 4, 12, 0, 1, tzinfo=timezone.utc)
        self.monotonic = 1_000_000_000

    def now(self) -> datetime:
        return self.wall

    def monotonic_ns(self) -> int:
        return self.monotonic

    def advance_ms(self, value: int) -> None:
        self.wall += timedelta(milliseconds=value)
        self.monotonic += value * 1_000_000


class FaultClock(FakeClock):
    def __init__(self) -> None:
        super().__init__()
        self.fault: str | None = None

    def now(self) -> datetime:
        if self.fault == "raise":
            raise RuntimeError(f"clock failed with {PROTECTED_SECRET}")
        if self.fault == "non_utc":
            return self.wall.replace(tzinfo=None)
        return super().now()


def _plan() -> EngineNetworkPlan:
    return EngineNetworkPlan.create(
        attempt_id=ATTEMPT_ID,
        network_identity_ref=_digest("network"),
        subnet="172.28.41.0/24",
        target_address="172.28.41.10",
        model_gateway_address="172.28.41.11",
        host_gateway_address="172.28.41.1",
        created_at=CREATED_AT,
    )


def _target_policy(**overrides: Any) -> TargetRelayPolicy:
    values: dict[str, Any] = {
        "binding_digest": _digest("binding"),
        "delegation_digest": _digest("delegation"),
        "objective_ref": _digest("objective"),
        "environment_ref": _digest("environment"),
        "target_snapshot_digest": _digest("snapshot"),
        "protected_target_ref": _digest("protected-target"),
        "relay_identity_ref": _digest("target-relay"),
        "admitted_routes": ("bounded_export", "health", "metadata", "record_lookup"),
        "admitted_record_ids": ("record-a1b2c3d4", "record-e5f6a7b8"),
        "admitted_tenant_ids": ("tenant-probe01", "tenant-protect1"),
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
    }
    values.update(overrides)
    return TargetRelayPolicy.from_network_plan(_plan(), **values)


def _model_policy(**overrides: Any) -> ModelGatewayPolicy:
    values: dict[str, Any] = {
        "binding_digest": _digest("binding"),
        "delegation_digest": _digest("delegation"),
        "objective_ref": _digest("objective"),
        "environment_ref": _digest("environment"),
        "provider_ref": _digest("provider"),
        "model_id": "bluefire-controlled-v1",
        "data_destination_ref": _digest("destination"),
        "relay_identity_ref": _digest("model-relay"),
        "authorization_ref": AUTHORIZATION_REF,
        "authorization_digest": _byte_digest(TOKEN),
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
        "max_requests": 4,
        "max_request_bytes": 1_024,
        "max_response_bytes": 1_024,
        "max_total_request_bytes": 4_096,
        "max_total_response_bytes": 4_096,
        "max_input_tokens_per_request": 256,
        "max_output_tokens_per_request": 128,
        "max_total_tokens": 1_536,
        "max_cost_microunits_per_request": 100_000,
        "max_total_cost_microunits": 400_000,
        "request_timeout_ms": 1_000,
    }
    values.update(overrides)
    if "authorization_ref" not in overrides:
        values["authorization_ref"] = model_gateway_authorization_ref(
            ATTEMPT_ID, values["authorization_digest"]
        )
    return ModelGatewayPolicy.from_network_plan(_plan(), **values)


def _target_headers(body: bytes) -> dict[str, str]:
    return {
        "content-type": "application/json; charset=utf-8",
        "content-length": str(len(body)),
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "x-bluefire-lab-request": "request-0123456789abcdef01234567",
    }


class FakeTargetForwarder:
    def __init__(self, clock: FakeClock) -> None:
        body = b'{"status":"ok"}\n'
        self.clock = clock
        self.calls: list[TargetOperation] = []
        self.result = ProtectedTargetResult(
            response=TenantResponse(status=200, headers=_target_headers(body), body=body),
            target_observation_ref=_digest("target-observation"),
            protected_secret_absent=True,
        )
        self.error: Exception | None = None
        self.advance_ms = 0
        self.entered: threading.Event | None = None
        self.release: threading.Event | None = None
        self.revocations = 0
        self.revoke_result = ProtectedRevocationResult(
            verified=True, receipt_ref=_digest("target-revocation")
        )

    def forward(self, operation: TargetOperation) -> ProtectedTargetResult:
        self.calls.append(operation)
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            assert self.release.wait(timeout=5)
        if self.advance_ms:
            self.clock.advance_ms(self.advance_ms)
        if self.error is not None:
            raise self.error
        return self.result

    def revoke(self, attempt_id: str, relay_identity_ref: str) -> ProtectedRevocationResult:
        assert attempt_id == ATTEMPT_ID
        assert relay_identity_ref == _digest("target-relay")
        self.revocations += 1
        return self.revoke_result


def _target_request(
    *,
    request_id: str = "relay-request-00000000000000000000000000000001",
    target: str = "/health",
    headers: tuple[tuple[str, str], ...] = (),
    **overrides: Any,
) -> TargetRelayRequest:
    values: dict[str, Any] = {
        "request_id": request_id,
        "attempt_id": ATTEMPT_ID,
        "authority": f"bf-target-{ATTEMPT_ID[-12:]}:8080",
        "method": "GET",
        "target": target,
        "headers": headers,
        "body": b"",
    }
    values.update(overrides)
    return TargetRelayRequest(**values)


def _target_relay(
    clock: FakeClock,
    *,
    policy: TargetRelayPolicy | None = None,
    forwarder: FakeTargetForwarder | None = None,
    audit: Any | None = None,
) -> tuple[FixedTargetRelay, FakeTargetForwarder, BoundedRelayAudit]:
    target_forwarder = forwarder or FakeTargetForwarder(clock)
    audit_log = audit or BoundedRelayAudit()
    return (
        FixedTargetRelay(
            policy or _target_policy(),
            target_forwarder,
            audit_log,
            clock=clock.now,
            monotonic_ns=clock.monotonic_ns,
        ),
        target_forwarder,
        audit_log,
    )


class FakeModelForwarder:
    def __init__(self, clock: FakeClock) -> None:
        body = b'{"id":"response-1"}'
        self.clock = clock
        self.calls: list[ModelForwardRequest] = []
        self.result = ProtectedModelResult(
            status=200,
            headers={"content-type": "application/json", "content-length": str(len(body))},
            body=body,
            input_tokens=23,
            output_tokens=17,
            cost_microunits=4_200,
            provider_request_ref=_digest("provider-request"),
            protected_secret_absent=True,
        )
        self.error: Exception | None = None
        self.advance_ms = 0
        self.entered: threading.Event | None = None
        self.release: threading.Event | None = None
        self.revocations = 0
        self.revoke_error: Exception | None = None
        self.revoke_result = ProtectedRevocationResult(
            verified=True, receipt_ref=_digest("provider-revocation")
        )
        self._durable_secret = PROTECTED_SECRET

    def forward(self, request: ModelForwardRequest) -> ProtectedModelResult:
        self.calls.append(request)
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            assert self.release.wait(timeout=5)
        if self.advance_ms:
            self.clock.advance_ms(self.advance_ms)
        if self.error is not None:
            raise self.error
        return self.result

    def revoke(self, attempt_id: str, authorization_ref: str) -> ProtectedRevocationResult:
        assert attempt_id == ATTEMPT_ID
        assert authorization_ref == AUTHORIZATION_REF
        self.revocations += 1
        if self.revoke_error is not None:
            raise self.revoke_error
        return self.revoke_result


def _model_body(**overrides: Any) -> bytes:
    value: dict[str, Any] = {
        "model": "bluefire-controlled-v1",
        "messages": [{"role": "user", "content": "inspect the admitted lab"}],
        "max_tokens": 64,
    }
    value.update(overrides)
    return json.dumps(value, separators=(",", ":")).encode()


def _json_unicode_escape(value: str) -> str:
    return "".join(f"\\u{ord(character):04x}" for character in value)


def _model_request(
    *,
    request_id: str = "gateway-request-00000000000000000000000000000001",
    body: bytes | None = None,
    **overrides: Any,
) -> ModelGatewayRequest:
    values: dict[str, Any] = {
        "request_id": request_id,
        "attempt_id": ATTEMPT_ID,
        "objective_ref": _digest("objective"),
        "provider_ref": _digest("provider"),
        "authority": f"bf-model-{ATTEMPT_ID[-12:]}:8081",
        "authorization": f"Bearer {TOKEN}",
        "method": "POST",
        "target": "/v1/chat/completions",
        "headers": (("accept", "application/json"), ("content-type", "application/json")),
        "body": _model_body() if body is None else body,
    }
    values.update(overrides)
    return ModelGatewayRequest(**values)


def _gateway(
    clock: FakeClock,
    *,
    policy: ModelGatewayPolicy | None = None,
    forwarder: FakeModelForwarder | None = None,
    audit: Any | None = None,
) -> tuple[ControlledModelGateway, FakeModelForwarder, BoundedRelayAudit]:
    model_forwarder = forwarder or FakeModelForwarder(clock)
    audit_log = audit or BoundedRelayAudit()
    return (
        ControlledModelGateway(
            policy or _model_policy(),
            TOKEN,
            model_forwarder,
            audit_log,
            clock=clock.now,
            monotonic_ns=clock.monotonic_ns,
        ),
        model_forwarder,
        audit_log,
    )


def _controlled_stream_request_body(**overrides: Any) -> bytes:
    # Generic relay grammar fixture, not a captured Strix root-tool roster.
    value: dict[str, Any] = {
        "model": "bluefire-controlled-v1",
        "messages": [{"role": "user", "content": "inspect the admitted lab"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "view_agent_graph",
                    "description": "Synthetic relay grammar descriptor for the pinned graph tool.",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "required": [],
                        "additionalProperties": False,
                    },
                    "strict": True,
                },
            }
        ],
        "stream": True,
        "parallel_tool_calls": False,
        "stream_options": {"include_usage": True},
        "max_tokens": 64,
    }
    value.update(overrides)
    return json.dumps(value, separators=(",", ":")).encode()


def _controlled_stream_documents(*, arguments: str = "{}") -> list[dict[str, Any]]:
    base: dict[str, Any] = {
        "id": f"chatcmpl-{ATTEMPT_ID[-12:]}-0001",
        "object": "chat.completion.chunk",
        "created": 1_762_272_001,
        "model": "bluefire-controlled-v1",
        "system_fingerprint": "bluefire-test-provider-fixture-estimate",
    }
    return [
        {
            **base,
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_0001_0123456789abcdef",
                                "type": "function",
                                "function": {
                                    "name": "view_agent_graph",
                                    "arguments": arguments,
                                },
                            }
                        ],
                    },
                    "finish_reason": None,
                }
            ],
        },
        {
            **base,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
        },
        {
            **base,
            "choices": [],
            "usage": {"prompt_tokens": 23, "completion_tokens": 17, "total_tokens": 40},
        },
    ]


def _controlled_stream_body(documents: list[dict[str, Any]] | None = None) -> bytes:
    values = _controlled_stream_documents() if documents is None else documents
    lines = [f"data: {json.dumps(value, separators=(',', ':'))}\n\n" for value in values]
    lines.append("data: [DONE]\n\n")
    return "".join(lines).encode()


def _controlled_stream_headers(body: bytes, **overrides: str) -> dict[str, str]:
    values = {
        "content-type": "text/event-stream",
        "content-length": str(len(body)),
        "cache-control": "no-store",
        "x-bluefire-provider": "Test provider",
    }
    values.update(overrides)
    return values


def _controlled_stream_result(
    body: bytes | None = None,
    *,
    headers: dict[str, str] | None = None,
    **overrides: Any,
) -> ProtectedModelResult:
    payload = _controlled_stream_body() if body is None else body
    values: dict[str, Any] = {
        "status": 200,
        "headers": _controlled_stream_headers(payload) if headers is None else headers,
        "body": payload,
        "input_tokens": 23,
        "output_tokens": 17,
        "cost_microunits": 0,
        "provider_request_ref": _digest("controlled-provider-request"),
        "protected_secret_absent": True,
        "fixture_usage_estimate": True,
        "live_model_proof": False,
    }
    values.update(overrides)
    return ProtectedModelResult(**values)


def test_target_policy_is_exactly_bound_to_network_plan_and_limits() -> None:
    policy = _target_policy()
    plan = _plan()

    assert policy.network_policy_digest == plan.policy_digest
    assert policy.relay_authority == f"{plan.target.service_name}:{plan.target.port}"
    assert policy.to_dict()["redirect_policy"] == "refuse_all"
    assert policy.policy_digest == content_hash(policy.to_dict())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attempt_id", "engine-attempt-wrong"),
        ("binding_digest", "sha256:bad"),
        ("relay_authority", "127.0.0.1:8080"),
        ("admitted_routes", ("health", "health")),
        ("admitted_routes", ("arbitrary",)),
        ("admitted_record_ids", ("../secret",)),
        ("admitted_tenant_ids", ("",)),
        ("max_requests", True),
        ("max_response_bytes", 0),
        ("request_timeout_ms", 30_001),
        ("expires_at", CREATED_AT),
    ],
)
def test_target_policy_rejects_unbound_or_unbounded_values(field: str, value: Any) -> None:
    with pytest.raises(ValueError):
        replace(_target_policy(), **{field: value})


@pytest.mark.parametrize(
    ("target", "expected_route", "record_id", "tenant_id"),
    [
        ("/health", "health", None, None),
        ("/openapi.json", "metadata", None, None),
        ("/records/record-a1b2c3d4", "record_lookup", "record-a1b2c3d4", None),
        ("/exports?tenant=tenant-protect1", "bounded_export", None, "tenant-protect1"),
    ],
)
def test_target_relay_forwards_only_typed_admitted_operations(
    target: str, expected_route: str, record_id: str | None, tenant_id: str | None
) -> None:
    clock = FakeClock()
    relay, forwarder, audit = _target_relay(clock)
    headers = (
        (("x-bluefire-lab-tenant", "tenant-protect1"),)
        if expected_route in {"record_lookup", "bounded_export"}
        else ()
    )

    response = relay.handle(_target_request(target=target, headers=headers))

    assert response.status == 200
    assert len(forwarder.calls) == 1
    operation = forwarder.calls[0]
    assert operation.route_id == expected_route
    assert operation.record_id == record_id
    assert operation.tenant_id == tenant_id
    assert operation.binding_digest == _digest("binding")
    assert operation.delegation_digest == _digest("delegation")
    assert operation.network_policy_digest == _plan().policy_digest
    assert operation.relay_identity_ref == _digest("target-relay")
    assert operation.protected_target_ref == _digest("protected-target")
    assert operation.source_identity == "engine_worker"
    assert operation.max_response_bytes == _target_policy().max_response_bytes
    assert not hasattr(operation, "url")
    assert response.receipt.audit_record_digest == audit.records()[0].record_digest


@pytest.mark.parametrize(
    "target",
    [
        "http://evil.invalid/health",
        "//evil.invalid/health",
        "/health#fragment",
        "/%68ealth",
        "/records/../record-a1b2c3d4",
        "/records//record-a1b2c3d4",
        "/records/record-unknown1",
        "/records/record-a1b2c3d4?x=1",
        "/exports",
        "/exports?tenant=tenant-protect1&tenant=tenant-probe01",
        "/exports?tenant=tenant-protect1&extra=x",
        "/exports?tenant=tenant-unknown1",
        "/health?x=1",
        "/health\\evil",
    ],
)
def test_target_relay_rejects_path_query_and_scope_aliases(target: str) -> None:
    clock = FakeClock()
    relay, forwarder, _audit = _target_relay(clock)

    with pytest.raises(EngineRelayError) as error:
        relay.handle(_target_request(target=target))

    assert error.value.code in {"route_refused", "scope_refused"}
    assert forwarder.calls == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"attempt_id": "engine-attempt-ffffffffffffffffffffffffffffffff"},
        {"authority": "evil.invalid:8080"},
        {"method": "CONNECT"},
        {"method": "POST"},
        {"body": b"not empty"},
        {"headers": (("host", "evil.invalid"),)},
        {"headers": (("authorization", "BlueFireLab secret"),)},
        {"headers": (("x-bluefire-lab-source-token", "secret"),)},
        {"headers": (("x-forwarded-host", "evil.invalid"),)},
        {"headers": (("connection", "upgrade"),)},
        {"headers": (("accept", "application/json"), ("accept", "text/plain"))},
        {"headers": (("Accept", "application/json"),)},
        {"headers": (("x-bluefire-lab-tenant", "tenant-unknown1"),)},
        {"headers": (("user-agent", "ok\r\nHost: evil"),)},
        {"headers": (("user-agent", "BlueFire\N{LATIN SMALL LETTER E WITH ACUTE}"),)},
        {"headers": (("user-agent", "BlueFire\u0085"),)},
        {"headers": (("user-agent", "BlueFire\u2028"),)},
    ],
)
def test_target_relay_rejects_authority_method_body_and_header_smuggling(
    overrides: dict[str, Any],
) -> None:
    clock = FakeClock()
    relay, forwarder, _audit = _target_relay(clock)

    with pytest.raises(EngineRelayError):
        relay.handle(_target_request(**overrides))

    assert forwarder.calls == []


@pytest.mark.parametrize("body", ["", None, bytearray()])
def test_target_relay_rejects_non_bytes_body_even_when_empty(body: Any) -> None:
    clock = FakeClock()
    relay, forwarder, _audit = _target_relay(clock)

    with pytest.raises(EngineRelayError) as error:
        relay.handle(_target_request(body=body))

    assert error.value.code == "method_refused"
    assert forwarder.calls == []


def test_target_relay_refuses_replay_and_reserves_budget_before_forwarding() -> None:
    clock = FakeClock()
    policy = _target_policy(max_requests=1, max_total_response_bytes=256 * 1024)
    relay, forwarder, _audit = _target_relay(clock, policy=policy)
    request = _target_request()

    relay.handle(request)
    with pytest.raises(EngineRelayError, match="already consumed") as replay:
        relay.handle(request)
    with pytest.raises(EngineRelayError, match="budget") as exhausted:
        relay.handle(_target_request(request_id="relay-request-00000000000000000000000000000002"))

    assert replay.value.code == "replay_refused"
    assert exhausted.value.code == "budget_exhausted"
    assert len(forwarder.calls) == 1


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (
            ProtectedTargetResult(
                TenantResponse(302, {"location": "/health"}, b""),
                _digest("observation"),
                True,
            ),
            "invalid_upstream",
        ),
        (
            ProtectedTargetResult(
                TenantResponse(200, {"content-type": "text/html"}, b"x"),
                _digest("observation"),
                True,
            ),
            "invalid_upstream",
        ),
        (
            ProtectedTargetResult(
                TenantResponse(
                    200,
                    {"content-type": "application/json; charset=utf-8", "content-length": "99"},
                    b"{}",
                ),
                _digest("observation"),
                True,
            ),
            "invalid_upstream",
        ),
        (
            ProtectedTargetResult(
                TenantResponse(200, _target_headers(b"{}"), b"{}"),
                _digest("observation"),
                False,
            ),
            "invalid_upstream",
        ),
        (
            ProtectedTargetResult(
                TenantResponse(
                    200,
                    {
                        **_target_headers(b"{}"),
                        "cache-control": "no-store\N{LATIN SMALL LETTER E WITH ACUTE}",
                    },
                    b"{}",
                ),
                _digest("observation"),
                True,
            ),
            "invalid_upstream",
        ),
    ],
)
def test_target_relay_rejects_redirects_malformed_responses_and_incomplete_secret_scan(
    result: ProtectedTargetResult, expected: str
) -> None:
    clock = FakeClock()
    forwarder = FakeTargetForwarder(clock)
    forwarder.result = result
    relay, _forwarder, audit = _target_relay(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        relay.handle(_target_request())

    assert error.value.code == expected
    assert audit.records()[0].status == expected


def test_target_relay_deadline_and_forwarder_failure_are_sanitized_and_audited() -> None:
    clock = FakeClock()
    forwarder = FakeTargetForwarder(clock)
    forwarder.error = RuntimeError(f"forwarder failed with {PROTECTED_SECRET}")
    relay, _forwarder, audit = _target_relay(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as failed:
        relay.handle(_target_request())
    assert failed.value.code == "upstream_failed"
    assert PROTECTED_SECRET not in str(failed.value)
    assert failed.value.__cause__ is None
    assert audit.records()[0].status == "upstream_failed"

    clock = FakeClock()
    forwarder = FakeTargetForwarder(clock)
    forwarder.advance_ms = 1_001
    relay, _forwarder, audit = _target_relay(
        clock, policy=_target_policy(request_timeout_ms=1_000), forwarder=forwarder
    )
    with pytest.raises(EngineRelayError) as deadline:
        relay.handle(_target_request())
    assert deadline.value.code == "deadline_exceeded"
    assert audit.records()[0].status == "deadline_exceeded"


def test_target_relay_revocation_suppresses_an_inflight_response() -> None:
    clock = FakeClock()
    forwarder = FakeTargetForwarder(clock)
    forwarder.entered = threading.Event()
    forwarder.release = threading.Event()
    relay, _forwarder, audit = _target_relay(clock, forwarder=forwarder)
    result: list[BaseException | object] = []

    def run() -> None:
        try:
            result.append(relay.handle(_target_request()))
        except BaseException as exc:  # pragma: no branch - assertion captures result
            result.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    assert forwarder.entered.wait(timeout=5)
    revocation = relay.revoke()
    forwarder.release.set()
    thread.join(timeout=5)

    assert revocation.verified is True
    assert len(result) == 1 and isinstance(result[0], EngineRelayError)
    assert result[0].code == "revoked"
    assert audit.records()[0].status == "revoked"
    with pytest.raises(EngineRelayError, match="revoked"):
        relay.handle(_target_request(request_id="relay-request-00000000000000000000000000000002"))


def test_target_relay_receipts_are_deterministic_and_hash_only() -> None:
    first_clock = FakeClock()
    first, _forwarder, first_audit = _target_relay(first_clock)
    second_clock = FakeClock()
    second, _forwarder, second_audit = _target_relay(second_clock)
    request = _target_request(
        target="/exports?tenant=tenant-protect1",
        headers=(("x-bluefire-lab-tenant", "tenant-protect1"),),
    )

    first_response = first.handle(request)
    second_response = second.handle(request)

    assert first_response.receipt == second_response.receipt
    assert first_audit.records()[0] == second_audit.records()[0]
    public = repr(first_response.receipt) + json.dumps(first_audit.records()[0].to_dict())
    assert "tenant-protect1" not in public
    assert 'status":"ok' not in public
    assert first_response.receipt.receipt_digest == content_hash(first_response.receipt.to_dict())


def test_target_relay_rejects_malformed_result_object_and_audits_refusal() -> None:
    clock = FakeClock()
    forwarder = FakeTargetForwarder(clock)
    forwarder.result = object()  # type: ignore[assignment]
    relay, _forwarder, audit = _target_relay(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        relay.handle(_target_request())

    assert error.value.code == "invalid_upstream"
    assert audit.records()[0].status == "invalid_upstream"


class CallbackBody(bytes):
    _callback: Callable[[], object]
    _triggered: bool

    def __new__(cls, callback: Callable[[], object], value: bytes) -> CallbackBody:
        instance = super().__new__(cls, value)
        instance._callback = callback
        instance._triggered = False
        return instance

    def decode(self, *args: Any, **kwargs: Any) -> str:
        if not self._triggered:
            self._triggered = True
            self._callback()
        return super().decode(*args, **kwargs)


class ExplodingHeaders(dict[str, str]):
    def items(self):  # type: ignore[no-untyped-def]
        raise RuntimeError(f"untrusted headers contained {PROTECTED_SECRET}")


def test_target_relay_revocation_during_response_validation_suppresses_publication() -> None:
    clock = FakeClock()
    forwarder = FakeTargetForwarder(clock)
    relay, _forwarder, audit = _target_relay(clock, forwarder=forwarder)
    body = CallbackBody(relay.revoke, b'{"status":"ok"}\n')
    forwarder.result = replace(
        forwarder.result,
        response=TenantResponse(
            status=200,
            headers=_target_headers(body),
            body=body,
        ),
    )

    with pytest.raises(EngineRelayError) as error:
        relay.handle(_target_request())

    assert error.value.code == "revoked"
    assert audit.records()[0].status == "revoked"


def test_target_relay_rejects_hostile_header_mapping_without_leak_or_busy_wedge() -> None:
    clock = FakeClock()
    forwarder = FakeTargetForwarder(clock)
    valid = forwarder.result
    forwarder.result = replace(
        valid,
        response=replace(
            valid.response,
            headers=ExplodingHeaders(valid.response.headers),
        ),
    )
    relay, _forwarder, audit = _target_relay(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        relay.handle(_target_request())

    assert error.value.code == "invalid_upstream"
    assert PROTECTED_SECRET not in str(error.value)
    assert error.value.__cause__ is None
    assert audit.records()[0].status == "invalid_upstream"
    forwarder.result = valid
    response = relay.handle(
        _target_request(request_id="relay-request-00000000000000000000000000000002")
    )
    assert response.status == 200


@pytest.mark.parametrize(
    "body",
    [b"not-json", b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e9999}'],
)
def test_target_relay_rejects_invalid_and_non_finite_json_responses(body: bytes) -> None:
    clock = FakeClock()
    forwarder = FakeTargetForwarder(clock)
    forwarder.result = replace(
        forwarder.result,
        response=TenantResponse(200, _target_headers(body), body),
    )
    relay, _forwarder, audit = _target_relay(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        relay.handle(_target_request())

    assert error.value.code == "invalid_upstream"
    assert audit.records()[0].status == "invalid_upstream"


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("deadline", "deadline_exceeded"), ("expiry", "expired")],
)
def test_target_relay_rechecks_time_after_untrusted_response_validation(
    mode: str, expected: str
) -> None:
    clock = FakeClock()
    forwarder = FakeTargetForwarder(clock)

    def advance() -> None:
        if mode == "deadline":
            clock.advance_ms(1_001)
        else:
            clock.wall = datetime(2026, 11, 4, 12, 30, tzinfo=timezone.utc)

    body = CallbackBody(advance, b'{"status":"ok"}\n')
    forwarder.result = replace(
        forwarder.result,
        response=TenantResponse(200, _target_headers(body), body),
    )
    relay, _forwarder, audit = _target_relay(
        clock,
        policy=_target_policy(request_timeout_ms=1_000),
        forwarder=forwarder,
    )

    with pytest.raises(EngineRelayError) as error:
        relay.handle(_target_request())

    assert error.value.code == expected
    assert audit.records()[0].status == expected


@pytest.mark.parametrize("fault", ["non_utc", "raise"])
def test_target_relay_clock_failure_after_forward_is_audited_and_never_wedges(
    fault: str,
) -> None:
    clock = FaultClock()
    forwarder = FakeTargetForwarder(clock)
    valid = forwarder.result
    body = CallbackBody(lambda: setattr(clock, "fault", fault), valid.response.body)
    forwarder.result = replace(
        valid,
        response=TenantResponse(200, _target_headers(body), body),
    )
    relay, _forwarder, audit = _target_relay(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        relay.handle(_target_request())

    assert error.value.code == "clock_invalid"
    assert PROTECTED_SECRET not in str(error.value)
    assert audit.records()[0].status == "clock_invalid"
    assert audit.records()[0].recorded_at == CREATED_AT
    clock.fault = None
    forwarder.result = valid
    response = relay.handle(
        _target_request(request_id="relay-request-00000000000000000000000000000002")
    )
    assert response.status == 200


class BlockingAudit:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.inner = BoundedRelayAudit()

    def append(self, record: RelayAuditRecord) -> None:
        self.entered.set()
        assert self.release.wait(timeout=5)
        self.inner.append(record)


def test_target_relay_commits_publication_before_audit_and_allows_later_revocation() -> None:
    clock = FakeClock()
    audit = BlockingAudit()
    relay, _forwarder, _audit = _target_relay(clock, audit=audit)
    handled: list[BaseException | object] = []
    revoked: list[ProtectedRevocationResult] = []

    def handle() -> None:
        try:
            handled.append(relay.handle(_target_request()))
        except BaseException as exc:  # pragma: no branch
            handled.append(exc)

    handle_thread = threading.Thread(target=handle)
    handle_thread.start()
    assert audit.entered.wait(timeout=5)
    revoke_thread = threading.Thread(target=lambda: revoked.append(relay.revoke()))
    revoke_thread.start()
    revoke_thread.join(timeout=5)

    assert not revoke_thread.is_alive()
    assert handle_thread.is_alive()
    assert len(revoked) == 1 and revoked[0].verified is True
    audit.release.set()
    handle_thread.join(timeout=5)

    assert len(handled) == 1 and not isinstance(handled[0], BaseException)
    assert len(audit.inner.records()) == 1
    with pytest.raises(EngineRelayError, match="revoked"):
        relay.handle(_target_request(request_id="relay-request-00000000000000000000000000000002"))


def test_target_relay_malformed_protected_revocation_is_unverified_and_stable() -> None:
    clock = FakeClock()
    forwarder = FakeTargetForwarder(clock)
    forwarder.revoke_result = object()  # type: ignore[assignment]
    relay, _forwarder, _audit = _target_relay(clock, forwarder=forwarder)

    first = relay.revoke()
    second = relay.revoke()

    assert first == second
    assert first.verified is False
    assert first.receipt_ref.startswith("sha256:")
    assert forwarder.revocations == 1


def test_model_policy_binds_authority_provider_destination_and_all_budgets() -> None:
    policy = _model_policy()
    plan = _plan()

    assert policy.network_policy_digest == plan.policy_digest
    assert (
        policy.gateway_authority == f"{plan.model_gateway.service_name}:{plan.model_gateway.port}"
    )
    assert policy.to_dict()["path"] == "/v1/chat/completions"
    assert policy.to_dict()["redirect_policy"] == "refuse_all"
    assert policy.policy_digest == content_hash(policy.to_dict())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attempt_id", "bad"),
        ("delegation_digest", "sha256:bad"),
        ("gateway_authority", "127.0.0.1:8081"),
        ("model_id", " bad"),
        ("max_requests", False),
        ("max_request_bytes", 1),
        ("max_total_request_bytes", 512),
        ("max_input_tokens_per_request", 0),
        ("max_total_tokens", 1),
        ("max_cost_microunits_per_request", 0),
        ("max_total_cost_microunits", 1),
        ("request_timeout_ms", 0),
        ("expires_at", CREATED_AT),
    ],
)
def test_model_policy_rejects_unbound_or_unbounded_values(field: str, value: Any) -> None:
    with pytest.raises(ValueError):
        replace(_model_policy(), **{field: value})


def test_model_gateway_forwards_sanitized_typed_request_and_returns_hash_only_receipt() -> None:
    clock = FakeClock()
    gateway, forwarder, audit = _gateway(clock)

    response = gateway.handle(_model_request())

    assert response.status == 200
    assert len(forwarder.calls) == 1
    forwarded = forwarder.calls[0]
    assert forwarded.attempt_id == ATTEMPT_ID
    assert forwarded.binding_digest == _digest("binding")
    assert forwarded.delegation_digest == _digest("delegation")
    assert forwarded.network_policy_digest == _plan().policy_digest
    assert forwarded.relay_identity_ref == _digest("model-relay")
    assert forwarded.provider_ref == _digest("provider")
    assert forwarded.data_destination_ref == _digest("destination")
    assert forwarded.authorization_ref == AUTHORIZATION_REF
    assert forwarded.max_input_tokens == 256
    assert forwarded.max_output_tokens == 128
    assert forwarded.max_response_bytes == _model_policy().max_response_bytes
    assert not hasattr(forwarded, "authorization")
    assert response.receipt.input_tokens == 23
    assert response.receipt.output_tokens == 17
    assert response.receipt.cost_microunits == 4_200
    assert response.receipt.audit_record_digest == audit.records()[0].record_digest
    public = repr(response.receipt) + json.dumps(audit.records()[0].to_dict())
    assert TOKEN not in public
    assert PROTECTED_SECRET not in public
    assert "inspect the admitted lab" not in public


@pytest.mark.parametrize(
    "overrides",
    [
        {"authorization": TOKEN},
        {"authorization": f"bearer {TOKEN}"},
        {"authorization": f"Bearer {TOKEN} "},
        {"authorization": f"Bearer {TOKEN[:-1]}\N{LATIN SMALL LETTER E WITH ACUTE}"},
        {"attempt_id": "engine-attempt-ffffffffffffffffffffffffffffffff"},
        {"objective_ref": _digest("different-objective")},
        {"provider_ref": _digest("different-provider")},
        {"authority": "evil.invalid:8081"},
        {"method": "CONNECT"},
        {"target": "http://evil.invalid/v1/chat/completions"},
        {"target": "/v1/chat/completions?x=1"},
        {"headers": (("host", "evil.invalid"), ("content-type", "application/json"))},
        {
            "headers": (
                ("content-type", "application/json"),
                ("proxy-authorization", "secret"),
            )
        },
        {
            "headers": (
                ("content-type", "application/json"),
                ("x-forwarded-host", "evil.invalid"),
            )
        },
        {
            "headers": (
                ("content-type", "application/json"),
                ("content-type", "application/json"),
            )
        },
        {"headers": (("Content-Type", "application/json"),)},
        {"headers": (("content-type", "text/plain"),)},
        {
            "headers": (
                ("content-type", "application/json"),
                ("user-agent", "BlueFire\N{LATIN SMALL LETTER E WITH ACUTE}"),
            )
        },
        {
            "headers": (
                ("content-type", "application/json"),
                ("user-agent", "BlueFire\u0085"),
            )
        },
        {
            "headers": (
                ("content-type", "application/json"),
                ("user-agent", "BlueFire\u2028"),
            )
        },
    ],
)
def test_model_gateway_rejects_auth_scope_route_and_header_smuggling(
    overrides: dict[str, Any],
) -> None:
    clock = FakeClock()
    gateway, forwarder, _audit = _gateway(clock)

    with pytest.raises(EngineRelayError):
        gateway.handle(_model_request(**overrides))

    assert forwarder.calls == []


@pytest.mark.parametrize(
    "body",
    [
        b"not-json",
        b"[]",
        b'{"model":"bluefire-controlled-v1","model":"other"}',
        b'{"model":"bluefire-controlled-v1","temperature":NaN}',
        b'{"model":"bluefire-controlled-v1","temperature":1e9999}',
        _model_body(model="other-model"),
        _model_body(max_tokens=True),
        _model_body(max_tokens=129),
        _model_body(max_tokens=1, max_completion_tokens=1),
        _model_body(secret=TOKEN),
    ],
)
def test_model_gateway_rejects_malformed_json_model_drift_and_token_authority(
    body: bytes,
) -> None:
    clock = FakeClock()
    gateway, forwarder, _audit = _gateway(clock)

    with pytest.raises(EngineRelayError):
        gateway.handle(_model_request(body=body))

    assert forwarder.calls == []


def test_model_gateway_rejects_unicode_escaped_ephemeral_bearer_in_request() -> None:
    clock = FakeClock()
    gateway, forwarder, _audit = _gateway(clock)
    escaped = _json_unicode_escape(TOKEN)
    body = (
        f'{{"model":"bluefire-controlled-v1","messages":[],"max_tokens":64,"hidden":"{escaped}"}}'
    ).encode()
    assert TOKEN.encode() not in body

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request(body=body))

    assert error.value.code == "invalid_request"
    assert TOKEN not in str(error.value)
    assert forwarder.calls == []


def test_model_gateway_rejects_excessive_json_depth() -> None:
    clock = FakeClock()
    gateway, forwarder, _audit = _gateway(clock)
    nested = "{}"
    for _ in range(66):
        nested = '{"a":' + nested + "}"
    body = ('{"model":"bluefire-controlled-v1","nested":' + nested + "}").encode()

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request(body=body))

    assert error.value.code == "invalid_json"
    assert forwarder.calls == []


def test_model_gateway_refuses_replay_and_conservatively_reserves_all_budgets() -> None:
    clock = FakeClock()
    policy = _model_policy(
        max_requests=1,
        max_total_request_bytes=1_024,
        max_total_response_bytes=1_024,
        max_total_tokens=384,
        max_total_cost_microunits=100_000,
    )
    gateway, forwarder, _audit = _gateway(clock, policy=policy)
    request = _model_request()

    gateway.handle(request)
    with pytest.raises(EngineRelayError) as replay:
        gateway.handle(request)
    with pytest.raises(EngineRelayError) as exhausted:
        gateway.handle(
            _model_request(request_id="gateway-request-00000000000000000000000000000002")
        )

    assert replay.value.code == "replay_refused"
    assert exhausted.value.code == "budget_exhausted"
    assert len(forwarder.calls) == 1


def test_model_gateway_busy_gate_prevents_concurrent_oversubscription() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.entered = threading.Event()
    forwarder.release = threading.Event()
    gateway, _forwarder, _audit = _gateway(clock, forwarder=forwarder)
    result: list[BaseException | object] = []

    def run() -> None:
        try:
            result.append(gateway.handle(_model_request()))
        except BaseException as exc:  # pragma: no branch
            result.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    assert forwarder.entered.wait(timeout=5)
    with pytest.raises(EngineRelayError) as busy:
        gateway.handle(
            _model_request(request_id="gateway-request-00000000000000000000000000000002")
        )
    forwarder.release.set()
    thread.join(timeout=5)

    assert busy.value.code == "busy"
    assert len(result) == 1 and not isinstance(result[0], BaseException)
    assert len(forwarder.calls) == 1


@pytest.mark.parametrize(
    "mutator",
    [
        lambda result: replace(result, status=302),
        lambda result: replace(result, headers={"location": "https://evil.invalid"}),
        lambda result: replace(result, headers={"content-type": "text/html"}),
        lambda result: replace(
            result,
            headers={"content-type": "application/json", "content-length": "999"},
        ),
        lambda result: replace(result, input_tokens=257),
        lambda result: replace(result, output_tokens=129),
        lambda result: replace(result, cost_microunits=100_001),
        lambda result: replace(result, provider_request_ref="sha256:bad"),
        lambda result: replace(result, protected_secret_absent=False),
        lambda result: replace(result, body=""),
        lambda result: replace(result, headers=None),
        lambda result: replace(
            result,
            headers={
                **result.headers,
                "cache-control": "no-store\N{LATIN SMALL LETTER E WITH ACUTE}",
            },
        ),
    ],
)
def test_model_gateway_rejects_malformed_or_unverified_upstream_result(
    mutator: Any,
) -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.result = mutator(forwarder.result)
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)

    with pytest.raises((EngineRelayError, ValueError)) as error:
        gateway.handle(_model_request())

    if isinstance(error.value, EngineRelayError):
        assert error.value.code == "invalid_upstream"
    assert audit.records()[0].status == "invalid_upstream"


def test_model_gateway_rejects_malformed_result_object_and_audits_refusal() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.result = object()  # type: ignore[assignment]
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request())

    assert error.value.code == "invalid_upstream"
    assert audit.records()[0].status == "invalid_upstream"


def test_model_gateway_revocation_during_response_validation_suppresses_publication() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)
    body = CallbackBody(gateway.revoke, forwarder.result.body)
    forwarder.result = replace(
        forwarder.result,
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body=body,
    )

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request())

    assert error.value.code == "revoked"
    assert audit.records()[0].status == "revoked"


def test_model_gateway_rejects_hostile_header_mapping_without_leak_or_busy_wedge() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    valid = forwarder.result
    forwarder.result = replace(valid, headers=ExplodingHeaders(valid.headers))
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request())

    assert error.value.code == "invalid_upstream"
    assert PROTECTED_SECRET not in str(error.value)
    assert error.value.__cause__ is None
    assert audit.records()[0].status == "invalid_upstream"
    forwarder.result = valid
    response = gateway.handle(
        _model_request(request_id="gateway-request-00000000000000000000000000000002")
    )
    assert response.status == 200


@pytest.mark.parametrize(
    "body",
    [b"not-json", b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e9999}'],
)
def test_model_gateway_rejects_invalid_and_non_finite_json_responses(body: bytes) -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.result = replace(
        forwarder.result,
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body=body,
    )
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request())

    assert error.value.code == "invalid_upstream"
    assert audit.records()[0].status == "invalid_upstream"


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("deadline", "deadline_exceeded"), ("expiry", "expired")],
)
def test_model_gateway_rechecks_time_after_untrusted_response_validation(
    mode: str, expected: str
) -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)

    def advance() -> None:
        if mode == "deadline":
            clock.advance_ms(1_001)
        else:
            clock.wall = datetime(2026, 11, 4, 12, 30, tzinfo=timezone.utc)

    body = CallbackBody(advance, forwarder.result.body)
    forwarder.result = replace(
        forwarder.result,
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body=body,
    )
    gateway, _forwarder, audit = _gateway(
        clock,
        policy=_model_policy(request_timeout_ms=1_000),
        forwarder=forwarder,
    )

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request())

    assert error.value.code == expected
    assert audit.records()[0].status == expected


@pytest.mark.parametrize("fault", ["non_utc", "raise"])
def test_model_gateway_clock_failure_after_forward_is_audited_and_never_wedges(
    fault: str,
) -> None:
    clock = FaultClock()
    forwarder = FakeModelForwarder(clock)
    valid = forwarder.result
    body = CallbackBody(lambda: setattr(clock, "fault", fault), valid.body)
    forwarder.result = replace(
        valid,
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body=body,
    )
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request())

    assert error.value.code == "clock_invalid"
    assert PROTECTED_SECRET not in str(error.value)
    assert audit.records()[0].status == "clock_invalid"
    assert audit.records()[0].recorded_at == CREATED_AT
    clock.fault = None
    forwarder.result = valid
    response = gateway.handle(
        _model_request(request_id="gateway-request-00000000000000000000000000000002")
    )
    assert response.status == 200


def test_model_gateway_rejects_ephemeral_bearer_in_upstream_response() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    body = f'{{"leak":"{TOKEN}"}}'.encode()
    forwarder.result = replace(
        forwarder.result,
        body=body,
        headers={"content-type": "application/json", "content-length": str(len(body))},
    )
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request())

    assert error.value.code == "invalid_upstream"
    assert TOKEN not in str(error.value)
    assert audit.records()[0].status == "secret_leak"


def test_model_gateway_rejects_unicode_escaped_ephemeral_bearer_in_response() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    escaped = _json_unicode_escape(TOKEN)
    body = f'{{"leak":"{escaped}"}}'.encode()
    assert TOKEN.encode() not in body
    forwarder.result = replace(
        forwarder.result,
        body=body,
        headers={"content-type": "application/json", "content-length": str(len(body))},
    )
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request())

    assert error.value.code == "invalid_upstream"
    assert TOKEN not in str(error.value)
    assert audit.records()[0].status == "secret_leak"


def test_model_gateway_deadline_and_forwarder_failure_are_sanitized_and_audited() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.error = RuntimeError(f"provider failed with {PROTECTED_SECRET}")
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as failed:
        gateway.handle(_model_request())
    assert failed.value.code == "upstream_failed"
    assert PROTECTED_SECRET not in str(failed.value)
    assert failed.value.__cause__ is None
    assert audit.records()[0].status == "upstream_failed"

    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.advance_ms = 1_001
    gateway, _forwarder, audit = _gateway(
        clock, policy=_model_policy(request_timeout_ms=1_000), forwarder=forwarder
    )
    with pytest.raises(EngineRelayError) as deadline:
        gateway.handle(_model_request())
    assert deadline.value.code == "deadline_exceeded"
    assert audit.records()[0].status == "deadline_exceeded"


def test_model_gateway_revocation_suppresses_inflight_result_and_is_idempotent() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.entered = threading.Event()
    forwarder.release = threading.Event()
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)
    result: list[BaseException | object] = []

    def run() -> None:
        try:
            result.append(gateway.handle(_model_request()))
        except BaseException as exc:  # pragma: no branch
            result.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    assert forwarder.entered.wait(timeout=5)
    first = gateway.revoke()
    second = gateway.revoke()
    forwarder.release.set()
    thread.join(timeout=5)

    assert first == second
    assert first.protected_revocation_verified is True
    assert first.inflight_request is True
    assert forwarder.revocations == 1
    assert len(result) == 1 and isinstance(result[0], EngineRelayError)
    assert result[0].code == "revoked"
    assert audit.records()[0].status == "revoked"
    with pytest.raises(EngineRelayError, match="revoked"):
        gateway.handle(
            _model_request(request_id="gateway-request-00000000000000000000000000000002")
        )


def test_model_gateway_commits_publication_before_audit_and_allows_later_revocation() -> None:
    clock = FakeClock()
    audit = BlockingAudit()
    gateway, _forwarder, _audit = _gateway(clock, audit=audit)
    handled: list[BaseException | object] = []
    revoked: list[GatewayRevocationReceipt] = []

    def handle() -> None:
        try:
            handled.append(gateway.handle(_model_request()))
        except BaseException as exc:  # pragma: no branch
            handled.append(exc)

    handle_thread = threading.Thread(target=handle)
    handle_thread.start()
    assert audit.entered.wait(timeout=5)
    revoke_thread = threading.Thread(target=lambda: revoked.append(gateway.revoke()))
    revoke_thread.start()
    revoke_thread.join(timeout=5)

    assert not revoke_thread.is_alive()
    assert handle_thread.is_alive()
    assert len(revoked) == 1
    assert revoked[0].protected_revocation_verified is True
    audit.release.set()
    handle_thread.join(timeout=5)

    assert len(handled) == 1 and not isinstance(handled[0], BaseException)
    assert len(audit.inner.records()) == 1
    with pytest.raises(EngineRelayError, match="revoked"):
        gateway.handle(
            _model_request(request_id="gateway-request-00000000000000000000000000000002")
        )


def test_model_gateway_malformed_protected_revocation_fails_lease_closed() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.revoke_result = object()  # type: ignore[assignment]
    gateway, _forwarder, _audit = _gateway(clock, forwarder=forwarder)
    lease = gateway.lease()

    first = gateway.revoke()
    second = gateway.revoke()

    assert first == second
    assert first.protected_revocation_verified is False
    assert first.protected_revocation_ref is not None
    assert first.protected_revocation_ref.startswith("sha256:")
    assert forwarder.revocations == 1
    with pytest.raises(EngineRelayError) as error:
        lease.revoke()
    assert error.value.code == "revocation_unverified"
    assert TOKEN not in repr(first)


def test_model_gateway_lease_exposes_only_ephemeral_token_and_refuses_unverified_revoke() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    gateway, _forwarder, _audit = _gateway(clock, forwarder=forwarder)
    lease = gateway.lease()

    assert lease.authorization_ref == AUTHORIZATION_REF
    assert lease.secret_value() == TOKEN
    assert TOKEN not in repr(lease)
    cleanup_ref = lease.revoke()
    assert cleanup_ref.startswith("sha256:")
    with pytest.raises(EngineRelayError, match="revoked"):
        lease.secret_value()

    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.revoke_result = ProtectedRevocationResult(
        verified=False, receipt_ref=_digest("unverified-revocation")
    )
    gateway, _forwarder, _audit = _gateway(clock, forwarder=forwarder)
    with pytest.raises(EngineRelayError) as unverified:
        gateway.lease().revoke()
    assert unverified.value.code == "revocation_unverified"


def test_gateway_constructor_and_cross_gateway_authority_fail_closed() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    with pytest.raises(ValueError):
        ControlledModelGateway(
            _model_policy(),
            "wrong-token-that-is-long-enough-0123456789",
            forwarder,
            BoundedRelayAudit(),
            clock=clock.now,
            monotonic_ns=clock.monotonic_ns,
        )

    other_token = "other-ephemeral-token-0123456789abcdef"
    other_policy = _model_policy(authorization_digest=_byte_digest(other_token))
    other = ControlledModelGateway(
        other_policy,
        other_token,
        forwarder,
        BoundedRelayAudit(),
        clock=clock.now,
        monotonic_ns=clock.monotonic_ns,
    )
    with pytest.raises(EngineRelayError) as error:
        other.handle(_model_request())
    assert error.value.code == "invalid_authorization"
    assert forwarder.calls == []


class FailingAudit:
    def append(self, _record: RelayAuditRecord) -> None:
        raise RuntimeError(f"audit failed with {PROTECTED_SECRET}")


def test_audit_failure_prevents_target_and_model_response_release_without_leaking() -> None:
    clock = FakeClock()
    target, _target_forwarder, _target_audit = _target_relay(clock, audit=FailingAudit())
    with pytest.raises(EngineRelayError) as target_error:
        target.handle(_target_request())
    assert target_error.value.code == "audit_unavailable"
    assert PROTECTED_SECRET not in str(target_error.value)

    clock = FakeClock()
    gateway, _model_forwarder, _model_audit = _gateway(clock, audit=FailingAudit())
    with pytest.raises(EngineRelayError) as model_error:
        gateway.handle(_model_request())
    assert model_error.value.code == "audit_unavailable"
    assert PROTECTED_SECRET not in str(model_error.value)


def test_gateway_receipts_are_deterministic_and_public_objects_contain_no_secrets() -> None:
    first_clock = FakeClock()
    first, first_forwarder, first_audit = _gateway(first_clock)
    second_clock = FakeClock()
    second, second_forwarder, second_audit = _gateway(second_clock)
    request = _model_request()

    first_response = first.handle(request)
    second_response = second.handle(request)

    assert first_response.receipt == second_response.receipt
    assert first_audit.records()[0] == second_audit.records()[0]
    public = " ".join(
        (
            repr(first),
            repr(first_response),
            repr(first_response.receipt),
            repr(first_forwarder.calls[0]),
            json.dumps(first_response.receipt.to_dict()),
            json.dumps(first_audit.records()[0].to_dict()),
        )
    )
    assert TOKEN not in public
    assert PROTECTED_SECRET not in public
    assert "inspect the admitted lab" not in public
    assert first_response.receipt.receipt_digest == content_hash(first_response.receipt.to_dict())
    assert second_forwarder.calls[0] == first_forwarder.calls[0]


def test_controlled_sse_policy_is_explicit_and_policy_digested() -> None:
    ordinary = _model_policy()
    controlled = _model_policy(allow_controlled_test_sse=True)

    assert ordinary.allow_controlled_test_sse is False
    assert controlled.allow_controlled_test_sse is True
    assert ordinary.policy_digest != controlled.policy_digest
    assert controlled.to_dict()["allow_controlled_test_sse"] is True
    with pytest.raises(ValueError):
        replace(controlled, allow_controlled_test_sse=1)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "case",
    ["not_admitted", "usage_missing", "parallel", "unknown_field", "duplicate_tool"],
)
def test_controlled_sse_request_requires_exact_policy_and_shape(case: str) -> None:
    clock = FakeClock()
    policy = _model_policy(allow_controlled_test_sse=case != "not_admitted")
    body_value = json.loads(_controlled_stream_request_body())
    if case == "usage_missing":
        body_value.pop("stream_options")
    elif case == "parallel":
        body_value["parallel_tool_calls"] = True
    elif case == "unknown_field":
        body_value["unreviewed"] = True
    elif case == "duplicate_tool":
        body_value["tools"].append(body_value["tools"][0])
    body = json.dumps(body_value, separators=(",", ":")).encode()
    gateway, forwarder, _audit = _gateway(clock, policy=policy)

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request(body=body))

    assert error.value.code in {"invalid_request", "scope_refused"}
    assert forwarder.calls == []


def test_controlled_sse_exact_fixture_succeeds_and_preserves_nonlive_truth() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.result = _controlled_stream_result()
    gateway, _forwarder, audit = _gateway(
        clock,
        policy=_model_policy(allow_controlled_test_sse=True),
        forwarder=forwarder,
    )
    request = _model_request(body=_controlled_stream_request_body())

    response = gateway.handle(request)

    assert response.status == 200
    assert dict(response.headers)["x-bluefire-provider"] == "Test provider"
    assert response.receipt.input_tokens == 23
    assert response.receipt.output_tokens == 17
    assert response.receipt.cost_microunits == 0
    assert response.receipt.fixture_usage_estimate is True
    assert response.receipt.live_model_proof is False
    record = audit.records()[0]
    assert record.status == "succeeded"
    assert record.fixture_usage_estimate is True
    assert record.live_model_proof is False
    assert record.response_digest == _byte_digest(response.body.decode("utf-8"))
    forwarded = forwarder.calls[0]
    assert forwarded.max_response_bytes == _model_policy().max_response_bytes
    public = json.dumps(response.receipt.to_dict()) + json.dumps(record.to_dict())
    assert "view_agent_graph" not in public
    assert TOKEN not in public
    assert PROTECTED_SECRET not in public


@pytest.mark.parametrize(
    ("case", "header", "value"),
    [
        ("missing_provider", "x-bluefire-provider", None),
        ("wrong_provider", "x-bluefire-provider", "test provider"),
        ("wrong_cache", "cache-control", "public"),
        ("wrong_type", "content-type", "application/json"),
        ("wrong_length", "content-length", "1"),
        ("extra_header", "location", "https://evil.invalid"),
    ],
)
def test_controlled_sse_rejects_noncanonical_response_headers(
    case: str, header: str, value: str | None
) -> None:
    del case
    clock = FakeClock()
    body = _controlled_stream_body()
    headers = _controlled_stream_headers(body)
    if value is None:
        headers.pop(header)
    else:
        headers[header] = value
    forwarder = FakeModelForwarder(clock)
    forwarder.result = _controlled_stream_result(body, headers=headers)
    gateway, _forwarder, audit = _gateway(
        clock,
        policy=_model_policy(allow_controlled_test_sse=True),
        forwarder=forwarder,
    )

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request(body=_controlled_stream_request_body()))

    assert error.value.code == "invalid_upstream"
    assert audit.records()[0].status == "invalid_upstream"


@pytest.mark.parametrize(
    "body",
    [
        b"",
        _controlled_stream_body().replace(b"\n", b"\r\n"),
        _controlled_stream_body()[:-2],
        _controlled_stream_body().replace(b"data: [DONE]\n\n", b""),
        _controlled_stream_body() + b"data: [DONE]\n\n",
        b": comment\n\n" + _controlled_stream_body(),
        b"event: message\ndata: {}\n\n" + _controlled_stream_body(),
        b"\xef\xbb\xbf" + _controlled_stream_body(),
        b"\xff\xfe\n\n",
        _controlled_stream_body() + b"\n\n",
    ],
)
def test_controlled_sse_rejects_malformed_truncated_or_ambiguous_framing(body: bytes) -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.result = _controlled_stream_result(body)
    gateway, _forwarder, audit = _gateway(
        clock,
        policy=_model_policy(
            allow_controlled_test_sse=True,
            max_response_bytes=4_096,
            max_total_response_bytes=4_096,
        ),
        forwarder=forwarder,
    )

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request(body=_controlled_stream_request_body()))

    assert error.value.code == "invalid_upstream"
    assert audit.records()[0].status == "invalid_upstream"


@pytest.mark.parametrize(
    "case",
    [
        "model_drift",
        "unknown_tool",
        "array_arguments",
        "duplicate_arguments",
        "finish_drift",
        "usage_total",
        "usage_mismatch",
        "zero_usage",
        "duplicate_member",
        "nonfinite",
    ],
)
def test_controlled_sse_rejects_semantically_invalid_frames(case: str) -> None:
    documents = json.loads(json.dumps(_controlled_stream_documents()))
    overrides: dict[str, Any] = {}
    if case == "model_drift":
        documents[1]["model"] = "other-model"
    elif case == "unknown_tool":
        documents[0]["choices"][0]["delta"]["tool_calls"][0]["function"]["name"] = "other"
    elif case == "array_arguments":
        documents[0]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"] = "[]"
    elif case == "duplicate_arguments":
        documents[0]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"] = (
            '{"unexpected":"a","unexpected":"b"}'
        )
    elif case == "finish_drift":
        documents[1]["choices"][0]["finish_reason"] = "stop"
    elif case == "usage_total":
        documents[2]["usage"]["total_tokens"] = 41
    elif case == "usage_mismatch":
        overrides["input_tokens"] = 24
    elif case == "zero_usage":
        documents[2]["usage"] = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
        overrides.update(input_tokens=0, output_tokens=0)
    body = _controlled_stream_body(documents)
    if case == "duplicate_member":
        body = body.replace(b'"created":1762272001', b'"created":1762272001,"created":1', 1)
    elif case == "nonfinite":
        body = body.replace(b'"created":1762272001', b'"created":1e9999', 1)
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.result = _controlled_stream_result(body, **overrides)
    gateway, _forwarder, audit = _gateway(
        clock,
        policy=_model_policy(allow_controlled_test_sse=True),
        forwarder=forwarder,
    )

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request(body=_controlled_stream_request_body()))

    assert error.value.code == "invalid_upstream"
    assert audit.records()[0].status == "invalid_upstream"


@pytest.mark.parametrize("kind", ["raw", "unicode", "double_unicode", "deep_unicode"])
def test_controlled_sse_scans_whole_decoded_and_nested_content_for_bearer(kind: str) -> None:
    if kind == "raw":
        arguments = json.dumps({"hidden": TOKEN}, separators=(",", ":"))
    elif kind == "unicode":
        arguments = f'{{"hidden":"{_json_unicode_escape(TOKEN)}"}}'
    elif kind == "double_unicode":
        arguments = json.dumps({"nested": _json_unicode_escape(TOKEN)}, separators=(",", ":"))
    else:
        encoded = _json_unicode_escape(TOKEN)
        for _ in range(4):
            encoded = encoded.replace("\\", "\\u005c")
        arguments = json.dumps({"nested": encoded}, separators=(",", ":"))
    body = _controlled_stream_body(_controlled_stream_documents(arguments=arguments))
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.result = _controlled_stream_result(body)
    gateway, _forwarder, audit = _gateway(
        clock,
        policy=_model_policy(
            allow_controlled_test_sse=True,
            max_response_bytes=4_096,
            max_total_response_bytes=4_096,
        ),
        forwarder=forwarder,
    )

    with pytest.raises(EngineRelayError) as error:
        gateway.handle(_model_request(body=_controlled_stream_request_body()))

    assert error.value.code == "invalid_upstream"
    assert TOKEN not in str(error.value)
    assert audit.records()[0].status == "secret_leak"


@pytest.mark.parametrize(
    "overrides",
    [
        {"fixture_usage_estimate": False},
        {"fixture_usage_estimate": 1},
        {"live_model_proof": True},
        {"live_model_proof": "false"},
        {"cost_microunits": 1},
    ],
)
def test_controlled_sse_rejects_untrusted_fixture_or_live_proof_claims(
    overrides: dict[str, Any],
) -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    forwarder.result = _controlled_stream_result(**overrides)
    gateway, _forwarder, audit = _gateway(
        clock,
        policy=_model_policy(allow_controlled_test_sse=True),
        forwarder=forwarder,
    )

    with pytest.raises(EngineRelayError):
        gateway.handle(_model_request(body=_controlled_stream_request_body()))

    assert audit.records()[0].status == "invalid_upstream"


def test_controlled_stream_json_refusal_is_known_nonlive_provider_result() -> None:
    clock = FakeClock()
    body = json.dumps(
        {
            "error": {
                "message": "required tool is unavailable",
                "type": "invalid_request_error",
                "code": "missing_required_tool",
            }
        },
        separators=(",", ":"),
    ).encode()
    forwarder = FakeModelForwarder(clock)
    forwarder.result = ProtectedModelResult(
        status=422,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
            "cache-control": "no-store",
        },
        body=body,
        input_tokens=0,
        output_tokens=0,
        cost_microunits=0,
        provider_request_ref=_digest("controlled-provider-refusal"),
        protected_secret_absent=True,
        fixture_usage_estimate=False,
        live_model_proof=False,
    )
    gateway, _forwarder, audit = _gateway(
        clock,
        policy=_model_policy(allow_controlled_test_sse=True),
        forwarder=forwarder,
    )

    response = gateway.handle(_model_request(body=_controlled_stream_request_body()))

    assert response.status == 422
    assert response.receipt.fixture_usage_estimate is False
    assert response.receipt.live_model_proof is False
    assert audit.records()[0].status == "succeeded"
    assert audit.records()[0].result_status == 422


def test_protected_upstream_unknown_is_typed_audited_consumed_and_sanitized() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    outcome_ref = _digest("ambiguous-provider-outcome")
    forwarder.error = ProtectedUpstreamUnknown(outcome_ref)
    gateway, _forwarder, audit = _gateway(
        clock, policy=_model_policy(allow_controlled_test_sse=True), forwarder=forwarder
    )
    request = _model_request(body=_controlled_stream_request_body())

    with pytest.raises(EngineRelayError) as unknown:
        gateway.handle(request)

    assert unknown.value.code == "upstream_unknown"
    assert unknown.value.__cause__ is None
    assert "target" not in str(unknown.value).lower()
    record = audit.records()[0]
    assert record.status == "upstream_unknown"
    assert record.evidence_ref == outcome_ref
    assert record.result_status is None
    with pytest.raises(EngineRelayError) as replay:
        gateway.handle(request)
    assert replay.value.code == "replay_refused"
    assert len(forwarder.calls) == 1


def test_malformed_protected_upstream_unknown_is_sanitized_without_wedging() -> None:
    clock = FakeClock()
    forwarder = FakeModelForwarder(clock)
    malformed = ProtectedUpstreamUnknown.__new__(ProtectedUpstreamUnknown)
    RuntimeError.__init__(malformed, f"ambiguous with {PROTECTED_SECRET}")
    forwarder.error = malformed
    gateway, _forwarder, audit = _gateway(clock, forwarder=forwarder)

    with pytest.raises(EngineRelayError) as unknown:
        gateway.handle(_model_request())

    assert unknown.value.code == "upstream_unknown"
    assert PROTECTED_SECRET not in str(unknown.value)
    assert unknown.value.__cause__ is None
    assert audit.records()[0].status == "upstream_unknown"
    assert audit.records()[0].evidence_ref is None
    forwarder.error = None
    response = gateway.handle(
        _model_request(request_id="gateway-request-00000000000000000000000000000002")
    )
    assert response.status == 200


def test_upstream_unknown_cannot_be_projected_as_target_outcome() -> None:
    clock = FakeClock()
    relay, _forwarder, audit = _target_relay(clock)
    relay.handle(_target_request())

    with pytest.raises(ValueError):
        replace(audit.records()[0], status="upstream_unknown")


def test_controlled_sse_admission_does_not_change_ordinary_json_path() -> None:
    clock = FakeClock()
    gateway, _forwarder, audit = _gateway(
        clock, policy=_model_policy(allow_controlled_test_sse=True)
    )

    response = gateway.handle(_model_request())

    assert response.status == 200
    assert response.receipt.fixture_usage_estimate is False
    assert response.receipt.live_model_proof is False
    assert audit.records()[0].status == "succeeded"
