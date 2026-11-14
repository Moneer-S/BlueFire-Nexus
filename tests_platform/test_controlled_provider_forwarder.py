from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import fields, replace
from datetime import datetime, timezone
from typing import Any

import pytest

from bluefire.controlled_provider_forwarder import (
    ControlledProviderAuditReceipt,
    ControlledProviderBinding,
    ControlledProviderDispatch,
    ControllerOwnedControlledProviderForwarder,
)
from bluefire.engine_relay import (
    EngineRelayError,
    ModelForwardRequest,
    ModelGatewayPolicy,
    ProtectedModelForwarder,
    ProtectedModelResult,
    ProtectedUpstreamUnknown,
    _digest_bytes,
    model_gateway_authorization_ref,
)
from bluefire.util import content_hash

ATTEMPT = "engine-attempt-" + "a" * 32
REQUEST = "gateway-request-" + "b" * 32
SECRET = "durable-provider-material-never-leaves-transport"  # pragma: allowlist secret


def digest(value: str) -> str:
    return content_hash({"label": value})


def stream_documents(*, sequence: int = 1) -> list[dict[str, Any]]:
    base: dict[str, Any] = {
        "id": f"chatcmpl-{ATTEMPT[-12:]}-{sequence:04d}",
        "object": "chat.completion.chunk",
        "created": 1_762_272_001,
        "model": "bluefire-controlled-strix-mechanics-v1",
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
                                "id": f"call_{sequence:04d}_0123456789abcdef",
                                "type": "function",
                                "function": {"name": "view_agent_graph", "arguments": "{}"},
                            }
                        ],
                    },
                    "finish_reason": None,
                }
            ],
        },
        {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
        {
            **base,
            "choices": [],
            "usage": {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19},
        },
    ]


def stream_body(documents: list[dict[str, Any]] | None = None) -> bytes:
    values = stream_documents() if documents is None else documents
    return (
        "".join(f"data: {json.dumps(value, separators=(',', ':'))}\n\n" for value in values)
        + "data: [DONE]\n\n"
    ).encode()


def response_body(result: ProtectedModelResult, body: bytes) -> ProtectedModelResult:
    return replace(result, body=body, headers={**result.headers, "content-length": str(len(body))})


def binding() -> ControlledProviderBinding:
    auth = digest("authorization")
    policy = ModelGatewayPolicy(
        attempt_id=ATTEMPT,
        binding_digest=digest("binding"),
        delegation_digest=digest("delegation"),
        objective_ref=digest("objective"),
        environment_ref=digest("environment"),
        provider_ref=digest("provider"),
        model_id="bluefire-controlled-strix-mechanics-v1",
        data_destination_ref=digest("destination"),
        relay_identity_ref=digest("relay"),
        network_policy_digest=digest("network"),
        gateway_authority=f"bf-model-{ATTEMPT[-12:]}:8081",
        authorization_ref=model_gateway_authorization_ref(ATTEMPT, auth),
        authorization_digest=auth,
        created_at="2026-11-04T12:00:00Z",
        expires_at="2026-11-04T12:30:00Z",
        max_requests=4,
        max_request_bytes=4096,
        max_response_bytes=4096,
        max_total_request_bytes=16384,
        max_total_response_bytes=16384,
        max_input_tokens_per_request=512,
        max_output_tokens_per_request=128,
        max_total_tokens=2560,
        max_cost_microunits_per_request=1,
        max_total_cost_microunits=4,
        request_timeout_ms=1000,
        allow_controlled_test_sse=True,
    )
    return ControlledProviderBinding(
        policy,
        digest("generation"),
        digest("manifest"),
        digest("material"),
        digest("readiness"),
        digest("custody"),
        49152,
    )


def request(authority: ControlledProviderBinding) -> ModelForwardRequest:
    # Forwarder/SSE correlation fixture, not an enrolled Strix wire profile.
    policy = authority.policy
    values = {
        item.name: getattr(policy, item.name)
        for item in fields(ModelForwardRequest)
        if hasattr(policy, item.name)
    }
    values.update(
        request_id=REQUEST,
        max_input_tokens=policy.max_input_tokens_per_request,
        max_output_tokens=policy.max_output_tokens_per_request,
        max_response_bytes=policy.max_response_bytes,
        max_cost_microunits=policy.max_cost_microunits_per_request,
        deadline_ns=1_000_001_000,
        headers=(("content-type", "application/json"),),
        body=json.dumps(
            {
                "model": policy.model_id,
                "stream": True,
                "messages": [{"role": "user", "content": "Run the fixture"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "view_agent_graph",
                            "parameters": {
                                "type": "object",
                                "properties": {},
                                "required": [],
                                "additionalProperties": False,
                            },
                        },
                    }
                ],
                "stream_options": {"include_usage": True},
            }
        ).encode(),
    )
    return ModelForwardRequest(**values)


class Generation:
    def __init__(self, authority: ControlledProviderBinding) -> None:
        self.authority = authority
        self.lock = threading.RLock()
        self.checks = 0
        self.sessions = 0
        self.raise_check = False
        self.check_after: int | None = None
        self.stopped = False

    @contextmanager
    def session(self, expected: ControlledProviderBinding) -> Iterator[Generation]:
        with self.lock:
            self.sessions += 1
            yield self

    def checked_binding(self) -> ControlledProviderBinding:
        self.checks += 1
        if self.raise_check:
            raise RuntimeError(SECRET)
        if self.check_after == self.checks:
            return replace(self.authority, custody_ref=digest("new custody"))
        return self.authority

    def lifecycle(self, operation: str) -> None:
        with self.lock:
            self.stopped = True
            self.authority = replace(self.authority, generation_ref=digest(operation))


class Transport:
    def __init__(self) -> None:
        self.calls: list[ControlledProviderDispatch] = []
        self.error: Exception | None = None
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = False
        self.secret = SECRET
        body = stream_body()
        self.result = ProtectedModelResult(
            status=200,
            headers={
                "content-type": "text/event-stream",
                "cache-control": "no-store",
                "content-length": str(len(body)),
                "x-bluefire-provider": "Test provider",
            },
            body=body,
            input_tokens=12,
            output_tokens=7,
            cost_microunits=0,
            provider_request_ref=digest("row"),
            protected_secret_absent=True,
            fixture_usage_estimate=True,
            live_model_proof=False,
        )

    def post_chat_completions(self, call: ControlledProviderDispatch) -> ProtectedModelResult:
        self.calls.append(call)
        self.entered.set()
        if self.block:
            assert self.release.wait(5)
        if self.error is not None:
            raise self.error
        return self.result


class Audit:
    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.override: dict[str, Any] = {}
        self.count = 1
        self.seen: list[tuple[str, str]] = []

    def correlate(
        self, authority: ControlledProviderBinding, request_id: str
    ) -> tuple[ControlledProviderAuditReceipt, ...]:
        call = self.transport.calls[-1]
        result = self.transport.result
        self.seen.append((authority.binding_ref, request_id))
        row = ControlledProviderAuditReceipt(
            binding_ref=authority.binding_ref,
            request_id=request_id,
            sequence=len(self.transport.calls),
            request_digest=_digest_bytes(call.body),
            request_bytes=len(call.body),
            response_digest=_digest_bytes(result.body),
            response_bytes=len(result.body),
            status=result.status,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            provider_request_ref=result.provider_request_ref,
        )
        return (replace(row, **self.override),) * self.count


class Harness:
    def __init__(self) -> None:
        self.binding = binding()
        self.generation = Generation(self.binding)
        self.transport = Transport()
        self.audit = Audit(self.transport)
        self.time = 1000
        self.wall = datetime(2026, 11, 4, 12, 1, tzinfo=timezone.utc)
        self.forwarder = ControllerOwnedControlledProviderForwarder(
            self.binding,
            self.generation,
            self.transport,
            self.audit,
            monotonic_ns=lambda: self.time,
            clock=lambda: self.wall,
        )
        self.request = request(self.binding)


def test_fixed_transport_exact_authority_and_fixture_only_result() -> None:
    h = Harness()
    capability: ProtectedModelForwarder = h.forwarder
    result = capability.forward(h.request)
    call = h.transport.calls[0]
    assert (call.host, call.port, call.method, call.path) == (
        "127.0.0.1",
        h.binding.port,
        "POST",
        "/v1/chat/completions",
    )
    assert (call.allow_dns, call.allow_proxy, call.allow_redirects) == (False, False, False)
    assert call.deadline_ns == h.request.deadline_ns
    assert call.max_response_bytes == h.request.max_response_bytes
    assert call.binding_ref == h.binding.binding_ref
    assert h.generation.checks == 3
    assert result.fixture_usage_estimate is True
    assert result.live_model_proof is False
    assert result.cost_microunits == 0
    assert result.headers["x-bluefire-provider"] == "Test provider"
    assert SECRET not in repr(call) + repr(result) + repr(h.forwarder) + repr(h.audit.seen)
    assert not any("authorization" in item.name for item in fields(call))


@pytest.mark.parametrize(
    "name",
    [
        "attempt_id",
        "binding_digest",
        "delegation_digest",
        "network_policy_digest",
        "relay_identity_ref",
        "objective_ref",
        "environment_ref",
        "provider_ref",
        "model_id",
        "data_destination_ref",
        "authorization_ref",
        "max_input_tokens",
        "max_output_tokens",
        "max_response_bytes",
        "max_cost_microunits",
    ],
)
def test_every_request_authority_and_cap_is_exact(name: str) -> None:
    h = Harness()
    original = getattr(h.request, name)
    changed: Any = original + 1 if isinstance(original, int) else "changed"
    with pytest.raises(EngineRelayError, match="changed"):
        h.forwarder.forward(replace(h.request, **{name: changed}))
    assert h.transport.calls == []


@pytest.mark.parametrize(
    "name",
    [
        "generation_ref",
        "manifest_ref",
        "material_ref",
        "readiness_ref",
        "custody_ref",
        "port",
        "policy",
    ],
)
def test_generation_drift_before_dispatch_is_refused(name: str) -> None:
    h = Harness()
    changed: Any = digest("drift")
    if name == "port":
        changed = 49153
    if name == "policy":
        changed = replace(h.binding.policy, objective_ref=digest("new objective"))
    h.generation.authority = replace(h.binding, **{name: changed})
    with pytest.raises(EngineRelayError):
        h.forwarder.forward(h.request)
    assert h.transport.calls == []


@pytest.mark.parametrize("check", [2, 3])
def test_fresh_post_dispatch_custody_checks_fail_closed(check: int) -> None:
    h = Harness()
    h.generation.check_after = check
    with pytest.raises(ProtectedUpstreamUnknown):
        h.forwarder.forward(h.request)
    assert len(h.transport.calls) == 1


@pytest.mark.parametrize(
    "headers",
    [
        (("authorization", "Bearer " + SECRET),),
        (("host", "external.example"),),
        (("proxy-authorization", SECRET),),
        (("forwarded", "host=external.example"),),
    ],
)
def test_caller_routing_or_authorization_headers_never_reach_transport(
    headers: tuple[tuple[str, str], ...],
) -> None:
    h = Harness()
    with pytest.raises(EngineRelayError) as error:
        h.forwarder.forward(replace(h.request, headers=headers))
    assert SECRET not in str(error.value)
    assert h.transport.calls == []


@pytest.mark.parametrize("after_dispatch", [False, True])
def test_exception_text_and_durable_material_never_escape(after_dispatch: bool) -> None:
    h = Harness()
    h.generation.raise_check = not after_dispatch
    h.transport.error = RuntimeError(SECRET) if after_dispatch else None
    with pytest.raises((EngineRelayError, ProtectedUpstreamUnknown)) as error:
        h.forwarder.forward(h.request)
    assert SECRET not in str(error.value) + repr(error.value) + repr(h.forwarder)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_ambiguous_dispatch_permanently_consumes_attempt_without_retry() -> None:
    h = Harness()
    h.transport.error = TimeoutError(SECRET)
    with pytest.raises(ProtectedUpstreamUnknown) as error:
        h.forwarder.forward(h.request)
    assert error.value.outcome_ref.startswith("sha256:")
    h.transport.error = None
    for request_id in (REQUEST, "gateway-request-" + "c" * 32):
        with pytest.raises(EngineRelayError) as refused:
            h.forwarder.forward(replace(h.request, request_id=request_id))
        assert refused.value.code == "upstream_unknown"
    assert len(h.transport.calls) == 1


@pytest.mark.parametrize(
    "malformed",
    [
        b"data: fixture\n\n",
        b"data: \xff\n\n",
        b"data: [DONE]\n\n",
        stream_body().removesuffix(b"data: [DONE]\n\n"),
        stream_body() + b"data: [DONE]\n\n",
    ],
)
def test_malformed_controlled_stream_latches_unknown_before_any_later_dispatch(
    malformed: bytes,
) -> None:
    h = Harness()
    h.transport.result = response_body(h.transport.result, malformed)
    with pytest.raises(ProtectedUpstreamUnknown) as error:
        h.forwarder.forward(h.request)
    assert error.value.__context__ is None
    # Restore a valid response: a new request ID must still never dispatch.
    h.transport.result = response_body(h.transport.result, stream_body())
    with pytest.raises(EngineRelayError) as refused:
        h.forwarder.forward(replace(h.request, request_id="gateway-request-" + "c" * 32))
    assert refused.value.code == "upstream_unknown"
    assert len(h.transport.calls) == 1
    assert not h.audit.seen


@pytest.mark.parametrize(
    "drift",
    [
        "attempt",
        "model",
        "fingerprint",
        "tool_roster",
        "prompt_usage",
        "output_usage",
        "usage_sum",
        "frame_identity",
        "audit_sequence",
        "material_reference",
    ],
)
def test_controlled_stream_semantic_drift_latches_unknown(drift: str) -> None:
    h = Harness()
    documents = stream_documents()
    if drift in {"attempt", "model", "fingerprint"}:
        key, changed = {
            "attempt": ("id", "chatcmpl-cccccccccccc-0001"),
            "model": ("model", "wrong-model"),
            "fingerprint": ("system_fingerprint", "live-model"),
        }[drift]
        for document in documents:
            document[key] = changed
    elif drift in {"tool_roster", "material_reference"}:
        function = documents[0]["choices"][0]["delta"]["tool_calls"][0]["function"]
        if drift == "tool_roster":
            function["name"] = "not_admitted"
        else:
            function["arguments"] = json.dumps(
                {"material_ref": h.binding.material_ref}, sort_keys=True, separators=(",", ":")
            )
    elif drift in {"prompt_usage", "output_usage", "usage_sum"}:
        usage = documents[2]["usage"]
        if drift == "prompt_usage":
            usage.update(prompt_tokens=13, total_tokens=20)
        elif drift == "output_usage":
            usage.update(completion_tokens=8, total_tokens=20)
        else:
            usage["total_tokens"] = 20
    elif drift == "frame_identity":
        documents[1]["created"] += 1
    elif drift == "audit_sequence":
        documents = stream_documents(sequence=2)
    h.transport.result = response_body(h.transport.result, stream_body(documents))
    with pytest.raises(ProtectedUpstreamUnknown):
        h.forwarder.forward(h.request)
    h.transport.result = response_body(h.transport.result, stream_body())
    with pytest.raises(EngineRelayError) as refused:
        h.forwarder.forward(replace(h.request, request_id="gateway-request-" + "c" * 32))
    assert refused.value.code == "upstream_unknown"
    assert len(h.transport.calls) == 1


@pytest.mark.parametrize(
    "changed",
    [
        {"status": 302},
        {"body": b"x" * 4097},
        {"input_tokens": 513},
        {"output_tokens": 129},
        {"cost_microunits": 1},
        {"cost_microunits": False},
        {"protected_secret_absent": False},
        {"fixture_usage_estimate": False},
        {"live_model_proof": True},
        {"provider_request_ref": SECRET},
        {"headers": {"location": "http://external.example"}},
    ],
)
def test_protected_result_caps_proof_scan_and_redirects_are_enforced(
    changed: dict[str, Any],
) -> None:
    h = Harness()
    h.transport.result = replace(h.transport.result, **changed)
    with pytest.raises(ProtectedUpstreamUnknown):
        h.forwarder.forward(h.request)


@pytest.mark.parametrize(
    "changed",
    [
        {"binding_ref": digest("wrong")},
        {"request_id": "gateway-request-" + "c" * 32},
        {"request_digest": digest("wrong")},
        {"request_bytes": 1},
        {"response_digest": digest("wrong")},
        {"response_bytes": 1},
        {"status": 201},
        {"input_tokens": 13},
        {"output_tokens": 8},
        {"provider_request_ref": digest("wrong")},
        {"provider_label": "Live provider"},
        {"provider_id": "other"},
        {"fixture_usage_estimate": False},
        {"live_model_proof": True},
        {"cost_microunits": 1},
        {"sequence": True},
    ],
)
def test_provider_audit_requires_exact_correlation(changed: dict[str, Any]) -> None:
    h = Harness()
    h.audit.override = changed
    with pytest.raises(ProtectedUpstreamUnknown):
        h.forwarder.forward(h.request)


@pytest.mark.parametrize("count", [0, 2])
def test_missing_or_duplicate_provider_audit_is_unknown(count: int) -> None:
    h = Harness()
    h.audit.count = count
    with pytest.raises(ProtectedUpstreamUnknown):
        h.forwarder.forward(h.request)


def test_replayed_audit_sequence_cannot_authorize_second_response() -> None:
    h = Harness()
    h.forwarder.forward(h.request)
    h.audit.override = {"sequence": 1}
    with pytest.raises(ProtectedUpstreamUnknown):
        h.forwarder.forward(replace(h.request, request_id="gateway-request-" + "c" * 32))


def test_deadline_and_authorization_window_prevent_dispatch() -> None:
    h = Harness()
    h.time = h.request.deadline_ns
    with pytest.raises(EngineRelayError):
        h.forwarder.forward(h.request)
    h.time = 1000
    h.wall = datetime(2026, 11, 4, 13, tzinfo=timezone.utc)
    with pytest.raises(EngineRelayError) as error:
        h.forwarder.forward(h.request)
    assert error.value.code == "expired"
    assert h.transport.calls == []


def test_revocation_scope_then_idempotent_drain_without_stopping_lab() -> None:
    h = Harness()
    with pytest.raises(EngineRelayError):
        h.forwarder.revoke(ATTEMPT, digest("wrong"))
    result = h.forwarder.revoke(ATTEMPT, h.binding.policy.authorization_ref)
    assert result.verified is True
    assert result is h.forwarder.revoke(ATTEMPT, h.binding.policy.authorization_ref)
    with pytest.raises(EngineRelayError) as error:
        h.forwarder.forward(h.request)
    assert error.value.code == "revoked"
    assert h.generation.stopped is False


@pytest.mark.parametrize("lifecycle", ["restart", "cleanup"])
def test_active_forward_serializes_restart_cleanup_and_revocation(lifecycle: str) -> None:
    h = Harness()
    h.transport.block = True
    results: list[object] = []
    errors: list[Exception] = []
    revoked = threading.Event()
    changed = threading.Event()

    def forward() -> None:
        try:
            results.append(h.forwarder.forward(h.request))
        except Exception as error:
            errors.append(error)

    def revoke() -> None:
        results.append(h.forwarder.revoke(ATTEMPT, h.binding.policy.authorization_ref))
        revoked.set()

    def transition() -> None:
        h.generation.lifecycle(lifecycle)
        changed.set()

    worker = threading.Thread(target=forward)
    revoker = threading.Thread(target=revoke)
    transitioner = threading.Thread(target=transition)
    worker.start()
    assert h.transport.entered.wait(2)
    transitioner.start()
    revoker.start()
    # The condition shares the flag being asserted, making the observation
    # independent of thread scheduling and avoiding sleeps.
    with h.forwarder._condition:
        assert h.forwarder._condition.wait_for(lambda: h.forwarder._revoked, timeout=2)
    assert not changed.is_set()
    assert not revoked.is_set()
    h.transport.release.set()
    for thread in (worker, revoker, transitioner):
        thread.join(3)
        assert not thread.is_alive()
    assert changed.is_set() and revoked.is_set()
    assert len(errors) == 1 and isinstance(errors[0], ProtectedUpstreamUnknown)
    assert len(h.transport.calls) == 1


def test_response_deadline_is_rechecked_after_dispatch() -> None:
    h = Harness()
    h.transport.block = True
    errors: list[Exception] = []

    def forward() -> None:
        try:
            h.forwarder.forward(h.request)
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=forward)
    worker.start()
    assert h.transport.entered.wait(2)
    h.time = h.request.deadline_ns
    h.transport.release.set()
    worker.join(3)
    assert not worker.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], ProtectedUpstreamUnknown)


@pytest.mark.parametrize("field", ["base_url", "host", "authorization", "api_key"])
def test_caller_destination_and_material_fields_are_refused(field: str) -> None:
    h = Harness()
    document = json.loads(h.request.body)
    document[field] = SECRET
    with pytest.raises(EngineRelayError):
        h.forwarder.forward(replace(h.request, body=json.dumps(document).encode()))
    assert not h.transport.calls


def test_success_cannot_be_replayed_and_attempt_budget_is_reserved() -> None:
    h = Harness()
    h.forwarder.forward(h.request)
    with pytest.raises(EngineRelayError) as error:
        h.forwarder.forward(h.request)
    assert error.value.code == "replay_refused"
    for sequence, suffix in enumerate("cde", start=2):
        h.transport.result = response_body(
            h.transport.result, stream_body(stream_documents(sequence=sequence))
        )
        h.forwarder.forward(replace(h.request, request_id="gateway-request-" + suffix * 32))
    with pytest.raises(EngineRelayError) as error:
        h.forwarder.forward(replace(h.request, request_id="gateway-request-" + "f" * 32))
    assert error.value.code == "budget_exhausted"
    assert len(h.transport.calls) == 4


@pytest.mark.parametrize("clock_failure", ["non_utc", "bad_monotonic"])
def test_clock_validation_is_fail_closed(clock_failure: str) -> None:
    h = Harness()
    if clock_failure == "non_utc":
        h.wall = h.wall.replace(tzinfo=None)
    else:
        h.time = -1
    with pytest.raises(EngineRelayError) as error:
        h.forwarder.forward(h.request)
    assert error.value.code == "clock_invalid"
    assert not h.transport.calls


def test_bare_provider_material_never_enters_authority_binding() -> None:
    with pytest.raises(ValueError, match="binding"):
        replace(binding(), material_ref=SECRET)
