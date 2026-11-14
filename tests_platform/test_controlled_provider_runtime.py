from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

import pytest

import bluefire.strix_tool_conformance as conformance
from bluefire.controlled_provider_forwarder import ControlledProviderDispatch
from bluefire.controlled_provider_preflight import PREFLIGHT_MESSAGES
from bluefire.controlled_provider_runtime import (
    ControllerOwnedTestProviderRuntime,
    NumericLoopbackControlledProviderTransport,
    ProtectedControlledProviderAudit,
)
from bluefire.controlled_strix_provider import (
    TARGET_MANIFEST_SCHEMA,
    ControlledProviderManifest,
)
from bluefire.engine_relay import (
    EngineRelayError,
    ModelGatewayPolicy,
    ModelGatewayRequest,
    _digest_bytes,
    model_gateway_authorization_ref,
)
from bluefire.strix_tool_conformance import (
    TARGET_MECHANICS_FINISH_ARGUMENTS,
    OfflineRootToolProfile,
    canonical_json,
    digest_json,
)
from tests_platform.strix_provider_profile_fixture import (
    ATTEMPT_ID,
    synthetic_manifest,
    synthetic_profile,
    synthetic_tools,
)
from tests_platform.test_controlled_provider_forwarder import binding, digest

GATEWAY_BEARER = "ephemeral-gateway-only-" + "x" * 40  # pragma: allowlist secret
NOW = datetime(2026, 11, 4, 12, 1, tzinfo=timezone.utc)


def policy(*, tools: bool = False, requests: int = 3) -> ModelGatewayPolicy:
    result = replace(
        binding().policy,
        max_requests=requests,
        authorization_digest=_digest_bytes(GATEWAY_BEARER.encode()),
        authorization_ref=model_gateway_authorization_ref(
            ATTEMPT_ID, _digest_bytes(GATEWAY_BEARER.encode())
        ),
    )
    if tools:
        result = replace(
            result,
            max_request_bytes=131_072,
            max_response_bytes=65_536,
            max_total_request_bytes=3 * 131_072,
            max_total_response_bytes=3 * 65_536,
            max_input_tokens_per_request=32_768,
            max_output_tokens_per_request=8_192,
            max_total_tokens=3 * 40_960,
        )
    return result


def preflight() -> bytes:
    return canonical_json(
        {"model": conformance.MODEL_ID, "messages": list(PREFLIGHT_MESSAGES), "stream": False}
    )


def gateway_request(
    runtime: ControllerOwnedTestProviderRuntime, body: bytes, number: int = 1
) -> ModelGatewayRequest:
    authority = runtime.binding.policy
    return ModelGatewayRequest(
        request_id="gateway-request-" + f"{number:032x}",
        attempt_id=ATTEMPT_ID,
        objective_ref=authority.objective_ref,
        provider_ref=authority.provider_ref,
        authority=authority.gateway_authority,
        authorization=f"Bearer {GATEWAY_BEARER}",
        headers=(("content-type", "application/json"),),
        body=body,
    )


def http_request(
    runtime: ControllerOwnedTestProviderRuntime,
    body: bytes,
    *,
    authorization: str = GATEWAY_BEARER,
    host: str | None = None,
    retry_count: str | None = "0",
    duplicate_retry_count: str | None = None,
    sdk_headers: bool = False,
) -> tuple[int, bytes]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
        channel.settimeout(3)
        channel.connect(("127.0.0.1", runtime.gateway_port))
        authority = host or runtime.binding.policy.gateway_authority
        headers = [
            "POST /v1/chat/completions HTTP/1.1",
            f"Host: {authority}",
            f"Authorization: Bearer {authorization}",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
        ]
        if retry_count is not None:
            headers.append(f"X-Stainless-Retry-Count: {retry_count}")
        if duplicate_retry_count is not None:
            headers.append(f"X-Stainless-Retry-Count: {duplicate_retry_count}")
        if sdk_headers:
            # Header shape only. Exact installed SDK values remain a separate
            # capture-and-enrollment prerequisite documented for this runtime.
            headers += [
                "Accept: application/json",
                "Accept-Encoding: gzip, deflate",
                "User-Agent: OpenAI/Python controlled-test",
                "X-Stainless-Lang: python",
                "X-Stainless-Package-Version: controlled-test",
                "X-Stainless-OS: Windows",
                "X-Stainless-Arch: x64",
                "X-Stainless-Runtime: CPython",
                "X-Stainless-Runtime-Version: controlled-test",
                "X-Stainless-Async: false",
                "X-Stainless-Read-Timeout: 30",
            ]
        channel.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + body)
        response = bytearray()
        while True:
            block = channel.recv(4096)
            if not block:
                break
            response.extend(block)
    headers, payload = bytes(response).split(b"\r\n\r\n", 1)
    return int(headers.split(b" ", 2)[1]), payload


def target_manifest() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    tools = synthetic_tools()
    repeat = next(
        tool["function"] for tool in tools if tool["function"]["name"] == "repeat_request"
    )
    repeat["strict"] = False
    repeat["parameters"] = {
        "type": "object",
        "properties": {
            "request_id": {"type": "string"},
            "modifications": {
                "anyOf": [{"additionalProperties": True, "type": "object"}, {"type": "null"}],
                "default": None,
            },
        },
        "required": ["request_id"],
        "additionalProperties": False,
    }
    result = synthetic_manifest()
    result["schema_version"] = TARGET_MANIFEST_SCHEMA
    result["profile"] = synthetic_profile(tools)
    result["target_inspection_seed"] = {
        "attempt_id": ATTEMPT_ID,
        "caido_request_id": "12345",
        "seed_receipt_ref": digest("verified-seed"),
    }
    result["phases"][0] = {
        "phase_id": "inspect_target",
        "tool_name": "repeat_request",
        "tool_schema_digest": digest_json(repeat["parameters"]),
        "parameters_schema": repeat["parameters"],
        "arguments": {"request_id": "12345", "modifications": None},
    }
    result["phases"][1]["arguments"] = dict(TARGET_MECHANICS_FINISH_ARGUMENTS)
    return result, tools


def tool_body(tools: list[dict[str, Any]], messages: list[dict[str, Any]]) -> bytes:
    return canonical_json(
        {
            "model": conformance.MODEL_ID,
            "messages": messages,
            "tools": tools,
            "stream": True,
            "parallel_tool_calls": False,
            "stream_options": {"include_usage": True},
            "tool_choice": "auto",
        }
    )


def call_from_sse(body: bytes) -> dict[str, Any]:
    return json.loads(body.decode().splitlines()[0][6:])["choices"][0]["delta"]["tool_calls"][0]


def test_real_listener_preflight_has_zero_cost_hash_only_audit_and_no_dns_or_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://untrusted.invalid:1")
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-live-key-must-never-be-used")
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *_args, **_kwargs: pytest.fail("DNS was used")
    )
    monkeypatch.setattr(
        socket, "getfqdn", lambda *_args, **_kwargs: pytest.fail("reverse DNS was used")
    )
    with ControllerOwnedTestProviderRuntime(policy(), GATEWAY_BEARER, clock=lambda: NOW) as runtime:
        status, body = http_request(runtime, preflight())
        assert status == 200
        assert json.loads(body)["choices"][0]["message"]["content"] == "OK"
        rows = runtime.relay_audit.records()
        assert len(rows) == 1
        assert rows[0].fixture_usage_estimate is True
        assert rows[0].live_model_proof is False
        assert rows[0].cost_microunits == 0
        assert "helpful assistant" not in repr(rows)
        assert GATEWAY_BEARER not in body.decode() + repr(runtime) + repr(runtime.transport)
        assert "ambient-live-key" not in body.decode()
        assert runtime.checked_binding() == runtime.binding


def test_worker_authority_cannot_access_fixture_or_override_protected_ids() -> None:
    with ControllerOwnedTestProviderRuntime(policy(), GATEWAY_BEARER, clock=lambda: NOW) as runtime:
        assert http_request(runtime, preflight(), authorization="incorrect")[0] == 400
        assert http_request(runtime, preflight(), host="127.0.0.1")[0] == 400
        assert runtime.relay_audit.records() == ()
        assert http_request(runtime, preflight())[0] == 200


@pytest.mark.parametrize(
    ("retry_count", "duplicate_retry_count"),
    [(None, None), ("1", None), ("9", None), ("00", None), ("-1", None), ("0", "0")],
    ids=["missing", "one", "nine", "noncanonical", "negative", "duplicate"],
)
def test_worker_listener_refuses_any_request_not_proven_as_initial_sdk_attempt(
    retry_count: str | None, duplicate_retry_count: str | None
) -> None:
    with ControllerOwnedTestProviderRuntime(policy(), GATEWAY_BEARER, clock=lambda: NOW) as runtime:
        status, _body = http_request(
            runtime,
            preflight(),
            retry_count=retry_count,
            duplicate_retry_count=duplicate_retry_count,
            sdk_headers=True,
        )
        assert status == 400
        assert runtime.relay_audit.records() == ()
        assert http_request(runtime, preflight(), sdk_headers=True)[0] == 200


def test_unknown_preflight_and_repeated_preflight_never_produce_an_inference_response() -> None:
    with ControllerOwnedTestProviderRuntime(policy(), GATEWAY_BEARER, clock=lambda: NOW) as runtime:
        modified = json.loads(preflight())
        modified["messages"][1]["content"] = "Assess this target"
        with pytest.raises(EngineRelayError):
            runtime.gateway.handle(gateway_request(runtime, canonical_json(modified)))
        assert runtime.audit.correlate(runtime.binding, "gateway-request-" + f"{1:032x}") == ()


def test_revocation_closes_new_authority_and_close_releases_both_listeners() -> None:
    runtime = ControllerOwnedTestProviderRuntime(policy(), GATEWAY_BEARER, clock=lambda: NOW)
    ports = (runtime.gateway_port, runtime.binding.port)
    assert runtime.gateway.revoke().protected_revocation_verified
    with pytest.raises(EngineRelayError) as refused:
        runtime.gateway.handle(gateway_request(runtime, preflight()))
    assert refused.value.code == "revoked"
    runtime.close()
    runtime.close()
    with pytest.raises(ValueError):
        runtime.checked_binding()
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
            channel.settimeout(0.2)
            assert channel.connect_ex(("127.0.0.1", port)) != 0


def test_tool_turns_require_exact_reviewed_enrollment_and_target_seed() -> None:
    manifest, tools = target_manifest()
    with ControllerOwnedTestProviderRuntime(
        policy(tools=True),
        GATEWAY_BEARER,
        manifest=ControlledProviderManifest.from_mapping(manifest),
        target_seed_verifier=lambda _seed: True,
        clock=lambda: NOW,
    ) as runtime:
        runtime.gateway.handle(gateway_request(runtime, preflight()))
        with pytest.raises(EngineRelayError):
            runtime.gateway.handle(
                gateway_request(
                    runtime, tool_body(tools, [{"role": "user", "content": "mechanics"}]), 2
                )
            )
        assert conformance.APPROVED_PROFILE_DIGESTS == frozenset()


def test_full_round_trip_replays_preseeded_target_then_finishes_and_rejects_schema_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, tools = target_manifest()
    candidate = OfflineRootToolProfile.from_mapping(manifest["profile"])
    # Synthetic descriptors exercise mechanics only; this is never product enrollment.
    monkeypatch.setattr(
        conformance, "APPROVED_PROFILE_DIGESTS", frozenset({candidate.profile_digest})
    )
    seed_checks: list[str] = []

    def verify(seed: Any) -> bool:
        seed_checks.append(seed.caido_request_id)
        return seed.attempt_id == ATTEMPT_ID and seed.caido_request_id == "12345"

    with ControllerOwnedTestProviderRuntime(
        policy(tools=True),
        GATEWAY_BEARER,
        manifest=ControlledProviderManifest.from_mapping(manifest),
        target_seed_verifier=verify,
        clock=lambda: NOW,
    ) as runtime:
        assert http_request(runtime, preflight())[0] == 200
        messages = [{"role": "user", "content": "mechanics"}]
        status, body = http_request(runtime, tool_body(tools, messages))
        assert status == 200
        call = call_from_sse(body)
        assert call["function"]["name"] == "repeat_request"
        assert json.loads(call["function"]["arguments"]) == {
            "request_id": "12345",
            "modifications": None,
        }
        del call["index"]
        messages += [
            {"role": "assistant", "tool_calls": [call]},
            {
                "role": "tool",
                "tool_call_id": call["id"],
                "content": "A paired result, not independently verified target success",
            },
        ]
        status, body = http_request(runtime, tool_body(tools, messages))
        assert status == 200
        finish = call_from_sse(body)
        assert finish["function"]["name"] == "finish_scan"
        assert json.loads(finish["function"]["arguments"]) == dict(
            TARGET_MECHANICS_FINISH_ARGUMENTS
        )
        assert len(runtime.relay_audit.records()) == 3
        assert len(seed_checks) >= 6
        with pytest.raises(EngineRelayError) as budget:
            runtime.gateway.handle(gateway_request(runtime, preflight(), 9))
        assert budget.value.code == "budget_exhausted"
    tools[0]["function"]["description"] += " drift"
    with pytest.raises(ValueError, match="schema differs"):
        candidate.check_request_roster(tools)


def test_late_response_is_consumed_and_revocation_drains(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = [time.monotonic_ns()]
    entered = threading.Event()
    release = threading.Event()
    with ControllerOwnedTestProviderRuntime(
        policy(), GATEWAY_BEARER, clock=lambda: NOW, monotonic_ns=lambda: ticks[0]
    ) as runtime:
        real = runtime.transport.post_chat_completions

        def delayed(request: Any) -> Any:
            response = real(request)
            entered.set()
            assert release.wait(3)
            ticks[0] += 2_000_000_000
            return response

        monkeypatch.setattr(runtime.transport, "post_chat_completions", delayed)
        failures: list[Exception] = []

        def forward() -> None:
            try:
                runtime.gateway.handle(gateway_request(runtime, preflight()))
            except Exception as error:
                failures.append(error)

        worker = threading.Thread(target=forward)
        worker.start()
        assert entered.wait(3)
        revoked: list[Any] = []
        revoker = threading.Thread(target=lambda: revoked.append(runtime.gateway.revoke()))
        revoker.start()
        assert not revoked
        release.set()
        worker.join(3)
        revoker.join(3)
        assert len(failures) == 1 and isinstance(failures[0], EngineRelayError)
        assert revoked[0].protected_revocation_verified
        assert all(row.status != "succeeded" for row in runtime.relay_audit.records())


def test_repeated_preflight_is_consumed_without_a_second_success() -> None:
    with ControllerOwnedTestProviderRuntime(policy(), GATEWAY_BEARER, clock=lambda: NOW) as runtime:
        runtime.gateway.handle(gateway_request(runtime, preflight()))
        with pytest.raises(EngineRelayError) as refusal:
            runtime.gateway.handle(gateway_request(runtime, preflight(), 2))
        assert refusal.value.code == "upstream_unknown"
        rows = runtime.relay_audit.records()
        assert [row.status for row in rows] == ["succeeded", "upstream_unknown"]


@pytest.mark.parametrize("where", ["header", "json", "escaped-json"])
def test_protected_transport_scans_encoded_material_before_audit(
    where: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "protected-fixture-only-" + "z" * 32
    encoded = "".join(f"\\u{ord(char):04x}" for char in secret)
    body = b"{}"
    header = "application/json"
    if where == "header":
        header = encoded
    elif where == "json":
        body = canonical_json({"content": secret})
    else:
        body = canonical_json({"content": encoded})
    response = (
        f"HTTP/1.1 200 OK\r\nContent-Type: {header}\r\nContent-Length: {len(body)}\r\nCache-Control: no-store\r\n\r\n"
    ).encode() + body
    connections: list[Any] = []

    class Channel:
        def __init__(self, *_args: Any) -> None:
            self.remaining = response
            connections.append(self)

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_args: Any) -> None:
            pass

        def settimeout(self, _value: float) -> None:
            pass

        def connect(self, destination: Any) -> None:
            assert destination == ("127.0.0.1", authority.port)

        def sendall(self, payload: bytes) -> None:
            assert f"Authorization: Bearer {secret}".encode() in payload
            assert GATEWAY_BEARER.encode() not in payload

        def recv(self, count: int) -> bytes:
            result, self.remaining = self.remaining[:count], self.remaining[count:]
            return result

    authority = replace(binding(), material_ref=_digest_bytes(secret.encode()))
    audit = ProtectedControlledProviderAudit(max_records=3)
    monkeypatch.setattr(
        audit, "correlate", lambda *_args: pytest.fail("material must be scanned before audit")
    )
    monkeypatch.setattr(socket, "socket", Channel)
    transport = NumericLoopbackControlledProviderTransport(
        authority, secret, audit, monotonic_ns=lambda: 1
    )
    dispatch = ControlledProviderDispatch(
        binding_ref=authority.binding_ref,
        request_id="gateway-request-" + "e" * 32,
        port=authority.port,
        deadline_ns=1_000_000_001,
        max_response_bytes=authority.policy.max_response_bytes,
        body=preflight(),
    )
    with pytest.raises(ValueError) as failure:
        transport.post_chat_completions(dispatch)
    assert failure.value.__context__ is None
    assert secret not in str(failure.value) + repr(transport)
    assert len(connections) == 1


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 302 Found\r\nLocation: http://untrusted.invalid/\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    ],
    ids=["redirect", "duplicate-length", "over-budget", "chunked"],
)
def test_transport_refuses_redirects_framing_and_budgets_without_retry(
    response: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "private-test-only-" + "j" * 32
    calls: list[Any] = []

    class Channel:
        def __init__(self, *_args: Any) -> None:
            self.data = response
            calls.append(self)

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_args: Any) -> None:
            pass

        def settimeout(self, _value: float) -> None:
            pass

        def connect(self, destination: Any) -> None:
            assert destination[0] == "127.0.0.1"

        def sendall(self, _payload: bytes) -> None:
            pass

        def recv(self, count: int) -> bytes:
            result, self.data = self.data[:count], self.data[count:]
            return result

    authority = replace(binding(), material_ref=_digest_bytes(secret.encode()))
    monkeypatch.setattr(socket, "socket", Channel)
    transport = NumericLoopbackControlledProviderTransport(
        authority, secret, ProtectedControlledProviderAudit(max_records=3), monotonic_ns=lambda: 1
    )
    with pytest.raises(ValueError):
        transport.post_chat_completions(
            ControlledProviderDispatch(
                binding_ref=authority.binding_ref,
                request_id="gateway-request-" + "f" * 32,
                port=authority.port,
                deadline_ns=1_000_000_001,
                max_response_bytes=authority.policy.max_response_bytes,
                body=preflight(),
            )
        )
    assert len(calls) == 1


def test_v3_rejects_unbound_target_or_changed_request_arguments() -> None:
    manifest, _tools = target_manifest()
    manifest["target_inspection_seed"]["attempt_id"] = "engine-attempt-" + "b" * 32
    with pytest.raises(ValueError, match="seed attempt"):
        ControlledProviderManifest.from_mapping(manifest)
    manifest, _tools = target_manifest()
    manifest["phases"][0]["arguments"]["modifications"] = {"url": "https://untrusted.invalid"}
    with pytest.raises(ValueError, match="arguments changed"):
        ControlledProviderManifest.from_mapping(manifest)


def test_v3_seed_revocation_refuses_next_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, _tools = target_manifest()
    enrolled = OfflineRootToolProfile.from_mapping(manifest["profile"])
    monkeypatch.setattr(
        conformance, "APPROVED_PROFILE_DIGESTS", frozenset({enrolled.profile_digest})
    )
    current = [True]
    with ControllerOwnedTestProviderRuntime(
        policy(tools=True),
        GATEWAY_BEARER,
        manifest=ControlledProviderManifest.from_mapping(manifest),
        target_seed_verifier=lambda _seed: current[0],
        clock=lambda: NOW,
    ) as runtime:
        current[0] = False
        with pytest.raises(EngineRelayError) as refusal:
            runtime.gateway.handle(gateway_request(runtime, preflight()))
        assert refusal.value.code == "upstream_failed"
        assert runtime.audit.correlate(runtime.binding, "gateway-request-" + f"{1:032x}") == ()
