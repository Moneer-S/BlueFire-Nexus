"""Controller-owned, credential-free adapter for the controlled Test provider.

No I/O is implemented here. The installed controller must adapt its generation
source to ``ControlledProviderGenerationSource``: a session holds the same
lifecycle lock as restart/cleanup and freshly verifies readiness and native
custody on each ``checked_binding`` call. The protected transport alone owns
provider material, attaches authorization, scans responses for that material,
and performs a single bounded dispatch without DNS, proxies or redirects.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from .controlled_strix_provider import PROVIDER_ID, PROVIDER_LABEL
from .engine_relay import (
    EngineRelayError,
    ModelForwardRequest,
    ModelGatewayPolicy,
    ProtectedModelForwarder,
    ProtectedModelResult,
    ProtectedRevocationResult,
    ProtectedUpstreamUnknown,
    _controlled_stream_tool_names,
    _digest_bytes,
    _normalized_headers,
    _parse_controlled_sse,
    _require_digest,
    _strict_json,
)
from .util import content_hash, parse_iso8601_datetime


@dataclass(frozen=True, slots=True)
class ControlledProviderBinding:
    """Exact immutable authority; all material references are digests only."""

    policy: ModelGatewayPolicy
    generation_ref: str
    manifest_ref: str
    material_ref: str
    readiness_ref: str
    custody_ref: str
    port: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy, ModelGatewayPolicy)
            or not self.policy.allow_controlled_test_sse
        ):
            raise ValueError("controlled provider requires the controlled streaming policy")
        for value in (
            self.generation_ref,
            self.manifest_ref,
            self.material_ref,
            self.readiness_ref,
            self.custody_ref,
        ):
            _require_digest(value, "controlled provider binding")
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise ValueError("controlled provider port is invalid")

    @property
    def binding_ref(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.controlled-provider-binding.v1",
                "policy_digest": self.policy.policy_digest,
                "generation_ref": self.generation_ref,
                "manifest_ref": self.manifest_ref,
                "material_ref": self.material_ref,
                "readiness_ref": self.readiness_ref,
                "custody_ref": self.custody_ref,
                "host": "127.0.0.1",
                "port": self.port,
                "provider_id": PROVIDER_ID,
                "provider_label": PROVIDER_LABEL,
            }
        )


class ControlledProviderGenerationSession(Protocol):
    def checked_binding(self) -> ControlledProviderBinding:
        """Fresh exact readiness/custody check while retaining lifecycle lock."""
        ...


class ControlledProviderGenerationSource(Protocol):
    def session(
        self, expected: ControlledProviderBinding
    ) -> AbstractContextManager[ControlledProviderGenerationSession]:
        """Serialize forwarding against generation restart and cleanup."""
        ...


@dataclass(frozen=True, slots=True)
class ControlledProviderDispatch:
    """Fixed numeric destination; this DTO cannot contain provider authority."""

    binding_ref: str
    request_id: str
    port: int
    deadline_ns: int
    max_response_bytes: int
    body: bytes = field(repr=False)
    host: str = field(default="127.0.0.1", init=False)
    method: str = field(default="POST", init=False)
    path: str = field(default="/v1/chat/completions", init=False)
    content_type: str = field(default="application/json", init=False)
    allow_dns: bool = field(default=False, init=False)
    allow_proxy: bool = field(default=False, init=False)
    allow_redirects: bool = field(default=False, init=False)


class ControlledProviderTransport(Protocol):
    def post_chat_completions(self, request: ControlledProviderDispatch) -> ProtectedModelResult:
        """One dispatch, attaching protected material internally and scanning it.

        Enforce the deadline and read cap during transport, including streaming.
        Never retry. Any exception is treated as ambiguous provider acceptance.
        ``protected_secret_absent`` attests scans of body and all headers,
        including decoded/escaped JSON and SSE string values.
        """
        ...


@dataclass(frozen=True, slots=True)
class ControlledProviderAuditReceipt:
    """Protected audit adapter's bounded, exact request/response correlation.

    Adapter must validate the source audit schema and row, scope its sequence
    to the exact generation/manifest, and associate request_id with the single
    dispatch. Raw rows and credentials never enter the relay.
    """

    binding_ref: str
    request_id: str
    sequence: int
    request_digest: str
    request_bytes: int
    response_digest: str
    response_bytes: int
    status: int
    input_tokens: int
    output_tokens: int
    provider_request_ref: str
    provider_id: str = PROVIDER_ID
    provider_label: str = PROVIDER_LABEL
    fixture_usage_estimate: bool = True
    live_model_proof: bool = False
    cost_microunits: int = 0

    def __post_init__(self) -> None:
        for value in (
            self.binding_ref,
            self.request_digest,
            self.response_digest,
            self.provider_request_ref,
        ):
            _require_digest(value, "controlled provider audit")
        if (
            not isinstance(self.request_id, str)
            or re.fullmatch(r"gateway-request-[0-9a-f]{32}", self.request_id) is None
            or self.provider_id != PROVIDER_ID
            or self.provider_label != PROVIDER_LABEL
            or self.fixture_usage_estimate is not True
            or self.live_model_proof is not False
            or type(self.cost_microunits) is not int
            or self.cost_microunits != 0
        ):
            raise ValueError("controlled provider audit identity is invalid")
        for count, maximum in (
            (self.sequence, 32),
            (self.request_bytes, 1_048_576),
            (self.response_bytes, 1_048_576),
            (self.status, 200),
            (self.input_tokens, 131_072),
            (self.output_tokens, 131_072),
        ):
            if type(count) is not int or not 0 <= count <= maximum:
                raise ValueError("controlled provider audit bound is invalid")
        if self.sequence == 0 or self.status != 200:
            raise ValueError("controlled provider audit status is invalid")


class ControlledProviderAudit(Protocol):
    def correlate(
        self, binding: ControlledProviderBinding, request_id: str
    ) -> tuple[ControlledProviderAuditReceipt, ...]:
        """Return all matching freshly verified protected rows (exactly one)."""
        ...


class ControllerOwnedControlledProviderForwarder(ProtectedModelForwarder):
    """One attempt's bounded forwarder; revocation drains without stopping lab."""

    def __init__(
        self,
        binding: ControlledProviderBinding,
        generation: ControlledProviderGenerationSource,
        transport: ControlledProviderTransport,
        audit: ControlledProviderAudit,
        *,
        monotonic_ns: Callable[[], int],
        clock: Callable[[], datetime],
    ) -> None:
        self._binding = binding
        self._generation = generation
        self._transport = transport
        self._audit = audit
        self._monotonic_ns = monotonic_ns
        self._clock = clock
        self._condition = threading.Condition()
        self._active = False
        self._revoked = False
        self._unknown = False
        self._revocation: ProtectedRevocationResult | None = None
        self._seen: set[str] = set()
        self._audit_sequences: set[int] = set()
        self._requests = 0
        self._request_bytes = 0

    def __repr__(self) -> str:
        return f"{type(self).__name__}(binding_ref={self._binding.binding_ref!r})"

    def _now(self) -> int:
        try:
            now = self._monotonic_ns()
            if isinstance(now, bool) or not isinstance(now, int) or now < 0:
                raise ValueError
            return now
        except Exception:
            pass
        # Leave the handler before raising so the protected exception cannot
        # survive in even a suppressed public exception context.
        raise EngineRelayError("clock_invalid", "controlled provider clock is invalid")

    def _validate(self, request: ModelForwardRequest) -> None:
        policy = self._binding.policy
        if not isinstance(request, ModelForwardRequest):
            raise EngineRelayError("invalid_request", "controlled provider request is invalid")
        for name in (
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
        ):
            if getattr(request, name) != getattr(policy, name):
                raise EngineRelayError("scope_refused", "controlled provider authority changed")
        for name, expected in (
            ("max_input_tokens", policy.max_input_tokens_per_request),
            ("max_output_tokens", policy.max_output_tokens_per_request),
            ("max_response_bytes", policy.max_response_bytes),
            ("max_cost_microunits", policy.max_cost_microunits_per_request),
        ):
            value = getattr(request, name)
            if isinstance(value, bool) or not isinstance(value, int) or value != expected:
                raise EngineRelayError("scope_refused", "controlled provider cap changed")
        if (
            not isinstance(request.request_id, str)
            or re.fullmatch(r"gateway-request-[0-9a-f]{32}", request.request_id) is None
            or not isinstance(request.body, bytes)
            or not 0 < len(request.body) <= policy.max_request_bytes
        ):
            raise EngineRelayError("invalid_request", "controlled provider request is invalid")
        now = self._now()
        if (
            isinstance(request.deadline_ns, bool)
            or not isinstance(request.deadline_ns, int)
            or not now < request.deadline_ns <= now + policy.request_timeout_ms * 1_000_000
        ):
            raise EngineRelayError("deadline_exceeded", "controlled provider deadline is invalid")
        _normalized_headers(
            request.headers,
            allowed=frozenset({"accept", "content-type", "user-agent"}),
            label="controlled provider request",
        )
        document = _strict_json(request.body, label="controlled provider request")
        if document.get("model") != policy.model_id or document.get("stream") is not True:
            raise EngineRelayError("invalid_request", "controlled provider model or stream changed")
        _controlled_stream_tool_names(document)

    def _authorization_current(self) -> None:
        checked: datetime | None = None
        try:
            now = self._clock()
            if now.tzinfo is None or now.utcoffset() != timedelta(0):
                raise ValueError
            checked = now
        except Exception:
            pass
        if checked is None:
            raise EngineRelayError("clock_invalid", "controlled provider clock is invalid")
        policy = self._binding.policy
        if (
            not parse_iso8601_datetime(policy.created_at)
            <= checked
            < parse_iso8601_datetime(policy.expires_at)
        ):
            raise EngineRelayError("expired", "controlled provider authorization is not current")

    def _fresh(self, session: ControlledProviderGenerationSession) -> None:
        try:
            observed = session.checked_binding()
        except Exception:
            raise EngineRelayError(
                "scope_refused", "controlled provider custody is unavailable"
            ) from None
        if not isinstance(observed, ControlledProviderBinding) or observed != self._binding:
            raise EngineRelayError("scope_refused", "controlled provider generation changed")

    def _reserve(self, request: ModelForwardRequest) -> None:
        policy = self._binding.policy
        with self._condition:
            if self._revoked:
                raise EngineRelayError("revoked", "controlled provider authority is revoked")
            if self._unknown:
                raise EngineRelayError(
                    "upstream_unknown", "controlled provider outcome is unresolved"
                )
            if self._active:
                raise EngineRelayError("busy", "controlled provider already has an active call")
            if request.request_id in self._seen:
                raise EngineRelayError("replay_refused", "controlled provider request was consumed")
            count = self._requests + 1
            if (
                count > policy.max_requests
                or self._request_bytes + len(request.body) > policy.max_total_request_bytes
                or count * policy.max_response_bytes > policy.max_total_response_bytes
                or count
                * (policy.max_input_tokens_per_request + policy.max_output_tokens_per_request)
                > policy.max_total_tokens
                or count * policy.max_cost_microunits_per_request > policy.max_total_cost_microunits
            ):
                raise EngineRelayError(
                    "budget_exhausted", "controlled provider budget is exhausted"
                )
            self._active = True
            self._seen.add(request.request_id)
            self._requests = count
            self._request_bytes += len(request.body)

    def _validate_result(
        self, request: ModelForwardRequest, result: ProtectedModelResult
    ) -> ProtectedModelResult:
        if not isinstance(result, ProtectedModelResult):
            raise ValueError("invalid controlled result")
        if (
            isinstance(result.status, bool)
            or not isinstance(result.status, int)
            or result.status != 200
            or not isinstance(result.body, bytes)
            or len(result.body) > request.max_response_bytes
            or result.protected_secret_absent is not True
            or result.fixture_usage_estimate is not True
            or result.live_model_proof is not False
            or type(result.cost_microunits) is not int
            or result.cost_microunits != 0
        ):
            raise ValueError("invalid controlled result")
        for value, cap in (
            (result.input_tokens, request.max_input_tokens),
            (result.output_tokens, request.max_output_tokens),
        ):
            if type(value) is not int or not 0 <= value <= cap:
                raise ValueError("invalid controlled usage")
        _require_digest(result.provider_request_ref, "controlled provider audit")
        headers = dict(
            _normalized_headers(
                tuple(result.headers.items()),
                allowed=frozenset(
                    {"content-type", "content-length", "cache-control", "x-bluefire-provider"}
                ),
                label="controlled provider response",
            )
        )
        if headers.get("x-bluefire-provider") != PROVIDER_LABEL:
            raise ValueError("invalid controlled provider label")
        if headers.get("content-type") != "text/event-stream":
            raise ValueError("invalid controlled response type")
        if (
            set(headers)
            != {"content-type", "content-length", "cache-control", "x-bluefire-provider"}
            or headers.get("cache-control") != "no-store"
            or headers["content-length"] != str(len(result.body))
        ):
            raise ValueError("invalid controlled response length")
        request_document = _strict_json(request.body, label="controlled provider request")
        stream = _parse_controlled_sse(
            result.body,
            attempt_id=request.attempt_id,
            model_id=request.model_id,
            tool_names=_controlled_stream_tool_names(request_document),
            # Material references must not be published either. The actual
            # credential is known and scanned only by the protected transport.
            bearer=self._binding.material_ref,
            max_input_tokens=request.max_input_tokens,
            max_output_tokens=request.max_output_tokens,
        )
        if (
            stream.input_tokens != result.input_tokens
            or stream.output_tokens != result.output_tokens
        ):
            raise ValueError("controlled stream usage changed")
        receipts = self._audit.correlate(self._binding, request.request_id)
        if not isinstance(receipts, tuple) or len(receipts) != 1:
            raise ValueError("invalid controlled audit count")
        receipt = receipts[0]
        if not isinstance(receipt, ControlledProviderAuditReceipt):
            raise ValueError("invalid controlled audit")
        if type(receipt.sequence) is not int or not 1 <= receipt.sequence <= 32:
            raise ValueError("invalid controlled audit sequence")
        expected = ControlledProviderAuditReceipt(
            binding_ref=self._binding.binding_ref,
            request_id=request.request_id,
            sequence=receipt.sequence,
            request_digest=_digest_bytes(request.body),
            request_bytes=len(request.body),
            response_digest=_digest_bytes(result.body),
            response_bytes=len(result.body),
            status=result.status,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            provider_request_ref=result.provider_request_ref,
        )
        # Equality alone would allow bool/int substitutions in untrusted rows.
        if (
            receipt != expected
            or any(
                type(getattr(receipt, name)) is not int
                for name in (
                    "request_bytes",
                    "response_bytes",
                    "status",
                    "input_tokens",
                    "output_tokens",
                    "cost_microunits",
                )
            )
            or receipt.fixture_usage_estimate is not True
            or receipt.live_model_proof is not False
            or receipt.sequence in self._audit_sequences
            or stream.documents[0]["id"]
            != f"chatcmpl-{request.attempt_id[-12:]}-{receipt.sequence:04d}"
        ):
            raise ValueError("controlled audit correlation changed")
        self._audit_sequences.add(receipt.sequence)
        return ProtectedModelResult(
            status=result.status,
            headers=headers,
            body=result.body,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cost_microunits=0,
            provider_request_ref=result.provider_request_ref,
            protected_secret_absent=True,
            fixture_usage_estimate=True,
            live_model_proof=False,
        )

    def forward(self, request: ModelForwardRequest) -> ProtectedModelResult:
        self._validate(request)
        self._authorization_current()
        self._reserve(request)
        dispatched = False
        failure: EngineRelayError | ProtectedUpstreamUnknown | None = None
        try:
            with self._generation.session(self._binding) as session:
                self._fresh(session)
                self._authorization_current()
                if self._now() >= request.deadline_ns:
                    raise EngineRelayError(
                        "deadline_exceeded", "controlled provider deadline elapsed"
                    )
                with self._condition:
                    if self._revoked:
                        raise EngineRelayError(
                            "revoked", "controlled provider authority is revoked"
                        )
                dispatched = True
                result = self._transport.post_chat_completions(
                    ControlledProviderDispatch(
                        binding_ref=self._binding.binding_ref,
                        request_id=request.request_id,
                        port=self._binding.port,
                        deadline_ns=request.deadline_ns,
                        max_response_bytes=request.max_response_bytes,
                        body=request.body,
                    )
                )
                self._fresh(session)
                validated = self._validate_result(request, result)
                self._fresh(session)
                self._authorization_current()
                if self._now() >= request.deadline_ns:
                    raise EngineRelayError(
                        "deadline_exceeded", "controlled provider deadline elapsed"
                    )
                with self._condition:
                    if self._revoked:
                        raise EngineRelayError(
                            "revoked", "controlled provider authority is revoked"
                        )
                return validated
        except Exception:
            # No exception text, raw transport receipt or provider response is
            # retained. The request is permanently consumed once reserved.
            if dispatched:
                with self._condition:
                    self._unknown = True
                failure = ProtectedUpstreamUnknown(
                    content_hash(
                        {
                            "schema_version": "bluefire.controlled-provider-unknown.v1",
                            "binding_ref": self._binding.binding_ref,
                            "request_id": request.request_id,
                            "request_digest": _digest_bytes(request.body),
                        }
                    )
                )
            else:
                failure = EngineRelayError(
                    "upstream_failed", "controlled provider preflight failed"
                )
        finally:
            with self._condition:
                self._active = False
                self._condition.notify_all()
        assert failure is not None
        raise failure

    def revoke(self, attempt_id: str, authorization_ref: str) -> ProtectedRevocationResult:
        policy = self._binding.policy
        if attempt_id != policy.attempt_id or authorization_ref != policy.authorization_ref:
            raise EngineRelayError("scope_refused", "controlled provider revocation scope changed")
        with self._condition:
            self._revoked = True
            self._condition.notify_all()
            while self._active:
                self._condition.wait()
            if self._revocation is None:
                self._revocation = ProtectedRevocationResult(
                    True,
                    content_hash(
                        {
                            "schema_version": "bluefire.controlled-provider-revocation.v1",
                            "binding_ref": self._binding.binding_ref,
                            "consumed_requests": self._requests,
                            "active_calls": 0,
                        }
                    ),
                )
            return self._revocation
