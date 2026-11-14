"""Private V2 extension of the launcher-bound tenant target adapter.

The original adapter and v1 relay admission are unchanged. V2 retains exactly
the same generation/liveness, protected source token, response/audit and secret
checks; only the app's bounded HTTP input grammar is separately versioned.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field, replace
from typing import cast

from .engine_relay import EngineRelayError, TargetRelayRequest
from .tenant_http_completion_contract import (
    _CONTROLLER_ADAPTER_AUTHORITY,
    VerifiedTenantHttpAdapterRevocation,
    _restore_adapter_revocation,
)
from .tenant_http_target_profile import (
    TenantHttpTargetOperationV2,
    TenantHttpTargetProfileV2,
    admit_tenant_http_operation,
    canonical_tenant_http_request,
)
from .tenant_record_controller_contract import (
    TenantTargetOperationUnknown,
    tenant_target_snapshot_ref,
)
from .tenant_record_lab import TenantRecordFixture
from .tenant_record_service import TenantResponse
from .tenant_record_target_adapter import (
    _REQUEST_ID,
    LOGICAL_AUTHORITY,
    REQUEST_TIMEOUT_SECONDS,
    TenantEngineTargetRequest,
    TenantEngineTargetResult,
    TenantEngineTargetRoute,
    TenantGenerationExpectation,
    TenantRecordLauncherTargetAdapter,
    TenantTargetAdapterError,
    _bytes_digest,
    _check_engine_audit,
    _check_response,
    _engine_secret_absent,
    _FixedEngineTargetRequest,
    _request_unknown_receipt,
    _safe_receipt,
)
from .tenant_record_target_child import SOURCE_HEADER
from .util import content_hash, parse_iso8601_datetime


@dataclass(frozen=True, slots=True)
class TenantHttpEngineTargetRequestV2:
    profile: TenantHttpTargetProfileV2
    operation: TenantHttpTargetOperationV2

    def __post_init__(self) -> None:
        if (
            type(self.profile) is not TenantHttpTargetProfileV2
            or type(self.operation) is not TenantHttpTargetOperationV2
        ):
            raise TenantTargetAdapterError("v2 engine HTTP request is invalid")
        profile = replace(self.profile)
        operation = self.operation
        rebuilt = admit_tenant_http_operation(
            profile,
            TargetRelayRequest(
                operation.request_id,
                operation.attempt_id,
                profile.authority,
                "GET",
                operation.target,
                operation.headers,
            ),
            deadline_ns=operation.deadline_ns,
        )
        if operation != rebuilt:
            raise TenantTargetAdapterError("v2 engine HTTP operation binding changed")

    @property
    def relay_request_id(self) -> str:
        return self.operation.request_id

    @property
    def operation_digest(self) -> str:
        return self.operation.digest

    @property
    def expected_generation(self) -> TenantGenerationExpectation:
        return self.profile.expected_generation

    @property
    def target_snapshot_ref(self) -> str:
        return self.profile.target_snapshot_ref

    @property
    def route(self) -> TenantEngineTargetRoute:
        return TenantEngineTargetRoute(self.operation.route_id)

    @property
    def record_id(self) -> str | None:
        return self.operation.record_id

    @property
    def tenant_id(self) -> str | None:
        return self.operation.tenant_id

    @property
    def tenant_assertion(self) -> str | None:
        return self.operation.tenant_assertion

    @property
    def max_response_bytes(self) -> int:
        return self.operation.max_response_bytes

    @property
    def deadline_ns(self) -> int:
        return self.operation.deadline_ns


@dataclass(frozen=True, slots=True)
class _CanonicalEngineHttpWireRequestV2:
    operation: TenantHttpTargetOperationV2
    source_token: bytes = field(repr=False)
    timeout_seconds: float
    max_response_bytes: int

    def __post_init__(self) -> None:
        canonical_tenant_http_request(self.operation.target, self.operation.headers)
        if (
            type(self.source_token) is not bytes
            or not 32 <= len(self.source_token) <= 64
            or not 0 < self.timeout_seconds <= REQUEST_TIMEOUT_SECONDS
            or self.max_response_bytes != self.operation.max_response_bytes
        ):
            raise TenantTargetAdapterError("v2 fixed HTTP wire request is invalid")

    @property
    def target(self) -> str:
        return self.operation.target

    @property
    def headers(self) -> tuple[tuple[str, str], ...]:
        encoded = base64.urlsafe_b64encode(self.source_token).decode("ascii").rstrip("=")
        return (("host", LOGICAL_AUTHORITY), (SOURCE_HEADER, encoded), *self.operation.headers)


def requested_tenant_v2(
    request: TenantHttpEngineTargetRequestV2, fixture: TenantRecordFixture
) -> str | None:
    if request.route is TenantEngineTargetRoute.BOUNDED_EXPORT:
        return request.tenant_id
    if request.route is TenantEngineTargetRoute.RECORD_LOOKUP:
        matches = [record for record in fixture.records if record.record_id == request.record_id]
        return matches[0].tenant_id if len(matches) == 1 else None
    return None


class TenantRecordHttpTargetAdapterV2(TenantRecordLauncherTargetAdapter):
    """One profile per adapter; no new launch, target, or source-token surface."""

    _http_profile: TenantHttpTargetProfileV2

    def bind_http_profile(self, profile: TenantHttpTargetProfileV2) -> None:
        replace(profile)
        with self._lock:
            if getattr(self, "_http_profile", None) is not None:
                if self._http_profile != profile:
                    raise EngineRelayError("scope_refused", "v2 adapter profile changed")
                return
            generation = self._checked_running(profile.expected_generation)
            profile.check_running(
                generation.source, generation.expectation, generation.generic_ready.endpoint
            )
            self._http_profile = profile
            remaining_ns = int(
                (
                    parse_iso8601_datetime(profile.expires_at)
                    - parse_iso8601_datetime(generation.source.packet.verified_at)
                ).total_seconds()
                * 1_000_000_000
            )
            self._http_deadline_ns = self._monotonic_ns() + min(
                profile.run_timeout_ms * 1_000_000, remaining_ns
            )
            self._http_seen: set[str] = set()
            self._http_reserved_bytes = 0
            self._http_revoked = False

    def revoke_http_profile(self) -> VerifiedTenantHttpAdapterRevocation:
        with self._lock:
            self._http_revoked = True
            return _restore_adapter_revocation(
                {
                    "schema_version": "bluefire.tenant-http-adapter-revocation.v2",
                    "profile_digest": self._http_profile.policy_digest,
                    "generation_digest": self._http_profile.expected_generation.digest,
                    "accepted_http_calls": len(self._http_seen),
                    "reserved_response_bytes": self._http_reserved_bytes,
                    "request_ids_digest": content_hash(sorted(self._http_seen)),
                },
                _authority=_CONTROLLER_ADAPTER_AUTHORITY,
            )

    # The effect path below deliberately retains v1's private audit/liveness checks.

    def engine_http_request(
        self, request: TenantHttpEngineTargetRequestV2
    ) -> TenantEngineTargetResult:
        """Execute one typed engine operation through the protected target child."""

        if type(request) is not TenantHttpEngineTargetRequestV2:
            raise TenantTargetAdapterError("engine target request is invalid")
        replace(request)
        self.bind_http_profile(request.profile)
        with self._lock:
            profile = request.profile
            if self._http_revoked:
                raise EngineRelayError("revoked", "v2 target profile is revoked")
            if request.relay_request_id in self._http_seen:
                raise EngineRelayError("replay_refused", "v2 target request was already consumed")
            if (
                len(self._http_seen) >= profile.max_http_calls
                or self._http_reserved_bytes + request.max_response_bytes
                > profile.max_total_response_bytes
            ):
                raise EngineRelayError(
                    "budget_exhausted", "v2 HTTP call or response-byte budget is exhausted"
                )
            if request.deadline_ns > self._http_deadline_ns:
                raise EngineRelayError("deadline_exceeded", "v2 HTTP run deadline changed")
            now_ns = self._monotonic_ns()
            if (
                isinstance(now_ns, bool)
                or not isinstance(now_ns, int)
                or request.deadline_ns <= now_ns
                or request.deadline_ns > now_ns + profile.request_timeout_ms * 1_000_000
            ):
                raise TenantTargetAdapterError("engine target request deadline expired")
            generation = self._checked_running(request.expected_generation)
            snapshot_ref = tenant_target_snapshot_ref(
                fixture_digest=generation.source.fixture.digest,
                target_snapshot_id=generation.target_ready.target_snapshot_id,
                service_generation=generation.target_ready.service_generation,
            )
            if request.target_snapshot_ref != snapshot_ref:
                raise TenantTargetAdapterError("engine target snapshot changed")
            profile.check_running(
                generation.source, generation.expectation, generation.generic_ready.endpoint
            )
            wall_remaining_ns = int(
                (
                    parse_iso8601_datetime(profile.expires_at)
                    - parse_iso8601_datetime(generation.source.packet.verified_at)
                ).total_seconds()
                * 1_000_000_000
            )
            if request.deadline_ns > now_ns + wall_remaining_ns:
                raise EngineRelayError(
                    "deadline_exceeded", "v2 HTTP deadline exceeds the profile lifetime"
                )
            requested_tenant = requested_tenant_v2(request, generation.source.fixture)
            generation = self._checked_running(request.expected_generation)
            dispatch_ns = self._monotonic_ns()
            if isinstance(dispatch_ns, bool) or not isinstance(dispatch_ns, int):
                raise TenantTargetAdapterError("engine target monotonic clock is invalid")
            remaining_seconds = (request.deadline_ns - dispatch_ns) / 1_000_000_000
            timeout_seconds = min(
                REQUEST_TIMEOUT_SECONDS,
                generation.source.packet.remaining_seconds,
                remaining_seconds,
            )
            if timeout_seconds <= 0:
                raise TenantTargetAdapterError("engine target request deadline expired")
            if (
                len(self._seen_request_ids) >= generation.target_ready.max_requests
                or len(self._request_bindings) >= generation.target_ready.max_requests
            ):
                raise TenantTargetAdapterError("target request binding limit reached")
            admission = generation.source.admission("engine_worker")
            fixed = _CanonicalEngineHttpWireRequestV2(
                operation=request.operation,
                source_token=admission.token,
                timeout_seconds=timeout_seconds,
                max_response_bytes=request.max_response_bytes,
            )
            effect_ns = self._monotonic_ns()
            if (
                isinstance(effect_ns, bool)
                or not isinstance(effect_ns, int)
                or effect_ns >= request.deadline_ns
            ):
                raise TenantTargetAdapterError("engine target request deadline expired")
            self._http_seen.add(request.relay_request_id)
            self._http_reserved_bytes += request.max_response_bytes
            try:
                raw_response = self._transport.request(
                    generation.generic_ready.endpoint, cast(_FixedEngineTargetRequest, fixed)
                )
            except Exception:
                self._mark_unknown()
                receipt = _request_unknown_receipt(
                    generation, request.operation_digest, "engine_worker", "transport"
                )
                raise TenantTargetOperationUnknown(
                    "engine target request outcome is unknown", receipt_digest=receipt
                ) from None
            try:
                if (
                    not isinstance(raw_response, TenantResponse)
                    or type(raw_response.body) is not bytes
                ):
                    raise TenantTargetAdapterError("engine target response is invalid")
                response = TenantResponse(
                    status=raw_response.status,
                    headers=dict(raw_response.headers),
                    body=bytes(raw_response.body),
                )
                _check_response(response)
                if not 200 <= response.status <= 599 or 300 <= response.status <= 399:
                    raise TenantTargetAdapterError("v2 response status or redirect is refused")
                if len(response.body) > request.max_response_bytes:
                    raise TenantTargetAdapterError("engine target response exceeded its byte bound")
                target_request_id = response.headers.get("x-bluefire-lab-request")
                if (
                    not isinstance(target_request_id, str)
                    or _REQUEST_ID.fullmatch(target_request_id) is None
                    or target_request_id in self._seen_request_ids
                ):
                    raise TenantTargetAdapterError("engine target response identity is invalid")
                if self._monotonic_ns() >= request.deadline_ns:
                    raise TenantTargetAdapterError("engine target response missed its deadline")
                self._checked_running(request.expected_generation)
                self._seen_request_ids.add(target_request_id)
                self._request_bindings[target_request_id] = (
                    request.expected_generation.digest,
                    "engine_worker",
                )
                row = self.audit_row(target_request_id)
                binding, retention_ref = self.audit_binding(
                    target_request_id,
                    generation_digest=request.expected_generation.digest,
                )
                _check_engine_audit(
                    request=cast(TenantEngineTargetRequest, request),
                    response=response,
                    row=row,
                    binding=binding,
                    retention_ref=retention_ref,
                    generation=generation,
                    requested_tenant=requested_tenant,
                )
                if not _engine_secret_absent(
                    admission.token,
                    response=response,
                    row=row,
                    binding=binding,
                    retention_ref=retention_ref,
                ):
                    raise TenantTargetAdapterError(
                        "engine target response failed its protected secret check"
                    )
                self._checked_running(request.expected_generation)
                if self._monotonic_ns() >= request.deadline_ns:
                    raise TenantTargetAdapterError("engine target response missed its deadline")
            except Exception:
                self._mark_unknown()
                receipt = _request_unknown_receipt(
                    generation, request.operation_digest, "engine_worker", "postcondition"
                )
                raise TenantTargetOperationUnknown(
                    "engine target request postcondition is unknown",
                    receipt_digest=receipt,
                ) from None
            observation_ref = _safe_receipt(
                "bluefire.tenant-engine-target-observation.v2",
                {
                    "relay_request_id": request.relay_request_id,
                    "operation_digest": request.operation_digest,
                    "target_request_id": target_request_id,
                    "generation_digest": request.expected_generation.digest,
                    "target_snapshot_ref": request.target_snapshot_ref,
                    "audit_row_digest": row.digest,
                    "audit_binding_digest": binding.digest,
                    "audit_retention_ref": retention_ref,
                    "response_status": response.status,
                    "response_sha256": _bytes_digest(response.body),
                    "response_headers_sha256": content_hash(dict(response.headers)),
                },
            )
            return TenantEngineTargetResult(
                relay_request_id=request.relay_request_id,
                operation_digest=request.operation_digest,
                target_request_id=target_request_id,
                response=response,
                generation_digest=request.expected_generation.digest,
                audit_row=row,
                audit_binding=binding,
                audit_retention_ref=retention_ref,
                target_observation_ref=observation_ref,
                protected_secret_absent=True,
            )
