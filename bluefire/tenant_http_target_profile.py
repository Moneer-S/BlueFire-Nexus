"""V2 admission for the disposable tenant app's controlled HTTP effects.

This contract grants no launch or execution authority. The origin is the exact
launcher-owned numeric loopback endpoint, never a URL supplied by the engine.
V1's fixed-route/known-identity relay remains a separate unchanged contract.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace
from datetime import timedelta
from typing import Any

from .engine_relay import EngineRelayError, TargetRelayRequest
from .tenant_record_controller_contract import tenant_target_snapshot_ref
from .tenant_record_lab_launcher import LoopbackEndpoint, ServiceRole
from .tenant_record_observer import MAX_RESPONSE_BYTES
from .tenant_record_target_adapter import TenantGenerationExpectation, TenantRunningGeneration
from .util import content_hash, parse_iso8601_datetime

PROFILE_SCHEMA = "bluefire.tenant-http-target-profile.v2"
OPERATION_SCHEMA = "bluefire.tenant-http-target-operation.v2"
MAX_AUDIT_ROW_RESERVATION_BYTES = 8192  # 16 records, bounded IDs, hashes and fixed audit fields.
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}")
_REQUEST = re.compile(r"relay-request-[0-9a-f]{32}")
_VALUE = re.compile(r"[a-z][a-z0-9_-]{2,63}")
_ALLOWED_HEADERS = frozenset({"accept", "user-agent", "x-bluefire-lab-tenant"})


def _digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError("v2 target proof reference is invalid")
    return value


def _integer(value: Any, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError("v2 target budget is invalid")
    return value


def canonical_tenant_http_request(
    target: str, headers: tuple[tuple[str, str], ...]
) -> tuple[str, str | None, str | None, str | None, tuple[tuple[str, str], ...]]:
    """Parse app-only origin-form grammar; do not consult the record directory.

    No encoding, dot segments, alternate slash, duplicate/unknown query fields,
    credentials, body framing, host forwarding or engine-owned source admission.
    Header ordering is engine-selected; names/values are canonical and bounded.
    """
    if not isinstance(target, str) or not 1 <= len(target) <= 96 or not target.isascii():
        raise EngineRelayError("route_refused", "v2 target is outside the app grammar")
    route: str
    record: str | None = None
    tenant: str | None = None
    if target == "/health":
        route = "health"
    elif target == "/openapi.json":
        route = "metadata"
    elif target.startswith("/records/") and _VALUE.fullmatch(target[9:]):
        route, record = "record_lookup", target[9:]
    elif target.startswith("/exports?tenant=") and _VALUE.fullmatch(target[16:]):
        route, tenant = "bounded_export", target[16:]
    else:
        raise EngineRelayError("route_refused", "v2 target is outside the app grammar")
    if type(headers) is not tuple or len(headers) > len(_ALLOWED_HEADERS):
        raise EngineRelayError("headers_refused", "v2 target headers are invalid")
    normalized: dict[str, str] = {}
    for pair in headers:
        if type(pair) is not tuple or len(pair) != 2:
            raise EngineRelayError("headers_refused", "v2 target headers are invalid")
        name, value = pair
        if (
            not isinstance(name, str)
            or name not in _ALLOWED_HEADERS
            or name in normalized
            or not isinstance(value, str)
            or not 1 <= len(value) <= 256
            or not value.isascii()
            or value != value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise EngineRelayError("headers_refused", "v2 target headers are invalid")
        if name == "x-bluefire-lab-tenant" and _VALUE.fullmatch(value) is None:
            raise EngineRelayError("headers_refused", "v2 tenant assertion is invalid")
        normalized[name] = value
    return (
        route,
        record,
        tenant,
        normalized.get("x-bluefire-lab-tenant"),
        tuple(sorted(normalized.items())),
    )


@dataclass(frozen=True, slots=True)
class TenantHttpTargetProfileV2:
    attempt_id: str
    binding_digest: str
    delegation_digest: str
    objective_ref: str
    environment_ref: str
    scope_ref: str
    asset_ref: str  # Exact generated fixture content digest; no external asset selector.
    launcher_run_id: str
    launcher_attempt_id: str
    engine_source_admission_digest: str
    expected_generation: TenantGenerationExpectation
    target_snapshot_ref: str
    packet_digest: str
    endpoint: LoopbackEndpoint
    created_at: str
    expires_at: str
    child_max_requests: int
    child_max_audit_events: int
    child_max_audit_bytes: int
    child_max_runtime_seconds: int
    child_request_reserve: int
    max_http_calls: int
    max_response_bytes: int
    max_total_response_bytes: int
    request_timeout_ms: int
    run_timeout_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, str) or _ATTEMPT.fullmatch(self.attempt_id) is None:
            raise ValueError("v2 target attempt is invalid")
        if (
            not isinstance(self.launcher_run_id, str)
            or re.fullmatch(r"engine-lab-[0-9a-f]{32}", self.launcher_run_id) is None
            or not isinstance(self.launcher_attempt_id, str)
            or _ATTEMPT.fullmatch(self.launcher_attempt_id) is None
        ):
            raise ValueError("v2 launcher owner identity is invalid")
        for name in (
            "binding_digest",
            "delegation_digest",
            "objective_ref",
            "environment_ref",
            "scope_ref",
            "asset_ref",
            "engine_source_admission_digest",
            "target_snapshot_ref",
            "packet_digest",
        ):
            _digest(getattr(self, name))
        if type(self.expected_generation) is not TenantGenerationExpectation:
            raise ValueError("v2 target generation is invalid")
        replace(self.expected_generation)
        if type(self.endpoint) is not LoopbackEndpoint or self.endpoint.port == 0:
            raise ValueError("v2 target endpoint is invalid")
        replace(self.endpoint)
        _integer(self.child_max_requests, 1, 256)
        _integer(self.child_max_audit_events, self.child_max_requests, 256)
        _integer(self.child_max_audit_bytes, 4096, 2 * 1024 * 1024)
        _integer(self.child_max_runtime_seconds, 1, 900)
        _integer(self.child_request_reserve, 0, self.child_max_requests - 1)
        _integer(self.max_http_calls, 1, self.child_max_requests - self.child_request_reserve)
        reserved = self.max_http_calls + self.child_request_reserve
        if (
            reserved > self.child_max_audit_events
            or reserved * MAX_AUDIT_ROW_RESERVATION_BYTES > self.child_max_audit_bytes
        ):
            raise ValueError("v2 HTTP budget exceeds the child audit reservation")
        _integer(self.max_response_bytes, 1, MAX_RESPONSE_BYTES)
        _integer(
            self.max_total_response_bytes,
            self.max_response_bytes,
            self.max_http_calls * self.max_response_bytes,
        )
        _integer(self.request_timeout_ms, 1, 5000)
        _integer(
            self.run_timeout_ms, self.request_timeout_ms, self.child_max_runtime_seconds * 1000
        )
        created = parse_iso8601_datetime(self.created_at)
        expires = parse_iso8601_datetime(self.expires_at)
        if (
            created.tzinfo is None
            or expires.tzinfo is None
            or not timedelta(0) < expires - created <= timedelta(milliseconds=self.run_timeout_ms)
        ):
            raise ValueError("v2 target lifetime is invalid")

    @property
    def authority(self) -> str:
        host = f"[{self.endpoint.host}]" if ":" in self.endpoint.host else self.endpoint.host
        return f"{host}:{self.endpoint.port}"

    @property
    def origin(self) -> str:
        return "http://" + self.authority

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.update(
            schema_version=PROFILE_SCHEMA,
            source_identity="engine_worker",
            origin=self.origin,
            redirect_policy="refuse_all",
            external_egress="deny",
            method="GET",
            body_bytes=0,
            value_grammar=_VALUE.pattern,
            allowed_headers=sorted(_ALLOWED_HEADERS),
            audit_row_reservation_bytes=MAX_AUDIT_ROW_RESERVATION_BYTES,
        )
        return result

    @property
    def policy_digest(self) -> str:
        return content_hash(self.to_dict())

    @classmethod
    def from_running(
        cls,
        *,
        generation: TenantRunningGeneration,
        expected_generation: TenantGenerationExpectation,
        **values: Any,
    ) -> "TenantHttpTargetProfileV2":
        """Pure construction from a controller-owned fresh launcher projection."""
        source = replace(generation)
        expected = replace(expected_generation)
        if (
            expected.plan_digest != source.lifecycle.plan.digest
            or expected.lifecycle_digest != source.lifecycle.digest
            or expected.target_snapshot_id != source.config.target_snapshot_id
            or expected.service_generation != source.config.service_generation
        ):
            raise ValueError("v2 profile differs from the launcher generation")
        packet = source.packet
        ready = [item for item in source.lifecycle.readiness if item.role is ServiceRole.TARGET]
        if len(ready) != 1:
            raise ValueError("v2 target readiness is incomplete")
        profile = cls(
            asset_ref=source.fixture.digest,
            launcher_run_id=source.lifecycle.plan.run_id,
            launcher_attempt_id=source.lifecycle.plan.attempt_id,
            engine_source_admission_digest=source.admission("engine_worker").token_digest,
            expected_generation=expected,
            target_snapshot_ref=tenant_target_snapshot_ref(
                fixture_digest=source.fixture.digest,
                target_snapshot_id=source.config.target_snapshot_id,
                service_generation=source.config.service_generation,
            ),
            packet_digest=packet.packet_digest,
            endpoint=ready[0].endpoint,
            child_max_requests=packet.max_requests,
            child_max_audit_events=packet.max_audit_events,
            child_max_audit_bytes=packet.max_audit_bytes,
            child_max_runtime_seconds=packet.max_runtime_seconds,
            **values,
        )
        if not (
            parse_iso8601_datetime(packet.created_at)
            <= parse_iso8601_datetime(profile.created_at)
            < parse_iso8601_datetime(profile.expires_at)
            <= parse_iso8601_datetime(packet.expires_at)
        ):
            raise ValueError("v2 profile is outside the target packet lifetime")
        return profile

    def check_running(
        self,
        generation: TenantRunningGeneration,
        expected: TenantGenerationExpectation,
        endpoint: LoopbackEndpoint,
    ) -> None:
        if (
            not parse_iso8601_datetime(self.created_at)
            <= parse_iso8601_datetime(generation.packet.verified_at)
            < parse_iso8601_datetime(self.expires_at)
        ):
            raise EngineRelayError("expired", "v2 profile lifetime elapsed")
        recreated = type(self).from_running(
            generation=generation,
            expected_generation=expected,
            **{
                name: getattr(self, name)
                for name in (
                    "attempt_id",
                    "binding_digest",
                    "delegation_digest",
                    "objective_ref",
                    "environment_ref",
                    "scope_ref",
                    "created_at",
                    "expires_at",
                    "child_request_reserve",
                    "max_http_calls",
                    "max_response_bytes",
                    "max_total_response_bytes",
                    "request_timeout_ms",
                    "run_timeout_ms",
                )
            },
        )
        if recreated != self or endpoint != self.endpoint:
            raise EngineRelayError("scope_refused", "v2 launcher target binding changed")


@dataclass(frozen=True, slots=True)
class TenantHttpTargetOperationV2:
    request_id: str
    attempt_id: str
    profile_digest: str
    generation_digest: str
    target_snapshot_ref: str
    asset_ref: str
    target: str
    headers: tuple[tuple[str, str], ...]
    route_id: str
    record_id: str | None
    tenant_id: str | None
    tenant_assertion: str | None
    max_response_bytes: int
    deadline_ns: int
    source_identity: str = "engine_worker"

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": OPERATION_SCHEMA, **asdict(self)}

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


def admit_tenant_http_operation(
    profile: TenantHttpTargetProfileV2, request: TargetRelayRequest, *, deadline_ns: int
) -> TenantHttpTargetOperationV2:
    replace(profile)
    if (
        type(request) is not TargetRelayRequest
        or not isinstance(request.request_id, str)
        or _REQUEST.fullmatch(request.request_id) is None
    ):
        raise EngineRelayError("invalid_request", "v2 target request identity is invalid")
    if request.attempt_id != profile.attempt_id or request.authority != profile.authority:
        raise EngineRelayError("scope_refused", "v2 target origin or attempt changed")
    if request.method != "GET" or type(request.body) is not bytes or request.body:
        raise EngineRelayError("method_refused", "v2 target admits only bodyless GET")
    route, record, tenant, assertion, headers = canonical_tenant_http_request(
        request.target, request.headers
    )
    _integer(deadline_ns, 1, 2**63 - 1)
    return TenantHttpTargetOperationV2(
        request.request_id,
        profile.attempt_id,
        profile.policy_digest,
        profile.expected_generation.digest,
        profile.target_snapshot_ref,
        profile.asset_ref,
        request.target,
        headers,
        route,
        record,
        tenant,
        assertion,
        profile.max_response_bytes,
        deadline_ns,
    )
