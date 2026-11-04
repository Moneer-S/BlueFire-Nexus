"""Fixed controller adapter for one launcher-owned tenant-record target.

The adapter deliberately exposes the narrow ``TenantRecordControllerTarget``
port rather than an HTTP, path, process, or packet API.  A trusted generation
source owns durable lifecycle state and fresh packet construction.  This
module independently binds that source to the launcher's RUNNING record, the
child's protected readiness/audit files, and one numeric-loopback endpoint.

Target generations are immutable.  Applying or rolling back a defense is a
durable generation transition: retain the old audit, stop and clean the old
lab, then start a newly identified generation over the same generated fixture.
The source is responsible for that write-ahead lifecycle transaction; this
adapter validates its result and never mutates an in-process target.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Protocol, Sequence, cast

from .runner_descriptor_io import _descriptor_mount_identity
from .runner_private_files import _PinnedPrivateDirectory
from .tenant_record_experiment_controller import (
    TenantDefensePlan,
    TenantFailureMechanism,
    TenantRoute,
    TenantTargetCleanup,
    TenantTargetOperationUnknown,
    TenantTargetReadback,
)
from .tenant_record_lab import (
    TenantDefenseConfig,
    TenantRecordFixture,
    baseline_defense_config,
)
from .tenant_record_lab_launcher import (
    LifecycleState,
    LoopbackEndpoint,
    ReadinessReceipt,
    ServiceRole,
    TenantLabLifecycleRecord,
    WorkspaceLayout,
)
from .tenant_record_observer import (
    AUDIT_SCHEMA,
    MAX_AUDIT_EVENTS,
    MAX_RESPONSE_BYTES,
    MAX_RESPONSE_HEADER_VALUE_CHARS,
    TenantAuditRow,
)
from .tenant_record_service import TenantResponse
from .tenant_record_target_child import SOURCE_HEADER, TargetReadyReceipt
from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

GENERATION_SCHEMA = "bluefire.tenant-record-adapter-generation.v1"
TRANSITION_SCHEMA = "bluefire.tenant-record-generation-transition.v1"
CLEANUP_SCHEMA = "bluefire.tenant-record-generation-cleanup.v1"
LOGICAL_AUTHORITY = "tenant-record.test"
MAX_SESSION_TOKEN_CHARS = 8192 - len("BlueFireLab ")
REQUEST_TIMEOUT_SECONDS = 5.0

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REQUEST_ID = re.compile(r"^request-[0-9a-f]{24}$")
_DEFENSE_OPERATION = re.compile(r"^tenant-defense-[0-9a-f]{32}$")
_ROLLBACK_OPERATION = re.compile(r"^tenant-rollback-[0-9a-f]{32}$")
_CLEANUP_OPERATION = re.compile(r"^tenant-cleanup-[0-9a-f]{32}$")
_LAB_ID = re.compile(r"^[a-z][a-z0-9-]{7,63}$")
_SOURCE_IDENTITIES = ("engine_worker", "ordinary_user", "controller_probe")
_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "cache-control",
        "x-content-type-options",
        "x-bluefire-lab-request",
    }
)


class TenantTargetAdapterError(RuntimeError):
    """Raised when the fixed target binding cannot be established safely."""


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TenantTargetAdapterError(f"{label} digest is invalid")
    return value


def _safe_receipt(kind: str, fields: Mapping[str, object]) -> str:
    """Create a canonical receipt containing identities, never secret values."""

    return cast(str, content_hash({"schema_version": kind, **fields}))


@dataclass(frozen=True, slots=True)
class TenantControllerAdmission:
    """One controller-minted child admission; its bearer is never serialized."""

    source_identity: str
    token: bytes = field(repr=False)
    token_digest: str

    def __post_init__(self) -> None:
        if self.source_identity not in _SOURCE_IDENTITIES:
            raise TenantTargetAdapterError("controller source identity is invalid")
        if type(self.token) is not bytes or not 32 <= len(self.token) <= 64:
            raise TenantTargetAdapterError("controller source admission is invalid")
        expected = "sha256:" + hashlib.sha256(self.token).hexdigest()
        if self.token_digest != expected:
            raise TenantTargetAdapterError("controller source admission digest changed")

    @classmethod
    def create(cls, source_identity: str, token: bytes) -> "TenantControllerAdmission":
        digest = "sha256:" + hashlib.sha256(token).hexdigest()
        return cls(source_identity=source_identity, token=token, token_digest=digest)


@dataclass(frozen=True, slots=True)
class TenantTargetPacketBinding:
    """Non-secret projection of the controller-retained target packet."""

    run_id: str
    attempt_id: str
    packet_digest: str
    fixture_digest: str
    config_digest: str
    max_requests: int
    max_audit_events: int
    max_audit_bytes: int
    max_runtime_seconds: int
    created_at: str
    expires_at: str
    verified_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not isinstance(self.attempt_id, str):
            raise TenantTargetAdapterError("target packet owner identity is invalid")
        for label, value in (
            ("target packet", self.packet_digest),
            ("target packet fixture", self.fixture_digest),
            ("target packet config", self.config_digest),
        ):
            _digest(value, label)
        if (
            type(self.max_requests) is not int
            or not 1 <= self.max_requests <= 256
            or type(self.max_audit_events) is not int
            or not self.max_requests <= self.max_audit_events <= MAX_AUDIT_EVENTS
            or type(self.max_audit_bytes) is not int
            or not 4096 <= self.max_audit_bytes <= 2 * 1024 * 1024
            or type(self.max_runtime_seconds) is not int
            or not 1 <= self.max_runtime_seconds <= 900
        ):
            raise TenantTargetAdapterError("target packet bounds are invalid")
        try:
            created = parse_iso8601_datetime(self.created_at)
            expires = parse_iso8601_datetime(self.expires_at)
            verified = parse_iso8601_datetime(self.verified_at)
        except (TypeError, ValueError) as exc:
            raise TenantTargetAdapterError("target packet time binding is invalid") from exc
        if (
            created.tzinfo is None
            or expires.tzinfo is None
            or verified.tzinfo is None
            or not created <= verified < expires
            or (expires - created).total_seconds() != self.max_runtime_seconds
        ):
            raise TenantTargetAdapterError("target packet is outside its admitted lifetime")

    @property
    def remaining_seconds(self) -> float:
        return cast(
            float,
            (
                parse_iso8601_datetime(self.expires_at) - parse_iso8601_datetime(self.verified_at)
            ).total_seconds(),
        )


@dataclass(frozen=True, slots=True)
class TenantRunningGeneration:
    """Fresh trusted source view of one launcher-verified RUNNING generation."""

    lifecycle: TenantLabLifecycleRecord
    packet: TenantTargetPacketBinding
    fixture: TenantRecordFixture
    config: TenantDefenseConfig
    admissions: tuple[TenantControllerAdmission, ...] = field(repr=False)
    liveness_receipt_digest: str

    def __post_init__(self) -> None:
        if self.lifecycle.state is not LifecycleState.RUNNING:
            raise TenantTargetAdapterError("tenant target generation is not running")
        if (
            self.packet.run_id != self.lifecycle.plan.run_id
            or self.packet.attempt_id != self.lifecycle.plan.attempt_id
            or self.packet.packet_digest != self.lifecycle.plan.target_packet_digest
            or self.packet.fixture_digest != self.fixture.digest
            or self.packet.config_digest != self.config.digest
        ):
            raise TenantTargetAdapterError("tenant target packet binding changed")
        if self.config.fixture_digest != self.fixture.digest:
            raise TenantTargetAdapterError("tenant target generation changed its fixture")
        if tuple(item.source_identity for item in self.admissions) != _SOURCE_IDENTITIES:
            raise TenantTargetAdapterError("tenant target admissions are incomplete")
        if len({item.token_digest for item in self.admissions}) != len(self.admissions):
            raise TenantTargetAdapterError("tenant target admissions reuse a bearer")
        _digest(self.liveness_receipt_digest, "generation liveness")

    @property
    def admission_digests(self) -> dict[str, str]:
        return {item.source_identity: item.token_digest for item in self.admissions}

    def admission(self, source_identity: str) -> TenantControllerAdmission:
        matches = [item for item in self.admissions if item.source_identity == source_identity]
        if len(matches) != 1:
            raise TenantTargetAdapterError("controller source admission is unavailable")
        return matches[0]


@dataclass(frozen=True, slots=True)
class TenantGenerationExpectation:
    """Non-secret identity pinned across adapter operations."""

    plan_digest: str
    lifecycle_digest: str
    ready_digest: str
    target_snapshot_id: str
    service_generation: str

    def __post_init__(self) -> None:
        for label, value in (
            ("generation plan", self.plan_digest),
            ("generation lifecycle", self.lifecycle_digest),
            ("generation readiness", self.ready_digest),
        ):
            _digest(value, label)
        if not self.target_snapshot_id or not self.service_generation:
            raise TenantTargetAdapterError("target generation identity is invalid")

    @property
    def digest(self) -> str:
        return _safe_receipt(
            GENERATION_SCHEMA,
            {
                "plan_digest": self.plan_digest,
                "lifecycle_digest": self.lifecycle_digest,
                "ready_digest": self.ready_digest,
                "target_snapshot_id": self.target_snapshot_id,
                "service_generation": self.service_generation,
            },
        )


class TenantGenerationTransitionOutcome(str, Enum):
    CHANGED = "changed"
    NOT_CHANGED = "not_changed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class TenantGenerationTransitionIntent:
    """Fixed mutation intent persisted by the generation source before effects."""

    direction: str
    operation_id: str
    defense_plan_digest: str
    fixture_digest: str
    prior: TenantGenerationExpectation
    prior_config_digest: str
    desired_config_digest: str

    def __post_init__(self) -> None:
        if self.direction not in {"apply", "rollback"}:
            raise TenantTargetAdapterError("target transition direction is invalid")
        operation_pattern = _DEFENSE_OPERATION if self.direction == "apply" else _ROLLBACK_OPERATION
        if (
            not isinstance(self.operation_id, str)
            or operation_pattern.fullmatch(self.operation_id) is None
        ):
            raise TenantTargetAdapterError("target transition operation is invalid")
        for label, value in (
            ("defense plan", self.defense_plan_digest),
            ("transition fixture", self.fixture_digest),
            ("transition prior config", self.prior_config_digest),
            ("transition desired config", self.desired_config_digest),
        ):
            _digest(value, label)

    @property
    def digest(self) -> str:
        return _safe_receipt(
            TRANSITION_SCHEMA,
            {
                "direction": self.direction,
                "operation_id": self.operation_id,
                "defense_plan_digest": self.defense_plan_digest,
                "fixture_digest": self.fixture_digest,
                "prior_generation_digest": self.prior.digest,
                "prior_config_digest": self.prior_config_digest,
                "desired_config_digest": self.desired_config_digest,
            },
        )


@dataclass(frozen=True, slots=True)
class TenantGenerationTransitionResult:
    outcome: TenantGenerationTransitionOutcome
    prior_lifecycle_digest: str
    write_ahead_receipt_digest: str
    source_receipt_digest: str
    generation: TenantRunningGeneration | None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, TenantGenerationTransitionOutcome):
            raise TenantTargetAdapterError("transition outcome is invalid")
        _digest(self.prior_lifecycle_digest, "transition prior lifecycle")
        _digest(self.write_ahead_receipt_digest, "transition write-ahead")
        _digest(self.source_receipt_digest, "transition source")
        if self.outcome is TenantGenerationTransitionOutcome.UNKNOWN:
            if self.generation is not None:
                raise TenantTargetAdapterError("unknown transition invented a generation")
        elif self.generation is None:
            raise TenantTargetAdapterError("settled transition lacks its generation")


class TenantGenerationCleanupOutcome(str, Enum):
    CLEANED = "cleaned"
    NOT_CLEANED = "not_cleaned"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class TenantGenerationCleanupIntent:
    operation_id: str
    fixture_digest: str
    expected_config_digest: str
    prior: TenantGenerationExpectation

    def __post_init__(self) -> None:
        if (
            not isinstance(self.operation_id, str)
            or _CLEANUP_OPERATION.fullmatch(self.operation_id) is None
        ):
            raise TenantTargetAdapterError("target cleanup operation is invalid")
        _digest(self.fixture_digest, "cleanup fixture")
        _digest(self.expected_config_digest, "cleanup config")

    @property
    def digest(self) -> str:
        return _safe_receipt(
            CLEANUP_SCHEMA,
            {
                "operation_id": self.operation_id,
                "fixture_digest": self.fixture_digest,
                "expected_config_digest": self.expected_config_digest,
                "prior_generation_digest": self.prior.digest,
            },
        )


@dataclass(frozen=True, slots=True)
class TenantGenerationCleanupResult:
    outcome: TenantGenerationCleanupOutcome
    prior_lifecycle_digest: str
    write_ahead_receipt_digest: str
    source_receipt_digest: str
    generation: TenantRunningGeneration | None = None
    cleaned_lifecycle: TenantLabLifecycleRecord | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, TenantGenerationCleanupOutcome):
            raise TenantTargetAdapterError("cleanup outcome is invalid")
        _digest(self.prior_lifecycle_digest, "cleanup prior lifecycle")
        _digest(self.write_ahead_receipt_digest, "cleanup write-ahead")
        _digest(self.source_receipt_digest, "cleanup source")
        if self.outcome is TenantGenerationCleanupOutcome.NOT_CLEANED:
            if self.generation is None or self.cleaned_lifecycle is not None:
                raise TenantTargetAdapterError("uncleaned result lacks its running generation")
        elif self.outcome is TenantGenerationCleanupOutcome.CLEANED:
            if (
                self.generation is not None
                or self.cleaned_lifecycle is None
                or self.cleaned_lifecycle.state is not LifecycleState.CLEANED
            ):
                raise TenantTargetAdapterError("cleaned result lacks verified lifecycle proof")
        elif self.generation is not None or self.cleaned_lifecycle is not None:
            raise TenantTargetAdapterError("cleanup result carries an impossible generation")


@dataclass(frozen=True, slots=True)
class TenantBoundAuditReceipt:
    """Non-secret durable binding for one protected target audit event."""

    request_id: str
    audit_row_digest: str
    source_identity: str
    source_admission_digest: str
    plan_digest: str
    lifecycle_digest: str
    liveness_receipt_digest: str
    run_id: str
    attempt_id: str
    packet_digest: str
    fixture_digest: str
    config_digest: str
    endpoint: LoopbackEndpoint
    ready_digest: str
    target_snapshot_id: str
    service_generation: str

    def __post_init__(self) -> None:
        if _REQUEST_ID.fullmatch(self.request_id) is None:
            raise TenantTargetAdapterError("bound audit request identity is invalid")
        if self.source_identity not in _SOURCE_IDENTITIES:
            raise TenantTargetAdapterError("bound audit source identity is invalid")
        for label, value in (
            ("bound audit row", self.audit_row_digest),
            ("bound audit admission", self.source_admission_digest),
            ("bound audit plan", self.plan_digest),
            ("bound audit lifecycle", self.lifecycle_digest),
            ("bound audit liveness", self.liveness_receipt_digest),
            ("bound audit packet", self.packet_digest),
            ("bound audit fixture", self.fixture_digest),
            ("bound audit config", self.config_digest),
            ("bound audit readiness", self.ready_digest),
        ):
            _digest(value, label)
        if self.endpoint.port == 0:
            raise TenantTargetAdapterError("bound audit endpoint is unresolved")

    @property
    def digest(self) -> str:
        return _safe_receipt(
            "bluefire.tenant-record-bound-audit.v1",
            {
                "request_id": self.request_id,
                "audit_row_digest": self.audit_row_digest,
                "source_identity": self.source_identity,
                "source_admission_digest": self.source_admission_digest,
                "plan_digest": self.plan_digest,
                "lifecycle_digest": self.lifecycle_digest,
                "liveness_receipt_digest": self.liveness_receipt_digest,
                "run_id": self.run_id,
                "attempt_id": self.attempt_id,
                "packet_digest": self.packet_digest,
                "fixture_digest": self.fixture_digest,
                "config_digest": self.config_digest,
                "endpoint": self.endpoint.to_dict(),
                "ready_digest": self.ready_digest,
                "target_snapshot_id": self.target_snapshot_id,
                "service_generation": self.service_generation,
            },
        )


class TenantLauncherGenerationSource(Protocol):
    """Trusted lifecycle owner, backed by the existing launcher/store.

    ``checked_running`` must perform a fresh backend custody/readiness check.
    ``transition`` and ``cleanup`` must durably persist the supplied intent
    before any stop, cleanup, prepare, or start effect.  A transition retains
    the old target audit before cleanup and never reuses the prior plan/run or
    attempt identity.  This port intentionally carries no paths, URLs,
    commands, provider token, or arbitrary packet bytes.
    """

    def checked_running(
        self, expected: TenantGenerationExpectation | None
    ) -> TenantRunningGeneration: ...

    def transition(
        self, intent: TenantGenerationTransitionIntent
    ) -> TenantGenerationTransitionResult: ...

    def cleanup(self, intent: TenantGenerationCleanupIntent) -> TenantGenerationCleanupResult: ...

    def retain_audit_binding(self, binding: TenantBoundAuditReceipt) -> str:
        """Durably and idempotently retain the binding before cleanup."""

        ...


@dataclass(frozen=True, slots=True)
class _FixedTargetRequest:
    route: TenantRoute
    protected_tenant_id: str
    record_id: str | None
    source_token: bytes = field(repr=False)
    timeout_seconds: float
    tenant_header: str | None = None
    session_token: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.route, TenantRoute)
            or _LAB_ID.fullmatch(self.protected_tenant_id) is None
            or type(self.source_token) is not bytes
            or not 32 <= len(self.source_token) <= 64
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0 < self.timeout_seconds <= REQUEST_TIMEOUT_SECONDS
        ):
            raise TenantTargetAdapterError("fixed target request is invalid")
        if self.route is TenantRoute.RECORD_LOOKUP:
            if not isinstance(self.record_id, str) or _LAB_ID.fullmatch(self.record_id) is None:
                raise TenantTargetAdapterError("fixed record request is invalid")
        elif self.record_id is not None:
            raise TenantTargetAdapterError("fixed export request is invalid")
        if (self.tenant_header is None) == (self.session_token is None):
            raise TenantTargetAdapterError("fixed target identity input is ambiguous")
        if self.tenant_header is not None and self.tenant_header != self.protected_tenant_id:
            raise TenantTargetAdapterError("fixed target assertion changed")
        if self.session_token is not None:
            _check_session_token(self.session_token)

    @property
    def target(self) -> str:
        if self.route is TenantRoute.RECORD_LOOKUP:
            if self.record_id is None:
                raise TenantTargetAdapterError("record mechanism lacks its exact record")
            return f"/records/{self.record_id}"
        if self.record_id is not None:
            raise TenantTargetAdapterError("export mechanism contains a record identity")
        return f"/exports?tenant={self.protected_tenant_id}"

    @property
    def headers(self) -> tuple[tuple[str, str], ...]:
        encoded = base64.urlsafe_b64encode(self.source_token).decode("ascii").rstrip("=")
        result = [("host", LOGICAL_AUTHORITY), (SOURCE_HEADER, encoded)]
        if self.tenant_header is not None:
            result.append(("x-bluefire-lab-tenant", self.tenant_header))
        if self.session_token is not None:
            result.append(("authorization", "BlueFireLab " + self.session_token))
        return tuple(result)


class TenantTargetTransport(Protocol):
    """Internal fixed request transport; it accepts no URL or command."""

    def request(
        self, endpoint: LoopbackEndpoint, request: _FixedTargetRequest
    ) -> TenantResponse: ...


class FixedTenantLoopbackTransport:
    """Bounded HTTP/1.1 transport for the fixed package-owned target child."""

    def __init__(self, *, timeout_seconds: float = REQUEST_TIMEOUT_SECONDS) -> None:
        if not isinstance(timeout_seconds, (int, float)) or not 0.1 <= timeout_seconds <= 10:
            raise TenantTargetAdapterError("target request timeout is invalid")
        self._timeout = float(timeout_seconds)

    def request(self, endpoint: LoopbackEndpoint, request: _FixedTargetRequest) -> TenantResponse:
        if endpoint.host not in {"127.0.0.1", "::1"} or not 1 <= endpoint.port <= 65535:
            raise TenantTargetAdapterError("target endpoint is not numeric loopback")
        timeout = min(self._timeout, request.timeout_seconds)
        if not 0 < timeout <= 10:
            raise TenantTargetAdapterError("target request deadline is invalid")
        connection = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=timeout)
        try:
            connection.putrequest("GET", request.target, skip_host=True, skip_accept_encoding=True)
            for name, value in request.headers:
                connection.putheader(name, value)
            connection.endheaders()
            wire = connection.getresponse()
            body = wire.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise TenantTargetAdapterError("target response exceeded its byte bound")
            headers: dict[str, str] = {}
            for raw_name, raw_value in wire.getheaders():
                name, value = raw_name.strip().lower(), raw_value.strip()
                if (
                    name not in _RESPONSE_HEADERS
                    or name in headers
                    or len(value) > MAX_RESPONSE_HEADER_VALUE_CHARS
                    or any(ord(character) < 32 or ord(character) == 127 for character in value)
                ):
                    raise TenantTargetAdapterError("target response headers are invalid")
                headers[name] = value
            if set(headers) != _RESPONSE_HEADERS:
                raise TenantTargetAdapterError("target response headers are incomplete")
            try:
                declared = int(headers["content-length"])
            except ValueError as exc:
                raise TenantTargetAdapterError("target response length is invalid") from exc
            if declared != len(body):
                raise TenantTargetAdapterError("target response length changed")
            return TenantResponse(status=wire.status, headers=headers, body=body)
        except TenantTargetAdapterError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            raise TenantTargetAdapterError("fixed target request failed") from exc
        finally:
            connection.close()


@dataclass(frozen=True, slots=True)
class _VerifiedGeneration:
    source: TenantRunningGeneration
    target_ready: TargetReadyReceipt
    generic_ready: ReadinessReceipt
    expectation: TenantGenerationExpectation


class TenantRecordLauncherTargetAdapter:
    """Production ``TenantRecordControllerTarget`` over one fixed lab child."""

    def __init__(
        self,
        *,
        scratch_root: Path,
        source: TenantLauncherGenerationSource,
        transport: TenantTargetTransport | None = None,
    ) -> None:
        try:
            root = scratch_root.resolve(strict=True)
        except OSError as exc:
            raise TenantTargetAdapterError("target scratch root is unavailable") from exc
        if not root.is_dir():
            raise TenantTargetAdapterError("target scratch root is invalid")
        try:
            with _PinnedPrivateDirectory(root, verify_permissions_only=True) as pinned_root:
                descriptor = pinned_root._require_descriptor()
                root_details = os.fstat(descriptor)
                root_identity = (root_details.st_dev, root_details.st_ino)
                root_mount_identity = _descriptor_mount_identity(descriptor)
        except Exception:
            raise TenantTargetAdapterError("target scratch root is not protected") from None
        self._root = root
        self._root_identity = root_identity
        self._root_mount_identity = root_mount_identity
        self._source = source
        self._transport = transport or FixedTenantLoopbackTransport()
        self._expected: TenantGenerationExpectation | None = None
        self._request_bindings: dict[str, tuple[str, str]] = {}
        self._seen_request_ids: set[str] = set()
        self._audit_bindings: dict[tuple[str, str], tuple[TenantBoundAuditReceipt, str]] = {}
        self._cleaned = False
        self._uncertain = False
        self._lock = threading.RLock()

    def current_config(self) -> TenantDefenseConfig | None:
        with self._lock:
            try:
                return self._checked_running().source.config
            except (TenantTargetAdapterError, OSError, ValueError):
                return None

    def audit_row(self, request_id: str) -> TenantAuditRow:
        if not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None:
            raise TenantTargetAdapterError("target audit request identity is invalid")
        with self._lock:
            generation = self._checked_running()
            layout = WorkspaceLayout.for_run(self._root, generation.source.lifecycle.plan.run_id)
            raw = _stable_read(
                self._root,
                layout.target_audit,
                generation.target_ready.max_audit_bytes,
                root_identity=self._root_identity,
                root_mount_identity=self._root_mount_identity,
            )
            rows = _parse_audit(raw, generation.target_ready, generation.source.packet)
            matches = [row for row in rows if row.request_id == request_id]
            if len(matches) != 1:
                raise TenantTargetAdapterError("exact target audit row is unavailable")
            binding = self._request_bindings.get(request_id)
            if binding is not None and binding != (
                generation.expectation.digest,
                matches[0].source_identity,
            ):
                raise TenantTargetAdapterError("target audit request binding changed")
            self._checked_running(generation.expectation)
            bound = TenantBoundAuditReceipt(
                request_id=matches[0].request_id,
                audit_row_digest=matches[0].digest,
                source_identity=matches[0].source_identity,
                source_admission_digest=generation.source.admission(
                    matches[0].source_identity
                ).token_digest,
                plan_digest=generation.source.lifecycle.plan.digest,
                lifecycle_digest=generation.source.lifecycle.digest,
                liveness_receipt_digest=generation.source.liveness_receipt_digest,
                run_id=generation.source.lifecycle.plan.run_id,
                attempt_id=generation.source.lifecycle.plan.attempt_id,
                packet_digest=generation.source.packet.packet_digest,
                fixture_digest=generation.source.fixture.digest,
                config_digest=generation.source.config.digest,
                endpoint=generation.generic_ready.endpoint,
                ready_digest=generation.target_ready.ready_digest,
                target_snapshot_id=generation.target_ready.target_snapshot_id,
                service_generation=generation.target_ready.service_generation,
            )
            try:
                retention = self._source.retain_audit_binding(bound)
                _digest(retention, "bound audit retention")
            except Exception:
                raise TenantTargetAdapterError(
                    "target audit binding could not be retained"
                ) from None
            self._audit_bindings[(generation.expectation.digest, request_id)] = (
                bound,
                retention,
            )
            self._request_bindings.pop(request_id, None)
            return matches[0]

    def audit_binding(
        self, request_id: str, *, generation_digest: str
    ) -> tuple[TenantBoundAuditReceipt, str]:
        """Return the already-retained binding without re-reading target state."""

        with self._lock:
            _digest(generation_digest, "retained audit generation")
            try:
                return self._audit_bindings[(generation_digest, request_id)]
            except KeyError:
                raise TenantTargetAdapterError(
                    "retained target audit binding is unavailable"
                ) from None

    def controller_request(
        self,
        mechanism: TenantFailureMechanism,
        *,
        source_identity: str,
        session_token: str | None,
    ) -> TenantResponse:
        with self._lock:
            generation = self._checked_running()
            checked = _checked_mechanism(mechanism, generation.source.fixture)
            if source_identity not in {"controller_probe", "ordinary_user"}:
                raise TenantTargetAdapterError("controller request source is invalid")
            admission = generation.source.admission(source_identity)
            config = generation.source.config
            tenant_header: str | None = None
            if source_identity == "controller_probe":
                if session_token is not None:
                    raise TenantTargetAdapterError("probe request cannot carry a session")
                tenant_header = checked.protected_tenant_id
            elif config.mode != "signed_session":
                raise TenantTargetAdapterError("legitimate use requires the hardened target")
            else:
                _check_session_token(session_token)
            request = _FixedTargetRequest(
                route=checked.route,
                protected_tenant_id=checked.protected_tenant_id,
                record_id=checked.record_id,
                source_token=admission.token,
                timeout_seconds=min(
                    REQUEST_TIMEOUT_SECONDS, generation.source.packet.remaining_seconds
                ),
                tenant_header=tenant_header,
                session_token=session_token,
            )
            if (
                len(self._seen_request_ids) >= generation.target_ready.max_requests
                or len(self._request_bindings) >= generation.target_ready.max_requests
            ):
                raise TenantTargetAdapterError("target request binding limit reached")
            try:
                response = self._transport.request(generation.generic_ready.endpoint, request)
            except Exception:
                self._mark_unknown()
                receipt = _request_unknown_receipt(
                    generation, checked.request_digest, source_identity, "transport"
                )
                raise TenantTargetOperationUnknown(
                    "target request outcome is unknown", receipt_digest=receipt
                ) from None
            try:
                _check_response(response)
                request_id = response.headers.get("x-bluefire-lab-request")
                if (
                    not isinstance(request_id, str)
                    or _REQUEST_ID.fullmatch(request_id) is None
                    or request_id in self._seen_request_ids
                ):
                    raise TenantTargetAdapterError("target response request identity is invalid")
                self._checked_running(generation.expectation)
            except Exception:
                self._mark_unknown()
                receipt = _request_unknown_receipt(
                    generation,
                    checked.request_digest,
                    source_identity,
                    "response_postcheck",
                )
                raise TenantTargetOperationUnknown(
                    "target request postcondition is unknown", receipt_digest=receipt
                ) from None
            self._seen_request_ids.add(request_id)
            self._request_bindings[request_id] = (
                generation.expectation.digest,
                source_identity,
            )
            return response

    def apply_defense(self, plan: TenantDefensePlan) -> TenantTargetReadback:
        return self._transition(plan, direction="apply", operation_id=plan.operation_id)

    def rollback_defense(
        self, plan: TenantDefensePlan, *, operation_id: str
    ) -> TenantTargetReadback:
        return self._transition(plan, direction="rollback", operation_id=operation_id)

    def cleanup_lab(
        self,
        fixture: TenantRecordFixture,
        *,
        expected_config_digest: str,
        operation_id: str,
    ) -> TenantTargetCleanup:
        with self._lock:
            current = self._checked_running()
            if (
                fixture.digest != current.source.fixture.digest
                or expected_config_digest != current.source.config.digest
            ):
                raise TenantTargetAdapterError("target cleanup preimage changed")
            intent = TenantGenerationCleanupIntent(
                operation_id=operation_id,
                fixture_digest=fixture.digest,
                expected_config_digest=expected_config_digest,
                prior=current.expectation,
            )
            try:
                result = self._source.cleanup(intent)
                if not isinstance(result, TenantGenerationCleanupResult):
                    raise TenantTargetAdapterError("target cleanup result is invalid")
                if result.prior_lifecycle_digest != intent.prior.lifecycle_digest:
                    raise TenantTargetAdapterError("target cleanup CAS preimage changed")
                receipt = _cleanup_receipt(intent, result)
                if result.outcome is TenantGenerationCleanupOutcome.UNKNOWN:
                    self._mark_unknown()
                    raise TenantTargetOperationUnknown(
                        "target cleanup outcome is unknown", receipt_digest=receipt
                    )
                if result.outcome is TenantGenerationCleanupOutcome.CLEANED:
                    assert result.cleaned_lifecycle is not None
                    cleaned = result.cleaned_lifecycle
                    if (
                        cleaned.plan.digest != current.expectation.plan_digest
                        or cleaned.revision <= current.source.lifecycle.revision
                        or cleaned.prepared_at != current.source.lifecycle.prepared_at
                        or cleaned.reserved_at != current.source.lifecycle.reserved_at
                        or cleaned.running_at != current.source.lifecycle.running_at
                        or cleaned.children != current.source.lifecycle.children
                        or cleaned.readiness != current.source.lifecycle.readiness
                        or cleaned.cleanup_receipt is None
                        or cleaned.cleanup_receipt.plan_digest != current.expectation.plan_digest
                    ):
                        raise TenantTargetAdapterError("target cleanup lifecycle proof changed")
                    self._expected = None
                    self._cleaned = True
                    self._uncertain = False
                    self._request_bindings.clear()
                    self._seen_request_ids.clear()
                    return TenantTargetCleanup(verified_absent=True, receipt_digest=receipt)
                assert result.generation is not None
                unchanged = self._verify_snapshot(result.generation)
                if unchanged.expectation != current.expectation:
                    raise TenantTargetAdapterError("target cleanup changed the active generation")
                self._checked_running(unchanged.expectation)
                return TenantTargetCleanup(verified_absent=False, receipt_digest=receipt)
            except TenantTargetOperationUnknown:
                self._mark_unknown()
                raise
            except Exception:
                self._mark_unknown()
                receipt = _source_failure_receipt("cleanup", intent.digest)
                raise TenantTargetOperationUnknown(
                    "target cleanup outcome is unknown", receipt_digest=receipt
                ) from None

    def _transition(
        self, plan: TenantDefensePlan, *, direction: str, operation_id: str
    ) -> TenantTargetReadback:
        with self._lock:
            current = self._checked_running()
            desired = plan.after if direction == "apply" else plan.before
            prior = plan.before if direction == "apply" else plan.after
            if (
                current.source.fixture.digest != plan.fixture_digest
                or current.source.config != prior
            ):
                raise TenantTargetAdapterError("target transition preimage changed")
            intent = TenantGenerationTransitionIntent(
                direction=direction,
                operation_id=operation_id,
                defense_plan_digest=plan.digest,
                fixture_digest=plan.fixture_digest,
                prior=current.expectation,
                prior_config_digest=prior.digest,
                desired_config_digest=desired.digest,
            )
            try:
                result = self._source.transition(intent)
                if not isinstance(result, TenantGenerationTransitionResult):
                    raise TenantTargetAdapterError("target transition result is invalid")
                if result.prior_lifecycle_digest != intent.prior.lifecycle_digest:
                    raise TenantTargetAdapterError("target transition CAS preimage changed")
                receipt = _transition_receipt(intent, result)
                if result.outcome is TenantGenerationTransitionOutcome.UNKNOWN:
                    self._mark_unknown()
                    raise TenantTargetOperationUnknown(
                        "target transition outcome is unknown", receipt_digest=receipt
                    )
                assert result.generation is not None
                settled = self._verify_snapshot(result.generation)
                if result.outcome is TenantGenerationTransitionOutcome.NOT_CHANGED:
                    if settled.expectation != current.expectation or settled.source.config != prior:
                        raise TenantTargetAdapterError(
                            "target transition settlement is inconsistent"
                        )
                    self._checked_running(settled.expectation)
                    return TenantTargetReadback(
                        observed_config=settled.source.config,
                        receipt_digest=receipt,
                    )
                if (
                    settled.source.fixture.digest != current.source.fixture.digest
                    or settled.source.config != desired
                    or settled.source.lifecycle.plan.run_id == current.source.lifecycle.plan.run_id
                    or settled.source.lifecycle.plan.attempt_id
                    == current.source.lifecycle.plan.attempt_id
                    or settled.source.packet.packet_digest == current.source.packet.packet_digest
                    or settled.source.admission_digests == current.source.admission_digests
                    or settled.expectation == current.expectation
                ):
                    raise TenantTargetAdapterError("target transition settlement is inconsistent")
                self._expected = settled.expectation
                self._request_bindings.clear()
                self._seen_request_ids.clear()
                live = self._checked_running(settled.expectation)
                return TenantTargetReadback(
                    observed_config=live.source.config, receipt_digest=receipt
                )
            except TenantTargetOperationUnknown:
                self._mark_unknown()
                raise
            except Exception:
                self._mark_unknown()
                receipt = _source_failure_receipt(direction, intent.digest)
                raise TenantTargetOperationUnknown(
                    "target transition outcome is unknown", receipt_digest=receipt
                ) from None

    def _checked_running(
        self, expected: TenantGenerationExpectation | None = None
    ) -> _VerifiedGeneration:
        if self._cleaned:
            raise TenantTargetAdapterError("target lab is already cleaned")
        pinned = None if self._uncertain else (self._expected if expected is None else expected)
        try:
            source = self._source.checked_running(pinned)
            verified = self._verify_snapshot(source)
        except TenantTargetAdapterError:
            raise
        except Exception:
            raise TenantTargetAdapterError("target generation cannot be revalidated") from None
        if pinned is not None and verified.expectation != pinned:
            raise TenantTargetAdapterError("target generation changed")
        self._expected = verified.expectation
        self._uncertain = False
        return verified

    def _mark_unknown(self) -> None:
        self._expected = None
        self._uncertain = True
        self._request_bindings.clear()
        self._seen_request_ids.clear()

    def _verify_snapshot(self, source: TenantRunningGeneration) -> _VerifiedGeneration:
        record = source.lifecycle
        if record.state is not LifecycleState.RUNNING:
            raise TenantTargetAdapterError("target generation is not running")
        target_readiness = [item for item in record.readiness if item.role is ServiceRole.TARGET]
        target_children = [item for item in record.children if item.role is ServiceRole.TARGET]
        if len(target_readiness) != 1 or len(target_children) != 1:
            raise TenantTargetAdapterError("target launcher custody is incomplete")
        generic = target_readiness[0]
        child = target_children[0]
        planned = record.plan.target_endpoint
        if (
            planned.host != child.endpoint.host
            or planned.host != generic.endpoint.host
            or (planned.port != 0 and generic.endpoint != planned)
            or (generic.endpoint != child.endpoint and child.endpoint.port != 0)
        ):
            raise TenantTargetAdapterError("target launcher endpoint changed")
        layout = WorkspaceLayout.for_run(self._root, record.plan.run_id)
        raw_ready = _stable_read(
            self._root,
            layout.target_ready,
            16 * 1024,
            root_identity=self._root_identity,
            root_mount_identity=self._root_mount_identity,
        )
        try:
            ready = TargetReadyReceipt.from_bytes(raw_ready)
        except Exception as exc:
            raise TenantTargetAdapterError("target readiness receipt is invalid") from exc
        if (
            record.plan.target_packet_digest != ready.packet_digest
            or generic.endpoint.host != ready.host
            or generic.endpoint.port != ready.port
            or ready.fixture_digest != source.fixture.digest
            or ready.config_digest != source.config.digest
            or ready.target_snapshot_id != source.config.target_snapshot_id
            or ready.service_generation != source.config.service_generation
            or dict(ready.admission_digests) != source.admission_digests
            or ready.max_runtime_seconds > record.plan.max_runtime_seconds
            or ready.max_runtime_seconds != source.packet.max_runtime_seconds
            or ready.max_requests != source.packet.max_requests
            or ready.max_audit_events != source.packet.max_audit_events
            or ready.max_audit_bytes != source.packet.max_audit_bytes
            or ready.packet_digest != source.packet.packet_digest
            or ready.pid != child.pid
        ):
            raise TenantTargetAdapterError("target readiness changed its launch binding")
        try:
            created = parse_iso8601_datetime(source.packet.created_at)
            started = parse_iso8601_datetime(ready.started_at)
            expires = parse_iso8601_datetime(source.packet.expires_at)
            verified = parse_iso8601_datetime(source.packet.verified_at)
            child_started = parse_iso8601_datetime(child.started_at)
            generic_ready_at = parse_iso8601_datetime(generic.observed_at)
            running_at = parse_iso8601_datetime(cast(str, record.running_at))
        except ValueError as exc:
            raise TenantTargetAdapterError("target readiness time is invalid") from exc
        if not created <= child_started <= started < expires or verified < max(
            started, generic_ready_at, running_at
        ):
            raise TenantTargetAdapterError("target readiness is outside the packet lifetime")
        expectation = TenantGenerationExpectation(
            plan_digest=record.plan.digest,
            lifecycle_digest=record.digest,
            ready_digest=ready.ready_digest,
            target_snapshot_id=ready.target_snapshot_id,
            service_generation=ready.service_generation,
        )
        return _VerifiedGeneration(source, ready, generic, expectation)


def _checked_mechanism(
    mechanism: TenantFailureMechanism, fixture: TenantRecordFixture
) -> TenantFailureMechanism:
    if not isinstance(mechanism, TenantFailureMechanism):
        raise TenantTargetAdapterError("target mechanism is invalid")
    try:
        checked = TenantFailureMechanism(
            fixture_digest=mechanism.fixture_digest,
            original_target_snapshot_id=mechanism.original_target_snapshot_id,
            route=mechanism.route,
            protected_tenant_id=mechanism.protected_tenant_id,
            record_id=mechanism.record_id,
            request_digest=mechanism.request_digest,
        )
    except (TypeError, ValueError) as exc:
        raise TenantTargetAdapterError("target mechanism is invalid") from exc
    baseline = baseline_defense_config(fixture)
    protected_records = {
        record.record_id for record in fixture.records_for(fixture.protected_tenant_id)
    }
    if (
        checked.fixture_digest != fixture.digest
        or checked.original_target_snapshot_id != baseline.target_snapshot_id
        or checked.protected_tenant_id != fixture.protected_tenant_id
        or (
            checked.route is TenantRoute.RECORD_LOOKUP
            and checked.record_id not in protected_records
        )
    ):
        raise TenantTargetAdapterError("target mechanism belongs to another fixture")
    return checked


def _check_session_token(value: str | None) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_SESSION_TOKEN_CHARS
        or value != value.strip()
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise TenantTargetAdapterError("legitimate-use session is invalid")


def _check_response(response: TenantResponse) -> None:
    if (
        not isinstance(response, TenantResponse)
        or type(response.status) is not int
        or not 100 <= response.status <= 599
        or type(response.body) is not bytes
        or len(response.body) > MAX_RESPONSE_BYTES
    ):
        raise TenantTargetAdapterError("target response is invalid")
    normalized: dict[str, str] = {}
    for raw_name, raw_value in response.headers.items():
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            raise TenantTargetAdapterError("target response headers are invalid")
        name, value = raw_name.strip().lower(), raw_value.strip()
        if (
            name in normalized
            or name not in _RESPONSE_HEADERS
            or len(value) > MAX_RESPONSE_HEADER_VALUE_CHARS
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise TenantTargetAdapterError("target response headers are invalid")
        normalized[name] = value
    if set(normalized) != _RESPONSE_HEADERS:
        raise TenantTargetAdapterError("target response headers are incomplete")
    if normalized != dict(response.headers):
        raise TenantTargetAdapterError("target response headers are not canonical")
    try:
        length = int(normalized["content-length"])
    except ValueError as exc:
        raise TenantTargetAdapterError("target response length is invalid") from exc
    if length != len(response.body):
        raise TenantTargetAdapterError("target response length changed")


def _parse_audit(
    value: bytes,
    ready: TargetReadyReceipt,
    packet: TenantTargetPacketBinding,
) -> tuple[TenantAuditRow, ...]:
    if not value or len(value) > ready.max_audit_bytes or not value.endswith(b"\n"):
        raise TenantTargetAdapterError("target audit is empty or incomplete")
    lines = value.splitlines(keepends=True)
    if not 1 <= len(lines) <= min(ready.max_audit_events, MAX_AUDIT_EVENTS):
        raise TenantTargetAdapterError("target audit event count is invalid")
    rows: list[TenantAuditRow] = []
    expected_fields = {
        "schema_version",
        "sequence",
        "request_id",
        "timestamp",
        "source_identity",
        "route",
        "requested_tenant",
        "authenticated_tenant",
        "response_status",
        "response_bytes",
        "response_sha256",
        "response_headers_sha256",
        "returned_record_ids",
        "returned_record_digests",
        "decision",
        "target_snapshot_id",
        "service_generation",
    }
    for index, line in enumerate(lines, start=1):
        try:
            decoded = json.loads(line)
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise TenantTargetAdapterError("target audit contains invalid JSON") from exc
        if (
            not isinstance(decoded, Mapping)
            or set(decoded) != expected_fields
            or decoded.get("schema_version") != AUDIT_SCHEMA
            or canonical_json_bytes(decoded) + b"\n" != line
        ):
            raise TenantTargetAdapterError("target audit row is not canonical")
        ids = decoded["returned_record_ids"]
        digests = decoded["returned_record_digests"]
        if not isinstance(ids, list) or not isinstance(digests, list):
            raise TenantTargetAdapterError("target audit record bindings are invalid")
        try:
            row = TenantAuditRow(
                sequence=cast(int, decoded["sequence"]),
                request_id=cast(str, decoded["request_id"]),
                timestamp=cast(str, decoded["timestamp"]),
                source_identity=cast(str, decoded["source_identity"]),
                route=cast(str, decoded["route"]),
                requested_tenant=cast(str | None, decoded["requested_tenant"]),
                authenticated_tenant=cast(str | None, decoded["authenticated_tenant"]),
                response_status=cast(int, decoded["response_status"]),
                response_bytes=cast(int, decoded["response_bytes"]),
                response_sha256=cast(str, decoded["response_sha256"]),
                response_headers_sha256=cast(str, decoded["response_headers_sha256"]),
                returned_record_ids=tuple(cast(Sequence[str], ids)),
                returned_record_digests=tuple(cast(Sequence[str], digests)),
                decision=cast(str, decoded["decision"]),
                target_snapshot_id=cast(str, decoded["target_snapshot_id"]),
                service_generation=cast(str, decoded["service_generation"]),
            )
        except (TypeError, ValueError) as exc:
            raise TenantTargetAdapterError("target audit row is invalid") from exc
        if (
            row.sequence != index
            or row.source_identity not in _SOURCE_IDENTITIES
            or row.target_snapshot_id != ready.target_snapshot_id
            or row.service_generation != ready.service_generation
            or any(existing.request_id == row.request_id for existing in rows)
        ):
            raise TenantTargetAdapterError("target audit sequence or generation changed")
        try:
            observed = parse_iso8601_datetime(row.timestamp)
            created = parse_iso8601_datetime(packet.created_at)
            expires = parse_iso8601_datetime(packet.expires_at)
        except ValueError as exc:
            raise TenantTargetAdapterError("target audit time is invalid") from exc
        started = parse_iso8601_datetime(ready.started_at)
        if not max(created, started) <= observed <= expires:
            raise TenantTargetAdapterError("target audit is outside the packet lifetime")
        rows.append(row)
    return tuple(rows)


def _stable_read(
    root: Path,
    path: Path,
    maximum: int,
    *,
    root_identity: tuple[int, int],
    root_mount_identity: int | None,
) -> bytes:
    if type(maximum) is not int or maximum < 1:
        raise TenantTargetAdapterError("protected file bound is invalid")
    try:
        target = path.parent
        run_root = target.parent
        if (
            not root.is_absolute()
            or not path.is_absolute()
            or run_root.parent != root
            or target.parent != run_root
            or target.name != "target"
            or path.parent != target
            or path.name not in {"ready.json", "audit.jsonl"}
        ):
            raise TenantTargetAdapterError("protected target file path is invalid")
        with _PinnedPrivateDirectory(
            root,
            expected_identity=root_identity,
            expected_mount_identity=root_mount_identity,
            verify_permissions_only=True,
        ) as pinned_root:
            with _PinnedPrivateDirectory(
                run_root,
                parent=pinned_root,
                verify_permissions_only=True,
            ) as pinned_run:
                with _PinnedPrivateDirectory(
                    target,
                    parent=pinned_run,
                    verify_permissions_only=True,
                ) as pinned_target:
                    value = pinned_target.read(
                        path.name,
                        maximum=maximum,
                        apply_permissions=False,
                    )
        if not value:
            raise TenantTargetAdapterError("protected target file is empty")
        return cast(bytes, value)
    except TenantTargetAdapterError:
        raise
    except Exception:
        raise TenantTargetAdapterError("protected target file is unavailable") from None


def _request_unknown_receipt(
    generation: _VerifiedGeneration,
    request_digest: str,
    source_identity: str,
    stage: str,
) -> str:
    return _safe_receipt(
        "bluefire.tenant-record-request-unknown.v1",
        {
            "generation_digest": generation.expectation.digest,
            "liveness_receipt_digest": generation.source.liveness_receipt_digest,
            "plan_digest": generation.source.lifecycle.plan.digest,
            "run_id": generation.source.lifecycle.plan.run_id,
            "attempt_id": generation.source.lifecycle.plan.attempt_id,
            "request_digest": request_digest,
            "source_identity": source_identity,
            "stage": stage,
        },
    )


def _source_failure_receipt(operation: str, intent_digest: str) -> str:
    return _safe_receipt(
        "bluefire.tenant-record-source-failure.v1",
        {"operation": operation, "intent_digest": intent_digest, "outcome": "unknown"},
    )


def _transition_receipt(
    intent: TenantGenerationTransitionIntent,
    result: TenantGenerationTransitionResult,
) -> str:
    generation_digest = None
    if result.generation is not None:
        generation_digest = result.generation.lifecycle.digest
    return _safe_receipt(
        "bluefire.tenant-record-transition-receipt.v1",
        {
            "intent_digest": intent.digest,
            "outcome": result.outcome.value,
            "prior_lifecycle_digest": result.prior_lifecycle_digest,
            "write_ahead_receipt_digest": result.write_ahead_receipt_digest,
            "source_receipt_digest": result.source_receipt_digest,
            "result_lifecycle_digest": generation_digest,
        },
    )


def _cleanup_receipt(
    intent: TenantGenerationCleanupIntent,
    result: TenantGenerationCleanupResult,
) -> str:
    generation_digest = None
    if result.generation is not None:
        generation_digest = result.generation.lifecycle.digest
    elif result.cleaned_lifecycle is not None:
        generation_digest = result.cleaned_lifecycle.digest
    return _safe_receipt(
        "bluefire.tenant-record-cleanup-receipt.v1",
        {
            "intent_digest": intent.digest,
            "outcome": result.outcome.value,
            "prior_lifecycle_digest": result.prior_lifecycle_digest,
            "write_ahead_receipt_digest": result.write_ahead_receipt_digest,
            "source_receipt_digest": result.source_receipt_digest,
            "result_lifecycle_digest": generation_digest,
        },
    )


__all__ = [
    "FixedTenantLoopbackTransport",
    "TenantBoundAuditReceipt",
    "TenantControllerAdmission",
    "TenantGenerationCleanupIntent",
    "TenantGenerationCleanupOutcome",
    "TenantGenerationCleanupResult",
    "TenantGenerationExpectation",
    "TenantGenerationTransitionIntent",
    "TenantGenerationTransitionOutcome",
    "TenantGenerationTransitionResult",
    "TenantLauncherGenerationSource",
    "TenantRecordLauncherTargetAdapter",
    "TenantRunningGeneration",
    "TenantTargetAdapterError",
    "TenantTargetPacketBinding",
    "TenantTargetTransport",
]
