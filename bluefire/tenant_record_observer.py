"""Protected target-side observations for the generated tenant-record lab."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from datetime import timezone
from typing import Any, Callable, Mapping, cast

from .evidence import EvidenceProvenance, EvidenceRecord
from .tenant_record_lab import TenantDefenseConfig, TenantRecordFixture
from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

AUDIT_SCHEMA = "bluefire.tenant-record-audit.v1"
OBSERVATION_SCHEMA = "bluefire.tenant-record-observation.v1"
OBSERVER_ID = "observer.tenant-record-target.v1"
MAX_AUDIT_EVENTS = 256
MAX_RESPONSE_BYTES = 64 * 1024
MAX_RESPONSE_HEADER_VALUE_CHARS = 8192

_RESPONSE_HEADER_NAMES = frozenset(
    {
        "content-type",
        "content-length",
        "cache-control",
        "x-content-type-options",
        "x-bluefire-lab-request",
    }
)

_REQUEST_ID = re.compile(r"request-[0-9a-f]{24}")
_IDENTITY = re.compile(r"[a-z][a-z0-9_-]{2,63}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class TenantRecordObservationError(ValueError):
    """Raised when target-side evidence is missing, inconsistent or unbounded."""


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class TenantAuditRow:
    sequence: int
    request_id: str
    timestamp: str
    source_identity: str
    route: str
    requested_tenant: str | None
    authenticated_tenant: str | None
    response_status: int
    response_bytes: int
    response_sha256: str
    response_headers_sha256: str
    returned_record_ids: tuple[str, ...]
    returned_record_digests: tuple[str, ...]
    decision: str
    target_snapshot_id: str
    service_generation: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or not 1 <= self.sequence <= MAX_AUDIT_EVENTS:
            raise TenantRecordObservationError("audit sequence is out of bounds")
        if _REQUEST_ID.fullmatch(self.request_id) is None:
            raise TenantRecordObservationError("audit request identity is invalid")
        if _IDENTITY.fullmatch(self.source_identity) is None:
            raise TenantRecordObservationError("audit source identity is invalid")
        try:
            timestamp = parse_iso8601_datetime(self.timestamp)
        except (AttributeError, TypeError, ValueError) as exc:
            raise TenantRecordObservationError("audit timestamp is invalid") from exc
        if not self.timestamp.endswith("Z") or timestamp.utcoffset() != timezone.utc.utcoffset(
            timestamp
        ):
            raise TenantRecordObservationError("audit timestamp is invalid")
        if self.route not in {"record_lookup", "bounded_export", "metadata", "health", "unknown"}:
            raise TenantRecordObservationError("audit route is invalid")
        if any(
            value is not None and (not isinstance(value, str) or _IDENTITY.fullmatch(value) is None)
            for value in (self.requested_tenant, self.authenticated_tenant)
        ):
            raise TenantRecordObservationError("audit tenant identity is invalid")
        if any(
            not isinstance(value, str) or _IDENTITY.fullmatch(value) is None
            for value in (self.target_snapshot_id, self.service_generation)
        ):
            raise TenantRecordObservationError("audit target identity is invalid")
        if self.decision not in {
            "allowed_client_asserted",
            "allowed_signed_session",
            "public_health",
            "public_metadata",
            "denied_missing_session",
            "denied_invalid_session",
            "denied_identity_mismatch",
            "not_found",
            "invalid_request",
        }:
            raise TenantRecordObservationError("audit decision is invalid")
        if type(self.response_status) is not int or not 100 <= self.response_status <= 599:
            raise TenantRecordObservationError("audit response status is invalid")
        if (
            type(self.response_bytes) is not int
            or not 0 <= self.response_bytes <= MAX_RESPONSE_BYTES
        ):
            raise TenantRecordObservationError("audit response byte count is invalid")
        if _DIGEST.fullmatch(self.response_sha256) is None:
            raise TenantRecordObservationError("audit response digest is invalid")
        if _DIGEST.fullmatch(self.response_headers_sha256) is None:
            raise TenantRecordObservationError("audit response header digest is invalid")
        if len(self.returned_record_ids) != len(self.returned_record_digests):
            raise TenantRecordObservationError("audit record bindings are incomplete")
        if len(self.returned_record_ids) > 16 or len(set(self.returned_record_ids)) != len(
            self.returned_record_ids
        ):
            raise TenantRecordObservationError("audit record bindings are invalid")
        if any(_IDENTITY.fullmatch(value) is None for value in self.returned_record_ids):
            raise TenantRecordObservationError("audit record identity is invalid")
        if any(_DIGEST.fullmatch(digest) is None for digest in self.returned_record_digests):
            raise TenantRecordObservationError("audit record digest is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": AUDIT_SCHEMA,
            "sequence": self.sequence,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "source_identity": self.source_identity,
            "route": self.route,
            "requested_tenant": self.requested_tenant,
            "authenticated_tenant": self.authenticated_tenant,
            "response_status": self.response_status,
            "response_bytes": self.response_bytes,
            "response_sha256": self.response_sha256,
            "response_headers_sha256": self.response_headers_sha256,
            "returned_record_ids": list(self.returned_record_ids),
            "returned_record_digests": list(self.returned_record_digests),
            "decision": self.decision,
            "target_snapshot_id": self.target_snapshot_id,
            "service_generation": self.service_generation,
        }

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


class BoundedTenantAuditLog:
    """Controller-owned append-only in-memory sink for one service generation."""

    def __init__(self, *, max_events: int = MAX_AUDIT_EVENTS) -> None:
        if type(max_events) is not int or not 1 <= max_events <= MAX_AUDIT_EVENTS:
            raise TenantRecordObservationError("audit event limit is invalid")
        self._max_events = max_events
        self._rows: list[TenantAuditRow] = []
        self._lock = threading.Lock()

    def append(self, row: TenantAuditRow) -> None:
        with self._lock:
            expected = len(self._rows) + 1
            if len(self._rows) >= self._max_events:
                raise TenantRecordObservationError("audit event limit reached")
            if row.sequence != expected or any(
                item.request_id == row.request_id for item in self._rows
            ):
                raise TenantRecordObservationError("audit row is not the next unique event")
            self._rows.append(row)

    def append_factory(self, factory: Callable[[int], TenantAuditRow]) -> TenantAuditRow:
        """Allocate the sequence and append while holding one lock."""

        with self._lock:
            if len(self._rows) >= self._max_events:
                raise TenantRecordObservationError("audit event limit reached")
            sequence = len(self._rows) + 1
            row = factory(sequence)
            if row.sequence != sequence or any(
                item.request_id == row.request_id for item in self._rows
            ):
                raise TenantRecordObservationError("audit row is not the next unique event")
            self._rows.append(row)
            return row

    def row(self, request_id: str) -> TenantAuditRow:
        with self._lock:
            matches = [row for row in self._rows if row.request_id == request_id]
        if len(matches) != 1:
            raise TenantRecordObservationError("exact target audit row is unavailable")
        return matches[0]

    def snapshot(self) -> tuple[TenantAuditRow, ...]:
        with self._lock:
            return tuple(self._rows)


def _records_from_body(body: bytes, fixture: TenantRecordFixture) -> tuple[tuple[str, str], ...]:
    if len(body) > MAX_RESPONSE_BYTES:
        raise TenantRecordObservationError("observed response is oversized")
    try:
        payload = json.loads(body)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return ()
    if not isinstance(payload, Mapping):
        return ()
    records = payload.get("records")
    if not isinstance(records, list) or len(records) > 16:
        return ()
    expected = {record.record_id: record for record in fixture.records}
    result: list[tuple[str, str]] = []
    for value in records:
        if not isinstance(value, Mapping):
            raise TenantRecordObservationError("observed response record is invalid")
        record_id = value.get("record_id")
        record = expected.get(record_id) if isinstance(record_id, str) else None
        if record is None or canonical_json_bytes(value) != canonical_json_bytes(record.to_dict()):
            raise TenantRecordObservationError(
                "observed response record does not match generated data"
            )
        result.append((record.record_id, record.digest))
    if len({item[0] for item in result}) != len(result):
        raise TenantRecordObservationError("observed response repeats a record")
    return tuple(result)


def _response_headers_digest(headers: Mapping[str, str]) -> str:
    """Hash the complete bounded application response-header set canonically."""

    normalized: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            raise TenantRecordObservationError("observed response headers are invalid")
        name = raw_name.strip().lower()
        value = raw_value.strip()
        if (
            not name
            or name in normalized
            or len(value) > MAX_RESPONSE_HEADER_VALUE_CHARS
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise TenantRecordObservationError("observed response headers are invalid")
        normalized[name] = value
    if set(normalized) != _RESPONSE_HEADER_NAMES:
        raise TenantRecordObservationError("observed response headers are incomplete")
    return _sha256(canonical_json_bytes(normalized))


def _tenant_classification(
    fixture: TenantRecordFixture,
    *,
    requested_tenant: str | None,
    authenticated_tenant: str | None,
) -> str:
    if requested_tenant == authenticated_tenant == fixture.protected_tenant_id:
        return "protected_authenticated"
    if requested_tenant == authenticated_tenant == fixture.probe_tenant_id:
        return "probe_authenticated"
    if requested_tenant == fixture.protected_tenant_id and authenticated_tenant is None:
        return "protected_requested_unauthenticated"
    if requested_tenant == fixture.probe_tenant_id and authenticated_tenant is None:
        return "probe_requested_unauthenticated"
    if requested_tenant is not None and authenticated_tenant is not None:
        return "cross_tenant_mismatch"
    return "unresolved"


def observe_tenant_response(
    *,
    fixture: TenantRecordFixture,
    config: TenantDefenseConfig,
    audit_row: TenantAuditRow,
    response_status: int,
    response_headers: Mapping[str, str],
    response_body: bytes,
    attempt_id: str,
    run_id: str,
    step_id: str,
    target_scope_ref: str,
) -> EvidenceRecord:
    """Bind one client response to the independently retained target audit row."""

    if (
        not isinstance(attempt_id, str)
        or not 1 <= len(attempt_id) <= 160
        or any(ord(character) < 33 or ord(character) == 127 for character in attempt_id)
    ):
        raise TenantRecordObservationError("attempt identity is invalid")
    if config.fixture_digest != fixture.digest:
        raise TenantRecordObservationError(
            "observation fixture does not match the target configuration"
        )
    if (
        audit_row.target_snapshot_id != config.target_snapshot_id
        or audit_row.service_generation != config.service_generation
    ):
        raise TenantRecordObservationError("audit row belongs to a different target generation")
    if response_status != audit_row.response_status:
        raise TenantRecordObservationError("client and target response status disagree")
    response_headers_sha256 = _response_headers_digest(response_headers)
    if response_headers_sha256 != audit_row.response_headers_sha256:
        raise TenantRecordObservationError("client and target response headers disagree")
    request_headers = {name.strip().lower(): value for name, value in response_headers.items()}
    if request_headers["x-bluefire-lab-request"] != audit_row.request_id:
        raise TenantRecordObservationError(
            "client response has no matching target request identity"
        )
    if (
        len(response_body) != audit_row.response_bytes
        or _sha256(response_body) != audit_row.response_sha256
    ):
        raise TenantRecordObservationError("client and target response bytes disagree")
    bindings = _records_from_body(response_body, fixture) if response_status == 200 else ()
    if (
        tuple(item[0] for item in bindings) != audit_row.returned_record_ids
        or tuple(item[1] for item in bindings) != audit_row.returned_record_digests
    ):
        raise TenantRecordObservationError("client and target record bindings disagree")
    protected_ids = {
        record.record_id for record in fixture.records_for(fixture.protected_tenant_id)
    }
    protected_returned = tuple(
        record_id for record_id, _digest in bindings if record_id in protected_ids
    )
    if audit_row.source_identity == "engine_worker" and protected_returned:
        assessment = "unauthorized_disclosure"
    elif audit_row.source_identity == "ordinary_user" and protected_returned:
        assessment = "legitimate_use_succeeded"
    elif response_status in {401, 403} and not bindings:
        assessment = "authorization_denied"
    elif not protected_returned:
        assessment = "no_protected_effect"
    else:
        assessment = "unknown"
    content = {
        "schema_version": OBSERVATION_SCHEMA,
        "attempt_id": attempt_id,
        "request_id": audit_row.request_id,
        "target_snapshot_id": config.target_snapshot_id,
        "service_generation": config.service_generation,
        "source_identity": audit_row.source_identity,
        "route": audit_row.route,
        "decision": audit_row.decision,
        "response_status": response_status,
        "response_bytes": len(response_body),
        "response_sha256": _sha256(response_body),
        "response_headers_sha256": response_headers_sha256,
        "requested_tenant": audit_row.requested_tenant,
        "authenticated_tenant": audit_row.authenticated_tenant,
        "tenant_classification": _tenant_classification(
            fixture,
            requested_tenant=audit_row.requested_tenant,
            authenticated_tenant=audit_row.authenticated_tenant,
        ),
        "returned_record_ids": [item[0] for item in bindings],
        "returned_record_digests": [item[1] for item in bindings],
        "protected_record_ids": list(protected_returned),
        "assessment": assessment,
        "audit_row_digest": audit_row.digest,
        "independent_observation": True,
        "engine_assertion": False,
    }
    return EvidenceRecord.create(
        run_id=run_id,
        step_id=step_id,
        behavior_id="tenant_record_authorization_boundary",
        provenance=EvidenceProvenance.OBSERVED,
        producer=OBSERVER_ID,
        content=content,
        target_scope_ref=target_scope_ref,
        environment={
            "fixture_digest": fixture.digest,
            "target_snapshot_id": config.target_snapshot_id,
            "service_generation": config.service_generation,
        },
        confidence=1.0,
        limitations=(
            "The observer establishes this bounded HTTP response and target event only.",
            "A denied request does not prove that no other route remains.",
        ),
        timestamp=audit_row.timestamp,
    )


def checked_observation_content(record: EvidenceRecord) -> Mapping[str, Any]:
    """Return a verified observation body for comparison projections."""

    checked = EvidenceRecord.from_mapping(record.to_dict())
    content = checked.content
    fields = {
        "schema_version",
        "attempt_id",
        "request_id",
        "target_snapshot_id",
        "service_generation",
        "source_identity",
        "route",
        "decision",
        "response_status",
        "response_bytes",
        "response_sha256",
        "response_headers_sha256",
        "requested_tenant",
        "authenticated_tenant",
        "tenant_classification",
        "returned_record_ids",
        "returned_record_digests",
        "protected_record_ids",
        "assessment",
        "audit_row_digest",
        "independent_observation",
        "engine_assertion",
    }
    if (
        checked.provenance is not EvidenceProvenance.OBSERVED
        or checked.producer != OBSERVER_ID
        or set(content) != fields
        or content.get("schema_version") != OBSERVATION_SCHEMA
        or content.get("independent_observation") is not True
        or content.get("engine_assertion") is not False
    ):
        raise TenantRecordObservationError("record is not a tenant target observation")
    assessment = content.get("assessment")
    if assessment not in {
        "unauthorized_disclosure",
        "legitimate_use_succeeded",
        "authorization_denied",
        "no_protected_effect",
        "unknown",
    }:
        raise TenantRecordObservationError("tenant observation assessment is invalid")
    tenant_classification = content.get("tenant_classification")
    if tenant_classification not in {
        "protected_authenticated",
        "probe_authenticated",
        "protected_requested_unauthenticated",
        "probe_requested_unauthenticated",
        "cross_tenant_mismatch",
        "unresolved",
    }:
        raise TenantRecordObservationError("tenant observation classification is invalid")
    for field in ("requested_tenant", "authenticated_tenant"):
        tenant = content.get(field)
        if tenant is not None and (
            not isinstance(tenant, str) or _IDENTITY.fullmatch(tenant) is None
        ):
            raise TenantRecordObservationError("tenant observation identity is invalid")
    requested_tenant = content.get("requested_tenant")
    authenticated_tenant = content.get("authenticated_tenant")
    if (
        (
            tenant_classification in {"protected_authenticated", "probe_authenticated"}
            and (
                requested_tenant is None
                or authenticated_tenant is None
                or requested_tenant != authenticated_tenant
            )
        )
        or (
            tenant_classification
            in {"protected_requested_unauthenticated", "probe_requested_unauthenticated"}
            and (requested_tenant is None or authenticated_tenant is not None)
        )
        or (
            tenant_classification == "cross_tenant_mismatch"
            and (
                requested_tenant is None
                or authenticated_tenant is None
                or requested_tenant == authenticated_tenant
            )
        )
        or (
            tenant_classification == "unresolved"
            and (
                (requested_tenant is not None and authenticated_tenant is None)
                or (
                    requested_tenant is not None
                    and authenticated_tenant is not None
                    and requested_tenant != authenticated_tenant
                )
            )
        )
    ):
        raise TenantRecordObservationError("tenant observation classification is inconsistent")
    returned = content.get("returned_record_ids")
    digests = content.get("returned_record_digests")
    protected = content.get("protected_record_ids")
    if (
        not isinstance(returned, list)
        or not isinstance(digests, list)
        or not isinstance(protected, list)
        or len(returned) != len(digests)
        or len(returned) > 16
        or not set(protected) <= set(returned)
        or any(not isinstance(item, str) for item in returned + protected)
        or any(not isinstance(item, str) or _DIGEST.fullmatch(item) is None for item in digests)
    ):
        raise TenantRecordObservationError("tenant observation record bindings are invalid")
    if assessment in {"unauthorized_disclosure", "legitimate_use_succeeded"} and not protected:
        raise TenantRecordObservationError("tenant observation effect has no protected records")
    if assessment in {"authorization_denied", "no_protected_effect"} and protected:
        raise TenantRecordObservationError("tenant observation assessment contradicts its records")
    if (
        type(content.get("response_status")) is not int
        or not 100 <= int(content["response_status"]) <= 599
        or type(content.get("response_bytes")) is not int
        or not 0 <= int(content["response_bytes"]) <= MAX_RESPONSE_BYTES
        or not isinstance(content.get("response_sha256"), str)
        or _DIGEST.fullmatch(str(content["response_sha256"])) is None
        or not isinstance(content.get("response_headers_sha256"), str)
        or _DIGEST.fullmatch(str(content["response_headers_sha256"])) is None
        or not isinstance(content.get("audit_row_digest"), str)
        or _DIGEST.fullmatch(str(content["audit_row_digest"])) is None
    ):
        raise TenantRecordObservationError("tenant observation response binding is invalid")
    return cast(Mapping[str, Any], content)
