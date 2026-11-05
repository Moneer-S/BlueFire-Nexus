"""Pure tenant-record operation, review, and target-result contracts.

Application coordinators, persistence validators, and native target adapters
share these identities and closed values without acquiring each other's effects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, cast

from .tenant_record_lab import TenantDefenseConfig, TenantRecordFixture
from .tenant_record_observer import TenantAuditRow
from .util import content_hash, json_clone, parse_iso8601_datetime

SCHEMA_PLAN = "bluefire.tenant-record-defense-plan.v1"
SCHEMA_REVIEW = "bluefire.tenant-record-defense-review.v1"
SCHEMA_MUTATION = "bluefire.tenant-record-defense-settlement.v1"
SCHEMA_MECHANISM = "bluefire.tenant-record-failure-mechanism.v1"
SCHEMA_ENGINE_OBSERVATION = "bluefire.tenant-record-engine-observation.v1"
SCHEMA_CHECK = "bluefire.tenant-record-controller-check.v1"
SCHEMA_DISPOSITION = "bluefire.tenant-record-disposition.v1"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_CHECK_ID = re.compile(r"^controller-check-[0-9a-f]{32}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_OPERATION_ID = re.compile(r"^tenant-(?:defense|rollback|cleanup)-[0-9a-f]{32}$")
_ACTOR = re.compile(r"^[a-z][a-z0-9-]{7,63}$")
_LAB_ID = re.compile(r"^[a-z][a-z0-9-]{7,63}$")


class TenantRecordControllerError(ValueError):
    """Raised when the trusted controller contract is inconsistent."""


class TenantTargetOperationUnknown(RuntimeError):
    """Raised by a trusted target adapter after persisting an uncertain result."""

    def __init__(self, message: str, *, receipt_digest: str) -> None:
        super().__init__(message)
        self.receipt_digest = _digest(receipt_digest, "unknown target operation receipt")


class ControllerCheckRole(str, Enum):
    RETAINED_REPRODUCER = "retained_reproducer"
    LEGITIMATE_USE = "legitimate_use"


class TenantRoute(str, Enum):
    RECORD_LOOKUP = "record_lookup"
    BOUNDED_EXPORT = "bounded_export"


class MutationState(str, Enum):
    APPLIED = "applied"
    NOT_APPLIED = "not_applied"
    ROLLED_BACK = "rolled_back"
    NOT_ROLLED_BACK = "not_rolled_back"
    UNKNOWN = "unknown"


class LabDisposition(str, Enum):
    RETAINED_HARDENING = "retained_hardening"
    CLEANED = "cleaned"
    UNKNOWN = "unknown"


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TenantRecordControllerError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 40:
        raise TenantRecordControllerError(f"{label} is invalid")
    try:
        parsed = parse_iso8601_datetime(value)
    except ValueError as exc:
        raise TenantRecordControllerError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise TenantRecordControllerError(f"{label} must include a timezone")
    return value


def _checked_config(value: TenantDefenseConfig) -> TenantDefenseConfig:
    raw = value.to_dict() if isinstance(value, TenantDefenseConfig) else None
    if not isinstance(raw, Mapping) or set(raw) != {
        "schema_version",
        "mode",
        "fixture_digest",
        "target_snapshot_id",
        "service_generation",
        "application_nonce",
        "session_key_id",
        "session_key_digest",
    }:
        raise TenantRecordControllerError("target configuration is invalid")
    if raw["schema_version"] != "bluefire.tenant-record-defense-config.v1":
        raise TenantRecordControllerError("target configuration schema is unsupported")
    try:
        checked = TenantDefenseConfig(
            mode=cast(str, raw["mode"]),
            fixture_digest=cast(str, raw["fixture_digest"]),
            target_snapshot_id=cast(str, raw["target_snapshot_id"]),
            service_generation=cast(str, raw["service_generation"]),
            application_nonce=cast(str | None, raw["application_nonce"]),
            session_key_id=cast(str | None, raw["session_key_id"]),
            session_key_digest=cast(str | None, raw["session_key_digest"]),
        )
    except (TypeError, ValueError) as exc:
        raise TenantRecordControllerError("target configuration is invalid") from exc
    if checked.to_dict() != json_clone(raw):
        raise TenantRecordControllerError("target configuration is not canonical")
    return checked


def tenant_target_snapshot_ref(
    *,
    fixture_digest: str,
    target_snapshot_id: str,
    service_generation: str,
) -> str:
    """Build the exact digest used by an engine attempt before it is launched."""

    if (
        not isinstance(target_snapshot_id, str)
        or _LAB_ID.fullmatch(target_snapshot_id) is None
        or not isinstance(service_generation, str)
        or _LAB_ID.fullmatch(service_generation) is None
    ):
        raise TenantRecordControllerError("target snapshot identity is invalid")
    return cast(
        str,
        content_hash(
            {
                "schema_version": "bluefire.tenant-record-target-snapshot-ref.v1",
                "fixture_digest": _digest(fixture_digest, "target snapshot fixture"),
                "target_snapshot_id": target_snapshot_id,
                "service_generation": service_generation,
            }
        ),
    )


def _defense_review_binding(
    before: TenantDefenseConfig,
    after: TenantDefenseConfig,
    *,
    responsible_actor: str,
    reviewed_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_REVIEW,
        "preimage_digest": before.digest,
        "approved_configuration_digest": after.digest,
        "responsible_actor": responsible_actor,
        "reviewed_at": reviewed_at,
        "claims_application": False,
    }


@dataclass(frozen=True, slots=True)
class TenantFailureMechanism:
    fixture_digest: str
    original_target_snapshot_id: str
    route: TenantRoute
    protected_tenant_id: str
    record_id: str | None
    request_digest: str

    def __post_init__(self) -> None:
        _digest(self.fixture_digest, "failure mechanism fixture")
        _digest(self.request_digest, "failure mechanism request")
        if (
            not isinstance(self.original_target_snapshot_id, str)
            or _LAB_ID.fullmatch(self.original_target_snapshot_id) is None
        ):
            raise TenantRecordControllerError("failure mechanism target snapshot is invalid")
        if (
            not isinstance(self.protected_tenant_id, str)
            or _LAB_ID.fullmatch(self.protected_tenant_id) is None
        ):
            raise TenantRecordControllerError("failure mechanism tenant is invalid")
        if not isinstance(self.route, TenantRoute):
            raise TenantRecordControllerError("failure mechanism route is invalid")
        if self.route is TenantRoute.RECORD_LOOKUP:
            if not isinstance(self.record_id, str) or _LAB_ID.fullmatch(self.record_id) is None:
                raise TenantRecordControllerError("record lookup requires the exact record")
        elif self.record_id is not None:
            raise TenantRecordControllerError("bounded export cannot carry a record identity")
        if self.request_digest != content_hash(self.request_binding()):
            raise TenantRecordControllerError("failure mechanism request digest is inconsistent")

    @classmethod
    def from_baseline_audit(
        cls,
        fixture: TenantRecordFixture,
        config: TenantDefenseConfig,
        row: TenantAuditRow,
    ) -> "TenantFailureMechanism":
        checked = _checked_config(config)
        protected = {
            record.record_id for record in fixture.records_for(fixture.protected_tenant_id)
        }
        if (
            checked.mode != "client_asserted"
            or checked.fixture_digest != fixture.digest
            or row.target_snapshot_id != checked.target_snapshot_id
            or row.service_generation != checked.service_generation
            or row.source_identity != "engine_worker"
            or row.decision != "allowed_client_asserted"
            or row.response_status != 200
            or row.requested_tenant != fixture.protected_tenant_id
            or row.authenticated_tenant != fixture.protected_tenant_id
            or not row.returned_record_ids
            or not set(row.returned_record_ids) <= protected
        ):
            raise TenantRecordControllerError(
                "baseline audit does not establish the protected failure mechanism"
            )
        try:
            route = TenantRoute(row.route)
        except ValueError as exc:
            raise TenantRecordControllerError(
                "baseline route is not a supported mechanism"
            ) from exc
        record_id: str | None = None
        if route is TenantRoute.RECORD_LOOKUP:
            if len(row.returned_record_ids) != 1:
                raise TenantRecordControllerError("record lookup did not bind one exact record")
            record_id = row.returned_record_ids[0]
        binding = cls._request_binding(
            fixture.digest,
            checked.target_snapshot_id,
            route,
            fixture.protected_tenant_id,
            record_id,
        )
        return cls(
            fixture_digest=fixture.digest,
            original_target_snapshot_id=checked.target_snapshot_id,
            route=route,
            protected_tenant_id=fixture.protected_tenant_id,
            record_id=record_id,
            request_digest=content_hash(binding),
        )

    @staticmethod
    def _request_binding(
        fixture_digest: str,
        target_snapshot_id: str,
        route: TenantRoute,
        protected_tenant_id: str,
        record_id: str | None,
    ) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_MECHANISM,
            "method": "GET",
            "host": "tenant-record.test",
            "fixture_digest": fixture_digest,
            "original_target_snapshot_id": target_snapshot_id,
            "route": route.value,
            "protected_tenant_id": protected_tenant_id,
            "record_id": record_id,
            "identity_input": "client_asserted_tenant_header",
        }

    def request_binding(self) -> dict[str, Any]:
        return self._request_binding(
            self.fixture_digest,
            self.original_target_snapshot_id,
            self.route,
            self.protected_tenant_id,
            self.record_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {**self.request_binding(), "request_digest": self.request_digest}


@dataclass(frozen=True, slots=True)
class TenantDefensePlan:
    operation_id: str
    fixture_digest: str
    before: TenantDefenseConfig
    after: TenantDefenseConfig
    review_id: str
    review_digest: str
    responsible_actor: str
    planned_at: str

    def __post_init__(self) -> None:
        if _OPERATION_ID.fullmatch(self.operation_id) is None or not self.operation_id.startswith(
            "tenant-defense-"
        ):
            raise TenantRecordControllerError("defense operation identity is invalid")
        _digest(self.fixture_digest, "defense fixture")
        _digest(self.review_digest, "defense review")
        before, after = _checked_config(self.before), _checked_config(self.after)
        if (
            before.mode != "client_asserted"
            or after.mode != "signed_session"
            or before.fixture_digest != after.fixture_digest
            or self.fixture_digest != before.fixture_digest
        ):
            raise TenantRecordControllerError("defense plan does not bind baseline to hardening")
        if not isinstance(self.review_id, str) or not self.review_id.startswith("review-"):
            raise TenantRecordControllerError("defense review identity is invalid")
        if _ACTOR.fullmatch(self.responsible_actor) is None:
            raise TenantRecordControllerError("defense actor is invalid")
        _timestamp(self.planned_at, "defense plan time")
        review = _defense_review_binding(
            before,
            after,
            responsible_actor=self.responsible_actor,
            reviewed_at=self.planned_at,
        )
        if (
            self.review_id != "review-" + content_hash(review).removeprefix("sha256:")[:20]
            or content_hash(review) != self.review_digest
        ):
            raise TenantRecordControllerError("defense review binding is inconsistent")

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_PLAN,
            "operation_id": self.operation_id,
            "fixture_digest": self.fixture_digest,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "review_id": self.review_id,
            "review_digest": self.review_digest,
            "responsible_actor": self.responsible_actor,
            "planned_at": self.planned_at,
        }


@dataclass(frozen=True, slots=True)
class TenantTargetReadback:
    """Target-controller result; ``None`` means the current state is unknown."""

    observed_config: TenantDefenseConfig | None
    receipt_digest: str

    def __post_init__(self) -> None:
        _digest(self.receipt_digest, "target operation receipt")
        if self.observed_config is not None:
            _checked_config(self.observed_config)


@dataclass(frozen=True, slots=True)
class TenantTargetCleanup:
    verified_absent: bool
    receipt_digest: str

    def __post_init__(self) -> None:
        if type(self.verified_absent) is not bool:
            raise TenantRecordControllerError("target cleanup result is invalid")
        _digest(self.receipt_digest, "target cleanup receipt")
