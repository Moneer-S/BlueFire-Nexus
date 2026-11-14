"""Immutable Strix admission identities, evidence records, and owner ports.

These contracts describe retained authority and receipts without coordinating
resource allocation or persistence.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace
from typing import Literal, Protocol

from .util import content_hash, parse_iso8601_datetime

State = Literal["reserved", "preparing", "verified", "unknown", "revoked", "cleaned"]
RESOURCE_KINDS = (
    "scope",
    "gateway",
    "network_plan",
    "network_snapshot",
    "network_verification",
    "custody_plan",
    "protected_roots",
    "containment",
    "runtime_install",
    "workspace",
    "executable",
    "path_environment",
    "control_root",
    "artifact_root",
    "source_root_custody",
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRANSITIONS: dict[str, set[str]] = {
    "reserved": {"preparing", "revoked"},
    "preparing": {"preparing", "verified", "unknown", "revoked"},
    "verified": {"unknown", "revoked", "cleaned"},
    "unknown": {"verified", "revoked", "cleaned"},
    "revoked": {"cleaned"},
    "cleaned": set(),
}


class StrixAdmissionIssuanceError(RuntimeError):
    """Exact controller authority or protected resource evidence is unavailable."""


class StrixAdmissionIssuanceConflict(StrixAdmissionIssuanceError):
    """A durable compare-and-swap or immutable request identity changed."""


def _digest(value: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise StrixAdmissionIssuanceError("invalid opaque digest")


def _timestamp(value: str) -> None:
    try:
        parsed = parse_iso8601_datetime(value)
        if parsed.isoformat().replace("+00:00", "Z") != value:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise StrixAdmissionIssuanceError("invalid canonical UTC timestamp") from exc


@dataclass(frozen=True, slots=True)
class StrixIssuanceHead:
    """Exact active authority, installed build, qualification and experiment head."""

    authority_ref: str
    authority_generation: int
    authority_record_digest: str
    build_digest: str
    qualification_ref: str
    experiment_id: str
    experiment_revision: int
    experiment_digest: str
    active: bool

    def validate(self) -> None:
        for name in (
            "authority_ref",
            "authority_record_digest",
            "build_digest",
            "qualification_ref",
            "experiment_digest",
        ):
            _digest(getattr(self, name))
        if (
            type(self.authority_generation) is not int
            or self.authority_generation < 1
            or type(self.experiment_revision) is not int
            or self.experiment_revision < 1
            or not isinstance(self.experiment_id, str)
            or re.fullmatch(r"experiment-[0-9a-f]{32}", self.experiment_id) is None
            or type(self.active) is not bool
        ):
            raise StrixAdmissionIssuanceError("invalid issuance authority head")


@dataclass(frozen=True, slots=True)
class ServerResolvedStrixAdmissionRequest:
    """Exact v19 server resolution; never construct this from browser resource refs.

    The injected source independently reopens this entire identity. The scope,
    gateway, budgets and limits digests bind the server's policy, not locations.
    A retry uses a fresh attempt ID and fresh retained preparation identity.
    """

    attempt_id: str
    candidate_ref: str
    preparation_ref: str
    binding_digest: str
    delegation_digest: str
    objective_ref: str
    environment_ref: str
    target_snapshot_digest: str
    scope_digest: str
    gateway_digest: str
    budgets_digest: str
    limits_digest: str
    head: StrixIssuanceHead
    created_at: str
    expires_at: str

    def validate(self) -> None:
        if (
            not isinstance(self.attempt_id, str)
            or re.fullmatch(r"engine-attempt-[0-9a-f]{32}", self.attempt_id) is None
        ):
            raise StrixAdmissionIssuanceError("invalid immutable attempt ID")
        for name in (
            "candidate_ref",
            "preparation_ref",
            "binding_digest",
            "delegation_digest",
            "objective_ref",
            "environment_ref",
            "target_snapshot_digest",
            "scope_digest",
            "gateway_digest",
            "budgets_digest",
            "limits_digest",
        ):
            _digest(getattr(self, name))
        if not isinstance(self.head, StrixIssuanceHead):
            raise StrixAdmissionIssuanceError("invalid issuance head")
        self.head.validate()
        _timestamp(self.created_at)
        _timestamp(self.expires_at)
        if parse_iso8601_datetime(self.created_at) >= parse_iso8601_datetime(self.expires_at):
            raise StrixAdmissionIssuanceError("invalid reservation lifetime")

    @property
    def request_digest(self) -> str:
        self.validate()
        return content_hash(
            {"schema_version": "bluefire.strix-issuance-request.v1", **asdict(self)}
        )


@dataclass(frozen=True, slots=True)
class StrixPreAdmissionProfile:
    """Cycle-free binding fixed before any resource allocation."""

    request: ServerResolvedStrixAdmissionRequest
    reservation_ref: str

    @property
    def profile_digest(self) -> str:
        expected = content_hash(
            {
                "schema_version": "bluefire.strix-issuance-reservation.v1",
                "attempt_id": self.request.attempt_id,
                "request_digest": self.request.request_digest,
            }
        )
        if self.reservation_ref != expected:
            raise StrixAdmissionIssuanceError("reservation identity changed")
        return content_hash(
            {
                "schema_version": "bluefire.strix-pre-admission-profile.v1",
                "reservation_ref": self.reservation_ref,
                "request_digest": self.request.request_digest,
            }
        )


@dataclass(frozen=True, slots=True)
class StrixResourceReceipt:
    kind: str
    resource_ref: str
    receipt_digest: str
    profile_digest: str

    def validate(self, profile: StrixPreAdmissionProfile) -> None:
        if self.kind not in RESOURCE_KINDS or self.profile_digest != profile.profile_digest:
            raise StrixAdmissionIssuanceError("resource profile binding changed")
        for value in (self.resource_ref, self.receipt_digest, self.profile_digest):
            _digest(value)


@dataclass(frozen=True, slots=True)
class StrixAbsenceReceipt:
    """Protected absence/rollback proof, including allocations lost before return."""

    kind: str
    profile_digest: str
    receipt_digest: str


@dataclass(frozen=True, slots=True)
class StrixReconciliationEvidence:
    """Complete protected inventory and optional independently checked absence."""

    profile_digest: str
    inventory_digest: str
    resources: tuple[StrixResourceReceipt, ...]
    absence: tuple[StrixAbsenceReceipt, ...] = ()

    def validate(self, profile: StrixPreAdmissionProfile) -> None:
        if (
            self.profile_digest != profile.profile_digest
            or not isinstance(self.resources, tuple)
            or not isinstance(self.absence, tuple)
        ):
            raise StrixAdmissionIssuanceError("invalid immutable reconciliation evidence")
        _digest(self.inventory_digest)
        for resource in self.resources:
            resource.validate(profile)
        for absence in self.absence:
            if (
                absence.kind not in RESOURCE_KINDS
                or absence.profile_digest != profile.profile_digest
            ):
                raise StrixAdmissionIssuanceError("resource absence profile binding changed")
            _digest(absence.receipt_digest)


@dataclass(frozen=True, slots=True)
class StrixIssuanceRecord:
    profile: StrixPreAdmissionProfile
    state: State
    sequence: int
    previous_digest: str | None
    resources: tuple[StrixResourceReceipt, ...]
    pending_kind: str | None
    record_digest: str
    reconciliation_evidence: StrixReconciliationEvidence | None = None

    def validate(self) -> None:
        _ = self.profile.profile_digest
        if (
            self.state not in _TRANSITIONS
            or type(self.sequence) is not int
            or self.sequence < 1
            or (self.sequence == 1) != (self.previous_digest is None)
            or (self.sequence == 1 and self.state != "reserved")
            or (self.pending_kind is not None and self.pending_kind not in RESOURCE_KINDS)
            or not isinstance(self.resources, tuple)
        ):
            raise StrixAdmissionIssuanceError("invalid issuance lifecycle")
        if self.previous_digest is not None:
            _digest(self.previous_digest)
        seen: set[str] = set()
        refs: set[str] = set()
        for receipt in self.resources:
            receipt.validate(self.profile)
            if receipt.kind in seen or receipt.resource_ref in refs:
                raise StrixAdmissionIssuanceError("duplicate issuance resource")
            seen.add(receipt.kind)
            refs.add(receipt.resource_ref)
        if self.state == "verified" and (seen != set(RESOURCE_KINDS) or self.pending_kind):
            raise StrixAdmissionIssuanceError("verified issuance has incomplete resources")
        evidence = self.reconciliation_evidence
        if evidence is not None:
            evidence.validate(self.profile)
        if self.state == "cleaned" and (
            evidence is None
            or evidence.resources != self.resources
            or len(evidence.absence) != len(RESOURCE_KINDS)
            or {receipt.kind for receipt in evidence.absence} != set(RESOURCE_KINDS)
        ):
            raise StrixAdmissionIssuanceError("cleaned issuance lacks complete absence evidence")
        if self.record_digest != _record_digest(self):
            raise StrixAdmissionIssuanceError("issuance record integrity changed")


def _record_digest(record: StrixIssuanceRecord) -> str:
    document = asdict(record)
    document.pop("record_digest")
    return content_hash({"schema_version": "bluefire.strix-issuance-state.v1", **document})


def _sealed(record: StrixIssuanceRecord) -> StrixIssuanceRecord:
    result = replace(record, record_digest=_record_digest(record))
    result.validate()
    return result


class StrixIssuanceIdentitySource(Protocol):
    def reopen_exact(
        self, *, candidate_ref: str, preparation_ref: str
    ) -> ServerResolvedStrixAdmissionRequest | None: ...

    def read_current_head(
        self, request: ServerResolvedStrixAdmissionRequest
    ) -> StrixIssuanceHead: ...


class StrixIssuancePersistence(Protocol):
    """Private append-only storage with immutable reservation and atomic CAS.

    reserve returns the identical existing reservation or raises on conflict.
    It MUST check the active authority/experiment head atomically. CAS MUST
    validate the whole retained chain and request, transition, expected digest,
    and supplied active head atomically. No preparing CAS may have two winners.
    Lost acknowledgements are reconciled by read, never retried allocations.
    """

    def reserve(
        self, record: StrixIssuanceRecord, *, active_head: StrixIssuanceHead
    ) -> StrixIssuanceRecord: ...

    def read(self, attempt_id: str) -> StrixIssuanceRecord | None: ...

    def compare_and_swap(
        self,
        record: StrixIssuanceRecord,
        *,
        expected_digest: str,
        active_head: StrixIssuanceHead | None,
    ) -> StrixIssuanceRecord: ...

    def confirm_verified(
        self,
        *,
        attempt_id: str,
        expected_digest: str,
        active_head: StrixIssuanceHead,
    ) -> StrixIssuanceRecord:
        """Atomically recheck active head and exact verified lifecycle after callbacks.

        Return only the unchanged verified record, otherwise raise a conflict.
        This read guard never appends a lifecycle event or revives an attempt.
        """
        ...


class ProtectedStrixIssuanceRegistry(Protocol):
    """Protected owners allocate by profile only and durably inventory first.

    allocate must journal every potential allocation under the profile BEFORE
    effects, even if it later raises. No location or credential is returned.
    inspect is read-only, complete, and includes unacknowledged allocations.
    """

    def allocate(self, profile: StrixPreAdmissionProfile, *, kind: str) -> StrixResourceReceipt: ...

    def reopen_exact(self, receipt: StrixResourceReceipt) -> StrixResourceReceipt: ...

    def inspect(self, profile: StrixPreAdmissionProfile) -> StrixReconciliationEvidence: ...


class IndependentStrixIssuanceVerifier(Protocol):
    """Independently reopen protected owners; equality alone is insufficient.

    verify_resource checks all cross-resource and request bindings, including
    actual build/qualification, scope/model policy, delegation, isolation,
    custody, roots, containment and runtime/workspace/path/control identities.
    Source-root custody is prelaunch only, never a final collection seal.
    verify_inventory proves complete enumeration including interrupted calls.
    verify_absence proves rollback/absence for the entire kind/profile domain,
    including any unreturned or unrecorded allocations; an empty list is no proof.
    """

    def verify_resource(
        self,
        profile: StrixPreAdmissionProfile,
        receipt: StrixResourceReceipt,
        resources: tuple[StrixResourceReceipt, ...],
    ) -> bool: ...

    def verify_inventory(
        self, profile: StrixPreAdmissionProfile, evidence: StrixReconciliationEvidence
    ) -> bool: ...

    def verify_absence(
        self,
        profile: StrixPreAdmissionProfile,
        receipt: StrixAbsenceReceipt,
        evidence: StrixReconciliationEvidence,
    ) -> bool: ...
