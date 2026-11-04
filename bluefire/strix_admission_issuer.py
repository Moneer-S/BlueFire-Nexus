"""Controller-private, effect-free orchestration of one Strix admission attempt.

Only injected protected owners persist or allocate. This module exposes no HTTP
projection, paths, credentials, process or network operations. Registry receipts
are opaque non-secret identities, not caller-provided resource locations. Source
root custody here is prelaunch identity; final collection sealing is settlement.
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


class ControllerPrivateStrixAdmissionIssuer:
    """Issue once; recover by inspection only. This is not a launch capability."""

    def __init__(
        self,
        *,
        identities: StrixIssuanceIdentitySource,
        persistence: StrixIssuancePersistence,
        registry: ProtectedStrixIssuanceRegistry,
        verifier: IndependentStrixIssuanceVerifier,
    ) -> None:
        self._identities = identities
        self._persistence = persistence
        self._registry = registry
        self._verifier = verifier

    def _exact_request(self, request: ServerResolvedStrixAdmissionRequest) -> None:
        if not isinstance(request, ServerResolvedStrixAdmissionRequest):
            raise StrixAdmissionIssuanceError("server-resolved request required")
        request.validate()
        resolved = self._identities.reopen_exact(
            candidate_ref=request.candidate_ref,
            preparation_ref=request.preparation_ref,
        )
        if resolved != request:
            raise StrixAdmissionIssuanceError("retained v19 candidate/preparation identity changed")

    def _active(self, request: ServerResolvedStrixAdmissionRequest, now: str) -> StrixIssuanceHead:
        self._exact_request(request)
        _timestamp(now)
        if not (
            parse_iso8601_datetime(request.created_at)
            <= parse_iso8601_datetime(now)
            < parse_iso8601_datetime(request.expires_at)
        ):
            raise StrixAdmissionIssuanceError("issuance reservation is outside its lifetime")
        head = self._identities.read_current_head(request)
        head.validate()
        if head != request.head or not head.active:
            raise StrixAdmissionIssuanceConflict("active issuance authority/head changed")
        return head

    def _read(self, attempt_id: str) -> StrixIssuanceRecord:
        record = self._persistence.read(attempt_id)
        if record is None:
            raise StrixAdmissionIssuanceError("issuance reservation is unavailable")
        record.validate()
        if record.profile.request.attempt_id != attempt_id:
            raise StrixAdmissionIssuanceError("issuance attempt identity changed")
        self._exact_request(record.profile.request)
        return record

    def reserve(
        self, request: ServerResolvedStrixAdmissionRequest, *, now: str
    ) -> StrixIssuanceRecord:
        head = self._active(request, now)
        profile = StrixPreAdmissionProfile(
            request,
            content_hash(
                {
                    "schema_version": "bluefire.strix-issuance-reservation.v1",
                    "attempt_id": request.attempt_id,
                    "request_digest": request.request_digest,
                }
            ),
        )
        initial = _sealed(StrixIssuanceRecord(profile, "reserved", 1, None, (), None, ""))
        retained = self._persistence.reserve(initial, active_head=head)
        retained.validate()
        if retained.profile != profile:
            raise StrixAdmissionIssuanceConflict("immutable reservation changed")
        return retained

    def _advance(
        self,
        previous: StrixIssuanceRecord,
        state: State,
        *,
        resources: tuple[StrixResourceReceipt, ...] | None = None,
        pending_kind: str | None = None,
        active_head: StrixIssuanceHead | None = None,
        reconciliation_evidence: StrixReconciliationEvidence | None = None,
    ) -> StrixIssuanceRecord:
        if state not in _TRANSITIONS[previous.state]:
            raise StrixAdmissionIssuanceConflict("issuance lifecycle transition is invalid")
        desired = _sealed(
            StrixIssuanceRecord(
                previous.profile,
                state,
                previous.sequence + 1,
                previous.record_digest,
                previous.resources if resources is None else resources,
                pending_kind,
                "",
                (
                    previous.reconciliation_evidence
                    if reconciliation_evidence is None
                    else reconciliation_evidence
                ),
            )
        )
        retained = self._persistence.compare_and_swap(
            desired,
            expected_digest=previous.record_digest,
            active_head=active_head,
        )
        retained.validate()
        if retained != desired:
            raise StrixAdmissionIssuanceConflict("issuance CAS returned a different record")
        return retained

    def _verify_resources(
        self,
        profile: StrixPreAdmissionProfile,
        resources: tuple[StrixResourceReceipt, ...],
    ) -> None:
        if len(resources) != len(RESOURCE_KINDS) or {r.kind for r in resources} != set(
            RESOURCE_KINDS
        ):
            raise StrixAdmissionIssuanceError("protected resource set is incomplete")
        if len({r.resource_ref for r in resources}) != len(resources):
            raise StrixAdmissionIssuanceError("protected resource identities overlap")
        for receipt in resources:
            receipt.validate(profile)
            reopened = self._registry.reopen_exact(receipt)
            if (
                reopened != receipt
                or self._verifier.verify_resource(profile, reopened, resources) is not True
            ):
                raise StrixAdmissionIssuanceError(
                    "independent resource binding verification failed"
                )

    def issue(
        self, request: ServerResolvedStrixAdmissionRequest, *, now: str
    ) -> StrixIssuanceRecord:
        self._exact_request(request)
        existing = self._persistence.read(request.attempt_id)
        record = (
            self.reserve(request, now=now) if existing is None else self._read(request.attempt_id)
        )
        if record.profile.request != request:
            raise StrixAdmissionIssuanceConflict("immutable reservation changed")
        if record.state != "reserved":
            # Re-entry and restart never replay preparing or unknown work.
            if record.state == "preparing":
                return self._advance(record, "unknown", pending_kind=record.pending_kind)
            if record.state == "verified":
                try:
                    self._active(request, now)
                    self._verify_resources(record.profile, record.resources)
                    confirmed = self._persistence.confirm_verified(
                        attempt_id=request.attempt_id,
                        expected_digest=record.record_digest,
                        active_head=self._active(request, now),
                    )
                    confirmed.validate()
                    if confirmed != record:
                        raise StrixAdmissionIssuanceConflict("verified lifecycle changed")
                except BaseException:
                    current = self._read(request.attempt_id)
                    if current.state == "verified":
                        self._advance(current, "unknown")
                    raise
            return record
        head = self._active(request, now)
        # Only the winner of this CAS is permitted to call allocate.
        record = self._advance(record, "preparing", active_head=head)
        try:
            for kind in RESOURCE_KINDS:
                head = self._active(request, now)
                record = self._advance(record, "preparing", pending_kind=kind, active_head=head)
                receipt = self._registry.allocate(record.profile, kind=kind)
                receipt.validate(record.profile)
                if receipt.kind != kind:
                    raise StrixAdmissionIssuanceError("registry returned the wrong resource kind")
                record = self._advance(
                    record,
                    "preparing",
                    resources=(*record.resources, receipt),
                    active_head=self._active(request, now),
                )
            self._verify_resources(record.profile, record.resources)
            return self._advance(record, "verified", active_head=self._active(request, now))
        except BaseException:
            # Cancellation and lost persistence acknowledgements are uncertain.
            # Read the committed head; never repeat the registry operation.
            current = self._read(request.attempt_id)
            if current.state in {"preparing", "verified"}:
                self._advance(current, "unknown", pending_kind=current.pending_kind)
            raise

    def interrupt(self, attempt_id: str, *, revoked: bool = False) -> StrixIssuanceRecord:
        record = self._read(attempt_id)
        if record.state == "cleaned" or (revoked and record.state == "revoked"):
            return record
        if revoked:
            return self._advance(record, "revoked", pending_kind=record.pending_kind)
        if record.state in {"preparing", "verified"}:
            return self._advance(record, "unknown", pending_kind=record.pending_kind)
        return record

    def reconcile(self, attempt_id: str, *, now: str) -> StrixIssuanceRecord:
        record = self._read(attempt_id)
        if record.state in {"reserved", "cleaned"}:
            return record
        if record.state in {"preparing", "verified"}:
            record = self._advance(record, "unknown", pending_kind=record.pending_kind)
        evidence = self._registry.inspect(record.profile)
        evidence.validate(record.profile)
        if self._verifier.verify_inventory(record.profile, evidence) is not True:
            raise StrixAdmissionIssuanceError("complete protected inventory is unproven")
        for resource in evidence.resources:
            resource.validate(record.profile)
        if len({r.kind for r in evidence.resources}) != len(evidence.resources):
            raise StrixAdmissionIssuanceError("duplicate reconciliation resource kind")
        # A complete inventory must retain every previously acknowledged receipt.
        if not set(record.resources).issubset(evidence.resources):
            raise StrixAdmissionIssuanceError("reconciliation lost an allocated resource")
        if evidence.absence:
            if len(evidence.absence) != len(RESOURCE_KINDS) or {
                r.kind for r in evidence.absence
            } != set(RESOURCE_KINDS):
                raise StrixAdmissionIssuanceError(
                    "absence receipts do not cover every resource kind"
                )
            for absence in evidence.absence:
                _digest(absence.receipt_digest)
                if (
                    absence.profile_digest != record.profile.profile_digest
                    or self._verifier.verify_absence(record.profile, absence, evidence) is not True
                ):
                    raise StrixAdmissionIssuanceError("independent resource absence is unproven")
            return self._advance(
                record,
                "cleaned",
                resources=evidence.resources,
                reconciliation_evidence=evidence,
            )
        if record.state == "revoked":
            return record
        if len(evidence.resources) != len(RESOURCE_KINDS):
            return record
        self._verify_resources(record.profile, evidence.resources)
        return self._advance(
            record,
            "verified",
            resources=evidence.resources,
            active_head=self._active(record.profile.request, now),
            reconciliation_evidence=evidence,
        )
