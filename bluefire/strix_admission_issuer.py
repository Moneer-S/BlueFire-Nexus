"""Controller-private, effect-free orchestration of one Strix admission attempt.

Only injected protected owners persist or allocate. This module exposes no HTTP
projection, paths, credentials, process or network operations. Registry receipts
are opaque non-secret identities, not caller-provided resource locations. Source
root custody here is prelaunch identity; final collection sealing is settlement.
"""

from __future__ import annotations

from .strix_admission_contract import (
    _DIGEST as _DIGEST,
)
from .strix_admission_contract import (
    _TRANSITIONS as _TRANSITIONS,
)
from .strix_admission_contract import (
    RESOURCE_KINDS as RESOURCE_KINDS,
)
from .strix_admission_contract import (
    IndependentStrixIssuanceVerifier as IndependentStrixIssuanceVerifier,
)
from .strix_admission_contract import (
    ProtectedStrixIssuanceRegistry as ProtectedStrixIssuanceRegistry,
)
from .strix_admission_contract import (
    ServerResolvedStrixAdmissionRequest as ServerResolvedStrixAdmissionRequest,
)
from .strix_admission_contract import (
    State as State,
)
from .strix_admission_contract import (
    StrixAbsenceReceipt as StrixAbsenceReceipt,
)
from .strix_admission_contract import (
    StrixAdmissionIssuanceConflict as StrixAdmissionIssuanceConflict,
)
from .strix_admission_contract import (
    StrixAdmissionIssuanceError as StrixAdmissionIssuanceError,
)
from .strix_admission_contract import (
    StrixIssuanceHead as StrixIssuanceHead,
)
from .strix_admission_contract import (
    StrixIssuanceIdentitySource as StrixIssuanceIdentitySource,
)
from .strix_admission_contract import (
    StrixIssuancePersistence as StrixIssuancePersistence,
)
from .strix_admission_contract import (
    StrixIssuanceRecord as StrixIssuanceRecord,
)
from .strix_admission_contract import (
    StrixPreAdmissionProfile as StrixPreAdmissionProfile,
)
from .strix_admission_contract import (
    StrixReconciliationEvidence as StrixReconciliationEvidence,
)
from .strix_admission_contract import (
    StrixResourceReceipt as StrixResourceReceipt,
)
from .strix_admission_contract import (
    _digest as _digest,
)
from .strix_admission_contract import (
    _record_digest as _record_digest,
)
from .strix_admission_contract import (
    _sealed as _sealed,
)
from .strix_admission_contract import (
    _timestamp as _timestamp,
)
from .util import content_hash, parse_iso8601_datetime


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
