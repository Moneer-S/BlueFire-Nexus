from __future__ import annotations

from dataclasses import replace
from typing import Callable

import pytest

from bluefire.strix_admission_issuer import (
    RESOURCE_KINDS,
    ControllerPrivateStrixAdmissionIssuer,
    ServerResolvedStrixAdmissionRequest,
    StrixAbsenceReceipt,
    StrixAdmissionIssuanceConflict,
    StrixAdmissionIssuanceError,
    StrixIssuanceHead,
    StrixIssuanceRecord,
    StrixPreAdmissionProfile,
    StrixReconciliationEvidence,
    StrixResourceReceipt,
)
from bluefire.util import content_hash

NOW = "2026-11-04T12:00:00Z"
LATER = "2026-11-04T13:00:00Z"


def digest(label: str) -> str:
    return content_hash({"test_identity": label})


def request(attempt: str = "a") -> ServerResolvedStrixAdmissionRequest:
    return ServerResolvedStrixAdmissionRequest(
        attempt_id="engine-attempt-" + attempt * 32,
        candidate_ref=digest("candidate"),
        preparation_ref=digest("preparation-" + attempt),
        binding_digest=digest("binding-" + attempt),
        delegation_digest=digest("delegation"),
        objective_ref=digest("objective"),
        environment_ref=digest("environment"),
        target_snapshot_digest=digest("target"),
        scope_digest=digest("scope"),
        gateway_digest=digest("gateway"),
        budgets_digest=digest("budgets"),
        limits_digest=digest("limits"),
        created_at=NOW,
        expires_at=LATER,
        head=StrixIssuanceHead(
            authority_ref=digest("authority"),
            authority_generation=1,
            authority_record_digest=digest("authority-record"),
            build_digest=digest("build"),
            qualification_ref=digest("qualification"),
            experiment_id="experiment-" + "b" * 32,
            experiment_revision=1,
            experiment_digest=digest("experiment"),
            active=True,
        ),
    )


class Identities:
    def __init__(self, value: ServerResolvedStrixAdmissionRequest) -> None:
        self.requests = {(value.candidate_ref, value.preparation_ref): value}
        self.head = value.head

    def reopen_exact(self, *, candidate_ref: str, preparation_ref: str):
        return self.requests.get((candidate_ref, preparation_ref))

    def read_current_head(self, value: ServerResolvedStrixAdmissionRequest):
        return self.head


class Persistence:
    def __init__(self, identities: Identities) -> None:
        self.identities = identities
        self.records: dict[str, StrixIssuanceRecord] = {}
        self.history: list[StrixIssuanceRecord] = []
        self.before_cas: Callable[[], None] | None = None
        self.fail_ack: str | None = None

    def _head(self, active_head: StrixIssuanceHead | None) -> None:
        if active_head is not None and (
            active_head != self.identities.head or not active_head.active
        ):
            raise StrixAdmissionIssuanceConflict("atomic authority/head CAS failed")

    def reserve(self, record: StrixIssuanceRecord, *, active_head: StrixIssuanceHead):
        self._head(active_head)
        record.validate()
        attempt = record.profile.request.attempt_id
        existing = self.records.get(attempt)
        if existing:
            if existing.profile != record.profile:
                raise StrixAdmissionIssuanceConflict("immutable attempt collision")
            return existing
        self.records[attempt] = record
        self.history.append(record)
        return record

    def read(self, attempt_id: str):
        return self.records.get(attempt_id)

    def confirm_verified(self, *, attempt_id, expected_digest, active_head):
        self._head(active_head)
        record = self.records[attempt_id]
        record.validate()
        if record.record_digest != expected_digest or record.state != "verified":
            raise StrixAdmissionIssuanceConflict("verified lifecycle changed during verification")
        return record

    def compare_and_swap(
        self,
        record: StrixIssuanceRecord,
        *,
        expected_digest: str,
        active_head: StrixIssuanceHead | None,
    ):
        if self.before_cas:
            hook, self.before_cas = self.before_cas, None
            hook()
        self._head(active_head)
        attempt = record.profile.request.attempt_id
        previous = self.records[attempt]
        previous.validate()
        record.validate()
        if previous.record_digest != expected_digest:
            raise StrixAdmissionIssuanceConflict("atomic lifecycle CAS failed")
        if record.profile != previous.profile or record.sequence != previous.sequence + 1:
            raise StrixAdmissionIssuanceConflict("immutable lifecycle changed")
        self.records[attempt] = record
        self.history.append(record)
        if self.fail_ack == record.state:
            self.fail_ack = None
            raise OSError("commit acknowledgement lost")
        return record


class Registry:
    def __init__(self, persistence: Persistence) -> None:
        self.persistence = persistence
        self.allocations: list[StrixResourceReceipt] = []
        self.calls: list[str] = []
        self.fail_kind: str | None = None
        self.fail: BaseException = RuntimeError("allocation acknowledgement lost")
        self.after_allocate: Callable[[], None] | None = None
        self.reopen_tamper: str | None = None
        self.absent = False
        self.omit_absence: str | None = None
        self.omit_resource: str | None = None

    def allocate(self, profile: StrixPreAdmissionProfile, *, kind: str):
        saved = self.persistence.records[profile.request.attempt_id]
        assert saved.state == "preparing" and saved.pending_kind == kind
        assert saved.profile == profile
        self.calls.append(kind)
        receipt = StrixResourceReceipt(
            kind,
            digest(profile.profile_digest + kind + "ref"),
            digest(profile.profile_digest + kind + "receipt"),
            profile.profile_digest,
        )
        self.allocations.append(receipt)
        if self.after_allocate:
            hook, self.after_allocate = self.after_allocate, None
            hook()
        if self.fail_kind == kind:
            raise self.fail
        return receipt

    def reopen_exact(self, receipt: StrixResourceReceipt):
        if receipt.kind == self.reopen_tamper:
            return replace(receipt, receipt_digest=digest("tampered"))
        return next(r for r in self.allocations if r.resource_ref == receipt.resource_ref)

    def inspect(self, profile: StrixPreAdmissionProfile):
        resources = tuple(
            r
            for r in self.allocations
            if r.profile_digest == profile.profile_digest and r.kind != self.omit_resource
        )
        absence = (
            tuple(
                StrixAbsenceReceipt(kind, profile.profile_digest, digest("absence-" + kind))
                for kind in RESOURCE_KINDS
                if kind != self.omit_absence
            )
            if self.absent
            else ()
        )
        return StrixReconciliationEvidence(
            profile.profile_digest,
            digest("inventory"),
            resources,
            absence,
        )


class Verifier:
    def __init__(self, registry: Registry) -> None:
        self.registry = registry
        self.resource_checks: list[str] = []
        self.absence_checks: list[str] = []
        self.reject_kind: str | None = None
        self.inventory_ok = True
        self.absence_ok = True
        self.on_verify: Callable[[], None] | None = None

    def verify_resource(self, profile, receipt, resources):
        self.resource_checks.append(receipt.kind)
        if self.on_verify:
            hook, self.on_verify = self.on_verify, None
            hook()
        return (
            receipt in self.registry.allocations
            and receipt.kind != self.reject_kind
            and receipt.profile_digest == profile.profile_digest
            and {r.kind for r in resources} == set(RESOURCE_KINDS)
        )

    def verify_inventory(self, profile, evidence):
        return self.inventory_ok and set(evidence.resources) == {
            r for r in self.registry.allocations if r.profile_digest == profile.profile_digest
        }

    def verify_absence(self, profile, receipt, evidence):
        self.absence_checks.append(receipt.kind)
        return self.absence_ok and self.registry.absent


class Fixture:
    def __init__(self) -> None:
        self.request = request()
        self.identities = Identities(self.request)
        self.persistence = Persistence(self.identities)
        self.registry = Registry(self.persistence)
        self.verifier = Verifier(self.registry)
        self.issuer = self.restart()

    def restart(self):
        return ControllerPrivateStrixAdmissionIssuer(
            identities=self.identities,
            persistence=self.persistence,
            registry=self.registry,
            verifier=self.verifier,
        )

    @property
    def saved(self):
        return self.persistence.records[self.request.attempt_id]


@pytest.fixture
def f():
    return Fixture()


def test_exact_reservation_is_idempotent_and_precedes_every_allocation(f):
    reserved = f.issuer.reserve(f.request, now=NOW)
    assert f.issuer.reserve(f.request, now=NOW) == reserved
    assert not f.registry.calls
    saved = f.issuer.issue(f.request, now=NOW)
    assert saved.state == "verified"
    assert f.registry.calls == list(RESOURCE_KINDS)
    assert f.verifier.resource_checks == list(RESOURCE_KINDS)
    assert f.persistence.history[0] == reserved
    assert {r.profile_digest for r in saved.resources} == {reserved.profile.profile_digest}
    assert saved.record_digest != saved.profile.profile_digest
    assert f.issuer.issue(f.request, now=NOW) == saved
    assert f.registry.calls == list(RESOURCE_KINDS)


@pytest.mark.parametrize(
    "field",
    [
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
    ],
)
def test_browser_or_tampered_request_cannot_select_identity(f, field):
    changed = replace(f.request, **{field: digest("forged")})
    with pytest.raises(StrixAdmissionIssuanceError, match="v19"):
        f.issuer.issue(changed, now=NOW)
    assert not f.registry.calls and not f.persistence.records


def test_resource_refs_are_not_request_fields(f):
    with pytest.raises(TypeError):
        replace(f.request, workspace_ref=digest("browser-path"))
    with pytest.raises(StrixAdmissionIssuanceError):
        f.issuer.issue({}, now=NOW)


def test_same_attempt_different_server_preparation_is_conflict(f):
    f.issuer.reserve(f.request, now=NOW)
    changed = replace(f.request, preparation_ref=digest("new-preparation"))
    f.identities.requests[(changed.candidate_ref, changed.preparation_ref)] = changed
    with pytest.raises(StrixAdmissionIssuanceConflict):
        f.issuer.issue(changed, now=NOW)
    assert not f.registry.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("authority_generation", 2),
        ("authority_record_digest", digest("new-authority")),
        ("build_digest", digest("new-build")),
        ("qualification_ref", digest("new-qualification")),
        ("experiment_revision", 2),
        ("experiment_digest", digest("new-experiment")),
        ("active", False),
    ],
)
def test_stale_authority_build_qualification_or_experiment_prevents_reservation(f, field, value):
    f.identities.head = replace(f.identities.head, **{field: value})
    with pytest.raises(StrixAdmissionIssuanceConflict):
        f.issuer.issue(f.request, now=NOW)
    assert not f.registry.calls and not f.persistence.records


def test_expired_request_cannot_allocate(f):
    with pytest.raises(StrixAdmissionIssuanceError, match="lifetime"):
        f.issuer.issue(f.request, now=LATER)
    assert not f.registry.calls


def test_authority_change_between_check_and_cas_cannot_prepare(f):
    f.issuer.reserve(f.request, now=NOW)
    f.persistence.before_cas = lambda: setattr(
        f.identities, "head", replace(f.identities.head, authority_generation=2)
    )
    with pytest.raises(StrixAdmissionIssuanceConflict):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "reserved" and not f.registry.calls


def test_head_change_after_partial_allocation_becomes_unknown(f):
    f.registry.after_allocate = lambda: setattr(
        f.identities, "head", replace(f.identities.head, authority_generation=2)
    )
    with pytest.raises(StrixAdmissionIssuanceConflict):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "unknown"
    assert len(f.registry.allocations) == 1
    assert f.issuer.reconcile(f.request.attempt_id, now=NOW).state == "unknown"
    assert len(f.registry.calls) == 1


@pytest.mark.parametrize("kind", RESOURCE_KINDS)
def test_partial_allocation_failure_is_unknown_and_never_replayed(f, kind):
    f.registry.fail_kind = kind
    with pytest.raises(RuntimeError, match="acknowledgement"):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "unknown" and f.saved.pending_kind == kind
    calls = list(f.registry.calls)
    assert f.restart().issue(f.request, now=NOW).state == "unknown"
    if kind != RESOURCE_KINDS[-1]:
        assert f.restart().reconcile(f.request.attempt_id, now=NOW).state == "unknown"
    else:
        assert f.restart().reconcile(f.request.attempt_id, now=NOW).state == "verified"
    assert f.registry.calls == calls


def test_cancellation_is_unknown_and_recovery_never_allocates(f):
    f.registry.fail_kind = "workspace"
    f.registry.fail = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "unknown"
    count = len(f.registry.calls)
    assert f.restart().reconcile(f.request.attempt_id, now=NOW).state == "unknown"
    assert len(f.registry.calls) == count


def test_restart_of_preparing_marks_unknown_without_replay(f):
    f.persistence.fail_ack = "preparing"
    with pytest.raises(OSError):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "preparing" and not f.registry.calls
    assert f.restart().issue(f.request, now=NOW).state == "unknown"
    assert not f.registry.calls


def test_lost_verified_commit_ack_is_unknown_until_independent_reconciliation(f):
    f.persistence.fail_ack = "verified"
    with pytest.raises(OSError):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "unknown"
    calls = list(f.registry.calls)
    assert f.restart().reconcile(f.request.attempt_id, now=NOW).state == "verified"
    assert f.registry.calls == calls


@pytest.mark.parametrize("kind", RESOURCE_KINDS)
def test_independent_verifier_rejects_every_resource_binding(f, kind):
    f.verifier.reject_kind = kind
    with pytest.raises(StrixAdmissionIssuanceError, match="independent"):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "unknown"


def test_registry_reopen_tamper_is_rejected(f):
    f.registry.reopen_tamper = "containment"
    with pytest.raises(StrixAdmissionIssuanceError):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "unknown"


def test_persisted_record_tamper_is_rejected_before_recovery(f):
    f.issuer.reserve(f.request, now=NOW)
    f.persistence.records[f.request.attempt_id] = replace(f.saved, state="cleaned")
    with pytest.raises(StrixAdmissionIssuanceError):
        f.restart().reconcile(f.request.attempt_id, now=NOW)
    assert not f.registry.calls


def test_unknown_cleanup_requires_absence_for_every_possible_allocation(f):
    f.registry.fail_kind = "workspace"
    with pytest.raises(RuntimeError):
        f.issuer.issue(f.request, now=NOW)
    f.registry.absent = True
    f.registry.omit_absence = "source_root_custody"
    with pytest.raises(StrixAdmissionIssuanceError, match="every resource"):
        f.issuer.reconcile(f.request.attempt_id, now=NOW)
    assert f.saved.state == "unknown"
    f.registry.omit_absence = None
    f.verifier.absence_ok = False
    with pytest.raises(StrixAdmissionIssuanceError, match="absence"):
        f.issuer.reconcile(f.request.attempt_id, now=NOW)
    f.verifier.absence_ok = True
    cleaned = f.issuer.reconcile(f.request.attempt_id, now=LATER)
    assert cleaned.state == "cleaned"
    assert set(f.verifier.absence_checks) == set(RESOURCE_KINDS)
    calls = list(f.registry.calls)
    assert f.restart().issue(f.request, now=NOW) == cleaned
    assert f.registry.calls == calls


def test_empty_inventory_is_not_cleanup_evidence(f):
    f.persistence.fail_ack = "preparing"
    with pytest.raises(OSError):
        f.issuer.issue(f.request, now=NOW)
    assert f.issuer.reconcile(f.request.attempt_id, now=NOW).state == "unknown"


def test_inventory_omission_cannot_hide_unreturned_allocation(f):
    f.registry.fail_kind = "workspace"
    with pytest.raises(RuntimeError):
        f.issuer.issue(f.request, now=NOW)
    f.registry.omit_resource = "workspace"
    f.registry.absent = True
    with pytest.raises(StrixAdmissionIssuanceError, match="inventory"):
        f.issuer.reconcile(f.request.attempt_id, now=NOW)
    assert f.saved.state == "unknown"


def test_revoked_attempt_can_only_reconcile_cleanup(f):
    f.issuer.issue(f.request, now=NOW)
    revoked = f.issuer.interrupt(f.request.attempt_id, revoked=True)
    assert revoked.state == "revoked"
    assert f.restart().reconcile(f.request.attempt_id, now=NOW) == revoked
    f.registry.absent = True
    assert f.restart().reconcile(f.request.attempt_id, now=LATER).state == "cleaned"
    assert f.registry.calls == list(RESOURCE_KINDS)


def test_retry_requires_new_attempt_identity(f):
    f.registry.fail_kind = "workspace"
    with pytest.raises(RuntimeError):
        f.issuer.issue(f.request, now=NOW)
    assert f.restart().issue(f.request, now=NOW).state == "unknown"
    retry = request("c")
    f.identities.requests[(retry.candidate_ref, retry.preparation_ref)] = retry
    f.registry.fail_kind = None
    assert f.restart().issue(retry, now=NOW).state == "verified"
    assert f.saved.state == "unknown"


def test_source_root_is_prelaunch_custody_and_never_final_collection(f):
    saved = f.issuer.issue(f.request, now=NOW)
    assert "source_root_custody" in {r.kind for r in saved.resources}
    assert not any("seal" in kind or "collection" in kind for kind in RESOURCE_KINDS)


def test_restart_marks_preparing_unknown_even_after_authority_change_and_expiry(f):
    f.persistence.fail_ack = "preparing"
    with pytest.raises(OSError):
        f.issuer.issue(f.request, now=NOW)
    f.identities.head = replace(f.identities.head, active=False)
    assert f.restart().issue(f.request, now=LATER).state == "unknown"
    assert f.restart().issue(f.request, now=LATER).state == "unknown"
    assert not f.registry.calls


@pytest.mark.parametrize("stale_authority", [False, True])
def test_verified_reentry_failure_becomes_unknown(f, stale_authority):
    f.issuer.issue(f.request, now=NOW)
    if stale_authority:
        f.identities.head = replace(f.identities.head, active=False)
    else:
        f.verifier.reject_kind = "source_root_custody"
    with pytest.raises(StrixAdmissionIssuanceError):
        f.restart().issue(f.request, now=NOW)
    assert f.saved.state == "unknown"
    assert f.registry.calls == list(RESOURCE_KINDS)


def test_losing_preparing_cas_cannot_allocate(f):
    f.issuer.reserve(f.request, now=NOW)
    f.persistence.before_cas = lambda: f.issuer.interrupt(f.request.attempt_id, revoked=True)
    with pytest.raises(StrixAdmissionIssuanceConflict):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "revoked" and not f.registry.calls


def test_cleanup_retains_exact_inventory_and_absence_proofs(f):
    f.issuer.issue(f.request, now=NOW)
    f.issuer.interrupt(f.request.attempt_id)
    f.registry.absent = True
    cleaned = f.issuer.reconcile(f.request.attempt_id, now=NOW)
    evidence = cleaned.reconciliation_evidence
    assert evidence == f.registry.inspect(cleaned.profile)
    assert len(evidence.absence) == len(RESOURCE_KINDS)
    tampered = replace(cleaned, reconciliation_evidence=None)
    f.persistence.records[f.request.attempt_id] = tampered
    with pytest.raises(StrixAdmissionIssuanceError, match="absence"):
        f.restart().reconcile(f.request.attempt_id, now=NOW)


def test_forged_registry_resource_ref_cannot_be_a_path_or_credential(f):
    original = f.registry.allocate

    def forged(profile, *, kind):
        return replace(original(profile, kind=kind), resource_ref="C:/browser/chosen/path")

    f.registry.allocate = forged
    with pytest.raises(StrixAdmissionIssuanceError, match="digest"):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "unknown" and len(f.registry.calls) == 1


def test_reentrant_revoke_during_verified_reentry_never_returns_stale_verified(f):
    f.issuer.issue(f.request, now=NOW)
    f.verifier.on_verify = lambda: f.issuer.interrupt(f.request.attempt_id, revoked=True)
    with pytest.raises(StrixAdmissionIssuanceConflict):
        f.restart().issue(f.request, now=NOW)
    assert f.saved.state == "revoked"
    assert f.registry.calls == list(RESOURCE_KINDS)


def test_reentrant_authority_deactivation_during_verified_reentry_fences_return(f):
    f.issuer.issue(f.request, now=NOW)
    f.verifier.on_verify = lambda: setattr(
        f.identities, "head", replace(f.identities.head, active=False)
    )
    with pytest.raises(StrixAdmissionIssuanceConflict):
        f.restart().issue(f.request, now=NOW)
    assert f.saved.state == "unknown"
    assert f.registry.calls == list(RESOURCE_KINDS)


def test_reentrant_revoke_during_first_verification_never_resurrects_attempt(f):
    f.verifier.on_verify = lambda: f.issuer.interrupt(f.request.attempt_id, revoked=True)
    with pytest.raises(StrixAdmissionIssuanceConflict):
        f.issuer.issue(f.request, now=NOW)
    assert f.saved.state == "revoked"
