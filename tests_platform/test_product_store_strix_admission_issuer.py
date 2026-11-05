from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import bluefire.product_store_strix_admission_issuer as issuance
from bluefire.product_store import SCHEMA_VERSION, ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.strix_admission_issuer import (
    RESOURCE_KINDS,
    ControllerPrivateStrixAdmissionIssuer,
    StrixAdmissionIssuanceConflict,
    StrixAdmissionIssuanceError,
    StrixIssuanceRecord,
    StrixPreAdmissionProfile,
    StrixResourceReceipt,
    _record_digest,
    _sealed,
)
from bluefire.strix_runtime_store import (
    ProductStorePersistedStrixRuntimeAdmissionSource,
    ProductStoreTenantRuntimeAdmissionIdentitySource,
    _proof_bundle_digest,
)
from bluefire.util import content_hash
from tests_platform.test_product_store_engine_actions import _advance_experiment, _store
from tests_platform.test_product_store_strix_runtime import (
    ATTEMPT_ID,
    AUTHORITY_REF,
    CREATED,
    admission,
    append_authority,
    authority,
    retain_verified,
)
from tests_platform.test_strix_admission_issuer import (
    Identities,
    Registry,
    Verifier,
    request,
)
from tests_platform.test_strix_runtime_store import Materializer
from tests_platform.test_strix_runtime_store import envelope as live_envelope


class AdmissionSource:
    def __init__(self, document):
        self.document = document
        self.on_reopen = None
        self.on_verify = None
        self.mutate = None
        self.model_id = document.get("model_id")
        self.custody_source_ref = document.get("custody_source_ref")

    def reopen_exact_admission(self, record):
        if self.on_reopen:
            hook, self.on_reopen = self.on_reopen, None
            hook()
        result = dict(self.document)
        for receipt in record.resources:
            prefix = {
                "scope": "scope_record",
                "gateway": "gateway_record",
                "source_root_custody": "custody_record",
            }.get(receipt.kind, receipt.kind)
            result[prefix + "_ref"] = receipt.resource_ref
            result[prefix + "_digest"] = receipt.receipt_digest
        if self.mutate:
            result.update(self.mutate)
        return result

    def verify_admission(self, record, document):
        if self.on_verify:
            hook, self.on_verify = self.on_verify, None
            hook()
        return (
            document["model_id"] == self.model_id
            and document["custody_source_ref"] == self.custody_source_ref
        )


class Fixture:
    def __init__(self, tmp_path: Path, *, live=False):
        self.store = _store(tmp_path)
        if live:
            retained, material, _, _ = live_envelope(tmp_path)
            self.live = replace(
                material, workspace=replace(material.workspace, attempt_id="attempt-" + "d" * 32)
            )
            installed_authority = authority()
            installed_authority.update(
                qualification_manifest_ref=material.runtime_qualification_ref,
                strix_build_digest=content_hash(material.build.to_dict()),
            )
            self.authority = self.store._append_strix_runtime_authority(
                authority_ref=AUTHORITY_REF,
                authority=installed_authority,
                authority_basis_ref=content_hash({"live": True}),
                expected_previous_event_digest=None,
            )
            document = admission(self.store, self.authority)
            document.update(retained["admission"]["document"])
            document.update(
                attempt_id=ATTEMPT_ID,
                build_digest=content_hash(material.build.to_dict()),
                authority_record_digest=self.authority["authority_record_digest"],
            )
            document["admission_proof_bundle_digest"] = _proof_bundle_digest(
                self.live,
                binding_digest=document["binding_digest"],
                delegation_digest=document["delegation_digest"],
            )
        else:
            self.authority = append_authority(self.store)
            document = admission(self.store, self.authority)
        self.source = AdmissionSource(document)
        document = self.source.document
        original = request()
        self.request = replace(
            original,
            attempt_id=ATTEMPT_ID,
            created_at=CREATED,
            expires_at=document["expires_at"],
            binding_digest=document["binding_digest"],
            delegation_digest=document["delegation_digest"],
            objective_ref=document["objective_ref"],
            environment_ref=document["environment_ref"],
            target_snapshot_digest=document["target_snapshot_digest"],
            budgets_digest=content_hash(document["budgets"]),
            limits_digest=content_hash(document["limits"]),
            head=replace(
                original.head,
                authority_ref=document["authority_ref"],
                authority_record_digest=document["authority_record_digest"],
                qualification_ref=document["qualification_ref"],
                build_digest=document["build_digest"],
                experiment_id=document["experiment_id"],
                experiment_revision=document["experiment_revision"],
                experiment_digest=document["experiment_digest"],
            ),
        )
        self.identities = Identities(self.request)
        self.persistence = self.adapter(self.store)

        class Records:
            def __getitem__(_, attempt):
                return self.persistence.read(attempt)

        source = self.source

        class ProtectedRegistry(Registry):
            def allocate(inner, profile, *, kind):
                receipt = super().allocate(profile, kind=kind)
                prefix = {
                    "scope": "scope_record",
                    "gateway": "gateway_record",
                    "source_root_custody": "custody_record",
                }.get(kind, kind)
                receipt = replace(
                    receipt,
                    resource_ref=source.document[prefix + "_ref"],
                    receipt_digest=source.document[prefix + "_digest"],
                )
                if kind == "source_root_custody":
                    current = self.persistence.read(profile.request.attempt_id)
                    candidate = advance(
                        current, "preparing", resources=(*current.resources, receipt)
                    )
                    document = source.reopen_exact_admission(candidate)
                    receipt = replace(
                        receipt,
                        receipt_digest=issuance.strix_issuance_admission_commitment(
                            profile, document
                        ),
                    )
                inner.allocations[-1] = receipt
                return receipt

        self.registry = ProtectedRegistry(SimpleNamespace(records=Records()))
        self.issuer().reserve(self.request, now=CREATED)
        self.verifier = Verifier(self.registry)

    def adapter(self, store):
        return issuance.ProductStoreStrixAdmissionIssuerPersistence(
            store,
            admissions=self.source,
            clock=lambda: CREATED,
        )

    def issuer(self):
        return ControllerPrivateStrixAdmissionIssuer(
            identities=self.identities,
            persistence=self.persistence,
            registry=getattr(self, "registry", None),
            verifier=getattr(self, "verifier", None),
        )

    def revoke(self):
        return self.store._append_strix_runtime_authority(
            authority_ref=AUTHORITY_REF,
            authority=authority(2, state="revoked", recorded_at="2026-11-04T12:02:00Z"),
            authority_basis_ref=content_hash({"revoked": True}),
            expected_previous_event_digest=self.authority["event_digest"],
        )


@pytest.fixture
def f(tmp_path):
    return Fixture(tmp_path)


def advance(previous, state, *, pending_kind=None, resources=None, evidence=None):
    return _sealed(
        StrixIssuanceRecord(
            previous.profile,
            state,
            previous.sequence + 1,
            previous.record_digest,
            previous.resources if resources is None else resources,
            pending_kind,
            "",
            evidence,
        )
    )


def test_product_store_and_private_adapter_import_smoke():
    assert SCHEMA_VERSION == 22
    assert issuance.ProductStoreStrixAdmissionIssuerPersistence is not None


def test_exact_reservation_round_trip_and_conflicting_identity(f):
    first = f.issuer().reserve(f.request, now=CREATED)
    assert f.issuer().reserve(f.request, now=CREATED) == first
    reopened = ProductStore(f.store.path)
    assert f.adapter(reopened).read(ATTEMPT_ID) == first
    changed = replace(f.request, scope_digest=content_hash({"changed": True}))
    profile = StrixPreAdmissionProfile(
        changed,
        content_hash(
            {
                "schema_version": "bluefire.strix-issuance-reservation.v1",
                "attempt_id": changed.attempt_id,
                "request_digest": changed.request_digest,
            }
        ),
    )
    with pytest.raises(StrixAdmissionIssuanceConflict):
        f.persistence.reserve(
            _sealed(replace(first, profile=profile)),
            active_head=f.request.head,
        )


def test_two_instances_preparing_cas_has_exactly_one_winner(f):
    record = f.persistence.read(ATTEMPT_ID)
    preparing = advance(record, "preparing")
    adapters = [f.persistence, f.adapter(ProductStore(f.store.path))]

    def compete(adapter):
        try:
            return adapter.compare_and_swap(
                preparing, expected_digest=record.record_digest, active_head=f.request.head
            )
        except StrixAdmissionIssuanceConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(compete, adapters))
    assert results.count(preparing) == 1
    assert results.count(None) == 1
    with pytest.raises(StrixAdmissionIssuanceConflict):
        compete_result = f.persistence.compare_and_swap(
            preparing, expected_digest=record.record_digest, active_head=f.request.head
        )
        assert compete_result is None


@pytest.mark.parametrize("bypass", ["skip_acknowledgements", "replace_acknowledged", "pending"])
def test_verified_cannot_bypass_preparation_with_valid_admission_and_authority(f, bypass):
    first = f.persistence.read(ATTEMPT_ID)
    preparing = advance(first, "preparing")
    previous = f.persistence.compare_and_swap(
        preparing, expected_digest=first.record_digest, active_head=f.request.head
    )
    if bypass == "replace_acknowledged":
        pending = advance(previous, "preparing", pending_kind="scope")
        previous = f.persistence.compare_and_swap(
            pending, expected_digest=previous.record_digest, active_head=f.request.head
        )
        scope = f.registry.allocate(previous.profile, kind="scope")
        acknowledged = advance(previous, "preparing", resources=(scope,))
        previous = f.persistence.compare_and_swap(
            acknowledged, expected_digest=previous.record_digest, active_head=f.request.head
        )
    resources = []
    for kind in RESOURCE_KINDS:
        prefix = {
            "scope": "scope_record",
            "gateway": "gateway_record",
            "source_root_custody": "custody_record",
        }.get(kind, kind)
        resources.append(
            StrixResourceReceipt(
                kind,
                f.source.document[prefix + "_ref"],
                f.source.document[prefix + "_digest"],
                previous.profile.profile_digest,
            )
        )
    if bypass == "replace_acknowledged":
        resources[0] = replace(resources[0], receipt_digest=content_hash({"replacement": True}))
    desired = advance(previous, "verified", resources=tuple(resources))
    document = f.source.reopen_exact_admission(desired)
    resources[-1] = replace(
        resources[-1],
        receipt_digest=issuance.strix_issuance_admission_commitment(previous.profile, document),
    )
    desired = advance(previous, "verified", resources=tuple(resources))
    # The full admission proof and active authority are valid; refusal must
    # come from the durable preparation history, not an unrelated bad proof.
    issuance._bind_admission(desired, f.source.reopen_exact_admission(desired))
    if bypass == "pending":
        desired = replace(desired, pending_kind="scope")
        desired = replace(desired, record_digest=_record_digest(desired))
    with pytest.raises(StrixAdmissionIssuanceError):
        f.persistence.compare_and_swap(
            desired, expected_digest=previous.record_digest, active_head=f.request.head
        )
    assert f.persistence.read(ATTEMPT_ID) == previous


def test_restart_preparing_becomes_unknown_without_replay(f):
    first = f.persistence.read(ATTEMPT_ID)
    preparing = advance(first, "preparing")
    f.persistence.compare_and_swap(
        preparing, expected_digest=first.record_digest, active_head=f.request.head
    )
    pending = advance(preparing, "preparing", pending_kind="scope")
    f.persistence.compare_and_swap(
        pending, expected_digest=preparing.record_digest, active_head=f.request.head
    )
    f.persistence = f.adapter(ProductStore(f.store.path))
    unknown = f.issuer().issue(f.request, now=CREATED)
    assert unknown.state == "unknown" and unknown.pending_kind == "scope"
    assert f.issuer().issue(f.request, now=CREATED) == unknown
    assert not f.registry.calls


def test_old_private_writes_cannot_diverge_issuer_lifecycle(f):
    envelope = f.store._read_strix_runtime_admission_envelope(ATTEMPT_ID)
    with pytest.raises(ResourceConflictError, match="issuer-owned"):
        f.store._append_strix_runtime_admission_event(
            attempt_id=ATTEMPT_ID,
            state="preparing",
            lifecycle_basis_ref=f.request.request_digest,
            recorded_at=CREATED,
            expected_head_digest=envelope["lifecycle_head_digest"],
        )
    assert f.persistence.read(ATTEMPT_ID).state == "reserved"


def test_atomic_reservation_retry_and_preparing_refuse_revoked_authority(f):
    first = f.persistence.read(ATTEMPT_ID)
    f.revoke()
    with pytest.raises(StrixAdmissionIssuanceConflict, match="authority"):
        f.persistence.reserve(first, active_head=f.request.head)
    with pytest.raises(StrixAdmissionIssuanceConflict, match="authority"):
        f.persistence.compare_and_swap(
            advance(first, "preparing"),
            expected_digest=first.record_digest,
            active_head=f.request.head,
        )
    assert f.persistence.read(ATTEMPT_ID) == first


def test_legacy_v20_attempt_is_never_adopted(tmp_path):
    store = _store(tmp_path)
    current = append_authority(store)
    retain_verified(store, current)
    adapter = issuance.ProductStoreStrixAdmissionIssuerPersistence(
        store, admissions=AdmissionSource({})
    )
    with pytest.raises(StrixAdmissionIssuanceConflict, match="legacy"):
        adapter.read(ATTEMPT_ID)
    assert store._read_strix_runtime_admission_envelope(ATTEMPT_ID)["lifecycle_state"] == "verified"


def test_legacy_event_helper_preserves_monotonic_lifecycle_and_rollback(tmp_path):
    store = _store(tmp_path)
    retained = retain_verified(store, append_authority(store))
    with pytest.raises(ProductStoreError, match="time precedes"):
        store._append_strix_runtime_admission_event(
            attempt_id=ATTEMPT_ID,
            state="unknown",
            lifecycle_basis_ref=content_hash({"unknown": True}),
            recorded_at="2026-11-04T12:02:00Z",
            expected_head_digest=retained["lifecycle_head_digest"],
        )
    assert store._read_strix_runtime_admission_envelope(ATTEMPT_ID) == retained


def test_issue_round_trips_every_preparation_and_verified_join(f):
    record = f.issuer().issue(f.request, now=CREATED)
    assert record.state == "verified"
    assert f.registry.calls == list(RESOURCE_KINDS)
    assert record.sequence == 2 + 2 * len(RESOURCE_KINDS) + 1
    assert f.adapter(ProductStore(f.store.path)).read(ATTEMPT_ID) == record
    assert f.issuer().issue(f.request, now=CREATED) == record
    assert f.registry.calls == list(RESOURCE_KINDS)
    state = f.store._read_strix_runtime_admission_envelope(ATTEMPT_ID)
    assert state["lifecycle_sequence"] == record.sequence
    with f.store._connection() as connection:
        rows = connection.execute(
            "SELECT sequence,record_digest,runtime_event_digest FROM strix_runtime_issuance_records ORDER BY sequence"
        ).fetchall()
        events = connection.execute(
            "SELECT sequence,lifecycle_basis_ref,event_digest FROM strix_runtime_admission_events ORDER BY sequence"
        ).fetchall()
    assert rows[0][0] == 1 and events[0][1] == f.request.request_digest
    assert all(tuple(row) == tuple(event) for row, event in zip(rows[1:], events[1:], strict=True))


@pytest.mark.parametrize("interference", ["authority", "revoked", "unknown", "experiment"])
def test_final_resource_callback_cannot_return_stale_verified(f, interference):
    verified = f.issuer().issue(f.request, now=CREATED)

    def interfere():
        if interference == "authority":
            f.revoke()
        elif interference in {"revoked", "unknown"}:
            f.issuer().interrupt(ATTEMPT_ID, revoked=interference == "revoked")
        else:
            _advance_experiment(f.store)

    f.verifier.on_verify = interfere
    with pytest.raises((StrixAdmissionIssuanceError, ProductStoreError)):
        f.issuer().issue(f.request, now=CREATED)
    current = f.persistence.read(ATTEMPT_ID)
    assert current != verified and current.state in {"unknown", "revoked"}
    assert f.registry.calls == list(RESOURCE_KINDS)


def test_admission_source_reentrant_revocation_is_guarded_after_callback(f):
    f.source.on_reopen = f.revoke
    with pytest.raises(StrixAdmissionIssuanceConflict, match="authority"):
        f.issuer().issue(f.request, now=CREATED)
    assert f.persistence.read(ATTEMPT_ID).state == "unknown"
    state = f.store._read_strix_runtime_admission_envelope(ATTEMPT_ID)
    assert state["admission"] is None


def test_lost_allocation_acknowledgement_reconciles_complete_cleanup_without_replay(f):
    f.registry.fail_kind = "network_plan"
    with pytest.raises(RuntimeError, match="acknowledgement"):
        f.issuer().issue(f.request, now=CREATED)
    unknown = f.persistence.read(ATTEMPT_ID)
    assert unknown.state == "unknown" and unknown.pending_kind == "network_plan"
    assert len(unknown.resources) == 2 and len(f.registry.allocations) == 3
    f.persistence = f.adapter(ProductStore(f.store.path))
    assert f.issuer().issue(f.request, now=CREATED) == unknown
    f.registry.absent = True
    cleaned = f.issuer().reconcile(ATTEMPT_ID, now=CREATED)
    assert cleaned.state == "cleaned"
    assert len(cleaned.resources) == 3
    assert len(cleaned.reconciliation_evidence.absence) == len(RESOURCE_KINDS)
    assert f.adapter(ProductStore(f.store.path)).read(ATTEMPT_ID) == cleaned
    assert len(f.registry.calls) == 3


def test_incomplete_absence_evidence_never_commits_cleaned(f):
    f.registry.fail_kind = "scope"
    with pytest.raises(RuntimeError):
        f.issuer().issue(f.request, now=CREATED)
    f.registry.absent = True
    f.registry.omit_absence = "source_root_custody"
    with pytest.raises(StrixAdmissionIssuanceError, match="every resource"):
        f.issuer().reconcile(ATTEMPT_ID, now=CREATED)
    assert f.persistence.read(ATTEMPT_ID).state == "unknown"


def test_unknown_inventory_reverification_retains_same_admission(f):
    verified = f.issuer().issue(f.request, now=CREATED)
    f.issuer().interrupt(ATTEMPT_ID)
    restored = f.issuer().reconcile(ATTEMPT_ID, now=CREATED)
    assert restored.state == "verified" and restored.resources == verified.resources
    assert restored.reconciliation_evidence is not None
    assert f.issuer().issue(f.request, now=CREATED) == restored
    assert f.registry.calls == list(RESOURCE_KINDS)


def test_lost_verified_commit_acknowledgement_is_unknown_without_reallocation(f, monkeypatch):
    original = f.store._connection
    lost = False

    @contextmanager
    def connection_with_lost_ack(*, write=False):
        nonlocal lost
        should_lose = False
        with original(write=write) as connection:
            yield connection
            if write and not lost:
                row = connection.execute(
                    "SELECT active_state FROM strix_runtime_admission_heads WHERE attempt_id=?",
                    (ATTEMPT_ID,),
                ).fetchone()
                should_lose = row is not None and row[0] == "verified"
        if should_lose:
            lost = True
            raise OSError("verified commit acknowledgement lost")

    monkeypatch.setattr(f.store, "_connection", connection_with_lost_ack)
    with pytest.raises(OSError, match="acknowledgement"):
        f.issuer().issue(f.request, now=CREATED)
    assert lost and f.persistence.read(ATTEMPT_ID).state == "unknown"
    f.persistence = f.adapter(ProductStore(f.store.path))
    assert f.issuer().issue(f.request, now=CREATED).state == "unknown"
    assert f.registry.calls == list(RESOURCE_KINDS)


def test_read_and_shipped_envelope_reuse_existing_scoped_read_transaction(f):
    from bluefire.product_store_tenant_action_materials import _read_scope

    expected = f.persistence.read(ATTEMPT_ID)
    with f.store._connection(write=True) as connection, _read_scope(f.store, connection):
        assert f.persistence.read(ATTEMPT_ID) == expected
        assert (
            f.store._read_strix_runtime_admission_envelope(ATTEMPT_ID)["lifecycle_state"]
            == "reserved"
        )
    assert f.persistence.read(ATTEMPT_ID) == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("model_id", "changed-model"),
        ("custody_source_ref", content_hash({"another": "source"})),
        ("admission_proof_bundle_digest", content_hash({"different": "proof"})),
    ],
)
def test_full_admission_commitment_rejects_source_tamper_even_if_callback_says_true(
    f, field, value
):
    f.issuer().issue(f.request, now=CREATED)
    f.issuer().interrupt(ATTEMPT_ID)
    f.source.mutate = {field: value}
    f.source.verify_admission = lambda record, document: True
    with pytest.raises(StrixAdmissionIssuanceConflict, match="policy/proof"):
        f.issuer().reconcile(ATTEMPT_ID, now=CREATED)
    assert f.persistence.read(ATTEMPT_ID).state == "unknown"


def test_last_admission_verification_callback_cannot_race_authority(f):
    f.source.on_verify = f.revoke
    with pytest.raises(StrixAdmissionIssuanceConflict, match="authority"):
        f.issuer().issue(f.request, now=CREATED)
    assert f.persistence.read(ATTEMPT_ID).state == "unknown"


@pytest.mark.parametrize("phase", ["retention", "confirmation"])
def test_lifetime_is_rechecked_after_final_callbacks(f, phase):
    def expired_clock():
        return f.request.expires_at

    if phase == "retention":
        f.source.on_verify = lambda: setattr(f.persistence, "_clock", expired_clock)
    else:
        f.issuer().issue(f.request, now=CREATED)
        f.persistence._clock = expired_clock
    with pytest.raises(StrixAdmissionIssuanceConflict, match="lifetime"):
        f.issuer().issue(f.request, now=CREATED)
    assert f.persistence.read(ATTEMPT_ID).state == "unknown"
    assert f.registry.calls == list(RESOURCE_KINDS)


def test_v21_verified_admission_reopens_through_real_shipped_materializer_adapter(tmp_path):
    fixture = Fixture(tmp_path, live=True)
    established_v20_proof = fixture.source.document["admission_proof_bundle_digest"]
    verified = fixture.issuer().issue(fixture.request, now=CREATED)
    state = fixture.store._read_strix_runtime_admission_envelope(ATTEMPT_ID)
    assert state["admission"]["document"]["admission_proof_bundle_digest"] == established_v20_proof
    assert issuance.strix_issuance_proof_bundle_digest(verified) != established_v20_proof
    source = ProductStorePersistedStrixRuntimeAdmissionSource(
        fixture.store, materializer=Materializer(fixture.live)
    )
    reopened = source.reopen_exact(
        attempt_id=ATTEMPT_ID,
        binding_digest=fixture.request.binding_digest,
        delegation_digest=fixture.request.delegation_digest,
    )
    assert reopened is not None and reopened.admission is fixture.live
    assert reopened.lifecycle_state == "VERIFIED"


@pytest.mark.parametrize("target", ["record", "event", "head", "admission"])
def test_joined_chain_tampering_fails_closed(f, target):
    verified = f.issuer().issue(f.request, now=CREATED)
    table, trigger, statement = {
        "record": (
            "strix_runtime_issuance_records",
            "strix_runtime_issuance_records_no_update",
            "UPDATE strix_runtime_issuance_records SET record_digest=? WHERE sequence=2",
        ),
        "event": (
            "strix_runtime_admission_events",
            "strix_runtime_admission_events_no_update",
            "UPDATE strix_runtime_admission_events SET lifecycle_basis_ref=? WHERE sequence=2",
        ),
        "head": (
            "strix_runtime_admission_heads",
            "strix_runtime_admission_heads_valid_update",
            "UPDATE strix_runtime_admission_heads SET active_event_digest=?",
        ),
        "admission": (
            "strix_runtime_admissions",
            "strix_runtime_admissions_no_update",
            "UPDATE strix_runtime_admissions SET admission_record_digest=?",
        ),
    }[target]
    with sqlite3.connect(f.store.path) as connection:
        connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute(statement, (content_hash({"tampered": table}),))
    with pytest.raises((StrixAdmissionIssuanceError, ProductStoreError)):
        f.persistence.confirm_verified(
            attempt_id=ATTEMPT_ID,
            expected_digest=verified.record_digest,
            active_head=f.request.head,
        )
    identity = ProductStoreTenantRuntimeAdmissionIdentitySource(f.store)
    with pytest.raises((StrixAdmissionIssuanceError, ProductStoreError)):
        identity.reopen_exact(
            attempt_id=ATTEMPT_ID,
            binding_digest=f.request.binding_digest,
            delegation_digest=f.request.delegation_digest,
            authority_generation=f.request.head.authority_generation,
            authority_record_digest=f.request.head.authority_record_digest,
            qualification_ref=f.request.head.qualification_ref,
        )
    persisted = ProductStorePersistedStrixRuntimeAdmissionSource(
        f.store, materializer=Materializer(None)
    )
    with pytest.raises((StrixAdmissionIssuanceError, ProductStoreError)):
        persisted.reopen_exact(
            attempt_id=ATTEMPT_ID,
            binding_digest=f.request.binding_digest,
            delegation_digest=f.request.delegation_digest,
        )


def test_immutable_issuer_rows_and_private_surface_absence(f):
    record = f.issuer().issue(f.request, now=CREATED)
    with sqlite3.connect(f.store.path) as connection:
        for query in (
            "DELETE FROM strix_runtime_issuance_records",
            "UPDATE strix_runtime_issuance_records SET sequence=sequence",
            "INSERT OR REPLACE INTO strix_runtime_issuance_records SELECT * FROM strix_runtime_issuance_records",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                connection.execute(query)
    for kind in ("strix_runtime_issuance_records", "strix_runtime_issuance"):
        with pytest.raises(ProductStoreError, match="unsupported"):
            f.store.list_resources(kind)
    assert record.profile.profile_digest not in str(f.store.list_engine_experiments())


def _snapshot(path):
    with sqlite3.connect(path) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return {
            name: connection.execute(f'SELECT * FROM "{name}"').fetchall()
            for (name,) in tables
            if name
            not in {
                "schema_migrations",
                "strix_runtime_issuance_records",
                "engine_attempt_execution_claims",
                "engine_attempt_pre_dispatch_settlements",
                "engine_attempt_reconciliation_intents",
            }
        }


def test_v20_migration_preserves_every_existing_row_and_rolls_back(tmp_path, monkeypatch):
    store = _store(tmp_path)
    current = append_authority(store)
    retain_verified(store, current)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TABLE strix_runtime_issuance_records")
        connection.execute("DROP TABLE engine_attempt_reconciliation_intents")
        connection.execute("DROP TABLE engine_attempt_pre_dispatch_settlements")
        connection.execute("DROP TABLE engine_attempt_execution_claims")
        connection.execute("DELETE FROM schema_migrations WHERE version=22")
        connection.execute("INSERT INTO schema_migrations VALUES(20,'2026-11-04T00:00:00Z')")
    before = _snapshot(store.path)
    upgraded = ProductStore(store.path)
    assert upgraded.schema_version == 22 and _snapshot(store.path) == before
    assert ProductStore(store.path).schema_version == 22
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TABLE strix_runtime_issuance_records")
        connection.execute("DROP TABLE engine_attempt_reconciliation_intents")
        connection.execute("DROP TABLE engine_attempt_pre_dispatch_settlements")
        connection.execute("DROP TABLE engine_attempt_execution_claims")
        connection.execute("DELETE FROM schema_migrations WHERE version=22")
    original = issuance.initialize_schema

    def interrupted(connection):
        original(connection)
        raise OSError("migration interruption")

    monkeypatch.setattr(issuance, "initialize_schema", interrupted)
    with pytest.raises(ProductStoreError, match="migration failed safely"):
        ProductStore(store.path)
    assert _snapshot(store.path) == before
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 20
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='engine_attempt_execution_claims'"
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                """SELECT 1 FROM sqlite_master
                WHERE name='engine_attempt_pre_dispatch_settlements'"""
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                """SELECT 1 FROM sqlite_master
                WHERE name='engine_attempt_reconciliation_intents'"""
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='strix_runtime_issuance_records'"
            ).fetchone()
            is None
        )
