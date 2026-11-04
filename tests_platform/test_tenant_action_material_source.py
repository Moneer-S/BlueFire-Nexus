from __future__ import annotations

import io
import json
import sqlite3
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

import bluefire.product_store as product_store
import bluefire.product_store_engine_actions as action_store
import bluefire.product_store_tenant_action_materials as slots
from bluefire.engine_action_preparation import EngineActionPreparationError, EngineWorkspaceAction
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.product_store_serialization import canonical_json
from bluefire.run_bundle_export import export_run_bundle
from bluefire.strix_runtime_admission_resolver import StrixRuntimeAuthorityRecord
from bluefire.tenant_action_material_source import (
    ProductStoreTenantActionMaterialSource,
    TenantRuntimeAdmissionIdentity,
    _admission_proofs,
)
from bluefire.tenant_engine_action_preparer import ControllerOwnedTenantActionPreparer
from bluefire.tenant_record_generation_source import (
    _lifecycle_document,
    _plan_document,
    _validate_journal,
)
from bluefire.util import content_hash
from tests_platform.test_product_store_engine_actions import _store_experiment
from tests_platform.test_run_bundle_export import finalized
from tests_platform.test_tenant_engine_action_preparer import _case, _forbid_effects, _shift


class _Journal:
    def __init__(self, store, owner, journal):
        self.store, self.owner, self.journal = store, owner, journal

    def read(self):
        return self.store._get_tenant_generation_journal(self.owner, self.journal)

    def advance(self):
        head = self.read()
        document = {**head["document"], "revision": head["revision"] + 1}
        return self.store._save_tenant_generation_journal(
            self.owner,
            self.journal,
            document,
            expected_revision=head["revision"],
            expected_digest=head["digest"],
            validator=_validate_journal,
        )


class _Authority:
    def __init__(self, record):
        self.record = record
        self.reads = 0

    def read_current(self):
        self.reads += 1
        return self.record


class _AdmissionIdentities:
    def __init__(self, record):
        self.record = record
        self.calls = []

    def reopen_exact(self, **values):
        self.calls.append(values)
        return self.record


@dataclass
class _Harness:
    case: Any
    store: ProductStore
    journal: _Journal
    authority: _Authority
    now: list[str]
    source: ProductStoreTenantActionMaterialSource
    preparer: ControllerOwnedTenantActionPreparer
    identities: _AdmissionIdentities

    def plan(self):
        return self.preparer.prepare(
            experiment=self.case.experiment,
            workspace=self.case.workspace,
            action=self.case.material.action,
            prepared_at=self.now[0],
        )

    def values(self, plan):
        return dict(
            experiment_id=self.case.experiment.experiment_id,
            experiment_revision=self.case.experiment.revision,
            experiment_digest=self.case.experiment.digest,
            workspace_digest=self.case.workspace["workspace_digest"],
            action=plan.action,
            limits=plan.limits,
            prepared_at=self.now[0],
            expires_at=plan.expires_at,
            protected_factory=plan.protected_factory,
            approval_request=plan.approval_request,
        )

    def retain(self):
        plan = self.plan()
        assert plan.retain_preparation is not None
        return plan.retain_preparation(**self.values(plan))

    def reopen(self):
        material = self.case.material
        return self.source.reopen_exact(
            experiment_id=material.experiment_id,
            experiment_revision=material.experiment_revision,
            experiment_digest=material.experiment_digest,
            action=material.action,
        )

    def counts(self):
        with self.store._connection() as connection:
            return tuple(
                connection.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
                for name in (
                    "tenant_action_material_slots",
                    "engine_action_preparations",
                    "approval_requests",
                )
            )


def _harness(tmp_path: Path, monkeypatch, action=EngineWorkspaceAction.START_BASELINE):
    case = _case(tmp_path, action, monkeypatch)
    store = _store_experiment(tmp_path, case.experiment)
    owner, journal = case.experiment.experiment_id, "experiment-" + "9" * 32
    generation = case.generation
    document = {
        "schema_version": "bluefire.tenant-record-generation-journal.v1",
        "experiment_id": journal,
        "revision": 1,
        "inputs_digest": content_hash({"fixed": "protected-inputs"}),
        "phase": "running",
        "active": {
            "plan": _plan_document(generation.lifecycle.plan),
            "lifecycle": _lifecycle_document(generation.lifecycle),
            "packet": {
                "run_id": generation.lifecycle.plan.run_id,
                "attempt_id": generation.lifecycle.plan.attempt_id,
                "created_at": generation.packet.created_at,
                "defense_mode": generation.config.mode,
            },
        },
        "operation": None,
        "consumed": [],
        "generation_ids": [
            {
                "run_id": generation.lifecycle.plan.run_id,
                "attempt_id": generation.lifecycle.plan.attempt_id,
            }
        ],
        "audit_bindings": [],
        "retained_audit": None,
    }
    store._create_tenant_generation_journal(owner, journal, document, validator=_validate_journal)
    authority = _Authority(
        StrixRuntimeAuthorityRecord(
            schema_version="bluefire.strix-runtime-authority.v1",
            generation=1,
            state="active",
            qualification_manifest_ref=content_hash("controller-only")
            if case.resolver.admission is None
            else case.admission.runtime_qualification_ref,
            protected_artifact_key="qualification-" + "a" * 32,
            installed_bluefire_revision="a" * 40,
            strix_build_digest=content_hash("controller-only")
            if case.resolver.admission is None
            else content_hash(case.admission.build.to_dict()),
            threat_review_ref=content_hash({"review": "fixed"}),
            recorded_at=case.material.prepared_at,
            revocation_reason=None,
        )
    )
    now = [case.material.prepared_at]
    identity = None
    if case.resolver.admission is not None:
        binding, delegation = ControllerOwnedTenantActionPreparer._engine_authority(
            case.experiment, case.material
        )
        identity = TenantRuntimeAdmissionIdentity(
            schema_version="bluefire.tenant-runtime-admission-identity.v1",
            attempt_id=binding.attempt_id,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
            authority_generation=authority.record.generation,
            authority_record_digest=content_hash(authority.record.to_dict()),
            qualification_ref=authority.record.qualification_manifest_ref,
            admission_record_ref=content_hash("retained-admission-reference"),
            admission_record_digest=content_hash("retained-admission-record"),
            custody_source_ref=content_hash("retained-custody-source"),
            custody_record_ref=content_hash("retained-custody-reference"),
            custody_record_digest=content_hash("retained-custody-record"),
            admission_proof_bundle_digest=content_hash(
                _admission_proofs(binding, delegation, case.admission)
            ),
        )
    identities = _AdmissionIdentities(identity)
    monkeypatch.setattr(action_store, "utc_now", lambda: now[0])
    monkeypatch.setattr(product_store, "utc_now", lambda: now[0])
    journal_reader = _Journal(store, owner, journal)
    source = ProductStoreTenantActionMaterialSource(
        store=store,
        generation_journal=journal_reader,
        generation_source=case.generations,
        runtime_authority_source=authority,
        runtime_resolver=case.resolver,
        clock=lambda: now[0],
        candidate_source=case.materials,
        admission_identity_source=identities,
    )
    preparer = ControllerOwnedTenantActionPreparer(
        material_source=source,
        material_issuer=source,
        generation_source=case.generations,
        runtime_resolver=case.resolver,
        controller_jobs=case.preparer._jobs,
    )
    return _Harness(case, store, journal_reader, authority, now, source, preparer, identities)


def test_first_issue_is_atomic_and_restart_reopens_without_candidates(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    assert harness.counts() == (0, 0, 0)
    prepared = harness.retain()
    assert harness.counts() == (1, 1, 1)
    assert harness.reopen() == harness.case.material
    source = ProductStoreTenantActionMaterialSource(
        store=ProductStore(harness.store.path),
        generation_journal=harness.journal,
        generation_source=harness.case.generations,
        runtime_authority_source=harness.authority,
        runtime_resolver=harness.case.resolver,
        clock=lambda: harness.now[0],
        admission_identity_source=harness.identities,
    )
    material = harness.case.material
    assert (
        source.reopen_exact(
            experiment_id=material.experiment_id,
            experiment_revision=material.experiment_revision,
            experiment_digest=material.experiment_digest,
            action=material.action,
        )
        == material
    )
    assert prepared["prepared_at"] == material.prepared_at


def test_exact_retry_after_sixty_seconds_reuses_all_identities(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    first = harness.retain()
    harness.now[0] = _shift(harness.now[0], 61)
    assert harness.retain() == first
    assert harness.counts() == (1, 1, 1)


def test_reopen_is_read_only_and_never_reissues_retained_material(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    _forbid_effects(monkeypatch)
    harness.retain()

    def forbidden(*args, **kwargs):
        raise AssertionError("read-only reopen attempted issuance")

    monkeypatch.setattr(harness.case.materials, "reopen_exact", forbidden)
    monkeypatch.setattr(harness.store, "_retain_tenant_action_material_preparation", forbidden)
    monkeypatch.setattr(harness.store, "_create_engine_action_preparation_at", forbidden)
    assert harness.reopen() == harness.case.material
    assert harness.counts() == (1, 1, 1)


def test_missing_persisted_runtime_admission_refuses_without_any_rows(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    harness.case.admission = None
    with pytest.raises(EngineActionPreparationError):
        harness.retain()
    assert harness.counts() == (0, 0, 0)


@pytest.mark.parametrize("missing", ["identity_source", "identity_record"])
def test_engine_requires_preexisting_persisted_admission_identity(tmp_path, monkeypatch, missing):
    harness = _harness(tmp_path, monkeypatch)
    if missing == "identity_source":
        harness.source._admission_identities = None
    else:
        harness.identities.record = None
    with pytest.raises(EngineActionPreparationError, match="persisted admission identity"):
        harness.retain()
    assert harness.counts() == (0, 0, 0)


@pytest.mark.parametrize(
    "field,value",
    [
        ("attempt_id", "engine-attempt-" + "f" * 32),
        ("binding_digest", content_hash("different-binding")),
        ("delegation_digest", content_hash("different-delegation")),
        ("authority_generation", 2),
        ("authority_record_digest", content_hash("different-authority-record")),
        ("qualification_ref", content_hash("different-qualification")),
        ("admission_proof_bundle_digest", content_hash("different-admission-proofs")),
    ],
)
def test_inexact_persisted_admission_identity_refuses_before_approval(
    tmp_path, monkeypatch, field, value
):
    harness = _harness(tmp_path, monkeypatch)
    harness.identities.record = replace(harness.identities.record, **{field: value})
    with pytest.raises(EngineActionPreparationError, match="persisted admission identity changed"):
        harness.retain()
    assert harness.counts() == (0, 0, 0)


@pytest.mark.parametrize(
    "field",
    [
        "admission_record_ref",
        "admission_record_digest",
        "custody_source_ref",
        "custody_record_ref",
        "custody_record_digest",
    ],
)
def test_retained_admission_and_custody_record_identity_cannot_refresh(
    tmp_path, monkeypatch, field
):
    harness = _harness(tmp_path, monkeypatch)
    harness.retain()
    harness.identities.record = replace(
        harness.identities.record, **{field: content_hash("replacement-record")}
    )
    with pytest.raises(EngineActionPreparationError):
        harness.reopen()
    with pytest.raises(EngineActionPreparationError):
        harness.retain()
    assert harness.counts() == (1, 1, 1)


def test_persisted_admission_identity_is_reread_before_preparation(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    original = harness.identities.reopen_exact
    calls = []

    def unstable(**values):
        result = original(**values)
        calls.append(True)
        return (
            result
            if len(calls) == 1
            else replace(result, admission_record_digest=content_hash("changed-during-reopen"))
        )

    monkeypatch.setattr(harness.identities, "reopen_exact", unstable)
    with pytest.raises(EngineActionPreparationError, match="persisted admission identity changed"):
        harness.retain()
    assert harness.counts() == (0, 0, 0)


def test_one_slot_cannot_be_rebound_to_another_workspace(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    first = harness.retain()
    harness.case.workspace["workspace_digest"] = content_hash("different-current-workspace")
    with pytest.raises(ResourceConflictError, match="CAS preimage"):
        harness.retain()
    assert harness.counts() == (1, 1, 1)
    with harness.store._connection() as connection:
        assert (
            connection.execute("SELECT request_ref FROM engine_action_preparations").fetchone()[0]
            == first["request_ref"]
        )


def test_experiment_head_advance_refuses_prior_material(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    harness.retain()
    prior = harness.case.experiment
    advanced = replace(
        prior,
        revision=2,
        previous_revision_digest=prior.digest,
        updated_at=_shift(prior.updated_at, 1),
    )
    harness.store.save_engine_experiment(
        prior.experiment_id,
        advanced.to_dict(),
        expected_revision=prior.revision,
        expected_digest=prior.digest,
        validator=lambda value: value,
    )
    with pytest.raises(EngineActionPreparationError):
        harness.reopen()
    assert harness.counts() == (1, 1, 1)


def test_uncommitted_slot_cannot_bypass_new_preparation_chronology(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    harness.now[0] = _shift(harness.now[0], 61)
    with pytest.raises(ProductStoreError, match="not current"):
        harness.retain()
    assert harness.counts() == (0, 0, 0)


def test_expired_same_head_refuses_without_refresh(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    first = harness.retain()
    harness.now[0] = harness.case.material.expires_at
    with pytest.raises(EngineActionPreparationError):
        harness.retain()
    assert harness.counts() == (1, 1, 1)
    with harness.store._connection() as connection:
        assert (
            connection.execute("SELECT prepared_at FROM engine_action_preparations").fetchone()[0]
            == first["prepared_at"]
        )


@pytest.mark.parametrize(
    "change", ["generation", "qualification", "revocation", "admission", "journal"]
)
def test_current_authority_drift_refuses_reopen_and_exact_retry(tmp_path, monkeypatch, change):
    harness = _harness(tmp_path, monkeypatch)
    harness.retain()
    if change == "generation":
        harness.authority.record = replace(harness.authority.record, generation=2)
    elif change == "qualification":
        harness.authority.record = replace(
            harness.authority.record, qualification_manifest_ref=content_hash("other")
        )
    elif change == "revocation":
        harness.authority.record = replace(
            harness.authority.record, state="revoked", revocation_reason="controller revoked"
        )
    elif change == "admission":
        harness.case.admission = replace(
            harness.case.admission, path_environment="different-fixed-environment"
        )
    else:
        harness.journal.advance()
    with pytest.raises(EngineActionPreparationError):
        harness.reopen()
    with pytest.raises(EngineActionPreparationError):
        harness.retain()
    assert harness.counts() == (1, 1, 1)


def test_concurrent_exact_issuance_has_one_slot_preparation_and_approval(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    plans = [harness.plan(), harness.plan()]
    stores = [harness.store, ProductStore(harness.store.path)]
    sources = [
        harness.source,
        ProductStoreTenantActionMaterialSource(
            store=stores[1],
            generation_journal=harness.journal,
            generation_source=harness.case.generations,
            runtime_authority_source=harness.authority,
            runtime_resolver=harness.case.resolver,
            clock=lambda: harness.now[0],
            candidate_source=harness.case.materials,
            admission_identity_source=harness.identities,
        ),
    ]
    retainers = [
        source.retainer(
            material=harness.case.material,
            experiment=harness.case.experiment,
            workspace_digest=harness.case.workspace["workspace_digest"],
        )
        for source in sources
    ]
    barrier = threading.Barrier(2)

    def retain(index):
        barrier.wait(timeout=10)
        return retainers[index](**harness.values(plans[index]))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(retain, range(2)))
    assert results[0] == results[1]
    assert harness.counts() == (1, 1, 1)


@pytest.mark.parametrize("point", ["after_approval", "after_slot"])
def test_injected_crash_rolls_back_slot_preparation_and_approval(tmp_path, monkeypatch, point):
    harness = _harness(tmp_path, monkeypatch)
    if point == "after_approval":
        original = harness.store._create_approval_request_at

        def crash(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("injected controller crash")

        monkeypatch.setattr(harness.store, "_create_approval_request_at", crash)
    else:
        original_connection = harness.store._connection

        @contextmanager
        def crash_connection(*, write=False):
            with original_connection(write=write) as connection:
                yield connection
                if (
                    write
                    and connection.execute(
                        "SELECT count(*) FROM tenant_action_material_slots"
                    ).fetchone()[0]
                ):
                    raise RuntimeError("injected controller crash")

        monkeypatch.setattr(harness.store, "_connection", crash_connection)
    with pytest.raises(RuntimeError, match="injected controller crash"):
        harness.retain()
    assert harness.counts() == (0, 0, 0)


def test_preexisting_preparation_without_slot_is_not_adopted(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    plan = harness.plan()
    harness.store.create_engine_action_preparation(**harness.values(plan))
    assert harness.counts() == (0, 1, 1)
    with pytest.raises((ProductStoreError, EngineActionPreparationError)):
        harness.retain()
    assert harness.counts() == (0, 1, 1)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE tenant_action_material_slots SET slot_digest=slot_digest",
        "DELETE FROM tenant_action_material_slots",
        "INSERT OR REPLACE INTO tenant_action_material_slots SELECT * FROM tenant_action_material_slots",
    ],
)
def test_sql_cannot_update_delete_or_replace_a_slot(tmp_path, monkeypatch, statement):
    harness = _harness(tmp_path, monkeypatch)
    harness.retain()
    with harness.store._connection(write=True) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(statement)
    assert harness.counts() == (1, 1, 1)


@pytest.mark.parametrize(
    "change", ["noncanonical", "digest", "extra_authority", "provenance", "orphan"]
)
def test_tampered_or_orphaned_slot_refuses_read(tmp_path, monkeypatch, change):
    harness = _harness(tmp_path, monkeypatch)
    harness.retain()
    with harness.store._connection(write=True) as connection:
        for trigger in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='tenant_action_material_slots'"
        ).fetchall():
            connection.execute(f"DROP TRIGGER {trigger[0]}")
        row = connection.execute("SELECT * FROM tenant_action_material_slots").fetchone()
        if change == "noncanonical":
            connection.execute(
                "UPDATE tenant_action_material_slots SET document_json=?",
                (json.dumps(json.loads(row["document_json"]), indent=2),),
            )
        elif change == "digest":
            connection.execute(
                "UPDATE tenant_action_material_slots SET slot_digest=?", (content_hash("other"),)
            )
        elif change == "extra_authority":
            document = json.loads(row["document_json"])
            document["command"] = "arbitrary-launch"
            connection.execute(
                "UPDATE tenant_action_material_slots SET document_json=?,slot_digest=?",
                (canonical_json(document), content_hash(document)),
            )
        elif change == "provenance":
            connection.execute(
                "UPDATE tenant_action_material_slots SET preparation_record_digest=?",
                (content_hash("other"),),
            )
        else:
            # A damaged store cannot repair an orphan by issuing another approval.
            connection.execute("PRAGMA defer_foreign_keys=ON")
            for trigger in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='engine_action_preparations'"
            ).fetchall():
                connection.execute(f"DROP TRIGGER {trigger[0]}")
            connection.execute("DELETE FROM engine_action_preparations")
            connection.execute("DELETE FROM tenant_action_material_slots")
            connection.execute("PRAGMA defer_foreign_keys=OFF")
            # Actual absent preparation is tested via direct SQL with FK disabled below.
    if change == "orphan":
        with sqlite3.connect(harness.store.path) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute(
                "INSERT INTO tenant_action_material_slots VALUES(?,?,?,?,?,?,?,?)", tuple(row)
            )
    with pytest.raises(EngineActionPreparationError):
        harness.reopen()


def test_slot_contains_only_bounded_nonsecret_material_and_stays_private(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    experiment_before = harness.store.get_engine_experiment(harness.case.experiment.experiment_id)
    runs, run_id = finalized(tmp_path)
    before_bundle = export_run_bundle(runs, run_id)
    prepared = harness.retain()
    with harness.store._connection() as connection:
        encoded = connection.execute(
            "SELECT document_json FROM tenant_action_material_slots"
        ).fetchone()[0]
    assert 0 < len(encoded.encode()) <= slots.MAX_DOCUMENT_BYTES
    for admission in harness.case.generation.admissions:
        assert admission.token.hex() not in encoded
        assert repr(admission.token) not in encoded
    assert str(harness.case.admission.executable) not in encoded
    assert str(harness.case.admission.control_root) not in encoded
    assert harness.case.admission.path_environment not in encoded
    assert (
        harness.store.get_engine_experiment(harness.case.experiment.experiment_id)
        == experiment_before
    )
    assert harness.store.list_jobs() == []
    for kind in ("runner", "model_provider", "research_source"):
        assert harness.store.list_resources(kind) == []
    public = harness.store.prepared_engine_action(prepared["request_ref"])
    assert "material" not in canonical_json(public)
    assert "generation_journal" not in canonical_json(public)
    assert not hasattr(harness.store, "list_tenant_action_material_slots")
    assert not hasattr(harness.store, "get_tenant_action_material_slot")
    for kind in ("tenant_action_material", "tenant_action_material_slot"):
        with pytest.raises(ProductStoreError, match="unsupported"):
            harness.store.list_resources(kind)
        with pytest.raises(ProductStoreError, match="unsupported"):
            harness.store.save_resource(kind, "private-slot", {"material": "denied"})
    after_bundle = export_run_bundle(runs, run_id)
    with (
        zipfile.ZipFile(io.BytesIO(before_bundle)) as before,
        zipfile.ZipFile(io.BytesIO(after_bundle)) as after,
    ):
        assert before.namelist() == after.namelist()
        assert all(before.read(name) == after.read(name) for name in before.namelist())


def test_controller_review_retains_exact_plan_mechanism_and_observation_lineage(
    tmp_path, monkeypatch
):
    harness = _harness(tmp_path, monkeypatch, EngineWorkspaceAction.REVIEW_DEFENSE)
    harness.source._admission_identities = None
    prepared = harness.retain()
    assert harness.counts() == (1, 1, 0)
    assert harness.reopen() == harness.case.material
    with harness.store._connection() as connection:
        document = json.loads(
            connection.execute("SELECT document_json FROM tenant_action_material_slots").fetchone()[
                0
            ]
        )
    assert document["runtime"] is None
    assert (
        document["controller_lineage"]["plan_digest"] == harness.case.material.defense_plan.digest
    )
    assert document["controller_lineage"]["mechanism_digest"] == content_hash(
        harness.case.material.mechanism.to_dict()
    )
    assert document["controller_lineage"]["observations"] == [
        content_hash(item.to_dict()) for item in harness.case.experiment.independent_observations
    ]
    assert prepared["approval_request_id"] is None


def _as_v18(store):
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TABLE tenant_action_material_slots")
        connection.execute("DELETE FROM schema_migrations WHERE version >= 19")
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations VALUES (18, '2026-11-04T00:00:00Z')"
        )


def _data_without_slots(path):
    with sqlite3.connect(path) as connection:
        tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        return {
            name: sorted(connection.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr)
            for (name,) in tables
            if name not in {"tenant_action_material_slots", "schema_migrations"}
            and not name.startswith("sqlite_")
        }


def test_v18_migration_preserves_all_journal_preparation_and_approval_data(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    plan = harness.plan()
    harness.store.create_engine_action_preparation(**harness.values(plan))
    _as_v18(harness.store)
    before = _data_without_slots(harness.store.path)
    upgraded = ProductStore(harness.store.path)
    assert upgraded.schema_version == 19
    assert _data_without_slots(harness.store.path) == before
    with upgraded._connection() as connection:
        assert (
            connection.execute("SELECT count(*) FROM tenant_action_material_slots").fetchone()[0]
            == 0
        )


def test_v19_migration_failure_rolls_back_schema_and_marker(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    _as_v18(harness.store)
    before = _data_without_slots(harness.store.path)
    original = slots.initialize_schema

    def interrupted(connection):
        original(connection)
        raise OSError("injected v19 migration interruption")

    monkeypatch.setattr(slots, "initialize_schema", interrupted)
    with pytest.raises(ProductStoreError, match="migration failed safely"):
        ProductStore(harness.store.path)
    assert _data_without_slots(harness.store.path) == before
    with sqlite3.connect(harness.store.path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 18
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE 'tenant_action_material%'"
            ).fetchall()
            == []
        )


def test_material_schema_initialization_requires_transaction():
    with sqlite3.connect(":memory:") as connection:
        with pytest.raises(ProductStoreError, match="requires one transaction"):
            slots.initialize_schema(connection)


def test_shared_read_scope_refuses_nested_write_and_resets_after_rollback(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    other_store = ProductStore(harness.store.path)
    original = harness.source._validate
    calls = []

    def validator(document):
        result = original(document)
        calls.append(True)
        if len(calls) == 2:
            with other_store._connection(write=True):
                raise AssertionError("nested write unexpectedly opened")
        return result

    monkeypatch.setattr(harness.source, "_validate", validator)
    with pytest.raises(ProductStoreError, match="write"):
        harness.retain()
    assert harness.counts() == (0, 0, 0)
    assert slots._READ_SCOPE.get() is None
    other_store.set_setting("after-rollback", {"write": "available"})
    assert other_store.get_setting("after-rollback") == {"write": "available"}


def test_shared_read_scope_does_not_reuse_another_database(tmp_path, monkeypatch):
    harness = _harness(tmp_path, monkeypatch)
    other_store = ProductStore(tmp_path / "other.db")
    other_store.set_setting("independent", {"retained": True})
    original = harness.source._validate
    observed = []

    def validator(document):
        result = original(document)
        if slots._READ_SCOPE.get() is not None:
            with other_store._connection() as connection:
                assert connection is not slots._READ_SCOPE.get()[3]
                observed.append(True)
            assert other_store.get_setting("independent") == {"retained": True}
        return result

    monkeypatch.setattr(harness.source, "_validate", validator)
    harness.retain()
    assert observed
    assert slots._READ_SCOPE.get() is None
