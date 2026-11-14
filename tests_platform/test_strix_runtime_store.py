from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.product_store_errors import ProductStoreError
from bluefire.strix_engine_runtime import StrixRuntimeAdmission
from bluefire.strix_runtime_admission_resolver import StrixRuntimeAuthorityRecord
from bluefire.strix_runtime_store import (
    ProductStorePersistedStrixRuntimeAdmissionSource,
    ProductStoreStrixRuntimeAuthoritySource,
    ProductStoreTenantRuntimeAdmissionIdentitySource,
    ProtectedStrixRuntimeAdmissionMaterialization,
    _proof_bundle_digest,
)
from bluefire.util import content_hash
from tests_platform.test_strix_engine_runtime import _fixture


def digest(character: str) -> str:
    return "sha256:" + character * 64


class PrivateStore:
    def __init__(self, *, authority: StrixRuntimeAuthorityRecord, envelope=None) -> None:
        self.authority = authority
        self.authority_digest = content_hash(authority.to_dict())
        self.envelope = envelope
        self.calls: list[tuple[Any, ...]] = []

    def _read_current_strix_runtime_authority(self, authority_ref):
        self.calls.append(("current", authority_ref))
        return {
            "authority": self.authority.to_dict(),
            "authority_record_digest": self.authority_digest,
            "event_digest": digest("e"),
        }

    def _read_strix_runtime_authority_event(self, authority_ref, generation, record_digest):
        self.calls.append(("exact", authority_ref, generation, record_digest))
        if generation != self.authority.generation or record_digest != self.authority_digest:
            return None
        return {
            "authority": self.authority.to_dict(),
            "authority_record_digest": self.authority_digest,
            "event_digest": digest("e"),
        }

    def _is_strix_runtime_authority_descendant(self, **values):
        self.calls.append(("descendant", values))
        return values["ancestor_generation"] < values["descendant_generation"]

    def _read_strix_runtime_admission_envelope(self, attempt_id):
        self.calls.append(("admission", attempt_id))
        return self.envelope


class Materializer:
    def __init__(
        self,
        admission: StrixRuntimeAdmission,
        *,
        overrides: Mapping[str, str] | None = None,
    ) -> None:
        self.admission = admission
        self.overrides = dict(overrides or {})
        self.calls: list[Mapping[str, Any]] = []

    def reopen_exact(
        self, document: Mapping[str, Any]
    ) -> ProtectedStrixRuntimeAdmissionMaterialization:
        self.calls.append(document)
        values = {
            name: self.overrides.get(name, document[name])
            for name in ProtectedStrixRuntimeAdmissionMaterialization.__dataclass_fields__
            if name != "admission"
        }
        return ProtectedStrixRuntimeAdmissionMaterialization(
            admission=self.admission,
            **values,
        )


def authority(*, state: str = "active") -> StrixRuntimeAuthorityRecord:
    return StrixRuntimeAuthorityRecord(
        schema_version="bluefire.strix-runtime-authority.v1",
        generation=1 if state == "active" else 2,
        state=state,
        qualification_manifest_ref=digest("1"),
        protected_artifact_key="q" + "a" * 31,
        installed_bluefire_revision="1" * 40,
        strix_build_digest=digest("2"),
        threat_review_ref=digest("3"),
        recorded_at="2026-11-04T12:00:00Z",
        revocation_reason=None if state == "active" else "operator revoked runtime",
    )


def envelope(
    tmp_path: Path, *, state: str = "verified"
) -> tuple[dict[str, Any], StrixRuntimeAdmission, Any, Any]:
    binding, delegation, admission = _fixture(tmp_path)
    proof = _proof_bundle_digest(
        admission,
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
    )
    document = {
        "attempt_id": binding.attempt_id,
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "authority_generation": 1,
        "authority_record_digest": digest("4"),
        "qualification_ref": admission.runtime_qualification_ref,
        "objective_ref": admission.objective_ref,
        "environment_ref": admission.environment_ref,
        "build": admission.build.to_dict(),
        "model_id": admission.gateway.model,
        "target_snapshot_digest": admission.scope.target_snapshot_digest,
        "budgets": asdict(admission.budgets),
        "limits": asdict(admission.limits),
        "runtime_install_ref": digest("b"),
        "runtime_install_digest": digest("c"),
        "workspace_ref": digest("d"),
        "workspace_digest": digest("e"),
        "executable_ref": digest("f"),
        "executable_digest": digest("0"),
        "path_environment_ref": digest("1"),
        "path_environment_digest": digest("2"),
        "control_root_ref": digest("3"),
        "control_root_digest": digest("4"),
        "artifact_root_ref": digest("5"),
        "artifact_root_digest": digest("6"),
        "custody_source_ref": digest("5"),
        "custody_record_ref": digest("6"),
        "custody_record_digest": digest("7"),
        "admission_proof_bundle_digest": proof,
    }
    for name in ProtectedStrixRuntimeAdmissionMaterialization.__dataclass_fields__:
        if name != "admission" and name not in document:
            document[name] = content_hash({"attempt_id": binding.attempt_id, "field": name})
    document.update(
        {
            "scope_record_digest": content_hash(asdict(admission.scope)),
            "gateway_record_digest": content_hash(asdict(admission.gateway)),
            "network_plan_digest": content_hash(admission.network_plan.to_dict()),
            "network_snapshot_digest": content_hash(admission.network_snapshot.to_dict()),
            "network_verification_digest": content_hash(admission.network_verification.to_dict()),
            "custody_plan_digest": admission.custody_plan.plan_digest,
            "protected_roots_digest": admission.protected_roots.receipt_digest,
            "containment_digest": admission.containment.receipt_digest,
        }
    )
    retained = {
        "document": document,
        "admission_record_ref": digest("8"),
        "admission_record_digest": digest("9"),
    }
    return (
        {
            "admission": retained,
            "lifecycle_state": state,
            "lifecycle_head_digest": digest("a"),
            "lifecycle_sequence": 3,
        },
        admission,
        binding,
        delegation,
    )


def test_authority_source_reopens_current_exact_and_descendant() -> None:
    record = authority()
    store = PrivateStore(authority=record)
    source = ProductStoreStrixRuntimeAuthoritySource(store, authority_ref=digest("b"))

    assert source.read_current() == record
    assert (
        source.read_exact(generation=record.generation, record_digest=store.authority_digest)
        == record
    )
    assert source.read_exact(generation=2, record_digest=digest("c")) is None
    assert source.is_descendant(
        ancestor_generation=1,
        ancestor_record_digest=store.authority_digest,
        descendant_generation=2,
        descendant_record_digest=digest("d"),
    )
    assert [item[0] for item in store.calls] == ["current", "exact", "exact", "descendant"]


def test_authority_source_requires_configured_record() -> None:
    record = authority()
    store = PrivateStore(authority=record)
    store._read_current_strix_runtime_authority = lambda _ref: None  # type: ignore[method-assign]
    source = ProductStoreStrixRuntimeAuthoritySource(store, authority_ref=digest("b"))
    with pytest.raises(ProductStoreError, match="not configured"):
        source.read_current()


def test_authority_source_requires_an_exact_digest_owner_ref() -> None:
    store = PrivateStore(authority=authority())
    with pytest.raises(ProductStoreError, match="authority ref"):
        ProductStoreStrixRuntimeAuthoritySource(store, authority_ref="sha256:short")


def test_tenant_identity_source_returns_only_exact_verified_envelope(tmp_path: Path) -> None:
    retained, _admission, binding, delegation = envelope(tmp_path)
    store = PrivateStore(authority=authority(), envelope=retained)
    source = ProductStoreTenantRuntimeAdmissionIdentitySource(store)
    values = {
        "attempt_id": binding.attempt_id,
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "authority_generation": 1,
        "authority_record_digest": digest("4"),
        "qualification_ref": retained["admission"]["document"]["qualification_ref"],
    }

    identity = source.reopen_exact(**values)
    assert identity is not None
    assert identity.admission_record_ref == digest("8")
    assert identity.custody_source_ref == digest("5")
    assert (
        identity.admission_proof_bundle_digest
        == retained["admission"]["document"]["admission_proof_bundle_digest"]
    )
    for field, changed in (
        ("binding_digest", digest("c")),
        ("delegation_digest", digest("d")),
        ("authority_generation", 2),
        ("authority_record_digest", digest("e")),
        ("qualification_ref", digest("f")),
    ):
        assert source.reopen_exact(**{**values, field: changed}) is None
    retained["lifecycle_state"] = "unknown"
    assert source.reopen_exact(**values) is None


@pytest.mark.parametrize("state", ["verified", "unknown", "revoked", "cleaned"])
def test_persisted_source_materializes_exact_record_and_retains_lifecycle(
    tmp_path: Path, state: str
) -> None:
    retained, admission, binding, delegation = envelope(tmp_path, state=state)
    store = PrivateStore(authority=authority(), envelope=retained)
    materializer = Materializer(admission)
    source = ProductStorePersistedStrixRuntimeAdmissionSource(store, materializer=materializer)

    record = source.reopen_exact(
        attempt_id=binding.attempt_id,
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
    )

    assert record is not None
    assert record.record_ref == digest("8")
    assert record.record_digest == digest("9")
    assert record.lifecycle_state == state.upper()
    assert record.lifecycle_head_digest == digest("a")
    assert record.admission is admission
    assert materializer.calls == [retained["admission"]["document"]]


def test_persisted_source_wrong_selector_or_missing_record_never_materializes(
    tmp_path: Path,
) -> None:
    retained, admission, binding, delegation = envelope(tmp_path)
    store = PrivateStore(authority=authority(), envelope=retained)
    materializer = Materializer(admission)
    source = ProductStorePersistedStrixRuntimeAdmissionSource(store, materializer=materializer)

    assert (
        source.reopen_exact(
            attempt_id=binding.attempt_id,
            binding_digest=digest("b"),
            delegation_digest=delegation.delegation_digest,
        )
        is None
    )
    assert materializer.calls == []
    store.envelope = None
    assert (
        source.reopen_exact(
            attempt_id=binding.attempt_id,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
        )
        is None
    )
    assert materializer.calls == []


@pytest.mark.parametrize(
    "drift",
    [
        "objective",
        "qualification",
        "build",
        "attempt",
        "model",
        "snapshot",
        "budgets",
        "limits",
        "proof",
        "materialization",
    ],
)
def test_persisted_source_rejects_materializer_or_record_drift(tmp_path: Path, drift: str) -> None:
    retained, admission, binding, delegation = envelope(tmp_path)
    overrides = None
    if drift == "objective":
        materialized = replace(admission, objective_ref=digest("f"))
    elif drift == "qualification":
        materialized = replace(admission, runtime_qualification_ref=digest("f"))
    elif drift == "build":
        retained["admission"]["document"]["build"] = {
            **admission.build.to_dict(),
            "engine": "other",
        }
        materialized = admission
    elif drift == "attempt":
        materialized = replace(
            admission,
            workspace=replace(admission.workspace, attempt_id="attempt-" + "f" * 32),
        )
    elif drift == "model":
        materialized = replace(
            admission,
            gateway=replace(admission.gateway, model="other-test-provider"),
        )
    elif drift == "snapshot":
        materialized = replace(
            admission,
            scope=replace(admission.scope, target_snapshot_digest=digest("f")),
        )
    elif drift == "budgets":
        materialized = replace(
            admission,
            budgets=replace(admission.budgets, wall_seconds=admission.budgets.wall_seconds + 1),
        )
    elif drift == "limits":
        materialized = replace(
            admission,
            limits=replace(admission.limits, pids=admission.limits.pids + 1),
        )
    elif drift == "materialization":
        materialized = admission
        overrides = {"workspace_ref": digest("f")}
    else:
        retained["admission"]["document"]["admission_proof_bundle_digest"] = digest("f")
        materialized = admission
    source = ProductStorePersistedStrixRuntimeAdmissionSource(
        PrivateStore(authority=authority(), envelope=retained),
        materializer=Materializer(materialized, overrides=overrides),
    )
    with pytest.raises(
        ProductStoreError,
        match="identity changed" if drift == "materialization" else "differs",
    ):
        source.reopen_exact(
            attempt_id=binding.attempt_id,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
        )
