"""Version fences keep controlled identities out of legacy admission owners."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from bluefire.engine_container_custody import ContainerCustodyPlanV2, DaemonInventoryV2
from bluefire.product_store_errors import ProductStoreError
from bluefire.strix_engine_runtime import (
    StrixEngineRuntimeError,
    StrixRuntimeAdmission,
    _require_legacy_admission_identity,
)
from bluefire.strix_runtime_admission_resolver import _admission_identity_document
from bluefire.strix_runtime_store import (
    ProductStorePersistedStrixRuntimeAdmissionSource,
    ProductStoreTenantRuntimeAdmissionIdentitySource,
    _proof_bundle_digest,
)
from bluefire.tenant_action_material_source import _admission_proofs
from bluefire.util import content_hash
from tests_platform.test_engine_container_custody import inventory_v2, plan_v2
from tests_platform.test_engine_network_policy import _plan_v2
from tests_platform.test_strix_engine_runtime import _fixture
from tests_platform.test_strix_runtime_admission_resolver import make_case
from tests_platform.test_strix_runtime_store import Materializer, PrivateStore, authority, envelope


def test_real_legacy_admission_identity_and_proof_projection_are_unchanged(tmp_path: Path) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    _require_legacy_admission_identity(admission)
    proofs = _admission_proofs(binding, delegation, admission)
    assert _proof_bundle_digest(
        admission,
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
    ) == content_hash(proofs)


@pytest.mark.parametrize(
    "field",
    [
        "network_plan",
        "network_snapshot",
        "network_verification",
        "custody_plan",
        "protected_roots",
        "containment",
    ],
)
def test_all_legacy_proof_identity_paths_refuse_explicit_v2_schema(
    tmp_path: Path, field: str
) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    proof = SimpleNamespace(to_dict=lambda: {"schema_version": "bluefire.test-proof.v2"})
    mixed = replace(admission, **{field: cast(Any, proof)})
    for read in (
        lambda: _require_legacy_admission_identity(mixed),
        lambda: _admission_proofs(binding, delegation, mixed),
        lambda: _proof_bundle_digest(
            mixed,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
        ),
        lambda: _admission_identity_document(
            mixed,
            custody_source_ref="sha256:" + "1" * 64,
            custody_record_ref="sha256:" + "2" * 64,
            custody_record_digest="sha256:" + "3" * 64,
        ),
    ):
        with pytest.raises(StrixEngineRuntimeError, match="version"):
            read()


def test_legacy_identity_refuses_known_v2_plan_types_even_if_relabelled(tmp_path: Path) -> None:
    _binding, _delegation, admission = _fixture(tmp_path)
    network = _plan_v2()
    custody = ContainerCustodyPlanV2.from_mapping(
        plan_v2(DaemonInventoryV2.from_mapping(inventory_v2()))
    )
    for field, proof in (("network_plan", network), ("custody_plan", custody)):
        object.__setattr__(proof, "schema_version", "bluefire.engine-network-plan.v1")
        mixed = replace(admission, **{field: cast(Any, proof)})
        with pytest.raises(StrixEngineRuntimeError, match="different version"):
            _require_legacy_admission_identity(mixed)


def test_resolver_refuses_a_mixed_saved_admission_before_qualification_read(tmp_path: Path) -> None:
    case = make_case(tmp_path)
    case.admissions.admission = replace(case.admission, network_plan=cast(Any, _plan_v2()))
    with pytest.raises(StrixEngineRuntimeError, match="different version"):
        case.resolver.resolve_for_launch(case.binding, case.delegation)


@pytest.mark.parametrize("schema", ["bluefire.strix-runtime-admission-record.v2", "unknown"])
def test_fake_store_cannot_project_or_materialize_other_version(
    tmp_path: Path, schema: str
) -> None:
    retained, admission, binding, delegation = envelope(tmp_path)
    retained["admission"]["document"]["schema_version"] = schema
    store = PrivateStore(authority=authority(), envelope=retained)
    materializer = Materializer(admission)
    source = ProductStorePersistedStrixRuntimeAdmissionSource(store, materializer=materializer)
    with pytest.raises(ProductStoreError, match="version"):
        source.reopen_exact(
            attempt_id=binding.attempt_id,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
        )
    with pytest.raises(ProductStoreError, match="version"):
        ProductStoreTenantRuntimeAdmissionIdentitySource(store).reopen_exact(
            attempt_id=binding.attempt_id,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
            authority_generation=1,
            authority_record_digest=retained["admission"]["document"]["authority_record_digest"],
            qualification_ref=admission.runtime_qualification_ref,
        )
    assert materializer.calls == []


def test_materializer_cannot_mix_v2_live_plans_into_legacy_retained_record(tmp_path: Path) -> None:
    retained, admission, binding, delegation = envelope(tmp_path)
    mixed = replace(admission, network_plan=cast(Any, _plan_v2()))
    source = ProductStorePersistedStrixRuntimeAdmissionSource(
        PrivateStore(authority=authority(), envelope=retained),
        materializer=Materializer(mixed),
    )
    with pytest.raises(ProductStoreError, match="version"):
        source.reopen_exact(
            attempt_id=binding.attempt_id,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
        )


@pytest.mark.parametrize(
    "hidden",
    [
        {"extra_proof": {"schema_version": "bluefire.test-proof.v2"}},
        {"controlled_runtime_profile": {"schema_version": "bluefire.strix-profile.v1"}},
    ],
)
def test_schema_less_legacy_source_cannot_hide_controlled_identity_fields(
    tmp_path: Path, hidden: dict[str, Any]
) -> None:
    retained, admission, binding, delegation = envelope(tmp_path)
    retained["admission"]["document"].update(hidden)
    store = PrivateStore(authority=authority(), envelope=retained)
    materializer = Materializer(admission)
    with pytest.raises(ProductStoreError, match="version"):
        ProductStorePersistedStrixRuntimeAdmissionSource(
            store, materializer=materializer
        ).reopen_exact(
            attempt_id=binding.attempt_id,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
        )
    with pytest.raises(ProductStoreError, match="version"):
        ProductStoreTenantRuntimeAdmissionIdentitySource(store).reopen_exact(
            attempt_id=binding.attempt_id,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
            authority_generation=1,
            authority_record_digest=retained["admission"]["document"]["authority_record_digest"],
            qualification_ref=admission.runtime_qualification_ref,
        )
    assert materializer.calls == []


def test_legacy_top_level_identity_requires_exact_legacy_type(tmp_path: Path) -> None:
    _binding, _delegation, admission = _fixture(tmp_path)

    class ControlledAdmission(StrixRuntimeAdmission):
        pass

    derived = ControlledAdmission(
        **{name: getattr(admission, name) for name in admission.__dataclass_fields__}
    )
    with pytest.raises(StrixEngineRuntimeError, match="different version"):
        _require_legacy_admission_identity(derived)
