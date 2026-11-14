"""Read-only adapters over ProductStore's private v20 Strix records.

The authority and tenant-action identity adapters only validate retained data.
The persisted-admission adapter requires an injected protected materializer for
opaque locations and custody.  None of these reads provision or repair state.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from .product_store_errors import ProductStoreError
from .strix_engine_runtime import StrixRuntimeAdmission
from .strix_runtime_admission_resolver import (
    PersistedStrixRuntimeAdmissionRecord,
    StrixRuntimeAuthorityRecord,
)
from .tenant_action_material_source import TenantRuntimeAdmissionIdentity
from .util import content_hash

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class PrivateStrixRuntimeStore(Protocol):
    def _read_current_strix_runtime_authority(
        self, authority_ref: str
    ) -> Mapping[str, Any] | None: ...

    def _read_strix_runtime_authority_event(
        self, authority_ref: str, generation: int, record_digest: str
    ) -> Mapping[str, Any] | None: ...

    def _is_strix_runtime_authority_descendant(
        self,
        *,
        authority_ref: str,
        ancestor_generation: int,
        ancestor_record_digest: str,
        descendant_generation: int,
        descendant_record_digest: str,
    ) -> bool: ...

    def _read_strix_runtime_admission_envelope(
        self, attempt_id: str
    ) -> Mapping[str, Any] | None: ...


_MATERIALIZATION_REF_FIELDS = (
    "scope_record_ref",
    "scope_record_digest",
    "gateway_record_ref",
    "gateway_record_digest",
    "network_plan_ref",
    "network_plan_digest",
    "network_snapshot_ref",
    "network_snapshot_digest",
    "network_verification_ref",
    "network_verification_digest",
    "custody_plan_ref",
    "custody_plan_digest",
    "protected_roots_ref",
    "protected_roots_digest",
    "containment_ref",
    "containment_digest",
    "runtime_install_ref",
    "runtime_install_digest",
    "workspace_ref",
    "workspace_digest",
    "executable_ref",
    "executable_digest",
    "path_environment_ref",
    "path_environment_digest",
    "control_root_ref",
    "control_root_digest",
    "artifact_root_ref",
    "artifact_root_digest",
    "custody_source_ref",
    "custody_record_ref",
    "custody_record_digest",
)


@dataclass(frozen=True, slots=True)
class ProtectedStrixRuntimeAdmissionMaterialization:
    """Live admission plus exact identities reopened by protected registries."""

    admission: StrixRuntimeAdmission
    scope_record_ref: str
    scope_record_digest: str
    gateway_record_ref: str
    gateway_record_digest: str
    network_plan_ref: str
    network_plan_digest: str
    network_snapshot_ref: str
    network_snapshot_digest: str
    network_verification_ref: str
    network_verification_digest: str
    custody_plan_ref: str
    custody_plan_digest: str
    protected_roots_ref: str
    protected_roots_digest: str
    containment_ref: str
    containment_digest: str
    runtime_install_ref: str
    runtime_install_digest: str
    workspace_ref: str
    workspace_digest: str
    executable_ref: str
    executable_digest: str
    path_environment_ref: str
    path_environment_digest: str
    control_root_ref: str
    control_root_digest: str
    artifact_root_ref: str
    artifact_root_digest: str
    custody_source_ref: str
    custody_record_ref: str
    custody_record_digest: str


class ProtectedStrixRuntimeAdmissionMaterializer(Protocol):
    """Resolve only controller-owned opaque refs to one exact live admission."""

    def reopen_exact(
        self, document: Mapping[str, Any]
    ) -> ProtectedStrixRuntimeAdmissionMaterialization: ...


def _authority(record: Mapping[str, Any]) -> StrixRuntimeAuthorityRecord:
    try:
        return StrixRuntimeAuthorityRecord.from_mapping(record["authority"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProductStoreError("retained Strix runtime authority is invalid") from exc


class ProductStoreStrixRuntimeAuthoritySource:
    """Trusted append-only authority source for one configured private owner."""

    def __init__(self, store: PrivateStrixRuntimeStore, *, authority_ref: str) -> None:
        if not isinstance(authority_ref, str) or _DIGEST.fullmatch(authority_ref) is None:
            raise ProductStoreError("Strix runtime authority ref is invalid")
        self._store = store
        self._authority_ref = authority_ref

    def read_current(self) -> StrixRuntimeAuthorityRecord:
        record = self._store._read_current_strix_runtime_authority(self._authority_ref)
        if record is None:
            raise ProductStoreError("Strix runtime authority is not configured")
        return _authority(record)

    def read_exact(
        self, *, generation: int, record_digest: str
    ) -> StrixRuntimeAuthorityRecord | None:
        record = self._store._read_strix_runtime_authority_event(
            self._authority_ref, generation, record_digest
        )
        return None if record is None else _authority(record)

    def is_descendant(
        self,
        *,
        ancestor_generation: int,
        ancestor_record_digest: str,
        descendant_generation: int,
        descendant_record_digest: str,
    ) -> bool:
        return self._store._is_strix_runtime_authority_descendant(
            authority_ref=self._authority_ref,
            ancestor_generation=ancestor_generation,
            ancestor_record_digest=ancestor_record_digest,
            descendant_generation=descendant_generation,
            descendant_record_digest=descendant_record_digest,
        )


class ProductStoreTenantRuntimeAdmissionIdentitySource:
    """Expose exact v19 preparation provenance without reopening live objects."""

    def __init__(self, store: PrivateStrixRuntimeStore) -> None:
        self._store = store

    def reopen_exact(
        self,
        *,
        attempt_id: str,
        binding_digest: str,
        delegation_digest: str,
        authority_generation: int,
        authority_record_digest: str,
        qualification_ref: str,
    ) -> TenantRuntimeAdmissionIdentity | None:
        envelope = self._store._read_strix_runtime_admission_envelope(attempt_id)
        if envelope is None or envelope["admission"] is None:
            return None
        document = envelope["admission"]["document"]
        if (
            envelope["lifecycle_state"] != "verified"
            or document["binding_digest"] != binding_digest
            or document["delegation_digest"] != delegation_digest
            or document["authority_generation"] != authority_generation
            or document["authority_record_digest"] != authority_record_digest
            or document["qualification_ref"] != qualification_ref
        ):
            return None
        return TenantRuntimeAdmissionIdentity(
            schema_version="bluefire.tenant-runtime-admission-identity.v1",
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            delegation_digest=delegation_digest,
            authority_generation=authority_generation,
            authority_record_digest=authority_record_digest,
            qualification_ref=qualification_ref,
            admission_record_ref=envelope["admission"]["admission_record_ref"],
            admission_record_digest=envelope["admission"]["admission_record_digest"],
            custody_source_ref=document["custody_source_ref"],
            custody_record_ref=document["custody_record_ref"],
            custody_record_digest=document["custody_record_digest"],
            admission_proof_bundle_digest=document["admission_proof_bundle_digest"],
        )


def _proof_bundle_digest(
    admission: StrixRuntimeAdmission, *, binding_digest: str, delegation_digest: str
) -> str:
    workspace = asdict(admission.workspace)
    return content_hash(
        {
            "binding_digest": binding_digest,
            "delegation_digest": delegation_digest,
            "build_digest": content_hash(admission.build.to_dict()),
            "network_plan_digest": content_hash(admission.network_plan.to_dict()),
            "network_snapshot_digest": content_hash(admission.network_snapshot.to_dict()),
            "network_verification_digest": content_hash(admission.network_verification.to_dict()),
            "custody_plan_digest": admission.custody_plan.plan_digest,
            "roots_digest": admission.protected_roots.receipt_digest,
            "containment_digest": admission.containment.receipt_digest,
            "scope_digest": content_hash(asdict(admission.scope)),
            "gateway_digest": content_hash(asdict(admission.gateway)),
            "budgets_digest": content_hash(asdict(admission.budgets)),
            "limits_digest": content_hash(asdict(admission.limits)),
            "execution_location_digest": content_hash(
                {
                    "workspace": {name: str(value) for name, value in workspace.items()},
                    "executable": str(admission.executable),
                    "control_root": str(admission.control_root),
                    "path_environment": admission.path_environment,
                }
            ),
        }
    )


class ProductStorePersistedStrixRuntimeAdmissionSource:
    """Materialize an exact saved admission through protected opaque refs."""

    def __init__(
        self,
        store: PrivateStrixRuntimeStore,
        *,
        materializer: ProtectedStrixRuntimeAdmissionMaterializer,
    ) -> None:
        self._store = store
        self._materializer = materializer

    def reopen_exact(
        self,
        *,
        attempt_id: str,
        binding_digest: str,
        delegation_digest: str,
    ) -> PersistedStrixRuntimeAdmissionRecord | None:
        envelope = self._store._read_strix_runtime_admission_envelope(attempt_id)
        if envelope is None or envelope["admission"] is None:
            return None
        retained = envelope["admission"]
        document = retained["document"]
        if (
            document["binding_digest"] != binding_digest
            or document["delegation_digest"] != delegation_digest
        ):
            return None
        materialized = self._materializer.reopen_exact(document)
        if not isinstance(materialized, ProtectedStrixRuntimeAdmissionMaterialization):
            raise ProductStoreError("protected Strix materializer returned an invalid admission")
        admission = materialized.admission
        if not isinstance(admission, StrixRuntimeAdmission) or any(
            getattr(materialized, name) != document[name] for name in _MATERIALIZATION_REF_FIELDS
        ):
            raise ProductStoreError("protected Strix materializer identity changed")
        expected_workspace_attempt = "attempt-" + attempt_id.removeprefix("engine-attempt-")
        exact_proofs = {
            "scope_record_digest": content_hash(asdict(admission.scope)),
            "gateway_record_digest": content_hash(asdict(admission.gateway)),
            "network_plan_digest": content_hash(admission.network_plan.to_dict()),
            "network_snapshot_digest": content_hash(admission.network_snapshot.to_dict()),
            "network_verification_digest": content_hash(admission.network_verification.to_dict()),
            "custody_plan_digest": admission.custody_plan.plan_digest,
            "protected_roots_digest": admission.protected_roots.receipt_digest,
            "containment_digest": admission.containment.receipt_digest,
        }
        if (
            admission.objective_ref != document["objective_ref"]
            or admission.environment_ref != document["environment_ref"]
            or admission.runtime_qualification_ref != document["qualification_ref"]
            or admission.build.to_dict() != document["build"]
            or admission.workspace.attempt_id != expected_workspace_attempt
            or admission.gateway.model != document["model_id"]
            or admission.scope.target_snapshot_digest != document["target_snapshot_digest"]
            or asdict(admission.budgets) != document["budgets"]
            or asdict(admission.limits) != document["limits"]
            or any(document[name] != digest for name, digest in exact_proofs.items())
            or _proof_bundle_digest(
                admission,
                binding_digest=binding_digest,
                delegation_digest=delegation_digest,
            )
            != document["admission_proof_bundle_digest"]
        ):
            raise ProductStoreError("protected Strix admission differs from its retained record")
        return PersistedStrixRuntimeAdmissionRecord(
            schema_version="bluefire.persisted-strix-runtime-admission.v1",
            record_ref=retained["admission_record_ref"],
            record_digest=retained["admission_record_digest"],
            custody_source_ref=document["custody_source_ref"],
            custody_record_ref=document["custody_record_ref"],
            custody_record_digest=document["custody_record_digest"],
            binding_digest=document["binding_digest"],
            authority_generation=document["authority_generation"],
            authority_record_digest=document["authority_record_digest"],
            delegation_digest=document["delegation_digest"],
            lifecycle_state=str(envelope["lifecycle_state"]).upper(),
            lifecycle_head_digest=envelope["lifecycle_head_digest"],
            admission=admission,
        )


__all__ = [
    "ProductStorePersistedStrixRuntimeAdmissionSource",
    "ProductStoreStrixRuntimeAuthoritySource",
    "ProductStoreTenantRuntimeAdmissionIdentitySource",
    "ProtectedStrixRuntimeAdmissionMaterializer",
    "ProtectedStrixRuntimeAdmissionMaterialization",
]
