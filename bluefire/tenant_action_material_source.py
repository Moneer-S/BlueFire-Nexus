"""Installed-controller source for immutable tenant preparation slots.

Candidates come only from retained protected controller material. This source
never launches a generation, mints an engine admission, or refreshes authority.
The first persistence is atomic with the existing preparation/approval owner.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping, Protocol

from .engine_action_preparation import EngineActionPreparationError, EngineWorkspaceAction
from .engine_attempt_contract import EngineAttemptBinding
from .engine_delegation import EngineCapabilityDelegation
from .engine_experiment import EngineExperiment
from .product_store_engine_actions import _tenant_mechanism, _tenant_plan
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json
from .product_store_tenant_action_materials import SLOT_SCHEMA, SlotValidator
from .strix_adapter import StrixBuildIdentity
from .strix_engine_runtime import StrixRuntimeAdmission, StrixRuntimeAdmissionResolver
from .strix_runtime_admission_resolver import (
    AppendOnlyStrixRuntimeAuthoritySource,
    StrixRuntimeAuthorityRecord,
)
from .tenant_engine_action_preparer import (
    ActiveTenantGenerationSource,
    ControllerOwnedTenantActionPreparer,
    RetainedTenantActionMaterialSource,
    TenantActionPreparationMaterial,
    TenantControllerCheckIdentity,
    TenantEngineAttemptIdentity,
    TenantEnginePreparationPolicy,
)
from .tenant_record_generation_source import _lifecycle, _validate_journal
from .tenant_record_target_adapter import TenantGenerationExpectation, TenantRunningGeneration
from .util import content_hash, parse_iso8601_datetime

_ENGINE = {EngineWorkspaceAction.START_BASELINE, EngineWorkspaceAction.START_ADAPTIVE_SEARCH}
_UNAVAILABLE = {EngineWorkspaceAction.RECONCILE_DEFENSE, EngineWorkspaceAction.RECONCILE_ROLLBACK}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class TenantRuntimeAdmissionIdentity:
    """Controller-saved immutable record identity, never synthesized here.

    A concrete persisted-admission owner must provide this envelope. The
    existing resolver alone does not expose it, so engine issuance without an
    injected identity source is deliberately unavailable.
    """

    schema_version: str
    attempt_id: str
    binding_digest: str
    delegation_digest: str
    authority_generation: int
    authority_record_digest: str
    qualification_ref: str
    admission_record_ref: str
    admission_record_digest: str
    custody_source_ref: str
    custody_record_ref: str
    custody_record_digest: str
    admission_proof_bundle_digest: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != "bluefire.tenant-runtime-admission-identity.v1"
            or not isinstance(self.attempt_id, str)
            or re.fullmatch(r"engine-attempt-[0-9a-f]{32}", self.attempt_id) is None
            or type(self.authority_generation) is not int
            or not 1 <= self.authority_generation <= 2**63 - 1
        ):
            raise EngineActionPreparationError("persisted admission identity is invalid")
        for name in self.__dataclass_fields__:
            if name not in {"schema_version", "attempt_id", "authority_generation"}:
                value = getattr(self, name)
                if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                    raise EngineActionPreparationError("persisted admission reference is invalid")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> TenantRuntimeAdmissionIdentity:
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise EngineActionPreparationError("persisted admission identity fields changed")
        return cls(**value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TenantRuntimeAdmissionIdentitySource(Protocol):
    """Read only exact durable admission/custody provenance; never create it."""

    def reopen_exact(
        self,
        *,
        attempt_id: str,
        binding_digest: str,
        delegation_digest: str,
        authority_generation: int,
        authority_record_digest: str,
        qualification_ref: str,
    ) -> TenantRuntimeAdmissionIdentity | None: ...


def _admission_proofs(
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    saved: StrixRuntimeAdmission,
) -> dict[str, Any]:
    """Supplemental reopened proofs, not a persisted admission record identity."""
    return {
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "build_digest": content_hash(saved.build.to_dict()),
        "network_plan_digest": content_hash(saved.network_plan.to_dict()),
        "network_snapshot_digest": content_hash(saved.network_snapshot.to_dict()),
        "network_verification_digest": content_hash(saved.network_verification.to_dict()),
        "custody_plan_digest": saved.custody_plan.plan_digest,
        "roots_digest": saved.protected_roots.receipt_digest,
        "containment_digest": saved.containment.receipt_digest,
        "scope_digest": content_hash(asdict(saved.scope)),
        "gateway_digest": content_hash(asdict(saved.gateway)),
        "budgets_digest": content_hash(asdict(saved.budgets)),
        "limits_digest": content_hash(asdict(saved.limits)),
        "execution_location_digest": content_hash(
            {
                "workspace": {name: str(value) for name, value in asdict(saved.workspace).items()},
                "executable": str(saved.executable),
                "control_root": str(saved.control_root),
                "path_environment": saved.path_environment,
            }
        ),
    }


class TenantActionSlotStore(Protocol):
    def _read_tenant_action_material_slot(
        self,
        *,
        experiment_id: str,
        experiment_revision: int,
        experiment_digest: str,
        action_kind: str,
    ) -> Mapping[str, Any] | None: ...

    def _retain_tenant_action_material_preparation(
        self,
        *,
        document: Mapping[str, Any],
        validator: SlotValidator,
        preparation_values: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def get_engine_experiment(self, experiment_id: str) -> Mapping[str, Any]: ...

    def get_protected_engine_action_preparation(self, request_ref: str) -> Mapping[str, Any]: ...


class TenantGenerationJournalReader(Protocol):
    def read(self) -> Mapping[str, Any]: ...


def _material_document(material: TenantActionPreparationMaterial) -> dict[str, Any]:
    policy = None
    if material.engine_policy is not None:
        policy = asdict(material.engine_policy)
        policy["model_authority_ref"] = policy.pop("model_authorization_ref")
    return {
        "prepared_at": material.prepared_at,
        "expires_at": material.expires_at,
        "target": asdict(material.target),
        "engine_identity": (
            None if material.engine_identity is None else asdict(material.engine_identity)
        ),
        "engine_policy": policy,
        "check_identity": (
            None if material.check_identity is None else asdict(material.check_identity)
        ),
        "defense_plan": None if material.defense_plan is None else material.defense_plan.to_dict(),
        "mechanism": None if material.mechanism is None else material.mechanism.to_dict(),
        "change_id": material.change_id,
    }


def _material(document: Mapping[str, Any]) -> TenantActionPreparationMaterial:
    row = document["material"]
    if not isinstance(row, Mapping) or set(row) != {
        "prepared_at",
        "expires_at",
        "target",
        "engine_identity",
        "engine_policy",
        "check_identity",
        "defense_plan",
        "mechanism",
        "change_id",
    }:
        raise EngineActionPreparationError("tenant material fields changed")
    policy = None
    if row["engine_policy"] is not None:
        policy_row = dict(row["engine_policy"])
        policy_row["model_authorization_ref"] = policy_row.pop("model_authority_ref")
        policy_row["build"] = StrixBuildIdentity(**policy_row["build"])
        policy = TenantEnginePreparationPolicy(**policy_row)
    result = TenantActionPreparationMaterial(
        experiment_id=document["experiment_id"],
        experiment_revision=document["experiment_revision"],
        experiment_digest=document["experiment_digest"],
        action=EngineWorkspaceAction(document["action_kind"]),
        prepared_at=row["prepared_at"],
        expires_at=row["expires_at"],
        target=TenantGenerationExpectation(**row["target"]),
        engine_identity=(
            None
            if row["engine_identity"] is None
            else TenantEngineAttemptIdentity(**row["engine_identity"])
        ),
        engine_policy=policy,
        check_identity=(
            None
            if row["check_identity"] is None
            else TenantControllerCheckIdentity(**row["check_identity"])
        ),
        defense_plan=None if row["defense_plan"] is None else _tenant_plan(row["defense_plan"]),
        mechanism=None if row["mechanism"] is None else _tenant_mechanism(row["mechanism"]),
        change_id=row["change_id"],
    )
    if _material_document(result) != row:
        raise EngineActionPreparationError("tenant material is not canonical")
    return result


class ProductStoreTenantActionMaterialSource:
    """Exact private reopen and atomic issuer, injected only by a controller.

    ``candidate_source`` supplies already retained controller identities and
    policy for first issuance. It cannot be populated from the browser request.
    After a commit, reopening depends solely on the slot and current authority.
    A missing candidate or admission is a refusal, never a provisioning request.
    """

    def __init__(
        self,
        *,
        store: TenantActionSlotStore,
        generation_journal: TenantGenerationJournalReader,
        generation_source: ActiveTenantGenerationSource,
        runtime_authority_source: AppendOnlyStrixRuntimeAuthoritySource,
        runtime_resolver: StrixRuntimeAdmissionResolver,
        clock: Callable[[], str],
        candidate_source: RetainedTenantActionMaterialSource | None = None,
        admission_identity_source: TenantRuntimeAdmissionIdentitySource | None = None,
    ) -> None:
        self._store = store
        self._journal = generation_journal
        self._generations = generation_source
        self._authority = runtime_authority_source
        self._resolver = runtime_resolver
        self._clock = clock
        self._candidates = candidate_source
        self._admission_identities = admission_identity_source

    def reopen_exact(
        self,
        *,
        experiment_id: str,
        experiment_revision: int,
        experiment_digest: str,
        action: EngineWorkspaceAction,
    ) -> TenantActionPreparationMaterial | None:
        if action in _UNAVAILABLE:
            raise EngineActionPreparationError("tenant reconciliation preparation is unavailable")
        key = dict(
            experiment_id=experiment_id,
            experiment_revision=experiment_revision,
            experiment_digest=experiment_digest,
            action_kind=action.value,
        )
        try:
            record = self._store._read_tenant_action_material_slot(
                experiment_id=experiment_id,
                experiment_revision=experiment_revision,
                experiment_digest=experiment_digest,
                action_kind=action.value,
            )
            if record is not None:
                self._validate(record["document"])
                protected = self._store.get_protected_engine_action_preparation(
                    record["preparation_ref"]
                )
                if protected["request_ref"] != record["preparation_ref"]:
                    raise EngineActionPreparationError("tenant preparation provenance changed")
                return _material(record["document"])
            if self._candidates is None:
                return None
            candidate = self._candidates.reopen_exact(
                experiment_id=experiment_id,
                experiment_revision=experiment_revision,
                experiment_digest=experiment_digest,
                action=action,
            )
            if candidate is None:
                return None
            if not isinstance(candidate, TenantActionPreparationMaterial) or (
                candidate.experiment_id,
                candidate.experiment_revision,
                candidate.experiment_digest,
                candidate.action,
            ) != (experiment_id, experiment_revision, experiment_digest, action):
                raise EngineActionPreparationError("tenant candidate identity changed")
            # Round-trip drops no fields and rejects malformed typed authority.
            _material({**key, "material": _material_document(candidate)})
            return candidate
        except (ProductStoreError, TypeError, ValueError, KeyError, AttributeError) as exc:
            raise EngineActionPreparationError("protected tenant slot is unavailable") from exc

    def retainer(
        self,
        *,
        material: TenantActionPreparationMaterial,
        experiment: EngineExperiment,
        workspace_digest: str,
    ) -> Callable[..., Mapping[str, Any]]:
        document = self._snapshot(material, experiment, workspace_digest)

        def retain(**values: Any) -> Mapping[str, Any]:
            expected = {
                "experiment_id": material.experiment_id,
                "experiment_revision": material.experiment_revision,
                "experiment_digest": material.experiment_digest,
                "workspace_digest": workspace_digest,
                "action": material.action,
                "expires_at": material.expires_at,
            }
            if any(values.get(name) != value for name, value in expected.items()):
                raise ResourceConflictError("tenant preparation material binding changed")
            # Retained chronology is immutable; only exact committed retry can
            # bypass the store's 60-second new-preparation check.
            values["prepared_at"] = material.prepared_at
            return self._store._retain_tenant_action_material_preparation(
                document=document,
                validator=self._validate,
                preparation_values=values,
            )

        return retain

    def _validate(self, document: Mapping[str, Any]) -> Mapping[str, Any]:
        if (
            not isinstance(document, Mapping)
            or set(document)
            != {
                "schema_version",
                "experiment_id",
                "experiment_revision",
                "experiment_digest",
                "action_kind",
                "workspace_digest",
                "material",
                "generation_journal",
                "running_generation",
                "runtime",
                "controller_lineage",
            }
            or document["schema_version"] != SLOT_SCHEMA
        ):
            raise EngineActionPreparationError("tenant slot fields changed")
        material = _material(document)
        experiment = self._experiment(material)
        expected = self._snapshot(material, experiment, document["workspace_digest"])
        if canonical_json(expected) != canonical_json(document):
            raise EngineActionPreparationError("tenant slot current authority changed")
        return document

    def _experiment(self, material: TenantActionPreparationMaterial) -> EngineExperiment:
        record = self._store.get_engine_experiment(material.experiment_id)
        if (
            record.get("active") is not True
            or record.get("revision") != material.experiment_revision
            or record.get("digest") != material.experiment_digest
        ):
            raise ResourceConflictError("tenant material experiment head changed")
        experiment = EngineExperiment._from_controller_mapping(record["document"])
        if experiment.digest != material.experiment_digest:
            raise EngineActionPreparationError("tenant material experiment digest changed")
        return experiment

    def _snapshot(
        self,
        material: TenantActionPreparationMaterial,
        experiment: EngineExperiment,
        workspace_digest: str,
    ) -> dict[str, Any]:
        if material.action in _UNAVAILABLE:
            raise EngineActionPreparationError("tenant reconciliation preparation is unavailable")
        ControllerOwnedTenantActionPreparer._check_material_shape(material)
        now = parse_iso8601_datetime(self._clock())
        created = parse_iso8601_datetime(material.prepared_at)
        expires = parse_iso8601_datetime(material.expires_at)
        if not (
            parse_iso8601_datetime(experiment.updated_at) <= created <= now < expires
            and 0 < (expires - created).total_seconds() <= 7800
        ):
            raise EngineActionPreparationError("tenant material slot is stale")
        journal = self._journal.read()
        payload = _validate_journal(journal["document"])
        generation = self._generations.checked_running(material.target)
        if not isinstance(generation, TenantRunningGeneration):
            raise EngineActionPreparationError("running tenant generation is unavailable")
        generation = TenantRunningGeneration(
            **{name: getattr(generation, name) for name in generation.__dataclass_fields__}
        )
        if (
            journal["owner_id"] != experiment.experiment_id
            or journal["active"] is not True
            or payload["phase"] != "running"
            or payload["active"] is None
            or payload["active"]["lifecycle"] is None
            or content_hash(payload) != journal["digest"]
            or _lifecycle(payload["active"]["lifecycle"]) != generation.lifecycle
            or generation.lifecycle.plan.digest != material.target.plan_digest
            or generation.lifecycle.digest != material.target.lifecycle_digest
            or generation.config.target_snapshot_id != material.target.target_snapshot_id
            or generation.config.service_generation != material.target.service_generation
            or payload["active"]["packet"]
            != {
                "run_id": generation.packet.run_id,
                "attempt_id": generation.packet.attempt_id,
                "created_at": generation.packet.created_at,
                "defense_mode": generation.config.mode,
            }
            or not (
                parse_iso8601_datetime(generation.packet.created_at)
                <= created
                <= parse_iso8601_datetime(generation.packet.verified_at)
                < expires
                <= parse_iso8601_datetime(generation.packet.expires_at)
            )
        ):
            raise EngineActionPreparationError("tenant generation journal binding changed")
        packet = asdict(generation.packet)
        del packet["verified_at"]  # Fresh liveness observation is not retained authority.
        runtime = None
        if material.action in _ENGINE:
            if self._admission_identities is None:
                raise EngineActionPreparationError(
                    "exact persisted admission identity source is unavailable"
                )
            binding, delegation = ControllerOwnedTenantActionPreparer._engine_authority(
                experiment, material
            )
            authority = self._authority.read_current()
            if not isinstance(authority, StrixRuntimeAuthorityRecord):
                raise EngineActionPreparationError("runtime authority is unavailable")
            authority = StrixRuntimeAuthorityRecord.from_mapping(authority.to_dict())
            saved = self._resolver.resolve(binding, delegation)
            if (
                authority.state != "active"
                or saved.runtime_qualified is not True
                or saved.runtime_qualification_ref != authority.qualification_manifest_ref
                or content_hash(saved.build.to_dict()) != authority.strix_build_digest
                or self._authority.read_current() != authority
            ):
                raise EngineActionPreparationError("runtime authority generation changed")
            proofs = _admission_proofs(binding, delegation, saved)
            identity_key: dict[str, Any] = {
                "attempt_id": binding.attempt_id,
                "binding_digest": binding.binding_digest,
                "delegation_digest": delegation.delegation_digest,
                "authority_generation": authority.generation,
                "authority_record_digest": content_hash(authority.to_dict()),
                "qualification_ref": authority.qualification_manifest_ref,
            }
            identity = self._admission_identities.reopen_exact(**identity_key)
            if not isinstance(identity, TenantRuntimeAdmissionIdentity):
                raise EngineActionPreparationError("exact persisted admission identity is missing")
            identity = TenantRuntimeAdmissionIdentity.from_mapping(identity.to_dict())
            if (
                any(identity.to_dict()[name] != value for name, value in identity_key.items())
                or identity.admission_proof_bundle_digest != content_hash(proofs)
                or self._admission_identities.reopen_exact(**identity_key) != identity
            ):
                raise EngineActionPreparationError("exact persisted admission identity changed")
            runtime = {
                "authority_generation": authority.generation,
                "authority_record_digest": content_hash(authority.to_dict()),
                "qualification_ref": authority.qualification_manifest_ref,
                "proofs": proofs,
                # The existing resolver exposes reopened proof objects, not
                # a persisted admission record envelope or record reference.
                "admission_proof_bundle_digest": content_hash(proofs),
                "admission_identity": identity.to_dict(),
                "admission_identity_digest": content_hash(identity.to_dict()),
            }
        if self._journal.read() != journal:
            raise EngineActionPreparationError("tenant generation journal changed during read")
        self._experiment(material)
        return {
            "schema_version": SLOT_SCHEMA,
            "experiment_id": material.experiment_id,
            "experiment_revision": material.experiment_revision,
            "experiment_digest": material.experiment_digest,
            "action_kind": material.action.value,
            "workspace_digest": workspace_digest,
            "material": _material_document(material),
            "generation_journal": {
                "owner_id": journal["owner_id"],
                "journal_id": journal["journal_id"],
                "revision": journal["revision"],
                "digest": journal["digest"],
                "inputs_digest": payload["inputs_digest"],
            },
            "running_generation": {
                "expectation": asdict(material.target),
                "packet": packet,
                "fixture_digest": generation.fixture.digest,
                "config_digest": generation.config.digest,
                "admission_digests": generation.admission_digests,
            },
            "runtime": runtime,
            "controller_lineage": {
                "plan_digest": (
                    None if material.defense_plan is None else material.defense_plan.digest
                ),
                "mechanism_digest": (
                    None
                    if material.mechanism is None
                    else content_hash(material.mechanism.to_dict())
                ),
                "change_digest": (
                    None
                    if experiment.defense_change is None
                    else content_hash(experiment.defense_change.to_dict())
                ),
                "observations": [
                    content_hash(item.to_dict()) for item in experiment.independent_observations
                ],
                "checks": [content_hash(item.to_dict()) for item in experiment.checks],
            },
        }
