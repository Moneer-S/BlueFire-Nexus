"""Private durable Installed Strix V2 authority; no execution or allocation.

An activation is imported only from a protected qualification owner, then bound
to the independently reopened ProductStore claim and v20 authority lineage.
Canonical hashes detect damage; they never qualify caller-authored evidence.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol

from . import product_store_engine_execution_claims as claims
from . import product_store_engine_jobs as jobs
from . import product_store_strix_runtime_records as runtime
from .accepted_engine_jobs import AcceptedPreparedEngineAttempt
from .engine_attempt_contract import AttemptState, EngineAttemptBinding, EngineAttemptRecord
from .engine_container_custody import ContainerCustodyPlanV2
from .engine_delegation import EngineCapabilityDelegation
from .engine_installed_attempt_factory import InstalledControlledStrixRuntimeIdentity
from .engine_installed_v2_authority import (
    InstalledStrixV2ActivationReceipt,
    InstalledStrixV2AuthoritySnapshot,
    InstalledStrixV2CompositionError,
    InstalledStrixV2HistoricalSnapshot,
    InstalledStrixV2PrelaunchSnapshot,
    _digest,
    _validate_admission_semantics,
)
from .engine_installed_v2_resources import InstalledStrixV2ResourceReceipt
from .engine_network_policy import HistoricalEngineNetworkPlanV2
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json, utc_now
from .strix_controlled_runtime_admission import (
    HistoricalStrixControlledRuntimeAdmissionV2,
    StrixControlledRuntimeAdmissionV2,
)
from .util import content_hash, parse_iso8601_datetime

if TYPE_CHECKING:
    from .product_store import ProductStore

AUTHORITY_SCHEMA = "bluefire.installed-strix-v2-retained-authority.v1"
PRELAUNCH_SCHEMA = "bluefire.installed-strix-v2-retained-prelaunch.v1"
HISTORICAL_SCHEMA = "bluefire.installed-strix-v2-retained-history.v1"
_MAX_BYTES = 262144
_ACTIVATION_FIELDS = frozenset(
    """
schema_version runtime_resolution_ref admission_ref claim_ref controlled_profile_ref
controlled_launch_digest startup_overlay_ref runtime_closure_plan_ref fixed_exec_receipt_ref
target_scope_admission_ref installed_projection_ref sealed_inputs_ref runtime_image_contract_ref
runtime_image_qualification_ref runtime_image_closure_ref worker_identity_ref caido_mode
caido_test_provider caido_provider_identity_ref caido_terms_acceptance_ref caido_entitlement_ref
caido_live_proof model_provider_kind model_live_proof model_gateway_lease_ref
worker_custody_identity_ref network_policy_digest custody_plan_digest exec_broker_binding_digest
exec_dispatch_authority_ref controller_fence exec_cancellation_ref worker_launch_digest
worker_controller_server_ref worker_custody_ready_receipt_ref operation_watchdog_ref
worker_containment_ref candidate_qualification_ref role_bindings receipt_ref
""".split()
)
_IDENTITY_FIELDS = frozenset(
    """
schema_version backend job_id preparation_ref binding_digest delegation_digest claim_ref
runtime_resolution_ref controlled_profile_ref runtime_admission_ref runtime_activation_ref
controlled_launch_digest startup_overlay_ref runtime_closure_plan_ref fixed_exec_receipt_ref
target_scope_admission_ref installed_projection_ref sealed_inputs_ref runtime_image_contract_ref
runtime_image_qualification_ref runtime_image_closure_ref worker_identity_ref exec_broker_binding_digest
worker_launch_digest worker_controller_server_ref worker_custody_ready_receipt_ref resource_set_digest
launch_digest
""".split()
)
_AUTHORITY_FIELDS = frozenset(
    """
schema_version prelaunch_ref resource_transaction_ref resource_receipt_ref observed_identity_ref
accepted binding delegation claim admission activation identity anchors recorded_at
""".split()
)
_PRELAUNCH_FIELDS = frozenset(
    """
schema_version prelaunch_ref accepted binding delegation claim admission anchors recorded_at
""".split()
)
_HISTORY_FIELDS = frozenset(
    """
schema_version resolution_ref authority_ref saved_record_ref reconciliation_ref identity
activation saved_record retained_authority_digest recorded_at
""".split()
)


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ProductStoreError(f"{label} fields or version changed")
    return value


def _activation(value: object) -> InstalledStrixV2ActivationReceipt:
    row = dict(_exact(value, _ACTIVATION_FIELDS, "V2 retained activation"))
    bindings = row["role_bindings"]
    if type(bindings) is not list:
        raise ProductStoreError("V2 activation role bindings changed")
    row["role_bindings"] = tuple(
        (item["role"], item["binding_ref"])
        for item in (
            _exact(item, frozenset({"role", "binding_ref"}), "V2 role") for item in bindings
        )
    )
    receipt = InstalledStrixV2ActivationReceipt(**row)
    if canonical_json(receipt.document()) != canonical_json(value):
        raise ProductStoreError("V2 activation codec changed its document")
    return receipt


def _identity(value: object) -> InstalledControlledStrixRuntimeIdentity:
    return InstalledControlledStrixRuntimeIdentity(
        **_exact(value, _IDENTITY_FIELDS, "V2 retained runtime identity")
    )


def _bounded(document: Mapping[str, Any]) -> str:
    encoded = canonical_json(document)
    if not 1 <= len(encoded.encode("utf-8")) <= _MAX_BYTES:
        raise ProductStoreError("V2 retained authority exceeds its document bound")
    return encoded


@dataclass(frozen=True, slots=True)
class QualifiedInstalledStrixV2Activation:
    """Exact evidence reopened by the protected component qualification owner."""

    admission: StrixControlledRuntimeAdmissionV2
    activation: InstalledStrixV2ActivationReceipt
    identity: InstalledControlledStrixRuntimeIdentity


@dataclass(frozen=True, slots=True)
class InstalledStrixV2PreactivationRecovery:
    """Cleanup-only locator for a consumed prelaunch transaction."""

    attempt_id: str
    claim_ref: str
    prelaunch_ref: str
    transaction_ref: str
    reconciliation_ref: str
    saved_record_ref: str
    role_owner_bindings: tuple[tuple[str, str, str], ...]
    state: str
    observed_activation_ref: str | None


@dataclass(frozen=True, slots=True)
class InstalledStrixV2ExecutionLineage:
    """Read-only retained identities for joining independently observed proof."""

    attempt_id: str
    job_id: str
    claim_ref: str
    binding_digest: str
    delegation_digest: str
    runtime_resolution_ref: str
    prelaunch_ref: str
    admission_ref: str
    resource_transaction_ref: str
    resource_receipt_ref: str
    runtime_activation_ref: str
    observed_identity_ref: str
    controlled_launch_digest: str
    engine_version: str
    engine_revision: str
    engine_package_digest: str
    policy_overlay_digest: str
    model_data_destination: str
    actual_role_bindings: tuple[tuple[str, str], ...]
    resource_state: str


class ProtectedInstalledStrixV2ActivationSource(Protocol):
    def reopen_qualified_prelaunch(
        self, *, admission_ref: str
    ) -> StrixControlledRuntimeAdmissionV2:
        """Reopen the qualified admission without allocating or launching."""
        ...

    def reopen_qualified_activation(
        self, *, admission_ref: str, activation_ref: str
    ) -> QualifiedInstalledStrixV2Activation:
        """Authenticate all retained receipt references against protected owners.

        This must independently reopen candidate/image qualification, installed
        projection, sealed inputs, worker custody/containment, fixed exec,
        target scope, model gateway, Caido terms/entitlement and role bindings.
        Caller declarations and their hashes do not satisfy this contract.
        Test provider evidence must retain its Test identity and false live proof.
        No allocation, launch, reissuance, credential acquisition or reconnect.
        """
        ...


def _require_claim_at(
    store: ProductStore,
    connection: sqlite3.Connection,
    *,
    accepted: AcceptedPreparedEngineAttempt,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    current_at: str | None,
) -> Mapping[str, Any]:
    delegation.validate_attempt_binding(binding)
    accepted.validate(accepted.job_id, binding, delegation)
    raw_job, prepared, record, _receipt, approval, acceptance = claims._chain(
        store,
        connection,
        job_id=accepted.job_id,
        binding=binding,
        delegation=delegation,
        reviewer=None,
    )
    claims._require_execution_claim_policy(record)
    row = claims._find_existing(
        connection,
        job_id=accepted.job_id,
        attempt_id=binding.attempt_id,
        preparation_ref=record["request_ref"],
        preparation_id=acceptance["preparation_id"],
        acceptance_record_digest=acceptance["record_digest"],
        submission_id=record["submission_id"],
    )
    if row is None:
        raise ResourceConflictError("V2 authority requires its durable accepted execution claim")
    claim = claims._decode_row(row)
    claims._same_claim(
        claim,
        raw_job=raw_job,
        preparation_row=prepared,
        record=record,
        acceptance=acceptance,
        binding=binding,
        delegation=delegation,
        runtime_resolution_ref=accepted.runtime_resolution_ref,
    )
    if any(claim.get(name) != value for name, value in asdict(accepted).items()):
        raise ResourceConflictError("V2 authority accepted claim changed")
    preflight = claims._validate_preflight_snapshot(
        connection,
        claim,
        raw_job=raw_job,
        record=record,
        binding=binding,
        delegation=delegation,
    )
    claims._validate_claim_lifetime(
        claim,
        raw_job=raw_job,
        preparation_row=prepared,
        approval=approval,
        binding=binding,
        delegation=delegation,
        preflight_updated_at=str(preflight["updated_at"]),
    )
    conflict = connection.execute(
        "SELECT 1 FROM engine_attempt_pre_dispatch_settlements WHERE job_id=? OR attempt_id=?",
        (accepted.job_id, binding.attempt_id),
    ).fetchone()
    if conflict is not None:
        raise ProductStoreError("V2 execution claim conflicts with no-dispatch history")
    active = jobs._active_experiment_at(connection, binding.experiment_id)
    _index, entry = active._attempt(binding.attempt_id)
    if (
        entry.job_id != accepted.job_id
        or entry.record.binding != binding
        or entry.delegation_digest != delegation.delegation_digest
    ):
        raise ResourceConflictError("V2 current attempt differs from retained claim")
    if current_at is not None:
        now = parse_iso8601_datetime(current_at)
        if (
            raw_job["state"] != "running"
            or entry.record.state not in {AttemptState.PREFLIGHT, AttemptState.RUNNING}
            or any(
                now >= parse_iso8601_datetime(str(value))
                for value in (prepared["expires_at"], delegation.expires_at, approval["expires_at"])
            )
            or now < parse_iso8601_datetime(str(claim["claimed_at"]))
        ):
            raise ResourceConflictError("V2 execution authority is no longer current")
    return claim


def _anchors_at(
    connection: sqlite3.Connection,
    attempt_id: str,
    *,
    checked_at: str,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
) -> dict[str, Any]:
    from .product_store_strix_admission_issuer import _read_at

    if (
        connection.execute(
            "SELECT 1 FROM strix_runtime_issuance_records WHERE attempt_id=? LIMIT 1",
            (attempt_id,),
        ).fetchone()
        is not None
    ):
        _read_at(connection, attempt_id)
    envelope = runtime._read_strix_runtime_admission_state(connection, attempt_id)
    if envelope["admission"] is None or envelope["lifecycle_state"] != "verified":
        raise ResourceConflictError("V2 runtime admission is no longer verified")
    reservation = envelope["reservation"]["document"]
    if any(
        reservation[name] != expected
        for name, expected in {
            "attempt_id": binding.attempt_id,
            "experiment_id": binding.experiment_id,
            "binding_digest": binding.binding_digest,
            "delegation_digest": delegation.delegation_digest,
            "objective_ref": binding.objective_ref,
            "environment_ref": binding.environment_ref,
            "target_snapshot_digest": binding.target_snapshot_ref,
        }.items()
    ):
        raise ResourceConflictError("V2 runtime admission differs from accepted authority")
    chain = runtime._read_authority_chain(connection, reservation["authority_ref"])
    if not chain:
        raise ResourceConflictError("V2 runtime authority disappeared")
    head = chain[-1]
    if (
        head["authority"]["state"] != "active"
        or head["authority"]["generation"] != reservation["authority_generation"]
        or head["authority_record_digest"] != reservation["authority_record_digest"]
        or head["authority"]["qualification_manifest_ref"] != reservation["qualification_ref"]
        or not parse_iso8601_datetime(reservation["created_at"])
        <= parse_iso8601_datetime(checked_at)
        < parse_iso8601_datetime(reservation["expires_at"])
    ):
        raise ResourceConflictError("V2 runtime authority head or lifetime changed")
    return {
        "authority_ref": reservation["authority_ref"],
        "authority_generation": reservation["authority_generation"],
        "authority_record_digest": reservation["authority_record_digest"],
        "qualification_ref": reservation["qualification_ref"],
        "lifecycle_head_digest": envelope["lifecycle_head_digest"],
        "admission_record_digest": envelope["admission"]["admission_record_digest"],
        "expires_at": reservation["expires_at"],
    }


_ANCHOR_FIELDS = frozenset(
    {
        "authority_ref",
        "authority_generation",
        "authority_record_digest",
        "qualification_ref",
        "lifecycle_head_digest",
        "admission_record_digest",
        "expires_at",
    }
)


def _legacy_prelaunch_ref(resolution_ref: str, admission_ref: str) -> str:
    return content_hash(
        {
            "schema_version": "bluefire.installed-strix-v2-prelaunch-snapshot.v1",
            "resolution_ref": resolution_ref,
            "admission_ref": admission_ref,
        }
    )


def _validate_legacy_admission_binding(
    admission: HistoricalStrixControlledRuntimeAdmissionV2,
    *,
    accepted: AcceptedPreparedEngineAttempt,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
) -> None:
    """Recheck old authority for cleanup only, without minting a launch plan."""

    delegation.validate_attempt_binding(binding)
    accepted.validate(accepted.job_id, binding, delegation)
    row = admission.to_dict()
    claim = row["accepted_execution_claim"]
    expected_claim = {
        "job_id": accepted.job_id,
        "preparation_ref": accepted.preparation_ref,
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "claim_ref": accepted.claim_ref,
        "runtime_resolution_ref": accepted.runtime_resolution_ref,
        "attempt_id": binding.attempt_id,
    }
    if any(claim.get(name) != value for name, value in expected_claim.items()) or any(
        row.get(name) != value
        for name, value in (
            ("attempt_id", binding.attempt_id),
            ("binding_digest", binding.binding_digest),
            ("delegation_digest", delegation.delegation_digest),
            ("objective_ref", binding.objective_ref),
            ("environment_ref", binding.environment_ref),
        )
    ):
        raise ProductStoreError("V2 historical admission claim binding changed")
    _validate_admission_semantics(
        row,
        binding=binding,
        delegation=delegation,
        historical_legacy=True,
    )


def _decode_prelaunch(row: sqlite3.Row, *, historical_legacy: bool = False):
    try:
        document = _exact(json.loads(row["document_json"]), _PRELAUNCH_FIELDS, "V2 prelaunch")
        if (
            document["schema_version"] != PRELAUNCH_SCHEMA
            or row["document_schema"] != PRELAUNCH_SCHEMA
            or _bounded(document) != row["document_json"]
            or content_hash(document) != row["document_digest"]
            or document["recorded_at"] != row["recorded_at"]
        ):
            raise ProductStoreError("V2 prelaunch integrity changed")
        binding = EngineAttemptBinding.from_mapping(document["binding"])
        delegation = EngineCapabilityDelegation.from_mapping(document["delegation"])
        accepted = AcceptedPreparedEngineAttempt(**document["accepted"])
        if historical_legacy:
            admission = HistoricalStrixControlledRuntimeAdmissionV2.from_mapping(
                document["admission"]
            )
            _validate_legacy_admission_binding(
                admission, accepted=accepted, binding=binding, delegation=delegation
            )
            snapshot = None
            prelaunch_ref = _legacy_prelaunch_ref(
                accepted.runtime_resolution_ref, admission.admission_ref
            )
        else:
            admission = StrixControlledRuntimeAdmissionV2.from_mapping(document["admission"])
            snapshot = InstalledStrixV2PrelaunchSnapshot(accepted.runtime_resolution_ref, admission)
            snapshot.validate(accepted=accepted, binding=binding, delegation=delegation)
            prelaunch_ref = snapshot.prelaunch_ref
        expected = {
            "attempt_id": binding.attempt_id,
            "job_id": accepted.job_id,
            "claim_ref": accepted.claim_ref,
            "runtime_resolution_ref": accepted.runtime_resolution_ref,
            "admission_ref": admission.admission_ref,
            "prelaunch_ref": prelaunch_ref,
            "binding_digest": binding.binding_digest,
            "delegation_digest": delegation.delegation_digest,
            "objective_ref": binding.objective_ref,
            "environment_ref": binding.environment_ref,
            "target_snapshot_ref": binding.target_snapshot_ref,
            "scope_ref": binding.scope_ref,
        }
        if (
            any(row[name] != value for name, value in expected.items())
            or document["prelaunch_ref"] != prelaunch_ref
            or document["claim"] != admission.to_dict()["accepted_execution_claim"]
        ):
            raise ProductStoreError("V2 prelaunch index or claim changed")
        _exact(document["anchors"], _ANCHOR_FIELDS, "V2 prelaunch anchors")
        return document, snapshot
    except (
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
        InstalledStrixV2CompositionError,
    ) as exc:
        raise ProductStoreError("V2 prelaunch cannot be decoded") from exc


def _read_prelaunch_at(
    connection: sqlite3.Connection, attempt_id: str, *, historical_legacy: bool = False
):
    row = connection.execute(
        "SELECT * FROM strix_composition_prelaunch_records WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if row is None:
        raise ResourceConflictError("V2 independently qualified prelaunch is unavailable")
    return row, _decode_prelaunch(row, historical_legacy=historical_legacy)


def _decode_authority(
    row: sqlite3.Row,
    *,
    historical_legacy: bool = False,
) -> tuple[
    dict[str, Any],
    InstalledStrixV2AuthoritySnapshot | None,
    InstalledControlledStrixRuntimeIdentity,
]:
    try:
        document = _exact(json.loads(row["document_json"]), _AUTHORITY_FIELDS, "V2 authority")
        if (
            document["schema_version"] != AUTHORITY_SCHEMA
            or row["document_schema"] != AUTHORITY_SCHEMA
            or _bounded(document) != row["document_json"]
            or content_hash(document) != row["document_digest"]
            or document["recorded_at"] != row["recorded_at"]
        ):
            raise ProductStoreError("V2 retained authority integrity changed")
        binding = EngineAttemptBinding.from_mapping(document["binding"])
        delegation = EngineCapabilityDelegation.from_mapping(document["delegation"])
        accepted = AcceptedPreparedEngineAttempt(**document["accepted"])
        accepted.validate(accepted.job_id, binding, delegation)
        if historical_legacy:
            admission = HistoricalStrixControlledRuntimeAdmissionV2.from_mapping(
                document["admission"]
            )
            _validate_legacy_admission_binding(
                admission, accepted=accepted, binding=binding, delegation=delegation
            )
        else:
            admission = StrixControlledRuntimeAdmissionV2.from_mapping(document["admission"])
        activation = _activation(document["activation"])
        identity = _identity(document["identity"])
        if historical_legacy:
            snapshot = None
            network = HistoricalEngineNetworkPlanV2.from_mapping(
                admission.to_dict()["network_plan"]
            )
            custody = ContainerCustodyPlanV2.from_mapping(admission.to_dict()["custody_plan"])
            profile_ref = admission.to_dict()["execution_identity"][
                "controlled_runtime_profile_ref"
            ]
            if (
                activation.runtime_resolution_ref != accepted.runtime_resolution_ref
                or activation.admission_ref != admission.admission_ref
                or activation.claim_ref != accepted.claim_ref
                or activation.controlled_profile_ref != profile_ref
                or activation.controlled_launch_digest != admission.historical_launch_digest
                or activation.network_policy_digest != network.policy_digest
                or activation.custody_plan_digest != custody.plan_digest
                or activation.exec_broker_binding_digest
                != admission.historical_exec_broker_binding_digest
            ):
                raise ProductStoreError("V2 historical activation differs from admission")
        else:
            snapshot = InstalledStrixV2AuthoritySnapshot(
                accepted.runtime_resolution_ref, admission, activation
            )
            snapshot.validate(accepted=accepted, binding=binding, delegation=delegation)
        # Reuse the full historical identity binding validation without creating
        # or retaining a recovery capability.
        historical = InstalledStrixV2HistoricalSnapshot.create(
            resolution_ref=accepted.runtime_resolution_ref,
            saved_record=EngineAttemptRecord.create(binding),
            reconciliation_ref=accepted.claim_ref,
            identity=identity,
            activation=activation,
        )
        historical.validate(
            accepted=accepted,
            binding=binding,
            delegation=delegation,
            saved_record=EngineAttemptRecord.create(binding),
            reconciliation_ref=accepted.claim_ref,
        )
        expected = {
            "attempt_id": binding.attempt_id,
            "job_id": accepted.job_id,
            "claim_ref": accepted.claim_ref,
            "runtime_resolution_ref": accepted.runtime_resolution_ref,
            "admission_ref": admission.admission_ref,
            "prelaunch_ref": _legacy_prelaunch_ref(
                accepted.runtime_resolution_ref, admission.admission_ref
            ),
            "activation_ref": activation.receipt_ref,
            "resource_transaction_ref": document["resource_transaction_ref"],
            "resource_receipt_ref": document["resource_receipt_ref"],
            "binding_digest": binding.binding_digest,
            "delegation_digest": delegation.delegation_digest,
            "objective_ref": binding.objective_ref,
            "environment_ref": binding.environment_ref,
            "target_snapshot_ref": binding.target_snapshot_ref,
            "scope_ref": binding.scope_ref,
        }
        if any(row[name] != value for name, value in expected.items()):
            raise ProductStoreError("V2 retained authority index changed")
        if document["prelaunch_ref"] != expected["prelaunch_ref"]:
            raise ProductStoreError("V2 activated authority changed prelaunch identity")
        _digest(document["resource_transaction_ref"], "V2 activated transaction")
        if (
            document["observed_identity_ref"] != content_hash(asdict(identity))
            or document["resource_receipt_ref"]
            != InstalledStrixV2ResourceReceipt.create(
                action="allocated",
                authority_ref=document["prelaunch_ref"],
                activation_receipt_ref=activation.receipt_ref,
                role_bindings=activation.role_bindings,
            ).receipt_ref
        ):
            raise ProductStoreError("V2 activated identity or resource receipt changed")
        _exact(document["anchors"], _ANCHOR_FIELDS, "V2 retained authority anchors")
        if document["claim"] != admission.to_dict()["accepted_execution_claim"]:
            raise ProductStoreError("V2 admission differs from its exact retained claim")
        return document, snapshot, identity
    except (
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
        InstalledStrixV2CompositionError,
    ) as exc:
        raise ProductStoreError("V2 retained authority cannot be decoded") from exc


def _read_authority_at(
    connection: sqlite3.Connection, attempt_id: str, *, allow_historical_legacy: bool = False
):
    row = connection.execute(
        "SELECT * FROM strix_composition_authority_records WHERE attempt_id=?",
        (attempt_id,),
    ).fetchone()
    if row is None:
        raise ResourceConflictError("V2 independently qualified activation has not been retained")
    try:
        document, snapshot, identity = _decode_authority(row)
    except ProductStoreError:
        if not allow_historical_legacy:
            raise
        document, snapshot, identity = _decode_authority(row, historical_legacy=True)
    historical_legacy = snapshot is None
    _prelaunch_row, (prelaunch, _prelaunch_snapshot) = _read_prelaunch_at(
        connection, attempt_id, historical_legacy=historical_legacy
    )
    if (
        prelaunch["prelaunch_ref"] != document["prelaunch_ref"]
        or prelaunch["accepted"] != document["accepted"]
        or prelaunch["binding"] != document["binding"]
        or prelaunch["delegation"] != document["delegation"]
        or prelaunch["claim"] != document["claim"]
        or prelaunch["admission"] != document["admission"]
        or prelaunch["anchors"] != document["anchors"]
    ):
        raise ProductStoreError("V2 activation differs from retained prelaunch")
    return row, (document, snapshot, identity)


class ProductStoreInstalledStrixV2AuthoritySource:
    """ProductStore-bound authority source with explicit protected evidence import."""

    def __init__(
        self,
        *,
        product_store: ProductStore,
        activations: ProtectedInstalledStrixV2ActivationSource,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        if (
            product_store is None
            or not callable(getattr(activations, "reopen_qualified_prelaunch", None))
            or not callable(getattr(activations, "reopen_qualified_activation", None))
            or not callable(clock)
        ):
            raise ProductStoreError("V2 authority dependencies are invalid")
        self._store = product_store
        self._activations = activations
        self._clock = clock

    def _require_store(self, product_store: ProductStore) -> None:
        if product_store is not self._store:
            raise ProductStoreError("V2 authority source belongs to a different ProductStore")

    def retain_prelaunch(
        self,
        *,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        admission_ref: str,
    ) -> InstalledStrixV2PrelaunchSnapshot:
        admission = self._activations.reopen_qualified_prelaunch(admission_ref=admission_ref)
        if not isinstance(admission, StrixControlledRuntimeAdmissionV2):
            raise ProductStoreError("V2 protected source did not reopen qualified admission")
        admission = StrixControlledRuntimeAdmissionV2.from_mapping(admission.to_dict())
        if admission.admission_ref != admission_ref:
            raise ResourceConflictError("V2 protected admission reference changed")
        snapshot = InstalledStrixV2PrelaunchSnapshot(accepted.runtime_resolution_ref, admission)
        snapshot.validate(accepted=accepted, binding=binding, delegation=delegation)
        timestamp = self._clock()
        with self._store._connection(write=True) as connection:
            claim = _require_claim_at(
                self._store,
                connection,
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                current_at=timestamp,
            )
            if claim != admission.to_dict()["accepted_execution_claim"]:
                raise ResourceConflictError(
                    "V2 prelaunch admission differs from exact accepted claim"
                )
            anchors = _anchors_at(
                connection,
                binding.attempt_id,
                checked_at=timestamp,
                binding=binding,
                delegation=delegation,
            )
            document = {
                "schema_version": PRELAUNCH_SCHEMA,
                "prelaunch_ref": snapshot.prelaunch_ref,
                "accepted": asdict(accepted),
                "binding": binding.to_dict(),
                "delegation": delegation.to_dict(),
                "claim": dict(claim),
                "admission": admission.to_dict(),
                "anchors": anchors,
                "recorded_at": timestamp,
            }
            prior = connection.execute(
                "SELECT * FROM strix_composition_prelaunch_records "
                "WHERE attempt_id=? OR claim_ref=? OR admission_ref=? OR prelaunch_ref=?",
                (binding.attempt_id, accepted.claim_ref, admission_ref, snapshot.prelaunch_ref),
            ).fetchall()
            if prior:
                if len(prior) != 1:
                    raise ResourceConflictError("V2 prelaunch identities diverged")
                existing, saved = _decode_prelaunch(prior[0])
                document["recorded_at"] = existing["recorded_at"]
                if document != existing:
                    raise ResourceConflictError("V2 prelaunch already retained different evidence")
                return saved
            connection.execute(
                "INSERT INTO strix_composition_prelaunch_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    binding.attempt_id,
                    accepted.job_id,
                    accepted.claim_ref,
                    accepted.runtime_resolution_ref,
                    admission_ref,
                    snapshot.prelaunch_ref,
                    binding.binding_digest,
                    delegation.delegation_digest,
                    binding.objective_ref,
                    binding.environment_ref,
                    binding.target_snapshot_ref,
                    binding.scope_ref,
                    PRELAUNCH_SCHEMA,
                    _bounded(document),
                    content_hash(document),
                    timestamp,
                ),
            )
            _row, (_document, saved) = _read_prelaunch_at(connection, binding.attempt_id)
            return saved

    def require_prelaunch_current(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        expected_resolution_ref: str,
    ) -> InstalledStrixV2PrelaunchSnapshot:
        self._require_store(product_store)
        if expected_resolution_ref != accepted.runtime_resolution_ref:
            raise ResourceConflictError("V2 prelaunch resolution changed")
        with self._store._connection() as connection:
            _row, (_document, prior) = _read_prelaunch_at(connection, binding.attempt_id)
        reopened = self._activations.reopen_qualified_prelaunch(
            admission_ref=prior.admission.admission_ref
        )
        if not isinstance(reopened, StrixControlledRuntimeAdmissionV2):
            raise ProductStoreError("V2 protected prelaunch is no longer available")
        timestamp = self._clock()
        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            _row, (document, snapshot) = _read_prelaunch_at(connection, binding.attempt_id)
            claim = _require_claim_at(
                self._store,
                connection,
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                current_at=timestamp,
            )
            self._same_retained(document, accepted, binding, delegation, claim)
            if reopened.to_dict() != document["admission"]:
                raise ResourceConflictError("V2 protected prelaunch admission changed")
            if (
                _anchors_at(
                    connection,
                    binding.attempt_id,
                    checked_at=timestamp,
                    binding=binding,
                    delegation=delegation,
                )
                != document["anchors"]
            ):
                raise ResourceConflictError("V2 prelaunch authority head changed")
            snapshot.validate(accepted=accepted, binding=binding, delegation=delegation)
            return snapshot

    def retain_activation(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        prelaunch_ref: str,
        admission_ref: str,
        activation_ref: str,
        resource_transaction_ref: str,
        observed_identity_ref: str,
    ) -> InstalledStrixV2AuthoritySnapshot:
        self._require_store(product_store)
        with self._store._connection() as connection:
            _prior_row, (_prior_prelaunch, prior_snapshot) = _read_prelaunch_at(
                connection, binding.attempt_id
            )
        if (
            prior_snapshot.prelaunch_ref != prelaunch_ref
            or prior_snapshot.admission.admission_ref != admission_ref
        ):
            raise ResourceConflictError("V2 activation changed the saved admission")
        qualified_prelaunch = self._activations.reopen_qualified_prelaunch(
            admission_ref=admission_ref
        )
        if (
            not isinstance(qualified_prelaunch, StrixControlledRuntimeAdmissionV2)
            or qualified_prelaunch.to_dict() != prior_snapshot.admission.to_dict()
        ):
            raise ResourceConflictError("V2 protected prelaunch changed before activation")
        evidence = self._activations.reopen_qualified_activation(
            admission_ref=admission_ref,
            activation_ref=activation_ref,
        )
        if not isinstance(evidence, QualifiedInstalledStrixV2Activation):
            raise ProductStoreError("V2 protected activation source did not reopen typed evidence")
        # Round-trip through the frozen durable codecs before retention.
        admission = StrixControlledRuntimeAdmissionV2.from_mapping(evidence.admission.to_dict())
        activation = _activation(evidence.activation.document())
        identity = _identity(asdict(evidence.identity))
        if admission.admission_ref != admission_ref or activation.receipt_ref != activation_ref:
            raise ResourceConflictError("V2 protected activation references changed")
        if observed_identity_ref != content_hash(asdict(identity)):
            raise ResourceConflictError("V2 observed identity differs from protected owner")
        snapshot = InstalledStrixV2AuthoritySnapshot(
            accepted.runtime_resolution_ref, admission, activation
        )
        snapshot.validate(accepted=accepted, binding=binding, delegation=delegation)
        timestamp = self._clock()
        with self._store._connection(write=True) as connection:
            from . import product_store_strix_v2_resources as resource_journal

            _prelaunch_row, (prelaunch, prelaunch_snapshot) = _read_prelaunch_at(
                connection, binding.attempt_id
            )
            transaction, replay = resource_journal._read_at(
                connection, _digest(resource_transaction_ref, "V2 resource transaction")
            )
            if (
                transaction["attempt_id"] != binding.attempt_id
                or transaction["authority_ref"] != prelaunch_ref
                or transaction["activation_ref"] is not None
                or transaction["action"] != "execution"
                or transaction["state"] != "allocating"
                or not replay.effects_started
                or replay.activation_ref is not None
            ):
                raise ResourceConflictError("V2 activation lacks its exact allocating intent")
            claim = _require_claim_at(
                self._store,
                connection,
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                current_at=timestamp,
            )
            if claim != admission.to_dict()["accepted_execution_claim"]:
                raise ResourceConflictError(
                    "V2 admission was not bound to the exact accepted claim"
                )
            self._same_retained(prelaunch, accepted, binding, delegation, claim)
            if (
                prelaunch_snapshot.admission.to_dict() != admission.to_dict()
                or prelaunch_snapshot.prelaunch_ref != prelaunch["prelaunch_ref"]
            ):
                raise ResourceConflictError("V2 activation differs from exact prelaunch")
            anchors = _anchors_at(
                connection,
                binding.attempt_id,
                checked_at=timestamp,
                binding=binding,
                delegation=delegation,
            )
            if anchors != prelaunch["anchors"]:
                raise ResourceConflictError("V2 prelaunch authority changed before activation")
            resource_receipt_ref = InstalledStrixV2ResourceReceipt.create(
                action="allocated",
                authority_ref=prelaunch_ref,
                activation_receipt_ref=activation_ref,
                role_bindings=activation.role_bindings,
            ).receipt_ref
            document = {
                "schema_version": AUTHORITY_SCHEMA,
                "prelaunch_ref": prelaunch_snapshot.prelaunch_ref,
                "resource_transaction_ref": resource_transaction_ref,
                "resource_receipt_ref": resource_receipt_ref,
                "observed_identity_ref": observed_identity_ref,
                "accepted": asdict(accepted),
                "binding": binding.to_dict(),
                "delegation": delegation.to_dict(),
                "claim": dict(claim),
                "admission": admission.to_dict(),
                "activation": activation.document(),
                "identity": asdict(identity),
                "anchors": anchors,
                "recorded_at": timestamp,
            }
            prior = connection.execute(
                "SELECT * FROM strix_composition_authority_records WHERE attempt_id=? OR claim_ref=? OR activation_ref=?",
                (binding.attempt_id, accepted.claim_ref, activation_ref),
            ).fetchall()
            if prior:
                if len(prior) != 1:
                    raise ResourceConflictError("V2 authority identities diverged")
                existing, saved, _identity_value = _decode_authority(prior[0])
                document["recorded_at"] = existing["recorded_at"]
                if document != existing:
                    raise ResourceConflictError(
                        "V2 authority activation already retained different evidence"
                    )
                return saved
            encoded = _bounded(document)
            connection.execute(
                """INSERT INTO strix_composition_authority_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    binding.attempt_id,
                    accepted.job_id,
                    accepted.claim_ref,
                    accepted.runtime_resolution_ref,
                    admission_ref,
                    prelaunch_snapshot.prelaunch_ref,
                    activation_ref,
                    resource_transaction_ref,
                    resource_receipt_ref,
                    binding.binding_digest,
                    delegation.delegation_digest,
                    binding.objective_ref,
                    binding.environment_ref,
                    binding.target_snapshot_ref,
                    binding.scope_ref,
                    AUTHORITY_SCHEMA,
                    encoded,
                    content_hash(document),
                    timestamp,
                ),
            )
            _row, (_document, saved, _identity_value) = _read_authority_at(
                connection, binding.attempt_id
            )
            return saved

    def require_current(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        expected_resolution_ref: str,
    ) -> InstalledStrixV2AuthoritySnapshot:
        self._require_store(product_store)
        if expected_resolution_ref != accepted.runtime_resolution_ref:
            raise ResourceConflictError("V2 authority resolution changed")
        # Reopen external protected qualification before the owning SQL read,
        # so a callback that changes a durable head cannot hide behind an older
        # pinned SQLite snapshot. Immutable retained references are reread below.
        with self._store._connection() as connection:
            _prior_row, (_prior_document, prior_snapshot, _prior_identity) = _read_authority_at(
                connection, binding.attempt_id
            )
        evidence = self._activations.reopen_qualified_activation(
            admission_ref=prior_snapshot.admission.admission_ref,
            activation_ref=prior_snapshot.activation.receipt_ref,
        )
        if not isinstance(evidence, QualifiedInstalledStrixV2Activation):
            raise ProductStoreError("V2 protected qualification is no longer available")
        timestamp = self._clock()
        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            _row, (document, snapshot, _identity_value) = _read_authority_at(
                connection, binding.attempt_id
            )
            claim = _require_claim_at(
                self._store,
                connection,
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                current_at=timestamp,
            )
            self._same_retained(document, accepted, binding, delegation, claim)
            if (
                evidence.admission.to_dict() != document["admission"]
                or evidence.activation.document() != document["activation"]
                or asdict(evidence.identity) != document["identity"]
            ):
                raise ResourceConflictError("V2 protected qualification changed after retention")
            if (
                _anchors_at(
                    connection,
                    binding.attempt_id,
                    checked_at=timestamp,
                    binding=binding,
                    delegation=delegation,
                )
                != document["anchors"]
            ):
                raise ResourceConflictError("V2 authority or admission lifecycle head changed")
            snapshot.validate(accepted=accepted, binding=binding, delegation=delegation)
            return snapshot

    def require_active(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        expected_resolution_ref: str,
    ) -> InstalledStrixV2AuthoritySnapshot:
        snapshot = self.require_current(
            product_store=product_store,
            accepted=accepted,
            binding=binding,
            delegation=delegation,
            expected_resolution_ref=expected_resolution_ref,
        )
        from . import product_store_strix_v2_resources as resource_journal

        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            _row, (document, retained, _identity) = _read_authority_at(
                connection, binding.attempt_id
            )
            transaction, replay = resource_journal._read_at(
                connection, document["resource_transaction_ref"]
            )
            if (
                retained != snapshot
                or transaction["state"] != "active"
                or transaction["action"] != "execution"
                or transaction["attempt_id"] != binding.attempt_id
                or replay.activation_ref != snapshot.activation.receipt_ref
            ):
                raise ResourceConflictError("V2 execution resources are not durably active")
            return snapshot

    def reopen_execution_lineage(
        self,
        *,
        product_store: ProductStore,
        attempt_id: str,
        resource_transaction_ref: str,
    ) -> InstalledStrixV2ExecutionLineage:
        """Reopen exact activated history without renewing authority or launching."""

        self._require_store(product_store)
        _digest(resource_transaction_ref, "V2 execution resource transaction")
        from . import product_store_strix_v2_resources as resource_journal

        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            _row, (document, snapshot, _identity) = _read_authority_at(connection, attempt_id)
            transaction, replay = resource_journal._read_at(connection, resource_transaction_ref)
            if (
                document["resource_transaction_ref"] != resource_transaction_ref
                or transaction["action"] != "execution"
                or transaction["attempt_id"] != attempt_id
                or transaction["state"] not in {"active", "stopping", "cleanup_unknown", "closed"}
                or replay.activation_ref != snapshot.activation.receipt_ref
                or replay.resource_receipt_ref != document["resource_receipt_ref"]
                or tuple(replay.actual_bindings) != snapshot.activation.role_bindings
            ):
                raise ResourceConflictError("V2 execution lineage differs from retained resources")
            accepted = AcceptedPreparedEngineAttempt(**document["accepted"])
            binding = EngineAttemptBinding.from_mapping(document["binding"])
            build = snapshot.admission.to_dict()["execution_identity"]["startup_build_identity"]
            return InstalledStrixV2ExecutionLineage(
                attempt_id=attempt_id,
                job_id=accepted.job_id,
                claim_ref=accepted.claim_ref,
                binding_digest=binding.binding_digest,
                delegation_digest=accepted.delegation_digest,
                runtime_resolution_ref=accepted.runtime_resolution_ref,
                prelaunch_ref=snapshot.prelaunch_ref,
                admission_ref=snapshot.admission.admission_ref,
                resource_transaction_ref=resource_transaction_ref,
                resource_receipt_ref=document["resource_receipt_ref"],
                runtime_activation_ref=snapshot.activation.receipt_ref,
                observed_identity_ref=document["observed_identity_ref"],
                controlled_launch_digest=snapshot.activation.controlled_launch_digest,
                engine_version=build["package_version"],
                engine_revision=build["source_revision"],
                engine_package_digest=build["package_sha256"],
                policy_overlay_digest=build["prompt_overlay_sha256"],
                model_data_destination=snapshot.admission.to_dict()["gateway"]["base_url"],
                actual_role_bindings=tuple(replay.actual_bindings),
                resource_state=transaction["state"],
            )

    def reopen_preactivation_recovery(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
        transaction_ref: str,
    ) -> InstalledStrixV2PreactivationRecovery:
        self._require_store(product_store)
        from . import product_store_strix_v2_resources as resource_journal

        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            _row, (document, prelaunch) = _read_prelaunch_at(connection, binding.attempt_id)
            claim = _require_claim_at(
                self._store,
                connection,
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                current_at=None,
            )
            self._same_retained(document, accepted, binding, delegation, claim)
            active = jobs._active_experiment_at(connection, binding.experiment_id)
            _index, entry = active._attempt(binding.attempt_id)
            if entry.record.to_dict() != saved_record.to_dict():
                raise ResourceConflictError("V2 preactivation recovery saved record changed")
            intents = connection.execute(
                "SELECT * FROM engine_attempt_reconciliation_intents "
                "WHERE reconciliation_ref=? OR claim_ref=?",
                (reconciliation_ref, accepted.claim_ref),
            ).fetchall()
            if len(intents) != 1:
                raise ResourceConflictError("V2 preactivation recovery lacks exact intent")
            intent = claims._decode_reconciliation_row(intents[0])
            job = connection.execute(
                "SELECT state FROM jobs WHERE job_id=?", (accepted.job_id,)
            ).fetchone()
            expected = {
                "reconciliation_ref": reconciliation_ref,
                "claim_ref": accepted.claim_ref,
                "job_id": accepted.job_id,
                "attempt_id": binding.attempt_id,
                "experiment_id": binding.experiment_id,
                "binding_digest": binding.binding_digest,
                "delegation_digest": delegation.delegation_digest,
                "runtime_resolution_ref": accepted.runtime_resolution_ref,
                "job_request_digest": claim["job_request_digest"],
            }
            if (
                job is None
                or job["state"] not in claims._RECOVERY_JOB_STATES
                or intent["job_state"] != job["state"]
                or any(intent[name] != value for name, value in expected.items())
            ):
                raise ResourceConflictError("V2 preactivation recovery intent changed")
            transaction, replay = resource_journal._read_at(connection, transaction_ref)
            if (
                transaction["attempt_id"] != binding.attempt_id
                or transaction["authority_ref"] != prelaunch.prelaunch_ref
                or transaction["action"] != "execution"
                or transaction["activation_ref"] is not None
                or transaction["state"] == "active"
                or replay.activation_ref is not None
            ):
                raise ResourceConflictError("V2 transaction is not preactivation recovery")
            activated = connection.execute(
                "SELECT activation_ref FROM strix_composition_authority_records WHERE attempt_id=?",
                (binding.attempt_id,),
            ).fetchone()
            if activated is not None:
                _read_authority_at(connection, binding.attempt_id)
            return InstalledStrixV2PreactivationRecovery(
                attempt_id=binding.attempt_id,
                claim_ref=accepted.claim_ref,
                prelaunch_ref=prelaunch.prelaunch_ref,
                transaction_ref=transaction_ref,
                reconciliation_ref=reconciliation_ref,
                saved_record_ref=content_hash(saved_record.to_dict()),
                role_owner_bindings=tuple(
                    (item["role"], item["binding_ref"], item["owner_ref"])
                    for item in replay.transaction["owners"]
                ),
                state=transaction["state"],
                observed_activation_ref=(
                    None if activated is None else activated["activation_ref"]
                ),
            )

    @staticmethod
    def _same_retained(document, accepted, binding, delegation, claim) -> None:
        expected = {
            "accepted": asdict(accepted),
            "binding": binding.to_dict(),
            "delegation": delegation.to_dict(),
            "claim": dict(claim),
        }
        if any(document[name] != value for name, value in expected.items()):
            raise ResourceConflictError("V2 retained execution authority changed")

    def _historical_at(
        self,
        connection: sqlite3.Connection,
        *,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
    ):
        row, (document, _snapshot, identity) = _read_authority_at(
            connection, binding.attempt_id, allow_historical_legacy=True
        )
        claim = _require_claim_at(
            self._store,
            connection,
            accepted=accepted,
            binding=binding,
            delegation=delegation,
            current_at=None,
        )
        self._same_retained(document, accepted, binding, delegation, claim)
        active = jobs._active_experiment_at(connection, binding.experiment_id)
        _index, entry = active._attempt(binding.attempt_id)
        if entry.record.to_dict() != saved_record.to_dict():
            raise ResourceConflictError("V2 historical saved record is not the persisted attempt")
        intents = connection.execute(
            "SELECT * FROM engine_attempt_reconciliation_intents WHERE reconciliation_ref=? OR claim_ref=?",
            (reconciliation_ref, accepted.claim_ref),
        ).fetchall()
        if len(intents) != 1:
            raise ResourceConflictError(
                "V2 recovery requires its existing exact reconciliation intent"
            )
        intent = claims._decode_reconciliation_row(intents[0])
        job = connection.execute(
            "SELECT state FROM jobs WHERE job_id=?", (accepted.job_id,)
        ).fetchone()
        expected = {
            "reconciliation_ref": reconciliation_ref,
            "claim_ref": accepted.claim_ref,
            "job_id": accepted.job_id,
            "attempt_id": binding.attempt_id,
            "experiment_id": binding.experiment_id,
            "binding_digest": binding.binding_digest,
            "delegation_digest": delegation.delegation_digest,
            "runtime_resolution_ref": accepted.runtime_resolution_ref,
            "job_request_digest": claim["job_request_digest"],
        }
        if (
            job is None
            or job["state"] not in claims._RECOVERY_JOB_STATES
            or intent["job_state"] != job["state"]
            or any(intent[name] != value for name, value in expected.items())
        ):
            raise ResourceConflictError("V2 recovery intent differs from its claim or terminal job")
        historical = InstalledStrixV2HistoricalSnapshot.create(
            resolution_ref=accepted.runtime_resolution_ref,
            saved_record=saved_record,
            reconciliation_ref=reconciliation_ref,
            identity=identity,
            activation=_activation(document["activation"]),
        )
        historical.validate(
            accepted=accepted,
            binding=binding,
            delegation=delegation,
            saved_record=saved_record,
            reconciliation_ref=reconciliation_ref,
        )
        return row, historical

    def ensure_historical(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
    ) -> InstalledStrixV2HistoricalSnapshot:
        self._require_store(product_store)
        with self._store._connection(write=True) as connection:
            row, historical = self._historical_at(
                connection,
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                saved_record=saved_record,
                reconciliation_ref=reconciliation_ref,
            )
            document = {
                "schema_version": HISTORICAL_SCHEMA,
                "resolution_ref": historical.resolution_ref,
                "authority_ref": historical.authority_ref,
                "saved_record_ref": historical.saved_record_ref,
                "reconciliation_ref": reconciliation_ref,
                "identity": asdict(historical.identity),
                "activation": historical.activation.document(),
                "saved_record": saved_record.to_dict(),
                "retained_authority_digest": row["document_digest"],
                "recorded_at": self._clock(),
            }
            previous = connection.execute(
                "SELECT * FROM strix_composition_historical_records WHERE reconciliation_ref=?",
                (reconciliation_ref,),
            ).fetchone()
            if previous is not None:
                retained = self._decode_history(previous, row, historical, saved_record)
                document["recorded_at"] = retained["recorded_at"]
                if document != retained:
                    raise ResourceConflictError(
                        "V2 historical intent already retains different evidence"
                    )
            else:
                connection.execute(
                    "INSERT INTO strix_composition_historical_records VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        reconciliation_ref,
                        binding.attempt_id,
                        accepted.claim_ref,
                        accepted.runtime_resolution_ref,
                        historical.activation.receipt_ref,
                        historical.saved_record_ref,
                        historical.authority_ref,
                        HISTORICAL_SCHEMA,
                        _bounded(document),
                        content_hash(document),
                        document["recorded_at"],
                    ),
                )
            return historical

    @staticmethod
    def _decode_history(row, authority_row, historical, saved_record):
        document = _exact(json.loads(row["document_json"]), _HISTORY_FIELDS, "V2 historical record")
        expected = {
            "reconciliation_ref": historical.reconciliation_ref,
            "attempt_id": saved_record.binding.attempt_id,
            "claim_ref": historical.identity.claim_ref,
            "runtime_resolution_ref": historical.resolution_ref,
            "activation_ref": historical.activation.receipt_ref,
            "saved_record_ref": historical.saved_record_ref,
            "authority_ref": historical.authority_ref,
        }
        if (
            document["schema_version"] != HISTORICAL_SCHEMA
            or row["document_schema"] != HISTORICAL_SCHEMA
            or _bounded(document) != row["document_json"]
            or content_hash(document) != row["document_digest"]
            or document["recorded_at"] != row["recorded_at"]
            or document["retained_authority_digest"] != authority_row["document_digest"]
            or document["saved_record"] != saved_record.to_dict()
            or _identity(document["identity"]) != historical.identity
            or _activation(document["activation"]) != historical.activation
            or any(row[name] != value for name, value in expected.items())
            or any(
                document[name] != value
                for name, value in {
                    "resolution_ref": historical.resolution_ref,
                    "authority_ref": historical.authority_ref,
                    "saved_record_ref": historical.saved_record_ref,
                    "reconciliation_ref": historical.reconciliation_ref,
                }.items()
            )
        ):
            raise ProductStoreError("V2 historical authority integrity changed")
        return document

    def reopen_reconciliation(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
    ) -> InstalledStrixV2HistoricalSnapshot:
        self._require_store(product_store)
        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            authority_row, historical = self._historical_at(
                connection,
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                saved_record=saved_record,
                reconciliation_ref=reconciliation_ref,
            )
            row = connection.execute(
                "SELECT * FROM strix_composition_historical_records WHERE reconciliation_ref=?",
                (reconciliation_ref,),
            ).fetchone()
            if row is None:
                raise ResourceConflictError("V2 historical authority has not been retained")
            self._decode_history(row, authority_row, historical, saved_record)
            return historical
