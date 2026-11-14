"""Private ProductStore journal for installed Strix V2 resource ownership.

Every write replays the persisted journal before advancing its head. The journal
records platform observations; a role close or a cleanup Boolean is never an
absence observation. No part of this repository allocates a platform resource.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Iterator, Protocol

from .accepted_engine_jobs import AcceptedPreparedEngineAttempt
from .engine_attempt_contract import EngineAttemptBinding, EngineAttemptRecord
from .engine_container_custody import ContainerCustodyPlanV2
from .engine_delegation import EngineCapabilityDelegation
from .engine_installed_attempt_factory import (
    INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
    INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES,
)
from .engine_installed_cleanup import (
    InstalledEngineBundleCleanupReceipt,
    InstalledEngineCleanupError,
    InstalledEngineCleanupResourceBinding,
    InstalledEngineResourceCleanupOutcome,
    cleanup_request_ref,
    resource_set_ref,
    validate_cleanup_receipt,
)
from .engine_installed_v2_authority import (
    InstalledStrixV2ActivationReceipt,
    InstalledStrixV2AuthorityGuard,
    InstalledStrixV2CompositionError,
    InstalledStrixV2HistoricalSnapshot,
    _digest,
)
from .engine_installed_v2_product_store import (
    InstalledStrixV2CleanupAbsenceObserver,
    InstalledStrixV2TransactionHead,
    installed_strix_v2_prelaunch_binding_ref,
    installed_strix_v2_reconciliation_binding_ref,
)
from .engine_installed_v2_resources import (
    InstalledStrixV2CleanupReceipt,
    InstalledStrixV2ResourceReceipt,
)
from .engine_network_policy import EngineNetworkPlanV2
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash, parse_iso8601_datetime

if TYPE_CHECKING:
    from .product_store import ProductStore

TRANSACTION_SCHEMA = "bluefire.installed-strix-v2-resource-transaction.v1"
EVENT_SCHEMA = "bluefire.installed-strix-v2-resource-event.v1"
_MAX_BYTES = 262144
_MAX_GENERATION = 4096
_TRANSACTION_FIELDS = frozenset(
    {
        "schema_version",
        "action",
        "authority_ref",
        "activation_ref",
        "reconciliation_ref",
        "role_bindings",
        "constraints",
        "transaction_ref",
        "owners",
    }
)
_EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "transaction_ref",
        "attempt_id",
        "authority_ref",
        "activation_ref",
        "action",
        "reconciliation_ref",
        "generation",
        "event_type",
        "state",
        "role",
        "owner_ref",
        "binding_ref",
        "receipt_ref",
        "previous_digest",
        "created_at",
        "document",
    }
)
_INDEX_FIELDS = (
    "transaction_ref",
    "attempt_id",
    "authority_ref",
    "activation_ref",
    "action",
    "reconciliation_ref",
)
_EVENT_INDEX_FIELDS = (
    "transaction_ref",
    "event_type",
    "state",
    "role",
    "owner_ref",
    "binding_ref",
    "receipt_ref",
    "previous_digest",
    "created_at",
)
_TRANSITIONS = {
    "allocation_started": ({"prepared"}, "allocating"),
    "activation_recorded": ({"allocating"}, "allocating"),
    "role_allocated": ({"allocating"}, "allocating"),
    "allocated": ({"allocating"}, "allocated"),
    "commit_started": ({"allocated"}, "committing"),
    "committed": ({"committing"}, "active"),
    "settlement_started": ({"active"}, "stopping"),
    "role_stop_claimed": ({"stopping", "cleanup_unknown"}, None),
    "role_terminal": ({"stopping", "cleanup_unknown"}, None),
    "bundle_absence_observed": ({"stopping", "cleanup_unknown"}, None),
    "bundle_receipt_recorded": ({"stopping", "cleanup_unknown"}, "receipt"),
    "cleanup_started": (
        {"prepared", "allocating", "allocated", "committing", "cleanup_unknown"},
        "stopping",
    ),
    "absence_observed": ({"stopping", "cleanup_unknown"}, "stopping"),
    "cleanup_unknown": ({"stopping", "cleanup_unknown"}, "cleanup_unknown"),
    "cleaned": ({"stopping"}, "closed"),
}


class InstalledStrixV2RoleTerminalObserver(Protocol):
    """Protected, durable role-specific source of terminal evidence."""

    def reopen_role_terminal(self, *, role: str, source_receipt_ref: str) -> Mapping[str, Any]: ...

    def role_identity_ref(self, role: str) -> str: ...


@dataclass(frozen=True, slots=True)
class InstalledStrixV2SettlementSnapshot:
    transaction_ref: str
    attempt_id: str
    action: str
    authority_ref: str
    claim_ref: str
    runtime_activation_ref: str
    attempt_ref: str
    runtime_resolution_ref: str
    saved_record_ref: str | None
    reconciliation_ref: str | None
    generation: int
    state: str
    role_owner_bindings: tuple[tuple[str, str, str], ...]
    actual_role_bindings: tuple[tuple[str, str], ...]
    role_outcomes: tuple[InstalledEngineResourceCleanupOutcome | None, ...]
    stop_claimed_roles: tuple[str, ...]
    whole_absence_ref: str | None
    retained_receipt: InstalledEngineBundleCleanupReceipt | None
    resource_set_ref: str
    owner_ref: str
    cleanup_ref: str


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ProductStoreError(f"V2 resource {label} fields changed")
    return value


def _bounded(value: Mapping[str, Any]) -> str:
    encoded = canonical_json(value)
    if not 1 <= len(encoded.encode("utf-8")) <= _MAX_BYTES:
        raise ProductStoreError("V2 resource journal document exceeds its bound")
    return encoded


def _copy_document(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProductStoreError("V2 resource journal document is invalid")
    return json.loads(_bounded(dict(value)))


def _decode_bundle_receipt(value: object) -> InstalledEngineBundleCleanupReceipt:
    document = _exact(
        value,
        frozenset(
            {
                "schema_version",
                "cleanup_ref",
                "attempt_ref",
                "activation_ref",
                "owner_ref",
                "runtime_resolution_ref",
                "resource_set_ref",
                "generation",
                "predecessor_receipt_ref",
                "state",
                "outcomes",
                "settled_at",
                "receipt_ref",
            }
        ),
        "bundle receipt",
    )
    if type(document["outcomes"]) is not list:
        raise ProductStoreError("V2 bundle receipt outcomes changed")
    try:
        outcomes = tuple(
            InstalledEngineResourceCleanupOutcome(
                **_exact(
                    item,
                    frozenset({"role", "resource_ref", "state", "evidence_ref"}),
                    "bundle outcome",
                )
            )
            for item in document["outcomes"]
        )
        return InstalledEngineBundleCleanupReceipt(
            **{name: item for name, item in document.items() if name != "outcomes"},
            outcomes=outcomes,
        )
    except (TypeError, ValueError, InstalledEngineCleanupError) as exc:
        raise ProductStoreError("V2 bundle receipt is invalid") from exc


def _transaction(document: object, index: Mapping[str, Any]) -> dict[str, Any]:
    document = _exact(document, _TRANSACTION_FIELDS, "transaction")
    if document["schema_version"] != TRANSACTION_SCHEMA:
        raise ProductStoreError("V2 resource transaction version changed")
    if index["action"] not in {"execution", "reconciliation"}:
        raise ProductStoreError("V2 resource transaction action is invalid")
    for name in ("transaction_ref", "authority_ref"):
        _digest(index[name], "V2 resource " + name)
    if index["activation_ref"] is not None:
        _digest(index["activation_ref"], "V2 resource activation_ref")
    if not isinstance(index["attempt_id"], str) or not index["attempt_id"].strip():
        raise ProductStoreError("V2 resource attempt is invalid")
    reconciliation_ref = index["reconciliation_ref"]
    if (index["action"] == "reconciliation") != (reconciliation_ref is not None) or (
        index["action"] == "execution"
    ) != (index["activation_ref"] is None):
        raise ProductStoreError("V2 resource transaction reconciliation changed")
    if reconciliation_ref is not None:
        _digest(reconciliation_ref, "V2 resource reconciliation")
    if any(document[name] != index[name] for name in _INDEX_FIELDS if name != "attempt_id"):
        raise ProductStoreError("V2 resource transaction binding changed")
    bindings = document["role_bindings"]
    roles = (
        INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES
        if index["action"] == "execution"
        else INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES
    )
    if type(bindings) is not list or len(bindings) != len(roles):
        raise ProductStoreError("V2 resource transaction roles are incomplete")
    for item, role in zip(bindings, roles, strict=True):
        item = _exact(item, frozenset({"role", "binding_ref"}), "role binding")
        if item["role"] != role:
            raise ProductStoreError("V2 resource transaction roles are noncanonical")
        _digest(item["binding_ref"], "V2 resource binding")
        if index["action"] == "reconciliation" and item["binding_ref"] != (
            installed_strix_v2_reconciliation_binding_ref(
                authority_ref=index["authority_ref"],
                activation_ref=index["activation_ref"],
                reconciliation_ref=reconciliation_ref,
                role=role,
            )
        ):
            raise ProductStoreError("V2 historical resource binding changed")
    base = {
        name: value for name, value in document.items() if name not in {"transaction_ref", "owners"}
    }
    if content_hash(base) != index["transaction_ref"]:
        raise ProductStoreError("V2 resource transaction digest changed")
    expected_owners = [
        {
            **item,
            "owner_ref": content_hash(
                {
                    "schema_version": "bluefire.installed-strix-v2-resource-owner.v1",
                    "transaction_ref": index["transaction_ref"],
                    **item,
                }
            ),
        }
        for item in bindings
    ]
    if document["owners"] != expected_owners:
        raise ProductStoreError("V2 resource transaction ownership changed")
    constraints = document["constraints"]
    if index["action"] == "execution":
        _exact(
            constraints,
            frozenset(
                {
                    "mode",
                    "budgets",
                    "scope",
                    "network_policy_digest",
                    "custody_plan_digest",
                    "controlled_launch_digest",
                    "scope_ref",
                }
            ),
            "execution constraints",
        )
        if constraints["mode"] != "execution" or not all(
            type(constraints[name]) is dict for name in ("budgets", "scope")
        ):
            raise ProductStoreError("V2 execution constraints are invalid")
        for name in (
            "network_policy_digest",
            "custody_plan_digest",
            "controlled_launch_digest",
            "scope_ref",
        ):
            _digest(constraints[name], "V2 execution " + name)
    else:
        _exact(
            constraints,
            frozenset(
                {
                    "mode",
                    "saved_record_ref",
                    "reconciliation_ref",
                    "activation_ref",
                }
            ),
            "reconciliation constraints",
        )
        if constraints["mode"] != "cleanup_only":
            raise ProductStoreError("V2 historical resource is not cleanup-only")
        for name in ("saved_record_ref", "reconciliation_ref", "activation_ref"):
            _digest(constraints[name], "V2 historical " + name)
    return document


def _retained_bindings_at(connection: sqlite3.Connection, index: Mapping[str, Any]):
    # The protected authority source is the codec owner. Reuse its full retained
    # authority validation, without requiring current authority for old cleanup.
    from . import product_store_strix_v2_authority as authority

    if index["action"] == "execution":
        _row, (_document, prelaunch) = authority._read_prelaunch_at(connection, index["attempt_id"])
        if prelaunch.prelaunch_ref != index["authority_ref"]:
            raise ProductStoreError("V2 resource prelaunch authority changed")
        return [
            {
                "role": role,
                "binding_ref": installed_strix_v2_prelaunch_binding_ref(
                    prelaunch_ref=prelaunch.prelaunch_ref,
                    role=role,
                ),
            }
            for role in INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES
        ]
    retained, (document, snapshot, identity) = authority._read_authority_at(
        connection, index["attempt_id"]
    )
    if snapshot.activation.receipt_ref != index["activation_ref"]:
        raise ProductStoreError("V2 resource activation differs from retained authority")
    history = connection.execute(
        "SELECT * FROM strix_composition_historical_records WHERE reconciliation_ref=?",
        (index["reconciliation_ref"],),
    ).fetchone()
    if history is None:
        raise ResourceConflictError("V2 historical resource authority is unavailable")
    saved = EngineAttemptRecord.from_mapping(json.loads(history["document_json"])["saved_record"])
    historical = InstalledStrixV2HistoricalSnapshot.create(
        resolution_ref=snapshot.resolution_ref,
        saved_record=saved,
        reconciliation_ref=index["reconciliation_ref"],
        identity=identity,
        activation=snapshot.activation,
    )
    historical.validate(
        accepted=AcceptedPreparedEngineAttempt(**document["accepted"]),
        binding=EngineAttemptBinding.from_mapping(document["binding"]),
        delegation=EngineCapabilityDelegation.from_mapping(document["delegation"]),
        saved_record=saved,
        reconciliation_ref=index["reconciliation_ref"],
    )
    if (
        history["attempt_id"] != index["attempt_id"]
        or saved.binding.to_dict() != document["binding"]
    ):
        raise ProductStoreError("V2 historical resource attempt binding changed")
    authority.ProductStoreInstalledStrixV2AuthoritySource._decode_history(
        history, retained, historical, saved
    )
    if historical.authority_ref != index["authority_ref"]:
        raise ProductStoreError("V2 historical resource authority binding changed")
    return [
        {
            "role": role,
            "binding_ref": installed_strix_v2_reconciliation_binding_ref(
                authority_ref=index["authority_ref"],
                activation_ref=index["activation_ref"],
                reconciliation_ref=index["reconciliation_ref"],
                role=role,
            ),
        }
        for role in INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES
    ]


def _retained_constraints_at(connection: sqlite3.Connection, index: Mapping[str, Any]):
    from . import product_store_strix_v2_authority as authority

    if index["action"] == "execution":
        _row, (document, snapshot) = authority._read_prelaunch_at(connection, index["attempt_id"])
        admission = document["admission"]
        plan = snapshot.validate(
            accepted=AcceptedPreparedEngineAttempt(**document["accepted"]),
            binding=EngineAttemptBinding.from_mapping(document["binding"]),
            delegation=EngineCapabilityDelegation.from_mapping(document["delegation"]),
        )
        return {
            "mode": "execution",
            "budgets": admission["budgets"],
            "scope": admission["scope"],
            "network_policy_digest": EngineNetworkPlanV2.from_mapping(
                admission["network_plan"]
            ).policy_digest,
            "custody_plan_digest": ContainerCustodyPlanV2.from_mapping(
                admission["custody_plan"]
            ).plan_digest,
            "controlled_launch_digest": plan.launch_digest,
            "scope_ref": admission["scope"]["scope_digest"],
        }
    history = connection.execute(
        "SELECT * FROM strix_composition_historical_records WHERE reconciliation_ref=?",
        (index["reconciliation_ref"],),
    ).fetchone()
    if history is None:
        raise ResourceConflictError("V2 historical resource authority is unavailable")
    return {
        "mode": "cleanup_only",
        "saved_record_ref": history["saved_record_ref"],
        "reconciliation_ref": index["reconciliation_ref"],
        "activation_ref": index["activation_ref"],
    }


@dataclass
class _Replay:
    state: str = "prepared"
    transaction: dict[str, Any] | None = None
    effects_started: bool = False
    allocated_roles: list[str] = field(default_factory=list)
    actual_bindings: list[tuple[str, str]] = field(default_factory=list)
    activation_ref: str | None = None
    identity_ref: str | None = None
    resource_receipt_ref: str | None = None
    absence_observed: bool = False
    cleanup_boundary: str | None = None
    settlement_started: bool = False
    settlement_request: dict[str, Any] | None = None
    stop_claimed_roles: list[str] = field(default_factory=list)
    stop_claim_documents: dict[str, dict[str, Any]] = field(default_factory=dict)
    role_terminal_observations: dict[str, dict[str, Any]] = field(default_factory=dict)
    bundle_absence: dict[str, Any] | None = None
    bundle_receipts: list[InstalledEngineBundleCleanupReceipt] = field(default_factory=list)

    def apply(self, event: dict[str, Any], index: Mapping[str, Any]) -> None:
        kind, state, payload = event["event_type"], event["state"], event["document"]
        if self.transaction is None:
            if kind != "prepared" or state != "prepared" or event["generation"] != 1:
                raise ProductStoreError("V2 resource journal has no initial preparation")
            self.transaction = _transaction(payload, index)
        else:
            transition = _TRANSITIONS.get(kind)
            expected_state = (
                {"closed", "cleanup_unknown"}
                if transition is not None and transition[1] == "receipt"
                else {
                    self.state
                    if transition is not None and transition[1] is None
                    else transition[1]
                }
                if transition is not None
                else set()
            )
            if transition is None or self.state not in transition[0] or state not in expected_state:
                raise ResourceConflictError("V2 resource journal transition is invalid")
        owners = self.transaction["owners"]
        if kind == "prepared":
            self.activation_ref = index["activation_ref"]
        role = event["role"]
        if kind in {"role_allocated", "role_stop_claimed", "role_terminal"}:
            owner = next((item for item in owners if item["role"] == role), None)
            if (
                owner is None
                or event["binding_ref"] != owner["binding_ref"]
                or event["owner_ref"] != owner["owner_ref"]
            ):
                raise ProductStoreError("V2 resource event role ownership changed")
            if kind != "role_stop_claimed":
                _digest(event["receipt_ref"], "V2 resource role receipt")
        elif any(event[name] is not None for name in ("role", "binding_ref", "owner_ref")):
            raise ProductStoreError("V2 resource event has unexpected role ownership")
        if kind in {
            "prepared",
            "allocation_started",
            "commit_started",
            "committed",
            "cleanup_started",
            "cleanup_unknown",
        }:
            if event["receipt_ref"] is not None or (kind != "prepared" and payload != {}):
                raise ProductStoreError("V2 resource transition has unexpected evidence")
        if kind == "allocation_started":
            self.effects_started = True
        elif kind == "settlement_started":
            if index["action"] not in {"execution", "reconciliation"} or self.settlement_started:
                raise ProductStoreError("V2 bundle settlement cannot start here")
            _exact(
                payload,
                frozenset(
                    {
                        "cleanup_ref",
                        "claim_ref",
                        "runtime_activation_ref",
                        "resource_set_ref",
                        "owner_ref",
                    }
                ),
                "bundle settlement request",
            )
            for name in payload:
                _digest(payload[name], "V2 bundle " + name)
            if event["receipt_ref"] is not None:
                raise ProductStoreError("V2 bundle settlement intent has unexpected receipt")
            self.settlement_started = True
            self.settlement_request = payload
            self.cleanup_boundary = event["created_at"]
        elif kind == "activation_recorded":
            if index["action"] != "execution" or self.activation_ref is not None:
                raise ProductStoreError("V2 resource activation is not available here")
            _exact(
                payload,
                frozenset(
                    {
                        "activation_ref",
                        "identity_ref",
                        "resource_receipt_ref",
                    }
                ),
                "activation receipt",
            )
            self.activation_ref = _digest(payload["activation_ref"], "V2 observed activation")
            self.identity_ref = _digest(payload["identity_ref"], "V2 observed identity")
            self.resource_receipt_ref = _digest(
                payload["resource_receipt_ref"], "V2 observed resource receipt"
            )
            if event["receipt_ref"] != self.activation_ref:
                raise ProductStoreError("V2 activation event receipt changed")
        elif kind == "role_allocated":
            position = len(self.allocated_roles)
            if position >= len(owners) or owners[position]["role"] != role:
                raise ProductStoreError("V2 resource allocation roles are noncanonical")
            _exact(
                payload,
                frozenset(
                    {
                        "resource_receipt_ref",
                        "actual_binding_ref",
                    }
                ),
                "allocation receipt",
            )
            resource_ref = _digest(payload["resource_receipt_ref"], "V2 allocation receipt")
            actual_binding = _digest(payload["actual_binding_ref"], "V2 actual role binding")
            if index["action"] == "execution" and self.activation_ref is None:
                raise ProductStoreError("V2 execution role lacks retained activation")
            if self.resource_receipt_ref not in {None, resource_ref}:
                raise ProductStoreError("V2 resource allocation receipt changed")
            expected = content_hash(
                {
                    "schema_version": "bluefire.installed-strix-v2-role-allocation.v1",
                    "transaction_ref": index["transaction_ref"],
                    **owner,
                    "resource_receipt_ref": resource_ref,
                    "actual_binding_ref": actual_binding,
                }
            )
            if event["receipt_ref"] != expected:
                raise ProductStoreError("V2 resource role allocation digest changed")
            self.resource_receipt_ref = resource_ref
            self.allocated_roles.append(role)
            self.actual_bindings.append((role, actual_binding))
        elif kind == "allocated":
            if self.allocated_roles != [item["role"] for item in owners]:
                raise ProductStoreError("V2 resource allocation roles are incomplete")
            receipt = InstalledStrixV2ResourceReceipt.create(
                action="allocated" if index["action"] == "execution" else "reopened",
                authority_ref=index["authority_ref"],
                activation_receipt_ref=self.activation_ref,
                role_bindings=tuple(self.actual_bindings),
                reconciliation_ref=index["reconciliation_ref"],
            )
            if (
                payload != receipt.document()
                or event["receipt_ref"] != receipt.receipt_ref
                or self.resource_receipt_ref != receipt.receipt_ref
            ):
                raise ProductStoreError("V2 resource allocation evidence changed")
        elif kind == "absence_observed":
            if self.settlement_started:
                raise ProductStoreError("V2 bundle settlement cannot use abort absence")
            expected = {
                "schema_version": "bluefire.installed-strix-v2-cleanup-absence.v1",
                "transaction_ref": index["transaction_ref"],
                "authority_ref": index["authority_ref"],
                "activation_ref": self.activation_ref,
                "action": index["action"] + "_abort",
                "reconciliation_ref": index["reconciliation_ref"],
                "role_bindings": owners,
                "state": "absent",
            }
            _exact(
                payload,
                frozenset(expected)
                | {
                    "observer_identity_ref",
                    "observer_generation",
                    "observed_at",
                    "observation_ref",
                },
                "absence observation",
            )
            if not self.effects_started or any(
                payload[name] != value for name, value in expected.items()
            ):
                raise ProductStoreError("V2 resource absence observation binding changed")
            _digest(payload["observer_identity_ref"], "V2 absence observer")
            if (
                type(payload["observer_generation"]) is not int
                or payload["observer_generation"] < 1
            ):
                raise ProductStoreError("V2 resource absence observer generation is invalid")
            observed_at = parse_iso8601_datetime(payload["observed_at"])
            if (
                self.cleanup_boundary is None
                or observed_at < parse_iso8601_datetime(self.cleanup_boundary)
                or observed_at > parse_iso8601_datetime(event["created_at"])
            ):
                raise ProductStoreError("V2 resource absence observation chronology changed")
            digest = content_hash(
                {name: value for name, value in payload.items() if name != "observation_ref"}
            )
            if payload["observation_ref"] != digest or event["receipt_ref"] != digest:
                raise ProductStoreError("V2 resource absence observation digest changed")
            self.absence_observed = True
        elif kind in {"cleanup_unknown", "cleanup_started"}:
            if self.settlement_started:
                raise ProductStoreError("V2 bundle settlement cannot use abort cleanup")
            self.absence_observed = False
            self.cleanup_boundary = event["created_at"]
        elif kind == "cleaned":
            if self.settlement_started:
                raise ProductStoreError("V2 bundle settlement cannot use abort receipt")
            if self.effects_started and not self.absence_observed:
                raise ResourceConflictError("V2 resource cleanup requires an absence observation")
            receipt = InstalledStrixV2CleanupReceipt.create(
                action=index["action"] + "_abort",
                transaction_ref=index["transaction_ref"],
                authority_ref=index["authority_ref"],
                activation_receipt_ref=self.activation_ref,
                reconciliation_ref=index["reconciliation_ref"],
            )
            if (
                canonical_json(payload) != canonical_json(receipt.document())
                or event["receipt_ref"] != receipt.receipt_ref
            ):
                raise ProductStoreError("V2 resource cleanup receipt changed")
        elif kind == "role_terminal":
            if (
                not self.settlement_started
                or self.bundle_absence is not None
                or role not in self.stop_claimed_roles
            ):
                raise ProductStoreError("V2 role terminal is outside its settlement")
            _exact(
                payload,
                frozenset(
                    {
                        "schema_version",
                        "transaction_ref",
                        "attempt_id",
                        "authority_ref",
                        "claim_ref",
                        "runtime_activation_ref",
                        "role",
                        "prelaunch_binding_ref",
                        "resource_ref",
                        "owner_ref",
                        "state",
                        "evidence_ref",
                        "source_receipt_ref",
                        "source_identity_ref",
                        "observed_at",
                        "observation_ref",
                    }
                ),
                "role terminal observation",
            )
            if (
                payload["schema_version"]
                != "bluefire.installed-strix-v2-role-terminal-observation.v1"
                or payload["role"] != role
                or payload["transaction_ref"] != index["transaction_ref"]
                or payload["attempt_id"] != index["attempt_id"]
                or payload["authority_ref"] != index["authority_ref"]
                or payload["runtime_activation_ref"] != self.activation_ref
                or payload["prelaunch_binding_ref"] != event["binding_ref"]
                or payload["owner_ref"] != event["owner_ref"]
                or role in self.role_terminal_observations
            ):
                raise ProductStoreError("V2 role terminal identity changed")
            for name in (
                "claim_ref",
                "resource_ref",
                "evidence_ref",
                "source_receipt_ref",
                "source_identity_ref",
            ):
                _digest(payload[name], "V2 role terminal " + name)
            if payload["state"] not in {"verified_absent", "verified_revoked", "verified_settled"}:
                raise ProductStoreError("V2 role terminal state is not verified")
            if (role, payload["resource_ref"]) not in self.actual_bindings:
                raise ProductStoreError("V2 role terminal actual resource changed")
            if (
                parse_iso8601_datetime(payload["observed_at"])
                < parse_iso8601_datetime(self.cleanup_boundary)
                or parse_iso8601_datetime(payload["observed_at"])
                > parse_iso8601_datetime(event["created_at"])
                or payload["observation_ref"]
                != content_hash(
                    {key: value for key, value in payload.items() if key != "observation_ref"}
                )
                or event["receipt_ref"] != payload["observation_ref"]
            ):
                raise ProductStoreError("V2 role terminal observation changed")
            self.role_terminal_observations[role] = payload
        elif kind == "role_stop_claimed":
            # This orders first-stop intents, not OS completion. A failed stop
            # may remain unknown while later owners are still safely stopped.
            if (
                not self.settlement_started
                or self.bundle_absence is not None
                or role in self.stop_claimed_roles
                or len(self.stop_claimed_roles) >= len(owners)
                or role != owners[-1 - len(self.stop_claimed_roles)]["role"]
            ):
                raise ProductStoreError("V2 role stop claim is duplicate or out of order")
            _exact(
                payload,
                frozenset({"claim_ref", "runtime_activation_ref", "resource_ref"}),
                "role stop claim",
            )
            if (
                payload["runtime_activation_ref"] != self.activation_ref
                or (role, payload["resource_ref"]) not in self.actual_bindings
                or event["receipt_ref"] is not None
            ):
                raise ProductStoreError("V2 role stop claim binding changed")
            _digest(payload["claim_ref"], "V2 role stop claim")
            self.stop_claimed_roles.append(role)
            self.stop_claim_documents[role] = payload
        elif kind == "bundle_absence_observed":
            if (
                not self.settlement_started
                or self.bundle_absence is not None
                or len(self.role_terminal_observations) != len(owners)
            ):
                raise ProductStoreError("V2 bundle absence lacks all role terminals")
            _exact(
                payload,
                frozenset(
                    {
                        "schema_version",
                        "transaction_ref",
                        "attempt_id",
                        "authority_ref",
                        "claim_ref",
                        "runtime_activation_ref",
                        "resource_set_ref",
                        "owner_ref",
                        "role_bindings",
                        "state",
                        "observer_identity_ref",
                        "observer_generation",
                        "observed_at",
                        "observation_ref",
                    }
                ),
                "bundle absence observation",
            )
            if (
                payload["schema_version"] != "bluefire.installed-strix-v2-bundle-absence.v1"
                or payload["transaction_ref"] != index["transaction_ref"]
                or payload["attempt_id"] != index["attempt_id"]
                or payload["authority_ref"] != index["authority_ref"]
                or payload["runtime_activation_ref"] != self.activation_ref
                or payload["state"] != "absent"
                or payload["observer_identity_ref"]
                in {row["source_identity_ref"] for row in self.role_terminal_observations.values()}
                or payload["role_bindings"]
                != [
                    {
                        **owner,
                        "resource_ref": binding,
                    }
                    for owner, (_, binding) in zip(owners, self.actual_bindings, strict=True)
                ]
                or type(payload["observer_generation"]) is not int
                or payload["observer_generation"] < 1
                or payload["observation_ref"]
                != content_hash(
                    {key: value for key, value in payload.items() if key != "observation_ref"}
                )
                or event["receipt_ref"] != payload["observation_ref"]
            ):
                raise ProductStoreError("V2 bundle absence observation changed")
            _digest(payload["observer_identity_ref"], "V2 whole absence observer")
            latest_role_at = max(
                parse_iso8601_datetime(row["observed_at"])
                for row in self.role_terminal_observations.values()
            )
            observed_at = parse_iso8601_datetime(payload["observed_at"])
            if observed_at < latest_role_at or observed_at > parse_iso8601_datetime(
                event["created_at"]
            ):
                raise ProductStoreError("V2 bundle absence observation is stale")
            self.bundle_absence = payload
        elif kind == "bundle_receipt_recorded":
            if not self.settlement_started:
                raise ProductStoreError("V2 bundle receipt is outside its settlement")
            receipt = _decode_bundle_receipt(payload)
            if (
                receipt.receipt_ref != event["receipt_ref"]
                or state != ("closed" if receipt.state == "verified_absent" else "cleanup_unknown")
                or receipt.cleanup_ref != self.settlement_request["cleanup_ref"]
                or receipt.generation != len(self.bundle_receipts) + 1
                or receipt.predecessor_receipt_ref
                != (self.bundle_receipts[-1].receipt_ref if self.bundle_receipts else None)
            ):
                raise ProductStoreError("V2 bundle receipt chain changed")
            if receipt.state == "verified_absent" and self.bundle_absence is None:
                raise ProductStoreError("V2 bundle settlement lacks whole absence")
            settled_at = parse_iso8601_datetime(receipt.settled_at)
            if (
                settled_at < parse_iso8601_datetime(self.cleanup_boundary)
                or settled_at > parse_iso8601_datetime(event["created_at"])
                or (
                    receipt.state == "verified_absent"
                    and settled_at < parse_iso8601_datetime(self.bundle_absence["observed_at"])
                )
            ):
                raise ProductStoreError("V2 bundle receipt chronology changed")
            for outcome, owner in zip(receipt.outcomes, reversed(owners), strict=True):
                observed = self.role_terminal_observations.get(owner["role"])
                if (
                    outcome.role != owner["role"]
                    or outcome.resource_ref != dict(self.actual_bindings)[owner["role"]]
                    or (
                        observed is not None
                        and (
                            outcome.state != observed["state"]
                            or outcome.evidence_ref != observed["evidence_ref"]
                        )
                    )
                    or (observed is None and outcome.state != "unknown")
                ):
                    raise ProductStoreError("V2 bundle receipt role evidence changed")
            self.bundle_receipts.append(receipt)
        self.state = state


def _verify_retained_activation_at(connection, index, replay) -> None:
    if index["action"] != "execution" or replay.activation_ref is None:
        return
    from . import product_store_strix_v2_authority as authority

    _authority_row, (activated, snapshot, identity) = authority._read_authority_at(
        connection, index["attempt_id"]
    )
    actual = dict(snapshot.activation.role_bindings)
    if (
        activated["prelaunch_ref"] != index["authority_ref"]
        or activated["resource_transaction_ref"] != index["transaction_ref"]
        or activated["resource_receipt_ref"] != replay.resource_receipt_ref
        or snapshot.activation.receipt_ref != replay.activation_ref
        or content_hash(asdict(identity)) != replay.identity_ref
        or any(actual.get(role) != binding for role, binding in replay.actual_bindings)
    ):
        raise ProductStoreError("V2 resource journal activation differs from protected owner")


def _settlement_snapshot_at(
    connection: sqlite3.Connection,
    index: Mapping[str, Any],
    replay: _Replay,
) -> InstalledStrixV2SettlementSnapshot:
    if index["state"] not in {"active", "stopping", "cleanup_unknown", "closed"}:
        raise ResourceConflictError("V2 bundle has not committed its owned resources")
    if index["state"] != "active" and not replay.settlement_started:
        raise ResourceConflictError("V2 bundle is in abort cleanup, not settlement")
    from . import product_store_strix_v2_authority as authority

    _row, (retained, snapshot, _identity) = authority._read_authority_at(
        connection, index["attempt_id"]
    )
    accepted = AcceptedPreparedEngineAttempt(**retained["accepted"])
    binding = EngineAttemptBinding.from_mapping(retained["binding"])
    if (
        binding.attempt_id != index["attempt_id"]
        or accepted.claim_ref is None
        or snapshot.activation.receipt_ref != replay.activation_ref
        or len(replay.actual_bindings) != len(replay.transaction["owners"])
        or [role for role, _ref in replay.actual_bindings]
        != [row["role"] for row in replay.transaction["owners"]]
    ):
        raise ProductStoreError("V2 bundle retained identity changed")
    manifest = tuple(
        InstalledEngineCleanupResourceBinding(role=role, resource_ref=resource_ref)
        for role, resource_ref in replay.actual_bindings
    )
    manifest_ref = resource_set_ref(manifest)
    historical = None
    if index["action"] == "reconciliation":
        historical = connection.execute(
            "SELECT saved_record_ref FROM strix_composition_historical_records "
            "WHERE reconciliation_ref=?",
            (index["reconciliation_ref"],),
        ).fetchone()
        if historical is None:
            raise ResourceConflictError("V2 historical bundle record is unavailable")
    owner_document = {
        "schema_version": (
            "bluefire.strix-v2-bundle-cleanup-owner.v1"
            if index["action"] == "execution"
            else "bluefire.strix-v2-historical-bundle-cleanup-owner.v1"
        ),
        "attempt_id": index["attempt_id"],
        "attempt_ref": binding.binding_digest,
        "claim_ref": accepted.claim_ref,
        "runtime_activation_ref": replay.activation_ref,
        "runtime_resolution_ref": accepted.runtime_resolution_ref,
        "resource_transaction_ref": index["transaction_ref"],
        "resource_set_ref": manifest_ref,
    }
    if historical is not None:
        owner_document["saved_record_ref"] = historical["saved_record_ref"]
        owner_document["reconciliation_ref"] = index["reconciliation_ref"]
    owner_ref = content_hash(owner_document)
    cleanup_ref = cleanup_request_ref(
        binding.binding_digest,
        accepted.claim_ref,
        owner_ref,
        accepted.runtime_resolution_ref,
        manifest_ref,
    )
    expected_request = {
        "cleanup_ref": cleanup_ref,
        "claim_ref": accepted.claim_ref,
        "runtime_activation_ref": replay.activation_ref,
        "resource_set_ref": manifest_ref,
        "owner_ref": owner_ref,
    }
    if replay.settlement_started and replay.settlement_request != expected_request:
        raise ProductStoreError("V2 bundle settlement request changed")
    outcomes: list[InstalledEngineResourceCleanupOutcome | None] = []
    for role, resource_ref in replay.actual_bindings:
        claimed = replay.stop_claim_documents.get(role)
        if claimed is not None and (
            claimed["claim_ref"] != accepted.claim_ref or claimed["resource_ref"] != resource_ref
        ):
            raise ProductStoreError("V2 bundle role stop claim changed")
        observation = replay.role_terminal_observations.get(role)
        if observation is not None and (
            observation["claim_ref"] != accepted.claim_ref
            or observation["resource_ref"] != resource_ref
        ):
            raise ProductStoreError("V2 bundle role terminal claim changed")
        outcomes.append(
            InstalledEngineResourceCleanupOutcome(
                role=role,
                resource_ref=resource_ref,
                state=observation["state"],
                evidence_ref=observation["evidence_ref"],
            )
            if observation is not None
            else None
        )
    if replay.bundle_absence is not None and any(
        replay.bundle_absence[name] != value
        for name, value in {
            "claim_ref": accepted.claim_ref,
            "resource_set_ref": manifest_ref,
            "owner_ref": owner_ref,
        }.items()
    ):
        raise ProductStoreError("V2 bundle whole absence binding changed")
    for position, receipt in enumerate(replay.bundle_receipts):
        predecessor = replay.bundle_receipts[position - 1] if position else None
        validate_cleanup_receipt(
            receipt,
            cleanup_ref=cleanup_ref,
            attempt_ref=binding.binding_digest,
            activation_ref=accepted.claim_ref,
            owner_ref=owner_ref,
            runtime_resolution_ref=accepted.runtime_resolution_ref,
            resource_set_ref=manifest_ref,
            resource_manifest=manifest,
            predecessor=predecessor,
        )
    return InstalledStrixV2SettlementSnapshot(
        transaction_ref=index["transaction_ref"],
        attempt_id=index["attempt_id"],
        action=index["action"],
        authority_ref=index["authority_ref"],
        claim_ref=accepted.claim_ref,
        runtime_activation_ref=replay.activation_ref,
        attempt_ref=binding.binding_digest,
        runtime_resolution_ref=accepted.runtime_resolution_ref,
        saved_record_ref=historical["saved_record_ref"] if historical is not None else None,
        reconciliation_ref=index["reconciliation_ref"],
        generation=index["generation"],
        state=index["state"],
        role_owner_bindings=tuple(
            (row["role"], row["binding_ref"], row["owner_ref"])
            for row in replay.transaction["owners"]
        ),
        actual_role_bindings=tuple(replay.actual_bindings),
        role_outcomes=tuple(outcomes),
        stop_claimed_roles=tuple(replay.stop_claimed_roles),
        whole_absence_ref=(
            replay.bundle_absence["observation_ref"] if replay.bundle_absence else None
        ),
        retained_receipt=replay.bundle_receipts[-1] if replay.bundle_receipts else None,
        resource_set_ref=manifest_ref,
        owner_ref=owner_ref,
        cleanup_ref=cleanup_ref,
    )


def _read_at(connection: sqlite3.Connection, transaction_ref: str):
    index = connection.execute(
        "SELECT * FROM strix_composition_resource_transactions WHERE transaction_ref=?",
        (transaction_ref,),
    ).fetchone()
    if index is None:
        raise ResourceConflictError("V2 resource transaction is unavailable")
    if type(index["generation"]) is not int or not 1 <= index["generation"] <= _MAX_GENERATION:
        raise ProductStoreError("V2 resource transaction generation is invalid")
    rows = connection.execute(
        "SELECT * FROM strix_composition_resource_events WHERE transaction_ref=? ORDER BY tx_sequence",
        (transaction_ref,),
    ).fetchall()
    if len(rows) != index["generation"]:
        raise ProductStoreError("V2 resource journal and head generations differ")
    replay, previous, timestamp = _Replay(), None, index["created_at"]
    parse_iso8601_datetime(timestamp)
    for generation, row in enumerate(rows, start=1):
        event = _exact(json.loads(row["document_json"]), _EVENT_FIELDS, "event")
        if (
            row["document_schema"] != EVENT_SCHEMA
            or event["schema_version"] != EVENT_SCHEMA
            or _bounded(event) != row["document_json"]
            or content_hash(event) != row["event_digest"]
            or type(event["generation"]) is not int
            or event["generation"] != generation
            or row["tx_sequence"] != generation
            or event["previous_digest"] != previous
            or any(event[name] != index[name] for name in _INDEX_FIELDS)
            or any(event[name] != row[name] for name in _EVENT_INDEX_FIELDS)
        ):
            raise ProductStoreError("V2 resource journal event integrity changed")
        if not isinstance(event["document"], dict):
            raise ProductStoreError("V2 resource event payload is invalid")
        if parse_iso8601_datetime(event["created_at"]) < parse_iso8601_datetime(timestamp):
            raise ProductStoreError("V2 resource event chronology changed")
        if generation == 1 and event["created_at"] != index["created_at"]:
            raise ProductStoreError("V2 resource preparation timestamp changed")
        replay.apply(event, index)
        previous, timestamp = row["event_digest"], event["created_at"]
    if (
        index["head_event_digest"] != previous
        or index["state"] != replay.state
        or index["updated_at"] != timestamp
    ):
        raise ProductStoreError("V2 resource transaction head integrity changed")
    if replay.transaction["role_bindings"] != _retained_bindings_at(
        connection, index
    ) or replay.transaction["constraints"] != _retained_constraints_at(connection, index):
        raise ProductStoreError("V2 resource intent differs from retained authority")
    _verify_retained_activation_at(connection, index, replay)
    if replay.settlement_started:
        _settlement_snapshot_at(connection, index, replay)
    return index, replay


def _head(index: Mapping[str, Any]) -> InstalledStrixV2TransactionHead:
    return InstalledStrixV2TransactionHead(
        index["transaction_ref"], index["generation"], index["state"]
    )


class ProductStoreInstalledStrixV2TransactionRepository:
    """Same-service ProductStore journal with an atomic compare-and-swap head."""

    def __init__(
        self,
        *,
        product_store: ProductStore,
        clock: Callable[[], str] = utc_now,
        absence_observer: InstalledStrixV2CleanupAbsenceObserver | None = None,
        role_terminal_observer: InstalledStrixV2RoleTerminalObserver | None = None,
    ) -> None:
        if product_store is None or not callable(clock):
            raise ProductStoreError("V2 resource journal dependencies are invalid")
        self._store = product_store
        self._clock = clock
        self._observer = absence_observer
        self._role_observer = role_terminal_observer

    def require_product_store(self, product_store: ProductStore) -> None:
        if product_store is not self._store:
            raise ProductStoreError("V2 resource journal belongs to a different ProductStore")

    def require_absence_observer(
        self, observer: InstalledStrixV2CleanupAbsenceObserver | None
    ) -> None:
        if observer is not self._observer:
            raise ProductStoreError("V2 resource journal has a different absence owner")

    def require_role_terminal_observer(
        self, observer: InstalledStrixV2RoleTerminalObserver | None
    ) -> None:
        if observer is not self._role_observer:
            raise ProductStoreError("V2 resource journal has a different role terminal owner")

    def _verify_protected_role_sources(self, replay: _Replay) -> None:
        if replay.role_terminal_observations:
            observer = self._role_observer
            if observer is None:
                raise ResourceConflictError("V2 protected role terminal source is unavailable")
            for role, saved in replay.role_terminal_observations.items():
                try:
                    reopened = _copy_document(
                        observer.reopen_role_terminal(
                            role=role, source_receipt_ref=saved["source_receipt_ref"]
                        )
                    )
                    identity = observer.role_identity_ref(role)
                except Exception as exc:
                    raise ResourceConflictError(
                        "V2 protected role terminal source cannot be reopened"
                    ) from exc
                if reopened != saved or identity != saved["source_identity_ref"]:
                    raise ResourceConflictError("V2 protected role terminal source changed")

    def _verify_protected_settlement_sources(self, replay: _Replay) -> None:
        self._verify_protected_role_sources(replay)
        if replay.bundle_absence is not None:
            observer = self._observer
            if observer is None:
                raise ResourceConflictError("V2 protected whole absence source is unavailable")
            try:
                reopened = _copy_document(
                    observer.reopen_absence(
                        observation_ref=replay.bundle_absence["observation_ref"]
                    )
                )
            except Exception as exc:
                raise ResourceConflictError(
                    "V2 protected whole absence source cannot be reopened"
                ) from exc
            if (
                reopened != replay.bundle_absence
                or observer.observer_identity_ref != replay.bundle_absence["observer_identity_ref"]
                or observer.observer_generation != replay.bundle_absence["observer_generation"]
            ):
                raise ResourceConflictError("V2 protected whole absence source changed")

    def load_settlement(self, transaction_ref: str) -> InstalledStrixV2SettlementSnapshot:
        _digest(transaction_ref, "V2 settlement transaction")
        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            index, replay = _read_at(connection, transaction_ref)
            snapshot = _settlement_snapshot_at(connection, index, replay)
        self._verify_protected_settlement_sources(replay)
        return snapshot

    def load_terminal_observations(self, transaction_ref: str) -> tuple[dict[str, Any], ...]:
        """Reopen every role source without recursively reopening whole absence.

        The whole-set observer uses this read during both its first observation
        and later by-ref replay. Missing or changed role sources remain unknown.
        """

        _digest(transaction_ref, "V2 terminal observation transaction")
        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            index, replay = _read_at(connection, transaction_ref)
            snapshot = _settlement_snapshot_at(connection, index, replay)
            roles = tuple(role for role, _actual_ref in snapshot.actual_role_bindings)
            if len(replay.role_terminal_observations) != len(roles) or any(
                role not in replay.role_terminal_observations for role in roles
            ):
                raise ResourceConflictError("V2 bundle lacks every protected role terminal")
            observations = tuple(
                _copy_document(replay.role_terminal_observations[role]) for role in roles
            )
        self._verify_protected_role_sources(replay)
        return observations

    @contextmanager
    def hold_active_execution(
        self,
        *,
        transaction_ref: str,
        claim_ref: str,
        controller_fence: str,
        authority_guard: InstalledStrixV2AuthorityGuard,
        deadline: float | None = None,
    ) -> Iterator[InstalledStrixV2ActivationReceipt]:
        """Pin saved active resource authority through one bounded effect send.

        The controller's live job/fence owner must wrap this scope as well. The
        database lease serializes the active→stopping journal transition, but
        cannot by itself prevent an independent job cancellation.
        """

        _digest(transaction_ref, "V2 effect transaction")
        _digest(claim_ref, "V2 effect claim")
        _digest(controller_fence, "V2 effect controller fence")
        if authority_guard is None:
            raise ResourceConflictError("V2 effect authority guard is unavailable")
        authority_guard.require_product_store(self._store)
        with self._store.action_package_catalog_lease(deadline=deadline):
            with self._store._connection() as connection:
                if not connection.in_transaction:
                    connection.execute("BEGIN")
                index, replay = _read_at(connection, transaction_ref)
                snapshot = _settlement_snapshot_at(connection, index, replay)
                from . import product_store_strix_v2_authority as authority

                _authority_row, (_retained, activated, _identity) = authority._read_authority_at(
                    connection, index["attempt_id"]
                )
                if (
                    snapshot.state != "active"
                    or snapshot.action != "execution"
                    or snapshot.claim_ref != claim_ref
                    or activated.activation.controller_fence != controller_fence
                    or activated.activation.receipt_ref != snapshot.runtime_activation_ref
                ):
                    raise ResourceConflictError("V2 effect authority is not active")
            current = authority_guard.require_active()
            if (
                current.activation.receipt_ref != snapshot.runtime_activation_ref
                or current.activation.claim_ref != claim_ref
                or current.activation.controller_fence != controller_fence
            ):
                raise ResourceConflictError("V2 effect authority changed before send")
            yield current.activation

    def begin_settlement(
        self,
        *,
        transaction_ref: str,
        expected_generation: int,
        cleanup_ref: str,
    ) -> InstalledStrixV2TransactionHead:
        _digest(cleanup_ref, "V2 bundle cleanup request")
        with self._store.action_package_catalog_lease():
            with self._store._connection(write=True) as connection:
                index, replay = _read_at(connection, transaction_ref)
                snapshot = _settlement_snapshot_at(connection, index, replay)
                if (
                    snapshot.state != "active"
                    or snapshot.generation != expected_generation
                    or snapshot.cleanup_ref != cleanup_ref
                ):
                    raise ResourceConflictError("V2 bundle settlement intent changed")
                return self._append_at(
                    connection,
                    index,
                    replay,
                    event_type="settlement_started",
                    state="stopping",
                    document={
                        "cleanup_ref": cleanup_ref,
                        "claim_ref": snapshot.claim_ref,
                        "runtime_activation_ref": snapshot.runtime_activation_ref,
                        "resource_set_ref": snapshot.resource_set_ref,
                        "owner_ref": snapshot.owner_ref,
                    },
                    timestamp=self._clock(),
                )

    def record_role_terminal(
        self,
        *,
        transaction_ref: str,
        expected_generation: int,
        role: str,
        receipt: object,
    ) -> InstalledStrixV2TransactionHead:
        observer = self._role_observer
        if observer is None or not callable(getattr(observer, "reopen_role_terminal", None)):
            raise ResourceConflictError("V2 protected role terminal owner is unavailable")
        typed_ref = getattr(receipt, "receipt_ref", None)
        evidence_ref = getattr(receipt, "evidence_ref", None)
        source_ref = _digest(
            typed_ref if typed_ref is not None else evidence_ref,
            "V2 role terminal source receipt",
        )
        observation = _copy_document(
            observer.reopen_role_terminal(role=role, source_receipt_ref=source_ref)
        )
        if observation.get("source_receipt_ref") != source_ref or observation.get(
            "source_identity_ref"
        ) != observer.role_identity_ref(role):
            raise ResourceConflictError("V2 protected role terminal source changed")
        observation_ref = _digest(
            observation.get("observation_ref"), "V2 role terminal observation"
        )
        prior = self.load_settlement(transaction_ref)
        if prior.generation != expected_generation:
            raise ResourceConflictError("V2 role terminal journal generation changed")
        with self._store._connection(write=True) as connection:
            index, replay = _read_at(connection, transaction_ref)
            snapshot = _settlement_snapshot_at(connection, index, replay)
            if snapshot.generation != expected_generation or snapshot.state not in {
                "stopping",
                "cleanup_unknown",
            }:
                raise ResourceConflictError("V2 role terminal journal generation changed")
            binding = next((row for row in snapshot.role_owner_bindings if row[0] == role), None)
            if binding is None:
                raise ResourceConflictError("V2 role terminal is not owned by this bundle")
            return self._append_at(
                connection,
                index,
                replay,
                event_type="role_terminal",
                state=snapshot.state,
                document=observation,
                timestamp=self._clock(),
                role=role,
                binding_ref=binding[1],
                owner_ref=binding[2],
                receipt_ref=observation_ref,
            )

    def claim_role_stop(
        self,
        *,
        transaction_ref: str,
        expected_generation: int,
        role: str,
    ) -> InstalledStrixV2TransactionHead:
        """Durably claim one exact first stop before calling its external owner."""

        prior = self.load_settlement(transaction_ref)
        if prior.generation != expected_generation:
            raise ResourceConflictError("V2 role stop journal generation changed")
        with self._store._connection(write=True) as connection:
            index, replay = _read_at(connection, transaction_ref)
            snapshot = _settlement_snapshot_at(connection, index, replay)
            if snapshot.generation != expected_generation or snapshot.state not in {
                "stopping",
                "cleanup_unknown",
            }:
                raise ResourceConflictError("V2 role stop is outside active settlement")
            if role in snapshot.stop_claimed_roles:
                raise ResourceConflictError("V2 role stop was already claimed")
            binding = next((row for row in snapshot.role_owner_bindings if row[0] == role), None)
            if binding is None:
                raise ResourceConflictError("V2 role stop is not owned by this bundle")
            return self._append_at(
                connection,
                index,
                replay,
                event_type="role_stop_claimed",
                state=snapshot.state,
                document={
                    "claim_ref": snapshot.claim_ref,
                    "runtime_activation_ref": snapshot.runtime_activation_ref,
                    "resource_ref": dict(snapshot.actual_role_bindings)[role],
                },
                timestamp=self._clock(),
                role=role,
                binding_ref=binding[1],
                owner_ref=binding[2],
            )

    def retain_bundle_receipt(
        self,
        *,
        transaction_ref: str,
        expected_generation: int,
        receipt: InstalledEngineBundleCleanupReceipt,
    ) -> InstalledStrixV2TransactionHead:
        if not isinstance(receipt, InstalledEngineBundleCleanupReceipt):
            raise ProductStoreError("V2 bundle settlement receipt is invalid")
        prior = self.load_settlement(transaction_ref)
        if prior.generation != expected_generation:
            raise ResourceConflictError("V2 bundle settlement journal generation changed")
        with self._store._connection(write=True) as connection:
            index, replay = _read_at(connection, transaction_ref)
            snapshot = _settlement_snapshot_at(connection, index, replay)
            if snapshot.generation != expected_generation or snapshot.state not in {
                "stopping",
                "cleanup_unknown",
            }:
                raise ResourceConflictError("V2 bundle settlement journal generation changed")
            if receipt.state == "verified_absent" and snapshot.whole_absence_ref is None:
                raise ResourceConflictError("V2 whole bundle absence has not been observed")
            return self._append_at(
                connection,
                index,
                replay,
                event_type="bundle_receipt_recorded",
                state="closed" if receipt.state == "verified_absent" else "cleanup_unknown",
                document=receipt.document(),
                timestamp=self._clock(),
                receipt_ref=receipt.receipt_ref,
            )

    def prepare_transaction(
        self,
        *,
        attempt_id: str,
        transaction_ref: str,
        authority_ref: str,
        activation_ref: str,
        action: str,
        reconciliation_ref: str | None,
        document: Mapping[str, Any],
    ) -> InstalledStrixV2TransactionHead:
        try:
            index = dict(
                attempt_id=attempt_id,
                transaction_ref=transaction_ref,
                authority_ref=authority_ref,
                activation_ref=activation_ref,
                action=action,
                reconciliation_ref=reconciliation_ref,
            )
            payload = _transaction(_copy_document(document), index)
            with self._store._connection(write=True) as connection:
                existing = connection.execute(
                    "SELECT 1 FROM strix_composition_resource_transactions WHERE transaction_ref=?",
                    (transaction_ref,),
                ).fetchone()
                if existing is not None:
                    saved, replay = _read_at(connection, transaction_ref)
                    if (
                        any(saved[name] != value for name, value in index.items())
                        or replay.transaction != payload
                        or saved["generation"] != 1
                        or saved["state"] != "prepared"
                    ):
                        raise ResourceConflictError(
                            "V2 resource transaction was already prepared or consumed"
                        )
                    return _head(saved)
                if payload["role_bindings"] != _retained_bindings_at(connection, index) or payload[
                    "constraints"
                ] != _retained_constraints_at(connection, index):
                    raise ProductStoreError("V2 resource intent differs from retained authority")
                timestamp = self._clock()
                parse_iso8601_datetime(timestamp)
                index.update(
                    state="prepared",
                    generation=0,
                    head_event_digest=None,
                    created_at=timestamp,
                    updated_at=timestamp,
                )
                connection.execute(
                    "INSERT INTO strix_composition_resource_transactions "
                    "(transaction_ref,attempt_id,authority_ref,activation_ref,action,reconciliation_ref,"
                    "state,generation,head_event_digest,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(
                        index[name]
                        for name in (
                            *_INDEX_FIELDS,
                            "state",
                            "generation",
                            "head_event_digest",
                            "created_at",
                            "updated_at",
                        )
                    ),
                )
                return self._append_at(
                    connection,
                    index,
                    _Replay(),
                    event_type="prepared",
                    state="prepared",
                    document=payload,
                    timestamp=timestamp,
                )
        except (
            KeyError,
            TypeError,
            ValueError,
            RecursionError,
            InstalledStrixV2CompositionError,
        ) as exc:
            raise ProductStoreError("V2 resource transaction cannot be prepared") from exc
        except sqlite3.IntegrityError as exc:
            raise ResourceConflictError("V2 resource transaction preparation conflicted") from exc

    def append_event(
        self,
        *,
        transaction_ref: str,
        expected_generation: int,
        event_type: str,
        state: str,
        document: Mapping[str, Any],
        role: str | None = None,
        owner_ref: str | None = None,
        binding_ref: str | None = None,
        receipt_ref: str | None = None,
    ) -> InstalledStrixV2TransactionHead:
        if event_type == "absence_observed":
            raise ProductStoreError("V2 absence requires the protected observation owner")
        if event_type in {
            "settlement_started",
            "role_stop_claimed",
            "role_terminal",
            "bundle_absence_observed",
            "bundle_receipt_recorded",
        }:
            raise ProductStoreError("V2 protected settlement event cannot be caller-authored")
        if type(expected_generation) is not int or not 1 <= expected_generation < _MAX_GENERATION:
            raise ResourceConflictError("V2 resource expected generation is invalid")
        try:
            _digest(transaction_ref, "V2 resource transaction")
            payload = _copy_document(document)
            with self._store._connection(write=True) as connection:
                index, replay = _read_at(connection, transaction_ref)
                if index["generation"] != expected_generation:
                    raise ResourceConflictError("V2 resource transaction generation changed")
                return self._append_at(
                    connection,
                    index,
                    replay,
                    event_type=event_type,
                    state=state,
                    document=payload,
                    timestamp=self._clock(),
                    role=role,
                    owner_ref=owner_ref,
                    binding_ref=binding_ref,
                    receipt_ref=receipt_ref,
                )
        except (
            KeyError,
            TypeError,
            ValueError,
            RecursionError,
            InstalledStrixV2CompositionError,
        ) as exc:
            raise ProductStoreError("V2 resource journal event cannot be appended") from exc
        except sqlite3.IntegrityError as exc:
            raise ResourceConflictError("V2 resource journal append conflicted") from exc

    def record_absence(
        self,
        *,
        transaction_ref: str,
        expected_generation: int,
        document: Mapping[str, Any],
    ) -> InstalledStrixV2TransactionHead:
        observer = self._observer
        if observer is None or not callable(getattr(observer, "reopen_absence", None)):
            raise ResourceConflictError("V2 protected absence owner is unavailable")
        payload = _copy_document(document)
        observation_ref = _digest(payload.get("observation_ref"), "V2 absence observation")
        reopened = observer.reopen_absence(observation_ref=observation_ref)
        if _copy_document(reopened) != payload:
            raise ResourceConflictError("V2 protected absence observation changed")
        if (
            payload.get("observer_identity_ref") != observer.observer_identity_ref
            or payload.get("observer_generation") != observer.observer_generation
        ):
            raise ResourceConflictError("V2 protected absence owner changed")
        if payload.get("schema_version") == "bluefire.installed-strix-v2-bundle-absence.v1":
            prior = self.load_settlement(transaction_ref)
            if prior.generation != expected_generation:
                raise ResourceConflictError("V2 bundle absence journal generation changed")
        with self._store._connection(write=True) as connection:
            index, replay = _read_at(connection, transaction_ref)
            if index["generation"] != expected_generation:
                raise ResourceConflictError("V2 absence journal generation changed")
            if replay.settlement_started:
                _settlement_snapshot_at(connection, index, replay)
                return self._append_at(
                    connection,
                    index,
                    replay,
                    event_type="bundle_absence_observed",
                    state=index["state"],
                    document=payload,
                    timestamp=self._clock(),
                    receipt_ref=observation_ref,
                )
            return self._append_at(
                connection,
                index,
                replay,
                event_type="absence_observed",
                state="stopping",
                document=payload,
                timestamp=self._clock(),
                receipt_ref=observation_ref,
            )

    @staticmethod
    def _append_at(
        connection,
        index,
        replay,
        *,
        event_type,
        state,
        document,
        timestamp,
        role=None,
        owner_ref=None,
        binding_ref=None,
        receipt_ref=None,
    ):
        if parse_iso8601_datetime(timestamp) < parse_iso8601_datetime(index["updated_at"]):
            raise ProductStoreError("V2 resource journal clock moved backwards")
        generation = index["generation"] + 1
        event = {
            "schema_version": EVENT_SCHEMA,
            **{name: index[name] for name in _INDEX_FIELDS},
            "generation": generation,
            "event_type": event_type,
            "state": state,
            "role": role,
            "owner_ref": owner_ref,
            "binding_ref": binding_ref,
            "receipt_ref": receipt_ref,
            "previous_digest": index["head_event_digest"],
            "created_at": timestamp,
            "document": document,
        }
        replay.apply(event, index)
        _verify_retained_activation_at(connection, index, replay)
        if replay.settlement_started:
            prospective = dict(index)
            prospective["state"] = state
            prospective["generation"] = generation
            _settlement_snapshot_at(connection, prospective, replay)
        encoded, digest = _bounded(event), content_hash(event)
        connection.execute(
            "INSERT INTO strix_composition_resource_events "
            "(transaction_ref,tx_sequence,event_type,state,role,owner_ref,binding_ref,receipt_ref,"
            "previous_digest,document_schema,document_json,event_digest,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                index["transaction_ref"],
                generation,
                event_type,
                state,
                role,
                owner_ref,
                binding_ref,
                receipt_ref,
                index["head_event_digest"],
                EVENT_SCHEMA,
                encoded,
                digest,
                timestamp,
            ),
        )
        changed = connection.execute(
            "UPDATE strix_composition_resource_transactions SET state=?,generation=?,"
            "head_event_digest=?,updated_at=? WHERE transaction_ref=? AND generation=? "
            "AND head_event_digest IS ?",
            (
                state,
                generation,
                digest,
                timestamp,
                index["transaction_ref"],
                index["generation"],
                index["head_event_digest"],
            ),
        ).rowcount
        if changed != 1:
            raise ResourceConflictError("V2 resource transaction compare-and-swap failed")
        return InstalledStrixV2TransactionHead(index["transaction_ref"], generation, state)

    def load_transaction(self, transaction_ref: str) -> InstalledStrixV2TransactionHead:
        try:
            _digest(transaction_ref, "V2 resource transaction")
            with self._store._connection() as connection:
                if not connection.in_transaction:
                    connection.execute("BEGIN")
                index, _replay = _read_at(connection, transaction_ref)
                return _head(index)
        except (
            KeyError,
            TypeError,
            ValueError,
            RecursionError,
            InstalledStrixV2CompositionError,
        ) as exc:
            raise ProductStoreError("V2 resource transaction cannot be loaded") from exc


__all__ = [
    "InstalledStrixV2RoleTerminalObserver",
    "InstalledStrixV2SettlementSnapshot",
    "ProductStoreInstalledStrixV2TransactionRepository",
]
