"""Join protected role terminal sources to exact saved V2 resource ownership.

The observer only reopens source evidence. It neither stops resources nor turns
six role receipts into a whole-set absence claim. A missing source leaves that
role unresolved in the ProductStore settlement journal.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from .engine_installed_attempt_factory import INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES
from .engine_installed_v2_authority import _digest
from .product_store import ProductStore
from .product_store_errors import ResourceConflictError
from .product_store_strix_v2_resources import _read_at, _settlement_snapshot_at
from .util import content_hash, parse_iso8601_datetime

_ROLE_TERMINAL_STATES = {
    "caido_channel": frozenset({"verified_absent"}),
    "docker_control": frozenset({"verified_absent"}),
    "model_gateway": frozenset({"verified_revoked"}),
    "source_collection": frozenset({"verified_absent", "verified_settled"}),
    "target_relay": frozenset({"verified_revoked"}),
    "worker_controller": frozenset({"verified_absent"}),
}


@dataclass(frozen=True, slots=True)
class StrixV2ExpectedRoleIdentity:
    transaction_ref: str
    attempt_id: str
    authority_ref: str
    claim_ref: str
    runtime_activation_ref: str
    role: str
    prelaunch_binding_ref: str
    resource_ref: str
    owner_ref: str


@dataclass(frozen=True, slots=True)
class StrixV2ProtectedRoleEvidence:
    source_receipt_ref: str
    evidence_ref: str
    state: str
    source_observed_at: str | None


class StrixV2ProtectedRoleSource(Protocol):
    """A concrete owner adapter that independently reopens its typed receipt."""

    @property
    def source_identity_ref(self) -> str: ...

    def reopen_source(
        self, source_receipt_ref: str, expected: StrixV2ExpectedRoleIdentity
    ) -> StrixV2ProtectedRoleEvidence | None: ...


class InstalledStrixV2ProtectedRoleTerminalObserver:
    """Fail-closed join of admitted owners and trusted installed source adapters.

    The installed service must build the source inventory from its concrete
    protected role owners. Request data or caller-supplied adapters are not a
    terminal authority; this class only joins already trusted source owners.
    """

    def __init__(
        self,
        *,
        product_store: ProductStore,
        transaction_ref: str,
        sources: Mapping[str, StrixV2ProtectedRoleSource],
    ) -> None:
        if not isinstance(product_store, ProductStore):
            raise ResourceConflictError("V2 role observer ProductStore is unavailable")
        self._store = product_store
        self._transaction_ref = _digest(transaction_ref, "V2 role observer transaction")
        if not isinstance(sources, Mapping) or any(
            role not in INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES for role in sources
        ):
            raise ResourceConflictError("V2 role observer source inventory is invalid")
        self._sources = dict(sources)

    def _expected(self, role: str) -> StrixV2ExpectedRoleIdentity:
        if role not in INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES:
            raise ResourceConflictError("V2 role observer role is invalid")
        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            index, replay = _read_at(connection, self._transaction_ref)
            snapshot = _settlement_snapshot_at(connection, index, replay)
        if snapshot.action != "execution" or snapshot.state not in {
            "stopping",
            "cleanup_unknown",
            "closed",
        }:
            raise ResourceConflictError("V2 role observer has no committed settlement")
        owner = next((row for row in snapshot.role_owner_bindings if row[0] == role), None)
        resource_ref = dict(snapshot.actual_role_bindings).get(role)
        if owner is None or resource_ref is None:
            raise ResourceConflictError("V2 role observer lacks exact owned resource")
        return StrixV2ExpectedRoleIdentity(
            transaction_ref=snapshot.transaction_ref,
            attempt_id=snapshot.attempt_id,
            authority_ref=snapshot.authority_ref,
            claim_ref=snapshot.claim_ref,
            runtime_activation_ref=snapshot.runtime_activation_ref,
            role=role,
            prelaunch_binding_ref=owner[1],
            resource_ref=resource_ref,
            owner_ref=owner[2],
        )

    def _source(self, role: str) -> StrixV2ProtectedRoleSource:
        source = self._sources.get(role)
        if source is None or not callable(getattr(source, "reopen_source", None)):
            raise ResourceConflictError("V2 protected role source is unavailable")
        _digest(source.source_identity_ref, "V2 protected role source identity")
        return source

    def role_identity_ref(self, role: str) -> str:
        expected = self._expected(role)
        source = self._source(role)
        return self._role_identity(expected, source.source_identity_ref)

    @staticmethod
    def _role_identity(expected: StrixV2ExpectedRoleIdentity, source_identity_ref: str) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.strix-v2-protected-role-observer.v1",
                "transaction_ref": expected.transaction_ref,
                "attempt_id": expected.attempt_id,
                "runtime_activation_ref": expected.runtime_activation_ref,
                "role": expected.role,
                "prelaunch_binding_ref": expected.prelaunch_binding_ref,
                "resource_ref": expected.resource_ref,
                "owner_ref": expected.owner_ref,
                "protected_source_identity_ref": source_identity_ref,
            }
        )

    def reopen_role_terminal(self, *, role: str, source_receipt_ref: str) -> Mapping[str, object]:
        _digest(source_receipt_ref, "V2 protected role source receipt")
        expected = self._expected(role)
        source = self._source(role)
        evidence = source.reopen_source(source_receipt_ref, expected)
        if evidence is None or not isinstance(evidence, StrixV2ProtectedRoleEvidence):
            raise ResourceConflictError("V2 protected role terminal is unavailable")
        if (
            evidence.source_receipt_ref != source_receipt_ref
            or evidence.state not in _ROLE_TERMINAL_STATES[role]
        ):
            raise ResourceConflictError("V2 protected role terminal identity changed")
        _digest(evidence.evidence_ref, "V2 protected role evidence")
        if evidence.source_observed_at is not None:
            parse_iso8601_datetime(evidence.source_observed_at)
        return {
            "schema_version": "bluefire.installed-strix-v2-role-terminal-observation.v2",
            "transaction_ref": expected.transaction_ref,
            "attempt_id": expected.attempt_id,
            "authority_ref": expected.authority_ref,
            "claim_ref": expected.claim_ref,
            "runtime_activation_ref": expected.runtime_activation_ref,
            "role": role,
            "prelaunch_binding_ref": expected.prelaunch_binding_ref,
            "resource_ref": expected.resource_ref,
            "owner_ref": expected.owner_ref,
            "state": evidence.state,
            "evidence_ref": evidence.evidence_ref,
            "source_receipt_ref": source_receipt_ref,
            "source_identity_ref": self._role_identity(expected, source.source_identity_ref),
            "source_observed_at": evidence.source_observed_at,
        }
