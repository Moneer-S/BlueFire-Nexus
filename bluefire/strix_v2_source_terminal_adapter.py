"""Protected source-collection terminal adapter for one installed Strix V2 attempt.

The installed service supplies its owned source collector. This adapter only
reopens the collector's retained receipt and compares it with the ProductStore
resource identity. It cannot create a source terminal or infer whole-set absence.
"""

from __future__ import annotations

from typing import Protocol

from .engine_installed_v2_authority import _digest
from .product_store_errors import ResourceConflictError
from .strix_v2_role_terminal_observer import (
    StrixV2ExpectedRoleIdentity,
    StrixV2ProtectedRoleEvidence,
)
from .util import parse_iso8601_datetime

_ROLE = "source_collection"
_SCHEMA = "bluefire.installed-strix-v2-source-collection-terminal.v1"


class _SourceTerminalReceipt(Protocol):
    schema_version: str
    transaction_ref: str
    attempt_id: str
    authority_ref: str
    claim_ref: str
    runtime_activation_ref: str
    prelaunch_binding_ref: str
    resource_ref: str
    owner_ref: str
    role: str
    state: str
    evidence_ref: str
    observed_at: str
    receipt_ref: str


class _ProtectedSourceOwner(Protocol):
    source_identity_ref: str
    transaction_ref: str
    attempt_id: str
    authority_ref: str
    prelaunch_binding_ref: str
    owner_ref: str
    binding_ref: str

    def reopen_source_receipt(self, source_receipt_ref: str) -> _SourceTerminalReceipt: ...


class SourceCollectionRoleTerminalAdapter:
    """Read-only join of a controller-owned source and its durable terminal."""

    def __init__(self, source_owner: _ProtectedSourceOwner) -> None:
        if source_owner is None or not callable(
            getattr(source_owner, "reopen_source_receipt", None)
        ):
            raise ResourceConflictError("V2 protected source collection owner is unavailable")
        self._source = source_owner
        self._source_identity_ref = _digest(
            getattr(source_owner, "source_identity_ref", None),
            "V2 source collection protected identity",
        )

    @property
    def source_identity_ref(self) -> str:
        current = _digest(
            getattr(self._source, "source_identity_ref", None),
            "V2 source collection protected identity",
        )
        if current != self._source_identity_ref:
            raise ResourceConflictError("V2 source collection protected identity changed")
        return current

    def reopen_source(
        self,
        source_receipt_ref: str,
        expected: StrixV2ExpectedRoleIdentity,
    ) -> StrixV2ProtectedRoleEvidence | None:
        if not isinstance(expected, StrixV2ExpectedRoleIdentity) or expected.role != _ROLE:
            raise ResourceConflictError("V2 source collection role binding is invalid")
        _digest(source_receipt_ref, "V2 source collection terminal reference")
        if self.source_identity_ref != self._source_identity_ref:
            raise ResourceConflictError("V2 source collection protected identity changed")
        source = self._source
        for name, value in (
            ("transaction_ref", expected.transaction_ref),
            ("attempt_id", expected.attempt_id),
            ("authority_ref", expected.authority_ref),
            ("prelaunch_binding_ref", expected.prelaunch_binding_ref),
            ("owner_ref", expected.owner_ref),
            ("binding_ref", expected.resource_ref),
        ):
            if getattr(source, name, None) != value:
                raise ResourceConflictError("V2 source collection owner changed")
        try:
            receipt = source.reopen_source_receipt(source_receipt_ref)
        except Exception as exc:
            raise ResourceConflictError("V2 source collection terminal cannot be reopened") from exc
        if receipt is None or self.source_identity_ref != self._source_identity_ref:
            raise ResourceConflictError("V2 source collection protected source changed")
        for name, value in (
            ("schema_version", _SCHEMA),
            ("transaction_ref", expected.transaction_ref),
            ("attempt_id", expected.attempt_id),
            ("authority_ref", expected.authority_ref),
            ("claim_ref", expected.claim_ref),
            ("runtime_activation_ref", expected.runtime_activation_ref),
            ("prelaunch_binding_ref", expected.prelaunch_binding_ref),
            ("resource_ref", expected.resource_ref),
            ("owner_ref", expected.owner_ref),
            ("role", _ROLE),
            ("receipt_ref", source_receipt_ref),
        ):
            if getattr(receipt, name, None) != value:
                raise ResourceConflictError("V2 source collection terminal binding changed")
        if receipt.state not in {"verified_settled", "verified_absent"}:
            raise ResourceConflictError("V2 source collection terminal state changed")
        evidence_ref = _digest(receipt.evidence_ref, "V2 source collection evidence")
        observed_at = receipt.observed_at
        parse_iso8601_datetime(observed_at)
        return StrixV2ProtectedRoleEvidence(
            source_receipt_ref=source_receipt_ref,
            evidence_ref=evidence_ref,
            state=receipt.state,
            source_observed_at=observed_at,
        )
