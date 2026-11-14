"""Protected source-collection terminal adapter for one installed Strix V2 attempt.

The installed service supplies its owned source collector. This adapter only
reopens the collector's retained receipt and compares it with the ProductStore
resource identity and authenticated native receipt chain. It cannot create a
source terminal, infer whole-set absence, or prove an independent target effect.
"""

from __future__ import annotations

from typing import Protocol

from .engine_installed_v2_authority import _digest
from .product_store import ProductStore
from .product_store_errors import ResourceConflictError
from .strix_v2_role_terminal_observer import (
    StrixV2ExpectedRoleIdentity,
    StrixV2ProtectedRoleEvidence,
)
from .util import content_hash, parse_iso8601_datetime

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
    native_observed: dict[str, object]
    native_qualified: dict[str, object]
    native_terminal: dict[str, object]


class _ProtectedSourceOwner(Protocol):
    source_identity_ref: str
    transaction_ref: str
    attempt_id: str
    authority_ref: str
    prelaunch_binding_ref: str
    owner_ref: str
    binding_ref: str

    def reopen_source_receipt(self, source_receipt_ref: str) -> _SourceTerminalReceipt: ...


class _RetainedNativeRecord(Protocol):
    kind: str
    document: dict[str, object]


class _ProtectedNativeReceiptLedger(Protocol):
    _store: ProductStore

    def reopen(
        self,
        *,
        attempt_id: str,
        claim_ref: str,
        prelaunch_ref: str,
        transaction_ref: str,
        closure_plan_ref: str,
        worker_plan_digest: str,
    ) -> tuple[_RetainedNativeRecord, ...]: ...


class SourceCollectionRoleTerminalAdapter:
    """Read-only join of source, protected native packets, and saved ownership.

    Only the installed service may supply the concrete protected source owner
    and ProductStore controller receipt journal; neither may come from a
    request, plugin, or model-generated result.
    """

    def __init__(
        self,
        *,
        product_store: ProductStore,
        source_owner: _ProtectedSourceOwner,
        native_receipt_journal: _ProtectedNativeReceiptLedger | None,
        closure_plan_ref: str,
        worker_plan_digest: str,
    ) -> None:
        if not isinstance(product_store, ProductStore):
            raise ResourceConflictError("V2 source collection ProductStore is unavailable")
        if source_owner is None or not callable(
            getattr(source_owner, "reopen_source_receipt", None)
        ):
            raise ResourceConflictError("V2 protected source collection owner is unavailable")
        if native_receipt_journal is not None and (
            getattr(native_receipt_journal, "_store", None) is not product_store
            or not callable(getattr(native_receipt_journal, "reopen", None))
        ):
            raise ResourceConflictError("V2 native receipt ledger belongs to another store")
        self._store = product_store
        self._source = source_owner
        self._owner_identity_ref = _digest(
            getattr(source_owner, "source_identity_ref", None),
            "V2 source collection protected identity",
        )
        self._native_journal = native_receipt_journal
        self._closure_plan_ref = _digest(closure_plan_ref, "V2 native closure plan")
        self._worker_plan_digest = _digest(worker_plan_digest, "V2 worker invocation plan")

    @property
    def source_identity_ref(self) -> str:
        current = _digest(
            getattr(self._source, "source_identity_ref", None),
            "V2 source collection protected identity",
        )
        if current != self._owner_identity_ref:
            raise ResourceConflictError("V2 source collection protected identity changed")
        return content_hash(
            {
                "schema_version": "bluefire.strix-v2-source-terminal-adapter.v1",
                "source_owner_identity_ref": current,
                "closure_plan_ref": self._closure_plan_ref,
                "worker_plan_digest": self._worker_plan_digest,
            }
        )

    def reopen_source(
        self,
        source_receipt_ref: str,
        expected: StrixV2ExpectedRoleIdentity,
    ) -> StrixV2ProtectedRoleEvidence | None:
        if not isinstance(expected, StrixV2ExpectedRoleIdentity) or expected.role != _ROLE:
            raise ResourceConflictError("V2 source collection role binding is invalid")
        _digest(source_receipt_ref, "V2 source collection terminal reference")
        _ = self.source_identity_ref
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
        if receipt is None:
            raise ResourceConflictError("V2 source collection protected source changed")
        _ = self.source_identity_ref
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
        ledger = self._native_journal
        if ledger is None:
            return None
        try:
            rows = ledger.reopen(
                attempt_id=expected.attempt_id,
                claim_ref=expected.claim_ref,
                prelaunch_ref=expected.authority_ref,
                transaction_ref=expected.transaction_ref,
                closure_plan_ref=self._closure_plan_ref,
                worker_plan_digest=self._worker_plan_digest,
            )
        except Exception as exc:
            raise ResourceConflictError("V2 protected native receipts cannot be reopened") from exc
        protected = {}
        for row in rows:
            if row.kind in {"native_observed", "native_qualified", "native_terminal"}:
                document = row.document.get("source")
                if not isinstance(document, dict) or not isinstance(document.get("document"), dict):
                    raise ResourceConflictError("V2 protected native packet changed")
                if row.kind in protected:
                    raise ResourceConflictError("V2 protected native packet was duplicated")
                protected[row.kind] = document["document"]
        if protected != {
            "native_observed": receipt.native_observed,
            "native_qualified": receipt.native_qualified,
            "native_terminal": receipt.native_terminal,
        }:
            raise ResourceConflictError("V2 source terminal differs from protected native packets")
        _ = self.source_identity_ref
        return StrixV2ProtectedRoleEvidence(
            source_receipt_ref=source_receipt_ref,
            evidence_ref=evidence_ref,
            state=receipt.state,
            source_observed_at=observed_at,
        )
