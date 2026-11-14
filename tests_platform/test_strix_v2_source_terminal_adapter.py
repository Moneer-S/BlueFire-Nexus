"""Contract fixtures for the source terminal to ProductStore identity join.

These fixtures do not establish installed source or native cleanup proof.
"""

from dataclasses import asdict
from types import SimpleNamespace

import pytest

from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ResourceConflictError
from bluefire.strix_v2_role_terminal_observer import StrixV2ExpectedRoleIdentity
from bluefire.strix_v2_source_terminal_adapter import SourceCollectionRoleTerminalAdapter
from bluefire.util import content_hash

_CLOSURE_REF = content_hash("native-closure")
_WORKER_PLAN = content_hash("worker-plan")


@pytest.fixture
def store(tmp_path):
    return ProductStore(tmp_path / "private" / "product.sqlite3")


def _expected() -> StrixV2ExpectedRoleIdentity:
    return StrixV2ExpectedRoleIdentity(
        transaction_ref=content_hash("transaction"),
        attempt_id="engine-attempt-" + "a" * 32,
        authority_ref=content_hash("authority"),
        claim_ref=content_hash("claim"),
        runtime_activation_ref=content_hash("activation"),
        role="source_collection",
        prelaunch_binding_ref=content_hash("prelaunch-binding"),
        resource_ref=content_hash("resource"),
        owner_ref=content_hash("owner"),
    )


class _FixtureSource:
    def __init__(self, expected: StrixV2ExpectedRoleIdentity) -> None:
        self.source_identity_ref = content_hash("protected-source-fixture")
        self.transaction_ref = expected.transaction_ref
        self.attempt_id = expected.attempt_id
        self.authority_ref = expected.authority_ref
        self.prelaunch_binding_ref = expected.prelaunch_binding_ref
        self.owner_ref = expected.owner_ref
        self.binding_ref = expected.resource_ref
        self.receipt_ref = content_hash("saved-source-terminal")
        self.receipt = SimpleNamespace(
            schema_version="bluefire.installed-strix-v2-source-collection-terminal.v1",
            **asdict(expected),
            state="verified_settled",
            evidence_ref=content_hash("saved-source-evidence"),
            observed_at="2026-11-13T12:00:00Z",
            receipt_ref=self.receipt_ref,
            native_observed={"phase": "observed"},
            native_qualified={"phase": "qualified"},
            native_terminal={"phase": "terminal"},
        )

    def reopen_source_receipt(self, source_receipt_ref: str):
        if source_receipt_ref != self.receipt_ref:
            raise KeyError(source_receipt_ref)
        return self.receipt


class _FixtureNativeLedger:
    def __init__(self, store, source, expected):
        self._store = store
        self.expected = expected
        self.documents = {
            "native_observed": dict(source.receipt.native_observed),
            "native_qualified": dict(source.receipt.native_qualified),
            "native_terminal": dict(source.receipt.native_terminal),
        }

    def reopen(self, **refs):
        assert refs == {
            "attempt_id": self.expected.attempt_id,
            "claim_ref": self.expected.claim_ref,
            "prelaunch_ref": self.expected.authority_ref,
            "transaction_ref": self.expected.transaction_ref,
            "closure_plan_ref": _CLOSURE_REF,
            "worker_plan_digest": _WORKER_PLAN,
        }
        return tuple(
            SimpleNamespace(kind=kind, document={"source": {"document": document}})
            for kind, document in self.documents.items()
        )


def _adapter(store, source, expected, *, ledger=True):
    return SourceCollectionRoleTerminalAdapter(
        product_store=store,
        source_owner=source,
        native_receipt_journal=_FixtureNativeLedger(store, source, expected) if ledger else None,
        closure_plan_ref=_CLOSURE_REF,
        worker_plan_digest=_WORKER_PLAN,
    )


def test_source_terminal_adapter_joins_exact_owner_contract_fixture(store):
    expected = _expected()
    source = _FixtureSource(expected)
    adapter = _adapter(store, source, expected)
    evidence = adapter.reopen_source(source.receipt_ref, expected)
    assert evidence.source_receipt_ref == source.receipt_ref
    assert evidence.evidence_ref == source.receipt.evidence_ref
    assert evidence.state == "verified_settled"
    assert evidence.source_observed_at == source.receipt.observed_at
    assert adapter.source_identity_ref != source.source_identity_ref


def test_source_terminal_adapter_refuses_changed_receipt_or_owner_contract_fixture(store):
    expected = _expected()
    source = _FixtureSource(expected)
    adapter = _adapter(store, source, expected)
    source.receipt.claim_ref = content_hash("different-claim")
    with pytest.raises(ResourceConflictError, match="binding changed"):
        adapter.reopen_source(source.receipt_ref, expected)
    source.receipt.claim_ref = expected.claim_ref
    source.owner_ref = content_hash("different-owner")
    with pytest.raises(ResourceConflictError, match="owner changed"):
        adapter.reopen_source(source.receipt_ref, expected)
    source.owner_ref = expected.owner_ref
    source.source_identity_ref = content_hash("different-source")
    with pytest.raises(ResourceConflictError, match="identity changed"):
        adapter.reopen_source(source.receipt_ref, expected)


def test_source_terminal_adapter_refuses_missing_protected_reopen_contract_fixture(store):
    expected = _expected()
    source = _FixtureSource(expected)
    adapter = _adapter(store, source, expected)
    with pytest.raises(ResourceConflictError, match="cannot be reopened"):
        adapter.reopen_source(content_hash("missing-terminal"), expected)


def test_source_terminal_adapter_requires_native_ledger_and_exact_packets_contract_fixture(store):
    expected = _expected()
    source = _FixtureSource(expected)
    assert (
        _adapter(store, source, expected, ledger=False).reopen_source(source.receipt_ref, expected)
        is None
    )
    adapter = _adapter(store, source, expected)
    source.receipt.native_terminal = {"phase": "different-terminal"}
    with pytest.raises(ResourceConflictError, match="differs from protected native"):
        adapter.reopen_source(source.receipt_ref, expected)
