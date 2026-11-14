"""Contract fixtures for the source terminal to ProductStore identity join.

These fixtures do not establish installed source or native cleanup proof.
"""

from dataclasses import asdict
from types import SimpleNamespace

import pytest

from bluefire.product_store_errors import ResourceConflictError
from bluefire.strix_v2_role_terminal_observer import StrixV2ExpectedRoleIdentity
from bluefire.strix_v2_source_terminal_adapter import SourceCollectionRoleTerminalAdapter
from bluefire.util import content_hash


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
        )

    def reopen_source_receipt(self, source_receipt_ref: str):
        if source_receipt_ref != self.receipt_ref:
            raise KeyError(source_receipt_ref)
        return self.receipt


def test_source_terminal_adapter_joins_exact_owner_contract_fixture():
    expected = _expected()
    source = _FixtureSource(expected)
    adapter = SourceCollectionRoleTerminalAdapter(source)
    evidence = adapter.reopen_source(source.receipt_ref, expected)
    assert evidence.source_receipt_ref == source.receipt_ref
    assert evidence.evidence_ref == source.receipt.evidence_ref
    assert evidence.state == "verified_settled"
    assert evidence.source_observed_at == source.receipt.observed_at
    assert adapter.source_identity_ref == source.source_identity_ref


def test_source_terminal_adapter_refuses_changed_receipt_or_owner_contract_fixture():
    expected = _expected()
    source = _FixtureSource(expected)
    adapter = SourceCollectionRoleTerminalAdapter(source)
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


def test_source_terminal_adapter_refuses_missing_protected_reopen_contract_fixture():
    expected = _expected()
    source = _FixtureSource(expected)
    adapter = SourceCollectionRoleTerminalAdapter(source)
    with pytest.raises(ResourceConflictError, match="cannot be reopened"):
        adapter.reopen_source(content_hash("missing-terminal"), expected)
