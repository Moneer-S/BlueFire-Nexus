"""Controller model lease observations, without starting a worker or provider."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire.engine_relay import (
    BoundedRelayAudit,
    ControlledModelGateway,
    EngineRelayError,
    GatewayRevocationReceipt,
    RelayAuditRecord,
)
from bluefire.product_store import ProductStore
from bluefire.product_store_strix_model_terminal import ProductStoreModelLeaseTerminalSource
from bluefire.strix_installed_model_lease_custody import (
    ControllerOwnedInstalledModelLease,
    InstalledModelLeaseCustodyError,
    InstalledModelLeaseTerminalReceipt,
)
from bluefire.util import content_hash
from tests_platform.test_engine_relay import FakeClock, _gateway
from tests_platform.test_strix_controlled_bootstrap import _profile
from tests_platform.test_strix_controlled_worker_channel import _binding
from tests_platform.test_strix_controlled_worker_rpc import _invocation


def _digest(label: str) -> str:
    return content_hash({"label": label})


class _TerminalSource:
    def __init__(self) -> None:
        self.receipts: dict[str, InstalledModelLeaseTerminalReceipt] = {}

    def retain(
        self, receipt: InstalledModelLeaseTerminalReceipt, *, timeout_seconds: float
    ) -> None:
        assert timeout_seconds > 0
        previous = self.receipts.get(receipt.evidence_ref)
        if previous is not None and previous != receipt:
            raise ValueError("terminal evidence identity conflict")
        self.receipts[receipt.evidence_ref] = receipt

    def reopen(
        self, evidence_ref: str, *, timeout_seconds: float
    ) -> InstalledModelLeaseTerminalReceipt | None:
        assert timeout_seconds > 0
        return self.receipts.get(evidence_ref)


class _Gateway(ControlledModelGateway):
    """Stand-in for the already separately tested protected gateway core."""

    def __init__(self, *, attempt_id: str, authorization_ref: str, model_id: str) -> None:
        self.policy = SimpleNamespace(
            attempt_id=attempt_id,
            authorization_ref=authorization_ref,
            policy_digest=_digest("policy"),
            provider_ref=_digest("provider"),
            model_id=model_id,
            data_destination_ref=_digest("destination"),
        )
        self.token = "test-relay-bearer-" + "a" * 32
        self.revoked = False
        self.drained = True
        self.protected = True
        self.accepted_requests = 0
        self.request_bytes = 0
        self.inflight_at_revocation = False
        self.on_secret: object = None
        self.block_bounded_revoke = False
        self.bounded_revoke_calls: list[float] = []

    def secret_value(self) -> str:
        if self.revoked:
            raise EngineRelayError("revoked", "gateway bearer is revoked")
        if callable(self.on_secret):
            self.on_secret()
        return self.token

    def revoke(self) -> GatewayRevocationReceipt:
        self.revoked = True
        return GatewayRevocationReceipt(
            attempt_id=self.policy.attempt_id,
            authorization_ref=self.policy.authorization_ref,
            policy_digest=self.policy.policy_digest,
            accepted_requests=self.accepted_requests,
            inflight_request=self.inflight_at_revocation,
            consumed_request_bytes=self.request_bytes,
            reserved_response_bytes=1024 * self.accepted_requests,
            reserved_tokens=512 * self.accepted_requests,
            reserved_cost_microunits=100000 * self.accepted_requests,
            protected_revocation_verified=self.protected,
            protected_revocation_ref=_digest("protected-revocation") if self.protected else None,
        )

    def revoke_bounded(self, timeout_seconds: float) -> GatewayRevocationReceipt:
        assert 0 < timeout_seconds <= 10
        self.bounded_revoke_calls.append(timeout_seconds)
        if self.block_bounded_revoke:
            time.sleep(timeout_seconds)
            return replace(self.revoke(), protected_revocation_verified=False)
        return self.revoke()

    def revocation_drained(self, receipt: GatewayRevocationReceipt) -> bool:
        return self.revoked and self.drained and receipt.protected_revocation_verified


def _owners(
    tmp_path: Path, *, timeout_seconds: float = 2.0
) -> tuple[
    ControllerOwnedInstalledModelLease,
    _Gateway,
    BoundedRelayAudit,
    _TerminalSource,
    object,
    tuple[int, int, int, int, tuple[int, ...]],
    dict[str, bool],
]:
    profile = _profile()
    invocation = _invocation(tmp_path, profile)
    binding = replace(_binding(profile), plan_digest=invocation.intent_digest)
    custody = (1234, 1001, 1001, 987654, (1234,))
    authorization_ref = content_hash(
        {
            "schema_version": "bluefire.model-gateway-authorization-ref.v1",
            "attempt_id": invocation.profile_attempt_id,
            "authorization_digest": invocation.model_authorization_digest,
        }
    )
    gateway = _Gateway(
        attempt_id=profile.attempt_id,
        authorization_ref=authorization_ref,
        model_id=invocation.model,
    )
    audit = BoundedRelayAudit()
    source = _TerminalSource()
    state = {"active": False}

    def require_active() -> None:
        if not state["active"]:
            raise InstalledModelLeaseCustodyError("attempt transaction is not active")

    lease = ControllerOwnedInstalledModelLease(
        gateway=gateway,
        audit=audit,
        binding=binding,
        invocation=invocation,
        custody_identity=custody,
        engine_binding_ref=_digest("binding"),
        delegation_ref=_digest("delegation"),
        accepted_claim_ref=_digest("accepted-claim"),
        admission_ref=_digest("admission"),
        relay_listener_ref=_digest("listener"),
        model_provider="controlled-test",
        model_data_destination=dict(invocation.environment)["LLM_API_BASE"],
        provider_kind="test",
        live_model_proof=False,
        require_active_transaction=require_active,
        terminal_source=source,
        timeout_seconds=timeout_seconds,
    )
    return lease, gateway, audit, source, binding, custody, state


def test_model_bearer_requires_committed_active_transaction(tmp_path: Path) -> None:
    lease, gateway, _audit, _source, binding, custody, state = _owners(tmp_path)
    with pytest.raises(InstalledModelLeaseCustodyError, match="not active"):
        lease.claim(binding, custody)
    assert gateway.revoked is False
    state["active"] = True
    assert lease.claim(binding, custody) == gateway.token


def test_authority_loss_during_secret_read_releases_no_bearer(tmp_path: Path) -> None:
    lease, gateway, _audit, _source, binding, custody, state = _owners(tmp_path)
    state["active"] = True
    gateway.on_secret = lambda: state.__setitem__("active", False)
    with pytest.raises(InstalledModelLeaseCustodyError, match="before model bearer release"):
        lease.claim(binding, custody)
    assert gateway.revoked is True
    assert lease.cleanup_uncertain is True


def test_protected_gateway_exposes_post_revocation_drain() -> None:
    gateway, _forwarder, _audit = _gateway(FakeClock())
    receipt = gateway.revoke()
    assert gateway.revocation_drained(receipt)
    assert not gateway.revocation_drained(
        replace(receipt, protected_revocation_ref=_digest("another-revocation"))
    )


def test_artifact_bearer_scan_covers_plain_and_common_encoded_forms() -> None:
    import base64
    from urllib.parse import quote_from_bytes

    gateway, _forwarder, _audit = _gateway(FakeClock())
    raw = gateway.secret_value().encode("ascii")
    values = (
        raw,
        raw.hex().encode("ascii"),
        base64.b64encode(raw),
        base64.urlsafe_b64encode(raw).rstrip(b"="),
        quote_from_bytes(raw, safe="").encode("ascii"),
        b"".join(f"%{byte:02x}".encode("ascii") for byte in raw),
        b"".join(f"\\u{byte:04x}".encode("ascii") for byte in raw),
    )
    gateway.revoke()
    for value in values:
        assert gateway.bearer_absent_from_retained_bytes(b"prefix" + value + b"suffix") is False
    assert gateway.bearer_absent_from_retained_bytes(b'{"result":"clean"}') is True


def test_revocation_requires_durable_reopen_and_full_request_audit(tmp_path: Path) -> None:
    lease, gateway, audit, source, _binding_row, _custody, _state = _owners(tmp_path)
    row = RelayAuditRecord(
        relay_kind="model_gateway",
        attempt_id=gateway.policy.attempt_id,
        objective_ref=_digest("objective"),
        sequence=1,
        request_id="gateway-request-" + "1" * 32,
        operation="chat_completions",
        request_digest=_digest("request"),
        request_bytes=71,
        response_digest=_digest("response"),
        response_bytes=32,
        status="succeeded",
        result_status=200,
        input_tokens=20,
        output_tokens=11,
        cost_microunits=0,
        elapsed_ms=12,
        recorded_at="2026-11-13T12:00:00Z",
        policy_digest=gateway.policy.policy_digest,
        evidence_ref=_digest("provider-request"),
        fixture_usage_estimate=True,
        live_model_proof=False,
    )
    audit.append(row)
    gateway.accepted_requests = 1
    gateway.request_bytes = 71
    gateway.inflight_at_revocation = True
    receipt = lease.revoke_and_observe()
    assert receipt.inflight_at_revocation is True
    assert receipt.accepted_requests == receipt.successful_requests == 1
    assert receipt.input_tokens == 20 and receipt.output_tokens == 11
    assert receipt.audit_refs == (row.record_digest,)
    assert receipt == lease.reopen_terminal()
    assert lease.cleanup_uncertain is False
    del source.receipts[receipt.evidence_ref]
    assert lease.reopen_terminal() is None
    assert lease.cleanup_uncertain is True


def test_private_product_store_reopens_typed_terminal_after_restart(tmp_path: Path) -> None:
    lease, _gateway, _audit, _source, _binding_row, _custody, _state = _owners(tmp_path)
    receipt = lease.revoke_and_observe()
    database_path = tmp_path / "product.db"
    first = ProductStoreModelLeaseTerminalSource(ProductStore(database_path))
    first.retain(receipt, timeout_seconds=1)
    reopened = ProductStoreModelLeaseTerminalSource(ProductStore(database_path)).reopen(
        receipt.receipt_ref, timeout_seconds=1
    )
    assert reopened == receipt
    assert InstalledModelLeaseTerminalReceipt.from_document(reopened.document()) == receipt
    assert first.reopen(_digest("missing"), timeout_seconds=1) is None


def test_private_terminal_retain_times_out_on_busy_product_database(tmp_path: Path) -> None:
    lease, _gateway, _audit, _source, _binding_row, _custody, _state = _owners(tmp_path)
    receipt = lease.revoke_and_observe()
    database_path = tmp_path / "product.db"
    source = ProductStoreModelLeaseTerminalSource(ProductStore(database_path))
    with sqlite3.connect(database_path) as blocker:
        blocker.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        with pytest.raises(InstalledModelLeaseCustodyError, match="unavailable"):
            source.retain(receipt, timeout_seconds=0.05)
        assert time.monotonic() - started < 0.5
    assert source.reopen(receipt.receipt_ref, timeout_seconds=1) is None


def test_retained_model_terminal_rechecks_source_usage_not_only_its_hash(
    tmp_path: Path,
) -> None:
    lease, _gateway, _audit, _source, _binding_row, _custody, _state = _owners(tmp_path)
    receipt = lease.revoke_and_observe()
    changed = replace(
        receipt,
        gateway_revocation=replace(receipt.gateway_revocation, consumed_request_bytes=1),
    )
    changed = replace(changed, evidence_ref=content_hash(changed.unsigned_document()))
    with pytest.raises(InstalledModelLeaseCustodyError, match="audit changed"):
        changed.validate()


def test_missing_request_audit_never_proves_revocation(tmp_path: Path) -> None:
    lease, gateway, _audit, source, _binding_row, _custody, _state = _owners(tmp_path)
    gateway.accepted_requests = 1
    gateway.request_bytes = 71
    with pytest.raises(InstalledModelLeaseCustodyError, match="audit coverage"):
        lease.revoke_and_observe()
    assert source.receipts == {}
    assert lease.cleanup_uncertain is True


@pytest.mark.parametrize("unresolved", ["protected", "drain"])
def test_unresolved_protected_or_active_gateway_remains_unknown(
    tmp_path: Path, unresolved: str
) -> None:
    lease, gateway, _audit, source, _binding_row, _custody, _state = _owners(tmp_path)
    if unresolved == "protected":
        gateway.protected = False
    else:
        gateway.drained = False
    with pytest.raises((InstalledModelLeaseCustodyError, RuntimeError)):
        lease.revoke_and_observe()
    assert source.receipts == {}
    assert lease.cleanup_uncertain is True


def test_model_lease_revoke_reconciliation_shares_one_total_bound(tmp_path: Path) -> None:
    lease, gateway, _audit, source, _binding_row, _custody, _state = _owners(
        tmp_path, timeout_seconds=0.08
    )
    gateway.block_bounded_revoke = True
    started = time.monotonic()
    with pytest.raises(RuntimeError):
        lease.revoke_and_observe()
    assert time.monotonic() - started < 0.3
    assert gateway.bounded_revoke_calls
    assert sum(gateway.bounded_revoke_calls) <= 0.09
    assert source.receipts == {}
    assert lease.cleanup_uncertain is True
