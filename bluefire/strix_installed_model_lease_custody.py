"""Observed model lease custody for one installed Strix V2 worker.

The worker receives a short lived relay bearer only after the installed
transaction is active.  A successful local ``revoke()`` is insufficient for
cleanup: this owner also reopens the protected gateway's revocation result and
its complete hash-only request audit before calling the lease settled.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, fields, replace
from typing import Callable, Mapping, Protocol

from .engine_relay import (
    BoundedRelayAudit,
    ControlledModelGateway,
    EngineRelayError,
    GatewayRevocationReceipt,
    RelayAuditRecord,
)
from .strix_controlled_worker_channel import ControlledWorkerBinding
from .strix_controlled_worker_invocation import ControlledWorkerInvocation
from .strix_controlled_worker_model_gateway import InstalledStrixV2ModelGatewayLease
from .util import content_hash


class InstalledModelLeaseCustodyError(RuntimeError):
    """The exact protected model lease cannot be proven terminal."""


@dataclass(frozen=True, slots=True)
class InstalledModelLeaseTerminalReceipt:
    """Hash-only, exact-source observation of a revoked model gateway."""

    attempt_id: str
    accepted_claim_ref: str
    lease_binding_ref: str
    bearer_scan_binding_ref: str
    custody_identity_ref: str
    authorization_ref: str
    policy_digest: str
    provider_ref: str
    provider_name: str
    model_id: str
    data_destination_ref: str
    provider_kind: str
    admitted_live_model_proof: bool
    live_model_proof: bool
    gateway_revocation: GatewayRevocationReceipt
    gateway_revocation_ref: str
    protected_revocation_ref: str
    inflight_at_revocation: bool
    accepted_requests: int
    successful_requests: int
    input_tokens: int
    output_tokens: int
    cost_microunits: int
    audit_rows: tuple[RelayAuditRecord, ...]
    audit_refs: tuple[str, ...]
    evidence_ref: str

    def unsigned_document(self) -> dict[str, object]:
        return {
            "schema_version": "bluefire.installed-strix-model-lease-terminal.v1",
            "attempt_id": self.attempt_id,
            "accepted_claim_ref": self.accepted_claim_ref,
            "lease_binding_ref": self.lease_binding_ref,
            "bearer_scan_binding_ref": self.bearer_scan_binding_ref,
            "custody_identity_ref": self.custody_identity_ref,
            "authorization_ref": self.authorization_ref,
            "policy_digest": self.policy_digest,
            "provider_ref": self.provider_ref,
            "provider_name": self.provider_name,
            "model_id": self.model_id,
            "data_destination_ref": self.data_destination_ref,
            "provider_kind": self.provider_kind,
            "admitted_live_model_proof": self.admitted_live_model_proof,
            "live_model_proof": self.live_model_proof,
            "gateway_revocation": self.gateway_revocation.to_dict(),
            "gateway_revocation_ref": self.gateway_revocation_ref,
            "protected_revocation_ref": self.protected_revocation_ref,
            "inflight_at_revocation": self.inflight_at_revocation,
            "accepted_requests": self.accepted_requests,
            "successful_requests": self.successful_requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_microunits": self.cost_microunits,
            "audit_rows": [row.to_dict() for row in self.audit_rows],
            "audit_refs": list(self.audit_refs),
        }

    @property
    def receipt_ref(self) -> str:
        return self.evidence_ref

    def document(self) -> dict[str, object]:
        return {**self.unsigned_document(), "evidence_ref": self.evidence_ref}

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> "InstalledModelLeaseTerminalReceipt":
        """Rebuild and validate a complete protected source document."""

        if (
            type(document) is not dict
            or document.get("schema_version") != "bluefire.installed-strix-model-lease-terminal.v1"
            or set(document) != {"schema_version", *(field.name for field in fields(cls))}
            or type(document.get("gateway_revocation")) is not dict
            or type(document.get("audit_rows")) is not list
            or type(document.get("audit_refs")) is not list
        ):
            raise InstalledModelLeaseCustodyError("model lease terminal document changed")
        try:
            gateway = dict(document["gateway_revocation"])
            if gateway.pop("schema_version", None) != "bluefire.model-gateway-revocation.v1":
                raise ValueError
            if set(gateway) != {field.name for field in fields(GatewayRevocationReceipt)}:
                raise ValueError
            rows = []
            for value in document["audit_rows"]:
                if type(value) is not dict:
                    raise ValueError
                row = dict(value)
                if row.pop("schema_version", None) != "bluefire.engine-relay-audit.v2":
                    raise ValueError
                if set(row) != {field.name for field in fields(RelayAuditRecord)}:
                    raise ValueError
                rows.append(RelayAuditRecord(**row))
            receipt = cls(
                **{
                    field.name: (
                        GatewayRevocationReceipt(**gateway)
                        if field.name == "gateway_revocation"
                        else tuple(rows)
                        if field.name == "audit_rows"
                        else tuple(document["audit_refs"])
                        if field.name == "audit_refs"
                        else document[field.name]
                    )
                    for field in fields(cls)
                }
            )
            receipt.validate()
            return receipt
        except (KeyError, TypeError, ValueError, InstalledModelLeaseCustodyError):
            raise InstalledModelLeaseCustodyError("model lease terminal document changed") from None

    def validate(self) -> None:
        from .strix_adapter import _SHA256

        if (
            not self.attempt_id.startswith("engine-attempt-")
            or len(self.attempt_id) != len("engine-attempt-") + 32
            or any(character not in "0123456789abcdef" for character in self.attempt_id[15:])
            or self.provider_kind not in {"test", "live"}
            or type(self.admitted_live_model_proof) is not bool
            or self.provider_kind == "test"
            and self.admitted_live_model_proof
            or type(self.live_model_proof) is not bool
            or self.provider_kind == "test"
            and self.live_model_proof
            or type(self.inflight_at_revocation) is not bool
            or not isinstance(self.gateway_revocation, GatewayRevocationReceipt)
            or type(self.provider_name) is not str
            or not 1 <= len(self.provider_name) <= 80
            or type(self.model_id) is not str
            or not 1 <= len(self.model_id) <= 160
        ):
            raise InstalledModelLeaseCustodyError("model lease terminal identity changed")
        for value in (
            self.accepted_claim_ref,
            self.lease_binding_ref,
            self.bearer_scan_binding_ref,
            self.custody_identity_ref,
            self.authorization_ref,
            self.policy_digest,
            self.provider_ref,
            self.data_destination_ref,
            self.gateway_revocation_ref,
            self.protected_revocation_ref,
            self.evidence_ref,
            *self.audit_refs,
        ):
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise InstalledModelLeaseCustodyError("model lease terminal reference changed")
        for value in (
            self.accepted_requests,
            self.successful_requests,
            self.input_tokens,
            self.output_tokens,
            self.cost_microunits,
        ):
            if type(value) is not int or value < 0:
                raise InstalledModelLeaseCustodyError("model lease terminal usage changed")
        if (
            self.successful_requests > self.accepted_requests
            or self.bearer_scan_binding_ref
            != content_hash(
                {
                    "schema_version": "bluefire.installed-strix-bearer-scan-binding.v1",
                    "attempt_id": self.attempt_id,
                    "lease_binding_ref": self.lease_binding_ref,
                    "custody_identity_ref": self.custody_identity_ref,
                    "authorization_ref": self.authorization_ref,
                }
            )
            or len(self.audit_refs) != self.accepted_requests
            or len(self.audit_rows) != self.accepted_requests
            or len(set(self.audit_refs)) != len(self.audit_refs)
            or self.audit_refs != tuple(row.record_digest for row in self.audit_rows)
            or self.gateway_revocation.receipt_digest != self.gateway_revocation_ref
            or self.gateway_revocation.attempt_id != self.attempt_id
            or self.gateway_revocation.authorization_ref != self.authorization_ref
            or self.gateway_revocation.policy_digest != self.policy_digest
            or self.gateway_revocation.protected_revocation_ref != self.protected_revocation_ref
            or self.gateway_revocation.inflight_request != self.inflight_at_revocation
            or self.gateway_revocation.accepted_requests != self.accepted_requests
            or not self.gateway_revocation.protected_revocation_verified
            or any(
                row.attempt_id != self.attempt_id or row.policy_digest != self.policy_digest
                for row in self.audit_rows
            )
            or any(
                row.relay_kind != "model_gateway" or row.sequence != sequence
                for sequence, row in enumerate(self.audit_rows, start=1)
            )
            or any(
                row.fixture_usage_estimate
                and self.provider_kind != "test"
                or row.live_model_proof
                and self.provider_kind != "live"
                or row.status == "succeeded"
                and self.provider_kind == "test"
                and not row.fixture_usage_estimate
                for row in self.audit_rows
            )
            or self.live_model_proof
            != (
                self.provider_kind == "live"
                and self.admitted_live_model_proof
                and self.successful_requests > 0
                and all(
                    row.live_model_proof for row in self.audit_rows if row.status == "succeeded"
                )
            )
            or self.successful_requests != sum(row.status == "succeeded" for row in self.audit_rows)
            or sum(row.request_bytes for row in self.audit_rows)
            != self.gateway_revocation.consumed_request_bytes
            or self.input_tokens != sum(row.input_tokens for row in self.audit_rows)
            or self.output_tokens != sum(row.output_tokens for row in self.audit_rows)
            or self.cost_microunits != sum(row.cost_microunits for row in self.audit_rows)
            or self.input_tokens + self.output_tokens > self.gateway_revocation.reserved_tokens
            or self.cost_microunits > self.gateway_revocation.reserved_cost_microunits
            or self.evidence_ref != content_hash(self.unsigned_document())
        ):
            raise InstalledModelLeaseCustodyError("model lease terminal audit changed")


class InstalledModelLeaseTerminalSource(Protocol):
    """Protected append and byte-identical reopen of one typed observation."""

    def retain(
        self, receipt: InstalledModelLeaseTerminalReceipt, *, timeout_seconds: float
    ) -> None: ...

    def reopen(
        self, evidence_ref: str, *, timeout_seconds: float
    ) -> InstalledModelLeaseTerminalReceipt | None: ...


class _ObservedGatewayLease:
    """Maintained bearer lease that retains the gateway's typed revocation."""

    def __init__(self, gateway: ControlledModelGateway, timeout_seconds: float) -> None:
        self._gateway = gateway
        self._timeout_seconds = timeout_seconds
        self._revocation_deadline: float | None = None
        self.revocation: GatewayRevocationReceipt | None = None

    @property
    def authorization_ref(self) -> str:
        return self._gateway.authorization_ref

    def secret_value(self) -> str:
        return self._gateway.secret_value()

    def revoke(self) -> str:
        deadline = self._revocation_deadline
        remaining = (
            self._timeout_seconds
            if deadline is None
            else min(self._timeout_seconds, deadline - time.monotonic())
        )
        if remaining <= 0:
            raise InstalledModelLeaseCustodyError("model revocation bound elapsed")
        receipt = self._gateway.revoke_bounded(remaining)
        if not receipt.protected_revocation_verified:
            raise InstalledModelLeaseCustodyError("protected model revocation is unresolved")
        self.revocation = receipt
        return receipt.receipt_digest

    def begin_bounded_revocation(self, deadline: float) -> None:
        self._revocation_deadline = deadline

    def end_bounded_revocation(self) -> None:
        self._revocation_deadline = None


class ControllerOwnedInstalledModelLease:
    """Bind the existing worker lease to active authority and terminal evidence."""

    def __init__(
        self,
        *,
        gateway: ControlledModelGateway,
        audit: BoundedRelayAudit,
        binding: ControlledWorkerBinding,
        invocation: ControlledWorkerInvocation,
        custody_identity: tuple[int, int, int, int, tuple[int, ...]],
        engine_binding_ref: str,
        delegation_ref: str,
        accepted_claim_ref: str,
        admission_ref: str,
        relay_listener_ref: str,
        model_provider: str,
        model_data_destination: str,
        provider_kind: str,
        live_model_proof: bool,
        require_active_transaction: Callable[[], None],
        terminal_source: InstalledModelLeaseTerminalSource,
        timeout_seconds: float = 2.0,
    ) -> None:
        if (
            not isinstance(gateway, ControlledModelGateway)
            or not isinstance(audit, BoundedRelayAudit)
            or not callable(require_active_transaction)
            or not callable(getattr(terminal_source, "retain", None))
            or not callable(getattr(terminal_source, "reopen", None))
            or gateway.policy.attempt_id != binding.attempt_id
            or gateway.policy.model_id != invocation.model
            or type(timeout_seconds) not in {int, float}
            or not 0 < timeout_seconds <= 10
        ):
            raise InstalledModelLeaseCustodyError("model lease owners are incomplete")
        maintained = _ObservedGatewayLease(gateway, timeout_seconds)
        delegate = InstalledStrixV2ModelGatewayLease(
            maintained,
            binding=binding,
            invocation=invocation,
            custody_identity=custody_identity,
            engine_binding_ref=engine_binding_ref,
            delegation_ref=delegation_ref,
            accepted_claim_ref=accepted_claim_ref,
            admission_ref=admission_ref,
            relay_listener_ref=relay_listener_ref,
            model_provider=model_provider,
            model_data_destination=model_data_destination,
            provider_kind=provider_kind,
            live_model_proof=live_model_proof,
            reconcile_revocation=maintained.revoke,
        )
        self._gateway = gateway
        self._audit = audit
        self._maintained = maintained
        self._delegate = delegate
        self._require_active_transaction = require_active_transaction
        self._terminal_source = terminal_source
        self._timeout_seconds = timeout_seconds
        self._accepted_claim_ref = accepted_claim_ref
        self._provider_name = model_provider
        self._terminal_ref: str | None = None

    @property
    def lease_binding_ref(self) -> str:
        return self._delegate.lease_binding_ref

    @property
    def custody_identity_ref(self) -> str:
        return self._delegate.custody_identity_ref

    @property
    def provider_kind(self) -> str:
        return self._delegate.provider_kind

    @property
    def live_model_proof(self) -> bool:
        return self._delegate.live_model_proof

    @property
    def bearer_scan_binding_ref(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.installed-strix-bearer-scan-binding.v1",
                "attempt_id": self._gateway.policy.attempt_id,
                "lease_binding_ref": self.lease_binding_ref,
                "custody_identity_ref": self.custody_identity_ref,
                "authorization_ref": self._gateway.authorization_ref,
            }
        )

    def bearer_absent_from_retained_bytes(self, payload: bytes) -> bool:
        return self._gateway.bearer_absent_from_retained_bytes(payload)

    @property
    def cleanup_uncertain(self) -> bool:
        return self._delegate.cleanup_uncertain or self.reopen_terminal() is None

    def claim(
        self,
        binding: ControlledWorkerBinding,
        custody_identity: tuple[int, int, int, int, tuple[int, ...]],
    ) -> str:
        self._require_active_transaction()
        token = self._delegate.claim(binding, custody_identity)
        try:
            self._require_active_transaction()
        except BaseException:
            # This token has not crossed the RPC boundary yet. Revoke before
            # returning; a failed protected revoke remains cleanup-unknown.
            try:
                self._delegate.revoke()
            except Exception:
                pass
            raise InstalledModelLeaseCustodyError(
                "attempt authority changed before model bearer release"
            ) from None
        return token

    def revoke(self) -> None:
        self.revoke_and_observe()

    def close(self) -> None:
        self._delegate.close(timeout_seconds=self._timeout_seconds)
        self._observe_terminal()

    def revoke_and_observe(self) -> InstalledModelLeaseTerminalReceipt:
        self._delegate.revoke(timeout_seconds=self._timeout_seconds)
        return self._observe_terminal()

    def reopen_terminal(
        self, receipt_ref: str | None = None
    ) -> InstalledModelLeaseTerminalReceipt | None:
        ref = receipt_ref if receipt_ref is not None else self._terminal_ref
        if ref is None:
            return None
        try:
            receipt = self._terminal_source.reopen(ref, timeout_seconds=self._timeout_seconds)
            if receipt is None:
                return None
            receipt.validate()
            if (
                receipt.evidence_ref != ref
                or receipt.lease_binding_ref != self.lease_binding_ref
                or receipt.custody_identity_ref != self.custody_identity_ref
                or receipt.accepted_claim_ref != self._accepted_claim_ref
            ):
                return None
            return receipt
        except Exception:
            return None

    def _observe_terminal(self) -> InstalledModelLeaseTerminalReceipt:
        previous = self.reopen_terminal()
        if previous is not None:
            return previous
        revocation = self._maintained.revocation
        policy = self._gateway.policy
        if (
            not isinstance(revocation, GatewayRevocationReceipt)
            or revocation.attempt_id != policy.attempt_id
            or revocation.authorization_ref != policy.authorization_ref
            or revocation.policy_digest != policy.policy_digest
            or not revocation.protected_revocation_verified
            or revocation.protected_revocation_ref is None
            or not self._gateway.revocation_drained(revocation)
        ):
            raise InstalledModelLeaseCustodyError("model revocation is not observed")
        try:
            self._gateway.secret_value()
        except EngineRelayError as exc:
            if exc.code != "revoked":
                raise InstalledModelLeaseCustodyError(
                    "model bearer absence is not observed"
                ) from None
        else:
            raise InstalledModelLeaseCustodyError("model bearer remains available")
        rows = self._audit.records()
        checked = self._checked_audit(rows, revocation)
        values: dict[str, object] = {
            "attempt_id": policy.attempt_id,
            "accepted_claim_ref": self._accepted_claim_ref,
            "lease_binding_ref": self.lease_binding_ref,
            "bearer_scan_binding_ref": self.bearer_scan_binding_ref,
            "custody_identity_ref": self.custody_identity_ref,
            "authorization_ref": policy.authorization_ref,
            "policy_digest": policy.policy_digest,
            "provider_ref": policy.provider_ref,
            "provider_name": self._provider_name,
            "model_id": policy.model_id,
            "data_destination_ref": policy.data_destination_ref,
            "provider_kind": self.provider_kind,
            "admitted_live_model_proof": self.live_model_proof,
            "live_model_proof": self.provider_kind == "live"
            and self.live_model_proof
            and any(row.status == "succeeded" for row in checked)
            and all(row.live_model_proof for row in checked if row.status == "succeeded"),
            "gateway_revocation": revocation,
            "gateway_revocation_ref": revocation.receipt_digest,
            "protected_revocation_ref": revocation.protected_revocation_ref,
            "inflight_at_revocation": revocation.inflight_request,
            "accepted_requests": revocation.accepted_requests,
            "successful_requests": sum(row.status == "succeeded" for row in checked),
            "input_tokens": sum(row.input_tokens for row in checked),
            "output_tokens": sum(row.output_tokens for row in checked),
            "cost_microunits": sum(row.cost_microunits for row in checked),
            "audit_rows": checked,
            "audit_refs": tuple(row.record_digest for row in checked),
        }
        # The source must retain and reopen the complete document.  A hash
        # supplied by this object alone never establishes durable revocation.
        pending = InstalledModelLeaseTerminalReceipt(
            **values,
            evidence_ref="sha256:" + "0" * 64,  # type: ignore[arg-type]
        )
        receipt = replace(pending, evidence_ref=content_hash(pending.unsigned_document()))
        receipt.validate()
        self._terminal_source.retain(receipt, timeout_seconds=self._timeout_seconds)
        self._terminal_ref = receipt.evidence_ref
        if self.reopen_terminal() != receipt:
            self._terminal_ref = None
            raise InstalledModelLeaseCustodyError("model revocation retention is unavailable")
        return receipt

    def _checked_audit(
        self,
        rows: tuple[RelayAuditRecord, ...],
        revocation: GatewayRevocationReceipt,
    ) -> tuple[RelayAuditRecord, ...]:
        if len(rows) != revocation.accepted_requests:
            raise InstalledModelLeaseCustodyError("model request audit coverage is incomplete")
        for sequence, row in enumerate(rows, start=1):
            if (
                not isinstance(row, RelayAuditRecord)
                or row.relay_kind != "model_gateway"
                or row.attempt_id != revocation.attempt_id
                or row.policy_digest != revocation.policy_digest
                or row.sequence != sequence
                or row.fixture_usage_estimate
                and self.provider_kind != "test"
                or row.live_model_proof
                and self.provider_kind != "live"
            ):
                raise InstalledModelLeaseCustodyError("model request audit changed")
        if (
            sum(row.request_bytes for row in rows) != revocation.consumed_request_bytes
            or sum(row.cost_microunits for row in rows) > revocation.reserved_cost_microunits
        ):
            raise InstalledModelLeaseCustodyError("model request usage changed")
        return rows


__all__ = [
    "ControllerOwnedInstalledModelLease",
    "InstalledModelLeaseCustodyError",
    "InstalledModelLeaseTerminalReceipt",
    "InstalledModelLeaseTerminalSource",
]
