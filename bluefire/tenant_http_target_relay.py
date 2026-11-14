"""Single-flight V2 HTTP controller relay; construction never launches a lab."""

from __future__ import annotations

import secrets
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from typing import Any, Protocol

from .engine_relay import EngineRelayError, RelayAuditRecord, RelayAuditSink, TargetRelayRequest
from .tenant_http_completion_contract import (
    VerifiedTenantHttpAdapterRevocation,
    VerifiedTenantHttpCessationReceipt,
)
from .tenant_http_target_adapter import (
    TenantHttpEngineTargetRequestV2,
    TenantRecordHttpTargetAdapterV2,
)
from .tenant_http_target_profile import (
    TenantHttpTargetOperationV2,
    TenantHttpTargetProfileV2,
    admit_tenant_http_operation,
)
from .tenant_record_target_adapter import TenantEngineTargetResult
from .util import content_hash, parse_iso8601_datetime


@dataclass(frozen=True, slots=True)
class TenantHttpControllerRefusalV2:
    sequence: int
    profile_digest: str
    code: str
    request_ref: str | None
    target_result: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "bluefire.tenant-http-controller-refusal.v2", **asdict(self)}


@dataclass(frozen=True, slots=True)
class TenantHttpRelayResultV2:
    operation: TenantHttpTargetOperationV2
    request: TenantHttpEngineTargetRequestV2
    result: TenantEngineTargetResult
    relay_audit: RelayAuditRecord


class TenantHttpCompletionOwner(Protocol):
    def settle_relay(
        self, relay: "ControlledTenantHttpRelayV2"
    ) -> VerifiedTenantHttpCessationReceipt: ...


class ControlledTenantHttpRelayV2:
    """Controller-only relay for one exact generation, with separate refusals.

    A returned 401/403/404 is a succeeded HTTP observation. Failure after
    dispatch has an unknown target outcome and consumes its call/byte reserve.
    Results/audits must be retained before terminal completion is committed.
    """

    def __init__(
        self,
        profile: TenantHttpTargetProfileV2,
        adapter: TenantRecordHttpTargetAdapterV2,
        audit: RelayAuditSink,
        *,
        clock: Callable[[], datetime],
        monotonic_ns: Callable[[], int],
    ) -> None:
        if type(profile) is not TenantHttpTargetProfileV2 or not isinstance(
            adapter, TenantRecordHttpTargetAdapterV2
        ):
            raise ValueError("v2 HTTP relay binding is invalid")
        self.profile = replace(profile)
        self._adapter = adapter
        self._audit = audit
        self._clock = clock
        self._monotonic_ns = monotonic_ns
        self._lock = threading.RLock()
        self._settlement_condition = threading.Condition(self._lock)
        self._instance_id = secrets.token_hex(16)
        self._revocation_state = "active"
        self._adapter_revocation_started = False
        self._settlement_receipt: VerifiedTenantHttpCessationReceipt | None = None
        self._frozen_trace: dict[str, Any] | None = None
        self._started_ns = monotonic_ns()
        remaining_ns = int(
            (parse_iso8601_datetime(profile.expires_at) - clock()).total_seconds() * 1_000_000_000
        )
        self._deadline_ns = self._started_ns + min(profile.run_timeout_ms * 1_000_000, remaining_ns)
        self._accepted = 0
        self._reserved_bytes = 0
        self._seen: set[str] = set()
        self._refusals: list[TenantHttpControllerRefusalV2] = []
        self._events: list[dict[str, Any]] = []
        self._pending = False
        self._revoked = False
        self._exhausted = False
        self._trace_lost = False
        self._unknown = 0
        self._succeeded = 0
        self._response_bytes = 0
        self._check_lifetime()
        adapter.bind_http_profile(profile)

    def _check_lifetime(self) -> None:
        now = self._clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or not parse_iso8601_datetime(self.profile.created_at)
            <= now
            < parse_iso8601_datetime(self.profile.expires_at)
        ):
            raise EngineRelayError("expired", "v2 target profile is outside its lifetime")
        if self._monotonic_ns() >= self._deadline_ns:
            self._exhausted = True
            raise EngineRelayError("deadline_exceeded", "v2 HTTP run deadline elapsed")

    def _event(self, kind: str, **fields: Any) -> None:
        # At most 2 dispatch/result events per HTTP call and 256 refusals.
        if len(self._events) >= 2 * self.profile.max_http_calls + 256:
            self._trace_lost = True
            raise EngineRelayError("audit_unavailable", "v2 controller trace capacity is exhausted")
        self._events.append(
            {
                "sequence": len(self._events) + 1,
                "kind": kind,
                "recorded_ns": self._monotonic_ns(),
                **fields,
            }
        )

    def handle(self, request: TargetRelayRequest) -> TenantHttpRelayResultV2:
        operation: TenantHttpTargetOperationV2 | None = None
        with self._lock:
            if self._revocation_state != "active":
                # The closed trace is immutable. These calls are outside its
                # admission interval and cannot dispatch or extend its log.
                raise EngineRelayError(
                    "revoked" if self._revoked else "revocation_pending",
                    "v2 HTTP relay is revoked"
                    if self._revoked
                    else "v2 HTTP revocation is unresolved",
                )
            try:
                self._check_lifetime()
                if self._revoked:
                    raise EngineRelayError("revoked", "v2 target relay is revoked")
                if self._pending:
                    raise EngineRelayError("busy", "v2 target relay has an in-flight request")
                started = self._monotonic_ns()
                deadline = min(
                    self._deadline_ns, started + self.profile.request_timeout_ms * 1_000_000
                )
                operation = admit_tenant_http_operation(self.profile, request, deadline_ns=deadline)
                if operation.request_id in self._seen:
                    raise EngineRelayError("replay_refused", "v2 HTTP request was consumed")
                if (
                    self._accepted >= self.profile.max_http_calls
                    or self._reserved_bytes + operation.max_response_bytes
                    > self.profile.max_total_response_bytes
                ):
                    self._exhausted = True
                    raise EngineRelayError(
                        "budget_exhausted", "v2 HTTP count or response-byte budget is exhausted"
                    )
                self._event(
                    "dispatch", request_id=operation.request_id, operation_ref=operation.digest
                )
                self._seen.add(operation.request_id)
                self._accepted += 1
                self._reserved_bytes += operation.max_response_bytes
                self._pending = True
                sequence = self._accepted
            except EngineRelayError as exc:
                if len(self._refusals) >= 256:
                    self._trace_lost = True
                    raise EngineRelayError(
                        "audit_unavailable", "v2 refusal trace capacity is exhausted"
                    ) from None
                refusal = TenantHttpControllerRefusalV2(
                    len(self._refusals) + 1,
                    self.profile.policy_digest,
                    exc.code,
                    None if operation is None else operation.digest,
                )
                self._refusals.append(refusal)
                self._event("controller_refusal", refusal_ref=content_hash(refusal.to_dict()))
                raise
        typed_request = TenantHttpEngineTargetRequestV2(self.profile, operation)
        try:
            result = self._adapter.engine_http_request(typed_request)
            with self._lock:
                self._check_lifetime()
                if self._revoked or self._monotonic_ns() >= deadline:
                    raise EngineRelayError(
                        "deadline_exceeded", "v2 HTTP response was not published in time"
                    )
            record = RelayAuditRecord(
                relay_kind="target",
                attempt_id=self.profile.attempt_id,
                objective_ref=self.profile.objective_ref,
                sequence=sequence,
                request_id=operation.request_id,
                operation=operation.route_id,
                request_digest=operation.digest,
                request_bytes=0,
                response_digest=result.audit_row.response_sha256,
                response_bytes=len(result.response.body),
                status="succeeded",
                result_status=result.response.status,
                input_tokens=0,
                output_tokens=0,
                cost_microunits=0,
                elapsed_ms=max(0, (self._monotonic_ns() - started) // 1_000_000),
                recorded_at=self._clock().isoformat().replace("+00:00", "Z"),
                policy_digest=self.profile.policy_digest,
                evidence_ref=result.target_observation_ref,
            )
            self._audit.append(record)
            with self._lock:
                self._check_lifetime()
                if self._revoked or self._monotonic_ns() >= deadline:
                    raise EngineRelayError(
                        "deadline_exceeded", "v2 HTTP publication deadline elapsed"
                    )
                self._event(
                    "target_result",
                    request_id=operation.request_id,
                    operation_ref=operation.digest,
                    target_request_id=result.target_request_id,
                    target_observation_ref=result.target_observation_ref,
                    relay_audit_ref=record.record_digest,
                )
                self._succeeded += 1
                self._response_bytes += len(result.response.body)
            return TenantHttpRelayResultV2(operation, typed_request, result, record)
        except Exception:
            with self._lock:
                self._unknown += 1
                self._event(
                    "target_unknown",
                    request_id=operation.request_id,
                    operation_ref=operation.digest,
                )
            raise EngineRelayError(
                "target_unknown", "v2 dispatched target outcome is unknown"
            ) from None
        finally:
            with self._settlement_condition:
                self._pending = False
                self._settlement_condition.notify_all()

    def revoke(self, owner: TenantHttpCompletionOwner) -> VerifiedTenantHttpCessationReceipt:
        """Close admission and retain proof through the controller completion owner."""
        with self._lock:
            if self._revocation_state == "active":
                self._revocation_state = "closing"
        try:
            receipt = owner.settle_relay(self)
            if type(receipt) is not VerifiedTenantHttpCessationReceipt:
                raise ValueError("v2 revocation has no controller receipt")
            receipt.to_dict()
            with self._lock:
                if (
                    not self._revoked
                    or self._revocation_state != "settled"
                    or self._settlement_receipt != receipt
                    or self._frozen_trace is None
                    or self._frozen_trace["trace_ref"] != receipt.controller_trace_ref
                    or receipt.profile_digest != self.profile.policy_digest
                    or receipt.generation_digest != self.profile.expected_generation.digest
                ):
                    raise ValueError("revocation did not retain this relay's exact receipt")
            return receipt
        except Exception:
            self._mark_revocation_unresolved()
            raise EngineRelayError(
                "revocation_unknown", "v2 controller completion is unresolved"
            ) from None

    def _begin_adapter_revocation(self) -> VerifiedTenantHttpAdapterRevocation:
        with self._lock:
            if (
                self._revocation_state not in {"active", "closing"}
                or self._adapter_revocation_started
            ):
                raise EngineRelayError(
                    "revocation_unknown", "v2 revocation requires exact reconciliation"
                )
            self._revocation_state = "closing"
            self._adapter_revocation_started = True
        try:
            receipt = self._adapter.revoke_http_profile()
            if type(receipt) is not VerifiedTenantHttpAdapterRevocation:
                raise ValueError("adapter revocation is unresolved")
            receipt.to_dict()
            with self._settlement_condition:
                if not self._settlement_condition.wait_for(lambda: not self._pending, timeout=5.0):
                    raise ValueError("relay still has an unsettled publication")
            return receipt
        except Exception:
            self._mark_revocation_unresolved()
            raise EngineRelayError(
                "revocation_unknown", "v2 adapter revocation is unresolved"
            ) from None

    def _mark_revocation_unresolved(self) -> None:
        with self._lock:
            if not self._revoked:
                self._revocation_state = "unresolved"

    def _revocation_candidate(self) -> dict[str, Any]:
        with self._lock:
            if self._pending or self._revocation_state not in {"closing", "unresolved", "settled"}:
                raise EngineRelayError("revocation_unknown", "v2 revocation trace is not settled")
            return self._trace_document(revoked=True, revocation_state="settled")

    def _publish_revocation(
        self, receipt: VerifiedTenantHttpCessationReceipt, candidate: dict[str, Any]
    ) -> None:
        if type(receipt) is not VerifiedTenantHttpCessationReceipt:
            raise ValueError("revocation receipt is not controller owned")
        receipt.to_dict()
        with self._lock:
            if (
                candidate != self._revocation_candidate()
                or receipt.controller_trace_ref != candidate["trace_ref"]
                or receipt.profile_digest != self.profile.policy_digest
            ):
                raise ValueError("revocation receipt no longer binds the relay trace")
            self._frozen_trace = candidate
            self._settlement_receipt = receipt
            self._revoked = True
            self._revocation_state = "settled"

    def controller_trace(self) -> dict[str, Any]:
        """Snapshot for protected retention; engine prose cannot close this trace.

        The run-terminal verifier additionally requires independent observation
        retention for every result, exact dispatch correlation and cessation.
        """
        with self._lock:
            if self._frozen_trace is not None:
                # Clone nested events as callers may retain/serialize this copy.
                return {
                    **self._frozen_trace,
                    "events": [dict(row) for row in self._frozen_trace["events"]],
                    "controller_refusals": [
                        dict(row) for row in self._frozen_trace["controller_refusals"]
                    ],
                }
            return self._trace_document(
                revoked=self._revoked, revocation_state=self._revocation_state
            )

    def _trace_document(self, *, revoked: bool, revocation_state: str) -> dict[str, Any]:
        document = {
            "schema_version": "bluefire.tenant-http-controller-trace.v2",
            "relay_instance_id": self._instance_id,
            "revocation_state": revocation_state,
            "profile_digest": self.profile.policy_digest,
            "started_ns": self._started_ns,
            "deadline_ns": self._deadline_ns,
            "events": [dict(event) for event in self._events],
            "controller_refusals": [item.to_dict() for item in self._refusals],
            "accepted_http_calls": self._accepted,
            "target_results": self._succeeded,
            "target_unknown": self._unknown,
            "response_bytes": self._response_bytes,
            "reserved_response_bytes": self._reserved_bytes,
            "pending": self._pending,
            "budget_exhausted": self._exhausted,
            "trace_truncated": self._trace_lost,
            "revoked": revoked,
        }
        return {**document, "trace_ref": content_hash(document)}
