"""Controller-owned protected forwarder for the tenant-record engine relay.

The public relay supplies only a typed operation.  This module rechecks its
immutable delegation and translates it into the adapter-native request that
keeps loopback endpoints and target admission material controller-private.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable

from .engine_relay import (
    EngineRelayError,
    ProtectedRevocationResult,
    ProtectedTargetResult,
    TargetOperation,
    TargetRelayPolicy,
)
from .tenant_record_observer import MAX_RESPONSE_BYTES
from .tenant_record_target_adapter import (
    TenantEngineTargetRequest,
    TenantEngineTargetResult,
    TenantEngineTargetRoute,
    TenantGenerationExpectation,
    TenantRecordLauncherTargetAdapter,
)
from .util import content_hash

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RELAY_REQUEST_ID = re.compile(r"^relay-request-[0-9a-f]{32}$")


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def tenant_protected_target_ref(
    expected_generation: TenantGenerationExpectation,
    target_snapshot_ref: str,
) -> str:
    """Bind one relay capability to an exact launcher generation and snapshot."""

    if not isinstance(expected_generation, TenantGenerationExpectation):
        raise ValueError("tenant target generation is invalid")
    return content_hash(
        {
            "schema_version": "bluefire.tenant-protected-target.v1",
            "generation_digest": expected_generation.digest,
            "target_snapshot_ref": _digest(target_snapshot_ref, "tenant target snapshot"),
        }
    )


class ControllerOwnedTenantTargetForwarder:
    """ProtectedTargetForwarder bound to one immutable tenant lab generation."""

    def __init__(
        self,
        *,
        policy: TargetRelayPolicy,
        expected_generation: TenantGenerationExpectation,
        target_snapshot_ref: str,
        adapter: TenantRecordLauncherTargetAdapter,
        monotonic_ns: Callable[[], int],
        revocation_timeout_seconds: float | None = None,
    ) -> None:
        if not isinstance(policy, TargetRelayPolicy):
            raise ValueError("tenant target relay policy is invalid")
        if not isinstance(expected_generation, TenantGenerationExpectation):
            raise ValueError("tenant target generation is invalid")
        if not isinstance(adapter, TenantRecordLauncherTargetAdapter):
            raise ValueError("tenant target adapter is invalid")
        snapshot_ref = _digest(target_snapshot_ref, "tenant target snapshot")
        if policy.target_snapshot_digest != snapshot_ref:
            raise ValueError("tenant target snapshot differs from relay policy")
        expected_target = tenant_protected_target_ref(expected_generation, snapshot_ref)
        if policy.protected_target_ref != expected_target:
            raise ValueError("tenant protected target differs from relay policy")
        if policy.max_response_bytes > MAX_RESPONSE_BYTES:
            raise ValueError("tenant target relay response cap exceeds the target bound")
        if not callable(monotonic_ns):
            raise ValueError("tenant target monotonic clock is invalid")
        timeout = (
            min(5.0, policy.request_timeout_ms / 1000)
            if revocation_timeout_seconds is None
            else revocation_timeout_seconds
        )
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 10
        ):
            raise ValueError("tenant target revocation timeout is invalid")
        self.policy = policy
        self._expected_generation = expected_generation
        self._target_snapshot_ref = snapshot_ref
        self._adapter = adapter
        self._monotonic_ns = monotonic_ns
        self._revocation_timeout_seconds = float(timeout)
        self._condition = threading.Condition()
        self._revoked = False
        self._inflight = 0
        self._seen: set[str] = set()
        self._accepted = 0
        self._reserved_response_bytes = 0
        self._last_revocation: ProtectedRevocationResult | None = None

    def forward(self, operation: TargetOperation) -> ProtectedTargetResult:
        """Revalidate and forward one operation without exposing target authority."""

        now_ns = self._monotonic_ns()
        self._check_operation(operation, now_ns=now_ns)
        operation_digest = content_hash(operation.to_dict())
        with self._condition:
            if self._revoked:
                raise EngineRelayError("revoked", "protected target relay is revoked")
            if operation.request_id in self._seen:
                raise EngineRelayError(
                    "duplicate_request", "protected target request was already admitted"
                )
            if self._accepted >= self.policy.max_requests:
                raise EngineRelayError("budget_exhausted", "protected target request cap reached")
            if (
                self._reserved_response_bytes + operation.max_response_bytes
                > self.policy.max_total_response_bytes
            ):
                raise EngineRelayError(
                    "budget_exhausted", "protected target response budget is exhausted"
                )
            self._seen.add(operation.request_id)
            self._accepted += 1
            self._reserved_response_bytes += operation.max_response_bytes
            self._inflight += 1
        try:
            result = self._adapter.engine_request(
                TenantEngineTargetRequest(
                    relay_request_id=operation.request_id,
                    operation_digest=operation_digest,
                    expected_generation=self._expected_generation,
                    target_snapshot_ref=self._target_snapshot_ref,
                    route=TenantEngineTargetRoute(operation.route_id),
                    record_id=operation.record_id,
                    tenant_id=operation.tenant_id,
                    tenant_assertion=operation.tenant_assertion,
                    max_response_bytes=operation.max_response_bytes,
                    deadline_ns=operation.deadline_ns,
                )
            )
            if (
                not isinstance(result, TenantEngineTargetResult)
                or result.relay_request_id != operation.request_id
                or result.operation_digest != operation_digest
                or result.generation_digest != self._expected_generation.digest
                or result.protected_secret_absent is not True
            ):
                raise EngineRelayError(
                    "invalid_upstream", "protected target result binding is invalid"
                )
        except Exception:
            with self._condition:
                self._inflight -= 1
                self._condition.notify_all()
            raise
        with self._condition:
            revoked = self._revoked
            self._inflight -= 1
            self._condition.notify_all()
        if revoked:
            raise EngineRelayError("revoked", "protected target relay was revoked in flight")
        return ProtectedTargetResult(
            response=result.response,
            target_observation_ref=result.target_observation_ref,
            protected_secret_absent=True,
        )

    def revoke(self, attempt_id: str, relay_identity_ref: str) -> ProtectedRevocationResult:
        """Block new calls and wait a bounded interval for admitted calls to settle."""

        if (
            attempt_id != self.policy.attempt_id
            or relay_identity_ref != self.policy.relay_identity_ref
        ):
            raise EngineRelayError("scope_refused", "protected target revocation scope changed")
        with self._condition:
            if self._last_revocation is not None and self._last_revocation.verified:
                return self._last_revocation
            self._revoked = True
            settled = self._condition.wait_for(
                lambda: self._inflight == 0,
                timeout=self._revocation_timeout_seconds,
            )
            result = ProtectedRevocationResult(
                verified=settled,
                receipt_ref=content_hash(
                    {
                        "schema_version": "bluefire.tenant-target-revocation.v1",
                        "attempt_id": self.policy.attempt_id,
                        "relay_identity_ref": self.policy.relay_identity_ref,
                        "policy_digest": self.policy.policy_digest,
                        "accepted_requests": self._accepted,
                        "settled": settled,
                        "inflight_requests": self._inflight,
                    }
                ),
            )
            self._last_revocation = result
            return result

    def _check_operation(self, operation: TargetOperation, *, now_ns: int) -> None:
        if not isinstance(operation, TargetOperation):
            raise EngineRelayError("invalid_request", "protected target operation is invalid")
        if (
            isinstance(now_ns, bool)
            or not isinstance(now_ns, int)
            or _RELAY_REQUEST_ID.fullmatch(operation.request_id) is None
            or operation.attempt_id != self.policy.attempt_id
            or operation.binding_digest != self.policy.binding_digest
            or operation.delegation_digest != self.policy.delegation_digest
            or operation.network_policy_digest != self.policy.network_policy_digest
            or operation.relay_identity_ref != self.policy.relay_identity_ref
            or operation.protected_target_ref != self.policy.protected_target_ref
            or operation.source_identity != "engine_worker"
        ):
            raise EngineRelayError("scope_refused", "protected target operation scope changed")
        if operation.route_id not in self.policy.admitted_routes:
            raise EngineRelayError("route_refused", "protected target route is not admitted")
        if (
            isinstance(operation.max_response_bytes, bool)
            or operation.max_response_bytes != self.policy.max_response_bytes
            or operation.max_response_bytes > MAX_RESPONSE_BYTES
        ):
            raise EngineRelayError("budget_refused", "protected target response cap changed")
        if (
            isinstance(operation.deadline_ns, bool)
            or not isinstance(operation.deadline_ns, int)
            or operation.deadline_ns <= now_ns
            or operation.deadline_ns > now_ns + self.policy.request_timeout_ms * 1_000_000
        ):
            raise EngineRelayError("deadline_exceeded", "protected target deadline is invalid")
        if operation.route_id in {"health", "metadata"}:
            valid = (
                operation.record_id is None
                and operation.tenant_id is None
                and operation.tenant_assertion is None
            )
        elif operation.route_id == "record_lookup":
            valid = (
                operation.record_id in self.policy.admitted_record_ids
                and operation.tenant_id is None
                and operation.tenant_assertion in {None, *self.policy.admitted_tenant_ids}
            )
        elif operation.route_id == "bounded_export":
            valid = (
                operation.record_id is None
                and operation.tenant_id in self.policy.admitted_tenant_ids
                and operation.tenant_assertion in {None, operation.tenant_id}
            )
        else:
            valid = False
        if not valid:
            raise EngineRelayError("scope_refused", "protected target route binding changed")
