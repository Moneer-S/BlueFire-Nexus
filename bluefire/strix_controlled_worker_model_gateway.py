"""Controller-only join from a maintained model lease to one worker attempt.

The worker receives only an ephemeral attempt relay bearer after the RPC server
has verified live process containment.  This adapter never exposes the legacy
``secret_value`` method and binds the lease to the exact invocation, binding,
and stable process-custody identity before releasing the bearer once.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Protocol

from . import strix_adapter as adapter
from . import strix_controlled_worker_channel as channel
from . import strix_controlled_worker_invocation as invocation_module
from .util import content_hash

LEASE_VERSION = "bluefire.strix-installed-model-gateway-lease.v1"


class InstalledStrixV2ModelGatewayLeaseError(RuntimeError):
    """The controller could not prove or settle the exact model lease."""


def _refuse() -> InstalledStrixV2ModelGatewayLeaseError:
    return InstalledStrixV2ModelGatewayLeaseError("installed Strix model lease refused")


class _MaintainedLease(Protocol):
    @property
    def authorization_ref(self) -> str: ...

    def secret_value(self) -> str: ...

    def revoke(self) -> str: ...


def _digest(value: object) -> str:
    if type(value) is not str or adapter._SHA256.fullmatch(value) is None:
        raise _refuse()
    return value


def _custody_identity(
    value: object,
) -> tuple[int, int, int, int, tuple[int, ...]]:
    if (
        type(value) is not tuple
        or len(value) != 5
        or any(type(item) is not int for item in value[:4])
        or not all(item >= 0 for item in value[:4])
        or value[0] <= 0
        or value[3] <= 0
        or type(value[4]) is not tuple
        or not value[4]
        or any(type(item) is not int or item <= 0 for item in value[4])
        or value[4][0] != value[0]
    ):
        raise _refuse()
    return value


class InstalledStrixV2ModelGatewayLease:
    """One-use model authority bound to an installed worker and durable refs."""

    __slots__ = (
        "_authorization_ref",
        "_binding",
        "_cleanup_uncertain",
        "_closed",
        "_condition",
        "_custody_identity",
        "_custody_identity_ref",
        "_lease",
        "_lease_binding_ref",
        "_live_model_proof",
        "_provider_kind",
        "_reconcile_required",
        "_reconcile_revocation",
        "_revocation_ref",
        "_state",
    )

    def __init__(
        self,
        lease: _MaintainedLease,
        *,
        binding: channel.ControlledWorkerBinding,
        invocation: invocation_module.ControlledWorkerInvocation,
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
        reconcile_revocation: Callable[[], str | None],
    ) -> None:
        identity = _custody_identity(custody_identity)
        if (
            type(binding) is not channel.ControlledWorkerBinding
            or type(invocation) is not invocation_module.ControlledWorkerInvocation
            or invocation.profile_attempt_id != binding.attempt_id
            or invocation.intent_digest != binding.plan_digest
            or not callable(getattr(lease, "secret_value", None))
            or not callable(getattr(lease, "revoke", None))
            or not callable(reconcile_revocation)
            or type(model_provider) is not str
            or not 1 <= len(model_provider) <= 80
            or not model_provider.isascii()
            or any(ord(character) < 33 or ord(character) == 127 for character in model_provider)
            or type(model_data_destination) is not str
            or model_data_destination != dict(invocation.environment)["LLM_API_BASE"]
            or type(provider_kind) is not str
            or provider_kind not in {"test", "live"}
            or type(live_model_proof) is not bool
            or provider_kind == "test"
            and live_model_proof
        ):
            raise _refuse()
        authorization_ref: str = content_hash(
            {
                "schema_version": "bluefire.model-gateway-authorization-ref.v1",
                "attempt_id": invocation.profile_attempt_id,
                "authorization_digest": invocation.model_authorization_digest,
            }
        )
        if getattr(lease, "authorization_ref", None) != authorization_ref:
            raise _refuse()
        refs = {
            "engine_binding_ref": _digest(engine_binding_ref),
            "delegation_ref": _digest(delegation_ref),
            "accepted_claim_ref": _digest(accepted_claim_ref),
            "admission_ref": _digest(admission_ref),
            "relay_listener_ref": _digest(relay_listener_ref),
        }
        custody_identity_ref: str = content_hash(
            {
                "schema_version": "bluefire.strix-worker-custody-identity.v1",
                "host_pid": identity[0],
                "uid": identity[1],
                "gid": identity[2],
                "start_ticks": identity[3],
                "namespace_pids": list(identity[4]),
            }
        )
        lease_binding_ref: str = content_hash(
            {
                "schema_version": LEASE_VERSION,
                "binding": binding.wire(),
                "invocation_intent_ref": invocation.intent_digest,
                "model": invocation.model,
                "model_provider": model_provider,
                "provider_kind": provider_kind,
                "live_model_proof": live_model_proof,
                "model_data_destination": model_data_destination,
                "model_authorization_digest": invocation.model_authorization_digest,
                "authorization_ref": authorization_ref,
                "custody_identity_ref": custody_identity_ref,
                **refs,
            }
        )
        self._binding = binding
        self._custody_identity = identity
        self._lease = lease
        self._reconcile_revocation = reconcile_revocation
        self._reconcile_required = False
        self._closed = False
        self._condition = threading.Condition()
        self._state = "available"
        self._revocation_ref: str | None = None
        self._provider_kind = provider_kind
        self._live_model_proof = live_model_proof
        self._authorization_ref = authorization_ref
        self._custody_identity_ref = custody_identity_ref
        self._lease_binding_ref = lease_binding_ref
        self._cleanup_uncertain = False

    def __repr__(self) -> str:
        return "InstalledStrixV2ModelGatewayLease(<private>)"

    @property
    def provider_kind(self) -> str:
        return self._provider_kind

    @property
    def live_model_proof(self) -> bool:
        return self._live_model_proof

    @property
    def authorization_ref(self) -> str:
        return self._authorization_ref

    @property
    def custody_identity_ref(self) -> str:
        return self._custody_identity_ref

    @property
    def lease_binding_ref(self) -> str:
        return self._lease_binding_ref

    @property
    def cleanup_uncertain(self) -> bool:
        with self._condition:
            return self._cleanup_uncertain

    @property
    def revocation_ref(self) -> str | None:
        with self._condition:
            return self._revocation_ref

    def claim(
        self,
        binding: channel.ControlledWorkerBinding,
        custody_identity: tuple[int, int, int, int, tuple[int, ...]],
    ) -> str:
        identity = _custody_identity(custody_identity)
        with self._condition:
            if (
                self._closed
                or self._state != "available"
                or binding != self._binding
                or identity != self._custody_identity
                or getattr(self._lease, "authorization_ref", None) != self.authorization_ref
            ):
                raise _refuse()
            self._state = "claiming"
        try:
            token = self._lease.secret_value()
        except Exception:
            with self._condition:
                if self._state == "claiming":
                    self._state = "uncertain"
                    self._cleanup_uncertain = True
                    self._condition.notify_all()
            raise _refuse() from None
        if (
            type(token) is not str
            or not 32 <= len(token) <= 512
            or any(ord(character) < 33 or ord(character) == 127 for character in token)
        ):
            with self._condition:
                if self._state == "claiming":
                    self._state = "uncertain"
                    self._cleanup_uncertain = True
                    self._condition.notify_all()
            raise _refuse()
        with self._condition:
            if (
                self._closed
                or self._state != "claiming"
                or getattr(self._lease, "authorization_ref", None) != self.authorization_ref
            ):
                raise _refuse()
            self._state = "claimed"
            return token

    def revoke(self, *, timeout_seconds: float = 2.0) -> None:
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 30:
            raise _refuse()
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while self._state == "revoking":
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._cleanup_uncertain = True
                    raise _refuse()
                self._condition.wait(remaining)
            if self._state == "revoked":
                return
            self._state = "revoking"
        begin_bound = getattr(self._lease, "begin_bounded_revocation", None)
        end_bound = getattr(self._lease, "end_bounded_revocation", None)
        if callable(begin_bound):
            try:
                begin_bound(deadline)
            except Exception:
                with self._condition:
                    self._state = "uncertain"
                    self._cleanup_uncertain = True
                    self._condition.notify_all()
                raise _refuse() from None
        receipt: object = None
        try:
            if not self._reconcile_required:
                try:
                    receipt = self._lease.revoke()
                except Exception:
                    self._reconcile_required = True
            if self._reconcile_required:
                try:
                    receipt = self._reconcile_revocation()
                except Exception:
                    receipt = None
            elif type(receipt) is not str or adapter._SHA256.fullmatch(receipt) is None:
                self._reconcile_required = True
                try:
                    receipt = self._reconcile_revocation()
                except Exception:
                    receipt = None
        finally:
            if callable(end_bound):
                end_bound()
        if type(receipt) is not str or adapter._SHA256.fullmatch(receipt) is None:
            with self._condition:
                self._state = "uncertain"
                self._cleanup_uncertain = True
                self._condition.notify_all()
            raise _refuse()
        with self._condition:
            self._revocation_ref = receipt
            self._state = "revoked"
            self._cleanup_uncertain = False
            self._condition.notify_all()

    def close(self, *, timeout_seconds: float = 2.0) -> None:
        with self._condition:
            self._closed = True
        self.revoke(timeout_seconds=timeout_seconds)


__all__ = [
    "InstalledStrixV2ModelGatewayLease",
    "InstalledStrixV2ModelGatewayLeaseError",
    "LEASE_VERSION",
]
