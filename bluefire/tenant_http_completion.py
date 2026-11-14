"""Controller-owned, durable completion proof for one bounded HTTP relay.

The controller owns this protected root and the independently protected engine
artifact store. Issuance invokes actual adapter revocation and reopens the
existing stopped/write-revoked worker publication; caller claims cannot issue a
receipt. Receipt files are exclusive and immutable. Reconciliation only reopens
an already committed exact receipt, never retries an ambiguous effect.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .engine_artifact_store import EngineArtifactStore
from .engine_attempt_contract import EngineAttemptBinding
from .engine_relay import EngineRelayError
from .runner_private_files import _PinnedPrivateDirectory
from .tenant_engine_run_trace import TenantEngineRunTraceBinding
from .tenant_http_completion_contract import (
    _CONTROLLER_ADAPTER_AUTHORITY,
    _CONTROLLER_CESSATION_AUTHORITY,
    VerifiedTenantHttpAdapterRevocation,
    VerifiedTenantHttpCessationReceipt,
    _restore_adapter_revocation,
    _restore_controller_cessation_receipt,
)
from .tenant_http_target_profile import TenantHttpTargetProfileV2
from .tenant_http_target_relay import ControlledTenantHttpRelayV2
from .util import canonical_json_bytes, content_hash, json_clone

_MAX_RECEIPT_BYTES = 8192


class TenantHttpCompletionError(ValueError):
    """Owned-work cessation/revocation has no exact reopened controller proof."""


class ControllerOwnedTenantHttpCompletion:
    def __init__(
        self,
        *,
        root: Path,
        artifacts: EngineArtifactStore,
        binding: EngineAttemptBinding,
        profile: TenantHttpTargetProfileV2,
        monotonic_ns: Callable[[], int],
    ) -> None:
        if (
            type(artifacts) is not EngineArtifactStore
            or type(binding) is not EngineAttemptBinding
            or type(profile) is not TenantHttpTargetProfileV2
        ):
            raise TenantHttpCompletionError("completion requires controller-owned sources")
        binding.to_dict()
        if (
            profile.attempt_id != binding.attempt_id
            or profile.binding_digest != binding.binding_digest
            or profile.target_snapshot_ref != binding.target_snapshot_ref
        ):
            raise TenantHttpCompletionError("completion owner differs from the engine attempt")
        self._root = root.resolve(strict=True)
        with _PinnedPrivateDirectory(self._root, verify_permissions_only=True) as pinned:
            self._root_identity = pinned.directory_identity()
            self._root_mount_identity = pinned.directory_mount_identity()
        self._artifacts = artifacts
        self._binding = binding
        self._profile = profile
        self._clock = monotonic_ns
        self._lock = threading.RLock()
        # A profile/run can have one closure only. An exact replay may reopen it;
        # another relay instance or trace cannot replace it.
        self._name = (
            content_hash(
                {
                    "run_id": binding.run_id,
                    "attempt_id": binding.attempt_id,
                    "profile_digest": profile.policy_digest,
                    "generation_digest": profile.expected_generation.digest,
                }
            ).removeprefix("sha256:")
            + ".json"
        )

    def _pin(self, *, write: bool = False) -> _PinnedPrivateDirectory:
        return _PinnedPrivateDirectory(
            self._root,
            expected_identity=self._root_identity,
            expected_mount_identity=self._root_mount_identity,
            verify_permissions_only=not write,
        )

    def _owned_worker_proof(self) -> dict[str, str]:
        reopened = self._artifacts.reopen_attempt(self._binding.attempt_id)
        publication = reopened.publication_binding
        seal = reopened.source_collection_seal
        if not reopened.recovery_eligible or publication is None or seal is None:
            raise TenantHttpCompletionError("worker publication has no durable controller seal")
        # to_dict verifies the private controller attestation, not just its text.
        seal_document = seal.to_dict()
        publication.to_dict()
        if (
            reopened.attempt_id != self._binding.attempt_id
            or publication.attempt_id != self._binding.attempt_id
            or publication.binding_digest != self._binding.binding_digest
            or publication.delegation_digest != self._profile.delegation_digest
            or seal.attempt_id != self._binding.attempt_id
            or seal_document["worker_state"] != "stopped"
            or seal_document["write_access_revoked"] is not True
            or reopened.artifact_publication_ref is None
            or reopened.source_collection_seal_ref != content_hash(seal_document)
        ):
            raise TenantHttpCompletionError("owned worker cessation binding changed")
        return {
            "artifact_manifest_ref": reopened.manifest_ref,
            "artifact_publication_ref": reopened.artifact_publication_ref,
            "worker_outcome_digest": publication.worker_outcome_digest,
            "source_collection_seal_ref": content_hash(seal_document),
        }

    def _trace_binding(self, document: Mapping[str, Any]) -> TenantEngineRunTraceBinding:
        return TenantEngineRunTraceBinding(
            run_id=self._binding.run_id,
            attempt_id=self._binding.attempt_id,
            profile_digest=self._profile.policy_digest,
            generation_digest=self._profile.expected_generation.digest,
            target_snapshot_ref=self._profile.target_snapshot_ref,
            scope_ref=self._profile.scope_ref,
            started_ns=document["started_ns"],
            deadline_ns=document["deadline_ns"],
            max_http_calls=self._profile.max_http_calls,
            max_total_response_bytes=self._profile.max_total_response_bytes,
            max_trace_events=2 * self._profile.max_http_calls + 256,
            controller_trace_ref=document["trace_ref"],
        )

    def _validate_candidate(
        self, document: Mapping[str, Any], adapter: VerifiedTenantHttpAdapterRevocation
    ) -> None:
        adapter.to_dict()
        payload = {name: value for name, value in document.items() if name != "trace_ref"}
        request_ids = [row["request_id"] for row in document["events"] if row["kind"] == "dispatch"]
        if (
            document["trace_ref"] != content_hash(payload)
            or document["profile_digest"] != self._profile.policy_digest
            or document["revoked"] is not True
            or document["revocation_state"] != "settled"
            or document["pending"] is not False
            or adapter.profile_digest != self._profile.policy_digest
            or adapter.generation_digest != self._profile.expected_generation.digest
            or adapter.accepted_http_calls != document["accepted_http_calls"]
            or adapter.reserved_response_bytes != document["reserved_response_bytes"]
            or adapter.request_ids_digest != content_hash(sorted(request_ids))
        ):
            raise TenantHttpCompletionError("adapter revocation differs from the final relay trace")

    def settle_relay(
        self, relay: ControlledTenantHttpRelayV2
    ) -> VerifiedTenantHttpCessationReceipt:
        if type(relay) is not ControlledTenantHttpRelayV2 or relay.profile != self._profile:
            raise TenantHttpCompletionError("completion relay binding changed")
        with self._lock:
            # A committed live retry reopens the same receipt before returning.
            current = relay.controller_trace()
            if current["revoked"]:
                return self.reopen_for_trace(
                    profile=self._profile, run_id=self._binding.run_id, controller_trace=current
                )
            try:
                with self._pin() as pinned:
                    if pinned.has_name(self._name):
                        raise TenantHttpCompletionError(
                            "an existing closure requires exact reconciliation"
                        )
                adapter = relay._begin_adapter_revocation()
                candidate = relay._revocation_candidate()
                self._validate_candidate(candidate, adapter)
                trace_binding = self._trace_binding(candidate)
                issued_ns = self._clock()
                last_event_ns = max(
                    (row["recorded_ns"] for row in candidate["events"]),
                    default=candidate["started_ns"],
                )
                if type(issued_ns) is not int or issued_ns < last_event_ns:
                    raise TenantHttpCompletionError(
                        "completion clock precedes the final target event"
                    )
                document = {
                    "schema_version": "bluefire.tenant-http-cessation.v2",
                    "run_id": self._binding.run_id,
                    "attempt_id": self._binding.attempt_id,
                    "binding_digest": trace_binding.digest,
                    "profile_digest": self._profile.policy_digest,
                    "generation_digest": self._profile.expected_generation.digest,
                    "target_snapshot_ref": self._profile.target_snapshot_ref,
                    "controller_trace_ref": candidate["trace_ref"],
                    "adapter_revocation_ref": adapter.digest,
                    **self._owned_worker_proof(),
                    "issued_ns": issued_ns,
                }
                payload = canonical_json_bytes(
                    {"receipt": document, "adapter_revocation": adapter.to_dict()}
                )
                with self._pin(write=True) as pinned:
                    # CREATE_NEW/exclusive creation never overwrites a prior
                    # closure. A partial or failed write remains unresolved;
                    # it is never removed and retried into optimistic success.
                    handle = pinned.open_new(self._name, maximum=_MAX_RECEIPT_BYTES)
                    try:
                        written = 0
                        while written < len(payload):
                            count = handle.write(payload[written:])
                            if count <= 0:
                                raise OSError("short completion receipt write")
                            written += count
                        handle.flush()
                        os.fsync(handle.fileno())
                        handle.validate_identity()
                        pinned.sync()
                    finally:
                        handle.close()
                # Reopen from the protected root and worker source before any
                # positive relay state or unforgeable capability is published.
                receipt = self.reopen_for_trace(
                    profile=self._profile, run_id=self._binding.run_id, controller_trace=candidate
                )
                relay._publish_revocation(receipt, candidate)
                return receipt
            except Exception:
                relay._mark_revocation_unresolved()
                raise EngineRelayError(
                    "revocation_unknown", "v2 controller completion is unresolved"
                ) from None

    def reconcile_relay(
        self, relay: ControlledTenantHttpRelayV2
    ) -> VerifiedTenantHttpCessationReceipt:
        """Only reopen an existing exact closure; never retry adapter revocation."""
        if type(relay) is not ControlledTenantHttpRelayV2 or relay.profile != self._profile:
            raise TenantHttpCompletionError("reconciliation relay binding changed")
        with self._lock:
            candidate = relay._revocation_candidate()
            receipt = self.reopen_for_trace(
                profile=self._profile, run_id=self._binding.run_id, controller_trace=candidate
            )
            relay._publish_revocation(receipt, candidate)
            return receipt

    def reopen_for_trace(
        self,
        *,
        profile: TenantHttpTargetProfileV2,
        run_id: str,
        controller_trace: Mapping[str, Any],
    ) -> VerifiedTenantHttpCessationReceipt:
        if profile != self._profile or run_id != self._binding.run_id:
            raise TenantHttpCompletionError("completion receipt owner changed")
        with self._lock:
            try:
                controller_trace = json_clone(dict(controller_trace))
                with self._pin() as pinned:
                    raw = pinned.read(
                        self._name, maximum=_MAX_RECEIPT_BYTES, apply_permissions=False
                    )
                envelope = json.loads(raw)
                if (
                    not isinstance(envelope, dict)
                    or set(envelope) != {"receipt", "adapter_revocation"}
                    or canonical_json_bytes(envelope) != raw
                ):
                    raise ValueError("receipt is not canonical")
                receipt = _restore_controller_cessation_receipt(
                    envelope["receipt"], _authority=_CONTROLLER_CESSATION_AUTHORITY
                )
                adapter = _restore_adapter_revocation(
                    envelope["adapter_revocation"], _authority=_CONTROLLER_ADAPTER_AUTHORITY
                )
                self._validate_candidate(controller_trace, adapter)
                if (
                    receipt.run_id != run_id
                    or receipt.attempt_id != profile.attempt_id
                    or receipt.profile_digest != profile.policy_digest
                    or receipt.generation_digest != profile.expected_generation.digest
                    or receipt.target_snapshot_ref != profile.target_snapshot_ref
                    or receipt.controller_trace_ref != controller_trace["trace_ref"]
                    or receipt.adapter_revocation_ref != adapter.digest
                    or receipt.binding_digest != self._trace_binding(controller_trace).digest
                ):
                    raise ValueError("receipt substitution")
                proof = self._owned_worker_proof()
                if any(getattr(receipt, name) != value for name, value in proof.items()):
                    raise ValueError("worker proof changed")
                return receipt
            except Exception:
                raise TenantHttpCompletionError(
                    "controller completion receipt cannot be reopened"
                ) from None
