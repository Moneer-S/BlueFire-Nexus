"""One reviewed correction, one fresh paired retest, and closure-only recovery."""

from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from . import product_store_file_access_managed_closure as managed_closure_store
from . import product_store_file_access_managed_ready as managed_ready_store
from . import product_store_file_access_native_evidence as native
from . import product_store_windows_correction as journal
from . import product_store_windows_correction_publication as publication
from . import product_store_windows_correction_retest as retest
from . import windows_file_access_context as context
from . import windows_file_access_correction_admission as admission
from . import windows_file_access_correction_control_process as control_process
from . import windows_file_access_correction_observation as observation
from . import windows_file_access_managed_result as managed_result
from . import windows_file_access_managed_session as managed_session
from . import windows_file_access_native_wire as wire
from .product_store_errors import ProductStoreError
from .util import canonical_json_bytes, content_hash
from .windows_file_access_pair_launch import (
    CorrectionLaunchOwner,
    PairLaunchOwner,
)


class WindowsCorrectionRuntime:
    """Keep both real process owners; persisted evidence cannot reconstruct them."""

    def __init__(self, control: Any) -> None:
        self.control, self.store = control, control.store
        self._control_owners: dict[str, control_process.CorrectionControlCleanupOwner] = {}
        self._retest_owners: dict[str, CorrectionLaunchOwner] = {}
        self._lock = threading.RLock()
        self._closing = False

    def _clock(self) -> datetime:
        return datetime.now(timezone.utc)

    def _runner_client(self, setup_receipt: dict) -> Any:
        try:
            source = setup_receipt["source"]
            client, _sandbox = self.control.service.runner_lifecycle.client_for_profile(
                source["source_profile_id"]
            )
            wire._require(dict(client.transport_identity()) == source["transport"])
            return client
        except Exception:
            raise ProductStoreError(
                "The original managed correction transport is unavailable."
            ) from None

    def _persist_managed_result(
        self,
        authenticated: managed_result.AuthenticatedManagedCorrectionResult,
        *,
        original: dict,
        binding: dict,
    ) -> None:
        task_id = original["task_id"]
        transport_hash = original["transport_request_hash"]
        managed_ready_store.validate_persisted_managed_correction_ready(
            self.store,
            task_id,
            transport_hash,
            binding,
            authenticated.value["persisted_consume_receipt"],
            packet=authenticated.packet,
            ready=authenticated.ready,
            clock=self._clock(),
        )
        trail = native.query(
            self.store,
            task_id,
            transport_hash,
            binding,
            self._clock(),
            _protocol=native._Protocol.CORRECTION_V3,
        )
        wire._require(
            type(trail) is native.CorrectionNativeTaskEvidence
            and trail.packet_bytes == authenticated.packet
            and trail.ready_bytes == authenticated.ready
            and (
                trail.terminal_bytes is None
                or (
                    trail.terminal_bytes == authenticated.terminal
                    and trail.actual_returncode == authenticated.value["actual_returncode"]
                )
            )
        )
        native.record(
            self.store,
            task_id,
            transport_hash,
            binding,
            "terminal",
            authenticated.terminal,
            authenticated.value["actual_returncode"],
            self._clock(),
            _protocol=native._Protocol.CORRECTION_V3,
        )
        completed = native.query(
            self.store,
            task_id,
            transport_hash,
            binding,
            self._clock(),
            _protocol=native._Protocol.CORRECTION_V3,
        )
        closure = managed_result.native_closure(
            authenticated,
            claim_digest=completed.claim_digest,
        )
        managed_closure_store.record_authenticated_managed_correction_closure(
            self.store,
            task_id,
            transport_hash,
            binding,
            closure,
            self._clock(),
        )

    def _retain_control(
        self, job_id: str, owner: control_process.CorrectionControlCleanupOwner
    ) -> None:
        with self._lock:
            if self._closing or job_id in self._control_owners:
                raise ProductStoreError("The original correction owner is unavailable.")
            self._control_owners[job_id] = owner

    def _retain_retest(self, job_id: str, owner: PairLaunchOwner) -> None:
        if not isinstance(owner, CorrectionLaunchOwner):
            raise ProductStoreError("The correction retest requires its original owner.")
        with self._lock:
            if self._closing or job_id in self._retest_owners:
                raise ProductStoreError("The original correction retest owner is unavailable.")
            self._retest_owners[job_id] = owner

    def cleanup(self, job_id: str) -> bool:
        """Close only retained processes; persistence failure keeps their owners."""
        with self._lock:
            setter = self._control_owners.get(job_id)
            reader = self._retest_owners.get(job_id)
        complete = True
        if setter is not None:
            try:
                wire._require(setter.retry_cleanup() and setter.cleanup_receipt is not None)
                journal.record_control_closure(self.store, job_id, setter.cleanup_receipt)
                with self._lock:
                    if self._control_owners.get(job_id) is setter:
                        del self._control_owners[job_id]
            except Exception:
                complete = False
        if reader is not None:
            try:
                wire._require(reader.retry_cleanup())
                result = reader.outcome(True).process
                if result is None or result.cleanup_receipt is None:
                    raise ProductStoreError("The correction retest closure is unresolved.")
                wire._require(type(result.cleanup_receipt) is native.OwnedCleanupReceipt)
                result.cleanup_receipt.document()
                original = wire._reservation(reader.original, wire._CORRECTION)
                retained = native.query_cleanup(
                    self.store,
                    original["task_id"],
                    original["transport_request_hash"],
                    wire._document(reader.original._expected),
                    self._clock(),
                    _protocol=native._Protocol.CORRECTION_V3,
                )
                if retained.owned_job_cleanup == "verified":
                    wire._require(
                        retained.receipt_bytes == result.cleanup_receipt._raw
                        and retained.private_packet_bytes == result.cleanup_receipt._packet
                    )
                else:
                    native.record_cleanup(
                        self.store,
                        original["task_id"],
                        original["transport_request_hash"],
                        wire._document(reader.original._expected),
                        result.cleanup_receipt,
                        self._clock(),
                        _protocol=native._Protocol.CORRECTION_V3,
                    )
                with self._lock:
                    if self._retest_owners.get(job_id) is reader:
                        del self._retest_owners[job_id]
            except Exception:
                complete = False
        return complete

    def close_all(self) -> bool:
        with self._lock:
            self._closing = True
            jobs = tuple(set(self._control_owners) | set(self._retest_owners))
        complete = True
        for job in jobs:
            try:
                complete = self.cleanup(job) and complete
            except Exception:
                complete = False
        return complete

    def execute(self, ctx: Any, request: dict) -> None:
        try:
            self._execute(ctx, request)
        except BaseException:
            try:
                self.cleanup(ctx.job_id)
            except Exception:
                pass
            saved = self.store.file_access_operation_records(ctx.job_id)
            if saved["outcome"] is None:
                dispatched = journal.has_dispatch(self.store, ctx.job_id)
                self.store.finish_file_access_operation(
                    ctx.job_id,
                    outcome={
                        "state": "unknown" if dispatched or saved["tasks"] else "refused_no_effect",
                        "evidence_digest": content_hash(
                            {"tasks": saved["tasks"], "control_dispatch_retained": dispatched}
                        ),
                    },
                )
            raise

    def _execute(self, ctx: Any, request: dict) -> None:
        ctx.checkpoint({"phase": "preparing_windows_correction"})
        saved = self.store.file_access_operation_records(ctx.job_id)
        if (
            saved["preparation"] is not None
            or saved["tasks"]
            or saved["outcome"] is not None
            or journal.has_dispatch(self.store, ctx.job_id)
        ):
            raise ProductStoreError("An existing correction can only be reconciled.")
        reviewed = saved["document"]
        current = context.correction_context(
            self.control.service,
            self.control.clock(),
            reviewed["review"]["control_owner_id"],
            _original_job_id=ctx.job_id,
        )
        if current["review_context"] != reviewed["review_context"] or request != {
            **reviewed["submitted_request"],
            "review": reviewed["review"],
        }:
            raise ProductStoreError("The original correction review changed.")
        started, issued = time.monotonic(), self.control.clock()
        prepared = admission.build_preparation(
            ctx.job_id,
            reviewed,
            current["_imported"],
            current["control"]["document"],
            issued_at_ms=issued,
        )
        deadline = started + (prepared["expires_at_ms"] - issued) / 1000
        self.store.prepare_file_access_operation(ctx.job_id, prepared, now_ms=self.control.clock())

        def require_live() -> None:
            wire._require(
                not self._closing
                and not ctx.cancellation_event.is_set()
                and prepared["issued_at_ms"] <= self.control.clock() < prepared["expires_at_ms"]
                and time.monotonic() < deadline
            )

        # Own the durable obligation before creating even a suspended child.
        original_dispatch = journal.begin_dispatch(
            self.store,
            ctx.job_id,
            binding_digest=prepared["binding_digest"],
            now_ms=self.control.clock(),
            revalidate=require_live,
        )

        def before_dispatch() -> None:
            require_live()
            original_dispatch(self.control.clock())
            require_live()

        changed = control_process.run_correction_control_process(
            current["_checked"],
            canonical_json_bytes(prepared["binding"]),
            original_monotonic_deadline=deadline,
            before_dispatch=before_dispatch,
            cancellation_event=ctx.cancellation_event,
            retain_cleanup_owner=lambda owner: self._retain_control(ctx.job_id, owner),
        )
        if not self.cleanup(ctx.job_id) or changed.process_cleanup != "verified":
            raise ProductStoreError("The original correction child closure remains unresolved.")
        require_live()
        with self.store._connection() as connection:
            result = retest.successful_control(connection, ctx.job_id, prepared)
        checked = observation.observe_correction_postimage(
            observation.CorrectionObservationInput(
                current["_checked"],
                canonical_json_bytes(prepared["binding"]),
                result["after_descriptor_sha256"],
            ),
            now_ms=self.control.clock(),
            deadline=min(deadline, time.monotonic() + 5),
            cancelled=lambda: self._closing or ctx.cancellation_event.is_set(),
        )
        require_live()
        self._retest(ctx, prepared, checked, deadline, require_live)

    def _retest(
        self,
        ctx: Any,
        prepared: dict,
        checked: observation.VerifiedWindowsCorrectionPostimage,
        deadline: float,
        require_live: Callable[[], None],
    ) -> None:
        ctx.checkpoint({"phase": "retesting_windows_correction"})
        saved = self.store.file_access_operation_records(ctx.job_id)
        issued = self.control.clock()
        original, binding = admission.build_retest_original(
            prepared["binding"],
            checked._setup,
            issued_at_ms=issued,
            reviewed_by=saved["document"]["submitted_request"]["reviewed_by"],
        )
        retest.register_retest(
            self.store,
            ctx.job_id,
            checked=checked,
            original=original,
            expected_binding=binding,
            now_ms=issued,
            revalidate=require_live,
        )
        reservation = wire.validate_correction_original_reservation(
            original, expected_binding=binding
        )
        packet_clock = self._clock()
        packet_monotonic = time.monotonic()
        packet = wire.prepare_correction_packet(
            reservation,
            challenge=secrets.token_hex(32),
            clock=packet_clock,
            monotonic_now=packet_monotonic,
            original_monotonic_deadline=deadline,
        )
        identity = dict(
            transport_request_hash=original["transport_request_hash"], expected_binding=binding
        )
        allowance: Callable[[datetime, float], None] | None = None
        descriptor: dict[str, Any] | None = None

        def revalidate() -> None:
            require_live()
            retest.revalidate_original(
                self.store,
                original["task_id"],
                **identity,
                prepared_packet=packet,
                clock=self._clock(),
                monotonic_now=time.monotonic(),
            )

        def consume_ready(
            packet_bytes: bytes,
            ready_bytes: bytes,
            consume_identity: dict[str, Any],
        ) -> managed_session.PersistedManagedCorrectionReady:
            nonlocal allowance
            active_descriptor = descriptor
            if active_descriptor is None:
                raise wire.NativeWireError("Native reader wire refused")
            wire._require(
                allowance is None
                and packet_bytes == packet._raw
                and consume_identity
                == {
                    "task_id": original["task_id"],
                    "transport_request_hash": original["transport_request_hash"],
                    "session_nonce": active_descriptor["session_nonce"],
                    "packet_digest": content_hash(wire._document(packet._raw)),
                    "ready_digest": content_hash(wire._document(ready_bytes)),
                    "ack_nonce": consume_identity.get("ack_nonce"),
                }
            )
            native.record(
                self.store,
                original["task_id"],
                original["transport_request_hash"],
                binding,
                "packet",
                packet_bytes,
                None,
                self._clock(),
                _protocol=native._Protocol.CORRECTION_V3,
            )
            allowance = retest.consume_ready(
                self.store,
                original["task_id"],
                **identity,
                prepared_packet=packet,
                ready_bytes=ready_bytes,
                clock=self._clock(),
                monotonic_now=time.monotonic(),
            )
            allowance(self._clock(), time.monotonic())
            return managed_ready_store.persisted_managed_correction_ready(
                self.store,
                original["task_id"],
                original["transport_request_hash"],
                binding,
                session_nonce=active_descriptor["session_nonce"],
                ack_nonce=str(consume_identity["ack_nonce"]),
                packet=packet_bytes,
                ready=ready_bytes,
                clock=self._clock(),
            )

        record, setup_receipt, retained_binding = observation.checked_provenance(checked)
        wire._require(retained_binding == prepared["binding"])
        descriptor = managed_session.build_descriptor(
            session_nonce=secrets.token_hex(32),
            task_id=original["task_id"],
            transport_request_hash=original["transport_request_hash"],
            expected_binding=binding,
            correction_binding=prepared["binding"],
            setup_record=checked._setup._raw,
            setup_receipt=checked._setup._receipt,
            target_descriptor_sha256=checked._descriptor_sha256,
            packet=packet._raw,
            packet_issued_at_ms=managed_session._milliseconds(packet_clock),
            manifest=original["manifest"],
            profile=original["profile"],
        )
        revalidate()
        client = self._runner_client(setup_receipt)
        try:
            result = client.execute_windows_correction_session(
                original["manifest"],
                original["profile"],
                descriptor,
                cancel_event=ctx.cancellation_event,
                ready_consumer=consume_ready,
            )
            authenticated = managed_result.validate_runner_result(
                result,
                original["manifest"],
                original["profile"],
                expected_packet=packet._raw,
                expected_session_nonce=descriptor["session_nonce"],
            )
        except Exception:
            raise ProductStoreError(
                "The original managed correction outcome is unavailable."
            ) from None
        wire._require(record == observation.checked_provenance(checked)[0])
        self._persist_managed_result(
            authenticated,
            original=original,
            binding=binding,
        )
        publication.publish(self.store, ctx.job_id, clock=self._clock())

    def _recover_managed_result(self, job_id: str) -> None:
        saved = self.store.file_access_operation_records(job_id)
        wire._require(len(saved["tasks"]) == 1)
        claim = saved["tasks"][0]["task"]
        original = {
            "manifest": claim["manifest"],
            "profile": claim["runner_profile"],
            "task_id": claim["task_id"],
            "transport_request_hash": claim["transport_request_hash"],
        }
        binding = managed_session.expected_binding_from_manifest(original["manifest"])
        reservation = wire.validate_correction_original_reservation(
            original,
            expected_binding=binding,
        )
        wire._require(reservation._raw == canonical_json_bytes(original))
        snapshot = native.query_cleanup(
            self.store,
            original["task_id"],
            original["transport_request_hash"],
            binding,
            self._clock(),
            _protocol=native._Protocol.CORRECTION_V3,
        )
        if snapshot.owned_job_cleanup == "verified":
            return
        trail = snapshot.native_evidence
        # Packet and Ready are the durable proof that the original service
        # persisted consumption before it acknowledged the watchdog. Missing
        # stages are never reconstructed from the remote result.
        packet_bytes = trail.packet_bytes
        ready_bytes = trail.ready_bytes
        if packet_bytes is None or ready_bytes is None:
            raise wire.NativeWireError("Native reader wire refused")
        consume = managed_ready_store.load_persisted_managed_correction_ready(
            self.store,
            original["task_id"],
            original["transport_request_hash"],
            binding,
            packet=packet_bytes,
            ready=ready_bytes,
            clock=self._clock(),
        ).document()
        with self.store._connection() as connection:
            _operation, _prepared, imported, _control = journal.original_at(
                self.store, connection, job_id
            )
        client = self._runner_client(imported["setup_receipt"])
        try:
            recovered = client.recover(
                original["task_id"],
                original["transport_request_hash"],
            )
            wire._require(
                isinstance(recovered, dict)
                and recovered.get("state") == "completed"
                and isinstance(recovered.get("result"), dict)
            )
            authenticated = managed_result.validate_runner_result(
                recovered["result"],
                original["manifest"],
                original["profile"],
                expected_packet=trail.packet_bytes,
                expected_session_nonce=consume["session_nonce"],
            )
            wire._require(authenticated.ready == trail.ready_bytes)
        except Exception:
            raise ProductStoreError(
                "The original managed correction outcome is unavailable."
            ) from None
        self._persist_managed_result(
            authenticated,
            original=original,
            binding=binding,
        )

    def recover(self, job_id: str, *, expected_outcome_digest: str) -> None:
        """Recover only the original authenticated result; never redispatch work."""
        if not self.cleanup(job_id):
            raise ProductStoreError("The original correction closure remains unresolved.")
        saved = self.store.file_access_operation_records(job_id)
        if saved["tasks"]:
            try:
                self._recover_managed_result(job_id)
            except Exception:
                raise ProductStoreError(
                    "The original correction closure remains unresolved."
                ) from None
        publication.publish(
            self.store, job_id, clock=self._clock(), expected_outcome_digest=expected_outcome_digest
        )
