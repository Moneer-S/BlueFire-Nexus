"""One reviewed correction, one fresh paired retest, and closure-only recovery."""

from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from . import product_store_file_access_native_evidence as native
from . import product_store_windows_correction as journal
from . import product_store_windows_correction_publication as publication
from . import product_store_windows_correction_retest as retest
from . import windows_file_access_context as context
from . import windows_file_access_correction_admission as admission
from . import windows_file_access_correction_control_process as control_process
from . import windows_file_access_correction_observation as observation
from . import windows_file_access_native_wire as wire
from .product_store_errors import ProductStoreError
from .util import canonical_json_bytes, content_hash
from .windows_file_access_correction_credential import CorrectionBeginProducer
from .windows_file_access_pair_launch import (
    CorrectionLaunchOwner,
    PairLaunchOwner,
    launch_correction_retest,
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
                original = wire._reservation(reader.original, wire._CORRECTION)
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
        packet = wire.prepare_correction_packet(
            reservation,
            challenge=secrets.token_hex(32),
            clock=self._clock(),
            monotonic_now=time.monotonic(),
            original_monotonic_deadline=deadline,
        )
        identity = dict(
            transport_request_hash=original["transport_request_hash"], expected_binding=binding
        )
        allowance: Callable[[datetime, float], None] | None = None

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

        def require_ready() -> None:
            if allowance is None:
                raise ProductStoreError("No original correction Ready allowance exists.")
            allowance(self._clock(), time.monotonic())

        def evidence(stage: str, raw: bytes, returncode: int | None, clock: datetime) -> None:
            nonlocal allowance
            if stage == "ready":
                wire._require(allowance is None)
                allowance = retest.consume_ready(
                    self.store,
                    original["task_id"],
                    **identity,
                    prepared_packet=packet,
                    ready_bytes=raw,
                    clock=clock,
                    monotonic_now=time.monotonic(),
                )
            elif stage in ("packet", "terminal"):
                native.record(
                    self.store,
                    original["task_id"],
                    original["transport_request_hash"],
                    binding,
                    stage,
                    raw,
                    returncode,
                    clock,
                    _protocol=native._Protocol.CORRECTION_V3,
                )
            else:
                raise ProductStoreError("The correction evidence stage is unavailable.")

        producer = CorrectionBeginProducer(
            checked,
            reservation,
            packet,
            revalidate_original=revalidate,
            require_ready_allowance=require_ready,
            cancellation_event=ctx.cancellation_event,
        )
        revalidate()
        result = launch_correction_retest(
            checked,
            reservation,
            packet,
            producer,
            revalidate_original=revalidate,
            evidence_sink=evidence,
            cancellation_event=ctx.cancellation_event,
            retain_launch_owner=lambda owner: self._retain_retest(ctx.job_id, owner),
        )
        if not self.cleanup(ctx.job_id) or result.cleanup != "verified":
            raise ProductStoreError("The original correction retest closure remains unresolved.")
        publication.publish(self.store, ctx.job_id, clock=self._clock())

    def recover(self, job_id: str, *, expected_outcome_digest: str) -> None:
        """No setup observation, setter, credential release, task or process replay."""
        if not self.cleanup(job_id):
            raise ProductStoreError("The original correction closure remains unresolved.")
        publication.publish(
            self.store, job_id, clock=self._clock(), expected_outcome_digest=expected_outcome_digest
        )
