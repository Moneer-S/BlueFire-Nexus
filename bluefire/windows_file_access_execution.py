"""One original Windows paired baseline and cleanup-only retained recovery."""

from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from . import windows_file_access_context as context
from . import windows_file_access_native_wire as wire
from . import windows_file_access_pair_admission as admission
from .product_store_errors import ProductStoreError
from .util import content_hash
from .windows_file_access_pair_credential import PairBeginProducer
from .windows_file_access_pair_launch import PairLaunchOwner, launch_pair_baseline


class WindowsBaselineRuntime:
    """Hold actual owners in memory; persisted rows never reconstruct authority."""

    def __init__(self, control: Any) -> None:
        self.control, self.store = control, control.store
        self._owners: dict[str, PairLaunchOwner] = {}
        self._lock = threading.RLock()
        self._closing = False

    def _clock(self) -> datetime:
        return datetime.now(timezone.utc)

    def _retain(self, job_id: str, owner: PairLaunchOwner) -> None:
        with self._lock:
            if self._closing or job_id in self._owners:
                raise ProductStoreError("The original Windows launch is no longer available.")
            self._owners[job_id] = owner

    def cleanup(self, job_id: str) -> bool:
        with self._lock:
            owner = self._owners.get(job_id)
        if owner is None:
            return True
        if not owner.retry_cleanup():
            return False
        result = owner.outcome(True).process
        if result is not None and result.cleanup_receipt is not None:
            original = wire._reservation(owner.original, wire._PAIR)
            self.store.record_file_access_native_pair_cleanup(
                original["task_id"],
                transport_request_hash=original["transport_request_hash"],
                expected_binding=wire._document(owner.original._expected),
                receipt=result.cleanup_receipt,
                clock=self._clock(),
            )
        with self._lock:
            if self._owners.get(job_id) is owner:
                del self._owners[job_id]
        return True

    def close_all(self) -> bool:
        with self._lock:
            self._closing = True
            identifiers = tuple(self._owners)
        complete = True
        for identifier in identifiers:
            try:
                complete = self.cleanup(identifier) and complete
            except Exception:
                complete = False
        return complete

    def execute(self, ctx: Any, request: dict) -> None:
        job_id = ctx.job_id
        try:
            self._execute(ctx, request)
        except BaseException:
            # Missing native/closure proof is never a successful baseline or an
            # invitation to retry the original credential/read operation.
            saved = self.store.file_access_operation_records(job_id)
            if saved["outcome"] is None:
                self.store.finish_file_access_operation(
                    job_id,
                    outcome={
                        "state": "unknown" if saved["tasks"] else "refused_no_effect",
                        "evidence_digest": content_hash(saved["tasks"]),
                    },
                )
            raise

    def _execute(self, ctx: Any, request: dict) -> None:
        ctx.checkpoint({"phase": "preparing_windows_baseline"})
        saved = self.store.file_access_operation_records(ctx.job_id)
        if saved["preparation"] is not None or saved["tasks"] or saved["outcome"] is not None:
            raise ProductStoreError("An existing Windows baseline can only be reconciled.")
        original_review = saved["document"]
        current = context.baseline_context(
            self.control.service,
            self.control.clock(),
            original_review["review"]["control_owner_id"],
        )
        if current["review_context"] != original_review["review_context"] or request != {
            **original_review["submitted_request"],
            "review": original_review["review"],
        }:
            raise ProductStoreError("The original Windows baseline review changed.")
        imported = current["control"]["document"]
        started = time.monotonic()
        issued = self.control.clock()
        prepared = admission.build_preparation(
            ctx.job_id, original_review, imported, issued_at_ms=issued
        )
        deadline = started + (prepared["expires_at_ms"] - issued) / 1000
        self.store.prepare_file_access_operation(ctx.job_id, prepared, now_ms=self.control.clock())
        original = prepared["original"]

        def before_claim() -> None:
            if ctx.cancellation_event.is_set() or self._closing:
                raise ProductStoreError("The original Windows baseline was stopped.")
            admission.validate_preparation(
                prepared, original_review, imported, now_ms=self.control.clock()
            )
            wire._require(time.monotonic() < deadline)

        self.store.register_file_access_task(
            ctx.job_id,
            task_id=original["task_id"],
            step_id="read_generated_pair",
            manifest=original["manifest"],
            runner_profile=original["profile"],
            now_ms=self.control.clock(),
            validate_context=before_claim,
        )
        binding = prepared["expected_binding"]
        reservation = wire.validate_pair_original_reservation(original, expected_binding=binding)
        packet = wire.prepare_pair_packet(
            reservation,
            challenge=secrets.token_hex(32),
            clock=self._clock(),
            monotonic_now=time.monotonic(),
            original_monotonic_deadline=deadline,
        )
        identity = {
            "transport_request_hash": original["transport_request_hash"],
            "expected_binding": binding,
        }
        allowance: Callable[[datetime, float], None] | None = None

        def revalidate() -> None:
            before_claim()
            self.store.revalidate_windows_file_access_pair_original(
                original["task_id"],
                **identity,
                prepared_packet=packet,
                clock=self._clock(),
                monotonic_now=time.monotonic(),
            )

        def require_ready() -> None:
            if allowance is None:
                raise ProductStoreError("No original committed Windows Ready allowance exists.")
            allowance(self._clock(), time.monotonic())

        def evidence(stage: str, raw: bytes, returncode: int | None, clock: datetime) -> None:
            nonlocal allowance
            if stage == "ready":
                if allowance is not None:
                    raise ProductStoreError("The Windows Ready allowance was already consumed.")
                allowance = self.store.consume_windows_file_access_pair_ready(
                    original["task_id"],
                    **identity,
                    prepared_packet=packet,
                    ready_bytes=raw,
                    clock=clock,
                    monotonic_now=time.monotonic(),
                )
            elif stage == "packet":
                self.store.record_file_access_native_pair_packet(
                    original["task_id"], **identity, public_bytes=raw, clock=clock
                )
            elif stage == "terminal":
                self.store.record_file_access_native_pair_terminal(
                    original["task_id"],
                    **identity,
                    terminal_bytes=raw,
                    actual_returncode=returncode,
                    clock=clock,
                )
            else:
                raise ProductStoreError("The Windows evidence stage is unavailable.")

        producer = PairBeginProducer(
            current["_checked"],
            reservation,
            packet,
            revalidate_original=revalidate,
            require_ready_allowance=require_ready,
            cancellation_event=ctx.cancellation_event,
        )
        revalidate()
        result = launch_pair_baseline(
            current["_checked"],
            reservation,
            packet,
            producer,
            revalidate_original=revalidate,
            evidence_sink=evidence,
            cancellation_event=ctx.cancellation_event,
            retain_launch_owner=lambda owner: self._retain(ctx.job_id, owner),
        )
        if not self.cleanup(ctx.job_id) or result.cleanup != "verified":
            raise ProductStoreError("The original Windows baseline cleanup remains unresolved.")
        self.store.publish_windows_file_access_baseline(ctx.job_id, clock=self._clock())

    def recover(self, job_id: str, *, expected_outcome_digest: str) -> None:
        # Only existing exact in-memory owners may close. Neither enrollment nor
        # credentials, task preparation, or process launch is consulted here.
        if not self.cleanup(job_id):
            raise ProductStoreError("The original Windows baseline cleanup remains unresolved.")
        self.store.recover_windows_file_access_baseline(
            job_id, expected_outcome_digest=expected_outcome_digest, clock=self._clock()
        )
