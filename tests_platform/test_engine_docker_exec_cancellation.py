from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from typing import Any, Iterator, cast

import pytest

from bluefire.engine_docker_exec_admission import DockerExecAdmissionV2
from bluefire.engine_docker_exec_cancellation import (
    DockerExecCancellationAuditRecordV2,
    DockerExecCancellationLaneV2,
)
from bluefire.engine_docker_exec_signals import ControllerExecCancellationV2
from bluefire.engine_worker_runtime import ResourceCustodySnapshot, ResourceCustodyState
from bluefire.util import content_hash
from tests_platform.test_engine_docker_exec_admission import admission

PLAN = "sha256:" + "1" * 64
NETWORK = "sha256:" + "2" * 64
ABSENT = ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)
UNKNOWN = ResourceCustodySnapshot(ResourceCustodyState.UNKNOWN)


class Clock:
    broken = False

    def __init__(self) -> None:
        self.value = time.monotonic_ns()

    def __call__(self) -> int:
        if self.broken:
            raise RuntimeError("clock unavailable")
        return self.value


class Authority:
    authority_ref = "sha256:" + "3" * 64
    claim_ref = "sha256:" + "4" * 64
    controller_fence = "sha256:" + "5" * 64

    def __init__(self, admitted: DockerExecAdmissionV2) -> None:
        self.admitted = admitted
        self.active = threading.Event()
        self.fail = False
        self.entries = 0
        self.exits = 0

    @contextmanager
    def cleanup_scope(self, admitted: DockerExecAdmissionV2) -> Iterator[None]:
        assert admitted is self.admitted
        if self.fail:
            raise RuntimeError("claim mapping differs")
        self.entries += 1
        self.active.set()
        try:
            yield
        finally:
            self.active.clear()
            self.exits += 1


class Audit:
    def __init__(self) -> None:
        self.records: list[DockerExecCancellationAuditRecordV2] = []
        self.fail_phase: str | None = None
        self.wrong_receipt = False
        self.request_gate: threading.Event | None = None
        self._lock = threading.Lock()

    def append(self, record: DockerExecCancellationAuditRecordV2) -> str:
        with self._lock:
            self.records.append(record)
        if record.phase == "requested" and self.request_gate is not None:
            self.request_gate.wait(2)
        if record.phase == self.fail_phase:
            raise RuntimeError("audit unavailable")
        return "sha256:" + "0" * 64 if self.wrong_receipt else content_hash(record.to_dict())


class Custody:
    def __init__(self, authority: Authority) -> None:
        self.authority = authority
        self.calls: list[tuple[str, str, str, str, float]] = []
        self.stop_result: Any = ABSENT
        self.inspect_result: Any = ABSENT
        self.fail_stop = False
        self.fail_inspect = False
        self.stop_gate: threading.Event | None = None
        self.on_stop: Any = None
        self.stopping = threading.Event()
        self.inspected = threading.Event()

    def stop_owned(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> ResourceCustodySnapshot:
        assert self.authority.active.is_set()
        self.calls.append(
            ("stop", attempt_id, custody_identity_digest, network_policy_digest, timeout_seconds)
        )
        self.stopping.set()
        if self.on_stop is not None:
            self.on_stop()
        if self.stop_gate is not None:
            self.stop_gate.wait(2)
        if self.fail_stop:
            raise RuntimeError("stop outcome unknown")
        return cast(ResourceCustodySnapshot, self.stop_result)

    def inspect(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> ResourceCustodySnapshot:
        assert self.authority.active.is_set()
        self.calls.append(
            ("inspect", attempt_id, custody_identity_digest, network_policy_digest, timeout_seconds)
        )
        self.inspected.set()
        if self.fail_inspect:
            raise RuntimeError("inspect unavailable")
        return cast(ResourceCustodySnapshot, self.inspect_result)


class Cancellation:
    value = False
    broken = False

    def is_cancelled(self) -> bool:
        if self.broken:
            raise RuntimeError("cancellation unavailable")
        return self.value


def lane(*, timeout: float = 1.0):
    admitted = admission()
    authority = Authority(admitted)
    custody = Custody(authority)
    audit = Audit()
    clock = Clock()
    cancellation = DockerExecCancellationLaneV2(
        custody=custody,
        authority=authority,
        custody_plan_digest=PLAN,
        network_policy_digest=NETWORK,
        audit=audit,
        monotonic_ns=time.monotonic_ns,
        cleanup_timeout_seconds=timeout,
    )
    return cancellation, admitted, authority, custody, audit, clock


def test_cancel_stops_exact_custody_then_independently_inspects_absence_and_caches_receipt() -> (
    None
):
    cancellation, admitted, authority, custody, audit, _clock = lane()
    receipt = cancellation.cancel(admitted, "cancelled")
    assert receipt.verified_absent and receipt.audited and receipt.issue is None
    assert receipt.admission_digest == admitted.admission_digest
    assert receipt.custody_plan_digest == PLAN and receipt.network_policy_digest == NETWORK
    assert [call[0] for call in custody.calls] == ["stop", "inspect"]
    for _method, attempt, plan, network, timeout in custody.calls:
        assert attempt == admitted.profile.attempt_id
        assert plan == PLAN and network == NETWORK and 0 < timeout <= 1
    assert custody.calls[1][-1] <= custody.calls[0][-1]
    assert authority.entries == authority.exits == 1
    assert [row.phase for row in audit.records] == ["requested", "absence_verified"]
    assert all(row.admission_digest == admitted.admission_digest for row in audit.records)
    assert audit.records[-1].stop_snapshot_digest == content_hash(ABSENT.to_dict())
    assert audit.records[-1].inspect_snapshot_digest == content_hash(ABSENT.to_dict())
    assert cancellation.cancel(admitted, "deadline_exceeded") is receipt
    assert len(custody.calls) == 2


@pytest.mark.parametrize("stage", ["stop", "inspect"])
@pytest.mark.parametrize(
    "result",
    [
        UNKNOWN,
        object(),
        replace(ABSENT, state=cast(ResourceCustodyState, "verified_absent")),
        replace(ABSENT, issue="custody_problem"),
    ],
)
def test_empty_ids_or_duck_typed_or_raw_state_do_not_prove_absence(stage: str, result: Any) -> None:
    cancellation, admitted, _authority, custody, audit, _clock = lane()
    setattr(custody, f"{stage}_result", result)
    receipt = cancellation.cancel(admitted, "cancelled")
    assert not receipt.verified_absent and receipt.audited
    assert receipt.issue == "absence_unverified"
    assert [call[0] for call in custody.calls] == ["stop", "inspect"]
    assert audit.records[-1].phase == "unknown"


@pytest.mark.parametrize("failure", ["stop", "inspect", "scope", "clock"])
def test_errors_remain_unknown_and_stop_error_still_gets_independent_inspection(
    failure: str,
) -> None:
    cancellation, admitted, authority, custody, audit, clock = lane(
        timeout=3.0 if failure == "clock" else 1.0
    )
    custody.fail_stop = failure == "stop"
    custody.fail_inspect = failure == "inspect"
    authority.fail = failure == "scope"
    clock.broken = failure == "clock"
    if failure == "clock":
        cancellation._clock = clock
    receipt = cancellation.cancel(admitted, "cancelled")
    assert not receipt.verified_absent
    assert receipt.issue is not None and audit.records[-1].phase == "unknown"
    assert len(custody.calls) == (0 if failure == "scope" else 2)


@pytest.mark.parametrize("failure", ["requested", "absence_verified", "wrong_receipt"])
def test_audit_failure_or_wrong_receipt_never_prevents_teardown(failure: str) -> None:
    cancellation, admitted, _authority, custody, audit, _clock = lane()
    audit.fail_phase = failure
    audit.wrong_receipt = failure == "wrong_receipt"
    receipt = cancellation.cancel(admitted, "cancelled")
    assert [call[0] for call in custody.calls] == ["stop", "inspect"]
    assert not receipt.verified_absent and not receipt.audited
    assert receipt.issue == "audit_failed"
    assert any(row.phase == "unknown" for row in audit.records)


def test_clock_elapsed_beyond_cleanup_budget_keeps_both_absence_results_unknown() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane()
    cancellation._clock = clock
    custody.on_stop = lambda: setattr(clock, "value", clock.value + 2_000_000_000)
    receipt = cancellation.cancel(admitted, "deadline_exceeded")
    assert len(custody.calls) == 2
    assert not receipt.verified_absent and receipt.issue == "cleanup_timeout"


def test_uncooperative_custody_is_bounded_and_late_absence_cannot_replace_unknown() -> None:
    cancellation, admitted, _authority, custody, _audit, _clock = lane(timeout=1.0)
    custody.stop_gate = threading.Event()
    start = time.monotonic()
    receipt = cancellation.cancel(admitted, "cancelled")
    elapsed = time.monotonic() - start
    assert custody.stopping.is_set() and elapsed < 3
    assert not receipt.verified_absent and receipt.issue == "cleanup_timeout"
    assert not receipt.audited
    custody.stop_gate.set()
    assert cancellation.cancel(admitted, "cancelled") is receipt


def test_simultaneous_cancellation_uses_one_cleanup_without_holding_lane_lock() -> None:
    cancellation, admitted, _authority, custody, _audit, _clock = lane()
    custody.stop_gate = threading.Event()
    receipts: list[Any] = []
    workers = [
        threading.Thread(target=lambda: receipts.append(cancellation.cancel(admitted, "cancelled")))
        for _ in range(2)
    ]
    workers[0].start()
    assert custody.stopping.wait(0.5)
    workers[1].start()
    assert cancellation._lock.acquire(timeout=0.2)
    cancellation._lock.release()
    custody.stop_gate.set()
    for worker in workers:
        worker.join(1)
        assert not worker.is_alive()
    assert len(custody.calls) == 2 and len(receipts) == 2
    assert receipts[0] is receipts[1] and receipts[0].verified_absent


def test_watcher_quarantines_then_cleans_while_attach_is_blocked_on_another_thread() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane(timeout=3.0)
    signal = ControllerExecCancellationV2()
    attach_locked = threading.Event()
    attach_release = threading.Event()
    proxy_lock = threading.Lock()
    uncertain = threading.Event()

    def attach() -> None:
        with proxy_lock:
            attach_locked.set()
            attach_release.wait(5)

    def stop() -> None:
        assert uncertain.is_set() and proxy_lock.locked()
        attach_release.set()

    custody.on_stop = stop
    attach_thread = threading.Thread(target=attach)
    attach_thread.start()
    try:
        assert attach_locked.wait(2)
        with cancellation.watch(
            admitted, signal, clock.value + 5_000_000_000, uncertain.set
        ) as watcher:
            signal.cancel()
            assert custody.inspected.wait(2)
        attach_thread.join(2)
        assert not attach_thread.is_alive()
        assert watcher.receipt is not None and watcher.receipt.verified_absent
        assert watcher.receipt.reason == "cancelled"
    finally:
        attach_release.set()
        attach_thread.join(2)


@pytest.mark.parametrize("trigger", ["deadline", "cancellation_probe", "clock_probe"])
def test_watcher_deadline_and_probe_errors_trigger_uncertainty_before_cleanup(trigger: str) -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane(timeout=3.0)
    signal = Cancellation()
    if trigger in {"deadline", "clock_probe"}:
        cancellation._clock = clock
    uncertain = threading.Event()
    custody.on_stop = lambda: (
        (_ for _ in ()).throw(AssertionError()) if not uncertain.is_set() else None
    )
    with cancellation.watch(
        admitted, signal, clock.value + 1_000_000_000, uncertain.set
    ) as watcher:
        if trigger == "deadline":
            clock.value += 1_000_000_000
        elif trigger == "cancellation_probe":
            signal.broken = True
        else:
            clock.broken = True
        assert custody.inspected.wait(2)
    assert uncertain.is_set() and watcher.receipt is not None
    assert (
        watcher.receipt.reason
        == {
            "deadline": "deadline_exceeded",
            "cancellation_probe": "cancellation_probe_failed",
            "clock_probe": "clock_probe_failed",
        }[trigger]
    )
    if trigger == "clock_probe":
        assert not watcher.receipt.verified_absent


def test_watcher_callback_error_still_tears_down_but_does_not_claim_settlement() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane()
    signal = ControllerExecCancellationV2()
    signal.cancel()

    def fail() -> None:
        raise RuntimeError("quarantine unavailable")

    with cancellation.watch(admitted, signal, clock.value + 1_000_000_000, fail) as watcher:
        assert custody.inspected.wait(0.5)
    assert watcher.receipt is not None and not watcher.receipt.verified_absent
    assert watcher.receipt.issue == "uncertainty_callback_failed"
    assert not watcher.receipt.audited


def test_closing_normal_watcher_stops_polling_without_teardown() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane()
    with cancellation.watch(
        admitted, ControllerExecCancellationV2(), clock.value + 1_000_000_000, lambda: None
    ) as watcher:
        assert watcher.receipt is None
    assert watcher._thread is not None and not watcher._thread.is_alive()
    assert not custody.calls and watcher.receipt is None


def test_watcher_exposes_a_monotonic_trigger_barrier() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane()
    signal = ControllerExecCancellationV2()
    with cancellation.watch(admitted, signal, clock.value + 1_000_000_000, lambda: None) as watcher:
        assert not watcher.triggered
        signal.cancel()
        assert custody.stopping.wait(1)
        assert watcher.triggered
        assert watcher.triggered
    assert watcher.triggered


def test_watcher_context_exit_joins_only_cleanup_budget_when_custody_blocks() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane(timeout=1.0)
    custody.stop_gate = threading.Event()
    signal = ControllerExecCancellationV2()
    signal.cancel()
    start = time.monotonic()
    try:
        with cancellation.watch(
            admitted, signal, clock.value + 1_000_000_000, lambda: None
        ) as watcher:
            assert custody.stopping.wait(2)
        assert time.monotonic() - start < 3
        assert watcher.receipt is not None and not watcher.receipt.verified_absent
    finally:
        custody.stop_gate.set()


def test_blocked_requested_audit_cannot_prevent_stop_or_independent_inspection() -> None:
    cancellation, admitted, _authority, custody, audit, _clock = lane(timeout=1.0)
    audit.request_gate = threading.Event()
    receipts: list[Any] = []
    worker = threading.Thread(
        target=lambda: receipts.append(cancellation.cancel(admitted, "cancelled"))
    )
    worker.start()
    try:
        assert custody.inspected.wait(2)
        assert not audit.request_gate.is_set()
        worker.join(2)
        assert not worker.is_alive() and not receipts[0].verified_absent
    finally:
        audit.request_gate.set()
        worker.join(2)


@pytest.mark.parametrize("timeout", [0.0, 10.1, float("nan"), float("inf"), True])
def test_cleanup_budget_must_be_positive_finite_and_at_most_ten_seconds(timeout: float) -> None:
    with pytest.raises(ValueError):
        lane(timeout=timeout)


@pytest.mark.parametrize(
    "field",
    [
        "custody_plan_digest",
        "network_policy_digest",
        "authority_ref",
        "claim_ref",
        "controller_fence",
    ],
)
def test_lane_binding_check_refuses_drift_without_rebinding_from_caller(field: str) -> None:
    cancellation, _admitted, authority, custody, _audit, _clock = lane()
    exact = {
        "custody_plan_digest": PLAN,
        "network_policy_digest": NETWORK,
        "authority_ref": authority.authority_ref,
        "claim_ref": authority.claim_ref,
        "controller_fence": authority.controller_fence,
    }
    cancellation.require_binding(authority=authority, **exact)
    changed = dict(exact)
    changed[field] = "sha256:" + "9" * 64
    with pytest.raises(ValueError, match="another cleanup authority"):
        cancellation.require_binding(authority=authority, **changed)
    cancellation.require_binding(authority=authority, **exact)
    assert not custody.calls


def test_equal_refs_cannot_substitute_an_authority_with_another_opaque_handle_map() -> None:
    cancellation, admitted, authority, custody, _audit, _clock = lane()
    other_handle = replace(admitted.request.handle, opaque_ref=object())
    other_admission = replace(admitted, request=replace(admitted.request, handle=other_handle))
    other_authority = Authority(other_admission)
    assert other_admission.admission_digest == admitted.admission_digest
    assert other_authority.authority_ref == authority.authority_ref
    assert other_authority.claim_ref == authority.claim_ref
    assert other_authority.controller_fence == authority.controller_fence
    with pytest.raises(ValueError, match="another cleanup authority"):
        cancellation.require_binding(
            authority=other_authority,
            custody_plan_digest=PLAN,
            network_policy_digest=NETWORK,
            authority_ref=authority.authority_ref,
            claim_ref=authority.claim_ref,
            controller_fence=authority.controller_fence,
        )
    assert authority.entries == other_authority.entries == 0
    assert not custody.calls


def test_unknown_clone_cannot_poison_original_cancellation_cache_with_same_public_digest() -> None:
    cancellation, admitted, authority, custody, _audit, _clock = lane()
    other_handle = replace(admitted.request.handle, opaque_ref=object())
    clone = replace(admitted, request=replace(admitted.request, handle=other_handle))
    assert clone.admission_digest == admitted.admission_digest
    refused = cancellation.cancel(clone, "cancelled")
    assert not refused.verified_absent and refused.issue == "cleanup_scope_failed"
    assert not custody.calls
    settled = cancellation.cancel(admitted, "cancelled")
    assert settled.verified_absent and settled.audited
    assert authority.entries == authority.exits == 1
    assert [call[0] for call in custody.calls] == ["stop", "inspect"]
    assert cancellation.cancel(admitted, "cancelled") is settled
    assert cancellation.cancel(clone, "cancelled") is refused
    assert len(cancellation._cleanups) == 2
    assert {id(item.opaque_ref) for item in cancellation._cleanups.values()} == {
        id(admitted.request.handle.opaque_ref),
        id(clone.request.handle.opaque_ref),
    }


@pytest.mark.parametrize("field", ["authority_ref", "claim_ref", "controller_fence"])
def test_authority_property_drift_is_refused_again_before_cleanup(field: str) -> None:
    cancellation, admitted, authority, custody, _audit, _clock = lane()
    setattr(authority, field, "sha256:" + "9" * 64)
    receipt = cancellation.cancel(admitted, "cancelled")
    assert not receipt.verified_absent and receipt.issue == "cleanup_scope_failed"
    assert authority.entries == 0 and not custody.calls


@pytest.mark.parametrize("unknown_audit_fails", [False, True])
def test_audit_consuming_remaining_logical_budget_cannot_publish_verified_receipt(
    unknown_audit_fails: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancellation, admitted, _authority, _custody, audit, clock = lane(timeout=3.0)
    cancellation._clock = clock

    def instant_exact_clock(callback: Any) -> int:
        value = callback()
        assert type(value) is int and value >= 0
        return cast(int, value)

    # This case isolates audit publication; bounded generic observations have
    # separate blocked/failed probe cases below.
    monkeypatch.setattr(
        "bluefire.engine_docker_exec_cancellation.read_monotonic_ns", instant_exact_clock
    )
    append = audit.append

    def late_audit(record: DockerExecCancellationAuditRecordV2) -> str:
        result = append(record)
        if record.phase == "absence_verified":
            clock.value += 4_000_000_000
        return cast(str, result)

    audit.append = late_audit
    audit.fail_phase = "unknown" if unknown_audit_fails else None
    receipt = cancellation.cancel(admitted, "cancelled")
    assert not receipt.verified_absent
    assert receipt.audited is not unknown_audit_fails
    assert receipt.issue == ("audit_failed" if unknown_audit_fails else "cleanup_timeout")
    assert audit.records[-1].phase == "unknown"
    if receipt.audited:
        assert audit.records[-1].issue == receipt.issue
        assert audit.records[-1].reason == receipt.reason
        assert audit.records[-1].admission_digest == receipt.admission_digest


def test_blocked_uncertainty_callback_does_not_prevent_teardown_or_later_flip_receipt() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane(timeout=3.0)
    signal = ControllerExecCancellationV2()
    signal.cancel()
    callback_started = threading.Event()
    callback_gate = threading.Event()
    callback_done = threading.Event()

    def blocked_callback() -> None:
        callback_started.set()
        callback_gate.wait(5)
        callback_done.set()

    try:
        with cancellation.watch(
            admitted, signal, clock.value + 5_000_000_000, blocked_callback
        ) as watcher:
            assert callback_started.wait(2)
            assert custody.inspected.wait(2)
        receipt = watcher.receipt
        assert receipt is not None and not receipt.verified_absent
    finally:
        callback_gate.set()
        assert callback_done.wait(2)
    assert watcher.receipt is receipt


def test_probe_completing_after_watch_closes_cannot_trigger_late_teardown() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane(timeout=0.05)
    entered = threading.Event()
    release = threading.Event()

    class BlockedProbe:
        def is_cancelled(self) -> bool:
            entered.set()
            release.wait(1)
            return True

    with cancellation.watch(
        admitted, BlockedProbe(), clock.value + 1_000_000_000, lambda: None
    ) as watcher:
        assert entered.wait(0.3)
    receipt = watcher.receipt
    assert receipt is not None and not receipt.verified_absent
    assert watcher.triggered and not custody.calls
    release.set()
    assert watcher._thread is not None
    watcher._thread.join(0.3)
    assert not watcher._thread.is_alive()
    assert watcher.receipt is receipt and not custody.calls


def test_observer_only_blocked_probe_sets_unknown_trigger_barrier_on_bounded_close() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane(timeout=0.2)
    controller_thread = threading.get_ident()
    observer_entered = threading.Event()
    observer_release = threading.Event()

    class ObserverBlockedProbe:
        def is_cancelled(self) -> bool:
            if threading.get_ident() != controller_thread:
                observer_entered.set()
                observer_release.wait(2)
            return False

    probe = ObserverBlockedProbe()
    try:
        with cancellation.watch(
            admitted, probe, clock.value + 1_000_000_000, lambda: None
        ) as watcher:
            assert observer_entered.wait(1)
            assert probe.is_cancelled() is False
            assert not watcher.triggered and watcher.receipt is None
        receipt = watcher.receipt
        assert watcher.triggered and receipt is not None
        assert not receipt.verified_absent and not receipt.audited
        assert receipt.issue == "cleanup_timeout"
        assert probe.is_cancelled() is False
        assert not custody.calls
    finally:
        observer_release.set()
        assert watcher._thread is not None
        watcher._thread.join(1)
    assert not watcher._thread.is_alive()
    assert watcher.receipt is receipt and not custody.calls


def test_bounded_cancellation_probe_timeout_still_invokes_independent_custody() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane(timeout=1.0)
    probe_entered = threading.Event()
    probe_release = threading.Event()
    uncertain = threading.Event()

    class BlockedProbe:
        def is_cancelled(self) -> bool:
            probe_entered.set()
            probe_release.wait(3)
            return False

    def check_uncertain() -> None:
        assert uncertain.is_set()

    custody.on_stop = check_uncertain
    started = time.monotonic()
    try:
        with cancellation.watch(
            admitted, BlockedProbe(), clock.value + 10_000_000_000, uncertain.set
        ) as watcher:
            assert probe_entered.wait(1)
            assert custody.inspected.wait(2)
            assert not probe_release.is_set()
        assert time.monotonic() - started < 3
        assert watcher.triggered and watcher.receipt is not None
        assert watcher.receipt.reason == "cancellation_probe_failed"
        assert [call[0] for call in custody.calls] == ["stop", "inspect"]
    finally:
        probe_release.set()


def test_bounded_exec_clock_probe_timeout_does_not_prevent_independent_custody() -> None:
    cancellation, admitted, _authority, custody, _audit, clock = lane(timeout=1.0)
    clock_entered = threading.Event()
    clock_release = threading.Event()
    uncertain = threading.Event()

    def blocked_clock() -> int:
        clock_entered.set()
        clock_release.wait(3)
        return cast(int, clock.value)

    def check_uncertain() -> None:
        assert uncertain.is_set()

    cancellation._clock = blocked_clock
    custody.on_stop = check_uncertain
    started = time.monotonic()
    try:
        with cancellation.watch(
            admitted, Cancellation(), clock.value + 10_000_000_000, uncertain.set
        ) as watcher:
            assert clock_entered.wait(1)
            assert custody.inspected.wait(2)
            assert not clock_release.is_set()
        assert time.monotonic() - started < 3
        assert watcher.triggered and watcher.receipt is not None
        assert not watcher.receipt.verified_absent
        assert [call[0] for call in custody.calls] == ["stop", "inspect"]
    finally:
        clock_release.set()
