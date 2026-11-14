"""Controller fakes only: durable gates never contact Docker or a socket."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import bluefire.engine_docker_exec_dispatch as dispatch_module
import bluefire.engine_docker_exec_journal as journal_module
from bluefire.accepted_engine_jobs import AcceptedPreparedEngineAttempt
from bluefire.engine_docker_exec_admission import DockerExecAdmissionV2
from bluefire.engine_docker_exec_dispatch import (
    ControllerExecDispatchAuthorityV2,
    DockerExecCustodyUnavailable,
    DockerExecDispatchError,
    DockerExecDispatchRuntimeV2,
    ProtectedDockerExecHandleBindingV2,
    ProtectedDockerExecHandleMapV2,
)
from bluefire.engine_docker_exec_journal import (
    DockerExecJournalError,
    SQLiteDockerExecOperationJournal,
)
from bluefire.engine_exec_operation_custody import VerifiedExecLifetimeCustodyV2
from bluefire.util import content_hash
from tests_platform.test_engine_delegation import _binding, _delegation
from tests_platform.test_engine_docker_control import policy_v2
from tests_platform.test_engine_docker_exec_admission import admission
from tests_platform.test_engine_docker_proxy import EXEC_ID, Cancel, Clock

CLAIM = "sha256:" + "a" * 64
FENCE = "sha256:" + "b" * 64
RAW = "sha256:" + "c" * 64
CUSTODY_PLAN = policy_v2().custody_plan_digest
NETWORK_POLICY = policy_v2().network_policy_digest


class MockExecLifetimeOwner:
    """Contract fake only; this class does not establish installed supervision."""

    def __init__(self, fence: Any = None, connection: sqlite3.Connection | None = None) -> None:
        self.fence = fence
        self.connection = connection
        self.calls: list[tuple[bool, bool]] = []
        self.mutate: dict[str, Any] = {}
        self.generation = 1
        self.active = True
        self.invalid_response = False
        self.reply_type = VerifiedExecLifetimeCustodyV2

    def require_live(self, **kwargs: Any) -> VerifiedExecLifetimeCustodyV2:
        self.calls.append(
            (
                bool(self.fence and self.fence.held),
                bool(self.connection and self.connection.in_transaction),
            )
        )
        if not self.active:
            raise DockerExecDispatchError("mock supervisor lease is unavailable")
        if self.invalid_response:
            return None  # type: ignore[return-value]
        admitted = kwargs["admission"]
        proof = self.reply_type(
            admission_digest=admitted.admission_digest,
            attempt_id=admitted.profile.attempt_id,
            operation_id=admitted.request.operation_id,
            container_id=admitted.container_id,
            claim_ref=kwargs["claim_ref"],
            controller_fence=kwargs["controller_fence"],
            custody_plan_digest=kwargs["custody_plan_digest"],
            network_policy_digest=kwargs["network_policy_digest"],
            operation_deadline_monotonic_ns=kwargs["operation_deadline_monotonic_ns"],
            controller_instance_ref="sha256:" + "7" * 64,
            supervisor_instance_ref="sha256:" + "8" * 64,
            lease_ref="sha256:" + "9" * 64,
            lease_generation=self.generation,
        )
        # Simulate malformed/drifted protected replies without letting the
        # canonical value constructor hide the dispatch boundary validation.
        for field, value in self.mutate.items():
            object.__setattr__(proof, field, value)
        return proof


class Fence:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.active = True
        self.cleanup = True
        self.held = False

    @contextmanager
    def hold_current(self, *, claim_ref: str, controller_fence: str):
        with self.lock:
            if not self.active or claim_ref != CLAIM or controller_fence != FENCE:
                raise RuntimeError("controller fence was revoked")
            self.held = True
            try:
                yield
            finally:
                self.held = False

    @contextmanager
    def hold_cleanup(self, *, claim_ref: str, controller_fence: str):
        with self.lock:
            if not self.cleanup or claim_ref != CLAIM or controller_fence != FENCE:
                raise RuntimeError("cleanup fence was revoked")
            yield


class Claims:
    def __init__(self, fence: Fence) -> None:
        self.fence = fence
        self.current = True
        self.calls = 0

    def require_current(self, *, accepted: Any, binding: Any, delegation: Any) -> None:
        assert self.fence.held
        accepted.validate(accepted.job_id, binding, delegation)
        self.calls += 1
        if not self.current:
            raise RuntimeError("accepted claim no longer current")


def controller(admitted: DockerExecAdmissionV2):
    delegation = replace(
        _delegation(),
        attempt_id=admitted.profile.attempt_id,
        engine_revision=admitted.profile.source_revision,
    )
    binding = _binding(delegation)
    accepted = AcceptedPreparedEngineAttempt(
        job_id="job-" + "a" * 32,
        preparation_ref="sha256:" + "1" * 64,
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
        claim_ref=CLAIM,
        runtime_resolution_ref="sha256:" + "2" * 64,
    )
    fence = Fence()
    claims = Claims(fence)
    mapping = ProtectedDockerExecHandleMapV2(
        (
            ProtectedDockerExecHandleBindingV2(
                handle=admitted.request.handle,
                container_id=admitted.container_id,
                policy_digest=admitted.policy_digest,
                execution_identity_digest=admitted.execution_identity_digest,
                profile_digest=admitted.profile.profile_digest,
                claim_ref=CLAIM,
                controller_fence=FENCE,
            ),
        )
    )
    authority = ControllerExecDispatchAuthorityV2(
        accepted=accepted,
        binding=binding,
        delegation=delegation,
        accepted_jobs=claims,
        controller_fence=FENCE,
        fence=fence,
        protected_handles=mapping,
    )
    return authority, fence, claims, mapping


def journal(path: Path) -> tuple[SQLiteDockerExecOperationJournal, sqlite3.Connection]:
    connection = sqlite3.connect(path, check_same_thread=False)
    return SQLiteDockerExecOperationJournal(connection), connection


def runtime(path: Path, admitted: DockerExecAdmissionV2 | None = None):
    current = admitted or admission()
    authority, fence, claims, mapping = controller(current)
    store, connection = journal(path)
    clock, cancel = Clock(), Cancel()
    value = DockerExecDispatchRuntimeV2(
        authority=authority,
        journal=store,
        monotonic_ns=clock,
        continuous_custody=MockExecLifetimeOwner(fence, connection),
    )
    return value, store, connection, current, fence, claims, mapping, clock, cancel


def gate(
    value,
    admitted,
    cancel,
    *,
    operation="container_exec_create",
    exec_id=None,
    deadline=6_000_000_000,
    request_digest=RAW,
):
    return value.gate(
        admitted,
        operation=operation,
        request_digest=request_digest,
        deadline_monotonic_ns=deadline,
        cancellation=cancel,
        custody_plan_digest=CUSTODY_PLAN,
        network_policy_digest=NETWORK_POLICY,
        exec_id=exec_id,
    )


def row(store, admitted):
    return store.snapshot(
        attempt_id=admitted.profile.attempt_id, operation_id=admitted.request.operation_id
    )


def test_reservation_is_persistent_before_transport_and_unknown_create_never_replays(
    tmp_path: Path,
) -> None:
    path = tmp_path / "exec.sqlite"
    value, store, connection, admitted, *_rest, cancel = runtime(path)
    reserved = gate(value, admitted, cancel)
    assert reserved.operation_id == admitted.request.operation_id
    assert reserved.attempt_id == admitted.profile.attempt_id
    assert reserved.container_id == admitted.container_id
    assert reserved.policy_digest == admitted.policy_digest
    assert reserved.claim_ref == value.authority.claim_ref
    assert reserved.controller_fence == value.authority.controller_fence
    assert not reserved.entered and not reserved.sent
    snapshot = row(store, admitted)
    assert snapshot["phase"] == "reserved"
    assert snapshot["create_request_digest"] == RAW
    assert snapshot["admission_ref"] == admitted.admission_digest
    assert admitted.request.argv[-1] not in snapshot["admission_json"]
    connection.close()
    reconstructed, fresh_store, fresh_connection, *_ = runtime(path, admitted)
    with pytest.raises(DockerExecJournalError, match="already reserved"):
        gate(reconstructed, admitted, Cancel())
    assert row(fresh_store, admitted)["reservation_ref"] == reserved.reservation_ref
    fresh_connection.close()


def test_historical_reservation_reopens_without_regranting_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "exec.sqlite"
    value, store, connection, admitted, *_rest, cancel = runtime(path)
    create_digest = content_hash("create request")
    start_digest = content_hash("start request")
    inspect_digest = content_hash("inspect request")
    reserved = gate(value, admitted, cancel, request_digest=create_digest)
    value.record_created(admitted, EXEC_ID)
    gate(
        value,
        admitted,
        cancel,
        operation="exec_start",
        exec_id=EXEC_ID,
        request_digest=start_digest,
    )
    value.record_started(admitted)
    gate(
        value,
        admitted,
        cancel,
        operation="exec_inspect",
        exec_id=EXEC_ID,
        request_digest=inspect_digest,
    )
    value.record_complete(admitted)
    original = row(store, admitted)
    assert original is not None
    connection.close()

    monkeypatch.setattr(journal_module, "_CLOCK_EPOCH_REF", content_hash("new process epoch"))
    reopened_connection = sqlite3.connect(path, check_same_thread=False)
    reopened = SQLiteDockerExecOperationJournal(reopened_connection)
    historical = reopened.reopen_historical(
        attempt_id=admitted.profile.attempt_id,
        operation_id=admitted.request.operation_id,
    )
    assert historical is not None
    assert historical["reservation_ref"] == reserved.reservation_ref
    assert historical["admission_ref"] == admitted.admission_digest
    assert historical["phase"] == "complete"
    assert historical["request_digest_fields_present"] is True
    assert historical["create_request_digest"] == create_digest
    assert historical["start_request_digest"] == start_digest
    assert historical["inspect_request_digest"] == inspect_digest
    with pytest.raises(TypeError):
        historical["phase"] = "complete"  # type: ignore[index]
    with pytest.raises(DockerExecJournalError, match="clock epoch continuity"):
        reopened.snapshot(
            attempt_id=admitted.profile.attempt_id,
            operation_id=admitted.request.operation_id,
        )
    with pytest.raises(DockerExecJournalError, match="clock epoch continuity"):
        reopened.claim_dispatch(
            admission=admitted.to_dict(),
            operation="container_exec_create",
            request_digest=RAW,
            deadline_monotonic_ns=6_000_000_000,
            authority_ref=value.authority.authority_ref,
        )
    reopened_connection.close()


def test_legacy_completed_reservation_reopens_as_partial_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "exec.sqlite"
    value, _store, connection, admitted, *_rest, cancel = runtime(path)
    gate(value, admitted, cancel)
    value.record_created(admitted, EXEC_ID)
    gate(value, admitted, cancel, operation="exec_start", exec_id=EXEC_ID)
    value.record_started(admitted)
    gate(value, admitted, cancel, operation="exec_inspect", exec_id=EXEC_ID)
    value.record_complete(admitted)
    connection.close()
    with sqlite3.connect(path) as legacy:
        legacy.execute(
            "CREATE TABLE previous ("
            "attempt_id TEXT NOT NULL, operation_id TEXT NOT NULL, "
            "admission_ref TEXT NOT NULL, admission_json TEXT NOT NULL, "
            "authority_ref TEXT NOT NULL, create_request_digest TEXT NOT NULL, "
            "dispatch_request_digest TEXT NOT NULL, deadline_ns INTEGER NOT NULL, "
            "reservation_ref TEXT NOT NULL UNIQUE, phase TEXT NOT NULL, "
            "exec_id TEXT, clock_epoch_ref TEXT, PRIMARY KEY(attempt_id,operation_id))"
        )
        legacy.execute(
            "INSERT INTO previous SELECT attempt_id,operation_id,admission_ref,"
            "admission_json,authority_ref,create_request_digest,dispatch_request_digest,"
            "deadline_ns,reservation_ref,phase,exec_id,clock_epoch_ref "
            "FROM docker_exec_operations_v2"
        )
        legacy.execute("DROP TABLE docker_exec_operations_v2")
        legacy.execute("ALTER TABLE previous RENAME TO docker_exec_operations_v2")
    monkeypatch.setattr(journal_module, "_CLOCK_EPOCH_REF", content_hash("upgraded epoch"))
    reopened_connection = sqlite3.connect(path, check_same_thread=False)
    reopened = SQLiteDockerExecOperationJournal(reopened_connection)
    historical = reopened.reopen_historical(
        attempt_id=admitted.profile.attempt_id,
        operation_id=admitted.request.operation_id,
    )
    assert historical is not None
    assert historical["phase"] == "complete"
    assert historical["request_digest_fields_present"] is False
    assert historical["start_request_digest"] is None
    assert historical["inspect_request_digest"] is None
    with pytest.raises(DockerExecJournalError, match="clock epoch continuity"):
        reopened.snapshot(
            attempt_id=admitted.profile.attempt_id,
            operation_id=admitted.request.operation_id,
        )
    reopened_connection.close()


def test_target_activation_scope_serializes_stop_and_refuses_revoked_claim() -> None:
    admitted = admission()
    authority, fence, claims, _mapping = controller(admitted)
    entered = threading.Event()
    release = threading.Event()
    stopped = threading.Event()
    errors: list[BaseException] = []
    scope_ref = content_hash("owned target policy")

    def activate() -> None:
        try:
            with authority.target_activation_scope(
                attempt_id=admitted.profile.attempt_id,
                target_scope_admission_ref=scope_ref,
            ):
                entered.set()
                assert release.wait(2)
        except BaseException as exc:
            errors.append(exc)

    def stop() -> None:
        assert entered.wait(2)
        with fence.lock:
            fence.active = False
        stopped.set()

    sender = threading.Thread(target=activate)
    stopper = threading.Thread(target=stop)
    sender.start()
    stopper.start()
    assert entered.wait(2)
    assert stopped.wait(0.05) is False
    release.set()
    sender.join(2)
    stopper.join(2)
    assert errors == []
    assert stopped.is_set()
    assert claims.calls == 1
    with pytest.raises(RuntimeError, match="controller fence was revoked"):
        with authority.target_activation_scope(
            attempt_id=admitted.profile.attempt_id,
            target_scope_admission_ref=scope_ref,
        ):
            pytest.fail("revoked target activation was admitted")


def test_single_use_send_holds_live_fence_and_mapping_then_releases_before_attach_read(
    tmp_path: Path,
) -> None:
    value, store, connection, admitted, fence, claims, _mapping, _clock, cancel = runtime(
        tmp_path / "exec.sqlite"
    )
    reserved = gate(value, admitted, cancel)
    assert claims.calls == 0
    with reserved.before_send():
        assert fence.held
        assert reserved.entered and not reserved.sent
        assert row(store, admitted)["phase"] == "reserved"
    assert reserved.sent and not fence.held and claims.calls == 1
    assert reserved.request_digest == RAW
    assert reserved.admission_digest == admitted.admission_digest
    with pytest.raises(DockerExecDispatchError, match="reused"):
        with reserved.before_send():
            pytest.fail("second request must not be written")
    connection.close()


@pytest.mark.parametrize("failure", ["claim", "fence", "mapping", "cancel", "clock", "deadline"])
def test_send_time_drift_or_unknown_authority_consumes_and_quarantines_reservation(
    tmp_path: Path, failure: str
) -> None:
    value, store, connection, admitted, fence, claims, mapping, clock, cancel = runtime(
        tmp_path / "exec.sqlite"
    )
    reserved = gate(value, admitted, cancel)
    if failure == "claim":
        claims.current = False
    elif failure == "fence":
        fence.active = False
    elif failure == "mapping":
        mapping.revoke(admitted.request.handle)
    elif failure == "cancel":
        cancel.value = True
    elif failure == "clock":
        clock.value = -1
    else:
        clock.value = 6_000_000_000
    with pytest.raises((DockerExecDispatchError, RuntimeError)):
        with reserved.before_send():
            pytest.fail("drifted authority must not reach socket write")
    assert not reserved.sent
    assert row(store, admitted)["phase"] == "uncertain"
    with pytest.raises(DockerExecJournalError):
        gate(value, admitted, Cancel())
    connection.close()


def test_partial_socket_write_is_uncertain_and_never_retryable(tmp_path: Path) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    reserved = gate(value, admitted, cancel)
    with pytest.raises(OSError):
        with reserved.before_send():
            raise OSError("socket lost after possible partial write")
    assert reserved.entered and not reserved.sent
    assert row(store, admitted)["phase"] == "uncertain"
    connection.close()


def test_durable_create_start_inspect_phases_bind_exec_id_and_total_deadline(
    tmp_path: Path,
) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    created = gate(value, admitted, cancel)
    with created.before_send():
        pass
    value.record_created(admitted, EXEC_ID)
    with pytest.raises(DockerExecJournalError):
        gate(value, admitted, cancel, operation="exec_start", exec_id="f" * 64)
    with pytest.raises(DockerExecJournalError):
        gate(
            value, admitted, cancel, operation="exec_start", exec_id=EXEC_ID, deadline=7_000_000_000
        )
    started = gate(value, admitted, cancel, operation="exec_start", exec_id=EXEC_ID)
    assert row(store, admitted)["phase"] == "start_reserved"
    with pytest.raises(DockerExecJournalError):
        gate(value, admitted, cancel, operation="exec_start", exec_id=EXEC_ID)
    with started.before_send():
        pass
    value.record_started(admitted)
    inspected = gate(value, admitted, cancel, operation="exec_inspect", exec_id=EXEC_ID)
    with inspected.before_send():
        pass
    value.record_complete(admitted)
    assert row(store, admitted)["phase"] == "complete"
    with pytest.raises(DockerExecJournalError):
        gate(value, admitted, cancel, operation="exec_inspect", exec_id=EXEC_ID)
    connection.close()


def test_start_cannot_be_reissued_after_gate_or_runtime_reconstruction(tmp_path: Path) -> None:
    path = tmp_path / "exec.sqlite"
    value, store, connection, admitted, *_rest, cancel = runtime(path)
    gate(value, admitted, cancel)
    value.record_created(admitted, EXEC_ID)
    gate(value, admitted, cancel, operation="exec_start", exec_id=EXEC_ID)
    connection.close()
    reconstructed, _, connection2, *_ = runtime(path, admitted)
    with pytest.raises(DockerExecJournalError):
        gate(reconstructed, admitted, Cancel(), operation="exec_start", exec_id=EXEC_ID)
    connection2.close()


def test_unknown_create_blocks_fresh_operation_id_after_reconstruction(tmp_path: Path) -> None:
    path = tmp_path / "exec.sqlite"
    value, _store, connection, admitted, *_rest, cancel = runtime(path)
    gate(value, admitted, cancel)
    connection.close()
    different = admission(operation_id="operation-" + "d" * 32)
    reconstructed, _store2, connection2, *_ = runtime(path, different)
    with pytest.raises(DockerExecJournalError, match="unfinished"):
        gate(reconstructed, different, Cancel())
    connection2.close()


def test_two_connections_cannot_reserve_two_execs_for_same_attempt(tmp_path: Path) -> None:
    path = tmp_path / "exec.sqlite"
    first = runtime(path)
    second = runtime(path, admission(operation_id="operation-" + "e" * 32))
    gate(first[0], first[3], first[-1])
    with pytest.raises(DockerExecJournalError, match="unfinished"):
        gate(second[0], second[3], second[-1])
    first[2].close()
    second[2].close()


def test_concurrent_reservations_serialize_before_any_transport_entry(tmp_path: Path) -> None:
    path = tmp_path / "exec.sqlite"
    first = runtime(path)
    second = runtime(path, admission(operation_id="operation-" + "e" * 32))
    barrier = threading.Barrier(2)
    results: list[Any] = []

    def reserve(values):
        barrier.wait(timeout=5)
        try:
            results.append(gate(values[0], values[3], values[-1]))
        except DockerExecJournalError as exc:
            results.append(exc)

    workers = [threading.Thread(target=reserve, args=(values,)) for values in (first, second)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
        assert not worker.is_alive()
    assert sum(isinstance(result, DockerExecJournalError) for result in results) == 1
    assert all(
        not result.entered for result in results if not isinstance(result, DockerExecJournalError)
    )
    first[2].close()
    second[2].close()


def test_cancellation_thread_cannot_be_overwritten_by_late_attach_completion(
    tmp_path: Path,
) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    gate(value, admitted, cancel)
    value.record_created(admitted, EXEC_ID)
    gate(value, admitted, cancel, operation="exec_start", exec_id=EXEC_ID)
    cancelled = threading.Thread(target=value.mark_uncertain, args=(admitted,))
    cancelled.start()
    cancelled.join(timeout=5)
    assert not cancelled.is_alive()
    with pytest.raises(DockerExecJournalError, match="already consumed"):
        value.record_started(admitted)
    assert row(store, admitted)["phase"] == "uncertain"
    connection.close()


def test_cleanup_uses_owned_mapping_after_execution_revocation_without_current_claim_requirement(
    tmp_path: Path,
) -> None:
    value, _store, connection, admitted, fence, claims, _mapping, _clock, _cancel = runtime(
        tmp_path / "exec.sqlite"
    )
    fence.active = False
    claims.current = False
    with value.authority.cleanup_scope(admitted):
        pass
    assert claims.calls == 0
    fence.cleanup = False
    with pytest.raises(RuntimeError):
        with value.authority.cleanup_scope(admitted):
            pytest.fail("foreign cleanup fence must not reach custody")
    connection.close()


def test_equal_public_handle_with_different_opaque_capability_is_refused(tmp_path: Path) -> None:
    value, _store, connection, admitted, *_ = runtime(tmp_path / "exec.sqlite")
    cloned = replace(
        admitted,
        request=replace(
            admitted.request, handle=replace(admitted.request.handle, opaque_ref=object())
        ),
    )
    assert cloned.request.handle == admitted.request.handle
    with pytest.raises(DockerExecDispatchError, match="mapping differs"):
        with value.authority.cleanup_scope(cloned):
            pytest.fail("opaque capability must be controller retained")
    connection.close()


def test_changed_claim_or_fence_cannot_reopen_matching_public_operation(tmp_path: Path) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    gate(value, admitted, cancel)
    value.record_created(admitted, EXEC_ID)
    with pytest.raises(DockerExecJournalError):
        store.claim_dispatch(
            admission=admitted.to_dict(),
            operation="exec_start",
            request_digest=RAW,
            deadline_monotonic_ns=6_000_000_000,
            authority_ref="sha256:" + "e" * 64,
            exec_id=EXEC_ID,
        )
    connection.close()


def test_no_memory_journal_or_default_runtime_authority() -> None:
    memory = sqlite3.connect(":memory:")
    with pytest.raises(DockerExecJournalError, match="persistent"):
        SQLiteDockerExecOperationJournal(memory)
    memory.close()
    with pytest.raises(TypeError):
        DockerExecDispatchRuntimeV2()  # type: ignore[call-arg]


def test_journal_requires_atomic_disk_journaling_and_extra_synchronous_commit(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(tmp_path / "exec.sqlite")
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    SQLiteDockerExecOperationJournal(connection)
    assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    assert connection.execute("PRAGMA synchronous").fetchone()[0] == 3
    connection.close()


def test_journal_refuses_backend_that_cannot_enable_extra_synchronous_commit(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(tmp_path / "exec.sqlite")
    connection.execute("PRAGMA synchronous=FULL")

    def ignore_extra(action, argument1, argument2, _database, _source):
        if (
            action == sqlite3.SQLITE_PRAGMA
            and argument1 == "synchronous"
            and str(argument2).upper() == "EXTRA"
        ):
            return sqlite3.SQLITE_IGNORE
        return sqlite3.SQLITE_OK

    connection.set_authorizer(ignore_extra)
    with pytest.raises(DockerExecJournalError, match="durability is unavailable"):
        SQLiteDockerExecOperationJournal(connection)
    assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
    assert (
        connection.execute(
            "SELECT name FROM sqlite_master WHERE name='docker_exec_operations_v2'"
        ).fetchone()
        is None
    )
    connection.close()


def test_cancel_after_write_prevents_successful_send_receipt(tmp_path: Path) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    reserved = gate(value, admitted, cancel)
    with pytest.raises(DockerExecDispatchError):
        with reserved.before_send():
            cancel.value = True
    assert not reserved.sent and row(store, admitted)["phase"] == "uncertain"
    connection.close()


def test_issued_gate_cannot_send_after_durable_quarantine_without_token_change(
    tmp_path: Path,
) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    reserved = gate(value, admitted, cancel)
    value.mark_uncertain(admitted)
    assert cancel.is_cancelled() is False
    with pytest.raises(DockerExecJournalError, match="revoked or changed"):
        with reserved.before_send():
            pytest.fail("durable quarantine must win over an issued gate")
    assert not reserved.sent and row(store, admitted)["phase"] == "uncertain"
    connection.close()


def test_short_create_route_deadline_does_not_shorten_total_exec_reservation(
    tmp_path: Path,
) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(
        tmp_path / "exec.sqlite", admission(timeout=120.0)
    )
    created = value.gate(
        admitted,
        operation="container_exec_create",
        request_digest=RAW,
        deadline_monotonic_ns=11_000_000_000,
        operation_deadline_monotonic_ns=121_000_000_000,
        cancellation=cancel,
        custody_plan_digest=CUSTODY_PLAN,
        network_policy_digest=NETWORK_POLICY,
    )
    with created.before_send():
        pass
    assert row(store, admitted)["deadline_ns"] == 121_000_000_000
    value.record_created(admitted, EXEC_ID)
    started = value.gate(
        admitted,
        operation="exec_start",
        request_digest=RAW,
        deadline_monotonic_ns=121_000_000_000,
        operation_deadline_monotonic_ns=121_000_000_000,
        cancellation=cancel,
        custody_plan_digest=CUSTODY_PLAN,
        network_policy_digest=NETWORK_POLICY,
        exec_id=EXEC_ID,
    )
    with started.before_send():
        pass
    assert started.sent
    connection.close()


def test_execution_mapping_revocation_preserves_exact_cleanup_custody(tmp_path: Path) -> None:
    value, _store, connection, admitted, _fence, _claims, mapping, _clock, _cancel = runtime(
        tmp_path / "exec.sqlite"
    )
    mapping.revoke(admitted.request.handle)
    with pytest.raises(DockerExecDispatchError, match="revoked"):
        with value.authority.execution_scope(admitted):
            pytest.fail("revoked mapping must refuse execution")
    with value.authority.cleanup_scope(admitted):
        pass
    connection.close()


@pytest.mark.parametrize(
    "phase", ["reserved", "created", "start_reserved", "started", "inspect_reserved"]
)
def test_new_controller_clock_epoch_cannot_resume_prior_monotonic_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    path = tmp_path / "exec.sqlite"
    value, store, connection, admitted, *_rest, cancel = runtime(path)
    gate(value, admitted, cancel)
    if phase != "reserved":
        value.record_created(admitted, EXEC_ID)
    if phase in {"start_reserved", "started", "inspect_reserved"}:
        gate(value, admitted, cancel, operation="exec_start", exec_id=EXEC_ID)
    if phase in {"started", "inspect_reserved"}:
        value.record_started(admitted)
    if phase == "inspect_reserved":
        gate(value, admitted, cancel, operation="exec_inspect", exec_id=EXEC_ID)
    old = row(store, admitted)
    connection.close()

    # Simulate a new process incarnation using the actual private fork hook.
    # There is no worker/caller epoch argument in the journal or runtime API.
    monkeypatch.setattr(journal_module, "_CLOCK_EPOCH_REF", journal_module._CLOCK_EPOCH_REF)
    journal_module._after_fork_child()
    reconstructed, fresh_store, fresh_connection, *_ = runtime(path, admitted)
    assert fresh_store._clock_epoch_ref != old["clock_epoch_ref"]
    operation = "exec_inspect" if phase in {"started", "inspect_reserved"} else "exec_start"
    with pytest.raises(DockerExecJournalError, match="epoch continuity"):
        gate(reconstructed, admitted, Cancel(), operation=operation, exec_id=EXEC_ID)
    with pytest.raises(DockerExecJournalError, match="epoch continuity"):
        row(fresh_store, admitted)
    with pytest.raises(DockerExecJournalError, match="epoch continuity"):
        reconstructed.mark_uncertain(admitted)
    with pytest.raises(DockerExecJournalError, match="unfinished"):
        gate(reconstructed, admission(operation_id="operation-" + "f" * 32), Cancel())
    with pytest.raises(DockerExecJournalError, match="epoch continuity"):
        with fresh_store.hold_send(
            admission=admitted.to_dict(),
            operation=operation,
            request_digest=RAW,
            authority_ref=reconstructed.authority.authority_ref,
            reservation_ref=old["reservation_ref"],
        ):
            pytest.fail("a prior clock epoch must never reach socket write")
    assert (
        fresh_connection.execute("SELECT phase FROM docker_exec_operations_v2").fetchone()[0]
        == phase
    )
    fresh_connection.close()


def test_issued_gate_and_existing_instance_refuse_clock_epoch_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    reserved = gate(value, admitted, cancel)
    old_epoch = store._clock_epoch_ref
    monkeypatch.setattr(journal_module, "_CLOCK_EPOCH_REF", journal_module._CLOCK_EPOCH_REF)
    journal_module._after_fork_child()
    assert store._clock_epoch_ref == old_epoch
    with pytest.raises(DockerExecJournalError, match="epoch continuity"):
        with reserved.before_send():
            pytest.fail("an inherited journal/gate must fail closed")
    assert not reserved.sent
    connection.close()


def test_completed_operation_history_remains_spent_after_clock_epoch_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "exec.sqlite"
    value, _store, connection, admitted, *_rest, cancel = runtime(path)
    gate(value, admitted, cancel)
    value.record_created(admitted, EXEC_ID)
    gate(value, admitted, cancel, operation="exec_start", exec_id=EXEC_ID)
    value.record_started(admitted)
    gate(value, admitted, cancel, operation="exec_inspect", exec_id=EXEC_ID)
    value.record_complete(admitted)
    connection.close()
    monkeypatch.setattr(journal_module, "_CLOCK_EPOCH_REF", journal_module._CLOCK_EPOCH_REF)
    journal_module._after_fork_child()
    reconstructed, _fresh_store, fresh_connection, *_ = runtime(path, admitted)
    with pytest.raises(DockerExecJournalError, match="epoch continuity"):
        gate(reconstructed, admitted, Cancel())
    assert (
        fresh_connection.execute("SELECT phase FROM docker_exec_operations_v2").fetchone()[0]
        == "complete"
    )
    different = admission(operation_id="operation-" + "f" * 32)
    gate(reconstructed, different, Cancel())
    assert (
        fresh_connection.execute("SELECT COUNT(*) FROM docker_exec_operations_v2").fetchone()[0]
        == 2
    )
    fresh_connection.close()


def test_legacy_schema_missing_clock_epoch_migrates_without_restoring_dispatch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "exec.sqlite"
    value, store, connection, admitted, *_rest, cancel = runtime(path)
    gate(value, admitted, cancel)
    value.record_created(admitted, EXEC_ID)
    saved = row(store, admitted)
    connection.execute("DROP TABLE docker_exec_operations_v2")
    connection.execute("""CREATE TABLE docker_exec_operations_v2 (
        attempt_id TEXT NOT NULL, operation_id TEXT NOT NULL,
        admission_ref TEXT NOT NULL, admission_json TEXT NOT NULL,
        authority_ref TEXT NOT NULL, create_request_digest TEXT NOT NULL,
        dispatch_request_digest TEXT NOT NULL, deadline_ns INTEGER NOT NULL,
        reservation_ref TEXT NOT NULL UNIQUE, phase TEXT NOT NULL,
        exec_id TEXT, PRIMARY KEY(attempt_id, operation_id))""")
    connection.execute(
        "INSERT INTO docker_exec_operations_v2 VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        tuple(
            saved[field]
            for field in (
                "attempt_id",
                "operation_id",
                "admission_ref",
                "admission_json",
                "authority_ref",
                "create_request_digest",
                "dispatch_request_digest",
                "deadline_ns",
                "reservation_ref",
                "phase",
                "exec_id",
            )
        ),
    )
    connection.commit()
    connection.close()
    reconstructed, _fresh_store, fresh_connection, *_ = runtime(path, admitted)
    assert (
        fresh_connection.execute(
            "SELECT clock_epoch_ref FROM docker_exec_operations_v2"
        ).fetchone()[0]
        is None
    )
    with pytest.raises(DockerExecJournalError, match="epoch continuity"):
        gate(reconstructed, admitted, Cancel(), operation="exec_start", exec_id=EXEC_ID)
    assert (
        fresh_connection.execute("SELECT phase FROM docker_exec_operations_v2").fetchone()[0]
        == "created"
    )
    fresh_connection.close()


@pytest.mark.parametrize("held_lock", ["gate", "mapping"])
def test_foreign_process_gate_refuses_before_inherited_locks_hooks_or_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    held_lock: str,
) -> None:
    value, store, connection, admitted, _fence, _claims, mapping, _clock, cancel = runtime(
        tmp_path / "exec.sqlite"
    )
    reserved = gate(value, admitted, cancel)
    actual_pid = reserved._creator_pid
    called: list[str] = []

    def forbidden(*_args, **_kwargs):
        called.append("inherited capability")
        raise AssertionError("foreign gate must not touch authority or SQLite")

    monkeypatch.setattr(value.authority, "execution_scope", forbidden)
    monkeypatch.setattr(store, "hold_send", forbidden)
    monkeypatch.setattr(store, "transition", forbidden)
    monkeypatch.setattr(dispatch_module.os, "getpid", lambda: actual_pid + 1)
    inherited_lock = reserved._lock if held_lock == "gate" else mapping._lock
    finished = threading.Event()
    errors: list[BaseException] = []

    def enter_foreign_gate():
        try:
            with reserved.before_send():
                pytest.fail("foreign process must not reach socket write")
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    inherited_lock.acquire()
    worker = threading.Thread(target=enter_foreign_gate, daemon=True)
    try:
        worker.start()
        refused_while_locked = finished.wait(timeout=1)
    finally:
        inherited_lock.release()
    worker.join(timeout=2)
    assert refused_while_locked and not worker.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], DockerExecDispatchError)
    assert "another process" in str(errors[0])
    assert not called and not reserved.entered and not reserved.sent
    connection.close()


def test_missing_continuous_owner_refuses_before_any_durable_reservation(tmp_path: Path) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    missing = DockerExecDispatchRuntimeV2(
        authority=value.authority,
        journal=store,
        monotonic_ns=value._clock,
    )
    with pytest.raises(DockerExecCustodyUnavailable, match="lifetime custody is unavailable"):
        gate(missing, admitted, cancel)
    assert row(store, admitted) is None
    connection.close()


@pytest.mark.parametrize("field", ["continuous_custody", "authority", "journal"])
def test_dispatch_runtime_provider_wiring_cannot_be_replaced(tmp_path: Path, field: str) -> None:
    value, store, connection, admitted, *_ = runtime(tmp_path / "exec.sqlite")
    original = getattr(value, field)
    with pytest.raises(AttributeError):
        setattr(value, field, object())
    assert getattr(value, field) is original and row(store, admitted) is None
    connection.close()


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("admission_digest", "sha256:" + "0" * 64),
        ("attempt_id", "engine-attempt-" + "0" * 32),
        ("operation_id", "operation-" + "0" * 32),
        ("container_id", "0" * 64),
        ("claim_ref", "sha256:" + "0" * 64),
        ("controller_fence", "sha256:" + "0" * 64),
        ("custody_plan_digest", "sha256:" + "0" * 64),
        ("network_policy_digest", "sha256:" + "0" * 64),
        ("operation_deadline_monotonic_ns", 6_000_000_001),
        ("operation_deadline_monotonic_ns", True),
        ("lease_generation", True),
        ("lease_generation", 0),
        ("lease_generation", 1.0),
        ("controller_instance_ref", "invalid"),
        ("supervisor_instance_ref", "invalid"),
        ("lease_ref", "invalid"),
        ("deadline_stop_enforced", False),
        ("deadline_stop_enforced", 1),
        ("controller_loss_stop_enforced", False),
    ],
)
def test_lifetime_custody_proof_drift_or_malformed_enforcement_never_reserves(
    tmp_path: Path,
    field: str,
    bad_value: Any,
) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    value.continuous_custody.mutate[field] = bad_value
    with pytest.raises(DockerExecCustodyUnavailable, match="lifetime custody"):
        gate(value, admitted, cancel)
    assert row(store, admitted) is None
    connection.close()


def test_lifetime_custody_requires_exact_canonical_reply_type(tmp_path: Path) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    value.continuous_custody.invalid_response = True
    with pytest.raises(DockerExecCustodyUnavailable, match="proof is unavailable"):
        gate(value, admitted, cancel)
    assert row(store, admitted) is None
    connection.close()


def test_lifetime_custody_rejects_subclassed_canonical_reply(tmp_path: Path) -> None:
    class DerivedProof(VerifiedExecLifetimeCustodyV2):
        pass

    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    value.continuous_custody.reply_type = DerivedProof
    with pytest.raises(DockerExecCustodyUnavailable, match="proof is unavailable"):
        gate(value, admitted, cancel)
    assert row(store, admitted) is None
    connection.close()


def test_lifetime_owner_is_checked_before_reservation_and_again_under_real_send_scope(
    tmp_path: Path,
) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    owner = value.continuous_custody
    reserved = gate(value, admitted, cancel)
    assert owner.calls == [(False, False)]
    owner.generation = 2  # Authenticated heartbeat may advance the same lease.
    with reserved.before_send():
        assert owner.calls == [(False, False), (True, True)]
        assert row(store, admitted)["phase"] == "reserved"
    assert reserved.sent and owner.active
    connection.close()


def test_continuous_custody_provider_failure_is_typed_and_sanitized_before_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")

    def fail(**_kwargs: Any):
        raise RuntimeError("private backend failure detail")

    monkeypatch.setattr(value.continuous_custody, "require_live", fail)
    with pytest.raises(DockerExecCustodyUnavailable, match="source is unavailable") as caught:
        gate(value, admitted, cancel)
    assert "private backend failure detail" not in str(caught.value)
    assert row(store, admitted) is None
    connection.close()


@pytest.mark.parametrize(
    "change",
    [
        "container_id",
        "controller_instance_ref",
        "supervisor_instance_ref",
        "lease_ref",
        "generation_rollback",
        "lost_owner",
    ],
)
def test_lifetime_lease_rechecked_at_send_refuses_drift_and_keeps_uncertain_custody(
    tmp_path: Path,
    change: str,
) -> None:
    value, store, connection, admitted, *_rest, cancel = runtime(tmp_path / "exec.sqlite")
    owner = value.continuous_custody
    owner.generation = 2
    reserved = gate(value, admitted, cancel)
    if change == "generation_rollback":
        owner.generation = 1
    elif change == "lost_owner":
        owner.active = False
    else:
        owner.mutate[change] = "0" * 64 if change == "container_id" else "sha256:" + "0" * 64
    with pytest.raises(DockerExecDispatchError):
        with reserved.before_send():
            pytest.fail("unverified lifetime custody must never reach request write")
    assert not reserved.sent and row(store, admitted)["phase"] == "uncertain"
    connection.close()
