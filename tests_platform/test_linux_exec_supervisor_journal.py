from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from bluefire.linux_exec_supervisor_journal import (
    ExecSupervisorJournalIdentityV2,
    LinuxExecSupervisorJournalError,
    SQLiteLinuxExecSupervisorJournalV2,
)
from bluefire.util import content_hash


def _digest(label: str) -> str:
    return content_hash(label)


def _identity(*, label: str = "one") -> ExecSupervisorJournalIdentityV2:
    return ExecSupervisorJournalIdentityV2(
        binding_ref=_digest("binding " + label),
        attempt_id="engine-attempt-" + "1" * 32,
        claim_ref=_digest("claim"),
        controller_fence=_digest("fence"),
        custody_plan_digest=_digest("custody"),
        network_policy_digest=_digest("network"),
        controller_instance_ref=_digest("controller"),
        daemon_instance_digest=_digest("daemon " + label),
        docker_endpoint_ref=_digest("Docker endpoint " + label),
        supervisor_instance_ref=_digest("supervisor " + label),
        supervisor_session_ref=_digest("session " + label),
        clock_epoch_ref=_digest("clock " + label),
        supervisor_qualification_ref=_digest("qualification " + label),
    )


def _operation(index: int = 1, *, generation: int = 1):
    operation_id = f"operation-{index:032x}"
    request = {
        "schema_version": "bluefire.exec-lifetime-operation-request.v2",
        "admission_digest": _digest(f"admission {index}"),
        "attempt_id": "engine-attempt-" + "1" * 32,
        "operation_id": operation_id,
        "container_id": f"{index:064x}",
        "claim_ref": _digest("claim"),
        "controller_fence": _digest("fence"),
        "custody_plan_digest": _digest("custody"),
        "network_policy_digest": _digest("network"),
        "operation_deadline_monotonic_ns": 50_000_000_000 + index,
        "controller_instance_ref": _digest("controller"),
        "supervisor_instance_ref": _digest("supervisor one"),
    }
    request_ref = content_hash(request)
    proof = {
        "schema_version": "bluefire.verified-exec-lifetime-custody.v2",
        **{key: value for key, value in request.items() if key != "schema_version"},
        "lease_ref": _digest(f"lease {index}"),
        "lease_generation": generation,
        "deadline_stop_enforced": True,
        "controller_loss_stop_enforced": True,
    }
    proof_ref = content_hash(proof)
    return operation_id, request_ref, request, proof_ref, proof


def _receipt(request_ref: str, proof: dict, index: int = 1):
    receipt = {
        "schema_version": "bluefire.exec-lifetime-terminal-receipt.v2",
        "request_ref": request_ref,
        "lease_ref": proof["lease_ref"],
        "lease_generation": proof["lease_generation"],
        "outcome": "verified_absent",
        "completion_qualification_ref": None,
        "final_inventory_digest": _digest(f"inventory {index}"),
        "clock_epoch_ref": _digest("clock one"),
        "observed_monotonic_ns": 100 + index,
        "background_work_absent": True,
        "container_absent": True,
    }
    return content_hash(receipt), receipt


def _record_active(journal: SQLiteLinuxExecSupervisorJournalV2, index: int = 1):
    operation_id, request_ref, request, proof_ref, proof = _operation(index)
    record = journal.record_active(
        operation_id=operation_id,
        request_ref=request_ref,
        request=request,
        proof_ref=proof_ref,
        proof=proof,
    )
    return record, request, proof


def test_active_cleanup_terminal_and_explicit_ack_survive_two_reopens(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    journal = SQLiteLinuxExecSupervisorJournalV2.create(directory, _identity())
    active, request, proof = _record_active(journal)
    assert active.phase == "active"

    proof = {**proof, "lease_generation": 2}
    proof_ref = content_hash(proof)
    updated = journal.update_live_proof(
        operation_id=active.operation_id,
        request_ref=active.request_ref,
        proof_ref=proof_ref,
        proof=proof,
    )
    assert updated.proof["lease_generation"] == 2
    pending = journal.mark_cleanup_pending(
        operation_id=active.operation_id,
        request_ref=active.request_ref,
        reason="controller_loss",
    )
    assert pending.phase == "cleanup_pending"
    receipt_ref, receipt = _receipt(active.request_ref, proof)
    event = journal.record_terminal(
        operation_id=active.operation_id,
        request_ref=active.request_ref,
        reason="controller_loss",
        receipt_ref=receipt_ref,
        receipt=receipt,
    )
    assert event.cursor == 1
    journal.close()

    reopened = SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())
    assert reopened.operations(phases=("active", "cleanup_pending")) == ()
    assert reopened.pending_terminal_events() == (event,)
    reopened.close()

    reopened_again = SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())
    assert reopened_again.pending_terminal_events() == (event,)
    reopened_again.acknowledge_terminal(cursor=event.cursor, receipt_ref=event.receipt_ref)
    assert reopened_again.pending_terminal_events() == ()
    # A lost acknowledgement can be replayed exactly.
    reopened_again.acknowledge_terminal(cursor=event.cursor, receipt_ref=event.receipt_ref)
    reopened_again.close()

    final = SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())
    assert final.pending_terminal_events() == ()
    terminal = final.operations(phases=("terminal",))[0]
    assert terminal.terminal_receipt_ref == receipt_ref
    final.close()


def test_rpc_pending_and_response_replay_survive_restart(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    journal = SQLiteLinuxExecSupervisorJournalV2.create(directory, _identity())
    request_digest = _digest("RPC request")
    assert (journal.last_rpc_cursor, journal.pending_rpc) == (0, None)
    assert journal.reserve_rpc(1, request_digest).disposition == "new"
    assert journal.last_rpc_cursor == 1
    assert journal.pending_rpc == (1, request_digest)
    journal.close()

    reopened = SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())
    pending = reopened.reserve_rpc(1, request_digest)
    assert pending.disposition == "pending"
    assert pending.response is None
    assert reopened.complete_rpc(1, request_digest, b'{"ok":true}') == b'{"ok":true}'
    assert reopened.pending_rpc is None
    reopened.close()

    replayed = SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())
    replay = replayed.reserve_rpc(1, request_digest)
    assert (replay.disposition, replay.response) == ("replay", b'{"ok":true}')
    assert replayed.complete_rpc(1, request_digest, b'{"ok":true}') == b'{"ok":true}'
    with pytest.raises(LinuxExecSupervisorJournalError, match="replayed differently"):
        replayed.reserve_rpc(1, _digest("different request"))
    replayed.acknowledge_rpc(1)
    assert replayed.reserve_rpc(2, _digest("second request")).disposition == "new"
    replayed.close()


def test_rpc_ack_compacts_without_losing_monotonic_sequence(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    journal = SQLiteLinuxExecSupervisorJournalV2.create(directory, _identity())
    for cursor in range(1, 141):
        request = _digest(f"RPC {cursor}")
        assert journal.reserve_rpc(cursor, request).disposition == "new"
        journal.complete_rpc(cursor, request, f"response:{cursor}".encode())
        journal.acknowledge_rpc(cursor)
    assert journal.last_rpc_cursor == 140
    journal.close()
    reopened = SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())
    replay = reopened.reserve_rpc(140, _digest("RPC 140"))
    assert replay.response == b"response:140"
    assert reopened.reserve_rpc(141, _digest("RPC 141")).disposition == "new"
    reopened.close()


def test_terminal_ack_requires_exact_next_cursor_and_receipt(tmp_path: Path) -> None:
    journal = SQLiteLinuxExecSupervisorJournalV2.create(tmp_path / "journal", _identity())
    events = []
    for index in (1, 2):
        active, _request, proof = _record_active(journal, index)
        receipt_ref, receipt = _receipt(active.request_ref, proof, index)
        journal.mark_cleanup_pending(
            operation_id=active.operation_id,
            request_ref=active.request_ref,
            reason="deadline_elapsed",
        )
        events.append(
            journal.record_terminal(
                operation_id=active.operation_id,
                request_ref=active.request_ref,
                reason="deadline_elapsed",
                receipt_ref=receipt_ref,
                receipt=receipt,
            )
        )
    with pytest.raises(LinuxExecSupervisorJournalError, match="acknowledgement changed"):
        journal.acknowledge_terminal(cursor=1, receipt_ref=_digest("wrong"))
    with pytest.raises(LinuxExecSupervisorJournalError, match="not current"):
        journal.acknowledge_terminal(cursor=2, receipt_ref=events[1].receipt_ref)
    journal.acknowledge_terminal(cursor=1, receipt_ref=events[0].receipt_ref)
    assert journal.pending_terminal_events() == (events[1],)
    with pytest.raises(LinuxExecSupervisorJournalError, match="acknowledgement changed"):
        journal.acknowledge_terminal(cursor=1, receipt_ref=events[1].receipt_ref)
    with pytest.raises(LinuxExecSupervisorJournalError, match="cleanup reason changed"):
        journal.mark_cleanup_pending(
            operation_id=f"operation-{1:032x}",
            request_ref=events[0].request_ref,
            reason="controller_loss",
        )
    journal.close()


def test_identity_drift_and_persistent_tamper_fail_closed(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    journal = SQLiteLinuxExecSupervisorJournalV2.create(directory, _identity())
    journal.close()
    with pytest.raises(LinuxExecSupervisorJournalError, match="identity changed"):
        SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity(label="two"))

    path = directory / "exec-supervisor-v2.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE supervisor_meta_v2 SET identity_ref=? WHERE singleton=1", (_digest("tamper"),)
    )
    connection.commit()
    connection.close()
    with pytest.raises(LinuxExecSupervisorJournalError, match="identity changed"):
        SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())


def test_terminal_ack_watermark_tamper_cannot_hide_pending_evidence(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    journal = SQLiteLinuxExecSupervisorJournalV2.create(directory, _identity())
    active, _request, proof = _record_active(journal)
    journal.mark_cleanup_pending(
        operation_id=active.operation_id,
        request_ref=active.request_ref,
        reason="controller_loss",
    )
    receipt_ref, receipt = _receipt(active.request_ref, proof)
    journal.record_terminal(
        operation_id=active.operation_id,
        request_ref=active.request_ref,
        reason="controller_loss",
        receipt_ref=receipt_ref,
        receipt=receipt,
    )
    journal.close()
    connection = sqlite3.connect(directory / "exec-supervisor-v2.sqlite3")
    connection.execute("UPDATE supervisor_meta_v2 SET acked_terminal_cursor=1 WHERE singleton=1")
    connection.commit()
    connection.close()
    with pytest.raises(LinuxExecSupervisorJournalError, match="acknowledgement state changed"):
        SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())


def test_second_process_cannot_open_same_journal(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    first = SQLiteLinuxExecSupervisorJournalV2.create(directory, _identity())
    with pytest.raises(LinuxExecSupervisorJournalError, match="another exec supervisor owns"):
        SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())
    first.close()
    second = SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())
    second.close()


def test_failed_reopen_releases_process_lock(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    directory.mkdir()
    with pytest.raises(LinuxExecSupervisorJournalError, match="does not exist"):
        SQLiteLinuxExecSupervisorJournalV2.reopen(directory, _identity())
    created = SQLiteLinuxExecSupervisorJournalV2.create(directory, _identity())
    created.close()


def test_binding_and_proof_regression_are_rejected(tmp_path: Path) -> None:
    journal = SQLiteLinuxExecSupervisorJournalV2.create(tmp_path / "journal", _identity())
    active, _request, proof = _record_active(journal)
    changed = {**proof, "container_id": "f" * 64, "lease_generation": 2}
    with pytest.raises(LinuxExecSupervisorJournalError, match="binding changed"):
        journal.update_live_proof(
            operation_id=active.operation_id,
            request_ref=active.request_ref,
            proof_ref=content_hash(changed),
            proof=changed,
        )
    regressed = {**proof, "lease_generation": 0}
    with pytest.raises(LinuxExecSupervisorJournalError, match="generation is invalid"):
        journal.update_live_proof(
            operation_id=active.operation_id,
            request_ref=active.request_ref,
            proof_ref=content_hash(regressed),
            proof=regressed,
        )
    weakened = {**proof, "lease_generation": 2, "deadline_stop_enforced": False}
    with pytest.raises(LinuxExecSupervisorJournalError, match="binding changed"):
        journal.update_live_proof(
            operation_id=active.operation_id,
            request_ref=active.request_ref,
            proof_ref=content_hash(weakened),
            proof=weakened,
        )
    journal.close()


def test_terminal_evidence_requires_precommitted_cleanup_intent(tmp_path: Path) -> None:
    journal = SQLiteLinuxExecSupervisorJournalV2.create(tmp_path / "journal", _identity())
    active, _request, proof = _record_active(journal)
    receipt_ref, receipt = _receipt(active.request_ref, proof)
    with pytest.raises(LinuxExecSupervisorJournalError, match="cleanup was not retained"):
        journal.record_terminal(
            operation_id=active.operation_id,
            request_ref=active.request_ref,
            reason="controller_loss",
            receipt_ref=receipt_ref,
            receipt=receipt,
        )
    assert journal.operations(phases=("active",))[0].operation_id == active.operation_id
    journal.close()


def test_payload_and_operation_bounds_are_enforced(tmp_path: Path) -> None:
    journal = SQLiteLinuxExecSupervisorJournalV2.create(tmp_path / "journal", _identity())
    with pytest.raises(LinuxExecSupervisorJournalError, match="response exceeds"):
        journal.complete_rpc(1, _digest("not reserved"), b"x" * 8193)
    operation_id, request_ref, request, proof_ref, proof = _operation()
    request = {**request, "oversized": "x" * (12 * 1024)}
    with pytest.raises(LinuxExecSupervisorJournalError, match="exceeds its bound"):
        journal.record_active(
            operation_id=operation_id,
            request_ref=request_ref,
            request=request,
            proof_ref=proof_ref,
            proof=proof,
        )
    for index in range(1, 129):
        _record_active(journal, index)
    operation_id, request_ref, request, proof_ref, proof = _operation(129)
    with pytest.raises(LinuxExecSupervisorJournalError, match="journal is full"):
        journal.record_active(
            operation_id=operation_id,
            request_ref=request_ref,
            request=request,
            proof_ref=proof_ref,
            proof=proof,
        )
    assert journal.path.stat().st_size <= 8 * 1024 * 1024
    journal.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-mode enforcement")
def test_world_accessible_or_symlinked_directory_is_rejected(tmp_path: Path) -> None:
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    os.chmod(public, 0o755)
    with pytest.raises(LinuxExecSupervisorJournalError, match="not private"):
        SQLiteLinuxExecSupervisorJournalV2.create(public, _identity())
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(private, target_is_directory=True)
    with pytest.raises(LinuxExecSupervisorJournalError, match="not private"):
        SQLiteLinuxExecSupervisorJournalV2.create(link, _identity())
