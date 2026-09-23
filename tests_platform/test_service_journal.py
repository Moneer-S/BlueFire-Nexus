"""Durable intent metadata cannot silently repeat an interrupted service effect."""

import json
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from bluefire.contracts import ContractError
from bluefire.tool_adapters.service_journal import ServiceIntentJournal
from bluefire.tool_adapters.service_lifecycle import OwnedUserService
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_service_lifecycle as lifecycle

identity = lifecycle.identity
identity_data = lifecycle.identity_data

SETUP = ("create_unit", "reload", "enable", "start")
CLEANUP = ("stop", "disable", "remove_links", "remove_unit", "reload_after_cleanup")


def finish(journal, row, operation, result="succeeded"):
    pending = journal.begin(row["identity_digest"], operation, row["revision"])
    return journal.finish(
        row["identity_digest"],
        pending["operations"][-1]["operation_id"],
        result,
        pending["revision"],
    )


@pytest.fixture(autouse=True)
def private_test_parent(tmp_path):
    if os.name == "nt":
        from bluefire.windows_owner_acl import apply_owner_private_acl_path

        apply_owner_private_acl_path(tmp_path, directory=True)
    else:
        tmp_path.chmod(0o700)


@pytest.fixture
def reserved(tmp_path, identity):
    path = tmp_path / "service-intents.sqlite3"
    journal = ServiceIntentJournal(path)
    return path, journal, journal.reserve(identity, "request-1")


def test_reservation_reopens_without_granting_execution_or_verified_absence(reserved, identity):
    path, journal, row = reserved
    assert row["revision"] == 0 and row["operations"] == []
    assert row["recovery_state"] == "cleanup_required"
    assert ServiceIntentJournal(path).get(identity.digest) == row
    assert journal.reserve(identity, "request-1") == row
    row["identity"]["owner_uid"] = 0
    assert journal.get(identity.digest)["identity"]["owner_uid"] == 1000


@pytest.mark.parametrize("stage", range(len(SETUP + CLEANUP)))
def test_crash_after_each_intent_preserves_pending_effect_and_forbids_replay(reserved, stage):
    path, journal, row = reserved
    operations = SETUP + CLEANUP
    for operation in operations[:stage]:
        row = finish(journal, row, operation)
    pending = journal.begin(row["identity_digest"], operations[stage], row["revision"])
    reopened = ServiceIntentJournal(path)
    retained = reopened.get(row["identity_digest"])
    assert retained == pending and retained["recovery_state"] == "inspection_required"
    for forbidden in {operations[stage], "start", "stop"}:
        with pytest.raises(ContractError):
            reopened.begin(row["identity_digest"], forbidden, retained["revision"])
    assert reopened.get(row["identity_digest"]) == retained
    # A coordinator may record an inspected unknown result; this never dispatches work.
    unknown = reopened.finish(
        row["identity_digest"],
        retained["operations"][-1]["operation_id"],
        "unknown",
        retained["revision"],
    )
    assert unknown["operations"][-1]["result"] == "unknown"
    assert unknown["recovery_state"] == "cleanup_required"


@pytest.mark.parametrize("stage", range(len(SETUP)))
@pytest.mark.parametrize("result", ["failed", "unknown"])
def test_failed_setup_cannot_restart_and_failure_survives_cleanup(reserved, stage, result):
    path, journal, row = reserved
    for operation in SETUP[:stage]:
        row = finish(journal, row, operation)
    row = finish(journal, row, SETUP[stage], result)
    failure = row["operations"][-1]
    for forbidden in SETUP:
        with pytest.raises(ContractError):
            journal.begin(row["identity_digest"], forbidden, row["revision"])
    for operation in CLEANUP:
        row = finish(journal, row, operation)
    assert failure in row["operations"]
    assert row["recovery_state"] == "verification_required"
    assert ServiceIntentJournal(path).get(row["identity_digest"]) == row
    with pytest.raises(ContractError):
        journal.begin(row["identity_digest"], "start", row["revision"])


@pytest.mark.parametrize("stage", range(len(CLEANUP)))
def test_failed_cleanup_requires_same_stage_and_never_proves_absence(reserved, stage):
    _, journal, row = reserved
    for operation in CLEANUP[:stage]:
        row = finish(journal, row, operation)
    row = finish(journal, row, CLEANUP[stage], "failed")
    failure = row["operations"][-1]
    assert row["recovery_state"] == "cleanup_required"
    for forbidden in {"start", *(CLEANUP[stage + 1 :])}:
        with pytest.raises(ContractError):
            journal.begin(row["identity_digest"], forbidden, row["revision"])
    row = finish(journal, row, CLEANUP[stage])
    for operation in CLEANUP[stage + 1 :]:
        row = finish(journal, row, operation)
    assert failure in row["operations"]
    assert row["recovery_state"] == "verification_required"


def test_stale_completion_cannot_complete_a_different_or_already_finished_intent(reserved):
    _, journal, row = reserved
    pending = journal.begin(row["identity_digest"], "create_unit", row["revision"])
    operation_id = pending["operations"][-1]["operation_id"]
    for supplied_id, revision in [("op-" + "0" * 32, pending["revision"]), (operation_id, 0)]:
        with pytest.raises(ContractError):
            journal.finish(row["identity_digest"], supplied_id, "succeeded", revision)
    completed = journal.finish(
        row["identity_digest"], operation_id, "succeeded", pending["revision"]
    )
    with pytest.raises(ContractError):
        journal.finish(row["identity_digest"], operation_id, "failed", completed["revision"])
    assert journal.get(row["identity_digest"]) == completed


@pytest.mark.parametrize("changed", ["manager_id", "boot_id", "owner_uid", "unit_nonce"])
def test_same_request_cannot_rebind_to_changed_resource_identity(reserved, identity_data, changed):
    _, journal, row = reserved
    changes = {
        "manager_id": "c" * 32,
        "boot_id": "87654321-4321-4321-4321-cba987654321",
        "owner_uid": 1001,
        "unit_nonce": "d" * 32,
    }
    identity_data[changed] = changes[changed]
    with pytest.raises(ContractError):
        journal.reserve(OwnedUserService.from_mapping(identity_data), "request-1")
    assert journal.get(row["identity_digest"]) == row


def test_duplicate_new_request_cannot_adopt_existing_identity(reserved, identity):
    _, journal, row = reserved
    with pytest.raises(ContractError):
        journal.reserve(identity, "request-2")
    assert journal.get(identity.digest) == row


@pytest.mark.parametrize("cleanup_finished", [False, True])
def test_new_authorization_cannot_reserve_the_same_unit_nonce(
    reserved, identity_data, cleanup_finished
):
    _, journal, row = reserved
    if cleanup_finished:
        for operation in CLEANUP:
            row = finish(journal, row, operation)
    identity_data["authorization_digest"] = "sha256:" + "d" * 64
    other = OwnedUserService.from_mapping(identity_data)
    assert other.digest != row["identity_digest"]
    with pytest.raises(ContractError):
        journal.reserve(other, "request-2")
    assert journal.get(row["identity_digest"]) == row


def test_concurrent_dispatchers_cannot_reserve_two_effects(reserved):
    path, _, row = reserved
    journals = [ServiceIntentJournal(path), ServiceIntentJournal(path)]
    gate = threading.Barrier(2)
    outcomes = []

    def compete(journal):
        gate.wait(timeout=5)
        try:
            outcomes.append(journal.begin(row["identity_digest"], "create_unit", row["revision"]))
        except ContractError:
            outcomes.append("conflict")

    threads = [threading.Thread(target=compete, args=(journal,)) for journal in journals]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not any(thread.is_alive() for thread in threads)
    assert len(outcomes) == 2 and outcomes.count("conflict") == 1
    retained = ServiceIntentJournal(path).get(row["identity_digest"])
    assert retained["revision"] == 1 and len(retained["operations"]) == 1
    assert retained["recovery_state"] == "inspection_required"


def test_committed_intent_survives_abrupt_coordinator_process_exit(reserved):
    path, _, row = reserved
    code = """
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from bluefire.tool_adapters.service_journal import ServiceIntentJournal
journal = ServiceIntentJournal(Path(sys.argv[2]))
journal.begin(sys.argv[3], 'create_unit', 0)
os._exit(23)
"""
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            code,
            str(Path(__file__).resolve().parents[1]),
            str(path),
            row["identity_digest"],
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert process.returncode == 23
    reopened = ServiceIntentJournal(path)
    retained = reopened.get(row["identity_digest"])
    assert retained["revision"] == 1 and retained["recovery_state"] == "inspection_required"
    assert retained["operations"][0]["result"] == "pending"
    with pytest.raises(ContractError):
        reopened.begin(row["identity_digest"], "create_unit", 1)


def test_corrupt_storage_is_refused_without_overwriting_evidence(reserved):
    path, journal, row = reserved
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE service_intents SET document = ?", (b'{"invalid":true}',))
    with pytest.raises(ContractError):
        journal.get(row["identity_digest"])
    with pytest.raises(ContractError):
        journal.begin(row["identity_digest"], "create_unit", row["revision"])
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute("SELECT document FROM service_intents").fetchone()[0]
            == b'{"invalid":true}'
        )


@pytest.mark.parametrize("field", ["request_id", "unit_nonce"])
def test_database_index_columns_must_match_the_retained_identity(reserved, field):
    path, journal, row = reserved
    with sqlite3.connect(path) as connection:
        if field == "request_id":
            connection.execute("UPDATE service_intents SET request_id=?", ("other-request",))
        else:
            connection.execute("UPDATE service_intents SET unit_nonce=?", ("d" * 32,))
    with pytest.raises(ContractError):
        journal.get(row["identity_digest"])


@pytest.mark.parametrize("mutation", ["skip_creation", "wrong_revision", "duplicate_operation"])
def test_consistent_checksum_does_not_bypass_lifecycle_validation(reserved, mutation):
    path, journal, row = reserved
    row = finish(journal, row, "create_unit")
    with sqlite3.connect(path) as connection:
        document = json.loads(
            connection.execute("SELECT document FROM service_intents").fetchone()[0]
        )
        if mutation == "skip_creation":
            document["operations"][0]["operation"] = "start"
        elif mutation == "wrong_revision":
            document["revision"] = 0
        else:
            document["operations"].append({**document["operations"][0], "operation": "reload"})
            document["revision"] = 4
        connection.execute(
            "UPDATE service_intents SET document=?, record_hash=?",
            (canonical_json_bytes(document), content_hash(document)),
        )
    with pytest.raises(ContractError):
        journal.get(row["identity_digest"])


@pytest.mark.parametrize(
    "operation", ["shell", "restart", "enable_linger", "remove_tree", "../start", ""]
)
def test_journal_never_accepts_generic_or_unreviewed_operations(reserved, operation):
    _, journal, row = reserved
    with pytest.raises(ContractError):
        journal.begin(row["identity_digest"], operation, row["revision"])
    assert journal.get(row["identity_digest"]) == row


@pytest.mark.parametrize("revision", [True, -1, "0", None, 0.0])
def test_revision_requires_exact_nonnegative_integer(reserved, revision):
    _, journal, row = reserved
    with pytest.raises(ContractError):
        journal.begin(row["identity_digest"], "create_unit", revision)
    assert journal.get(row["identity_digest"]) == row


def test_repeated_cleanup_failure_is_bounded_and_preserved(reserved):
    _, journal, row = reserved
    for _ in range(32):
        row = finish(journal, row, "stop", "failed")
    with pytest.raises(ContractError):
        journal.begin(row["identity_digest"], "stop", row["revision"])
    retained = journal.get(row["identity_digest"])
    assert retained == row and retained["recovery_state"] == "cleanup_required"
    assert len(retained["operations"]) == 32
