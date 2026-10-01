"""Pending-intent handoffs preserve history; decoding cannot release an effect."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from bluefire.contracts import ContractError
from bluefire.tool_adapters.service_journal import ServiceIntentJournal
from bluefire.tool_adapters.service_operation_binding import MAX_BYTES, ServiceOperationBinding
from tests_platform import test_service_lifecycle as lifecycle

identity = lifecycle.identity
identity_data = lifecycle.identity_data

FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures/service_operation_binding_v1.json").read_text()
)
PINS = {
    "reviewed_scope_digest": "sha256:" + "d" * 64,
    "manager_installation_digest": "sha256:" + "e" * 64,
    "payload_installation_digest": "sha256:" + "f" * 64,
}


@pytest.mark.parametrize("case", FIXTURES["valid"], ids=lambda case: case["name"])
def test_shared_valid_handoffs_have_the_same_canonical_digest(case):
    binding = ServiceOperationBinding.from_mapping(case["document"])
    assert binding.digest == case["canonical_sha256"]
    assert ServiceOperationBinding.from_json(json.dumps(case["document"]).encode()) == binding
    assert ServiceOperationBinding(binding.canonical_bytes()) == binding
    exported = binding.to_dict()
    exported["identity"]["owner_uid"] = 0
    assert binding.to_dict() == case["document"]
    assert binding.digest == case["canonical_sha256"]


@pytest.mark.parametrize("case", FIXTURES["invalid"], ids=lambda case: case["name"])
def test_shared_invalid_handoffs_are_refused(case):
    with pytest.raises(ContractError):
        ServiceOperationBinding.from_mapping(case["document"])
    with pytest.raises(ContractError):
        ServiceOperationBinding.from_json(json.dumps(case["document"]).encode())


@pytest.mark.parametrize("case", FIXTURES["invalid_json"], ids=lambda case: case["name"])
def test_duplicate_or_non_document_json_is_refused(case):
    with pytest.raises(ContractError):
        ServiceOperationBinding.from_json(case["json"].encode())


@pytest.mark.parametrize("case", FIXTURES["invalid_bytes"], ids=lambda case: case["name"])
def test_non_utf8_or_bom_wire_documents_are_refused(case):
    with pytest.raises(ContractError):
        ServiceOperationBinding.from_json(bytes.fromhex(case["hex"]))


def test_decode_is_bounded_and_internal_storage_must_be_canonical():
    document = FIXTURES["valid"][0]["document"]
    expected = ServiceOperationBinding.from_mapping(document)
    padded = expected.canonical_bytes().ljust(MAX_BYTES, b" ")
    assert ServiceOperationBinding.from_json(padded) == expected
    with pytest.raises(ContractError):
        ServiceOperationBinding.from_json(padded + b" ")
    with pytest.raises(ContractError):
        ServiceOperationBinding.from_json(b" " * (MAX_BYTES + 1))
    with pytest.raises(ContractError):
        ServiceOperationBinding.from_json(bytearray(b"{}"))
    with pytest.raises(ContractError):
        ServiceOperationBinding(json.dumps(document, indent=2).encode())


@pytest.fixture
def journal(tmp_path):
    if os.name == "nt":
        from bluefire.windows_owner_acl import apply_owner_private_acl_path

        apply_owner_private_acl_path(tmp_path, directory=True)
    else:
        tmp_path.chmod(0o700)
    path = tmp_path / "handoff.sqlite3"
    return path, ServiceIntentJournal(path)


def test_handoff_binds_the_committed_pending_database_record_without_mutation(journal, identity):
    path, store = journal
    row = store.reserve(identity, "request-handoff")
    with pytest.raises(ContractError, match="no pending"):
        store.pending_binding(identity.digest, row["revision"], **PINS)
    pending = store.begin(identity.digest, "create_unit", row["revision"])
    original = path.read_bytes()
    binding = store.pending_binding(identity.digest, pending["revision"], **PINS)
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        raw, digest = connection.execute(
            "SELECT document, record_hash FROM service_intents WHERE identity_digest=?",
            (identity.digest,),
        ).fetchone()
    committed = json.loads(raw)
    document = binding.to_dict()
    assert document["journal_record_hash"] == digest
    assert document["identity"] == committed["identity"] == identity.to_dict()
    assert document["journal_request_id"] == committed["request_id"]
    assert document["journal_revision"] == committed["revision"]
    assert document["operation_id"] == committed["operations"][-1]["operation_id"]
    assert document["operation"] == committed["operations"][-1]["operation"] == "create_unit"
    assert all(document[name] == pin for name, pin in PINS.items())
    assert path.read_bytes() == original and store.get(identity.digest) == pending


def test_reopening_reconstructs_metadata_but_never_releases_or_repeats_pending_work(
    journal, identity
):
    path, store = journal
    row = store.reserve(identity, "request-reopen")
    pending = store.begin(identity.digest, "create_unit", row["revision"])
    binding = store.pending_binding(identity.digest, pending["revision"], **PINS)
    reopened = ServiceIntentJournal(path)
    assert reopened.pending_binding(identity.digest, pending["revision"], **PINS) == binding
    assert reopened.get(identity.digest)["recovery_state"] == "inspection_required"
    for operation in ("create_unit", "start", "stop"):
        with pytest.raises(ContractError):
            reopened.begin(identity.digest, operation, pending["revision"])
    assert reopened.get(identity.digest) == pending


def test_stale_or_completed_intent_cannot_be_recaptured(journal, identity):
    _, store = journal
    row = store.reserve(identity, "request-stale")
    pending = store.begin(identity.digest, "create_unit", row["revision"])
    binding = store.pending_binding(identity.digest, pending["revision"], **PINS)
    with pytest.raises(ContractError, match="stale"):
        store.pending_binding(identity.digest, 0, **PINS)
    finished = store.finish(
        identity.digest, pending["operations"][-1]["operation_id"], "unknown", pending["revision"]
    )
    with pytest.raises(ContractError, match="stale"):
        store.pending_binding(identity.digest, pending["revision"], **PINS)
    with pytest.raises(ContractError, match="no pending"):
        store.pending_binding(identity.digest, finished["revision"], **PINS)
    # Historical bytes stay readable; successful decoding is never current authority.
    assert ServiceOperationBinding.from_json(binding.canonical_bytes()) == binding
    assert store.get(identity.digest)["recovery_state"] == "cleanup_required"


@pytest.mark.parametrize("pin", PINS)
def test_scope_or_installation_changes_cannot_share_a_handoff_digest(journal, identity, pin):
    _, store = journal
    row = store.reserve(identity, "request-pins")
    pending = store.begin(identity.digest, "create_unit", row["revision"])
    original = store.pending_binding(identity.digest, pending["revision"], **PINS)
    changed = store.pending_binding(
        identity.digest, pending["revision"], **{**PINS, pin: "sha256:" + "9" * 64}
    )
    assert changed.digest != original.digest
    assert store.get(identity.digest) == pending


def test_corrupted_persisted_history_cannot_supply_a_handoff(journal, identity):
    path, store = journal
    row = store.reserve(identity, "request-corrupt")
    pending = store.begin(identity.digest, "create_unit", row["revision"])
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE service_intents SET record_hash=?", ("sha256:" + "0" * 64,))
    original = path.read_bytes()
    with pytest.raises(ContractError):
        store.pending_binding(identity.digest, pending["revision"], **PINS)
    assert path.read_bytes() == original
