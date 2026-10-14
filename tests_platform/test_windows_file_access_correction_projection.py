"""Read-only correction views over actual SQLite and synthetic retained proof."""

from __future__ import annotations

import hashlib
import json

import pytest

from bluefire import product_store_capability_grants as usages
from bluefire import product_store_file_access_native_evidence as native
from bluefire import product_store_windows_correction_publication as publication
from bluefire import windows_file_access_correction_admission as admission
from bluefire import windows_file_access_correction_observation as observation
from bluefire import windows_file_access_correction_projection as module
from bluefire import windows_file_access_enrollment as enrollment
from bluefire import windows_file_access_native_wire as wire
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import content_hash
from tests_platform import test_windows_file_access_baseline_publication as baseline
from tests_platform import test_windows_file_access_correction_journal as journal_fake
from tests_platform import test_windows_file_access_correction_publication as publication_fake
from tests_platform.test_windows_file_access_baseline_publication import at_ms
from tests_platform.test_windows_file_access_baseline_publication import saved as saved
from tests_platform.test_windows_file_access_correction_admission import harden_original
from tests_platform.test_windows_file_access_correction_journal import retained as retained
from tests_platform.test_windows_file_access_correction_retest import candidate as candidate
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


@pytest.fixture
def completed(saved):
    baseline.produce(saved)
    saved["revision"] = baseline.publish(saved)
    return saved


@pytest.fixture
def hardened(candidate, monkeypatch):
    value = candidate
    execution = publication_fake.execute(value, monkeypatch)
    value.revision = publication.publish(value.store, value.job, clock=execution.observed_time)
    value.clock = execution.observed_time
    return value


def project(store, imported, milliseconds):
    return module.projection(store, imported["control_owner_id"], clock=at_ms(milliseconds))


_QUERIES = {
    "revision": (
        "SELECT document_json FROM file_access_revisions WHERE job_id=?",
        "UPDATE file_access_revisions SET document_json=?,document_digest=? WHERE job_id=?",
        "DELETE FROM file_access_revisions WHERE job_id=?",
        "DROP TRIGGER file_access_revisions_no_update",
        "DROP TRIGGER file_access_revisions_no_delete",
    ),
    "terminal": (
        "SELECT document_json FROM file_access_task_evidence WHERE task_id=? AND stage='terminal'",
        "UPDATE file_access_task_evidence SET document_json=?,document_digest=? WHERE task_id=? AND stage='terminal'",
        "DELETE FROM file_access_task_evidence WHERE task_id=? AND stage='terminal'",
        "DROP TRIGGER file_access_task_evidence_no_update",
        "DROP TRIGGER file_access_task_evidence_no_delete",
    ),
    "native_closure": (
        "SELECT document_json FROM file_access_owned_process_closures WHERE task_id=?",
        "UPDATE file_access_owned_process_closures SET document_json=?,document_digest=? WHERE task_id=?",
        "DELETE FROM file_access_owned_process_closures WHERE task_id=?",
        "DROP TRIGGER file_access_owned_process_closures_no_update",
        "DROP TRIGGER file_access_owned_process_closures_no_delete",
    ),
    "outcome": (
        "SELECT document_json FROM file_access_outcomes WHERE job_id=? ORDER BY sequence DESC LIMIT 1",
        "UPDATE file_access_outcomes SET document_json=?,document_digest=? WHERE job_id=?",
        "DELETE FROM file_access_outcomes WHERE job_id=?",
        "DROP TRIGGER file_access_outcomes_no_update",
        "DROP TRIGGER file_access_outcomes_no_delete",
    ),
    "control_closure": (
        "SELECT document_json FROM file_access_windows_control_evidence WHERE job_id=? AND stage='closure'",
        "UPDATE file_access_windows_control_evidence SET document_json=?,document_digest=? WHERE job_id=? AND stage='closure'",
        "DELETE FROM file_access_windows_control_evidence WHERE job_id=? AND stage='closure'",
        "DROP TRIGGER file_access_windows_control_evidence_no_update",
        "DROP TRIGGER file_access_windows_control_evidence_no_delete",
    ),
}


def damage(store, target, identifier, mode, transform=None):
    # Disable immutability only in this disposable fixture to model damaged history.
    select, update, delete, no_update, no_delete = _QUERIES[target]
    with store._connection(write=True) as connection:
        if mode == "missing":
            connection.execute(no_delete)
            connection.execute(delete, (identifier,))
        else:
            row = json.loads(connection.execute(select, (identifier,)).fetchone()[0])
            row = transform(row) if transform is not None else {**row, "schema_version": "corrupt"}
            connection.execute(no_update)
            connection.execute(update, (canonical_json(row), content_hash(row), identifier))


def test_live_settled_baseline_offers_only_harden_and_preserves_proof(completed):
    value = completed
    view = project(value["store"], value["imported"], ISSUED + 3000)
    assert view["schema_version"] == "bluefire.windows-file-access-control.v3"
    assert view["revision"] == 2 and view["status"] == "baseline_verified"
    assert view["control_digest"] == content_hash(value["revision"])
    assert view["allowed_operations"] == ["harden"] and view["task_usage_state"] == "settled"
    assert view["resource"]["protection"] == "reader_readable"
    assert view["baseline"] == value["revision"]["baseline"]
    assert view["baseline"]["independent_observation"] is False
    assert view["correction"] is view["retest"] is None
    assert view["account_object_cleanup"] == "required"


@pytest.mark.parametrize("offset", [0, 1])
def test_exact_expiry_retains_baseline_history_without_new_operations(completed, offset):
    value = completed
    view = project(value["store"], value["imported"], value["imported"]["expires_at_ms"] + offset)
    assert view["revision"] == 2 and view["status"] == "baseline_verified"
    assert view["baseline"] == value["revision"]["baseline"]
    assert view["allowed_operations"] == []


def test_unsettled_usage_never_offers_harden_or_asserts_current_protection(completed, monkeypatch):
    monkeypatch.setattr(usages, "control_usages_settled", lambda *args: False)
    view = project(completed["store"], completed["imported"], ISSUED + 3000)
    assert view["status"] == "uncertain" and view["task_usage_state"] == "unresolved"
    assert view["resource"]["protection"] == "unknown" and view["allowed_operations"] == []


@pytest.mark.parametrize("state", ["reserved", "dispatched", "unknown"])
def test_pending_correction_is_uncertain_even_without_a_native_task(retained, state):
    value = retained
    if state != "reserved":
        journal_fake.begin(value)
    if state == "unknown":
        value.store.finish_file_access_operation(
            value.job,
            outcome={"state": "unknown", "evidence_digest": content_hash({"synthetic": True})},
        )
    records = value.store.file_access_operation_records(value.job)
    assert records["tasks"] == []
    assert (
        records["outcome"]["state"] == "unknown"
        if state == "unknown"
        else records["outcome"] is None
    )
    view = project(value.store, value.saved["imported"], ISSUED + 3000)
    assert view["status"] == "uncertain" and view["task_usage_state"] == "unresolved"
    assert view["resource"]["protection"] == "unknown" and view["allowed_operations"] == []
    assert view["correction"] is view["retest"] is None
    assert view["account_object_cleanup"] == "required"


@pytest.mark.parametrize("mode", ["missing", "corrupt"])
@pytest.mark.parametrize("target", ["revision", "terminal", "native_closure", "outcome"])
def test_damaged_baseline_cannot_be_projected_as_verified(completed, target, mode):
    value = completed
    identifier = (
        value["context"]["task_id"] if target in ("terminal", "native_closure") else value["job"]
    )
    damage(value["store"], target, identifier, mode)
    with pytest.raises(ProductStoreError):
        project(value["store"], value["imported"], ISSUED + 3000)


def test_completed_hardened_history_is_read_only_after_expiry(hardened, monkeypatch):
    value = hardened

    def forbidden(*args, **kwargs):
        pytest.fail("Historical projection invoked a fresh admission or native boundary")

    for owner, name in (
        (enrollment, "read_windows_file_setup_status"),
        (observation, "observe_correction_preimage"),
        (observation, "observe_correction_postimage"),
        (value.store, "prepare_file_access_operation"),
        (wire, "prepare_correction_packet"),
        (wire, "prepare_pair_packet"),
        (journal_fake.journal, "begin_dispatch"),
    ):
        monkeypatch.setattr(owner, name, forbidden)
    before = hashlib.sha256(value.path.read_bytes()).hexdigest()
    clock = value.saved["imported"]["expires_at_ms"] + 1
    view = project(value.store, value.saved["imported"], clock)
    assert project(value.store, value.saved["imported"], clock) == view
    assert hashlib.sha256(value.path.read_bytes()).hexdigest() == before
    assert view["revision"] == 3 and view["status"] == "hardened"
    assert view["resource"]["protection"] == "metadata_only" and view["allowed_operations"] == []
    assert view["correction"] == value.revision["correction"]
    assert view["retest"] == value.revision["retest"]
    assert view["retest"]["independent_observation"] is False
    assert view["retest"]["native_cleanup"] == view["retest"]["owned_job_cleanup"] == "verified"
    assert view["account_object_cleanup"] == "required"


@pytest.mark.parametrize("mode", ["missing", "corrupt"])
@pytest.mark.parametrize(
    "target",
    [
        "revision",
        "baseline",
        "terminal",
        "native_closure",
        "outcome",
        "control_closure",
        "control_terminal",
    ],
)
def test_hardened_view_requires_original_control_and_native_terminal_closure(
    hardened, target, mode
):
    value = hardened
    identifier = (
        value.original["task_id"] if target in ("terminal", "native_closure") else value.job
    )
    transform = None
    if target == "baseline":
        target, identifier = "revision", value.saved["job"]
    if target == "control_terminal":
        target = "control_closure"
        missing = mode == "missing"

        def transform(row):
            row["payload"]["terminal"] = None if missing else {"schema_version": "corrupt"}
            return row

        mode = "corrupt"
    damage(value.store, target, identifier, mode, transform)
    with pytest.raises(ProductStoreError):
        project(value.store, value.saved["imported"], ISSUED + 5000)


def test_missing_completed_revision_cannot_admit_a_new_baseline_review(hardened):
    value = hardened
    with value.store._connection() as connection:
        prior = journal_fake.journal.original_at(value.store, connection, value.job)[3]
    damage(value.store, "revision", value.job, "missing")
    context = admission.correction_context(value.saved["imported"], prior, "sha256:" + "7" * 64)
    with value.store._connection() as connection:
        with pytest.raises(ProductStoreError):
            journal_fake.journal.validate_review(
                value.store, connection, prior, context, now_ms=ISSUED + 5000
            )
    original, _ = harden_original(
        dict(imported=value.saved["imported"], control=prior, context=context)
    )
    original["submitted_request"]["submission_id"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    with pytest.raises(ProductStoreError):
        value.store.create_file_access_operation(
            original["submitted_request"],
            review_document=original["review"],
            review_context=context,
            enrollment_id=value.saved["imported"]["enrollment_id"],
            now_ms=ISSUED + 5000,
        )


def test_refused_outcome_cannot_hide_a_retained_dispatch(retained):
    value = retained
    journal_fake.begin(value)
    value.store.finish_file_access_operation(
        value.job,
        outcome={"state": "unknown", "evidence_digest": content_hash({"synthetic": True})},
    )
    damage(
        value.store,
        "outcome",
        value.job,
        "corrupt",
        lambda row: {**row, "state": "refused_no_effect"},
    )
    with pytest.raises(ProductStoreError):
        project(value.store, value.saved["imported"], ISSUED + 5000)


@pytest.mark.parametrize(
    "state,target",
    [
        ("baseline", "revision"),
        ("baseline", "outcome"),
        ("hardened", "revision"),
        ("hardened", "outcome"),
        ("hardened", "control_closure"),
    ],
)
def test_oversized_retained_row_is_null_before_decode(request, monkeypatch, state, target):
    value = request.getfixturevalue("completed" if state == "baseline" else "hardened")
    store, imported, job = (
        (value["store"], value["imported"], value["job"])
        if state == "baseline"
        else (value.store, value.saved["imported"], value.job)
    )
    damage(store, target, job, "corrupt", lambda row: {"padding": "x" * (wire.PUBLIC_MAX + 1)})
    seen = []
    original = native._row_document

    def bounded(row, maximum):
        if row is not None and row["document_json"] is None:
            seen.append("sql-null")
        return original(row, maximum)

    monkeypatch.setattr(native, "_row_document", bounded)
    with pytest.raises(ProductStoreError):
        project(store, imported, ISSUED + 5000)
    assert seen == ["sql-null"]


def test_hardened_projection_exposes_no_linux_or_private_windows_facts(hardened):
    value = hardened
    value.store.create_job(
        "file_access.operation",
        {
            "control_owner_id": "other-synthetic-owner",
            "reader_uid": 9137,
            "private_path": "/private/unrelated-synthetic-file",
        },
    )
    value.store.create_job(
        "other.synthetic.kind",
        {"control_owner_id": value.saved["imported"]["control_owner_id"], "uid": 9137},
    )
    view = project(value.store, value.saved["imported"], ISSUED + 5000)
    raw = canonical_json(view)
    record = value.saved["imported"]["enrollment"]
    for private in (
        "uid",
        "gid",
        "reader_sid",
        "owner_sid",
        "credential_reference",
        "private_profile",
        "sandbox_root",
        "records.jsonl",
        "file_identity",
    ):
        assert private not in raw
    assert record["resource"]["reader_sid"] not in raw
    assert record["resource"]["owner_sid"] not in raw
    assert "unrelated-synthetic-file" not in raw
