"""Durable authored objective submissions; no grant or runtime effects."""

import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest

from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash
from tests_platform.test_product_store_capability_grants import saved as saved
from tests_platform.test_product_store_capability_grants import state as state


@pytest.fixture
def submission(tmp_path):
    store = ProductStore(tmp_path / "objectives.sqlite3")
    submitted = {
        "submission_id": str(uuid.uuid4()),
        "review": {
            "control_owner_id": "job-" + "a" * 32,
            "question": "Verify redaction",
            "limits": {},
        },
        "reviewed_by": "local-reviewer",
        "review_digest": content_hash("review"),
    }
    marker = {
        "schema_version": "bluefire.composition-objective-request.v1",
        "grant_id": "grant-" + uuid.UUID(submitted["submission_id"]).hex,
        "grant_digest": content_hash("grant"),
    }
    return store, marker, submitted


def refusal(submitted):
    return {
        "schema_version": "bluefire.composition-objective-refusal.v1",
        "control_owner_id": submitted["review"]["control_owner_id"],
        "submitted_request_digest": content_hash(submitted),
    }


@pytest.mark.parametrize("refused", [False, True])
def test_objective_submission_atomically_publishes_exact_request(submission, refused):
    store, marker, submitted = submission
    marker = refusal(submitted) if refused else marker
    job, created = store.create_capability_objective_submission(marker, submitted)
    assert created and job["state"] == "queued" and job["kind"] == "composition.objective"
    assert job["request"] == {
        **marker,
        "_submission": {
            "schema_version": "bluefire.job-submission.v1",
            "submission_id": submitted["submission_id"],
            "intent_digest": content_hash(marker),
        },
    }
    assert job["progress"] == {
        "submitted_request": submitted,
        "admission": {
            "accepted": False,
            "problem": {
                "code": "composition_admission_pending",
                "message": "The saved delegation is not admitted.",
            },
        },
    }
    replay, created = ProductStore(store.path).create_capability_objective_submission(
        marker, submitted
    )
    assert not created and replay == job
    with store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM capability_grants").fetchone()[0] == 0


@pytest.mark.parametrize("changed", ["reviewed_by", "review_digest", "review", "marker", "refusal"])
def test_objective_submission_rejects_same_key_changed_intent(submission, changed):
    store, marker, submitted = submission
    original, _ = store.create_capability_objective_submission(marker, submitted)
    altered = deepcopy(submitted)
    if changed == "marker":
        marker["grant_digest"] = content_hash("changed grant")
    elif changed == "refusal":
        marker = refusal(submitted)
    else:
        altered[changed] = (
            {**altered[changed], "question": "Changed"} if changed == "review" else "changed"
        )
    with pytest.raises(ProductStoreError):
        store.create_capability_objective_submission(marker, altered)
    assert store.get_job(original["job_id"]) == original


def test_objective_submission_insert_failure_is_atomic(submission):
    store, marker, submitted = submission
    with store._connection(write=True) as connection:
        connection.execute(
            "CREATE TRIGGER reject_objective AFTER INSERT ON jobs "
            "BEGIN SELECT RAISE(ABORT, 'authored insertion failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="authored insertion failure"):
        store.create_capability_objective_submission(marker, submitted)
    with store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM capability_grants").fetchone()[0] == 0


def test_objective_submission_race_has_one_exact_winner(submission):
    store, marker, submitted = submission
    barrier = threading.Barrier(2)

    def create(actor):
        value = {**submitted, "reviewed_by": actor}
        barrier.wait(timeout=10)
        try:
            return store.create_capability_objective_submission(marker, value)
        except ProductStoreError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(create, ["first-reviewer", "second-reviewer"]))
    winners = [item for item in results if item is not None]
    assert len(winners) == 1 and winners[0][1] is True
    with store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("grant_id", "grant-" + "f" * 32),
        ("grant_digest", "not-a-digest"),
        ("extra", "unreviewed"),
    ],
)
def test_objective_submission_rejects_invalid_marker(submission, field, value):
    store, marker, submitted = submission
    marker[field] = value
    with pytest.raises(ProductStoreError):
        store.create_capability_objective_submission(marker, submitted)


def test_objective_refusal_binds_full_request_and_control(submission):
    store, _, submitted = submission
    marker = refusal(submitted)
    for field, value in [
        ("control_owner_id", "job-" + "b" * 32),
        ("submitted_request_digest", content_hash("other")),
    ]:
        with pytest.raises(ProductStoreError):
            store.create_capability_objective_submission({**marker, field: value}, submitted)


def objective_grant(saved):
    store, state, _, args = saved
    identifier = uuid.uuid4()
    grant = {key: value for key, value in state["grant"].items() if key != "grant_digest"}
    grant["grant_id"] = "grant-" + identifier.hex
    grant["grant_digest"] = content_hash(grant)
    request = {
        "submission_id": str(identifier),
        "review": {
            "control_owner_id": grant["environment"]["control_owner_id"],
            "question": grant["objective"]["question"],
            "limits": grant["limits"],
        },
        "reviewed_by": grant["approved_by"],
        "review_digest": content_hash("review"),
    }
    marker = {
        "schema_version": "bluefire.composition-objective-request.v1",
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
    }
    owner, _ = store.create_capability_objective_submission(marker, request)
    return store, grant, owner, args


def interrupted(store, owner):
    with store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET state='interrupted' WHERE job_id=?", (owner["job_id"],))


def save_objective_grant(store, grant, owner, args):
    return store.save_capability_grant(
        grant, lineage_id="lineage-1", objective_job_id=owner["job_id"], **args
    )


ACCEPTED = {"accepted": True, "problem": None}
REFUSED = {"accepted": False, "problem": {"code": "interrupted", "message": "No grant was issued."}}


@pytest.mark.parametrize("final_state", ["queued", "interrupted"])
def test_objective_grant_and_admission_projection_match(saved, final_state):
    store, grant, owner, args = objective_grant(saved)
    save_objective_grant(store, grant, owner, args)
    if final_state == "interrupted":
        interrupted(store, owner)
    completed = store.finish_capability_objective_submission(
        owner["job_id"], expected_state=final_state, admission=ACCEPTED
    )
    assert completed["state"] == "completed"
    assert completed["progress"]["admission"] == ACCEPTED
    assert completed["progress"]["submitted_request"] == owner["progress"]["submitted_request"]
    assert (
        store.finish_capability_objective_submission(
            owner["job_id"], expected_state=final_state, admission=ACCEPTED
        )
        == completed
    )
    with pytest.raises(ProductStoreError):
        store.finish_capability_objective_submission(
            owner["job_id"], expected_state=final_state, admission=REFUSED
        )


def test_interrupted_no_grant_refusal_permanently_denies_late_writer(saved):
    store, grant, owner, args = objective_grant(saved)
    interrupted(store, owner)
    completed = store.finish_capability_objective_submission(
        owner["job_id"], expected_state="interrupted", admission=REFUSED
    )
    with pytest.raises(ProductStoreError, match="no longer pending"):
        save_objective_grant(store, grant, owner, args)
    assert store.get_job(owner["job_id"]) == completed
    with store._connection() as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM capability_grants WHERE grant_id=?", (grant["grant_id"],)
            ).fetchone()
            is None
        )


def test_interrupted_saved_grant_can_never_publish_absence(saved):
    store, grant, owner, args = objective_grant(saved)
    save_objective_grant(store, grant, owner, args)
    interrupted(store, owner)
    with pytest.raises(ProductStoreError, match="grant exists"):
        store.finish_capability_objective_submission(
            owner["job_id"], expected_state="interrupted", admission=REFUSED
        )
    assert store.get_job(owner["job_id"])["state"] == "interrupted"


def test_admission_requires_same_latest_state_and_real_grant(saved):
    store, grant, owner, args = objective_grant(saved)
    with pytest.raises(ProductStoreError, match="saved grant"):
        store.finish_capability_objective_submission(
            owner["job_id"], expected_state="queued", admission=ACCEPTED
        )
    interrupted(store, owner)
    with pytest.raises(ProductStoreError, match="state changed"):
        store.finish_capability_objective_submission(
            owner["job_id"], expected_state="queued", admission=REFUSED
        )
    with pytest.raises(ProductStoreError, match="no longer pending"):
        save_objective_grant(store, grant, owner, args)


def test_admission_preserves_concurrent_stop_observation(saved):
    store, grant, owner, args = objective_grant(saved)
    save_objective_grant(store, grant, owner, args)
    with store._connection(write=True) as connection:
        progress = {**owner["progress"], "stopped": True}
        from bluefire.product_store_serialization import canonical_json

        connection.execute(
            "UPDATE jobs SET progress_json=? WHERE job_id=?",
            (canonical_json(progress), owner["job_id"]),
        )
    completed = store.finish_capability_objective_submission(
        owner["job_id"], expected_state="queued", admission=ACCEPTED
    )
    assert completed["progress"]["stopped"] is True


def test_interrupted_writer_race_never_admits_orphans(saved):
    store, grant, owner, args = objective_grant(saved)
    barrier = threading.Barrier(2)

    def write():
        barrier.wait(timeout=10)
        try:
            save_objective_grant(store, grant, owner, args)
            return "saved"
        except ProductStoreError:
            return "denied"

    def recover():
        barrier.wait(timeout=10)
        interrupted(store, owner)
        try:
            return store.finish_capability_objective_submission(
                owner["job_id"], expected_state="interrupted", admission=REFUSED
            )
        except ProductStoreError:
            return store.finish_capability_objective_submission(
                owner["job_id"], expected_state="interrupted", admission=ACCEPTED
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer = executor.submit(write)
        recovery = executor.submit(recover)
        written, recovered = writer.result(timeout=20), recovery.result(timeout=20)
    assert recovered["progress"]["admission"]["accepted"] == (written == "saved")
    assert recovered["state"] == "completed"
