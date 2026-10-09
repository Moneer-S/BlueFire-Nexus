"""Durable authorization outcomes, without runner, provider or native effects."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest

from bluefire.composition_jobs import CompositionJobs
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash
from tests_platform.test_capability_composition import proposal
from tests_platform.test_capability_composition import state as state
from tests_platform.test_composition_runtime import controller as controller
from tests_platform.test_product_store_capability_grants import saved as saved


def authorize_request(controller, monkeypatch):
    jobs, state, _, _, _ = controller
    reviewed = {
        key: state["grant"][key] for key in ("objective", "environment", "limits", "snapshot")
    }
    reviewed["review_digest"] = content_hash(reviewed)
    monkeypatch.setattr(jobs, "review", lambda _: reviewed)
    original = jobs.store.save_capability_grant

    def save_fixture_lineage(document, **context):
        # The shared fixture predates the controller's canonical lineage ID.
        return original(document, **{**context, "lineage_id": "lineage-1"})

    monkeypatch.setattr(jobs.store, "save_capability_grant", save_fixture_lineage)
    return {
        "submission_id": str(uuid.uuid4()),
        "review": {
            "control_owner_id": state["grant"]["environment"]["control_owner_id"],
            "question": state["grant"]["objective"]["question"],
            "limits": state["grant"]["limits"],
        },
        "reviewed_by": state["grant"]["approved_by"],
        "review_digest": reviewed["review_digest"],
    }


@pytest.mark.parametrize("accepted", [False, True])
def test_exact_admission_replay_precedes_freshness_but_collision_never_returns_content(
    controller, monkeypatch, accepted
):
    jobs, _, _, _, _ = controller
    request = authorize_request(controller, monkeypatch)
    if not accepted:
        request["review_digest"] = content_hash("stale-review")
    result = jobs.authorize(request)
    owner = result["owner"]
    assert owner["state"] == "completed"
    assert owner["progress"]["submitted_request"] == request
    assert owner["progress"]["admission"]["accepted"] is accepted
    assert (result["grant"] is not None) is accepted
    monkeypatch.setattr(
        jobs,
        "review",
        lambda _: (_ for _ in ()).throw(AssertionError("No fresh admission on replay")),
    )
    assert jobs.authorize(request) == result
    changed = deepcopy(request)
    changed["reviewed_by"] = "different-operator"
    with pytest.raises(ProductStoreError, match="another exact operation"):
        jobs.authorize(changed)
    if not accepted:
        assert result["attempts"] == []
        assert owner["progress"]["admission"]["problem"]["code"] == "composition_review_changed"
        with pytest.raises(ProductStoreError, match="not admitted"):
            jobs.validate_proposal(owner["job_id"], proposal())
        with pytest.raises(ProductStoreError, match="No capability grant"):
            jobs.stop(owner["job_id"])
        with pytest.raises(ProductStoreError, match="No capability grant"):
            jobs.continue_objective(owner["job_id"])
        assert (
            jobs.objectives(request["review"]["control_owner_id"])["objectives"][-1]["status"]
            == "refused"
        )


@pytest.mark.parametrize("saved_grant", [False, True])
@pytest.mark.parametrize("restart", [False, True])
def test_interruption_after_durable_submission_recovers_only_already_saved_authority(
    controller, monkeypatch, saved_grant, restart
):
    jobs, _, _, _, _ = controller
    request = authorize_request(controller, monkeypatch)
    original = jobs.store.save_capability_grant

    def fail(*args, **kwargs):
        owner = jobs.store.get_job("job-" + uuid.UUID(request["submission_id"]).hex)
        assert owner["progress"]["submitted_request"] == request
        assert owner["progress"]["admission"]["accepted"] is False
        if saved_grant:
            original(*args, **kwargs)
        if restart:
            raise KeyboardInterrupt("Injected process exit")
        raise RuntimeError("Injected publication interruption")

    monkeypatch.setattr(jobs.store, "save_capability_grant", fail)
    with pytest.raises((RuntimeError, KeyboardInterrupt), match="Injected"):
        jobs.authorize(request)
    if restart:
        pending = jobs.authorize(request)
        assert pending["owner"]["state"] == "queued"
        assert pending["grant"] is None
        jobs.store.recover_interrupted_jobs()
    monkeypatch.setattr(
        jobs, "review", lambda _: (_ for _ in ()).throw(AssertionError("No reauthorization"))
    )
    result = jobs.authorize(request)
    assert result["owner"]["state"] == "completed"
    assert (result["grant"] is not None) is saved_grant
    if not saved_grant:
        assert (
            result["owner"]["progress"]["admission"]["problem"]["code"]
            == "composition_admission_interrupted"
        )


def test_matching_live_admission_in_another_controller_remains_pending(controller, monkeypatch):
    jobs, _, _, _, clock = controller
    request = authorize_request(controller, monkeypatch)
    other = CompositionJobs(jobs.service, clock=lambda: clock[0])
    entered, release = threading.Event(), threading.Event()
    original = jobs.store.save_capability_grant

    def held(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(jobs.store, "save_capability_grant", held)
    with ThreadPoolExecutor(max_workers=1) as pool:
        winner = pool.submit(jobs.authorize, request)
        try:
            assert entered.wait(5)
            pending = other.authorize(request)
            assert pending["owner"]["state"] == "queued"
            assert pending["grant"] is None
            assert (
                pending["owner"]["progress"]["admission"]["problem"]["code"]
                == "composition_admission_pending"
            )
        finally:
            release.set()
        completed = winner.result(timeout=5)
    assert completed["owner"]["progress"]["admission"] == {"accepted": True, "problem": None}
    clock[0] = completed["grant"]["document"]["expires_at_ms"] + 1
    monkeypatch.setattr(
        other,
        "review",
        lambda _: (_ for _ in ()).throw(AssertionError("No fresh admission after expiry")),
    )
    repeated = other.authorize(request)
    assert repeated["owner"] == completed["owner"]
    assert repeated["grant"]["document"] == completed["grant"]["document"]
    assert repeated["grant"]["status"] == "expired"


def test_restart_refusal_atomically_excludes_a_stale_original_grant_writer(controller, monkeypatch):
    jobs, _, _, _, clock = controller
    request = authorize_request(controller, monkeypatch)
    other = CompositionJobs(jobs.service, clock=lambda: clock[0])
    entered, release = threading.Event(), threading.Event()
    original = jobs.store.save_capability_grant

    def held(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(jobs.store, "save_capability_grant", held)
    with ThreadPoolExecutor(max_workers=1) as pool:
        winner = pool.submit(jobs.authorize, request)
        try:
            assert entered.wait(5)
            jobs.store.recover_interrupted_jobs()
            result = other.authorize(request)
            assert result["owner"]["state"] == "completed"
            assert result["grant"] is None
        finally:
            release.set()
        with pytest.raises(ProductStoreError):
            winner.result(timeout=5)
    assert other.authorize(request) == result
    with jobs.store._connection() as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM capability_grants WHERE grant_id=?",
                ("grant-" + uuid.UUID(request["submission_id"]).hex,),
            ).fetchone()
            is None
        )


def test_unreadable_existing_grant_never_becomes_a_no_authority_refusal(controller, monkeypatch):
    jobs, _, _, _, _ = controller
    request = authorize_request(controller, monkeypatch)
    original = jobs.store.save_capability_grant

    def crash(*args, **kwargs):
        original(*args, **kwargs)
        raise KeyboardInterrupt("Simulated restart after grant persistence")

    monkeypatch.setattr(jobs.store, "save_capability_grant", crash)
    with pytest.raises(KeyboardInterrupt):
        jobs.authorize(request)
    jobs.store.recover_interrupted_jobs()
    monkeypatch.setattr(
        jobs.store,
        "get_capability_grant",
        lambda *_, **__: (_ for _ in ()).throw(
            ProductStoreError("Stored authority could not be verified")
        ),
    )
    with pytest.raises(ProductStoreError, match="could not be verified"):
        jobs.authorize(request)
    assert (
        jobs.store.get_job("job-" + uuid.UUID(request["submission_id"]).hex)["state"]
        == "interrupted"
    )


def test_failure_before_durable_submission_cannot_mint_authority(controller, monkeypatch):
    jobs, _, _, _, _ = controller
    request = authorize_request(controller, monkeypatch)
    monkeypatch.setattr(
        jobs.store,
        "create_capability_objective_submission",
        lambda *_: (_ for _ in ()).throw(RuntimeError("Injected insert failure")),
    )
    monkeypatch.setattr(
        jobs.store,
        "save_capability_grant",
        lambda *_, **__: (_ for _ in ()).throw(AssertionError("No authority before submission")),
    )
    with pytest.raises(RuntimeError, match="Injected insert"):
        jobs.authorize(request)
    with pytest.raises(ProductStoreError):
        jobs.store.get_job("job-" + uuid.UUID(request["submission_id"]).hex)


def test_later_verified_success_closes_older_refusal_context_and_reservation(
    controller, monkeypatch
):
    jobs, state, _, _, _ = controller
    child = {
        "progress": {
            "settlement": "settled",
            "verified_result": {"objective": {"established": True}},
        },
        "request": {"composition_attempt": {"attempt_id": "attempt-" + "b" * 32}},
    }
    monkeypatch.setattr(jobs, "_children", lambda _: [child])
    monkeypatch.setattr(
        jobs.store, "get_capability_attempt", lambda _: {"test": "settled-later-attempt"}
    )
    monkeypatch.setattr(jobs, "_verified_result", lambda _: {"objective": {"established": True}})
    monkeypatch.setattr(
        jobs,
        "_facts",
        lambda *_: (_ for _ in ()).throw(AssertionError("Old refusal must not be reused")),
    )
    prior = "attempt-" + "a" * 32
    with pytest.raises(ProductStoreError, match="objective is established"):
        jobs.proposal_context(state["parent_job_id"], prior_attempt_id=prior)
    with pytest.raises(ProductStoreError, match="objective is established"):
        jobs.validate_proposal(state["parent_job_id"], proposal(), prior_attempt_id=prior)
