from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.job_runtime import JobContext, JobQueueFull, JobState, RunJobController
from bluefire.product_store import ProductStore, ProductStoreError
from bluefire.util import content_hash

SUBMISSION_ID = "32d3c13d-9378-4bb4-a9b3-8df094b85491"
INTENT_DIGEST = content_hash({"test_intent": "first reviewed replay"})
REQUEST = {"source_run_id": "run-source", "mode": "simulate"}


def _binding() -> dict[str, str]:
    return {"submission_id": SUBMISSION_ID, "intent_digest": INTENT_DIGEST}


def test_submission_is_durable_and_keeps_original_request(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "product.db")
    request: dict[str, Any] = {**REQUEST, "parameters": {"count": 2}}
    assert store.get_job_submission("run.replay", **_binding()) is None
    original, created = store.create_idempotent_job("run.replay", request, **_binding())
    assert created is True
    assert original["job_id"] == "job-" + uuid.UUID(SUBMISSION_ID).hex
    assert original["request"]["_submission"] == {
        "schema_version": "bluefire.job-submission.v1",
        **_binding(),
    }
    assert "_submission" not in request
    request["parameters"]["count"] = 9
    reopened = ProductStore(store.path)
    duplicate, created = reopened.create_idempotent_job(
        "run.replay", {"local_attempt": "different receipt"}, **_binding()
    )
    assert created is False
    assert duplicate == original
    assert duplicate["request"]["parameters"]["count"] == 2
    assert reopened.get_job_submission("run.replay", **_binding()) == original
    assert len(store.list_jobs()) == 1


@pytest.mark.parametrize("terminal", ["completed", "failed", "cancelled", "interrupted"])
def test_retry_preserves_terminal_state_and_result(tmp_path: Path, terminal: str) -> None:
    store = ProductStore(tmp_path / "product.db")
    original, _ = store.create_idempotent_job("run.replay", REQUEST, **_binding())
    job_id = original["job_id"]
    store.transition_job(job_id, "planning")
    store.transition_job(job_id, "running")
    if terminal == "cancelled":
        store.transition_job(job_id, "cancelling")
    finished = store.transition_job(job_id, terminal, result_ref="run-result")
    duplicate, created = store.create_idempotent_job("run.replay", REQUEST, **_binding())
    assert created is False
    assert duplicate == finished


@pytest.mark.parametrize("changed", ["kind", "intent"])
def test_key_reuse_for_another_intent_refuses_both_lookup_and_create(
    tmp_path: Path, changed: str
) -> None:
    store = ProductStore(tmp_path / "product.db")
    original, _ = store.create_idempotent_job("run.replay", REQUEST, **_binding())
    kind = "run.other" if changed == "kind" else "run.replay"
    binding = _binding()
    if changed == "intent":
        binding["intent_digest"] = content_hash({"test_intent": "changed replay"})
    with pytest.raises(ProductStoreError, match="different intent"):
        store.get_job_submission(kind, **binding)
    with pytest.raises(ProductStoreError, match="different intent"):
        store.create_idempotent_job(kind, REQUEST, **binding)
    assert store.get_job(original["job_id"]) == original


def test_ordinary_job_collision_is_not_claimed_as_a_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ProductStore(tmp_path / "product.db")
    monkeypatch.setattr("bluefire.product_store.uuid.uuid4", lambda: uuid.UUID(SUBMISSION_ID))
    original = store.create_job("run.replay", REQUEST)
    with pytest.raises(ProductStoreError, match="different intent"):
        store.create_idempotent_job("run.replay", REQUEST, **_binding())
    with pytest.raises(ProductStoreError, match="different intent"):
        store.get_job_submission("run.replay", **_binding())
    assert store.get_job(original["job_id"]) == original


@pytest.mark.parametrize(
    "submission_id",
    [None, True, "", SUBMISSION_ID.upper(), SUBMISSION_ID.replace("-", ""), " " + SUBMISSION_ID],
)
def test_submission_id_requires_canonical_uuid(tmp_path: Path, submission_id: Any) -> None:
    store = ProductStore(tmp_path / "product.db")
    binding = {**_binding(), "submission_id": submission_id}
    with pytest.raises(ProductStoreError, match="canonical UUID"):
        store.get_job_submission("run.replay", **binding)
    with pytest.raises(ProductStoreError, match="canonical UUID"):
        store.create_idempotent_job("run.replay", REQUEST, **binding)
    assert store.list_jobs() == []


@pytest.mark.parametrize("digest", [None, True, "", INTENT_DIGEST.upper(), "a" * 64])
def test_submission_digest_requires_canonical_sha256(tmp_path: Path, digest: Any) -> None:
    store = ProductStore(tmp_path / "product.db")
    binding = {**_binding(), "intent_digest": digest}
    with pytest.raises(ProductStoreError, match="digest"):
        store.get_job_submission("run.replay", **binding)
    with pytest.raises(ProductStoreError, match="digest"):
        store.create_idempotent_job("run.replay", REQUEST, **binding)
    assert store.list_jobs() == []


@pytest.mark.parametrize("metadata", [None, {}, {"schema_version": "invented"}])
def test_caller_cannot_override_submission_metadata(tmp_path: Path, metadata: Any) -> None:
    store = ProductStore(tmp_path / "product.db")
    with pytest.raises(ProductStoreError, match="metadata conflicts"):
        store.create_idempotent_job(
            "run.replay", {**REQUEST, "_submission": metadata}, **_binding()
        )
    assert store.list_jobs() == []


def test_exact_metadata_echo_is_accepted_but_secret_rules_still_apply(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "product.db")
    request = {
        **REQUEST,
        "_submission": {"schema_version": "bluefire.job-submission.v1", **_binding()},
    }
    original, _ = store.create_idempotent_job("run.replay", request, **_binding())
    duplicate, created = store.create_idempotent_job("run.replay", request, **_binding())
    assert not created
    assert duplicate == original
    with pytest.raises(ProductStoreError, match="environment-variable reference"):
        store.create_idempotent_job(
            # Public rejection fixture, not a credential.
            "run.replay",
            {"password": "test-only-forbidden-value"},  # pragma: allowlist secret
            **_binding(),
        )
    assert len(store.list_jobs()) == 1


def test_cross_store_race_has_exactly_one_creator(tmp_path: Path) -> None:
    stores = [ProductStore(tmp_path / "product.db") for _ in range(4)]
    barrier = threading.Barrier(len(stores))

    def submit(index: int) -> tuple[Mapping[str, Any], bool]:
        barrier.wait(timeout=5)
        return stores[index].create_idempotent_job("run.replay", {"attempt": index}, **_binding())

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        results = list(pool.map(submit, range(len(stores))))
    assert sum(created for _, created in results) == 1
    assert all(snapshot == results[0][0] for snapshot, _ in results)
    assert len(stores[0].list_jobs()) == 1


def test_duplicate_returns_while_queue_full_without_replacing_approval_callback(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "product.db")
    called: list[Mapping[str, Any]] = []

    def original(context: JobContext, request: Mapping[str, Any]) -> str:
        called.append(request)
        return "run-result"

    def replacement(context: JobContext, request: Mapping[str, Any]) -> None:
        pytest.fail("duplicate must never replace or enqueue a callback")

    with RunJobController(store, original, max_workers=1, max_pending_jobs=1) as controller:
        job = controller.submit("run.replay", REQUEST, requires_approval=True, **_binding())
        awaiting = controller.wait_for_state(job["job_id"], {JobState.AWAITING_APPROVAL}, timeout=3)
        duplicate = controller.submit(
            "run.replay", {}, callback=replacement, requires_approval=False, **_binding()
        )
        assert duplicate == awaiting
        assert called == []
        with pytest.raises(JobQueueFull):
            controller.submit(
                "run.replay", {}, submission_id=str(uuid.uuid4()), intent_digest=INTENT_DIGEST
            )
        assert len(store.list_jobs()) == 1
        controller.approve(job["job_id"])
        completed = controller.wait(job["job_id"], timeout=3)
        assert completed["result_ref"] == "run-result"
        assert controller.submit("run.replay", {}, **_binding()) == completed
    assert len(called) == 1
    assert called[0]["source_run_id"] == REQUEST["source_run_id"]


def test_racing_controllers_enqueue_only_creator_and_release_losing_slot(tmp_path: Path) -> None:
    barrier = threading.Barrier(2)

    class RacingStore(ProductStore):
        def get_job_submission(
            self, kind: str, *, submission_id: str, intent_digest: str
        ) -> Mapping[str, Any] | None:
            result = super().get_job_submission(
                kind, submission_id=submission_id, intent_digest=intent_digest
            )
            barrier.wait(timeout=5)
            return result

    stores = [RacingStore(tmp_path / "product.db") for _ in range(2)]

    def callback(context: JobContext, request: Mapping[str, Any]) -> None:
        pytest.fail("all jobs in this test await explicit approval")

    controllers = [
        RunJobController(store, callback, max_workers=1, max_pending_jobs=1, recover_on_start=False)
        for store in stores
    ]
    try:

        def submit(controller: RunJobController) -> Mapping[str, Any]:
            return controller.submit("run.replay", REQUEST, requires_approval=True, **_binding())

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, controllers))
        assert results[0]["job_id"] == results[1]["job_id"]
        assert sorted(len(controller.active_job_ids) for controller in controllers) == [0, 1]
        loser = next(controller for controller in controllers if not controller.active_job_ids)
        ordinary = loser.submit("run.ordinary", {}, requires_approval=True)
        assert ordinary["job_id"] != results[0]["job_id"]
        assert len(stores[0].list_jobs()) == 2
    finally:
        for controller in controllers:
            controller.shutdown()


@pytest.mark.parametrize("missing", ["submission_id", "intent_digest"])
def test_controller_requires_both_submission_arguments(tmp_path: Path, missing: str) -> None:
    store = ProductStore(tmp_path / "product.db")
    binding = _binding()
    binding.pop(missing)
    with RunJobController(store, lambda context, request: None) as controller:
        with pytest.raises(ValueError, match="together"):
            controller.submit("run.replay", REQUEST, **binding)
    assert store.list_jobs() == []


def test_scheduling_failure_is_terminal_and_frees_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ProductStore(tmp_path / "product.db")
    with RunJobController(
        store, lambda context, request: "run-result", max_workers=1, max_pending_jobs=1
    ) as controller:
        submit = controller._executor.submit

        def fail(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("private scheduler detail")

        monkeypatch.setattr(controller._executor, "submit", fail)
        with pytest.raises(RuntimeError, match="private scheduler detail"):
            controller.submit("run.replay", REQUEST, **_binding())
        failed = store.get_job_submission("run.replay", **_binding())
        assert failed is not None and failed["state"] == "failed"
        assert failed["error"] == {
            "code": "job_scheduling_failed",
            "message": "background job could not be scheduled",
        }
        assert controller.active_job_ids == ()
        assert controller.submit("run.replay", REQUEST, **_binding()) == failed
        monkeypatch.setattr(controller._executor, "submit", submit)
        ordinary = controller.submit("run.ordinary", {})
        assert controller.wait(ordinary["job_id"], timeout=3)["state"] == "completed"


def test_store_failure_frees_capacity_and_does_not_claim_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ProductStore(tmp_path / "product.db")
    with RunJobController(
        store, lambda context, request: "run-result", max_workers=1, max_pending_jobs=1
    ) as controller:
        create = store.create_idempotent_job

        def fail(*args: Any, **kwargs: Any) -> None:
            raise ProductStoreError("test store failure")

        monkeypatch.setattr(store, "create_idempotent_job", fail)
        with pytest.raises(ProductStoreError, match="test store failure"):
            controller.submit("run.replay", REQUEST, **_binding())
        assert store.get_job_submission("run.replay", **_binding()) is None
        assert controller.active_job_ids == ()
        monkeypatch.setattr(store, "create_idempotent_job", create)
        job = controller.submit("run.replay", REQUEST, **_binding())
        assert controller.wait(job["job_id"], timeout=3)["state"] == "completed"


def test_failure_after_insert_rolls_back_the_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ProductStore(tmp_path / "product.db")

    def fail(row: Any) -> Mapping[str, Any]:
        raise ProductStoreError("test snapshot failure after insert")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_job_from_row", fail)
        with pytest.raises(ProductStoreError, match="snapshot failure"):
            store.create_idempotent_job("run.replay", REQUEST, **_binding())
    assert store.get_job_submission("run.replay", **_binding()) is None
    assert store.list_jobs() == []
    _, created = store.create_idempotent_job("run.replay", REQUEST, **_binding())
    assert created


def test_duplicate_committed_between_lookup_and_capacity_refusal_is_returned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ProductStore(tmp_path / "product.db")
    with RunJobController(
        store, lambda context, request: None, max_workers=1, max_pending_jobs=1
    ) as controller:
        controller.submit("run.ordinary", {}, requires_approval=True)
        duplicate, _ = store.create_idempotent_job("run.replay", REQUEST, **_binding())
        lookup = store.get_job_submission
        lookups = 0

        def raced_lookup(
            kind: str, *, submission_id: str, intent_digest: str
        ) -> Mapping[str, Any] | None:
            nonlocal lookups
            lookups += 1
            if lookups == 1:
                return None
            return lookup(kind, submission_id=submission_id, intent_digest=intent_digest)

        monkeypatch.setattr(store, "get_job_submission", raced_lookup)
        assert controller.submit("run.replay", REQUEST, **_binding()) == duplicate
        assert lookups == 2
        assert duplicate["job_id"] not in controller.active_job_ids
        assert len(store.list_jobs()) == 2


def test_recovery_returns_interrupted_submission_without_rescheduling(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "product.db")
    job, _ = store.create_idempotent_job("run.replay", REQUEST, **_binding())
    calls: list[str] = []

    def execute(context: JobContext, request: Mapping[str, Any]) -> None:
        calls.append(context.job_id)

    with RunJobController(ProductStore(store.path), execute) as controller:
        assert controller.recovered_jobs == 1
        duplicate = controller.submit("run.replay", REQUEST, **_binding())
        assert duplicate["job_id"] == job["job_id"]
        assert duplicate["state"] == "interrupted"
        assert controller.active_job_ids == ()
    assert calls == []


def test_ordinary_submissions_remain_distinct_and_undecorated(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "product.db")
    with RunJobController(store, lambda context, request: None) as controller:
        first = controller.submit("run.ordinary", REQUEST)
        second = controller.submit("run.ordinary", REQUEST)
        assert first["job_id"] != second["job_id"]
        assert first["request"] == second["request"] == REQUEST
        assert controller.wait(first["job_id"], timeout=3)["state"] == "completed"
        assert controller.wait(second["job_id"], timeout=3)["state"] == "completed"
