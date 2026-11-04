"""Prepared-action admission stays inert until trusted installed composition binds it."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from bluefire.engine_action_preparation import EngineActionPreparationServiceError
from bluefire.engine_action_submission import EngineActionSubmissionServiceError
from bluefire.engine_experiment_service import EngineExperimentServiceError
from bluefire.service import BlueFireService

EXPERIMENT = "experiment-" + "1" * 32
DIGEST = "sha256:" + "a" * 64
PREPARE_REQUEST = {
    "schema_version": "bluefire.engine-action-prepare-request.v1",
    "expected_revision": 1,
    "expected_digest": DIGEST,
    "workspace_digest": DIGEST,
}
SUBMIT_REQUEST = {
    "schema_version": "bluefire.engine-action-submit.v1",
    "preparation_id": DIGEST,
    "protected_request_ref": DIGEST,
}


def _service(tmp_path: Path, **values: Any) -> BlueFireService:
    return BlueFireService(
        project_root=Path(__file__).resolve().parents[1],
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "state" / "bluefire.sqlite3",
        **values,
    )


def test_default_product_composition_keeps_prepared_action_admission_unavailable(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    try:
        for method, request in (
            (service.engine_experiment_service.prepare_action_request, PREPARE_REQUEST),
            (service.engine_experiment_service.submit_prepared_action_request, SUBMIT_REQUEST),
        ):
            with pytest.raises(EngineExperimentServiceError) as caught:
                method(EXPERIMENT, request)
            assert caught.value.code == "engine_action_unavailable"

        assert service.product_store.list_jobs() == []
        assert service.product_store.list_engine_experiments() == []
        with service.product_store._connection() as connection:
            assert connection.execute("SELECT count(*) FROM approval_requests").fetchone()[0] == 0
            assert (
                connection.execute("SELECT count(*) FROM engine_action_preparations").fetchone()[0]
                == 0
            )
            assert (
                connection.execute("SELECT count(*) FROM engine_action_acceptances").fetchone()[0]
                == 0
            )
    finally:
        service.close()


def test_trusted_factories_receive_shared_composition_and_bind_exact_coordinators(
    tmp_path: Path,
) -> None:
    preparation_calls = []
    submission_calls = []
    factory_calls = []

    class Preparation:
        def prepare_request(self, experiment_id, request):
            preparation_calls.append((experiment_id, request))
            return {"prepared": True}

    class Submission:
        def submit(self, *, experiment_id, request):
            submission_calls.append((experiment_id, request))
            return {"accepted": True}

    class ControllerJobs:
        def submit(self, **_values):
            raise AssertionError("composition must not dispatch a controller effect")

    preparation = Preparation()
    submission = Submission()
    controller_jobs = ControllerJobs()

    def preparation_factory(store, workspace_source):
        factory_calls.append(("prepare", store, workspace_source))
        return preparation

    def submission_factory(store, workspace_source, jobs, configured_controller_jobs):
        factory_calls.append(("submit", store, workspace_source, jobs, configured_controller_jobs))
        return submission

    service = _service(
        tmp_path,
        engine_controller_jobs=controller_jobs,
        engine_action_preparation_factory=preparation_factory,
        engine_action_submission_factory=submission_factory,
    )
    try:
        engine_service = service.engine_experiment_service
        assert factory_calls == [
            ("prepare", service.product_store, engine_service),
            (
                "submit",
                service.product_store,
                engine_service,
                service.engine_attempt_jobs,
                controller_jobs,
            ),
        ]
        assert preparation_calls == [] and submission_calls == []
        assert engine_service.prepare_action_request(EXPERIMENT, PREPARE_REQUEST) == {
            "prepared": True
        }
        assert engine_service.submit_prepared_action_request(EXPERIMENT, SUBMIT_REQUEST) == {
            "accepted": True
        }
        assert preparation_calls == [(EXPERIMENT, PREPARE_REQUEST)]
        assert preparation_calls[0][1] is PREPARE_REQUEST
        assert submission_calls == [(EXPERIMENT, SUBMIT_REQUEST)]
        assert submission_calls[0][1] is SUBMIT_REQUEST
        assert service.product_store.list_jobs() == []
    finally:
        service.close()


@pytest.mark.parametrize("configured", ["preparation", "submission"])
def test_each_action_factory_is_independent_and_keeps_safe_error_mapping(
    tmp_path: Path,
    configured: str,
) -> None:
    class Preparation:
        def prepare_request(self, _experiment_id, _request):
            raise EngineActionPreparationServiceError(
                "engine_action_preparation_refused", "The action preparation was refused."
            )

    class Submission:
        def submit(self, **_values):
            raise EngineActionSubmissionServiceError(
                "engine_action_submission_refused", "The action submission was refused."
            )

    factories = (
        {"engine_action_preparation_factory": lambda *_args: Preparation()}
        if configured == "preparation"
        else {"engine_action_submission_factory": lambda *_args: Submission()}
    )
    service = _service(tmp_path, **factories)
    try:
        engine_service = service.engine_experiment_service
        for method, request, kind in (
            (engine_service.prepare_action_request, PREPARE_REQUEST, "preparation"),
            (engine_service.submit_prepared_action_request, SUBMIT_REQUEST, "submission"),
        ):
            with pytest.raises(EngineExperimentServiceError) as caught:
                method(EXPERIMENT, request)
            assert caught.value.code == (
                f"engine_action_{kind}_refused"
                if kind == configured
                else "engine_action_unavailable"
            )
        assert service.product_store.list_jobs() == []
    finally:
        service.close()
