"""Canonical local-service routing for external-engine experiments."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from bluefire.api_routes import APIRoutes
from bluefire.application_errors import APIError
from bluefire.engine_experiment_api import dispatch_engine_experiments
from bluefire.engine_experiment_service import EngineExperimentServiceError

ROOT = "/api/v1/engine-experiments"
EXPERIMENT = "experiment-" + "1" * 32
ATTEMPT = "engine-attempt-" + "2" * 32
CHECK = "controller-check-" + "5" * 32
DIGEST = "sha256:" + "a" * 64


class _Service:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def list(self, *, limit: int = 100):
        self.calls.append(("list", limit))
        return {"listed": True}

    def get(self, experiment_id: str):
        self.calls.append(("get", experiment_id))
        return {"read": True}

    def workspace(
        self,
        experiment_id: str,
        *,
        selected_attempt_id: str | None = None,
        selected_check_id: str | None = None,
    ):
        self.calls.append(("workspace", experiment_id, selected_attempt_id, selected_check_id))
        return {"workspace": True}

    def create_request(self, request: Mapping[str, Any]):
        self.calls.append(("create_request", request))
        return {"created": True}

    def submit_attempt_request(self, request: Mapping[str, Any]):
        self.calls.append(("submit_attempt_request", request))
        return {"submitted": True}

    def recover_attempt(self, *, experiment_id: str, attempt_id: str):
        self.calls.append(("recover_attempt", experiment_id, attempt_id))
        return {"recovered": True}

    def perform_controller_transition_request(
        self,
        experiment_id: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("perform_controller_transition_request", experiment_id, request))
        return {"transitioned": True}

    def submit_controller_operation_request(
        self,
        experiment_id: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("submit_controller_operation_request", experiment_id, request))
        return {"job_id": "job-" + "4" * 32}


class _Handler:
    def __init__(self, path: str) -> None:
        self.path = path
        self.service = _Service()
        self.platform_server = SimpleNamespace(
            service=SimpleNamespace(engine_experiment_service=self.service)
        )
        self.errors: list[tuple[int, str, str]] = []
        self.allowed: list[str] = []
        self.responses: list[Mapping[str, Any]] = []

    @property
    def _routes(self) -> APIRoutes:
        return APIRoutes(self)

    def _error(self, status: int, code: str, message: str) -> None:
        self.errors.append((status, code, message))

    def _method_not_allowed(self, allow: str) -> None:
        self.allowed.append(allow)

    def _dispatch(self, callback) -> None:
        self.responses.append(callback())


def _create_request() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-experiment-create.v1",
        "experiment_id": EXPERIMENT,
        "objective_ref": DIGEST,
        "environment_ref": DIGEST,
        "scope_ref": DIGEST,
        "scope_version": "bluefire.engine-capability-delegation.v1",
        "target_snapshot_ref": DIGEST,
    }


def _attempt_request() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-attempt-submit.v1",
        "experiment_id": EXPERIMENT,
        "binding": {},
        "delegation": {},
        "approval_binding": {},
        "approval_id": "approval-" + "3" * 32,
        "approval_nonce": "one-time-nonce",
        "approved_by": "Test operator",
        "submission_id": "12345678-1234-4123-8123-123456789abc",
        "intent_digest": DIGEST,
        "expected_revision": 1,
        "expected_digest": DIGEST,
    }


def _transition_request(action: str = "review_defense") -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-controller-transition.v1",
        "expected_revision": 2,
        "expected_digest": DIGEST,
        "action": action,
        "request_ref": DIGEST,
    }


def _controller_job_request(action: str) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-controller-job-submit.v1",
        "expected_revision": 2,
        "expected_digest": DIGEST,
        "action": action,
        "request_ref": DIGEST,
        "submission_id": "22345678-1234-4123-8123-123456789abc",
        "intent_digest": DIGEST,
    }


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (ROOT, ("list", 100)),
        (f"{ROOT}/{EXPERIMENT}", ("get", EXPERIMENT)),
        (
            f"{ROOT}/{EXPERIMENT}/workspace",
            ("workspace", EXPERIMENT, None, None),
        ),
    ],
)
def test_engine_reads_dispatch_only_canonical_paths(path: str, expected: tuple[Any, ...]) -> None:
    handler = _Handler(path)
    assert dispatch_engine_experiments(handler, path)
    assert handler.service.calls == [expected]
    assert handler.errors == [] and handler.allowed == []


def test_engine_creation_and_attempt_submission_keep_exact_envelopes() -> None:
    create = _create_request()
    handler = _Handler(ROOT)
    assert dispatch_engine_experiments(handler, ROOT, create)
    assert handler.service.calls == [("create_request", create)]

    attempt = _attempt_request()
    path = f"{ROOT}/{EXPERIMENT}/attempts"
    handler = _Handler(path)
    assert dispatch_engine_experiments(handler, path, attempt)
    assert handler.service.calls == [("submit_attempt_request", attempt)]


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("attempt", ATTEMPT, (ATTEMPT, None)),
        ("check", CHECK, (None, CHECK)),
    ],
)
def test_workspace_selection_binds_one_exact_saved_item(key, value, expected) -> None:
    path = f"{ROOT}/{EXPERIMENT}/workspace"
    handler = _Handler(f"{path}?{key}={value}")
    assert dispatch_engine_experiments(handler, path)
    assert handler.service.calls == [("workspace", EXPERIMENT, expected[0], expected[1])]


@pytest.mark.parametrize(
    "query",
    [
        "attempt=",
        f"attempt={ATTEMPT}&check={CHECK}",
        f"attempt={ATTEMPT}&attempt={ATTEMPT}",
        f"unknown={ATTEMPT}",
        "attempt=engine-attempt-invalid",
        f"attempt=engine%2Dattempt-{ATTEMPT.removeprefix('engine-attempt-')}",
    ],
)
def test_workspace_selection_rejects_ambiguous_or_noncanonical_queries(query) -> None:
    path = f"{ROOT}/{EXPERIMENT}/workspace"
    handler = _Handler(f"{path}?{query}")
    assert dispatch_engine_experiments(handler, path)
    assert handler.service.calls == []
    assert handler.errors[0][1] == "engine_experiment_invalid"


@pytest.mark.parametrize("field", sorted(_create_request()))
def test_engine_creation_rejects_missing_fields(field: str) -> None:
    body = _create_request()
    del body[field]
    handler = _Handler(ROOT)
    assert dispatch_engine_experiments(handler, ROOT, body)
    assert handler.service.calls == []
    assert handler.errors[0][1] == "engine_experiment_invalid"


def test_engine_creation_rejects_client_supplied_chronology() -> None:
    body = _create_request()
    body["created_at"] = "2026-11-04T12:00:00Z"
    handler = _Handler(ROOT)
    assert dispatch_engine_experiments(handler, ROOT, body)
    assert handler.service.calls == []
    assert handler.errors[0][1] == "engine_experiment_invalid"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda body: body.update(extra=True),
        lambda body: body.update(expected_revision=True),
        lambda body: body.update(submission_id="not-a-uuid"),
        lambda body: body.update(approval_id="approval-invalid"),
        lambda body: body.update(binding=[]),
        lambda body: body.update(intent_digest="not-a-digest"),
    ],
)
def test_engine_attempt_rejects_ambiguous_or_malformed_envelopes(mutation) -> None:
    body = _attempt_request()
    mutation(body)
    path = f"{ROOT}/{EXPERIMENT}/attempts"
    handler = _Handler(path)
    assert dispatch_engine_experiments(handler, path, body)
    assert handler.service.calls == []
    assert handler.errors[0][1] == "engine_experiment_invalid"


@pytest.mark.parametrize(
    ("path_action", "wire_action", "operation"),
    [
        ("review", "review_defense", "transition"),
        ("retain", "retain_defense", "transition"),
        ("apply", "apply_defense", "controller-job"),
        ("reconcile", "reconcile_defense", "controller-job"),
        ("rollback", "rollback_defense", "controller-job"),
        ("rollback-reconcile", "reconcile_rollback", "controller-job"),
    ],
)
def test_defense_transitions_forward_only_cas_bound_request_refs(
    path_action: str, wire_action: str, operation: str
) -> None:
    body = (
        _transition_request(wire_action)
        if operation == "transition"
        else _controller_job_request(wire_action)
    )
    path = f"{ROOT}/{EXPERIMENT}/defense/{path_action}"
    handler = _Handler(path)
    assert dispatch_engine_experiments(handler, path, body)
    method = (
        "perform_controller_transition_request"
        if operation == "transition"
        else "submit_controller_operation_request"
    )
    assert handler.service.calls == [(method, EXPERIMENT, body)]


@pytest.mark.parametrize("role", ["retained-reproducer", "legitimate-use"])
@pytest.mark.parametrize("action", ["run", "recover"])
def test_controller_checks_use_custodied_jobs(role: str, action: str) -> None:
    role_wire = role.replace("-", "_")
    prefix = {"run": "run", "recover": "reconcile"}[action]
    wire_action = f"{prefix}_{role_wire}"
    body = _controller_job_request(wire_action)
    path = f"{ROOT}/{EXPERIMENT}/checks/{role}/{action}"
    handler = _Handler(path)
    assert dispatch_engine_experiments(handler, path, body)
    assert handler.service.calls == [("submit_controller_operation_request", EXPERIMENT, body)]


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (
            f"{ROOT}/{EXPERIMENT}/defense/review",
            _transition_request("record_observation"),
        ),
        (
            f"{ROOT}/{EXPERIMENT}/defense/apply",
            _controller_job_request("rollback_defense"),
        ),
        (
            f"{ROOT}/{EXPERIMENT}/checks/legitimate-use/run",
            _controller_job_request("run_retained_reproducer"),
        ),
    ],
)
def test_path_binding_rejects_other_controller_authority(path, body) -> None:
    handler = _Handler(path)
    assert dispatch_engine_experiments(handler, path, body)
    assert handler.service.calls == []
    assert handler.errors[0][1] == "engine_experiment_invalid"


def test_attempt_recovery_is_empty_and_cannot_replace_state() -> None:
    path = f"{ROOT}/{EXPERIMENT}/attempts/{ATTEMPT}/recover"
    handler = _Handler(path)
    assert dispatch_engine_experiments(handler, path, {})
    assert handler.service.calls == [("recover_attempt", EXPERIMENT, ATTEMPT)]

    handler = _Handler(path)
    assert dispatch_engine_experiments(handler, path, {"replacement": True})
    assert handler.service.calls == []
    assert handler.errors[0][1] == "engine_experiment_invalid"


@pytest.mark.parametrize(
    "suffix",
    [
        f"/{EXPERIMENT.upper()}",
        "/experiment-invalid",
        f"/{EXPERIMENT}/attempts/engine-attempt-invalid/recover",
        f"/{EXPERIMENT}/evidence",
        f"/{EXPERIMENT}/independent-observations",
        f"/{EXPERIMENT}/defense/execute",
        f"/{EXPERIMENT}/checks/retained-reproducer/publish-evidence",
        f"/{EXPERIMENT}/checks/retained-reproducer/settle",
        f"/{EXPERIMENT}/assistant-context",
        "/",
    ],
)
def test_unknown_or_authority_expanding_paths_never_dispatch(suffix: str) -> None:
    path = ROOT + suffix
    handler = _Handler(path)
    assert dispatch_engine_experiments(handler, path)
    assert handler.service.calls == []
    assert handler.errors[0][1] == "engine_experiment_invalid"


@pytest.mark.parametrize(
    ("path", "body", "allowed"),
    [
        (ROOT, None, None),
        (f"{ROOT}/{EXPERIMENT}", {}, "GET"),
        (f"{ROOT}/{EXPERIMENT}/workspace", {}, "GET"),
        (f"{ROOT}/{EXPERIMENT}/attempts", None, "POST"),
        (f"{ROOT}/{EXPERIMENT}/defense/review", None, "POST"),
    ],
)
def test_engine_routes_do_not_confuse_reads_and_commands(path, body, allowed) -> None:
    handler = _Handler(path)
    assert dispatch_engine_experiments(handler, path, body)
    if path == ROOT and body is None:
        assert handler.service.calls == [("list", 100)]
    else:
        assert handler.service.calls == []
        assert handler.allowed == [allowed]


def test_query_and_encoded_command_paths_never_dispatch() -> None:
    raw = f"{ROOT}/{EXPERIMENT}%2Fdefense%2Fapply"
    decoded = f"{ROOT}/{EXPERIMENT}/defense/apply"
    handler = _Handler(raw)
    assert dispatch_engine_experiments(
        handler,
        decoded,
        _controller_job_request("apply_defense"),
    )
    assert handler.service.calls == []
    assert handler.errors[0][1] == "engine_experiment_invalid"

    handler = _Handler(ROOT + "?limit=1000")
    assert dispatch_engine_experiments(handler, ROOT)
    assert handler.service.calls == []
    assert handler.errors[0][1] == "invalid_management_query"


def test_service_refusals_keep_stable_safe_api_codes() -> None:
    handler = _Handler(f"{ROOT}/{EXPERIMENT}")
    handler.service.get = lambda _identifier: (_ for _ in ()).throw(
        EngineExperimentServiceError(
            "engine_experiment_conflict",
            "The experiment changed after review.",
        )
    )
    with pytest.raises(APIError) as caught:
        dispatch_engine_experiments(handler, handler.path)
    assert caught.value.status == 409
    assert caught.value.code == "engine_experiment_conflict"
    assert caught.value.message == "The experiment changed after review."


def test_unknown_service_errors_do_not_echo_diagnostics() -> None:
    handler = _Handler(f"{ROOT}/{EXPERIMENT}")
    handler.service.get = lambda _identifier: (_ for _ in ()).throw(
        EngineExperimentServiceError("private_new_code", "private adapter path")
    )
    with pytest.raises(APIError) as caught:
        dispatch_engine_experiments(handler, handler.path)
    assert caught.value.status == 500
    assert caught.value.code == "engine_service_error"
    assert "private adapter path" not in caught.value.message


def test_unknown_workspace_selection_is_a_stable_not_found() -> None:
    path = f"{ROOT}/{EXPERIMENT}/workspace"
    handler = _Handler(f"{path}?attempt={ATTEMPT}")
    handler.service.workspace = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        EngineExperimentServiceError(
            "engine_selection_not_found",
            "The selected engine experiment item was not found.",
        )
    )
    with pytest.raises(APIError) as caught:
        dispatch_engine_experiments(handler, path)
    assert caught.value.status == 404
    assert caught.value.code == "engine_selection_not_found"


def test_non_engine_route_falls_through_without_side_effects() -> None:
    handler = _Handler("/api/v1/runs")
    assert not dispatch_engine_experiments(handler, "/api/v1/runs")
    assert handler.service.calls == [] and handler.errors == []
