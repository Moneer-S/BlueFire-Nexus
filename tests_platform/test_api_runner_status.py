"""Profile-specific read-only runner readiness uses native enrollment checks."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError
from bluefire.service import BlueFireService
from tests_platform.test_api import request, running_server
from tests_platform.test_runner_lifecycle import PROFILE_ID, _bootstrap
from tests_platform.test_runner_lifecycle import lifecycle as lifecycle
from tests_platform.test_runner_lifecycle import secret_provider as secret_provider

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "query,expected",
    [("", None), ("?", None), ("?profile_id=sandbox-execute.v1", "sandbox-execute.v1")],
)
def test_status_dispatches_exact_optional_profile(query, expected):
    with running_server() as (server, service):
        code, _, body = request(server, "GET", "/api/v1/runner" + query)
        assert code == 200 and json.loads(body)["state"] == "ready"
        assert service.calls == [("runner_status", expected)]


@pytest.mark.parametrize(
    "query",
    [
        "?profile_id=",
        "?profile_id",
        "?profile_id=a.v1&profile_id=b.v1",
        "?profile_id=a.v1&profile_id=a.v1",
        "?unknown=a.v1",
        "?profile_id=a.v1&extra=true",
        "?profile_id=../profile",
        "?profile_id=%2Ftmp",
        "?profile_id=white+space",
        "?profile_id=%00",
        "?profile_id=%FF",
        "?profile_id=%zz",
        "?profile_id=a.v1#fragment",
        "?profile_id=" + "a" * 201,
    ],
)
def test_invalid_status_queries_refuse_without_dispatch(query):
    with running_server() as (server, service):
        code, _, body = request(server, "GET", "/api/v1/runner" + query)
        assert code == 400
        assert json.loads(body)["error"]["code"] == "invalid_runner_status_query"
        assert not service.calls


def test_unknown_profile_uses_real_service_validation_before_lifecycle(tmp_path, monkeypatch):
    lifecycle = ManagedRunnerLifecycle(tmp_path / "managed")
    monkeypatch.setattr(
        lifecycle, "status", lambda **_kw: pytest.fail("Unknown profile must not query lifecycle")
    )
    service = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", runner_lifecycle=lifecycle
    )
    try:
        with running_server(service) as (server, _):
            code, _, body = request(server, "GET", "/api/v1/runner?profile_id=unknown-profile.v1")
            assert code == 404 and json.loads(body)["error"]["code"] == "profile_not_found"
    finally:
        service.close()
    assert not lifecycle.root.exists()


def test_selected_unenrolled_profile_cannot_borrow_ready_profile(lifecycle, monkeypatch):
    _bootstrap(lifecycle)
    called = []
    monkeypatch.setattr(lifecycle, "_authenticated_health", lambda *_args: called.append(True))
    assert lifecycle.status(profile_id=PROFILE_ID)["profile_id"] == PROFILE_ID
    assert lifecycle.status(profile_id=PROFILE_ID)["state"] == "stopped"
    for operation in (
        lifecycle.status,
        lambda **kw: lifecycle.client_for_profile(kw["profile_id"]),
    ):
        with pytest.raises(RunnerLifecycleError, match="not enrolled"):
            operation(profile_id="new-unenrolled-profile.v1")
    assert called == []


def test_http_selected_profile_checks_actual_enrollment_before_readiness(lifecycle, tmp_path):
    _bootstrap(lifecycle)
    service = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", runner_lifecycle=lifecycle
    )
    profile = next(row for row in service._runner_profiles() if row.id == PROFILE_ID)
    # A new configured profile does not acquire an older enrollment's authority.
    added = replace(profile, id="configured-unenrolled.v1")
    service._runtime_runner_profiles = (*service._runner_profiles(), added)
    try:
        with running_server(service) as (server, _):
            code, _, body = request(server, "GET", "/api/v1/runner?profile_id=" + PROFILE_ID)
            status = json.loads(body)
            assert (
                code == 200 and status["profile_id"] == PROFILE_ID and status["state"] == "stopped"
            )
            code, _, body = request(server, "GET", "/api/v1/runner?profile_id=" + added.id)
            refusal = json.loads(body)["error"]
            assert code == 409 and refusal["code"] == "runner_lifecycle_unavailable"
            assert refusal["details"] == ["Runner profile is not enrolled."]
    finally:
        service.close()
