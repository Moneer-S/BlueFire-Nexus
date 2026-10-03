"""Profile-specific read-only runner readiness uses native enrollment checks."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

import bluefire.api_routes as api_routes
from bluefire.runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError
from bluefire.runner_trust import load_local_enrollment
from bluefire.service import BlueFireService
from tests_platform.test_api import request, running_server
from tests_platform.test_runner_lifecycle import PROFILE_ID, _bootstrap
from tests_platform.test_runner_lifecycle import lifecycle as lifecycle
from tests_platform.test_runner_lifecycle import secret_provider as secret_provider

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "suffix,status", [("", 200), ("?", 200), ("#fragment", 400), ("?#fragment", 400)]
)
def test_empty_query_bypasses_strict_parser_after_fragment_refusal(monkeypatch, suffix, status):
    def strict_parser_must_not_run(*_args, **_kwargs):
        pytest.fail("Empty queries must not reach version-dependent strict parsing")

    monkeypatch.setattr(api_routes, "parse_qsl", strict_parser_must_not_run)
    with running_server() as (server, service):
        code, _, body = request(server, "GET", "/api/v1/runner" + suffix)
        assert code == status
        if status == 200:
            assert service.calls == [("runner_status", None)]
        else:
            assert not service.calls
            assert json.loads(body)["error"]["code"] == "invalid_runner_status_query"


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


@pytest.mark.parametrize("process_record_present", [False, True])
def test_selected_unenrolled_profile_cannot_borrow_ready_profile(
    lifecycle, monkeypatch, secret_provider, process_record_present
):
    _bootstrap(lifecycle)
    called = []
    monkeypatch.setattr(lifecycle, "_authenticated_health", lambda *_args: called.append(True))
    assert lifecycle.status(profile_id=PROFILE_ID)["profile_id"] == PROFILE_ID
    assert lifecycle.status(profile_id=PROFILE_ID)["state"] == "stopped"
    before = lifecycle.bootstrap_record_path.read_bytes()
    if process_record_present:
        # Presence alone cannot establish whether the shared host is absent or ready.
        lifecycle.process_record_path.write_text("{}", encoding="utf-8")
    status = lifecycle.status(profile_id="new-unenrolled-profile.v1")
    assert status["state"] == "unavailable"
    assert status["profile_id"] == "new-unenrolled-profile.v1"
    assert status["process"] == "unavailable"
    assert status["health"] is None and status["runner"] is None
    assert status["profile_enrollment"] == {
        "state": "not_enrolled",
        "enrolled_profile_ids": [PROFILE_ID],
    }
    for operation in (
        lifecycle.start,
        lambda **kw: lifecycle.client_for_profile(kw["profile_id"]),
    ):
        with pytest.raises(RunnerLifecycleError, match="not enrolled"):
            operation(profile_id="new-unenrolled-profile.v1")
    assert called == []
    assert lifecycle.bootstrap_record_path.read_bytes() == before
    assert load_local_enrollment(
        lifecycle.enrollment_root, secret_provider=secret_provider
    ).allowed_profile_ids == (PROFILE_ID,)


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
            status = json.loads(body)
            assert code == 200 and status["state"] == "unavailable"
            assert status["profile_id"] == added.id
            assert status["process"] == "unavailable" and status["health"] is None
            assert status["profile_enrollment"] == {
                "state": "not_enrolled",
                "enrolled_profile_ids": [PROFILE_ID],
            }
            assert str(tmp_path) not in body.decode()
            assert service._runtime_runner_profiles[-1] == added
    finally:
        service.close()


def test_unenrolled_profile_recovery_requires_explicit_trust_replacement(
    lifecycle, secret_provider, monkeypatch
):
    _bootstrap(lifecycle)
    added = "new-unenrolled-profile.v1"
    profiles = (PROFILE_ID, added)
    monkeypatch.setattr(
        lifecycle, "_authenticated_health", lambda *_args: pytest.fail("No host probe authorized")
    )
    with pytest.raises(RunnerLifecycleError, match="does not match"):
        lifecycle.bootstrap(allowed_profile_ids=profiles, profile_id=added)
    assert lifecycle.status(profile_id=added)["profile_enrollment"]["state"] == "not_enrolled"
    with pytest.raises(RunnerLifecycleError, match="revoked"):
        lifecycle.remove(confirm_runner_id=lifecycle.runner_id)
    revoked = lifecycle.revoke()
    assert revoked["enrollment"] == "revoked"
    assert lifecycle.status(profile_id=added)["process"] == "unavailable"
    with pytest.raises(RunnerLifecycleError):
        lifecycle.remove(confirm_runner_id="wrong-runner.v1")
    assert lifecycle.remove(confirm_runner_id=lifecycle.runner_id)["state"] == "unbootstrapped"
    status = lifecycle.bootstrap(allowed_profile_ids=profiles, profile_id=added)
    assert status["profile_id"] == added and status["state"] == "stopped"
    assert status["process"] == "absent" and status["health"] is None
    assert "profile_enrollment" not in status
    assert (
        load_local_enrollment(
            lifecycle.enrollment_root, secret_provider=secret_provider
        ).allowed_profile_ids
        == profiles
    )


def test_unverified_bootstrap_never_offers_enrollment_recovery(lifecycle):
    _bootstrap(lifecycle)
    lifecycle.bootstrap_record_path.write_text("{}", encoding="utf-8")
    status = lifecycle.status(profile_id="new-unenrolled-profile.v1")
    assert status["state"] == "unavailable"
    assert status["process"] == "unavailable"
    assert "profile_enrollment" not in status


@pytest.mark.parametrize("selected", [PROFILE_ID, "new-unenrolled-profile.v1"])
def test_pending_upgrade_preserves_selected_profile_enrollment(lifecycle, monkeypatch, selected):
    _bootstrap(lifecycle)
    before = lifecycle.bootstrap_record_path.read_bytes()
    monkeypatch.setattr("bluefire.runner_lifecycle.pending_upgrade", lambda _lifecycle: True)
    monkeypatch.setattr(
        lifecycle, "_authenticated_health", lambda *_args: pytest.fail("No host probe authorized")
    )
    status = lifecycle.status(profile_id=selected)
    assert status["state"] == "unavailable"
    assert status["process"] == "absent"
    assert status["upgrade_recovery_required"] is True
    assert status["profile_id"] == selected
    assert status["health"] is None
    if selected == PROFILE_ID:
        assert "profile_enrollment" not in status
    else:
        assert status["profile_enrollment"] == {
            "state": "not_enrolled",
            "enrolled_profile_ids": [PROFILE_ID],
        }
    assert lifecycle.bootstrap_record_path.read_bytes() == before
