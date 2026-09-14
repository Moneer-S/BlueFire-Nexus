"""Normal authenticated loopback HTTP preparation; no runner/effect launch."""

import json

import pytest

from tests_platform.test_api import RUN_ID, request, running_server


def test_replay_preparation_route_forwards_the_exact_request_without_replay():
    payload = {"exact": False, "parameter_overrides": {"create_fixture": {"record_count": 3}}}
    with running_server() as (server, service):
        status, _, body = request(
            server, "POST", f"/api/v1/runs/{RUN_ID}/replay-preparations", body=payload
        )
    assert status == 200
    assert json.loads(body) == {
        "schema_version": "bluefire.replay-preparation.v1",
        "effects_started": False,
    }
    assert service.calls == [("prepare_replay", RUN_ID, payload)]


@pytest.mark.parametrize("method,suffix,status", [("GET", "", 405), ("POST", "?exact=true", 400)])
def test_replay_preparation_method_and_query_cannot_bypass_body_review(method, suffix, status):
    with running_server() as (server, service):
        actual, _, _ = request(
            server,
            method,
            f"/api/v1/runs/{RUN_ID}/replay-preparations{suffix}",
            body={} if method == "POST" else None,
        )
    assert actual == status
    assert service.calls == []


@pytest.mark.parametrize(
    "violation,status", [("session", 401), ("origin", 403), ("identifier", 400), ("body", 400)]
)
def test_replay_preparation_retains_existing_http_authority_and_shape_guards(violation, status):
    with running_server() as (server, service):
        actual, _, _ = request(
            server,
            "POST",
            f"/api/v1/runs/{'bad-run' if violation == 'identifier' else RUN_ID}/replay-preparations",
            body=[] if violation == "body" else {},
            authenticated=violation != "session",
            origin="https://untrusted.example" if violation == "origin" else "same",
        )
    assert actual == status
    assert service.calls == []


def test_replay_submission_keeps_preparation_context_and_explicit_approval_separate():
    payload = {
        "preparation_id": "replay-preparation-" + "a" * 64,
        "preparation_context": {
            "schema_version": "bluefire.replay-preparation-context.v1",
            "runner_readiness": None,
        },
        "approval": {"confirmed": True, "approved_by": "operator"},
    }
    with running_server() as (server, service):
        status, _, _ = request(server, "POST", f"/api/v1/runs/{RUN_ID}/replays", body=payload)
    assert status == 201
    assert service.calls == [("replay", RUN_ID, payload)]
