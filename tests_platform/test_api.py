from __future__ import annotations

import http.client
import json
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

import pytest

from bluefire.api import APIError, BlueFireHTTPServer, PlatformService, create_server, serve

RUN_ID = "run-20260823T120000Z-0123456789abcdef"
JOB_ID = "job-0123456789abcdef0123456789abcdef"
SCENARIO_ID = "scenario.example.v1"
RESOURCE_ID = "collector.example.v1"
PROPOSAL_ID = "proposal-review-0123456789abcdef0123456789abcdef"
DETECTION_ID = "detection-0123456789abcdef0123"


class StubService:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def catalog(self):
        self.calls.append(("catalog",))
        return {"behaviors": [{"id": "observe.host.v1"}], "runner_profiles": []}

    def scenarios(self):
        self.calls.append(("scenarios",))
        return {"scenarios": []}

    def draft_ai_graph(self, request: Mapping[str, Any]):
        self.calls.append(("draft_ai_graph", request))
        return {"draft_id": "ai-draft-0123456789abcdef0123", "saved": False}

    def settings(self):
        self.calls.append(("settings",))
        return {"settings": []}

    def upsert_setting(self, key: str, request: Mapping[str, Any]):
        self.calls.append(("upsert_setting", key, request))
        return {"setting": {"key": key, "value": request.get("value")}}

    def scenario_versions(self):
        self.calls.append(("scenario_versions",))
        return {"scenarios": []}

    def save_scenario_version(self, request: Mapping[str, Any]):
        self.calls.append(("save_scenario_version", request))
        return {"scenario": request.get("scenario", {})}

    def scenario_version(self, scenario_id: str, *, version: int | None = None):
        self.calls.append(("scenario_version", scenario_id, version))
        return {"scenario": {"scenario_id": scenario_id, "version": version or 1}}

    def resources(self, kind: str):
        self.calls.append(("resources", kind))
        return {"kind": kind, "resources": []}

    def resource(self, kind: str, resource_id: str):
        self.calls.append(("resource", kind, resource_id))
        return {"resource": {"kind": kind, "id": resource_id}}

    def save_resource(
        self,
        kind: str,
        resource_id: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("save_resource", kind, resource_id, request))
        return {"resource": {"kind": kind, "id": resource_id}}

    def detection_health(self):
        self.calls.append(("detection_health",))
        return {"ready": True}

    def detection_candidates(self):
        self.calls.append(("detection_candidates",))
        return {"candidates": []}

    def detection_candidate(self, candidate_id: str):
        self.calls.append(("detection_candidate", candidate_id))
        return {"candidate": {"id": candidate_id}}

    def upsert_detection_hypothesis(self, request: Mapping[str, Any]):
        self.calls.append(("upsert_detection_hypothesis", request))
        return {"candidate": {"id": DETECTION_ID}}

    def parse_detection_candidate(self, candidate_id: str, request: Mapping[str, Any]):
        self.calls.append(("parse_detection_candidate", candidate_id, request))
        return {"candidate": {"id": candidate_id}}

    def exercise_detection_fixtures(self, candidate_id: str, request: Mapping[str, Any]):
        self.calls.append(("exercise_detection_fixtures", candidate_id, request))
        return {"candidate": {"id": candidate_id}}

    def exercise_detection_observed(self, candidate_id: str, request: Mapping[str, Any]):
        self.calls.append(("exercise_detection_observed", candidate_id, request))
        return {"candidate": {"id": candidate_id}}

    def evaluate_detection_benign(self, candidate_id: str, request: Mapping[str, Any]):
        self.calls.append(("evaluate_detection_benign", candidate_id, request))
        return {"candidate": {"id": candidate_id}}

    def reject_detection_candidate(self, candidate_id: str, request: Mapping[str, Any]):
        self.calls.append(("reject_detection_candidate", candidate_id, request))
        return {"candidate": {"id": candidate_id}}

    def activate_resource(
        self,
        kind: str,
        resource_id: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("activate_resource", kind, resource_id, request))
        return {"resource": {"kind": kind, "id": resource_id, "status": "active"}}

    def deactivate_resource(
        self,
        kind: str,
        resource_id: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("deactivate_resource", kind, resource_id, request))
        return {"resource": {"kind": kind, "id": resource_id, "status": "inactive"}}

    def probe_runner_profile(self, resource_id: str, request: Mapping[str, Any]):
        self.calls.append(("probe_runner_profile", resource_id, request))
        return {"profile_id": resource_id, "health": {"state": "ready"}}

    def validate(self, request: Mapping[str, Any]):
        self.calls.append(("validate", request))
        return {"valid": True}

    def preflight(self, request: Mapping[str, Any]):
        self.calls.append(("preflight", request))
        return {"ready": True}

    def run(self, request: Mapping[str, Any]):
        self.calls.append(("run", request))
        return {"run_id": RUN_ID, "status": "created"}

    def submit_run(self, request: Mapping[str, Any]):
        self.calls.append(("submit_run", request))
        return {"job": {"job_id": JOB_ID, "state": "queued"}}

    def job(self, job_id: str):
        self.calls.append(("job", job_id))
        return {"job_id": job_id, "state": "running"}

    def retry_job(self, job_id: str):
        self.calls.append(("retry_job", job_id))
        return {
            "retry_of_job_id": job_id,
            "job": {"job_id": JOB_ID, "state": "queued"},
        }

    def approve_job(self, job_id: str, request: Mapping[str, Any]):
        self.calls.append(("approve_job", job_id, request))
        return {"job": {"job_id": job_id, "state": "running"}}

    def proposal_reviews(self, job_id: str):
        self.calls.append(("proposal_reviews", job_id))
        return {"job_id": job_id, "proposals": []}

    def proposal_review(self, job_id: str, proposal_record_id: str):
        self.calls.append(("proposal_review", job_id, proposal_record_id))
        return {"job_id": job_id, "proposal_record_id": proposal_record_id}

    def accept_proposal_review(
        self,
        job_id: str,
        proposal_record_id: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("accept_proposal_review", job_id, proposal_record_id, request))
        return {"job": {"job_id": job_id, "state": "running"}}

    def reject_proposal_review(
        self,
        job_id: str,
        proposal_record_id: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("reject_proposal_review", job_id, proposal_record_id, request))
        return {"job": {"job_id": job_id, "state": "awaiting_approval"}}

    def pause_job(self, job_id: str):
        self.calls.append(("pause_job", job_id))
        return {"job_id": job_id, "state": "running"}

    def resume_job(self, job_id: str):
        self.calls.append(("resume_job", job_id))
        return {"job_id": job_id, "state": "running"}

    def cancel_job(self, job_id: str):
        self.calls.append(("cancel_job", job_id))
        return {"job_id": job_id, "state": "cancelling"}

    def list(self):
        self.calls.append(("list",))
        return {"runs": [{"run_id": RUN_ID, "status": "created"}]}

    def detail(self, run_id: str):
        self.calls.append(("detail", run_id))
        if run_id == "run-20260823T120000Z-ffffffffffffffff":
            raise APIError(404, "run_not_found", "Run was not found.")
        return {"run_id": run_id, "status": "created"}

    def events(self, run_id: str, *, after_sequence: int, limit: int):
        self.calls.append(("events", run_id, after_sequence, limit))
        return {
            "run_id": run_id,
            "after_sequence": after_sequence,
            "next_sequence": after_sequence,
            "has_more": False,
            "items": [],
        }

    def replay(self, run_id: str, request: Mapping[str, Any]):
        self.calls.append(("replay", run_id, request))
        return {"run_id": RUN_ID, "parent_run_id": run_id, "status": "created"}

    def compare(self, request: Mapping[str, Any]):
        self.calls.append(("compare", request))
        return {"run_ids": request.get("run_ids", []), "status": "complete"}


@contextmanager
def running_server(
    service: StubService | None = None,
    *,
    max_request_body: int = 1024,
) -> Iterator[tuple[BlueFireHTTPServer, StubService]]:
    target = service or StubService()
    server = create_server(target, host="127.0.0.1", port=0, max_request_body=max_request_body)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, target
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def request(
    server: BlueFireHTTPServer,
    method: str,
    path: str,
    *,
    body: Any = None,
    content_type: str = "application/json",
    origin: str | None = "same",
    extra_headers: Mapping[str, str] | None = None,
) -> tuple[int, Mapping[str, str], bytes]:
    port = server.server_address[1]
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    payload = (
        None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    )
    headers = dict(extra_headers or {})
    if payload is not None:
        headers["Content-Type"] = content_type
    if method == "POST" and origin is not None:
        headers["Origin"] = f"http://127.0.0.1:{port}" if origin == "same" else origin
    connection.request(method, path, body=payload, headers=headers)
    response = connection.getresponse()
    data = response.read()
    response_headers = {name: value for name, value in response.getheaders()}
    connection.close()
    return response.status, response_headers, data


def json_body(payload: bytes) -> Mapping[str, Any]:
    value = json.loads(payload)
    assert isinstance(value, dict)
    return value


def test_loopback_binding_is_mandatory() -> None:
    service = StubService()
    for host in ("0.0.0.0", "::", "example.test", ""):
        with pytest.raises(ValueError, match="loopback"):
            create_server(service, host=host, port=0)


def test_stub_implements_the_complete_platform_service_protocol() -> None:
    assert isinstance(StubService(), PlatformService)


def test_serve_closes_owned_service_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    service = StubService()
    closed = {"server": False, "service": False}

    class ImmediateServer:
        def serve_forever(self) -> None:
            return None

        def server_close(self) -> None:
            closed["server"] = True

    service.close = lambda: closed.__setitem__("service", True)  # type: ignore[attr-defined]
    monkeypatch.setattr("bluefire.api.create_server", lambda *args, **kwargs: ImmediateServer())

    serve(service)

    assert closed == {"server": True, "service": True}


def test_get_routes_dispatch_to_the_injected_service() -> None:
    with running_server() as (server, service):
        routes = [
            ("/api/v1/catalog", "catalog"),
            ("/api/v1/scenarios", "scenarios"),
            ("/api/v1/settings", "settings"),
            ("/api/v1/scenario-versions", "scenario_versions"),
            (f"/api/v1/scenario-versions/{SCENARIO_ID}", "scenario_version"),
            (
                f"/api/v1/scenario-versions/{SCENARIO_ID}/versions/7",
                "scenario_version",
            ),
            ("/api/v1/resources/collectors", "resources"),
            (f"/api/v1/resources/collectors/{RESOURCE_ID}", "resource"),
            ("/api/v1/runs", "list"),
            (f"/api/v1/jobs/{JOB_ID}", "job"),
            (f"/api/v1/runs/{RUN_ID}", "detail"),
            (f"/api/v1/runs/{RUN_ID}/events?after_sequence=12&limit=25", "events"),
        ]
        for path, expected_call in routes:
            status, headers, payload = request(server, "GET", path)
            assert status == 200
            assert headers["Content-Type"] == "application/json; charset=utf-8"
            assert json_body(payload)
            assert service.calls[-1][0] == expected_call
        assert service.calls[-1] == ("events", RUN_ID, 12, 25)
        assert ("scenario_version", SCENARIO_ID, None) in service.calls
        assert ("scenario_version", SCENARIO_ID, 7) in service.calls
        assert ("resources", "collector") in service.calls
        assert ("resource", "collector", RESOURCE_ID) in service.calls


@pytest.mark.parametrize(
    "query",
    [
        "after_sequence=-1",
        "limit=0",
        "limit=1001",
        "limit=2&limit=3",
        "unknown=1",
        "after_sequence=",
    ],
)
def test_event_pagination_rejects_malformed_or_unbounded_queries(query: str) -> None:
    with running_server() as (server, service):
        status, _, payload = request(server, "GET", f"/api/v1/runs/{RUN_ID}/events?{query}")
    assert status == 400
    assert json_body(payload)["error"]["code"] == "invalid_event_page"
    assert not service.calls


def test_post_routes_forward_json_objects_without_orchestration() -> None:
    body = {"scenario": {"schema_version": "bluefire.scenario.v1"}}
    with running_server() as (server, service):
        cases = [
            ("/api/v1/scenarios/validate", 200, "validate"),
            ("/api/v1/scenario-versions", 200, "save_scenario_version"),
            ("/api/v1/settings/ui.preferences", 200, "upsert_setting"),
            (
                f"/api/v1/resources/collectors/{RESOURCE_ID}",
                200,
                "save_resource",
            ),
            ("/api/v1/runs/preflight", 200, "preflight"),
            ("/api/v1/runs", 202, "submit_run"),
            (f"/api/v1/runs/{RUN_ID}/replays", 201, "replay"),
            ("/api/v1/comparisons", 200, "compare"),
        ]
        for path, expected_status, expected_call in cases:
            status, _, payload = request(server, "POST", path, body=body)
            assert status == expected_status
            assert json_body(payload)
            assert service.calls[-1][0] == expected_call

        assert ("upsert_setting", "ui.preferences", body) in service.calls
        assert ("save_resource", "collector", RESOURCE_ID, body) in service.calls


def test_ai_graph_draft_route_forwards_only_to_the_service_boundary() -> None:
    body = {
        "objective": "Create and inspect a bounded synthetic fixture.",
        "provider_id": "deterministic-offline.v1",
        "max_nodes": 4,
        "max_edges": 3,
    }
    with running_server() as (server, service):
        status, _, payload = request(server, "POST", "/api/v1/ai/drafts", body=body)
        assert status == 200
        assert json_body(payload)["saved"] is False
        assert service.calls[-1] == ("draft_ai_graph", body)

        status, headers, payload = request(server, "GET", "/api/v1/ai/drafts")
        assert status == 405
        assert headers["Allow"] == "POST"
        assert json_body(payload)["error"]["code"] == "method_not_allowed"

        status, _, payload = request(
            server,
            "POST",
            "/api/v1/ai/drafts?save=true",
            body=body,
        )
        assert status == 400
        assert json_body(payload)["error"]["code"] == "invalid_management_query"
        assert service.calls == [("draft_ai_graph", body)]


def test_detection_lab_routes_dispatch_only_explicit_lifecycle_operations() -> None:
    body = {"source": "bounded-source"}
    with running_server() as (server, service):
        get_routes = [
            ("/api/v1/detection-lab/health", "detection_health"),
            ("/api/v1/detections", "detection_candidates"),
            (f"/api/v1/detections/{DETECTION_ID}", "detection_candidate"),
        ]
        for path, expected_call in get_routes:
            status, _, payload = request(server, "GET", path)
            assert status == 200
            assert json_body(payload)
            assert service.calls[-1][0] == expected_call

        status, _, _ = request(server, "POST", "/api/v1/detections", body=body)
        assert status == 201
        assert service.calls[-1] == ("upsert_detection_hypothesis", body)

        actions = {
            "parse": "parse_detection_candidate",
            "exercise-fixtures": "exercise_detection_fixtures",
            "exercise-observed": "exercise_detection_observed",
            "evaluate-benign": "evaluate_detection_benign",
            "reject": "reject_detection_candidate",
        }
        for action, expected_call in actions.items():
            status, _, payload = request(
                server,
                "POST",
                f"/api/v1/detections/{DETECTION_ID}/{action}",
                body=body,
            )
            assert status == 200
            assert json_body(payload)
            assert service.calls[-1] == (expected_call, DETECTION_ID, body)


@pytest.mark.parametrize(
    ("path", "expected_code"),
    [
        ("/api/v1/detections/not-a-detection", "invalid_detection_id"),
        (
            f"/api/v1/detections/{DETECTION_ID}/execute",
            "invalid_detection_action",
        ),
        ("/api/v1/detections?status=parsed", "invalid_management_query"),
    ],
)
def test_detection_lab_paths_reject_ambiguous_authority(path: str, expected_code: str) -> None:
    with running_server() as (server, service):
        status, _, payload = request(server, "GET", path)
    assert status == 400
    assert json_body(payload)["error"]["code"] == expected_code
    assert not service.calls


def test_runtime_resource_actions_dispatch_only_explicit_safe_routes() -> None:
    runner_profile_id = "profile.managed.v1"
    provider_id = "provider.managed.v1"
    plugin_id = "plugin.managed.v1"
    with running_server() as (server, service):
        cases = [
            (
                f"/api/v1/resources/runner-profiles/{runner_profile_id}/activate",
                "activate_resource",
            ),
            (
                f"/api/v1/resources/runner-profiles/{runner_profile_id}/deactivate",
                "deactivate_resource",
            ),
            (
                f"/api/v1/resources/runner-profiles/{runner_profile_id}/probe",
                "probe_runner_profile",
            ),
            (
                f"/api/v1/resources/model-providers/{provider_id}/activate",
                "activate_resource",
            ),
            (
                f"/api/v1/resources/model-providers/{provider_id}/deactivate",
                "deactivate_resource",
            ),
            (
                f"/api/v1/resources/plugins/{plugin_id}/activate",
                "activate_resource",
            ),
            (
                f"/api/v1/resources/plugins/{plugin_id}/deactivate",
                "deactivate_resource",
            ),
        ]
        for path, expected_call in cases:
            status, _, payload = request(server, "POST", path, body={})
            assert status == 200
            assert json_body(payload)
            assert service.calls[-1][0] == expected_call

        assert (
            "activate_resource",
            "runner_profile",
            runner_profile_id,
            {},
        ) in service.calls
        assert ("probe_runner_profile", runner_profile_id, {}) in service.calls
        assert (
            "activate_resource",
            "model_provider",
            provider_id,
            {},
        ) in service.calls
        assert ("activate_resource", "plugin", plugin_id, {}) in service.calls


def test_resource_lifecycle_actions_reject_nonempty_bodies_before_dispatch() -> None:
    with running_server() as (server, service):
        status, _, payload = request(
            server,
            "POST",
            "/api/v1/resources/plugins/plugin.managed.v1/activate",
            body={"entry_point": "must-not-be-accepted"},
        )

    assert status == 400
    assert json_body(payload)["error"]["code"] == "resource_action_invalid"
    assert not service.calls


@pytest.mark.parametrize(
    ("path", "expected_code"),
    [
        (
            "/api/v1/resources/runner-profiles/Profile.Upper/activate",
            "invalid_resource_id",
        ),
        (
            "/api/v1/resources/runner-profiles/profile.safe.v1/restart",
            "invalid_resource_action",
        ),
        (
            "/api/v1/resources/model-providers/provider.safe.v1/probe",
            "invalid_resource_action",
        ),
        (
            "/api/v1/resources/runner-profiles/profile.safe.v1/probe?path=C:%5Crunner.exe",
            "invalid_management_query",
        ),
    ],
)
def test_runtime_resource_action_paths_reject_ambiguous_inputs(
    path: str,
    expected_code: str,
) -> None:
    with running_server() as (server, service):
        status, _, payload = request(server, "POST", path, body={})
    assert status == 400
    assert json_body(payload)["error"]["code"] == expected_code
    assert not service.calls


@pytest.mark.parametrize(
    ("path", "expected_code"),
    [
        ("/api/v1/settings/Uppercase", "invalid_setting_key"),
        ("/api/v1/settings/ui.preferences?extra=1", "invalid_management_query"),
        ("/api/v1/scenario-versions/Uppercase", "invalid_scenario_id"),
        (
            f"/api/v1/scenario-versions/{SCENARIO_ID}/versions/0",
            "invalid_scenario_version",
        ),
        (
            f"/api/v1/scenario-versions/{SCENARIO_ID}/versions/01",
            "invalid_scenario_version",
        ),
        (
            "/api/v1/scenario-versions/scenario.example.v1/history/1",
            "invalid_scenario_version_path",
        ),
        ("/api/v1/resources/unknown-kind", "invalid_resource_kind"),
        ("/api/v1/resources/collectors/Uppercase", "invalid_resource_id"),
        ("/api/v1/resources/collectors/one/extra", "invalid_resource_path"),
    ],
)
def test_management_routes_reject_unknown_or_ambiguous_paths(
    path: str,
    expected_code: str,
) -> None:
    with running_server() as (server, service):
        status, _, payload = request(server, "GET", path)

    assert status == 400
    assert json_body(payload)["error"]["code"] == expected_code
    assert not service.calls


def test_job_control_routes_dispatch_to_the_durable_service() -> None:
    with running_server() as (server, service):
        cases = [
            ("approval", {"approved_by": "local-operator"}, "approve_job"),
            ("pause", {}, "pause_job"),
            ("resume", {}, "resume_job"),
            ("cancel", {}, "cancel_job"),
            ("retry", {}, "retry_job"),
        ]
        for action, body, expected_call in cases:
            status, _, payload = request(
                server,
                "POST",
                f"/api/v1/jobs/{JOB_ID}/{action}",
                body=body,
            )
            assert status == 202
            assert json_body(payload)
            assert service.calls[-1][0] == expected_call


def test_proposal_review_routes_dispatch_exact_job_and_proposal_ids() -> None:
    body = {
        "decided_by": "operator",
        "state_digest": "sha256:" + "1" * 64,
        "plan_digest": "sha256:" + "2" * 64,
        "proposal_digest": "sha256:" + "3" * 64,
    }
    with running_server() as (server, service):
        status, _, _ = request(
            server,
            "GET",
            f"/api/v1/jobs/{JOB_ID}/proposals",
        )
        assert status == 200
        assert service.calls[-1] == ("proposal_reviews", JOB_ID)

        status, _, _ = request(
            server,
            "GET",
            f"/api/v1/jobs/{JOB_ID}/proposals/{PROPOSAL_ID}",
        )
        assert status == 200
        assert service.calls[-1] == ("proposal_review", JOB_ID, PROPOSAL_ID)

        for action, operation in (
            ("accept", "accept_proposal_review"),
            ("reject", "reject_proposal_review"),
        ):
            status, _, _ = request(
                server,
                "POST",
                f"/api/v1/jobs/{JOB_ID}/proposals/{PROPOSAL_ID}/{action}",
                body=body,
            )
            assert status == 202
            assert service.calls[-1] == (operation, JOB_ID, PROPOSAL_ID, body)


@pytest.mark.parametrize(
    ("path", "code"),
    [
        (
            f"/api/v1/jobs/{JOB_ID}/proposals/not-a-proposal",
            "invalid_proposal_id",
        ),
        (
            f"/api/v1/jobs/{JOB_ID}/proposals/{PROPOSAL_ID}/apply",
            "invalid_proposal_action",
        ),
    ],
)
def test_proposal_review_routes_reject_invalid_authority_paths(path: str, code: str) -> None:
    with running_server() as (server, service):
        status, _, payload = request(server, "GET", path)
    assert status == 400
    assert json_body(payload)["error"]["code"] == code
    assert not service.calls


def test_job_retry_requires_an_empty_json_object() -> None:
    with running_server() as (server, service):
        status, _, payload = request(
            server,
            "POST",
            f"/api/v1/jobs/{JOB_ID}/retry",
            body={"approval_request_id": "must-not-be-accepted"},
        )

    assert status == 400
    assert json_body(payload)["error"]["code"] == "retry_invalid"
    assert not service.calls


def test_explicit_api_errors_are_safe_and_preserve_status() -> None:
    missing = "run-20260823T120000Z-ffffffffffffffff"
    with running_server() as (server, _):
        status, _, payload = request(server, "GET", f"/api/v1/runs/{missing}")
    assert status == 404
    assert json_body(payload) == {
        "error": {"code": "run_not_found", "message": "Run was not found."}
    }


def test_post_requires_an_exact_same_origin_header() -> None:
    with running_server() as (server, service):
        for origin in (None, "https://127.0.0.1:1", "http://example.test", "null"):
            status, _, payload = request(
                server,
                "POST",
                "/api/v1/scenarios/validate",
                body={},
                origin=origin,
            )
            assert status == 403
            assert json_body(payload)["error"]["code"] == "origin_rejected"
        assert not service.calls


def test_host_must_name_the_loopback_listener() -> None:
    with running_server() as (server, _):
        port = server.server_address[1]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.putrequest("GET", "/", skip_host=True)
        connection.putheader("Host", f"example.test:{port}")
        connection.endheaders()
        response = connection.getresponse()
        payload = response.read()
        connection.close()
    assert response.status == 421
    assert json_body(payload)["error"]["code"] == "invalid_host"


@pytest.mark.parametrize(
    ("path", "expected_code"),
    [
        ("/ui/%2e%2e/api.py", "path_traversal"),
        ("/ui/%252e%252e/api.py", "path_traversal"),
        ("/api/v1/runs/%2e%2e", "path_traversal"),
        ("http://example.test/ui/app.js", "invalid_path"),
    ],
)
def test_path_traversal_and_non_origin_request_targets_are_rejected(
    path: str, expected_code: str
) -> None:
    with running_server() as (server, _):
        status, _, payload = request(server, "GET", path)
    assert status == 400
    assert json_body(payload)["error"]["code"] == expected_code


def test_unknown_and_invalid_run_routes_do_not_reach_the_service() -> None:
    with running_server() as (server, service):
        status, _, payload = request(server, "GET", "/api/v1/unknown")
        assert status == 404
        assert json_body(payload)["error"]["code"] == "not_found"

        status, _, payload = request(server, "GET", "/api/v1/runs/not-a-run")
        assert status == 400
        assert json_body(payload)["error"]["code"] == "invalid_run_id"
        assert not service.calls


def test_json_content_type_utf8_and_object_shape_are_enforced() -> None:
    with running_server() as (server, service):
        status, _, payload = request(
            server,
            "POST",
            "/api/v1/scenarios/validate",
            body=b"{}",
            content_type="text/plain",
        )
        assert status == 415
        assert json_body(payload)["error"]["code"] == "content_type_required"

        status, _, payload = request(
            server,
            "POST",
            "/api/v1/scenarios/validate",
            body=b"{}",
            content_type="application/json; charset=latin-1",
        )
        assert status == 415
        assert json_body(payload)["error"]["code"] == "unsupported_charset"

        status, _, payload = request(
            server,
            "POST",
            "/api/v1/scenarios/validate",
            body=b"[]",
        )
        assert status == 400
        assert json_body(payload)["error"]["code"] == "object_required"

        for invalid in (b"{", b'{"x":NaN}', b'{"x":1,"x":2}'):
            status, _, payload = request(
                server,
                "POST",
                "/api/v1/scenarios/validate",
                body=invalid,
            )
            assert status == 400
            assert json_body(payload)["error"]["code"] == "invalid_json"
        assert not service.calls


def test_request_body_limit_is_checked_before_dispatch() -> None:
    with running_server(max_request_body=64) as (server, service):
        status, headers, payload = request(
            server,
            "POST",
            "/api/v1/scenarios/validate",
            body={"value": "x" * 80},
        )
    assert status == 413
    assert headers["Connection"] == "close"
    assert json_body(payload)["error"]["code"] == "body_too_large"
    assert not service.calls


def test_content_length_is_required_for_post() -> None:
    with running_server() as (server, _):
        port = server.server_address[1]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.putrequest("POST", "/api/v1/scenarios/validate")
        connection.putheader("Origin", f"http://127.0.0.1:{port}")
        connection.putheader("Content-Type", "application/json")
        connection.endheaders()
        response = connection.getresponse()
        payload = response.read()
        connection.close()
    assert response.status == 411
    assert json_body(payload)["error"]["code"] == "length_required"


@pytest.mark.parametrize(
    ("duplicate_header", "expected_status", "expected_code"),
    [
        ("Origin", 403, "origin_rejected"),
        ("Content-Length", 400, "invalid_length"),
        ("Content-Type", 415, "content_type_required"),
    ],
)
def test_security_sensitive_duplicate_headers_are_rejected(
    duplicate_header: str, expected_status: int, expected_code: str
) -> None:
    with running_server() as (server, service):
        port = server.server_address[1]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.putrequest("POST", "/api/v1/scenarios/validate")
        headers = {
            "Origin": f"http://127.0.0.1:{port}",
            "Content-Type": "application/json",
            "Content-Length": "2",
        }
        for name, value in headers.items():
            connection.putheader(name, value)
            if name == duplicate_header:
                connection.putheader(name, value)
        connection.endheaders(b"{}")
        response = connection.getresponse()
        payload = response.read()
        response_headers = dict(response.getheaders())
        connection.close()
    assert response.status == expected_status
    assert response_headers["Connection"] == "close"
    assert json_body(payload)["error"]["code"] == expected_code
    assert not service.calls


def test_unsupported_methods_are_405_without_cors() -> None:
    with running_server() as (server, service):
        for method in ("PUT", "PATCH", "DELETE", "OPTIONS"):
            status, headers, payload = request(server, method, "/api/v1/runs")
            assert status == 405
            assert headers["Allow"] == "GET, HEAD, POST"
            assert "Access-Control-Allow-Origin" not in headers
            assert json_body(payload)["error"]["code"] == "method_not_allowed"
        assert not service.calls


def test_known_routes_report_the_allowed_method() -> None:
    with running_server() as (server, service):
        status, headers, payload = request(
            server,
            "POST",
            "/api/v1/catalog",
            body={},
        )
        assert status == 405
        assert headers["Allow"] == "GET"
        assert json_body(payload)["error"]["code"] == "method_not_allowed"

        status, headers, payload = request(
            server,
            "GET",
            "/api/v1/runs/preflight",
        )
        assert status == 405
        assert headers["Allow"] == "POST"
        assert json_body(payload)["error"]["code"] == "method_not_allowed"

        status, headers, payload = request(
            server,
            "GET",
            "/api/v1/settings/ui.preferences",
        )
        assert status == 405
        assert headers["Allow"] == "POST"
        assert json_body(payload)["error"]["code"] == "method_not_allowed"

        status, headers, payload = request(
            server,
            "POST",
            "/api/v1/resources/collectors",
            body={},
        )
        assert status == 405
        assert headers["Allow"] == "GET"
        assert json_body(payload)["error"]["code"] == "method_not_allowed"

        status, headers, payload = request(server, "POST", "/", body={})
        assert status == 405
        assert headers["Allow"] == "GET, HEAD"
        assert json_body(payload)["error"]["code"] == "method_not_allowed"
        assert not service.calls


def test_static_assets_have_strict_security_headers_and_head_support() -> None:
    with running_server() as (server, _):
        for path, content_type in (
            ("/", "text/html"),
            ("/ui/app.js", "javascript"),
            ("/ui/styles.css", "text/css"),
        ):
            status, headers, payload = request(server, "GET", path)
            assert status == 200
            assert content_type in headers["Content-Type"]
            assert payload
            assert headers["Cache-Control"] == "no-store"
            assert headers["X-Content-Type-Options"] == "nosniff"
            assert (
                headers["Permissions-Policy"] == "camera=(), geolocation=(), microphone=(), usb=()"
            )
            assert "default-src 'self'" in headers["Content-Security-Policy"]
            assert "object-src 'none'" in headers["Content-Security-Policy"]
            assert "style-src-attr 'unsafe-inline'" in headers["Content-Security-Policy"]

        status, headers, payload = request(server, "HEAD", "/ui/app.js")
        assert status == 200
        assert payload == b""
        assert (
            int(headers["Content-Length"])
            == (Path(__file__).parents[1] / "bluefire" / "ui" / "app.js").stat().st_size
        )


def test_invalid_service_json_is_sanitized() -> None:
    service = StubService()
    service.catalog = lambda: {"bad": float("nan")}  # type: ignore[method-assign]
    with running_server(service) as (server, _):
        status, _, payload = request(server, "GET", "/api/v1/catalog")
    assert status == 500
    assert json_body(payload)["error"] == {
        "code": "invalid_service_response",
        "message": "The platform service returned an invalid response.",
    }
