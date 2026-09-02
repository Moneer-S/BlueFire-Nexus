from __future__ import annotations

import http.client
import json
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

import pytest

import bluefire.api as api_module
from bluefire.api import (
    BROWSER_BOOTSTRAP_HEADER,
    BROWSER_BOOTSTRAP_LIFETIME_SECONDS,
    BROWSER_SESSION_COOKIE,
    BROWSER_SESSION_LIFETIME_SECONDS,
    APIError,
    BlueFireHTTPServer,
    PlatformService,
    browser_console_url,
    create_server,
    generate_browser_bootstrap_capability,
    serve,
)

RUN_ID = "run-20260823T120000Z-0123456789abcdef"
JOB_ID = "job-0123456789abcdef0123456789abcdef"
SCENARIO_ID = "scenario.example.v1"
RESOURCE_ID = "collector.example.v1"
PROPOSAL_ID = "proposal-review-0123456789abcdef0123456789abcdef"
DETECTION_ID = "detection-0123456789abcdef0123"
PACKAGE_ID = "package.managed.v1"
PACKAGE_VERSION = "1.2.3"
PUBLISHER_ID = "publisher.managed.v1"
PUBLISHER_KEY_ID = "release-key.v1"
PROVIDER_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "provider_upgrade"


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

    def intake_reviewed_t1082(self, request: Mapping[str, Any]):
        self.calls.append(("intake_reviewed_t1082", request))
        return {
            "schema_version": "bluefire.reviewed-source-intake-result.v1",
            "destination_id": request.get("destination_id"),
        }

    def save_resource(
        self,
        kind: str,
        resource_id: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("save_resource", kind, resource_id, request))
        return {"resource": {"kind": kind, "id": resource_id}}

    def action_packages(self):
        self.calls.append(("action_packages",))
        return {"packages": [], "publishers": []}

    def action_package(self, package_id: str):
        self.calls.append(("action_package", package_id))
        return {"package": {"package_id": package_id}}

    def install_action_package(self, request: Mapping[str, Any]):
        self.calls.append(("install_action_package", request))
        return {"package": {"package_id": PACKAGE_ID, "version": PACKAGE_VERSION}}

    def activate_action_package(
        self,
        package_id: str,
        version: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("activate_action_package", package_id, version, request))
        return {"package": {"package_id": package_id, "version": version, "active": True}}

    def deactivate_action_package(
        self,
        package_id: str,
        version: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("deactivate_action_package", package_id, version, request))
        return {"package": {"package_id": package_id, "version": version, "active": False}}

    def remove_action_package(
        self,
        package_id: str,
        version: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(("remove_action_package", package_id, version, request))
        return {"package": {"package_id": package_id, "version": version, "removed": True}}

    def trust_action_package_publisher(self, request: Mapping[str, Any]):
        self.calls.append(("trust_action_package_publisher", request))
        return {"publisher": {"publisher_id": request.get("publisher_id")}}

    def transition_action_package_publisher(
        self,
        publisher_id: str,
        key_id: str,
        action: str,
        request: Mapping[str, Any],
    ):
        self.calls.append(
            (
                "transition_action_package_publisher",
                publisher_id,
                key_id,
                action,
                request,
            )
        )
        return {"publisher": {"publisher_id": publisher_id, "key_id": key_id, "state": action}}

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

    def clone_detection_candidate(self, candidate_id: str, request: Mapping[str, Any]):
        self.calls.append(("clone_detection_candidate", candidate_id, request))
        return {"candidate": {"id": candidate_id}}

    def tune_detection_candidate(self, candidate_id: str, request: Mapping[str, Any]):
        self.calls.append(("tune_detection_candidate", candidate_id, request))
        return {"candidate": {"id": candidate_id}}

    def compare_detection_candidates(self, candidate_id: str, request: Mapping[str, Any]):
        self.calls.append(("compare_detection_candidates", candidate_id, request))
        return {"candidate": {"id": candidate_id}}

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

    def runner_status(self, *, profile_id: str | None = None):
        self.calls.append(("runner_status", profile_id))
        return {"state": "ready", "profile_id": profile_id}

    def bootstrap_runner(
        self,
        *,
        profile_id: str | None = None,
        allow_upgrade: bool = False,
    ):
        self.calls.append(("bootstrap_runner", profile_id, allow_upgrade))
        return {"state": "stopped", "profile_id": profile_id}

    def start_runner(self, *, profile_id: str | None = None):
        self.calls.append(("start_runner", profile_id))
        return {"state": "ready", "profile_id": profile_id}

    def stop_runner(self, *, profile_id: str | None = None):
        self.calls.append(("stop_runner", profile_id))
        return {"state": "stopped", "profile_id": profile_id}

    def revoke_runner(self):
        self.calls.append(("revoke_runner",))
        return {"state": "revoked"}

    def remove_runner(self, *, confirm_runner_id: str):
        self.calls.append(("remove_runner", confirm_runner_id))
        return {"state": "unbootstrapped"}

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

    def active_jobs(self):
        self.calls.append(("active_jobs",))
        return {"schema_version": "bluefire.active-job-list.v1", "jobs": []}

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
    authenticate: bool = True,
    bootstrap_capability: str | None = None,
) -> Iterator[tuple[BlueFireHTTPServer, StubService]]:
    target = service or StubService()
    capability = bootstrap_capability or generate_browser_bootstrap_capability()
    server = create_server(
        target,
        browser_bootstrap_capability=capability,
        host="127.0.0.1",
        port=0,
        max_request_body=max_request_body,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if authenticate:
            status, headers, payload = request(
                server,
                "POST",
                "/api/v1/session",
                extra_headers={BROWSER_BOOTSTRAP_HEADER: capability},
                authenticated=False,
            )
            assert status == 204
            assert payload == b""
            server._test_browser_cookie = headers["Set-Cookie"].split(";", 1)[0]  # type: ignore[attr-defined]
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
    authenticated: bool = True,
) -> tuple[int, Mapping[str, str], bytes]:
    port = server.server_address[1]
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    payload = (
        None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    )
    headers = dict(extra_headers or {})
    if authenticated and path.startswith("/api/v1") and path.split("?", 1)[0] != "/api/v1/session":
        cookie = getattr(server, "_test_browser_cookie", None)
        if cookie is not None:
            headers.setdefault("Cookie", cookie)
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
    capability = generate_browser_bootstrap_capability()
    for host in ("0.0.0.0", "::", "example.test", ""):
        with pytest.raises(ValueError, match="loopback"):
            create_server(
                service,
                browser_bootstrap_capability=capability,
                host=host,
                port=0,
            )


def test_browser_console_url_refuses_an_unresolved_ephemeral_port() -> None:
    capability = generate_browser_bootstrap_capability()

    with pytest.raises(ValueError, match="non-zero listener port"):
        browser_console_url("127.0.0.1", 0, capability)


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

    serve(service, browser_bootstrap_capability=generate_browser_bootstrap_capability())

    assert closed == {"server": True, "service": True}


def test_serve_announces_only_after_bind_and_before_serving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = StubService()
    events: list[str] = []

    class BoundServer:
        server_address = ("127.0.0.1", 49321)

        def serve_forever(self) -> None:
            events.append("serve")

        def server_close(self) -> None:
            events.append("server_close")

    service.close = lambda: events.append("service_close")  # type: ignore[attr-defined]
    monkeypatch.setattr("bluefire.api.create_server", lambda *args, **kwargs: BoundServer())

    serve(
        service,
        browser_bootstrap_capability=generate_browser_bootstrap_capability(),
        host="127.0.0.1",
        port=0,
        on_ready=lambda server: events.append(f"ready:{server.server_address[1]}"),
    )

    assert events == ["ready:49321", "serve", "server_close", "service_close"]


def test_serve_bind_failure_closes_service_without_announcing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = StubService()
    events: list[str] = []
    service.close = lambda: events.append("service_close")  # type: ignore[attr-defined]

    def fail_bind(*args: Any, **kwargs: Any) -> Any:
        raise OSError("bind failed")

    monkeypatch.setattr("bluefire.api.create_server", fail_bind)

    with pytest.raises(OSError, match="bind failed"):
        serve(
            service,
            browser_bootstrap_capability=generate_browser_bootstrap_capability(),
            on_ready=lambda _server: events.append("ready"),
        )

    assert events == ["service_close"]


def test_serve_readiness_callback_failure_closes_bound_server_and_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = StubService()
    events: list[str] = []

    class BoundServer:
        server_address = ("127.0.0.1", 49321)

        def serve_forever(self) -> None:
            events.append("serve")

        def server_close(self) -> None:
            events.append("server_close")

    service.close = lambda: events.append("service_close")  # type: ignore[attr-defined]
    monkeypatch.setattr("bluefire.api.create_server", lambda *args, **kwargs: BoundServer())

    def fail_ready(_server: Any) -> None:
        events.append("ready")
        raise RuntimeError("announcement failed")

    with pytest.raises(RuntimeError, match="announcement failed"):
        serve(
            service,
            browser_bootstrap_capability=generate_browser_bootstrap_capability(),
            on_ready=fail_ready,
        )

    assert events == ["ready", "server_close", "service_close"]


def test_static_assets_are_public_but_local_api_requires_a_browser_session() -> None:
    with running_server(authenticate=False) as (server, service):
        status, _, payload = request(server, "GET", "/", authenticated=False)
        assert status == 200
        assert payload

        status, _, payload = request(
            server,
            "GET",
            "/api/v1/catalog",
            authenticated=False,
        )
        assert status == 401
        assert json_body(payload)["error"]["code"] == "browser_session_required"

        status, _, payload = request(
            server,
            "GET",
            "/api/v1/jobs",
            authenticated=False,
        )
        assert status == 401
        assert json_body(payload)["error"]["code"] == "browser_session_required"

        status, headers, payload = request(
            server,
            "POST",
            "/api/v1/scenarios/validate",
            body={"untrusted": True},
            authenticated=False,
        )
        assert status == 401
        assert headers["Connection"] == "close"
        assert json_body(payload)["error"]["code"] == "browser_session_required"
        assert not service.calls


def test_browser_bootstrap_is_single_use_and_sets_a_strict_bounded_cookie(
    capsys: pytest.CaptureFixture[str],
) -> None:
    capability = generate_browser_bootstrap_capability()
    with running_server(
        authenticate=False,
        bootstrap_capability=capability,
    ) as (server, service):
        invalid = generate_browser_bootstrap_capability()
        status, _, payload = request(
            server,
            "POST",
            "/api/v1/session",
            extra_headers={BROWSER_BOOTSTRAP_HEADER: invalid},
            authenticated=False,
        )
        assert status == 401
        assert capability.encode() not in payload

        status, headers, payload = request(
            server,
            "POST",
            "/api/v1/session",
            extra_headers={BROWSER_BOOTSTRAP_HEADER: capability},
            authenticated=False,
        )
        assert status == 204
        assert payload == b""
        cookie_header = headers["Set-Cookie"]
        cookie = cookie_header.split(";", 1)[0]
        attributes = set(cookie_header.split("; ")[1:])
        assert cookie.startswith(f"{BROWSER_SESSION_COOKIE}=")
        assert attributes == {
            "HttpOnly",
            f"Max-Age={BROWSER_SESSION_LIFETIME_SECONDS}",
            "Path=/api/v1",
            "SameSite=Strict",
        }
        assert "Domain=" not in cookie_header
        assert "Secure" not in attributes
        assert "__Host-" not in cookie_header
        assert capability not in cookie_header
        assert capability not in repr(vars(service))
        assert capability not in repr(vars(server))

        status, _, payload = request(
            server,
            "GET",
            "/api/v1/session",
            extra_headers={"Cookie": cookie},
            authenticated=False,
        )
        assert status == 204
        assert payload == b""

        status, _, replay_payload = request(
            server,
            "POST",
            "/api/v1/session",
            extra_headers={BROWSER_BOOTSTRAP_HEADER: capability},
            authenticated=False,
        )
        assert status == 401
        assert capability.encode() not in replay_payload
        assert not service.calls

    captured = capsys.readouterr()
    assert capability not in captured.out
    assert capability not in captured.err


def test_browser_bootstrap_query_and_body_are_refused_without_being_read() -> None:
    capability = generate_browser_bootstrap_capability()
    with running_server(
        authenticate=False,
        bootstrap_capability=capability,
    ) as (server, service):
        port = server.server_address[1]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.putrequest("POST", f"/api/v1/session?capability={capability}")
        connection.putheader("Origin", f"http://127.0.0.1:{port}")
        connection.putheader(BROWSER_BOOTSTRAP_HEADER, capability)
        connection.putheader("Content-Length", "1048576")
        connection.putheader("Content-Type", "application/octet-stream")
        connection.endheaders()
        response = connection.getresponse()
        payload = response.read()
        response_headers = dict(response.getheaders())
        connection.close()

        assert response.status == 400
        assert response_headers["Connection"] == "close"
        assert json_body(payload)["error"]["code"] == "browser_session_bootstrap_invalid"
        assert capability.encode() not in payload
        assert not service.calls


def test_concurrent_browser_bootstrap_exchange_has_exactly_one_winner() -> None:
    capability = generate_browser_bootstrap_capability()
    with running_server(
        authenticate=False,
        bootstrap_capability=capability,
    ) as (server, service):
        barrier = threading.Barrier(8)
        results: list[tuple[int, Mapping[str, str], bytes]] = []
        result_lock = threading.Lock()

        def exchange() -> None:
            barrier.wait(timeout=3)
            result = request(
                server,
                "POST",
                "/api/v1/session",
                extra_headers={BROWSER_BOOTSTRAP_HEADER: capability},
                authenticated=False,
            )
            with result_lock:
                results.append(result)

        threads = [threading.Thread(target=exchange) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        assert all(not thread.is_alive() for thread in threads)
        assert sorted(status for status, _, _ in results) == [204] + [401] * 7
        assert sum("Set-Cookie" in headers for _, headers, _ in results) == 1
        assert all(capability.encode() not in payload for _, _, payload in results)
        assert not service.calls


def test_bootstrap_and_browser_sessions_expire_without_service_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [100.0]
    monkeypatch.setattr(api_module.time, "monotonic", lambda: now[0])

    expired_capability = generate_browser_bootstrap_capability()
    with running_server(
        authenticate=False,
        bootstrap_capability=expired_capability,
    ) as (server, service):
        now[0] += BROWSER_BOOTSTRAP_LIFETIME_SECONDS
        status, _, _ = request(
            server,
            "POST",
            "/api/v1/session",
            extra_headers={BROWSER_BOOTSTRAP_HEADER: expired_capability},
            authenticated=False,
        )
        assert status == 401
        assert not service.calls

    now[0] = 1_000.0
    capability = generate_browser_bootstrap_capability()
    with running_server(
        authenticate=False,
        bootstrap_capability=capability,
    ) as (server, service):
        status, headers, _ = request(
            server,
            "POST",
            "/api/v1/session",
            extra_headers={BROWSER_BOOTSTRAP_HEADER: capability},
            authenticated=False,
        )
        assert status == 204
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        now[0] += BROWSER_SESSION_LIFETIME_SECONDS
        port = server.server_address[1]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.putrequest("POST", "/api/v1/scenarios/validate")
        connection.putheader("Origin", f"http://127.0.0.1:{port}")
        connection.putheader("Cookie", cookie)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "1048576")
        connection.endheaders()
        response = connection.getresponse()
        payload = response.read()
        response_headers = dict(response.getheaders())
        connection.close()
        assert response.status == 401
        assert response_headers["Connection"] == "close"
        assert json_body(payload)["error"]["code"] == "browser_session_required"
        assert not service.calls


def test_browser_session_cookie_parsing_is_exact_and_duplicate_safe() -> None:
    with running_server() as (server, service):
        valid_cookie = server._test_browser_cookie  # type: ignore[attr-defined]
        session_value = valid_cookie.split("=", 1)[1]
        malformed = (
            f"{valid_cookie}; {valid_cookie}",
            f"{BROWSER_SESSION_COOKIE}=not-the-session",
            f'{BROWSER_SESSION_COOKIE}="{session_value}"',
            f"theme=dark, {valid_cookie}",
            f"broken; {valid_cookie}",
        )
        for cookie in malformed:
            status, _, payload = request(
                server,
                "GET",
                "/api/v1/catalog",
                extra_headers={"Cookie": cookie},
                authenticated=False,
            )
            assert status == 401
            assert json_body(payload)["error"]["code"] == "browser_session_required"

        status, _, _ = request(
            server,
            "GET",
            "/api/v1/session",
            extra_headers={"Cookie": f"theme=dark; {valid_cookie}"},
            authenticated=False,
        )
        assert status == 204

        port = server.server_address[1]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.putrequest("GET", "/api/v1/catalog")
        connection.putheader("Cookie", valid_cookie)
        connection.putheader("Cookie", valid_cookie)
        connection.endheaders()
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        assert response.status == 401
        assert json_body(payload)["error"]["code"] == "browser_session_required"
        assert not service.calls


def test_unauthenticated_post_is_rejected_before_waiting_for_its_declared_body() -> None:
    with running_server(authenticate=False) as (server, service):
        port = server.server_address[1]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.putrequest("POST", "/api/v1/scenarios/validate")
        connection.putheader("Origin", f"http://127.0.0.1:{port}")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "1048576")
        connection.endheaders()
        response = connection.getresponse()
        payload = response.read()
        response_headers = dict(response.getheaders())
        connection.close()

    assert response.status == 401
    assert response_headers["Connection"] == "close"
    assert json_body(payload)["error"]["code"] == "browser_session_required"
    assert not service.calls


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
            ("/api/v1/jobs", "active_jobs"),
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


def test_active_job_inventory_rejects_query_authority() -> None:
    with running_server() as (server, service):
        status, _, payload = request(server, "GET", "/api/v1/jobs?history=true")

    assert status == 400
    assert json_body(payload)["error"]["code"] == "invalid_management_query"
    assert not service.calls


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


def test_reviewed_t1082_intake_route_is_post_only_and_forwards_the_destination() -> None:
    route = "/api/v1/research-intakes/mitre-attack-t1082-v19-2"
    body = {
        "destination_id": "operator-review-20260829",
        "runner_profile_id": "sandbox-execute.v1",
        "operator_id": "local-source-reviewer",
    }
    with running_server() as (server, service):
        status, headers, payload = request(server, "GET", route)
        assert status == 405
        assert headers["Allow"] == "POST"
        assert json_body(payload)["error"]["code"] == "method_not_allowed"

        status, headers, payload = request(server, "POST", route, body=body)
        assert status == 201
        assert headers["Content-Type"] == "application/json; charset=utf-8"
        assert json_body(payload)["destination_id"] == body["destination_id"]

        status, _, payload = request(server, "POST", route + "?source=arbitrary", body=body)
        assert status == 400
        assert json_body(payload)["error"]["code"] == "invalid_management_query"

    assert service.calls == [("intake_reviewed_t1082", body)]


def test_action_package_routes_dispatch_exact_lifecycle_authority() -> None:
    install_body = {"envelope": {"schema_version": "bluefire.action-package.v1"}}
    lifecycle_body = {"actor": "local-operator", "reason": "explicit-test"}
    trust_body = {
        "publisher_id": PUBLISHER_ID,
        "key_id": PUBLISHER_KEY_ID,
        "public_key": "test-key",
    }
    with running_server() as (server, service):
        status, _, payload = request(server, "GET", "/api/v1/action-packages")
        assert status == 200
        assert json_body(payload)["packages"] == []
        assert service.calls[-1] == ("action_packages",)

        status, _, payload = request(
            server,
            "GET",
            f"/api/v1/action-packages/{PACKAGE_ID}",
        )
        assert status == 200
        assert json_body(payload)["package"]["package_id"] == PACKAGE_ID
        assert service.calls[-1] == ("action_package", PACKAGE_ID)

        status, _, _ = request(
            server,
            "POST",
            "/api/v1/action-packages",
            body=install_body,
        )
        assert status == 201
        assert service.calls[-1] == ("install_action_package", install_body)

        for action, operation in (
            ("activate", "activate_action_package"),
            ("deactivate", "deactivate_action_package"),
            ("remove", "remove_action_package"),
        ):
            status, _, payload = request(
                server,
                "POST",
                f"/api/v1/action-packages/{PACKAGE_ID}/versions/{PACKAGE_VERSION}/{action}",
                body=lifecycle_body,
            )
            assert status == 200
            assert json_body(payload)["package"]["version"] == PACKAGE_VERSION
            assert service.calls[-1] == (
                operation,
                PACKAGE_ID,
                PACKAGE_VERSION,
                lifecycle_body,
            )

        status, _, _ = request(
            server,
            "POST",
            "/api/v1/action-package-publishers",
            body=trust_body,
        )
        assert status == 201
        assert service.calls[-1] == ("trust_action_package_publisher", trust_body)

        for action in ("suspend", "revoke"):
            status, _, payload = request(
                server,
                "POST",
                (
                    f"/api/v1/action-package-publishers/{PUBLISHER_ID}"
                    f"/keys/{PUBLISHER_KEY_ID}/{action}"
                ),
                body=lifecycle_body,
            )
            assert status == 200
            assert json_body(payload)["publisher"]["state"] == action
            assert service.calls[-1] == (
                "transition_action_package_publisher",
                PUBLISHER_ID,
                PUBLISHER_KEY_ID,
                action,
                lifecycle_body,
            )


def test_provider_package_api_forwards_exact_v2_envelope_and_lifecycle_authority() -> None:
    envelope = json.loads(
        (PROVIDER_FIXTURE_ROOT / "provider-1.0.0.signed.json").read_text(encoding="utf-8")
    )
    index = json.loads((PROVIDER_FIXTURE_ROOT / "fixture-index.json").read_text(encoding="utf-8"))
    row = index["packages"][0]
    package_id = index["package_id"]
    version = row["version"]
    install_body = {"envelope": envelope, "installed_by": "provider-api-operator"}
    activate_body = {
        "runner_profile_id": "sandbox-execute.v1",
        "activated_by": "provider-api-operator",
        "reason": "Verify the exact signed provider fixture through the API route.",
    }
    catalog_digest = "sha256:" + "7" * 64
    lifecycle_body = {
        "package_digest": row["package_digest"],
        "expected_catalog_generation": 7,
        "expected_catalog_digest": catalog_digest,
        "deactivated_by": "provider-api-operator",
        "reason": "Verify exact provider deactivation authority.",
    }
    removal_body = {
        **lifecycle_body,
        "removed_by": "provider-api-operator",
    }
    removal_body.pop("deactivated_by")

    with running_server(max_request_body=1024 * 1024) as (server, service):
        status, _, _ = request(
            server,
            "POST",
            "/api/v1/action-packages",
            body=install_body,
        )
        assert status == 201
        assert service.calls[-1] == ("install_action_package", install_body)

        status, _, _ = request(
            server,
            "POST",
            f"/api/v1/action-packages/{package_id}/versions/{version}/activate",
            body=activate_body,
        )
        assert status == 200
        assert service.calls[-1] == (
            "activate_action_package",
            package_id,
            version,
            activate_body,
        )

        status, _, _ = request(
            server,
            "POST",
            f"/api/v1/action-packages/{package_id}/versions/{version}/deactivate",
            body=lifecycle_body,
        )
        assert status == 200
        assert service.calls[-1] == (
            "deactivate_action_package",
            package_id,
            version,
            lifecycle_body,
        )

        status, _, _ = request(
            server,
            "POST",
            f"/api/v1/action-packages/{package_id}/versions/{version}/remove",
            body=removal_body,
        )
        assert status == 200
        assert service.calls[-1] == (
            "remove_action_package",
            package_id,
            version,
            removal_body,
        )


@pytest.mark.parametrize(
    ("method", "path", "expected_code"),
    [
        ("GET", "/api/v1/action-packages?active=true", "invalid_management_query"),
        ("GET", "/api/v1/action-packages#inventory", "invalid_management_query"),
        ("GET", "/api/v1/action-packages/Package.Upper", "invalid_action_package_id"),
        (
            "POST",
            f"/api/v1/action-packages/{PACKAGE_ID}/versions/01.2.3/activate",
            "invalid_action_package_version",
        ),
        (
            "POST",
            f"/api/v1/action-packages/{PACKAGE_ID}/versions/1.2.3-01/activate",
            "invalid_action_package_version",
        ),
        (
            "POST",
            f"/api/v1/action-packages/{PACKAGE_ID}/versions/18446744073709551616.0.0/activate",
            "invalid_action_package_version",
        ),
        (
            "POST",
            f"/api/v1/action-packages/{PACKAGE_ID}/versions/{PACKAGE_VERSION}/restart",
            "invalid_action_package_action",
        ),
        (
            "GET",
            f"/api/v1/action-packages/{PACKAGE_ID}/versions/{PACKAGE_VERSION}",
            "invalid_action_package_path",
        ),
        (
            "POST",
            "/api/v1/action-package-publishers/Publisher.Upper/keys/release-key.v1/suspend",
            "invalid_action_package_publisher_id",
        ),
        (
            "POST",
            f"/api/v1/action-package-publishers/{PUBLISHER_ID}/keys/Key.Upper/suspend",
            "invalid_action_package_key_id",
        ),
        (
            "POST",
            (f"/api/v1/action-package-publishers/{PUBLISHER_ID}" f"/keys/{PUBLISHER_KEY_ID}/trust"),
            "invalid_action_package_publisher_action",
        ),
        (
            "POST",
            "/api/v1/action-package-publishers?scope=global",
            "invalid_management_query",
        ),
    ],
)
def test_action_package_routes_reject_ambiguous_path_authority(
    method: str,
    path: str,
    expected_code: str,
) -> None:
    with running_server() as (server, service):
        status, _, payload = request(
            server,
            method,
            path,
            body={} if method == "POST" else None,
        )

    assert status == 400
    assert json_body(payload)["error"]["code"] == expected_code
    assert not service.calls


@pytest.mark.parametrize(
    ("method", "path", "expected_allow"),
    [
        ("HEAD", "/api/v1/action-packages", "GET, POST"),
        ("PUT", "/api/v1/action-packages", "GET, POST"),
        ("POST", f"/api/v1/action-packages/{PACKAGE_ID}", "GET"),
        ("HEAD", f"/api/v1/action-packages/{PACKAGE_ID}", "GET"),
        (
            "GET",
            f"/api/v1/action-packages/{PACKAGE_ID}/versions/{PACKAGE_VERSION}/activate",
            "POST",
        ),
        (
            "DELETE",
            f"/api/v1/action-packages/{PACKAGE_ID}/versions/{PACKAGE_VERSION}/remove",
            "POST",
        ),
        ("GET", "/api/v1/action-package-publishers", "POST"),
        ("PATCH", "/api/v1/action-package-publishers", "POST"),
        (
            "GET",
            (
                f"/api/v1/action-package-publishers/{PUBLISHER_ID}"
                f"/keys/{PUBLISHER_KEY_ID}/suspend"
            ),
            "POST",
        ),
    ],
)
def test_action_package_routes_report_exact_allowed_methods(
    method: str,
    path: str,
    expected_allow: str,
) -> None:
    with running_server() as (server, service):
        status, headers, payload = request(
            server,
            method,
            path,
            body={} if method == "POST" else None,
        )

    assert status == 405
    assert headers["Allow"] == expected_allow
    if method == "HEAD":
        assert payload == b""
    else:
        assert json_body(payload)["error"]["code"] == "method_not_allowed"
    assert not service.calls


def test_action_package_posts_keep_pre_body_browser_and_same_origin_guards() -> None:
    with running_server() as (server, service):
        status, _, payload = request(
            server,
            "POST",
            "/api/v1/action-packages",
            body={},
            origin="http://example.test",
        )
        assert status == 403
        assert json_body(payload)["error"]["code"] == "origin_rejected"

        port = server.server_address[1]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.putrequest("POST", "/api/v1/action-packages")
        connection.putheader("Origin", f"http://127.0.0.1:{port}")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "1048576")
        connection.endheaders()
        response = connection.getresponse()
        unauthorized_payload = response.read()
        response_headers = dict(response.getheaders())
        connection.close()

    assert response.status == 401
    assert response_headers["Connection"] == "close"
    assert json_body(unauthorized_payload)["error"]["code"] == "browser_session_required"
    assert not service.calls


def test_runner_routes_dispatch_only_explicit_managed_lifecycle_actions() -> None:
    profile_id = "sandbox-execute.v1"
    with running_server() as (server, service):
        status, _, payload = request(server, "GET", "/api/v1/runner")
        assert status == 200
        assert json_body(payload)["state"] == "ready"

        actions = [
            (
                "bootstrap",
                {"profile_id": profile_id, "allow_upgrade": True},
                ("bootstrap_runner", profile_id, True),
            ),
            ("start", {"profile_id": profile_id}, ("start_runner", profile_id)),
            ("stop", {"profile_id": profile_id}, ("stop_runner", profile_id)),
            ("revoke", {}, ("revoke_runner",)),
            (
                "remove",
                {"confirm_runner_id": "bluefire-rust-runner.v1"},
                ("remove_runner", "bluefire-rust-runner.v1"),
            ),
        ]
        for action, body, expected_call in actions:
            status, _, payload = request(
                server,
                "POST",
                f"/api/v1/runner/{action}",
                body=body,
            )
            assert status == 200
            assert json_body(payload)["state"]
            assert service.calls[-1] == expected_call

        assert service.calls[0] == ("runner_status", None)


@pytest.mark.parametrize(
    ("action", "body"),
    [
        ("bootstrap", {"unknown": True}),
        ("start", {"allow_upgrade": True}),
        ("stop", {"confirm_runner_id": "wrong-boundary"}),
        ("revoke", {"profile_id": "sandbox-execute.v1"}),
        ("remove", {}),
        (
            "remove",
            {"confirm_runner_id": "bluefire-rust-runner.v1", "extra": True},
        ),
    ],
)
def test_runner_routes_reject_ambiguous_action_bodies(
    action: str,
    body: Mapping[str, Any],
) -> None:
    with running_server() as (server, service):
        status, _, payload = request(
            server,
            "POST",
            f"/api/v1/runner/{action}",
            body=body,
        )

    assert status == 400
    assert json_body(payload)["error"]["code"] == "runner_action_invalid"
    assert not service.calls


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
            "clone": "clone_detection_candidate",
            "tune": "tune_detection_candidate",
            "compare": "compare_detection_candidates",
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
            assert status == (201 if action in {"clone", "tune"} else 200)
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
        connection.putheader("Cookie", server._test_browser_cookie)  # type: ignore[attr-defined]
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
            "Cookie": server._test_browser_cookie,  # type: ignore[attr-defined]
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
            "POST",
            "/api/v1/jobs",
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
            assert "script-src 'self';" in headers["Content-Security-Policy"]
            assert "style-src 'self' 'unsafe-inline'" in headers["Content-Security-Policy"]
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
