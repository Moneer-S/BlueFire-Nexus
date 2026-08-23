from __future__ import annotations

import http.client
import json
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

import pytest

from bluefire.api import APIError, BlueFireHTTPServer, create_server

RUN_ID = "run-20260823T120000Z-0123456789abcdef"


class StubService:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def catalog(self):
        self.calls.append(("catalog",))
        return {"behaviors": [{"id": "observe.host.v1"}], "runner_profiles": []}

    def scenarios(self):
        self.calls.append(("scenarios",))
        return {"scenarios": []}

    def validate(self, request: Mapping[str, Any]):
        self.calls.append(("validate", request))
        return {"valid": True}

    def preflight(self, request: Mapping[str, Any]):
        self.calls.append(("preflight", request))
        return {"ready": True}

    def run(self, request: Mapping[str, Any]):
        self.calls.append(("run", request))
        return {"run_id": RUN_ID, "status": "created"}

    def list(self):
        self.calls.append(("list",))
        return {"runs": [{"run_id": RUN_ID, "status": "created"}]}

    def detail(self, run_id: str):
        self.calls.append(("detail", run_id))
        if run_id == "run-20260823T120000Z-ffffffffffffffff":
            raise APIError(404, "run_not_found", "Run was not found.")
        return {"run_id": run_id, "status": "created"}

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


def test_get_routes_dispatch_to_the_injected_service() -> None:
    with running_server() as (server, service):
        routes = [
            ("/api/v1/catalog", "catalog"),
            ("/api/v1/scenarios", "scenarios"),
            ("/api/v1/runs", "list"),
            (f"/api/v1/runs/{RUN_ID}", "detail"),
        ]
        for path, expected_call in routes:
            status, headers, payload = request(server, "GET", path)
            assert status == 200
            assert headers["Content-Type"] == "application/json; charset=utf-8"
            assert json_body(payload)
            assert service.calls[-1][0] == expected_call


def test_post_routes_forward_json_objects_without_orchestration() -> None:
    body = {"scenario": {"schema_version": "bluefire.scenario.v1"}}
    with running_server() as (server, service):
        cases = [
            ("/api/v1/scenarios/validate", 200, "validate"),
            ("/api/v1/runs/preflight", 200, "preflight"),
            ("/api/v1/runs", 201, "run"),
            (f"/api/v1/runs/{RUN_ID}/replays", 201, "replay"),
            ("/api/v1/comparisons", 200, "compare"),
        ]
        for path, expected_status, expected_call in cases:
            status, _, payload = request(server, "POST", path, body=body)
            assert status == expected_status
            assert json_body(payload)
            assert service.calls[-1][0] == expected_call


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
