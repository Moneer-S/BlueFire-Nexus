"""Authenticated shared Compare routes, with only saved synthetic S3 operations.

The opt-in producer writes actual API bytes, never reconstructed browser responses.
It does not exercise installed runners, SDK calls, credentials, or AWS.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from tests_platform.test_api import json_body, request, running_server
from tests_platform.test_s3_comparison import (
    comparison_service,
    forbidden,
    journey,
    saved_state,
)
from tests_platform.test_s3_comparison import stable_identities as stable_identities

FIXTURE = Path(__file__).with_name("fixtures") / "s3_comparison_v1.json"
MAX_CAPTURE_BYTES = 8 * 1024 * 1024


@pytest.fixture(autouse=True)
def local_transport_only(monkeypatch):
    original = socket.socket.connect

    def loopback(sock, address):
        assert isinstance(address, tuple) and address[0] == "127.0.0.1"
        return original(sock, address)

    monkeypatch.setattr(socket.socket, "connect", loopback)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def capture(server, method, path, body=None):
    status, headers, raw = request(server, method, path, body=body)
    assert status == 200, (method, path, status)
    assert len(raw) <= MAX_CAPTURE_BYTES
    assert headers["Content-Type"].startswith("application/json")
    return {
        "method": method,
        "path": path,
        "request_body": deepcopy(body),
        "status": status,
        "content_type": headers["Content-Type"],
        "body_utf8": raw.decode("utf-8"),
    }


def compare_case(server, name, identifiers):
    body = {"run_ids": identifiers}
    captured = capture(server, "POST", "/api/v1/comparisons", body)
    return {"name": name, "request": body, "response": json.loads(captured["body_utf8"])}, captured


def test_authenticated_compare_route_joins_saved_results_and_has_no_effects(
    tmp_path, stable_identities
):
    with comparison_service(tmp_path) as (app, executor):
        owner, _, identifiers = journey(app, executor)
        expected = app.compare({"run_ids": identifiers})
        before, calls = saved_state(app, owner), deepcopy(executor.calls)
        executor.environments = executor.readiness = executor.execute = forbidden
        with running_server(app) as (server, _):
            status, _, raw = request(
                server, "POST", "/api/v1/comparisons", body={"run_ids": identifiers}
            )
            assert status == 200 and json_body(raw) == expected
        assert server.socket.fileno() == -1
        assert saved_state(app, owner) == before and executor.calls == calls


@pytest.mark.parametrize(
    "authorized,origin,expected", [(False, "same", 401), (True, "https://example.invalid", 403)]
)
def test_compare_auth_and_origin_refuse_before_saved_context_access(
    tmp_path, stable_identities, monkeypatch, authorized, origin, expected
):
    with comparison_service(tmp_path) as (app, executor):
        owner, _, identifiers = journey(app, executor)
        before, calls = saved_state(app, owner), deepcopy(executor.calls)
        monkeypatch.setattr(app, "compare", forbidden)
        with running_server(app, authenticate=authorized) as (server, _):
            status, _, _ = request(
                server, "POST", "/api/v1/comparisons", body={"run_ids": identifiers}, origin=origin
            )
            assert status == expected
        assert server.socket.fileno() == -1
        assert saved_state(app, owner) == before and executor.calls == calls


def produce_contract(root):
    cases, routes = [], []
    with comparison_service(root / "paired") as (app, executor):
        owner, reads, identifiers = journey(app, executor)
        before, calls = saved_state(app, owner), deepcopy(executor.calls)
        with running_server(app) as (server, _):
            selections = [
                ("paired_denied", identifiers),
                ("baseline_only", reads["baseline"]),
                ("retest_only", reads["retest"]),
                ("partial_selection", [reads["baseline"][0], reads["retest"][0]]),
                ("reversed_selection", list(reversed(identifiers))),
            ]
            for name, selected in selections:
                case, route = compare_case(server, name, selected)
                cases.append(case)
                routes.append(route)
            saved_jobs = app.s3_access
            try:
                app.s3_access = None
                case, _ = compare_case(server, "missing_context", identifiers)
                cases.append(case)
            finally:
                app.s3_access = saved_jobs
            for path in [
                "/api/v1/catalog",
                "/api/v1/scenarios",
                "/api/v1/detections",
                "/api/v1/jobs",
                "/api/v1/s3-access/environments",
                "/api/v1/s3-access/exercises",
                f"/api/v1/s3-access/exercises/{owner}",
                f"/api/v1/s3-access/exercises/{owner}/audit-reviews",
                "/api/v1/runs",
                *[f"/api/v1/runs/{identifier}" for identifier in identifiers],
            ]:
                routes.append(capture(server, "GET", path))
        assert server.socket.fileno() == -1
        assert saved_state(app, owner) == before and executor.calls == calls
    for mode in (
        "unchanged_probe",
        "legitimate_denied",
        "failed_legitimate",
        "failed_assume_role",
        "not_started",
        "unknown_cleanup",
        "mixed_provenance",
    ):
        with comparison_service(root / mode) as (app, executor):
            other_owner, _, identifiers = journey(app, executor, mode)
            before, calls = saved_state(app, other_owner), deepcopy(executor.calls)
            with running_server(app) as (server, _):
                case, _ = compare_case(server, mode, identifiers)
                cases.append(case)
            assert server.socket.fileno() == -1
            assert saved_state(app, other_owner) == before and executor.calls == calls
    return {
        "schema_version": "bluefire.s3-comparison-fixtures.v1",
        "proof_scope": "synthetic_application_responses",
        "cases": cases,
        "browser": {"owner_id": owner, "routes": routes},
    }


def test_actual_api_contract_fixture(tmp_path, stable_identities):
    document = produce_contract(tmp_path)
    encoded = (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )
    assert len(encoded) <= MAX_CAPTURE_BYTES
    # Capture only public synthetic response material, never session/bootstrap headers.
    for forbidden_value in (
        str(tmp_path),
        str(Path.home()),
        "X-BlueFire-Browser-Session",
        "X-BlueFire-Browser-Bootstrap",
    ):
        assert forbidden_value not in encoded.decode("utf-8")
    if os.environ.get("BLUEFIRE_WRITE_S3_COMPARISON_FIXTURE") == "1":
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        with FIXTURE.open("xb") as target:
            target.write(encoded)
    assert (
        FIXTURE.is_file()
    ), "Generate the actual response fixture with BLUEFIRE_WRITE_S3_COMPARISON_FIXTURE=1."
    assert json.loads(FIXTURE.read_text(encoding="utf-8")) == document
