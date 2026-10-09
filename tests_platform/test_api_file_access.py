"""File-access routes retain the authenticated HTTP shell and exact saved identities."""

import pytest

from tests_platform.test_api import JOB_ID, json_body, request, running_server

SUBMISSION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PREFIX = "/api/v1/file-access/"
READS = (
    "status",
    f"operations/{JOB_ID}",
    f"controls/{JOB_ID}",
    f"operations/{JOB_ID}/reconciliations/{SUBMISSION_ID}",
)
WRITES = ("review", "operations", "control-list", f"operations/{JOB_ID}/reconcile")


def test_file_access_routes_forward_exact_bodies_and_saved_identifiers():
    body = {"submission_id": SUBMISSION_ID, "review": {"operation": "create"}}
    routes = (
        ("GET", READS[0], ("file_access_status",)),
        ("GET", READS[1], ("file_access_operation", JOB_ID)),
        ("GET", READS[2], ("file_access_control", JOB_ID)),
        ("GET", READS[3], ("file_access_reconciliation", JOB_ID, SUBMISSION_ID)),
        ("POST", WRITES[0], ("file_access_review", body)),
        ("POST", WRITES[1], ("submit_file_access_operation", body)),
        ("POST", WRITES[2], ("list_file_access_controls", body)),
        ("POST", WRITES[3], ("reconcile_file_access_operation", JOB_ID, body)),
    )
    with running_server() as (server, service):
        for method, suffix, expected in routes:
            status, headers, payload = request(
                server, method, PREFIX + suffix, body=body if method == "POST" else None
            )
            assert status == 200
            assert headers["Content-Type"] == "application/json; charset=utf-8"
            assert json_body(payload) == {"saved": True}
            assert service.calls[-1] == expected
        assert service.calls == [expected for _, _, expected in routes]


@pytest.mark.parametrize("suffix", WRITES)
def test_file_access_mutations_refuse_before_service_dispatch(suffix):
    violations = (
        ("GET", "", None, {}, 405, "method_not_allowed"),
        ("POST", "?authority=expanded", {}, {}, 400, "invalid_management_query"),
        ("POST", "#authority", {}, {}, 400, "invalid_management_query"),
        ("POST", "", {}, {"authenticated": False}, 401, "browser_session_required"),
        ("POST", "", {}, {"origin": "https://untrusted.example"}, 403, "origin_rejected"),
        ("POST", "", [], {}, 400, "object_required"),
        ("POST", "", b"{", {}, 400, "invalid_json"),
        ("POST", "", {}, {"content_type": "text/plain"}, 415, "content_type_required"),
    )
    with running_server() as (server, service):
        for method, tail, body, options, expected_status, expected_code in violations:
            status, _, payload = request(
                server, method, PREFIX + suffix + tail, body=body, **options
            )
            assert status == expected_status
            assert json_body(payload)["error"]["code"] == expected_code
            assert service.calls == []


@pytest.mark.parametrize("suffix", READS)
def test_file_access_reads_keep_session_query_and_verb_guards(suffix):
    violations = (
        ("GET", "", None, False, 401, "browser_session_required"),
        ("GET", "?scope=expanded", None, True, 400, "invalid_management_query"),
        ("GET", "#authority", None, True, 400, "invalid_management_query"),
        ("POST", "", {}, True, 405, "method_not_allowed"),
    )
    with running_server() as (server, service):
        for method, tail, body, authenticated, expected_status, expected_code in violations:
            status, _, payload = request(
                server, method, PREFIX + suffix + tail, body=body, authenticated=authenticated
            )
            assert status == expected_status
            assert json_body(payload)["error"]["code"] == expected_code
            assert service.calls == []


@pytest.mark.parametrize(
    "suffix",
    [
        "operations/bad",
        f"operations/{JOB_ID.upper()}",
        f"operations/{JOB_ID}/",
        f"operations/{JOB_ID}/execute",
        f"operations/{JOB_ID}/reconciliations/bad",
        f"operations/{JOB_ID}/reconciliations/{SUBMISSION_ID.upper()}",
        f"controls/{JOB_ID}/reconcile",
        f"controls/{JOB_ID}/reconciliations/{SUBMISSION_ID}",
        "controls",
        "enrollments",
        "approve",
    ],
)
def test_file_access_paths_require_canonical_saved_identities(suffix):
    with running_server() as (server, service):
        for method in ("GET", "POST"):
            status, _, payload = request(
                server, method, PREFIX + suffix, body={} if method == "POST" else None
            )
            assert status == 400
            assert json_body(payload)["error"]["code"] == "file_access_invalid"
            assert service.calls == []


def test_file_access_does_not_add_unsupported_http_methods():
    with running_server() as (server, service):
        for method in ("HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"):
            status, _, _ = request(server, method, PREFIX + "operations", body={})
            assert status == 405
            assert service.calls == []
