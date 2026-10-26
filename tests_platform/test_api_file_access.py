"""File-access routes retain the authenticated HTTP shell and exact saved identities."""

from types import SimpleNamespace

import pytest

from bluefire.file_access_control import FileAccessControl
from bluefire.product_store import ProductStore
from tests_platform.test_api import JOB_ID, StubService, json_body, request, running_server
from tests_platform.test_macos_file_access_contract import binding

SUBMISSION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PREFIX = "/api/v1/file-access/"
WINDOWS_CONTROL = "win-file-control-" + "b" * 32
MACOS_CONTROL = "file-control-" + "c" * 64
READS = (
    "status",
    f"operations/{JOB_ID}",
    f"controls/{JOB_ID}",
    f"operations/{JOB_ID}/reconciliations/{SUBMISSION_ID}",
    f"controls/{WINDOWS_CONTROL}",
    f"controls/{MACOS_CONTROL}",
)
WRITES = ("review", "operations", "control-list", f"operations/{JOB_ID}/reconcile", "setup-import")


def test_file_access_routes_forward_exact_bodies_and_saved_identifiers():
    body = {"submission_id": SUBMISSION_ID, "review": {"operation": "create"}}
    routes = (
        ("GET", READS[0], ("file_access_status",)),
        ("GET", READS[1], ("file_access_operation", JOB_ID)),
        ("GET", READS[2], ("file_access_control", JOB_ID)),
        ("GET", READS[3], ("file_access_reconciliation", JOB_ID, SUBMISSION_ID)),
        ("GET", READS[4], ("file_access_control", WINDOWS_CONTROL)),
        ("GET", READS[5], ("file_access_control", MACOS_CONTROL)),
        ("POST", WRITES[0], ("file_access_review", body)),
        ("POST", WRITES[1], ("submit_file_access_operation", body)),
        ("POST", WRITES[2], ("list_file_access_controls", body)),
        ("POST", WRITES[3], ("reconcile_file_access_operation", JOB_ID, body)),
        ("POST", WRITES[4], ("import_file_access_setup", body)),
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


def test_authenticated_http_reads_a_saved_macos_file_access_control(tmp_path):
    store = ProductStore(tmp_path / "owner.sqlite3")
    setup = {"schema_version": "bluefire.macos-file-access-setup.v1", "binding": binding()}
    saved = store.import_macos_file_access_setup(setup, now_ms=1000)
    owner = saved["control_owner_id"]
    assert owner.startswith("file-control-")
    assert len(owner) == len("file-control-") + 64

    service = StubService()
    control = FileAccessControl(SimpleNamespace(product_store=store), clock=lambda: 1000)
    service.file_access_control = lambda owner_id: control.control(owner_id)

    with running_server(service) as (server, _):
        status, headers, payload = request(server, "GET", PREFIX + f"controls/{owner}")

    result = json_body(payload)
    assert status == 200
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert result["schema_version"] == "bluefire.file-access-control.v1"
    assert result["platform"] == "macos"
    assert result["control_owner_id"] == owner
    assert result["status"] == "created"
    assert result["allowed_operations"] == []


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
        f"operations/{WINDOWS_CONTROL}",
        f"controls/{WINDOWS_CONTROL}/reconcile",
        f"controls/{WINDOWS_CONTROL.upper()}",
        "controls/file-control-" + "c" * 63,
        "controls/file-control-" + "c" * 65,
        "controls/file-control-" + "C" * 64,
        "controls/" + MACOS_CONTROL + "/reconcile",
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


@pytest.mark.parametrize("owner", [JOB_ID, WINDOWS_CONTROL, MACOS_CONTROL])
def test_saved_control_assistance_context_keeps_read_guards(owner):
    suffix = PREFIX + f"controls/{owner}/assistant-context"
    service = StubService()
    with running_server(service) as (server, _):
        status, _, payload = request(server, "GET", suffix)
        assert status == 200 and json_body(payload) == {"saved": True}
        assert service.calls == [("file_access_assistance_context", owner)]
        service.calls.clear()
        for method, tail, authenticated, expected in (
            ("GET", "", False, 401),
            ("GET", "?_saved_only=true", True, 400),
            ("GET", "#authority", True, 400),
            ("POST", "", True, 405),
        ):
            status, _, _ = request(
                server,
                method,
                suffix + tail,
                body={} if method == "POST" else None,
                authenticated=authenticated,
            )
            assert status == expected and service.calls == []


def test_actual_saved_control_assistance_http_is_minimized_and_does_not_probe(
    tmp_path, monkeypatch
):
    from bluefire import macos_file_access_control
    from bluefire.service import BlueFireService

    store = ProductStore(tmp_path / "saved.sqlite3")
    imported = store.import_macos_file_access_setup(
        {"schema_version": "bluefire.macos-file-access-setup.v1", "binding": binding()}, now_ms=1000
    )
    owner = imported["control_owner_id"]
    source = SimpleNamespace(product_store=store)
    source.file_access = FileAccessControl(source, clock=lambda: 1000)
    monkeypatch.setattr(
        macos_file_access_control,
        "endpoint",
        lambda *_: pytest.fail("Read contacted native endpoint"),
    )
    service = StubService()
    service.file_access_assistance_context = (
        lambda identifier: BlueFireService.file_access_assistance_context(source, identifier)
    )
    before = store.path.read_bytes()
    with running_server(service) as (server, _):
        status, _, payload = request(server, "GET", PREFIX + f"controls/{owner}/assistant-context")
    value = json_body(payload)
    assert status == 200 and value["analysis_only"] is True and value["capabilities"] == []
    assert value["selected"]["control_owner_id"] == owner
    assert value["reference_summary"]["readiness"] == "not_assessed"
    assert value["reference_summary"]["baseline"] == {"recorded": False}
    assert store.path.read_bytes() == before
