"""Connected fail-closed Windows branch and explicit fake Linux regression."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from bluefire import file_access_context as context
from bluefire import file_access_execution
from bluefire.file_access_contract import FileAccessContractError
from bluefire.file_access_control import FileAccessControl
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash
from tests_platform.test_windows_file_access_enrollment import NOW_MS, declared_candidate


def forbidden(*args, **kwargs):
    raise AssertionError("unavailable Windows context must not enter Linux or resource effects")


@pytest.fixture
def windows(monkeypatch):
    from bluefire import _windows_file_access_enrollment_observe as observation

    def unavailable(**kwargs):
        raise RuntimeError("Synthetic unavailable protected observer")

    monkeypatch.setattr(observation, "observe", unavailable)
    monkeypatch.setattr(observation, "observe_status", unavailable)
    monkeypatch.setattr(context, "is_macos_host", lambda: False)
    monkeypatch.setattr(context, "is_windows_host", lambda: True)
    monkeypatch.setattr(context, "read_file_access_enrollment", forbidden)
    monkeypatch.setattr(context, "inspect_file_access_resource", forbidden)
    monkeypatch.setattr(file_access_execution, "recipe", forbidden)
    store = SimpleNamespace(
        save_file_access_enrollment=forbidden, get_file_access_control=forbidden
    )
    # Caller attributes are assertions only, not a native/protected producer.
    service = SimpleNamespace(
        product_store=store,
        windows_file_access_verified=True,
        windows_file_access_enrollment=declared_candidate(),
        windows_credential_provider=forbidden,
        _profile=forbidden,
        _execute_readiness_boundary=forbidden,
    )
    return service, FileAccessControl(service, clock=lambda: NOW_MS)


def test_windows_status_is_honestly_unavailable_despite_parsed_data_or_claimed_trust_flags(windows):
    _, control = windows
    status = control.status()
    assert status == {
        "schema_version": "bluefire.file-access-status.v1",
        "available": False,
        "problem": {
            "code": "windows_file_access_enrollment_unavailable",
            "message": "Verified Windows protected setup and native admission are required.",
        },
        "enrollment": None,
        "allowed_operations": [],
    }
    assert "S-1-" not in str(status) and "owner_uid" not in str(status)


@pytest.mark.parametrize("operation", ["create", "baseline", "harden", "rollback", "reset"])
def test_windows_operations_refuse_before_linux_recipe_or_reservation(windows, operation):
    _, control = windows
    with pytest.raises((FileAccessContractError, ProductStoreError)):
        control._context(operation, None if operation == "create" else "synthetic-owner")


def test_existing_context_entrypoints_route_windows_to_fail_closed_boundary(windows):
    service, _ = windows
    for callback in (
        lambda: context.enrollment(service, NOW_MS),
        lambda: context.execution(service, {"verified": True}),
        lambda: context.binding({"verified": True}, revision=1, now_ms=NOW_MS),
        lambda: context.composition(service, "synthetic-owner", NOW_MS),
    ):
        with pytest.raises(FileAccessContractError):
            callback()


def test_verified_protected_setup_status_does_not_enable_any_operation(windows, monkeypatch):
    from bluefire import _windows_file_access_enrollment_observe as observation
    from bluefire import windows_file_access_enrollment as enrollment
    from bluefire.util import canonical_json_bytes

    service, control = windows
    row = declared_candidate()
    receipt = {"synthetic_protected_observer_receipt": True}
    row["setup_receipt_digest"] = content_hash(receipt)
    calls = []

    def observed(*, now_ms):
        assert now_ms == NOW_MS
        calls.append(now_ms)
        return canonical_json_bytes(row), canonical_json_bytes(receipt)

    monkeypatch.setattr(observation, "observe", observed)
    monkeypatch.setattr(observation, "observe_status", observed)
    status = control.status()
    assert status["available"] is False and status["allowed_operations"] == []
    assert status["enrollment"] is None
    assert status["setup"] == {
        "enrollment_id": row["enrollment_id"],
        "enrollment_digest": content_hash(row),
        "expires_at_ms": row["expires_at_ms"],
        "verification": "protected_setup_only",
    }
    assert status["problem"]["code"] == "windows_native_admission_unavailable"
    assert "S-1-" not in str(status) and "secret-ref" not in str(status)
    assert type(context.enrollment(service, NOW_MS)) is enrollment.VerifiedWindowsSetup
    with pytest.raises(enrollment.WindowsEnrollmentUnavailable):
        control._context("baseline", "synthetic-owner")
    assert calls == [NOW_MS] * 3


def test_linux_v1_enrollment_and_status_flow_remain_exact(monkeypatch):
    monkeypatch.setattr(context, "is_macos_host", lambda: False)
    monkeypatch.setattr(context, "is_windows_host", lambda: False)
    calls = []
    current = {
        "document": {
            "schema_version": "bluefire.file-access-enrollment.v1",
            "enrollment_id": "file-enrollment-synthetic",
            "expires_at_ms": NOW_MS + 1,
            "worker": {"uid": 1001},
        },
        "document_digest": "sha256:" + "a" * 64,
    }
    monkeypatch.setattr(context, "read_file_access_enrollment", lambda **kwargs: current)

    class Store:
        def save_file_access_enrollment(self, document, *, expected_document_digest):
            calls.append(("save", document, expected_document_digest))

        def get_file_access_enrollment(self, identity):
            calls.append(("get", identity))
            return current

        @contextmanager
        def _connection(self):
            yield SimpleNamespace(execute=lambda *args: SimpleNamespace(fetchone=lambda: None))

    service = SimpleNamespace(product_store=Store())
    control = FileAccessControl(service, clock=lambda: NOW_MS)
    assert control.status() == {
        "schema_version": "bluefire.file-access-status.v1",
        "available": True,
        "problem": None,
        "enrollment": {
            "enrollment_id": "file-enrollment-synthetic",
            "enrollment_digest": current["document_digest"],
            "expires_at_ms": NOW_MS + 1,
            "owner_uid": 1000,
            "probe_uid": 1001,
        },
        "allowed_operations": ["create"],
    }
    assert calls == [
        ("save", current["document"], current["document_digest"]),
        ("get", "file-enrollment-synthetic"),
    ]


def test_linux_context_still_uses_original_recipe_and_profile_flow(monkeypatch):
    monkeypatch.setattr(context, "is_macos_host", lambda: False)
    monkeypatch.setattr(context, "is_windows_host", lambda: False)
    enrolled = {
        "document": {"schema_version": "bluefire.file-access-enrollment.v1"},
        "document_digest": "sha256:" + "a" * 64,
    }
    profile = SimpleNamespace(
        id="sandbox-execute.v1", to_dict=lambda: {"profile_id": "sandbox-execute.v1"}
    )
    runtime = {
        "profile": profile,
        "implementation_digests": {"linux-method": "sha256:" + "b" * 64},
        "enrollment": enrolled,
        "expires_at_ms": NOW_MS + 1,
    }
    calls = []
    monkeypatch.setattr(context, "enrollment", lambda *args: enrolled)
    monkeypatch.setattr(context, "execution", lambda service, enrollment: runtime)

    def recipe(operation, control):
        calls.append((operation, control))
        return ["synthetic-linux-recipe"]

    monkeypatch.setattr(file_access_execution, "recipe", recipe)
    control = FileAccessControl(SimpleNamespace(product_store=object()), clock=lambda: NOW_MS)
    actual = control._context("create", None)
    assert calls == [("create", None)] and actual["control"] is None
    assert actual["review_context"]["recipe"] == ["synthetic-linux-recipe"]
    assert actual["review_context"]["profile_digest"] == content_hash(profile.to_dict())
