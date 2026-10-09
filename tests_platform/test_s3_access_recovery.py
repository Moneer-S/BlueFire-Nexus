"""Historical original results are adopted without discovery or replay."""

from datetime import datetime, timedelta
from threading import Event

import pytest

from bluefire import s3_access_executor as module
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_recovery import validate_recovery_context
from tests_platform.test_s3_access_executor import configured as configured
from tests_platform.test_s3_access_wire import NOW


def dispatched(configured):
    contexts = []

    def retain(context):
        assert not configured.client.calls
        contexts.append(validate_recovery_context(configured.request, context))

    execution = configured.executor.execute(
        configured.request,
        authorization=configured.approval,
        cancellation_event=Event(),
        before_dispatch=retain,
    )
    context = contexts[0]
    configured.client.recovery = {
        "original_task_id": context["task_id"],
        "original_request_hash": context["transport_request_hash"],
        "state": "completed",
        "result": configured.client.result,
        "error_code": None,
        "cancellation_requested": False,
        "receipt_ids": [],
        "cleanup_required": False,
    }
    return context, execution


def test_missing_callback_cannot_dispatch(configured):
    with pytest.raises(S3AccessError, match="durably saved"):
        configured.executor.execute(
            configured.request, authorization=configured.approval, cancellation_event=Event()
        )
    assert not configured.client.calls


def test_checkpoint_failure_refuses_dispatch_and_sanitizes_details(configured):
    def fail(context):
        raise OSError("private database detail")

    with pytest.raises(S3AccessError, match="not dispatched") as caught:
        configured.executor.execute(
            configured.request,
            authorization=configured.approval,
            cancellation_event=Event(),
            before_dispatch=fail,
        )
    assert "private" not in str(caught.value)
    assert not configured.client.calls


def test_callback_must_finish_synchronously(configured):
    with pytest.raises(S3AccessError, match="not dispatched"):
        configured.executor.execute(
            configured.request,
            authorization=configured.approval,
            cancellation_event=Event(),
            before_dispatch=lambda context: True,
        )
    assert not configured.client.calls


def test_original_identity_is_durable_before_dispatch_and_canonical_copy(configured):
    context, _ = dispatched(configured)
    checked = validate_recovery_context(configured.request, context)
    checked["profile"]["profile_id"] = "changed"
    assert checked != context
    assert "credential_reference" not in str(context) and "secret_access_key" not in str(context)


def test_recovery_after_scope_expiry_uses_only_original_authenticated_task(configured, monkeypatch):
    context, execution = dispatched(configured)

    class Expired(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW + timedelta(days=30)

    monkeypatch.setattr(module, "datetime", Expired)
    configured.client.s3_access_environments = lambda: pytest.fail("fresh discovery")
    configured.client.execute_task = lambda *a, **k: pytest.fail("execution replay")
    recovered = module.configured_executor(configured.service).recover_original(
        configured.request, context
    )
    assert recovered == {"status": "finalized", "execution": execution}
    assert configured.client.recovery_calls == [
        (context["task_id"], context["transport_request_hash"])
    ]
    assert len(configured.client.calls) == 1


@pytest.mark.parametrize(
    "state,status",
    [
        ("running", "running"),
        ("not_found", "absent"),
        ("indeterminate", "unavailable"),
        ("recovery_required", "unavailable"),
        ("failed", "unavailable"),
    ],
)
def test_unresolved_original_never_becomes_permission_to_replay(configured, state, status):
    context, _ = dispatched(configured)
    configured.client.recovery.update(state=state, result=None)
    assert configured.executor.recover_original(configured.request, context) == {
        "status": status,
        "execution": None,
    }
    assert len(configured.client.calls) == 1


@pytest.mark.parametrize(
    "field",
    [
        "enrollment_generation",
        "runner_binary_digest",
        "inventory_digest",
        "server_fingerprint",
        "client_fingerprint",
    ],
)
def test_changed_authenticated_host_cannot_supply_historical_result(configured, field):
    context, _ = dispatched(configured)
    configured.client.identity[field] = "sha256:" + "b" * 64
    assert (
        configured.executor.recover_original(configured.request, context)["status"] == "unavailable"
    )
    assert not configured.client.recovery_calls


@pytest.mark.parametrize("field", ["task_id", "transport_request_hash", "request_digest"])
def test_changed_saved_original_identity_is_rejected_before_contact(configured, field):
    context, _ = dispatched(configured)
    context[field] = "other"
    with pytest.raises(S3AccessError):
        configured.executor.recover_original(configured.request, context)
    assert not configured.client.recovery_calls


@pytest.mark.parametrize(
    "kind",
    ["request", "synthetic", "cleanup", "response_identity", "extra_context", "secret_field"],
)
def test_corrupt_result_or_checkpoint_cannot_be_adopted(configured, kind):
    context, _ = dispatched(configured)
    if kind == "request":
        configured.client.recovery["result"]["request_id"] = "wrong"
    elif kind == "synthetic":
        configured.client.recovery["result"]["output"]["s3_execution"]["provenance"] = "synthetic"
    elif kind == "cleanup":
        configured.client.recovery["cleanup_required"] = True
    elif kind == "response_identity":
        configured.client.recovery["original_task_id"] = "other"
    else:
        if kind == "extra_context":
            context["unexpected"] = True
        else:
            context["profile"]["secret_access_key"] = "FAKE-UNUSED"
        with pytest.raises(S3AccessError):
            validate_recovery_context(configured.request, context)
        return
    assert configured.executor.recover_original(configured.request, context) == {
        "status": "unavailable",
        "execution": None,
    }


def test_cancel_after_checkpoint_does_not_dispatch(configured):
    cancelled = Event()
    result = configured.executor.execute(
        configured.request,
        authorization=configured.approval,
        cancellation_event=cancelled,
        before_dispatch=lambda context: cancelled.set(),
    )
    assert result["dispatch"] == "not_started"
    assert not configured.client.calls
