"""Read-only policy reconciliation and execution accounting, with fake clients."""

import threading
from copy import deepcopy
from datetime import datetime

import pytest

from bluefire import s3_access_executor as executor_module
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_execution_contract import validate_execution
from bluefire.s3_access_executor import configured_executor
from bluefire.s3_access_sdk import S3SdkAdapter
from bluefire.s3_access_wire import S3WorkerRequest, operation_plan, validate_result
from bluefire.util import content_hash
from tests_platform.test_s3_access_sdk import FakeFactory, worker_request
from tests_platform.test_s3_access_wire import NOW, acknowledge, credentials, request_row


@pytest.mark.parametrize("state", ["before", "after", "drift"])
def test_reconciliation_observes_full_policy_without_mutation(state):
    request = worker_request("reconcile_policy")
    factory = FakeFactory(request)
    if state == "after":
        factory.policy = request.to_dict()["policy_change"]["after"]
    elif state == "drift":
        factory.policy["Statement"][0]["Sid"] = "AnotherStatement"
    original = deepcopy(factory.policy)
    result = S3SdkAdapter(
        request, credentials(), factory=factory, permit=acknowledge, clock=lambda: NOW
    ).execute()
    assert result["outcome"] == "observed"
    assert result["data"] == {
        "policy_digest": content_hash(original),
        "structural_review": "drift" if state == "drift" else "matched_" + state,
    }
    assert factory.policy == original
    assert [call[0] for call in factory.calls] == ["GetCallerIdentity", "GetBucketPolicy"]
    assert len(operation_plan(request)) == 2
    altered = deepcopy(result)
    altered["data"]["structural_review"] = (
        "matched_before" if state != "before" else "matched_after"
    )
    with pytest.raises(S3AccessError):
        validate_result(request, altered)


@pytest.mark.parametrize(
    "field,value",
    [
        ("policy_change", None),
        ("policy_change", {}),
        ("exclusive_writer_digest", "sha256:" + "f" * 64),
        ("max_sends", 3),
    ],
)
def test_reconciliation_requires_exact_review_and_no_write_authority(field, value):
    row = request_row("reconcile_policy")
    row[field] = value
    with pytest.raises(S3AccessError):
        S3WorkerRequest.from_mapping(row)


def execution_row(request):
    result = S3SdkAdapter(
        request, credentials(), factory=FakeFactory(request), permit=acknowledge, clock=lambda: NOW
    ).execute()
    return {
        "schema_version": "bluefire.s3-execution.v1",
        "request_digest": request.digest,
        "admission": {"accepted": True, "problem": None},
        "dispatch": "permit_issued",
        "send_debits": result["send_permits_consumed"],
        "result": result,
        "cleanup": "verified",
        "provenance": "synthetic",
        "reservation_digest": "sha256:" + "f" * 64,
    }


def test_execution_projection_retains_synthetic_and_unknown_cleanup():
    request = worker_request()
    row = execution_row(request)
    row["cleanup"] = "unknown"
    assert validate_execution(request, row) == row
    assert row["provenance"] == "synthetic"


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_digest", "sha256:" + "0" * 64),
        ("send_debits", True),
        ("send_debits", 1),
        ("reservation_digest", None),
        ("dispatch", "not_started"),
        ("cleanup", "done"),
        ("provenance", "independent"),
        ("admission", {"accepted": 1, "problem": None}),
        ("admission", {"accepted": False, "problem": "admission_refused"}),
    ],
)
def test_execution_refuses_inconsistent_accounting_and_provenance(field, value):
    request = worker_request()
    row = execution_row(request)
    row[field] = value
    with pytest.raises(S3AccessError):
        validate_execution(request, row)


def test_lost_write_ack_cannot_be_reported_as_settled_failure():
    request = worker_request("apply_policy")
    row = execution_row(request)
    row["send_debits"] = 3
    row["result"] = None
    with pytest.raises(S3AccessError):
        validate_execution(request, row)
    row["dispatch"] = "unknown"
    assert validate_execution(request, row)["result"] is None


def test_default_executor_never_discovers_ambient_cloud_access(monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(executor_module, "datetime", Clock)
    executor = configured_executor(object())
    request = worker_request()
    assert executor.environments() == []
    result = executor.execute(request, authorization={}, cancellation_event=threading.Event())
    assert result["admission"] == {"accepted": False, "problem": "runtime_unavailable"}
    assert result["send_debits"] == 0
    assert result["dispatch"] == "not_started"
