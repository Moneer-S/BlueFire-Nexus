"""Synthetic pairing tests; no collection, AWS calls, or native execution."""

import json

import pytest

from bluefire import s3_access_audit
from bluefire.s3_access_audit import correlate_read_pair
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_wire import S3WorkerRequest
from tests_platform.test_s3_access_audit import event, log, result
from tests_platform.test_s3_access_wire import request_row


def read_request(operation: str, request_id: str, *, deadline: str = "2026-10-09T00:00:30Z"):
    row = request_row(operation)
    row["request_id"] = request_id * 64
    row["deadline"] = deadline
    return S3WorkerRequest.from_mapping(row)


def worker_result(request: S3WorkerRequest, prefix: str):
    value = result(request)
    for index, call in enumerate(value["calls"][3:]):
        call["request_id"] = f"{prefix}-read-{index}"
    return value


def log_for(request: S3WorkerRequest, result_value: dict):
    reader = "probe" if request.to_dict()["operation"] == "probe_read" else "legitimate"
    count = 1 if reader == "probe" else 2
    events = []
    for index in range(count):
        row = event(request, index=index)
        reader_hex = "1" if reader == "probe" else "2"
        row["eventID"] = f"{reader_hex * 8}-0000-4000-8000-{index + 1:012d}"
        row["requestID"] = result_value["calls"][index + 3]["request_id"]
        events.append(row)
    return log(*events)


def make_pair():
    probe = read_request("probe_read", "a")
    legitimate = read_request("legitimate_read", "b", deadline="2026-10-09T00:00:20Z")
    probe_result = worker_result(probe, "probe")
    legitimate_result = worker_result(legitimate, "legitimate")
    return probe, probe_result, legitimate, legitimate_result


def test_pair_normalizes_shared_logs_once_and_keeps_one_projection(monkeypatch):
    probe, probe_result, legitimate, legitimate_result = make_pair()
    raw = [log_for(probe, probe_result), log_for(legitimate, legitimate_result)]
    original = s3_access_audit.normalize_audit
    calls = []

    def counted(scope, sources, *, delivery_state="unknown"):
        calls.append((scope.digest, sources, delivery_state))
        return original(scope, sources, delivery_state=delivery_state)

    monkeypatch.setattr(s3_access_audit, "normalize_audit", counted)
    report = correlate_read_pair(
        probe,
        probe_result,
        legitimate,
        legitimate_result,
        raw,
        delivery_state="complete",
    )

    assert len(calls) == 1
    assert calls[0][1] is raw and calls[0][2] == "complete"
    assert report["schema_version"] == "bluefire.s3-audit-pair.v1"
    assert report["scope_digest"] == probe.to_dict()["scope_digest"]
    assert report["audit"]["source_event_count"] == 3
    sessions = {row["reader"]: row["session_arn"] for row in report["audit"]["events"]}
    assert sessions["probe"].endswith("/bf-" + probe.to_dict()["request_id"][:32] + "-probe")
    assert sessions["legitimate"].endswith(
        "/bf-" + legitimate.to_dict()["request_id"][:32] + "-legitimate"
    )
    assert set(report["correlations"]) == {"probe", "legitimate"}
    assert all("audit" not in row for row in report["correlations"].values())
    assert report["correlations"]["probe"]["request_digest"] == probe.digest
    assert report["correlations"]["legitimate"]["request_digest"] == legitimate.digest
    assert report["independent_collection_proven"] is False
    assert report["effective_access_claim"] is False


def test_pair_keeps_each_original_reader_session_and_authorized_window():
    probe, probe_result, legitimate, legitimate_result = make_pair()
    raw = [log_for(probe, probe_result), log_for(legitimate, legitimate_result)]
    report = correlate_read_pair(probe, probe_result, legitimate, legitimate_result, raw)
    probe_correlation = report["correlations"]["probe"]
    legitimate_correlation = report["correlations"]["legitimate"]

    assert probe_correlation["reads"][0]["reader"] == "probe"
    assert probe_correlation["reads"][0]["worker_request_id"] == "probe-read-0"
    assert probe_correlation["authorized_request_window"]["through"] == (
        "2026-10-09T00:00:30+00:00"
    )
    assert legitimate_correlation["reads"][0]["reader"] == "legitimate"
    assert legitimate_correlation["reads"][0]["worker_request_id"] == ("legitimate-read-0")
    assert [row["purpose"] for row in legitimate_correlation["reads"]] == [
        "primary",
        "health",
    ]
    assert all(row["status"] == "matched" for row in legitimate_correlation["reads"])
    assert legitimate_correlation["authorized_request_window"]["through"] == (
        "2026-10-09T00:00:20+00:00"
    )
    assert all(
        not row["full_object_bytes_proven"]
        for correlation in report["correlations"].values()
        for row in correlation["reads"]
    )
    assert probe_correlation == {
        key: value
        for key, value in s3_access_audit.correlate_reads(probe, probe_result, raw).items()
        if key != "audit"
    }
    assert legitimate_correlation == {
        key: value
        for key, value in s3_access_audit.correlate_reads(
            legitimate, legitimate_result, raw
        ).items()
        if key != "audit"
    }


@pytest.mark.parametrize(
    "invalid", ["swapped", "duplicate_id", "scope", "wrong_operation", "missing"]
)
def test_pair_refuses_wrong_missing_order_duplicate_or_scope(invalid):
    probe, probe_result, legitimate, legitimate_result = make_pair()
    if invalid == "swapped":
        first, first_result, second, second_result = (
            legitimate,
            legitimate_result,
            probe,
            probe_result,
        )
    elif invalid == "duplicate_id":
        duplicate = read_request("legitimate_read", "a")
        first, first_result, second, second_result = (
            probe,
            probe_result,
            duplicate,
            worker_result(duplicate, "duplicate"),
        )
    elif invalid == "scope":
        row = legitimate.to_dict()
        row["scope"]["limits"]["audit_events"] -= 1
        scope = S3AccessScope.from_mapping(row["scope"])
        row["scope"] = scope.to_dict()
        row["scope_digest"] = scope.digest
        changed = S3WorkerRequest.from_mapping(row)
        first, first_result, second, second_result = (
            probe,
            probe_result,
            changed,
            worker_result(changed, "changed"),
        )
    elif invalid == "wrong_operation":
        wrong = read_request("inspect_policy", "c")
        first, first_result, second, second_result = (wrong, {}, legitimate, legitimate_result)
    else:
        with pytest.raises(S3AccessError, match="missing"):
            correlate_read_pair(None, {}, legitimate, legitimate_result, [])
        return

    with pytest.raises(S3AccessError):
        correlate_read_pair(first, first_result, second, second_result, [])


def test_pair_refuses_a_worker_result_bound_to_another_request():
    probe, _probe_result, legitimate, legitimate_result = make_pair()
    mismatched = worker_result(read_request("probe_read", "c"), "other")
    with pytest.raises(S3AccessError):
        correlate_read_pair(probe, mismatched, legitimate, legitimate_result, [])


def test_unreported_member_stays_unreported_even_when_audit_has_its_event():
    probe, probe_result, legitimate, legitimate_result = make_pair()
    probe_result.update(
        outcome="failed",
        data=None,
        problem="scoped_operation_failed",
        send_permits_consumed=3,
        calls=probe_result["calls"][:3],
    )
    report = correlate_read_pair(
        probe,
        probe_result,
        legitimate,
        legitimate_result,
        [
            log_for(probe, worker_result(probe, "probe")),
            log_for(legitimate, legitimate_result),
        ],
        delivery_state="complete",
    )
    assert report["correlations"]["probe"]["reads"][0]["status"] == "worker_unreported"
    assert report["correlations"]["probe"]["reads"][0]["worker_request_id"] is None
    assert all(row["status"] == "matched" for row in report["correlations"]["legitimate"]["reads"])


@pytest.mark.parametrize(
    ("delivery", "status"), [("unknown", "unknown"), ("truncated", "truncated")]
)
def test_pair_preserves_unknown_and_truncated_collection_states(delivery, status):
    probe, probe_result, legitimate, legitimate_result = make_pair()
    report = correlate_read_pair(
        probe, probe_result, legitimate, legitimate_result, [], delivery_state=delivery
    )
    assert report["audit"]["reported_delivery_state"] == delivery
    assert report["correlations"]["probe"]["reads"][0]["status"] == status
    assert all(row["status"] == status for row in report["correlations"]["legitimate"]["reads"])


@pytest.mark.parametrize("difference", ["session", "event_time"])
def test_wrong_probe_session_or_time_does_not_hide_legitimate_match(difference):
    probe, probe_result, legitimate, legitimate_result = make_pair()
    probe_log = json.loads(log_for(probe, probe_result))
    legitimate_log = log_for(legitimate, legitimate_result)
    probe_event = probe_log["Records"][0]
    if difference == "session":
        probe_event["userIdentity"]["arn"] = probe_event["userIdentity"]["arn"].replace(
            "a" * 32, "c" * 32
        )
    else:
        probe_event["eventTime"] = "2026-10-09T00:00:31Z"
    report = correlate_read_pair(
        probe,
        probe_result,
        legitimate,
        legitimate_result,
        [log(*probe_log["Records"]), legitimate_log],
        delivery_state="complete",
    )
    assert report["correlations"]["probe"]["reads"][0]["status"] == "missing"
    assert all(row["status"] == "matched" for row in report["correlations"]["legitimate"]["reads"])


def test_pair_preserves_unknown_record_status_without_claiming_no_event():
    probe, probe_result, legitimate, legitimate_result = make_pair()
    raw = [log({"eventID": "bad"})]
    report = correlate_read_pair(
        probe,
        probe_result,
        legitimate,
        legitimate_result,
        raw,
        delivery_state="complete",
    )
    assert report["audit"]["counts"]["unknown"] == 1
    assert all(row["status"] == "unknown" for row in report["correlations"]["probe"]["reads"])
