"""Synthetic CloudTrail JSON tests, never live collection or AWS access evidence."""

import copy
import hashlib
import json

import pytest

from bluefire.s3_access_audit import correlate_reads, normalize_audit
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_wire import S3WorkerRequest, operation_plan
from tests_platform.test_s3_access_wire import request_row


def request(operation="probe_read"):
    return S3WorkerRequest.from_mapping(request_row(operation))


def scope(req=None):
    return S3AccessScope.from_mapping((req or request()).to_dict()["scope"])


def result(req=None, error=None):
    req = req or request()
    source = req.to_dict()
    reader = "probe" if source["operation"] == "probe_read" else "legitimate"
    calls = [
        {"operation": action, "role": role, "request_id": f"request-{i}", "http_status": 200}
        for i, (_, action, role) in enumerate(operation_plan(req))
    ]
    objects = [
        {"result": "read", **{name: obj[name] for name in ("purpose", "sha256", "size_bytes")}}
        for obj in source["scope"]["objects"][: 1 if reader == "probe" else 2]
    ]
    if error:
        calls[3].update(error_code=error, http_status=403 if error == "AccessDenied" else 404)
        objects[0] = {"purpose": "primary", "result": "service_denied"}
    observed = error in {None, "AccessDenied"}
    return {
        "schema_version": "bluefire.s3-worker-result.v1",
        "request_digest": req.digest,
        "outcome": "observed" if observed else "failed",
        "data": (
            {"reader": reader, "objects": objects, "effective_access_claim": False}
            if observed
            else None
        ),
        "problem": None if observed else "scoped_operation_failed",
        "send_permits_consumed": len(calls),
        "calls": calls,
        "runtime_isolation_proven": False,
    }


def event(req=None, *, index=0, error=None):
    req = req or request()
    row = req.to_dict()
    bound = row["scope"]
    reader = "probe" if row["operation"] == "probe_read" else "legitimate"
    session = "bf-" + row["request_id"][:32] + "-" + reader
    arn = f"arn:aws:sts::{bound['account_id']}:assumed-role/"
    arn += bound["roles"][reader].rsplit("/", 1)[1] + "/" + session
    value = {
        "eventVersion": "1.11",
        "eventTime": "2026-10-09T00:00:10Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "eventType": "AwsApiCall",
        "eventCategory": "Data",
        "awsRegion": bound["region"],
        "eventID": f"00000000-0000-4000-8000-{index:012d}",
        "requestID": f"request-{index + 3}",
        "recipientAccountId": bound["account_id"],
        "readOnly": True,
        "managementEvent": False,
        "requestParameters": {"bucketName": bound["bucket"], "key": bound["objects"][index]["key"]},
        "responseElements": None,
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": bound["account_id"],
            "arn": arn,
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "accountId": bound["account_id"],
                    "arn": bound["roles"][reader],
                }
            },
        },
    }
    if error:
        value["errorCode"] = error
    return value


def log(*events):
    return json.dumps({"Records": events}, separators=(",", ":")).encode()


def correlated(events, *, req=None, error=None, delivery="complete"):
    req = req or request()
    return correlate_reads(req, result(req, error), [log(*events)], delivery_state=delivery)


@pytest.mark.parametrize("operation", ["probe_read", "legitimate_read"])
@pytest.mark.parametrize(
    "error,outcome", [(None, "service_success"), ("AccessDenied", "service_denied")]
)
def test_exact_read_correlation_has_no_independence_or_bytes_claim(operation, error, outcome):
    req = request(operation)
    events = [event(req, error=error)] + (
        [event(req, index=1)] if operation == "legitimate_read" else []
    )
    report = correlated(events, req=req, error=error)
    assert report["reads"][0]["status"] == "matched"
    assert report["reads"][0]["audit_outcomes"] == [outcome]
    assert all(not row["full_object_bytes_proven"] for row in report["reads"])
    assert report["independent_collection_proven"] is False
    assert report["effective_access_claim"] is False
    assert report["audit"]["reported_delivery_state"] == "complete"
    assert report["authorized_request_window"] == {
        "from": "2026-10-09T00:00:00+00:00",
        "through": "2026-10-09T00:00:30+00:00",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("eventSource", "sts.amazonaws.com"),
        ("eventName", "PutBucketPolicy"),
        ("eventType", "AwsServiceEvent"),
        ("eventCategory", "Management"),
        ("awsRegion", "us-west-1"),
        ("recipientAccountId", "999999999999"),
        ("managementEvent", True),
        ("readOnly", False),
    ],
)
def test_wrong_event_scope_never_matches(field, value):
    row = event()
    row[field] = value
    report = correlated([row])
    assert report["reads"][0]["status"] == "missing"
    assert report["audit"]["counts"]["excluded"] == 1


@pytest.mark.parametrize(
    "path,value",
    [
        (("userIdentity", "accountId"), "999999999999"),
        (("userIdentity", "type"), "IAMUser"),
        (("userIdentity", "sessionContext", "sessionIssuer", "type"), "IAMUser"),
        (("userIdentity", "sessionContext", "sessionIssuer", "accountId"), "999999999999"),
        (
            ("userIdentity", "sessionContext", "sessionIssuer", "arn"),
            "arn:aws:iam::123456789012:role/foreign",
        ),
        (("requestParameters", "bucketName"), "other-bucket"),
        (("requestParameters", "key"), "bluefire/other/records.jsonl"),
    ],
)
def test_wrong_identity_and_object_never_matches(path, value):
    row = event()
    target = row
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert correlated([row])["reads"][0]["status"] == "missing"


@pytest.mark.parametrize("change", ["request", "session", "purpose", "before", "after"])
def test_exact_request_session_object_and_authorized_window(change):
    req = request("legitimate_read")
    row = event(req)
    if change == "request":
        row["requestID"] = "another-request"
    elif change == "session":
        row["userIdentity"]["arn"] = row["userIdentity"]["arn"].replace("b" * 32, "c" * 32)
    elif change == "purpose":
        row["requestParameters"]["key"] = req.to_dict()["scope"]["objects"][1]["key"]
    else:
        row["eventTime"] = "2026-10-09T00:00:31Z" if change == "after" else "2026-10-08T23:59:59Z"
    assert correlated([row], req=req)["reads"][0]["status"] == "missing"


@pytest.mark.parametrize(
    "field", ["requestID", "requestParameters", "userIdentity", "eventTime", "recipientAccountId"]
)
def test_missing_required_field_is_unknown_not_denial(field):
    row = event(error="AccessDenied")
    del row[field]
    report = correlated([row], error="AccessDenied")
    assert report["reads"][0]["status"] == "unknown"
    assert not report["reads"][0]["audit_event_ids"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("eventVersion", "2.0"),
        ("eventVersion", "1.06"),
        ("eventVersion", "1.6"),
        ("eventTime", "2026-10-09T00:00:10+00:00"),
        ("eventTime", "2026-99-99T00:00:10Z"),
        ("requestID", ""),
        ("requestID", "x" * 129),
        ("eventID", "secret text"),
        ("errorCode", None),
        ("errorCode", []),
        ("errorMessage", "unclassified failure"),
        ("responseElements", {"errorCode": "AccessDenied"}),
        ("addendum", {"reason": "UPDATED_DATA"}),
    ],
)
def test_unsupported_or_incomplete_record_cannot_claim_success(field, value):
    row = event()
    row[field] = value
    assert correlated([row])["reads"][0]["status"] == "unknown"


@pytest.mark.parametrize(
    "error,outcome",
    [
        ("NoSuchKey", "object_missing"),
        ("NoSuchBucket", "bucket_missing"),
        ("ExpiredToken", "credential_error"),
        ("InvalidToken", "credential_error"),
        ("SlowDown", "other_service_error"),
        ("InternalError", "other_service_error"),
    ],
)
def test_non_denial_errors_remain_distinct(error, outcome):
    report = correlated([event(error=error)], error=error)
    assert report["reads"][0]["status"] == "matched"
    assert report["reads"][0]["audit_outcomes"] == [outcome]


def test_disagreeing_worker_and_audit_outcomes_are_conflict():
    assert correlated([event(error="AccessDenied")])["reads"][0]["status"] == "conflict"
    second = event(error="AccessDenied")
    second["eventID"] = "10000000-0000-4000-8000-000000000000"
    assert correlated([event(), second])["reads"][0]["status"] == "conflict"
    assert (
        correlated([event(error="ExpiredToken")], error="InvalidToken")["reads"][0]["status"]
        == "conflict"
    )
    assert (
        correlated([event(error="InternalError")], error="SlowDown")["reads"][0]["status"]
        == "conflict"
    )


def test_missing_response_elements_is_not_success_and_unknown_error_is_redacted():
    row = event()
    del row["responseElements"]
    assert correlated([row])["reads"][0]["status"] == "unknown"
    row["errorCode"] = "SYNTHETIC-PRIVATE-ERROR"
    projected = normalize_audit(scope(), [log(row)])
    assert projected["events"][0]["outcome"] == "other_service_error"
    assert projected["events"][0]["service_error_code"] == "OtherServiceError"
    assert "SYNTHETIC-PRIVATE-ERROR" not in json.dumps(projected)


def test_deduplication_preserves_source_digest_occurrences_and_arrival_order():
    req = request("legitimate_read")
    first, second = event(req), event(req, index=1)
    second["eventTime"] = "2026-10-09T00:00:20Z"
    first["addendum"] = {"reason": "DELIVERY_DELAY"}
    raw = [log(second, first), log(first)]
    report = normalize_audit(scope(req), raw)
    assert [row["purpose"] for row in report["events"]] == ["health", "primary"]
    assert report["events"][1]["delivery_delayed"] is True
    assert report["events"][1]["occurrences"] == [
        {"source_index": 0, "record_index": 1},
        {"source_index": 1, "record_index": 0},
    ]
    assert report["counts"]["duplicates"] == 1
    assert report["source_event_count"] == 3
    assert report["sources"][0]["sha256"] == "sha256:" + hashlib.sha256(raw[0]).hexdigest()


@pytest.mark.parametrize(
    "field,value",
    [
        ("errorCode", "AccessDenied"),
        ("userAgent", "changed"),
        ("eventTime", "2026-10-09T00:00:11Z"),
    ],
)
def test_conflicting_duplicate_event_ids_fail_closed_even_in_dropped_fields(field, value):
    changed = event()
    changed[field] = value
    with pytest.raises(S3AccessError, match="conflicting records"):
        normalize_audit(scope(), [log(event()), log(changed)])


@pytest.mark.parametrize(
    "delivery,status",
    [
        ("complete", "missing"),
        ("incomplete", "awaiting_delivery"),
        ("unknown", "unknown"),
        ("truncated", "truncated"),
    ],
)
def test_collection_state_is_explicit_and_missing_is_not_denied(delivery, status):
    report = correlated([], delivery=delivery)
    assert report["reads"][0]["status"] == status
    assert report["reads"][0]["audit_outcomes"] == []
    assert report["audit"]["reported_delivery_state"] == delivery


def test_unreported_worker_call_cannot_be_correlated_from_audit_only():
    req = request()
    value = result(req)
    value.update(
        outcome="failed", data=None, problem="scoped_operation_failed", calls=value["calls"][:3]
    )
    report = correlate_reads(req, value, [log(event())], delivery_state="complete")
    assert report["reads"][0]["status"] == "worker_unreported"
    assert report["reads"][0]["audit_event_ids"] == []


def test_duplicate_worker_ids_or_failed_reader_identity_refused():
    req = request("legitimate_read")
    value = result(req)
    value["calls"][4]["request_id"] = value["calls"][3]["request_id"]
    with pytest.raises(S3AccessError, match="unique request mapping"):
        correlate_reads(req, value, [])
    value = result(req, "NoSuchKey")
    value["calls"][2].update(error_code="AccessDenied", http_status=403)
    with pytest.raises(S3AccessError, match="unique request mapping"):
        correlate_reads(req, value, [])


def test_raw_secrets_and_arbitrary_fields_are_not_exported():
    row = event(error="AccessDenied")
    secret = "SYNTHETIC-PRIVATE-STRING-MUST-NOT-APPEAR"
    row.update(
        userAgent=secret,
        errorMessage=secret,
        sourceIPAddress=secret,
        additionalEventData={"headers": secret},
        eventContext={"arbitrary": secret},
    )
    row["userIdentity"].update(accessKeyId=secret, principalId=secret)
    row["requestParameters"]["headers"] = secret
    exported = json.dumps(correlated([row], error="AccessDenied"))
    assert secret not in exported
    assert "accessKeyId" not in exported and "errorMessage" not in exported


@pytest.mark.parametrize(
    "raw",
    [
        b'{"Records":[],"Records":[]}',
        b'{"Records":[NaN]}',
        b'{"Records":[1e999]}',
        b"\xff",
        b"{}",
        b"[]",
        b'{"Records":[]',
        b'{"Records":[],"other":1}',
        b"\x1f\x8b",
    ],
)
def test_strict_raw_json_no_duplicates_nonfinite_truncated_or_gzip(raw):
    with pytest.raises(S3AccessError):
        normalize_audit(scope(), [raw])


def test_aggregate_bytes_and_events_count_duplicates_and_empty_sources():
    row = scope().to_dict()
    raw = log(event())
    row["limits"]["audit_bytes"] = len(raw) * 2 - 1
    with pytest.raises(S3AccessError, match="aggregate byte"):
        normalize_audit(S3AccessScope.from_mapping(row), [raw, raw])
    row = scope().to_dict()
    row["limits"]["audit_events"] = 1
    bounded = S3AccessScope.from_mapping(row)
    with pytest.raises(S3AccessError, match="aggregate bound"):
        normalize_audit(bounded, [log(event(), event())])
    with pytest.raises(S3AccessError, match="source count"):
        normalize_audit(bounded, [log(), log()])


@pytest.mark.parametrize("raw", ["{}", bytearray(b"{}"), memoryview(b"{}")])
def test_only_bytes_sources(raw):
    with pytest.raises(S3AccessError, match="uncompressed bytes"):
        normalize_audit(scope(), [raw])


def test_resources_must_not_contradict_exact_object_scope():
    row = event()
    source = scope().to_dict()
    resource = {
        "type": "AWS::S3::Object",
        "accountId": source["account_id"],
        "ARN": "arn:aws:s3:::" + source["bucket"] + "/" + source["objects"][0]["key"],
    }
    row["resources"] = [resource]
    assert correlated([row])["reads"][0]["status"] == "matched"
    resource["ARN"] += "other"
    assert correlated([row])["reads"][0]["status"] == "missing"


def test_input_not_mutated_and_wrong_result_binding_refused():
    req = request()
    value = result(req)
    original = copy.deepcopy(value)
    correlate_reads(req, value, [log(event())])
    assert value == original
    value["request_digest"] = "sha256:" + "0" * 64
    with pytest.raises(S3AccessError):
        correlate_reads(req, value, [])
    with pytest.raises(S3AccessError):
        correlate_reads(request("inspect_policy"), {}, [])
    with pytest.raises(S3AccessError):
        normalize_audit(scope(), [], delivery_state="authenticated")
