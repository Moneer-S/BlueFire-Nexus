"""Synthetic prepared requests and bounded bodies, never SDK or AWS execution."""

import hashlib
import io
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from bluefire import s3_audit_collection_contract as audit
from bluefire import s3_audit_send as sends
from bluefire import s3_audit_wire as wire
from bluefire.s3_access_contract import S3AccessError, S3AccessScope, timestamp
from bluefire.s3_access_sdk_boundary import BotocoreFactory, S3SendGuard
from bluefire.s3_access_sdk_transport import BoundedSdkBody
from bluefire.s3_access_wire import S3WorkerRequest
from bluefire.util import content_hash
from tests_platform.test_s3_access_wire import acknowledge, credentials
from tests_platform.test_s3_audit_collection_contract import listing_rows
from tests_platform.test_s3_audit_wire import request_row

RESERVATION = "sha256:" + "8" * 64


def guard_fixture():
    row = request_row()
    request = S3WorkerRequest.from_mapping(row)
    return row, S3SendGuard(request, acknowledge, lambda: timestamp(row["audit"]["issued_at"]))


def prepared(row, send):
    params = sends.parameters(send)
    headers = {}
    body = b""
    url = "https://" + send["host"] + "/"
    if send["service"] == "sts":
        body = urlencode({"Action": send["operation"], "Version": "2011-06-15", **params}).encode()
    else:
        headers["x-amz-expected-bucket-owner"] = params["ExpectedBucketOwner"]
        url += params["Bucket"]
        if send["operation"] == "ListObjectsV2":
            url += "?" + urlencode(
                {
                    "list-type": "2",
                    "prefix": params["Prefix"],
                    "start-after": params["StartAfter"],
                    "max-keys": "16",
                    "encoding-type": "url",
                }
            )
        else:
            url += "/" + params["Key"]
            headers["If-Match"] = params["IfMatch"]
    return SimpleNamespace(
        method=send["method"],
        url=url,
        headers=headers,
        body=body,
        stream_output=send["operation"] == "GetObject",
    )


class RawBody:
    def __init__(self, payload):
        self.stream = io.BytesIO(payload)

    def read(self, amount, *, decode_content):
        assert decode_content is False
        return self.stream.read(amount)

    def close(self):
        self.stream.close()


def complete_send(row, guard, payload=b"synthetic response"):
    send = wire.planned_send(row, guard.sequence + 1, committed_discovery=guard._audit.discovery)
    guard.begin(send["service"], send["operation"], send["role"], sends.parameters(send))
    request = prepared(row, send)
    guard.hook(request)
    limit, account = guard.response_policy()
    guard.claim_transport_send(request)
    body = BoundedSdkBody(RawBody(payload), lambda: None, limit, account)
    guard.capture_response(body)
    assert body.read() == payload
    guard.finish()
    return guard.response_receipt()


def discovery_fixture():
    row, guard = guard_fixture()
    scope = S3AccessScope.from_mapping(row["scope"])
    listings = listing_rows(scope, row["audit"])
    for _ in range(3):
        complete_send(row, guard)
    for listing in listings:
        listing["body_sha256"] = complete_send(row, guard)["body_sha256"]
    found = audit.discovery(
        scope,
        row["audit"],
        request_digest=guard.request.digest,
        reservation_digest=RESERVATION,
        listings=listings,
    )
    durable = found["durable"]
    ack = {
        "kind": "discovery_committed",
        "request_digest": guard.request.digest,
        "reservation_digest": RESERVATION,
        "discovery_digest": content_hash(durable),
        "frame_digest": durable["frame_digest"],
        "next_send_sequence": durable["next_send_sequence"],
    }
    return row, guard, found, ack


def test_audit_target_keeps_original_scope_and_separate_bucket_region():
    row, guard = guard_fixture()
    original = deepcopy(row["scope"])
    assert sends.target(row, "s3") == ("us-west-2", "s3.us-west-2.amazonaws.com")
    assert sends.target(row, "sts") == (
        original["region"],
        "sts." + original["region"] + ".amazonaws.com",
    )
    assert guard.scope.to_dict() == original
    assert audit.list_parameters(guard.scope, row["audit"])[0]["Prefix"].endswith(
        "/CloudTrail/" + original["region"] + "/2026/10/09/"
    )


@pytest.mark.parametrize(
    "change", ["role", "session", "duration", "duration_float", "body", "host"]
)
def test_audit_sts_collector_preparation_refuses_substitution(change):
    row, guard = guard_fixture()
    complete_send(row, guard)
    send = wire.planned_send(row, 2)
    params = sends.parameters(send)
    if change == "role":
        params["RoleArn"] = row["scope"]["roles"]["legitimate"]
    elif change == "session":
        params["RoleSessionName"] += "-changed"
    elif change == "duration":
        params["DurationSeconds"] = 901
    elif change == "duration_float":
        params["DurationSeconds"] = 900.0
    if change in {"role", "session", "duration", "duration_float"}:
        with pytest.raises(S3AccessError):
            guard.begin("sts", "AssumeRole", "controller", params)
    else:
        guard.begin("sts", "AssumeRole", "controller", params)
        request = prepared(row, send)
        if change == "body":
            request.body += b"&ExternalId=unreviewed"
        else:
            request.url = "https://other.example/"
        with pytest.raises(S3AccessError):
            guard.hook(request)
    assert guard.sequence == 1


@pytest.mark.parametrize(
    "change", ["pagination", "max_keys", "prefix", "owner", "encoding", "duplicate"]
)
def test_audit_listing_prepared_request_has_only_exact_fixed_query(change):
    row, guard = guard_fixture()
    for _ in range(3):
        complete_send(row, guard)
    send = wire.planned_send(row, 4)
    guard.begin("s3", "ListObjectsV2", "collector", sends.parameters(send))
    request = prepared(row, send)
    if change == "pagination":
        request.url += "&continuation-token=unreviewed"
    elif change == "max_keys":
        request.url = request.url.replace("max-keys=16", "max-keys=17")
    elif change == "prefix":
        request.url = request.url.replace("prefix=AWSLogs", "prefix=other")
    elif change == "owner":
        request.headers["x-amz-expected-bucket-owner"] = "111111111111"
    elif change == "encoding":
        request.url = request.url.replace("encoding-type=url", "encoding-type=other")
    else:
        request.url += "&max-keys=16"
    with pytest.raises(S3AccessError):
        guard.hook(request)
    assert guard.sequence == 3


def test_audit_get_requires_exact_one_shot_discovery_ack_and_retains_copy():
    row, guard, found, ack = discovery_fixture()
    selected_send = wire.planned_send(row, 5, committed_discovery=found["durable"])
    with pytest.raises(S3AccessError):
        guard.begin("s3", "GetObject", "collector", sends.parameters(selected_send))
    retained = guard.accept_discovery(found["frame"], ack, reservation_digest=RESERVATION)
    retained["selected"][0]["key"] = "not-the-original-key"
    assert guard._audit.discovery == found["durable"]
    with pytest.raises(S3AccessError):
        guard.accept_discovery(found["frame"], ack, reservation_digest=RESERVATION)
    complete_send(row, guard)
    assert guard.sequence == 5
    assert guard.compressed_bytes == len(b"synthetic response")


@pytest.mark.parametrize("change", ["ack", "body_digest"])
def test_audit_discovery_refuses_wrong_ack_or_nonoriginal_body_without_replay(change):
    row, guard, found, ack = discovery_fixture()
    if change == "ack":
        ack["request_digest"] = "sha256:" + "0" * 64
    else:
        scope = S3AccessScope.from_mapping(row["scope"])
        listings = listing_rows(scope, row["audit"])
        listings[0]["body_sha256"] = "sha256:" + "0" * 64
        found = audit.discovery(
            scope,
            row["audit"],
            request_digest=guard.request.digest,
            reservation_digest=RESERVATION,
            listings=listings,
        )
        ack.update(
            discovery_digest=content_hash(found["durable"]),
            frame_digest=found["durable"]["frame_digest"],
        )
    expected_error = "Discovery ACK" if change == "ack" else "original listing bodies"
    with pytest.raises(S3AccessError, match=expected_error):
        guard.accept_discovery(found["frame"], ack, reservation_digest=RESERVATION)
    assert guard._audit.discovery is None
    assert guard.sequence == 4
    with pytest.raises(S3AccessError):
        guard.accept_discovery(found["frame"], ack, reservation_digest=RESERVATION)


@pytest.mark.parametrize("change", ["condition", "range", "query", "key"])
def test_audit_conditional_get_refuses_resource_or_header_changes(change):
    row, guard, found, ack = discovery_fixture()
    guard.accept_discovery(found["frame"], ack, reservation_digest=RESERVATION)
    send = wire.planned_send(row, 5, committed_discovery=found["durable"])
    guard.begin("s3", "GetObject", "collector", sends.parameters(send))
    request = prepared(row, send)
    if change == "condition":
        request.headers["If-Match"] = '"different"'
    elif change == "range":
        request.headers["Range"] = "bytes=0-1"
    elif change == "query":
        request.url += "?versionId=unreviewed"
    else:
        request.url += "-changed"
    with pytest.raises(S3AccessError):
        guard.hook(request)
    assert guard.sequence == 4 and not guard.write_permitted


def test_audit_response_receipt_requires_original_complete_body_and_no_bypass():
    row, guard = guard_fixture()
    send = wire.planned_send(row, 1)
    guard.begin("sts", "GetCallerIdentity", "controller", {})
    request = prepared(row, send)
    guard.hook(request)
    limit, account = guard.response_policy()
    guard.claim_transport_send(request)
    with pytest.raises(S3AccessError):
        guard.capture_response(BoundedSdkBody(RawBody(b"other"), lambda: None))
    body = BoundedSdkBody(RawBody(b"original"), lambda: None, limit, account)
    guard.capture_response(body)
    guard.finish()
    with pytest.raises(S3AccessError):
        guard.response_receipt()
    with pytest.raises(S3AccessError):
        guard.begin("sts", "AssumeRole", "controller", sends.parameters(wire.planned_send(row, 2)))
    assert body.read() == b"original"
    receipt = guard.response_receipt()
    assert receipt == {
        "body_sha256": "sha256:" + hashlib.sha256(b"original").hexdigest(),
        "sdk_body_bytes": 8,
    }
    assert guard.sdk_body_bytes == 8 and guard.compressed_bytes == 0


def test_audit_response_budget_counts_consumed_failure_bytes_without_refund():
    row, guard = guard_fixture()
    guard._audit.limits["sdk_body_bytes"] = 3
    send = wire.planned_send(row, 1)
    guard.begin("sts", "GetCallerIdentity", "controller", {})
    request = prepared(row, send)
    guard.hook(request)
    limit, account = guard.response_policy()
    guard.claim_transport_send(request)
    body = BoundedSdkBody(RawBody(b"four"), lambda: None, limit, account)
    guard.capture_response(body)
    with pytest.raises(S3AccessError):
        body.read()
    assert body.closed and not body.complete
    assert guard.sdk_body_bytes == 4
    with pytest.raises(S3AccessError):
        guard.response_receipt()


@pytest.mark.parametrize("service", ["s3", "sts"])
def test_audit_factory_uses_exact_target_and_audit_only_response_callbacks(service):
    row, guard = guard_fixture()
    created, configured = [], []
    client = SimpleNamespace(
        _endpoint=SimpleNamespace(http_session=SimpleNamespace()),
        meta=SimpleNamespace(events=SimpleNamespace(register=lambda *_args: None)),
        close=lambda: None,
    )

    class Session:
        def set_config_variable(self, *_args):
            pass

        def create_client(self, name, **values):
            created.append((name, values))
            return client

    factory = BotocoreFactory(
        session_factory=Session,
        config_factory=lambda **values: configured.append(values) or values,
        client_error_type=ValueError,
        ca_bundle="/fixed/cacert.pem",
        assert_runtime=lambda: None,
    )
    factory.client(service, credentials(), guard.scope, guard, 5)
    region, host = sends.target(row, service)
    assert created[0][1]["region_name"] == configured[0]["region_name"] == region
    assert created[0][1]["endpoint_url"] == "https://" + host
    transport = client._endpoint.http_session
    assert transport.response_policy == guard.response_policy
    assert transport.response_observer == guard.capture_response
