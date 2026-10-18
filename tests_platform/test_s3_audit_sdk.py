"""In-memory AuditSdk integration through the real send guard and bounded body."""

import gzip
import hashlib
import io
import json
from datetime import datetime, timedelta
from types import SimpleNamespace
from urllib.parse import quote, urlencode

import pytest

from bluefire import s3_audit_collection_contract as audit
from bluefire.s3_access_contract import S3AccessError, S3AccessScope, timestamp
from bluefire.s3_access_sdk import S3SdkAdapter
from bluefire.s3_access_sdk_transport import BoundedSdkTransport
from bluefire.s3_access_wire import S3WorkerRequest
from bluefire.s3_audit_wire import discovery as validate_discovery
from bluefire.util import content_hash
from tests_platform.test_s3_access_audit import event as cloudtrail_event
from tests_platform.test_s3_access_wire import NOW, acknowledge, credentials
from tests_platform.test_s3_audit_wire import request_row

RESERVATION_DIGEST = "sha256:" + "b" * 64


class RawBody:
    def __init__(self, payload):
        self.data = io.BytesIO(payload)
        self.closed = False

    def read(self, amount, *, decode_content=False):
        assert type(amount) is int and 0 < amount <= 8192
        assert decode_content is False
        return self.data.read(amount)

    def close(self):
        self.closed = True
        self.data.close()


class HttpResponse:
    def __init__(self, payload, *, request_id, status=200):
        self.raw = RawBody(payload)
        self.headers = {
            "Content-Length": str(len(payload)),
            "Content-Encoding": "identity",
        }
        self.status_code = status
        self._content = None
        self.request_id = request_id

    @property
    def content(self):
        if self._content is None:
            self._content = b"".join(self.raw.stream())
        return self._content


class FakeSdkServiceError(Exception):
    def __init__(self, response):
        super().__init__("synthetic SDK service failure")
        self.response = response


class FakeSession:
    def __init__(self):
        self.pending = None
        self.closed = False

    def send(self, request):
        assert self.pending is not None
        response = self.pending
        self.pending = None
        return response

    def close(self):
        self.closed = True


def _gzip_payload(row, mode):
    if mode == "invalid_gzip":
        return b"not-a-gzip-stream"
    if mode == "concatenated_gzip":
        payload = b'{"Records":[]}'
        return gzip.compress(payload, mtime=0) + gzip.compress(payload, mtime=0)
    if mode == "oversized_gzip":
        payload = b'{"Records":[],"padding":"' + b"x" * (1024 * 1024 + 32) + b'"}'
        return gzip.compress(payload, mtime=0)
    if mode == "event_limit":
        payload = json.dumps({"Records": [{}] * 501}, separators=(",", ":")).encode()
        return gzip.compress(payload, mtime=0)
    if mode == "bad_crc":
        payload = bytearray(gzip.compress(b'{"Records":[{}]}', mtime=0))
        payload[-8] ^= 1
        return bytes(payload)
    if mode == "truncated_gzip":
        return gzip.compress(b'{"Records":[{}]}', mtime=0)[:-4]
    if mode == "aggregate_expanded_bytes":
        limits = audit.budget(S3AccessScope.from_mapping(row["scope"]), row["audit"]["source"])[
            "per_batch"
        ]
        payload = json.dumps(
            {"Records": [{"padding": "x" * (limits["expanded_bytes"] // 2 + 1)}]},
            separators=(",", ":"),
        ).encode()
        return gzip.compress(payload, mtime=0)
    if mode == "aggregate_events":
        limits = audit.budget(S3AccessScope.from_mapping(row["scope"]), row["audit"]["source"])[
            "per_batch"
        ]
        payload = json.dumps(
            {"Records": [{}] * (limits["events"] // 2 + 1)}, separators=(",", ":")
        ).encode()
        return gzip.compress(payload, mtime=0)
    if mode == "oversized_correlations":
        limits = audit.budget(S3AccessScope.from_mapping(row["scope"]), row["audit"]["source"])[
            "per_batch"
        ]
        original = row["audit"]["original_pair"]["reads"][0]
        request = S3WorkerRequest.from_mapping(original["request"])
        request_id = original["result"]["calls"][3]["request_id"]
        records = []
        for index in range(limits["events"]):
            record = cloudtrail_event(request, index=0)
            record["eventID"] = f"00000000-0000-4000-8000-{index:012d}"
            record["requestID"] = request_id
            records.append(record)
        payload = json.dumps({"Records": records}, separators=(",", ":")).encode()
        return gzip.compress(payload, mtime=0)

    records = []
    originals = row["audit"]["original_pair"]["reads"]
    for index, entry in enumerate(originals):
        original = S3WorkerRequest.from_mapping(entry["request"])
        object_count = 1 if entry["reader"] == "probe" else 2
        for object_index in range(object_count):
            record = cloudtrail_event(original, index=object_index)
            record["eventID"] = f"00000000-0000-4000-8000-{index * 10 + object_index:012d}"
            record["requestID"] = entry["result"]["calls"][3 + object_index]["request_id"]
            records.append(record)
    payload = json.dumps({"Records": records}, separators=(",", ":")).encode()
    return gzip.compress(payload, mtime=0)


class FakeAuditFactory:
    """Synthetic SDK client: no boto, sockets, credentials or external services."""

    def __init__(self, row, *, ack_mode="valid", listing_mode="one", object_mode="valid"):
        self.row = row
        self.ack_mode = ack_mode
        self.listing_mode = listing_mode
        self.object_mode = object_mode
        self.packed_objects = [_gzip_payload(row, object_mode) for _ in range(2)]
        self.packed = self.packed_objects[0]
        self.operations = []
        self.trace = []
        self.list_payloads = []
        self.list_count = 0
        self.get_count = 0
        self.durable = None
        self.sessions = []
        self.transports = []
        self.bodies = []
        self.clients = []
        self.collector_session = None

    def service_error(self, error):
        if isinstance(error, FakeSdkServiceError):
            return error.response
        return None

    def client(self, service, secret, scope, guard, timeout):
        assert scope.digest == S3WorkerRequest.from_mapping(self.row).to_dict()["scope_digest"]
        assert 0 < timeout <= 5
        is_controller = secret.access_key == credentials().access_key
        role = "controller" if is_controller else "collector"
        session = FakeSession()
        transport = BoundedSdkTransport(
            session,
            guard.claim_transport_send,
            lambda: guard.request.assert_current(guard.clock),
            response_policy=guard.response_policy,
            response_observer=guard.capture_response,
        )
        self.sessions.append(session)
        self.transports.append(transport)

        client = SimpleNamespace(closed=False)
        client.close = lambda: (transport.close(), setattr(client, "closed", True))
        for name, operation in (
            ("get_caller_identity", "GetCallerIdentity"),
            ("assume_role", "AssumeRole"),
            ("list_objects_v2", "ListObjectsV2"),
            ("get_object", "GetObject"),
        ):
            setattr(
                client,
                name,
                lambda _operation=operation, **parameters: self._invoke(
                    session, transport, guard, service, role, _operation, parameters
                ),
            )
        self.clients.append(client)
        return client

    def _prepared(self, service, operation, parameters):
        scope = self.row["scope"]
        if service == "sts":
            fields = {"Action": operation, "Version": "2011-06-15", **parameters}
            return SimpleNamespace(
                method="POST",
                url=f"https://sts.{scope['region']}.amazonaws.com/",
                body=urlencode(fields).encode("ascii"),
                headers={},
                stream_output=False,
            )

        source = self.row["audit"]["source"]
        headers = {"x-amz-expected-bucket-owner": parameters["ExpectedBucketOwner"]}
        if operation == "ListObjectsV2":
            query = urlencode(
                {
                    "list-type": "2",
                    "prefix": parameters["Prefix"],
                    "start-after": parameters["StartAfter"],
                    "max-keys": str(parameters["MaxKeys"]),
                    "encoding-type": "url",
                }
            )
            path = "/" + parameters["Bucket"]
            return SimpleNamespace(
                method="GET",
                url=f"https://s3.{source['audit_bucket_region']}.amazonaws.com{path}?{query}",
                body=b"",
                headers=headers,
                stream_output=False,
            )
        headers["If-Match"] = parameters["IfMatch"]
        path = "/" + parameters["Bucket"] + "/" + quote(parameters["Key"], safe="/")
        return SimpleNamespace(
            method="GET",
            url=f"https://s3.{source['audit_bucket_region']}.amazonaws.com{path}",
            body=b"",
            headers=headers,
            stream_output=True,
        )

    def _mapping(self, service, operation, role, parameters):
        index = len(self.operations)
        request_id = f"SYNTHETIC-REQUEST-{index}"
        result = {
            "ResponseMetadata": {
                "RequestId": request_id,
                "HTTPStatusCode": 200,
                "RetryAttempts": 0,
            }
        }
        if service == "sts" and operation == "GetCallerIdentity":
            session_name = "controller-session" if role == "controller" else self.collector_session
            role_arn = (
                self.row["scope"]["roles"]["controller"]
                if role == "controller"
                else self.row["audit"]["source"]["collector_role_arn"]
            )
            role_name = role_arn.rsplit("/", 1)[1]
            result.update(
                Account=self.row["scope"]["account_id"],
                Arn=(
                    f"arn:aws:sts::{self.row['scope']['account_id']}:"
                    f"assumed-role/{role_name}/{session_name}"
                ),
                UserId=f"AROA{'C' * 16}:{session_name}",
            )
            if role == "collector" and self.object_mode == "wrong_collector_identity":
                result["Account"] = "000000000000"
            return result, json.dumps(result, separators=(",", ":")).encode(), request_id
        if service == "sts" and operation == "AssumeRole":
            self.collector_session = parameters["RoleSessionName"]
            assumed_id = f"AROA{'C' * 16}:{self.collector_session}"
            result.update(
                Credentials={
                    "AccessKeyId": "ASIA" + "R" * 16,
                    "SecretAccessKey": "R" * 40,
                    "SessionToken": "R" * 64,
                    "Expiration": (NOW + timedelta(seconds=900)).isoformat(),
                },
                AssumedRoleUser={
                    "Arn": (
                        f"arn:aws:sts::{self.row['scope']['account_id']}:assumed-role/"
                        f"{parameters['RoleArn'].rsplit('/', 1)[1]}/{self.collector_session}"
                    ),
                    "AssumedRoleId": assumed_id,
                },
            )
            return result, json.dumps(result, separators=(",", ":")).encode(), request_id
        if operation == "ListObjectsV2":
            list_index = self.list_count
            self.list_count += 1
            objects = []
            if self.listing_mode != "empty" and list_index == 0:
                count = 2 if self.listing_mode == "two" else 1
                for object_index in range(count):
                    suffix = chr(ord("A") + object_index) * 16 + ".json.gz"
                    objects.append(
                        {
                            "Key": parameters["StartAfter"] + suffix,
                            "Size": len(self.packed_objects[object_index]),
                            "ETag": f'"synthetic-etag-{object_index}"',
                        }
                    )
            result.update(
                Name=parameters["Bucket"],
                Prefix=parameters["Prefix"],
                StartAfter=parameters["StartAfter"],
                MaxKeys=parameters["MaxKeys"],
                KeyCount=len(objects),
                IsTruncated=self.listing_mode == "truncated" and list_index == 0,
                EncodingType="url",
                Contents=objects,
            )
            payload = json.dumps(result, separators=(",", ":")).encode()
            self.list_payloads.append(payload)
            return result, payload, request_id
        if operation == "GetObject":
            object_index = self.get_count
            self.get_count += 1
            etag = f'"synthetic-etag-{object_index}"'
            size = len(self.packed_objects[object_index])
            if self.object_mode == "wrong_etag":
                etag = '"different-etag"'
            if self.object_mode == "wrong_size":
                size += 1
            result.update(ContentLength=size, ETag=etag)
            return result, self.packed_objects[object_index], request_id
        raise AssertionError(f"unexpected fake SDK operation: {operation}")

    def _invoke(self, session, transport, guard, service, role, operation, parameters):
        prepared = self._prepared(service, operation, parameters)
        guard.hook(prepared)
        value, payload, request_id = self._mapping(service, operation, role, parameters)
        status = (
            412 if operation == "GetObject" and self.object_mode == "precondition_failed" else 200
        )
        session.pending = HttpResponse(payload, request_id=request_id, status=status)
        response = transport.send(prepared)
        self.operations.append((service, operation, role, dict(parameters)))
        self.trace.append(("send", operation))
        if status == 412:
            raise FakeSdkServiceError(
                {
                    "Error": {"Code": "PreconditionFailed"},
                    "ResponseMetadata": {
                        "RequestId": request_id,
                        "HTTPStatusCode": status,
                        "RetryAttempts": 0,
                    },
                }
            )
        if operation == "GetObject":
            value["Body"] = response.raw
            return value
        parsed = json.loads(response.content)
        if operation == "AssumeRole":
            parsed["Credentials"]["Expiration"] = datetime.fromisoformat(
                parsed["Credentials"]["Expiration"]
            )
        return parsed

    def commit_discovery(self, frame):
        assert self.list_count > 0
        durable = validate_discovery(self.row, frame, reservation_digest=RESERVATION_DIGEST)
        self.durable = durable
        self.trace.append(("durable-discovery",))
        ack = {
            "kind": "discovery_committed",
            "request_digest": durable["request_digest"],
            "reservation_digest": durable["reservation_digest"],
            "discovery_digest": content_hash(durable),
            "frame_digest": durable["frame_digest"],
            "next_send_sequence": durable["next_send_sequence"],
        }
        if self.ack_mode == "lost":
            raise RuntimeError("synthetic acknowledgement delivery lost")
        if self.ack_mode == "wrong":
            ack["frame_digest"] = "sha256:" + "f" * 64
        self.trace.append(("discovery-ack",))
        return ack


def run_audit(*, ack_mode="valid", listing_mode="one", object_mode="valid"):
    row = request_row()
    request = S3WorkerRequest.from_mapping(row)
    factory = FakeAuditFactory(
        request.to_dict(), ack_mode=ack_mode, listing_mode=listing_mode, object_mode=object_mode
    )
    adapter = S3SdkAdapter(
        request,
        credentials(),
        factory=factory,
        permit=acknowledge,
        clock=lambda: timestamp(row["audit"]["issued_at"]),
        discovery=factory.commit_discovery,
        audit_reservation_digest=RESERVATION_DIGEST,
    )
    return adapter.execute(), factory, adapter


def test_collect_uses_exact_collector_lists_and_ack_before_conditional_get():
    result, factory, adapter = run_audit()
    assert result["outcome"] == "observed"
    assert [operation for service, operation, _role, _params in factory.operations[:3]] == [
        "GetCallerIdentity",
        "AssumeRole",
        "GetCallerIdentity",
    ]
    assert [role for _service, _operation, role, _params in factory.operations[:3]] == [
        "controller",
        "controller",
        "collector",
    ]
    assert all(service == "sts" for service, _operation, _role, _params in factory.operations[:3])
    list_indices = [
        index
        for index, (_service, operation, _role, _params) in enumerate(factory.operations)
        if operation == "ListObjectsV2"
    ]
    get_indices = [
        index
        for index, (_service, operation, _role, _params) in enumerate(factory.operations)
        if operation == "GetObject"
    ]
    assert len(list_indices) == len(factory.list_payloads) > 0
    expected_lists = audit.list_parameters(
        S3AccessScope.from_mapping(factory.row["scope"]), factory.row["audit"]
    )
    assert [factory.operations[index][3] for index in list_indices] == expected_lists
    assert len(get_indices) == 1
    ack_position = factory.trace.index(("discovery-ack",))
    get_position = factory.trace.index(("send", "GetObject"))
    assert ack_position < get_position
    selected = factory.durable["selected"][0]
    get_parameters = factory.operations[get_indices[0]][3]
    assert get_parameters["Key"] == selected["key"]
    assert get_parameters["IfMatch"] == selected["etag"] == '"synthetic-etag-0"'
    assert factory.durable["listings"][0]["body_sha256"] == (
        "sha256:" + hashlib.sha256(factory.list_payloads[0]).hexdigest()
    )
    assert result["data"]["delivery_state"] == "incomplete"
    assert result["data"]["correlations"]["probe"]["reads"][0]["status"] == "matched"
    assert [read["status"] for read in result["data"]["correlations"]["legitimate"]["reads"]] == [
        "matched",
        "matched",
    ]
    assert result["data"]["effective_access_claim"] is False
    assert result["data"]["log_integrity_proven"] is False
    assert all(body.closed for transport in factory.transports for body in transport.bodies)
    assert all(client.closed for client in factory.clients)
    with pytest.raises(S3AccessError, match="executed twice"):
        adapter.execute()


@pytest.mark.parametrize("ack_mode", ["lost", "wrong"])
def test_lost_or_wrong_durable_ack_never_dispatches_get(ack_mode):
    result, factory, _adapter = run_audit(ack_mode=ack_mode)
    assert result["outcome"] == "failed"
    assert factory.durable is not None
    assert "GetObject" not in [
        operation for _service, operation, _role, _params in factory.operations
    ]


def test_fresh_collector_identity_mismatch_refuses_before_listing():
    result, factory, _adapter = run_audit(object_mode="wrong_collector_identity")
    assert result["outcome"] == "failed"
    assert [operation for _service, operation, _role, _params in factory.operations] == [
        "GetCallerIdentity",
        "AssumeRole",
        "GetCallerIdentity",
    ]


@pytest.mark.parametrize("object_mode", ["wrong_size", "wrong_etag"])
def test_get_response_must_match_committed_size_and_etag(object_mode):
    result, factory, _adapter = run_audit(object_mode=object_mode)
    assert result["outcome"] == "failed"
    assert "GetObject" in [operation for _service, operation, _role, _params in factory.operations]
    assert all(body.closed for transport in factory.transports for body in transport.bodies)


@pytest.mark.parametrize(
    "object_mode",
    [
        "invalid_gzip",
        "concatenated_gzip",
        "oversized_gzip",
        "event_limit",
        "bad_crc",
        "truncated_gzip",
    ],
)
def test_object_gzip_and_event_budgets_fail_closed(object_mode):
    result, factory, _adapter = run_audit(object_mode=object_mode)
    assert result["outcome"] == "failed"
    assert "GetObject" in [operation for _service, operation, _role, _params in factory.operations]
    assert all(body.closed for transport in factory.transports for body in transport.bodies)


@pytest.mark.parametrize("object_mode", ["aggregate_expanded_bytes", "aggregate_events"])
def test_two_selected_objects_share_expansion_and_event_budgets(object_mode):
    result, factory, _adapter = run_audit(listing_mode="two", object_mode=object_mode)
    get_operations = [
        operation
        for _service, operation, _role, _params in factory.operations
        if operation == "GetObject"
    ]
    assert result["outcome"] == "failed"
    assert get_operations == ["GetObject", "GetObject"]
    assert factory.durable is not None and len(factory.durable["selected"]) == 2
    assert factory.get_count == 2
    assert all(body.closed for transport in factory.transports for body in transport.bodies)
    assert all(client.closed for client in factory.clients)


def test_conditional_412_is_a_single_service_failure_without_retry():
    result, factory, _adapter = run_audit(object_mode="precondition_failed")
    get_operations = [
        operation
        for _service, operation, _role, _params in factory.operations
        if operation == "GetObject"
    ]
    assert result["outcome"] == "failed"
    assert get_operations == ["GetObject"]
    assert factory.get_count == 1
    assert len(get_operations) == len(set(get_operations)) == 1
    assert all(body.closed for transport in factory.transports for body in transport.bodies)
    assert all(client.closed for client in factory.clients)


def test_final_oversized_result_still_closes_all_clients_and_bodies():
    row = request_row()
    request = S3WorkerRequest.from_mapping(row)
    limits = audit.budget(S3AccessScope.from_mapping(row["scope"]), row["audit"]["source"])[
        "per_batch"
    ]
    payload = _gzip_payload(request.to_dict(), "oversized_correlations")
    expanded = gzip.decompress(payload)
    records = json.loads(expanded)["Records"]
    assert len(records) == limits["events"]
    assert len(expanded) <= limits["expanded_bytes"]
    assert len(payload) <= limits["compressed_bytes"]
    assert len(payload) <= audit.MAX_RESPONSE_BYTES

    factory = FakeAuditFactory(request.to_dict(), object_mode="oversized_correlations")
    adapter = S3SdkAdapter(
        request,
        credentials(),
        factory=factory,
        permit=acknowledge,
        clock=lambda: timestamp(row["audit"]["issued_at"]),
        discovery=factory.commit_discovery,
        audit_reservation_digest=RESERVATION_DIGEST,
    )

    with pytest.raises(S3AccessError, match="document exceeds its byte bound"):
        adapter.execute()
    assert factory.get_count == 1
    assert all(client.closed for client in factory.clients)
    assert all(transport.session.closed for transport in factory.transports)
    assert all(body.closed for transport in factory.transports for body in transport.bodies)


@pytest.mark.parametrize("listing_mode", ["empty", "truncated"])
def test_empty_and_truncated_listings_commit_before_any_selected_read(listing_mode):
    result, factory, _adapter = run_audit(listing_mode=listing_mode)
    assert result["outcome"] == "observed"
    assert factory.durable["truncated"] is (listing_mode == "truncated")
    if listing_mode == "empty":
        assert factory.durable["selected"] == []
        assert result["data"]["objects"] == []
        assert "GetObject" not in [
            operation for _service, operation, _role, _params in factory.operations
        ]
    else:
        assert result["data"]["delivery_state"] == "truncated"
        assert len(factory.durable["selected"]) == 1
        assert [operation for _service, operation, _role, _params in factory.operations].count(
            "GetObject"
        ) == 1
