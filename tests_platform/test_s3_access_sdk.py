"""Deterministic fake-client checks; no SDK, network or runtime isolation proof."""

import hashlib
import io
import json
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_sdk import S3SdkAdapter
from bluefire.s3_access_sdk_boundary import BotocoreFactory, metadata
from bluefire.s3_access_wire import S3WorkerRequest, validate_result
from bluefire.util import canonical_json_bytes
from tests_platform.test_s3_access_policy import fixture
from tests_platform.test_s3_access_wire import NOW, acknowledge, credentials, request_row

DATA = [b'{"record":"synthetic"}\n', b'{"health":"ok"}\n']


def worker_request(operation="inspect_policy"):
    row = request_row(operation)
    if operation.endswith("read"):
        for obj, data in zip(row["scope"]["objects"], DATA, strict=True):
            obj.update(size_bytes=len(data), sha256="sha256:" + hashlib.sha256(data).hexdigest())
        row["scope_digest"] = S3AccessScope.from_mapping(row["scope"]).digest
    return S3WorkerRequest.from_mapping(row)


def response_meta(status=200):
    return {
        "ResponseMetadata": {
            "RequestId": "SAFE-REQUEST-ID",
            "HTTPStatusCode": status,
            "RetryAttempts": 0,
        }
    }


class FakeServiceError(Exception):
    def __init__(self, response):
        super().__init__("SECRET-TRANSPORT-DETAIL")
        self.response = response


class FakeFactory:
    """Only tests construct this class. No request field or runtime loader selects it."""

    def __init__(
        self, request, *, modify=None, failure=None, skip_hook=False, duplicate_hook=False
    ):
        self.row = request.to_dict()
        self.scope = self.row["scope"]
        self.policy = deepcopy(fixture()[1])
        if self.row["operation"] == "rollback_policy":
            self.policy = deepcopy(self.row["policy_change"]["after"])
        self.modify, self.failure = modify, failure
        self.skip_hook, self.duplicate_hook = skip_hook, duplicate_hook
        self.calls, self.clients, self.bodies, self.configs = [], [], [], []
        self.reader = None

    def service_error(self, error):
        return error.response if isinstance(error, FakeServiceError) else None

    def client(self, service, secret, scope, guard, timeout):
        assert scope.digest == self.row["scope_digest"]
        assert 0 < timeout <= 5
        role = "controller" if secret.access_key == credentials().access_key else self.reader
        client = SimpleNamespace(closed=False)
        client.close = lambda: setattr(client, "closed", True)
        for name, operation in {
            "get_caller_identity": "GetCallerIdentity",
            "assume_role": "AssumeRole",
            "get_bucket_policy": "GetBucketPolicy",
            "put_bucket_policy": "PutBucketPolicy",
            "get_object": "GetObject",
        }.items():
            setattr(
                client,
                name,
                lambda _operation=operation, **params: self.invoke(
                    service, _operation, role, guard, params
                ),
            )
        self.clients.append(client)
        return client

    def invoke(self, service, operation, role, guard, params):
        host = S3AccessScope.from_mapping(self.scope).service_hosts[service]
        if service == "sts":
            prepared = SimpleNamespace(
                method="POST",
                url="https://" + host + "/",
                body=urlencode({"Action": operation, "Version": "2011-06-15", **params}).encode(),
                headers={},
                stream_output=False,
            )
        else:
            path = "/" + params["Bucket"]
            path += "/" + params["Key"] if operation == "GetObject" else "?policy"
            prepared = SimpleNamespace(
                method="PUT" if operation == "PutBucketPolicy" else "GET",
                url="https://" + host + path,
                body=params.get("Policy", "").encode(),
                headers={"x-amz-expected-bucket-owner": params["ExpectedBucketOwner"]},
                stream_output=operation == "GetObject",
            )
        if self.modify:
            self.modify("prepared", operation, prepared)
        if not self.skip_hook:
            guard.hook(prepared)
            if self.duplicate_hook:
                guard.hook(prepared)
            if self.modify:
                self.modify("after_hook", operation, prepared)
            guard.claim_transport_send(prepared)
        self.calls.append((operation, role, deepcopy(params)))
        if self.failure:
            error = self.failure(operation, len(self.calls))
            if error:
                raise error
        result = response_meta(204 if operation == "PutBucketPolicy" else 200)
        if operation == "GetCallerIdentity":
            session = "controller-session" if role == "controller" else self.session_name
            name = self.scope["roles"][role].rsplit("/", 1)[1]
            result.update(
                Account=self.scope["account_id"],
                Arn=f"arn:aws:sts::{self.scope['account_id']}:assumed-role/{name}/{session}",
                UserId="AROA" + "F" * 16 + ":" + session,
            )
        elif operation == "AssumeRole":
            self.reader = "probe" if self.row["operation"] == "probe_read" else "legitimate"
            self.session_name = params["RoleSessionName"]
            result.update(
                Credentials={
                    "AccessKeyId": "ASIA" + "R" * 16,
                    "SecretAccessKey": "R" * 40,
                    "SessionToken": "R" * 64,
                    "Expiration": NOW + timedelta(seconds=900),
                },
                AssumedRoleUser={
                    "Arn": f"arn:aws:sts::{self.scope['account_id']}:assumed-role/{params['RoleArn'].rsplit('/', 1)[1]}/{self.session_name}",
                    "AssumedRoleId": "AROA" + "F" * 16 + ":" + self.session_name,
                },
            )
        elif operation == "GetBucketPolicy":
            result["Policy"] = canonical_json_bytes(self.policy).decode()
        elif operation == "PutBucketPolicy":
            self.policy = json.loads(params["Policy"])
        elif operation == "GetObject":
            index = [obj["key"] for obj in self.scope["objects"]].index(params["Key"])
            body = io.BytesIO(DATA[index])
            self.bodies.append(body)
            result.update(Body=body, ContentLength=len(DATA[index]))
        if self.modify:
            self.modify("response", operation, result)
        return result


def run(operation="inspect_policy", *, factory=None, permit=acknowledge, clock=lambda: NOW):
    request = worker_request(operation)
    source = factory or FakeFactory(request)
    adapter = S3SdkAdapter(request, credentials(), factory=source, permit=permit, clock=clock)
    return adapter.execute(), source, adapter


@pytest.mark.parametrize(
    "operation,count",
    [
        ("inspect_policy", 2),
        ("apply_policy", 4),
        ("rollback_policy", 4),
        ("probe_read", 4),
        ("legitimate_read", 5),
    ],
)
def test_fixed_operation_happy_paths_use_all_required_guards(operation, count):
    permits = []
    result, source, adapter = run(
        operation, permit=lambda send: permits.append(send) or acknowledge(send)
    )
    assert result["outcome"] == "observed"
    assert result["send_permits_consumed"] == count == len(permits) == len(source.calls)
    assert not result["runtime_isolation_proven"]
    assert all(client.closed for client in source.clients)
    assert all(body.closed for body in source.bodies)
    if operation.endswith("read"):
        assert (
            result["data"]["objects"][0]["sha256"]
            == "sha256:" + hashlib.sha256(DATA[0]).hexdigest()
        )
        assert result["data"]["effective_access_claim"] is False
    else:
        assert "policy_digest" in result["data"]
    serialized = json.dumps(result) + json.dumps(permits)
    for secret in (credentials().secret_key, credentials().token, "R" * 40):
        assert secret not in serialized
    with pytest.raises(S3AccessError):
        adapter.execute()


@pytest.mark.parametrize("skip,duplicate", [(True, False), (False, True)])
def test_fake_client_cannot_skip_or_repeat_required_before_send(skip, duplicate):
    factory = FakeFactory(worker_request(), skip_hook=skip, duplicate_hook=duplicate)
    result, _, _ = run(factory=factory)
    assert result["outcome"] == "failed"
    assert result["calls"] == []
    assert all(client.closed for client in factory.clients)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda row: row.pop("RequestId"),
        lambda row: row.update(RequestId="bad\nSECRET"),
        lambda row: row.update(HTTPStatusCode=206),
        lambda row: row.update(RetryAttempts=1),
        lambda row: row.update(RetryAttempts=False),
    ],
)
def test_missing_or_invalid_metadata_never_confirms_success(mutate):
    def modify(kind, operation, value):
        if kind == "response":
            mutate(value["ResponseMetadata"])

    result, _, _ = run(factory=FakeFactory(worker_request(), modify=modify))
    assert result["outcome"] == "failed"
    assert result["calls"] == []
    assert "SECRET" not in json.dumps(result)


@pytest.mark.parametrize(
    "url",
    [
        "http://s3.us-east-1.amazonaws.com/bucket",
        "https://evil.example/",
        "https://s3.us-east-1.amazonaws.com:8443/",
        "https://user@sts.us-east-1.amazonaws.com/",
        "https://sts.us-east-1.amazonaws.com/#x",
    ],
)
def test_prepared_endpoint_drift_refuses_before_native_debit(url):
    def modify(kind, operation, value):
        if kind == "prepared":
            value.url = url

    result, source, _ = run(factory=FakeFactory(worker_request(), modify=modify))
    assert result["outcome"] == "failed"
    assert result["send_permits_consumed"] == 0
    assert not source.calls


@pytest.mark.parametrize("mutation", ["owner", "range", "key", "method", "query"])
def test_object_request_cannot_widen_exact_resource(mutation):
    def modify(kind, operation, value):
        if kind == "prepared" and operation == "GetObject":
            if mutation == "owner":
                value.headers["x-amz-expected-bucket-owner"] = "000000000000"
            elif mutation == "range":
                value.headers["Range"] = "bytes=0-1"
            elif mutation == "key":
                value.url += "-other"
            elif mutation == "method":
                value.method = "DELETE"
            else:
                value.url += "?versionId=other"

    factory = FakeFactory(worker_request("probe_read"), modify=modify)
    result, _, _ = run("probe_read", factory=factory)
    assert result["outcome"] == "failed"
    assert result["send_permits_consumed"] == 3


@pytest.mark.parametrize("mutation", ["account", "role", "user", "assumed_id"])
def test_fresh_reader_identity_is_verified_before_object_read(mutation):
    identities = 0

    def modify(kind, operation, value):
        nonlocal identities
        if kind != "response":
            return
        if operation == "AssumeRole" and mutation == "assumed_id":
            value["AssumedRoleUser"].pop("AssumedRoleId")
        if operation == "GetCallerIdentity":
            identities += 1
            if identities != 2:
                return
            if mutation == "account":
                value["Account"] = "000000000000"
            elif mutation == "role":
                value["Arn"] = value["Arn"].replace("assumed-role/", "assumed-role/other-")
            elif mutation == "user":
                value["UserId"] = "AROA" + "X" * 16 + ":" + value["UserId"].split(":")[1]

    factory = FakeFactory(worker_request("probe_read"), modify=modify)
    result, _, _ = run("probe_read", factory=factory)
    assert result["outcome"] == "failed"
    assert all(call[0] != "GetObject" for call in factory.calls)


@pytest.mark.parametrize("operation", ["apply_policy", "rollback_policy"])
def test_complete_preimage_drift_refuses_write(operation):
    factory = FakeFactory(worker_request(operation))
    factory.policy["Statement"][0]["Sid"] = "DriftedStatement"
    result, _, _ = run(operation, factory=factory)
    assert result["outcome"] == "failed"
    assert [call[0] for call in factory.calls] == ["GetCallerIdentity", "GetBucketPolicy"]


@pytest.mark.parametrize("failure_at", [3, 4])
def test_uncertain_write_or_failed_readback_is_reconcile_only(failure_at):
    factory = FakeFactory(
        worker_request("apply_policy"),
        failure=lambda operation, number: (
            RuntimeError("SECRET-TRANSPORT-DETAIL") if number == failure_at else None
        ),
    )
    result, _, _ = run("apply_policy", factory=factory)
    assert result["outcome"] == "reconcile_required"
    assert result["problem"] == "write_outcome_unsettled"
    assert len(factory.calls) == failure_at
    assert "SECRET" not in json.dumps(result)


def test_readback_drift_after_write_requires_reconciliation():
    def modify(kind, operation, value):
        if kind == "response" and operation == "PutBucketPolicy":
            factory.policy["Statement"][0]["Sid"] = "ConcurrentWriter"

    factory = FakeFactory(worker_request("apply_policy"), modify=modify)
    result, _, _ = run("apply_policy", factory=factory)
    assert result["outcome"] == "reconcile_required"


@pytest.mark.parametrize("invalid_id", [False, True])
def test_access_denied_is_scoped_observation_only_with_valid_metadata(invalid_id):
    error = response_meta(403)
    error["Error"] = {"Code": "AccessDenied", "Message": "SECRET-TRANSPORT-DETAIL"}
    if invalid_id:
        error["ResponseMetadata"]["RequestId"] = "invalid\n"
    factory = FakeFactory(
        worker_request("probe_read"),
        failure=lambda operation, _: FakeServiceError(error) if operation == "GetObject" else None,
    )
    result, _, _ = run("probe_read", factory=factory)
    assert result["outcome"] == ("failed" if invalid_id else "observed")
    if not invalid_id:
        assert result["data"]["objects"] == [{"purpose": "primary", "result": "service_denied"}]
    assert "SECRET" not in json.dumps(result)


@pytest.mark.parametrize("mutation", ["length", "digest", "excess", "short", "missing_metadata"])
def test_object_integrity_failure_always_closes_body(mutation):
    replacements = []

    def modify(kind, operation, value):
        if kind != "response" or operation != "GetObject":
            return
        if mutation == "length":
            value["ContentLength"] += 1
        elif mutation == "missing_metadata":
            value.pop("ResponseMetadata")
        else:
            value["Body"].close()
            data = DATA[0]
            value["Body"] = io.BytesIO(
                {"digest": b"x" * len(data), "excess": data + b"x", "short": data[:-1]}[mutation]
            )
            replacements.append(value["Body"])

    factory = FakeFactory(worker_request("probe_read"), modify=modify)
    result, _, _ = run("probe_read", factory=factory)
    assert result["outcome"] == "failed"
    assert all(body.closed for body in factory.bodies + replacements)


def test_expiry_after_ack_still_counts_debit_and_refuses_send():
    now = NOW

    def permit(send):
        nonlocal now
        now = NOW + timedelta(seconds=31)
        return acknowledge(send)

    result, factory, _ = run(permit=permit, clock=lambda: now)
    assert result["outcome"] == "failed"
    assert result["send_permits_consumed"] == 1
    assert not factory.calls


def test_runtime_factory_uses_explicit_config_credentials_and_transport_guard():
    configs, sessions, checked = [], [], []

    class Session:
        def __init__(self):
            self.values = {}
            sessions.append(self)

        def set_config_variable(self, name, value):
            self.values[name] = value

        def create_client(self, service, **kwargs):
            self.created = (service, kwargs)
            events = SimpleNamespace(
                register=lambda name, hook: setattr(self, "event", (name, hook))
            )
            return SimpleNamespace(
                _endpoint=SimpleNamespace(http_session=SimpleNamespace()),
                meta=SimpleNamespace(events=events),
            )

    factory = BotocoreFactory(
        session_factory=Session,
        config_factory=lambda **values: configs.append(values) or values,
        client_error_type=FakeServiceError,
        ca_bundle="/reviewed/runtime/cacert.pem",
        assert_runtime=lambda: checked.append(True),
    )
    request = worker_request()
    from bluefire.s3_access_sdk_boundary import S3SendGuard

    guard = S3SendGuard(request, acknowledge, lambda: NOW)
    factory.client(
        "s3", credentials(), S3AccessScope.from_mapping(request.to_dict()["scope"]), guard, 5
    )
    assert checked == [True]
    assert sessions[0].values == {
        "config_file": "/dev/null",
        "credentials_file": "/dev/null",
        "profile": None,
    }
    assert configs[0]["retries"] == {"mode": "standard", "total_max_attempts": 1}
    assert configs[0]["proxies"] == {}
    assert configs[0]["s3"]["addressing_style"] == "path"
    assert sessions[0].created[1]["aws_session_token"] == credentials().token
    assert sessions[0].event[0] == "before-send.*.*"


@pytest.mark.parametrize("mutation", ["url", "method", "header", "body"])
def test_prepared_request_cannot_change_between_permit_and_transport(mutation):
    def modify(kind, operation, value):
        if kind != "after_hook":
            return
        if mutation == "url":
            value.url = "https://other.example/"
        elif mutation == "method":
            value.method = "GET"
        elif mutation == "header":
            value.headers["Host"] = "other.example"
        else:
            value.body = b"changed"

    factory = FakeFactory(worker_request(), modify=modify)
    result, _, _ = run(factory=factory)
    assert result["outcome"] == "failed"
    assert result["send_permits_consumed"] == 1
    assert not factory.calls


def test_stream_expiry_after_bytes_never_becomes_success_and_closes():
    now = NOW
    replacements = []

    class ExpiringBody(io.BytesIO):
        def read(self, amount):
            nonlocal now
            chunk = super().read(amount)
            now += timedelta(seconds=31)
            return chunk

    def modify(kind, operation, value):
        if kind == "response" and operation == "GetObject":
            value["Body"].close()
            value["Body"] = ExpiringBody(DATA[0])
            replacements.append(value["Body"])

    factory = FakeFactory(worker_request("probe_read"), modify=modify)
    result, _, _ = run("probe_read", factory=factory, clock=lambda: now)
    assert result["outcome"] == "failed"
    assert all(body.closed for body in replacements)


def test_metadata_projects_unknown_service_error_without_message_or_headers():
    value = response_meta(500)
    value["Error"] = {"Code": "UNTRUSTED\n", "Message": "secret"}
    value["ResponseMetadata"]["HTTPHeaders"] = {"x-secret": "secret"}
    assert metadata(value, success=False) == {
        "request_id": "SAFE-REQUEST-ID",
        "http_status": 500,
        "error_code": "OtherServiceError",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("runtime_isolation_proven", True),
        ("request_digest", "sha256:" + "0" * 64),
        ("outcome", "success"),
        ("send_permits_consumed", True),
        ("send_permits_consumed", 1),
        ("calls", [1]),
        ("data", {"arbitrary": "secret"}),
        ("problem", "untrusted text"),
    ],
)
def test_result_wire_refuses_widened_claims_and_arbitrary_payloads(field, value):
    result, _, _ = run()
    result[field] = value
    with pytest.raises(S3AccessError):
        validate_result(worker_request(), result)


@pytest.mark.parametrize(
    "mutation",
    [
        "call-order",
        "request-id",
        "object-digest",
        "object-size-float",
        "access-claim",
        "denial-without-service-error",
    ],
)
def test_result_read_observation_must_match_calls_and_exact_scope(mutation):
    result, _, _ = run("probe_read")
    if mutation == "call-order":
        result["calls"].reverse()
    elif mutation == "request-id":
        result["calls"][0]["request_id"] = "bad\n"
    elif mutation == "object-digest":
        result["data"]["objects"][0]["sha256"] = "sha256:" + "0" * 64
    elif mutation == "object-size-float":
        result["data"]["objects"][0]["size_bytes"] = float(
            result["data"]["objects"][0]["size_bytes"]
        )
    elif mutation == "access-claim":
        result["data"]["effective_access_claim"] = True
    else:
        result["data"]["objects"][0] = {"purpose": "primary", "result": "service_denied"}
    with pytest.raises(S3AccessError):
        validate_result(worker_request("probe_read"), result)
