"""Finite fixture clients are synthetic; no SDK import or external effects."""

import hashlib
import io
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from bluefire import s3_fixture_contract as fixtures
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_sdk import S3SdkAdapter
from bluefire.s3_access_wire import S3WorkerRequest, validate_result
from tests_platform.test_s3_access_sdk import FakeFactory, FakeServiceError, response_meta
from tests_platform.test_s3_access_wire import NOW, acknowledge, credentials, request_row


def fixture_request(operation="prepare_fixture", purpose="primary", expected_etag=None):
    row = request_row("inspect_policy")
    for obj in row["scope"]["objects"]:
        data = fixtures.payload(row["scope"]["scope_id"], obj["purpose"])
        obj.update(size_bytes=len(data), sha256="sha256:" + hashlib.sha256(data).hexdigest())
    scope = S3AccessScope.from_mapping(row["scope"])
    descriptor = {
        "schema_version": fixtures.ENROLLMENT_SCHEMA,
        "scope_digest": scope.digest,
        "generation_digest": "sha256:" + "7" * 64,
        "exclusive_writer_digest": "sha256:" + "8" * 64,
        "bucket_shape": fixtures.BUCKET_SHAPE,
    }
    row.update(
        schema_version=fixtures.REQUEST_SCHEMA,
        operation=operation,
        scope_digest=scope.digest,
        max_sends=fixtures.SEND_LIMITS[operation],
        fixture_authority_digest=fixtures.authority_digest(scope, descriptor),
        fixture={
            "schema_version": fixtures.OPERATION_SCHEMA,
            "intent_id": "a" * 64,
            "purpose": purpose,
            "expected_etag": expected_etag,
        },
    )
    return S3WorkerRequest.from_mapping(row), descriptor


class FixtureFactory(FakeFactory):
    def __init__(self, request, *, objects=None, modify=None, fail_after=None):
        super().__init__(request, modify=modify)
        self.objects = {} if objects is None else objects
        self.fail_after = fail_after

    def client(self, service, secret, scope, guard, timeout):
        client = super().client(service, secret, scope, guard, timeout)
        for name, operation in {
            "get_bucket_versioning": "GetBucketVersioning",
            "get_object_lock_configuration": "GetObjectLockConfiguration",
            "put_object": "PutObject",
            "delete_object": "DeleteObject",
            "list_objects_v2": "ListObjectsV2",
        }.items():
            setattr(
                client,
                name,
                lambda _operation=operation, **params: self.invoke(
                    service, _operation, "controller", guard, params
                ),
            )
        return client

    @staticmethod
    def error(code, status=404):
        raise FakeServiceError({**response_meta(status), "Error": {"Code": code}})

    def invoke(self, service, operation, role, guard, params):
        if service == "sts":
            return super().invoke(service, operation, role, guard, params)
        path = "/" + self.scope["bucket"]
        headers = {"x-amz-expected-bucket-owner": self.scope["account_id"]}
        if operation in {"GetBucketVersioning", "GetObjectLockConfiguration"}:
            path += "?" + ("versioning" if operation == "GetBucketVersioning" else "object-lock")
        elif operation == "ListObjectsV2":
            path += "?" + urlencode(
                {
                    "list-type": "2",
                    "prefix": params["Prefix"],
                    "max-keys": "3",
                    "encoding-type": "url",
                }
            )
        else:
            path += "/" + params["Key"]
        if operation == "PutObject":
            headers.update(
                {
                    "if-none-match": "*",
                    "x-amz-server-side-encryption": "AES256",
                    "content-type": params["ContentType"],
                    "content-length": str(params["ContentLength"]),
                    "expect": "100-continue",
                    "x-amz-checksum-sha256": params["ChecksumSHA256"],
                    **{"x-amz-meta-" + key: value for key, value in params["Metadata"].items()},
                }
            )
        elif operation == "DeleteObject":
            headers["if-match"] = params["IfMatch"]
            headers["content-length"] = "0"
        elif operation == "GetObject":
            headers["x-amz-checksum-mode"] = params["ChecksumMode"]
        prepared = SimpleNamespace(
            method=(
                "PUT"
                if operation == "PutObject"
                else "DELETE" if operation == "DeleteObject" else "GET"
            ),
            url="https://" + S3AccessScope.from_mapping(self.scope).service_hosts["s3"] + path,
            body=io.BytesIO(params["Body"]) if operation == "PutObject" else b"",
            headers=headers,
            stream_output=operation == "GetObject",
        )
        if self.modify:
            self.modify("prepared", operation, prepared)
        guard.hook(prepared)
        guard.claim_transport_send(prepared)
        self.calls.append((operation, role, deepcopy(params)))
        result = response_meta(204 if operation == "DeleteObject" else 200)
        if operation == "GetObjectLockConfiguration":
            self.error("ObjectLockConfigurationNotFoundError")
        elif operation == "GetObject":
            obj = self.objects.get(params["Key"])
            if obj is None:
                self.error("NoSuchKey")
            body = io.BytesIO(obj["body"])
            self.bodies.append(body)
            result.update(
                Body=body,
                ContentLength=len(obj["body"]),
                ETag=obj["etag"],
                Metadata=deepcopy(obj["metadata"]),
                ContentType="application/x-ndjson",
                ServerSideEncryption="AES256",
            )
        elif operation == "PutObject":
            if params["Key"] in self.objects:
                self.error("PreconditionFailed", 412)
            self.objects[params["Key"]] = {
                "body": params["Body"],
                "etag": '"owned-token"',
                "metadata": params["Metadata"],
            }
            result.update(ETag='"owned-token"', ServerSideEncryption="AES256")
        elif operation == "DeleteObject":
            obj = self.objects.get(params["Key"])
            if obj is None or obj["etag"] != params["IfMatch"]:
                self.error("PreconditionFailed", 412)
            del self.objects[params["Key"]]
        elif operation == "ListObjectsV2":
            result.update(
                IsTruncated=False,
                Prefix=params["Prefix"],
                Name=self.scope["bucket"],
                MaxKeys=3,
                KeyCount=len(self.objects),
                Contents=[
                    {"Key": key, "Size": len(value["body"]), "ETag": value["etag"]}
                    for key, value in self.objects.items()
                ],
            )
        if self.modify:
            self.modify("response", operation, result)
        if operation == self.fail_after:
            raise RuntimeError("untrusted secret transport details")
        return result


def run(request, *, objects=None, modify=None, fail_after=None, permit=acknowledge):
    factory = FixtureFactory(request, objects=objects, modify=modify, fail_after=fail_after)
    result = S3SdkAdapter(
        request, credentials(), factory=factory, permit=permit, clock=lambda: NOW
    ).execute()
    assert all(body.closed for body in factory.bodies)
    assert all(client.closed for client in factory.clients)
    return result, factory


def test_exact_prepare_reconcile_cleanup_uses_conditional_operations():
    request, _ = fixture_request()
    result, factory = run(request)
    assert result["outcome"] == "observed"
    assert result["data"]["state"] == "owned"
    assert result["send_permits_consumed"] == 6
    for name, count, state, token in [
        ("reconcile_fixture", 5, "owned", None),
        ("cleanup_fixture", 7, "absent", '"owned-token"'),
    ]:
        request, _ = fixture_request(name, expected_etag=token)
        result, factory = run(request, objects=factory.objects)
        assert result["outcome"] == "observed"
        assert result["data"]["state"] == state
        assert result["send_permits_consumed"] == count
        assert validate_result(request, result) == result
    assert factory.objects == {}


def test_absent_cleanup_is_read_only_but_reserves_seven():
    request, _ = fixture_request("cleanup_fixture")
    result, factory = run(request)
    assert request.to_dict()["max_sends"] == 7
    assert result["outcome"] == "observed"
    assert result["send_permits_consumed"] == 5
    assert all(op != "DeleteObject" for op, _, _ in factory.calls)


@pytest.mark.parametrize("name", ["prepare_fixture", "cleanup_fixture"])
def test_lost_mutation_ack_requires_reconciliation_never_replay(name):
    request, _ = fixture_request()
    _, prior = run(request)
    request, _ = fixture_request(
        name, expected_etag='"owned-token"' if name == "cleanup_fixture" else None
    )
    result, factory = run(
        request,
        objects=prior.objects if name == "cleanup_fixture" else {},
        fail_after="DeleteObject" if name == "cleanup_fixture" else "PutObject",
    )
    assert result["outcome"] == "reconcile_required"
    assert result["send_permits_consumed"] == 5
    assert "untrusted" not in str(result)
    reconciliation, _ = fixture_request("reconcile_fixture")
    observed, _ = run(reconciliation, objects=factory.objects)
    assert observed["outcome"] == "observed"
    assert observed["data"]["state"] == ("absent" if name == "cleanup_fixture" else "owned")


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(Status="Enabled"),
        lambda value: value.update(Status="Suspended"),
        lambda value: value.update(MFADelete="Disabled"),
    ],
)
def test_non_never_versioned_shape_refuses_before_mutation(change):
    request, _ = fixture_request()
    result, factory = run(
        request,
        modify=lambda kind, op, value: (
            change(value) if kind == "response" and op == "GetBucketVersioning" else None
        ),
    )
    assert result["outcome"] == "failed"
    assert not factory.objects
    assert len(factory.calls) == 2


@pytest.mark.parametrize(
    "header,value",
    [
        ("if-none-match", "other"),
        ("x-amz-meta-bluefire-intent", "b" * 64),
        ("x-amz-expected-bucket-owner", "000000000000"),
        ("x-extra", "bad"),
        ("expect", "unsupported"),
    ],
)
def test_prepared_mutation_drift_refuses_before_debit(header, value):
    request, _ = fixture_request()
    result, factory = run(
        request,
        modify=lambda kind, op, request: (
            request.headers.update({header: value})
            if kind == "prepared" and op == "PutObject"
            else None
        ),
    )
    assert result["outcome"] == "failed"
    assert result["send_permits_consumed"] == 4
    assert not factory.objects


def test_existing_even_owned_object_never_overwritten():
    request, _ = fixture_request()
    _, prior = run(request)
    result, factory = run(request, objects=prior.objects)
    assert result["outcome"] == "failed"
    assert len(factory.calls) == 4


@pytest.mark.parametrize(
    "field,value", [("metadata", {}), ("etag", '"changed"'), ("body", b"wrong")]
)
def test_cleanup_requires_exact_preimage(field, value):
    request, _ = fixture_request()
    _, prior = run(request)
    next(iter(prior.objects.values()))[field] = value
    request, _ = fixture_request("cleanup_fixture", expected_etag='"owned-token"')
    result, factory = run(request, objects=prior.objects)
    assert result["outcome"] == "failed"
    assert len(factory.calls) == 4
    assert factory.objects


@pytest.mark.parametrize(
    "mutation",
    [
        lambda row: row.update(schema_version="bluefire.s3-worker-request.v1"),
        lambda row: row["scope"]["objects"][0].update(sha256="sha256:" + "0" * 64),
        lambda row: row["fixture"].update(expected_etag="*"),
        lambda row: row["fixture"].update(extra=True),
    ],
)
def test_v2_contract_refuses_legacy_or_unbound_bytes(mutation):
    row = fixture_request()[0].to_dict()
    mutation(row)
    with pytest.raises(S3AccessError):
        S3WorkerRequest.from_mapping(row)


def test_python_matches_shared_native_fixture_corpus():
    value = json.loads(
        (Path(__file__).parent / "fixtures" / "s3_fixture_v2.json").read_text(encoding="utf-8")
    )
    for case in value["cases"]:
        request = S3WorkerRequest.from_mapping(case["request"])
        row = request.to_dict()
        assert request.digest == case["request_digest"]
        assert (
            fixtures.authority_digest(S3AccessScope.from_mapping(row["scope"]), value["enrollment"])
            == row["fixture_authority_digest"]
        )
        objects = {}
        if row["operation"] == "reconcile_fixture" or row["fixture"]["expected_etag"]:
            obj = row["scope"]["objects"][0]
            objects[obj["key"]] = {
                "body": fixtures.payload(row["scope"]["scope_id"], "primary"),
                "etag": '"owned-token"',
                "metadata": fixtures.object_metadata(row["scope"], row["fixture"]),
            }
        sends = []
        result, _ = run(
            request,
            objects=objects,
            permit=lambda send, sends=sends: sends.append(send) or acknowledge(send),
        )
        assert sends == case["sends"]
        assert result == case["result"]


def test_recovered_delete_result_cannot_claim_wrong_success_status():
    request, _ = fixture_request()
    _, factory = run(request)
    request, _ = fixture_request("cleanup_fixture", expected_etag='"owned-token"')
    result, _ = run(request, objects=factory.objects)
    result["calls"][4]["http_status"] = 200
    with pytest.raises(S3AccessError):
        validate_result(request, result)


def test_access_denial_is_not_absence(monkeypatch):
    original = FixtureFactory.error

    def denial(code, status=404):
        return original("AccessDenied", 403) if code == "NoSuchKey" else original(code, status)

    monkeypatch.setattr(FixtureFactory, "error", staticmethod(denial))
    result, source = run(fixture_request()[0])
    assert result["outcome"] == "failed" and result["data"] is None
    assert len(source.calls) == 4 and not source.objects


def test_object_lock_success_even_empty_is_unsupported(monkeypatch):
    original = FixtureFactory.error
    monkeypatch.setattr(
        FixtureFactory,
        "error",
        staticmethod(
            lambda code, status=404: (
                None if code == "ObjectLockConfigurationNotFoundError" else original(code, status)
            )
        ),
    )
    result, source = run(fixture_request()[0])
    assert result["outcome"] == "failed"
    assert len(source.calls) == 3 and not source.objects


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(IsTruncated=True),
        lambda value: value.update(NextContinuationToken="untrusted"),
        lambda value: value.update(KeyCount=True),
        lambda value: value.update(Contents=[{"Key": "foreign", "Size": 3}], KeyCount=1),
        lambda value: value.update(Prefix="another-prefix"),
    ],
)
def test_unbounded_or_foreign_listing_never_confirms_cleanup(change):
    request, _ = fixture_request("cleanup_fixture")
    result, _ = run(
        request,
        modify=lambda kind, op, value: (
            change(value) if kind == "response" and op == "ListObjectsV2" else None
        ),
    )
    assert result["outcome"] == "failed" and result["data"] is None


def test_missing_write_request_id_is_uncertain_not_success():
    request, _ = fixture_request()
    result, source = run(
        request,
        modify=lambda kind, op, value: (
            value["ResponseMetadata"].pop("RequestId")
            if kind == "response" and op == "PutObject"
            else None
        ),
    )
    assert result["outcome"] == "reconcile_required"
    assert result["send_permits_consumed"] == 5
    assert len(source.objects) == 1


def test_denied_native_mutation_permit_never_reaches_fake_service():
    request, _ = fixture_request()
    result, source = run(
        request, permit=lambda send: {} if send["sequence"] == 5 else acknowledge(send)
    )
    assert result["outcome"] == "failed"
    assert result["send_permits_consumed"] == 4
    assert not source.objects


@pytest.mark.parametrize("value", [None, "1", "00", 0])
def test_delete_requires_exact_sdk_empty_body_content_length(value):
    request, _ = fixture_request()
    _, prior = run(request)
    request, _ = fixture_request("cleanup_fixture", expected_etag='"owned-token"')

    def modify(kind, operation, prepared):
        if kind == "prepared" and operation == "DeleteObject":
            if value is None:
                prepared.headers.pop("content-length")
            else:
                prepared.headers["content-length"] = value

    result, source = run(request, objects=prior.objects, modify=modify)
    assert result["outcome"] == "failed"
    assert result["send_permits_consumed"] == 4
    assert source.objects


def test_put_requires_exact_sdk_expect_header():
    request, _ = fixture_request()
    result, source = run(
        request,
        modify=lambda kind, op, prepared: (
            prepared.headers.pop("expect") if kind == "prepared" and op == "PutObject" else None
        ),
    )
    assert result["outcome"] == "failed"
    assert result["send_permits_consumed"] == 4
    assert not source.objects


def test_expect_header_is_not_admitted_on_reads():
    request, _ = fixture_request()
    result, source = run(
        request,
        modify=lambda kind, op, prepared: (
            prepared.headers.update(expect="100-continue")
            if kind == "prepared" and op == "GetObject"
            else None
        ),
    )
    assert result["outcome"] == "failed"
    assert result["send_permits_consumed"] == 3
    assert not source.objects


@pytest.mark.parametrize("extra_call", [False, True])
def test_failed_readonly_cleanup_cannot_exceed_five_send_plan(extra_call):
    request, _ = fixture_request("cleanup_fixture")
    result, _ = run(request)
    result.update(
        outcome="failed",
        problem="scoped_operation_failed",
        data=None,
        send_permits_consumed=6,
    )
    if extra_call:
        result["calls"].append({"unvalidated": "extra"})
    with pytest.raises(S3AccessError, match="accounting"):
        validate_result(request, result)


@pytest.mark.parametrize("value", [None, "DISABLED", "enabled", True])
def test_fixture_get_requires_exact_sdk_checksum_mode(value):
    request, _ = fixture_request()

    def modify(kind, operation, prepared):
        if kind == "prepared" and operation == "GetObject":
            if value is None:
                prepared.headers.pop("x-amz-checksum-mode")
            else:
                prepared.headers["x-amz-checksum-mode"] = value

    result, source = run(request, modify=modify)
    assert result["outcome"] == "failed"
    assert result["send_permits_consumed"] == 3
    assert len(source.calls) == 3 and not source.objects


@pytest.mark.parametrize("operation", ["GetBucketVersioning", "PutObject", "ListObjectsV2"])
def test_fixture_checksum_mode_is_not_admitted_on_other_operations(operation):
    request, _ = fixture_request(
        "cleanup_fixture" if operation == "ListObjectsV2" else "prepare_fixture"
    )
    result, source = run(
        request,
        modify=lambda kind, op, prepared: (
            prepared.headers.update({"x-amz-checksum-mode": "ENABLED"})
            if kind == "prepared" and op == operation
            else None
        ),
    )
    assert result["outcome"] == "failed"
    assert all(op != operation for op, _, _ in source.calls)
    assert not source.objects


def test_fixture_get_explicit_checksum_mode_matches_pinned_sdk_shape():
    request, _ = fixture_request()
    result, source = run(request)
    assert result["outcome"] == "observed"
    reads = [params for op, _, params in source.calls if op == "GetObject"]
    assert len(reads) == 2
    assert all(params["ChecksumMode"] == "ENABLED" for params in reads)
