"""Pure extraction parity against retained contracts, without SDK or host access."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from bluefire import s3_access_wire as wire
from bluefire import s3_access_wire_contract as ordinary
from bluefire import s3_audit_collection_contract as audit
from bluefire.s3_access_audit import _validated_read
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_audit_read_contract import validated_read
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_audit import result as read_result
from tests_platform.test_s3_access_wire import request_row
from tests_platform.test_s3_audit_collection_contract import collection_row
from tests_platform.test_s3_fixture_sdk import fixture_request


def test_leaf_preserves_frozen_v1_request_bytes_digest_and_plan():
    path = Path(__file__).parents[1] / "runner/tests/fixtures/s3_access_binding_v1.json"
    corpus = json.loads(path.read_bytes())
    for case in corpus["cases"]:
        source = ordinary.request(case["request"])
        assert canonical_json_bytes(source) == canonical_json_bytes(case["request"])
        assert content_hash(source) == case["request_digest"]
        assert ordinary.operation_plan(source) == [
            (call["service"], call["operation"], call["role"]) for call in case["plan"]
        ]


@pytest.mark.parametrize(
    "operation",
    [
        "inspect_policy",
        "reconcile_policy",
        "apply_policy",
        "rollback_policy",
        "probe_read",
        "legitimate_read",
    ],
)
def test_public_request_class_keeps_ordinary_canonicalization(operation):
    source = request_row(operation)
    request = wire.S3WorkerRequest.from_mapping(source)
    assert type(request) is wire.S3WorkerRequest
    assert request.to_dict() == ordinary.request(source)
    assert request._canonical == canonical_json_bytes(ordinary.request(source))
    assert wire.operation_plan(request) == ordinary.operation_plan(request.to_dict())


@pytest.mark.parametrize("operation", ["prepare_fixture", "reconcile_fixture", "cleanup_fixture"])
def test_fixture_request_and_failed_result_keep_v2_contract(operation):
    request, _ = fixture_request(operation)
    source = request.to_dict()
    assert ordinary.request(source) == source
    assert wire.operation_plan(request) == ordinary.operation_plan(source)
    result = {
        "schema_version": "bluefire.s3-worker-result.v2",
        "request_digest": request.digest,
        "outcome": "failed",
        "data": None,
        "problem": "scoped_operation_failed",
        "send_permits_consumed": 0,
        "calls": [],
        "runtime_isolation_proven": False,
    }
    assert ordinary.validate_result(source, result) == wire.validate_result(request, result)


@pytest.mark.parametrize(
    "updates,message",
    [
        (
            {"operation": "arbitrary", "launch_id": "bad"},
            "worker operation or schema is unsupported",
        ),
        ({"launch_id": "bad", "max_sends": True}, "worker identity is invalid"),
        ({"max_sends": True, "deadline": "bad"}, "worker send allowance is invalid"),
        ({"max_sends": 3, "policy_change": {}}, "worker send allowance is invalid"),
        (
            {"policy_change": {}, "exclusive_writer_digest": "bad"},
            "operation cannot carry policy mutation authority",
        ),
    ],
)
def test_request_refusal_order_is_shared(updates, message):
    source = {**request_row(), **updates}
    for validate in (ordinary.request, wire.S3WorkerRequest.from_mapping):
        with pytest.raises(S3AccessError) as caught:
            validate(source)
        assert str(caught.value) == message


@pytest.mark.parametrize("operation", ["probe_read", "legitimate_read"])
@pytest.mark.parametrize("error", [None, "AccessDenied", "NoSuchKey"])
def test_read_result_and_compatibility_wrapper_use_same_leaf(operation, error):
    request = wire.S3WorkerRequest.from_mapping(request_row(operation))
    result = read_result(request, error)
    source = request.to_dict()
    assert ordinary.validate_result(source, result) == wire.validate_result(request, result)
    checked, checked_source, checked_result = _validated_read(request, result)
    assert type(checked) is wire.S3WorkerRequest
    assert checked._canonical == request._canonical
    assert checked_source == source
    assert checked_result == validated_read(source, result) == result


@pytest.mark.parametrize(
    "updates,message",
    [
        (
            {"request_digest": "bad", "outcome": "bad"},
            "worker result binding or provenance is invalid",
        ),
        ({"outcome": "bad", "calls": None}, "worker result outcome is invalid"),
        ({"send_permits_consumed": True, "calls": None}, "worker result accounting is invalid"),
        ({"send_permits_consumed": 0}, "worker result accounting is invalid"),
    ],
)
def test_result_refusal_order_and_integer_rules_are_shared(updates, message):
    request = wire.S3WorkerRequest.from_mapping(request_row("probe_read"))
    result = {**read_result(request), **updates}
    for validate in (
        lambda: ordinary.validate_result(request.to_dict(), result),
        lambda: wire.validate_result(request, result),
    ):
        with pytest.raises(S3AccessError) as caught:
            validate()
        assert str(caught.value) == message


def test_original_pair_validates_without_importing_public_request_facade(monkeypatch):
    scope = S3AccessScope.from_mapping(request_row()["scope"])
    source = collection_row(scope)["original_pair"]
    expected = deepcopy(source)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("original-pair validation reached the v3 dispatch facade")

    monkeypatch.setattr(wire.S3WorkerRequest, "from_mapping", forbidden)
    assert audit.original_pair(scope, source) == expected


def test_original_pair_still_refuses_non_v1_business_request():
    scope = S3AccessScope.from_mapping(request_row()["scope"])
    source = collection_row(scope)["original_pair"]
    source["reads"][0]["request"]["schema_version"] = "bluefire.s3-worker-request.v3"
    with pytest.raises(S3AccessError, match="audit requires an original business read request"):
        audit.original_pair(scope, source)


def test_wire_safe_constants_remain_identity_reexports():
    assert wire.SAFE_ERROR_CODES is ordinary.SAFE_ERROR_CODES
    assert wire.SAFE_REQUEST_ID is ordinary.SAFE_REQUEST_ID
    assert wire.OPERATIONS is ordinary.OPERATIONS
