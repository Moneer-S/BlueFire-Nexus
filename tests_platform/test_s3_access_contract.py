"""Pure scope tests; no credentials, enrollment or AWS requests."""

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from bluefire.s3_access_contract import (
    LIMIT_CEILINGS,
    SCOPE_SCHEMA,
    S3AccessError,
    S3AccessScope,
    document,
)
from bluefire.util import content_hash


def sample_scope():
    suffix = "0" * 32
    prefix = f"bluefire/s3-{suffix}/"
    return {
        "schema_version": SCOPE_SCHEMA,
        "scope_id": "s3-" + suffix,
        "account_id": "123456789012",
        "region": "us-east-1",
        "roles": {
            name: "arn:aws:iam::123456789012:role/bluefire-" + name
            for name in ("controller", "probe", "legitimate")
        },
        "bucket": "bluefire-owned-fixture",
        "prefix": prefix,
        "objects": [
            {
                "purpose": purpose,
                "key": prefix + name,
                "sha256": "sha256:" + digest * 64,
                "size_bytes": 32,
            }
            for purpose, name, digest in (
                ("primary", "records.jsonl", "a"),
                ("health", "health.jsonl", "b"),
            )
        ],
        "policy": {
            "probe_sid": "BlueFireProbe" + suffix,
            "legitimate_sid": "BlueFireLegitimate" + suffix,
            "baseline_digest": "sha256:" + "c" * 64,
        },
        "ownership_receipt_digest": "sha256:" + "d" * 64,
        "created_at": "2026-10-09T00:00:00Z",
        "expires_at": "2026-10-09T01:00:00Z",
        "limits": dict(LIMIT_CEILINGS),
    }


def test_scope_is_immutable_and_has_exact_derived_resources():
    source = sample_scope()
    scope = S3AccessScope.from_mapping(source)
    expected = deepcopy(source)
    source["roles"]["probe"] = "changed"
    projected = scope.to_dict()
    projected["objects"][0]["key"] = "changed"
    assert scope.to_dict() == expected
    assert scope.digest == content_hash(expected)
    assert scope.object_arns == tuple(
        f"arn:aws:s3:::{expected['bucket']}/{obj['key']}" for obj in expected["objects"]
    )
    assert scope.service_hosts == {
        "s3": "s3.us-east-1.amazonaws.com",
        "sts": "sts.us-east-1.amazonaws.com",
        "iam": "iam.amazonaws.com",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "other"),
        ("scope_id", "../../scope"),
        ("account_id", "123"),
        ("region", "us-gov-west-1"),
        ("region", "cn-north-1"),
        ("region", "us-east-1.attacker.example"),
        ("region", "us-east-1/"),
        ("bucket", "other.bucket"),
        ("bucket", "*"),
        ("bucket", "name--x-s3"),
        ("bucket", "xn--bucket"),
        ("bucket", "bucket-s3alias"),
        ("prefix", "outside/"),
        ("objects", []),
        ("objects", None),
        ("limits", {}),
        ("ownership_receipt_digest", "missing"),
        ("created_at", "2026-10-09T00:00:00"),
        ("expires_at", "2026-10-08T00:00:00Z"),
        ("expires_at", "2026-10-10T00:00:00Z"),
    ],
)
def test_scope_rejects_unsupported_fields(field, value):
    source = sample_scope()
    source[field] = value
    with pytest.raises(S3AccessError):
        S3AccessScope.from_mapping(source)


@pytest.mark.parametrize(
    "value",
    [
        "arn:aws:iam::123456789012:root",
        "arn:aws:iam::999999999999:role/probe",
        "arn:aws:sts::123456789012:assumed-role/probe/session",
        "arn:aws:iam::123456789012:role/*",
        "arn:aws:iam::123456789012:role/path/probe",
        "arn:aws-cn:iam::123456789012:role/probe",
    ],
)
def test_scope_rejects_unbound_principals(value):
    source = sample_scope()
    source["roles"]["probe"] = value
    with pytest.raises(S3AccessError):
        S3AccessScope.from_mapping(source)


def test_scope_requires_separate_roles_and_exact_object_identity():
    for mutate in (
        lambda row: row["roles"].update(probe=row["roles"]["legitimate"]),
        lambda row: row["objects"].reverse(),
        lambda row: row["objects"].append(deepcopy(row["objects"][0])),
        lambda row: row["objects"][0].update(size_bytes=True),
        lambda row: row["objects"][0].update(key=row["prefix"] + "other.jsonl"),
        lambda row: row["objects"][0].update(sha256="sha256:" + "G" * 64),
        lambda row: row["objects"][0].update(size_bytes=65536),
        lambda row: row["policy"].update(probe_sid="OtherOwner"),
        lambda row: row.update(credential="NOT-A-CREDENTIAL"),
    ):
        source = sample_scope()
        mutate(source)
        with pytest.raises(S3AccessError):
            S3AccessScope.from_mapping(source)


@pytest.mark.parametrize("name", list(LIMIT_CEILINGS))
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1", 999999999])
def test_every_limit_is_a_bounded_non_boolean_integer(name, value):
    source = sample_scope()
    source["limits"][name] = value
    with pytest.raises(S3AccessError):
        S3AccessScope.from_mapping(source)


def test_session_and_convergence_constraints():
    for limits in ({"session_seconds": 899}, {"business_seconds": 1, "convergence_seconds": 2}):
        source = sample_scope()
        source["limits"].update(limits)
        with pytest.raises(S3AccessError):
            S3AccessScope.from_mapping(source)


def test_expiry_is_timezone_safe_and_clock_is_injected():
    source = sample_scope()
    source["created_at"] = "2026-10-08T19:00:00-05:00"
    source["expires_at"] = "2026-10-08T20:00:00-05:00"
    scope = S3AccessScope.from_mapping(source)
    assert scope.digest == S3AccessScope.from_mapping(sample_scope()).digest
    scope.assert_current(clock=lambda: datetime(2026, 10, 9, 0, 0, tzinfo=timezone.utc))
    for now in (
        datetime(2026, 10, 8, 23, 59, tzinfo=timezone.utc),
        datetime(2026, 10, 9, 1, tzinfo=timezone.utc),
        datetime(2026, 10, 9),
    ):
        with pytest.raises(S3AccessError):
            scope.assert_current(clock=lambda now=now: now)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"a":1,"a":2}',
        b'{"a":{"b":1,"b":2}}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":1e999}',
        b"[]",
        b"\xff",
        b"{",
        {1: "value"},
        {"a": (1, 2)},
        {"a": float("inf")},
        {"a": "x" * 32768},
    ],
)
def test_strict_json_boundary(payload):
    with pytest.raises(S3AccessError):
        document(payload)


def test_mapping_cycles_fail_with_sanitized_error():
    source = {}
    source["loop"] = source
    with pytest.raises(S3AccessError, match="strict bounded JSON"):
        document(source)
