"""Structural policy tests do not contact AWS or simulate IAM decisions."""

from copy import deepcopy

import pytest

from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_policy import (
    S3PolicyChange,
    parse_policy,
    plan_hardening,
    plan_rollback,
    verify_readback,
)
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_contract import sample_scope


def fixture():
    source = sample_scope()
    primary, health = S3AccessScope.from_mapping(source).object_arns
    statements = [
        {
            "Sid": "PreservedRead",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:role/unrelated-reader"},
            "Action": ["s3:GetObject"],
            "Resource": [health],
        },
        {
            "Sid": source["policy"]["probe_sid"],
            "Effect": "Allow",
            "Principal": {"AWS": source["roles"]["probe"]},
            "Action": "s3:GetObject",
            "Resource": primary,
        },
        {
            "Sid": source["policy"]["legitimate_sid"],
            "Effect": "Allow",
            "Principal": {"AWS": source["roles"]["legitimate"]},
            "Action": "s3:GetObject",
            "Resource": [primary, health],
        },
        {
            "Sid": "PreservedDeny",
            "Effect": "Deny",
            "Principal": {"AWS": "arn:aws:iam::123456789012:role/unrelated-denied"},
            "Action": "s3:GetObject",
            "Resource": primary,
        },
    ]
    policy = {"Version": "2012-10-17", "Statement": statements}
    source["policy"]["baseline_digest"] = content_hash(policy)
    return S3AccessScope.from_mapping(source), policy


def bind(scope, policy):
    source = scope.to_dict()
    source["policy"]["baseline_digest"] = content_hash(policy)
    return S3AccessScope.from_mapping(source)


def test_change_removes_only_probe_preserving_order_and_statement_shapes():
    scope, before = fixture()
    original = deepcopy(before)
    change = plan_hardening(scope, before)
    row = change.to_dict()
    assert before == original
    assert row["before"] == original
    assert row["after"] == {
        "Version": "2012-10-17",
        "Statement": [original["Statement"][i] for i in (0, 2, 3)],
    }
    assert row["before_digest"] == scope.to_dict()["policy"]["baseline_digest"]
    assert row["after_digest"] == content_hash(row["after"])
    assert row["scope_digest"] == scope.digest
    assert verify_readback(scope, change, canonical_json_bytes(row["after"])) == row["after_digest"]
    assert plan_rollback(scope, change, row["after"]) == original
    before["Statement"].clear()
    row["after"]["Statement"].clear()
    assert change.to_dict()["before"] == original
    assert S3PolicyChange.from_mapping(scope, change.to_dict()).digest == change.digest


@pytest.mark.parametrize(
    "field,value",
    [
        ("Condition", {}),
        ("NotAction", "s3:PutObject"),
        ("NotPrincipal", {"AWS": "*"}),
        ("Principal", "*"),
        ("Principal", {"AWS": "*"}),
        ("Principal", {"AWS": ["arn:aws:iam::123456789012:role/probe"]}),
        ("Principal", {"Service": "s3.amazonaws.com"}),
        ("Principal", {"AWS": "arn:aws:iam::123456789012:root"}),
        ("Action", "s3:*"),
        ("Action", ["s3:GetObject", "s3:PutObject"]),
        ("Action", ["s3:GetObject", "s3:GetObject"]),
        ("Action", []),
        ("Resource", "*"),
        ("Resource", "arn:aws:s3:::bluefire-owned-fixture/*"),
        ("Resource", "arn:aws:s3:::another-bucket/key"),
        ("Resource", []),
        ("Resource", {"unexpected": "value"}),
        ("Effect", "Deny"),
        ("Sid", "OtherProbe"),
    ],
)
def test_probe_unsupported_or_ambiguous_shape_is_refused(field, value):
    scope, policy = fixture()
    policy["Statement"][1][field] = value
    with pytest.raises(S3AccessError):
        plan_hardening(bind(scope, policy), policy)


def test_no_duplicate_keys_even_in_nested_principal():
    scope, policy = fixture()
    payload = canonical_json_bytes(policy).replace(b'"AWS":', b'"AWS":"*","AWS":', 1)
    with pytest.raises(S3AccessError, match="duplicate JSON keys"):
        plan_hardening(scope, payload)


def test_public_cross_account_controller_and_foreign_owned_sid_are_refused():
    scope, original = fixture()
    for role in (
        "*",
        "arn:aws:iam::111111111111:role/outside",
        scope.to_dict()["roles"]["controller"],
        "arn:aws:iam::123456789012:user/user",
    ):
        policy = deepcopy(original)
        policy["Statement"][0]["Principal"]["AWS"] = role
        with pytest.raises(S3AccessError):
            plan_hardening(bind(scope, policy), policy)
    policy = deepcopy(original)
    policy["Statement"][1]["Principal"]["AWS"] = "arn:aws:iam::123456789012:role/unrelated"
    with pytest.raises(S3AccessError):
        plan_hardening(bind(scope, policy), policy)


def test_duplicate_sid_and_overlapping_routes_are_refused():
    scope, original = fixture()
    for sid in (original["Statement"][1]["Sid"], "AnotherProbeGrant"):
        policy = deepcopy(original)
        duplicate = deepcopy(policy["Statement"][1])
        duplicate["Sid"] = sid
        policy["Statement"].append(duplicate)
        with pytest.raises(S3AccessError):
            plan_hardening(bind(scope, policy), policy)


def test_legitimate_reader_must_cover_both_exact_objects():
    scope, original = fixture()
    primary, health = scope.object_arns
    for resources in (primary, health, [primary, primary]):
        policy = deepcopy(original)
        policy["Statement"][2]["Resource"] = resources
        with pytest.raises(S3AccessError):
            plan_hardening(bind(scope, policy), policy)
    policy = deepcopy(original)
    policy["Statement"][1]["Resource"] = [primary, health]
    with pytest.raises(S3AccessError):
        plan_hardening(bind(scope, policy), policy)


def test_missing_grants_or_prior_hardening_are_not_reinterpreted():
    scope, original = fixture()
    for index in (1, 2):
        policy = deepcopy(original)
        policy["Statement"].pop(index)
        with pytest.raises(S3AccessError):
            plan_hardening(bind(scope, policy), policy)


def test_baseline_drift_is_refused_without_writing_source():
    scope, policy = fixture()
    policy["Statement"][0]["Sid"] = "Changed"
    retained = deepcopy(policy)
    with pytest.raises(S3AccessError, match="baseline policy drifted"):
        plan_hardening(scope, policy)
    assert policy == retained


@pytest.mark.parametrize("mutation", ["statement", "order", "shape", "missing", "restored"])
def test_readback_and_rollback_refuse_any_postimage_drift(mutation):
    scope, before = fixture()
    change = plan_hardening(scope, before)
    current = change.to_dict()["after"]
    if mutation == "statement":
        current["Statement"][0]["Sid"] = "Changed"
    elif mutation == "order":
        current["Statement"].reverse()
    elif mutation == "shape":
        current["Statement"][0]["Action"] = "s3:GetObject"
    elif mutation == "missing":
        current["Statement"].pop()
    else:
        current = before
    for call in (verify_readback, plan_rollback):
        with pytest.raises(S3AccessError):
            call(scope, change, current)


def test_saved_plan_tampering_and_cross_scope_reuse_are_refused():
    scope, before = fixture()
    change = plan_hardening(scope, before)
    for field in ("scope_digest", "before_digest", "after_digest", "removed_sid", "schema_version"):
        changed = change.to_dict()
        changed[field] = "changed"
        with pytest.raises(S3AccessError):
            S3PolicyChange.from_mapping(scope, changed)
    changed = change.to_dict()
    changed["after"]["Statement"].pop()
    changed["after_digest"] = content_hash(changed["after"])
    with pytest.raises(S3AccessError):
        S3PolicyChange.from_mapping(scope, changed)
    other = scope.to_dict()
    other["region"] = "eu-west-1"
    with pytest.raises(S3AccessError):
        verify_readback(S3AccessScope.from_mapping(other), change, change.to_dict()["after"])


@pytest.mark.parametrize(
    "value",
    [
        {"Version": "2008-10-17", "Statement": []},
        {"Version": "2012-10-17", "Statement": {}},
        {"Version": "2012-10-17", "Statement": [], "Id": "extra"},
    ],
)
def test_unsupported_policy_envelopes(value):
    with pytest.raises(S3AccessError):
        parse_policy(value)
