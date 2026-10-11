"""One structural bucket-policy edit; never an IAM effective-access evaluator."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, cast

from .s3_access_contract import (
    MAX_POLICY_BYTES,
    S3AccessError,
    S3AccessScope,
    document,
    exact,
    role_arn,
)
from .util import canonical_json_bytes, content_hash

CHANGE_SCHEMA = "bluefire.s3-access-policy-change.v1"
_SID = re.compile(r"[A-Za-z0-9]{1,128}", re.ASCII)


def _values(value: Any, *, maximum: int) -> list[str]:
    values = [value] if isinstance(value, str) else value
    if (
        not isinstance(values, list)
        or not 1 <= len(values) <= maximum
        or any(not isinstance(item, str) for item in values)
        or len(set(values)) != len(values)
    ):
        raise S3AccessError("policy action or resource shape is unsupported")
    return values


def parse_policy(value: Any) -> dict[str, Any]:
    row = document(value, limit=MAX_POLICY_BYTES)
    exact(row, {"Version", "Statement"}, "bucket policy")
    if (
        row["Version"] != "2012-10-17"
        or not isinstance(row["Statement"], list)
        or not 1 <= len(row["Statement"]) <= 32
    ):
        raise S3AccessError("bucket policy version or statement count is unsupported")
    seen = set()
    for statement in row["Statement"]:
        exact(statement, {"Sid", "Effect", "Principal", "Action", "Resource"}, "bucket statement")
        sid = statement["Sid"]
        if not isinstance(sid, str) or _SID.fullmatch(sid) is None or sid in seen:
            raise S3AccessError("bucket policy statement identity is invalid or duplicate")
        seen.add(sid)
        if statement["Effect"] not in ("Allow", "Deny"):
            raise S3AccessError("bucket policy effect is unsupported")
        principal = exact(statement["Principal"], {"AWS"}, "bucket principal")
        if not isinstance(principal["AWS"], str):
            raise S3AccessError("bucket policy requires one exact role principal")
        if _values(statement["Action"], maximum=1) != ["s3:GetObject"]:
            raise S3AccessError("bucket policy action is unsupported")
        _values(statement["Resource"], maximum=2)
    return row


def _validate(scope: S3AccessScope, policy: Mapping[str, Any], *, hardened: bool) -> None:
    binding = scope.to_dict()
    roles, owned = binding["roles"], binding["policy"]
    primary, health = scope.object_arns
    counts = {"probe": 0, "legitimate": 0}
    routes = set()
    for statement in policy["Statement"]:
        role = role_arn(statement["Principal"]["AWS"], binding["account_id"])
        resources = set(_values(statement["Resource"], maximum=2))
        if not resources <= {primary, health} or role == roles["controller"]:
            raise S3AccessError("bucket statement expands the supported resource or principal set")
        # Duplicate routes with different SIDs still make ownership ambiguous.
        for resource in resources:
            route = (role, resource)
            if route in routes:
                raise S3AccessError("bucket policy contains overlapping role/resource routes")
            routes.add(route)
        if role in (roles["probe"], roles["legitimate"]):
            reader = "probe" if role == roles["probe"] else "legitimate"
            expected_resources = {primary} if reader == "probe" else {primary, health}
            if (
                statement["Sid"] != owned[reader + "_sid"]
                or statement["Effect"] != "Allow"
                or resources != expected_resources
            ):
                raise S3AccessError("reader grant differs from its exact owned statement")
            counts[reader] += 1
        elif statement["Sid"] in (owned["probe_sid"], owned["legitimate_sid"]):
            raise S3AccessError("owned statement identity belongs to another role")
    if counts != {"probe": 0 if hardened else 1, "legitimate": 1}:
        raise S3AccessError("bucket policy lacks the exact independent reader grants")


@dataclass(frozen=True, slots=True)
class S3PolicyChange:
    """Immutable before/after review material, not an execution approval."""

    _canonical: bytes

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    @classmethod
    def from_mapping(cls, scope: S3AccessScope, value: Any) -> S3PolicyChange:
        row = document(value, limit=2 * MAX_POLICY_BYTES + 4096)
        exact(
            row,
            {
                "schema_version",
                "scope_digest",
                "before",
                "before_digest",
                "after",
                "after_digest",
                "removed_sid",
            },
            "policy change",
        )
        expected = plan_hardening(scope, row["before"])
        if row != expected.to_dict():
            raise S3AccessError("saved policy change differs from its exact scope and snapshots")
        return expected


def plan_hardening(scope: S3AccessScope, baseline: Any) -> S3PolicyChange:
    scope = S3AccessScope.from_mapping(scope.to_dict())
    before = parse_policy(baseline)
    _validate(scope, before, hardened=False)
    binding = scope.to_dict()
    if content_hash(before) != binding["policy"]["baseline_digest"]:
        raise S3AccessError("baseline policy drifted from the scope binding")
    sid = binding["policy"]["probe_sid"]
    after = {
        "Version": before["Version"],
        "Statement": [row for row in before["Statement"] if row["Sid"] != sid],
    }
    _validate(scope, after, hardened=True)
    return S3PolicyChange(
        canonical_json_bytes(
            {
                "schema_version": CHANGE_SCHEMA,
                "scope_digest": scope.digest,
                "before": before,
                "before_digest": content_hash(before),
                "after": after,
                "after_digest": content_hash(after),
                "removed_sid": sid,
            }
        )
    )


def verify_readback(scope: S3AccessScope, change: S3PolicyChange, observed: Any) -> str:
    checked = S3PolicyChange.from_mapping(scope, change.to_dict()).to_dict()
    current = parse_policy(observed)
    _validate(scope, current, hardened=True)
    if current != checked["after"] or content_hash(current) != checked["after_digest"]:
        raise S3AccessError("readback differs from the exact reviewed postimage")
    return cast(str, checked["after_digest"])


def plan_rollback(scope: S3AccessScope, change: S3PolicyChange, current: Any) -> dict[str, Any]:
    """Return the original policy only when the complete postimage still matches."""
    verify_readback(scope, change, current)
    return cast(
        dict[str, Any], S3PolicyChange.from_mapping(scope, change.to_dict()).to_dict()["before"]
    )
