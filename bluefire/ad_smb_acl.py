"""Structural single-allow removal using a native Windows descriptor projection.

This is not an SDDL parser or native attestation. The enrolled Windows adapter
must validate the full binary descriptor, bind its complete parsed projection,
and classify each ACE using the native SMB rights contract before effects.
Revoke-SmbShareAccess removes ALL allow ACEs for a trustee, so this recipe
requires exactly one. Controller Full share access does not grant share-control
or Security-log administration; separate observed readiness is required.

https://learn.microsoft.com/en-us/previous-versions/windows/desktop/smb/msft-smbshareaccesscontrolentry
https://learn.microsoft.com/en-us/previous-versions/windows/desktop/smb/revokeaccess-msft-smbshare
https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field
from typing import Any

from .ad_smb_contract import AdSmbError, AdSmbScope, digest, document, exact, sid, timestamp
from .util import canonical_json_bytes, content_hash

MAX_DESCRIPTOR_BYTES = 65536


def descriptor(value: Any) -> dict[str, Any]:
    """Validate a bounded projection, not the native meaning of its binary bytes."""
    row = document(value)
    exact(
        row,
        {"binary_b64", "sha256", "revision", "control", "owner_sid", "group_sid", "dacl", "sacl"},
        "descriptor",
    )
    encoded = row["binary_b64"]
    if not isinstance(encoded, str) or len(encoded) > ((MAX_DESCRIPTOR_BYTES + 2) // 3) * 4:
        raise AdSmbError("descriptor bytes exceed their bound")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise AdSmbError("descriptor encoding is invalid") from None
    if (
        not 20 <= len(raw) <= MAX_DESCRIPTOR_BYTES
        or base64.b64encode(raw).decode("ascii") != encoded
        or digest(row["sha256"]) != "sha256:" + hashlib.sha256(raw).hexdigest()
    ):
        raise AdSmbError("descriptor bytes and digest do not match")
    if (
        type(row["revision"]) is not int
        or row["revision"] != 1
        or type(row["control"]) is not int
        or row["control"] not in (0x8004, 0x9004)
        or row["sacl"] is not None
    ):
        raise AdSmbError("descriptor revision, control flags or SACL are unsupported")
    sid(row["owner_sid"])
    sid(row["group_sid"])
    acl = row["dacl"]
    exact(acl, {"revision", "aces"}, "DACL")
    if (
        type(acl["revision"]) is not int
        or acl["revision"] != 2
        or not isinstance(acl["aces"], list)
        or not 2 <= len(acl["aces"]) <= 3
    ):
        raise AdSmbError("DACL is absent, empty or outside the supported recipe")
    trustees = set()
    for ace in acl["aces"]:
        exact(ace, {"ace_type", "flags", "trustee_sid", "smb_right", "raw_ace_digest"}, "ACE")
        trustee = sid(ace["trustee_sid"])
        digest(ace["raw_ace_digest"])
        if (
            ace["ace_type"] != "access_allowed"
            or type(ace["flags"]) is not int
            or ace["flags"] != 0
            or ace["smb_right"] not in ("Read", "Full")
            or trustee in trustees
        ):
            raise AdSmbError("only unique explicit simple allow ACEs are supported")
        trustees.add(trustee)
    return row


def _bound_descriptor(scope: dict[str, Any], value: Any, *, hardened: bool) -> dict[str, Any]:
    row = descriptor(value)
    expected = {scope["principals"][name]["sid"]: "Read" for name in ("probe", "legitimate")}
    expected[scope["principals"]["controller"]["sid"]] = "Full"
    if hardened:
        del expected[scope["principals"]["probe"]["sid"]]
    if {ace["trustee_sid"]: ace["smb_right"] for ace in row["dacl"]["aces"]} != expected:
        raise AdSmbError("ACL has missing, alternate, group or unsupported access routes")
    if row["owner_sid"] in {scope["principals"][name]["sid"] for name in ("probe", "legitimate")}:
        raise AdSmbError("test readers must not own the security descriptor")
    return row


def snapshot(scope: AdSmbScope, value: Any, *, hardened: bool) -> dict[str, Any]:
    scope = AdSmbScope.from_mapping(scope.to_dict())
    bound = scope.to_dict()
    row = document(value)
    exact(
        row,
        {
            "schema_version",
            "scope_digest",
            "native_parser_digest",
            "source_receipt_digest",
            "observed_at",
            "resource",
            "descriptor",
        },
        "snapshot",
    )
    if (
        row["schema_version"] != "bluefire.ad-smb-snapshot.v1"
        or row["scope_digest"] != scope.digest
        or row["native_parser_digest"] != bound["native_parser_digest"]
    ):
        raise AdSmbError("snapshot does not bind the exact reviewed scope and parser")
    digest(row["source_receipt_digest"])
    observed = timestamp(row["observed_at"])
    if not timestamp(bound["created_at"]) <= observed <= timestamp(bound["expires_at"]):
        raise AdSmbError("snapshot falls outside the scope lifetime")
    row["observed_at"] = observed.isoformat()
    expected_resource = {
        "member_host_id": bound["hosts"]["member"]["host_id"],
        "share": bound["share"],
        "files": bound["files"],
    }
    if canonical_json_bytes(row["resource"]) != canonical_json_bytes(expected_resource):
        raise AdSmbError("share, generated files, NTFS state or target identity has drifted")
    row["descriptor"] = _bound_descriptor(bound, row["descriptor"], hardened=hardened)
    if not hardened and row["descriptor"]["sha256"] != bound["share"]["baseline_descriptor_digest"]:
        raise AdSmbError("baseline descriptor differs from the reviewed preimage")
    return row


def _plan(scope: AdSmbScope, before: Any, proposed_after: Any) -> dict[str, Any]:
    scope = AdSmbScope.from_mapping(scope.to_dict())
    bound = scope.to_dict()
    before = snapshot(scope, before, hardened=False)
    after = _bound_descriptor(bound, proposed_after, hardened=True)
    original = before["descriptor"]
    probe = bound["principals"]["probe"]["sid"]
    expected = {
        **original,
        "dacl": {
            **original["dacl"],
            "aces": [ace for ace in original["dacl"]["aces"] if ace["trustee_sid"] != probe],
        },
    }
    expected["binary_b64"], expected["sha256"] = after["binary_b64"], after["sha256"]
    if after != expected or after["sha256"] == original["sha256"]:
        raise AdSmbError("proposed descriptor is not exactly one explicit probe Read removal")
    removed = next(ace for ace in original["dacl"]["aces"] if ace["trustee_sid"] == probe)
    return {
        "schema_version": "bluefire.ad-smb-acl-change.v1",
        "scope_digest": scope.digest,
        "before": before,
        "after_descriptor": after,
        "removed_ace": removed,
        "before_digest": content_hash(original),
        "after_digest": content_hash(after),
        "native_projection_verified": False,
        "effective_access_claim": False,
    }


@dataclass(frozen=True, slots=True)
class AdSmbAclChange:
    _canonical: bytes = field(repr=False)

    @classmethod
    def from_mapping(cls, scope: AdSmbScope, value: Any) -> "AdSmbAclChange":
        row = document(value)
        exact(
            row,
            {
                "schema_version",
                "scope_digest",
                "before",
                "after_descriptor",
                "removed_ace",
                "before_digest",
                "after_digest",
                "native_projection_verified",
                "effective_access_claim",
            },
            "ACL change",
        )
        expected = _plan(scope, row["before"], row["after_descriptor"])
        if (
            canonical_json_bytes(row) != canonical_json_bytes(expected)
            or row["native_projection_verified"] is not False
            or row["effective_access_claim"] is not False
        ):
            raise AdSmbError("ACL change differs from the exact structural plan")
        return cls(canonical_json_bytes(row))

    def to_dict(self) -> dict[str, Any]:
        return document(self._canonical)

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


def plan_hardening(scope: AdSmbScope, before: Any, proposed_after: Any) -> AdSmbAclChange:
    return AdSmbAclChange.from_mapping(scope, _plan(scope, before, proposed_after))


def verify_readback(scope: AdSmbScope, change: AdSmbAclChange, observed: Any) -> dict[str, Any]:
    plan = AdSmbAclChange.from_mapping(scope, change.to_dict()).to_dict()
    current = snapshot(scope, observed, hardened=True)
    if current["descriptor"] != plan["after_descriptor"] or timestamp(
        current["observed_at"]
    ) < timestamp(plan["before"]["observed_at"]):
        raise AdSmbError("readback is stale or differs from the exact postimage")
    return {
        "structural_review": "exact_postimage",
        "snapshot_digest": content_hash(current),
        "change_digest": content_hash(plan),
        "native_projection_verified": False,
        "effective_access_claim": False,
    }


def plan_rollback(scope: AdSmbScope, change: AdSmbAclChange, current: Any) -> dict[str, Any]:
    verify_readback(scope, change, current)
    plan = AdSmbAclChange.from_mapping(scope, change.to_dict()).to_dict()
    return {
        "schema_version": "bluefire.ad-smb-rollback-plan.v1",
        "scope_digest": scope.digest,
        "change_digest": content_hash(plan),
        "required_postimage_digest": plan["after_digest"],
        "restore_descriptor": plan["before"]["descriptor"],
        "restore_ace": plan["removed_ace"],
        "native_projection_verified": False,
        "effective_access_claim": False,
    }
