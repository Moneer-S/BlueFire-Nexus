"""Synthetic projections use intentionally non-native descriptor bytes.

Passing these tests proves only structural checks. Actual descriptor parsing and
byte/projection authentication belong to the Windows native boundary.
"""

import base64
import copy
import hashlib

import pytest

from bluefire.ad_smb_acl import (
    AdSmbAclChange,
    descriptor,
    plan_hardening,
    plan_rollback,
    verify_readback,
)
from bluefire.ad_smb_contract import AdSmbError, AdSmbScope
from tests_platform.test_ad_smb_contract import DOMAIN, NOW, pin, scope_row


def fixture():
    row = scope_row()
    before = {
        "revision": 1,
        "control": 0x8004,
        "owner_sid": "S-1-5-32-544",
        "group_sid": DOMAIN + "-513",
        "sacl": None,
        "dacl": {
            "revision": 2,
            "aces": [
                {
                    "ace_type": "access_allowed",
                    "flags": 0,
                    "trustee_sid": row["principals"][role]["sid"],
                    "smb_right": "Full" if role == "controller" else "Read",
                    "raw_ace_digest": pin(str(index)),
                }
                for index, role in enumerate(("controller", "probe", "legitimate"), 1)
            ],
        },
    }
    bind_bytes(before, b"SYNTHETIC-BEFORE-NOT-A-NATIVE-DESCRIPTOR")
    row["share"]["baseline_descriptor_digest"] = before["sha256"]
    scope = AdSmbScope.from_mapping(row)
    after = copy.deepcopy(before)
    after["dacl"]["aces"].pop(1)
    bind_bytes(after, b"SYNTHETIC-AFTER-NOT-A-NATIVE-DESCRIPTOR")
    observation = observe(scope, before)
    return scope, observation, after


def bind_bytes(value, raw):
    value["binary_b64"] = base64.b64encode(raw).decode("ascii")
    value["sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()


def observe(scope, parsed):
    row = scope.to_dict()
    return {
        "schema_version": "bluefire.ad-smb-snapshot.v1",
        "scope_digest": scope.digest,
        "native_parser_digest": row["native_parser_digest"],
        "source_receipt_digest": pin("f"),
        "observed_at": NOW.isoformat(),
        "descriptor": copy.deepcopy(parsed),
        "resource": {
            "member_host_id": row["hosts"]["member"]["host_id"],
            "share": row["share"],
            "files": row["files"],
        },
    }


def test_exact_structural_remove_readback_and_guarded_rollback():
    scope, before, after = fixture()
    change = plan_hardening(scope, before, after)
    row = change.to_dict()
    assert row["removed_ace"]["trustee_sid"] == scope.to_dict()["principals"]["probe"]["sid"]
    assert row["native_projection_verified"] is False and row["effective_access_claim"] is False
    assert AdSmbAclChange.from_mapping(scope, row).digest == change.digest
    observed = observe(scope, after)
    assert verify_readback(scope, change, observed)["structural_review"] == "exact_postimage"
    rollback = plan_rollback(scope, change, observed)
    assert rollback["restore_descriptor"] == before["descriptor"]
    assert rollback["restore_ace"] == row["removed_ace"]
    assert rollback["native_projection_verified"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("revision", 2),
        ("revision", True),
        ("control", 0),
        ("control", 0x8014),
        ("owner_sid", "BA"),
        ("group_sid", None),
        ("sacl", {}),
        ("sha256", pin("a")),
        ("binary_b64", "bad!"),
        ("binary_b64", "YQ=="),
    ],
)
def test_descriptor_unknown_null_or_ambiguous_state_refused(field, value):
    _, before, _ = fixture()
    parsed = before["descriptor"]
    parsed[field] = value
    with pytest.raises(AdSmbError):
        descriptor(parsed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("ace_type", "access_denied"),
        ("ace_type", "object_allowed"),
        ("flags", 16),
        ("flags", True),
        ("smb_right", "Change"),
        ("smb_right", "Custom"),
        ("trustee_sid", "Everyone"),
        ("raw_ace_digest", "unknown"),
    ],
)
def test_no_general_acl_semantics(field, value):
    scope, before, after = fixture()
    before["descriptor"]["dacl"]["aces"][1][field] = value
    with pytest.raises(AdSmbError):
        plan_hardening(scope, before, after)


@pytest.mark.parametrize(
    "kind",
    [
        "duplicate_probe",
        "extra_group",
        "group_replace",
        "everyone",
        "probe_owner",
        "null_dacl",
        "empty_dacl",
    ],
)
def test_duplicate_or_alternate_routes_are_not_a_one_allow_recipe(kind):
    scope, before, after = fixture()
    parsed = before["descriptor"]
    if kind == "duplicate_probe":
        parsed["dacl"]["aces"].append(copy.deepcopy(parsed["dacl"]["aces"][1]))
    elif kind == "extra_group":
        parsed["dacl"]["aces"].append({**parsed["dacl"]["aces"][1], "trustee_sid": DOMAIN + "-513"})
    elif kind in {"group_replace", "everyone"}:
        parsed["dacl"]["aces"][1]["trustee_sid"] = (
            DOMAIN + "-513" if kind == "group_replace" else "S-1-1-0"
        )
    elif kind == "probe_owner":
        parsed["owner_sid"] = scope.to_dict()["principals"]["probe"]["sid"]
    else:
        parsed["dacl"] = None if kind == "null_dacl" else {"revision": 2, "aces": []}
    with pytest.raises(AdSmbError):
        plan_hardening(scope, before, after)


@pytest.mark.parametrize(
    "kind",
    [
        "owner",
        "group",
        "control",
        "legitimate",
        "controller",
        "remaining_bytes",
        "reorder",
        "same_bytes",
    ],
)
def test_every_unaffected_descriptor_component_preserved(kind):
    scope, before, after = fixture()
    if kind == "owner":
        after["owner_sid"] = "S-1-5-18"
    elif kind == "group":
        after["group_sid"] = "S-1-5-18"
    elif kind == "control":
        after["control"] = 0x9004
    elif kind == "legitimate":
        after["dacl"]["aces"][1]["smb_right"] = "Full"
    elif kind == "controller":
        after["dacl"]["aces"][0]["smb_right"] = "Read"
    elif kind == "remaining_bytes":
        after["dacl"]["aces"][1]["raw_ace_digest"] = pin("f")
    elif kind == "reorder":
        after["dacl"]["aces"].reverse()
    else:
        after["binary_b64"] = before["descriptor"]["binary_b64"]
        after["sha256"] = before["descriptor"]["sha256"]
    with pytest.raises(AdSmbError):
        plan_hardening(scope, before, after)


@pytest.mark.parametrize("field", ["member_host_id", "share", "files"])
def test_resource_ntfs_file_and_host_drift_refuses_readback_and_rollback(field):
    scope, before, after = fixture()
    change = plan_hardening(scope, before, after)
    current = observe(scope, after)
    if field == "member_host_id":
        current["resource"][field] = pin("e")
    elif field == "share":
        current["resource"][field]["root_ntfs_digest"] = pin("e")
    else:
        current["resource"][field][0]["sha256"] = pin("e")
    for action in (verify_readback, plan_rollback):
        with pytest.raises(AdSmbError):
            action(scope, change, current)


def test_rollback_rejects_structurally_equal_but_different_binary_postimage():
    scope, before, after = fixture()
    change = plan_hardening(scope, before, after)
    bind_bytes(after, b"SYNTHETIC-OTHER-FULL-DESCRIPTOR-BYTES")
    with pytest.raises(AdSmbError):
        plan_rollback(scope, change, observe(scope, after))


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope_digest", pin("0")),
        ("native_parser_digest", pin("0")),
        ("observed_at", "2026-10-08T23:59:59Z"),
        ("source_receipt_digest", None),
    ],
)
def test_snapshot_binding_and_lifetime(field, value):
    scope, before, after = fixture()
    before[field] = value
    with pytest.raises(AdSmbError):
        plan_hardening(scope, before, after)


def test_stale_readback_and_forged_change_claims_refused():
    scope, before, after = fixture()
    before["observed_at"] = "2026-10-09T00:00:10Z"
    change = plan_hardening(scope, before, after)
    with pytest.raises(AdSmbError):
        verify_readback(scope, change, observe(scope, after))
    for field in ("native_projection_verified", "effective_access_claim"):
        row = change.to_dict()
        row[field] = True
        with pytest.raises(AdSmbError):
            AdSmbAclChange.from_mapping(scope, row)
    row = change.to_dict()
    row["removed_ace"]["smb_right"] = "Full"
    with pytest.raises(AdSmbError):
        AdSmbAclChange.from_mapping(scope, row)


def test_byte_bound_and_input_detachment():
    scope, before, after = fixture()
    original = copy.deepcopy((before, after))
    change = plan_hardening(scope, before, after)
    assert (before, after) == original
    before["descriptor"]["owner_sid"] = "S-1-5-18"
    assert change.to_dict()["before"]["descriptor"]["owner_sid"] != "S-1-5-18"
    bind_bytes(after, b"x" * 65537)
    with pytest.raises(AdSmbError):
        descriptor(after)


def test_boolean_integer_alias_does_not_rewrite_snapshot_or_removed_ace():
    scope, before, after = fixture()
    change = plan_hardening(scope, before, after)
    current = observe(scope, after)
    current["resource"]["share"]["dfs"] = 0
    with pytest.raises(AdSmbError):
        verify_readback(scope, change, current)
    row = change.to_dict()
    row["removed_ace"]["flags"] = False
    with pytest.raises(AdSmbError):
        AdSmbAclChange.from_mapping(scope, row)


@pytest.mark.parametrize("place", ["share", "primary", "health", "all"])
def test_volume_only_drift_refuses_baseline_readback_and_rollback(place):
    scope, before, after = fixture()
    change = plan_hardening(scope, before, after)
    current = observe(scope, after)
    for snapshot in (before, current):
        resource = snapshot["resource"]
        targets = {
            "share": resource["share"],
            "primary": resource["files"][0],
            "health": resource["files"][1],
        }
        for name, target in targets.items():
            if place in (name, "all"):
                target["volume_serial"] = "f123456789abcdee"
    with pytest.raises(AdSmbError):
        plan_hardening(scope, before, after)
    for action in (verify_readback, plan_rollback):
        with pytest.raises(AdSmbError):
            action(scope, change, current)
