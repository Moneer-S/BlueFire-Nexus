"""Synthetic native-shaped records, not Windows observations or authenticated proof."""

import base64
import hashlib
import json
from copy import deepcopy
from datetime import timedelta
from pathlib import Path

import pytest

from bluefire.ad_smb_acl import plan_hardening
from bluefire.ad_smb_contract import AdSmbError, AdSmbScope
from bluefire.ad_smb_native_member_results import validate_native_member as validate_member
from bluefire.util import content_hash
from tests_platform.test_ad_smb_acl import fixture as acl_fixture
from tests_platform.test_ad_smb_acl import observe
from tests_platform.test_ad_smb_contract import NOW, pin


def validate_native_member(request, value):
    validate_member(request, value, audit_byte_limit=request["scope"]["limits"]["audit_bytes"])


def fixture():
    scope, before, after = acl_fixture()
    row = scope.to_dict()
    metadata = {
        "name": row["share"]["name"],
        "local_path": row["share"]["local_root"],
        "share_type": 0,
        "flags": 0x8030,
        "client_cache_flags": 0x30,
        "encrypt_data_flag": True,
        "permissions": 0,
        "maximum_uses": 2**32 - 1,
        "remark_digest": pin("f"),
    }
    parsed = before["descriptor"]
    row["share"]["identity_digest"] = content_hash(metadata)
    row["share"]["root_ntfs_digest"] = parsed["sha256"]
    for item in row["files"]:
        item["ntfs_digest"] = parsed["sha256"]
    scope = AdSmbScope.from_mapping(row)
    request = {
        "scope": scope.to_dict(),
        "step": "inspect_member",
        "phase": "inspect",
        "requested_at": (NOW + timedelta(seconds=1)).isoformat(),
        "change": plan_hardening(scope, observe(scope, parsed), after).to_dict(),
    }
    root = row["share"]["local_root"]
    paths = [root[:2] + "\\", root[:2] + "\\BlueFire", root[:2] + "\\BlueFire\\AD", root]
    paths += [root + "\\" + item["name"] for item in row["files"]]
    objects = []
    for index, path in enumerate(paths):
        identity = (
            row["share"]["root_file_id"]
            if index == 3
            else row["files"][index - 4]["file_id"] if index >= 4 else f"{index + 100:032x}"
        )
        objects.append(
            {
                "final_path": "\\\\?\\" + path,
                "volume_serial": row["share"]["volume_serial"],
                "file_id": identity,
                "directory": index < 4,
                "size": 0 if index < 4 else row["files"][index - 4]["size_bytes"],
                "links": 1,
                "attributes": 0x10 if index < 4 else 0x20,
                "reparse_tag": 0,
                "creation_time": 1,
                "last_write_time": 1,
                "change_time": 1,
                "ntfs": True,
                "disk_file": True,
                "delete_pending": False,
                "selected_security": {
                    "security_information": 7,
                    "binary_hex": base64.b64decode(parsed["binary_b64"]).hex(),
                    "sha256": parsed["sha256"],
                    "finite_descriptor": deepcopy(parsed) if index >= 3 else None,
                    "sacl_observed": False,
                },
            }
        )
    result = {
        "share": {
            "schema_version": "bluefire.ad-smb-local-share.v1",
            "metadata": metadata,
            "current_uses": 0,
            "descriptor": deepcopy(parsed),
        },
        "files": {
            "observation": {
                "schema_version": "bluefire.ad-smb-local-files.v1",
                "share_name": row["share"]["name"],
                "local_path": root,
                "objects": objects,
                "files": [
                    {"name": item["name"], "bytes": item["size_bytes"], "sha256": item["sha256"]}
                    for item in row["files"]
                ],
                "selected_facts_unchanged": True,
                "authenticated_member_identity": False,
                "effective_access_proved": False,
            },
            "issue": None,
            "owned_handles_closed": True,
        },
        "after_descriptor": after,
    }
    return request, result


def test_exact_synthetic_inspection_validates_without_altering_evidence():
    request, result = fixture()
    before = deepcopy(result)
    validate_native_member(request, result)
    assert result == before


def test_retained_windows_generated_descriptor_pair_in_member_projection():
    # Emitted by the Windows descriptor integration test, not a live share.
    # The surrounding member/file observation remains deliberately synthetic.
    raw = (Path(__file__).parent / "fixtures" / "ad_smb_native_descriptor.json").read_bytes()
    assert (
        hashlib.sha256(raw).hexdigest()
        == "4681f67fb8a5469e8f896574dc5ba1dac6bdb60b4d0786a4401742983f4fb032"
    )
    native = json.loads(raw)
    assert native["authenticated_share_claim"] is False
    request, result = fixture()
    row = request["scope"]
    row["domain"]["sid"] = "S-1-5-21-101-202-303"
    for index, role in enumerate(("probe", "legitimate", "controller"), 1):
        row["principals"][role]["sid"] = row["domain"]["sid"] + f"-{1000 + index}"
        row["principals"][role]["group_sids"] = [row["domain"]["sid"] + "-513"]
    row["share"]["baseline_descriptor_digest"] = native["before"]["sha256"]
    row["share"]["root_ntfs_digest"] = native["before"]["sha256"]
    for item in row["files"]:
        item["ntfs_digest"] = native["before"]["sha256"]
    scope = AdSmbScope.from_mapping(row)
    request["scope"] = scope.to_dict()
    request["change"] = plan_hardening(
        scope, observe(scope, native["before"]), native["after"]
    ).to_dict()
    result["share"]["descriptor"] = native["before"]
    result["after_descriptor"] = native["after"]
    for index, obj in enumerate(result["files"]["observation"]["objects"]):
        obj["selected_security"].update(
            binary_hex=base64.b64decode(native["before"]["binary_b64"]).hex(),
            sha256=native["before"]["sha256"],
            finite_descriptor=native["before"] if index >= 3 else None,
        )
    validate_native_member(request, result)


@pytest.mark.parametrize(
    "path,bad",
    [
        (("share", "metadata", "maximum_uses"), True),
        (("share", "metadata", "flags"), 0x30),
        (("share", "metadata", "client_cache_flags"), 0x2030),
        (("share", "metadata", "remark_digest"), pin("e")),
        (("share", "current_uses"), -1),
        (("files", "owned_handles_closed"), False),
        (("files", "observation", "authenticated_member_identity"), True),
        (("files", "observation", "effective_access_proved"), True),
        (("files", "observation", "selected_facts_unchanged"), False),
        (("files", "observation", "objects", 0, "final_path"), "C:\\foreign"),
        (("files", "observation", "objects", 0, "volume_serial"), "f" * 16),
        (("files", "observation", "objects", 3, "file_id"), "f" * 32),
        (("files", "observation", "objects", 4, "attributes"), 0x400),
        (("files", "observation", "objects", 4, "links"), 2),
        (("files", "observation", "objects", 4, "size"), 2**64),
        (("files", "observation", "objects", 4, "creation_time"), 2**63),
        (("files", "observation", "objects", 3, "selected_security", "sacl_observed"), True),
        (("files", "observation", "objects", 3, "selected_security", "binary_hex"), "00" * 20),
        (("files", "observation", "objects", 3, "selected_security", "finite_descriptor"), None),
        (("files", "observation", "files", 0, "sha256"), pin("e")),
        (("after_descriptor", "owner_sid"), "S-1-5-18"),
    ],
)
def test_inspection_refuses_scope_drift_or_unsupported_proof(path, bad):
    request, result = fixture()
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = bad
    with pytest.raises(AdSmbError):
        validate_native_member(request, result)


@pytest.mark.parametrize("phase", ["harden", "rollback"])
def test_matched_write_requires_exact_direction_and_preserved_metadata(phase):
    request, inspect = fixture()
    request.update(phase=phase, step=f"{phase}_share")
    share = inspect["share"]
    if phase == "harden":
        share["descriptor"] = inspect["after_descriptor"]
    result = {
        "state": "readback_matched",
        "write_attempted": True,
        "set_status": 0,
        "readback": share,
        "issue": None,
    }
    validate_native_member(request, result)
    result["readback"]["metadata"]["maximum_uses"] -= 1
    with pytest.raises(AdSmbError):
        validate_native_member(request, result)


@pytest.mark.parametrize(
    "state,attempt,status,issue",
    [
        ("not_attempted", False, None, "preimage_unavailable"),
        ("unknown", True, 5, "set_response_failed_state_unknown"),
        ("unknown", True, 0, "original_deadline_expired_after_write"),
        ("unknown", True, 0, "exact_readback_unavailable"),
    ],
)
def test_negative_write_states_remain_original_negative_observations(state, attempt, status, issue):
    request, _ = fixture()
    request.update(phase="harden", step="harden_share")
    result = {
        "state": state,
        "write_attempted": attempt,
        "set_status": status,
        "readback": None,
        "issue": issue,
    }
    before = deepcopy(result)
    validate_native_member(request, result)
    assert result == before
    result["write_attempted"] = not attempt
    with pytest.raises(AdSmbError):
        validate_native_member(request, result)


def audit_fixture():
    request, _ = fixture()
    request.update(step="collect_audit", phase="audit")
    return request, {
        "schema_version": "bluefire.ad-smb-native-audit-capture.v1",
        "channel": "Security",
        "window_start": "2026-10-09T00:00:00.0000000Z",
        "window_end": "2026-10-09T00:00:01.0000000Z",
        "state": "query_exhausted",
        "raw_events": ["<Event>SYNTHETIC</Event>"],
        "utf8_bytes": 24,
        "system_error": None,
        "handles_closed": True,
        "log_continuity_verified": False,
        "authenticated_source_claim": False,
        "independent_evidence_claim": False,
        "effective_access_claim": False,
    }


def test_original_audit_capture_is_not_normalized_or_certified_as_events():
    request, result = audit_fixture()
    result["utf8_bytes"] = len(result["raw_events"][0].encode())
    before = deepcopy(result)
    validate_native_member(request, result)
    assert result == before


@pytest.mark.parametrize(
    "key,bad",
    [
        ("schema_version", "unknown"),
        ("channel", "Application"),
        ("window_end", "2026-10-09T00:00:02.0000000Z"),
        ("utf8_bytes", True),
        ("utf8_bytes", 1),
        ("handles_closed", False),
        ("authenticated_source_claim", True),
        ("effective_access_claim", True),
        ("independent_evidence_claim", True),
        ("log_continuity_verified", True),
        ("raw_events", ["x" * 65537]),
        ("raw_events", ["a\0b"]),
        ("system_error", 5),
        ("state", "read_failed"),
    ],
)
def test_audit_refuses_wrong_scope_accounting_and_extra_claims(key, bad):
    request, result = audit_fixture()
    result["utf8_bytes"] = len(result["raw_events"][0].encode())
    result[key] = bad
    with pytest.raises(AdSmbError):
        validate_native_member(request, result)


@pytest.mark.parametrize(
    "state", ["deadline", "cancelled", "event_rejected", "byte_limit", "cleanup_unknown"]
)
def test_partial_audit_is_retained_as_partial(state):
    request, result = audit_fixture()
    result["utf8_bytes"] = len(result["raw_events"][0].encode())
    result["state"] = state
    result["handles_closed"] = state != "cleanup_unknown"
    validate_native_member(request, result)
    assert result["state"] == state and result["independent_evidence_claim"] is False


@pytest.mark.parametrize("state", ["byte_limit", "event_rejected"])
def test_native_insufficient_buffer_retains_exact_partial_capture(state):
    request, result = audit_fixture()
    result.update(state=state, system_error=122, raw_events=["<Event/>"], utf8_bytes=8)
    validate_native_member(request, result)
    assert result["system_error"] == 122 and result["raw_events"] == ["<Event/>"]
    result["system_error"] = 5
    with pytest.raises(AdSmbError):
        validate_native_member(request, result)
