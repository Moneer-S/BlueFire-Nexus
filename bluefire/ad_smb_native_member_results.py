"""Closed member-worker output checks, not source authentication or access proof.

Raw captures remain private original evidence. No timestamp, receipt, independent
observation or successful security outcome is invented by this validator.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Mapping

from .ad_smb_acl import AdSmbAclChange, descriptor
from .ad_smb_contract import AdSmbError, AdSmbScope, digest, document, exact, timestamp
from .util import content_hash


def _integer(value: Any, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise AdSmbError("Native member integer is outside its exact bound.")
    return value


def _hex(value: Any, low: int, high: int) -> bytes:
    if (
        not isinstance(value, str)
        or not low <= len(value) <= high
        or len(value) % 2
        or re.fullmatch(r"[0-9a-f]+", value) is None
    ):
        raise AdSmbError("Native member hexadecimal bytes are invalid.")
    return bytes.fromhex(value)


def _share(row: Any, scope: dict[str, Any], *, bound: bool) -> dict[str, Any]:
    exact(row, {"schema_version", "metadata", "current_uses", "descriptor"}, "Native share")
    metadata = row["metadata"]
    exact(
        metadata,
        {
            "name",
            "local_path",
            "share_type",
            "flags",
            "client_cache_flags",
            "encrypt_data_flag",
            "permissions",
            "maximum_uses",
            "remark_digest",
        },
        "Native share metadata",
    )
    for key in ("share_type", "flags", "client_cache_flags", "permissions", "maximum_uses"):
        _integer(metadata[key], 0, 2**32 - 1)
    _integer(row["current_uses"], 0, 2**32 - 1)
    digest(metadata["remark_digest"])
    flags = metadata["flags"]
    if (
        row["schema_version"] != "bluefire.ad-smb-local-share.v1"
        or metadata["name"] != scope["share"]["name"]
        or metadata["local_path"] != scope["share"]["local_root"]
        or metadata["share_type"] != 0
        or flags & 0x4003
        or flags & ~0xBF30
        or metadata["client_cache_flags"] != flags & 0x30
        or type(metadata["encrypt_data_flag"]) is not bool
        or metadata["encrypt_data_flag"] != bool(flags & 0x8000)
        or (
            bound
            and (
                not metadata["encrypt_data_flag"]
                or content_hash(metadata) != scope["share"]["identity_digest"]
            )
        )
    ):
        raise AdSmbError("Native share metadata differs from its fixed original binding.")
    return descriptor(row["descriptor"])


def _security(value: Any, *, finite: bool) -> str:
    exact(
        value,
        {"security_information", "binary_hex", "sha256", "finite_descriptor", "sacl_observed"},
        "Selected native security",
    )
    raw = _hex(value["binary_hex"], 40, 131072)
    if (
        type(value["security_information"]) is not int
        or value["security_information"] != 7
        or value["sacl_observed"] is not False
        or digest(value["sha256"]) != "sha256:" + hashlib.sha256(raw).hexdigest()
        or (value["finite_descriptor"] is not None) != finite
    ):
        raise AdSmbError("Selected native security bytes or scope are invalid.")
    if finite:
        parsed = descriptor(value["finite_descriptor"])
        if (
            base64.b64decode(parsed["binary_b64"], validate=True) != raw
            or parsed["sha256"] != value["sha256"]
        ):
            raise AdSmbError("Selected native descriptor projection differs from its bytes.")
    return digest(value["sha256"])


def _files(row: Any, scope: dict[str, Any]) -> None:
    exact(row, {"observation", "issue", "owned_handles_closed"}, "Native files attempt")
    if row["issue"] is not None or row["owned_handles_closed"] is not True:
        raise AdSmbError("Native inspection did not finish its owned handles.")
    observed = row["observation"]
    exact(
        observed,
        {
            "schema_version",
            "share_name",
            "local_path",
            "objects",
            "files",
            "selected_facts_unchanged",
            "authenticated_member_identity",
            "effective_access_proved",
        },
        "Native files observation",
    )
    root = scope["share"]["local_root"]
    if (
        observed["schema_version"] != "bluefire.ad-smb-local-files.v1"
        or observed["share_name"] != scope["share"]["name"]
        or observed["local_path"] != root
        or observed["selected_facts_unchanged"] is not True
        or observed["authenticated_member_identity"] is not False
        or observed["effective_access_proved"] is not False
        or not isinstance(observed["objects"], list)
        or len(observed["objects"]) != 6
        or not isinstance(observed["files"], list)
        or len(observed["files"]) != 2
    ):
        raise AdSmbError("Native inspection has an invalid observation or extra proof.")
    paths = [root[:2] + "\\", root[:2] + "\\BlueFire", root[:2] + "\\BlueFire\\AD", root]
    paths += [root + "\\" + item["name"] for item in scope["files"]]
    identities = set()
    for index, obj in enumerate(observed["objects"]):
        exact(
            obj,
            {
                "final_path",
                "volume_serial",
                "file_id",
                "directory",
                "size",
                "links",
                "attributes",
                "reparse_tag",
                "creation_time",
                "last_write_time",
                "change_time",
                "ntfs",
                "disk_file",
                "delete_pending",
                "selected_security",
            },
            "Native object",
        )
        _hex(obj["volume_serial"], 16, 16)
        identity = _hex(obj["file_id"], 32, 32)
        _integer(obj["size"], 0, 2**64 - 1)
        for field in ("links", "attributes", "reparse_tag"):
            _integer(obj[field], 0, 2**32 - 1)
        for field in ("creation_time", "last_write_time", "change_time"):
            _integer(obj[field], -(2**63), 2**63 - 1)
        if (
            obj["final_path"] != "\\\\?\\" + paths[index]
            or obj["volume_serial"] != scope["share"]["volume_serial"]
            or not any(identity)
            or identity in identities
            or obj["directory"] is not (index < 4)
            or obj["ntfs"] is not True
            or obj["disk_file"] is not True
            or obj["delete_pending"] is not False
            or obj["reparse_tag"] != 0
            or obj["attributes"] & 0x1400
            or bool(obj["attributes"] & 0x10) != (index < 4)
            or (index >= 4 and (obj["links"] != 1 or not 1 <= obj["size"] <= 65536))
        ):
            raise AdSmbError("Native held object differs from the fixed non-reparse recipe.")
        identities.add(identity)
        security_digest = _security(obj["selected_security"], finite=index >= 3)
        if index == 3 and (
            obj["file_id"] != scope["share"]["root_file_id"]
            or security_digest != scope["share"]["root_ntfs_digest"]
        ):
            raise AdSmbError("Native root identity or selected security changed.")
        if index >= 4:
            expected = scope["files"][index - 4]
            if (
                obj["file_id"] != expected["file_id"]
                or obj["size"] != expected["size_bytes"]
                or security_digest != expected["ntfs_digest"]
            ):
                raise AdSmbError("Native file identity, size or selected security changed.")
    for row, expected in zip(observed["files"], scope["files"], strict=True):
        exact(row, {"name", "bytes", "sha256"}, "Native file digest")
        _integer(row["bytes"], 1, 65536)
        if row != {
            "name": expected["name"],
            "bytes": expected["size_bytes"],
            "sha256": expected["sha256"],
        }:
            raise AdSmbError("Native file content differs from the exact generated target.")


def _inspect(row: dict[str, Any], scope: dict[str, Any]) -> None:
    exact(row, {"share", "files", "after_descriptor"}, "Native inspection")
    before = _share(row["share"], scope, bound=True)
    after = descriptor(row["after_descriptor"])
    roles = {scope["principals"][name]["sid"]: "Read" for name in ("probe", "legitimate")}
    roles[scope["principals"]["controller"]["sid"]] = "Full"
    probe = scope["principals"]["probe"]["sid"]
    if (
        before["sha256"] != scope["share"]["baseline_descriptor_digest"]
        or {ace["trustee_sid"]: ace["smb_right"] for ace in before["dacl"]["aces"]} != roles
        or before["owner_sid"]
        in {scope["principals"][name]["sid"] for name in ("probe", "legitimate")}
    ):
        raise AdSmbError("Native inspection does not bind the original baseline descriptor.")
    expected = {
        **before,
        "binary_b64": after["binary_b64"],
        "sha256": after["sha256"],
        "dacl": {
            **before["dacl"],
            "aces": [ace for ace in before["dacl"]["aces"] if ace["trustee_sid"] != probe],
        },
    }
    if after != expected or after["sha256"] == before["sha256"]:
        raise AdSmbError("Native descriptor proposal changed more than the one probe allow.")
    _files(row["files"], scope)


def _write(row: dict[str, Any], request: Mapping[str, Any], scope: AdSmbScope) -> None:
    exact(
        row, {"state", "write_attempted", "set_status", "readback", "issue"}, "Native share write"
    )
    if type(row["write_attempted"]) is not bool:
        raise AdSmbError("Native write attempt flag is invalid.")
    if row["set_status"] is not None:
        _integer(row["set_status"], 0, 2**32 - 1)
    readback = None
    if row["readback"] is not None:
        readback = _share(row["readback"], scope.to_dict(), bound=False)
    if row["state"] == "not_attempted":
        if (
            row["write_attempted"]
            or row["set_status"] is not None
            or row["issue"]
            not in {"original_deadline_expired", "preimage_unavailable", "preimage_changed"}
            or (row["issue"] == "preimage_unavailable" and readback is not None)
            or (row["issue"] == "preimage_changed" and readback is None)
        ):
            raise AdSmbError("Native unattempted write contradicts its observations.")
    elif row["state"] == "readback_matched":
        change = AdSmbAclChange.from_mapping(scope, request["change"]).to_dict()
        desired = (
            change["before"]["descriptor"]
            if request["phase"] == "rollback"
            else change["after_descriptor"]
        )
        if (
            not row["write_attempted"]
            or row["set_status"] != 0
            or row["issue"] is not None
            or readback != desired
        ):
            raise AdSmbError("Native matched write lacks its exact reviewed readback.")
        _share(row["readback"], scope.to_dict(), bound=True)
    elif row["state"] == "unknown":
        if (
            not row["write_attempted"]
            or row["set_status"] is None
            or row["issue"]
            not in {
                "original_deadline_expired_after_write",
                "set_response_failed_state_unknown",
                "exact_readback_unavailable",
            }
            or (row["issue"] == "original_deadline_expired_after_write" and readback is not None)
            or (row["issue"] == "set_response_failed_state_unknown" and row["set_status"] == 0)
            or (row["issue"] == "exact_readback_unavailable" and row["set_status"] != 0)
        ):
            raise AdSmbError("Native unknown write has inconsistent attempt facts.")
    else:
        raise AdSmbError("Native share write state is invalid.")


def _audit(
    row: dict[str, Any], request: Mapping[str, Any], scope: dict[str, Any], byte_limit: int
) -> None:
    _integer(byte_limit, 1, scope["limits"]["audit_bytes"])
    exact(
        row,
        {
            "schema_version",
            "channel",
            "window_start",
            "window_end",
            "state",
            "raw_events",
            "utf8_bytes",
            "system_error",
            "handles_closed",
            "log_continuity_verified",
            "authenticated_source_claim",
            "independent_evidence_claim",
            "effective_access_claim",
        },
        "Native audit capture",
    )

    def utc(value: str) -> str:
        instant = timestamp(value)
        return instant.strftime("%Y-%m-%dT%H:%M:%S.") + f"{instant.microsecond:06d}0Z"

    if (
        row["schema_version"] != "bluefire.ad-smb-native-audit-capture.v1"
        or row["channel"] != "Security"
        or row["window_start"] != utc(scope["created_at"])
        or row["window_end"] != utc(request["requested_at"])
        or row["state"]
        not in {
            "query_exhausted",
            "event_limit",
            "byte_limit",
            "event_rejected",
            "deadline",
            "cancelled",
            "read_failed",
            "cleanup_unknown",
        }
        or type(row["handles_closed"]) is not bool
        or (row["state"] == "cleanup_unknown") != (not row["handles_closed"])
        or any(
            row[key] is not False
            for key in (
                "log_continuity_verified",
                "authenticated_source_claim",
                "independent_evidence_claim",
                "effective_access_claim",
            )
        )
        or not isinstance(row["raw_events"], list)
        or len(row["raw_events"]) > scope["limits"]["audit_events"]
    ):
        raise AdSmbError("Native audit capture has invalid bounds or extra evidence claims.")
    total = 0
    for event in row["raw_events"]:
        if (
            not isinstance(event, str)
            or "\0" in event
            or not 1 <= len(event.encode("utf-8")) <= 65536
        ):
            raise AdSmbError("Native audit event exceeds its finite capture bound.")
        total += len(event.encode("utf-8"))
    _integer(row["utf8_bytes"], 0, byte_limit)
    if total != row["utf8_bytes"]:
        raise AdSmbError("Native audit byte accounting differs from its retained events.")
    if row["system_error"] is not None:
        _integer(row["system_error"], 0, 2**32 - 1)
        capped = row["system_error"] == 122 and row["state"] in {"byte_limit", "event_rejected"}
        if not capped and row["state"] not in {"deadline", "read_failed", "cleanup_unknown"}:
            raise AdSmbError("Native audit system error contradicts its capture state.")
    if (
        (
            row["state"] == "event_limit"
            and len(row["raw_events"]) != scope["limits"]["audit_events"]
        )
        or (row["state"] == "read_failed" and row["system_error"] is None)
        or (
            row["state"] == "query_exhausted"
            and (len(row["raw_events"]) >= scope["limits"]["audit_events"] or total >= byte_limit)
        )
    ):
        raise AdSmbError("Native audit completion contradicts its finite counters.")


def validate_native_member(
    request: Mapping[str, Any], value: Mapping[str, Any], *, audit_byte_limit: int | None = None
) -> None:
    """Check exact native schemas before receiver completion; unknown stays unknown."""
    try:
        scope = AdSmbScope.from_mapping(request["scope"])
        row = document(value, limit=4 * 1024 * 1024 + 65536)
        if request["step"] == "inspect_member":
            _inspect(row, scope.to_dict())
        elif request["step"] in {"harden_share", "rollback_share"}:
            _write(row, request, scope)
        elif request["step"] == "collect_audit":
            if audit_byte_limit is None:
                raise AdSmbError("Native audit capture requires its derived receiver allowance.")
            _audit(row, request, scope.to_dict(), audit_byte_limit)
        else:
            raise AdSmbError("Native member operation is unsupported.")
    except (KeyError, TypeError, ValueError, OverflowError, UnicodeError):
        raise AdSmbError(
            "Native member result is invalid or differs from its original binding."
        ) from None
