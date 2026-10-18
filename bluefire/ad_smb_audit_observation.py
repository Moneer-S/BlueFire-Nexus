"""Validation for bounded normalized AD audit observations."""

from __future__ import annotations

import re
from datetime import timezone
from typing import Any, Mapping

from .ad_smb_contract import AdSmbError, AdSmbScope, digest, exact, timestamp
from .util import content_hash

SCHEMA = "bluefire.ad-smb-audit-observation.v2"
_COMPLETENESS = {
    "query_exhausted": "complete",
    "event_limit": "truncated",
    "byte_limit": "truncated",
    "event_rejected": "incomplete",
    "deadline": "incomplete",
    "cancelled": "incomplete",
    "read_failed": "incomplete",
    "cleanup_unknown": "unknown",
}
_LIMITATIONS = [
    "Source receipts and completeness are caller assertions until an enrolled collector verifies them.",
    "A 5145 success is a share access check, not proof of a successful NTFS read or returned bytes.",
    "A 5145 failure describes share-level denial; missing events cannot establish NTFS denial or prevention.",
    "A matching server logon does not bind an execution attempt or prove a newly created client session.",
]


def _uint64_decimal(value: Any) -> int | None:
    if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]{0,19}", value) is None:
        return None
    number = int(value)
    return number if number < 2**64 else None


def _audit_utc(value: str) -> str:
    instant = timestamp(value).astimezone(timezone.utc)
    return instant.strftime("%Y-%m-%dT%H:%M:%S.") + f"{instant.microsecond:06d}0Z"


def _event_time(value: str) -> tuple[str, int]:
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z", value)
    if match is None:
        raise AdSmbError("Normalized AD event time is not exact UTC Windows time.")
    fraction = match[2] or ""
    if any(char != "0" for char in fraction[7:]):
        raise AdSmbError("Normalized AD event time exceeds Windows 100ns precision.")
    timestamp(match[1] + "Z")
    return match[1], int(fraction[:7].ljust(7, "0"))


def _validate_event(
    row: Any, scope: AdSmbScope, start: tuple[str, int], end: tuple[str, int]
) -> int:
    if not isinstance(row, dict):
        raise AdSmbError("Normalized AD audit event is invalid.")
    common = {
        "event_id",
        "version",
        "record_id",
        "computer",
        "observed_at",
        "audit_outcome",
        "raw_sha256",
        "binding",
    }
    optional = {
        "logon_id",
        "principal_role",
        "principal_sid",
        "client_ip",
        "logon_type",
        "authentication_package",
        "kerberos_network_logon",
        "file_purpose",
        "relative_target",
        "access_mask",
        "requests_file_data",
        "share_check",
        "server_logon",
        "logon_record_id",
    }
    if not common <= set(row) <= common | optional:
        raise AdSmbError("Normalized AD audit event fields are unsupported.")
    bound = scope.to_dict()
    record_id = _uint64_decimal(row["record_id"])
    if (
        type(row["event_id"]) is not int
        or row["event_id"] not in (4624, 5145)
        or type(row["version"]) is not int
        or row["version"] not in ((0, 1, 2) if row["event_id"] == 4624 else (0,))
        or record_id is None
        or not isinstance(row["computer"], str)
        or len(row["computer"]) > 8192
        or row["computer"].casefold() != bound["hosts"]["member"]["fqdn"].casefold()
        or not isinstance(row["observed_at"], str)
        or not isinstance(row["audit_outcome"], str)
        or row["audit_outcome"] not in {"success", "failure", "unknown"}
        or not isinstance(row["binding"], str)
        or row["binding"] not in {"matched", "incomplete", "outside_scope"}
    ):
        raise AdSmbError("Normalized AD audit event identity is invalid.")
    observed = _event_time(row["observed_at"])
    if not start <= observed <= end:
        raise AdSmbError("Normalized AD event time is outside the captured window.")
    digest(row["raw_sha256"])
    if "logon_id" in row:
        logon_id = row["logon_id"]
        if (
            not isinstance(logon_id, str)
            or re.fullmatch(r"0x[0-9a-f]{1,16}", logon_id) is None
            or (int(logon_id, 16) == 0 and (logon_id != "0x0" or row["binding"] == "matched"))
        ):
            raise AdSmbError("Normalized AD audit logon identity is invalid.")
    matched = row["binding"] == "matched"
    if not matched and not set(row) <= common | {"logon_id"}:
        raise AdSmbError("Unmatched AD audit event exposes projected identity fields.")
    if matched:
        if not {"principal_role", "principal_sid", "client_ip", "logon_id"} <= set(row):
            raise AdSmbError("Matched AD audit event lost its scoped identity.")
        role = row["principal_role"]
        if (
            not isinstance(role, str)
            or role not in {"probe", "legitimate"}
            or row["principal_sid"] != bound["principals"][role]["sid"]
            or row["client_ip"] != bound["hosts"]["client"]["ipv4"]
        ):
            raise AdSmbError("Matched AD audit event differs from the scoped principal or client.")
    if row["event_id"] == 4624:
        expected = common | {
            "logon_id",
            "principal_role",
            "principal_sid",
            "client_ip",
            "logon_type",
            "authentication_package",
            "kerberos_network_logon",
        }
        if matched and set(row) != expected:
            raise AdSmbError("Matched AD logon event fields are incomplete.")
        share_fields = {
            "file_purpose",
            "relative_target",
            "access_mask",
            "requests_file_data",
            "share_check",
            "server_logon",
            "logon_record_id",
        }
        if share_fields & set(row):
            raise AdSmbError("Normalized AD logon event contains share-only fields.")
        if matched and (
            type(row["logon_type"]) is not int
            or not 0 <= row["logon_type"] < 2**32
            or not isinstance(row["authentication_package"], str)
            or row["authentication_package"] not in {"Kerberos", "NTLM", "Negotiate", "other"}
            or type(row["kerberos_network_logon"]) is not bool
            or row["kerberos_network_logon"]
            != (
                row["logon_type"] == 3
                and row["authentication_package"] == "Kerberos"
                and row["audit_outcome"] == "success"
            )
        ):
            raise AdSmbError("Normalized AD logon details are invalid.")
    else:
        expected = common | {
            "logon_id",
            "principal_role",
            "principal_sid",
            "client_ip",
            "file_purpose",
            "relative_target",
            "access_mask",
            "requests_file_data",
            "share_check",
            "server_logon",
        }
        if matched and set(row) not in (expected, expected | {"logon_record_id"}):
            raise AdSmbError("Matched AD share event fields are incomplete.")
        if {"logon_type", "authentication_package", "kerberos_network_logon"} & set(row):
            raise AdSmbError("Normalized AD share event contains logon-only fields.")
        if matched:
            targets = {entry["name"].casefold(): entry for entry in bound["files"]}
            target = targets.get(str(row.get("relative_target", "")).casefold())
            mask = row.get("access_mask")
            if (
                target is None
                or row.get("file_purpose") != target["purpose"]
                or not isinstance(mask, str)
                or re.fullmatch(r"0x[0-9a-f]{1,8}", mask) is None
                or type(row.get("requests_file_data")) is not bool
                or row["requests_file_data"] != bool(int(mask, 16) & 1)
                or not isinstance(row.get("share_check"), str)
                or row.get("share_check") not in {"granted", "denied", "unknown"}
                or row["share_check"]
                != {"success": "granted", "failure": "denied"}.get(row["audit_outcome"], "unknown")
                or not isinstance(row.get("server_logon"), str)
                or row.get("server_logon")
                not in {"missing", "ambiguous", "kerberos_network", "not_verified_kerberos"}
            ):
                raise AdSmbError("Normalized AD share event details are invalid.")
    if "logon_record_id" in row and (
        row["server_logon"] not in {"kerberos_network", "not_verified_kerberos"}
        or _uint64_decimal(row["logon_record_id"]) is None
    ):
        raise AdSmbError("Normalized AD server-logon reference is invalid.")
    return record_id


def validate_normalized_audit(
    request: Mapping[str, Any], scope: AdSmbScope, summary: Mapping[str, Any]
) -> None:
    normalized = summary["normalized_observation"]
    fields = {
        "schema_version",
        "scope_digest",
        "source_host_id",
        "source_receipt_digest",
        "capture_batch_digest",
        "window_start",
        "window_end",
        "reported_completeness",
        "source_authenticity_verified",
        "log_continuity_verified",
        "independent_observation",
        "effective_access_claim",
        "fresh_session_claim",
        "file_content_read_claim",
        "input_events",
        "input_bytes",
        "duplicate_events",
        "events",
        "limitations",
        "capture_state",
    }
    exact(normalized, fields, "Normalized AD audit observation")
    bound = scope.to_dict()
    state = normalized["capture_state"]
    if (
        normalized["schema_version"] != SCHEMA
        or normalized["scope_digest"] != scope.digest
        or normalized["source_host_id"] != bound["hosts"]["member"]["host_id"]
        or normalized["window_start"] != _audit_utc(bound["created_at"])
        or normalized["window_end"] != _audit_utc(request["requested_at"])
        or not isinstance(state, str)
        or state not in _COMPLETENESS
        or normalized["reported_completeness"] != _COMPLETENESS[state]
        or any(
            normalized[key] is not False
            for key in (
                "source_authenticity_verified",
                "log_continuity_verified",
                "independent_observation",
                "effective_access_claim",
                "fresh_session_claim",
                "file_content_read_claim",
            )
        )
        or type(normalized["input_events"]) is not int
        or not 0 <= normalized["input_events"] <= bound["limits"]["audit_events"]
        or type(normalized["input_bytes"]) is not int
        or not normalized["input_events"]
        <= normalized["input_bytes"]
        <= bound["limits"]["audit_bytes"]
        or type(normalized["duplicate_events"]) is not int
        or type(summary["events"]) is not int
        or not isinstance(normalized["events"], list)
        or len(normalized["events"]) > normalized["input_events"]
        or normalized["duplicate_events"] != normalized["input_events"] - len(normalized["events"])
        or summary["events"] != normalized["input_events"]
        or summary["truncated"] is not (state != "query_exhausted")
    ):
        raise AdSmbError("Normalized AD audit bounds or claims are inconsistent.")
    start = _event_time(normalized["window_start"])
    end = _event_time(normalized["window_end"])
    if start >= end:
        raise AdSmbError("Normalized AD audit window is empty or reversed.")
    # The original receipt is absent from this saved summary; this digest is not authenticated here.
    digest(normalized["source_receipt_digest"])
    digest(normalized["capture_batch_digest"])
    if normalized["capture_batch_digest"] != content_hash(
        {
            "source_receipt_digest": normalized["source_receipt_digest"],
            "channel": "Security",
            "window_start": normalized["window_start"],
            "window_end": normalized["window_end"],
        }
    ):
        raise AdSmbError("Normalized AD audit batch identity is inconsistent.")
    if normalized["limitations"] != _LIMITATIONS:
        raise AdSmbError("Normalized AD audit limitations are incomplete.")
    rows = normalized["events"]
    ids = [_validate_event(row, scope, start, end) for row in rows]
    if len(ids) != len(set(ids)):
        raise AdSmbError("Normalized AD audit contains duplicate record identities.")
    for row in rows:
        if row["event_id"] != 5145 or row["binding"] != "matched":
            continue
        candidates = [
            entry
            for entry in rows
            if entry["event_id"] == 4624 and entry.get("logon_id") == row["logon_id"]
        ]
        expected, expected_record = "missing", None
        if candidates:
            expected = "ambiguous"
        if len(candidates) == 1:
            logon = candidates[0]
            if (
                logon["binding"] == "matched"
                and logon["principal_sid"] == row["principal_sid"]
                and _event_time(logon["observed_at"]) <= _event_time(row["observed_at"])
                and int(logon["record_id"]) < int(row["record_id"])
            ):
                expected = (
                    "kerberos_network"
                    if logon["kerberos_network_logon"]
                    else "not_verified_kerberos"
                )
                expected_record = logon["record_id"]
        if row["server_logon"] != expected or row.get("logon_record_id") != expected_record:
            raise AdSmbError("Normalized AD server-logon correlation is inconsistent.")
