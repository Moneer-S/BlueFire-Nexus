"""Private pure native-reader JSON/original-reservation contract.

Hashes establish consistency only. Expected bindings and original monotonic
deadlines are separate trusted-admission premises. A terminal proves neither
its source nor owned-process closure; historical parsing never enables replay.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from .execution_contracts import execution_task_identity
from .util import canonical_json_bytes, content_hash

PUBLIC_MAX, READY_MAX, TERMINAL_MAX, BEGIN_MAX = 65536, 1024, 8192, 2048
REQUEST_SCHEMA = "bluefire.windows-file-worker-request.v1"
READY_SCHEMA = "bluefire.windows-file-worker-ready.v1"
RESULT_SCHEMA = "bluefire.windows-file-worker-result.v1"
ERROR_SCHEMA = "bluefire.windows-file-worker-error.v1"
PROOF_SCHEMA = "bluefire.windows-fixed-read.v1"
ACTION, CAPABILITY = "private.windows.file_read.v1", "windows_file_read"
EXPECTED = "operation_job_id generation control_revision credential_binding_digest host resource"
ERROR_CODES = frozenset(
    "request_invalid begin_invalid begin_consumed deadline cancelled native_failed output_failed result_bound_exceeded".split()
)
ISSUES = frozenset(
    "credential_generation_mismatch cleanup_unknown cancelled deadline effective_token_drift resource_identity_or_metadata_mismatch controller_identity_mismatch reader_identity_mismatch controller_token_drift effective_reader_mismatch data_handle_mismatch read_length_mismatch read_eof_mismatch read_digest_mismatch data_metadata_drift resource_drift held_metadata_drift held_descriptor_drift selected_descriptor_mismatch windows_required native_failure native_response_invalid thread_changed preexisting_impersonation_refused owned_impersonation_missing descriptor_cleanup_unknown duplicate_logon_refused fixed_local_drive_required ordinary_object_required acl_capable_ntfs_required token_snapshot_drift".split()
)
STAGES = frozenset(
    "credential cleanup complete context caller logon impersonate metadata read recheck descriptor token_close metadata_open data_open volume final_path token token_privileges".split()
)


@dataclass(frozen=True, slots=True)
class _Protocol:
    version: int
    action: str
    capability: str
    operation: str
    behavior: str
    proof: str

    def schema(self, kind: str) -> str:
        _require(kind in ("request", "ready", "result", "error", "operation"))
        return f"bluefire.windows-file-worker-{kind}.v{self.version}"

    @property
    def magic(self) -> bytes:
        return b"BFWFBEG1" if self is _V1 else b"BFWFBEG2"


_V1 = _Protocol(
    1, ACTION, CAPABILITY, "read_generated", "identity.windows.file_read.v1", PROOF_SCHEMA
)
_PAIR = _Protocol(
    2,
    "private.windows.file_read_pair.v2",
    "windows_file_read_pair",
    "read_generated_pair",
    "identity.windows.file_read_pair.v2",
    "bluefire.windows-fixed-read-pair.v2",
)


def _protocol(value: _Protocol) -> _Protocol:
    _require(value is _V1 or value is _PAIR)
    return value


class NativeWireError(ValueError):
    """A bounded, path-free refusal, never an access or authentication claim."""


def _require(value: bool) -> None:
    if not value:
        raise NativeWireError("Native reader wire refused")


def _exact(value: Any, keys: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == set(keys.split()))
    return cast(dict[str, Any], value)


def _same(left: Any, right: Any) -> bool:
    return canonical_json_bytes(left) == canonical_json_bytes(right)


def _int(value: Any, low: int, high: int) -> int:
    _require(type(value) is int and low <= value <= high)
    return cast(int, value)


def _hex(value: Any, size: int) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value) is not None)
    return cast(str, value)


def _digest(value: Any) -> str:
    _require(type(value) is str and value.startswith("sha256:"))
    _hex(value[7:], 64)
    return cast(str, value)


def _identifier(value: Any) -> None:
    _require(
        type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is not None
    )


def _walk(value: Any, depth: int = 0) -> None:
    _require(depth <= 64)
    if type(value) is dict:
        _require(len(value) <= 32 and all(type(k) is str for k in value))
        for child in value.values():
            _walk(child, depth + 1)
    elif type(value) is list:
        _require(len(value) <= 16)
        for child in value:
            _walk(child, depth + 1)
    elif type(value) is int:
        _int(value, -(2**63), 2**64 - 1)
    else:
        _require(value is None or type(value) in (str, bool))


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in items:
        _require(key not in value)
        value[key] = child
    return value


def _bad_number(_: str) -> None:
    raise NativeWireError("Native reader JSON number refused")


def _document(value: Any, limit: int = PUBLIC_MAX) -> dict[str, Any]:
    try:
        if type(value) is bytes:
            _require(0 < len(value) <= limit)
            _require(not value.startswith(b"\xef\xbb\xbf"))
            value = json.loads(
                value.decode("utf-8", errors="strict"),
                object_pairs_hook=_pairs,
                parse_float=_bad_number,
                parse_constant=_bad_number,
            )
        _require(type(value) is dict)
        _walk(value)
        raw = canonical_json_bytes(value)
        _require(0 < len(raw) <= limit)
        return cast(dict[str, Any], json.loads(raw))
    except (UnicodeError, RecursionError, TypeError, ValueError):
        raise NativeWireError("Native reader document refused") from None


def _time(value: Any, canonical: bool = False) -> datetime:
    _require(type(value) is str and len(value) <= 40 and value.isascii())
    match = re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(?:[Zz]|[+-]\d{2}:\d{2})", value
    )
    if match is None:
        raise NativeWireError("Native reader wire refused")
    fraction = match.group(1) or ""
    _require(len(fraction) <= 6 or set(fraction[6:]) <= {"0"})
    try:
        parsed = datetime.fromisoformat(
            value.replace("t", "T").replace("z", "Z").replace("Z", "+00:00")
        )
    except ValueError:
        raise NativeWireError("Native reader timestamp refused") from None
    if canonical:
        _require(
            value.endswith("Z")
            and parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") == value
        )
    return parsed


def _clock(value: Any) -> datetime:
    _require(type(value) is datetime and value.utcoffset() is not None)
    return cast(datetime, value)


def _mono(value: Any) -> float:
    _require(type(value) in (int, float) and 0 <= value <= 2**53 and math.isfinite(value))
    return float(value)


def _resource(row: Any) -> None:
    _exact(row, "owner_sid reader_sid ancestors file_identity size_bytes sha256 state")
    accounts = []
    for name in ("owner_sid", "reader_sid"):
        value = row[name]
        _require(
            type(value) is str
            and re.fullmatch(r"S-1-5-21-(?:[1-9][0-9]{0,9}-){3}[1-9][0-9]{0,9}", value) is not None
        )
        numbers = tuple(int(part) for part in value[9:].split("-"))
        _require(
            len(numbers) == 4 and all(0 < n <= 0xFFFFFFFF for n in numbers) and numbers[3] >= 1000
        )
        accounts.append(numbers)
    _require(accounts[0][:3] == accounts[1][:3] and accounts[0] != accounts[1])
    _require(type(row["ancestors"]) is list and len(row["ancestors"]) == 4)
    identities = []
    for identity in row["ancestors"] + [row["file_identity"]]:
        _exact(identity, "volume_serial file_id")
        identities.append((_hex(identity["volume_serial"], 16), _hex(identity["file_id"], 32)))
        _require(identity["file_id"] != "0" * 32)
    _require(len(set(identities)) == 5 and len({v for v, _ in identities}) == 1)
    _int(row["size_bytes"], 1, 1048576)
    _digest(row["sha256"])
    _require(row["state"] in ("readable", "metadata_only"))


def _original(
    context: Any, expected: Any, *, protocol: _Protocol = _V1
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = _protocol(protocol)
    context, expected = _document(context), _document(expected)
    _exact(context, "manifest profile task_id transport_request_hash")
    _exact(expected, EXPECTED)
    manifest, profile = context["manifest"], context["profile"]
    _exact(
        profile,
        "schema_version profile_id runner_id platform sandbox_root allowed_actions control_blocked_actions capabilities max_safety_tier approval_required_at_or_above target_scope limits policy_digest",
    )
    _exact(
        manifest,
        "schema_version request_id run_id step_id behavior_id action_id mode runner_id runner_profile_id platform requested_at expires_at params target_scope required_capabilities safety_tier limits cleanup_action_id policy_digest approval evidence_refs request_hash",
    )
    _exact(manifest["params"], "windows_file_read_request")
    request = _exact(
        manifest["params"]["windows_file_read_request"], "schema_version request_id " + EXPECTED
    )
    _require(request["schema_version"] == protocol.schema("operation"))
    _require(_same({key: request[key] for key in EXPECTED.split()}, expected))
    generation = _hex(request["generation"], 32)
    _int(request["control_revision"], 1, 2**31 - 1)
    _digest(request["credential_binding_digest"])
    host = _exact(
        request["host"], "runner_profile_id profile_digest native_generation host_id channel_digest"
    )
    _resource(request["resource"])
    if protocol is _PAIR:
        _require(request["resource"]["state"] == "readable")
    _identifier(profile["profile_id"])
    _require(
        host["runner_profile_id"] == profile["profile_id"]
        and host["profile_digest"] == profile["policy_digest"]
    )
    for name in ("profile_digest", "native_generation", "host_id", "channel_digest"):
        _digest(host[name])
    _require(
        profile["schema_version"] == "bluefire.runner-profile.v1"
        and profile["runner_id"] == "bluefire-rust-runner.v1"
        and profile["platform"] == "windows"
    )
    _require(profile["sandbox_root"] == f"C:\\BlueFire\\EndpointAccess\\{generation}")
    _require(
        profile["allowed_actions"] == [protocol.action]
        and profile["control_blocked_actions"] == []
        and profile["capabilities"] == [protocol.capability]
    )
    _require(
        profile["max_safety_tier"] == "controlled"
        and profile["approval_required_at_or_above"] == "safe"
        and profile["target_scope"] == {"filesystem": [], "network": []}
    )
    limits = _exact(
        profile["limits"],
        "timeout_ms max_stdout_bytes max_stderr_bytes max_artifact_bytes max_files",
    )
    for key, low, high in (
        ("timeout_ms", 1, 5000),
        ("max_stdout_bytes", 1024, 8192),
        ("max_stderr_bytes", 1, 1024),
        ("max_artifact_bytes", 1, 1),
        ("max_files", 1, 1),
    ):
        _int(limits[key], low, high)
    unsealed = dict(profile, policy_digest="")
    _require(profile["policy_digest"] == content_hash(unsealed))
    job = request["operation_job_id"]
    _require(type(job) is str and job.startswith("job-"))
    _hex(job[4:], 32)
    request_id = hashlib.sha256(f"{job}:{protocol.operation}".encode("ascii")).hexdigest()[:32]
    _require(
        request["request_id"] == request_id
        and manifest["request_id"] == f"win-read-{request_id}"
        and manifest["run_id"] == job
    )
    _require(
        manifest["schema_version"] == "bluefire.runner-manifest.v1"
        and manifest["step_id"] == protocol.operation
        and manifest["behavior_id"] == protocol.behavior
        and manifest["action_id"] == protocol.action
        and manifest["mode"] == "execute"
    )
    for key, profile_key in (
        ("runner_id", "runner_id"),
        ("runner_profile_id", "profile_id"),
        ("platform", "platform"),
        ("target_scope", "target_scope"),
        ("required_capabilities", "capabilities"),
        ("limits", "limits"),
        ("policy_digest", "policy_digest"),
    ):
        _require(_same(manifest[key], profile[profile_key]))
    _require(
        manifest["safety_tier"] == "controlled"
        and manifest["cleanup_action_id"] is None
        and manifest["evidence_refs"] == []
    )
    requested, expires = _time(manifest["requested_at"]), _time(manifest["expires_at"])
    _require(0 < (expires - requested).total_seconds() <= 5)
    approval = _exact(manifest["approval"], "approved_by approved_at expires_at request_hash")
    _identifier(approval["approved_by"])
    _require(
        approval["approved_at"] == manifest["requested_at"]
        and approval["expires_at"] == manifest["expires_at"]
        and approval["request_hash"] == manifest["request_hash"]
    )
    unsealed = dict(manifest, request_hash="", approval=dict(approval, request_hash=""))
    _require(manifest["request_hash"] == content_hash(unsealed))
    task, transport = execution_task_identity(manifest, profile)
    _require(context["task_id"] == task and context["transport_request_hash"] == transport)
    return context, expected
