"""Closed AD worker messages; parsing binds bytes, never authenticates a host."""

from __future__ import annotations

import hashlib
import re
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from .ad_smb_acl import AdSmbAclChange
from .ad_smb_channel import AdSmbHostChannel
from .ad_smb_contract import (
    AdSmbError,
    AdSmbReadTarget,
    AdSmbScope,
    digest,
    document,
    exact,
    timestamp,
)
from .ad_smb_results import PHASES, job_id, original_context, phase_deadline, reviewer
from .util import canonical_json_bytes, content_hash

PUBLIC_MAX = 1024 * 1024
READY_MAX = 4096
BEGIN_MAX = 2048
TERMINAL_MAX = 4 * 1024 * 1024 + 65536
RECEIVER_RESULT_MAX = 4 * 1024 * 1024 - 4096
RESULT_WRAPPER_RESERVE = 1024
AUDIT_METADATA_RESERVE = 2048
LIMIT_KEYS = {
    "timeout_ms",
    "max_stdout_bytes",
    "max_stderr_bytes",
    "max_artifact_bytes",
    "max_files",
}
ERROR_CODES = {
    "request_invalid",
    "begin_invalid",
    "deadline",
    "native_unavailable",
    "precondition_failed",
    "native_failed",
    "result_bound_exceeded",
}


def hex_value(value: Any, length: int) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is None:
        raise AdSmbError("AD worker identity is invalid.")
    return value


def frame(payload: bytes | bytearray, maximum: int) -> bytearray:
    if not 0 < len(payload) <= maximum:
        raise AdSmbError("AD worker frame exceeds its bound.")
    return bytearray(struct.pack("<I", len(payload))) + payload


@dataclass(frozen=True)
class WorkerPacket:
    _raw: bytes = field(repr=False)
    prepared_monotonic: float = field(default_factory=time.monotonic, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return document(self._raw, limit=PUBLIC_MAX)

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    @property
    def request(self) -> dict[str, Any]:
        result: dict[str, Any] = self.to_dict()["manifest"]["params"]["ad_smb_request"]
        return result

    @property
    def output_limit(self) -> int:
        public = self.to_dict()
        return min(
            int(public["manifest"]["limits"]["max_stdout_bytes"]),
            RECEIVER_RESULT_MAX - len(canonical_json_bytes(public)) - RESULT_WRAPPER_RESERVE,
        )

    @property
    def audit_byte_limit(self) -> int:
        limits = self.request["scope"]["limits"]
        remaining = self.output_limit - AUDIT_METADATA_RESERVE - 3 * limits["audit_events"]
        if remaining < 6:
            raise AdSmbError("AD worker output allowance cannot retain bounded audit evidence.")
        # Any UTF-8 byte expands at most sixfold as JSON; each array element
        # reserves its two quotes and separator. Native uses the same bound.
        result: int = min(limits["audit_bytes"], remaining // 6)
        return result

    def public_frame(self) -> bytearray:
        return frame(self._raw, PUBLIC_MAX)


def prepare_packet(
    context: Mapping[str, Any],
    channel: AdSmbHostChannel,
    *,
    challenge: str,
    credential_binding_digest: str | None,
    expected_upn_sha256: str | None,
    prior_local_authentication_ids: list[str],
    clock: datetime,
) -> WorkerPacket:
    """Revalidate a saved original task; its durable admission remains the caller's duty."""
    prepared = time.monotonic()
    try:
        source = document(context, limit=PUBLIC_MAX)
        request = source["manifest"]["params"]["ad_smb_request"]
        exact(
            request,
            {
                "schema_version",
                "request_id",
                "workflow_job_id",
                "operation_job_id",
                "index",
                "phase",
                "step",
                "scope",
                "scope_digest",
                "target",
                "requested_at",
                "deadline",
                "environment_digest",
                "host",
                "principal_binding_digest",
                "review_digest",
                "reviewed_by",
                "change",
            },
            "AD original request",
        )
        checked = original_context(request, source)
        scope = AdSmbScope.from_mapping(request["scope"])
        scope_row = scope.to_dict()
        selected = AdSmbHostChannel.from_mapping(scope, channel.to_dict())
        selected.assert_current(clock)
        bound = selected.to_dict()
        reading = request["step"].startswith("read_")
        role = "client" if reading else "member"
        phase = request["phase"]
        index = request["index"]
        job_id(request["workflow_job_id"])
        job_id(request["operation_job_id"])
        reviewer(request["reviewed_by"])
        for key in ("environment_digest", "principal_binding_digest", "review_digest"):
            digest(request[key])
        digest(request["host"]["native_generation"])
        start, end = timestamp(request["requested_at"]), timestamp(request["deadline"])
        if (
            request["schema_version"] != "bluefire.ad-smb-step.v1"
            or request["request_id"]
            != hashlib.sha256(f"{request['operation_job_id']}:{index}".encode()).hexdigest()[:32]
            or type(index) is not int
            or phase not in PHASES
            or not 0 <= index < len(PHASES[phase])
            or PHASES[phase][index] != request["step"]
            or request["scope_digest"] != scope.digest
            or request["scope"] != scope_row
            or bound["role"] != role
            or request["host"]["host_id"] != bound["host_id"]
            or request["host"]["channel_digest"] != selected.digest
            or checked["profile"]["policy_digest"] != bound["profile_digest"]
            or checked["profile"]["profile_id"] != bound["profile_id"]
            or not timestamp(scope_row["created_at"])
            <= start
            <= clock
            < end
            <= phase_deadline(scope, phase)
            or (end - start).total_seconds() > scope_row["limits"]["operation_seconds"]
        ):
            raise AdSmbError("AD worker original admission differs from its channel.")
        if phase in {"harden", "retest", "rollback"}:
            AdSmbAclChange.from_mapping(scope, request["change"])
        elif request["change"] is not None:
            raise AdSmbError("AD original phase cannot carry a share change.")
        if phase == "audit" and start <= timestamp(scope_row["created_at"]):
            raise AdSmbError("AD audit requires the nonempty original observation interval.")
        expected_target = None
        if reading:
            _, reader, purpose = request["step"].split("_")
            expected_target = AdSmbReadTarget.from_scope(
                scope, reader=reader, purpose=purpose
            ).to_dict()
            digest(credential_binding_digest)
            digest(expected_upn_sha256)
            if credential_binding_digest != request["principal_binding_digest"]:
                raise AdSmbError(
                    "AD reader credential binding differs from the original environment."
                )
        elif credential_binding_digest is not None or expected_upn_sha256 is not None:
            raise AdSmbError("Member operations cannot carry reader credentials.")
        if request["target"] != expected_target:
            raise AdSmbError("AD worker target differs from the exact scoped file.")
        if (
            type(prior_local_authentication_ids) is not list
            or len(prior_local_authentication_ids) > 5
            or len(set(prior_local_authentication_ids)) != len(prior_local_authentication_ids)
            or (not reading and prior_local_authentication_ids)
        ):
            raise AdSmbError("AD worker prior local contexts are invalid.")
        for value in prior_local_authentication_ids:
            hex_value(value, 16)
            if value == "0" * 16:
                raise AdSmbError("AD prior local authentication identity is invalid.")
        ceilings = {
            "timeout_ms": scope_row["limits"]["operation_seconds"] * 1000,
            "max_stdout_bytes": TERMINAL_MAX,
            "max_stderr_bytes": 65536,
            "max_artifact_bytes": scope_row["limits"]["returned_payload_bytes"],
            "max_files": 2,
        }
        limits = checked["manifest"]["limits"]
        profile_limits = checked["profile"]["limits"]
        exact(limits, LIMIT_KEYS, "AD manifest limits")
        exact(profile_limits, LIMIT_KEYS, "AD profile limits")
        for key, ceiling in ceilings.items():
            if (
                type(limits[key]) is not int
                or type(profile_limits[key]) is not int
                or not 0 < limits[key] <= profile_limits[key] <= ceiling
            ):
                raise AdSmbError("AD worker limits exceed the finite enrolled scope.")
        delta = end - clock
        milliseconds = (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000
        remaining = min(limits["timeout_ms"], milliseconds)
        if not 1 <= remaining <= 60000:
            raise AdSmbError("AD worker original deadline has elapsed.")
        row = {
            "schema_version": "bluefire.ad-smb-worker-request.v1",
            "challenge": hex_value(challenge, 64),
            "task_id": checked["task_id"],
            "request_hash": checked["transport_request_hash"],
            "manifest": checked["manifest"],
            "profile": checked["profile"],
            "channel_digest": selected.digest,
            "host_role": role,
            "host_id": bound["host_id"],
            "client_identity_digest": scope_row["hosts"]["client"]["identity_receipt_digest"],
            "credential_binding_digest": credential_binding_digest,
            "expected_upn_sha256": expected_upn_sha256,
            "prior_local_authentication_ids": list(prior_local_authentication_ids),
            "remaining_ms": remaining,
        }
        return WorkerPacket(canonical_json_bytes(document(row, limit=PUBLIC_MAX)), prepared)
    except (KeyError, IndexError, TypeError, OverflowError):
        raise AdSmbError("AD worker original admission is incomplete.") from None


def ready(packet: WorkerPacket, raw: bytes, pid: int) -> None:
    row = document(raw, limit=READY_MAX)
    expected = {
        "schema_version": "bluefire.ad-smb-worker-ready.v1",
        "challenge": packet.to_dict()["challenge"],
        "packet_digest": packet.digest,
        "task_id": packet.to_dict()["task_id"],
        "request_hash": packet.to_dict()["request_hash"],
        "pid": pid,
    }
    if type(row.get("pid")) is not int or not 0 < pid < 2**32 or row != expected:
        raise AdSmbError("AD worker readiness did not match the owned process.")


def terminal(packet: WorkerPacket, raw: bytes) -> dict[str, Any]:
    row = document(raw, limit=min(TERMINAL_MAX, packet.output_limit))
    exact(
        row,
        {
            "schema_version",
            "challenge",
            "packet_digest",
            "task_id",
            "request_hash",
            "operation",
            "result",
        },
        "AD worker terminal",
    )
    public = packet.to_dict()
    if (
        row["schema_version"] != "bluefire.ad-smb-worker-result.v1"
        or any(row[key] != public[key] for key in ("challenge", "task_id", "request_hash"))
        or row["packet_digest"] != packet.digest
        or row["operation"] != packet.request["step"]
        or not isinstance(row["result"], dict)
    ):
        raise AdSmbError("AD worker terminal identity changed.")
    result = row["result"]
    if result.get("schema_version") == "bluefire.ad-smb-worker-error.v1":
        exact(result, {"schema_version", "code", "possible_effects"}, "AD worker error")
        if (
            not isinstance(result["code"], str)
            or result["code"] not in ERROR_CODES
            or type(result["possible_effects"]) is not bool
        ):
            raise AdSmbError("AD worker error is invalid.")
    # Native operation projection is separate. This envelope cannot grant
    # authenticated source, fresh server logon or effective-access evidence.
    return row


def begin_prefix(packet: WorkerPacket, *, reader: bool) -> bytearray:
    public = packet.to_dict()
    if reader != (public["host_role"] == "client"):
        raise AdSmbError("AD private delivery role mismatch.")
    return (
        bytearray(b"BFADBEG1")
        + bytearray.fromhex(public["challenge"])
        + bytearray.fromhex(packet.digest[7:])
        + bytearray([int(reader)])
    )
