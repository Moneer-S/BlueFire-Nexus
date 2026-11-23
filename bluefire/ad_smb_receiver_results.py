"""Private original worker records. Consistency parsing does not authenticate them."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Mapping

from .ad_smb_channel import AdSmbHostChannel
from .ad_smb_contract import AdSmbError, document, exact, timestamp
from .ad_smb_native_member_results import validate_native_member
from .ad_smb_native_results import project_native_read
from .ad_smb_results import original_context
from .ad_smb_worker_wire import (
    PUBLIC_MAX,
    RESULT_WRAPPER_RESERVE,
    WorkerPacket,
    prepare_packet,
    terminal,
)
from .execution_contracts import execution_task_identity
from .util import canonical_json_bytes, content_hash

SCHEMA = "bluefire.ad-smb-receiver-result.v1"
TIMED_SCHEMA = "bluefire.ad-smb-receiver-result.v2"


def native_generation(channel: AdSmbHostChannel) -> str:
    row = channel.to_dict()
    return content_hash(
        {
            "runner_binary_digest": row["runner_binary_digest"],
            "inventory_digest": row["inventory_digest"],
            "channel_digest": channel.digest,
        }
    )


def context(manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> dict[str, Any]:
    try:
        request = manifest["params"]["ad_smb_request"]
        task, request_hash = execution_task_identity(manifest, profile)
        return original_context(
            request,
            {
                "schema_version": "bluefire.ad-smb-original-task.v1",
                "request_digest": content_hash(request),
                "task_id": task,
                "transport_request_hash": request_hash,
                "manifest": dict(manifest),
                "profile": dict(profile),
                "transport_identity": request["host"],
            },
        )
    except (KeyError, TypeError, ValueError):
        raise AdSmbError("AD receiver original documents are invalid.") from None


def stored_result(
    value: Mapping[str, Any],
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    channel: AdSmbHostChannel,
    *,
    maximum: int,
) -> dict[str, Any]:
    """Validate historical bytes without fresh discovery, secrets or dispatch."""
    try:
        row = document(value, limit=maximum)
        exact(
            row,
            {
                "schema_version",
                "packet",
                "terminal",
                "native_digest",
                "dispatch",
                "cleanup",
                "issue",
            }
            | ({"receiver_completed_at"} if row.get("schema_version") == TIMED_SCHEMA else set()),
            "AD receiver result",
        )
        original = context(manifest, profile)
        request = original["manifest"]["params"]["ad_smb_request"]
        if row["schema_version"] == TIMED_SCHEMA:
            completed = timestamp(row["receiver_completed_at"])
            if row["receiver_completed_at"] != completed.isoformat() or not timestamp(
                request["requested_at"]
            ) <= completed <= timestamp(request["deadline"]):
                raise AdSmbError("AD receiver completion is outside its original request.")
        if request["host"]["native_generation"] != native_generation(channel):
            raise AdSmbError("AD receiver implementation generation changed.")
        packet_row = document(row["packet"], limit=PUBLIC_MAX)
        remaining = packet_row["remaining_ms"]
        if type(remaining) is not int or not 1 <= remaining <= 60000:
            raise AdSmbError("AD receiver interval is invalid.")
        # Reconstruct a possible original preparation instant, never the current
        # time. Recovery validates original authority bytes after their expiry.
        clock = max(timestamp(request["requested_at"]), timestamp(channel.to_dict()["created_at"]))
        if remaining < original["manifest"]["limits"]["timeout_ms"]:
            # Integer milliseconds identify an interval, not its upper endpoint.
            # Choosing its first microsecond avoids crossing an earlier expiry.
            clock = max(
                clock,
                timestamp(request["deadline"])
                - timedelta(milliseconds=remaining + 1)
                + timedelta(microseconds=1),
            )
        prepared = prepare_packet(
            original,
            channel,
            challenge=packet_row["challenge"],
            credential_binding_digest=packet_row["credential_binding_digest"],
            expected_upn_sha256=packet_row["expected_upn_sha256"],
            prior_local_authentication_ids=packet_row["prior_local_authentication_ids"],
            clock=clock,
        )
        if packet_row != prepared.to_dict():
            raise AdSmbError("AD receiver packet differs from its original documents.")
        if (
            row["schema_version"] == TIMED_SCHEMA
            and timestamp(row["receiver_completed_at"]) < clock
        ):
            raise AdSmbError("AD receiver completion precedes its original packet interval.")
        packet = WorkerPacket(canonical_json_bytes(packet_row))
        checked = terminal(packet, canonical_json_bytes(row["terminal"]))
        overhead = (
            len(canonical_json_bytes(row))
            - len(canonical_json_bytes(packet_row))
            - len(canonical_json_bytes(checked))
        )
        if overhead > RESULT_WRAPPER_RESERVE:
            raise AdSmbError("AD original wrapper exceeds its reserved output allowance.")
        is_error = checked["result"].get("schema_version") == "bluefire.ad-smb-worker-error.v1"
        if (
            row["schema_version"] not in {SCHEMA, TIMED_SCHEMA}
            or row["native_digest"] != channel.to_dict()["runner_binary_digest"]
            or row["dispatch"] != "attempted"
            or row["cleanup"] != "verified"
            or row["issue"] != ("native_error" if is_error else None)
        ):
            raise AdSmbError("AD receiver outcome has no verified original terminal.")
        if not is_error:
            if packet_row["host_role"] == "client":
                project_native_read(
                    request,
                    canonical_json_bytes(checked["result"]),
                    client_identity_digest=packet_row["client_identity_digest"],
                    credential_binding_digest=packet_row["credential_binding_digest"],
                    owned_process_exit_verified=True,
                )
            else:
                validate_native_member(
                    request,
                    checked["result"],
                    audit_byte_limit=(
                        packet.audit_byte_limit if request["step"] == "collect_audit" else None
                    ),
                )
        return row
    except (KeyError, TypeError, ValueError, OverflowError):
        raise AdSmbError("AD receiver original result is invalid.") from None


def result_record(
    packet: WorkerPacket,
    result: Mapping[str, Any],
    *,
    native_digest: str,
    issue: str | None,
    receiver_completed_at: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": TIMED_SCHEMA if receiver_completed_at is not None else SCHEMA,
        "packet": packet.to_dict(),
        "terminal": dict(result),
        "native_digest": native_digest,
        "dispatch": "attempted",
        "cleanup": "verified",
        "issue": issue,
        **(
            {"receiver_completed_at": receiver_completed_at}
            if receiver_completed_at is not None
            else {}
        ),
    }
