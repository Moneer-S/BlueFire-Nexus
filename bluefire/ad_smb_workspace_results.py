"""Minimize an original receiver terminal for the saved AD workspace.

The caller authenticates transport and pins its original channel. This parser
does not mint that authority. Snapshot time is the recorded receiver completion
time, not a claimed native/remote observation timestamp. Snapshot resources bind
the reviewed target; write results do not imply a second post-write file scan.
"""

from __future__ import annotations

from typing import Any, Mapping

from .ad_smb_audit import normalize_events
from .ad_smb_channel import AdSmbHostChannel
from .ad_smb_contract import AdSmbError, AdSmbScope
from .ad_smb_native_results import project_native_read
from .ad_smb_receiver_results import TIMED_SCHEMA, stored_result
from .ad_smb_results import original_context, validate_execution
from .ad_smb_worker_wire import RECEIVER_RESULT_MAX
from .util import canonical_json_bytes, content_hash


def project_original(
    request: Mapping[str, Any],
    original: Mapping[str, Any],
    channel: AdSmbHostChannel,
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Project only already authenticated original bytes, never a new observation."""
    context = original_context(request, original)
    row = stored_result(
        value, context["manifest"], context["profile"], channel, maximum=RECEIVER_RESULT_MAX
    )
    raw = row["terminal"]["result"]
    execution: dict[str, Any] = {
        "schema_version": "bluefire.ad-smb-execution.v1",
        "request_digest": content_hash(request),
        "provenance": "runner_reported",
        "dispatch": "attempted",
        "cleanup": row["cleanup"],
        "observation": None,
    }
    if row["issue"] == "native_error":
        if raw["possible_effects"] is False:
            execution["dispatch"] = "not_started"
        return validate_execution(request, execution)

    def snapshot(descriptor: Mapping[str, Any]) -> dict[str, Any]:
        if row["schema_version"] != TIMED_SCHEMA:
            raise AdSmbError("Historical AD evidence has no receiver observation timestamp.")
        scope = AdSmbScope.from_mapping(request["scope"])
        bound = scope.to_dict()
        return {
            "schema_version": "bluefire.ad-smb-snapshot.v1",
            "scope_digest": scope.digest,
            "native_parser_digest": bound["native_parser_digest"],
            "source_receipt_digest": content_hash(row),
            "observed_at": row["receiver_completed_at"],
            "resource": {
                "member_host_id": bound["hosts"]["member"]["host_id"],
                "share": bound["share"],
                "files": bound["files"],
            },
            "descriptor": dict(descriptor),
        }

    step = request["step"]
    if step == "inspect_member":
        execution["observation"] = {
            "snapshot": snapshot(raw["share"]["descriptor"]),
            "after_descriptor": raw["after_descriptor"],
        }
    elif step in {"harden_share", "rollback_share"}:
        execution["observation"] = {
            "state": raw["state"],
            "snapshot": (
                snapshot(raw["readback"]["descriptor"])
                if raw["state"] == "readback_matched"
                else None
            ),
        }
    elif step.startswith("read_"):
        public = row["packet"]
        observation = project_native_read(
            request,
            canonical_json_bytes(raw),
            client_identity_digest=public["client_identity_digest"],
            credential_binding_digest=public["credential_binding_digest"],
            owned_process_exit_verified=True,
        )
        execution["observation"] = observation
        execution["cleanup"] = observation["local_cleanup"]
    else:
        source_digest = content_hash(raw)
        receipt_digest = content_hash(row)
        completeness = {
            "query_exhausted": "complete",
            "event_limit": "truncated",
            "byte_limit": "truncated",
            "event_rejected": "incomplete",
            "deadline": "incomplete",
            "cancelled": "incomplete",
            "read_failed": "incomplete",
            "cleanup_unknown": "unknown",
        }[raw["state"]]
        scope = AdSmbScope.from_mapping(request["scope"])
        member_host_id = scope.to_dict()["hosts"]["member"]["host_id"]
        capture_batch_digest = content_hash(
            {
                "source_receipt_digest": receipt_digest,
                "channel": raw["channel"],
                "window_start": raw["window_start"],
                "window_end": raw["window_end"],
            }
        )
        try:
            normalized = normalize_events(
                scope,
                [event.encode("utf-8") for event in raw["raw_events"]],
                source_host_id=member_host_id,
                source_receipt_digest=receipt_digest,
                capture_batch_digest=capture_batch_digest,
                window_start=raw["window_start"],
                window_end=raw["window_end"],
                completeness=completeness,
            )
        except AdSmbError:
            normalized = None
        if normalized is not None:
            normalized["capture_state"] = raw["state"]
        execution["observation"] = {
            "source_digest": source_digest,
            "events": len(raw["raw_events"]),
            "truncated": raw["state"] != "query_exhausted",
            "authenticated_source": False,
            "independent_observation": False,
            "effective_access_claim": False,
            **({"normalized_observation": normalized} if normalized is not None else {}),
        }
        if raw["handles_closed"] is not True:
            execution["cleanup"] = "unknown"
    return validate_execution(request, execution)
