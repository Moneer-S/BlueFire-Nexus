"""Finite saved AD stages and conservative, non-authenticating result projection."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .ad_smb_acl import AdSmbAclChange, plan_hardening, snapshot, verify_readback
from .ad_smb_audit_observation import validate_normalized_audit
from .ad_smb_contract import (
    AdSmbError,
    AdSmbReadTarget,
    AdSmbScope,
    digest,
    document,
    exact,
    sid,
    timestamp,
)
from .execution_contracts import execution_task_identity
from .runner_contracts import seal_manifest, seal_profile
from .util import content_hash

OWNER_KIND = "ad_smb.exercise"
OPERATION_KIND = "ad_smb.operation"
ACTION = "owned.ad.smb_access.v1"
PHASES = {
    "inspect": ("inspect_member",),
    "baseline": ("read_probe_primary", "read_legitimate_primary", "read_legitimate_health"),
    "harden": ("harden_share",),
    "retest": ("read_probe_primary", "read_legitimate_primary", "read_legitimate_health"),
    "rollback": ("rollback_share",),
    "audit": ("collect_audit",),
}
TERMINAL = {"completed", "failed", "cancelled", "interrupted"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def submission(value: Any) -> str:
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
        return value
    except ValueError:
        raise AdSmbError("An exact submission identity is required.") from None


def job_id(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"job-[0-9a-f]{32}", value) is None:
        raise AdSmbError("An exact saved AD exercise is required.")
    return value


def environment(value: Any) -> dict[str, Any]:
    row = document(value)
    exact(
        row,
        {"environment_id", "scope", "member", "client", "principal_binding_digest", "provenance"},
        "AD enrolled environment",
    )
    if (
        not isinstance(row["environment_id"], str)
        or re.fullmatch(r"ad-env-[0-9a-f]{32}", row["environment_id"]) is None
        or row["provenance"] not in ("runner_reported", "synthetic_fixture")
    ):
        raise AdSmbError("AD enrollment identity is invalid.")
    row["scope"] = AdSmbScope.from_mapping(row["scope"]).to_dict()
    digest(row["principal_binding_digest"])
    for role in ("member", "client"):
        bound = row[role]
        exact(
            bound,
            {
                "runner_profile_id",
                "host_id",
                "native_generation",
                "profile_digest",
                "channel_digest",
            },
            "AD enrolled host",
        )
        if (
            not isinstance(bound["runner_profile_id"], str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", bound["runner_profile_id"]) is None
            or bound["host_id"] != row["scope"]["hosts"][role]["host_id"]
        ):
            raise AdSmbError("AD profile is not bound to the exact scoped host.")
        digest(bound["native_generation"])
        digest(bound["profile_digest"])
        digest(bound["channel_digest"])
    if row["member"]["runner_profile_id"] == row["client"]["runner_profile_id"]:
        raise AdSmbError("Member and client require distinct enrolled profiles.")
    return row


def readiness(value: Any) -> dict[str, Any]:
    row = document(value)
    exact(
        row,
        {
            "available",
            "member_observation",
            "client_read_admission",
            "secret_channel_available",
            "problem",
            "binding_digest",
        },
        "AD readiness",
    )
    flags = ("available", "member_observation", "client_read_admission", "secret_channel_available")
    if any(type(row[key]) is not bool for key in flags):
        raise AdSmbError("AD readiness flags are invalid.")
    if row["available"]:
        if not all(row[key] for key in flags) or row["problem"] is not None:
            raise AdSmbError("AD native admission prerequisites are incomplete.")
        digest(row["binding_digest"])
    elif row["problem"] not in {
        "native_admission_unavailable",
        "enrollment_unavailable",
        "changed",
        "scope_not_current",
        "member_channel_unavailable",
        "client_channel_unavailable",
        "role_channels_unavailable",
    }:
        raise AdSmbError("AD unavailability reason is invalid.")
    elif row["binding_digest"] is not None:
        digest(row["binding_digest"])
    return row


def phase_current(scope: AdSmbScope, phase: str, clock: datetime) -> None:
    scope.assert_current(lambda: clock)
    if clock >= phase_deadline(scope, phase):
        raise AdSmbError("The reviewed AD stage window has ended.")


def phase_deadline(scope: AdSmbScope, phase: str) -> datetime:
    row = scope.to_dict()
    start = timestamp(row["created_at"])
    limit = timestamp(row["expires_at"])
    if phase in {"inspect", "baseline", "harden", "retest"}:
        limit = min(limit, start + timedelta(seconds=row["limits"]["business_seconds"]))
    elif phase == "audit":
        limit = min(
            limit,
            start
            + timedelta(seconds=row["limits"]["business_seconds"] + row["limits"]["audit_seconds"]),
        )
    elif phase != "rollback":
        raise AdSmbError("AD stage is unsupported.")
    return limit


def phase_budget(phase: str) -> dict[str, int]:
    if phase not in PHASES:
        raise AdSmbError("AD stage is unsupported.")
    reads = 3 if phase in {"baseline", "retest"} else 0
    return {
        "business_attempts": reads,
        "sessions": reads,
        "share_changes": int(phase == "harden"),
        "rollbacks": int(phase == "rollback"),
    }


def latest(owner: Mapping[str, Any], phase: str) -> dict[str, Any] | None:
    return next(
        (row for row in reversed(owner["progress"]["operations"]) if row["phase"] == phase), None
    )


def remaining(owner: Mapping[str, Any]) -> dict[str, int]:
    limits = owner["request"]["environment"]["scope"]["limits"]
    return {
        key: limits[key] - owner["progress"]["reserved"].get(key, 0)
        for key in phase_budget("inspect")
    }


def affordable(owner: Mapping[str, Any], phase: str) -> bool:
    budget = phase_budget(phase)
    if phase == "harden":
        # Never spend the sole change when the scoped fresh checks cannot follow it.
        budget = {key: value + phase_budget("retest")[key] for key, value in budget.items()}
    return all(remaining(owner)[key] >= value for key, value in budget.items())


def allowed_phases(owner: Mapping[str, Any]) -> list[str]:
    progress = owner["progress"]
    if (
        progress["pending_operation"]
        or progress["policy_state"] == "unknown"
        or len(progress["operations"]) >= 6
    ):
        return []
    phases = []
    inspected, baseline = latest(owner, "inspect"), latest(owner, "baseline")
    if not progress["stopped"]:
        if inspected is None:
            phases.append("inspect")
        elif inspected["outcome"]["state"] == "complete":
            if baseline is None:
                phases.append("baseline")
            elif (
                baseline["outcome"]["state"] == "complete"
                and baseline["outcome"]["read_expectation"] == "matched"
                and baseline["outcome"]["distinct_local_contexts"] is True
                and latest(owner, "harden") is None
            ):
                phases.append("harden")
            if progress["policy_state"] == "hardened" and latest(owner, "retest") is None:
                phases.append("retest")
    if progress["policy_state"] == "hardened" and latest(owner, "rollback") is None:
        phases.append("rollback")
    if progress["operations"] and latest(owner, "audit") is None:
        phases.append("audit")
    return [phase for phase in phases if affordable(owner, phase)]


def reviewed_change(owner: Mapping[str, Any]) -> dict[str, Any] | None:
    inspected = latest(owner, "inspect")
    if not inspected or inspected["outcome"]["state"] != "complete":
        return None
    evidence = inspected["executions"][0]["observation"]
    scope = AdSmbScope.from_mapping(owner["request"]["environment"]["scope"])
    return plan_hardening(scope, evidence["snapshot"], evidence["after_descriptor"]).to_dict()


def review_document(owner: Mapping[str, Any], phase: str) -> dict[str, Any]:
    if phase not in allowed_phases(owner):
        raise AdSmbError("This AD stage needs settled original evidence or a new scope.")
    row = {
        "schema_version": "bluefire.ad-smb-review.v1",
        "workflow_job_id": owner["job_id"],
        "revision": owner["progress"]["revision"],
        "phase": phase,
        "environment_digest": content_hash(owner["request"]["environment"]),
        "readiness_digest": content_hash(owner["request"]["readiness"]),
        "steps": list(PHASES[phase]),
        "budget": phase_budget(phase),
        "change": reviewed_change(owner) if phase in {"harden", "retest", "rollback"} else None,
        "policy_state": owner["progress"]["policy_state"],
        "history_digest": content_hash(owner["progress"]["operations"]),
    }
    return {**row, "review_digest": content_hash(row)}


def request_for(
    owner: Mapping[str, Any],
    phase: str,
    operation_id: str,
    index: int,
    requested_at: str,
    deadline: str,
    review: Mapping[str, Any],
    reviewed_by: str,
) -> dict[str, Any]:
    step = PHASES[phase][index]
    selected = environment(owner["request"]["environment"])
    scope = AdSmbScope.from_mapping(selected["scope"])
    target = None
    if step.startswith("read_"):
        _, reader, purpose = step.split("_")
        target = AdSmbReadTarget.from_scope(scope, reader=reader, purpose=purpose).to_dict()
    return {
        "schema_version": "bluefire.ad-smb-step.v1",
        "request_id": hashlib.sha256(f"{operation_id}:{index}".encode()).hexdigest()[:32],
        "workflow_job_id": owner["job_id"],
        "operation_job_id": operation_id,
        "index": index,
        "phase": phase,
        "step": step,
        "scope": scope.to_dict(),
        "scope_digest": scope.digest,
        "target": target,
        "requested_at": requested_at,
        "deadline": deadline,
        "environment_digest": content_hash(selected),
        "host": selected["client" if target else "member"],
        "principal_binding_digest": selected["principal_binding_digest"],
        "review_digest": review["review_digest"],
        "reviewed_by": reviewer(reviewed_by),
        "change": review["change"],
    }


def reviewer(value: Any) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,99}", value) is None
    ):
        raise AdSmbError("A bounded non-secret reviewer identity is required.")
    return value


def validate_request(
    owner: Mapping[str, Any], request: Any, review: Mapping[str, Any]
) -> dict[str, Any]:
    row = document(request)
    try:
        deadline = timestamp(row["deadline"])
        requested = timestamp(row["requested_at"])
        scope = AdSmbScope.from_mapping(owner["request"]["environment"]["scope"])
        if (
            type(row["index"]) is not int
            or row["phase"] not in PHASES
            or not 0 <= row["index"] < len(PHASES[row["phase"]])
            or not timestamp(scope.to_dict()["created_at"])
            <= requested
            < deadline
            <= phase_deadline(scope, row["phase"])
            or (deadline - requested).total_seconds()
            > scope.to_dict()["limits"]["operation_seconds"]
        ):
            raise AdSmbError("AD original step is invalid.")
        expected = request_for(
            owner,
            row["phase"],
            job_id(row["operation_job_id"]),
            row["index"],
            row["requested_at"],
            row["deadline"],
            review,
            row["reviewed_by"],
        )
        phase_current(scope, row["phase"], requested)
        if row != expected:
            raise AdSmbError("AD original step differs from the saved exact review.")
        return row
    except (KeyError, TypeError, IndexError):
        raise AdSmbError("AD original step is incomplete.") from None


def execution_manifest(request: Mapping[str, Any], profile: Mapping[str, Any]) -> dict[str, Any]:
    """Pending fixed native identity, not action registration or dispatch authority."""
    limits = dict(profile["limits"])
    limits["timeout_ms"] = min(
        limits["timeout_ms"], request["scope"]["limits"]["operation_seconds"] * 1000
    )
    return seal_manifest(
        {
            "schema_version": "bluefire.runner-manifest.v1",
            "request_id": "ad-" + request["request_id"],
            "run_id": request["operation_job_id"],
            "step_id": request["step"],
            "behavior_id": "identity.ad.smb_access.v1",
            "action_id": ACTION,
            "mode": "execute",
            "runner_id": profile["runner_id"],
            "runner_profile_id": profile["profile_id"],
            "platform": "windows",
            "requested_at": request["requested_at"],
            "expires_at": request["deadline"],
            "params": {"ad_smb_request": dict(request)},
            "target_scope": {"filesystem": [], "network": []},
            "required_capabilities": ["ad_smb_access"],
            "safety_tier": "controlled",
            "limits": limits,
            "cleanup_action_id": None,
            "policy_digest": profile["policy_digest"],
            "approval": {
                "approved_by": request["reviewed_by"],
                "approved_at": request["requested_at"],
                "expires_at": request["deadline"],
                "request_hash": "",
            },
            "evidence_refs": [],
            "request_hash": "",
        }
    )


def original_context(request: Mapping[str, Any], value: Any) -> dict[str, Any]:
    """Bind historical task bytes without treating a digest as authenticated evidence."""
    row = document(value)
    exact(
        row,
        {
            "schema_version",
            "request_digest",
            "task_id",
            "transport_request_hash",
            "manifest",
            "profile",
            "transport_identity",
        },
        "AD original task",
    )
    profile = row["profile"]
    exact(
        profile,
        {
            "schema_version",
            "profile_id",
            "runner_id",
            "platform",
            "sandbox_root",
            "allowed_actions",
            "control_blocked_actions",
            "capabilities",
            "max_safety_tier",
            "approval_required_at_or_above",
            "target_scope",
            "limits",
            "policy_digest",
        },
        "AD original profile",
    )
    if (
        profile != seal_profile(profile)
        or profile["platform"] != "windows"
        or profile["profile_id"] != request["host"]["runner_profile_id"]
        or profile["policy_digest"] != request["host"]["profile_digest"]
        or profile["allowed_actions"] != [ACTION]
        or profile["control_blocked_actions"] != []
        or profile["capabilities"] != ["ad_smb_access"]
        or profile["target_scope"] != {"filesystem": [], "network": []}
        or profile["runner_id"] != "bluefire-rust-runner.v1"
        or profile["max_safety_tier"] != "controlled"
        or profile["approval_required_at_or_above"] != "safe"
    ):
        raise AdSmbError("AD original profile differs from the finite enrolled native binding.")
    transport = row["transport_identity"]
    exact(
        transport,
        {"host_id", "runner_profile_id", "native_generation", "profile_digest", "channel_digest"},
        "AD original channel",
    )
    if any(transport[key] != request["host"][key] for key in request["host"]):
        raise AdSmbError("AD recovery cannot select another enrolled host or implementation.")
    digest(transport["channel_digest"])
    expected = execution_manifest(request, profile)
    task, request_hash = execution_task_identity(expected, profile)
    if (
        row["schema_version"] != "bluefire.ad-smb-original-task.v1"
        or row["request_digest"] != content_hash(request)
        or row["manifest"] != expected
        or row["task_id"] != task
        or row["transport_request_hash"] != request_hash
    ):
        raise AdSmbError("AD original native request, profile or transport task changed.")
    return row


def validate_execution(request: Mapping[str, Any], value: Any) -> dict[str, Any]:
    limit = (
        AdSmbScope.from_mapping(request["scope"]).to_dict()["limits"]["returned_payload_bytes"]
        if request.get("step") == "collect_audit"
        else 256 * 1024
    )
    row = document(value, limit=limit)
    exact(
        row,
        {"schema_version", "request_digest", "provenance", "dispatch", "cleanup", "observation"},
        "AD execution",
    )
    if (
        row["schema_version"] != "bluefire.ad-smb-execution.v1"
        or row["request_digest"] != content_hash(request)
        or row["provenance"] not in {"runner_reported", "synthetic_fixture"}
        or row["dispatch"] not in {"not_started", "attempted", "unknown"}
        or row["cleanup"] not in {"verified", "unknown"}
    ):
        raise AdSmbError("AD execution identity or state is invalid.")
    observation = row["observation"]
    if observation is None:
        return row
    if row["dispatch"] != "attempted":
        raise AdSmbError("Undispatched AD work cannot carry a native observation.")
    scope = AdSmbScope.from_mapping(request["scope"])
    step = request["step"]
    if step == "inspect_member":
        exact(observation, {"snapshot", "after_descriptor"}, "AD member inspection")
        plan_hardening(scope, observation["snapshot"], observation["after_descriptor"])
    elif step in {"harden_share", "rollback_share"}:
        exact(observation, {"state", "snapshot"}, "AD share change")
        if observation["state"] not in {"not_attempted", "readback_matched", "unknown"}:
            raise AdSmbError("AD share write state is invalid.")
        if observation["state"] == "not_attempted" and observation["snapshot"] is not None:
            raise AdSmbError("AD unattempted write cannot claim a post-write readback.")
        if observation["snapshot"] is not None:
            if step == "harden_share":
                verify_readback(
                    scope,
                    AdSmbAclChange.from_mapping(scope, request["change"]),
                    observation["snapshot"],
                )
            else:
                checked = snapshot(scope, observation["snapshot"], hardened=False)
                if checked["descriptor"] != request["change"]["before"]["descriptor"]:
                    raise AdSmbError("AD rollback differs from the exact original descriptor.")
        elif observation["state"] == "readback_matched":
            raise AdSmbError("AD matched write lacks its exact readback.")
    elif step.startswith("read_"):
        row["observation"] = read_observation(request, observation)
    elif step == "collect_audit":
        legacy_fields = {
            "source_digest",
            "events",
            "truncated",
            "authenticated_source",
            "independent_observation",
            "effective_access_claim",
        }
        if isinstance(observation, dict) and set(observation) == legacy_fields | {
            "normalized_observation"
        }:
            validate_normalized_audit(request, scope, observation)
        else:
            exact(observation, legacy_fields, "AD audit summary")
        digest(observation["source_digest"])
        if (
            type(observation["events"]) is not int
            or not 0 <= observation["events"] <= scope.to_dict()["limits"]["audit_events"]
            or type(observation["truncated"]) is not bool
            or any(
                observation[key] is not False
                for key in (
                    "authenticated_source",
                    "independent_observation",
                    "effective_access_claim",
                )
            )
        ):
            raise AdSmbError("AD audit summary cannot self-certify independent access proof.")
    else:
        raise AdSmbError("AD observation has an unsupported original step.")
    if (
        step in {"inspect_member", "harden_share", "rollback_share"}
        and observation["snapshot"] is not None
    ):
        observed_at = timestamp(observation["snapshot"]["observed_at"])
        if not timestamp(request["requested_at"]) <= observed_at <= timestamp(request["deadline"]):
            raise AdSmbError("AD member observation is outside its original request window.")
    return row


def read_observation(request: Mapping[str, Any], value: Any) -> dict[str, Any]:
    """Closed safe projection expected from the future authenticated native adapter.

    This is deliberately not a native wire parser; that adapter must rederive this
    projection from the exact original raw terminal before it is reachable live.
    """
    row = document(value)
    exact(
        row,
        {
            "request_id",
            "scope_digest",
            "reader",
            "purpose",
            "expected_remote_sid",
            "state",
            "volume_serial",
            "file_id",
            "sha256",
            "bytes_read",
            "local_user_sid",
            "local_authentication_id",
            "local_cleanup",
            "server_session_closed",
            "authenticated_remote_reader",
            "fresh_server_logon",
            "independent_observation",
            "effective_access_claim",
        },
        "AD fresh read projection",
    )
    target = request["target"]
    if any(
        row[key] != expected
        for key, expected in {
            "request_id": request["request_id"],
            "scope_digest": request["scope_digest"],
            "reader": target["reader"],
            "purpose": target["file"]["purpose"],
            "expected_remote_sid": target["expected_remote_sid"],
        }.items()
    ):
        raise AdSmbError("AD read projection lost its exact original target.")
    if (
        row["state"]
        not in {
            "bytes_matched",
            "open_access_denied",
            "unknown",
            "deadline",
            "cancelled",
            "not_started",
        }
        or type(row["bytes_read"]) is not int
        or not 0 <= row["bytes_read"] <= target["file"]["size_bytes"] + 1
        or row["local_cleanup"] not in {"verified", "unknown"}
        or row["server_session_closed"] is not None
        or any(
            row[key] is not False
            for key in (
                "authenticated_remote_reader",
                "fresh_server_logon",
                "independent_observation",
                "effective_access_claim",
            )
        )
    ):
        raise AdSmbError("AD read projection overstates its observed guarantees.")
    if row["local_user_sid"] is not None:
        sid(row["local_user_sid"])
    if row["local_authentication_id"] is not None:
        luid = row["local_authentication_id"]
        if (
            not isinstance(luid, str)
            or re.fullmatch(r"[0-9a-f]{16}", luid) is None
            or int(luid, 16) == 0
        ):
            raise AdSmbError("AD local LUID must remain a nonzero exact hexadecimal identity.")
    if row["volume_serial"] is not None:
        volume = row["volume_serial"]
        if not isinstance(volume, str) or re.fullmatch(r"[0-9a-f]{16}", volume) is None:
            raise AdSmbError("AD observed volume must remain exact hexadecimal data.")
    if row["file_id"] is not None and (
        not isinstance(row["file_id"], str) or re.fullmatch(r"[0-9a-f]{32}", row["file_id"]) is None
    ):
        raise AdSmbError("AD observed file identity is invalid.")
    if row["sha256"] is not None:
        digest(row["sha256"])
    if row["state"] == "bytes_matched" and (
        any(row[key] != target["file"][key] for key in ("volume_serial", "file_id", "sha256"))
        or row["bytes_read"] != target["file"]["size_bytes"]
        or row["local_user_sid"] is None
        or row["local_authentication_id"] is None
        or row["local_cleanup"] != "verified"
    ):
        raise AdSmbError("AD matched read lacks its exact file/volume/content and local context.")
    if row["state"] == "open_access_denied" and (
        row["bytes_read"] != 0
        or any(row[key] is not None for key in ("volume_serial", "file_id", "sha256"))
        or row["local_user_sid"] is None
        or row["local_authentication_id"] is None
        or row["local_cleanup"] != "verified"
    ):
        raise AdSmbError("AD open denial cannot stand in for missing context or consumed bytes.")
    return row


def outcome(
    phase: str, executions: list[dict[str, Any]], prior: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    known = bool(executions) and all(
        row["cleanup"] == "verified"
        and (
            row["dispatch"] == "not_started"
            or (row["dispatch"] == "attempted" and row["observation"] is not None)
        )
        for row in executions
    )
    observations = [row["observation"] for row in executions if row["observation"] is not None]
    read_expectation = None
    distinct = None
    audit_complete = None
    if phase in {"baseline", "retest"}:
        known = known and all(
            row["state"] in {"bytes_matched", "open_access_denied"} for row in observations
        )
        expected = (
            ["open_access_denied", "bytes_matched", "bytes_matched"]
            if phase == "retest"
            else ["bytes_matched"] * 3
        )
        read_expectation = (
            "matched"
            if len(observations) == 3 and [row["state"] for row in observations] == expected
            else "not_met" if len(observations) == 3 and known else "incomplete"
        )
        old_luids = {
            execution["observation"]["local_authentication_id"]
            for operation in prior or []
            if operation["phase"] in {"baseline", "retest"}
            for execution in operation["executions"]
            if execution["observation"] is not None
        }
        distinct = len({row["local_authentication_id"] for row in observations}) == len(
            observations
        ) and not old_luids.intersection(row["local_authentication_id"] for row in observations)
    elif phase in {"harden", "rollback"}:
        known = known and all(
            row["state"] in {"readback_matched", "not_attempted"} for row in observations
        )
    elif phase == "audit" and observations:
        audit_complete = not observations[0]["truncated"]
    no_effect = known and (
        all(row["dispatch"] == "not_started" for row in executions)
        or (
            phase in {"harden", "rollback"}
            and observations
            and observations[0]["state"] == "not_attempted"
        )
    )
    complete = known and len(observations) == len(PHASES[phase])
    state = (
        "unknown"
        if not known
        else "not_started" if no_effect else "complete" if complete else "partial"
    )
    return {
        "state": state,
        "read_expectation": read_expectation,
        "distinct_local_contexts": distinct,
        "audit_complete": audit_complete,
        "evidence_digest": content_hash(executions),
        "cleanup": (
            "verified"
            if executions and all(row["cleanup"] == "verified" for row in executions)
            else "unknown"
        ),
        "authenticated_remote_reader": False,
        "independent_observation": False,
        "effective_access_claim": False,
    }
