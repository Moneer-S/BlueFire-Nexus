"""Inactive metadata artifacts for the fixed original-workspace Darwin methods."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence, cast

from .macos_file_access_contract import (
    MAX_MESSAGE,
    MAX_REQUESTS,
    REQUEST_SCHEMA,
    MacOSFileAccessContractError,
    validate_binding,
    validate_observation,
    validate_request,
)
from .macos_file_access_intent import ReviewedMacOSTaskIntent
from .util import canonical_json_bytes, content_hash, json_clone

PROBE_ACTION = "macos.file_access.probe.v1"
OWNER_ACTION = "macos.file_access.verify_owner.v1"
CLOSE_ACTION = "macos.file_access.close_attempt.v1"
READ_ACTIONS = (PROBE_ACTION, OWNER_ACTION)
METHODS = (*READ_ACTIONS, CLOSE_ACTION)
PROBE_TYPE = "artifact.macos_file_access.probe.v1"
VERIFY_TYPE = "artifact.macos_file_access.verification.v1"
ATTEMPT_TYPE = "artifact.macos_file_access.attempt.v1"
CLOSURE_TYPE = "artifact.macos_file_access.attempt_closure.v1"
OBSERVATION_SCHEMA = "bluefire.macos-file-access-composition-observation.v1"
CLOSURE_SCHEMA = "bluefire.macos-file-access-attempt-closure.v1"


def _require(value: bool) -> None:
    if not value:
        raise MacOSFileAccessContractError("The exact original Darwin metadata is unavailable.")


def _digest(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _task(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"execute-[0-9a-f]{64}", value) is not None


def _attempt_id(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"attempt-[0-9a-f]{32}", value) is not None


def _exact(value: Any, keys: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == set(keys.split()))
    _require(len(canonical_json_bytes(value)) <= MAX_MESSAGE)
    return cast(dict[str, Any], value)


def validate_read_receipt(receipt: Any, intent: Any, binding: Any) -> dict[str, Any]:
    """Validate inactive evidence; no document here grants a native operation."""
    original = ReviewedMacOSTaskIntent.from_document(intent).document()
    bound = validate_binding(binding)
    row = _exact(
        receipt,
        "schema_version task_id transport_request_hash context_digest binding_digest operation state dispatch producer_request_usage settlement_scope original_workers namespace whole_enrollment_cleanup control_revision_before control_revision_after requests terminals shared_request_budget_used",
    )
    _require(
        row["schema_version"] == "bluefire.macos-file-access-task-receipt.v1"
        and original["operation"] in ("probe", "verify_owner")
        and all(
            row[key] == original[key]
            for key in (
                "task_id",
                "transport_request_hash",
                "context_digest",
                "binding_digest",
                "operation",
            )
        )
        and original["binding_digest"] == content_hash(bound)
        and original["control_revision"] == bound["control_revision"]
        and bound["mode"] == "0600"
        and row["state"] == "complete"
        and row["dispatch"] == "attempted"
        and row["producer_request_usage"] == "settled"
        and row["settlement_scope"] == "producer_local_only"
        and row["original_workers"] == "retained"
        and row["namespace"] == "original_creator_held"
        and row["whole_enrollment_cleanup"] is False
        and type(row["control_revision_before"]) is type(row["control_revision_after"]) is int
        and row["control_revision_before"]
        == row["control_revision_after"]
        == bound["control_revision"]
        and type(row["shared_request_budget_used"]) is int
        and 2 <= row["shared_request_budget_used"] <= MAX_REQUESTS
        and type(row["requests"]) is list
        and len(row["requests"]) == 1
        and type(row["terminals"]) is list
        and len(row["terminals"]) == 1
    )
    primitive = "read_reader" if original["operation"] == "probe" else "read_owner"
    request_row = _exact(row["requests"][0], "request_id sequence operation request_digest")
    _require(request_row["operation"] == primitive)
    request = validate_request(
        {
            "schema_version": REQUEST_SCHEMA,
            "binding": bound,
            "binding_digest": content_hash(bound),
            "request_id": request_row["request_id"],
            "sequence": request_row["sequence"],
            "operation": primitive,
            **{
                key: original[key]
                for key in ("issued_at_ms", "expires_at_ms", "issued_monotonic_ns", "deadline_ns")
            },
        }
    )
    _require(request_row["request_digest"] == content_hash(request))
    terminal = validate_observation(row["terminals"][0], request)
    _require(
        terminal["held_handle_cleanup"] == "retained"
        and terminal["request_handle_cleanup"] != "unknown"
    )
    _require(
        terminal["outcome"]
        in (("allowed", "denied") if primitive == "read_reader" else ("allowed",))
    )
    return cast(dict[str, Any], json_clone(row))


def observation(frame: Mapping[str, Any], receipt: Any, *, observed_at_ms: int) -> dict[str, Any]:
    attempt, claim, intent = frame["attempt"], frame["claim"], frame["intent"]
    binding = claim["runner_profile"]["macos_file_access_binding"]
    original = validate_read_receipt(receipt, intent, binding)
    _require(
        type(observed_at_ms) is int
        and intent["issued_at_ms"] <= observed_at_ms < intent["expires_at_ms"]
    )
    return {
        "schema_version": OBSERVATION_SCHEMA,
        "attempt_id": attempt["attempt_id"],
        "run_id": claim["manifest"]["run_id"],
        "step_id": claim["step_id"],
        "request_hash": claim["request_hash"],
        "binding": json_clone(binding),
        "intent": json_clone(intent),
        "reader": "non_owner" if intent["operation"] == "probe" else "owner",
        "outcome": original["terminals"][0]["outcome"],
        "observed_at_ms": observed_at_ms,
        "native_receipt_digest": content_hash(original),
        "probe_task_id": attempt["probe_task_id"],
        "probe_receipt_digest": attempt["probe_receipt_digest"],
    }


def validate_metadata(value: Any, receipt: Any) -> dict[str, Any]:
    """Validate data shape; the journal must join descriptive IDs to its original frame."""
    row = _exact(
        value,
        "schema_version attempt_id run_id step_id request_hash binding intent reader outcome observed_at_ms native_receipt_digest probe_task_id probe_receipt_digest",
    )
    _require(row["schema_version"] == OBSERVATION_SCHEMA)
    native = validate_read_receipt(receipt, row["intent"], row["binding"])
    intent = row["intent"]
    _require(
        _attempt_id(row["attempt_id"])
        and _digest(row["request_hash"])
        and type(row["run_id"]) is str
        and bool(row["run_id"])
        and type(row["step_id"]) is str
        and bool(row["step_id"])
        and row["native_receipt_digest"] == content_hash(native)
        and row["reader"] == ("non_owner" if intent["operation"] == "probe" else "owner")
        and row["outcome"] == native["terminals"][0]["outcome"]
        and type(row["observed_at_ms"]) is int
        and intent["issued_at_ms"] <= row["observed_at_ms"] < intent["expires_at_ms"]
        and _task(row["probe_task_id"])
        and (
            row["probe_task_id"] == intent["task_id"]
            if intent["operation"] == "probe"
            else row["probe_task_id"] != intent["task_id"]
        )
        and (
            row["probe_receipt_digest"] is None
            if intent["operation"] == "probe"
            else _digest(row["probe_receipt_digest"])
        )
    )
    return cast(dict[str, Any], json_clone(row))


def request(
    action_id: str, parameters: Mapping[str, Any], bound_inputs: Mapping[str, Any]
) -> Mapping[str, Any]:
    _require(action_id in METHODS and dict(parameters) == {})
    if action_id == PROBE_ACTION:
        _require(not bound_inputs)
    elif action_id == OWNER_ACTION:
        _require(set(bound_inputs) == {"probe"})
        probe = _probe_artifact(bound_inputs["probe"])
        _require(probe["observation"]["reader"] == "non_owner")
    else:
        _require(not bound_inputs or set(bound_inputs) == {"workspace"})
        if bound_inputs:
            _attempt_artifact(bound_inputs["workspace"])
    return {"params": {}}


def _probe_artifact(value: Any) -> dict[str, Any]:
    row = _exact(value, "type observation observation_digest native_receipt native_receipt_digest")
    _require(row["type"] == PROBE_TYPE)
    observed = validate_metadata(row["observation"], row["native_receipt"])
    _require(
        row["observation_digest"] == content_hash(observed)
        and row["native_receipt_digest"] == observed["native_receipt_digest"]
    )
    return row


def _attempt_artifact(value: Any) -> dict[str, Any]:
    row = _exact(value, "type attempt_id run_id binding_digest probe_task_id probe_receipt_digest")
    _require(
        row["type"] == ATTEMPT_TYPE
        and _attempt_id(row["attempt_id"])
        and type(row["run_id"]) is str
        and bool(row["run_id"])
        and _task(row["probe_task_id"])
    )
    for key in ("binding_digest", "probe_receipt_digest"):
        _require(_digest(row[key]))
    return row


def outputs(
    action_id: str,
    parameters: Mapping[str, Any],
    *,
    bound_inputs: Mapping[str, Any],
    runner_output: Any,
    receipt_ids: Sequence[str],
) -> dict[str, Any]:
    request(action_id, parameters, bound_inputs)
    _require(not receipt_ids)
    if action_id == CLOSE_ACTION:
        output = _exact(runner_output, "attempt_closure")
        closure = validate_closure(output["attempt_closure"])
        if bound_inputs:
            workspace = _attempt_artifact(bound_inputs["workspace"])
            _require(
                all(
                    closure[key] == workspace[key]
                    for key in ("attempt_id", "run_id", "binding_digest")
                )
            )
            _require(
                any(
                    row["task_id"] == workspace["probe_task_id"]
                    and row["native_receipt_digest"] == workspace["probe_receipt_digest"]
                    for row in closure["task_closures"]
                )
            )
        return {
            "closure": {
                "type": CLOSURE_TYPE,
                "attempt_closure": closure,
                "closure_digest": content_hash(closure),
            }
        }
    output = _exact(runner_output, "macos_receipt observation")
    observed = validate_metadata(output["observation"], output["macos_receipt"])
    _require(observed["reader"] == ("non_owner" if action_id == PROBE_ACTION else "owner"))
    artifact = {
        "type": PROBE_TYPE if action_id == PROBE_ACTION else VERIFY_TYPE,
        "observation": observed,
        "observation_digest": content_hash(observed),
        "native_receipt": json_clone(output["macos_receipt"]),
        "native_receipt_digest": observed["native_receipt_digest"],
    }
    if action_id == OWNER_ACTION:
        probe = _probe_artifact(bound_inputs["probe"])
        preceding = probe["observation"]
        _require(
            all(observed[key] == preceding[key] for key in ("attempt_id", "run_id", "binding"))
        )
        _require(
            observed["probe_task_id"] == preceding["intent"]["task_id"]
            and observed["probe_receipt_digest"] == preceding["native_receipt_digest"]
            and observed["intent"]["task_id"] != preceding["intent"]["task_id"]
            and observed["observed_at_ms"] >= preceding["observed_at_ms"]
        )
        return {"verification": artifact}
    return {
        "probe": artifact,
        "workspace": {
            "type": ATTEMPT_TYPE,
            "attempt_id": observed["attempt_id"],
            "run_id": observed["run_id"],
            "binding_digest": observed["intent"]["binding_digest"],
            "probe_task_id": observed["intent"]["task_id"],
            "probe_receipt_digest": observed["native_receipt_digest"],
        },
    }


def validate_closure(value: Any) -> dict[str, Any]:
    row = _exact(
        value,
        "schema_version attempt_id lease_digest compiled_digest run_id binding_digest control_revision cleanup_task_id cleanup_transport_request_hash cleanup_claim_digest task_closures state producer_request_usage attempt_artifacts original_workers namespace whole_enrollment_cleanup shared_request_budget_used",
    )
    _require(
        row["schema_version"] == CLOSURE_SCHEMA
        and row["state"] == "closed"
        and row["producer_request_usage"] == "settled"
        and row["attempt_artifacts"] == "not_created"
        and row["original_workers"] == "retained"
        and row["namespace"] == "original_creator_held"
        and row["whole_enrollment_cleanup"] is False
        and type(row["task_closures"]) is list
        and len(row["task_closures"]) <= 2
        and _attempt_id(row["attempt_id"])
        and _task(row["cleanup_task_id"])
        and type(row["run_id"]) is str
        and bool(row["run_id"])
        and type(row["control_revision"]) is int
        and 1 <= row["control_revision"] < 2**31
        and type(row["shared_request_budget_used"]) is int
        and 0 <= row["shared_request_budget_used"] <= MAX_REQUESTS
    )
    for key in (
        "lease_digest",
        "compiled_digest",
        "binding_digest",
        "cleanup_transport_request_hash",
        "cleanup_claim_digest",
    ):
        _require(_digest(row[key]))
    _require(row["cleanup_task_id"] == "execute-" + row["cleanup_transport_request_hash"][7:])
    for task in row["task_closures"]:
        _exact(task, "task_id transport_request_hash request_hash state native_receipt_digest")
        _require(
            _task(task["task_id"])
            and _digest(task["transport_request_hash"])
            and _digest(task["request_hash"])
            and task["task_id"] == "execute-" + task["transport_request_hash"][7:]
            and task["state"] in ("complete", "not_sent")
            and (
                _digest(task["native_receipt_digest"])
                if task["state"] == "complete"
                else task["native_receipt_digest"] is None
            )
        )
    _require(len({task["task_id"] for task in row["task_closures"]}) == len(row["task_closures"]))
    return cast(dict[str, Any], json_clone(row))
