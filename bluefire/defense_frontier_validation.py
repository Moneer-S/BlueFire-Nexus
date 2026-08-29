"""Independent semantic validation for GATE-04 evidence."""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .ai import AIProviderError, validate_persisted_proposal_record
from .approvals import execution_approval_binding
from .config import AutonomyLevel, RunnerProfile
from .contracts import ExecutionMode, ScenarioDefinition, load_scenario
from .defense_frontier import (
    CANONICAL_PROFILE_ID,
    COLLECTOR_ID,
    COMPARISON_REPORT,
    DEFENSE_CHANGE_NOTE,
    DEFENSE_REPORT,
    FRONTIER_PROFILE_ID,
    JOURNEY_REPORT,
    JOURNEY_SCHEMA,
    PROVIDER_ID,
    SCENARIO_ID,
    STRUCTURAL_REPORT,
)
from .defense_frontier_report_validation import (
    DefenseFrontierValidationError,
    _exact,
    _list,
    _mapping,
    _require,
    _validate_comparison,
    _validate_defense,
    _validate_structural,
)
from .planner import DeterministicPlanner, PlannerError
from .registry import load_builtin_registry
from .run_store import RunStore
from .runner_bootstrap import load_runner_manifest
from .util import content_hash, file_hash, json_clone

_REPORT_LIMIT = 8 * 1024 * 1024

_CANONICAL_PATH = (
    ("create_fixture", "sandbox.fixture.create.v1", "sandbox.fixture.create.v1", "success"),
    ("inspect_system", "endpoint.discovery.system.v1", "endpoint.discovery.system.v1", "success"),
    (
        "inspect_processes",
        "endpoint.discovery.processes.v1",
        "endpoint.discovery.processes.v1",
        "partial",
    ),
    (
        "transform_fixture",
        "sandbox.fixture.transform.v1",
        "sandbox.fixture.transform.v1",
        "success",
    ),
    ("choose_discovery", "sandbox.discovery.list.v1", "sandbox.discovery.list.v1", "success"),
    (
        "stage_evidence",
        "sandbox.collection.stage.v1",
        "sandbox.collection.stage.v1",
        "success",
    ),
    (
        "try_internal_transport",
        "sandbox.network.loopback.v1",
        "sandbox.network.loopback.v1",
        "success",
    ),
    ("cleanup_workspace", "sandbox.cleanup.v1", "sandbox.cleanup.v1", "success"),
)
_FRONTIER_PATH = (
    *_CANONICAL_PATH[:-2],
    (
        "try_internal_transport",
        "sandbox.network.loopback.v1",
        "sandbox.network.loopback.v1",
        "blocked",
    ),
    (
        "preserve_approved_copy",
        "sandbox.export.local.v1",
        "sandbox.export.local.v1",
        "success",
    ),
    _CANONICAL_PATH[-1],
)


def load_report(path: Path) -> Mapping[str, Any]:
    _require(not path.is_symlink(), "a required GATE-04 report is unavailable")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "a required GATE-04 report is unavailable",
        )
        _require(before.st_size <= _REPORT_LIMIT, "a GATE-04 report exceeded its byte bound")
        payload = bytearray()
        while len(payload) <= _REPORT_LIMIT:
            block = os.read(descriptor, min(64 * 1024, _REPORT_LIMIT + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        path_metadata = path.lstat()
        _require(
            len(payload) <= _REPORT_LIMIT
            and (after.st_dev, after.st_ino, after.st_size)
            == (before.st_dev, before.st_ino, before.st_size)
            and (path_metadata.st_dev, path_metadata.st_ino) == (before.st_dev, before.st_ino)
            and stat.S_ISREG(path_metadata.st_mode)
            and path_metadata.st_nlink == 1,
            "a GATE-04 report changed while it was read",
        )
        value = json.loads(bytes(payload).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DefenseFrontierValidationError("a GATE-04 report is not valid JSON") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    _require(isinstance(value, Mapping), "a GATE-04 report is not an object")
    return value


def _step(run: Mapping[str, Any], step_id: str) -> Mapping[str, Any] | None:
    rows = _list(run.get("steps"), "run steps")
    matches = [row for row in rows if isinstance(row, Mapping) and row.get("step_id") == step_id]
    _require(len(matches) <= 1, "a frontier step was repeated")
    return matches[0] if matches else None


def _records(run: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    evidence = _mapping(run.get("evidence"), "run evidence")
    return [
        row
        for row in _list(evidence.get("records"), "evidence records")
        if isinstance(row, Mapping)
    ]


def _observed(run: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        row
        for row in _records(run)
        if row.get("provenance") == "observed" and row.get("producer") == COLLECTOR_ID
    ]


def _export_observed(run: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    result = []
    for row in _observed(run):
        content = row.get("content")
        path = content.get("path") if isinstance(content, Mapping) else None
        if isinstance(path, str) and path.replace("\\", "/").startswith("exports/ephemeral/"):
            result.append(row)
    return result


def _detection_observed_count(run: Mapping[str, Any], behavior_id: str) -> int:
    document = _mapping(run.get("detections"), "run detections")
    candidates = _list(document.get("candidates"), "detection candidates")
    matches = [
        row
        for row in candidates
        if isinstance(row, Mapping) and row.get("behavior_id") == behavior_id
    ]
    _require(len(matches) == 1, "the frontier detector is missing or ambiguous")
    candidate = matches[0]
    observed_ids = _list(candidate.get("observed_evidence_ids"), "observed detection IDs")
    malicious_ids = _list(candidate.get("malicious_fixture_ids"), "malicious fixture IDs")
    evidence_ids = {
        row.get("evidence_id") for row in _observed(run) if isinstance(row.get("evidence_id"), str)
    }
    _require(
        candidate.get("state") == "benign_evaluated"
        and all(isinstance(item, str) and item in evidence_ids for item in observed_ids)
        and len(observed_ids) == len(set(observed_ids))
        and all(isinstance(item, str) for item in malicious_ids)
        and len(malicious_ids) == len(set(malicious_ids))
        and candidate.get("match_count") == len(malicious_ids) + len(observed_ids),
        "a detection is detached from observed evidence",
    )
    return len(observed_ids)


def _transport_receiver_binding(run: Mapping[str, Any]) -> Mapping[str, object]:
    step = _mapping(_step(run, "try_internal_transport"), "transport step")
    runner_task_id = step.get("runner_task_id")
    artifacts = _mapping(step.get("artifacts"), "transport artifacts")
    receipt = _mapping(artifacts.get("receipt"), "transport receipt")
    details = _mapping(receipt.get("details"), "transport receipt details")
    digest = details.get("sha256")
    byte_count = details.get("bytes_sent")
    _require(
        step.get("status") == "success"
        and isinstance(runner_task_id, str)
        and re.fullmatch(r"execute-[0-9a-f]{64}", runner_task_id) is not None
        and isinstance(digest, str)
        and len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
        and isinstance(byte_count, int)
        and not isinstance(byte_count, bool)
        and byte_count > 0,
        "transport receiver binding is invalid",
    )
    return {
        "task_id": runner_task_id,
        "sha256": digest,
        "bytes_received": byte_count,
    }


def _execution_summary(run: Mapping[str, Any], role: str) -> Mapping[str, Any]:
    steps = _list(run.get("steps"), "run steps")
    approval = _mapping(run.get("approval"), "run approval")
    cleanup = _mapping(run.get("cleanup"), "run cleanup")
    return {
        "role": role,
        "run_id": run.get("run_id"),
        "profile_id": run.get("runner_profile_id"),
        "status": run.get("status"),
        "objective_reached": run.get("objective_reached"),
        "approval_id": approval.get("approval_id"),
        "approval_status": approval.get("status"),
        "path": [
            {
                "step_id": row.get("step_id"),
                "behavior_id": row.get("behavior_id"),
                "action_id": row.get("action_id"),
                "status": row.get("status"),
            }
            for row in steps
            if isinstance(row, Mapping)
        ],
        "observed_evidence_ids": [
            str(row["evidence_id"])
            for row in _observed(run)
            if isinstance(row.get("evidence_id"), str)
        ],
        "cleanup": {
            key: cleanup.get(key) for key in ("attempted", "success", "outstanding_receipt_count")
        },
    }


def _timestamp(value: Any, context: str) -> datetime:
    _require(isinstance(value, str), f"{context} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DefenseFrontierValidationError(f"{context} is invalid") from exc
    _require(parsed.tzinfo is not None, f"{context} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _approval_id(run: Mapping[str, Any]) -> str:
    approval = _mapping(run.get("approval"), "run approval")
    _exact(
        approval,
        {
            "schema_version",
            "approval_id",
            "run_id",
            "state_digest",
            "plan_digest",
            "profile_id",
            "target_scope_digest",
            "maximum_tier",
            "status",
            "requested_at",
            "expires_at",
            "approved_at",
            "approved_by",
            "consumed_at",
            "claimed_at",
        },
        "run approval",
    )
    value = approval.get("approval_id")
    policy = _mapping(run.get("policy"), "run policy")
    recorded_binding = _mapping(policy.get("approval_binding"), "approval binding")
    scenario = ScenarioDefinition.from_mapping(run.get("scenario"))
    plan = _mapping(run.get("plan"), "run plan")
    profile = RunnerProfile.from_mapping(run.get("profile"))
    target_scope = _mapping(run.get("authorized_target_scope"), "authorized target scope")
    provider = _mapping(run.get("ai_provider"), "run AI provider")
    context = _mapping(policy.get("approval_context"), "approval context")
    runner_readiness = policy.get("runner_readiness")
    catalog_authority = policy.get("catalog_authority")
    _require(
        runner_readiness is None or isinstance(runner_readiness, Mapping),
        "runner readiness is invalid",
    )
    _require(
        catalog_authority is None or isinstance(catalog_authority, Mapping),
        "catalog authority is invalid",
    )
    try:
        autonomy = AutonomyLevel(run.get("autonomy"))
    except (TypeError, ValueError) as exc:
        raise DefenseFrontierValidationError("run autonomy is invalid") from exc
    expected_binding = execution_approval_binding(
        registry=load_builtin_registry(),
        scenario=scenario,
        plan=plan,
        profile=profile,
        target_scope=target_scope,
        autonomy=autonomy,
        ai_provider=provider,
        context=context or None,
        runner_readiness=runner_readiness,
        catalog_authority=catalog_authority,
    )
    expected_intent_id = "intent-" + content_hash(expected_binding).removeprefix("sha256:")[:32]
    requested_at = _timestamp(approval.get("requested_at"), "approval requested_at")
    approved_at = _timestamp(approval.get("approved_at"), "approval approved_at")
    consumed_at = _timestamp(approval.get("consumed_at"), "approval consumed_at")
    claimed_at = _timestamp(approval.get("claimed_at"), "approval claimed_at")
    created_at = _timestamp(run.get("created_at"), "run created_at")
    finalized_at = _timestamp(run.get("finalized_at"), "run finalized_at")
    expires_at = _timestamp(approval.get("expires_at"), "approval expires_at")
    _require(
        approval.get("schema_version") == "bluefire.approval-request.v1"
        and approval.get("status") == "claimed"
        and isinstance(value, str)
        and re.fullmatch(r"approval-[0-9a-f]{32}", value) is not None
        and approval.get("run_id") == expected_intent_id
        and isinstance(approval.get("approved_by"), str)
        and bool(str(approval["approved_by"]).strip())
        and policy.get("approval") == approval
        and policy.get("authorized_target_scope") == target_scope
        and policy.get("autonomy") == autonomy.value
        and policy.get("ai_provider") == provider
        and recorded_binding == expected_binding
        and all(approval.get(field) == expected_binding[field] for field in expected_binding)
        and requested_at <= approved_at <= consumed_at <= claimed_at
        and claimed_at <= created_at <= finalized_at < expires_at,
        "run approval was not freshly claimed against its exact execution boundary",
    )
    return value


def _cleanup(run: Mapping[str, Any]) -> None:
    cleanup = _mapping(run.get("cleanup"), "run cleanup")
    cleanup_step = _mapping(_step(run, "cleanup_workspace"), "cleanup step")
    cleanup_details = _mapping(cleanup_step.get("cleanup"), "cleanup step details")
    objective = _mapping(run.get("objective_evaluation"), "objective evaluation")
    _require(
        cleanup.get("attempted") is True
        and cleanup.get("success") is True
        and cleanup.get("outstanding_receipt_count") == 0
        and cleanup_step.get("behavior_id") == "sandbox.cleanup.v1"
        and cleanup_step.get("action_id") == "sandbox.cleanup.v1"
        and cleanup_step.get("execution_disposition") == "execute"
        and cleanup_step.get("status") == "success"
        and cleanup_details.get("verification_performed") is True
        and cleanup_details.get("errors") == []
        and cleanup_details.get("retained_paths") == []
        and isinstance(cleanup_details.get("requested_receipts"), int)
        and not isinstance(cleanup_details.get("requested_receipts"), bool)
        and cleanup_details.get("requested_receipts", 0) > 0
        and cleanup_details.get("verified_receipts") == cleanup_details.get("requested_receipts")
        and objective.get("cleanup_required") is True
        and objective.get("cleanup_satisfied") is True
        and objective.get("cleanup_forced") is False,
        "run cleanup was not authoritatively verified",
    )


def _validate_native_execution(run: Mapping[str, Any]) -> None:
    _require(run.get("mode") == "execute", "a frontier run was not Execute mode")
    steps = _list(run.get("steps"), "run steps")
    executed = [
        row
        for row in _records(run)
        if row.get("provenance") == "executed" and row.get("producer") == "bluefire-rust-runner"
    ]
    for raw_step in steps:
        step = _mapping(raw_step, "run step")
        _require(
            step.get("execution_disposition") == "execute",
            "a frontier step was simulated or counterfactual",
        )
        matching = [
            row
            for row in executed
            if row.get("step_id") == step.get("step_id")
            and row.get("action_id") == step.get("action_id")
        ]
        if step.get("status") in {"success", "partial"}:
            _require(len(matching) == 1, "a successful step lacks unique native evidence")
            evidence = matching[0]
            content = _mapping(evidence.get("content"), "native evidence content")
            runner_rows = _list(content.get("runner_evidence"), "native runner evidence")
            _require(
                evidence.get("runner_profile_id") == run.get("runner_profile_id")
                and _mapping(evidence.get("environment"), "native evidence environment").get(
                    "platform"
                )
                == "windows"
                and any(
                    isinstance(row, Mapping)
                    and row.get("kind") == "executed"
                    and row.get("producer") == "bluefire-rust-runner"
                    and row.get("runner_id") == "bluefire-rust-runner.v1"
                    and row.get("runner_profile_id") == run.get("runner_profile_id")
                    for row in runner_rows
                ),
                "native evidence is not bound to the packaged runner identity",
            )
        elif step.get("status") == "blocked":
            _require(not matching, "a pre-dispatch block has executed evidence")
        else:
            raise DefenseFrontierValidationError("a frontier step did not succeed or block")
    _require(
        len(executed)
        == sum(
            1
            for row in steps
            if isinstance(row, Mapping) and row.get("status") in {"success", "partial"}
        ),
        "native evidence contains an unbound or missing execution record",
    )
    mutating_actions = {
        "sandbox.fixture.create.v1",
        "sandbox.fixture.transform.v1",
        "sandbox.collection.stage.v1",
        "sandbox.export.local.v1",
    }
    for step in steps:
        if isinstance(step, Mapping) and step.get("action_id") in mutating_actions:
            receipts = _list(step.get("receipts"), "mutating step receipts")
            _require(
                step.get("status") != "success" or bool(receipts),
                "a successful native mutation lacks a cleanup receipt",
            )


def _validate_planner(frontier: Mapping[str, Any]) -> Mapping[str, Any]:
    proposals = _list(frontier.get("ai_proposals"), "AI proposal records")
    matches = [
        row
        for row in proposals
        if isinstance(row, Mapping)
        and row.get("current_step_id") == "try_internal_transport"
        and row.get("outcome") == "blocked"
    ]
    _require(len(matches) == 1, "the blocked planner decision is missing or ambiguous")
    record = matches[0]
    try:
        validated_proposal = validate_persisted_proposal_record(record)
    except AIProviderError as exc:
        raise DefenseFrontierValidationError(
            "the blocked proposal failed durable contract validation"
        ) from exc
    proposal = _mapping(record.get("proposal"), "blocked proposal")
    provider = _mapping(record.get("provider"), "blocked proposal provider")
    policy = _mapping(record.get("proposal_policy_evaluation"), "blocked proposal policy")
    state = _mapping(record.get("planner_state"), "blocked planner state")
    _require(
        record.get("schema_version") == "bluefire.ai-proposal-record.v3"
        and record.get("run_id") == frontier.get("run_id")
        and record.get("plan_digest") == content_hash(_mapping(frontier.get("plan"), "run plan"))
        and state.get("schema_version") == "bluefire.planner-state.v1"
        and state.get("mode") == "execute",
        "planner state schema is invalid",
    )
    _require(
        record.get("planner_state_digest") == content_hash(state),
        "planner state digest is invalid",
    )
    steps = _list(frontier.get("steps"), "frontier steps")
    current_indexes = [
        index
        for index, row in enumerate(steps)
        if isinstance(row, Mapping) and row.get("step_id") == record.get("current_step_id")
    ]
    _require(len(current_indexes) == 1, "planner state step identity is ambiguous")
    completed_rows: list[dict[str, Any]] = []
    for row in steps[: current_indexes[0] + 1]:
        _require(isinstance(row, Mapping), "planner state contains a malformed completed step")
        completed_rows.append(dict(row))
    current_decision_id = completed_rows[-1].pop("planner_decision_id", None)
    _require(
        current_decision_id == record.get("deterministic_decision_id")
        and len({row.get("step_id") for row in completed_rows}) == len(completed_rows),
        "planner state decision lineage is invalid",
    )
    expected_completed = [
        {
            "step_id": row.get("step_id"),
            "behavior_id": row.get("behavior_id"),
            "status": row.get("status"),
        }
        for row in completed_rows
    ]
    _require(
        state.get("completed_steps") == expected_completed,
        "planner state is not the exact observed run prefix",
    )
    expected_state_digest = content_hash(
        {
            "artifacts": {str(row["step_id"]): row.get("artifacts", {}) for row in completed_rows},
            "steps": completed_rows,
        }
    )
    _require(
        record.get("state_digest") == expected_state_digest
        and state.get("source_state_digest") == expected_state_digest,
        "planner state is not bound to the observed run prefix",
    )
    decisions = _list(frontier.get("planner_decisions"), "frontier planner decisions")
    matching_decisions = [
        _mapping(row, "frontier planner decision")
        for row in decisions
        if isinstance(row, Mapping)
        and row.get("decision_id") == record.get("deterministic_decision_id")
    ]
    _require(len(matching_decisions) == 1, "planner decision record is missing or ambiguous")
    decision = matching_decisions[0]
    summarized_decision = _mapping(state.get("deterministic_decision"), "planner decision summary")
    _require(
        decision.get("run_id") == frontier.get("run_id")
        and decision.get("current_state_digest") == record.get("state_digest")
        and decision.get("selected_step_id") == summarized_decision.get("selected_step_id")
        and decision.get("selected_behavior_id") == summarized_decision.get("selected_behavior_id")
        and decision.get("execution_disposition")
        == summarized_decision.get("execution_disposition"),
        "planner decision record does not match the durable proposal state",
    )
    _require(
        validated_proposal.proposal_type.value == "select_registered"
        and proposal.get("proposal_type") == "select_registered"
        and proposal.get("selected_step_id") == "preserve_approved_copy"
        and proposal.get("selected_behavior_id") == "sandbox.export.local.v1"
        and record.get("application_status") == "accepted_registered_default",
        "Auto did not select the registered fallback",
    )
    _require(
        provider.get("effective_provider_id") == PROVIDER_ID
        and provider.get("used_fallback") is False
        and policy.get("status") == "permitted"
        and policy.get("mutation") is False
        and policy.get("execute_requires_fresh_approval") is False,
        "the deterministic provider or policy record is invalid",
    )
    _require(
        any(
            isinstance(row, Mapping)
            and row.get("step_id") == "try_internal_transport"
            and row.get("status") == "blocked"
            for row in expected_completed
        ),
        "planner state omitted the observed control block",
    )
    return record


def _validate_locked_execution_path(
    run: Mapping[str, Any], expected_path: Sequence[tuple[str, str, str, str]]
) -> None:
    steps = _list(run.get("steps"), "run steps")
    actual_path = tuple(
        (
            row.get("step_id"),
            row.get("behavior_id"),
            row.get("action_id"),
            row.get("status"),
        )
        for row in steps
        if isinstance(row, Mapping)
    )
    _require(
        len(actual_path) == len(steps) and actual_path == tuple(expected_path),
        "frontier execution path is not the locked scenario path",
    )


def _validate_run_semantics(
    canonical: Mapping[str, Any],
    frontier: Mapping[str, Any],
    replay: Mapping[str, Any],
) -> Mapping[str, int]:
    runs = (canonical, frontier, replay)
    _require(
        all(
            run.get("status") == "completed" and run.get("objective_reached") is True
            for run in runs
        ),
        "a frontier objective was not reached",
    )
    _require(
        [run.get("runner_profile_id") for run in runs]
        == [CANONICAL_PROFILE_ID, FRONTIER_PROFILE_ID, CANONICAL_PROFILE_ID],
        "frontier profile ordering is invalid",
    )
    expected_paths = (_CANONICAL_PATH, _FRONTIER_PATH, _CANONICAL_PATH)
    for run, expected_path in zip(runs, expected_paths, strict=True):
        _validate_locked_execution_path(run, expected_path)
        try:
            expected_plan = DeterministicPlanner(load_builtin_registry()).compile(
                ScenarioDefinition.from_mapping(run.get("scenario")),
                mode=ExecutionMode.EXECUTE,
                profile=RunnerProfile.from_mapping(run.get("profile")),
                autonomy=AutonomyLevel(run.get("autonomy")),
                ai_provider=_mapping(run.get("ai_provider"), "run AI provider"),
            )
        except (PlannerError, TypeError, ValueError) as exc:
            raise DefenseFrontierValidationError(
                "frontier approved plan could not be independently compiled"
            ) from exc
        _require(
            run.get("plan") == expected_plan.to_dict(),
            "frontier approved plan does not match the maintained scenario and registry",
        )
    for run in runs:
        _validate_native_execution(run)
    approvals = [_approval_id(run) for run in runs]
    _require(len(set(approvals)) == 3, "frontier approvals were reused")
    approved_by = [_mapping(run.get("approval"), "run approval").get("approved_by") for run in runs]
    _require(
        len(set(approved_by)) == 3,
        "frontier Execute runs did not use independent approval decisions",
    )
    for run in runs:
        _cleanup(run)
        _require(bool(_observed(run)), "a run lacks independent collector evidence")
    canonical_transport = _step(canonical, "try_internal_transport")
    replay_transport = _step(replay, "try_internal_transport")
    _require(
        canonical_transport is not None
        and canonical_transport.get("status") == "success"
        and replay_transport is not None
        and replay_transport.get("status") == "success",
        "authenticated canonical transport did not execute twice",
    )
    _require(
        _step(canonical, "preserve_approved_copy") is None
        and _step(replay, "preserve_approved_copy") is None,
        "canonical runs unexpectedly executed the fallback",
    )
    blocked = _mapping(_step(frontier, "try_internal_transport"), "frontier blocked step")
    blocked_policy = _mapping(blocked.get("policy"), "frontier blocked policy")
    alternate = _mapping(_step(frontier, "preserve_approved_copy"), "frontier alternate step")
    _require(
        blocked.get("status") == "blocked"
        and blocked_policy.get("status") == "control_blocked"
        and blocked.get("receipts", []) in ([], ()),
        "frontier prevention was not a pre-dispatch control block",
    )
    _require(
        alternate.get("behavior_id") == "sandbox.export.local.v1"
        and alternate.get("action_id") == "sandbox.export.local.v1"
        and alternate.get("status") == "success",
        "frontier alternate action did not execute",
    )
    _require(
        len(_export_observed(frontier)) == 1
        and not _export_observed(canonical)
        and not _export_observed(replay),
        "frontier export evidence is not path-specific",
    )
    _validate_planner(frontier)
    lineage = _mapping(replay.get("replay"), "replay lineage")
    _require(
        lineage.get("source_run_id") == frontier.get("run_id")
        and lineage.get("defense_change") == DEFENSE_CHANGE_NOTE
        and lineage.get("profile_changed") is True,
        "defense replay lineage is invalid",
    )
    observed_matches = {
        "canonical": _detection_observed_count(canonical, "sandbox.export.local.v1"),
        "frontier": _detection_observed_count(frontier, "sandbox.export.local.v1"),
        "replay": _detection_observed_count(replay, "sandbox.export.local.v1"),
    }
    _require(
        observed_matches == {"canonical": 0, "frontier": 1, "replay": 0},
        "frontier detection outcomes did not differ",
    )
    return observed_matches


def _validate_journey(
    report: Mapping[str, Any],
    runs: Sequence[Mapping[str, Any]],
    refs: Sequence[Mapping[str, str]],
    observed_matches: Mapping[str, int],
    repository: Path,
) -> None:
    _exact(
        report,
        {
            "schema_version",
            "passed",
            "scenario",
            "runner",
            "executions",
            "run_bundles",
            "planner_adaptation",
            "receiver_observation",
            "checks",
        },
        "journey report",
    )
    _require(
        report.get("schema_version") == JOURNEY_SCHEMA and report.get("passed") is True,
        "journey report did not pass",
    )
    scenario = _mapping(report.get("scenario"), "journey scenario")
    _exact(
        scenario,
        {"scenario_id", "scenario_digest", "transport_port_source"},
        "journey scenario",
    )
    runtime_scenario = _mapping(runs[0].get("scenario"), "runtime frontier scenario")
    maintained_scenario = json_clone(
        load_scenario(repository / "scenarios" / "ai_adaptive_safe_chain.yaml").to_dict()
    )
    runtime_transport = [
        row
        for row in _list(runtime_scenario.get("steps"), "runtime scenario steps")
        if isinstance(row, Mapping) and row.get("id") == "try_internal_transport"
    ]
    maintained_transport = [
        row
        for row in _list(maintained_scenario.get("steps"), "maintained scenario steps")
        if isinstance(row, Mapping) and row.get("id") == "try_internal_transport"
    ]
    _require(
        len(runtime_transport) == 1 and len(maintained_transport) == 1,
        "frontier scenario transport step is ambiguous",
    )
    runtime_parameters = _mapping(
        runtime_transport[0].get("parameters"), "runtime transport parameters"
    )
    maintained_parameters = _mapping(
        maintained_transport[0].get("parameters"), "maintained transport parameters"
    )
    runtime_port = runtime_parameters.get("port")
    _require(
        isinstance(runtime_port, int)
        and not isinstance(runtime_port, bool)
        and 1 <= runtime_port <= 65_535,
        "frontier runtime port is invalid",
    )
    maintained_parameters["port"] = runtime_port
    _require(
        scenario.get("scenario_id") == SCENARIO_ID
        and scenario.get("transport_port_source") == "operating-system-assigned-loopback"
        and scenario.get("scenario_digest") == content_hash(runtime_scenario)
        and runtime_scenario == maintained_scenario
        and all(run.get("scenario") == runtime_scenario for run in runs),
        "journey scenario binding is invalid",
    )
    runner = _mapping(report.get("runner"), "journey runner")
    _exact(
        runner,
        {
            "source",
            "runner_id",
            "runner_version",
            "platform",
            "architecture",
            "binary_sha256",
        },
        "journey runner",
    )
    native_root = repository / "bluefire" / "native"
    manifest = load_runner_manifest(resource_root=native_root)
    _require(
        runner
        == {
            "source": "packaged",
            "runner_id": manifest.runner_id,
            "runner_version": manifest.runner_version,
            "platform": manifest.platform,
            "architecture": manifest.architecture,
            "binary_sha256": file_hash(native_root / manifest.filename),
        },
        "journey runner is not bound to the packaged native artifact",
    )
    raw_refs = _list(report.get("run_bundles"), "journey run bundles", length=3)
    _require(raw_refs == list(refs), "journey run bundle references are invalid")
    executions = _list(report.get("executions"), "journey executions", length=3)
    _require(
        executions
        == [
            _execution_summary(runs[0], "canonical"),
            _execution_summary(runs[1], "frontier_alternate"),
            _execution_summary(runs[2], "controlled_replay"),
        ],
        "journey execution summaries are invalid",
    )
    adaptation = _mapping(report.get("planner_adaptation"), "journey planner adaptation")
    _require(
        adaptation
        == {
            "provider_id": PROVIDER_ID,
            "blocked_step_id": "try_internal_transport",
            "selected_step_id": "preserve_approved_copy",
            "selected_behavior_id": "sandbox.export.local.v1",
            "selected_action_id": "sandbox.export.local.v1",
            "selection_kind": "registered-blocked-edge-successor",
            "structured_state_schema": "bluefire.planner-state.v1",
        },
        "journey planner adaptation summary is invalid",
    )
    receiver = _mapping(report.get("receiver_observation"), "receiver observation")
    _exact(
        receiver,
        {"summary", "accepted_artifact_bindings", "credentialed_task_ids"},
        "receiver observation",
    )
    expected_bindings = [
        _transport_receiver_binding(runs[0]),
        _transport_receiver_binding(runs[2]),
    ]
    _require(
        receiver.get("summary")
        == {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 4,
            "challenges_issued": 2,
            "requests_accepted": 2,
            "requests_refused": 0,
        }
        and receiver.get("accepted_artifact_bindings") == expected_bindings
        and receiver.get("credentialed_task_ids")
        == [binding["task_id"] for binding in expected_bindings],
        "receiver observation is invalid",
    )
    checks = _mapping(report.get("checks"), "journey checks")
    _require(
        checks.get("export_detection_matches") == observed_matches,
        "journey detection check drifted",
    )
    expected_true = {
        "canonical_transport_executed",
        "frontier_control_blocked",
        "structured_planner_state",
        "registered_alternate_selected",
        "policy_and_fresh_approvals",
        "alternate_objective_reached",
        "independent_observation",
        "cleanup_verified",
        "controlled_replay",
    }
    _require(
        set(checks) == expected_true | {"export_detection_matches"}
        and all(checks.get(key) is True for key in expected_true),
        "journey checks are incomplete",
    )


def validate_persisted_frontier(
    repository: Path,
    evidence_dir: Path,
) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
    """Recompute every material GATE-04 claim from immutable run bundles."""

    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    journey = load_report(destination / JOURNEY_REPORT)
    defense = load_report(destination / DEFENSE_REPORT)
    comparison = load_report(destination / COMPARISON_REPORT)
    structural = load_report(destination / STRUCTURAL_REPORT)
    raw_refs = _list(journey.get("run_bundles"), "journey run bundles", length=3)
    refs: tuple[Mapping[str, str], ...] = tuple(
        {
            "run_id": str(_mapping(item, "run bundle reference").get("run_id")),
            "path": str(item.get("path")),
        }
        for item in raw_refs
    )
    _require(
        all(ref["path"] == f"runs/{ref['run_id']}" for ref in refs)
        and len({ref["run_id"] for ref in refs}) == 3,
        "frontier run bundle references are invalid",
    )
    store = RunStore(destination / "runs")
    for ref in refs:
        _require(
            store.validate_bundle(ref["run_id"]).get("valid") is True,
            "a frontier run bundle is invalid",
        )
    runs = tuple(store.get_run(ref["run_id"]) for ref in refs)
    observed_matches = _validate_run_semantics(*runs)
    _validate_journey(journey, runs, refs, observed_matches, root)
    _validate_defense(defense, *runs)
    _validate_comparison(comparison, store, [ref["run_id"] for ref in refs])
    _validate_structural(structural, root)
    checks = {
        "canonical_block": True,
        "independent_observation": True,
        "structured_planner_state": True,
        "valid_alternate_selection": True,
        "policy_approval": True,
        "alternate_objective": True,
        "evidence_detection_delta": True,
        "defense_change": True,
        "replay": True,
        "compare_explanation": True,
        "deterministic_provider": True,
        "real_provider_contract": True,
    }
    return checks, refs


__all__ = [
    "DefenseFrontierValidationError",
    "load_report",
    "validate_persisted_frontier",
]
