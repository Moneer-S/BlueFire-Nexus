"""Independent byte and persisted-run authority for the Gate 11 proof."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from .approvals import execution_intent_id
from .config import ConfigError, EnvironmentType, RunnerProfile, load_config
from .contracts import ContractError, SafetyTier, ScenarioDefinition, load_scenario
from .cross_platform_artifact_validation import validate_run_readiness
from .cross_platform_observation_validation import (
    CrossPlatformObservationValidationError,
    validate_observed_filesystem_evidence,
)
from .evidence import EvidenceError, EvidenceGraph, EvidenceProvenance, EvidenceRecord
from .planner import PlanStep
from .run_store import RunStore, RunStoreError
from .runner_adapter import RunnerActionAdapter, RunnerAdapterError
from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECEIPT = re.compile(r"^[0-9a-f]{64}$")
_TASK = re.compile(r"^execute-[0-9a-f]{64}$")
_DECISION = re.compile(r"^decision-[0-9a-f]{20}$")
_EVIDENCE = re.compile(r"^evidence-[0-9a-f]{20}$")
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _fields(value: str) -> set[str]:
    return set(value.split())


_BUNDLE_FILES = frozenset(
    _fields(
        "detections.json evidence.json events.jsonl plan.json policy.json profile.json result.json scenario.json"
    )
)
_PLAN_FIELDS = _fields(
    "step_id behavior_id action_id simulation_id parameters inputs expected_outputs "
    "required_capabilities safety_tier alternates"
)
_RESULT_FIELDS = _fields(
    "schema_version step_id behavior_id action_id simulation_id status execution_disposition "
    "artifacts telemetry evidence_ids policy runner_status request_hash receipts cleanup error runner_task_id planner_decision_id"
)


def _same(rows: Sequence[tuple[str, str]]) -> tuple[tuple[str, str, str], ...]:
    return tuple((step, action, action) for step, action in rows)


_WINDOWS_STEPS = _same(
    (
        ("run_native_canary", "sandbox.execution.native-canary.v1"),
        ("discover_system", "endpoint.discovery.system.v1"),
        ("discover_processes", "endpoint.discovery.processes.v1"),
        ("create_fixture", "sandbox.fixture.create.v1"),
        ("transform_fixture", "sandbox.fixture.transform.v1"),
        ("inspect_fixture_metadata", "sandbox.discovery.metadata.v1"),
        ("stage_records", "sandbox.collection.stage.v1"),
        ("create_persistence_canary", "sandbox.restricted.persistence-marker.v1"),
        ("create_observability_variant", "sandbox.observability.variant.v1"),
    )
) + (
    ("authorized_peer_handoff", "sandbox.credential.peer-challenge.v1", "sandbox.peer.handoff.v1"),
    ("cleanup_workspace", "sandbox.cleanup.v1", "sandbox.cleanup.v1"),
)
_LINUX_PLAN = _same(
    (
        ("create_fixture", "sandbox.fixture.create.v1"),
        ("discover_system", "endpoint.discovery.system.v1"),
        ("discover_processes", "endpoint.discovery.processes.v1"),
        ("discover_files", "sandbox.discovery.recursive.v1"),
        ("archive_files", "sandbox.archive.tar.v1"),
        ("transform_fixture", "sandbox.fixture.transform.v1"),
        ("enumerate_fixture", "sandbox.discovery.list.v1"),
        ("stage_records", "sandbox.collection.stage.v1"),
        ("internal_transport", "sandbox.network.loopback.v1"),
        ("approved_fallback", "sandbox.export.local.v1"),
        ("cleanup_workspace", "sandbox.cleanup.v1"),
    )
)
_LINUX_STEPS = tuple(row for row in _LINUX_PLAN if row[0] != "approved_fallback")
_RUN_CONTRACT = {
    "windows": (
        "scenario.endpoint.deep-behavior-lab.v1",
        "sandbox-endpoint-deep-lab.v1",
        _WINDOWS_STEPS,
        _WINDOWS_STEPS,
    ),
    "linux": (
        "scenario.linux-container.validation.v1",
        "sandbox-execute.v1",
        _LINUX_PLAN,
        _LINUX_STEPS,
    ),
}
_RECEIPT_STEPS = {
    "windows": frozenset(
        {
            "create_fixture",
            "transform_fixture",
            "stage_records",
            "create_persistence_canary",
            "create_observability_variant",
        }
    ),
    "linux": frozenset({"create_fixture", "archive_files", "transform_fixture", "stage_records"}),
}


class CrossPlatformRunValidationError(ValueError):
    """Raised when independent bytes or a persisted Execute run are invalid."""


def _require(condition: object, message: str) -> None:
    if not condition:
        raise CrossPlatformRunValidationError(message)


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping) and set(value) == fields, f"{label} fields are invalid")
    return cast(Mapping[str, Any], value)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "a persisted JSON object contains duplicate keys")
        result[key] = value
    return result


def _json(payload: bytes, label: str) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CrossPlatformRunValidationError(f"{label} is not strict JSON") from exc


def _is_link(details: Any) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE
    )


def _safe_directory(path: Path, label: str) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise CrossPlatformRunValidationError(f"{label} is unavailable") from exc
    _require(stat.S_ISDIR(details.st_mode) and not _is_link(details), f"{label} is unsafe")


def _file_identity(row: Any) -> tuple[Any, ...]:
    return row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_nlink


def _safe_file(path: Path, maximum: int, label: str) -> tuple[int, str, bytes]:
    try:
        before = path.lstat()
        _require(
            stat.S_ISREG(before.st_mode)
            and not _is_link(before)
            and before.st_nlink == 1
            and 1 <= before.st_size <= maximum,
            f"{label} is not a safe bounded file",
        )
        payload = path.read_bytes()
        after = path.lstat()
    except CrossPlatformRunValidationError:
        raise
    except OSError as exc:
        raise CrossPlatformRunValidationError(f"{label} is unavailable") from exc
    _require(
        _file_identity(before) == _file_identity(after) and len(payload) == before.st_size,
        f"{label} changed",
    )
    return len(payload), "sha256:" + hashlib.sha256(payload).hexdigest(), payload


def _canonical_bundle(root: Path, run_id: str) -> Mapping[str, Any]:
    bundle = root / "runs" / run_id
    _safe_directory(bundle, f"run bundle {run_id}")
    try:
        entries = {item.name: item for item in bundle.iterdir()}
    except OSError as exc:
        raise CrossPlatformRunValidationError("run bundle inventory is unavailable") from exc
    _require(set(entries) == _BUNDLE_FILES | {"manifest.json"}, "run bundle inventory is not exact")
    payloads: dict[str, bytes] = {}
    for name, path in entries.items():
        maximum = 64 * 1024 if name == "manifest.json" else 64 * 1024 * 1024
        payloads[name] = _safe_file(path, maximum, f"run bundle {name}")[2]
    documents: dict[str, Any] = {}
    for name in _BUNDLE_FILES - {"events.jsonl"} | {"manifest.json"}:
        value = _json(payloads[name], f"run bundle {name}")
        _require(
            isinstance(value, Mapping) and payloads[name] == canonical_json_bytes(value) + b"\n",
            f"run bundle {name} is not one canonical object",
        )
        documents[name] = value
    event_rows: list[Mapping[str, Any]] = []
    for line in payloads["events.jsonl"].splitlines(keepends=True):
        _require(line.endswith(b"\n"), "run event stream has an unterminated row")
        value = _json(line[:-1], "run event")
        _require(
            isinstance(value, Mapping) and line == canonical_json_bytes(value) + b"\n",
            "run event row is not canonical",
        )
        event_rows.append(value)
    _require(event_rows, "run event stream is empty")
    manifest = _exact(
        documents["manifest.json"],
        {"schema_version", "run_id", "files", "bundle_hash"},
        "run bundle manifest",
    )
    files = manifest.get("files")
    if (
        manifest.get("schema_version") != "1.0"
        or manifest.get("run_id") != run_id
        or not isinstance(files, Mapping)
        or set(files) != _BUNDLE_FILES
    ):
        raise CrossPlatformRunValidationError("run bundle manifest identity is invalid")
    for name in _BUNDLE_FILES:
        descriptor = _exact(files[name], {"hash", "size_bytes"}, f"manifest {name}")
        _require(
            descriptor.get("hash") == "sha256:" + hashlib.sha256(payloads[name]).hexdigest()
            and descriptor.get("size_bytes") == len(payloads[name]),
            f"manifest does not bind {name}",
        )
    _require(manifest.get("bundle_hash") == content_hash(files), "bundle hash is invalid")
    try:
        stored_events = RunStore(root / "runs").read_events(run_id)
    except (OSError, RunStoreError, ValueError) as exc:
        raise CrossPlatformRunValidationError("run event chain is invalid") from exc
    _require(stored_events == event_rows, "run event chain changed during validation")
    documents["events.jsonl"] = event_rows
    return documents


def _strings(value: Any, label: str) -> tuple[str, ...]:
    _require(
        isinstance(value, list)
        and all(isinstance(item, str) and item for item in value)
        and len(value) == len(set(value)),
        f"{label} is not a unique string list",
    )
    return tuple(value)


def _utc(value: Any, label: str) -> datetime:
    _require(isinstance(value, str) and value.endswith("Z"), f"{label} is not UTC")
    try:
        parsed = parse_iso8601_datetime(str(value))
    except ValueError as exc:
        raise CrossPlatformRunValidationError(f"{label} is not UTC") from exc
    _require(parsed.tzinfo == timezone.utc, f"{label} is not UTC")
    return parsed


def _plan_step(value: Any) -> PlanStep:
    fields = _PLAN_FIELDS | (
        {"execution_binding"}
        if isinstance(value, Mapping) and "execution_binding" in value
        else set()
    )
    row = _exact(value, fields, "plan step")
    for name in ("step_id", "behavior_id", "action_id"):
        _require(isinstance(row.get(name), str) and row[name], f"plan step {name} is invalid")
    _require(
        row.get("simulation_id") is None or isinstance(row.get("simulation_id"), str),
        "plan simulation identity is invalid",
    )
    parameters = row.get("parameters")
    inputs = row.get("inputs")
    binding = row.get("execution_binding")
    if (
        not isinstance(parameters, Mapping)
        or not isinstance(inputs, Mapping)
        or not all(
            isinstance(key, str) and isinstance(item, Mapping) for key, item in inputs.items()
        )
        or (binding is not None and not isinstance(binding, Mapping))
    ):
        raise CrossPlatformRunValidationError("plan step mappings are invalid")
    try:
        step = PlanStep(
            step_id=str(row["step_id"]),
            behavior_id=str(row["behavior_id"]),
            action_id=str(row["action_id"]),
            simulation_id=row.get("simulation_id"),
            parameters=dict(parameters),
            inputs={str(key): dict(item) for key, item in inputs.items()},
            expected_outputs=_strings(row.get("expected_outputs"), "plan expected outputs"),
            required_capabilities=_strings(row.get("required_capabilities"), "plan capabilities"),
            safety_tier=SafetyTier(row.get("safety_tier")),
            alternates=_strings(row.get("alternates"), "plan alternates"),
            execution_binding=dict(binding) if isinstance(binding, Mapping) else None,
        )
    except (TypeError, ValueError) as exc:
        raise CrossPlatformRunValidationError("plan step could not be rehydrated") from exc
    _require(step.to_dict() == dict(row), "plan step does not round-trip")
    return step


def _policy_decision(value: Any, step: PlanStep, profile_id: str) -> None:
    row = _exact(
        value,
        _fields(
            "schema_version status step_id behavior_id action_id runner_profile_id reasons "
            "required_approvals evaluated_capabilities target_scope_digest policy_digest"
        ),
        "step policy decision",
    )
    reasons = _strings(row.get("reasons"), "policy reasons")
    approvals = _strings(row.get("required_approvals"), "policy approvals")
    capabilities = _strings(row.get("evaluated_capabilities"), "policy capabilities")
    body = {
        "status": row.get("status"),
        "step_id": step.step_id,
        "behavior_id": step.behavior_id,
        "action_id": step.action_id,
        "runner_profile_id": profile_id,
        "reasons": list(reasons),
        "capabilities": list(capabilities),
        "target_scope_digest": row.get("target_scope_digest"),
    }
    _require(
        row.get("schema_version") == "bluefire.policy-decision.v1"
        and row.get("status") == "allowed"
        and row.get("step_id") == step.step_id
        and row.get("behavior_id") == step.behavior_id
        and row.get("action_id") == step.action_id
        and row.get("runner_profile_id") == profile_id
        and reasons == ("request is within the registered action and selected profile",)
        and approvals == ("operator",)
        and capabilities == step.required_capabilities
        and _SHA256.fullmatch(str(row.get("target_scope_digest"))) is not None
        and row.get("policy_digest") == content_hash(body),
        "step policy decision is not a bound allow decision",
    )


def _receipt_ids(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key == "receipt_ids":
                _require(isinstance(item, list), "artifact receipt binding is not a list")
                for receipt_id in item:
                    _require(
                        isinstance(receipt_id, str) and _RECEIPT.fullmatch(receipt_id) is not None,
                        "artifact receipt identity is invalid",
                    )
                    found.add(receipt_id)
            else:
                found.update(_receipt_ids(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_receipt_ids(item))
    return found


def _event_payloads(events: Sequence[Mapping[str, Any]], event_type: str) -> list[Any]:
    return [item.get("data") for item in events if item.get("event_type") == event_type]


def _nested_evidence(
    value: Any,
    *,
    outer: EvidenceRecord,
    step: Mapping[str, Any],
    platform: str,
    profile_id: str,
) -> None:
    row = _exact(
        value,
        _fields(
            "evidence_id kind producer request_hash policy_digest action_id behavior_id runner_id "
            "runner_profile_id platform recorded_at references details"
        ),
        "nested runner evidence",
    )
    details = _exact(
        row.get("details"),
        {"status", "output_hash", "receipt_ids", "stdout_total_bytes", "stderr_total_bytes"},
        "nested runner evidence details",
    )
    body = dict(row)
    body["evidence_id"] = ""
    content = outer.content
    stdout = _exact(content.get("stdout"), {"text", "total_bytes", "truncated"}, "runner stdout")
    stderr = _exact(content.get("stderr"), {"text", "total_bytes", "truncated"}, "runner stderr")
    for stream, label in ((stdout, "stdout"), (stderr, "stderr")):
        text = stream.get("text")
        total = stream.get("total_bytes")
        _require(
            isinstance(text, str)
            and type(total) is int
            and len(text.encode("utf-8")) <= total <= 4 * 1024 * 1024
            and isinstance(stream.get("truncated"), bool),
            f"runner {label} is invalid",
        )
    _require(
        row.get("evidence_id") == content_hash(body)
        and row.get("kind") == "executed"
        and row.get("producer") == "bluefire-rust-runner"
        and row.get("request_hash") == step.get("request_hash") == content.get("request_hash")
        and row.get("policy_digest") == content.get("policy_digest")
        and _SHA256.fullmatch(str(row.get("policy_digest"))) is not None
        and row.get("action_id") == step.get("action_id")
        and row.get("behavior_id") == step.get("behavior_id")
        and row.get("runner_id") == "bluefire-rust-runner.v1"
        and row.get("runner_profile_id") == profile_id
        and row.get("platform") == platform
        and _utc(row.get("recorded_at"), "nested evidence recorded_at") is not None
        and isinstance(row.get("references"), list)
        and all(
            isinstance(item, str) and _EVIDENCE.fullmatch(item) is not None
            for item in row["references"]
        )
        and row.get("references") == list(outer.parent_evidence_ids)
        and details.get("status") == step.get("runner_status") == content.get("runner_status")
        and details.get("output_hash") == content_hash(content.get("output"))
        and details.get("receipt_ids") == step.get("receipts")
        and details.get("stdout_total_bytes") == stdout.get("total_bytes")
        and details.get("stderr_total_bytes") == stderr.get("total_bytes"),
        "nested runner evidence is not cryptographically bound",
    )


def _observed_evidence(
    record: EvidenceRecord, outer: EvidenceRecord, step: Mapping[str, Any]
) -> None:
    try:
        validate_observed_filesystem_evidence(record, outer, step)
    except CrossPlatformObservationValidationError as exc:
        raise CrossPlatformRunValidationError(str(exc)) from exc


def validate_persisted_run(
    root: Path,
    reference: Mapping[str, str],
    *,
    repository: Path,
    acceptance_binding: Mapping[str, str],
    platform: str,
    runner: Mapping[str, Any],
    execution: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Strictly rehydrate one nonempty Execute run and return cross-report facts."""
    run_id = reference["run_id"]
    docs = _canonical_bundle(root, run_id)
    scenario_id, profile_id, plan_rows, result_rows = _RUN_CONTRACT[platform]
    try:
        scenario = ScenarioDefinition.from_mapping(docs["scenario.json"], "persisted scenario")
        profile = RunnerProfile.from_mapping(docs["profile.json"], "persisted runner profile")
        config = load_config(repository / "bluefire" / "data" / "bluefire.example.yaml")
        canonical_profile = next(item for item in config.runner_profiles if item.id == profile_id)
        scenario_path = (
            repository / "scenarios" / "endpoint_deep_behavior_lab.yaml"
            if platform == "windows"
            else repository / "bluefire" / "data" / "linux_container_validation.yaml"
        )
        canonical_scenario = load_scenario(scenario_path).to_dict()
    except (
        ConfigError,
        ContractError,
        KeyError,
        OSError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        raise CrossPlatformRunValidationError(
            "scenario or profile could not be rehydrated"
        ) from exc
    dynamic_step = "authorized_peer_handoff" if platform == "windows" else "internal_transport"
    try:
        persisted_dynamic = next(
            item for item in scenario.to_dict()["steps"] if item["id"] == dynamic_step
        )
        port = persisted_dynamic["parameters"].get("port")
        canonical_dynamic = next(
            item for item in canonical_scenario["steps"] if item["id"] == dynamic_step
        )
        canonical_dynamic["parameters"]["port"] = port
    except (KeyError, StopIteration, TypeError) as exc:
        raise CrossPlatformRunValidationError(
            "scenario dynamic receiver binding is invalid"
        ) from exc
    _require(
        scenario.id == scenario_id
        and scenario.to_dict() == canonical_scenario
        and type(port) is int
        and 1024 <= port <= 65535
        and profile.to_dict() == canonical_profile.to_dict()
        and tuple((step.id, step.behavior_id) for step in scenario.steps)
        == tuple((step, behavior) for step, behavior, _action in plan_rows)
        and profile.id == profile_id
        and profile.mode.value == "execute"
        and profile.environment_type is EnvironmentType.DISPOSABLE
        and platform in profile.platforms
        and set(action for _step, _behavior, action in plan_rows) <= set(profile.enabled_actions),
        f"{platform} scenario/profile identity is invalid",
    )
    plan = _exact(
        docs["plan.json"],
        _fields(
            "schema_version scenario_id objective mode ai_enabled autonomy ai_provider "
            "runner_profile_id scenario_digest steps edges"
        ),
        "persisted plan",
    )
    raw_plan_steps = plan.get("steps")
    _require(isinstance(raw_plan_steps, list) and raw_plan_steps, "persisted plan is empty")
    plan_step_rows = cast(list[Any], raw_plan_steps)
    plan_steps = tuple(_plan_step(item) for item in plan_step_rows)
    _require(
        plan.get("schema_version") == "bluefire.plan.v1"
        and plan.get("scenario_id") == scenario.id
        and plan.get("objective") == scenario.purpose
        and plan.get("mode") == "execute"
        and plan.get("ai_enabled") is False
        and plan.get("autonomy") == "off"
        and plan.get("runner_profile_id") == profile.id
        and plan.get("scenario_digest") == content_hash(scenario.to_dict())
        and plan.get("edges") == [edge.to_dict() for edge in scenario.edges]
        and tuple((step.step_id, step.behavior_id, step.action_id) for step in plan_steps)
        == plan_rows,
        f"{platform} plan is not the exact reviewed graph",
    )
    policy = _exact(
        docs["policy.json"],
        _fields(
            "schema_version preflight decisions ai_proposals authorized_target_scope autonomy "
            "ai_provider approval approval_binding approval_context runner_readiness catalog_authority"
        ),
        "persisted run policy",
    )
    inventory_digest = validate_run_readiness(
        policy.get("runner_readiness"), profile, platform, runner
    )
    scope = ["sandbox.workspace", "network.loopback"]
    if platform == "linux":
        scope.append("export.local")
    _require(
        policy.get("schema_version") == "bluefire.run-policy.v1"
        and policy.get("authorized_target_scope") == {"scope_refs": scope}
        and policy.get("autonomy") == plan.get("autonomy")
        and policy.get("ai_provider") == plan.get("ai_provider")
        and policy.get("ai_proposals") == []
        and policy.get("catalog_authority") == policy["runner_readiness"].get("catalog_authority"),
        "persisted run policy is not exact",
    )
    result = _exact(
        docs["result.json"],
        _fields(
            "schema_version run_id created_at finalized_at acceptance_binding status mode ai_enabled "
            "autonomy ai_provider runner_profile_id approval authorized_target_scope scenario_id objective "
            "objective_reached approval_pause objective_evaluation steps materialization_steps "
            "checkpoint_materialization replay_checkpoints planner_decisions ai_proposals cleanup replay "
            "collector_session limitations runtime_budget adaptive_retry"
        ),
        "persisted run result",
    )
    raw_steps = result.get("steps")
    cleanup = result.get("cleanup")
    _require(isinstance(raw_steps, list) and raw_steps, "persisted Execute result is empty")
    run_steps = cast(list[Mapping[str, Any]], raw_steps)
    created = _utc(result.get("created_at"), "run created_at")
    finalized = _utc(result.get("finalized_at"), "run finalized_at")
    approval = _exact(
        result.get("approval"),
        _fields(
            "schema_version approval_id run_id state_digest plan_digest profile_id target_scope_digest "
            "maximum_tier status requested_at expires_at approved_at approved_by consumed_at claimed_at"
        ),
        "run approval",
    )
    approval_binding = _exact(
        policy.get("approval_binding"),
        _fields("state_digest plan_digest target_scope_digest profile_id maximum_tier"),
        "run approval binding",
    )
    evaluation = _exact(
        result.get("objective_evaluation"),
        _fields(
            "terminal_step_id terminal_status cleanup_required cleanup_forced cleanup_satisfied"
        ),
        "run objective evaluation",
    )
    budget = _exact(
        result.get("runtime_budget"),
        _fields(
            "configured_seconds configured_steps consumed_steps remaining_steps cleanup_reserve_seconds "
            "elapsed_seconds collector_elapsed_seconds exhausted"
        ),
        "run runtime budget",
    )
    expected_reserve = min(
        5.0, max(0.25, profile.budgets.max_seconds * 0.1), profile.budgets.max_seconds / 2.0
    )
    approval_times = [
        _utc(approval.get(name), f"approval {name}")
        for name in ("requested_at", "approved_at", "consumed_at", "claimed_at", "expires_at")
    ]
    _require(
        result.get("schema_version") == "bluefire.run-result.v1"
        and result.get("run_id") == run_id == execution.get("run_id")
        and result.get("mode") == "execute"
        and result.get("status") == "completed"
        and result.get("objective_reached") is True
        and result.get("runner_profile_id") == profile.id
        and result.get("scenario_id") == scenario.id
        and result.get("acceptance_binding") == dict(acceptance_binding)
        and created <= finalized
        and result.get("authorized_target_scope") == policy.get("authorized_target_scope")
        and result.get("objective") == scenario.purpose
        and result.get("autonomy") == plan.get("autonomy")
        and result.get("ai_provider") == plan.get("ai_provider")
        and result.get("ai_enabled") is False
        and result.get("approval_pause") is None
        and result.get("materialization_steps") == []
        and result.get("checkpoint_materialization") is None
        and result.get("replay_checkpoints") == []
        and result.get("replay") is None
        and result.get("ai_proposals") == []
        and result.get("collector_session") is None
        and result.get("limitations") == list(scenario.limitations)
        and evaluation
        == {
            "terminal_step_id": result_rows[-2][0],
            "terminal_status": run_steps[-2].get("status"),
            "cleanup_required": True,
            "cleanup_forced": False,
            "cleanup_satisfied": True,
        }
        and budget.get("configured_seconds") == float(profile.budgets.max_seconds)
        and budget.get("configured_steps") == profile.budgets.max_steps
        and budget.get("consumed_steps") == len(run_steps)
        and budget.get("remaining_steps") == max(profile.budgets.max_steps - len(run_steps), 0)
        and budget.get("cleanup_reserve_seconds") == expected_reserve
        and type(budget.get("elapsed_seconds")) in {int, float}
        and 0 <= budget["elapsed_seconds"] <= profile.budgets.max_seconds
        and type(budget.get("collector_elapsed_seconds")) in {int, float}
        and 0 <= budget["collector_elapsed_seconds"] <= budget["elapsed_seconds"]
        and budget.get("exhausted") is False
        and result.get("adaptive_retry") == {"maximum": 1, "used": 0, "remaining": 1}
        and approval.get("schema_version") == "bluefire.approval-request.v1"
        and isinstance(approval.get("approval_id"), str)
        and str(approval["approval_id"]).startswith("approval-")
        and approval.get("run_id") == execution_intent_id(approval_binding)
        and approval.get("status") == "claimed"
        and approval.get("approved_by")
        == (
            "gate-11-runtime-reviewer"
            if platform == "windows"
            else "gate-11-linux-runtime-reviewer"
        )
        and approval.get("plan_digest") == content_hash(plan)
        and approval.get("target_scope_digest")
        == content_hash(policy.get("authorized_target_scope"))
        and approval.get("profile_id") == profile.id
        and {key: approval.get(key) for key in approval_binding} == dict(approval_binding)
        and policy.get("approval") == approval
        and approval_times[0]
        <= approval_times[1]
        <= approval_times[2]
        <= approval_times[3]
        <= finalized
        < approval_times[4]
        and cleanup == {"attempted": True, "success": True, "outstanding_receipt_count": 0}
        and len(run_steps) == execution.get("step_count") == len(result_rows),
        f"{platform} run is not a completed nonempty Execute proof",
    )
    adapter = RunnerActionAdapter()
    plan_by_id = {step.step_id: step for step in plan_steps}
    prior: dict[str, Mapping[str, Any]] = {}
    all_receipts: list[str] = []
    step_by_id: dict[str, Mapping[str, Any]] = {}
    for index, (raw, expected) in enumerate(zip(run_steps, result_rows, strict=True)):
        step = plan_by_id[expected[0]]
        fields = _RESULT_FIELDS | (
            {"execution_binding"} if step.execution_binding is not None else set()
        )
        row = _exact(raw, fields, f"{platform} step result")
        _require(
            (row.get("step_id"), row.get("behavior_id"), row.get("action_id")) == expected
            and row.get("simulation_id") == step.simulation_id
            and row.get("status") in {"success", "partial"}
            and row.get("runner_status") == row.get("status")
            and row.get("execution_disposition") == "execute"
            and row.get("error") is None
            and isinstance(row.get("artifacts"), Mapping)
            and bool(row["artifacts"])
            and isinstance(row.get("telemetry"), list)
            and bool(row["telemetry"])
            and isinstance(row.get("evidence_ids"), list)
            and bool(row["evidence_ids"])
            and len(row["evidence_ids"]) == len(set(row["evidence_ids"]))
            and _SHA256.fullmatch(str(row.get("request_hash"))) is not None
            and _TASK.fullmatch(str(row.get("runner_task_id"))) is not None
            and _DECISION.fullmatch(str(row.get("planner_decision_id"))) is not None
            and row.get("execution_binding") == step.execution_binding,
            f"{platform} step {index} is not genuine Execute output",
        )
        _policy_decision(row.get("policy"), step, profile.id)
        receipts = row.get("receipts")
        _require(isinstance(receipts, list), "step receipt binding is not a list")
        receipt_rows = cast(list[Any], receipts)
        expected_count = 1 if step.step_id in _RECEIPT_STEPS[platform] else 0
        _require(
            len(receipt_rows) == expected_count
            and all(isinstance(item, str) and _RECEIPT.fullmatch(item) for item in receipt_rows),
            f"{platform} step receipt count is invalid",
        )
        all_receipts.extend(cast(list[str], receipt_rows))
        bound: dict[str, Any] = {}
        for name, binding in step.inputs.items():
            source = binding.get("from_step")
            artifact = binding.get("artifact")
            _require(
                isinstance(source, str)
                and source in prior
                and isinstance(artifact, str)
                and artifact in prior[source],
                "plan input does not bind an earlier action artifact",
            )
            bound[name] = prior[cast(str, source)][cast(str, artifact)]
        row_copy = dict(row)
        row_copy["_bound_inputs"] = bound
        step_by_id[step.step_id] = row_copy
        prior[step.step_id] = row["artifacts"]
    _require(len(all_receipts) == len(set(all_receipts)), "run receipt identities are duplicated")
    raw_decisions = result.get("planner_decisions")
    if not isinstance(raw_decisions, list) or len(raw_decisions) != len(run_steps):
        raise CrossPlatformRunValidationError("planner decision lineage is incomplete")
    decision_fields = _fields(
        "schema_version decision_id run_id objective current_state_digest selected_behavior_id selected_action_id "
        "selected_step_id selected_edge execution_disposition prerequisites_considered expected_outputs reason "
        "alternatives_considered policy_evaluation confidence approvals_required remaining_budgets proposed_by"
    )
    for index, (raw_step, raw_decision) in enumerate(zip(run_steps, raw_decisions, strict=True)):
        decision = _exact(raw_decision, decision_fields, "persisted planner decision")
        prefix = [dict(item) for item in run_steps[: index + 1]]
        prefix[-1].pop("planner_decision_id")
        state_digest = content_hash(
            {
                "artifacts": {str(item["step_id"]): item.get("artifacts", {}) for item in prefix},
                "steps": prefix,
            }
        )
        edges = [
            edge.to_dict()
            for edge in scenario.edges
            if edge.from_step == raw_step["step_id"] and edge.outcome.value == raw_step["status"]
        ]
        expected_edge = edges[0] if edges else None
        next_id = expected_edge["to_step"] if expected_edge else None
        next_step = plan_by_id.get(str(next_id)) if next_id is not None else None
        disposition = "execute" if next_step is not None else "stop"
        decision_id = (
            "decision-"
            + content_hash(
                {
                    "run_id": run_id,
                    "current_step_id": raw_step["step_id"],
                    "outcome": raw_step["status"],
                    "state_digest": state_digest,
                    "selected_step_id": next_id,
                    "disposition": disposition,
                }
            ).removeprefix("sha256:")[:20]
        )
        _require(
            len(edges) <= 1
            and raw_step.get("planner_decision_id") == decision.get("decision_id") == decision_id
            and decision.get("schema_version") == "bluefire.planner-decision.v1"
            and decision.get("run_id") == run_id
            and decision.get("objective") == scenario.purpose
            and decision.get("current_state_digest") == state_digest
            and decision.get("selected_step_id") == next_id
            and decision.get("selected_edge") == expected_edge
            and decision.get("selected_behavior_id")
            == (next_step.behavior_id if next_step else None)
            and decision.get("selected_action_id") == (next_step.action_id if next_step else None)
            and decision.get("execution_disposition") == disposition
            and decision.get("proposed_by") == "deterministic-planner.v1",
            "planner decision is not bound to the completed run prefix",
        )
    events = docs["events.jsonl"]
    planner_events = _event_payloads(events, "planner.decision")
    finalized_events = _event_payloads(events, "run.finalized")
    _require(
        planner_events == raw_decisions and finalized_events == [result],
        "event stream does not bind planner/final result",
    )
    evidence_doc = _exact(docs["evidence.json"], {"schema_version", "records"}, "run evidence")
    raw_records = evidence_doc.get("records")
    if (
        evidence_doc.get("schema_version") != "1.0"
        or not isinstance(raw_records, list)
        or not raw_records
    ):
        raise CrossPlatformRunValidationError("run evidence is empty")
    graph = EvidenceGraph()
    records: list[EvidenceRecord] = []
    try:
        for raw in raw_records:
            record = EvidenceRecord.from_mapping(raw)
            graph.add(record)
            records.append(record)
    except (EvidenceError, TypeError, ValueError) as exc:
        raise CrossPlatformRunValidationError("run evidence graph could not be rehydrated") from exc
    expected_by_step = {step: (behavior, action) for step, behavior, action in result_rows}
    outer_by_step: dict[str, EvidenceRecord] = {}
    runner_profile_digests: set[str] = set()
    observed_by_step: dict[str, EvidenceRecord] = {}
    for record in records:
        expected_identity = expected_by_step.get(record.step_id)
        _require(
            expected_identity == (record.behavior_id, record.action_id)
            and record.run_id == run_id
            and record.runner_profile_id == profile.id
            and record.provenance in {EvidenceProvenance.EXECUTED, EvidenceProvenance.OBSERVED},
            "run evidence is synthetic, orphaned, or cross-bound",
        )
        if record.provenance is EvidenceProvenance.OBSERVED:
            _require(
                record.step_id not in observed_by_step,
                "run has duplicate independently observed receipt evidence",
            )
            observed_by_step[record.step_id] = record
        if record.provenance is EvidenceProvenance.EXECUTED:
            profile_digest = record.content.get("policy_digest")
            _require(
                record.producer == "bluefire-rust-runner"
                and record.step_id not in outer_by_step
                and record.environment == {"environment_type": "disposable", "platform": platform}
                and record.confidence == 1.0
                and _utc(record.timestamp, "outer evidence timestamp") is not None
                and record.target_scope_ref == f"runner-profile:{profile.id}",
                "outer runner evidence is invalid",
            )
            if not isinstance(profile_digest, str) or _SHA256.fullmatch(profile_digest) is None:
                raise CrossPlatformRunValidationError(
                    "outer runner evidence profile digest is invalid"
                )
            runner_profile_digests.add(profile_digest)
            outer_by_step[record.step_id] = record
    _require(
        set(outer_by_step) == set(expected_by_step)
        and len(runner_profile_digests) == 1
        and set(observed_by_step) == _RECEIPT_STEPS[platform]
        and len(records) == len(expected_by_step) + len(_RECEIPT_STEPS[platform]),
        "run lacks executed or independently observed receipt evidence",
    )
    for record in records:
        if record.provenance is EvidenceProvenance.OBSERVED:
            _observed_evidence(record, outer_by_step[record.step_id], step_by_id[record.step_id])
    for step_id, row in step_by_id.items():
        bound_records = graph.by_step(step_id)
        _require(
            row.get("evidence_ids") == [record.evidence_id for record in bound_records],
            "step evidence IDs do not exhaust their evidence records",
        )
        outer = outer_by_step[step_id]
        content = _exact(
            outer.content,
            {
                "request_hash",
                "runner_task_id",
                "policy_digest",
                "runner_status",
                "runner_evidence",
                "output",
                "stdout",
                "stderr",
                "error",
            },
            "outer runner evidence content",
        )
        nested = content.get("runner_evidence")
        if (
            content.get("runner_task_id") != row.get("runner_task_id")
            or content.get("error") is not None
            or not isinstance(nested, list)
            or len(nested) != 1
        ):
            raise CrossPlatformRunValidationError(
                "outer runner evidence does not bind the task result"
            )
        _nested_evidence(nested[0], outer=outer, step=row, platform=platform, profile_id=profile.id)
        plan_step = plan_by_id[step_id]
        try:
            rebuilt = adapter.logical_outputs(
                plan_step,
                bound_inputs=row["_bound_inputs"],
                runner_output=content.get("output"),
                receipt_ids=cast(Sequence[str], row.get("receipts")),
            )
        except RunnerAdapterError as exc:
            raise CrossPlatformRunValidationError(
                "runner output cannot rebuild action artifacts"
            ) from exc
        _require(rebuilt == row.get("artifacts"), "action artifacts do not match runner evidence")
        artifact_receipts = _receipt_ids(rebuilt)
        _require(
            (
                artifact_receipts == set(cast(Sequence[str], row.get("receipts")))
                if step_id in _RECEIPT_STEPS[platform]
                else not artifact_receipts
            ),
            "action artifact receipt binding is incomplete",
        )
    _require(
        policy.get("decisions") == [row["policy"] for row in run_steps],
        "run policy decisions do not match executed steps",
    )
    cleanup_step = step_by_id["cleanup_workspace"]
    cleanup_report = _exact(
        cleanup_step.get("cleanup"),
        _fields(
            "requested_receipts removed_paths already_absent_receipts retained_paths errors "
            "verification_performed verified_removed_paths verified_absent_paths verified_receipts"
        ),
        "runner cleanup report",
    )
    _require(
        cleanup_report == outer_by_step["cleanup_workspace"].content.get("output")
        and cleanup_report.get("requested_receipts") == len(all_receipts)
        and cleanup_report.get("verified_receipts") == len(all_receipts)
        and cleanup_report.get("already_absent_receipts") == []
        and cleanup_report.get("retained_paths") == []
        and cleanup_report.get("errors") == []
        and cleanup_report.get("verification_performed") is True
        and cleanup_report.get("verified_removed_paths")
        == len(cleanup_report.get("removed_paths", []))
        and type(cleanup_report.get("verified_absent_paths")) is int
        and cleanup_report["verified_absent_paths"] >= 0,
        "receipt cleanup did not verify every persisted receipt binding",
    )
    facts: dict[str, Any] = {
        "run_id": run_id,
        "step_count": len(run_steps),
        "inventory_digest": inventory_digest,
    }
    if platform == "windows":
        peer = step_by_id["authorized_peer_handoff"]
        receipt = peer["artifacts"]["receipt"]
        facts["transfer"] = {
            "run_id": run_id,
            "step_id": peer["step_id"],
            "runner_task_id": peer["runner_task_id"],
            "source_process_id": receipt["lab_peers"]["source_process_id"],
            "destination_process_id": receipt["lab_peers"]["destination_process_id"],
            "authenticated": receipt["lab_authorization"]["challenge_verified"],
            "bytes": receipt["size"],
            "sha256": receipt["sha256"],
        }
    else:
        network = step_by_id["internal_transport"]
        details = network["artifacts"]["receipt"]["details"]
        facts["transfer"] = {
            "run_id": run_id,
            "step_id": network["step_id"],
            "runner_task_id": network["runner_task_id"],
            "authenticated": True,
            "bytes": details["bytes_sent"],
            "sha256": details["sha256"],
        }
    return facts


__all__ = [
    "CrossPlatformRunValidationError",
    "validate_persisted_run",
]
