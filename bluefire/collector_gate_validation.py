"""Independent semantic validation for persisted GATE-05 evidence."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping

from .collector_interfaces import (
    CloudIdentityAuditAdapter,
    LinuxAuditRuntimeAdapter,
    SecurityQueryAdapter,
    WindowsEventLogAdapter,
)
from .collector_journey import (
    COMPARISON_REPORT,
    CORRUPTION_REPORT,
    CORRUPTION_SCHEMA,
    JOURNEY_REPORT,
    JOURNEY_SCHEMA,
    PLATFORM_REPORT,
    PLATFORM_SCHEMA,
)
from .collectors import (
    CollectionSession,
    CollectorError,
    FilesystemCollector,
    LoopbackReceiverCollector,
    NativeProcessCollector,
    filesystem_observation_key,
    optional_collector_descriptors,
    reconcile_observations,
)
from .comparison import compare_runs
from .evidence import EvidenceGraph, EvidenceProvenance, EvidenceRecord
from .run_store import RunStore
from .util import content_hash

_MAX_REPORT_BYTES = 8 * 1024 * 1024
_GATE_COLLECTOR_IDS = frozenset(
    {
        FilesystemCollector.descriptor.id,
        LoopbackReceiverCollector.descriptor.id,
        NativeProcessCollector.descriptor.id,
    }
)
_EXPECTED_DESCRIPTORS = {
    descriptor.id: descriptor.to_dict()
    for descriptor in (
        FilesystemCollector.descriptor,
        LoopbackReceiverCollector.descriptor,
        NativeProcessCollector.descriptor,
    )
}
_EXPECTED_IMPLEMENTATIONS = {
    FilesystemCollector.descriptor.id: "bluefire.collectors.FilesystemCollector",
    LoopbackReceiverCollector.descriptor.id: "bluefire.collectors.LoopbackReceiverCollector",
    NativeProcessCollector.descriptor.id: "bluefire.collectors.NativeProcessCollector",
}
_EXPECTED_REPLAY_LINEAGE_FIELDS = {
    "schema_version",
    "source_run_id",
    "source_scenario_digest",
    "exact",
    "from_step_id",
    "swap_step_id",
    "swap_behavior_id",
    "parameter_overrides",
    "action_implementations_from",
    "action_implementation_overrides",
    "action_implementations_to",
    "action_implementations_changed",
    "action_reselection_steps",
    "ai_changed",
    "autonomy_from",
    "autonomy_to",
    "ai_provider_changed",
    "ai_provider_from",
    "ai_provider_to",
    "profile_changed",
    "defense_change",
    "catalog_authority_from",
    "catalog_authority_to",
    "catalog_authority_changed",
    "collector_settings_from",
    "collector_settings_to",
    "collector_settings_changed",
    "collector_authority_from",
    "collector_authority_to",
    "collector_authority_changed",
}
_EXPECTED_DEFENSE_CHANGE = (
    "collector-gate-network-observer.v1: restore reviewed loopback transport "
    "and enable its independent receiver collector"
)


class CollectorGateValidationError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CollectorGateValidationError(message)


def _read_json(path: Path) -> Mapping[str, Any]:
    _require(path.is_file() and not path.is_symlink(), "GATE-05 report is absent or unsafe")
    _require(path.stat().st_size <= _MAX_REPORT_BYTES, "GATE-05 report exceeds its byte bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CollectorGateValidationError("GATE-05 report is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise CollectorGateValidationError("GATE-05 report must be an object")
    return value


def _session(value: Any) -> CollectionSession:
    if not isinstance(value, Mapping):
        raise CollectorGateValidationError("GATE-05 collection session is absent")
    return CollectionSession.from_mapping(value)


def _observed(session: CollectionSession, collector_id: str) -> tuple[EvidenceRecord, ...]:
    result = session.results.get(collector_id)
    if result is None:
        raise CollectorGateValidationError(f"GATE-05 result is absent for {collector_id}")
    return tuple(
        record for record in result.records if record.provenance is EvidenceProvenance.OBSERVED
    )


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _run_steps(run: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    raw_steps = run.get("steps")
    if not isinstance(raw_steps, list):
        raise CollectorGateValidationError("GATE-05 run steps are absent")
    valid_steps = [
        step
        for step in raw_steps
        if isinstance(step, Mapping) and isinstance(step.get("step_id"), str)
    ]
    steps = {str(step["step_id"]): step for step in valid_steps}
    _require(
        len(valid_steps) == len(raw_steps) == len(steps),
        "GATE-05 run steps are invalid or duplicated",
    )
    return steps


def _validate_session_descriptors(session: CollectionSession) -> None:
    _require(
        set(session.settings.collectors) == set(_EXPECTED_DESCRIPTORS),
        "GATE-05 runtime settings do not name the exact built-in collector set",
    )
    _require(
        all(
            collector_id in _EXPECTED_DESCRIPTORS
            and result.descriptor.to_dict() == _EXPECTED_DESCRIPTORS[collector_id]
            for collector_id, result in session.results.items()
        ),
        "GATE-05 result does not use the exact built-in collector descriptor",
    )


def _approval_context(run: Mapping[str, Any]) -> Mapping[str, Any]:
    policy = run.get("policy")
    context = policy.get("approval_context") if isinstance(policy, Mapping) else None
    if not isinstance(context, Mapping):
        raise CollectorGateValidationError("GATE-05 approved policy context is absent")
    return context


def _authority_source(
    run: Mapping[str, Any],
    session: CollectionSession,
    collector_id: str,
    *,
    receiver_session_id: str | None,
) -> Mapping[str, Any]:
    result = session.results.get(collector_id)
    records = _observed(session, collector_id)
    _require(
        result is not None and len(result.records) == 1 and len(records) == 1,
        f"GATE-05 authority has no unique observation for {collector_id}",
    )
    record = records[0]
    observed = record.content.get("observed_fields")
    settings_row = session.settings.collectors.get(collector_id)
    settings = settings_row.get("settings") if isinstance(settings_row, Mapping) else None
    if collector_id == FilesystemCollector.descriptor.id:
        _require(
            isinstance(settings, Mapping),
            "GATE-05 filesystem authority has no runtime settings",
        )
        return {
            "schema_version": "bluefire.filesystem-source-authority.v1",
            "sandbox_binding": "exact-factory-argument",
            "max_file_bytes": 64 * 1024 * 1024,
            "read_timeout_seconds": 5.0,
            "path_policy": "handle-pinned-contained-no-follow",
        }
    if collector_id == NativeProcessCollector.descriptor.id:
        _require(
            isinstance(settings, Mapping)
            and isinstance(observed, Mapping)
            and settings.get("process_id") == observed.get("process_id")
            and settings.get("expected_parent_process_id") == observed.get("parent_process_id")
            and isinstance(observed.get("creation_identity"), str)
            and str(observed["creation_identity"]).isascii()
            and str(observed["creation_identity"]).isdecimal(),
            "GATE-05 process authority does not match its native observation",
        )
        assert isinstance(observed, Mapping)
        return {
            "schema_version": "bluefire.process-source-authority.v1",
            "authorized_processes": [
                {
                    "process_id": observed["process_id"],
                    "parent_process_id": observed["parent_process_id"],
                    "creation_identity": observed["creation_identity"],
                }
            ],
        }
    if collector_id == LoopbackReceiverCollector.descriptor.id:
        steps = _run_steps(run)
        step = steps.get(record.step_id)
        artifacts = step.get("artifacts") if isinstance(step, Mapping) else None
        receipt = artifacts.get("receipt") if isinstance(artifacts, Mapping) else None
        details = receipt.get("details") if isinstance(receipt, Mapping) else None
        destination = details.get("destination") if isinstance(details, Mapping) else None
        port = destination.get("port") if isinstance(destination, Mapping) else None
        process_id = observed.get("receiver_process_id") if isinstance(observed, Mapping) else None
        _require(
            isinstance(settings, Mapping)
            and set(settings) == {"collect_after_step"}
            and settings.get("collect_after_step") == record.step_id
            and isinstance(destination, Mapping)
            and destination.get("host") == "127.0.0.1"
            and type(port) is int
            and 1 <= port <= 65535
            and type(process_id) is int
            and process_id > 0
            and isinstance(receiver_session_id, str)
            and _is_sha256(receiver_session_id)
            and isinstance(observed, Mapping)
            and observed.get("receiver_session_id") == receiver_session_id,
            "GATE-05 receiver authority does not match its transport observation",
        )
        return {
            "schema_version": "bluefire.receiver-source-authority.v1",
            "host": "127.0.0.1",
            "port": port,
            "process_id": process_id,
            "session_id": receiver_session_id,
        }
    raise CollectorGateValidationError("GATE-05 authority names a non-canonical collector")


def _validate_collector_authority(
    run: Mapping[str, Any],
    session: CollectionSession,
    *,
    receiver_session_id: str | None = None,
) -> Mapping[str, Any]:
    value = _approval_context(run).get("collector_registry_authority")
    _require(
        isinstance(value, Mapping)
        and set(value) == {"schema_version", "settings_hash", "backends", "authority_hash"},
        "GATE-05 collector registry authority fields are invalid",
    )
    assert isinstance(value, Mapping)
    enabled = [
        collector_id
        for collector_id, row in session.settings.collectors.items()
        if row["enabled"] is True
    ]
    backends = value.get("backends")
    _require(
        value.get("schema_version") == "bluefire.collector-registry-authority.v1"
        and value.get("settings_hash") == session.settings.settings_hash
        and isinstance(backends, list)
        and len(backends) == len(enabled),
        "GATE-05 collector registry authority is not bound to enabled runtime settings",
    )
    expected_backend_fields = {
        "collector_id",
        "descriptor",
        "descriptor_hash",
        "implementation_id",
        "source_authority",
        "source_authority_hash",
    }
    normalized: list[Mapping[str, Any]] = []
    assert isinstance(backends, list)
    for index, backend in enumerate(backends):
        _require(
            isinstance(backend, Mapping) and set(backend) == expected_backend_fields,
            "GATE-05 collector registry authority backend fields are invalid",
        )
        assert isinstance(backend, Mapping)
        collector_id = enabled[index]
        descriptor = _EXPECTED_DESCRIPTORS.get(collector_id)
        source = backend.get("source_authority")
        _require(
            descriptor is not None
            and backend.get("collector_id") == collector_id
            and backend.get("descriptor") == descriptor
            and backend.get("descriptor_hash") == content_hash(descriptor)
            and backend.get("implementation_id") == _EXPECTED_IMPLEMENTATIONS[collector_id]
            and isinstance(source, Mapping),
            "GATE-05 collector registry authority backend is not canonical",
        )
        assert descriptor is not None
        assert isinstance(source, Mapping)
        expected_source = dict(
            _authority_source(
                run,
                session,
                collector_id,
                receiver_session_id=receiver_session_id,
            )
        )
        _require(
            dict(source) == expected_source
            and backend.get("source_authority_hash") == content_hash(expected_source),
            "GATE-05 collector registry source authority is not canonical",
        )
        normalized.append(
            {
                "collector_id": collector_id,
                "descriptor": descriptor,
                "descriptor_hash": content_hash(descriptor),
                "implementation_id": _EXPECTED_IMPLEMENTATIONS[collector_id],
                "source_authority": expected_source,
                "source_authority_hash": content_hash(expected_source),
            }
        )
    body = {
        "schema_version": "bluefire.collector-registry-authority.v1",
        "settings_hash": session.settings.settings_hash,
        "backends": normalized,
    }
    _require(
        value.get("authority_hash") == content_hash(body)
        and dict(value)
        == {
            **body,
            "authority_hash": content_hash(body),
        },
        "GATE-05 collector registry authority hash is invalid",
    )
    return dict(value)


def _plan_action_implementations(run: Mapping[str, Any]) -> Mapping[str, str]:
    plan = run.get("plan")
    steps = plan.get("steps") if isinstance(plan, Mapping) else None
    if not isinstance(steps, list):
        raise CollectorGateValidationError("GATE-05 replay plan is absent")
    rows = [
        (str(step["step_id"]), str(step["action_id"]))
        for step in steps
        if isinstance(step, Mapping)
        and isinstance(step.get("step_id"), str)
        and isinstance(step.get("action_id"), str)
    ]
    result = dict(rows)
    _require(len(result) == len(rows), "GATE-05 replay plan has duplicated step identities")
    return result


def _run_ai_provider_id(run: Mapping[str, Any]) -> str | None:
    raw = run.get("ai_provider")
    if isinstance(raw, Mapping) and isinstance(raw.get("provider"), Mapping):
        raw = raw["provider"]
    if isinstance(raw, Mapping):
        value = raw.get("provider_id") or raw.get("requested_provider_id")
        return value if isinstance(value, str) and value else None
    return raw if isinstance(raw, str) and raw else None


def _run_catalog_authority(run: Mapping[str, Any]) -> Mapping[str, Any]:
    policy = run.get("policy")
    value = policy.get("catalog_authority") if isinstance(policy, Mapping) else None
    if not isinstance(value, Mapping):
        raise CollectorGateValidationError("GATE-05 catalog authority is absent")
    return value


def _validate_replay_lineage(
    baseline_run: Mapping[str, Any],
    replay_run: Mapping[str, Any],
    baseline: CollectionSession,
    replay: CollectionSession,
    baseline_authority: Mapping[str, Any],
    replay_authority: Mapping[str, Any],
) -> None:
    lineage = replay_run.get("replay")
    approved_lineage = _approval_context(replay_run).get("replay")
    source_scenario = baseline_run.get("scenario")
    baseline_actions = _plan_action_implementations(baseline_run)
    replay_actions = _plan_action_implementations(replay_run)
    baseline_catalog = _run_catalog_authority(baseline_run)
    replay_catalog = _run_catalog_authority(replay_run)
    baseline_provider = _run_ai_provider_id(baseline_run)
    replay_provider = _run_ai_provider_id(replay_run)
    _require(
        not isinstance(baseline_run.get("replay"), Mapping)
        and isinstance(lineage, Mapping)
        and set(lineage) == _EXPECTED_REPLAY_LINEAGE_FIELDS
        and approved_lineage == lineage
        and lineage.get("schema_version") == "bluefire.replay-lineage.v1"
        and lineage.get("source_run_id") == baseline_run.get("run_id")
        and isinstance(source_scenario, Mapping)
        and lineage.get("source_scenario_digest") == content_hash(source_scenario)
        and lineage.get("exact") is False
        and lineage.get("from_step_id") is None
        and lineage.get("swap_step_id") is None
        and lineage.get("swap_behavior_id") is None
        and lineage.get("parameter_overrides") is None
        and lineage.get("action_implementations_from") == baseline_actions
        and lineage.get("action_implementation_overrides") == {}
        and lineage.get("action_implementations_to") == replay_actions
        and type(lineage.get("action_implementations_changed")) is bool
        and lineage.get("action_implementations_changed") == (baseline_actions != replay_actions)
        and lineage.get("action_reselection_steps") == []
        and lineage.get("ai_changed") is True
        and lineage.get("autonomy_from") == baseline_run.get("autonomy")
        and lineage.get("autonomy_to") == replay_run.get("autonomy")
        and lineage.get("ai_provider_changed") is True
        and lineage.get("ai_provider_from") == baseline_provider
        and lineage.get("ai_provider_to") == replay_provider
        and baseline_run.get("runner_profile_id") != replay_run.get("runner_profile_id")
        and lineage.get("profile_changed") is True
        and lineage.get("defense_change") == _EXPECTED_DEFENSE_CHANGE
        and lineage.get("catalog_authority_from") == baseline_catalog
        and lineage.get("catalog_authority_to") == replay_catalog
        and type(lineage.get("catalog_authority_changed")) is bool
        and lineage.get("catalog_authority_changed") == (baseline_catalog != replay_catalog)
        and lineage.get("collector_settings_from") == baseline.settings.settings_hash
        and lineage.get("collector_settings_to") == replay.settings.settings_hash
        and lineage.get("collector_settings_changed") is True
        and lineage.get("collector_authority_from") == baseline_authority
        and lineage.get("collector_authority_to") == replay_authority
        and baseline_authority != replay_authority
        and lineage.get("collector_authority_changed") is True,
        "GATE-05 replay lineage is not bound to its exact source and collector settings",
    )


def _one_observation(session: CollectionSession, collector_id: str) -> EvidenceRecord:
    result = session.results.get(collector_id)
    observed = _observed(session, collector_id)
    _require(
        result is not None
        and result.health.readiness.value == "ready"
        and len(result.records) == 1
        and len(observed) == 1,
        f"GATE-05 collector {collector_id} did not produce one healthy observation",
    )
    return observed[0]


def _validate_collection_lineage(
    record: EvidenceRecord,
    records_by_id: Mapping[str, EvidenceRecord],
    steps: Mapping[str, Mapping[str, Any]],
    *,
    require_executed: bool = False,
) -> tuple[EvidenceRecord, Mapping[str, Any]]:
    parent = (
        records_by_id.get(record.parent_evidence_ids[0])
        if len(record.parent_evidence_ids) == 1
        else None
    )
    step = steps.get(record.step_id)
    step_evidence_ids = step.get("evidence_ids") if isinstance(step, Mapping) else None
    _require(
        parent is not None
        and (
            (
                parent.producer == "bluefire-rust-runner"
                and parent.provenance is EvidenceProvenance.EXECUTED
            )
            or (
                not require_executed
                and parent.producer == "policy-engine.v1"
                and parent.provenance is EvidenceProvenance.CONTROL_BLOCKED
            )
        )
        and parent.run_id == record.run_id
        and parent.step_id == record.step_id
        and parent.behavior_id == record.behavior_id
        and parent.action_id == record.action_id
        and parent.runner_profile_id == record.runner_profile_id
        and parent.target_scope_ref == record.target_scope_ref
        and isinstance(step, Mapping)
        and step.get("behavior_id") == record.behavior_id
        and step.get("action_id") == record.action_id
        and isinstance(step_evidence_ids, list)
        and all(isinstance(item, str) for item in step_evidence_ids)
        and len(step_evidence_ids) == len(set(step_evidence_ids))
        and parent.evidence_id in step_evidence_ids
        and record.evidence_id in step_evidence_ids,
        "GATE-05 collector observation is not bound to its scheduled action evidence",
    )
    assert parent is not None
    assert isinstance(step, Mapping)
    return parent, step


def _validate_filesystem_binding(
    run: Mapping[str, Any],
    records: tuple[EvidenceRecord, ...],
    session: CollectionSession,
    predicted_fields: Mapping[str, Any] | None = None,
) -> None:
    record = _one_observation(session, FilesystemCollector.descriptor.id)
    records_by_id = {item.evidence_id: item for item in records}
    steps = _run_steps(run)
    _validate_collection_lineage(record, records_by_id, steps)

    stage = steps.get("stage_evidence")
    artifacts = stage.get("artifacts") if isinstance(stage, Mapping) else None
    bundle = artifacts.get("bundle") if isinstance(artifacts, Mapping) else None
    path = bundle.get("path") if isinstance(bundle, Mapping) else None
    digest = bundle.get("sha256") if isinstance(bundle, Mapping) else None
    size = bundle.get("size") if isinstance(bundle, Mapping) else None
    observed_fields = record.content.get("observed_fields")
    expected_fields = {"path": path, "size_bytes": size, "sha256": digest}
    observation_key = filesystem_observation_key(path) if isinstance(path, str) else None
    settings_row = session.settings.collectors.get(FilesystemCollector.descriptor.id)
    settings = settings_row.get("settings") if isinstance(settings_row, Mapping) else None
    configured_paths = settings.get("paths") if isinstance(settings, Mapping) else None
    predicted = (
        predicted_fields.get(observation_key)
        if isinstance(predicted_fields, Mapping) and isinstance(observation_key, str)
        else None
    )
    _require(
        (
            isinstance(stage, Mapping)
            and stage.get("status") == "success"
            and stage.get("runner_status") == "success"
            and isinstance(bundle, Mapping)
            and bundle.get("type") == "artifact.sandbox.bundle.v1"
            and bundle.get("format") == "jsonl"
            and isinstance(path, str)
            and path == "staged/bundle.jsonl"
            and _is_sha256(digest)
            and isinstance(size, int)
            and not isinstance(size, bool)
            and size > 0
            and isinstance(settings_row, Mapping)
            and settings_row.get("enabled") is True
            and isinstance(settings, Mapping)
            and set(settings) == {"collect_after_step", "paths"}
            and settings.get("collect_after_step") == record.step_id
            and tuple(configured_paths) == (path,)
            if isinstance(configured_paths, (list, tuple))
            else False
        ),
        "GATE-05 filesystem runtime is not bound to the real staged bundle",
    )
    _require(
        record.content.get("artifact_type") == "collector_observation"
        and record.content.get("observation_kind") == "filesystem"
        and record.content.get("observation_key") == observation_key
        and record.content.get("collector_id") == FilesystemCollector.descriptor.id
        and record.content.get("mechanism") == "independent-file-handle-read"
        and observed_fields == expected_fields
        and record.content.get("path") == path
        and record.content.get("size_bytes") == size
        and record.content.get("sha256") == digest
        and isinstance(record.content.get("modified_ns"), int)
        and not isinstance(record.content.get("modified_ns"), bool)
        and int(record.content["modified_ns"]) > 0
        and set(record.content)
        == {
            "artifact_type",
            "collector_id",
            "mechanism",
            "modified_ns",
            "observation_key",
            "observation_kind",
            "observed_fields",
            "path",
            "sha256",
            "size_bytes",
        }
        and record.environment
        == {
            "environment_type": "disposable",
            "collector_id": FilesystemCollector.descriptor.id,
            "collector_version": FilesystemCollector.descriptor.version,
        }
        and (predicted_fields is None or predicted == expected_fields),
        "GATE-05 filesystem observation does not match the real staged bundle",
    )


def _validate_process_binding(
    run: Mapping[str, Any],
    records: tuple[EvidenceRecord, ...],
    session: CollectionSession,
    predicted_fields: Mapping[str, Any],
    expected_platform: str,
) -> None:
    record = _one_observation(session, NativeProcessCollector.descriptor.id)
    records_by_id = {item.evidence_id: item for item in records}
    steps = _run_steps(run)
    _validate_collection_lineage(record, records_by_id, steps)

    predicted = predicted_fields.get("process/native-child")
    observed = record.content.get("observed_fields")
    process_id = predicted.get("process_id") if isinstance(predicted, Mapping) else None
    parent_process_id = (
        predicted.get("parent_process_id") if isinstance(predicted, Mapping) else None
    )
    executable_name = predicted.get("executable_name") if isinstance(predicted, Mapping) else None
    settings_row = session.settings.collectors.get(NativeProcessCollector.descriptor.id)
    settings = settings_row.get("settings") if isinstance(settings_row, Mapping) else None
    _require(
        isinstance(predicted, Mapping)
        and set(predicted) == {"process_id", "parent_process_id", "executable_name", "command_line"}
        and isinstance(process_id, int)
        and not isinstance(process_id, bool)
        and process_id > 0
        and isinstance(parent_process_id, int)
        and not isinstance(parent_process_id, bool)
        and parent_process_id > 0
        and process_id != parent_process_id
        and isinstance(executable_name, str)
        and 0 < len(executable_name) <= 260
        and "\x00" not in executable_name
        and "/" not in executable_name
        and "\\" not in executable_name
        and predicted.get("command_line") == "intentionally not collected"
        and isinstance(settings_row, Mapping)
        and settings_row.get("enabled") is True
        and isinstance(settings, Mapping)
        and set(settings) == {"collect_after_step", "process_id", "expected_parent_process_id"}
        and settings.get("collect_after_step") == record.step_id
        and settings.get("process_id") == process_id
        and settings.get("expected_parent_process_id") == parent_process_id,
        "GATE-05 process prediction and runtime identity are not bound",
    )
    _require(
        isinstance(observed, Mapping)
        and observed.get("process_id") == process_id
        and observed.get("parent_process_id") == parent_process_id
        and observed.get("executable_name") == executable_name
        and observed.get("platform") == expected_platform
        and expected_platform in {"windows", "linux"}
        and record.content.get("artifact_type") == "collector_observation"
        and record.content.get("observation_key") == "process/native-child"
        and record.content.get("observation_kind") == "process"
        and record.content.get("source") == "process/native-child"
        and record.content.get("mechanism") == observed.get("native_api")
        and set(record.content)
        == {
            "artifact_type",
            "mechanism",
            "observation_key",
            "observation_kind",
            "observed_fields",
            "source",
        }
        and record.environment
        == {
            "environment_type": "disposable",
            "collector_id": NativeProcessCollector.descriptor.id,
            "collector_version": NativeProcessCollector.descriptor.version,
            "platform": expected_platform,
        },
        "GATE-05 process observation does not match its declared child identity",
    )
    assert isinstance(observed, Mapping)
    creation_identity = observed.get("creation_identity")
    _require(
        isinstance(creation_identity, str)
        and creation_identity.isascii()
        and creation_identity.isdecimal()
        and int(creation_identity) > 0,
        "GATE-05 native process creation identity is invalid",
    )
    if expected_platform == "windows":
        _require(
            set(observed)
            == {
                "creation_identity",
                "entries_inspected",
                "entry_limit",
                "executable_name",
                "native_api",
                "parent_process_id",
                "platform",
                "process_id",
            }
            and observed.get("native_api") == "CreateToolhelp32Snapshot/GetProcessTimes"
            and observed.get("entry_limit") == 16_384
            and isinstance(observed.get("entries_inspected"), int)
            and not isinstance(observed.get("entries_inspected"), bool)
            and 1 <= int(observed["entries_inspected"]) <= 16_384,
            "GATE-05 Windows native process observation shape is invalid",
        )
    else:
        _require(
            set(observed)
            == {
                "bytes_limit",
                "creation_identity",
                "executable_name",
                "native_api",
                "parent_process_id",
                "platform",
                "process_id",
            }
            and observed.get("native_api") == "/proc/<pid>/stat"
            and observed.get("bytes_limit") == 16_384,
            "GATE-05 Linux native process observation shape is invalid",
        )


def _validate_receiver_bindings(
    run: Mapping[str, Any],
    records: tuple[EvidenceRecord, ...],
    session: CollectionSession,
    receiver_report: Mapping[str, Any] | None,
    predicted_fields: Mapping[str, Any],
) -> None:
    records_by_id = {record.evidence_id: record for record in records}
    steps = _run_steps(run)
    receiver = session.results.get(LoopbackReceiverCollector.descriptor.id)
    if receiver is None:
        _require(receiver_report is None, "GATE-05 receiver report has no invoked collector")
        return
    record = _one_observation(session, LoopbackReceiverCollector.descriptor.id)
    parent, step = _validate_collection_lineage(
        record,
        records_by_id,
        steps,
        require_executed=True,
    )
    observed_fields = record.content.get("observed_fields")
    artifacts = step.get("artifacts")
    receipt = artifacts.get("receipt") if isinstance(artifacts, Mapping) else None
    details = receipt.get("details") if isinstance(receipt, Mapping) else None
    task_id = step.get("runner_task_id")
    destination = details.get("destination") if isinstance(details, Mapping) else None
    digest = details.get("sha256") if isinstance(details, Mapping) else None
    bytes_received = details.get("bytes_sent") if isinstance(details, Mapping) else None
    receiver_session_id = (
        receiver_report.get("session_id") if isinstance(receiver_report, Mapping) else None
    )
    expected_fields = {
        "task_id": task_id,
        "sha256": digest,
        "bytes_received": bytes_received,
    }
    expected_prediction = {
        **expected_fields,
        "receiver_session_id": receiver_session_id,
    }
    observation_key = f"network/authenticated-receiver/{task_id}"
    process_prediction = predicted_fields.get("process/native-child")
    receiver_process_id = (
        observed_fields.get("receiver_process_id") if isinstance(observed_fields, Mapping) else None
    )
    settings_row = session.settings.collectors.get(LoopbackReceiverCollector.descriptor.id)
    settings = settings_row.get("settings") if isinstance(settings_row, Mapping) else None
    _require(
        parent.content.get("runner_status") == "success"
        and parent.content.get("runner_task_id") == task_id
        and step.get("status") == "success"
        and step.get("runner_status") == "success"
        and isinstance(task_id, str)
        and task_id.startswith("execute-")
        and _is_sha256(task_id.removeprefix("execute-"))
        and isinstance(receipt, Mapping)
        and receipt.get("type") == "artifact.sandbox.network.receipt.v1"
        and receipt.get("transport") == "loopback"
        and isinstance(details, Mapping)
        and _is_sha256(digest)
        and isinstance(bytes_received, int)
        and not isinstance(bytes_received, bool)
        and bytes_received > 0
        and isinstance(destination, Mapping)
        and destination.get("host") == "127.0.0.1"
        and isinstance(destination.get("port"), int)
        and not isinstance(destination.get("port"), bool)
        and 1 <= int(destination["port"]) <= 65535
        and details.get("receiver_acknowledged") is True
        and details.get("receiver_stored") is False
        and isinstance(receiver_session_id, str)
        and _is_sha256(receiver_session_id)
        and isinstance(settings_row, Mapping)
        and settings_row.get("enabled") is True
        and isinstance(settings, Mapping)
        and set(settings) == {"collect_after_step"}
        and settings.get("collect_after_step") == record.step_id,
        "GATE-05 network observation is not bound to its successful transport receipt",
    )
    _require(
        isinstance(observed_fields, Mapping)
        and set(observed_fields)
        == {
            "task_id",
            "sha256",
            "bytes_received",
            "receiver_process_id",
            "receiver_session_id",
        }
        and {key: observed_fields.get(key) for key in (*expected_fields, "receiver_session_id")}
        == expected_prediction
        and isinstance(receiver_process_id, int)
        and not isinstance(receiver_process_id, bool)
        and receiver_process_id > 0
        and isinstance(process_prediction, Mapping)
        and receiver_process_id == process_prediction.get("parent_process_id")
        and receiver_process_id != process_prediction.get("process_id")
        and predicted_fields.get(observation_key) == expected_prediction
        and record.content.get("artifact_type") == "collector_observation"
        and record.content.get("observation_kind") == "network"
        and record.content.get("source") == "receiver/authenticated-loopback"
        and record.content.get("mechanism") == "receiver-owned-authenticated-binding"
        and record.content.get("sha256") == digest
        and record.content.get("size_bytes") == bytes_received
        and record.content.get("observation_key") == observation_key
        and set(record.content)
        == {
            "artifact_type",
            "mechanism",
            "observation_key",
            "observation_kind",
            "observed_fields",
            "sha256",
            "size_bytes",
            "source",
        }
        and record.environment
        == {
            "environment_type": "disposable",
            "collector_id": LoopbackReceiverCollector.descriptor.id,
            "collector_version": LoopbackReceiverCollector.descriptor.version,
            "transport": "loopback",
        },
        "GATE-05 receiver process identity or authenticated binding is invalid",
    )
    summary = receiver_report.get("summary") if isinstance(receiver_report, Mapping) else None
    _require(
        isinstance(receiver_report, Mapping)
        and set(receiver_report)
        == {
            "summary",
            "session_id",
            "accepted_artifact_bindings",
            "credentialed_task_ids",
            "transport_artifact",
        }
        and summary
        == {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 2,
            "challenges_issued": 1,
            "requests_accepted": 1,
            "requests_refused": 0,
        }
        and receiver_report.get("accepted_artifact_bindings") == [expected_fields]
        and receiver_report.get("session_id") == receiver_session_id
        and receiver_report.get("credentialed_task_ids") == [task_id]
        and receiver_report.get("transport_artifact") == expected_fields,
        "GATE-05 receiver report is not bound to its authenticated transport observation",
    )


def _validate_run_graphs(
    store: RunStore,
    sessions: Mapping[str, CollectionSession],
    *,
    replay_run_id: str,
    predicted_fields: Mapping[str, Any],
    expected_platform: str,
    receiver_report: Mapping[str, Any],
) -> bool:
    for run_id, session in sessions.items():
        _validate_session_descriptors(session)
        run = store.get_run(run_id)
        evidence = run.get("evidence")
        rows = evidence.get("records") if isinstance(evidence, Mapping) else None
        if not isinstance(rows, list) or not rows:
            raise CollectorGateValidationError("GATE-05 run evidence is absent")
        records: list[EvidenceRecord] = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise CollectorGateValidationError("GATE-05 run evidence is invalid")
            records.append(EvidenceRecord.from_mapping(row))
        graph = EvidenceGraph()
        graph.extend(records)
        _require(
            len(graph.records()) == len(records)
            and all(record.content_hash.startswith("sha256:") for record in records)
            and all(record.record_hash.startswith("sha256:") for record in records),
            "GATE-05 evidence graph or hashes are invalid",
        )
        _require(
            all(record.run_id == run_id for record in records),
            "GATE-05 persisted evidence belongs to a different run",
        )
        session_ids = {
            record.evidence_id for result in session.results.values() for record in result.records
        }
        persisted_collector_ids = {
            record.evidence_id for record in records if record.producer in _GATE_COLLECTOR_IDS
        }
        _require(
            session_ids == persisted_collector_ids,
            "GATE-05 collector session evidence does not match persisted collector evidence",
        )
        is_replay = run_id == replay_run_id
        _validate_filesystem_binding(
            run,
            tuple(records),
            session,
            predicted_fields if is_replay else None,
        )
        _validate_process_binding(
            run,
            tuple(records),
            session,
            predicted_fields,
            expected_platform,
        )
        _validate_receiver_bindings(
            run,
            tuple(records),
            session,
            receiver_report if is_replay else None,
            predicted_fields,
        )
    return True


def validate_persisted_collectors(
    repository: Path,
    evidence_dir: Path,
) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require((root / "pyproject.toml").is_file(), "GATE-05 repository root is invalid")
    journey = _read_json(destination / JOURNEY_REPORT)
    platform = _read_json(destination / PLATFORM_REPORT)
    comparison = _read_json(destination / COMPARISON_REPORT)
    corruption = _read_json(destination / CORRUPTION_REPORT)
    _require(
        journey.get("schema_version") == JOURNEY_SCHEMA
        and journey.get("passed") is True
        and platform.get("schema_version") == PLATFORM_SCHEMA
        and platform.get("passed") is True
        and corruption.get("schema_version") == CORRUPTION_SCHEMA
        and corruption.get("passed") is True,
        "GATE-05 report schema or status is invalid",
    )
    raw_run_ids = journey.get("run_ids")
    raw_bundles = journey.get("run_bundles")
    if not (
        isinstance(raw_run_ids, list)
        and len(raw_run_ids) == 2
        and all(isinstance(run_id, str) for run_id in raw_run_ids)
        and len(set(raw_run_ids)) == 2
    ):
        raise CollectorGateValidationError("GATE-05 run bundle references are invalid")
    run_ids = [run_id for run_id in raw_run_ids if isinstance(run_id, str)]
    bundles = [{"run_id": run_id, "path": f"runs/{run_id}"} for run_id in run_ids]
    if not isinstance(raw_bundles, list) or raw_bundles != bundles:
        raise CollectorGateValidationError("GATE-05 run bundle references are invalid")
    baseline = _session(journey.get("baseline_session"))
    replay = _session(journey.get("replay_session"))
    expected_collectors = [
        descriptor.to_dict()
        for descriptor in (
            FilesystemCollector.descriptor,
            LoopbackReceiverCollector.descriptor,
            NativeProcessCollector.descriptor,
        )
    ]
    _require(
        journey.get("collectors") == expected_collectors,
        "GATE-05 collector inventory is not bound to source descriptors",
    )
    filesystem_records = _observed(replay, FilesystemCollector.descriptor.id)
    process_records = _observed(replay, NativeProcessCollector.descriptor.id)
    network_records = _observed(replay, LoopbackReceiverCollector.descriptor.id)

    reconciliation = journey.get("reconciliation")
    predicted_fields = journey.get("predicted_fields")
    execution = journey.get("execution")
    receiver_report = journey.get("receiver")
    if not (
        isinstance(reconciliation, Mapping)
        and isinstance(predicted_fields, Mapping)
        and isinstance(execution, Mapping)
        and isinstance(receiver_report, Mapping)
        and execution.get("runner_platform") in {"windows", "linux"}
    ):
        raise CollectorGateValidationError("GATE-05 field reconciliation is absent")

    run_root = destination / "runs"
    store = RunStore(run_root)
    graph_valid = _validate_run_graphs(
        store,
        {
            run_ids[0]: baseline,
            run_ids[1]: replay,
        },
        replay_run_id=run_ids[1],
        predicted_fields=predicted_fields,
        expected_platform=str(execution["runner_platform"]),
        receiver_report=receiver_report,
    )
    baseline_run = store.get_run(run_ids[0])
    replay_run = store.get_run(run_ids[1])
    baseline_authority = _validate_collector_authority(baseline_run, baseline)
    replay_authority = _validate_collector_authority(
        replay_run,
        replay,
        receiver_session_id=(
            receiver_report.get("session_id")
            if isinstance(receiver_report.get("session_id"), str)
            else None
        ),
    )
    _validate_replay_lineage(
        baseline_run,
        replay_run,
        baseline,
        replay,
        baseline_authority,
        replay_authority,
    )
    _require(
        baseline.to_dict() == baseline_run.get("collector_session")
        and replay.to_dict() == replay_run.get("collector_session"),
        "GATE-05 journey sessions do not match the immutable run bundles",
    )
    recomputed_comparison = compare_runs(store, run_ids)
    _require(
        comparison == recomputed_comparison,
        "GATE-05 comparison does not match the immutable run bundles",
    )
    delta = comparison.get("deltas")
    if not isinstance(delta, list) or len(delta) != 1 or not isinstance(delta[0], Mapping):
        raise CollectorGateValidationError("GATE-05 comparison delta is invalid")
    delta_row = delta[0]
    collector_delta = delta_row.get("collector_session_delta")
    if not isinstance(collector_delta, Mapping):
        raise CollectorGateValidationError("GATE-05 collector delta is absent")

    reconciliation_body = dict(reconciliation)
    reconciliation_digest = reconciliation_body.pop("reconciliation_hash", None)
    field_rows = reconciliation.get("field_comparisons")
    recomputed_reconciliation = reconcile_observations(
        predicted_fields,
        tuple(record for result in replay.results.values() for record in result.records),
    )
    _require(
        reconciliation == recomputed_reconciliation
        and reconciliation_digest == content_hash(reconciliation_body)
        and isinstance(field_rows, list)
        and bool(field_rows)
        and isinstance(reconciliation.get("missing_observations"), list)
        and bool(reconciliation["missing_observations"])
        and any(
            isinstance(row, Mapping)
            and (bool(row.get("missing_fields")) or bool(row.get("unexpected_fields")))
            for row in field_rows
        ),
        "GATE-05 predicted-versus-observed fields are incomplete",
    )
    optional = platform.get("optional_collectors")
    interfaces = platform.get("adapter_interfaces")
    optional_kinds = (
        {row.get("kind") for row in optional if isinstance(row, Mapping)}
        if isinstance(optional, list)
        else set()
    )
    interface_names = set(interfaces) if isinstance(interfaces, list) else set()
    expected_interfaces = {
        WindowsEventLogAdapter.__name__,
        LinuxAuditRuntimeAdapter.__name__,
        CloudIdentityAuditAdapter.__name__,
        SecurityQueryAdapter.__name__,
    }
    platform_valid = (
        optional == [descriptor.to_dict() for descriptor in optional_collector_descriptors()]
        and {"host_audit", "cloud_identity_audit", "siem", "edr"} <= optional_kinds
        and interface_names == expected_interfaces
        and platform.get("configured") is False
        and platform.get("readiness") == "not_configured"
    )
    corruption_checks = corruption.get("checks")
    tampered_session = copy.deepcopy(replay.to_dict())
    first_collector = next(iter(tampered_session["results"]))
    tampered_session["results"][first_collector]["health"]["summary"] = "altered"
    try:
        CollectionSession.from_mapping(tampered_session)
    except CollectorError:
        independent_corruption_refusal = True
    else:
        independent_corruption_refusal = False
    corruption_valid = (
        isinstance(corruption_checks, Mapping)
        and set(corruption_checks)
        == {
            "content_hash_mismatch_refused",
            "health_session_hash_mismatch_refused",
            "semantically_rehashed_evidence_refused",
            "settings_hash_mismatch_refused",
            "unaltered_session_verified",
        }
        and all(value is True for value in corruption_checks.values())
        and independent_corruption_refusal
    )
    baseline_network = baseline.settings.collectors[LoopbackReceiverCollector.descriptor.id]
    replay_network = replay.settings.collectors[LoopbackReceiverCollector.descriptor.id]
    settings_toggle = (
        baseline_network["enabled"] is False
        and replay_network["enabled"] is True
        and LoopbackReceiverCollector.descriptor.id not in baseline.results
        and LoopbackReceiverCollector.descriptor.id in replay.results
        and baseline.settings.settings_hash != replay.settings.settings_hash
    )
    health_and_hashes = graph_valid and all(
        result.health.readiness.value == "ready"
        and all(record.content_hash and record.record_hash for record in result.records)
        for result in replay.results.values()
    )
    checks = {
        "process_collector": len(process_records) == 1,
        "filesystem_collector": len(filesystem_records) == 1,
        "network_collector": len(network_records) == 1,
        "platform_interfaces": platform_valid,
        "native_when_supported": (
            len(process_records) == 1
            and process_records[0].content.get("mechanism")
            in {"CreateToolhelp32Snapshot/GetProcessTimes", "/proc/<pid>/stat"}
        ),
        "predicted_vs_observed": True,
        "lineage_hash_health": health_and_hashes,
        "corruption_refusal": corruption_valid,
        "settings_toggle": settings_toggle,
        "replay_compare_delta": (
            delta_row.get("collector_session_changed") is True
            and collector_delta.get("collectors_enabled")
            == [LoopbackReceiverCollector.descriptor.id]
            and collector_delta.get("observation_delta") == 1
            and delta_row.get("replay_lineage_changed") is True
        ),
    }
    _require(all(checks.values()), "one or more GATE-05 semantic checks failed")
    return checks, tuple(bundles)


__all__ = [
    "CollectorGateValidationError",
    "validate_persisted_collectors",
]
