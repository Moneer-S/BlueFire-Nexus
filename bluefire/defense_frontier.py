"""Real native journey for the GATE-04 defense frontier.

The journey keeps authority in existing BlueFire contracts: one packaged Rust
runner, the maintained adaptive scenario, two reviewed Execute profiles, one
independent filesystem collector, and an approval for every Execute run.  The
only dynamic scenario value is an operating-system assigned loopback port that
is bound before any approval is created.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import stat
import threading
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, cast

from . import native_journey_runtime as _native_journey_runtime
from .ai import OpenAIResponsesProvider, build_ai_provider
from .comparison import compare_runs
from .config import AIProviderKind, load_config
from .contracts import load_scenario
from .native_journey_runtime import (
    DefenseFrontierError,
    _create_pinned_runner_journal,
    _extend_cleanup_failures,
    _raise_cleanup_failures,
    _remove_pinned_tree,
    _remove_runner_journal,
    _require,
)
from .native_journey_runtime import (
    _close_runtime_and_remove as _close_runtime_and_remove_impl,
)
from .native_journey_runtime import (
    _create_pinned_runtime as _create_pinned_runtime_impl,
)
from .receiver import LoopbackArtifactReceiver, ReceiverConfig
from .receiver_auth import derive_receiver_task_key
from .runner_bootstrap import RunnerBootstrapError, bootstrap_runner, current_platform
from .runner_client import SubprocessRustRunner
from .runner_lifecycle import ManagedRunnerLifecycle
from .runner_private_files import _PinnedPrivateDirectory
from .runtime_paths import (
    _TOKEN_KNOWN_FOLDER_ACCESS as _RUNTIME_TOKEN_KNOWN_FOLDER_ACCESS,
)
from .runtime_paths import (
    runtime_temp_parent as _runtime_temp_parent,
)
from .service import BlueFireService
from .util import content_hash, file_hash

SCENARIO_ID = "scenario.ai-adaptive.safe-chain.v1"
CANONICAL_PROFILE_ID = "sandbox-execute.v1"
FRONTIER_PROFILE_ID = "sandbox-blocked-network.v1"
COLLECTOR_ID = "collector.filesystem.sandbox.v1"
PROVIDER_ID = "deterministic-offline.v1"
REAL_PROVIDER_ID = "openai-responses.v1"
_TOKEN_KNOWN_FOLDER_ACCESS = _RUNTIME_TOKEN_KNOWN_FOLDER_ACCESS

JOURNEY_REPORT = "gate04-journey-report.json"
DEFENSE_REPORT = "gate04-defense-change-report.json"
COMPARISON_REPORT = "gate04-comparison-report.json"
STRUCTURAL_REPORT = "gate04-structural-report.json"
REPORT_PATHS = (
    JOURNEY_REPORT,
    DEFENSE_REPORT,
    COMPARISON_REPORT,
    STRUCTURAL_REPORT,
)

JOURNEY_SCHEMA = "bluefire.defense-frontier-journey.v1"
DEFENSE_SCHEMA = "bluefire.defense-frontier-change.v1"
COMPARISON_SCHEMA = "bluefire.defense-frontier-comparison.v1"
STRUCTURAL_SCHEMA = "bluefire.defense-frontier-structural.v1"
HELPER_SCHEMA = "bluefire.gate-04-helper.v1"
DEFENSE_CHANGE_NOTE = (
    "defense-frontier-control-revision.v1: restore reviewed loopback transport "
    "after proving the blocked-profile fallback"
)

_TASK_RESULT = re.compile(r"^execute-[0-9a-f]{64}\.json$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_MAX_REPORT_BYTES = 8 * 1024 * 1024
_MAX_SCAN_BYTES = 128 * 1024 * 1024

# Preserve the historical module seam used by other native journeys and their
# fault-injection tests while the implementation lives in one cohesive module.
_CLEANUP_ATTEMPTS = _native_journey_runtime._CLEANUP_ATTEMPTS
_CLEANUP_RETRY_SECONDS = _native_journey_runtime._CLEANUP_RETRY_SECONDS
_REPARSE_POINT = _native_journey_runtime._REPARSE_POINT
_MAX_RUNTIME_CLEANUP_DEPTH = _native_journey_runtime._MAX_RUNTIME_CLEANUP_DEPTH
_MAX_RUNTIME_CLEANUP_ENTRIES = _native_journey_runtime._MAX_RUNTIME_CLEANUP_ENTRIES
_MAX_JOURNAL_ENTRIES = _native_journey_runtime._MAX_JOURNAL_ENTRIES
_RuntimeCleanupError = _native_journey_runtime._RuntimeCleanupError
_pin_owned_directory = _native_journey_runtime._pin_owned_directory
_pin_runtime_directory = _native_journey_runtime._pin_runtime_directory
_retry_cleanup = _native_journey_runtime._retry_cleanup
_safe_directory_details = _native_journey_runtime._safe_directory_details
time = _native_journey_runtime.time


def _create_pinned_runtime(prefix: str) -> tuple[Path, _PinnedPrivateDirectory]:
    return _create_pinned_runtime_impl(prefix, _runtime_temp_parent)


def _close_runtime_and_remove(
    runtime: Path,
    runtime_guard: _PinnedPrivateDirectory,
    close_service: Callable[[], None],
) -> None:
    _close_runtime_and_remove_impl(
        runtime,
        runtime_guard,
        close_service,
        remove_tree=lambda guard, deadline: _remove_pinned_tree(guard, deadline=deadline),
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    _require(len(payload) <= _MAX_REPORT_BYTES, "a GATE-04 report exceeded its byte bound")
    _require(not path.exists() and path.parent.is_dir(), "a GATE-04 report path is stale")
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        _require(
            stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
            "a GATE-04 report path is unsafe",
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "a GATE-04 report write made no progress")
            offset += written
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = bytearray()
        while len(observed) <= _MAX_REPORT_BYTES:
            block = os.read(
                descriptor,
                min(64 * 1024, _MAX_REPORT_BYTES + 1 - len(observed)),
            )
            if not block:
                break
            observed.extend(block)
        current = os.fstat(descriptor)
        _require(
            bytes(observed) == payload
            and (current.st_dev, current.st_ino) == identity
            and stat.S_ISREG(current.st_mode)
            and current.st_nlink == 1
            and current.st_size == len(payload),
            "a GATE-04 report changed during publication",
        )
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        try:
            current = path.lstat()
            if identity == (current.st_dev, current.st_ino) and not path.is_symlink():
                path.unlink()
        except OSError:
            pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _scenario_with_bound_port(repository: Path, port: int) -> dict[str, Any]:
    scenario = load_scenario(repository / "scenarios" / "ai_adaptive_safe_chain.yaml").to_dict()
    _require(scenario.get("id") == SCENARIO_ID, "the maintained frontier scenario is unavailable")
    steps = scenario.get("steps")
    _require(isinstance(steps, list), "the frontier scenario steps are invalid")
    matches = [
        row
        for row in cast(list[Any], steps)
        if isinstance(row, dict) and row.get("id") == "try_internal_transport"
    ]
    _require(len(matches) == 1, "the frontier transport step is ambiguous")
    parameters = matches[0].get("parameters")
    _require(isinstance(parameters, dict), "the frontier transport parameters are invalid")
    cast(dict[str, Any], parameters)["port"] = port
    return scenario


def _request(
    scenario: Mapping[str, Any],
    *,
    profile_id: str,
    approved_by: str,
) -> dict[str, Any]:
    return {
        "scenario": dict(scenario),
        "mode": "execute",
        "runner_profile_id": profile_id,
        "target_scope": {"scope_refs": ["sandbox.workspace", "network.loopback", "export.local"]},
        "autonomy": "auto",
        "ai_provider_id": PROVIDER_ID,
        "collectors": [COLLECTOR_ID],
        "approval": {"confirmed": True, "approved_by": approved_by},
    }


def _step(run: Mapping[str, Any], step_id: str) -> Mapping[str, Any] | None:
    rows = run.get("steps")
    if not isinstance(rows, list):
        return None
    matches = [row for row in rows if isinstance(row, Mapping) and row.get("step_id") == step_id]
    _require(len(matches) <= 1, f"frontier run repeated step {step_id}")
    return matches[0] if matches else None


def _observed_records(run: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    evidence = run.get("evidence")
    records = evidence.get("records") if isinstance(evidence, Mapping) else None
    _require(isinstance(records, list), "frontier run evidence is invalid")
    return [
        row
        for row in cast(list[Any], records)
        if isinstance(row, Mapping)
        and row.get("provenance") == "observed"
        and row.get("producer") == COLLECTOR_ID
    ]


def _export_observations(run: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for record in _observed_records(run):
        content = record.get("content")
        path = content.get("path") if isinstance(content, Mapping) else None
        if isinstance(path, str) and path.replace("\\", "/").startswith("exports/ephemeral/"):
            result.append(record)
    return result


def _proposal_after_block(run: Mapping[str, Any]) -> Mapping[str, Any]:
    proposals = run.get("ai_proposals")
    _require(isinstance(proposals, list), "frontier proposal records are invalid")
    matches = [
        row
        for row in cast(list[Any], proposals)
        if isinstance(row, Mapping)
        and row.get("current_step_id") == "try_internal_transport"
        and row.get("outcome") == "blocked"
    ]
    _require(len(matches) == 1, "the blocked frontier proposal is missing or ambiguous")
    return cast(Mapping[str, Any], matches[0])


def _execution_summary(run: Mapping[str, Any], *, role: str) -> dict[str, Any]:
    run_id = run.get("run_id")
    _require(isinstance(run_id, str) and _RUN_ID.fullmatch(run_id) is not None, "run ID is invalid")
    steps = run.get("steps")
    _require(isinstance(steps, list), "frontier run steps are invalid")
    approval = run.get("approval")
    cleanup = run.get("cleanup")
    _require(isinstance(approval, Mapping), "frontier approval is invalid")
    _require(isinstance(cleanup, Mapping), "frontier cleanup is invalid")
    return {
        "role": role,
        "run_id": run_id,
        "profile_id": run.get("runner_profile_id"),
        "status": run.get("status"),
        "objective_reached": run.get("objective_reached"),
        "approval_id": cast(Mapping[str, Any], approval).get("approval_id"),
        "approval_status": cast(Mapping[str, Any], approval).get("status"),
        "path": [
            {
                "step_id": row.get("step_id"),
                "behavior_id": row.get("behavior_id"),
                "action_id": row.get("action_id"),
                "status": row.get("status"),
            }
            for row in cast(list[Any], steps)
            if isinstance(row, Mapping)
        ],
        "observed_evidence_ids": [
            str(row["evidence_id"])
            for row in _observed_records(run)
            if isinstance(row.get("evidence_id"), str)
        ],
        "cleanup": {
            key: cast(Mapping[str, Any], cleanup).get(key)
            for key in ("attempted", "success", "outstanding_receipt_count")
        },
    }


def _profile_digest(run: Mapping[str, Any]) -> str:
    profile = run.get("profile")
    _require(isinstance(profile, Mapping), "frontier run profile snapshot is unavailable")
    return content_hash(profile)


def _detection_observed_matches(run: Mapping[str, Any], behavior_id: str) -> int:
    detections = run.get("detections")
    candidates = detections.get("candidates") if isinstance(detections, Mapping) else None
    _require(isinstance(candidates, list), "frontier detections are invalid")
    matches = [
        row
        for row in cast(list[Any], candidates)
        if isinstance(row, Mapping) and row.get("behavior_id") == behavior_id
    ]
    _require(len(matches) == 1, f"frontier detection {behavior_id} is unavailable")
    observed = matches[0].get("observed_evidence_ids")
    _require(isinstance(observed, list), "frontier observed detection bindings are invalid")
    return len(cast(list[Any], observed))


def _transport_receiver_binding(run: Mapping[str, Any]) -> Mapping[str, object]:
    step = _step(run, "try_internal_transport")
    _require(step is not None and step.get("status") == "success", "transport step is unavailable")
    verified_step = cast(Mapping[str, Any], step)
    runner_task_id = verified_step.get("runner_task_id")
    artifacts = verified_step.get("artifacts")
    receipt = artifacts.get("receipt") if isinstance(artifacts, Mapping) else None
    details = receipt.get("details") if isinstance(receipt, Mapping) else None
    digest = details.get("sha256") if isinstance(details, Mapping) else None
    byte_count = details.get("bytes_sent") if isinstance(details, Mapping) else None
    _require(
        isinstance(runner_task_id, str)
        and _TASK_RESULT.fullmatch(runner_task_id + ".json") is not None
        and isinstance(digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
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


def _validate_runs(
    canonical: Mapping[str, Any],
    frontier: Mapping[str, Any],
    replay: Mapping[str, Any],
    receiver_observation: Mapping[str, Any],
) -> Mapping[str, Any]:
    runs = (canonical, frontier, replay)
    _require(
        all(
            run.get("status") == "completed" and run.get("objective_reached") is True
            for run in runs
        ),
        "a frontier Execute run did not reach its declared objective",
    )
    _require(
        [run.get("runner_profile_id") for run in runs]
        == [CANONICAL_PROFILE_ID, FRONTIER_PROFILE_ID, CANONICAL_PROFILE_ID],
        "frontier profile sequence is invalid",
    )
    approvals = [run.get("approval") for run in runs]
    approval_ids = [row.get("approval_id") for row in approvals if isinstance(row, Mapping)]
    _require(
        len(approval_ids) == 3
        and len(set(approval_ids)) == 3
        and all(isinstance(row, Mapping) and row.get("status") == "claimed" for row in approvals),
        "frontier Execute approvals were not fresh and claimed",
    )
    canonical_transport = _step(canonical, "try_internal_transport")
    _require(
        canonical_transport is not None
        and canonical_transport.get("status") == "success"
        and _step(canonical, "preserve_approved_copy") is None,
        "canonical frontier transport did not execute",
    )
    blocked = _step(frontier, "try_internal_transport")
    alternate = _step(frontier, "preserve_approved_copy")
    _require(
        blocked is not None
        and blocked.get("status") == "blocked"
        and isinstance(blocked.get("policy"), Mapping)
        and blocked["policy"].get("status") == "control_blocked",
        "the frontier control did not block before dispatch",
    )
    _require(
        alternate is not None
        and alternate.get("behavior_id") == "sandbox.export.local.v1"
        and alternate.get("action_id") == "sandbox.export.local.v1"
        and alternate.get("status") == "success",
        "the registered local-preservation alternate did not execute",
    )
    replay_transport = _step(replay, "try_internal_transport")
    _require(
        replay_transport is not None
        and replay_transport.get("status") == "success"
        and _step(replay, "preserve_approved_copy") is None,
        "the controlled replay did not restore canonical transport",
    )
    _require(
        all(
            isinstance(run.get("cleanup"), Mapping)
            and run["cleanup"].get("attempted") is True
            and run["cleanup"].get("success") is True
            and run["cleanup"].get("outstanding_receipt_count") == 0
            for run in runs
        ),
        "frontier cleanup was not verified",
    )
    _require(
        all(_observed_records(run) for run in runs), "independent frontier observation is missing"
    )
    exports = _export_observations(frontier)
    _require(len(exports) == 1, "the alternate export was not uniquely observed")
    _require(
        not _export_observations(canonical) and not _export_observations(replay),
        "export evidence leaked into the canonical path",
    )
    proposal = _proposal_after_block(frontier)
    proposed = proposal.get("proposal")
    policy = proposal.get("proposal_policy_evaluation")
    planner_state = proposal.get("planner_state")
    _require(
        isinstance(proposed, Mapping)
        and proposed.get("selected_step_id") == "preserve_approved_copy"
        and proposed.get("selected_behavior_id") == "sandbox.export.local.v1"
        and proposal.get("application_status") == "accepted_registered_default"
        and isinstance(policy, Mapping)
        and policy.get("status") == "permitted",
        "deterministic Auto did not select the registered alternate",
    )
    _require(
        isinstance(planner_state, Mapping)
        and planner_state.get("schema_version") == "bluefire.planner-state.v1"
        and proposal.get("planner_state_digest") == content_hash(planner_state),
        "the structured planner state is not durably bound",
    )
    lineage = replay.get("replay")
    _require(
        isinstance(lineage, Mapping)
        and lineage.get("source_run_id") == frontier.get("run_id")
        and lineage.get("defense_change") == DEFENSE_CHANGE_NOTE
        and lineage.get("profile_changed") is True,
        "the controlled replay lineage is incomplete",
    )
    receiver_summary = receiver_observation.get("summary")
    accepted_artifacts = receiver_observation.get("accepted_artifact_bindings")
    credentialed_task_ids = receiver_observation.get("credentialed_task_ids")
    expected_receiver_bindings = [
        _transport_receiver_binding(canonical),
        _transport_receiver_binding(replay),
    ]
    _require(
        receiver_summary
        == {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 4,
            "challenges_issued": 2,
            "requests_accepted": 2,
            "requests_refused": 0,
        },
        "the authenticated receiver did not observe both canonical transfers",
    )
    _require(
        accepted_artifacts == expected_receiver_bindings
        and credentialed_task_ids == [binding["task_id"] for binding in expected_receiver_bindings]
        and len(set(credentialed_task_ids)) == 2,
        "receiver effects are not bound to the two canonical transport tasks",
    )
    export_detection_matches = {
        "canonical": _detection_observed_matches(canonical, "sandbox.export.local.v1"),
        "frontier": _detection_observed_matches(frontier, "sandbox.export.local.v1"),
        "replay": _detection_observed_matches(replay, "sandbox.export.local.v1"),
    }
    _require(
        export_detection_matches == {"canonical": 0, "frontier": 1, "replay": 0},
        "frontier observed detection outcomes did not differ",
    )
    return {
        "canonical_transport_executed": True,
        "frontier_control_blocked": True,
        "structured_planner_state": True,
        "registered_alternate_selected": True,
        "policy_and_fresh_approvals": True,
        "alternate_objective_reached": True,
        "independent_observation": True,
        "cleanup_verified": True,
        "controlled_replay": True,
        "export_detection_matches": export_detection_matches,
    }


def _structural_report(repository: Path) -> Mapping[str, Any]:
    config = load_config(repository / "bluefire" / "data" / "bluefire.example.yaml")
    real = config.ai.provider(REAL_PROVIDER_ID)
    provider = build_ai_provider(config.ai, provider_id=REAL_PROVIDER_ID, environ={})
    scenario_path = repository / "scenarios" / "ai_adaptive_safe_chain.yaml"
    packaged_path = repository / "bluefire" / "data" / scenario_path.name
    _require(real.kind is AIProviderKind.OPENAI_RESPONSES, "the real provider kind is invalid")
    _require(
        isinstance(provider, OpenAIResponsesProvider), "the real provider adapter is unavailable"
    )
    _require(
        real.endpoint is not None and real.endpoint.startswith("https://"),
        "the real provider endpoint is unsafe",
    )
    _require(
        real.api_key is not None and real.api_key.env == "OPENAI_API_KEY",
        "the real provider credential reference is invalid",
    )
    credential_reference = real.api_key.env if real.api_key is not None else ""
    _require(
        config.ai.fallback.id == PROVIDER_ID, "the real provider fallback is not deterministic"
    )
    _require(
        scenario_path.read_bytes() == packaged_path.read_bytes(),
        "packaged frontier scenario drifted",
    )
    return {
        "schema_version": STRUCTURAL_SCHEMA,
        "passed": True,
        "scenario_contract": {
            "scenario_id": SCENARIO_ID,
            "source_sha256": file_hash(scenario_path),
            "packaged_sha256": file_hash(packaged_path),
        },
        "real_provider_contract": {
            "provider_id": REAL_PROVIDER_ID,
            "kind": real.kind.value,
            "endpoint_scheme": "https",
            "credential_reference": credential_reference,
            "fallback_provider_id": config.ai.fallback.id,
            "manual_key_required_for_release": False,
            "proposal_only": True,
        },
    }


def _secret_representations(values: Sequence[bytes]) -> tuple[bytes, ...]:
    rendered: set[bytes] = set()
    for value in values:
        rendered.update(
            {
                value,
                value.hex().encode("ascii"),
                base64.b64encode(value),
                base64.urlsafe_b64encode(value).rstrip(b"="),
            }
        )
    return tuple(rendered)


def _assert_secrets_absent(root: Path, values: Sequence[bytes]) -> None:
    needles = _secret_representations(values)
    total = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        size = path.stat().st_size
        total += size
        _require(
            size <= _MAX_SCAN_BYTES and total <= _MAX_SCAN_BYTES,
            "GATE-04 secret audit exceeded its byte bound",
        )
        payload = path.read_bytes()
        _require(
            not any(needle in payload for needle in needles),
            "receiver authority leaked into GATE-04 artifacts",
        )


def produce_defense_frontier_evidence(repository: Path, evidence_dir: Path) -> Mapping[str, Any]:
    """Run all three native paths and publish the four locked helper reports."""

    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require(root.is_dir() and not root.is_symlink(), "the GATE-04 repository is invalid")
    _require(
        destination.is_dir() and not destination.is_symlink(),
        "the GATE-04 evidence directory is invalid",
    )
    _require(
        not any((destination / name).exists() for name in REPORT_PATHS),
        "stale GATE-04 reports are present",
    )
    runs_dir = destination / "runs"
    _require(not runs_dir.exists(), "a stale GATE-04 run root is present")
    runs_dir.mkdir()

    receiver_key = secrets.token_bytes(32)
    task_keys: list[bytes] = []
    credentialed_task_ids: list[str] = []

    def task_key(task_id: str) -> bytes:
        value = derive_receiver_task_key(receiver_key, task_id)
        credentialed_task_ids.append(task_id)
        task_keys.append(value)
        return value

    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=receiver_key,
            port=0,
            max_requests=2,
            max_connections=8,
            idle_timeout_seconds=120.0,
        )
    )
    receiver_result: dict[str, Any] = {}
    receiver_failure: list[BaseException] = []

    def serve_receiver() -> None:
        try:
            receiver_result.update(receiver.serve())
        except BaseException as exc:  # pragma: no cover - converted to a bounded gate failure
            receiver_failure.append(exc)

    receiver_thread: threading.Thread | None = None
    try:
        receiver_thread = threading.Thread(
            target=serve_receiver,
            name="bluefire-gate04-loopback-receiver",
            daemon=True,
        )
        receiver_thread.start()
    except BaseException as exc:
        startup_failures: list[BaseException] = [exc]
        try:
            receiver.close()
        except BaseException as close_exc:
            _extend_cleanup_failures(startup_failures, close_exc)
        try:
            if receiver_thread is not None and receiver_thread.ident is not None:
                receiver_thread.join(timeout=5.0)
        except BaseException as join_exc:
            _extend_cleanup_failures(startup_failures, join_exc)
        task_keys.clear()
        receiver_key = b""
        _raise_cleanup_failures(startup_failures)
        raise AssertionError("unreachable") from exc
    service: BlueFireService | None = None
    runtime: Path | None = None
    runtime_guard: _PinnedPrivateDirectory | None = None
    journal_guard: _PinnedPrivateDirectory | None = None
    journal_cleanup_attempted = False
    runtime_cleanup_attempted = False
    primary_failure: BaseException | None = None

    def close_runtime_service() -> None:
        nonlocal service
        current = service
        if current is not None:
            current.close()
            service = None

    try:
        journal_guard = _create_pinned_runner_journal(runs_dir)
        runtime, runtime_guard = _create_pinned_runtime(".g4-")
        runtime_stage_failure: BaseException | None = None
        try:
            try:
                bootstrapped = bootstrap_runner(
                    environ={},
                    resource_root=root / "bluefire" / "native",
                    managed_root=runtime / "managed",
                )
            except RunnerBootstrapError as exc:
                raise DefenseFrontierError("the packaged native runner is unavailable") from exc
            _require(
                current_platform() == "windows"
                and bootstrapped.source == "packaged"
                and bootstrapped.manifest.platform == "windows",
                "GATE-04 requires the packaged Windows runner on this host",
            )
            scenario = _scenario_with_bound_port(root, receiver.port)
            runner = SubprocessRustRunner(
                bootstrapped.binary_path,
                runtime / "transport",
                timeout_seconds=35.0,
                output_limit_bytes=4 * 1024 * 1024,
                receiver_task_key_factory=task_key,
                durable_result_guard=journal_guard,
            )
            service = BlueFireService(
                project_root=root,
                runs_dir=runs_dir,
                product_db_path=runtime / "product" / "product.sqlite3",
                runner_factory=lambda _profile: (runner, bootstrapped.sandbox_path),
                runner_lifecycle=ManagedRunnerLifecycle(runtime / "managed-lifecycle"),
            )
            canonical = service.run(
                _request(
                    scenario,
                    profile_id=CANONICAL_PROFILE_ID,
                    approved_by="gate-04-canonical-reviewer",
                )
            )
            frontier = service.run(
                _request(
                    scenario,
                    profile_id=FRONTIER_PROFILE_ID,
                    approved_by="gate-04-frontier-reviewer",
                )
            )
            replay = service.replay(
                str(frontier["run_id"]),
                {
                    "runner_profile_id": CANONICAL_PROFILE_ID,
                    "defense_change": DEFENSE_CHANGE_NOTE,
                    "autonomy": "auto",
                    "ai_provider_id": PROVIDER_ID,
                    "target_scope": {
                        "scope_refs": [
                            "sandbox.workspace",
                            "network.loopback",
                            "export.local",
                        ]
                    },
                    "collectors": [COLLECTOR_ID],
                    "approval": {
                        "confirmed": True,
                        "approved_by": "gate-04-replay-reviewer",
                    },
                },
            )
            receiver_thread.join(timeout=20.0)
            _require(not receiver_thread.is_alive(), "the GATE-04 receiver did not stop")
            _require(not receiver_failure, "the GATE-04 receiver failed")
            receiver_observation = {
                "summary": dict(receiver_result),
                "accepted_artifact_bindings": [
                    dict(binding) for binding in receiver.accepted_artifact_bindings
                ],
                "credentialed_task_ids": list(credentialed_task_ids),
            }
            checks = _validate_runs(canonical, frontier, replay, receiver_observation)
            primary_comparison = compare_runs(
                service.store,
                [str(canonical["run_id"]), str(frontier["run_id"]), str(replay["run_id"])],
            )
            defense_comparison = compare_runs(
                service.store,
                [str(frontier["run_id"]), str(replay["run_id"])],
            )
            run_refs = [
                {"run_id": str(run["run_id"]), "path": f"runs/{run['run_id']}"}
                for run in (canonical, frontier, replay)
            ]
            journey = {
                "schema_version": JOURNEY_SCHEMA,
                "passed": True,
                "scenario": {
                    "scenario_id": SCENARIO_ID,
                    "scenario_digest": content_hash(scenario),
                    "transport_port_source": "operating-system-assigned-loopback",
                },
                "runner": {
                    "source": bootstrapped.source,
                    "runner_id": bootstrapped.manifest.runner_id,
                    "runner_version": bootstrapped.manifest.runner_version,
                    "platform": bootstrapped.manifest.platform,
                    "architecture": bootstrapped.manifest.architecture,
                    "binary_sha256": "sha256:" + bootstrapped.binary_sha256,
                },
                "executions": [
                    _execution_summary(canonical, role="canonical"),
                    _execution_summary(frontier, role="frontier_alternate"),
                    _execution_summary(replay, role="controlled_replay"),
                ],
                "run_bundles": run_refs,
                "planner_adaptation": {
                    "provider_id": PROVIDER_ID,
                    "blocked_step_id": "try_internal_transport",
                    "selected_step_id": "preserve_approved_copy",
                    "selected_behavior_id": "sandbox.export.local.v1",
                    "selected_action_id": "sandbox.export.local.v1",
                    "selection_kind": "registered-blocked-edge-successor",
                    "structured_state_schema": "bluefire.planner-state.v1",
                },
                "receiver_observation": receiver_observation,
                "checks": dict(checks),
            }
            defense = {
                "schema_version": DEFENSE_SCHEMA,
                "passed": True,
                "changes": [
                    {
                        "change_id": "defense.loopback.block.v1",
                        "kind": "runner-profile-control",
                        "applied": True,
                        "from_profile_id": CANONICAL_PROFILE_ID,
                        "to_profile_id": FRONTIER_PROFILE_ID,
                        "from_profile_digest": _profile_digest(canonical),
                        "to_profile_digest": _profile_digest(frontier),
                        "expected_effect": "block sandbox.network.loopback.v1 before dispatch",
                        "observed_effect": "control_blocked_then_registered_local_export",
                        "from_run_id": canonical["run_id"],
                        "to_run_id": frontier["run_id"],
                    },
                    {
                        "change_id": "defense.loopback.restore.v1",
                        "kind": "runner-profile-control",
                        "applied": True,
                        "from_profile_id": FRONTIER_PROFILE_ID,
                        "to_profile_id": CANONICAL_PROFILE_ID,
                        "from_profile_digest": _profile_digest(frontier),
                        "to_profile_digest": _profile_digest(replay),
                        "expected_effect": "restore reviewed authenticated loopback transport",
                        "observed_effect": "canonical_transport_replayed",
                        "from_run_id": frontier["run_id"],
                        "to_run_id": replay["run_id"],
                        "replay_lineage_digest": content_hash(replay["replay"]),
                    },
                ],
            }
            comparison = {
                "schema_version": COMPARISON_SCHEMA,
                "passed": True,
                "run_ids": [canonical["run_id"], frontier["run_id"], replay["run_id"]],
                "primary": primary_comparison,
                "defense_replay": defense_comparison,
                "required_explanations": [
                    "path_difference",
                    "first_block",
                    "prevention_bypass",
                    "detection_bypass",
                    "telemetry_delta",
                    "objective_result",
                    "authoritative_cleanup",
                    "defensive_effect",
                ],
            }
            structural = _structural_report(root)
            for run in (canonical, frontier, replay):
                _require(
                    service.store.validate_bundle(str(run["run_id"])).get("valid") is True,
                    "a frontier run bundle failed integrity validation",
                )
        except BaseException as exc:
            runtime_stage_failure = exc
        finally:
            runtime_failures: list[BaseException] = []
            if runtime_stage_failure is not None:
                _extend_cleanup_failures(runtime_failures, runtime_stage_failure)
            try:
                _close_runtime_and_remove(runtime, runtime_guard, close_runtime_service)
            except BaseException as exc:
                _extend_cleanup_failures(runtime_failures, exc)
            finally:
                runtime_cleanup_attempted = True
            _raise_cleanup_failures(runtime_failures)
        try:
            _remove_runner_journal(runs_dir, journal_guard)
        finally:
            journal_cleanup_attempted = True
        for name, report in zip(
            REPORT_PATHS,
            (journey, defense, comparison, structural),
            strict=True,
        ):
            _write_json(destination / name, report)
        _assert_secrets_absent(destination, [receiver_key, *task_keys])
        return {
            "schema_version": HELPER_SCHEMA,
            "status": "passed",
            "reports": list(REPORT_PATHS),
            "run_count": 3,
        }
    except BaseException as exc:
        primary_failure = exc
    finally:
        final_failures: list[BaseException] = []
        if primary_failure is not None:
            _extend_cleanup_failures(final_failures, primary_failure)
        if runtime is not None and not runtime_cleanup_attempted:
            try:
                if runtime_guard is None:
                    close_runtime_service()
                else:
                    _close_runtime_and_remove(
                        runtime,
                        runtime_guard,
                        close_runtime_service,
                    )
            except BaseException as exc:
                _extend_cleanup_failures(final_failures, exc)
        if journal_guard is not None and not journal_cleanup_attempted:
            try:
                _remove_runner_journal(runs_dir, journal_guard)
            except BaseException as exc:
                _extend_cleanup_failures(final_failures, exc)
        try:
            receiver.close()
        except BaseException as exc:
            _extend_cleanup_failures(final_failures, exc)
        try:
            if receiver_thread is not None and receiver_thread.is_alive():
                receiver_thread.join(timeout=5.0)
            if receiver_thread is not None and receiver_thread.is_alive():
                raise DefenseFrontierError("the GATE-04 receiver did not stop")
        except BaseException as exc:
            _extend_cleanup_failures(final_failures, exc)
        # Bytes are immutable; dropping every reference is the only portable
        # process-local cleanup. No representation is persisted.
        task_keys.clear()
        receiver_key = b""
        _raise_cleanup_failures(final_failures)
    raise AssertionError("defense-frontier journey completed without a result")


__all__ = [
    "COMPARISON_REPORT",
    "DEFENSE_REPORT",
    "DefenseFrontierError",
    "HELPER_SCHEMA",
    "JOURNEY_REPORT",
    "REPORT_PATHS",
    "STRUCTURAL_REPORT",
    "produce_defense_frontier_evidence",
]
