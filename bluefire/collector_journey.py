"""Native Execute/replay journey for independent collector acceptance.

The journey uses the maintained adaptive scenario, packaged Windows Rust runner,
normal :class:`BlueFireService` Execute and replay boundaries, fresh approvals,
and a managed collector registry.  It does not manufacture run bundles or action
effects: the service and runner own both runs, while collectors independently
observe the still-live sandbox, a control-plane-owned child, and the authenticated
loopback receiver.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Mapping

from .collector_comparison import summarize_collector_session
from .collector_interfaces import (
    CloudIdentityAuditAdapter,
    LinuxAuditRuntimeAdapter,
    SecurityQueryAdapter,
    WindowsEventLogAdapter,
)
from .collectors import (
    CollectionSession,
    CollectorError,
    CollectorRegistry,
    CollectorRuntimeSettings,
    FilesystemCollector,
    LoopbackReceiverCollector,
    NativeProcessCollector,
    filesystem_observation_key,
    optional_collector_descriptors,
    reconcile_observations,
)
from .comparison import compare_runs
from .defense_frontier import (
    CANONICAL_PROFILE_ID,
    FRONTIER_PROFILE_ID,
    PROVIDER_ID,
    _assert_secrets_absent,
    _close_runtime_and_remove,
    _create_pinned_runner_journal,
    _create_pinned_runtime,
    _extend_cleanup_failures,
    _raise_cleanup_failures,
    _remove_runner_journal,
    _scenario_with_bound_port,
)
from .evidence import EvidenceProvenance, EvidenceRecord
from .receiver import LoopbackArtifactReceiver, ReceiverConfig
from .receiver_auth import derive_receiver_task_key
from .runner_bootstrap import RunnerBootstrapError, bootstrap_runner, current_platform
from .runner_client import SubprocessRustRunner
from .runner_lifecycle import ManagedRunnerLifecycle
from .runner_private_files import _PinnedPrivateDirectory
from .service import BlueFireService

JOURNEY_REPORT = "gate05-collector-journey.json"
PLATFORM_REPORT = "gate05-platform-readiness.json"
COMPARISON_REPORT = "gate05-collector-comparison.json"
CORRUPTION_REPORT = "gate05-corruption-refusal.json"
REPORT_PATHS = (
    JOURNEY_REPORT,
    PLATFORM_REPORT,
    COMPARISON_REPORT,
    CORRUPTION_REPORT,
)
HELPER_SCHEMA = "bluefire.gate-05-helper.v1"
JOURNEY_SCHEMA = "bluefire.collector-journey.v1"
PLATFORM_SCHEMA = "bluefire.collector-platform-readiness.v1"
CORRUPTION_SCHEMA = "bluefire.collector-corruption-refusal.v1"

_MAX_REPORT_BYTES = 8 * 1024 * 1024
_COLLECT_AFTER_STEP = "try_internal_transport"
_BUNDLE_PATH = "staged/bundle.jsonl"
_DEFENSE_CHANGE = (
    "collector-gate-network-observer.v1: restore reviewed loopback transport "
    "and enable its independent receiver collector"
)


class CollectorJourneyError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CollectorJourneyError(message)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    _require(
        len(payload) <= _MAX_REPORT_BYTES and not path.exists() and path.parent.is_dir(),
        "a GATE-05 report path is stale or invalid",
    )
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        before = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino)
        _require(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "a GATE-05 report target is unsafe",
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "a GATE-05 report write made no progress")
            offset += written
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = bytearray()
        while len(observed) <= _MAX_REPORT_BYTES:
            block = os.read(descriptor, min(64 * 1024, _MAX_REPORT_BYTES + 1 - len(observed)))
            if not block:
                break
            observed.extend(block)
        after = os.fstat(descriptor)
        _require(
            bytes(observed) == payload
            and (after.st_dev, after.st_ino) == identity
            and stat.S_ISREG(after.st_mode)
            and after.st_nlink == 1,
            "a GATE-05 report changed during publication",
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


def _runtime_settings(
    *,
    process_id: int,
    parent_process_id: int,
    network_enabled: bool,
) -> CollectorRuntimeSettings:
    schedule = {"collect_after_step": _COLLECT_AFTER_STEP}
    return CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {**schedule, "paths": [_BUNDLE_PATH]},
            },
            NativeProcessCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    **schedule,
                    "process_id": process_id,
                    "expected_parent_process_id": parent_process_id,
                },
            },
            LoopbackReceiverCollector.descriptor.id: {
                "enabled": network_enabled,
                "settings": schedule,
            },
        }
    )


def _execute_request(
    scenario: Mapping[str, Any],
    *,
    profile_id: str,
    approved_by: str,
    settings: CollectorRuntimeSettings,
) -> Mapping[str, Any]:
    return {
        "scenario": dict(scenario),
        "mode": "execute",
        "runner_profile_id": profile_id,
        "target_scope": {"scope_refs": ["sandbox.workspace", "network.loopback", "export.local"]},
        "autonomy": "auto",
        "ai_provider_id": PROVIDER_ID,
        "collector_runtime": settings.to_dict(),
        "approval": {"confirmed": True, "approved_by": approved_by},
    }


def _replay_request(
    *,
    settings: CollectorRuntimeSettings,
) -> Mapping[str, Any]:
    return {
        "runner_profile_id": CANONICAL_PROFILE_ID,
        "defense_change": _DEFENSE_CHANGE,
        "autonomy": "auto",
        "ai_provider_id": PROVIDER_ID,
        "target_scope": {"scope_refs": ["sandbox.workspace", "network.loopback", "export.local"]},
        "collector_runtime": settings.to_dict(),
        "approval": {"confirmed": True, "approved_by": "gate-05-replay-reviewer"},
    }


def _step(run: Mapping[str, Any], step_id: str) -> Mapping[str, Any]:
    rows = run.get("steps")
    matches = (
        [row for row in rows if isinstance(row, Mapping) and row.get("step_id") == step_id]
        if isinstance(rows, list)
        else []
    )
    _require(len(matches) == 1, f"GATE-05 run omitted or repeated step {step_id}")
    return matches[0]


def _session(run: Mapping[str, Any]) -> CollectionSession:
    value = run.get("collector_session")
    _require(isinstance(value, Mapping), "GATE-05 run collector session is absent")
    assert isinstance(value, Mapping)
    try:
        session = CollectionSession.from_mapping(value)
    except CollectorError as exc:
        raise CollectorJourneyError("GATE-05 run collector session is invalid") from exc
    return session


def _observed(session: CollectionSession, collector_id: str) -> EvidenceRecord:
    result = session.results.get(collector_id)
    records = (
        tuple(
            record for record in result.records if record.provenance is EvidenceProvenance.OBSERVED
        )
        if result is not None
        else ()
    )
    _require(
        result is not None and result.health.readiness.value == "ready" and len(records) == 1,
        f"GATE-05 collector {collector_id} did not produce one healthy observation",
    )
    return records[0]


def _transport_binding(run: Mapping[str, Any]) -> Mapping[str, Any]:
    step = _step(run, _COLLECT_AFTER_STEP)
    artifacts = step.get("artifacts")
    receipt = artifacts.get("receipt") if isinstance(artifacts, Mapping) else None
    details = receipt.get("details") if isinstance(receipt, Mapping) else None
    task_id = step.get("runner_task_id")
    digest = details.get("sha256") if isinstance(details, Mapping) else None
    byte_count = details.get("bytes_sent") if isinstance(details, Mapping) else None
    _require(
        step.get("status") == "success"
        and isinstance(task_id, str)
        and task_id.startswith("execute-")
        and isinstance(digest, str)
        and len(digest) == 64
        and isinstance(byte_count, int)
        and not isinstance(byte_count, bool)
        and byte_count > 0,
        "GATE-05 replay transport receipt is invalid",
    )
    return {"task_id": task_id, "sha256": digest, "bytes_received": byte_count}


def _predicted_fields(
    replay: Mapping[str, Any],
    *,
    process_id: int,
    parent_process_id: int,
    receiver_session_id: str,
) -> Mapping[str, Mapping[str, Any]]:
    stage = _step(replay, "stage_evidence")
    artifacts = stage.get("artifacts")
    bundle = artifacts.get("bundle") if isinstance(artifacts, Mapping) else None
    _require(isinstance(bundle, Mapping), "GATE-05 real staged bundle is absent")
    assert isinstance(bundle, Mapping)
    path = bundle.get("path")
    size = bundle.get("size")
    digest = bundle.get("sha256")
    _require(
        isinstance(path, str)
        and path == _BUNDLE_PATH
        and isinstance(size, int)
        and not isinstance(size, bool)
        and size > 0
        and isinstance(digest, str)
        and len(digest) == 64,
        "GATE-05 real staged bundle identity is invalid",
    )
    assert isinstance(path, str)
    network = _transport_binding(replay)
    return {
        filesystem_observation_key(path): {
            "path": path,
            "size_bytes": size,
            "sha256": digest,
        },
        "process/native-child": {
            "process_id": process_id,
            "parent_process_id": parent_process_id,
            "executable_name": Path(sys.executable).name,
            "command_line": "intentionally not collected",
        },
        f"network/authenticated-receiver/{network['task_id']}": {
            **network,
            "receiver_session_id": receiver_session_id,
        },
        "system/kernel-audit": {"event": "optional platform adapter"},
    }


def _corruption_checks(
    session: CollectionSession,
    run: Mapping[str, Any],
) -> Mapping[str, bool]:
    original = session.to_dict()
    first_collector = next(iter(original["results"]))
    content_tamper = copy.deepcopy(original)
    content_tamper["results"][first_collector]["records"][0]["content"]["tampered"] = True
    health_tamper = copy.deepcopy(original)
    health_tamper["results"][first_collector]["health"]["summary"] = "altered"
    settings_tamper = copy.deepcopy(original)
    settings_tamper["settings"]["collectors"][first_collector]["enabled"] = False
    source_record = session.results[first_collector].records[0]
    altered_record = EvidenceRecord.create(
        run_id=source_record.run_id,
        step_id=source_record.step_id,
        behavior_id=source_record.behavior_id,
        action_id=source_record.action_id,
        provenance=source_record.provenance,
        producer=source_record.producer,
        runner_profile_id=source_record.runner_profile_id,
        environment=source_record.environment,
        timestamp=source_record.timestamp,
        parent_evidence_ids=source_record.parent_evidence_ids,
        content={**source_record.content, "semantically_rewritten": True},
        confidence=source_record.confidence,
        limitations=source_record.limitations,
        target_scope_ref=source_record.target_scope_ref,
    )
    rewritten_evidence = [
        record.to_dict() for result in session.results.values() for record in result.records
    ]
    rewritten_evidence[0] = altered_record.to_dict()

    def refused(document: Mapping[str, Any]) -> bool:
        try:
            CollectionSession.from_mapping(document)
        except CollectorError:
            return True
        return False

    try:
        summarize_collector_session(
            original,
            rewritten_evidence,
            source_record.run_id,
            run.get("steps"),
        )
    except CollectorError:
        semantic_rewrite_refused = True
    else:
        semantic_rewrite_refused = False
    return {
        "content_hash_mismatch_refused": refused(content_tamper),
        "health_session_hash_mismatch_refused": refused(health_tamper),
        "settings_hash_mismatch_refused": refused(settings_tamper),
        "semantically_rehashed_evidence_refused": semantic_rewrite_refused,
        "unaltered_session_verified": CollectionSession.from_mapping(original).to_dict()
        == original,
    }


def _start_child() -> subprocess.Popen[bytes]:
    command = [sys.executable, "-I", "-B", "-c", "import time; time.sleep(120)"]
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creation_flags,
    )


def _stop_child(child: subprocess.Popen[bytes] | None) -> None:
    if child is None or child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=3)


def produce_collector_evidence(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, Any]:
    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require(
        root.is_dir() and not root.is_symlink() and (root / "pyproject.toml").is_file(),
        "GATE-05 repository root is invalid",
    )
    _require(
        destination.is_dir() and not destination.is_symlink(),
        "GATE-05 evidence directory is invalid",
    )
    _require(
        not any((destination / name).exists() for name in REPORT_PATHS)
        and not (destination / "runs").exists(),
        "GATE-05 evidence directory contains stale owned artifacts",
    )
    run_root = destination / "runs"
    run_root.mkdir(mode=0o700)

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
            max_requests=1,
            max_connections=8,
            max_body_bytes=4 * 1024 * 1024,
            request_timeout_seconds=5.0,
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
    child: subprocess.Popen[bytes] | None = None
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
        receiver_thread = threading.Thread(
            target=serve_receiver,
            name="bluefire-gate05-loopback-receiver",
            daemon=True,
        )
        receiver_thread.start()
        child = _start_child()
        parent_process_id = os.getpid()
        baseline_settings = _runtime_settings(
            process_id=child.pid,
            parent_process_id=parent_process_id,
            network_enabled=False,
        )
        replay_settings = _runtime_settings(
            process_id=child.pid,
            parent_process_id=parent_process_id,
            network_enabled=True,
        )

        journal_guard = _create_pinned_runner_journal(run_root)
        runtime, runtime_guard = _create_pinned_runtime(".g5-")
        runtime_stage_failure: BaseException | None = None
        try:
            try:
                bootstrapped = bootstrap_runner(
                    environ={},
                    resource_root=root / "bluefire" / "native",
                    managed_root=runtime / "managed",
                )
            except RunnerBootstrapError as exc:
                raise CollectorJourneyError("the packaged native runner is unavailable") from exc
            _require(
                current_platform() == "windows"
                and bootstrapped.source == "packaged"
                and bootstrapped.manifest.platform == "windows",
                "GATE-05 requires the packaged Windows runner on this host",
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

            def collector_registry_factory(sandbox: Path) -> CollectorRegistry:
                return CollectorRegistry(
                    (
                        FilesystemCollector(sandbox),
                        NativeProcessCollector({child.pid: parent_process_id}),
                        LoopbackReceiverCollector(receiver),
                    )
                )

            service = BlueFireService(
                project_root=root,
                runs_dir=run_root,
                product_db_path=runtime / "product" / "product.sqlite3",
                runner_factory=lambda _profile: (runner, bootstrapped.sandbox_path),
                runner_lifecycle=ManagedRunnerLifecycle(runtime / "managed-lifecycle"),
                collector_registry_factory=collector_registry_factory,
            )
            baseline = service.run(
                _execute_request(
                    scenario,
                    profile_id=FRONTIER_PROFILE_ID,
                    approved_by="gate-05-baseline-reviewer",
                    settings=baseline_settings,
                )
            )
            replay = service.replay(
                str(baseline["run_id"]),
                _replay_request(settings=replay_settings),
            )
            receiver_thread.join(timeout=20.0)
            _require(not receiver_thread.is_alive(), "GATE-05 receiver did not stop")
            _require(not receiver_failure, "GATE-05 receiver failed")

            baseline_session = _session(baseline)
            replay_session = _session(replay)
            baseline_transport = _step(baseline, _COLLECT_AFTER_STEP)
            replay_transport = _step(replay, _COLLECT_AFTER_STEP)
            _require(
                baseline.get("status") == "completed"
                and baseline.get("objective_reached") is True
                and baseline.get("runner_profile_id") == FRONTIER_PROFILE_ID
                and baseline_transport.get("status") == "blocked",
                "GATE-05 baseline did not traverse the maintained blocked profile",
            )
            _require(
                replay.get("status") == "completed"
                and replay.get("objective_reached") is True
                and replay.get("runner_profile_id") == CANONICAL_PROFILE_ID
                and replay_transport.get("status") == "success",
                "GATE-05 replay did not traverse the maintained canonical profile",
            )
            lineage = replay.get("replay")
            _require(
                isinstance(lineage, Mapping)
                and lineage.get("source_run_id") == baseline.get("run_id")
                and lineage.get("collector_settings_changed") is True
                and lineage.get("collector_settings_from") == baseline_settings.settings_hash
                and lineage.get("collector_settings_to") == replay_settings.settings_hash,
                "GATE-05 controlled replay omitted collector settings lineage",
            )

            baseline_filesystem = _observed(baseline_session, FilesystemCollector.descriptor.id)
            baseline_process = _observed(baseline_session, NativeProcessCollector.descriptor.id)
            replay_filesystem = _observed(replay_session, FilesystemCollector.descriptor.id)
            replay_process = _observed(replay_session, NativeProcessCollector.descriptor.id)
            replay_network = _observed(replay_session, LoopbackReceiverCollector.descriptor.id)
            _require(
                LoopbackReceiverCollector.descriptor.id not in baseline_session.results
                and baseline_session.settings.settings_hash == baseline_settings.settings_hash
                and replay_session.settings.settings_hash == replay_settings.settings_hash,
                "GATE-05 settings did not change the invoked backend set",
            )
            _require(
                replay_process.content.get("mechanism")
                in {"CreateToolhelp32Snapshot/GetProcessTimes", "/proc/<pid>/stat"},
                "GATE-05 native process backend was not exercised",
            )
            transport_binding = _transport_binding(replay)
            _require(
                replay_network.content.get("observed_fields")
                == {
                    **transport_binding,
                    "receiver_process_id": receiver.process_id,
                    "receiver_session_id": receiver.session_id,
                },
                "GATE-05 receiver observation does not match the real transport receipt",
            )
            expected_binding = dict(transport_binding)
            accepted_bindings = [dict(item) for item in receiver.accepted_artifact_bindings]
            _require(
                receiver_result.get("requests_accepted") == 1
                and accepted_bindings == [expected_binding]
                and credentialed_task_ids == [expected_binding["task_id"]],
                "GATE-05 receiver did not bind the canonical replay transfer",
            )

            predicted = _predicted_fields(
                replay,
                process_id=child.pid,
                parent_process_id=parent_process_id,
                receiver_session_id=receiver.session_id,
            )
            replay_records = tuple(
                record for result in replay_session.results.values() for record in result.records
            )
            reconciliation = reconcile_observations(predicted, replay_records)
            _require(
                reconciliation["missing_observations"] == ["system/kernel-audit"]
                and any(
                    row["missing_fields"] or row["unexpected_fields"]
                    for row in reconciliation["field_comparisons"]
                ),
                "GATE-05 field reconciliation did not expose missing and unexpected fields",
            )
            comparison = compare_runs(
                service.store,
                [str(baseline["run_id"]), str(replay["run_id"])],
            )
            delta = comparison["deltas"][0]
            _require(
                delta["collector_session_changed"] is True
                and delta["collector_session_delta"]["collectors_enabled"]
                == [LoopbackReceiverCollector.descriptor.id]
                and delta["collector_session_delta"]["observation_delta"] == 1
                and delta["replay_lineage_changed"] is True,
                "GATE-05 replay comparison omitted the collector delta",
            )
            corruption = _corruption_checks(replay_session, replay)
            _require(all(corruption.values()), "GATE-05 corruption refusal is incomplete")
            run_ids = [str(baseline["run_id"]), str(replay["run_id"])]
            _require(
                all(
                    service.store.validate_bundle(run_id).get("valid") is True for run_id in run_ids
                ),
                "a GATE-05 run bundle failed integrity validation",
            )

            journey_report = {
                "schema_version": JOURNEY_SCHEMA,
                "passed": True,
                "run_ids": run_ids,
                "run_bundles": [{"run_id": run_id, "path": f"runs/{run_id}"} for run_id in run_ids],
                "collectors": [
                    descriptor.to_dict()
                    for descriptor in (
                        FilesystemCollector.descriptor,
                        LoopbackReceiverCollector.descriptor,
                        NativeProcessCollector.descriptor,
                    )
                ],
                "baseline_session": baseline_session.to_dict(),
                "replay_session": replay_session.to_dict(),
                "predicted_fields": predicted,
                "reconciliation": reconciliation,
                "receiver": {
                    "summary": dict(receiver_result),
                    "session_id": receiver.session_id,
                    "accepted_artifact_bindings": accepted_bindings,
                    "credentialed_task_ids": list(credentialed_task_ids),
                    "transport_artifact": expected_binding,
                },
                "execution": {
                    "scenario_id": scenario["id"],
                    "runner_source": bootstrapped.source,
                    "runner_platform": bootstrapped.manifest.platform,
                    "baseline_profile_id": baseline["runner_profile_id"],
                    "replay_profile_id": replay["runner_profile_id"],
                    "collect_after_step": _COLLECT_AFTER_STEP,
                },
                "checks": {
                    "process_observed": bool(baseline_process and replay_process),
                    "filesystem_observed": bool(baseline_filesystem and replay_filesystem),
                    "network_observed": bool(replay_network),
                    "native_backend_exercised": True,
                    "lineage_and_hashes_verified": True,
                    "settings_toggle_changed_backend_set": True,
                    "replay_comparison_delta_verified": True,
                },
            }
            platform_report = {
                "schema_version": PLATFORM_SCHEMA,
                "passed": True,
                "optional_collectors": [
                    descriptor.to_dict() for descriptor in optional_collector_descriptors()
                ],
                "adapter_interfaces": [
                    WindowsEventLogAdapter.__name__,
                    LinuxAuditRuntimeAdapter.__name__,
                    CloudIdentityAuditAdapter.__name__,
                    SecurityQueryAdapter.__name__,
                ],
                "configured": False,
                "readiness": "not_configured",
                "limitations": [
                    "Optional external adapters require deployment-owned read-only credentials."
                ],
            }
            corruption_report = {
                "schema_version": CORRUPTION_SCHEMA,
                "passed": True,
                "checks": dict(corruption),
            }
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
            _remove_runner_journal(run_root, journal_guard)
        finally:
            journal_cleanup_attempted = True
        for name, report in zip(
            REPORT_PATHS,
            (journey_report, platform_report, comparison, corruption_report),
            strict=True,
        ):
            _write_json(destination / name, report)
        _assert_secrets_absent(destination, [receiver_key, *task_keys])
        return {
            "schema_version": HELPER_SCHEMA,
            "status": "passed",
            "reports": list(REPORT_PATHS),
            "run_count": 2,
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
                _remove_runner_journal(run_root, journal_guard)
            except BaseException as exc:
                _extend_cleanup_failures(final_failures, exc)
        try:
            receiver.stop()
        except BaseException as exc:
            _extend_cleanup_failures(final_failures, exc)
        try:
            if receiver_thread is not None and receiver_thread.is_alive():
                receiver_thread.join(timeout=5.0)
            if receiver_thread is not None and receiver_thread.is_alive():
                raise CollectorJourneyError("GATE-05 receiver did not stop")
        except BaseException as exc:
            _extend_cleanup_failures(final_failures, exc)
        try:
            receiver.close()
        except BaseException as exc:
            _extend_cleanup_failures(final_failures, exc)
        try:
            _stop_child(child)
        except BaseException as exc:
            _extend_cleanup_failures(final_failures, exc)
        task_keys.clear()
        receiver_key = b""
        _raise_cleanup_failures(final_failures)
    raise AssertionError("collector journey completed without a result")


__all__ = [
    "COMPARISON_REPORT",
    "CORRUPTION_REPORT",
    "CollectorJourneyError",
    "HELPER_SCHEMA",
    "JOURNEY_REPORT",
    "JOURNEY_SCHEMA",
    "PLATFORM_REPORT",
    "PLATFORM_SCHEMA",
    "REPORT_PATHS",
    "produce_collector_evidence",
]
