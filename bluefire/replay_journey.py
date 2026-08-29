"""Packaged-runner evidence journey for GATE-06 materialized replay."""

from __future__ import annotations

import copy
import json
import os
import secrets
import stat
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Mapping, cast

from .api import APIError
from .defense_frontier import (
    CANONICAL_PROFILE_ID,
    FRONTIER_PROFILE_ID,
    PROVIDER_ID,
    _assert_secrets_absent,
    _close_runtime_and_remove,
    _remove_runner_journal,
    _runtime_temp_parent,
    _scenario_with_bound_port,
)
from .receiver import LoopbackArtifactReceiver, ReceiverConfig
from .receiver_auth import derive_receiver_task_key
from .replay_checkpoint import checkpoint_for_step, validate_checkpoint
from .runner_bootstrap import RunnerBootstrapError, bootstrap_runner, current_platform
from .runner_client import SubprocessRustRunner
from .runner_lifecycle import ManagedRunnerLifecycle
from .service import BlueFireService
from .util import canonical_json_bytes, content_hash, file_hash

JOURNEY_REPORT = "gate06-journey-report.json"
CORRUPTION_REPORT = "gate06-corruption-report.json"
COMPARISON_REPORT = "gate06-comparison-report.json"
REPORT_PATHS = (JOURNEY_REPORT, CORRUPTION_REPORT, COMPARISON_REPORT)
HELPER_SCHEMA = "bluefire.gate-06-helper.v1"
JOURNEY_SCHEMA = "bluefire.replay-gate-journey.v1"
CORRUPTION_SCHEMA = "bluefire.replay-gate-corruption.v1"

RESTART_STEP_ID = "choose_discovery"
PARAMETER_STEP_ID = "stage_evidence"
SWAP_STEP_ID = "choose_discovery"
SWAP_BEHAVIOR_ID = "sandbox.discovery.metadata.v1"
SWAP_ACTION_ID = "sandbox.discovery.metadata.v1"
DEFENSE_CHANGE = (
    "gate-06-reviewed-defense.v1: enable the approved loopback transport profile "
    "after materialized prefix verification"
)
TARGET_SCOPE = {"scope_refs": ["sandbox.workspace", "network.loopback", "export.local"]}
DIMENSIONS = frozenset(
    {
        "planner",
        "scope",
        "implementation",
        "evidence",
        "detection",
        "cleanup",
        "budgets",
        "assessment",
    }
)
_MAX_REPORT_BYTES = 8 * 1024 * 1024


class ReplayJourneyError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayJourneyError(message)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    _require(
        len(payload) <= _MAX_REPORT_BYTES and path.parent.is_dir() and not path.exists(),
        "a GATE-06 report path is stale or invalid",
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
            "a GATE-06 report target is unsafe",
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "a GATE-06 report write made no progress")
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
            "a GATE-06 report changed during publication",
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


class _CountingRunner:
    """Preserve the task-aware runner boundary while counting real dispatches."""

    def __init__(self, runner: SubprocessRustRunner) -> None:
        self._runner = runner
        self.dispatch_count = 0

    def inventory(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self._runner.inventory())

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        self.dispatch_count += 1
        return cast(Mapping[str, Any], self._runner.execute(manifest, profile))

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        self.dispatch_count += 1
        return cast(
            Mapping[str, Any],
            self._runner.execute_task(
                manifest,
                profile,
                task_id=task_id,
                cancel_event=cancel_event,
                durable_result_path=durable_result_path,
            ),
        )


def _scenario(repository: Path, port: int) -> Mapping[str, Any]:
    """Derive the stateful file chain from the maintained adaptive scenario."""

    source = cast(dict[str, Any], copy.deepcopy(_scenario_with_bound_port(repository, port)))
    removed = {"inspect_system", "inspect_processes"}
    source["id"] = "scenario.gate-06.materialized-replay.v1"
    source["title"] = "Materialized Restart Replay Acceptance"
    source["purpose"] = (
        "Create and transform a deterministic fixture, restart from its dependent "
        "discovery node, exercise reviewed replay variants, and clean every workspace."
    )
    source["steps"] = [step for step in source["steps"] if step.get("id") not in removed]
    source["edges"] = [
        edge
        for edge in source["edges"]
        if edge.get("from_step") not in removed and edge.get("to_step") not in removed
    ]
    source["edges"].insert(
        0,
        {
            "from_step": "create_fixture",
            "outcome": "success",
            "to_step": "transform_fixture",
        },
    )
    return source


def _approval(identity: str) -> Mapping[str, Any]:
    return {"confirmed": True, "approved_by": identity}


def _source_request(scenario: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "scenario": dict(scenario),
        "mode": "execute",
        "runner_profile_id": FRONTIER_PROFILE_ID,
        "target_scope": dict(TARGET_SCOPE),
        "autonomy": "off",
        "approval": _approval("gate-06-source-reviewer"),
    }


def _restart_request(identity: str, **variants: Any) -> Mapping[str, Any]:
    return {
        "from_step_id": RESTART_STEP_ID,
        "target_scope": dict(TARGET_SCOPE),
        "approval": _approval(identity),
        **variants,
    }


def _step(run: Mapping[str, Any], step_id: str) -> Mapping[str, Any]:
    rows = run.get("steps")
    matches = (
        [row for row in rows if isinstance(row, Mapping) and row.get("step_id") == step_id]
        if isinstance(rows, list)
        else []
    )
    _require(len(matches) == 1, "a GATE-06 run omitted an expected unique step")
    return matches[0]


def _approval_id(run: Mapping[str, Any]) -> str:
    approval = run.get("approval")
    value = approval.get("approval_id") if isinstance(approval, Mapping) else None
    if not isinstance(value, str) or not value.startswith("approval-"):
        raise ReplayJourneyError("a GATE-06 approval is absent")
    return value


def _materialization(run: Mapping[str, Any], checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
    report = run.get("checkpoint_materialization")
    rows = run.get("materialization_steps")
    if not isinstance(report, Mapping) or not isinstance(rows, list):
        raise ReplayJourneyError(
            "a GATE-06 candidate did not verify freshly materialized prefix state"
        )
    _require(
        report.get("status") == "verified"
        and report.get("checkpoint_id") == checkpoint.get("checkpoint_id")
        and report.get("manifest_hash") == checkpoint.get("manifest_hash")
        and report.get("candidate_run_id") == run.get("run_id")
        and report.get("approval_id") == _approval_id(run)
        and report.get("fresh_receipt_count", 0) > 0
        and report.get("source_receipts_reused") is False
        and [row.get("step_id") for row in rows]
        == [row.get("step_id") for row in checkpoint["executed_steps"]]
        and all(isinstance(row.get("runner_task_id"), str) for row in rows),
        "a GATE-06 candidate did not verify freshly materialized prefix state",
    )
    return report


def _rewrite_checkpoint_and_refuse(
    service: BlueFireService,
    runner: _CountingRunner,
    run_root: Path,
    source_run_id: str,
    mutate: Callable[[dict[str, Any]], None],
    identity: str,
) -> Mapping[str, Any]:
    bundle = run_root / source_run_id
    result_path = bundle / "result.json"
    manifest_path = bundle / "manifest.json"
    original_result = result_path.read_bytes()
    original_manifest = manifest_path.read_bytes()
    before = runner.dispatch_count
    code: str | None = None
    try:
        result = json.loads(original_result)
        checkpoints = result.get("replay_checkpoints")
        _require(isinstance(checkpoints, list), "GATE-06 source checkpoint inventory is absent")
        selected = next(
            item for item in checkpoints if item.get("checkpoint_before_step_id") == RESTART_STEP_ID
        )
        mutate(selected)
        result_path.write_bytes(canonical_json_bytes(result) + b"\n")
        manifest = json.loads(original_manifest)
        manifest["files"]["result.json"] = {
            "hash": file_hash(result_path),
            "size_bytes": result_path.stat().st_size,
        }
        manifest["bundle_hash"] = content_hash(manifest["files"])
        manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
        try:
            service.replay(
                source_run_id,
                _restart_request(identity, exact=True),
            )
        except APIError as exc:
            code = exc.code
    finally:
        result_path.write_bytes(original_result)
        manifest_path.write_bytes(original_manifest)
    return {
        "refused": code == "replay_refused",
        "error_code": code,
        "dispatch_count_before": before,
        "dispatch_count_after": runner.dispatch_count,
    }


def _corruption_report(
    service: BlueFireService,
    runner: _CountingRunner,
    run_root: Path,
    source_run_id: str,
) -> Mapping[str, Any]:
    manifest_refusal = _rewrite_checkpoint_and_refuse(
        service,
        runner,
        run_root,
        source_run_id,
        lambda checkpoint: checkpoint.__setitem__("manifest_hash", "sha256:" + "0" * 64),
        "gate-06-corrupt-manifest-reviewer",
    )

    def corrupt_material(checkpoint: dict[str, Any]) -> None:
        files = checkpoint.get("material_files")
        if not isinstance(files, list) or not files or not isinstance(files[0], dict):
            raise ReplayJourneyError("GATE-06 checkpoint has no material file")
        files[0]["sha256"] = "sha256:" + "f" * 64

    material_refusal = _rewrite_checkpoint_and_refuse(
        service,
        runner,
        run_root,
        source_run_id,
        corrupt_material,
        "gate-06-corrupt-material-reviewer",
    )
    passed = all(
        item.get("refused") is True
        and item.get("dispatch_count_before") == item.get("dispatch_count_after")
        for item in (manifest_refusal, material_refusal)
    )
    _require(passed, "GATE-06 checkpoint corruption was not refused before dispatch")
    return {
        "schema_version": CORRUPTION_SCHEMA,
        "passed": True,
        "source_run_id": source_run_id,
        "refusals": {
            "manifest_hash": manifest_refusal,
            "material_digest": material_refusal,
        },
    }


def _comparison_dimensions(comparison: Mapping[str, Any]) -> bool:
    summaries = comparison.get("summaries")
    deltas = comparison.get("deltas")
    return (
        isinstance(summaries, list)
        and isinstance(deltas, list)
        and len(summaries) == 4
        and len(deltas) == 3
        and all(
            isinstance(row, Mapping) and set(row.get("dimensions", {})) == DIMENSIONS
            for row in summaries
        )
        and all(
            isinstance(row, Mapping) and set(row.get("dimensions", {})) == DIMENSIONS
            for row in deltas
        )
    )


def produce_replay_gate_evidence(repository: Path, evidence_dir: Path) -> Mapping[str, Any]:
    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require(
        root.is_dir() and not root.is_symlink() and (root / "pyproject.toml").is_file(),
        "GATE-06 repository root is invalid",
    )
    _require(
        destination.is_dir()
        and not destination.is_symlink()
        and not any((destination / name).exists() for name in REPORT_PATHS)
        and not (destination / "runs").exists(),
        "GATE-06 evidence directory contains stale owned artifacts",
    )
    run_root = destination / "runs"
    run_root.mkdir(mode=0o700)

    receiver_key = secrets.token_bytes(32)
    task_keys: list[bytes] = []
    credentialed_task_ids: list[str] = []

    def task_key(task_id: str) -> bytes:
        value = cast(bytes, derive_receiver_task_key(receiver_key, task_id))
        task_keys.append(value)
        credentialed_task_ids.append(task_id)
        return value

    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=receiver_key,
            port=0,
            max_requests=1,
            max_connections=8,
            max_body_bytes=4 * 1024 * 1024,
            request_timeout_seconds=5.0,
            idle_timeout_seconds=180.0,
        )
    )
    receiver_result: dict[str, Any] = {}
    receiver_failure: list[BaseException] = []

    def serve_receiver() -> None:
        try:
            receiver_result.update(receiver.serve())
        except BaseException as exc:  # pragma: no cover - converted to a bounded gate failure
            receiver_failure.append(exc)

    receiver_thread = threading.Thread(
        target=serve_receiver,
        name="bluefire-gate06-loopback-receiver",
        daemon=True,
    )
    receiver_thread.start()
    service: BlueFireService | None = None
    runtime: Path | None = None
    runtime_cleanup_attempted = False

    def close_service() -> None:
        nonlocal service
        if service is not None:
            service.close()
            service = None

    try:
        runtime = Path(tempfile.mkdtemp(prefix=".g6-", dir=_runtime_temp_parent()))
        try:
            try:
                bootstrapped = bootstrap_runner(
                    environ={},
                    resource_root=root / "bluefire" / "native",
                    managed_root=runtime / "managed",
                )
            except RunnerBootstrapError as exc:
                raise ReplayJourneyError("the packaged native runner is unavailable") from exc
            _require(
                current_platform() == "windows"
                and bootstrapped.source == "packaged"
                and bootstrapped.manifest.platform == "windows",
                "GATE-06 requires the packaged Windows runner on this host",
            )
            scenario = _scenario(root, receiver.port)
            native_runner = SubprocessRustRunner(
                bootstrapped.binary_path,
                runtime / "transport",
                timeout_seconds=35.0,
                output_limit_bytes=4 * 1024 * 1024,
                receiver_task_key_factory=task_key,
            )
            runner = _CountingRunner(native_runner)
            service = BlueFireService(
                project_root=root,
                runs_dir=run_root,
                product_db_path=runtime / "product.sqlite3",
                runner_factory=lambda _profile: (runner, bootstrapped.sandbox_path),
                runner_lifecycle=ManagedRunnerLifecycle(runtime / "managed-lifecycle"),
            )
            source = service.run(_source_request(scenario))
            source_run_id = str(source["run_id"])
            checkpoint = checkpoint_for_step(source.get("replay_checkpoints", []), RESTART_STEP_ID)
            checkpoint = validate_checkpoint(
                checkpoint,
                expected_source_run_id=source_run_id,
                expected_step_id=RESTART_STEP_ID,
            )
            exact = service.replay(
                source_run_id,
                _restart_request("gate-06-exact-reviewer", exact=True),
            )
            parameter = service.replay(
                source_run_id,
                _restart_request(
                    "gate-06-parameter-reviewer",
                    parameter_overrides={PARAMETER_STEP_ID: {"bundle_format": "json"}},
                ),
            )
            combined = service.replay(
                source_run_id,
                _restart_request(
                    "gate-06-combined-reviewer",
                    swap_step_id=SWAP_STEP_ID,
                    swap_behavior_id=SWAP_BEHAVIOR_ID,
                    action_implementations={SWAP_STEP_ID: SWAP_ACTION_ID},
                    autonomy="auto",
                    ai_provider_id=PROVIDER_ID,
                    runner_profile_id=CANONICAL_PROFILE_ID,
                    defense_change=DEFENSE_CHANGE,
                ),
            )
            receiver_thread.join(timeout=25.0)
            _require(
                not receiver_thread.is_alive() and not receiver_failure, "GATE-06 receiver failed"
            )
            _require(
                receiver_result.get("requests_accepted") == 1 and len(credentialed_task_ids) == 1,
                "GATE-06 combined replay did not traverse authenticated loopback transport",
            )

            runs = [source, exact, parameter, combined]
            run_ids = [str(run["run_id"]) for run in runs]
            _require(len(run_ids) == len(set(run_ids)) == 4, "GATE-06 did not create four runs")
            _require(
                all(
                    run.get("status") == "completed"
                    and run.get("objective_reached") is True
                    and run.get("mode") == "execute"
                    and run.get("cleanup")
                    == {"attempted": True, "success": True, "outstanding_receipt_count": 0}
                    for run in runs
                ),
                "a GATE-06 Execute run did not complete cleanup",
            )
            _require(
                source.get("runner_profile_id") == FRONTIER_PROFILE_ID
                and source.get("autonomy") == "off"
                and _step(source, "try_internal_transport").get("status") == "blocked",
                "GATE-06 source did not use the reviewed blocked profile",
            )
            materializations = [_materialization(run, checkpoint) for run in runs[1:]]
            approval_ids = [_approval_id(run) for run in runs]
            _require(
                len(approval_ids) == len(set(approval_ids)) == 4,
                "GATE-06 replay approvals were not freshly regenerated",
            )
            exact_lineage = exact.get("replay")
            parameter_lineage = parameter.get("replay")
            combined_lineage = combined.get("replay")
            _require(
                isinstance(exact_lineage, Mapping)
                and exact_lineage.get("exact") is True
                and exact_lineage.get("from_step_id") == RESTART_STEP_ID
                and exact_lineage.get("source_run_id") == source_run_id,
                "GATE-06 exact node replay lineage is invalid",
            )
            _require(
                isinstance(parameter_lineage, Mapping)
                and parameter_lineage.get("parameter_overrides")
                == {PARAMETER_STEP_ID: {"bundle_format": "json"}}
                and _step(parameter, PARAMETER_STEP_ID)
                .get("artifacts", {})
                .get("bundle", {})
                .get("format")
                == "json",
                "GATE-06 typed parameter override was not executed",
            )
            _require(
                isinstance(combined_lineage, Mapping)
                and combined_lineage.get("swap_step_id") == SWAP_STEP_ID
                and combined_lineage.get("swap_behavior_id") == SWAP_BEHAVIOR_ID
                and combined_lineage.get("action_implementation_overrides")
                == {SWAP_STEP_ID: SWAP_ACTION_ID}
                and combined_lineage.get("action_implementations_changed") is True
                and combined_lineage.get("ai_changed") is True
                and combined_lineage.get("autonomy_from") == "off"
                and combined_lineage.get("autonomy_to") == "auto"
                and combined_lineage.get("profile_changed") is True
                and combined_lineage.get("profile_from") == FRONTIER_PROFILE_ID
                and combined_lineage.get("profile_to") == CANONICAL_PROFILE_ID
                and combined_lineage.get("defense_change") == DEFENSE_CHANGE
                and combined_lineage.get("defense_change_digest")
                == content_hash({"defense_change": DEFENSE_CHANGE})
                and _step(combined, SWAP_STEP_ID).get("behavior_id") == SWAP_BEHAVIOR_ID
                and _step(combined, SWAP_STEP_ID).get("action_id") == SWAP_ACTION_ID,
                "GATE-06 combined replay variants are incomplete",
            )
            corruption = _corruption_report(service, runner, run_root, source_run_id)
            comparison = service.compare({"run_ids": run_ids})
            _require(
                _comparison_dimensions(comparison), "GATE-06 comparison dimensions are incomplete"
            )
            _require(
                all(
                    service.store.validate_bundle(run_id).get("valid") is True for run_id in run_ids
                ),
                "a GATE-06 run bundle failed integrity validation",
            )

            checkpoint_authority = checkpoint["source_authority"]
            source_cleanup = checkpoint["source_cleanup"]
            _require(
                checkpoint_authority["profile"]["profile_id"] == FRONTIER_PROFILE_ID
                and checkpoint_authority["target_scope"]["scope_hash"]
                == content_hash({"scope_refs": sorted(TARGET_SCOPE["scope_refs"])})
                and checkpoint_authority["runner"]["platform"] == "windows"
                and source_cleanup["state"] == "completed"
                and source_cleanup["outstanding_receipt_count"] == 0
                and bool(checkpoint["material_files"]),
                "GATE-06 checkpoint authority is incomplete",
            )
            journey = {
                "schema_version": JOURNEY_SCHEMA,
                "passed": True,
                "run_ids": run_ids,
                "run_bundles": [{"run_id": run_id, "path": f"runs/{run_id}"} for run_id in run_ids],
                "roles": {
                    "source": run_ids[0],
                    "exact_restart": run_ids[1],
                    "parameter_restart": run_ids[2],
                    "combined_restart": run_ids[3],
                },
                "restart_step_id": RESTART_STEP_ID,
                "execution": {
                    "scenario_id": scenario["id"],
                    "runner_source": bootstrapped.source,
                    "runner_platform": bootstrapped.manifest.platform,
                    "source_profile_id": FRONTIER_PROFILE_ID,
                    "combined_profile_id": CANONICAL_PROFILE_ID,
                },
                "checkpoint": {
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "manifest_hash": checkpoint["manifest_hash"],
                    "artifact_state_hash": checkpoint["artifact_state_hash"],
                    "material_state_hash": checkpoint["material_state_hash"],
                    "material_file_count": len(checkpoint["material_files"]),
                    "prefix_step_ids": [row["step_id"] for row in checkpoint["executed_steps"]],
                },
                "approval_ids": approval_ids,
                "materialization_receipt_hashes": [
                    report["receipt_hash"] for report in materializations
                ],
                "checks": {
                    "checkpoint_integrity": True,
                    "materialized_state": True,
                    "scope_cleanup_binding": True,
                    "approval_regeneration": True,
                    "exact_replay": True,
                    "node_restart": True,
                    "parameter_override": True,
                    "action_substitution": True,
                    "autonomy_change": True,
                    "profile_change": True,
                    "defense_metadata": True,
                    "comparison_dimensions": True,
                },
            }
        finally:
            try:
                _close_runtime_and_remove(runtime, close_service)
            finally:
                runtime_cleanup_attempted = True

        _remove_runner_journal(run_root)
        for name, report in zip(REPORT_PATHS, (journey, corruption, comparison), strict=True):
            _write_json(destination / name, report)
        _assert_secrets_absent(destination, [receiver_key, *task_keys])
        return {
            "schema_version": HELPER_SCHEMA,
            "status": "passed",
            "reports": list(REPORT_PATHS),
            "run_count": 4,
        }
    finally:
        if runtime is not None and not runtime_cleanup_attempted:
            _close_runtime_and_remove(runtime, close_service)
        receiver.stop()
        if receiver_thread.is_alive():
            receiver_thread.join(timeout=5.0)
        receiver.close()
        task_keys.clear()
        receiver_key = b""


__all__ = [
    "COMPARISON_REPORT",
    "CORRUPTION_REPORT",
    "CORRUPTION_SCHEMA",
    "DEFENSE_CHANGE",
    "DIMENSIONS",
    "HELPER_SCHEMA",
    "JOURNEY_REPORT",
    "JOURNEY_SCHEMA",
    "PARAMETER_STEP_ID",
    "REPORT_PATHS",
    "RESTART_STEP_ID",
    "ReplayJourneyError",
    "SWAP_ACTION_ID",
    "SWAP_BEHAVIOR_ID",
    "SWAP_STEP_ID",
    "TARGET_SCOPE",
    "produce_replay_gate_evidence",
]
