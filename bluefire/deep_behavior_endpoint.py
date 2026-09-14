"""Real packaged-runner journey for the official endpoint/identity pack."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, cast

from .contracts import load_scenario
from .cross_platform_journey import (
    _assert_secrets_absent,
    _private_trust_material,
    _receiver_report,
    _ReceiverProcess,
    _start_receiver,
    _stop_receiver_process,
)
from .receiver_auth import derive_receiver_task_key
from .run_store import RunStore
from .runner_bootstrap import load_runner_manifest, validate_runner_inventory
from .runner_client import SubprocessRustRunner
from .runner_trust import create_local_enrollment
from .service import BlueFireService
from .util import file_hash

ENDPOINT_SCHEMA = "bluefire.deep-behavior-endpoint-execute.v1"
ENDPOINT_PACK_ID = "bluefire.endpoint-identity.v1"
ENDPOINT_PROFILE_ID = "sandbox-endpoint-deep-lab.v1"
ENDPOINT_SCENARIO = "endpoint_deep_behavior_lab.yaml"

_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class EndpointPackJourneyError(ValueError):
    """The official endpoint pack did not establish its dynamic claim."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EndpointPackJourneyError(message)


def _safe_runtime(runtime: Path) -> Path:
    details = runtime.lstat()
    _require(
        stat.S_ISDIR(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and not int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT,
        "the endpoint pack runtime is unsafe",
    )
    return runtime.resolve(strict=True)


def _scenario_with_receiver(repository: Path, port: int) -> Mapping[str, Any]:
    scenario = load_scenario(repository / "scenarios" / ENDPOINT_SCENARIO).to_dict()
    steps = scenario.get("steps")
    _require(isinstance(steps, list), "the endpoint pack scenario is invalid")
    steps = cast(list[Any], steps)
    matched = False
    for step in steps:
        if isinstance(step, dict) and step.get("id") == "authorized_peer_handoff":
            parameters = step.get("parameters")
            _require(isinstance(parameters, dict), "the peer handoff parameters are absent")
            parameters = cast(dict[str, Any], parameters)
            parameters["port"] = port
            matched = True
    _require(matched, "the endpoint pack peer handoff is absent")
    return scenario


def _step_map(result: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    steps = result.get("steps")
    _require(isinstance(steps, list), "the endpoint pack run has no steps")
    steps = cast(list[Any], steps)
    mapped: dict[str, Mapping[str, Any]] = {}
    for raw in steps:
        _require(isinstance(raw, Mapping), "an endpoint pack step is invalid")
        raw = cast(Mapping[str, Any], raw)
        step_id = raw.get("step_id")
        _require(isinstance(step_id, str) and step_id not in mapped, "step identity is invalid")
        mapped[cast(str, step_id)] = raw
    return mapped


def _status(step: Mapping[str, Any]) -> bool:
    return step.get("status") in {"success", "partial"}


def _phase_checks(
    result: Mapping[str, Any],
    receiver: Mapping[str, Any],
) -> Mapping[str, bool]:
    steps = _step_map(result)
    required = {
        "run_native_canary",
        "discover_system",
        "discover_processes",
        "create_fixture",
        "transform_fixture",
        "inspect_fixture_metadata",
        "stage_records",
        "create_persistence_canary",
        "create_observability_variant",
        "authorized_peer_handoff",
        "cleanup_workspace",
    }
    _require(set(steps) == required, "the endpoint pack phase inventory is not exact")
    variant = steps["create_observability_variant"].get("artifacts")
    variant_record = variant.get("variant") if isinstance(variant, Mapping) else None
    transfer = receiver.get("transfer")
    return {
        "execution": _status(steps["run_native_canary"]),
        "discovery": _status(steps["discover_system"]) and _status(steps["discover_processes"]),
        "collection_staging": all(
            _status(steps[name])
            for name in (
                "create_fixture",
                "transform_fixture",
                "inspect_fixture_metadata",
                "stage_records",
            )
        ),
        "persistence": _status(steps["create_persistence_canary"]),
        "authorized_credentials": isinstance(transfer, Mapping)
        and transfer.get("authenticated") is True,
        "disposable_lateral": isinstance(transfer, Mapping)
        and transfer.get("source_process_id") != transfer.get("destination_process_id"),
        "telemetry_shaping": _status(steps["create_observability_variant"])
        and isinstance(variant_record, Mapping)
        and variant_record.get("equivalence_verified") is True,
        "cleanup": steps["cleanup_workspace"].get("status") == "success",
    }


def _scan_stats(root: Path) -> Mapping[str, int | bool]:
    files = 0
    scanned = 0
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            files += 1
            scanned += path.stat().st_size
            _require(scanned <= 128 * 1024 * 1024, "endpoint evidence exceeded scan bounds")
    return {"passed": True, "files_scanned": files, "bytes_scanned": scanned}


def run_endpoint_pack_journey(
    repository: Path,
    evidence_dir: Path,
    runtime: Path,
) -> Mapping[str, Any]:
    """Execute all reviewed endpoint phases with a separate disposable peer."""

    _require(os.name == "nt", "the endpoint pack dynamic proof requires Windows")
    root = repository.resolve(strict=True)
    evidence = evidence_dir.resolve(strict=True)
    owned_runtime = _safe_runtime(runtime)
    state_parent = owned_runtime / "endpoint-state"
    state_parent.mkdir()
    enrollment = create_local_enrollment(
        state_parent / "BlueFire Nexus" / "enrollment",
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=(ENDPOINT_PROFILE_ID,),
    )
    receiver: _ReceiverProcess | None = None
    service: BlueFireService | None = None
    receiver_keys: list[bytes] = []
    trust_material: tuple[bytes, ...] = ()
    try:
        receiver, ready = _start_receiver(root, state_parent)
        enrollment_key = enrollment.hmac_key()

        def receiver_task_key(task_id: str) -> bytes:
            key = derive_receiver_task_key(enrollment_key, task_id)
            receiver_keys.append(key)
            return key

        native = root / "bluefire" / "native"
        manifest = load_runner_manifest(resource_root=native)
        binary = native / manifest.filename
        _require(
            binary.is_file()
            and not binary.is_symlink()
            and binary.stat().st_size == manifest.size
            and file_hash(binary) == "sha256:" + manifest.sha256,
            "the endpoint pack runner artifact does not match its manifest",
        )
        runner = SubprocessRustRunner(
            binary,
            owned_runtime / "endpoint-transport",
            timeout_seconds=35.0,
            output_limit_bytes=4 * 1024 * 1024,
            receiver_task_key_factory=receiver_task_key,
        )
        inventory = runner.inventory()
        validate_runner_inventory(inventory, manifest)
        sandbox = owned_runtime / "endpoint-sandbox"
        sandbox.mkdir()
        service = BlueFireService(
            project_root=root,
            runs_dir=evidence / "runs",
            product_db_path=owned_runtime / "endpoint-product.sqlite3",
            runner_factory=lambda _profile: (runner, sandbox),
        )
        result = service.run(
            {
                "scenario": _scenario_with_receiver(root, int(ready["port"])),
                "mode": "execute",
                "runner_profile_id": ENDPOINT_PROFILE_ID,
                "target_scope": {"scope_refs": ["sandbox.workspace", "network.loopback"]},
                "autonomy": "off",
                "approval": {
                    "confirmed": True,
                    "approved_by": "gate-03-endpoint-runtime-reviewer",
                },
            }
        )
        run_id = result.get("run_id")
        cleanup = result.get("cleanup")
        _require(
            isinstance(run_id, str)
            and _RUN_ID.fullmatch(run_id) is not None
            and result.get("status") == "completed"
            and result.get("objective_reached") is True
            and isinstance(cleanup, Mapping)
            and cleanup.get("success") is True
            and cleanup.get("outstanding_receipt_count") == 0,
            "the endpoint pack run did not reconcile",
        )
        run_id = cast(str, run_id)
        receiver_record = _receiver_report(result, receiver, ready)
        receiver = None
        phases = _phase_checks(result, receiver_record)
        _require(all(phases.values()), "an endpoint pack phase did not execute")
        store = RunStore(evidence / "runs")
        _require(store.validate_bundle(run_id).get("valid") is True, "endpoint bundle failed")
        _require(not [path for path in sandbox.rglob("*") if path.is_file()], "cleanup failed")
        transfer = receiver_record["transfer"]
        trust_material = _private_trust_material(
            enrollment,
            (str(transfer["runner_task_id"]),),
        )
        _require(bool(receiver_keys), "the endpoint peer credential was not derived")
        _assert_secrets_absent(evidence, (*trust_material, *receiver_keys))
        return {
            "schema_version": ENDPOINT_SCHEMA,
            "passed": True,
            "proof_kind": "dynamic",
            "pack_id": ENDPOINT_PACK_ID,
            "platform": "windows",
            "environment_type": "disposable",
            "runner": {
                "runner_id": inventory["runner_id"],
                "runner_version": inventory["runner_version"],
                "platform": inventory["platform"],
                "binary_sha256": "sha256:" + manifest.sha256,
                "binary_size": manifest.size,
            },
            "execution": {
                "run_id": run_id,
                "status": "completed",
                "objective_reached": True,
                "step_count": len(result["steps"]),
            },
            "phases": phases,
            "receiver": receiver_record["receiver"],
            "cleanup": {
                "workspace_files_remaining": 0,
                "receiver_process_exited": True,
                "outstanding_receipt_count": 0,
            },
            "credential_scan": _scan_stats(evidence / "runs" / run_id),
            "run_bundle": {"run_id": run_id, "path": f"runs/{run_id}"},
        }
    finally:
        if receiver is not None:
            _stop_receiver_process(receiver)
        if service is not None:
            service.close()
        for index in range(len(receiver_keys)):
            receiver_keys[index] = b""
        trust_material = ()


__all__ = [
    "ENDPOINT_PACK_ID",
    "ENDPOINT_PROFILE_ID",
    "ENDPOINT_SCHEMA",
    "EndpointPackJourneyError",
    "run_endpoint_pack_journey",
]
