"""Pure deterministic simulation adapters with no runner or host side effects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import StepOutcome
from .planner import PlanStep
from .util import content_hash


class SimulationError(ValueError):
    pass


def _bounded_integer(value: Any, context: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SimulationError(f"{context} must be an integer between {minimum} and {maximum}")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise SimulationError(f"{context} must be a boolean")
    return value


def _choice(value: Any, context: str, choices: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise SimulationError(f"{context} is not a reviewed choice")
    return value


@dataclass(frozen=True, slots=True)
class SimulationResult:
    outcome: StepOutcome
    artifacts: Mapping[str, Any]
    telemetry: tuple[str, ...]
    details: Mapping[str, Any]
    limitations: tuple[str, ...]


class SimulationRegistry:
    """Dispatch only static, reviewed simulation identifiers."""

    simulation_ids = frozenset(
        {
            "simulation.sandbox.fixture.create.v1",
            "simulation.sandbox.fixture.transform.v1",
            "simulation.sandbox.discovery.list.v1",
            "simulation.sandbox.discovery.metadata.v1",
            "simulation.endpoint.discovery.system.v1",
            "simulation.endpoint.discovery.processes.v1",
            "simulation.sandbox.discovery.recursive.v1",
            "simulation.sandbox.archive.tar.v1",
            "simulation.sandbox.collection.stage.v1",
            "simulation.sandbox.network.loopback.v1",
            "simulation.sandbox.export.local.v1",
            "simulation.sandbox.restricted.persistence-marker.v1",
            "simulation.sandbox.cleanup.v1",
        }
    )

    def execute(
        self,
        step: PlanStep,
        *,
        bound_inputs: Mapping[str, Any],
    ) -> SimulationResult:
        simulation_id = step.simulation_id
        if simulation_id not in self.simulation_ids:
            raise SimulationError(f"unreviewed or missing simulation adapter: {simulation_id}")

        base_limitations = (
            "Synthetic projection only; no Rust runner action or host effect occurred.",
        )
        artifacts: dict[str, Any]
        telemetry: tuple[str, ...]
        if simulation_id == "simulation.sandbox.fixture.create.v1":
            count = _bounded_integer(step.parameters.get("record_count", 6), "record_count", 1, 100)
            body = [
                {
                    "record_id": f"synthetic-{index:03}",
                    "synthetic": True,
                    "template": "telemetry-seed",
                    "value": f"telemetry-value-{index:03}",
                }
                for index in range(1, count + 1)
            ]
            artifacts = {
                "workspace": {
                    "type": "artifact.sandbox.workspace.v1",
                    "root": "synthetic/fixtures",
                    "fixture_path": "synthetic/fixtures/input.jsonl",
                    "record_count": count,
                    "format": "jsonl",
                    "content_hash": content_hash(body),
                }
            }
            telemetry = ("sandbox.fixture.created",)
        elif simulation_id == "simulation.sandbox.fixture.transform.v1":
            workspace = _mapping(bound_inputs.get("workspace"), "workspace")
            record_count = _bounded_integer(
                workspace.get("record_count"), "workspace.record_count", 1, 100
            )
            source_hash = workspace.get("content_hash")
            if not isinstance(source_hash, str) or not source_hash:
                raise SimulationError("workspace.content_hash must be a non-empty digest")
            redact_values = _boolean(step.parameters.get("redact_values", True), "redact_values")
            transformed_hash = content_hash(
                {
                    "source_content_hash": source_hash,
                    "record_count": record_count,
                    "redact_values": redact_values,
                    "transform": "canonical-reviewed-jsonl-v1",
                }
            )
            artifacts = {
                "fixture": {
                    "type": "artifact.sandbox.fixture.v1",
                    "path": "synthetic/fixtures/transformed.jsonl",
                    "source": workspace.get("fixture_path"),
                    "record_count": record_count,
                    "redact_values": redact_values,
                    "content_hash": transformed_hash,
                }
            }
            telemetry = ("sandbox.fixture.transformed",)
        elif simulation_id in {
            "simulation.sandbox.discovery.list.v1",
            "simulation.sandbox.discovery.metadata.v1",
        }:
            if step.parameters:
                raise SimulationError("exact fixture discovery accepts no logical parameters")
            fixture = _mapping(bound_inputs.get("fixture"), "fixture")
            fixture_path = fixture.get("path")
            if not isinstance(fixture_path, str) or not fixture_path:
                raise SimulationError("fixture.path must be a non-empty synthetic path")
            fixture_hash = fixture.get("content_hash")
            if not isinstance(fixture_hash, str) or not fixture_hash:
                raise SimulationError("fixture.content_hash must be a non-empty digest")
            redact_values = _boolean(fixture.get("redact_values"), "fixture.redact_values")
            method = "list" if simulation_id.endswith("list.v1") else "metadata"
            artifacts = {
                "records": [
                    {
                        "type": "artifact.sandbox.discovery.records.v1",
                        "path": fixture_path,
                        "kind": "file",
                        "method": method,
                        "synthetic": True,
                        "record_count": _bounded_integer(
                            fixture.get("record_count"), "fixture.record_count", 1, 100
                        ),
                        "content_hash": fixture_hash,
                        "redact_values": redact_values,
                    }
                ]
            }
            telemetry = (
                (
                    "sandbox.discovery.listed"
                    if method == "list"
                    else "sandbox.discovery.metadata_inspected"
                ),
            )
        elif simulation_id == "simulation.endpoint.discovery.system.v1":
            artifacts = {
                "system": {
                    "type": "artifact.endpoint.system-profile.v1",
                    "operating_system": "synthetic",
                    "architecture": "synthetic",
                    "logical_processors": 1,
                }
            }
            telemetry = ("endpoint.discovery.system_observed",)
        elif simulation_id == "simulation.endpoint.discovery.processes.v1":
            maximum = _bounded_integer(
                step.parameters.get("record_limit", 25), "record_limit", 1, 100
            )
            entries = [
                {"pid": "100", "parent_pid": "1", "name": "bluefire-synthetic-a"},
                {"pid": "101", "parent_pid": "100", "name": "bluefire-synthetic-b"},
            ][:maximum]
            artifacts = {
                "processes": {
                    "type": "artifact.endpoint.process-records.v1",
                    "entries": entries,
                    "synthetic": True,
                }
            }
            telemetry = ("endpoint.discovery.processes_observed",)
        elif simulation_id == "simulation.sandbox.discovery.recursive.v1":
            workspace = _mapping(bound_inputs.get("workspace"), "workspace")
            fixture_path = workspace.get("fixture_path", "synthetic/fixtures/input.jsonl")
            _bounded_integer(step.parameters.get("record_limit", 25), "record_limit", 1, 100)
            _bounded_integer(step.parameters.get("max_depth", 3), "max_depth", 1, 16)
            artifacts = {
                "records": [
                    {
                        "type": "artifact.sandbox.filesystem.record.v1",
                        "path": fixture_path,
                        "kind": "file",
                        "depth": 1,
                        "synthetic": True,
                    }
                ]
            }
            telemetry = ("sandbox.discovery.recursive_completed",)
        elif simulation_id == "simulation.sandbox.archive.tar.v1":
            records = bound_inputs.get("records")
            if not isinstance(records, list) or not records:
                raise SimulationError("archive simulation requires filesystem records")
            body = {"format": "ustar", "records": records}
            artifacts = {
                "bundle": {
                    "type": "artifact.sandbox.archive.v1",
                    "path": "synthetic/staged/discovery.tar",
                    "record_count": len(records),
                    "content_hash": content_hash(body),
                }
            }
            telemetry = ("sandbox.archive.created",)
        elif simulation_id == "simulation.sandbox.collection.stage.v1":
            records = bound_inputs.get("records")
            if not isinstance(records, list) or len(records) != 1:
                raise SimulationError("collection simulation requires one discovery record")
            source = _mapping(records[0], "records[0]")
            if source.get("kind") != "file":
                raise SimulationError("collection simulation requires an exact file record")
            record_count = _bounded_integer(
                source.get("record_count"), "records[0].record_count", 1, 100
            )
            source_hash = source.get("content_hash")
            if not isinstance(source_hash, str) or not source_hash:
                raise SimulationError("records[0].content_hash must be a non-empty digest")
            bundle_format = _choice(
                step.parameters.get("bundle_format", "jsonl"),
                "bundle_format",
                frozenset({"jsonl", "json"}),
            )
            body = {
                "source_content_hash": source_hash,
                "record_count": record_count,
                "format": bundle_format,
            }
            artifacts = {
                "bundle": {
                    "type": "artifact.sandbox.bundle.v1",
                    "path": f"synthetic/staged/bundle.{bundle_format}",
                    "record_count": record_count,
                    "format": bundle_format,
                    "content_hash": content_hash(body),
                }
            }
            telemetry = ("sandbox.collection.staged",)
        elif simulation_id == "simulation.sandbox.network.loopback.v1":
            bundle = _mapping(bound_inputs.get("bundle"), "bundle")
            bundle_hash = bundle.get("content_hash")
            if not isinstance(bundle_hash, str) or not bundle_hash:
                raise SimulationError("bundle.content_hash must be a non-empty digest")
            port = _bounded_integer(step.parameters.get("port", 4317), "port", 1024, 65535)
            artifacts = {
                "receipt": {
                    "type": "artifact.sandbox.network.receipt.v1",
                    "would_send": bundle_hash,
                    "destination": f"127.0.0.1:{port}",
                }
            }
            telemetry = ("sandbox.network.loopback_attempted",)
        elif simulation_id == "simulation.sandbox.export.local.v1":
            bundle = _mapping(bound_inputs.get("bundle"), "bundle")
            bundle_hash = bundle.get("content_hash")
            if not isinstance(bundle_hash, str) or not bundle_hash:
                raise SimulationError("bundle.content_hash must be a non-empty digest")
            retention_label = _choice(
                step.parameters.get("retention_label", "ephemeral"),
                "retention_label",
                frozenset({"ephemeral", "review"}),
            )
            artifacts = {
                "receipt": {
                    "type": "artifact.sandbox.export.receipt.v1",
                    "would_export": bundle_hash,
                    "path": f"synthetic/exports/{retention_label}/bundle.bin",
                    "retention_label": retention_label,
                }
            }
            telemetry = ("sandbox.export.local_completed",)
        elif simulation_id == "simulation.sandbox.restricted.persistence-marker.v1":
            marker_path = "synthetic/restricted/persistence-marker.json"
            label = _choice(
                step.parameters.get("label", "persistence_detection_canary"),
                "label",
                frozenset({"persistence_detection_canary", "control_validation"}),
            )
            artifacts = {
                "workspace": {
                    "type": "artifact.sandbox.workspace.v1",
                    "root": "synthetic/restricted",
                    "marker_path": marker_path,
                },
                "marker": {
                    "type": "artifact.sandbox.restricted-marker.v1",
                    "path": marker_path,
                    "label": label,
                    "synthetic": True,
                },
            }
            telemetry = ("sandbox.restricted.persistence_marker_created",)
        elif simulation_id == "simulation.sandbox.cleanup.v1":
            if _boolean(step.parameters.get("verify_removal", True), "verify_removal") is not True:
                raise SimulationError("cleanup simulation requires verify_removal=true")
            _mapping(bound_inputs.get("workspace"), "workspace")
            artifacts = {
                "receipt": {
                    "type": "artifact.sandbox.cleanup.receipt.v1",
                    "would_remove_runner_owned_artifacts": True,
                    "verification_requested": True,
                }
            }
            telemetry = ("sandbox.cleanup.completed",)
        else:  # pragma: no cover - guarded by the reviewed ID set above
            raise SimulationError(f"simulation adapter is not implemented: {simulation_id}")

        return SimulationResult(
            outcome=StepOutcome.SUCCESS,
            artifacts=artifacts,
            telemetry=telemetry,
            details={
                "simulation_id": simulation_id,
                "artifact_digest": content_hash(artifacts),
                "side_effects_started": False,
            },
            limitations=base_limitations,
        )


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SimulationError(f"{context} input is missing or malformed")
    return value


__all__ = ["SimulationError", "SimulationRegistry", "SimulationResult"]
