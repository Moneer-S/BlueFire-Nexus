"""Pure deterministic simulation adapters with no runner or host side effects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import StepOutcome
from .planner import PlanStep
from .util import content_hash


class SimulationError(ValueError):
    pass


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
            count = int(step.parameters.get("record_count", 6))
            artifacts = {
                "workspace": {
                    "type": "artifact.sandbox.workspace.v1",
                    "root": "synthetic/fixtures",
                    "fixture_path": "synthetic/fixtures/input.txt",
                    "record_count": count,
                }
            }
            telemetry = ("sandbox.fixture.created",)
        elif simulation_id == "simulation.sandbox.fixture.transform.v1":
            workspace = _mapping(bound_inputs.get("workspace"), "workspace")
            artifacts = {
                "fixture": {
                    "type": "artifact.sandbox.fixture.v1",
                    "path": "synthetic/fixtures/transformed.txt",
                    "source": workspace.get("fixture_path"),
                    "redacted": bool(step.parameters.get("redact_values", True)),
                }
            }
            telemetry = ("sandbox.fixture.transformed",)
        elif simulation_id in {
            "simulation.sandbox.discovery.list.v1",
            "simulation.sandbox.discovery.metadata.v1",
        }:
            fixture = _mapping(bound_inputs.get("fixture"), "fixture")
            method = "list" if simulation_id.endswith("list.v1") else "metadata"
            artifacts = {
                "records": [
                    {
                        "type": "artifact.sandbox.discovery.records.v1",
                        "path": fixture.get("path"),
                        "method": method,
                        "synthetic": True,
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
            maximum = max(1, min(int(step.parameters.get("record_limit", 25)), 100))
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
            fixture_path = workspace.get("fixture_path", "synthetic/fixtures/input.txt")
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
            if not isinstance(records, list) or not records:
                raise SimulationError("collection simulation requires discovery records")
            body = {"records": records, "format": step.parameters.get("bundle_format", "jsonl")}
            artifacts = {
                "bundle": {
                    "type": "artifact.sandbox.bundle.v1",
                    "path": "synthetic/staged/000-transformed.txt",
                    "record_count": len(records),
                    "content_hash": content_hash(body),
                }
            }
            telemetry = ("sandbox.collection.staged",)
        elif simulation_id == "simulation.sandbox.network.loopback.v1":
            bundle = _mapping(bound_inputs.get("bundle"), "bundle")
            artifacts = {
                "receipt": {
                    "type": "artifact.sandbox.network.receipt.v1",
                    "would_send": bundle.get("content_hash"),
                    "destination": f"127.0.0.1:{step.parameters.get('port', 4317)}",
                }
            }
            telemetry = ("sandbox.network.loopback_attempted",)
        elif simulation_id == "simulation.sandbox.export.local.v1":
            bundle = _mapping(bound_inputs.get("bundle"), "bundle")
            artifacts = {
                "receipt": {
                    "type": "artifact.sandbox.export.receipt.v1",
                    "would_export": bundle.get("content_hash"),
                    "retention_label": step.parameters.get("retention_label", "ephemeral"),
                }
            }
            telemetry = ("sandbox.export.local_completed",)
        elif simulation_id == "simulation.sandbox.restricted.persistence-marker.v1":
            marker_path = "synthetic/restricted/persistence-marker.json"
            label = step.parameters.get("label", "persistence_detection_canary")
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
            _mapping(bound_inputs.get("workspace"), "workspace")
            artifacts = {
                "receipt": {
                    "type": "artifact.sandbox.cleanup.receipt.v1",
                    "would_remove_runner_owned_artifacts": True,
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
