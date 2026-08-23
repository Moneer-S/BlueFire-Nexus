"""Deny-by-default translation from logical plan steps to runner parameters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from .planner import PlanStep
from .runner_client import reject_forbidden_execution_keys


class RunnerAdapterError(ValueError):
    """Raised when typed logical artifacts cannot produce a safe runner call."""


@dataclass(frozen=True, slots=True)
class AdaptedAction:
    params: Mapping[str, Any]
    filesystem_scope: tuple[str, ...]
    network_destinations: tuple[Mapping[str, Any], ...] = ()
    observable_paths: tuple[str, ...] = ()


def _runner_path(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RunnerAdapterError(f"{context} must be a non-empty runner path")
    logical = PurePosixPath(value)
    if (
        logical.is_absolute()
        or "\\" in value
        or ":" in value
        or not logical.parts
        or any(part in {"", ".", ".."} for part in logical.parts)
        or logical.as_posix() != value
    ):
        raise RunnerAdapterError(f"{context} is not a normalized relative path")
    return logical.as_posix()


def _artifact_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RunnerAdapterError(f"{context} must be a typed artifact object")
    return value


def _artifact_path(value: Any, context: str) -> str:
    return _runner_path(_artifact_mapping(value, context).get("path"), f"{context}.path")


def _receipt_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RunnerAdapterError("cleanup receipt IDs must be 64 lowercase hexadecimal characters")
    return value


class RunnerActionAdapter:
    """Compile only the eight reviewed action IDs into strict runner params.

    Paths are constants or validated outputs of earlier runner actions.  No
    scenario parameter can become an executable, command, or filesystem path.
    """

    action_ids = frozenset(
        {
            "sandbox.fixture.create.v1",
            "sandbox.fixture.transform.v1",
            "sandbox.discovery.list.v1",
            "sandbox.discovery.metadata.v1",
            "sandbox.collection.stage.v1",
            "sandbox.network.loopback.v1",
            "sandbox.export.local.v1",
            "sandbox.cleanup.v1",
        }
    )

    def adapt(
        self,
        step: PlanStep,
        *,
        bound_inputs: Mapping[str, Any],
        receipt_ids: Sequence[str],
        loopback_host: str = "127.0.0.1",
    ) -> AdaptedAction:
        action_id = step.action_id
        if action_id not in self.action_ids:
            raise RunnerAdapterError(f"unreviewed or missing runner action: {action_id}")

        if action_id == "sandbox.fixture.create.v1":
            adapted = AdaptedAction(
                params={"path": "fixtures/input.txt", "content_template": "telemetry-seed"},
                filesystem_scope=("fixtures/input.txt",),
                observable_paths=("fixtures/input.txt",),
            )
        elif action_id == "sandbox.fixture.transform.v1":
            workspace = _artifact_mapping(bound_inputs.get("workspace"), "workspace")
            source = _runner_path(workspace.get("fixture_path"), "workspace.fixture_path")
            adapted = AdaptedAction(
                params={
                    "input": source,
                    "output": "fixtures/transformed.txt",
                    "transform": "uppercase-ascii",
                },
                filesystem_scope=(source, "fixtures/transformed.txt"),
                observable_paths=("fixtures/transformed.txt",),
            )
        elif action_id == "sandbox.discovery.list.v1":
            fixture = _artifact_path(bound_inputs.get("fixture"), "fixture")
            maximum = step.parameters.get("record_limit", 25)
            adapted = AdaptedAction(
                params={"path": str(PurePosixPath(fixture).parent), "max_entries": maximum},
                filesystem_scope=(str(PurePosixPath(fixture).parent),),
            )
        elif action_id == "sandbox.discovery.metadata.v1":
            fixture = _artifact_path(bound_inputs.get("fixture"), "fixture")
            adapted = AdaptedAction(
                params={"path": fixture},
                filesystem_scope=(fixture,),
            )
        elif action_id == "sandbox.collection.stage.v1":
            records = bound_inputs.get("records")
            if not isinstance(records, list) or not records:
                raise RunnerAdapterError("records must contain typed discovery artifacts")
            inputs = [
                _artifact_path(item, f"records[{index}]") for index, item in enumerate(records)
            ]
            adapted = AdaptedAction(
                params={"inputs": inputs, "destination_directory": "staged"},
                filesystem_scope=tuple(inputs) + ("staged",),
                observable_paths=(f"staged/000-{PurePosixPath(inputs[0]).name}",),
            )
        elif action_id == "sandbox.network.loopback.v1":
            if loopback_host not in {"127.0.0.1", "::1"}:
                raise RunnerAdapterError("network adapter accepts literal loopback hosts only")
            bundle = _artifact_path(bound_inputs.get("bundle"), "bundle")
            port = step.parameters.get("port", 4317)
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise RunnerAdapterError("loopback port must be an integer between 1 and 65535")
            destination = {"host": loopback_host, "port": port}
            adapted = AdaptedAction(
                params={"artifact": bundle, "destination": destination},
                filesystem_scope=(bundle,),
                network_destinations=(destination,),
            )
        elif action_id == "sandbox.export.local.v1":
            bundle = _artifact_path(bound_inputs.get("bundle"), "bundle")
            adapted = AdaptedAction(
                params={"source": bundle, "destination": "exports/bundle.bin"},
                filesystem_scope=(bundle, "exports/bundle.bin"),
                observable_paths=("exports/bundle.bin",),
            )
        else:
            clean_receipts = tuple(_receipt_id(item) for item in receipt_ids)
            if not clean_receipts:
                raise RunnerAdapterError("cleanup requires runner-issued receipt IDs")
            cleanup_order = list(dict.fromkeys(clean_receipts))
            cleanup_order.reverse()
            adapted = AdaptedAction(
                params={"receipt_ids": cleanup_order},
                filesystem_scope=(),
            )

        reject_forbidden_execution_keys(adapted.params)
        return adapted

    def logical_outputs(
        self,
        step: PlanStep,
        *,
        bound_inputs: Mapping[str, Any],
        runner_output: Any,
        receipt_ids: Sequence[str],
    ) -> dict[str, Any]:
        """Map a successful/partial runner result back to typed graph outputs."""

        action_id = step.action_id
        if action_id not in self.action_ids:
            raise RunnerAdapterError(f"unreviewed or missing runner action: {action_id}")
        if not isinstance(runner_output, Mapping):
            return {}

        if action_id == "sandbox.fixture.create.v1":
            path = _runner_path(runner_output.get("artifact"), "runner output artifact")
            return {
                "workspace": {
                    "type": "artifact.sandbox.workspace.v1",
                    "root": str(PurePosixPath(path).parent),
                    "fixture_path": path,
                    "receipt_ids": list(receipt_ids),
                }
            }
        if action_id == "sandbox.fixture.transform.v1":
            path = _runner_path(runner_output.get("artifact"), "runner output artifact")
            return {
                "fixture": {
                    "type": "artifact.sandbox.fixture.v1",
                    "path": path,
                    "sha256": runner_output.get("sha256"),
                    "receipt_ids": list(receipt_ids),
                }
            }
        if action_id in {"sandbox.discovery.list.v1", "sandbox.discovery.metadata.v1"}:
            source = _artifact_path(bound_inputs.get("fixture"), "fixture")
            return {
                "records": [
                    {
                        "type": "artifact.sandbox.discovery.records.v1",
                        "path": source,
                        "metadata": dict(runner_output),
                    }
                ]
            }
        if action_id == "sandbox.collection.stage.v1":
            staged = runner_output.get("staged")
            if not isinstance(staged, list) or not staged:
                return {}
            first = _artifact_mapping(staged[0], "runner staged output")
            path = _runner_path(first.get("artifact"), "runner staged output.artifact")
            return {
                "bundle": {
                    "type": "artifact.sandbox.bundle.v1",
                    "path": path,
                    "sha256": first.get("sha256"),
                    "receipt_ids": list(receipt_ids),
                }
            }
        if action_id == "sandbox.network.loopback.v1":
            return {
                "receipt": {
                    "type": "artifact.sandbox.network.receipt.v1",
                    "transport": "loopback",
                    "details": dict(runner_output),
                }
            }
        if action_id == "sandbox.export.local.v1":
            path = _runner_path(runner_output.get("artifact"), "runner export output")
            return {
                "receipt": {
                    "type": "artifact.sandbox.export.receipt.v1",
                    "path": path,
                    "sha256": runner_output.get("sha256"),
                    "receipt_ids": list(receipt_ids),
                }
            }
        return {
            "receipt": {
                "type": "artifact.sandbox.cleanup.receipt.v1",
                "details": dict(runner_output),
            }
        }


__all__ = ["AdaptedAction", "RunnerActionAdapter", "RunnerAdapterError"]
