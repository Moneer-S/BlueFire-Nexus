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


def _bounded_integer(value: Any, context: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RunnerAdapterError(f"{context} must be an integer between {minimum} and {maximum}")
    return int(value)


def _reviewed_boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise RunnerAdapterError(f"{context} must be a boolean")
    return value


def _reviewed_choice(value: Any, context: str, choices: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        expected = ", ".join(sorted(choices))
        raise RunnerAdapterError(f"{context} must be one of: {expected}")
    return value


def _runner_sha256(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RunnerAdapterError(f"{context} must be 64 lowercase hexadecimal characters")
    return value


def _exact_fixture_discovery_record(
    *,
    bound_inputs: Mapping[str, Any],
    runner_output: Mapping[str, Any],
    context: str,
    include_readonly: bool,
) -> dict[str, Any]:
    fixture = _artifact_mapping(bound_inputs.get("fixture"), "fixture")
    source = _artifact_path(fixture, "fixture")
    if set(runner_output) != {
        "path",
        "entries",
        "returned_entries",
        "target_cardinality",
    }:
        raise RunnerAdapterError(f"{context} widened or malformed the exact fixture result")
    entries = runner_output.get("entries")
    if not isinstance(entries, list) or len(entries) != 1:
        raise RunnerAdapterError(f"{context} must return exactly one bound fixture entry")
    entry = _artifact_mapping(entries[0], f"{context}.entries[0]")
    expected_entry_keys = {"path", "name", "kind", "size"}
    if include_readonly:
        expected_entry_keys.add("readonly")
    path = _runner_path(entry.get("path"), f"{context}.entries[0].path")
    expected_name = PurePosixPath(source).name
    size = entry.get("size")
    returned_entries = _bounded_integer(
        runner_output.get("returned_entries"), f"{context}.returned_entries", 1, 1
    )
    if (
        runner_output.get("path") != source
        or returned_entries != 1
        or runner_output.get("target_cardinality") != "one"
        or path != source
        or entry.get("name") != expected_name
        or entry.get("kind") != "file"
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or set(entry) != expected_entry_keys
        or (include_readonly and not isinstance(entry.get("readonly"), bool))
    ):
        raise RunnerAdapterError(f"{context} widened or malformed the exact fixture result")
    record_count = _bounded_integer(fixture.get("record_count"), "fixture.record_count", 1, 100)
    return {
        "type": "artifact.sandbox.discovery.records.v1",
        "path": source,
        "kind": "file",
        "record_count": record_count,
        "sha256": fixture.get("sha256"),
        "redact_values": fixture.get("redact_values"),
        "metadata": dict(entry),
    }


class RunnerActionAdapter:
    """Compile only the thirteen reviewed action IDs into strict runner params.

    Paths are constants or validated outputs of earlier runner actions.  No
    scenario parameter can become an executable, command, or filesystem path.
    """

    action_ids = frozenset(
        {
            "sandbox.fixture.create.v1",
            "sandbox.fixture.transform.v1",
            "sandbox.discovery.list.v1",
            "sandbox.discovery.metadata.v1",
            "endpoint.discovery.system.v1",
            "endpoint.discovery.processes.v1",
            "sandbox.discovery.recursive.v1",
            "sandbox.archive.tar.v1",
            "sandbox.collection.stage.v1",
            "sandbox.network.loopback.v1",
            "sandbox.export.local.v1",
            "sandbox.restricted.persistence-marker.v1",
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
            record_count = _bounded_integer(
                step.parameters.get("record_count", 6), "record_count", 1, 100
            )
            adapted = AdaptedAction(
                params={
                    "path": "fixtures/input.jsonl",
                    "content_template": "telemetry-seed",
                    "record_count": record_count,
                },
                filesystem_scope=("fixtures/input.jsonl",),
                observable_paths=("fixtures/input.jsonl",),
            )
        elif action_id == "sandbox.fixture.transform.v1":
            workspace = _artifact_mapping(bound_inputs.get("workspace"), "workspace")
            source = _runner_path(workspace.get("fixture_path"), "workspace.fixture_path")
            redact_values = _reviewed_boolean(
                step.parameters.get("redact_values", True), "redact_values"
            )
            adapted = AdaptedAction(
                params={
                    "input": source,
                    "output": "fixtures/transformed.jsonl",
                    "redact_values": redact_values,
                },
                filesystem_scope=(source, "fixtures/transformed.jsonl"),
                observable_paths=("fixtures/transformed.jsonl",),
            )
        elif action_id == "sandbox.discovery.list.v1":
            if step.parameters:
                raise RunnerAdapterError("exact fixture discovery accepts no logical parameters")
            fixture = _artifact_path(bound_inputs.get("fixture"), "fixture")
            adapted = AdaptedAction(
                params={"path": fixture},
                filesystem_scope=(fixture,),
            )
        elif action_id == "sandbox.discovery.metadata.v1":
            if step.parameters:
                raise RunnerAdapterError("exact fixture discovery accepts no logical parameters")
            fixture = _artifact_path(bound_inputs.get("fixture"), "fixture")
            adapted = AdaptedAction(
                params={"path": fixture},
                filesystem_scope=(fixture,),
            )
        elif action_id == "endpoint.discovery.system.v1":
            adapted = AdaptedAction(params={}, filesystem_scope=())
        elif action_id == "endpoint.discovery.processes.v1":
            maximum = _bounded_integer(
                step.parameters.get("record_limit", 25), "record_limit", 1, 100
            )
            adapted = AdaptedAction(
                params={"max_entries": maximum},
                filesystem_scope=(),
            )
        elif action_id == "sandbox.discovery.recursive.v1":
            workspace = _artifact_mapping(bound_inputs.get("workspace"), "workspace")
            root = _runner_path(workspace.get("root"), "workspace.root")
            maximum = _bounded_integer(
                step.parameters.get("record_limit", 25), "record_limit", 1, 100
            )
            depth = _bounded_integer(step.parameters.get("max_depth", 3), "max_depth", 1, 16)
            adapted = AdaptedAction(
                params={"path": root, "max_entries": maximum, "max_depth": depth},
                filesystem_scope=(root,),
            )
        elif action_id == "sandbox.archive.tar.v1":
            records = bound_inputs.get("records")
            if not isinstance(records, list) or not records:
                raise RunnerAdapterError("records must contain typed filesystem artifacts")
            inputs: list[str] = []
            for index, item in enumerate(records):
                record = _artifact_mapping(item, f"records[{index}]")
                if record.get("kind") != "file":
                    continue
                inputs.append(_artifact_path(record, f"records[{index}]"))
            if not inputs:
                raise RunnerAdapterError("records must contain at least one regular file artifact")
            archive_destination = "staged/discovery.tar"
            adapted = AdaptedAction(
                params={"inputs": inputs, "destination": archive_destination},
                filesystem_scope=tuple(inputs) + (archive_destination,),
                observable_paths=(archive_destination,),
            )
        elif action_id == "sandbox.collection.stage.v1":
            records = bound_inputs.get("records")
            if not isinstance(records, list) or len(records) != 1:
                raise RunnerAdapterError(
                    "records must contain exactly one typed discovery artifact"
                )
            record = _artifact_mapping(records[0], "records[0]")
            if record.get("kind") != "file":
                raise RunnerAdapterError("records[0] must be an exact regular-file artifact")
            inputs = [_artifact_path(record, "records[0]")]
            bundle_format = _reviewed_choice(
                step.parameters.get("bundle_format", "jsonl"),
                "bundle_format",
                frozenset({"jsonl", "json"}),
            )
            bundle_path = f"staged/bundle.{bundle_format}"
            adapted = AdaptedAction(
                params={
                    "inputs": inputs,
                    "destination_directory": "staged",
                    "bundle_format": bundle_format,
                },
                filesystem_scope=tuple(inputs) + ("staged",),
                observable_paths=(bundle_path,),
            )
        elif action_id == "sandbox.network.loopback.v1":
            if loopback_host not in {"127.0.0.1", "::1"}:
                raise RunnerAdapterError("network adapter accepts literal loopback hosts only")
            bundle = _artifact_path(bound_inputs.get("bundle"), "bundle")
            port = step.parameters.get("port", 4317)
            if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
                raise RunnerAdapterError("loopback port must be an integer between 1024 and 65535")
            network_destination = {"host": loopback_host, "port": port}
            adapted = AdaptedAction(
                params={"artifact": bundle, "destination": network_destination},
                filesystem_scope=(bundle,),
                network_destinations=(network_destination,),
            )
        elif action_id == "sandbox.export.local.v1":
            bundle = _artifact_path(bound_inputs.get("bundle"), "bundle")
            retention_label = _reviewed_choice(
                step.parameters.get("retention_label", "ephemeral"),
                "retention_label",
                frozenset({"ephemeral", "review"}),
            )
            destination = f"exports/{retention_label}/bundle.bin"
            adapted = AdaptedAction(
                params={"source": bundle, "retention_label": retention_label},
                filesystem_scope=(bundle, destination),
                observable_paths=(destination,),
            )
        elif action_id == "sandbox.restricted.persistence-marker.v1":
            label = step.parameters.get("label", "persistence_detection_canary")
            if label not in {"persistence_detection_canary", "control_validation"}:
                raise RunnerAdapterError("restricted marker label is not reviewed")
            marker_path = "restricted/persistence-marker.json"
            adapted = AdaptedAction(
                params={"label": label},
                filesystem_scope=(marker_path,),
                observable_paths=(marker_path,),
            )
        elif action_id == "sandbox.cleanup.v1":
            verify_removal = _reviewed_boolean(
                step.parameters.get("verify_removal", True), "verify_removal"
            )
            if not verify_removal:
                raise RunnerAdapterError("verify_removal must be true for reviewed cleanup")
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
            raise RunnerAdapterError("successful runner output must be an object")

        if action_id == "sandbox.fixture.create.v1":
            if set(runner_output) != {
                "artifact",
                "sha256",
                "size",
                "template",
                "record_count",
                "format",
            }:
                raise RunnerAdapterError("runner fixture-create output shape is invalid")
            path = _runner_path(runner_output.get("artifact"), "runner output artifact")
            expected_count = _bounded_integer(
                step.parameters.get("record_count", 6), "record_count", 1, 100
            )
            record_count = _bounded_integer(
                runner_output.get("record_count"), "runner output record_count", 1, 100
            )
            _runner_sha256(runner_output.get("sha256"), "runner output sha256")
            _bounded_integer(runner_output.get("size"), "runner output size", 1, 2**63 - 1)
            if (
                path != "fixtures/input.jsonl"
                or runner_output.get("template") != "telemetry-seed"
                or runner_output.get("format") != "jsonl"
                or record_count != expected_count
            ):
                raise RunnerAdapterError(
                    "runner fixture-create output changed the reviewed request"
                )
            return {
                "workspace": {
                    "type": "artifact.sandbox.workspace.v1",
                    "root": str(PurePosixPath(path).parent),
                    "fixture_path": path,
                    "record_count": runner_output.get("record_count"),
                    "format": runner_output.get("format"),
                    "receipt_ids": list(receipt_ids),
                }
            }
        if action_id == "sandbox.fixture.transform.v1":
            if set(runner_output) != {
                "artifact",
                "sha256",
                "size",
                "record_count",
                "redact_values",
                "redacted_value_count",
                "format",
                "implementation",
            }:
                raise RunnerAdapterError("runner fixture-transform output shape is invalid")
            path = _runner_path(runner_output.get("artifact"), "runner output artifact")
            workspace = _artifact_mapping(bound_inputs.get("workspace"), "workspace")
            expected_count = _bounded_integer(
                workspace.get("record_count"), "workspace.record_count", 1, 100
            )
            record_count = _bounded_integer(
                runner_output.get("record_count"), "runner output record_count", 1, 100
            )
            redact_values = _reviewed_boolean(
                step.parameters.get("redact_values", True), "redact_values"
            )
            redacted_value_count = _bounded_integer(
                runner_output.get("redacted_value_count"),
                "runner output redacted_value_count",
                0,
                100,
            )
            _runner_sha256(runner_output.get("sha256"), "runner output sha256")
            _bounded_integer(runner_output.get("size"), "runner output size", 1, 2**63 - 1)
            if (
                path != "fixtures/transformed.jsonl"
                or runner_output.get("format") != "jsonl"
                or runner_output.get("implementation") != "in_process_reviewed_jsonl_transform"
                or runner_output.get("redact_values") is not redact_values
                or record_count != expected_count
                or redacted_value_count != (record_count if redact_values else 0)
            ):
                raise RunnerAdapterError(
                    "runner fixture-transform output changed the reviewed request"
                )
            return {
                "fixture": {
                    "type": "artifact.sandbox.fixture.v1",
                    "path": path,
                    "sha256": runner_output.get("sha256"),
                    "record_count": runner_output.get("record_count"),
                    "redact_values": runner_output.get("redact_values"),
                    "receipt_ids": list(receipt_ids),
                }
            }
        if action_id == "sandbox.discovery.list.v1":
            return {
                "records": [
                    _exact_fixture_discovery_record(
                        bound_inputs=bound_inputs,
                        runner_output=runner_output,
                        context="runner list output",
                        include_readonly=False,
                    )
                ]
            }
        if action_id == "sandbox.discovery.metadata.v1":
            return {
                "records": [
                    _exact_fixture_discovery_record(
                        bound_inputs=bound_inputs,
                        runner_output=runner_output,
                        context="runner metadata output",
                        include_readonly=True,
                    )
                ]
            }
        if action_id == "endpoint.discovery.system.v1":
            return {
                "system": {
                    "type": "artifact.endpoint.system-profile.v1",
                    "details": dict(runner_output),
                }
            }
        if action_id == "endpoint.discovery.processes.v1":
            entries = runner_output.get("entries")
            if not isinstance(entries, list):
                return {}
            return {
                "processes": {
                    "type": "artifact.endpoint.process-records.v1",
                    "entries": entries,
                    "truncated": bool(runner_output.get("truncated", False)),
                }
            }
        if action_id == "sandbox.discovery.recursive.v1":
            entries = runner_output.get("entries")
            if not isinstance(entries, list):
                return {}
            records = []
            for index, item in enumerate(entries):
                entry = _artifact_mapping(item, f"runner entries[{index}]")
                path = _runner_path(entry.get("path"), f"runner entries[{index}].path")
                records.append(
                    {
                        "type": "artifact.sandbox.filesystem.record.v1",
                        "path": path,
                        "kind": entry.get("kind"),
                        "metadata": dict(entry),
                    }
                )
            return {"records": records}
        if action_id == "sandbox.archive.tar.v1":
            path = _runner_path(runner_output.get("artifact"), "runner archive output")
            return {
                "bundle": {
                    "type": "artifact.sandbox.archive.v1",
                    "path": path,
                    "sha256": runner_output.get("sha256"),
                    "receipt_ids": list(receipt_ids),
                }
            }
        if action_id == "sandbox.collection.stage.v1":
            if set(runner_output) != {
                "artifact",
                "format",
                "input_count",
                "accepted_input_count",
                "rejected_input_count",
                "record_count",
                "sha256",
                "size",
                "complete",
            }:
                raise RunnerAdapterError("runner bundle output shape is invalid")
            bundle_format = _reviewed_choice(
                step.parameters.get("bundle_format", "jsonl"),
                "bundle_format",
                frozenset({"jsonl", "json"}),
            )
            if runner_output.get("format") != bundle_format:
                raise RunnerAdapterError("runner bundle format does not match the requested format")
            records = bound_inputs.get("records")
            if not isinstance(records, list) or len(records) != 1:
                raise RunnerAdapterError("bound collection records are invalid")
            source_record = _artifact_mapping(records[0], "records[0]")
            expected_count = _bounded_integer(
                source_record.get("record_count"), "records[0].record_count", 1, 100
            )
            input_count = _bounded_integer(
                runner_output.get("input_count"), "runner bundle output.input_count", 1, 1
            )
            accepted_input_count = _bounded_integer(
                runner_output.get("accepted_input_count"),
                "runner bundle output.accepted_input_count",
                1,
                1,
            )
            rejected_input_count = _bounded_integer(
                runner_output.get("rejected_input_count"),
                "runner bundle output.rejected_input_count",
                0,
                0,
            )
            record_count = _bounded_integer(
                runner_output.get("record_count"),
                "runner bundle output.record_count",
                1,
                100,
            )
            if (
                runner_output.get("complete") is not True
                or input_count != 1
                or accepted_input_count != 1
                or rejected_input_count != 0
                or record_count != expected_count
            ):
                raise RunnerAdapterError(
                    "runner bundle output is incomplete or changes record count"
                )
            path = _runner_path(runner_output.get("artifact"), "runner bundle output.artifact")
            _runner_sha256(runner_output.get("sha256"), "runner bundle output.sha256")
            _bounded_integer(runner_output.get("size"), "runner bundle output.size", 1, 2**63 - 1)
            expected_path = f"staged/bundle.{bundle_format}"
            if path != expected_path:
                raise RunnerAdapterError("runner bundle artifact is not the fixed staging path")
            return {
                "bundle": {
                    "type": "artifact.sandbox.bundle.v1",
                    "path": path,
                    "sha256": runner_output.get("sha256"),
                    "format": bundle_format,
                    "record_count": runner_output.get("record_count"),
                    "size": runner_output.get("size"),
                    "receipt_ids": list(receipt_ids),
                }
            }
        if action_id == "sandbox.network.loopback.v1":
            if set(runner_output) != {
                "destination",
                "artifact",
                "bytes_sent",
                "sha256",
                "http_status",
                "receiver_acknowledged",
                "receiver_stored",
            }:
                raise RunnerAdapterError("runner network output shape is invalid")
            bundle = _artifact_mapping(bound_inputs.get("bundle"), "bundle")
            source = _artifact_path(bundle, "bundle")
            expected_sha256 = _runner_sha256(bundle.get("sha256"), "bundle.sha256")
            expected_size = _bounded_integer(bundle.get("size"), "bundle.size", 1, 2**63 - 1)
            expected_port = _bounded_integer(step.parameters.get("port", 4317), "port", 1024, 65535)
            destination = _artifact_mapping(
                runner_output.get("destination"), "runner network output.destination"
            )
            if set(destination) != {"host", "port"}:
                raise RunnerAdapterError("runner network destination shape is invalid")
            actual_port = _bounded_integer(
                destination.get("port"),
                "runner network output.destination.port",
                1024,
                65535,
            )
            actual_source = _runner_path(
                runner_output.get("artifact"), "runner network output.artifact"
            )
            actual_size = _bounded_integer(
                runner_output.get("bytes_sent"),
                "runner network output.bytes_sent",
                1,
                2**63 - 1,
            )
            actual_sha256 = _runner_sha256(
                runner_output.get("sha256"), "runner network output.sha256"
            )
            http_status = _bounded_integer(
                runner_output.get("http_status"),
                "runner network output.http_status",
                200,
                201,
            )
            acknowledged = _reviewed_boolean(
                runner_output.get("receiver_acknowledged"),
                "runner network output.receiver_acknowledged",
            )
            receiver_stored = _reviewed_boolean(
                runner_output.get("receiver_stored"),
                "runner network output.receiver_stored",
            )
            if (
                destination.get("host") != "127.0.0.1"
                or actual_port != expected_port
                or actual_source != source
                or actual_size != expected_size
                or actual_sha256 != expected_sha256
                or acknowledged is not True
                or (http_status == 201) != receiver_stored
            ):
                raise RunnerAdapterError("runner network output does not match the bound request")
            return {
                "receipt": {
                    "type": "artifact.sandbox.network.receipt.v1",
                    "transport": "loopback",
                    "details": dict(runner_output),
                }
            }
        if action_id == "sandbox.export.local.v1":
            if set(runner_output) != {
                "source",
                "artifact",
                "size",
                "sha256",
                "retention_label",
                "destination_policy",
            }:
                raise RunnerAdapterError("runner export output shape is invalid")
            path = _runner_path(runner_output.get("artifact"), "runner export output")
            retention_label = _reviewed_choice(
                step.parameters.get("retention_label", "ephemeral"),
                "retention_label",
                frozenset({"ephemeral", "review"}),
            )
            expected_path = f"exports/{retention_label}/bundle.bin"
            bundle = _artifact_mapping(bound_inputs.get("bundle"), "bundle")
            source = _artifact_path(bundle, "bundle")
            expected_sha256 = _runner_sha256(bundle.get("sha256"), "bundle.sha256")
            expected_size = _bounded_integer(bundle.get("size"), "bundle.size", 1, 2**63 - 1)
            actual_sha256 = _runner_sha256(
                runner_output.get("sha256"), "runner export output.sha256"
            )
            actual_size = _bounded_integer(
                runner_output.get("size"), "runner export output.size", 1, 2**63 - 1
            )
            if (
                path != expected_path
                or runner_output.get("source") != source
                or runner_output.get("retention_label") != retention_label
                or runner_output.get("destination_policy") != "runner_fixed_retention_destination"
            ):
                raise RunnerAdapterError("runner export output does not match retention policy")
            if actual_sha256 != expected_sha256 or actual_size != expected_size:
                raise RunnerAdapterError("runner export output does not match the bound bundle")
            return {
                "receipt": {
                    "type": "artifact.sandbox.export.receipt.v1",
                    "path": path,
                    "sha256": runner_output.get("sha256"),
                    "retention_label": retention_label,
                    "receipt_ids": list(receipt_ids),
                }
            }
        if action_id == "sandbox.restricted.persistence-marker.v1":
            path = _runner_path(runner_output.get("artifact"), "runner marker output")
            marker = {
                "type": "artifact.sandbox.restricted-marker.v1",
                "path": path,
                "sha256": runner_output.get("sha256"),
                "receipt_ids": list(receipt_ids),
            }
            return {
                "workspace": {
                    "type": "artifact.sandbox.workspace.v1",
                    "root": str(PurePosixPath(path).parent),
                    "marker_path": path,
                    "receipt_ids": list(receipt_ids),
                },
                "marker": marker,
            }
        if action_id == "sandbox.cleanup.v1":
            return {
                "receipt": {
                    "type": "artifact.sandbox.cleanup.receipt.v1",
                    "details": dict(runner_output),
                }
            }
        raise RunnerAdapterError(f"logical output adapter is not implemented: {action_id}")


__all__ = ["AdaptedAction", "RunnerActionAdapter", "RunnerAdapterError"]
