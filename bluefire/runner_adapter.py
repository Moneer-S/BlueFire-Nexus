"""Deny-by-default translation from logical plan steps to runner parameters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from .planner import PlanStep
from .provider_runner_contracts import PROVIDER_BINDING_SCHEMA
from .runner_client import reject_forbidden_execution_keys
from .util import json_clone

_IDENTITY_MATERIAL_PATH = "identity-material/public-canary.json"
_IDENTITY_MATERIAL_SHA256 = "4af6ae2cf13d13d9d325632af3f90d1730faae52424f176b2cc34a0eef0db6ca"
_IDENTITY_MATERIAL_SIZE = 189
_OBSERVABILITY_VARIANT_PATH = "observability/variant.bin"
_STAGED_BUNDLE_PATHS = frozenset({"staged/bundle.json", "staged/bundle.jsonl"})
_NATIVE_CANARY_SEED = b"bluefire-native-execution-canary-v1"
_PROVIDER_ACTION_OUTPUT_SCHEMA = "bluefire.provider-action-output.v1"


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


def _single_receipt_ids(receipt_ids: Sequence[str], context: str) -> list[str]:
    validated = [_receipt_id(value) for value in receipt_ids]
    if len(validated) != 1:
        raise RunnerAdapterError(f"{context} requires exactly one runner-issued receipt ID")
    return validated


def _exact_parameter_keys(
    parameters: Mapping[str, Any], *, allowed: frozenset[str], context: str
) -> None:
    extras = set(parameters) - allowed
    if extras:
        raise RunnerAdapterError(f"{context} contains unreviewed parameters")


def _provider_binding(step: PlanStep) -> Mapping[str, Any] | None:
    binding = step.execution_binding
    if not isinstance(binding, Mapping) or binding.get("schema_version") != PROVIDER_BINDING_SCHEMA:
        return None
    if (
        binding.get("logical_behavior_id") != step.behavior_id
        or binding.get("logical_action_id") != step.action_id
    ):
        raise RunnerAdapterError("provider binding changed the logical action identity")
    return binding


def _validate_provider_parameter(spec: Mapping[str, Any], value: Any, context: str) -> None:
    parameter_type = spec.get("type")
    valid = {
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "string_list": lambda item: isinstance(item, list)
        and all(isinstance(child, str) for child in item),
    }.get(str(parameter_type), lambda _item: False)(value)
    if not valid:
        raise RunnerAdapterError(f"{context} does not match the signed provider parameter type")
    allowed = spec.get("enum")
    if isinstance(allowed, list) and allowed and value not in allowed:
        raise RunnerAdapterError(f"{context} is outside the signed provider enum")
    if parameter_type in {"integer", "number"}:
        minimum = spec.get("minimum")
        maximum = spec.get("maximum")
        if minimum is not None and value < minimum:
            raise RunnerAdapterError(f"{context} is below the signed provider minimum")
        if maximum is not None and value > maximum:
            raise RunnerAdapterError(f"{context} exceeds the signed provider maximum")


def _provider_parameters(binding: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    raw_specs = binding.get("parameters")
    if not isinstance(raw_specs, list):
        raise RunnerAdapterError("provider binding has no signed parameter contract")
    specs = {str(spec.get("name")): spec for spec in raw_specs if isinstance(spec, Mapping)}
    if len(specs) != len(raw_specs) or set(values) - set(specs):
        raise RunnerAdapterError("provider parameters do not match the signed contract")
    missing = [
        name for name, spec in specs.items() if spec.get("required") is True and name not in values
    ]
    if missing:
        raise RunnerAdapterError("provider parameters omit a required signed field")
    result = dict(json_clone(dict(values)))
    for name, value in result.items():
        _validate_provider_parameter(specs[name], value, f"provider parameter {name}")
    reject_forbidden_execution_keys(result)
    return result


def _provider_output_value(spec: Mapping[str, Any], value: Any, context: str) -> Any:
    artifact_type = spec.get("type")

    def validate_one(item: Any, label: str) -> Mapping[str, Any]:
        if not isinstance(item, Mapping) or item.get("type") != artifact_type:
            raise RunnerAdapterError(f"{label} does not match its signed provider artifact type")
        reject_forbidden_execution_keys(item)
        return dict(json_clone(dict(item)))

    if spec.get("multiple") is True:
        if not isinstance(value, list) or (spec.get("required") is True and not value):
            raise RunnerAdapterError(f"{context} must be a non-empty provider artifact array")
        return [validate_one(item, f"{context}[{index}]") for index, item in enumerate(value)]
    return validate_one(value, context)


def _provider_outputs(binding: Mapping[str, Any], value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"schema_version", "outputs"}:
        raise RunnerAdapterError("successful provider result must have exact ABI wrapper fields")
    if value.get("schema_version") != _PROVIDER_ACTION_OUTPUT_SCHEMA:
        raise RunnerAdapterError("successful provider result has an unsupported ABI schema")
    outputs = value.get("outputs")
    if not isinstance(outputs, Mapping):
        raise RunnerAdapterError("successful provider outputs must be an object")
    raw_specs = binding.get("outputs")
    if not isinstance(raw_specs, list):
        raise RunnerAdapterError("provider binding has no signed output contract")
    specs = {str(spec.get("name")): spec for spec in raw_specs if isinstance(spec, Mapping)}
    if len(specs) != len(raw_specs) or set(outputs) - set(specs):
        raise RunnerAdapterError("provider outputs do not match the signed contract")
    missing = [
        name for name, spec in specs.items() if spec.get("required") is True and name not in outputs
    ]
    if missing:
        raise RunnerAdapterError("provider outputs omit a required signed artifact")
    return {
        name: _provider_output_value(specs[name], item, f"provider output {name}")
        for name, item in outputs.items()
    }


def _bound_content_artifact(
    value: Any,
    context: str,
    *,
    artifact_type: str,
    allowed_paths: frozenset[str],
) -> tuple[Mapping[str, Any], str, str, int]:
    artifact = _artifact_mapping(value, context)
    if artifact.get("type") != artifact_type:
        raise RunnerAdapterError(f"{context}.type does not match the reviewed artifact type")
    path = _artifact_path(artifact, context)
    if path not in allowed_paths:
        raise RunnerAdapterError(f"{context}.path is not a reviewed fixed path")
    sha256 = _runner_sha256(artifact.get("sha256"), f"{context}.sha256")
    size = _bounded_integer(artifact.get("size"), f"{context}.size", 1, 2**63 - 1)
    return artifact, path, sha256, size


def _native_canary_digests(rounds: int) -> tuple[str, str]:
    state = hashlib.sha256(_NATIVE_CANARY_SEED).digest()
    seed_sha256 = state.hex()
    for _ in range(rounds):
        state = hashlib.sha256(state).digest()
    return seed_sha256, state.hex()


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
    """Compile only the nineteen reviewed action IDs into strict runner params.

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
            "endpoint.discovery.windows-version.v1",
            "endpoint.discovery.processes.v1",
            "sandbox.discovery.recursive.v1",
            "sandbox.archive.tar.v1",
            "sandbox.collection.stage.v1",
            "sandbox.execution.native-canary.v1",
            "sandbox.identity-material.seed.v1",
            "sandbox.identity-material.inspect.v1",
            "sandbox.network.loopback.v1",
            "sandbox.peer.handoff.v1",
            "sandbox.observability.variant.v1",
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
        provider = _provider_binding(step)
        if provider is not None:
            if bound_inputs:
                raise RunnerAdapterError("provider ABI v1 accepts no host artifact inputs")
            if receipt_ids:
                raise RunnerAdapterError("pure provider action cannot consume cleanup receipts")
            return AdaptedAction(
                params=_provider_parameters(provider, step.parameters),
                filesystem_scope=(),
            )
        if action_id not in self.action_ids:
            raise RunnerAdapterError(f"unreviewed or missing runner action: {action_id}")

        if action_id == "sandbox.execution.native-canary.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset({"rounds"}),
                context="native execution canary",
            )
            rounds = _bounded_integer(step.parameters.get("rounds", 256), "rounds", 1, 4096)
            adapted = AdaptedAction(params={"rounds": rounds}, filesystem_scope=())
        elif action_id == "sandbox.identity-material.seed.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset(),
                context="identity-material seed",
            )
            adapted = AdaptedAction(
                params={},
                filesystem_scope=(_IDENTITY_MATERIAL_PATH,),
                observable_paths=(_IDENTITY_MATERIAL_PATH,),
            )
        elif action_id == "sandbox.identity-material.inspect.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset(),
                context="identity-material inspection",
            )
            identity, path, sha256, size = _bound_content_artifact(
                bound_inputs.get("identity_material"),
                "identity_material",
                artifact_type="artifact.sandbox.identity-material.v1",
                allowed_paths=frozenset({_IDENTITY_MATERIAL_PATH}),
            )
            if (
                sha256 != _IDENTITY_MATERIAL_SHA256
                or size != _IDENTITY_MATERIAL_SIZE
                or identity.get("classification") != "public"
                or identity.get("synthetic") is not True
            ):
                raise RunnerAdapterError(
                    "identity_material does not match the fixed public synthetic canary"
                )
            adapted = AdaptedAction(params={}, filesystem_scope=(path,))
        elif action_id == "sandbox.fixture.create.v1":
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
        elif action_id == "endpoint.discovery.windows-version.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset(),
                context="Windows version discovery",
            )
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
        elif action_id == "sandbox.peer.handoff.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset({"port"}),
                context="peer handoff",
            )
            _, bundle, _, _ = _bound_content_artifact(
                bound_inputs.get("bundle"),
                "bundle",
                artifact_type="artifact.sandbox.bundle.v1",
                allowed_paths=_STAGED_BUNDLE_PATHS,
            )
            port = _bounded_integer(step.parameters.get("port", 4317), "port", 1024, 65535)
            network_destination = {"host": "127.0.0.1", "port": port}
            adapted = AdaptedAction(
                params={"port": port},
                filesystem_scope=(bundle,),
                network_destinations=(network_destination,),
            )
        elif action_id == "sandbox.observability.variant.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset({"representation"}),
                context="observability variant",
            )
            _, bundle, _, _ = _bound_content_artifact(
                bound_inputs.get("bundle"),
                "bundle",
                artifact_type="artifact.sandbox.bundle.v1",
                allowed_paths=_STAGED_BUNDLE_PATHS,
            )
            representation = _reviewed_choice(
                step.parameters.get("representation"),
                "representation",
                frozenset({"canonical", "chunked_hex"}),
            )
            adapted = AdaptedAction(
                params={"representation": representation},
                filesystem_scope=(bundle, _OBSERVABILITY_VARIANT_PATH),
                observable_paths=(_OBSERVABILITY_VARIANT_PATH,),
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
        provider = _provider_binding(step)
        if provider is not None:
            if receipt_ids:
                raise RunnerAdapterError("pure provider action returned cleanup receipts")
            return _provider_outputs(provider, runner_output)
        if action_id not in self.action_ids:
            raise RunnerAdapterError(f"unreviewed or missing runner action: {action_id}")
        if not isinstance(runner_output, Mapping):
            raise RunnerAdapterError("successful runner output must be an object")

        if action_id == "sandbox.execution.native-canary.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset({"rounds"}),
                context="native execution canary",
            )
            if set(runner_output) != {
                "algorithm",
                "implementation",
                "rounds",
                "seed_sha256",
                "result_sha256",
                "external_effects",
            }:
                raise RunnerAdapterError("runner native-canary output shape is invalid")
            expected_rounds = _bounded_integer(
                step.parameters.get("rounds", 256), "rounds", 1, 4096
            )
            actual_rounds = _bounded_integer(
                runner_output.get("rounds"), "runner native-canary output.rounds", 1, 4096
            )
            seed_sha256 = _runner_sha256(
                runner_output.get("seed_sha256"),
                "runner native-canary output.seed_sha256",
            )
            result_sha256 = _runner_sha256(
                runner_output.get("result_sha256"),
                "runner native-canary output.result_sha256",
            )
            expected_seed_sha256, expected_result_sha256 = _native_canary_digests(expected_rounds)
            if (
                runner_output.get("algorithm") != "sha256"
                or runner_output.get("implementation") != "rust-in-process-sha256-v1"
                or actual_rounds != expected_rounds
                or seed_sha256 != expected_seed_sha256
                or result_sha256 != expected_result_sha256
                or runner_output.get("external_effects") is not False
            ):
                raise RunnerAdapterError("runner native-canary output changed the reviewed request")
            return {
                "result": {
                    "type": "artifact.sandbox.execution.canary.v1",
                    "algorithm": "sha256",
                    "implementation": "rust-in-process-sha256-v1",
                    "rounds": actual_rounds,
                    "seed_sha256": seed_sha256,
                    "result_sha256": result_sha256,
                    "external_effects": False,
                }
            }
        if action_id == "sandbox.identity-material.seed.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset(),
                context="identity-material seed",
            )
            if set(runner_output) != {
                "artifact",
                "byte_count",
                "classification",
                "sha256",
                "synthetic",
            }:
                raise RunnerAdapterError("runner identity-material seed output shape is invalid")
            path = _runner_path(
                runner_output.get("artifact"), "runner identity-material seed output.artifact"
            )
            byte_count = _bounded_integer(
                runner_output.get("byte_count"),
                "runner identity-material seed output.byte_count",
                1,
                2**63 - 1,
            )
            sha256 = _runner_sha256(
                runner_output.get("sha256"),
                "runner identity-material seed output.sha256",
            )
            if (
                path != _IDENTITY_MATERIAL_PATH
                or byte_count != _IDENTITY_MATERIAL_SIZE
                or sha256 != _IDENTITY_MATERIAL_SHA256
                or runner_output.get("classification") != "public"
                or runner_output.get("synthetic") is not True
            ):
                raise RunnerAdapterError(
                    "runner identity-material seed output changed the fixed public canary"
                )
            return {
                "identity_material": {
                    "type": "artifact.sandbox.identity-material.v1",
                    "path": path,
                    "sha256": sha256,
                    "size": byte_count,
                    "classification": "public",
                    "synthetic": True,
                    "receipt_ids": _single_receipt_ids(receipt_ids, "identity-material seed"),
                }
            }
        if action_id == "sandbox.identity-material.inspect.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset(),
                context="identity-material inspection",
            )
            if set(runner_output) != {"byte_count", "field_count", "sha256"}:
                raise RunnerAdapterError(
                    "runner identity-material inspection output shape is invalid"
                )
            identity, path, expected_sha256, expected_size = _bound_content_artifact(
                bound_inputs.get("identity_material"),
                "identity_material",
                artifact_type="artifact.sandbox.identity-material.v1",
                allowed_paths=frozenset({_IDENTITY_MATERIAL_PATH}),
            )
            byte_count = _bounded_integer(
                runner_output.get("byte_count"),
                "runner identity-material inspection output.byte_count",
                1,
                2**63 - 1,
            )
            field_count = _bounded_integer(
                runner_output.get("field_count"),
                "runner identity-material inspection output.field_count",
                0,
                64,
            )
            sha256 = _runner_sha256(
                runner_output.get("sha256"),
                "runner identity-material inspection output.sha256",
            )
            if (
                expected_sha256 != _IDENTITY_MATERIAL_SHA256
                or expected_size != _IDENTITY_MATERIAL_SIZE
                or identity.get("classification") != "public"
                or identity.get("synthetic") is not True
                or byte_count != expected_size
                or field_count != 5
                or sha256 != expected_sha256
            ):
                raise RunnerAdapterError(
                    "runner identity-material inspection does not match its bound canary"
                )
            return {
                "inspection": {
                    "type": "artifact.sandbox.identity-material.inspection.v1",
                    "path": path,
                    "sha256": sha256,
                    "size": byte_count,
                    "field_count": field_count,
                }
            }
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
        if action_id == "endpoint.discovery.windows-version.v1":
            if set(runner_output) != {
                "operating_system",
                "major_version",
                "minor_version",
                "build_number",
            }:
                raise RunnerAdapterError("runner Windows version output shape is invalid")
            major_version = _bounded_integer(
                runner_output.get("major_version"),
                "runner Windows version output.major_version",
                0,
                2**32 - 1,
            )
            minor_version = _bounded_integer(
                runner_output.get("minor_version"),
                "runner Windows version output.minor_version",
                0,
                2**32 - 1,
            )
            build_number = _bounded_integer(
                runner_output.get("build_number"),
                "runner Windows version output.build_number",
                0,
                2**32 - 1,
            )
            if runner_output.get("operating_system") != "windows":
                raise RunnerAdapterError("runner Windows version operating system is invalid")
            return {
                "windows_version": {
                    "type": "artifact.endpoint.windows-version.v1",
                    "details": {
                        "operating_system": "windows",
                        "major_version": major_version,
                        "minor_version": minor_version,
                        "build_number": build_number,
                    },
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
            bound_records_value = bound_inputs.get("records")
            if not isinstance(bound_records_value, list) or len(bound_records_value) != 1:
                raise RunnerAdapterError("bound collection records are invalid")
            source_record = _artifact_mapping(bound_records_value[0], "records[0]")
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
        if action_id == "sandbox.peer.handoff.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset({"port"}),
                context="peer handoff",
            )
            if set(runner_output) != {
                "destination",
                "artifact",
                "bytes_sent",
                "sha256",
                "http_status",
                "receiver_acknowledged",
                "receiver_stored",
                "lab_authorization",
                "lab_peers",
            }:
                raise RunnerAdapterError("runner peer-handoff output shape is invalid")
            _, source, expected_sha256, expected_size = _bound_content_artifact(
                bound_inputs.get("bundle"),
                "bundle",
                artifact_type="artifact.sandbox.bundle.v1",
                allowed_paths=_STAGED_BUNDLE_PATHS,
            )
            expected_port = _bounded_integer(step.parameters.get("port", 4317), "port", 1024, 65535)
            destination = _artifact_mapping(
                runner_output.get("destination"), "runner peer-handoff output.destination"
            )
            if set(destination) != {"host", "port"}:
                raise RunnerAdapterError("runner peer-handoff destination shape is invalid")
            actual_port = _bounded_integer(
                destination.get("port"),
                "runner peer-handoff output.destination.port",
                1024,
                65535,
            )
            actual_source = _runner_path(
                runner_output.get("artifact"), "runner peer-handoff output.artifact"
            )
            actual_size = _bounded_integer(
                runner_output.get("bytes_sent"),
                "runner peer-handoff output.bytes_sent",
                1,
                2**63 - 1,
            )
            actual_sha256 = _runner_sha256(
                runner_output.get("sha256"), "runner peer-handoff output.sha256"
            )
            http_status = _bounded_integer(
                runner_output.get("http_status"),
                "runner peer-handoff output.http_status",
                200,
                200,
            )
            acknowledged = _reviewed_boolean(
                runner_output.get("receiver_acknowledged"),
                "runner peer-handoff output.receiver_acknowledged",
            )
            receiver_stored = _reviewed_boolean(
                runner_output.get("receiver_stored"),
                "runner peer-handoff output.receiver_stored",
            )
            authorization = _artifact_mapping(
                runner_output.get("lab_authorization"),
                "runner peer-handoff output.lab_authorization",
            )
            peers = _artifact_mapping(
                runner_output.get("lab_peers"),
                "runner peer-handoff output.lab_peers",
            )
            if set(authorization) != {
                "scope",
                "credential_kind",
                "credential_handle",
                "challenge_verified",
                "raw_credential_exposed",
            }:
                raise RunnerAdapterError("runner peer-handoff authorization shape is invalid")
            if set(peers) != {
                "scope",
                "source_kind",
                "destination_kind",
                "source_process_id",
                "destination_process_id",
                "source_handle",
                "destination_handle",
                "distinct_processes",
                "receiver_mode",
                "accepted_artifact_limit",
                "storage_mode",
                "exit_after_accept",
                "transfer_acknowledged",
            }:
                raise RunnerAdapterError("runner peer-handoff peer shape is invalid")
            credential_handle = _runner_sha256(
                authorization.get("credential_handle"),
                "runner peer-handoff authorization.credential_handle",
            )
            source_handle = _runner_sha256(
                peers.get("source_handle"),
                "runner peer-handoff peers.source_handle",
            )
            destination_handle = _runner_sha256(
                peers.get("destination_handle"),
                "runner peer-handoff peers.destination_handle",
            )
            challenge_verified = _reviewed_boolean(
                authorization.get("challenge_verified"),
                "runner peer-handoff authorization.challenge_verified",
            )
            raw_credential_exposed = _reviewed_boolean(
                authorization.get("raw_credential_exposed"),
                "runner peer-handoff authorization.raw_credential_exposed",
            )
            source_process_id = _bounded_integer(
                peers.get("source_process_id"),
                "runner peer-handoff peers.source_process_id",
                1,
                2**32 - 1,
            )
            destination_process_id = _bounded_integer(
                peers.get("destination_process_id"),
                "runner peer-handoff peers.destination_process_id",
                1,
                2**32 - 1,
            )
            distinct_processes = _reviewed_boolean(
                peers.get("distinct_processes"),
                "runner peer-handoff peers.distinct_processes",
            )
            accepted_artifact_limit = _bounded_integer(
                peers.get("accepted_artifact_limit"),
                "runner peer-handoff peers.accepted_artifact_limit",
                1,
                1,
            )
            exit_after_accept = _reviewed_boolean(
                peers.get("exit_after_accept"),
                "runner peer-handoff peers.exit_after_accept",
            )
            transfer_acknowledged = _reviewed_boolean(
                peers.get("transfer_acknowledged"),
                "runner peer-handoff peers.transfer_acknowledged",
            )
            if (
                destination.get("host") != "127.0.0.1"
                or actual_port != expected_port
                or actual_source != source
                or actual_size != expected_size
                or actual_sha256 != expected_sha256
                or acknowledged is not True
                or http_status != 200
                or receiver_stored is not False
                or authorization.get("scope") != "approved_task"
                or authorization.get("credential_kind") != "managed_one_task_hmac_capability"
                or challenge_verified is not True
                or raw_credential_exposed is not False
                or peers.get("scope") != "authorized_disposable_loopback_lab"
                or peers.get("source_kind") != "rust_runner_process"
                or peers.get("destination_kind") != "managed_loopback_receiver_process"
                or source_process_id == destination_process_id
                or source_handle == destination_handle
                or distinct_processes is not True
                or peers.get("receiver_mode") != "disposable_peer"
                or accepted_artifact_limit != 1
                or peers.get("storage_mode") != "memory_only"
                or exit_after_accept is not True
                or transfer_acknowledged is not True
            ):
                raise RunnerAdapterError(
                    "runner peer-handoff output does not match the bound request"
                )
            return {
                "receipt": {
                    "type": "artifact.sandbox.peer-handoff.receipt.v2",
                    "transport": "authenticated_loopback",
                    "artifact": actual_source,
                    "sha256": actual_sha256,
                    "size": actual_size,
                    "destination": dict(destination),
                    "http_status": http_status,
                    "receiver_acknowledged": True,
                    "receiver_stored": receiver_stored,
                    "lab_authorization": {
                        **dict(authorization),
                        "credential_handle": credential_handle,
                    },
                    "lab_peers": {
                        **dict(peers),
                        "source_handle": source_handle,
                        "destination_handle": destination_handle,
                    },
                }
            }
        if action_id == "sandbox.observability.variant.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset({"representation"}),
                context="observability variant",
            )
            if set(runner_output) != {
                "artifact",
                "representation",
                "source_artifact",
                "source_sha256",
                "source_size",
                "sha256",
                "size",
                "equivalence_verified",
            }:
                raise RunnerAdapterError("runner observability-variant output shape is invalid")
            _, source, expected_source_sha256, expected_source_size = _bound_content_artifact(
                bound_inputs.get("bundle"),
                "bundle",
                artifact_type="artifact.sandbox.bundle.v1",
                allowed_paths=_STAGED_BUNDLE_PATHS,
            )
            representation = _reviewed_choice(
                step.parameters.get("representation"),
                "representation",
                frozenset({"canonical", "chunked_hex"}),
            )
            path = _runner_path(
                runner_output.get("artifact"),
                "runner observability-variant output.artifact",
            )
            source_artifact = _runner_path(
                runner_output.get("source_artifact"),
                "runner observability-variant output.source_artifact",
            )
            source_sha256 = _runner_sha256(
                runner_output.get("source_sha256"),
                "runner observability-variant output.source_sha256",
            )
            source_size = _bounded_integer(
                runner_output.get("source_size"),
                "runner observability-variant output.source_size",
                1,
                2**63 - 1,
            )
            sha256 = _runner_sha256(
                runner_output.get("sha256"),
                "runner observability-variant output.sha256",
            )
            size = _bounded_integer(
                runner_output.get("size"),
                "runner observability-variant output.size",
                1,
                2**63 - 1,
            )
            encoded_hex_size = expected_source_size * 2
            expected_size = encoded_hex_size
            if representation == "chunked_hex":
                expected_size += (encoded_hex_size - 1) // 64
            if (
                path != _OBSERVABILITY_VARIANT_PATH
                or runner_output.get("representation") != representation
                or source_artifact != source
                or source_sha256 != expected_source_sha256
                or source_size != expected_source_size
                or size != expected_size
                or runner_output.get("equivalence_verified") is not True
            ):
                raise RunnerAdapterError(
                    "runner observability-variant output does not match its bound bundle"
                )
            return {
                "variant": {
                    "type": "artifact.sandbox.observability.variant.v1",
                    "path": path,
                    "representation": representation,
                    "source_path": source_artifact,
                    "source_sha256": source_sha256,
                    "source_size": source_size,
                    "sha256": sha256,
                    "size": size,
                    "equivalence_verified": True,
                    "receipt_ids": _single_receipt_ids(receipt_ids, "observability variant"),
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
