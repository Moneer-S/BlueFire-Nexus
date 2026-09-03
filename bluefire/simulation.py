"""Pure deterministic simulation adapters with no runner or host side effects."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import StepOutcome
from .planner import PlanStep
from .util import canonical_json_bytes, content_hash

_IDENTITY_MATERIAL_BYTES = (
    b'{"canary_id":"bluefire-public-identity-canary-v1","classification":"public",'
    b'"material":"synthetic-public-identity-canary","schema_version":'
    b'"bluefire.identity-material.v1","synthetic":true}\n'
)
_IDENTITY_MATERIAL_CONTENT_HASH = (
    "sha256:4af6ae2cf13d13d9d325632af3f90d1730faae52424f176b2cc34a0eef0db6ca"
)
_NATIVE_CANARY_SEED = b"bluefire-native-execution-canary-v1"
_SIMULATED_IDENTITY_MATERIAL_PATH = "synthetic/identity-material/public-canary.json"
_SIMULATED_OBSERVABILITY_VARIANT_PATH = "synthetic/observability/variant.bin"
_SIMULATED_STAGED_BUNDLE_PATHS = frozenset(
    {"synthetic/staged/bundle.json", "synthetic/staged/bundle.jsonl"}
)


class SimulationError(ValueError):
    pass


def _bounded_integer(value: Any, context: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SimulationError(f"{context} must be an integer between {minimum} and {maximum}")
    return int(value)


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise SimulationError(f"{context} must be a boolean")
    return value


def _choice(value: Any, context: str, choices: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise SimulationError(f"{context} is not a reviewed choice")
    return value


def _exact_parameter_keys(
    parameters: Mapping[str, Any], *, allowed: frozenset[str], context: str
) -> None:
    if set(parameters) - allowed:
        raise SimulationError(f"{context} contains unreviewed parameters")


def _content_hash(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise SimulationError(f"{context} must be a sha256-prefixed lowercase digest")
    return value


def _native_canary_digests(rounds: int) -> tuple[str, str]:
    state = hashlib.sha256(_NATIVE_CANARY_SEED).digest()
    seed_sha256 = state.hex()
    for _ in range(rounds):
        state = hashlib.sha256(state).digest()
    return seed_sha256, state.hex()


def _simulated_bundle(value: Any) -> tuple[Mapping[str, Any], str, str, int]:
    bundle = _mapping(value, "bundle")
    path = bundle.get("path")
    if (
        bundle.get("type") != "artifact.sandbox.bundle.v1"
        or not isinstance(path, str)
        or path not in _SIMULATED_STAGED_BUNDLE_PATHS
    ):
        raise SimulationError("bundle must be one fixed simulated staged bundle")
    bundle_hash = _content_hash(bundle.get("content_hash"), "bundle.content_hash")
    bundle_size = _bounded_integer(bundle.get("size"), "bundle.size", 1, 2**63 - 1)
    return bundle, path, bundle_hash, bundle_size


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
            "simulation.sandbox.execution.native-canary.v1",
            "simulation.sandbox.execution.process-tree-cancellation-witness.v1",
            "simulation.sandbox.identity-material.seed.v1",
            "simulation.sandbox.identity-material.inspect.v1",
            "simulation.sandbox.network.loopback.v1",
            "simulation.sandbox.credential.peer-challenge.v1",
            "simulation.sandbox.peer.handoff.v1",
            "simulation.sandbox.observability.variant.v1",
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
        limitations: tuple[str, ...] = base_limitations
        artifacts: dict[str, Any]
        telemetry: tuple[str, ...]
        if simulation_id == "simulation.sandbox.execution.native-canary.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset({"rounds"}),
                context="native execution canary simulation",
            )
            rounds = _bounded_integer(step.parameters.get("rounds", 256), "rounds", 1, 4096)
            seed_sha256, result_sha256 = _native_canary_digests(rounds)
            artifacts = {
                "result": {
                    "type": "artifact.sandbox.execution.canary.v1",
                    "algorithm": "sha256",
                    "implementation": "rust-in-process-sha256-v1",
                    "rounds": rounds,
                    "seed_sha256": seed_sha256,
                    "result_sha256": result_sha256,
                    "external_effects": False,
                }
            }
            telemetry = ("sandbox.execution.native_canary_completed",)
        elif simulation_id == "simulation.sandbox.execution.process-tree-cancellation-witness.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset(),
                context="process-tree cancellation witness simulation",
            )
            artifacts = {}
            telemetry = ("sandbox.execution.process_tree_cancellation_witnessed",)
            limitations = (
                *base_limitations,
                "No cooperative nonce or process-tree termination was exercised.",
            )
        elif simulation_id == "simulation.sandbox.identity-material.seed.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset(),
                context="identity-material seed simulation",
            )
            artifacts = {
                "identity_material": {
                    "type": "artifact.sandbox.identity-material.v1",
                    "path": _SIMULATED_IDENTITY_MATERIAL_PATH,
                    "content_hash": _IDENTITY_MATERIAL_CONTENT_HASH,
                    "size": len(_IDENTITY_MATERIAL_BYTES),
                    "classification": "public",
                    "synthetic": True,
                }
            }
            telemetry = ("sandbox.identity_material.seeded",)
        elif simulation_id == "simulation.sandbox.identity-material.inspect.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset(),
                context="identity-material inspection simulation",
            )
            identity = _mapping(bound_inputs.get("identity_material"), "identity_material")
            identity_hash = _content_hash(
                identity.get("content_hash"), "identity_material.content_hash"
            )
            identity_size = _bounded_integer(
                identity.get("size"), "identity_material.size", 1, 2**63 - 1
            )
            if (
                identity.get("type") != "artifact.sandbox.identity-material.v1"
                or identity.get("path") != _SIMULATED_IDENTITY_MATERIAL_PATH
                or identity_hash != _IDENTITY_MATERIAL_CONTENT_HASH
                or identity_size != len(_IDENTITY_MATERIAL_BYTES)
                or identity.get("classification") != "public"
                or identity.get("synthetic") is not True
            ):
                raise SimulationError(
                    "identity_material does not match the fixed simulated public canary"
                )
            artifacts = {
                "inspection": {
                    "type": "artifact.sandbox.identity-material.inspection.v1",
                    "path": _SIMULATED_IDENTITY_MATERIAL_PATH,
                    "content_hash": identity_hash,
                    "size": identity_size,
                    "field_count": 5,
                }
            }
            telemetry = ("sandbox.identity_material.inspected",)
        elif simulation_id == "simulation.sandbox.fixture.create.v1":
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
            archive_records = bound_inputs.get("records")
            if not isinstance(archive_records, list) or not archive_records:
                raise SimulationError("archive simulation requires filesystem records")
            archive_body: dict[str, Any] = {"format": "ustar", "records": archive_records}
            artifacts = {
                "bundle": {
                    "type": "artifact.sandbox.archive.v1",
                    "path": "synthetic/staged/discovery.tar",
                    "record_count": len(archive_records),
                    "content_hash": content_hash(archive_body),
                }
            }
            telemetry = ("sandbox.archive.created",)
        elif simulation_id == "simulation.sandbox.collection.stage.v1":
            collection_records = bound_inputs.get("records")
            if not isinstance(collection_records, list) or len(collection_records) != 1:
                raise SimulationError("collection simulation requires one discovery record")
            source = _mapping(collection_records[0], "records[0]")
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
            collection_body: dict[str, Any] = {
                "source_content_hash": source_hash,
                "record_count": record_count,
                "format": bundle_format,
            }
            body_bytes = canonical_json_bytes(collection_body)
            artifacts = {
                "bundle": {
                    "type": "artifact.sandbox.bundle.v1",
                    "path": f"synthetic/staged/bundle.{bundle_format}",
                    "record_count": record_count,
                    "format": bundle_format,
                    "source_content_hash": source_hash,
                    "content_hash": content_hash(collection_body),
                    "size": len(body_bytes),
                }
            }
            telemetry = ("sandbox.collection.staged",)
        elif simulation_id in {
            "simulation.sandbox.credential.peer-challenge.v1",
            "simulation.sandbox.peer.handoff.v1",
        }:
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset({"port"}),
                context="peer handoff simulation",
            )
            _, bundle_path, bundle_hash, bundle_size = _simulated_bundle(bound_inputs.get("bundle"))
            port = _bounded_integer(step.parameters.get("port", 4317), "port", 1024, 65535)
            credential_handle = content_hash(
                {
                    "projection": "managed-credential-handle",
                    "bundle": bundle_hash,
                    "port": port,
                }
            ).removeprefix("sha256:")
            source_handle = content_hash(
                {"projection": "source-peer", "bundle": bundle_hash}
            ).removeprefix("sha256:")
            destination_handle = content_hash(
                {"projection": "destination-peer", "port": port}
            ).removeprefix("sha256:")
            artifacts = {
                "receipt": {
                    "type": "artifact.sandbox.peer-handoff.receipt.v2",
                    "transport": "simulated_authenticated_loopback",
                    "artifact": bundle_path,
                    "content_hash": bundle_hash,
                    "size": bundle_size,
                    "destination": {"host": "127.0.0.1", "port": port},
                    "would_authenticate": True,
                    "receiver_stored": False,
                    "lab_authorization": {
                        "scope": "approved_task",
                        "credential_kind": "simulated_managed_one_task_capability_reference",
                        "credential_handle": credential_handle,
                        "challenge_verified": False,
                        "raw_credential_exposed": False,
                    },
                    "lab_peers": {
                        "scope": "authorized_disposable_loopback_lab",
                        "source_kind": "simulated_rust_runner_process",
                        "destination_kind": "simulated_managed_loopback_receiver_process",
                        "source_process_id": None,
                        "destination_process_id": None,
                        "source_handle": source_handle,
                        "destination_handle": destination_handle,
                        "distinct_processes": False,
                        "receiver_mode": "disposable_peer",
                        "accepted_artifact_limit": 1,
                        "storage_mode": "memory_only",
                        "exit_after_accept": True,
                        "transfer_acknowledged": False,
                    },
                    "synthetic": True,
                }
            }
            telemetry = (
                (
                    "sandbox.credential.peer_challenge_attempted"
                    if simulation_id == "simulation.sandbox.credential.peer-challenge.v1"
                    else "sandbox.peer.handoff_attempted"
                ),
            )
            limitations = base_limitations + (
                "No peer was contacted and no authentication exchange or transfer occurred.",
            )
        elif simulation_id == "simulation.sandbox.observability.variant.v1":
            _exact_parameter_keys(
                step.parameters,
                allowed=frozenset({"representation"}),
                context="observability variant simulation",
            )
            _, bundle_path, bundle_hash, bundle_size = _simulated_bundle(bound_inputs.get("bundle"))
            representation = _choice(
                step.parameters.get("representation", "canonical"),
                "representation",
                frozenset({"canonical", "chunked_hex"}),
            )
            encoded_size = bundle_size * 2
            newline_count = (encoded_size - 1) // 64 if representation == "chunked_hex" else 0
            variant_size = encoded_size + newline_count
            variant_hash = content_hash(
                {
                    "representation": representation,
                    "source_content_hash": bundle_hash,
                    "source_path": bundle_path,
                    "source_size": bundle_size,
                    "variant_size": variant_size,
                }
            )
            artifacts = {
                "variant": {
                    "type": "artifact.sandbox.observability.variant.v1",
                    "path": _SIMULATED_OBSERVABILITY_VARIANT_PATH,
                    "representation": representation,
                    "source_path": bundle_path,
                    "source_content_hash": bundle_hash,
                    "source_size": bundle_size,
                    "content_hash": variant_hash,
                    "size": variant_size,
                    "equivalence_verified": True,
                    "synthetic": True,
                }
            }
            telemetry = ("sandbox.observability.variant_created",)
            limitations = base_limitations + (
                "No representation file was created; equivalence is a deterministic projection.",
            )
        elif simulation_id == "simulation.sandbox.network.loopback.v1":
            bundle = _mapping(bound_inputs.get("bundle"), "bundle")
            bundle_hash_value = bundle.get("content_hash")
            bundle_hash = bundle_hash_value if isinstance(bundle_hash_value, str) else ""
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
            bundle_hash_value = bundle.get("content_hash")
            bundle_hash = bundle_hash_value if isinstance(bundle_hash_value, str) else ""
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
            limitations=limitations,
        )


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SimulationError(f"{context} input is missing or malformed")
    return value


__all__ = ["SimulationError", "SimulationRegistry", "SimulationResult"]
