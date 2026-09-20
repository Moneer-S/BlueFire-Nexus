"""Reviewed metadata for the fixed Linux GNU gzip collection adapter.

This module declares a typed contract only. It does not install, locate,
invoke, or dispatch GNU gzip.
"""

from __future__ import annotations

from typing import Any, Mapping

from .contracts import ToolAdapterContract

ADAPTER_ID = "sandbox.collection.atomic-gzip.v1"
TOOL_ID = "gnu.gzip.v1"
BEHAVIOR_ID = ADAPTER_ID
VERSION = "1.1.0"
SOURCE_REFERENCE = (
    "https://github.com/redcanaryco/atomic-red-team/blob/"
    "388942adbd9641f4dfdcf079d7efe9a75ec0ac43/"
    "atomics/T1560.001/T1560.001.yaml"
)
SOURCE_DIGEST = "sha256:681f0727810cc1fa1d2032f818d0cdb5b02dd058ed85416658ee26437773e681"
TEST_GUID = "cde3c2af-3485-49eb-9c1f-0ed60e9cc0af"
FIXED_ARGUMENTS = ("-n", "-c")


def _document() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.tool-adapter.v1",
        "adapter_id": ADAPTER_ID,
        "adapter_version": VERSION,
        "tool_id": TOOL_ID,
        "source": {
            "project": "Atomic Red Team",
            "reference": SOURCE_REFERENCE,
            "revision": "388942adbd9641f4dfdcf079d7efe9a75ec0ac43",
            "content_digest": SOURCE_DIGEST,
            "license": "MIT",
        },
        "action_id": ADAPTER_ID,
        "action_version": VERSION,
        "behavior_id": BEHAVIOR_ID,
        "implementation_id": "bluefire.adapter.collection-atomic-gzip.v1",
        "implementation_version": VERSION,
        "compatibility": {
            "platforms": ["linux"],
            "architectures": ["x86_64", "aarch64"],
            "target_type": "owned_endpoint",
            "prerequisite_ids": [
                "sandbox.collection.atomic-gzip.installation.v1",
                "sandbox.collection.atomic-gzip.observer.v1",
            ],
        },
        "parameters": [
            {
                "name": "stage_variant",
                "type": "string",
                "default": "primary",
                "enum": ["primary", "heldout"],
            },
            {
                "name": "max_collection_bytes",
                "type": "integer",
                "default": 1_048_576,
                "minimum": 1,
                "maximum": 1_048_576,
            },
        ],
        "supervision": {
            "invocation_id": "sandbox.collection.atomic-gzip.fixed-invocation.v1",
            "installation_binding": "verified-version-and-digest",
            "network": "none",
            "privilege": "current-user",
            "working_directory": "private-adapter-workspace",
            "environment": "adapter-allowlist",
            "cancellation": "terminate-owned-process-tree",
            "filesystem": "receipt-owned-workspace",
            "cleanup_action_id": "sandbox.cleanup.v1",
        },
        "limits": {
            "timeout_ms": 5_000,
            "max_input_bytes": 1 * 1024 * 1024,
            "max_output_bytes": 1 * 1024 * 1024,
            "max_diagnostic_bytes": 8_192,
            "max_artifacts": 1,
            "max_artifact_bytes": 1 * 1024 * 1024,
            "max_processes": 1,
            "max_attempts": 1,
        },
        "result": {
            "parser_id": "sandbox.collection.atomic-gzip.parser.v1",
            "artifact_types": ["artifact.sandbox.collection.v1"],
            "observation_schema": "observation.collection.gzip.v1",
        },
    }


CONTRACT = ToolAdapterContract.from_mapping(_document())


def contract() -> ToolAdapterContract:
    return CONTRACT


def normalize_parameters(values: Mapping[str, Any]) -> Mapping[str, Any]:
    return CONTRACT.validate_parameters(values)


__all__ = [
    "ADAPTER_ID",
    "BEHAVIOR_ID",
    "CONTRACT",
    "FIXED_ARGUMENTS",
    "SOURCE_DIGEST",
    "TEST_GUID",
    "TOOL_ID",
    "VERSION",
    "contract",
    "normalize_parameters",
]
