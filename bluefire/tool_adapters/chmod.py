"""Reviewed metadata for the fixed Linux GNU chmod permission adapter.

This module declares a typed contract only.  It does not install, locate,
invoke, or dispatch GNU chmod, and its logical inputs contain no path or
command controls.
"""

from __future__ import annotations

from typing import Any, Mapping

from .contracts import ToolAdapterContract

ADAPTER_ID = "sandbox.permission.chmod.v1"
TOOL_ID = "gnu.coreutils.chmod.v1"
BEHAVIOR_ID = "sandbox.permission.relax.v1"
VERSION = "1.0.0"
SOURCE_REFERENCE = (
    "https://github.com/redcanaryco/atomic-red-team/blob/"
    "6132b92779873cb0d05bef07ba0a480d47eb1cc8/"
    "atomics/T1222.002/T1222.002.yaml"
)
SOURCE_DIGEST = "sha256:76ea316186fe0c7f1d7bdaa9b29c92684eb7f63e28ba14834f50b9bd4fcc2049"
TEST_GUID = "34ca1464-de9d-40c6-8c77-690adf36a135"
FIXED_ARGUMENTS = ("<mode>", "--", "/proc/self/fd/<held-file>")


def _document() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.tool-adapter.v1",
        "adapter_id": ADAPTER_ID,
        "adapter_version": VERSION,
        "tool_id": TOOL_ID,
        "source": {
            "project": "Atomic Red Team",
            "reference": SOURCE_REFERENCE,
            "revision": "6132b92779873cb0d05bef07ba0a480d47eb1cc8",
            "content_digest": SOURCE_DIGEST,
            "license": "MIT",
        },
        "action_id": ADAPTER_ID,
        "action_version": VERSION,
        "behavior_id": BEHAVIOR_ID,
        "implementation_id": "bluefire.adapter.permission-chmod.v1",
        "implementation_version": VERSION,
        "compatibility": {
            "platforms": ["linux"],
            "architectures": ["x86_64", "aarch64"],
            "target_type": "owned_endpoint",
            "prerequisite_ids": [
                "sandbox.permission.chmod.installation.v1",
                "sandbox.permission.chmod.observer.v1",
            ],
        },
        "parameters": [
            {
                "name": "mode",
                "type": "string",
                "required": True,
                "enum": ["0600", "0640", "0660", "0666"],
            },
        ],
        "supervision": {
            "invocation_id": "sandbox.permission.chmod.fixed-invocation.v1",
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
            "max_input_bytes": 64 * 1024 * 1024,
            "max_output_bytes": 8_192,
            "max_diagnostic_bytes": 8_192,
            "max_artifacts": 2,
            "max_artifact_bytes": 64 * 1024 * 1024,
            "max_processes": 1,
            "max_attempts": 1,
        },
        "result": {
            "parser_id": "sandbox.permission.chmod.parser.v1",
            "artifact_types": ["artifact.permission.mode.v1"],
            "observation_schema": "observation.permission.mode.v1",
        },
    }


CONTRACT = ToolAdapterContract.from_mapping(_document())


def contract() -> ToolAdapterContract:
    """Return the immutable reviewed contract snapshot."""

    return CONTRACT


def normalize_parameters(values: Mapping[str, Any]) -> Mapping[str, Any]:
    """Normalize typed fixture/receipt/mode choices without authorizing effects."""

    return CONTRACT.validate_parameters(values)


__all__ = [
    "ADAPTER_ID",
    "BEHAVIOR_ID",
    "CONTRACT",
    "FIXED_ARGUMENTS",
    "SOURCE_DIGEST",
    "TEST_GUID",
    "TOOL_ID",
    "contract",
    "normalize_parameters",
]
