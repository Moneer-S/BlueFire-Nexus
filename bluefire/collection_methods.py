"""Exact typed bindings for reviewed bounded collection implementations."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .util import canonical_json_bytes, content_hash

COLLECTION_METHODS = {
    "sandbox.collection.records.v1": "jsonl",
    "sandbox.collection.archive.v1": "ustar",
    "sandbox.collection.atomic-gzip.v1": "gzip",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_PATH = "fixtures/transformed.jsonl"
_MAX_BYTES = 1024 * 1024


class CollectionMethodError(ValueError):
    """A collection request or result broke its exact reviewed binding."""


def _selection(action_id: str, parameters: Mapping[str, Any]) -> tuple[str, str, str]:
    if action_id not in COLLECTION_METHODS or set(parameters) - {
        "stage_variant",
        "max_collection_bytes",
    }:
        raise CollectionMethodError("collection requires a reviewed method and parameter set")
    collection_byte_limit(parameters)
    variant = parameters.get("stage_variant", "primary")
    if variant not in ("primary", "heldout"):
        raise CollectionMethodError("stage_variant must be primary or heldout")
    directory = "staged/collection" if variant == "primary" else "staged/variation"
    container = COLLECTION_METHODS[action_id]
    extension = {"ustar": "tar", "jsonl": "jsonl", "gzip": "jsonl.gz"}[container]
    path = f"{directory}/bundle.{extension}"
    return str(variant), directory, path


def collection_byte_limit(parameters: Mapping[str, Any]) -> int:
    limit = parameters.get("max_collection_bytes", _MAX_BYTES)
    if type(limit) is not int or not 1 <= limit <= _MAX_BYTES:
        raise CollectionMethodError("max_collection_bytes must be an integer from 1 to 1048576")
    return limit


def _record(bound_inputs: Mapping[str, Any]) -> Mapping[str, Any]:
    records = bound_inputs.get("records")
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], Mapping):
        raise CollectionMethodError("collection requires exactly one typed discovery record")
    record = records[0]
    if (
        record.get("type") != "artifact.sandbox.discovery.records.v1"
        or record.get("kind") != "file"
    ):
        raise CollectionMethodError("collection requires an exact discovery file artifact")
    count = record.get("record_count")
    if type(count) is not int or not 1 <= count <= 100:
        raise CollectionMethodError("collection discovery count is invalid")
    return record


def collection_request(
    action_id: str, parameters: Mapping[str, Any], bound_inputs: Mapping[str, Any]
) -> tuple[dict[str, Any], tuple[str, ...], tuple[str, ...]]:
    variant, directory, path = _selection(action_id, parameters)
    record = _record(bound_inputs)
    digest = record.get("sha256")
    if (
        record.get("path") != _SOURCE_PATH
        or not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
    ):
        raise CollectionMethodError(
            "collection requires the exact transformed fixture and SHA-256 binding"
        )
    request: dict[str, Any] = {
        "input": _SOURCE_PATH,
        "expected_sha256": digest,
        "stage_variant": variant,
    }
    if "max_collection_bytes" in parameters:
        request["max_collection_bytes"] = collection_byte_limit(parameters)
    return (
        request,
        (_SOURCE_PATH, directory),
        (path,),
    )


def collection_artifacts(
    action_id: str,
    parameters: Mapping[str, Any],
    bound_inputs: Mapping[str, Any],
    output: Mapping[str, Any],
    receipt_ids: Sequence[str],
) -> dict[str, Any]:
    params, _, paths = collection_request(action_id, parameters, bound_inputs)
    digest, size = output.get("sha256"), output.get("size")
    expected_fields = {"artifact", "container", "input_count", "source_sha256", "size", "sha256"}
    if COLLECTION_METHODS[action_id] == "gzip":
        expected_fields.add("tool")
        tool = output.get("tool")
        if (
            not isinstance(tool, Mapping)
            or set(tool) != {"executable", "sha256", "arguments", "source_test"}
            or tool.get("executable") not in ("/usr/bin/gzip", "/bin/gzip")
            or not isinstance(tool.get("sha256"), str)
            or not _SHA256.fullmatch(tool["sha256"])
            or tool.get("arguments") != ["-n", "-c"]
            or tool.get("source_test") != "cde3c2af-3485-49eb-9c1f-0ed60e9cc0af"
        ):
            raise CollectionMethodError("gzip result lacks its reviewed executable identity")
    if (
        set(output) != expected_fields
        or output.get("artifact") != paths[0]
        or output.get("container") != COLLECTION_METHODS[action_id]
        or type(output.get("input_count")) is not int
        or output["input_count"] != 1
        or output.get("source_sha256") != params["expected_sha256"]
        or not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
        or type(size) is not int
        or not 1 <= size <= collection_byte_limit(parameters)
    ):
        raise CollectionMethodError(
            "collection result differs from its exact source, method, or destination binding"
        )
    return {
        "bundle": {
            "type": "artifact.sandbox.collection.v1",
            "path": paths[0],
            "container": output["container"],
            "source_sha256": output["source_sha256"],
            "sha256": digest,
            "size": size,
            "receipt_ids": list(receipt_ids),
        }
    }


def simulate_collection(
    action_id: str, parameters: Mapping[str, Any], bound_inputs: Mapping[str, Any]
) -> dict[str, Any]:
    _, _, path = _selection(action_id, parameters)
    record = _record(bound_inputs)
    source_hash = record.get("content_hash")
    if not isinstance(source_hash, str) or not source_hash.startswith("sha256:"):
        raise CollectionMethodError("synthetic collection requires a source content hash")
    body = {
        "source_content_hash": source_hash,
        "container": COLLECTION_METHODS[action_id],
        "record_count": record["record_count"],
    }
    return {
        "bundle": {
            "type": "artifact.sandbox.collection.v1",
            "path": f"synthetic/{path}",
            "container": COLLECTION_METHODS[action_id],
            "source_content_hash": source_hash,
            "content_hash": content_hash(body),
            "size": len(canonical_json_bytes(body)),
        }
    }
