"""Exact producer-byte verification for the collector acceptance journey."""

from __future__ import annotations

from typing import Any, Mapping

from .collector_gate_evidence import (
    _is_sha256,
    _one_observation,
    _require,
    _run_steps,
    _validate_collection_lineage,
)
from .collectors import CollectionSession, FilesystemCollector, filesystem_observation_key
from .evidence import EvidenceProvenance, EvidenceRecord


def _validate_filesystem_binding(
    run: Mapping[str, Any],
    records: tuple[EvidenceRecord, ...],
    session: CollectionSession,
    predicted_fields: Mapping[str, Any] | None = None,
) -> None:
    record = _one_observation(
        session, FilesystemCollector.descriptor.id, path="staged/bundle.jsonl"
    )
    records_by_id = {item.evidence_id: item for item in records}
    steps = _run_steps(run)
    _validate_collection_lineage(record, records_by_id, steps)

    stage = steps.get("stage_evidence")
    export = steps.get("preserve_approved_copy")
    export_completed = isinstance(export, Mapping) and export.get("status") == "success"
    eligible_paths = (
        "fixtures/input.jsonl",
        "fixtures/transformed.jsonl",
        "staged/bundle.jsonl",
        "exports/ephemeral/bundle.bin",
    )
    expected_paths = {
        path
        for item in records
        if item.provenance is EvidenceProvenance.EXECUTED
        and item.producer == "bluefire-rust-runner"
        and item.content.get("runner_status") in {"success", "partial"}
        for path in item.content.get("expected_observable_paths", ())
    }
    all_filesystem = session.results[FilesystemCollector.descriptor.id].records
    _require(
        len(all_filesystem) == len(expected_paths)
        and all(item.provenance is EvidenceProvenance.OBSERVED for item in all_filesystem)
        and {item.content.get("path") for item in all_filesystem} == set(expected_paths),
        "GATE-05 filesystem observations do not cover the exact staged and final file effects",
    )
    for file_record in all_filesystem:
        file_parent, _file_step = _validate_collection_lineage(file_record, records_by_id, steps)
        file_output = file_parent.content.get("output")
        file_path = file_record.content.get("path")
        _require(
            file_path in eligible_paths
            and file_path in file_parent.content.get("expected_observable_paths", ())
            and isinstance(file_output, Mapping)
            and file_output.get("artifact") == file_path
            and _is_sha256(file_output.get("sha256"))
            and type(file_output.get("size")) is int
            and file_record.content.get("observed_fields")
            == {
                "path": file_path,
                "sha256": file_output.get("sha256"),
                "size_bytes": file_output.get("size"),
            }
            and file_record.content.get("sha256") == file_output.get("sha256")
            and file_record.content.get("size_bytes") == file_output.get("size"),
            "GATE-05 filesystem observation is not bound to its actual producer bytes",
        )
    artifacts = stage.get("artifacts") if isinstance(stage, Mapping) else None
    bundle = artifacts.get("bundle") if isinstance(artifacts, Mapping) else None
    path = bundle.get("path") if isinstance(bundle, Mapping) else None
    digest = bundle.get("sha256") if isinstance(bundle, Mapping) else None
    size = bundle.get("size") if isinstance(bundle, Mapping) else None
    observed_fields = record.content.get("observed_fields")
    expected_fields = {"path": path, "size_bytes": size, "sha256": digest}
    observation_key = filesystem_observation_key(path) if isinstance(path, str) else None
    settings_row = session.settings.collectors.get(FilesystemCollector.descriptor.id)
    settings = settings_row.get("settings") if isinstance(settings_row, Mapping) else None
    configured_paths = settings.get("paths") if isinstance(settings, Mapping) else None
    predicted = (
        predicted_fields.get(observation_key)
        if isinstance(predicted_fields, Mapping) and isinstance(observation_key, str)
        else None
    )
    _require(
        (
            isinstance(stage, Mapping)
            and stage.get("status") == "success"
            and stage.get("runner_status") == "success"
            and isinstance(bundle, Mapping)
            and bundle.get("type") == "artifact.sandbox.bundle.v1"
            and bundle.get("format") == "jsonl"
            and isinstance(path, str)
            and path == "staged/bundle.jsonl"
            and _is_sha256(digest)
            and isinstance(size, int)
            and not isinstance(size, bool)
            and size > 0
            and isinstance(settings_row, Mapping)
            and settings_row.get("enabled") is True
            and isinstance(settings, Mapping)
            and set(settings) == {"schedule", "paths"}
            and settings.get("schedule") == "after_each_producer"
            and record.step_id == "stage_evidence"
            and tuple(configured_paths) == eligible_paths
            if isinstance(configured_paths, (list, tuple))
            else False
        ),
        "GATE-05 filesystem runtime is not bound to the real staged bundle",
    )
    _require(
        record.content.get("artifact_type") == "collector_observation"
        and record.content.get("observation_kind") == "filesystem"
        and record.content.get("observation_key") == observation_key
        and record.content.get("collector_id") == FilesystemCollector.descriptor.id
        and record.content.get("mechanism") == "independent-file-handle-read"
        and observed_fields == expected_fields
        and record.content.get("path") == path
        and record.content.get("size_bytes") == size
        and record.content.get("sha256") == digest
        and isinstance(record.content.get("modified_ns"), int)
        and not isinstance(record.content.get("modified_ns"), bool)
        and int(record.content["modified_ns"]) > 0
        and set(record.content)
        == {
            "artifact_type",
            "collector_id",
            "mechanism",
            "modified_ns",
            "observation_key",
            "observation_kind",
            "observed_fields",
            "path",
            "sha256",
            "size_bytes",
        }
        and record.environment
        == {
            "environment_type": "disposable",
            "collector_id": FilesystemCollector.descriptor.id,
            "collector_version": FilesystemCollector.descriptor.version,
        }
        and (predicted_fields is None or predicted == expected_fields),
        "GATE-05 filesystem observation does not match the real staged bundle",
    )
    if export_completed:
        exported = _one_observation(
            session, FilesystemCollector.descriptor.id, path="exports/ephemeral/bundle.bin"
        )
        parent, _ = _validate_collection_lineage(exported, records_by_id, steps)
        output = parent.content.get("output")
        export_fields = {**expected_fields, "path": "exports/ephemeral/bundle.bin"}
        _require(
            isinstance(output, Mapping)
            and output.get("artifact") == "exports/ephemeral/bundle.bin"
            and output.get("source") == path
            and output.get("sha256") == digest
            and output.get("size") == size
            and exported.environment == record.environment
            and exported.content
            == {
                **record.content,
                **export_fields,
                "observed_fields": export_fields,
                "observation_key": filesystem_observation_key("exports/ephemeral/bundle.bin"),
                "modified_ns": exported.content.get("modified_ns"),
            }
            and type(exported.content.get("modified_ns")) is int
            and exported.content["modified_ns"] > 0,
            "GATE-05 final export observation is not bound to the actual exported bundle",
        )
