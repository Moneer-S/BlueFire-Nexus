"""Require declared observations before an Execute objective can be complete.

Execution receipts describe an attempted effect. They cannot substitute for an
independent read of the resulting file, and an explicit telemetry gap is never
a negative detection result. This evaluator does not collect host telemetry.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .collection_methods import COLLECTION_METHODS
from .evidence import EvidenceProvenance, EvidenceRecord
from .util import parse_iso8601_datetime

_FILESYSTEM_PRODUCERS = frozenset(
    {
        "sandbox-observer.v1",
        "collector.filesystem.sandbox.v1",
        "collector.collection-semantics.sandbox.v1",
    }
)


def evaluate_observation_integrity(
    records: Sequence[EvidenceRecord],
    *,
    configured_file_paths: Sequence[str] | None = None,
) -> Mapping[str, Any]:
    """Reconcile required file effects and preserve every unavailable observation.

    Managed collectors explicitly select their file paths. Their final produced
    file effect must still be observed; choosing an unrelated sensor cannot
    establish it. No additional files are read by this evaluator. Other Execute
    runs use all adapter per-action declarations retained in executed evidence. A
    scheduled observation may occur after another step, but must remain in the same
    run/profile and occur after the producing action's evidence.
    """
    gaps = [
        record.evidence_id
        for record in records
        if record.provenance is EvidenceProvenance.UNKNOWN
        or record.content.get("artifact_type") == "evidence_gap"
    ]
    executions = [
        record
        for record in records
        if record.provenance is EvidenceProvenance.EXECUTED
        and record.producer == "bluefire-rust-runner"
        and record.content.get("runner_status") in {"success", "partial"}
    ]
    file_producers = [
        record for record in executions if record.content.get("expected_observable_paths")
    ]
    final_file_paths = (
        list(file_producers[-1].content["expected_observable_paths"]) if file_producers else []
    )
    requirements: list[tuple[str, EvidenceRecord | None]] = []
    if configured_file_paths is None:
        for record in executions:
            requirements.extend(
                (path, record) for path in record.content.get("expected_observable_paths", ())
            )
    else:
        for path in dict.fromkeys((*configured_file_paths, *final_file_paths)):
            producers = [
                record
                for record in executions
                if path in record.content.get("expected_observable_paths", ())
                and isinstance(record.content.get("output"), Mapping)
                and record.content["output"].get("artifact") == path
            ]
            requirements.append((path, producers[-1] if producers else None))

    postconditions: list[dict[str, Any]] = []
    positions = {record.evidence_id: index for index, record in enumerate(records)}
    for path, execution in requirements:
        semantic_container = (
            COLLECTION_METHODS.get(execution.action_id or "") if execution else None
        )
        output = execution.content.get("output") if execution is not None else None
        expected = output if isinstance(output, Mapping) else {}
        digest = expected.get("sha256")
        digest = digest.removeprefix("sha256:") if isinstance(digest, str) else None
        size_field = (
            "byte_count"
            if execution is not None and execution.action_id == "sandbox.identity-material.seed.v1"
            else "size"
        )
        expected_size = expected.get(size_field)
        # The reviewed marker wire contract reports a digest but no byte count.
        # Its independent read still proves byte identity; retain that narrower
        # verified dimension rather than deriving or inventing a producer size.
        digest_only = (
            execution is not None
            and execution.action_id == "sandbox.restricted.persistence-marker.v1"
            and size_field not in expected
        )
        valid_identity = (
            expected.get("artifact") == path
            and isinstance(digest, str)
            and len(digest) == 64
            and all(character in "0123456789abcdef" for character in digest)
            and (digest_only or (type(expected_size) is int and expected_size >= 0))
        )
        matching: list[str] = []
        conflicting: list[str] = []
        if execution is not None and valid_identity:
            execution_index = positions[execution.evidence_id]
            next_write_index = min(
                (
                    positions[writer.evidence_id]
                    for writer in file_producers
                    if positions[writer.evidence_id] > execution_index
                    and path in writer.content["expected_observable_paths"]
                ),
                default=len(records),
            )
            # A later create-new episode after cleanup is a new postcondition,
            # not contradictory evidence about the earlier file incarnation.
            for observed in records[execution_index + 1 : next_write_index]:
                if (
                    observed.provenance is not EvidenceProvenance.OBSERVED
                    or observed.producer not in _FILESYSTEM_PRODUCERS
                    or observed.run_id != execution.run_id
                    or observed.runner_profile_id != execution.runner_profile_id
                    or observed.target_scope_ref != execution.target_scope_ref
                    or parse_iso8601_datetime(observed.timestamp)
                    < parse_iso8601_datetime(execution.timestamp)
                ):
                    continue
                content = observed.content
                if semantic_container is not None and (
                    observed.producer != "collector.collection-semantics.sandbox.v1"
                    or content.get("observation_kind") != "collection_semantics"
                ):
                    continue
                if content.get("artifact_type") == "collector_observation":
                    if content.get("observation_kind") not in {
                        "filesystem",
                        "collection_semantics",
                    }:
                        continue
                    fields = content.get("observed_fields")
                elif content.get("artifact_type") == "file_observation":
                    fields = content
                else:
                    continue
                if not isinstance(fields, Mapping) or fields.get("path") != path:
                    continue
                semantic_valid = semantic_container is None or _valid_collection_counts(
                    fields, semantic_container
                )
                if (
                    fields.get("sha256") == digest
                    and type(fields.get("size_bytes")) is int
                    and fields["size_bytes"] >= 0
                    and (digest_only or fields["size_bytes"] == expected_size)
                    and semantic_valid
                ):
                    matching.append(observed.evidence_id)
                else:
                    conflicting.append(observed.evidence_id)
        state = (
            "producer_identity_unavailable"
            if not valid_identity
            else (
                "conflicting_observation"
                if conflicting
                else "verified" if matching else "observation_unavailable"
            )
        )
        postconditions.append(
            {
                "path": path,
                "state": state,
                "execution_evidence_id": execution.evidence_id if execution else None,
                "observed_evidence_ids": sorted(matching),
                "conflicting_evidence_ids": sorted(conflicting),
                "verified_dimensions": (
                    [
                        "path",
                        "sha256",
                        *([] if digest_only else ["size_bytes"]),
                        *(
                            [
                                "container",
                                "record_count",
                                "retained_record_count",
                                "redacted_record_count",
                                "empty_record_count",
                            ]
                            if semantic_container
                            else []
                        ),
                    ]
                    if state == "verified"
                    else []
                ),
            }
        )
    satisfied = not gaps and all(row["state"] == "verified" for row in postconditions)
    return {
        "schema_version": "bluefire.observation-integrity.v1",
        "satisfied": satisfied,
        "requirement_scope": (
            "all_declared_file_effects"
            if configured_file_paths is None
            else "selected_paths_and_final_file_effect"
        ),
        "final_file_effect_paths": final_file_paths,
        "state": (
            "not_required"
            if not postconditions and not gaps
            else "verified" if satisfied else "incomplete"
        ),
        "required_file_count": len(postconditions),
        "verified_file_count": sum(row["state"] == "verified" for row in postconditions),
        "gap_evidence_ids": sorted(gaps),
        "file_postconditions": postconditions,
        "limitations": [
            "File postconditions establish independent metadata and digest observation; "
            "they do not establish host audit events or that a detector fired.",
            "Managed collection verifies selected paths and the final produced file effect; "
            "unselected intermediate effects are not independently established by this report.",
        ],
    }


def _valid_collection_counts(fields: Mapping[str, Any], container: str) -> bool:
    counts: list[Any] = [
        fields.get(name)
        for name in (
            "record_count",
            "retained_record_count",
            "redacted_record_count",
            "empty_record_count",
        )
    ]
    return bool(
        fields.get("container") == container
        and all(type(count) is int and 0 <= count <= 100 for count in counts)
        and counts[0] > 0
        and counts[0] == sum(counts[1:])
    )
