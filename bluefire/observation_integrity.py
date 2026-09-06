"""Require declared observations before an Execute objective can be complete.

Execution receipts describe an attempted effect. They cannot substitute for an
independent read of the resulting file, and an explicit telemetry gap is never
a negative detection result. This evaluator does not collect host telemetry.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .evidence import EvidenceProvenance, EvidenceRecord
from .util import parse_iso8601_datetime

_FILESYSTEM_PRODUCERS = frozenset({"sandbox-observer.v1", "collector.filesystem.sandbox.v1"})


def evaluate_observation_integrity(
    records: Sequence[EvidenceRecord],
    *,
    configured_file_paths: Sequence[str] = (),
) -> Mapping[str, Any]:
    """Reconcile required file effects and preserve every unavailable observation.

    Managed collectors explicitly select their file paths. Other Execute runs use
    the adapter's per-action declarations, retained in the executed evidence. A
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
    requirements: list[tuple[str, EvidenceRecord | None]] = []
    for record in executions:
        requirements.extend(
            (path, record) for path in record.content.get("expected_observable_paths", ())
        )
    for path in configured_file_paths:
        producers = [
            record
            for record in executions
            if isinstance(record.content.get("output"), Mapping)
            and record.content["output"].get("artifact") == path
        ]
        requirements.append((path, producers[-1] if producers else None))

    postconditions: list[dict[str, Any]] = []
    for path, execution in requirements:
        output = execution.content.get("output") if execution is not None else None
        expected = output if isinstance(output, Mapping) else {}
        valid_identity = (
            expected.get("artifact") == path
            and isinstance(expected.get("sha256"), str)
            and len(expected["sha256"]) == 64
            and all(character in "0123456789abcdef" for character in expected["sha256"])
            and type(expected.get("size")) is int
            and expected["size"] >= 0
        )
        matching: list[str] = []
        conflicting: list[str] = []
        if execution is not None and valid_identity:
            for observed in records:
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
                if content.get("artifact_type") == "collector_observation":
                    if content.get("observation_kind") != "filesystem":
                        continue
                    fields = content.get("observed_fields")
                elif content.get("artifact_type") == "file_observation":
                    fields = content
                else:
                    continue
                if not isinstance(fields, Mapping) or fields.get("path") != path:
                    continue
                if (
                    fields.get("sha256") == expected["sha256"]
                    and type(fields.get("size_bytes")) is int
                    and fields["size_bytes"] == expected["size"]
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
            }
        )
    satisfied = not gaps and all(row["state"] == "verified" for row in postconditions)
    return {
        "schema_version": "bluefire.observation-integrity.v1",
        "satisfied": satisfied,
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
            "they do not establish host audit events or that a detector fired."
        ],
    }
