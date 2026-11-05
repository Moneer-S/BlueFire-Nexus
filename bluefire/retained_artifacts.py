"""One reviewed generated JSONL output, sealed with its original run bundle.

The reference is historical byte custody, never evidence of current source access.
Payloads stay private to storage and the authenticated native materialization task.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from .capability_resources import CapabilityContractError
from .retained_artifact_contract import (
    FIELDS as FIELDS,
)
from .retained_artifact_contract import (
    HEX_CHUNK_CHARS as HEX_CHUNK_CHARS,
)
from .retained_artifact_contract import (
    MAX_BYTES as MAX_BYTES,
)
from .retained_artifact_contract import (
    MAX_CHUNKS as MAX_CHUNKS,
)
from .retained_artifact_contract import (
    MAX_ENVELOPE_BYTES as MAX_ENVELOPE_BYTES,
)
from .retained_artifact_contract import (
    METHOD as METHOD,
)
from .retained_artifact_contract import (
    PACK as PACK,
)
from .retained_artifact_contract import (
    POLICY as POLICY,
)
from .retained_artifact_contract import (
    source_reference as source_reference,
)
from .retained_artifact_contract import (
    validate_bytes as validate_bytes,
)
from .retained_artifact_contract import (
    validate_envelope as validate_envelope,
)
from .retained_artifact_contract import (
    wire_chunks as wire_chunks,
)
from .util import canonical_json_bytes, content_hash


class PayloadUnavailable(CapabilityContractError):
    """Historical evidence is valid, but its separately retained bytes are unavailable."""


def capture(
    store, *, run_id, attempt_id, lineage_id, step, artifact, payload, evidence_id, observation_id
):
    if (
        step.action_id != POLICY["producer"]
        or artifact.get("type") != "artifact.sandbox.bundle.v1"
        or artifact.get("format") != "jsonl"
        or artifact.get("path") != "staged/bundle.jsonl"
        or not isinstance(artifact.get("receipt_ids"), list)
        or len(artifact["receipt_ids"]) != 1
        or not isinstance(artifact["receipt_ids"][0], str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact["receipt_ids"][0]) is None
    ):
        raise CapabilityContractError("only the reviewed successful staging output can be retained")
    body = {
        "run_id": run_id,
        "attempt_id": attempt_id,
        "lineage_id": lineage_id,
        "step_id": step.step_id,
        "artifact": "bundle",
        "artifact_type": artifact["type"],
        "sha256": artifact["sha256"],
        "size_bytes": artifact["size"],
    }
    reference = source_reference({**body, "source_ref": content_hash(body)})
    validate_bytes(payload, reference)
    document = {
        "schema_version": "bluefire.retained-artifacts.v1",
        "policy": POLICY,
        "artifacts": [
            {
                "source": reference,
                "producer_evidence_id": evidence_id,
                "observation_evidence_id": observation_id,
                "producer_receipt_ids": list(artifact["receipt_ids"]),
                "payload": {
                    "path": "retained/bundle.jsonl",
                    "sha256": reference["sha256"],
                    "size_bytes": reference["size_bytes"],
                    "export": "excluded",
                },
            }
        ],
    }
    if len(canonical_json_bytes(document)) + 1 > MAX_ENVELOPE_BYTES:
        raise CapabilityContractError("retained artifact envelope exceeds its reviewed byte bound")
    # One publication only. Never overwrite a previously captured output.
    if (store._run_path(run_id, must_exist=True) / "artifacts.json").exists():
        raise CapabilityContractError("attempt retention count is exhausted")
    store.write_retained_payload(run_id, payload)
    store.write_json(run_id, "artifacts.json", document)
    store.append_event(
        run_id, "artifact.retained", {"source": reference, "disposition": POLICY["disposition"]}
    )
    return reference


def resolve_metadata(store, reference):
    reference = source_reference(reference)
    run = store.get_run(reference["run_id"], require_finalized=True)
    if "artifacts.json" not in run["manifest"]["files"]:
        raise CapabilityContractError(
            "source bytes are unavailable; historical runs are never regenerated"
        )
    if (
        run["manifest"]["files"]["artifacts.json"].get("size_bytes", MAX_ENVELOPE_BYTES + 1)
        > MAX_ENVELOPE_BYTES
    ):
        raise CapabilityContractError("retained artifact envelope exceeds its reviewed bound")
    document = store.read_json(reference["run_id"], "artifacts.json", _max_bytes=MAX_ENVELOPE_BYTES)
    entry = validate_envelope(document)
    if entry["source"] != reference:
        raise CapabilityContractError("retained artifact selection changed")
    rows = [row for row in run.get("steps", []) if row.get("step_id") == reference["step_id"]]
    if len(rows) != 1:
        raise CapabilityContractError("retained producer step is unavailable")
    row = rows[0]
    artifact = row.get("artifacts", {}).get("bundle", {})
    from .evidence import EvidenceRecord

    records = [
        EvidenceRecord.from_mapping(record).to_dict()
        for record in run.get("evidence", {}).get("records", [])
    ]
    if (
        row.get("status") != "success"
        or row.get("action_id") != POLICY["producer"]
        or artifact.get("sha256") != reference["sha256"]
        or artifact.get("size") != reference["size_bytes"]
        or artifact.get("type") != reference["artifact_type"]
        or artifact.get("format") != "jsonl"
        or artifact.get("receipt_ids") != entry["producer_receipt_ids"]
        or entry["producer_evidence_id"] not in row.get("evidence_ids", [])
        or not any(
            record.get("evidence_id") == entry["producer_evidence_id"]
            and record.get("provenance") == "executed"
            and record.get("producer") == "bluefire-rust-runner"
            and record.get("action_id") == POLICY["producer"]
            and record.get("step_id") == reference["step_id"]
            and record.get("content", {}).get("request_hash") == row.get("request_hash")
            and record.get("content", {}).get("runner_status") == "success"
            for record in records
        )
        or not any(
            record.get("evidence_id") == entry["observation_evidence_id"]
            and record.get("provenance") == "observed"
            and record.get("producer") == "sandbox-observer.v1"
            and record.get("step_id") == reference["step_id"]
            and entry["producer_evidence_id"] in record.get("parent_evidence_ids", [])
            and record.get("content", {}).get("path") == "staged/bundle.jsonl"
            and record.get("content", {}).get("sha256") == reference["sha256"]
            and record.get("content", {}).get("size_bytes") == reference["size_bytes"]
            for record in records
        )
    ):
        raise CapabilityContractError("retained producer evidence does not match the source")
    return run


def resolve(store, reference):
    resolve_metadata(store, reference)
    try:
        payload = store.read_retained_payload(reference["run_id"])
        validate_bytes(payload, reference)
    except (ValueError, OSError) as exc:
        raise PayloadUnavailable(
            "retained payload is unavailable; historical evidence remains separate"
        ) from exc
    return payload


def historical_sources(jobs, grant, *, owner_id):
    """Validate sealed custody metadata independently of current payload availability."""
    if grant.get("pack") != PACK:
        return []
    owner = jobs.store.get_job(owner_id)
    if (
        owner.get("kind") != "composition.objective"
        or owner.get("state") != "completed"
        or owner.get("request", {}).get("grant_id") != grant["grant_id"]
        or owner.get("request", {}).get("grant_digest") != grant["grant_digest"]
        or owner.get("progress", {}).get("admission") != {"accepted": True, "problem": None}
    ):
        raise CapabilityContractError("retained sources require the exact admitted saved objective")
    view = jobs.store.get_capability_grant(grant["grant_id"], now_ms=jobs.clock())
    with jobs.store._connection() as connection:
        rows = connection.execute(
            "SELECT attempt_id FROM capability_attempts WHERE lineage_id=? ORDER BY rowid LIMIT 33",
            (view["lineage_id"],),
        ).fetchall()
    if len(rows) > grant["limits"]["max_attempts"]:
        raise CapabilityContractError(
            "source history exceeds the reviewed cumulative attempt bound"
        )
    result = []
    for row in rows:
        attempt = jobs.store.get_capability_attempt(row["attempt_id"])
        if attempt["state"] != "settled":
            continue
        lease = attempt["lease"]
        child = jobs.store.get_job(lease["job_id"])
        marker = child.get("request", {}).get("composition_attempt", {})
        if (
            child.get("kind") != "composition.attempt"
            or marker.get("parent_job_id") != owner_id
            or any(
                marker.get(key) != lease[key]
                for key in ("attempt_id", "run_id", "grant_id", "grant_digest")
            )
        ):
            continue
        source_grant = jobs.store.get_capability_grant(lease["grant_id"], now_ms=jobs.clock())[
            "document"
        ]
        if source_grant.get("pack") != PACK or source_grant["environment"] != grant["environment"]:
            continue
        capture = child.get("progress", {}).get("retained_artifact_capture")
        if capture is None:
            continue
        try:
            run = jobs.service.detection_lab.run_store.get_run(
                lease["run_id"], require_finalized=True
            )
            if "artifacts.json" not in run["manifest"]["files"]:
                raise CapabilityContractError(
                    "captured source metadata is missing from its sealed run"
                )
            if (
                run["manifest"]["files"]["artifacts.json"].get("size_bytes", MAX_ENVELOPE_BYTES + 1)
                > MAX_ENVELOPE_BYTES
            ):
                raise CapabilityContractError("captured source metadata exceeds its reviewed bound")
            document = jobs.service.detection_lab.run_store.read_json(
                lease["run_id"], "artifacts.json", _max_bytes=MAX_ENVELOPE_BYTES
            )
            reference = source_reference(validate_envelope(document)["source"])
            if (
                not isinstance(capture, Mapping)
                or set(capture)
                != {
                    "schema_version",
                    "source",
                    "producer_record_hash",
                    "observation_record_hash",
                    "capture_digest",
                }
                or capture["schema_version"] != "bluefire.retained-artifact-capture.v1"
                or capture["source"] != reference
                or capture["capture_digest"]
                != content_hash(
                    {key: value for key, value in capture.items() if key != "capture_digest"}
                )
            ):
                raise CapabilityContractError("trusted source capture binding changed")
            producer_records = run.get("evidence", {}).get("records", [])
            if not all(
                any(record.get("record_hash") == capture[key] for record in producer_records)
                for key in ("producer_record_hash", "observation_record_hash")
            ):
                raise CapabilityContractError("trusted source capture evidence changed")
            from .runner_contracts import _verified_grant_attempt

            claim = _verified_grant_attempt(
                attempt["claim"]["document"],
                expected_document_digest=attempt["claim"]["document_digest"],
            ).to_dict()
            if (
                reference["lineage_id"] != view["lineage_id"]
                or reference["attempt_id"] != lease["attempt_id"]
                or reference["run_id"] != lease["run_id"]
                or any(
                    claim[key] != lease[key]
                    for key in (
                        "attempt_id",
                        "run_id",
                        "grant_id",
                        "grant_digest",
                        "plan_digest",
                        "compiled_digest",
                        "lease_digest",
                        "native_envelope_digest",
                    )
                )
                or run.get("policy", {}).get("grant_attempt") != claim
                or run.get("mode") != "execute"
                or run.get("plan", {}).get("autonomy") != "off"
                or content_hash(run["plan"]) != lease["plan_digest"]
                or run["scenario"] != attempt["compiled"]["scenario"]
            ):
                raise CapabilityContractError("source metadata differs from its claimed attempt")
            producers = [
                item for item in run.get("steps", []) if item.get("step_id") == reference["step_id"]
            ]
            if len(producers) != 1 or not any(
                task["step_id"] == reference["step_id"]
                and task["task_id"] == producers[0].get("runner_task_id")
                and task["request_hash"] == producers[0].get("request_hash")
                for task in attempt["tasks"]
            ):
                raise CapabilityContractError(
                    "source producer differs from its registered native task"
                )
            resolve_metadata(jobs.service.detection_lab.run_store, reference)
            result.append(reference)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            raise CapabilityContractError(
                "retained historical source evidence failed integrity validation"
            ) from exc
    return result


def available_sources(jobs, grant, *, owner_id):
    result = []
    for reference in historical_sources(jobs, grant, owner_id=owner_id):
        try:
            resolve(jobs.service.detection_lab.run_store, reference)
        except PayloadUnavailable:
            continue
        result.append(reference)
    return result


def resolve_for_grant(jobs, grant, source_ref, *, owner_id):
    matches = [
        row
        for row in available_sources(jobs, grant, owner_id=owner_id)
        if row["source_ref"] == source_ref
    ]
    if len(matches) != 1:
        raise CapabilityContractError(
            "retained source is unavailable or outside this authorized objective lineage"
        )
    return matches[0]


def receiver_terminal_absent(child) -> bool:
    """Only the receiver owner's explicit no-terminal shape permits unknown fallback."""
    observation = child.get("progress", {}).get("receiver_observation")
    return (
        isinstance(observation, Mapping)
        and set(observation)
        in (
            {"schema_version", "state", "reason"},
            {"schema_version", "state", "reason", "launch_id"},
        )
        and observation.get("schema_version") == "bluefire.owned-receiver-observation.v1"
        and observation.get("state") == "insufficient_evidence"
        and isinstance(observation.get("reason"), str)
    )


def prior_failure(jobs, grant, attempt, child, *, owner_id):
    """A sealed successful output and a later failed task, with separate cleanup."""
    from .detection_evaluations import _source, _source_binding
    from .product_store_errors import ProductStoreError

    run, records, observed = _source(jobs.service.detection_lab, attempt["lease"]["run_id"])
    from .runner_contracts import _verified_grant_attempt

    claim = _verified_grant_attempt(
        attempt["claim"]["document"], expected_document_digest=attempt["claim"]["document_digest"]
    ).to_dict()
    if (
        attempt["state"] != "settled"
        or run.get("policy", {}).get("grant_attempt") != claim
        or child.get("request", {}).get("composition_attempt", {}).get("parent_job_id") != owner_id
        or any(
            claim[key] != attempt["lease"][key]
            for key in (
                "attempt_id",
                "run_id",
                "grant_id",
                "grant_digest",
                "plan_digest",
                "compiled_digest",
                "lease_digest",
                "native_envelope_digest",
            )
        )
        or content_hash(run["plan"]) != attempt["lease"]["plan_digest"]
        or run["scenario"] != attempt["compiled"]["scenario"]
        or run.get("mode") != "execute"
        or run["plan"].get("autonomy") != "off"
    ):
        raise ProductStoreError("The prior failed run differs from its exact claimed attempt.")
    rows = run.get("steps", [])
    candidates = []
    for reference in historical_sources(jobs, grant, owner_id=owner_id):
        for index, row in enumerate(rows):
            workspace = row.get("artifacts", {}).get("workspace", {})
            original = (
                reference["attempt_id"] == attempt["lease"]["attempt_id"]
                and row.get("step_id") == reference["step_id"]
                and row.get("action_id") == POLICY["producer"]
            )
            materialized = (
                row.get("action_id") == METHOD
                and workspace.get("historical_source") == reference
                and attempt["compiled"].get("retained_sources", {}).get(row.get("step_id"))
                == reference
                and workspace.get("historical_source_ref") == reference["source_ref"]
                and any(
                    step.get("id") == row.get("step_id")
                    and step.get("behavior_id") == METHOD
                    and step.get("parameters") == {"source_ref": reference["source_ref"]}
                    for step in attempt["compiled"]["scenario"].get("steps", [])
                )
                and workspace.get("sha256") == reference["sha256"]
                and workspace.get("size") == reference["size_bytes"]
                and workspace.get("receipt_ids")
                and any(
                    record.step_id == row.get("step_id")
                    and record.action_id == METHOD
                    and record.provenance.value == "executed"
                    and record.content.get("runner_status") == "success"
                    and record.content.get("request_hash") == row.get("request_hash")
                    and isinstance(record.content.get("output"), Mapping)
                    and record.content["output"].get("source_ref") == reference["source_ref"]
                    and record.content["output"].get("sha256") == reference["sha256"]
                    and record.content["output"].get("size") == reference["size_bytes"]
                    for record in records
                )
                and any(
                    task["step_id"] == row.get("step_id")
                    and task["task_id"] == row.get("runner_task_id")
                    and task["request_hash"] == row.get("request_hash")
                    for task in attempt["tasks"]
                )
            )
            if row.get("status") == "success" and (original or materialized):
                candidates.append((reference, index))
    if not candidates:
        raise ProductStoreError(
            "The settled prior attempt has no verified retained output or materialization."
        )
    # A later successful staging node may itself have a new retained output.
    # Prefer that last producer while keeping every original source immutable.
    reference, index = max(candidates, key=lambda candidate: candidate[1])
    failures = [
        row
        for row in rows[index + 1 :]
        if row.get("action_id") != "sandbox.cleanup.v1"
        and row.get("status") in {"blocked", "failed", "partial"}
        and any(
            task["step_id"] == row.get("step_id")
            and task["request_hash"] == row.get("request_hash")
            and task["task_id"] == row.get("runner_task_id")
            for task in attempt["tasks"]
        )
    ]
    if (
        not failures
        or run.get("cleanup", {}).get("success") is not True
        or run["cleanup"].get("outstanding_receipt_count") != 0
        or child.get("progress", {}).get("receiver_closed") is not True
    ):
        raise ProductStoreError(
            "Retained continuation requires a later failed task and verified prior cleanup."
        )
    failure = failures[0]
    return {
        "run_id": run["run_id"],
        "source_binding": _source_binding(run, records, observed),
        "retained_artifact_result": {
            "source": reference,
            "prior_run_id": run["run_id"],
            "later_failure": {"step_id": failure["step_id"], "outcome": failure["status"]},
            "receiver_decision": "unknown",
        },
        "cleanup": {"run": "complete", "receiver": "verified_closed"},
    }


def execution_callbacks(jobs, *, marker, compiled, grant, current, lease, check):
    """Build the two retained-output hooks on the existing claimed attempt."""
    from .capability_packs import grant_pack
    from .product_store_errors import ProductStoreError

    if grant_pack(grant) != PACK:
        return None, None
    attempt_id = marker["attempt_id"]

    def materialize_retained(step):
        check()
        expected = compiled.get("retained_sources", {}).get(step.step_id)
        if expected is None or grant_pack(grant) != PACK:
            raise ProductStoreError(
                "The exact materialization node was not compiled for this grant."
            )
        source = resolve_for_grant(
            jobs, grant, step.parameters["source_ref"], owner_id=marker["parent_job_id"]
        )
        if source != expected:
            raise ProductStoreError("The exact compiled retained source changed.")
        payload = resolve(jobs.service.detection_lab.run_store, source)
        check()
        return {"source": source, "payload": payload}

    def retain_output(step, artifact, observer, executed_record):
        check()
        evidence_id = executed_record.evidence_id
        captured = []
        observed = observer.observe_file(
            relative_path="staged/bundle.jsonl",
            run_id=lease["run_id"],
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action_id=step.action_id,
            runner_profile_id=current["profile"].id,
            parent_evidence_ids=(evidence_id,),
            _validated_content_sink=captured.append,
            _max_content_bytes=MAX_BYTES,
        )
        if (
            observed.content["sha256"] != artifact["sha256"]
            or observed.content["size_bytes"] != artifact["size"]
        ):
            raise ProductStoreError(
                "Pinned retention observation differs from the successful producer."
            )
        source = capture(
            jobs.service.detection_lab.run_store,
            run_id=lease["run_id"],
            attempt_id=attempt_id,
            lineage_id=lease["lineage_id"],
            step=step,
            artifact=artifact,
            payload=captured[0],
            evidence_id=evidence_id,
            observation_id=observed.evidence_id,
        )
        if (
            jobs.store.get_job(lease["job_id"])["progress"].get("retained_artifact_capture")
            is not None
        ):
            raise ProductStoreError("The attempt already has a retained capture receipt.")
        receipt = {
            "schema_version": "bluefire.retained-artifact-capture.v1",
            "source": source,
            "producer_record_hash": executed_record.record_hash,
            "observation_record_hash": observed.record_hash,
        }
        jobs._publish(
            lease["job_id"],
            {"retained_artifact_capture": {**receipt, "capture_digest": content_hash(receipt)}},
        )
        return observed, source

    return materialize_retained, retain_output


def publish_continuation(jobs, marker, job_id):
    """Cache a historical continuation summary after separate cleanup settles."""
    from .capability_packs import grant_pack
    from .product_store_errors import ProductStoreError

    grant = jobs.store.get_capability_grant(marker["grant_id"], now_ms=jobs.clock())["document"]
    if grant_pack(grant) == PACK:
        try:
            prior = prior_failure(
                jobs,
                grant,
                jobs.store.get_capability_attempt(marker["attempt_id"]),
                jobs.store.get_job(job_id),
                owner_id=marker["parent_job_id"],
            )
        except (ProductStoreError, KeyError, ValueError):
            pass
        else:
            continuation = {
                "schema_version": "bluefire.retained-continuation.v1",
                **prior["retained_artifact_result"],
                "cleanup": prior["cleanup"],
            }
            jobs._publish(
                job_id,
                {
                    "retained_continuation": {
                        **continuation,
                        "continuation_digest": content_hash(continuation),
                    }
                },
            )
