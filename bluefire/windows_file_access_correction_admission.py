"""Closed correction bindings, separate from protected paired setup authority.

These pure contracts prove consistency only. Concrete observation, a fresh
review and the original durable claim remain separate dispatch requirements.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from . import _windows_file_access_native_contract as wire
from . import windows_file_access_admission as common
from . import windows_file_access_pair_admission as pair
from .execution_contracts import execution_task_identity
from .util import content_hash

BINDING_SCHEMA = "bluefire.windows-file-access-correction-binding.v1"
CONTEXT_SCHEMA = "bluefire.windows-file-access-correction-context.v1"
PREPARATION_SCHEMA = "bluefire.windows-file-access-correction-preparation.v1"
CONTROL_SCHEMA = "bluefire.windows-file-access-control-record.v2"
OPERATION_MS = 10000
_BINDING_KEYS = (
    "schema_version operation_job_id control_owner_id prior_control_digest baseline_digest "
    "enrollment_digest protected_receipt_digest generation control_revision "
    "previous_descriptor_sha256 target_resource issued_at_ms expires_at_ms"
)


def _profile(receipt: dict) -> dict:
    profile = {
        **receipt["private_profile"],
        "allowed_actions": [wire._CORRECTION.action],
        "capabilities": [wire._CORRECTION.capability],
        "policy_digest": "",
    }
    profile["policy_digest"] = content_hash(profile)
    return profile


def correction_profile(checked: pair.VerifiedWindowsPairSetup) -> dict:
    """Derive a narrower operation profile without rewriting protected setup."""
    return _profile(pair.checked_provenance(checked)[1])


def correction_host(checked: pair.VerifiedWindowsPairSetup) -> dict:
    record, receipt = pair.checked_provenance(checked)
    return {**record["host"], "profile_digest": _profile(receipt)["policy_digest"]}


def _binding(value: Any, record: dict, receipt: dict) -> dict:
    row = wire._document(value)
    wire._exact(row, _BINDING_KEYS)
    wire._require(row["schema_version"] == BINDING_SCHEMA)
    job = row["operation_job_id"]
    wire._require(type(job) is str and job.startswith("job-"))
    wire._hex(job[4:], 32)
    for key in (
        "prior_control_digest",
        "baseline_digest",
        "enrollment_digest",
        "protected_receipt_digest",
        "previous_descriptor_sha256",
    ):
        wire._digest(row[key])
    wire._int(row["control_revision"], 3, 2**31 - 1)
    issued = wire._int(row["issued_at_ms"], 1, 2**63 - 1 - OPERATION_MS)
    expires = wire._int(row["expires_at_ms"], issued + 1, issued + OPERATION_MS)
    wire._require(
        row["control_owner_id"] == common._control_id_for(record, common._PAIR_SETUP)
        and row["enrollment_digest"] == content_hash(record)
        and row["protected_receipt_digest"] == content_hash(receipt)
        and row["generation"] == record["generation"]
        and row["target_resource"] == {**record["resource"], "state": "metadata_only"}
        and record["issued_at_ms"] <= issued < expires <= record["expires_at_ms"]
    )
    wire._resource(row["target_resource"])
    return row


def validate_correction_binding(value: Any, checked: pair.VerifiedWindowsPairSetup) -> dict:
    record, receipt = pair.checked_provenance(checked)
    return _binding(value, record, receipt)


def correction_context(imported: Any, control: Any, previous_descriptor_sha256: str) -> dict:
    """Require the original complete readable baseline; not its authentication."""
    saved = pair.validate_import(imported)
    record = saved["enrollment"]
    row = wire._document(control)
    wire._exact(
        row,
        "schema_version control_owner_id enrollment_id generation revision status "
        "original_import_digest operation_job_id task_id transport_request_hash resource baseline",
    )
    baseline = wire._exact(
        row["baseline"],
        "schema_version non_owner owner size_bytes sha256 resource_generation observed_at "
        "native_cleanup owned_job_cleanup independent_observation baseline_digest",
    )
    wire._require(
        row["schema_version"] == CONTROL_SCHEMA
        and row["control_owner_id"] == saved["control_owner_id"]
        and row["enrollment_id"] == saved["enrollment_id"]
        and row["generation"] == saved["generation"]
        and type(row["revision"]) is int
        and row["revision"] == 2
        and row["status"] == "baseline_verified"
        and row["original_import_digest"] == content_hash(saved)
        and row["resource"] == record["resource"]
        and row["resource"]["state"] == "readable"
        and baseline["schema_version"] == "bluefire.windows-file-readable-baseline.v2"
        and baseline["non_owner"] == baseline["owner"] == "allowed"
        and baseline["native_cleanup"] == baseline["owned_job_cleanup"] == "verified"
        and baseline["independent_observation"] is False
        and baseline["size_bytes"] == record["resource"]["size_bytes"]
        and baseline["sha256"] == record["resource"]["sha256"]
        and baseline["resource_generation"] == record["generation"]
    )
    wire._digest(baseline["baseline_digest"])
    wire._digest(previous_descriptor_sha256)
    wire._time(baseline["observed_at"], canonical=True)
    return {
        "schema_version": CONTEXT_SCHEMA,
        "control_digest": content_hash(row),
        "baseline_digest": baseline["baseline_digest"],
        "enrollment_digest": content_hash(record),
        "protected_receipt_digest": content_hash(saved["setup_receipt"]),
        "previous_descriptor_sha256": previous_descriptor_sha256,
        "target_resource": {**record["resource"], "state": "metadata_only"},
        "control_revision": row["revision"] + 1,
        "profile_digest": _profile(saved["setup_receipt"])["policy_digest"],
    }


def build_preparation(
    job_id: str, original: dict, imported: dict, control: dict, *, issued_at_ms: int
) -> dict:
    """Bind one already-reserved review; no native task or effect is created."""
    saved = pair.validate_import(imported)
    record, receipt = saved["enrollment"], saved["setup_receipt"]
    wire._exact(original, "submitted_request review review_context enrollment_digest created_at_ms")
    review, submitted = original["review"], original["submitted_request"]
    wire._exact(submitted, "submission_id review review_digest reviewed_by")
    wire._exact(
        review,
        "schema_version operation control_owner_id context_digest enrollment_digest "
        "control_digest expires_at_ms effect review_digest",
    )
    identifier = uuid.UUID(submitted["submission_id"])
    wire._require(
        str(identifier) == submitted["submission_id"] and job_id == "job-" + identifier.hex
    )
    wire._identifier(submitted["reviewed_by"])
    wire._int(original["created_at_ms"], 1, 2**63 - 1)
    expected_context = correction_context(
        saved, control, original["review_context"]["previous_descriptor_sha256"]
    )
    wire._require(
        original["review_context"] == expected_context
        and review["schema_version"] == "bluefire.file-access-control-review.v1"
        and review["context_digest"] == content_hash(expected_context)
        and review["operation"] == "harden"
        and review["control_owner_id"] == saved["control_owner_id"]
        and review["control_digest"] == content_hash(control)
        and review["enrollment_digest"] == original["enrollment_digest"] == content_hash(record)
        and submitted["review"]
        == {"operation": "harden", "control_owner_id": saved["control_owner_id"]}
        and submitted["review_digest"] == review["review_digest"]
        and content_hash({key: value for key, value in review.items() if key != "review_digest"})
        == review["review_digest"]
    )
    wire._int(issued_at_ms, 1, 2**63 - 1 - OPERATION_MS)
    wire._int(review["expires_at_ms"], 1, 2**63 - 1)
    wire._require(record["issued_at_ms"] <= original["created_at_ms"] <= issued_at_ms)
    expires = min(issued_at_ms + OPERATION_MS, review["expires_at_ms"], record["expires_at_ms"])
    binding = _binding(
        {
            "schema_version": BINDING_SCHEMA,
            "operation_job_id": job_id,
            "control_owner_id": saved["control_owner_id"],
            "prior_control_digest": content_hash(control),
            "baseline_digest": expected_context["baseline_digest"],
            "enrollment_digest": content_hash(record),
            "protected_receipt_digest": content_hash(receipt),
            "generation": record["generation"],
            "control_revision": expected_context["control_revision"],
            "previous_descriptor_sha256": expected_context["previous_descriptor_sha256"],
            "target_resource": expected_context["target_resource"],
            "issued_at_ms": issued_at_ms,
            "expires_at_ms": expires,
        },
        record,
        receipt,
    )
    return {
        "schema_version": PREPARATION_SCHEMA,
        "job_id": job_id,
        "control_owner_id": saved["control_owner_id"],
        "control_digest": content_hash(control),
        "context_digest": review["context_digest"],
        "review_digest": review["review_digest"],
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires,
        "binding": binding,
        "binding_digest": content_hash(binding),
    }


def validate_retained_preparation(
    value: Any, original: dict, imported: dict, control: dict
) -> dict:
    row = wire._document(value)
    wire._exact(
        row,
        "schema_version job_id control_owner_id control_digest context_digest review_digest "
        "issued_at_ms expires_at_ms binding binding_digest",
    )
    wire._require(
        row
        == build_preparation(
            row["job_id"], original, imported, control, issued_at_ms=row["issued_at_ms"]
        )
    )
    return row


def build_retest_original(
    binding: Any, checked: pair.VerifiedWindowsPairSetup, *, issued_at_ms: int, reviewed_by: str
) -> tuple[dict, dict]:
    """Pure native subtask bounded by the same original correction deadline."""
    row = validate_correction_binding(binding, checked)
    record, receipt = pair.checked_provenance(checked)
    return _build_retest_original(row, record, receipt, issued_at_ms, reviewed_by)


def _build_retest_original(
    row: dict, record: dict, receipt: dict, issued_at_ms: int, reviewed_by: str
) -> tuple[dict, dict]:
    """Historical consistency helper; cannot mint setup or postimage authority."""
    _binding(row, record, receipt)
    wire._identifier(reviewed_by)
    wire._int(issued_at_ms, row["issued_at_ms"], row["expires_at_ms"] - 1)
    expires = min(issued_at_ms + 5000, row["expires_at_ms"])
    profile, protocol = _profile(receipt), wire._CORRECTION
    expected = {
        "operation_job_id": row["operation_job_id"],
        "generation": row["generation"],
        "control_revision": row["control_revision"],
        "credential_binding_digest": content_hash(record["credential_reference"]),
        "host": {**record["host"], "profile_digest": profile["policy_digest"]},
        "resource": row["target_resource"],
        "correction_binding_digest": content_hash(row),
    }
    request_id = hashlib.sha256(
        f"{row['operation_job_id']}:{protocol.operation}".encode("ascii")
    ).hexdigest()[:32]
    approval = {
        "approved_by": reviewed_by,
        "approved_at": common._iso(issued_at_ms),
        "expires_at": common._iso(expires),
        "request_hash": "",
    }
    manifest = {
        "schema_version": "bluefire.runner-manifest.v1",
        "request_id": "win-read-" + request_id,
        "run_id": row["operation_job_id"],
        "step_id": protocol.operation,
        "behavior_id": protocol.behavior,
        "action_id": protocol.action,
        "mode": "execute",
        "runner_id": profile["runner_id"],
        "runner_profile_id": profile["profile_id"],
        "platform": "windows",
        "requested_at": common._iso(issued_at_ms),
        "expires_at": common._iso(expires),
        "params": {
            "windows_file_read_request": {
                "schema_version": protocol.schema("operation"),
                "request_id": request_id,
                **expected,
            }
        },
        "target_scope": profile["target_scope"],
        "required_capabilities": profile["capabilities"],
        "safety_tier": "controlled",
        "limits": profile["limits"],
        "cleanup_action_id": None,
        "policy_digest": profile["policy_digest"],
        "approval": approval,
        "evidence_refs": [],
        "request_hash": "",
    }
    manifest["request_hash"] = approval["request_hash"] = content_hash(manifest)
    task_id, transport = execution_task_identity(manifest, profile)
    original = {
        "manifest": manifest,
        "profile": profile,
        "task_id": task_id,
        "transport_request_hash": transport,
    }
    wire._original(original, expected, protocol=protocol)
    return original, expected
