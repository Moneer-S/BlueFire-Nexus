"""Read-only historical Linux baseline, correction and composed-retest linkage."""

from __future__ import annotations

from typing import Any, Mapping, cast

from .application_errors import APIError
from .capability_file_access import objective_result as file_objective_result
from .capability_grant import authority_id
from .capability_packs import FILE_ACCESS_PACK, grant_pack
from .file_access_contract import canonical_file_access_binding
from .file_access_observation import baseline_record, control_observation
from .file_access_plan import recipe
from .product_store_errors import ProductStoreError
from .run_store import RunStoreError
from .util import content_hash

SCHEMA = "bluefire.file-access-composed-retest-linkage.v1"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProductStoreError(message)


def _revision(store: Any, owner_id: str, revision: int) -> dict[str, Any]:
    return cast(dict[str, Any], store.get_linux_file_access_revision_record(owner_id, revision))


def _operation(store: Any, job_id: str, *, owner_id: str, kind: str, revision: dict) -> dict:
    records = store.file_access_operation_records(job_id)
    document, prepared, outcome = (
        records["document"],
        records["preparation"],
        records["outcome"],
    )
    review = document.get("review", {})
    submitted = document.get("submitted_request", {})
    expected_steps = [
        (step["step_id"], step["action_id"])
        for step in recipe(kind, prepared.get("prior") if prepared is not None else None)
    ]
    recorded_steps = [
        (row["task"].get("step_id"), row["task"].get("manifest", {}).get("action_id"))
        for row in records["tasks"]
    ]
    _require(
        records["control_owner_id"] == owner_id
        and revision["job_id"] == job_id
        and review.get("operation") == kind
        and review.get("control_owner_id") == owner_id
        and review.get("review_digest") == submitted.get("review_digest")
        and review.get("review_digest")
        == content_hash({key: value for key, value in review.items() if key != "review_digest"})
        and submitted.get("review") == {"operation": kind, "control_owner_id": owner_id}
        and prepared is not None
        and prepared.get("job_id") == job_id
        and prepared.get("revision") == revision["document"]["revision"]
        and prepared.get("target_binding") == revision["document"]["binding"]
        and prepared.get("target_binding_digest") == revision["document"]["binding_digest"]
        and prepared.get("recipe") == recipe(kind, prepared.get("prior"))
        and recorded_steps == expected_steps
        and outcome is not None
        and outcome.get("state") == "complete"
        and outcome.get("control_digest") == revision["document_digest"]
        and outcome.get("evidence_digest") == content_hash(records["tasks"])
        and all(
            row["task"].get("job_id") == job_id
            and row["terminal"] is not None
            and row["terminal"].get("task_id") == row["task"].get("task_id")
            and row["terminal"].get("request_hash") == row["task"].get("request_hash")
            and row["terminal"]["result"].get("status") == "success"
            for row in records["tasks"]
        ),
        "The original file-access operation does not verify this historical revision.",
    )
    return cast(dict[str, Any], records)


def _historical_controls(store: Any, environment: Mapping[str, Any], now_ms: int):
    owner_id = environment["control_owner_id"]
    hardened_revision = environment["control_revision"]
    _require(
        type(hardened_revision) is int and hardened_revision >= 3,
        "The grant lacks a historical hardened control revision.",
    )
    change = _revision(store, owner_id, hardened_revision)
    predecessor = _revision(store, owner_id, hardened_revision - 1)
    changed = change["document"]
    before = predecessor["document"]
    baseline = changed.get("baseline")
    baseline_source = baseline.get("source_binding", {}) if isinstance(baseline, dict) else {}
    baseline_job_id = baseline_source.get("operation_job_id")
    _require(
        changed.get("status") == "hardened"
        and change["document_digest"] == environment["control_digest"]
        and isinstance(baseline_job_id, str)
        and before.get("status") in {"baseline_verified", "rolled_back"}
        and before.get("baseline") == baseline
        and before.get("enrollment_id") == changed.get("enrollment_id")
        and before.get("source") == changed.get("source"),
        "The reviewed hardening lacks its exact retained predecessor and baseline.",
    )
    baseline_job_id = cast(str, baseline_job_id)
    baseline_records = store.file_access_operation_records(baseline_job_id)
    baseline_preparation = baseline_records["preparation"]
    _require(
        baseline_preparation is not None
        and type(baseline_preparation.get("revision")) is int
        and baseline_preparation["revision"] < hardened_revision,
        "The original baseline revision is unavailable.",
    )
    original = _revision(store, owner_id, baseline_preparation["revision"])
    baseline_control = original["document"]
    _require(
        baseline_control.get("status") == "baseline_verified"
        and baseline_control.get("baseline") == baseline
        and baseline_control.get("source") == changed.get("source")
        and baseline_source.get("evidence_digest") == baseline.get("baseline_digest"),
        "The original baseline is not the retained hardening's source.",
    )
    original_binding = canonical_file_access_binding(baseline_control["binding"])
    before_binding = canonical_file_access_binding(before["binding"])
    changed_binding = canonical_file_access_binding(changed["binding"])

    def stable(binding):
        return {
            key: value for key, value in binding.items() if key not in {"mode", "control_revision"}
        }

    _require(
        stable(original_binding) == stable(before_binding) == stable(changed_binding)
        and original_binding["mode"] == before_binding["mode"] == "0640"
        and changed_binding["mode"] == "0600"
        and original_binding["control_revision"] == baseline_control["revision"]
        and before_binding["control_revision"] == before["revision"]
        and changed_binding["control_revision"] == hardened_revision
        and changed_binding["resource_generation"] == environment["resource_generation"]
        and content_hash(changed_binding["resource"]) == environment["resource_digest"]
        and changed_binding["enrollment_digest"] == environment["probe_enrollment_digest"]
        and baseline["baseline_digest"] == environment["baseline_digest"],
        "The baseline and correction do not share one enrolled generated resource.",
    )
    baseline_operation = _operation(
        store, baseline_job_id, owner_id=owner_id, kind="baseline", revision=original
    )
    observed = control_observation(
        "baseline", baseline_operation["tasks"], binding=original_binding, now_ms=now_ms
    )
    _require(
        baseline_operation["outcome"].get("verified_observation") == observed
        and baseline_record(baseline_job_id, observed) == baseline,
        "The baseline does not match its original authenticated read observations.",
    )
    change_operation = _operation(
        store, change["job_id"], owner_id=owner_id, kind="harden", revision=change
    )
    _require(
        change_operation["document"]["review"].get("control_digest")
        == predecessor["document_digest"]
        and change_operation["preparation"].get("prior") == before
        and change_operation["preparation"].get("source") == before["source"],
        "The correction lacks its separate reviewed control preimage.",
    )
    return (
        {
            "operation_job_id": baseline_job_id,
            "control_revision": baseline_control["revision"],
            "control_digest": original["document_digest"],
            "baseline_digest": baseline["baseline_digest"],
            "resource_generation": original_binding["resource_generation"],
            "mode": "0640",
            "non_owner": "allowed",
            "owner": "allowed",
            "record_count": baseline["record_count"],
            "sha256": baseline["sha256"],
        },
        {
            "operation_job_id": change["job_id"],
            "control_revision": hardened_revision,
            "control_digest": change["document_digest"],
            "previous_control_digest": predecessor["document_digest"],
            "resource_generation": changed_binding["resource_generation"],
            "mode": "0600",
        },
    )


def _unknown_retest(marker: Mapping[str, Any], job_id: str) -> dict[str, Any]:
    return {
        "attempt_job_id": job_id,
        "run_id": marker["run_id"],
        "state": "unknown",
        "non_owner_decision": None,
        "owner_decision": None,
        "record_count": None,
        "sha256": None,
        "run_cleanup": None,
        "request_cleanup": None,
        "objective_established": None,
        "result_digest": None,
    }


def projection(service: Any, owner_id: str, attempt_id: str) -> dict[str, Any]:
    """Recompute one historical comparison; no current-control or model claim is proof."""
    authority_id(attempt_id, "attempt")
    objective = service.composition.read(owner_id)
    grant_view = objective["grant"]
    _require(grant_view is not None, "The selected composition objective has no grant.")
    grant = grant_view["document"]
    _require(grant_pack(grant) == FILE_ACCESS_PACK, "Select a Linux file-access objective.")
    marker_jobs = [
        (job, job["request"]["composition_attempt"])
        for job in objective["attempts"]
        if job["request"].get("composition_attempt", {}).get("attempt_id") == attempt_id
    ]
    _require(len(marker_jobs) == 1, "The selected attempt is not part of this objective.")
    child, marker = marker_jobs[0]
    _require(
        marker.get("parent_job_id") == owner_id
        and marker.get("grant_id") == grant["grant_id"]
        and marker.get("grant_digest") == grant["grant_digest"],
        "The selected attempt belongs to another grant or owner.",
    )
    environment = grant["environment"]
    baseline, change = _historical_controls(
        service.product_store, environment, service.composition.clock()
    )
    retest = _unknown_retest(marker, child["job_id"])
    comparison = {
        "state": "unknown",
        "non_owner_change": "unknown",
        "owner_preserved": None,
        "content_preserved": None,
        "cleanup_verified": None,
    }
    try:
        attempt = service.product_store.get_capability_attempt(attempt_id)
    except ProductStoreError:
        attempt = None
    if attempt is not None:
        lease, compiled = attempt["lease"], attempt["compiled"]
        dependency = compiled.get("file_access", {})
        _require(
            lease["attempt_id"] == attempt_id
            and lease["job_id"] == child["job_id"]
            and lease["grant_id"] == grant["grant_id"]
            and lease["grant_digest"] == grant["grant_digest"]
            and lease["run_id"] == marker["run_id"]
            and compiled["compiled_digest"] == marker["compiled_digest"]
            and dependency.get("control_owner_id") == environment["control_owner_id"]
            and dependency.get("control_digest") == change["control_digest"]
            and dependency.get("baseline_digest") == baseline["baseline_digest"]
            and dependency.get("control_revision") == change["control_revision"]
            and dependency.get("resource_generation") == change["resource_generation"],
            "The original attempt does not bind this historical correction.",
        )
        if attempt["state"] == "settled":
            try:
                verified = service.composition._verified_result(attempt)
            except (APIError, ProductStoreError, RunStoreError, KeyError, TypeError, ValueError):
                verified = None
            if verified is not None:
                result, cleanup, outcome = (
                    verified["file_access_result"],
                    verified["cleanup"],
                    verified["objective"],
                )
                _require(
                    verified["run_id"] == marker["run_id"]
                    and result["resource_generation"] == change["resource_generation"]
                    and result["control_revision"] == change["control_revision"]
                    and result["resource_digest"] == environment["resource_digest"]
                    and result["probe_enrollment_digest"] == environment["probe_enrollment_digest"]
                    and result["mode"] == "0600"
                    and result["non_owner_decision"] in {"allowed", "permission_denied", "unknown"}
                    and result["owner_decision"] in {"allowed", "unknown"}
                    and type(result["record_count"]) is int
                    and cleanup["run"] in {"complete", "incomplete"}
                    and cleanup["request"] == "verified_closed",
                    "The verified retest differs from its exact original attempt.",
                )
                _require(
                    outcome
                    == file_objective_result(
                        grant,
                        {
                            **result,
                            "run_cleanup": cleanup["run"],
                            "request_cleanup": cleanup["request"],
                        },
                    ),
                    "The retest's objective proof is inconsistent with its bound observations.",
                )
                retest = {
                    **retest,
                    "state": "verified",
                    "non_owner_decision": result["non_owner_decision"],
                    "owner_decision": result["owner_decision"],
                    "record_count": result["record_count"],
                    "sha256": result["sha256"],
                    "run_cleanup": cleanup["run"],
                    "request_cleanup": cleanup["request"],
                    "objective_established": outcome["established"],
                    "result_digest": content_hash(verified),
                }
                comparison = {
                    "state": ("established" if outcome["established"] else "not_established"),
                    "non_owner_change": {
                        "permission_denied": "allowed_to_denied",
                        "allowed": "still_allowed",
                        "unknown": "unknown",
                    }[result["non_owner_decision"]],
                    "owner_preserved": (
                        result["owner_decision"] == "allowed"
                        if result["owner_decision"] != "unknown"
                        else None
                    ),
                    "content_preserved": (
                        result["sha256"] == baseline["sha256"]
                        and result["record_count"] == baseline["record_count"]
                        if result["owner_decision"] == "allowed"
                        else None
                    ),
                    "cleanup_verified": cleanup
                    == {
                        "run": "complete",
                        "request": "verified_closed",
                    },
                }
    body = {
        "schema_version": SCHEMA,
        "objective_owner_id": owner_id,
        "attempt_id": attempt_id,
        "control_owner_id": environment["control_owner_id"],
        "baseline": baseline,
        "change": change,
        "retest": retest,
        "comparison": comparison,
    }
    return {**body, "linkage_digest": content_hash(body)}
