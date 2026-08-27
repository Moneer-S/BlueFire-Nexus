"""Run-to-run comparison over normalized bundle data."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from typing import Any, Mapping, Sequence

from .run_store import RunStore
from .util import content_hash


class ComparisonError(ValueError):
    pass


_CATALOG_AUTHORITY_SCHEMA = "bluefire.action-catalog-authority.v1"
_CATALOG_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "generation",
        "catalog_digest",
        "built_in_catalog_digest",
        "packages",
        "action_bindings",
        "authority_digest",
    }
)
_PACKAGE_AUTHORITY_FIELDS = frozenset(
    {
        "package_id",
        "package_version",
        "package_digest",
        "content_digest",
        "publisher_id",
        "key_id",
        "signer_fingerprint",
        "activated_generation",
        "runner_identity_digest",
        "runner_inventory_digest",
        "runner_platform",
        "behavior_ids",
        "action_ids",
    }
)
_PACKAGE_IDENTITY_FIELDS = (
    "package_id",
    "package_version",
    "package_digest",
    "content_digest",
    "publisher_id",
    "key_id",
    "signer_fingerprint",
    "activated_generation",
)
_ACTION_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "catalog_generation",
        "catalog_digest",
        "logical_behavior_id",
        "logical_action_id",
        "package_id",
        "package_version",
        "package_digest",
        "content_digest",
        "program_digest",
        "runner_opcode",
        "opcode_contract_digest",
        "constants",
    }
)
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def compare_runs(store: RunStore, run_ids: Sequence[str]) -> Mapping[str, Any]:
    if len(run_ids) < 2:
        raise ComparisonError("comparison requires at least two runs")
    if len(run_ids) != len(set(run_ids)):
        raise ComparisonError("comparison run IDs must be unique")
    snapshots = []
    for run_id in run_ids:
        integrity = store.validate_bundle(run_id)
        if not integrity.get("valid"):
            raise ComparisonError(f"run bundle failed integrity validation: {run_id}")
        snapshots.append(store.get_run(run_id))
    summaries = [_summarize(snapshot) for snapshot in snapshots]
    baseline = summaries[0]
    deltas = [_delta(baseline, candidate) for candidate in summaries[1:]]
    body = {
        "schema_version": "bluefire.comparison.v1",
        "run_ids": list(run_ids),
        "baseline_run_id": run_ids[0],
        "summaries": summaries,
        "deltas": deltas,
    }
    return dict(body, comparison_id="comparison-" + content_hash(body)[7:27])


def _summarize(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    steps = snapshot.get("steps")
    if steps is None:
        steps = (
            snapshot.get("result", {}).get("steps", [])
            if isinstance(snapshot.get("result"), dict)
            else []
        )
    if not isinstance(steps, list):
        steps = []
    path: list[str] = []
    outcomes: dict[str, str] = {}
    first_blocked: str | None = None
    telemetry: set[str] = set()
    controls: set[str] = set()
    policy_states: Counter[str] = Counter()
    outcome_counts: Counter[str] = Counter()
    cleanup_success: bool | None = None
    for row in steps:
        if not isinstance(row, Mapping):
            continue
        step_id = str(row.get("step_id", ""))
        if step_id:
            path.append(step_id)
            outcome = str(row.get("status", "unknown"))
            outcomes[step_id] = outcome
            outcome_counts[outcome] += 1
        if first_blocked is None and row.get("status") in {"blocked", "control_blocked", "refused"}:
            first_blocked = step_id or None
        for item in row.get("telemetry", []) if isinstance(row.get("telemetry"), list) else []:
            telemetry.add(str(item))
        policy = row.get("policy")
        if isinstance(policy, Mapping):
            policy_status = str(policy.get("status", "unknown"))
            policy_states[policy_status] += 1
            if policy_status in {"control_blocked", "refused"}:
                controls.add(policy_status)
        if step_id and "cleanup" in step_id:
            cleanup_success = row.get("status") == "success"

    evidence_doc = snapshot.get("evidence", {})
    records = evidence_doc.get("records", []) if isinstance(evidence_doc, Mapping) else []
    provenance = Counter(
        str(row.get("provenance", "unknown")) for row in records if isinstance(row, Mapping)
    )
    evidence_details = _evidence_details(records)
    detections_doc = snapshot.get("detections", {})
    candidates = detections_doc.get("candidates", []) if isinstance(detections_doc, Mapping) else []
    detection_states = Counter(
        str(row.get("state", "unknown")) for row in candidates if isinstance(row, Mapping)
    )
    detection_matches = sum(
        int(row.get("match_count", 0))
        for row in candidates
        if isinstance(row, Mapping) and isinstance(row.get("match_count", 0), int)
    )
    benign_matches = sum(
        int(row.get("benign_match_count", 0))
        for row in candidates
        if isinstance(row, Mapping) and isinstance(row.get("benign_match_count", 0), int)
    )
    ai_proposals = snapshot.get("ai_proposals", [])
    if not isinstance(ai_proposals, list):
        ai_proposals = []
    ai_applications = Counter(
        str(row.get("application_status", row.get("application", "unknown")))
        for row in ai_proposals
        if isinstance(row, Mapping)
    )
    decisions = snapshot.get("planner_decisions", [])
    if not isinstance(decisions, list):
        decisions = []
    remaining_budgets = {}
    if decisions and isinstance(decisions[-1], Mapping):
        budget_value = decisions[-1].get("remaining_budgets")
        if isinstance(budget_value, Mapping):
            remaining_budgets = {
                str(key): int(value)
                for key, value in budget_value.items()
                if isinstance(value, int) and not isinstance(value, bool)
            }
    objective_reached = bool(snapshot.get("objective_reached", False))
    return {
        "run_id": snapshot.get("run_id"),
        "mode": snapshot.get("mode"),
        "profile_id": snapshot.get("runner_profile_id"),
        "catalog_authority": _catalog_authority_summary(snapshot),
        "path": path,
        "outcomes": outcomes,
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "first_blocked_step": first_blocked,
        "objective_reached": objective_reached,
        "evidence_provenance": dict(sorted(provenance.items())),
        "evidence_details": evidence_details,
        "detection_states": dict(sorted(detection_states.items())),
        "detection_matches": detection_matches,
        "benign_matches": benign_matches,
        "telemetry": sorted(telemetry),
        "controls": sorted(controls),
        "cleanup_success": cleanup_success,
        "policy_states": dict(sorted(policy_states.items())),
        "autonomy": snapshot.get("autonomy", "off"),
        "ai_provider_id": _provider_id(snapshot.get("ai_provider")),
        "ai_proposal_count": len(ai_proposals),
        "ai_applications": dict(sorted(ai_applications.items())),
        "remaining_budgets": remaining_budgets,
        "duration_ms": _duration_ms(snapshot),
        "counterfactual_steps": [
            row.get("step_id")
            for row in steps
            if isinstance(row, Mapping) and row.get("execution_disposition") == "counterfactual"
        ],
    }


def _delta(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    baseline_path = list(baseline["path"])
    candidate_path = list(candidate["path"])
    first_divergence: int | None = None
    for index in range(max(len(baseline_path), len(candidate_path))):
        left = baseline_path[index] if index < len(baseline_path) else None
        right = candidate_path[index] if index < len(candidate_path) else None
        if left != right:
            first_divergence = index
            break
    baseline_evidence = Counter(baseline["evidence_provenance"])
    candidate_evidence = Counter(candidate["evidence_provenance"])
    keys = sorted(set(baseline_evidence) | set(candidate_evidence))
    evidence_delta = {key: candidate_evidence[key] - baseline_evidence[key] for key in keys}
    evidence_detail_delta = _evidence_detail_delta(
        baseline.get("evidence_details"), candidate.get("evidence_details")
    )
    baseline_detection = Counter(baseline["detection_states"])
    candidate_detection = Counter(candidate["detection_states"])
    detection_keys = sorted(set(baseline_detection) | set(candidate_detection))
    detection_delta = {
        key: candidate_detection[key] - baseline_detection[key] for key in detection_keys
    }
    baseline_outcomes = Counter(baseline["outcome_counts"])
    candidate_outcomes = Counter(candidate["outcome_counts"])
    outcome_keys = sorted(set(baseline_outcomes) | set(candidate_outcomes))
    signals: list[str] = []
    if not baseline["objective_reached"] and candidate["objective_reached"]:
        signals.append("objective_recovered")
    elif baseline["objective_reached"] and not candidate["objective_reached"]:
        signals.append("objective_regressed")
    if baseline["cleanup_success"] is False and candidate["cleanup_success"] is True:
        signals.append("cleanup_recovered")
    elif baseline["cleanup_success"] is True and candidate["cleanup_success"] is False:
        signals.append("cleanup_regressed")
    observed_delta = candidate_evidence["observed"] - baseline_evidence["observed"]
    if observed_delta > 0:
        signals.append("observed_evidence_increased")
    elif observed_delta < 0:
        signals.append("observed_evidence_decreased")
    detection_match_delta = candidate["detection_matches"] - baseline["detection_matches"]
    benign_match_delta = candidate["benign_matches"] - baseline["benign_matches"]
    authority_delta = _catalog_authority_delta(
        baseline["catalog_authority"], candidate["catalog_authority"]
    )
    if detection_match_delta > 0:
        signals.append("detection_matches_increased")
    elif detection_match_delta < 0:
        signals.append("detection_matches_decreased")
    if benign_match_delta > 0:
        signals.append("benign_matches_increased")
    elif benign_match_delta < 0:
        signals.append("benign_matches_decreased")
    if authority_delta["changed"]:
        signals.append("catalog_authority_changed")
    assessment = _assessment(signals)
    return {
        "from_run_id": baseline["run_id"],
        "to_run_id": candidate["run_id"],
        "first_path_divergence": first_divergence,
        "first_blocked_changed": baseline["first_blocked_step"] != candidate["first_blocked_step"],
        "objective_changed": baseline["objective_reached"] != candidate["objective_reached"],
        "cleanup_changed": baseline["cleanup_success"] != candidate["cleanup_success"],
        "evidence_delta": evidence_delta,
        "evidence_detail_delta": evidence_detail_delta,
        "detection_delta": detection_delta,
        "detection_match_delta": detection_match_delta,
        "benign_match_delta": benign_match_delta,
        "outcome_delta": {
            key: candidate_outcomes[key] - baseline_outcomes[key] for key in outcome_keys
        },
        "telemetry_added": sorted(set(candidate["telemetry"]) - set(baseline["telemetry"])),
        "telemetry_removed": sorted(set(baseline["telemetry"]) - set(candidate["telemetry"])),
        "controls_added": sorted(set(candidate["controls"]) - set(baseline["controls"])),
        "controls_removed": sorted(set(baseline["controls"]) - set(candidate["controls"])),
        "autonomy_changed": baseline["autonomy"] != candidate["autonomy"],
        "ai_provider_changed": baseline["ai_provider_id"] != candidate["ai_provider_id"],
        "ai_proposal_delta": candidate["ai_proposal_count"] - baseline["ai_proposal_count"],
        "catalog_authority_changed": authority_delta["changed"],
        "catalog_authority_delta": authority_delta,
        "material_configuration_changed": authority_delta["changed"],
        "configuration_changes": (["catalog_authority"] if authority_delta["changed"] else []),
        "duration_delta_ms": _number_delta(
            baseline.get("duration_ms"), candidate.get("duration_ms")
        ),
        "assessment": assessment,
        "signals": signals,
    }


def _catalog_authority_summary(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    policy = snapshot.get("policy")
    if not isinstance(policy, Mapping):
        return _legacy_catalog_authority()
    preflight = policy.get("preflight")
    if not isinstance(preflight, Mapping) or "catalog_authority" not in preflight:
        return _legacy_catalog_authority()
    value = preflight["catalog_authority"]
    if not isinstance(value, Mapping):
        return _malformed_catalog_authority(value, ["authority_not_object"])

    errors: list[str] = []
    if set(value) != _CATALOG_AUTHORITY_FIELDS:
        errors.append("authority_fields_invalid")
    if value.get("schema_version") != _CATALOG_AUTHORITY_SCHEMA:
        errors.append("schema_version_invalid")
    generation = value.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        errors.append("generation_invalid")
    for field in (
        "catalog_digest",
        "built_in_catalog_digest",
        "authority_digest",
    ):
        if not _is_digest(value.get(field)):
            errors.append(f"{field}_invalid")

    packages = value.get("packages")
    package_summaries: list[dict[str, Any]] = []
    if not isinstance(packages, list):
        errors.append("packages_invalid")
    else:
        package_ids: set[str] = set()
        for package in packages:
            package_errors = _package_authority_errors(package, generation)
            if package_errors:
                errors.extend(package_errors)
                continue
            package_id = str(package["package_id"])
            if package_id in package_ids:
                errors.append("package_id_duplicate")
                continue
            package_ids.add(package_id)
            package_summaries.append({field: package[field] for field in _PACKAGE_IDENTITY_FIELDS})
    action_bindings = value.get("action_bindings")
    if not isinstance(action_bindings, list):
        errors.append("action_bindings_invalid")
    else:
        package_rows = packages if isinstance(packages, list) else []
        package_index = {
            str(package["package_id"]): package
            for package in package_rows
            if isinstance(package, Mapping) and not _package_authority_errors(package, generation)
        }
        binding_keys: set[tuple[str, str]] = set()
        for binding in action_bindings:
            binding_errors = _action_binding_errors(
                binding,
                generation=generation,
                catalog_digest=value.get("catalog_digest"),
                package_index=package_index,
            )
            errors.extend(binding_errors)
            if not binding_errors:
                key = (
                    str(binding["logical_behavior_id"]),
                    str(binding["logical_action_id"]),
                )
                if key in binding_keys:
                    errors.append("action_binding_duplicate")
                binding_keys.add(key)

    record_digest = _safe_content_hash(value)
    if record_digest is None:
        errors.append("authority_not_canonical_json")
    else:
        body = dict(value)
        claimed_digest = body.pop("authority_digest", None)
        body_digest = _safe_content_hash(body)
        if body_digest is None or claimed_digest != body_digest:
            errors.append("authority_digest_mismatch")

    if errors:
        return _malformed_catalog_authority(value, errors, record_digest=record_digest)
    package_summaries.sort(key=lambda item: str(item["package_id"]))
    return {
        "state": "bound",
        "schema_version": _CATALOG_AUTHORITY_SCHEMA,
        "generation": generation,
        "catalog_digest": value["catalog_digest"],
        "authority_digest": value["authority_digest"],
        "authority_record_digest": record_digest,
        "package_count": len(package_summaries),
        "packages": package_summaries,
    }


def _legacy_catalog_authority() -> dict[str, Any]:
    return {
        "state": "legacy_unbound",
        "schema_version": None,
        "generation": None,
        "catalog_digest": None,
        "authority_digest": None,
        "authority_record_digest": None,
        "package_count": 0,
        "packages": [],
    }


def _malformed_catalog_authority(
    value: Any,
    errors: Sequence[str],
    *,
    record_digest: str | None = None,
) -> dict[str, Any]:
    if record_digest is None:
        record_digest = _safe_content_hash(value)
    return {
        "state": "malformed",
        "schema_version": None,
        "generation": None,
        "catalog_digest": None,
        "authority_digest": None,
        "authority_record_digest": record_digest,
        "package_count": 0,
        "packages": [],
        "error_codes": sorted(set(errors)),
    }


def _package_authority_errors(value: Any, generation: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["package_entry_not_object"]
    errors: list[str] = []
    if set(value) != _PACKAGE_AUTHORITY_FIELDS:
        errors.append("package_fields_invalid")
    for field in ("package_id", "publisher_id", "key_id"):
        item = value.get(field)
        if not isinstance(item, str) or not _IDENTIFIER.fullmatch(item):
            errors.append(f"package_{field}_invalid")
    version = value.get("package_version")
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        errors.append("package_version_invalid")
    for field in (
        "package_digest",
        "content_digest",
        "signer_fingerprint",
        "runner_identity_digest",
        "runner_inventory_digest",
    ):
        if not _is_digest(value.get(field)):
            errors.append(f"package_{field}_invalid")
    activated_generation = value.get("activated_generation")
    if (
        isinstance(activated_generation, bool)
        or not isinstance(activated_generation, int)
        or activated_generation < 1
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or activated_generation > generation
    ):
        errors.append("package_activated_generation_invalid")
    platform = value.get("runner_platform")
    if not isinstance(platform, str) or not platform or len(platform) > 64:
        errors.append("package_runner_platform_invalid")
    for field in ("behavior_ids", "action_ids"):
        identifiers = value.get(field)
        if (
            not isinstance(identifiers, list)
            or not identifiers
            or len(identifiers) > 64
            or any(
                not isinstance(item, str) or not _STABLE_ID.fullmatch(item) for item in identifiers
            )
            or len(identifiers) != len(set(identifiers))
        ):
            errors.append(f"package_{field}_invalid")
    return errors


def _catalog_authority_delta(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> dict[str, Any]:
    baseline_packages = {
        str(item["package_id"]): item
        for item in baseline.get("packages", [])
        if isinstance(item, Mapping) and isinstance(item.get("package_id"), str)
    }
    candidate_packages = {
        str(item["package_id"]): item
        for item in candidate.get("packages", [])
        if isinstance(item, Mapping) and isinstance(item.get("package_id"), str)
    }
    package_ids = sorted(set(baseline_packages) | set(candidate_packages))
    packages_added = [
        dict(candidate_packages[package_id])
        for package_id in package_ids
        if package_id not in baseline_packages
    ]
    packages_removed = [
        dict(baseline_packages[package_id])
        for package_id in package_ids
        if package_id not in candidate_packages
    ]
    packages_changed = [
        {
            "package_id": package_id,
            "from": dict(baseline_packages[package_id]),
            "to": dict(candidate_packages[package_id]),
        }
        for package_id in package_ids
        if package_id in baseline_packages
        and package_id in candidate_packages
        and baseline_packages[package_id] != candidate_packages[package_id]
    ]
    fields = (
        "state",
        "generation",
        "catalog_digest",
        "authority_digest",
        "authority_record_digest",
    )
    fields_changed = [field for field in fields if baseline.get(field) != candidate.get(field)]
    changed = bool(fields_changed or packages_added or packages_removed or packages_changed)
    return {
        "changed": changed,
        "fields_changed": fields_changed,
        "from_state": baseline.get("state"),
        "to_state": candidate.get("state"),
        "from_generation": baseline.get("generation"),
        "to_generation": candidate.get("generation"),
        "generation_delta": _number_delta(baseline.get("generation"), candidate.get("generation")),
        "from_catalog_digest": baseline.get("catalog_digest"),
        "to_catalog_digest": candidate.get("catalog_digest"),
        "from_authority_digest": baseline.get("authority_digest"),
        "to_authority_digest": candidate.get("authority_digest"),
        "packages_added": packages_added,
        "packages_removed": packages_removed,
        "packages_changed": packages_changed,
    }


def _action_binding_errors(
    value: Any,
    *,
    generation: Any,
    catalog_digest: Any,
    package_index: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    if not isinstance(value, Mapping):
        return ["action_binding_not_object"]
    errors: list[str] = []
    if set(value) != _ACTION_BINDING_FIELDS:
        errors.append("action_binding_fields_invalid")
    if value.get("schema_version") != "bluefire.runner-execution-binding.v1":
        errors.append("action_binding_schema_invalid")
    if value.get("catalog_generation") != generation:
        errors.append("action_binding_generation_invalid")
    if value.get("catalog_digest") != catalog_digest or not _is_digest(value.get("catalog_digest")):
        errors.append("action_binding_catalog_digest_invalid")
    for field in ("logical_behavior_id", "logical_action_id"):
        item = value.get(field)
        if not isinstance(item, str) or not _STABLE_ID.fullmatch(item):
            errors.append(f"action_binding_{field}_invalid")
    package_id = value.get("package_id")
    package = package_index.get(package_id) if isinstance(package_id, str) else None
    if package is None:
        errors.append("action_binding_package_invalid")
    else:
        for binding_field, package_field in (
            ("package_version", "package_version"),
            ("package_digest", "package_digest"),
            ("content_digest", "content_digest"),
        ):
            if value.get(binding_field) != package.get(package_field):
                errors.append(f"action_binding_{binding_field}_mismatch")
        if value.get("logical_behavior_id") not in package.get("behavior_ids", []):
            errors.append("action_binding_behavior_not_in_package")
        if value.get("logical_action_id") not in package.get("action_ids", []):
            errors.append("action_binding_action_not_in_package")
    for field in (
        "package_digest",
        "content_digest",
        "program_digest",
        "opcode_contract_digest",
    ):
        if not _is_digest(value.get(field)):
            errors.append(f"action_binding_{field}_invalid")
    opcode = value.get("runner_opcode")
    if not isinstance(opcode, str) or not _STABLE_ID.fullmatch(opcode):
        errors.append("action_binding_runner_opcode_invalid")
    constants = value.get("constants")
    if not isinstance(constants, Mapping) or _safe_content_hash(constants) is None:
        errors.append("action_binding_constants_invalid")
    return errors


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _safe_content_hash(value: Any) -> str | None:
    try:
        return content_hash(value)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None


def _provider_id(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        selected = value.get("provider_id") or value.get("requested_provider_id")
        return str(selected) if isinstance(selected, str) and selected else None
    return None


def _evidence_details(records: Any) -> dict[str, Any]:
    if not isinstance(records, list):
        records = []
    producer_counts: Counter[str] = Counter()
    observed_artifacts: dict[str, dict[str, Any]] = {}
    evidence_gaps: dict[str, dict[str, Any]] = {}
    for row in records:
        if not isinstance(row, Mapping):
            continue
        provenance = str(row.get("provenance", "unknown"))
        producer = _bounded_text(row.get("producer"), default="unknown-producer")
        producer_counts[producer] += 1
        content = row.get("content")
        content = content if isinstance(content, Mapping) else {}
        if provenance == "observed":
            artifact = _observed_artifact_summary(row, content, producer)
            if artifact is not None:
                observed_artifacts[artifact["key"]] = artifact
        elif provenance == "unknown" and content.get("artifact_type") == "evidence_gap":
            gap = _evidence_gap_summary(row, content, producer)
            evidence_gaps[gap["key"]] = gap
    return {
        "producer_counts": dict(sorted(producer_counts.items())),
        "observed_artifacts": [
            {key: value for key, value in item.items() if key != "key"}
            for item in sorted(observed_artifacts.values(), key=lambda value: value["key"])
        ],
        "evidence_gaps": [
            {key: value for key, value in item.items() if key != "key"}
            for item in sorted(evidence_gaps.values(), key=lambda value: value["key"])
        ],
    }


def _observed_artifact_summary(
    row: Mapping[str, Any], content: Mapping[str, Any], producer: str
) -> dict[str, Any] | None:
    path = content.get("path")
    source = content.get("source")
    logical_path = path if isinstance(path, str) else source if isinstance(source, str) else None
    if logical_path is None:
        return None
    normalized_path = _safe_relative_path(logical_path)
    if normalized_path is None:
        return None
    step_id = _bounded_text(row.get("step_id"), default="unknown-step")
    artifact_type = _bounded_text(content.get("artifact_type"), default="unknown_artifact")
    item: dict[str, Any] = {
        "key": f"{producer}\0{step_id}\0{normalized_path}",
        "evidence_id": _bounded_text(row.get("evidence_id"), default="evidence-unknown"),
        "step_id": step_id,
        "producer": producer,
        "artifact_type": artifact_type,
        "path": normalized_path,
        "content_hash": _digest_or_none(row.get("content_hash")),
    }
    digest = _digest_or_none(content.get("sha256"))
    if digest is not None:
        item["sha256"] = digest
    size = _safe_int(content.get("size_bytes"))
    if size is None:
        size = _safe_int(content.get("size"))
    if size is not None:
        item["size_bytes"] = size
    return item


def _evidence_gap_summary(
    row: Mapping[str, Any], content: Mapping[str, Any], producer: str
) -> dict[str, Any]:
    requested = _bounded_text(content.get("requested_artifact"), default="unspecified")
    reason = content.get("reason")
    reason_text = reason if isinstance(reason, str) else "unavailable"
    reason_code = reason_text if _IDENTIFIER.fullmatch(reason_text) else "unclassified"
    step_id = _bounded_text(row.get("step_id"), default="unknown-step")
    return {
        "key": f"{producer}\0{step_id}\0{requested}\0{reason_code}",
        "evidence_id": _bounded_text(row.get("evidence_id"), default="evidence-unknown"),
        "step_id": step_id,
        "producer": producer,
        "requested_artifact": requested,
        "reason_code": reason_code,
        "reason_hash": content_hash({"reason": reason_text}),
        "content_hash": _digest_or_none(row.get("content_hash")),
    }


def _evidence_detail_delta(baseline: Any, candidate: Any) -> dict[str, Any]:
    baseline_details = baseline if isinstance(baseline, Mapping) else {}
    candidate_details = candidate if isinstance(candidate, Mapping) else {}
    baseline_observed = _keyed_observed(baseline_details.get("observed_artifacts"))
    candidate_observed = _keyed_observed(candidate_details.get("observed_artifacts"))
    observed_keys = sorted(set(baseline_observed) | set(candidate_observed))
    observed_added = [
        candidate_observed[key] for key in observed_keys if key not in baseline_observed
    ]
    observed_removed = [
        baseline_observed[key] for key in observed_keys if key not in candidate_observed
    ]
    observed_changed = [
        {
            "from": baseline_observed[key],
            "to": candidate_observed[key],
        }
        for key in observed_keys
        if key in baseline_observed
        and key in candidate_observed
        and _artifact_identity(baseline_observed[key])
        != _artifact_identity(candidate_observed[key])
    ]
    baseline_gaps = _keyed_gaps(baseline_details.get("evidence_gaps"))
    candidate_gaps = _keyed_gaps(candidate_details.get("evidence_gaps"))
    gap_keys = sorted(set(baseline_gaps) | set(candidate_gaps))
    return {
        "observed_artifacts_added": observed_added,
        "observed_artifacts_removed": observed_removed,
        "observed_artifacts_changed": observed_changed,
        "evidence_gaps_added": [
            candidate_gaps[key] for key in gap_keys if key not in baseline_gaps
        ],
        "evidence_gaps_removed": [
            baseline_gaps[key] for key in gap_keys if key not in candidate_gaps
        ],
        "producer_delta": _counter_delta(
            baseline_details.get("producer_counts"), candidate_details.get("producer_counts")
        ),
    }


def _keyed_observed(value: Any) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    rows = value if isinstance(value, list) else []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        producer = _bounded_text(row.get("producer"), default="unknown-producer")
        step_id = _bounded_text(row.get("step_id"), default="unknown-step")
        path = row.get("path")
        if isinstance(path, str):
            result[f"{producer}\0{step_id}\0{path}"] = row
    return result


def _keyed_gaps(value: Any) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    rows = value if isinstance(value, list) else []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        producer = _bounded_text(row.get("producer"), default="unknown-producer")
        step_id = _bounded_text(row.get("step_id"), default="unknown-step")
        requested = _bounded_text(row.get("requested_artifact"), default="unspecified")
        reason_code = _bounded_text(row.get("reason_code"), default="unclassified")
        result[f"{producer}\0{step_id}\0{requested}\0{reason_code}"] = row
    return result


def _artifact_identity(value: Mapping[str, Any]) -> tuple[Any, Any, Any]:
    return (value.get("sha256"), value.get("size_bytes"), value.get("content_hash"))


def _counter_delta(baseline: Any, candidate: Any) -> dict[str, int]:
    baseline_counts = Counter(
        {
            str(key): int(value)
            for key, value in (baseline.items() if isinstance(baseline, Mapping) else ())
            if isinstance(value, int) and not isinstance(value, bool)
        }
    )
    candidate_counts = Counter(
        {
            str(key): int(value)
            for key, value in (candidate.items() if isinstance(candidate, Mapping) else ())
            if isinstance(value, int) and not isinstance(value, bool)
        }
    )
    return {
        key: candidate_counts[key] - baseline_counts[key]
        for key in sorted(set(baseline_counts) | set(candidate_counts))
    }


def _bounded_text(value: Any, *, default: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        return default
    return value[:200]


def _safe_relative_path(value: str) -> str | None:
    logical = value.replace("\\", "/")
    if logical.startswith("/") or "\x00" in logical:
        return None
    parts = [part for part in logical.split("/") if part]
    if not parts or any(part in {".", ".."} for part in parts):
        return None
    return "/".join(parts)[:500]


def _digest_or_none(value: Any) -> str | None:
    if isinstance(value, str):
        if _DIGEST.fullmatch(value):
            return value
        if len(value) == 64 and all(character in "0123456789abcdef" for character in value):
            return "sha256:" + value
    return None


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return int(value)


def _duration_ms(snapshot: Mapping[str, Any]) -> int | None:
    created = snapshot.get("created_at")
    finalized = snapshot.get("finalized_at")
    if not isinstance(created, str) or not isinstance(finalized, str):
        return None
    try:
        start = datetime.fromisoformat(created.replace("Z", "+00:00"))
        end = datetime.fromisoformat(finalized.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, round((end - start).total_seconds() * 1000))


def _number_delta(baseline: Any, candidate: Any) -> int | None:
    if isinstance(baseline, int) and isinstance(candidate, int):
        return candidate - baseline
    return None


def _assessment(signals: Sequence[str]) -> str:
    regressed = any(
        signal.endswith("regressed")
        or signal in {"observed_evidence_decreased", "benign_matches_increased"}
        for signal in signals
    )
    improved = any(
        signal.endswith("recovered")
        or signal
        in {
            "observed_evidence_increased",
            "detection_matches_increased",
            "benign_matches_decreased",
        }
        for signal in signals
    )
    if improved and not regressed:
        return "improved"
    if regressed and not improved:
        return "regressed"
    if signals:
        return "mixed"
    return "no_material_change"


__all__ = ["ComparisonError", "compare_runs"]
