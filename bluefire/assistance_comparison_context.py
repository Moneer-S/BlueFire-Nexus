"""Strict minimized facts from one immutable comparison; never recompute or dispatch."""

import re
from typing import Any, Mapping

from .assistance_comparison_s3 import project as s3_summary
from .assistance_comparison_s3 import require
from .product_store_errors import ProductStoreError
from .util import canonical_json_bytes, content_hash

KIND = "comparison_snapshot"
SUMMARY_SCHEMA = "bluefire.comparison-assistance-summary.v1"
MAX_SUMMARY_BYTES = 32768
_MAX_COUNT = 2**31 - 1
_MISSING = object()
_PROVENANCE = ("synthetic", "executed", "observed", "control_blocked", "counterfactual", "unknown")
_MATERIAL = {
    "configuration",
    "path",
    "outcomes",
    "first_prevention",
    "objective",
    "controls",
    "telemetry",
    "ai_proposals",
    "counterfactual",
    "planner",
    "implementation",
    "evidence",
    "detection",
    "cleanup",
    "budgets",
}
_STATUSES = {
    "success",
    "failed",
    "blocked",
    "control_blocked",
    "refused",
    "skipped",
    "not_run",
    "unknown",
    "unreported",
}
LIMITATIONS = [
    "This explains one immutable saved comparison; it does not rerun, recompute, approve or change any experiment or control.",
    "Recorded objectives belong to their own run and mode; equal results do not establish the same objective, causation, prevention or defensive effectiveness.",
    "Evidence record counts, observed artifact counts and detector matches are distinct populations; missing values remain unreported. Observed, fixture and benign match populations may overlap and are not a coverage denominator.",
    "Repeated step identities do not contain individual attempt outcomes in this snapshot; final per-step outcomes cannot be assigned to each attempt.",
    "Legitimate use is unreported unless explicit saved read-result rows record it. S3 runner reports and synthetic evidence keep their provenance and do not prove effective access or defensive effectiveness.",
    "Current source integrity is reported separately from immutable historical comparison facts; unavailable source bundles are not substituted or recomputed.",
]


def selection(value):
    require(isinstance(value, dict) and set(value) == {"kind", "snapshot_id", "snapshot_digest"})
    require(
        value["kind"] == KIND
        and isinstance(value["snapshot_id"], str)
        and re.fullmatch(r"run-comparison-[0-9a-f]{64}", value["snapshot_id"])
    )
    require(value["snapshot_digest"] == "sha256:" + value["snapshot_id"][15:])
    return dict(value)


def _count(value):
    if value is _MISSING or value is None:
        return None
    require(type(value) is int and 0 <= value <= _MAX_COUNT)
    return value


def _mapping(value):
    require(isinstance(value, dict))
    return value


def _path(row):
    path = row.get("path")
    if path is None:
        return None
    require(
        isinstance(path, list)
        and len(path) <= _MAX_COUNT
        and all(isinstance(item, str) and 0 < len(item) <= 512 for item in path)
    )
    return path


def _execution(row, path):
    recorded = row.get("execution_path")
    if recorded is None:
        return None
    require(isinstance(recorded, list) and (path is None or len(recorded) == len(path)))
    for index, item in enumerate(recorded):
        require(isinstance(item, dict) and set(item) == {"step_id", "behavior_id", "action_id"})
        require(
            isinstance(item["step_id"], str)
            and 0 < len(item["step_id"]) <= 512
            and (path is None or item["step_id"] == path[index])
        )
        require(
            all(
                item[key] is None or isinstance(item[key], str) and len(item[key]) <= 512
                for key in ("behavior_id", "action_id")
            )
        )
    return recorded


def _stop(row):
    block = row.get("first_block")
    if block is None:
        legacy = row.get("first_blocked_step")
        require(legacy is None or isinstance(legacy, str) and len(legacy) <= 512)
        return (
            {"recorded": False}
            if not legacy
            else {"recorded": True, "status": None, "policy_status": None}
        )
    _mapping(block)
    require(set(block) == {"step_id", "behavior_id", "action_id", "status", "policy_status"})
    require(isinstance(block["step_id"], str) and len(block["step_id"]) <= 512)
    require(
        all(
            block[key] is None or isinstance(block[key], str) and len(block[key]) <= 512
            for key in ("behavior_id", "action_id")
        )
    )
    result = {"recorded": True}
    for key in ("status", "policy_status"):
        value = block[key]
        require(value is None or isinstance(value, str) and len(value) <= 512)
        result[key] = value if value is None or value in _STATUSES else "unreported"
    return result


def _cleanup(row):
    value = row.get("cleanup")
    if value is None:
        legacy = row.get("cleanup_success")
        require(legacy is None or type(legacy) is bool)
        return {
            "source": "not_recorded" if legacy is None else "step_heuristic",
            "authoritative": False,
            "state": "unknown" if legacy is None else "success" if legacy else "failed",
            "success": legacy,
        }
    _mapping(value)
    require({"source", "authoritative", "state", "success"} <= set(value))
    require(
        value["source"] in {"run_result", "step_heuristic", "not_recorded"}
        and type(value["authoritative"]) is bool
        and (value["success"] is None or type(value["success"]) is bool)
        and value["state"]
        in {
            "success",
            "failed",
            "unknown",
            "not_attempted",
            "verified_success",
            "failed_or_incomplete",
            "contradictory",
        }
    )
    if value["authoritative"]:
        outstanding = _count(value.get("outstanding_receipt_count"))
        require(
            value["source"] == "run_result"
            and outstanding is not None
            and (
                (
                    value.get("attempted") is False
                    and value["state"] == "not_attempted"
                    and value["success"] is None
                    and outstanding == 0
                )
                or value.get("attempted") is True
                and (
                    (
                        value["state"] == "verified_success"
                        and value["success"] is True
                        and outstanding == 0
                    )
                    or (value["state"] == "failed_or_incomplete" and value["success"] is False)
                )
            )
        )
    return {key: value[key] for key in ("source", "authoritative", "state", "success")}


def _artifact(value):
    _mapping(value)
    require(
        all(
            isinstance(value.get(key), str) and 0 < len(value[key]) <= 4096
            for key in ("evidence_id", "step_id", "producer", "artifact_type", "path")
        )
    )
    for key in ("content_hash", "sha256"):
        raw = value.get(key)
        require(raw is None or isinstance(raw, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", raw))
    _count(value.get("size_bytes"))


def _array_count(value, *, changed=False, artifacts=False):
    if value is _MISSING or value is None:
        return None
    require(isinstance(value, list) and len(value) <= _MAX_COUNT)
    for item in value:
        _mapping(item)
        if changed:
            require(set(item) == {"from", "to"})
            _artifact(item["from"])
            _artifact(item["to"])
        elif artifacts:
            _artifact(item)
    return len(value)


def _observations(row):
    provenance = row.get("evidence_provenance")
    counts = None
    if provenance is not None:
        _mapping(provenance)
        counts = {key: 0 for key in (*_PROVENANCE, "other")}
        for key, value in provenance.items():
            require(isinstance(key, str) and 0 < len(key) <= 512)
            count = _count(value)
            require(count is not None)
            target = key if key in _PROVENANCE else "other"
            counts[target] = _count(counts[target] + count)
    details = row.get("evidence_details")
    if details is not None:
        _mapping(details)
    return {
        "evidence_records": counts,
        "observed_artifacts": (
            _array_count(details.get("observed_artifacts", _MISSING), artifacts=True)
            if details is not None
            else None
        ),
        "evidence_gaps": (
            _array_count(details.get("evidence_gaps", _MISSING)) if details is not None else None
        ),
    }


def _run(row, position):
    _mapping(row)
    mode, objective = row.get("mode"), row.get("objective_reached")
    require(mode is None or mode in {"simulate", "execute"})
    require(objective is None or type(objective) is bool)
    path = _path(row)
    _execution(row, path)
    detection = {
        name: _count(row.get(key, _MISSING))
        for name, key in (
            ("total_matches", "detection_matches"),
            ("observed_matches", "observed_detection_matches"),
            ("fixture_matches", "fixture_detection_matches"),
            ("benign_matches", "benign_matches"),
        )
    }
    return {
        "position": position,
        "mode": mode,
        "objective_reached": objective,
        "recorded_attempts": len(path) if path is not None else None,
        "repeated_step_ids": len(path) != len(set(path)) if path is not None else None,
        "first_stop": _stop(row),
        "observations": _observations(row),
        "detection": detection,
        "cleanup": _cleanup(row),
    }


def _divergence(before, after, delta):
    left, right = _path(before), _path(after)
    index = delta.get("first_path_divergence")
    if index is None:
        if left is not None and right is not None:
            require(left == right)
        return None, "none" if left is not None and right is not None else "unreported"
    _count(index)
    require(index < _MAX_COUNT)
    if left is None or right is None:
        return index + 1, "unreported"
    require(index < max(len(left), len(right)))
    if index >= min(len(left), len(right)) or left[index] != right[index]:
        return index + 1, "path"
    baseline, candidate = _execution(before, left), _execution(after, right)
    if baseline is not None and candidate is not None:
        for key in ("behavior_id", "action_id"):
            a, b = baseline[index][key], candidate[index][key]
            if (
                all(
                    isinstance(value, str)
                    and re.fullmatch(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*", value)
                    for value in (a, b)
                )
                and a != b
            ):
                return index + 1, "method"
    return index + 1, "unreported"


def _objective_comparability(before, after, delta):
    recorded = delta.get("objective_comparability")
    require(recorded is None or recorded in {"comparable", "different_objectives", "unverified"})
    left, right = before.get("capability_objective"), after.get("capability_objective")
    for projection in (left, right):
        if projection is None:
            continue
        projection = _mapping(projection)
        require(
            projection.get("state") in {"verified", "unverified"}
            and isinstance(projection.get("objective_digest"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", projection["objective_digest"])
        )
    if left is None and right is None:
        expected = "comparable"
    elif left is None or right is None:
        expected = "different_objectives"
    else:
        expected = (
            "unverified"
            if left["state"] != "verified" or right["state"] != "verified"
            else (
                "different_objectives"
                if left["objective_digest"] != right["objective_digest"]
                else "comparable"
            )
        )
    if recorded is None:
        require(left is None and right is None)
    else:
        require(recorded == expected)
    return expected


def _change(before, after, delta, position):
    _mapping(delta)
    material = delta.get("material_changes")
    require(
        material is None
        or isinstance(material, list)
        and all(isinstance(item, str) and item in _MATERIAL for item in material)
        and len(set(material)) == len(material)
    )
    if "material_changed" in delta:
        require(
            type(delta["material_changed"]) is bool
            and (material is None or delta["material_changed"] is bool(material))
        )
    same_mode = before.get("mode") in {"simulate", "execute"} and before.get("mode") == after.get(
        "mode"
    )
    known_objectives = (
        type(before.get("objective_reached")) is type(after.get("objective_reached")) is bool
    )
    comparability = _objective_comparability(before, after, delta)
    if not same_mode:
        relation = "mixed_or_unreported_modes"
    elif comparability == "different_objectives":
        relation = "different_objectives"
    elif comparability == "unverified":
        relation = "unverified_objective_proof"
    elif not known_objectives:
        relation = "unreported"
    else:
        relation = (
            "same_recorded_result"
            if before["objective_reached"] == after["objective_reached"]
            else "different_recorded_results"
        )
    details = delta.get("evidence_detail_delta")
    if details is not None:
        _mapping(details)
    observations = {
        name: (
            _array_count(details.get(key, _MISSING), changed=name == "changed", artifacts=True)
            if details is not None
            else None
        )
        for name, key in (
            ("added", "observed_artifacts_added"),
            ("removed", "observed_artifacts_removed"),
            ("changed", "observed_artifacts_changed"),
        )
    }
    divergence, kind = _divergence(before, after, delta)
    return {
        "compared_position": position,
        "objective_relation": relation,
        "material_changed": delta.get("material_changed"),
        "material_changes": material,
        "first_divergence_position": divergence,
        "divergence_kind": kind,
        "observations": observations,
    }


def _summary(snapshot):
    comparison = _mapping(snapshot["comparison"])
    ids, rows, deltas = comparison["run_ids"], comparison["summaries"], comparison["deltas"]
    require(
        isinstance(ids, list) and 2 <= len(ids) <= 32 and comparison["baseline_run_id"] == ids[0]
    )
    require(
        all(
            isinstance(item, str) and re.fullmatch(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}", item)
            for item in ids
        )
        and len(set(ids)) == len(ids)
    )
    require(
        isinstance(rows, list)
        and len(rows) == len(ids)
        and all(
            isinstance(row, dict) and row.get("run_id") == ids[index]
            for index, row in enumerate(rows)
        )
    )
    require(
        isinstance(deltas, list)
        and len(deltas) == len(ids) - 1
        and all(
            isinstance(row, dict)
            and row.get("from_run_id") == ids[0]
            and row.get("to_run_id") == ids[index + 1]
            for index, row in enumerate(deltas)
        )
    )
    integrity = _mapping(snapshot["source_integrity"])
    require(
        set(integrity) == {"status", "runs"}
        and isinstance(integrity["runs"], list)
        and len(integrity["runs"]) == len(ids)
    )
    sources = []
    for index, row in enumerate(integrity["runs"]):
        require(
            isinstance(row, dict)
            and set(row) == {"run_id", "status"}
            and row["run_id"] == ids[index]
            and row["status"] in {"verified", "missing", "changed", "invalid"}
        )
        sources.append({"position": index + 1, "status": row["status"]})
    require(
        integrity["status"]
        == ("verified" if all(row["status"] == "verified" for row in sources) else "unavailable")
    )
    result = {
        "schema_version": SUMMARY_SCHEMA,
        "saved_comparison": {
            "run_count": len(ids),
            "baseline_position": 1,
            "runs": [_run(row, index + 1) for index, row in enumerate(rows)],
            "changes": [
                _change(rows[0], rows[index + 1], row, index + 2)
                for index, row in enumerate(deltas)
            ],
            "legitimate_use": s3_summary(comparison.get("s3_access"), ids),
        },
        "source_integrity": {"status": integrity["status"], "runs": sources},
    }
    require(len(canonical_json_bytes(result)) <= MAX_SUMMARY_BYTES)
    return result


def context(service, value=None, *, snapshot_id=None) -> Mapping[str, Any]:
    try:
        chosen = selection(value) if value is not None else None
        identifier = chosen["snapshot_id"] if chosen is not None else snapshot_id
        require(
            isinstance(identifier, str) and re.fullmatch(r"run-comparison-[0-9a-f]{64}", identifier)
        )
        snapshot = service.comparison_snapshot(identifier)
        current = selection(
            {
                "kind": KIND,
                "snapshot_id": snapshot["snapshot_id"],
                "snapshot_digest": snapshot["digest"],
            }
        )
        require(current["snapshot_id"] == identifier and (chosen is None or current == chosen))
        summary = _summary(snapshot)
        document = {
            "schema_version": "bluefire.assistance-context.v1",
            "selected": current,
            "analysis_only": True,
            "capabilities": [],
            "reference_summary": summary,
            "limitations": list(LIMITATIONS),
        }
        return {**document, "context_digest": content_hash(document)}
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ProductStoreError("The saved comparison facts are unavailable or invalid.") from exc
