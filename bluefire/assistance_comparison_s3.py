"""Validate and minimize explicit saved S3 read comparisons without source calls."""

import re

from .product_store_errors import ProductStoreError

_ROWS = (("probe", "primary"), ("legitimate", "primary"), ("legitimate", "health"))
_PHASES = ("baseline", "retest")
_REASONS = {
    "mixed_selection",
    "unsupported_operation",
    "ambiguous_phase",
    "incompatible_context",
    "saved_context_unavailable",
    "saved_binding_invalid",
}


def require(condition):
    if not condition:
        raise ProductStoreError("The saved comparison facts are unavailable or invalid.")


def exact(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys))
    return value


def _identifier(value, pattern):
    require(isinstance(value, str) and re.fullmatch(pattern, value))


def _cell(value, run_ids):
    exact(value, ("run_id", "state", "provenance", "cleanup"))
    require(
        value["state"] in {"read", "service_denied", "unreported", "not_selected", "not_recorded"}
    )
    if value["state"] in {"not_selected", "not_recorded"}:
        require(value["run_id"] is value["provenance"] is value["cleanup"] is None)
    else:
        require(
            value["run_id"] in run_ids
            and value["provenance"] in {"synthetic", "runner_reported"}
            and value["cleanup"] in {"verified", "unknown"}
        )
    return {key: value[key] for key in ("state", "provenance", "cleanup")}


def project(value, run_ids):
    """Use only the immutable snapshot's explicit rows; never query a workflow."""
    if value is None:
        return {"state": "not_recorded"}
    require(
        isinstance(value, dict)
        and value.get("schema_version") == "bluefire.s3-access-comparison.v1"
    )
    if value.get("state") == "unavailable":
        exact(value, ("schema_version", "state", "reason", "proof_scope"))
        require(value["reason"] in _REASONS and value["proof_scope"] == "saved_read_results_only")
        return {"state": "unavailable", "reason": value["reason"]}
    exact(
        value,
        (
            "schema_version",
            "state",
            "workflow_job_id",
            "scope_digest",
            "source_digest",
            "baseline",
            "retest",
            "rows",
            "change_state",
            "gaps",
            "proof_scope",
            "effective_access_claim",
            "defensive_effectiveness_claim",
        ),
    )
    require(value["state"] in {"paired", "baseline_only", "retest_only", "partial"})
    _identifier(value["workflow_job_id"], r"job-[0-9a-f]{32}")
    for key in ("scope_digest", "source_digest"):
        _identifier(value[key], r"sha256:[0-9a-f]{64}")
    require(
        value["proof_scope"] == "saved_read_results_only"
        and value["effective_access_claim"] is False
        and value["defensive_effectiveness_claim"] is False
    )
    require(isinstance(value["rows"], list) and len(value["rows"]) == 3)
    phases = {name: value[name] for name in _PHASES}
    require(any(phase is not None for phase in phases.values()))
    selected = []
    for phase in phases.values():
        if phase is None:
            continue
        exact(
            phase,
            (
                "operation_job_id",
                "run_ids",
                "selection_complete",
                "observation_complete",
                "cleanup",
            ),
        )
        _identifier(phase["operation_job_id"], r"job-[0-9a-f]{32}")
        require(
            isinstance(phase["run_ids"], list)
            and 1 <= len(phase["run_ids"]) <= 2
            and all(isinstance(item, str) and item in run_ids for item in phase["run_ids"])
            and len(set(phase["run_ids"])) == len(phase["run_ids"])
        )
        require(
            type(phase["selection_complete"]) is bool
            and type(phase["observation_complete"]) is bool
            and phase["cleanup"] in {"verified", "unknown"}
        )
        selected.extend(phase["run_ids"])
    require(
        len(selected) == len(run_ids)
        and len(set(selected)) == len(selected)
        and set(selected) == set(run_ids)
    )
    minimized = []
    for index, raw in enumerate(value["rows"]):
        exact(raw, ("reader", "purpose", "baseline", "retest", "changed"))
        require(
            (raw["reader"], raw["purpose"]) == _ROWS[index]
            and (raw["changed"] is None or type(raw["changed"]) is bool)
        )
        minimized.append(
            {
                "reader": raw["reader"],
                "purpose": raw["purpose"],
                **{name: _cell(raw[name], run_ids) for name in _PHASES},
                "changed": raw["changed"],
            }
        )
    provenance = {
        raw[name]["provenance"]
        for raw in value["rows"]
        for name in _PHASES
        if raw[name]["run_id"] is not None
    }
    require(len(provenance) <= 1)
    for name, phase in phases.items():
        primary, legitimate, health = (raw[name] for raw in value["rows"])
        if phase is None:
            require(all(cell["state"] == "not_recorded" for cell in (primary, legitimate, health)))
            continue
        ids = [cell["run_id"] for cell in (primary, legitimate) if cell["run_id"] is not None]
        require(phase["run_ids"] == ids)
        if legitimate["state"] in {"not_recorded", "not_selected"}:
            require(health["state"] == legitimate["state"] and health["run_id"] is None)
        else:
            require(
                all(health[key] == legitimate[key] for key in ("run_id", "provenance", "cleanup"))
                and (health["state"] == "unreported") == (legitimate["state"] == "unreported")
            )
        complete = len(ids) == 2
        observed = complete and all(
            cell["state"] in {"read", "service_denied"} for cell in (primary, legitimate, health)
        )
        clean = complete and all(cell["cleanup"] == "verified" for cell in (primary, legitimate))
        require(
            phase["selection_complete"] is complete
            and phase["observation_complete"] is observed
            and phase["cleanup"] == ("verified" if clean else "unknown")
        )
    gaps = [name + "_missing" for name in _PHASES if phases[name] is None]
    gaps += [
        name + "_selection_incomplete"
        for name in _PHASES
        if phases[name] is not None and not phases[name]["selection_complete"]
    ]
    gaps += [
        name + "_observations_incomplete"
        for name in _PHASES
        if phases[name] is not None and not phases[name]["observation_complete"]
    ]
    if any(
        raw[name]["run_id"] is not None and raw[name]["cleanup"] != "verified"
        for raw in value["rows"]
        for name in _PHASES
    ):
        gaps.append("cleanup_unresolved")
    require(value["gaps"] == gaps)
    state = (
        "retest_only"
        if phases["baseline"] is None
        else "baseline_only" if phases["retest"] is None else "paired" if not gaps else "partial"
    )
    comparable = state == "paired"
    flags = [raw["baseline"]["state"] != raw["retest"]["state"] for raw in value["rows"]]
    require(
        value["state"] == state
        and all(
            raw["changed"] is (flags[index] if comparable else None)
            for index, raw in enumerate(value["rows"])
        )
    )
    change = "unknown" if not comparable else "changed" if any(flags) else "unchanged"
    require(value["change_state"] == change)
    return {
        "state": "saved_s3_read_results",
        "comparison_state": state,
        "change_state": change,
        "rows": minimized,
        "gaps": gaps,
        "proof_scope": "saved_read_results_only",
        "effective_access_claim": False,
        "defensive_effectiveness_claim": False,
    }
