"""Bounded receiver facts from verified native receipts, without effect authority."""

import re

from .ai_assistance import RECEIVER_INSPECT, RECEIVER_TEST
from .ai_receiver_inspection import phase_context
from .ai_wire import AIProviderError
from .product_store_errors import ProductStoreError
from .receiver_defense_context import context as native_context
from .receiver_defense_context import intent, selected
from .util import content_hash

KINDS = {"receiver_scenario", "receiver_test"}
LIMITATIONS = [
    "The Assistant coordinates retained receiver tests and interprets verified development evidence.",
    "Prepare receiver is an explicit native effect; each Execute requires separate fresh approval, including Auto.",
    "Receiver runtime AI remains Off. Analysis cannot change policy, settings, approval or execution.",
    "Restoration means a fresh reviewed-records receiver, not host or VM rollback. Missing evidence is not prevention.",
]


def selection(value):
    if not isinstance(value, dict):
        raise ProductStoreError("Select a saved receiver graph or existing receiver test.")
    if value.get("kind") == "receiver_scenario" and set(value) == {
        "kind",
        "selection",
        "run_intent",
    }:
        selected(value["selection"])
        intent(value["run_intent"])
    elif value.get("kind") == "receiver_test" and set(value) == {
        "kind",
        "receiver_job_id",
        "receiver_context_digest",
    }:
        if not isinstance(value["receiver_job_id"], str) or not re.fullmatch(
            r"job-[0-9a-f]{32}", value["receiver_job_id"]
        ):
            raise ProductStoreError("Select an exact receiver owner.")
        if not isinstance(value["receiver_context_digest"], str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", value["receiver_context_digest"]
        ):
            raise ProductStoreError("Select the exact receiver context digest.")
    else:
        raise ProductStoreError("Receiver selection contains unsupported fields.")
    return dict(value)


def prefix(service, owner_id):
    """Hydrate/verify native receipts first; expose only bounded count facts to a model."""
    view = service.receiver_defense.read(owner_id)
    rows = []
    baseline = None
    for phase in view["phases"]:
        result = phase["result"]
        if result is None:
            break
        child = service.product_store.get_job(phase["receiver_job"]["job_id"])
        durable = child["progress"]["result"]
        digest = child["progress"]["result_digest"]
        if content_hash(durable) != digest:
            raise ProductStoreError("Receiver source result digest is invalid.")
        if not rows:
            baseline = result["artifact"]
        decision = result["receiver_observation"].get("terminal", {}).get("decision") or {}
        counts = decision.get("semantics") or {}
        run = result["run"]
        # Transport concerns the reviewed handoff, not the overall run (which may
        # complete its cleanup successfully after a real receiver HTTP refusal).
        handoff_id = view["context"]["handoff"]["handoff_step_id"]
        steps = [row for row in run["steps"] if row["step_id"] == handoff_id]
        status = steps[0].get("status") if len(steps) == 1 else None
        state = {
            "success": "completed",
            "failed": "failed",
            "cancelled": "cancelled",
            "interrupted": "interrupted",
        }.get(status, "unknown")
        rows.append(
            {
                "phase": phase["phase"],
                "evidence_ref": "receiver:" + phase["phase"] + ":" + child["job_id"],
                "result_digest": digest,
                "decision": result["decision"],
                "transport_state": state,
                "receiver_cleanup": (
                    "verified_closed"
                    if durable["cleanup"]["receiver"] == "verified_closed"
                    else "uncertain"
                ),
                "run_cleanup": (
                    durable["cleanup"]["run"]
                    if durable["cleanup"]["run"] in {"complete", "incomplete"}
                    else "unknown"
                ),
                "artifact_matches_baseline": (
                    result["artifact"] == baseline if result["artifact"] and baseline else None
                ),
                **{
                    key: counts.get(key)
                    for key in ("record_count", "retained_record_count", "redacted_record_count")
                },
            }
        )
    if rows:
        try:
            phase_context(rows, None)
        except AIProviderError as exc:
            raise ProductStoreError(
                "Verified receiver facts exceed the analysis contract."
            ) from exc
    return view, rows


def context(service, value):
    value = selection(value)
    creating = value["kind"] == "receiver_scenario"
    rows = []
    if creating:
        receiver = native_context(service, {key: value[key] for key in ("selection", "run_intent")})
        available = receiver["eligible"]
        path = "/compare"
    else:
        view, rows = prefix(service, value["receiver_job_id"])
        receiver = view["context"]
        if (
            receiver is None
            or receiver["context_digest"] != value["receiver_context_digest"]
            or not view["admission"]["accepted"]
        ):
            raise ProductStoreError(
                "The selected receiver context is unavailable or was not admitted."
            )
        receiver = {key: item for key, item in receiver.items() if key != "availability"}
        available = bool(rows)
        path = "/compare?receiver_job=" + value["receiver_job_id"]
    document = {
        "schema_version": "bluefire.assistance-context.v1",
        "selected": value,
        "receiver_context": receiver,
        "source_prefix": rows,
        "reference_summary": {"title": receiver["scenario_title"][:200], "phases": rows},
        "capabilities": [
            {
                "id": RECEIVER_TEST if creating else RECEIVER_INSPECT,
                "title": (
                    "Coordinate a receiver comparison"
                    if creating
                    else "Inspect receiver evidence and suggest the next phase"
                ),
                "available": available,
                "supported_autonomy": ["assist", "auto"],
                "reason": (
                    "Native preparation and each fresh Execute approval remain explicit."
                    if available
                    else "Select an eligible receiver graph or a test with verified finalized phase evidence."
                ),
                "native_path": path,
            }
        ],
        "limitations": LIMITATIONS,
    }
    return {**document, "context_digest": content_hash(document)}


def fresh(service, parent):
    retained = parent["request"]["context"]
    chosen = retained["selected"]
    if chosen["kind"] == "receiver_scenario":
        if context(service, chosen) != retained:
            raise ProductStoreError("The receiver graph or native authority changed.")
    else:
        current = context(service, chosen)
        old = retained["source_prefix"]
        if (
            current["receiver_context"] != retained["receiver_context"]
            or current["source_prefix"][: len(old)] != old
        ):
            raise ProductStoreError("The selected receiver evidence prefix changed.")
    return retained
