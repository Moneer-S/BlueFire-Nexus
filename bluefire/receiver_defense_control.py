"""Retain a lab policy separately from its short-lived receiver processes."""

from __future__ import annotations

from . import product_store_receiver_defense as records
from .product_store_errors import ProductStoreError
from .receiver_defense_workflow import retained
from .receiver_policy import REVIEWED_RECORDS_POLICY


def source_owner(coordinator, context):
    source = context.get("source_control")
    if not source:
        return None
    parent = coordinator._job(source["job_id"])
    original = parent["request"].get("context")
    if (
        not retained(original)
        or original.get("source_control")
        or original["control"]["control_digest"] != source["control_digest"]
        or original["control"] != context["control"]
    ):
        raise ProductStoreError("The retained control does not match this experiment and scope.")
    return parent


def validate_source(coordinator, context):
    parent = source_owner(coordinator, context)
    if parent is None:
        return None
    view = coordinator.read(parent["job_id"])
    if view["control"]["status"] != "retained":
        raise ProductStoreError("The selected receiver policy is not retained.")
    baseline = coordinator.baseline(parent)
    return {
        "run_id": baseline["run_id"],
        "artifact": baseline["artifact"],
        "source_binding": baseline["source_binding"],
    }


def view(coordinator, parent, phase_views, completed):
    context = parent["request"].get("context")
    if not retained(context) or context.get("control") is None:
        return None
    source = source_owner(coordinator, context)
    if source:
        return coordinator.read(source["job_id"])["control"]
    progress = parent["progress"]
    rollback = progress.get("control_rollback")
    protected = next((phase for phase in phase_views if phase["phase"] == "protected"), None)
    accepted = (
        protected is not None and (protected.get("decision") or {}).get("decision") == "accept"
    )
    verified = protected is not None and protected["status"] == "completed"
    status = (
        "rolled_back"
        if rollback
        else (
            "retained"
            if completed
            else "verified" if verified else "accepted" if accepted else "proposed"
        )
    )
    with coordinator.store._connection() as connection:
        related = records.related_control_tests(coordinator.store, connection, parent["job_id"])
        settled = all(
            records.control_settled(coordinator.store, connection, owner) for owner in related
        )
        receiver_states = []
        for owner in related:
            for entry in [
                *owner["progress"].get("phases", {}).values(),
                *owner["progress"].get("attempt_history", []),
            ]:
                try:
                    child = records.job_at(coordinator.store, connection, entry["receiver_job_id"])
                except ProductStoreError:
                    receiver_states.append("uncertain")
                    continue
                state = child["progress"]
                if state.get("prepare_started") and not state.get("receiver_closed"):
                    prepared = records.preparation(child)
                    receiver_states.append(
                        "active"
                        if prepared
                        and coordinator.owners.reviewable(child["job_id"], prepared["session"])
                        else "uncertain"
                    )
    receiver_state = (
        "unknown"
        if "uncertain" in receiver_states
        else "active" if "active" in receiver_states else "stopped"
    )
    return {
        **context["control"],
        "owner_job_id": parent["job_id"],
        "status": status,
        "desired_policy_id": (
            REVIEWED_RECORDS_POLICY if rollback or not accepted else context["control"]["policy_id"]
        ),
        "receiver_state": receiver_state,
        "can_retest": status == "retained" and settled,
        "can_rollback": accepted and not rollback and settled,
        "rollback": rollback,
    }
