"""Private canonical approval and result seams for existing native execution."""

from __future__ import annotations

from datetime import datetime, timezone

from . import product_store_receiver_defense as records
from .detection_evaluations import _source, _source_binding
from .product_store_errors import ProductStoreError
from .receiver_session_contract import ReceiverSessionError
from .runner_client import RunnerTransportError
from .util import content_hash


def authority(service, marker):
    return (
        {} if marker is None else {"receiver_defense": service.receiver_defense.authority(marker)}
    )


def expiry(service, marker, *, ordinary=None):
    ordinary = ordinary or service._approval_review_expires_at()
    if marker is None:
        return ordinary
    binding = service.receiver_defense.authority(marker)
    expires = datetime.fromtimestamp(binding["session"]["expires_at_ms"] / 1000, timezone.utc)
    current = datetime.fromisoformat(ordinary.replace("Z", "+00:00"))
    return min(expires, current).isoformat().replace("+00:00", "Z")


def task_hook(service, marker):
    if marker is None:
        return None

    def dispatch(step, bound_inputs, manifest, task_id):
        try:
            service.receiver_defense.owners.dispatch(marker, step, bound_inputs, manifest, task_id)
        except (ProductStoreError, ReceiverSessionError) as exc:
            raise RunnerTransportError(
                "The exact owned receiver refused the handoff binding."
            ) from exc

    return dispatch


def finish(coordinator, job_id, marker, run_id):
    identifier = marker["receiver_job_id"]
    try:
        observed = coordinator.owners.observe(identifier)
    finally:
        closed = coordinator.owners.close(identifier)
    if run_id is None:
        records.update(
            coordinator.store,
            identifier,
            {
                "receiver_observation": observed,
                "receiver_closed": closed,
                "problem": {
                    "code": "receiver_execution_incomplete",
                    "message": "The native job did not retain a finalized run. No receiver effect will be repeated.",
                },
            },
        )
        return
    run, evidence, observed_records = _source(coordinator.service.detection_lab, run_id)
    child = coordinator.store.get_job(identifier)
    prepared = records.preparation(child)
    expected_scenario = (
        prepared["run_request"]["scenario"]
        if prepared["execution_kind"] == "scenario.run"
        else prepared["replay_preparation"]["scenario"]
    )
    if (
        run["scenario"] != expected_scenario
        or run["mode"] != "execute"
        or run["plan"]["autonomy"] != "off"
        or job_id != child["progress"].get("execution_job_id")
    ):
        raise ProductStoreError("The finalized run differs from its reviewed receiver phase.")
    decision = (
        observed.get("terminal", {}).get("decision")
        if observed.get("state") == "verified"
        else None
    )
    established = decision is not None and decision["decision"] in {"accepted", "policy_refused"}
    artifact = (
        {"sha256": decision["sha256"], "size_bytes": decision["bytes_received"]}
        if established
        else None
    )
    if (
        prepared["baseline_artifact"] is not None
        and artifact is not None
        and artifact != prepared["baseline_artifact"]
    ):
        raise ProductStoreError("The receiver terminal differs from the baseline bytes.")
    cleanup = run.get("cleanup", {})
    result = {
        "phase": marker["phase"],
        "policy_id": prepared["session"]["policy"]["policy_id"],
        "preparation_job_id": identifier,
        "execution_job_id": job_id,
        "execution_kind": prepared["execution_kind"],
        "run_id": run_id,
        "source_binding": _source_binding(run, evidence, observed_records),
        "receiver_observation": observed,
        "decision": (
            decision["decision"]
            if decision and decision["decision"] in {"accepted", "policy_refused"}
            else "insufficient_evidence"
        ),
        "artifact": artifact,
        "cleanup": {
            "receiver": "verified_closed" if closed else "uncertain",
            "run": (
                "complete"
                if cleanup.get("success") is True and cleanup.get("outstanding_receipt_count") == 0
                else "incomplete"
            ),
        },
    }
    from .receiver_defense_result import verified_result

    candidate = {
        **child,
        "progress": {
            **child["progress"],
            "result": result,
            "result_digest": content_hash(result),
            "receiver_closed": closed,
        },
    }
    verified_result(coordinator, candidate)
    records.update(
        coordinator.store,
        identifier,
        {"result": result, "result_digest": content_hash(result), "receiver_closed": closed},
    )
    records.settle_owner(coordinator.store, marker["parent_job_id"])


def settle(coordinator, job_id, marker, run_id):
    """Keep ordinary run completion independent of unavailable receiver evidence."""
    try:
        finish(coordinator, job_id, marker, run_id)
    except (ProductStoreError, ReceiverSessionError, ValueError, KeyError, TypeError):
        records.update(
            coordinator.store,
            marker["receiver_job_id"],
            {
                "finalized_run_id": run_id,
                "problem": {
                    "code": "receiver_evidence_unavailable",
                    "message": "The native run is retained, but its receiver evidence could not be verified. Inspect the run and cleanup; no receiver effect will be repeated.",
                },
            },
        )

    if coordinator.store.get_job(marker["receiver_job_id"])["progress"].get("result"):
        coordinator.service.assistance_receiver.phase_committed(marker["parent_job_id"])
