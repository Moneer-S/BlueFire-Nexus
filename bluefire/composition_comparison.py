"""Read-only capability objective proof for new run comparisons."""

from __future__ import annotations

from typing import Any

from .capability_packs import grant_pack
from .product_store_errors import ProductStoreError
from .run_store import RunStoreError
from .util import content_hash

SCHEMA = "bluefire.composition-objective-projection.v1"


def projections(service: Any, run_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Join only exact persisted run/attempt pairs and recompute settled proof."""
    result: dict[str, dict[str, Any]] = {}
    for run_id in run_ids:
        attempt = service.product_store.get_capability_attempt_for_run(run_id)
        if attempt is None:
            continue
        lease = attempt["lease"]
        if lease["run_id"] != run_id:
            raise ProductStoreError("Capability comparison run binding changed.")
        grant = service.product_store.get_capability_grant(
            lease["grant_id"], now_ms=service.composition.clock()
        )["document"]
        if grant["grant_digest"] != lease["grant_digest"]:
            raise ProductStoreError("Capability comparison grant binding changed.")
        objective_digest = content_hash(
            {"pack": grant_pack(grant), "predicate": grant["objective"]["predicate"]}
        )
        established: bool | None = None
        result_digest: str | None = None
        if attempt["state"] == "settled":
            try:
                verified = service.composition._verified_result(attempt)
            except (ProductStoreError, RunStoreError, KeyError, TypeError, ValueError):
                pass
            else:
                objective = verified.get("objective")
                if (
                    verified.get("run_id") != run_id
                    or not isinstance(objective, dict)
                    or type(objective.get("established")) is not bool
                ):
                    raise ProductStoreError("Capability comparison proof has another objective.")
                established = objective["established"]
                result_digest = content_hash(verified)
        result[run_id] = {
            "schema_version": SCHEMA,
            "run_id": run_id,
            "attempt_id": attempt["attempt_id"],
            "state": "verified" if established is not None else "unverified",
            "objective_digest": objective_digest,
            "established": established,
            "result_digest": result_digest,
        }
    return result
