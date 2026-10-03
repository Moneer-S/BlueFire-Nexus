"""Reviewed costs and fixed effect footprints for the first composition pack."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .util import content_hash, json_clone

PACK = "bluefire.receiver-composition-pack.v1"
MIB = 1024 * 1024
METHODS = (
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "sandbox.collection.stage.v1",
    "sandbox.peer.handoff.v1",
    "sandbox.cleanup.v1",
)
_WRITES = {
    METHODS[0]: ("fixtures/input.jsonl",),
    METHODS[1]: ("fixtures/transformed.jsonl",),
    METHODS[4]: ("staged/bundle.jsonl",),
}
_READS = {
    METHODS[0]: (),
    METHODS[1]: ("fixtures/input.jsonl",),
    METHODS[2]: ("fixtures/transformed.jsonl",),
    METHODS[3]: ("fixtures/transformed.jsonl",),
    METHODS[4]: ("fixtures/transformed.jsonl",),
    METHODS[5]: ("staged/bundle.jsonl",),
    METHODS[6]: (),
}
_SEMANTIC_PORTS = {
    METHODS[0]: ((), (("workspace", "workspace", False),)),
    METHODS[1]: ((("workspace", "workspace", False, True),), (("fixture", "fixture", False),)),
    METHODS[2]: ((("fixture", "fixture", False, True),), (("records", "discovery.records", True),)),
    METHODS[3]: ((("fixture", "fixture", False, True),), (("records", "discovery.records", True),)),
    METHODS[4]: ((("records", "discovery.records", True, True),), (("bundle", "bundle", False),)),
    METHODS[5]: (
        (("bundle", "bundle", False, True),),
        (("receipt", "peer-handoff.receipt", False),),
    ),
    METHODS[6]: (
        (("workspace", "workspace", False, True),),
        (("receipt", "cleanup.receipt", False),),
    ),
}
LIMIT_BOUNDS = {
    "max_attempts": (1, 32),
    "max_nodes_per_attempt": (1, 64),
    "max_edges_per_attempt": (0, 256),
    "max_business_steps": (1, 2048),
    "max_generated_bytes": (1, 1024 * MIB),
    "max_network_bytes": (1, 1024 * MIB),
    "max_peak_workspace_bytes": (1, 64 * MIB),
    "max_workspace_files": (1, 256),
    "max_retained_metadata_bytes": (1, 1024 * MIB),
    "max_reserved_attempt_ms": (1000, 86_400_000),
    "per_attempt_wall_ms": (1000, 900_000),
    "cleanup_reserve_ms": (250, 120_000),
}
RESERVATION_LIMITS = {
    "attempts": "max_attempts",
    "business_steps": "max_business_steps",
    "generated_bytes": "max_generated_bytes",
    "network_bytes": "max_network_bytes",
    "retained_metadata_bytes": "max_retained_metadata_bytes",
    "reserved_attempt_ms": "max_reserved_attempt_ms",
}


class CapabilityContractError(ValueError):
    """A proposed capability contract is unsupported or inconsistent."""


def exact(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CapabilityContractError(f"{context} has invalid fields")
    return value


def integer(value: Any, low: int, high: int, context: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise CapabilityContractError(f"{context} is outside its reviewed range")
    return value


def validate_limits(value: Any) -> dict[str, int]:
    row = exact(value, set(LIMIT_BOUNDS), "composition limits")
    result = {key: integer(row[key], *bounds, key) for key, bounds in LIMIT_BOUNDS.items()}
    if not result["cleanup_reserve_ms"] < result["per_attempt_wall_ms"]:
        raise CapabilityContractError("cleanup reserve must fit inside the attempt allowance")
    if result["per_attempt_wall_ms"] > result["max_reserved_attempt_ms"]:
        raise CapabilityContractError("attempt allowance exceeds the cumulative time allowance")
    return result


def method_cost(method_id: str) -> dict[str, Any]:
    """Conservative material bounds; metadata reservations need writer enforcement."""
    if method_id not in METHODS:
        raise CapabilityContractError("method has no reviewed composition cost contract")
    writes = _WRITES.get(method_id, ())
    body = {
        "schema_version": "bluefire.method-cost.v1",
        "pack": PACK,
        "method_id": method_id,
        "reads": list(_READS[method_id]),
        "writes": list(writes),
        "material_directories": sorted({path.split("/")[0] for path in writes}),
        "removes": "owned_receipts" if method_id == METHODS[6] else None,
        "generated_bytes": MIB * len(writes),
        "network_bytes": MIB if method_id == METHODS[5] else 0,
        "retained_metadata_bytes": 128 * 1024,
        "business_steps": 0 if method_id == METHODS[6] else 1,
        "maximum_material_file_bytes": MIB,
    }
    return {**body, "cost_digest": content_hash(body)}


def semantic_ports(method_id: str) -> tuple[tuple, tuple]:
    """The semantic I/O boundary for which the pack's effect bounds were reviewed."""
    if method_id not in _SEMANTIC_PORTS:
        raise CapabilityContractError("method has no reviewed composition semantic contract")
    inputs, outputs = _SEMANTIC_PORTS[method_id]
    return (
        tuple(
            (name, "artifact.sandbox." + kind + ".v1", multiple, required)
            for name, kind, multiple, required in inputs
        ),
        tuple(
            (
                name,
                "artifact.sandbox." + kind + (".v2" if kind == "peer-handoff.receipt" else ".v1"),
                multiple,
            )
            for name, kind, multiple in outputs
        ),
    )


def reserve_resources(
    steps: Sequence[Mapping[str, Any]], limits: Mapping[str, Any]
) -> dict[str, Any]:
    """Price a whole graph conservatively, including branches not ultimately taken."""
    checked = validate_limits(limits)
    integer(len(steps), 1, checked["max_nodes_per_attempt"], "graph node count")
    occupied: set[str] = set()
    handoffs = 0
    totals = {name: 0 for name in RESERVATION_LIMITS}
    totals.update(attempts=1, reserved_attempt_ms=checked["per_attempt_wall_ms"])
    for step in steps:
        cost = method_cost(step["behavior_id"])
        writes = set(cost["writes"])
        if writes & occupied:
            raise CapabilityContractError("graph contains conflicting fixed material writers")
        occupied.update(writes)
        handoffs += step["behavior_id"] == METHODS[5]
        for key in (
            "business_steps",
            "generated_bytes",
            "network_bytes",
            "retained_metadata_bytes",
        ):
            totals[key] += cost[key]
    if handoffs != 1:
        raise CapabilityContractError("receiver composition requires exactly one handoff")
    peak = len(occupied) * MIB
    if peak > checked["max_peak_workspace_bytes"] or len(occupied) > checked["max_workspace_files"]:
        raise CapabilityContractError("graph exceeds its workspace material allowance")
    for name, bound in RESERVATION_LIMITS.items():
        if totals[name] > checked[bound]:
            raise CapabilityContractError(f"graph exceeds its {name} allowance")
    return {
        "schema_version": "bluefire.composition-reservation.v1",
        **totals,
        "peak_workspace_bytes": peak,
        "workspace_files": len(occupied),
        "cleanup_reserve_ms": checked["cleanup_reserve_ms"],
        "material_write_slots": sorted(occupied),
    }


def accumulate_reservation(
    consumed: Mapping[str, Any], reservation: Mapping[str, Any], limits: Mapping[str, Any]
) -> dict[str, int]:
    """Account for a trusted compiled reservation inside the store claim transaction.

    The caller must independently verify the compiled document digest first; this
    arithmetic function cannot establish a reservation's graph provenance.
    """
    exact(consumed, set(RESERVATION_LIMITS), "consumed composition resources")
    checked = validate_limits(limits)
    total: dict[str, int] = {}
    for key, bound in RESERVATION_LIMITS.items():
        prior = integer(consumed[key], 0, checked[bound], key)
        amount = integer(reservation.get(key), 0, checked[bound], key)
        total[key] = integer(prior + amount, 0, checked[bound], key)
    if reservation.get("attempts") != 1:
        raise CapabilityContractError("one reservation must consume one attempt")
    return dict(json_clone(total))
