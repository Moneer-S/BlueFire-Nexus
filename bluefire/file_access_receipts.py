"""Pure original-task receipt provenance for retained control revisions."""

from .domain_errors import ProductStoreError
from .util import content_hash


def original_receipts(tasks, prepared):
    known = {}
    source = prepared["source"]
    if source is not None:
        if "recovery" in source:
            for row in source["recovery"]:
                known.update(
                    {key: {"root": row["root"], **value} for key, value in row["sources"].items()}
                )
        else:
            receipt = source["creation_receipt"]
            known[receipt["receipt_id"]] = {
                "root": source["workspace"],
                "task_id": source["creation_task_id"],
                "request_hash": source["creation_request_hash"],
                "receipt": receipt,
            }
    for row in tasks:
        task, terminal = row["task"], row["terminal"]
        for receipt_id, receipt in terminal["receipt_snapshot"]["documents"].items():
            if (
                receipt["request_hash"] == task["request_hash"]
                and receipt["action_id"] == task["manifest"]["action_id"]
            ):
                known[receipt_id] = {
                    "root": task["runner_profile"]["sandbox_root"],
                    "task_id": task["task_id"],
                    "request_hash": task["request_hash"],
                    "receipt": receipt,
                }
    return known


def validate_partial_sources(prepared, tasks, control):
    inventory = control["source"].get("recovery")
    if (
        not isinstance(inventory, list)
        or not 1 <= len(inventory) <= 2
        or control["binding"] is not None
        or control["binding_digest"] != content_hash(None)
    ):
        raise ProductStoreError("Partial control lacks an exact bounded reset inventory.")
    prior = prepared["prior"]
    if control["baseline"] != (None if prior is None else prior["baseline"]):
        raise ProductStoreError("Partial recovery cannot fabricate baseline proof.")
    originals = original_receipts(tasks, prepared)
    seen = set()
    for row in inventory:
        workspace = row["workspace"]
        if (
            workspace in seen
            or workspace not in prepared["roots"]
            or row["root"] != prepared["roots"][workspace]
            or row["profile"] != prepared["profiles"][workspace]
            or row["profile_digest"] != content_hash(row["profile"])
            or row["run_id"] != prepared["run_id"]
            or set(row["sources"]) != set(row["snapshot"]["documents"])
        ):
            raise ProductStoreError(
                "Partial reset inventory changed an original workspace or profile."
            )
        seen.add(workspace)
        for identity, source in row["sources"].items():
            if {"root": row["root"], **source} != originals.get(identity) or source[
                "receipt"
            ] != row["snapshot"]["documents"][identity]:
                raise ProductStoreError(
                    "Partial reset inventory copied another task's receipt authority."
                )
