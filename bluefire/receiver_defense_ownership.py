"""In-memory exact receiver owners; durable metadata never reconstructs authority."""

from __future__ import annotations

from . import product_store_receiver_defense as records
from . import receiver_defense_workflow as workflow
from .owned_receiver_registry import OwnedReceiverRegistry, handoff_artifact
from .product_store_assistance import job_at
from .product_store_errors import ProductStoreError


class ReceiverOwners(OwnedReceiverRegistry):
    def __init__(self, store, *, factory=None):
        self.store = store
        super().__init__(
            state=lambda identifier: store.get_job(identifier)["progress"],
            publish=lambda identifier, update: records.update(store, identifier, update),
            factory=factory,
        )

    def dispatch(self, binding, step, bound_inputs, manifest, task_id):
        identifier = binding["receiver_job_id"]
        with self.store._connection(write=True) as connection:
            job = job_at(self.store, connection, identifier)
            prepared = records.preparation(job)
            if prepared is None:
                raise ProductStoreError("Receiver preparation is unavailable at handoff.")
            parent = records.owner_at(self.store, connection, binding["parent_job_id"], active=True)
            current = parent["request"]["context"]
            if prepared["session"]["policy"]["policy_id"] != workflow.policy(
                current, binding["phase"]
            ):
                raise ProductStoreError("The actual receiver policy changed before handoff.")
            if workflow.retained(current) and prepared.get("control_binding") != current["control"]:
                raise ProductStoreError("The retained receiver control changed before handoff.")
            handoff = current["handoff"]
            actual = handoff_artifact(
                step,
                bound_inputs,
                manifest,
                step_id=handoff["handoff_step_id"],
                port=handoff["port"],
            )
            if actual is None:
                return
            if (
                job["progress"].get("task_binding") is not None
                or job["progress"].get("decision", {}).get("decision") != "accept"
            ):
                raise ProductStoreError(
                    "The actual handoff artifact differs from its reviewed receiver contract."
                )
            if (
                prepared["baseline_artifact"] is not None
                and actual != prepared["baseline_artifact"]
            ):
                raise ProductStoreError(
                    "The replay bytes differ from the authenticated baseline; handoff was refused."
                )
            owner = self.current(identifier, prepared["session"])
            task = {"task_id": task_id, **actual}
            # Persist consumption before the ambiguous private write. Never retry
            # this task after a failed write or service/process loss.
            records.safe_patch(connection, job, {"task_binding": task})
        owner.bind_task(
            task_id,
            digest=actual["sha256"],
            size=actual["size_bytes"],
            review_digest=prepared["session"]["review_digest"],
        )
        with self.store._connection() as connection:
            records.owner_at(self.store, connection, binding["parent_job_id"], active=True)

    def observe(self, job_id):
        job = self.store.get_job(job_id)
        prepared = records.preparation(job)
        return self.observe_bound(
            job_id, prepared["session"] if prepared else None, job["progress"].get("task_binding")
        )
