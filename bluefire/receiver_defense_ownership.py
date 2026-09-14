"""In-memory exact receiver owners; durable metadata never reconstructs authority."""

from __future__ import annotations

import re
import threading
import time
from typing import Any, Mapping

from . import product_store_receiver_defense as records
from .product_store_assistance import job_at
from .product_store_errors import ProductStoreError
from .receiver_session import OwnedReceiverSession, reconcile_retained_receiver_sessions
from .receiver_session_contract import ReceiverSessionError, validate_terminal


class ReceiverOwners:
    def __init__(self, store, *, factory=None):
        self.store = store
        self.factory = factory or self._prepare_owned
        self._owners: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._partial: dict[int, list[OwnedReceiverSession]] = {}

    def _prepare_owned(self, policy_id, *, port):
        sink: list[OwnedReceiverSession] = []
        self._partial[threading.get_ident()] = sink
        return OwnedReceiverSession.prepare(policy_id, port=port, _owner_sink=sink)

    def prepare(self, job_id, policy_id, port):
        # Retain ownership before any durable publication can fail. The factory
        # itself retains partially constructed processes using existing containment.
        try:
            owner = self.factory(policy_id, port=port)
        except BaseException:
            partial = self._partial.pop(threading.get_ident(), None)
            if partial:
                with self._lock:
                    self._owners[job_id] = partial[0]
            elif partial is not None:
                # The fixed factory failed before creating any session or child.
                records.update(self.store, job_id, {"receiver_closed": True})
            raise
        finally:
            self._partial.pop(threading.get_ident(), None)
        with self._lock:
            if job_id in self._owners:
                owner.close()
                raise ProductStoreError("An owned receiver already exists for this preparation.")
            self._owners[job_id] = owner
        return owner.review_binding

    def current(self, job_id, binding):
        with self._lock:
            owner = self._owners.get(job_id)
        if owner is None or owner.review_binding != binding:
            raise ProductStoreError(
                "Receiver ownership was lost. Clean up and explicitly prepare a new session."
            )
        owner.require_current(binding["review_digest"])
        return owner

    def reviewable(self, job_id, binding):
        # Read-only UI indication, not an authority check or process probe.
        with self._lock:
            return job_id in self._owners and time.monotonic_ns() < binding["deadline_ns"]

    def close(self, job_id):
        with self._lock:
            owner = self._owners.get(job_id)
        if owner is None:
            job = self.store.get_job(job_id)
            if not job["progress"].get("prepare_started"):
                records.update(self.store, job_id, {"receiver_closed": True})
                return True
            return job["progress"].get("receiver_closed") is True
        closed = owner.close()
        if closed:
            try:
                binding = owner.review_binding
            except ReceiverSessionError:
                # The exact retained construction attempt closed before readiness.
                records.update(
                    self.store, job_id, {"receiver_closed": True, "startup_cleanup_verified": True}
                )
            else:
                receipt = {
                    "schema_version": "bluefire.receiver-cleanup.v1",
                    "receiver_job_id": job_id,
                    "review_digest": binding["review_digest"],
                    "process_id": binding["receiver_process_id"],
                    "creation_identity": binding["creation_identity"],
                    "verified_closed": True,
                }
                records.update(
                    self.store,
                    job_id,
                    {"receiver_closed": True, "receiver_cleanup_receipt": receipt},
                )
            with self._lock:
                self._owners.pop(job_id, None)
        return closed

    def close_all(self):
        with self._lock:
            identifiers = tuple(self._owners)
        complete = True
        for identifier in identifiers:
            try:
                complete = self.close(identifier) and complete
            except Exception:
                # Continue every owned cleanup attempt and retain failing owners.
                complete = False
        try:
            retained = reconcile_retained_receiver_sessions()
            complete = retained["remaining"] == 0 and complete
        except Exception:
            complete = False
        return complete

    def dispatch(self, binding, step, bound_inputs, manifest, task_id):
        identifier = binding["receiver_job_id"]
        with self.store._connection(write=True) as connection:
            job = job_at(self.store, connection, identifier)
            prepared = records.preparation(job)
            if prepared is None:
                raise ProductStoreError("Receiver preparation is unavailable at handoff.")
            parent = records.owner_at(self.store, connection, binding["parent_job_id"], active=True)
            handoff = parent["request"]["context"]["handoff"]
            if step.step_id != handoff["handoff_step_id"]:
                if manifest["action_id"] == "sandbox.peer.handoff.v1":
                    raise ProductStoreError("An unreviewed second handoff is forbidden.")
                return
            artifact = bound_inputs.get("bundle")
            if (
                manifest["action_id"] != "sandbox.peer.handoff.v1"
                or not isinstance(artifact, Mapping)
                or artifact.get("type") != "artifact.sandbox.bundle.v1"
                or manifest.get("target_scope", {}).get("network")
                != [{"host": "127.0.0.1", "port": handoff["port"]}]
                or artifact.get("path") != "staged/bundle.jsonl"
                or artifact.get("format") != "jsonl"
                or not isinstance(artifact.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is None
                or type(artifact.get("size")) is not int
                or not 1 <= artifact["size"] <= 1024 * 1024
                or job["progress"].get("task_binding") is not None
                or job["progress"].get("decision", {}).get("decision") != "accept"
            ):
                raise ProductStoreError(
                    "The actual handoff artifact differs from its reviewed receiver contract."
                )
            actual = {"sha256": artifact["sha256"], "size_bytes": artifact["size"]}
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
        with self._lock:
            owner = self._owners.get(job_id)
        if owner is None:
            return {
                "schema_version": "bluefire.owned-receiver-observation.v1",
                "state": "insufficient_evidence",
                "reason": "The exact owned receiver terminal is unavailable.",
            }
        observed = owner.wait_observation(timeout_seconds=10)
        if observed.get("state") == "verified":
            task = job["progress"].get("task_binding")
            if (
                prepared is None
                or task is None
                or observed.get("review_binding") != prepared["session"]
            ):
                raise ProductStoreError("Receiver observation has another preparation binding.")
            expected_task = {
                "kind": "bind",
                "review_digest": prepared["session"]["review_digest"],
                **task,
            }
            if observed.get("task_binding") != expected_task:
                raise ProductStoreError("Receiver observation has another exact task binding.")
            validate_terminal(observed["terminal"], prepared["session"], expected_task)
            exit_receipt = observed.get("process_exit", {})
            if (
                exit_receipt.get("returncode") != 0
                or exit_receipt.get("process_id") != prepared["session"]["receiver_process_id"]
                or exit_receipt.get("creation_identity") != prepared["session"]["creation_identity"]
            ):
                raise ProductStoreError(
                    "Receiver process exit does not match its exact owned generation."
                )
        return dict(observed)
