"""Shared exact receiver process ownership, independent of workflow authority."""

from __future__ import annotations

import re
import threading
import time
from typing import Any, Mapping

from .product_store_errors import ProductStoreError
from .receiver_session import OwnedReceiverSession, reconcile_retained_receiver_sessions
from .receiver_session_contract import ReceiverSessionError, validate_terminal


class OwnedReceiverRegistry:
    """Retain live owners; durable observations never reconstruct process authority."""

    def __init__(self, *, state, publish, factory=None):
        self._state = state
        self._publish = publish
        self.factory = factory or self._prepare_owned
        self._owners: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._partial: dict[int, list[OwnedReceiverSession]] = {}

    def _prepare_owned(self, policy_id, *, port):
        sink: list[OwnedReceiverSession] = []
        self._partial[threading.get_ident()] = sink
        return OwnedReceiverSession.prepare(policy_id, port=port, _owner_sink=sink)

    def prepare(self, identifier, policy_id, port):
        try:
            owner = self.factory(policy_id, port=port)
        except BaseException:
            partial = self._partial.pop(threading.get_ident(), None)
            if partial:
                with self._lock:
                    self._owners[identifier] = partial[0]
            elif partial is not None:
                self._publish(identifier, {"receiver_closed": True})
            raise
        finally:
            self._partial.pop(threading.get_ident(), None)
        with self._lock:
            if identifier in self._owners:
                owner.close()
                raise ProductStoreError("An owned receiver already exists for this preparation.")
            self._owners[identifier] = owner
        return owner.review_binding

    def current(self, identifier, binding):
        with self._lock:
            owner = self._owners.get(identifier)
        if owner is None or owner.review_binding != binding:
            raise ProductStoreError(
                "Receiver ownership was lost. Clean up and explicitly prepare a new session."
            )
        owner.require_current(binding["review_digest"])
        return owner

    def reviewable(self, identifier, binding):
        with self._lock:
            return identifier in self._owners and time.monotonic_ns() < binding["deadline_ns"]

    def close(self, identifier):
        with self._lock:
            owner = self._owners.get(identifier)
        if owner is None:
            state = self._state(identifier)
            if not state.get("prepare_started"):
                self._publish(identifier, {"receiver_closed": True})
                return True
            return state.get("receiver_closed") is True
        closed = owner.close()
        if closed:
            try:
                binding = owner.review_binding
            except ReceiverSessionError:
                self._publish(
                    identifier, {"receiver_closed": True, "startup_cleanup_verified": True}
                )
            else:
                receipt = {
                    "schema_version": "bluefire.receiver-cleanup.v1",
                    "receiver_job_id": identifier,
                    "review_digest": binding["review_digest"],
                    "process_id": binding["receiver_process_id"],
                    "creation_identity": binding["creation_identity"],
                    "verified_closed": True,
                }
                self._publish(
                    identifier,
                    {"receiver_closed": True, "receiver_cleanup_receipt": receipt},
                )
            with self._lock:
                self._owners.pop(identifier, None)
        return closed

    def close_all(self):
        with self._lock:
            identifiers = tuple(self._owners)
        complete = True
        for identifier in identifiers:
            try:
                complete = self.close(identifier) and complete
            except Exception:
                complete = False
        try:
            retained = reconcile_retained_receiver_sessions()
            complete = retained["remaining"] == 0 and complete
        except Exception:
            complete = False
        return complete

    def observe_bound(self, identifier, binding, task):
        with self._lock:
            owner = self._owners.get(identifier)
        if owner is None:
            return {
                "schema_version": "bluefire.owned-receiver-observation.v1",
                "state": "insufficient_evidence",
                "reason": "The exact owned receiver terminal is unavailable.",
            }
        observed = owner.wait_observation(timeout_seconds=10)
        if observed.get("state") == "verified":
            if binding is None or task is None or observed.get("review_binding") != binding:
                raise ProductStoreError("Receiver observation has another preparation binding.")
            expected_task = {"kind": "bind", "review_digest": binding["review_digest"], **task}
            if observed.get("task_binding") != expected_task:
                raise ProductStoreError("Receiver observation has another exact task binding.")
            validate_terminal(observed["terminal"], binding, expected_task)
            exit_receipt = observed.get("process_exit", {})
            if (
                exit_receipt.get("returncode") != 0
                or exit_receipt.get("process_id") != binding["receiver_process_id"]
                or exit_receipt.get("creation_identity") != binding["creation_identity"]
            ):
                raise ProductStoreError(
                    "Receiver process exit does not match its exact owned generation."
                )
        return dict(observed)


def handoff_artifact(step, bound_inputs, manifest, *, step_id, port):
    """Validate material and destination, leaving authority/consumption to the caller."""
    if step.step_id != step_id:
        if manifest["action_id"] == "sandbox.peer.handoff.v1":
            raise ProductStoreError("An unreviewed second handoff is forbidden.")
        return None
    artifact = bound_inputs.get("bundle")
    if (
        manifest["action_id"] != "sandbox.peer.handoff.v1"
        or not isinstance(artifact, Mapping)
        or artifact.get("type") != "artifact.sandbox.bundle.v1"
        or manifest.get("target_scope", {}).get("network") != [{"host": "127.0.0.1", "port": port}]
        or artifact.get("path") != "staged/bundle.jsonl"
        or artifact.get("format") != "jsonl"
        or not isinstance(artifact.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is None
        or type(artifact.get("size")) is not int
        or not 1 <= artifact["size"] <= 1024 * 1024
    ):
        raise ProductStoreError(
            "The actual handoff artifact differs from its reviewed receiver contract."
        )
    return {"sha256": artifact["sha256"], "size_bytes": artifact["size"]}
