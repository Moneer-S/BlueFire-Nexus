"""Cleanup requests and durable absence receipts for a contained Strix worker."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Mapping, cast

from .strix_worker_containment_activation import (
    StrixWorkerActivationReceipt,
    StrixWorkerRevalidationReceipt,
    _clone,
)
from .strix_worker_containment_plan import (
    _CLEANUP_RECEIPT_SCHEMA,
    _CLEANUP_REQUEST_SCHEMA,
    StrixWorkerContainmentError,
    StrixWorkerReplayState,
    _after,
    _attempt,
    _boolean,
    _digest,
    _exact,
    _integer,
    _text,
    _timestamp,
)
from .util import canonical_json_bytes, content_hash


@dataclass(frozen=True, slots=True)
class StrixWorkerCleanupRequest:
    schema_version: str
    activation_ref: str
    plan_ref: str
    attempt_id: str
    binding_digest: str
    controller_generation: int
    controller_boot_id_digest: str
    requested_at: str
    request_ref: str

    @classmethod
    def create(
        cls, activation: StrixWorkerActivationReceipt, *, requested_at: str
    ) -> "StrixWorkerCleanupRequest":
        original = activation.document
        row = {
            "schema_version": _CLEANUP_REQUEST_SCHEMA,
            "activation_ref": activation.receipt_ref,
            "plan_ref": original["plan_ref"],
            "attempt_id": original["attempt_id"],
            "binding_digest": original["binding_digest"],
            "controller_generation": original["controller_generation"],
            "controller_boot_id_digest": original["controller_boot_id_digest"],
            "requested_at": _timestamp(requested_at, "cleanup request"),
        }
        row["request_ref"] = content_hash(row)
        return cls.from_mapping(row, activation)

    @classmethod
    def from_mapping(
        cls, value: Any, activation: StrixWorkerActivationReceipt
    ) -> "StrixWorkerCleanupRequest":
        row = _exact(value, set(cls.__dataclass_fields__), "worker cleanup request")
        parsed = cls(
            schema_version=_text(row["schema_version"], "cleanup request version"),
            activation_ref=_digest(row["activation_ref"], "activation reference"),
            plan_ref=_digest(row["plan_ref"], "plan reference"),
            attempt_id=_attempt(row["attempt_id"]),
            binding_digest=_digest(row["binding_digest"], "binding"),
            controller_generation=_integer(
                row["controller_generation"], "controller generation", 1, 2**31 - 1
            ),
            controller_boot_id_digest=_digest(
                row["controller_boot_id_digest"], "controller boot ID"
            ),
            requested_at=_timestamp(row["requested_at"], "cleanup request"),
            request_ref=_digest(row["request_ref"], "cleanup request"),
        )
        original = activation.document
        expected = {
            "schema_version": _CLEANUP_REQUEST_SCHEMA,
            "activation_ref": activation.receipt_ref,
            "plan_ref": original["plan_ref"],
            "attempt_id": original["attempt_id"],
            "binding_digest": original["binding_digest"],
            "controller_generation": original["controller_generation"],
            "controller_boot_id_digest": original["controller_boot_id_digest"],
        }
        if any(getattr(parsed, name) != item for name, item in expected.items()):
            raise StrixWorkerContainmentError("worker cleanup request is not bound")
        _after(
            parsed.requested_at,
            original["observed_at"],
            "cleanup request",
            maximum=timedelta(minutes=30),
        )
        unsigned = parsed.to_dict()
        unsigned.pop("request_ref")
        if parsed.request_ref != content_hash(unsigned):
            raise StrixWorkerContainmentError("worker cleanup request digest is invalid")
        return parsed

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


def validate_revalidation_receipt(
    activation: StrixWorkerActivationReceipt, value: Any
) -> StrixWorkerRevalidationReceipt:
    return StrixWorkerRevalidationReceipt.from_mapping(value, activation)


def validate_cleanup_request(
    activation: StrixWorkerActivationReceipt, value: Any
) -> StrixWorkerCleanupRequest:
    return StrixWorkerCleanupRequest.from_mapping(value, activation)


@dataclass(frozen=True, slots=True)
class StrixWorkerCleanupReceipt:
    _canonical: bytes

    @property
    def document(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], json.loads(self._canonical))

    @classmethod
    def from_mapping(
        cls,
        value: Any,
        activation: StrixWorkerActivationReceipt,
        request: StrixWorkerCleanupRequest,
    ) -> "StrixWorkerCleanupReceipt":
        fields = {
            "schema_version",
            "activation_ref",
            "request_ref",
            "plan_ref",
            "attempt_id",
            "binding_digest",
            "controller_generation",
            "controller_boot_id_digest",
            "observed_at",
            "pidfd_ref",
            "host_pid",
            "start_ticks",
            "cgroup_ref",
            "cgroup_inode",
            "identity_lease_ref",
            "rootfs_identity_digest",
            "cancellation_requested",
            "pidfd_exit_observed",
            "process_absent",
            "cgroup_kill_used",
            "cgroup_empty",
            "cgroup_removed",
            "namespaces_absent",
            "private_roots_absent",
            "rootfs_absent",
            "relays_closed",
            "input_fds_closed",
            "identity_absent",
            "identity_lease_released",
            "receipt_ref",
        }
        row = _exact(value, fields, "worker cleanup receipt")
        original = activation.document
        canonical = {
            "schema_version": _text(row["schema_version"], "cleanup receipt version"),
            "activation_ref": _digest(row["activation_ref"], "activation reference"),
            "request_ref": _digest(row["request_ref"], "cleanup request reference"),
            "plan_ref": _digest(row["plan_ref"], "plan reference"),
            "attempt_id": _attempt(row["attempt_id"]),
            "binding_digest": _digest(row["binding_digest"], "binding"),
            "controller_generation": _integer(
                row["controller_generation"], "controller generation", 1, 2**31 - 1
            ),
            "controller_boot_id_digest": _digest(
                row["controller_boot_id_digest"], "controller boot ID"
            ),
            "observed_at": _timestamp(row["observed_at"], "cleanup observation"),
            "pidfd_ref": _digest(row["pidfd_ref"], "cleaned pidfd"),
            "host_pid": _integer(row["host_pid"], "cleaned host PID", 2, 2**31 - 1),
            "start_ticks": _integer(
                row["start_ticks"], "cleaned process start ticks", 1, 2**63 - 1
            ),
            "cgroup_ref": _digest(row["cgroup_ref"], "cleaned cgroup"),
            "cgroup_inode": _integer(row["cgroup_inode"], "cleaned cgroup inode", 1, 2**63 - 1),
            "identity_lease_ref": _digest(row["identity_lease_ref"], "released identity lease"),
            "rootfs_identity_digest": _digest(row["rootfs_identity_digest"], "removed rootfs identity"),
            "cancellation_requested": _boolean(
                row["cancellation_requested"], "cancellation request", True
            ),
            "pidfd_exit_observed": _boolean(
                row["pidfd_exit_observed"], "pidfd exit observation", True
            ),
            "process_absent": _boolean(row["process_absent"], "worker process absence", True),
            "cgroup_kill_used": _boolean(row["cgroup_kill_used"], "cgroup.kill use"),
            "cgroup_empty": _boolean(row["cgroup_empty"], "empty cgroup", True),
            "cgroup_removed": _boolean(row["cgroup_removed"], "removed cgroup", True),
            "namespaces_absent": _boolean(row["namespaces_absent"], "namespace absence", True),
            "private_roots_absent": _boolean(
                row["private_roots_absent"], "private-root absence", True
            ),
            "rootfs_absent": _boolean(row["rootfs_absent"], "private rootfs absence", True),
            "relays_closed": _boolean(row["relays_closed"], "relay closure", True),
            "input_fds_closed": _boolean(row["input_fds_closed"], "input descriptor closure", True),
            "identity_absent": _boolean(row["identity_absent"], "identity absence", True),
            "identity_lease_released": _boolean(
                row["identity_lease_released"], "identity lease release", True
            ),
            "receipt_ref": _digest(row["receipt_ref"], "cleanup receipt"),
        }
        expected = {
            "schema_version": _CLEANUP_RECEIPT_SCHEMA,
            "activation_ref": activation.receipt_ref,
            "request_ref": request.request_ref,
            "plan_ref": original["plan_ref"],
            "attempt_id": original["attempt_id"],
            "binding_digest": original["binding_digest"],
            "controller_generation": original["controller_generation"],
            "controller_boot_id_digest": original["controller_boot_id_digest"],
            "pidfd_ref": original["process"]["pidfd_ref"],
            "host_pid": original["process"]["host_pid"],
            "start_ticks": original["process"]["start_ticks"],
            "cgroup_ref": original["cgroup"]["cgroup_ref"],
            "cgroup_inode": original["cgroup"]["inode"],
            "identity_lease_ref": original["identity"]["lease_ref"],
            "rootfs_identity_digest": original["mount_policy"]["rootfs_identity_digest"],
        }
        if any(canonical[name] != expected[name] for name in expected):
            raise StrixWorkerContainmentError("worker cleanup does not bind the activation")
        _after(
            cast(str, canonical["observed_at"]),
            request.requested_at,
            "cleanup observation",
            maximum=timedelta(minutes=10),
        )
        if canonical["receipt_ref"] != content_hash(
            {name: item for name, item in canonical.items() if name != "receipt_ref"}
        ):
            raise StrixWorkerContainmentError("worker cleanup receipt digest is invalid")
        return cls(canonical_json_bytes(canonical))

    @property
    def receipt_ref(self) -> str:
        return str(self.document["receipt_ref"])

    def to_dict(self) -> dict[str, Any]:
        return dict(self.document)


def validate_cleanup_receipt(
    activation: StrixWorkerActivationReceipt,
    request: StrixWorkerCleanupRequest,
    value: Any,
    replay: StrixWorkerReplayState,
) -> StrixWorkerCleanupReceipt:
    request = StrixWorkerCleanupRequest.from_mapping(request.to_dict(), activation)
    replay = StrixWorkerReplayState.from_mapping(replay.to_dict())
    if replay.ledger_ref != activation.document["replay_ledger_ref"]:
        raise StrixWorkerContainmentError("worker replay ledger does not match the activation")
    receipt = StrixWorkerCleanupReceipt.from_mapping(value, activation, request)
    original = activation.document
    if (
        replay.generation < original["replay_generation"] + 2
        or original["replay_head_digest"] not in replay.ancestor_head_digests
        or activation.receipt_ref not in replay.consumed_activation_refs
        or original["identity"]["lease_ref"] not in replay.consumed_identity_lease_refs
        or request.request_ref not in replay.consumed_cleanup_request_refs
        or activation.receipt_ref not in replay.consumed_cleanup_activation_refs
    ):
        raise StrixWorkerContainmentError("worker cleanup is not committed to the replay ledger")
    return receipt


def receipt_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """Return a document with its deterministic ``receipt_ref`` populated."""

    if "receipt_ref" in document:
        raise StrixWorkerContainmentError("receipt document already contains receipt_ref")
    result = cast(dict[str, Any], _clone(dict(document)))
    result["receipt_ref"] = content_hash(result)
    return result
