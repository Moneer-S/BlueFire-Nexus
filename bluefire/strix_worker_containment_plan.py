"""Plan and replay facts for one controller-owned Linux Strix worker.

This module performs no OS work. Receipts are evidence, not authority; the
controller retains live pidfd, cgroup, relay, and namespace descriptors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, TypeAlias, cast

from . import strix_worker_containment_identity as _identity_contract
from .util import content_hash, parse_iso8601_datetime

_INPUT_KINDS, _RELAY_PURPOSES = _identity_contract.INPUT_KINDS, _identity_contract.RELAY_PURPOSES
RelayPlan: TypeAlias = _identity_contract.RelayPlan
SealedInputPlan: TypeAlias = _identity_contract.SealedInputPlan
StrixWorkerContainmentError = _identity_contract.StrixWorkerContainmentError
retained_kernel_identity_digest = _identity_contract.retained_kernel_identity_digest
_digest, _exact = _identity_contract.digest, _identity_contract.exact
_integer, _text = _identity_contract.integer, _identity_contract.text

_PLAN_SCHEMA = "bluefire.strix-worker-containment-plan.v1"
_ACTIVATION_SCHEMA = "bluefire.strix-worker-containment-activation.v1"
_REVALIDATION_SCHEMA = "bluefire.strix-worker-containment-revalidation.v1"
_CLEANUP_REQUEST_SCHEMA = "bluefire.strix-worker-containment-cleanup.v1"
_CLEANUP_RECEIPT_SCHEMA = "bluefire.strix-worker-containment-cleanup-receipt.v1"
_REPLAY_SCHEMA = "bluefire.strix-worker-containment-replay.v1"
_ATTEMPT = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_INPUT_PATHS = {
    "config": "/inputs/config.json",
    "mcp": "/inputs/mcp.json",
    "objective": "/inputs/objective.json",
}
_ROOT_PURPOSES = ("config", "home", "tmp", "workspace")
_NAMESPACE_KINDS = ("ipc", "mount", "network", "pid", "uts")
_SEALS = ("grow", "seal", "shrink", "write")
_BLOCKED_SYSCALLS = (
    "bpf",
    "clone3",
    "execve",
    "execveat",
    "fork",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "keyctl",
    "mount",
    "move_mount",
    "open_by_handle_at",
    "perf_event_open",
    "pivot_root",
    "ptrace",
    "setns",
    "unshare",
    "vfork",
)


def _attempt(value: Any) -> str:
    result = _text(value, "attempt ID", 47)
    if _ATTEMPT.fullmatch(result) is None:
        raise StrixWorkerContainmentError("attempt ID is invalid")
    return result


def _boolean(value: Any, label: str, expected: bool | None = None) -> bool:
    if not isinstance(value, bool) or (expected is not None and value is not expected):
        raise StrixWorkerContainmentError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    result = _text(value, label, 40)
    try:
        parse_iso8601_datetime(result)
    except ValueError as exc:
        raise StrixWorkerContainmentError(f"{label} is not bounded RFC 3339") from exc
    return result


def _after(
    later: str,
    earlier: str,
    label: str,
    *,
    maximum: timedelta | None = None,
    strict: bool = False,
) -> None:
    delta = parse_iso8601_datetime(later) - parse_iso8601_datetime(earlier)
    if (
        delta < timedelta(0)
        or (strict and delta == timedelta(0))
        or (maximum is not None and delta > maximum)
    ):
        raise StrixWorkerContainmentError(f"{label} chronology is invalid")


def _sorted_unique(value: Any, label: str, allowed: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise StrixWorkerContainmentError(f"{label} is invalid")
    result = tuple(_text(item, label, 64) for item in value)
    if result != tuple(sorted(set(result))) or any(item not in allowed for item in result):
        raise StrixWorkerContainmentError(f"{label} is invalid")
    return result


def _digest_list(value: Any, label: str, maximum: int = 64) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise StrixWorkerContainmentError(f"{label} is invalid")
    result = tuple(_digest(item, label) for item in value)
    if result != tuple(sorted(set(result))):
        raise StrixWorkerContainmentError(f"{label} must be unique and sorted")
    return result


@dataclass(frozen=True, slots=True)
class StrixWorkerContainmentPlan:
    schema_version: str
    attempt_id: str
    claim_digest: str
    binding_digest: str
    delegation_digest: str
    runtime_qualification_ref: str
    installed_projection_ref: str
    startup_overlay_ref: str
    sealed_inputs_ref: str
    admission_record_ref: str
    resource_identity_ref: str
    invocation_digest: str
    executable_digest: str
    package_digest: str
    boundary_helper_digest: str
    replay_ledger_ref: str
    replay_generation: int
    replay_head_digest: str
    controller_generation: int
    controller_boot_id_digest: str
    controller_peer_host_pid: int
    controller_peer_start_ticks: int
    controller_peer_process_ref: str
    controller_uid: int
    controller_gid: int
    controller_rpc_channel_ref: str
    controller_rpc_socket_identity_digest: str
    controller_rpc_socket_st_dev: int
    controller_rpc_socket_st_ino: int
    controller_rpc_policy_digest: str
    controller_rpc_transport: str
    controller_rpc_passcred: bool
    pid_namespace_profile: str
    uid: int
    gid: int
    identity_generation: int
    identity_lease_ref: str
    cgroup_ref: str
    pids_max: int
    seccomp_policy_digest: str
    clone_filter_digest: str
    network_policy_digest: str
    mount_policy_digest: str
    config_root_identity_digest: str
    home_root_identity_digest: str
    tmp_root_identity_digest: str
    workspace_root_identity_digest: str
    memory_max_bytes: int
    cpu_quota_micros: int
    cpu_period_micros: int
    sealed_inputs: tuple[SealedInputPlan, ...]
    relays: tuple[RelayPlan, ...]
    created_at: str
    expires_at: str

    @classmethod
    def from_mapping(cls, value: Any) -> "StrixWorkerContainmentPlan":
        row = _exact(value, set(cls.__dataclass_fields__), "worker containment plan")
        inputs = tuple(
            SealedInputPlan.from_mapping(item)
            for item in _list(row["sealed_inputs"], 3, 3, "sealed inputs")
        )
        relays = tuple(
            RelayPlan.from_mapping(item) for item in _list(row["relays"], 2, 2, "worker relays")
        )
        result = cls(
            schema_version=_text(row["schema_version"], "plan version"),
            attempt_id=_attempt(row["attempt_id"]),
            claim_digest=_digest(row["claim_digest"], "claim"),
            binding_digest=_digest(row["binding_digest"], "binding"),
            delegation_digest=_digest(row["delegation_digest"], "delegation"),
            runtime_qualification_ref=_digest(
                row["runtime_qualification_ref"], "runtime qualification"
            ),
            installed_projection_ref=_digest(
                row["installed_projection_ref"], "installed runtime projection"
            ),
            startup_overlay_ref=_digest(row["startup_overlay_ref"], "startup overlay"),
            sealed_inputs_ref=_digest(row["sealed_inputs_ref"], "sealed input projection"),
            admission_record_ref=_digest(row["admission_record_ref"], "admission record"),
            resource_identity_ref=_digest(row["resource_identity_ref"], "resource identity"),
            invocation_digest=_digest(row["invocation_digest"], "worker invocation"),
            executable_digest=_digest(row["executable_digest"], "worker executable"),
            package_digest=_digest(row["package_digest"], "worker package"),
            boundary_helper_digest=_digest(row["boundary_helper_digest"], "native boundary helper"),
            replay_ledger_ref=_digest(row["replay_ledger_ref"], "worker replay ledger"),
            replay_generation=_integer(
                row["replay_generation"], "worker replay generation", 0, 2**63 - 1
            ),
            replay_head_digest=_digest(row["replay_head_digest"], "worker replay head"),
            controller_generation=_integer(
                row["controller_generation"], "controller generation", 1, 2**31 - 1
            ),
            controller_boot_id_digest=_digest(
                row["controller_boot_id_digest"], "controller boot ID"
            ),
            controller_peer_host_pid=_integer(
                row["controller_peer_host_pid"], "controller peer host PID", 2, 2**31 - 1
            ),
            controller_peer_start_ticks=_integer(
                row["controller_peer_start_ticks"], "controller peer start ticks", 1, 2**63 - 1
            ),
            controller_peer_process_ref=_digest(
                row["controller_peer_process_ref"], "controller peer process"
            ),
            controller_uid=_integer(row["controller_uid"], "controller UID", 0, 2**31 - 2),
            controller_gid=_integer(row["controller_gid"], "controller GID", 0, 2**31 - 2),
            controller_rpc_channel_ref=_digest(
                row["controller_rpc_channel_ref"], "controller RPC channel"
            ),
            controller_rpc_socket_identity_digest=_digest(
                row["controller_rpc_socket_identity_digest"], "controller RPC socket identity"
            ),
            controller_rpc_socket_st_dev=_integer(
                row["controller_rpc_socket_st_dev"], "controller RPC socket device", 0, 2**64 - 1
            ),
            controller_rpc_socket_st_ino=_integer(
                row["controller_rpc_socket_st_ino"], "controller RPC socket inode", 1, 2**64 - 1
            ),
            controller_rpc_policy_digest=_digest(
                row["controller_rpc_policy_digest"], "controller RPC policy"
            ),
            controller_rpc_transport=_text(
                row["controller_rpc_transport"], "controller RPC transport", 32
            ),
            controller_rpc_passcred=_boolean(
                row["controller_rpc_passcred"], "controller RPC SO_PASSCRED", True
            ),
            pid_namespace_profile=_text(row["pid_namespace_profile"], "PID namespace profile", 32),
            uid=_integer(row["uid"], "worker UID", 1000, 2**31 - 2),
            gid=_integer(row["gid"], "worker GID", 1000, 2**31 - 2),
            identity_generation=_integer(
                row["identity_generation"], "identity generation", 1, 2**31 - 1
            ),
            identity_lease_ref=_digest(row["identity_lease_ref"], "identity lease"),
            cgroup_ref=_digest(row["cgroup_ref"], "worker cgroup"),
            pids_max=_integer(row["pids_max"], "worker task limit", 4, 64),
            seccomp_policy_digest=_digest(row["seccomp_policy_digest"], "seccomp policy"),
            clone_filter_digest=_digest(row["clone_filter_digest"], "clone filter"),
            network_policy_digest=_digest(row["network_policy_digest"], "network policy"),
            mount_policy_digest=_digest(row["mount_policy_digest"], "mount policy"),
            config_root_identity_digest=_digest(
                row["config_root_identity_digest"], "config root identity"
            ),
            home_root_identity_digest=_digest(
                row["home_root_identity_digest"], "home root identity"
            ),
            tmp_root_identity_digest=_digest(
                row["tmp_root_identity_digest"], "temporary root identity"
            ),
            workspace_root_identity_digest=_digest(
                row["workspace_root_identity_digest"], "workspace root identity"
            ),
            memory_max_bytes=_integer(
                row["memory_max_bytes"], "memory limit", 128 * 1024**2, 8 * 1024**3
            ),
            cpu_quota_micros=_integer(row["cpu_quota_micros"], "CPU quota", 1_000, 10_000_000),
            cpu_period_micros=_integer(row["cpu_period_micros"], "CPU period", 1_000, 1_000_000),
            sealed_inputs=inputs,
            relays=relays,
            created_at=_timestamp(row["created_at"], "plan creation"),
            expires_at=_timestamp(row["expires_at"], "plan expiry"),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if self.schema_version != _PLAN_SCHEMA:
            raise StrixWorkerContainmentError("worker containment plan version is unsupported")
        if tuple(item.kind for item in self.sealed_inputs) != _INPUT_KINDS:
            raise StrixWorkerContainmentError("sealed inputs must be complete and sorted")
        if tuple(item.purpose for item in self.relays) != _RELAY_PURPOSES:
            raise StrixWorkerContainmentError("worker relays must be complete and sorted")
        if len({item.port for item in self.relays}) != len(self.relays):
            raise StrixWorkerContainmentError("worker relay ports must be distinct")
        relay_namespaces = {
            (
                item.network_namespace_ref,
                item.network_namespace_st_dev,
                item.network_namespace_st_ino,
            )
            for item in self.relays
        }
        if len(relay_namespaces) != 1:
            raise StrixWorkerContainmentError(
                "worker relays must share the exact worker network namespace"
            )
        if self.pid_namespace_profile != "host-pid-authenticated":
            raise StrixWorkerContainmentError("PID namespace profile is unsupported")
        if self.uid == self.controller_uid or self.gid == self.controller_gid:
            raise StrixWorkerContainmentError(
                "worker identity is not disposable from controller identity"
            )
        if (
            self.controller_rpc_transport != "af_unix_sock_seqpacket"
            or self.controller_rpc_socket_identity_digest
            != retained_kernel_identity_digest(
                role="controller-rpc-sock-seqpacket",
                st_dev=self.controller_rpc_socket_st_dev,
                st_ino=self.controller_rpc_socket_st_ino,
            )
        ):
            raise StrixWorkerContainmentError("controller RPC channel identity is invalid")
        _after(
            self.expires_at,
            self.created_at,
            "plan lifetime",
            maximum=timedelta(minutes=30),
            strict=True,
        )

    @property
    def plan_ref(self) -> str:
        return cast(str, content_hash(self.to_dict()))

    def to_dict(self) -> dict[str, Any]:
        return {
            **{
                name: getattr(self, name)
                for name in (
                    "schema_version",
                    "attempt_id",
                    "claim_digest",
                    "binding_digest",
                    "delegation_digest",
                    "runtime_qualification_ref",
                    "installed_projection_ref",
                    "startup_overlay_ref",
                    "sealed_inputs_ref",
                    "admission_record_ref",
                    "resource_identity_ref",
                    "invocation_digest",
                    "executable_digest",
                    "package_digest",
                    "boundary_helper_digest",
                    "replay_ledger_ref",
                    "replay_generation",
                    "replay_head_digest",
                    "controller_generation",
                    "controller_boot_id_digest",
                    "controller_peer_host_pid",
                    "controller_peer_start_ticks",
                    "controller_peer_process_ref",
                    "controller_uid",
                    "controller_gid",
                    "controller_rpc_channel_ref",
                    "controller_rpc_socket_identity_digest",
                    "controller_rpc_socket_st_dev",
                    "controller_rpc_socket_st_ino",
                    "controller_rpc_policy_digest",
                    "controller_rpc_transport",
                    "controller_rpc_passcred",
                    "pid_namespace_profile",
                    "uid",
                    "gid",
                    "identity_generation",
                    "identity_lease_ref",
                    "cgroup_ref",
                    "pids_max",
                    "seccomp_policy_digest",
                    "clone_filter_digest",
                    "network_policy_digest",
                    "mount_policy_digest",
                    "config_root_identity_digest",
                    "home_root_identity_digest",
                    "tmp_root_identity_digest",
                    "workspace_root_identity_digest",
                    "memory_max_bytes",
                    "cpu_quota_micros",
                    "cpu_period_micros",
                )
            },
            "sealed_inputs": [item.to_dict() for item in self.sealed_inputs],
            "relays": [item.to_dict() for item in self.relays],
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


def _list(value: Any, minimum: int, maximum: int, label: str) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise StrixWorkerContainmentError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class StrixWorkerReplayState:
    schema_version: str
    ledger_ref: str
    generation: int
    head_digest: str
    ancestor_head_digests: tuple[str, ...]
    consumed_activation_refs: tuple[str, ...]
    consumed_cleanup_request_refs: tuple[str, ...]
    consumed_cleanup_activation_refs: tuple[str, ...]
    consumed_identity_lease_refs: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Any) -> "StrixWorkerReplayState":
        row = _exact(value, set(cls.__dataclass_fields__), "worker replay state")
        result = cls(
            schema_version=_text(row["schema_version"], "replay version"),
            ledger_ref=_digest(row["ledger_ref"], "replay ledger"),
            generation=_integer(row["generation"], "replay generation", 0, 2**63 - 1),
            head_digest=_digest(row["head_digest"], "replay head"),
            ancestor_head_digests=_digest_list(row["ancestor_head_digests"], "replay ancestors"),
            consumed_activation_refs=_digest_list(
                row["consumed_activation_refs"], "consumed activations"
            ),
            consumed_cleanup_request_refs=_digest_list(
                row["consumed_cleanup_request_refs"], "consumed cleanup requests"
            ),
            consumed_cleanup_activation_refs=_digest_list(
                row["consumed_cleanup_activation_refs"], "cleaned worker activations"
            ),
            consumed_identity_lease_refs=_digest_list(
                row["consumed_identity_lease_refs"], "consumed identity leases"
            ),
        )
        if (
            result.schema_version != _REPLAY_SCHEMA
            or result.head_digest in result.ancestor_head_digests
        ):
            raise StrixWorkerContainmentError("worker replay state is invalid")
        return result

    @classmethod
    def empty(
        cls, *, ledger_ref: str, head_digest: str, generation: int = 0
    ) -> "StrixWorkerReplayState":
        return cls.from_mapping(
            {
                "schema_version": _REPLAY_SCHEMA,
                "ledger_ref": ledger_ref,
                "generation": generation,
                "head_digest": head_digest,
                "ancestor_head_digests": [],
                "consumed_activation_refs": [],
                "consumed_cleanup_request_refs": [],
                "consumed_cleanup_activation_refs": [],
                "consumed_identity_lease_refs": [],
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "ledger_ref": self.ledger_ref,
            "generation": self.generation,
            "head_digest": self.head_digest,
            "ancestor_head_digests": list(self.ancestor_head_digests),
            "consumed_activation_refs": list(self.consumed_activation_refs),
            "consumed_cleanup_request_refs": list(self.consumed_cleanup_request_refs),
            "consumed_cleanup_activation_refs": list(self.consumed_cleanup_activation_refs),
            "consumed_identity_lease_refs": list(self.consumed_identity_lease_refs),
        }
