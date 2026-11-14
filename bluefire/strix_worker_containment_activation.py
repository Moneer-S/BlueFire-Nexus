"""Activation and revalidation receipts for a contained Strix worker."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Mapping, cast

from .strix_worker_containment_identity import RelayPlan, retained_kernel_identity_digest
from .strix_worker_containment_plan import (
    _ACTIVATION_SCHEMA,
    _BLOCKED_SYSCALLS,
    _INPUT_KINDS,
    _INPUT_PATHS,
    _NAMESPACE_KINDS,
    _REVALIDATION_SCHEMA,
    _ROOT_PURPOSES,
    _SEALS,
    StrixWorkerContainmentError,
    StrixWorkerContainmentPlan,
    StrixWorkerReplayState,
    _after,
    _attempt,
    _boolean,
    _digest,
    _exact,
    _integer,
    _list,
    _sorted_unique,
    _text,
    _timestamp,
)
from .util import canonical_json_bytes, content_hash


def _identity(row: Any, plan: StrixWorkerContainmentPlan) -> dict[str, Any]:
    value = _exact(row, {"uid", "gid", "generation", "lease_ref"}, "worker identity")
    result: dict[str, Any] = {
        "uid": _integer(value["uid"], "observed worker UID", 1000, 2**31 - 2),
        "gid": _integer(value["gid"], "observed worker GID", 1000, 2**31 - 2),
        "generation": _integer(value["generation"], "observed identity generation", 1, 2**31 - 1),
        "lease_ref": _digest(value["lease_ref"], "observed identity lease"),
    }
    if result != {
        "uid": plan.uid,
        "gid": plan.gid,
        "generation": plan.identity_generation,
        "lease_ref": plan.identity_lease_ref,
    }:
        raise StrixWorkerContainmentError("worker identity does not match the plan")
    return result


def _process(row: Any) -> dict[str, Any]:
    value = _exact(
        row,
        {
            "host_pid",
            "start_ticks",
            "pidfd_ref",
            "pidfd_st_dev",
            "pidfd_st_ino",
            "pidfd_spawn_owned",
        },
        "worker process",
    )
    result: dict[str, Any] = {
        "host_pid": _integer(value["host_pid"], "worker host PID", 2, 2**31 - 1),
        "start_ticks": _integer(value["start_ticks"], "worker start ticks", 1, 2**63 - 1),
        "pidfd_ref": _digest(value["pidfd_ref"], "spawn-owned pidfd"),
        "pidfd_st_dev": _integer(value["pidfd_st_dev"], "pidfd device", 0, 2**64 - 1),
        "pidfd_st_ino": _integer(value["pidfd_st_ino"], "pidfd inode", 1, 2**64 - 1),
        "pidfd_spawn_owned": _boolean(value["pidfd_spawn_owned"], "spawn-owned pidfd proof", True),
    }
    expected = retained_kernel_identity_digest(
        role=f"pidfd:{result['host_pid']}:{result['start_ticks']}",
        st_dev=result["pidfd_st_dev"],
        st_ino=result["pidfd_st_ino"],
    )
    if result["pidfd_ref"] != expected:
        raise StrixWorkerContainmentError("spawn-owned pidfd identity is invalid")
    return result


def _cgroup(row: Any, plan: StrixWorkerContainmentPlan, host_pid: int) -> dict[str, Any]:
    fields = {
        "cgroup_ref",
        "inode",
        "pids_max",
        "pids_current",
        "leader_tgid",
        "member_threads",
        "memory_max_bytes",
        "cpu_quota_micros",
        "cpu_period_micros",
        "leaf",
        "delegated",
        "controller_owned",
    }
    value = _exact(row, fields, "worker cgroup")
    current = _integer(value["pids_current"], "worker cgroup pids.current", 1, plan.pids_max)
    member_rows = _list(value["member_threads"], current, current, "worker cgroup members")
    members: list[dict[str, int]] = []
    for item in member_rows:
        member = _exact(item, {"tid", "tgid"}, "worker cgroup thread")
        members.append(
            {
                "tid": _integer(member["tid"], "worker thread ID", 2, 2**31 - 1),
                "tgid": _integer(member["tgid"], "worker thread group ID", 2, 2**31 - 1),
            }
        )
    if [item["tid"] for item in members] != sorted({item["tid"] for item in members}):
        raise StrixWorkerContainmentError("worker cgroup thread IDs must be unique and sorted")
    result: dict[str, Any] = {
        "cgroup_ref": _digest(value["cgroup_ref"], "observed worker cgroup"),
        "inode": _integer(value["inode"], "worker cgroup inode", 1, 2**63 - 1),
        "pids_max": _integer(value["pids_max"], "worker cgroup pids.max", 4, 64),
        "pids_current": current,
        "leader_tgid": _integer(value["leader_tgid"], "worker leader TGID", 2, 2**31 - 1),
        "member_threads": members,
        "memory_max_bytes": _integer(
            value["memory_max_bytes"], "observed memory limit", 128 * 1024**2, 8 * 1024**3
        ),
        "cpu_quota_micros": _integer(
            value["cpu_quota_micros"], "observed CPU quota", 1_000, 10_000_000
        ),
        "cpu_period_micros": _integer(
            value["cpu_period_micros"], "observed CPU period", 1_000, 1_000_000
        ),
        "leaf": _boolean(value["leaf"], "leaf cgroup", True),
        "delegated": _boolean(value["delegated"], "delegated cgroup", True),
        "controller_owned": _boolean(value["controller_owned"], "controller-owned cgroup", True),
    }
    expected = (
        plan.cgroup_ref,
        plan.pids_max,
        plan.memory_max_bytes,
        plan.cpu_quota_micros,
        plan.cpu_period_micros,
        host_pid,
    )
    actual = (
        result["cgroup_ref"],
        result["pids_max"],
        result["memory_max_bytes"],
        result["cpu_quota_micros"],
        result["cpu_period_micros"],
        result["leader_tgid"],
    )
    if (
        actual != expected
        or any(item["tgid"] != host_pid for item in members)
        or host_pid not in {item["tid"] for item in members}
    ):
        raise StrixWorkerContainmentError("worker cgroup does not match the plan and process")
    return result


def _namespaces(value: Any, plan: StrixWorkerContainmentPlan) -> list[dict[str, Any]]:
    rows = _list(value, 5, 5, "worker namespaces")
    result: list[dict[str, Any]] = []
    for item in rows:
        row = _exact(
            item,
            {
                "kind",
                "identity_digest",
                "st_dev",
                "st_ino",
                "inode",
                "host_inode",
                "isolated",
            },
            "worker namespace",
        )
        parsed = {
            "kind": _text(row["kind"], "namespace kind", 16),
            "identity_digest": _digest(row["identity_digest"], "namespace identity"),
            "st_dev": _integer(row["st_dev"], "namespace device", 0, 2**64 - 1),
            "st_ino": _integer(row["st_ino"], "namespace retained inode", 1, 2**64 - 1),
            "inode": _integer(row["inode"], "namespace inode", 1, 2**63 - 1),
            "host_inode": _integer(row["host_inode"], "host namespace inode", 1, 2**63 - 1),
            "isolated": _boolean(row["isolated"], "namespace isolation"),
        }
        result.append(parsed)
    if tuple(row["kind"] for row in result) != _NAMESPACE_KINDS:
        raise StrixWorkerContainmentError("worker namespaces must be complete and sorted")
    for row in result:
        if (
            row["st_ino"] != row["inode"]
            or row["identity_digest"]
            != retained_kernel_identity_digest(
                role=f"worker-{row['kind']}-namespace",
                st_dev=row["st_dev"],
                st_ino=row["st_ino"],
            )
        ):
            raise StrixWorkerContainmentError(
                "worker namespace retained identity is invalid"
            )
        pid_profile = (
            row["kind"] == "pid" and plan.pid_namespace_profile == "host-pid-authenticated"
        )
        if pid_profile != (row["isolated"] is False and row["inode"] == row["host_inode"]):
            raise StrixWorkerContainmentError("worker namespace isolation profile is invalid")
        if not pid_profile and (row["isolated"] is not True or row["inode"] == row["host_inode"]):
            raise StrixWorkerContainmentError("worker namespace is not isolated from the host")
    return result


def _inputs(value: Any, plan: StrixWorkerContainmentPlan) -> list[dict[str, Any]]:
    rows = _list(value, 3, 3, "observed sealed inputs")
    result: list[dict[str, Any]] = []
    for item in rows:
        row = _exact(
            item,
            {
                "kind",
                "path",
                "content_digest",
                "byte_length",
                "fd_identity_digest",
                "fd_st_dev",
                "fd_st_ino",
                "seals",
            },
            "observed sealed input",
        )
        result.append(
            {
                "kind": _text(row["kind"], "observed input kind", 16),
                "path": _text(row["path"], "observed input path", 128),
                "content_digest": _digest(row["content_digest"], "observed input content"),
                "byte_length": _integer(
                    row["byte_length"], "observed input length", 1, 4 * 1024 * 1024
                ),
                "fd_identity_digest": _digest(
                    row["fd_identity_digest"], "sealed input descriptor identity"
                ),
                "fd_st_dev": _integer(row["fd_st_dev"], "sealed input device", 0, 2**64 - 1),
                "fd_st_ino": _integer(row["fd_st_ino"], "sealed input inode", 1, 2**64 - 1),
                "seals": list(_sorted_unique(row["seals"], "sealed input seals", _SEALS)),
            }
        )
    if (
        tuple(row["kind"] for row in result) != _INPUT_KINDS
        or any(row["path"] != _INPUT_PATHS[row["kind"]] for row in result)
        or tuple(
            (row["kind"], row["content_digest"], row["byte_length"], row["fd_identity_digest"])
            for row in result
        )
        != tuple(
            (item.kind, item.content_digest, item.byte_length, item.fd_identity_digest)
            for item in plan.sealed_inputs
        )
        or any(
            row["seals"] != list(_SEALS)
            or row["fd_identity_digest"]
            != retained_kernel_identity_digest(
                role=f"sealed-input:{row['kind']}", st_dev=row["fd_st_dev"], st_ino=row["fd_st_ino"]
            )
            for row in result
        )
        or plan.sealed_inputs_ref != _sealed_input_projection_ref(result)
    ):
        raise StrixWorkerContainmentError("sealed input observations do not match the plan")
    return result


def _sealed_input_projection_ref(rows: list[dict[str, Any]]) -> str:
    """Hash post-pivot mount facts, excluding controller source descriptors."""

    return cast(
        str,
        content_hash(
            [
                {
                    "kind": row["kind"],
                    "path": row["path"],
                    "dev": row["fd_st_dev"],
                    "inode": row["fd_st_ino"],
                    "seals": row["seals"],
                    "digest": row["content_digest"],
                    "length": row["byte_length"],
                }
                for row in rows
            ]
        ),
    )


def _roots(value: Any, plan: StrixWorkerContainmentPlan) -> list[dict[str, Any]]:
    rows = _list(value, 4, 4, "private worker roots")
    result: list[dict[str, Any]] = []
    for item in rows:
        row = _exact(
            item,
            {
                "purpose",
                "object_identity_digest",
                "st_dev",
                "st_ino",
                "owner_uid",
                "owner_gid",
                "mode",
                "writable",
                "private",
                "nosuid",
                "nodev",
                "noexec",
            },
            "private worker root",
        )
        result.append(
            {
                "purpose": _text(row["purpose"], "private root purpose", 16),
                "object_identity_digest": _digest(
                    row["object_identity_digest"], "private root identity"
                ),
                "st_dev": _integer(row["st_dev"], "private root device", 0, 2**64 - 1),
                "st_ino": _integer(row["st_ino"], "private root inode", 1, 2**64 - 1),
                "owner_uid": _integer(row["owner_uid"], "private root UID", 1000, 2**31 - 2),
                "owner_gid": _integer(row["owner_gid"], "private root GID", 1000, 2**31 - 2),
                "mode": _integer(row["mode"], "private root mode", 0, 0o7777),
                "writable": _boolean(row["writable"], "private root writable", True),
                "private": _boolean(row["private"], "private root isolation", True),
                "nosuid": _boolean(row["nosuid"], "private root nosuid", True),
                "nodev": _boolean(row["nodev"], "private root nodev", True),
                "noexec": _boolean(row["noexec"], "private root noexec", True),
            }
        )
    planned = {
        "config": plan.config_root_identity_digest,
        "home": plan.home_root_identity_digest,
        "tmp": plan.tmp_root_identity_digest,
        "workspace": plan.workspace_root_identity_digest,
    }
    if tuple(row["purpose"] for row in result) != _ROOT_PURPOSES or any(
        row["owner_uid"] != plan.uid
        or row["owner_gid"] != plan.gid
        or row["mode"] != 0o700
        or row["object_identity_digest"] != planned[row["purpose"]]
        or row["object_identity_digest"]
        != retained_kernel_identity_digest(
            role=f"private-root:{row['purpose']}", st_dev=row["st_dev"], st_ino=row["st_ino"]
        )
        for row in result
    ):
        raise StrixWorkerContainmentError("private worker roots are not exact")
    return result


def _security(value: Any, plan: StrixWorkerContainmentPlan) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "no_new_privs",
            "seccomp_digest",
            "clone_filter_digest",
            "blocked_syscalls",
            "clone_policy",
            "seccomp_tsync",
            "installed_before_authority",
            "audit_arch",
            "clone3_action",
            "process_spawn_action",
            "effective_capabilities",
            "ambient_capabilities",
            "dumpable",
        },
        "worker security state",
    )
    result: dict[str, Any] = {
        "no_new_privs": _boolean(row["no_new_privs"], "no-new-privileges", True),
        "seccomp_digest": _digest(row["seccomp_digest"], "seccomp policy"),
        "clone_filter_digest": _digest(row["clone_filter_digest"], "clone filter"),
        "blocked_syscalls": list(
            _sorted_unique(row["blocked_syscalls"], "blocked syscall", _BLOCKED_SYSCALLS)
        ),
        "clone_policy": _text(row["clone_policy"], "clone policy", 32),
        "seccomp_tsync": _boolean(row["seccomp_tsync"], "seccomp TSYNC", True),
        "installed_before_authority": _boolean(
            row["installed_before_authority"], "seccomp installation chronology", True
        ),
        "audit_arch": _text(row["audit_arch"], "seccomp audit architecture", 16),
        "clone3_action": _text(row["clone3_action"], "clone3 action", 24),
        "process_spawn_action": _text(row["process_spawn_action"], "process-spawn action", 24),
        "effective_capabilities": list(
            _sorted_unique(row["effective_capabilities"], "effective capability", ())
        ),
        "ambient_capabilities": list(
            _sorted_unique(row["ambient_capabilities"], "ambient capability", ())
        ),
        "dumpable": _boolean(row["dumpable"], "worker dumpable state", False),
    }
    if (
        result["blocked_syscalls"] != list(_BLOCKED_SYSCALLS)
        or result["clone_policy"] != "same_tgid_thread_only"
        or result["seccomp_digest"] != plan.seccomp_policy_digest
        or result["clone_filter_digest"] != plan.clone_filter_digest
        or result["audit_arch"] != "x86_64"
        or result["clone3_action"] != "errno:enosys"
        or result["process_spawn_action"] != "errno:eperm"
    ):
        raise StrixWorkerContainmentError("worker seccomp policy is incomplete")
    return result


def _network(
    value: Any,
    plan: StrixWorkerContainmentPlan,
    namespaces: list[dict[str, Any]],
) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "relays",
            "network_namespace_ref",
            "network_namespace_st_dev",
            "network_namespace_st_ino",
            "loopback_only",
            "default_route_absent",
            "dns_absent",
            "metadata_unreachable",
            "target_unreachable",
            "daemon_sockets_absent",
            "raw_socket_denied",
            "policy_digest",
        },
        "worker network state",
    )
    relays = [
        RelayPlan.from_mapping(item).to_dict()
        for item in _list(row["relays"], 2, 2, "observed relays")
    ]
    result: dict[str, Any] = {
        "relays": relays,
        "network_namespace_ref": _digest(
            row["network_namespace_ref"], "observed worker network namespace"
        ),
        "network_namespace_st_dev": _integer(
            row["network_namespace_st_dev"],
            "observed worker network namespace device",
            0,
            2**64 - 1,
        ),
        "network_namespace_st_ino": _integer(
            row["network_namespace_st_ino"],
            "observed worker network namespace inode",
            1,
            2**64 - 1,
        ),
        "loopback_only": _boolean(row["loopback_only"], "loopback-only network", True),
        "default_route_absent": _boolean(
            row["default_route_absent"], "default-route absence", True
        ),
        "dns_absent": _boolean(row["dns_absent"], "DNS absence", True),
        "metadata_unreachable": _boolean(row["metadata_unreachable"], "metadata refusal", True),
        "target_unreachable": _boolean(row["target_unreachable"], "direct target refusal", True),
        "daemon_sockets_absent": _boolean(
            row["daemon_sockets_absent"], "daemon-socket absence", True
        ),
        "raw_socket_denied": _boolean(row["raw_socket_denied"], "raw socket refusal", True),
        "policy_digest": _digest(row["policy_digest"], "worker network policy"),
    }
    network_namespace = next(
        item for item in namespaces if item["kind"] == "network"
    )
    observed_namespace = (
        result["network_namespace_ref"],
        result["network_namespace_st_dev"],
        result["network_namespace_st_ino"],
    )
    namespace_row_identity = (
        network_namespace["identity_digest"],
        network_namespace["st_dev"],
        network_namespace["st_ino"],
    )
    planned_namespaces = {
        (
            item.network_namespace_ref,
            item.network_namespace_st_dev,
            item.network_namespace_st_ino,
        )
        for item in plan.relays
    }
    if (
        relays != [item.to_dict() for item in plan.relays]
        or result["policy_digest"] != plan.network_policy_digest
        or result["network_namespace_ref"]
        != retained_kernel_identity_digest(
            role="worker-network-namespace",
            st_dev=result["network_namespace_st_dev"],
            st_ino=result["network_namespace_st_ino"],
        )
        or planned_namespaces != {observed_namespace}
        or namespace_row_identity != observed_namespace
    ):
        raise StrixWorkerContainmentError(
            "observed relays do not share the exact worker network namespace"
        )
    return result


def _mount_policy(value: Any, plan: StrixWorkerContainmentPlan) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "policy_digest",
            "profile",
            "proc_mounted",
            "host_argv_env_unavailable",
            "inputs_materialized_before_pivot",
            "pivot_root_complete",
            "host_root_detached",
            "rootfs_identity_digest",
            "rootfs_st_dev",
            "rootfs_st_ino",
        },
        "worker mount policy",
    )
    result: dict[str, Any] = {
        "policy_digest": _digest(row["policy_digest"], "mount policy"),
        "profile": _text(row["profile"], "mount profile", 32),
        "proc_mounted": _boolean(row["proc_mounted"], "worker proc mount", False),
        "host_argv_env_unavailable": _boolean(
            row["host_argv_env_unavailable"], "host process confidentiality", True
        ),
        "inputs_materialized_before_pivot": _boolean(
            row["inputs_materialized_before_pivot"], "input materialization chronology", True
        ),
        "pivot_root_complete": _boolean(row["pivot_root_complete"], "private-root pivot", True),
        "host_root_detached": _boolean(row["host_root_detached"], "host-root detachment", True),
        "rootfs_identity_digest": _digest(row["rootfs_identity_digest"], "private rootfs identity"),
        "rootfs_st_dev": _integer(row["rootfs_st_dev"], "private rootfs device", 0, 2**64 - 1),
        "rootfs_st_ino": _integer(row["rootfs_st_ino"], "private rootfs inode", 1, 2**64 - 1),
    }
    if (
        result["policy_digest"] != plan.mount_policy_digest
        or result["profile"] != "private-root-no-proc"
        or result["rootfs_identity_digest"]
        != retained_kernel_identity_digest(
            role="private-rootfs",
            st_dev=result["rootfs_st_dev"],
            st_ino=result["rootfs_st_ino"],
        )
    ):
        raise StrixWorkerContainmentError("worker mount policy does not match the plan")
    return result


_ACTIVATION_BINDINGS = (
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
    "controller_peer_process_ref",
    "controller_peer_start_ticks",
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
)


@dataclass(frozen=True, slots=True)
class StrixWorkerActivationReceipt:
    _canonical: bytes

    @property
    def document(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], json.loads(self._canonical))

    @classmethod
    def from_mapping(
        cls, value: Any, plan: StrixWorkerContainmentPlan
    ) -> "StrixWorkerActivationReceipt":
        plan = StrixWorkerContainmentPlan.from_mapping(plan.to_dict())
        fields = {
            "schema_version",
            "plan_ref",
            *_ACTIVATION_BINDINGS,
            "plan_expires_at",
            "observed_at",
            "identity",
            "process",
            "cgroup",
            "namespaces",
            "sealed_inputs",
            "private_roots",
            "security",
            "network",
            "mount_policy",
            "receipt_ref",
        }
        row = _exact(value, fields, "worker activation receipt")
        canonical: dict[str, Any] = {
            "schema_version": _text(row["schema_version"], "activation version"),
            "plan_ref": _digest(row["plan_ref"], "worker plan reference"),
        }
        for name in _ACTIVATION_BINDINGS:
            expected = getattr(plan, name)
            canonical[name] = (
                _integer(row[name], name.replace("_", " "), 0, 2**63 - 1)
                if name == "replay_generation"
                else _integer(row[name], name.replace("_", " "), 2, 2**31 - 1)
                if name == "controller_peer_host_pid"
                else _integer(row[name], name.replace("_", " "), 1, 2**63 - 1)
                if name in {"controller_peer_start_ticks", "controller_rpc_socket_st_ino"}
                else _integer(row[name], name.replace("_", " "), 0, 2**64 - 1)
                if name in {"controller_uid", "controller_gid", "controller_rpc_socket_st_dev"}
                else _integer(row[name], name.replace("_", " "), 1, 2**31 - 1)
                if name == "controller_generation"
                else _boolean(row[name], name.replace("_", " "), True)
                if name == "controller_rpc_passcred"
                else _text(row[name], name.replace("_", " "), 32)
                if name in {"pid_namespace_profile", "controller_rpc_transport"}
                else _attempt(row[name])
                if name == "attempt_id"
                else _digest(row[name], name.replace("_", " "))
            )
            if canonical[name] != expected:
                raise StrixWorkerContainmentError(f"activation {name} does not match the plan")
        canonical["plan_expires_at"] = _timestamp(row["plan_expires_at"], "plan expiry")
        if canonical["plan_expires_at"] != plan.expires_at:
            raise StrixWorkerContainmentError("activation plan expiry does not match the plan")
        canonical["observed_at"] = _timestamp(row["observed_at"], "activation observation")
        canonical["identity"] = _identity(row["identity"], plan)
        canonical["process"] = _process(row["process"])
        canonical["cgroup"] = _cgroup(row["cgroup"], plan, canonical["process"]["host_pid"])
        canonical["namespaces"] = _namespaces(row["namespaces"], plan)
        canonical["sealed_inputs"] = _inputs(row["sealed_inputs"], plan)
        canonical["private_roots"] = _roots(row["private_roots"], plan)
        canonical["security"] = _security(row["security"], plan)
        canonical["network"] = _network(row["network"], plan, canonical["namespaces"])
        canonical["mount_policy"] = _mount_policy(row["mount_policy"], plan)
        canonical["receipt_ref"] = _digest(row["receipt_ref"], "activation receipt")
        if (
            canonical["schema_version"] != _ACTIVATION_SCHEMA
            or canonical["plan_ref"] != plan.plan_ref
        ):
            raise StrixWorkerContainmentError("worker activation does not bind the plan")
        _after(
            canonical["observed_at"],
            plan.created_at,
            "activation observation",
            maximum=timedelta(minutes=5),
        )
        _after(plan.expires_at, canonical["observed_at"], "activation before plan expiry")
        expected_ref = content_hash(
            {name: item for name, item in canonical.items() if name != "receipt_ref"}
        )
        if canonical["receipt_ref"] != expected_ref:
            raise StrixWorkerContainmentError("worker activation receipt digest is invalid")
        return cls(canonical_json_bytes(canonical))

    @property
    def receipt_ref(self) -> str:
        return str(self.document["receipt_ref"])

    def to_dict(self) -> dict[str, Any]:
        # Validation has reduced all members to JSON primitives.
        return dict(self.document)


def _clone(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _clone(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clone(item) for item in value]
    return value


def validate_activation_receipt(
    plan: StrixWorkerContainmentPlan, value: Any, replay: StrixWorkerReplayState
) -> StrixWorkerActivationReceipt:
    plan = StrixWorkerContainmentPlan.from_mapping(plan.to_dict())
    replay = StrixWorkerReplayState.from_mapping(replay.to_dict())
    if replay.ledger_ref != plan.replay_ledger_ref:
        raise StrixWorkerContainmentError("worker replay ledger does not match the plan")
    receipt = StrixWorkerActivationReceipt.from_mapping(value, plan)
    if (
        replay.generation != plan.replay_generation + 1
        or replay.head_digest == plan.replay_head_digest
        or plan.replay_head_digest not in replay.ancestor_head_digests
        or receipt.receipt_ref not in replay.consumed_activation_refs
        or plan.identity_lease_ref not in replay.consumed_identity_lease_refs
    ):
        raise StrixWorkerContainmentError(
            "worker activation is not committed to the expected replay successor"
        )
    return receipt


def _revalidated_members(
    value: Any, pids_current: int, pids_max: int, leader_tgid: int
) -> list[dict[str, int]]:
    if pids_current > pids_max:
        raise StrixWorkerContainmentError("worker task count exceeds pids.max")
    result: list[dict[str, int]] = []
    for item in _list(value, pids_current, pids_current, "revalidated cgroup members"):
        row = _exact(item, {"tid", "tgid"}, "revalidated worker thread")
        result.append(
            {
                "tid": _integer(row["tid"], "revalidated thread ID", 2, 2**31 - 1),
                "tgid": _integer(row["tgid"], "revalidated thread group ID", 2, 2**31 - 1),
            }
        )
    tids = [item["tid"] for item in result]
    if (
        tids != sorted(set(tids))
        or leader_tgid not in tids
        or any(item["tgid"] != leader_tgid for item in result)
    ):
        raise StrixWorkerContainmentError("revalidated worker threads escaped the owned TGID")
    return result


@dataclass(frozen=True, slots=True)
class StrixWorkerRevalidationReceipt:
    _canonical: bytes

    @property
    def document(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], json.loads(self._canonical))

    @classmethod
    def from_mapping(
        cls, value: Any, activation: StrixWorkerActivationReceipt
    ) -> "StrixWorkerRevalidationReceipt":
        fields = {
            "schema_version",
            "activation_ref",
            "plan_ref",
            "attempt_id",
            "binding_digest",
            "installed_projection_ref",
            "startup_overlay_ref",
            "sealed_inputs_ref",
            "controller_generation",
            "controller_boot_id_digest",
            "observed_at",
            "host_pid",
            "start_ticks",
            "pidfd_signallable",
            "cgroup_ref",
            "cgroup_inode",
            "cgroup_snapshot_digest",
            "memory_max_bytes",
            "cpu_quota_micros",
            "cpu_period_micros",
            "leaf",
            "delegated",
            "controller_owned",
            "namespace_snapshot_digest",
            "input_snapshot_digest",
            "root_snapshot_digest",
            "seccomp_digest",
            "clone_filter_digest",
            "network_snapshot_digest",
            "mount_policy_digest",
            "proc_absent",
            "host_process_details_unavailable",
            "rootfs_identity_digest",
            "rootfs_st_dev",
            "rootfs_st_ino",
            "pids_max",
            "pids_current",
            "leader_tgid",
            "member_threads",
            "no_new_privs",
            "limits_unchanged",
            "relays_owned",
            "receipt_ref",
        }
        row = _exact(value, fields, "worker revalidation receipt")
        original = activation.document
        pids_max = _integer(row["pids_max"], "revalidated pids.max", 4, 64)
        pids_current = _integer(row["pids_current"], "revalidated pids.current", 1, 64)
        leader_tgid = _integer(row["leader_tgid"], "revalidated leader TGID", 2, 2**31 - 1)
        members = _revalidated_members(row["member_threads"], pids_current, pids_max, leader_tgid)
        canonical: dict[str, Any] = {
            "schema_version": _text(row["schema_version"], "revalidation version"),
            "activation_ref": _digest(row["activation_ref"], "activation reference"),
            "plan_ref": _digest(row["plan_ref"], "plan reference"),
            "attempt_id": _attempt(row["attempt_id"]),
            "binding_digest": _digest(row["binding_digest"], "binding"),
            "installed_projection_ref": _digest(
                row["installed_projection_ref"], "installed runtime projection"
            ),
            "startup_overlay_ref": _digest(row["startup_overlay_ref"], "startup overlay"),
            "sealed_inputs_ref": _digest(row["sealed_inputs_ref"], "sealed input projection"),
            "controller_generation": _integer(
                row["controller_generation"], "controller generation", 1, 2**31 - 1
            ),
            "controller_boot_id_digest": _digest(
                row["controller_boot_id_digest"], "controller boot ID"
            ),
            "observed_at": _timestamp(row["observed_at"], "revalidation observation"),
            "host_pid": _integer(row["host_pid"], "worker host PID", 2, 2**31 - 1),
            "start_ticks": _integer(row["start_ticks"], "worker start ticks", 1, 2**63 - 1),
            "pidfd_signallable": _boolean(row["pidfd_signallable"], "pidfd liveness", True),
            "cgroup_ref": _digest(row["cgroup_ref"], "revalidated cgroup"),
            "cgroup_inode": _integer(row["cgroup_inode"], "revalidated cgroup inode", 1, 2**63 - 1),
            "cgroup_snapshot_digest": _digest(row["cgroup_snapshot_digest"], "cgroup snapshot"),
            "memory_max_bytes": _integer(
                row["memory_max_bytes"],
                "revalidated memory limit",
                128 * 1024**2,
                8 * 1024**3,
            ),
            "cpu_quota_micros": _integer(
                row["cpu_quota_micros"], "revalidated CPU quota", 1_000, 10_000_000
            ),
            "cpu_period_micros": _integer(
                row["cpu_period_micros"], "revalidated CPU period", 1_000, 1_000_000
            ),
            "leaf": _boolean(row["leaf"], "revalidated leaf cgroup", True),
            "delegated": _boolean(row["delegated"], "revalidated cgroup delegation", True),
            "controller_owned": _boolean(
                row["controller_owned"], "revalidated cgroup ownership", True
            ),
            "namespace_snapshot_digest": _digest(
                row["namespace_snapshot_digest"], "namespace snapshot"
            ),
            "input_snapshot_digest": _digest(row["input_snapshot_digest"], "input snapshot"),
            "root_snapshot_digest": _digest(row["root_snapshot_digest"], "root snapshot"),
            "seccomp_digest": _digest(row["seccomp_digest"], "seccomp policy"),
            "clone_filter_digest": _digest(row["clone_filter_digest"], "clone filter"),
            "network_snapshot_digest": _digest(row["network_snapshot_digest"], "network snapshot"),
            "mount_policy_digest": _digest(row["mount_policy_digest"], "mount policy"),
            "proc_absent": _boolean(row["proc_absent"], "proc absence", True),
            "host_process_details_unavailable": _boolean(
                row["host_process_details_unavailable"], "host process confidentiality", True
            ),
            "rootfs_identity_digest": _digest(row["rootfs_identity_digest"], "private rootfs identity"),
            "rootfs_st_dev": _integer(row["rootfs_st_dev"], "private rootfs device", 0, 2**64 - 1),
            "rootfs_st_ino": _integer(row["rootfs_st_ino"], "private rootfs inode", 1, 2**64 - 1),
            "pids_max": pids_max,
            "pids_current": pids_current,
            "leader_tgid": leader_tgid,
            "member_threads": members,
            "no_new_privs": _boolean(row["no_new_privs"], "revalidated no-new-privileges", True),
            "limits_unchanged": _boolean(row["limits_unchanged"], "limit revalidation", True),
            "relays_owned": _boolean(row["relays_owned"], "relay ownership", True),
            "receipt_ref": _digest(row["receipt_ref"], "revalidation receipt"),
        }
        expected = {
            "schema_version": _REVALIDATION_SCHEMA,
            "activation_ref": activation.receipt_ref,
            "plan_ref": original["plan_ref"],
            "attempt_id": original["attempt_id"],
            "binding_digest": original["binding_digest"],
            "installed_projection_ref": original["installed_projection_ref"],
            "startup_overlay_ref": original["startup_overlay_ref"],
            "sealed_inputs_ref": original["sealed_inputs_ref"],
            "controller_generation": original["controller_generation"],
            "controller_boot_id_digest": original["controller_boot_id_digest"],
            "host_pid": original["process"]["host_pid"],
            "start_ticks": original["process"]["start_ticks"],
            "cgroup_ref": original["cgroup"]["cgroup_ref"],
            "cgroup_inode": original["cgroup"]["inode"],
            "memory_max_bytes": original["cgroup"]["memory_max_bytes"],
            "cpu_quota_micros": original["cgroup"]["cpu_quota_micros"],
            "cpu_period_micros": original["cgroup"]["cpu_period_micros"],
            "namespace_snapshot_digest": content_hash(original["namespaces"]),
            "input_snapshot_digest": content_hash(original["sealed_inputs"]),
            "root_snapshot_digest": content_hash(original["private_roots"]),
            "seccomp_digest": original["security"]["seccomp_digest"],
            "clone_filter_digest": original["security"]["clone_filter_digest"],
            "network_snapshot_digest": content_hash(original["network"]),
            "mount_policy_digest": original["mount_policy"]["policy_digest"],
            "rootfs_identity_digest": original["mount_policy"]["rootfs_identity_digest"],
            "rootfs_st_dev": original["mount_policy"]["rootfs_st_dev"],
            "rootfs_st_ino": original["mount_policy"]["rootfs_st_ino"],
            "pids_max": original["cgroup"]["pids_max"],
            "leader_tgid": original["cgroup"]["leader_tgid"],
        }
        if any(canonical[name] != expected[name] for name in expected):
            raise StrixWorkerContainmentError("worker containment revalidation drifted")
        if canonical["rootfs_identity_digest"] != retained_kernel_identity_digest(
            role="private-rootfs",
            st_dev=canonical["rootfs_st_dev"],
            st_ino=canonical["rootfs_st_ino"],
        ):
            raise StrixWorkerContainmentError("worker rootfs revalidation identity is invalid")
        current_cgroup = {
            "cgroup_ref": canonical["cgroup_ref"],
            "inode": canonical["cgroup_inode"],
            "pids_max": canonical["pids_max"],
            "pids_current": canonical["pids_current"],
            "leader_tgid": canonical["leader_tgid"],
            "member_threads": canonical["member_threads"],
            "memory_max_bytes": canonical["memory_max_bytes"],
            "cpu_quota_micros": canonical["cpu_quota_micros"],
            "cpu_period_micros": canonical["cpu_period_micros"],
            "leaf": canonical["leaf"],
            "delegated": canonical["delegated"],
            "controller_owned": canonical["controller_owned"],
        }
        if canonical["cgroup_snapshot_digest"] != content_hash(current_cgroup):
            raise StrixWorkerContainmentError("worker cgroup snapshot digest is invalid")
        _after(
            cast(str, canonical["observed_at"]),
            cast(str, original["observed_at"]),
            "revalidation observation",
            maximum=timedelta(minutes=30),
        )
        _after(
            cast(str, original["plan_expires_at"]),
            cast(str, canonical["observed_at"]),
            "revalidation before plan expiry",
        )
        if canonical["receipt_ref"] != content_hash(
            {name: item for name, item in canonical.items() if name != "receipt_ref"}
        ):
            raise StrixWorkerContainmentError("worker revalidation receipt digest is invalid")
        return cls(canonical_json_bytes(canonical))

    @property
    def receipt_ref(self) -> str:
        return str(self.document["receipt_ref"])

    def to_dict(self) -> dict[str, Any]:
        return dict(self.document)
