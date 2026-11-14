from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.strix_worker_containment import (
    StrixWorkerActivationReceipt,
    StrixWorkerCleanupRequest,
    StrixWorkerContainmentError,
    StrixWorkerContainmentPlan,
    StrixWorkerReplayState,
    StrixWorkerRevalidationReceipt,
    receipt_document,
    retained_kernel_identity_digest,
    validate_activation_receipt,
    validate_cleanup_receipt,
)
from bluefire.util import content_hash


def _d(label: str) -> str:
    return content_hash({"label": label})


def _sealed_input_mount_facts() -> list[dict[str, object]]:
    return [
        {
            "kind": kind,
            "path": f"/inputs/{kind}.json",
            "dev": 21,
            "inode": 301 + index,
            "seals": ["grow", "seal", "shrink", "write"],
            "digest": _d(f"input:{kind}"),
            "length": 100 + index,
        }
        for index, kind in enumerate(("config", "mcp", "objective"))
    ]


def _plan_document() -> dict[str, object]:
    return {
        "schema_version": "bluefire.strix-worker-containment-plan.v1",
        "attempt_id": "engine-attempt-" + "a" * 32,
        "claim_digest": _d("claim"),
        "binding_digest": _d("binding"),
        "delegation_digest": _d("delegation"),
        "runtime_qualification_ref": _d("runtime"),
        "installed_projection_ref": _d("installed-projection"),
        "startup_overlay_ref": _d("startup-overlay"),
        "sealed_inputs_ref": content_hash(_sealed_input_mount_facts()),
        "admission_record_ref": _d("admission"),
        "resource_identity_ref": _d("resource"),
        "invocation_digest": _d("invocation"),
        "executable_digest": _d("executable"),
        "package_digest": _d("package"),
        "boundary_helper_digest": _d("native-boundary-helper"),
        "replay_ledger_ref": _d("ledger"),
        "replay_generation": 41,
        "replay_head_digest": _d("head"),
        "controller_generation": 7,
        "controller_boot_id_digest": _d("boot"),
        "controller_peer_host_pid": 41_900,
        "controller_peer_start_ticks": 7_700_001,
        "controller_peer_process_ref": _d("controller-peer-process"),
        "controller_uid": 1000,
        "controller_gid": 1000,
        "controller_rpc_channel_ref": _d("controller-rpc-channel"),
        "controller_rpc_socket_identity_digest": retained_kernel_identity_digest(
            role="controller-rpc-sock-seqpacket", st_dev=51, st_ino=701
        ),
        "controller_rpc_socket_st_dev": 51,
        "controller_rpc_socket_st_ino": 701,
        "controller_rpc_policy_digest": _d("controller-rpc-passcred-policy"),
        "controller_rpc_transport": "af_unix_sock_seqpacket",
        "controller_rpc_passcred": True,
        "pid_namespace_profile": "host-pid-authenticated",
        "uid": 20_021,
        "gid": 20_021,
        "identity_generation": 3,
        "identity_lease_ref": _d("identity-lease"),
        "cgroup_ref": _d("worker-cgroup"),
        "pids_max": 8,
        "seccomp_policy_digest": _d("seccomp"),
        "clone_filter_digest": _d("clone-filter"),
        "network_policy_digest": _d("network-policy"),
        "mount_policy_digest": _d("mount-policy"),
        "config_root_identity_digest": retained_kernel_identity_digest(
            role="private-root:config", st_dev=31, st_ino=401
        ),
        "home_root_identity_digest": retained_kernel_identity_digest(
            role="private-root:home", st_dev=31, st_ino=402
        ),
        "tmp_root_identity_digest": retained_kernel_identity_digest(
            role="private-root:tmp", st_dev=31, st_ino=403
        ),
        "workspace_root_identity_digest": retained_kernel_identity_digest(
            role="private-root:workspace", st_dev=31, st_ino=404
        ),
        "memory_max_bytes": 512 * 1024**2,
        "cpu_quota_micros": 200_000,
        "cpu_period_micros": 100_000,
        "sealed_inputs": [
            {
                "kind": kind,
                "content_digest": _d(f"input:{kind}"),
                "byte_length": 100 + index,
                "fd_identity_digest": retained_kernel_identity_digest(
                    role=f"sealed-input:{kind}", st_dev=21, st_ino=301 + index
                ),
            }
            for index, kind in enumerate(("config", "mcp", "objective"))
        ],
        "relays": [
            {
                "purpose": purpose,
                "relay_ref": _d(f"relay:{purpose}"),
                "owner_ref": _d(f"owner:{purpose}"),
                "owner_process_ref": _d(f"owner-process:{purpose}"),
                "listener_ref": _d(f"listener:{purpose}"),
                "socket_identity_digest": retained_kernel_identity_digest(
                    role=f"relay-socket:{purpose}",
                    st_dev=41,
                    st_ino=501 + index,
                    host="127.0.0.1",
                    port=port,
                ),
                "socket_st_dev": 41,
                "socket_st_ino": 501 + index,
                "network_namespace_ref": retained_kernel_identity_digest(
                    role="worker-network-namespace", st_dev=42, st_ino=601
                ),
                "network_namespace_st_dev": 42,
                "network_namespace_st_ino": 601,
                "transport": "tcp",
                "host": "127.0.0.1",
                "port": port,
            }
            for index, (purpose, port) in enumerate((("caido", 39001), ("model", 39002)))
        ],
        "created_at": "2026-11-05T12:00:00Z",
        "expires_at": "2026-11-05T12:30:00Z",
    }


def _plan() -> StrixWorkerContainmentPlan:
    return StrixWorkerContainmentPlan.from_mapping(_plan_document())


def _replay() -> StrixWorkerReplayState:
    return StrixWorkerReplayState.empty(
        ledger_ref=_d("ledger"), head_digest=_d("head"), generation=41
    )


def _committed_activation_replay(
    plan: StrixWorkerContainmentPlan, document: dict[str, object]
) -> StrixWorkerReplayState:
    receipt = StrixWorkerActivationReceipt.from_mapping(document, plan)
    row = _replay().to_dict()
    row["generation"] = plan.replay_generation + 1
    row["ancestor_head_digests"] = [plan.replay_head_digest]
    row["head_digest"] = _d("activation-ledger-head")
    row["consumed_activation_refs"] = [receipt.receipt_ref]
    row["consumed_identity_lease_refs"] = [plan.identity_lease_ref]
    return StrixWorkerReplayState.from_mapping(row)


def _committed_cleanup_replay(activation, request) -> StrixWorkerReplayState:
    row = _replay().to_dict()
    row["generation"] = activation.document["replay_generation"] + 2
    row["ancestor_head_digests"] = sorted(
        [activation.document["replay_head_digest"], _d("activation-ledger-head")]
    )
    row["head_digest"] = _d("cleanup-ledger-head")
    row["consumed_activation_refs"] = [activation.receipt_ref]
    row["consumed_identity_lease_refs"] = [activation.document["identity"]["lease_ref"]]
    row["consumed_cleanup_request_refs"] = [request.request_ref]
    row["consumed_cleanup_activation_refs"] = [activation.receipt_ref]
    return StrixWorkerReplayState.from_mapping(row)


def _namespace_observations(plan: StrixWorkerContainmentPlan) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for index, kind in enumerate(("ipc", "mount", "network", "pid", "uts")):
        inode = (
            2000 + index
            if kind == "pid"
            else plan.relays[0].network_namespace_st_ino
            if kind == "network"
            else 1000 + index
        )
        st_dev = plan.relays[0].network_namespace_st_dev if kind == "network" else 43
        result.append(
            {
                "kind": kind,
                "identity_digest": retained_kernel_identity_digest(
                    role=f"worker-{kind}-namespace", st_dev=st_dev, st_ino=inode
                ),
                "st_dev": st_dev,
                "st_ino": inode,
                "inode": inode,
                "host_inode": 2000 + index,
                "isolated": kind != "pid",
            }
        )
    return result


def _activation_document(plan: StrixWorkerContainmentPlan) -> dict[str, object]:
    host_pid = 42_001
    bindings = {
        name: getattr(plan, name)
        for name in (
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
        )
    }
    return receipt_document(
        {
            "schema_version": "bluefire.strix-worker-containment-activation.v1",
            "plan_ref": plan.plan_ref,
            **bindings,
            "observed_at": "2026-11-05T12:01:00Z",
            "plan_expires_at": plan.expires_at,
            "identity": {
                "uid": plan.uid,
                "gid": plan.gid,
                "generation": plan.identity_generation,
                "lease_ref": plan.identity_lease_ref,
            },
            "process": {
                "host_pid": host_pid,
                "start_ticks": 8_100_001,
                "pidfd_ref": retained_kernel_identity_digest(
                    role=f"pidfd:{host_pid}:8100001", st_dev=11, st_ino=201
                ),
                "pidfd_st_dev": 11,
                "pidfd_st_ino": 201,
                "pidfd_spawn_owned": True,
            },
            "cgroup": {
                "cgroup_ref": plan.cgroup_ref,
                "inode": 911_001,
                "pids_max": plan.pids_max,
                "pids_current": 3,
                "leader_tgid": host_pid,
                "member_threads": [
                    {"tid": host_pid, "tgid": host_pid},
                    {"tid": host_pid + 1, "tgid": host_pid},
                    {"tid": host_pid + 2, "tgid": host_pid},
                ],
                "memory_max_bytes": plan.memory_max_bytes,
                "cpu_quota_micros": plan.cpu_quota_micros,
                "cpu_period_micros": plan.cpu_period_micros,
                "leaf": True,
                "delegated": True,
                "controller_owned": True,
            },
            "namespaces": _namespace_observations(plan),
            "sealed_inputs": [
                {
                    **item.to_dict(),
                    "path": f"/inputs/{item.kind}.json",
                    "fd_st_dev": 21,
                    "fd_st_ino": 301 + index,
                    "seals": ["grow", "seal", "shrink", "write"],
                }
                for index, item in enumerate(plan.sealed_inputs)
            ],
            "private_roots": [
                {
                    "purpose": purpose,
                    "object_identity_digest": {
                        "config": plan.config_root_identity_digest,
                        "home": plan.home_root_identity_digest,
                        "tmp": plan.tmp_root_identity_digest,
                        "workspace": plan.workspace_root_identity_digest,
                    }[purpose],
                    "st_dev": 31,
                    "st_ino": 401 + index,
                    "owner_uid": plan.uid,
                    "owner_gid": plan.gid,
                    "mode": 0o700,
                    "writable": True,
                    "private": True,
                    "nosuid": True,
                    "nodev": True,
                    "noexec": True,
                }
                for index, purpose in enumerate(("config", "home", "tmp", "workspace"))
            ],
            "security": {
                "no_new_privs": True,
                "seccomp_digest": _d("seccomp"),
                "clone_filter_digest": _d("clone-filter"),
                "blocked_syscalls": [
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
                ],
                "clone_policy": "same_tgid_thread_only",
                "seccomp_tsync": True,
                "installed_before_authority": True,
                "audit_arch": "x86_64",
                "clone3_action": "errno:enosys",
                "process_spawn_action": "errno:eperm",
                "effective_capabilities": [],
                "ambient_capabilities": [],
                "dumpable": False,
            },
            "network": {
                "relays": [item.to_dict() for item in plan.relays],
                "network_namespace_ref": plan.relays[0].network_namespace_ref,
                "network_namespace_st_dev": plan.relays[0].network_namespace_st_dev,
                "network_namespace_st_ino": plan.relays[0].network_namespace_st_ino,
                "loopback_only": True,
                "default_route_absent": True,
                "dns_absent": True,
                "metadata_unreachable": True,
                "target_unreachable": True,
                "daemon_sockets_absent": True,
                "raw_socket_denied": True,
                "policy_digest": _d("network-policy"),
            },
            "mount_policy": {
                "policy_digest": _d("mount-policy"),
                "profile": "private-root-no-proc",
                "proc_mounted": False,
                "host_argv_env_unavailable": True,
                "inputs_materialized_before_pivot": True,
                "pivot_root_complete": True,
                "host_root_detached": True,
                "rootfs_identity_digest": retained_kernel_identity_digest(
                    role="private-rootfs", st_dev=61, st_ino=801
                ),
                "rootfs_st_dev": 61,
                "rootfs_st_ino": 801,
            },
        }
    )


def _activation():
    plan = _plan()
    document = _activation_document(plan)
    return plan, validate_activation_receipt(
        plan, document, _committed_activation_replay(plan, document)
    )


def _revalidation_document(activation) -> dict[str, object]:
    original = activation.document
    return receipt_document(
        {
            "schema_version": "bluefire.strix-worker-containment-revalidation.v1",
            "activation_ref": activation.receipt_ref,
            "plan_ref": original["plan_ref"],
            "attempt_id": original["attempt_id"],
            "binding_digest": original["binding_digest"],
            "installed_projection_ref": original["installed_projection_ref"],
            "startup_overlay_ref": original["startup_overlay_ref"],
            "sealed_inputs_ref": original["sealed_inputs_ref"],
            "controller_generation": original["controller_generation"],
            "controller_boot_id_digest": original["controller_boot_id_digest"],
            "observed_at": "2026-11-05T12:02:00Z",
            "host_pid": original["process"]["host_pid"],
            "start_ticks": original["process"]["start_ticks"],
            "pidfd_signallable": True,
            "cgroup_ref": original["cgroup"]["cgroup_ref"],
            "cgroup_inode": original["cgroup"]["inode"],
            "cgroup_snapshot_digest": content_hash(original["cgroup"]),
            "memory_max_bytes": original["cgroup"]["memory_max_bytes"],
            "cpu_quota_micros": original["cgroup"]["cpu_quota_micros"],
            "cpu_period_micros": original["cgroup"]["cpu_period_micros"],
            "leaf": original["cgroup"]["leaf"],
            "delegated": original["cgroup"]["delegated"],
            "controller_owned": original["cgroup"]["controller_owned"],
            "namespace_snapshot_digest": content_hash(original["namespaces"]),
            "input_snapshot_digest": content_hash(original["sealed_inputs"]),
            "root_snapshot_digest": content_hash(original["private_roots"]),
            "seccomp_digest": original["security"]["seccomp_digest"],
            "clone_filter_digest": original["security"]["clone_filter_digest"],
            "network_snapshot_digest": content_hash(original["network"]),
            "mount_policy_digest": original["mount_policy"]["policy_digest"],
            "proc_absent": True,
            "host_process_details_unavailable": True,
            "rootfs_identity_digest": original["mount_policy"]["rootfs_identity_digest"],
            "rootfs_st_dev": original["mount_policy"]["rootfs_st_dev"],
            "rootfs_st_ino": original["mount_policy"]["rootfs_st_ino"],
            "pids_max": original["cgroup"]["pids_max"],
            "pids_current": original["cgroup"]["pids_current"],
            "leader_tgid": original["cgroup"]["leader_tgid"],
            "member_threads": original["cgroup"]["member_threads"],
            "no_new_privs": True,
            "limits_unchanged": True,
            "relays_owned": True,
        }
    )


def _cleanup_document(activation, request) -> dict[str, object]:
    return receipt_document(
        {
            "schema_version": "bluefire.strix-worker-containment-cleanup-receipt.v1",
            "activation_ref": activation.receipt_ref,
            "request_ref": request.request_ref,
            "plan_ref": activation.document["plan_ref"],
            "attempt_id": activation.document["attempt_id"],
            "binding_digest": activation.document["binding_digest"],
            "controller_generation": activation.document["controller_generation"],
            "controller_boot_id_digest": activation.document["controller_boot_id_digest"],
            "observed_at": "2026-11-05T12:04:00Z",
            "pidfd_ref": activation.document["process"]["pidfd_ref"],
            "host_pid": activation.document["process"]["host_pid"],
            "start_ticks": activation.document["process"]["start_ticks"],
            "cgroup_ref": activation.document["cgroup"]["cgroup_ref"],
            "cgroup_inode": activation.document["cgroup"]["inode"],
            "identity_lease_ref": activation.document["identity"]["lease_ref"],
            "rootfs_identity_digest": activation.document["mount_policy"][
                "rootfs_identity_digest"
            ],
            "cancellation_requested": True,
            "pidfd_exit_observed": True,
            "process_absent": True,
            "cgroup_kill_used": False,
            "cgroup_empty": True,
            "cgroup_removed": True,
            "namespaces_absent": True,
            "private_roots_absent": True,
            "rootfs_absent": True,
            "relays_closed": True,
            "input_fds_closed": True,
            "identity_absent": True,
            "identity_lease_released": True,
        }
    )


def test_worker_receipts_round_trip_and_bind_every_runtime_identity() -> None:
    plan, activation = _activation()
    assert activation.document["attempt_id"] == plan.attempt_id
    assert activation.document["cgroup"]["member_threads"][1]["tgid"] == 42_001
    assert plan.sealed_inputs_ref == content_hash(_sealed_input_mount_facts())
    assert plan.sealed_inputs_ref == (
        "sha256:412818b92e006bb14df2ac5982c1a9353b0d320a8bd679b6d127331a619b16bd"
    )
    assert activation.to_dict() == _activation_document(plan)

    revalidated = StrixWorkerRevalidationReceipt.from_mapping(
        _revalidation_document(activation), activation
    )
    assert revalidated.document["pids_current"] == 3


@pytest.mark.parametrize(
    "field", ["installed_projection_ref", "startup_overlay_ref", "sealed_inputs_ref"]
)
def test_revalidation_rejects_substituted_projection_binding(field: str) -> None:
    _, activation = _activation()
    document = _revalidation_document(activation)
    document.pop("receipt_ref")
    document[field] = _d(f"substitute:{field}")
    with pytest.raises(StrixWorkerContainmentError, match="drifted"):
        StrixWorkerRevalidationReceipt.from_mapping(receipt_document(document), activation)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("rootfs_identity_digest", _d("substitute:rootfs")),
        ("rootfs_st_dev", 62),
        ("rootfs_st_ino", 802),
    ],
)
def test_revalidation_rejects_substituted_rootfs_identity(
    field: str, replacement: object
) -> None:
    _, activation = _activation()
    document = _revalidation_document(activation)
    document.pop("receipt_ref")
    document[field] = replacement
    with pytest.raises(StrixWorkerContainmentError):
        StrixWorkerRevalidationReceipt.from_mapping(receipt_document(document), activation)


@pytest.mark.parametrize(
    "field",
    [
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
        "controller_generation",
        "controller_boot_id_digest",
        "controller_peer_host_pid",
        "controller_peer_process_ref",
        "pid_namespace_profile",
        "replay_ledger_ref",
    ],
)
def test_activation_rejects_substituted_plan_binding(field: str) -> None:
    plan = _plan()
    document = _activation_document(plan)
    document.pop("receipt_ref")
    document[field] = (
        8
        if field == "controller_generation"
        else 41_901
        if field == "controller_peer_host_pid"
        else 42
        if field == "replay_generation"
        else "engine-attempt-" + "b" * 32
        if field == "attempt_id"
        else "isolated-pid"
        if field == "pid_namespace_profile"
        else _d(f"substitute:{field}")
    )
    with pytest.raises(StrixWorkerContainmentError):
        StrixWorkerActivationReceipt.from_mapping(receipt_document(document), plan)


def test_only_threads_in_the_owned_tgid_can_fill_the_bounded_cgroup() -> None:
    plan = _plan()
    document = _activation_document(plan)
    document.pop("receipt_ref")
    document["cgroup"]["member_threads"][2]["tgid"] = 99_001
    with pytest.raises(StrixWorkerContainmentError, match="cgroup"):
        StrixWorkerActivationReceipt.from_mapping(receipt_document(document), plan)

    plan_row = _plan_document()
    plan_row["pids_max"] = 1
    with pytest.raises(StrixWorkerContainmentError, match="task limit"):
        StrixWorkerContainmentPlan.from_mapping(plan_row)

    document = _activation_document(plan)
    document.pop("receipt_ref")
    document["cgroup"]["pids_max"] = plan.pids_max + 1
    with pytest.raises(StrixWorkerContainmentError, match="cgroup"):
        StrixWorkerActivationReceipt.from_mapping(receipt_document(document), plan)


def test_plan_and_activation_bind_one_observed_worker_network_namespace() -> None:
    plan_row = _plan_document()
    second_relay = plan_row["relays"][1]
    second_relay["network_namespace_st_ino"] = 602
    second_relay["network_namespace_ref"] = retained_kernel_identity_digest(
        role="worker-network-namespace", st_dev=42, st_ino=602
    )
    with pytest.raises(StrixWorkerContainmentError, match="share the exact"):
        StrixWorkerContainmentPlan.from_mapping(plan_row)

    plan = _plan()
    document = _activation_document(plan)
    document.pop("receipt_ref")
    document["namespaces"][2].update(
        {
            "identity_digest": retained_kernel_identity_digest(
                role="worker-network-namespace", st_dev=42, st_ino=602
            ),
            "st_ino": 602,
            "inode": 602,
        }
    )
    document["network"]["network_namespace_st_ino"] = 602
    document["network"]["network_namespace_ref"] = retained_kernel_identity_digest(
        role="worker-network-namespace", st_dev=42, st_ino=602
    )
    with pytest.raises(StrixWorkerContainmentError, match="network namespace"):
        StrixWorkerActivationReceipt.from_mapping(receipt_document(document), plan)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("security", "clone_policy"), "unrestricted"),
        (("security", "seccomp_tsync"), False),
        (("security", "clone3_action"), "errno:eperm"),
        (("security", "process_spawn_action"), "errno:enosys"),
        (("security", "no_new_privs"), False),
        (("network", "default_route_absent"), False),
        (("network", "target_unreachable"), False),
        (("private_roots", 1, "mode"), 0o755),
        (("private_roots", 3, "owner_uid"), 20_022),
        (("sealed_inputs", 0, "path"), "/inputs/wrong.json"),
        (("namespaces", 0, "host_inode"), 1000),
        (("namespaces", 3, "isolated"), True),
        (("mount_policy", "proc_mounted"), True),
        (("mount_policy", "rootfs_st_ino"), 802),
    ],
)
def test_activation_fails_closed_on_security_or_isolation_drift(path, replacement) -> None:
    plan = _plan()
    document = _activation_document(plan)
    document.pop("receipt_ref")
    cursor = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement
    with pytest.raises(StrixWorkerContainmentError):
        StrixWorkerActivationReceipt.from_mapping(receipt_document(document), plan)


def test_validated_receipt_is_immutable_and_rejects_direct_invalid_plan() -> None:
    plan, activation = _activation()
    exposed = activation.document
    exposed["process"]["host_pid"] = 99_999
    assert activation.document["process"]["host_pid"] == 42_001
    assert activation.receipt_ref == _activation_document(plan)["receipt_ref"]

    invalid = replace(plan, schema_version="unsupported")
    with pytest.raises(StrixWorkerContainmentError, match="version"):
        StrixWorkerActivationReceipt.from_mapping(_activation_document(plan), invalid)


def test_activation_rejects_wrong_replay_ledger_and_policy_digests() -> None:
    plan = _plan()
    unrelated = StrixWorkerReplayState.empty(
        ledger_ref=_d("unrelated-ledger"), head_digest=_d("unrelated-head")
    )
    with pytest.raises(StrixWorkerContainmentError, match="replay ledger"):
        validate_activation_receipt(plan, _activation_document(plan), unrelated)

    for section, field in (
        ("security", "seccomp_digest"),
        ("security", "clone_filter_digest"),
        ("network", "policy_digest"),
    ):
        document = _activation_document(plan)
        document.pop("receipt_ref")
        document[section][field] = _d(f"substituted:{field}")
        with pytest.raises(StrixWorkerContainmentError):
            StrixWorkerActivationReceipt.from_mapping(receipt_document(document), plan)


def test_activation_and_revalidation_must_precede_plan_expiry() -> None:
    plan_row = _plan_document()
    plan_row["expires_at"] = "2026-11-05T12:02:00Z"
    plan = StrixWorkerContainmentPlan.from_mapping(plan_row)
    document = _activation_document(plan)
    document.pop("receipt_ref")
    document["observed_at"] = "2026-11-05T12:03:00Z"
    with pytest.raises(StrixWorkerContainmentError, match="expiry"):
        StrixWorkerActivationReceipt.from_mapping(receipt_document(document), plan)

    _, activation = _activation()
    revalidation = _revalidation_document(activation)
    revalidation.pop("receipt_ref")
    revalidation["observed_at"] = "2026-11-05T12:31:00Z"
    with pytest.raises(StrixWorkerContainmentError):
        StrixWorkerRevalidationReceipt.from_mapping(receipt_document(revalidation), activation)


def test_revalidation_rejects_process_cgroup_or_snapshot_drift() -> None:
    _, activation = _activation()
    document = _revalidation_document(activation)
    document.pop("receipt_ref")
    document["pids_current"] = 2
    document["member_threads"] = [
        document["member_threads"][0],
        {"tid": 42_009, "tgid": document["leader_tgid"]},
    ]
    current = deepcopy(activation.document["cgroup"])
    current["pids_current"] = document["pids_current"]
    current["member_threads"] = document["member_threads"]
    document["cgroup_snapshot_digest"] = content_hash(current)
    changed = StrixWorkerRevalidationReceipt.from_mapping(receipt_document(document), activation)
    assert changed.document["pids_current"] == 2

    document = changed.to_dict()
    document.pop("receipt_ref")
    document["member_threads"][1]["tgid"] = 99_001
    with pytest.raises(StrixWorkerContainmentError, match="TGID"):
        StrixWorkerRevalidationReceipt.from_mapping(receipt_document(document), activation)

    document = _revalidation_document(activation)
    document.pop("receipt_ref")
    document["controller_owned"] = False
    with pytest.raises(StrixWorkerContainmentError):
        StrixWorkerRevalidationReceipt.from_mapping(receipt_document(document), activation)

    document = _revalidation_document(activation)
    document.pop("receipt_ref")
    document["network_snapshot_digest"] = _d("different-network")
    with pytest.raises(StrixWorkerContainmentError, match="drifted"):
        StrixWorkerRevalidationReceipt.from_mapping(receipt_document(document), activation)


def test_cleanup_requires_exact_activation_and_complete_absence() -> None:
    _, activation = _activation()
    request = StrixWorkerCleanupRequest.create(activation, requested_at="2026-11-05T12:03:00Z")
    row = _cleanup_document(activation, request)
    receipt = validate_cleanup_receipt(
        activation,
        request,
        row,
        _committed_cleanup_replay(activation, request),
    )
    assert receipt.document["cgroup_empty"] is True
    assert receipt.document["rootfs_absent"] is True

    incomplete = deepcopy(row)
    incomplete.pop("receipt_ref")
    incomplete["relays_closed"] = False
    with pytest.raises(StrixWorkerContainmentError):
        validate_cleanup_receipt(
            activation,
            request,
            receipt_document(incomplete),
            _committed_cleanup_replay(activation, request),
        )

    incomplete = deepcopy(row)
    incomplete.pop("receipt_ref")
    incomplete["rootfs_absent"] = False
    with pytest.raises(StrixWorkerContainmentError):
        validate_cleanup_receipt(
            activation,
            request,
            receipt_document(incomplete),
            _committed_cleanup_replay(activation, request),
        )


def test_replay_rejects_activation_and_cleanup_request_reuse() -> None:
    plan = _plan()
    document = _activation_document(plan)
    with pytest.raises(StrixWorkerContainmentError, match="expected replay successor"):
        validate_activation_receipt(plan, document, _replay())
    activation = validate_activation_receipt(
        plan, document, _committed_activation_replay(plan, document)
    )

    request = StrixWorkerCleanupRequest.create(activation, requested_at="2026-11-05T12:03:00Z")
    with pytest.raises(StrixWorkerContainmentError, match="replay ledger"):
        validate_cleanup_receipt(
            activation, request, _cleanup_document(activation, request), _replay()
        )

    different_request = StrixWorkerCleanupRequest.create(
        activation, requested_at="2026-11-05T12:03:01Z"
    )
    with pytest.raises(StrixWorkerContainmentError, match="replay ledger"):
        validate_cleanup_receipt(
            activation,
            different_request,
            _cleanup_document(activation, different_request),
            _committed_cleanup_replay(activation, request),
        )
