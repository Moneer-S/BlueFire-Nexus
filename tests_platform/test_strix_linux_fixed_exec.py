from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from bluefire import strix_linux_fixed_exec as fixed_exec
from bluefire import strix_linux_runtime_closure as closure
from bluefire.util import content_hash
from tests_platform.test_strix_linux_runtime_closure import _plan_document


def _sha(label: str) -> str:
    return content_hash({"fixed-exec-fixture": label})


def _expected() -> fixed_exec.FixedExecExpectedBindings:
    return fixed_exec.FixedExecExpectedBindings.from_mapping(
        {
            "attempt_id": "attempt-fixed-exec-1",
            "resource_claim_ref": _sha("resource-claim"),
            "worker_activation_ref": _sha("worker-activation"),
            "worker_containment_ref": _sha("worker-containment"),
            "boundary_helper_digest": _sha("boundary-helper"),
            "worker_custody_identity_digest": _sha("worker-custody"),
            "cgroup_ref": _sha("worker-cgroup"),
            "seccomp_profile_digest": _sha("seccomp-profile"),
            "input_bindings_ref": _sha("input-bindings"),
            "sealed_inputs_ref": _sha("sealed-inputs"),
            "startup_overlay_ref": _sha("startup-overlay"),
            "installed_projection_ref": closure.FIXED_GUEST_PROJECTION_DIGEST,
            "controller_socket_identity_ref": _sha("controller-socket"),
            "model_listener_ref": _sha("model-listener"),
            "caido_listener_ref": _sha("caido-listener"),
            "endpoint_cleanup_authority_ref": _sha("cleanup-authority"),
            "endpoint_directory_identity_ref": _sha("endpoint-directory"),
            "native_observation_ref": _sha("native-observation"),
            "controller_boot_id": "11111111-2222-3333-4444-555555555555",
            "worker_host_pid": 12345,
            "worker_uid": 60001,
            "worker_gid": 60001,
            "worker_start_ticks": 987654,
            "worker_nspid": [12345],
        }
    )


def _receipt_document() -> tuple[dict[str, Any], closure.StrixLinuxRuntimeClosurePlan]:
    plan_document = _plan_document()
    plan_document["seccomp_profile_digest"] = _sha("seccomp-profile")
    plan_document["startup_overlay_ref"] = _sha("startup-overlay")
    plan = closure.StrixLinuxRuntimeClosurePlan.from_mapping(plan_document)
    expected = _expected()
    document: dict[str, Any] = {
        **expected.to_dict(),
        "schema_version": fixed_exec.RECEIPT_SCHEMA,
        "observed_at": "2026-11-05T12:00:00Z",
        "plan_ref": plan.plan_ref,
        "source_root_identity_digest": plan.root_identity_digest,
        "closure_inventory_digest": plan.inventory_digest,
        "interpreter_digest": plan.interpreter_digest,
        "strix_entrypoint_digest": plan.strix_entrypoint_digest,
        "bootstrap_digest": plan.bootstrap_digest,
        "lockdown_source_digest": plan.lockdown_source_digest,
        "private_root_mount_id": 301,
        "private_root_st_dev": 302,
        "private_root_st_ino": 303,
        "mount_namespace_inode": 401,
        "network_namespace_inode": 402,
        "ipc_namespace_inode": 403,
        "uts_namespace_inode": 404,
        "argv_digest": content_hash(list(closure.FIXED_ARGV)),
        "environment_digest": content_hash(
            [list(item) for item in closure.FIXED_ENVIRONMENT]
        ),
        "input_paths_digest": content_hash(
            [list(item) for item in closure.FIXED_INPUT_PATHS]
        ),
        "guest_projection_digest": closure.FIXED_GUEST_PROJECTION_DIGEST,
        "private_device_policy_digest": closure.PRIVATE_DEVICE_POLICY_DIGEST,
        "control_socket_path": closure.FIXED_CONTROL_SOCKET,
        "private_overmounts": list(closure.PRIVATE_OVERMOUNTS),
        "execveat_empty_path": True,
        "fresh_address_space": True,
        "ambient_credentials_absent": True,
        "closure_copy_verified": True,
        "closure_mount_read_only": True,
        "closure_mount_nosuid": True,
        "closure_mount_nodev": True,
        "private_devices_exact": True,
        "private_etc_exact": True,
        "proc_absent": True,
        "sys_absent": True,
        "host_root_detached": True,
        "sealed_inputs_bound": True,
        "controller_socket_bound": True,
        "model_listener_bound": True,
        "caido_listener_bound": True,
        "supplementary_groups_empty": True,
        "capabilities_empty": True,
        "no_new_privileges": True,
        "seccomp_tsync_armed": True,
        "exec_process_probes_refused": True,
        "startup_imports_verified": True,
        "required_threads_verified": True,
        "endpoint_cleanup_capability_held": True,
        "production_activation_eligible": True,
    }
    document["receipt_ref"] = content_hash(document)
    return document, plan


def test_authenticated_native_receipt_binds_every_controller_identity() -> None:
    document, plan = _receipt_document()

    receipt = fixed_exec.StrixLinuxFixedExecReceipt._from_authenticated_native(
        document, plan=plan, expected=_expected()
    )

    assert receipt.receipt_ref == document["receipt_ref"]
    assert receipt.to_dict()["plan_ref"] == plan.plan_ref
    assert receipt.to_dict()["private_device_policy_digest"] == (
        closure.PRIVATE_DEVICE_POLICY_DIGEST
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("worker_activation_ref", _sha("wrong-activation")),
        ("worker_host_pid", 12346),
        ("seccomp_profile_digest", _sha("wrong-policy")),
        ("guest_projection_digest", _sha("wrong-projection")),
        ("bootstrap_digest", _sha("wrong-bootstrap")),
        ("endpoint_cleanup_capability_held", False),
    ],
)
def test_native_receipt_refuses_identity_or_kernel_fact_substitution(
    field: str, replacement: object
) -> None:
    document, plan = _receipt_document()
    document[field] = replacement
    document["receipt_ref"] = content_hash(
        {name: value for name, value in document.items() if name != "receipt_ref"}
    )

    with pytest.raises(closure.StrixLinuxRuntimeClosureError):
        fixed_exec.StrixLinuxFixedExecReceipt._from_authenticated_native(
            document, plan=plan, expected=_expected()
        )


def test_receipt_self_hash_does_not_replace_controller_expected_bindings() -> None:
    document, plan = _receipt_document()
    expected = _expected()
    substituted = deepcopy(expected.to_dict())
    substituted["resource_claim_ref"] = _sha("different-claim")
    document["resource_claim_ref"] = substituted["resource_claim_ref"]
    document["receipt_ref"] = content_hash(
        {name: value for name, value in document.items() if name != "receipt_ref"}
    )

    with pytest.raises(closure.StrixLinuxRuntimeClosureError):
        fixed_exec.StrixLinuxFixedExecReceipt._from_authenticated_native(
            document, plan=plan, expected=expected
        )


def test_serialized_receipt_is_not_a_live_authority() -> None:
    document, plan = _receipt_document()
    receipt = fixed_exec.StrixLinuxFixedExecReceipt._from_authenticated_native(
        document, plan=plan, expected=_expected()
    )

    assert not isinstance(receipt, fixed_exec.FixedExecAuthority)
    assert not hasattr(receipt, "verify")
    with pytest.raises(TypeError):
        fixed_exec.StrixLinuxFixedExecReceipt()
