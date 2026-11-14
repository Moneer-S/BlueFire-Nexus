"""Qualify one pinned Linux Strix bootstrap without releasing model or tool work.

This same-job producer proves fixed interpreter/bootstrap execution and native
absence after cancellation. It deliberately does not start an installed Strix
investigation or create a product activation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from bluefire.strix_linux_fixed_exec import (
    FixedExecExpectedBindings,
    StrixLinuxFixedExecReceipt,
)
from bluefire.strix_linux_native_endpoint_cleanup import NativeGuestEndpointCleanupOwner
from bluefire.strix_linux_native_launch_material import prepare_native_launch
from bluefire.strix_linux_native_worker import (
    InstalledStrixLinuxWorkerController,
    OpenedWorkerContainmentDescriptors,
)
from bluefire.strix_linux_runtime_closure import (
    FIXED_ARGV,
    FIXED_CONTROL_SOCKET,
    FIXED_ENVIRONMENT,
    FIXED_GUEST_PROJECTION_DIGEST,
    FIXED_INPUT_PATHS,
    PRIVATE_DEVICE_POLICY_DIGEST,
    PRIVATE_OVERMOUNTS,
    SOURCE_REVISION,
    StrixLinuxRuntimeClosurePlan,
    _read_preparation_document,
    pin_runtime_closure,
    plan_prepared_runtime_closure,
)
from bluefire.util import canonical_json_bytes, content_hash
from tools.build_strix_worker_runtime_artifact import inspect_artifact
from tools.strix_runtime_closure_prepare_core import runtime_inventory_digest

_BASIS_SCHEMA = "bluefire.strix-fixed-exec-observation-basis.v1"
_QUALIFICATION_SCHEMA = "bluefire.strix-linux-fixed-exec-qualification.v1"
_COMPOSITE_SCHEMA = "bluefire.strix-linux-qualified-runtime-composite.v1"
_NO_DISPATCH_SCHEMA = "bluefire.strix-fixed-exec-no-dispatch-inputs.v1"
_RUNNER_NAME = "bluefire-runner"
_DIGEST_PREFIX = "sha256:"


class FixedExecQualificationError(RuntimeError):
    """The exact bootstrap or verified cleanup was not established."""


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return _DIGEST_PREFIX + digest.hexdigest()


def _write_document(path: Path, document: Mapping[str, Any], *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        payload = canonical_json_bytes(dict(document)) + b"\n"
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def _fd_fact(descriptor: int) -> dict[str, int]:
    row = os.fstat(descriptor)
    return {
        "device": row.st_dev,
        "inode": row.st_ino,
        "mode": stat.S_IMODE(row.st_mode),
        "uid": row.st_uid,
        "gid": row.st_gid,
    }


def _checked_handles_document(
    opened: OpenedWorkerContainmentDescriptors,
    observed: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the native checked, open descriptors rather than predicted refs."""
    return {
        "schema_version": "bluefire.strix-qualification-checked-handles.v1",
        "native_observation_ref": observed["observation_ref"],
        "pidfd": _fd_fact(opened.pidfd),
        "controller_rpc": _fd_fact(opened.controller_rpc_fd),
        "cgroup": _fd_fact(opened.cgroup_fd),
        "namespaces": {name: _fd_fact(fd) for name, fd in sorted(opened.namespace_fds.items())},
        "roots": {name: _fd_fact(fd) for name, fd in sorted(opened.root_fds.items())},
        "inputs": {name: _fd_fact(fd) for name, fd in sorted(opened.input_fds.items())},
        "relays": {name: _fd_fact(fd) for name, fd in sorted(opened.relay_fds.items())},
    }


def _inputs() -> dict[str, bytes]:
    # This intentionally cannot start a model or target operation if runpy wins
    # the race against cancellation after the qualified bootstrap receipt.
    return {
        "objective": canonical_json_bytes({"qualification_only": True}),
        "config": canonical_json_bytes({"qualification_only": True}),
        "mcp": canonical_json_bytes([]),
        "launch_material": canonical_json_bytes({"schema_version": _NO_DISPATCH_SCHEMA}),
    }


def _new_attempt_id() -> str:
    """Use the same bounded identity class as the guest endpoint owner."""
    return "engine-attempt-" + secrets.token_hex(16)


def _input_documents(payloads: Mapping[str, bytes]) -> tuple[dict[str, Any], dict[str, Any]]:
    rows = {
        name: {"digest": _DIGEST_PREFIX + hashlib.sha256(value).hexdigest(), "bytes": len(value)}
        for name, value in sorted(payloads.items())
    }
    bindings = {"schema_version": "bluefire.strix-qualification-input-bindings.v1", "inputs": rows}
    sealed = {
        "schema_version": "bluefire.strix-qualification-sealed-inputs.v1",
        "bindings_ref": content_hash(bindings),
        "inputs": {name: {**row, "mode": 0o444, "sealed": True} for name, row in rows.items()},
    }
    return bindings, sealed


def _receipt_basis(
    *,
    plan: StrixLinuxRuntimeClosurePlan,
    observed: Mapping[str, Any],
    attempt_id: str,
    claim_ref: str,
    runner_digest: str,
    input_bindings_ref: str,
    sealed_inputs_ref: str,
    worker_activation_ref: str,
    worker_containment_ref: str,
    endpoint_cleanup_ref: str,
) -> tuple[dict[str, Any], FixedExecExpectedBindings]:
    worker = observed["worker"]
    root = observed["private_root"]
    namespaces = observed["namespaces"]
    expected = FixedExecExpectedBindings.from_mapping({
        "attempt_id": attempt_id,
        "resource_claim_ref": claim_ref,
        "worker_activation_ref": worker_activation_ref,
        "worker_containment_ref": worker_containment_ref,
        "boundary_helper_digest": runner_digest,
        "worker_custody_identity_digest": observed["worker_custody_identity_digest"],
        "cgroup_ref": observed["cgroup_ref"],
        "seccomp_profile_digest": plan.seccomp_profile_digest,
        "input_bindings_ref": input_bindings_ref,
        "sealed_inputs_ref": sealed_inputs_ref,
        "startup_overlay_ref": plan.startup_overlay_ref,
        "installed_projection_ref": FIXED_GUEST_PROJECTION_DIGEST,
        "controller_socket_identity_ref": observed["controller_socket_identity_ref"],
        "model_listener_ref": observed["model_listener_ref"],
        "caido_listener_ref": observed["caido_listener_ref"],
        "endpoint_cleanup_authority_ref": endpoint_cleanup_ref,
        "endpoint_directory_identity_ref": observed["endpoint_directory_identity_ref"],
        "native_observation_ref": observed["observation_ref"],
        "controller_boot_id": plan.controller_boot_id,
        "worker_host_pid": worker["pid"],
        "worker_uid": worker["uid"],
        "worker_gid": worker["gid"],
        "worker_start_ticks": worker["start_ticks"],
        "worker_nspid": worker["nspid"],
    })
    receipt_base: dict[str, Any] = {
        **expected.to_dict(),
        "schema_version": "bluefire.strix-linux-fixed-exec-receipt.v1",
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "plan_ref": plan.plan_ref,
        "source_root_identity_digest": plan.root_identity_digest,
        "closure_inventory_digest": plan.inventory_digest,
        "interpreter_digest": plan.interpreter_digest,
        "strix_entrypoint_digest": plan.strix_entrypoint_digest,
        "bootstrap_digest": plan.bootstrap_digest,
        "lockdown_source_digest": plan.lockdown_source_digest,
        "private_root_mount_id": root["mount_id"],
        "private_root_st_dev": root["device"],
        "private_root_st_ino": root["inode"],
        "mount_namespace_inode": namespaces["mnt"]["inode"],
        "network_namespace_inode": namespaces["net"]["inode"],
        "ipc_namespace_inode": namespaces["ipc"]["inode"],
        "uts_namespace_inode": namespaces["uts"]["inode"],
        "argv_digest": content_hash(list(FIXED_ARGV)),
        "environment_digest": content_hash([list(item) for item in FIXED_ENVIRONMENT]),
        "input_paths_digest": content_hash([list(item) for item in FIXED_INPUT_PATHS]),
        "guest_projection_digest": FIXED_GUEST_PROJECTION_DIGEST,
        "private_device_policy_digest": PRIVATE_DEVICE_POLICY_DIGEST,
        "control_socket_path": FIXED_CONTROL_SOCKET,
        "private_overmounts": list(PRIVATE_OVERMOUNTS),
    }
    for name in (
        "execveat_empty_path", "fresh_address_space", "ambient_credentials_absent",
        "closure_copy_verified", "closure_mount_read_only", "closure_mount_nosuid",
        "closure_mount_nodev", "private_devices_exact", "private_etc_exact",
        "proc_absent", "sys_absent", "host_root_detached", "sealed_inputs_bound",
        "controller_socket_bound", "model_listener_bound", "caido_listener_bound",
        "supplementary_groups_empty", "capabilities_empty",
        "endpoint_cleanup_capability_held",
    ):
        receipt_base[name] = True
    armed = {
        "schema_version": "bluefire.strix-fixed-exec-armed.v1",
        "attempt_id": attempt_id,
        "plan_ref": plan.plan_ref,
        "worker_custody_identity_digest": observed["worker_custody_identity_digest"],
        "seccomp_profile_digest": plan.seccomp_profile_digest,
        "no_new_privileges": True,
        "seccomp_mode": 2,
        "tsync": True,
    }
    basis = {
        "schema_version": _BASIS_SCHEMA,
        "armed_payload": armed,
        "qualified_receipt_base": receipt_base,
    }
    basis["basis_ref"] = content_hash(basis)
    return basis, expected


def _composite(
    *, plan: StrixLinuxRuntimeClosurePlan, preparation: Mapping[str, Any],
    qualification_ref: str,
) -> dict[str, Any]:
    components = preparation["components"]
    document = {
        "schema_version": _COMPOSITE_SCHEMA,
        "prelaunch_plan_ref": plan.plan_ref,
        "fixed_exec_qualification_ref": qualification_ref,
        "inventory_digest": plan.inventory_digest,
        "interpreter_digest": plan.interpreter_digest,
        "entrypoint_digest": plan.bootstrap_digest,
        "worker_invocation_digest": content_hash({
            "schema_version": "bluefire.strix-installed-worker-invocation.v1",
            "argv": list(FIXED_ARGV),
            "caller_arguments_allowed": False,
        }),
        "worker_distribution": "bluefire-strix-worker",
        "worker_artifact_digest": plan.worker_artifact_digest,
        "worker_record_digest": plan.worker_record_digest,
        "worker_source_revision": plan.worker_source_revision,
        "installed_distributions_digest": components["installed_distributions_ref"],
        "full_product_wheel_present": False,
        "strix_candidate_digest": plan.package_digest,
        "source_revision": SOURCE_REVISION,
        "python_version": "3.12.14",
    }
    document["composite_ref"] = content_hash({
        "schema_version": _COMPOSITE_SCHEMA,
        "prelaunch_plan_ref": plan.plan_ref,
        "fixed_exec_qualification_ref": qualification_ref,
    })
    return document


def _verify_worker_artifact(
    path: Path,
    *,
    expected_source_revision: str,
    plan: StrixLinuxRuntimeClosurePlan,
    preparation: Mapping[str, Any],
) -> dict[str, Any]:
    """Reopen the same-job wheel; a preparation manifest is not wheel custody."""
    identity = inspect_artifact(path, expected_source_revision=expected_source_revision)
    components = preparation.get("components")
    if not isinstance(components, dict) or any((
        identity["artifact_digest"] != plan.worker_artifact_digest,
        identity["artifact_digest"] != components.get("worker_artifact_digest"),
        identity["manifest_digest"] != components.get("worker_artifact_manifest_digest"),
        identity["worker_record_digest"] != plan.worker_record_digest,
        identity["worker_record_digest"] != components.get("worker_record_digest"),
        identity["worker_source_revision"] != plan.worker_source_revision,
        identity["worker_source_revision"] != expected_source_revision,
    )):
        raise FixedExecQualificationError("worker wheel does not match prepared runtime")
    return identity


def _verified_preparation_document(
    path: Path, plan: StrixLinuxRuntimeClosurePlan
) -> dict[str, Any]:
    preparation, source_ref = _read_preparation_document(
        path, "strix-linux-runtime-preparation-manifest.json"
    )
    if source_ref != plan.preparation_manifest_ref:
        raise FixedExecQualificationError("prepared manifest identity changed")
    return preparation


def _exact_runtime_root(
    path: Path, plan: StrixLinuxRuntimeClosurePlan, pinned_root_fd: int
) -> None:
    """The published directory must be the inode the native helper consumed."""
    details = path.lstat()
    pinned = os.fstat(pinned_root_fd)
    expected = (plan.root_st_dev, plan.root_st_ino)
    if (
        path.is_symlink()
        or not stat.S_ISDIR(details.st_mode)
        or (details.st_dev, details.st_ino) != expected
        or (pinned.st_dev, pinned.st_ino) != expected
    ):
        raise FixedExecQualificationError("runtime root identity changed")


def qualify(
    *, runtime_root: Path, preparation_manifest: Path,
    qualification_manifest: Path, candidate_manifest: Path,
    worker_artifact: Path, runner_path: Path, runner_sha256: str,
    expected_worker_source_revision: str, output_root: Path,
) -> dict[str, Any]:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise FixedExecQualificationError("native qualifier requires root on Linux")
    if not runner_path.is_absolute() or runner_path.name != _RUNNER_NAME:
        raise FixedExecQualificationError("runner path must be a pinned bluefire-runner")
    if _file_digest(runner_path) != runner_sha256:
        raise FixedExecQualificationError("runner digest does not match")
    if (
        not output_root.is_absolute()
        or output_root.exists()
        or output_root.is_symlink()
        or output_root.parent.is_symlink()
        or not output_root.parent.is_dir()
    ):
        raise FixedExecQualificationError("output root must be new under an existing directory")
    plan = plan_prepared_runtime_closure(
        runtime_root, preparation_manifest, qualification_manifest, candidate_manifest,
        expected_worker_source_revision=expected_worker_source_revision,
    )
    preparation = _verified_preparation_document(preparation_manifest, plan)
    worker_identity = _verify_worker_artifact(
        worker_artifact,
        expected_source_revision=expected_worker_source_revision,
        plan=plan,
        preparation=preparation,
    )
    if runtime_root.stat().st_dev != output_root.parent.stat().st_dev:
        raise FixedExecQualificationError("qualified root must move within one filesystem")
    pinned = pin_runtime_closure(runtime_root, plan)
    attempt_id = _new_attempt_id()
    payloads = _inputs()
    input_bindings, sealed_inputs = _input_documents(payloads)
    claim = {
        "schema_version": "bluefire.strix-fixed-exec-qualification-claim.v1",
        "attempt_id": attempt_id,
        "plan_ref": plan.plan_ref,
        "runner_digest": runner_sha256,
        "input_bindings_ref": content_hash(input_bindings),
        "sealed_inputs_ref": content_hash(sealed_inputs),
        "product_activation": False,
        "model_effect_target_dispatch": False,
    }
    claim_ref = content_hash(claim)
    cancellation_fd = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
    native: InstalledStrixLinuxWorkerController | None = None
    endpoint: NativeGuestEndpointCleanupOwner | None = None
    host_launch_directory: Path | None = None
    terminal: Mapping[str, Any] | None = None
    documents: list[dict[str, Any]] = []
    try:
        with prepare_native_launch(
            pinned=pinned, runner_path=runner_path, expected_runner_digest=runner_sha256,
            attempt_id=attempt_id, resource_claim_ref=claim_ref,
            input_bindings_ref=content_hash(input_bindings),
            sealed_inputs_ref=content_hash(sealed_inputs),
            objective=payloads["objective"], config=payloads["config"],
            mcp=payloads["mcp"], launch_material=payloads["launch_material"],
            cancellation_fd=cancellation_fd,
        ) as launch:
            for name, payload in payloads.items():
                identity = launch.identity[name]
                if identity["digest"] != _DIGEST_PREFIX + hashlib.sha256(payload).hexdigest() or identity["byte_length"] != len(payload):
                    raise FixedExecQualificationError("sealed input identity changed")
            native = InstalledStrixLinuxWorkerController.start(
                runner_fd=launch.runner_fd, identity=launch.identity,
                descriptors=launch.descriptors,
            )
        observed = native.observed_document()
        if observed is None:
            raise FixedExecQualificationError("native observation unavailable")
        opened = native.open_containment_descriptors()
        try:
            checked_handles = _checked_handles_document(opened, observed)
        finally:
            opened.close()
        containment = {
            "schema_version": "bluefire.strix-qualification-observed-containment.v1",
            "native_observation_ref": observed["observation_ref"],
            "checked_handles_ref": content_hash(checked_handles),
            "product_activation": False,
        }
        containment_ref = content_hash(containment)
        activation = {
            "schema_version": "bluefire.strix-qualification-only-worker-observation.v1",
            "attempt_id": attempt_id,
            "resource_claim_ref": claim_ref,
            "plan_ref": plan.plan_ref,
            "native_observation_ref": observed["observation_ref"],
            "checked_handles_ref": content_hash(checked_handles),
            "product_activation": False,
            "model_effect_target_dispatch": False,
        }
        host_launch_directory = Path(tempfile.mkdtemp(prefix="strix-fixed-exec-host-", dir=output_root.parent))
        os.chmod(host_launch_directory, 0o700)
        host_stat = host_launch_directory.stat()
        endpoint = NativeGuestEndpointCleanupOwner(
            worker=native, attempt_id=attempt_id, claim_digest=claim_ref,
            resource_claim_ref=claim_ref,
            worker_containment_ref=containment_ref,
            host_launch_directory=host_launch_directory,
            host_directory_identity=(host_stat.st_dev, host_stat.st_ino),
            require_launch_file=False,
        )
        basis, expected = _receipt_basis(
            plan=plan, observed=observed, attempt_id=attempt_id,
            claim_ref=claim_ref, runner_digest=runner_sha256,
            input_bindings_ref=content_hash(input_bindings),
            sealed_inputs_ref=content_hash(sealed_inputs),
            worker_activation_ref=content_hash(activation),
            worker_containment_ref=containment_ref,
            endpoint_cleanup_ref=endpoint.cleanup_owner_ref,
        )
        native.qualify(basis)
        qualified = native.qualified_document
        if qualified is None:
            raise FixedExecQualificationError("native qualified receipt unavailable")
        verified = StrixLinuxFixedExecReceipt._from_authenticated_native(
            qualified, plan=plan, expected=expected,
        )
        # The intentionally invalid launch document can let the installed
        # worker exit immediately after the qualified bootstrap receipt.
        # An exit code does not establish why it exited or qualify runpy.
        # Neither path opens the controller RPC server.
        terminal = native.wait_and_reap(timeout_seconds=0.5)
        if terminal is None:
            terminal = native.cancel_and_reap()
        if (
            not (
                terminal.get("reason") == "cancelled"
                or (
                    terminal.get("reason") == "completed"
                    and terminal.get("exit_code") == 2
                    and terminal.get("signal") is None)
            )
            or terminal.get("verified_absent") is not True
            or native.cleanup_uncertain
        ):
            raise FixedExecQualificationError("native worker absence was not verified")
        os.rmdir(host_launch_directory)
        cleanup = endpoint.cleanup(launch_identity=None).to_dict()
        if cleanup.get("native_terminal_ref") != terminal["receipt_ref"]:
            raise FixedExecQualificationError("endpoint cleanup does not bind terminal")
        documents = list(native.accepted_native_documents())
        if [row["phase"] for row in documents] != ["observed", "qualified", "terminal"]:
            raise FixedExecQualificationError("authenticated native receipt chain incomplete")
        qualification = {
            "schema_version": _QUALIFICATION_SCHEMA,
            "scope": "fixed-exec-bootstrap",
            "installed_worker_entrypoint_executed": None,
            "installed_worker_entrypoint_qualified": False,
            "product_activation": False,
            "model_tool_target_effects": False,
            "attempt_id": attempt_id,
            "plan_ref": plan.plan_ref,
            "runner_digest": runner_sha256,
            "worker_artifact_digest": worker_identity["artifact_digest"],
            "worker_artifact_manifest_digest": worker_identity["manifest_digest"],
            "worker_record_digest": worker_identity["worker_record_digest"],
            "resource_claim_ref": claim_ref,
            "native_observation_ref": observed["observation_ref"],
            "fixed_exec_receipt_ref": verified.receipt_ref,
            "native_terminal_ref": terminal["receipt_ref"],
            "native_terminal_reason": terminal["reason"],
            "native_terminal_exit_code": terminal.get("exit_code"),
            "native_terminal_signal": terminal.get("signal"),
            "endpoint_cleanup_ref": cleanup["receipt_ref"],
            "native_packets_ref": content_hash({"packets": documents}),
            "verified_absent": True,
        }
        qualification_ref = content_hash(qualification)
        if _verified_preparation_document(preparation_manifest, plan) != preparation:
            raise FixedExecQualificationError("prepared manifest changed during qualification")
        if _verify_worker_artifact(
            worker_artifact,
            expected_source_revision=expected_worker_source_revision,
            plan=plan,
            preparation=preparation,
        ) != worker_identity:
            raise FixedExecQualificationError("worker wheel changed during qualification")
        composite = _composite(plan=plan, preparation=preparation, qualification_ref=qualification_ref)
        if runtime_inventory_digest(runtime_root) != plan.inventory_digest:
            raise FixedExecQualificationError("runtime inventory changed during qualification")
        _exact_runtime_root(runtime_root, plan, pinned.root_fd)
        output_root.mkdir(mode=0o700)
        final_root = output_root / "strix-linux-runtime-root"
        runtime_root.rename(final_root)
        _exact_runtime_root(final_root, plan, pinned.root_fd)
        if runtime_inventory_digest(final_root) != plan.inventory_digest:
            raise FixedExecQualificationError("moved runtime inventory changed")
        for name, doc in (
            ("strix-linux-prelaunch-plan.json", plan.to_dict()),
            ("qualification-claim.json", claim),
            ("qualification-input-bindings.json", input_bindings),
            ("qualification-sealed-inputs.json", sealed_inputs),
            ("qualification-checked-handles.json", checked_handles),
            ("qualification-observed-containment.json", containment),
            ("qualification-worker-observation.json", activation),
            ("qualification-native-observed.json", observed),
            ("qualification-native-qualified.json", qualified),
            ("qualification-native-terminal.json", terminal),
            ("qualification-endpoint-cleanup.json", cleanup),
            ("qualification-native-packets.json", {"packets": documents}),
            ("strix-linux-fixed-exec-qualification.json", {**qualification, "qualification_ref": qualification_ref}),
        ):
            _write_document(
                output_root / name, doc,
                mode=0o644 if name in {
                    "strix-linux-prelaunch-plan.json",
                    "strix-linux-fixed-exec-qualification.json",
                } else 0o600,
            )
        os.chmod(output_root, 0o755)
        _write_document(output_root / "strix-linux-runtime-composite.json", composite, mode=0o644)
        return composite
    finally:
        if native is not None:
            if terminal is None:
                try:
                    native.cancel_and_reap()
                except Exception:
                    pass
            if endpoint is not None:
                endpoint.close()
            native.close()
        if host_launch_directory is not None and host_launch_directory.exists():
            try:
                os.rmdir(host_launch_directory)
            except OSError:
                pass
        os.close(cancellation_fd)
        pinned.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "runtime-root", "preparation-manifest", "qualification-manifest",
        "candidate-manifest", "worker-artifact", "runner-path", "runner-sha256",
        "expected-worker-source-revision", "output-root",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    result = qualify(
        runtime_root=Path(args.runtime_root),
        preparation_manifest=Path(args.preparation_manifest),
        qualification_manifest=Path(args.qualification_manifest),
        candidate_manifest=Path(args.candidate_manifest),
        worker_artifact=Path(args.worker_artifact),
        runner_path=Path(args.runner_path),
        runner_sha256=args.runner_sha256,
        expected_worker_source_revision=args.expected_worker_source_revision,
        output_root=Path(args.output_root),
    )
    print(json.dumps({
        "composite_manifest": str(Path(args.output_root) / "strix-linux-runtime-composite.json"),
        "runtime_root": str(Path(args.output_root) / "strix-linux-runtime-root"),
        "composite_ref": result["composite_ref"],
        "scope": "fixed-exec-bootstrap",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
