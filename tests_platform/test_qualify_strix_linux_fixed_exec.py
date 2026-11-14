"""Cross-module contracts for the no-dispatch native fixed-exec qualifier."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

if sys.platform != "linux":
    pytest.skip("Linux native fixed-exec qualification", allow_module_level=True)

from bluefire.strix_linux_fixed_exec import StrixLinuxFixedExecReceipt
from bluefire.strix_linux_native_endpoint_cleanup import _ATTEMPT
from bluefire.strix_linux_runtime_closure import StrixLinuxRuntimeClosurePlan
from bluefire.strix_worker_fixed_bootstrap import _QUALIFIED_RECEIPT_BASE_FIELDS
from bluefire.util import content_hash
from tests_platform.test_build_strix_worker_runtime_artifact import _build
from tests_platform.test_strix_linux_runtime_closure import _plan_document
from tools.qualify_strix_linux_fixed_exec import (
    FixedExecQualificationError,
    _composite,
    _exact_runtime_root,
    _input_documents,
    _inputs,
    _new_attempt_id,
    _receipt_basis,
    _verified_preparation_document,
    _verify_worker_artifact,
    _write_document,
)


def _digest(label: str) -> str:
    return content_hash({"qualifier-test": label})


def _observed() -> dict[str, object]:
    return {
        "observation_ref": _digest("observed"),
        "worker_custody_identity_digest": _digest("custody"),
        "cgroup_ref": _digest("cgroup"),
        "controller_socket_identity_ref": _digest("controller-socket"),
        "model_listener_ref": _digest("model-listener"),
        "caido_listener_ref": _digest("caido-listener"),
        "endpoint_directory_identity_ref": _digest("endpoint-directory"),
        "worker": {"pid": 2234, "uid": 60001, "gid": 60001, "start_ticks": 123456,
                   "nspid": [2234, 1]},
        "private_root": {"mount_id": 31, "device": 32, "inode": 33},
        "namespaces": {name: {"inode": 40 + index} for index, name in enumerate(
            ("mnt", "net", "ipc", "uts")
        )},
    }


def test_qualifier_attempt_identity_is_accepted_by_endpoint_owner() -> None:
    assert _ATTEMPT.fullmatch(_new_attempt_id()) is not None


def test_only_public_composite_handoff_is_readable_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    old_umask = os.umask(0o077)
    try:
        private = tmp_path / "qualification-native-packets.json"
        public = tmp_path / "strix-linux-runtime-composite.json"
        plan_path = tmp_path / "strix-linux-prelaunch-plan.json"
        plan = StrixLinuxRuntimeClosurePlan.from_mapping(_plan_document())
        _write_document(private, {"receipt": "private"})
        _write_document(public, {"composite": "digests-only"}, mode=0o644)
        _write_document(plan_path, plan.to_dict(), mode=0o644)
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert stat.S_IMODE(public.stat().st_mode) == 0o644
    assert stat.S_IMODE(plan_path.stat().st_mode) == 0o644
    assert StrixLinuxRuntimeClosurePlan.from_mapping(
        json.loads(plan_path.read_text(encoding="utf-8"))
    ).plan_ref == plan.plan_ref


def test_preparation_manifest_path_swap_cannot_change_published_components(
    tmp_path: Path,
) -> None:
    path = tmp_path / "strix-linux-runtime-preparation-manifest.json"
    _write_document(path, {"components": {"installed_distributions_ref": _digest("first")}})
    original_ref = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    plan = SimpleNamespace(preparation_manifest_ref=original_ref)
    assert _verified_preparation_document(path, plan)["components"][
        "installed_distributions_ref"
    ] == _digest("first")
    path.unlink()
    _write_document(path, {"components": {"installed_distributions_ref": _digest("swapped")}})
    with pytest.raises(FixedExecQualificationError):
        _verified_preparation_document(path, plan)


def test_published_runtime_must_be_same_inode_as_pinned_launch_root(tmp_path: Path) -> None:
    original = tmp_path / "original"
    swapped = tmp_path / "swapped"
    original.mkdir()
    swapped.mkdir()
    original_fd = os.open(original, os.O_RDONLY | os.O_DIRECTORY)
    try:
        details = original.stat()
        plan = SimpleNamespace(root_st_dev=details.st_dev, root_st_ino=details.st_ino)
        _exact_runtime_root(original, plan, original_fd)
        with pytest.raises(FixedExecQualificationError):
            _exact_runtime_root(swapped, plan, original_fd)
    finally:
        os.close(original_fd)


def test_worker_wheel_is_reopened_against_preparation_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    built, _payload = _build(tmp_path, "worker")
    path = Path(str(built["artifact_path"]))
    expected_revision = "a" * 40
    plan = SimpleNamespace(
        worker_artifact_digest=built["artifact_digest"],
        worker_record_digest=built["worker_record_digest"],
        worker_source_revision=expected_revision,
    )
    components = {
        "worker_artifact_digest": built["artifact_digest"],
        "worker_artifact_manifest_digest": built["manifest_digest"],
        "worker_record_digest": built["worker_record_digest"],
    }
    preparation = {"components": components}
    identity = _verify_worker_artifact(
        path, expected_source_revision=expected_revision,
        plan=plan, preparation=preparation,
    )
    assert identity["artifact_digest"] == built["artifact_digest"]
    altered_preparation = deepcopy(preparation)
    altered_preparation["components"]["worker_artifact_manifest_digest"] = _digest("wrong")
    with pytest.raises(FixedExecQualificationError):
        _verify_worker_artifact(
            path, expected_source_revision=expected_revision,
            plan=plan, preparation=altered_preparation,
        )
    with path.open("ab") as output:
        output.write(b"tampered")
    with pytest.raises(FixedExecQualificationError):
        _verify_worker_artifact(
            path, expected_source_revision=expected_revision,
            plan=plan, preparation=preparation,
        )


def test_basis_matches_guest_contract_and_qualifies_only_authenticated_receipt() -> None:
    plan = StrixLinuxRuntimeClosurePlan.from_mapping(_plan_document())
    basis, expected = _receipt_basis(
        plan=plan, observed=_observed(), attempt_id="qualifier-1",
        claim_ref=_digest("claim"), runner_digest=_digest("runner"),
        input_bindings_ref=_digest("inputs"), sealed_inputs_ref=_digest("sealed"),
        worker_activation_ref=_digest("qualification-only-observation"),
        worker_containment_ref=_digest("checked-containment"),
        endpoint_cleanup_ref=_digest("endpoint-owner"),
    )
    assert set(basis["qualified_receipt_base"]) == _QUALIFIED_RECEIPT_BASE_FIELDS
    assert basis["basis_ref"] == content_hash({
        name: value for name, value in basis.items() if name != "basis_ref"
    })
    qualified = deepcopy(basis["qualified_receipt_base"])
    qualified.update({
        "startup_imports_verified": True,
        "required_threads_verified": True,
        "exec_process_probes_refused": True,
        "seccomp_tsync_armed": True,
        "no_new_privileges": True,
        "production_activation_eligible": True,
    })
    qualified["receipt_ref"] = content_hash(qualified)
    receipt = StrixLinuxFixedExecReceipt._from_authenticated_native(
        qualified, plan=plan, expected=expected,
    )
    assert receipt.receipt_ref == qualified["receipt_ref"]


def test_no_dispatch_inputs_and_composite_scope_are_explicit() -> None:
    payloads = _inputs()
    assert all(b"http" not in value and b"api_key" not in value for value in payloads.values())
    bindings, sealed = _input_documents(payloads)
    assert sealed["bindings_ref"] == content_hash(bindings)
    plan = StrixLinuxRuntimeClosurePlan.from_mapping(_plan_document())
    composite = _composite(
        plan=plan,
        preparation={"components": {"installed_distributions_ref": _digest("distributions")}},
        qualification_ref=_digest("native-qualification"),
    )
    assert composite["composite_ref"] == content_hash({
        "schema_version": composite["schema_version"],
        "prelaunch_plan_ref": plan.plan_ref,
        "fixed_exec_qualification_ref": _digest("native-qualification"),
    })
    assert composite["full_product_wheel_present"] is False


def test_receipt_refusal_if_observed_identity_changes() -> None:
    plan = StrixLinuxRuntimeClosurePlan.from_mapping(_plan_document())
    basis, expected = _receipt_basis(
        plan=plan, observed=_observed(), attempt_id="qualifier-1",
        claim_ref=_digest("claim"), runner_digest=_digest("runner"),
        input_bindings_ref=_digest("inputs"), sealed_inputs_ref=_digest("sealed"),
        worker_activation_ref=_digest("qualification-only-observation"),
        worker_containment_ref=_digest("checked-containment"),
        endpoint_cleanup_ref=_digest("endpoint-owner"),
    )
    qualified = deepcopy(basis["qualified_receipt_base"])
    qualified.update({
        "startup_imports_verified": True,
        "required_threads_verified": True,
        "exec_process_probes_refused": True,
        "seccomp_tsync_armed": True,
        "no_new_privileges": True,
        "production_activation_eligible": True,
    })
    qualified["native_observation_ref"] = _digest("substituted-observation")
    qualified["receipt_ref"] = content_hash(qualified)
    with pytest.raises(ValueError):
        StrixLinuxFixedExecReceipt._from_authenticated_native(
            qualified, plan=plan, expected=expected,
        )
