"""Focused descriptor and identity checks for the installed worker launch."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

if sys.platform != "linux":
    pytest.skip("Linux memfd contract", allow_module_level=True)

fcntl = pytest.importorskip("fcntl")

from bluefire import strix_linux_native_launch_material as launch  # noqa: E402
from bluefire import strix_linux_runtime_closure as closure  # noqa: E402
from bluefire.util import content_hash  # noqa: E402

linux = pytest.mark.skipif(sys.platform != "linux", reason="Linux memfd contract")
root_linux = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0, reason="native helper runs as root"
)


@linux
def test_sealed_launch_input_has_exact_mode_digest_and_seals() -> None:
    descriptor = launch._sealed_file("unit", b"sample\n", mode=0o444, maximum=32)
    try:
        assert launch._identity(descriptor) == {
            "digest": "sha256:" + hashlib.sha256(b"sample\n").hexdigest(),
            "byte_length": 7,
            "mode": 0o444,
            "seals": launch._INPUT_SEALS,
        }
        assert fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) == launch._INPUT_SEALS
        with pytest.raises(OSError):
            os.write(descriptor, b"changed")
    finally:
        os.close(descriptor)


def _fake_pinned(root: Path) -> tuple[Any, Any]:
    relative = (
        "bootstrap/worker.py",
        "bootstrap/worker_lockdown.py",
        "runtime/bin/python",
        "runtime/bin/strix",
    )
    files = []
    directories = set()
    for item in relative:
        path = root / item
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = (item + "\n").encode()
        path.write_bytes(payload)
        mode = 0o555 if item == "runtime/bin/python" else 0o444
        path.chmod(mode)
        files.append(
            closure.RuntimeFile.from_mapping(
                {
                    "path": item,
                    "mode": mode,
                    "size": len(payload),
                    "content_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                }
            )
        )
        for ancestor in path.relative_to(root).parents:
            if ancestor.as_posix() != ".":
                directories.add(ancestor.as_posix())
    directory_rows = tuple(
        closure.RuntimeDirectory.from_mapping({"path": item, "mode": 0o555})
        for item in sorted(directories)
    )
    file_rows = tuple(sorted(files, key=lambda row: row.path))
    inventory = {
        "schema_version": "bluefire.strix-linux-runtime-inventory.v1",
        "directories": [item.to_dict() for item in directory_rows],
        "files": [item.to_dict() for item in file_rows],
        "total_bytes": sum(item.size for item in file_rows),
    }
    plan = SimpleNamespace(
        directory_inventory=directory_rows,
        file_inventory=file_rows,
        inventory_digest=content_hash(inventory),
        plan_ref=content_hash({"test": "plan"}),
        seccomp_profile_digest=content_hash({"test": "seccomp"}),
        startup_overlay_ref=content_hash({"test": "startup"}),
        root_identity_digest=content_hash({"test": "root"}),
        controller_boot_id="11111111-2222-3333-4444-555555555555",
    )
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    executable_fd = os.open(root / "runtime/bin/python", os.O_RDONLY)

    class Pinned:
        def __init__(self) -> None:
            self.plan = plan
            self.root_fd = root_fd
            self.executable_fd = executable_fd

        def verify(self) -> None:
            os.fstat(self.root_fd)
            os.fstat(self.executable_fd)

    return Pinned(), plan


@root_linux
def test_prepare_native_launch_seals_exact_manifest_and_refuses_changed_source(
    tmp_path: Path,
) -> None:
    root = tmp_path / "strix-linux-runtime-root"
    root.mkdir()
    pinned, plan = _fake_pinned(root)
    runner = tmp_path / "bluefire-runner"
    runner.write_bytes(b"#!/bin/sh\nexit 0\n")
    runner.chmod(0o555)
    runner_digest = "sha256:" + hashlib.sha256(runner.read_bytes()).hexdigest()
    cancellation_fd, cancellation_writer = os.pipe()
    try:
        values = dict(
            pinned=pinned,
            runner_path=runner,
            expected_runner_digest=runner_digest,
            attempt_id="engine-attempt-test",
            resource_claim_ref=content_hash({"test": "claim"}),
            input_bindings_ref=content_hash({"test": "inputs"}),
            sealed_inputs_ref=content_hash({"test": "sealed"}),
            objective=b"Inspect the generated test target.\n",
            config=b'{"env":{}}\n',
            mcp=b"[]\n",
            launch_material=b"fixed-frame",
            cancellation_fd=cancellation_fd,
        )
        with launch.prepare_native_launch(**values) as prepared:
            identity = prepared.identity
            descriptor_set = prepared.descriptors
            runner_fd = prepared.runner_fd
            assert os.fstat(runner_fd).st_ino == runner.stat().st_ino
            assert len(descriptor_set.as_tuple()) == 11
            assert identity["prelaunch_bindings"]["boundary_helper_digest"] == runner_digest
            assert identity["prelaunch_bindings"]["source_root_identity_digest"] == plan.root_identity_digest
            manifest_fd = descriptor_set.closure_manifest
            assert stat.S_IMODE(os.fstat(manifest_fd).st_mode) == 0o400
            assert fcntl.fcntl(manifest_fd, fcntl.F_GET_SEALS) == launch._INPUT_SEALS
            payload = os.pread(manifest_fd, os.fstat(manifest_fd).st_size, 0)
            manifest = json.loads(payload)
            assert manifest["schema_version"] == launch._NATIVE_MANIFEST_SCHEMA
            assert manifest["inventory_digest"] == plan.inventory_digest
            assert identity["closure_manifest_ref"] == "sha256:" + hashlib.sha256(payload).hexdigest()
        with pytest.raises(OSError):
            os.fstat(runner_fd)
        (root / "bootstrap/worker.py").chmod(0o644)
        (root / "bootstrap/worker.py").write_bytes(b"changed\n")
        with pytest.raises(launch.StrixNativeLaunchMaterialError):
            launch.prepare_native_launch(**values)
    finally:
        os.close(cancellation_fd)
        os.close(cancellation_writer)
        os.close(pinned.executable_fd)
        os.close(pinned.root_fd)
