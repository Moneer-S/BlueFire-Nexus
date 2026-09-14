from __future__ import annotations

import pytest

from bluefire.cross_platform_wheel import _write_member
from tools.verify_packaged_runner import _disposable_workspace_proof, _native_runner_members


def test_packaged_wheel_refuses_foreign_native_runner_sibling() -> None:
    root = "bluefire_nexus-3.0.0.data/purelib/bluefire/native"
    with pytest.raises(RuntimeError, match="exactly one target-native runner"):
        _native_runner_members(
            [f"{root}/bluefire-runner.exe", f"{root}/bluefire-runner"],
            "bluefire-runner.exe",
        )


def test_wheel_member_extraction_preserves_binary_bytes(tmp_path) -> None:
    payload = b"MZ\n\x1a\n\x00binary\r\npayload\n"
    destination = tmp_path / "bluefire-runner.exe"

    _write_member(destination, payload)

    assert destination.read_bytes() == payload


def test_disposable_workspace_proof_is_sanitized_and_machine_checkable(tmp_path):
    checkout = tmp_path / "checkout"
    work_root = tmp_path / "runner-temp" / "bluefire-wheel-smoke-state"
    sandbox = work_root / "sandbox"
    checkout.mkdir()
    sandbox.mkdir(parents=True)

    proof = _disposable_workspace_proof(
        work_root=work_root,
        checkout=checkout,
        sandbox=sandbox,
        remaining_files=[],
        signed_alias={"remaining_file_count": 0},
    )

    assert proof == {
        "schema_version": "bluefire.disposable-workspace-proof.v1",
        "work_root": {
            "role": "ci-temp-disposable",
            "outside_checkout": True,
            "path": "omitted",
        },
        "source": {
            "wheel_imported_outside_checkout": True,
            "source_overrides_absent": True,
        },
        "sandboxes": [
            {
                "name": "fixture-smoke",
                "relative_scope": "sandbox",
                "inside_work_root": True,
                "remaining_file_count": 0,
            },
            {
                "name": "signed-alias-smoke",
                "relative_scope": "alias-sandbox",
                "inside_work_root": True,
                "remaining_file_count": 0,
            },
        ],
    }
    serialized = repr(proof)
    assert str(tmp_path) not in serialized
    assert str(checkout) not in serialized
    assert str(work_root) not in serialized


def test_disposable_workspace_proof_refuses_checkout_work_root(tmp_path):
    checkout = tmp_path / "checkout"
    work_root = checkout / "wheel-smoke-state"
    sandbox = work_root / "sandbox"
    sandbox.mkdir(parents=True)

    with pytest.raises(RuntimeError, match="outside the checkout"):
        _disposable_workspace_proof(
            work_root=work_root,
            checkout=checkout,
            sandbox=sandbox,
            remaining_files=[],
            signed_alias={"remaining_file_count": 0},
        )


def test_disposable_workspace_proof_refuses_escaped_or_dirty_sandbox(tmp_path):
    checkout = tmp_path / "checkout"
    work_root = tmp_path / "runner-temp" / "bluefire-wheel-smoke-state"
    escaped_sandbox = tmp_path / "other" / "sandbox"
    retained = work_root / "sandbox" / "leak.txt"
    checkout.mkdir()
    work_root.mkdir(parents=True)
    escaped_sandbox.mkdir(parents=True)

    with pytest.raises(RuntimeError, match="inside the disposable root"):
        _disposable_workspace_proof(
            work_root=work_root,
            checkout=checkout,
            sandbox=escaped_sandbox,
            remaining_files=[],
            signed_alias={"remaining_file_count": 0},
        )

    with pytest.raises(RuntimeError, match="retained files"):
        _disposable_workspace_proof(
            work_root=work_root,
            checkout=checkout,
            sandbox=work_root / "sandbox",
            remaining_files=[retained],
            signed_alias={"remaining_file_count": 0},
        )

    with pytest.raises(RuntimeError, match="retained file count"):
        _disposable_workspace_proof(
            work_root=work_root,
            checkout=checkout,
            sandbox=work_root / "sandbox",
            remaining_files=[],
            signed_alias={},
        )
