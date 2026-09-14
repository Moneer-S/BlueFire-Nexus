from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

import bluefire.runner_bootstrap as runner_bootstrap
import bluefire.runner_host as runner_host
import bluefire.runner_lifecycle as runner_lifecycle
import bluefire.runner_trust as runner_trust
from bluefire.windows_owner_acl import WindowsOwnerAclError, apply_owner_private_acl_path


def test_native_staging_remains_importable_without_site_packages() -> None:
    repository = Path(__file__).resolve().parents[1]
    completed = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-S",
            "-B",
            "-c",
            (
                "import sys; import bluefire.runner_bootstrap; import tools.stage_native_runner; "
                "assert 'bluefire.runner_trust' not in sys.modules; "
                "assert 'cryptography' not in sys.modules"
            ),
        ],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="non-Windows fail-closed contract")
def test_owner_acl_path_fails_closed_off_windows(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    path.write_bytes(b"unchanged")

    with pytest.raises(WindowsOwnerAclError, match="input is invalid"):
        apply_owner_private_acl_path(path, directory=False)

    assert path.read_bytes() == b"unchanged"


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL contract")
def test_bootstrap_lifecycle_and_host_acl_hardening_need_no_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_root = tmp_path / "private-runtime"
    payload = private_root / "state.bin"
    original = b"owner-bound"

    def unavailable(*args: object, **kwargs: object) -> None:
        raise AssertionError("ACL hardening must not start a subprocess")

    monkeypatch.setattr(subprocess, "run", unavailable)
    assert runner_bootstrap._private_directory(private_root) == private_root.resolve(strict=True)
    payload.write_bytes(original)
    runner_bootstrap._set_executable_mode(payload)
    runner_lifecycle._owner_private_pinned(private_root, directory=True)
    runner_lifecycle._owner_private_pinned(payload, directory=False)
    runner_trust._owner_private(payload, directory=False)

    descriptor = os.open(payload, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        before = os.fstat(descriptor)
        runner_host._owner_private_open_regular(payload, descriptor)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    assert (after.st_dev, after.st_ino, after.st_size) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
    )
    assert payload.read_bytes() == original
