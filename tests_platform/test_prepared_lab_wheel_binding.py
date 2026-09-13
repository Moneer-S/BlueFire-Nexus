from __future__ import annotations

import io
import os
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from bluefire import prepared_lab as lab
from tests_platform.test_prepared_lab import _wheel


def _inputs(tmp_path: Path) -> tuple[Path, Path, list[lab.WheelInput]]:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    product = _wheel(tmp_path / "bluefire_nexus-3.0.0-py3-none-linux_x86_64.whl", relocated=True)
    dependency = wheelhouse / "dependency-1.0-py3-none-any.whl"
    dependency.write_bytes(b"reviewed dependency bytes")
    return product, wheelhouse, lab.wheel_inputs(product, wheelhouse)


def _archive(wheels: list[lab.WheelInput]) -> bytes:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w|") as archive:
        for wheel in wheels:
            lab._archive_wheel(archive, wheel)
    return payload.getvalue()


def _tamper(path: Path, offset: int = 0) -> None:
    details = path.stat()
    with path.open("r+b") as handle:
        handle.seek(offset)
        old = handle.read(1)
        handle.seek(offset)
        handle.write(bytes([old[0] ^ 1]))
    os.utime(path, ns=(details.st_atime_ns, details.st_mtime_ns))


def test_install_archive_contains_exact_validated_wheel_bytes(tmp_path: Path) -> None:
    _, _, wheels = _inputs(tmp_path)
    with tarfile.open(fileobj=io.BytesIO(_archive(wheels))) as archive:
        assert archive.getnames() == [wheel.path.name for wheel in wheels]
        for wheel in wheels:
            member = archive.getmember(wheel.path.name)
            assert member.size == wheel.size and member.mode == 0o644
            source = archive.extractfile(member)
            assert source is not None and source.read() == wheel.path.read_bytes()


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("change", ["replace", "same_inode", "hardlink"])
def test_archive_refuses_changed_product_or_dependency(
    tmp_path: Path, index: int, change: str
) -> None:
    _, _, wheels = _inputs(tmp_path)
    wheel = wheels[index]
    if change == "replace":
        payload = wheel.path.read_bytes()
        wheel.path.rename(wheel.path.with_suffix(".old"))
        wheel.path.write_bytes(payload)  # Even identical bytes are a new file owner.
    elif change == "same_inode":
        _tamper(wheel.path)
        assert lab.identity(wheel.path, directory=False) == wheel.identity
        assert wheel.path.stat().st_size == wheel.size
    else:
        os.link(wheel.path, wheel.path.with_suffix(".linked"))
    with pytest.raises(ValueError, match="wheel|unlinked"):
        _archive(wheels)


def test_archive_revalidates_the_opened_handle_before_copying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, wheels = _inputs(tmp_path)
    selected = wheels[0]
    replacement = tmp_path / "replacement.whl"
    replacement.write_bytes(selected.path.read_bytes())
    original_open = Path.open

    def open_path(path: Path, *args: Any, **kwargs: Any) -> Any:
        return original_open(replacement if path == selected.path else path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_path)
    monkeypatch.setattr(
        tarfile.TarFile,
        "addfile",
        lambda *args, **kwargs: pytest.fail("replacement handle reached archive copy"),
    )
    with pytest.raises(ValueError, match="opening"):
        _archive(wheels)


def test_digest_checks_the_bytes_actually_copied_during_a_concurrent_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product, wheelhouse, _ = _inputs(tmp_path)
    with zipfile.ZipFile(product, "a") as archive:
        archive.writestr("padding.bin", b"0" * 131072)
    wheels = lab.wheel_inputs(product, wheelhouse)
    original_read = lab._WheelCopy.read
    changed = False

    def read(source: lab._WheelCopy, size: int) -> bytes:
        nonlocal changed
        block = original_read(source, size)
        if not changed:
            changed = True
            _tamper(product, len(block) + 1)
        return block

    monkeypatch.setattr(lab._WheelCopy, "read", read)
    with pytest.raises(ValueError, match="bytes changed"):
        _archive(wheels)
    assert changed


def test_product_validation_uses_the_snapshot_whose_digest_is_retained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product, wheelhouse, _ = _inputs(tmp_path)
    validate = lab._validate_product_wheel

    def swap_then_validate(path: Path, snapshot: Any) -> None:
        _wheel(path, platform="windows", relocated=True)
        validate(path, snapshot)

    monkeypatch.setattr(lab, "_validate_product_wheel", swap_then_validate)
    wheels = lab.wheel_inputs(product, wheelhouse)
    with pytest.raises(ValueError, match="wheel"):
        _archive(wheels)


@pytest.mark.parametrize("index", [0, 1])
def test_replacement_during_clone_never_reaches_the_guest_installer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, index: int
) -> None:
    product, wheelhouse, wheels = _inputs(tmp_path)
    state = tmp_path / "state"
    captured: dict[str, lab.DisposableWslDistribution] = {}
    cleanup = []

    def create(executable: Path, runtime: Path) -> lab.DisposableWslDistribution:
        install = runtime / ("wsl-distribution-" + "1" * 16)
        install.mkdir()
        lease = lab.DisposableWslDistribution(
            executable,
            runtime,
            "BlueFire-Gate11-Run-" + "1" * 16,
            install,
            lab.identity(install, directory=True),
            registration_id="guid",
        )
        monkeypatch.setattr(lease, "cleanup", lambda: cleanup.append(True))
        captured["lease"] = lease
        if index == 0:
            _wheel(product, platform="windows", relocated=True)
        else:
            _tamper(wheels[index].path)
        return lease

    monkeypatch.setattr(lab, "_trusted_wsl_executable", lambda: Path(sys.executable))
    monkeypatch.setattr(lab, "create_disposable_wsl_distribution", create)
    monkeypatch.setattr(lab, "registration", lambda _: ("guid", captured["lease"].install_root))
    monkeypatch.setattr(
        lab.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("changed wheel reached guest installation"),
    )
    with pytest.raises(ValueError, match="wheel"):
        lab.prepare(state, product, wheelhouse)
    assert cleanup == [True]


def test_installer_receives_the_original_archive_handle_without_reopening_its_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product, wheelhouse, wheels = _inputs(tmp_path)
    state = tmp_path / "state"
    captured: dict[str, lab.DisposableWslDistribution] = {}
    replacement = tmp_path / "replacement.tar"
    replacement.write_bytes(b"unvalidated replacement archive")
    reopened = []
    installed = []
    original_open = Path.open

    def create(executable: Path, runtime: Path) -> lab.DisposableWslDistribution:
        install = runtime / ("wsl-distribution-" + "2" * 16)
        install.mkdir()
        lease = lab.DisposableWslDistribution(
            executable,
            runtime,
            "BlueFire-Gate11-Run-" + "2" * 16,
            install,
            lab.identity(install, directory=True),
            registration_id="guid",
        )
        monkeypatch.setattr(lease, "cleanup", lambda: None)
        captured["lease"] = lease
        return lease

    def open_path(path: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if path == state / "wheel-inputs.tar" and mode == "rb":
            # Model the pathname being rebound after validation. On Windows,
            # retaining the original open handle may itself deny that rename.
            reopened.append(True)
            return original_open(replacement, mode, *args, **kwargs)
        return original_open(path, mode, *args, **kwargs)

    def install(_command: Any, **kwargs: Any) -> None:
        payload = kwargs.get("stdin")
        if payload is not None:
            installed.append(payload.read())

    monkeypatch.setattr(lab, "_trusted_wsl_executable", lambda: Path(sys.executable))
    monkeypatch.setattr(lab, "create_disposable_wsl_distribution", create)
    monkeypatch.setattr(lab, "registration", lambda _: ("guid", captured["lease"].install_root))
    monkeypatch.setattr(Path, "open", open_path)
    monkeypatch.setattr(lab.subprocess, "run", install)
    lab.prepare(state, product, wheelhouse)
    assert not reopened
    assert installed == [_archive(wheels)]
