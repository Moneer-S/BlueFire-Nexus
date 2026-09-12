"""Filesystem-only regressions: no WSL management or guest processes execute."""

from __future__ import annotations

import os
import stat
import sys
from types import SimpleNamespace

import pytest

from bluefire import lab_ownership as ownership
from bluefire import runner_descriptor_io as descriptors


def test_lab_ownership_exports_the_shared_identity_boundary():
    assert ownership.descriptor_identity is descriptors.descriptor_identity
    assert ownership.identity_format is descriptors.identity_format
    assert ownership._windows_file_identity is descriptors._windows_file_identity


@pytest.mark.parametrize(
    ("platform", "expected"),
    [("win32", "windows-file-id-info.v1"), ("linux", "posix-stat.v1")],
)
def test_identity_format_preserves_lease_format_names(monkeypatch, platform, expected):
    monkeypatch.setattr(descriptors, "sys", SimpleNamespace(platform=platform))
    assert ownership.identity_format() == expected


@pytest.mark.parametrize("stat_volume", [0x12345678, 0xFEDCBA9812345678])
def test_windows_identity_uses_full_native_volume_and_file_id(monkeypatch, stat_volume):
    full = (0xFEDCBA9812345678, 0xFEDCBA9812345678FEDCBA9812345678)
    details = SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=1, st_dev=stat_volume, st_ino=9)
    monkeypatch.setattr(descriptors, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(descriptors, "os", SimpleNamespace(fstat=lambda _fd: details))
    monkeypatch.setattr(descriptors, "_windows_file_identity", lambda _fd: full)
    assert ownership.descriptor_identity(17) == full


def test_native_identity_failure_never_falls_back_to_stat(monkeypatch):
    details = SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=1, st_dev=1, st_ino=2)
    monkeypatch.setattr(descriptors, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(descriptors, "os", SimpleNamespace(fstat=lambda _fd: details))

    def unavailable(_descriptor):
        raise OSError("native identity unavailable")

    monkeypatch.setattr(descriptors, "_windows_file_identity", unavailable)
    with pytest.raises(OSError, match="native identity unavailable"):
        ownership.descriptor_identity(17)


@pytest.mark.parametrize("fault", [None, "file_id", "attributes", "reparse"])
def test_native_file_information_requires_full_id_and_ordinary_handle(monkeypatch, fault):
    calls = []

    class Query:
        def __call__(self, _handle, kind, target, _size):
            calls.append(kind)
            if kind == 18:
                if fault == "file_id":
                    return False
                target._obj.VolumeSerialNumber = 0xFEDCBA9812345678
                target._obj.FileId[:] = bytes(range(16))
            else:
                assert kind == 9
                if fault == "attributes":
                    return False
                target._obj.FileAttributes = 0x400 if fault == "reparse" else 0
            return True

    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(get_osfhandle=lambda _: 7))
    monkeypatch.setattr(
        descriptors.ctypes,
        "WinDLL",
        lambda *_a, **_k: SimpleNamespace(GetFileInformationByHandleEx=Query()),
        raising=False,
    )
    if fault is None:
        assert ownership._windows_file_identity(17) == (
            0xFEDCBA9812345678,
            int.from_bytes(bytes(range(16)), "little"),
        )
    else:
        with pytest.raises(OSError, match="identity is unavailable"):
            ownership._windows_file_identity(17)
    assert calls == ([18] if fault == "file_id" else [18, 9])


@pytest.mark.parametrize(
    ("mode", "links", "attributes", "directory"),
    [
        (stat.S_IFREG, 2, 0, False),
        (stat.S_IFLNK, 1, 0, False),
        (stat.S_IFREG, 1, 0x400, False),
        (stat.S_IFDIR, 1, 0x400, True),
        (stat.S_IFREG, 1, 0, True),
        (stat.S_IFDIR, 1, 0, False),
    ],
)
def test_shared_descriptor_refuses_nonordinary_objects_before_native_identity(
    monkeypatch, mode, links, attributes, directory
):
    details = SimpleNamespace(st_mode=mode, st_nlink=links, st_file_attributes=attributes)
    monkeypatch.setattr(descriptors, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(descriptors, "os", SimpleNamespace(fstat=lambda _fd: details))
    monkeypatch.setattr(
        descriptors,
        "_windows_file_identity",
        lambda _fd: pytest.fail("unsafe descriptor reached the identity query"),
    )
    with pytest.raises(ValueError, match="ordinary"):
        ownership.descriptor_identity(17, directory=directory)


def test_path_and_open_file_identity_agree_and_handle_stays_owned(tmp_path):
    path = tmp_path / "owned"
    path.write_bytes(b"reviewed")
    with path.open("rb") as handle:
        assert ownership.identity(path, directory=False) == ownership.descriptor_identity(
            handle.fileno()
        )
        assert handle.read() == b"reviewed"


@pytest.mark.parametrize("kind", ["hardlink", "wrong_type"])
def test_identity_retains_file_type_and_link_guards(tmp_path, kind):
    path = tmp_path / "owned"
    path.write_bytes(b"reviewed")
    if kind == "hardlink":
        os.link(path, tmp_path / "linked")
    with pytest.raises(ValueError, match="ordinary"):
        ownership.identity(path, directory=kind == "wrong_type")


def test_empty_storage_cleanup_refuses_replacement_and_retained_disk(tmp_path):
    path = tmp_path / "storage"
    path.mkdir()
    original = ownership.identity(path, directory=True)
    disk = path / "retained.vhdx"
    disk.write_bytes(b"test-owned disk stand-in")
    assert not ownership.remove_empty_storage(path, original)
    assert disk.read_bytes() == b"test-owned disk stand-in"
    assert not ownership.remove_empty_storage(path, (original[0], original[1] + 1))
    disk.unlink()
    assert ownership.remove_empty_storage(path, original)
    assert ownership.path_absent(path)


def test_dangling_link_is_not_absence(monkeypatch):
    path = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=stat.S_IFLNK))
    assert ownership.path_absent(path) is False


@pytest.mark.parametrize(
    "source", ["bluefire/lab_ownership.py", "bluefire/runner_descriptor_io.py"]
)
def test_lab_identity_source_is_required_by_existing_provider_audit(source):
    from bluefire import provider_gate
    from tests_platform.test_provider_gate import _structural_report

    report = _structural_report()
    provider_gate._validate_structural(report)
    shell = report["checks"]["no_model_shell"]
    shell["source_files"] = [row for row in shell["source_files"] if row["path"] != source]
    with pytest.raises(ValueError, match="no-model-shell evidence is invalid"):
        provider_gate._validate_structural(report)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle deletion")
def test_windows_deletion_pins_exact_directory_and_refuses_rename(tmp_path, monkeypatch):
    path = tmp_path / "storage"
    path.mkdir()
    expected = ownership.identity(path, directory=True)
    original = ownership._windows_mark_delete_descriptor
    attempted = []

    def delete(descriptor):
        with pytest.raises(OSError):
            path.rename(tmp_path / "moved")
        attempted.append(True)
        original(descriptor)

    monkeypatch.setattr(ownership, "_windows_mark_delete_descriptor", delete)
    assert ownership.remove_empty_storage(path, expected)
    assert attempted == [True]
