from __future__ import annotations

import os
from pathlib import Path

import pytest

from bluefire import runner_private_files as files
from bluefire import windows_owner_acl as acl
from bluefire.runner_transport_errors import RunnerTransportError


def prepared(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    with files._PinnedPrivateDirectory(root) as directory:
        directory.create("record.json", b'{"safe":true}', maximum=128)
    return root


def test_verified_reads_do_not_apply_permissions(tmp_path, monkeypatch):
    root = prepared(tmp_path)
    before = [
        (path.stat().st_ctime_ns, path.stat().st_mode) for path in (root, root / "record.json")
    ]

    def forbidden(*args, **kwargs):
        pytest.fail("read-only verification attempted permission repair")

    monkeypatch.setattr(files, "_owner_private_handle", forbidden)
    monkeypatch.setattr(acl, "apply_owner_private_acl", forbidden)
    if os.name != "nt":
        monkeypatch.setattr(os, "fchmod", forbidden)
    with files._PinnedPrivateDirectory(root, verify_permissions_only=True) as directory:
        assert directory.names(maximum=1) == ("record.json",)
        assert directory.read("record.json", maximum=128) == b'{"safe":true}'
        assert directory.directory_identity() == (root.stat().st_dev, root.stat().st_ino)
    after = [
        (path.stat().st_ctime_ns, path.stat().st_mode) for path in (root, root / "record.json")
    ]
    assert after == before


def test_unsafe_file_permissions_are_refused_without_repair(tmp_path):
    root = prepared(tmp_path)
    path = root / "unverified.json"
    path.write_bytes(b"not accepted")
    if os.name != "nt":
        path.chmod(0o644)
    before = path.stat()
    with files._PinnedPrivateDirectory(root, verify_permissions_only=True) as directory:
        with pytest.raises(OSError, match="permissions"):
            directory.read(path.name, maximum=128)
    after = path.stat()
    assert (before.st_ctime_ns, before.st_mode) == (after.st_ctime_ns, after.st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode contract")
def test_unsafe_directory_mode_is_not_repaired(tmp_path):
    root = prepared(tmp_path)
    root.chmod(0o755)
    before = root.stat()
    with pytest.raises(RunnerTransportError):
        with files._PinnedPrivateDirectory(root, verify_permissions_only=True):
            pytest.fail("unsafe directory accepted")
    assert root.stat().st_mode == before.st_mode
    assert root.stat().st_ctime_ns == before.st_ctime_ns


@pytest.mark.parametrize("value", [None, 0, 1, "true"])
def test_permission_mode_is_type_strict(tmp_path, value):
    with pytest.raises(RunnerTransportError):
        files._PinnedPrivateDirectory(tmp_path, verify_permissions_only=value)


def test_hardlinked_record_is_rejected(tmp_path):
    root = prepared(tmp_path)
    os.link(root / "record.json", root / "alias.json")
    with files._PinnedPrivateDirectory(root, verify_permissions_only=True) as directory:
        with pytest.raises(OSError):
            directory.read("record.json", maximum=128)


def test_permission_change_during_held_read_is_refused(tmp_path, monkeypatch):
    root = prepared(tmp_path)
    original = files._verify_private_permissions
    seen = []

    def verify(descriptor, *, directory):
        original(descriptor, directory=directory)
        seen.append(directory)
        if not directory:
            raise OSError("private-object permissions are invalid")

    monkeypatch.setattr(files, "_verify_private_permissions", verify)
    with files._PinnedPrivateDirectory(root, verify_permissions_only=True) as directory:
        with pytest.raises(OSError, match="permissions"):
            directory.read("record.json", maximum=128)
    assert False in seen


@pytest.mark.parametrize("method", ["read", "file_identity"])
@pytest.mark.parametrize("verify_only", [False, True])
def test_read_and_identity_open_only_the_requested_access(
    tmp_path, monkeypatch, method, verify_only
):
    root = prepared(tmp_path)
    original = files._PinnedPrivateDirectory._open_existing
    calls = []

    def opened(self, name, **options):
        calls.append(options.get("write_dac", False))
        return original(self, name, **options)

    monkeypatch.setattr(files._PinnedPrivateDirectory, "_open_existing", opened)
    with files._PinnedPrivateDirectory(root, verify_permissions_only=verify_only) as directory:
        getattr(directory, method)("record.json", maximum=128)
    assert calls == [not verify_only]


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL contract")
@pytest.mark.parametrize("descriptor,directory", [(-1, False), (True, False), (0, 1)])
def test_windows_verification_rejects_bad_inputs(descriptor, directory):
    with pytest.raises(acl.WindowsOwnerAclError):
        acl.verify_owner_private_acl(descriptor, directory=directory)
