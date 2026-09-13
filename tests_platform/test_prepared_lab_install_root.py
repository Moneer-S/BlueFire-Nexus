"""Fresh clone root metadata is secured before accounts or executable paths exist."""

from types import SimpleNamespace

import pytest

from bluefire import prepared_lab_install as installer


@pytest.mark.parametrize("mode,expected", [(0o777, 0o755), (0o755, 0o755), (0o770, 0o750)])
def test_imported_clone_root_loses_only_group_and_world_write(monkeypatch, mode, expected):
    metadata = SimpleNamespace(st_mode=0o40000 | mode, st_uid=0, st_gid=0, st_dev=1, st_ino=2)
    writes = []

    def chmod(value):
        writes.append(value)
        metadata.st_mode = 0o40000 | value

    root = SimpleNamespace(lstat=lambda: metadata, chmod=chmod)
    monkeypatch.setattr(installer.sys, "platform", "linux")
    monkeypatch.setattr(installer.os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(installer, "Path", lambda path: root if path == "/" else pytest.fail(path))
    installer.secure_clone_root()
    assert writes == [expected]
    assert metadata.st_mode == 0o40000 | expected


@pytest.mark.parametrize("fault", ["owner", "group", "type", "readback", "identity"])
def test_unsafe_clone_root_or_failed_sealing_refuses(monkeypatch, fault):
    before = SimpleNamespace(st_mode=0o40777, st_uid=0, st_gid=0, st_dev=1, st_ino=2)
    if fault == "owner":
        before.st_uid = 1000
    elif fault == "group":
        before.st_gid = 1000
    elif fault == "type":
        before.st_mode = 0o120777
    after = SimpleNamespace(**vars(before))
    calls = []

    def chmod(mode):
        calls.append(mode)
        if fault != "readback":
            after.st_mode = 0o40000 | mode
        if fault == "identity":
            after.st_ino += 1

    values = iter((before, after))
    root = SimpleNamespace(lstat=lambda: next(values), chmod=chmod)
    monkeypatch.setattr(installer.sys, "platform", "linux")
    monkeypatch.setattr(installer.os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(installer, "Path", lambda _: root)
    with pytest.raises(ValueError, match="clone filesystem root"):
        installer.secure_clone_root()
    assert calls == ([0o755] if fault in {"readback", "identity"} else [])
