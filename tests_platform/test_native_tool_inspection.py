"""Deterministic filesystem model: these are not installed-tool/live proofs."""

from __future__ import annotations

import errno
import hashlib
import stat
from types import SimpleNamespace

import pytest

from bluefire import native_tool_inspection as inspection
from bluefire.native_tool_installations import NativeToolInstallation


class Filesystem:
    O_RDONLY = 0
    O_DIRECTORY = 1
    O_NOFOLLOW = 2
    O_CLOEXEC = 4
    O_NONBLOCK = 8

    def __init__(self):
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        header[16:18] = (2).to_bytes(2, "little")
        header[18:20] = (62).to_bytes(2, "little")
        self.content = bytes(header) + b"reviewed-fixture-bytes"
        self.closed = []
        self.opened = []
        self.position = 0
        self.capability = None
        self.rebound = False
        self.mutate_after_hash = False
        self.read_failure = False
        self.stats = {}
        for descriptor in (10, 11, 12, 13):
            self.stats[descriptor] = SimpleNamespace(
                st_dev=1,
                st_ino=descriptor,
                st_uid=0,
                st_gid=0,
                st_mode=(stat.S_IFREG | 0o755) if descriptor == 13 else (stat.S_IFDIR | 0o755),
                st_size=len(self.content) if descriptor == 13 else 4096,
                st_mtime_ns=1,
                st_ctime_ns=1,
                st_nlink=1,
            )

    def open(self, path, flags, *, dir_fd=None):
        expected = [("/", None), ("usr", 10), ("bin", 11), ("chmod", 12)]
        assert (path, dir_fd) == expected[len(self.opened)]
        assert flags & self.O_NOFOLLOW
        assert flags & self.O_CLOEXEC
        if len(self.opened) < 3:
            assert flags & self.O_DIRECTORY
        else:
            assert flags & self.O_NONBLOCK
        descriptor = 10 + len(self.opened)
        self.opened.append(descriptor)
        return descriptor

    def close(self, descriptor):
        self.closed.append(descriptor)

    def fstat(self, descriptor):
        return SimpleNamespace(**vars(self.stats[descriptor]))

    def getxattr(self, descriptor, name):
        assert descriptor == 13 and name == "security.capability"
        if self.capability is None:
            raise OSError(errno.ENODATA, "no attribute")
        if isinstance(self.capability, Exception):
            raise self.capability
        return self.capability

    def read(self, descriptor, size):
        assert descriptor == 13 and 0 < size <= 65536
        if self.read_failure:
            raise OSError("private installation path must not be surfaced")
        chunk = self.content[self.position : self.position + size]
        self.position += len(chunk)
        return chunk

    def stat(self, path, *, dir_fd, follow_symlinks):
        assert not follow_symlinks
        descriptor = {(10, "usr"): 11, (11, "bin"): 12, (12, "chmod"): 13}[(dir_fd, path)]
        if descriptor == 13 and self.mutate_after_hash:
            self.stats[13].st_ctime_ns += 1
        result = self.fstat(descriptor)
        if self.rebound:
            result.st_ino += 100
        return result


def record(filesystem):
    return NativeToolInstallation.from_mapping(
        {
            "schema_version": "bluefire.native-tool-installation.v1",
            "adapter_id": "sandbox.permission.chmod.v1",
            "adapter_version": "1.0.0",
            "adapter_contract_digest": "sha256:" + "a" * 64,
            "tool_id": "gnu.coreutils.chmod.v1",
            "tool_version": "9.4",
            "platform": "linux",
            "architecture": "x86_64",
            "content_sha256": "sha256:" + hashlib.sha256(filesystem.content).hexdigest(),
            "size_bytes": len(filesystem.content),
            "installation_location": "/usr/bin/chmod",
        }
    )


@pytest.fixture
def filesystem(monkeypatch):
    value = Filesystem()
    monkeypatch.setattr(inspection, "os", value)
    monkeypatch.setattr(inspection, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(inspection, "platform", SimpleNamespace(machine=lambda: "x86_64"))
    return value


def test_inspection_matches_exact_bytes_without_executing_and_closes_handles(filesystem):
    installed = record(filesystem)
    result = inspection.inspect_native_tool(installed)
    assert result.installation_digest == installed.digest
    assert result.content_sha256 == installed.to_dict()["content_sha256"]
    assert result.size_bytes == len(filesystem.content)
    assert filesystem.closed == [13, 12, 11, 10]


@pytest.mark.parametrize(
    "descriptor,field,value",
    [
        (10, "st_uid", 1000),
        (11, "st_mode", stat.S_IFDIR | 0o777),
        (12, "st_mode", stat.S_IFLNK | 0o755),
        (13, "st_uid", 1000),
        (13, "st_mode", stat.S_IFREG | 0o6755),
        (13, "st_mode", stat.S_IFREG | 0o777),
        (13, "st_mode", stat.S_IFREG | 0o644),
        (13, "st_mode", stat.S_IFIFO | 0o755),
        (13, "st_nlink", 0),
    ],
)
def test_unprotected_ownership_or_file_kind_is_refused(filesystem, descriptor, field, value):
    setattr(filesystem.stats[descriptor], field, value)
    with pytest.raises(inspection.NativeToolInspectionError, match="not protected"):
        inspection.inspect_native_tool(record(filesystem))
    assert filesystem.closed == list(reversed(filesystem.opened))


@pytest.mark.parametrize(
    "problem,code",
    [
        ("changed_bytes", "digest_mismatch"),
        ("size", "size_mismatch"),
        ("short_read", "installation_changed"),
        ("excess", "installation_changed"),
        ("architecture", "unsupported_binary"),
        ("script", "unsupported_binary"),
        ("rebound", "installation_changed"),
        ("after_hash", "installation_changed"),
        ("capability", "unexpected_privilege"),
        ("unknown_capability", "capabilities_unknown"),
        ("read_failure", "inspection_unavailable"),
    ],
)
def test_changed_or_unreviewed_tool_is_refused(filesystem, problem, code):
    installed = record(filesystem)
    if problem == "changed_bytes":
        filesystem.content = filesystem.content[:-1] + b"X"
    elif problem == "size":
        filesystem.stats[13].st_size += 1
    elif problem == "short_read":
        filesystem.content = filesystem.content[:-1]
    elif problem == "excess":
        filesystem.content += b"X"
    elif problem == "architecture":
        filesystem.content = filesystem.content[:18] + b"\xb7\0" + filesystem.content[20:]
    elif problem == "script":
        filesystem.content = b"#!/bin/sh" + filesystem.content[9:]
    elif problem == "rebound":
        filesystem.rebound = True
    elif problem == "after_hash":
        filesystem.mutate_after_hash = True
    elif problem == "capability":
        filesystem.capability = b"unreviewed"
    elif problem == "unknown_capability":
        filesystem.capability = OSError(errno.EACCES, "unavailable")
    else:
        filesystem.read_failure = True
    with pytest.raises(inspection.NativeToolInspectionError) as caught:
        inspection.inspect_native_tool(installed)
    assert caught.value.code == code
    assert "/usr/bin" not in str(caught.value)
    assert filesystem.closed == list(reversed(filesystem.opened))


def test_platform_mismatch_does_not_open_anything(filesystem, monkeypatch):
    monkeypatch.setattr(inspection, "sys", SimpleNamespace(platform="win32"))
    with pytest.raises(inspection.NativeToolInspectionError) as caught:
        inspection.inspect_native_tool(record(filesystem))
    assert caught.value.code == "unsupported_platform"
    assert filesystem.opened == []


@pytest.mark.parametrize("interruption", ["cancel", "deadline"])
def test_interruption_closes_every_owned_descriptor(filesystem, monkeypatch, interruption):
    ticks = iter([0, 0, 0, 0, 0, 10])
    if interruption == "deadline":
        monkeypatch.setattr(inspection, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    with pytest.raises(inspection.NativeToolInspectionError) as caught:
        inspection.inspect_native_tool(
            record(filesystem),
            cancelled=lambda: interruption == "cancel" and len(filesystem.opened) == 4,
        )
    assert caught.value.code == ("cancelled" if interruption == "cancel" else "inspection_timeout")
    assert filesystem.closed == list(reversed(filesystem.opened))
