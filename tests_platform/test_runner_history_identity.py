"""Mock native descriptor APIs; never mount filesystems or launch a runner."""

from __future__ import annotations

import ctypes
import errno
import json
import stat
import sys
from types import SimpleNamespace

import pytest

from bluefire import runner_history_identity as identity

UUID = bytes.fromhex("0123456789abcdeffedcba9876543210")
GENERATION = 0xFEDCBA98
INODE = 0xFEDCBA9876543210


def _details(**updates):
    return SimpleNamespace(
        **{"st_mode": stat.S_IFREG, "st_nlink": 1, "st_dev": 7, "st_ino": INODE, **updates}
    )


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(identity, "sys", SimpleNamespace(platform="linux", byteorder="little"))
    monkeypatch.setattr(identity, "os", SimpleNamespace(fstat=lambda _fd: _details()))
    monkeypatch.setattr(identity, "_require_linux_abi", lambda: None)
    monkeypatch.setattr(identity, "_filesystem_type", lambda _fd: identity._EXT_MAGIC)
    calls = []

    def ioctl(descriptor, request, buffer, mutate):
        assert descriptor == 17 and mutate is True
        calls.append(request)
        if request == identity._GETFSUUID:
            assert len(buffer) == 24 and buffer[:8] == bytes.fromhex("1000000000000000")
            buffer[8:] = UUID
        else:
            assert request == identity._GETVERSION and len(buffer) == 8
            buffer[:4] = GENERATION.to_bytes(4, "little")
        return 0

    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(ioctl=ioctl))
    return calls


def test_ext4_identity_uses_full_uuid_inode_and_unsigned_generation_only(linux):
    result = identity.durable_descriptor_identity(17)
    assert result == {
        "format": "linux-ext4-inode-generation.v1",
        "filesystem_uuid": UUID.hex(),
        "inode": str(INODE),
        "generation": "fedcba98",
    }
    assert json.loads(json.dumps(result)) == result
    assert linux == [0x8008662C, 0x80086603] * 2
    assert "device" not in result and "mount" not in result and "f_fsid" not in result


def test_windows_identity_preserves_full_width_without_stat_fallback(monkeypatch):
    volume, file_id = 0xFEDCBA9876543210, 0xFEDCBA98765432100123456789ABCDEF
    monkeypatch.setattr(identity, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(identity, "os", SimpleNamespace(fstat=lambda _fd: _details(st_ino=9)))
    monkeypatch.setattr(identity, "descriptor_identity", lambda _fd, **_kw: (volume, file_id))
    assert identity.durable_descriptor_identity(17) == {
        "format": "windows-file-id-info.v1",
        "volume_serial_number": "fedcba9876543210",
        "file_id": "fedcba98765432100123456789abcdef",
    }


@pytest.mark.parametrize("filesystem", [0x794C7630, 0x01021994, 0x65735546, 0])
def test_unsupported_filesystem_never_attempts_ioctl(linux, monkeypatch, filesystem):
    monkeypatch.setattr(identity, "_filesystem_type", lambda _fd: filesystem)
    with pytest.raises(identity.DurableIdentityUnavailable):
        identity.durable_descriptor_identity(17)
    assert not linux


@pytest.mark.parametrize("error", [errno.ENOTTY, errno.EOPNOTSUPP, errno.ENOSYS])
@pytest.mark.parametrize("ioctl_code", [identity._GETFSUUID, identity._GETVERSION])
def test_unsupported_ioctl_is_explicitly_unavailable(linux, monkeypatch, error, ioctl_code):
    original = sys.modules["fcntl"].ioctl

    def unsupported(fd, code, buffer, mutate):
        if code == ioctl_code:
            raise OSError(error, "/private/native/details")
        return original(fd, code, buffer, mutate)

    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(ioctl=unsupported))
    with pytest.raises(identity.DurableIdentityUnavailable) as caught:
        identity.durable_descriptor_identity(17)
    assert "/private" not in str(caught.value) and caught.value.__suppress_context__


@pytest.mark.parametrize(
    "fault",
    ["short", "length", "flags", "zero", "generation_size", "generation_high", "return", "io"],
)
def test_malformed_or_failed_ioctl_never_becomes_unavailable(linux, monkeypatch, fault):
    original = sys.modules["fcntl"].ioctl

    def malformed(fd, request, buffer, mutate):
        result = original(fd, request, buffer, mutate)
        if request == identity._GETFSUUID:
            if fault == "short":
                del buffer[-1:]
            elif fault == "length":
                buffer[:4] = (15).to_bytes(4, "little")
            elif fault == "flags":
                buffer[4] = 1
            elif fault == "zero":
                buffer[8:] = bytes(16)
            elif fault == "return":
                return 1
            elif fault == "io":
                raise OSError(errno.EIO, "/private/native/details")
        elif fault == "generation_size":
            del buffer[-1:]
        elif fault == "generation_high":
            buffer[7] = 1
        return result

    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(ioctl=malformed))
    with pytest.raises(OSError) as caught:
        identity.durable_descriptor_identity(17)
    assert not isinstance(caught.value, identity.DurableIdentityUnavailable)
    assert "/private" not in str(caught.value)


@pytest.mark.parametrize("field", ["uuid", "generation"])
def test_changed_identity_during_capture_is_a_hard_refusal(linux, monkeypatch, field):
    original = identity._ext4_identifiers
    calls = []

    def changed(fd, sentinel):
        value = original(fd, sentinel)
        calls.append(True)
        if len(calls) == 2:
            return (
                (bytes(reversed(value[0])), value[1])
                if field == "uuid"
                else (value[0], value[1] ^ 1)
            )
        return value

    monkeypatch.setattr(identity, "_ext4_identifiers", changed)
    with pytest.raises(OSError) as caught:
        identity.durable_descriptor_identity(17)
    assert not isinstance(caught.value, identity.DurableIdentityUnavailable)


@pytest.mark.parametrize("platform", ["win32", "linux", "darwin"])
@pytest.mark.parametrize(
    "details,directory",
    [
        (_details(st_mode=stat.S_IFLNK), False),
        (_details(st_nlink=2), False),
        (_details(st_file_attributes=0x400), False),
        (_details(), True),
    ],
)
def test_nonordinary_descriptor_is_never_an_availability_downgrade(
    monkeypatch, platform, details, directory
):
    monkeypatch.setattr(identity, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(identity, "os", SimpleNamespace(fstat=lambda _fd: details))
    with pytest.raises(OSError) as caught:
        identity.durable_descriptor_identity(17, directory=directory)
    assert not isinstance(caught.value, identity.DurableIdentityUnavailable)


def test_full_windows_identity_query_failure_is_not_unavailable(monkeypatch):
    monkeypatch.setattr(identity, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(identity, "os", SimpleNamespace(fstat=lambda _fd: _details()))

    def failed(*_args, **_kwargs):
        raise OSError(errno.ENOSYS, "/private/native/details")

    monkeypatch.setattr(identity, "descriptor_identity", failed)
    with pytest.raises(OSError) as caught:
        identity.durable_descriptor_identity(17)
    assert not isinstance(caught.value, identity.DurableIdentityUnavailable)
    assert "/private" not in str(caught.value)


@pytest.mark.parametrize("platform", ["darwin", "freebsd13"])
def test_unknown_platform_explicitly_has_no_durable_identity(linux, monkeypatch, platform):
    monkeypatch.setattr(identity, "sys", SimpleNamespace(platform=platform))
    with pytest.raises(identity.DurableIdentityUnavailable):
        identity.durable_descriptor_identity(17)


def test_statfs_layout_uses_explicit_supported_abi_and_ignores_fsid(monkeypatch):
    assert ctypes.sizeof(identity._LinuxStatFS64) == 120
    assert identity._LinuxStatFS64.f_fsid.offset == 56
    assert identity._LinuxStatFS64.f_flags.offset == 80
    calls = []

    class Operation:
        def __call__(self, descriptor, pointer):
            assert descriptor == 17
            value = ctypes.cast(pointer, ctypes.POINTER(identity._LinuxStatFS64)).contents
            value.f_type = identity._EXT_MAGIC
            value.f_fsid[0] = 98765
            calls.append(True)
            return 0

    operation = Operation()
    monkeypatch.setattr(
        identity.ctypes, "CDLL", lambda *_a, **_kw: SimpleNamespace(fstatfs=operation)
    )
    assert identity._filesystem_type(17) == identity._EXT_MAGIC
    assert operation.argtypes == (ctypes.c_int, ctypes.POINTER(identity._LinuxStatFS64))
    assert operation.restype is ctypes.c_int and calls == [True]


@pytest.mark.parametrize("machine", ["i686", "armv7l", "ppc64le", "riscv64"])
def test_unknown_linux_abi_does_not_call_libc(monkeypatch, machine):
    monkeypatch.setattr(
        identity, "os", SimpleNamespace(uname=lambda: SimpleNamespace(machine=machine))
    )
    with pytest.raises(identity.DurableIdentityUnavailable):
        identity._require_linux_abi()


@pytest.mark.parametrize("ioctl_code", [identity._GETFSUUID, identity._GETVERSION])
@pytest.mark.parametrize("partial", [False, True])
def test_successful_partial_or_unwritten_getter_is_refused(linux, monkeypatch, ioctl_code, partial):
    original = sys.modules["fcntl"].ioctl

    def incomplete(fd, code, buffer, mutate):
        if code != ioctl_code:
            return original(fd, code, buffer, mutate)
        if partial:
            if code == identity._GETFSUUID:
                buffer[8:12] = UUID[:4]
            else:
                buffer[:2] = GENERATION.to_bytes(4, "little")[:2]
        return 0

    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(ioctl=incomplete))
    with pytest.raises(OSError) as caught:
        identity.durable_descriptor_identity(17)
    assert not isinstance(caught.value, identity.DurableIdentityUnavailable)


def test_complete_zero_generation_is_not_an_unwritten_getter(linux, monkeypatch):
    original = sys.modules["fcntl"].ioctl

    def zero(fd, request, buffer, mutate):
        result = original(fd, request, buffer, mutate)
        if request == identity._GETVERSION:
            buffer[:4] = bytes(4)
        return result

    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(ioctl=zero))
    assert identity.durable_descriptor_identity(17)["generation"] == "00000000"


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_supported_linux_abi_matches_the_reviewed_lp64_layout(monkeypatch, machine):
    real_sizeof = ctypes.sizeof
    pointer_type, long_type, int_type = object(), object(), object()
    widths = {pointer_type: 8, long_type: 8, int_type: 4}
    monkeypatch.setattr(
        identity, "os", SimpleNamespace(uname=lambda: SimpleNamespace(machine=machine))
    )
    monkeypatch.setattr(identity, "sys", SimpleNamespace(byteorder="little"))
    monkeypatch.setattr(
        identity,
        "ctypes",
        SimpleNamespace(
            c_void_p=pointer_type,
            c_long=long_type,
            c_int=int_type,
            sizeof=lambda kind: widths[kind] if kind in widths else real_sizeof(kind),
        ),
    )
    identity._require_linux_abi()


@pytest.mark.parametrize("error", [errno.ENOSYS, errno.EIO, errno.EACCES, errno.EINVAL])
def test_statfs_unavailability_is_separate_from_io_or_validation_failure(monkeypatch, error):
    class Operation:
        def __call__(self, _descriptor, _pointer):
            ctypes.set_errno(error)
            return -1

    monkeypatch.setattr(
        identity.ctypes, "CDLL", lambda *_a, **_kw: SimpleNamespace(fstatfs=Operation())
    )
    with pytest.raises(OSError) as caught:
        identity._filesystem_type(17)
    assert isinstance(caught.value, identity.DurableIdentityUnavailable) == (error == errno.ENOSYS)


def test_descriptor_reuse_during_capture_is_a_hard_refusal(linux, monkeypatch):
    calls = []

    def fstat(_descriptor):
        calls.append(True)
        return _details(st_ino=INODE if len(calls) == 1 else INODE + 1)

    monkeypatch.setattr(identity, "os", SimpleNamespace(fstat=fstat))
    with pytest.raises(OSError) as caught:
        identity.durable_descriptor_identity(17)
    assert not isinstance(caught.value, identity.DurableIdentityUnavailable)


@pytest.mark.parametrize("native", [(True, 1), (-1, 1), (2**64, 1), (1, 0), (1, 2**128)])
def test_malformed_windows_identity_cannot_downgrade_to_unavailable(monkeypatch, native):
    monkeypatch.setattr(identity, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(identity, "os", SimpleNamespace(fstat=lambda _fd: _details()))
    monkeypatch.setattr(identity, "descriptor_identity", lambda _fd, **_kw: native)
    with pytest.raises(OSError) as caught:
        identity.durable_descriptor_identity(17)
    assert not isinstance(caught.value, identity.DurableIdentityUnavailable)
