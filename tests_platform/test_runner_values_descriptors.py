"""In-memory and file-only regressions for reviewed values and descriptor reads."""

from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import runner_adapter as adapter
from bluefire import runner_descriptor_io as descriptor_io
from bluefire import runner_private_files as private
from bluefire import runner_provider_values as values


def test_provider_value_hooks_and_error_identity_remain_at_adapter_boundary(monkeypatch) -> None:
    calls = []
    assert adapter.RunnerAdapterError is values.RunnerAdapterError

    def validate(spec, value, context):
        calls.append((spec, value, context))
        raise adapter.RunnerAdapterError("injected parameter refusal")

    monkeypatch.setattr(adapter, "_validate_provider_parameter", validate)
    spec = {"name": "count", "type": "integer", "required": True}
    with pytest.raises(adapter.RunnerAdapterError, match="injected parameter refusal"):
        adapter._provider_parameters({"parameters": [spec]}, {"count": 2})
    assert calls == [(spec, 2, "provider parameter count")]
    output = {"name": "result", "type": "fixture", "required": True}
    monkeypatch.setattr(
        adapter, "_provider_output_value", lambda spec, item, context: (spec, item, context)
    )
    assert adapter._provider_outputs(
        {"outputs": [output]},
        {
            "schema_version": "bluefire.provider-action-output.v1",
            "outputs": {"result": {"type": "fixture"}},
        },
    ) == {"result": (output, {"type": "fixture"}, "provider output result")}


def test_descriptor_read_preserves_caller_ownership_and_limit_plus_one(tmp_path: Path) -> None:
    path = tmp_path / "owned.bin"
    path.write_bytes(b"abcde")
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.lseek(descriptor, 4, os.SEEK_SET)
        assert private._read_descriptor_bounded(descriptor, 5) == b"abcde"
        with pytest.raises(OSError, match="size limit"):
            private._read_descriptor_bounded(descriptor, 2)
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == 3
        with pytest.raises(OSError, match="invalid bounded read"):
            private._read_descriptor_bounded(descriptor, True)
        assert os.read(descriptor, 2) == b"de"
    finally:
        os.close(descriptor)


def test_descriptor_compatibility_exports_keep_the_same_functions_and_flags() -> None:
    assert private._read_descriptor_bounded is descriptor_io._read_descriptor_bounded
    assert private._descriptor_mount_identity is descriptor_io._descriptor_mount_identity
    assert private._LINUX_AT_EMPTY_PATH == descriptor_io._LINUX_AT_EMPTY_PATH == 0x1000
    assert private._LINUX_STATX_MNT_ID == descriptor_io._LINUX_STATX_MNT_ID == 0x1000
    assert adapter._PROVIDER_ACTION_OUTPUT_SCHEMA == values._PROVIDER_ACTION_OUTPUT_SCHEMA


@pytest.mark.parametrize("result", ["valid", "unavailable", "missing_mask", "zero_id", "error"])
def test_linux_mount_identity_requires_successful_descriptor_bound_statx(monkeypatch, result):
    """Exercise the Linux syscall contract with a stub; no native Linux call occurs."""

    calls = []

    class Statx:
        def __call__(self, descriptor, path, flags, mask, buffer):
            calls.append((descriptor, path, flags, mask))
            raw = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte * 256)).contents
            raw[0:4] = (0 if result == "missing_mask" else mask).to_bytes(4, "little")
            raw[144:152] = (0 if result == "zero_id" else 23).to_bytes(8, "little")
            if result == "error":
                ctypes.set_errno(errno.EIO)
                return -1
            return 0

    def library(name, *, use_errno):
        assert name is None and use_errno is True
        return SimpleNamespace() if result == "unavailable" else SimpleNamespace(statx=Statx())

    monkeypatch.setattr(descriptor_io, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(ctypes, "CDLL", library)
    if result == "valid":
        assert private._descriptor_mount_identity(91) == 23
    else:
        with pytest.raises(OSError, match="mount identity is unavailable") as failure:
            private._descriptor_mount_identity(91)
        assert failure.value.errno == (errno.EIO if result == "error" else errno.ENOSYS)
    assert calls == ([] if result == "unavailable" else [(91, b"", 0x1000, 0x1000)])


def test_non_linux_mount_query_does_not_load_libc(monkeypatch):
    monkeypatch.setattr(descriptor_io, "sys", SimpleNamespace(platform="win32"))

    def library(*_args, **_kwargs):
        pytest.fail("Non-Linux descriptor inspection must not load libc.")

    monkeypatch.setattr(ctypes, "CDLL", library)
    assert private._descriptor_mount_identity(91) is None


def test_closed_descriptor_is_not_reopened_through_a_path(tmp_path: Path) -> None:
    path = tmp_path / "owned.bin"
    path.write_bytes(b"unchanged owned bytes")
    descriptor = os.open(path, os.O_RDONLY)
    os.close(descriptor)
    with pytest.raises(OSError):
        private._read_descriptor_bounded(descriptor, 64)
    assert path.read_bytes() == b"unchanged owned bytes"
