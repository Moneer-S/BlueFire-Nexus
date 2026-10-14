from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_handles as handles


@pytest.mark.parametrize("directory,data", [(True, True), (1, False), (False, 1)])
def test_invalid_open_mode_is_refused_before_platform_access(directory, data):
    with pytest.raises(handles.WindowsFileHandleError, match="request is invalid"):
        handles.open_observation(Path("unused"), directory=directory, data=data)


def test_native_structure_layouts_have_fixed_windows_widths():
    assert ctypes.sizeof(handles._Basic) == 40
    assert ctypes.sizeof(handles._Standard) == 24
    assert ctypes.sizeof(handles._Tag) == 8


def test_non_windows_refuses_without_attempting_a_path(monkeypatch):
    monkeypatch.setattr(handles.sys, "platform", "linux")
    with pytest.raises(handles.WindowsFileHandleError, match="unavailable"):
        handles.open_observation(Path("unused"), directory=False)


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows handle reads")
def test_native_generated_file_identity_and_data_read_are_separate(tmp_path):
    path = tmp_path / "generated.jsonl"
    payload = b'{"record":1}\n'
    path.write_bytes(payload)
    metadata = handles.open_observation(path, directory=False)
    data = None
    try:
        before = handles.inspect_observation(metadata, directory=False)
        assert before.size == len(payload) and before.links == 1
        assert not before.directory and before.identity[1] > 0
        assert not os.get_inheritable(metadata)
        with pytest.raises(OSError):
            os.read(metadata, 1)
        data = handles.open_observation(path, directory=False, data=True)
        assert not os.get_inheritable(data)
        assert handles.inspect_observation(data, directory=False) == before
        assert os.read(data, len(payload) + 1) == payload
        assert os.read(data, 1) == b""
        assert handles.inspect_observation(metadata, directory=False) == before
        with pytest.raises(OSError):
            path.write_bytes(b"changed")
        assert "final_path" not in repr(before)
    finally:
        if data is not None:
            os.close(data)
        os.close(metadata)
    assert path.read_bytes() == payload


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows handle reads")
def test_native_directory_and_file_kind_cannot_be_substituted(tmp_path):
    descriptor = handles.open_observation(tmp_path, directory=True)
    try:
        assert handles.inspect_observation(descriptor, directory=True).directory
        with pytest.raises(handles.WindowsFileHandleError, match="not an ordinary"):
            handles.inspect_observation(descriptor, directory=False)
    finally:
        os.close(descriptor)


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows open refusal")
def test_missing_file_is_not_reported_as_permission_denial(tmp_path):
    with pytest.raises(handles.WindowsFileHandleError) as error:
        handles.open_observation(tmp_path / "absent.jsonl", directory=False, data=True)
    assert not isinstance(error.value, handles.WindowsDataOpenDenied)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows error classification")
@pytest.mark.parametrize(
    "data,error,denied", [(True, 5, True), (False, 5, False), (True, 2, False), (True, 32, False)]
)
def test_only_final_data_access_denied_is_distinguished(monkeypatch, data, error, denied):
    kernel = SimpleNamespace(
        GetDriveTypeW=lambda path: 3, CreateFileW=lambda *args: ctypes.c_void_p(-1).value
    )
    monkeypatch.setattr(handles, "_kernel", lambda: kernel)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error)
    with pytest.raises(handles.WindowsFileHandleError) as failure:
        handles.open_observation(Path("C:/BlueFire/unused.jsonl"), directory=False, data=data)
    assert isinstance(failure.value, handles.WindowsDataOpenDenied) is denied


@pytest.mark.skipif(sys.platform != "win32", reason="Windows local-path constraints")
@pytest.mark.parametrize("path", [r"\\server\share\file", r"\\?\C:\file", "relative.jsonl"])
def test_network_device_and_relative_paths_never_reach_createfile(monkeypatch, path):
    kernel = SimpleNamespace(
        GetDriveTypeW=lambda path: 3,
        CreateFileW=lambda *args: pytest.fail("must refuse before open"),
    )
    monkeypatch.setattr(handles, "_kernel", lambda: kernel)
    with pytest.raises(handles.WindowsFileHandleError, match="fixed local drive"):
        handles.open_observation(Path(path), directory=False)
