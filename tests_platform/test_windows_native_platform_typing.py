"""Fixed Win32 symbols over fakes only; no DLL, handle, account or ACL effects."""

from __future__ import annotations

import os
import sys
from pathlib import PureWindowsPath
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_handles as handles
from bluefire import windows_file_access_peer as peer
from bluefire import windows_session_facts as session


@pytest.mark.parametrize(
    "module,constructor,error",
    [
        (session, session._WindowsApi, session.WindowsSessionFactsError),
        (peer, peer._Api, peer.WindowsPeerBindingError),
    ],
)
def test_platform_refusal_precedes_fixed_dll_resolution(monkeypatch, module, constructor, error):
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        module.ctypes,
        "WinDLL",
        lambda *args, **kwargs: pytest.fail("No DLL may be loaded after platform refusal"),
        raising=False,
    )
    with pytest.raises(error, match="unavailable"):
        constructor()


@pytest.mark.parametrize("inheritable", [False, True])
def test_fixed_descriptor_export_preserves_flags_and_cleanup(monkeypatch, inheritable):
    calls = []
    closed = []
    kernel = SimpleNamespace(
        GetDriveTypeW=lambda drive: 3,
        CreateFileW=lambda *args: 128,
        CloseHandle=lambda handle: pytest.fail("Descriptor conversion already owns the handle"),
    )
    crt = SimpleNamespace(open_osfhandle=lambda handle, flags: calls.append((handle, flags)) or 41)
    fake_os = SimpleNamespace(
        fspath=os.fspath,
        O_RDONLY=0,
        O_BINARY=0x8000,
        O_NOINHERIT=0x80,
        set_inheritable=lambda descriptor, value: calls.append((descriptor, value)),
        get_inheritable=lambda descriptor: inheritable,
        close=closed.append,
    )
    monkeypatch.setattr(handles, "_kernel", lambda: kernel)
    monkeypatch.setattr(handles, "Path", PureWindowsPath)
    monkeypatch.setattr(handles, "_windows_extended_path", lambda path: path)
    monkeypatch.setattr(handles, "os", fake_os)
    monkeypatch.setitem(sys.modules, "msvcrt", crt)
    if inheritable:
        with pytest.raises(handles.WindowsFileHandleError, match="inheritable"):
            handles.open_observation(PureWindowsPath("C:/synthetic/fixed.jsonl"), directory=False)
        assert closed == [41]
    else:
        assert (
            handles.open_observation(PureWindowsPath("C:/synthetic/fixed.jsonl"), directory=False)
            == 41
        )
        assert closed == []
    assert calls == [(128, 0x8080), (41, False)]
