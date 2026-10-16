from __future__ import annotations

import ctypes
import sys
import uuid
from ctypes import wintypes
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_peer as peer

GENERATION = peer.WindowsPeerGeneration(41, 123456)


class FakeApi:
    def __init__(self):
        self.generations = [GENERATION, GENERATION]
        self.running = [True, True]
        self.inheritable = False
        self.calls = []
        self.pipe_pids = [41, 41]

    def pipe_peer(self, handle, *, server_end):
        self.calls.append(("pipe", handle))
        return self.pipe_pids.pop(0)

    def require_noninherited(self, handle):
        self.calls.append(("inheritance", handle))
        if self.inheritable:
            raise peer.WindowsPeerBindingError("inheritable")

    def require_running(self, handle):
        self.calls.append(("running", handle))
        if not self.running.pop(0):
            raise peer.WindowsPeerBindingError("exited")

    def generation(self, handle):
        self.calls.append(("generation", handle))
        return self.generations.pop(0)


def test_reported_pid_and_both_live_generation_observations_must_match(monkeypatch):
    api = FakeApi()
    monkeypatch.setattr(peer, "_Api", lambda: api)
    assert peer.require_live_pipe_peer(100, 200, expected=GENERATION, server_end=False) is None
    assert api.calls == [
        ("pipe", 200),
        ("inheritance", 100),
        ("running", 100),
        ("generation", 100),
        ("running", 100),
        ("generation", 100),
        ("pipe", 200),
    ]


@pytest.mark.parametrize("position", [0, 1])
@pytest.mark.parametrize(
    "changed", [peer.WindowsPeerGeneration(42, 123456), peer.WindowsPeerGeneration(41, 123457)]
)
def test_pid_reuse_or_process_substitution_refuses(position, changed):
    api = FakeApi()
    api.generations[position] = changed
    with pytest.raises(peer.WindowsPeerBindingError):
        peer._validate(api, 100, GENERATION, 41)


@pytest.mark.parametrize("position", [0, 1])
def test_process_exit_at_either_end_refuses(position):
    api = FakeApi()
    api.running[position] = False
    with pytest.raises(peer.WindowsPeerBindingError):
        peer._validate(api, 100, GENERATION, 41)


def test_different_os_reported_pid_refuses():
    with pytest.raises(peer.WindowsPeerBindingError, match="differs"):
        peer._validate(FakeApi(), 100, GENERATION, 42)


def test_inheritable_handle_refuses():
    api = FakeApi()
    api.inheritable = True
    with pytest.raises(peer.WindowsPeerBindingError):
        peer._validate(api, 100, GENERATION, 41)


@pytest.mark.parametrize("handle", [None, True, -1, 0, ctypes.c_void_p(-1).value, 1 << 128])
def test_invalid_or_pseudo_handle_is_not_queried(monkeypatch, handle):
    monkeypatch.setattr(peer, "_Api", lambda: pytest.fail("no native query"))
    with pytest.raises(peer.WindowsPeerBindingError):
        peer.require_live_pipe_peer(handle, 200, expected=GENERATION, server_end=False)


def test_non_windows_refuses(monkeypatch):
    monkeypatch.setattr(peer.sys, "platform", "linux")
    with pytest.raises(peer.WindowsPeerBindingError, match="unavailable"):
        peer.require_live_pipe_peer(100, 200, expected=GENERATION, server_end=False)


@pytest.mark.skipif(sys.platform != "win32", reason="read-only current-process handle binding")
def test_native_borrowed_query_handle_is_verified_without_closing_or_opening_a_peer():
    from bluefire.windows_session_facts import current_process_principal

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes = ()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.DuplicateHandle.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    kernel.DuplicateHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    pseudo = kernel.GetCurrentProcess()
    owned = wintypes.HANDLE()
    assert kernel.DuplicateHandle(pseudo, pseudo, pseudo, ctypes.byref(owned), 0x00101000, False, 0)
    try:
        facts = current_process_principal()
        expected = peer.WindowsPeerGeneration(facts.process_id, facts.process_created_filetime)
        peer._validate(peer._Api(), owned.value, expected, facts.process_id)
        peer._validate(peer._Api(), owned.value, expected, facts.process_id)
    finally:
        assert kernel.CloseHandle(owned)


def test_reconnected_pipe_peer_refuses(monkeypatch):
    api = FakeApi()
    api.pipe_pids = [41, 42]
    monkeypatch.setattr(peer, "_Api", lambda: api)
    with pytest.raises(peer.WindowsPeerBindingError, match="connection peer changed"):
        peer.require_live_pipe_peer(100, 200, expected=GENERATION, server_end=False)


@pytest.mark.skipif(
    sys.platform != "win32", reason="disposable owner-private local pipe, no data exchange"
)
def test_native_pipe_peer_query_on_both_ends_matches_retained_process():
    from bluefire import windows_owner_acl as acl
    from bluefire.windows_session_facts import current_process_principal

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("descriptor", ctypes.c_void_p),
            ("inherit", wintypes.BOOL),
        ]

    security, kernel = acl._configure_apis()
    facts = current_process_principal()
    descriptor = acl._converted_descriptor(security, f"D:P(A;;GA;;;{facts.user_sid})")
    attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
    kernel.CreateNamedPipeW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(SecurityAttributes),
    )
    kernel.CreateNamedPipeW.restype = wintypes.HANDLE
    kernel.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.argtypes = ()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.DuplicateHandle.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    kernel.DuplicateHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    owned = []
    try:
        name = r"\\.\pipe\bluefire-peer-test-" + uuid.uuid4().hex
        server = kernel.CreateNamedPipeW(
            name, 0x00080003, 0xE, 1, 512, 512, 1000, ctypes.byref(attributes)
        )
        assert server not in (None, 0, wintypes.HANDLE(-1).value)
        owned.append(server)
        client = kernel.CreateFileW(name, 0xC0000000, 0, None, 3, 0x00110000, None)
        assert client not in (None, 0, wintypes.HANDLE(-1).value)
        owned.append(client)
        pseudo = kernel.GetCurrentProcess()
        process = wintypes.HANDLE()
        assert kernel.DuplicateHandle(
            pseudo, pseudo, pseudo, ctypes.byref(process), 0x00101000, False, 0
        )
        owned.append(process.value)
        expected = peer.WindowsPeerGeneration(facts.process_id, facts.process_created_filetime)
        api = peer._Api()
        flags, instances = wintypes.DWORD(), wintypes.DWORD()
        available = bool(
            api.kernel.GetNamedPipeInfo(
                server, ctypes.byref(flags), None, None, ctypes.byref(instances)
            )
        )
        assert (api.kernel.GetFileType(server), available, instances.value) == (3, True, 1)
        assert flags.value in (5, 13)
        peer.require_live_pipe_peer(process.value, server, expected=expected, server_end=True)
        peer.require_live_pipe_peer(process.value, client, expected=expected, server_end=False)
    finally:
        closed = [bool(kernel.CloseHandle(handle)) for handle in reversed(owned)]
        freed = not kernel.LocalFree(descriptor)
        assert all(closed) and freed


@pytest.mark.parametrize("server,flags", [(True, 5), (True, 13), (False, 4), (False, 12)])
def test_pipe_query_accepts_only_expected_role_and_documented_or_observed_flags(server, flags):
    api = _pipe_api(flags=flags)
    assert api.pipe_peer(200, server_end=server) == 41


def _pipe_api(*, flags=13, instances=1, file_type=3, pid=41):
    def information(handle, output, outgoing, incoming, count):
        ctypes.cast(output, ctypes.POINTER(wintypes.DWORD))[0] = flags
        ctypes.cast(count, ctypes.POINTER(wintypes.DWORD))[0] = instances
        return True

    def process(handle, output):
        ctypes.cast(output, ctypes.POINTER(wintypes.DWORD))[0] = pid
        return True

    api = object.__new__(peer._Api)
    api.kernel = SimpleNamespace(
        GetFileType=lambda _: file_type,
        GetNamedPipeInfo=information,
        GetNamedPipeClientProcessId=process,
        GetNamedPipeServerProcessId=process,
    )
    return api


@pytest.mark.parametrize(
    "changes",
    [
        {"flags": 1},
        {"flags": 12},
        {"flags": 15},
        {"flags": 0x10005},
        {"instances": 2},
        {"instances": 255},
        {"file_type": 1},
        {"pid": 0},
    ],
)
def test_wrong_pipe_type_end_instance_bound_or_missing_pid_refuses(changes):
    with pytest.raises(peer.WindowsPeerBindingError):
        _pipe_api(**changes).pipe_peer(200, server_end=True)
