from __future__ import annotations

import ctypes
import os
import sys
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest

from bluefire import windows_session_facts as facts


@pytest.mark.parametrize(
    "field,value",
    [
        ("process_id", True),
        ("process_id", 0),
        ("process_id", 2**32),
        ("process_created_filetime", -1),
        ("token_id", True),
        ("token_id", 2**64),
        ("authentication_id", 0),
        ("modified_id", "30"),
        ("session_id", -1),
        ("session_id", True),
        ("elevated", 0),
        ("user_sid", "S-1-5-21-text"),
        ("user_sid", "S-1-281474976710656-1"),
        ("user_sid", "S-1-5-4294967296"),
    ],
)
def test_private_expected_principal_has_exact_native_types_and_bounds(field, value):
    principal = facts.WindowsPrincipalFacts(
        41, 123456, "S-1-5-21-101-202-303-1001", 10, 20, 30, 2, False
    )
    with pytest.raises(facts.WindowsSessionFactsError):
        replace(principal, **{field: value}).validate()


def test_supported_large_sid_authority_retains_native_string_form():
    facts.WindowsPrincipalFacts(
        41, 123456, "S-1-0xffffffffffff-4294967295", 10, 20, 30, 2, False
    ).validate()


class FakeApi:
    def __init__(self):
        self.generations = [(41, 123456), (41, 123456)]
        self.snapshots = [(10, 20, 30)] * 3
        self.thread_checks = 0
        self.thread_failure = None
        self.closed = []
        self.opened = []
        self.close_failure = None
        self.elevation = 0
        self.sid_failure = False

    def require_no_thread_token(self):
        self.thread_checks += 1
        if self.thread_checks == self.thread_failure:
            raise facts.WindowsSessionFactsError("Windows thread identity is not primary-only")

    def process_generation(self):
        return self.generations.pop(0)

    @contextmanager
    def process_token(self):
        token = len(self.opened) + 100
        self.opened.append(token)
        try:
            yield token
        finally:
            self.closed.append(token)
            if token == self.close_failure:
                raise facts.WindowsSessionFactsError("Windows identity handle cleanup failed")

    def statistics(self, token):
        return self.snapshots.pop(0)

    def user_sid(self, token):
        if self.sid_failure:
            raise facts.WindowsSessionFactsError("Windows token user response is invalid")
        return "S-1-5-21-101-202-303-1001"

    def dword(self, token, kind):
        return self.elevation if kind == facts._TOKEN_ELEVATION else 2


def test_stable_snapshot_closes_both_handles_and_hides_private_values():
    api = FakeApi()
    observed = facts._observe(api)
    assert observed == facts.WindowsPrincipalFacts(
        41, 123456, "S-1-5-21-101-202-303-1001", 10, 20, 30, 2, False
    )
    assert api.thread_checks == 2
    assert api.closed == [101, 100]
    assert "S-1-" not in repr(observed)
    assert "token_id" not in repr(observed)
    assert "authentication_id" not in repr(observed)
    assert "modified_id" not in repr(observed)


@pytest.mark.parametrize("position", [1, 2])
@pytest.mark.parametrize("component", [0, 1, 2])
def test_changed_held_or_reopened_token_refuses_and_closes(position, component):
    api = FakeApi()
    changed = list(api.snapshots[position])
    changed[component] += 1
    api.snapshots[position] = tuple(changed)
    with pytest.raises(facts.WindowsSessionFactsError, match="token changed"):
        facts._observe(api)
    assert sorted(api.closed) == api.opened


@pytest.mark.parametrize("generation", [(42, 123456), (41, 123457)])
def test_process_generation_change_refuses(generation):
    api = FakeApi()
    api.generations[-1] = generation
    with pytest.raises(facts.WindowsSessionFactsError, match="process changed"):
        facts._observe(api)
    assert api.closed == [101, 100]


@pytest.mark.parametrize("check", [1, 2])
def test_impersonation_at_either_end_refuses(check):
    api = FakeApi()
    api.thread_failure = check
    with pytest.raises(facts.WindowsSessionFactsError, match="not primary-only"):
        facts._observe(api)
    assert sorted(api.closed) == api.opened


@pytest.mark.parametrize("handle", [100, 101])
def test_cleanup_failure_cannot_return_success(handle):
    api = FakeApi()
    api.close_failure = handle
    with pytest.raises(facts.WindowsSessionFactsError, match="cleanup failed"):
        facts._observe(api)
    assert api.closed == [101, 100]


def test_invalid_elevation_and_mid_observation_failure_close_first_token():
    for kind in ("elevation", "sid_failure"):
        api = FakeApi()
        setattr(api, kind, 2 if kind == "elevation" else True)
        with pytest.raises(facts.WindowsSessionFactsError):
            facts._observe(api)
        assert api.closed == [100]


def _user_buffer(*, revision=1, count=2, authority=5):
    offset = ctypes.sizeof(facts._TokenUser)
    sid = bytes([revision, count]) + authority.to_bytes(6, "big")
    sid += (32).to_bytes(4, "little") + (545).to_bytes(4, "little")
    buffer = ctypes.create_string_buffer(offset + len(sid))
    user = facts._TokenUser.from_buffer(buffer)
    user.sid = ctypes.addressof(buffer) + offset
    ctypes.memmove(user.sid, sid, len(sid))
    return buffer, len(buffer)


def test_sid_decodes_only_bounded_bytes_with_documented_byte_orders():
    assert facts._decode_user_sid(*_user_buffer()) == "S-1-5-32-545"
    assert (
        facts._decode_user_sid(*_user_buffer(authority=0x010203040506))
        == "S-1-0x010203040506-32-545"
    )


@pytest.mark.parametrize("offset", [-8, 0, 1, 15, 100000])
def test_sid_pointer_outside_payload_refused_without_dereference(offset):
    buffer, length = _user_buffer()
    facts._TokenUser.from_buffer(buffer).sid = ctypes.addressof(buffer) + offset
    # Offset15 can be in the payload on32bit Python; force a invalid header too.
    if ctypes.sizeof(facts._TokenUser) <= offset < length:
        buffer[offset] = b"\x00"
    with pytest.raises(facts.WindowsSessionFactsError, match="user response is invalid"):
        facts._decode_user_sid(buffer, length)


@pytest.mark.parametrize("length_delta", [-1, 1, -100])
def test_sid_returned_length_not_allocation_capacity_is_authoritative(length_delta):
    buffer, length = _user_buffer()
    with pytest.raises(facts.WindowsSessionFactsError):
        facts._decode_user_sid(buffer, length + length_delta)


@pytest.mark.parametrize("revision,count", [(0, 2), (2, 2), (1, 0), (1, 16), (1, 3)])
def test_sid_invalid_header_or_truncated_tail_refused(revision, count):
    with pytest.raises(facts.WindowsSessionFactsError):
        facts._decode_user_sid(*_user_buffer(revision=revision, count=count))


def _native_shell(**security):
    api = object.__new__(facts._WindowsApi)
    closed = []
    api.kernel = SimpleNamespace(
        GetCurrentThread=lambda: -2,
        GetCurrentProcess=lambda: -1,
        CloseHandle=lambda handle: closed.append(handle.value) or True,
    )
    api.security = SimpleNamespace(**security)
    return api, closed


@pytest.mark.parametrize("error", [0, 5, 1309, 1347])
def test_thread_open_errors_are_not_mistaken_for_no_impersonation(monkeypatch, error):
    api, closed = _native_shell(OpenThreadToken=lambda *args: False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error, raising=False)
    with pytest.raises(facts.WindowsSessionFactsError, match="identity is unavailable"):
        api.require_no_thread_token()
    assert closed == []


def test_only_no_token_error_is_accepted(monkeypatch):
    api, closed = _native_shell(OpenThreadToken=lambda *args: False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 1008, raising=False)
    api.require_no_thread_token()
    assert closed == []


@pytest.mark.parametrize("opened", [False, True])
def test_unexpected_thread_handle_is_closed_and_refused(monkeypatch, opened):
    def open_thread(thread, access, as_self, pointer):
        assert access == 8 and as_self is True
        ctypes.cast(pointer, ctypes.POINTER(facts._HANDLE))[0] = 77
        return opened

    api, closed = _native_shell(OpenThreadToken=open_thread)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 1008, raising=False)
    with pytest.raises(facts.WindowsSessionFactsError, match="not primary-only"):
        api.require_no_thread_token()
    assert closed == [77]


@pytest.mark.parametrize("opened", [False, True])
def test_process_token_open_cleanup_even_for_malformed_failure(opened):
    def open_process(process, access, pointer):
        assert access == 8
        ctypes.cast(pointer, ctypes.POINTER(facts._HANDLE))[0] = 88
        return opened

    api, closed = _native_shell(OpenProcessToken=open_process)
    if opened:
        with api.process_token() as token:
            assert token == 88
    else:
        with pytest.raises(facts.WindowsSessionFactsError, match="token is unavailable"):
            with api.process_token():
                pytest.fail("failed open must not yield")
    assert closed == [88]


@pytest.mark.parametrize("first_size", [0, 4097, 0xFFFFFFFF])
def test_token_information_allocation_is_bounded(monkeypatch, first_size):
    calls = []

    def information(token, kind, buffer, capacity, length):
        calls.append(capacity)
        ctypes.cast(length, ctypes.POINTER(facts._DWORD))[0] = first_size
        return False

    api, _ = _native_shell(GetTokenInformation=information)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 122, raising=False)
    with pytest.raises(facts.WindowsSessionFactsError, match="information is unavailable"):
        api.information(88, facts._TOKEN_USER)
    assert calls == [0]


@pytest.mark.parametrize("second_size,success", [(0, True), (5, True), (4, False)])
def test_token_information_growth_or_failed_read_refuses(monkeypatch, second_size, success):
    def information(token, kind, buffer, capacity, length):
        ctypes.cast(length, ctypes.POINTER(facts._DWORD))[0] = second_size if capacity else 4
        return success if capacity else False

    api, _ = _native_shell(GetTokenInformation=information)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 122, raising=False)
    with pytest.raises(facts.WindowsSessionFactsError, match="changed or is invalid"):
        api.information(88, facts._TOKEN_USER)


def test_primary_statistics_use_native_fixed_width_layout(monkeypatch):
    assert ctypes.sizeof(facts._Luid) == 8
    assert ctypes.sizeof(facts._Statistics) == 56
    statistics = facts._Statistics()
    statistics.token_id.low = 1
    statistics.authentication_id.low = 2
    statistics.modified_id.low = 3
    statistics.token_type = 1
    buffer = ctypes.create_string_buffer(bytes(statistics), ctypes.sizeof(statistics))
    api, _ = _native_shell()
    monkeypatch.setattr(api, "information", lambda *args: (buffer, len(buffer)))
    assert api.statistics(88) == (1, 2, 3)
    facts._Statistics.from_buffer(buffer).token_type = 2
    with pytest.raises(facts.WindowsSessionFactsError, match="statistics are invalid"):
        api.statistics(88)


@pytest.mark.parametrize("kind,size", [(10, 56), (12, 4), (20, 4)])
def test_fixed_native_structures_do_not_use_zero_length_probe(kind, size):
    calls = []

    def information(token, observed_kind, buffer, capacity, length):
        calls.append((observed_kind, capacity))
        ctypes.cast(length, ctypes.POINTER(facts._DWORD))[0] = size
        return capacity == size

    api, _ = _native_shell(GetTokenInformation=information)
    buffer, length = api.information(88, kind)
    assert length == len(buffer) == size
    assert calls == [(kind, size)]


def test_unknown_native_information_class_is_not_queried():
    api, _ = _native_shell()
    with pytest.raises(facts.WindowsSessionFactsError, match="class is unsupported"):
        api.information(88, 999)


def test_public_failure_does_not_disclose_native_exception(monkeypatch):
    def broken():
        raise OSError("private-host-path-or-identity")

    monkeypatch.setattr(facts, "_WindowsApi", broken)
    with pytest.raises(facts.WindowsSessionFactsError) as error:
        facts.current_process_principal()
    assert str(error.value) == "Windows process identity observation failed"
    assert error.value.__suppress_context__ is True


def test_non_windows_refuses_before_loading_native_apis(monkeypatch):
    monkeypatch.setattr(facts.sys, "platform", "linux")
    with pytest.raises(facts.WindowsSessionFactsError, match="identity is unavailable"):
        facts.current_process_principal()


@pytest.mark.skipif(sys.platform != "win32", reason="read-only native Windows identity")
def test_native_current_process_snapshot_without_publishing_local_identity():
    from bluefire.windows_owner_acl import current_user_sid

    first = facts.current_process_principal()
    second = facts.current_process_principal()
    # Compare booleans so pytest cannot print real local SIDs/token identifiers.
    assert bool(first.user_sid == current_user_sid())
    assert bool(first == second)
    assert first.process_id == os.getpid()
    assert first.process_created_filetime > 0
    assert isinstance(first.elevated, bool)
