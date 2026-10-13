"""Synthetic buffers/fake APIs only; no native enrollment or account effects."""

from __future__ import annotations

import ctypes
import hashlib
import struct
from typing import Any

import pytest

from bluefire import windows_file_access_enrollment_native as native

OWNER = "S-1-5-21-101-202-303-1001"
READER = "S-1-5-21-101-202-303-1002"
GENERATION = "0123456789abcdef0123456789abcdef"
NAME = "bf_0123456789abcdef"


def sid(value: str) -> bytes:
    parts = [int(part) for part in value.split("-")[1:]]
    return (
        bytes([parts[0], len(parts) - 2])
        + parts[1].to_bytes(6, "big")
        + b"".join(number.to_bytes(4, "little") for number in parts[2:])
    )


def descriptor(*, owner: str = "S-1-5-18", directory: bool = False, reverse: bool = False) -> bytes:
    owner_bytes = sid(owner)
    entries = b""
    for identity, mask in (
        ("S-1-5-18", 0x1F01FF),
        ("S-1-5-32-544", 0x1F01FF),
        (OWNER, 0x1200A0 if directory else 0x120089),
    ):
        entry_sid = sid(identity)
        entries += struct.pack("<BBHI", 0, 0, 8 + len(entry_sid), mask) + entry_sid
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(entries), 3, 0) + entries
    if reverse:
        return struct.pack("<BBHIIII", 1, 0, 0x9004, 20 + len(acl), 0, 0, 20) + acl + owner_bytes
    return (
        struct.pack("<BBHIIII", 1, 0, 0x9004, 20, 0, 0, 20 + len(owner_bytes)) + owner_bytes + acl
    )


@pytest.mark.parametrize("owner", ["S-1-5-18", "S-1-5-32-544"])
@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_exact_protected_metadata_recipe(owner: str, directory: bool, reverse: bool) -> None:
    raw = descriptor(owner=owner, directory=directory, reverse=reverse)
    assert native.verify_protected_metadata_descriptor(raw, OWNER, directory=directory) == (
        "sha256:" + hashlib.sha256(raw).hexdigest()
    )


@pytest.mark.parametrize(
    "offset,value",
    [
        (0, b"\x02"),
        (1, b"\x01"),
        (2, b"\x04\x80"),
        (4, b"\x15\0\0\0"),
        (8, b"\xff\xff\xff\xff"),
        (12, b"\x14\0\0\0"),
        (16, b"\x14\0\0\0"),
        (32, b"\x04"),
        (33, b"\x01"),
        (36, b"\x04\0"),
        (38, b"\x01\0"),
        (40, b"\x01"),
        (41, b"\x10"),
        (42, b"\xff\xff"),
        (44, b"\xff\x01\x1f\x80"),
        (48, b"\x02"),
        (49, b"\x10"),
    ],
)
def test_descriptor_refuses_geometry_flags_masks_and_broader_fields(
    offset: int, value: bytes
) -> None:
    raw = bytearray(descriptor())
    raw[offset : offset + len(value)] = value
    with pytest.raises(native.WindowsEnrollmentNativeError):
        native.verify_protected_metadata_descriptor(bytes(raw), OWNER, directory=False)


@pytest.mark.parametrize(
    "change",
    ["user_owner", "truncated", "trailing", "spare_acl", "directory_mask", "alias_sid", "oversize"],
)
def test_descriptor_refuses_nonfinite_recipe(change: str) -> None:
    raw = descriptor()
    owner = OWNER
    if change == "user_owner":
        raw = descriptor(owner=OWNER)
    elif change == "truncated":
        raw = raw[:-1]
    elif change == "trailing":
        raw += b"\0\0\0\0"
    elif change == "spare_acl":
        altered = bytearray(raw + b"\0\0\0\0")
        struct.pack_into("<H", altered, 34, len(raw) - 32 + 4)
        raw = bytes(altered)
    elif change == "directory_mask":
        raw = descriptor(directory=True)
    elif change == "alias_sid":
        owner = "S-1-5-21-0101-202-303-1001"
    elif change == "oversize":
        raw = b"\0" * 65537
    with pytest.raises(native.WindowsEnrollmentNativeError):
        native.verify_protected_metadata_descriptor(raw, owner, directory=False)


def test_full_width_identity_preserves_native_little_endian_bytes_and_high_bits() -> None:
    opaque = bytes.fromhex("0123456789abcdeffedcba9876543210")
    assert native.file_identity_wire(0xFEDCBA9876543210, int.from_bytes(opaque, "little")) == (
        "fedcba9876543210",
        "0123456789abcdeffedcba9876543210",
    )
    assert native.file_identity_wire(1 << 63, 1 << 127) == (
        "8000000000000000",
        "00000000000000000000000000000080",
    )
    assert native.file_identity_wire(7, 1) != native.file_identity_wire(7 | 1 << 63, 1)
    assert native.file_identity_wire(7, 1) != native.file_identity_wire(7, 1 | 1 << 127)


@pytest.mark.parametrize(
    "volume,file_id", [(True, 1), (-1, 1), (1 << 64, 1), (1, True), (1, 0), (1, -1), (1, 1 << 128)]
)
def test_identity_refuses_lossy_or_invalid_values(volume: Any, file_id: Any) -> None:
    with pytest.raises(native.WindowsEnrollmentNativeError):
        native.file_identity_wire(volume, file_id)


class SamFake:
    def __init__(self, *, name: str = NAME, reader: str = READER, flags: int = 0x201) -> None:
        minimum = ctypes.sizeof(native._UserInfo23)
        name_bytes = (name + "\0").encode("utf-16-le")
        padding = b"\0" * (-(minimum + len(name_bytes)) % 4)
        self.buffer = ctypes.create_string_buffer(
            minimum + len(name_bytes) + len(padding) + len(sid(reader))
        )
        self.start = ctypes.addressof(self.buffer)
        self.length = ctypes.sizeof(self.buffer)
        self.info = native._UserInfo23.from_buffer(self.buffer)
        self.info.name = self.start + minimum
        self.info.flags = flags
        self.info.sid = self.start + minimum + len(name_bytes) + len(padding)
        ctypes.memmove(self.info.name, name_bytes, len(name_bytes))
        ctypes.memmove(self.info.sid, sid(reader), len(sid(reader)))
        self.get_status = self.size_status = self.free_status = 0
        self.after_get = lambda: None
        self.freed = 0
        self.calls: list[str] = []

    def NetUserGetInfo(self, server: Any, name: str, level: int, output: Any) -> int:
        assert server is None and name == NAME and level == 23
        self.calls.append("get")
        output._obj.value = self.start
        self.after_get()
        return self.get_status

    def NetApiBufferSize(self, pointer: Any, output: Any) -> int:
        assert pointer.value == self.start
        self.calls.append("size")
        output._obj.value = self.length
        return self.size_status

    def NetApiBufferFree(self, pointer: Any) -> int:
        assert pointer.value == self.start
        self.calls.append("free")
        self.freed += 1
        return self.free_status


def fake_sam(monkeypatch: pytest.MonkeyPatch, api: SamFake) -> list[float]:
    clock = [100.0]
    monkeypatch.setattr(native.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(native, "_sam_api", lambda: api)
    return clock


def lookup() -> native.LocalReaderAccount:
    return native.resolve_local_reader_account(
        GENERATION, READER, deadline=104.0, cancelled=lambda: False
    )


def test_fake_local_sam_mapping_is_fixed_and_buffer_freed(monkeypatch: pytest.MonkeyPatch) -> None:
    api = SamFake()
    fake_sam(monkeypatch, api)
    result = lookup()
    assert (result.account_name, result.reader_sid, result.flags) == (NAME, READER, 0x201)
    assert api.calls == ["get", "size", "free"]
    assert NAME not in repr(result) and READER not in repr(result)
    assert not hasattr(result, "verified")


@pytest.mark.parametrize(
    "change",
    [
        "get",
        "size",
        "small",
        "large",
        "name_pointer",
        "sid_pointer",
        "name",
        "sid",
        "disabled",
        "trust",
        "normal_missing",
        "optional_pointer",
        "sid_geometry",
    ],
)
def test_fake_sam_failures_refuse_and_free(monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    api = SamFake(
        name="bf_ffffffffffffffff" if change == "name" else NAME,
        reader=OWNER if change == "sid" else READER,
    )
    fake_sam(monkeypatch, api)
    if change == "get":
        api.get_status = 5
    elif change == "size":
        api.size_status = 5
    elif change == "small":
        api.length = ctypes.sizeof(native._UserInfo23) - 1
    elif change == "large":
        api.length = 65537
    elif change == "name_pointer":
        api.info.name = api.start - 2
    elif change == "sid_pointer":
        api.info.sid = api.start + api.length - 4
    elif change == "disabled":
        api.info.flags |= 2
    elif change == "trust":
        api.info.flags |= 0x1000
    elif change == "normal_missing":
        api.info.flags = 1
    elif change == "optional_pointer":
        api.info.comment = api.start + api.length
    elif change == "sid_geometry":
        assert api.info.sid is not None
        ctypes.memmove(api.info.sid + 1, b"\xff", 1)
    with pytest.raises(native.WindowsEnrollmentNativeError):
        lookup()
    assert api.freed == 1


@pytest.mark.parametrize("cleanup", [False, True])
def test_fake_sam_cleanup_failure_overrides_success_or_lookup_failure(
    monkeypatch: pytest.MonkeyPatch, cleanup: bool
) -> None:
    api = SamFake()
    fake_sam(monkeypatch, api)
    api.free_status = 5
    api.get_status = 5 if cleanup else 0
    with pytest.raises(native.WindowsEnrollmentNativeError, match="cleanup failed"):
        lookup()
    assert api.freed == 1


@pytest.mark.parametrize("stop", ["deadline", "cancelled"])
def test_fake_sam_stop_after_api_frees_without_following_buffer(
    monkeypatch: pytest.MonkeyPatch, stop: str
) -> None:
    api = SamFake()
    clock = fake_sam(monkeypatch, api)
    stopped = [False]
    api.after_get = lambda: (
        clock.__setitem__(0, 104.0) if stop == "deadline" else stopped.__setitem__(0, True)
    )
    with pytest.raises(native.WindowsEnrollmentNativeError, match="stopped"):
        native.resolve_local_reader_account(
            GENERATION, READER, deadline=104.0, cancelled=lambda: stopped[0]
        )
    assert api.calls == ["get", "free"]


@pytest.mark.parametrize(
    "generation,reader,deadline,cancelled",
    [
        (GENERATION.upper(), READER, 104.0, False),
        ("0" * 31, READER, 104.0, False),
        (GENERATION, "S-1-5-21-0101-202-303-1002", 104.0, False),
        (GENERATION, READER, float("nan"), False),
        (GENERATION, READER, 106.0, False),
        (GENERATION, READER, 100.0, False),
        (GENERATION, READER, True, False),
        (GENERATION, READER, 104.0, True),
    ],
)
def test_invalid_mapping_inputs_do_not_call_api(
    monkeypatch: pytest.MonkeyPatch, generation: str, reader: str, deadline: float, cancelled: bool
) -> None:
    api = SamFake()
    fake_sam(monkeypatch, api)
    with pytest.raises(native.WindowsEnrollmentNativeError):
        native.resolve_local_reader_account(
            generation, reader, deadline=deadline, cancelled=lambda: cancelled
        )
    assert api.calls == []


class SecurityFake:
    def __init__(self) -> None:
        self.raw = descriptor()
        self.buffer = ctypes.create_string_buffer(self.raw)
        self.status = self.free_status = 0
        self.length = len(self.raw)
        self.freed = 0
        self.after_get = lambda: None

    def GetSecurityInfo(
        self,
        handle: int,
        kind: int,
        selected: int,
        owner: Any,
        group: Any,
        dacl: Any,
        sacl: Any,
        output: Any,
    ) -> int:
        assert (handle, kind, selected, owner, group, dacl, sacl) == (
            123,
            1,
            5,
            None,
            None,
            None,
            None,
        )
        output._obj.value = ctypes.addressof(self.buffer)
        self.after_get()
        return self.status

    def GetSecurityDescriptorLength(self, pointer: Any) -> int:
        return self.length

    def LocalFree(self, pointer: Any) -> int:
        self.freed += 1
        return self.free_status


@pytest.mark.parametrize("change", ["none", "api", "size", "recipe", "cleanup", "deadline"])
def test_fake_held_metadata_observation_and_cleanup(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    api = SecurityFake()
    clock = [100.0]
    monkeypatch.setattr(native.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(native, "_security_api", lambda: (api, api))
    if change == "api":
        api.status = 5
    elif change == "size":
        api.length = 65537
    elif change == "recipe":
        ctypes.memmove(ctypes.addressof(api.buffer) + 2, b"\x04\x80", 2)
    elif change == "cleanup":
        api.free_status = 1
    elif change == "deadline":
        api.after_get = lambda: clock.__setitem__(0, 104.0)
    if change == "none":
        assert (
            native.observe_protected_metadata_descriptor(
                123, OWNER, directory=False, deadline=104.0, cancelled=lambda: False
            )
            == "sha256:" + hashlib.sha256(api.raw).hexdigest()
        )
    else:
        with pytest.raises(native.WindowsEnrollmentNativeError):
            native.observe_protected_metadata_descriptor(
                123, OWNER, directory=False, deadline=104.0, cancelled=lambda: False
            )
    assert api.freed == 1


def test_ffi_structure_uses_full_pointer_and_fixed_dword_width() -> None:
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    assert native._UserInfo23.flags.offset == pointer_size * 3
    assert native._UserInfo23.sid.offset == (32 if pointer_size == 8 else 16)
    assert ctypes.sizeof(native._UserInfo23) == (40 if pointer_size == 8 else 20)


@pytest.mark.parametrize("handle", [True, 0, -1, native._POINTER_LIMIT, native._POINTER_LIMIT + 15])
def test_invalid_held_handle_never_reaches_api(
    monkeypatch: pytest.MonkeyPatch, handle: Any
) -> None:
    def forbidden() -> None:
        pytest.fail("invalid handle reached native factory")

    monkeypatch.setattr(native, "_security_api", forbidden)
    with pytest.raises(native.WindowsEnrollmentNativeError):
        native.observe_protected_metadata_descriptor(
            handle, OWNER, directory=False, deadline=104.0, cancelled=lambda: False
        )


@pytest.mark.parametrize("failure", ["unterminated", "surrogate", "unaligned"])
def test_fake_sam_name_geometry_is_bounded(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    api = SamFake()
    fake_sam(monkeypatch, api)
    assert api.info.name is not None
    if failure == "unterminated":
        ctypes.memmove(api.info.name + 38, b"xx", 2)
    elif failure == "surrogate":
        ctypes.memmove(api.info.name, b"\x00\xd8", 2)
    else:
        api.info.name += 1
    with pytest.raises(native.WindowsEnrollmentNativeError):
        lookup()
    assert api.freed == 1


def test_fake_api_exception_is_sanitized_and_owned_buffer_freed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = SamFake()
    fake_sam(monkeypatch, api)

    def failure() -> None:
        raise OSError("synthetic sensitive native details")

    api.after_get = failure
    with pytest.raises(native.WindowsEnrollmentNativeError) as caught:
        lookup()
    assert "sensitive" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    assert api.freed == 1


def test_fake_cleanup_exception_never_returns_account_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = SamFake()
    fake_sam(monkeypatch, api)

    def failure(pointer: Any) -> int:
        api.freed += 1
        raise OSError("synthetic cleanup detail")

    monkeypatch.setattr(api, "NetApiBufferFree", failure)
    with pytest.raises(native.WindowsEnrollmentNativeError, match="cleanup failed"):
        lookup()
    assert api.freed == 1


def test_unavailable_factories_are_sanitized_without_native_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(native.sys, "platform", "nonwindows-test")
    with pytest.raises(native.WindowsEnrollmentNativeError, match="unavailable"):
        native._sam_api()
    with pytest.raises(native.WindowsEnrollmentNativeError, match="unavailable"):
        native._security_api()


@pytest.mark.parametrize("operation", ["sam", "metadata"])
@pytest.mark.parametrize("stop", ["deadline", "cancelled"])
def test_successful_native_cleanup_does_not_bypass_final_original_stop_check(
    monkeypatch: pytest.MonkeyPatch, operation: str, stop: str
) -> None:
    clock = [100.0]
    stopped = [False]
    monkeypatch.setattr(native.time, "monotonic", lambda: clock[0])
    api = SamFake() if operation == "sam" else SecurityFake()
    if operation == "sam":
        monkeypatch.setattr(native, "_sam_api", lambda: api)
        free_name = "NetApiBufferFree"
    else:
        monkeypatch.setattr(native, "_security_api", lambda: (api, api))
        free_name = "LocalFree"

    def free(pointer: Any) -> int:
        api.freed += 1
        if stop == "deadline":
            clock[0] = 104.0
        else:
            stopped[0] = True
        return 0

    monkeypatch.setattr(api, free_name, free)
    with pytest.raises(native.WindowsEnrollmentNativeError, match="stopped"):
        if operation == "sam":
            native.resolve_local_reader_account(
                GENERATION, READER, deadline=104.0, cancelled=lambda: stopped[0]
            )
        else:
            native.observe_protected_metadata_descriptor(
                123, OWNER, directory=False, deadline=104.0, cancelled=lambda: stopped[0]
            )
    assert api.freed == 1


@pytest.mark.parametrize("earlier_failure", [False, True])
def test_local_free_exception_overrides_descriptor_success_or_failure(
    monkeypatch: pytest.MonkeyPatch, earlier_failure: bool
) -> None:
    api = SecurityFake()
    api.status = 5 if earlier_failure else 0
    monkeypatch.setattr(native.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(native, "_security_api", lambda: (api, api))

    def free(pointer: Any) -> int:
        api.freed += 1
        raise OSError("synthetic private cleanup detail")

    monkeypatch.setattr(api, "LocalFree", free)
    with pytest.raises(native.WindowsEnrollmentNativeError, match="cleanup failed") as caught:
        native.observe_protected_metadata_descriptor(
            123, OWNER, directory=False, deadline=104.0, cancelled=lambda: False
        )
    assert api.freed == 1
    assert "private" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
