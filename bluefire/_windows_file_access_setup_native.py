"""Private create-only Win32 setup boundary; never invoked by status or admission.

Only the original elevated local CLI lifecycle calls this backend. A blocked native
call requires an external disposable hard-deadline supervisor. No rollback, adoption,
account deletion or cleanup of published objects is attempted after partial effects.
"""

from __future__ import annotations

import ctypes
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

from . import windows_file_access_enrollment_native as native
from . import windows_file_access_handles as handles
from . import windows_session_facts as session
from .secret_store import WindowsDPAPISecretProvider
from .windows_file_access_dacl import verify_resource_dacl
from .windows_file_access_policy import WindowsFileAccessPolicy
from .windows_owner_acl import _handle_from_descriptor


class _UserInfo2(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_void_p),
        ("password", ctypes.c_void_p),
        ("password_age", ctypes.c_uint32),
        ("priv", ctypes.c_uint32),
        ("home", ctypes.c_void_p),
        ("comment", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("script", ctypes.c_void_p),
        ("auth_flags", ctypes.c_uint32),
        ("full_name", ctypes.c_void_p),
        ("user_comment", ctypes.c_void_p),
        ("parameters", ctypes.c_void_p),
        ("workstations", ctypes.c_void_p),
        ("last_logon", ctypes.c_uint32),
        ("last_logoff", ctypes.c_uint32),
        ("expires", ctypes.c_uint32),
        ("max_storage", ctypes.c_uint32),
        ("units_per_week", ctypes.c_uint32),
        ("logon_hours", ctypes.c_void_p),
        ("bad_passwords", ctypes.c_uint32),
        ("num_logons", ctypes.c_uint32),
        ("logon_server", ctypes.c_void_p),
        ("country", ctypes.c_uint32),
        ("code_page", ctypes.c_uint32),
    ]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("descriptor", ctypes.c_void_p),
        ("inherit", ctypes.c_int32),
    ]


def _require_local_machine(gate: native._Gate) -> None:
    """NULL NetUserAdd on a DC is AD mutation, so refuse DC/DS roles first."""
    api = ctypes.WinDLL("netapi32.dll", use_last_error=True, winmode=0x800)
    api.DsRoleGetPrimaryDomainInformation.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_int32,
        ctypes.POINTER(ctypes.c_void_p),
    )
    api.DsRoleGetPrimaryDomainInformation.restype = ctypes.c_uint32
    api.DsRoleFreeMemory.argtypes = (ctypes.c_void_p,)
    api.DsRoleFreeMemory.restype = None
    pointer = ctypes.c_void_p()
    try:
        gate.check()
        status = api.DsRoleGetPrimaryDomainInformation(None, 1, ctypes.byref(pointer))
        gate.check()
        if status != 0 or not pointer.value or not 0 < pointer.value < native._POINTER_LIMIT - 8:
            native._refuse("Windows setup machine role is unavailable")
        # Successful Basic query owns a fixed native structure. Read only its
        # two scalar fields; never follow the optional domain string pointers.
        scalars = (ctypes.c_uint32 * 2).from_buffer_copy(ctypes.string_at(pointer, 8))
        if scalars[0] not in (0, 1, 2, 3) or scalars[1] & ~0x1000000:
            native._refuse("Windows setup refuses directory-service machine roles")
    finally:
        if pointer.value:
            try:
                api.DsRoleFreeMemory(pointer)
            except Exception:
                native._refuse("Windows setup machine role cleanup failed")
        gate.check()


def _local_account(api: Any, name: str, *, missing: bool = False) -> str | None:
    """Derive a local SID from a bounded owned allocation, not a caller SID."""
    pointer = ctypes.c_void_p()
    try:
        status = api.NetUserGetInfo(None, name, 23, ctypes.byref(pointer))
        if missing and status == 2221 and not pointer.value:
            return None
        if status != 0 or not pointer.value:
            native._refuse("Windows setup local account observation failed")
        length = ctypes.c_uint32()
        if api.NetApiBufferSize(pointer, ctypes.byref(length)) != 0:
            native._refuse()
        minimum = ctypes.sizeof(native._UserInfo23)
        if not minimum <= length.value <= native._MAX_BUFFER:
            native._refuse()
        raw = ctypes.string_at(pointer, length.value)
        info = native._UserInfo23.from_buffer_copy(raw)
        sid, _ = native._sid(
            raw, native._relative(info.sid, pointer.value, length.value, minimum, 4), len(raw)
        )
        return native._account_from_buffer(pointer.value, length.value, name, sid).reader_sid
    finally:
        if pointer.value:
            try:
                failed = api.NetApiBufferFree(pointer) != 0
            except Exception:
                failed = True
            if failed:
                native._refuse("Windows setup account buffer cleanup failed")


def _elevated_owner(gate: native._Gate) -> session.WindowsPrincipalFacts:
    """Prove current primary + actual linked limited token + local SAM continuity."""
    gate.check()
    _require_local_machine(gate)
    api = session._WindowsApi()
    before = session._observe(api)
    native._local_sid(before.user_sid)
    if not before.elevated:
        native._refuse("Windows setup requires a linked elevated local owner")
    linked = ctypes.c_void_p()
    try:
        with api.process_token() as token:
            size = ctypes.c_uint32(ctypes.sizeof(linked))
            if not api.security.GetTokenInformation(
                token, 19, ctypes.byref(linked), size.value, ctypes.byref(size)
            ):
                native._refuse()
            if (
                size.value != ctypes.sizeof(linked)
                or not linked.value
                or not 0 < linked.value < native._POINTER_LIMIT
            ):
                native._refuse()
            api.statistics(linked.value)  # Primary, finite actual instance.
            if api.user_sid(linked.value) != before.user_sid or api.dword(linked.value, 20) != 0:
                native._refuse("Windows setup linked owner continuity failed")
    finally:
        if linked.value and not api.kernel.CloseHandle(linked):
            native._refuse("Windows setup linked token cleanup failed")
    security = ctypes.WinDLL("advapi32.dll", use_last_error=True, winmode=0x800)
    security.GetUserNameW.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    security.GetUserNameW.restype = ctypes.c_int32
    name, length = ctypes.create_unicode_buffer(257), ctypes.c_uint32(257)
    if not security.GetUserNameW(name, ctypes.byref(length)) or not 1 < length.value <= 257:
        native._refuse()
    if _local_account(native._sam_api(), name.value) != before.user_sid:
        native._refuse("Windows setup owner is not the local SAM account")
    gate.check()
    if session._observe(api) != before:
        native._refuse("Windows setup owner changed")
    return before


class _Credential:
    """Owned UTF16 buffer; no printable representation or immutable password str."""

    __slots__ = ("buffer", "length")

    def __init__(self) -> None:
        # Fixed ASCII alphabet includes four classes; 64 random characters.
        alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%"
        values = bytearray(
            b"Aa2!" + bytes(alphabet[secrets.randbelow(len(alphabet))] for _ in range(60))
        )
        try:
            self.length = len(values)
            self.buffer = (ctypes.c_uint16 * (self.length + 1))(*values, 0)
        finally:
            values[:] = b"\0" * len(values)

    def __repr__(self) -> str:
        return "<owned Windows setup credential>"

    def wipe(self) -> None:
        ctypes.memset(self.buffer, 0, ctypes.sizeof(self.buffer))

    def protect(self, purpose: str) -> bytes:
        # Existing provider accepts bytes. Reachable native buffers are wiped by
        # it; immutable Python copies are explicitly not claimed erasable.
        return WindowsDPAPISecretProvider().protect(
            purpose, ctypes.string_at(self.buffer, self.length * 2)
        )


class _NativeSetup:
    def __init__(
        self, gate: native._Gate, owner: session.WindowsPrincipalFacts, issued: int
    ) -> None:
        if sys.platform != "win32":
            native._refuse()
        self.gate, self.owner = gate, owner
        self.issued, self.expires = issued, issued + 5000
        self.held: list[int] = []
        self.observed: dict[
            str, tuple[dict[str, Any], bool, bool, WindowsFileAccessPolicy | None]
        ] = {}
        self.payloads: dict[str, bytes] = {}
        self.cleanup_failed = False
        self.sam = native._sam_api()
        self.sam.NetUserAdd.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        )
        self.sam.NetUserAdd.restype = ctypes.c_uint32
        self.kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
        self.security = ctypes.WinDLL("advapi32.dll", use_last_error=True, winmode=0x800)
        self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        )
        self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int32
        self.kernel.CreateDirectoryW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.POINTER(_SecurityAttributes),
        )
        self.kernel.CreateDirectoryW.restype = ctypes.c_int32
        self.kernel.CreateFileW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(_SecurityAttributes),
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        )
        self.kernel.CreateFileW.restype = ctypes.c_void_p
        self.kernel.WriteFile.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        )
        self.kernel.WriteFile.restype = ctypes.c_int32
        for name in ("FlushFileBuffers", "CloseHandle"):
            getattr(self.kernel, name).argtypes = (ctypes.c_void_p,)
            getattr(self.kernel, name).restype = ctypes.c_int32
        self.kernel.LocalFree.argtypes = (ctypes.c_void_p,)
        self.kernel.LocalFree.restype = ctypes.c_void_p

    def current(self) -> None:
        self.gate.check()
        if (
            not self.issued <= time.time_ns() // 1_000_000 < self.expires
            or session.current_process_principal() != self.owner
        ):
            native._refuse("Windows setup principal changed")
        self.gate.check()
        if not self.issued <= time.time_ns() // 1_000_000 < self.expires:
            native._refuse("Windows setup original interval ended")

    def _sddl(self, directory: bool) -> str:
        mask = 0x1200A0 if directory else 0x120089
        return f"O:BAD:P(A;;0x1f01ff;;;SY)(A;;0x1f01ff;;;BA)(A;;0x{mask:x};;;{self.owner.user_sid})"

    def absent(self, path: str, *, directory: bool) -> None:
        self.current()
        try:
            descriptor = handles.open_observation(Path(path), directory=directory)
        except handles.WindowsFileHandleError:
            if ctypes.get_last_error() in (2, 3):
                return
            native._refuse("Windows setup preexisting state is unresolved")
        else:
            os.close(descriptor)
            native._refuse("Windows setup refuses preexisting state")

    def _create(self, path: str, raw: bytes | None, sddl: str) -> None:
        self.current()
        descriptor = ctypes.c_void_p()
        handle = None
        try:
            if not self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None
            ):
                native._refuse()
            self.current()
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, 0)
            if raw is None:
                if not self.kernel.CreateDirectoryW(path, ctypes.byref(attributes)):
                    native._refuse("Windows setup exclusive directory creation failed")
                self.current()
            else:
                handle = self.kernel.CreateFileW(
                    path, 0x40000000, 1, ctypes.byref(attributes), 1, 0x00200080, None
                )
                if not handle or handle == ctypes.c_void_p(-1).value:
                    handle = None
                    native._refuse("Windows setup exclusive file creation failed")
                self.current()
                written = ctypes.c_uint32()
                data = ctypes.create_string_buffer(raw)
                if not self.kernel.WriteFile(
                    handle, data, len(raw), ctypes.byref(written), None
                ) or written.value != len(raw):
                    native._refuse("Windows setup file publication failed")
                self.current()
                if not self.kernel.FlushFileBuffers(handle):
                    native._refuse("Windows setup file flush failed")
            self.current()
        finally:
            failed = False
            if handle:
                try:
                    failed = not self.kernel.CloseHandle(handle)
                except Exception:
                    failed = True
            if descriptor.value:
                try:
                    failed = bool(self.kernel.LocalFree(descriptor)) or failed
                except Exception:
                    failed = True
            if failed:
                native._refuse("Windows setup creation cleanup is unknown")

    def observe(
        self,
        path: str,
        *,
        directory: bool,
        protected: bool = True,
        policy: WindowsFileAccessPolicy | None = None,
    ) -> dict[str, Any]:
        self.current()
        if len(self.held) >= 96:
            native._refuse("Windows setup held-object bound exceeded")
        descriptor = handles.open_observation(Path(path), directory=directory, data=not directory)
        self.held.append(descriptor)
        facts = handles.inspect_observation(descriptor, directory=directory)
        if facts.final_path != "\\\\?\\" + path:
            native._refuse()
        if protected:
            native.observe_protected_metadata_descriptor(
                _handle_from_descriptor(descriptor),
                self.owner.user_sid,
                directory=directory,
                deadline=self.gate.deadline,
                cancelled=self.gate.cancelled,
            )
        elif policy is not None:
            verify_resource_dacl(
                _handle_from_descriptor(descriptor),
                policy,
                state="directory" if directory else "readable",
            )
        volume, file_id = native.file_identity_wire(*facts.identity)
        row = {"identity": {"volume_serial": volume, "file_id": file_id}, "size": facts.size}
        self.observed[path] = (row, directory, protected, policy)
        self.current()
        return row

    def directory(self, path: str, policy: WindowsFileAccessPolicy | None = None) -> dict[str, Any]:
        self._create(path, None, self._sddl(True) if policy is None else policy.directory_sddl())
        return self.observe(path, directory=True, protected=policy is None, policy=policy)

    def publish(
        self, path: str, raw: bytes, policy: WindowsFileAccessPolicy | None = None
    ) -> dict[str, Any]:
        self._create(
            path, raw, self._sddl(False) if policy is None else policy.file_sddl("readable")
        )
        before = self.observe(path, directory=False, protected=policy is None, policy=policy)
        descriptor = self.held[-1]
        payload = os.read(descriptor, len(raw) + 1)
        if (
            payload != raw
            or os.read(descriptor, 1) != b""
            or self.observe(path, directory=False, protected=policy is None, policy=policy)
            != before
        ):
            native._refuse("Windows setup fresh publication changed")
        self.payloads[path] = raw
        return before

    def verify_all(self) -> None:
        """All fixed ancestries remain held while fresh identity/DACL opens occur."""
        for path, (before, directory, protected, policy) in list(self.observed.items()):
            if (
                self.observe(path, directory=directory, protected=protected, policy=policy)
                != before
            ):
                native._refuse("Windows setup held publication drifted")
            if path in self.payloads:
                raw = self.payloads[path]
                descriptor = self.held[-1]
                if os.read(descriptor, len(raw) + 1) != raw or os.read(descriptor, 1) != b"":
                    native._refuse("Windows setup published bytes drifted")
        self.current()

    def read_public(self, path: str, maximum: int) -> bytes:
        observation = self.observe(path, directory=False)
        if not 1 <= observation["size"] <= maximum:
            native._refuse("Windows setup public record exceeds its bound")
        descriptor = self.held[-1]
        raw = os.read(descriptor, maximum + 1)
        if len(raw) != observation["size"] or os.read(descriptor, 1) != b"":
            native._refuse("Windows setup public record changed")
        self.payloads[path] = raw
        self.current()
        return raw

    def missing_account(self, generation: str) -> None:
        self.current()
        if _local_account(self.sam, "bf_" + generation[:16], missing=True) is not None:
            native._refuse("Windows setup refuses preexisting account")
        self.current()

    def account(self, generation: str, credential: _Credential, expires_seconds: int) -> str:
        self.current()
        _require_local_machine(self.gate)
        self.current()
        name = ctypes.create_unicode_buffer("bf_" + generation[:16])
        info = _UserInfo2()
        info.name, info.password = ctypes.addressof(name), ctypes.addressof(credential.buffer)
        info.priv, info.flags, info.expires, info.max_storage = (
            1,
            0x10241,
            expires_seconds,
            0xFFFFFFFF,
        )
        error = ctypes.c_uint32()
        if self.sam.NetUserAdd(None, 2, ctypes.byref(info), ctypes.byref(error)) != 0:
            native._refuse("Windows setup account creation failed")
        self.current()
        sid = _local_account(self.sam, name.value)
        if sid is None:
            native._refuse()
        WindowsFileAccessPolicy(self.owner.user_sid, sid)
        self.verify_account(generation, sid, expires_seconds)
        return sid

    def verify_account(self, generation: str, sid: str, expires_seconds: int) -> None:
        self.current()
        name = "bf_" + generation[:16]
        if _local_account(self.sam, name) != sid:
            native._refuse("Windows setup account changed")
        pointer = ctypes.c_void_p()
        try:
            if (
                self.sam.NetUserGetInfo(None, name, 2, ctypes.byref(pointer)) != 0
                or not pointer.value
            ):
                native._refuse()
            size = ctypes.c_uint32()
            if (
                self.sam.NetApiBufferSize(pointer, ctypes.byref(size)) != 0
                or not ctypes.sizeof(_UserInfo2) <= size.value <= native._MAX_BUFFER
            ):
                native._refuse()
            info = _UserInfo2.from_buffer_copy(ctypes.string_at(pointer, ctypes.sizeof(_UserInfo2)))
            if info.expires != expires_seconds or info.flags != 0x10241 or info.priv != 1:
                native._refuse("Windows setup account expiry is unverified")
        finally:
            if pointer.value and self.sam.NetApiBufferFree(pointer) != 0:
                native._refuse("Windows setup account cleanup failed")
        self.current()

    def close(self) -> None:
        failed = self.cleanup_failed
        for descriptor in reversed(self.held):
            try:
                os.close(descriptor)
            except Exception:
                failed = True
        self.held.clear()
        self.cleanup_failed = failed
        if failed:
            native._refuse("Windows setup held handle cleanup is unknown")
