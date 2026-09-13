"""Operating-system-backed protection for locally persisted secret references.

This module deliberately exposes opaque bytes rather than a filesystem or
environment-variable convention.  Production providers use Windows DPAPI or
an owner-private POSIX master key.  The in-memory provider is only a
deterministic test boundary: its opaque values are random handles and the
corresponding plaintext never leaves process memory.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import os
import platform
import secrets
import stat
import struct
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

_ENVELOPE_MAGIC = b"BFSX"
_ENVELOPE_VERSION = 1
_PROVIDER_WINDOWS_DPAPI = 1
_PROVIDER_POSIX_OWNER_PRIVATE = 2
_PROVIDER_IN_MEMORY = 255
_ENVELOPE_HEADER = struct.Struct(">4sBBI")

_MAX_PURPOSE_BYTES = 512
_MAX_PLAINTEXT_BYTES = 1024 * 1024
_MAX_PROTECTED_PAYLOAD_BYTES = 2 * 1024 * 1024
_MAX_OPAQUE_BYTES = _ENVELOPE_HEADER.size + _MAX_PROTECTED_PAYLOAD_BYTES
_MEMORY_HANDLE_BYTES = 32

_PURPOSE_DOMAIN = b"bluefire.secret-store.purpose.v1\x00"
_POSIX_AAD_DOMAIN = b"bluefire.secret-store.posix-aead.v1\x00"
_CRYPTPROTECT_UI_FORBIDDEN = 0x00000001
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800

_POSIX_KEY_MAGIC = b"BFSK"
_POSIX_KEY_VERSION = 1
_POSIX_KEY_ID_BYTES = 16
_POSIX_XCHACHA_KEY_BYTES = 32
_POSIX_XCHACHA_NONCE_BYTES = 24
_POSIX_XCHACHA_TAG_BYTES = 16
_POSIX_KEY_RECORD = struct.Struct(f">4sB{_POSIX_KEY_ID_BYTES}s{_POSIX_XCHACHA_KEY_BYTES}s")
_POSIX_PAYLOAD_HEADER = struct.Struct(f">{_POSIX_KEY_ID_BYTES}s{_POSIX_XCHACHA_NONCE_BYTES}s")
_POSIX_KEY_FILENAME = "secret-store-master-key.v1"
_POSIX_MAX_DIRECTORY_ENTRIES = 256
_POSIX_TEMP_TOKEN_CHARACTERS = 32
_POSIX_LOCK_TIMEOUT_SECONDS = 5.0
_POSIX_LOCK_POLL_SECONDS = 0.02


class _PosixCryptoApi:
    """Lazily bound XChaCha20-Poly1305 operations for the POSIX provider."""

    _encrypt: Callable[[bytes, bytes | None, bytes, bytes], bytes]
    _decrypt: Callable[[bytes, bytes | None, bytes, bytes], bytes]
    _crypto_error: type[Exception]

    def __init__(self) -> None:
        try:
            from nacl import bindings
            from nacl.exceptions import CryptoError

            if (
                bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES != _POSIX_XCHACHA_KEY_BYTES
                or bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
                != _POSIX_XCHACHA_NONCE_BYTES
                or bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES != _POSIX_XCHACHA_TAG_BYTES
            ):
                raise OSError("unsupported POSIX secret crypto binding")
            encrypt = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt
            decrypt = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt
            if (
                not callable(encrypt)
                or not callable(decrypt)
                or not isinstance(CryptoError, type)
                or not issubclass(CryptoError, Exception)
            ):
                raise OSError("invalid POSIX secret crypto binding")
        except (ImportError, AttributeError, OSError, RuntimeError, TypeError, ValueError):
            raise OSError("POSIX secret crypto binding is unavailable") from None

        self._encrypt = encrypt
        self._decrypt = decrypt
        self._crypto_error = CryptoError

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes,
        nonce: bytes,
        key: bytes,
    ) -> bytes:
        try:
            result = self._encrypt(plaintext, associated_data, nonce, key)
        except self._crypto_error:
            raise OSError("POSIX secret encryption failed") from None
        except (MemoryError, OSError, TypeError, ValueError):
            raise OSError("POSIX secret encryption failed") from None
        if (
            not isinstance(result, bytes)
            or len(result) != len(plaintext) + _POSIX_XCHACHA_TAG_BYTES
        ):
            raise OSError("POSIX secret encryption failed")
        return result

    def decrypt(
        self,
        ciphertext: bytes,
        associated_data: bytes,
        nonce: bytes,
        key: bytes,
    ) -> bytes:
        try:
            result = self._decrypt(ciphertext, associated_data, nonce, key)
        except self._crypto_error:
            raise OSError("POSIX secret decryption failed") from None
        except (MemoryError, OSError, TypeError, ValueError):
            raise OSError("POSIX secret decryption failed") from None
        if (
            not isinstance(result, bytes)
            or len(ciphertext) < _POSIX_XCHACHA_TAG_BYTES
            or len(result) != len(ciphertext) - _POSIX_XCHACHA_TAG_BYTES
        ):
            raise OSError("POSIX secret decryption failed")
        return result


_POSIX_CRYPTO_API: _PosixCryptoApi | None = None
_POSIX_CRYPTO_API_LOCK = threading.Lock()

_DARWIN_ACL_TYPE_EXTENDED = 0x00000100
_DARWIN_ACL_FIRST_ENTRY = 0
_DARWIN_MNT_IGNORE_OWNERSHIP = 0x00200000
_DARWIN_STATFS_SIZE = 2168
_DARWIN_STATFS_FLAGS_OFFSET = 64


class _DarwinFsId(ctypes.Structure):
    _fields_ = [("values", ctypes.c_int32 * 2)]


class _DarwinStatFs(ctypes.Structure):
    """Modern Darwin ``struct statfs`` used by 64-bit Python processes."""

    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _DarwinFsId),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


class _DarwinSecurityApi:
    fstatfs: Any
    acl_get_fd_np: Any
    acl_get_entry: Any
    acl_free: Any

    def __init__(self) -> None:
        if (
            ctypes.sizeof(_DarwinStatFs) != _DARWIN_STATFS_SIZE
            or _DarwinStatFs.f_flags.offset != _DARWIN_STATFS_FLAGS_OFFSET
        ):
            raise OSError("unsupported Darwin filesystem ABI")
        try:
            library = ctypes.CDLL(None, use_errno=True)
            machine = platform.machine().casefold()
            if machine == "x86_64":
                fstatfs = getattr(library, "fstatfs$INODE64")
            elif machine in {"arm64", "aarch64"}:
                fstatfs = library.fstatfs
            else:
                raise OSError("unsupported Darwin architecture")

            fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(_DarwinStatFs)]
            fstatfs.restype = ctypes.c_int
            acl_get_fd_np = library.acl_get_fd_np
            acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
            acl_get_fd_np.restype = ctypes.c_void_p
            acl_get_entry = library.acl_get_entry
            acl_get_entry.argtypes = [
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            acl_get_entry.restype = ctypes.c_int
            acl_free = library.acl_free
            acl_free.argtypes = [ctypes.c_void_p]
            acl_free.restype = ctypes.c_int
        except (AttributeError, OSError, TypeError, ValueError):
            raise OSError("Darwin descriptor security API is unavailable") from None

        self.fstatfs = fstatfs
        self.acl_get_fd_np = acl_get_fd_np
        self.acl_get_entry = acl_get_entry
        self.acl_free = acl_free


_DARWIN_SECURITY_API: _DarwinSecurityApi | None = None
_DARWIN_SECURITY_API_LOCK = threading.Lock()


class SecretStoreError(RuntimeError):
    """A sanitized refusal from the secret-protection boundary."""


@runtime_checkable
class SecretProvider(Protocol):
    """Protect and recover bytes for one explicit application purpose."""

    @property
    def provider_id(self) -> str: ...

    def protect(self, purpose: str, plaintext: bytes) -> bytes: ...

    def unprotect(self, purpose: str, opaque: bytes) -> bytes: ...


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class WindowsDPAPISecretProvider:
    """Current-user Windows DPAPI provider with purpose-bound entropy.

    The provider loads only known DLLs through the system32-only loader flag.
    It neither reads ``SYSTEMROOT`` nor launches a helper process.  DPAPI's
    machine-scope flag is intentionally absent, so only the enrolling Windows
    user can normally recover a protected value.
    """

    @property
    def provider_id(self) -> str:
        return "windows-dpapi-current-user.v1"

    def __init__(self) -> None:
        if os.name != "nt":
            raise SecretStoreError("Operating-system secret protection is unavailable.")
        try:
            win_dll = ctypes.WinDLL  # type: ignore[attr-defined]
            crypt32 = win_dll(
                "crypt32.dll",
                use_last_error=True,
                winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
            kernel32 = win_dll(
                "kernel32.dll",
                use_last_error=True,
                winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
            protect = crypt32.CryptProtectData
            unprotect = crypt32.CryptUnprotectData
            local_free = kernel32.LocalFree

            blob_pointer = ctypes.POINTER(_DataBlob)
            protect.argtypes = [
                blob_pointer,
                wintypes.LPCWSTR,
                blob_pointer,
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.DWORD,
                blob_pointer,
            ]
            protect.restype = wintypes.BOOL
            unprotect.argtypes = list(protect.argtypes)
            unprotect.restype = wintypes.BOOL
            local_free.argtypes = [ctypes.c_void_p]
            local_free.restype = ctypes.c_void_p
        except (AttributeError, OSError, TypeError):
            raise SecretStoreError("Operating-system secret protection is unavailable.") from None

        self._protect_data = protect
        self._unprotect_data = unprotect
        self._local_free = local_free

    def protect(self, purpose: str, plaintext: bytes) -> bytes:
        purpose_digest = _purpose_digest(purpose)
        secret = _validated_plaintext(plaintext)
        payload = self._call_dpapi(self._protect_data, secret, purpose_digest, protecting=True)
        return _encode_envelope(_PROVIDER_WINDOWS_DPAPI, payload)

    def unprotect(self, purpose: str, opaque: bytes) -> bytes:
        purpose_digest = _purpose_digest(purpose)
        payload = _decode_envelope(opaque, expected_provider=_PROVIDER_WINDOWS_DPAPI)
        return self._call_dpapi(
            self._unprotect_data,
            payload,
            purpose_digest,
            protecting=False,
        )

    def _call_dpapi(
        self,
        operation: object,
        value: bytes,
        purpose_digest: bytes,
        *,
        protecting: bool,
    ) -> bytes:
        input_blob, input_buffer = _blob_from_bytes(value)
        entropy_blob, entropy_buffer = _blob_from_bytes(purpose_digest)
        output_blob = _DataBlob()
        # Keep the backing buffers alive until the native call returns.
        _ = (input_buffer, entropy_buffer)
        try:
            succeeded = operation(  # type: ignore[operator]
                ctypes.byref(input_blob),
                None,
                ctypes.byref(entropy_blob),
                None,
                None,
                _CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
        except (OSError, ValueError):
            succeeded = False

        if not succeeded:
            message = (
                "Secret protection failed."
                if protecting
                else "Protected secret is invalid or cannot be opened."
            )
            raise SecretStoreError(message) from None

        try:
            output_size = int(output_blob.cbData)
            if (
                output_size < 0
                or output_size > _MAX_PROTECTED_PAYLOAD_BYTES
                or (output_size and not bool(output_blob.pbData))
            ):
                raise SecretStoreError(
                    "Secret protection failed."
                    if protecting
                    else "Protected secret is invalid or cannot be opened."
                )
            recovered = bytes(ctypes.string_at(output_blob.pbData, output_size))
        finally:
            if output_blob.pbData:
                self._local_free(ctypes.cast(output_blob.pbData, ctypes.c_void_p))

        if not protecting and len(recovered) > _MAX_PLAINTEXT_BYTES:
            raise SecretStoreError("Protected secret is invalid or cannot be opened.")
        return recovered


class PosixOwnerPrivateSecretProvider:
    """Purpose-bound AEAD backed by one owner-private local master key.

    POSIX has no universal login secret service that is available both on a
    desktop and in a headless local lab.  This provider therefore relies on
    the operating system's user ownership and mode enforcement for the master
    key, then uses XChaCha20-Poly1305 so envelopes copied without that key or
    modified envelopes fail authentication.  A compromised same-user process
    or privileged operating system remains authoritative, matching BlueFire's
    local runner model.

    ``key_path`` is explicit to keep tests isolated.  Production selection
    supplies the fixed path beneath BlueFire's managed per-user product root;
    no BlueFire-specific environment variable directly overrides the key file.
    """

    @property
    def provider_id(self) -> str:
        return "posix-owner-private-xchacha20poly1305.v1"

    def __init__(self, key_path: str | Path) -> None:
        if os.name != "posix":
            raise SecretStoreError("Operating-system secret protection is unavailable.")
        try:
            path = Path(key_path).expanduser()
            encoded_name = os.fsencode(path.name)
        except (OSError, RuntimeError, TypeError, UnicodeError, ValueError):
            raise SecretStoreError("Operating-system secret protection is unavailable.") from None
        if (
            not path.is_absolute()
            or path.name in {"", ".", ".."}
            or ".." in path.parts[1:]
            or path.parent == path
            or not encoded_name
            or len(encoded_name) > 200
            or b"\0" in encoded_name
        ):
            raise SecretStoreError("Operating-system secret protection is unavailable.")
        self._key_path = path
        self._lock = threading.RLock()

    def protect(self, purpose: str, plaintext: bytes) -> bytes:
        purpose_digest = _purpose_digest(purpose)
        secret = _validated_plaintext(plaintext)
        try:
            crypto = _posix_crypto_api()
            with self._lock:
                key_id, key = self._load_or_create_key()
            nonce = secrets.token_bytes(_POSIX_XCHACHA_NONCE_BYTES)
            associated_data = _posix_associated_data(key_id, purpose_digest)
            ciphertext = crypto.encrypt(
                secret,
                associated_data,
                nonce,
                key,
            )
            return _encode_envelope(
                _PROVIDER_POSIX_OWNER_PRIVATE,
                _POSIX_PAYLOAD_HEADER.pack(key_id, nonce) + ciphertext,
            )
        except SecretStoreError:
            raise
        except (MemoryError, OSError, TypeError, ValueError):
            raise SecretStoreError("Secret protection failed.") from None

    def unprotect(self, purpose: str, opaque: bytes) -> bytes:
        purpose_digest = _purpose_digest(purpose)
        try:
            payload = _decode_envelope(
                opaque,
                expected_provider=_PROVIDER_POSIX_OWNER_PRIVATE,
            )
            minimum = _POSIX_PAYLOAD_HEADER.size + _POSIX_XCHACHA_TAG_BYTES
            if len(payload) < minimum:
                raise SecretStoreError("Protected secret is invalid or cannot be opened.")
            key_id, nonce = _POSIX_PAYLOAD_HEADER.unpack_from(payload)
            crypto = _posix_crypto_api()
            with self._lock:
                stored_key_id, key = self._load_key()
            if not hmac.compare_digest(key_id, stored_key_id):
                raise SecretStoreError("Protected secret is invalid or cannot be opened.")
            plaintext = crypto.decrypt(
                payload[_POSIX_PAYLOAD_HEADER.size :],
                _posix_associated_data(key_id, purpose_digest),
                nonce,
                key,
            )
            if len(plaintext) > _MAX_PLAINTEXT_BYTES:
                raise SecretStoreError("Protected secret is invalid or cannot be opened.")
            return plaintext
        except SecretStoreError:
            raise
        except (MemoryError, OSError, TypeError, ValueError):
            raise SecretStoreError("Protected secret is invalid or cannot be opened.") from None

    def _load_or_create_key(self) -> tuple[bytes, bytes]:
        root_descriptor = self._open_key_root(create=True)
        lock_descriptor: int | None = None
        try:
            lock_descriptor = self._open_initialization_lock(root_descriptor, create=True)
            _posix_lock(lock_descriptor)
            try:
                _validate_posix_named_regular(
                    root_descriptor,
                    f".{self._key_path.name}.lock",
                    lock_descriptor,
                    expected_size=0,
                )
                self._recover_interrupted_key_publication(root_descriptor)
                try:
                    result = self._read_key(root_descriptor)
                except FileNotFoundError:
                    self._cleanup_stale_temporary_keys(root_descriptor)
                    result = self._create_key(root_descriptor)
                else:
                    self._cleanup_stale_temporary_keys(root_descriptor)
                self._validate_key_root_path(root_descriptor)
                return result
            finally:
                _posix_unlock(lock_descriptor)
        finally:
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            os.close(root_descriptor)

    def _load_key(self) -> tuple[bytes, bytes]:
        root_descriptor = self._open_key_root(create=False)
        lock_descriptor: int | None = None
        try:
            lock_descriptor = self._open_initialization_lock(root_descriptor, create=False)
            _posix_lock(lock_descriptor)
            try:
                _validate_posix_named_regular(
                    root_descriptor,
                    f".{self._key_path.name}.lock",
                    lock_descriptor,
                    expected_size=0,
                )
                self._recover_interrupted_key_publication(root_descriptor)
                try:
                    result = self._read_key(root_descriptor)
                except FileNotFoundError:
                    self._cleanup_stale_temporary_keys(root_descriptor)
                    raise
                self._cleanup_stale_temporary_keys(root_descriptor)
                self._validate_key_root_path(root_descriptor)
                return result
            finally:
                _posix_unlock(lock_descriptor)
        finally:
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            os.close(root_descriptor)

    def _open_key_root(self, *, create: bool) -> int:
        root = self._key_path.parent
        _reject_posix_symlink_ancestors(root)
        if create:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            _reject_posix_symlink_ancestors(root)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(root, flags)
        try:
            self._validate_key_root_path(descriptor)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _validate_key_root_path(self, descriptor: int) -> None:
        _reject_posix_symlink_ancestors(self._key_path.parent)
        details = os.fstat(descriptor)
        _validate_darwin_descriptor_security(descriptor)
        current = os.stat(self._key_path.parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or (details.st_dev, details.st_ino) != (current.st_dev, current.st_ino)
            or details.st_uid != _posix_user_id()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise OSError("unsafe secret key root")

    def _open_initialization_lock(self, root_descriptor: int, *, create: bool) -> int:
        flags = (
            os.O_RDWR
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        name = f".{self._key_path.name}.lock"
        descriptor: int | None = None
        try:
            if create:
                try:
                    descriptor = os.open(
                        name,
                        flags | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=root_descriptor,
                    )
                except FileExistsError:
                    descriptor = os.open(name, flags, dir_fd=root_descriptor)
                else:
                    os.fchmod(descriptor, 0o600)  # type: ignore[attr-defined]
            else:
                descriptor = os.open(name, flags, dir_fd=root_descriptor)
            _validate_posix_named_regular(
                root_descriptor,
                name,
                descriptor,
                expected_size=0,
            )
            return descriptor
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            raise

    def _read_key(self, root_descriptor: int) -> tuple[bytes, bytes]:
        descriptor = os.open(
            self._key_path.name,
            os.O_RDONLY
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=root_descriptor,
        )
        try:
            before = _validate_posix_named_regular(
                root_descriptor,
                self._key_path.name,
                descriptor,
                expected_size=_POSIX_KEY_RECORD.size,
            )
            payload = _read_exact(descriptor, _POSIX_KEY_RECORD.size)
            after = _validate_posix_named_regular(
                root_descriptor,
                self._key_path.name,
                descriptor,
                expected_size=_POSIX_KEY_RECORD.size,
            )
            if (
                _posix_file_marker(before) != _posix_file_marker(after)
                or len(payload) != _POSIX_KEY_RECORD.size
            ):
                raise OSError("secret key changed while it was read")
        finally:
            os.close(descriptor)
        magic, version, key_id, key = _POSIX_KEY_RECORD.unpack(payload)
        if magic != _POSIX_KEY_MAGIC or version != _POSIX_KEY_VERSION:
            raise OSError("invalid secret key record")
        return key_id, key

    def _recover_interrupted_key_publication(self, root_descriptor: int) -> None:
        """Finish the one safe hard-link publication crash state.

        The caller holds the persistent initialization lock.  A key with two
        links is accepted only when its other link has the exact randomized
        temporary-key name and lives in the same private directory.  Other
        hard-link states remain fail-closed.
        """

        try:
            published = os.stat(
                self._key_path.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if published.st_nlink != 2:
            return
        if (
            not stat.S_ISREG(published.st_mode)
            or published.st_uid != _posix_user_id()
            or stat.S_IMODE(published.st_mode) != 0o600
            or published.st_size != _POSIX_KEY_RECORD.size
        ):
            raise OSError("unsafe interrupted secret key publication")

        candidates = [
            name
            for name, candidate in self._temporary_key_entries(root_descriptor)
            if (candidate.st_dev, candidate.st_ino) == (published.st_dev, published.st_ino)
        ]
        if len(candidates) != 1:
            raise OSError("interrupted secret key publication is ambiguous")

        os.unlink(candidates[0], dir_fd=root_descriptor)
        _sync_posix_directory(root_descriptor)
        current = os.stat(
            self._key_path.name,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if (current.st_dev, current.st_ino) != (
            published.st_dev,
            published.st_ino,
        ) or current.st_nlink != 1:
            raise OSError("interrupted secret key publication changed")

    def _cleanup_stale_temporary_keys(self, root_descriptor: int) -> None:
        removed = False
        for name, details in self._temporary_key_entries(root_descriptor):
            permissions = stat.S_IMODE(details.st_mode)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != _posix_user_id()
                or permissions & ~0o600
                or details.st_nlink != 1
                or details.st_size > _POSIX_KEY_RECORD.size
            ):
                raise OSError("unsafe stale secret key material")
            current = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
            if _posix_file_marker(details) != _posix_file_marker(current):
                raise OSError("stale secret key material changed")
            os.unlink(name, dir_fd=root_descriptor)
            removed = True
        if removed:
            _sync_posix_directory(root_descriptor)

    def _temporary_key_entries(
        self,
        root_descriptor: int,
    ) -> list[tuple[str, os.stat_result]]:
        found: list[tuple[str, os.stat_result]] = []
        with os.scandir(root_descriptor) as entries:
            for index, entry in enumerate(entries, start=1):
                if index > _POSIX_MAX_DIRECTORY_ENTRIES:
                    raise OSError("secret key directory exceeds recovery limit")
                if not _is_posix_key_temporary_name(entry.name, self._key_path.name):
                    continue
                try:
                    details = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                found.append((entry.name, details))
        return found

    def _create_key(self, root_descriptor: int) -> tuple[bytes, bytes]:
        key_id = secrets.token_bytes(_POSIX_KEY_ID_BYTES)
        key = secrets.token_bytes(_POSIX_XCHACHA_KEY_BYTES)
        payload = _POSIX_KEY_RECORD.pack(_POSIX_KEY_MAGIC, _POSIX_KEY_VERSION, key_id, key)
        temporary_name = f".{self._key_path.name}.{secrets.token_hex(16)}.tmp"
        temporary_exists = False
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=root_descriptor,
            )
            temporary_exists = True
            os.fchmod(descriptor, 0o600)  # type: ignore[attr-defined]
            _validate_posix_regular(descriptor, expected_size=0)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            _validate_posix_regular(descriptor, expected_size=len(payload))
            os.close(descriptor)
            descriptor = None
            try:
                self._read_key(root_descriptor)
            except FileNotFoundError:
                pass
            else:
                raise OSError("secret key appeared during initialization")
            os.link(
                temporary_name,
                self._key_path.name,
                src_dir_fd=root_descriptor,
                dst_dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            published = os.stat(
                self._key_path.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            temporary = os.stat(
                temporary_name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if (published.st_dev, published.st_ino) != (
                temporary.st_dev,
                temporary.st_ino,
            ) or published.st_nlink != 2:
                raise OSError("secret key publication changed")
            os.unlink(temporary_name, dir_fd=root_descriptor)
            temporary_exists = False
            _sync_posix_directory(root_descriptor)
            stored_key_id, stored_key = self._read_key(root_descriptor)
            if not hmac.compare_digest(stored_key_id, key_id) or not hmac.compare_digest(
                stored_key, key
            ):
                raise OSError("secret key publication changed")
            return stored_key_id, stored_key
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary_exists:
                try:
                    os.unlink(temporary_name, dir_fd=root_descriptor)
                    _sync_posix_directory(root_descriptor)
                except OSError:
                    pass


class InMemorySecretProvider:
    """Process-local test provider backed by unguessable opaque handles.

    This is not an encryption fallback and is never selected automatically.
    Each protection call creates a new random handle, even for the same value.
    Purpose bindings and plaintext values remain only in the private in-memory
    mapping, so persisting the returned envelope cannot reveal or recover them
    in another process.
    """

    @property
    def provider_id(self) -> str:
        return "in-memory-test.v1"

    def __init__(self) -> None:
        self._values: dict[bytes, tuple[bytes, bytes]] = {}
        self._lock = threading.RLock()

    def protect(self, purpose: str, plaintext: bytes) -> bytes:
        purpose_digest = _purpose_digest(purpose)
        secret = _validated_plaintext(plaintext)
        with self._lock:
            while True:
                handle = secrets.token_bytes(_MEMORY_HANDLE_BYTES)
                if handle not in self._values:
                    break
            self._values[handle] = (purpose_digest, secret)
        return _encode_envelope(_PROVIDER_IN_MEMORY, handle)

    def unprotect(self, purpose: str, opaque: bytes) -> bytes:
        purpose_digest = _purpose_digest(purpose)
        handle = _decode_envelope(opaque, expected_provider=_PROVIDER_IN_MEMORY)
        if len(handle) != _MEMORY_HANDLE_BYTES:
            raise SecretStoreError("Protected secret is invalid or cannot be opened.")
        with self._lock:
            record = self._values.get(handle)
        if record is None or not hmac.compare_digest(record[0], purpose_digest):
            raise SecretStoreError("Protected secret is invalid or cannot be opened.")
        return record[1]


def default_secret_provider() -> SecretProvider:
    """Return the production provider, failing closed on unsupported systems."""

    if os.name == "nt":
        return WindowsDPAPISecretProvider()
    if os.name == "posix":
        try:
            key_path = _posix_managed_product_root() / _POSIX_KEY_FILENAME
        except (OSError, RuntimeError, UnicodeError, ValueError):
            raise SecretStoreError("Operating-system secret protection is unavailable.") from None
        return PosixOwnerPrivateSecretProvider(key_path)
    raise SecretStoreError("Operating-system secret protection is unavailable.")


def _posix_managed_product_root(
    *,
    environ: Mapping[str, str] | None = None,
    platform_name: str | None = None,
) -> Path:
    """Mirror the POSIX managed-root policy without importing execution code."""

    values = os.environ if environ is None else environ
    platform = (sys.platform if platform_name is None else platform_name).strip().casefold()
    if platform in {"darwin", "macos"}:
        return Path.home() / "Library" / "Application Support" / "BlueFire Nexus"
    if platform == "linux":
        base = values.get("XDG_STATE_HOME", "").strip()
        if base:
            return Path(base).expanduser() / "bluefire-nexus"
        return Path.home() / ".local" / "state" / "bluefire-nexus"
    raise OSError("unsupported POSIX secret key platform")


def _posix_crypto_api() -> _PosixCryptoApi:
    global _POSIX_CRYPTO_API

    api = _POSIX_CRYPTO_API
    if api is not None:
        return api
    with _POSIX_CRYPTO_API_LOCK:
        api = _POSIX_CRYPTO_API
        if api is None:
            api = _PosixCryptoApi()
            _POSIX_CRYPTO_API = api
        return api


def _posix_associated_data(key_id: bytes, purpose_digest: bytes) -> bytes:
    return (
        _POSIX_AAD_DOMAIN
        + _ENVELOPE_MAGIC
        + bytes((_ENVELOPE_VERSION, _PROVIDER_POSIX_OWNER_PRIVATE))
        + key_id
        + purpose_digest
    )


def _posix_user_id() -> int:
    operation = getattr(os, "getuid", None)
    if not callable(operation):
        raise OSError("POSIX user identity is unavailable")
    user_id = operation()
    if not isinstance(user_id, int) or user_id < 0:
        raise OSError("POSIX user identity is invalid")
    return user_id


def _reject_posix_symlink_ancestors(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            details = os.stat(current, follow_symlinks=False)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(details.st_mode):
            raise OSError("secret key path contains a symbolic link")


def _validate_posix_regular(descriptor: int, *, expected_size: int) -> os.stat_result:
    details = os.fstat(descriptor)
    _validate_darwin_descriptor_security(descriptor)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != _posix_user_id()
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_nlink != 1
        or details.st_size != expected_size
    ):
        raise OSError("unsafe secret key material")
    return details


def _darwin_security_api() -> _DarwinSecurityApi:
    global _DARWIN_SECURITY_API

    api = _DARWIN_SECURITY_API
    if api is not None:
        return api
    with _DARWIN_SECURITY_API_LOCK:
        api = _DARWIN_SECURITY_API
        if api is None:
            api = _DarwinSecurityApi()
            _DARWIN_SECURITY_API = api
        return api


def _validate_darwin_mount_flags(flags: int) -> None:
    if flags & _DARWIN_MNT_IGNORE_OWNERSHIP:
        raise OSError("Darwin filesystem ignores ownership")


def _validate_darwin_descriptor_security(descriptor: int) -> None:
    """Reject Darwin descriptors whose ownership boundary is not exclusive."""

    if sys.platform != "darwin":
        return

    api = _darwin_security_api()
    filesystem = _DarwinStatFs()
    try:
        ctypes.set_errno(0)
        statfs_result = int(api.fstatfs(descriptor, ctypes.byref(filesystem)))
    except Exception:
        raise OSError("Darwin filesystem policy cannot be verified") from None
    if statfs_result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, "Darwin filesystem policy cannot be verified")
    _validate_darwin_mount_flags(int(filesystem.f_flags))

    try:
        ctypes.set_errno(0)
        acl = api.acl_get_fd_np(descriptor, _DARWIN_ACL_TYPE_EXTENDED)
        acl_error = ctypes.get_errno()
    except Exception:
        raise OSError("Darwin extended ACL cannot be verified") from None
    if not acl:
        if acl_error == errno.ENOENT:
            return
        error_number = acl_error or errno.EIO
        raise OSError(error_number, "Darwin extended ACL cannot be verified")

    entry = ctypes.c_void_p()
    entry_result: int | None = None
    entry_error = 0
    entry_failed = False
    free_result: int | None = None
    free_failed = False
    try:
        try:
            ctypes.set_errno(0)
            entry_result = int(
                api.acl_get_entry(
                    acl,
                    _DARWIN_ACL_FIRST_ENTRY,
                    ctypes.byref(entry),
                )
            )
            entry_error = ctypes.get_errno()
        except Exception:
            entry_failed = True
    finally:
        try:
            ctypes.set_errno(0)
            free_result = int(api.acl_free(acl))
        except Exception:
            free_failed = True

    if free_failed or free_result != 0:
        raise OSError("Darwin extended ACL release failed")
    if entry_failed:
        raise OSError("Darwin extended ACL cannot be parsed")
    if entry_result == 0:
        raise OSError("Darwin extended ACL is not owner-private")
    if entry_result != -1 or entry_error != errno.EINVAL or entry.value is not None:
        raise OSError("Darwin extended ACL cannot be parsed")


def _validate_posix_named_regular(
    root_descriptor: int,
    name: str,
    descriptor: int,
    *,
    expected_size: int,
) -> os.stat_result:
    details = _validate_posix_regular(descriptor, expected_size=expected_size)
    current = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    if not stat.S_ISREG(current.st_mode) or (details.st_dev, details.st_ino) != (
        current.st_dev,
        current.st_ino,
    ):
        raise OSError("secret key path identity changed")
    return details


def _posix_file_marker(details: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _is_posix_key_temporary_name(name: str, key_name: str) -> bool:
    prefix = f".{key_name}."
    suffix = ".tmp"
    if not name.startswith(prefix) or not name.endswith(suffix):
        return False
    token = name[len(prefix) : -len(suffix)]
    return len(token) == _POSIX_TEMP_TOKEN_CHARACTERS and all(
        character in "0123456789abcdef" for character in token
    )


def _sync_posix_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        unsupported = {
            errno.EBADF,
            errno.EINVAL,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }
        if error.errno not in unsupported:
            raise


def _read_exact(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("secret key write did not progress")
        view = view[written:]


def _posix_lock(descriptor: int) -> None:
    import fcntl

    deadline = time.monotonic() + _POSIX_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            operation = int(fcntl.LOCK_EX) | int(fcntl.LOCK_NB)  # type: ignore[attr-defined]
            fcntl.flock(descriptor, operation)  # type: ignore[attr-defined]
            return
        except OSError as error:
            if error.errno not in {errno.EACCES, errno.EAGAIN, errno.EINTR}:
                raise
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OSError("secret key initialization lock timed out")
        time.sleep(min(_POSIX_LOCK_POLL_SECONDS, remaining))


def _posix_unlock(descriptor: int) -> None:
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)  # type: ignore[attr-defined]


def _purpose_digest(purpose: str) -> bytes:
    if not isinstance(purpose, str) or not purpose:
        raise SecretStoreError("Secret purpose is invalid.")
    try:
        encoded = purpose.encode("utf-8", errors="strict")
    except UnicodeError:
        raise SecretStoreError("Secret purpose is invalid.") from None
    if len(encoded) > _MAX_PURPOSE_BYTES or any(
        character < " " or character == "\x7f" for character in purpose
    ):
        raise SecretStoreError("Secret purpose is invalid.")
    return hashlib.sha256(_PURPOSE_DOMAIN + encoded).digest()


def _validated_plaintext(plaintext: bytes) -> bytes:
    if not isinstance(plaintext, bytes) or len(plaintext) > _MAX_PLAINTEXT_BYTES:
        raise SecretStoreError("Secret value is invalid or exceeds the protection limit.")
    return plaintext


def _encode_envelope(provider: int, payload: bytes) -> bytes:
    if not payload or len(payload) > _MAX_PROTECTED_PAYLOAD_BYTES:
        raise SecretStoreError("Secret protection failed.")
    return (
        _ENVELOPE_HEADER.pack(
            _ENVELOPE_MAGIC,
            _ENVELOPE_VERSION,
            provider,
            len(payload),
        )
        + payload
    )


def _decode_envelope(opaque: bytes, *, expected_provider: int) -> bytes:
    if (
        not isinstance(opaque, bytes)
        or len(opaque) < _ENVELOPE_HEADER.size
        or len(opaque) > _MAX_OPAQUE_BYTES
    ):
        raise SecretStoreError("Protected secret is invalid or cannot be opened.")
    try:
        magic, version, provider, payload_size = _ENVELOPE_HEADER.unpack_from(opaque)
    except struct.error:
        raise SecretStoreError("Protected secret is invalid or cannot be opened.") from None
    payload = opaque[_ENVELOPE_HEADER.size :]
    if (
        magic != _ENVELOPE_MAGIC
        or version != _ENVELOPE_VERSION
        or provider != expected_provider
        or payload_size != len(payload)
        or not payload
    ):
        raise SecretStoreError("Protected secret is invalid or cannot be opened.")
    return payload


def _blob_from_bytes(value: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    # Allocate one byte for an empty input while preserving the native cbData=0.
    backing = ctypes.create_string_buffer(value, max(1, len(value)))
    pointer = ctypes.cast(backing, ctypes.POINTER(ctypes.c_ubyte))
    return _DataBlob(len(value), pointer), backing


__all__ = [
    "InMemorySecretProvider",
    "PosixOwnerPrivateSecretProvider",
    "SecretProvider",
    "SecretStoreError",
    "WindowsDPAPISecretProvider",
    "default_secret_provider",
]
