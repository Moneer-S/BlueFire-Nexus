"""Controller process custody for the installed, test-only Caido wire provider.

The listener comes from the native worker's authenticated descriptor transfer.
This owner never creates a network endpoint and never supplies target authority.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import select
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .engine_installed_v2_authority import InstalledStrixV2AuthorityGuard
from .test_caido_protocol_provider import (
    AUDIT_SCHEMA,
    MAX_AUDIT_BYTES,
    READY_SCHEMA,
    SO_NETNS_COOKIE,
    TestCaidoAuditRecord,
    TestCaidoProviderManifest,
    _canonical,
    provider_source_digest,
)
from .util import content_hash

_READY_LIMIT = 4_096
_MANIFEST_PIPE_LIMIT = 4_096
_START_TIMEOUT = 10.0
_DRAIN_TIMEOUT = 5.0
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BOOT_ID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


class TestCaidoProcessError(RuntimeError):
    """Stable, secret-free provider process failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Test Caido provider process failed: " + code)


@dataclass(frozen=True, slots=True)
class TestCaidoProcessDrainReceipt:
    """Provider-only clearance; worker listener and target require separate proof."""

    attempt_id: str
    provider_identity_ref: str
    provider_source_digest: str
    listener_ref: str
    ready_ref: str
    process_identity_ref: str
    resource_owner_ref: str
    audit_digest: str
    audit_record_count: int
    provider_process_exited: bool = True
    provider_state_drained: bool = True
    test_provider: bool = True
    live_caido_proof: bool = False
    target_cleanup_verified: bool = False

    @property
    def evidence_ref(self) -> str:
        return content_hash(
            {"schema_version": "bluefire.test-caido-process-drain.v1", **asdict(self)}
        )


@dataclass(frozen=True, slots=True)
class TestCaidoProcessActivationReceipt:
    """Release of the provider serve gate after protected active authority."""

    attempt_id: str
    provider_identity_ref: str
    ready_ref: str
    authority_snapshot_ref: str
    resource_owner_ref: str
    test_provider: bool = True
    live_caido_proof: bool = False


@dataclass(frozen=True, slots=True)
class TestCaidoProcessReadyReceipt:
    """Exact child-ready line joined to retained controller process custody."""

    attempt_id: str
    provider_identity_ref: str
    listener_ref: str
    provider_source_digest: str
    process_identity_ref: str
    resource_owner_ref: str
    ready_ref: str
    test_provider: bool = True
    live_caido_proof: bool = False

    @property
    def evidence_ref(self) -> str:
        return content_hash(
            {"schema_version": "bluefire.test-caido-process-ready.v1", **asdict(self)}
        )


def _owner_binding(
    *,
    prelaunch_ref: str,
    resource_transaction_ref: str,
    resource_owner_binding: tuple[str, str, str],
) -> str:
    if (
        type(prelaunch_ref) is not str
        or _DIGEST.fullmatch(prelaunch_ref) is None
        or type(resource_transaction_ref) is not str
        or _DIGEST.fullmatch(resource_transaction_ref) is None
        or type(resource_owner_binding) is not tuple
        or len(resource_owner_binding) != 3
        or not all(type(value) is str for value in resource_owner_binding)
    ):
        raise TestCaidoProcessError("resource_owner_binding_invalid")
    expected_binding = content_hash(
        {
            "schema_version": "bluefire.installed-strix-v2-prelaunch-resource-binding.v1",
            "prelaunch_ref": prelaunch_ref,
            "role": "caido_channel",
        }
    )
    expected_owner = content_hash(
        {
            "schema_version": "bluefire.installed-strix-v2-resource-owner.v1",
            "transaction_ref": resource_transaction_ref,
            "role": "caido_channel",
            "binding_ref": expected_binding,
        }
    )
    if resource_owner_binding != ("caido_channel", expected_binding, expected_owner):
        raise TestCaidoProcessError("resource_owner_binding_invalid")
    return expected_owner


@dataclass(frozen=True, slots=True)
class TestCaidoProcessIdentity:
    """Controller-host PID and pinned audit inode retained before ready."""

    pid: int
    start_ticks: int
    boot_id: str
    audit_device: int
    audit_inode: int

    def __post_init__(self) -> None:
        if (
            type(self.pid) is not int
            or self.pid <= 0
            or type(self.start_ticks) is not int
            or self.start_ticks <= 0
            or type(self.boot_id) is not str
            or _BOOT_ID.fullmatch(self.boot_id) is None
            or type(self.audit_device) is not int
            or self.audit_device < 0
            or type(self.audit_inode) is not int
            or self.audit_inode <= 0
        ):
            raise TestCaidoProcessError("process_identity_invalid")

    @property
    def identity_ref(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.test-caido-process-identity.v1",
                "pid": self.pid,
                "start_ticks": self.start_ticks,
                "boot_id": self.boot_id,
                "audit_device": self.audit_device,
                "audit_inode": self.audit_inode,
            }
        )


def _close(descriptor: int | None) -> None:
    if descriptor is not None:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _verify_listener(descriptor: int, manifest: TestCaidoProviderManifest) -> None:
    binding = manifest.binding
    if type(descriptor) is not int or descriptor < 3:
        raise TestCaidoProcessError("listener_descriptor_invalid")
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISSOCK(info.st_mode):
            raise OSError
        duplicate = os.dup(descriptor)
        try:
            listener = socket.socket(fileno=duplicate)
        except (OSError, ValueError):
            _close(duplicate)
            raise
        try:
            local = listener.getsockname()
            accepting = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            cookie = listener.getsockopt(socket.SOL_SOCKET, SO_NETNS_COOKIE, 8)
            valid = (
                listener.family == binding.family
                and listener.type == binding.socket_type
                and tuple(local[:2]) == (binding.host, binding.port)
                and accepting == 1
                and info.st_dev == binding.listener_device
                and info.st_ino == binding.listener_inode
                and len(cookie) == 8
                and int.from_bytes(cookie, sys.byteorder) == binding.netns_cookie
            )
        finally:
            listener.close()
    except (OSError, ValueError):
        raise TestCaidoProcessError("listener_custody_invalid") from None
    if not valid:
        raise TestCaidoProcessError("listener_custody_invalid")


def _verify_audit(descriptor: int) -> None:
    if type(descriptor) is not int or descriptor < 3:
        raise TestCaidoProcessError("audit_descriptor_invalid")
    try:
        info = os.fstat(descriptor)
        fcntl = importlib.import_module("fcntl")
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        get_euid = getattr(os, "geteuid", None)
        if (
            not stat.S_ISREG(info.st_mode)
            or not callable(get_euid)
            or info.st_uid != get_euid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or info.st_size != 0
            or os.lseek(descriptor, 0, os.SEEK_CUR) != 0
            or (flags & (os.O_WRONLY | os.O_RDWR)) != os.O_RDWR
            or not flags & os.O_APPEND
        ):
            raise OSError
    except (OSError, ImportError):
        raise TestCaidoProcessError("audit_descriptor_invalid") from None


def _decode_object(raw: bytes) -> Mapping[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError):
        raise TestCaidoProcessError("provider_record_invalid") from None
    try:
        canonical = _canonical(value)
    except (TypeError, ValueError):
        raise TestCaidoProcessError("provider_record_invalid") from None
    if not isinstance(value, dict) or canonical != raw:
        raise TestCaidoProcessError("provider_record_invalid")
    return value


def _read_ready(descriptor: int, process: subprocess.Popen[bytes], timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TestCaidoProcessError("provider_ready_timeout")
        readable, _, _ = select.select([descriptor], [], [], min(remaining, 0.1))
        if not readable:
            if process.poll() is not None:
                raise TestCaidoProcessError("provider_exited_before_ready")
            continue
        block = os.read(descriptor, _READY_LIMIT + 1 - len(data))
        if not block:
            return bytes(data)
        data.extend(block)
        if len(data) > _READY_LIMIT:
            raise TestCaidoProcessError("provider_ready_invalid")


def reopen_ready(
    *,
    manifest: TestCaidoProviderManifest,
    process_identity: TestCaidoProcessIdentity,
    resource_owner_ref: str,
    ready_payload: bytes,
) -> TestCaidoProcessReadyReceipt:
    """Validate the exact saved ready bytes from a protected owner journal."""

    if (
        type(manifest) is not TestCaidoProviderManifest
        or type(process_identity) is not TestCaidoProcessIdentity
        or type(resource_owner_ref) is not str
        or _DIGEST.fullmatch(resource_owner_ref) is None
        or type(ready_payload) is not bytes
        or not ready_payload.endswith(b"\n")
        or ready_payload.count(b"\n") != 1
        or len(ready_payload) > _READY_LIMIT
    ):
        raise TestCaidoProcessError("provider_ready_invalid")
    ready = _decode_object(ready_payload[:-1])
    if ready != {
        "schema_version": READY_SCHEMA,
        "attempt_id": manifest.binding.attempt_id,
        "provider_identity_ref": manifest.identity_ref,
        "listener_ref": manifest.binding.listener_ref,
        "provider_source_digest": manifest.provider_source_digest,
        "test_provider": True,
        "live_caido_proof": False,
        "production_eligible": False,
        "ready": True,
    }:
        raise TestCaidoProcessError("provider_ready_invalid")
    return TestCaidoProcessReadyReceipt(
        attempt_id=manifest.binding.attempt_id,
        provider_identity_ref=manifest.identity_ref,
        listener_ref=manifest.binding.listener_ref,
        provider_source_digest=manifest.provider_source_digest,
        process_identity_ref=process_identity.identity_ref,
        resource_owner_ref=resource_owner_ref,
        ready_ref=content_hash(ready),
    )


def _read_audit(descriptor: int, manifest: TestCaidoProviderManifest) -> tuple[str, int]:
    try:
        size = os.fstat(descriptor).st_size
        if not 0 < size <= MAX_AUDIT_BYTES:
            raise OSError
        os.lseek(descriptor, 0, os.SEEK_SET)
        payload = bytearray()
        while len(payload) < size:
            block = os.read(descriptor, min(8192, size - len(payload)))
            if not block:
                raise OSError
            payload.extend(block)
    except OSError:
        raise TestCaidoProcessError("provider_audit_unknown") from None
    if not payload.endswith(b"\n") or b"bft_" in payload or b"Bearer " in payload:
        raise TestCaidoProcessError("provider_audit_invalid")
    rows = payload[:-1].split(b"\n")
    expected = set(TestCaidoAuditRecord.__dataclass_fields__)
    for sequence, raw in enumerate(rows, 1):
        row = _decode_object(raw)
        if (
            set(row) != expected
            or type(row["sequence"]) is not int
            or row["sequence"] != sequence
            or row["schema_version"] != AUDIT_SCHEMA
            or row["attempt_id"] != manifest.binding.attempt_id
            or row["provider_identity_ref"] != manifest.identity_ref
            or row["test_provider"] is not True
            or row["live_caido_proof"] is not False
        ):
            raise TestCaidoProcessError("provider_audit_invalid")
    final = _decode_object(rows[-1])
    if (
        final["operation"] != "lifecycle"
        or final["outcome"] != "drained"
        or final["state"] != "drained"
    ):
        raise TestCaidoProcessError("provider_drain_unverified")
    return "sha256:" + hashlib.sha256(payload).hexdigest(), len(rows)


def _boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as source:
            value = source.read(40).strip()
    except OSError:
        raise TestCaidoProcessError("process_identity_unknown") from None
    if _BOOT_ID.fullmatch(value) is None:
        raise TestCaidoProcessError("process_identity_unknown")
    return value


def _start_ticks(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as source:
            value = source.read(4096)
    except FileNotFoundError:
        return None
    except OSError:
        raise TestCaidoProcessError("process_identity_unknown") from None
    right = value.rfind(")")
    fields = value[right + 2 :].split() if right >= 0 else []
    try:
        if fields[0] in {"Z", "X"}:
            return None
        result = int(fields[19])  # field 22, after pid and parenthesized comm
    except (IndexError, ValueError):
        raise TestCaidoProcessError("process_identity_unknown") from None
    return result


def _process_identity(pid: int, audit_fd: int) -> TestCaidoProcessIdentity:
    start = _start_ticks(pid)
    if start is None:
        raise TestCaidoProcessError("provider_exited_before_ready")
    info = os.fstat(audit_fd)
    return TestCaidoProcessIdentity(
        pid=pid,
        start_ticks=start,
        boot_id=_boot_id(),
        audit_device=info.st_dev,
        audit_inode=info.st_ino,
    )


def reopen_drain(
    *,
    manifest: TestCaidoProviderManifest,
    process_identity: TestCaidoProcessIdentity,
    ready_ref: str,
    resource_owner_ref: str,
    audit_fd: int,
) -> TestCaidoProcessDrainReceipt:
    """Verify a retained provider drain after a controller restart.

    The caller must reopen the exact private audit inode through its retained
    resource journal. Native listener and target absence remain separate.
    """

    if sys.platform != "linux" or type(manifest) is not TestCaidoProviderManifest:
        raise TestCaidoProcessError("reopen_binding_invalid")
    if (
        type(process_identity) is not TestCaidoProcessIdentity
        or type(ready_ref) is not str
        or _DIGEST.fullmatch(ready_ref) is None
        or type(resource_owner_ref) is not str
        or _DIGEST.fullmatch(resource_owner_ref) is None
    ):
        raise TestCaidoProcessError("reopen_binding_invalid")
    if process_identity.boot_id == _boot_id():
        current = _start_ticks(process_identity.pid)
        if current == process_identity.start_ticks:
            raise TestCaidoProcessError("provider_still_live")
    try:
        info = os.fstat(audit_fd)
        get_euid = getattr(os, "geteuid", None)
        if (
            not stat.S_ISREG(info.st_mode)
            or not callable(get_euid)
            or info.st_uid != get_euid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or info.st_dev != process_identity.audit_device
            or info.st_ino != process_identity.audit_inode
        ):
            raise OSError
    except OSError:
        raise TestCaidoProcessError("provider_audit_unknown") from None
    digest, count = _read_audit(audit_fd, manifest)
    return TestCaidoProcessDrainReceipt(
        attempt_id=manifest.binding.attempt_id,
        provider_identity_ref=manifest.identity_ref,
        provider_source_digest=manifest.provider_source_digest,
        listener_ref=manifest.binding.listener_ref,
        ready_ref=ready_ref,
        process_identity_ref=process_identity.identity_ref,
        resource_owner_ref=resource_owner_ref,
        audit_digest=digest,
        audit_record_count=count,
    )


class InstalledStrixV2CaidoProvider:
    """Own one fixed Test provider process and its controller EOF lease."""

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        owner_write_fd: int,
        audit_read_fd: int,
        manifest: TestCaidoProviderManifest,
        ready_ref: str,
        ready_payload: bytes,
        process_identity: TestCaidoProcessIdentity,
        activation_write_fd: int,
        prelaunch_ref: str,
        resource_owner_ref: str,
    ) -> None:
        self._process = process
        self._owner_write_fd: int | None = owner_write_fd
        self._audit_read_fd: int | None = audit_read_fd
        self._manifest = manifest
        self._ready_ref = ready_ref
        self._ready_payload = ready_payload
        self._process_identity = process_identity
        self._activation_write_fd: int | None = activation_write_fd
        self._prelaunch_ref = prelaunch_ref
        self._resource_owner_ref = resource_owner_ref
        self._activation: TestCaidoProcessActivationReceipt | None = None
        self._receipt: TestCaidoProcessDrainReceipt | None = None
        self._lock = threading.RLock()

    @classmethod
    def start(
        cls,
        *,
        manifest: TestCaidoProviderManifest,
        listener_fd: int,
        audit_fd: int,
        prelaunch_ref: str,
        resource_transaction_ref: str,
        resource_owner_binding: tuple[str, str, str],
        readiness_timeout: float = _START_TIMEOUT,
    ) -> InstalledStrixV2CaidoProvider:
        if sys.platform != "linux":
            raise TestCaidoProcessError("platform_unsupported")
        if type(manifest) is not TestCaidoProviderManifest:
            raise TestCaidoProcessError("manifest_invalid")
        if manifest.provider_source_digest != provider_source_digest():
            raise TestCaidoProcessError("provider_source_changed")
        if not 0 < readiness_timeout <= _START_TIMEOUT:
            raise TestCaidoProcessError("readiness_bound_invalid")
        if listener_fd == audit_fd:
            raise TestCaidoProcessError("descriptor_alias_refused")
        resource_owner_ref = _owner_binding(
            prelaunch_ref=prelaunch_ref,
            resource_transaction_ref=resource_transaction_ref,
            resource_owner_binding=resource_owner_binding,
        )
        _verify_listener(listener_fd, manifest)
        _verify_audit(audit_fd)
        payload = _canonical(manifest.as_mapping())
        if len(payload) > _MANIFEST_PIPE_LIMIT:
            raise TestCaidoProcessError("manifest_bound")

        manifest_read = manifest_write = ready_read = ready_write = None
        owner_read = owner_write = child_listener = child_audit = audit_read = None
        activate_read = activate_write = None
        process: subprocess.Popen[bytes] | None = None
        try:
            manifest_read, manifest_write = os.pipe2(os.O_CLOEXEC)
            ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
            owner_read, owner_write = os.pipe2(os.O_CLOEXEC)
            activate_read, activate_write = os.pipe2(os.O_CLOEXEC)
            child_listener = os.dup(listener_fd)
            child_audit = os.dup(audit_fd)
            audit_read = os.dup(audit_fd)
            argv = (
                sys.executable,
                "-I",
                "-m",
                "bluefire.test_caido_protocol_provider",
                "--manifest-fd",
                str(manifest_read),
                "--listener-fd",
                str(child_listener),
                "--audit-fd",
                str(child_audit),
                "--ready-fd",
                str(ready_write),
                "--owner-fd",
                str(owner_read),
                "--activate-fd",
                str(activate_read),
            )
            process = subprocess.Popen(  # nosec B603 - fixed installed module, no shell/ambient env
                argv,
                pass_fds=(
                    manifest_read,
                    child_listener,
                    child_audit,
                    ready_write,
                    owner_read,
                    activate_read,
                ),
                close_fds=True,
                cwd="/",
                env={"LANG": "C.UTF-8"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                umask=0o077,
            )
            process_identity = _process_identity(process.pid, audit_fd)
            _close(manifest_read)
            _close(ready_write)
            _close(owner_read)
            _close(child_listener)
            _close(child_audit)
            _close(activate_read)
            manifest_read = ready_write = owner_read = child_listener = child_audit = None
            activate_read = None
            remaining = memoryview(payload)
            while remaining:
                count = os.write(manifest_write, remaining)
                if count <= 0:
                    raise TestCaidoProcessError("manifest_delivery_unknown")
                remaining = remaining[count:]
            _close(manifest_write)
            manifest_write = None
            raw = _read_ready(ready_read, process, readiness_timeout)
            _close(ready_read)
            ready_read = None
            ready = reopen_ready(
                manifest=manifest,
                process_identity=process_identity,
                resource_owner_ref=resource_owner_ref,
                ready_payload=raw,
            )
            if process.poll() is not None:
                raise TestCaidoProcessError("provider_ready_invalid")
            if owner_write is None or audit_read is None or activate_write is None:
                raise TestCaidoProcessError("provider_launch_unknown")
            result = cls(
                process=process,
                owner_write_fd=owner_write,
                audit_read_fd=audit_read,
                manifest=manifest,
                ready_ref=ready.ready_ref,
                ready_payload=raw,
                process_identity=process_identity,
                activation_write_fd=activate_write,
                prelaunch_ref=prelaunch_ref,
                resource_owner_ref=resource_owner_ref,
            )
            owner_write = audit_read = activate_write = None
            return result
        except Exception as exc:
            _close(owner_write)
            _close(activate_write)
            _close(manifest_write)
            manifest_write = None
            _close(ready_read)
            ready_read = None
            if process is not None:
                try:
                    process.wait(timeout=_DRAIN_TIMEOUT)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=_DRAIN_TIMEOUT)
            if isinstance(exc, TestCaidoProcessError):
                raise
            raise TestCaidoProcessError("provider_launch_unknown") from None
        finally:
            for descriptor in (
                manifest_read,
                manifest_write,
                ready_read,
                ready_write,
                owner_read,
                owner_write,
                activate_read,
                activate_write,
                child_listener,
                child_audit,
                audit_read,
            ):
                _close(descriptor)

    @property
    def ready_ref(self) -> str:
        return self._ready_ref

    @property
    def ready_payload(self) -> bytes:
        """Canonical child line to persist before releasing the serve gate."""

        return self._ready_payload

    @property
    def ready_receipt(self) -> TestCaidoProcessReadyReceipt:
        return reopen_ready(
            manifest=self._manifest,
            process_identity=self._process_identity,
            resource_owner_ref=self._resource_owner_ref,
            ready_payload=self._ready_payload,
        )

    @property
    def provider_identity_ref(self) -> str:
        return self._manifest.identity_ref

    @property
    def mode(self) -> str:
        return "test_protocol_provider"

    @property
    def test_provider(self) -> bool:
        return True

    @property
    def live_caido_proof(self) -> bool:
        return False

    @property
    def cleanup_uncertain(self) -> bool:
        with self._lock:
            return self._receipt is None and self._process.poll() is not None

    @property
    def process_identity(self) -> TestCaidoProcessIdentity:
        return self._process_identity

    @property
    def activation_receipt(self) -> TestCaidoProcessActivationReceipt | None:
        return self._activation

    def activate(
        self, authority_guard: InstalledStrixV2AuthorityGuard
    ) -> TestCaidoProcessActivationReceipt:
        """Release the one-use serve gate only after retained V2 active state."""

        with self._lock:
            if self._activation is not None:
                return self._activation
            if (
                type(authority_guard) is not InstalledStrixV2AuthorityGuard
                or self._activation_write_fd is None
                or self._owner_write_fd is None
            ):
                raise TestCaidoProcessError("provider_activation_refused")
            active = getattr(authority_guard, "require_active", None)
            if not callable(active):
                raise TestCaidoProcessError("provider_activation_unavailable")
            try:
                snapshot = active()
                activation = snapshot.activation
                admitted = snapshot.admission.to_dict()
                valid = (
                    snapshot.prelaunch_ref == self._prelaunch_ref
                    and activation.claim_ref == self._manifest.accepted_claim_digest
                    and activation.admission_ref == self._manifest.runtime_admission_digest
                    and activation.controlled_profile_ref
                    == self._manifest.controlled_profile_digest
                    and admitted["delegation_digest"] == self._manifest.authorization_digest
                    and activation.caido_mode == "test_protocol_provider"
                    and activation.caido_test_provider is True
                    and activation.caido_provider_identity_ref == self._manifest.identity_ref
                    and dict(activation.role_bindings)["caido_channel"]
                    == self._manifest.identity_ref
                )
            except Exception as exc:
                raise TestCaidoProcessError("provider_activation_unavailable") from exc
            if not valid:
                raise TestCaidoProcessError("provider_activation_refused")
            try:
                if (
                    self._process.poll() is not None
                    or os.write(self._activation_write_fd, b"\x01") != 1
                ):
                    raise OSError
            except OSError:
                raise TestCaidoProcessError("provider_activation_unknown") from None
            finally:
                _close(self._activation_write_fd)
                self._activation_write_fd = None
            self._activation = TestCaidoProcessActivationReceipt(
                attempt_id=self._manifest.binding.attempt_id,
                provider_identity_ref=self._manifest.identity_ref,
                ready_ref=self._ready_ref,
                authority_snapshot_ref=snapshot.snapshot_ref,
                resource_owner_ref=self._resource_owner_ref,
            )
            return self._activation

    def cancel(self, *, timeout: float = _DRAIN_TIMEOUT) -> TestCaidoProcessDrainReceipt:
        with self._lock:
            if self._receipt is not None:
                return self._receipt
            if not 0 < timeout <= _DRAIN_TIMEOUT:
                raise TestCaidoProcessError("drain_bound_invalid")
            _close(self._owner_write_fd)
            _close(self._activation_write_fd)
            self._owner_write_fd = None
            self._activation_write_fd = None
            try:
                code = self._process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=_DRAIN_TIMEOUT)
                raise TestCaidoProcessError("provider_drain_timeout") from None
            if code != 0:
                raise TestCaidoProcessError("provider_exit_unknown")
            if self._audit_read_fd is None:
                raise TestCaidoProcessError("provider_audit_unknown")
            digest, count = _read_audit(self._audit_read_fd, self._manifest)
            _close(self._audit_read_fd)
            self._audit_read_fd = None
            self._receipt = TestCaidoProcessDrainReceipt(
                attempt_id=self._manifest.binding.attempt_id,
                provider_identity_ref=self._manifest.identity_ref,
                provider_source_digest=self._manifest.provider_source_digest,
                listener_ref=self._manifest.binding.listener_ref,
                ready_ref=self._ready_ref,
                process_identity_ref=self._process_identity.identity_ref,
                resource_owner_ref=self._resource_owner_ref,
                audit_digest=digest,
                audit_record_count=count,
            )
            return self._receipt

    def close(self) -> None:
        self.cancel()


__all__ = [
    "InstalledStrixV2CaidoProvider",
    "TestCaidoProcessDrainReceipt",
    "TestCaidoProcessActivationReceipt",
    "TestCaidoProcessReadyReceipt",
    "TestCaidoProcessError",
    "TestCaidoProcessIdentity",
    "reopen_drain",
    "reopen_ready",
]
