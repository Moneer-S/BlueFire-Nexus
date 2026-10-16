"""One supervised exchange for a transferred owned suspended Windows child.

The caller transfers the Popen, its actual process Handle and the supplied Job's
cleanup responsibility. It must already own authenticated original admission,
the pinned child image and private pipes. No process, Job or credential is
created here. Identity helpers borrow that exact Handle; no PID is reopened.
Unresolved cleanup retains the same owner, and cleanup retry cannot resume or
deliver another Begin. A native observation never settles a business outcome.
"""

from __future__ import annotations

import struct
import subprocess  # nosec B404 - types only; no process creation
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import IO, Callable, Literal, cast

from . import windows_file_access_child as child
from . import windows_file_access_native_wire as wire
from ._windows_file_access_cleanup_proof import SCHEMA as CLEANUP_SCHEMA
from ._windows_file_access_cleanup_proof import OwnedCleanupReceipt
from .runner_windows_containment import WindowsJobContainment
from .util import canonical_json_bytes, content_hash

Issue = Literal[
    "cancelled",
    "deadline",
    "binding_refused",
    "admission_refused",
    "begin_refused",
    "protocol_refused",
    "output_bound",
    "unexpected_stderr",
    "worker_failed",
    "evidence_refused",
    "cleanup_unknown",
]
PublicEvidenceSink = Callable[
    [Literal["packet", "ready", "terminal"], bytes, int | None, datetime], None
]
_JOIN_SECONDS = 1.0
_POLL_SECONDS = 0.01


class _Protocol(Enum):
    READER_V1 = "reader_v1"
    PAIR_V2 = "pair_v2"
    CORRECTION_V3 = "correction_v3"


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _monotonic() -> float:
    return time.monotonic()


def _wipe(value: object) -> None:
    if type(value) is bytearray:
        value[:] = b"\0" * len(value)


@dataclass(frozen=True, slots=True)
class ProcessOutcome:
    projection: wire.NativeProjection | None = field(repr=False)
    dispatch: Literal["not_started", "attempted", "unknown"]
    cleanup: Literal["verified", "unknown"]
    issue: Issue | None
    cleanup_owner: CleanupOwner | None = field(repr=False)
    cleanup_receipt: OwnedCleanupReceipt | None = field(default=None, repr=False)
    settled: bool = field(default=False, init=False)


class _Stopped(RuntimeError):
    pass


class CleanupOwner:
    """Own transferred resources until positively verified closure, not replay."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        job: int,
        containment: WindowsJobContainment,
        packet: wire.PreparedPacket,
        original: wire.OriginalReservation,
        revalidate: Callable[[], None],
        producer: Callable[[bytearray], bytearray],
        cancellation: threading.Event,
        evidence_sink: PublicEvidenceSink,
        *,
        _protocol: _Protocol = _Protocol.READER_V1,
        release_launch_resources: Callable[[], bool] | None = None,
    ) -> None:
        self.process, self.job, self.containment = process, job, containment
        self.packet, self.original = packet, original
        self.revalidate, self.producer, self.cancellation = revalidate, producer, cancellation
        self.evidence_sink = evidence_sink
        self.protocol = _protocol
        self.release_launch_resources = release_launch_resources
        self.handle = getattr(process, "_handle", None)
        self.pid = process.pid
        self.stopped, self.done = threading.Event(), threading.Event()
        self.stderr_done = threading.Event()
        self.lock, self.cleanup_lock = threading.Lock(), threading.Lock()
        self.generation: child.WindowsPeerGeneration | None = None
        self.adoption_attempted = False
        self.adopted = self.assigned = self.began = self.consumed = False
        self.issue: Issue | None = None
        self.ready: bytes | None = None
        self.terminal: bytes | None = None
        self.exchange: threading.Thread | None = None
        self.errors: threading.Thread | None = None
        self.closer: threading.Thread | None = None
        self.job_drained = self.job_closed = self.parent_exited = self.start_handles_closed = False
        self.handle_closed = self.handle_ambiguous = self.verified = False
        self.launch_resources_closed = release_launch_resources is None
        self.pipe_closed: set[str] = set()
        self.pipe_ambiguous: set[str] = set()
        self.stdout_count = 0
        self._last_wall_clock: datetime | None = None
        self._child_generation_captured = False
        self._supported_terminal_returncode: int | None = None
        self._cleanup_receipt: OwnedCleanupReceipt | None = None
        self._receipt_finalized = False

    def __repr__(self) -> str:
        return "<WindowsReadCleanupOwner retained>"

    def _fail(self, issue: Issue) -> None:
        with self.lock:
            self.issue = self.issue or issue

    def _clock(self) -> datetime:
        value = _utc()
        try:
            observed = wire._clock(value).astimezone(timezone.utc)
        except Exception:
            return value
        with self.lock:
            if self._last_wall_clock is None or observed > self._last_wall_clock:
                self._last_wall_clock = observed
        return value

    @property
    def cleanup_receipt(self) -> OwnedCleanupReceipt | None:
        return self._cleanup_receipt

    def _handle_current(self) -> int:
        if (
            self.handle is not getattr(self.process, "_handle", None)
            or type(self.pid) is not int
            or not 0 < self.pid <= 0xFFFFFFFF
            or type(self.process.pid) is not int
            or self.process.pid != self.pid
            or not isinstance(self.handle, int)
            or isinstance(self.handle, bool)
            or not 0 < int(self.handle) < (1 << (struct.calcsize("P") * 8)) - 0x10000
            or getattr(self.handle, "closed", None) is not False
            or not callable(getattr(self.handle, "Close", None))
        ):
            raise _Stopped()
        return int(self.handle)

    def current(self) -> None:
        if self.stopped.is_set() or self.issue is not None:
            raise _Stopped()
        try:
            self._handle_current()
        except Exception:
            self._fail("binding_refused")
            raise _Stopped() from None
        if self.cancellation.is_set():
            self._fail("cancelled")
            raise _Stopped()
        try:
            wire._prepared(self.packet, self._clock(), _monotonic())
        except wire.NativeWireError:
            self._fail("deadline")
            raise _Stopped() from None

    def _identity(self) -> None:
        if self.generation is None:
            raise _Stopped()
        child.require_retained_child(self._handle_current(), self.job, expected=self.generation)
        self.current()

    def _retained(self) -> wire.RetainedPacket:
        if self.packet._original != self.original:
            raise _Stopped()
        if self.protocol is _Protocol.CORRECTION_V3:
            return wire.validate_correction_retained_packet(self.original, self.packet._raw)
        if self.protocol is _Protocol.PAIR_V2:
            return wire.validate_pair_retained_packet(self.original, self.packet._raw)
        if self.protocol is _Protocol.READER_V1:
            return wire.validate_retained_packet(self.original, self.packet._raw)
        raise _Stopped()

    def _limits(self) -> dict[str, int]:
        if self.protocol is _Protocol.CORRECTION_V3:
            return cast(
                dict[str, int],
                wire._reservation(self.original, wire._CORRECTION)["manifest"]["limits"],
            )
        if self.protocol is _Protocol.PAIR_V2:
            return cast(
                dict[str, int], wire._reservation(self.original, wire._PAIR)["manifest"]["limits"]
            )
        if self.protocol is _Protocol.READER_V1:
            return cast(dict[str, int], wire._reservation(self.original)["manifest"]["limits"])
        raise _Stopped()

    def _public_frame(self) -> bytes:
        if self.protocol is _Protocol.CORRECTION_V3:
            return wire.correction_public_frame(
                self.packet, clock=self._clock(), monotonic_now=_monotonic()
            )
        if self.protocol is _Protocol.PAIR_V2:
            return wire.pair_public_frame(
                self.packet, clock=self._clock(), monotonic_now=_monotonic()
            )
        return wire.public_frame(self.packet, clock=self._clock(), monotonic_now=_monotonic())

    def _ready(self, retained: wire.RetainedPacket, ready: bytes) -> None:
        if self.protocol is _Protocol.CORRECTION_V3:
            wire.validate_correction_ready(retained, ready)
        elif self.protocol is _Protocol.PAIR_V2:
            wire.validate_pair_ready(retained, ready)
        else:
            wire.validate_ready(retained, ready)

    def _begin_prefix(self) -> bytearray:
        if self.protocol is _Protocol.CORRECTION_V3:
            return wire.correction_begin_prefix(
                self.packet, clock=self._clock(), monotonic_now=_monotonic()
            )
        if self.protocol is _Protocol.PAIR_V2:
            return wire.pair_begin_prefix(
                self.packet, clock=self._clock(), monotonic_now=_monotonic()
            )
        return wire.begin_prefix(self.packet, clock=self._clock(), monotonic_now=_monotonic())

    def _terminal(
        self, retained: wire.RetainedPacket, ready: bytes, terminal: bytes
    ) -> wire.NativeProjection:
        validator = {
            _Protocol.READER_V1: wire.validate_terminal,
            _Protocol.PAIR_V2: wire.validate_pair_terminal,
            _Protocol.CORRECTION_V3: wire.validate_correction_terminal,
        }[self.protocol]
        return validator(
            self.original,
            retained,
            ready,
            terminal,
            clock=self._clock(),
            returncode=self.process.returncode,
        )

    def _write(self, stream: IO[bytes], value: bytes | bytearray) -> None:
        view = memoryview(value)
        while view:
            self.current()
            count = stream.write(view)
            if type(count) is not int or not 0 < count <= len(view):
                raise _Stopped()
            self.current()
            view = view[count:]
        stream.flush()
        self.current()

    def _read_exact(self, stream: IO[bytes], length: int) -> bytes:
        data = bytearray()
        while len(data) < length:
            self.current()
            part = stream.read(length - len(data))
            self.current()
            if type(part) is not bytes or not part or len(part) > length - len(data):
                raise _Stopped()
            data.extend(part)
        return bytes(data)

    def _frame(self, stream: IO[bytes], maximum: int, total: int) -> bytes:
        if self.stdout_count + 4 > total:
            self._fail("output_bound")
            raise _Stopped()
        length = struct.unpack("<I", self._read_exact(stream, 4))[0]
        self.stdout_count += 4
        if not 0 < length <= maximum or self.stdout_count + length > total:
            self._fail("output_bound")
            raise _Stopped()
        data = self._read_exact(stream, length)
        self.stdout_count += length
        return data

    def _close_pipe(self, name: str) -> bool:
        if name in self.pipe_closed:
            return True
        stream = getattr(self.process, name, None)
        if stream is None or name in self.pipe_ambiguous:
            return False
        try:
            stream.close()
            if getattr(stream, "closed", None) is not True:
                return False
            self.pipe_closed.add(name)
            return True
        except Exception:
            if getattr(stream, "closed", None) is True:
                self.pipe_ambiguous.add(name)
            return False

    def _exchange(self) -> None:
        prefix, expected_prefix, private = bytearray(), bytearray(), bytearray()
        phase: Issue = "binding_refused"
        try:
            self.current()
            self._retained()
            self.containment.assign_retained(self.job, self.process)
            self.assigned = True
            self.current()
            self.generation = child.capture_retained_child(
                self._handle_current(), self.job, expected_pid=self.process.pid
            )
            self._child_generation_captured = True
            self.current()
            self.containment.resume_retained(self.process, self.job, self.generation)
            self.current()
            stdin, stdout = self.process.stdin, self.process.stdout
            if stdin is None or stdout is None:
                raise _Stopped()
            phase = "admission_refused"
            self.revalidate()
            self.current()
            public = self._public_frame()
            phase = "evidence_refused"
            self.evidence_sink("packet", self.packet._raw, None, self._clock())
            self.current()
            phase = "protocol_refused"
            self._write(stdin, public)
            phase = "protocol_refused"
            retained = self._retained()
            limits = self._limits()
            ready = self._frame(stdout, wire.READY_MAX, limits["max_stdout_bytes"])
            self._ready(retained, ready)
            self.current()
            phase = "evidence_refused"
            self.evidence_sink("ready", ready, None, self._clock())
            self.current()
            phase = "binding_refused"
            self._identity()
            phase = "admission_refused"
            self.revalidate()
            self.current()
            phase = "begin_refused"
            self._identity()
            prefix = self._begin_prefix()
            if self.consumed:
                raise _Stopped()
            self.consumed = True
            private = self.producer(prefix)
            self.current()
            expected_prefix = self._begin_prefix()
            prefix_end = 4 + len(expected_prefix)
            if type(private) is not bytearray or len(private) < prefix_end + 4:
                raise _Stopped()
            length = struct.unpack_from("<I", private)[0]
            if (
                not len(expected_prefix) + 4 <= length <= wire.BEGIN_MAX
                or len(private) != length + 4
                or private[4:prefix_end] != expected_prefix
            ):
                raise _Stopped()
            units = struct.unpack_from("<H", private, prefix_end)[0]
            if not 1 <= units <= 256 or length != len(expected_prefix) + 2 + 2 * units:
                raise _Stopped()
            _wipe(expected_prefix)
            self._identity()
            self.current()
            phase = "admission_refused"
            self.revalidate()
            self.current()
            self._identity()
            self.current()
            phase = "begin_refused"
            self.began = True
            self._write(stdin, private)
            _wipe(private)
            if not self._close_pipe("stdin"):
                raise _Stopped()
            self.current()
            phase = "protocol_refused"
            terminal = self._frame(stdout, wire.TERMINAL_MAX, limits["max_stdout_bytes"])
            extra = stdout.read(1)
            self.current()
            if type(extra) is not bytes or extra != b"":
                if (
                    type(extra) is bytes
                    and self.stdout_count + len(extra) > limits["max_stdout_bytes"]
                ):
                    self._fail("output_bound")
                raise _Stopped()
            # Persistence participates in the same monitored exchange. An EOF
            # is not an exit or proof that the stderr reader has completed.
            while not self.stderr_done.is_set() or self.process.poll() is None:
                self.current()
                self.stopped.wait(_POLL_SECONDS)
            self.current()
            phase = "worker_failed"
            self._terminal(retained, ready, terminal)
            phase = "evidence_refused"
            self.evidence_sink("terminal", terminal, self.process.returncode, self._clock())
            self.current()
            self.ready, self.terminal = ready, terminal
        except BaseException:
            self._fail(phase)
        finally:
            _wipe(private)
            _wipe(prefix)
            _wipe(expected_prefix)
            self.done.set()

    def _stderr(self) -> None:
        try:
            stream = self.process.stderr
            if stream is None:
                raise _Stopped()
            maximum = self._limits()["max_stderr_bytes"]
            count = 0
            while True:
                part = stream.read(min(4096, maximum + 1 - count))
                if part == b"":
                    return
                if type(part) is not bytes or not part:
                    raise _Stopped()
                count += len(part)
                self._fail("output_bound" if count > maximum else "unexpected_stderr")
                if count > maximum:
                    return
        except BaseException:
            self._fail("protocol_refused")
        finally:
            self.stderr_done.set()

    def _cleanup(self) -> None:
        try:
            usable = False
            try:
                self._handle_current()
                usable = True
            except Exception:
                pass
            if usable and not self.parent_exited:
                try:
                    if self.process.poll() is None:
                        self.process.kill()
                    self.process.wait(timeout=5)
                    self._record_exit(self.process.poll())
                except Exception:
                    pass
            # Parent stop failures cannot skip drainage of the adopted exact Job.
            # On adoption collision, never fall back to legacy PID-based cleanup.
            if self.adopted and not self.job_drained:
                try:
                    self.job_drained = (
                        self.containment.drain_retained(self.process, self.job) is True
                    )
                except Exception:
                    pass
            if usable and not self.parent_exited:
                try:
                    self._handle_current()
                    self.process.wait(timeout=5)
                    self._record_exit(self.process.poll())
                except Exception:
                    pass
            for thread in (self.exchange, self.errors):
                if thread is not None and thread.ident is not None:
                    thread.join(timeout=_JOIN_SECONDS)
                if thread is not None and thread.is_alive():
                    return
            if not self.job_drained or not self.parent_exited:
                return
            if not self.job_closed:
                self.job_closed = self.containment.finish_retained(self.process, self.job) is True
            if not self.job_closed:
                return
            if not self.start_handles_closed:
                self.start_handles_closed = (
                    self.containment.close_retained_start_handles(self.process) is True
                )
            if not self.start_handles_closed:
                return
            pipes = [self._close_pipe(name) for name in ("stdin", "stdout", "stderr")]
            if not all(pipes) or self.handle_ambiguous:
                return
            if not self.handle_closed:
                self._handle_current()
                handle = self.handle
                if handle is None:
                    return
                try:
                    handle.Close()
                except Exception:
                    # Popen Handle.Close marks closed BEFORE the native close.
                    # A later no-op Close can never resolve this ambiguity.
                    self.handle_ambiguous = True
                    return
                if getattr(handle, "closed", None) is not True:
                    self.handle_ambiguous = True
                    return
                self.handle_closed = True
            if not self.launch_resources_closed:
                release = self.release_launch_resources
                if release is None:
                    return
                try:
                    self.launch_resources_closed = release() is True
                except Exception:
                    return
                if not self.launch_resources_closed:
                    return
            self.verified = True
        except Exception:
            return

    def _record_exit(self, code: int | None) -> None:
        self.parent_exited = code is not None
        self._supported_terminal_returncode = code if type(code) is int and code in (0, 4) else None

    def _cache_cleanup_receipt(self) -> None:
        with self.cleanup_lock:
            if self._receipt_finalized:
                return
            if (
                not all(
                    (
                        self.verified,
                        self.adopted,
                        self.job_drained,
                        self.job_closed,
                        self.parent_exited,
                        self.start_handles_closed,
                        self.handle_closed,
                        self.launch_resources_closed,
                    )
                )
                or self.handle_ambiguous
                or self.pipe_ambiguous
                or self.pipe_closed != {"stdin", "stdout", "stderr"}
                or self.closer is None
                or any(
                    thread is not None and thread.is_alive()
                    for thread in (self.exchange, self.errors, self.closer)
                )
            ):
                return
            # Closure is final even if attribution or the wall clock is unavailable.
            # Never reconstruct a different receipt on a later cleanup-only retry.
            self._receipt_finalized = True
            try:
                retained = self._retained()
                packet = wire._document(retained._raw)
                observed = wire._clock(_utc()).astimezone(timezone.utc)
                with self.lock:
                    latest = self._last_wall_clock
                wire._require(latest is None or observed >= latest)
                receipt = object.__new__(OwnedCleanupReceipt)
                document = {
                    "schema_version": CLEANUP_SCHEMA,
                    "provenance": "runner_owned_cleanup",
                    "protocol": self.protocol.value,
                    "task_id": packet["task_id"],
                    "transport_request_hash": packet["request_hash"],
                    "packet_digest": content_hash(packet),
                    "original_requested_at": packet["manifest"]["requested_at"],
                    "original_expires_at": packet["manifest"]["expires_at"],
                    "observed_at": observed.isoformat(timespec="microseconds").replace(
                        "+00:00", "Z"
                    ),
                    "child_generation_captured": self._child_generation_captured,
                    "begin_attempted": self.began,
                    "supported_terminal_returncode": self._supported_terminal_returncode,
                    "cleanup": "verified",
                    "settled": False,
                }
                object.__setattr__(receipt, "_raw", canonical_json_bytes(document))
                object.__setattr__(receipt, "_packet", self.packet._raw)
                receipt.document()
                self._cleanup_receipt = receipt
            except Exception:
                return

    def retry_cleanup(self) -> bool:
        """Retry only closure of the same owned resources; never business work."""
        self.stopped.set()
        try:
            with self.cleanup_lock:
                if self.closer is None or (not self.closer.is_alive() and not self.verified):
                    self.closer = threading.Thread(
                        target=self._cleanup, daemon=True, name="windows-read-cleanup"
                    )
                    self.closer.start()
                closer = self.closer
            closer.join(timeout=_JOIN_SECONDS)
            clean = self.verified and not closer.is_alive()
            if clean:
                self._cache_cleanup_receipt()
            return clean
        except Exception:
            return False


def supervise_suspended(
    process: subprocess.Popen[bytes],
    *,
    owned_job: int,
    containment: WindowsJobContainment,
    prepared_packet: wire.PreparedPacket,
    original_reservation: wire.OriginalReservation,
    revalidate_original: Callable[[], None],
    begin_producer: Callable[[bytearray], bytearray],
    cancellation_event: threading.Event,
    evidence_sink: PublicEvidenceSink,
) -> ProcessOutcome:
    """Transfer ownership without launching; return any unresolved cleanup owner.

    The one-use producer owns its private buffer until it returns that mutable
    framed buffer. It must erase its own allocations on failure before transfer.
    This supervisor erases the received buffer and its supplied public prefix.
    The required sink saves only exact public payloads under the original claim.
    Packet/Ready persistence must succeed before Begin; terminal failure leaves
    dispatch unknown and never means that no read was attempted.
    """
    return _supervise_suspended(
        process,
        owned_job=owned_job,
        containment=containment,
        prepared_packet=prepared_packet,
        original_reservation=original_reservation,
        revalidate_original=revalidate_original,
        begin_producer=begin_producer,
        cancellation_event=cancellation_event,
        evidence_sink=evidence_sink,
        protocol=_Protocol.READER_V1,
    )


def supervise_pair_suspended(
    process: subprocess.Popen[bytes],
    *,
    owned_job: int,
    containment: WindowsJobContainment,
    prepared_packet: wire.PreparedPacket,
    original_reservation: wire.OriginalReservation,
    revalidate_original: Callable[[], None],
    begin_producer: Callable[[bytearray], bytearray],
    cancellation_event: threading.Event,
    evidence_sink: PublicEvidenceSink,
    release_launch_resources: Callable[[], bool] | None = None,
    retain_cleanup_owner: Callable[[CleanupOwner], None] | None = None,
) -> ProcessOutcome:
    """Supervise only a pre-admitted pair-v2 child; never upgrade a v1 claim.

    Ownership, one-use delivery and evidence requirements match the v1 entry.
    A partial pair is retained only within the original monitored interval;
    historical validity never extends that interval or permits late dispatch.
    The optional trusted launcher callback runs after native child resources close;
    cleanup remains unknown unless it returns exactly True. It is not serialized.
    No launcher, credential source, enrollment or baseline result is created.
    """
    return _supervise_suspended(
        process,
        owned_job=owned_job,
        containment=containment,
        prepared_packet=prepared_packet,
        original_reservation=original_reservation,
        revalidate_original=revalidate_original,
        begin_producer=begin_producer,
        cancellation_event=cancellation_event,
        evidence_sink=evidence_sink,
        protocol=_Protocol.PAIR_V2,
        release_launch_resources=release_launch_resources,
        retain_cleanup_owner=retain_cleanup_owner,
    )


def supervise_correction_suspended(
    process: subprocess.Popen[bytes],
    *,
    owned_job: int,
    containment: WindowsJobContainment,
    prepared_packet: wire.PreparedPacket,
    original_reservation: wire.OriginalReservation,
    revalidate_original: Callable[[], None],
    begin_producer: Callable[[bytearray], bytearray],
    cancellation_event: threading.Event,
    evidence_sink: PublicEvidenceSink,
    release_launch_resources: Callable[[], bool] | None = None,
    retain_cleanup_owner: Callable[[CleanupOwner], None] | None = None,
) -> ProcessOutcome:
    """Own one already-admitted correction retest, never its prior DACL effect."""
    return _supervise_suspended(
        process,
        owned_job=owned_job,
        containment=containment,
        prepared_packet=prepared_packet,
        original_reservation=original_reservation,
        revalidate_original=revalidate_original,
        begin_producer=begin_producer,
        cancellation_event=cancellation_event,
        evidence_sink=evidence_sink,
        protocol=_Protocol.CORRECTION_V3,
        release_launch_resources=release_launch_resources,
        retain_cleanup_owner=retain_cleanup_owner,
    )


def _supervise_suspended(
    process: subprocess.Popen[bytes],
    *,
    owned_job: int,
    containment: WindowsJobContainment,
    prepared_packet: wire.PreparedPacket,
    original_reservation: wire.OriginalReservation,
    revalidate_original: Callable[[], None],
    begin_producer: Callable[[bytearray], bytearray],
    cancellation_event: threading.Event,
    evidence_sink: PublicEvidenceSink,
    protocol: _Protocol,
    release_launch_resources: Callable[[], bool] | None = None,
    retain_cleanup_owner: Callable[[CleanupOwner], None] | None = None,
) -> ProcessOutcome:
    owner = CleanupOwner(
        process,
        owned_job,
        containment,
        prepared_packet,
        original_reservation,
        revalidate_original,
        begin_producer,
        cancellation_event,
        evidence_sink,
        _protocol=protocol,
        release_launch_resources=release_launch_resources,
    )
    projection = None
    try:
        if retain_cleanup_owner is not None:
            retain_cleanup_owner(owner)
        owner.adoption_attempted = True
        containment.adopt_retained_job(owned_job, process)
        owner.adopted = True
        owner.exchange = threading.Thread(
            target=owner._exchange, daemon=True, name="windows-read-exchange"
        )
        owner.errors = threading.Thread(
            target=owner._stderr, daemon=True, name="windows-read-stderr"
        )
        owner.exchange.start()
        owner.errors.start()
        while True:
            owner.current()
            if owner.issue is not None:
                break
            if owner.done.is_set() and process.poll() is not None:
                break
            owner.stopped.wait(_POLL_SECONDS)
    except BaseException:
        owner._fail("protocol_refused")
        owner.stopped.set()
        if not owner.adopted and not owner.adoption_attempted:
            try:
                owner.adoption_attempted = True
                containment.adopt_retained_job(owned_job, process)
                owner.adopted = True
            except BaseException:
                pass
    finally:
        clean = owner.retry_cleanup()
    if owner.ready is not None and owner.terminal is not None and owner.issue is None:
        try:
            projection = owner._terminal(owner._retained(), owner.ready, owner.terminal)
        except Exception:
            owner._fail("worker_failed")
    issue: Issue | None = owner.issue or (
        "worker_failed" if projection is not None and not projection.observation_complete else None
    )
    return ProcessOutcome(
        projection,
        "attempted" if projection is not None else ("unknown" if owner.began else "not_started"),
        "verified" if clean else "unknown",
        issue if clean else "cleanup_unknown",
        None if clean else owner,
        owner.cleanup_receipt if clean else None,
    )
