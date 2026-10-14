"""Fixed packaged pair worker launch with retained, cleanup-only ownership.

The original packet interval includes launch and credential work. A blocked
native launch remains owned and unknown; neither timeout nor process exit alone
certifies cleanup. No pathname, command, environment or protocol is caller-selected.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import subprocess  # nosec B404
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import windows_file_access_correction_observation as correction_observation
from . import windows_file_access_handles as handles
from . import windows_file_access_native_wire as wire
from . import windows_file_access_pair_admission as admission
from . import windows_file_access_process as supervisor
from .runner_bootstrap import load_runner_manifest
from .runner_lifecycle import ManagedRunnerLifecycle
from .runner_trust import _PinnedDirectory
from .runner_windows_containment import WindowsJobContainment
from .util import content_hash
from .windows_file_access_correction_credential import CorrectionBeginProducer
from .windows_file_access_enrollment_native import file_identity_wire
from .windows_file_access_pair_credential import PairBeginProducer
from .windows_file_access_setup_child import _managed_root

_JOIN_SECONDS = 1.0


def _utc() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class PairLaunchOutcome:
    process: supervisor.ProcessOutcome | None = field(repr=False)
    dispatch: str
    cleanup: str
    credential_cleanup: str
    issue: str | None
    cleanup_owner: PairLaunchOwner | None = field(repr=False)
    settled: bool = field(default=False, init=False)


class PairLaunchOwner:
    """One launch and exact retained cleanup state; retry never launches again."""

    _protocol = supervisor._Protocol.PAIR_V2

    def __init__(
        self,
        checked: admission.VerifiedWindowsPairSetup,
        original: wire.OriginalReservation,
        packet: wire.PreparedPacket,
        producer: PairBeginProducer,
        revalidate: Callable[[], None],
        evidence_sink: supervisor.PublicEvidenceSink,
        cancellation: threading.Event,
    ) -> None:
        wire._require(type(checked) is admission.VerifiedWindowsPairSetup)
        self.record, self.receipt = admission.checked_provenance(checked)
        wire._reservation(original, wire._PAIR)
        wire._require(
            type(packet) is wire.PreparedPacket
            and packet._original == original
            and type(producer) is PairBeginProducer
            and producer._checked == checked
            and producer._original == original
            and producer._packet == packet
            and producer._cancellation is cancellation
        )
        self._initialize(original, packet, producer, revalidate, evidence_sink, cancellation)

    def _initialize(
        self,
        original: wire.OriginalReservation,
        packet: wire.PreparedPacket,
        producer: PairBeginProducer | CorrectionBeginProducer,
        revalidate: Callable[[], None],
        evidence_sink: supervisor.PublicEvidenceSink,
        cancellation: threading.Event,
    ) -> None:
        self.original, self.packet, self.producer = original, packet, producer
        self.revalidate, self.evidence_sink, self.cancellation = (
            revalidate,
            evidence_sink,
            cancellation,
        )
        self.stopped, self.done = threading.Event(), threading.Event()
        self.pins = contextlib.ExitStack()
        self.pins_closed = self.pins_ambiguous = False
        self.fds: set[int] = set()
        self.fd_ambiguous = False
        self.streams: dict[str, Any] = {}
        self.child_ends: list[int] = []
        self.streams_closed: set[str] = set()
        self.streams_ambiguous: set[str] = set()
        self.containment: WindowsJobContainment | None = None
        self.job: int | None = None
        self.job_closed = self.job_ambiguous = False
        self.creation_started = self.creation_unknown = self.transferred = False
        self.process: subprocess.Popen[bytes] | None = None
        self.result: supervisor.ProcessOutcome | None = None
        self.retained_owner: supervisor.CleanupOwner | None = None
        self.worker: threading.Thread | None = None
        self.issue: str | None = None
        self.resources_closed = False
        self._retry_lock = threading.Lock()

    def __repr__(self) -> str:
        return "<WindowsPairLaunchOwner retained>"

    def _current(self) -> None:
        wire._require(not self.stopped.is_set() and not self.cancellation.is_set())
        wire._prepared(self.packet, _utc(), time.monotonic())

    def _close_fds(self, selected: tuple[int, ...] | None = None) -> bool:
        for descriptor in tuple(self.fds) if selected is None else selected:
            if descriptor not in self.fds:
                continue
            self.fds.remove(descriptor)
            try:
                os.close(descriptor)
            except Exception:
                # A raw descriptor may already have been released. Never retry it.
                self.fd_ambiguous = True
        return not self.fd_ambiguous

    def _release_resources(self) -> bool:
        """Called by supervisor only after its exact process/Job/pipes are closed."""
        if not self._close_fds() or self.pins_ambiguous:
            return False
        if not self.pins_closed:
            try:
                self.pins.close()
            except Exception:
                self.pins_ambiguous = True
                return False
            self.pins_closed = True
        self.resources_closed = self.producer.credential_cleanup in ("not_started", "verified")
        return self.resources_closed

    def _image(self) -> tuple[str, Path]:
        self._current()
        root = _managed_root()
        try:
            self.pins.enter_context(
                _PinnedDirectory(root, private=True, verify_permissions_only=True)
            )
        except BaseException:
            self.pins_ambiguous = True
            raise
        lifecycle = ManagedRunnerLifecycle(root)
        local = lifecycle._load_active_enrollment()
        bootstrap = lifecycle._load_bootstrap(local)
        manifest = load_runner_manifest(platform_name="windows", architecture="x86_64")
        image, source = self.record["native_image"], self.receipt["source"]
        wire._require(
            bootstrap.source == "packaged"
            and bootstrap.managed_binary
            and bootstrap.binary_digest == image["sha256"] == "sha256:" + manifest.sha256
            and bootstrap.runner_version == manifest.runner_version
            and image["size_bytes"] == manifest.size
            and 1 <= manifest.size <= 64 * 1024 * 1024
        )
        client, _ = lifecycle.client_for_profile(source["source_profile_id"])
        wire._require(dict(client.transport_identity()) == source["transport"])
        path = Path(bootstrap.binary_path)
        wire._require(
            path.is_absolute()
            and path.name == "bluefire-runner.exe"
            and 0 < len(path.parents) <= 32
        )
        before = []
        for candidate in (*reversed(path.parents), path):
            self._current()
            directory = candidate != path
            try:
                descriptor = handles.open_observation(
                    candidate, directory=directory, data=not directory
                )
            except BaseException:
                self.fd_ambiguous = True
                raise
            self.fds.add(descriptor)
            facts = handles.inspect_observation(descriptor, directory=directory)
            wire._require(facts.final_path == "\\\\?\\" + os.fspath(candidate))
            before.append((descriptor, directory, facts))
        descriptor, _, facts = before[-1]
        volume, file_id = file_identity_wire(*facts.identity)
        wire._require(
            {"volume_serial": volume, "file_id": file_id} == image["identity"]
            and facts.size == manifest.size
        )
        digest, total = hashlib.sha256(), 0
        while total <= manifest.size:
            self._current()
            chunk = os.read(descriptor, min(65536, manifest.size + 1 - total))
            wire._require(type(chunk) is bytes)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        wire._require(total == manifest.size and "sha256:" + digest.hexdigest() == image["sha256"])
        for descriptor, directory, facts in before:
            self._current()
            wire._require(handles.inspect_observation(descriptor, directory=directory) == facts)
        again, _ = lifecycle.client_for_profile(source["source_profile_id"])
        wire._require(dict(again.transport_identity()) == source["transport"])
        self.revalidate()
        self._current()
        return os.fspath(path), root

    def _launch(self) -> None:
        executable, root = self._image()
        self.containment = WindowsJobContainment(kill_on_close=True)
        system = str(self.containment.system_directory().parent)
        self._current()
        self.job = self.containment.create_job()
        self._current()
        child_ends = self.child_ends
        for name in ("stdin", "stdout", "stderr"):
            self._current()
            read, write = os.pipe()
            self.fds.update((read, write))
            owned, passed = (write, read) if name == "stdin" else (read, write)
            try:
                self.streams[name] = os.fdopen(
                    owned, "wb" if name == "stdin" else "rb", buffering=0
                )
            except BaseException:
                self.fds.remove(owned)
                self.fd_ambiguous = True
                raise
            self.fds.remove(owned)
            child_ends.append(passed)
        self._current()
        self.creation_started = True
        try:
            self.process = subprocess.Popen(  # nosec B603 - fixed held packaged image and command
                [
                    executable,
                    {
                        supervisor._Protocol.PAIR_V2: "windows-file-baseline-worker",
                        supervisor._Protocol.CORRECTION_V3: "windows-file-correction-worker",
                    }[self._protocol],
                ],
                cwd=root,
                env={"SYSTEMROOT": system, "WINDIR": system, "TEMP": str(root), "TMP": str(root)},
                stdin=child_ends[0],
                stdout=child_ends[1],
                stderr=child_ends[2],
                shell=False,
                close_fds=True,
                bufsize=0,
                creationflags=0x08000000 | 0x00000200 | 0x00000004,
            )
        except BaseException:
            # Without a returned exact process handle, closure cannot be proven.
            self.creation_unknown = True
            raise
        for name, stream in self.streams.items():
            setattr(self.process, name, stream)
        if not self._close_fds(tuple(child_ends)):
            self.stopped.set()

    def _untransferred_cleanup(self) -> bool:
        if self.process is not None:
            if self.job is None or self.containment is None:
                return False
            if self.retained_owner is None:
                # No supervisor owner escaped construction. Retain this exact
                # child for cleanup only, without starting protocol threads.
                retained = supervisor.CleanupOwner(
                    self.process,
                    self.job,
                    self.containment,
                    self.packet,
                    self.original,
                    self.revalidate,
                    self.producer,
                    self.stopped,
                    self.evidence_sink,
                    _protocol=self._protocol,
                    release_launch_resources=self._release_resources,
                )
                self._retain_cleanup_owner(retained)
            return self._retry_retained_cleanup()
        if self.job is not None and not self.job_closed and not self.job_ambiguous:
            try:
                assert self.containment is not None
                self.job_closed = self.containment.close_handle(self.job) is True
                self.job_ambiguous = not self.job_closed
            except Exception:
                self.job_ambiguous = True
        for name, stream in self.streams.items():
            if name in self.streams_closed or name in self.streams_ambiguous:
                continue
            try:
                stream.close()
                if getattr(stream, "closed", None) is True:
                    self.streams_closed.add(name)
                else:
                    self.streams_ambiguous.add(name)
            except Exception:
                self.streams_ambiguous.add(name)
        resources = self._release_resources()
        return bool(
            resources
            and not self.creation_unknown
            and not self.job_ambiguous
            and (self.job is None or self.job_closed)
            and not self.streams_ambiguous
            and self.streams_closed == set(self.streams)
        )

    def _retain_cleanup_owner(self, owner: supervisor.CleanupOwner) -> None:
        wire._require(self.retained_owner is None or self.retained_owner is owner)
        self.retained_owner = owner
        self.transferred = True

    def _retry_retained_cleanup(self) -> bool:
        retained = self.retained_owner
        if retained is None:
            return False
        if not retained.adopted and not retained.adoption_attempted:
            retained.adoption_attempted = True
            try:
                retained.containment.adopt_retained_job(retained.job, retained.process)
                retained.adopted = True
            except BaseException:
                return False
        if not retained.retry_cleanup():
            return False
        if self.result is None:
            self.result = supervisor.ProcessOutcome(
                None,
                "unknown" if retained.began else "not_started",
                "verified",
                retained.issue,
                None,
                retained.cleanup_receipt,
            )
        else:
            issue = retained.issue
            if issue is None and self.result.issue != "cleanup_unknown":
                issue = self.result.issue
            if (
                issue is None
                and self.result.projection is not None
                and not self.result.projection.observation_complete
            ):
                issue = "worker_failed"
            self.result = replace(
                self.result,
                cleanup="verified",
                issue=issue,
                cleanup_owner=None,
                cleanup_receipt=retained.cleanup_receipt,
            )
        return self.resources_closed

    def _work(self) -> None:
        try:
            try:
                self._launch()
            except BaseException:
                self.issue = "launch_unknown" if self.creation_started else "launch_refused"
                self.stopped.set()
                self.producer.request_stop()
            if self.process is not None and self.job is not None and self.containment is not None:
                if not self._close_fds(tuple(self.child_ends)):
                    self.stopped.set()
                    self.producer.request_stop()
                # Even a late/failed launch transfers the exact child for cleanup.
                # The set cancellation prevents assignment/resume/Begin work.
                entry = {
                    supervisor._Protocol.PAIR_V2: supervisor.supervise_pair_suspended,
                    supervisor._Protocol.CORRECTION_V3: supervisor.supervise_correction_suspended,
                }[self._protocol]
                self.result = entry(
                    self.process,
                    owned_job=self.job,
                    containment=self.containment,
                    prepared_packet=self.packet,
                    original_reservation=self.original,
                    revalidate_original=self.revalidate,
                    begin_producer=self.producer,
                    cancellation_event=self.stopped,
                    evidence_sink=self.evidence_sink,
                    release_launch_resources=self._release_resources,
                    retain_cleanup_owner=self._retain_cleanup_owner,
                )
            else:
                self._untransferred_cleanup()
        except BaseException:
            self.issue = self.issue or "launch_unknown"
            self.stopped.set()
            self.producer.request_stop()
        finally:
            self.done.set()

    def retry_cleanup(self) -> bool:
        """Stop and release this original owner only; never launch or deliver Begin."""
        self.stopped.set()
        self.producer.request_stop()
        with self._retry_lock:
            try:
                if self.worker is not None and self.worker.ident is not None:
                    self.worker.join(timeout=_JOIN_SECONDS)
                    if self.worker.is_alive():
                        return False
                if self.transferred:
                    return self._retry_retained_cleanup()
                return self._untransferred_cleanup()
            except BaseException:
                return False

    def outcome(self, clean: bool) -> PairLaunchOutcome:
        result = self.result
        return PairLaunchOutcome(
            result,
            (
                result.dispatch
                if result is not None
                else ("unknown" if self.creation_started else "not_started")
            ),
            "verified" if clean else "unknown",
            self.producer.credential_cleanup,
            (self.issue or (result.issue if result else None)) if clean else "cleanup_unknown",
            None if clean else self,
        )


class CorrectionLaunchOwner(PairLaunchOwner):
    """Same retained resources, admitted only by the separate postimage type."""

    _protocol = supervisor._Protocol.CORRECTION_V3

    def __init__(
        self,
        checked: correction_observation.VerifiedWindowsCorrectionPostimage,
        original: wire.OriginalReservation,
        packet: wire.PreparedPacket,
        producer: CorrectionBeginProducer,
        revalidate: Callable[[], None],
        evidence_sink: supervisor.PublicEvidenceSink,
        cancellation: threading.Event,
    ) -> None:
        self.record, self.receipt, binding = correction_observation.checked_provenance(checked)
        context = wire._reservation(original, wire._CORRECTION)
        wire._require(
            type(packet) is wire.PreparedPacket
            and packet._original == original
            and type(producer) is CorrectionBeginProducer
            and producer._checked == checked
            and producer._original == original
            and producer._packet == packet
            and producer._cancellation is cancellation
            and context["manifest"]["params"]["windows_file_read_request"][
                "correction_binding_digest"
            ]
            == content_hash(binding)
        )
        self._initialize(original, packet, producer, revalidate, evidence_sink, cancellation)

    def __repr__(self) -> str:
        return "<WindowsCorrectionLaunchOwner retained>"


def launch_pair_baseline(
    checked: admission.VerifiedWindowsPairSetup,
    original: wire.OriginalReservation,
    packet: wire.PreparedPacket,
    producer: PairBeginProducer,
    *,
    revalidate_original: Callable[[], None],
    evidence_sink: supervisor.PublicEvidenceSink,
    cancellation_event: threading.Event,
    retain_launch_owner: Callable[[PairLaunchOwner], None] | None = None,
) -> PairLaunchOutcome:
    """One fixed original launch; return unresolved ownership for cleanup only."""
    wire._require(sys.platform == "win32")
    owner = PairLaunchOwner(
        checked, original, packet, producer, revalidate_original, evidence_sink, cancellation_event
    )
    return _launch_owner(owner, retain_launch_owner)


def launch_correction_retest(
    checked: correction_observation.VerifiedWindowsCorrectionPostimage,
    original: wire.OriginalReservation,
    packet: wire.PreparedPacket,
    producer: CorrectionBeginProducer,
    *,
    revalidate_original: Callable[[], None],
    evidence_sink: supervisor.PublicEvidenceSink,
    cancellation_event: threading.Event,
    retain_launch_owner: Callable[[PairLaunchOwner], None] | None = None,
) -> PairLaunchOutcome:
    """Launch one freshly admitted retest; never dispatch or repeat its DACL change."""
    wire._require(sys.platform == "win32")
    owner = CorrectionLaunchOwner(
        checked, original, packet, producer, revalidate_original, evidence_sink, cancellation_event
    )
    return _launch_owner(owner, retain_launch_owner)


def _launch_owner(
    owner: PairLaunchOwner, retain_launch_owner: Callable[[PairLaunchOwner], None] | None
) -> PairLaunchOutcome:
    if retain_launch_owner is not None:
        retain_launch_owner(owner)
    owner.worker = threading.Thread(target=owner._work, daemon=True, name="windows-pair-launch")
    try:
        owner._current()
        owner.worker.start()
        while not owner.done.is_set():
            owner._current()
            owner.stopped.wait(0.01)
    except BaseException:
        owner.issue = owner.issue or "launch_stopped"
        owner.stopped.set()
    return owner.outcome(owner.retry_cleanup())
