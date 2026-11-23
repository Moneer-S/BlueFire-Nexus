"""Fixed protected-record observations, never verified enrollment or readiness.

The original approved protected setup producer is still missing. Protected
record/anchor bytes and self-consistent hashes cannot substitute for it, local SAM,
resource/image/channel facts or private admission. Native calls can block; the
caller must own an external disposable-process hard deadline and cleanup.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import windows_file_access_admission as enrollment
from . import windows_file_access_admission as setup
from . import windows_file_access_enrollment_native as native
from . import windows_file_access_handles as handles
from .windows_owner_acl import _handle_from_descriptor
from .windows_session_facts import WindowsPrincipalFacts, current_process_principal

_PATHS = (
    "C:\\",
    r"C:\ProgramData",
    r"C:\ProgramData\BlueFire",
    r"C:\ProgramData\BlueFire\EndpointAccess",
    enrollment.ANCHOR_PATH,
)


class WindowsEnrollmentRecordError(RuntimeError):
    """Path-free unknown observation, including incomplete owned cleanup."""


@dataclass(frozen=True, slots=True)
class ProtectedEnrollmentRecordObservation:
    """Immutable byte/fact snapshot, deliberately without a verification flag.

    Creation is not an authority boundary. Even a native-produced snapshot does not
    authenticate the original generation or prove the record's independent anchor.
    """

    raw_bytes: bytes = field(repr=False)
    principal: WindowsPrincipalFacts = field(repr=False)
    object_facts: tuple[handles.WindowsFileFacts, ...] = field(repr=False)
    selected_descriptor_sha256: str
    record_sha256: str

    @property
    def record_identity_wire(self) -> tuple[str, str]:
        return native.file_identity_wire(*self.object_facts[-1].identity)


@dataclass(frozen=True, slots=True)
class ProtectedEnrollmentPairObservation:
    """Held/fresh protected pair, not an approved setup or execution context."""

    record: ProtectedEnrollmentRecordObservation = field(repr=False)
    anchor_bytes: bytes = field(repr=False)
    anchor_object_facts: tuple[handles.WindowsFileFacts, ...] = field(repr=False)
    anchor_selected_descriptor_sha256: str
    anchor_sha256: str


@dataclass(frozen=True)
class _HeldMetadata:
    paths: tuple[str, ...]
    held: tuple[int, ...]
    facts: tuple[handles.WindowsFileFacts, ...]
    selected: dict[int, str]
    data: int
    raw: bytes
    generation: str | None


class _ProtectedRecordReader:
    """Private concrete operations; public APIs accept no backend/trust callback."""

    def __init__(self, gate: native._Gate) -> None:
        self.gate = gate
        self.descriptors: list[int] = []

    def open(self, index: int, *, data: bool = False) -> int:
        if type(index) is not int or not 0 <= index < len(_PATHS) or (data and index != 4):
            raise WindowsEnrollmentRecordError("Windows enrollment open is unsupported")
        self.gate.check()
        descriptor = handles.open_observation(Path(_PATHS[index]), directory=index < 4, data=data)
        self.descriptors.append(descriptor)
        self.gate.check()
        return descriptor

    def open_anchor(self, index: int, generation: str, *, data: bool = False) -> int:
        paths = setup._anchor_paths(generation)
        if (
            type(index) is not int
            or not 0 <= index < len(paths)
            or (data and index != len(paths) - 1)
        ):
            raise WindowsEnrollmentRecordError("Windows enrollment anchor open is unsupported")
        self.gate.check()
        descriptor = handles.open_observation(
            Path(paths[index]), directory=index < len(paths) - 1, data=data
        )
        self.descriptors.append(descriptor)
        self.gate.check()
        return descriptor

    def facts(self, descriptor: int, *, directory: bool) -> handles.WindowsFileFacts:
        return handles.inspect_observation(descriptor, directory=directory)

    def protected(self, descriptor: int, owner_sid: str, *, directory: bool) -> str:
        return native.observe_protected_metadata_descriptor(
            _handle_from_descriptor(descriptor),
            owner_sid,
            directory=directory,
            deadline=self.gate.deadline,
            cancelled=self.gate.cancelled,
        )

    def principal(self) -> WindowsPrincipalFacts:
        return current_process_principal()

    def read(self, descriptor: int, count: int) -> bytes:
        return os.read(descriptor, count)

    def close(self) -> None:
        failed = False
        for descriptor in reversed(self.descriptors):
            try:
                os.close(descriptor)
            except Exception:
                failed = True
        self.descriptors.clear()
        if failed:
            raise WindowsEnrollmentRecordError("Windows enrollment record cleanup is unknown")


def _principal(reader: _ProtectedRecordReader, gate: native._Gate) -> WindowsPrincipalFacts:
    gate.check()
    principal = reader.principal()
    gate.check()
    if type(principal) is not WindowsPrincipalFacts:
        raise WindowsEnrollmentRecordError("Windows enrollment principal is unavailable")
    principal.validate()
    native._local_sid(principal.user_sid)
    if principal.elevated is not False:
        raise WindowsEnrollmentRecordError("Windows enrollment principal is unsupported")
    return principal


def _facts(
    reader: _ProtectedRecordReader,
    descriptor: int,
    index: int,
    gate: native._Gate,
    *,
    paths: tuple[str, ...] = _PATHS,
    maximum: int = enrollment.MAX_ENROLLMENT_BYTES,
) -> handles.WindowsFileFacts:
    directory = index < len(paths) - 1
    gate.check()
    facts = reader.facts(descriptor, directory=directory)
    gate.check()
    if (
        type(facts) is not handles.WindowsFileFacts
        or type(facts.identity) is not tuple
        or len(facts.identity) != 2
        or facts.final_path != "\\\\?\\" + paths[index]
        or type(facts.directory) is not bool
        or facts.directory is not directory
        or type(facts.size) is not int
        or not 0 <= facts.size <= 2**63 - 1
        or type(facts.links) is not int
        or not 1 <= facts.links <= 2**32 - 1
        or (not directory and facts.links != 1)
        or type(facts.attributes) is not int
        or not 0 <= facts.attributes <= 2**32 - 1
        or facts.attributes & (0x400 | 0x1000)
        or bool(facts.attributes & 0x10) is not directory
        or any(
            type(value) is not int or not 0 <= value <= 2**63 - 1
            for value in (facts.created, facts.written, facts.changed)
        )
    ):
        raise WindowsEnrollmentRecordError("Windows enrollment object facts are unsupported")
    native.file_identity_wire(*facts.identity)
    if not directory and not 1 <= facts.size <= maximum:
        raise WindowsEnrollmentRecordError("Windows enrollment record exceeds its bound")
    return facts


def _protected(
    reader: _ProtectedRecordReader,
    descriptor: int,
    principal: WindowsPrincipalFacts,
    *,
    directory: bool,
    gate: native._Gate,
) -> str:
    gate.check()
    digest = reader.protected(descriptor, principal.user_sid, directory=directory)
    gate.check()
    enrollment.wire._digest(digest)
    return digest


def _current_candidate(
    raw: bytes, principal: WindowsPrincipalFacts, protocol=enrollment._READER_SETUP
) -> None:
    now_ms = time.time_ns() // 1_000_000
    row = enrollment._document_for(raw, protocol)
    enrollment.wire._require(row["issued_at_ms"] <= now_ms < row["expires_at_ms"])
    if row["resource"]["owner_sid"] != principal.user_sid:
        raise WindowsEnrollmentRecordError("Windows enrollment owner differs from the process")


def _open(
    reader: _ProtectedRecordReader,
    index: int,
    generation: str | None,
    gate: native._Gate,
    *,
    data: bool = False,
) -> int:
    gate.check()
    descriptor = (
        reader.open(index, data=data)
        if generation is None
        else reader.open_anchor(index, generation, data=data)
    )
    gate.check()
    return descriptor


def _hold_metadata(
    reader: _ProtectedRecordReader,
    principal: WindowsPrincipalFacts,
    gate: native._Gate,
    *,
    generation: str | None = None,
) -> _HeldMetadata:
    paths = _PATHS if generation is None else setup._anchor_paths(generation)
    maximum = enrollment.MAX_ENROLLMENT_BYTES if generation is None else setup.MAX_ANCHOR_BYTES
    last = len(paths) - 1
    held, before = [], []
    for index in range(len(paths)):
        descriptor = _open(reader, index, generation, gate)
        held.append(descriptor)
        before.append(_facts(reader, descriptor, index, gate, paths=paths, maximum=maximum))
    if len({facts.identity[0] for facts in before}) != 1 or len(
        {facts.identity for facts in before}
    ) != len(paths):
        raise WindowsEnrollmentRecordError("Windows enrollment ancestry identities differ")
    selected = {
        index: _protected(reader, held[index], principal, directory=index < last, gate=gate)
        for index in range(2, len(paths))
    }
    data = _open(reader, last, generation, gate, data=True)
    if (
        _facts(reader, data, last, gate, paths=paths, maximum=maximum) != before[last]
        or _protected(reader, data, principal, directory=False, gate=gate) != selected[last]
    ):
        raise WindowsEnrollmentRecordError("Windows enrollment fresh data object changed")
    raw = bytearray()
    while len(raw) <= before[last].size:
        gate.check()
        count = min(4096, before[last].size + 1 - len(raw))
        chunk = reader.read(data, count)
        gate.check()
        if type(chunk) is not bytes or len(chunk) > count:
            raise WindowsEnrollmentRecordError("Windows enrollment data response is invalid")
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) != before[last].size:
        raise WindowsEnrollmentRecordError("Windows enrollment data size changed")
    return _HeldMetadata(paths, tuple(held), tuple(before), selected, data, bytes(raw), generation)


def _recheck_metadata(
    reader: _ProtectedRecordReader,
    metadata: _HeldMetadata,
    principal: WindowsPrincipalFacts,
    gate: native._Gate,
) -> None:
    paths, before = metadata.paths, metadata.facts
    maximum = (
        enrollment.MAX_ENROLLMENT_BYTES if metadata.generation is None else setup.MAX_ANCHOR_BYTES
    )
    last = len(paths) - 1
    for index in range(len(paths)):
        fresh = _open(reader, index, metadata.generation, gate)
        if (
            _facts(reader, metadata.held[index], index, gate, paths=paths, maximum=maximum)
            != before[index]
            or _facts(reader, fresh, index, gate, paths=paths, maximum=maximum) != before[index]
        ):
            raise WindowsEnrollmentRecordError("Windows enrollment held or fresh object changed")
        if index in metadata.selected:
            for descriptor in (metadata.held[index], fresh):
                if (
                    _protected(reader, descriptor, principal, directory=index < last, gate=gate)
                    != metadata.selected[index]
                ):
                    raise WindowsEnrollmentRecordError(
                        "Windows enrollment protected descriptor changed"
                    )
    if (
        _facts(reader, metadata.data, last, gate, paths=paths, maximum=maximum) != before[last]
        or _protected(reader, metadata.data, principal, directory=False, gate=gate)
        != metadata.selected[last]
    ):
        raise WindowsEnrollmentRecordError("Windows enrollment final data observation changed")


def _recheck_held_metadata(
    reader: _ProtectedRecordReader,
    metadata: _HeldMetadata,
    principal: WindowsPrincipalFacts,
    gate: native._Gate,
) -> None:
    maximum = (
        enrollment.MAX_ENROLLMENT_BYTES if metadata.generation is None else setup.MAX_ANCHOR_BYTES
    )
    last = len(metadata.paths) - 1
    for index, descriptor in enumerate(metadata.held):
        if (
            _facts(reader, descriptor, index, gate, paths=metadata.paths, maximum=maximum)
            != metadata.facts[index]
        ):
            raise WindowsEnrollmentRecordError("Windows enrollment held pair changed")
        if (
            index in metadata.selected
            and _protected(reader, descriptor, principal, directory=index < last, gate=gate)
            != metadata.selected[index]
        ):
            raise WindowsEnrollmentRecordError("Windows enrollment held pair descriptor changed")
    if (
        _facts(reader, metadata.data, last, gate, paths=metadata.paths, maximum=maximum)
        != metadata.facts[last]
        or _protected(reader, metadata.data, principal, directory=False, gate=gate)
        != metadata.selected[last]
    ):
        raise WindowsEnrollmentRecordError("Windows enrollment held pair data changed")


def _observe_metadata(
    *,
    deadline: float,
    cancelled: Callable[[], bool],
    include_anchor: bool,
    protocol: enrollment._SetupProtocol | None = enrollment._READER_SETUP,
) -> tuple[ProtectedEnrollmentRecordObservation, ProtectedEnrollmentPairObservation | None]:
    try:
        gate = native._Gate(deadline, cancelled)
        reader = _ProtectedRecordReader(gate)
    except Exception:
        raise WindowsEnrollmentRecordError(
            "Windows enrollment record observation is unavailable"
        ) from None
    try:
        principal = _principal(reader, gate)
        record = _hold_metadata(reader, principal, gate)
        if protocol is None:
            protocol = enrollment._protocol_from_record(record.raw)
        enrollment._setup_protocol(protocol)
        _current_candidate(record.raw, principal, protocol)
        gate.check()
        anchor = None
        if include_anchor:
            generation = enrollment._document_for(record.raw, protocol)["generation"]
            anchor = _hold_metadata(reader, principal, gate, generation=generation)
            if (
                anchor.facts[:3] != record.facts[:3]
                or anchor.selected[2] != record.selected[2]
                or {facts.identity for facts in anchor.facts[3:]}
                & {facts.identity for facts in record.facts[3:]}
            ):
                raise WindowsEnrollmentRecordError("Windows enrollment anchor ancestry differs")
            enrollment._match_anchor_record_for(
                anchor.raw, record.raw, record.facts[-1].identity, protocol
            )
            gate.check()
        _recheck_metadata(reader, record, principal, gate)
        if anchor is not None:
            _recheck_metadata(reader, anchor, principal, gate)
            enrollment._match_anchor_record_for(
                anchor.raw, record.raw, record.facts[-1].identity, protocol
            )
            gate.check()
            _recheck_held_metadata(reader, record, principal, gate)
            _recheck_held_metadata(reader, anchor, principal, gate)
        if _principal(reader, gate) != principal:
            raise WindowsEnrollmentRecordError("Windows enrollment final observation changed")
        _current_candidate(record.raw, principal, protocol)
        gate.check()
        observed_record = ProtectedEnrollmentRecordObservation(
            record.raw,
            principal,
            record.facts,
            record.selected[len(record.paths) - 1],
            "sha256:" + hashlib.sha256(record.raw).hexdigest(),
        )
        observed_pair = (
            None
            if anchor is None
            else ProtectedEnrollmentPairObservation(
                observed_record,
                anchor.raw,
                anchor.facts,
                anchor.selected[len(anchor.paths) - 1],
                "sha256:" + hashlib.sha256(anchor.raw).hexdigest(),
            )
        )
        return observed_record, observed_pair
    except Exception:
        raise WindowsEnrollmentRecordError(
            "Windows protected enrollment record is unavailable"
        ) from None
    finally:
        try:
            reader.close()
        except Exception:
            raise WindowsEnrollmentRecordError(
                "Windows enrollment record cleanup is unknown"
            ) from None
        try:
            gate.check()
        except Exception:
            raise WindowsEnrollmentRecordError(
                "Windows enrollment record observation stopped"
            ) from None


def observe_protected_enrollment_record(
    *, deadline: float, cancelled: Callable[[], bool]
) -> ProtectedEnrollmentRecordObservation:
    """Read the fixed protected record, without anchor or enrollment authority.

    All ancestry/data handles remain share-read only through fresh identity, selected
    descriptor and primary-process rechecks. No path, owner, trust flag or alternate
    backend is accepted. External hard deadline and owned cleanup remain mandatory.
    """
    return _observe_metadata(deadline=deadline, cancelled=cancelled, include_anchor=False)[0]


def observe_protected_enrollment_pair(
    *, deadline: float, cancelled: Callable[[], bool]
) -> ProtectedEnrollmentPairObservation:
    """Read the fixed record and generation-specific independently protected anchor.

    Both complete ancestries/data handles are held concurrently through fresh checks.
    The nine-field anchor must match the observed record's full native identity and
    closed contents. The original monotonic budget is never renewed. Metadata from
    both files is bounded to 20 KiB total, with at most 24 owned descriptors.

    Protection and linkage do not supply the missing original approved privileged
    setup receipt, owned-account lifecycle, installed-host/image/channel facts or
    private admission. This result is non-authoritative and cannot enable context.
    No credential is resolved and no malformed/preexisting state is repaired.
    """
    pair = _observe_metadata(deadline=deadline, cancelled=cancelled, include_anchor=True)[1]
    if pair is None:
        raise WindowsEnrollmentRecordError("Windows enrollment anchor observation is unavailable")
    return pair


def observe_protected_pair_enrollment(
    *, deadline: float, cancelled: Callable[[], bool]
) -> ProtectedEnrollmentPairObservation:
    """Read only an explicitly selected paired-v2 protected record and anchor."""
    pair = _observe_metadata(
        deadline=deadline, cancelled=cancelled, include_anchor=True, protocol=enrollment._PAIR_SETUP
    )[1]
    if pair is None:
        raise WindowsEnrollmentRecordError("Windows enrollment anchor observation is unavailable")
    return pair


def _observe_selected_enrollment(
    *, deadline: float, cancelled: Callable[[], bool]
) -> ProtectedEnrollmentPairObservation:
    """Status-only closed selection after holding the actual protected record."""
    pair = _observe_metadata(
        deadline=deadline, cancelled=cancelled, include_anchor=True, protocol=None
    )[1]
    if pair is None:
        raise WindowsEnrollmentRecordError("Windows enrollment anchor observation is unavailable")
    return pair
