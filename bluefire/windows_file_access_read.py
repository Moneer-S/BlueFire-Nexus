"""Fixed Windows generated-file read, not a registered execution capability.

The trusted caller must independently enroll the reader, authorize the resource
and own a worker deadline. There is no path, credential or process-launch API.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .runner_transport_framing import _duplicates_rejected
from .windows_file_access_dacl import WindowsFileAccessDaclError, verify_resource_dacl
from .windows_file_access_handles import (
    WindowsDataOpenDenied,
    WindowsFileFacts,
    WindowsFileHandleError,
    inspect_observation,
    open_observation,
)
from .windows_file_access_policy import WindowsFileAccessPolicy
from .windows_owner_acl import WindowsOwnerAclError, _handle_from_descriptor
from .windows_session_facts import (
    WindowsPrincipalFacts,
    WindowsSessionFactsError,
    current_process_principal,
)

_MAX_BYTES = 1024 * 1024
_MAX_SECONDS = 5.0
_MAX_RECORD_DEPTH = 32
_ANCHOR = "C:\\BlueFire\\EndpointAccess"


class WindowsFileReadError(RuntimeError):
    """A finite observation is unavailable; this never means prevented access."""


@dataclass(frozen=True)
class WindowsResourceExpectation:
    """Private resource enrollment, independent of a transient reader process."""

    generation: str
    policy: WindowsFileAccessPolicy = field(repr=False)
    directory_identities: tuple[tuple[int, int], ...]
    file_identity: tuple[int, int]
    size: int
    sha256: str
    record_count: int
    state: Literal["readable", "metadata_only"]

    def validate(self) -> None:
        if (
            type(self.generation) is not str
            or re.fullmatch(r"[0-9a-f]{32}", self.generation) is None
            or type(self.policy) is not WindowsFileAccessPolicy
            or self.state not in ("readable", "metadata_only")
            or type(self.size) is not int
            or not 1 <= self.size <= _MAX_BYTES
            or type(self.record_count) is not int
            or not 1 <= self.record_count <= 100
            or type(self.sha256) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.sha256) is None
            or type(self.directory_identities) is not tuple
            or len(self.directory_identities) != 4
        ):
            raise WindowsFileReadError("Windows reader expectation is invalid")
        identities = (*self.directory_identities, self.file_identity)
        for pair in identities:
            if (
                type(pair) is not tuple
                or len(pair) != 2
                or type(pair[0]) is not int
                or type(pair[1]) is not int
                or not 0 <= pair[0] <= 2**64 - 1
                or not 1 <= pair[1] <= 2**128 - 1
            ):
                raise WindowsFileReadError("Windows resource identity is invalid")
        if len(set(identities)) != 5 or len({pair[0] for pair in identities}) != 1:
            raise WindowsFileReadError("Windows resource aliases or crosses a volume")


@dataclass(frozen=True)
class WindowsReadExpectation:
    """A primary-process read binding; never substitute effective-thread facts."""

    resource: WindowsResourceExpectation = field(repr=False)
    principal: WindowsPrincipalFacts = field(repr=False)

    def validate(self) -> None:
        if type(self.resource) is not WindowsResourceExpectation:
            raise WindowsFileReadError("Windows reader resource expectation is invalid")
        self.resource.validate()
        if (
            type(self.principal) is not WindowsPrincipalFacts
            or self.principal.user_sid != self.resource.policy.reader_sid
            or self.principal.elevated is not False
        ):
            raise WindowsFileReadError("Windows reader principal expectation is invalid")
        try:
            self.principal.validate()
        except WindowsSessionFactsError:
            raise WindowsFileReadError("Windows reader principal expectation is invalid") from None


@dataclass(frozen=True)
class WindowsReadObservation:
    outcome: Literal["allowed", "permission_denied"]
    principal: WindowsPrincipalFacts = field(repr=False)
    file_identity: tuple[int, int]
    observed_size: int
    sha256: str | None
    record_count: int | None
    selected_descriptor_sha256: str
    read_handles_closed: bool = True


class _Reader:
    def __init__(self) -> None:
        self.descriptors: list[int] = []

    def principal(self) -> WindowsPrincipalFacts:
        return current_process_principal()

    def open(self, path: str, *, directory: bool, data: bool = False) -> int:
        if len(self.descriptors) >= 6:
            raise WindowsFileReadError("Windows reader handle bound exceeded")
        descriptor = open_observation(Path(path), directory=directory, data=data)
        self.descriptors.append(descriptor)
        return descriptor

    def facts(self, descriptor: int, *, directory: bool) -> WindowsFileFacts:
        return inspect_observation(descriptor, directory=directory)

    def dacl(
        self,
        descriptor: int,
        policy: WindowsFileAccessPolicy,
        state: Literal["readable", "metadata_only", "directory"],
    ) -> str:
        return verify_resource_dacl(_handle_from_descriptor(descriptor), policy, state=state)

    def read(self, descriptor: int, maximum: int) -> bytes:
        return os.read(descriptor, maximum)

    def close(self) -> None:
        failed = False
        for descriptor in reversed(self.descriptors):
            try:
                os.close(descriptor)
            except OSError:
                failed = True
        self.descriptors.clear()
        if failed:
            raise WindowsFileReadError("Windows reader handle cleanup is unknown")


def _current(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise WindowsFileReadError("Windows reader observation deadline exceeded")


def _nonfinite(_value: str) -> None:
    raise WindowsFileReadError("Windows generated records contain a nonfinite value")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise WindowsFileReadError("Windows generated records contain a nonfinite value")
    return number


def _record(line: str, deadline: float) -> None:
    record = json.loads(
        line,
        parse_constant=_nonfinite,
        parse_float=_finite_float,
        object_pairs_hook=_duplicates_rejected,
    )
    if not isinstance(record, dict):
        raise WindowsFileReadError("Windows read contents are not the generated records")
    pending: list[tuple[object, int]] = [(record, 1)]
    while pending:
        _current(deadline)
        value, depth = pending.pop()
        if isinstance(value, (dict, list)):
            if depth > _MAX_RECORD_DEPTH:
                raise WindowsFileReadError("Windows generated record nesting exceeds its limit")
            children = value.values() if isinstance(value, dict) else value
            pending.extend(
                (child, depth + 1) for child in children if isinstance(child, (dict, list))
            )


def _inspect(expectation: WindowsReadExpectation, reader: _Reader) -> WindowsReadObservation:
    resource = expectation.resource
    deadline = time.monotonic() + _MAX_SECONDS
    principal = reader.principal()
    if principal != expectation.principal:
        raise WindowsFileReadError("Windows reader principal differs from enrollment")
    root = f"{_ANCHOR}\\{resource.generation}"
    paths = ("C:\\", "C:\\BlueFire", _ANCHOR, root, root + "\\records.jsonl")
    identities = (*resource.directory_identities, resource.file_identity)
    held, before = [], []
    for index, path in enumerate(paths):
        _current(deadline)
        descriptor = reader.open(path, directory=index < 4)
        held.append(descriptor)
        facts = reader.facts(descriptor, directory=index < 4)
        if (
            facts.identity != identities[index]
            or facts.final_path != "\\\\?\\" + path
            or facts.directory is not (index < 4)
        ):
            raise WindowsFileReadError("Windows resource path or identity changed")
        before.append(facts)
    if before[-1].size != resource.size:
        raise WindowsFileReadError("Windows resource size differs from enrollment")
    _current(deadline)
    root_dacl = reader.dacl(held[3], resource.policy, "directory")
    file_dacl = reader.dacl(held[4], resource.policy, resource.state)
    _current(deadline)
    outcome: Literal["allowed", "permission_denied"] = "allowed"
    digest, records = None, None
    try:
        data = reader.open(paths[-1], directory=False, data=True)
    except WindowsDataOpenDenied:
        outcome = "permission_denied"
    else:
        if reader.facts(data, directory=False) != before[-1]:
            raise WindowsFileReadError("Windows data handle differs from the held resource")
        payload = bytearray()
        while len(payload) <= resource.size:
            _current(deadline)
            chunk = reader.read(data, min(65536, resource.size + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > resource.size:
                raise WindowsFileReadError("Windows data read exceeds the enrolled size")
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        if len(payload) != resource.size or digest != resource.sha256:
            raise WindowsFileReadError("Windows read contents differ from enrollment")
        lines = payload.decode("utf-8").splitlines()
        if not lines:
            raise WindowsFileReadError("Windows read contents are not the generated records")
        for line in lines:
            _record(line, deadline)
        records = len(lines)
        if records != resource.record_count:
            raise WindowsFileReadError("Windows record count differs from enrollment")
        if reader.facts(data, directory=False) != before[-1]:
            raise WindowsFileReadError("Windows data changed during the read")
    for index, descriptor in enumerate(held):
        _current(deadline)
        if reader.facts(descriptor, directory=index < 4) != before[index]:
            raise WindowsFileReadError("Windows held resource changed during observation")
    if (
        reader.dacl(held[3], resource.policy, "directory") != root_dacl
        or reader.dacl(held[4], resource.policy, resource.state) != file_dacl
        or reader.principal() != principal
    ):
        raise WindowsFileReadError("Windows principal or resource DACL changed during observation")
    _current(deadline)
    return WindowsReadObservation(
        outcome, principal, before[-1].identity, before[-1].size, digest, records, file_dacl
    )


def fresh_windows_read(expectation: WindowsReadExpectation) -> WindowsReadObservation:
    """Read only the fixed generated file, under this process's actual identity.

    Current-token equality is not independent launch authentication, and two-ended
    observations do not exclude transient changes restored between checks. This
    function does not implement an enrollment, channel, worker or control change.
    """
    if type(expectation) is not WindowsReadExpectation:
        raise WindowsFileReadError("Windows reader expectation is invalid")
    expectation.validate()
    reader = _Reader()
    try:
        return _inspect(expectation, reader)
    except WindowsFileReadError:
        raise
    except (
        WindowsFileHandleError,
        WindowsFileAccessDaclError,
        WindowsSessionFactsError,
        WindowsOwnerAclError,
        OSError,
        ValueError,
        TypeError,
        RecursionError,
    ):
        raise WindowsFileReadError("Windows reader observation is unavailable") from None
    finally:
        reader.close()
