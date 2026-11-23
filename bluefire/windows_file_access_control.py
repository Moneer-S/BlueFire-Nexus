"""Finite owner DACL transition for the fixed enrolled generated resource.

Not a registered capability or permission grant. Trusted orchestration must
serialize control changes, own a hard worker deadline and journal dispatch for
reconciliation. Native pre/post checks are not an atomic compare-and-swap.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import time
from ctypes import wintypes
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Literal

from . import windows_owner_acl as native
from .windows_file_access_dacl import WindowsReaderMaskMismatch
from .windows_file_access_handles import WindowsFileFacts
from .windows_file_access_policy import WindowsFileAccessPolicy
from .windows_file_access_read import _ANCHOR, WindowsResourceExpectation, _Reader
from .windows_session_facts import WindowsPrincipalFacts


class WindowsControlError(RuntimeError):
    """Preserve uncertainty after attempted mutation; never silently replay it."""

    def __init__(self, *, change_may_have_occurred: bool):
        self.change_may_have_occurred = change_may_have_occurred
        super().__init__(
            "Windows file control needs reconciliation"
            if change_may_have_occurred
            else "Windows file control preconditions are unavailable"
        )


@dataclass(frozen=True)
class WindowsControlRequest:
    resource: WindowsResourceExpectation = field(repr=False)
    owner: WindowsPrincipalFacts = field(repr=False)
    previous_descriptor_sha256: str
    target: Literal["readable", "metadata_only"]

    def validate(self) -> None:
        if (
            type(self.resource) is not WindowsResourceExpectation
            or type(self.owner) is not WindowsPrincipalFacts
            or self.owner.user_sid != self.resource.policy.owner_sid
            or self.owner.elevated is not False
            or self.target not in ("readable", "metadata_only")
            or self.target == self.resource.state
            or type(self.previous_descriptor_sha256) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.previous_descriptor_sha256) is None
        ):
            raise WindowsControlError(change_may_have_occurred=False)
        self.resource.validate()
        self.owner.validate()


@dataclass(frozen=True)
class WindowsControlObservation:
    before_descriptor_sha256: str
    after_descriptor_sha256: str
    target: Literal["readable", "metadata_only"]
    file_identity: tuple[int, int]
    preserved_sha256: str
    fresh_owner_read: bool
    read_handles_closed: bool


@dataclass(frozen=True)
class WindowsControlReconciliation:
    state: Literal["original_observed", "target_observed"]
    descriptor_sha256: str
    file_identity: tuple[int, int]
    preserved_sha256: str
    fresh_owner_read: bool
    read_handles_closed: bool


def _set_selected_dacl(
    handle: int, policy: WindowsFileAccessPolicy, target: Literal["readable", "metadata_only"]
) -> None:
    descriptor = ctypes.c_void_p()
    security, kernel = native._configure_apis()
    try:
        text = policy.file_sddl(target)
        if (
            not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text, 1, ctypes.byref(descriptor), None
            )
            or not descriptor.value
        ):
            raise OSError("Descriptor conversion unavailable")
        dacl = native._descriptor_dacl(security, descriptor)
        if not dacl.value:
            raise OSError("Null DACL refused")
        # Only the protected DACL is changed. Owner, group and SACL are untouched;
        # these exact noninherited file ACEs cannot propagate to descendants.
        if (
            security.SetSecurityInfo(wintypes.HANDLE(handle), 1, 0x80000004, None, None, dacl, None)
            != 0
        ):
            raise OSError("Selected DACL application unavailable")
    finally:
        if descriptor.value and kernel.LocalFree(descriptor):
            raise OSError("Descriptor cleanup unavailable")


class _Controller(_Reader):
    def open_control(self, path: str) -> int:
        if len(self.descriptors) != 4:
            raise OSError("Control ancestors are not held")
        descriptor = native._windows_open_descriptor(Path(path), directory=False, write_dac=True)
        self.descriptors.append(descriptor)
        return descriptor

    def seek(self, descriptor: int) -> None:
        if os.lseek(descriptor, 0, os.SEEK_SET) != 0:
            raise OSError("Resource read position is unavailable")

    def apply(
        self,
        descriptor: int,
        policy: WindowsFileAccessPolicy,
        target: Literal["readable", "metadata_only"],
    ) -> None:
        _set_selected_dacl(native._handle_from_descriptor(descriptor), policy, target)


def _current(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise OSError("Control observation deadline exceeded")


def _read_contents(
    controller: _Controller, descriptor: int, resource: WindowsResourceExpectation, deadline: float
) -> str:
    controller.seek(descriptor)
    length, digest = 0, hashlib.sha256()
    while length <= resource.size:
        _current(deadline)
        chunk = controller.read(descriptor, min(65536, resource.size + 1 - length))
        if not chunk:
            break
        length += len(chunk)
        digest.update(chunk)
    result = "sha256:" + digest.hexdigest()
    if length != resource.size or result != resource.sha256:
        raise OSError("Original contents are not preserved")
    return result


def _held_resource(
    controller: _Controller,
    resource: WindowsResourceExpectation,
    deadline: float,
    *,
    write_dac: bool,
) -> tuple[list[int], list[WindowsFileFacts], tuple[str, ...]]:
    root = _ANCHOR + "\\" + resource.generation
    paths = ("C:\\", "C:\\BlueFire", _ANCHOR, root, root + "\\records.jsonl")
    identities = (*resource.directory_identities, resource.file_identity)
    held, before = [], []
    for index, path in enumerate(paths):
        _current(deadline)
        if index < 4:
            descriptor = controller.open(path, directory=True)
        elif write_dac:
            descriptor = controller.open_control(path)
        else:
            descriptor = controller.open(path, directory=False, data=True)
        held.append(descriptor)
        facts = controller.facts(descriptor, directory=index < 4)
        if (
            facts.identity != identities[index]
            or facts.final_path != "\\\\?\\" + path
            or facts.directory is not (index < 4)
        ):
            raise OSError("Resource identity changed")
        before.append(facts)
    if before[-1].size != resource.size:
        raise OSError("Resource size changed")
    return held, before, paths


def transition_windows_file_access(
    request: WindowsControlRequest,
    *,
    admit: Callable[[], None],
    before_apply: Callable[[], None] | None = None,
) -> WindowsControlObservation:
    """Apply one already-authorized original change, without rollback or retry.

    Admission must bind the original task, generation, prior descriptor and target
    and journal the upcoming effect. A returned result verifies a DACL and fresh
    owner read, NOT separate-reader denial. Failure after dispatch requires fresh
    reconciliation; another call is never an automatic recovery operation.
    An optional original-operation guard runs after post-admission metadata,
    immediately before the setter; it cannot replace or repeat admission.
    """
    controller = _Controller()
    changed = False
    try:
        if (
            type(request) is not WindowsControlRequest
            or not callable(admit)
            or (before_apply is not None and not callable(before_apply))
        ):
            raise WindowsControlError(change_may_have_occurred=False)
        request.validate()
        resource = request.resource
        deadline = time.monotonic() + 5.0
        if controller.principal() != request.owner:
            raise OSError("Owner principal differs from enrollment")
        held, before, paths = _held_resource(controller, resource, deadline, write_dac=True)
        root_dacl = controller.dacl(held[3], resource.policy, "directory")
        previous = controller.dacl(held[4], resource.policy, resource.state)
        if previous != request.previous_descriptor_sha256:
            raise OSError("Original descriptor changed")
        _read_contents(controller, held[4], resource, deadline)
        admit()
        _current(deadline)
        # Recheck after caller admission, immediately before the sole mutation.
        if controller.principal() != request.owner:
            raise OSError("Owner changed before dispatch")
        for index, descriptor in enumerate(held):
            if controller.facts(descriptor, directory=index < 4) != before[index]:
                raise OSError("Held resource changed before dispatch")
        if (
            controller.dacl(held[3], resource.policy, "directory") != root_dacl
            or controller.dacl(held[4], resource.policy, resource.state) != previous
        ):
            raise OSError("Resource permissions changed before dispatch")
        if before_apply is not None:
            before_apply()
        _current(deadline)
        changed = True
        controller.apply(held[4], resource.policy, request.target)
        _current(deadline)
        after_dacl = controller.dacl(held[4], resource.policy, request.target)
        fresh = controller.open(paths[-1], directory=False, data=True)
        after = controller.facts(fresh, directory=False)
        if replace(after, changed=before[-1].changed) != before[-1]:
            raise OSError("Resource changed beyond the selected DACL")
        digest = _read_contents(controller, fresh, resource, deadline)
        for index, descriptor in enumerate(held):
            expected = before[index] if index < 4 else after
            if controller.facts(descriptor, directory=index < 4) != expected:
                raise OSError("Resource changed during verification")
        if (
            controller.facts(fresh, directory=False) != after
            or controller.dacl(held[3], resource.policy, "directory") != root_dacl
            or controller.dacl(held[4], resource.policy, request.target) != after_dacl
            or controller.principal() != request.owner
        ):
            raise OSError("Control verification changed")
        _current(deadline)
        return WindowsControlObservation(
            previous, after_dacl, request.target, after.identity, digest, True, True
        )
    except Exception:
        raise WindowsControlError(change_may_have_occurred=changed) from None
    finally:
        try:
            controller.close()
        except Exception:
            raise WindowsControlError(change_may_have_occurred=changed) from None


def reconcile_windows_file_access(request: WindowsControlRequest) -> WindowsControlReconciliation:
    """Read current original-resource state; never retry or undo an old effect.

    A recognized state is not causal attribution to the prior operation or
    proof of the distinct reader's effective access. Drift and failed cleanup
    remain unresolved. Trusted original-task recovery admission belongs to the
    caller; no new authority or enrollment is issued by this observation.
    """
    controller = _Controller()
    try:
        if type(request) is not WindowsControlRequest:
            raise OSError("Original control request is unavailable")
        request.validate()
        resource = request.resource
        deadline = time.monotonic() + 5.0
        if controller.principal() != request.owner:
            raise OSError("Owner principal differs from enrollment")
        held, before, _ = _held_resource(controller, resource, deadline, write_dac=False)
        root_dacl = controller.dacl(held[3], resource.policy, "directory")
        state: Literal["original_observed", "target_observed"]
        try:
            descriptor = controller.dacl(held[4], resource.policy, resource.state)
        except WindowsReaderMaskMismatch:
            descriptor = controller.dacl(held[4], resource.policy, request.target)
            selected, state = request.target, "target_observed"
        else:
            if descriptor != request.previous_descriptor_sha256:
                raise OSError("Original descriptor changed beyond its enrolled digest")
            selected, state = resource.state, "original_observed"
        digest = _read_contents(controller, held[4], resource, deadline)
        for index, handle in enumerate(held):
            if controller.facts(handle, directory=index < 4) != before[index]:
                raise OSError("Recovery resource changed during observation")
        if (
            controller.dacl(held[3], resource.policy, "directory") != root_dacl
            or controller.dacl(held[4], resource.policy, selected) != descriptor
            or controller.principal() != request.owner
        ):
            raise OSError("Recovery observation changed")
        _current(deadline)
        return WindowsControlReconciliation(
            state, descriptor, before[-1].identity, digest, True, True
        )
    except Exception:
        raise WindowsControlError(change_may_have_occurred=True) from None
    finally:
        try:
            controller.close()
        except Exception:
            raise WindowsControlError(change_may_have_occurred=True) from None
