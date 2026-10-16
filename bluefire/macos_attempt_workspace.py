"""Live original-process custody of a metadata-only Darwin attempt directory."""

from __future__ import annotations

import os
import re
import sys
from _thread import RLock as RLockType
from pathlib import Path
from threading import RLock
from typing import Any

from .evidence import EvidenceError, SandboxObserver
from .util import content_hash

EMPTY_WORKSPACE_SCHEMA = "bluefire.macos-file-access-empty-workspace.v1"
_PHASES = ("reserve", "pre_close", "post_close")


class MacOSAttemptWorkspaceError(EvidenceError):
    pass


class MacOSAttemptWorkspaceGuard:
    """Keep this exact object in memory; serialized attestations cannot restore custody."""

    _pid: int
    _lock: RLockType
    _closed: bool
    _phase: int
    _attempt_id: str
    _lease_digest: str
    _compiled_digest: str
    _observer: SandboxObserver
    _workspace_path_digest: str
    _workspace_identity_digest: str

    def __init__(
        self,
        workspace: str | Path,
        *,
        attempt_id: str,
        lease_digest: str,
        compiled_digest: str,
    ) -> None:
        if sys.platform != "darwin" or os.name != "posix":
            raise MacOSAttemptWorkspaceError("original Darwin workspace inventory is unavailable")
        if (
            type(attempt_id) is not str
            or re.fullmatch(r"attempt-[0-9a-f]{32}", attempt_id) is None
            or any(
                type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
                for value in (lease_digest, compiled_digest)
            )
            or not isinstance(workspace, (str, Path))
            or not Path(workspace).is_absolute()
        ):
            raise MacOSAttemptWorkspaceError("original Darwin workspace binding is invalid")
        self._pid = os.getpid()
        self._lock = RLock()
        self._closed = False
        self._phase = -1
        self._attempt_id = attempt_id
        self._lease_digest = lease_digest
        self._compiled_digest = compiled_digest
        self._observer = SandboxObserver(workspace)
        try:
            self._workspace_path_digest = content_hash({"sandbox_root": str(self._observer.root)})
            initial = self._observer.empty_posix_inventory()
            self._workspace_identity_digest = initial["workspace_identity_digest"]
        except BaseException:
            self._closed = True
            self._observer.close()
            raise

    def _original_process(self) -> None:
        if os.getpid() != self._pid:
            # A fork copy may inherit a held lock. Poison its descriptor before locking.
            self._closed = True
            self._observer.close()
            raise MacOSAttemptWorkspaceError("original Darwin workspace process is unavailable")

    def validate_binding(
        self,
        workspace: str | Path,
        *,
        attempt_id: str,
        lease_digest: str,
        compiled_digest: str,
    ) -> None:
        """Join the live guard to its one-shot claim without advancing attestation."""
        self._original_process()
        with self._lock:
            if self._closed or (
                self._attempt_id != attempt_id
                or self._lease_digest != lease_digest
                or self._compiled_digest != compiled_digest
                or self._workspace_path_digest != content_hash({"sandbox_root": str(workspace)})
            ):
                self._closed = True
                self._observer.close()
                raise MacOSAttemptWorkspaceError("original Darwin workspace binding changed")

    def attest(self, phase: str) -> dict[str, Any]:
        """Re-enumerate at each boundary; repeated current phases never reuse a scan."""
        self._original_process()
        with self._lock:
            if self._closed:
                raise MacOSAttemptWorkspaceError("original Darwin workspace guard is closed")
            if type(phase) is not str or phase not in _PHASES:
                raise MacOSAttemptWorkspaceError("original Darwin workspace phase is invalid")
            index = _PHASES.index(phase)
            if index not in (self._phase, self._phase + 1):
                raise MacOSAttemptWorkspaceError("original Darwin workspace phase is out of order")
            try:
                inventory = self._observer.empty_posix_inventory()
                if inventory != {
                    "entry_count": 0,
                    "workspace_identity_digest": self._workspace_identity_digest,
                }:
                    raise MacOSAttemptWorkspaceError("original Darwin workspace identity changed")
            except BaseException:
                self._closed = True
                self._observer.close()
                raise
            self._phase = index
            return {
                "schema_version": EMPTY_WORKSPACE_SCHEMA,
                "attempt_id": self._attempt_id,
                "lease_digest": self._lease_digest,
                "compiled_digest": self._compiled_digest,
                "workspace_path_digest": self._workspace_path_digest,
                "workspace_identity_digest": self._workspace_identity_digest,
                "phase": phase,
                "entry_count": 0,
                "state": "verified_empty",
            }

    def close(self) -> None:
        """Release only the pinned descriptor, never entries or the directory itself."""
        if os.getpid() != self._pid:
            self._closed = True
            self._observer.close()
            return
        with self._lock:
            self._closed = True
            self._observer.close()
