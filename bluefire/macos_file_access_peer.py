"""Darwin consistency observations of a child already owned by the creator.

Neither process metadata nor a start timestamp adopts a process or mints live
authority. The fixed creator must retain its original Popen and unreaped child.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, NoReturn

from .macos_file_access_clock import MONOTONIC_CLOCK as MONOTONIC_CLOCK
from .macos_file_access_clock import _BSDInfo as _BSDInfo
from .macos_file_access_clock import _refuse as _refuse
from .macos_file_access_clock import _supported_runtime as _supported_runtime
from .macos_file_access_clock import _Timebase as _Timebase
from .macos_file_access_clock import darwin_clock_ns as darwin_clock_ns
from .macos_file_access_contract import MacOSFileAccessContractError

_IDS = ("real_uid", "effective_uid", "saved_uid", "real_gid", "effective_gid", "saved_gid")
_OBSERVATION_REFUSAL_MARKER = object()


def _query_bsd(process_id: int) -> _BSDInfo:
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    query = library.proc_pidinfo
    query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    query.restype = ctypes.c_int
    facts = _BSDInfo()
    if query(process_id, 3, 0, ctypes.byref(facts), ctypes.sizeof(facts)) != ctypes.sizeof(facts):
        _observation_refusal("peer_bsd_query_failed")
    return facts


def _observation_refusal(site: str) -> NoReturn:
    error = _refuse()
    setattr(error, "_safe_startup_observation_site", site)  # noqa: B010
    setattr(error, "_safe_startup_observation_marker", _OBSERVATION_REFUSAL_MARKER)  # noqa: B010
    raise error from None


@dataclass(frozen=True)
class MacOSChildConsistency:
    process_id: int
    parent_id: int
    start: tuple[int, int]
    ids: tuple[int, int, int, int, int, int]

    def identity_document(self) -> dict[str, Any]:
        return {
            "pid": self.process_id,
            "parent_pid": self.parent_id,
            "start_seconds": self.start[0],
            "start_microseconds": self.start[1],
            "ids": dict(zip(_IDS, self.ids, strict=True)),
            "scope": "known_child_consistency_only",
        }


def observe_owned_child(
    process: subprocess.Popen[bytes],
    *,
    expected_ids: Mapping[str, int],
    expected_start: tuple[int, int] | None = None,
) -> MacOSChildConsistency:
    """Check six IDs of an already-retained direct child without reaping it.

    Supplementary groups and executable identity require their separate fixed
    launch/native observations. This function does not establish either one.
    """
    from .runner_client import (
        _darwin_child_exited_without_reap,
        _darwin_child_status_ownership_available,
    )

    try:
        getuid = getattr(os, "getuid", None)
        geteuid = getattr(os, "geteuid", None)
        if not _supported_runtime():
            _observation_refusal("peer_runtime_unsupported")
        if not callable(getuid):
            _observation_refusal("peer_uid_api_missing")
        if not callable(geteuid):
            _observation_refusal("peer_euid_api_missing")
        if getuid() != 0:
            _observation_refusal("peer_real_uid_not_root")
        if geteuid() != 0:
            _observation_refusal("peer_effective_uid_not_root")
        if not isinstance(process, subprocess.Popen):
            _observation_refusal("peer_process_type_invalid")
        if type(process.pid) is not int:
            _observation_refusal("peer_pid_type_invalid")
        if not 1 < process.pid < 2**31:
            _observation_refusal("peer_pid_out_of_range")
        if process.returncode is not None:
            _observation_refusal("peer_process_already_reaped")
        if not _darwin_child_status_ownership_available():
            _observation_refusal("peer_status_ownership_unavailable_initial")
        if set(expected_ids) != set(_IDS):
            _observation_refusal("peer_identity_keys_invalid")
        if any(
            type(value) is not int or not 0 < value < 2**32 - 1 for value in expected_ids.values()
        ):
            _observation_refusal("peer_identity_value_invalid")
        if (
            not expected_ids["real_uid"]
            == expected_ids["effective_uid"]
            == expected_ids["saved_uid"]
        ):
            _observation_refusal("peer_uid_mismatch")
        if (
            not expected_ids["real_gid"]
            == expected_ids["effective_gid"]
            == expected_ids["saved_gid"]
        ):
            _observation_refusal("peer_gid_mismatch")
        if expected_start is not None:
            if type(expected_start) is not tuple:
                _observation_refusal("peer_expected_start_invalid")
            if len(expected_start) != 2:
                _observation_refusal("peer_expected_start_invalid")
            if any(type(value) is not int for value in expected_start):
                _observation_refusal("peer_expected_start_invalid")
            if not 0 < expected_start[0] < 2**64:
                _observation_refusal("peer_expected_start_invalid")
            if not 0 <= expected_start[1] < 1_000_000:
                _observation_refusal("peer_expected_start_invalid")
        if _darwin_child_exited_without_reap(process.pid):
            _observation_refusal("peer_child_exited_before_query")
        parent = os.getpid()
        facts = _query_bsd(process.pid)
        ids = (
            facts.real_uid,
            facts.uid,
            facts.saved_uid,
            facts.real_gid,
            facts.gid,
            facts.saved_gid,
        )
        start = (facts.start_seconds, facts.start_microseconds)
        if facts.pid != process.pid:
            _observation_refusal("peer_pid_mismatch")
        if facts.parent_pid != parent:
            _observation_refusal("peer_parent_mismatch")
        if not facts.flags & 0x10:
            _observation_refusal("peer_status_flags_missing")
        if facts.flags & 0x7:
            _observation_refusal("peer_status_flags_invalid")
        if not 1 <= facts.status <= 4:
            _observation_refusal("peer_status_invalid")
        if ids != tuple(expected_ids[key] for key in _IDS):
            _observation_refusal("peer_observed_ids_mismatch")
        if not start[0]:
            _observation_refusal("peer_start_invalid")
        if not 0 <= start[1] < 1_000_000:
            _observation_refusal("peer_start_invalid")
        if expected_start is not None and start != expected_start:
            _observation_refusal("peer_start_mismatch")
        if process.returncode is not None:
            _observation_refusal("peer_process_reaped_after_query")
        if not _darwin_child_status_ownership_available():
            _observation_refusal("peer_status_ownership_unavailable_after_query")
        if _darwin_child_exited_without_reap(process.pid):
            _observation_refusal("peer_child_exited_after_query")
        return MacOSChildConsistency(process.pid, parent, start, ids)
    except MacOSFileAccessContractError as exc:
        if getattr(exc, "_safe_startup_observation_marker", None) is _OBSERVATION_REFUSAL_MARKER:
            raise
        raise _refuse() from None
    except (AttributeError, ChildProcessError, OSError, OverflowError, TypeError, ValueError):
        _observation_refusal("unknown")
