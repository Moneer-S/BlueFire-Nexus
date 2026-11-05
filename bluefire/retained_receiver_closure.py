"""Prove closure of one saved Linux receiver generation after parent loss."""

from __future__ import annotations

import os
import signal
import sys
import time

from .runner_linux_containment import LinuxPrivateProcessContainment

_TERM_GRACE_SECONDS = 2.0
_KILL_GRACE_SECONDS = 3.0
_POLL_SECONDS = 0.025
_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)


def close_exact_receiver(process_id: int, creation_identity: str) -> dict[str, object]:
    """Signal only an exact pidfd identity; inspect the whole original session."""
    if not sys.platform.startswith("linux") or not LinuxPrivateProcessContainment.available():
        raise OSError("exact receiver process closure is unavailable on this platform")
    if (
        type(process_id) is not int
        or process_id <= 1
        or not isinstance(creation_identity, str)
        or not creation_identity.isdecimal()
        or int(creation_identity) <= 0
    ):
        raise OSError("exact receiver process identity is invalid")

    def leader():
        try:
            identity = LinuxPrivateProcessContainment.process_identity(process_id)
        except ProcessLookupError:
            return None
        if str(identity[1]) != creation_identity or identity[2:] != (process_id, process_id):
            raise OSError("receiver process identity changed or no longer owns its session")
        return identity

    def members() -> list[tuple[int, int, int, int]]:
        before = leader()
        result = []
        with os.scandir("/proc") as entries:
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                try:
                    identity = LinuxPrivateProcessContainment.process_identity(int(entry.name))
                except ProcessLookupError:
                    continue
                if identity[3] == process_id:
                    result.append(identity)
        after = leader()
        if after is None and len(result) == 1 and result[0][0] == process_id:
            # The reaper may remove the final leader after it was enumerated.
            # No descendant is authorized here; the caller still rescans empty.
            return []
        if result and (before is None or after is None):
            raise OSError("receiver session leader is absent; member ownership is unknown")
        return result

    term_deadline = time.monotonic() + _TERM_GRACE_SECONDS
    deadline = term_deadline + _KILL_GRACE_SECONDS
    while True:
        current = members()
        if not current:
            # Reinspect after the first empty scan; a late descendant must not
            # turn a partial directory enumeration into a closure proof.
            current = members()
            if not current:
                if leader() is not None:
                    raise OSError("receiver generation is still live")
                break
        now = time.monotonic()
        if now >= deadline:
            raise OSError("receiver session still has live members")
        signum = signal.SIGTERM if now < term_deadline else _KILL_SIGNAL
        # Keep the exact leader as the session-generation anchor until every
        # descendant is gone; a numeric SID alone cannot authorize orphan kills.
        descendants = [identity for identity in current if identity[0] != process_id]
        for identity in descendants or current:
            if leader() is None:
                raise OSError("receiver session leader is absent; member ownership is unknown")
            if not LinuxPrivateProcessContainment._signal_identity(identity, signum):
                raise OSError("exact receiver session member could not be stopped")
        time.sleep(_POLL_SECONDS)
    return {
        "schema_version": "bluefire.receiver-closure-proof.v1",
        "process_id": process_id,
        "creation_identity": creation_identity,
        "session_member_count": 0,
        "verified_closed": True,
    }
