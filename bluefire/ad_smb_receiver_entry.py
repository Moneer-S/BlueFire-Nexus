"""Explicit installed AD receiver entry; no discovery, enrollment or launcher.

Only an owner-provisioned receiver.json at the fixed managed product location
can be used. Starting this module is effectful and is not invoked by the UI.
Local listener/worker/ledger cleanup is distinct from remote SMB session state.
"""

from __future__ import annotations

import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ad_smb_admitted_transport import AdmittedAdSmbReceiver, _admission, _profile
from .ad_smb_channel import AdSmbHostChannel
from .ad_smb_contract import AdSmbError, AdSmbScope, document, exact, timestamp
from .runner_bootstrap import managed_product_root
from .runner_client import SubprocessRustRunner
from .runner_trust import _PinnedDirectory, _validated_enrollment_root


def _configuration(root: Path) -> tuple[dict[str, Any], AdSmbScope, AdSmbHostChannel]:
    with _PinnedDirectory(_validated_enrollment_root(root), private=True) as directory:
        row = document(directory.read("receiver.json", maximum=131072), limit=131072)
    exact(
        row,
        {
            "schema_version",
            "scope",
            "channel",
            "profile",
            "runner_binary",
            "credential_binding_digest",
        },
        "Installed AD receiver",
    )
    if row["schema_version"] != "bluefire.ad-smb-receiver-config.v1":
        raise AdSmbError("Installed AD receiver configuration is invalid.")
    scope = AdSmbScope.from_mapping(row["scope"])
    scope.assert_current(lambda: datetime.now(timezone.utc))
    channel = AdSmbHostChannel.from_mapping(scope, row["channel"])
    channel.assert_current(datetime.now(timezone.utc))
    _profile(scope, channel, row["profile"])
    _admission(channel, row["credential_binding_digest"])
    if not isinstance(row["runner_binary"], str) or not Path(row["runner_binary"]).is_absolute():
        raise AdSmbError("Installed AD native path must be exact and absolute.")
    return row, scope, channel


def serve_installed(stop: threading.Event) -> None:
    """Serve only the fixed existing role configuration until stop or original expiry."""
    if sys.platform != "win32":
        raise AdSmbError("AD installed receivers require Windows.")
    if stop.is_set():
        return
    root = managed_product_root() / "ad-smb" / "receiver"
    row, scope, channel = _configuration(root)
    end = min(timestamp(scope.to_dict()["expires_at"]), timestamp(channel.to_dict()["expires_at"]))
    remaining = (end - datetime.now(timezone.utc)).total_seconds()
    if not 0 < remaining <= 86400:
        raise AdSmbError("AD installed receiver lifetime is invalid.")
    deadline = time.monotonic() + remaining
    work = _validated_enrollment_root(Path(row["profile"]["sandbox_root"]))
    receiver = None
    try:
        with _PinnedDirectory(work, private=True):
            runner = SubprocessRustRunner(
                row["runner_binary"],
                work,
                timeout_seconds=scope.to_dict()["limits"]["operation_seconds"],
                output_limit_bytes=1024 * 1024,
            )
            if stop.is_set():
                return
            receiver = AdmittedAdSmbReceiver(
                root / "enrollment",
                runner,
                state_path=root / "transport.sqlite3",
                scope=scope,
                channel=channel,
                profile=row["profile"],
                credential_root=(
                    root / "credentials" if channel.to_dict()["role"] == "client" else None
                ),
                credential_binding_digest=row["credential_binding_digest"],
            )
        if stop.is_set() or time.monotonic() >= deadline or datetime.now(timezone.utc) >= end:
            return
        receiver.start()
        while not stop.is_set() and not receiver._stop.is_set():
            left = min(
                deadline - time.monotonic(), (end - datetime.now(timezone.utc)).total_seconds()
            )
            if left <= 0:
                break
            stop.wait(min(left, 0.25))
    finally:
        if receiver is not None:
            receiver.shutdown()
            with receiver._workers_lock:
                workers = bool(receiver._workers)
            if (
                receiver._listener.fileno() != -1
                or receiver._ledger_lock is not None
                or workers
                or (receiver._serve_thread is not None and receiver._serve_thread.is_alive())
            ):
                raise AdSmbError("AD receiver stopped with unverified owned cleanup.")


def main() -> int:
    if len(sys.argv) != 1:
        return 2
    stop = threading.Event()
    previous = {}
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, lambda *_: stop.set())
        serve_installed(stop)
        return 0
    except Exception:
        # Never serialize configuration, private paths, provider errors or keys.
        print("AD receiver unavailable or owned cleanup unverified.", file=sys.stderr)
        return 2
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
