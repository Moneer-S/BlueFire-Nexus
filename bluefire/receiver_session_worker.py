"""Fixed Linux disposable receiver worker; no caller code, files, or credentials."""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent.parent))

from bluefire.receiver import LoopbackArtifactReceiver, ReceiverConfig
from bluefire.receiver_policy import ReceiverContentPolicy
from bluefire.receiver_session_channel import read_frame, write_frame
from bluefire.receiver_session_contract import (
    SESSION_SECONDS,
    ready_binding,
    validate_prepare,
    validate_task,
    worker_generation,
)
from bluefire.runner_bootstrap import managed_product_root
from bluefire.runner_linux_containment import LinuxPrivateProcessContainment
from bluefire.runner_trust import load_local_enrollment
from bluefire.util import content_hash


def run(arguments: list[str]) -> int:
    if (
        not sys.platform.startswith("linux")
        or len(arguments) != 4
        or arguments[0] != "--parent"
        or arguments[2] != "--launch"
        or re.fullmatch(r"[1-9][0-9]{0,9}", arguments[1]) is None
        or re.fullmatch(r"[0-9a-f]{64}", arguments[3]) is None
    ):
        return 74
    parent = int(arguments[1])
    launch = arguments[3]
    # The existing Linux primitive checks the parent on both sides of prctl.
    from bluefire.runner_parent_death import _arm_parent_death

    if parent <= 1 or not _arm_parent_death(parent):
        return 74
    startup_deadline = time.monotonic_ns() + 10_000_000_000
    write_frame(
        1,
        {
            "kind": "armed",
            "launch_id": launch,
            "process_id": os.getpid(),
            "parent_process_id": parent,
        },
    )
    prepared = validate_prepare(
        read_frame(0, deadline_ns=startup_deadline),
        launch_id=launch,
        generation=worker_generation(),
        now_ns=time.monotonic_ns(),
    )
    if os.getppid() != parent:
        return 74
    # No enrollment read or listener creation occurs before the owned parent
    # confirms registration by sending the exact prepare frame.
    enrollment = load_local_enrollment(managed_product_root() / "enrollment", require_active=True)
    key = enrollment.hmac_key()
    policy = ReceiverContentPolicy(prepared["policy"]["policy_id"])
    with LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=key,
            host="127.0.0.1",
            port=prepared["port"],
            disposable_peer=True,
            max_connections=8,
            max_body_bytes=1024 * 1024,
            idle_timeout_seconds=float(SESSION_SECONDS),
            content_policy=policy.policy_id,
        )
    ) as receiver:
        identity = LinuxPrivateProcessContainment.process_identity(os.getpid())
        binding = ready_binding(
            prepared,
            session_id=receiver.session_id,
            process_id=os.getpid(),
            creation_identity=str(identity[1]),
        )
        write_frame(1, {"kind": "ready", "binding": binding})
        task = validate_task(
            read_frame(0, deadline_ns=prepared["deadline_ns"]), binding, now_ns=time.monotonic_ns()
        )
        if os.getppid() != parent or worker_generation() != prepared["worker_generation"]:
            return 74
        receiver.bind_policy_task(
            task["task_id"],
            task["sha256"],
            task["size_bytes"],
            deadline=prepared["deadline_ns"] / 1_000_000_000,
        )
        write_frame(
            1,
            {
                "kind": "bound",
                "review_digest": binding["review_digest"],
                "task_digest": content_hash(task),
            },
        )

        def watch_parent() -> None:
            try:
                os.read(0, 1)  # EOF or any extra frame stops the single-use session.
            finally:
                receiver.stop()

        threading.Thread(target=watch_parent, name="bluefire-receiver-parent", daemon=True).start()
        summary = receiver.serve()
        decisions = receiver.policy_decisions
        if len(decisions) > 1:
            return 74
        write_frame(
            1,
            {
                "kind": "terminal",
                "review_digest": binding["review_digest"],
                "task_digest": content_hash(task),
                "summary": dict(summary),
                "decision": dict(decisions[0]) if decisions else None,
            },
        )
    return 0


def main() -> int:
    try:
        return run(sys.argv[1:])
    except (Exception, KeyboardInterrupt):
        # The owned parent reports an unavailable observation and reconciles
        # the exact process. Never send traceback, local paths, or key values.
        return 74


if __name__ == "__main__":
    raise SystemExit(main())
