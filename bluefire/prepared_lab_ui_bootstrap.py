"""Transfer the exact UI channel only after final-exec process protection."""

from __future__ import annotations

import os
import secrets
import socket
import subprocess  # nosec B404
from typing import cast

from .ai_broker_bootstrap import (
    adopt_bootstrap,
    adopt_inference,
    bootstrap_pair,
    protected_identity,
    receive_bootstrap,
    send_bootstrap,
)
from .ai_broker_contract import refusal
from .prepared_lab_enrollment import read_enrollment
from .prepared_lab_runtime import ENV, HOME, PYTHON, stop_child
from .runner_linux_containment import LinuxPrivateProcessContainment

_RETAINED: list[subprocess.Popen[bytes]] = []


def start_ui(port: int, bootstrap_fd: int, launch: str) -> subprocess.Popen[bytes]:
    if _RETAINED:
        raise refusal("broker_unavailable")
    endpoint = adopt_bootstrap(bootstrap_fd)
    inference_fd = None
    inference: socket.socket | None = None
    parent = child = None
    process = None
    try:
        identity = LinuxPrivateProcessContainment.process_identity(os.getpid())
        send_bootstrap(
            endpoint,
            {
                "kind": "armed",
                "launch_id": launch,
                "process_id": 1,
                "creation_identity": identity[1],
            },
        )
        frame, inference_fd = receive_bootstrap(
            endpoint, expected_uid=0, expected_pid=0, descriptor_required=True
        )
        if (
            set(frame) != {"kind", "launch_id", "enrollment"}
            or frame["kind"] != "grant"
            or frame["launch_id"] != launch
        ):
            raise refusal()
        enrollment = read_enrollment(frame["enrollment"])
        if inference_fd is None:
            raise refusal()
        owned_fd, inference_fd = inference_fd, None
        inference = adopt_inference(owned_fd)
        parent, child = bootstrap_pair()
        ui_launch = secrets.token_hex(32)
        process = cast(subprocess.Popen[bytes], subprocess.Popen.__new__(subprocess.Popen))
        _RETAINED.append(process)
        subprocess.Popen.__init__(
            process,
            [
                str(PYTHON),
                "-I",
                "-B",
                "-m",
                "bluefire.prepared_lab_product",
                str(port),
                str(child.fileno()),
                ui_launch,
            ],
            stdin=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            pass_fds=(child.fileno(),),
            start_new_session=True,
            env=ENV,
            cwd=HOME,
        )
        child.close()
        before = LinuxPrivateProcessContainment.process_identity(process.pid)
        armed, _ = receive_bootstrap(parent, expected_uid=1000, expected_pid=process.pid)
        if protected_identity(process.pid, 1000) != before or dict(armed) != {
            "kind": "armed",
            "launch_id": ui_launch,
            "process_id": process.pid,
            "creation_identity": before[1],
        }:
            raise refusal()
        send_bootstrap(
            parent,
            {"kind": "grant", "launch_id": ui_launch, "enrollment": frame["enrollment"]},
            descriptor=inference.fileno(),
        )
        bound, _ = receive_bootstrap(parent, expected_uid=1000, expected_pid=process.pid)
        if (
            bound
            != {"kind": "bound", "launch_id": ui_launch, "enrollment_digest": enrollment.digest}
            or protected_identity(process.pid, 1000) != before
        ):
            raise refusal()
        inference.close()
        inference = None
        send_bootstrap(
            endpoint, {"kind": "bound", "launch_id": launch, "enrollment_digest": enrollment.digest}
        )
        admitted, _ = receive_bootstrap(endpoint, expected_uid=0, expected_pid=0)
        if admitted != {
            "kind": "admit",
            "launch_id": launch,
            "enrollment_digest": enrollment.digest,
        }:
            raise refusal()
        send_bootstrap(
            parent,
            {"kind": "admit", "launch_id": ui_launch, "enrollment_digest": enrollment.digest},
        )
        parent.close()
        _RETAINED.remove(process)
        return process
    except BaseException:
        if process is not None and getattr(process, "pid", None) is not None:
            stop_child(process)
            _RETAINED.remove(process)
        raise
    finally:
        for channel in (endpoint, parent, child, inference):
            if channel is not None:
                channel.close()
        if inference_fd is not None:
            os.close(inference_fd)
