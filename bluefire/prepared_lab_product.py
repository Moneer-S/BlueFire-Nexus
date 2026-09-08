"""Fixed, final-exec UI entry: protect first, receive exactly one owned channel."""

from __future__ import annotations

import os
import sys

from .ai_broker import BrokeredAIProviderAccess
from .ai_broker_bootstrap import (
    adopt_bootstrap,
    adopt_inference,
    protect_process,
    receive_bootstrap,
    send_bootstrap,
)
from .ai_broker_channel import SocketBrokerChannel
from .ai_broker_contract import refusal
from .prepared_lab_enrollment import product_config, read_enrollment
from .prepared_lab_runtime import HOME
from .runner_linux_containment import LinuxPrivateProcessContainment


def run(port: int, bootstrap_fd: int, launch_id: str) -> int:
    protect_process(1000, parent=1)
    endpoint = adopt_bootstrap(bootstrap_fd)
    descriptor = None
    access = None
    try:
        identity = LinuxPrivateProcessContainment.process_identity(os.getpid())
        send_bootstrap(
            endpoint,
            {
                "kind": "armed",
                "launch_id": launch_id,
                "process_id": identity[0],
                "creation_identity": identity[1],
            },
        )
        frame, descriptor = receive_bootstrap(
            endpoint, expected_uid=1000, expected_pid=1, descriptor_required=True
        )
        if (
            set(frame) != {"kind", "launch_id", "enrollment"}
            or frame["kind"] != "grant"
            or frame["launch_id"] != launch_id
        ):
            raise refusal()
        enrollment = read_enrollment(frame["enrollment"])
        if descriptor is None:
            raise refusal()
        owned_fd, descriptor = descriptor, None
        access = BrokeredAIProviderAccess(
            enrollment, SocketBrokerChannel(adopt_inference(owned_fd))
        )
        send_bootstrap(
            endpoint,
            {"kind": "bound", "launch_id": launch_id, "enrollment_digest": enrollment.digest},
        )
        admitted, _ = receive_bootstrap(endpoint, expected_uid=1000, expected_pid=1)
        if admitted != {
            "kind": "admit",
            "launch_id": launch_id,
            "enrollment_digest": enrollment.digest,
        }:
            raise refusal()
    except BaseException:
        if access is not None:
            access.close()
        raise
    finally:
        endpoint.close()
        if descriptor is not None:
            os.close(descriptor)
    try:
        from .cli import main

        return main(
            [
                "--runs-dir",
                str(HOME / "experiments"),
                "ui",
                "--no-browser",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            ai_provider_access=access,
            config=product_config(enrollment),
        )
    finally:
        access.close()


def main() -> None:
    try:
        if len(sys.argv) != 4:
            raise refusal()
        port, descriptor = int(sys.argv[1]), int(sys.argv[2])
        if not 1024 <= port <= 65535 or len(sys.argv[3]) != 64:
            raise refusal()
        result = run(port, descriptor, sys.argv[3])
    except Exception:
        # No source/configuration/body/credential or traceback on this channel.
        result = 2
    raise SystemExit(result)


if __name__ == "__main__":
    main()
