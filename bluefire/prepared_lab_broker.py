"""Fixed clone-local inference owner; the target's network namespace is unchanged."""

from __future__ import annotations

import os
import secrets
import socket
import subprocess  # nosec B404
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, cast

from .ai_broker_bootstrap import (
    adopt_bootstrap,
    adopt_inference,
    bootstrap_pair,
    protect_process,
    protected_identity,
    receive_bootstrap,
    send_bootstrap,
)
from .ai_broker_channel import FramedSocket
from .ai_broker_contract import refusal
from .ai_broker_worker import serve_broker
from .ai_transport import ManagedAIJSONTransport
from .ai_wire import AIProviderTransportError
from .config import AIProviderConfig
from .prepared_lab_enrollment import enroll, enrollment_document, read_enrollment
from .prepared_lab_installation import verify_installation
from .prepared_lab_runtime import ENV, HOME, PYTHON, ROOT, STOP_FILE, guest_command, namespaces, uid
from .runner_linux_containment import LinuxPrivateProcessContainment

_RETAINED: list["OwnedProcesses"] = []
BROKER_HOME = str(HOME.with_name("bluefire-broker"))


def command(mode: str, port: int, descriptor: int, launch: str, parent: int) -> list[str]:
    if mode not in {"launch-worker", "launch-target", "worker-enter", "worker"}:
        raise refusal()
    return [
        str(PYTHON),
        "-I",
        "-B",
        "-m",
        "bluefire.prepared_lab_broker",
        mode,
        str(port),
        str(descriptor),
        launch,
        str(parent),
    ]


class OwnedProcesses:
    """Retain exact process objects through failed construction or failed drain."""

    def __init__(self) -> None:
        self.containment = LinuxPrivateProcessContainment()
        self.processes: list[subprocess.Popen[bytes]] = []
        self.channels: list[socket.socket] = []

    def spawn(
        self, role: str, port: int, endpoint: socket.socket, launch: str
    ) -> subprocess.Popen[bytes]:
        if role not in {"launch-worker", "launch-target"} or not self.containment.available():
            raise refusal()
        process = cast(subprocess.Popen[bytes], subprocess.Popen.__new__(subprocess.Popen))
        self.processes.append(process)
        subprocess.Popen.__init__(
            process,
            command(role, port, endpoint.fileno(), launch, os.getpid()),
            stdin=subprocess.DEVNULL if role == "launch-worker" else sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
            shell=False,
            close_fds=True,
            pass_fds=(endpoint.fileno(),),
            start_new_session=True,
            env=ENV,
            cwd=ROOT,
        )
        self.containment.register(process)
        return process

    def close(self) -> bool:
        complete = True
        for channel in tuple(self.channels):
            try:
                channel.close()
                self.channels.remove(channel)
            except OSError:
                complete = False
        for process in reversed(tuple(self.processes)):
            try:
                if self.containment.contains(process):
                    good = self.containment.release(process, terminate=True)
                elif getattr(process, "pid", None) is not None:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
                    good = True
                else:
                    good = True
                if good:
                    self.processes.remove(process)
                else:
                    complete = False
            except (OSError, RuntimeError, subprocess.SubprocessError):
                complete = False
        if (self.processes or self.channels) and self not in _RETAINED:
            _RETAINED.append(self)
        elif not self.processes and not self.channels and self in _RETAINED:
            _RETAINED.remove(self)
        return complete and not self.processes and not self.channels


def _target_child(process: subprocess.Popen[bytes], owner: OwnedProcesses) -> int:
    """The registered unshare leader has exactly one PID-namespace init child."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not owner.containment.exited_without_reap(process):
        children = (
            (Path("/proc") / str(process.pid) / "task" / str(process.pid) / "children")
            .read_text()
            .split()
        )
        if len(children) == 1 and children[0].isdecimal():
            return int(children[0])
        if len(children) > 1:
            break
        time.sleep(0.025)
    raise refusal("broker_unavailable")


def _grant(
    endpoint: socket.socket,
    *,
    uid: int,
    pid: int,
    launch: str,
    document: Mapping[str, Any],
    inference: socket.socket,
    namespace_pid: int | None = None,
) -> None:
    before = LinuxPrivateProcessContainment.process_identity(pid)
    frame, _ = receive_bootstrap(endpoint, expected_uid=uid, expected_pid=pid)
    identity = protected_identity(pid, uid)
    if identity != before or dict(frame) != {
        "kind": "armed",
        "launch_id": launch,
        "process_id": pid if namespace_pid is None else namespace_pid,
        "creation_identity": identity[1],
    }:
        raise refusal()
    send_bootstrap(
        endpoint, {"kind": "grant", "launch_id": launch, **document}, descriptor=inference.fileno()
    )
    response, _ = receive_bootstrap(endpoint, expected_uid=uid, expected_pid=pid)
    if (
        response
        != {
            "kind": "bound",
            "launch_id": launch,
            "enrollment_digest": document["enrollment"]["digest"],
        }
        or protected_identity(pid, uid) != identity
    ):
        raise refusal()
    send_bootstrap(
        endpoint,
        {
            "kind": "admit",
            "launch_id": launch,
            "enrollment_digest": document["enrollment"]["digest"],
        },
    )


def supervise(port: int, definition: Mapping[str, Any], *, stop: threading.Event) -> None:
    if _RETAINED:
        raise refusal("broker_unavailable")
    verify_installation()
    if uid() != 0 or set(definition) != {
        "configuration",
        "destination_policy",
        "credential",
        "max_nodes",
        "max_edges",
    }:
        raise refusal()
    config = AIProviderConfig.from_mapping(definition["configuration"])
    enrollment = enroll(
        config,
        definition["destination_policy"],
        max_nodes=definition["max_nodes"],
        max_edges=definition["max_edges"],
    )
    public = enrollment_document(enrollment)
    expires = datetime.fromtimestamp(enrollment.expires_at_ms / 1000, timezone.utc)
    print(
        f"This enrolled lab session expires at {expires:%Y-%m-%d %H:%M:%S UTC}. "
        "Saved run records remain in the lab; "
        "finish or stop active work before then. Restart the same prepared-lab start command "
        "for a fresh session.",
        flush=True,
    )
    owner = OwnedProcesses()
    try:
        worker_parent, worker_child = bootstrap_pair()
        owner.channels.extend((worker_parent, worker_child))
        target_parent, target_child = bootstrap_pair()
        owner.channels.extend((target_parent, target_child))
        inference_worker, inference_ui = socket.socketpair(
            getattr(socket, "AF_UNIX", -1), socket.SOCK_STREAM
        )
        owner.channels.extend((inference_worker, inference_ui))
        for endpoint in owner.channels:
            endpoint.set_inheritable(False)
        worker_launch = secrets.token_hex(32)
        worker = owner.spawn("launch-worker", port, worker_child, worker_launch)
        worker_child.close()
        _grant(
            worker_parent,
            uid=1001,
            pid=worker.pid,
            launch=worker_launch,
            document={"enrollment": public, "credential": definition["credential"]},
            inference=inference_worker,
        )
        worker_parent.close()
        inference_worker.close()
        target_launch = secrets.token_hex(32)
        target = owner.spawn("launch-target", port, target_child, target_launch)
        target_child.close()
        init_pid = _target_child(target, owner)
        _grant(
            target_parent,
            uid=1000,
            pid=init_pid,
            launch=target_launch,
            document={"enrollment": public},
            inference=inference_ui,
            namespace_pid=1,
        )
        target_parent.close()
        inference_ui.close()
        while not STOP_FILE.exists() and not stop.is_set():
            enrollment.require_current(config)
            if owner.containment.exited_without_reap(
                target
            ) or owner.containment.exited_without_reap(worker):
                # A worker can cross its deadline after the first check and exit.
                # Classify that boundary before treating its exit as an ordinary stop.
                enrollment.require_current(config)
                break
            time.sleep(0.1)
    except AIProviderTransportError as exc:
        if exc.code != "broker_session_expired":
            raise
        print(
            "The provider enrollment expired. Stopping this isolated lab session. "
            "Restart the same prepared-lab start command, then review saved jobs and any "
            "interrupted cleanup before resuming. No work is restarted automatically.",
            flush=True,
        )
    finally:
        if not owner.close():
            raise refusal("broker_unavailable")


def worker(descriptor: int, launch: str, parent: int) -> None:
    protect_process(1001, parent=parent)
    endpoint = adopt_bootstrap(descriptor)
    inference_fd = None
    stream = None
    try:
        identity = LinuxPrivateProcessContainment.process_identity(os.getpid())
        send_bootstrap(
            endpoint,
            {
                "kind": "armed",
                "launch_id": launch,
                "process_id": identity[0],
                "creation_identity": identity[1],
            },
        )
        frame, inference_fd = receive_bootstrap(
            endpoint, expected_uid=0, expected_pid=parent, descriptor_required=True
        )
        if (
            set(frame) != {"kind", "launch_id", "enrollment", "credential"}
            or frame["kind"] != "grant"
            or frame["launch_id"] != launch
        ):
            raise refusal()
        enrollment = read_enrollment(frame["enrollment"])
        if inference_fd is None:
            raise refusal()
        owned_fd, inference_fd = inference_fd, None
        stream = FramedSocket(adopt_inference(owned_fd))
        send_bootstrap(
            endpoint, {"kind": "bound", "launch_id": launch, "enrollment_digest": enrollment.digest}
        )
        admitted, _ = receive_bootstrap(endpoint, expected_uid=0, expected_pid=parent)
        if admitted != {
            "kind": "admit",
            "launch_id": launch,
            "enrollment_digest": enrollment.digest,
        }:
            raise refusal()
    except BaseException:
        if stream is not None:
            stream.close()
        raise
    finally:
        endpoint.close()
        if inference_fd is not None:
            os.close(inference_fd)
    if stream is None:
        raise refusal()
    serve_broker(
        stream,
        enrollment,
        frame["credential"],
        transport=ManagedAIJSONTransport(
            enrolled_endpoint=enrollment.config.endpoint,
            destination_policy=enrollment.destination_policy,
        ),
        stop=threading.Event(),
    )


def main() -> None:
    try:
        mode, raw_port, raw_fd, launch, raw_parent = sys.argv[1:]
        port, descriptor, parent = int(raw_port), int(raw_fd), int(raw_parent)
        if not 1024 <= port <= 65535 or descriptor <= 2 or len(launch) != 64 or parent <= 1:
            raise refusal()
        if mode == "worker":
            worker(descriptor, launch, parent)
            return
        if uid() != 0:
            raise refusal()
        from .runner_parent_death import _arm_parent_death

        if not _arm_parent_death(parent):
            raise refusal()
        # Only the bootstrap channel survives these fixed execs; it never holds
        # the inference descriptor before the final protected process handshake.
        os.set_inheritable(descriptor, True)
        if mode == "launch-target":
            os.execve(
                str(PYTHON), guest_command("launch", port, str(descriptor), launch), ENV
            )  # nosec B606
        elif mode == "launch-worker":
            os.execve(
                "/usr/bin/unshare",
                [
                    "/usr/bin/unshare",
                    "--mount",
                    "--ipc",
                    "--propagation",
                    "private",
                    *command("worker-enter", port, descriptor, launch, parent),
                ],
                ENV,
            )  # nosec B606
        elif mode == "worker-enter":
            if any(
                namespaces()[kind] == os.readlink(f"/proc/{parent}/ns/{kind}")
                for kind in ("mnt", "ipc")
            ):
                raise refusal()
            from .prepared_lab_runtime import isolate_mounts

            isolate_mounts()
            environment = {
                **ENV,
                "HOME": BROKER_HOME,
                "USER": "bluefire-broker",
                "LOGNAME": "bluefire-broker",
            }
            os.chdir(BROKER_HOME)
            os.execve(
                "/usr/bin/setpriv",
                [
                    "/usr/bin/setpriv",
                    "--reuid=1001",
                    "--regid=1001",
                    "--clear-groups",
                    "--no-new-privs",
                    "--bounding-set=-all",
                    "--inh-caps=-all",
                    "--ambient-caps=-all",
                    *command("worker", port, descriptor, launch, parent),
                ],
                environment,
            )  # nosec B606
        else:
            raise refusal()
    except Exception:
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
