"""Linux namespace setup and ordinary installed-product session for prepared_lab.

No task, approval, scenario, or runner request is constructed here. Root is used
only for namespace setup. Every product process runs as UID/GID 1000 without
capabilities, inherited secrets, host filesystems, or non-loopback networking.
"""

from __future__ import annotations

import json
import os
import select
import shlex
import signal
import socket
import subprocess  # nosec B404
import sys
import threading
import time

from bluefire.linux_session_facts import isolation_facts as isolation_facts
from bluefire.linux_session_facts import isolation_surface_facts as isolation_surface_facts
from bluefire.prepared_lab_relay import Relay, private_socket, remove_owned_socket, tcp_listener
from bluefire.prepared_lab_runtime import (
    BRIDGE,
    ENV,
    HOME,
    KINDS,
    PRODUCT,
    STOP_FILE,
    guest_command,
    isolate_mounts,
    namespaces,
    stop_child,
    uid,
)

STOP = threading.Event()


def dropped(command: list[str]) -> list[str]:
    return [
        "/usr/bin/setpriv",
        "--reuid=1000",
        "--regid=1000",
        "--clear-groups",
        "--no-new-privs",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        *command,
    ]


def enter(port: int, parent: str, *bootstrap: str, file_access: bool = False) -> None:
    if uid() != 0 or os.getpid() != 1 or socket.if_nameindex() != [(1, "lo")]:
        raise ValueError("setup requires a new PID and loopback-only network namespace")
    original = json.loads(parent)
    if set(original) != set(KINDS) or any(namespaces()[key] == original[key] for key in KINDS):
        raise ValueError("all four namespace identities must differ from the parent")
    isolate_mounts()
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True, env=ENV)  # nosec B603
    if file_access:
        from .prepared_lab_file_access import enroll_fixed_reader

        enroll_fixed_reader()
    os.execve(  # nosec B606
        "/usr/bin/setpriv", dropped(guest_command("inner", port, *bootstrap)), ENV
    )


def stopping() -> bool:
    if STOP_FILE.exists():
        STOP.set()
    return STOP.is_set()


def read_command(pending: bytearray, descriptor: int) -> str | None:
    """Read bounded UTF-8 lines without TextIO read-ahead hiding queued input."""
    newline = pending.find(b"\n")
    if newline < 0:
        ready, _, _ = select.select([descriptor], [], [], 0.5)
        if not ready:
            return None
        block = os.read(descriptor, 8193 - len(pending))
        if not block:
            line = bytes(pending)
            pending.clear()
        else:
            pending.extend(block)
            newline = pending.find(b"\n")
            if newline < 0:
                if len(pending) > 8192:
                    raise ValueError("product command exceeds its input bound")
                return None
            line = bytes(pending[: newline + 1])
            del pending[: newline + 1]
    else:
        line = bytes(pending[: newline + 1])
        del pending[: newline + 1]
    if len(line) > 8192:
        raise ValueError("product command exceeds its input bound")
    try:
        return line.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("product command must use UTF-8") from None


def inner(port: int, *bootstrap: str) -> None:
    if bootstrap:
        from .ai_broker_bootstrap import protect_process

        protect_process(1000)
    facts = isolation_facts()
    os.umask(0o077)
    (HOME / "lab-isolation.json").write_text(json.dumps(facts, indent=2))
    listener = socket.socket(getattr(socket, "AF_UNIX", -1), socket.SOCK_STREAM)
    server = None
    identity = None
    relay = Relay(STOP)
    try:
        # Never unlink an inherited pathname to make a session appear startable.
        listener.bind(str(BRIDGE))
        identity = private_socket(BRIDGE)
        listener.listen(8)
        threading.Thread(
            target=relay.serve, args=(listener, ("127.0.0.1", port)), daemon=True
        ).start()
        if bootstrap:
            from .prepared_lab_ui_bootstrap import start_ui

            server = start_ui(port, int(bootstrap[0]), bootstrap[1])
        else:
            server = subprocess.Popen(  # nosec B603
                PRODUCT + ["ui", "--no-browser", "--host", "127.0.0.1", "--port", str(port)],
                env=ENV,
                cwd=HOME,
            )
        print(
            "Isolated lab ready. Enter BlueFire arguments (for example: runner status --profile sandbox-execute.v1). Enter quit to stop the session.",
            flush=True,
        )
        pending = bytearray()
        while server.poll() is None and not stopping():
            line = read_command(pending, sys.stdin.fileno())
            if line is None:
                continue
            if not line or line.strip() == "quit":
                break
            if len(line) > 8192:
                raise ValueError("product command exceeds its input bound")
            try:
                args = shlex.split(line)
            except ValueError:
                print("Unclosed quote in BlueFire arguments.", flush=True)
                continue
            if args:
                # Exactly one installed product executable; no shell or command substitution.
                process = subprocess.Popen(  # nosec B603
                    PRODUCT + args, env=ENV, cwd=HOME
                )  # nosec B603
                try:
                    while process.poll() is None and not stopping():
                        STOP.wait(0.2)
                finally:
                    stop_child(process)
        if server.poll() not in (None, 0):
            raise ValueError("the normal BlueFire UI server exited unsuccessfully")
    finally:
        if identity is not None:
            try:
                subprocess.run(  # nosec B603
                    PRODUCT + ["runner", "stop", "--profile", "sandbox-execute.v1"],
                    env=ENV,
                    cwd=HOME,
                    timeout=30,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )  # nosec B603
            except (OSError, subprocess.TimeoutExpired):
                print(
                    "Runner stop did not complete; retained lab data requires inspection.",
                    file=sys.stderr,
                )
        stop_child(server)
        relay.close()
        listener.close()
        if identity is not None and not remove_owned_socket(BRIDGE, identity):
            print("Bridge identity changed; replacement retained.", file=sys.stderr)


def outer(port: int) -> None:
    if uid() != 1000:
        raise ValueError("the UI relay must be unprivileged")
    deadline = time.monotonic() + 30
    while not STOP.is_set():
        try:
            private_socket(BRIDGE)
            break
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise ValueError("the isolated UI bridge did not become ready") from None
            STOP.wait(0.1)
    relay = Relay(STOP)
    try:
        relay.serve(tcp_listener(port), BRIDGE)
    finally:
        relay.close()


def main() -> None:
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    mode, raw_port, *args = sys.argv[1:]
    port = int(raw_port)
    if not 1024 <= port <= 65535:
        raise ValueError("invalid UI port")
    if mode in {"broker-launch", "broker-launch-file-access"} and not args:
        from .prepared_lab_broker import supervise
        from .prepared_lab_inference_input import read_definition

        supervise(
            port,
            read_definition(sys.stdin.fileno()),
            stop=STOP,
            file_access=mode.endswith("file-access"),
        )
    elif mode in {"launch", "launch-file-access"} and len(args) in {0, 2}:
        if uid() != 0:
            raise ValueError("namespace creation requires clone-local root")
        if mode == "launch-file-access":
            from .prepared_lab_file_access import assert_probe_identity_unused

            assert_probe_identity_unused()
        if STOP_FILE.exists():
            details = STOP_FILE.lstat()
            if (
                STOP_FILE.is_symlink()
                or not STOP_FILE.is_file()
                or details.st_uid != 0
                or details.st_nlink != 1
            ):
                raise ValueError("prior session stop marker is unsafe")
            STOP_FILE.unlink()
        # util-linux documented flags: https://man7.org/linux/man-pages/man1/unshare.1.html
        os.execve(  # nosec B606
            "/usr/bin/unshare",
            [
                "/usr/bin/unshare",
                "--mount",
                "--net",
                "--pid",
                "--ipc",
                "--fork",
                "--mount-proc",
                "--propagation",
                "private",
                "--kill-child=TERM",
                *guest_command(
                    "enter-file-access" if mode == "launch-file-access" else "enter",
                    port,
                    json.dumps(namespaces()),
                    *args,
                ),
            ],
            ENV,
        )  # nosec B606
    elif mode in {"enter", "enter-file-access"} and len(args) in {1, 3}:
        enter(port, args[0], *args[1:], file_access=mode == "enter-file-access")
    elif mode == "inner" and len(args) in {0, 2}:
        inner(port, *args)
    elif mode == "outer" and not args:
        outer(port)
    elif mode == "stop" and not args:
        if uid() != 0:
            raise ValueError("session management requires clone-local root")
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None:
            raise ValueError("session management requires no-follow file opens")
        try:
            descriptor = os.open(STOP_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow, 0o600)
        except FileExistsError:
            details = STOP_FILE.lstat()
            if (
                STOP_FILE.is_symlink()
                or not STOP_FILE.is_file()
                or details.st_uid != 0
                or details.st_nlink != 1
            ):
                raise ValueError("session stop marker is unsafe") from None
        else:
            os.close(descriptor)
        deadline = time.monotonic() + 45
        while BRIDGE.exists() or BRIDGE.is_symlink():
            if time.monotonic() >= deadline:
                raise ValueError("session did not remove its owned bridge; retained for inspection")
            time.sleep(0.1)
    else:
        raise ValueError("invalid fixed lab session mode")


if __name__ == "__main__":
    main()
