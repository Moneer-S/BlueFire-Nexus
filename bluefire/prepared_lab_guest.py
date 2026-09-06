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
from pathlib import Path

from bluefire.prepared_lab_relay import Relay, private_socket, remove_owned_socket, tcp_listener

ROOT = Path("/opt/bluefire-lab")
HOME = Path("/home/bluefire")
BRIDGE = HOME / ".bluefire-lab-ui.sock"
PYTHON = ROOT / "venv/bin/python"
PRODUCT = [str(ROOT / "venv/bin/bluefire"), "--runs-dir", str(HOME / "experiments")]
ENV = {
    "HOME": str(HOME),
    "USER": "bluefire",
    "LOGNAME": "bluefire",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "PYTHONUNBUFFERED": "1",
    "PYTHONNOUSERSITE": "1",
}
STOP = threading.Event()
STOP_FILE = ROOT / "session-stop"
KINDS = ("mnt", "net", "pid", "ipc")


def uid() -> int:
    return int(getattr(os, "getuid", lambda: -1)())


def gid() -> int:
    return int(getattr(os, "getgid", lambda: -1)())


def namespaces() -> dict[str, str]:
    return {kind: os.readlink(f"/proc/self/ns/{kind}") for kind in KINDS}


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


def guest_command(mode: str, port: int, *args: str) -> list[str]:
    return [str(PYTHON), "-I", "-B", "-m", "bluefire.prepared_lab_guest", mode, str(port), *args]


def enter(port: int, parent: str) -> None:
    if uid() != 0 or os.getpid() != 1 or socket.if_nameindex() != [(1, "lo")]:
        raise ValueError("setup requires a new PID and loopback-only network namespace")
    original = json.loads(parent)
    if set(original) != set(KINDS) or any(namespaces()[key] == original[key] for key in KINDS):
        raise ValueError("all four namespace identities must differ from the parent")
    # Remove host-backed submounts within this already-private mount namespace.
    # Merely covering their parent leaves mountinfo entries and hidden mounts.
    host_mounts = []
    for row in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = row.split(" - ", 1)
        if after.split()[0] in {"9p", "drvfs", "virtiofs"}:
            target = before.split()[4]
            if "\\" in target or not target.startswith(("/mnt/", "/usr/lib/wsl/")):
                raise ValueError("an unexpected host mount cannot be safely detached")
            host_mounts.append(target)
    for target in sorted(host_mounts, key=lambda value: value.count("/"), reverse=True):
        subprocess.run(  # nosec B603
            ["/usr/bin/umount", "--", target], check=True, env=ENV
        )  # nosec B603
    # unshare's explicit --propagation private prevents these mounts escaping.
    for name in (
        "/mnt",
        "/run",
        "/tmp",  # nosec B108
        "/usr/lib/wsl",
        "/dev/shm",  # nosec B108
    ):  # nosec B108
        path = Path(name)
        if not path.is_dir() or path.is_symlink():
            raise ValueError("a required isolation mount point is absent or linked")
        mode = "1777" if name in {"/tmp", "/dev/shm"} else "0755"  # nosec B108  # nosec B108
        subprocess.run(  # nosec B603
            [
                "/usr/bin/mount",
                "-t",
                "tmpfs",
                "-o",
                f"nodev,nosuid,noexec,mode={mode}",
                "tmpfs",
                name,
            ],
            check=True,
            env=ENV,
        )  # nosec B603
    if Path("/init").is_file():
        subprocess.run(  # nosec B603
            ["/usr/bin/mount", "--bind", "/dev/null", "/init"], check=True, env=ENV
        )  # nosec B603
    subprocess.run(  # nosec B603
        ["/usr/sbin/ip", "link", "set", "lo", "up"], check=True, env=ENV
    )  # nosec B603
    subprocess.run(  # nosec B603
        ["/usr/bin/mount", "--bind", str(ROOT), str(ROOT)], check=True, env=ENV
    )  # nosec B603
    subprocess.run(  # nosec B603
        ["/usr/bin/mount", "-o", "remount,bind,ro", str(ROOT)], check=True, env=ENV
    )  # nosec B603
    os.execve(  # nosec B606
        "/usr/bin/setpriv", dropped(guest_command("inner", port)), ENV
    )  # nosec B606


def isolation_facts() -> dict[str, object]:
    if uid() != 1000 or gid() != 1000 or getattr(os, "getgroups", lambda: [-1])():
        raise ValueError("the lab account must have UID/GID 1000 and no supplementary groups")
    if socket.if_nameindex() != [(1, "lo")]:
        raise ValueError("the isolated lab has a non-loopback network interface")
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    if status.get("NoNewPrivs", "").strip() != "1" or any(
        int(status.get(key, "1"), 16) != 0
        for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    ):
        raise ValueError("the lab still has privileges or can regain them")
    if any(
        Path(path).exists() for path in ("/mnt/c", "/run/WSL", "/tmp/.X11-unix")  # nosec B108
    ):  # nosec B108
        raise ValueError("host filesystem or socket access remains exposed")
    mounts = Path("/proc/self/mountinfo").read_text()
    if any(marker in mounts for marker in (" - 9p ", " - drvfs ", " - virtiofs ")):
        raise ValueError("a host-backed filesystem is still mounted")
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    if any(line.split()[0] != "lo" for line in routes if line.split()):
        raise ValueError("a non-loopback IPv4 route remains")
    routes6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    if any(line.split()[-1] != "lo" for line in routes6 if line.split()):
        raise ValueError("a non-loopback IPv6 route remains")
    return {
        "uid": uid(),
        "gid": gid(),
        "namespaces": namespaces(),
        "interfaces": socket.if_nameindex(),
        "capabilities": "zero",
        "no_new_privileges": True,
        "routes": routes,
        "routes6": routes6,
    }


def stop_child(process: subprocess.Popen[bytes] | None) -> None:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def stopping() -> bool:
    if STOP_FILE.exists():
        STOP.set()
    return STOP.is_set()


def inner(port: int) -> None:
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
        server = subprocess.Popen(  # nosec B603
            PRODUCT + ["ui", "--host", "127.0.0.1", "--port", str(port)], env=ENV, cwd=HOME
        )  # nosec B603
        print(
            "Isolated lab ready. Enter BlueFire arguments (for example: runner status --profile sandbox-execute.v1). Enter quit to stop the session.",
            flush=True,
        )
        while server.poll() is None and not stopping():
            ready, _, _ = select.select([sys.stdin], [], [], 0.5)
            if not ready:
                continue
            line = sys.stdin.readline(8193)
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
    if mode == "launch":
        if uid() != 0:
            raise ValueError("namespace creation requires clone-local root")
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
                *guest_command("enter", port, json.dumps(namespaces())),
            ],
            ENV,
        )  # nosec B606
    elif mode == "enter" and len(args) == 1:
        enter(port, args[0])
    elif mode == "inner" and not args:
        inner(port)
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
