from __future__ import annotations

import json
import socket
import stat
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import prepared_lab as lab
from bluefire.prepared_lab_relay import Relay, remove_owned_socket, tcp_listener


def _wheel(path: Path, *, platform: str = "linux", guest: bool = True) -> Path:
    import zipfile

    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "bluefire/native/runner-manifest.json",
            json.dumps({"artifact": {"platform": platform, "architecture": "x86_64"}}),
        )
        if guest:
            archive.writestr("bluefire/prepared_lab_guest.py", "# packaged helper")
    return path


def test_lab_requires_platform_native_wheel_and_existing_packaged_launcher(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    product = tmp_path / "bluefire_nexus-3.0.0-py3-none-linux_x86_64.whl"
    _wheel(product, platform="windows")
    with pytest.raises(ValueError, match="Linux x86_64"):
        lab.wheel_inputs(product, wheelhouse)
    _wheel(product, guest=False)
    with pytest.raises(ValueError, match="predates"):
        lab.wheel_inputs(product, wheelhouse)
    _wheel(product)
    assert lab.wheel_inputs(product, wheelhouse) == [product]
    _wheel(wheelhouse / "bluefire_nexus-2.8.0-py3-none-linux_x86_64.whl")
    with pytest.raises(ValueError, match="one BlueFire"):
        lab.wheel_inputs(product, wheelhouse)


def test_lease_refuses_replaced_registration_and_storage_before_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "0123456789abcdef"
    install = tmp_path / f"wsl-distribution-{token}"
    install.mkdir()
    lease = lab.DisposableWslDistribution(
        Path(sys.executable),
        tmp_path,
        "BlueFire-Gate11-Run-" + token,
        install,
        lab.identity(install, directory=True),
    )
    (tmp_path / "management.lock").touch()
    record = {
        "state_identity": lab.identity(tmp_path, directory=True),
        "registration_id": "original",
        "lock_identity": lab.identity(tmp_path / "management.lock", directory=False),
    }
    monkeypatch.setattr(lab, "registration", lambda _name: ("original", install))
    lab.verify(lease, record)
    monkeypatch.setattr(lab, "registration", lambda _name: ("replacement", install))
    with pytest.raises(ValueError, match="registration identity"):
        lab.verify(lease, record)
    monkeypatch.setattr(lab, "registration", lambda _name: ("original", install))
    lease.install_identity = (0, 0)
    with pytest.raises(ValueError, match="storage identity"):
        lab.verify(lease, record)


def test_guest_commands_clear_environment_and_keep_product_args_out_of_shell(
    tmp_path: Path,
) -> None:
    lease = lab.DisposableWslDistribution(
        Path(sys.executable),
        tmp_path,
        "BlueFire-Gate11-Run-" + "0" * 16,
        tmp_path / "install",
        (1, 2),
    )
    command = lab.guest(
        lease,
        "bluefire",
        lab.GUEST_PYTHON,
        "-I",
        "-m",
        "bluefire.prepared_lab_guest",
        "outer",
        "8767",
    )
    assert command[command.index("--exec") + 1 :][:2] == ["/usr/bin/env", "-i"]
    assert not any("WSL_INTEROP" in item or "TOKEN" in item or "SECRET" in item for item in command)
    assert command[-3:] == ["bluefire.prepared_lab_guest", "outer", "8767"]


def test_socket_cleanup_retains_replacement_even_if_it_has_same_name() -> None:
    class SocketPath:
        removed = False

        def lstat(self) -> SimpleNamespace:
            return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_dev=2, st_ino=9)

        def unlink(self) -> None:
            self.removed = True

    path = SocketPath()
    assert remove_owned_socket(path, (2, 8)) is False  # type: ignore[arg-type]
    assert not path.removed
    assert remove_owned_socket(path, (2, 9)) is True  # type: ignore[arg-type]
    assert path.removed


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_relay_forwards_opaque_bytes_and_shutdown_closes_active_connections() -> None:
    received = []
    target = tcp_listener(_free_port())
    listener = tcp_listener(_free_port())
    stop = threading.Event()
    relay = Relay(stop)

    def answer() -> None:
        with target:
            peer, _ = target.accept()
            with peer:
                peer.settimeout(3)
                received.append(peer.recv(32))
                peer.sendall(b"ordinary product response")

    worker = threading.Thread(target=answer)
    proxy = threading.Thread(target=relay.serve, args=(listener, target.getsockname()))
    worker.start()
    proxy.start()
    try:
        with socket.create_connection(listener.getsockname(), timeout=3) as client:
            client.sendall(b"opaque request")
            assert client.recv(64) == b"ordinary product response"
        assert received == [b"opaque request"]
    finally:
        relay.close()
        worker.join(timeout=3)
        proxy.join(timeout=3)
    assert not worker.is_alive() and not proxy.is_alive()


@pytest.mark.skipif(
    sys.platform != "linux", reason="SO_REUSEADDR TIME_WAIT behavior is a Linux boundary"
)
def test_linux_ui_listener_restarts_immediately_after_accepted_connection() -> None:
    port = _free_port()
    listener = tcp_listener(port)
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    peer, _ = listener.accept()
    # The relay endpoint performs the active close, leaving its tuple in TIME_WAIT.
    peer.shutdown(socket.SHUT_WR)
    assert client.recv(1) == b""
    client.close()
    peer.close()
    listener.close()
    with tcp_listener(port) as restarted:
        assert restarted.getsockname() == ("127.0.0.1", port)


def test_ui_port_cannot_select_privileged_or_wildcard_endpoint() -> None:
    for port in (0, 80, 1023, 65536, True):
        with pytest.raises(ValueError, match="port"):
            tcp_listener(port)


@pytest.mark.parametrize(
    "fault", ["uid", "groups", "capability", "privileges", "interface", "mount", "route", "route6"]
)
def test_namespace_witness_refuses_remaining_authority(
    fault: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from bluefire import prepared_lab_guest as guest

    monkeypatch.setattr(guest, "uid", lambda: 0 if fault == "uid" else 1000)
    monkeypatch.setattr(guest, "gid", lambda: 1000)
    monkeypatch.setattr(
        guest.os, "getgroups", lambda: [5] if fault == "groups" else [], raising=False
    )
    monkeypatch.setattr(
        guest.socket,
        "if_nameindex",
        lambda: [(1, "lo"), (2, "eth0")] if fault == "interface" else [(1, "lo")],
    )
    monkeypatch.setattr(guest, "namespaces", lambda: {kind: kind + ":[2]" for kind in guest.KINDS})
    monkeypatch.setattr(Path, "exists", lambda _path: False)
    status = "NoNewPrivs: " + ("0" if fault == "privileges" else "1") + "\n"
    status += "\n".join(
        f"{key}: " + ("1" if fault == "capability" else "0")
        for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    )
    files = {
        "/proc/self/status": status,
        "/proc/self/mountinfo": "1 0 0:1 / /mnt/c rw - 9p host rw" if fault == "mount" else "",
        "/proc/net/route": "Iface Destination\n" + ("eth0 00000000\n" if fault == "route" else ""),
        "/proc/net/ipv6_route": "0000 eth0\n" if fault == "route6" else "",
    }
    monkeypatch.setattr(Path, "read_text", lambda path, **_kwargs: files[path.as_posix()])
    with pytest.raises(ValueError):
        guest.isolation_facts()


@pytest.mark.parametrize("replaced", [False, True])
def test_preparation_canonicalizes_state_and_never_cleans_unbound_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replaced: bool
) -> None:
    (tmp_path / "intermediate").mkdir()
    state = tmp_path / "intermediate" / ".." / "lab"
    captured = {}
    cleaned = []
    commands = []

    def create(executable: Path, runtime: Path) -> lab.DisposableWslDistribution:
        assert runtime == state.resolve()
        with (runtime / "management.lock").open("r+b") as competing:
            with pytest.raises(ValueError, match="active session"):
                with lab.management_lock(competing):
                    pytest.fail("preparation must hold its lock before clone creation")
        token = "1" * 16
        install = runtime / ("wsl-distribution-" + token)
        install.mkdir()
        lease = lab.DisposableWslDistribution(
            executable,
            runtime,
            "BlueFire-Gate11-Run-" + token,
            install,
            lab.identity(install, directory=True),
        )
        monkeypatch.setattr(lease, "cleanup", lambda: cleaned.append(True))
        captured["lease"] = lease
        return lease

    monkeypatch.setattr(lab, "wheel_inputs", lambda *_args: [])
    monkeypatch.setattr(lab, "_trusted_wsl_executable", lambda: Path(sys.executable))
    monkeypatch.setattr(lab, "create_disposable_wsl_distribution", create)
    monkeypatch.setattr(
        lab,
        "registration",
        lambda _name: ("guid", tmp_path if replaced else captured["lease"].install_root),
    )

    def managed_command(command, **_kwargs):
        with (state / "management.lock").open("r+b") as competing:
            with pytest.raises(ValueError, match="active session"):
                with lab.management_lock(competing):
                    pytest.fail("installation and termination must retain the management lock")
        commands.append(command)

    monkeypatch.setattr(lab.subprocess, "run", managed_command)
    if replaced:
        with pytest.raises(ValueError, match="does not match"):
            lab.prepare(state, tmp_path / "product.whl", tmp_path)
        assert not commands and not cleaned
    else:
        lab.prepare(state, tmp_path / "product.whl", tmp_path)
        assert (state / "lease.json").is_file()
        assert commands[-1] == [
            str(Path(sys.executable)),
            "--terminate",
            captured["lease"].distribution_name,
        ]
        assert not cleaned


def test_start_stops_owned_clients_even_when_distribution_identity_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = lab.DisposableWslDistribution(
        Path(sys.executable),
        tmp_path,
        "BlueFire-Gate11-Run-" + "1" * 16,
        tmp_path / "install",
        (1, 2),
    )
    processes = []
    management = []
    interrupt = True

    @contextmanager
    def owned(_state: Path):
        yield lease, {}

    class Client:
        returncode = None
        stopped = False

        def __init__(self, *_args, **_kwargs):
            processes.append(self)

        def poll(self):
            nonlocal interrupt
            if interrupt:
                interrupt = False
                raise KeyboardInterrupt
            return self.returncode

        def terminate(self):
            self.returncode = 0
            self.stopped = True

        def wait(self, **_kwargs):
            return self.returncode

    def refuse(*_args):
        raise ValueError("registration identity changed")

    monkeypatch.setattr(lab, "owned", owned)
    monkeypatch.setattr(lab, "verify", refuse)
    monkeypatch.setattr(lab.subprocess, "Popen", Client)
    monkeypatch.setattr(
        lab.subprocess, "run", lambda command, **_kwargs: management.append(command)
    )
    with pytest.raises(ValueError, match="identity changed"):
        lab.start(tmp_path, 8767)
    assert len(processes) == 2 and all(process.stopped for process in processes)
    assert not management
