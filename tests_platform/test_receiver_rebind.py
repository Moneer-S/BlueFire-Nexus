"""Real socket lifecycle checks; no worker, action, provider or artifact transfer."""

from __future__ import annotations

import errno
import socket
import sys
from pathlib import Path

import pytest

import bluefire.receiver as receiver_module
from bluefire.receiver import LoopbackArtifactReceiver, ReceiverConfig
from bluefire.receiver_policy import REDACTED_ONLY_POLICY, REVIEWED_RECORDS_POLICY


def config(port: int = 0, policy: str | None = REVIEWED_RECORDS_POLICY) -> ReceiverConfig:
    return ReceiverConfig(
        authentication_key=b"r" * 32,
        port=port,
        disposable_peer=True,
        max_connections=8,
        max_body_bytes=1024 * 1024,
        idle_timeout_seconds=240,
        content_policy=policy,
    )


def close_with_server_time_wait(receiver: LoopbackArtifactReceiver) -> None:
    """Order both FINs explicitly; no timing sleep or protocol/auth traffic."""
    listener = receiver._server.socket
    listener.settimeout(3)
    address = (receiver.host, receiver.port)
    with socket.create_connection(address, timeout=3) as client:
        accepted, _peer = listener.accept()
        with accepted:
            accepted.settimeout(3)
            accepted.shutdown(socket.SHUT_WR)
            assert client.recv(1) == b""
            client.shutdown(socket.SHUT_WR)
            assert accepted.recv(1) == b""
    receiver.close()
    rows = [line.split() for line in Path("/proc/net/tcp").read_text().splitlines()[1:]]
    assert any(
        row[1] == f"0100007F:{address[1]:04X}" and row[3] == "06" for row in rows
    ), "The test must establish actual server-side TIME_WAIT before rebinding"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux TIME_WAIT semantics")
def test_fresh_owned_policies_rebind_same_port_after_real_connections() -> None:
    port = 0
    identities = []
    for policy in (REVIEWED_RECORDS_POLICY, REDACTED_ONLY_POLICY, REVIEWED_RECORDS_POLICY):
        with LoopbackArtifactReceiver(config(port, policy)) as receiver:
            port = receiver.port
            assert receiver.host == "127.0.0.1"
            assert receiver._server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) == 0
            identities.append(receiver.session_id)
            close_with_server_time_wait(receiver)
    assert len(set(identities)) == 3


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux listener exclusivity")
def test_owned_receiver_cannot_replace_an_active_exact_listener() -> None:
    with LoopbackArtifactReceiver(config()) as receiver:
        with pytest.raises(OSError) as error:
            LoopbackArtifactReceiver(config(receiver.port, REDACTED_ONLY_POLICY))
        assert error.value.errno == errno.EADDRINUSE
        assert receiver._server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux legacy socket policy")
def test_opaque_disposable_receiver_keeps_nonreuse_behavior() -> None:
    with LoopbackArtifactReceiver(config(policy=None)) as receiver:
        port = receiver.port
        assert receiver._server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
        close_with_server_time_wait(receiver)
    with pytest.raises(OSError) as error:
        LoopbackArtifactReceiver(config(port, policy=None))
    assert error.value.errno == errno.EADDRINUSE


@pytest.mark.parametrize(
    ("platform", "disposable", "policy", "expected"),
    [
        ("linux", True, REVIEWED_RECORDS_POLICY, True),
        ("linux", True, None, False),
        ("linux", False, None, False),
        ("win32", True, REVIEWED_RECORDS_POLICY, False),
        ("darwin", True, REVIEWED_RECORDS_POLICY, False),
    ],
)
def test_reuse_policy_is_scoped_before_bind_without_launch(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    disposable: bool,
    policy: str | None,
    expected: bool,
) -> None:
    captured = []

    def before_bind(server, address, handler):
        assert address == ("127.0.0.1", 4317)
        captured.append(server.allow_reuse_address)

    monkeypatch.setattr(receiver_module.sys, "platform", platform)
    monkeypatch.setattr(receiver_module.socketserver.TCPServer, "__init__", before_bind)
    selected = config(4317, policy) if disposable else ReceiverConfig(authentication_key=b"r" * 32)
    receiver_module._LoopbackTCPServer(
        ("127.0.0.1", 4317), receiver_module._ReceiverHandler, config=selected, storage=None
    )
    assert captured == [expected]
