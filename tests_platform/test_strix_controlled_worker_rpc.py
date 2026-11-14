"""Effect-free production IPC checks; Linux socket/peer tests never start Strix."""

from __future__ import annotations

import array
import asyncio
import inspect
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, AsyncIterator

import pytest

from bluefire import strix_adapter as adapter
from bluefire import strix_controlled_backend as backend
from bluefire import strix_controlled_installed_worker as installed
from bluefire import strix_controlled_worker_channel as channel
from bluefire import strix_controlled_worker_invocation as invocation_module
from bluefire import strix_controlled_worker_launch as launch
from bluefire import strix_controlled_worker_model_gateway as worker_model_gateway
from bluefire import strix_controlled_worker_packets as packets
from bluefire import strix_controlled_worker_rpc as rpc
from bluefire.engine_relay import ControlledModelGatewayLease
from bluefire.strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
    REVIEWED_SOURCE_REVISION,
)
from bluefire.util import content_hash, file_hash
from tests_platform.test_strix_controlled_backend import FakeTransport
from tests_platform.test_strix_controlled_bootstrap import _environment, _identities, _profile
from tests_platform.test_strix_controlled_worker_channel import _binding, _complete, _request

linux = pytest.mark.skipif(
    sys.platform != "linux", reason="production AF_UNIX/SO_PEERCRED is Linux only"
)


class _ModelLease:
    token = "test-relay-bearer-" + "a" * 32

    def __init__(self) -> None:
        self.claimed = 0
        self.revoked = 0

    def claim(
        self,
        binding: channel.ControlledWorkerBinding,
        custody_identity: tuple[int, int, int, int, tuple[int, ...]],
    ) -> str:
        assert binding.plan_digest
        assert custody_identity[0] > 0
        self.claimed += 1
        return self.token

    def revoke(self) -> None:
        self.revoked += 1


@linux
def test_adopted_guest_listener_binds_actual_socket_and_never_unlinks_host_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with tempfile.TemporaryDirectory(prefix="bf-guest-rpc-", dir="/tmp") as directory:
        guest = Path(directory)
        endpoint = guest / "controller.sock"
        monkeypatch.setattr(rpc, "GUEST_CONTROL_ENDPOINT", str(endpoint))
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        listener.bind(str(endpoint))
        endpoint.chmod(0o600)
        listener.listen(1)
        worker_uid = os.geteuid() or 1001
        worker_gid = os.getegid() or 1001
        if os.geteuid() == 0:
            os.chown(guest, worker_uid, worker_gid)
            os.chown(endpoint, worker_uid, worker_gid)
        directory_fd = os.open(guest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory_info = os.fstat(directory_fd)
        endpoint_info = endpoint.stat()
        socket_info = os.fstat(listener.fileno())
        listener_fact = {
            "device": socket_info.st_dev,
            "inode": socket_info.st_ino,
            "family": socket.AF_UNIX,
            "socket_type": socket.SOCK_SEQPACKET,
            "accept_conn": True,
            "passcred": True,
            "address": str(endpoint),
            "port": 0,
            "netns_cookie": int.from_bytes(
                listener.getsockopt(socket.SOL_SOCKET, rpc._SO_NETNS_COOKIE, 8), sys.byteorder
            ),
        }
        observed = {
            "listeners": {
                "endpoint_directory_device": directory_info.st_dev,
                "endpoint_directory_inode": directory_info.st_ino,
                "endpoint_directory_mode": stat.S_IMODE(directory_info.st_mode),
                "endpoint_directory_uid": directory_info.st_uid,
                "endpoint_directory_gid": directory_info.st_gid,
                "endpoint_path": {
                    "device": endpoint_info.st_dev,
                    "inode": endpoint_info.st_ino,
                    "mode": stat.S_IMODE(endpoint_info.st_mode),
                    "uid": endpoint_info.st_uid,
                    "gid": endpoint_info.st_gid,
                },
                "control": listener_fact,
            },
        }
        observed["observation_ref"] = content_hash(observed)
        profile = _profile()
        binding = _binding(profile)
        with tempfile.TemporaryDirectory(prefix="bf-host-rpc-") as parent:
            server = rpc.AttemptControllerServer(
                Path(parent), profile, binding, FakeTransport(), _ModelLease(),
                guest_listener_mode=True,
            )
            assert server._listener is None
            host_launch = server.publish_launch_material(
                b"test-frame",
                startup_overlay_ref="sha256:" + "a" * 64,
                installed_projection_ref="sha256:" + "b" * 64,
            )
            assert host_launch.exists()
            server.adopt_guest_listener(
                endpoint_directory_fd=directory_fd,
                listener_fd=listener.fileno(),
                worker_uid=worker_uid,
                worker_gid=worker_gid,
                native_observed=observed,
            )
            assert server.directory_identity == (guest.stat().st_dev, guest.stat().st_ino)
            assert server.endpoint_identity == (endpoint.stat().st_dev, endpoint.stat().st_ino)
            assert server.server_identity_ref.startswith("sha256:")
            server.close()
            assert endpoint.is_socket()
            assert server.cleanup_uncertain
            assert not host_launch.exists()
            assert not server.private_directory.exists()
        os.close(directory_fd)
        listener.close()
        endpoint.unlink()


@linux
def test_armed_custody_publishes_readiness_without_model_or_effect_dispatch() -> None:
    with tempfile.TemporaryDirectory(prefix="bf-arm-rpc-") as parent:
        profile = _profile()
        invocation = _invocation(Path(parent), profile)
        binding = replace(_binding(profile), plan_digest=invocation.intent_digest)
        effects = FakeTransport().bind(profile)
        lease = _ModelLease()
        server = rpc.AttemptControllerServer(Path(parent), profile, binding, effects, lease)
        material = launch.ControlledWorkerLaunchMaterial(
            profile=profile,
            binding=binding,
            endpoint=str(server.endpoint),
            token=server.token,
            controller_pid=os.getpid(),
            controller_uid=os.geteuid(),
            controller_gid=os.getegid(),
            environment=tuple(sorted(_environment().items())),
            package_identities=(_identities("strix-agent"), _identities("openai-agents")),
            invocation=invocation,
        )
        launch.write_launch_material(server, material)
        process_fd = os.pidfd_open(os.getpid(), 0)
        try:
            worker = rpc.OwnedWorkerProcess(
                os.getpid(), os.geteuid(), os.getegid(), process_fd
            )
            authority = _test_boundary(worker)
            ready = server.arm_custody(
                worker=worker, containment_authority=authority
            )
            assert ready == server.wait_until_custody_ready(0.1)
            assert server.custody_active
            assert not server._used
            assert server._listener is not None
            assert effects.calls == []
            assert lease.claimed == 0
            server.close()
            assert lease.revoked == 1
        finally:
            os.close(process_fd)


@linux
def test_close_during_custody_arm_releases_transferred_pidfd_and_verifier() -> None:
    with tempfile.TemporaryDirectory(prefix="bf-arm-race-") as parent:
        profile = _profile()
        invocation = _invocation(Path(parent), profile)
        binding = replace(_binding(profile), plan_digest=invocation.intent_digest)
        lease = _ModelLease()
        effects = FakeTransport().bind(profile)
        server = rpc.AttemptControllerServer(Path(parent), profile, binding, effects, lease)
        server.publish_launch_material(
            b"test-frame",
            startup_overlay_ref=invocation.startup_overlay_ref,
            installed_projection_ref=invocation_module.PROC_MEMFD_PROJECTION_REF,
        )
        process_fd = os.pidfd_open(os.getpid(), 0)
        try:
            worker = rpc.OwnedWorkerProcess(
                os.getpid(), os.geteuid(), os.getegid(), process_fd
            )
            authority = _test_boundary(worker)
            original = authority.take_verifier
            entered = threading.Event()
            release = threading.Event()
            results: list[str] = []

            def delayed_take_verifier(**kwargs: Any) -> _TestBoundaryVerifier:
                entered.set()
                assert release.wait(2.0)
                return original(**kwargs)

            authority.take_verifier = delayed_take_verifier  # type: ignore[method-assign]

            def arm() -> None:
                try:
                    server.arm_custody(worker=worker, containment_authority=authority)
                    results.append("ready")
                except rpc.ControlledWorkerRPCError:
                    results.append("refused")

            arming = threading.Thread(target=arm)
            arming.start()
            assert entered.wait(2.0)
            closing = threading.Thread(target=server.close)
            closing.start()
            assert server._stopped.wait(2.0)
            release.set()
            arming.join(2.0)
            closing.join(2.0)
            assert not arming.is_alive() and not closing.is_alive()
            assert results == ["refused"]
            assert not server.custody_active
            assert server.retained_containment_verifier is None
            assert lease.claimed == 0
            assert effects.calls == []
        finally:
            os.close(process_fd)


class _TestBoundaryVerifier:
    """Unit seam only; installed containment qualification is separate."""

    schema_version = rpc.CONTAINMENT_AUTHORITY_VERSION
    containment_ref = "sha256:" + "c" * 64
    startup_overlay_ref = invocation_module.startup_overlay.STARTUP_OVERLAY_RECEIPT_REF
    installed_projection_ref = invocation_module.PROC_MEMFD_PROJECTION_REF
    sealed_inputs_ref = "sha256:" + "d" * 64

    def __init__(self, worker: rpc.OwnedWorkerProcess) -> None:
        self.custody_identity = worker.custody_identity
        self.closed = False

    def verify(self) -> None:
        if self.closed:
            raise rpc.ControlledWorkerRPCError("closed test containment")

    def close(self) -> None:
        self.closed = True


class _TestContainmentAuthority:
    schema_version = rpc.CONTAINMENT_AUTHORITY_VERSION
    containment_ref = _TestBoundaryVerifier.containment_ref
    startup_overlay_ref = _TestBoundaryVerifier.startup_overlay_ref
    installed_projection_ref = _TestBoundaryVerifier.installed_projection_ref
    sealed_inputs_ref = _TestBoundaryVerifier.sealed_inputs_ref

    def __init__(self) -> None:
        self.taken = False

    def take_verifier(
        self, *, worker: rpc.OwnedWorkerProcess, binding: channel.ControlledWorkerBinding
    ) -> _TestBoundaryVerifier:
        assert binding.attempt_id
        if self.taken:
            raise rpc.ControlledWorkerRPCError("reused test containment")
        self.taken = True
        return _TestBoundaryVerifier(worker)


def _test_boundary(_worker: rpc.OwnedWorkerProcess) -> _TestContainmentAuthority:
    return _TestContainmentAuthority()


def _invocation(
    root: Path, profile: backend.ControlledRuntimeProfile
) -> invocation_module.ControlledWorkerInvocation:
    executable = root / "strix"
    executable.write_bytes(
        b"#!/private/qualified/python\n"
        b"from strix.interface.main import main\n"
        b"if __name__ == '__main__':\n"
        b"    raise SystemExit(main())\n"
    )
    workspace_root = root / "attempts"
    workspace_root.mkdir()
    attempt_id = "attempt-" + profile.attempt_id.removeprefix("engine-attempt-")
    workspace = adapter.prepare_attempt_workspace(
        workspace_root,
        attempt_id=attempt_id,
        objective="Assess the admitted disposable target without assuming the answer.",
    )
    build = adapter.StrixBuildIdentity(
        source_revision=REVIEWED_SOURCE_REVISION,
        source_tree_sha256="sha256:" + "a" * 64,
        package_sha256=profile.build_digest,
        executable_sha256=file_hash(executable),
        image_reference=profile.image_reference,
        image_inventory_sha256="sha256:" + "d" * 64,
        prompt_upstream_sha256="sha256:" + REVIEWED_PROMPT_SHA256,
        prompt_overlay_sha256="sha256:" + OVERLAY_SHA256,
        prompt_patched_sha256="sha256:" + PATCHED_PROMPT_SHA256,
    )
    plan = adapter.build_launch_plan(
        build=build,
        scope=adapter.StrixScope(
            target="http://bluefire-lab:8080/",
            resolved_addresses=("172.18.0.7",),
            target_snapshot_digest="sha256:" + "4" * 64,
            scope_digest="sha256:" + "5" * 64,
            network_policy_digest="sha256:" + "6" * 64,
            network_name="bf-strix-01234567",
        ),
        gateway=adapter.StrixModelGateway(
            model="controlled-test-provider",
            base_url="http://bluefire-model-gateway:8081/v1",
            authorization_digest="sha256:" + "7" * 64,
        ),
        budgets=adapter.StrixBudgets(300, 12, "1"),
        limits=adapter.StrixRuntimeLimits(),
        workspace=workspace,
        executable=executable.resolve(),
        path_environment="/reviewed/bin",
    )
    return invocation_module.ControlledWorkerInvocation.from_plan(
        plan, profile_attempt_id=profile.attempt_id
    )


def _material(server: rpc.AttemptControllerServer) -> launch.ControlledWorkerLaunchMaterial:
    return launch.ControlledWorkerLaunchMaterial(
        profile=server.channel.profile,
        binding=server.channel.binding,
        endpoint=str(server.endpoint),
        token=server.token,
        controller_pid=os.getpid(),
        controller_uid=os.geteuid(),
        controller_gid=os.getegid(),
        environment=tuple(sorted(_environment().items())),
        package_identities=(_identities("strix-agent"), _identities("openai-agents")),
        invocation=server._test_invocation,
        io_timeout_seconds=2.0,
    )


def _portable_material() -> launch.ControlledWorkerLaunchMaterial:
    with tempfile.TemporaryDirectory(prefix="bf-invocation-") as directory:
        profile = _profile()
        invocation = _invocation(Path(directory), profile)
        return launch.ControlledWorkerLaunchMaterial(
            profile=profile,
            binding=replace(_binding(profile), plan_digest=invocation.intent_digest),
            endpoint="/run/bluefire/private/controller.sock",
            token="a" * 64,
            controller_pid=123,
            controller_uid=1000,
            controller_gid=1000,
            environment=tuple(sorted(_environment().items())),
            package_identities=(_identities("strix-agent"), _identities("openai-agents")),
            invocation=invocation,
        )


def _installed_model_lease(
    invocation: invocation_module.ControlledWorkerInvocation,
    binding: channel.ControlledWorkerBinding,
    *,
    protected_revocation_verified: bool = True,
    reconcile: str | None = None,
    provider_kind: str = "test",
    live_model_proof: bool = False,
) -> tuple[worker_model_gateway.InstalledStrixV2ModelGatewayLease, SimpleNamespace]:
    token = "test-relay-bearer-" + "a" * 32
    authorization_ref = content_hash(
        {
            "schema_version": "bluefire.model-gateway-authorization-ref.v1",
            "attempt_id": invocation.profile_attempt_id,
            "authorization_digest": invocation.model_authorization_digest,
        }
    )
    gateway = SimpleNamespace(
        authorization_ref=authorization_ref, secret_value=lambda: token, revocations=0
    )

    def revoke() -> SimpleNamespace:
        gateway.revocations += 1
        return SimpleNamespace(
            protected_revocation_verified=protected_revocation_verified,
            receipt_digest="sha256:" + "e" * 64,
        )

    gateway.revoke = revoke
    maintained = ControlledModelGatewayLease(gateway)
    custody = (1234, 1001, 1001, 987654, (1234,))
    return (
        worker_model_gateway.InstalledStrixV2ModelGatewayLease(
            maintained,
            binding=binding,
            invocation=invocation,
            custody_identity=custody,
            engine_binding_ref="sha256:" + "1" * 64,
            delegation_ref="sha256:" + "2" * 64,
            accepted_claim_ref="sha256:" + "3" * 64,
            admission_ref="sha256:" + "4" * 64,
            relay_listener_ref="sha256:" + "5" * 64,
            model_provider="controlled-test",
            model_data_destination=dict(invocation.environment)["LLM_API_BASE"],
            provider_kind=provider_kind,
            live_model_proof=live_model_proof,
            reconcile_revocation=lambda: reconcile,
        ),
        gateway,
    )


@asynccontextmanager
async def _server(
    effects: FakeTransport | None = None,
    *,
    lifetime_seconds: float = 5.0,
    peer_pid: int | None = None,
    cancellation: threading.Event | None = None,
) -> AsyncIterator[tuple[rpc.AttemptControllerServer, FakeTransport, asyncio.Task[None]]]:
    # Keep the actual Unix path below sockaddr_un's cap even with a long pytest root.
    with tempfile.TemporaryDirectory(prefix="bf-rpc-") as directory:
        profile = _profile()
        invocation = _invocation(Path(directory), profile)
        binding = replace(
            _binding(profile),
            plan_digest=invocation.intent_digest,
            deadline_ns=time.monotonic_ns() + int(lifetime_seconds * 1_000_000_000),
        )
        effects = (effects or FakeTransport()).bind(profile)
        lease = _ModelLease()
        server = rpc.AttemptControllerServer(Path(directory), profile, binding, effects, lease)
        server._test_invocation = invocation
        server._test_model_lease = lease
        server._test_launch_path = launch.write_launch_material(server, _material(server))
        selected_pid = os.getpid() if peer_pid is None else peer_pid
        worker_pidfd = os.pidfd_open(selected_pid, 0)
        worker = rpc.OwnedWorkerProcess(
            pid=selected_pid,
            uid=os.geteuid(),
            gid=os.getegid(),
            pidfd=worker_pidfd,
        )
        serving = asyncio.create_task(
            server.serve(
                worker=worker,
                containment_authority=_test_boundary(worker),
                cancellation=cancellation if cancellation is not None else threading.Event(),
            )
        )
        # Let the server acquire process custody before a synchronous test body
        # can finish and cancel an otherwise never-started coroutine.
        await asyncio.sleep(0)
        ready = server.wait_until_custody_ready(0.1)
        assert ready.server_identity_ref == server.server_identity_ref
        assert ready.startup_overlay_ref == invocation.startup_overlay_ref
        assert ready.installed_projection_ref == invocation_module.PROC_MEMFD_PROJECTION_REF
        os.close(worker_pidfd)
        try:
            yield server, effects, serving
        finally:
            server.close()
            if not serving.done():
                serving.cancel()
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await asyncio.wait_for(serving, 2.0)


async def _client(server: rpc.AttemptControllerServer) -> rpc.SocketControlledControllerTransport:
    path = server._test_launch_path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    material = launch.read_launch_material(path)
    assert not path.exists()
    with pytest.raises(rpc.ControlledWorkerRPCError):
        launch.read_launch_material(path)
    connected = await asyncio.to_thread(launch.connect_worker, material)
    assert connected.model_gateway_token == _ModelLease.token
    return connected.transport


async def _raw_client(
    server: rpc.AttemptControllerServer, *, token: str | None = None
) -> socket.socket:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    packets.configure_socket(connection)
    loop = asyncio.get_running_loop()
    await loop.sock_connect(connection, str(server.endpoint))
    await rpc.write_frame(
        connection,
        rpc.hello(server.channel.binding, server.token if token is None else token),
        server.deadline(),
    )
    return connection


def _oversized_packet(limit: int) -> bytes:
    payload = b"x"
    return (
        packets._HEADER.pack(
            packets._MAGIC,
            b"o" * 16,
            limit + 5,
            0,
            len(payload),
            0,
        )
        + payload
    )


async def _ack(connection: socket.socket, server: rpc.AttemptControllerServer) -> None:
    frame = await rpc.read_frame(
        connection,
        server.deadline(),
        limit=rpc.HANDSHAKE_LIMIT,
        expected_peer=packets.PeerIdentity(os.getpid(), os.geteuid(), os.getegid()),
    )
    assert channel.decode_frame(frame) == channel.decode_frame(
        rpc._ack(server.channel.binding, _ModelLease.token)
    )


def _worker_flags(**overrides: Any) -> SimpleNamespace:
    values = {
        "isolated": 1,
        "no_site": 1,
        "no_user_site": 1,
        "dont_write_bytecode": 1,
        "utf8_mode": 1,
        "safe_path": True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_exact_typed_rpc_method_surface_and_no_fixture_import() -> None:
    methods = {
        name
        for name in vars(rpc.SocketControlledControllerTransport)
        if not name.startswith("_") and name != "close"
    }
    assert methods == set(backend._TRANSPORT_METHODS) == set(channel.METHODS)
    for name in methods:
        method = getattr(rpc.SocketControlledControllerTransport, name)
        assert inspect.iscoroutinefunction(method)
        assert tuple(inspect.signature(method).parameters) == ("self", "request")
    source = inspect.getsource(rpc)
    assert "import subprocess" not in source
    assert "strix_controlled_worker_process" not in source
    assert "socket.AF_INET" not in source


def test_installed_entrypoint_sanitizes_upstream_bearer_exception(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bearer = "sentinel-relay-bearer-" + "z" * 48

    def fail() -> object:
        raise RuntimeError(f"provider failed with {bearer} and /private/launch.json")

    monkeypatch.setattr(installed, "main", fail)
    with pytest.raises(SystemExit) as stopped:
        installed.entrypoint()
    captured = capsys.readouterr()
    assert stopped.value.code == 2
    assert bearer not in str(stopped.value)
    assert bearer not in captured.out + captured.err
    assert "/private/launch.json" not in captured.out + captured.err


def test_installed_entrypoint_preserves_upstream_system_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = SystemExit(7)

    def stop() -> object:
        raise expected

    monkeypatch.setattr(installed, "main", stop)
    with pytest.raises(SystemExit) as stopped:
        installed.entrypoint()
    assert stopped.value is expected


def test_installed_entrypoint_sanitizes_message_system_exit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bearer = "sentinel-relay-bearer-" + "q" * 48

    def stop() -> object:
        raise SystemExit(f"provider stopped with {bearer}")

    monkeypatch.setattr(installed, "main", stop)
    with pytest.raises(SystemExit) as stopped:
        installed.entrypoint()
    captured = capsys.readouterr()
    assert stopped.value.code == 2
    assert bearer not in str(stopped.value)
    assert bearer not in captured.out + captured.err


@pytest.mark.parametrize("error_type", [asyncio.CancelledError, KeyboardInterrupt])
def test_installed_entrypoint_sanitizes_non_exception_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error_type: type[BaseException],
) -> None:
    bearer = "sentinel-relay-bearer-" + "w" * 48

    def stop() -> object:
        raise error_type(f"provider stopped with {bearer}")

    monkeypatch.setattr(installed, "main", stop)
    with pytest.raises(SystemExit) as stopped:
        installed.entrypoint()
    captured = capsys.readouterr()
    assert stopped.value.code == 2
    assert bearer not in str(stopped.value)
    assert bearer not in captured.out + captured.err


def test_dispatcher_uses_live_post_effect_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile()
    binding = _binding(profile)
    worker = channel.WorkerChannel(profile, binding)
    controller = channel.ControllerChannel(profile, binding)
    effects = FakeTransport().bind(profile)
    dispatcher = channel.ControllerDispatcher(controller, effects)
    frame = worker.request(
        "create_exact",
        backend.ControlledCreateRequest.create(profile),
        request_id="1" * 32,
        now_ns=100,
    )
    accepted = dispatcher.accept(frame, received_ns=100)
    monkeypatch.setattr(channel.time, "monotonic_ns", lambda: binding.deadline_ns)
    with pytest.raises(channel.ControlledWorkerChannelError):
        _complete(accepted)
    assert len(effects.calls) == 1
    assert not controller.usable


def test_material_repr_hides_capability_and_exact_protocol_binding() -> None:
    material = _portable_material()
    assert material.token not in repr(material)
    assert material.endpoint not in repr(material)
    assert material.wire()["binding"] == material.binding.wire()
    assert material.wire()["schema_version"] == launch.LAUNCH_VERSION
    encoded = channel.encode_frame(material.wire())
    assert _ModelLease.token.encode("utf-8") not in encoded
    assert b"LLM_API_KEY" not in encoded


def test_installed_model_lease_joins_real_maintained_lease_shape_once() -> None:
    material = _portable_material()
    lease, gateway = _installed_model_lease(material.invocation, material.binding)
    custody = (1234, 1001, 1001, 987654, (1234,))
    token = lease.claim(material.binding, custody)

    assert token == "test-relay-bearer-" + "a" * 32
    assert not hasattr(lease, "secret_value")
    assert token not in repr(lease)
    assert lease.lease_binding_ref.startswith("sha256:")
    assert lease.custody_identity_ref.startswith("sha256:")
    assert lease.provider_kind == "test"
    assert lease.live_model_proof is False
    assert lease.revocation_ref is None
    for name, value in (
        ("authorization_ref", "sha256:" + "0" * 64),
        ("custody_identity_ref", "sha256:" + "0" * 64),
        ("lease_binding_ref", "sha256:" + "0" * 64),
        ("cleanup_uncertain", False),
    ):
        with pytest.raises(AttributeError):
            setattr(lease, name, value)
    with pytest.raises(worker_model_gateway.InstalledStrixV2ModelGatewayLeaseError):
        lease.claim(material.binding, custody)

    lease.close()
    lease.close()
    assert gateway.revocations == 1
    assert not lease.cleanup_uncertain
    assert lease.revocation_ref == "sha256:" + "e" * 64


def test_installed_model_lease_recovers_ambiguous_protected_revocation() -> None:
    material = _portable_material()
    reconciled = "sha256:" + "f" * 64
    lease, gateway = _installed_model_lease(
        material.invocation,
        material.binding,
        protected_revocation_verified=False,
        reconcile=reconciled,
    )

    lease.close()
    assert gateway.revocations == 1
    assert not lease.cleanup_uncertain
    assert lease.revocation_ref == reconciled


def test_installed_model_lease_requires_explicit_provider_proof_classification() -> None:
    material = _portable_material()
    live, _gateway = _installed_model_lease(
        material.invocation,
        material.binding,
        provider_kind="live",
        live_model_proof=True,
    )
    assert live.provider_kind == "live"
    assert live.live_model_proof is True
    with pytest.raises(AttributeError):
        live.provider_kind = "test"  # type: ignore[misc]
    live.close()

    with pytest.raises(worker_model_gateway.InstalledStrixV2ModelGatewayLeaseError):
        _installed_model_lease(
            material.invocation,
            material.binding,
            provider_kind="test",
            live_model_proof=True,
        )
    with pytest.raises(worker_model_gateway.InstalledStrixV2ModelGatewayLeaseError):
        _installed_model_lease(
            material.invocation,
            material.binding,
            provider_kind="inferred-live",
        )


def test_installed_model_lease_revoke_before_claim_is_terminal() -> None:
    material = _portable_material()
    lease, _gateway = _installed_model_lease(material.invocation, material.binding)
    custody = (1234, 1001, 1001, 987654, (1234,))

    lease.revoke()
    assert lease.revocation_ref == "sha256:" + "e" * 64
    with pytest.raises(worker_model_gateway.InstalledStrixV2ModelGatewayLeaseError):
        lease.claim(material.binding, custody)


def test_installed_model_lease_allows_exactly_one_concurrent_claim() -> None:
    material = _portable_material()
    lease, _gateway = _installed_model_lease(material.invocation, material.binding)
    custody = (1234, 1001, 1001, 987654, (1234,))
    barrier = threading.Barrier(3)
    tokens: list[str] = []
    failures: list[BaseException] = []

    def claim() -> None:
        barrier.wait()
        try:
            tokens.append(lease.claim(material.binding, custody))
        except BaseException as error:
            failures.append(error)

    workers = [threading.Thread(target=claim) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join(timeout=5)
        assert not worker.is_alive()
    assert tokens == ["test-relay-bearer-" + "a" * 32]
    assert len(failures) == 1
    assert isinstance(failures[0], worker_model_gateway.InstalledStrixV2ModelGatewayLeaseError)
    lease.close()


def test_installed_model_lease_revoke_overtakes_blocked_claim() -> None:
    material = _portable_material()
    lease, gateway = _installed_model_lease(material.invocation, material.binding)
    custody = (1234, 1001, 1001, 987654, (1234,))
    started = threading.Event()
    release = threading.Event()
    tokens: list[str] = []
    failures: list[BaseException] = []

    def blocked_secret() -> str:
        started.set()
        assert release.wait(5)
        return "test-relay-bearer-" + "a" * 32

    gateway.secret_value = blocked_secret

    def claim() -> None:
        try:
            tokens.append(lease.claim(material.binding, custody))
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=claim)
    worker.start()
    assert started.wait(5)
    lease.close()
    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert tokens == []
    assert len(failures) == 1
    assert isinstance(failures[0], worker_model_gateway.InstalledStrixV2ModelGatewayLeaseError)
    assert lease.revocation_ref == "sha256:" + "e" * 64


def test_installed_model_lease_failed_revoke_permanently_refuses_claim() -> None:
    material = _portable_material()
    lease, _gateway = _installed_model_lease(
        material.invocation,
        material.binding,
        protected_revocation_verified=False,
        reconcile=None,
    )
    custody = (1234, 1001, 1001, 987654, (1234,))

    with pytest.raises(worker_model_gateway.InstalledStrixV2ModelGatewayLeaseError):
        lease.close()
    assert lease.cleanup_uncertain
    with pytest.raises(AttributeError):
        lease.cleanup_uncertain = False  # type: ignore[misc]
    assert lease.cleanup_uncertain
    assert lease.revocation_ref is None
    with pytest.raises(worker_model_gateway.InstalledStrixV2ModelGatewayLeaseError):
        lease.claim(material.binding, custody)


@pytest.mark.parametrize(
    "field,value",
    [
        ("intent_digest", "sha256:" + "f" * 64),
        ("target", "http://different.example/"),
        ("model", "different-model"),
        ("wall_seconds", 1),
        ("profile_attempt_id", "engine-attempt-" + "f" * 32),
        ("startup_overlay_ref", "sha256:" + "f" * 64),
        ("startup_overlay_receipt", (("schema_version", "unreviewed"),)),
    ],
)
def test_invocation_substitution_breaks_the_plan_join(field: str, value: Any) -> None:
    invocation = _portable_material().invocation
    with pytest.raises(invocation_module.ControlledWorkerInvocationError):
        replace(invocation, **{field: value})


@linux
@pytest.mark.parametrize("fault", ["objective_bytes", "objective_mode", "config_link", "cwd_mode"])
def test_invocation_reopens_exact_workspace_files_before_model_authority(
    tmp_path: Path, fault: str
) -> None:
    invocation = _invocation(tmp_path, _profile())
    cwd = Path(invocation.cwd)
    if fault == "objective_bytes":
        (cwd / "objective.txt").write_text("changed\n", encoding="utf-8")
        (cwd / "objective.txt").chmod(0o600)
    elif fault == "objective_mode":
        (cwd / "objective.txt").chmod(0o644)
    elif fault == "config_link":
        config = cwd / "config" / "cli-config.json"
        replacement = cwd / "replacement.json"
        replacement.write_text('{"env":{}}\n', encoding="utf-8")
        replacement.chmod(0o600)
        config.unlink()
        config.symlink_to(replacement)
    else:
        cwd.chmod(0o755)
    with pytest.raises(invocation_module.ControlledWorkerInvocationError):
        invocation.validate_installed_files()


@linux
@pytest.mark.parametrize(
    "fault", ["cwd_mode", "home_mode", "tmp_link", "tmp_mode", "executable_bytes"]
)
def test_descriptor_bind_mode_revalidates_fixed_guest_projection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fault: str
) -> None:
    controlled = _invocation(tmp_path, _profile())
    cwd = Path(controlled.cwd)
    guest = tmp_path / "guest"
    guest_executable = guest / "runtime" / "bin" / "strix"
    guest_cwd = guest / "workspace"
    guest_home = guest / "home" / "worker"
    guest_tmp = guest / "tmp"
    guest_executable.parent.mkdir(parents=True)
    guest_executable.write_bytes(
        invocation_module.fixed_guest_console_script(Path(controlled.argv[0]).read_bytes())
    )
    guest_executable.chmod(0o444)
    for directory in (guest_cwd, guest_home, guest_tmp):
        directory.mkdir(parents=True, mode=0o700)
        directory.chmod(0o700)
    monkeypatch.setattr(invocation_module, "DESCRIPTOR_BIND_GUEST_EXECUTABLE", guest_executable)
    monkeypatch.setattr(invocation_module, "DESCRIPTOR_BIND_GUEST_RUNTIME_UID", os.geteuid())
    monkeypatch.setattr(invocation_module, "DESCRIPTOR_BIND_GUEST_CWD", guest_cwd)
    monkeypatch.setattr(invocation_module, "DESCRIPTOR_BIND_GUEST_HOME", guest_home)
    monkeypatch.setattr(invocation_module, "DESCRIPTOR_BIND_GUEST_TMP", guest_tmp)
    payloads = {
        Path("/inputs/objective.json"): (cwd / "objective.txt").read_bytes(),
        Path("/inputs/config.json"): (cwd / "config" / "cli-config.json").read_bytes(),
        Path("/inputs/mcp.json"): (cwd / "config" / "mcp-servers.json").read_bytes(),
    }
    monkeypatch.setattr(
        invocation_module,
        "_sealed_bind_bytes",
        lambda path, *, maximum: payloads[path][:maximum],
    )
    if fault == "cwd_mode":
        guest_cwd.chmod(0o755)
    elif fault == "home_mode":
        guest_home.chmod(0o755)
    elif fault == "tmp_link":
        guest_tmp.rmdir()
        guest_tmp.symlink_to(guest_home, target_is_directory=True)
    elif fault == "tmp_mode":
        guest_tmp.chmod(0o755)
    else:
        guest_executable.chmod(0o644)
        guest_executable.write_bytes(b"substituted executable")
    with pytest.raises(invocation_module.ControlledWorkerInvocationError):
        controlled.pin_installed_inputs(mode=invocation_module.DESCRIPTOR_BIND_INPUT_MODE)


@linux
def test_descriptor_bind_mode_derives_only_fixed_mounted_input_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    controlled = _invocation(tmp_path, _profile())
    cwd = Path(controlled.cwd)
    guest = tmp_path / "guest"
    guest_executable = guest / "runtime" / "bin" / "strix"
    guest_executable.parent.mkdir(parents=True)
    guest_executable.write_bytes(
        invocation_module.fixed_guest_console_script(Path(controlled.argv[0]).read_bytes())
    )
    guest_executable.chmod(0o444)
    guest_cwd = guest / "workspace"
    guest_home = guest / "home" / "worker"
    guest_tmp = guest / "tmp"
    for directory in (guest_cwd, guest_home, guest_tmp):
        directory.mkdir(parents=True, mode=0o700)
        directory.chmod(0o700)
    monkeypatch.setattr(invocation_module, "DESCRIPTOR_BIND_GUEST_EXECUTABLE", guest_executable)
    monkeypatch.setattr(invocation_module, "DESCRIPTOR_BIND_GUEST_RUNTIME_UID", os.geteuid())
    monkeypatch.setattr(invocation_module, "DESCRIPTOR_BIND_GUEST_CWD", guest_cwd)
    monkeypatch.setattr(invocation_module, "DESCRIPTOR_BIND_GUEST_HOME", guest_home)
    monkeypatch.setattr(invocation_module, "DESCRIPTOR_BIND_GUEST_TMP", guest_tmp)
    payloads = {
        Path("/inputs/objective.json"): (cwd / "objective.txt").read_bytes(),
        Path("/inputs/config.json"): (cwd / "config" / "cli-config.json").read_bytes(),
        Path("/inputs/mcp.json"): (cwd / "config" / "mcp-servers.json").read_bytes(),
    }
    monkeypatch.setattr(
        invocation_module,
        "_sealed_bind_bytes",
        lambda path, *, maximum: payloads[path][:maximum],
    )
    pinned = controlled.pin_installed_inputs(mode=invocation_module.DESCRIPTOR_BIND_INPUT_MODE)
    try:
        assert pinned.argv[9:14:2] == (
            "/inputs/objective.json",
            "/inputs/config.json",
            "/inputs/mcp.json",
        )
        assert pinned.argv[0] == str(guest_executable)
        assert pinned.cwd == str(guest_cwd)
        environment = pinned.runtime_environment(dict(controlled.environment))
        assert environment["HOME"] == str(guest_home)
        assert environment["PATH"] == "/runtime/bin"
        assert environment["TMPDIR"] == str(guest_tmp)
        assert pinned._descriptors == ()
    finally:
        pinned.close()


@pytest.mark.parametrize(
    "values",
    [
        {"token": ""},
        {"token": "A" * 64},
        {"endpoint": "relative/controller.sock"},
        {"controller_pid": 0},
        {"controller_pid": True},
        {"controller_uid": -1},
        {"controller_uid": True},
        {"controller_gid": -1},
        {"controller_gid": True},
        {"installed_input_mode": "unreviewed"},
        {"io_timeout_seconds": float("nan")},
        {"io_timeout_seconds": float("inf")},
        {"io_timeout_seconds": False},
    ],
)
def test_material_rejects_invalid_scalar_values(values: dict[str, Any]) -> None:
    with pytest.raises(rpc.ControlledWorkerRPCError):
        replace(_portable_material(), **values)


@pytest.mark.parametrize("field", ["POLICY", "MANIFEST", "BOUNDARY", "RELAY", "TMPFS"])
def test_material_environment_must_match_every_profile_identity(field: str) -> None:
    material = _portable_material()
    environment = dict(material.environment)
    environment[f"BLUEFIRE_STRIX_{field}_DIGEST"] = "sha256:" + "f" * 64
    with pytest.raises(rpc.ControlledWorkerRPCError):
        replace(material, environment=tuple(sorted(environment.items())))


def test_material_rejects_extra_credentials_duplicate_names_and_swapped_packages() -> None:
    material = _portable_material()
    environment = dict(material.environment)
    environment["OPENAI_API_KEY"] = "SENSITIVE_TEST_CREDENTIAL"
    with pytest.raises(rpc.ControlledWorkerRPCError):
        replace(material, environment=tuple(sorted(environment.items())))
    with pytest.raises(rpc.ControlledWorkerRPCError):
        replace(material, environment=material.environment + (material.environment[-1],))
    with pytest.raises(rpc.ControlledWorkerRPCError):
        replace(material, package_identities=tuple(reversed(material.package_identities)))


@pytest.mark.parametrize(
    "extra", ["OPENAI_API_KEY", "DOCKER_HOST", "PATH", "PYTHONPATH", "HTTP_PROXY"]
)
def test_launch_environment_rejects_ambient_authority(extra: str) -> None:
    exact = {
        launch.LAUNCH_ENVIRONMENT_NAME: "/run/private/launch.json",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/runtime/bin",
    }
    with pytest.raises(rpc.ControlledWorkerRPCError):
        launch.validate_process_environment(dict(exact, **{extra: "untrusted"}))
    assert launch.validate_process_environment(exact) == Path("/run/private/launch.json")


@pytest.mark.parametrize(
    "environment",
    [
        {launch.LAUNCH_ENVIRONMENT_NAME: "/run/private/launch.json"},
        {
            launch.LAUNCH_ENVIRONMENT_NAME: "/run/private/launch.json",
            "LANG": "C.UTF-8",
            "LC_ALL": "C",
        },
        {
            launch.LAUNCH_ENVIRONMENT_NAME: "/run/private/launch.json",
            "LANG": "C",
            "LC_ALL": "C.UTF-8",
            "PATH": "/runtime/bin",
        },
        {
            launch.LAUNCH_ENVIRONMENT_NAME: "/run/private/launch.json",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/host/bin",
        },
    ],
)
def test_launch_environment_requires_exact_fixed_locale(
    environment: dict[str, str],
) -> None:
    with pytest.raises(rpc.ControlledWorkerRPCError):
        launch.validate_process_environment(environment)


@pytest.mark.parametrize(
    "argv,flag,flag_value",
    [
        (["worker", "fixture"], "isolated", 1),
        (["worker"], "isolated", 0),
        (["worker"], "dont_write_bytecode", 0),
        (["worker"], "no_site", 0),
        (["worker"], "no_user_site", 0),
        (["worker"], "utf8_mode", 0),
        (["worker"], "safe_path", False),
    ],
)
def test_installed_entrypoint_refuses_before_launch_material(
    monkeypatch: pytest.MonkeyPatch, argv: list[str], flag: str, flag_value: object
) -> None:
    monkeypatch.setattr(rpc, "require_linux", lambda: None)
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(sys, "flags", _worker_flags(**{flag: flag_value}))
    monkeypatch.setattr(
        launch,
        "read_launch_material",
        lambda _path: pytest.fail("read material before launch checks"),
    )
    with pytest.raises(rpc.ControlledWorkerRPCError):
        installed.main()


def test_installed_entrypoint_injects_exact_material_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment()
    identities = (_identities("strix-agent"), _identities("openai-agents"))
    checked: list[bool] = []
    pinned_closed: list[bool] = []
    pinned = SimpleNamespace(
        argv=("strix", "-n"),
        cwd=os.getcwd(),
        runtime_environment=lambda base: dict(base),
        close=lambda: pinned_closed.append(True),
    )
    invocation = SimpleNamespace(
        pin_installed_inputs=lambda *, mode: (
            checked.append(mode == invocation_module.PROC_MEMFD_INPUT_MODE),
            pinned,
        )[1],
        runtime_environment=lambda _bootstrap_environment: {
            "STRIX_LLM": "controlled-test-provider"
        },
        cwd=os.getcwd(),
    )
    material = SimpleNamespace(
        environment=tuple(sorted(environment.items())),
        package_identities=identities,
        invocation=invocation,
        installed_input_mode=invocation_module.PROC_MEMFD_INPUT_MODE,
    )
    closed: list[bool] = []
    transport = SimpleNamespace(close=lambda: closed.append(True))
    monkeypatch.setattr(rpc, "require_linux", lambda: None)
    monkeypatch.setattr(sys, "argv", ["worker"])
    monkeypatch.setattr(sys, "flags", _worker_flags())
    monkeypatch.setattr(
        os,
        "environ",
        {
            launch.LAUNCH_ENVIRONMENT_NAME: "/run/private/launch.json",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/runtime/bin",
        },
    )
    monkeypatch.setattr(launch, "read_launch_material", lambda _path: material)
    monkeypatch.setattr(
        launch,
        "connect_worker",
        lambda observed: (
            SimpleNamespace(
                transport=transport,
                model_gateway_token="test-relay-bearer-" + "a" * 32,
            )
            if observed is material
            else pytest.fail("wrong material")
        ),
    )

    def bootstrap_main(**values: Any) -> str:
        assert values["transport"] is transport
        assert values["environment"] == environment
        assert os.environ["STRIX_LLM"] == "controlled-test-provider"
        assert os.environ["LLM_API_KEY"].startswith("test-relay-bearer-")
        assert "DOCKER_HOST" not in os.environ
        assert sys.argv == ["strix", "-n"]
        assert values["identity_getter"]("strix-agent") == identities[0]
        assert values["identity_getter"]("openai-agents") == identities[1]
        return "bootstrap-only"

    monkeypatch.setattr(installed.bootstrap, "main", bootstrap_main)
    assert installed.main() == "bootstrap-only"
    assert checked == [True]
    assert "LLM_API_KEY" not in os.environ
    assert closed == [True]
    assert pinned_closed == [True]


@linux
def test_installed_entrypoint_applies_exact_reviewed_plan_and_scrubs_relay_bearer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = _profile()
    invocation = _invocation(tmp_path, profile)
    material = SimpleNamespace(
        environment=tuple(sorted(_environment().items())),
        package_identities=(_identities("strix-agent"), _identities("openai-agents")),
        invocation=invocation,
        installed_input_mode=invocation_module.PROC_MEMFD_INPUT_MODE,
    )
    closed: list[bool] = []
    transport = SimpleNamespace(close=lambda: closed.append(True))
    observed: dict[str, Any] = {}
    monkeypatch.setattr(sys, "argv", ["worker"])
    monkeypatch.setattr(sys, "flags", _worker_flags())
    monkeypatch.setattr(
        os,
        "environ",
        {
            launch.LAUNCH_ENVIRONMENT_NAME: "/private/launch.json",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/runtime/bin",
        },
    )
    monkeypatch.setattr(launch, "read_launch_material", lambda _path: material)
    monkeypatch.setattr(
        launch,
        "connect_worker",
        lambda _material: SimpleNamespace(
            transport=transport, model_gateway_token=_ModelLease.token
        ),
    )

    def bootstrap_main(**values: Any) -> str:
        observed.update(
            argv=tuple(sys.argv),
            cwd=os.getcwd(),
            environment=dict(os.environ),
            bootstrap_environment=values["environment"],
            objective=Path(sys.argv[9]).read_bytes(),
            config=Path(sys.argv[11]).read_bytes(),
            mcp=Path(sys.argv[13]).read_bytes(),
        )
        return "installed-plan"

    monkeypatch.setattr(installed.bootstrap, "main", bootstrap_main)
    assert installed.main() == "installed-plan"
    assert observed["argv"][:9] == invocation.argv[:9]
    assert observed["argv"][10] == invocation.argv[10]
    assert observed["argv"][12] == invocation.argv[12]
    assert observed["argv"][14:] == invocation.argv[14:]
    assert all(observed["argv"][index].startswith("/proc/self/fd/") for index in (9, 11, 13))
    assert observed["objective"] == (Path(invocation.cwd) / "objective.txt").read_bytes()
    assert observed["config"] == b'{"env":{}}\n'
    assert observed["mcp"] == b"[]\n"
    assert observed["cwd"] == invocation.cwd
    assert observed["environment"]["LLM_API_KEY"] == _ModelLease.token
    assert observed["environment"]["STRIX_RUNTIME_BACKEND"] == backend.BACKEND_NAME
    assert observed["bootstrap_environment"] == _environment()
    assert "LLM_API_KEY" not in os.environ
    assert closed == [True]


@linux
def test_installed_inputs_are_sealed_against_workspace_path_replacement(tmp_path: Path) -> None:
    invocation = _invocation(tmp_path, _profile())
    objective_path = Path(invocation.cwd) / "objective.txt"
    original = objective_path.read_bytes()
    pinned = invocation.pin_installed_inputs()
    try:
        replacement = objective_path.with_name("replacement.txt")
        replacement.write_bytes(b"changed after validation")
        replacement.chmod(0o600)
        os.replace(replacement, objective_path)
        assert Path(pinned.argv[9]).read_bytes() == original
        descriptor = int(Path(pinned.argv[9]).name)
        with pytest.raises(OSError):
            os.write(descriptor, b"changed")
    finally:
        pinned.close()


@linux
def test_failed_model_lease_revoke_remains_retryable(tmp_path: Path) -> None:
    class FlakyLease(_ModelLease):
        def revoke(self) -> None:
            self.revoked += 1
            if self.revoked == 1:
                raise OSError("synthetic relay outage")

    profile = _profile()
    binding = _binding(profile)
    lease = FlakyLease()
    server = rpc.AttemptControllerServer(
        tmp_path, profile, binding, FakeTransport().bind(profile), lease
    )
    server.close()
    assert server.cleanup_uncertain
    assert not server._model_gateway_revoked
    server.close()
    assert server._model_gateway_revoked
    assert lease.revoked == 2
    assert not server.cleanup_uncertain


@linux
@pytest.mark.parametrize("exit_stage", ["before_claim", "before_admission"])
def test_worker_exit_is_rechecked_before_model_or_effect_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exit_stage: str
) -> None:
    async def run() -> None:
        profile = _profile()
        invocation = _invocation(tmp_path, profile)
        binding = replace(
            _binding(profile),
            plan_digest=invocation.intent_digest,
            deadline_ns=time.monotonic_ns() + 5_000_000_000,
        )
        effects = FakeTransport().bind(profile)
        lease = _ModelLease()
        server = rpc.AttemptControllerServer(tmp_path, profile, binding, effects, lease)
        server._test_invocation = invocation
        server._test_launch_path = launch.write_launch_material(server, _material(server))
        request = channel.WorkerChannel(profile, binding).request(
            "create_exact",
            backend.ControlledCreateRequest.create(profile),
            request_id="e" * 32,
            now_ns=time.monotonic_ns(),
        )
        wait_for_exit, release_exit = os.pipe()
        child = os.fork()
        if child == 0:
            try:
                os.close(release_exit)
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                packets.configure_socket(connection)
                connection.setblocking(True)
                connection.connect(str(server.endpoint))
                for packet in packets._packets_for_frame(
                    rpc.hello(binding, server.token), frame_id=b"h" * 16
                ):
                    connection.send(packet)
                if exit_stage == "before_admission":
                    connection.recvmsg(
                        packets.PACKET_BYTES,
                        socket.CMSG_SPACE(packets._CREDENTIALS.size),
                    )
                    for packet in packets._packets_for_frame(request, frame_id=b"r" * 16):
                        connection.send(packet)
                os.read(wait_for_exit, 1)
                connection.close()
            except BaseException:
                os._exit(2)
            os._exit(0)
        os.close(wait_for_exit)
        pidfd = os.pidfd_open(child, 0)
        worker = rpc.OwnedWorkerProcess(child, os.geteuid(), os.getegid(), pidfd)
        os.close(pidfd)
        original_read = rpc.read_frame
        reads = 0
        reaped = False

        async def observe_exit(*args: Any, **kwargs: Any) -> bytes:
            nonlocal reads, reaped
            frame = await original_read(*args, **kwargs)
            reads += 1
            selected = 1 if exit_stage == "before_claim" else 2
            if reads == selected:
                os.write(release_exit, b"x")
                status = await asyncio.to_thread(os.waitpid, child, 0)
                reaped = True
                assert os.waitstatus_to_exitcode(status[1]) == 0
            return frame

        monkeypatch.setattr(rpc, "read_frame", observe_exit)
        try:
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await server.serve(
                    worker=worker,
                    containment_authority=_test_boundary(worker),
                    cancellation=threading.Event(),
                )
            assert effects.calls == []
            assert lease.claimed == (0 if exit_stage == "before_claim" else 1)
            assert lease.revoked == 1
        finally:
            server.close()
            os.close(release_exit)
            if not reaped:
                with suppress(ProcessLookupError):
                    os.kill(child, 9)
                with suppress(ChildProcessError):
                    os.waitpid(child, 0)

    asyncio.run(run())


@linux
def test_real_socket_all_serial_roundtrips_preserve_controller_handle() -> None:
    async def run() -> None:
        async with _server() as (server, effects, _serving):
            client = await _client(server)
            try:
                created = await client.create_exact(
                    backend.ControlledCreateRequest.create(server.channel.profile)
                )
                assert created.handle.opaque_ref is not effects.handle.opaque_ref
                methods = (
                    "reconcile_create",
                    "exec_exact",
                    "read_exact",
                    "begin_write_exact",
                    "write_chunk_exact",
                    "commit_write_exact",
                    "reconcile_write_exact",
                    "abort_write_exact",
                    "running_exact",
                    "persist_exact",
                    "hydrate_exact",
                    "resolve_caido_exact",
                    "delete_exact",
                )
                for name in methods:
                    request = _request(name, server.channel.profile, created.handle)
                    receipt = await getattr(client, name)(request)
                    assert type(receipt) is channel.METHODS[name].receipt_type
                    if name != "reconcile_create":
                        assert effects.calls[-1][1].handle is effects.handle
                assert client.channel.pending_count == server.channel.pending_count == 0
                assert client.channel.usable and server.channel.usable
            finally:
                client.close()
        assert server._test_model_lease.claimed == 1
        assert server._test_model_lease.revoked == 1

    asyncio.run(run())


@linux
@pytest.mark.parametrize("fault", ["permissions", "symlink", "oversize", "schema", "duplicate_key"])
def test_protected_material_rejects_loose_or_malformed_files(fault: str) -> None:
    async def run() -> None:
        async with _server() as (server, effects, _serving):
            path = server._test_launch_path
            if fault == "permissions":
                path.chmod(0o644)
            elif fault == "symlink":
                target = path.with_name("other.json")
                path.rename(target)
                path.symlink_to(target)
            elif fault == "oversize":
                path.write_bytes(b"x" * (launch.MAX_LAUNCH_BYTES + 1))
            elif fault == "schema":
                value = _material(server).wire()
                value["schema_version"] = "untrusted"
                path.write_bytes(channel.encode_frame(value))
            else:
                body = b'{"a":1,"a":2}'
                path.write_bytes(len(body).to_bytes(4, "little") + body)
            with pytest.raises(rpc.ControlledWorkerRPCError):
                launch.read_launch_material(path)
            assert effects.calls == []
            if fault in {"schema", "duplicate_key"}:
                assert not path.exists()

    asyncio.run(run())


@linux
def test_cancel_roundtrip_can_overtake_blocked_exec() -> None:
    async def run() -> None:
        effects = FakeTransport()
        effects.exec_started, effects.exec_gate = asyncio.Event(), asyncio.Event()
        async with _server(effects) as (server, _effects, _serving):
            client = await _client(server)
            try:
                handle = (
                    await client.create_exact(
                        backend.ControlledCreateRequest.create(server.channel.profile)
                    )
                ).handle
                request = _request("exec_exact", server.channel.profile, handle)
                execution = asyncio.create_task(client.exec_exact(request))
                await asyncio.wait_for(effects.exec_started.wait(), 1.0)
                cancellation = _request(
                    "cancel_exact",
                    server.channel.profile,
                    handle,
                    exec_digest=request.request_digest,
                )
                receipt = await asyncio.wait_for(client.cancel_exact(cancellation), 1.0)
                assert receipt.operation_lifecycle == "terminal"
                assert not execution.done()
                effects.exec_gate.set()
                assert (await execution).stdout == b"stdout"
                assert client.channel.usable and server.channel.usable
            finally:
                effects.exec_gate.set()
                client.close()

    asyncio.run(run())


@linux
@pytest.mark.parametrize(
    "fault",
    [
        "oversize",
        "duplicate_key",
        "partial_header",
        "partial_body",
        "replay",
        "sequence",
        "binding",
    ],
)
def test_malformed_replay_and_partial_frames_close_permanently(fault: str) -> None:
    async def run() -> None:
        async with _server() as (server, effects, serving):
            connection = await _raw_client(server)
            try:
                await _ack(connection, server)
                worker = channel.WorkerChannel(server.channel.profile, server.channel.binding)
                frame = worker.request(
                    "create_exact",
                    backend.ControlledCreateRequest.create(server.channel.profile),
                    request_id="1" * 32,
                    now_ns=time.monotonic_ns(),
                )
                if fault == "oversize":
                    frame = _oversized_packet(channel.MAX_FRAME_BYTES)
                elif fault == "duplicate_key":
                    body = b'{"a":1,"a":2}'
                    frame = len(body).to_bytes(4, "little") + body
                elif fault == "partial_header":
                    frame = frame[:2]
                elif fault == "partial_body":
                    frame = frame[:-2]
                elif fault in {"sequence", "binding"}:
                    value = channel.decode_frame(frame)
                    if fault == "sequence":
                        value["sequence"] += 1
                    else:
                        value["binding"]["nonce"] = "e" * 32
                    frame = channel.encode_frame(value)
                loop = asyncio.get_running_loop()
                if fault == "oversize":
                    connection.send(frame)
                else:
                    await rpc.write_frame(connection, frame, server.deadline())
                if fault == "replay":
                    await rpc.read_frame(
                        connection,
                        server.deadline(),
                        limit=channel.MAX_FRAME_BYTES,
                        expected_peer=packets.PeerIdentity(os.getpid(), os.geteuid(), os.getegid()),
                    )
                    await rpc.write_frame(connection, frame, server.deadline())
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert not server.channel.usable
                assert len(effects.calls) == (1 if fault == "replay" else 0)
                assert await loop.sock_recv(connection, 1) == b""
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    pidfd = os.pidfd_open(os.getpid(), 0)
                    try:
                        worker = rpc.OwnedWorkerProcess(
                            os.getpid(), os.geteuid(), os.getegid(), pidfd
                        )
                        await server.serve(
                            worker=worker,
                            containment_authority=_test_boundary(worker),
                            cancellation=threading.Event(),
                        )
                    finally:
                        os.close(pidfd)
            finally:
                connection.close()

    asyncio.run(run())


@linux
@pytest.mark.parametrize("fault", ["token", "worker_pid", "controller_pid"])
def test_bad_authentication_never_dispatches(fault: str) -> None:
    async def run() -> None:
        # Pin a live other process so SO_PEERCRED itself refuses the caller;
        # a nonexistent PID is already refused by the separate pidfd guard.
        async with _server(peer_pid=os.getppid() if fault == "worker_pid" else None) as (
            server,
            effects,
            serving,
        ):
            if fault == "controller_pid":
                material = replace(_material(server), controller_pid=os.getpid() + 1)
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.to_thread(launch.connect_worker, material)
            else:
                connection = await _raw_client(server, token="0" * 64 if fault == "token" else None)
                connection.close()
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await asyncio.wait_for(asyncio.shield(serving), 1.0)
            assert effects.calls == []
            assert not server.channel.usable
            assert server._test_model_lease.claimed == 0
            assert server._test_model_lease.revoked == 1

    asyncio.run(run())


@linux
@pytest.mark.parametrize(
    "input_mode",
    [invocation_module.PROC_MEMFD_INPUT_MODE, invocation_module.DESCRIPTOR_BIND_INPUT_MODE],
)
def test_connect_worker_checks_listener_creator_for_input_mode(
    monkeypatch: pytest.MonkeyPatch, input_mode: str
) -> None:
    with tempfile.TemporaryDirectory(prefix="bf-rpc-") as directory:
        profile = _profile()
        invocation = _invocation(Path(directory), profile)
        binding = replace(
            _binding(profile),
            plan_digest=invocation.intent_digest,
            deadline_ns=time.monotonic_ns() + 5_000_000_000,
        )
        server = rpc.AttemptControllerServer(
            Path(directory), profile, binding, FakeTransport().bind(profile), _ModelLease()
        )
        server._test_invocation = invocation
        controller_peer = os.getpid() + 1, os.geteuid() + 1, os.getegid() + 1
        material = replace(
            _material(server),
            installed_input_mode=input_mode,
            controller_pid=controller_peer[0],
            controller_uid=controller_peer[1],
            controller_gid=controller_peer[2],
        )
        observed: list[tuple[int, int, int]] = []

        def refuse_peer(
            _connection: socket.socket, pid: int, uid: int, gid: int
        ) -> bool:
            observed.append((pid, uid, gid))
            return False

        monkeypatch.setattr(rpc, "peer_matches", refuse_peer)
        try:
            with pytest.raises(rpc.ControlledWorkerRPCError):
                launch.connect_worker(material)
        finally:
            server.close()
        expected = (
            controller_peer
            if input_mode == invocation_module.PROC_MEMFD_INPUT_MODE
            else (os.getpid(), os.geteuid(), os.getegid())
        )
        assert observed == [expected]


@linux
def test_lost_model_authority_ack_revokes_lease_and_never_dispatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        original = rpc.write_frame

        async def fail_ack(connection: socket.socket, frame: bytes, deadline_ns: int) -> None:
            if b"model_gateway_token" in frame:
                raise rpc.ControlledWorkerRPCError("synthetic delivery loss")
            await original(connection, frame, deadline_ns)

        monkeypatch.setattr(rpc, "write_frame", fail_ack)
        async with _server() as (server, effects, serving):
            connection = await _raw_client(server)
            try:
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert server._test_model_lease.claimed == 1
                assert server._test_model_lease.revoked == 1
                assert effects.calls == []
            finally:
                connection.close()

    asyncio.run(run())


@linux
def test_close_during_model_claim_never_acks_post_revocation_authority() -> None:
    async def run() -> None:
        async with _server() as (server, effects, serving):
            lease = server._test_model_lease
            original_claim = lease.claim

            def close_during_claim(
                binding: channel.ControlledWorkerBinding,
                custody_identity: tuple[int, int, int, int, tuple[int, ...]],
            ) -> str:
                token = original_claim(binding, custody_identity)
                server.close()
                return token

            lease.claim = close_during_claim
            connection = await _raw_client(server)
            try:
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await rpc.read_frame(
                        connection,
                        server.channel.binding.deadline_ns,
                        limit=rpc.HANDSHAKE_LIMIT,
                        expected_peer=packets.PeerIdentity(os.getpid(), os.geteuid(), os.getegid()),
                    )
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert lease.claimed == 1
                assert lease.revoked >= 1
                assert effects.calls == []
            finally:
                connection.close()

    asyncio.run(run())


@linux
def test_controller_disconnect_fails_pending_worker_call_and_future_calls() -> None:
    async def run() -> None:
        effects = FakeTransport()
        effects.create_started, effects.create_gate = asyncio.Event(), asyncio.Event()
        async with _server(effects) as (server, _effects, _serving):
            client = await _client(server)
            request = backend.ControlledCreateRequest.create(server.channel.profile)
            pending = asyncio.create_task(client.create_exact(request))
            await asyncio.wait_for(effects.create_started.wait(), 1.0)
            server.close()
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await asyncio.wait_for(pending, 1.0)
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await client.create_exact(request)
            assert not client.channel.usable
            client.close()

    asyncio.run(run())


@linux
@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_server_cancellation_stops_admission_before_resistant_effect_settles(
    monkeypatch: pytest.MonkeyPatch, cleanup_failure: bool
) -> None:
    async def run() -> None:
        started, cancelled, release, settled = (asyncio.Event() for _ in range(4))

        class ResistantTransport(FakeTransport):
            async def create_exact(
                self, request: backend.ControlledCreateRequest
            ) -> backend.ControlledCreateReceipt:
                started.set()
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    cancelled.set()
                    await release.wait()
                settled.set()
                return await super().create_exact(request)

        async with _server(ResistantTransport()) as (server, _effects, serving):
            client = await _client(server)
            try:
                if cleanup_failure:
                    original_unlink = Path.unlink

                    def unlink(path: Path, *args: Any, **kwargs: Any) -> None:
                        if path == server.endpoint:
                            raise PermissionError("fixture cleanup refusal")
                        original_unlink(path, *args, **kwargs)

                    monkeypatch.setattr(Path, "unlink", unlink)
                pending = asyncio.create_task(
                    client.create_exact(
                        backend.ControlledCreateRequest.create(server.channel.profile)
                    )
                )
                await asyncio.wait_for(started.wait(), 1.0)
                serving.cancel()
                await asyncio.wait_for(cancelled.wait(), 1.0)
                assert server.endpoint.exists() is cleanup_failure
                assert server.cleanup_uncertain is cleanup_failure
                assert server._listener is None and server._connection is None
                assert not server.channel.usable
                assert not serving.done() and not settled.is_set()
                assert server._pidfd is not None
                verifier = server._containment_verifier
                assert verifier is not None and not verifier.closed
                serving.cancel()
                await asyncio.sleep(0)
                assert not serving.done()
                assert server._pidfd is not None
                assert server._containment_verifier is verifier and not verifier.closed
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(pending, 1.0)
                release.set()
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert settled.is_set()
                assert server._pidfd is None
                assert server._containment_verifier is None and verifier.closed
            finally:
                release.set()
                client.close()

    asyncio.run(run())


@linux
def test_supervisor_thread_close_stops_active_effect() -> None:
    async def run() -> None:
        effects = FakeTransport()
        effects.create_started, effects.create_gate = asyncio.Event(), asyncio.Event()
        async with _server(effects) as (server, _effects, serving):
            client = await _client(server)
            pending = asyncio.create_task(
                client.create_exact(backend.ControlledCreateRequest.create(server.channel.profile))
            )
            await asyncio.wait_for(effects.create_started.wait(), 1.0)
            await asyncio.to_thread(server.close)
            effects.create_gate.set()
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await asyncio.wait_for(pending, 1.0)
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await asyncio.wait_for(asyncio.shield(serving), 1.0)
            client.close()

    asyncio.run(run())


@linux
def test_deadline_abandons_blocked_effect_and_pending_call() -> None:
    async def run() -> None:
        effects = FakeTransport()
        effects.create_started, effects.create_gate = asyncio.Event(), asyncio.Event()
        async with _server(effects, lifetime_seconds=0.5) as (server, _effects, serving):
            client = await _client(server)
            try:
                pending = asyncio.create_task(
                    client.create_exact(
                        backend.ControlledCreateRequest.create(server.channel.profile)
                    )
                )
                await asyncio.wait_for(effects.create_started.wait(), 1.0)
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(pending, 1.0)
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert not client.channel.usable and not server.channel.usable
            finally:
                client.close()

    asyncio.run(run())


@linux
@pytest.mark.skipif(not hasattr(os, "pidfd_open"), reason="kernel process descriptors unavailable")
def test_owned_child_exit_stops_listener_even_before_connection() -> None:
    async def run() -> None:
        # Fixed inert child: no imports from the product, effects, or network.
        child = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"LANG": "C.UTF-8"},
            start_new_session=True,
        )
        try:
            async with _server(peer_pid=child.pid) as (server, effects, serving):
                await asyncio.sleep(0.05)
                assert server._pidfd is not None
                assert server.wait_until_custody_ready(0.1).worker_custody_identity[0] == child.pid
                child.kill()
                await asyncio.to_thread(child.wait, 1.0)
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    server.wait_until_custody_ready(0.1)
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert not server.endpoint.exists()
                assert not server.channel.usable
                assert effects.calls == []
                assert server._pidfd is None
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=1.0)

    asyncio.run(run())


@linux
def test_custody_readiness_refuses_after_server_close() -> None:
    async def run() -> None:
        async with _server() as (server, _effects, _serving):
            assert server.wait_until_custody_ready(0.1).server_identity_ref
            server.close()
            with pytest.raises(rpc.ControlledWorkerRPCError):
                server.wait_until_custody_ready(0.1)

    asyncio.run(run())


@linux
def test_concurrent_endpoint_cleanup_calls_helper_once() -> None:
    async def run() -> None:
        async with _server() as (server, _effects, _serving):
            calls = 0
            call_lock = threading.Lock()

            class CleanupOwner:
                schema_version = rpc.ENDPOINT_CLEANUP_OWNER_VERSION
                attempt_id = server.channel.binding.attempt_id
                claim_digest = server.channel.binding.claim_digest
                worker_containment_ref = _TestContainmentAuthority.containment_ref
                directory_identity = server.directory_identity
                endpoint_identity = server.endpoint_identity

                def cleanup(
                    self, *, launch_identity: tuple[int, int] | None
                ) -> rpc.WorkerEndpointCleanupReceiptV1:
                    nonlocal calls
                    with call_lock:
                        calls += 1
                    time.sleep(0.05)
                    for path in (server.endpoint, server._test_launch_path):
                        with suppress(FileNotFoundError):
                            path.unlink()
                    with suppress(FileNotFoundError):
                        server.private_directory.rmdir()
                    return rpc.WorkerEndpointCleanupReceiptV1(
                        schema_version=rpc.ENDPOINT_CLEANUP_RECEIPT_VERSION,
                        attempt_id=self.attempt_id,
                        claim_digest=self.claim_digest,
                        worker_containment_ref=self.worker_containment_ref,
                        directory_identity=self.directory_identity,
                        endpoint_identity=self.endpoint_identity,
                        launch_identity=launch_identity,
                        endpoint_absent=True,
                        launch_absent=True,
                        directory_absent=True,
                    )

            server._endpoint_cleanup_owner = CleanupOwner()
            server._endpoint_cleanup_pending = True
            workers = [threading.Thread(target=server._cleanup_endpoint_paths) for _ in range(8)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=2)
                assert not worker.is_alive()
            assert calls == 1
            assert server.endpoint_cleanup_receipt is not None
            assert not server._endpoint_cleanup_pending

    asyncio.run(run())


@linux
@pytest.mark.parametrize("concurrent_close", [False, True])
def test_distinct_uid_cleanup_owner_handles_pre_serve_close(concurrent_close: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="bf-rpc-") as directory:
        profile = _profile()
        invocation = _invocation(Path(directory), profile)
        binding = replace(_binding(profile), plan_digest=invocation.intent_digest)
        server = rpc.AttemptControllerServer(
            Path(directory), profile, binding, FakeTransport().bind(profile), _ModelLease()
        )
        server._test_invocation = invocation
        launch_path = launch.write_launch_material(server, _material(server))
        calls = 0
        call_lock = threading.Lock()

        class CleanupOwner:
            schema_version = rpc.ENDPOINT_CLEANUP_OWNER_VERSION
            attempt_id = binding.attempt_id
            claim_digest = binding.claim_digest
            worker_containment_ref = _TestContainmentAuthority.containment_ref
            directory_identity = server.directory_identity
            endpoint_identity = server.endpoint_identity

            def cleanup(
                self, *, launch_identity: tuple[int, int] | None
            ) -> rpc.WorkerEndpointCleanupReceiptV1:
                nonlocal calls
                with call_lock:
                    calls += 1
                time.sleep(0.05)
                assert launch_identity == server._launch_identity
                for path in (server.endpoint, launch_path):
                    with suppress(FileNotFoundError):
                        path.unlink()
                server.private_directory.rmdir()
                return rpc.WorkerEndpointCleanupReceiptV1(
                    schema_version=rpc.ENDPOINT_CLEANUP_RECEIPT_VERSION,
                    attempt_id=self.attempt_id,
                    claim_digest=self.claim_digest,
                    worker_containment_ref=self.worker_containment_ref,
                    directory_identity=self.directory_identity,
                    endpoint_identity=self.endpoint_identity,
                    launch_identity=launch_identity,
                    endpoint_absent=True,
                    launch_absent=True,
                    directory_absent=True,
                )

        owner = CleanupOwner()
        server.bind_endpoint_cleanup_owner(owner, worker_uid=os.geteuid() + 1)
        with pytest.raises(rpc.ControlledWorkerRPCError):
            server.bind_endpoint_cleanup_owner(owner, worker_uid=os.geteuid() + 1)
        workers = (
            [threading.Thread(target=server.close) for _ in range(8)] if concurrent_close else []
        )
        if workers:
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=2)
                assert not worker.is_alive()
        else:
            server.close()
        assert calls == 1
        assert server.endpoint_cleanup_receipt is not None
        assert server.endpoint_cleanup_receipt.launch_identity == server._launch_identity
        assert not server.cleanup_uncertain
        assert not launch_path.exists()
        assert not server.endpoint.exists()


@linux
def test_launch_publication_racing_close_leaves_no_unbound_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with tempfile.TemporaryDirectory(prefix="bf-rpc-") as directory:
        profile = _profile()
        invocation = _invocation(Path(directory), profile)
        binding = replace(_binding(profile), plan_digest=invocation.intent_digest)
        server = rpc.AttemptControllerServer(
            Path(directory), profile, binding, FakeTransport().bind(profile), _ModelLease()
        )
        server._test_invocation = invocation
        material = _material(server)
        entered = threading.Event()
        resume = threading.Event()
        original_fsync = os.fsync
        failures: list[BaseException] = []

        def paused_fsync(descriptor: int) -> None:
            entered.set()
            assert resume.wait(5)
            original_fsync(descriptor)

        monkeypatch.setattr(rpc.os, "fsync", paused_fsync)

        def publish() -> None:
            try:
                launch.write_launch_material(server, material)
            except BaseException as error:
                failures.append(error)

        writer = threading.Thread(target=publish)
        closer = threading.Thread(target=server.close)
        try:
            writer.start()
            assert entered.wait(5)
            closer.start()
            assert server._stopped.wait(5)
        finally:
            resume.set()
            writer.join(timeout=5)
            if closer.ident is not None:
                closer.join(timeout=5)
            server.close()
        assert not writer.is_alive() and not closer.is_alive()
        assert len(failures) == 1
        assert type(failures[0]) is rpc.ControlledWorkerRPCError
        assert server._launch_identity is None
        assert not (server.private_directory / "launch.json").exists()
        assert not server.endpoint.exists()
        assert not server.cleanup_uncertain


@linux
def test_cancellation_signal_closes_admission_before_next_request() -> None:
    async def run() -> None:
        cancellation = threading.Event()
        async with _server(cancellation=cancellation) as (server, effects, serving):
            connection = await _raw_client(server)
            try:
                await _ack(connection, server)
                worker = channel.WorkerChannel(server.channel.profile, server.channel.binding)
                frame = worker.request(
                    "create_exact",
                    backend.ControlledCreateRequest.create(server.channel.profile),
                    request_id="1" * 32,
                    now_ns=time.monotonic_ns(),
                )
                cancellation.set()
                with suppress(OSError):
                    await rpc.write_frame(connection, frame, server.deadline())
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert effects.calls == []
                assert not server.channel.usable
                assert not server.endpoint.exists()
                assert await asyncio.get_running_loop().sock_recv(connection, 1) == b""
            finally:
                connection.close()

    asyncio.run(run())


@linux
def test_worker_call_cancellation_closes_channel_and_settles_controller_handler() -> None:
    async def run() -> None:
        settled = asyncio.Event()

        class ObservedTransport(FakeTransport):
            async def create_exact(
                self, request: backend.ControlledCreateRequest
            ) -> backend.ControlledCreateReceipt:
                try:
                    return await super().create_exact(request)
                finally:
                    settled.set()

        effects = ObservedTransport()
        effects.create_started, effects.create_gate = asyncio.Event(), asyncio.Event()
        async with _server(effects) as (server, _effects, serving):
            client = await _client(server)
            try:
                request = backend.ControlledCreateRequest.create(server.channel.profile)
                pending = asyncio.create_task(client.create_exact(request))
                await asyncio.wait_for(effects.create_started.wait(), 1.0)
                pending.cancel()
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await pending
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert settled.is_set()
                assert not client.channel.usable and not server.channel.usable
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await client.create_exact(request)
                assert len(effects.calls) == 1
            finally:
                client.close()

    asyncio.run(run())


@linux
def test_worker_refuses_oversized_response_header_and_never_reuses_socket() -> None:
    async def run() -> None:
        profile = _profile()
        binding = replace(_binding(profile), deadline_ns=time.monotonic_ns() + 5_000_000_000)
        worker_socket, controller_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        packets.configure_socket(worker_socket)
        packets.configure_socket(controller_socket)
        client = rpc.SocketControlledControllerTransport(
            worker_socket,
            channel.WorkerChannel(profile, binding),
            controller_peer=packets.PeerIdentity(os.getpid(), os.geteuid(), os.getegid()),
        )
        try:
            request = backend.ControlledCreateRequest.create(profile)
            pending = asyncio.create_task(client.create_exact(request))
            frame = await rpc.read_frame(
                controller_socket,
                binding.deadline_ns,
                limit=channel.MAX_FRAME_BYTES,
                expected_peer=packets.PeerIdentity(os.getpid(), os.geteuid(), os.getegid()),
            )
            assert channel.decode_frame(frame)["method"] == "create_exact"
            controller_socket.send(_oversized_packet(channel.MAX_FRAME_BYTES))
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await asyncio.wait_for(pending, 1.0)
            assert not client.channel.usable
            assert await asyncio.get_running_loop().sock_recv(controller_socket, 1) == b""
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await client.create_exact(request)
        finally:
            client.close()
            controller_socket.close()

    asyncio.run(run())


@linux
def test_forked_child_cannot_continue_authenticated_worker_channel() -> None:
    async def run() -> None:
        async with _server() as (server, effects, serving):
            connection = await _raw_client(server)
            try:
                await _ack(connection, server)
                worker = channel.WorkerChannel(server.channel.profile, server.channel.binding)
                frame = worker.request(
                    "create_exact",
                    backend.ControlledCreateRequest.create(server.channel.profile),
                    request_id="1" * 32,
                    now_ns=time.monotonic_ns(),
                )
                wire_packets = packets._packets_for_frame(frame, frame_id=b"f" * 16)
                child = os.fork()
                if child == 0:
                    try:
                        connection.setblocking(True)
                        for packet in wire_packets:
                            if connection.send(packet) != len(packet):
                                os._exit(3)
                    except BaseException:
                        os._exit(2)
                    os._exit(0)
                status = await asyncio.to_thread(os.waitpid, child, 0)
                assert os.waitstatus_to_exitcode(status[1]) == 0
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert effects.calls == []
                assert not server.channel.usable
            finally:
                connection.close()

    asyncio.run(run())


@linux
def test_transferred_descriptor_cannot_delegate_authenticated_worker_channel() -> None:
    async def run() -> None:
        async with _server() as (server, effects, serving):
            connection = await _raw_client(server)
            sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                await _ack(connection, server)
                worker = channel.WorkerChannel(server.channel.profile, server.channel.binding)
                frame = worker.request(
                    "create_exact",
                    backend.ControlledCreateRequest.create(server.channel.profile),
                    request_id="2" * 32,
                    now_ns=time.monotonic_ns(),
                )
                wire_packet = packets._packets_for_frame(frame, frame_id=b"t" * 16)[0]
                child = os.fork()
                if child == 0:
                    try:
                        sender.close()
                        connection.close()
                        _body, ancillary, _flags, _address = receiver.recvmsg(
                            1, socket.CMSG_SPACE(array.array("i").itemsize)
                        )
                        descriptors = array.array("i")
                        for level, kind, data in ancillary:
                            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                descriptors.frombytes(data[: descriptors.itemsize])
                        if len(descriptors) != 1:
                            os._exit(4)
                        transferred = socket.socket(fileno=descriptors[0])
                        try:
                            if transferred.send(wire_packet) != len(wire_packet):
                                os._exit(3)
                        finally:
                            transferred.close()
                    except BaseException:
                        os._exit(2)
                    os._exit(0)
                receiver.close()
                rights = array.array("i", [connection.fileno()])
                sender.sendmsg(
                    [b"f"],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())],
                )
                status = await asyncio.to_thread(os.waitpid, child, 0)
                assert os.waitstatus_to_exitcode(status[1]) == 0
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert effects.calls == []
            finally:
                connection.close()
                sender.close()
                receiver.close()

    asyncio.run(run())


@linux
def test_every_chunk_requires_the_original_worker_credentials() -> None:
    async def run() -> None:
        async with _server() as (server, effects, serving):
            connection = await _raw_client(server)
            try:
                await _ack(connection, server)
                frame = channel.encode_frame({"payload": "x" * 200_000})
                wire_packets = packets._packets_for_frame(frame, frame_id=b"m" * 16)
                assert len(wire_packets) > 1
                assert connection.send(wire_packets[0]) == len(wire_packets[0])
                child = os.fork()
                if child == 0:
                    try:
                        for packet in wire_packets[1:]:
                            if connection.send(packet) != len(packet):
                                os._exit(3)
                    except BaseException:
                        os._exit(2)
                    os._exit(0)
                status = await asyncio.to_thread(os.waitpid, child, 0)
                assert os.waitstatus_to_exitcode(status[1]) == 0
                with pytest.raises(rpc.ControlledWorkerRPCError):
                    await asyncio.wait_for(asyncio.shield(serving), 1.0)
                assert effects.calls == []
            finally:
                connection.close()

    asyncio.run(run())


@linux
def test_packet_layer_reassembles_large_frame_with_credentials() -> None:
    async def run() -> None:
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        packets.configure_socket(sender)
        packets.configure_socket(receiver)
        try:
            frame = channel.encode_frame({"payload": "x" * 200_000})
            deadline = time.monotonic_ns() + 5_000_000_000
            reading = asyncio.create_task(
                rpc.read_frame(
                    receiver,
                    deadline,
                    limit=channel.MAX_FRAME_BYTES,
                    expected_peer=packets.PeerIdentity(os.getpid(), os.geteuid(), os.getegid()),
                )
            )
            await rpc.write_frame(sender, frame, deadline)
            assert await reading == frame
        finally:
            sender.close()
            receiver.close()

    asyncio.run(run())


@linux
def test_packet_layer_accepts_a_sender_thread_from_the_owned_tgid() -> None:
    async def run() -> None:
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        packets.configure_socket(sender)
        packets.configure_socket(receiver)
        observed_tid: list[int] = []
        frame = channel.encode_frame({"payload": "thread-owned"})

        def send() -> None:
            observed_tid.append(threading.get_native_id())
            sender.setblocking(True)
            for packet in packets._packets_for_frame(frame, frame_id=b"g" * 16):
                assert sender.send(packet) == len(packet)

        thread = threading.Thread(target=send)
        try:
            deadline = time.monotonic_ns() + 5_000_000_000
            reading = asyncio.create_task(
                rpc.read_frame(
                    receiver,
                    deadline,
                    limit=channel.MAX_FRAME_BYTES,
                    expected_peer=packets.PeerIdentity(os.getpid(), os.geteuid(), os.getegid()),
                )
            )
            thread.start()
            assert await reading == frame
            thread.join()
            assert observed_tid and observed_tid[0] != os.getpid()
        finally:
            thread.join()
            sender.close()
            receiver.close()

    asyncio.run(run())


@linux
def test_packet_layer_refuses_short_nonterminal_chunk_without_starving_loop() -> None:
    async def run() -> None:
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        packets.configure_socket(sender)
        packets.configure_socket(receiver)
        try:
            packet = packets._HEADER.pack(b"BFP1", b"s" * 16, 16, 0, 1, 0) + b"x"
            deadline = time.monotonic_ns() + 5_000_000_000
            reading = asyncio.create_task(
                rpc.read_frame(
                    receiver,
                    deadline,
                    limit=channel.MAX_FRAME_BYTES,
                    expected_peer=packets.PeerIdentity(os.getpid(), os.geteuid(), os.getegid()),
                )
            )
            assert sender.send(packet) == len(packet)
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await asyncio.wait_for(reading, 0.5)
        finally:
            sender.close()
            receiver.close()

    asyncio.run(run())


@linux
@pytest.mark.parametrize("fault", ["reordered", "repeated", "offset", "total", "terminal"])
def test_packet_layer_rejects_invalid_chunk_sequences(fault: str) -> None:
    async def run() -> None:
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        packets.configure_socket(sender)
        packets.configure_socket(receiver)
        try:
            frame = channel.encode_frame({"payload": "x" * 200_000})
            wire = list(packets._packets_for_frame(frame, frame_id=b"q" * 16))
            if fault == "reordered":
                wire[0], wire[1] = wire[1], wire[0]
            elif fault == "repeated":
                wire.insert(1, wire[0])
            else:
                magic, frame_id, total, offset, size, terminal = packets._HEADER.unpack(
                    wire[0][: packets._HEADER.size]
                )
                if fault == "offset":
                    offset = 1
                elif fault == "total":
                    total += 1
                else:
                    terminal = 1
                wire[0] = (
                    packets._HEADER.pack(magic, frame_id, total, offset, size, terminal)
                    + wire[0][packets._HEADER.size :]
                )
            deadline = time.monotonic_ns() + 5_000_000_000
            reading = asyncio.create_task(
                rpc.read_frame(
                    receiver,
                    deadline,
                    limit=channel.MAX_FRAME_BYTES,
                    expected_peer=packets.PeerIdentity(os.getpid(), os.geteuid(), os.getegid()),
                )
            )
            for packet in wire:
                with suppress(OSError):
                    sender.send(packet)
            with pytest.raises(rpc.ControlledWorkerRPCError):
                await reading
        finally:
            sender.close()
            receiver.close()

    asyncio.run(run())


@linux
def test_pidfd_identity_mismatch_is_refused() -> None:
    pidfd = os.pidfd_open(os.getpid(), 0)
    try:
        with pytest.raises(rpc.ControlledWorkerRPCError):
            rpc.OwnedWorkerProcess(os.getpid() + 1, os.geteuid(), os.getegid(), pidfd)
    finally:
        os.close(pidfd)


@linux
def test_pidfd_close_error_never_retries_a_reused_descriptor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = _profile()
    binding = _binding(profile)
    server = rpc.AttemptControllerServer(
        tmp_path, profile, binding, FakeTransport().bind(profile), _ModelLease()
    )
    descriptor = os.open(os.devnull, os.O_RDONLY)
    server._pidfd = descriptor
    real_close = os.close
    faulted = False

    def close_once(value: int) -> None:
        nonlocal faulted
        if value == descriptor and not faulted:
            faulted = True
            real_close(value)
            raise InterruptedError("synthetic post-close interruption")
        real_close(value)

    monkeypatch.setattr(rpc.os, "close", close_once)
    server.close()
    assert server._pidfd is None and server.cleanup_uncertain
    replacement = os.open(os.devnull, os.O_RDONLY)
    if replacement != descriptor:
        os.dup2(replacement, descriptor)
        real_close(replacement)
        replacement = descriptor
    try:
        server.close()
        os.fstat(replacement)
    finally:
        real_close(replacement)


@linux
def test_worker_custody_survives_caller_pidfd_close_and_descriptor_reuse() -> None:
    original = os.pidfd_open(os.getpid(), 0)
    worker = rpc.OwnedWorkerProcess(os.getpid(), os.geteuid(), os.getegid(), original)
    os.close(original)
    reused = os.open("/dev/null", os.O_RDONLY)
    if reused != original:
        os.dup2(reused, original)
        os.close(reused)
        reused = original
    try:
        assert reused == original
        owned = worker.take_pidfd()
        try:
            assert rpc._pidfd_matches(owned, os.getpid())
            assert not rpc._pidfd_exited(owned)
        finally:
            os.close(owned)
    finally:
        os.close(reused)
        worker.close()
