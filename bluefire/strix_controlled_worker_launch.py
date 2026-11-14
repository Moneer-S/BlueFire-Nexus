"""Protected one-use launch material for the installed controlled worker.

The daemon supplies exact identities after verifying installed artifacts. The
file is a local capability, never public evidence or a caller-authored plan.
It carries the one digest-bound fixed invocation, not an arbitrary command,
provider credential, package import, or effect selection.
"""

from __future__ import annotations

import asyncio
import os
import re
import socket
import stat
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping

from . import strix_controlled_backend as backend
from . import strix_controlled_bootstrap as bootstrap
from . import strix_controlled_worker_channel as channel
from . import strix_controlled_worker_invocation as invocation_module
from . import strix_controlled_worker_packets as packets
from . import strix_controlled_worker_rpc as rpc

LAUNCH_ENVIRONMENT_NAME = "BLUEFIRE_STRIX_WORKER_LAUNCH_FILE"
LAUNCH_VERSION = "bluefire.strix-controlled-installed-worker-launch.v3"
MAX_LAUNCH_BYTES = 32 * 1024
_TOKEN = re.compile(r"[0-9a-f]{64}\Z")
_ENVIRONMENT_NAMES = frozenset(
    {
        "STRIX_RUNTIME_BACKEND",
        "DOCKER_HOST",
        "STRIX_IMAGE",
        "BLUEFIRE_STRIX_ATTEMPT_ID",
        "BLUEFIRE_STRIX_SOURCE_REVISION",
        "BLUEFIRE_STRIX_SANDBOX_UID",
        "BLUEFIRE_STRIX_SANDBOX_GID",
    }
    | {
        "BLUEFIRE_STRIX_" + name + "_DIGEST"
        for name in (
            "BUILD",
            "PROFILE",
            "POLICY",
            "RELAY",
            "RELAY_UPSTREAM",
            "RELAY_CHANNEL",
            "RELAY_RETRY",
            "BOUNDARY",
            "ADMISSION",
            "IMAGE",
            "MANIFEST",
            "SDK",
            "BOOTSTRAP",
            "TMPFS",
        )
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class ControlledWorkerLaunchMaterial:
    profile: backend.ControlledRuntimeProfile
    binding: channel.ControlledWorkerBinding
    endpoint: str
    token: str = field(repr=False)
    controller_pid: int
    controller_uid: int
    controller_gid: int
    environment: tuple[tuple[str, str], ...]
    package_identities: tuple[bootstrap.ControlledInstalledPackageIdentity, ...]
    invocation: invocation_module.ControlledWorkerInvocation
    installed_input_mode: str = invocation_module.PROC_MEMFD_INPUT_MODE
    io_timeout_seconds: float = 300.0

    def __repr__(self) -> str:
        return "ControlledWorkerLaunchMaterial(<private>)"

    @property
    def installed_projection_ref(self) -> str:
        return invocation_module.installed_projection_ref(self.installed_input_mode)

    def __post_init__(self) -> None:
        channel.WorkerChannel(self.profile, self.binding)
        if (
            type(self.endpoint) is not str
            or not self.endpoint.startswith("/")
            or "\x00" in self.endpoint
            or len(os.fsencode(self.endpoint)) > 100
            or type(self.token) is not str
            or _TOKEN.fullmatch(self.token) is None
            or type(self.controller_pid) is not int
            or self.controller_pid <= 0
            or type(self.controller_uid) is not int
            or self.controller_uid < 0
            or type(self.controller_gid) is not int
            or self.controller_gid < 0
            or type(self.io_timeout_seconds) not in {int, float}
            or not 0.01 <= self.io_timeout_seconds <= 300
            or type(self.environment) is not tuple
            or any(
                type(pair) is not tuple or len(pair) != 2 or any(type(v) is not str for v in pair)
                for pair in self.environment
            )
            or tuple(sorted(dict(self.environment).items())) != self.environment
            or set(dict(self.environment)) != _ENVIRONMENT_NAMES
            or self.installed_input_mode
            not in {
                invocation_module.PROC_MEMFD_INPUT_MODE,
                invocation_module.DESCRIPTOR_BIND_INPUT_MODE,
            }
        ):
            raise rpc._refuse()
        config = bootstrap._validate_environment(dict(self.environment))
        if any(
            getattr(config, item.name) != getattr(self.profile, item.name)
            for item in fields(config)
            if item.name != "docker_host"
        ):
            raise rpc._refuse()
        if type(self.package_identities) is not tuple or any(
            type(item) is not bootstrap.ControlledInstalledPackageIdentity
            for item in self.package_identities
        ):
            raise rpc._refuse()
        names = tuple(item.package for item in self.package_identities)
        if names != ("strix-agent", "openai-agents"):
            raise rpc._refuse()
        identities = {item.package: item for item in self.package_identities}
        bootstrap._validate_package_identities(config, identities.__getitem__)
        if (
            type(self.invocation) is not invocation_module.ControlledWorkerInvocation
            or self.invocation.profile_attempt_id != self.binding.attempt_id
            or self.invocation.intent_digest != self.binding.plan_digest
            or dict(self.invocation.engine).get("package_sha256") != self.profile.build_digest
            or dict(self.invocation.engine).get("source_revision") != self.profile.source_revision
            or dict(self.invocation.engine).get("image_reference") != self.profile.image_reference
        ):
            raise rpc._refuse()

    def wire(self) -> dict[str, Any]:
        return {
            "schema_version": LAUNCH_VERSION,
            "profile": asdict(self.profile),
            "binding": self.binding.wire(),
            "endpoint": self.endpoint,
            "token": self.token,
            "controller_pid": self.controller_pid,
            "controller_uid": self.controller_uid,
            "controller_gid": self.controller_gid,
            "environment": dict(self.environment),
            "package_identities": [asdict(item) for item in self.package_identities],
            "invocation": self.invocation.wire(),
            "installed_input_mode": self.installed_input_mode,
            "installed_projection_ref": self.installed_projection_ref,
            "io_timeout_seconds": self.io_timeout_seconds,
        }


def write_launch_material(
    server: rpc.AttemptControllerServer, material: ControlledWorkerLaunchMaterial
) -> Path:
    """Create once in the listener's private directory; never replace a file."""
    rpc.require_linux()
    if (
        material.endpoint != str(server.endpoint)
        or material.token != server.token
        or material.binding != server.channel.binding
        or material.profile != server.channel.profile
    ):
        raise rpc._refuse()
    frame = channel.encode_frame(material.wire())
    if len(frame) > MAX_LAUNCH_BYTES:
        raise rpc._refuse()
    return server.publish_launch_material(
        frame,
        startup_overlay_ref=material.invocation.startup_overlay_ref,
        installed_projection_ref=material.installed_projection_ref,
    )


def read_launch_material(path: Path) -> ControlledWorkerLaunchMaterial:
    """Reject symlinks/loose permissions, consume before connecting, bound read."""
    rpc.require_linux()
    failed = False
    value: Any = None
    try:
        if not path.is_absolute() or path.name != "launch.json":
            raise rpc._refuse()
        parent = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.geteuid()
        ):
            raise rpc._refuse()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or not 4 < info.st_size <= MAX_LAUNCH_BYTES
            ):
                raise rpc._refuse()
            # Unlink while holding the verified inode; no reconnect may reuse it.
            path.unlink()
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                frame = source.read(MAX_LAUNCH_BYTES + 1)
            value = channel.decode_frame(frame)
        finally:
            os.close(descriptor)
        expected = {item.name for item in fields(ControlledWorkerLaunchMaterial)} | {
            "schema_version",
            "installed_projection_ref",
        }
        if (
            type(value) is not dict
            or set(value) != expected
            or value["schema_version"] != LAUNCH_VERSION
            or type(value["environment"]) is not dict
            or type(value["package_identities"]) is not list
        ):
            raise rpc._refuse()
        material = ControlledWorkerLaunchMaterial(
            profile=backend.ControlledRuntimeProfile(**value["profile"]),
            binding=channel.ControlledWorkerBinding(**value["binding"]),
            endpoint=value["endpoint"],
            token=value["token"],
            controller_pid=value["controller_pid"],
            controller_uid=value["controller_uid"],
            controller_gid=value["controller_gid"],
            environment=tuple(sorted(value["environment"].items())),
            package_identities=tuple(
                bootstrap.ControlledInstalledPackageIdentity(**item)
                for item in value["package_identities"]
            ),
            invocation=invocation_module.ControlledWorkerInvocation.from_wire(value["invocation"]),
            installed_input_mode=value["installed_input_mode"],
            io_timeout_seconds=value["io_timeout_seconds"],
        )
        if value["installed_projection_ref"] != material.installed_projection_ref:
            raise rpc._refuse()
        return material
    except Exception:
        failed = True
    if failed:
        raise rpc._refuse()
    raise rpc._refuse()


@dataclass(frozen=True, slots=True, repr=False)
class ConnectedWorker:
    transport: rpc.SocketControlledControllerTransport
    model_gateway_token: str = field(repr=False)

    def __repr__(self) -> str:
        return "ConnectedWorker(<private>)"


def connect_worker(
    material: ControlledWorkerLaunchMaterial,
) -> ConnectedWorker:
    """Authenticate the guest listener and controller's credentialed reply."""
    rpc.require_linux()
    connection: socket.socket | None = None
    failed = False
    try:
        endpoint = Path(material.endpoint)
        info = endpoint.lstat()
        parent = endpoint.parent.lstat()
        if (
            not stat.S_ISSOCK(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid()
            or not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.geteuid()
        ):
            raise rpc._refuse()
        deadline = min(
            material.binding.deadline_ns,
            time.monotonic_ns() + int(material.io_timeout_seconds * 1_000_000_000),
        )
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        packets.configure_socket(connection)
        connection.settimeout(rpc._remaining(deadline))
        connection.connect(material.endpoint)
        # The descriptor-bound guest creates its listener before transferring
        # that FD to the controller. The older proc-memfd mode uses a listener
        # created by the controller. SO_PEERCRED names that original creator;
        # the acknowledgement independently authenticates the sender on every
        # packet before the model relay bearer is accepted.
        expected_listener_peer = (
            (os.getpid(), os.geteuid(), os.getegid())
            if material.installed_input_mode == invocation_module.DESCRIPTOR_BIND_INPUT_MODE
            else (material.controller_pid, material.controller_uid, material.controller_gid)
        )
        if not rpc.peer_matches(connection, *expected_listener_peer):
            raise rpc._refuse()
        connection.setblocking(False)

        async def authenticate() -> bytes:
            await rpc.write_frame(connection, rpc.hello(material.binding, material.token), deadline)
            return await rpc.read_frame(
                connection,
                deadline,
                limit=rpc.HANDSHAKE_LIMIT,
                expected_peer=packets.PeerIdentity(
                    material.controller_pid, material.controller_uid, material.controller_gid
                ),
            )

        frame = asyncio.run(authenticate())
        ack = channel.decode_frame(bytes(frame))
        if (
            set(ack) != {"protocol_version", "binding", "model_gateway_token"}
            or ack["protocol_version"] != channel.PROTOCOL_VERSION
            or ack["binding"] != material.binding.wire()
            or type(ack["model_gateway_token"]) is not str
            or not 32 <= len(ack["model_gateway_token"]) <= 512
            or any(
                ord(character) < 33 or ord(character) == 127
                for character in ack["model_gateway_token"]
            )
        ):
            raise rpc._refuse()
        return ConnectedWorker(
            transport=rpc.SocketControlledControllerTransport(
                connection,
                channel.WorkerChannel(material.profile, material.binding),
                controller_peer=packets.PeerIdentity(
                    material.controller_pid, material.controller_uid, material.controller_gid
                ),
                io_timeout_seconds=material.io_timeout_seconds,
            ),
            model_gateway_token=ack["model_gateway_token"],
        )
    except Exception:
        failed = True
    if failed and connection is not None:
        connection.close()
    raise rpc._refuse()


def validate_process_environment(environment: Mapping[str, str]) -> Path:
    if set(environment) != {LAUNCH_ENVIRONMENT_NAME, "LANG", "LC_ALL", "PATH"}:
        raise rpc._refuse()
    if (
        environment["LANG"] != "C"
        or environment["LC_ALL"] != "C"
        or environment["PATH"] != "/runtime/bin"
    ):
        raise rpc._refuse()
    value = environment.get(LAUNCH_ENVIRONMENT_NAME)
    if type(value) is not str or not value or "\x00" in value:
        raise rpc._refuse()
    return Path(value)
