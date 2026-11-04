from __future__ import annotations

import base64
import hashlib
import json
import struct
import threading
from typing import Callable
from urllib.parse import quote, urlencode

import pytest

from bluefire.engine_container_custody import ContainerCustodyPlan
from bluefire.engine_docker_control import DockerApiPolicy, DockerOwnership
from bluefire.engine_docker_proxy import (
    DockerDaemonExchange,
    DockerPolicyProxy,
    DockerProxyAuditRecord,
    DockerProxyReply,
    EngineDockerProxyError,
    parse_docker_http_request,
)
from bluefire.engine_network_policy import EngineNetworkPlan
from bluefire.strix_adapter import StrixBuildIdentity
from bluefire.strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
    REVIEWED_SOURCE_REVISION,
)
from bluefire.util import content_hash

ATTEMPT_ID = "engine-attempt-0123456789abcdef0123456789abcdef"
CONTAINER_ID = "1" * 64
OTHER_CONTAINER_ID = "2" * 64
EXEC_ID = "3" * 64
NETWORK_ID = "4" * 64
IMAGE_DIGEST = "sha256:" + "c" * 64
IMAGE_REFERENCE = "ghcr.io/usestrix/sandbox@" + IMAGE_DIGEST
TMPFS_OPTIONS = "nodev,nosuid,rw,size=512m"
DAEMON_DIGEST = "sha256:" + "1" * 64
NOW = "2026-11-04T12:00:00Z"


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build() -> StrixBuildIdentity:
    return StrixBuildIdentity(
        source_revision=REVIEWED_SOURCE_REVISION,
        source_tree_sha256="sha256:" + "a" * 64,
        package_sha256="sha256:" + "b" * 64,
        executable_sha256="sha256:" + "d" * 64,
        image_reference=IMAGE_REFERENCE,
        image_inventory_sha256="sha256:" + "e" * 64,
        prompt_upstream_sha256="sha256:" + REVIEWED_PROMPT_SHA256,
        prompt_overlay_sha256="sha256:" + OVERLAY_SHA256,
        prompt_patched_sha256="sha256:" + PATCHED_PROMPT_SHA256,
    )


def network() -> EngineNetworkPlan:
    return EngineNetworkPlan.create(
        attempt_id=ATTEMPT_ID,
        network_identity_ref="sha256:" + "f" * 64,
        subnet="172.28.40.0/24",
        target_address="172.28.40.2",
        model_gateway_address="172.28.40.3",
        host_gateway_address="172.28.40.1",
        created_at=NOW,
    )


def custody() -> ContainerCustodyPlan:
    plan = network()
    return ContainerCustodyPlan.from_mapping(
        {
            "schema_version": "bluefire.engine-container-custody.v1",
            "attempt_id": ATTEMPT_ID,
            "daemon_instance_digest": DAEMON_DIGEST,
            "disposable_boundary_ref": "sha256:" + "2" * 64,
            "baseline_inventory_digest": "sha256:" + "3" * 64,
            "required_labels": {
                "bluefire.engine.attempt": ATTEMPT_ID,
                "strix-run-id": ATTEMPT_ID,
                "strix-run-type": "bluefire",
            },
            "sandbox_image_digest": IMAGE_DIGEST,
            "network_id": NETWORK_ID,
            "network_policy_digest": plan.policy_digest,
            "expected_mounts": [
                {
                    "mount_type": "tmpfs",
                    "source": "",
                    "destination": "/workspace",
                    "read_only": False,
                    "options_digest": content_hash({"options": TMPFS_OPTIONS}),
                }
            ],
            "expected_capabilities": [],
            "expected_user": "1000:1000",
            "memory_bytes": 2 * 1024**3,
            "nano_cpus": 2_000_000_000,
            "pids_limit": 512,
            "expected_container_count": 1,
        }
    )


def policy() -> DockerApiPolicy:
    return DockerApiPolicy.create(
        build=build(),
        network=network(),
        custody=custody(),
        api_version="v1.47",
        tmpfs_options={"/workspace": TMPFS_OPTIONS},
    )


def ownership(
    *, container: bool = False, pending: bool = False, exec_id: bool = False
) -> DockerOwnership:
    return DockerOwnership.create(
        daemon_instance_digest=DAEMON_DIGEST,
        pending_container_ids=(CONTAINER_ID,) if pending else (),
        container_ids=(CONTAINER_ID,) if container else (),
        exec_bindings=((EXEC_ID, CONTAINER_ID),) if container and exec_id else (),
    )


def create_body() -> dict[str, object]:
    item = policy()
    return {
        "AttachStderr": False,
        "AttachStdin": False,
        "AttachStdout": False,
        "Cmd": ["tail", "-f", "/dev/null"],
        "Env": [],
        "HostConfig": {
            "AutoRemove": False,
            "Binds": [],
            "CapAdd": [],
            "CapDrop": ["ALL"],
            "CgroupParent": item.cgroup_parent,
            "DeviceRequests": [],
            "Devices": [],
            "Dns": [],
            "DnsOptions": [],
            "DnsSearch": [],
            "ExtraHosts": [],
            "IpcMode": item.expected_ipc_mode,
            "LogConfig": {"Config": {"max-file": "1", "max-size": "10m"}, "Type": "json-file"},
            "Memory": item.memory_bytes,
            "Mounts": [],
            "NanoCpus": item.nano_cpus,
            "NetworkMode": item.network_name,
            "OomKillDisable": False,
            "PidMode": item.expected_pid_mode,
            "PidsLimit": item.pids_limit,
            "PortBindings": {},
            "Privileged": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": True,
            "RestartPolicy": {"MaximumRetryCount": 0, "Name": "no"},
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/workspace": TMPFS_OPTIONS},
            "UTSMode": item.expected_uts_mode,
        },
        "Image": item.image_reference,
        "Labels": dict(item.required_labels),
        "NetworkDisabled": False,
        "NetworkingConfig": {
            "EndpointsConfig": {item.network_name: {"Aliases": [], "NetworkID": item.network_id}}
        },
        "OpenStdin": False,
        "StdinOnce": False,
        "Tty": False,
        "User": item.expected_user,
    }


def exec_body() -> dict[str, object]:
    return {
        "AttachStderr": True,
        "AttachStdin": False,
        "AttachStdout": True,
        "Cmd": ["sh", "-lc", "id"],
        "DetachKeys": "",
        "Env": [],
        "Privileged": False,
        "Tty": False,
        "User": policy().expected_user,
        "WorkingDir": "/workspace",
    }


def inspect_body(*, container_id: str = CONTAINER_ID) -> dict[str, object]:
    item = policy()
    return {
        "Id": container_id,
        "Image": item.image_digest,
        "Name": "/" + item.container_name,
        "Config": {
            "AttachStderr": False,
            "AttachStdin": False,
            "AttachStdout": False,
            "Cmd": ["tail", "-f", "/dev/null"],
            "Env": [],
            "Image": item.image_reference,
            "Labels": dict(item.required_labels),
            "NetworkDisabled": False,
            "OpenStdin": False,
            "StdinOnce": False,
            "Tty": False,
            "User": item.expected_user,
        },
        "HostConfig": {
            "AutoRemove": False,
            "Binds": [],
            "CapAdd": [],
            "CapDrop": ["ALL"],
            "CgroupParent": item.cgroup_parent,
            "DeviceRequests": [],
            "Devices": [],
            "Dns": [],
            "DnsOptions": [],
            "DnsSearch": [],
            "ExtraHosts": [],
            "GroupAdd": [],
            "IpcMode": item.expected_ipc_mode,
            "Links": [],
            "LogConfig": {
                "Config": {"max-file": "1", "max-size": "10m"},
                "Type": "json-file",
            },
            "Memory": item.memory_bytes,
            "Mounts": [],
            "NanoCpus": item.nano_cpus,
            "NetworkMode": item.network_name,
            "OomKillDisable": False,
            "PidMode": item.expected_pid_mode,
            "PidsLimit": item.pids_limit,
            "PortBindings": {},
            "Privileged": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": True,
            "RestartPolicy": {"MaximumRetryCount": 0, "Name": "no"},
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/workspace": TMPFS_OPTIONS},
            "UTSMode": item.expected_uts_mode,
            "UsernsMode": "",
            "VolumesFrom": [],
        },
        "Mounts": [],
        "NetworkSettings": {
            "Networks": {item.network_name: {"NetworkID": item.network_id}},
            "Ports": {},
        },
        "State": {
            "Dead": False,
            "Error": "",
            "ExitCode": 0,
            "OOMKilled": False,
            "Paused": False,
            "Pid": 0,
            "Restarting": False,
            "Running": False,
            "Status": "created",
        },
    }


def raw_request(
    method: str,
    target: str,
    body: dict[str, object] | bytes | None = None,
    *,
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> bytes:
    if isinstance(body, dict):
        payload = json.dumps(body, separators=(",", ":")).encode()
    else:
        payload = body or b""
    headers = [("Host", "docker")]
    if payload:
        headers.extend(
            [("Content-Type", "application/json"), ("Content-Length", str(len(payload)))]
        )
    headers.extend(extra_headers)
    rendered = b"".join(f"{key}: {value}\r\n".encode() for key, value in headers)
    return f"{method} {target} HTTP/1.1\r\n".encode() + rendered + b"\r\n" + payload


def raw_response(
    status: int,
    body: dict[str, object] | bytes | None = None,
    *,
    content_type: str | None = "application/json",
    include_length: bool = True,
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> bytes:
    if isinstance(body, dict):
        payload = json.dumps(body, separators=(",", ":")).encode()
    else:
        payload = body or b""
    reason = {200: "OK", 201: "Created", 204: "No Content", 302: "Found"}[status]
    headers: list[tuple[str, str]] = [
        ("Api-Version", "1.47"),
        ("Docker-Experimental", "false"),
        ("OSType", "linux"),
    ]
    if content_type is not None:
        headers.append(("Content-Type", content_type))
    if include_length:
        headers.append(("Content-Length", str(len(payload))))
    headers.extend(extra_headers)
    rendered = b"".join(f"{key}: {value}\r\n".encode() for key, value in headers)
    return f"HTTP/1.1 {status} {reason}\r\n".encode() + rendered + b"\r\n" + payload


def archive_stat(
    path: str,
    *,
    size: int,
    link_target: str = "",
    mode: int = 0x800001ED,
) -> str:
    payload = json.dumps(
        {
            "linkTarget": link_target,
            "mode": mode,
            "mtime": "2026-11-04T12:00:00Z",
            "name": path.rsplit("/", 1)[-1],
            "size": size,
        },
        separators=(",", ":"),
    ).encode()
    return base64.b64encode(payload).decode()


class Cancel:
    def __init__(self) -> None:
        self.value = False

    def is_cancelled(self) -> bool:
        return self.value


class Clock:
    def __init__(self) -> None:
        self.value = 1_000_000_000

    def __call__(self) -> int:
        return self.value


class Audit:
    def __init__(self, *, fail_phase: str | None = None, substitute_receipt: bool = False) -> None:
        self.records: list[DockerProxyAuditRecord] = []
        self.fail_phase = fail_phase
        self.substitute_receipt = substitute_receipt
        self.reentrant: Callable[[], None] | None = None

    def append(self, record: DockerProxyAuditRecord) -> str:
        if self.reentrant is not None:
            self.reentrant()
        if record.phase == self.fail_phase:
            raise RuntimeError("audit unavailable")
        self.records.append(record)
        if self.substitute_receipt:
            return "sha256:" + "0" * 64
        return content_hash(record.to_dict())


class Transport:
    def __init__(
        self,
        response: bytes,
        *,
        clock: Clock | None = None,
        advance_ns: int = 0,
        override_request_digest: str | None = None,
        override_daemon: str | None = None,
    ) -> None:
        self.response = response
        self.clock = clock
        self.advance_ns = advance_ns
        self.override_request_digest = override_request_digest
        self.override_daemon = override_daemon
        self.seen: list[bytes] = []

    def exchange(
        self,
        raw_request_value: bytes,
        *,
        deadline_monotonic_ns: int,
        cancellation: Cancel,
    ) -> DockerDaemonExchange:
        del deadline_monotonic_ns, cancellation
        self.seen.append(raw_request_value)
        if self.clock is not None:
            self.clock.value += self.advance_ns
        return DockerDaemonExchange(
            request_digest=self.override_request_digest or _sha(raw_request_value),
            daemon_instance_digest=self.override_daemon or DAEMON_DIGEST,
            raw_response=self.response,
        )


def proxy(
    transport: Transport,
    *,
    owned: DockerOwnership | None = None,
    audit: Audit | None = None,
    clock: Clock | None = None,
) -> tuple[DockerPolicyProxy, Audit, Clock]:
    actual_audit = audit or Audit()
    actual_clock = clock or Clock()
    return (
        DockerPolicyProxy(
            policy=policy(),
            ownership=owned or ownership(),
            transport=transport,
            audit=actual_audit,
            monotonic_ns=actual_clock,
        ),
        actual_audit,
        actual_clock,
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"GET http://docker/version HTTP/1.1\r\nHost: docker\r\n\r\n",
        b"GET /version HTTP/1.1\nHost: docker\n\n",
        b"GET /version HTTP/1.1\r\nHost: docker\r\nHost: docker\r\n\r\n",
        b"GET /version HTTP/1.1\r\nHost: docker\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"GET /version HTTP/1.1\r\nHost: docker\r\n Connection: close\r\n\r\n",
        b"GET /version HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
        b"GET /version HTTP/1.1\r\nHost: docker\r\nContent-Length: 1\r\n\r\n",
        b"GET /version HTTP/1.1\r\nHost: docker\r\nContent-Length: " + b"9" * 100 + b"\r\n\r\n",
        b"GET /version HTTP/1.1\r\nHost: docker\r\n\r\nGET /_ping HTTP/1.1\r\nHost: docker\r\n\r\n",
    ],
)
def test_request_parser_refuses_smuggling_ambiguity_and_upgrades(raw: bytes) -> None:
    with pytest.raises(EngineDockerProxyError):
        parse_docker_http_request(raw)


def test_request_parser_preserves_an_exact_bounded_request() -> None:
    raw = raw_request("GET", "/version")
    parsed = parse_docker_http_request(raw)
    assert parsed.method == "GET"
    assert parsed.target == "/version"
    assert dict(parsed.headers) == {"host": "docker"}
    assert parsed.body == b""


def test_request_parser_checks_header_lines_without_rejecting_json_whitespace() -> None:
    payload = json.dumps(create_body(), indent=2).encode()
    raw = (
        f"POST /v1.47/containers/create?name={policy().container_name} HTTP/1.1\r\n"
        "Host: docker\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n\r\n"
    ).encode() + payload
    assert parse_docker_http_request(raw).body == payload


def test_version_is_forwarded_byte_exact_and_redacted() -> None:
    raw = raw_request("GET", "/version")
    transport = Transport(
        raw_response(
            200,
            {
                "ApiVersion": "1.47",
                "Os": "linux",
                "DockerRootDir": "/private/daemon/path",
            },
        )
    )
    item, audit, _clock = proxy(transport)
    result = item.handle(raw, Cancel())
    assert result.status_code == 200
    assert json.loads(result.body) == {"ApiVersion": "1.47", "Os": "linux"}
    assert b"private" not in result.body
    assert transport.seen == [raw]
    assert [record.phase for record in audit.records] == ["validated", "published"]


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_realistic_ping_headers_and_head_representation_length(method: str) -> None:
    body = b"OK" if method == "GET" else b""
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Api-Version: 1.47\r\n"
        b"Builder-Version: 2\r\n"
        b"Cache-Control: no-cache, no-store, must-revalidate\r\n"
        b"Content-Length: 2\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Docker-Experimental: false\r\n"
        b"OSType: linux\r\n"
        b"Pragma: no-cache\r\n"
        b"Swarm: inactive\r\n\r\n" + body
    )
    item, _audit, _clock = proxy(Transport(response))
    result = item.handle(raw_request(method, "/_ping"), Cancel())
    assert result.status_code == 200
    assert result.body == body
    assert dict(result.headers)["content-length"] == "2"
    rendered = result.to_http_bytes()
    assert rendered.endswith(b"\r\n\r\n" if method == "HEAD" else b"\r\n\r\nOK")


def test_ping_only_headers_are_refused_on_other_operations() -> None:
    item, _audit, _clock = proxy(
        Transport(
            raw_response(
                200,
                {"ApiVersion": "1.47", "Os": "linux"},
                extra_headers=(("Builder-Version", "2"),),
            )
        )
    )
    assert item.handle(raw_request("GET", "/version"), Cancel()).status_code == 503


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (b"Api-Version: 1.47", b"Api-Version: 1.46"),
        (b"Docker-Experimental: false", b"Docker-Experimental: maybe"),
        (b"OSType: linux", b"OSType: windows"),
    ],
)
def test_common_daemon_header_substitution_is_refused(original: bytes, replacement: bytes) -> None:
    response = raw_response(200, {"ApiVersion": "1.47", "Os": "linux"})
    item, _audit, _clock = proxy(Transport(response.replace(original, replacement)))
    assert item.handle(raw_request("GET", "/version"), Cancel()).status_code == 503


def test_create_is_pending_then_exact_inspect_promotes_it() -> None:
    plan = policy()
    create = raw_request(
        "POST",
        f"/v1.47/containers/create?name={plan.container_name}",
        create_body(),
    )
    transport = Transport(raw_response(201, {"Id": CONTAINER_ID, "Warnings": None}))
    item, _audit, _clock = proxy(transport)
    result = item.handle(create, Cancel())
    assert result.status_code == 201
    assert item.snapshot().ownership.pending_container_ids == (CONTAINER_ID,)
    assert item.snapshot().ownership.container_ids == ()

    inspect = raw_request("GET", f"/v1.47/containers/{CONTAINER_ID}/json")
    transport.response = raw_response(200, inspect_body())
    result = item.handle(inspect, Cancel())
    assert result.status_code == 200
    assert item.snapshot().ownership.pending_container_ids == ()
    assert item.snapshot().ownership.container_ids == (CONTAINER_ID,)
    assert json.loads(result.body)["Id"] == CONTAINER_ID


def test_inspect_allows_omitted_empty_hostconfig_mounts_from_moby() -> None:
    row = inspect_body()
    row["HostConfig"].pop("Mounts")
    item, _audit, _clock = proxy(Transport(raw_response(200, row)), owned=ownership(pending=True))
    result = item.handle(raw_request("GET", f"/v1.47/containers/{CONTAINER_ID}/json"), Cancel())
    assert result.status_code == 200
    assert item.snapshot().ownership.container_ids == (CONTAINER_ID,)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda row: row.__setitem__("Id", CONTAINER_ID[:12]),
        lambda row: row.__setitem__("Image", "sha256:" + "f" * 64),
        lambda row: row["Config"].__setitem__("User", "root"),
        lambda row: row["Config"]["Labels"].pop("bluefire.engine.attempt"),
        lambda row: row["HostConfig"].__setitem__("Privileged", True),
        lambda row: row["HostConfig"].__setitem__("VolumesFrom", ["victim:rw"]),
        lambda row: row["HostConfig"].__setitem__("GroupAdd", ["0"]),
        lambda row: row["HostConfig"].__setitem__("UsernsMode", "host"),
        lambda row: row["HostConfig"].__setitem__("Dns", ["8.8.8.8"]),
        lambda row: row["HostConfig"].pop("VolumesFrom"),
        lambda row: row["HostConfig"].pop("GroupAdd"),
        lambda row: row["HostConfig"].pop("Dns"),
        lambda row: row["HostConfig"].__setitem__("Mounts", [{"Type": "bind"}]),
        lambda row: row["Config"].pop("Env"),
        lambda row: row["NetworkSettings"].pop("Ports"),
        lambda row: row["HostConfig"].__setitem__(
            "ExtraHosts", ["host.docker.internal:host-gateway"]
        ),
        lambda row: row["HostConfig"].__setitem__("NetworkMode", "host"),
        lambda row: row["HostConfig"].__setitem__("PidMode", "private"),
        lambda row: row["HostConfig"].__setitem__("UTSMode", "private"),
        lambda row: row["HostConfig"].__setitem__("IpcMode", "host"),
        lambda row: row["HostConfig"].pop("PidMode"),
        lambda row: row["HostConfig"].pop("IpcMode"),
        lambda row: row["HostConfig"].pop("UTSMode"),
        lambda row: row.pop("Mounts"),
        lambda row: row.__setitem__(
            "Mounts",
            [{"Destination": "/host", "Source": "/", "Type": "bind"}],
        ),
        lambda row: row["State"].update({"Pid": 7, "Running": True, "Status": "running"}),
        lambda row: row["NetworkSettings"]["Networks"][policy().network_name].__setitem__(
            "NetworkID", "f" * 64
        ),
    ],
)
def test_inspect_substitution_never_promotes_pending_container(mutator: object) -> None:
    row = inspect_body()
    mutator(row)  # type: ignore[operator]
    item, _audit, _clock = proxy(Transport(raw_response(200, row)), owned=ownership(pending=True))
    result = item.handle(raw_request("GET", f"/v1.47/containers/{CONTAINER_ID}/json"), Cancel())
    assert result.status_code == 503
    assert item.snapshot().ownership.container_ids == ()
    assert item.snapshot().reconciliation_required is True


def test_create_requires_a_full_id_and_quarantines_uncertain_effect() -> None:
    plan = policy()
    item, _audit, _clock = proxy(
        Transport(raw_response(201, {"Id": CONTAINER_ID[:12], "Warnings": []}))
    )
    result = item.handle(
        raw_request(
            "POST",
            f"/v1.47/containers/create?name={plan.container_name}",
            create_body(),
        ),
        Cancel(),
    )
    assert result.status_code == 503
    assert item.snapshot().reconciliation_required is True


def test_malformed_create_with_known_full_id_retains_quarantine_candidate() -> None:
    plan = policy()
    item, _audit, _clock = proxy(
        Transport(raw_response(201, {"Id": CONTAINER_ID, "Warnings": ["unexpected"]}))
    )
    result = item.handle(
        raw_request(
            "POST",
            f"/v1.47/containers/create?name={plan.container_name}",
            create_body(),
        ),
        Cancel(),
    )
    state = item.snapshot()
    assert result.status_code == 503
    assert state.ownership.pending_container_ids == (CONTAINER_ID,)
    assert state.quarantined_container_ids == (CONTAINER_ID,)


def test_malformed_exec_with_known_full_id_retains_quarantine_binding() -> None:
    item, _audit, _clock = proxy(
        Transport(raw_response(201, {"Id": EXEC_ID, "unexpected": True})),
        owned=ownership(container=True),
    )
    result = item.handle(
        raw_request("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", exec_body()),
        Cancel(),
    )
    state = item.snapshot()
    assert result.status_code == 503
    assert state.ownership.exec_bindings == ()
    assert state.quarantined_exec_bindings == ((EXEC_ID, CONTAINER_ID),)


def test_exec_registration_and_delete_update_exact_ownership() -> None:
    exec_request = raw_request("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", exec_body())
    transport = Transport(raw_response(201, {"Id": EXEC_ID}))
    item, _audit, _clock = proxy(transport, owned=ownership(container=True))
    result = item.handle(exec_request, Cancel())
    assert result.status_code == 201
    assert item.snapshot().ownership.exec_bindings == ((EXEC_ID, CONTAINER_ID),)

    transport.response = raw_response(204, b"", content_type=None, include_length=False)
    result = item.handle(
        raw_request("DELETE", f"/v1.47/containers/{CONTAINER_ID}?force=1&v=1"),
        Cancel(),
    )
    assert result.status_code == 204
    assert result.headers == ()
    assert b"content-length" not in result.to_http_bytes()
    assert item.snapshot().ownership.container_ids == ()
    assert item.snapshot().ownership.exec_bindings == ()


def test_multiplex_stream_is_bounded_and_frame_complete() -> None:
    payload = b"hello\nworld\r"
    frame = bytes([1, 0, 0, 0]) + struct.pack(">I", len(payload)) + payload
    target = f"/v1.47/containers/{CONTAINER_ID}/logs?" + urlencode(
        {"follow": "0", "stderr": "1", "stdout": "1", "tail": "100", "timestamps": "1"}
    )
    item, _audit, _clock = proxy(
        Transport(raw_response(200, frame, content_type="application/vnd.docker.raw-stream")),
        owned=ownership(container=True),
    )
    assert item.handle(raw_request("GET", target), Cancel()).body == frame

    malformed, _audit, _clock = proxy(
        Transport(raw_response(200, frame[:-1], content_type="application/vnd.docker.raw-stream")),
        owned=ownership(container=True),
    )
    assert malformed.handle(raw_request("GET", target), Cancel()).status_code == 503
    assert malformed.snapshot().reconciliation_required is True

    stdin_frame = bytes([0, 0, 0, 0]) + struct.pack(">I", 1) + b"x"
    wrong_direction, _audit, _clock = proxy(
        Transport(raw_response(200, stdin_frame, content_type="application/vnd.docker.raw-stream")),
        owned=ownership(container=True),
    )
    assert wrong_direction.handle(raw_request("GET", target), Cancel()).status_code == 503


def test_archive_body_may_contain_http_delimiter_without_response_smuggling() -> None:
    body = b"tar-prefix\nbinary\rtar\r\n\r\nsuffix"
    target = f"/v1.47/containers/{CONTAINER_ID}/archive?" + urlencode({"path": "/workspace"})
    item, _audit, _clock = proxy(
        Transport(
            raw_response(
                200,
                body,
                content_type="application/x-tar",
                extra_headers=(
                    (
                        "X-Docker-Container-Path-Stat",
                        archive_stat("/workspace", size=len(body)),
                    ),
                ),
            )
        ),
        owned=ownership(container=True),
    )
    assert item.handle(raw_request("GET", target), Cancel()).body == body


@pytest.mark.parametrize(
    "stat_header",
    [
        None,
        "not-base64",
        archive_stat("/workspace/other", size=1),
        archive_stat("/workspace", size=1, link_target="/etc"),
        archive_stat("/workspace", size=1, mode=0o100644),
        archive_stat("/workspace", size=1, mode=0x080001FF),
    ],
)
def test_archive_requires_exact_contract_scoped_path_stat(stat_header: str | None) -> None:
    target = f"/v1.47/containers/{CONTAINER_ID}/archive?" + urlencode({"path": "/workspace"})
    extra = () if stat_header is None else (("X-Docker-Container-Path-Stat", stat_header),)
    item, _audit, _clock = proxy(
        Transport(raw_response(200, b"x", content_type="application/x-tar", extra_headers=extra)),
        owned=ownership(container=True),
    )
    assert item.handle(raw_request("GET", target), Cancel()).status_code == 503


def test_archive_refuses_symlinkable_descendant_even_with_matching_stat() -> None:
    path = "/workspace/results.tar"
    target = f"/v1.47/containers/{CONTAINER_ID}/archive?" + urlencode({"path": path})
    item, _audit, _clock = proxy(
        Transport(
            raw_response(
                200,
                b"x",
                content_type="application/x-tar",
                extra_headers=(("X-Docker-Container-Path-Stat", archive_stat(path, size=1)),),
            )
        ),
        owned=ownership(container=True),
    )
    assert item.handle(raw_request("GET", target), Cancel()).status_code == 503


@pytest.mark.parametrize(
    "response",
    [
        raw_response(302, b"", content_type=None, extra_headers=(("Location", "http://host/"),)),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: " + b"9" * 100 + b"\r\n\r\n",
        raw_response(200, {"ApiVersion": "1.47", "Os": "linux"}) + b"trailing",
    ],
)
def test_daemon_response_ambiguity_redirects_and_upgrades_are_refused(response: bytes) -> None:
    item, _audit, _clock = proxy(Transport(response))
    result = item.handle(raw_request("GET", "/version"), Cancel())
    assert result.status_code == 503
    assert b"host" not in result.body
    assert item.snapshot().reconciliation_required is True


@pytest.mark.parametrize(
    ("target", "body"),
    [
        ("/version", b'{"ApiVersion":"1.47","ApiVersion":"1.99","Os":"linux"}'),
        ("/v1.47/info", b'{"ID":"daemon","OSType":"linux","load":NaN}'),
        ("/v1.47/info", b'{"ID":"daemon","OSType":"windows"}'),
    ],
)
def test_daemon_json_duplicate_nonfinite_and_wrong_os_are_refused(target: str, body: bytes) -> None:
    item, _audit, _clock = proxy(Transport(raw_response(200, body)))
    assert item.handle(raw_request("GET", target), Cancel()).status_code == 503
    assert item.snapshot().reconciliation_required is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"override_request_digest": "sha256:" + "9" * 64},
        {"override_daemon": "sha256:" + "8" * 64},
    ],
)
def test_transport_binding_substitution_is_refused_without_leaking_details(
    overrides: dict[str, str],
) -> None:
    item, _audit, _clock = proxy(
        Transport(
            raw_response(200, {"ApiVersion": "1.47", "Os": "linux"}),
            **overrides,
        )
    )
    result = item.handle(raw_request("GET", "/version"), Cancel())
    assert result.status_code == 503
    assert result.body == b'{"error":"docker_proxy_refused"}'


def test_audit_failure_after_create_preserves_quarantined_custody() -> None:
    plan = policy()
    audit = Audit(fail_phase="validated")
    item, _audit, _clock = proxy(
        Transport(raw_response(201, {"Id": CONTAINER_ID, "Warnings": []})), audit=audit
    )
    result = item.handle(
        raw_request(
            "POST",
            f"/v1.47/containers/create?name={plan.container_name}",
            create_body(),
        ),
        Cancel(),
    )
    state = item.snapshot()
    assert result.status_code == 503
    assert state.reconciliation_required is True
    assert state.ownership.pending_container_ids == (CONTAINER_ID,)
    assert state.quarantined_container_ids == (CONTAINER_ID,)
    assert audit.records[-1].outcome == "audit_failed"


def test_published_audit_failure_suppresses_response_and_blocks_future_work() -> None:
    audit = Audit(fail_phase="published")
    item, _audit, _clock = proxy(
        Transport(raw_response(200, {"ApiVersion": "1.47", "Os": "linux"})), audit=audit
    )
    result = item.handle(raw_request("GET", "/version"), Cancel())
    assert result.status_code == 503
    assert item.snapshot().reconciliation_required is True
    assert item.handle(raw_request("GET", "/version"), Cancel()).status_code == 503


def test_unbound_audit_receipt_is_treated_as_an_audit_failure() -> None:
    item, _audit, _clock = proxy(
        Transport(raw_response(200, {"ApiVersion": "1.47", "Os": "linux"})),
        audit=Audit(substitute_receipt=True),
    )
    assert item.handle(raw_request("GET", "/version"), Cancel()).status_code == 503
    assert item.snapshot().reconciliation_required is True


def test_reentrant_audit_is_refused_as_busy_without_deadlock() -> None:
    audit = Audit()
    transport = Transport(raw_response(200, {"ApiVersion": "1.47", "Os": "linux"}))
    item, _audit, _clock = proxy(transport, audit=audit)
    replies: list[DockerProxyReply] = []
    audit.reentrant = lambda: replies.append(item.handle(raw_request("GET", "/version"), Cancel()))
    assert item.handle(raw_request("GET", "/version"), Cancel()).status_code == 200
    assert replies and all(reply.status_code == 409 for reply in replies)


def test_audit_records_only_bound_hashes_and_sanitized_operation_state() -> None:
    request = raw_request("GET", "/version")
    response = raw_response(
        200,
        {"ApiVersion": "1.47", "Os": "linux", "Private": "do-not-publish"},
    )
    item, audit, _clock = proxy(Transport(response))
    assert item.handle(request, Cancel()).status_code == 200
    record = audit.records[-1]
    assert record.request_digest == _sha(request)
    assert record.response_digest == _sha(response)
    assert record.operation == "version"
    assert "do-not-publish" not in json.dumps(record.to_dict())


def test_single_flight_rejects_concurrent_request() -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingTransport(Transport):
        def exchange(self, *args: object, **kwargs: object) -> DockerDaemonExchange:
            entered.set()
            assert release.wait(5)
            return super().exchange(*args, **kwargs)  # type: ignore[arg-type]

    item, _audit, _clock = proxy(
        BlockingTransport(raw_response(200, {"ApiVersion": "1.47", "Os": "linux"}))
    )
    first: list[DockerProxyReply] = []
    thread = threading.Thread(
        target=lambda: first.append(item.handle(raw_request("GET", "/version"), Cancel()))
    )
    thread.start()
    assert entered.wait(5)
    assert item.handle(raw_request("GET", "/version"), Cancel()).status_code == 409
    release.set()
    thread.join(5)
    assert [reply.status_code for reply in first] == [200]


def test_deadline_and_cancellation_after_transport_suppress_publication() -> None:
    clock = Clock()
    item, _audit, _clock = proxy(
        Transport(
            raw_response(200, {"ApiVersion": "1.47", "Os": "linux"}),
            clock=clock,
            advance_ns=11 * 1_000_000_000,
        ),
        clock=clock,
    )
    assert item.handle(raw_request("GET", "/version"), Cancel()).status_code == 504
    assert item.snapshot().reconciliation_required is True

    cancel = Cancel()

    class CancellingTransport(Transport):
        def exchange(self, *args: object, **kwargs: object) -> DockerDaemonExchange:
            result = super().exchange(*args, **kwargs)  # type: ignore[arg-type]
            cancel.value = True
            return result

    cancelled, _audit, _clock = proxy(
        CancellingTransport(raw_response(200, {"ApiVersion": "1.47", "Os": "linux"}))
    )
    assert cancelled.handle(raw_request("GET", "/version"), cancel).status_code == 503
    assert cancelled.snapshot().reconciliation_required is True


def test_pretransport_cancellation_is_audited_without_contacting_transport() -> None:
    cancel = Cancel()
    cancel.value = True
    transport = Transport(raw_response(200, {"ApiVersion": "1.47", "Os": "linux"}))
    item, audit, _clock = proxy(transport)
    assert item.handle(raw_request("GET", "/version"), cancel).status_code == 503
    assert transport.seen == []
    assert audit.records[-1].outcome == "cancelled"
    assert item.snapshot().reconciliation_required is False


def test_image_inspect_proves_exact_preloaded_digest() -> None:
    target = f"/v1.47/images/{quote(IMAGE_REFERENCE, safe='')}/json"
    item, _audit, _clock = proxy(
        Transport(raw_response(200, {"Id": IMAGE_DIGEST, "RepoDigests": [IMAGE_REFERENCE]}))
    )
    result = item.handle(raw_request("GET", target), Cancel())
    assert json.loads(result.body) == {"Id": IMAGE_DIGEST, "RepoDigests": [IMAGE_REFERENCE]}

    substituted, _audit, _clock = proxy(
        Transport(raw_response(200, {"Id": IMAGE_DIGEST, "RepoDigests": IMAGE_REFERENCE}))
    )
    assert substituted.handle(raw_request("GET", target), Cancel()).status_code == 503


def test_initial_clock_failure_is_sanitized() -> None:
    def broken_clock() -> int:
        raise RuntimeError("private clock detail")

    item = DockerPolicyProxy(
        policy=policy(),
        ownership=ownership(),
        transport=Transport(raw_response(200, {"ApiVersion": "1.47", "Os": "linux"})),
        audit=Audit(),
        monotonic_ns=broken_clock,
    )
    result = item.handle(raw_request("GET", "/version"), Cancel())
    assert result.status_code == 503
    assert b"private" not in result.body


def test_reply_http_serialization_contains_only_sanitized_headers() -> None:
    reply = DockerProxyReply.create(200, b"OK", content_type="text/plain")
    rendered = reply.to_http_bytes()
    assert rendered.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"content-length: 2\r\n" in rendered
    assert rendered.endswith(b"\r\n\r\nOK")
