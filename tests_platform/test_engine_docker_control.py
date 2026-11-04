from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from urllib.parse import quote, urlencode

import pytest

from bluefire.engine_container_custody import ContainerCustodyPlan
from bluefire.engine_docker_control import (
    DockerApiOperation,
    DockerApiPolicy,
    DockerApiRequest,
    DockerOwnership,
    DockerResponseContract,
    EngineDockerPolicyError,
    authorize_docker_api_request,
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


def custody(*, labels: dict[str, str] | None = None) -> ContainerCustodyPlan:
    plan = network()
    return ContainerCustodyPlan.from_mapping(
        {
            "schema_version": "bluefire.engine-container-custody.v1",
            "attempt_id": ATTEMPT_ID,
            "daemon_instance_digest": DAEMON_DIGEST,
            "disposable_boundary_ref": "sha256:" + "2" * 64,
            "baseline_inventory_digest": "sha256:" + "3" * 64,
            "required_labels": labels
            or {
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
            "expected_capabilities": ["NET_ADMIN", "NET_RAW"],
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


def ownership(*, container: bool = True, exec_id: bool = True) -> DockerOwnership:
    containers = (CONTAINER_ID,) if container else ()
    execs = ((EXEC_ID, CONTAINER_ID),) if container and exec_id else ()
    return DockerOwnership.create(
        daemon_instance_digest=DAEMON_DIGEST,
        container_ids=containers,
        exec_bindings=execs,
    )


def request(
    method: str,
    target: str,
    body: dict[str, object] | bytes | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> DockerApiRequest:
    if isinstance(body, dict):
        raw = json.dumps(body, separators=(",", ":")).encode()
    else:
        raw = body or b""
    actual_headers = dict(headers or {})
    if raw:
        actual_headers.setdefault("content-type", "application/json")
        actual_headers.setdefault("content-length", str(len(raw)))
    return DockerApiRequest.create(method=method, target=target, headers=actual_headers, body=raw)


def create_body() -> dict[str, object]:
    plan = policy()
    return {
        "AttachStderr": False,
        "AttachStdin": False,
        "AttachStdout": False,
        "Cmd": ["tail", "-f", "/dev/null"],
        "Env": [],
        "HostConfig": {
            "AutoRemove": False,
            "Binds": [],
            "CapAdd": list(plan.expected_capabilities),
            "CapDrop": ["ALL"],
            "CgroupParent": plan.cgroup_parent,
            "DeviceRequests": [],
            "Devices": [],
            "Dns": [],
            "DnsOptions": [],
            "DnsSearch": [],
            "ExtraHosts": [],
            "IpcMode": "private",
            "LogConfig": {
                "Config": {"max-file": "1", "max-size": "10m"},
                "Type": "json-file",
            },
            "Memory": plan.memory_bytes,
            "Mounts": [],
            "NanoCpus": plan.nano_cpus,
            "NetworkMode": plan.network_name,
            "OomKillDisable": False,
            "PidMode": "private",
            "PidsLimit": plan.pids_limit,
            "PortBindings": {},
            "Privileged": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": True,
            "RestartPolicy": {"MaximumRetryCount": 0, "Name": "no"},
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/workspace": TMPFS_OPTIONS},
            "UTSMode": "private",
        },
        "Image": plan.image_reference,
        "Labels": dict(plan.required_labels),
        "NetworkDisabled": False,
        "NetworkingConfig": {
            "EndpointsConfig": {plan.network_name: {"Aliases": [], "NetworkID": plan.network_id}}
        },
        "OpenStdin": False,
        "StdinOnce": False,
        "Tty": False,
        "User": plan.expected_user,
    }


def exec_body(*, command: list[str] | None = None) -> dict[str, object]:
    return {
        "AttachStderr": True,
        "AttachStdin": False,
        "AttachStdout": True,
        "Cmd": command or ["sh", "-lc", "id"],
        "DetachKeys": "",
        "Env": [],
        "Privileged": False,
        "Tty": False,
        "User": policy().expected_user,
        "WorkingDir": "/workspace",
    }


def authorize(
    method: str,
    target: str,
    body: dict[str, object] | bytes | None = None,
    *,
    owned: DockerOwnership | None = None,
) -> object:
    return authorize_docker_api_request(
        policy(), request(method, target, body), owned or ownership()
    )


def test_policy_binds_existing_plans_labels_image_network_and_tmpfs() -> None:
    item = policy()

    assert item.attempt_id == ATTEMPT_ID
    assert item.image_reference == IMAGE_REFERENCE
    assert item.network_policy_digest == network().policy_digest
    assert item.container_name.endswith(ATTEMPT_ID[-12:])
    assert item.policy_digest == content_hash(item.to_dict())
    assert dict(item.required_labels) == {
        "bluefire.engine.attempt": ATTEMPT_ID,
        "strix-run-id": ATTEMPT_ID,
        "strix-run-type": "bluefire",
    }


@pytest.mark.parametrize("missing", ["bluefire.engine.attempt", "strix-run-id", "strix-run-type"])
def test_policy_requires_both_controller_and_upstream_labels(missing: str) -> None:
    labels = {
        "bluefire.engine.attempt": ATTEMPT_ID,
        "strix-run-id": ATTEMPT_ID,
        "strix-run-type": "bluefire",
    }
    labels.pop(missing)
    # The custody contract rejects its own BlueFire label first; this policy
    # additionally requires the two upstream labels.
    with pytest.raises(ValueError, match="labels|bind"):
        DockerApiPolicy.create(
            build=build(),
            network=network(),
            custody=custody(labels=labels),
            api_version="v1.47",
            tmpfs_options={"/workspace": TMPFS_OPTIONS},
        )


def test_policy_rejects_unpinned_api_and_tmpfs_bytes() -> None:
    with pytest.raises(EngineDockerPolicyError, match="API version"):
        DockerApiPolicy.create(
            build=build(),
            network=network(),
            custody=custody(),
            api_version="latest",
            tmpfs_options={"/workspace": TMPFS_OPTIONS},
        )
    with pytest.raises(EngineDockerPolicyError, match="digest"):
        DockerApiPolicy.create(
            build=build(),
            network=network(),
            custody=custody(),
            api_version="v1.47",
            tmpfs_options={"/workspace": "nosuid,rw"},
        )


@pytest.mark.parametrize(
    "changed,match",
    [
        ({"expected_user": "0:0"}, "non-root"),
        ({"expected_capabilities": ("NET_ADMIN", "SYS_ADMIN")}, "capability"),
        ({"expected_container_count": 2}, "exactly one"),
        ({"memory_bytes": 128 * 1024**2}, "tmpfs capacity"),
    ],
)
def test_policy_rejects_root_broad_capabilities_multiple_containers_and_large_tmpfs(
    changed: dict[str, object], match: str
) -> None:
    with pytest.raises(EngineDockerPolicyError, match=match):
        DockerApiPolicy.create(
            build=build(),
            network=network(),
            custody=replace(custody(), **changed),
            api_version="v1.47",
            tmpfs_options={"/workspace": TMPFS_OPTIONS},
        )


@pytest.mark.parametrize(
    "changed",
    [
        {"schema_version": "bluefire.engine-docker-api-policy.v2"},
        {"api_version": "latest"},
        {"expected_user": "root"},
        {"expected_capabilities": ("SYS_ADMIN",)},
        {"tmpfs": ()},
        {"memory_bytes": 2.0 * 1024**3},
        {"expected_container_count": 2},
        {"cgroup_parent": "/"},
        {"exec_deadline_seconds": 0},
    ],
)
def test_direct_policy_construction_revalidates_every_internal_invariant(
    changed: dict[str, object],
) -> None:
    with pytest.raises(EngineDockerPolicyError):
        replace(policy(), **changed)


def test_direct_nested_tmpfs_construction_is_revalidated() -> None:
    item = policy().tmpfs[0]
    with pytest.raises(EngineDockerPolicyError):
        replace(item, size_bytes=item.size_bytes + 1)


@pytest.mark.parametrize(
    "method,target",
    [
        ("GET", "http://docker/version"),
        ("GET", "//docker/version"),
        ("GET", "/v1.47//info"),
        ("GET", "/v1.47/../info"),
        ("GET", "/v1.47/%2e%2e/info"),
        ("GET", "/version#fragment"),
        ("CONNECT", "/version"),
    ],
)
def test_request_parser_rejects_ambiguous_targets_and_methods(method: str, target: str) -> None:
    with pytest.raises(EngineDockerPolicyError):
        request(method, target)


def test_request_parser_rejects_authority_headers_and_length_smuggling() -> None:
    with pytest.raises(EngineDockerPolicyError, match="header"):
        request("GET", "/version", headers={"authorization": "secret"})
    with pytest.raises(EngineDockerPolicyError, match="host"):
        request("GET", "/version", headers={"host": "127.0.0.1"})
    with pytest.raises(EngineDockerPolicyError, match="length"):
        request(
            "POST",
            "/v1.47/containers/create?name=x",
            b"{}",
            headers={"content-length": "3", "content-type": "application/json"},
        )
    with pytest.raises(EngineDockerPolicyError, match="accept"):
        request("GET", "/version", headers={"accept": "text/html"})


def test_direct_request_construction_cannot_bypass_header_or_body_validation() -> None:
    with pytest.raises(EngineDockerPolicyError, match="header"):
        DockerApiRequest(
            method="GET",
            target="/version",
            headers=(("authorization", "secret"),),
            body=b"",
        )
    with pytest.raises(EngineDockerPolicyError, match="application/json"):
        DockerApiRequest(
            method="POST",
            target="/v1.47/build",
            headers=(),
            body=b"{}",
        )


@pytest.mark.parametrize(
    "method,target,operation,response",
    [
        ("GET", "/_ping", DockerApiOperation.PING, DockerResponseContract.PING),
        ("HEAD", "/_ping", DockerApiOperation.PING, DockerResponseContract.PING),
        (
            "GET",
            "/version",
            DockerApiOperation.VERSION,
            DockerResponseContract.VERSION_REDACTED,
        ),
        (
            "GET",
            "/v1.47/info",
            DockerApiOperation.INFO,
            DockerResponseContract.INFO_REDACTED,
        ),
    ],
)
def test_only_exact_negotiation_and_redacted_metadata_are_allowed(
    method: str,
    target: str,
    operation: DockerApiOperation,
    response: DockerResponseContract,
) -> None:
    result = authorize(method, target)
    assert result.operation is operation
    assert result.response_contract is response


def test_image_inspection_requires_the_exact_fully_encoded_digest_reference() -> None:
    encoded = quote(IMAGE_REFERENCE, safe="")
    result = authorize("GET", f"/v1.47/images/{encoded}/json")
    assert result.operation is DockerApiOperation.IMAGE_INSPECT
    assert result.response_contract is DockerResponseContract.EXACT_IMAGE

    for target in (
        "/v1.47/images/ghcr.io/usestrix/sandbox:latest/json",
        f"/v1.46/images/{encoded}/json",
        "/v1.47/images/json",
    ):
        with pytest.raises(EngineDockerPolicyError):
            authorize("GET", target)


def test_exact_container_create_requires_post_inspect_registration() -> None:
    plan = policy()
    result = authorize_docker_api_request(
        plan,
        request("POST", f"/v1.47/containers/create?name={plan.container_name}", create_body()),
        ownership(container=False, exec_id=False),
    )

    assert result.operation is DockerApiOperation.CONTAINER_CREATE
    assert result.response_contract is DockerResponseContract.REGISTER_PENDING_CONTAINER
    assert result.body_digest == content_hash(create_body())

    with pytest.raises(EngineDockerPolicyError, match="count"):
        authorize("POST", f"/v1.47/containers/create?name={plan.container_name}", create_body())


def test_every_authorization_is_bound_to_the_admitted_daemon_and_baseline() -> None:
    plan = policy()
    assert plan.daemon_instance_digest == DAEMON_DIGEST
    assert plan.disposable_boundary_ref == custody().disposable_boundary_ref
    assert plan.baseline_inventory_digest == custody().baseline_inventory_digest

    rotated = DockerOwnership.create(
        daemon_instance_digest="sha256:" + "9" * 64,
        container_ids=(CONTAINER_ID,),
        exec_bindings=((EXEC_ID, CONTAINER_ID),),
    )
    with pytest.raises(EngineDockerPolicyError, match="daemon identity changed"):
        authorize_docker_api_request(plan, request("GET", "/version"), rotated)

    changed = replace(plan, daemon_instance_digest="sha256:" + "9" * 64)
    assert changed.policy_digest != plan.policy_digest


def test_created_container_is_pending_until_exact_inspection() -> None:
    pending = DockerOwnership.create(
        daemon_instance_digest=DAEMON_DIGEST,
        pending_container_ids=(CONTAINER_ID,),
    )
    result = authorize_docker_api_request(
        policy(), request("GET", f"/v1.47/containers/{CONTAINER_ID}/json"), pending
    )
    assert result.response_contract is DockerResponseContract.VERIFY_AND_REGISTER_CONTAINER

    with pytest.raises(EngineDockerPolicyError, match="positively owned"):
        authorize_docker_api_request(
            policy(), request("POST", f"/v1.47/containers/{CONTAINER_ID}/start"), pending
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda row: row["HostConfig"]["Binds"].append("/host:/workspace"),
        lambda row: row["HostConfig"]["Devices"].append({"PathOnHost": "/dev/kvm"}),
        lambda row: row["HostConfig"]["ExtraHosts"].append("host.docker.internal:host-gateway"),
        lambda row: row["HostConfig"].__setitem__("Privileged", True),
        lambda row: row["HostConfig"].__setitem__("ReadonlyRootfs", False),
        lambda row: row["HostConfig"].__setitem__("NetworkMode", "host"),
        lambda row: row["HostConfig"].__setitem__("PidMode", "host"),
        lambda row: row["HostConfig"].__setitem__("IpcMode", "host"),
        lambda row: row["HostConfig"].__setitem__("UTSMode", "host"),
        lambda row: row["HostConfig"].__setitem__("SecurityOpt", ["apparmor:unconfined"]),
        lambda row: row["HostConfig"].__setitem__("PortBindings", {"80/tcp": [{}]}),
        lambda row: row["HostConfig"].__setitem__("PublishAllPorts", True),
        lambda row: row["HostConfig"]["CapAdd"].append("SYS_ADMIN"),
        lambda row: row["HostConfig"].__setitem__("Memory", 0),
        lambda row: row["HostConfig"].__setitem__("NanoCpus", 0),
        lambda row: row["HostConfig"].__setitem__("PidsLimit", -1),
        lambda row: row["HostConfig"].__setitem__("CgroupParent", "/"),
        lambda row: row["HostConfig"].__setitem__("Tmpfs", {}),
        lambda row: row["HostConfig"].__setitem__(
            "RestartPolicy", {"MaximumRetryCount": 1, "Name": "always"}
        ),
        lambda row: row["HostConfig"].__setitem__("AutoRemove", True),
        lambda row: row.__setitem__("Env", ["AWS_ACCESS_KEY_ID=secret"]),
        lambda row: row.__setitem__("Cmd", ["sh", "-c", "host command"]),
        lambda row: row.__setitem__("Image", "sandbox:latest"),
        lambda row: row.__setitem__("User", "root"),
        lambda row: row["Labels"].pop("bluefire.engine.attempt"),
        lambda row: row["NetworkingConfig"]["EndpointsConfig"].__setitem__(
            "bridge", {"Aliases": [], "NetworkID": NETWORK_ID}
        ),
        lambda row: row.__setitem__("Hostname", "host"),
    ],
)
def test_container_create_rejects_escape_and_unreviewed_fields(mutator: object) -> None:
    row = create_body()
    mutator(row)  # type: ignore[operator]
    with pytest.raises(EngineDockerPolicyError):
        authorize_docker_api_request(
            policy(),
            request("POST", f"/v1.47/containers/create?name={policy().container_name}", row),
            ownership(container=False, exec_id=False),
        )


@pytest.mark.parametrize("field", ["Memory", "NanoCpus", "PidsLimit"])
def test_container_create_rejects_float_limits_equal_to_reviewed_integers(field: str) -> None:
    row = create_body()
    row["HostConfig"][field] = float(row["HostConfig"][field])  # type: ignore[index]
    with pytest.raises(EngineDockerPolicyError, match="integer"):
        authorize_docker_api_request(
            policy(),
            request("POST", f"/v1.47/containers/create?name={policy().container_name}", row),
            ownership(container=False, exec_id=False),
        )


def test_ownership_requires_full_daemon_ids_and_cannot_be_constructed_directly() -> None:
    with pytest.raises(EngineDockerPolicyError):
        DockerOwnership.create(
            daemon_instance_digest=DAEMON_DIGEST,
            container_ids=(CONTAINER_ID[:12],),
        )
    with pytest.raises(EngineDockerPolicyError):
        DockerOwnership(
            daemon_instance_digest=DAEMON_DIGEST,
            pending_container_ids=(),
            container_ids=(CONTAINER_ID[:12],),
            exec_bindings=(),
        )


def test_raw_pinned_upstream_host_gateway_shape_is_explicitly_non_admitting() -> None:
    row = create_body()
    row["HostConfig"]["ExtraHosts"] = ["host.docker.internal:host-gateway"]  # type: ignore[index]
    row["Labels"].pop("bluefire.engine.attempt")  # type: ignore[union-attr]
    with pytest.raises(EngineDockerPolicyError):
        authorize_docker_api_request(
            policy(),
            request("POST", f"/v1.47/containers/create?name={policy().container_name}", row),
            ownership(container=False, exec_id=False),
        )


@pytest.mark.parametrize(
    "method,suffix,body,operation",
    [
        ("GET", "json", None, DockerApiOperation.CONTAINER_INSPECT),
        ("POST", "start", None, DockerApiOperation.CONTAINER_START),
        ("POST", "exec", exec_body(), DockerApiOperation.CONTAINER_EXEC_CREATE),
    ],
)
def test_container_operations_require_positive_ownership(
    method: str, suffix: str, body: dict[str, object] | None, operation: DockerApiOperation
) -> None:
    result = authorize(method, f"/v1.47/containers/{CONTAINER_ID}/{suffix}", body)
    assert result.operation is operation
    with pytest.raises(EngineDockerPolicyError, match="positively owned"):
        authorize_docker_api_request(
            policy(),
            request(method, f"/v1.47/containers/{OTHER_CONTAINER_ID}/{suffix}", body),
            ownership(),
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("Privileged", True),
        ("Tty", True),
        ("AttachStdin", True),
        ("Env", ["TOKEN=secret"]),
        ("User", "root"),
        ("WorkingDir", "/"),
    ],
)
def test_exec_rejects_privilege_identity_environment_and_terminal_escalation(
    field: str, value: object
) -> None:
    row = exec_body()
    row[field] = value
    with pytest.raises(EngineDockerPolicyError):
        authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", row)


def test_exec_allows_bounded_model_chosen_commands_only_in_owned_sandbox() -> None:
    row = exec_body(command=["sh", "-lc", "find /workspace -maxdepth 2 -type f"])
    result = authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", row)
    assert result.operation is DockerApiOperation.CONTAINER_EXEC_CREATE
    assert result.response_contract is DockerResponseContract.REGISTER_EXEC
    assert result.owner_container_id == CONTAINER_ID

    row = exec_body(command=["x" * 8193])
    with pytest.raises(EngineDockerPolicyError, match="command"):
        authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", row)

    for command in (["sh", "-lc", "echo one\necho two"], ["id\x7f"]):
        with pytest.raises(EngineDockerPolicyError, match="command"):
            authorize(
                "POST",
                f"/v1.47/containers/{CONTAINER_ID}/exec",
                exec_body(command=command),
            )


@pytest.mark.parametrize(
    "path,allowed",
    [
        ("/workspace", True),
        ("/workspace/results/report.json", True),
        ("/tmp/sandbox-docker-archive/bundle.tar", True),
        ("/etc/passwd", False),
        ("/workspace/../etc/passwd", False),
        ("/tmp", False),
    ],
)
def test_archive_reads_are_bounded_to_owned_workspace(path: str, allowed: bool) -> None:
    target = f"/v1.47/containers/{CONTAINER_ID}/archive?{urlencode({'path': path})}"
    if allowed:
        result = authorize("GET", target)
        assert result.response_contract is DockerResponseContract.BOUNDED_ARCHIVE
    else:
        with pytest.raises(EngineDockerPolicyError):
            authorize("GET", target)


def test_logs_stop_kill_and_delete_require_exact_bounded_queries() -> None:
    logs = f"/v1.47/containers/{CONTAINER_ID}/logs?follow=0&stderr=1&stdout=1&tail=100&timestamps=1"
    assert authorize("GET", logs).operation is DockerApiOperation.CONTAINER_LOGS
    assert (
        authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/stop?t=30").operation
        is DockerApiOperation.CONTAINER_STOP
    )
    assert (
        authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/kill?signal=SIGKILL").operation
        is DockerApiOperation.CONTAINER_KILL
    )
    assert (
        authorize("DELETE", f"/v1.47/containers/{CONTAINER_ID}?force=1&v=1").operation
        is DockerApiOperation.CONTAINER_DELETE
    )

    for method, target in (
        ("GET", logs.replace("follow=0", "follow=1")),
        ("GET", logs.replace("tail=100", "tail=0100")),
        ("POST", f"/v1.47/containers/{CONTAINER_ID}/stop?t=31"),
        ("POST", f"/v1.47/containers/{CONTAINER_ID}/kill?signal=SIGHUP"),
        ("DELETE", f"/v1.47/containers/{CONTAINER_ID}?force=0&v=1"),
    ):
        with pytest.raises(EngineDockerPolicyError):
            authorize(method, target)


def test_exec_start_and_inspect_require_registered_exec_binding() -> None:
    start = authorize("POST", f"/v1.47/exec/{EXEC_ID}/start", {"Detach": False, "Tty": False})
    assert start.operation is DockerApiOperation.EXEC_START
    assert start.response_contract is DockerResponseContract.BOUNDED_EXEC_STREAM
    assert start.owner_container_id == CONTAINER_ID
    assert start.deadline_seconds == policy().exec_deadline_seconds
    assert start.response_byte_limit == policy().exec_response_byte_limit
    inspect = authorize("GET", f"/v1.47/exec/{EXEC_ID}/json")
    assert inspect.operation is DockerApiOperation.EXEC_INSPECT

    with pytest.raises(EngineDockerPolicyError, match="positively owned"):
        authorize_docker_api_request(
            policy(),
            request("GET", f"/v1.47/exec/{'9' * 64}/json"),
            ownership(),
        )


@pytest.mark.parametrize(
    "method,target,body",
    [
        ("POST", "/v1.47/images/create?fromImage=sandbox", None),
        ("POST", "/v1.47/build", {}),
        ("GET", "/v1.47/containers/json", None),
        ("GET", "/v1.47/networks", None),
        ("POST", "/v1.47/networks/create", {}),
        ("GET", "/v1.47/volumes", None),
        ("GET", "/v1.47/events", None),
        ("POST", f"/v1.47/containers/{CONTAINER_ID}/attach", {}),
        ("PUT", f"/v1.47/containers/{CONTAINER_ID}/archive?path=%2Fworkspace", b"x"),
        ("POST", "/v1.47/system/prune", {}),
        ("GET", "/v1.47/plugins", None),
        ("GET", "/v1.47/swarm", None),
    ],
)
def test_all_unreviewed_daemon_and_resource_routes_fail_closed(
    method: str, target: str, body: dict[str, object] | bytes | None
) -> None:
    with pytest.raises(EngineDockerPolicyError):
        authorize(method, target, body)


def test_json_duplicate_keys_nonfinite_values_bom_and_oversize_fail_closed() -> None:
    target = f"/v1.47/containers/{CONTAINER_ID}/exec"
    for raw in (
        b'{"Cmd":["id"],"Cmd":["whoami"]}',
        b'{"value":NaN}',
        b"\xef\xbb\xbf{}",
        b"{" + b" " * (64 * 1024) + b"}",
    ):
        with pytest.raises(EngineDockerPolicyError):
            authorize(target=target, method="POST", body=raw)


def test_decision_digests_are_stable_and_bind_policy_and_body() -> None:
    first = authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", exec_body())
    second = authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", exec_body())
    changed = authorize(
        "POST",
        f"/v1.47/containers/{CONTAINER_ID}/exec",
        exec_body(command=["sh", "-lc", "pwd"]),
    )
    assert first == second
    assert first.policy_digest == policy().policy_digest
    assert first.body_digest != changed.body_digest


def test_test_mutations_do_not_change_shared_create_fixture() -> None:
    original = create_body()
    changed = deepcopy(original)
    changed["HostConfig"]["Binds"].append("/host:/workspace")  # type: ignore[index]
    assert original["HostConfig"]["Binds"] == []  # type: ignore[index]
