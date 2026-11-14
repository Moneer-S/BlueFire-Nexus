"""Opt-in real-dockerd custody check for an owned disposable container.

This proves the external supervisor's Docker cleanup and recovery path. It does
not by itself prove an admitted Strix exec, target response, or model decision.
The installed journey must establish those separately on the same candidate.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from bluefire.engine_docker_transport import LinuxDockerDaemonEndpoint
from bluefire.engine_exec_operation_supervisor import (
    ExecLifetimeOperationRequestV2,
    ExecLifetimeSupervisorBindingV2,
)
from bluefire.linux_exec_lifetime_supervisor import (
    LinuxExecLifetimeSupervisorProfileV2,
    LinuxExternalExecLifetimeSupervisorV2,
)
from bluefire.linux_exec_supervisor_docker import SupervisorDockerContainerIdentity
from bluefire.util import content_hash


def _docker(environment: dict[str, str], *arguments: str, timeout: int = 45) -> str:
    result = subprocess.run(
        ["docker", *arguments],
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"owned Docker test command failed ({arguments[0]}): {result.stderr.strip()[:500]}"
        )
    return result.stdout.strip()


def _inspect(environment: dict[str, str], identifier: str) -> dict[str, Any]:
    rows = json.loads(_docker(environment, "container", "inspect", identifier))
    assert isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict)
    return rows[0]


def _absent(environment: dict[str, str], identifier: str) -> bool:
    result = subprocess.run(
        ["docker", "container", "inspect", identifier],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode == 0:
        return False
    assert result.returncode == 1 and "No such" in result.stderr
    inventory = _docker(
        environment,
        "ps",
        "--all",
        "--no-trunc",
        "--filter",
        f"id={identifier}",
        "--format",
        "{{.ID}}",
    )
    assert inventory == ""
    return True


@pytest.mark.skipif(sys.platform != "linux", reason="Linux pidfd and local dockerd")
def test_real_docker_broker_loss_retains_absence_and_recovery(
    tmp_path: Path,
) -> None:
    if os.environ.get("BLUEFIRE_REAL_DOCKER_TEST") != "1":
        pytest.skip("explicit real-Docker qualification was not requested")
    assert shutil.which("docker"), "hosted runner requires the Docker CLI"

    socket_path = Path(os.environ.get("BLUEFIRE_DOCKER_SOCKET", "/var/run/docker.sock")).resolve(
        strict=True
    )
    assert socket_path.is_socket(), "hosted runner requires a local Docker Unix socket"
    docker_config = tmp_path / "empty-docker-config"
    docker_config.mkdir(mode=0o700)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "DOCKER_HOST": f"unix://{socket_path}",
        "DOCKER_CONFIG": str(docker_config),
    }
    version = json.loads(_docker(environment, "version", "--format", "{{json .Server}}"))
    minimum = tuple(int(part) for part in version["MinAPIVersion"].split("."))
    assert minimum <= (1, 43), "hosted dockerd no longer supports pinned API v1.43"
    daemon = json.loads(_docker(environment, "info", "--format", "{{json .}}"))
    assert isinstance(daemon.get("ID"), str) and daemon["ID"]

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.connect(str(socket_path))
        peer_pid, peer_uid, peer_gid = struct.unpack(
            "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
    socket_stat = socket_path.lstat()
    endpoint = LinuxDockerDaemonEndpoint(
        socket_path=str(socket_path),
        daemon_instance_digest=content_hash({"docker_id": daemon["ID"]}),
        socket_device=socket_stat.st_dev,
        socket_inode=socket_stat.st_ino,
        peer_uid=peer_uid,
        peer_gid=peer_gid,
        peer_pid=peer_pid,
    )

    # Pull only a small test image. Create by its observed immutable digest, and
    # keep the container disconnected, read-only, unprivileged, and short-lived.
    image_tag = os.environ.get("BLUEFIRE_REAL_DOCKER_TEST_IMAGE", "busybox:1.36")
    _docker(environment, "pull", image_tag, timeout=120)
    image = json.loads(_docker(environment, "image", "inspect", image_tag))[0]
    digests = image.get("RepoDigests")
    assert isinstance(digests, list) and digests and "@sha256:" in digests[0]
    image_reference = digests[0]
    _docker(environment, "pull", image_reference, timeout=120)
    image_config_digest = image["Id"]

    nonce = secrets.token_hex(16)
    attempt_id = f"engine-attempt-{nonce}"
    operation_id = f"operation-{secrets.token_hex(16)}"
    container_name = f"strix-sandbox-{nonce}"
    policy_digest = content_hash({"test_policy": nonce})
    execution_digest = content_hash({"test_execution": nonce})
    profile_digest = content_hash({"test_profile": nonce})
    labels = tuple(
        sorted(
            {
                "bluefire.engine.attempt": attempt_id,
                "bluefire.engine.image-identity": content_hash(
                    {"test_image_identity": image_reference}
                ),
                "strix-run-id": attempt_id,
                "strix-run-type": "bluefire",
            }.items()
        )
    )
    created_id: str | None = None
    backend: LinuxExternalExecLifetimeSupervisorV2 | None = None
    recovery: LinuxExternalExecLifetimeSupervisorV2 | None = None
    try:
        create = [
            "create",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "32",
            "--memory",
            "64m",
            "--cpus",
            "0.5",
        ]
        for key, value in labels:
            create.extend(("--label", f"{key}={value}"))
        created_id = _docker(environment, *create, image_reference, "sleep", "600")
        assert len(created_id) == 64
        _docker(environment, "start", created_id)
        observed = _inspect(environment, created_id)
        assert observed["Id"] == created_id
        assert observed["Config"]["Image"] == image_reference
        assert observed["Image"] == image_config_digest
        assert observed["Config"]["Labels"] == dict(labels)
        assert observed["State"]["Running"] is True

        identity = SupervisorDockerContainerIdentity(
            container_id=created_id,
            container_name=container_name,
            image_config_digest=image_config_digest,
            image_reference=image_reference,
            required_labels=labels,
            policy_digest=policy_digest,
            execution_identity_digest=execution_digest,
            profile_digest=profile_digest,
        )
        binding = ExecLifetimeSupervisorBindingV2(
            attempt_id=attempt_id,
            claim_ref=content_hash({"claim": nonce}),
            controller_fence=content_hash({"fence": nonce}),
            custody_plan_digest=content_hash({"custody": nonce}),
            network_policy_digest=content_hash({"network": nonce}),
            controller_instance_ref=content_hash({"controller": nonce}),
            supervisor_qualification_ref=content_hash({"supervisor": nonce}),
        )
        profile = LinuxExecLifetimeSupervisorProfileV2(
            state_directory=tmp_path / "supervisor-state",
            daemon_endpoint=endpoint,
            api_version="v1.43",
            containers=(identity,),
            supervisor_qualification_ref=binding.supervisor_qualification_ref,
            cleanup_timeout_milliseconds=15_000,
        )
        backend = LinuxExternalExecLifetimeSupervisorV2.new(profile)
        activation = backend.activate_new(binding)
        request = ExecLifetimeOperationRequestV2(
            admission_digest=content_hash({"admission": nonce}),
            attempt_id=attempt_id,
            operation_id=operation_id,
            container_id=created_id,
            claim_ref=binding.claim_ref,
            controller_fence=binding.controller_fence,
            custody_plan_digest=binding.custody_plan_digest,
            network_policy_digest=binding.network_policy_digest,
            operation_deadline_monotonic_ns=time.monotonic_ns() + 60_000_000_000,
            controller_instance_ref=binding.controller_instance_ref,
            supervisor_instance_ref=activation.supervisor_instance_ref,
        )
        lease = backend.arm(request)
        assert lease.operation_id == operation_id
        assert _inspect(environment, created_id)["State"]["Running"] is True

        broker = backend._process  # exact process under test, never a worker handle
        assert broker is not None and broker.poll() is None
        os.kill(broker.pid, signal.SIGKILL)
        broker.wait(timeout=5)
        backend.detach()
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline and not _absent(environment, created_id):
            time.sleep(0.1)
        assert _absent(environment, created_id), "guardian did not remove owned container"

        deadline = time.monotonic() + 15
        while True:
            recovery = LinuxExternalExecLifetimeSupervisorV2.reconcile(profile)
            try:
                recovered = recovery.reopen_existing(binding)
                break
            except Exception:
                recovery.detach()
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        assert len(recovered.terminal_receipts) == 1
        receipt = recovered.terminal_receipts[0]
        assert receipt.outcome == "verified_absent"
        assert receipt.container_absent and receipt.background_work_absent
        events = recovery.terminal_events()
        assert len(events) == 1
        assert events[0].receipt.receipt_ref == receipt.receipt_ref
        assert events[0].evidence_digest == receipt.final_inventory_digest

        evidence_root = Path(os.environ.get("BLUEFIRE_REAL_DOCKER_EVIDENCE_DIR", str(tmp_path)))
        assert evidence_root.is_absolute()
        evidence_root.mkdir(parents=True, exist_ok=True)
        (evidence_root / "real-docker-supervisor.json").write_text(
            json.dumps(
                {
                    "schema_version": "bluefire.real-docker-supervisor-test.v1",
                    "os": sys.platform,
                    "image_reference": image_reference,
                    "image_config_digest": image_config_digest,
                    "daemon_instance_digest": endpoint.daemon_instance_digest,
                    "container_id": created_id,
                    "lease_ref": lease.lease_ref,
                    "receipt_ref": receipt.receipt_ref,
                    "terminal_cursor": events[0].cursor,
                    "final_inventory_digest": receipt.final_inventory_digest,
                    "independent_container_absence": True,
                    "proof_scope": "real Docker supervisor cleanup; no exec or Strix target action",
                },
                sort_keys=True,
                indent=2,
            ),
            encoding="utf-8",
        )
        recovery.acknowledge_terminal(cursor=events[0].cursor, receipt_ref=receipt.receipt_ref)
        assert recovery.terminal_events() == ()
        recovery.close()
        recovery = None
    finally:
        if recovery is not None:
            recovery.detach()
        if backend is not None:
            backend.detach()
        if created_id is not None and not _absent(environment, created_id):
            _docker(environment, "rm", "--force", created_id, timeout=30)
            assert _absent(environment, created_id)
