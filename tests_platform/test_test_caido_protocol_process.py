"""Test-only provider process custody; installed worker proof is separate."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from bluefire import test_caido_protocol_process as process_owner
from bluefire import test_caido_protocol_provider as provider
from bluefire.engine_installed_v2_authority import InstalledStrixV2AuthorityGuard
from bluefire.util import content_hash


def digest(character: str) -> str:
    return "sha256:" + character * 64


def manifest(listener: socket.socket) -> provider.TestCaidoProviderManifest:
    info = os.fstat(listener.fileno())
    netns = os.stat("/proc/self/ns/net")
    cookie = int.from_bytes(
        listener.getsockopt(socket.SOL_SOCKET, provider.SO_NETNS_COOKIE, 8),
        sys.byteorder,
    )
    return provider.TestCaidoProviderManifest(
        accepted_claim_digest=digest("a"),
        runtime_admission_digest=digest("b"),
        controlled_profile_digest=digest("c"),
        authorization_digest=digest("d"),
        provider_source_digest=provider.provider_source_digest(),
        binding=provider.TestCaidoListenerBinding(
            attempt_id="engine-attempt-" + "1" * 32,
            container_ref=digest("1"),
            provider_generation_ref=digest("2"),
            owner_process_ref=digest("3"),
            listener_ref=digest("4"),
            custody_ref=digest("5"),
            netns_device=netns.st_dev,
            netns_inode=netns.st_ino,
            netns_cookie=cookie,
            listener_device=info.st_dev,
            listener_inode=info.st_ino,
        ),
    )


def owner_binding(prelaunch_ref: str, transaction_ref: str) -> tuple[str, str, str]:
    binding_ref = content_hash(
        {
            "schema_version": "bluefire.installed-strix-v2-prelaunch-resource-binding.v1",
            "prelaunch_ref": prelaunch_ref,
            "role": "caido_channel",
        }
    )
    owner_ref = content_hash(
        {
            "schema_version": "bluefire.installed-strix-v2-resource-owner.v1",
            "transaction_ref": transaction_ref,
            "role": "caido_channel",
            "binding_ref": binding_ref,
        }
    )
    return "caido_channel", binding_ref, owner_ref


def test_process_owner_binding_refuses_changed_role_or_transaction() -> None:
    prelaunch_ref = digest("6")
    transaction_ref = digest("7")
    exact = owner_binding(prelaunch_ref, transaction_ref)
    assert (
        process_owner._owner_binding(  # noqa: SLF001 - exact boundary check
            prelaunch_ref=prelaunch_ref,
            resource_transaction_ref=transaction_ref,
            resource_owner_binding=exact,
        )
        == exact[2]
    )
    for changed in (
        ("docker_control", exact[1], exact[2]),
        owner_binding(prelaunch_ref, digest("8")),
        ("caido_channel", exact[1], digest("9")),
    ):
        with pytest.raises(
            process_owner.TestCaidoProcessError, match="resource_owner_binding_invalid"
        ):
            process_owner._owner_binding(  # noqa: SLF001 - exact boundary check
                prelaunch_ref=prelaunch_ref,
                resource_transaction_ref=transaction_ref,
                resource_owner_binding=changed,
            )


def test_provider_audit_parser_refuses_duplicate_or_secret_bearing_json() -> None:
    with pytest.raises(process_owner.TestCaidoProcessError, match="provider_record_invalid"):
        process_owner._decode_object(b'{"sequence":1,"sequence":2}')  # noqa: SLF001
    with pytest.raises(process_owner.TestCaidoProcessError, match="provider_record_invalid"):
        process_owner._decode_object(b'{"value":NaN}')  # noqa: SLF001


def test_saved_ready_line_reopens_only_for_exact_attempt_and_provider() -> None:
    binding = provider.TestCaidoListenerBinding(
        attempt_id="engine-attempt-" + "1" * 32,
        container_ref=digest("1"),
        provider_generation_ref=digest("2"),
        owner_process_ref=digest("3"),
        listener_ref=digest("4"),
        custody_ref=digest("5"),
        netns_device=6,
        netns_inode=7,
        netns_cookie=8,
        listener_device=9,
        listener_inode=10,
    )
    value = provider.TestCaidoProviderManifest(
        accepted_claim_digest=digest("a"),
        runtime_admission_digest=digest("b"),
        controlled_profile_digest=digest("c"),
        authorization_digest=digest("d"),
        provider_source_digest=provider.provider_source_digest(),
        binding=binding,
    )
    identity = process_owner.TestCaidoProcessIdentity(
        pid=1234,
        start_ticks=99,
        boot_id="00000000-0000-0000-0000-000000000001",
        audit_device=4,
        audit_inode=5,
    )
    ready = {
        "schema_version": provider.READY_SCHEMA,
        "attempt_id": binding.attempt_id,
        "provider_identity_ref": value.identity_ref,
        "listener_ref": binding.listener_ref,
        "provider_source_digest": value.provider_source_digest,
        "test_provider": True,
        "live_caido_proof": False,
        "production_eligible": False,
        "ready": True,
    }
    payload = provider._canonical(ready) + b"\n"  # noqa: SLF001 - exact saved wire
    reopened = process_owner.reopen_ready(
        manifest=value,
        process_identity=identity,
        resource_owner_ref=digest("e"),
        ready_payload=payload,
    )
    assert reopened.ready_ref == content_hash(ready)
    assert reopened.process_identity_ref == identity.identity_ref
    with pytest.raises(process_owner.TestCaidoProcessError, match="provider_ready_invalid"):
        process_owner.reopen_ready(
            manifest=value,
            process_identity=identity,
            resource_owner_ref=digest("e"),
            ready_payload=payload.replace(b'"ready":true', b'"ready":false'),
        )


@pytest.mark.skipif(sys.platform != "linux", reason="owned process FDs are Linux-only")
def test_prelaunch_provider_waits_for_activation_and_reopens_drain(tmp_path) -> None:
    # -I deliberately ignores this source checkout. Only an exact installed
    # candidate can exercise the child process test; source tests do not claim it.
    described = subprocess.run(
        [sys.executable, "-I", "-m", "bluefire.test_caido_protocol_provider", "--describe"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    if described.returncode != 0:
        pytest.skip("Test Caido provider is not installed in the isolated Python environment")
    try:
        installed = json.loads(described.stdout)
    except ValueError:
        pytest.skip("installed Test Caido provider descriptor is unreadable")
    if installed.get("provider_source_digest") != provider.provider_source_digest():
        pytest.skip("isolated Python has a different installed Test Caido provider revision")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", provider.LISTENER_PORT))
    listener.listen(4)
    audit_path = tmp_path / "caido-audit.jsonl"
    audit_fd = os.open(audit_path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_APPEND, 0o600)
    try:
        value = manifest(listener)
        prelaunch_ref = digest("6")
        transaction_ref = digest("7")
        owned = process_owner.InstalledStrixV2CaidoProvider.start(
            manifest=value,
            listener_fd=listener.fileno(),
            audit_fd=audit_fd,
            prelaunch_ref=prelaunch_ref,
            resource_transaction_ref=transaction_ref,
            resource_owner_binding=owner_binding(prelaunch_ref, transaction_ref),
        )
        assert owned.activation_receipt is None
        with socket.create_connection(("127.0.0.1", provider.LISTENER_PORT), timeout=1) as client:
            client.settimeout(0.1)
            client.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1:48080\r\n\r\n")
            with pytest.raises(TimeoutError):
                client.recv(1)
        # This controlled snapshot tests only the child activation pipe. A
        # product journey must use ProductStore-backed require_active instead.
        fake_snapshot = SimpleNamespace(
            prelaunch_ref=prelaunch_ref,
            snapshot_ref=digest("8"),
            admission=SimpleNamespace(
                to_dict=lambda: {"delegation_digest": value.authorization_digest}
            ),
            activation=SimpleNamespace(
                claim_ref=value.accepted_claim_digest,
                admission_ref=value.runtime_admission_digest,
                controlled_profile_ref=value.controlled_profile_digest,
                caido_mode="test_protocol_provider",
                caido_test_provider=True,
                caido_provider_identity_ref=value.identity_ref,
                role_bindings=(("caido_channel", value.identity_ref),),
            ),
        )
        guard = object.__new__(InstalledStrixV2AuthorityGuard)
        with patch.object(
            InstalledStrixV2AuthorityGuard,
            "require_active",
            lambda _self: fake_snapshot,
            create=True,
        ):
            activation = owned.activate(guard)
        assert activation.provider_identity_ref == value.identity_ref
        with socket.create_connection(("127.0.0.1", provider.LISTENER_PORT), timeout=2) as client:
            client.settimeout(2)
            client.sendall(
                b"GET /health HTTP/1.1\r\n"
                b"Host: 127.0.0.1:48080\r\n"
                b"Accept: */*\r\n"
                b"Accept-Encoding: gzip, deflate\r\n"
                b"User-Agent: Python/3.12 aiohttp/3.14.5\r\n\r\n"
            )
            response = client.recv(8192)
        assert response.startswith(b"HTTP/1.1 200 OK")
        # Closing the controller's sole write descriptor exercises the same
        # kernel EOF seen by the provider after abrupt controller exit.
        owner_write_fd = owned._owner_write_fd  # noqa: SLF001 - lifecycle fault injection
        assert owner_write_fd is not None
        os.close(owner_write_fd)
        owned._owner_write_fd = None  # noqa: SLF001 - avoid a second close on reused FD
        assert owned._process.wait(timeout=3) == 0  # noqa: SLF001 - independent child exit
        drained = owned.cancel()
        assert drained.provider_process_exited is True
        assert drained.provider_state_drained is True
        assert drained.target_cleanup_verified is False
        assert drained.audit_record_count >= 2
        reopened = process_owner.reopen_drain(
            manifest=value,
            process_identity=owned.process_identity,
            ready_ref=owned.ready_ref,
            resource_owner_ref=drained.resource_owner_ref,
            audit_fd=audit_fd,
        )
        assert reopened.evidence_ref == drained.evidence_ref
        assert owned.cancel() is drained
    finally:
        os.close(audit_fd)
        listener.close()


@pytest.mark.skipif(sys.platform != "linux", reason="listener inspection is Linux-only")
def test_listener_substitution_is_rejected_before_process_launch() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", provider.LISTENER_PORT))
        listener.listen(4)
        value = manifest(listener)
        wrong = replace(
            value, binding=replace(value.binding, netns_cookie=value.binding.netns_cookie + 1)
        )
        with pytest.raises(process_owner.TestCaidoProcessError, match="listener_custody_invalid"):
            process_owner._verify_listener(listener.fileno(), wrong)  # noqa: SLF001
    finally:
        listener.close()
