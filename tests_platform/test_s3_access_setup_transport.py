"""Real mTLS and retained extension, synthetic runner/runtime, no AWS or worker.

Portable projection cases substitute only the Linux host gate. The native-host
cases below keep that gate intact; positive Linux admission is a separate lane.
"""

from __future__ import annotations

import os
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import s3_access_setup as setup
from bluefire import s3_access_transport as transport
from bluefire.runner_private_files import _PinnedPrivateDirectory
from bluefire.runner_transport import (
    AuthenticatedRunnerClient,
    AuthenticatedRunnerServer,
    RunnerAuthenticationError,
    RunnerConnectionError,
    RunnerRemoteError,
)
from bluefire.runner_trust import load_local_enrollment, revoke_local_enrollment
from bluefire.s3_access_contract import S3AccessScope
from bluefire.s3_access_executor import configured_executor
from bluefire.s3_access_extension_store import S3ExtensionStore
from bluefire.s3_access_host_config import public_environments
from bluefire.util import content_hash
from tests_platform.s3_profile_fixtures import managed_profile
from tests_platform.test_s3_access_extension import imported, publish
from tests_platform.test_s3_access_extension import local as local
from tests_platform.test_s3_access_wire import NOW, credential_row


class DiscoveryOnlyRunner:
    s3_access_admission_protocol = transport.SCHEMA

    def __init__(self, runner_id):
        self.runner_id = runner_id
        self.calls = 0

    def inventory(self):
        return {
            "schema_version": "bluefire.runner-inventory.v1",
            "runner_id": self.runner_id,
            "runner_version": "0.1.0",
            "action_sdk_version": "bluefire.runner-action-sdk.v1",
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
            "platform": "linux",
            "actions": [
                {
                    "schema_version": "bluefire.runner-action-sdk.v1",
                    "action_id": transport.ACTION,
                    "action_version": "1.0.0",
                    "readiness": "structural",
                    "capabilities": ["cloud_aws_s3_access"],
                    "platforms": ["linux"],
                }
            ],
        }

    def execute(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("Discovery must never execute a worker")


def client(local, server):
    enrollment, configuration, provider = local
    host, port = server.server_address
    return AuthenticatedRunnerClient(
        enrollment.root,
        profile_id=configuration["environments"][0]["profile"]["profile_id"],
        host=host,
        port=port,
        secret_provider=provider,
        socket_timeout_seconds=3,
    )


def server(local):
    enrollment, _, provider = local
    return AuthenticatedRunnerServer(
        enrollment.root,
        DiscoveryOnlyRunner(enrollment.runner_id),
        enrollment.root.parent / "discovery.sqlite3",
        secret_provider=provider,
        socket_timeout_seconds=3,
    )


def snapshot(root):
    return {path.name: path.read_bytes() for path in root.iterdir()}


def bind_profile(local):
    configuration = local[1]
    entry = configuration["environments"][0]
    profile = managed_profile(entry["profile"]["profile_id"])
    configuration["schema_version"] = "bluefire.s3-host-environments.v3"
    entry["managed_profile_digest"] = content_hash(profile.to_dict())


@pytest.fixture
def portable_projection(local, monkeypatch):
    bind_profile(local)
    imported(local)
    # Bypass the OS gate, not the real directory, trust, HMAC or revision checks.
    monkeypatch.setattr(transport, "read_configuration", setup.read_configuration)
    monkeypatch.setattr(
        transport,
        "inspect_extension",
        lambda enrollment: setup.inspect_extension(enrollment, clock=lambda: NOW),
    )
    return local


@pytest.mark.parametrize("state", ["absent", "expired"])
def test_real_mtls_reports_missing_or_expired_reference_without_decryption(
    local, monkeypatch, state
):
    enrollment, _, provider = local
    bind_profile(local)
    if state == "absent":
        publish(local)
    else:
        imported(local)
    monkeypatch.setattr(transport, "read_configuration", setup.read_configuration)
    monkeypatch.setattr(
        transport,
        "inspect_extension",
        lambda value: setup.inspect_extension(value, clock=lambda: NOW + timedelta(days=1)),
    )
    original = provider.unprotect

    def unprotect(purpose, opaque):
        assert not purpose.startswith("bluefire.s3-temporary.v1:")
        return original(purpose, opaque)

    monkeypatch.setattr(provider, "unprotect", unprotect)
    extension = S3ExtensionStore(enrollment).root
    before = snapshot(extension)
    with server(local) as host:
        rows = client(local, host).s3_access_environments()
        assert len(rows) == 1
        assert rows[0]["available"] is False
        assert rows[0]["problem"] == f"access_reference_{state}"
        assert host.runner.calls == 0
    assert snapshot(extension) == before


def test_real_mtls_projection_survives_restart_without_decrypting_cloud_material(
    portable_projection, monkeypatch
):
    enrollment, configuration, provider = portable_projection
    trust_before = snapshot(enrollment.root)
    extension = S3ExtensionStore(enrollment).root
    extension_before = snapshot(extension)
    original = provider.unprotect

    def unprotect(purpose, opaque):
        assert not purpose.startswith("bluefire.s3-temporary.v1:")
        return original(purpose, opaque)

    monkeypatch.setattr(provider, "unprotect", unprotect)
    for _ in range(2):
        with server(portable_projection) as host:
            rows = client(portable_projection, host).s3_access_environments()
            assert len(rows) == 1
            assert rows[0]["environment"] == public_environments(configuration)[0]
            assert (
                rows[0]["managed_profile_digest"]
                == configuration["environments"][0]["managed_profile_digest"]
            )
            assert rows[0]["available"] is True
            assert host.runner.calls == 0
            for forbidden in ("credential_reference", "runtime_root", "ledger_root"):
                assert forbidden not in str(rows)
            for key in ("access_key", "secret_key", "token"):
                assert credential_row()[key] not in str(rows)
        assert host._serve_thread is None or not host._serve_thread.is_alive()
    assert snapshot(enrollment.root) == trust_before
    assert snapshot(extension) == extension_before
    assert (
        load_local_enrollment(enrollment.root, secret_provider=provider).metadata
        == enrollment.metadata
    )


def test_complete_profile_drift_reaches_executor_over_real_authenticated_transport(
    portable_projection,
):
    enrollment, configuration, _ = portable_projection
    entry = configuration["environments"][0]
    profile = managed_profile(entry["profile"]["profile_id"])
    scope = S3AccessScope.from_mapping(entry["scope"])
    before = snapshot(S3ExtensionStore(enrollment).root)
    with server(portable_projection) as host:
        caller = client(portable_projection, host)
        service = SimpleNamespace(
            _runner_profiles=lambda: (profile,),
            runner_lifecycle=SimpleNamespace(
                client_for_profile=lambda *args, **kwargs: (
                    caller,
                    Path(entry["profile"]["sandbox_root"]),
                )
            ),
        )
        executor = configured_executor(service)
        assert executor.readiness(scope)["available"] is True
        profile.budgets = replace(profile.budgets, max_steps=11)
        readiness = executor.readiness(scope)
        assert readiness["available"] is False and readiness["problem"] == "profile_changed"
        assert entry["managed_profile_digest"] != content_hash(profile.to_dict())
        assert host.runner.calls == 0
    assert snapshot(S3ExtensionStore(enrollment).root) == before


def test_real_mtls_keeps_legacy_configuration_readable_without_new_authority(local, monkeypatch):
    imported(local)
    monkeypatch.setattr(transport, "read_configuration", setup.read_configuration)
    monkeypatch.setattr(
        transport,
        "inspect_extension",
        lambda enrollment: setup.inspect_extension(enrollment, clock=lambda: NOW),
    )
    before = snapshot(S3ExtensionStore(local[0]).root)
    with server(local) as host:
        rows = client(local, host).s3_access_environments()
        assert rows[0]["environment"] == public_environments(local[1])[0]
        assert rows[0]["managed_profile_digest"] is None
        assert rows[0]["available"] is False and rows[0]["problem"] == "profile_changed"
        assert host.runner.calls == 0
    assert snapshot(S3ExtensionStore(local[0]).root) == before


def test_incomplete_extension_refuses_authenticated_discovery_without_repair(portable_projection):
    enrollment, _, _ = portable_projection
    extension = S3ExtensionStore(enrollment).root
    with _PinnedPrivateDirectory(extension) as directory:
        directory.create(".pending.json", b"{}", maximum=16)
    before = snapshot(extension)
    with server(portable_projection) as host:
        with pytest.raises(RunnerRemoteError) as caught:
            client(portable_projection, host).s3_access_environments()
        assert caught.value.code == "runner_failure"
        assert host.runner.calls == 0
    assert snapshot(extension) == before


def test_revocation_blocks_retained_authenticated_projection(portable_projection):
    enrollment, _, provider = portable_projection
    extension = S3ExtensionStore(enrollment).root
    before = snapshot(extension)
    with server(portable_projection) as host:
        caller = client(portable_projection, host)
        assert caller.s3_access_environments()
        revoke_local_enrollment(enrollment.root, secret_provider=provider)
        with pytest.raises((RunnerAuthenticationError, RunnerConnectionError, RunnerRemoteError)):
            caller.s3_access_environments()
        assert host.runner.calls == 0
    assert snapshot(extension) == before


LINUX_OWNER = sys.platform.startswith("linux") and getattr(os, "getuid", lambda: 0)() > 0


@pytest.mark.skipif(not LINUX_OWNER, reason="requires the real owned non-root Linux host")
def test_real_linux_host_gate_projects_retained_extension(local):
    imported(local)
    with server(local) as host:
        rows = client(local, host).s3_access_environments()
        assert rows[0]["environment"] == public_environments(local[1])[0]
        assert host.runner.calls == 0


@pytest.mark.skipif(LINUX_OWNER, reason="requires an unsupported host")
def test_unsupported_host_remains_closed_over_real_mtls(local):
    imported(local)
    with server(local) as host:
        with pytest.raises(RunnerRemoteError) as caught:
            client(local, host).s3_access_environments()
        assert caught.value.code == "runner_failure"
        assert host.runner.calls == 0
