from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

import bluefire.runner_trust as runner_trust
from bluefire.runner_trust import (
    RunnerTrustError,
    certificate_fingerprint,
    create_local_enrollment,
    enrollment_status,
    load_local_enrollment,
    local_enrollment_creation_path,
    remove_local_enrollment,
    revoke_local_enrollment,
)
from bluefire.secret_store import InMemorySecretProvider

EXPECTED_FILES = {
    "ca-cert.pem",
    "server-cert.pem",
    "server-key.pem",
    "server-key-password.secret",
    "client-cert.pem",
    "client-key.pem",
    "client-key-password.secret",
    "hmac.secret",
    "trust.json",
}


@pytest.fixture
def secret_provider() -> InMemorySecretProvider:
    return InMemorySecretProvider()


def test_local_enrollment_material_and_lifecycle(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    root = tmp_path / "trust"
    enrollment = create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("sandbox-execute-owned.v1", "sandbox-restricted-owned.v1"),
        secret_provider=secret_provider,
    )

    assert {item.name for item in root.iterdir()} == EXPECTED_FILES
    assert enrollment.root == root.resolve()
    assert enrollment.status == "active"
    assert enrollment.allowed_profile_ids == (
        "sandbox-execute-owned.v1",
        "sandbox-restricted-owned.v1",
    )
    assert len(enrollment.hmac_key()) == 32

    raw = root.joinpath("trust.json").read_text(encoding="utf-8")
    metadata = json.loads(raw)
    assert set(metadata) == {
        "schema_version",
        "runner_id",
        "client_id",
        "allowed_profile_ids",
        "status",
        "ca_fingerprint",
        "server_fingerprint",
        "client_fingerprint",
        "created_at",
        "expires_at",
        "revoked_at",
        "secret_provider",
    }
    assert "PRIVATE KEY" not in raw
    assert enrollment.hmac_key().hex() not in raw
    assert str(root) not in raw

    ca = x509.load_pem_x509_certificate(enrollment.ca_certificate.read_bytes())
    server = x509.load_pem_x509_certificate(enrollment.server_certificate.read_bytes())
    client = x509.load_pem_x509_certificate(enrollment.client_certificate.read_bytes())
    assert certificate_fingerprint(ca) == metadata["ca_fingerprint"]
    assert certificate_fingerprint(server) == metadata["server_fingerprint"]
    assert certificate_fingerprint(client) == metadata["client_fingerprint"]
    assert list(server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [
        ExtendedKeyUsageOID.SERVER_AUTH
    ]
    assert list(client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [
        ExtendedKeyUsageOID.CLIENT_AUTH
    ]
    sans = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert {str(value) for value in sans.get_values_for_type(x509.IPAddress)} == {
        "127.0.0.1",
        "::1",
    }
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in enrollment.server_private_key.read_bytes()
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in enrollment.client_private_key.read_bytes()
    for key_path, password in (
        (enrollment.server_private_key, enrollment.server_key_password()),
        (enrollment.client_private_key, enrollment.client_key_password()),
    ):
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=password)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert enrollment.server_key_password() not in enrollment.server_private_key.read_bytes()
    assert enrollment.client_key_password() not in enrollment.client_private_key.read_bytes()
    assert enrollment.hmac_key() not in enrollment.hmac_key_file.read_bytes()

    loaded = load_local_enrollment(root, secret_provider=secret_provider)
    assert loaded.metadata == enrollment.metadata
    revoked = revoke_local_enrollment(root, secret_provider=secret_provider)
    assert revoked.status == "revoked"
    assert isinstance(revoked.metadata["revoked_at"], str)
    assert enrollment_status(root, secret_provider=secret_provider)["status"] == "revoked"
    with pytest.raises(RunnerTrustError, match="Enrollment is not active"):
        load_local_enrollment(root, secret_provider=secret_provider)

    remove_local_enrollment(root, secret_provider=secret_provider)
    assert not root.exists()


def test_enrollments_use_random_authentication_keys_and_exclusive_roots(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    first = create_local_enrollment(
        tmp_path / "first",
        runner_id="bluefire-rust-runner.v1",
        client_id="client.one",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    second = create_local_enrollment(
        tmp_path / "second",
        runner_id="bluefire-rust-runner.v1",
        client_id="client.two",
        allowed_profile_ids=("profile.two",),
        secret_provider=secret_provider,
    )
    assert first.hmac_key() != second.hmac_key()

    with pytest.raises(RunnerTrustError, match="could not be created"):
        create_local_enrollment(
            first.root,
            runner_id="bluefire-rust-runner.v1",
            client_id="client.one",
            allowed_profile_ids=("profile.one",),
            secret_provider=secret_provider,
        )
    with pytest.raises(RunnerTrustError, match="unique and non-empty"):
        create_local_enrollment(
            tmp_path / "duplicate-profiles",
            runner_id="bluefire-rust-runner.v1",
            client_id="client.one",
            allowed_profile_ids=("profile.one", "profile.one"),
            secret_provider=secret_provider,
        )


def test_loading_fails_closed_for_metadata_key_and_certificate_tampering(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    root = tmp_path / "trust"
    enrollment = create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    metadata = dict(enrollment.metadata)
    metadata["private_key_path"] = "C:/sensitive/key.pem"  # pragma: allowlist secret
    enrollment.trust_file.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(RunnerTrustError) as failure:
        load_local_enrollment(root, secret_provider=secret_provider)
    assert "C:/sensitive" not in str(failure.value)
    assert "unsupported shape" in str(failure.value)

    # Restore only the public metadata and then corrupt a secret-bearing file.
    metadata.pop("private_key_path")
    enrollment.trust_file.write_text(json.dumps(metadata), encoding="utf-8")
    enrollment.hmac_key_file.write_bytes(b"not-a-valid-key")
    with pytest.raises(RunnerTrustError) as failure:
        load_local_enrollment(root, secret_provider=secret_provider)
    assert str(root) not in str(failure.value)
    assert "cryptographic material is invalid" in str(failure.value)
    with pytest.raises(RunnerTrustError):
        remove_local_enrollment(root, secret_provider=secret_provider)
    remove_local_enrollment(
        root,
        secret_provider=secret_provider,
        confirm_runner_id="bluefire-rust-runner.v1",
    )
    assert not root.exists()


def test_loading_refuses_duplicate_metadata_keys_and_unexpected_material(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    root = tmp_path / "trust"
    enrollment = create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    original = enrollment.trust_file.read_text(encoding="utf-8").strip()
    enrollment.trust_file.write_text(
        original[:-1] + ',"status":"active"}',
        encoding="utf-8",
    )
    with pytest.raises(RunnerTrustError, match="unavailable or invalid"):
        load_local_enrollment(root, secret_provider=secret_provider)

    enrollment.trust_file.write_text(original + "\n", encoding="utf-8")
    (root / "unexpected.txt").write_text("not trust material", encoding="utf-8")
    with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
        load_local_enrollment(root, secret_provider=secret_provider)


def test_expired_enrollment_can_be_inspected_revoked_and_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        validity_days=1,
        secret_provider=secret_provider,
    )
    future = datetime.now(timezone.utc) + timedelta(days=2)

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> FutureDateTime:
            return cls.fromtimestamp(future.timestamp(), tz=tz)

    monkeypatch.setattr(runner_trust, "datetime", FutureDateTime)
    with pytest.raises(RunnerTrustError, match="not currently valid"):
        load_local_enrollment(root, secret_provider=secret_provider)
    assert enrollment_status(root, secret_provider=secret_provider)["status"] == "expired"
    assert revoke_local_enrollment(root, secret_provider=secret_provider).status == "revoked"
    remove_local_enrollment(root, secret_provider=secret_provider)
    assert not root.exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows chmod does not expose POSIX owner bits")
def test_enrollment_files_and_directory_are_owner_private(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    enrollment = create_local_enrollment(
        tmp_path / "trust",
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    assert stat.S_IMODE(enrollment.root.stat().st_mode) == 0o700
    for item in enrollment.root.iterdir():
        assert stat.S_IMODE(item.stat().st_mode) == 0o600


def test_completed_creation_stage_without_authenticated_intent_is_preserved_and_refused(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    root = tmp_path / "trust"
    staging = tmp_path / ".trust.creating"
    create_local_enrollment(
        staging,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        validity_days=7,
        secret_provider=secret_provider,
    )

    staged_materials = {
        entry.name: entry.read_bytes() for entry in staging.iterdir() if entry.is_file()
    }
    with pytest.raises(RunnerTrustError, match="not authenticated"):
        create_local_enrollment(
            root,
            runner_id="bluefire-rust-runner.v1",
            client_id="bluefire-control-plane.v1",
            allowed_profile_ids=("profile.one",),
            validity_days=7,
            secret_provider=secret_provider,
        )

    assert not root.exists()
    assert staging.is_dir()
    assert {
        entry.name: entry.read_bytes() for entry in staging.iterdir() if entry.is_file()
    } == staged_materials
    assert not (tmp_path / ".trust.creation-intent.json").exists()


def test_creation_path_helper_is_pure_absolute_and_rejects_links(tmp_path: Path) -> None:
    root = tmp_path / "nested" / "trust"
    expected = tmp_path / "nested" / ".trust.creating"

    assert local_enrollment_creation_path(root) == expected
    assert local_enrollment_creation_path(root).is_absolute()
    assert not root.parent.exists()

    actual_parent = tmp_path / "actual"
    actual_parent.mkdir()
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(actual_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
        local_enrollment_creation_path(linked_parent / "trust")


def test_creation_stage_mismatch_and_partial_stage_fail_closed(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    mismatched_root = tmp_path / "mismatched"
    mismatched_stage = tmp_path / ".mismatched.creating"
    create_local_enrollment(
        mismatched_stage,
        runner_id="different-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    with pytest.raises(RunnerTrustError, match="not authenticated"):
        create_local_enrollment(
            mismatched_root,
            runner_id="bluefire-rust-runner.v1",
            client_id="bluefire-control-plane.v1",
            allowed_profile_ids=("profile.one",),
            secret_provider=secret_provider,
        )
    assert not mismatched_root.exists()
    assert mismatched_stage.is_dir()

    partial_root = tmp_path / "partial"
    partial_stage = tmp_path / ".partial.creating"
    partial_stage.mkdir()
    partial_material = partial_stage / "ca-cert.pem"
    partial_material.write_bytes(b"incomplete")
    with pytest.raises(RunnerTrustError, match="not authenticated"):
        create_local_enrollment(
            partial_root,
            runner_id="bluefire-rust-runner.v1",
            client_id="bluefire-control-plane.v1",
            allowed_profile_ids=("profile.one",),
            secret_provider=secret_provider,
        )
    assert not partial_root.exists()
    assert partial_material.read_bytes() == b"incomplete"


def test_completed_creation_stage_survives_publish_failure_and_resumes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    staging = tmp_path / ".trust.creating"
    original_rename = runner_trust.os.rename
    failed = False

    def interrupted_publish(source: Path, destination: Path) -> None:
        nonlocal failed
        if Path(source) == staging and Path(destination) == root and not failed:
            failed = True
            raise OSError("injected publication interruption")
        original_rename(source, destination)

    monkeypatch.setattr(runner_trust.os, "rename", interrupted_publish)
    with pytest.raises(RunnerTrustError, match="could not be created"):
        create_local_enrollment(
            root,
            runner_id="bluefire-rust-runner.v1",
            client_id="bluefire-control-plane.v1",
            allowed_profile_ids=("profile.one",),
            secret_provider=secret_provider,
        )
    monkeypatch.setattr(runner_trust.os, "rename", original_rename)

    assert not root.exists()
    assert {entry.name for entry in staging.iterdir()} == EXPECTED_FILES
    enrollment = create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    assert enrollment.root == root.resolve()
    assert not staging.exists()


def test_stale_revocation_temporary_is_recoverable_but_links_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    temporary = root / ".trust.json.tmp"
    temporary.write_bytes(b"interrupted metadata replacement")

    assert load_local_enrollment(root, secret_provider=secret_provider).status == "active"
    assert revoke_local_enrollment(root, secret_provider=secret_provider).status == "revoked"
    assert not temporary.exists()

    victim = tmp_path / "victim.tmp"
    victim.write_bytes(b"unsafe replacement")
    os.link(victim, temporary)
    with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
        load_local_enrollment(root, require_active=False, secret_provider=secret_provider)
    assert temporary.read_bytes() == b"unsafe replacement"
    assert victim.read_bytes() == b"unsafe replacement"


def test_revocation_intent_recovers_an_interrupted_pinned_metadata_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    intent = tmp_path / ".trust.revocation-intent.json"
    original_write = runner_trust._PinnedRegularUpdate.write
    failed = False

    def interrupt_write(
        target: runner_trust._PinnedRegularUpdate,
        payload: bytes,
    ) -> None:
        nonlocal failed
        if not failed:
            failed = True
            os.lseek(target.descriptor, 0, os.SEEK_SET)
            os.ftruncate(target.descriptor, 0)
            os.write(target.descriptor, payload[:17])
            os.fsync(target.descriptor)
            raise OSError("injected crash during pinned metadata write")
        original_write(target, payload)

    monkeypatch.setattr(runner_trust._PinnedRegularUpdate, "write", interrupt_write)
    with pytest.raises(RunnerTrustError, match="could not be revoked"):
        revoke_local_enrollment(root, secret_provider=secret_provider)

    assert failed
    assert intent.is_file()
    with pytest.raises(RunnerTrustError, match="revocation must be recovered"):
        load_local_enrollment(root, require_active=False, secret_provider=secret_provider)

    authenticated_intent = intent.read_bytes()
    envelope = json.loads(authenticated_intent)
    envelope["root_digest"] = "0" * 64
    intent.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(RunnerTrustError, match="intent is invalid"):
        revoke_local_enrollment(root, secret_provider=secret_provider)
    intent.write_bytes(authenticated_intent)

    monkeypatch.setattr(runner_trust._PinnedRegularUpdate, "write", original_write)
    enrollment = revoke_local_enrollment(root, secret_provider=secret_provider)
    assert enrollment.status == "revoked"
    assert not intent.exists()


def test_pinned_revocation_write_never_mutates_or_deletes_a_racing_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    target_path = root / "trust.json"
    parked = tmp_path / "parked-trust.json"
    victim = tmp_path / "victim.json"
    victim.write_bytes(b"victim must survive")
    victim_mode = stat.S_IMODE(victim.stat().st_mode)
    intent = tmp_path / ".trust.revocation-intent.json"
    original_write = runner_trust._PinnedRegularUpdate.write
    state = {"swapped": False, "blocked": False}

    def race_before_write(
        target: runner_trust._PinnedRegularUpdate,
        payload: bytes,
    ) -> None:
        try:
            target_path.rename(parked)
            os.link(victim, target_path)
            state["swapped"] = True
        except OSError:
            state["blocked"] = True
            if parked.exists() and not target_path.exists():
                parked.rename(target_path)
        original_write(target, payload)

    monkeypatch.setattr(runner_trust._PinnedRegularUpdate, "write", race_before_write)
    failure: RunnerTrustError | None = None
    enrollment = None
    try:
        enrollment = revoke_local_enrollment(root, secret_provider=secret_provider)
    except RunnerTrustError as error:
        failure = error

    assert state["swapped"] or state["blocked"]
    assert victim.read_bytes() == b"victim must survive"
    assert stat.S_IMODE(victim.stat().st_mode) == victim_mode
    if state["swapped"]:
        assert failure is not None
        assert target_path.samefile(victim)
        assert intent.is_file()
        target_path.unlink()
        parked.rename(target_path)
        monkeypatch.setattr(runner_trust._PinnedRegularUpdate, "write", original_write)
        enrollment = revoke_local_enrollment(root, secret_provider=secret_provider)
    else:
        assert failure is None

    assert enrollment is not None
    assert enrollment.status == "revoked"
    assert victim.read_bytes() == b"victim must survive"
    assert not intent.exists()


def test_confirmed_removal_resumes_after_identity_anchor_unlink_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    tombstone = tmp_path / ".trust.removing"
    original_unlink = runner_trust._PinnedDirectory.unlink
    state = {"failed": False}

    def interrupted_unlink(
        directory: runner_trust._PinnedDirectory, name: str, *, maximum: int
    ) -> None:
        if directory.path == tombstone and name == "server-cert.pem" and not state["failed"]:
            state["failed"] = True
            raise OSError("injected unlink interruption")
        original_unlink(directory, name, maximum=maximum)

    monkeypatch.setattr(runner_trust._PinnedDirectory, "unlink", interrupted_unlink)
    with pytest.raises(RunnerTrustError, match="could not be removed"):
        remove_local_enrollment(
            root,
            secret_provider=secret_provider,
            confirm_runner_id="bluefire-rust-runner.v1",
        )
    monkeypatch.setattr(runner_trust._PinnedDirectory, "unlink", original_unlink)

    assert not root.exists()
    assert tombstone.is_dir()
    assert (tombstone / "server-cert.pem").is_file()
    with pytest.raises(RunnerTrustError, match="confirmation does not match"):
        remove_local_enrollment(
            root,
            secret_provider=secret_provider,
            confirm_runner_id="different-runner.v1",
        )
    remove_local_enrollment(
        root,
        secret_provider=secret_provider,
        confirm_runner_id="bluefire-rust-runner.v1",
    )
    assert not tombstone.exists()


def test_confirmed_removal_resumes_after_empty_tombstone_rmdir_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    tombstone = tmp_path / ".trust.removing"
    original_remove = runner_trust._PinnedDirectory.remove
    failed = False

    def interrupted_remove(directory: runner_trust._PinnedDirectory) -> None:
        nonlocal failed
        if directory.path == tombstone and not failed:
            failed = True
            raise OSError("injected rmdir interruption")
        original_remove(directory)

    monkeypatch.setattr(runner_trust._PinnedDirectory, "remove", interrupted_remove)
    with pytest.raises(RunnerTrustError, match="could not be removed"):
        remove_local_enrollment(
            root,
            secret_provider=secret_provider,
            confirm_runner_id="bluefire-rust-runner.v1",
        )
    monkeypatch.setattr(runner_trust._PinnedDirectory, "remove", original_remove)

    assert tombstone.is_dir()
    assert not tuple(tombstone.iterdir())
    remove_local_enrollment(
        root,
        secret_provider=secret_provider,
        confirm_runner_id="bluefire-rust-runner.v1",
    )
    remove_local_enrollment(
        root,
        secret_provider=secret_provider,
        confirm_runner_id="bluefire-rust-runner.v1",
    )
    assert not tombstone.exists()


def test_removal_refuses_conflicting_or_foreign_tombstone_state(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    tombstone = tmp_path / ".trust.removing"
    tombstone.mkdir()
    with pytest.raises(RunnerTrustError, match="state is inconsistent"):
        remove_local_enrollment(
            root,
            secret_provider=secret_provider,
            confirm_runner_id="bluefire-rust-runner.v1",
        )
    assert root.is_dir()
    tombstone.rmdir()

    root.rename(tombstone)
    foreign = tombstone / "foreign.txt"
    foreign.write_text("do not remove", encoding="utf-8")
    with pytest.raises(RunnerTrustError, match="unexpected files"):
        remove_local_enrollment(
            root,
            secret_provider=secret_provider,
            confirm_runner_id="bluefire-rust-runner.v1",
        )
    assert foreign.read_text(encoding="utf-8") == "do not remove"


def test_confirmed_removal_recovers_partial_live_root_but_not_identityless_material(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    root = tmp_path / "trust"
    enrollment = create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    enrollment.client_certificate.unlink()
    remove_local_enrollment(
        root,
        secret_provider=secret_provider,
        confirm_runner_id="bluefire-rust-runner.v1",
    )
    assert not root.exists()

    identityless = tmp_path / "identityless"
    identityless.mkdir()
    protected = secret_provider.protect("unrelated-purpose", b"unrelated")
    material = identityless / "hmac.secret"
    material.write_bytes(protected)
    with pytest.raises(RunnerTrustError, match="confirmation does not match"):
        remove_local_enrollment(
            identityless,
            secret_provider=secret_provider,
            confirm_runner_id="bluefire-rust-runner.v1",
        )
    assert material.read_bytes() == protected


def test_removal_refuses_link_like_material_without_touching_the_tombstone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    tombstone = tmp_path / ".trust.removing"
    root.rename(tombstone)
    unsafe_material = tombstone / "client-cert.pem"
    victim = tmp_path / "victim.pem"
    victim.write_bytes(unsafe_material.read_bytes())
    unsafe_material.unlink()
    os.link(victim, unsafe_material)

    with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
        remove_local_enrollment(
            root,
            secret_provider=secret_provider,
            confirm_runner_id="bluefire-rust-runner.v1",
        )
    assert unsafe_material.is_file()
    assert victim.is_file()


def test_removal_refuses_a_path_through_a_linked_ancestor(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    actual_parent = tmp_path / "actual"
    actual_parent.mkdir()
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(actual_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    root = actual_parent / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )

    with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
        remove_local_enrollment(
            linked_parent / "trust",
            secret_provider=secret_provider,
            confirm_runner_id="bluefire-rust-runner.v1",
        )
    assert root.is_dir()


def test_authenticated_creation_intent_recovers_partial_stage_and_rejects_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    staging = tmp_path / ".trust.creating"
    intent = tmp_path / ".trust.creation-intent.json"
    original_write = runner_trust._write_certificate
    crashed = False

    def crash_after_first_write(path: Path, certificate: x509.Certificate) -> None:
        nonlocal crashed
        original_write(path, certificate)
        if path.parent == staging and not crashed:
            crashed = True
            raise SystemExit("injected process crash")

    monkeypatch.setattr(runner_trust, "_write_certificate", crash_after_first_write)
    with pytest.raises(SystemExit, match="injected process crash"):
        create_local_enrollment(
            root,
            runner_id="bluefire-rust-runner.v1",
            client_id="bluefire-control-plane.v1",
            allowed_profile_ids=("profile.one",),
            validity_days=7,
            secret_provider=secret_provider,
        )
    monkeypatch.setattr(runner_trust, "_write_certificate", original_write)

    assert intent.is_file()
    assert staging.is_dir()
    with pytest.raises(RunnerTrustError, match="recovery does not match"):
        create_local_enrollment(
            root,
            runner_id="bluefire-rust-runner.v1",
            client_id="bluefire-control-plane.v1",
            allowed_profile_ids=("profile.two",),
            validity_days=7,
            secret_provider=secret_provider,
        )
    assert staging.is_dir()

    enrollment = create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        validity_days=7,
        secret_provider=secret_provider,
    )
    assert enrollment.root == root.resolve()
    assert not staging.exists()
    assert not intent.exists()


def test_creation_refuses_pending_removal_and_intact_unconfirmed_removal_resumes(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    root = tmp_path / "trust"
    tombstone = tmp_path / ".trust.removing"

    def create(path: Path) -> None:
        create_local_enrollment(
            path,
            runner_id="bluefire-rust-runner.v1",
            client_id="bluefire-control-plane.v1",
            allowed_profile_ids=("profile.one",),
            secret_provider=secret_provider,
        )

    create(root)
    root.rename(tombstone)

    with pytest.raises(RunnerTrustError, match="removal must be recovered"):
        create(root)
    assert not root.exists()
    assert tombstone.is_dir()

    remove_local_enrollment(root, secret_provider=secret_provider)
    assert not tombstone.exists()
    assert not (tmp_path / ".trust.removal-intent.json").exists()


@pytest.mark.parametrize(
    ("corrupt_name", "valid_anchor"),
    (
        ("server-cert.pem", "trust.json"),
        ("trust.json", "server-cert.pem"),
    ),
)
def test_confirmed_removal_survives_exactly_one_valid_public_identity_anchor(
    tmp_path: Path,
    secret_provider: InMemorySecretProvider,
    corrupt_name: str,
    valid_anchor: str,
) -> None:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    (root / corrupt_name).write_bytes(b"corrupt identity anchor")
    assert (root / valid_anchor).is_file()

    remove_local_enrollment(
        root,
        secret_provider=secret_provider,
        confirm_runner_id="bluefire-rust-runner.v1",
    )

    assert not root.exists()
    assert not (tmp_path / ".trust.removing").exists()
    assert not (tmp_path / ".trust.removal-intent.json").exists()


def test_pinned_tombstone_cleanup_never_unlinks_through_a_swapped_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    tombstone = tmp_path / ".trust.removing"
    parked = tmp_path / "parked-trust"
    victim = tmp_path / "victim"
    victim.mkdir()
    sentinel = victim / "ca-cert.pem"
    sentinel.write_bytes(b"must survive")
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    original_unlink = runner_trust._PinnedDirectory.unlink
    state = {"swapped": False, "blocked": False}

    def swap_before_first_unlink(
        directory: runner_trust._PinnedDirectory, name: str, *, maximum: int
    ) -> None:
        if directory.path == tombstone and not any(state.values()):
            try:
                tombstone.rename(parked)
                tombstone.symlink_to(victim, target_is_directory=True)
                state["swapped"] = True
            except OSError:
                state["blocked"] = True
        original_unlink(directory, name, maximum=maximum)

    monkeypatch.setattr(runner_trust._PinnedDirectory, "unlink", swap_before_first_unlink)
    try:
        remove_local_enrollment(
            root,
            secret_provider=secret_provider,
            confirm_runner_id="bluefire-rust-runner.v1",
        )
    except RunnerTrustError:
        assert state["swapped"]
    finally:
        monkeypatch.setattr(runner_trust._PinnedDirectory, "unlink", original_unlink)

    assert state["swapped"] or state["blocked"]
    assert sentinel.read_bytes() == b"must survive"
    if state["swapped"]:
        tombstone.unlink()
        parked.rename(tombstone)
        remove_local_enrollment(
            root,
            secret_provider=secret_provider,
            confirm_runner_id="bluefire-rust-runner.v1",
        )


def test_material_reads_are_bounded_and_hardlinks_are_rejected_before_acl_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    enrollment = create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    original_metadata = enrollment.trust_file.read_bytes()
    with enrollment.trust_file.open("wb") as handle:
        handle.truncate(runner_trust._MAX_TRUST_BYTES + 1)
    with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
        load_local_enrollment(root, secret_provider=secret_provider)
    enrollment.trust_file.write_bytes(original_metadata)

    victim = tmp_path / "outside.secret"
    victim.write_bytes(enrollment.hmac_key_file.read_bytes())
    enrollment.hmac_key_file.unlink()
    os.link(victim, enrollment.hmac_key_file)
    original_owner_private = runner_trust._owner_private
    original_fchmod = runner_trust._posix_fchmod
    touched: list[Path] = []
    hardlink_chmod_called = False
    victim_identity = (victim.stat().st_dev, victim.stat().st_ino)

    def record_owner_private(path: Path, *, directory: bool) -> None:
        touched.append(path)
        original_owner_private(path, directory=directory)

    def record_fchmod(descriptor: int, mode: int) -> None:
        nonlocal hardlink_chmod_called
        details = os.fstat(descriptor)
        if (details.st_dev, details.st_ino) == victim_identity:
            hardlink_chmod_called = True
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(runner_trust, "_owner_private", record_owner_private)
    monkeypatch.setattr(runner_trust, "_posix_fchmod", record_fchmod)
    with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
        load_local_enrollment(root, secret_provider=secret_provider)
    assert enrollment.hmac_key_file not in touched
    assert not hardlink_chmod_called
    assert victim.read_bytes() == enrollment.hmac_key_file.read_bytes()


def test_transition_lock_serializes_across_processes(tmp_path: Path) -> None:
    destination = tmp_path / "trust"
    ready = tmp_path / "ready"
    release = tmp_path / "release"
    code = """
import sys
import time
from pathlib import Path
import bluefire.runner_trust as trust
destination, ready, release = map(Path, sys.argv[1:])
with trust._enrollment_transition_lock(destination):
    ready.write_text('ready', encoding='utf-8')
    while not release.exists():
        time.sleep(0.02)
"""
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", code, str(destination), str(ready), str(release)],
        cwd=Path.cwd(),
    )
    acquired = threading.Event()

    def acquire_in_parent() -> None:
        with runner_trust._enrollment_transition_lock(destination):
            acquired.set()

    try:
        deadline = time.monotonic() + 20
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.is_file()
        contender = threading.Thread(target=acquire_in_parent, daemon=True)
        contender.start()
        assert not acquired.wait(0.25)
        release.write_text("release", encoding="utf-8")
        assert acquired.wait(20)
        contender.join(timeout=5)
        assert not contender.is_alive()
        assert process.wait(timeout=20) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_removal_journal_recovers_crashes_at_each_destructive_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    def create(path: Path) -> None:
        create_local_enrollment(
            path,
            runner_id="bluefire-rust-runner.v1",
            client_id="bluefire-control-plane.v1",
            allowed_profile_ids=("profile.one",),
            secret_provider=secret_provider,
        )

    before_rename = tmp_path / "before-rename"
    create(before_rename)
    before_tombstone = tmp_path / ".before-rename.removing"
    before_intent = tmp_path / ".before-rename.removal-intent.json"
    original_rename = runner_trust.os.rename
    failed_rename = False

    def interrupt_before_rename(source: Path, destination: Path) -> None:
        nonlocal failed_rename
        if source == before_rename and destination == before_tombstone and not failed_rename:
            failed_rename = True
            raise OSError("injected crash after journal write")
        original_rename(source, destination)

    monkeypatch.setattr(runner_trust.os, "rename", interrupt_before_rename)
    with pytest.raises(RunnerTrustError, match="could not be removed"):
        remove_local_enrollment(before_rename, secret_provider=secret_provider)
    monkeypatch.setattr(runner_trust.os, "rename", original_rename)
    assert before_rename.is_dir()
    assert before_intent.is_file()
    remove_local_enrollment(before_rename, secret_provider=secret_provider)
    assert not before_rename.exists()
    assert not before_intent.exists()

    after_rename = tmp_path / "after-rename"
    create(after_rename)
    after_tombstone = tmp_path / ".after-rename.removing"
    after_intent = tmp_path / ".after-rename.removal-intent.json"
    original_cleanup = runner_trust._cleanup_removal_tombstone
    failed_cleanup = False

    def interrupt_before_first_unlink(
        tombstone: Path,
        *,
        runner_id: str,
        directory_identity: tuple[int, int],
    ) -> None:
        nonlocal failed_cleanup
        if not failed_cleanup:
            failed_cleanup = True
            raise OSError("injected crash after tombstone rename")
        original_cleanup(
            tombstone,
            runner_id=runner_id,
            directory_identity=directory_identity,
        )

    monkeypatch.setattr(runner_trust, "_cleanup_removal_tombstone", interrupt_before_first_unlink)
    with pytest.raises(RunnerTrustError, match="could not be removed"):
        remove_local_enrollment(after_rename, secret_provider=secret_provider)
    monkeypatch.setattr(runner_trust, "_cleanup_removal_tombstone", original_cleanup)
    assert not after_rename.exists()
    assert after_tombstone.is_dir()
    assert after_intent.is_file()
    remove_local_enrollment(after_rename, secret_provider=secret_provider)
    assert not after_tombstone.exists()
    assert not after_intent.exists()

    after_tombstone_removal = tmp_path / "after-tombstone-removal"
    create(after_tombstone_removal)
    final_tombstone = tmp_path / ".after-tombstone-removal.removing"
    final_intent = tmp_path / ".after-tombstone-removal.removal-intent.json"
    original_intent_unlink = runner_trust._unlink_transition_file
    failed_intent_unlink = False

    def interrupt_final_journal_unlink(path: Path) -> None:
        nonlocal failed_intent_unlink
        if path == final_intent and not failed_intent_unlink:
            failed_intent_unlink = True
            raise OSError("injected crash after tombstone removal")
        original_intent_unlink(path)

    monkeypatch.setattr(runner_trust, "_unlink_transition_file", interrupt_final_journal_unlink)
    with pytest.raises(RunnerTrustError, match="could not be removed"):
        remove_local_enrollment(after_tombstone_removal, secret_provider=secret_provider)
    monkeypatch.setattr(runner_trust, "_unlink_transition_file", original_intent_unlink)
    assert not after_tombstone_removal.exists()
    assert not final_tombstone.exists()
    assert final_intent.is_file()
    remove_local_enrollment(after_tombstone_removal, secret_provider=secret_provider)
    assert not final_intent.exists()


def test_oversized_sparse_private_material_is_rejected_without_allocation(
    tmp_path: Path, secret_provider: InMemorySecretProvider
) -> None:
    root = tmp_path / "trust"
    enrollment = create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    for name in ("server-key.pem", "hmac.secret", "server-cert.pem"):
        material = root / name
        original = material.read_bytes()
        with material.open("wb") as handle:
            handle.truncate(runner_trust._MAX_MATERIAL_BYTES + 1)
        with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
            load_local_enrollment(root, secret_provider=secret_provider)
        material.write_bytes(original)
    assert (
        load_local_enrollment(root, secret_provider=secret_provider).runner_id
        == enrollment.runner_id
    )


def test_memory_error_and_short_read_are_sanitized_as_trust_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("profile.one",),
        secret_provider=secret_provider,
    )
    original_json_loads = runner_trust.json.loads
    original_certificate_loader = runner_trust.x509.load_pem_x509_certificate
    original_read = runner_trust.os.read

    def json_memory_failure(*_args: object, **_kwargs: object) -> object:
        raise MemoryError("injected JSON allocation failure")

    monkeypatch.setattr(runner_trust.json, "loads", json_memory_failure)
    with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
        load_local_enrollment(root, secret_provider=secret_provider)
    monkeypatch.setattr(runner_trust.json, "loads", original_json_loads)

    def certificate_memory_failure(_payload: bytes) -> object:
        raise MemoryError("injected certificate allocation failure")

    monkeypatch.setattr(
        runner_trust.x509,
        "load_pem_x509_certificate",
        certificate_memory_failure,
    )
    with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
        load_local_enrollment(root, secret_provider=secret_provider)
    monkeypatch.setattr(
        runner_trust.x509,
        "load_pem_x509_certificate",
        original_certificate_loader,
    )

    def memory_failure(_descriptor: int, _count: int) -> bytes:
        raise MemoryError("injected allocation failure")

    monkeypatch.setattr(runner_trust.os, "read", memory_failure)
    with pytest.raises(RunnerTrustError, match="size limit"):
        load_local_enrollment(root, secret_provider=secret_provider)

    state = {"returned": False}

    def short_read(descriptor: int, count: int) -> bytes:
        if not state["returned"]:
            state["returned"] = True
            return original_read(descriptor, min(count, 8))
        return b""

    monkeypatch.setattr(runner_trust.os, "read", short_read)
    with pytest.raises(RunnerTrustError, match="unavailable or unsafe"):
        load_local_enrollment(root, secret_provider=secret_provider)


def test_removal_memory_errors_are_sanitized_at_public_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret_provider: InMemorySecretProvider,
) -> None:
    def corrupt_anchor(_path: Path, _maximum: int) -> bytes:
        return b"corrupt identity anchor"

    def certificate_memory_failure(_payload: bytes) -> object:
        raise MemoryError("injected certificate allocation failure")

    monkeypatch.setattr(runner_trust, "_bounded_regular_read", corrupt_anchor)
    monkeypatch.setattr(
        runner_trust.x509,
        "load_pem_x509_certificate",
        certificate_memory_failure,
    )
    assert runner_trust._public_removal_identities(tmp_path / "synthetic") == set()

    def removal_memory_failure(*_args: object, **_kwargs: object) -> None:
        raise MemoryError("injected removal allocation failure")

    monkeypatch.setattr(
        runner_trust,
        "_remove_local_enrollment_locked",
        removal_memory_failure,
    )
    with pytest.raises(RunnerTrustError, match="could not be removed"):
        remove_local_enrollment(
            tmp_path / "missing-trust",
            secret_provider=secret_provider,
            confirm_runner_id="bluefire-rust-runner.v1",
        )


def test_write_acl_and_payload_stay_bound_to_created_file_during_parent_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "parent"
    parked = tmp_path / "parked"
    victim = tmp_path / "victim"
    parent.mkdir()
    victim.mkdir()
    sentinel = victim / "material.secret"
    sentinel.write_bytes(b"victim")
    original_write = runner_trust._write_descriptor_all
    state = {"swapped": False, "blocked": False}

    def swap_after_descriptor_write(descriptor: int, payload: bytes) -> None:
        original_write(descriptor, payload)
        try:
            parent.rename(parked)
            parent.symlink_to(victim, target_is_directory=True)
            state["swapped"] = True
        except OSError:
            state["blocked"] = True

    monkeypatch.setattr(runner_trust, "_write_descriptor_all", swap_after_descriptor_write)
    runner_trust._write_secret(parent / "material.secret", b"created")

    assert state["swapped"] or state["blocked"]
    assert sentinel.read_bytes() == b"victim"
    if state["swapped"]:
        assert (parked / "material.secret").read_bytes() == b"created"
        parent.unlink()
        parked.rename(parent)
    else:
        assert (parent / "material.secret").read_bytes() == b"created"
