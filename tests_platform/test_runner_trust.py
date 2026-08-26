from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone
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
        def now(cls, tz: timezone | None = None) -> FutureDateTime:
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
