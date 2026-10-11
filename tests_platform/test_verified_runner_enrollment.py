from __future__ import annotations

import os

import pytest

from bluefire import runner_trust as trust
from bluefire import windows_owner_acl as acl
from bluefire.secret_store import InMemorySecretProvider


@pytest.fixture
def enrollment(tmp_path):
    return trust.create_local_enrollment(
        tmp_path / "enrollment",
        runner_id="verify-runner",
        client_id="verify-client",
        allowed_profile_ids=["verify-profile"],
        secret_provider=InMemorySecretProvider(),
    )


def stamps(root):
    return {p.name: (p.stat().st_ctime_ns, p.stat().st_mode) for p in (root, *root.iterdir())}


def test_full_enrollment_verification_and_secrets_do_not_repair_permissions(
    enrollment, monkeypatch
):
    before = stamps(enrollment.root)

    def forbidden(*args, **kwargs):
        pytest.fail("verification-only enrollment performed permission maintenance")

    for name in (
        "apply_owner_private_acl",
        "apply_owner_private_acl_handle",
        "apply_owner_private_acl_path",
    ):
        monkeypatch.setattr(acl, name, forbidden)
    monkeypatch.setattr(trust, "_posix_fchmod", forbidden)
    current = trust.load_local_enrollment(
        enrollment.root, secret_provider=enrollment.secret_provider, verify_permissions_only=True
    )
    assert current.metadata == enrollment.metadata
    assert len(current.hmac_key()) == 32
    assert current.server_key_password() and current.client_key_password()
    assert stamps(enrollment.root) == before


def test_verification_refuses_unsafe_permissions_without_repair_and_default_is_unchanged(
    enrollment,
):
    path = enrollment.root / "trust.json"
    payload = path.read_bytes()
    path.unlink()
    path.write_bytes(payload)
    if os.name != "nt":
        path.chmod(0o644)
    before = stamps(enrollment.root)
    with pytest.raises(trust.RunnerTrustError):
        trust.load_local_enrollment(
            enrollment.root,
            secret_provider=enrollment.secret_provider,
            verify_permissions_only=True,
        )
    assert stamps(enrollment.root) == before
    normal = trust.load_local_enrollment(
        enrollment.root, secret_provider=enrollment.secret_provider
    )
    assert normal.metadata == enrollment.metadata and normal.verify_permissions_only is False
    checked = trust.load_local_enrollment(
        enrollment.root, secret_provider=enrollment.secret_provider, verify_permissions_only=True
    )
    assert checked.metadata == enrollment.metadata


@pytest.mark.parametrize("kind", ["extra", "crypto"])
def test_verification_keeps_complete_inventory_and_crypto_validation(enrollment, kind):
    with trust._PinnedDirectory(enrollment.root, private=True) as directory:
        if kind == "extra":
            directory.create("foreign.json", b"{}")
        else:
            directory.unlink("ca-cert.pem", maximum=65536)
            directory.create("ca-cert.pem", b"not a certificate")
    with pytest.raises(trust.RunnerTrustError):
        trust.load_local_enrollment(
            enrollment.root,
            secret_provider=enrollment.secret_provider,
            verify_permissions_only=True,
        )


@pytest.mark.parametrize("value", [None, 0, 1, "true"])
def test_enrollment_permission_mode_is_closed(enrollment, value):
    with pytest.raises(trust.RunnerTrustError, match="verification mode"):
        trust.load_local_enrollment(
            enrollment.root,
            secret_provider=enrollment.secret_provider,
            verify_permissions_only=value,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows handle access flags")
def test_verified_enrollment_does_not_request_write_dac(enrollment, monkeypatch):
    original = trust._windows_open_pinned
    modes = []

    def opened(path, **kwargs):
        modes.append(kwargs.get("write_dac", False))
        return original(path, **kwargs)

    monkeypatch.setattr(trust, "_windows_open_pinned", opened)
    verified = trust.load_local_enrollment(
        enrollment.root, secret_provider=enrollment.secret_provider, verify_permissions_only=True
    )
    verified.hmac_key()
    assert modes and not any(modes)
