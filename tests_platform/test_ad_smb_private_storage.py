"""Actual private filesystem and role certificates; no listener or AD effects."""

import os
from datetime import datetime, timedelta

import pytest

from bluefire import ad_smb_channel_trust as channel_trust
from bluefire import ad_smb_credentials as credentials
from bluefire import ad_smb_installed as installed
from bluefire import ad_smb_receiver_entry as receiver_entry
from bluefire import runner_trust as trust
from bluefire import windows_owner_acl as acl
from bluefire.ad_smb_contract import AdSmbError, AdSmbScope
from bluefire.ad_smb_private_storage import private_root
from bluefire.util import canonical_json_bytes
from tests_platform.test_ad_smb_channel_trust import bundle as bundle
from tests_platform.test_ad_smb_channel_trust import channel as channel
from tests_platform.test_ad_smb_contract import NOW
from tests_platform.test_ad_smb_credentials import bound as bound
from tests_platform.test_ad_smb_installed import configuration
from tests_platform.test_ad_smb_receiver import original


def prepared(tmp_path, values):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    with trust._PinnedDirectory(root, private=True) as directory:
        for name, payload in values.items():
            directory.create(name, payload)
    return root


def stamps(root):
    return {
        path.name: (path.stat().st_mode, path.stat().st_ctime_ns)
        for path in (root, *root.iterdir())
    }


def forbid_repairs(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("AD inspection attempted permission repair")

    for name in (
        "apply_owner_private_acl",
        "apply_owner_private_acl_handle",
        "apply_owner_private_acl_path",
    ):
        monkeypatch.setattr(acl, name, forbidden)
    monkeypatch.setattr(trust, "_posix_fchmod", forbidden)


@pytest.mark.parametrize("side", ["server", "client"])
def test_actual_role_bundle_loads_without_peer_key_or_permission_repair(
    bundle, tmp_path, monkeypatch, side
):
    checked, prepare, values, calls, provider = bundle
    prepare(side)
    root = prepared(tmp_path, values)
    monkeypatch.setattr(channel_trust, "_PinnedDirectory", trust._PinnedDirectory)
    monkeypatch.setattr(channel_trust, "private_root", private_root)
    before = stamps(root)
    forbid_repairs(monkeypatch)
    enrollment = channel_trust.load_channel_enrollment(
        root, channel=checked, side=side, secret_provider=provider
    )
    assert enrollment.verify_permissions_only is True
    assert len(enrollment.hmac_key()) == 32
    assert stamps(root) == before
    assert enrollment.transport_identity_scope() == {"ad_smb_channel_digest": checked.digest}
    opposite = "client" if side == "server" else "server"
    assert not (root / (opposite + "-key.pem")).exists()


@pytest.mark.parametrize("kind", ["peer_key", "extra", "hardlink", "permissions"])
def test_actual_role_bundle_refuses_unsafe_files_without_repair(
    bundle, tmp_path, monkeypatch, kind
):
    checked, prepare, values, calls, provider = bundle
    prepare("server")
    root = prepared(tmp_path, values)
    if kind in {"peer_key", "extra"}:
        with trust._PinnedDirectory(root, private=True) as directory:
            directory.create("client-key.pem" if kind == "peer_key" else "extra", b"synthetic")
    elif kind == "hardlink":
        os.link(root / "server-key.pem", tmp_path / "alias")
    else:
        path = root / "trust.json"
        payload = path.read_bytes()
        path.unlink()
        path.write_bytes(payload)
        if os.name != "nt":
            path.chmod(0o644)
    monkeypatch.setattr(channel_trust, "_PinnedDirectory", trust._PinnedDirectory)
    monkeypatch.setattr(channel_trust, "private_root", private_root)
    before = stamps(root)
    forbid_repairs(monkeypatch)
    with pytest.raises(trust.RunnerTrustError):
        channel_trust.load_channel_enrollment(
            root, channel=checked, side="server", secret_provider=provider
        )
    assert stamps(root) == before


def test_actual_credential_directory_retains_exact_inventory_without_decrypting(
    bound, tmp_path, monkeypatch
):
    binding, packet, provider, row, blobs = bound
    root = prepared(tmp_path, blobs)
    monkeypatch.setattr(credentials, "_PinnedDirectory", trust._PinnedDirectory)
    monkeypatch.setattr(credentials, "private_root", private_root)
    monkeypatch.setattr(
        provider, "unprotect", lambda *_: pytest.fail("metadata inspection decrypted a credential")
    )
    before = stamps(root)
    forbid_repairs(monkeypatch)
    loaded = credentials.load_credential_binding(
        root,
        scope=binding._scope,
        channel=binding._channel,
        expected_digest=binding.digest,
        secret_provider=provider,
    )
    assert loaded.digest == binding.digest
    assert loaded.reader_binding("probe") == binding.reader_binding("probe")
    assert stamps(root) == before


@pytest.mark.parametrize("extra", [False, True])
def test_actual_controller_configuration_uses_its_own_file_contract(tmp_path, monkeypatch, extra):
    value, _, _ = configuration(tmp_path)
    files = {
        "controller.json": canonical_json_bytes(
            {"schema_version": installed.CONFIG_SCHEMA, "environments": [value.to_dict()]}
        )
    }
    if extra:
        files["unreviewed.json"] = b"{}"
    root = prepared(tmp_path, files)
    before = stamps(root)
    forbid_repairs(monkeypatch)
    if extra:
        with pytest.raises(AdSmbError):
            installed.load_installed(root)
    else:
        loaded = installed.load_installed(root)
        assert len(loaded) == 1 and loaded[0].public == value.public
    assert stamps(root) == before


def test_role_files_never_become_an_ordinary_runner_enrollment(tmp_path):
    root = prepared(tmp_path, {"controller.json": b"{}"})
    assert private_root(root) == root
    with pytest.raises(trust.RunnerTrustError):
        trust._validated_enrollment_root(root, verify_permissions_only=True)


@pytest.mark.parametrize("mutation", [None, "extra", "unsafe_child", "child_file"])
def test_actual_receiver_configuration_has_its_own_private_layout(tmp_path, monkeypatch, mutation):
    task, channel = original()
    scope = AdSmbScope.from_mapping(task["manifest"]["params"]["ad_smb_request"]["scope"])
    row = {
        "schema_version": "bluefire.ad-smb-receiver-config.v1",
        "scope": scope.to_dict(),
        "channel": channel.to_dict(),
        "profile": task["profile"],
        "runner_binary": str(tmp_path / "not-launched.exe"),
        "credential_binding_digest": None,
    }
    root = prepared(tmp_path, {"receiver.json": canonical_json_bytes(row)})
    for name in ("enrollment", "credentials", ".bluefire-runner-results"):
        child = root / name
        if mutation == "child_file" and name == "enrollment":
            with trust._PinnedDirectory(root, private=True) as directory:
                directory.create(name, b"not a directory")
        else:
            child.mkdir(mode=0o700)
            with trust._PinnedDirectory(child, private=True):
                pass
    if mutation == "extra":
        with trust._PinnedDirectory(root, private=True) as directory:
            directory.create("unknown.json", b"{}")
    elif mutation == "unsafe_child":
        child = root / "enrollment"
        child.rmdir()
        child.mkdir(mode=0o755)
        if os.name != "nt":
            child.chmod(0o755)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW + timedelta(seconds=2)

    monkeypatch.setattr(receiver_entry, "datetime", Clock)
    before = stamps(root)
    forbid_repairs(monkeypatch)
    if mutation is not None:
        with pytest.raises((AdSmbError, trust.RunnerTrustError)):
            receiver_entry._configuration(root)
    else:
        parsed, actual_scope, actual_channel = receiver_entry._configuration(root)
        assert parsed == row
        assert actual_scope.digest == scope.digest and actual_channel.digest == channel.digest
    assert stamps(root) == before


def test_actual_work_root_accepts_existing_outputs_without_tls_material(tmp_path, monkeypatch):
    root = prepared(tmp_path, {"operation-result.json": b"{}"})
    before = stamps(root)
    forbid_repairs(monkeypatch)
    assert private_root(root) == root
    with trust._PinnedDirectory(root, private=True, verify_permissions_only=True) as directory:
        assert directory.read("operation-result.json", maximum=16) == b"{}"
    assert stamps(root) == before


def test_private_root_never_creates_missing_storage(tmp_path, monkeypatch):
    root = tmp_path / "missing"
    forbid_repairs(monkeypatch)
    with pytest.raises(trust.RunnerTrustError):
        private_root(root)
    assert not root.exists()
