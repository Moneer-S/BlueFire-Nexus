"""In-memory synthetic protected blobs; no DPAPI or host credential reads."""

import struct
from copy import deepcopy
from datetime import timedelta
from pathlib import Path

import pytest

from bluefire import ad_smb_credentials as credentials
from bluefire import ad_smb_worker_wire as wire
from bluefire.ad_smb_contract import AdSmbError, AdSmbScope
from bluefire.secret_store import InMemorySecretProvider
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ad_smb_contract import NOW
from tests_platform.test_ad_smb_worker_wire import fixture, rebind_context


def private_payload(upn=b"reader@example.test", password="synthetic fixture"):
    raw = password.encode("utf-16-le")
    return bytearray(
        b"BFADCRD1" + struct.pack("<H", len(upn)) + upn + struct.pack("<H", len(raw) // 2) + raw
    )


@pytest.fixture
def bound(monkeypatch):
    context, channel = fixture("baseline")
    scope = AdSmbScope.from_mapping(context["manifest"]["params"]["ad_smb_request"]["scope"])
    provider = InMemorySecretProvider()
    row = {
        "schema_version": "bluefire.ad-smb-credentials.v1",
        "scope_digest": scope.digest,
        "channel_digest": channel.digest,
        "client_host_id": scope.to_dict()["hosts"]["client"]["host_id"],
        "secret_provider": provider.provider_id,
        "readers": {},
    }
    blobs = {}
    for reader in ("probe", "legitimate"):
        upn = reader.encode("ascii") + b"@example.test"
        principal = scope.to_dict()["principals"][reader]
        item = {
            key: principal[key] for key in ("sid", "credential_handle", "identity_receipt_digest")
        }
        item["upn_sha256"] = credentials._sha(upn)
        raw = provider.protect(
            credentials._purpose(channel, reader, item), bytes(private_payload(upn))
        )
        row["readers"][reader] = {**item, "protected_sha256": credentials._sha(raw)}
        blobs[reader + ".secret"] = raw
    blobs["credentials.json"] = canonical_json_bytes(row)

    class Storage:
        def __init__(self, _root, *, private, verify_permissions_only):
            assert private is True and verify_permissions_only is True

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def names(self, *, maximum):
            assert maximum == 4
            return tuple(blobs)

        def read(self, name, *, maximum):
            assert len(blobs[name]) <= maximum
            return blobs[name]

    monkeypatch.setattr(credentials, "_PinnedDirectory", Storage)
    monkeypatch.setattr(credentials, "private_root", lambda path: Path(path))
    monkeypatch.setattr(type(channel), "assert_current", lambda self, *args: None)
    binding = credentials.load_credential_binding(
        Path("synthetic"),
        scope=scope,
        channel=channel,
        expected_digest=content_hash(row),
        secret_provider=provider,
    )
    binding_digest, upn_digest = binding.reader_binding("probe")
    context = rebind_context(context, principal_binding_digest=binding_digest)
    packet = wire.prepare_packet(
        context,
        channel,
        challenge="a" * 64,
        credential_binding_digest=binding_digest,
        expected_upn_sha256=upn_digest,
        prior_local_authentication_ids=[],
        clock=NOW + timedelta(seconds=1),
    )
    return binding, packet, provider, row, blobs


def test_only_selected_reader_decrypted_once_after_explicit_use(bound, monkeypatch):
    binding, packet, provider, _, _ = bound
    original, calls = provider.unprotect, []

    def unprotect(purpose, raw):
        calls.append(purpose)
        return original(purpose, raw)

    monkeypatch.setattr(provider, "unprotect", unprotect)
    once = binding.one_use(packet)
    assert calls == []
    raw = once.begin()
    assert raw[4:12] == b"BFADBEG1" and raw[76] == 1
    assert len(calls) == 1 and ":probe:" in calls[0]
    assert b"probe@example.test" in raw
    assert "reader@example" not in repr(once)
    raw[:] = b"\0" * len(raw)
    with pytest.raises(AdSmbError):
        once.begin()
    assert len(calls) == 1


@pytest.mark.parametrize(
    "mutation", ["extra_file", "changed_cipher", "changed_sid", "extra_field", "member"]
)
def test_binding_mutations_refuse_before_secret_resolution(bound, monkeypatch, mutation):
    binding, packet, provider, row, blobs = bound
    monkeypatch.setattr(provider, "unprotect", lambda *_: pytest.fail("must not decrypt"))
    if mutation == "extra_file":
        blobs["controller.secret"] = b"forbidden"
    elif mutation == "changed_cipher":
        blobs["probe.secret"] += b"changed"
    elif mutation == "changed_sid":
        row["readers"]["probe"]["sid"] += "1"
        blobs["credentials.json"] = canonical_json_bytes(row)
    elif mutation == "extra_field":
        row["readers"]["probe"]["raw"] = "must not leak"
        blobs["credentials.json"] = canonical_json_bytes(row)
    else:
        changed = packet.to_dict()
        changed["host_role"] = "member"
        packet = wire.WorkerPacket(canonical_json_bytes(changed))
    with pytest.raises(AdSmbError) as error:
        binding.one_use(packet).begin()
    assert "must not leak" not in str(error.value)


@pytest.mark.parametrize(
    "payload",
    [
        bytearray(),
        bytearray(b"BFADCRD1"),
        private_payload(b"no-domain"),
        private_payload(b"r\0@example.test"),
        private_payload(b"r@a@b"),
        private_payload(b"Reader@example.test"),
        private_payload(b"reader@EXAMPLE.test"),
        private_payload(b"reader@127.0.0.1"),
        private_payload(b"reader@-bad.test"),
        private_payload(b"r" * 65 + b"@example.test"),
        private_payload(b"r\xc3\xa9@example.test"),
        private_payload(password=""),
        private_payload(password="a\0b"),
        private_payload(password="a" * 257),
        private_payload() + b"extra",
    ],
)
def test_malformed_private_payload_has_sanitized_failure(payload):
    with pytest.raises(AdSmbError) as error:
        credentials._private_payload(payload, credentials._sha(b"reader@example.test"))
    assert "reader@example" not in str(error.value) + repr(error.value)


def test_upn_digest_mismatch_and_storage_change_during_resolution(bound, monkeypatch):
    binding, packet, provider, row, blobs = bound
    original = provider.unprotect

    def changed(purpose, opaque):
        private = original(purpose, opaque)
        replacement = deepcopy(row)
        replacement["readers"]["legitimate"]["upn_sha256"] = "sha256:" + "f" * 64
        blobs["credentials.json"] = canonical_json_bytes(replacement)
        return private

    monkeypatch.setattr(provider, "unprotect", changed)
    once = binding.one_use(packet)
    with pytest.raises(AdSmbError):
        once.begin()
    with pytest.raises(AdSmbError):
        once.begin()


def test_unprotect_errors_never_escape_with_secret_details(bound, monkeypatch):
    binding, packet, provider, _, _ = bound

    def fail(*_):
        raise OSError("password=synthetic-sensitive-error")

    monkeypatch.setattr(provider, "unprotect", fail)
    with pytest.raises(AdSmbError) as error:
        binding.one_use(packet).begin()
    assert "synthetic-sensitive" not in str(error.value) + repr(error.value)


def test_duplicate_upn_binding_refuses_before_any_decryption(bound, monkeypatch):
    binding, packet, provider, row, blobs = bound
    row["readers"]["legitimate"]["upn_sha256"] = row["readers"]["probe"]["upn_sha256"]
    blobs["credentials.json"] = canonical_json_bytes(row)
    monkeypatch.setattr(provider, "unprotect", lambda *_: pytest.fail("must not decrypt"))
    with pytest.raises(AdSmbError):
        binding.one_use(packet).begin()
