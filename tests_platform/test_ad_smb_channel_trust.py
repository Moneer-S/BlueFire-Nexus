"""In-memory certificate/opaque-provider tests, not host enrollment or TLS proof."""

import ipaddress
import json
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from bluefire import ad_smb_channel_trust as trust
from bluefire.ad_smb_channel import AdSmbHostChannel
from bluefire.ad_smb_contract import AdSmbScope
from bluefire.runner_trust import RunnerTrustError, certificate_fingerprint
from bluefire.secret_store import SecretStoreError
from bluefire.util import canonical_json_bytes
from tests_platform.test_ad_smb_channel import channel as _channel
from tests_platform.test_ad_smb_channel import channel_row
from tests_platform.test_ad_smb_contract import NOW, scope_row

PASSWORD = b"synthetic-test-only-key-password00"


@pytest.fixture
def channel(monkeypatch):
    return _channel.__wrapped__(monkeypatch)


def certificate(key, name, issuer, issuer_key, *, ca=False, side=None, address=None):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=1))
        .not_valid_after(NOW + timedelta(hours=3))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if side:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    (
                        ExtendedKeyUsageOID.SERVER_AUTH
                        if side == "server"
                        else ExtendedKeyUsageOID.CLIENT_AUTH
                    )
                ]
            ),
            critical=False,
        )
    if address:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address(address))]),
            critical=False,
        )
    return builder.sign(issuer_key or key, hashes.SHA256())


@pytest.fixture
def bundle(channel, monkeypatch):
    keys = {role: ec.generate_private_key(ec.SECP256R1()) for role in ("ca", "server", "client")}
    ca = certificate(keys["ca"], "synthetic-ca", None, None, ca=True)
    server = certificate(
        keys["server"], "ad-member", ca.subject, keys["ca"], side="server", address="10.44.0.2"
    )
    client = certificate(keys["client"], "ad-controller", ca.subject, keys["ca"], side="client")
    row = channel_row()
    for role, cert in (("ca", ca), ("server", server), ("client", client)):
        row[role + "_fingerprint"] = certificate_fingerprint(cert)
    checked = AdSmbHostChannel.from_mapping(AdSmbScope.from_mapping(scope_row()), row)
    certificates = {
        role + "-cert.pem": cert.public_bytes(serialization.Encoding.PEM)
        for role, cert in (("ca", ca), ("server", server), ("client", client))
    }
    values = {}
    calls = []

    class Directory:
        def __init__(self, path, *, private):
            assert private is True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def names(self):
            return list(values)

        def read(self, name, *, maximum):
            calls.append(name)
            value = values[name]
            if len(value) > maximum:
                raise RunnerTrustError("synthetic bound")
            return value

    class Provider:
        provider_id = "synthetic-memory-only"

        def unprotect(self, purpose, opaque):
            calls.append(purpose)
            if opaque == b"synthetic-hmac":
                return bytes(range(32))
            if opaque == b"synthetic-password":
                return PASSWORD
            raise SecretStoreError("synthetic-raw-secret-not-for-errors")

    monkeypatch.setattr(trust, "_PinnedDirectory", Directory)
    monkeypatch.setattr(trust, "_validated_enrollment_root", lambda path: Path(path))

    def prepare(side):
        values.clear()
        values.update(certificates)
        values.update(
            {
                "trust.json": canonical_json_bytes(
                    {
                        "schema_version": trust.SCHEMA,
                        "side": side,
                        "status": "active",
                        "channel": checked.to_dict(),
                        "secret_provider": Provider.provider_id,
                    }
                ),
                "hmac.secret": b"synthetic-hmac",
                side + "-key-password.secret": b"synthetic-password",
                side
                + "-key.pem": keys[side].private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(PASSWORD),
                ),
            }
        )
        calls.clear()
        return values

    return checked, prepare, values, calls, Provider()


@pytest.mark.parametrize("side", ["server", "client"])
def test_role_bundle_validates_real_in_memory_certificates_only_own_key(bundle, side):
    checked, prepare, values, calls, provider = bundle
    prepare(side)
    result = trust.load_channel_enrollment(
        Path("synthetic-role"), channel=checked, side=side, secret_provider=provider
    )
    opposite = "client" if side == "server" else "server"
    assert opposite + "-key.pem" not in calls
    assert opposite + "-key-password.secret" not in calls
    assert result.transport_identity_scope() == {"ad_smb_channel_digest": checked.digest}
    assert result.allowed_profile_ids == ("profile-member",)
    assert result._purpose("request-hmac").endswith(f":{side}:request-hmac")
    assert "synthetic-hmac" not in repr(result)
    assert PASSWORD.decode() not in repr(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "peer-key",
        "peer-password",
        "unknown",
        "missing",
        "revoked",
        "side",
        "channel",
        "provider",
        "hmac",
        "password",
        "duplicate",
        "large",
    ],
)
def test_bad_role_materials_fail_sanitized_before_any_network(bundle, mutation):
    checked, prepare, values, calls, provider = bundle
    prepare("server")
    if mutation in {"peer-key", "peer-password", "unknown"}:
        values[
            {
                "peer-key": "client-key.pem",
                "peer-password": "client-key-password.secret",
                "unknown": "extra",
            }[mutation]
        ] = b"unsafe"
    elif mutation == "missing":
        del values["ca-cert.pem"]
    elif mutation == "hmac":
        values["hmac.secret"] = b"bad"
    elif mutation == "password":
        values["server-key-password.secret"] = b"bad"
    elif mutation == "duplicate":
        values["trust.json"] = b'{"schema_version":1,"schema_version":2}'
    elif mutation == "large":
        values["trust.json"] = b"x" * 65537
    else:
        row = json.loads(values["trust.json"])
        if mutation == "revoked":
            row["status"] = "revoked"
        if mutation == "side":
            row["side"] = "client"
        if mutation == "provider":
            row["secret_provider"] = "other"
        if mutation == "channel":
            row["channel"]["host_ipv4"] = "10.44.0.99"
        values["trust.json"] = canonical_json_bytes(row)
    with pytest.raises(RunnerTrustError) as error:
        trust.load_channel_enrollment(
            Path("synthetic-role"), channel=checked, side="server", secret_provider=provider
        )
    assert "synthetic-raw-secret" not in str(error.value) + repr(error.value)


def test_same_certificate_bytes_cannot_be_rebound_to_other_address(bundle):
    checked, prepare, values, calls, provider = bundle
    prepare("server")
    row = checked.to_dict()
    row["host_ipv4"] = "10.44.0.9"
    # Deliberately forged object bypasses the public factory, but the loader
    # still rejects its certificate SAN instead of relabeling the endpoint.
    forged = AdSmbHostChannel(canonical_json_bytes(row))
    metadata = json.loads(values["trust.json"])
    metadata["channel"] = row
    values["trust.json"] = canonical_json_bytes(metadata)
    with pytest.raises(RunnerTrustError):
        trust.load_channel_enrollment(
            Path("synthetic-role"), channel=forged, side="server", secret_provider=provider
        )


def test_cache_rechecks_revocation_on_every_call(bundle):
    from bluefire.ad_smb_channel_transport import _ChannelEnrollmentCache

    checked, prepare, values, calls, provider = bundle
    prepare("server")
    cache = _ChannelEnrollmentCache(Path("synthetic-role"), checked, "server", provider)
    cache.active()
    row = json.loads(values["trust.json"])
    row["status"] = "revoked"
    values["trust.json"] = canonical_json_bytes(row)
    from bluefire.runner_transport_errors import RunnerAuthenticationError

    with pytest.raises(RunnerAuthenticationError):
        cache.active()
