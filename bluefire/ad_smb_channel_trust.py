"""Read-only, own-key-only enrollment for explicitly scoped AD host channels.

No enrollment creation, certificate issuance, transfer or listener occurs here.
The locally protected bundle is an owner-installed prerequisite. Its public
host binding is an enrollment assertion, not remote machine attestation.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .ad_smb_channel import AdSmbHostChannel, _time
from .ad_smb_contract import AdSmbError
from .runner_trust import (
    RunnerEnrollment,
    RunnerTrustError,
    _match_key,
    _PinnedDirectory,
    _read_private_key_bytes,
    _secret_provider,
    _strict_object,
    _validated_enrollment_root,
    _verify_leaf,
    _verify_signature,
    certificate_fingerprint,
)
from .secret_store import SecretProvider, SecretStoreError

SCHEMA = "bluefire.ad-smb-host-trust.v1"
_PUBLIC = {"trust.json", "ca-cert.pem", "server-cert.pem", "client-cert.pem", "hmac.secret"}


@dataclass(frozen=True, repr=False)
class AdSmbChannelEnrollment(RunnerEnrollment):
    def _purpose(self, purpose: str) -> str:
        return f"{SCHEMA}:{self.metadata['channel_digest']}:{self.metadata['side']}:{purpose}"

    def transport_identity_scope(self) -> Mapping[str, str]:
        return {"ad_smb_channel_digest": str(self.metadata["channel_digest"])}


def _certificates(
    materials: Mapping[str, bytes], channel: AdSmbHostChannel, side: str, password: bytes
) -> None:
    row = channel.to_dict()
    ca = x509.load_pem_x509_certificate(materials["ca-cert.pem"])
    server = x509.load_pem_x509_certificate(materials["server-cert.pem"])
    client = x509.load_pem_x509_certificate(materials["client-cert.pem"])
    for name, cert in (("ca", ca), ("server", server), ("client", client)):
        if certificate_fingerprint(cert) != row[name + "_fingerprint"]:
            raise ValueError("certificate fingerprint")
        if cert.not_valid_before_utc > _time(row["created_at"]) or cert.not_valid_after_utc < _time(
            row["expires_at"]
        ):
            raise ValueError("certificate lifetime")
    if ca.issuer != ca.subject or ca.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value != x509.BasicConstraints(ca=True, path_length=0):
        raise ValueError("authority constraints")
    usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    if not (usage.key_cert_sign and usage.crl_sign and usage.digital_signature):
        raise ValueError("authority usage")
    _verify_signature(ca, ca)
    _verify_leaf(ca, server, ExtendedKeyUsageOID.SERVER_AUTH)
    _verify_leaf(ca, client, ExtendedKeyUsageOID.CLIENT_AUTH)
    for cert, field in ((server, "runner_id"), (client, "client_id")):
        if [item.value for item in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)] != [
            row[field]
        ]:
            raise ValueError("peer name")
    sans = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if list(sans) != [x509.IPAddress(ipaddress.IPv4Address(row["host_ipv4"]))]:
        raise ValueError("server address")
    try:
        client.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        pass
    else:
        raise ValueError("client address")
    key = _read_private_key_bytes(materials[side + "-key.pem"], password)
    _match_key(key, server if side == "server" else client)


def load_channel_enrollment(
    root: str | Path,
    *,
    channel: AdSmbHostChannel,
    side: str,
    secret_provider: SecretProvider | None = None,
) -> AdSmbChannelEnrollment:
    """Validate an exact protected role bundle; never load the peer's private key."""
    try:
        if side not in {"server", "client"}:
            raise ValueError("side")
        channel.assert_current()
        destination = _validated_enrollment_root(root)
        names = _PUBLIC | {side + "-key.pem", side + "-key-password.secret"}
        with _PinnedDirectory(destination, private=True) as directory:
            if set(directory.names()) != names:
                raise ValueError("material set")
            materials = {name: directory.read(name, maximum=65536) for name in names}
            trust = json.loads(
                materials["trust.json"].decode("utf-8"), object_pairs_hook=_strict_object
            )
            if not isinstance(trust, dict) or set(trust) != {
                "schema_version",
                "side",
                "status",
                "channel",
                "secret_provider",
            }:
                raise ValueError("trust shape")
            provider = _secret_provider(secret_provider)
            if (
                trust["schema_version"] != SCHEMA
                or trust["side"] != side
                or trust["status"] != "active"
                or trust["channel"] != channel.to_dict()
                or trust["secret_provider"] != provider.provider_id
            ):
                raise ValueError("trust binding")
            row = channel.to_dict()
            metadata: dict[str, Any] = {
                **row,
                "schema_version": SCHEMA,
                "side": side,
                "status": "active",
                "allowed_profile_ids": [row["profile_id"]],
                "channel_digest": channel.digest,
            }
            enrollment = AdSmbChannelEnrollment(destination, metadata, provider)
            password = provider.unprotect(
                enrollment._purpose(side + "-key-password"),
                materials[side + "-key-password.secret"],
            )
            key = provider.unprotect(enrollment._purpose("request-hmac"), materials["hmac.secret"])
            if (
                not isinstance(password, bytes)
                or not 32 <= len(password) <= 128
                or not isinstance(key, bytes)
                or len(key) != 32
            ):
                raise ValueError("protected material size")
            _certificates(materials, channel, side, password)
            if set(directory.names()) != names or any(
                directory.read(name, maximum=65536) != original
                for name, original in materials.items()
            ):
                raise ValueError("enrollment changed")
            return enrollment
    except (
        AdSmbError,
        RunnerTrustError,
        SecretStoreError,
        OSError,
        ValueError,
        TypeError,
        UnicodeError,
        MemoryError,
        x509.ExtensionNotFound,
    ):
        raise RunnerTrustError("AD host enrollment is unavailable, inactive or invalid.") from None
