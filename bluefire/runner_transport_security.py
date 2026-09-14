"""Mutual-TLS and message authentication for the runner transport."""

from __future__ import annotations

import hashlib
import hmac
import ssl
from typing import Any, Mapping

from cryptography import x509
from cryptography.x509.oid import NameOID

from .runner_transport_errors import RunnerAuthenticationError
from .runner_trust import RunnerEnrollment, certificate_fingerprint
from .util import canonical_json_bytes


def request_authentication(enrollment: RunnerEnrollment, unsigned: Mapping[str, Any]) -> str:
    digest = hmac.new(
        enrollment.hmac_key(), canonical_json_bytes(dict(unsigned)), hashlib.sha256
    ).hexdigest()
    return "sha256:" + digest


def sign_request(enrollment: RunnerEnrollment, unsigned: Mapping[str, Any]) -> dict[str, Any]:
    return {**dict(unsigned), "authentication": request_authentication(enrollment, unsigned)}


def sign_response(enrollment: RunnerEnrollment, unsigned: Mapping[str, Any]) -> dict[str, Any]:
    return {**dict(unsigned), "authentication": request_authentication(enrollment, unsigned)}


def _certificate_common_name(certificate_bytes: bytes) -> str:
    try:
        certificate = x509.load_der_x509_certificate(certificate_bytes)
        names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    except (TypeError, ValueError):
        raise RunnerAuthenticationError("Runner peer certificate is invalid.") from None
    if len(names) != 1 or not isinstance(names[0].value, str):
        raise RunnerAuthenticationError("Runner peer certificate identity is invalid.")
    return names[0].value


def verify_peer(
    connection: ssl.SSLSocket,
    *,
    expected_fingerprint: str,
    expected_common_name: str,
) -> str:
    certificate = connection.getpeercert(binary_form=True)
    if not certificate:
        raise RunnerAuthenticationError("Runner peer did not present a certificate.")
    fingerprint = certificate_fingerprint(certificate)
    if not hmac.compare_digest(fingerprint, expected_fingerprint):
        raise RunnerAuthenticationError("Runner peer certificate identity does not match.")
    if not hmac.compare_digest(_certificate_common_name(certificate), expected_common_name):
        raise RunnerAuthenticationError("Runner peer certificate identity does not match.")
    if connection.version() != "TLSv1.3":
        raise RunnerAuthenticationError("Runner transport did not negotiate TLS 1.3.")
    return fingerprint


def server_context(enrollment: RunnerEnrollment) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.load_verify_locations(cafile=str(enrollment.ca_certificate))
        context.load_cert_chain(
            certfile=str(enrollment.server_certificate),
            keyfile=str(enrollment.server_private_key),
            password=enrollment.server_key_password(),
        )
    except (OSError, ssl.SSLError):
        raise RunnerAuthenticationError("Runner server identity could not be loaded.") from None
    return context


def client_context(enrollment: RunnerEnrollment) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    try:
        context.load_verify_locations(cafile=str(enrollment.ca_certificate))
        context.load_cert_chain(
            certfile=str(enrollment.client_certificate),
            keyfile=str(enrollment.client_private_key),
            password=enrollment.client_key_password(),
        )
    except (OSError, ssl.SSLError):
        raise RunnerAuthenticationError("Runner client identity could not be loaded.") from None
    return context


__all__ = [
    "client_context",
    "request_authentication",
    "server_context",
    "sign_request",
    "sign_response",
    "verify_peer",
]
