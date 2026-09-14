"""Byte-bound review of the fixed system-gzip process boundary."""

from tools.provider_gate_common import _sha256_bytes

REVIEWED_GZIP_SOURCE_SHA256 = (
    "sha256:e0cb7d372101fcf42b4aaa2dde455838a4c842b4c3d893557b8a928fbf834fa4"
)
REVIEWED_GZIP_SOURCE_BYTES = 9713


def reviewed_gzip_source(source: bytes) -> bool:
    return (
        type(source) is bytes
        and len(source) == REVIEWED_GZIP_SOURCE_BYTES
        and _sha256_bytes(source) == REVIEWED_GZIP_SOURCE_SHA256
    )
