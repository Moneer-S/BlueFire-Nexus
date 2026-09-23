"""Byte-bound review of the fixed system-gzip process boundary."""

from tools.provider_gate_common import _sha256_bytes

REVIEWED_GZIP_SOURCE_SHA256 = (
    "sha256:e8a0ac021970d5ac1f11b7d86fcb7f61da62e3173a48df06b68597eed54d0d27"
)
REVIEWED_GZIP_SOURCE_BYTES = 9361


def reviewed_gzip_source(source: bytes) -> bool:
    return (
        type(source) is bytes
        and len(source) == REVIEWED_GZIP_SOURCE_BYTES
        and _sha256_bytes(source) == REVIEWED_GZIP_SOURCE_SHA256
    )
