"""Hash-pinned startup correction for the reviewed Strix CLI entry point.

The pinned upstream CLI checks and pulls Docker before choosing its registered
runtime backend. BlueFire applies this exact byte replacement to the reviewed
source; an unknown preimage or replacement fails closed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

REVIEWED_SOURCE_REVISION = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"
REVIEWED_STARTUP_SHA256 = "735ad8463f83256f049749a91c00f85cd6b58301c225244c7b6b798898cc7014"
STARTUP_OVERLAY_SHA256 = "e86820ed36e72496f65c0133a367779332782a4b00814c8e6bea73ccc2885303"
PATCHED_STARTUP_SHA256 = "db3294b351406479960f1f18cde51e58d48f2dd9d4c1c249004385510a6e4fbf"

_ORIGINAL = b"    check_docker_installed()\n    pull_docker_image()\n    validate_environment()\n"
_REPLACEMENT = (
    b"    from strix.runtime.backends import get_backend\n"
    b"\n"
    b"    backend_name = load_settings().runtime.backend\n"
    b"    get_backend(backend_name)\n"
    b'    if backend_name == "docker":\n'
    b"        check_docker_installed()\n"
    b"        pull_docker_image()\n"
    b"    validate_environment()\n"
)


class StrixStartupOverlayError(ValueError):
    """The reviewed Strix startup correction could not be applied exactly."""


@dataclass(frozen=True, slots=True)
class StrixStartupOverlayReceipt:
    source_revision: str
    upstream_sha256: str
    overlay_sha256: str
    patched_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": "bluefire.strix-startup-overlay.v1",
            "source_revision": self.source_revision,
            "upstream_sha256": self.upstream_sha256,
            "overlay_sha256": self.overlay_sha256,
            "patched_sha256": self.patched_sha256,
        }


def apply_startup_overlay(
    upstream: bytes,
    *,
    overlay: bytes | None = None,
) -> tuple[bytes, StrixStartupOverlayReceipt]:
    """Apply the one reviewed startup replacement, refusing drift or ambiguity."""

    if not isinstance(upstream, bytes):
        raise StrixStartupOverlayError("upstream startup source must be bytes")
    correction = _REPLACEMENT if overlay is None else overlay
    if not isinstance(correction, bytes) or not correction:
        raise StrixStartupOverlayError("startup overlay must be non-empty bytes")
    upstream_hash = hashlib.sha256(upstream).hexdigest()
    overlay_hash = hashlib.sha256(correction).hexdigest()
    if upstream_hash != REVIEWED_STARTUP_SHA256:
        raise StrixStartupOverlayError("Strix startup preimage is not the reviewed source")
    if overlay_hash != STARTUP_OVERLAY_SHA256:
        raise StrixStartupOverlayError("Strix startup overlay is not the reviewed replacement")
    if upstream.count(_ORIGINAL) != 1:
        raise StrixStartupOverlayError("reviewed Strix startup block is missing or ambiguous")
    patched = upstream.replace(_ORIGINAL, correction, 1)
    patched_hash = hashlib.sha256(patched).hexdigest()
    if patched_hash != PATCHED_STARTUP_SHA256:
        raise StrixStartupOverlayError("patched Strix startup did not match the reviewed result")
    return patched, StrixStartupOverlayReceipt(
        source_revision=REVIEWED_SOURCE_REVISION,
        upstream_sha256=upstream_hash,
        overlay_sha256=overlay_hash,
        patched_sha256=patched_hash,
    )
