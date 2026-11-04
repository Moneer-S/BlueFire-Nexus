"""Hash-pinned policy correction for the reviewed Strix system prompt.

The upstream prompt is executable dependency content. BlueFire refuses an
unknown preimage and replaces only the reviewed authorization/refusal block.
This module does not grant scope or execution authority.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib.resources import files

REVIEWED_SOURCE_REVISION = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"
REVIEWED_PROMPT_SHA256 = "f5413d1ea78571cec610069020e49b7227f6c3691867c127ff383b6aa1b2ab17"
OVERLAY_SHA256 = "a88d1cb62230023c7809df4010831ea696e9a6e5793ab7ff80e46f24d4bc506d"
PATCHED_PROMPT_SHA256 = "1908703508eff7287d492e63d1722d7f1a4a968ab3d2c237e92898abdd65d6fe"

_START = b"AUTHORIZATION STATUS:\n"
_END = b"THOROUGH VALIDATION MANDATE:\n"


class StrixPolicyOverlayError(ValueError):
    """The reviewed prompt correction could not be applied exactly."""


@dataclass(frozen=True, slots=True)
class StrixPolicyOverlayReceipt:
    source_revision: str
    upstream_sha256: str
    overlay_sha256: str
    patched_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": "bluefire.strix-prompt-overlay.v1",
            "source_revision": self.source_revision,
            "upstream_sha256": self.upstream_sha256,
            "overlay_sha256": self.overlay_sha256,
            "patched_sha256": self.patched_sha256,
        }


def packaged_overlay() -> bytes:
    """Return the exact correction text shipped as package data."""

    return files("bluefire").joinpath("data/strix_prompt_policy_overlay.txt").read_bytes()


def apply_policy_overlay(
    upstream: bytes,
    *,
    overlay: bytes | None = None,
) -> tuple[bytes, StrixPolicyOverlayReceipt]:
    """Apply the one reviewed replacement, refusing drift or ambiguity."""

    if not isinstance(upstream, bytes):
        raise StrixPolicyOverlayError("upstream prompt must be bytes")
    correction = packaged_overlay() if overlay is None else overlay
    if not isinstance(correction, bytes) or not correction:
        raise StrixPolicyOverlayError("prompt overlay must be non-empty bytes")
    upstream_hash = hashlib.sha256(upstream).hexdigest()
    overlay_hash = hashlib.sha256(correction).hexdigest()
    if upstream_hash != REVIEWED_PROMPT_SHA256:
        raise StrixPolicyOverlayError("Strix prompt preimage is not the reviewed source")
    if overlay_hash != OVERLAY_SHA256:
        raise StrixPolicyOverlayError("Strix prompt overlay is not the packaged review")
    if upstream.count(_START) != 1 or upstream.count(_END) != 1:
        raise StrixPolicyOverlayError("reviewed Strix policy section is missing or ambiguous")
    start = upstream.index(_START)
    end = upstream.index(_END, start)
    if end <= start:
        raise StrixPolicyOverlayError("reviewed Strix policy section is out of order")
    patched = upstream[:start] + correction + upstream[end:]
    patched_hash = hashlib.sha256(patched).hexdigest()
    if patched_hash != PATCHED_PROMPT_SHA256:
        raise StrixPolicyOverlayError("patched Strix prompt did not match the reviewed result")
    if (
        b"never question your authority" in patched.lower()
        or b"refusal avoidance" in patched.lower()
    ):
        raise StrixPolicyOverlayError("upstream blanket authority language remained after overlay")
    return patched, StrixPolicyOverlayReceipt(
        source_revision=REVIEWED_SOURCE_REVISION,
        upstream_sha256=upstream_hash,
        overlay_sha256=overlay_hash,
        patched_sha256=patched_hash,
    )
