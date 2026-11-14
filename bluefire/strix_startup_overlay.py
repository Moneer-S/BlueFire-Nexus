"""Hash-pinned startup correction for the reviewed Strix CLI entry point.

The pinned upstream CLI checks and pulls Docker before choosing its registered
runtime backend, and later persists the in-memory model authorization into its
configuration. BlueFire makes Docker setup conditional and skips persistence
only for the ``bluefire-controlled`` backend. Both exact byte replacements are
bound to the reviewed source; an unknown preimage or replacement fails closed.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass

from .util import content_hash

REVIEWED_SOURCE_REVISION = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"  # pragma: allowlist secret
REVIEWED_STARTUP_SHA256 = (
    "735ad8463f83256f049749a91c00f85cd6b58301c225244c7b6b798898cc7014"  # pragma: allowlist secret
)
STARTUP_OVERLAY_SHA256 = (
    "e7eb0aec715ea4d11176394105da4ca43cd9636cb329f764368008bdfd8d57ae"  # pragma: allowlist secret
)
PATCHED_STARTUP_SHA256 = (
    "3c125771640c0255fc2f0b27152be7a5f78d8e9dd2e74906e2981ba28194986f"  # pragma: allowlist secret
)

_ORIGINAL = b"    check_docker_installed()\n    pull_docker_image()\n    validate_environment()\n"
_REPLACEMENT = (
    b"    # BlueFire: validate the registered backend before Docker-specific setup.\n"
    b"    from strix.runtime.backends import get_backend\n"
    b"\n"
    b"    backend_name = load_settings().runtime.backend\n"
    b"    get_backend(backend_name)\n"
    b'    if backend_name == "docker":\n'
    b"        check_docker_installed()\n"
    b"        pull_docker_image()\n"
    b"    validate_environment()\n"
)
_PERSIST_ORIGINAL = b"    persist_current()\n"
_PERSIST_REPLACEMENT = (
    b"    # BlueFire: keep controlled relay authorization in memory only.\n"
    b'    if load_settings().runtime.backend != "bluefire-controlled":\n'
    b"        persist_current()\n"
)
_OVERLAY = _REPLACEMENT + b"\x00" + _PERSIST_REPLACEMENT


class StrixStartupOverlayError(ValueError):
    """The reviewed Strix startup correction could not be applied exactly."""


def _validate_patched_control_flow(patched: bytes) -> None:
    """Validate both modified blocks in the complete transformed module."""
    try:
        source = patched.decode("utf-8")
        compile(source, "strix/interface/main.py", "exec")
        tree = ast.parse(source)
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        main = functions["main"]
        bootstrap = functions["_bootstrap_scan"]
        main_text = [ast.unparse(node) for node in main.body]
        bootstrap_text = [ast.unparse(node) for node in bootstrap.body]
    except (UnicodeError, SyntaxError, KeyError, ValueError, TypeError):
        raise StrixStartupOverlayError("patched Strix startup control flow is invalid") from None
    if not any(
        "backend_name = load_settings().runtime.backend" in row for row in main_text
    ) or not any(
        "if backend_name == 'docker':\n    check_docker_installed()\n    pull_docker_image()" in row
        for row in main_text
    ):
        raise StrixStartupOverlayError("patched Strix backend selection is invalid")
    if not any(
        "if load_settings().runtime.backend != 'bluefire-controlled':\n    persist_current()" in row
        for row in bootstrap_text
    ) or any(row == "persist_current()" for row in bootstrap_text):
        raise StrixStartupOverlayError("patched Strix persistence guard is invalid")


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


def reviewed_startup_overlay_receipt() -> StrixStartupOverlayReceipt:
    """Return the exact admitted startup adaptation identity."""
    return StrixStartupOverlayReceipt(
        source_revision=REVIEWED_SOURCE_REVISION,
        upstream_sha256=REVIEWED_STARTUP_SHA256,
        overlay_sha256=STARTUP_OVERLAY_SHA256,
        patched_sha256=PATCHED_STARTUP_SHA256,
    )


STARTUP_OVERLAY_RECEIPT_REF = content_hash(reviewed_startup_overlay_receipt().to_dict())


def apply_startup_overlay(
    upstream: bytes,
    *,
    overlay: bytes | None = None,
) -> tuple[bytes, StrixStartupOverlayReceipt]:
    """Apply the one reviewed startup replacement, refusing drift or ambiguity."""

    if not isinstance(upstream, bytes):
        raise StrixStartupOverlayError("upstream startup source must be bytes")
    correction = _OVERLAY if overlay is None else overlay
    if not isinstance(correction, bytes) or not correction:
        raise StrixStartupOverlayError("startup overlay must be non-empty bytes")
    upstream_hash = hashlib.sha256(upstream).hexdigest()
    overlay_hash = hashlib.sha256(correction).hexdigest()
    if upstream_hash != REVIEWED_STARTUP_SHA256:
        raise StrixStartupOverlayError("Strix startup preimage is not the reviewed source")
    if overlay_hash != STARTUP_OVERLAY_SHA256:
        raise StrixStartupOverlayError("Strix startup overlay is not the reviewed replacement")
    if upstream.count(_ORIGINAL) != 1 or upstream.count(_PERSIST_ORIGINAL) != 1:
        raise StrixStartupOverlayError("reviewed Strix startup block is missing or ambiguous")
    patched = upstream.replace(_ORIGINAL, _REPLACEMENT, 1).replace(
        _PERSIST_ORIGINAL, _PERSIST_REPLACEMENT, 1
    )
    patched_hash = hashlib.sha256(patched).hexdigest()
    if patched_hash != PATCHED_STARTUP_SHA256:
        raise StrixStartupOverlayError("patched Strix startup did not match the reviewed result")
    _validate_patched_control_flow(patched)
    return patched, StrixStartupOverlayReceipt(
        source_revision=REVIEWED_SOURCE_REVISION,
        upstream_sha256=upstream_hash,
        overlay_sha256=overlay_hash,
        patched_sha256=patched_hash,
    )
