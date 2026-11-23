"""Verify owned AD storage without treating every directory as runner TLS material."""

from pathlib import Path

from .runner_trust import _canonical_transition_path, _PinnedDirectory


def private_root(root: str | Path) -> Path:
    """Verify an existing directory; each consumer owns its finite file schema.

    Role bundles and credential stores require their exact named files. Mutable
    worker directories instead retain the worker's existing output contracts.
    Neither this check nor later reads repair permissions or create storage.
    """
    path = _canonical_transition_path(root, create_parent=False)
    with _PinnedDirectory(path, private=True, verify_permissions_only=True):
        return path
