"""Shared errors for signed action-package contracts."""


class ActionPackageError(ValueError):
    """Raised when an action package is malformed, untrusted, or incompatible."""


__all__ = ["ActionPackageError"]
