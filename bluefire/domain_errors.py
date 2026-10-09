"""Stable neutral errors shared across validation and effect-owning boundaries."""


class ProductStoreError(ValueError):
    """Raised when product metadata or a state transition is invalid."""


class RunnerTransportError(RuntimeError):
    """A sanitized failure at the maintained runner transport boundary."""
