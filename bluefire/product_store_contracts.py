"""Pure input contracts shared across product-store persistence operations."""

from __future__ import annotations

import re
from collections.abc import Collection
from typing import Any

from .product_store_errors import ProductStoreError

STABLE_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_MAX_ACTION_PACKAGE_ACTOR_CHARS = 128
MAX_OCCUPIED_PACKAGE_IDS = 4096


def stable_identifier(value: Any, context: str) -> str:
    """Return an exact stable lowercase identifier or reject the value."""

    if not isinstance(value, str) or not STABLE_IDENTIFIER_PATTERN.fullmatch(value):
        raise ProductStoreError(f"{context} must be a stable lowercase identifier")
    return value


def package_actor(value: Any, context: str) -> str:
    """Validate a bounded printable actor identity for a package event."""

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > _MAX_ACTION_PACKAGE_ACTOR_CHARS
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProductStoreError(
            f"{context} must be a non-empty printable string no longer than "
            f"{_MAX_ACTION_PACKAGE_ACTOR_CHARS} characters"
        )
    return value


def occupied_package_ids(value: Any, context: str) -> tuple[str, ...]:
    """Normalize a bounded collection of package-owned stable identifiers."""

    if isinstance(value, (str, bytes)) or not isinstance(value, Collection):
        raise ProductStoreError(f"{context} must be a collection of stable identifiers")
    if len(value) > MAX_OCCUPIED_PACKAGE_IDS:
        raise ProductStoreError(
            f"{context} cannot contain more than {MAX_OCCUPIED_PACKAGE_IDS} identifiers"
        )
    normalized: set[str] = set()
    for item in value:
        stable_id = stable_identifier(item, context)
        if len(stable_id) > 128:
            raise ProductStoreError(f"{context} identifiers cannot exceed 128 characters")
        normalized.add(stable_id)
    return tuple(sorted(normalized))


__all__ = [
    "MAX_OCCUPIED_PACKAGE_IDS",
    "STABLE_IDENTIFIER_PATTERN",
    "occupied_package_ids",
    "package_actor",
    "stable_identifier",
]
