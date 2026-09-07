"""Pure input contracts shared across product-store persistence operations."""

from __future__ import annotations

import re
from collections.abc import Collection
from typing import Any

from .product_store_errors import ProductStoreError
from .util import json_clone

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


_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SECRET_FIELDS = {
    "auth",
    "authorization",
    "bearer",
    "cookie",
    "api_key",
    "apikey",
    "credential",
    "credentials",
    "password",
    "private_key",
    "secret",
    "secrets",
    "token",
}
_CREDENTIAL_VALUE_PATTERNS = (
    re.compile(r"\A(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}\Z"),
    re.compile(r"\Ask-[A-Za-z0-9_-]{20,}\Z"),
    re.compile(r"\Axox[baprs]-[A-Za-z0-9-]{10,}\Z"),
    re.compile(r"\AAKIA[0-9A-Z]{16}\Z"),
    re.compile(r"\AeyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\Z"),
    re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
    re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"),
)


def safe_document(value: Any, *, context: str = "document") -> Any:
    """Clone JSON data and reject persisted plaintext secrets.

    A secret-shaped field may be null or an exact ``{"env": "NAME"}``
    reference.  This keeps configuration exportable without making the local
    database a credential store.
    """

    try:
        cloned = json_clone(value)
    except (TypeError, ValueError) as exc:
        raise ProductStoreError(f"{context} must contain only JSON values") from exc

    def inspect(item: Any, path: str) -> None:
        if isinstance(item, str):
            if any(pattern.search(item) for pattern in _CREDENTIAL_VALUE_PATTERNS):
                raise ProductStoreError(
                    f"{path} contains a credential-shaped plaintext value; "
                    "use an environment-variable reference"
                )
            return
        if isinstance(item, list):
            for index, child in enumerate(item):
                inspect(child, f"{path}[{index}]")
            return
        if not isinstance(item, dict):
            return
        for raw_key, child in item.items():
            if not isinstance(raw_key, str):
                raise ProductStoreError(f"{path} contains a non-string key")
            key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw_key).lower().replace("-", "_")
            segments = tuple(part for part in re.split(r"[^a-z0-9]+", key) if part)
            secret_shaped = key in _SECRET_FIELDS or any(
                segment in _SECRET_FIELDS for segment in segments
            )
            if secret_shaped:
                if child is None:
                    continue
                if key.endswith(("_available", "_configured", "_present")) and isinstance(
                    child, bool
                ):
                    continue
                if (
                    key.endswith(("_reference", "_env"))
                    and isinstance(child, str)
                    and _ENVIRONMENT_NAME.fullmatch(child)
                ):
                    continue
                if (
                    key in {"credentials", "secrets"}
                    and isinstance(child, dict)
                    and all(
                        isinstance(reference, dict)
                        and set(reference) == {"env"}
                        and isinstance(reference["env"], str)
                        and _ENVIRONMENT_NAME.fullmatch(reference["env"])
                        for reference in child.values()
                    )
                ):
                    continue
                if (
                    not isinstance(child, dict)
                    or set(child) != {"env"}
                    or not isinstance(child["env"], str)
                    or not _ENVIRONMENT_NAME.fullmatch(child["env"])
                ):
                    raise ProductStoreError(
                        f"{path}.{raw_key} must be null or an environment-variable reference"
                    )
            inspect(child, f"{path}.{raw_key}")

    inspect(cloned, context)
    return cloned
