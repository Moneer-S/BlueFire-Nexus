"""Durable-result persistence isolated from authenticated transport."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .util import canonical_json_bytes


class PinnedResultDirectory(Protocol):
    def create(self, name: str, payload: bytes, *, maximum: int) -> None: ...

    def read(self, name: str, *, maximum: int) -> bytes: ...


PinnedDirectoryFactory = Callable[[Path], AbstractContextManager[PinnedResultDirectory]]


def commit_durable_result(
    *,
    result_root: Path,
    destination_name: str,
    result: Mapping[str, Any],
    maximum: int,
    pinned_directory_factory: PinnedDirectoryFactory,
) -> None:
    """Commit canonical result bytes once, accepting only exact idempotency."""

    encoded = canonical_json_bytes(dict(result))
    if len(encoded) > maximum:
        raise ValueError("runner durable result exceeds the transport limit")
    with pinned_directory_factory(result_root) as pinned:
        try:
            pinned.create(destination_name, encoded, maximum=maximum)
        except FileExistsError:
            existing = pinned.read(destination_name, maximum=maximum)
            if existing != encoded:
                raise OSError("durable result identity conflicts") from None


__all__ = ["commit_durable_result"]
