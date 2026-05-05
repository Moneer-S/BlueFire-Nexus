"""Plugin loading for external module extensions."""

from __future__ import annotations

import logging
from importlib import metadata
from typing import Any, Dict, Mapping, Type

from .modules.base import BaseModule

ENTRY_POINT_GROUP = "bluefire.modules"
LOGGER = logging.getLogger(__name__)


def load_plugin_modules(_config: Mapping[str, Any] | None = None) -> Dict[str, Type[BaseModule]]:
    """Load module classes exposed through Python entry points."""
    loaded: Dict[str, Type[BaseModule]] = {}
    try:
        entries = metadata.entry_points(group=ENTRY_POINT_GROUP)
    except Exception:
        return loaded

    for entry in entries:
        candidate = None
        try:
            candidate = entry.load()
        except Exception as exc:
            LOGGER.warning("Skipping plugin entry %s: %s", entry.name, exc)
        if isinstance(candidate, type) and issubclass(candidate, BaseModule):
            loaded[candidate.name] = candidate
    return loaded
