"""Base abstractions for pluggable BlueFire modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Mapping, Optional

from ..models import ModuleResult


class BaseModule(ABC):
    """Common interface all orchestrated modules must implement."""

    name: str = "base"
    attack_techniques: tuple[str, ...] = ()

    def __init__(self) -> None:
        self._config: Dict[str, Any] = {}

    def update_config(self, config: Mapping[str, Any]) -> None:
        """Receive merged module configuration from orchestrator."""
        self._config = dict(config)

    def validate(self, params: Mapping[str, Any]) -> Optional[str]:
        """Return validation error text, or None when valid."""
        _ = params
        return None

    @abstractmethod
    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        """Run the module operation and return a structured result."""
        raise NotImplementedError
