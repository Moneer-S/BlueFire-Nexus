"""Closed registry of externally bound native tool contracts."""

from __future__ import annotations

from types import MappingProxyType, ModuleType
from typing import cast

from ..contracts import ContractError
from . import chmod, gzip
from .contracts import ToolAdapterContract

_ADAPTERS = MappingProxyType(
    {
        chmod.ADAPTER_ID: chmod,
        gzip.ADAPTER_ID: gzip,
    }
)


def adapter_for(adapter_id: str):
    try:
        return cast(ModuleType, _ADAPTERS[adapter_id])
    except (KeyError, TypeError):
        raise ContractError("unknown native tool adapter") from None


def known_adapter_ids() -> frozenset[str]:
    return frozenset(_ADAPTERS)


def contract_for(adapter_id: str) -> ToolAdapterContract:
    return cast(ToolAdapterContract, adapter_for(adapter_id).CONTRACT)


__all__ = ["adapter_for", "contract_for", "known_adapter_ids"]
