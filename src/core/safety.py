"""Safety gate enforcement for module execution."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


class SafetyViolation(RuntimeError):
    """Raised when execution violates configured safety constraints."""


def _normalize_networks(networks: Iterable[str]) -> list[ipaddress._BaseNetwork]:
    parsed: list[ipaddress._BaseNetwork] = []
    for network in networks:
        parsed.append(ipaddress.ip_network(network, strict=False))
    return parsed


def ensure_target_allowed(target: str, allowed_subnets: Iterable[str]) -> None:
    """Ensure IP target belongs to one of the allowed subnets.

    Hostnames (anything that does not parse as an IP literal) are
    permitted regardless of ``allowed_subnets`` — DNS resolution
    happens at the module level under module-specific gates and the
    safety layer cannot meaningfully bound it here.

    For IP targets, an EMPTY ``allowed_subnets`` list is treated as
    "no IP targets permitted" rather than "no restriction", which
    keeps the semantic consistent with the network_touch guard
    (``ensure_safe`` requires a non-empty ``allowed_subnets`` for
    network_touch outside dry-run). This closes the strict_local
    footgun where ``allowed_subnets: []`` previously allowed any IP
    target through.
    """
    if not target:
        return
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        # Hostnames are allowed in dry-run scenarios.
        return
    allowed = _normalize_networks(allowed_subnets)
    if not any(ip in network for network in allowed):
        raise SafetyViolation(f"target '{target}' is outside allowed_subnets")


@dataclass
class SafetyGate:
    """Evaluate operation payloads against runtime safety settings."""

    run_context: Any

    def _elapsed_seconds(self) -> float:
        start = getattr(self.run_context, "start_time", datetime.now(timezone.utc))
        return (datetime.now(timezone.utc) - start).total_seconds()

    def ensure_safe(self, payload: Mapping[str, Any]) -> None:
        dry_run = bool(getattr(self.run_context, "dry_run", True))
        allowed_subnets = list(getattr(self.run_context, "allowed_subnets", []))
        max_runtime = int(getattr(self.run_context, "max_runtime", 3600))

        if self._elapsed_seconds() > max_runtime:
            raise SafetyViolation("max_runtime exceeded")

        target_value = payload.get("target") or payload.get("targets")
        if isinstance(target_value, str):
            ensure_target_allowed(target_value, allowed_subnets)
        elif isinstance(target_value, list):
            for target in target_value:
                if isinstance(target, str):
                    ensure_target_allowed(target, allowed_subnets)

        destructive = bool(payload.get("destructive", False))
        acknowledged = bool(payload.get("i_understand_this_is_a_lab", False))
        if destructive and not acknowledged:
            raise SafetyViolation(
                "destructive operation requires i_understand_this_is_a_lab=true"
            )

        # Block implicit live-network behavior in non-dry-run mode.
        network_touch = bool(payload.get("network_touch", False))
        if network_touch and not dry_run and not allowed_subnets:
            raise SafetyViolation(
                "network_touch operation requires configured allowed_subnets"
            )
