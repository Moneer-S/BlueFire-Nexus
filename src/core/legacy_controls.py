"""Helpers for enabling, validating, and summarizing legacy capability packs."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, Dict, Mapping
from urllib.parse import urlparse

SAFE_DOMAIN_PATTERNS = (
    "localhost",
    "*.localhost",
    "*.example.lab",
    "example.lab",
    "*.invalid",
    "*.test",
)
LEGACY_PACK_KEYS = ("actor_pack", "c2_pack", "stealth_pack")


@dataclass(frozen=True)
class LegacyCapabilityDecision:
    enabled: bool
    mode: str
    acknowledged: bool
    activation_source: str
    master_enabled: bool
    pack_enabled: bool
    capability_enabled: bool

    def summary_message(self) -> str:
        if not self.enabled:
            return "disabled"
        if self.mode == "emulate" and not self.acknowledged:
            return f"enabled via {self.activation_source}, emulate blocked until lab confirmation"
        return f"enabled via {self.activation_source} in {self.mode} mode"


def _host_from_candidate(candidate: str) -> str:
    if "://" in candidate:
        return (urlparse(candidate).hostname or "").lower()
    return candidate.lower().split("/")[0].split(":")[0]


def get_legacy_config(config: Mapping[str, Any]) -> Dict[str, Any]:
    modules_cfg = config.get("modules", {})
    if not isinstance(modules_cfg, Mapping):
        return {}
    legacy_cfg = modules_cfg.get("legacy", {})
    return dict(legacy_cfg) if isinstance(legacy_cfg, Mapping) else {}


def _is_acknowledged(value: Mapping[str, Any]) -> bool:
    return bool(
        value.get("lab_confirmation", False)
        or value.get("global_lab_acknowledged", False)
        or value.get("i_understand_this_is_a_lab", False)
    )


def resolve_legacy_settings(
    config: Mapping[str, Any],
    *,
    pack_key: str,
    capability: str,
    module_enabled: bool = False,
    module_mode: str | None = None,
    module_acknowledged: bool = False,
) -> Dict[str, Any]:
    """Resolve effective enablement and mode for a legacy capability."""

    legacy_cfg = get_legacy_config(config)
    pack_cfg = legacy_cfg.get(pack_key, {})
    if not isinstance(pack_cfg, Mapping):
        pack_cfg = {}
    capability_cfg = (pack_cfg.get("capabilities") or {}).get(capability, {})
    if not isinstance(capability_cfg, Mapping):
        capability_cfg = {}

    master_enabled = bool(legacy_cfg.get("enable_all_lab_capabilities", False))
    pack_enabled = bool(pack_cfg.get("enabled", False))
    capability_enabled = bool(capability_cfg.get("enabled", False))
    enabled = master_enabled or pack_enabled or capability_enabled or bool(module_enabled)

    if master_enabled:
        enablement_source = "master_toggle"
    elif capability_enabled:
        enablement_source = "capability_toggle"
    elif pack_enabled:
        enablement_source = "pack_toggle"
    elif module_enabled:
        enablement_source = "module_toggle"
    else:
        enablement_source = "disabled"

    mode = str(
        module_mode
        or capability_cfg.get("mode")
        or pack_cfg.get("mode")
        or legacy_cfg.get("global_mode", "simulate")
    ).lower()
    if mode not in {"simulate", "emulate"}:
        mode = "simulate"

    acknowledged = bool(
        module_acknowledged
        or _is_acknowledged(capability_cfg)
        or _is_acknowledged(pack_cfg)
        or _is_acknowledged(legacy_cfg)
    )

    return {
        "enabled": enabled,
        "mode": mode,
        "acknowledged": acknowledged,
        "master_enabled": master_enabled,
        "pack_enabled": pack_enabled,
        "capability_enabled": capability_enabled,
        "enablement_source": enablement_source,
    }


def evaluate_legacy_capability(
    config: Mapping[str, Any],
    pack_key: str,
    capability: str,
    *,
    module_enabled: bool = False,
    module_mode: str | None = None,
    module_acknowledged: bool = False,
) -> LegacyCapabilityDecision:
    settings = resolve_legacy_settings(
        config,
        pack_key=pack_key,
        capability=capability,
        module_enabled=module_enabled,
        module_mode=module_mode,
        module_acknowledged=module_acknowledged,
    )
    return LegacyCapabilityDecision(
        enabled=bool(settings["enabled"]),
        mode=str(settings["mode"]),
        acknowledged=bool(settings["acknowledged"]),
        activation_source=str(settings["enablement_source"]),
        master_enabled=bool(settings["master_enabled"]),
        pack_enabled=bool(settings["pack_enabled"]),
        capability_enabled=bool(settings["capability_enabled"]),
    )


def capability_effective_enabled(
    config: Mapping[str, Any],
    pack_key: str,
    capability: str,
) -> bool:
    return evaluate_legacy_capability(config, pack_key, capability).enabled


def capability_mode(
    config: Mapping[str, Any],
    pack_key: str,
    capability: str,
) -> str:
    return evaluate_legacy_capability(config, pack_key, capability).mode


def summarize_legacy_controls(config: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a compact summary for CLI/reporting surfaces."""

    legacy_cfg = get_legacy_config(config)
    summary: Dict[str, Any] = {
        "enable_all_lab_capabilities": bool(
            legacy_cfg.get("enable_all_lab_capabilities", False)
        ),
        "global_mode": str(legacy_cfg.get("global_mode", "simulate")).lower(),
        "global_lab_acknowledged": _is_acknowledged(legacy_cfg),
        "announce_activation": bool(legacy_cfg.get("announce_activation", True)),
        "packs": {},
    }
    for pack_key in LEGACY_PACK_KEYS:
        pack_cfg = legacy_cfg.get(pack_key, {})
        if not isinstance(pack_cfg, Mapping):
            pack_cfg = {}
        capabilities = pack_cfg.get("capabilities") or {}
        summary["packs"][pack_key] = {
            "enabled": bool(pack_cfg.get("enabled", False)),
            "mode": str(pack_cfg.get("mode", summary["global_mode"])).lower(),
            "acknowledged": _is_acknowledged(pack_cfg),
            "enabled_capabilities": sorted(
                capability
                for capability, capability_cfg in capabilities.items()
                if isinstance(capability_cfg, Mapping)
                and capability_cfg.get("enabled", False)
            ),
        }
    return summary


def build_legacy_summary(config: Mapping[str, Any]) -> Dict[str, Any]:
    return summarize_legacy_controls(config)


def is_domain_allowed(candidate: str, config: Mapping[str, Any]) -> bool:
    """Best-effort validation for user-supplied domains/endpoints."""

    host = _host_from_candidate(candidate)
    if not host:
        return True
    safeties = config.get("general", {}).get("safeties", {})
    configured = safeties.get("allowed_domains", [])
    patterns = list(configured) if configured else list(SAFE_DOMAIN_PATTERNS)
    return any(fnmatch(host, pattern.lower()) for pattern in patterns)


__all__ = [
    "LEGACY_PACK_KEYS",
    "LegacyCapabilityDecision",
    "build_legacy_summary",
    "capability_effective_enabled",
    "capability_mode",
    "evaluate_legacy_capability",
    "get_legacy_config",
    "is_domain_allowed",
    "resolve_legacy_settings",
    "summarize_legacy_controls",
]
