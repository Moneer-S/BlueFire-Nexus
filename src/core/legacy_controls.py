"""Helpers for enabling, validating, and summarizing legacy capability packs."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, Dict, Mapping, Sequence
from urllib.parse import urlparse

SAFE_DOMAIN_PATTERNS = (
    "localhost",
    "*.localhost",
    "*.example.lab",
    "example.lab",
    "*.invalid",
    "*.test",
)
LEGACY_PACK_KEYS = ("actor_pack", "c2_pack", "stealth_pack", "tactic_pack")
LEGACY_PACK_CAPABILITIES: Dict[str, tuple[str, ...]] = {
    "actor_pack": ("apt29", "apt28", "apt32", "apt38", "apt41", "actor_profile"),
    "c2_pack": (
        "dns_tunneling",
        "tls_fast_flux",
        "websocket_quic",
        "solana_rpc",
        "network_obfuscator_legacy",
    ),
    "stealth_pack": (
        "anti_forensic",
        "anti_sandbox",
        "anti_detection_legacy",
        "dynamic_api",
    ),
    # Tactic pack wraps the preserved per-tactic legacy classes. New
    # capabilities are added one focused PR at a time so the adapter
    # surface stays reviewable.
    "tactic_pack": ("credential_access", "lateral_movement", "privilege_escalation"),
}
CAPABILITY_ALIASES: Dict[str, Dict[str, str]] = {
    "c2_pack": {
        "dns": "dns_tunneling",
        "dns_tunnel": "dns_tunneling",
        "quic_c2": "websocket_quic",
        "quic": "websocket_quic",
        "network_obfuscator": "network_obfuscator_legacy",
    },
    "stealth_pack": {
        "anti_detection": "anti_detection_legacy",
    },
}
LEGACY_PRESET_ALIASES: Dict[str, str] = {
    "baseline": "safe-baseline",
    "safe": "safe-baseline",
    "simulate-all": "full-simulate",
    "all-simulate": "full-simulate",
    "all-emulate": "full-emulate",
    "emulate-all": "full-emulate",
    "actor-sim": "actor-simulate",
    "c2-sim": "c2-simulate",
    "stealth-sim": "stealth-simulate",
}
LEGACY_PRESET_PROFILES: Dict[str, Dict[str, Any]] = {
    "safe-baseline": {
        "description": "Disable all legacy capability packs.",
        "risk": "low",
        "global": {
            "enable_all_lab_capabilities": False,
            "global_mode": "simulate",
            "global_lab_acknowledged": False,
            "lab_confirmation": False,
        },
        "packs": {},
    },
    "full-simulate": {
        "description": "Enable all legacy packs in simulate mode.",
        "risk": "medium",
        "global": {
            "enable_all_lab_capabilities": True,
            "global_mode": "simulate",
            "global_lab_acknowledged": False,
            "lab_confirmation": False,
        },
        "packs": {},
    },
    "full-emulate": {
        "description": "Enable all legacy packs in emulate mode with lab confirmation.",
        "risk": "critical",
        "global": {
            "enable_all_lab_capabilities": True,
            "global_mode": "emulate",
            "global_lab_acknowledged": True,
            "lab_confirmation": True,
        },
        "packs": {},
    },
    "actor-simulate": {
        "description": "Enable the full actor pack in simulate mode.",
        "risk": "medium",
        "global": {
            "enable_all_lab_capabilities": False,
            "global_mode": "simulate",
            "global_lab_acknowledged": False,
            "lab_confirmation": False,
        },
        "packs": {
            "actor_pack": {
                "enabled": True,
                "mode": "simulate",
                "lab_confirmation": False,
                "capabilities": "all",
                "capability_mode": "simulate",
                "capability_lab_confirmation": False,
            }
        },
    },
    "c2-simulate": {
        "description": "Enable the full protocol/C2 pack in simulate mode.",
        "risk": "high",
        "global": {
            "enable_all_lab_capabilities": False,
            "global_mode": "simulate",
            "global_lab_acknowledged": False,
            "lab_confirmation": False,
        },
        "packs": {
            "c2_pack": {
                "enabled": True,
                "mode": "simulate",
                "lab_confirmation": False,
                "capabilities": "all",
                "capability_mode": "simulate",
                "capability_lab_confirmation": False,
            }
        },
    },
    "stealth-simulate": {
        "description": "Enable the full stealth pack in simulate mode.",
        "risk": "high",
        "global": {
            "enable_all_lab_capabilities": False,
            "global_mode": "simulate",
            "global_lab_acknowledged": False,
            "lab_confirmation": False,
        },
        "packs": {
            "stealth_pack": {
                "enabled": True,
                "mode": "simulate",
                "lab_confirmation": False,
                "capabilities": "all",
                "capability_mode": "simulate",
                "capability_lab_confirmation": False,
            }
        },
    },
}
LEGACY_GUIDED_PROFILE_ALIASES: Dict[str, str] = {
    "safe": "safe-evaluation",
    "baseline": "safe-evaluation",
    "detect": "detection-regression",
    "detection": "detection-regression",
    "regression": "detection-regression",
    "protocol": "protocol-research",
    "c2": "protocol-research",
    "stealth": "stealth-research",
    "full": "full-lab-emulation",
    "emulate": "full-lab-emulation",
    "credential": "detection-regression",
    "credentials": "detection-regression",
    "att&ck": "detection-regression",
    "attack": "detection-regression",
}
LEGACY_GUIDED_PROFILES: Dict[str, Dict[str, str]] = {
    "safe-evaluation": {
        "recommended_preset": "safe-baseline",
        "risk": "low",
        "notes": "No legacy packs are enabled; use for baseline validation and CI checks.",
    },
    "detection-regression": {
        "recommended_preset": "full-simulate",
        "risk": "medium",
        "notes": "Enables broad ATT&CK coverage in simulate mode for rule regression testing.",
    },
    "protocol-research": {
        "recommended_preset": "c2-simulate",
        "risk": "high",
        "notes": "Focuses on protocol/C2 behaviors without emulate-mode execution.",
    },
    "stealth-research": {
        "recommended_preset": "stealth-simulate",
        "risk": "high",
        "notes": "Focuses on stealth behaviors while keeping execution in simulate mode.",
    },
    "full-lab-emulation": {
        "recommended_preset": "full-emulate",
        "risk": "critical",
        "notes": "Only for isolated lab environments with explicit operator confirmation.",
    },
}


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
        or value.get("lab_acknowledged", False)
        or value.get("global_lab_acknowledged", False)
        or value.get("i_understand_this_is_a_lab", False)
    )


def _normalize_capability(pack_key: str, capability: str) -> str:
    alias_map = CAPABILITY_ALIASES.get(pack_key, {})
    value = str(capability).lower().strip()
    return alias_map.get(value, value)


def normalize_pack_name(pack_key: str) -> str:
    value = str(pack_key).lower().strip()
    if value not in LEGACY_PACK_KEYS:
        raise ValueError(
            f"Unknown legacy pack '{pack_key}'. Expected one of: {', '.join(LEGACY_PACK_KEYS)}"
        )
    return value


def normalize_capability_name(pack_key: str, capability: str) -> str:
    normalized_pack = normalize_pack_name(pack_key)
    normalized_capability = _normalize_capability(normalized_pack, capability)
    allowed = LEGACY_PACK_CAPABILITIES.get(normalized_pack, ())
    if allowed and normalized_capability not in allowed:
        raise ValueError(
            f"Unknown legacy capability '{capability}' for {normalized_pack}. "
            f"Expected one of: {', '.join(allowed)}"
        )
    return normalized_capability


def capability_aliases(pack_key: str, capability: str) -> tuple[str, ...]:
    normalized_pack = normalize_pack_name(pack_key)
    normalized_capability = _normalize_capability(normalized_pack, capability)
    aliases = tuple(
        alias
        for alias, target in CAPABILITY_ALIASES.get(normalized_pack, {}).items()
        if target == normalized_capability
    )
    return aliases


def supported_legacy_capabilities() -> Dict[str, Dict[str, Any]]:
    """Return canonical capabilities and aliases by legacy pack."""
    payload: Dict[str, Dict[str, Any]] = {}
    for pack_key in LEGACY_PACK_KEYS:
        capabilities = LEGACY_PACK_CAPABILITIES.get(pack_key, ())
        payload[pack_key] = {
            "capabilities": [
                {
                    "name": capability,
                    "aliases": list(capability_aliases(pack_key, capability)),
                }
                for capability in capabilities
            ]
        }
    return payload


def resolve_legacy_preset_name(preset_name: str) -> str:
    """Resolve aliases and return a canonical preset profile name."""
    value = str(preset_name).strip().lower()
    canonical = LEGACY_PRESET_ALIASES.get(value, value)
    if canonical not in LEGACY_PRESET_PROFILES:
        allowed = ", ".join(sorted(LEGACY_PRESET_PROFILES))
        raise ValueError(f"Unknown legacy preset '{preset_name}'. Expected one of: {allowed}")
    return canonical


def legacy_preset_catalog() -> Dict[str, Dict[str, Any]]:
    """Return legacy preset profiles with aliases for CLI rendering."""
    payload = deepcopy(LEGACY_PRESET_PROFILES)
    for name in payload:
        payload[name]["aliases"] = sorted(
            alias for alias, canonical in LEGACY_PRESET_ALIASES.items() if canonical == name
        )
    return payload


def _infer_guided_profile_from_text(value: str) -> str | None:
    if not value:
        return None
    safe_markers = {
        "baseline",
        "safe",
        "ci",
        "sanity",
        "smoke",
        "disable",
        "disabled",
        "minimal",
        "none",
    }
    words = {token.strip(".,:;()[]{}") for token in value.split()}
    if words & safe_markers:
        return "safe-evaluation"
    if any(
        keyword in value for keyword in ("emulate", "emulation", "live-fire", "full lab")
    ):
        return "full-lab-emulation"
    if any(
        keyword in value
        for keyword in ("protocol", "c2", "dns", "quic", "tls", "solana", "beacon", "tunnel")
    ):
        return "protocol-research"
    if any(
        keyword in value
        for keyword in ("stealth", "evasion", "anti-detection", "sandbox", "forensic")
    ):
        return "stealth-research"
    if any(
        keyword in value
        for keyword in (
            "detect",
            "detection",
            "regression",
            "sigma",
            "yara",
            "splunk",
            "coverage",
            "simulate",
            "simulation",
            "attack chain",
        )
    ):
        return "detection-regression"
    return None


def _infer_guided_profile_from_modules(modules: Sequence[str] | None) -> str | None:
    if not modules:
        return None
    normalized = {str(name).strip().lower() for name in modules if str(name).strip()}
    has_actor = any(
        name.startswith("legacy_apt") or name == "legacy_actor_profile"
        for name in normalized
    )
    has_protocol = "legacy_protocol_research" in normalized
    has_stealth = "legacy_stealth_research" in normalized
    if has_protocol and not has_stealth:
        return "protocol-research"
    if has_stealth and not has_protocol:
        return "stealth-research"
    if has_protocol and has_stealth:
        return "detection-regression"
    if has_actor:
        return "detection-regression"
    return None


def _infer_guided_profile_from_scenario_name(name: str) -> str | None:
    value = str(name).strip().lower()
    if not value:
        return None
    if "protocol" in value or "c2" in value:
        return "protocol-research"
    if "stealth" in value or "evasion" in value:
        return "stealth-research"
    if "legacy" in value:
        return "detection-regression"
    return None


def resolve_guided_profile_name(
    objective: str,
    *,
    modules: Sequence[str] | None = None,
) -> str:
    """Resolve guided objective aliases to canonical objective keys."""
    value = str(objective).strip().lower()
    canonical = LEGACY_GUIDED_PROFILE_ALIASES.get(value, value)
    if canonical in LEGACY_GUIDED_PROFILES:
        return canonical
    if value in LEGACY_GUIDED_PROFILES:
        return value
    inferred_from_text = _infer_guided_profile_from_text(value)
    inferred_from_modules = _infer_guided_profile_from_modules(modules)
    if inferred_from_text in {"safe-evaluation", "full-lab-emulation"}:
        return inferred_from_text
    if (
        inferred_from_modules in {"protocol-research", "stealth-research"}
        and inferred_from_text == "detection-regression"
    ):
        return inferred_from_modules
    if inferred_from_text:
        return inferred_from_text
    if inferred_from_modules:
        return inferred_from_modules
    return "safe-evaluation"


def guided_legacy_profile_catalog() -> Dict[str, Dict[str, Any]]:
    """Return guided objective mappings to recommended presets."""
    payload: Dict[str, Dict[str, Any]] = deepcopy(LEGACY_GUIDED_PROFILES)
    for objective_key, details in payload.items():
        details["aliases"] = sorted(
            alias
            for alias, canonical in LEGACY_GUIDED_PROFILE_ALIASES.items()
            if canonical == objective_key
        )
        details["description"] = (
            f"{objective_key} -> {details.get('recommended_preset', 'safe-baseline')}"
        )
    return payload


def recommend_legacy_preset_for_objective(
    objective: str,
    *,
    modules: Sequence[str] | None = None,
) -> Dict[str, Any]:
    """Return recommended preset metadata for a guided objective."""
    objective_key = resolve_guided_profile_name(objective, modules=modules)
    profile = deepcopy(LEGACY_GUIDED_PROFILES[objective_key])
    profile["objective"] = objective_key
    aliases = [
        alias
        for alias, canonical in LEGACY_GUIDED_PROFILE_ALIASES.items()
        if canonical == objective_key
    ]
    profile["aliases"] = sorted(aliases)
    return profile


def recommend_legacy_preset_for_scenario(
    objective: str,
    *,
    modules: Sequence[str] | None = None,
    scenario_name: str = "",
) -> Dict[str, Any]:
    """Recommend preset using objective plus scenario/module context."""
    objective_text = str(objective).strip().lower()
    explicit_objective = objective_text not in {
        "",
        "exercise lab-gated legacy protocol adapters with explicit master or granular enablement.",
        (
            "exercise lab-gated legacy capability adapters with explicit "
            "master or granular enablement."
        ),
        "exercise legacy capability adapters with explicit master or granular enablement.",
    }
    if explicit_objective:
        return recommend_legacy_preset_for_objective(objective_text, modules=modules)

    scenario_hint = _infer_guided_profile_from_scenario_name(scenario_name)
    if scenario_hint:
        profile = deepcopy(LEGACY_GUIDED_PROFILES[scenario_hint])
        profile["objective"] = scenario_hint
        profile["aliases"] = sorted(
            alias
            for alias, canonical in LEGACY_GUIDED_PROFILE_ALIASES.items()
            if canonical == scenario_hint
        )
        return profile

    return recommend_legacy_preset_for_objective(objective_text, modules=modules)


def summarize_legacy_risk_posture(summary: Mapping[str, Any]) -> Dict[str, Any]:
    """Compute a compact risk posture from legacy activation summary."""
    packs = summary.get("packs", {}) if isinstance(summary, Mapping) else {}
    emulate_count = 0
    enabled_count = 0
    for pack in LEGACY_PACK_KEYS:
        pack_summary = packs.get(pack, {}) if isinstance(packs, Mapping) else {}
        capabilities = pack_summary.get("enabled_capabilities") or []
        if not isinstance(capabilities, list):
            continue
        enabled_count += len(capabilities)
        mode = str(pack_summary.get("mode", "simulate")).lower()
        if mode == "emulate":
            emulate_count += len(capabilities)

    if emulate_count > 0:
        level = "critical"
    elif enabled_count >= 8:
        level = "high"
    elif enabled_count > 0:
        level = "medium"
    else:
        level = "low"

    return {
        "enabled_capability_count": enabled_count,
        "emulate_capability_count": emulate_count,
        "risk_level": level,
    }


def _normalize_mode(value: Any, default: str = "simulate") -> str:
    mode = str(value or default).lower().strip()
    if mode not in {"simulate", "emulate"}:
        return default
    return mode


def legacy_preset_overrides(preset_name: str) -> Dict[str, Any]:
    """Return deterministic dot-path config overrides for a preset profile."""
    name = resolve_legacy_preset_name(preset_name)
    profile = LEGACY_PRESET_PROFILES[name]
    overrides: Dict[str, Any] = {
        "modules.legacy.active_preset": name,
        "modules.legacy.enable_all_lab_capabilities": False,
        "modules.legacy.global_mode": "simulate",
        "modules.legacy.global_lab_acknowledged": False,
        "modules.legacy.lab_confirmation": False,
    }
    for pack_key in LEGACY_PACK_KEYS:
        overrides[f"modules.legacy.{pack_key}.enabled"] = False
        overrides[f"modules.legacy.{pack_key}.mode"] = "simulate"
        overrides[f"modules.legacy.{pack_key}.lab_confirmation"] = False
        for capability in LEGACY_PACK_CAPABILITIES.get(pack_key, ()):
            base = f"modules.legacy.{pack_key}.capabilities.{capability}"
            overrides[f"{base}.enabled"] = False
            overrides[f"{base}.mode"] = "simulate"
            overrides[f"{base}.lab_confirmation"] = False

    for key, value in (profile.get("global", {}) or {}).items():
        overrides[f"modules.legacy.{key}"] = value

    if bool(overrides.get("modules.legacy.enable_all_lab_capabilities", False)):
        master_mode = _normalize_mode(overrides.get("modules.legacy.global_mode", "simulate"))
        master_ack = bool(
            overrides.get("modules.legacy.global_lab_acknowledged", False)
            or overrides.get("modules.legacy.lab_confirmation", False)
        )
        for pack_key in LEGACY_PACK_KEYS:
            overrides[f"modules.legacy.{pack_key}.enabled"] = True
            overrides[f"modules.legacy.{pack_key}.mode"] = master_mode
            overrides[f"modules.legacy.{pack_key}.lab_confirmation"] = master_ack
            for capability in LEGACY_PACK_CAPABILITIES.get(pack_key, ()):
                base = f"modules.legacy.{pack_key}.capabilities.{capability}"
                overrides[f"{base}.enabled"] = True
                overrides[f"{base}.mode"] = master_mode
                overrides[f"{base}.lab_confirmation"] = master_ack

    packs_cfg = profile.get("packs", {}) or {}
    for pack_key, raw_settings in packs_cfg.items():
        if not isinstance(raw_settings, Mapping):
            continue
        normalized_pack = normalize_pack_name(pack_key)
        settings = dict(raw_settings)
        pack_mode = _normalize_mode(settings.get("mode", "simulate"))
        pack_ack = bool(settings.get("lab_confirmation", False))
        overrides[f"modules.legacy.{normalized_pack}.enabled"] = bool(settings.get("enabled", True))
        overrides[f"modules.legacy.{normalized_pack}.mode"] = pack_mode
        overrides[f"modules.legacy.{normalized_pack}.lab_confirmation"] = pack_ack
        requested = settings.get("capabilities", "all")
        if requested == "all":
            selected = LEGACY_PACK_CAPABILITIES.get(normalized_pack, ())
        elif isinstance(requested, (list, tuple, set)):
            selected = tuple(
                normalize_capability_name(normalized_pack, str(capability))
                for capability in requested
            )
        else:
            selected = ()
        capability_mode = _normalize_mode(
            settings.get("capability_mode", pack_mode),
            default=pack_mode,
        )
        capability_ack = bool(settings.get("capability_lab_confirmation", pack_ack))
        for capability in selected:
            base = f"modules.legacy.{normalized_pack}.capabilities.{capability}"
            overrides[f"{base}.enabled"] = True
            overrides[f"{base}.mode"] = capability_mode
            overrides[f"{base}.lab_confirmation"] = capability_ack
    return overrides


def _capability_candidate_keys(pack_key: str, capability: str) -> tuple[str, list[str]]:
    canonical = _normalize_capability(pack_key, capability)
    alias_map = CAPABILITY_ALIASES.get(pack_key, {})
    candidates: list[str] = [
        alias for alias, target in alias_map.items() if target == canonical
    ]
    requested = str(capability).lower().strip()
    if requested not in candidates:
        candidates.append(requested)
    if canonical not in candidates:
        candidates.append(canonical)
    return canonical, candidates


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
    capability_name, candidate_keys = _capability_candidate_keys(pack_key, capability)
    capabilities = pack_cfg.get("capabilities") or {}
    if not isinstance(capabilities, Mapping):
        capabilities = {}

    capability_cfg: Dict[str, Any] = {}
    capability_enabled = False
    for key in candidate_keys:
        value = capabilities.get(key, {})
        if not isinstance(value, Mapping):
            continue
        value_dict = dict(value)
        capability_enabled = capability_enabled or bool(value_dict.get("enabled", False))
        capability_cfg.update(value_dict)

    master_enabled = bool(legacy_cfg.get("enable_all_lab_capabilities", False))
    pack_enabled = bool(pack_cfg.get("enabled", False))
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

    capability_mode = capability_cfg.get("mode")
    if capability_mode is None and capability_cfg.get("emulate_enabled", False):
        capability_mode = "emulate"
    global_mode = legacy_cfg.get("global_mode", legacy_cfg.get("lab_mode", "simulate"))
    global_mode_explicit = "global_mode" in legacy_cfg or "lab_mode" in legacy_cfg
    if master_enabled and global_mode_explicit:
        mode = str(
            module_mode
            or capability_mode
            or global_mode
            or pack_cfg.get("mode")
            or "simulate"
        ).lower()
    else:
        mode = str(
            module_mode
            or capability_mode
            or pack_cfg.get("mode")
            or global_mode
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
        "capability_name": capability_name,
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
        "global_mode": str(
            legacy_cfg.get("global_mode", legacy_cfg.get("lab_mode", "simulate"))
        ).lower(),
        "active_preset": str(legacy_cfg.get("active_preset", "")).lower(),
        "global_lab_acknowledged": _is_acknowledged(legacy_cfg),
        "announce_activation": bool(legacy_cfg.get("announce_activation", True)),
        "packs": {},
    }
    for pack_key in LEGACY_PACK_KEYS:
        pack_cfg = legacy_cfg.get(pack_key, {})
        if not isinstance(pack_cfg, Mapping):
            pack_cfg = {}
        capabilities = pack_cfg.get("capabilities") or {}
        enabled_capabilities = {
            _normalize_capability(pack_key, capability)
            for capability, capability_cfg in capabilities.items()
            if isinstance(capability_cfg, Mapping)
            and capability_cfg.get("enabled", False)
        }
        summary["packs"][pack_key] = {
            "enabled": bool(pack_cfg.get("enabled", False)),
            "mode": str(
                pack_cfg.get("mode", pack_cfg.get("lab_mode", summary["global_mode"]))
            ).lower(),
            "acknowledged": _is_acknowledged(pack_cfg),
            "enabled_capabilities": sorted(enabled_capabilities),
        }
    return summary


def render_manual_preset_name(pack_key: str) -> str:
    """Return a stable synthetic preset label for manual pack overrides."""
    normalized_pack = normalize_pack_name(pack_key)
    return f"{normalized_pack}-manual"


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
    "CAPABILITY_ALIASES",
    "LEGACY_PACK_KEYS",
    "LEGACY_PACK_CAPABILITIES",
    "LEGACY_GUIDED_PROFILE_ALIASES",
    "LEGACY_GUIDED_PROFILES",
    "LEGACY_PRESET_ALIASES",
    "LEGACY_PRESET_PROFILES",
    "LegacyCapabilityDecision",
    "build_legacy_summary",
    "capability_effective_enabled",
    "capability_mode",
    "capability_aliases",
    "evaluate_legacy_capability",
    "guided_legacy_profile_catalog",
    "get_legacy_config",
    "is_domain_allowed",
    "legacy_preset_catalog",
    "legacy_preset_overrides",
    "normalize_capability_name",
    "normalize_pack_name",
    "recommend_legacy_preset_for_objective",
    "render_manual_preset_name",
    "resolve_guided_profile_name",
    "resolve_legacy_preset_name",
    "resolve_legacy_settings",
    "supported_legacy_capabilities",
    "summarize_legacy_controls",
    "summarize_legacy_risk_posture",
]
