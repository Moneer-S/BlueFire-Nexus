"""Central configuration helpers for BlueFire-Nexus.

The runtime config has historically been read directly via
``self.config.get(...)`` chains scattered through the codebase. This
module gathers the most common reads behind small, well-typed
helpers so feature code can ask for "the resolved AI config" or
"the resolved safety gates" instead of reaching into nested dicts.

Each helper returns a plain ``dict`` (or scalar) — no new wrapper
classes, no import-time side effects. Helpers never make network
calls. Helpers always return defaults that match the local-first,
offline-by-default baseline.

## Precedence model

For settings that can be overridden from multiple sources, the
documented order is:

1. **CLI flag** — operator's most-specific request.
2. **Scenario step param** — per-step overrides in scenario YAML.
3. **Config file** — `general.*`, `modules.*` keys in `config.yaml`.
4. **Environment variable** — for ambient runtime control (test
   isolation, container deployments).
5. **Default** — the local-first, simulate-only baseline.

The only intentional deviation is :func:`resolve_output_root`, where
the order simplifies to **config > env var > default** because no
CLI flag or scenario step exposes a runtime output_root override.

See ``docs/USAGE_GUIDELINES.md`` for the operator-facing description.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Tuple


# ---------------------------------------------------------------------------
# Generic precedence resolver
# ---------------------------------------------------------------------------


_MISSING = object()


def resolve_setting(
    *,
    cli: Any = _MISSING,
    scenario: Any = _MISSING,
    config: Any = _MISSING,
    env: Any = _MISSING,
    default: Any = None,
    truthy_only: bool = True,
) -> Any:
    """Return the first non-empty value following the documented precedence.

    Order: CLI > scenario step param > config > env var > default.

    A value is considered "set" when it is not ``_MISSING`` AND
    (when ``truthy_only=True``) not falsy in Python's normal sense
    (None, "", 0, [], {}). With ``truthy_only=False``, only the
    explicit ``_MISSING`` sentinel is treated as absent — useful for
    settings where ``False`` or ``0`` are meaningful explicit values.
    """

    def _present(value: Any) -> bool:
        if value is _MISSING:
            return False
        if truthy_only:
            return bool(value)
        return True

    for candidate in (cli, scenario, config, env):
        if _present(candidate):
            return candidate
    return default


# ---------------------------------------------------------------------------
# Output root
# ---------------------------------------------------------------------------


def resolve_output_root(config: Optional[Mapping[str, Any]] = None) -> Path:
    """Resolve the runtime output root.

    Order:
    1. ``general.output_root`` in the loaded config.
    2. ``BLUEFIRE_OUTPUT_ROOT`` env var.
    3. ``output`` default.

    Reuses the same precedence as ``BlueFireNexus._output_root`` and
    is the single source of truth for "where does this run write to".

    Type discipline (closes Codex P2 on PR #34): ``general.output_root``
    must be a non-empty string to count as "set". ``None``, booleans,
    ints, lists, and other non-string values are treated as **unset**
    rather than being coerced via ``str(...)`` into surprising
    directory names like ``"None"`` / ``"False"`` / ``"0"``. The
    fallback chain (env -> default) then takes over so a YAML
    misconfiguration like ``output_root: null`` does not silently
    write to a directory literally named ``None``.
    """
    if isinstance(config, Mapping):
        general = config.get("general")
        if isinstance(general, Mapping):
            raw = general.get("output_root")
            # Only honour explicit string values. Anything else (None,
            # bool, int, list, dict, ...) is treated as unset so the
            # fallback chain runs.
            if isinstance(raw, str):
                configured = raw.strip()
                if configured:
                    return Path(configured)
    env_root = os.environ.get("BLUEFIRE_OUTPUT_ROOT", "").strip()
    if env_root:
        return Path(env_root)
    return Path("output")


# ---------------------------------------------------------------------------
# Safety gates
# ---------------------------------------------------------------------------


_DEFAULT_SAFETY = {
    "auto_wipe": False,
    "max_runtime": 3600,
    "allowed_subnets": ("10.0.0.0/24",),
    "allowed_domains": ("*.example.lab", "example.lab", "localhost"),
}


def get_safety_config(config: Optional[Mapping[str, Any]] = None) -> dict:
    """Return the resolved safety-gate config dict.

    Always returns the local-first defaults when keys are absent. The
    `dry_run` flag is included alongside the safety gates because it
    is the umbrella switch for the simulate / dry-run model.
    """
    if not isinstance(config, Mapping):
        config = {}
    general = config.get("general") if isinstance(config.get("general"), Mapping) else {}
    safeties = general.get("safeties") if isinstance(general.get("safeties"), Mapping) else {}

    return {
        "dry_run": bool(general.get("dry_run", True)),
        "auto_wipe": bool(safeties.get("auto_wipe", _DEFAULT_SAFETY["auto_wipe"])),
        "max_runtime": int(safeties.get("max_runtime", _DEFAULT_SAFETY["max_runtime"])),
        "allowed_subnets": list(
            safeties.get("allowed_subnets", _DEFAULT_SAFETY["allowed_subnets"])
        ),
        "allowed_domains": list(
            safeties.get("allowed_domains", _DEFAULT_SAFETY["allowed_domains"])
        ),
    }


# ---------------------------------------------------------------------------
# AI / provider config
# ---------------------------------------------------------------------------


# Default AI config keys. Local-first: no network calls, no API keys
# required, template provider supplies deterministic offline output.
#
# `temperature`: None means "use the provider's own default" so the
# offline template provider (which has no notion of temperature) is
# unaffected; remote backends apply this as their sampling temperature
# when they exist.
#
# `fallback_provider`: empty string means "no fallback configured" —
# a primary provider failure surfaces as an error result. Setting this
# to ``"template"`` is the safest choice for "always degrade
# gracefully to the offline path". The fallback execution wrapper is
# Phase 2; Phase 1 only carries the config field.
_DEFAULT_AI_CONFIG = {
    "enabled": False,
    "provider": "template",
    "model": "default",
    "api_base": "",
    "api_key_env": "",
    "timeout": 30,
    "max_tokens": 1024,
    "temperature": None,
    "fallback_provider": "",
}

# The shapes of the supported provider configs are documented here so
# operators can reason about plug-and-play providers. The runtime does
# NOT default to any of these — `provider: template` remains the
# offline default. Aliases (``google -> gemini``, ``xai -> grok``,
# ``claude -> anthropic``) are normalised at provider-construction
# time by ``ProviderFactory.normalise_name``; the catalogue lists
# canonical names.
_KNOWN_PROVIDERS: Tuple[str, ...] = (
    "template",
    "none",
    "openai",
    "anthropic",
    "gemini",
    "grok",
    "ollama",
    "openai_compatible",
    "llama.cpp",
    "lm-studio",
)


def get_ai_config(config: Optional[Mapping[str, Any]] = None) -> dict:
    """Return the resolved AI / copilot config dict.

    Merges the following layers (later wins):

    1. Documented defaults (``_DEFAULT_AI_CONFIG`` — template-only,
       offline, no API keys).
    2. ``modules.ai.*`` from the loaded config.
    3. The provider-specific block under ``ai_providers.<provider>``
       (when present), so operators can stash credentials and base
       URLs per provider without touching ``modules.ai``.

    Returns a plain dict with stable keys for ``provider``, ``model``,
    ``api_base``, ``api_key_env``, ``timeout``, ``max_tokens``,
    ``enabled``, and a normalised ``provider_settings`` sub-dict
    containing the provider's own keys for callers that need raw
    pass-through (e.g. an OpenAI-compatible endpoint that needs
    ``api_key`` resolved through ``api_key_env``).

    No network calls, no imports of provider SDKs. The default keeps
    the runtime fully offline.
    """
    if not isinstance(config, Mapping):
        config = {}

    modules = config.get("modules") if isinstance(config.get("modules"), Mapping) else {}
    ai_section = modules.get("ai") if isinstance(modules.get("ai"), Mapping) else {}

    # Step 1: collect raw values from `modules.ai` (no normalisation
    # yet — empty strings stay empty so the provider-block fallback
    # below can detect them).
    raw: dict = {}
    for key in _DEFAULT_AI_CONFIG:
        if key in ai_section:
            raw[key] = ai_section[key]

    # Step 2: provider-specific block populates empty raw values for
    # well-known fields, so `ai_providers.openai_compatible.api_base`
    # can supply a base URL without forcing `modules.ai.api_base`.
    # Explicit `modules.ai.*` values still win because Step 1 already
    # captured them.
    provider_name = str(raw.get("provider", _DEFAULT_AI_CONFIG["provider"]) or "template").lower().strip()
    provider_sub: dict = {}
    providers_block = config.get("ai_providers")
    if isinstance(providers_block, Mapping):
        candidate = providers_block.get(provider_name)
        if isinstance(candidate, Mapping):
            provider_sub = dict(candidate)

    for field in ("api_base", "model"):
        if (field not in raw or not str(raw.get(field, "")).strip()) and provider_sub.get(field):
            raw[field] = str(provider_sub[field])

    # Step 3: apply documented defaults + type coercion.
    resolved = dict(_DEFAULT_AI_CONFIG)
    resolved.update(raw)
    resolved["enabled"] = bool(resolved.get("enabled", False))
    resolved["provider"] = provider_name
    resolved["model"] = str(resolved.get("model") or "default")
    resolved["api_base"] = str(resolved.get("api_base") or "")
    resolved["api_key_env"] = str(resolved.get("api_key_env") or "")
    try:
        resolved["timeout"] = int(resolved["timeout"])
    except (TypeError, ValueError):
        resolved["timeout"] = _DEFAULT_AI_CONFIG["timeout"]
    try:
        resolved["max_tokens"] = int(resolved["max_tokens"])
    except (TypeError, ValueError):
        resolved["max_tokens"] = _DEFAULT_AI_CONFIG["max_tokens"]

    # `temperature`: None means "let the provider decide". Operators can
    # set a float (typically 0.0-2.0); anything that does not parse as a
    # float falls back to None rather than an arbitrary number, so a
    # YAML typo cannot silently bias generation.
    raw_temperature = resolved.get("temperature", _DEFAULT_AI_CONFIG["temperature"])
    if raw_temperature is None or raw_temperature == "":
        resolved["temperature"] = None
    else:
        try:
            resolved["temperature"] = float(raw_temperature)
        except (TypeError, ValueError):
            resolved["temperature"] = None

    # `fallback_provider`: normalise to a string and validate against
    # known names so an obvious typo (e.g. ``ollam``) surfaces as
    # "fallback disabled" rather than silently routing to template
    # without warning. An empty string means "no fallback".
    raw_fallback = str(resolved.get("fallback_provider") or "").lower().strip()
    if raw_fallback and raw_fallback not in _KNOWN_PROVIDERS:
        # Operator chose a name that is not in the canonical catalogue.
        # Treat as unset (no fallback) to avoid surprise routing.
        raw_fallback = ""
    resolved["fallback_provider"] = raw_fallback

    resolved["provider_settings"] = provider_sub
    resolved["known_providers"] = list(_KNOWN_PROVIDERS)
    return resolved


def is_offline_ai(config: Optional[Mapping[str, Any]] = None) -> bool:
    """Return True when the AI layer is in offline / template mode.

    Used by call sites that want to short-circuit any provider
    initialisation when the runtime is configured for the local-first
    baseline.
    """
    ai = get_ai_config(config)
    if not ai["enabled"]:
        return True
    return ai["provider"] in {"template", "none", ""}


# ---------------------------------------------------------------------------
# Legacy capability one-line check
# ---------------------------------------------------------------------------


def is_legacy_capability_enabled(
    config: Optional[Mapping[str, Any]],
    pack: str,
    capability: str,
) -> bool:
    """Return True if a given legacy pack/capability is enabled.

    Thin wrapper around :func:`legacy_controls.evaluate_legacy_capability`
    that returns just the enabled flag — convenient for call sites
    that don't need the full decision (mode / acknowledgement /
    activation source).
    """
    # Local import keeps this module free of circular-import risk
    # against legacy_controls (which itself imports from utility
    # modules near the package root).
    from .legacy_controls import evaluate_legacy_capability

    if not isinstance(config, Mapping):
        return False
    return evaluate_legacy_capability(config, pack, capability).enabled


# ---------------------------------------------------------------------------
# Mutation defaults
# ---------------------------------------------------------------------------


_DEFAULT_MUTATION_CONFIG = {
    "enabled": False,
    "default_strategy": "",
    "allowed_strategies": (
        "low_noise",
        "evasion-lite",
        "protocol_shift",
        "protocol-shift",
    ),
}


def get_mutation_config(config: Optional[Mapping[str, Any]] = None) -> dict:
    """Return the resolved mutation-engine config dict.

    The CLI ``--mutate`` flag is the operator's per-run override; this
    helper exposes the file-level defaults so future scenarios or
    automation can pin a baseline strategy without depending on CLI
    invocation.
    """
    if not isinstance(config, Mapping):
        config = {}
    modules = config.get("modules") if isinstance(config.get("modules"), Mapping) else {}
    section = modules.get("mutation") if isinstance(modules.get("mutation"), Mapping) else {}
    resolved = dict(_DEFAULT_MUTATION_CONFIG)
    if "enabled" in section:
        resolved["enabled"] = bool(section["enabled"])
    if "default_strategy" in section:
        resolved["default_strategy"] = str(section["default_strategy"] or "")
    return resolved


# ---------------------------------------------------------------------------
# Simple-mode cross-cutting presets
# ---------------------------------------------------------------------------
#
# These presets span more than legacy controls — they touch
# `general.*`, `modules.ai.*`, and `modules.legacy.*` together so an
# operator can pick a posture in one action rather than editing
# scattered fields. They are config-level overrides, not hidden
# runtime behaviour: applying a preset writes the documented dot-path
# values into the loaded config and that's it.
#
# The legacy-only presets in `legacy_controls.LEGACY_PRESET_PROFILES`
# remain available for fine-grained legacy-pack work; these presets
# are additive — operators can apply a simple preset and then layer a
# legacy preset on top, or vice-versa.

# Each preset ships a "description" (operator-facing) plus a flat
# dot-path "overrides" mapping that the runner applies via
# `config_manager.set(...)`. Keep the keys conservative — these
# presets must never override a more-specific operator choice that
# already lives in `config.yaml` UNLESS the operator explicitly
# applies the preset.
_SIMPLE_PRESETS: dict = {
    "local_safe": {
        "description": (
            "Most conservative baseline. Dry-run enabled, no legacy "
            "packs, AI in offline template mode."
        ),
        "overrides": {
            "general.dry_run": True,
            "modules.ai.enabled": False,
            "modules.ai.provider": "template",
            "modules.legacy.enable_all_lab_capabilities": False,
            "modules.legacy.global_mode": "simulate",
            "modules.legacy.global_lab_acknowledged": False,
            "modules.legacy.lab_confirmation": False,
        },
    },
    "lab_legacy_enabled": {
        "description": (
            "All approved legacy capability packs enabled in simulate "
            "mode for purple-team detection-regression work. Emulate "
            "mode stays gated until lab acknowledgement is added "
            "explicitly."
        ),
        "overrides": {
            "general.dry_run": True,
            "modules.ai.enabled": False,
            "modules.ai.provider": "template",
            "modules.legacy.enable_all_lab_capabilities": True,
            "modules.legacy.global_mode": "simulate",
            "modules.legacy.global_lab_acknowledged": False,
            "modules.legacy.lab_confirmation": False,
        },
    },
    "ai_enabled": {
        "description": (
            "Enable the offline copilot template provider so scenario "
            "runs produce plan / narrative / detection-suggestion "
            "artifacts. No network calls; no API keys required."
        ),
        "overrides": {
            "modules.ai.enabled": True,
            "modules.ai.provider": "template",
        },
    },
    "ai_disabled": {
        "description": "Explicitly disable the AI copilot artifact layer.",
        "overrides": {
            "modules.ai.enabled": False,
            "modules.ai.provider": "template",
        },
    },
    "strict_local": {
        "description": (
            "Hardest local-first posture. Dry-run enabled, no legacy, "
            "no AI, safety gates restricted to loopback only "
            "(127.0.0.0/8 and ::1/128 for IPv4 / IPv6 loopback; "
            "`localhost` for hostname targets)."
        ),
        "overrides": {
            "general.dry_run": True,
            # Loopback-only IP targets. The runtime treats an empty
            # `allowed_subnets` as "no IPs permitted" (per
            # `ensure_target_allowed`), so this preset enumerates
            # the loopback CIDRs explicitly so loopback IPs are
            # genuinely allowed and everything else is genuinely
            # blocked. Previous versions left this as `[]` which
            # silently allowed any IP target via a short-circuit
            # in the safety check.
            "general.safeties.allowed_subnets": ["127.0.0.0/8", "::1/128"],
            "general.safeties.allowed_domains": ["localhost"],
            "modules.ai.enabled": False,
            "modules.ai.provider": "template",
            "modules.legacy.enable_all_lab_capabilities": False,
            "modules.legacy.global_mode": "simulate",
            "modules.legacy.global_lab_acknowledged": False,
            "modules.legacy.lab_confirmation": False,
        },
    },
}


def simple_preset_names() -> Tuple[str, ...]:
    """Return the canonical list of simple-mode preset names."""
    return tuple(_SIMPLE_PRESETS.keys())


def simple_preset_catalog() -> dict:
    """Return a deep copy of the preset catalogue for CLI rendering.

    Deep-copy is required because preset overrides may contain mutable
    values (lists for ``allowed_subnets`` / ``allowed_domains``); a
    shallow copy would let callers silently mutate the global preset
    definition by editing those nested lists in place.
    """
    return {
        name: {
            "description": entry["description"],
            "overrides": copy.deepcopy(entry["overrides"]),
        }
        for name, entry in _SIMPLE_PRESETS.items()
    }


def simple_preset_overrides(name: str) -> dict:
    """Return the flat dot-path overrides for a simple-mode preset.

    Raises ``ValueError`` for unknown preset names so CLI / programmatic
    callers fail loudly rather than silently applying nothing.

    Returns a deep copy so callers that mutate nested values
    (e.g. appending to a list) cannot leak that mutation back into
    ``_SIMPLE_PRESETS`` and corrupt later calls in the same process.
    """
    canonical = str(name or "").strip().lower()
    if canonical not in _SIMPLE_PRESETS:
        allowed = ", ".join(sorted(_SIMPLE_PRESETS))
        raise ValueError(
            f"Unknown simple-mode preset {name!r}. Expected one of: {allowed}"
        )
    return copy.deepcopy(_SIMPLE_PRESETS[canonical]["overrides"])


def apply_simple_preset(config_manager: Any, name: str) -> dict:
    """Apply a simple-mode preset to a ``ConfigManager``-like object.

    The argument is duck-typed: anything with a ``set(dot_path,
    value)`` method (i.e. ``ConfigManager``) is accepted, so callers
    don't need to import the class here. Returns the applied
    overrides dict for telemetry/logging.
    """
    overrides = simple_preset_overrides(name)
    setter = getattr(config_manager, "set", None)
    if not callable(setter):
        raise TypeError(
            "apply_simple_preset requires a ConfigManager-like object with a "
            "callable .set(dot_path, value) method"
        )
    for path, value in overrides.items():
        setter(path, value)
    return overrides


__all__ = [
    "apply_simple_preset",
    "get_ai_config",
    "get_mutation_config",
    "get_safety_config",
    "is_legacy_capability_enabled",
    "is_offline_ai",
    "resolve_output_root",
    "resolve_setting",
    "simple_preset_catalog",
    "simple_preset_names",
    "simple_preset_overrides",
]
