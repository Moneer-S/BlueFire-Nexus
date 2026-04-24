import logging
import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

import yaml
from dotenv import load_dotenv

from .legacy_controls import summarize_legacy_controls

LOGGER = logging.getLogger(__name__)
ENV_TEMPLATE_RE = re.compile(r"\{\{\s*env\s+([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


class ConfigManager:
    """Load and persist BlueFire-Nexus configuration."""

    def __init__(self, config_path: str = "config.yaml") -> None:
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self._load_env()
        self._load_config()

    def _load_env(self) -> None:
        """Load .env variables if present."""
        load_dotenv(override=False)

    def _default_config(self) -> Dict[str, Any]:
        """Safe-by-default configuration with no remote egress."""
        return {
            "general": {
                "name": "BlueFire-Nexus",
                "version": "2.0.0",
                "mode": "simulation",
                "log_level": os.getenv("LOG_LEVEL", "INFO"),
                "dry_run": True,
                "safeties": {
                    "auto_wipe": False,
                    "max_runtime": 3600,
                    "allowed_subnets": ["10.0.0.0/24"],
                    "allowed_domains": ["*.example.lab", "example.lab", "localhost"],
                },
            },
            "modules": {
                "ai": {
                    "enabled": False,
                    "provider": "template",
                    "model": "default",
                    "api_base": "",
                },
                "legacy": {
                    "enable_all_lab_capabilities": False,
                    "global_mode": "simulate",
                    "active_preset": "",
                    "global_lab_acknowledged": False,
                    "lab_confirmation": False,
                    "announce_activation": True,
                    "actor_pack": {
                        "enabled": False,
                        "mode": "simulate",
                        "lab_confirmation": False,
                        "capabilities": {
                            "apt29": {"enabled": False, "lab_confirmation": False},
                            "apt28": {"enabled": False, "lab_confirmation": False},
                            "apt32": {"enabled": False, "lab_confirmation": False},
                            "apt38": {"enabled": False, "lab_confirmation": False},
                            "apt41": {"enabled": False, "lab_confirmation": False},
                        },
                    },
                    "c2_pack": {
                        "enabled": False,
                        "mode": "simulate",
                        "lab_confirmation": False,
                        "capabilities": {
                            "dns_tunneling": {"enabled": False, "lab_confirmation": False},
                            "tls_fast_flux": {"enabled": False, "lab_confirmation": False},
                            "websocket_quic": {"enabled": False, "lab_confirmation": False},
                            "solana_rpc": {"enabled": False, "lab_confirmation": False},
                            "network_obfuscator_legacy": {
                                "enabled": False,
                                "lab_confirmation": False,
                            },
                        },
                    },
                    "stealth_pack": {
                        "enabled": False,
                        "mode": "simulate",
                        "lab_confirmation": False,
                        "capabilities": {
                            "anti_forensic": {"enabled": False, "lab_confirmation": False},
                            "anti_sandbox": {"enabled": False, "lab_confirmation": False},
                            "anti_detection_legacy": {
                                "enabled": False,
                                "lab_confirmation": False,
                            },
                            "dynamic_api": {"enabled": False, "lab_confirmation": False},
                        },
                    },
                },
                "command_control": {"enabled": False},
                "discovery": {"enabled": True},
                "execution": {"enabled": True},
                "persistence": {"enabled": True},
                "defense_evasion": {"enabled": True},
                "exfiltration": {"enabled": False},
                "network_obfuscator": {"enabled": True},
            },
            "ai_providers": {
                "openai": {
                    "api_key": "{{ env OPENAI_API_KEY }}",
                    "model": "gpt-4o-mini",
                    "api_base": "{{ env OPENAI_BASE_URL }}",
                },
                "anthropic": {
                    "api_key": "{{ env ANTHROPIC_API_KEY }}",
                    "model": "claude-3-5-sonnet-latest",
                },
                "google": {
                    "api_key": "{{ env GOOGLE_API_KEY }}",
                    "model": "gemini-1.5-pro",
                },
                "openai_compatible": {
                    "api_key": "{{ env OPENAI_COMPATIBLE_API_KEY }}",
                    "api_base": "{{ env OPENAI_COMPATIBLE_BASE_URL }}",
                    "model": "model-name",
                },
                "ollama": {
                    "api_base": "{{ env OLLAMA_BASE_URL }}",
                    "model": "llama3.1",
                },
                "template": {},
                "none": {},
            },
            "telemetry": {
                "enabled": True,
                "default_sink": "jsonl",
                "sinks": [
                    {
                        "type": "jsonl",
                        "enabled": True,
                    }
                ],
            },
            "copilot": {
                "enabled": False,
                "rag": {
                    "knowledge_paths": [
                        "README.md",
                        "docs/ARCHITECTURE.md",
                        "docs",
                    ],
                },
            },
        }

    def _load_config(self) -> None:
        """Load YAML config, creating a default file if missing."""
        if not self.config_path.exists():
            self._create_default_config()

        with self.config_path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}

        if not isinstance(loaded, dict):
            raise ValueError(f"Config at {self.config_path} must be a dictionary")

        merged = self._default_config()
        self._deep_merge(merged, loaded)
        self._normalize_legacy_config_aliases(merged)
        self.config = self._resolve_env_templates(merged)

    def _normalize_legacy_config_aliases(self, config: Dict[str, Any]) -> None:
        """Translate old legacy config keys into canonical runtime keys."""
        modules = config.get("modules", {})
        if not isinstance(modules, dict):
            return
        legacy = modules.get("legacy", {})
        if not isinstance(legacy, dict):
            return

        if "lab_mode" in legacy:
            if (
                "global_mode" not in legacy
                or str(legacy.get("global_mode", "simulate")).lower() == "simulate"
            ):
                legacy["global_mode"] = legacy.get("lab_mode")
        if "lab_acknowledged" in legacy:
            if not legacy.get("global_lab_acknowledged", False):
                legacy["global_lab_acknowledged"] = bool(legacy.get("lab_acknowledged"))
            if not legacy.get("lab_confirmation", False):
                legacy["lab_confirmation"] = bool(legacy.get("lab_acknowledged"))

        for pack_name in ("actor_pack", "c2_pack", "stealth_pack"):
            pack = legacy.get(pack_name, {})
            if not isinstance(pack, dict):
                continue
            if "lab_confirmation" not in pack and "lab_acknowledged" in pack:
                pack["lab_confirmation"] = bool(pack.get("lab_acknowledged"))

            capabilities = pack.get("capabilities", {})
            if not isinstance(capabilities, dict):
                continue
            for _capability_name, settings in capabilities.items():
                if not isinstance(settings, dict):
                    continue
                if settings.get("emulate_enabled", False) and "mode" not in settings:
                    settings["mode"] = "emulate"
                if "lab_confirmation" not in settings and settings.get("emulate_enabled", False):
                    settings["lab_confirmation"] = True

    def _create_default_config(self) -> None:
        """Write a safe default configuration file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        default_cfg = self._default_config()
        with self.config_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(default_cfg, handle, sort_keys=False)
        LOGGER.info("Created default configuration at %s", self.config_path)

    def _deep_merge(self, base: Dict[str, Any], incoming: Dict[str, Any]) -> None:
        """Recursively merge incoming values into base dict."""
        for key, value in incoming.items():
            if (
                key in base
                and isinstance(base[key], dict)
                and isinstance(value, dict)
            ):
                self._deep_merge(base[key], value)
                continue
            base[key] = value

    def _resolve_env_templates(self, value: Any) -> Any:
        """Resolve `{{ env VAR }}` templates in nested structures."""
        if isinstance(value, dict):
            return {k: self._resolve_env_templates(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._resolve_env_templates(v) for v in value]
        if isinstance(value, str):
            match = ENV_TEMPLATE_RE.fullmatch(value.strip())
            if match:
                return os.getenv(match.group(1), "")
        return value

    def legacy_activation_summary(self) -> Dict[str, Any]:
        """Return a concise view of global and granular legacy capability activation."""
        return summarize_legacy_controls(self.config)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from dot-notation key path."""
        value: Any = self.config
        for part in key.split("."):
            if not isinstance(value, dict) or part not in value:
                return default
            value = value[part]
        return value

    def set(self, key: str, value: Any) -> None:
        """Set a value by dot-notation path."""
        keys = key.split(".")
        current: Dict[str, Any] = self.config
        for part in keys[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        current[keys[-1]] = value

    def to_dict(self) -> Dict[str, Any]:
        """Return a deep copy of active config."""
        return deepcopy(self.config)

    def save(self) -> None:
        """Persist configuration to disk."""
        with self.config_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(self.config, handle, sort_keys=False)


config = ConfigManager()
