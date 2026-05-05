"""ModuleResult contract conformance test.

Iterates every module returned by ``build_runtime_modules()`` and exercises
its ``execute()`` in two safety modes:

* **lab_off** — legacy packs disabled, no lab confirmation. Standard modules
  must return a conformant ``ModuleResult``. Legacy adapters are allowed to
  *raise* ``RuntimeError`` (current behaviour: ``_ensure_allowed`` rejects
  disabled capabilities) OR return ``status="blocked"`` once they are
  migrated to the soft-block pattern. Either is recorded.

* **lab_simulate** — every legacy pack/capability enabled in simulate mode
  with lab confirmation. Every registered module must return a conformant
  ``ModuleResult`` with status in ``ALLOWED_STATUSES`` and the documented
  field shapes.

The test does NOT enforce specific status values beyond the allowed set; it
enforces shape + types + that ``module`` matches the registry name. Safety
behaviour (zero subprocess/network calls) is asserted in
``tests/test_module_safety.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import ALLOWED_STATUSES, ModuleResult, TelemetryEvent
from src.core.modules.registry import build_runtime_modules


# ---------------------------------------------------------------------------
# Config / context helpers
# ---------------------------------------------------------------------------


def _lab_off_config() -> Dict[str, Any]:
    """Default-safe config: legacy packs off, dry-run on."""
    return {
        "general": {"dry_run": True, "safeties": {"max_runtime": 60, "allowed_subnets": []}},
        "modules": {
            "execution": {"allow_real_execution": False, "timeout_seconds": 5},
            "legacy": {
                "enable_all_lab_capabilities": False,
                "global_mode": "simulate",
                "lab_confirmation": False,
                "actor_pack": {"enabled": False},
                "c2_pack": {"enabled": False},
                "stealth_pack": {"enabled": False},
            },
        },
    }


def _lab_simulate_config() -> Dict[str, Any]:
    """All legacy capability packs enabled in simulate mode with lab confirmation."""
    cfg = _lab_off_config()
    legacy = cfg["modules"]["legacy"]
    legacy["enable_all_lab_capabilities"] = True
    legacy["lab_confirmation"] = True
    legacy["global_mode"] = "simulate"
    legacy["actor_pack"] = {
        "enabled": True,
        "mode": "simulate",
        "lab_confirmation": True,
        "capabilities": {
            k: {"enabled": True, "mode": "simulate"}
            for k in ("apt29", "apt28", "apt32", "apt38", "apt41", "actor_profile")
        },
    }
    legacy["c2_pack"] = {
        "enabled": True,
        "mode": "simulate",
        "lab_confirmation": True,
        "capabilities": {
            k: {"enabled": True, "mode": "simulate"}
            for k in (
                "dns_tunneling",
                "tls_fast_flux",
                "websocket_quic",
                "solana_rpc",
                "network_obfuscator_legacy",
            )
        },
    }
    legacy["stealth_pack"] = {
        "enabled": True,
        "mode": "simulate",
        "lab_confirmation": True,
        "capabilities": {
            k: {"enabled": True, "mode": "simulate"}
            for k in ("anti_forensic", "anti_sandbox", "anti_detection_legacy", "dynamic_api")
        },
    }
    return cfg


def _make_context(tmp_path: Path, config: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "run_id": "contract-test-run",
        "output_dir": tmp_path,
        "config": config,
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": ["127.0.0.1/32"],
    }


# Per-module dry-run-safe params. Each entry only includes the params the
# module documents/uses — we are not stress-testing param validation here.
_MINIMAL_PARAMS: Dict[str, Dict[str, Any]] = {
    "initial_access": {"vector": "phishing_email", "target": "lab-user"},
    "execution": {"command": "echo simulated"},
    "persistence": {"technique": "scheduled_task"},
    "defense_evasion": {"technique": "argument_spoofing"},
    "discovery": {"targets": ["127.0.0.1"]},
    "exfiltration": {"method": "via_c2"},
    "command_control": {"channel": "http", "c2_url": "https://example.invalid/c2"},
    "anti_detection": {"method": "memory_evasion"},
    "intelligence": {"focus": "apt29"},
    "network_obfuscator": {"protocol": "dns"},
    "resource_development": {"resource_type": "infrastructure"},
    "reconnaissance": {"source": "osint"},
    "collection": {"technique": "file_staging", "target": "lab-host"},
    "legacy_capability_summary": {},
    "legacy_actor_profile": {"actor": "apt29", "tactics": ["credential_access"]},
    "legacy_apt29_research": {"technique": "phishing", "target": "lab-user"},
    "legacy_apt28_research": {"technique": "phishing", "target": "lab-user"},
    "legacy_apt32_research": {"technique": "phishing", "target": "lab-user"},
    "legacy_apt38_research": {"technique": "phishing", "target": "lab-user"},
    "legacy_apt41_research": {"technique": "phishing", "target": "lab-user"},
    "legacy_protocol_research": {"protocol": "dns_tunneling"},
    "legacy_stealth_research": {"capability": "anti_forensic"},
}


def _params_for(name: str) -> Dict[str, Any]:
    return dict(_MINIMAL_PARAMS.get(name, {}))


# ---------------------------------------------------------------------------
# Shape assertions
# ---------------------------------------------------------------------------


def _assert_module_result_shape(name: str, result: Any) -> None:
    assert isinstance(result, ModuleResult), (
        f"{name}.execute() returned {type(result).__name__}, expected ModuleResult"
    )
    assert result.module == name, (
        f"{name}.execute() returned ModuleResult with module={result.module!r}; "
        f"expected {name!r}"
    )
    assert result.status in ALLOWED_STATUSES, (
        f"{name}.execute() returned non-standard status {result.status!r}; "
        f"expected one of {sorted(ALLOWED_STATUSES)}"
    )
    assert isinstance(result.message, str), f"{name}.message must be str"
    assert isinstance(result.techniques, list), f"{name}.techniques must be list"
    for tech in result.techniques:
        assert isinstance(tech, str), f"{name}.techniques entries must be str"
    assert isinstance(result.artifacts, dict), f"{name}.artifacts must be dict"
    assert isinstance(result.detection_hints, dict), f"{name}.detection_hints must be dict"
    assert isinstance(result.telemetry, list), f"{name}.telemetry must be list"
    for event in result.telemetry:
        assert isinstance(event, TelemetryEvent), (
            f"{name}.telemetry entries must be TelemetryEvent, got {type(event).__name__}"
        )
        assert event.module == name, (
            f"{name}.telemetry event has module={event.module!r}, expected {name!r}"
        )
    assert result.error is None or isinstance(result.error, str), (
        f"{name}.error must be None or str"
    )


# ---------------------------------------------------------------------------
# Discovery: parametrize over every registered module
# ---------------------------------------------------------------------------


def _all_module_names() -> list[str]:
    return sorted(build_runtime_modules().keys())


@pytest.fixture(scope="module")
def runtime_modules() -> Dict[str, Any]:
    return build_runtime_modules()


@pytest.mark.parametrize("module_name", _all_module_names())
def test_module_returns_conformant_result_in_lab_simulate_mode(
    module_name: str, runtime_modules: Dict[str, Any], tmp_path: Path
) -> None:
    """Every module must return a conformant ModuleResult with all packs in simulate mode."""
    cfg = _lab_simulate_config()
    module = runtime_modules[module_name]
    # Push the module-relevant config slice into the module instance.
    module_cfg = dict(cfg["modules"].get(module_name, {}))
    module_cfg["config_root"] = cfg
    if module_name.startswith("legacy_"):
        module_cfg["enabled"] = True
        module_cfg["mode"] = "simulate"
        module_cfg["lab_confirmation"] = True
    module.update_config(module_cfg)
    context = _make_context(tmp_path, cfg)

    result = module.execute(_params_for(module_name), context)
    _assert_module_result_shape(module_name, result)


@pytest.mark.parametrize("module_name", _all_module_names())
def test_module_lab_off_either_returns_or_raises_safely(
    module_name: str, runtime_modules: Dict[str, Any], tmp_path: Path
) -> None:
    """With lab off, modules must either return a conformant result or raise RuntimeError.

    Standard modules return success (they don't depend on lab gates). Legacy
    adapters today raise RuntimeError via ``_ensure_allowed``; once migrated
    to a soft-block pattern they will return ``status="blocked"``. Either
    behaviour is accepted here; arbitrary exception types are not.
    """
    cfg = _lab_off_config()
    module = runtime_modules[module_name]
    module_cfg = dict(cfg["modules"].get(module_name, {}))
    module_cfg["config_root"] = cfg
    if module_name.startswith("legacy_"):
        module_cfg["enabled"] = False
        module_cfg["mode"] = "simulate"
        module_cfg["lab_confirmation"] = False
    module.update_config(module_cfg)
    context = _make_context(tmp_path, cfg)

    try:
        result = module.execute(_params_for(module_name), context)
    except RuntimeError:
        # Acceptable transitional behaviour for legacy adapters.
        return
    _assert_module_result_shape(module_name, result)


def test_registry_has_no_duplicate_module_names(runtime_modules: Dict[str, Any]) -> None:
    names = list(runtime_modules.keys())
    assert len(names) == len(set(names)), f"duplicate module names: {names}"


def test_registry_module_name_matches_class_name(runtime_modules: Dict[str, Any]) -> None:
    for name, instance in runtime_modules.items():
        assert instance.name == name, (
            f"registry key {name!r} does not match instance.name {instance.name!r}"
        )
