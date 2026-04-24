"""Runtime helpers that execute legacy capability code safely in adapter modules."""

from __future__ import annotations

import importlib
import platform
from typing import Any, Callable, Dict, Mapping
from urllib.parse import urlparse

from ...models import TelemetryEvent

ACTOR_IMPORTS: Dict[str, tuple[str, str]] = {
    "apt29": ("src.core.actors.apt29", "APT29"),
    "apt28": ("src.core.actors.apt28", "APT28"),
    "apt32": ("src.core.actors.apt32", "APT32"),
    "apt38": ("src.core.actors.apt38", "APT38"),
    "apt41": ("src.core.actors.apt41", "APT41"),
}


def normalize_protocol_key(protocol: str) -> str:
    value = str(protocol or "").lower().strip()
    aliases = {
        "dns": "dns_tunneling",
        "dns_tunnel": "dns_tunneling",
        "quic_c2": "websocket_quic",
        "quic": "websocket_quic",
        "network_obfuscator": "network_obfuscator_legacy",
    }
    return aliases.get(value, value or "dns_tunneling")


def normalize_stealth_key(capability: str) -> str:
    value = str(capability or "").lower().strip()
    aliases = {
        "anti_detection": "anti_detection_legacy",
    }
    return aliases.get(value, value or "anti_forensic")


def _load_attr(module_path: str, attr_name: str) -> Any:
    module = importlib.import_module(module_path)
    return getattr(module, attr_name)


def _host_from_endpoint(endpoint: str) -> str:
    if "://" in endpoint:
        return (urlparse(endpoint).hostname or "").lower()
    return endpoint.split("/", 1)[0].split(":", 1)[0].lower()


def instantiate_apt_actor(actor: str) -> Any:
    """Instantiate a legacy actor profile with graceful fallback."""
    actor_key = actor.lower()
    module_path, class_name = ACTOR_IMPORTS.get(actor_key, ACTOR_IMPORTS["apt29"])
    cls = _load_attr(module_path, class_name)
    return cls()


def run_actor_technique(
    actor_name: str,
    tactic: str,
    technique: str,
    params: Mapping[str, Any],
) -> Dict[str, Any]:
    """Run one actor technique and normalize output for adapter consumers."""
    actor = instantiate_apt_actor(actor_name)
    if hasattr(actor, "execute_technique"):
        raw = actor.execute_technique(tactic, technique, **dict(params))
        if isinstance(raw, Mapping):
            payload = dict(raw)
            payload.setdefault("actor", actor_name.upper())
            payload.setdefault("tactic", tactic)
            payload.setdefault("technique", technique)
            if "status" not in payload:
                payload["status"] = "success" if payload.get("success", False) else "completed"
            return payload
    return {
        "status": "completed",
        "actor": actor_name.upper(),
        "tactic": tactic,
        "technique": technique,
        "parameters": dict(params),
    }


def run_dns_tunneling(endpoint: str, data: bytes) -> Dict[str, Any]:
    tunnel_cls = _load_attr("src.operators.c2_protocols.dns_tunneling", "DNSTunnel")
    domain = _host_from_endpoint(endpoint) or "example.lab"
    tunnel = tunnel_cls(domain=domain)
    tunnel.exfil(data)
    return {
        "status": "success",
        "protocol": "dns_tunneling",
        "endpoint": endpoint,
        "domain": domain,
        "record_type": "TXT",
        "size": len(data),
        "chunk_size": 48,
    }


def run_tls_fast_flux(endpoint: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    cls = _load_attr("src.operators.c2_protocols.tls_fast_flux", "TLSFlux")
    flux = cls(endpoints=[endpoint])
    response = flux.beacon(dict(payload))
    code = getattr(response, "status_code", None)
    return {
        "status": "success",
        "protocol": "tls_fast_flux",
        "endpoint": endpoint,
        "status_code": code,
        "rotation_count": 1,
    }


def run_solana_rpc(endpoint: str, instruction: str) -> Dict[str, Any]:
    cls = _load_attr("src.operators.c2_protocols.solana_rpc", "SolanaC2")
    client = cls(program_id="LegacyProgram1111111111111111111111111111111111", endpoint=endpoint)
    tx = client.send_command(instruction)
    return {
        "status": "success",
        "protocol": "solana_rpc",
        "endpoint": endpoint,
        "instruction": instruction,
        "tx": str(tx),
    }


def run_quic_placeholder(endpoint: str) -> Dict[str, Any]:
    # QUIC class is server oriented; import check avoids starting long-lived listeners.
    _load_attr("src.operators.c2_protocols.websocket_quic", "QUICC2")
    return {
        "status": "prepared",
        "protocol": "quic_c2",
        "endpoint": endpoint,
        "transport": "udp",
    }


def run_network_obfuscation(payload: Mapping[str, Any]) -> Dict[str, Any]:
    cls = _load_attr("src.core.network.network_obfuscator", "NetworkObfuscator")
    obfuscator = cls()
    result = obfuscator.obfuscate_traffic(dict(payload))
    return {
        "status": "success",
        "protocol": "network_obfuscator_legacy",
        "result": result,
    }


def run_stealth_capability(capability: str, params: Mapping[str, Any]) -> Dict[str, Any]:
    cap = normalize_stealth_key(capability)
    runtime_cap = "anti_detection" if cap == "anti_detection_legacy" else cap
    if cap == "anti_forensic":
        manager_cls = _load_attr("src.core.anti_forensic", "AntiForensicManager")
        manager = manager_cls()
        return {
            "status": "success",
            "capability": cap,
            "sandbox_detected": bool(manager.detect_sandbox()),
            "evasion": manager.evade_detection(),
        }
    if runtime_cap == "anti_detection":
        manager_cls = _load_attr("src.core.anti_detection", "AntiDetectionManager")
        manager = manager_cls()
        return {
            "status": "success",
            "capability": "anti_detection_legacy",
            "environment_checks": manager.check_environment(),
            "evasion": manager.evade_detection(),
        }
    if cap == "anti_sandbox":
        validator_cls = _load_attr("src.core.anti_sandbox", "EnvironmentValidator")
        validator = validator_cls()
        return {
            "status": "success",
            "capability": cap,
            "debugging": bool(validator.is_debugging()),
            "sandbox_detected": bool(validator.detect_sandbox()),
            "memory_ok": bool(validator.check_memory()),
        }
    if cap == "dynamic_api":
        resolver_cls = _load_attr("src.core.dynamic_api", "StealthAPIResolver")
        api_hash = str(params.get("api_hash", "0xA3D82B19"))
        resolver = resolver_cls()
        resolved = resolver.resolve(api_hash)
        resolved_name = getattr(resolved, "__name__", str(resolved))
        return {
            "status": "success",
            "capability": cap,
            "api_hash": api_hash,
            "resolved": resolved_name,
        }
    return {"status": "skipped", "capability": cap}


def build_legacy_event(
    module: str,
    event_type: str,
    run_id: str,
    details: Mapping[str, Any],
    *,
    severity: str = "info",
) -> TelemetryEvent:
    payload = {"run_id": run_id, "platform": platform.system(), **dict(details)}
    return TelemetryEvent(
        event_type=event_type,
        module=module,
        details=payload,
        severity=severity,
    )


def safe_call(action: Callable[..., Dict[str, Any]], *args: Any, **kwargs: Any) -> Dict[str, Any]:
    try:
        return action(*args, **kwargs)
    except Exception as exc:
        return {"status": "failure", "error": str(exc)}


def flatten_indicators(result: Mapping[str, Any]) -> Dict[str, Any]:
    """Extract compact detection-relevant fields from heterogeneous legacy results."""
    flattened: Dict[str, Any] = {}
    for key in ("description", "status", "technique", "tactic", "actor", "capability"):
        if key in result:
            flattened[key] = result[key]

    details = result.get("details")
    if isinstance(details, Mapping):
        for key in (
            "command",
            "target",
            "sender",
            "campaign_id",
            "execution_method",
            "bypass_technique",
            "target_process",
            "protocol",
            "endpoint",
            "channel",
            "data_size",
        ):
            if key in details:
                flattened[key] = details[key]

    parameters = result.get("parameters")
    if isinstance(parameters, Mapping):
        for key in ("target", "command", "protocol", "endpoint"):
            if key in parameters and key not in flattened:
                flattened[key] = parameters[key]

    return flattened
