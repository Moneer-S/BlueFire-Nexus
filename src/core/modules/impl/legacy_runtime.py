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


# Per-tactic dispatch tables for the preserved legacy classes.
#
# Earlier versions of these helpers fed a single-key payload like
# ``{"browser": {...}}`` into the staged-pipeline entrypoint of each
# legacy class (``CredentialAccess.access``, ``LateralMovement.move``,
# ``PrivilegeEscalation.escalate``, ``Impact.impact``, ``Collection.collect``).
# Those entrypoints chain three sub-stages and pass each stage's RESULT
# (not the original payload) to the next stage. So a payload meant for
# the second or third stage was silently dropped — the helper returned
# an empty `details` dict.
#
# The fix below dispatches directly to the per-technique handler method
# (``_handle_<method>``) the preserved class already exposes. The third
# field of each dispatch tuple is therefore the handler-method *suffix*,
# not a stage-input key. ``branch`` is retained only for diagnostic
# telemetry on the adapter so reports still distinguish staging vs.
# capture vs. compression results.
#
# This also resolves the privilege-escalation ``creation`` collision:
# token_creation -> ``_handle_creation`` (token branch),
# service_creation -> ``_handle_service_creation`` (service branch).


def _dispatch_legacy_handler(
    legacy: Any, method: str, params: Mapping[str, Any]
) -> Dict[str, Any]:
    """Call ``legacy._handle_<method>(dict(params))`` defensively.

    Returns an empty dict if the method does not exist (so an
    incorrectly registered dispatch row surfaces as empty details
    rather than an AttributeError) or if the handler raises (so
    `safe_call` upstream can normalise the failure shape).
    """
    handler = getattr(legacy, f"_handle_{method}", None)
    if handler is None:
        return {}
    outcome = handler(dict(params))
    if not isinstance(outcome, Mapping):
        return {}
    return dict(outcome)


def _legacy_runtime_result(
    technique: str,
    legacy_method: str,
    mitre: str,
    branch_outcome: Mapping[str, Any],
) -> Dict[str, Any]:
    """Normalise a legacy handler's outcome into the adapter's runtime shape."""
    status = str(branch_outcome.get("status", "completed"))
    if status not in {"success", "completed", "error", "failure"}:
        status = "completed"
    return {
        "status": status,
        "technique": technique,
        "legacy_method": legacy_method,
        # `legacy_key` retained for backward compatibility with adapters
        # / telemetry consumers that already field this name.
        "legacy_key": legacy_method,
        "mitre_technique": mitre,
        "details": dict(branch_outcome.get("details", {})),
        "timestamp": branch_outcome.get("timestamp", ""),
    }


# CredentialAccess: (legacy_handler_method, canonical_mitre).
# Legacy class methods: _handle_lsass / _handle_sam / _handle_ntds
# (dumping); _handle_browser / _handle_keychain / _handle_ssh
# (extraction); _handle_keylogging / _handle_clipboard / _handle_screen
# (interception).
CREDENTIAL_TECHNIQUE_KEYS: Dict[str, tuple[str, str]] = {
    "lsass_dump": ("lsass", "T1003.001"),
    "sam_dump": ("sam", "T1003.002"),
    "ntds_dump": ("ntds", "T1003.003"),
    "browser_credentials": ("browser", "T1555.003"),
    "keychain": ("keychain", "T1555.001"),
    "ssh_keys": ("ssh", "T1552.004"),
    "keylogging": ("keylogging", "T1056.001"),
    "clipboard": ("clipboard", "T1115"),
    "screen_capture": ("screen", "T1113"),
}


def run_credential_access(technique: str, params: Mapping[str, Any]) -> Dict[str, Any]:
    """Invoke the per-technique handler on the preserved `CredentialAccess` class."""
    legacy_method, mitre = CREDENTIAL_TECHNIQUE_KEYS.get(
        technique, ("lsass", "T1003.001")
    )
    cls = _load_attr("src.core.credential.credential_access", "CredentialAccess")
    legacy = cls()
    branch_outcome = _dispatch_legacy_handler(legacy, legacy_method, params)
    return _legacy_runtime_result(technique, legacy_method, mitre, branch_outcome)


# LateralMovement: (branch, legacy_handler_method, canonical_mitre).
# Branch is for telemetry only. Service-branch methods are
# ``_handle_service_creation`` / ``_handle_service_modification`` /
# ``_handle_service_stop``, distinct from the data-key names
# (``creation`` / ``modification`` / ``stop``) used by the staged-
# pipeline entrypoint.
LATERAL_MOVEMENT_TECHNIQUE_KEYS: Dict[str, tuple[str, str, str]] = {
    "psexec": ("execution", "psexec", "T1021.002"),
    "wmi": ("execution", "wmi", "T1047"),
    "powershell_remoting": ("execution", "powershell", "T1059.001"),
    "winrm": ("execution", "powershell", "T1021.006"),
    "smb_share": ("file", "smb", "T1021.002"),
    "ftp_transfer": ("file", "ftp", "T1105"),
    "scp_transfer": ("file", "scp", "T1105"),
    "service_create": ("service", "service_creation", "T1543.003"),
    "service_modify": ("service", "service_modification", "T1543.003"),
    "service_stop": ("service", "service_stop", "T1489"),
}


def run_lateral_movement(technique: str, params: Mapping[str, Any]) -> Dict[str, Any]:
    """Invoke the per-technique handler on the preserved `LateralMovement` class."""
    _branch, legacy_method, mitre = LATERAL_MOVEMENT_TECHNIQUE_KEYS.get(
        technique, ("execution", "psexec", "T1021.002")
    )
    cls = _load_attr("src.core.movement.lateral_movement", "LateralMovement")
    legacy = cls()
    branch_outcome = _dispatch_legacy_handler(legacy, legacy_method, params)
    return _legacy_runtime_result(technique, legacy_method, mitre, branch_outcome)


# PrivilegeEscalation: (branch, legacy_handler_method, canonical_mitre).
# Token-branch ``creation`` collides with service-branch ``creation``
# under the staged-pipeline entrypoint, so dispatch goes through the
# per-method names: ``_handle_creation`` (token, T1134.003) vs.
# ``_handle_service_creation`` (service, T1543.003). They are distinct
# methods on the legacy class — see `_handle_creation` (token) and
# `_handle_service_creation` (service) in
# `src/core/privilege/privilege_escalation.py`.
PRIVILEGE_ESCALATION_TECHNIQUE_KEYS: Dict[str, tuple[str, str, str]] = {
    "token_impersonation": ("token", "impersonation", "T1134.001"),
    "token_duplication": ("token", "duplication", "T1134.002"),
    "token_creation": ("token", "creation", "T1134.003"),
    "process_hollowing": ("process", "hollowing", "T1055.012"),
    "process_injection": ("process", "injection", "T1055"),
    "process_masquerading": ("process", "masquerading", "T1036.005"),
    "service_creation": ("service", "service_creation", "T1543.003"),
    "service_modification": ("service", "service_modification", "T1543.003"),
    "service_stop": ("service", "service_stop", "T1489"),
}


def run_privilege_escalation(
    technique: str, params: Mapping[str, Any]
) -> Dict[str, Any]:
    """Invoke the per-technique handler on the preserved `PrivilegeEscalation` class."""
    _branch, legacy_method, mitre = PRIVILEGE_ESCALATION_TECHNIQUE_KEYS.get(
        technique, ("token", "impersonation", "T1134.001")
    )
    cls = _load_attr("src.core.privilege.privilege_escalation", "PrivilegeEscalation")
    legacy = cls()
    branch_outcome = _dispatch_legacy_handler(legacy, legacy_method, params)
    return _legacy_runtime_result(technique, legacy_method, mitre, branch_outcome)


# Impact: (branch, legacy_handler_method, canonical_mitre).
# Service-branch methods on the legacy class are ``_handle_service_stop``
# / ``_handle_service_modify`` / ``_handle_service_delete``. System-
# branch methods are ``_handle_reboot`` / ``_handle_shutdown`` /
# ``_handle_crash``.
IMPACT_TECHNIQUE_KEYS: Dict[str, tuple[str, str, str]] = {
    "data_encryption": ("data", "encryption", "T1486"),
    "data_destruction": ("data", "deletion", "T1485"),
    "data_manipulation": ("data", "modification", "T1565"),
    "service_stop": ("service", "service_stop", "T1489"),
    "service_modify": ("service", "service_modify", "T1543.003"),
    "service_delete": ("service", "service_delete", "T1543.003"),
    "system_reboot": ("system", "reboot", "T1529"),
    "system_shutdown": ("system", "shutdown", "T1529"),
    "endpoint_dos": ("system", "crash", "T1499"),
}


def run_impact(technique: str, params: Mapping[str, Any]) -> Dict[str, Any]:
    """Invoke the per-technique handler on the preserved `Impact` class."""
    _branch, legacy_method, mitre = IMPACT_TECHNIQUE_KEYS.get(
        technique, ("data", "encryption", "T1486")
    )
    cls = _load_attr("src.core.impact.impact", "Impact")
    legacy = cls()
    branch_outcome = _dispatch_legacy_handler(legacy, legacy_method, params)
    return _legacy_runtime_result(technique, legacy_method, mitre, branch_outcome)


# Collection: (branch, legacy_handler_method, canonical_mitre).
# Methods on the legacy class are ``_handle_file_staging`` /
# ``_handle_directory_staging`` / ``_handle_archive_staging``
# (staging); ``_handle_keyboard_capture`` / ``_handle_clipboard_capture``
# / ``_handle_screen_capture`` (capture); ``_handle_compression`` /
# ``_handle_encryption`` / ``_handle_encoding`` (compression).
COLLECTION_TECHNIQUE_KEYS: Dict[str, tuple[str, str, str]] = {
    "file_staging": ("staging", "file_staging", "T1074.001"),
    "directory_staging": ("staging", "directory_staging", "T1074.001"),
    "archive_staging": ("staging", "archive_staging", "T1560.001"),
    "keyboard_capture": ("capture", "keyboard_capture", "T1056.001"),
    "clipboard_capture": ("capture", "clipboard_capture", "T1115"),
    "screen_capture": ("capture", "screen_capture", "T1113"),
    "compression": ("compression", "compression", "T1560"),
    "encryption": ("compression", "encryption", "T1022"),
    "encoding": ("compression", "encoding", "T1132"),
}


def run_collection(technique: str, params: Mapping[str, Any]) -> Dict[str, Any]:
    """Invoke the per-technique handler on the preserved `Collection` class."""
    _branch, legacy_method, mitre = COLLECTION_TECHNIQUE_KEYS.get(
        technique, ("staging", "file_staging", "T1074.001")
    )
    cls = _load_attr("src.core.collection.collection", "Collection")
    legacy = cls()
    branch_outcome = _dispatch_legacy_handler(legacy, legacy_method, params)
    return _legacy_runtime_result(technique, legacy_method, mitre, branch_outcome)


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
