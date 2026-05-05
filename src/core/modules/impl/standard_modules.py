"""First-class module implementations for the orchestrator."""

from __future__ import annotations

import shlex
import subprocess  # nosec B404
from datetime import datetime, timezone
from typing import Any, Dict, Mapping

from ...models import ModuleResult, TelemetryEvent
from ..base import BaseModule


def _result(
    module: str,
    status: str,
    message: str,
    *,
    techniques: list[str] | None = None,
    artifacts: Dict[str, Any] | None = None,
    hints: Dict[str, Any] | None = None,
    telemetry: list[TelemetryEvent] | None = None,
    error: str | None = None,
) -> ModuleResult:
    return ModuleResult(
        status=status,
        module=module,
        message=message,
        techniques=techniques or [],
        artifacts=artifacts or {},
        detection_hints=hints or {},
        telemetry=telemetry or [],
        error=error,
    )


class InitialAccessModule(BaseModule):
    name = "initial_access"
    attack_techniques = ("T1566",)

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        vector = params.get("vector", "phishing_email")
        target = params.get("target", "lab-user")
        event = TelemetryEvent(
            event_type="initial_access_simulated",
            module=self.name,
            details={"vector": vector, "target": target, "run_id": context["run_id"]},
        )
        hints = {
            "title": f"Suspicious initial access vector: {vector}",
            "logsource": {"category": "email", "product": "generic"},
            "detection": {
                "selection": {"target.user": target, "vector": vector},
                "condition": "selection",
            },
            "mitre_technique": "T1566",
        }
        return _result(
            self.name,
            "success",
            f"Simulated initial access via {vector}",
            techniques=["T1566"],
            telemetry=[event],
            hints=hints,
            artifacts={"target": target, "vector": vector},
        )


class ExecutionModule(BaseModule):
    name = "execution"
    attack_techniques = ("T1059",)

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        command = str(params.get("command") or params.get("cmd") or "echo simulated-execution")
        allow_real = bool(self._config.get("allow_real_execution", False))
        dry_run = bool(context.get("dry_run", True))
        timeout = int(self._config.get("timeout_seconds", 10))

        if dry_run or not allow_real:
            output = f"[dry-run] would execute: {command}"
            status = "success"
            message = "Execution simulated safely (dry-run or real execution disabled)."
            rc = 0
        else:
            try:
                proc = subprocess.run(  # nosec B603
                    shlex.split(command),
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                output = (proc.stdout or "")[:4096]
                status = "success" if proc.returncode == 0 else "failure"
                message = f"Execution finished with return code {proc.returncode}."
                rc = proc.returncode
            except Exception as exc:
                return _result(
                    self.name,
                    "failure",
                    "Execution failed.",
                    techniques=["T1059"],
                    error=str(exc),
                )

        event = TelemetryEvent(
            event_type="execution",
            module=self.name,
            details={
                "command": command,
                "return_code": rc,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
        hints = {
            "title": "Suspicious command execution",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"process.command_line|contains": command.split(" ")[0]},
                "condition": "selection",
            },
            "mitre_technique": "T1059",
            "process_command_line": command,
        }
        return _result(
            self.name,
            status,
            message,
            techniques=["T1059"],
            telemetry=[event],
            hints=hints,
            artifacts={"command": command, "stdout": output, "return_code": rc},
        )


class PersistenceModule(BaseModule):
    name = "persistence"
    attack_techniques = ("T1053",)

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        technique = str(params.get("technique", "scheduled_task"))
        event = TelemetryEvent(
            event_type="persistence_simulated",
            module=self.name,
            details={"technique": technique, "run_id": context["run_id"]},
        )
        hints = {
            "title": f"Persistence behavior: {technique}",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"persistence.technique": technique},
                "condition": "selection",
            },
            "mitre_technique": "T1053",
        }
        return _result(
            self.name,
            "success",
            f"Simulated persistence technique {technique}.",
            techniques=["T1053"],
            telemetry=[event],
            hints=hints,
            artifacts={"technique": technique},
        )


class DefenseEvasionModule(BaseModule):
    name = "defense_evasion"
    attack_techniques = ("T1036", "T1070.006")

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        technique = str(params.get("technique", "argument_spoofing"))
        event = TelemetryEvent(
            event_type="defense_evasion_simulated",
            module=self.name,
            details={"technique": technique, "run_id": context["run_id"]},
        )
        hints = {
            "title": f"Defense evasion behavior: {technique}",
            "logsource": {"category": "process_creation", "product": "linux"},
            "detection": {"selection": {"evasion.technique": technique}, "condition": "selection"},
            "mitre_technique": "T1036",
        }
        return _result(
            self.name,
            "success",
            f"Simulated defense evasion technique {technique}.",
            techniques=["T1036"],
            telemetry=[event],
            hints=hints,
            artifacts={"technique": technique},
        )


# Discovery profile catalog: maps a `discovery_type` value to its MITRE
# technique, default Sigma-style logsource, default detection selection
# template, and the telemetry event type and synthetic artifact builder.
#
# Adding a new profile is a single entry here; the module body branches off
# `discovery_type` and uses these values to shape telemetry, artifacts, and
# detection hints. Keeping the catalog in code (not config) means the
# `tests/test_module_*.py` registry-wide tests cover every entry.
_DISCOVERY_PROFILES: Dict[str, Dict[str, Any]] = {
    "network_scan": {
        "mitre": "T1046",
        "logsource": {"category": "network_connection", "product": "linux"},
        "selection_field": "network.target|in",
        "title_prefix": "Network/service discovery against",
        "event_type": "discovery_network_scan",
    },
    "host_discovery": {
        "mitre": "T1018",
        "logsource": {"category": "network_connection", "product": "linux"},
        "selection_field": "network.target|in",
        "title_prefix": "Remote host discovery against",
        "event_type": "discovery_host_enumeration",
    },
    "port_scan": {
        "mitre": "T1046",
        "logsource": {"category": "network_connection", "product": "linux"},
        "selection_field": "network.target|in",
        "title_prefix": "Port/service scan against",
        "event_type": "discovery_port_scan",
    },
    "service_scan": {
        "mitre": "T1046",
        "logsource": {"category": "network_connection", "product": "linux"},
        "selection_field": "network.target|in",
        "title_prefix": "Service-version scan against",
        "event_type": "discovery_service_scan",
    },
    "system_info": {
        "mitre": "T1082",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "title_prefix": "System information enumeration on",
        "event_type": "discovery_system_info",
    },
    "process_info": {
        "mitre": "T1057",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "title_prefix": "Process enumeration on",
        "event_type": "discovery_process_info",
    },
    "service_info": {
        "mitre": "T1007",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "title_prefix": "System service enumeration on",
        "event_type": "discovery_service_info",
    },
    "user_info": {
        "mitre": "T1087",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "title_prefix": "Account enumeration on",
        "event_type": "discovery_user_info",
    },
    "group_info": {
        "mitre": "T1069",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "title_prefix": "Permission group enumeration on",
        "event_type": "discovery_group_info",
    },
    "files": {
        "mitre": "T1083",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.path|contains",
        "title_prefix": "File and directory enumeration on",
        "event_type": "discovery_file_enumeration",
    },
}


class DiscoveryModule(BaseModule):
    name = "discovery"
    attack_techniques = ("T1046", "T1018", "T1082", "T1057", "T1007", "T1087", "T1069", "T1083")

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        targets_raw = params.get("targets") or context.get("allowed_subnets", [])
        if isinstance(targets_raw, str):
            targets = [targets_raw]
        else:
            targets = list(targets_raw)

        # `discovery_type` selects the catalog entry. Honour it explicitly so
        # scenarios that pass `discovery_type: files` etc. produce different
        # telemetry/detections rather than the old one-size-fits-all shape.
        # Unknown values fall back to `network_scan` to preserve existing
        # behaviour.
        requested_type = str(params.get("discovery_type") or "network_scan").lower()
        profile_key = requested_type if requested_type in _DISCOVERY_PROFILES else "network_scan"
        profile = _DISCOVERY_PROFILES[profile_key]

        # `network_touch=False` is the documented "planning only" hint:
        # synthesise telemetry shape WITHOUT enumerating discovered targets.
        # Default is True (matches prior behaviour for scenarios that don't
        # set the flag).
        network_touch = bool(params.get("network_touch", True))
        if network_touch:
            discovered = [{"target": t, "status": "simulated_up"} for t in targets]
        else:
            discovered = []

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details={
                "discovery_type": profile_key,
                "targets": targets,
                "discovered_count": len(discovered),
                "network_touch": network_touch,
                "mitre_technique": profile["mitre"],
            },
        )
        title_target = ", ".join(targets) if targets else "lab subnets"
        hints = {
            "title": f"{profile['title_prefix']} {title_target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: targets or ["lab"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "discovery_type": profile_key,
            "network_targets": targets,
            "network_touch": network_touch,
        }
        if requested_type != profile_key:
            hints["unrecognized_discovery_type"] = requested_type

        message = (
            f"Simulated {profile_key} discovery against {len(discovered)} targets."
            if network_touch
            else f"Planned {profile_key} discovery for {len(targets)} targets (no network touch)."
        )
        return _result(
            self.name,
            "success",
            message,
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "discovery_type": profile_key,
                "targets": targets,
                "discovered": discovered,
                "network_touch": network_touch,
            },
        )


class ExfiltrationModule(BaseModule):
    name = "exfiltration"
    attack_techniques = ("T1041",)

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        method = str(params.get("method", "via_c2"))
        if params.get("destructive", False) and not params.get("i_understand_this_is_a_lab", False):
            return _result(
                self.name,
                "failure",
                "Destructive exfiltration simulation requires explicit lab acknowledgment.",
                techniques=["T1041"],
                error="missing_lab_acknowledgment",
            )
        artifact_name = f"exfil_{context['run_id']}.txt"
        event = TelemetryEvent(
            event_type="exfiltration_simulated",
            module=self.name,
            details={"method": method, "artifact": artifact_name},
        )
        hints = {
            "title": "Potential data exfiltration",
            "logsource": {"category": "network_connection", "product": "windows"},
            "detection": {"selection": {"exfil.method": method}, "condition": "selection"},
            "mitre_technique": "T1041",
            "network_method": method,
        }
        return _result(
            self.name,
            "success",
            f"Simulated exfiltration via {method}.",
            techniques=["T1041"],
            telemetry=[event],
            hints=hints,
            artifacts={"method": method, "artifact_name": artifact_name},
        )


class CommandControlModule(BaseModule):
    name = "command_control"
    attack_techniques = ("T1071.001",)

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        channel = str(params.get("channel", "http"))
        c2_url = str(params.get("c2_url", "https://example.invalid/c2"))
        event = TelemetryEvent(
            event_type="c2_beacon_simulated",
            module=self.name,
            details={"channel": channel, "c2_url": c2_url},
        )
        hints = {
            "title": "Application-layer C2 communication",
            "logsource": {"category": "network_connection", "product": "windows"},
            "detection": {"selection": {"network.url|contains": c2_url}, "condition": "selection"},
            "mitre_technique": "T1071.001",
            "network_url": c2_url,
        }
        return _result(
            self.name,
            "success",
            f"Simulated C2 beacon over {channel}.",
            techniques=["T1071.001"],
            telemetry=[event],
            hints=hints,
            artifacts={"channel": channel, "c2_url": c2_url},
        )


class AntiDetectionModule(BaseModule):
    name = "anti_detection"
    attack_techniques = ("T1027",)

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        method = str(params.get("method", "memory_evasion"))
        event = TelemetryEvent(
            event_type="anti_detection_simulated",
            module=self.name,
            details={"method": method},
        )
        hints = {
            "title": "Obfuscated data or anti-detection behavior",
            "logsource": {"category": "process_creation", "product": "linux"},
            "detection": {"selection": {"anti_detection.method": method}, "condition": "selection"},
            "mitre_technique": "T1027",
        }
        return _result(
            self.name,
            "success",
            f"Simulated anti-detection method {method}.",
            techniques=["T1027"],
            telemetry=[event],
            hints=hints,
            artifacts={"method": method},
        )


class IntelligenceModule(BaseModule):
    name = "intelligence"
    attack_techniques = ("T1595",)

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        focus = str(params.get("focus", "apt29"))
        event = TelemetryEvent(
            event_type="intelligence_collection_simulated",
            module=self.name,
            details={"focus": focus},
        )
        hints = {
            "title": f"Intelligence collection focus: {focus}",
            "logsource": {"category": "threat_intelligence", "product": "generic"},
            "detection": {
                "selection": {"intelligence.focus": focus},
                "condition": "selection",
            },
            "mitre_technique": "T1595",
        }
        return _result(
            self.name,
            "success",
            f"Collected simulated intelligence for {focus}.",
            techniques=["T1595"],
            telemetry=[event],
            hints=hints,
            artifacts={"focus": focus, "confidence": "medium"},
        )


class NetworkObfuscatorModule(BaseModule):
    name = "network_obfuscator"
    attack_techniques = ("T1572",)

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        protocol = str(params.get("protocol", "dns"))
        event = TelemetryEvent(
            event_type="network_obfuscation_simulated",
            module=self.name,
            details={"protocol": protocol},
        )
        hints = {
            "title": f"Network protocol obfuscation: {protocol}",
            "logsource": {"category": "network_connection", "product": "generic"},
            "detection": {
                "selection": {"network.protocol": protocol},
                "condition": "selection",
            },
            "mitre_technique": "T1572",
            "network_protocol": protocol,
        }
        return _result(
            self.name,
            "success",
            f"Simulated obfuscation over protocol {protocol}.",
            techniques=["T1572"],
            telemetry=[event],
            hints=hints,
            artifacts={"protocol": protocol},
        )


class ResourceDevelopmentModule(BaseModule):
    name = "resource_development"
    attack_techniques = ("T1583",)

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        resource_type = str(params.get("resource_type", "infrastructure"))
        event = TelemetryEvent(
            event_type="resource_development_simulated",
            module=self.name,
            details={"resource_type": resource_type},
        )
        hints = {
            "title": f"Adversary resource development: {resource_type}",
            "logsource": {"category": "infrastructure_provisioning", "product": "generic"},
            "detection": {
                "selection": {"resource.type": resource_type},
                "condition": "selection",
            },
            "mitre_technique": "T1583",
        }
        return _result(
            self.name,
            "success",
            f"Simulated resource development for {resource_type}.",
            techniques=["T1583"],
            telemetry=[event],
            hints=hints,
            artifacts={"resource_type": resource_type},
        )


class ReconnaissanceModule(BaseModule):
    name = "reconnaissance"
    attack_techniques = ("T1592",)

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        source = str(params.get("source", "osint"))
        event = TelemetryEvent(
            event_type="reconnaissance_simulated",
            module=self.name,
            details={"source": source},
        )
        hints = {
            "title": f"Reconnaissance activity from source: {source}",
            "logsource": {"category": "network_connection", "product": "generic"},
            "detection": {
                "selection": {"reconnaissance.source": source},
                "condition": "selection",
            },
            "mitre_technique": "T1592",
        }
        return _result(
            self.name,
            "success",
            f"Simulated reconnaissance via {source}.",
            techniques=["T1592"],
            telemetry=[event],
            hints=hints,
            artifacts={"source": source},
        )


# Credential-access technique catalog.
#
# Each entry maps an operator-facing `technique` value to its MITRE ATT&CK
# sub-technique, the Sigma-style logsource a defender would query, the
# detection-selection field that identifies the technique, and the synthetic
# telemetry event_type emitted by the module.
#
# This catalog is intentionally aligned with the technique surface of the
# legacy `src/core/credential/credential_access.py` class (LSASS / SAM /
# NTDS / browser / keychain / SSH / keylogging / clipboard / screen capture).
# That legacy class is preserved for emulate-mode follow-up work; this
# module produces realistic simulate-mode telemetry/hints without invoking
# its real side-effect paths.
_CREDENTIAL_ACCESS_PROFILES: Dict[str, Dict[str, Any]] = {
    "lsass_dump": {
        "mitre": "T1003.001",
        "logsource": {"category": "process_access", "product": "windows"},
        "selection_field": "target.process.name",
        "selection_value": "lsass.exe",
        "event_type": "credential_access_lsass_dump",
        "title_prefix": "LSASS process credential extraction",
    },
    "sam_dump": {
        "mitre": "T1003.002",
        "logsource": {"category": "registry_event", "product": "windows"},
        "selection_field": "registry.key|contains",
        "selection_value": "SAM",
        "event_type": "credential_access_sam_dump",
        "title_prefix": "SAM hive credential extraction",
    },
    "ntds_dump": {
        "mitre": "T1003.003",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "file.path|contains",
        "selection_value": "NTDS.dit",
        "event_type": "credential_access_ntds_dump",
        "title_prefix": "NTDS.dit domain credential extraction",
    },
    "browser_credentials": {
        "mitre": "T1555.003",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.path|contains",
        "selection_value": "Login Data",
        "event_type": "credential_access_browser",
        "title_prefix": "Browser stored-credential extraction",
    },
    "keychain": {
        "mitre": "T1555.001",
        "logsource": {"category": "file_event", "product": "macos"},
        "selection_field": "file.path|contains",
        "selection_value": "login.keychain",
        "event_type": "credential_access_keychain",
        "title_prefix": "macOS Keychain credential extraction",
    },
    "ssh_keys": {
        "mitre": "T1552.004",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.path|contains",
        "selection_value": ".ssh/id_",
        "event_type": "credential_access_ssh",
        "title_prefix": "SSH private-key file access",
    },
    "keylogging": {
        "mitre": "T1056.001",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "SetWindowsHookEx",
        "event_type": "credential_access_keylogging",
        "title_prefix": "Keyboard input capture",
    },
    "clipboard": {
        "mitre": "T1115",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "GetClipboardData",
        "event_type": "credential_access_clipboard",
        "title_prefix": "Clipboard data capture",
    },
    "screen_capture": {
        "mitre": "T1113",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "BitBlt",
        "event_type": "credential_access_screen_capture",
        "title_prefix": "Screen capture for credential harvest",
    },
}


class CredentialAccessModule(BaseModule):
    """Standard adapter for the credential-access tactic.

    Produces simulate-mode telemetry, ATT&CK-aligned detection hints, and
    structured artifacts for nine credential-access techniques. The legacy
    class at `src/core/credential/credential_access.py` is preserved as the
    source of technique coverage; emulate-mode wiring is a follow-up.
    """

    name = "credential_access"
    attack_techniques = (
        "T1003.001",
        "T1003.002",
        "T1003.003",
        "T1555.003",
        "T1555.001",
        "T1552.004",
        "T1056.001",
        "T1115",
        "T1113",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("technique") or "lsass_dump").lower()
        profile_key = (
            requested if requested in _CREDENTIAL_ACCESS_PROFILES else "lsass_dump"
        )
        profile = _CREDENTIAL_ACCESS_PROFILES[profile_key]
        target = str(params.get("target") or "lab-host")

        # Default behaviour mirrors the rest of the standard modules: no
        # subprocess / socket / HTTP calls under any input. Per-technique
        # telemetry shape is synthesised so detection drafts vary by
        # technique rather than emitting a single hardcoded shape.
        details = {
            "technique": profile_key,
            "target": target,
            "mitre_technique": profile["mitre"],
            "selection_value": profile["selection_value"],
        }

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=details,
        )
        hints = {
            "title": f"{profile['title_prefix']} on {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "credential_technique": profile_key,
            "target_host": target,
        }
        if requested != profile_key:
            hints["unrecognized_credential_technique"] = requested

        return _result(
            self.name,
            "success",
            f"Simulated credential-access technique '{profile_key}' against {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "technique": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
            },
        )


# Lateral-movement technique catalog.
#
# Aligned with the technique surface of the legacy
# `src/core/movement/lateral_movement.py` class (psexec / wmi / powershell-
# remoting / smb / ssh / ftp / scp / service_creation). The legacy class is
# preserved for emulate-mode follow-up; this module produces simulate-mode
# telemetry and hints.
_LATERAL_MOVEMENT_PROFILES: Dict[str, Dict[str, Any]] = {
    "psexec": {
        "mitre": "T1021.002",
        "logsource": {"category": "network_connection", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "PsExec",
        "event_type": "lateral_movement_psexec",
        "title_prefix": "PsExec lateral movement to",
    },
    "wmi": {
        "mitre": "T1047",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "wmic",
        "event_type": "lateral_movement_wmi",
        "title_prefix": "WMI remote execution against",
    },
    "winrm": {
        "mitre": "T1021.006",
        "logsource": {"category": "network_connection", "product": "windows"},
        "selection_field": "network.dst_port",
        "selection_value": 5985,
        "event_type": "lateral_movement_winrm",
        "title_prefix": "WinRM/PowerShell remoting against",
    },
    "smb_share": {
        "mitre": "T1021.002",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "file.path|contains",
        "selection_value": "ADMIN$",
        "event_type": "lateral_movement_smb_share",
        "title_prefix": "SMB administrative-share access on",
    },
    "ssh": {
        "mitre": "T1021.004",
        "logsource": {"category": "network_connection", "product": "linux"},
        "selection_field": "network.dst_port",
        "selection_value": 22,
        "event_type": "lateral_movement_ssh",
        "title_prefix": "SSH lateral movement to",
    },
    "ftp_transfer": {
        "mitre": "T1570",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 21,
        "event_type": "lateral_movement_ftp_transfer",
        "title_prefix": "FTP lateral tool transfer to",
    },
    "scp_transfer": {
        "mitre": "T1570",
        "logsource": {"category": "network_connection", "product": "linux"},
        "selection_field": "process.command_line|contains",
        "selection_value": "scp ",
        "event_type": "lateral_movement_scp_transfer",
        "title_prefix": "SCP lateral tool transfer to",
    },
    "service_create": {
        "mitre": "T1543.003",
        "logsource": {"category": "service_creation", "product": "windows"},
        "selection_field": "service.image_path|contains",
        "selection_value": "svcname",
        "event_type": "lateral_movement_service_create",
        "title_prefix": "Remote Windows service creation on",
    },
}


class LateralMovementModule(BaseModule):
    """Standard adapter for the lateral-movement tactic.

    Produces simulate-mode telemetry, ATT&CK-aligned detection hints, and
    structured artifacts for eight lateral-movement techniques. The legacy
    `src/core/movement/lateral_movement.py` class is preserved as the
    source of technique coverage; emulate-mode wiring is a follow-up.
    """

    name = "lateral_movement"
    attack_techniques = (
        "T1021.002",
        "T1047",
        "T1021.006",
        "T1021.004",
        "T1570",
        "T1543.003",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("technique") or "psexec").lower()
        profile_key = (
            requested if requested in _LATERAL_MOVEMENT_PROFILES else "psexec"
        )
        profile = _LATERAL_MOVEMENT_PROFILES[profile_key]
        source = str(params.get("source") or "lab-attacker")
        target = str(params.get("target") or "lab-host")

        details = {
            "technique": profile_key,
            "source": source,
            "target": target,
            "mitre_technique": profile["mitre"],
            "selection_value": profile["selection_value"],
        }

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=details,
        )
        hints = {
            "title": f"{profile['title_prefix']} {target} (from {source})",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "lateral_technique": profile_key,
            "source_host": source,
            "target_host": target,
        }
        if requested != profile_key:
            hints["unrecognized_lateral_technique"] = requested

        return _result(
            self.name,
            "success",
            f"Simulated lateral-movement technique '{profile_key}' from {source} to {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "technique": profile_key,
                "source": source,
                "target": target,
                "mitre_technique": profile["mitre"],
            },
        )


# Privilege-escalation technique catalog.
#
# Aligned with the technique surface of the legacy
# `src/core/privilege/privilege_escalation.py` class (token impersonation /
# duplication / creation, process hollowing / injection / masquerading,
# service creation / modification). Adds a `uac_bypass` profile commonly
# requested by purple-team scenarios.
_PRIVILEGE_ESCALATION_PROFILES: Dict[str, Dict[str, Any]] = {
    "token_impersonation": {
        "mitre": "T1134.001",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "ImpersonateLoggedOnUser",
        "event_type": "privilege_escalation_token_impersonation",
        "title_prefix": "Token impersonation on",
    },
    "token_duplication": {
        "mitre": "T1134.001",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "DuplicateTokenEx",
        "event_type": "privilege_escalation_token_duplication",
        "title_prefix": "Access token duplication on",
    },
    "token_creation": {
        "mitre": "T1134.003",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "LogonUser",
        "event_type": "privilege_escalation_token_creation",
        "title_prefix": "Make-and-impersonate token on",
    },
    "process_hollowing": {
        "mitre": "T1055.012",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "NtUnmapViewOfSection",
        "event_type": "privilege_escalation_process_hollowing",
        "title_prefix": "Process hollowing on",
    },
    "process_injection": {
        "mitre": "T1055",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "WriteProcessMemory",
        "event_type": "privilege_escalation_process_injection",
        "title_prefix": "Process injection on",
    },
    "process_masquerading": {
        "mitre": "T1036.005",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.image|endswith",
        "selection_value": "svchost.exe",
        "event_type": "privilege_escalation_process_masquerading",
        "title_prefix": "Process-name masquerading on",
    },
    "service_creation": {
        "mitre": "T1543.003",
        "logsource": {"category": "service_creation", "product": "windows"},
        "selection_field": "service.name|contains",
        "selection_value": "svc",
        "event_type": "privilege_escalation_service_creation",
        "title_prefix": "Privileged Windows service creation on",
    },
    "service_modification": {
        "mitre": "T1543.003",
        "logsource": {"category": "service_modification", "product": "windows"},
        "selection_field": "service.image_path|contains",
        "selection_value": "svc",
        "event_type": "privilege_escalation_service_modification",
        "title_prefix": "Privileged Windows service modification on",
    },
    "uac_bypass": {
        "mitre": "T1548.002",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "fodhelper",
        "event_type": "privilege_escalation_uac_bypass",
        "title_prefix": "UAC bypass attempt on",
    },
}


class PrivilegeEscalationModule(BaseModule):
    """Standard adapter for the privilege-escalation tactic.

    Produces simulate-mode telemetry, ATT&CK-aligned detection hints, and
    structured artifacts for nine privilege-escalation techniques. The
    legacy `src/core/privilege/privilege_escalation.py` class is preserved
    as the source of technique coverage; emulate-mode wiring is a follow-up.
    """

    name = "privilege_escalation"
    attack_techniques = (
        "T1134.001",
        "T1134.003",
        "T1055.012",
        "T1055",
        "T1036.005",
        "T1543.003",
        "T1548.002",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("technique") or "token_impersonation").lower()
        profile_key = (
            requested if requested in _PRIVILEGE_ESCALATION_PROFILES else "token_impersonation"
        )
        profile = _PRIVILEGE_ESCALATION_PROFILES[profile_key]
        target = str(params.get("target") or "lab-host")

        details = {
            "technique": profile_key,
            "target": target,
            "mitre_technique": profile["mitre"],
            "selection_value": profile["selection_value"],
        }

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=details,
        )
        hints = {
            "title": f"{profile['title_prefix']} {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "privesc_technique": profile_key,
            "target_host": target,
        }
        if requested != profile_key:
            hints["unrecognized_privesc_technique"] = requested

        return _result(
            self.name,
            "success",
            f"Simulated privilege-escalation technique '{profile_key}' on {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "technique": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
            },
        )


# Impact technique catalog.
#
# Aligned with the technique surface of the legacy `src/core/impact/impact.py`
# class (encryption / deletion / modification / service_stop|modify|delete /
# reboot / shutdown / crash). Adds resource_hijacking (T1496) which is a
# commonly-requested impact technique not in the legacy class.
_IMPACT_PROFILES: Dict[str, Dict[str, Any]] = {
    "data_encryption": {
        "mitre": "T1486",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.extension|in",
        "selection_value": [".locked", ".enc", ".crypt"],
        "event_type": "impact_data_encryption",
        "title_prefix": "Data encryption for impact on",
    },
    "data_destruction": {
        "mitre": "T1485",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.operation",
        "selection_value": "delete",
        "event_type": "impact_data_destruction",
        "title_prefix": "Bulk file destruction on",
    },
    "data_manipulation": {
        "mitre": "T1565",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.operation",
        "selection_value": "modify",
        "event_type": "impact_data_manipulation",
        "title_prefix": "Stored data manipulation on",
    },
    "service_stop": {
        "mitre": "T1489",
        "logsource": {"category": "service_modification", "product": "windows"},
        "selection_field": "service.action",
        "selection_value": "stop",
        "event_type": "impact_service_stop",
        "title_prefix": "Defensive service stop on",
    },
    "service_modify": {
        "mitre": "T1489",
        "logsource": {"category": "service_modification", "product": "windows"},
        "selection_field": "service.action",
        "selection_value": "disable",
        "event_type": "impact_service_modify",
        "title_prefix": "Defensive service modification on",
    },
    "service_delete": {
        "mitre": "T1489",
        "logsource": {"category": "service_modification", "product": "windows"},
        "selection_field": "service.action",
        "selection_value": "delete",
        "event_type": "impact_service_delete",
        "title_prefix": "Defensive service deletion on",
    },
    "system_reboot": {
        "mitre": "T1529",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "shutdown /r",
        "event_type": "impact_system_reboot",
        "title_prefix": "Forced system reboot on",
    },
    "system_shutdown": {
        "mitre": "T1529",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "shutdown /s",
        "event_type": "impact_system_shutdown",
        "title_prefix": "Forced system shutdown on",
    },
    "endpoint_dos": {
        "mitre": "T1499",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "fork-bomb",
        "event_type": "impact_endpoint_dos",
        "title_prefix": "Endpoint denial-of-service on",
    },
    "resource_hijacking": {
        "mitre": "T1496",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.image|endswith",
        "selection_value": "miner.exe",
        "event_type": "impact_resource_hijacking",
        "title_prefix": "Resource hijacking on",
    },
}


class ImpactModule(BaseModule):
    """Standard adapter for the impact tactic.

    Produces simulate-mode telemetry, ATT&CK-aligned detection hints, and
    structured artifacts for ten impact techniques. The legacy
    `src/core/impact/impact.py` class is preserved as the source of
    technique coverage; emulate-mode wiring is a follow-up.

    Note: this module never writes destructive payloads under any input.
    Telemetry shape is synthesised; no real file system, registry, service,
    or system-shutdown side effects occur even with `dry_run=False`.
    """

    name = "impact"
    attack_techniques = (
        "T1486",
        "T1485",
        "T1565",
        "T1489",
        "T1529",
        "T1499",
        "T1496",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("technique") or "data_encryption").lower()
        profile_key = (
            requested if requested in _IMPACT_PROFILES else "data_encryption"
        )
        profile = _IMPACT_PROFILES[profile_key]
        target = str(params.get("target") or "lab-host")

        details = {
            "technique": profile_key,
            "target": target,
            "mitre_technique": profile["mitre"],
            "selection_value": profile["selection_value"],
        }

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=details,
        )
        hints = {
            "title": f"{profile['title_prefix']} {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "impact_technique": profile_key,
            "target_host": target,
        }
        if requested != profile_key:
            hints["unrecognized_impact_technique"] = requested

        return _result(
            self.name,
            "success",
            f"Simulated impact technique '{profile_key}' on {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "technique": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
            },
        )


# Collection technique catalog.
#
# Aligned with the technique surface of the legacy
# `src/core/collection/collection.py` class (file/directory/archive staging,
# keyboard/clipboard/screen capture, compression, encryption, encoding).
# Adds audio_capture (T1123) and email_collection (T1114.001) which are
# commonly-requested techniques not in the legacy class.
_COLLECTION_PROFILES: Dict[str, Dict[str, Any]] = {
    "file_staging": {
        "mitre": "T1074.001",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.path|contains",
        "selection_value": "staging",
        "event_type": "collection_file_staging",
        "title_prefix": "Local file staging on",
    },
    "directory_staging": {
        "mitre": "T1074.001",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.path|contains",
        "selection_value": "staging-dir",
        "event_type": "collection_directory_staging",
        "title_prefix": "Local directory staging on",
    },
    "archive_collected": {
        "mitre": "T1560",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "tar -",
        "event_type": "collection_archive_collected",
        "title_prefix": "Archiving collected data on",
    },
    "archive_compressed": {
        "mitre": "T1560.002",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "gzip",
        "event_type": "collection_archive_compressed",
        "title_prefix": "Compressed archive of collected data on",
    },
    "archive_encrypted": {
        "mitre": "T1560.001",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "openssl",
        "event_type": "collection_archive_encrypted",
        "title_prefix": "Encrypted archive of collected data on",
    },
    "keyboard_capture": {
        "mitre": "T1056.001",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "SetWindowsHookEx",
        "event_type": "collection_keyboard_capture",
        "title_prefix": "Keystroke capture on",
    },
    "clipboard_capture": {
        "mitre": "T1115",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "GetClipboardData",
        "event_type": "collection_clipboard_capture",
        "title_prefix": "Clipboard capture on",
    },
    "screen_capture": {
        "mitre": "T1113",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "BitBlt",
        "event_type": "collection_screen_capture",
        "title_prefix": "Screen capture on",
    },
    "audio_capture": {
        "mitre": "T1123",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "audio_capture",
        "event_type": "collection_audio_capture",
        "title_prefix": "Audio capture on",
    },
    "email_collection": {
        "mitre": "T1114.001",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "file.path|contains",
        "selection_value": ".pst",
        "event_type": "collection_email_collection",
        "title_prefix": "Local email collection on",
    },
}


class CollectionModule(BaseModule):
    """Standard adapter for the collection tactic.

    Produces simulate-mode telemetry, ATT&CK-aligned detection hints, and
    structured artifacts for ten collection techniques. The legacy
    `src/core/collection/collection.py` class is preserved as the source
    of technique coverage; emulate-mode wiring is a follow-up.
    """

    name = "collection"
    attack_techniques = (
        "T1074.001",
        "T1560",
        "T1560.001",
        "T1560.002",
        "T1056.001",
        "T1115",
        "T1113",
        "T1123",
        "T1114.001",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("technique") or "file_staging").lower()
        profile_key = (
            requested if requested in _COLLECTION_PROFILES else "file_staging"
        )
        profile = _COLLECTION_PROFILES[profile_key]
        target = str(params.get("target") or "lab-host")

        details = {
            "technique": profile_key,
            "target": target,
            "mitre_technique": profile["mitre"],
            "selection_value": profile["selection_value"],
        }

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=details,
        )
        hints = {
            "title": f"{profile['title_prefix']} {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "collection_technique": profile_key,
            "target_host": target,
        }
        if requested != profile_key:
            hints["unrecognized_collection_technique"] = requested

        return _result(
            self.name,
            "success",
            f"Simulated collection technique '{profile_key}' on {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "technique": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
            },
        )


class LegacyWrappedModule(BaseModule):
    """Adapter that wraps existing legacy modules into ModuleResult objects."""

    def __init__(self, name: str, legacy_instance: Any, execute_method: str):
        super().__init__()
        self.name = name
        self.legacy_instance = legacy_instance
        self.execute_method = execute_method

    def update_config(self, config: Mapping[str, Any]) -> None:
        super().update_config(config)
        if hasattr(self.legacy_instance, "update_config"):
            self.legacy_instance.update_config({"modules": {self.name: dict(config)}})

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        method = getattr(self.legacy_instance, self.execute_method)
        raw = method(dict(params))
        status = str(raw.get("status", "success"))
        message = str(raw.get("message") or raw.get("reason") or "Legacy module executed.")
        artifacts = raw.get("results") if isinstance(raw.get("results"), dict) else raw
        telemetry = [
            TelemetryEvent(
                event_type="legacy_module_execution",
                module=self.name,
                details={
                    "run_id": (
                        context.get("run_context").run_id
                        if context.get("run_context")
                        else "unknown"
                    )
                },
            )
        ]
        hints = {"mitre_technique": "T0000"}
        return _result(
            self.name,
            "success" if status in {"success", "partial_success"} else "failure",
            message,
            artifacts={"legacy_result": artifacts},
            hints=hints,
            telemetry=telemetry,
            error=raw.get("error"),
        )
