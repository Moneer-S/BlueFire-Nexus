"""First-class module implementations for the orchestrator."""

from __future__ import annotations

import platform
import shlex
import subprocess  # nosec B404
from datetime import datetime, timezone
from typing import Any, Dict, Mapping

from ...models import ModuleResult, TelemetryEvent
from ..base import BaseModule, resolve_target_from_step


# Operator-facing target_os values map to a sigma-style logsource.
# Used by ExecutionModule (and optionally other modules) so detection
# drafts match the OS the operator is emulating against rather than
# defaulting to a single hardcoded shape.
_EXECUTION_LOGSOURCE_BY_OS: Dict[str, Dict[str, str]] = {
    "windows": {"category": "process_creation", "product": "windows"},
    "linux": {"category": "process_creation", "product": "linux"},
    "macos": {"category": "process_creation", "product": "macos"},
    "darwin": {"category": "process_creation", "product": "macos"},
}


def _resolve_target_os(params: Mapping[str, Any]) -> str:
    """Resolve the operator-facing target_os value or fall back to host OS.

    Order of precedence:
    1. Explicit `target_os` param (windows / linux / macos / darwin).
    2. `platform.system()` mapped to the same vocabulary.
    3. Hard fallback: linux (the most common purple-team lab host).
    """
    explicit = str(params.get("target_os") or "").strip().lower()
    if explicit in _EXECUTION_LOGSOURCE_BY_OS:
        return "macos" if explicit == "darwin" else explicit

    system = platform.system().lower()
    mapping = {"windows": "windows", "linux": "linux", "darwin": "macos"}
    return mapping.get(system, "linux")


def _execution_logsource(target_os: str) -> Dict[str, str]:
    return dict(_EXECUTION_LOGSOURCE_BY_OS.get(target_os, _EXECUTION_LOGSOURCE_BY_OS["linux"]))


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


# Execution interpreter sub-technique catalog.
#
# Maps the basename of a command's first token (case-insensitive,
# trailing ``.exe`` stripped) to its specific Command and Scripting
# Interpreter sub-technique. Was historically pinned to bare T1059
# regardless of interpreter, which left the showcase scenario's
# ``powershell -enc ...`` step claiming the parent technique even
# though every detection vendor maps PowerShell-specific telemetry
# to T1059.001. The parent T1059 is reserved as the fallback when
# no interpreter is recognised.
_EXECUTION_INTERPRETER_PROFILES: Dict[str, Dict[str, str]] = {
    "powershell": {"mitre": "T1059.001", "interpreter": "powershell"},
    "pwsh": {"mitre": "T1059.001", "interpreter": "powershell"},
    "osascript": {"mitre": "T1059.002", "interpreter": "applescript"},
    "cmd": {"mitre": "T1059.003", "interpreter": "windows_cmd"},
    "bash": {"mitre": "T1059.004", "interpreter": "unix_shell"},
    "sh": {"mitre": "T1059.004", "interpreter": "unix_shell"},
    "zsh": {"mitre": "T1059.004", "interpreter": "unix_shell"},
    "ksh": {"mitre": "T1059.004", "interpreter": "unix_shell"},
    "dash": {"mitre": "T1059.004", "interpreter": "unix_shell"},
    "fish": {"mitre": "T1059.004", "interpreter": "unix_shell"},
    "cscript": {"mitre": "T1059.005", "interpreter": "vbscript"},
    "wscript": {"mitre": "T1059.005", "interpreter": "vbscript"},
    "python": {"mitre": "T1059.006", "interpreter": "python"},
    "python3": {"mitre": "T1059.006", "interpreter": "python"},
    "py": {"mitre": "T1059.006", "interpreter": "python"},
    "node": {"mitre": "T1059.007", "interpreter": "javascript"},
    "deno": {"mitre": "T1059.007", "interpreter": "javascript"},
    "jsc": {"mitre": "T1059.007", "interpreter": "javascript"},
}


def _resolve_execution_profile(command: str) -> Dict[str, str]:
    """Return ``{mitre, interpreter}`` for a command, falling back to T1059.

    Examines the basename of the first whitespace-separated token of
    the command, lower-cased and with ``.exe`` stripped, against the
    interpreter catalog. ``powershell.exe -nop ...`` and
    ``c:\\windows\\system32\\cmd.exe /c ...`` both resolve correctly.
    """
    if not command.strip():
        return {"mitre": "T1059", "interpreter": "unknown"}
    first_token = command.strip().split(maxsplit=1)[0]
    # Strip Windows-style path; basename is what matters.
    basename = first_token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if basename.endswith(".exe"):
        basename = basename[:-4]
    profile = _EXECUTION_INTERPRETER_PROFILES.get(basename)
    if profile is None:
        return {"mitre": "T1059", "interpreter": "unknown"}
    return dict(profile)


class ExecutionModule(BaseModule):
    name = "execution"
    attack_techniques = tuple(
        sorted({"T1059", *(profile["mitre"] for profile in _EXECUTION_INTERPRETER_PROFILES.values())})
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        command = str(params.get("command") or params.get("cmd") or "echo simulated-execution")
        allow_real = bool(self._config.get("allow_real_execution", False))
        dry_run = bool(context.get("dry_run", True))
        timeout = int(self._config.get("timeout_seconds", 10))
        interpreter_profile = _resolve_execution_profile(command)
        mitre = interpreter_profile["mitre"]

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
                    techniques=[mitre],
                    error=str(exc),
                )

        target_os = _resolve_target_os(params)
        event = TelemetryEvent(
            event_type="execution",
            module=self.name,
            details={
                "command": command,
                "return_code": rc,
                "target_os": target_os,
                "interpreter": interpreter_profile["interpreter"],
                "mitre_technique": mitre,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
        hints = {
            "title": f"Suspicious command execution ({target_os})",
            "logsource": _execution_logsource(target_os),
            "detection": {
                "selection": {"process.command_line|contains": command.split(" ")[0]},
                "condition": "selection",
            },
            "mitre_technique": mitre,
            "process_command_line": command,
            "target_os": target_os,
            "interpreter": interpreter_profile["interpreter"],
        }
        return _result(
            self.name,
            status,
            message,
            techniques=[mitre],
            telemetry=[event],
            hints=hints,
            artifacts={
                "command": command,
                "stdout": output,
                "return_code": rc,
                "target_os": target_os,
                "interpreter": interpreter_profile["interpreter"],
                "mitre_technique": mitre,
            },
        )


# Persistence technique catalog.
_PERSISTENCE_PROFILES: Dict[str, Dict[str, Any]] = {
    "scheduled_task": {
        "mitre": "T1053.005",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "schtasks",
        "event_type": "persistence_scheduled_task",
        "title_prefix": "Scheduled task persistence on",
    },
    "cron": {
        "mitre": "T1053.003",
        "logsource": {"category": "process_creation", "product": "linux"},
        "selection_field": "process.command_line|contains",
        "selection_value": "crontab",
        "event_type": "persistence_cron",
        "title_prefix": "Cron-job persistence on",
    },
    "registry_run_key": {
        "mitre": "T1547.001",
        "logsource": {"category": "registry_event", "product": "windows"},
        "selection_field": "registry.key|contains",
        "selection_value": "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        "event_type": "persistence_registry_run_key",
        "title_prefix": "Run-key registry persistence on",
    },
    "service": {
        "mitre": "T1543.003",
        "logsource": {"category": "service_creation", "product": "windows"},
        "selection_field": "service.image_path|contains",
        "selection_value": "svc",
        "event_type": "persistence_service",
        "title_prefix": "Windows service persistence on",
    },
    "launch_agent": {
        "mitre": "T1543.001",
        "logsource": {"category": "file_event", "product": "macos"},
        "selection_field": "file.path|contains",
        "selection_value": "LaunchAgents",
        "event_type": "persistence_launch_agent",
        "title_prefix": "Launch-agent persistence on",
    },
    "launch_daemon": {
        "mitre": "T1543.004",
        "logsource": {"category": "file_event", "product": "macos"},
        "selection_field": "file.path|contains",
        "selection_value": "LaunchDaemons",
        "event_type": "persistence_launch_daemon",
        "title_prefix": "Launch-daemon persistence on",
    },
    "wmi_subscription": {
        "mitre": "T1546.003",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "__EventFilter",
        "event_type": "persistence_wmi_subscription",
        "title_prefix": "WMI event-subscription persistence on",
    },
    "startup_folder": {
        "mitre": "T1547.001",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "file.path|contains",
        "selection_value": "Startup",
        "event_type": "persistence_startup_folder",
        "title_prefix": "Startup-folder persistence on",
    },
    "bashrc": {
        "mitre": "T1546.004",
        "logsource": {"category": "file_event", "product": "linux"},
        "selection_field": "file.path|contains",
        "selection_value": ".bashrc",
        "event_type": "persistence_bashrc",
        "title_prefix": "Shell-rc persistence on",
    },
    "bootkit": {
        "mitre": "T1542.003",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "bcdedit",
        "event_type": "persistence_bootkit",
        "title_prefix": "Bootkit persistence on",
    },
}


class PersistenceModule(BaseModule):
    name = "persistence"
    attack_techniques = (
        "T1053.005",
        "T1053.003",
        "T1547.001",
        "T1543.003",
        "T1543.001",
        "T1543.004",
        "T1546.003",
        "T1546.004",
        "T1542.003",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("technique") or "scheduled_task").lower()
        profile_key = (
            requested if requested in _PERSISTENCE_PROFILES else "scheduled_task"
        )
        profile = _PERSISTENCE_PROFILES[profile_key]
        target = str(params.get("target") or "lab-host")

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details={
                "technique": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
                "selection_value": profile["selection_value"],
            },
        )
        hints = {
            "title": f"{profile['title_prefix']} {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "persistence_technique": profile_key,
            "target_host": target,
        }
        if requested != profile_key:
            hints["unrecognized_persistence_technique"] = requested

        return _result(
            self.name,
            "success",
            f"Simulated persistence technique '{profile_key}' on {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "technique": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
            },
        )


# Defense-evasion technique catalog.
_DEFENSE_EVASION_PROFILES: Dict[str, Dict[str, Any]] = {
    "argument_spoofing": {
        "mitre": "T1564.010",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "--legit",
        "event_type": "defense_evasion_argument_spoofing",
        "title_prefix": "Process-argument spoofing on",
    },
    "masquerading": {
        "mitre": "T1036",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.image|endswith",
        "selection_value": "svchost.exe",
        "event_type": "defense_evasion_masquerading",
        "title_prefix": "Process-name masquerading on",
    },
    "timestomping": {
        "mitre": "T1070.006",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.action",
        "selection_value": "timestamp_modify",
        "event_type": "defense_evasion_timestomping",
        "title_prefix": "File timestomping on",
    },
    "log_clearing": {
        "mitre": "T1070.001",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "wevtutil cl",
        "event_type": "defense_evasion_log_clearing",
        "title_prefix": "Event-log clearing on",
    },
    "hidden_files": {
        "mitre": "T1564.001",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.attributes|contains",
        "selection_value": "hidden",
        "event_type": "defense_evasion_hidden_files",
        "title_prefix": "Hidden-file creation on",
    },
    "system_binary_proxy": {
        "mitre": "T1218",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.image|endswith",
        "selection_value": "rundll32.exe",
        "event_type": "defense_evasion_system_binary_proxy",
        "title_prefix": "System-binary proxy execution on",
    },
    "powershell_obfuscation": {
        "mitre": "T1027",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "FromBase64String",
        "event_type": "defense_evasion_powershell_obfuscation",
        "title_prefix": "PowerShell-payload obfuscation on",
    },
    "impair_defenses": {
        "mitre": "T1562.001",
        "logsource": {"category": "service_modification", "product": "windows"},
        "selection_field": "service.name|contains",
        "selection_value": "WinDefend",
        "event_type": "defense_evasion_impair_defenses",
        "title_prefix": "Defensive-tool impairment on",
    },
}


class DefenseEvasionModule(BaseModule):
    name = "defense_evasion"
    attack_techniques = (
        "T1564.010",
        "T1036",
        "T1070.006",
        "T1070.001",
        "T1564.001",
        "T1218",
        "T1027",
        "T1562.001",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("technique") or "argument_spoofing").lower()
        profile_key = (
            requested if requested in _DEFENSE_EVASION_PROFILES else "argument_spoofing"
        )
        profile = _DEFENSE_EVASION_PROFILES[profile_key]
        target = str(params.get("target") or "lab-host")

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details={
                "technique": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
                "selection_value": profile["selection_value"],
            },
        )
        hints = {
            "title": f"{profile['title_prefix']} {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "evasion_technique": profile_key,
            "target_host": target,
        }
        if requested != profile_key:
            hints["unrecognized_evasion_technique"] = requested

        return _result(
            self.name,
            "success",
            f"Simulated defense-evasion technique '{profile_key}' on {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "technique": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
            },
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
        # Optional step-to-step propagation: when the scenario step
        # sets `target_from_step: <step_id>` and does NOT pass an
        # explicit `target`, pick up the upstream step's
        # `artifacts.target` (single-target upstream like collection)
        # or first entry of `artifacts.targets` (multi-target upstream
        # like discovery). Explicit `target` always wins. The semantic
        # contract is "the host the data was exfiltrated FROM" so the
        # natural pairing is collection -> exfiltration.
        target, propagated_from = resolve_target_from_step(
            params, context, fallback="lab-host"
        )
        artifact_name = f"exfil_{context['run_id']}.txt"
        details: Dict[str, Any] = {
            "method": method,
            "target": target,
            "artifact": artifact_name,
        }
        if propagated_from:
            details["target_propagated_from_step"] = propagated_from
        event = TelemetryEvent(
            event_type="exfiltration_simulated",
            module=self.name,
            details=details,
        )
        hints: Dict[str, Any] = {
            "title": f"Potential data exfiltration from {target}",
            "logsource": {"category": "network_connection", "product": "windows"},
            "detection": {"selection": {"exfil.method": method}, "condition": "selection"},
            "mitre_technique": "T1041",
            "network_method": method,
            "source_host": target,
        }
        if propagated_from:
            hints["target_propagated_from_step"] = propagated_from
        artifacts: Dict[str, Any] = {
            "method": method,
            "target": target,
            "artifact_name": artifact_name,
        }
        if propagated_from:
            artifacts["target_propagated_from_step"] = propagated_from
        return _result(
            self.name,
            "success",
            f"Simulated exfiltration via {method} from {target}.",
            techniques=["T1041"],
            telemetry=[event],
            hints=hints,
            artifacts=artifacts,
        )


# Command-control channel catalog.
#
# Each `channel` value maps to its MITRE technique, sigma-style logsource,
# detection selection field, and synthetic event_type. Detection drafts now
# vary per channel instead of emitting a single hardcoded shape.
_COMMAND_CONTROL_PROFILES: Dict[str, Dict[str, Any]] = {
    "http": {
        "mitre": "T1071.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.url|contains",
        "event_type": "command_control_http",
        "title_prefix": "Application-layer HTTP C2 to",
    },
    "https": {
        "mitre": "T1071.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.url|contains",
        "event_type": "command_control_https",
        "title_prefix": "Application-layer HTTPS C2 to",
    },
    "dns": {
        "mitre": "T1071.004",
        "logsource": {"category": "dns", "product": "network"},
        "selection_field": "dns.question.name|contains",
        "event_type": "command_control_dns",
        "title_prefix": "DNS-tunneled C2 to",
    },
    "tcp": {
        "mitre": "T1095",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "event_type": "command_control_tcp",
        "title_prefix": "Non-application-layer TCP C2 to",
    },
    "icmp": {
        "mitre": "T1095",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.protocol",
        "event_type": "command_control_icmp",
        "title_prefix": "ICMP-tunneled C2 to",
    },
    "websocket": {
        "mitre": "T1071.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.url|contains",
        "event_type": "command_control_websocket",
        "title_prefix": "WebSocket C2 to",
    },
    "mail": {
        "mitre": "T1071.003",
        "logsource": {"category": "email", "product": "host"},
        "selection_field": "email.recipient|contains",
        "event_type": "command_control_mail",
        "title_prefix": "Mail-channel C2 to",
    },
    "web_service": {
        "mitre": "T1102",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.url|contains",
        "event_type": "command_control_web_service",
        "title_prefix": "Web-service-bidirectional C2 to",
    },
}


class CommandControlModule(BaseModule):
    name = "command_control"
    attack_techniques = ("T1071.001", "T1071.003", "T1071.004", "T1095", "T1102")

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("channel") or "http").lower()
        profile_key = requested if requested in _COMMAND_CONTROL_PROFILES else "http"
        profile = _COMMAND_CONTROL_PROFILES[profile_key]

        # Optional step-to-step propagation: when the scenario step
        # sets `c2_endpoint_from_step: <step_id>` and does NOT pass an
        # explicit `c2_url`, pick up the upstream step's
        # `artifacts.target` (single-target upstream like a recon /
        # resource_development step that registered a domain) or the
        # first entry of `artifacts.targets` (multi-target upstream)
        # and shape it into a c2_url. Explicit `c2_url` always wins.
        explicit_url = str(params.get("c2_url") or "").strip()
        propagated_from: str | None = None
        if explicit_url:
            c2_url = explicit_url
        else:
            upstream_target, propagated_from = resolve_target_from_step(
                params,
                context,
                fallback="",
                param_key="c2_url",
                step_param_key="c2_endpoint_from_step",
            )
            if upstream_target:
                # If the upstream value already looks like a URL (has
                # a scheme), use it verbatim. Otherwise treat it as a
                # hostname and wrap into a default C2 URL shape.
                if "://" in upstream_target:
                    c2_url = upstream_target
                else:
                    c2_url = f"https://{upstream_target}/c2"
            else:
                c2_url = "https://example.invalid/c2"

        details: Dict[str, Any] = {
            "channel": profile_key,
            "c2_url": c2_url,
            "mitre_technique": profile["mitre"],
        }
        if propagated_from:
            details["c2_endpoint_propagated_from_step"] = propagated_from

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=details,
        )
        hints: Dict[str, Any] = {
            "title": f"{profile['title_prefix']} {c2_url}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: c2_url},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "c2_channel": profile_key,
            "network_url": c2_url,
        }
        if requested != profile_key:
            hints["unrecognized_c2_channel"] = requested
        if propagated_from:
            hints["c2_endpoint_propagated_from_step"] = propagated_from

        artifacts: Dict[str, Any] = {
            "channel": profile_key,
            "c2_url": c2_url,
            "mitre_technique": profile["mitre"],
        }
        if propagated_from:
            artifacts["c2_endpoint_propagated_from_step"] = propagated_from

        return _result(
            self.name,
            "success",
            f"Simulated C2 beacon over {profile_key} to {c2_url}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts=artifacts,
        )


# Anti-detection profile catalog.
#
# Each entry maps a high-level operator method (`memory_evasion`,
# `code_obfuscation`, ...) to a real defense-evasion ATT&CK sub-technique
# AND a Sigma-style detection draft that uses sourcetype-appropriate
# Windows / Sysmon field names. Without this catalog the module emitted
# a single generic hint with the BlueFire field `anti_detection.method`
# as the discriminator, which is not a real telemetry field anywhere.
#
# `selection_field` / `selection_value` should be picked so that the
# resulting Sigma rule could plausibly fire against real Sysmon
# telemetry for the technique. The values are deliberately simulate-
# safe (no live commands invoked) but represent the kind of indicator
# a defender would actually look for.
_ANTI_DETECTION_PROFILES: Dict[str, Dict[str, Any]] = {
    "memory_evasion": {
        "mitre": "T1055",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "ParentImage|endswith",
        "selection_value": "\\explorer.exe",
        "event_type": "anti_detection_memory_evasion",
        "title_prefix": "In-memory execution / process injection",
        "details": {"injection_target": "lsass.exe", "alloc_protect": "PAGE_EXECUTE_READWRITE"},
    },
    "code_obfuscation": {
        "mitre": "T1027",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "TargetFilename|endswith",
        "selection_value": ".enc",
        "event_type": "anti_detection_code_obfuscation",
        "title_prefix": "Obfuscated/encoded payload artefact",
        "details": {"payload_entropy": 7.8, "packer_signature": "upx"},
    },
    "anti_debug": {
        "mitre": "T1622",
        "logsource": {"category": "process_access", "product": "windows"},
        "selection_field": "CallTrace|contains",
        "selection_value": "IsDebuggerPresent",
        "event_type": "anti_detection_anti_debug",
        "title_prefix": "Anti-debug API probe",
        "details": {"api": "IsDebuggerPresent", "method_hint": "PEB_BeingDebugged"},
    },
    "anti_sandbox": {
        "mitre": "T1497.001",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "CommandLine|contains",
        "selection_value": "wmic computersystem get model",
        "event_type": "anti_detection_anti_sandbox",
        "title_prefix": "Sandbox/VM environment probe",
        "details": {"probe_command": "wmic computersystem get model", "indicator": "VirtualBox"},
    },
    "anti_vm": {
        "mitre": "T1497.001",
        "logsource": {"category": "registry_event", "product": "windows"},
        "selection_field": "TargetObject|contains",
        "selection_value": "\\SYSTEM\\CurrentControlSet\\Services\\VBoxService",
        "event_type": "anti_detection_anti_vm",
        "title_prefix": "VM artefact registry lookup",
        "details": {"registry_key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VBoxService"},
    },
    "timestomp": {
        "mitre": "T1070.006",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "TargetFilename|endswith",
        "selection_value": "\\drivers\\etc\\hosts",
        "event_type": "anti_detection_timestomp",
        "title_prefix": "Timestamp manipulation",
        "details": {"target_file": "C:\\Windows\\System32\\drivers\\etc\\hosts", "modified_attr": "MFT"},
    },
    "log_clear": {
        "mitre": "T1070.001",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "CommandLine|contains",
        "selection_value": "wevtutil cl",
        "event_type": "anti_detection_log_clear",
        "title_prefix": "Windows event-log clearing",
        "details": {"target_log": "Security", "tool": "wevtutil.exe"},
    },
    "dynamic_api": {
        "mitre": "T1027.007",
        "logsource": {"category": "process_access", "product": "windows"},
        "selection_field": "CallTrace|contains",
        "selection_value": "GetProcAddress",
        "event_type": "anti_detection_dynamic_api",
        "title_prefix": "Dynamic API resolution",
        "details": {"resolver": "GetProcAddress", "target_api": "VirtualAlloc"},
    },
    "reflective_loading": {
        "mitre": "T1620",
        "logsource": {"category": "image_load", "product": "windows"},
        "selection_field": "ImageLoaded|endswith",
        "selection_value": "\\unsigned_module.dll",
        "event_type": "anti_detection_reflective_loading",
        "title_prefix": "Reflective code loading",
        "details": {"loader": "manual_dll_mapping", "target_process": "lsass.exe"},
    },
    "process_hollowing": {
        "mitre": "T1055.012",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "ParentCommandLine|contains",
        "selection_value": "svchost.exe -k",
        "event_type": "anti_detection_process_hollowing",
        "title_prefix": "Process hollowing",
        "details": {"target_process": "svchost.exe", "image_replaced": True},
    },
    "string_encryption": {
        "mitre": "T1027.013",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "TargetFilename|endswith",
        "selection_value": ".bin",
        "event_type": "anti_detection_string_encryption",
        "title_prefix": "Encrypted string payload",
        "details": {"cipher": "AES-256-CBC", "payload_entropy": 7.9},
    },
    "api_unhooking": {
        "mitre": "T1562.001",
        "logsource": {"category": "process_access", "product": "windows"},
        "selection_field": "CallTrace|contains",
        "selection_value": "ntdll.dll+",
        "event_type": "anti_detection_api_unhooking",
        "title_prefix": "EDR API unhooking",
        "details": {"target_dll": "ntdll.dll", "method_hint": "fresh_image_overwrite"},
    },
}


_ANTI_DETECTION_DEFAULT = "memory_evasion"


class AntiDetectionModule(BaseModule):
    """Standard adapter for the anti-detection / defense-evasion tactic.

    Produces simulate-mode telemetry, ATT&CK-aligned detection hints, and
    structured artifacts for twelve evasion methods. The legacy stealth
    pack at `src/core/anti_detection/` is preserved as the source of
    research-grade behaviour; emulate-mode wiring is gated behind the
    explicit `legacy_stealth_research` adapter.
    """

    name = "anti_detection"
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _ANTI_DETECTION_PROFILES.values()})
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("method") or _ANTI_DETECTION_DEFAULT).lower()
        profile_key = (
            requested if requested in _ANTI_DETECTION_PROFILES else _ANTI_DETECTION_DEFAULT
        )
        profile = _ANTI_DETECTION_PROFILES[profile_key]
        target, propagated_from = resolve_target_from_step(
            params, context, fallback="lab-host"
        )

        # Profile details first so the canonical fields below
        # (``method`` / ``target`` / ``mitre_technique`` /
        # ``selection_value``) always win — even if a future profile
        # contributor reuses one of those keys for a per-method
        # detail. ``target`` in particular is canonical here (the
        # host being acted on); a profile that meant a per-method
        # file path / process name should namespace its own key
        # (e.g. ``target_file`` for ``timestomp``).
        details: Dict[str, Any] = dict(profile["details"])
        details.update(
            {
                "method": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
                "selection_value": profile["selection_value"],
            }
        )
        if propagated_from:
            details["target_propagated_from_step"] = propagated_from

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=dict(details),
        )

        hints: Dict[str, Any] = {
            "title": f"{profile['title_prefix']} on {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "anti_detection_method": profile_key,
            "target_host": target,
        }
        if requested != profile_key:
            hints["unrecognized_anti_detection_method"] = requested
        if propagated_from:
            hints["target_propagated_from_step"] = propagated_from

        # Same merge discipline as ``details``: canonical fields
        # last so they cannot be overwritten by profile detail keys.
        artifacts: Dict[str, Any] = dict(profile["details"])
        artifacts.update(
            {
                "method": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
            }
        )
        if propagated_from:
            artifacts["target_propagated_from_step"] = propagated_from

        return _result(
            self.name,
            "success",
            f"Simulated anti-detection method '{profile_key}' on {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts=artifacts,
        )


# Intelligence-collection profile catalog.
#
# `intelligence_type` selects the catalog entry. Default falls back to
# `actor_research` keyed on `focus` (preserving the legacy single-arg shape).
_INTELLIGENCE_PROFILES: Dict[str, Dict[str, Any]] = {
    "actor_research": {
        "mitre": "T1591.002",
        "logsource": {"category": "threat_intelligence", "product": "vendor"},
        "selection_field": "threat.actor",
        "event_type": "intelligence_actor_research",
        "title_prefix": "Threat-actor research on",
    },
    "ttp_research": {
        "mitre": "T1591",
        "logsource": {"category": "threat_intelligence", "product": "vendor"},
        "selection_field": "threat.ttp_focus",
        "event_type": "intelligence_ttp_research",
        "title_prefix": "TTP catalog research on",
    },
    "ioc_collection": {
        "mitre": "T1592.002",
        "logsource": {"category": "threat_intelligence", "product": "ioc_feed"},
        "selection_field": "threat.ioc_class",
        "event_type": "intelligence_ioc_collection",
        "title_prefix": "IOC collection focused on",
    },
    "vuln_research": {
        "mitre": "T1588.006",
        "logsource": {"category": "threat_intelligence", "product": "vuln_feed"},
        "selection_field": "threat.cve_pattern",
        "event_type": "intelligence_vuln_research",
        "title_prefix": "Vulnerability research focused on",
    },
    "credential_intel": {
        "mitre": "T1589.001",
        "logsource": {"category": "threat_intelligence", "product": "leak_feed"},
        "selection_field": "threat.credential_corpus",
        "event_type": "intelligence_credential_intel",
        "title_prefix": "Credential leak research on",
    },
    "domain_intel": {
        "mitre": "T1590.005",
        "logsource": {"category": "threat_intelligence", "product": "passive_dns"},
        "selection_field": "threat.domain_pattern",
        "event_type": "intelligence_domain_intel",
        "title_prefix": "Domain-history research on",
    },
    "network_intel": {
        "mitre": "T1590",
        "logsource": {"category": "threat_intelligence", "product": "asn_feed"},
        "selection_field": "threat.network_pattern",
        "event_type": "intelligence_network_intel",
        "title_prefix": "Network-topology research on",
    },
}


class IntelligenceModule(BaseModule):
    name = "intelligence"
    attack_techniques = (
        "T1591",
        "T1591.002",
        "T1592.002",
        "T1588.006",
        "T1589.001",
        "T1590",
        "T1590.005",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        # Backwards compat: prior callers used `focus` only. New callers may
        # pass `intelligence_type` to select a specific catalog entry; without
        # it, default to actor_research keyed by the legacy `focus` value.
        requested = str(params.get("intelligence_type") or "actor_research").lower()
        profile_key = (
            requested if requested in _INTELLIGENCE_PROFILES else "actor_research"
        )
        profile = _INTELLIGENCE_PROFILES[profile_key]
        focus = str(params.get("focus") or "apt29")

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details={
                "intelligence_type": profile_key,
                "focus": focus,
                "mitre_technique": profile["mitre"],
            },
        )
        hints = {
            "title": f"{profile['title_prefix']} {focus}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: focus},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "intelligence_type": profile_key,
            "intelligence_focus": focus,
        }
        if requested != profile_key:
            hints["unrecognized_intelligence_type"] = requested

        return _result(
            self.name,
            "success",
            f"Collected simulated {profile_key} intelligence on {focus}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "intelligence_type": profile_key,
                "focus": focus,
                "confidence": "medium",
                "mitre_technique": profile["mitre"],
            },
        )


# Network-obfuscator profile catalog.
_NETWORK_OBFUSCATOR_PROFILES: Dict[str, Dict[str, Any]] = {
    "dns": {
        "mitre": "T1572",
        "logsource": {"category": "dns", "product": "network"},
        "selection_field": "dns.question.length",
        "selection_value": ">100",
        "event_type": "network_obfuscation_dns",
        "title_prefix": "DNS-tunneled obfuscation on",
    },
    "domain_fronting": {
        "mitre": "T1090.004",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "tls.sni|contains",
        "selection_value": "cdn",
        "event_type": "network_obfuscation_domain_fronting",
        "title_prefix": "Domain-fronting obfuscation on",
    },
    "multi_hop": {
        "mitre": "T1090.003",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.hop_count",
        "selection_value": ">3",
        "event_type": "network_obfuscation_multi_hop",
        "title_prefix": "Multi-hop proxy obfuscation on",
    },
    "tor": {
        "mitre": "T1090.003",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 9001,
        "event_type": "network_obfuscation_tor",
        "title_prefix": "Tor-circuit obfuscation on",
    },
    "internal_proxy": {
        "mitre": "T1090.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 8080,
        "event_type": "network_obfuscation_internal_proxy",
        "title_prefix": "Internal-proxy obfuscation on",
    },
    "external_proxy": {
        "mitre": "T1090.002",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_country|in",
        "selection_value": "external",
        "event_type": "network_obfuscation_external_proxy",
        "title_prefix": "External-proxy obfuscation on",
    },
    "protocol_tunneling": {
        "mitre": "T1572",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.encapsulation",
        "selection_value": "tunnel",
        "event_type": "network_obfuscation_protocol_tunneling",
        "title_prefix": "Protocol-tunneling obfuscation on",
    },
    "jitter_padding": {
        "mitre": "T1001.003",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.payload_padding",
        "selection_value": "padded",
        "event_type": "network_obfuscation_jitter_padding",
        "title_prefix": "Jitter/padding obfuscation on",
    },
}


class NetworkObfuscatorModule(BaseModule):
    name = "network_obfuscator"
    attack_techniques = (
        "T1572",
        "T1090.001",
        "T1090.002",
        "T1090.003",
        "T1090.004",
        "T1001.003",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("protocol") or "dns").lower()
        profile_key = (
            requested if requested in _NETWORK_OBFUSCATOR_PROFILES else "dns"
        )
        profile = _NETWORK_OBFUSCATOR_PROFILES[profile_key]

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details={
                "protocol": profile_key,
                "mitre_technique": profile["mitre"],
                "selection_value": profile["selection_value"],
            },
        )
        hints = {
            "title": f"{profile['title_prefix']} egress channel",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "network_protocol": profile_key,
            "obfuscation_profile": profile_key,
        }
        if requested != profile_key:
            hints["unrecognized_obfuscation_protocol"] = requested

        return _result(
            self.name,
            "success",
            f"Simulated network obfuscation via '{profile_key}'.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "protocol": profile_key,
                "mitre_technique": profile["mitre"],
            },
        )


# Resource-development profile catalog.
_RESOURCE_DEVELOPMENT_PROFILES: Dict[str, Dict[str, Any]] = {
    "domain": {
        "mitre": "T1583.001",
        "logsource": {"category": "infrastructure_provisioning", "product": "registrar"},
        "selection_field": "resource.kind",
        "event_type": "resource_development_domain",
        "title_prefix": "Adversary domain registration:",
    },
    "vps": {
        "mitre": "T1583.003",
        "logsource": {"category": "infrastructure_provisioning", "product": "cloud"},
        "selection_field": "resource.kind",
        "event_type": "resource_development_vps",
        "title_prefix": "Adversary VPS provisioning:",
    },
    "web_service": {
        "mitre": "T1583.006",
        "logsource": {"category": "infrastructure_provisioning", "product": "saas"},
        "selection_field": "resource.kind",
        "event_type": "resource_development_web_service",
        "title_prefix": "Adversary web-service account:",
    },
    "email_account": {
        "mitre": "T1585.002",
        "logsource": {"category": "account_provisioning", "product": "saas"},
        "selection_field": "resource.kind",
        "event_type": "resource_development_email_account",
        "title_prefix": "Adversary email-account creation:",
    },
    "social_account": {
        "mitre": "T1585.001",
        "logsource": {"category": "account_provisioning", "product": "saas"},
        "selection_field": "resource.kind",
        "event_type": "resource_development_social_account",
        "title_prefix": "Adversary social-media account:",
    },
    "code_signing_cert": {
        "mitre": "T1588.003",
        "logsource": {"category": "certificate_acquisition", "product": "ca"},
        "selection_field": "resource.kind",
        "event_type": "resource_development_code_signing_cert",
        "title_prefix": "Code-signing certificate acquisition:",
    },
    "compromised_infrastructure": {
        "mitre": "T1584.001",
        "logsource": {"category": "infrastructure_provisioning", "product": "compromised"},
        "selection_field": "resource.kind",
        "event_type": "resource_development_compromised_infrastructure",
        "title_prefix": "Compromised-infrastructure acquisition:",
    },
    "malware": {
        "mitre": "T1588.001",
        "logsource": {"category": "tooling_acquisition", "product": "marketplace"},
        "selection_field": "resource.kind",
        "event_type": "resource_development_malware",
        "title_prefix": "Adversary malware acquisition:",
    },
    "exploit": {
        "mitre": "T1588.005",
        "logsource": {"category": "tooling_acquisition", "product": "marketplace"},
        "selection_field": "resource.kind",
        "event_type": "resource_development_exploit",
        "title_prefix": "Adversary exploit acquisition:",
    },
    "vulnerability": {
        "mitre": "T1588.006",
        "logsource": {"category": "threat_intelligence", "product": "vuln_feed"},
        "selection_field": "resource.kind",
        "event_type": "resource_development_vulnerability",
        "title_prefix": "Adversary vulnerability acquisition:",
    },
}


class ResourceDevelopmentModule(BaseModule):
    name = "resource_development"
    attack_techniques = (
        "T1583.001",
        "T1583.003",
        "T1583.006",
        "T1585.001",
        "T1585.002",
        "T1588.001",
        "T1588.003",
        "T1588.005",
        "T1588.006",
        "T1584.001",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("resource_type") or "domain").lower()
        profile_key = (
            requested if requested in _RESOURCE_DEVELOPMENT_PROFILES else "domain"
        )
        # `target` for resource_development means "the domain / vps /
        # cert / etc. being registered". Surface it into artifacts so
        # downstream propagation consumers (e.g. command_control's
        # `c2_endpoint_from_step`) can pick up the registered
        # infrastructure as the C2 endpoint.
        target = str(params.get("target") or "").strip()
        # Backwards-compat: legacy default "infrastructure" -> map to "vps".
        if requested == "infrastructure":
            profile_key = "vps"
        profile = _RESOURCE_DEVELOPMENT_PROFILES[profile_key]

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details={
                "resource_type": profile_key,
                "mitre_technique": profile["mitre"],
            },
        )
        hints = {
            "title": f"{profile['title_prefix']} {profile_key}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile_key},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "resource_type": profile_key,
        }
        if requested not in _RESOURCE_DEVELOPMENT_PROFILES and requested != "infrastructure":
            hints["unrecognized_resource_type"] = requested

        artifacts: Dict[str, Any] = {
            "resource_type": profile_key,
            "mitre_technique": profile["mitre"],
        }
        if target:
            artifacts["target"] = target
        return _result(
            self.name,
            "success",
            f"Simulated resource development: {profile_key}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts=artifacts,
        )


# Reconnaissance source catalog.
_RECONNAISSANCE_PROFILES: Dict[str, Dict[str, Any]] = {
    "osint": {
        "mitre": "T1593",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_host|in",
        "selection_value": ["github.com", "linkedin.com"],
        "event_type": "reconnaissance_osint",
        "title_prefix": "OSINT reconnaissance from",
    },
    "whois": {
        "mitre": "T1590.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 43,
        "event_type": "reconnaissance_whois",
        "title_prefix": "WHOIS reconnaissance from",
    },
    "dns_records": {
        "mitre": "T1590.002",
        "logsource": {"category": "dns", "product": "network"},
        "selection_field": "dns.record_type|in",
        "selection_value": ["MX", "SOA", "TXT"],
        "event_type": "reconnaissance_dns_records",
        "title_prefix": "DNS-record reconnaissance from",
    },
    "email_harvesting": {
        "mitre": "T1589.002",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_host|contains",
        "selection_value": "hunter.io",
        "event_type": "reconnaissance_email_harvesting",
        "title_prefix": "Email-address harvesting from",
    },
    "social_media": {
        "mitre": "T1593.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_host|in",
        "selection_value": ["twitter.com", "x.com", "linkedin.com"],
        "event_type": "reconnaissance_social_media",
        "title_prefix": "Social-media reconnaissance from",
    },
    "search_engine": {
        "mitre": "T1593.002",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_host|in",
        "selection_value": ["google.com", "bing.com", "duckduckgo.com"],
        "event_type": "reconnaissance_search_engine",
        "title_prefix": "Search-engine reconnaissance from",
    },
    "code_repository": {
        "mitre": "T1593.003",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_host|in",
        "selection_value": ["github.com", "gitlab.com", "bitbucket.org"],
        "event_type": "reconnaissance_code_repository",
        "title_prefix": "Code-repository reconnaissance from",
    },
    "active_scan": {
        "mitre": "T1595.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 0,
        "event_type": "reconnaissance_active_scan",
        "title_prefix": "Active IP-block scan from",
    },
    "service_banner": {
        "mitre": "T1595.002",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.banner_grab",
        "selection_value": True,
        "event_type": "reconnaissance_service_banner",
        "title_prefix": "Service-banner scan from",
    },
    "vuln_scan": {
        "mitre": "T1595.002",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.tool",
        "selection_value": "vuln_scanner",
        "event_type": "reconnaissance_vuln_scan",
        "title_prefix": "Vulnerability scan from",
    },
}


class ReconnaissanceModule(BaseModule):
    name = "reconnaissance"
    attack_techniques = (
        "T1593",
        "T1593.001",
        "T1593.002",
        "T1593.003",
        "T1590.001",
        "T1590.002",
        "T1589.002",
        "T1595.001",
        "T1595.002",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("source") or "osint").lower()
        profile_key = (
            requested if requested in _RECONNAISSANCE_PROFILES else "osint"
        )
        profile = _RECONNAISSANCE_PROFILES[profile_key]

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details={
                "source": profile_key,
                "mitre_technique": profile["mitre"],
                "selection_value": profile["selection_value"],
            },
        )
        hints = {
            "title": f"{profile['title_prefix']} {profile_key}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "reconnaissance_source": profile_key,
        }
        if requested != profile_key:
            hints["unrecognized_recon_source"] = requested

        return _result(
            self.name,
            "success",
            f"Simulated reconnaissance via '{profile_key}'.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts={
                "source": profile_key,
                "mitre_technique": profile["mitre"],
            },
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
        # Optional step-to-step propagation: when the scenario step
        # sets `target_from_step: <step_id>` and does NOT pass an
        # explicit `target`, pick up the upstream step's
        # `artifacts.target` (single-target upstream) or first entry
        # of `artifacts.targets` (multi-target upstream like
        # discovery). Explicit `target` always wins.
        target, propagated_from = resolve_target_from_step(
            params, context, fallback="lab-host"
        )

        # Default behaviour mirrors the rest of the standard modules: no
        # subprocess / socket / HTTP calls under any input. Per-technique
        # telemetry shape is synthesised so detection drafts vary by
        # technique rather than emitting a single hardcoded shape.
        details: Dict[str, Any] = {
            "technique": profile_key,
            "target": target,
            "mitre_technique": profile["mitre"],
            "selection_value": profile["selection_value"],
        }
        if propagated_from:
            details["target_propagated_from_step"] = propagated_from

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=details,
        )
        hints: Dict[str, Any] = {
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
        if propagated_from:
            hints["target_propagated_from_step"] = propagated_from

        artifacts: Dict[str, Any] = {
            "technique": profile_key,
            "target": target,
            "mitre_technique": profile["mitre"],
        }
        if propagated_from:
            artifacts["target_propagated_from_step"] = propagated_from

        return _result(
            self.name,
            "success",
            f"Simulated credential-access technique '{profile_key}' against {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts=artifacts,
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

        # Two independent step-to-step propagation slots:
        #   - `target_from_step` resolves the lateral-movement
        #     destination (where the attacker pivots TO). Pairs
        #     naturally with discovery (the upstream step that
        #     enumerated reachable hosts).
        #   - `source_from_step` resolves the attacker host (where
        #     the lateral movement originates FROM). Pairs naturally
        #     with credential_access (the upstream step that
        #     harvested creds on the pivot host).
        # Both slots are optional and independent. Explicit `target`
        # / `source` always win over their respective propagated
        # values. Falling back to the documented module defaults
        # ("lab-host" / "lab-attacker") preserves prior behaviour
        # for callers that don't opt in.
        target, target_propagated_from = resolve_target_from_step(
            params, context, fallback="lab-host"
        )
        source, source_propagated_from = resolve_target_from_step(
            params,
            context,
            fallback="lab-attacker",
            param_key="source",
            step_param_key="source_from_step",
        )

        details: Dict[str, Any] = {
            "technique": profile_key,
            "source": source,
            "target": target,
            "mitre_technique": profile["mitre"],
            "selection_value": profile["selection_value"],
        }
        if target_propagated_from:
            details["target_propagated_from_step"] = target_propagated_from
        if source_propagated_from:
            details["source_propagated_from_step"] = source_propagated_from

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=details,
        )
        hints: Dict[str, Any] = {
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
        if target_propagated_from:
            hints["target_propagated_from_step"] = target_propagated_from
        if source_propagated_from:
            hints["source_propagated_from_step"] = source_propagated_from

        artifacts: Dict[str, Any] = {
            "technique": profile_key,
            "source": source,
            "target": target,
            "mitre_technique": profile["mitre"],
        }
        if target_propagated_from:
            artifacts["target_propagated_from_step"] = target_propagated_from
        if source_propagated_from:
            artifacts["source_propagated_from_step"] = source_propagated_from

        return _result(
            self.name,
            "success",
            f"Simulated lateral-movement technique '{profile_key}' from {source} to {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts=artifacts,
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

        # Step-to-step propagation (PR #64): impact pairs naturally
        # with collection / staging steps. The collection module's
        # artifacts carry ``target`` (the host where data was staged);
        # an impact step that would simulate destruction / encryption
        # on that same host can opt in via ``target_from_step``
        # rather than re-declare the host name. Explicit ``target``
        # always wins; falling back to the documented module default
        # (``lab-host``) preserves prior behaviour for callers that
        # don't opt in.
        target, target_propagated_from = resolve_target_from_step(
            params, context, fallback="lab-host"
        )

        details: Dict[str, Any] = {
            "technique": profile_key,
            "target": target,
            "mitre_technique": profile["mitre"],
            "selection_value": profile["selection_value"],
        }
        if target_propagated_from:
            details["target_propagated_from_step"] = target_propagated_from

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=details,
        )
        hints: Dict[str, Any] = {
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
        if target_propagated_from:
            hints["target_propagated_from_step"] = target_propagated_from

        artifacts: Dict[str, Any] = {
            "technique": profile_key,
            "target": target,
            "mitre_technique": profile["mitre"],
        }
        if target_propagated_from:
            artifacts["target_propagated_from_step"] = target_propagated_from

        return _result(
            self.name,
            "success",
            f"Simulated impact technique '{profile_key}' on {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts=artifacts,
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
        # The wrapped module's behaviour is opaque to this adapter; we
        # cannot map it to a Sysmon-shaped logsource (process_creation /
        # file_event / registry_event / etc.) without inspecting the
        # legacy class. Emit an explicitly-labeled `legacy_wrapped`
        # logsource + selection so any Sigma / YARA-L / SPL draft built
        # from this hint surfaces as "needs operator review" rather than
        # silently falling back to ``process_creation/windows`` (which
        # would mis-label every wrapped legacy module as a Windows
        # process-creation rule).
        hints = {
            "title": f"Wrapped legacy module activity ({self.name})",
            "mitre_technique": "T0000",
            "logsource": {"category": "legacy_wrapped", "product": "bluefire"},
            "detection": {
                "selection": {"event.module": self.name},
                "condition": "selection",
            },
            "wrapped_module": self.name,
            "needs_operator_review": True,
        }
        return _result(
            self.name,
            "success" if status in {"success", "partial_success"} else "failure",
            message,
            artifacts={"legacy_result": artifacts},
            hints=hints,
            telemetry=telemetry,
            error=raw.get("error"),
        )
