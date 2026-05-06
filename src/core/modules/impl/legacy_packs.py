"""Legacy capability pack adapters for actor, C2, stealth, and tactic research code."""

from __future__ import annotations

from typing import Any, Dict, Mapping
from urllib.parse import urlparse

from ...legacy_controls import (
    build_legacy_summary,
    capability_effective_enabled,
    evaluate_legacy_capability,
)
from ...models import ModuleResult, TelemetryEvent
from ..base import BaseModule
from .legacy_base import LegacyAdapterBase, _result
from .legacy_runtime import (
    CREDENTIAL_TECHNIQUE_KEYS,
    LATERAL_MOVEMENT_TECHNIQUE_KEYS,
    PRIVILEGE_ESCALATION_TECHNIQUE_KEYS,
    flatten_indicators,
    instantiate_apt_actor,
    normalize_protocol_key,
    normalize_stealth_key,
    run_actor_technique,
    run_credential_access,
    run_dns_tunneling,
    run_lateral_movement,
    run_network_obfuscation,
    run_privilege_escalation,
    run_quic_placeholder,
    run_solana_rpc,
    run_stealth_capability,
    run_tls_fast_flux,
    safe_call,
)


def _capability_artifacts(
    context: Mapping[str, Any],
    pack: str,
    capability: str,
    mode: str,
    payload: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "legacy": {
            "summary": build_legacy_summary(context.get("config", {})),
            "pack": pack,
            "capability": capability,
            "mode": mode,
            "payload": dict(payload or {}),
        }
    }


def _endpoint_host(endpoint: str) -> str:
    if "://" in endpoint:
        return (urlparse(endpoint).hostname or "").lower()
    return endpoint.split("/", 1)[0].split(":", 1)[0].lower()


class LegacyPackSummaryModule(BaseModule):
    """Expose effective legacy enablement state as a runtime module."""

    name = "legacy_capability_summary"
    attack_techniques = ()

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        summary = build_legacy_summary(context.get("config", {}))
        event = TelemetryEvent(
            event_type="legacy_capability_summary",
            module=self.name,
            details={"run_id": context.get("run_id", "unknown"), "summary": summary},
        )
        return _result(
            self.name,
            "success",
            "Collected legacy capability enablement summary.",
            artifacts={"legacy_summary": summary, "requested": dict(params)},
            telemetry=[event],
        )


class LegacyActorProfileModule(LegacyAdapterBase):
    name = "legacy_actor_profile"
    attack_techniques = ("T1589", "T1591")
    pack_name = "actor_pack"
    capability_name = "actor_profile"

    _PROFILE_MAP = {
        "apt29": {"name": "APT29", "aliases": ["Cozy Bear"], "focus": "credential_access"},
        "apt28": {"name": "APT28", "aliases": ["Fancy Bear"], "focus": "political_espionage"},
        "apt32": {"name": "APT32", "aliases": ["OceanLotus"], "focus": "corporate_espionage"},
        "apt38": {"name": "APT38", "aliases": ["Lazarus Group"], "focus": "financial_operations"},
        "apt41": {"name": "APT41", "aliases": ["Winnti"], "focus": "supply_chain"},
    }

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        actor_key = str(params.get("actor", "apt29")).lower()
        profile = dict(self._PROFILE_MAP.get(actor_key, self._PROFILE_MAP["apt29"]))
        decision = evaluate_legacy_capability(context.get("config", {}), self.pack_name, actor_key)
        enabled = decision.enabled
        mode = decision.mode
        self._ensure_allowed(
            context,
            pack_name=self.pack_name,
            capability_name=actor_key,
            effective_enabled=enabled,
            mode=mode,
        )

        tactics = list(params.get("tactics", [])) or [profile["focus"]]
        runtime = safe_call(instantiate_apt_actor, actor_key) if mode == "emulate" else None
        runtime_class = (
            runtime.__class__.__name__
            if runtime is not None and not isinstance(runtime, dict)
            else "simulated"
        )
        event = TelemetryEvent(
            event_type="legacy_actor_profile",
            module=self.name,
            details={
                "run_id": context.get("run_id", "unknown"),
                "actor": actor_key,
                "mode": mode,
                "tactics": tactics,
                "runtime_class": runtime_class,
            },
        )
        hints = {
            "title": f"Legacy actor profile enabled: {profile['name']}",
            "logsource": {"category": "threat_intelligence", "product": "generic"},
            "detection": {
                "selection": {
                    "legacy.actor": profile["name"],
                    "legacy.mode": mode,
                },
                "condition": "selection",
            },
            "mitre_technique": "T1589",
        }
        artifacts = _capability_artifacts(
            context,
            self.pack_name,
            actor_key,
            mode,
            {
                "profile": profile,
                "tactics": tactics,
                "runtime_class": runtime_class,
                "simulate_only": mode == "simulate",
            },
        )
        artifacts["actor_profile"] = profile
        artifacts["tactics"] = tactics
        return _result(
            self.name,
            "success",
            f"Legacy actor profile '{profile['name']}' ready in {mode} mode.",
            techniques=["T1589"],
            artifacts=artifacts,
            hints=hints,
            telemetry=[event],
        )


class LegacyApt29ResearchModule(LegacyAdapterBase):
    name = "legacy_apt29_research"
    attack_techniques = ("T1566", "T1059", "T1036", "T1071.004")
    pack_name = "actor_pack"
    capability_name = "apt29"
    actor_signature = "cozy_bear_dukes"
    aka = ("Cozy Bear", "The Dukes", "Nobelium", "Midnight Blizzard")

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        decision = evaluate_legacy_capability(
            context.get("config", {}),
            self.pack_name,
            self.capability_name,
        )
        mode = decision.mode
        self._ensure_allowed(
            context,
            pack_name=self.pack_name,
            capability_name=self.capability_name,
            effective_enabled=decision.enabled,
            mode=mode,
        )
        technique = str(params.get("technique", "phishing")).lower()
        target = str(params.get("target", "lab-user"))

        details: Dict[str, Any]
        hints: Dict[str, Any]
        techniques: list[str]
        if technique == "phishing":
            campaign_id = f"APT29-CAMP-{context.get('run_id', 'run')[-8:]}"
            details = {
                "campaign_id": campaign_id,
                "sender": "security@example.lab",
                "target": target,
                "delivery_method": "attachment",
            }
            hints = {
                "title": "APT29-style phishing campaign",
                "logsource": {"category": "email", "product": "generic"},
                "detection": {
                    "selection": {
                        "email.sender": details["sender"],
                        "email.subject|contains": "Security",
                    },
                    "condition": "selection",
                },
                "mitre_technique": "T1566",
            }
            techniques = ["T1566"]
        elif technique == "powershell":
            command = str(
                params.get("command")
                or "powershell -nop -w hidden -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA="
            )
            details = {
                "command": command,
                "bypass_technique": "amsi_bypass",
                "execution_method": "scheduled_task",
            }
            hints = {
                "title": "APT29-style PowerShell execution",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "process.command_line|contains": "powershell",
                        "process.command_line|contains_any": ["-enc", "-nop"],
                    },
                    "condition": "selection",
                },
                "mitre_technique": "T1059",
                "process_command_line": command,
            }
            techniques = ["T1059"]
        elif technique == "process_hollowing":
            target_process = str(params.get("target_process", "svchost.exe"))
            details = {
                "target_process": target_process,
                "hollowing_method": "ntunmap",
                "detection_evasion": ["parent_process_spoofing", "command_line_spoofing"],
            }
            hints = {
                "title": "APT29-style process hollowing research",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "process.image": target_process,
                        "process.integrity_level": "suspicious",
                    },
                    "condition": "selection",
                },
                "mitre_technique": "T1036",
            }
            techniques = ["T1036"]
        else:
            data_size = int(params.get("data_size", 4096))
            details = {
                "protocol": "dns",
                "channel": "fallback",
                "data_size": data_size,
                "target_domain": "cdn.example.lab",
            }
            hints = {
                "title": "APT29-style DNS C2 research",
                "logsource": {"category": "dns", "product": "network"},
                "detection": {
                    "selection": {
                        "dns.question.name|contains": "example.lab",
                        "dns.query_length": "suspicious",
                    },
                    "condition": "selection",
                },
                "mitre_technique": "T1071.004",
            }
            techniques = ["T1071.004"]

        # Inject the per-actor signature + alias surface so APT29's detection
        # drafts carry the same correlation fields as the per-actor APT28/32/
        # 38/41 adapters. Defenders can then filter Sigma/SPL rules by actor
        # signature regardless of which actor pack produced them.
        selection = hints.setdefault("detection", {}).setdefault("selection", {})
        if self.actor_signature:
            selection["legacy.actor_signature"] = self.actor_signature
        if self.aka:
            selection["legacy.actor_aka"] = list(self.aka)

        if mode == "emulate":
            runtime = safe_call(
                run_actor_technique,
                "apt29",
                self._resolve_tactic(technique),
                technique,
                {**dict(params), "target": target},
            )
            details["runtime_outcome"] = runtime
            indicators = flatten_indicators(runtime)
            if indicators:
                details["runtime_indicators"] = indicators
                hints.setdefault("legacy_indicators", {}).update(indicators)
            if runtime.get("status") == "failure":
                details["runtime_warning"] = (
                    "legacy actor runtime failed for apt29/"
                    f"{technique}: {runtime.get('error')}"
                )
        else:
            details["runtime_outcome"] = {
                "status": "simulated",
                "actor": "apt29",
                "technique": technique,
                "reason": "simulate mode selected",
            }

        event = TelemetryEvent(
            event_type="legacy_apt29_research",
            module=self.name,
            details={
                "run_id": context.get("run_id", "unknown"),
                "mode": mode,
                "technique": technique,
                **details,
            },
        )
        artifacts = _capability_artifacts(
            context,
            self.pack_name,
            self.capability_name,
            mode,
            details,
        )
        return _result(
            self.name,
            "success",
            f"APT29 legacy research technique '{technique}' prepared in {mode} mode.",
            techniques=techniques,
            artifacts=artifacts,
            hints=hints,
            telemetry=[event],
        )

    @staticmethod
    def _resolve_tactic(technique: str) -> str:
        if technique == "phishing":
            return "initial_access"
        if technique == "powershell":
            return "execution"
        if technique == "process_hollowing":
            return "defense_evasion"
        return "command_and_control"


class LegacyGenericActorTechniqueModule(LegacyAdapterBase):
    """Adapter base for non-APT29 actor profile classes.

    Per-actor subclasses below override `_TACTIC_TO_TECHNIQUE`,
    `attack_techniques`, and `actor_signature` so each actor's adapter
    emits the technique surface and detection-relevant identifiers
    matching public reporting on that actor's tradecraft. The base
    class keeps the generic mapping so direct instantiation still
    works for testing.
    """

    attack_techniques = ("T1589", "T1059", "T1071")
    pack_name = "actor_pack"
    capability_name = "apt28"
    actor_name = "APT28"
    actor_signature: str = ""
    aka: tuple[str, ...] = ()

    _TACTIC_TO_TECHNIQUE: Mapping[str, str] = {
        "initial_access": "T1566",
        "execution": "T1059",
        "defense_evasion": "T1036",
        "command_and_control": "T1071",
    }

    # Tactic -> Sigma logsource. Falls back to threat_intelligence/generic
    # when the tactic isn't in this map. Per-actor subclasses can override
    # to emit different log surfaces (e.g. APT32 watering-hole tradecraft).
    _TACTIC_TO_LOGSOURCE: Mapping[str, Mapping[str, str]] = {
        "initial_access": {"category": "email", "product": "generic"},
        "execution": {"category": "process_creation", "product": "host"},
        "defense_evasion": {"category": "process_creation", "product": "host"},
        "command_and_control": {"category": "network_connection", "product": "host"},
    }

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        actor_key = self.actor_name.lower()
        decision = evaluate_legacy_capability(context.get("config", {}), self.pack_name, actor_key)
        mode = decision.mode
        self._ensure_allowed(
            context,
            pack_name=self.pack_name,
            capability_name=actor_key,
            effective_enabled=capability_effective_enabled(
                context.get("config", {}),
                self.pack_name,
                actor_key,
            ),
            mode=mode,
        )
        tactic = str(params.get("tactic", "execution")).lower()
        technique = str(params.get("technique", "powershell"))
        target = str(params.get("target", "lab-user"))
        details = {
            "actor": self.actor_name,
            "tactic": tactic,
            "technique": technique,
            "target": target,
            "mode": mode,
        }
        mitre = self._TACTIC_TO_TECHNIQUE.get(tactic, "T1589")

        if mode == "emulate":
            runtime = safe_call(
                run_actor_technique,
                actor_key,
                tactic,
                technique,
                {**dict(params), "target": target},
            )
            details["runtime_outcome"] = runtime
            indicators = flatten_indicators(runtime)
            if indicators:
                details["runtime_indicators"] = indicators
            if runtime.get("status") == "failure":
                details["runtime_warning"] = (
                    "legacy actor runtime failed for "
                    f"{actor_key}/{technique}: {runtime.get('error')}"
                )
        else:
            details["runtime_outcome"] = {
                "status": "simulated",
                "actor": actor_key,
                "technique": technique,
                "reason": "simulate mode selected",
            }

        event = TelemetryEvent(
            event_type="legacy_actor_technique",
            module=self.name,
            details={"run_id": context.get("run_id", "unknown"), **details},
        )
        selection: Dict[str, Any] = {
            "legacy.actor": self.actor_name,
            "legacy.tactic": tactic,
            "legacy.technique": technique,
        }
        if self.actor_signature:
            selection["legacy.actor_signature"] = self.actor_signature
        if self.aka:
            selection["legacy.actor_aka"] = list(self.aka)
        logsource = dict(
            self._TACTIC_TO_LOGSOURCE.get(
                tactic, {"category": "threat_intelligence", "product": "generic"}
            )
        )
        hints = {
            "title": f"{self.actor_name} legacy technique: {tactic}/{technique}",
            "logsource": logsource,
            "detection": {
                "selection": selection,
                "condition": "selection",
            },
            "mitre_technique": mitre,
        }
        artifacts = _capability_artifacts(
            context,
            self.pack_name,
            actor_key,
            mode,
            details,
        )
        return _result(
            self.name,
            "success",
            f"{self.actor_name} legacy tactic '{tactic}' / '{technique}' prepared in {mode} mode.",
            techniques=[mitre],
            artifacts=artifacts,
            hints=hints,
            telemetry=[event],
        )


class LegacyApt28ResearchModule(LegacyGenericActorTechniqueModule):
    """APT28 / Sofacy / Fancy Bear adapter.

    Refines the generic actor surface for APT28's commonly-reported
    tradecraft: spearphishing attachments (T1566.001), PowerShell
    execution (T1059.001), obfuscation (T1027), and HTTP/HTTPS C2
    (T1071.001).
    """

    name = "legacy_apt28_research"
    capability_name = "apt28"
    actor_name = "APT28"
    actor_signature = "fancy_bear_sofacy"
    aka = ("Fancy Bear", "Sofacy", "Sednit", "Strontium", "Pawn Storm")
    attack_techniques = ("T1566", "T1566.001", "T1059.001", "T1027", "T1071", "T1071.001")
    _TACTIC_TO_TECHNIQUE: Mapping[str, str] = {
        "initial_access": "T1566.001",
        "execution": "T1059.001",
        "defense_evasion": "T1027",
        "command_and_control": "T1071.001",
    }


class LegacyApt32ResearchModule(LegacyGenericActorTechniqueModule):
    """APT32 / OceanLotus adapter.

    Reflects OceanLotus tradecraft: spearphishing attachment + link
    (T1566.001 / T1566.002), Visual Basic loaders such as KerrDown
    (T1059.005), obfuscation (T1027), HTTPS C2 (T1071.001), and
    drive-by / watering-hole compromise (T1189).
    """

    name = "legacy_apt32_research"
    capability_name = "apt32"
    actor_name = "APT32"
    actor_signature = "oceanlotus"
    aka = ("OceanLotus", "SeaLotus", "Cobalt Kitty", "APT-C-00")
    attack_techniques = (
        "T1566.001",
        "T1566.002",
        "T1059.005",
        "T1027",
        "T1071.001",
        "T1189",
    )
    _TACTIC_TO_TECHNIQUE: Mapping[str, str] = {
        "initial_access": "T1566.001",
        "execution": "T1059.005",
        "defense_evasion": "T1027",
        "command_and_control": "T1071.001",
    }


class LegacyApt38ResearchModule(LegacyGenericActorTechniqueModule):
    """APT38 / Lazarus financial sub-cluster adapter.

    Reflects financially-motivated DPRK tradecraft: spearphishing
    (T1566), PowerShell (T1059.001), disk-wiping for cover-up
    (T1561), HTTPS C2 (T1071.001), and scheduled-task persistence
    (T1053.005).
    """

    name = "legacy_apt38_research"
    capability_name = "apt38"
    actor_name = "APT38"
    actor_signature = "lazarus_apt38"
    aka = ("Lazarus (financial)", "Bluenoroff", "Stardust Chollima")
    attack_techniques = (
        "T1566",
        "T1059.001",
        "T1561",
        "T1071.001",
        "T1053.005",
    )
    _TACTIC_TO_TECHNIQUE: Mapping[str, str] = {
        "initial_access": "T1566",
        "execution": "T1059.001",
        "defense_evasion": "T1561",
        "command_and_control": "T1071.001",
    }


class LegacyApt41ResearchModule(LegacyGenericActorTechniqueModule):
    """APT41 dual-purpose adapter.

    Reflects APT41's mixed espionage/criminal tradecraft:
    spearphishing (T1566), PowerShell loaders (T1059.001), web
    shells (T1505.003), HTTPS C2 (T1071.001), and WMI-event
    persistence (T1546.003).
    """

    name = "legacy_apt41_research"
    capability_name = "apt41"
    actor_name = "APT41"
    actor_signature = "apt41_dual_use"
    aka = ("Wicked Panda", "Barium", "Winnti")
    attack_techniques = (
        "T1566",
        "T1059.001",
        "T1505.003",
        "T1071.001",
        "T1546.003",
    )
    _TACTIC_TO_TECHNIQUE: Mapping[str, str] = {
        "initial_access": "T1566",
        "execution": "T1059.001",
        "defense_evasion": "T1505.003",
        "command_and_control": "T1071.001",
    }


# Per-technique simulate-mode tradecraft notes for the legacy
# credential-access adapter. The `notes` field is what makes the legacy
# adapter distinct from the standard `credential_access` module: it
# surfaces operator-facing context (canonical tools, file paths, follow-
# up extractor commands) sourced from the preserved legacy class. None
# of these notes encode commands the adapter actually executes.
_LEGACY_CREDENTIAL_NOTES: Dict[str, Dict[str, Any]] = {
    "lsass_dump": {
        "title": "Legacy LSASS memory-dump tradecraft research",
        "logsource": {"category": "process_access", "product": "windows"},
        "selection_field": "target.process.name",
        "selection_value": "lsass.exe",
        "event_type": "legacy_credential_access_lsass",
        "notes": {
            "canonical_tools": ["procdump", "comsvcs.dll MiniDump", "WerFault", "MiniDumpWriteDump"],
            "follow_up_extractor": "mimikatz `sekurlsa::minidump` / pypykatz `lsa minidump`",
            "default_dump_path": "C:\\Windows\\Temp\\<random>.dmp",
        },
    },
    "sam_dump": {
        "title": "Legacy SAM hive credential-extraction tradecraft research",
        "logsource": {"category": "registry_event", "product": "windows"},
        "selection_field": "registry.key|contains",
        "selection_value": "SAM",
        "event_type": "legacy_credential_access_sam",
        "notes": {
            "canonical_tools": ["reg save HKLM\\SAM", "esentutl /y /vss"],
            "follow_up_extractor": "secretsdump.py / impacket SAMR",
            "files": ["SYSTEM", "SAM", "SECURITY"],
        },
    },
    "ntds_dump": {
        "title": "Legacy NTDS.dit domain-credential tradecraft research",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "file.path|contains",
        "selection_value": "NTDS.dit",
        "event_type": "legacy_credential_access_ntds",
        "notes": {
            "canonical_tools": ["ntdsutil ifm", "vssadmin create shadow", "esentutl /y /vss"],
            "follow_up_extractor": "secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL",
        },
    },
    "browser_credentials": {
        "title": "Legacy browser stored-credential tradecraft research",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.path|contains",
        "selection_value": "Login Data",
        "event_type": "legacy_credential_access_browser",
        "notes": {
            "browsers": ["chrome", "edge", "firefox"],
            "credential_artifacts": ["Login Data", "Cookies", "key4.db", "logins.json"],
        },
    },
    "keychain": {
        "title": "Legacy macOS Keychain credential tradecraft research",
        "logsource": {"category": "file_event", "product": "macos"},
        "selection_field": "file.path|contains",
        "selection_value": "login.keychain",
        "event_type": "legacy_credential_access_keychain",
        "notes": {
            "canonical_paths": ["~/Library/Keychains/login.keychain-db"],
            "follow_up_extractor": "security find-generic-password / chainbreaker",
        },
    },
    "ssh_keys": {
        "title": "Legacy SSH private-key file-access tradecraft research",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.path|contains",
        "selection_value": ".ssh/id_",
        "event_type": "legacy_credential_access_ssh",
        "notes": {
            "canonical_paths": ["~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/known_hosts"],
            "common_misuse": "passphrase-less keys harvested for lateral movement",
        },
    },
    "keylogging": {
        "title": "Legacy keyboard-input capture tradecraft research",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "SetWindowsHookEx",
        "event_type": "legacy_credential_access_keylogging",
        "notes": {
            "canonical_apis": ["SetWindowsHookEx WH_KEYBOARD_LL", "GetAsyncKeyState"],
            "telemetry_signal": "process registers low-level keyboard hook",
        },
    },
    "clipboard": {
        "title": "Legacy clipboard-data capture tradecraft research",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "GetClipboardData",
        "event_type": "legacy_credential_access_clipboard",
        "notes": {
            "canonical_apis": ["OpenClipboard", "GetClipboardData", "AddClipboardFormatListener"],
            "common_misuse": "wallet-address swap, credential capture between paste actions",
        },
    },
    "screen_capture": {
        "title": "Legacy screen-capture credential-harvest tradecraft research",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "BitBlt",
        "event_type": "legacy_credential_access_screen",
        "notes": {
            "canonical_apis": ["BitBlt", "GetDC", "PrintWindow"],
            "common_misuse": "MFA token / SSO challenge screen capture",
        },
    },
}


class LegacyCredentialAccessModule(LegacyAdapterBase):
    """Adapter for the preserved `CredentialAccess` legacy class.

    Companion to the simulate-only standard `credential_access` module.
    This adapter sits behind the standard legacy gating pattern
    (`tactic_pack` / `credential_access` capability) so the rich
    tradecraft notes from `src/core/credential/credential_access.py`
    are reachable without changing the safety/mode model of the
    standard module. In simulate mode it emits the per-technique notes
    directly. In emulate mode it routes through `safe_call` into the
    legacy class, which itself produces synthesised tradecraft
    descriptors — never live subprocess/socket calls.
    """

    name = "legacy_credential_access"
    pack_name = "tactic_pack"
    capability_name = "credential_access"
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
        decision = self._ensure_allowed(context)
        mode = decision.mode

        requested = str(params.get("technique") or "lsass_dump").lower()
        technique_key = (
            requested if requested in CREDENTIAL_TECHNIQUE_KEYS else "lsass_dump"
        )
        legacy_key, mitre = CREDENTIAL_TECHNIQUE_KEYS[technique_key]
        profile = _LEGACY_CREDENTIAL_NOTES[technique_key]
        target = str(params.get("target") or "lab-host")

        details: Dict[str, Any] = {
            "technique": technique_key,
            "legacy_key": legacy_key,
            "mitre_technique": mitre,
            "target": target,
            "mode": mode,
            "tradecraft_notes": dict(profile["notes"]),
        }

        if mode == "emulate":
            runtime = safe_call(run_credential_access, technique_key, params)
            details["runtime_outcome"] = runtime
            indicators = flatten_indicators(runtime)
            if indicators:
                details["runtime_indicators"] = indicators
            if runtime.get("status") == "failure":
                details["runtime_warning"] = (
                    "legacy credential-access runtime failed for "
                    f"{technique_key}: {runtime.get('error')}"
                )
        else:
            details["runtime_outcome"] = {
                "status": "simulated",
                "technique": technique_key,
                "reason": "simulate mode selected",
            }

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details={
                "run_id": context.get("run_id", "unknown"),
                **details,
            },
        )
        hints: Dict[str, Any] = {
            "title": f"{profile['title']} on {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {
                    profile["selection_field"]: profile["selection_value"],
                    "legacy.pack": self.pack_name,
                    "legacy.capability": self.capability_name,
                    "legacy.technique": technique_key,
                },
                "condition": "selection",
            },
            "mitre_technique": mitre,
            "credential_technique": technique_key,
            "target_host": target,
            "tradecraft_notes": dict(profile["notes"]),
        }
        if requested != technique_key:
            hints["unrecognized_credential_technique"] = requested

        artifacts = _capability_artifacts(
            context,
            self.pack_name,
            self.capability_name,
            mode,
            details,
        )
        return _result(
            self.name,
            "success",
            f"Legacy credential-access tradecraft for '{technique_key}' "
            f"prepared in {mode} mode.",
            techniques=[mitre],
            artifacts=artifacts,
            hints=hints,
            telemetry=[event],
        )


# Per-technique simulate-mode tradecraft notes for the legacy
# lateral-movement adapter. Each entry mirrors the public-record
# tradecraft surface for the technique (canonical tools, file paths,
# protocol/port indicators) sourced from the preserved legacy class.
_LEGACY_LATERAL_MOVEMENT_NOTES: Dict[str, Dict[str, Any]] = {
    "psexec": {
        "title": "Legacy PsExec lateral-movement tradecraft research",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "PsExec",
        "event_type": "legacy_lateral_movement_psexec",
        "notes": {
            "canonical_tools": ["PsExec", "smbexec.py", "PAExec"],
            "service_name_pattern": "PSEXESVC",
            "default_share": "ADMIN$",
        },
    },
    "wmi": {
        "title": "Legacy WMI remote-execution tradecraft research",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "wmic",
        "event_type": "legacy_lateral_movement_wmi",
        "notes": {
            "canonical_tools": ["wmic.exe", "Invoke-WmiMethod", "wmiexec.py"],
            "telemetry_signal": "wmiprvse spawning unusual children",
        },
    },
    "powershell_remoting": {
        "title": "Legacy PowerShell remoting tradecraft research",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "Invoke-Command",
        "event_type": "legacy_lateral_movement_powershell_remoting",
        "notes": {
            "canonical_tools": ["Invoke-Command", "Enter-PSSession", "wsmprovhost.exe"],
            "transport": "WSMan over HTTP/HTTPS",
        },
    },
    "winrm": {
        "title": "Legacy WinRM/PowerShell-remoting tradecraft research",
        "logsource": {"category": "network_connection", "product": "windows"},
        "selection_field": "network.dst_port",
        "selection_value": 5985,
        "event_type": "legacy_lateral_movement_winrm",
        "notes": {
            "canonical_tools": ["winrs", "Enter-PSSession"],
            "default_ports": [5985, 5986],
            "transport": "WSMan",
        },
    },
    "smb_share": {
        "title": "Legacy SMB administrative-share tradecraft research",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "file.path|contains",
        "selection_value": "ADMIN$",
        "event_type": "legacy_lateral_movement_smb_share",
        "notes": {
            "canonical_tools": ["net use", "smbclient", "Copy-Item -ToSession"],
            "shares": ["ADMIN$", "C$", "IPC$"],
        },
    },
    "ftp_transfer": {
        "title": "Legacy FTP lateral-tool-transfer tradecraft research",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 21,
        "event_type": "legacy_lateral_movement_ftp_transfer",
        "notes": {
            "canonical_tools": ["ftp.exe", "curl ftp://"],
            "default_port": 21,
        },
    },
    "scp_transfer": {
        "title": "Legacy SCP lateral-tool-transfer tradecraft research",
        "logsource": {"category": "process_creation", "product": "linux"},
        "selection_field": "process.command_line|contains",
        "selection_value": "scp ",
        "event_type": "legacy_lateral_movement_scp_transfer",
        "notes": {
            "canonical_tools": ["scp", "rsync -e ssh"],
            "default_port": 22,
        },
    },
    "service_create": {
        "title": "Legacy remote service-creation tradecraft research",
        "logsource": {"category": "service_creation", "product": "windows"},
        "selection_field": "service.image_path|contains",
        "selection_value": "svchost.exe",
        "event_type": "legacy_lateral_movement_service_create",
        "notes": {
            "canonical_tools": ["sc.exe create", "New-Service", "services.py (impacket)"],
            "telemetry_signal": "Windows event 7045 (service installed)",
        },
    },
    "service_modify": {
        "title": "Legacy remote service-modification tradecraft research",
        "logsource": {"category": "service_modification", "product": "windows"},
        "selection_field": "service.image_path|contains",
        "selection_value": "svchost.exe",
        "event_type": "legacy_lateral_movement_service_modify",
        "notes": {
            "canonical_tools": ["sc.exe config", "Set-Service"],
            "telemetry_signal": "registry-key change under HKLM\\SYSTEM\\CurrentControlSet\\Services",
        },
    },
    "service_stop": {
        "title": "Legacy remote service-stop / disruption tradecraft research",
        "logsource": {"category": "service_event", "product": "windows"},
        "selection_field": "service.action",
        "selection_value": "stopped",
        "event_type": "legacy_lateral_movement_service_stop",
        "notes": {
            "canonical_tools": ["sc.exe stop", "Stop-Service"],
            "common_targets": ["AV/EDR services", "backup agents", "logging services"],
        },
    },
}


class LegacyLateralMovementModule(LegacyAdapterBase):
    """Adapter for the preserved `LateralMovement` legacy class.

    Companion to the simulate-only standard `lateral_movement` module.
    Sits behind `tactic_pack` / `lateral_movement` capability gating.
    Surfaces per-technique tradecraft notes (canonical tools, default
    ports, telemetry signals) from `src/core/movement/lateral_movement.py`
    in simulate mode; emulate mode routes through `safe_call` into the
    legacy class which itself returns synthesised tradecraft descriptors
    only — no live network or process side effects.
    """

    name = "legacy_lateral_movement"
    pack_name = "tactic_pack"
    capability_name = "lateral_movement"
    attack_techniques = (
        "T1021.002",
        "T1021.004",
        "T1021.006",
        "T1047",
        "T1059.001",
        "T1105",
        "T1543.003",
        "T1489",
        "T1570",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        decision = self._ensure_allowed(context)
        mode = decision.mode

        requested = str(params.get("technique") or "psexec").lower()
        technique_key = (
            requested if requested in LATERAL_MOVEMENT_TECHNIQUE_KEYS else "psexec"
        )
        branch, legacy_key, mitre = LATERAL_MOVEMENT_TECHNIQUE_KEYS[technique_key]
        profile = _LEGACY_LATERAL_MOVEMENT_NOTES[technique_key]
        target = str(params.get("target") or "lab-host")
        source = str(params.get("source") or "lab-attacker")

        details: Dict[str, Any] = {
            "technique": technique_key,
            "legacy_key": legacy_key,
            "legacy_branch": branch,
            "mitre_technique": mitre,
            "source": source,
            "target": target,
            "mode": mode,
            "tradecraft_notes": dict(profile["notes"]),
        }

        if mode == "emulate":
            runtime = safe_call(run_lateral_movement, technique_key, params)
            details["runtime_outcome"] = runtime
            indicators = flatten_indicators(runtime)
            if indicators:
                details["runtime_indicators"] = indicators
            if runtime.get("status") == "failure":
                details["runtime_warning"] = (
                    "legacy lateral-movement runtime failed for "
                    f"{technique_key}: {runtime.get('error')}"
                )
        else:
            details["runtime_outcome"] = {
                "status": "simulated",
                "technique": technique_key,
                "reason": "simulate mode selected",
            }

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details={
                "run_id": context.get("run_id", "unknown"),
                **details,
            },
        )
        hints: Dict[str, Any] = {
            "title": f"{profile['title']} {source} -> {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {
                    profile["selection_field"]: profile["selection_value"],
                    "legacy.pack": self.pack_name,
                    "legacy.capability": self.capability_name,
                    "legacy.technique": technique_key,
                },
                "condition": "selection",
            },
            "mitre_technique": mitre,
            "lateral_movement_technique": technique_key,
            "source_host": source,
            "target_host": target,
            "tradecraft_notes": dict(profile["notes"]),
        }
        if requested != technique_key:
            hints["unrecognized_lateral_movement_technique"] = requested

        artifacts = _capability_artifacts(
            context,
            self.pack_name,
            self.capability_name,
            mode,
            details,
        )
        return _result(
            self.name,
            "success",
            f"Legacy lateral-movement tradecraft for '{technique_key}' "
            f"prepared in {mode} mode.",
            techniques=[mitre],
            artifacts=artifacts,
            hints=hints,
            telemetry=[event],
        )


# Per-technique simulate-mode tradecraft notes for the legacy
# privilege-escalation adapter. Each entry surfaces the canonical APIs,
# tools, and telemetry signals associated with the technique sourced
# from the preserved legacy class. None of the strings are commands the
# adapter actually executes.
_LEGACY_PRIVILEGE_ESCALATION_NOTES: Dict[str, Dict[str, Any]] = {
    "token_impersonation": {
        "title": "Legacy access-token impersonation tradecraft research",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "ImpersonateLoggedOnUser",
        "event_type": "legacy_privilege_escalation_token_impersonation",
        "notes": {
            "canonical_apis": ["OpenProcessToken", "ImpersonateLoggedOnUser"],
            "follow_up": "act under the impersonated security context",
        },
    },
    "token_duplication": {
        "title": "Legacy token-duplication tradecraft research",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "DuplicateTokenEx",
        "event_type": "legacy_privilege_escalation_token_duplication",
        "notes": {
            "canonical_apis": ["OpenProcessToken", "DuplicateTokenEx", "CreateProcessWithTokenW"],
            "follow_up": "spawn process under the duplicated primary token",
        },
    },
    "token_creation": {
        "title": "Legacy make-and-impersonate token tradecraft research",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "LogonUser",
        "event_type": "legacy_privilege_escalation_token_creation",
        "notes": {
            "canonical_apis": ["LogonUser", "CreateProcessWithLogonW"],
            "telemetry_signal": "Windows event 4624 logon-type 9 (NewCredentials)",
        },
    },
    "process_hollowing": {
        "title": "Legacy process-hollowing tradecraft research",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.command_line|contains",
        "selection_value": "NtUnmapViewOfSection",
        "event_type": "legacy_privilege_escalation_process_hollowing",
        "notes": {
            "canonical_apis": ["CreateProcess CREATE_SUSPENDED", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext"],
            "common_targets": ["svchost.exe", "explorer.exe", "RuntimeBroker.exe"],
        },
    },
    "process_injection": {
        "title": "Legacy process-injection tradecraft research",
        "logsource": {"category": "process_creation", "product": "host"},
        "selection_field": "process.command_line|contains",
        "selection_value": "WriteProcessMemory",
        "event_type": "legacy_privilege_escalation_process_injection",
        "notes": {
            "canonical_apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "NtMapViewOfSection"],
            "techniques_covered": ["DLL injection (T1055.001)", "APC injection (T1055.004)", "Thread execution hijack (T1055.003)"],
        },
    },
    "process_masquerading": {
        "title": "Legacy process-name masquerading tradecraft research",
        "logsource": {"category": "process_creation", "product": "windows"},
        "selection_field": "process.image|endswith",
        "selection_value": "svchost.exe",
        "event_type": "legacy_privilege_escalation_process_masquerading",
        "notes": {
            "common_misuse": "renaming attacker binary to a system-image filename",
            "telemetry_signal": "image path mismatch with parent / unusual command line",
        },
    },
    "service_creation": {
        "title": "Legacy privileged service-creation tradecraft research",
        "logsource": {"category": "service_creation", "product": "windows"},
        "selection_field": "service.image_path|contains",
        "selection_value": "svchost.exe",
        "event_type": "legacy_privilege_escalation_service_creation",
        "notes": {
            "canonical_tools": ["sc.exe create", "New-Service", "OpenSCManager + CreateService"],
            "telemetry_signal": "Windows event 7045 (service installed)",
        },
    },
    "service_modification": {
        "title": "Legacy privileged service-modification tradecraft research",
        "logsource": {"category": "service_modification", "product": "windows"},
        "selection_field": "service.image_path|contains",
        "selection_value": "svchost.exe",
        "event_type": "legacy_privilege_escalation_service_modification",
        "notes": {
            "canonical_tools": ["sc.exe config", "Set-Service", "ChangeServiceConfig"],
            "telemetry_signal": "registry change under HKLM\\SYSTEM\\CurrentControlSet\\Services",
        },
    },
    "service_stop": {
        "title": "Legacy privileged service-stop tradecraft research",
        "logsource": {"category": "service_event", "product": "windows"},
        "selection_field": "service.action",
        "selection_value": "stopped",
        "event_type": "legacy_privilege_escalation_service_stop",
        "notes": {
            "canonical_tools": ["sc.exe stop", "Stop-Service", "ControlService SERVICE_CONTROL_STOP"],
            "common_targets": ["AV/EDR services", "logging services"],
        },
    },
}


class LegacyPrivilegeEscalationModule(LegacyAdapterBase):
    """Adapter for the preserved `PrivilegeEscalation` legacy class.

    Companion to the simulate-only standard `privilege_escalation`
    module. Sits behind `tactic_pack` / `privilege_escalation`
    capability gating. Surfaces per-technique tradecraft notes
    (canonical APIs, tools, telemetry signals) from
    `src/core/privilege/privilege_escalation.py` in simulate mode;
    emulate mode routes through `safe_call` into the legacy class
    which itself returns synthesised tradecraft descriptors only — no
    live syscall, process-injection, or service-control side effects.
    """

    name = "legacy_privilege_escalation"
    pack_name = "tactic_pack"
    capability_name = "privilege_escalation"
    attack_techniques = (
        "T1134.001",
        "T1134.002",
        "T1134.003",
        "T1055",
        "T1055.012",
        "T1036.005",
        "T1543.003",
        "T1489",
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        decision = self._ensure_allowed(context)
        mode = decision.mode

        requested = str(params.get("technique") or "token_impersonation").lower()
        technique_key = (
            requested
            if requested in PRIVILEGE_ESCALATION_TECHNIQUE_KEYS
            else "token_impersonation"
        )
        branch, legacy_key, mitre = PRIVILEGE_ESCALATION_TECHNIQUE_KEYS[technique_key]
        profile = _LEGACY_PRIVILEGE_ESCALATION_NOTES[technique_key]
        target = str(params.get("target") or "lab-host")

        details: Dict[str, Any] = {
            "technique": technique_key,
            "legacy_key": legacy_key,
            "legacy_branch": branch,
            "mitre_technique": mitre,
            "target": target,
            "mode": mode,
            "tradecraft_notes": dict(profile["notes"]),
        }

        if mode == "emulate":
            runtime = safe_call(run_privilege_escalation, technique_key, params)
            details["runtime_outcome"] = runtime
            indicators = flatten_indicators(runtime)
            if indicators:
                details["runtime_indicators"] = indicators
            if runtime.get("status") == "failure":
                details["runtime_warning"] = (
                    "legacy privilege-escalation runtime failed for "
                    f"{technique_key}: {runtime.get('error')}"
                )
        else:
            details["runtime_outcome"] = {
                "status": "simulated",
                "technique": technique_key,
                "reason": "simulate mode selected",
            }

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details={
                "run_id": context.get("run_id", "unknown"),
                **details,
            },
        )
        hints: Dict[str, Any] = {
            "title": f"{profile['title']} on {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {
                    profile["selection_field"]: profile["selection_value"],
                    "legacy.pack": self.pack_name,
                    "legacy.capability": self.capability_name,
                    "legacy.technique": technique_key,
                },
                "condition": "selection",
            },
            "mitre_technique": mitre,
            "privilege_escalation_technique": technique_key,
            "target_host": target,
            "tradecraft_notes": dict(profile["notes"]),
        }
        if requested != technique_key:
            hints["unrecognized_privilege_escalation_technique"] = requested

        artifacts = _capability_artifacts(
            context,
            self.pack_name,
            self.capability_name,
            mode,
            details,
        )
        return _result(
            self.name,
            "success",
            f"Legacy privilege-escalation tradecraft for '{technique_key}' "
            f"prepared in {mode} mode.",
            techniques=[mitre],
            artifacts=artifacts,
            hints=hints,
            telemetry=[event],
        )


class LegacyProtocolResearchModule(LegacyAdapterBase):
    name = "legacy_protocol_research"
    attack_techniques = ("T1071.004", "T1572", "T1090")
    pack_name = "c2_pack"
    capability_name = "dns_tunneling"

    _SUPPORTED = {
        "dns_tunneling": ("T1071.004", "dns"),
        "tls_fast_flux": ("T1090", "https"),
        "websocket_quic": ("T1572", "quic"),
        "solana_rpc": ("T1572", "rpc"),
        "network_obfuscator_legacy": ("T1090", "multi"),
    }

    _DEFAULT_ENDPOINTS = {
        "dns_tunneling": "exfil.example.lab",
        "tls_fast_flux": "https://edge.example.lab",
        "websocket_quic": "quic://edge.example.lab:4433",
        "solana_rpc": "https://rpc.example.lab",
        "network_obfuscator_legacy": "edge.example.lab",
    }

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        capability = normalize_protocol_key(str(params.get("protocol", "dns_tunneling")))
        if capability not in self._SUPPORTED:
            capability = "dns_tunneling"
        self.capability_name = capability
        decision = evaluate_legacy_capability(context.get("config", {}), self.pack_name, capability)
        mode = decision.mode
        self._ensure_allowed(
            context,
            pack_name=self.pack_name,
            capability_name=capability,
            effective_enabled=decision.enabled,
            mode=mode,
        )

        technique, transport = self._SUPPORTED[capability]
        endpoint = str(
            params.get("endpoint")
            or params.get("domain")
            or self._DEFAULT_ENDPOINTS[capability]
        )
        cadence = int(params.get("cadence_seconds", 30))
        endpoint_host = _endpoint_host(endpoint) or endpoint
        details = {
            "protocol": capability,
            "transport": transport,
            "endpoint": endpoint,
            "cadence_seconds": cadence,
            "mode": mode,
            "legacy_subtype": capability,
        }
        if capability == "dns_tunneling":
            details.setdefault("dns_record_type", str(params.get("dns_record_type", "TXT")))
            details.setdefault("chunk_size", int(params.get("chunk_size", 48)))
            details.setdefault("entropy_signal", str(params.get("entropy_signal", "elevated")))
        elif capability == "tls_fast_flux":
            details.setdefault("rotation_count", int(params.get("rotation_count", 1)))
            details.setdefault("tls_ja3", str(params.get("tls_ja3", "771,4866-4867-4865,23-24,0")))
        elif capability == "websocket_quic":
            parsed = urlparse(endpoint) if "://" in endpoint else None
            port = parsed.port if parsed else None
            details.setdefault("udp_port", int(port or params.get("udp_port", 4433)))
            details.setdefault("alpn", str(params.get("alpn", "h3")))
        elif capability == "solana_rpc":
            details.setdefault("instruction", str(params.get("instruction", "noop")))
            details.setdefault("rpc_method", str(params.get("rpc_method", "sendTransaction")))
        else:
            details.setdefault(
                "obfuscation_profile",
                str(params.get("obfuscation_profile", "multi-hop-jitter")),
            )

        if capability != "network_obfuscator_legacy" and not self._domain_allowed(
            context, endpoint
        ):
            return self.blocked_result(
                f"legacy protocol endpoint '{endpoint}' is outside allowed legacy lab domains"
            )

        if mode == "emulate":
            if capability == "dns_tunneling":
                payload = str(params.get("data", "legacy-dns-payload")).encode()
                runtime = safe_call(run_dns_tunneling, endpoint, payload)
            elif capability == "tls_fast_flux":
                runtime = safe_call(run_tls_fast_flux, endpoint, dict(params))
            elif capability == "websocket_quic":
                runtime = safe_call(run_quic_placeholder, endpoint)
            elif capability == "solana_rpc":
                instruction = str(params.get("instruction", "noop"))
                runtime = safe_call(run_solana_rpc, endpoint, instruction)
            else:
                runtime = safe_call(run_network_obfuscation, dict(params))
            details["runtime_outcome"] = runtime
            details["runtime_outcome"].setdefault("protocol", capability)
            indicators = flatten_indicators(runtime)
            if indicators:
                details["runtime_indicators"] = indicators
            if runtime.get("status") == "failure":
                details["runtime_warning"] = (
                    "legacy protocol runtime failed for "
                    f"{capability}: {runtime.get('error')}"
                )
        else:
            details["runtime_outcome"] = {
                "status": "simulated",
                "protocol": capability,
                "reason": "simulate mode selected",
            }

        event = TelemetryEvent(
            event_type="legacy_protocol_research",
            module=self.name,
            details={"run_id": context.get("run_id", "unknown"), **details},
        )
        hints = {
            "title": f"Legacy protocol research: {capability}",
            "logsource": {"category": "network_connection", "product": "network"},
            "detection": {
                "selection": {
                    "network.transport": transport,
                    "network.endpoint|contains": endpoint_host,
                    "legacy.capability": capability,
                    "legacy.mode": mode,
                },
                "condition": "selection",
            },
            "mitre_technique": technique,
            "network_url": endpoint,
            "endpoint": endpoint,
            "transport": transport,
            "protocol": capability,
            "cadence_seconds": cadence,
            "legacy_subtype": capability,
        }
        if capability == "dns_tunneling":
            hints.update(
                {
                    "event_type": "DNS_QUERY",
                    "dns_record_type": details.get("dns_record_type"),
                    "chunk_size": details.get("chunk_size"),
                    "entropy_signal": details.get("entropy_signal"),
                }
            )
            hints["detection"]["selection"].update(
                {
                    "dns.question.name|contains": endpoint_host,
                    "dns.record_type": details.get("dns_record_type"),
                }
            )
        elif capability == "tls_fast_flux":
            hints.update(
                {
                    "event_type": "NETWORK_CONNECTION",
                    "rotation_count": details.get("rotation_count"),
                    "tls_ja3": details.get("tls_ja3"),
                }
            )
            hints["detection"]["selection"].update(
                {
                    "tls.server_name|contains": endpoint_host,
                }
            )
        elif capability == "websocket_quic":
            hints.update(
                {
                    "event_type": "NETWORK_CONNECTION",
                    "udp_port": details.get("udp_port"),
                    "alpn": details.get("alpn"),
                }
            )
            hints["detection"]["selection"].update(
                {
                    "network.protocol": "quic",
                    "network.port": details.get("udp_port"),
                }
            )
        elif capability == "solana_rpc":
            hints.update(
                {
                    "event_type": "NETWORK_CONNECTION",
                    "instruction": details.get("instruction"),
                    "rpc_method": details.get("rpc_method"),
                }
            )
            hints["detection"]["selection"].update(
                {
                    "network.application": "solana_rpc",
                }
            )
        else:
            hints.update(
                {
                    "event_type": "NETWORK_CONNECTION",
                    "obfuscation_profile": details.get("obfuscation_profile"),
                }
            )
            hints["detection"]["selection"].update(
                {
                    "network.path": "obfuscated",
                }
            )
        artifacts = _capability_artifacts(context, self.pack_name, capability, mode, details)
        return _result(
            self.name,
            "success",
            f"Legacy protocol '{capability}' prepared in {mode} mode.",
            techniques=[technique],
            artifacts=artifacts,
            hints=hints,
            telemetry=[event],
        )


class LegacyStealthResearchModule(LegacyAdapterBase):
    name = "legacy_stealth_research"
    attack_techniques = ("T1497", "T1562", "T1070", "T1027")
    pack_name = "stealth_pack"
    capability_name = "anti_forensic"

    _SUPPORTED = {
        "anti_forensic": ("T1070", "cleanup"),
        "anti_detection_legacy": ("T1562", "evasion"),
        "anti_sandbox": ("T1497", "environment_check"),
        "dynamic_api": ("T1027", "api_resolution"),
    }

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        capability = normalize_stealth_key(str(params.get("capability", "anti_forensic")))
        if capability not in self._SUPPORTED:
            capability = "anti_forensic"
        self.capability_name = capability
        decision = evaluate_legacy_capability(context.get("config", {}), self.pack_name, capability)
        mode = decision.mode
        self._ensure_allowed(
            context,
            pack_name=self.pack_name,
            capability_name=capability,
            effective_enabled=decision.enabled,
            mode=mode,
        )

        technique, action = self._SUPPORTED[capability]
        target = str(params.get("target", "current_process"))
        details = {
            "capability": capability,
            "action": action,
            "target": target,
            "mode": mode,
            "platform_support": self._platform_support(capability),
            "legacy_subtype": capability,
        }
        if capability == "dynamic_api":
            details["api_hash"] = str(params.get("api_hash", "0xA3D82B19"))
        elif capability == "anti_forensic":
            details["cleanup_targets"] = ["event_logs", "temp_files"]
        elif capability == "anti_detection_legacy":
            details["checks"] = ["sandbox", "vm", "debugger"]
        else:
            details["signals"] = ["hostname", "mac", "process_list"]

        hints = {
            "title": f"Legacy stealth research: {capability}",
            "logsource": {"category": "process_creation", "product": "host"},
            "detection": {
                "selection": {
                    "legacy.capability": capability,
                    "legacy.mode": mode,
                    "legacy.subtype": capability,
                },
                "condition": "selection",
            },
            "mitre_technique": technique,
            "capability": capability,
            "legacy_subtype": capability,
            "event_type": "PROCESS_LAUNCH",
        }
        if capability == "dynamic_api":
            hints.update(
                {
                    "api_hash": details.get("api_hash"),
                    "process_command_line": "LoadLibrary/GetProcAddress dynamic resolution",
                }
            )
            hints["detection"]["selection"].update(
                {
                    "process.command_line|contains": "GetProcAddress",
                }
            )
        elif capability == "anti_forensic":
            hints.update(
                {
                    "cleanup_targets": ",".join(details.get("cleanup_targets", [])),
                }
            )
            hints["detection"]["selection"].update(
                {
                    "file.operation": "delete",
                }
            )
        elif capability == "anti_detection_legacy":
            hints.update(
                {
                    "target_process": target,
                    "process_name": target,
                }
            )
            hints["detection"]["selection"].update(
                {
                    "process.command_line|contains": "anti-detection",
                }
            )
        else:
            hints.update(
                {
                    "sandbox_signals": ",".join(details.get("signals", [])),
                }
            )
            hints["detection"]["selection"].update(
                {
                    "process.environment_check": "sandbox",
                }
            )

        if mode == "emulate":
            runtime = safe_call(run_stealth_capability, capability, params)
            details["runtime_outcome"] = runtime
            if runtime.get("status") == "failure":
                details["runtime_warning"] = (
                    "legacy stealth capability "
                    f"'{capability}' failed: {runtime.get('error')}"
                )
            indicators = flatten_indicators(runtime)
            if indicators:
                details["runtime_indicators"] = indicators
                hints.setdefault("legacy_indicators", {}).update(indicators)
        else:
            details["runtime_outcome"] = {
                "status": "simulated",
                "capability": capability,
                "reason": "simulate mode selected",
            }

        event = TelemetryEvent(
            event_type="legacy_stealth_research",
            module=self.name,
            details={"run_id": context.get("run_id", "unknown"), **details},
        )
        artifacts = _capability_artifacts(context, self.pack_name, capability, mode, details)
        return _result(
            self.name,
            "success",
            f"Legacy stealth capability '{capability}' prepared in {mode} mode.",
            techniques=[technique],
            artifacts=artifacts,
            hints=hints,
            telemetry=[event],
        )

    @staticmethod
    def _platform_support(capability: str) -> str:
        if capability in {"anti_forensic", "anti_detection_legacy", "dynamic_api"}:
            return "windows-preferred"
        return "cross-platform"


def discover_legacy_modules() -> Dict[str, type[BaseModule]]:
    return {
        LegacyPackSummaryModule.name: LegacyPackSummaryModule,
        LegacyActorProfileModule.name: LegacyActorProfileModule,
        LegacyApt29ResearchModule.name: LegacyApt29ResearchModule,
        LegacyApt28ResearchModule.name: LegacyApt28ResearchModule,
        LegacyApt32ResearchModule.name: LegacyApt32ResearchModule,
        LegacyApt38ResearchModule.name: LegacyApt38ResearchModule,
        LegacyApt41ResearchModule.name: LegacyApt41ResearchModule,
        LegacyCredentialAccessModule.name: LegacyCredentialAccessModule,
        LegacyLateralMovementModule.name: LegacyLateralMovementModule,
        LegacyPrivilegeEscalationModule.name: LegacyPrivilegeEscalationModule,
        LegacyProtocolResearchModule.name: LegacyProtocolResearchModule,
        LegacyStealthResearchModule.name: LegacyStealthResearchModule,
    }


__all__ = [
    "LegacyPackSummaryModule",
    "LegacyActorProfileModule",
    "LegacyApt29ResearchModule",
    "LegacyGenericActorTechniqueModule",
    "LegacyApt28ResearchModule",
    "LegacyApt32ResearchModule",
    "LegacyApt38ResearchModule",
    "LegacyApt41ResearchModule",
    "LegacyCredentialAccessModule",
    "LegacyLateralMovementModule",
    "LegacyPrivilegeEscalationModule",
    "LegacyProtocolResearchModule",
    "LegacyStealthResearchModule",
    "discover_legacy_modules",
]
