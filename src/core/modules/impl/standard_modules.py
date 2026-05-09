"""First-class module implementations for the orchestrator."""

from __future__ import annotations

import base64
import binascii
import platform
import shlex
import subprocess  # nosec B404
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple

from ...models import ModuleResult, TelemetryEvent
from ..base import BaseModule, resolve_target_from_step
from ..contracts import (
    ArtifactSpec,
    CapabilityIOContract,
    consumes,
    produces,
)
from ..contracts import (
    C2_ENDPOINT,
    COLLECTED_DATA,
    CREDENTIAL,
    DETECTION_CONTEXT,
    DISCOVERY_RESULT,
    EXFIL_PACKAGE,
    FILE,
    HOST,
    IMPACT_TARGET,
    PERSISTENCE_MARKER,
    PROCESS,
    SERVICE,
    SHARE,
    STAGED_FILE,
    TOKEN,
    USER,
)


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


# Initial-access vector catalog.
#
# Each entry maps an operator-facing vector (`phishing_attachment`,
# `valid_accounts`, `exploit_public_app`, ...) to a real
# initial-access ATT&CK technique AND a Sigma-style detection draft
# that uses sourcetype-appropriate fields a defender would actually
# look for. Without this catalog the module emitted a single
# generic T1566 (phishing parent) hint with the synthetic
# `vector` field as the only discriminator, which is not a real
# telemetry field anywhere.
_INITIAL_ACCESS_PROFILES: Dict[str, Dict[str, Any]] = {
    "phishing_email": {
        "mitre": "T1566",
        "logsource": {"category": "email", "product": "generic"},
        "selection_field": "email.subject|contains",
        "selection_value": "Action Required",
        "event_type": "initial_access_phishing_email",
        "title_prefix": "Suspicious phishing email targeting",
        "details": {"vector_class": "phishing", "delivery": "email"},
    },
    "phishing_attachment": {
        "mitre": "T1566.001",
        "logsource": {"category": "email", "product": "generic"},
        "selection_field": "email.attachment.extension|contains",
        "selection_value": "lnk",
        "event_type": "initial_access_phishing_attachment",
        "title_prefix": "Phishing attachment delivered to",
        "details": {"vector_class": "phishing", "delivery": "attachment"},
    },
    "phishing_link": {
        "mitre": "T1566.002",
        "logsource": {"category": "email", "product": "generic"},
        "selection_field": "email.url|contains",
        "selection_value": "http",
        "event_type": "initial_access_phishing_link",
        "title_prefix": "Phishing link delivered to",
        "details": {"vector_class": "phishing", "delivery": "link"},
    },
    "spearphishing_via_service": {
        "mitre": "T1566.003",
        "logsource": {"category": "email", "product": "generic"},
        "selection_field": "email.sender.service|contains",
        "selection_value": "linkedin",
        "event_type": "initial_access_phishing_via_service",
        "title_prefix": "Spearphishing-via-service delivered to",
        "details": {"vector_class": "phishing", "delivery": "third_party_service"},
    },
    "spearphishing_voice": {
        "mitre": "T1566.004",
        "logsource": {"category": "voip", "product": "generic"},
        "selection_field": "call.callee.user|contains",
        "selection_value": "@example.invalid",
        "event_type": "initial_access_phishing_voice",
        "title_prefix": "Voice-phishing call to",
        "details": {"vector_class": "phishing", "delivery": "voice_call"},
    },
    "valid_accounts": {
        "mitre": "T1078",
        "logsource": {"category": "authentication", "product": "generic"},
        "selection_field": "event.action",
        "selection_value": "logon_success",
        "event_type": "initial_access_valid_accounts",
        "title_prefix": "Authenticated initial access via valid credentials to",
        "details": {"vector_class": "valid_accounts"},
    },
    "default_accounts": {
        "mitre": "T1078.001",
        "logsource": {"category": "authentication", "product": "generic"},
        "selection_field": "user.name|contains",
        "selection_value": "admin",
        "event_type": "initial_access_default_accounts",
        "title_prefix": "Default-account logon to",
        "details": {"vector_class": "valid_accounts", "account_class": "default"},
    },
    "domain_accounts": {
        "mitre": "T1078.002",
        "logsource": {"category": "authentication", "product": "windows"},
        "selection_field": "user.domain|contains",
        "selection_value": "EXAMPLE",
        "event_type": "initial_access_domain_accounts",
        "title_prefix": "Domain-account logon to",
        "details": {"vector_class": "valid_accounts", "account_class": "domain"},
    },
    "local_accounts": {
        "mitre": "T1078.003",
        "logsource": {"category": "authentication", "product": "generic"},
        "selection_field": "event.logon_type",
        "selection_value": 2,
        "event_type": "initial_access_local_accounts",
        "title_prefix": "Local-account logon to",
        "details": {"vector_class": "valid_accounts", "account_class": "local"},
    },
    "cloud_accounts": {
        "mitre": "T1078.004",
        "logsource": {"category": "cloud_audit", "product": "generic"},
        "selection_field": "user.oauth_provider|contains",
        "selection_value": "azure",
        "event_type": "initial_access_cloud_accounts",
        "title_prefix": "Cloud-account logon to",
        "details": {"vector_class": "valid_accounts", "account_class": "cloud"},
    },
    "exploit_public_app": {
        "mitre": "T1190",
        "logsource": {"category": "webserver", "product": "generic"},
        "selection_field": "http.url|contains",
        "selection_value": "/admin",
        "event_type": "initial_access_exploit_public_app",
        "title_prefix": "Public-application exploitation against",
        "details": {"vector_class": "exploit", "exposure": "public_facing"},
    },
    "external_remote_services": {
        "mitre": "T1133",
        "logsource": {"category": "authentication", "product": "generic"},
        "selection_field": "event.action",
        "selection_value": "remote_service_access",
        "event_type": "initial_access_external_remote_services",
        "title_prefix": "External-remote-service access to",
        "details": {"vector_class": "remote_service"},
    },
    "external_rdp": {
        "mitre": "T1133",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 3389,
        "event_type": "initial_access_external_rdp",
        "title_prefix": "External RDP access to",
        "details": {"vector_class": "remote_service", "service": "rdp", "port": 3389},
    },
    "external_ssh": {
        "mitre": "T1133",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 22,
        "event_type": "initial_access_external_ssh",
        "title_prefix": "External SSH access to",
        "details": {"vector_class": "remote_service", "service": "ssh", "port": 22},
    },
    "external_vpn": {
        "mitre": "T1133",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 1194,
        "event_type": "initial_access_external_vpn",
        "title_prefix": "External VPN access to",
        "details": {"vector_class": "remote_service", "service": "vpn", "port": 1194},
    },
    "trusted_relationship": {
        "mitre": "T1199",
        "logsource": {"category": "authentication", "product": "generic"},
        "selection_field": "user.name|contains",
        "selection_value": "contractor",
        "event_type": "initial_access_trusted_relationship",
        "title_prefix": "Trusted-relationship abuse against",
        "details": {"vector_class": "trusted_relationship"},
    },
    "hardware_additions": {
        "mitre": "T1200",
        "logsource": {"category": "device_event", "product": "windows"},
        "selection_field": "device.class|contains",
        "selection_value": "USB",
        "event_type": "initial_access_hardware_additions",
        "title_prefix": "Hardware-addition initial access to",
        "details": {"vector_class": "hardware_addition", "device_class": "usb"},
    },
    "removable_media": {
        "mitre": "T1091",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "TargetFilename|contains",
        "selection_value": "\\Device\\USB",
        "event_type": "initial_access_removable_media",
        "title_prefix": "Removable-media replication to",
        "details": {"vector_class": "removable_media"},
    },
    "drive_by_compromise": {
        "mitre": "T1189",
        "logsource": {"category": "proxy", "product": "generic"},
        "selection_field": "http.url|contains",
        "selection_value": "/exploit-kit/",
        "event_type": "initial_access_drive_by_compromise",
        "title_prefix": "Drive-by browser compromise of",
        "details": {"vector_class": "drive_by"},
    },
    "supply_chain": {
        "mitre": "T1195",
        "logsource": {"category": "file_event", "product": "host"},
        "selection_field": "file.path|contains",
        "selection_value": "site-packages",
        "event_type": "initial_access_supply_chain",
        "title_prefix": "Supply-chain compromise affecting",
        "details": {"vector_class": "supply_chain"},
    },
}


_INITIAL_ACCESS_DEFAULT = "phishing_email"


# Common operator shortcuts -> canonical catalog key.
# Aliases preserve historic call sites — existing scenario YAMLs
# that say `vector: spearphishing_attachment` or
# `vector: phishing_attachment` resolve to T1566.001 cleanly.
_INITIAL_ACCESS_ALIASES: Dict[str, str] = {
    "spearphishing_attachment": "phishing_attachment",
    "spearphishing_link": "phishing_link",
    "spearphishing_service": "spearphishing_via_service",
    "vishing": "spearphishing_voice",
    "voice_phishing": "spearphishing_voice",
    "exploit_public_facing_application": "exploit_public_app",
    "exploit": "exploit_public_app",
    "remote_services": "external_remote_services",
    # Each service-specific shortcut targets its own profile so the
    # generated detection draft uses the correct port + service.
    # Codex P2 finding on PR #110: routing all three to the generic
    # ``external_remote_services`` profile (port 3389 / service rdp)
    # produced misleading drafts for ``vector: ssh`` and
    # ``vector: vpn``.
    "vpn": "external_vpn",
    "rdp": "external_rdp",
    "ssh": "external_ssh",
    "supply_chain_compromise": "supply_chain",
    "replication_through_removable_media": "removable_media",
    "usb_drop": "removable_media",
    "driveby": "drive_by_compromise",
}


def _resolve_initial_access_vector(requested: str) -> tuple[str, bool]:
    """Return (canonical_key, recognised) for an operator-supplied vector."""
    lowered = requested.lower()
    if lowered in _INITIAL_ACCESS_PROFILES:
        return lowered, True
    if lowered in _INITIAL_ACCESS_ALIASES:
        return _INITIAL_ACCESS_ALIASES[lowered], True
    return _INITIAL_ACCESS_DEFAULT, False


class InitialAccessModule(BaseModule):
    name = "initial_access"
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _INITIAL_ACCESS_PROFILES.values()})
    )
    # Initial access is a chain entry point: it lands on a target user/host
    # and produces the "we are in" signal downstream stages key off. It does
    # not need to consume anything from a prior step (the operator-supplied
    # ``target`` is the entry).
    io_contract = CapabilityIOContract(
        produces=produces(
            ArtifactSpec(type=USER, key="target", description="user or host receiving the initial-access vector"),
            ArtifactSpec(type=HOST, key="target", description="alternate host/landing target", required=False),
        ),
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("vector") or _INITIAL_ACCESS_DEFAULT)
        profile_key, recognised = _resolve_initial_access_vector(requested)
        profile = _INITIAL_ACCESS_PROFILES[profile_key]
        target = str(params.get("target") or "lab-user")

        # Profile details first so canonical fields below
        # (``vector`` / ``target`` / ``mitre_technique``) always win
        # — even if a future profile contributor reuses one of those
        # keys for a per-vector detail.
        details: Dict[str, Any] = dict(profile["details"])
        details.update(
            {
                "vector": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
                "run_id": context["run_id"],
            }
        )

        event = TelemetryEvent(
            event_type=profile["event_type"],
            module=self.name,
            details=dict(details),
        )

        hints: Dict[str, Any] = {
            "title": f"{profile['title_prefix']} {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "initial_access_vector": profile_key,
            "target_user": target,
        }
        if not recognised:
            hints["unrecognized_initial_access_vector"] = requested

        # Same merge discipline as ``details``: canonical fields
        # last so they cannot be overwritten by profile detail keys.
        artifacts: Dict[str, Any] = dict(profile["details"])
        artifacts.update(
            {
                "vector": profile_key,
                "target": target,
                "mitre_technique": profile["mitre"],
            }
        )

        return _result(
            self.name,
            "success",
            f"Simulated initial access via {profile_key} against {target}.",
            techniques=[profile["mitre"]],
            telemetry=[event],
            hints=hints,
            artifacts=artifacts,
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

    Examines the basename of the first token of the command, lower-
    cased and with ``.exe`` stripped, against the interpreter
    catalog. The first token is extracted with ``shlex.split`` so
    quoted executables containing spaces resolve correctly:
    ``"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -c ...`` extracts
    ``pwsh`` rather than truncating at the space inside the quoted
    path. If ``shlex.split`` raises (e.g. unbalanced quotes), the
    fallback splits on whitespace.

    Both ``powershell.exe -nop ...`` and
    ``C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nop``
    resolve to ``T1059.001`` / ``powershell``.
    """
    if not command.strip():
        return {"mitre": "T1059", "interpreter": "unknown"}
    try:
        # ``posix=False`` keeps Windows-style backslash paths intact
        # while still handling double-quoted tokens with spaces. The
        # first token from this lex is the executable.
        tokens = shlex.split(command, posix=False)
        first_token = tokens[0] if tokens else ""
        # Strip surviving surrounding quotes (``posix=False`` keeps
        # them attached to the token).
        if len(first_token) >= 2 and first_token[0] == first_token[-1] and first_token[0] in {'"', "'"}:
            first_token = first_token[1:-1]
    except ValueError:
        first_token = command.strip().split(maxsplit=1)[0]
    if not first_token:
        return {"mitre": "T1059", "interpreter": "unknown"}
    # Strip Windows-style path; basename is what matters.
    basename = first_token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if basename.endswith(".exe"):
        basename = basename[:-4]
    profile = _EXECUTION_INTERPRETER_PROFILES.get(basename)
    if profile is None:
        return {"mitre": "T1059", "interpreter": "unknown"}
    return dict(profile)


# Windows signed-binary proxy execution catalog (T1218).
#
# Each entry models a real Windows tradecraft pattern where adversaries
# launch attacker-controlled code through a Microsoft-signed binary so
# the spawning process is "trusted" from an EDR perspective. These are
# Windows-only by definition; the catalog feeds detection drafts that
# match on the `process.image` (or `Image` in Sysmon EID 1 vocabulary)
# of the proxy binary.
_PROXY_EXECUTION_PROFILES: Dict[str, Dict[str, Any]] = {
    "mshta": {
        "mitre": "T1218.005",
        "interpreter": "mshta",
        "default_image": "C:\\Windows\\System32\\mshta.exe",
        "title_suffix": "mshta.exe HTML application execution",
    },
    "rundll32": {
        "mitre": "T1218.011",
        "interpreter": "rundll32",
        "default_image": "C:\\Windows\\System32\\rundll32.exe",
        "title_suffix": "rundll32.exe DLL load",
    },
    "regsvr32": {
        "mitre": "T1218.010",
        "interpreter": "regsvr32",
        "default_image": "C:\\Windows\\System32\\regsvr32.exe",
        "title_suffix": "regsvr32.exe COM object load",
    },
    "msiexec": {
        "mitre": "T1218.007",
        "interpreter": "msiexec",
        "default_image": "C:\\Windows\\System32\\msiexec.exe",
        "title_suffix": "msiexec.exe MSI installation",
    },
    "installutil": {
        "mitre": "T1218.004",
        "interpreter": "installutil",
        "default_image": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe",
        "title_suffix": "InstallUtil.exe .NET assembly load",
    },
    "certutil": {
        "mitre": "T1140",  # Deobfuscate/decode files or information
        "interpreter": "certutil",
        "default_image": "C:\\Windows\\System32\\certutil.exe",
        "title_suffix": "certutil.exe payload decoding",
    },
    "bitsadmin": {
        "mitre": "T1197",  # BITS Jobs
        "interpreter": "bitsadmin",
        "default_image": "C:\\Windows\\System32\\bitsadmin.exe",
        "title_suffix": "bitsadmin.exe BITS-job execution",
    },
}


def _resolve_proxy_profile(command: str) -> Optional[Dict[str, Any]]:
    """Return the matching :data:`_PROXY_EXECUTION_PROFILES` entry, if any.

    Mirrors :func:`_resolve_execution_profile` but for the system-binary
    proxy catalog. Returns ``None`` when the first command token does
    not match any known proxy binary.
    """

    if not command.strip():
        return None
    try:
        tokens = shlex.split(command, posix=False)
        first_token = tokens[0] if tokens else ""
        if (
            len(first_token) >= 2
            and first_token[0] == first_token[-1]
            and first_token[0] in {'"', "'"}
        ):
            first_token = first_token[1:-1]
    except ValueError:
        first_token = command.strip().split(maxsplit=1)[0]
    if not first_token:
        return None
    basename = first_token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if basename.endswith(".exe"):
        basename = basename[:-4]
    profile = _PROXY_EXECUTION_PROFILES.get(basename)
    if profile is None:
        return None
    return dict(profile)


def _command_basename(command: str) -> str:
    """Return the basename of the first token of ``command``.

    Centralises the "what's the executable name?" extraction so the
    detection draft, telemetry, and artifact paths agree. Unlike
    ``command.split(" ")[0]``, this honours quoted Windows paths with
    spaces (``"C:\\Program Files\\PowerShell\\7\\pwsh.exe"`` →
    ``pwsh.exe``).
    """

    if not command.strip():
        return ""
    try:
        tokens = shlex.split(command, posix=False)
        first_token = tokens[0] if tokens else ""
        if (
            len(first_token) >= 2
            and first_token[0] == first_token[-1]
            and first_token[0] in {'"', "'"}
        ):
            first_token = first_token[1:-1]
    except ValueError:
        first_token = command.strip().split(maxsplit=1)[0]
    return first_token.replace("\\", "/").rsplit("/", 1)[-1]


# Flag spellings PowerShell accepts for ``-EncodedCommand``. Matched
# case-insensitively by walking command tokens and looking for a flag
# that begins with the dash-stripped form.
_POWERSHELL_ENC_FLAGS: Tuple[str, ...] = (
    "encodedcommand",
    "encoded",
    "encode",
    "enc",
    "ec",
)


def _decode_powershell_encoded_command(command: str) -> Optional[str]:
    """Return the decoded payload of a PowerShell ``-EncodedCommand``, or None.

    PowerShell accepts ``-EncodedCommand <base64>`` (and abbreviated
    forms like ``-enc``, ``-ec``). The base64-encoded value is the
    UTF-16 LE bytes of the script. EDR vendors decode this on the way
    in; defenders authoring detection drafts want to see the decoded
    payload so they can match strings or patterns inside it.

    Returns ``None`` when the command does not use ``-EncodedCommand``,
    when the next token after the flag is not valid base64, or when
    the decoded bytes do not look like UTF-16 LE text. Never raises.
    """

    if not command.strip():
        return None
    try:
        tokens = shlex.split(command, posix=False)
    except ValueError:
        return None
    for index, token in enumerate(tokens[:-1]):
        normalised = token.lstrip("-/").lower()
        if normalised not in _POWERSHELL_ENC_FLAGS:
            continue
        candidate = tokens[index + 1]
        # Surrounding quotes survive ``posix=False`` lexing; strip them.
        if (
            len(candidate) >= 2
            and candidate[0] == candidate[-1]
            and candidate[0] in {'"', "'"}
        ):
            candidate = candidate[1:-1]
        try:
            raw = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            return None
        # PowerShell -EncodedCommand uses UTF-16 LE per the documented
        # contract. Decode strictly so a mis-encoded payload (e.g. a
        # base64 blob that happens to decode to ASCII) does not return
        # a misleading "decoded" string.
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    return None


def _extract_proxy_target(command: str, interpreter: str) -> Optional[str]:
    """Extract the proxy binary's payload target (URL / DLL / .ocx / .msi).

    For mshta the target is the script URL or HTA path; for rundll32
    it's ``DLL,Function``; for regsvr32 it's a COM object path / URL;
    for msiexec it's the .msi path / URL. Best-effort: returns the
    first non-flag token after the proxy binary, or ``None`` when no
    such token is present.
    """

    if not command.strip():
        return None
    try:
        tokens = shlex.split(command, posix=False)
    except ValueError:
        tokens = command.strip().split()
    if len(tokens) < 2:
        return None
    # Skip the leading executable + any flag tokens (start with ``-``
    # or ``/``). The first remaining token is the payload target.
    for token in tokens[1:]:
        if token.startswith("-") or token.startswith("/"):
            continue
        candidate = token
        if (
            len(candidate) >= 2
            and candidate[0] == candidate[-1]
            and candidate[0] in {'"', "'"}
        ):
            candidate = candidate[1:-1]
        if candidate:
            return candidate
    # rundll32 callers commonly pass the DLL,Function pair as a single
    # token after a flag — fall through to returning the second-to-last
    # token when nothing un-flagged was found.
    if interpreter == "rundll32" and len(tokens) >= 2:
        candidate = tokens[1]
        if (
            len(candidate) >= 2
            and candidate[0] == candidate[-1]
            and candidate[0] in {'"', "'"}
        ):
            candidate = candidate[1:-1]
        return candidate or None
    return None


class ExecutionModule(BaseModule):
    name = "execution"
    attack_techniques = tuple(
        sorted(
            {
                "T1059",
                *(p["mitre"] for p in _EXECUTION_INTERPRETER_PROFILES.values()),
                *(p["mitre"] for p in _PROXY_EXECUTION_PROFILES.values()),
            }
        )
    )
    # Execution drops a process on the target host; persistence /
    # defense_evasion / credential_access can chain off the spawned
    # process. The host is operator-supplied (or implicit lab-local) so
    # there is no required upstream consumer here.
    io_contract = CapabilityIOContract(
        produces=produces(
            ArtifactSpec(type=PROCESS, key="command", description="command line of the spawned process"),
        ),
        consumes=consumes(
            ArtifactSpec(type=HOST, key="target", description="optional host the command targets", required=False),
        ),
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        command = str(params.get("command") or params.get("cmd") or "echo simulated-execution")
        allow_real = bool(self._config.get("allow_real_execution", False))
        dry_run = bool(context.get("dry_run", True))
        timeout = int(self._config.get("timeout_seconds", 10))

        # Prefer a Windows signed-binary proxy profile (T1218 family)
        # when the operator's command is launched via mshta /
        # rundll32 / regsvr32 / msiexec / installutil / certutil /
        # bitsadmin. The interpreter catalog still resolves a
        # T1059.x sub-technique for the rest (powershell / cmd /
        # wscript / python / etc.).
        proxy_profile = _resolve_proxy_profile(command)
        interpreter_profile = (
            proxy_profile if proxy_profile is not None else _resolve_execution_profile(command)
        )
        mitre = interpreter_profile["mitre"]
        interpreter = interpreter_profile["interpreter"]

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
        # Defender-relevant context that EDR / Sysmon EID 1 captures
        # natively. Operators can override the parent via param when
        # modelling a chained spawn (powershell.exe -> rundll32.exe);
        # otherwise we default to a generic shell parent so the
        # detection draft has a non-empty ParentCommandLine to fire on.
        # Use bare binary names (not absolute paths) so the lab
        # safety canary - which resolves any artifact string that
        # names a real on-disk file - cannot accidentally flag the
        # default. Real EDR vendors capture ParentCommandLine in
        # vendor-specific shape; the binary name is the part the
        # detection draft fires on regardless.
        parent_command_line = str(params.get("parent_command_line") or "").strip()
        if not parent_command_line:
            parent_command_line = (
                "explorer.exe" if target_os == "windows" else "bash"
            )
        image_basename = _command_basename(command)
        # PowerShell payload decoding: when the operator launches a
        # ``-EncodedCommand`` (the canonical APT loader pattern), surface
        # the decoded UTF-16 LE script so detection drafts can match on
        # the actual payload contents instead of the opaque base64 blob.
        decoded_command: Optional[str] = None
        if interpreter == "powershell":
            decoded_command = _decode_powershell_encoded_command(command)
        # Proxy binary payload target — the URL / DLL / .ocx / .msi
        # operands EDR vendors flag for T1218 detection.
        proxy_target: Optional[str] = (
            _extract_proxy_target(command, interpreter)
            if proxy_profile is not None
            else None
        )

        telemetry_details: Dict[str, Any] = {
            "command": command,
            "return_code": rc,
            "target_os": target_os,
            "interpreter": interpreter,
            "mitre_technique": mitre,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "image_basename": image_basename,
            "parent_command_line": parent_command_line,
        }
        if decoded_command is not None:
            telemetry_details["decoded_command"] = decoded_command
        if proxy_target is not None:
            telemetry_details["proxy_target"] = proxy_target
        if proxy_profile is not None:
            telemetry_details["proxy_profile"] = interpreter

        event = TelemetryEvent(
            event_type="execution",
            module=self.name,
            details=telemetry_details,
        )
        # Detection draft uses the existing Sigma vocabulary the
        # downstream pipeline already understands (process.image,
        # process.command_line, process.parent_command_line - the
        # CIM/UDM translator at draft time maps these to vendor-
        # specific fields). Always pin Image / ParentCommandLine so
        # the draft fires reliably; widen with command_line|contains
        # only for content that's actually defender-relevant.
        if proxy_profile is not None:
            title = f"Signed-binary proxy execution: {proxy_profile['title_suffix']}"
            logsource = {"category": "process_creation", "product": "windows"}
            # Always pin against the canonical Windows binary name (e.g.
            # ``mshta.exe`` even if the operator typed ``mshta``); EDR
            # captures process.image with the full filename so the
            # detection draft must match the same shape.
            canonical_image = (
                proxy_profile["default_image"].rsplit("\\", 1)[-1]
            )
            selection: Dict[str, Any] = {
                "process.image|endswith": f"\\{canonical_image}",
                "process.parent_command_line|contains": parent_command_line.split()[0]
                if parent_command_line.split()
                else parent_command_line,
            }
            if proxy_target is not None:
                selection["process.command_line|contains"] = proxy_target
        elif decoded_command is not None:
            title = f"PowerShell EncodedCommand execution ({target_os})"
            logsource = {"category": "process_creation", "product": "windows"}
            selection = {
                "process.image|endswith": "\\powershell.exe",
                "process.command_line|contains_all": ["-enc"],
            }
        else:
            title = f"Suspicious command execution ({target_os})"
            logsource = _execution_logsource(target_os)
            selection = {
                "process.image|endswith": (
                    f"\\{image_basename}" if image_basename else command.split(" ")[0]
                ),
                "process.command_line|contains": image_basename or command.split(" ")[0],
            }

        hints: Dict[str, Any] = {
            "title": title,
            "logsource": logsource,
            "detection": {
                "selection": selection,
                "condition": "selection",
            },
            "mitre_technique": mitre,
            "process_command_line": command,
            "process_image": image_basename,
            "process_parent_command_line": parent_command_line,
            "target_os": target_os,
            "interpreter": interpreter,
        }
        if decoded_command is not None:
            hints["decoded_command"] = decoded_command
        if proxy_target is not None:
            hints["proxy_target"] = proxy_target
        if proxy_profile is not None:
            hints["proxy_profile"] = interpreter
            hints["proxy_default_image"] = proxy_profile["default_image"]

        artifacts: Dict[str, Any] = {
            "command": command,
            "stdout": output,
            "return_code": rc,
            "target_os": target_os,
            "interpreter": interpreter,
            "mitre_technique": mitre,
            "image_basename": image_basename,
            "parent_command_line": parent_command_line,
        }
        if decoded_command is not None:
            artifacts["decoded_command"] = decoded_command
        if proxy_target is not None:
            artifacts["proxy_target"] = proxy_target
        if proxy_profile is not None:
            artifacts["proxy_profile"] = interpreter

        return _result(
            self.name,
            status,
            message,
            techniques=[mitre],
            telemetry=[event],
            hints=hints,
            artifacts=artifacts,
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _PERSISTENCE_PROFILES.values()})
    )
    # Persistence anchors itself to a host, optionally a service or
    # process, and emits a marker that defense_evasion can hide and
    # reporting can correlate against.
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=HOST, key="target", description="host receiving the persistence anchor"),
            ArtifactSpec(type=USER, key="user", description="user/service account the anchor runs as", required=False),
            ArtifactSpec(type=SERVICE, key="service", description="service the persistence is attached to", required=False),
            ArtifactSpec(type=PROCESS, key="process", description="process the persistence references", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=PERSISTENCE_MARKER, key="technique", description="technique-keyed anchor (registry path, task name, service name)"),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _DEFENSE_EVASION_PROFILES.values()})
    )
    # Defense evasion runs against an existing host/process/file.
    # Useful chains: persistence -> defense_evasion (hide the marker),
    # execution -> defense_evasion (mask the spawned process).
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=HOST, key="target", description="host the evasion runs on"),
            ArtifactSpec(type=PROCESS, key="process", description="process to mask / spoof / inject", required=False),
            ArtifactSpec(type=FILE, key="file", description="file to timestomp / hide", required=False),
            ArtifactSpec(type=PERSISTENCE_MARKER, key="persistence_marker", description="anchor to hide", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=DETECTION_CONTEXT, key="evasion_technique", description="technique label for detection drafts"),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _DISCOVERY_PROFILES.values()})
    )
    # Discovery is the canonical chain producer: it enumerates hosts /
    # services / shares / users / files and seeds the rest of the
    # offensive chain. The downstream tactics declare host/share/etc.
    # consumption to match.
    io_contract = CapabilityIOContract(
        produces=produces(
            ArtifactSpec(type=DISCOVERY_RESULT, key="discovered", description="list of discovered targets/services/users"),
            ArtifactSpec(type=HOST, key="targets", description="enumerated hosts (when discovery_type yields hosts)", required=False),
            ArtifactSpec(type=SERVICE, key="targets", description="enumerated services (when discovery_type targets services)", required=False),
            ArtifactSpec(type=SHARE, key="targets", description="enumerated shares (when discovery_type targets shares)", required=False),
            ArtifactSpec(type=USER, key="targets", description="enumerated users (when discovery_type targets accounts)", required=False),
            ArtifactSpec(type=FILE, key="targets", description="enumerated file paths (when discovery_type=files)", required=False),
            # Any of the above can also serve as an impact_target downstream;
            # surface the abstract type so the chaining engine + impact
            # module's contract align without forcing the operator to
            # rewire params.
            ArtifactSpec(type=IMPACT_TARGET, key="targets", description="enumerated impact targets (host/service/share view)", required=False),
        ),
    )

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


# Exfiltration profile catalog.
#
# Each entry maps a high-level operator method (`via_c2`,
# `dns_tunneling`, `https_to_cloud_storage`, ...) to a real
# exfiltration ATT&CK technique AND a Sigma-style detection draft
# that uses telemetry-shaped fields a defender would actually look
# for. Without this catalog the module emitted a single generic
# T1041 hint with the BlueFire field `exfil.method` as the
# discriminator, which is not a real telemetry field anywhere.
_EXFILTRATION_PROFILES: Dict[str, Dict[str, Any]] = {
    "via_c2": {
        "mitre": "T1041",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_hostname|contains",
        "selection_value": "c2.example.invalid",
        "event_type": "exfiltration_via_c2",
        "title_prefix": "Data exfiltration over C2 channel from",
        "details": {"protocol": "https", "encoding": "base64", "channel_reuse": True},
    },
    "dns_tunneling": {
        "mitre": "T1048.003",
        "logsource": {"category": "dns", "product": "network"},
        "selection_field": "dns.question.name|contains",
        "selection_value": ".tunnel.example.invalid",
        "event_type": "exfiltration_dns_tunneling",
        "title_prefix": "Data exfiltration over DNS tunnel from",
        "details": {"record_type": "TXT", "label_length": 63, "carrier_domain": "tunnel.example.invalid"},
    },
    "https_to_cloud_storage": {
        "mitre": "T1567.002",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_hostname|endswith",
        "selection_value": ".s3.amazonaws.com",
        "event_type": "exfiltration_cloud_storage",
        "title_prefix": "Data exfiltration to cloud storage from",
        "details": {"service": "s3", "method": "PUT", "bucket": "lab-exfil-bucket"},
    },
    "https_to_code_repo": {
        "mitre": "T1567.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_hostname|endswith",
        "selection_value": "github.com",
        "event_type": "exfiltration_code_repository",
        "title_prefix": "Data exfiltration to code repository from",
        "details": {"service": "github", "method": "push", "repo": "lab-exfil-repo"},
    },
    "https_to_web_service": {
        "mitre": "T1567",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_hostname|contains",
        "selection_value": "pastebin.com",
        "event_type": "exfiltration_web_service",
        "title_prefix": "Data exfiltration to public web service from",
        "details": {"service": "pastebin", "method": "POST"},
    },
    "email_smtp": {
        "mitre": "T1048.003",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 25,
        "event_type": "exfiltration_email_smtp",
        "title_prefix": "Data exfiltration over SMTP from",
        "details": {"protocol": "smtp", "port": 25, "smtp_relay": "mail.example.invalid"},
    },
    "ftp_to_remote": {
        "mitre": "T1048.003",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 21,
        "event_type": "exfiltration_ftp",
        "title_prefix": "Data exfiltration over FTP from",
        "details": {"protocol": "ftp", "port": 21, "remote": "ftp.example.invalid"},
    },
    "alt_protocol_unencrypted": {
        "mitre": "T1048.003",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 8080,
        "event_type": "exfiltration_alt_protocol_unencrypted",
        "title_prefix": "Data exfiltration over unencrypted non-C2 protocol from",
        "details": {"protocol": "http", "port": 8080, "encryption": "none"},
    },
    "alt_protocol_symmetric": {
        "mitre": "T1048.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 4443,
        "event_type": "exfiltration_alt_protocol_symmetric",
        "title_prefix": "Data exfiltration over symmetrically-encrypted non-C2 protocol from",
        "details": {"protocol": "custom-tls", "port": 4443, "encryption": "AES-256-GCM"},
    },
    "alt_protocol_asymmetric": {
        "mitre": "T1048.002",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_port",
        "selection_value": 443,
        "event_type": "exfiltration_alt_protocol_asymmetric",
        "title_prefix": "Data exfiltration over asymmetrically-encrypted non-C2 protocol from",
        "details": {"protocol": "tls", "port": 443, "encryption": "TLSv1.3"},
    },
    "scheduled_transfer": {
        "mitre": "T1029",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.dst_hostname|contains",
        "selection_value": "scheduled.example.invalid",
        "event_type": "exfiltration_scheduled",
        "title_prefix": "Scheduled data exfiltration from",
        "details": {"window": "02:00-03:00", "interval_seconds": 3600},
    },
    "usb_removable_media": {
        "mitre": "T1052.001",
        "logsource": {"category": "file_event", "product": "windows"},
        "selection_field": "TargetFilename|contains",
        "selection_value": "\\Device\\USB",
        "event_type": "exfiltration_usb",
        "title_prefix": "Data exfiltration to removable USB media from",
        "details": {"medium": "usb", "device_class": "removable_storage"},
    },
    "bluetooth": {
        "mitre": "T1011.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.protocol",
        "selection_value": "bluetooth",
        "event_type": "exfiltration_bluetooth",
        "title_prefix": "Data exfiltration over Bluetooth from",
        "details": {"medium": "bluetooth", "profile": "OBEX"},
    },
    "traffic_duplication": {
        "mitre": "T1020.001",
        "logsource": {"category": "network_connection", "product": "host"},
        "selection_field": "network.flow.duplicate",
        "selection_value": True,
        "event_type": "exfiltration_traffic_duplication",
        "title_prefix": "Data exfiltration via traffic duplication from",
        "details": {"mirror_target": "tap.example.invalid", "duplicate_ratio": 1.0},
    },
}


_EXFILTRATION_DEFAULT = "via_c2"


# Common operator shortcuts -> canonical catalog key.
# Aliases preserve historic call sites (`method: via_c2` already
# matches the canonical key, but `method: c2` / `method: dns` /
# `method: cloud` / `method: usb` are friendlier shortcuts).
_EXFILTRATION_ALIASES: Dict[str, str] = {
    "c2": "via_c2",
    "over_c2": "via_c2",
    "dns": "dns_tunneling",
    "dns_tunnel": "dns_tunneling",
    "cloud": "https_to_cloud_storage",
    "cloud_storage": "https_to_cloud_storage",
    "s3": "https_to_cloud_storage",
    "code_repo": "https_to_code_repo",
    "github": "https_to_code_repo",
    "web_service": "https_to_web_service",
    "pastebin": "https_to_web_service",
    "email": "email_smtp",
    "smtp": "email_smtp",
    "ftp": "ftp_to_remote",
    "usb": "usb_removable_media",
    "removable_media": "usb_removable_media",
    "scheduled": "scheduled_transfer",
    "mirror": "traffic_duplication",
}


def _resolve_exfiltration_method(requested: str) -> tuple[str, bool]:
    """Return (canonical_key, recognised) for an operator-supplied method."""
    lowered = requested.lower()
    if lowered in _EXFILTRATION_PROFILES:
        return lowered, True
    if lowered in _EXFILTRATION_ALIASES:
        return _EXFILTRATION_ALIASES[lowered], True
    return _EXFILTRATION_DEFAULT, False


class ExfiltrationModule(BaseModule):
    name = "exfiltration"
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _EXFILTRATION_PROFILES.values()})
    )
    # Exfiltration consumes either a staged file / collected data set,
    # plus the source host the data came from. It produces an
    # exfil_package artifact + a detection_context the report can
    # surface.
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=HOST, key="target", description="source host the data is exfiltrated from"),
            ArtifactSpec(type=COLLECTED_DATA, key="collected_data", description="aggregated records to exfiltrate", required=False),
            ArtifactSpec(type=STAGED_FILE, key="staged_file", description="staged file to exfiltrate", required=False),
            ArtifactSpec(type=C2_ENDPOINT, key="c2_endpoint", description="optional channel for via_c2 method", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=EXFIL_PACKAGE, key="artifact_name", description="name of the exfiltrated bundle"),
        ),
    )

    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        requested = str(params.get("method") or _EXFILTRATION_DEFAULT)
        profile_key, recognised = _resolve_exfiltration_method(requested)
        profile = _EXFILTRATION_PROFILES[profile_key]

        # Destructive-guard runs BEFORE propagation/profile resolution
        # so a destructive request without lab-ack cannot read upstream
        # results or emit telemetry. Use the resolved canonical mitre
        # for the failure record (was historically pinned to T1041).
        if params.get("destructive", False) and not params.get("i_understand_this_is_a_lab", False):
            return _result(
                self.name,
                "failure",
                "Destructive exfiltration simulation requires explicit lab acknowledgment.",
                techniques=[profile["mitre"]],
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

        # Profile details first so canonical fields below
        # (``method`` / ``target`` / ``mitre_technique`` / ``artifact``)
        # always win — even if a future profile contributor reuses
        # one of those keys for a per-method detail.
        details: Dict[str, Any] = dict(profile["details"])
        details.update(
            {
                "method": profile_key,
                "target": target,
                "artifact": artifact_name,
                "mitre_technique": profile["mitre"],
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
            "title": f"{profile['title_prefix']} {target}",
            "logsource": dict(profile["logsource"]),
            "detection": {
                "selection": {profile["selection_field"]: profile["selection_value"]},
                "condition": "selection",
            },
            "mitre_technique": profile["mitre"],
            "exfiltration_method": profile_key,
            "source_host": target,
        }
        if not recognised:
            hints["unrecognized_exfiltration_method"] = requested
        if propagated_from:
            hints["target_propagated_from_step"] = propagated_from

        # Same merge discipline as ``details``: canonical fields
        # last so they cannot be overwritten by profile detail keys.
        artifacts: Dict[str, Any] = dict(profile["details"])
        artifacts.update(
            {
                "method": profile_key,
                "target": target,
                "artifact_name": artifact_name,
                "mitre_technique": profile["mitre"],
            }
        )
        if propagated_from:
            artifacts["target_propagated_from_step"] = propagated_from

        return _result(
            self.name,
            "success",
            f"Simulated exfiltration via {profile_key} from {target}.",
            techniques=[profile["mitre"]],
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _COMMAND_CONTROL_PROFILES.values()})
    )
    # C2 publishes an endpoint and may consume a previously-provisioned
    # endpoint from resource_development (domain / VPS / web service).
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=C2_ENDPOINT, key="endpoint", description="provisioned endpoint from resource_development", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=C2_ENDPOINT, key="channel", description="active C2 channel keyed by protocol"),
        ),
    )

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
    # Anti-detection runs against an existing host and optionally
    # references the process / file / persistence-marker it is hiding.
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=HOST, key="target", description="host the evasion runs on"),
            ArtifactSpec(type=PROCESS, key="process", description="process to mask / inject", required=False),
            ArtifactSpec(type=FILE, key="file", description="file to hide / timestomp", required=False),
            ArtifactSpec(type=PERSISTENCE_MARKER, key="persistence_marker", description="anchor to hide from defenders", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=DETECTION_CONTEXT, key="anti_detection_method", description="evasion method label for reporting"),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _INTELLIGENCE_PROFILES.values()})
    )
    # Intelligence is a research surface that emits defender-side
    # context (actor / TTP / IoC / vuln research). It does not branch
    # the offensive chain, so the only consumer is the report layer.
    io_contract = CapabilityIOContract(
        produces=produces(
            ArtifactSpec(type=DETECTION_CONTEXT, key="intelligence_type", description="research category for reporting"),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _NETWORK_OBFUSCATOR_PROFILES.values()})
    )
    # Network obfuscator wraps a C2 endpoint with an obfuscation
    # protocol; the chain pair is resource_development /
    # command_control -> network_obfuscator (then exfiltration uses
    # the wrapped endpoint).
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=C2_ENDPOINT, key="endpoint", description="endpoint to wrap with the obfuscation protocol", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=C2_ENDPOINT, key="protocol", description="wrapped C2 channel keyed by obfuscation protocol"),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _RESOURCE_DEVELOPMENT_PROFILES.values()})
    )
    # Resource development produces adversary infrastructure that the
    # rest of the chain consumes: domain / VPS / web service /
    # email account / code-signing cert / etc. The natural pairing is
    # resource_development -> command_control / exfiltration.
    io_contract = CapabilityIOContract(
        produces=produces(
            ArtifactSpec(type=C2_ENDPOINT, key="kind", description="provisioned C2-bearing infrastructure (domain / VPS / web service)"),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _RECONNAISSANCE_PROFILES.values()})
    )
    # Reconnaissance gathers external-only intel (OSINT, passive DNS,
    # cert transparency). It does not feed offensive stages directly;
    # its output is detection_context for reporting.
    io_contract = CapabilityIOContract(
        produces=produces(
            ArtifactSpec(type=DETECTION_CONTEXT, key="source", description="recon source for reporting"),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _CREDENTIAL_ACCESS_PROFILES.values()})
    )
    # Credential access typically runs against a discovered host
    # (discovery -> credential_access) and emits credential / token
    # evidence for lateral_movement and collection to consume.
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=HOST, key="target", description="host the credential extraction runs against"),
            ArtifactSpec(type=USER, key="user", description="user/account whose credential is targeted", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=CREDENTIAL, key="technique", description="credential evidence keyed by technique"),
            ArtifactSpec(type=TOKEN, key="technique", description="forged/extracted token (when applicable)", required=False),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _LATERAL_MOVEMENT_PROFILES.values()})
    )
    # Lateral movement consumes a destination host (where the attacker
    # pivots TO) plus the source host and the credential it presents.
    # Pairs naturally with discovery (target) and credential_access
    # (source + credential).
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=HOST, key="target", description="destination host the pivot lands on"),
            ArtifactSpec(type=HOST, key="source", description="source host the pivot originates from", required=False),
            ArtifactSpec(type=CREDENTIAL, key="credential", description="credential presented to the destination", required=False),
            ArtifactSpec(type=TOKEN, key="token", description="token presented to the destination", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=HOST, key="target", description="newly-controlled destination host"),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _PRIVILEGE_ESCALATION_PROFILES.values()})
    )
    # Privilege escalation runs against a host and optionally
    # consumes the credential / token it leverages. Produces a token
    # downstream stages can present.
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=HOST, key="target", description="host the privesc runs on"),
            ArtifactSpec(type=CREDENTIAL, key="credential", description="credential the privesc leverages", required=False),
            ArtifactSpec(type=TOKEN, key="token", description="token the privesc duplicates / impersonates", required=False),
            ArtifactSpec(type=PROCESS, key="process", description="process to inject / hollow", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=TOKEN, key="technique", description="elevated token / privilege artefact"),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _IMPACT_PROFILES.values()})
    )
    # Impact runs against a host or impact target (a service, dataset,
    # or staged file). Collection -> impact (encrypt the staged data)
    # and discovery -> impact (target an enumerated host) are the
    # canonical chain pairings.
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=IMPACT_TARGET, key="target", description="resource to act on (host / service / dataset)"),
            ArtifactSpec(type=HOST, key="target", description="alternate: bare host as the impact target", required=False),
            ArtifactSpec(type=STAGED_FILE, key="staged_file", description="staged file to encrypt / destroy", required=False),
            ArtifactSpec(type=SERVICE, key="service", description="service to stop / disable / delete", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=DETECTION_CONTEXT, key="technique", description="impact technique label for reporting"),
        ),
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
    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _COLLECTION_PROFILES.values()})
    )
    # Collection runs against a host or share, optionally guided by a
    # credential, and emits collected_data + a staged_file the
    # exfiltration / impact stages can consume.
    io_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=HOST, key="target", description="host or share to harvest from"),
            ArtifactSpec(type=SHARE, key="share", description="specific share to harvest", required=False),
            ArtifactSpec(type=CREDENTIAL, key="credential", description="credential guiding what to target", required=False),
            ArtifactSpec(type=USER, key="user", description="user whose data to focus on", required=False),
        ),
        produces=produces(
            ArtifactSpec(type=COLLECTED_DATA, key="technique", description="aggregated records keyed by collection technique"),
            ArtifactSpec(type=STAGED_FILE, key="technique", description="staged file ready for exfiltration / impact", required=False),
        ),
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
