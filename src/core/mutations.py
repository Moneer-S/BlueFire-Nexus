"""Capability-aware scenario mutation engine.

Synthetic tunables (intensity / noise_ratio / variant) are useful for
detection-stability soak runs but they don't change *what* the chain
actually does. Real mutation has to walk the per-module catalogs and
swap one valid technique / channel / method / interpreter for
another, so the mutated scenario emits genuinely different telemetry
and a defender's detection drafts are tested against a different
shape of activity each run.

This module exposes:

- :func:`propose_mutations(step) -> list[StepMutation]` — read the
  module catalogs and return every catalog-driven swap available for
  the given step (modulo the value the step already carries).
- :func:`apply_mutation(step, mutation) -> dict` — return a deep-
  copied step dict with the mutation applied.
- :data:`MUTATION_CATALOG` — the public mapping of (module, params
  field) → valid alternative values. Tests pin the contents so a
  drop-in catalog change cannot silently invalidate scenarios.

The catalogs are derived from the same per-module catalogs the
runtime modules use. We could import them directly, but doing so
would couple the mutation engine to module-private implementation
details; instead we mirror the public catalog keys here and pin the
mirror against the runtime catalog with a regression test.
"""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple


@dataclass(frozen=True, slots=True)
class StepMutation:
    """A single concrete swap on a scenario step.

    ``module`` + ``param_key`` identify the slot being mutated. ``from_value``
    is the original value (None when the step omits it). ``to_value`` is
    the proposed swap. ``rationale`` is a short defender-readable string
    the report layer can surface so the operator sees *what* was
    swapped without diffing scenario YAML.
    """

    module: str
    param_key: str
    from_value: Optional[Any]
    to_value: Any
    rationale: str


# Public catalog. Keys are (module, params field). Values are the
# canonical alternatives the module accepts for that field.
#
# Kept narrow on purpose: every entry here is a slot the runtime
# module is documented to recognise, so a swap always lands the
# scenario on a real technique / channel / method.
MUTATION_CATALOG: Dict[Tuple[str, str], Tuple[str, ...]] = {
    # NOTE: ExecutionModule is intentionally absent. The runtime
    # accepts ``params["command"]`` / ``params["cmd"]`` as a free-form
    # string (the interpreter is resolved from the first token), so
    # swapping the whole command line is operator-supplied content
    # rather than a catalog selection. The cross-cutting ``target_os``
    # mutation still applies to execution steps that declare it.
    # Modelling a "swap interpreter prefix" mutation that rewrites
    # command in-place is a follow-up.
    ("command_control", "channel"): (
        "http",
        "https",
        "dns",
        "tcp",
        "icmp",
        "websocket",
        "mail",
        "web_service",
        "dga",
        "internal_proxy",
        "domain_fronting",
    ),
    ("network_obfuscator", "protocol"): (
        "dns",
        "domain_fronting",
        "external_proxy",
        "internal_proxy",
        "jitter_padding",
        "multi_hop",
        "protocol_tunneling",
        "tor",
    ),
    ("initial_access", "vector"): (
        "phishing_email",
        "phishing_attachment",
        "phishing_link",
        "spearphishing_via_service",
        "spearphishing_voice",
        "valid_accounts",
        "default_accounts",
        "domain_accounts",
        "local_accounts",
        "cloud_accounts",
        "exploit_public_app",
        "supply_chain",
        "drive_by_compromise",
        "trusted_relationship",
        "external_remote_services",
        "external_rdp",
        "external_ssh",
        "external_vpn",
        "removable_media",
        "hardware_additions",
    ),
    ("persistence", "technique"): (
        "scheduled_task",
        "cron",
        "registry_run_key",
        "service",
        "launch_agent",
        "launch_daemon",
        "wmi_subscription",
        "startup_folder",
        "bashrc",
        "bootkit",
        "authorized_keys",
        "systemd_user_service",
        "macos_login_item",
        "com_hijack",
        "ifeo_debugger",
        "appinit_dlls",
    ),
    ("defense_evasion", "technique"): (
        "argument_spoofing",
        "masquerading",
        "timestomping",
        "log_clearing",
        "hidden_files",
        "system_binary_proxy",
        "powershell_obfuscation",
        "impair_defenses",
        "debugger_evasion",
        "encrypted_encoded_file",
        "environmental_keying",
    ),
    ("anti_detection", "method"): (
        "memory_evasion",
        "anti_debug",
        "anti_sandbox",
        "anti_vm",
        "api_unhooking",
        "code_obfuscation",
        "dynamic_api",
        "log_clear",
        "process_hollowing",
        "reflective_loading",
        "string_encryption",
        "timestomp",
    ),
    ("discovery", "discovery_type"): (
        "network_scan",
        "host_discovery",
        "port_scan",
        "service_scan",
        "system_info",
        "process_info",
        "service_info",
        "user_info",
        "group_info",
        "files",
        "ssh_artifacts",
        "systemd_units",
        "macos_plist_artifacts",
    ),
    ("credential_access", "technique"): (
        "lsass_dump",
        "sam_dump",
        "ntds_dump",
        "browser_credentials",
        "keychain",
        "ssh_keys",
        "keylogging",
        "clipboard",
        "screen_capture",
        "dpapi_master_key",
        "kerberoasting",
        "as_rep_roasting",
        "golden_ticket",
        "silver_ticket",
        "dcsync",
        "lsa_secrets",
        "cached_domain_credentials",
        "pam_unix_backdoor",
    ),
    ("lateral_movement", "technique"): (
        "psexec",
        "wmi",
        "winrm",
        "smb_share",
        "ssh",
        "ftp_transfer",
        "scp_transfer",
        "service_create",
        "rdp",
        "pass_the_hash",
        "pass_the_ticket",
    ),
    ("collection", "technique"): (
        "file_staging",
        "directory_staging",
        "screen_capture",
        "keyboard_capture",
        "clipboard_capture",
        "audio_capture",
        "email_collection",
        "archive_collected",
        "archive_compressed",
        "archive_encrypted",
        "network_share",
    ),
    ("exfiltration", "method"): (
        "via_c2",
        "dns_tunneling",
        "https_to_cloud_storage",
        "https_to_code_repo",
        "https_to_web_service",
        "alt_protocol_asymmetric",
        "alt_protocol_symmetric",
        "alt_protocol_unencrypted",
        "bluetooth",
        "email_smtp",
        "ftp_to_remote",
        "scheduled_transfer",
        "traffic_duplication",
        "usb_removable_media",
    ),
    ("impact", "technique"): (
        "data_encryption",
        "data_destruction",
        "data_manipulation",
        "service_stop",
        "service_modify",
        "service_delete",
        "system_reboot",
        "system_shutdown",
        "endpoint_dos",
        "resource_hijacking",
        "disk_structure_wipe",
        "inhibit_system_recovery",
        "internal_defacement",
    ),
    ("privilege_escalation", "technique"): (
        "token_impersonation",
        "token_duplication",
        "token_creation",
        "process_hollowing",
        "process_injection",
        "process_masquerading",
        "service_creation",
        "service_modification",
        "uac_bypass",
        "parent_pid_spoof",
        "sid_history_injection",
        "create_process_with_token",
    ),
    ("intelligence", "intelligence_type"): (
        "actor_research",
        "ttp_research",
        "ioc_collection",
        "vuln_research",
        "credential_intel",
        "domain_intel",
        "network_intel",
    ),
    ("reconnaissance", "source"): (
        "osint",
        "active_scan",
        "code_repository",
        "dns_records",
        "email_harvesting",
        "search_engine",
        "service_banner",
        "social_media",
        "vuln_scan",
        "whois",
    ),
    ("resource_development", "resource_type"): (
        "domain",
        "vps",
        "web_service",
        "email_account",
        "social_account",
        "code_signing_cert",
        "compromised_infrastructure",
        "malware",
        "exploit",
        "vulnerability",
    ),
}


# A separate cross-cutting axis: target_os swap. Applies to any step
# that already carries ``target_os`` (currently ``execution``) and is
# kept in its own table because it crosses module boundaries.
TARGET_OS_VALUES: Tuple[str, ...] = ("windows", "linux", "macos")


# Interpreter-prefix rewrite catalog for ExecutionModule's
# free-form ``command`` slot. Each entry models a canonical
# command-line shape: a one-token executable + a one-line payload
# flag + the payload itself. The mutation engine extracts the
# payload from a current command, identifies which interpreter
# was used, and re-renders the command with each alternative
# interpreter's prefix.
#
# Kept narrow on purpose: only the four interpreters that are
# unambiguously cross-platform with a one-line payload flag.
# ``-EncodedCommand`` powershell payloads are intentionally
# excluded - swapping interpreters loses the encoded-command
# semantic, and re-encoding the payload for a different
# interpreter is operator-supplied content rather than a
# catalog-driven swap.
_INTERPRETER_PREFIX_REWRITES: Tuple[Dict[str, str], ...] = (
    {
        "name": "powershell",
        "binaries": "powershell|pwsh",
        "prefix": "powershell -nop -c",
        "payload_flag": "-c",
    },
    {
        "name": "cmd",
        "binaries": "cmd",
        "prefix": "cmd /c",
        "payload_flag": "/c",
    },
    {
        "name": "bash",
        "binaries": "bash|sh|zsh",
        "prefix": "bash -c",
        "payload_flag": "-c",
    },
    {
        "name": "python",
        "binaries": "python|python3|py",
        "prefix": "python -c",
        "payload_flag": "-c",
    },
)


def _identify_interpreter(command: str) -> Optional[Dict[str, str]]:
    """Return the matching :data:`_INTERPRETER_PREFIX_REWRITES` entry.

    Looks at the basename of the first token, lowercased and with
    a trailing ``.exe`` stripped. ``None`` when no entry recognises
    the command (the swap surface is defined for a small canonical
    set, not every possible exotic interpreter).
    """

    if not command.strip():
        return None
    try:
        import shlex

        tokens = shlex.split(command, posix=False)
    except ValueError:
        return None
    if not tokens:
        return None
    first = tokens[0]
    if (
        len(first) >= 2
        and first[0] == first[-1]
        and first[0] in {'"', "'"}
    ):
        first = first[1:-1]
    basename = first.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if basename.endswith(".exe"):
        basename = basename[:-4]
    for entry in _INTERPRETER_PREFIX_REWRITES:
        if basename in set(entry["binaries"].split("|")):
            return entry
    return None


def _extract_payload_after_flag(command: str, payload_flag: str) -> Optional[str]:
    """Pull the payload that follows a known one-line flag.

    Returns the literal substring after the flag (whitespace-trimmed).
    ``None`` when the flag is not present in the command. Quoted
    payloads keep their surrounding quotes so the rewrite preserves
    operator-supplied quoting verbatim.
    """

    if not command.strip() or not payload_flag:
        return None
    try:
        import shlex

        tokens = shlex.split(command, posix=False)
    except ValueError:
        return None
    for index, token in enumerate(tokens):
        # Match ``flag`` exactly (case-insensitive) or ``/flag`` /
        # ``-flag`` permutations that map to the same payload-flag
        # semantic. Don't accept partial matches.
        if token.lower() == payload_flag.lower():
            payload_tokens = tokens[index + 1:]
            if not payload_tokens:
                return None
            return " ".join(payload_tokens).strip()
    return None


def _command_has_encoded_command_flag(command: str) -> bool:
    """Detect ``-EncodedCommand`` / ``-enc`` / ``-ec`` style flags.

    Interpreter swap is skipped for encoded commands because the
    payload semantics don't translate (re-encoding a base64+UTF-16
    payload for cmd / bash / python is operator content, not a
    catalog swap).
    """

    if not command.strip():
        return False
    try:
        import shlex

        tokens = shlex.split(command, posix=False)
    except ValueError:
        return False
    enc_flags = {
        "encodedcommand",
        "encoded",
        "encode",
        "enc",
        "ec",
    }
    for token in tokens:
        normalised = token.lstrip("-/").lower()
        if normalised in enc_flags:
            return True
    return False


def propose_command_interpreter_swaps(
    step: Mapping[str, Any],
) -> List[StepMutation]:
    """Return interpreter-prefix swap mutations for an execution step.

    Recognises a small canonical set of cross-platform interpreters
    (powershell / cmd / bash / python). When the current command
    uses one of them, returns one :class:`StepMutation` per
    alternative interpreter, with ``param_key="command"`` and
    ``to_value`` set to the rewritten command.

    Returns an empty list when:

    - the step is not an execution module step;
    - the step's ``params.command`` (or ``cmd``) is missing or empty;
    - the command's interpreter is not in the canonical rewrite set;
    - the command uses ``-EncodedCommand`` (encoded payloads are
      operator content, not a catalog swap surface).
    """

    if str(step.get("module") or "").strip() != "execution":
        return []
    params = step.get("params") or {}
    if not isinstance(params, Mapping):
        return []
    command_key = "command" if "command" in params else (
        "cmd" if "cmd" in params else None
    )
    if command_key is None:
        return []
    command = str(params.get(command_key) or "").strip()
    if not command:
        return []
    if _command_has_encoded_command_flag(command):
        return []
    current = _identify_interpreter(command)
    if current is None:
        return []
    payload = _extract_payload_after_flag(command, current["payload_flag"])
    if payload is None or not payload:
        return []
    proposals: List[StepMutation] = []
    for alternative in _INTERPRETER_PREFIX_REWRITES:
        if alternative["name"] == current["name"]:
            continue
        rewritten = f"{alternative['prefix']} {payload}".strip()
        proposals.append(
            StepMutation(
                module="execution",
                param_key=command_key,
                from_value=command,
                to_value=rewritten,
                rationale=(
                    f"rewrite execution.{command_key} interpreter from "
                    f"{current['name']!r} to {alternative['name']!r}; "
                    f"payload preserved verbatim"
                ),
            )
        )
    return proposals


def propose_mutations(step: Mapping[str, Any]) -> List[StepMutation]:
    """Return every catalog-driven swap available for the step.

    Reads ``step["module"]`` and ``step["params"]`` and walks
    :data:`MUTATION_CATALOG` for matching slots. Each candidate value
    that differs from the current params value yields a
    :class:`StepMutation`.

    The cross-cutting ``target_os`` axis is included when the step's
    params already declare it (so we don't randomly inject a target_os
    on a step that doesn't think in OS terms).
    """

    module = str(step.get("module") or "").strip()
    params = step.get("params") or {}
    if not isinstance(params, Mapping):
        return []

    proposals: List[StepMutation] = []
    for (catalog_module, key), values in MUTATION_CATALOG.items():
        if catalog_module != module:
            continue
        # Only propose swaps for slots the step actually carries.
        # Without this guard a discovery step that omits e.g. ``targets``
        # would still get every catalog candidate proposed against an
        # implicit None, which yields meaningless "swap from None to X"
        # mutations the runtime would treat as fresh values rather than
        # genuine swaps.
        if key not in params:
            continue
        current = params.get(key)
        for candidate in values:
            if candidate == current:
                continue
            proposals.append(
                StepMutation(
                    module=module,
                    param_key=key,
                    from_value=current,
                    to_value=candidate,
                    rationale=f"swap {module}.{key} from {current!r} to {candidate!r}",
                )
            )
    if "target_os" in params:
        current_os = params["target_os"]
        for candidate in TARGET_OS_VALUES:
            if candidate == current_os:
                continue
            proposals.append(
                StepMutation(
                    module=module,
                    param_key="target_os",
                    from_value=current_os,
                    to_value=candidate,
                    rationale=f"swap {module}.target_os from {current_os!r} to {candidate!r}",
                )
            )
    # Execution module: ``params.command`` is a free-form string the
    # runtime resolves to an interpreter at runtime. Catalog-keyed
    # swaps don't apply, but a content-aware interpreter rewrite
    # (powershell -> cmd / bash / python) gives the mutation engine
    # a real swap surface for execution steps too.
    if module == "execution":
        proposals.extend(propose_command_interpreter_swaps(step))
    return proposals


def apply_mutation(
    step: Mapping[str, Any],
    mutation: StepMutation,
) -> Dict[str, Any]:
    """Return a deep-copied step with ``mutation`` applied to params.

    The original step mapping is not mutated. The returned dict has
    its ``params`` field updated to set ``mutation.param_key`` to
    ``mutation.to_value``; every other field is preserved as-is so a
    downstream consumer can still load the step into a scenario YAML.

    A small ``mutation_history`` list is appended to ``params`` (or
    created) so the report / dashboard / copilot can render a
    "mutated from <X> to <Y>" trail without needing the
    :class:`StepMutation` object.
    """

    out = copy.deepcopy(dict(step))
    params = out.get("params")
    if not isinstance(params, dict):
        params = {}
        out["params"] = params
    params[mutation.param_key] = mutation.to_value
    history = list(params.get("mutation_history") or [])
    history.append(
        {
            "param_key": mutation.param_key,
            "from_value": mutation.from_value,
            "to_value": mutation.to_value,
            "rationale": mutation.rationale,
        }
    )
    params["mutation_history"] = history
    return out


def random_mutation(
    step: Mapping[str, Any],
    *,
    rng: Optional[random.Random] = None,
) -> Optional[StepMutation]:
    """Pick one random mutation for the step, or ``None`` when no
    catalog slot applies.

    Uses an injectable ``rng`` so callers (especially tests) can pin
    the choice deterministically. Default is ``random.Random()``
    using the process-wide seed; callers wanting a reproducible
    experiment seed should pass an explicit ``random.Random(seed)``.
    """

    proposals = propose_mutations(step)
    if not proposals:
        return None
    chooser = rng or random.Random()
    return chooser.choice(proposals)


__all__ = [
    "MUTATION_CATALOG",
    "StepMutation",
    "TARGET_OS_VALUES",
    "apply_mutation",
    "propose_command_interpreter_swaps",
    "propose_mutations",
    "random_mutation",
]
