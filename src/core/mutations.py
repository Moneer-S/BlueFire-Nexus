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
    ),
    ("exfiltration", "method"): (
        "via_c2",
        "dns_tunneling",
        "https_to_cloud_storage",
        "https_to_code_repo",
        "https_to_web_service",
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
    "propose_mutations",
    "random_mutation",
]
